"""remediation-engine — API d'entrée des événements et de consultation des incidents."""
import asyncio
import hmac
import json
import os
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path

import yaml
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import StreamingResponse
from prometheus_client import make_asgi_app
from pydantic import BaseModel, Field

sys.path.insert(0, str(Path(__file__).parent))

from engine import Engine  # noqa: E402
from resilience_common import RequestContextMiddleware, log_event, read_secret, setup_logging  # noqa: E402
from store import Store  # noqa: E402

logger = setup_logging()
POLICY = yaml.safe_load(Path(os.getenv("POLICY_FILE", "/srv/policy.yaml")).read_text(encoding="utf-8"))
TOKEN = read_secret("internal_token")
store = Store(os.getenv("STATE_DB", "/data/remediation.db"))
engine = Engine(store, POLICY)


async def self_watchdog() -> None:
    """Chien de garde : si l'API du moteur ne répond plus (processus vivant mais bloqué),
    on termine le processus pour que Docker le relance. Un moteur zombie est pire qu'un moteur mort."""
    import httpx
    failures = 0
    await asyncio.sleep(15)
    async with httpx.AsyncClient(timeout=3) as client:
        while True:
            try:
                (await client.get("http://127.0.0.1:8000/health")).raise_for_status()
                failures = 0
            except Exception:
                failures += 1
                log_event(logger, "watchdog.health_failed", failures=failures)
                if failures >= 3:
                    log_event(logger, "watchdog.exit")
                    os._exit(1)
            await asyncio.sleep(5)


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        await engine.executor.sync_waf()  # remet le WAF en cohérence avec l'état persistant
    except Exception as exc:
        log_event(logger, "startup.waf_sync_failed", error=str(exc))
    await engine.resume_open_incidents()
    tasks = [asyncio.create_task(engine.expiry_loop()), asyncio.create_task(engine.health_loop()),
             asyncio.create_task(self_watchdog())]
    log_event(logger, "engine.started", playbooks=list(POLICY["playbooks"]))
    yield
    for t in tasks:
        t.cancel()


app = FastAPI(title="remediation-engine", lifespan=lifespan, docs_url=None, redoc_url=None)
app.add_middleware(RequestContextMiddleware, logger=logger)
app.mount("/metrics", make_asgi_app())


def require_token(authorization: str = Header(default="")):
    if not hmac.compare_digest(authorization.encode(), f"Bearer {TOKEN}".encode()):
        raise HTTPException(403, "jeton de service invalide")


class Event(BaseModel):
    source: str = Field(max_length=40)
    type: str = Field(max_length=40)
    anomaly_score: float | None = None
    confidence: float | None = None
    window: dict | None = None
    top_features: list | None = None
    suspects: dict | None = None
    model_version: str | None = None
    detail: str | None = Field(default=None, max_length=500)


@app.post("/events", dependencies=[Depends(require_token)])
async def post_event(event: Event):
    return await engine.handle_event(event.model_dump(exclude_none=True))


@app.post("/alertmanager", dependencies=[Depends(require_token)])
async def alertmanager(request: Request):
    """Webhook Alertmanager : les alertes SIEM deviennent des événements du moteur."""
    payload = await request.json()
    results = []
    for alert in payload.get("alerts", []):
        labels = alert.get("labels", {})
        if alert.get("status") != "firing" or "incident_type" not in labels:
            continue
        results.append(await engine.handle_event({
            "source": "siem", "type": labels["incident_type"],
            "detail": f"{labels.get('alertname')} : {alert.get('annotations', {}).get('summary', '')}"[:500],
            "suspects": {"container": labels["job"]} if labels.get("job") in ("auth-service", "payment-service") else {},
        }))
    return {"processed": len(results), "results": results}


@app.get("/incidents")
async def incidents(limit: int = 20):
    return store.list_incidents(max(1, min(limit, 100)))


@app.get("/incidents/stream")
async def stream(request: Request):
    """Flux SSE temps réel pour le dashboard."""
    queue: asyncio.Queue = asyncio.Queue()
    engine.listeners.add(queue)

    async def gen():
        try:
            yield "retry: 2000\n\n"
            while not await request.is_disconnected():
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=15)
                    yield f"event: {msg['kind']}\ndata: {json.dumps(msg, default=str)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            engine.listeners.discard(queue)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/incidents/{inc_id}")
async def incident(inc_id: str):
    inc = store.get_incident(inc_id)
    if not inc:
        raise HTTPException(404, "incident introuvable")
    return inc


@app.get("/actions")
async def actions(limit: int = 100):
    return store.list_actions(limit=max(1, min(limit, 500)))


@app.get("/blocks")
async def blocks():
    return store.active_blocks()


@app.post("/admin/reset", dependencies=[Depends(require_token)])
async def reset():
    """Remise à zéro avant une démo : lève tous les blocages (hors démo uniquement)."""
    store.clear_blocks()
    await engine.executor.sync_waf()
    return {"blocks": 0}


class PauseIn(BaseModel):
    seconds: int = Field(ge=30, le=1800)


@app.post("/admin/pause", dependencies=[Depends(require_token)])
async def pause(body: PauseIn):
    """Fenêtre de maintenance planifiée : le moteur n'agit plus (déploiement volontaire)."""
    return {"paused_until": engine.pause(body.seconds)}


@app.post("/admin/resume", dependencies=[Depends(require_token)])
async def resume():
    engine.resume()
    return {"paused_until": engine.paused_until, "grace": "45 s"}


@app.get("/status")
async def status():
    containers = await engine.executor.containers()
    paused = engine.paused_until
    return {"time": time.time(), "paused_until": paused if paused > time.time() else None,
            "open_incidents": len(store.open_incidents()),
            "active_blocks": len(store.active_blocks()), "containers": containers,
            "dry_run": os.getenv("DRY_RUN", "false")}


@app.get("/health")
async def health():
    return {"status": "ok"}
