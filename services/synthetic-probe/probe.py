"""synthetic-probe — transaction témoin toutes les PROBE_INTERVAL secondes, à travers le WAF.

C'est le « juge de paix » de la remédiation : un incident n'est résolu que si une transaction
témoin postérieure aux actions de remédiation réussit.
"""
import asyncio
import os
import time
import uuid
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI
from prometheus_client import Counter, Gauge, Histogram, make_asgi_app

from resilience_common import log_event, read_secret, setup_logging

logger = setup_logging()

BASE_URL = os.getenv("PROBE_TARGET", "https://waf")
INTERVAL = float(os.getenv("PROBE_INTERVAL", "5"))
TLS_CA = os.getenv("PROBE_CA", "/run/secrets/tls_cert")
PROBE_EMAIL, SINK_EMAIL = "probe@resilience.example.com", "sink@resilience.example.com"

SUCCESS = Gauge("probe_success", "1 si la dernière transaction témoin a réussi")
LAST_OK = Gauge("probe_last_success_timestamp", "Horodatage de la dernière transaction témoin réussie")
DURATION = Histogram("probe_duration_seconds", "Durée d'une transaction témoin complète",
                     buckets=(0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10))
RUNS = Counter("probe_runs_total", "Exécutions de la sonde", ["result", "step"])

history: deque = deque(maxlen=50)


class ProbeError(Exception):
    def __init__(self, step: str, detail: str):
        super().__init__(f"{step}: {detail}")
        self.step = step


async def call(client: httpx.AsyncClient, step: str, method: str, path: str, **kw) -> httpx.Response:
    try:
        resp = await client.request(method, path, **kw)
    except httpx.HTTPError as exc:
        raise ProbeError(step, type(exc).__name__)
    if resp.status_code >= 400:
        raise ProbeError(step, f"HTTP {resp.status_code}")
    return resp


async def ensure_account(client: httpx.AsyncClient, email: str, password: str) -> str:
    resp = await client.post("/api/auth/register", json={"email": email, "password": password})
    if resp.status_code not in (201, 409):
        raise ProbeError("register", f"HTTP {resp.status_code}")
    tokens = (await call(client, "login", "POST", "/api/auth/login",
                         json={"email": email, "password": password})).json()
    me = await call(client, "account", "GET", "/api/accounts/me",
                    headers={"Authorization": f"Bearer {tokens['access_token']}"})
    return me.json()["iban"]


async def run_once(client: httpx.AsyncClient, password: str, sink_iban: str) -> dict:
    start = time.perf_counter()
    tokens = (await call(client, "login", "POST", "/api/auth/login",
                         json={"email": PROBE_EMAIL, "password": password})).json()
    auth = {"Authorization": f"Bearer {tokens['access_token']}"}
    tx = (await call(client, "payment", "POST", "/api/payments",
                     json={"to_account": sink_iban, "amount_cents": 1, "label": "transaction témoin"},
                     headers={**auth, "Idempotency-Key": uuid.uuid4().hex})).json()
    check = (await call(client, "verify", "GET", f"/api/payments/{tx['transaction_id']}", headers=auth)).json()
    if check["status"] != "COMPLETED":
        raise ProbeError("verify", f"statut {check['status']}")
    return {"transaction_id": tx["transaction_id"], "latency_ms": round((time.perf_counter() - start) * 1000)}


async def loop() -> None:
    password = read_secret("probe_password")
    verify = TLS_CA if os.path.exists(TLS_CA) else False
    headers = {"User-Agent": "resilience-probe/1.0"}
    sink_iban = None
    async with httpx.AsyncClient(base_url=BASE_URL, verify=verify, timeout=5, headers=headers) as client:
        while True:
            started = time.time()
            result = {"at": datetime.now(timezone.utc).isoformat(), "ts": started}
            try:
                if sink_iban is None:
                    await ensure_account(client, PROBE_EMAIL, password)
                    sink_iban = await ensure_account(client, SINK_EMAIL, password)
                with DURATION.time():
                    result.update(await run_once(client, password, sink_iban))
                result["ok"] = True
                SUCCESS.set(1)
                LAST_OK.set(started)
                RUNS.labels("success", "done").inc()
            except ProbeError as exc:
                result.update(ok=False, error=str(exc))
                SUCCESS.set(0)
                RUNS.labels("failure", exc.step).inc()
                log_event(logger, "probe.failure", step=exc.step, error=str(exc))
            history.append(result)
            await asyncio.sleep(max(0.5, INTERVAL - (time.time() - started)))


@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(loop())
    yield
    task.cancel()


app = FastAPI(title="synthetic-probe", lifespan=lifespan, docs_url=None, redoc_url=None)
app.mount("/metrics", make_asgi_app())


@app.get("/last-result")
async def last_result():
    return history[-1] if history else {"ok": False, "error": "aucune exécution"}


@app.get("/history")
async def get_history(limit: int = 20):
    return list(history)[-limit:]


@app.get("/health")
async def health():
    return {"status": "ok"}
