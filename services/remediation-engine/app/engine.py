"""Boucle Détecter → Décider → Agir → Vérifier.

Un incident n'est RESOLVED que lorsqu'une transaction témoin postérieure aux actions réussit.
"""
import asyncio
import json
import logging
import os
import time

import httpx
from prometheus_client import Counter, Gauge, Histogram

from actions import ActionError, ActionSkipped, Executor
from resilience_common import log_event

logger = logging.getLogger("remediation-engine")

PROBE_URL = os.getenv("PROBE_URL", "http://synthetic-probe:8000")

INCIDENTS = Counter("remediation_incidents_total", "Incidents ouverts", ["type", "source"])
ACTIONS = Counter("remediation_actions_total", "Actions de remédiation", ["action", "result"])
OPEN = Gauge("remediation_incidents_open", "Incidents en cours de traitement")
RTO = Histogram("remediation_incident_rto_seconds", "Durée début d'incident → transaction témoin OK",
                buckets=(5, 10, 20, 30, 45, 60, 90, 120, 180, 300))
LAST_RTO = Gauge("remediation_last_rto_seconds", "RTO du dernier incident résolu")
BLOCKS = Gauge("remediation_active_blocks", "Blocages actifs au WAF", ["kind"])


class Engine:
    def __init__(self, store, policy: dict):
        self.store = store
        self.policy = policy
        self.defaults = policy["defaults"]
        self.executor = Executor(store, policy)
        self.listeners: set[asyncio.Queue] = set()
        self.tasks: dict[str, asyncio.Task] = {}
        self.http = httpx.AsyncClient(timeout=5)
        self.last_health: dict[str, str] = {}
        self.suppress_until: dict[str, float] = {}  # conteneurs redémarrés par le moteur lui-même
        self.pause_file = os.path.join(os.path.dirname(os.getenv("STATE_DB", "/data/remediation.db")), "paused_until")

    # ─────────────────────── maintenance planifiée ───────────────────────
    @property
    def paused_until(self) -> float:
        """Fenêtre de maintenance planifiée (déploiement) : persistée pour survivre au redéploiement du moteur."""
        try:
            return float(open(self.pause_file).read())
        except (OSError, ValueError):
            return 0.0

    def pause(self, seconds: float) -> float:
        until = time.time() + seconds
        with open(self.pause_file, "w") as fh:
            fh.write(str(until))
        log_event(logger, "engine.paused", until=until)
        return until

    def resume(self, grace_s: float = 45) -> None:
        """Fin de maintenance avec un délai de grâce : la fenêtre glissante du ML (30 s) voit encore
        le déploiement juste après la reprise."""
        self.pause(grace_s)
        self.last_health.clear()
        log_event(logger, "engine.resumed", grace_s=grace_s)

    # ─────────────────────── diffusion temps réel (SSE) ───────────────────────
    def publish(self, kind: str, payload: dict) -> None:
        for q in list(self.listeners):
            if q.qsize() < 100:
                q.put_nowait({"kind": kind, "data": payload, "at": time.time()})

    # ─────────────────────── entrée des événements ───────────────────────
    async def handle_event(self, event: dict) -> dict:
        """Normalise un événement (ML, SIEM, Docker) et ouvre ou enrichit un incident."""
        type_ = event.get("type")
        source = event.get("source", "unknown")
        if self.paused_until > time.time():
            log_event(logger, "event.ignored_maintenance", type=type_, source=source)
            return {"accepted": False, "reason": "maintenance planifiée en cours"}
        if type_ not in self.policy["playbooks"]:
            return {"accepted": False, "reason": f"type inconnu : {type_}"}
        if source == "ml-detector":
            if event.get("anomaly_score", 0) < self.defaults["min_anomaly_score"] or \
                    event.get("confidence", 1) < self.defaults["min_confidence"]:
                return {"accepted": False, "reason": "score ou confiance sous le seuil de décision"}

        now = time.time()
        window = self.defaults["correlation_window_s"]
        existing = self.store.find_open(type_, now - window)
        if existing is None and (type_ == "service_outage" or source == "ml-detector"):
            # Symptôme générique (sonde en échec) ou relance du ML pendant un incident en cours :
            # c'est la conséquence de l'incident déjà ouvert, pas un nouvel incident.
            existing = next(iter(self.store.open_incidents()), None)
        if existing:
            self.store.attach_event(existing["id"], event)
            return {"accepted": True, "incident_id": existing["id"], "correlated": True}
        # Traîne d'un incident déjà résolu : la fenêtre glissante du ML (30 s) et les alertes SIEM
        # voient encore l'incident juste après la reprise. On les rattache au lieu d'ouvrir un doublon.
        recent = self.store.recent_resolved(None if source == "ml-detector" else type_, now - 45)
        if recent:
            self.store.attach_event(recent["id"], event)
            return {"accepted": True, "incident_id": recent["id"], "correlated": True}

        window_start = None
        if isinstance(event.get("window"), dict):
            window_start = _parse_ts(event["window"].get("start"))
        incident = self.store.create_incident(type_, source, event, window_start)
        INCIDENTS.labels(type_, source).inc()
        log_event(logger, "incident.detected", incident_id=incident["id"], type=type_, source=source,
                  score=event.get("anomaly_score"), suspects=event.get("suspects"))
        self.publish("incident", self.store.get_incident(incident["id"]))
        self.tasks[incident["id"]] = asyncio.create_task(self.remediate(incident["id"], event))
        return {"accepted": True, "incident_id": incident["id"], "correlated": False}

    # ─────────────────────── traitement d'un incident ───────────────────────
    def _budget_ok(self) -> bool:
        b = self.defaults["global_budget"]
        return self.store.actions_since(time.time() - b["per_seconds"]) < b["actions"]

    async def _resolve_target(self, target: str, event: dict) -> str | None:
        if target != "{suspect_container}":
            return target
        suspect = (event.get("suspects") or {}).get("container")
        if suspect:
            return suspect
        # Pas de suspect désigné : premier conteneur métier en mauvaise santé.
        for c in await self.executor.containers():
            if c["tier"] in ("business", "edge", "data") and c["remediable"] and \
                    (c["health"] == "unhealthy" or c["state"] != "running"):
                return c["service"]
        return None

    async def _run_playbook(self, inc_id: str, name: str, event: dict) -> None:
        playbook = self.policy["playbooks"][name]
        self.store.update_incident(inc_id, status="REMEDIATING", playbook=name)
        self.publish("incident", self.store.get_incident(inc_id))
        for step in playbook["steps"]:
            params = {k: v for k, v in step.items() if k != "action"}
            action = step["action"]
            if not self._budget_ok():
                rec = self.store.record_action(inc_id, action, params, "refused", "budget global d'actions épuisé")
                self.publish("action", rec)
                raise ActionError("budget épuisé")
            if "target" in params:
                params["target"] = await self._resolve_target(params["target"], event)
                if params["target"] is None:
                    rec = self.store.record_action(inc_id, action, params, "skipped", "aucune cible identifiée")
                    ACTIONS.labels(action, "skipped").inc()
                    self.publish("action", rec)
                    continue
            call_params = dict(params)
            if action == "block_source":
                call_params.update(suspects=event.get("suspects") or {}, incident_id=inc_id)
            elif action == "rate_limit_strict":
                call_params["incident_id"] = inc_id
            try:
                detail = await self.executor.run(action, call_params)
                result = "ok"
            except ActionSkipped as exc:
                detail, result = str(exc), "skipped"
            except Exception as exc:  # une action en échec n'interrompt pas le playbook
                detail, result = f"{type(exc).__name__}: {exc}", "error"
            if action == "restart_container" and result == "ok":
                self.suppress_until[params["target"]] = time.time() + 60
            ACTIONS.labels(action, result).inc()
            rec = self.store.record_action(inc_id, action, params, result, detail)
            self.publish("action", rec)
        self._refresh_block_metrics()

    async def _verify(self, inc_id: str, after: float) -> dict | None:
        """Attend une transaction témoin réussie démarrée APRÈS la fin des actions."""
        self.store.update_incident(inc_id, status="VERIFYING")
        self.publish("incident", self.store.get_incident(inc_id))
        deadline = time.time() + self.defaults["verify_timeout_s"]
        while time.time() < deadline:
            try:
                last = (await self.http.get(f"{PROBE_URL}/last-result")).json()
                if last.get("ok") and last.get("ts", 0) > after:
                    return last
            except httpx.HTTPError:
                pass
            await asyncio.sleep(1)
        return None

    async def remediate(self, inc_id: str, event: dict) -> None:
        OPEN.inc()
        try:
            playbook = self.store.get_incident(inc_id)["type"]
            for attempt in range(self.defaults["max_escalations"] + 1):
                try:
                    await self._run_playbook(inc_id, playbook, event)
                except ActionError as exc:
                    self._close(inc_id, "ESCALATED", summary=str(exc))
                    return
                proof = await self._verify(inc_id, after=time.time())
                if proof:
                    inc = self.store.get_incident(inc_id)
                    start = inc["window_start"] or inc["detected_at"]
                    rto = round(proof["ts"] - start, 1)
                    RTO.observe(rto)
                    LAST_RTO.set(rto)
                    self._close(inc_id, "RESOLVED", proof=proof, rto_s=rto,
                                summary=f"rétabli par le playbook {playbook} — transaction témoin {proof['transaction_id'][:8]}")
                    return
                nxt = self.policy["playbooks"][playbook].get("escalate_to")
                rec = self.store.record_action(inc_id, "verify", {"playbook": playbook}, "error",
                                               f"pas de transaction témoin réussie → escalade vers {nxt}")
                self.publish("action", rec)
                if not nxt:
                    break
                playbook = nxt
            self._close(inc_id, "ESCALATED", summary="reprise non vérifiée après escalade : intervention humaine requise")
        finally:
            OPEN.dec()
            self.tasks.pop(inc_id, None)

    def _close(self, inc_id: str, status: str, proof: dict | None = None, rto_s: float | None = None,
               summary: str = "") -> None:
        self.store.update_incident(inc_id, status=status, resolved_at=time.time(), rto_s=rto_s,
                                   proof=json.dumps(proof) if proof else None, summary=summary)
        log_event(logger, f"incident.{status.lower()}", incident_id=inc_id, rto_s=rto_s, summary=summary)
        self.publish("incident", self.store.get_incident(inc_id))

    # ─────────────────────── tâches de fond ───────────────────────
    def _refresh_block_metrics(self) -> None:
        counts = {"ip": 0, "fingerprint": 0, "strict": 0}
        for b in self.store.active_blocks():
            counts[b["kind"]] = counts.get(b["kind"], 0) + 1
        for kind, n in counts.items():
            BLOCKS.labels(kind).set(n)

    async def expiry_loop(self) -> None:
        """Lève les blocages arrivés à expiration (les mesures temporaires restent temporaires)."""
        while True:
            await asyncio.sleep(5)
            try:
                if self.store.purge_expired_blocks():
                    await self.executor.sync_waf()
                    self._refresh_block_metrics()
                    self.publish("blocks", {"active": self.store.active_blocks()})
            except Exception as exc:
                log_event(logger, "expiry.error", level=logging.WARNING, error=str(exc))

    async def health_loop(self) -> None:
        """Surveille l'état Docker : un conteneur métier arrêté ou unhealthy devient un événement."""
        await asyncio.sleep(20)
        while True:
            try:
                for c in await self.executor.containers():
                    if not c["remediable"] or c["service"] in self.executor.protected_containers:
                        continue
                    if self.suppress_until.get(c["service"], 0) > time.time():
                        continue  # redémarrage en cours, déclenché par nous
                    bad = c["state"] != "running" or c["health"] == "unhealthy"
                    was_bad = self.last_health.get(c["service"]) == "bad"
                    self.last_health[c["service"]] = "bad" if bad else "ok"
                    if bad and not was_bad:
                        type_ = "db_outage" if c["service"] == "postgres" else "service_crash"
                        await self.handle_event({
                            "source": "docker-health", "type": type_,
                            "suspects": {"container": c["service"]},
                            "detail": f"{c['service']} : {c['state']} / {c['health']}",
                        })
            except Exception as exc:
                log_event(logger, "health.error", level=logging.WARNING, error=str(exc))
            await asyncio.sleep(3)

    async def resume_open_incidents(self) -> None:
        """Après un redémarrage du moteur, reprend les incidents laissés ouverts."""
        for inc in self.store.open_incidents():
            event = inc["events"][-1] if inc["events"] else {}
            log_event(logger, "incident.resumed", incident_id=inc["id"])
            self.tasks[inc["id"]] = asyncio.create_task(self.remediate(inc["id"], event))


def _parse_ts(value) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    from datetime import datetime
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None
