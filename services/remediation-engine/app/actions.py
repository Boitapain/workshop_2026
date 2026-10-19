"""Exécuteurs d'actions de remédiation.

Chaque action est idempotente et ne dispose que du strict nécessaire :
- Docker : via un socket-proxy n'autorisant que GET /containers/json et POST /containers/<id>/(restart|kill) ;
- WAF : écriture de fichiers dans un volume partagé + SIGHUP (rechargement à chaud de Nginx) ;
- services métier : routes /internal/* protégées par jeton de service, joignables seulement sur le réseau control.
"""
import ipaddress
import json
import logging
import os
import time
from pathlib import Path

import httpx

from resilience_common import log_event, read_secret

logger = logging.getLogger("remediation-engine")

DOCKER_URL = os.getenv("DOCKER_PROXY", "http://docker-proxy-rw:2375")
DYNAMIC_DIR = Path(os.getenv("WAF_DYNAMIC_DIR", "/waf-dynamic"))
AUTH_URL = "http://auth-service:8000"
PAYMENT_URL = "http://payment-service:8000"
BACKUP_URL = "http://pg-backup:8080"
DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"


class ActionError(Exception):
    pass


class ActionSkipped(Exception):
    pass


class Executor:
    def __init__(self, store, policy: dict):
        self.store = store
        self.policy = policy
        self.token = read_secret("internal_token")
        self.http = httpx.AsyncClient(timeout=10)
        prot = policy.get("protected", {})
        self.protected_nets = [ipaddress.ip_network(n) for n in prot.get("ips", [])]
        self.nat_gateways = set(prot.get("nat_gateways", []))
        self.protected_uas = set(prot.get("user_agents", []))
        self.protected_containers = set(prot.get("containers", []))

    @property
    def auth(self) -> dict:
        return {"Authorization": f"Bearer {self.token}"}

    # ─────────────────────────── Docker ───────────────────────────
    async def containers(self) -> list[dict]:
        filters = json.dumps({"label": ["com.docker.compose.project=resilience"]})
        resp = await self.http.get(f"{DOCKER_URL}/containers/json", params={"all": "1", "filters": filters})
        resp.raise_for_status()
        out = []
        for c in resp.json():
            labels = c.get("Labels", {})
            status = c.get("Status", "")
            health = "unhealthy" if "(unhealthy)" in status else "healthy" if "(healthy)" in status else \
                "starting" if "health: starting" in status else "none"
            out.append({"id": c["Id"], "service": labels.get("com.docker.compose.service"),
                        "state": c.get("State"), "health": health, "status": status,
                        "remediable": labels.get("resilience.remediable") == "true",
                        "tier": labels.get("resilience.tier"), "role": labels.get("resilience.role")})
        return out

    async def _container(self, service: str) -> dict:
        for c in await self.containers():
            if c["service"] == service:
                return c
        raise ActionError(f"conteneur introuvable : {service}")

    async def restart_container(self, target: str, **_) -> str:
        if target in self.protected_containers:
            raise ActionSkipped(f"{target} est protégé")
        c = await self._container(target)
        if not c["remediable"]:
            raise ActionSkipped(f"{target} n'a pas le label resilience.remediable=true")
        if DRY_RUN:
            return f"[dry-run] restart {target}"
        resp = await self.http.post(f"{DOCKER_URL}/containers/{c['id']}/restart", params={"t": "3"}, timeout=30)
        if resp.status_code not in (204, 304):
            raise ActionError(f"restart {target} : HTTP {resp.status_code}")
        return f"conteneur {target} redémarré"

    async def reload_waf(self) -> None:
        waf = next((c for c in await self.containers() if c["role"] == "waf"), None)
        if not waf:
            raise ActionError("WAF introuvable")
        if DRY_RUN:
            return
        resp = await self.http.post(f"{DOCKER_URL}/containers/{waf['id']}/kill", params={"signal": "HUP"})
        if resp.status_code != 204:
            raise ActionError(f"rechargement WAF : HTTP {resp.status_code}")

    # ─────────────────────────── WAF ───────────────────────────
    def _ip_protected(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True
        return any(addr in net for net in self.protected_nets)

    async def sync_waf(self) -> None:
        """Régénère les fichiers dynamiques du WAF à partir des blocages actifs, puis recharge Nginx."""
        DYNAMIC_DIR.mkdir(parents=True, exist_ok=True)
        blocks = self.store.active_blocks()
        deny = "".join(f"{b['value']} 1;\n" for b in blocks if b["kind"] == "ip")
        fp = "".join(f'"{_nginx_escape(b["value"])}" 1;\n' for b in blocks if b["kind"] == "fingerprint")
        strict = "8443 1;\n" if any(b["kind"] == "strict" for b in blocks) else ""
        for name, content in (("engine.deny", deny), ("engine.fpdeny", fp), ("engine.strict", strict)):
            tmp = DYNAMIC_DIR / f".{name}.tmp"
            tmp.write_text(content)
            tmp.replace(DYNAMIC_DIR / name)  # écriture atomique
        await self.reload_waf()

    async def block_source(self, suspects: dict, ttl_s: int = 900, incident_id: str | None = None, **_) -> str:
        ip = (suspects or {}).get("src_ip")
        ua = (suspects or {}).get("user_agent")
        if not ip:
            raise ActionSkipped("aucune source identifiée par la détection")
        if ip in self.nat_gateways:
            # IP de passerelle NAT partagée par tous les clients externes : on bloque l'empreinte IP+UA.
            if not ua or ua in self.protected_uas or ua == "-":
                raise ActionSkipped(f"{ip} est une passerelle NAT et aucune empreinte exploitable")
            self.store.upsert_block("fingerprint", f"{ip}|{ua}", ttl_s, incident_id)
            await self.sync_waf()
            return f"empreinte bloquée au WAF ({ip} + UA « {ua[:60]} ») pour {ttl_s} s"
        if self._ip_protected(ip):
            raise ActionSkipped(f"{ip} appartient à un réseau protégé")
        self.store.upsert_block("ip", ip, ttl_s, incident_id)
        await self.sync_waf()
        return f"IP {ip} bloquée au WAF pour {ttl_s} s"

    async def rate_limit_strict(self, ttl_s: int = 300, incident_id: str | None = None, **_) -> str:
        self.store.upsert_block("strict", "global", ttl_s, incident_id)
        await self.sync_waf()
        return f"limitation stricte activée pour {ttl_s} s"

    # ─────────────────────────── Services ───────────────────────────
    async def revoke_sessions(self, scope: str = "recent_failures", **_) -> str:
        if DRY_RUN:
            return f"[dry-run] revoke {scope}"
        resp = await self.http.post(f"{AUTH_URL}/internal/revoke", json={"scope": scope}, headers=self.auth)
        if resp.status_code != 200:
            raise ActionError(f"révocation : HTTP {resp.status_code}")
        return f"sessions révoquées ({scope}) : {resp.json()}"

    async def maintenance_mode(self, enabled: bool, **_) -> str:
        # Paramètre nommé « enabled » et non « on » : en YAML 1.1, la clé « on » est lue comme le booléen True.
        if DRY_RUN:
            return f"[dry-run] maintenance={enabled}"
        resp = await self.http.post(f"{PAYMENT_URL}/internal/maintenance", json={"on": enabled}, headers=self.auth)
        if resp.status_code != 200:
            raise ActionError(f"mode maintenance : HTTP {resp.status_code}")
        return "mode lecture seule activé" if enabled else "mode lecture seule désactivé"

    async def restore_db(self, **_) -> str:
        if DRY_RUN:
            return "[dry-run] restore_db"
        resp = await self.http.post(f"{BACKUP_URL}/restore", headers=self.auth, timeout=120)
        if resp.status_code != 200:
            raise ActionError(f"restauration : HTTP {resp.status_code} {resp.text[:200]}")
        data = resp.json()
        return f"base restaurée depuis {data['restored_from']} en {data['duration_s']} s"

    async def run(self, action: str, params: dict) -> str:
        fn = getattr(self, action, None)
        if fn is None or action.startswith("_") or action in ("run", "containers", "sync_waf", "reload_waf"):
            raise ActionError(f"action inconnue : {action}")
        start = time.perf_counter()
        detail = await fn(**params)
        log_event(logger, "remediation.action", action=action, detail=detail,
                  duration_ms=round((time.perf_counter() - start) * 1000))
        return detail


def _nginx_escape(value: str) -> str:
    # La valeur vient d'un en-tête contrôlé par le client : on neutralise tout ce qui pourrait
    # sortir de la chaîne entre guillemets dans la configuration Nginx.
    value = "".join(ch for ch in value if ch.isprintable())[:300]
    return value.replace("\\", "\\\\").replace('"', '\\"')
