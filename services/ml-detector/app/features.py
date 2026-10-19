"""Extraction des features : un vecteur toutes les 5 s sur une fenêtre glissante de 30 s.

Sources : Prometheus (métriques applicatives, PostgreSQL, sonde), Loki (journaux du WAF) et l'API
Docker en lecture seule (CPU / mémoire des conteneurs métier, via docker-proxy-ro).
"""
import json
import math
import re
from collections import Counter

import httpx

PROM = "http://prometheus:9090/api/v1/query"
LOKI = "http://loki:3100/loki/api/v1/query"
LOKI_RANGE = "http://loki:3100/loki/api/v1/query_range"
W = "30s"
BUSINESS = 'job=~"auth-service|payment-service"'
WAF_ACCESS = '{service="waf"} |= "\\"log_type\\":\\"access\\""'

PROM_QUERIES = {
    "login_failure_ratio": f'sum(increase(auth_login_total{{result="failure"}}[{W}])) / clamp_min(sum(increase(auth_login_total[{W}])), 1)',
    "login_attempt_rate": f"sum(rate(auth_login_total[{W}]))",
    "api_latency_p95": f'histogram_quantile(0.95, sum by (le) (rate(http_request_duration_seconds_bucket{{{BUSINESS}}}[{W}])))',
    "pg_connections": 'sum(pg_stat_database_numbackends{datname="resilience"})',
    "pg_mod_per_payment": (f'(sum(rate(pg_stat_database_tup_deleted{{datname="resilience"}}[{W}])) + '
                           f'sum(rate(pg_stat_database_tup_updated{{datname="resilience"}}[{W}]))) / '
                           f'clamp_min(sum(rate(payments_total{{status="completed"}}[{W}])), 0.2)'),
    "payment_rate": f'sum(rate(payments_total{{status="completed"}}[{W}]))',
    "probe_failure": f"1 - avg_over_time(probe_success[{W}])",
    "targets_down": f'count(up{{{BUSINESS}}} == 0) or vector(0)',
    "pg_down": "1 - (max(pg_up) or vector(0))",
    "ledger_drift": "abs(max(ledger_drift_ratio)) or vector(0)",
}

FEATURES = [
    "waf_rps", "ratio_4xx", "ratio_5xx", "waf_403_rate", "distinct_clients", "top_client_share",
    "path_entropy", "login_failure_ratio", "login_attempt_rate", "api_latency_p95", "cpu_business",
    "mem_business_mb", "pg_connections", "pg_mod_per_payment", "payment_rate", "probe_failure",
    "targets_down", "pg_down", "ledger_drift",
]

DOCKER = "http://docker-proxy-ro:2375"
BUSINESS_SERVICES = ("auth-service", "payment-service")
_cpu_prev: dict[str, tuple[int, float]] = {}

UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


async def _prom(client: httpx.AsyncClient, query: str) -> float:
    try:
        resp = await client.get(PROM, params={"query": query})
        result = resp.json()["data"]["result"]
        if not result:
            return 0.0
        value = float(result[0]["value"][1])
        return 0.0 if math.isnan(value) or math.isinf(value) else value
    except Exception:
        return 0.0


async def _waf_lines(client: httpx.AsyncClient, now_ns: int) -> list[dict]:
    """Lignes d'accès du WAF sur la fenêtre (limité à 5 000 lignes : largement suffisant en démo)."""
    try:
        resp = await client.get(LOKI_RANGE, params={
            "query": WAF_ACCESS, "start": str(now_ns - 30 * 10**9), "end": str(now_ns),
            "limit": "5000", "direction": "backward"})
        lines = []
        for stream in resp.json()["data"]["result"]:
            for _, line in stream["values"]:
                try:
                    lines.append(json.loads(line))
                except ValueError:
                    continue
        return lines
    except Exception:
        return []


def _waf_features(lines: list[dict], protected_uas: set[str]) -> tuple[dict, dict]:
    external = [l for l in lines if l.get("user_agent") not in protected_uas]
    total = len(lines)
    feats = {
        "waf_rps": total / 30,
        "ratio_4xx": sum(1 for l in lines if 400 <= int(l.get("status", 0)) < 500) / max(total, 1),
        "ratio_5xx": sum(1 for l in lines if int(l.get("status", 0)) >= 500) / max(total, 1),
        "waf_403_rate": sum(1 for l in lines if int(l.get("status", 0)) == 403) / 30,
    }
    clients = Counter((l.get("remote_addr"), l.get("user_agent")) for l in external)
    feats["distinct_clients"] = len(clients)
    feats["top_client_share"] = (clients.most_common(1)[0][1] / max(total, 1)) if clients else 0.0
    paths = Counter(UUID_RE.sub("{id}", l.get("uri", "")) for l in lines)
    n = sum(paths.values())
    feats["path_entropy"] = -sum((c / n) * math.log2(c / n) for c in paths.values()) if n else 0.0

    # Suspect : client externe le plus présent parmi les requêtes en erreur (sinon, le plus actif).
    failing = Counter((l.get("remote_addr"), l.get("user_agent")) for l in external
                      if int(l.get("status", 0)) >= 400)
    top = (failing or clients).most_common(1)
    suspects = {"src_ip": top[0][0][0], "user_agent": top[0][0][1], "requests": top[0][1]} if top else {}
    return feats, suspects


async def _docker_resources(client: httpx.AsyncClient) -> dict:
    """CPU (cœurs) et mémoire (Mo) cumulés des conteneurs métier, d'après l'API Docker (stats one-shot).
    Le CPU est dérivé de deux mesures successives du compteur cumulatif total_usage."""
    import time
    cpu, mem = 0.0, 0.0
    per_container: dict[str, float] = {}
    try:
        filters = json.dumps({"label": ["com.docker.compose.project=resilience"]})
        listing = (await client.get(f"{DOCKER}/containers/json", params={"filters": filters})).json()
        for c in listing:
            if c.get("Labels", {}).get("com.docker.compose.service") not in BUSINESS_SERVICES:
                continue
            st = (await client.get(f"{DOCKER}/containers/{c['Id']}/stats",
                                   params={"stream": "false", "one-shot": "true"})).json()
            usage, now = st["cpu_stats"]["cpu_usage"]["total_usage"], time.monotonic()
            prev = _cpu_prev.get(c["Id"])
            if prev and now > prev[1] and usage >= prev[0]:
                cores = (usage - prev[0]) / (now - prev[1]) / 1e9
                cpu += cores
                per_container[c["Labels"]["com.docker.compose.service"]] = cores
            _cpu_prev[c["Id"]] = (usage, now)
            ms = st.get("memory_stats", {})
            mem += (ms.get("usage", 0) - ms.get("stats", {}).get("inactive_file", 0)) / 1e6
    except Exception:
        pass
    top = max(per_container, key=per_container.get) if per_container else None
    return {"cpu_business": cpu, "mem_business_mb": mem, "_top_cpu_container": top}


async def collect(client: httpx.AsyncClient, now_ns: int, protected_uas: set[str]) -> tuple[dict, dict]:
    values = {name: await _prom(client, q) for name, q in PROM_QUERIES.items()}
    resources = await _docker_resources(client)
    top_container = resources.pop("_top_cpu_container")
    values.update(resources)
    waf, suspects = _waf_features(await _waf_lines(client, now_ns), protected_uas)
    if top_container:
        suspects["container"] = top_container  # conteneur métier le plus consommateur de CPU
    values.update(waf)
    return {f: float(values.get(f, 0.0)) for f in FEATURES}, suspects
