#!/usr/bin/env python3
"""Chaos engineering — injection de défaillances sur le PC Hôte (exercices du PRA).

Chaque injection est horodatée dans ml/data/labels.csv : ces étiquettes servent aussi
à entraîner le classifieur supervisé du ml-detector (services/ml-detector/train.py).

Usage :
    python chaos/chaos.py list
    python chaos/chaos.py run crash-payment
    python chaos/chaos.py run all          # toute la campagne, avec pauses entre les scénarios
"""
import csv
import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LABELS = ROOT / "ml" / "data" / "labels.csv"
PROJECT = "resilience"
DASHBOARD = "http://127.0.0.1:8080"


def c(service: str) -> str:
    return f"{PROJECT}-{service}-1"


def sh(*args: str) -> str:
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()


def api_ok(path: str) -> bool:
    try:
        with urllib.request.urlopen(f"{DASHBOARD}{path}", timeout=2) as r:
            return r.status == 200
    except Exception:
        return False


def crash(service: str) -> None:
    """Arrêt brutal du processus principal (SIGTERM au PID 1) : simule un crash applicatif."""
    sh("docker", "exec", c(service), "python", "-c", "import os,signal; os.kill(1, signal.SIGTERM)")


SCENARIOS = {
    "crash-payment": {
        "label": "service_crash", "desc": "C1 — arrêt brutal de payment-service (docker kill)",
        "inject": lambda: sh("docker", "kill", c("payment-service")),
    },
    "crash-db": {
        "label": "db_outage", "desc": "C2 — arrêt brutal de PostgreSQL (docker kill)",
        "inject": lambda: sh("docker", "kill", c("postgres")),
    },
    "cpu-stress": {
        "label": "resource_exhaustion", "desc": "C4 — saturation CPU dans auth-service pendant 90 s",
        "inject": lambda: subprocess.Popen(
            ["docker", "exec", c("auth-service"), "python", "-c",
             "import multiprocessing as m,time\n"
             "def burn():\n t=time.time()+90\n while time.time()<t: pass\n"
             "ps=[m.Process(target=burn) for _ in range(4)];[p.start() for p in ps];[p.join() for p in ps]"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
    },
    "db-tamper": {
        "label": "data_tampering",
        "desc": "C6 — altération massive des soldes avec les identifiants applicatifs (compromission simulée)",
        "inject": lambda: sh("docker", "exec", c("postgres"), "sh", "-c",
                             "PGPASSWORD=$(cat /run/secrets/db_payment_password) psql -h 127.0.0.1 -U payment_app "
                             "-d resilience -c \"UPDATE accounts SET balance_cents = 0\""),
    },
    "crash-ml": {
        "label": None, "desc": "C7 — crash du ml-detector (le SIEM doit rester un filet de sécurité)",
        "inject": lambda: crash("ml-detector"),
        "recovered": lambda: api_ok("/ml/status"),
    },
    "crash-engine": {
        "label": None, "desc": "C8 — crash du moteur de remédiation (redémarrage Docker + reprise d'état)",
        "inject": lambda: crash("remediation-engine"),
        "recovered": lambda: api_ok("/engine/status"),
    },
}


def label(type_: str, start: float, end: float, scenario: str) -> None:
    LABELS.parent.mkdir(parents=True, exist_ok=True)
    new = not LABELS.exists()
    with LABELS.open("a", newline="") as fh:
        w = csv.writer(fh)
        if new:
            w.writerow(["start", "end", "type", "scenario"])
        w.writerow([round(start, 1), round(end, 1), type_, scenario])


def last_incident() -> dict | None:
    try:
        with urllib.request.urlopen(f"{DASHBOARD}/engine/incidents?limit=1", timeout=3) as r:
            data = json.load(r)
            return data[0] if data else None
    except Exception:
        return None


def run(name: str, observe_s: int = 90) -> None:
    sc = SCENARIOS[name]
    before = (last_incident() or {}).get("id")
    print(f"\n▶ {name} : {sc['desc']}")
    start = time.time()
    sc["inject"]()
    if "recovered" in sc:
        # Composant du plan de contrôle : pas d'incident attendu, on mesure le retour de son API.
        time.sleep(1)
        while not sc["recovered"]() and time.time() - start < observe_s:
            time.sleep(0.5)
        ok = sc["recovered"]()
        print(f"  {'✔ rétabli' if ok else '✖ non rétabli'} en {time.time() - start:.1f} s (redémarrage par Docker)")
        return
    resolved = None
    while time.time() - start < observe_s:
        time.sleep(2)
        inc = last_incident()
        if inc and inc["id"] != before and inc["status"] in ("RESOLVED", "ESCALATED"):
            resolved = inc
            break
    end = time.time()
    if sc["label"]:
        label(sc["label"], start, end, name)
    if resolved:
        print(f"  ✔ {resolved['id']} {resolved['type']} → {resolved['status']} — RTO {resolved['rto_s']} s")
        for a in resolved["actions"]:
            print(f"     · {a['action']} [{a['result']}] {a['detail'][:90]}")
    else:
        print(f"  … aucun incident clos en {observe_s} s (vérifier le dashboard)")


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)  # consoles Windows
    if len(sys.argv) < 2 or sys.argv[1] == "list":
        for k, v in SCENARIOS.items():
            print(f"{k:15} {v['desc']}")
        return 0
    if sys.argv[1] == "run":
        names = list(SCENARIOS) if sys.argv[2] == "all" else [sys.argv[2]]
        for i, n in enumerate(names):
            run(n)
            if i < len(names) - 1:
                print("  (pause 60 s : retour au régime nominal)")
                time.sleep(60)
        return 0
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main())
