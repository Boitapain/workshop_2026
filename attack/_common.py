"""Utilitaires communs aux scripts de test de résilience. Cible : le labo local uniquement."""
import csv
import json
import ssl
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LABELS = ROOT / "ml" / "data" / "labels.csv"
DASHBOARD = "http://127.0.0.1:8080"

# Contexte TLS : on accepte le certificat auto-signé du labo (pas de vérification de chaîne).
TLS = ssl.create_default_context()
TLS.check_hostname = False
TLS.verify_mode = ssl.CERT_NONE


def guard(target: str) -> None:
    """Refuse toute cible qui n'est pas le labo local. Garde-fou volontaire."""
    allowed = ("https://localhost", "https://127.0.0.1", "https://192.168.137.1")
    if not target.startswith(allowed):
        sys.exit(f"Cible non autorisée : {target}. Ce script ne vise que le labo local {allowed}.")


def label(incident_type: str, start: float, end: float, scenario: str) -> None:
    """Horodate l'épisode pour entraîner le classifieur du ml-detector (même format que chaos.py)."""
    LABELS.parent.mkdir(parents=True, exist_ok=True)
    new = not LABELS.exists()
    with LABELS.open("a", newline="") as fh:
        w = csv.writer(fh)
        if new:
            w.writerow(["start", "end", "type", "scenario"])
        w.writerow([round(start, 1), round(end, 1), incident_type, scenario])


def last_incident() -> dict | None:
    try:
        with urllib.request.urlopen(f"{DASHBOARD}/engine/incidents?limit=1", timeout=3) as r:
            data = json.load(r)
            return data[0] if data else None
    except Exception:
        return None


def watch_remediation(before_id: str | None, timeout: int = 90) -> None:
    """Attend que le moteur clôture un nouvel incident, et affiche le résultat."""
    print("  … on laisse la plateforme se défendre")
    start = time.time()
    while time.time() - start < timeout:
        inc = last_incident()
        if inc and inc["id"] != before_id and inc["status"] in ("RESOLVED", "ESCALATED"):
            print(f"  {'✔' if inc['status'] == 'RESOLVED' else '✖'} {inc['id']} {inc['type']} "
                  f"→ {inc['status']} (RTO {inc['rto_s']} s)")
            for a in inc["actions"]:
                print(f"     · {a['action']} [{a['result']}] {a['detail'][:90]}")
            return
        time.sleep(2)
    print("  … aucun incident clos dans le délai (voir le dashboard http://127.0.0.1:8080)")
