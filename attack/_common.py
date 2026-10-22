"""Utilitaires communs aux scripts de test de résilience.

Kit portable et autonome : aucune dépendance vers le reste du projet (pas de ../ml/),
stdlib Python uniquement. Conçu pour être copié tel quel sur le PC Attaquant et lancé
contre le labo via le port 443.

Configuration par variables d'environnement (toutes optionnelles) :
  RESILIENCE_TARGET      cible par défaut            (défaut : https://192.168.137.1)
  RESILIENCE_LAB_HOST    hôte labo autorisé en plus  (défaut : 192.168.137.1)
  RESILIENCE_DASHBOARD   base du dashboard ops        (défaut : auto — voir dashboard_base)
  RESILIENCE_LABELS      fichier de labels            (défaut : attack/data/labels.csv)
"""
import csv
import json
import os
import ssl
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Hôte du labo (PC défenseur). Sur le hotspot Windows, la passerelle est 192.168.137.1.
LAB_HOST = os.environ.get("RESILIENCE_LAB_HOST", "192.168.137.1")

# Cible par défaut si aucune n'est passée en argument.
DEFAULT_TARGET = os.environ.get("RESILIENCE_TARGET", f"https://{LAB_HOST}")

# Labels écrits en local, dans le kit (plus de dépendance vers ../ml/data/).
# À recopier sur l'hôte (ml/data/labels.csv) pour (ré)entraîner le ml-detector.
LABELS = Path(os.environ.get("RESILIENCE_LABELS", HERE / "data" / "labels.csv"))

# Contexte TLS : on accepte le certificat auto-signé du labo (pas de vérification de chaîne).
TLS = ssl.create_default_context()
TLS.check_hostname = False
TLS.verify_mode = ssl.CERT_NONE


def guard(target: str) -> None:
    """Refuse toute cible qui n'est pas le labo local. Garde-fou volontaire."""
    allowed = ("https://localhost", "https://127.0.0.1", f"https://{LAB_HOST}")
    if not target.startswith(allowed):
        sys.exit(f"Cible non autorisée : {target}. Ce script ne vise que le labo {allowed}.")


def dashboard_base(target: str) -> str | None:
    """Base du dashboard ops (8080), ou None en « mode aveugle ».

    Le dashboard ops n'est publié que sur 127.0.0.1 côté labo et le pare-feu n'ouvre
    que le 443 vers le LAN. Depuis le PC Attaquant il n'est donc PAS joignable : on
    attaque en aveugle et le retour d'incident se regarde sur l'écran défenseur.
    Forcer une base explicite via RESILIENCE_DASHBOARD si le 8080 a été exposé.
    """
    explicit = os.environ.get("RESILIENCE_DASHBOARD")
    if explicit:
        return explicit.rstrip("/")
    host = urllib.parse.urlparse(target).hostname or ""
    if host in ("localhost", "127.0.0.1", "::1"):
        return "http://127.0.0.1:8080"
    return None


def label(incident_type: str, start: float, end: float, scenario: str) -> None:
    """Horodate l'épisode pour entraîner le classifieur du ml-detector (même format que chaos.py)."""
    LABELS.parent.mkdir(parents=True, exist_ok=True)
    new = not LABELS.exists()
    with LABELS.open("a", newline="") as fh:
        w = csv.writer(fh)
        if new:
            w.writerow(["start", "end", "type", "scenario"])
        w.writerow([round(start, 1), round(end, 1), incident_type, scenario])
    print(f"  · épisode horodaté dans {LABELS}")


def last_incident(target: str) -> dict | None:
    base = dashboard_base(target)
    if not base:
        return None
    try:
        with urllib.request.urlopen(f"{base}/engine/incidents?limit=1", timeout=3) as r:
            data = json.load(r)
            return data[0] if data else None
    except Exception:
        return None


def watch_remediation(before_id: str | None, target: str, timeout: int = 90) -> None:
    """Attend que le moteur clôture un nouvel incident, et affiche le résultat.

    En mode aveugle (dashboard ops non joignable depuis l'attaquant), on n'attend pas :
    le retour d'incident / RTO se regarde sur l'écran défenseur.
    """
    base = dashboard_base(target)
    if not base:
        print("  … mode aveugle : retour d'incident à regarder sur l'écran défenseur "
              "(dashboard ops http://127.0.0.1:8080 + Grafana, côté labo)")
        return
    print("  … on laisse la plateforme se défendre")
    start = time.time()
    while time.time() - start < timeout:
        inc = last_incident(target)
        if inc and inc["id"] != before_id and inc["status"] in ("RESOLVED", "ESCALATED"):
            print(f"  {'✔' if inc['status'] == 'RESOLVED' else '✖'} {inc['id']} {inc['type']} "
                  f"→ {inc['status']} (RTO {inc['rto_s']} s)")
            for a in inc["actions"]:
                print(f"     · {a['action']} [{a['result']}] {a['detail'][:90]}")
            return
        time.sleep(2)
    print(f"  … aucun incident clos dans le délai (voir le dashboard {base})")
