"""Chef d'orchestre du Clip Chrono (60 s, un seul plan).

Tu filmes le dashboard (http://127.0.0.1:8080) pendant que ce script déroule la séquence :
nominal → attaque → détection ML → remédiation automatique → vérification → rétabli.

Il remet d'abord la plateforme à zéro, affiche un compte à rebours pour démarrer l'enregistrement,
puis déclenche l'attaque au bon instant. Tu n'as qu'à filmer et laisser faire.

Usage :
    python chaos/clip.py                       # attaque = brute force (par défaut)
    python chaos/clip.py --attack injection
    python chaos/clip.py --target https://192.168.137.1   # si l'attaque vient d'un autre poste, voir note
"""
import argparse
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
HERE = Path(__file__).resolve().parent.parent
DASH = "http://127.0.0.1:8080"
TOKEN_CMD = ("import httpx;t=open('/run/secrets/internal_token').read().strip();"
             "print(httpx.post('http://localhost:8000/admin/{}',{}headers={{'Authorization':'Bearer '+t}}).text)")


def engine(action: str, body: str = "") -> None:
    subprocess.run(["docker", "compose", "-f", str(HERE / "infra/docker-compose.yml"),
                    "exec", "-T", "remediation-engine", "python", "-c", TOKEN_CMD.format(action, body)],
                   capture_output=True)


def metric(query: str) -> float:
    try:
        u = f"http://127.0.0.1:9090/api/v1/query?query={urllib.request.quote(query)}"
        import json
        r = json.load(urllib.request.urlopen(u, timeout=3))["data"]["result"]
        return float(r[0]["value"][1]) if r else 0.0
    except Exception:
        return 0.0


def wait_quiet(timeout: int = 120) -> None:
    print("Mise au calme de la plateforme…", flush=True)
    start = time.time()
    while time.time() - start < timeout:
        import json
        try:
            st = json.load(urllib.request.urlopen(f"{DASH}/engine/status", timeout=3))
            score = metric("ml_anomaly_score")
            if st["paused_until"] is None and st["open_incidents"] == 0 and score < 0.45:
                return
        except Exception:
            pass
        time.sleep(3)
    print("  (le système n'est pas parfaitement calme, on continue quand même)")


def countdown(n: int, msg: str) -> None:
    for i in range(n, 0, -1):
        print(f"  {msg} dans {i}…", flush=True)
        time.sleep(1)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--attack", default="brute_force", choices=["brute_force", "injection", "http_flood"])
    ap.add_argument("--target", default="https://localhost")
    ap.add_argument("--attack-at", type=int, default=7, help="seconde de déclenchement de l'attaque")
    ap.add_argument("--duration", type=int, default=35, help="durée de l'attaque")
    args = ap.parse_args()

    engine("reset")
    wait_quiet()
    print("\n" + "=" * 60)
    print("  PLATEFORME PRÊTE — Clip Chrono")
    print("  1. Mets le dashboard http://127.0.0.1:8080 en PLEIN ÉCRAN")
    print("  2. Lance l'enregistrement d'écran (Win+Alt+R)")
    print("=" * 60 + "\n")
    countdown(5, "DÉBUT du clip")

    t0 = time.time()
    print(f"\n[00 s] ● NOMINAL — montre le service vert, les transactions qui défilent", flush=True)
    time.sleep(args.attack_at)

    print(f"[{int(time.time()-t0):02d} s] ⚔ ATTAQUE lancée ({args.attack})", flush=True)
    atk = subprocess.Popen([sys.executable, str(HERE / "attack" / f"{args.attack}.py"),
                            args.target, "--seconds", str(args.duration)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Suit l'incident en direct et annonce les temps forts pour la narration.
    seen = set()
    while time.time() - t0 < 60:
        try:
            inc = json.load(urllib.request.urlopen(f"{DASH}/engine/incidents?limit=1", timeout=3))
            if inc and inc[0]["id"] != before:
                i = inc[0]
                if ("det", i["id"]) not in seen and time.time() - t0 > args.attack_at:
                    seen.add(("det", i["id"]))
                    print(f"[{int(time.time()-t0):02d} s] ⚠ DÉTECTÉ par le ML : {i['type']}", flush=True)
                for a in i.get("actions", []):
                    key = ("act", i["id"], a["id"])
                    if key not in seen and a["result"] == "ok":
                        seen.add(key)
                        print(f"[{int(time.time()-t0):02d} s] ⚙ REMÉDIATION : {a['action']}", flush=True)
                if i["status"] == "RESOLVED" and ("ok", i["id"]) not in seen:
                    seen.add(("ok", i["id"]))
                    print(f"[{int(time.time()-t0):02d} s] ✔ VÉRIFIÉ — transaction témoin OK, RTO {i['rto_s']} s", flush=True)
        except Exception:
            pass
        time.sleep(1)

    atk.wait()
    print(f"\n[60 s] ● RÉTABLI — arrête l'enregistrement. Clip terminé.", flush=True)


if __name__ == "__main__":
    main()
