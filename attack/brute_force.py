"""Scénario Red Team — bourrage d'identifiants (SO1 / brute_force).

Martèle /api/auth/login avec de mauvais mots de passe depuis une empreinte constante.
Objectif : faire monter le ratio d'échecs de connexion → détection ML → blocage au WAF.

Usage : python attack/brute_force.py [cible] [--rps 20] [--seconds 40]
"""
import argparse
import concurrent.futures as cf
import json
import time
import urllib.request

from _common import TLS, guard, label, last_incident, watch_remediation

UA = "resilience-redteam-bruteforce/1.0"       # empreinte constante : le WAF peut bloquer IP+UA


def attempt(target: str, i: int) -> int:
    body = json.dumps({"email": f"victim{i % 5}@resilience.example.com",
                       "password": f"wrong-{i}-{time.time()}"}).encode()
    req = urllib.request.Request(f"{target}/api/auth/login", data=body, method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": UA})
    try:
        with urllib.request.urlopen(req, context=TLS, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="?", default="https://localhost")
    ap.add_argument("--rps", type=int, default=20)
    ap.add_argument("--seconds", type=int, default=40)
    args = ap.parse_args()
    guard(args.target)

    before = (last_incident() or {}).get("id")
    print(f"▶ Brute force sur {args.target} : ~{args.rps} tentatives/s pendant {args.seconds} s")
    start, i, codes = time.time(), 0, {}
    with cf.ThreadPoolExecutor(max_workers=args.rps) as pool:
        while time.time() - start < args.seconds:
            batch = [pool.submit(attempt, args.target, i + k) for k in range(args.rps)]
            i += args.rps
            for f in cf.as_completed(batch):
                codes[f.result()] = codes.get(f.result(), 0) + 1
            time.sleep(1)
    end = time.time()
    label("brute_force", start, end, "redteam-brute-force")
    print(f"  {i} tentatives — réponses {codes}  (403 = bloqué par le WAF, 401 = refus, 429 = rate-limit)")
    watch_remediation(before)


if __name__ == "__main__":
    main()
