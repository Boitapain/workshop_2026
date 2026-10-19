"""Scénario Red Team — saturation de requêtes (SO3 / http_flood).

Envoie un gros volume de requêtes GET depuis une empreinte constante.
Objectif : faire monter le débit et la latence → détection ML → blocage + rate-limit strict.

Usage : python attack/http_flood.py [cible] [--workers 40] [--seconds 40]
"""
import argparse
import concurrent.futures as cf
import time
import urllib.request

from _common import TLS, guard, label, last_incident, watch_remediation

UA = "resilience-redteam-flood/1.0"


def hit(target: str) -> int:
    req = urllib.request.Request(f"{target}/api/accounts/me", headers={"User-Agent": UA})
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
    ap.add_argument("--workers", type=int, default=40)
    ap.add_argument("--seconds", type=int, default=40)
    args = ap.parse_args()
    guard(args.target)

    before = (last_incident() or {}).get("id")
    print(f"▶ Flood sur {args.target} : {args.workers} connexions en parallèle pendant {args.seconds} s")
    start, n, codes = time.time(), 0, {}

    def worker() -> None:
        nonlocal n
        while time.time() - start < args.seconds:
            c = hit(args.target)
            codes[c] = codes.get(c, 0) + 1
            n += 1

    with cf.ThreadPoolExecutor(max_workers=args.workers) as pool:
        for _ in range(args.workers):
            pool.submit(worker)
    end = time.time()
    label("http_flood", start, end, "redteam-http-flood")
    print(f"  {n} requêtes — réponses {codes}  (403 = bloqué, 429 = rate-limit, 401 = non authentifié)")
    watch_remediation(before)


if __name__ == "__main__":
    main()
