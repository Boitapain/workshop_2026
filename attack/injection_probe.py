"""Scénario Red Team — tentatives d'injection (SO2 / injection).

Envoie des charges utiles d'injection SQL / XSS classiques sur les routes de l'API.
Objectif : faire monter les blocages ModSecurity (403) → détection ML → blocage de la source.
Les charges visent à être ARRÊTÉES par le WAF : c'est le test que la défense tient.

Usage : python attack/injection_probe.py [cible] [--seconds 40]
"""
import argparse
import time
import urllib.parse
import urllib.request

from _common import TLS, guard, label, last_incident, watch_remediation

UA = "resilience-redteam-injection/1.0"

# Charges d'injection usuelles (OWASP). Elles doivent déclencher les règles CRS du WAF.
PAYLOADS = [
    "' OR '1'='1", "1; DROP TABLE users--", "' UNION SELECT NULL,NULL--",
    "admin'--", "<script>alert(1)</script>", "../../../../etc/passwd",
    "1 AND SLEEP(5)", "%27%20OR%201=1--", "{{7*7}}", "|cat /etc/passwd",
]


def send(target: str, payload: str) -> int:
    q = urllib.parse.urlencode({"id": payload, "q": payload})
    req = urllib.request.Request(f"{target}/api/payments?{q}", headers={"User-Agent": UA})
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
    ap.add_argument("--seconds", type=int, default=40)
    args = ap.parse_args()
    guard(args.target)

    before = (last_incident() or {}).get("id")
    print(f"▶ Sondage d'injection sur {args.target} pendant {args.seconds} s")
    start, n, codes = time.time(), 0, {}
    while time.time() - start < args.seconds:
        for p in PAYLOADS:
            c = send(args.target, p)
            codes[c] = codes.get(c, 0) + 1
            n += 1
        time.sleep(0.3)
    end = time.time()
    label("injection", start, end, "redteam-injection")
    blocked = codes.get(403, 0)
    print(f"  {n} charges — réponses {codes}")
    print(f"  {blocked}/{n} bloquées par le WAF (403)" + ("  ✔ la défense tient" if blocked else "  ⚠ aucune bloquée !"))
    watch_remediation(before)


if __name__ == "__main__":
    main()
