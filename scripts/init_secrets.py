#!/usr/bin/env python3
"""Génère les secrets locaux de RESILIENCE-ALPHA dans ./secrets (ignoré par git).

Idempotent : un secret existant n'est jamais écrasé (sauf --force).
Seuls des fichiers chiffrés SOPS (*.enc.yaml) peuvent être commités — voir secrets/README.md.
Dépendances : Python 3 (stdlib) + openssl en ligne de commande.
"""
import argparse
import secrets
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "secrets"

PASSWORDS = [
    "db_superuser_password", "db_auth_password", "db_payment_password", "db_backup_password",
    "db_exporter_password", "internal_token", "probe_password", "traffic_password",
    "grafana_admin_password", "dashboard_password",
]


def write(name: str, content: str, force: bool) -> None:
    path = OUT / name
    if path.exists() and not force:
        print(f"  = {name} (existant)")
        return
    path.write_text(content, encoding="ascii", newline="\n")
    print(f"  + {name}")


def openssl(*args: str) -> None:
    subprocess.run(["openssl", *args], check=True, capture_output=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true", help="regénère tous les secrets")
    parser.add_argument("--host-ip", default="192.168.137.1", help="IP du PC Hôte sur le hotspot")
    args = parser.parse_args()
    OUT.mkdir(exist_ok=True)
    print(f"Secrets -> {OUT}")

    for name in PASSWORDS:
        write(name, secrets.token_urlsafe(32), args.force)

    jwt_key = OUT / "jwt_private_key"
    if args.force or not jwt_key.exists():
        openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(jwt_key))
        print("  + jwt_private_key")

    cert, key = OUT / "tls_cert", OUT / "tls_key"
    if args.force or not cert.exists():
        san = f"DNS:waf,DNS:localhost,IP:127.0.0.1,IP:{args.host_ip}"
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                "-days", "30", "-subj", "/CN=resilience-alpha", "-addext", f"subjectAltName={san}",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-keyout", str(key), "-out", str(cert))
        print(f"  + tls_cert / tls_key (SAN {san})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
