"""pg-backup — sauvegardes périodiques vérifiées + restauration à la demande (support du PRA).

- Toutes les BACKUP_INTERVAL secondes : pg_dump -Fc, vérification (pg_restore --list).
- Un dump n'est marqué « sain » (latest_good) que si la transaction témoin réussit au même moment :
  on ne prend jamais comme référence un état déjà altéré par une attaque.
- POST /restore (jeton de service) : restaure les données métier du dernier dump sain.
  Le journal d'audit n'est PAS restauré : il reste une trace intacte de l'incident.
Bibliothèque standard uniquement (image postgres:alpine + python3).
"""
import hmac
import json
import os
import subprocess
import threading
import time
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BACKUP_DIR = Path("/backups")
INTERVAL = int(os.getenv("BACKUP_INTERVAL", "120"))
RETENTION = int(os.getenv("BACKUP_RETENTION", "3600"))
PROBE_URL = os.getenv("PROBE_URL", "http://synthetic-probe:8000/last-result")
RESTORED_TABLES = ["users", "accounts", "transactions", "refresh_tokens", "auth_state"]


def secret(name: str) -> str:
    return Path(f"/run/secrets/{name}").read_text().strip()


TOKEN = secret("internal_token")
ENV_BACKUP = {**os.environ, "PGHOST": "postgres", "PGDATABASE": "resilience",
              "PGUSER": "backup", "PGPASSWORD": secret("db_backup_password")}
ENV_ADMIN = {**ENV_BACKUP, "PGUSER": "postgres", "PGPASSWORD": secret("db_superuser_password")}

state = {"last_backup": None, "last_good": None, "last_error": None, "backups_total": 0, "restores_total": 0}
lock = threading.Lock()


def log(event: str, **fields) -> None:
    print(json.dumps({"ts": datetime.now(timezone.utc).isoformat(), "service": "pg-backup",
                      "event": event, **fields}), flush=True)


def probe_ok() -> bool:
    try:
        with urllib.request.urlopen(PROBE_URL, timeout=3) as resp:
            return bool(json.load(resp).get("ok"))
    except Exception:
        return False


def latest_good() -> Path | None:
    link = BACKUP_DIR / "latest_good"
    if link.exists():
        target = BACKUP_DIR / link.read_text().strip()
        if target.exists():
            return target
    return None


def backup_once() -> None:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = BACKUP_DIR / f"dump-{stamp}.dump"
    with lock:
        subprocess.run(["pg_dump", "-Fc", "-f", str(target)], env=ENV_BACKUP, check=True,
                       capture_output=True, timeout=60)
        subprocess.run(["pg_restore", "--list", str(target)], check=True, capture_output=True, timeout=30)
        state["last_backup"] = target.name
        state["backups_total"] += 1
        healthy = probe_ok()
        if healthy:
            (BACKUP_DIR / "latest_good").write_text(target.name)
            state["last_good"] = target.name
        log("backup.done", file=target.name, size=target.stat().st_size, marked_good=healthy)
        good = latest_good()
        for old in BACKUP_DIR.glob("dump-*.dump"):
            if old != good and time.time() - old.stat().st_mtime > RETENTION:
                old.unlink()


def restore_latest_good() -> dict:
    dump = latest_good()
    if dump is None:
        raise RuntimeError("aucun dump sain disponible")
    started = time.time()
    with lock:
        truncate = (f"SET lock_timeout = '10s'; TRUNCATE {', '.join(RESTORED_TABLES)} CASCADE;")
        # pg_restore génère le SQL des données ; on l'exécute avec le TRUNCATE dans une seule transaction.
        gen_cmd = ["pg_restore", "--data-only", "--disable-triggers", "-f", "-"]
        for t in RESTORED_TABLES:
            gen_cmd += ["-t", t]
        dump_sql = subprocess.run(gen_cmd + [str(dump)], env=ENV_ADMIN, check=True,
                                  capture_output=True, timeout=60).stdout
        script = b"BEGIN;\n" + truncate.encode() + b"\n" + dump_sql + b"\nCOMMIT;\n"
        subprocess.run(["psql", "-v", "ON_ERROR_STOP=1", "-q"], input=script, env=ENV_ADMIN,
                       check=True, capture_output=True, timeout=120)
        subprocess.run(["psql", "-v", "ON_ERROR_STOP=1", "-q", "-c",
                        "INSERT INTO audit_log (actor, action, details) VALUES "
                        f"('remediation-engine', 'restore_db', '{json.dumps({'dump': dump.name})}'::jsonb)"],
                       env=ENV_ADMIN, check=True, capture_output=True, timeout=10)
        state["restores_total"] += 1
    result = {"restored_from": dump.name, "duration_s": round(time.time() - started, 2)}
    log("restore.done", **result)
    return result


def scheduler() -> None:
    while True:
        try:
            backup_once()
            state["last_error"] = None
        except Exception as exc:
            state["last_error"] = str(exc)[:300]
            log("backup.error", error=state["last_error"])
        time.sleep(INTERVAL)


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: dict | str, ctype: str = "application/json") -> None:
        data = (json.dumps(body) if isinstance(body, dict) else body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/health":
            self._send(200, {"status": "ok", **state})
        elif self.path == "/metrics":
            good = latest_good()
            lines = [
                f"backup_total {state['backups_total']}",
                f"backup_restores_total {state['restores_total']}",
                f"backup_last_good_timestamp {good.stat().st_mtime if good else 0}",
                f"backup_error {1 if state['last_error'] else 0}",
            ]
            self._send(200, "\n".join(lines) + "\n", "text/plain; version=0.0.4")
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        auth = self.headers.get("Authorization", "")
        if not hmac.compare_digest(auth.encode(), f"Bearer {TOKEN}".encode()):
            return self._send(403, {"error": "accès interne refusé"})
        try:
            if self.path == "/restore":
                return self._send(200, restore_latest_good())
            if self.path == "/backup":
                backup_once()
                return self._send(200, {"last_backup": state["last_backup"], "last_good": state["last_good"]})
        except subprocess.CalledProcessError as exc:
            log("restore.error", error=exc.stderr.decode(errors="replace")[:500])
            return self._send(500, {"error": "échec de la commande", "detail": exc.stderr.decode(errors="replace")[:300]})
        except Exception as exc:
            return self._send(500, {"error": str(exc)})
        self._send(404, {"error": "not found"})

    def log_message(self, *args):  # logs HTTP par défaut désactivés (on journalise en JSON)
        pass


if __name__ == "__main__":
    BACKUP_DIR.mkdir(exist_ok=True)
    time.sleep(int(os.getenv("BACKUP_INITIAL_DELAY", "30")))  # laisser la plateforme démarrer
    threading.Thread(target=scheduler, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
