"""Briques communes aux services Python de RESILIENCE-ALPHA : logs JSON, secrets, middleware."""
import json
import logging
import os
import sys
import time
import uuid
from contextvars import ContextVar
from pathlib import Path

from starlette.middleware.base import BaseHTTPMiddleware

SERVICE_NAME = os.getenv("SERVICE_NAME", "unknown")
request_id_var: ContextVar[str] = ContextVar("request_id", default="-")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + "Z",
            "service": SERVICE_NAME,
            "level": record.levelname.lower(),
            "request_id": request_id_var.get(),
            "event": record.getMessage(),
        }
        payload.update(getattr(record, "fields", {}))
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def setup_logging() -> logging.Logger:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(os.getenv("LOG_LEVEL", "INFO"))
    logging.getLogger("uvicorn.access").disabled = True
    logging.getLogger("httpx").setLevel(logging.WARNING)
    return logging.getLogger(SERVICE_NAME)


def log_event(logger: logging.Logger, event: str, level: int = logging.INFO, **fields) -> None:
    logger.log(level, event, extra={"fields": fields})


def read_secret(name: str, default: str | None = None) -> str:
    """Lit un secret Docker (/run/secrets/<name>), ou la variable <NAME>_FILE / <NAME> en dev."""
    candidates = [os.getenv(f"{name.upper()}_FILE"), f"/run/secrets/{name}"]
    for path in filter(None, candidates):
        p = Path(path)
        if p.is_file():
            return p.read_text().strip()
    value = os.getenv(name.upper(), default)
    if value is None:
        raise RuntimeError(f"secret manquant : {name}")
    return value


def client_ip(request) -> str:
    # Le WAF est le seul point d'entrée et positionne X-Real-IP ; on ne fait confiance à rien d'autre.
    return request.headers.get("x-real-ip") or (request.client.host if request.client else "-")


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Propage X-Request-ID et journalise chaque requête (sans corps ni en-têtes sensibles)."""

    def __init__(self, app, logger: logging.Logger):
        super().__init__(app)
        self.logger = logger

    async def dispatch(self, request, call_next):
        rid = request.headers.get("x-request-id") or uuid.uuid4().hex
        token = request_id_var.set(rid)
        start = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            response.headers["x-request-id"] = rid
            return response
        finally:
            if not request.url.path.startswith(("/metrics", "/health", "/ready")):
                log_event(
                    self.logger, "http.request",
                    method=request.method, path=request.url.path, status=status,
                    duration_ms=round((time.perf_counter() - start) * 1000, 1),
                    client_ip=client_ip(request),
                )
            request_id_var.reset(token)
