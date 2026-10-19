"""payment-service — comptes et virements idempotents."""
import asyncio
import hmac
import json
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import asyncpg
import httpx
import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from prometheus_client import Counter, Gauge, Histogram
from prometheus_fastapi_instrumentator import Instrumentator
from pydantic import BaseModel, Field

from resilience_common import RequestContextMiddleware, client_ip, log_event, read_secret, setup_logging

logger = setup_logging()

MAX_AMOUNT_CENTS = 500_000  # plafond unitaire : 5 000 €
AUTH_URL = "http://auth-service:8000"
INTERNAL_TOKEN = read_secret("internal_token")

PAYMENTS = Counter("payments_total", "Virements traités", ["status"])
AMOUNT = Histogram("payment_amount_cents", "Montant des virements",
                   buckets=(100, 1_000, 10_000, 50_000, 100_000, 500_000))
MAINTENANCE = Gauge("payment_maintenance_mode", "1 si le service est en lecture seule")
# Invariant comptable : l'argent ne fait que circuler entre comptes internes, donc la somme des soldes
# vaut toujours INITIAL_BALANCE × nombre de comptes. Tout écart signe une altération des données.
INITIAL_BALANCE_CENTS = 100_000
LEDGER_DRIFT = Gauge("ledger_drift_ratio", "Écart relatif à l'invariant comptable (0 = cohérent)")
LEDGER_ACCOUNTS = Gauge("ledger_accounts_total", "Nombre de comptes")


class State:
    maintenance = False
    jwks: jwt.PyJWKSet | None = None
    epoch = 0
    epoch_checked = 0.0


async def load_jwks() -> None:
    async with httpx.AsyncClient(timeout=3) as client:
        for attempt in range(30):
            try:
                resp = await client.get(f"{AUTH_URL}/.well-known/jwks.json")
                resp.raise_for_status()
                State.jwks = jwt.PyJWKSet.from_dict(resp.json())
                log_event(logger, "jwks.loaded", keys=len(State.jwks.keys))
                return
            except Exception as exc:  # auth-service pas encore prêt
                log_event(logger, "jwks.retry", attempt=attempt, error=str(exc))
                await asyncio.sleep(2)
    raise RuntimeError("impossible de charger les clés JWKS")


async def ledger_check(pool: asyncpg.Pool) -> None:
    while True:
        try:
            row = await pool.fetchrow("SELECT count(*) AS n, coalesce(sum(balance_cents), 0) AS total FROM accounts")
            expected = row["n"] * INITIAL_BALANCE_CENTS
            LEDGER_ACCOUNTS.set(row["n"])
            LEDGER_DRIFT.set((row["total"] - expected) / expected if expected else 0)
        except Exception as exc:
            log_event(logger, "ledger.check_failed", error=type(exc).__name__)
        await asyncio.sleep(5)


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.pool = await asyncpg.create_pool(
        host="postgres", database="resilience", user="payment_app",
        password=read_secret("db_payment_password"), min_size=2, max_size=15,
    )
    await load_jwks()
    ledger = asyncio.create_task(ledger_check(app.state.pool))
    yield
    ledger.cancel()
    await app.state.pool.close()


app = FastAPI(title="payment-service", lifespan=lifespan, docs_url=None, redoc_url=None)
app.add_middleware(RequestContextMiddleware, logger=logger)
Instrumentator().instrument(app).expose(app, include_in_schema=False)


async def db(request: Request) -> asyncpg.Pool:
    return request.app.state.pool


async def current_epoch(pool: asyncpg.Pool) -> int:
    if time.monotonic() - State.epoch_checked > 2:
        State.epoch = await pool.fetchval("SELECT epoch FROM auth_state WHERE id = 1")
        State.epoch_checked = time.monotonic()
    return State.epoch


async def current_user(request: Request, authorization: str = Header(default=""),
                       pool: asyncpg.Pool = Depends(db)) -> dict:
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "jeton manquant")
    token = authorization[7:]
    try:
        kid = jwt.get_unverified_header(token).get("kid")
        if State.jwks is None or kid not in {k.key_id for k in State.jwks.keys}:
            await load_jwks()  # rotation de clé : on recharge une fois
        claims = jwt.decode(token, State.jwks[kid].key, algorithms=["RS256"],
                            options={"require": ["exp", "iat", "sub", "epoch"]})
    except (jwt.PyJWTError, KeyError):
        raise HTTPException(401, "jeton invalide")
    if claims["epoch"] != await current_epoch(pool):
        raise HTTPException(401, "jeton révoqué")
    valid_after = await pool.fetchval("SELECT tokens_valid_after FROM users WHERE id = $1", uuid.UUID(claims["sub"]))
    if valid_after is None or claims["iat"] < valid_after.timestamp():
        raise HTTPException(401, "jeton révoqué")
    return claims


class PaymentIn(BaseModel):
    to_account: str = Field(min_length=5, max_length=40, pattern=r"^[A-Z0-9-]+$")
    amount_cents: int = Field(gt=0)
    currency: str = Field(default="EUR", pattern="^EUR$")
    label: str = Field(default="", max_length=140)


def _tx_out(row) -> dict:
    return {"transaction_id": str(row["id"]), "status": row["status"], "amount_cents": row["amount_cents"],
            "label": row["label"], "created_at": row["created_at"].isoformat(),
            "from_iban": row["from_iban"], "to_iban": row["to_iban"]}


TX_SELECT = """SELECT t.id, t.status, t.amount_cents, t.label, t.created_at,
                      fa.iban AS from_iban, ta.iban AS to_iban
               FROM transactions t
               JOIN accounts fa ON fa.id = t.from_account
               JOIN accounts ta ON ta.id = t.to_account"""


@app.get("/accounts/me")
async def my_account(user: dict = Depends(current_user), pool: asyncpg.Pool = Depends(db)):
    row = await pool.fetchrow(
        "SELECT iban, balance_cents, currency FROM accounts WHERE user_id = $1", uuid.UUID(user["sub"]))
    if not row:
        raise HTTPException(404, "compte introuvable")
    return dict(row)


@app.post("/payments", status_code=201)
async def create_payment(body: PaymentIn, request: Request,
                         idempotency_key: str = Header(min_length=8, max_length=64),
                         user: dict = Depends(current_user), pool: asyncpg.Pool = Depends(db)):
    if State.maintenance:
        raise HTTPException(503, "service en lecture seule (maintenance)")
    if body.amount_cents > MAX_AMOUNT_CENTS:
        PAYMENTS.labels("rejected").inc()
        raise HTTPException(422, "plafond unitaire dépassé")
    user_id = uuid.UUID(user["sub"])

    async with pool.acquire() as conn, conn.transaction():
        existing = await conn.fetchrow(
            TX_SELECT + " WHERE t.initiated_by = $1 AND t.idempotency_key = $2", user_id, idempotency_key)
        if existing:
            return _tx_out(existing)  # rejeu idempotent : même réponse

        src = await conn.fetchrow("SELECT id FROM accounts WHERE user_id = $1", user_id)
        dst = await conn.fetchrow("SELECT id FROM accounts WHERE iban = $1", body.to_account)
        if not src or not dst:
            PAYMENTS.labels("rejected").inc()
            raise HTTPException(422, "compte destinataire inconnu")
        if src["id"] == dst["id"]:
            PAYMENTS.labels("rejected").inc()
            raise HTTPException(422, "virement vers soi-même interdit")

        # Verrouillage dans un ordre déterministe pour éviter les interblocages.
        locked = {r["id"]: r["balance_cents"] for r in await conn.fetch(
            "SELECT id, balance_cents FROM accounts WHERE id = ANY($1::uuid[]) ORDER BY id FOR UPDATE",
            [src["id"], dst["id"]])}
        if locked[src["id"]] < body.amount_cents:
            PAYMENTS.labels("rejected").inc()
            raise HTTPException(422, "solde insuffisant")

        await conn.execute("UPDATE accounts SET balance_cents = balance_cents - $2 WHERE id = $1",
                           src["id"], body.amount_cents)
        await conn.execute("UPDATE accounts SET balance_cents = balance_cents + $2 WHERE id = $1",
                           dst["id"], body.amount_cents)
        tx_id = await conn.fetchval(
            """INSERT INTO transactions (from_account, to_account, amount_cents, status, label,
                                         idempotency_key, initiated_by)
               VALUES ($1, $2, $3, 'COMPLETED', $4, $5, $6) RETURNING id""",
            src["id"], dst["id"], body.amount_cents, body.label, idempotency_key, user_id)
        row = await conn.fetchrow(TX_SELECT + " WHERE t.id = $1", tx_id)

    PAYMENTS.labels("completed").inc()
    AMOUNT.observe(body.amount_cents)
    log_event(logger, "payment.completed", transaction_id=str(tx_id), user_id=str(user_id),
              amount_cents=body.amount_cents, client_ip=client_ip(request))
    return _tx_out(row)


@app.get("/payments/{tx_id}")
async def get_payment(tx_id: uuid.UUID, user: dict = Depends(current_user), pool: asyncpg.Pool = Depends(db)):
    # Anti-IDOR : la transaction n'est visible que si l'utilisateur en est l'émetteur ou le bénéficiaire.
    row = await pool.fetchrow(
        TX_SELECT + " WHERE t.id = $1 AND (fa.user_id = $2 OR ta.user_id = $2)", tx_id, uuid.UUID(user["sub"]))
    if not row:
        raise HTTPException(404, "transaction introuvable")
    return _tx_out(row)


@app.get("/payments")
async def list_payments(limit: int = 20, user: dict = Depends(current_user), pool: asyncpg.Pool = Depends(db)):
    rows = await pool.fetch(
        TX_SELECT + " WHERE fa.user_id = $1 OR ta.user_id = $1 ORDER BY t.created_at DESC LIMIT $2",
        uuid.UUID(user["sub"]), max(1, min(limit, 100)))
    return [_tx_out(r) for r in rows]


# --- Route interne : réservée au moteur de remédiation ---

class MaintenanceIn(BaseModel):
    on: bool


@app.post("/internal/maintenance")
async def maintenance(body: MaintenanceIn, authorization: str = Header(default=""),
                      pool: asyncpg.Pool = Depends(db)):
    if not hmac.compare_digest(authorization.encode(), f"Bearer {INTERNAL_TOKEN}".encode()):
        raise HTTPException(403, "accès interne refusé")
    State.maintenance = body.on
    MAINTENANCE.set(1 if body.on else 0)
    await pool.execute(
        "INSERT INTO audit_log (actor, action, details) VALUES ('remediation-engine', 'maintenance', $1::jsonb)",
        json.dumps({"on": body.on}))
    log_event(logger, "payment.maintenance", on=body.on)
    return {"maintenance": body.on}


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/ready")
async def ready(pool: asyncpg.Pool = Depends(db)):
    try:
        await pool.fetchval("SELECT 1", timeout=2)
    except Exception:
        raise HTTPException(503, "base de données indisponible")
    return {"status": "ready", "maintenance": State.maintenance,
            "time": datetime.now(timezone.utc).isoformat()}
