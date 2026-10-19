"""auth-service — inscription, connexion, jetons JWT RS256, révocation."""
import base64
import hashlib
import hmac
import json
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import asyncpg
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from cryptography.hazmat.primitives import serialization
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from prometheus_client import Counter
from prometheus_fastapi_instrumentator import Instrumentator
from pydantic import BaseModel, EmailStr, Field

from resilience_common import RequestContextMiddleware, client_ip, log_event, read_secret, setup_logging

logger = setup_logging()

ACCESS_TTL = timedelta(minutes=10)
REFRESH_TTL = timedelta(hours=24)
LOCK_AFTER = 5
INITIAL_BALANCE_CENTS = 100_000  # 1 000 € fictifs à l'ouverture, pour la démo

LOGINS = Counter("auth_login_total", "Tentatives de connexion", ["result"])
REVOCATIONS = Counter("auth_revocations_total", "Révocations déclenchées", ["scope"])

ph = PasswordHasher()
# Hash factice : on vérifie quand même un mot de passe pour un email inconnu (temps constant, anti-énumération).
DUMMY_HASH = ph.hash(secrets.token_urlsafe(16))

_private_key = serialization.load_pem_private_key(read_secret("jwt_private_key").encode(), password=None)
_public_numbers = _private_key.public_key().public_numbers()
_public_pem = _private_key.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
)
KID = hashlib.sha256(_public_pem).hexdigest()[:16]
INTERNAL_TOKEN = read_secret("internal_token")


def _b64u(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


JWKS = {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": KID,
                  "n": _b64u(_public_numbers.n), "e": _b64u(_public_numbers.e)}]}


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.pool = await asyncpg.create_pool(
        host="postgres", database="resilience", user="auth_app",
        password=read_secret("db_auth_password"), min_size=1, max_size=10,
    )
    yield
    await app.state.pool.close()


app = FastAPI(title="auth-service", lifespan=lifespan, docs_url=None, redoc_url=None)
app.add_middleware(RequestContextMiddleware, logger=logger)
Instrumentator().instrument(app).expose(app, include_in_schema=False)


async def db(request: Request) -> asyncpg.Pool:
    return request.app.state.pool


class Credentials(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)


class RefreshIn(BaseModel):
    refresh_token: str = Field(max_length=200)


def _hash_refresh(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def _issue_tokens(conn: asyncpg.Connection, user_id: uuid.UUID, role: str) -> dict:
    epoch = await conn.fetchval("SELECT epoch FROM auth_state WHERE id = 1")
    now = datetime.now(timezone.utc)
    access = jwt.encode(
        {"sub": str(user_id), "role": role, "epoch": epoch, "jti": uuid.uuid4().hex,
         "iat": int(now.timestamp()), "exp": int((now + ACCESS_TTL).timestamp())},
        _private_key, algorithm="RS256", headers={"kid": KID},
    )
    refresh = secrets.token_urlsafe(48)
    await conn.execute(
        "INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)",
        user_id, _hash_refresh(refresh), now + REFRESH_TTL,
    )
    return {"access_token": access, "refresh_token": refresh, "token_type": "Bearer",
            "expires_in": int(ACCESS_TTL.total_seconds())}


def _new_iban() -> str:
    return "FR76-RSLA-" + "-".join(f"{secrets.randbelow(10000):04d}" for _ in range(3))


@app.post("/auth/register", status_code=201)
async def register(body: Credentials, request: Request, pool: asyncpg.Pool = Depends(db)):
    async with pool.acquire() as conn, conn.transaction():
        exists = await conn.fetchval("SELECT 1 FROM users WHERE email = $1", body.email.lower())
        if exists:
            raise HTTPException(409, "compte déjà existant")
        user_id = await conn.fetchval(
            "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id",
            body.email.lower(), ph.hash(body.password),
        )
        iban = _new_iban()
        await conn.execute(
            "INSERT INTO accounts (user_id, iban, balance_cents) VALUES ($1, $2, $3)",
            user_id, iban, INITIAL_BALANCE_CENTS,
        )
        await conn.execute(
            "INSERT INTO audit_log (actor, action, details) VALUES ('user', 'register', $1::jsonb)",
            json.dumps({"user_id": str(user_id)}),
        )
    log_event(logger, "auth.register", user_id=str(user_id), client_ip=client_ip(request))
    return {"user_id": str(user_id), "iban": iban}


@app.post("/auth/login")
async def login(body: Credentials, request: Request, pool: asyncpg.Pool = Depends(db)):
    ip = client_ip(request)
    async with pool.acquire() as conn:
        user = await conn.fetchrow(
            "SELECT id, password_hash, role, failed_logins, locked_until FROM users WHERE email = $1",
            body.email.lower(),
        )
        now = datetime.now(timezone.utc)
        if user and user["locked_until"] and user["locked_until"] > now:
            LOGINS.labels("locked").inc()
            log_event(logger, "auth.login.locked", user_id=str(user["id"]), client_ip=ip)
            raise HTTPException(429, "compte temporairement verrouillé")
        try:
            ph.verify(user["password_hash"] if user else DUMMY_HASH, body.password)
            ok = user is not None
        except VerificationError:
            ok = False

        if not ok:
            LOGINS.labels("failure").inc()
            if user:
                failed = user["failed_logins"] + 1
                locked_until = None
                if failed >= LOCK_AFTER:
                    # Verrouillage progressif : 30 s, 60 s, 120 s… plafonné à 15 min.
                    locked_until = now + timedelta(seconds=min(30 * 2 ** (failed - LOCK_AFTER), 900))
                await conn.execute(
                    "UPDATE users SET failed_logins = $2, locked_until = $3 WHERE id = $1",
                    user["id"], failed, locked_until,
                )
            log_event(logger, "auth.login.failure", client_ip=ip,
                      known_user=user is not None, user_agent=request.headers.get("user-agent", "-")[:120])
            raise HTTPException(401, "identifiants invalides")

        async with conn.transaction():
            await conn.execute(
                "UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = $1", user["id"]
            )
            tokens = await _issue_tokens(conn, user["id"], user["role"])
    LOGINS.labels("success").inc()
    log_event(logger, "auth.login.success", user_id=str(user["id"]), client_ip=ip)
    return tokens


@app.post("/auth/refresh")
async def refresh(body: RefreshIn, pool: asyncpg.Pool = Depends(db)):
    async with pool.acquire() as conn, conn.transaction():
        row = await conn.fetchrow(
            """UPDATE refresh_tokens SET revoked_at = now()
               WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()
               RETURNING user_id""",
            _hash_refresh(body.refresh_token),
        )
        if not row:
            raise HTTPException(401, "refresh token invalide")
        role = await conn.fetchval("SELECT role FROM users WHERE id = $1", row["user_id"])
        return await _issue_tokens(conn, row["user_id"], role)


@app.post("/auth/logout", status_code=204)
async def logout(body: RefreshIn, pool: asyncpg.Pool = Depends(db)):
    await pool.execute(
        "UPDATE refresh_tokens SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL",
        _hash_refresh(body.refresh_token),
    )


@app.get("/.well-known/jwks.json")
async def jwks():
    return JWKS


# --- Routes internes : réservées au moteur de remédiation (réseau control + jeton de service) ---

def require_internal(authorization: str = Header(default="")):
    expected = f"Bearer {INTERNAL_TOKEN}"
    if not hmac.compare_digest(authorization.encode(), expected.encode()):
        raise HTTPException(403, "accès interne refusé")


class RevokeIn(BaseModel):
    scope: str = Field(pattern="^(global|users|recent_failures)$")
    user_ids: list[uuid.UUID] = []
    since_seconds: int = Field(default=120, ge=10, le=3600)


@app.post("/internal/revoke", dependencies=[Depends(require_internal)])
async def internal_revoke(body: RevokeIn, pool: asyncpg.Pool = Depends(db)):
    async with pool.acquire() as conn, conn.transaction():
        if body.scope == "global":
            epoch = await conn.fetchval("UPDATE auth_state SET epoch = epoch + 1 WHERE id = 1 RETURNING epoch")
            await conn.execute("UPDATE refresh_tokens SET revoked_at = now() WHERE revoked_at IS NULL")
            affected = {"epoch": epoch}
        else:
            if body.scope == "recent_failures":
                # Comptes ayant subi des échecs de connexion récents : sessions potentiellement compromises.
                ids = [r["id"] for r in await conn.fetch(
                    "SELECT id FROM users WHERE failed_logins > 0 AND role = 'customer'")]
            else:
                ids = body.user_ids
            await conn.execute("UPDATE users SET tokens_valid_after = now() WHERE id = ANY($1::uuid[])", ids)
            await conn.execute(
                "UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = ANY($1::uuid[]) AND revoked_at IS NULL",
                ids,
            )
            affected = {"users": len(ids)}
        await conn.execute(
            "INSERT INTO audit_log (actor, action, details) VALUES ('remediation-engine', 'revoke', $1::jsonb)",
            json.dumps({"scope": body.scope, **affected}),
        )
    REVOCATIONS.labels(body.scope).inc()
    log_event(logger, "auth.revoke", scope=body.scope, **affected)
    return {"scope": body.scope, **affected}


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/ready")
async def ready(pool: asyncpg.Pool = Depends(db)):
    try:
        await pool.fetchval("SELECT 1", timeout=2)
    except Exception:
        raise HTTPException(503, "base de données indisponible")
    return {"status": "ready", "time": time.time()}
