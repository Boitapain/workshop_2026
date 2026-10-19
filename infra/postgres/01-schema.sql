-- RESILIENCE-ALPHA — schéma métier
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email           text NOT NULL UNIQUE,
    password_hash   text NOT NULL,
    role            text NOT NULL DEFAULT 'customer' CHECK (role IN ('customer', 'probe', 'admin')),
    failed_logins   int  NOT NULL DEFAULT 0,
    locked_until    timestamptz,
    tokens_valid_after timestamptz NOT NULL DEFAULT to_timestamp(0),
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE accounts (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         uuid NOT NULL REFERENCES users(id),
    iban            text NOT NULL UNIQUE,
    balance_cents   bigint NOT NULL DEFAULT 0 CHECK (balance_cents >= 0),
    currency        text NOT NULL DEFAULT 'EUR'
);
CREATE INDEX accounts_user_idx ON accounts(user_id);

CREATE TABLE transactions (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    from_account    uuid NOT NULL REFERENCES accounts(id),
    to_account      uuid NOT NULL REFERENCES accounts(id),
    amount_cents    bigint NOT NULL CHECK (amount_cents > 0),
    status          text NOT NULL CHECK (status IN ('PENDING', 'COMPLETED', 'REJECTED')),
    label           text,
    idempotency_key text NOT NULL,
    initiated_by    uuid NOT NULL REFERENCES users(id),
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (initiated_by, idempotency_key)
);
CREATE INDEX transactions_from_idx ON transactions(from_account, created_at DESC);
CREATE INDEX transactions_to_idx   ON transactions(to_account, created_at DESC);

CREATE TABLE refresh_tokens (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid NOT NULL REFERENCES users(id),
    token_hash  text NOT NULL UNIQUE,
    expires_at  timestamptz NOT NULL,
    revoked_at  timestamptz
);

-- Époque globale des jetons : l'incrémenter invalide tous les JWT émis avant.
CREATE TABLE auth_state (
    id          int PRIMARY KEY CHECK (id = 1),
    epoch       int NOT NULL DEFAULT 1
);
INSERT INTO auth_state (id, epoch) VALUES (1, 1);

CREATE TABLE audit_log (
    id          bigserial PRIMARY KEY,
    at          timestamptz NOT NULL DEFAULT now(),
    actor       text NOT NULL,
    action      text NOT NULL,
    details     jsonb NOT NULL DEFAULT '{}'
);
