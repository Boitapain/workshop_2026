#!/bin/sh
# Rôles applicatifs à moindre privilège. Les mots de passe viennent des secrets Docker.
set -eu
AUTH_PW=$(cat /run/secrets/db_auth_password)
PAY_PW=$(cat /run/secrets/db_payment_password)
BKP_PW=$(cat /run/secrets/db_backup_password)
EXP_PW=$(cat /run/secrets/db_exporter_password)

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<SQL
CREATE ROLE auth_app    LOGIN PASSWORD '$AUTH_PW';
CREATE ROLE payment_app LOGIN PASSWORD '$PAY_PW';
CREATE ROLE backup      LOGIN PASSWORD '$BKP_PW';
CREATE ROLE exporter    LOGIN PASSWORD '$EXP_PW';

REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO auth_app, payment_app, backup, exporter;

-- auth-service
GRANT SELECT, INSERT, UPDATE ON users, refresh_tokens TO auth_app;
GRANT SELECT, UPDATE ON auth_state TO auth_app;
GRANT INSERT ON accounts TO auth_app;
GRANT INSERT ON audit_log TO auth_app;
GRANT USAGE ON SEQUENCE audit_log_id_seq TO auth_app;

-- payment-service
GRANT SELECT ON users, auth_state TO payment_app;
GRANT SELECT, UPDATE ON accounts TO payment_app;
GRANT SELECT, INSERT ON transactions TO payment_app;
GRANT INSERT ON audit_log TO payment_app;
GRANT USAGE ON SEQUENCE audit_log_id_seq TO payment_app;

-- sauvegarde et supervision
GRANT pg_read_all_data TO backup;
GRANT pg_monitor TO exporter;
SQL
