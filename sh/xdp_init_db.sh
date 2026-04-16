#!/usr/bin/env bash

set -euo pipefail

if [ -f "/opt/db.env" ]; then
  . "/opt/db.env"
else
  echo "[FATAL] Env file not found: /opt/db.env" >&2
  exit 1
fi

: "${DB_HOST:?DB_HOST is required}"
: "${DB_PORT:?DB_PORT is required}"
: "${DB_USER:?DB_USER is required}"
: "${DB_NAME:?DB_NAME is required}"
: "${DB_PASS:?DB_PASS is required}"

export PGPASSWORD="$DB_PASS"

force_drop_database() {
  local db_name="$1"

  # PostgreSQL 13+ supports WITH (FORCE).
  if psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d postgres \
      -v ON_ERROR_STOP=1 \
      -c "DROP DATABASE IF EXISTS ${db_name} WITH (FORCE);" >/dev/null 2>&1; then
    return 0
  fi

  # Fallback for older versions: block new connects, terminate old sessions, then drop.
  psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d postgres -v ON_ERROR_STOP=1 <<SQL
ALTER DATABASE ${db_name} WITH ALLOW_CONNECTIONS = false;
REVOKE CONNECT ON DATABASE ${db_name} FROM PUBLIC;
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE datname = '${db_name}'
  AND pid <> pg_backend_pid();
DROP DATABASE IF EXISTS ${db_name};
SQL
}

echo "=== XDP DB INIT ==="
echo "User:    ${DB_USER}"
echo "DB name: ${DB_NAME}"
echo "Host:    ${DB_HOST}"
echo

echo "[1/3] Drop database if exists: ${DB_NAME}"
force_drop_database "${DB_NAME}"

echo "[2/3] Create database: ${DB_NAME}"
createdb -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" "${DB_NAME}"

echo "[3/3] Create tables from schema.sql"
psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -f schema.sql

echo
echo "Done. Database ${DB_NAME} is clean and has tables ready."