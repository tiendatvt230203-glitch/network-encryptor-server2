#!/usr/bin/env bash

set -euo pipefail

SQL_DIR="sql_options"
LOAD_ONE_SCRIPT="sh/xdp_load_option.sh"

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

echo "=== XDP LOAD ALL OPTIONS ==="
echo "DB user: ${DB_USER}"
echo "DB name: ${DB_NAME}"
echo "Host:    ${DB_HOST}"
echo "Dir:     ${SQL_DIR}"
echo

if [ ! -d "${SQL_DIR}" ]; then
  echo "Thư mục ${SQL_DIR} không tồn tại."
  exit 1
fi

shopt -s nullglob
SQL_FILES=("${SQL_DIR}"/*.sql)
shopt -u nullglob

if [ "${#SQL_FILES[@]}" -eq 0 ]; then
  echo "Không tìm thấy file .sql nào trong ${SQL_DIR}"
  exit 1
fi

if [ ! -x "${LOAD_ONE_SCRIPT}" ]; then
  echo "[FATAL] Script not executable: ${LOAD_ONE_SCRIPT}" >&2
  echo "Run: chmod +x ${LOAD_ONE_SCRIPT}" >&2
  exit 1
fi

declare -A IDS=()
for sql_file in "${SQL_FILES[@]}"; do
  base="$(basename "${sql_file}")"
  if [[ "${base}" =~ ^([0-9]+)_.*\.sql$ ]]; then
    id="${BASH_REMATCH[1]}"
    id=$((10#${id}))
    IDS["${id}"]=1
  fi
done

if [ "${#IDS[@]}" -eq 0 ]; then
  echo "[FATAL] No option files matched pattern <id>_*.sql in ${SQL_DIR}" >&2
  exit 1
fi

mapfile -t SORTED_IDS < <(printf '%s\n' "${!IDS[@]}" | sort -n)
for id in "${SORTED_IDS[@]}"; do
  echo ">>> Load option id=${id}"
  "${LOAD_ONE_SCRIPT}" "${id}"
done

echo
echo "Hoàn tất load tất cả option IDs: ${SORTED_IDS[*]}"