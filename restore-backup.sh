#!/usr/bin/env bash
set -euo pipefail

BACKUP=${1:-}
DB_PATH=${2:-/opt/open-prime-rmm/server/data/outpost.db}

if [[ -z "$BACKUP" || ! -f "$BACKUP" ]]; then
  echo "Usage: sudo $0 /path/to/outpost-YYYYMMDD-HHMMSS.db [database-path]" >&2
  exit 2
fi

python3 - "$BACKUP" <<'PY'
import sqlite3,sys
path=sys.argv[1]
con=sqlite3.connect(path)
try:
    result=con.execute('PRAGMA quick_check').fetchone()[0]
finally:
    con.close()
if result != 'ok':
    raise SystemExit(f'Backup integrity check failed: {result}')
print('Backup integrity: ok')
PY

STAMP=$(date +%Y%m%d-%H%M%S)
DATA_DIR=$(dirname "$DB_PATH")
APP_DIR="$DATA_DIR/applications"
APP_BACKUP="${BACKUP%.db}.applications.tar.gz"
CURRENT_BACKUP="${DB_PATH}.before-restore-${STAMP}"
CURRENT_APP_BACKUP="${APP_DIR}.before-restore-${STAMP}"

systemctl stop outpost
trap 'systemctl start outpost >/dev/null 2>&1 || true' EXIT

if [[ -f "$DB_PATH" ]]; then
  cp -a "$DB_PATH" "$CURRENT_BACKUP"
  echo "Current database saved as: $CURRENT_BACKUP"
fi
rm -f "${DB_PATH}-wal" "${DB_PATH}-shm"
install -m 600 -o outpost -g outpost "$BACKUP" "$DB_PATH"

# Backups created by 1.30.0+ may include the matching installer-file sidecar.
# Old database-only backups remain fully supported.
if [[ -f "$APP_BACKUP" ]]; then
  if [[ -d "$APP_DIR" ]]; then
    mv "$APP_DIR" "$CURRENT_APP_BACKUP"
    echo "Current application files saved as: $CURRENT_APP_BACKUP"
  fi
  mkdir -p "$DATA_DIR"
  tar -C "$DATA_DIR" -xzf "$APP_BACKUP"
  chown -R outpost:outpost "$APP_DIR" 2>/dev/null || true
  echo "Application files restored from: $APP_BACKUP"
else
  echo "No matching application-files sidecar found; existing application files were left unchanged."
fi

systemctl start outpost
trap - EXIT
systemctl status outpost --no-pager -l

echo "Restore complete."
