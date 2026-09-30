#!/usr/bin/env bash
set -euo pipefail
DB_PATH=${1:-/opt/open-prime-rmm/server/data/outpost.db}
BACKUP_DIR=${2:-/opt/open-prime-rmm/server/data/backups}
DATA_DIR=$(dirname "$DB_PATH")
APP_DIR="$DATA_DIR/applications"
mkdir -p "$BACKUP_DIR"
STAMP=$(date +%Y%m%d-%H%M%S)
OUT="$BACKUP_DIR/outpost-$STAMP.db"
APP_OUT="$BACKUP_DIR/outpost-$STAMP.applications.tar.gz"
python3 - "$DB_PATH" "$OUT" <<'PY'
import sqlite3,sys,os
src,dst=sys.argv[1:3]
s=sqlite3.connect(src,timeout=30)
d=sqlite3.connect(dst)
try:
    s.backup(d); d.commit()
    result=d.execute('PRAGMA quick_check').fetchone()[0]
finally:
    d.close(); s.close()
if result != 'ok':
    os.unlink(dst)
    raise SystemExit(f'Backup integrity check failed: {result}')
os.chmod(dst,0o600)
print(dst)
PY
chown outpost:outpost "$OUT" 2>/dev/null || true

# OpenPrimeRMM 1.30.0 application installers live beside the database rather
# than inside SQLite. Keep the historical .db backup format intact and add a
# timestamp-matched sidecar archive when application files exist.
if [[ -d "$APP_DIR" ]]; then
  tar -C "$DATA_DIR" -czf "$APP_OUT" applications
  chmod 600 "$APP_OUT"
  chown outpost:outpost "$APP_OUT" 2>/dev/null || true
  echo "Application files backup: $APP_OUT"
fi

echo "Backup created: $OUT"
