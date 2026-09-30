#!/usr/bin/env bash
# OpenPrimeRMM interactive Linux installer
# Supports Debian/Ubuntu directly, with best-effort Fedora/openSUSE support.
set -euo pipefail

APP_NAME="OpenPrimeRMM"
SERVICE_NAME="open-prime-rmm"
SERVICE_USER="openprime"
APP_DIR="/opt/open-prime-rmm"
ENV_FILE="/etc/open-prime-rmm.env"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_PORT="8420"

say(){ printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
warn(){ printf '\033[1;33mWARN:\033[0m %s\n' "$*" >&2; }
fail(){ printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }
ask(){ local prompt="$1" default="${2:-}" value=""; if [ -n "$default" ]; then read -r -p "$prompt [$default]: " value; printf '%s' "${value:-$default}"; else read -r -p "$prompt: " value; printf '%s' "$value"; fi; }
yesno(){ local prompt="$1" default="${2:-Y}" value=""; read -r -p "$prompt [$default/n]: " value; value="${value:-$default}"; [[ "$value" =~ ^[Yy] ]]; }
rand(){ openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c "$1"; }

[ "$(id -u)" -eq 0 ] || fail "Run as root: sudo bash install.sh"
[ -f "$SRC_DIR/server/app.py" ] || fail "Run from the OpenPrimeRMM project folder; server/app.py not found."
command -v systemctl >/dev/null 2>&1 || fail "systemd is required for the auto-start service."

DOMAIN="${1:-}"
if [ -z "$DOMAIN" ]; then DOMAIN="$(ask 'Public DNS name for this RMM server, or blank for LAN/IP-only' '')"; fi
PORT="$(ask 'Internal application port' "$DEFAULT_PORT")"
COMPANY="$(ask 'Company/display name shown in reports' 'OpenPrimeRMM')"
USE_CADDY="no"
if [ -n "$DOMAIN" ]; then if yesno "Install/configure Caddy for automatic HTTPS on $DOMAIN?" "Y"; then USE_CADDY="yes"; fi; fi
ROTATE="no"
if [ -f "$ENV_FILE" ]; then if yesno "$ENV_FILE exists. Keep existing secrets/enroll key?" "Y"; then ROTATE="no"; else ROTATE="yes"; fi; fi

source_os="unknown"
if [ -r /etc/os-release ]; then . /etc/os-release; source_os="${ID:-unknown}"; fi
say "Installing dependencies for $source_os..."
case "$source_os" in
  debian|ubuntu|linuxmint|pop)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y python3 python3-venv python3-pip openssl curl ca-certificates gnupg rsync
    if [ "$USE_CADDY" = "yes" ] && ! command -v caddy >/dev/null 2>&1; then
      apt-get install -y debian-keyring debian-archive-keyring apt-transport-https
      curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
      curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
      apt-get update && apt-get install -y caddy
    fi
    ;;
  fedora|rhel|centos|rocky|almalinux)
    dnf install -y python3 python3-pip openssl curl ca-certificates rsync || yum install -y python3 python3-pip openssl curl ca-certificates rsync
    [ "$USE_CADDY" = "yes" ] && ! command -v caddy >/dev/null 2>&1 && dnf install -y 'dnf-command(copr)' && dnf copr enable -y @caddy/caddy && dnf install -y caddy || true
    ;;
  opensuse*|suse|sles)
    zypper --non-interactive install python3 python3-pip python3-venv openssl curl ca-certificates rsync
    [ "$USE_CADDY" = "yes" ] && ! command -v caddy >/dev/null 2>&1 && zypper --non-interactive install caddy || true
    ;;
  *)
    fail "Unsupported distro '$source_os'. Install python3, venv, pip, openssl, curl, and Caddy manually, then re-run."
    ;;
esac

say "Creating service user and installing files..."
id -u "$SERVICE_USER" >/dev/null 2>&1 || useradd -r -d "$APP_DIR" -s /usr/sbin/nologin "$SERVICE_USER" 2>/dev/null || useradd -r -d "$APP_DIR" -s /sbin/nologin "$SERVICE_USER"
mkdir -p "$APP_DIR"
rsync -a --delete --exclude '.git' --exclude '.venv' --exclude '__pycache__' --exclude 'server/data' "$SRC_DIR/" "$APP_DIR/"
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --upgrade pip
"$APP_DIR/venv/bin/pip" install -r "$APP_DIR/server/requirements.txt"
mkdir -p "$APP_DIR/server/data" "$APP_DIR/server/data/backups" "$APP_DIR/server/data/applications"
chown -R "$SERVICE_USER:$SERVICE_USER" "$APP_DIR"

if [ ! -f "$ENV_FILE" ] || [ "$ROTATE" = "yes" ]; then
  say "Generating unique instance secrets..."
  ADMIN_PW="$(rand 24)"
  ENROLL="$(rand 36)"
  SESSION_SECRET="$(rand 48)"
  READONLY_TOKEN="$(rand 48)"
  cat > "$ENV_FILE" <<EOF_ENV
OUTPOST_ADMIN_PASSWORD=$ADMIN_PW
OUTPOST_ENROLL_KEY=$ENROLL
OUTPOST_COMPANY_NAME=$COMPANY
OUTPOST_SESSION_SECRET=$SESSION_SECRET
OUTPOST_READONLY_API_TOKEN=$READONLY_TOKEN
OUTPOST_DATA_DIR=$APP_DIR/server/data
EOF_ENV
  chmod 600 "$ENV_FILE"
else
  say "Keeping existing secrets in $ENV_FILE."
fi
. "$ENV_FILE"

say "Installing systemd auto-start service..."
cat > "/etc/systemd/system/$SERVICE_NAME.service" <<EOF_SERVICE
[Unit]
Description=$APP_NAME server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$APP_DIR/server
EnvironmentFile=$ENV_FILE
ExecStart=$APP_DIR/venv/bin/uvicorn app:app --host 127.0.0.1 --port $PORT
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=full
ReadWritePaths=$APP_DIR/server/data

[Install]
WantedBy=multi-user.target
EOF_SERVICE
systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"
sleep 2
systemctl is-active --quiet "$SERVICE_NAME" || fail "$SERVICE_NAME failed to start; run: journalctl -u $SERVICE_NAME -n 80 --no-pager"

if [ "$USE_CADDY" = "yes" ]; then
  command -v caddy >/dev/null 2>&1 || warn "Caddy was requested but is not installed; skipping reverse proxy."
  if command -v caddy >/dev/null 2>&1; then
    say "Configuring Caddy for https://$DOMAIN ..."
    cat > /etc/caddy/Caddyfile <<EOF_CADDY
$DOMAIN {
    reverse_proxy 127.0.0.1:$PORT
}
EOF_CADDY
    systemctl enable --now caddy || true
    systemctl reload caddy || systemctl restart caddy
  fi
fi

BASE_URL="http://127.0.0.1:$PORT"
[ -n "$DOMAIN" ] && BASE_URL="https://$DOMAIN"
PUBLIC_IP="$(curl -4fsS --max-time 5 https://ifconfig.me 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}' || true)"
cat <<EOF_DONE

=========================================================================
  OpenPrimeRMM installed and running.
=========================================================================
  Dashboard      : $BASE_URL
  Local test     : http://127.0.0.1:$PORT
  Admin password : $OUTPOST_ADMIN_PASSWORD
  Enroll key     : $OUTPOST_ENROLL_KEY
  Read-only API  : configured in $ENV_FILE
  Secrets file   : $ENV_FILE (root-only; back it up securely)

  If using public HTTPS, point DNS A record $DOMAIN to: ${PUBLIC_IP:-your public IP}
  and forward TCP 80/443 to this server.

  First Windows agent install, run PowerShell as Administrator:
    irm $BASE_URL/downloads/Install-Agent.ps1 -OutFile \$env:TEMP\\Install-Agent.ps1
    & \$env:TEMP\\Install-Agent.ps1 -ServerUrl $BASE_URL -EnrollKey '$OUTPOST_ENROLL_KEY' -OrgName 'Default'

  Useful commands:
    systemctl status $SERVICE_NAME --no-pager
    journalctl -u $SERVICE_NAME -f
=========================================================================
EOF_DONE
