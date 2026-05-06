#!/usr/bin/env bash
# setup-env.sh — bootstrap a .env for the authentication service.
#
# Usage:
#   cd authentication
#   ./scripts/setup-env.sh
#
# What it does:
#   1. Copies .env.example → .env (skips if .env already exists, unless --force)
#   2. Generates CSRF_SECRET_KEY  (openssl rand -hex 32)
#   3. Generates WORKOS_COOKIE_PASSWORD  (44-char Fernet key via Python)
#   4. Generates an RSA-2048 keypair and writes JWT_PRIVATE_KEY_PEM /
#      JWT_PUBLIC_KEY_PEM as properly-escaped single-line values
#
# After running this script you still need to fill in:
#   WORKOS_CLIENT_ID  — from WorkOS Dashboard → API Keys
#   WORKOS_API_KEY    — from WorkOS Dashboard → API Keys
#
# Options:
#   --force   Overwrite an existing .env (secrets will be regenerated)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${ENV_FILE:-${SERVICE_DIR}/.env}"
ENV_EXAMPLE="${SERVICE_DIR}/.env.example"

# ── Argument parsing ──────────────────────────────────────────────────────────
FORCE=false
for arg in "$@"; do
  case "$arg" in
    --force) FORCE=true ;;
    *) echo "Unknown option: $arg" >&2; exit 1 ;;
  esac
done

# ── Step 1: copy example ──────────────────────────────────────────────────────
if [[ -f "$ENV_FILE" && "$FORCE" == false ]]; then
  echo ".env already exists — skipping copy (use --force to overwrite)"
else
  cp "$ENV_EXAMPLE" "$ENV_FILE"
  echo "Created .env from .env.example"
fi

# ── Step 2: CSRF secret ───────────────────────────────────────────────────────
CSRF_SECRET=$(openssl rand -hex 32)
python3 - <<PYEOF
import pathlib, re
path = pathlib.Path("${ENV_FILE}")
text = path.read_text()
text = re.sub(r'^CSRF_SECRET_KEY=.*$', 'CSRF_SECRET_KEY=${CSRF_SECRET}', text, flags=re.MULTILINE)
path.write_text(text)
PYEOF
 echo "Generated CSRF_SECRET_KEY"

# ── Step 3: WorkOS cookie password ───────────────────────────────────────────
# Must be exactly 32 url-safe base64-encoded bytes (Fernet key requirement)
# Fernet requires url-safe base64 WITH padding (44 chars)
COOKIE_PASSWORD=$(python3 -c "import os, base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())")
python3 - <<PYEOF
import pathlib, re
path = pathlib.Path("${ENV_FILE}")
text = path.read_text()
text = re.sub(r'^WORKOS_COOKIE_PASSWORD=.*$', 'WORKOS_COOKIE_PASSWORD=${COOKIE_PASSWORD}', text, flags=re.MULTILINE)
path.write_text(text)
PYEOF
 echo "Generated WORKOS_COOKIE_PASSWORD"

# ── Step 4: RSA keypair ───────────────────────────────────────────────────────
PRIV_PEM=$(openssl genrsa 2048 2>/dev/null)
PUB_PEM=$(echo "$PRIV_PEM" | openssl rsa -pubout 2>/dev/null)

# Generate Base64 representations, eliminating literal \n parsing problems
PRIV_B64=$(echo "$PRIV_PEM" | base64)
PUB_B64=$(echo "$PUB_PEM" | base64)

export PRIV_B64
export PUB_B64

# Python handles the multi-line replacement safely (no shell delimiter issues)
python3 - <<PYEOF
import os
import re

priv = os.environ['PRIV_B64'].replace('\n', '').strip()
pub = os.environ['PUB_B64'].replace('\n', '').strip()

with open("${ENV_FILE}", "r") as f:
    content = f.read()

# Fallback regex handling
if 'JWT_PRIVATE_KEY_PEM=' in content:
    content = re.sub(
        r'^JWT_PRIVATE_KEY_PEM=.*$',
        'JWT_PRIVATE_KEY_PEM=' + priv,
        content, flags=re.MULTILINE
    )
if 'JWT_PUBLIC_KEY_PEM=' in content:
    content = re.sub(
        r'^JWT_PUBLIC_KEY_PEM=.*$',
        'JWT_PUBLIC_KEY_PEM=' + pub,
        content, flags=re.MULTILINE
    )

with open("${ENV_FILE}", "w") as f:
    f.write(content)
PYEOF
echo "Generated JWT_PRIVATE_KEY_PEM / JWT_PUBLIC_KEY_PEM as Base64 strings"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "✓ .env is ready."
echo ""
echo "Still required — fill these in manually:"
echo "  WORKOS_CLIENT_ID  — WorkOS Dashboard → API Keys"
echo "  WORKOS_API_KEY    — WorkOS Dashboard → API Keys"
echo ""
echo "Then start the service:"
echo "  cd $(git rev-parse --show-toplevel 2>/dev/null || echo '../..')"
echo "  docker compose -f docker-compose.dev.yml up -d authentication"
