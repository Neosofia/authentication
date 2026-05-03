#!/usr/bin/env bash
# setup-env.sh — bootstrap a local .local.env for the authentication service.
#
# Usage:
#   cd authentication
#   ./scripts/setup-env.sh
#
# What it does:
#   1. Copies .local.env.example → .local.env (skips if .local.env already exists, unless --force)
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
#   --force   Overwrite an existing .local.env (secrets will be regenerated)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${ENV_FILE:-${SERVICE_DIR}/.local.env}"
ENV_EXAMPLE="${SERVICE_DIR}/.local.env.example"

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
  echo ".local.env already exists — skipping copy (use --force to overwrite)"
else
  cp "$ENV_EXAMPLE" "$ENV_FILE"
  echo "Created .local.env from .local.env.example"
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

# Collapse to single line with literal \n separators so Docker Compose / dotenv
# parsers can read the value without choking on bare newlines.
PRIV_ONELINE=$(printf '%s' "$PRIV_PEM" | awk 'NF {printf "%s\\\\n", $0}')
PUB_ONELINE=$(printf '%s' "$PUB_PEM" | awk 'NF {printf "%s\\\\n", $0}')

export PRIV_ONELINE
export PUB_ONELINE

# Python handles the multi-line replacement safely (no shell delimiter issues)
python3 - <<PYEOF
import os
import re

priv = '"' + os.environ['PRIV_ONELINE'].replace('"', '\\"') + '"'
pub = '"' + os.environ['PUB_ONELINE'].replace('"', '\\"') + '"'

with open("${ENV_FILE}", "r") as f:
    content = f.read()

content = re.sub(
    r'^JWT_PRIVATE_KEY_PEM=.*?-----END PRIVATE KEY-----',
    lambda m: 'JWT_PRIVATE_KEY_PEM=' + priv,
    content, flags=re.MULTILINE | re.DOTALL
)
content = re.sub(
    r'^JWT_PUBLIC_KEY_PEM=.*?-----END PUBLIC KEY-----',
    lambda m: 'JWT_PUBLIC_KEY_PEM=' + pub,
    content, flags=re.MULTILINE | re.DOTALL
)

# If the keys were blank in .env.example, set them directly
if 'JWT_PRIVATE_KEY_PEM=' + priv not in content:
    content = re.sub(r'^JWT_PRIVATE_KEY_PEM=$', 'JWT_PRIVATE_KEY_PEM=' + priv, content, flags=re.MULTILINE)
if 'JWT_PUBLIC_KEY_PEM=' + pub not in content:
    content = re.sub(r'^JWT_PUBLIC_KEY_PEM=$', 'JWT_PUBLIC_KEY_PEM=' + pub, content, flags=re.MULTILINE)

with open("${ENV_FILE}", "w") as f:
    f.write(content)
PYEOF
echo "Generated JWT_PRIVATE_KEY_PEM / JWT_PUBLIC_KEY_PEM"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "✓ .local.env is ready."
echo ""
echo "Still required — fill these in manually:"
echo "  WORKOS_CLIENT_ID  — WorkOS Dashboard → API Keys"
echo "  WORKOS_API_KEY    — WorkOS Dashboard → API Keys"
echo ""
echo "Then start the service:"
echo "  cd $(git rev-parse --show-toplevel 2>/dev/null || echo '../..')"
echo "  docker compose -f docker-compose.dev.yml up -d authentication"
