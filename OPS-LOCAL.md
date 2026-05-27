# Authentication Service — Local Operations

Single-box setup for developers and testers. HTTP only — no HTTPS, no cloud infrastructure.

**Before starting here**: complete [OPERATIONS.md](OPERATIONS.md) (WorkOS setup + local tooling).

---

## 1. Start the Service

### Option A — Flask on the host + Docker Postgres (fastest iteration)

Flask reloads on code changes. Best for active development.

```bash
# From the repo root:
docker compose -f docker-compose.dev.yml up -d auth-postgres
uv run alembic upgrade head
uv run python -m gunicorn -c src/gunicorn.py src.app:app
```

> To enable hot-reload and the Werkzeug debugger locally, set `ENV=development` in `.env` before running gunicorn. **Never set this in staging or production** — see [SECURITY.md §3.6](SECURITY.md#36-web-layer-defenses).

### Option B — Single Service (Docker)

Runs the production container image locally. Best for testing the built image.

```bash
# From the repo root:
docker compose -f docker-compose.dev.yml up -d authentication
docker compose -f docker-compose.dev.yml ps
```

This compose loads `.env` from the service directory (optional — the container
falls back to real environment variables if `.env` is absent).


---

## 2. Test the End-to-End Flow

1. Open http://localhost:8014 in a browser and click **Sign in**.
2. WorkOS will prompt you to authenticate as your test user.
3. After authentication, you'll be redirected back to the homepage showing your user info.
4. Click **Sign out** and verify you're returned to the login page.
5. Click **Sign in** again.
6. **Important**: Verify you see the WorkOS login form (not instant re-authentication) — this proves the logout actually revoked your session server-side.

---

## 3. Service Credentials (service-to-service)

Migration `002` registers the `authentication` service and creates its first
credential with a randomly generated secret. The plaintext is printed once when
the migration runs (container startup logs or `alembic upgrade head` output).
Only the bcrypt hash is stored in `service_credentials`; the secret cannot be
read back from the database.

Look up the service row to confirm registration:

```sql
SELECT s.slug, sc.uuid AS credential_uuid, sc.changed_at
FROM services s
JOIN service_credentials sc ON sc.service_uuid = s.uuid
WHERE s.slug = 'authentication';
```

Then request a service token using the secret captured from migration output:

```bash
curl -X POST http://localhost:8014/api/token \
  -H "Authorization: Basic $(echo -n 'authentication:YOUR_SECRET' | base64)" \
  -d "grant_type=client_credentials"
```

Expected response: `{"access_token": "eyJ...", "token_type": "Bearer", "expires_in": 300}`

---

## 4. Run the Test Suite

The test suite uses pytest with mocked external dependencies (WorkOS, Postgres). No live services required.

**On the host (fastest):**

```bash
SCHEMAS_DIR=../schemas uv run pytest tests/ -v

# Specific layer
SCHEMAS_DIR=../schemas uv run pytest tests/unit/ -v
SCHEMAS_DIR=../schemas uv run pytest tests/integration/ -v
SCHEMAS_DIR=../schemas uv run pytest tests/contract/ -v

# Specific test
SCHEMAS_DIR=../schemas uv run pytest tests/unit/test_api_routes.py::TestCSRFExemption -v
```

**Container integration tests (builds the image, spins up Postgres + authentication):**

```bash
# First run or after any src/ change — force a clean image rebuild to avoid stale layer cache
docker build --no-cache -t authentication-authentication .

SCHEMAS_DIR=../schemas uv run pytest tests/integration/test_container.py -v --no-cov
```

> The `--build` flag used by the test fixture reuses Docker layer cache. Run `docker build --no-cache` whenever `src/` changes so the container image is up to date before running these tests.

---

## 5. Troubleshooting

| Symptom | Likely cause |
|---------|-------------|
| `{"detail": "invalid_grant"}` | Code already used, expired (10-min window), or `redirect_uri` mismatch |
| `{"detail": "WorkOS unavailable"}` | Wrong `WORKOS_API_KEY` or network issue |
| User doesn't authenticate / org membership error | User has no active org role in WorkOS — add to org with explicit role |
| `redirect_uri` rejected by WorkOS | URI not registered in WorkOS application Redirects tab |
| Blank page after login | Check browser console; verify `src/templates/index.html` exists |
| "Error authenticating with code" | Check `WORKOS_API_KEY`, `WORKOS_CLIENT_ID`, and that redirect URI matches WorkOS dashboard; code expires after 10 min |
| Logout doesn't show WorkOS form on next login | Verify `WORKOS_COOKIE_PASSWORD` is a valid 32-character string |
| Session cookie missing after login | Check `auth_response.sealed_session` is non-empty; DevTools → Cookies for `wos_session` (`Secure`, `SameSite=None`). UI origin must match `FRONTEND_URL` (CORS + credentialed `/api/token`) |
