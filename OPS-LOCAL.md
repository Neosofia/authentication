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
uv run flask --app src.main:app run --port 8014
```

### Option B — Single Service (Docker)

Runs the production container image locally. Best for testing the built image.

```bash
# From the repo root:
docker compose -f docker-compose.dev.yml up -d authentication
docker compose -f docker-compose.dev.yml ps
```

This compose uses `ENV=development` and expects the corresponding env file
for the selected environment to exist. In this local setup, the service loads
`.dev.env` as the selected file and also mounts it as `.env` for bootstrap
compatibility.

If you want to run with a different environment, set `ENV` explicitly and
provide the matching file:

- `ENV=local` → `.local.env`
- `ENV=development` / `ENV=dev` → `.dev.env`
- `ENV=staging` → `.staging.env`
- `ENV=production` / `ENV=prod` → `.prod.env`

You can also override the exact file with `ENV_FILE` if needed.

The selected file must exist, otherwise startup fails fast.

> **Do not** run `docker compose up -d` from inside a nested checkout path; always run from the repository root.
> The per-service compose file omits shared infrastructure (Traefik, LocalStack
> secret seeding) and will fail to start correctly.
>
> To bring up the full platform, omit the service name: `docker compose -f docker-compose.dev.yml up -d`

---

## 2. Test the End-to-End Flow

1. Open http://localhost:8014 in a browser and click **Sign in**.
2. WorkOS will prompt you to authenticate as your test clinician user.
3. After authentication, you'll be redirected back to the homepage showing your user info.
4. Click **Sign out** and verify you're returned to the login page.
5. Click **Sign in** again.
6. **Important**: Verify you see the WorkOS login form (not instant re-authentication) — this proves the logout actually revoked your session server-side.

---

## 3. Machine Credentials (service-to-service)

The `test-service` credential is seeded automatically by the Alembic migration
when `SEED_MACHINE_SECRET` is set. Set it in `.env`, then run migrations:

```bash
# .env must contain: SEED_MACHINE_SECRET=secret
uv run alembic upgrade head
```

Then request a machine token:

```bash
curl -X POST http://localhost:8014/api/token \
  -H "Authorization: Basic $(echo -n 'test-service:secret' | base64)" \
  -d "grant_type=client_credentials"
```

Expected response: `{"access_token": "eyJ...", "token_type": "Bearer", "expires_in": 300}`

---

## 4. Run the Test Suite

The test suite uses pytest with mocked external dependencies (WorkOS, Postgres). No live services required.

**On the host (fastest):**

```bash
uv run pytest tests/ -v

# Specific file
uv run pytest tests/test_api.py -v
uv run pytest tests/test_auth_routes.py -v

# Specific test class or test
uv run pytest tests/test_api.py::TestTokenClientCredentials -v
uv run pytest tests/test_api.py::TestHealth::test_ok_when_db_available -v
```

**Inside a running container:**

```bash
# From the repo root:
docker compose -f docker-compose.dev.yml up -d authentication
docker compose -f docker-compose.dev.yml exec authentication uv run pytest tests/ -v
```

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
| Session cookie missing after login | Check `auth_response.sealed_session` is non-empty; check DevTools → Application → Cookies for `wos_session` |
