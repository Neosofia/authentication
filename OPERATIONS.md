# Authentication Service — Operations

Common setup required for **all** deployment paths: local single-box and cloud (Proxmox + NetBird).
After completing the steps here, choose your path in [§4](#4-choose-your-path).

---

## 1. Local Tooling

| Tool | Purpose | Install |
|------|---------|---------|
| Docker Desktop | Container runtime | [docs.docker.com](https://docs.docker.com/get-docker/) |
| `uv` | Python package manager | [ADR-0005](https://github.com/Neosofia/cdp/blob/main/architecture/structurizr/decisions/0005-use-uv-for-python-package-management.md) |
| `openssl` | Secret generation | ships with macOS / most Linux distros |

Install Python dependencies. Use `--frozen` for reproducible installs that match the committed `uv.lock` hashes (enforced in CI — see [SECURITY.md §3.9](SECURITY.md#39-platform--supply-chain)):

```bash
uv sync --frozen
```

---

## 2. Configure WorkOS

### Create an application

1. Sign in to [dashboard.workos.com](https://dashboard.workos.com).
2. Go to **Authentication** (left sidebar under Products).
3. Click **Set up now** or **Create application**.
4. Create an OAuth application:
   - Name: `neosofia-auth-local`
   - Environment: **Staging**
   - Type: **OAuth**
5. Add redirect URIs — use the value that matches your deployment path:
   - Local: `http://localhost:8014/callback`
   - Cloud/dev: `https://auth.dev.<your-base-domain>/callback`
6. Set **App homepage URL** and sign-out redirect to match.

### Get credentials

Copy the **environment-level credentials** from **API Keys** on the overview page:

- **Client ID** — looks like `client_01ABC…`
- **API Key** — looks like `sk_test_ABC…`

> **IMPORTANT**: Use **environment-level** credentials (from API Keys), NOT the OAuth app's Client ID.

### JWT Template

The service reads tenant fields **only** from the WorkOS access-token JWT (custom-claims template). It does not use `org_id`, auth-response `organization_id`, or database lookups as substitutes.

1. In the WorkOS Dashboard go to **Authentication → Sessions → Custom claims**.
2. Add this template:

```json
{
  "workos_tenant_name": "{{ organization.name }}",
  "workos_tenant_id": "{{ organization.id }}",
  "tenant_uuid": "{{ organization.external_id }}"
}
```

`workos_tenant_id` is the WorkOS organization id; `tenant_uuid` is the platform tenant UUID (`organization.external_id`). They are not interchangeable.

**OAuth callback** (before sealing the session):

1. **User** — if `user.external_id` is empty, generate UUIDv7 and `update_user` (using the WorkOS `user_id` as the API key).
2. **Organization** — if the JWT has `workos_tenant_id` but no `tenant_uuid`, `update_organization` to set `external_id` to UUIDv7 (using `workos_tenant_id` as the API key).
3. **Session refresh** — if either step ran or the JWT still lacks `tenant_uuid`, `authenticate_with_refresh_token` so the access token and `auth_response.user` reflect the new `external_id` values.
4. **Claims** — read `workos_tenant_id`, `workos_tenant_name`, and `tenant_uuid` from the JWT only (no fallbacks).

All users must have organization membership and a role in `VALID_ROLES`.

### Session Timeouts

> [!CAUTION]
> The WorkOS sandbox defaults are dangerously permissive (365-day sessions, 2-day inactivity timeout). **You must change these before any testing.** Leaving defaults in place violates the platform's clinical safety posture — a compromised or abandoned session could remain valid for almost a year.

1. Go to **Authentication → Sessions → Session lifetime**.
2. Set:

   | Setting | Value | WorkOS default |
   |---------|-------|----------------|
   | Maximum session length | 12 hours | 365 days |
   | Access token duration | 5 minutes | 5 minutes |
   | Inactivity timeout | 30 minutes | 2 days |

3. Save.

### Test Organization and Users

#### Organization

> [!CAUTION]
> **Do not use the "Default Test Organization" automatically created by WorkOS.** WorkOS blocks API updates on that org; login will fail when the callback tries to set `external_id`. Create your own organization instead.

1. Go to **Organizations** → **Create Organization**.
2. Name it e.g. `Neosofia Test Clinic` (the callback will set **External ID** on first login if it is empty).
3. Go to roles and create your top-level application actor roles: `operator`, `clinician`, and `patient`.

#### Test user

1. Go to **Users** → **Create User**.
2. Fill in name + email (use a real email you can receive).
3. Select the user → **Organization Memberships** → **Add Member**.
4. Select your test organization and assign one of your configured roles.

> **Note**: All users must have an explicit org role assignment. Users without org membership are rejected at token issuance. Assign `operator` only to system operators; it grants access to global platform administration endpoints such as service credential management.

---

## 3. Generate Environment Secrets

Run the setup script — it generates secrets (RSA keypair, CSRF key, cookie password, app DB password) and writes `.env`:

```bash
uv run python scripts/setup-env.py
```

Then open `.env` and fill in the two WorkOS values from §2:

```dotenv
WORKOS_CLIENT_ID=client_...   # WorkOS Dashboard → API Keys
WORKOS_API_KEY=sk_test_...    # WorkOS Dashboard → API Keys
WORKOS_REDIRECT_URI=...       # must match the redirect URI you registered in §2
```

See [Appendix A](#appendix-a-environment-variable-reference) for the full variable reference.

---

## 4. Choose Your Path

| | [OPS-LOCAL](OPS-LOCAL.md) | [OPS-CLOUD](OPS-CLOUD.md) |
|---|---|---|
| **Best for** | Developers, unit testers, CI | QA with HTTPS, staging/prod operators |
| **Runs on** | Your laptop (Docker Compose) | Proxmox LXC + NetBird reverse proxy |
| **HTTPS** | No (HTTP only) | Yes — public TLS via NetBird custom domain |
| **Secrets** | Local `.env` file | AWS Secrets Manager + KMS |
| **Infrastructure** | None | AWS (state/secrets) + Proxmox (compute) |
| **Setup time** | ~5 minutes | ~30 minutes first time |

→ **[OPS-LOCAL.md](OPS-LOCAL.md)** — start here if you just want to run and test the service locally.

→ **[OPS-CLOUD.md](OPS-CLOUD.md)** — start here if you need HTTPS, are deploying to a shared environment, or are operating staging/prod.

→ **[Public cloud platform operations](https://github.com/Neosofia/infrastructure/blob/main/public-cloud/OPERATIONS.md)** — shared JWT, JWKS, CORS, healthcheck, and PaaS networking guidance for authentication and all downstream consumers (capabilities, python-template, etc.).

- **CORS preflight cache:** OPTIONS responses include `Access-Control-Max-Age: 86400` (24 h; Chrome caps at 2 h) so browsers cache cross-origin preflights.

---

## 5. Database Roles and URLs

Authentication always uses **two** PostgreSQL roles:

| Role | Env var | Used by | Permissions |
|------|---------|---------|-------------|
| Superuser (e.g. `auth`) | `MIGRATION_DATABASE_URL` | Alembic on container start / deploy | DDL, audit schema, `CREATE ROLE app` |
| Restricted `app` | `APP_DATABASE_URL` | Running web service | `SELECT`, `INSERT`, `UPDATE` only; subject to RLS |

Migration `000` reads the `app` role password from `APP_DATABASE_URL` and creates that role. The password is never hardcoded in production — it must come from your secret store.

### Local development

Run `uv run python scripts/setup-env.py` first — it generates `.env`, `.env.postgres`, and all database passwords (sample files intentionally leave these blank). Then start Postgres and the service:

```dotenv
MIGRATION_DATABASE_URL=postgresql+psycopg://auth:<generated>@localhost:5014/auth
APP_DATABASE_URL=postgresql+psycopg://app:<generated>@localhost:5014/auth
```

```bash
docker compose up -d auth-postgres
uv run alembic upgrade head
uv run python -m gunicorn -c src/gunicorn.py src.app:app
```

### Railway (and similar PaaS)

Railway's Postgres plugin creates one superuser (`auth`) with a platform-generated password. Wire it to migrations only:

```dotenv
MIGRATION_DATABASE_URL="postgresql+psycopg://${{Postgres.PGUSER}}:${{Postgres.PGPASSWORD}}@${{Postgres.PGHOST}}:${{Postgres.PGPORT}}/${{Postgres.PGDATABASE}}"
```

Create a **separate** secret for the restricted app role (e.g. Railway **Secret** → `APP_DATABASE_PASSWORD`). Generate with `openssl rand -base64 32`. Wire the runtime URL to the `app` user — **not** the Postgres superuser:

```dotenv
APP_DATABASE_URL="postgresql+psycopg://app:${{APP_DATABASE_PASSWORD}}@${{Postgres.PGHOST}}:${{Postgres.PGPORT}}/${{Postgres.PGDATABASE}}"
```

> **Do not** point both URLs at `${{Postgres.PGUSER}}` / `${{Postgres.PGPASSWORD}}`. That runs the web service as the superuser and leaves a dormant `app` role with a dev-only password if migration `000` ran earlier.

On first deploy after fixing the URLs, recreate the Postgres volume (no clients yet) so migration `000` creates `app` with the new secret.

### Proxmox / AWS (private cloud)

Follow the same split: superuser credentials in `MIGRATION_DATABASE_URL`, `app` + unique password in `APP_DATABASE_URL`. Store both in your secret manager bundle (`AWS_SECRETS_ARN`).

### Validation (fail-hard)

Startup and Alembic require both database URLs to be set and to use different PostgreSQL users.

---

## Appendix A: Environment Variable Reference

| Variable | Where to find it | Generate with |
|----------|-----------------|---------------|
| `WORKOS_CLIENT_ID` | WorkOS Dashboard → API Keys | — |
| `WORKOS_API_KEY` | WorkOS Dashboard → API Keys | — |
| `WORKOS_COOKIE_PASSWORD` | Generated by `scripts/setup-env.py` | `openssl rand -base64 32` |
| `WORKOS_REDIRECT_URI` | Set to your callback URL | — |
| `CSRF_SECRET_KEY` | Generated by `scripts/setup-env.py` | `openssl rand -hex 32` |
| `JWT_PRIVATE_KEY_PEM` | Generated by `scripts/setup-env.py` | `openssl genrsa 2048` |
| `JWT_PUBLIC_KEY_PEM` | Derived from private key | `openssl rsa -pubout` |
| `JWT_PREVIOUS_PUBLIC_KEY_PEM` | Set during key-rotation overlap window only; clear after overlap | copy old `JWT_PUBLIC_KEY_PEM` value |
| `VALID_ROLES` | Comma-separated list of accepted WorkOS org roles (required; service refuses to start if unset). See [SECURITY.md §3.1](SECURITY.md#31-identity--authentication). | — |
| `ACCESS_TOKEN_TTL_SECS` | Optional, default `900` (15 min) | — |
| `SERVICE_TOKEN_TTL_SECS` | Optional, default `300` (5 min) | — |
| `MIGRATION_DATABASE_URL` | Superuser URL for Alembic | [§5](#5-database-roles-and-urls) |
| `APP_DATABASE_URL` | Restricted `app` role URL for runtime | Generated by `scripts/setup-env.py` — [§5](#5-database-roles-and-urls) |
| `APP_DATABASE_PASSWORD` | Railway/cloud only — password for the `app` role referenced in `APP_DATABASE_URL` | `openssl rand -base64 32` |

> **Note:** `MIGRATION_DATABASE_URL` and `APP_DATABASE_URL` are both required and must use different PostgreSQL users. See [§5](#5-database-roles-and-urls).

---

## Appendix B: JWT Key Rotation Runbook

Use this runbook whenever the platform RSA signing key must be rotated (e.g., scheduled rotation, key compromise).

### Prerequisites

- Access to the secret store (Vault / environment configuration) for the authentication service.
- Knowledge of the current `JWT_PRIVATE_KEY_PEM` and `JWT_PUBLIC_KEY_PEM` values (old key pair).
- Downstream services fetch JWKS at startup and cache for up to **1 hour** (`max-age=3600`). Plan the overlap window accordingly (≥ 1 hour recommended; 2 hours is safe).

### Steps

**1. Generate the new key pair**

```bash
# Generate 2048-bit RSA private key
openssl genrsa 2048 > new_private.pem

# Derive the public key
openssl rsa -pubout < new_private.pem > new_public.pem
```

**2. Base64-encode both keys for the secret store**

```bash
base64 -w0 new_private.pem   # → JWT_PRIVATE_KEY_PEM (new)
base64 -w0 new_public.pem    # → JWT_PUBLIC_KEY_PEM  (new)
```

**3. Open the overlap window — publish both keys**

In the authentication service configuration:

| Variable | Value |
|---|---|
| `JWT_PRIVATE_KEY_PEM` | **new** private key (base64) |
| `JWT_PUBLIC_KEY_PEM` | **new** public key (base64) |
| `JWT_PREVIOUS_PUBLIC_KEY_PEM` | **old** public key (base64) |

Redeploy the authentication service. `/.well-known/jwks.json` will now return two JWK entries — one for the new key (`kid` = new thumbprint) and one for the old key.

**4. Wait for the overlap window**

Allow at least **1 hour** (the JWKS `max-age`) for all downstream service instances to refresh their cached public key. Tokens issued before the rotation will still carry the old `kid` and will validate against the old key still present in the JWKS set.

**5. Close the overlap window — remove the old key**

Once all in-flight tokens signed with the old key have expired (max `ACCESS_TOKEN_TTL_SECS`, default 15 min, plus the cache refresh window), remove the old key:

| Variable | Value |
|---|---|
| `JWT_PRIVATE_KEY_PEM` | **new** private key (base64) — unchanged |
| `JWT_PUBLIC_KEY_PEM` | **new** public key (base64) — unchanged |
| `JWT_PREVIOUS_PUBLIC_KEY_PEM` | *(unset / empty string)* |

Redeploy. `/.well-known/jwks.json` returns only the single new key.

**6. Securely delete old key material**

Shred or zero the old private key from any local working copies:

```bash
shred -u new_private.pem new_public.pem   # scratch files
```

Remove the old public key from the secret store history if your platform supports it.

**7. Verify**

```bash
curl -s https://<auth-host>/.well-known/jwks.json | python3 -m json.tool
```

Confirm the response contains exactly one JWK entry with a `kid` matching the new key's RFC 7638 thumbprint.

### Rollback

If the new key must be abandoned before all downstream caches expire:

1. Set `JWT_PRIVATE_KEY_PEM` / `JWT_PUBLIC_KEY_PEM` back to the **old** key pair.
2. Set `JWT_PREVIOUS_PUBLIC_KEY_PEM` to the **new** (abandoned) public key so tokens already issued with the new key remain verifiable until they expire.
3. Redeploy, then wait for new-key tokens to drain, then clear `JWT_PREVIOUS_PUBLIC_KEY_PEM`.
