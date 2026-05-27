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
3. Go to roles and create your application roles (e.g. `admin` and `member`).

#### Test user

1. Go to **Users** → **Create User**.
2. Fill in name + email (use a real email you can receive).
3. Select the user → **Organization Memberships** → **Add Member**.
4. Select your test organization and assign one of your configured roles.

> **Note**: All users must have an explicit org role assignment. Users without org membership are rejected at token issuance.

---

## 3. Generate Environment Secrets

Run the setup script — it generates all secrets (RSA keypair, CSRF key, cookie password) and writes `.env`:

```bash
./scripts/setup-env.sh
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

## Appendix A: Environment Variable Reference

| Variable | Where to find it | Generate with |
|----------|-----------------|---------------|
| `WORKOS_CLIENT_ID` | WorkOS Dashboard → API Keys | — |
| `WORKOS_API_KEY` | WorkOS Dashboard → API Keys | — |
| `WORKOS_COOKIE_PASSWORD` | Generated by `setup-env.sh` | `openssl rand -base64 32` |
| `WORKOS_REDIRECT_URI` | Set to your callback URL | — |
| `CSRF_SECRET_KEY` | Generated by `setup-env.sh` | `openssl rand -hex 32` |
| `JWT_PRIVATE_KEY_PEM` | Generated by `setup-env.sh` | `openssl genrsa 2048` |
| `JWT_PUBLIC_KEY_PEM` | Derived from private key | `openssl rsa -pubout` |
| `JWT_PREVIOUS_PUBLIC_KEY_PEM` | Set during key-rotation overlap window only; clear after overlap | copy old `JWT_PUBLIC_KEY_PEM` value |
| `VALID_ROLES` | Comma-separated list of accepted WorkOS org roles (required; service refuses to start if unset). See [SECURITY.md §3.1](SECURITY.md#31-identity--authentication). | — |
| `ACCESS_TOKEN_TTL_SECS` | Optional, default `900` (15 min) | — |
| `SERVICE_TOKEN_TTL_SECS` | Optional, default `300` (5 min) | — |
| `MIGRATION_DATABASE_URL` | Migration DB URL used by Alembic. Required for service operation. | `postgresql+psycopg://auth:dev_only@localhost:5014/auth` |
| `DATABASE_URL` | Runtime app DB URL | `postgresql+psycopg://auth:dev_only@localhost:5014/auth` |

> **Note:** `MIGRATION_DATABASE_URL` is required for the authentication service to operate correctly. It is used by Alembic migrations and should generally be a separate migration role from the runtime app user. `DATABASE_URL` is used only by the running application.

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
