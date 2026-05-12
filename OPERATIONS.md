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

The Auth Service reads role and organization ID directly from the WorkOS SDK session response (`auth_response.role`, `auth_response.organization_id`) — no custom JWT template is required. You may leave the WorkOS JWT template empty or at its default.

> **Note**: All users must have an organization membership with a recognized role. Users without an org are rejected at token issuance.

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
> **Do not use the "Default Test Organization" automatically created by WorkOS.** WorkOS prevents API updates to default test organizations, which causes an `AuthorizationError` when this service attempts to generate and save a UUIDv7 `external_id` for the organization during login. You must explicitly create a new organization.

1. Go to **Organizations** → **Create Organization**.
2. Name it e.g. `Neosofia Test Clinic`.
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
| `JWT_ISSUER` | Set to your issuer URL | `https://auth.neosofia.local` |
| `VALID_ROLES` | Comma-separated list of accepted WorkOS org roles (required; service refuses to start if unset). See [SECURITY.md §3.1](SECURITY.md#31-identity--authentication). | — |
| `ACCESS_TOKEN_TTL_SECS` | Optional, default `900` (15 min) | — |
| `SERVICE_TOKEN_TTL_SECS` | Optional, default `300` (5 min) | — |
| `DATABASE_URL` | Local Postgres | `postgresql+psycopg://auth:dev_only@localhost:5014/auth` |
| `SERVICE_TOKEN_TTL_SECS` | Optional, default `300` | — |
