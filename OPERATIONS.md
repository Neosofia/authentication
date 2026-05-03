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

Install Python dependencies:

```bash
uv sync
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

1. Go to **Authentication → Sessions → JWT Template**.
2. Replace the template contents with:

   ```json
   {
       "neosofia:user_type": "{{ organization_membership.role || 'patient' }}",
       "neosofia:tenant_id": {{ organization.id }}
   }
   ```

3. Save. This embeds `user_type` and `tenant_id` directly into the WorkOS access token so the Auth Service can read them without extra SDK calls. Clinicians get their role slug (e.g. `clinician`); patients with no org membership fall back to `patient`. `neosofia:tenant_id` is omitted for patients (WorkOS drops null keys automatically).

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

1. Go to **Organizations** → **Create Organization**.
2. Name it e.g. `Neosofia Test Clinic`.
3. Go to roles and create a `clinician` and `patient` role.

#### Clinician user

1. Go to **Users** → **Create User**.
2. Fill in name + email (use a real email you can receive).
3. Select the user → **Organization Memberships** → **Add Member**.
4. Select `Neosofia Test Clinic`, assign role **clinician**.

> **Note**: Clinicians require an explicit org role assignment. Patients authenticate without
> org membership and will receive `neosofia:user_type=patient` with no `neosofia:tenant_id` claim.

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
| `ACCESS_TOKEN_TTL_SECS` | Optional, default `900` | — |
    | `DATABASE_URL` | Local Postgres | `postgresql+asyncpg://auth:dev_only@localhost:5014/auth` |
| `MACHINE_TOKEN_TTL_SECS` | Optional, default `300` | — |
