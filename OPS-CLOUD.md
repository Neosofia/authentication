# Authentication Service — Cloud Operations

Deploying and operating the authentication service on Proxmox with public HTTPS via NetBird.
Covers the dev environment (shell scripts) and staging/prod (OpenTofu).

**Before starting here**: complete [OPERATIONS.md](OPERATIONS.md) (WorkOS setup + local tooling).

For generic private-cloud mechanics (CT provisioning, DNS/NetBird setup, secret seeding,
deploy/rotate/teardown patterns) see the
[Private Cloud Runbook](https://github.com/Neosofia/infrastructure/blob/main/private-cloud/RUNBOOK.md).
This document covers only what is specific to the authentication service.

---

## Service parameters

| Parameter | Dev | Staging | Prod |
|-----------|-----|---------|------|
| Port | 8000 | 8000 | 8000 |
| Public URL | `auth.dev.<base-domain>` | `auth.staging.<base-domain>` | `auth.<base-domain>` |
| Suggested CT ID | 120 | 121 | 122 |
| Suggested CT IP | 10.0.0.120/10 | 10.0.0.121/10 | 10.0.0.122/10 |
| Resources | 2 vCPU / 4 GiB | 2 vCPU / 4 GiB | 4 vCPU / 8 GiB |

---

## Generating service secrets

The authentication service requires cryptographic material that must be generated — do not
hand-craft these values.

```bash
cd ~/projects/neosofia/authentication
./scripts/setup-env.sh   # creates .env from .env.example + generates RSA-4096 keypair,
                         # CSRF secret, and cookie password
$EDITOR .env             # fill in the remaining variables (see table below)
```

### Required variables

| Variable | Where to get it |
|----------|----------------|
| `WORKOS_CLIENT_ID` | WorkOS dashboard → your application → Client ID |
| `WORKOS_API_KEY` | WorkOS dashboard → API Keys → Secret Key (`sk_...`) |
| `PUBLIC_BASE_URL` | The public HTTPS URL for this environment (e.g. `https://auth.dev.neosofia.tech`) |

### WorkOS one-time setup (per environment)

In the WorkOS dashboard, add the environment's callback URL to the application's
**Redirect URI allowlist**:

```
https://auth.dev.<base-domain>/callback
https://auth.staging.<base-domain>/callback   # when staging is brought up
https://auth.<base-domain>/callback           # when prod is brought up
```

Use a WorkOS **staging** project (`sk_test_...`) for dev and staging.
Use a WorkOS **production** project (`sk_live_...`) for prod.

---

## Dev deployment

Follow the [Private Cloud Runbook — First deployment](https://github.com/Neosofia/infrastructure/blob/main/private-cloud/RUNBOOK.md#first-deployment-of-a-service-dev-environment)
with these authentication-specific values:

```bash
# Step 1 — Provision CT (from infrastructure repo)
./private-cloud/containers/create-ct.sh authentication 120 10.0.0.120/10

# Step 2 — Seed secrets
bash private-cloud/containers/seed-ct-env.sh authentication ~/projects/neosofia/authentication/.env

# Step 3 — Trigger deploy
cd ~/projects/neosofia/authentication
git tag authentication/$(date +%Y.%m.%d)
git push origin authentication/$(date +%Y.%m.%d)

# Step 4 — Verify
ssh root@$PVE_HOST "pct exec 120 -- /usr/bin/curl -s http://localhost:8000/api/health"
# → {"status":"ok"}
```

### Machine credential seeding

The `test-service` credential is seeded automatically by migration `002` when
`SEED_MACHINE_SECRET` is set in `.env` before the first deploy. Add it alongside
other secrets before Step 2:

```
SEED_MACHINE_SECRET=<choose a strong secret>
```

To verify after deploy:

```bash
ssh root@$PVE_HOST "pct exec 120 -- \
  docker exec authentication bash -c \
  'curl -sf -X POST http://localhost:8000/api/token \
    -H \"Authorization: Basic \$(echo -n test-service:\$SEED_MACHINE_SECRET | base64)\" \
    -d grant_type=client_credentials | python3 -m json.tool'"
```

### Observability

```bash
COMPOSE="-f docker-compose.yml -f docker-compose.cloud.yml"
APP=/opt/actions-runner/_work/authentication/authentication

ssh $PVE_HOST "pct exec 120 -- bash -c 'cd $APP && docker compose $COMPOSE logs -f'"
ssh $PVE_HOST "pct exec 120 -- bash -c 'cd $APP && docker compose $COMPOSE ps'"
ssh $PVE_HOST "pct exec 120 -- docker exec -it auth-postgres psql -U auth -d auth"
```

---

## Staging and Prod — OpenTofu

Managed with OpenTofu. State lives in S3; secrets in AWS Secrets Manager.

### One-time AWS bootstrap

Run once per AWS account. Creates the S3 bucket, DynamoDB lock table, and KMS key
shared by all environments. See [infra/tofu/bootstrap/README.md](infra/tofu/bootstrap/README.md).

```bash
aws sso login   # or: export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...

cd infra/tofu/bootstrap
tofu init
tofu apply

# Save backend configs (gitignored — regenerate any time)
tofu output -raw backend_config_staging > ../envs/staging/backend.conf
tofu output -raw backend_config_prod    > ../envs/prod/backend.conf
```

> [!CAUTION]
> **Back up `terraform.tfstate`** before closing this terminal — copy it to a
> password manager or private encrypted location. See bootstrap README for recovery steps.

### Deploy staging

```bash
cd infra/tofu/envs/staging

# First time only
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars    # fill in workos_*, repo_root, proxmox_ssh_host

tofu init -backend-config=backend.conf
tofu plan -out=staging.tfplan
tofu apply staging.tfplan
```

Then configure manually (one-time):
- Cloudflare: `*.staging.<base-domain>` CNAME → NetBird cluster hostname (DNS only)
- NetBird: wildcard reverse proxy route `*.staging.<base-domain>` → `<staging CT IP>:8000`
- WorkOS (staging project): add `https://auth.staging.<base-domain>/callback` to redirect URI allowlist

### Deploy prod

Identical to staging. Prod uses 4 cores / 8 GiB RAM and a WorkOS **production** project.

```bash
cd infra/tofu/envs/prod
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars
tofu init -backend-config=backend.conf
tofu plan -out=prod.tfplan
tofu apply prod.tfplan
```

### Rotating secrets

```bash
# Single secret
tofu apply -replace=module.auth.random_password.postgres

# All random secrets
tofu apply -var='rotate_secrets=true'
```

If rotating the Postgres password, wipe the data volume first:

```bash
ssh root@$PVE_HOST "pct exec $STAGING_CTID bash -c '
  cd /opt/authentication-staging
  docker compose down -v
  rm -rf /var/lib/authentication-staging/postgres
'"
tofu apply
```

### Rollback a secret

```bash
aws secretsmanager get-secret-value \
  --secret-id neosofia/authentication/staging/env \
  --version-stage AWSPREVIOUS
```

---

## Troubleshooting

| Symptom | Likely cause |
|---------|-------------|
| Service returns 500 on `/api/health` | Missing or malformed secret — check `/etc/authentication/env` exists and `docker logs authentication --tail 50` |
| WorkOS OAuth redirect fails | Verify the callback URL is on the WorkOS app's redirect URI allowlist and NetBird is proxying to the correct CT IP + port |
| Alembic migration stuck on startup | `ssh root@$PVE_HOST "pct exec $DEV_CTID -- docker exec -it authentication python -m alembic current"` |
| Postgres password drift after secret rotation | Wipe the data volume and re-apply (see Rotating secrets above) |

For NetBird cert, TLS, and general CT/Docker troubleshooting see the
[Private Cloud Runbook — Troubleshooting](https://github.com/Neosofia/infrastructure/blob/main/private-cloud/RUNBOOK.md#troubleshooting).

