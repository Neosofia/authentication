# Authentication Service — Cloud Operations

Deploying and operating the authentication service on Proxmox with public HTTPS via NetBird.
Covers the dev environment (shell scripts) and staging/prod (OpenTofu).

**Before starting here**: complete [OPERATIONS.md](OPERATIONS.md) (WorkOS setup + local tooling).

---

## Architecture for Cloud Development Environment

This architecture is based on a local dev environment running Proxmox.

```
     ┌───────────────────────────────────────────────────────┐
     │ Operator terminal (NetBird client)                    │
     └──────────────────────────┬────────────────────────────┘
                                │ NetBird mesh
                                ▼
     ┌───────────────────────────────────────────────────────┐
     │ NetBird — custom domain → Docker                     │
     │  auth.dev.<base-domain>     → <dev IP>:8000           │
     │  auth.staging.<base-domain> → <staging IP>:8000       │
     │  auth.prod.<base-domain>    → <prod IP>:8000          │
     └──────────────────────────┬────────────────────────────┘
                                │ Proxmox SDN
                                ▼
     ┌───────────────────────────────────────────────────────┐
     │ Service host (Debian 13, Docker CE)                   │
     │  ┌──────────────────────┐  ┌──────────────────────┐   │
     │  │ pdc-authentication   │──│ pdc-auth-postgres    │   │
     │  │ FastAPI :8000        │  │ PostgreSQL 16        │   │
     │  └────────┬─────────────┘  └──────────────────────┘   │
     │           │ fetches secrets at startup                │
     │           │ via /etc/authentication/env (deploy.sh)   │
     │  data:     /var/lib/pdc-auth/postgres                 │
     └───────────────────────────────────────────────────────┘
```


## DNS and reverse proxy setup (one-time, per environment)

These steps are manual and done once per environment in external dashboards.
Examples use `auth.dev.pdc.neosofia.tech` — substitute your base domain and env prefix.

### 1. Reverse proxy — custom domain

In your reverse proxy provider's dashboard, add a **custom domain** for the environment
(e.g. in NetBird: **Network → Routing → Reverse Proxy → Custom Domain**):

- Domain: `*.dev.pdc.neosofia.tech`

The provider will display a **CNAME target** you must point your DNS at
(e.g. `us1.netbird.services` — varies by provider and region).
Note that value, then **jump to step 2** to create the DNS record before continuing here.

Once the DNS record is in place, return and wait for the domain status to show **Active**
with a wildcard cert issued.

> **Known issue (NetBird ≥ beta)**: requesting a cert for a _specific_ subdomain
> (e.g. `auth.dev.pdc.neosofia.tech`) wedges at "Issuing". Use a wildcard custom domain
> and rely on the wildcard cert instead. Track [NetBird #5517](https://github.com/netbirdio/netbird/issues/5517).

### 2. DNS (Cloudflare or any provider)

Add a wildcard CNAME for the environment using the CNAME target noted in step 1:

| Name | Type | Target | Proxy |
|------|------|--------|-------|
| `*.dev.pdc.neosofia.tech` | CNAME | `<CNAME target from step 1>` | DNS only/Off/Inactive |

One wildcard covers all services in that environment.
Repeat with `*.staging.` and `*.prod.` when those environments are brought up.

> **Cloudflare**: the record must be **DNS only** (grey cloud). Orange-cloud (proxied) will
> break NetBird's TLS termination.

Return to step 1 once the record is saved.

### 3. Reverse proxy — per-service routes

Back in the reverse proxy dashboard, add a route for each service under the custom domain, for example:

| Field | Value |
|-------|-------|
| Domain | `auth.dev.pdc.neosofia.tech` |
| Target | `http://<host-ip>:8000` |
| Protocol | HTTP |

Staging and prod follow the same pattern with their host IPs and subdomain prefixes.

---

## Operator Tools

The operator or sysadmin will need local CLI tooling, SSH access to the Proxmox host (for dev setup),
AWS credentials (for staging/prod setup),
and a NetBird client connected to the mesh (for dev setup).

**Tooling** (in addition to [OPERATIONS.md](OPERATIONS.md) §1):

| Tool | Install |
|------|---------|
| OpenTofu ≥ 1.7 | `brew install opentofu` |
| AWS CLI v2 | [aws.amazon.com/cli](https://aws.amazon.com/cli/) |

**Access** (all from the operator terminal):
- SSH to Proxmox host with key-based auth
- AWS credentials: `aws sso login` (or export access key)
- SSH agent loaded: `ssh-add ~/.ssh/id_ed25519`
- NetBird client connected to the mesh

**Done once in external dashboards (not automated)**:
- DNS + NetBird: see [DNS and reverse proxy setup](#dns-and-reverse-proxy-setup-one-time-per-environment) above
- WorkOS: add your environment's callback URL to the application's redirect URI allowlist

---

## Operator environment variables

Infrastructure scripts read from `~/.ops.env` (outside any repo).
Create it if it does not exist:

```bash
$EDITOR ~/.ops.env
```

Required variables:

```bash
PVE_HOST=root@<proxmox-host>        # SSH target for Proxmox
GHA_ORG=neosofia                    # GitHub organisation
GHA_RUNNER_TOKEN=<token>            # Org-level runner registration token
                                    # Generate: GitHub → neosofia org → Settings → Actions → Runners → New runner
```

You can override the path at call time: `OPS_ENV=/other/path ./proxmox/create-ct.sh ...`

---

## Dev Environment — Shell Scripts

The dev environment is managed with shell scripts. No Tofu, no AWS state.

### First deployment

**Step 1 — Provision the LXC CT** (operator terminal, from the infrastructure repo)

```bash
cd <neosofia-infrastructure-folder>
./proxmox/create-ct.sh authentication <ctid> <ip-cidr>
# e.g. ./proxmox/create-ct.sh authentication 121 10.0.0.121/10
```

Provisions an unprivileged Debian 13 CT: 2 vCPU, 4 GiB RAM, 20 GiB rootfs,
`nesting=1` + `keyctl=1` for Docker. Installs Docker CE. Registers an org-level
GHA self-hosted runner with label `authentication`. Idempotent — safe to re-run.

**Step 2 — Seed service secrets** (operator terminal)

⚠ **Do this before pushing any tag.** The GHA runner is live immediately after
Step 1. If a deploy triggers before secrets exist, the deploy will fail.

```bash
# 1. Generate .env (handles RSA keypair, CSRF secret, cookie password — do not skip)
cd ~/projects/neosofia/authentication
./scripts/setup-env.sh   # creates .env from .env.example + generates secrets
$EDITOR .env             # fill in WORKOS_CLIENT_ID, WORKOS_API_KEY, PUBLIC_BASE_URL, etc.

# 2. Push to the CT
cd ~/projects/neosofia/infrastructure
bash scripts/seed-ct-env.sh authentication ${DEV_CTID} ~/projects/neosofia/authentication/.dev.env
```

**Step 3 — Trigger the first deploy** (push a CalVer tag)

```bash
cd ~/projects/neosofia/authentication
git tag authentication/$(date +%Y.%m.%d)
git push origin authentication/$(date +%Y.%m.%d)
```

This runs `authentication-build-push` → on success triggers `authentication-deploy-dev`.
The runner inside the CT pulls the image, starts the compose stack (LocalStack + Postgres +
auth service). On first boot, LocalStack's init hook generates RSA keypairs and seeds
the `pdc/authentication/dev/env` secret bundle. The auth container starts only after
LocalStack is healthy.

The GHCR packages are public — no token required.

**Step 4 — Verify** (operator terminal)

```bash
# Internal health check (curl runs in the CT, not inside the container)
ssh root@$PVE_HOST "pct exec $DEV_CTID -- /usr/bin/curl -s http://localhost:8000/api/health"
# → {"status":"ok"}

# Public health check (once DNS + NetBird proxy are configured)
curl https://auth.dev.<your-base-domain>/api/health
# → {"status":"ok"}
```

### Seed a machine credential (service-to-service)

The `test-service` credential is seeded automatically by migration `002` when
`SEED_MACHINE_SECRET` is set in `/etc/authentication/env` before the first deploy.
The GHA deploy workflow runs `alembic upgrade head` before starting the container,
so the credential is present by the time the service accepts traffic.

Add to `/etc/authentication/env` on the CT (alongside other secrets):

```
SEED_MACHINE_SECRET=<choose a strong secret>
```

To verify after deploy:

```bash
ssh root@$PVE_HOST "pct exec $DEV_CTID -- \
  docker exec pdc-authentication bash -c \
  'curl -sf -X POST http://localhost:8000/api/token \
    -H \"Authorization: Basic \$(echo -n test-service:\$SEED_MACHINE_SECRET | base64)\" \
    -d grant_type=client_credentials | python3 -m json.tool'"
```

### Ongoing operations

**Redeploy from a new image tag** (automated)

Push a CalVer tag to trigger the full pipeline:

```bash
git tag authentication/$(date +%Y.%m.%d)
git push origin authentication/$(date +%Y.%m.%d)
```

This runs `authentication-build-push` (build → test → scan → push to GHCR), which on
success automatically triggers `authentication-deploy-dev`. The deploy workflow runs on
the self-hosted runner inside the CT — it pulls the tagged image, retags it `:latest`,
and runs `docker compose up --force-recreate --no-deps authentication`. No operator
terminal action needed.

To deploy manually (e.g. re-deploy an existing tag):

```bash
# GitHub UI: Actions → Authentication Service — Deploy Dev → Run workflow → enter tag
# Or via CLI:
gh workflow run authentication-deploy-dev.yml -f image_tag=2026.04.23
```

Existing secrets and Postgres data are preserved across deploys.

**Rotate all secrets** (operator terminal)

Secrets live in the shared secrets service. To rotate, update the secret then restart the service.

```bash
# Re-seed updated secrets then restart the service
cd ~/projects/neosofia/infrastructure
bash scripts/seed-ct-env.sh authentication ~/projects/neosofia/authentication/.dev.env

ssh $PVE_HOST "pct exec $DEV_CTID -- bash -c '
  docker compose -f /opt/actions-runner/_work/authentication/authentication/docker-compose.yml \
    -f /opt/actions-runner/_work/authentication/authentication/docker-compose.cloud.yml \
    restart authentication
'"
```

To update WorkOS credentials, edit `.dev.env`, re-seed via the above, then restart.

**Observability** (operator terminal)

```bash
COMPOSE="-f docker-compose.yml -f docker-compose.cloud.yml"
APP=/opt/actions-runner/_work/authentication/authentication

# Tail logs
ssh $PVE_HOST "pct exec $DEV_CTID -- bash -c 'cd $APP && docker compose $COMPOSE logs -f'"

# Container status
ssh $PVE_HOST "pct exec $DEV_CTID -- bash -c 'cd $APP && docker compose $COMPOSE ps'"

# Postgres shell
ssh $PVE_HOST "pct exec $DEV_CTID -- docker exec -it pdc-auth-postgres psql -U pdc -d pdc_auth"
```

**Backups**

Postgres data lives at `/var/lib/pdc-auth/postgres` inside the CT.
Configure a nightly Proxmox Backup snapshot, or dump on demand from the operator terminal:

```bash
ssh root@$PVE_HOST "pct exec $DEV_CTID \
  docker exec pdc-auth-postgres pg_dump -U pdc pdc_auth" \
  > pdc-auth-$(date +%F).sql
```

**Teardown** (operator terminal)

```bash
ssh $PVE_HOST "pct stop $DEV_CTID && pct destroy $DEV_CTID"
```

Wipes everything including the Postgres volume. Re-run Steps 1–3 above to
rebuild from scratch.

---

## Staging and Prod — OpenTofu

Managed with OpenTofu from the operator terminal. State lives in S3; secrets in AWS Secrets Manager.

### One-time AWS bootstrap (operator terminal)

Run once per AWS account. Creates the S3 bucket, DynamoDB lock table, and KMS key
that all other environments share. See [infra/tofu/bootstrap/README.md](infra/tofu/bootstrap/README.md)
for full details including state backup and recovery.

```bash
aws sso login   # or: export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...

cd infra/tofu/bootstrap
tofu init
tofu apply

# Save backend configs for each env (gitignored — regenerate any time)
tofu output -raw backend_config_staging > ../envs/staging/backend.conf
tofu output -raw backend_config_prod    > ../envs/prod/backend.conf
```

> [!CAUTION]
> **Back up `terraform.tfstate`** before closing this terminal — copy it to a
> password manager or private encrypted location. It is gitignored by design
> (operator-specific, public repo). See bootstrap README for recovery steps if lost.

### Deploy staging (operator terminal)

```bash
cd infra/tofu/envs/staging

# First time only
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars    # fill in workos_*, repo_root, proxmox_ssh_host

tofu init -backend-config=backend.conf
tofu plan -out=staging.tfplan
tofu apply staging.tfplan
```

Apply steps (in order):
1. Create/update LXC CT on Proxmox
2. Install Docker in the CT
3. Generate secrets (passwords, RSA-4096 JWT key) — idempotent unless `rotate_secrets=true`
4. Write secret bundle to AWS Secrets Manager at `pdc/authentication/staging/env`
5. Render `/etc/pdc-auth/staging.env` inside the CT (mode 0600)
6. Build `pdc-authentication:staging` locally for `linux/amd64`
7. Ship via `docker save | ssh pve pct exec docker load`
8. `docker compose up -d` inside the CT

Verify:
```bash
ssh root@$PVE_HOST "pct exec $STAGING_CTID -- /usr/bin/curl -s http://localhost:8000/api/health"
# → {"status":"ok"}
```

Then configure manually (one-time):
- Cloudflare: `*.staging.<your-base-domain>` CNAME → NetBird cluster hostname (DNS only)
- NetBird: new reverse proxy wildcard service → `*.staging.<your-base-domain>` → `<staging CT IP>:8000`
- WorkOS (staging project): add `https://auth.staging.<your-base-domain>/callback` to redirect URI allowlist

### Deploy prod (operator terminal)

Identical to staging. Prod uses larger resources (4 cores / 8 GiB RAM) and a
WorkOS **production** project (`sk_live_...`).

```bash
cd infra/tofu/envs/prod
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars
tofu init -backend-config=backend.conf
tofu plan -out=prod.tfplan
tofu apply prod.tfplan
```

### Rotating secrets (operator terminal)

```bash
# Single secret
tofu apply -replace=module.auth.random_password.postgres

# All random secrets
tofu apply -var='rotate_secrets=true'
```

Rotation cascades: new secret → new Secrets Manager version → new env file → container recreated.

If rotating the Postgres password, wipe the data volume first:

```bash
ssh root@$PVE_HOST "pct exec $STAGING_CTID bash -c '
  cd /opt/pdc-auth-staging
  docker compose down -v
  rm -rf /var/lib/pdc-auth-staging/postgres
'"
tofu apply
```

### Rollback a secret (operator terminal)

```bash
aws secretsmanager get-secret-value \
  --secret-id pdc/authentication/staging/env \
  --version-stage AWSPREVIOUS
```

---

## Troubleshooting

| Symptom | Likely cause |
|---------|-------------|
| `docker: command not found` during bootstrap | `create-auth-ct.sh` failed partway — re-run it (idempotent) |
| Service returns 500 on `/api/health` | Missing or malformed secret — check `/etc/authentication/env` exists and `docker logs pdc-authentication --tail 50` |
| WorkOS OAuth redirect fails | Verify the callback URL is on the WorkOS app's redirect URI allowlist and NetBird is proxying the domain to the correct CT IP + port |
| NetBird cert stuck "Issuing" on a specific subdomain | Known NetBird beta bug ([#5517](https://github.com/netbirdio/netbird/issues/5517)) — use a wildcard Custom Domain (`*.dev.<base-domain>`) instead of a per-service domain; verify the DNS CNAME is DNS-only (grey cloud) |
| TLS `internal_error` / SSL alert 80 after cert issued | NetBird edge cert state is wedged — delete and re-create the service and custom domain in the NetBird dashboard |
| Alembic migration stuck on startup | `ssh root@$PVE_HOST "pct exec $DEV_CTID docker exec -it pdc-authentication python -m alembic current"` |
| `tofu apply` fails with S3 backend error | Run `aws sso login` on the operator terminal and retry |
| Postgres password drift after secret rotation | Wipe the data volume and re-apply (see Rotating secrets above) |
