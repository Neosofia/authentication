# Authentication Service — Cloud Operations

This service defines its dependencies via the Dockerfile
and the environment variables it expects. The deployment method will depend on how your platform is architected and the environment you are deploying to. For example, Neosofia uses a mix of private cloud hypervisors running Proxmox and public cloud operators like Railway for development environments. For staging and production environments, "traditional" hyperscalers like AWS are used. While supporting both private and pubic providers do incur more overhead from an operational overhead point of view, the flexibility and portability outweigh it.

> **Note:** complete [OPERATIONS.md](OPERATIONS.md) first for WorkOS setup and local tooling.

## Deployment


### Step 1 — Register the target environment in WorkOS

Follow [OPERATIONS.md §2](OPERATIONS.md#2-configure-workos) for the full WorkOS setup.
For each environment (staging, prod), create a new WorkOS environment, then set one
callback URL (`https://auth.<env>.<base-domain>/callback`) and one homepage for it.

Each of dev, staging, and prod needs its own WorkOS environment with its own `WORKOS_CLIENT_ID` and `WORKOS_API_KEY`.

### Step 2 — Generate cryptographic environment variables

Follow [OPERATIONS.md §3](OPERATIONS.md#3-generate-environment-secrets) to run `setup-env.sh` and fill in the WorkOS credentials.

> **Warning:** each environment needs its own `.env`. If you already have one from another environment, move it first (e.g. `mv .env .dev.env`) before running the script.

### Step 3 — Fill in the remaining variables

See [OPERATIONS.md Appendix A](OPERATIONS.md#appendix-a-environment-variable-reference) for the full variable reference. Open `.env` and set the cloud-specific URL variables:

```bash
$EDITOR .env
```

| Variable | Value |
|----------|-------|
| `FRONTEND_URL` | The public base URL of the UI service (e.g. `https://staging.neosofia.tech`). The auth service redirects human users back here after they successfully log in or out via WorkOS. |
| `WORKOS_REDIRECT_URI` | `https://auth.<env>.<base-domain>/callback` |
| `JWT_ISSUER` | `https://auth.<env>.<base-domain>` |

> **Rate limiting:** per-node limits (60/min login, 20/min token) apply in all environments. See [SECURITY.md §3.7](SECURITY.md#37-rate-limiting) for thresholds and the Redis upgrade path.

> **TLS:** terminate TLS at the ingress layer (Traefik for staging, CloudFront for prod). See [SECURITY.md §3.5](SECURITY.md#35-network-isolation--transport-security) for architecture rationale and compliance notes.

### Step 4 — Deploy

Follow the runbook that matches your target infrastructure:

- [Private Cloud Runbook](https://github.com/Neosofia/infrastructure/blob/main/private-cloud/RUNBOOK.md) — LXC containers on Proxmox
- [Public Cloud Runbook](https://github.com/Neosofia/infrastructure/blob/main/public-cloud/RUNBOOK.md) — OpenTofu on AWS / Railway / etc. Service-specific `tfvars` live in `infra/tofu/envs/<env>/terraform.tfvars`.

### Step 5 - Test

Ensure deploy logs have no errors and that the health check page works.
