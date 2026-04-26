# Provisions the authentication service on a Proxmox LXC CT.
#
# Shape:
#   - Proxmox provider creates an unprivileged CT with Docker-compatible flags
#   - Secrets (DB password, CSRF key, cookie password, JWT keypair) are generated
#     by Tofu, stored in AWS Secrets Manager (durable backup, re-hydratable),
#     and rendered into /etc/pdc-auth/<env>.env inside the CT (mode 0600)
#   - Docker image is built on the *machine running tofu apply* (which has clean
#     egress) and shipped to the CT via `docker save | ssh pve pct exec docker load`,
#     sidestepping LaLiga's Cloudflare R2 blocks
#   - compose up is invoked via null_resource with triggers on image digest +
#     env file contents, so apply is idempotent
#
# Scope:
#   - WorkOS credentials come in as inputs (caller is responsible for fetching
#     them from wherever is authoritative, e.g. `aws secretsmanager get-secret-value`)
#   - DNS + NetBird reverse proxy are managed manually per user preference
#   - Docker daemon access is via SSH to Proxmox host + pct exec

terraform {
  required_version = ">= 1.7"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
    proxmox = {
      source  = "bpg/proxmox"
      version = "~> 0.66"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
  }
}

locals {
  ct_hostname = "pdc-auth-${var.environment}"
  ct_ip_cidr  = "${var.ct_ip}/${var.ct_ip_prefix}"
  env_path    = "/etc/pdc-auth/${var.environment}.env"
  data_path   = "/var/lib/pdc-auth-${var.environment}/postgres"
  app_path    = "/opt/pdc-auth-${var.environment}"
}
