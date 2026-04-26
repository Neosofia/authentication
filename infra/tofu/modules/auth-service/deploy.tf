# Render aws.env (bootstrap credentials) into the CT and compose up.
# The application now fetches its full secret bundle from Secrets Manager at
# startup — the CT only needs three values to bootstrap that call:
#   AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SECRETS_ARN
#
# All via null_resource + local-exec so the logic stays in one place.
# Triggers on IAM key rotation + repo commit so applies are idempotent.

locals {
  aws_env_content = join("\n", [
    "# Managed by OpenTofu — do not edit manually.",
    "# Bootstrap credentials: gives the CT read-only access to its secret bundle.",
    "AWS_ACCESS_KEY_ID=${aws_iam_access_key.ct_reader.id}",
    "AWS_SECRET_ACCESS_KEY=${aws_iam_access_key.ct_reader.secret}",
    "AWS_REGION=${var.aws_region}",
    "AWS_SECRETS_ARN=${aws_secretsmanager_secret.bundle.arn}",
    "ENV=${var.environment}",
  ])
}

# Render aws.env inside the CT. mode 0600, owned by root.
resource "null_resource" "env_file" {
  triggers = {
    # Re-write when the IAM key or secret ARN changes
    access_key_id  = aws_iam_access_key.ct_reader.id
    secrets_arn    = aws_secretsmanager_secret.bundle.arn
    docker         = null_resource.install_docker.id
    env_path       = local.env_path
  }

  provisioner "local-exec" {
    command = <<-EOT
      ssh -o StrictHostKeyChecking=accept-new ${var.proxmox_ssh_user}@${var.proxmox_ssh_host} \
        "pct exec ${var.ctid} -- bash -s" <<'SCRIPT'
      set -euo pipefail
      mkdir -p "$(dirname ${local.env_path})"
      chmod 0700 "$(dirname ${local.env_path})"
      cat > ${local.env_path}.tmp <<'ENV'
${local.aws_env_content}
ENV
      mv ${local.env_path}.tmp ${local.env_path}
      chmod 0600 ${local.env_path}
      chown root:root ${local.env_path}
      mkdir -p ${local.data_path}
      SCRIPT
    EOT
  }
}

# Build the image on the local machine (clean egress) and ship to the CT.
# Triggers on the git HEAD of the repo so code changes force a rebuild.
data "external" "git_head" {
  program = ["bash", "-c", "printf '{\"sha\":\"%s\"}' \"$(git -C \"${var.repo_root}\" rev-parse HEAD 2>/dev/null || echo unknown)\""]
}

resource "null_resource" "deploy" {
  triggers = {
    git_sha   = data.external.git_head.result.sha
    env_file  = null_resource.env_file.id
    image_tag = "pdc-authentication:${var.environment}"
  }

  provisioner "local-exec" {
    working_dir = var.repo_root
    command     = <<-EOT
      set -euo pipefail

      TAG="pdc-authentication:${var.environment}"

      echo "[deploy] Building $TAG for linux/amd64..."
      docker buildx build --platform linux/amd64 \
        -t "$TAG" \
        -f Dockerfile \
        --load \
        .

      echo "[deploy] Pulling postgres:16 for linux/amd64..."
      docker pull --platform linux/amd64 postgres:16

      echo "[deploy] Shipping images to CT ${var.ctid}..."
      docker save "$TAG" postgres:16 \
        | ssh ${var.proxmox_ssh_user}@${var.proxmox_ssh_host} "pct exec ${var.ctid} -- docker load"

      echo "[deploy] Syncing compose files..."
      tar -C . -cf - docker-compose.yml docker-compose.cloud.yml \
        | ssh ${var.proxmox_ssh_user}@${var.proxmox_ssh_host} \
            "pct exec ${var.ctid} -- bash -c 'mkdir -p ${local.app_path} && tar -xf - -C ${local.app_path}'"

      echo "[deploy] Starting compose stack..."
      ssh ${var.proxmox_ssh_user}@${var.proxmox_ssh_host} \
        "pct exec ${var.ctid} -- bash -c 'cd ${local.app_path} && IMAGE_TAG=$TAG docker compose -f docker-compose.yml -f docker-compose.cloud.yml up -d --force-recreate'"
    EOT
  }
}
