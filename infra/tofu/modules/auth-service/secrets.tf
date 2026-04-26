# Secret generation + AWS Secrets Manager storage.
#
# Rationale: state file already holds these values (unavoidable for Tofu-
# generated secrets), but Secrets Manager gives us a durable, versioned copy
# independent of state, plus an audit trail. Rotation = taint the random_* /
# tls_private_key resources and re-apply.

resource "random_password" "postgres" {
  length  = 40
  special = false
  keepers = {
    rotate = var.rotate_secrets ? timestamp() : "stable"
  }
}

resource "random_password" "csrf" {
  length  = 64
  special = false
  keepers = {
    rotate = var.rotate_secrets ? timestamp() : "stable"
  }
}

resource "random_password" "cookie" {
  length  = 44
  special = false
  keepers = {
    rotate = var.rotate_secrets ? timestamp() : "stable"
  }
}

resource "tls_private_key" "jwt" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

data "aws_kms_alias" "tofu" {
  name = var.kms_key_alias
}

locals {
  secret_prefix = "pdc/authentication/${var.environment}"
  secrets = {
    POSTGRES_PASSWORD      = random_password.postgres.result
    DATABASE_URL           = "postgresql+asyncpg://pdc:${random_password.postgres.result}@auth-postgres:5432/pdc_auth"
    CSRF_SECRET_KEY        = random_password.csrf.result
    WORKOS_COOKIE_PASSWORD = random_password.cookie.result
    WORKOS_API_KEY         = var.workos_api_key
    WORKOS_CLIENT_ID       = var.workos_client_id
    WORKOS_REDIRECT_URI    = "${var.public_base_url}/callback"
    JWT_ISSUER             = var.public_base_url
    JWT_PRIVATE_KEY_PEM    = tls_private_key.jwt.private_key_pem
    JWT_PUBLIC_KEY_PEM     = tls_private_key.jwt.public_key_pem
  }
}

resource "aws_secretsmanager_secret" "bundle" {
  name        = "${local.secret_prefix}/env"
  description = "pdc-authentication ${var.environment} environment variables (bundle)"
  kms_key_id  = data.aws_kms_alias.tofu.target_key_arn
  tags = {
    Project     = "pdc"
    Service     = "authentication"
    Environment = var.environment
  }
}

resource "aws_secretsmanager_secret_version" "bundle" {
  secret_id = aws_secretsmanager_secret.bundle.id
  secret_string = jsonencode(local.secrets)
}
