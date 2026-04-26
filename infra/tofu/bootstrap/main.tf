# Bootstrap AWS resources needed for OpenTofu remote state + secrets.
#
# - S3 bucket (versioned, encrypted) for tfstate
# - DynamoDB table for state locking
# - KMS key for state + Secrets Manager encryption
#
# Run ONCE per AWS account. Uses local state — this module bootstraps the
# backend other modules depend on, so it can't use the S3 backend itself.
# Do NOT commit terraform.tfstate — back it up securely. See README.md.

terraform {
  required_version = ">= 1.7"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
  }
}

provider "aws" {
  region = var.region
}

# ---------------------------------------------------------------------------
# KMS key — used by both S3 (state) and Secrets Manager (downstream envs)
# ---------------------------------------------------------------------------
resource "aws_kms_key" "tofu" {
  description             = "pdc OpenTofu state + secrets encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags = {
    Project = "pdc"
    Purpose = "tofu-state-and-secrets"
  }
}

resource "aws_kms_alias" "tofu" {
  name          = "alias/pdc-tofu"
  target_key_id = aws_kms_key.tofu.key_id
}

# ---------------------------------------------------------------------------
# S3 bucket for state
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "state" {
  bucket = var.state_bucket_name
  tags = {
    Project = "pdc"
    Purpose = "tofu-state"
  }
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.tofu.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ---------------------------------------------------------------------------
# DynamoDB table for state locking
# ---------------------------------------------------------------------------
resource "aws_dynamodb_table" "locks" {
  name         = var.lock_table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"
  attribute {
    name = "LockID"
    type = "S"
  }
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.tofu.arn
  }
  tags = {
    Project = "pdc"
    Purpose = "tofu-state-locks"
  }
}
