output "region" {
  value = var.region
}

output "state_bucket" {
  value = aws_s3_bucket.state.id
}

output "lock_table" {
  value = aws_dynamodb_table.locks.id
}

output "kms_key_arn" {
  value = aws_kms_key.tofu.arn
}

output "kms_key_alias" {
  value = aws_kms_alias.tofu.name
}

output "backend_config_staging" {
  description = "Copy into infra/tofu/envs/staging/backend.conf"
  value       = <<-EOT
    bucket         = "${aws_s3_bucket.state.id}"
    key            = "authentication/staging.tfstate"
    region         = "${var.region}"
    dynamodb_table = "${aws_dynamodb_table.locks.id}"
    encrypt        = true
    kms_key_id     = "${aws_kms_alias.tofu.name}"
  EOT
}

output "backend_config_prod" {
  description = "Copy into infra/tofu/envs/prod/backend.conf"
  value       = <<-EOT
    bucket         = "${aws_s3_bucket.state.id}"
    key            = "authentication/prod.tfstate"
    region         = "${var.region}"
    dynamodb_table = "${aws_dynamodb_table.locks.id}"
    encrypt        = true
    kms_key_id     = "${aws_kms_alias.tofu.name}"
  EOT
}
