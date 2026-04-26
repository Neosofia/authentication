output "ctid" {
  value = proxmox_virtual_environment_container.ct.vm_id
}

output "ct_ip" {
  value = var.ct_ip
}

output "secrets_bundle_arn" {
  value       = aws_secretsmanager_secret.bundle.arn
  description = "AWS Secrets Manager ARN holding the canonical env bundle."
}

output "env_file_path" {
  value       = local.env_path
  description = "Path to the rendered env file inside the CT."
}

output "ct_reader_iam_user" {
  value       = aws_iam_user.ct_reader.name
  description = "IAM user the CT uses to read the secret bundle."
}

output "ct_reader_access_key_id" {
  value       = aws_iam_access_key.ct_reader.id
  description = "AWS_ACCESS_KEY_ID for the CT reader IAM user."
}

output "ct_reader_secret_access_key" {
  value       = aws_iam_access_key.ct_reader.secret
  description = "AWS_SECRET_ACCESS_KEY for the CT reader IAM user."
  sensitive   = true
}
