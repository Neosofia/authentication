variable "region" {
  description = "AWS region for state + secrets resources."
  type        = string
  default     = "us-west-2"
}

variable "state_bucket_name" {
  description = "S3 bucket for OpenTofu remote state. Must be globally unique."
  type        = string
  default     = "pdc-tofu-state"
}

variable "lock_table_name" {
  description = "DynamoDB table for OpenTofu state locks."
  type        = string
  default     = "pdc-tofu-locks"
}
