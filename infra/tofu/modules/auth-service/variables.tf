variable "environment" {
  description = "Deployment environment name (e.g. dev, staging, prod). Used in resource names and Secrets Manager paths."
  type        = string
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "aws_region" {
  description = "AWS region for Secrets Manager."
  type        = string
}

variable "kms_key_alias" {
  description = "KMS alias (e.g. alias/pdc-tofu) used to encrypt secrets in Secrets Manager."
  type        = string
}

# ---- Proxmox target ---------------------------------------------------------

variable "proxmox_endpoint" {
  description = "Proxmox API endpoint, e.g. https://192.168.3.205:8006/api2/json"
  type        = string
}

variable "proxmox_ssh_user" {
  description = "SSH user on the Proxmox host (needs pct and docker access)."
  type        = string
  default     = "root"
}

variable "proxmox_ssh_host" {
  description = "Hostname or IP to SSH to for pct exec + image loading."
  type        = string
}

variable "proxmox_node" {
  description = "Proxmox node name."
  type        = string
  default     = "pve"
}

variable "ctid" {
  description = "LXC container ID."
  type        = number
}

variable "ct_bridge" {
  description = "Bridge name for the CT's primary NIC."
  type        = string
  default     = "local"
}

variable "ct_ip" {
  description = "IPv4 address for the CT (no CIDR)."
  type        = string
}

variable "ct_ip_prefix" {
  description = "CIDR prefix length for the CT's IP."
  type        = number
  default     = 10
}

variable "ct_gateway" {
  description = "IPv4 gateway for the CT."
  type        = string
  default     = "10.0.0.1"
}

variable "ct_storage" {
  description = "Proxmox storage pool for the rootfs."
  type        = string
  default     = "local-lvm"
}

variable "ct_rootfs_gib" {
  description = "Rootfs size in GiB."
  type        = number
  default     = 20
}

variable "ct_cores" {
  description = "Number of CPU cores."
  type        = number
  default     = 2
}

variable "ct_memory_mib" {
  description = "Memory in MiB."
  type        = number
  default     = 4096
}

variable "ct_template_file_id" {
  description = "Proxmox template file ID, e.g. local:vztmpl/debian-13-standard_13.0-1_amd64.tar.zst"
  type        = string
}

# ---- Application config -----------------------------------------------------

variable "workos_api_key" {
  description = "WorkOS API key (sk_...). Treat as secret."
  type        = string
  sensitive   = true
}

variable "workos_client_id" {
  description = "WorkOS client ID (client_...)."
  type        = string
}

variable "public_base_url" {
  description = "Public URL where the service is reachable (e.g. https://auth.pdc.neosofia.tech). Used for WORKOS_REDIRECT_URI and JWT_ISSUER."
  type        = string
}

variable "repo_root" {
  description = "Absolute path to the repo root on the machine running tofu apply. Used to build the Docker image."
  type        = string
}

variable "rotate_secrets" {
  description = "If true, force regeneration of random secrets on next apply. Use with -replace= for fine-grained rotation."
  type        = bool
  default     = false
}
