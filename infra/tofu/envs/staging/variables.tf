variable "aws_region" {
  type    = string
  default = "us-west-2"
}

variable "kms_key_alias" {
  type    = string
  default = "alias/pdc-tofu"
}

variable "proxmox_endpoint" {
  type        = string
  description = "e.g. https://192.168.3.205:8006/api2/json"
}

variable "proxmox_insecure" {
  type        = bool
  default     = true
  description = "Accept self-signed Proxmox cert. Set false once you install a real cert."
}

variable "proxmox_ssh_user" {
  type    = string
  default = "root"
}

variable "proxmox_ssh_host" {
  type        = string
  description = "SSH target for Proxmox host (IP or hostname)."
}

variable "proxmox_node" {
  type    = string
  default = "pve"
}

variable "ct_bridge" {
  type    = string
  default = "local"
}

variable "ct_gateway" {
  type    = string
  default = "10.0.0.1"
}

variable "ct_template_file_id" {
  type        = string
  description = "e.g. local:vztmpl/debian-13-standard_13.0-1_amd64.tar.zst"
}

variable "workos_api_key" {
  type      = string
  sensitive = true
}

variable "workos_client_id" {
  type = string
}

variable "repo_root" {
  type        = string
  description = "Absolute path to the repo root on the tofu-running machine."
}
