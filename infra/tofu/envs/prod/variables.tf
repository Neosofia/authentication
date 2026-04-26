variable "aws_region" {
  type    = string
  default = "us-west-2"
}

variable "kms_key_alias" {
  type    = string
  default = "alias/pdc-tofu"
}

variable "proxmox_endpoint" {
  type = string
}

variable "proxmox_insecure" {
  type    = bool
  default = true
}

variable "proxmox_ssh_user" {
  type    = string
  default = "root"
}

variable "proxmox_ssh_host" {
  type = string
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
  type = string
}

variable "workos_api_key" {
  type      = string
  sensitive = true
}

variable "workos_client_id" {
  type = string
}

variable "repo_root" {
  type = string
}
