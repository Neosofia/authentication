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
  }

  backend "s3" {}
}

provider "aws" {
  region = var.aws_region
}

provider "proxmox" {
  endpoint = var.proxmox_endpoint
  ssh {
    agent    = true
    username = var.proxmox_ssh_user
  }
  insecure = var.proxmox_insecure
}

module "auth" {
  source = "../../modules/auth-service"

  environment   = "prod"
  aws_region    = var.aws_region
  kms_key_alias = var.kms_key_alias

  proxmox_endpoint    = var.proxmox_endpoint
  proxmox_ssh_user    = var.proxmox_ssh_user
  proxmox_ssh_host    = var.proxmox_ssh_host
  proxmox_node        = var.proxmox_node
  ctid                = 320
  ct_template_file_id = var.ct_template_file_id
  ct_bridge           = var.ct_bridge
  ct_ip               = "10.0.1.64"
  ct_gateway          = var.ct_gateway

  # Prod gets more resources. Tune as needed.
  ct_cores      = 4
  ct_memory_mib = 8192
  ct_rootfs_gib = 40

  workos_api_key   = var.workos_api_key
  workos_client_id = var.workos_client_id
  public_base_url  = "https://auth.pdc.neosofia.tech"

  repo_root = var.repo_root
}
