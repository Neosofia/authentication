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

  # Backend config is supplied via `-backend-config=backend.conf` at init time.
  # See bootstrap module outputs.
  backend "s3" {}
}

provider "aws" {
  region = var.aws_region
}

provider "proxmox" {
  endpoint = var.proxmox_endpoint
  # API token is expected via env vars:
  #   PROXMOX_VE_API_TOKEN="<tokenid>=<secret>"
  # SSH agent / key auth is used for the local-exec steps.
  ssh {
    agent    = true
    username = var.proxmox_ssh_user
  }
  insecure = var.proxmox_insecure
}

module "auth" {
  source = "../../modules/auth-service"

  environment   = "dev"
  aws_region    = var.aws_region
  kms_key_alias = var.kms_key_alias

  proxmox_endpoint    = var.proxmox_endpoint
  proxmox_ssh_user    = var.proxmox_ssh_user
  proxmox_ssh_host    = var.proxmox_ssh_host
  proxmox_node        = var.proxmox_node
  ctid                = 120
  ct_template_file_id = var.ct_template_file_id
  ct_bridge           = var.ct_bridge
  ct_ip               = "10.0.0.120"
  ct_gateway          = var.ct_gateway

  workos_api_key   = var.workos_api_key
  workos_client_id = var.workos_client_id
  public_base_url  = "https://auth.dev.pdc.neosofia.tech"

  repo_root = var.repo_root
}
