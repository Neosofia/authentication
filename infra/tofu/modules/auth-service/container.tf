# LXC container on Proxmox. Unprivileged, with nesting + keyctl so Docker works.
#
# cloud-init installs Docker on first boot. Subsequent applies update only the
# attributes that changed.

resource "proxmox_virtual_environment_container" "ct" {
  node_name    = var.proxmox_node
  vm_id        = var.ctid
  unprivileged = true
  start_on_boot = true
  started       = true

  features {
    nesting = true
    keyctl  = true
  }

  operating_system {
    template_file_id = var.ct_template_file_id
    type             = "debian"
  }

  cpu {
    cores = var.ct_cores
  }

  memory {
    dedicated = var.ct_memory_mib
  }

  disk {
    datastore_id = var.ct_storage
    size         = var.ct_rootfs_gib
  }

  network_interface {
    name   = "eth0"
    bridge = var.ct_bridge
  }

  initialization {
    hostname = local.ct_hostname
    ip_config {
      ipv4 {
        address = local.ct_ip_cidr
        gateway = var.ct_gateway
      }
    }
  }

  # cloud-init user-data runs once on first boot to install Docker.
  # Using a heredoc keeps the script in-repo and reviewable.
  lifecycle {
    ignore_changes = [
      # The provider sometimes reports drift on these internals we don't
      # actually manage day-to-day; avoid unnecessary recreates.
      operating_system[0].template_file_id,
    ]
  }
}

# Install Docker via pct exec. We run this outside the CT resource itself
# because bpg/proxmox cloud-init on LXC is less consistent than on VMs.
resource "null_resource" "install_docker" {
  triggers = {
    ctid = proxmox_virtual_environment_container.ct.vm_id
  }

  # Needs SSH agent access or key access to the Proxmox host.
  provisioner "local-exec" {
    command = <<-EOT
      ssh -o StrictHostKeyChecking=accept-new ${var.proxmox_ssh_user}@${var.proxmox_ssh_host} \
        "pct exec ${var.ctid} -- bash -s" <<'SCRIPT'
      set -euo pipefail
      if command -v docker >/dev/null 2>&1; then
        exit 0
      fi
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq
      apt-get install -y -qq ca-certificates curl gnupg openssl git
      install -m 0755 -d /etc/apt/keyrings
      curl -fsSL https://download.docker.com/linux/debian/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
      chmod a+r /etc/apt/keyrings/docker.gpg
      echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(. /etc/os-release; echo $VERSION_CODENAME) stable" \
        > /etc/apt/sources.list.d/docker.list
      apt-get update -qq
      apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
      systemctl enable --now docker
      SCRIPT
    EOT
  }
}
