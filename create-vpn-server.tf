provider "digitalocean" {
  token = "${chomp(file(var.digitalocean_key_path))}"
}

resource "digitalocean_droplet" "vpn-server" {
  image = "debian-9-x64"
  name = "${var.hostname}"
  region = "${var.region}"
  size = "s-1vcpu-1gb"
  private_networking = false
  ssh_keys = ["${var.ssh_fingerprint}"]

  connection {
    user = "root"
    type = "ssh"
    private_key = "${file(var.pvt_key)}"
    timeout = "2m"
  }
  provisioner "file" {
    source      = "${var.command_file}"
    destination = "/tmp/terraform-init.sh"
  }

  provisioner "remote-exec" {
    inline = [
      "chmod +x /tmp/terraform-init.sh",
      "/tmp/terraform-init.sh ${var.port} ${var.server_user}",
      "rm -rf /tmp/terraform-init.sh",
    ]
  }
  provisioner "local-exec" {
    command  = <<EOF
           echo 'Retreiving client files from the server...'
           scp -P 2222 -i ${var.pvt_key} -r ${var.server_user}@${digitalocean_droplet.vpn-server.ipv4_address}:/tmp/vpn-files/VPN-at-${digitalocean_droplet.vpn-server.ipv4_address}.tar ~/Desktop/
           echo 'Removing files from the server and closing the firewall'
           ssh -p 2222 -i ${var.pvt_key} ${var.server_user}@${digitalocean_droplet.vpn-server.ipv4_address} 'sudo rm -rf /tmp/vpn-files && sudo iptables-save | grep -v DELETEFLAG | sudo iptables-restore'
           echo 'All set'
           EOF
   }

}
