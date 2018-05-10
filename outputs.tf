output "host-ip" {
  value = "${digitalocean_droplet.vpn-server.ipv4_address}"
}
