variable "digitalocean_key_path" {
  description = "Text file with the DigitalOcean API key"
  default = "/path/to/personal/access/token"
}
variable "pvt_key" {
  description = "Location of the private SSH key to connect to the server"
  default = "/path/to/private/key"
}
variable "ssh_fingerprint" {
  description = "MD5 of the public SSH key"
  default = "place md5 value here"
}
variable "command_file"{
  default = "vpn-config.sh"
}
variable "port" {
  description = "Port that the VPN server should listen on"
  default = "443"
}
variable "server_user" {
  description = "User account created on the vpn server.  Only used if you need to SSH to the box."
  default = "vpnmanager"
}
variable "hostname" {
  description = "Name of the VPN server"
  default = "openvpn"
}
variable "region" {
  description = "Valid options are nyc3, sfo2, ams3, lon1, sgp1, tor1, blr1"
  default = "nyc3"
}
