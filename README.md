# one-click-vpn
One-click deployment of OpenVPN on a DigitalOcean droplet

This will create a hardened OpenVPN server on a new, minimal DigitalOcean droplet running the latest version of Debian.

To get started, we'll assume you're deploying from a Mac with [Homebrew](https://brew.sh/) installed 
 
1. Create a Personal Access Token in DigitalOcean (from the API page) and save it to a a text file.
2. Install terraform with ```brew install terraform```
3. Generate an SSH keypair and add the private key location to the variables.tf file (```pvt_key```).
  ```bash
  ssh-keygen -q -N "" -t rsa -b 4096 -f ${/path/to/key}
  chmod 400 ${/path/to/key}
  ```
4. Get the md5 of your public key and add it to the variables.tf file (```ssh_fingerprint```).
  ```bash
  ssh-keygen -E md5 -lf ${/path/to/key.pub} | awk '{print $2}' | sed 's/^MD5://g'
  ```
5. Deploy your server with
  ```bash
  terraform init
  terraform apply
  ```
The server init log and OpenVPN client files will be saved in a tar file on your desktop.  Install them using e.g. [TunnelBlick](https://tunnelblick.net/)

That's it!  If you want to destroy your server, simply run ```terraform destroy```.
