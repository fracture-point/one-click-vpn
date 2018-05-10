#!/bin/bash
# OPTIONAL ARGUMENTS BELOW, WITH THEIR DEFAULTS
# PORT - 443
# user - vpnmanager

apt-get update && apt-get -y upgrade
apt-get -y install ntp openvpn easy-rsa fail2ban unattended-upgrades psad sudo haveged dnsutils iptables openssl ca-certificates

MYIP=$(dig +short myip.opendns.com @resolver1.opendns.com)
MYNAME=$(cat /etc/hostname)
TMPDIR=/tmp/vpn-files
LOGNAME=server-config.log
OS=debian
GROUPNAME=nogroup
PORT=${1:-443}
SERVERUSER=${2:-vpnmanager}
RCLOCAL='/etc/rc.local'
PROTOCOL=tcp
CLIENT1=Client1-at-$MYIP.ovpn
CLIENT2=Client2-at-$MYIP.ovpn

mkdir $TMPDIR
touch $TMPDIR/$LOGNAME
echo "Begin initial VPS configuration" >> $TMPDIR/$LOGNAME
echo "IP Addres: $MYIP" >> $TMPDIR/$LOGNAME

echo "" >> $TMPDIR/$LOGNAME
echo "Config - Users" >> $TMPDIR/$LOGNAME
useradd $SERVERUSER -d /home/$SERVERUSER -m -G www-data,sudo -s /bin/bash
useradd --system ovpn -s /sbin/nologin
mkdir -p /home/$SERVERUSER/.ssh
echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCiZmRVjCCL7uRrdofHseqj33paviGjRrHuIQWJFCubVS8fpy8XLf2RK+FMluspnRmrhmNS+1EtiFM6cqtLD5/GD1gtk5GRW3PsBvotLt8saRECeCWMJpErVJvQhF++Rp6FlTsJQuDoZRCkUAsg9KAi4ndMYPDcIi3rkmAVM86hCNHX7+ndUZA9RFUJy+9/gk95yKc3tjM/iOrg5cMqYTR7VXmmrQMJiyLulf4bmN83huWGCMPbtzrpR9fjDiImv2oLjBtwu1pvFns9oEvoAsLY9LZZU9DqRZC2Hvs+ARHltC0a7iM/CWPSatU6u8n3f7OWcXjhO/5EvAE7ExnZ7vl84xP+CQ4+k5Z5l7KnGldPfpw8UMaynnrTSrGa8592RcNpA+qLNCTWCJMGWD3DrkxmR6qbJ+mkmr13kHyNqAkwIo+a4NL9OJqmqliAqEDLtVNDUOYsVkfVgBqNtfkAv1bP3gYhi8+feCqY96G2bt8tCR4RXm9/JGmyvMS7R5sL9Pu0/tG+E3tyt9ZHHHMKTFsjBE0lo6O8byWhxNnLwDok6F3CMUtrsrJ/Im00mcp6keIxTeWW1s8TvsgX83S2FUWTwOQLkOnweq2D7gXRwKCyv7b8ghtvcqDGznPyJlOwvf0xbe/6W4d3CZoAOEw6smDrnQ5f3Sw9/yZBtM9t9gLtiw== > /home/$SERVERUSER/.ssh/authorized_keys
chown -R $SERVERUSER:$SERVERUSER /home/$SERVERUSER
 
echo "" >> $TMPDIR/$LOGNAME
echo "Config SSH Server" >> $TMPDIR/$LOGNAME
echo "4 replacements" >> $TMPDIR/$LOGNAME
sed -i -e 's/^[#\t ]*Port[\t ]*.*/Port 2222/g w /dev/stdout' /etc/ssh/sshd_config >> $TMPDIR/$LOGNAME
sed -i -e 's/^[#\t ]*PasswordAuthentication[#\t ]*yes/PasswordAuthentication no/g w /dev/stdout' /etc/ssh/sshd_config >> $TMPDIR/$LOGNAME
sed -i -e 's/^[#\t ]*X11Forwarding[#\t ]*yes/X11Forwarding no/g w /dev/stdout' /etc/ssh/sshd_config >> $TMPDIR/$LOGNAME
sed -i -e 's/^[#\t ]*Protocol.*/Protocol 2/g w /dev/stdout' /etc/ssh/sshd_config >> $TMPDIR/$LOGNAME
service sshd restart
service ssh restart

echo "" >> $TMPDIR/$LOGNAME
echo "Config - Automatic Updates" >> $TMPDIR/$LOGNAME
echo "6 replacements" >> $TMPDIR/$LOGNAME
sed -i -e 's/^[/\t ]*\("o=Debian,a=stable";\)/\t\1/g w /dev/stdout' /etc/apt/apt.conf.d/50unattended-upgrades >> $TMPDIR/$LOGNAME
sed -i -e 's/^[/\t ]*\("o=Debian,a=stable-updates";\)/\t\1/g w /dev/stdout' /etc/apt/apt.conf.d/50unattended-upgrades >> $TMPDIR/$LOGNAME
sed -i -e 's/^[/\t ]*\("o=Debian,a=proposed-updates";\)/\t\1/g w /dev/stdout' /etc/apt/apt.conf.d/50unattended-upgrades >> $TMPDIR/$LOGNAME
sed -i -e 's/^[/\t ]*\("origin=Debian,codename=${distro_codename},label=Debian-Security";\)/\t\1/g w /dev/stdout' /etc/apt/apt.conf.d/50unattended-upgrades >> $TMPDIR/$LOGNAME
sed -i -e 's/.*Automatic-Reboot-Time.*/Unattended-Upgrade::Automatic-Reboot-Time "02:00";/g w /dev/stdout' /etc/apt/apt.conf.d/50unattended-upgrades >> $TMPDIR/$LOGNAME
sed -i -e 's/.*Automatic-Reboot "false".*/Unattended-Upgrade::Automatic-Reboot "true";/g w /dev/stdout' /etc/apt/apt.conf.d/50unattended-upgrades >> $TMPDIR/$LOGNAME
 
echo "" >> $TMPDIR/$LOGNAME
echo "Config - Swap File" >> $TMPDIR/$LOGNAME
fallocate -l 1024MB /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
swapon -s
echo /swapfile   none    swap    sw    0   0 >> /etc/fstab
sysctl vm.swappiness=10
sysctl vm.vfs_cache_pressure=50
echo vm.swappiness=10 >> /etc/sysctl.conf
echo vm.vfs_cache_pressure = 50 >> /etc/sysctl.conf
free -mh >> $TMPDIR/$LOGNAME
 
echo "" >> $TMPDIR/$LOGNAMEs
echo "Security - Disable root account, disable recovery mode, allow sudo users to sudo without password" >> $TMPDIR/$LOGNAME
echo "3 replacements" >> $TMPDIR/$LOGNAME
sudo passwd -l root
sudo usermod --expiredate 1 root
sed -i -e 's/^[#\t ]*#GRUB_DISABLE_RECOVERY="true"[\t ]*.*/GRUB_DISABLE_RECOVERY="true"/g w /dev/stdout' /etc/default/grub >> $TMPDIR/$LOGNAME
sudo update-grub
sed -i -e 's/^[#\t ]*PermitRootLogin[#\t ]*yes/PermitRootLogin no/g w /dev/stdout' /etc/ssh/sshd_config >> $TMPDIR/$LOGNAME  - sed -i -e 's|^\(root.*\)\(\/bin\/bash\)|\1/sbin/nologin|g w /dev/stdout' /etc/passwd >> $TMPDIR/$LOGNAME
echo "%sudo   ALL=(ALL:ALL) NOPASSWD: ALL" > /etc/sudoers.d/no-pw-sudo
chmod 440 /etc/sudoers.d/no-pw-sudo

echo "" >> $TMPDIR/$LOGNAME
echo "Security - Firewall" >> $TMPDIR/$LOGNAME
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -t nat -P PREROUTING ACCEPT
iptables -t nat -P POSTROUTING ACCEPT
iptables -t nat -P OUTPUT ACCEPT
iptables -t mangle -P PREROUTING ACCEPT
iptables -t mangle -P OUTPUT ACCEPT
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP                           -m comment --comment "Deny recon"
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP                   -m comment --comment "Deny synflood"
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP                            -m comment --comment "Deny xman recon"
iptables -A INPUT -i lo -j ACCEPT                                               -m comment --comment "Allow localhost"
iptables -A OUTPUT -o lo -j ACCEPT                                              -m comment --comment "Allow localhost"
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT                -m comment --comment "Allow localhost"
iptables -I INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT                -m comment --comment "Allow open connections"
iptables -P OUTPUT ACCEPT                                                       -m comment --comment "Allow outbound traffic"
iptables -A INPUT -p tcp -m tcp --dport 2222 -s 10.8.0.0/24 -j ACCEPT           -m comment --comment "Allow SSH to VPN server, while on VPN"
iptables -A INPUT -p tcp -m tcp --dport 2222  -j ACCEPT                         -m comment --comment "World access, to be removed after install DELETEFLAG"
iptables -A INPUT -j LOG                                                        -m comment --comment "Need to log inputs, forwards for PSAD"
iptables -A FORWARD -j LOG                                                      -m comment --comment "Need to log inputs, forwards for PSAD"
iptables -A INPUT -j DROP                                                       -m comment --comment "Drop everything else"
apt-get remove -y iptables-persistent
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections
apt-get install -y iptables-persistent
service iptables-persistent start
 
echo "" >> $TMPDIR/$LOGNAME
echo "Security - Fail2ban" >> $TMPDIR/$LOGNAME
echo "6 replacements" >> $TMPDIR/$LOGNAME
sed -i -e 's/^bantime  = 600/bantime  = 86400/g w /dev/stdout' /etc/fail2ban/jail.conf >> $TMPDIR/$LOGNAME
sed -i -e 's/^destemail = root@localhost/destemail = security@multimail.work/g w /dev/stdout' /etc/fail2ban/jail.conf >> $TMPDIR/$LOGNAME
sed -i -e 's/^sender = *.*/sender = fail2ban@'$MYNAME'/g w /dev/stdout' /etc/fail2ban/jail.conf >> $TMPDIR/$LOGNAME
sed -i -e 's/^action = %(action_)s/action = %(action_mwl)s/g w /dev/stdout' /etc/fail2ban/jail.conf >> $TMPDIR/$LOGNAME
sed -i -e 's/^port     = ssh/port     = ssh,2222/g w /dev/stdout' /etc/fail2ban/jail.conf >> $TMPDIR/$LOGNAME
sed -i -e 's/^UMASK[\t ]*.*/UMASK           027/g w /dev/stdout' /etc/login.defs >> $TMPDIR/$LOGNAME
 
echo "" >> $TMPDIR/$LOGNAME
echo "Security - PSAD" >> $TMPDIR/$LOGNAME
echo "6 replacements" >> $TMPDIR/$LOGNAME
sed -i -e 's/EMAIL_ADDRESSES             root@localhost;/EMAIL_ADDRESSES             security@'${HOSTNAME}';/g w /dev/stdout' /etc/psad/psad.conf >> $TMPDIR/$LOGNAME
sed -i -e 's|IPT_SYSLOG_FILE             /var/log/messages;|IPT_SYSLOG_FILE             /var/log/syslog;|g w /dev/stdout' /etc/psad/psad.conf >> $TMPDIR/$LOGNAME
sed -i -e 's/EMAIL_ALERT_DANGER_LEVEL    1;/EMAIL_ALERT_DANGER_LEVEL    4;/g w /dev/stdout' /etc/psad/psad.conf >> $TMPDIR/$LOGNAME
sed -i -e 's/ENABLE_AUTO_IDS             N;/ENABLE_AUTO_IDS             Y;/g w /dev/stdout' /etc/psad/psad.conf >> $TMPDIR/$LOGNAME
sed -i -e 's/AUTO_IDS_DANGER_LEVEL       5;/AUTO_IDS_DANGER_LEVEL       2;/g w /dev/stdout' /etc/psad/psad.conf >> $TMPDIR/$LOGNAME
sed -i -e 's/ENABLE_AUTO_IDS_EMAILS      Y;/ENABLE_AUTO_IDS_EMAILS      N;/g w /dev/stdout' /etc/psad/psad.conf >> $TMPDIR/$LOGNAME
echo "$MYIP    0;" >> /etc/psad/auto_dl
psad --sig-update
service psad restart
 
echo "" >> $TMPDIR/$LOGNAME
echo "VPN Configuration" >> $TMPDIR/$LOGNAME

echo "Installing base VPN daemon and generating server certs" >> $TMPDIR/$LOGNAME
rm -rf /etc/openvpn/easy-rsa/
wget -O /root/EasyRSA-3.0.4.tgz https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.4/EasyRSA-3.0.4.tgz
tar xzf /root/EasyRSA-3.0.4.tgz -C /root/
mv /root/EasyRSA-3.0.4/ /etc/openvpn/easy-rsa/
chown -R root:root /etc/openvpn/easy-rsa/
rm -rf /root/EasyRSA-3.0.4.tgz
cd /etc/openvpn/easy-rsa/ && ./easyrsa init-pki
cd /etc/openvpn/easy-rsa/ && ./easyrsa --keysize=4096 --batch build-ca nopass
cd /etc/openvpn/easy-rsa/ && ./easyrsa --keysize=2048 gen-dh
cd /etc/openvpn/easy-rsa/ && ./easyrsa --keysize=4096 build-server-full server nopass
cd /etc/openvpn/easy-rsa/ && EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
cd /etc/openvpn/easy-rsa/pki && cp ca.crt private/ca.key dh.pem issued/server.crt private/server.key crl.pem /etc/openvpn
chown nobody:$GROUPNAME /etc/openvpn/crl.pem
openvpn --genkey --secret /etc/openvpn/ta.key

echo "Writing server config file" >> $TMPDIR/$LOGNAME
echo "port $PORT" > /etc/openvpn/server.conf
echo "proto $PROTOCOL" >> /etc/openvpn/server.conf
echo "dev tun" >> /etc/openvpn/server.conf
echo "sndbuf 0" >> /etc/openvpn/server.conf
echo "rcvbuf 0" >> /etc/openvpn/server.conf
echo "ca ca.crt" >> /etc/openvpn/server.conf
echo "cert server.crt" >> /etc/openvpn/server.conf
echo "key server.key" >> /etc/openvpn/server.conf
echo "dh dh.pem" >> /etc/openvpn/server.conf
echo "auth SHA512" >> /etc/openvpn/server.conf
echo "tls-auth ta.key 0" >> /etc/openvpn/server.conf
echo "topology subnet" >> /etc/openvpn/server.conf
echo "server 10.8.0.0 255.255.255.0" >> /etc/openvpn/server.conf
echo "ifconfig-pool-persist ipp.txt" >> /etc/openvpn/server.conf
echo "push \"redirect-gateway def1 bypass-dhcp\"" >> /etc/openvpn/server.conf
echo "keepalive 10 120" >> /etc/openvpn/server.conf
echo "cipher AES-256-CBC" >> /etc/openvpn/server.conf
echo "compress lz4" >> /etc/openvpn/server.conf
echo "user nobody" >> /etc/openvpn/server.conf
echo "group nogroup" >> /etc/openvpn/server.conf
echo "persist-key" >> /etc/openvpn/server.conf
echo "persist-tun" >> /etc/openvpn/server.conf
echo "status openvpn-status.log" >> /etc/openvpn/server.conf
echo "verb 3" >> /etc/openvpn/server.conf
echo "crl-verify crl.pem" >> /etc/openvpn/server.conf
echo "tls-cipher TLS-DHE-RSA-WITH-AES-256-GCM-SHA384:TLS-DHE-RSA-WITH-AES-256-CBC-SHA256" >> /etc/openvpn/server.conf
echo "ncp-ciphers AES-256-GCM:AES-256-CBC" >> /etc/openvpn/server.conf
echo "tls-version-min 1.2" >> /etc/openvpn/server.conf
echo "remote-cert-eku \"TLS Web Client Authentication\"" >> /etc/openvpn/server.conf

echo "Configuring forwarding for VPN" >> $TMPDIR/$LOGNAME
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
echo 1 > /proc/sys/net/ipv4/ip_forward
echo '#!/bin/sh -e' > $RCLOCAL
echo 'exit 0' >> $RCLOCAL
chmod +x $RCLOCAL
 
echo "Configuring firewall for VPN" >> $TMPDIR/$LOGNAME
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $MYIP
sed -i "1 a\iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $MYIP" $RCLOCAL
iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT -m comment --comment "Allow inbound VPN connections"
iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT
iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
sed -i "1 a\iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT" $RCLOCAL
sed -i "1 a\iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT" $RCLOCAL
sed -i "1 a\iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" $RCLOCAL
systemctl restart openvpn@server.service
sleep 10
iptables -L -v -n --line-numbers | more >> $TMPDIR/$LOGNAME
netstat -antup >> $TMPDIR/$LOGNAME
psad -S >> $TMPDIR/$LOGNAME

echo "Generating and writing client ovpn files" >> $TMPDIR/$LOGNAME
cd /etc/openvpn/easy-rsa/ && ./easyrsa --keysize=4096 build-client-full $CLIENT1 nopass
cd /etc/openvpn/easy-rsa/ && ./easyrsa --keysize=4096 build-client-full $CLIENT2 nopass
echo "client" > $TMPDIR/$CLIENT1
echo "dev tun" >> $TMPDIR/$CLIENT1
echo "proto $PROTOCOL" >> $TMPDIR/$CLIENT1
echo "sndbuf 0" >> $TMPDIR/$CLIENT1
echo "rcvbuf 0" >> $TMPDIR/$CLIENT1
echo "resolv-retry infinite" >> $TMPDIR/$CLIENT1
echo "nobind" >> $TMPDIR/$CLIENT1
echo "persist-tun" >> $TMPDIR/$CLIENT1
echo "remote-cert-tls server" >> $TMPDIR/$CLIENT1
echo "auth SHA512" >> $TMPDIR/$CLIENT1
echo "cipher AES-256-CBC" >> $TMPDIR/$CLIENT1
echo "compress lz4" >> $TMPDIR/$CLIENT1
echo "key-direction 1" >> $TMPDIR/$CLIENT1
echo "verb 3" >> $TMPDIR/$CLIENT1
echo "tls-version-min 1.2" >> $TMPDIR/$CLIENT1
echo "remote-cert-eku \"TLS Web Server Authentication\"" >> $TMPDIR/$CLIENT1
echo "auth-nocache" >> $TMPDIR/$CLIENT1
echo "remote $MYIP $PORT" >> $TMPDIR/$CLIENT1
echo "# When adding an ASN block, use this converter to write out the subnet" >> $TMPDIR/$CLIENT1
echo "# http://www.rjsmith.com/CIDR-Table.html" >> $TMPDIR/$CLIENT1
echo "route www.crunchbase.com 255.255.255.255 net_gateway" >> $TMPDIR/$CLIENT1
echo "# Route for JetBlue, https://ipinfo.io/AS19535" >> $TMPDIR/$CLIENT1
echo "route 64.25.20.0 255.255.255.0 net_gateway" >> $TMPDIR/$CLIENT1
echo "route 64.25.21.0 255.255.255.0 net_gateway" >> $TMPDIR/$CLIENT1
echo "route 64.25.22.0 255.255.255.0 net_gateway" >> $TMPDIR/$CLIENT1
echo "route 64.25.24.0 255.255.254.0 net_gateway" >> $TMPDIR/$CLIENT1
echo "route 64.25.28.0 255.255.254.0 net_gateway" >> $TMPDIR/$CLIENT1
echo "# Route for craigslist, https://ipinfo.io/AS22414" >> $TMPDIR/$CLIENT1
echo "route 208.82.236.0 255.255.252.0 net_gateway" >> $TMPDIR/$CLIENT1
echo "# Route for WeWork printing" >> $TMPDIR/$CLIENT1
echo "route print.wework.com 255.255.255.255 net_gateway" >> $TMPDIR/$CLIENT1

echo "<ca>" >> $TMPDIR/$CLIENT1
cat /etc/openvpn/easy-rsa/pki/ca.crt >> $TMPDIR/$CLIENT1
echo "</ca>" >> $TMPDIR/$CLIENT1
echo "<tls-auth>" >> $TMPDIR/$CLIENT1
cat /etc/openvpn/ta.key >> $TMPDIR/$CLIENT1
echo "</tls-auth>" >> $TMPDIR/$CLIENT1
 
cp $TMPDIR/$CLIENT1 $TMPDIR/$CLIENT2

echo "<cert>" >> $TMPDIR/$CLIENT1
cat /etc/openvpn/easy-rsa/pki/issued/$CLIENT1.crt >> $TMPDIR/$CLIENT1
echo "</cert>" >> $TMPDIR/$CLIENT1
echo "<key>" >> $TMPDIR/$CLIENT1
cat /etc/openvpn/easy-rsa/pki/private/$CLIENT1.key >> $TMPDIR/$CLIENT1
echo "</key>" >> $TMPDIR/$CLIENT1
 
echo "<cert>" >> $TMPDIR/$CLIENT2
cat /etc/openvpn/easy-rsa/pki/issued/$CLIENT2.crt >> $TMPDIR/$CLIENT2
echo "</cert>" >> $TMPDIR/$CLIENT2
echo "<key>" >> $TMPDIR/$CLIENT2
cat /etc/openvpn/easy-rsa/pki/private/$CLIENT2.key >> $TMPDIR/$CLIENT2
echo "</key>" >> $TMPDIR/$CLIENT2
 
echo "" >> $TMPDIR/$LOGNAME
echo "Beginning Cleanup" >> $TMPDIR/$LOGNAME
echo "NOT running service rsyslog stop"
echo "NOT running systemctl disable rsyslog"
echo "NOT running apt-get -y remove rsyslog"
echo "Packaging outputs for transfer"
tar -czf $TMPDIR/VPN-at-$MYIP.tar -C $TMPDIR .
chown -R $SERVERUSER:$SERVERUSER $TMPDIR
rm -rf /var/log/*
echo "NOT removing the temp directory of outputs so that Terraform can retrieve them first, then delete them" >> $TMPDIR/$LOGNAME
# rm -rf $TMPDIR
echo "Cleanup Complete" >> $TMPDIR/$LOGNAME

unset MYIP
unset MYNAME
unset TMPDIR
unset LOGNAME
unset OS
unset GROUPNAME
unset PORT
unset SERVERUSER
unset RCLOCAL
unset PROTOCOL
unset CLIENT1
unset CLIENT2
