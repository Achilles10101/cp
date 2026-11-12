#!/bin/bash
# install-planted.sh - runs INSIDE a cp-mint-clean container: what an intro-round image has installed before the
# vulnerabilities are planted (OpenSSH = the critical service; vsftpd/apache2 = unauthorized services; hacking tools
# and a game = prohibited software), then tools/verify/mint21/plant-mint.sh (copied to /tmp/plant-mint.sh).
set -e; umask 022; export LANG=en_US.UTF-8
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d; chmod 755 /usr/sbin/policy-rc.d
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -q openssh-server vsftpd apache2 \
    nmap john hydra wireshark wireshark-common tshark aircrack-ng ophcrack minetest netcat-traditional telnetd 2>&1 | tail -2
rm -f /usr/sbin/policy-rc.d
systemctl start ssh apache2 || true
bash /tmp/plant-mint.sh
rm -f /tmp/plant-mint.sh
apt-get clean; rm -f /var/log/apt/*.log
