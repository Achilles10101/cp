#!/bin/bash
# TEST CONTAINER ONLY: Debian 12 intro image = same README/plants as cp-mint-planted, GDM instead of LightDM.
set -e; umask 022; export LANG=en_US.UTF-8
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d; chmod 755 /usr/sbin/policy-rc.d
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -q openssh-server vsftpd apache2 \
    nmap john hydra wireshark wireshark-common tshark aircrack-ng ophcrack minetest netcat-traditional telnetd 2>&1 | tail -2
rm -f /usr/sbin/policy-rc.d
systemctl start ssh apache2 vsftpd || true
set +e
bash /tmp/plant-mint.sh
# Debian: UID 998 is taken -> the hidden "system" user gets the next free system UID
id sysbackup >/dev/null 2>&1 || { useradd -r -m -d /home/sysbackup -s /bin/bash sysbackup; echo 'sysbackup:backup' | chpasswd; }
rm -rf /etc/lightdm          # Debian GNOME has no LightDM: GDM autologin instead
sed -i 's/^\[daemon\]/[daemon]\nAutomaticLoginEnable=true\nAutomaticLogin=bob/' /etc/gdm3/daemon.conf
rm -f /tmp/plant-mint.sh; apt-get clean; rm -f /var/log/apt/*.log
echo planted-deb12
