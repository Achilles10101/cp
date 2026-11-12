#!/bin/bash
# install-services.sh - runs INSIDE a cp-mint-clean container. Installs every critical service with DEFAULT settings
# (apt defaults, recommends on, as `sudo apt install` on Mint; php-mysql because the 2026-10-21 pack has
# mysqli/pdo_mysql) + the test-only workarounds this kernel needs. Build with --hostname mint-cptest (postfix main.cf).
set -e; umask 022; export LANG=en_US.UTF-8
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d; chmod 755 /usr/sbin/policy-rc.d   # no starts during install
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -q openssh-server vsftpd apache2 php libapache2-mod-php php-fpm php-mysql \
    mysql-server postgresql samba bind9 postfix dovecot-imapd dovecot-pop3d openvpn squid nginx 2>&1 | tail -3
rm -f /usr/sbin/policy-rc.d
# ---- TEST-CONTAINER ONLY overrides (the container kernel has no IPv6 at all: socket(AF_INET6) fails) ----
# 1. vsftpd: default listen_ipv6=YES cannot bind -> IPv4 listener via a systemd drop-in (same file as plant-mint.sh)
mkdir -p /etc/systemd/system/vsftpd.service.d
printf '# TEST-CONTAINER ONLY: kernel has no IPv6\n[Service]\nExecStart=\nExecStart=/usr/sbin/vsftpd /etc/vsftpd.conf -olisten=YES -olisten_ipv6=NO\n' > /etc/systemd/system/vsftpd.service.d/cptest-noipv6.conf
# 2. dovecot: default "listen = *, ::" fails -> IPv4 only (local.conf is read last by dovecot.conf)
printf '# TEST-CONTAINER ONLY: kernel has no IPv6\nlisten = *\n' > /etc/dovecot/local.conf
# 3. nginx: default site listens on [::]:80 (no IPv6) and port 80 is apache2's -> installed but stopped + disabled
systemctl disable nginx >/dev/null 2>&1 || true
# test account for the vsftpd login check (svccheck.sh / vsftpd.sh "Test login" prompt)
id ftpuser >/dev/null 2>&1 || useradd -m -s /bin/bash ftpuser
echo 'ftpuser:Ftp-Us3r!pass' | chpasswd
find / -xdev -perm -0002 ! -type l ! -path '/proc/*' ! -path '/tmp' ! -path '/var/tmp' ! -path '/tmp/*' ! -path '/var/tmp/*' ! -path '/dev/*' ! -path '/run/*' -exec chmod o-w {} + 2>/dev/null || true
apt-get clean; rm -f /var/log/apt/*.log
echo services-installed
