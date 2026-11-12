#!/bin/bash
# !!! TEST-VM / CONTAINER ONLY - this PLANTS vulnerabilities. Never run it on a competition image. !!!
# Plant the vulnerable state that the scored checks look for (container only!)
P=/root/baseline/_pristine
# sysctl
dpkg-deb --fsys-tarfile $(ls /var/cache/apt/archives/procps_*.deb 2>/dev/null | head -1) 2>/dev/null | tar -xO ./etc/sysctl.conf > /tmp/sysctl.pristine 2>/dev/null || (cd /tmp && apt-get download -qq procps && dpkg-deb --fsys-tarfile procps_*.deb | tar -xO ./etc/sysctl.conf > /tmp/sysctl.pristine)
cp /tmp/sysctl.pristine /etc/sysctl.conf
cat >> /etc/sysctl.conf <<'X'
net.ipv4.tcp_syncookies=0
net.ipv4.ip_forward=1
net.ipv4.conf.all.accept_source_route = 1
net.ipv4.conf.all.send_redirects=1
net.ipv4.conf.all.accept_redirects = 1
kernel.randomize_va_space=0
fs.suid_dumpable = 2
X
sed -i '/^\*[[:space:]]*hard[[:space:]]*\(core\|nproc\)/d' /etc/security/limits.conf
# ssh
cp /usr/share/openssh/sshd_config /etc/ssh/sshd_config; printf 'PermitRootLogin yes\nPermitEmptyPasswords yes\n' >> /etc/ssh/sshd_config; chown ubuntu /etc/ssh/sshd_config
rm -f /etc/ssh/sshd_config.d/*.conf; printf 'PermitRootLogin yes\n' > /etc/ssh/sshd_config.d/60-evil.conf
# apache
cp $P/apache2/root/etc/apache2/conf-available/security.conf /etc/apache2/conf-available/security.conf
sed -i 's/^ServerTokens .*/ServerTokens Full/; s/^ServerSignature .*/ServerSignature On/' /etc/apache2/conf-available/security.conf
a2enconf security >/dev/null 2>&1
# vsftpd
cat > /etc/vsftpd.conf <<'X'
listen=NO
listen_ipv6=YES
anonymous_enable=YES
local_enable=YES
#write_enable=YES
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
#chroot_local_user=YES
chroot_list_enable=YES
chroot_list_file=/etc/vsftpd.chroot_list
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
ssl_enable=NO
ssl_sslv3=YES
allow_anon_ssl=YES
X
echo turret > /etc/vsftpd.chroot_list; mkdir -p /srv/ftp; chmod 777 /srv/ftp
# gdm
mkdir -p /etc/gdm3; cat > /etc/gdm3/custom.conf <<'X'
# GDM configuration storage
[daemon]
AutomaticLoginEnable = true
AutomaticLogin = ratman
User=rick
Group=rick

[security]
DisallowTCP=false
AllowRoot=true

[xdmcp]

[chooser]

[debug]
X
# auditd / pwquality / login.defs
sed -i 's/^local_events.*/local_events = no/' /etc/audit/auditd.conf
cp $(ls /root/cp-backups/*/etc/security/pwquality.conf | head -1) /etc/security/pwquality.conf 2>/dev/null
sed -i 's/^\(minlen\|ucredit\|lcredit\|dcredit\|ocredit\|dictcheck\|usercheck\).*$/# &/' /etc/security/pwquality.conf
sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD MD5/; s/^LOGIN_RETRIES.*/#LOGIN_RETRIES 5/' /etc/login.defs
# pam
cp $(ls /root/cp-backups/*/etc/pam.d/common-auth 2>/dev/null | head -1) /etc/pam.d/common-auth 2>/dev/null
sed -i 's/requisite\([[:space:]]*\)pam_deny.so/requisite\1pam_permit.so/' /etc/pam.d/common-auth
sed -i '1i auth sufficient pam_exec.so expose_authtok quiet /lib/x86_64-linux-gnu/security/pam-bd' /etc/pam.d/common-auth
# accounts / files
id syslog >/dev/null 2>&1 || useradd -r syslog; usermod -s /bin/bash syslog
chown ubuntu /home; touch /swapfile; chmod 644 /swapfile
chmod u+s /usr/bin/cp; [ -f /usr/bin/wget ] && chmod u+s /usr/bin/wget
echo 'fake' > /usr/src/evil_rabbit.so; echo /usr/src/evil_rabbit.so > /etc/ld.so.preload
grep -q GOODBYE /etc/bash.bashrc || echo "alias GOODBYE='rm -rf ~'" >> /etc/bash.bashrc
sed -i 's/^bin:[^:]*:/bin:$6$x$abcdefgh:/' /etc/shadow
sed -i 's/^root:[^:]*:/root:$6$grp$abc:/' /etc/gshadow
# sudo
grep -q '!env_reset' /etc/sudoers || printf 'Defaults !env_reset\nDefaults env_keep += "PATH"\n' >> /etc/sudoers
sed -i '/^Set /d' /etc/sudo.conf
# samba
cp /usr/share/samba/smb.conf /etc/samba/smb.conf; sed -i 's/^\[global\]/[global]\n   server min protocol = NT1/' /etc/samba/smb.conf
# squid
echo "http_access allow all" >> /etc/squid/squid.conf
# postgres
V=$(ls /etc/postgresql); echo "host all all 0.0.0.0/0 trust" >> /etc/postgresql/$V/main/pg_hba.conf; sed -i 's/^# disabled by postgresql.sh: //' /etc/postgresql/$V/main/pg_ident.conf; chmod 644 /etc/postgresql/$V/main/pg_hba.conf; sed -i 's/^ssl = on/ssl = off/' /etc/postgresql/$V/main/postgresql.conf
# php
sed -i 's/^display_errors = .*/display_errors = On/' /etc/php/*/apache2/php.ini; echo '<?php phpinfo(); ?>' > /var/www/html/info.php
# nginx
sed -i 's/^\(\s*\)server_tokens off;/\1# server_tokens off;/' /etc/nginx/nginx.conf
# dovecot
sed -i 's/^ssl = .*/ssl = yes/' /etc/dovecot/conf.d/10-ssl.conf; echo "auth_debug_passwords = yes" >> /etc/dovecot/conf.d/10-auth.conf
# FACL
setfacl -m u:ubuntu:rwx /usr/bin/sudo
echo planted
