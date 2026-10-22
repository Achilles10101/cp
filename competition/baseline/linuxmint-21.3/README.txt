Baseline pack: Linux Mint 21.3 "Virginia" Cinnamon (Ubuntu 22.04 jammy base), captured 2026-10-21.
Clean test container: jammy packages + Linux Mint's own mintsystem 8.5.8 / mintupdate 6.0.9 / mintsources 2.2.9 /
mint-common 2.3.1 / lightdm-settings 2.0.2 built from github.com/linuxmint (Mint's package server was unreachable).
  system/ and the top-level *.txt  -> captured on the image WITHOUT any services (stock Mint desktop)
  <service>/                       -> captured after installing every critical service with default settings:
                                      openssh-server vsftpd apache2 php libapache2-mod-php php-fpm mysql-server (8.0)
                                      postgresql (14) samba bind9 postfix dovecot-imapd/pop3d openvpn squid nginx
Removed on purpose (different on every install, would always show as "changed"): ssh host keys,
/etc/hosts, /etc/mysql/debian.cnf, /etc/bind/rndc.key, and a test-only /etc/dovecot/local.conf.
MariaDB was not captured (mysql/ is MySQL 8.0). baseline.sh also uses this pack for linuxmint-21.1 / 21.2.
