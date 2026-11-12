#!/bin/bash
# V postcheck (runs INSIDE a test container): desktop, sudo, authorized accounts, services
echo "== desktop packages"
for p in cinnamon cinnamon-core lightdm network-manager mint-meta-cinnamon mint-meta-core slick-greeter lightdm-settings xorg; do
  s=$(dpkg-query -W -f='${Status}' "$p" 2>/dev/null); printf '  %-22s %s\n' "$p" "${s:-not-known}"; done
echo "  default target: $(systemctl get-default)  lightdm enabled: $(systemctl is-enabled lightdm 2>&1)  NetworkManager: $(systemctl is-active NetworkManager 2>&1)/$(systemctl is-enabled NetworkManager 2>&1)"
echo "== sudo"
ls -l /usr/bin/sudo; getfacl -p /usr/bin/sudo 2>/dev/null | grep -v '^#' | tr '\n' ' '; echo
visudo -c >/dev/null 2>&1 && echo "  visudo -c OK" || echo "  visudo -c FAIL"
for u in cpuser alice bob carol dave frank; do
  printf '  %-7s id: %s\n' "$u" "$(id "$u" 2>&1)"
  sudo -l -U "$u" 2>/dev/null | grep -E '^\s+\(' | sed 's/^/      sudo: /'
done
echo "  root passwd status: $(passwd -S root | awk '{print $2}')  cpuser: $(passwd -S cpuser | awk '{print $2,$3,$4,$5,$6,$7}')"
# can cpuser actually run sudo? (password unknown -> test via su with the cached ACL path: run sudo -n -l as cpuser)
su -s /bin/bash cpuser -c 'sudo -n -l >/dev/null 2>&1; echo "  cpuser sudo -n -l rc=$? (1 = needs password = OK, sudo works)"; sudo -V >/dev/null 2>&1 && echo "  sudo binary runs as cpuser"' 2>&1
echo "== homes"
for u in cpuser alice bob carol dave frank; do printf '  /home/%-6s %s\n' "$u" "$(stat -c '%A %U:%G' /home/$u 2>&1) files=$(find /home/$u -type f 2>/dev/null | wc -l)"; done
echo "== human accounts (uid>=1000 or with /home)"; awk -F: '$3>=1000 && $3<65534 {print "  "$1" "$3" "$6" "$7}' /etc/passwd
echo "== quarantine"; [ -f /root/cp-quarantine/INDEX.txt ] && sed 's/^/  /' /root/cp-quarantine/INDEX.txt || echo "  (none)"
echo "== services active"; for u in ssh vsftpd apache2 nginx php8.1-fpm mysql postgresql smbd named postfix dovecot openvpn squid cups avahi-daemon ufw; do printf '%s=%s ' "$u" "$(systemctl is-active $u 2>/dev/null)"; done; echo
echo "== ufw"; ufw status 2>/dev/null | head -20
echo "== sysctl ipv6 disable: $(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)"
echo "== TODO count: $(grep -c . /root/cp-state/TODO.txt 2>/dev/null)"
echo "== /opt"; ls /opt 2>/dev/null
