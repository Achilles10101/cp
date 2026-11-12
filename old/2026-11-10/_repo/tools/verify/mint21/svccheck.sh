#!/bin/bash
# svccheck.sh - is every critical service still up AND answering? (TEST HARNESS)
# usage: svccheck.sh [ssh_port]
P="${1:-22}"
banner() { timeout 5 bash -c "exec 3<>/dev/tcp/127.0.0.1/$1; IFS= read -r -t 4 l <&3; echo \"\$l\"" 2>/dev/null | tr -d "\r"; }
chk() { local name="$1"; shift; if out="$("$@" 2>&1)"; then printf '  OK   %-11s %s\n' "$name" "$(echo "$out" | head -1 | cut -c1-70)"; else printf '  FAIL %-11s %s\n' "$name" "$(echo "$out" | tail -1 | cut -c1-90)"; fi; }
active() { for u in "$@"; do systemctl is-active --quiet "$u" && return 0; done; echo "not active: $*"; return 1; }
export -f active banner 2>/dev/null
has() { dpkg -s "$1" >/dev/null 2>&1; }
echo "service check $(date +%T)"
has openssh-server && chk ssh      bash -c "active ssh && ssh-keyscan -T 3 -p $P 127.0.0.1 2>/dev/null | grep -q ssh && echo 'keyscan ok on $P'"
has vsftpd         && chk vsftpd   bash -c "active vsftpd && b=\$(echo QUIT | timeout 4 bash -c 'exec 3<>/dev/tcp/127.0.0.1/21; head -1 <&3') && echo \"\$b\" | grep -q '^220' && curl -s --ssl -k --max-time 6 -u ftpuser:'Ftp-Us3r!pass' ftp://127.0.0.1/ -o /dev/null -w 'login+list ok (%{response_code})'"
has apache2        && chk apache2  bash -c "active apache2 && curl -sf -o /dev/null --max-time 5 -w 'http %{http_code}' http://127.0.0.1/ && { curl -sk -o /dev/null --max-time 5 -w ' https %{http_code}' https://127.0.0.1/ || true; }"
has nginx          && chk nginx    bash -c "active nginx && curl -s -o /dev/null --max-time 5 -w 'http %{http_code}' http://127.0.0.1/"
ls /etc/php/*/fpm >/dev/null 2>&1 && chk php-fpm bash -c "active php8.1-fpm php8.3-fpm && echo active"
has mysql-server || has mariadb-server && chk mysql bash -c "active mysql mariadb && mysql -NBe 'select concat(\"query ok \", version())'"
has postgresql     && chk postgres bash -c "active postgresql && sudo -u postgres psql -XAtc 'select \$\$query ok\$\$' "
has samba          && chk samba    bash -c "active smbd && smbclient -L 127.0.0.1 -N -m SMB3 2>&1 | grep -qE 'Sharename|NT_STATUS_ACCESS_DENIED|NT_STATUS_LOGON_FAILURE' && echo 'smb answers'"
has bind9          && chk bind9    bash -c "active named bind9 && dig +short +time=3 @127.0.0.1 localhost A | grep -q 127.0.0.1 && echo 'resolves localhost'"
has postfix        && chk postfix  bash -c "active postfix && b=\$(banner 25) && echo \"\$b\" | grep -q '^220' && echo \"\$b\""
has dovecot-core   && chk dovecot  bash -c "active dovecot && b=\$(banner 143) && echo \"\$b\" | grep -q 'OK' && echo \"\$b\""
has openvpn        && chk openvpn  bash -c "active openvpn && echo active"
has squid          && chk squid    bash -c "active squid && curl -s -o /dev/null --max-time 6 -x http://127.0.0.1:3128 -w 'proxied %{http_code}' http://127.0.0.1/"
