#!/bin/bash
# critical.sh - harden the CRITICAL services, in a safe order, with one summary at the end.
#
# Usage (from inside competition/):
#   sudo bash services/critical.sh              # detects the services installed here and asks for each one
#   sudo bash services/critical.sh ssh vsftpd   # only these (no questions about the others)
#   sudo bash services/critical.sh --list       # show what is detected, change nothing
#
# Nothing is read from or remembered for other scripts: for every detected service it shows what it found
# (installed / active / listening on :port) and asks "Run <svc>.sh (the README must list it as critical)? [y/N]".
# Order: ssh, vsftpd, databases (mysql, postgresql) before the web stack (apache2, nginx, php, wordpress),
# then samba, bind9, mail, openvpn, squid. Every service script asks its own README questions, validates
# its config, restarts once, checks the service answers and rolls back from /root/cp-backups on failure.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../cp-common.sh
source "$SCRIPT_DIR/../cp-common.sh" 2>/dev/null || { echo "ERROR: cp-common.sh not found (keep the repo layout intact)"; exit 1; }
cp_require_root

ORDER=(ssh vsftpd mysql postgresql apache2 nginx php wordpress samba bind9 mail openvpn squid)
LIST_ONLY=0; ARGS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --list|-n) LIST_ONLY=1 ;;
        -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
        *) ARGS+=("$1") ;;
    esac
    shift
done

# README spellings -> services/*.sh names
norm() {
    local w out=""
    for w in $(echo "$*" | tr 'A-Z,;' 'a-z  '); do
        case "$w" in
            ssh|openssh|openssh-server|sshd|sftp) w=ssh ;;
            ftp|vsftp|vsftpd|ftps) w=vsftpd ;;
            apache|apache2|httpd|http|web) w=apache2 ;;
            nginx) w=nginx ;;
            php|php-fpm) w=php ;;
            mysql|mariadb|mysql-server|mariadb-server) w=mysql ;;
            postgres|postgresql|psql|pgsql) w=postgresql ;;
            samba|smb|smbd|cifs) w=samba ;;
            bind|bind9|dns|named) w=bind9 ;;
            mail|postfix|dovecot|smtp|imap|email|e-mail) w=mail ;;
            wordpress|wp) w=wordpress ;;
            openvpn|vpn) w=openvpn ;;
            squid|proxy) w=squid ;;
            none|-) w=none ;;
            *) cp_warn "Unknown service name '$w' (known: ${ORDER[*]})" >&2; continue ;;
        esac
        [[ " $out " == *" $w "* ]] || out="$out $w"
    done
    echo "${out# }"
}

installed() {
    case "$1" in
        ssh)        command -v sshd >/dev/null || [ -x /usr/sbin/sshd ] ;;
        vsftpd)     command -v vsftpd >/dev/null || [ -x /usr/sbin/vsftpd ] ;;
        apache2)    command -v apache2ctl >/dev/null ;;
        nginx)      command -v nginx >/dev/null || [ -x /usr/sbin/nginx ] ;;
        php)        compgen -G '/etc/php/*/*/php.ini' >/dev/null ;;
        mysql)      command -v mysqld >/dev/null || command -v mariadbd >/dev/null || [ -x /usr/sbin/mysqld ] ;;
        postgresql) compgen -G '/etc/postgresql/*/main' >/dev/null ;;
        samba)      command -v smbd >/dev/null || [ -x /usr/sbin/smbd ] ;;
        bind9)      command -v named >/dev/null || [ -x /usr/sbin/named ] ;;
        mail)       command -v postconf >/dev/null || command -v doveconf >/dev/null ;;
        wordpress)  [ -n "$(find /var/www /srv /usr/share/wordpress /etc/wordpress -maxdepth 5 -name wp-config.php -print -quit 2>/dev/null)" ] ;;
        openvpn)    command -v openvpn >/dev/null && grep -qlE '^[[:space:]]*(server|mode[[:space:]]+server)([[:space:]]|$)' /etc/openvpn/server/*.conf /etc/openvpn/*.conf 2>/dev/null ;;
        squid)      command -v squid >/dev/null || [ -x /usr/sbin/squid ] ;;
        *) return 1 ;;
    esac
}

# is_up SVC -> prints "active" or "DOWN: units"; return 0 when up
is_up() {
    local u bad="" any
    case "$1" in
        ssh)        systemctl is-active --quiet ssh || systemctl is-active --quiet sshd || systemctl is-active --quiet ssh.socket || bad="ssh" ;;
        vsftpd)     systemctl is-active --quiet vsftpd || bad="vsftpd" ;;
        apache2)    systemctl is-active --quiet apache2 || bad="apache2" ;;
        nginx)      systemctl is-active --quiet nginx || bad="nginx" ;;
        php)        for u in $(systemctl list-unit-files 'php*-fpm.service' --no-legend 2>/dev/null | awk '{print $1}'); do
                        systemctl is-enabled --quiet "$u" 2>/dev/null && ! systemctl is-active --quiet "$u" && bad="$bad ${u%.service}"
                    done
                    if compgen -G '/etc/apache2/mods-enabled/php*.load' >/dev/null && ! systemctl is-active --quiet apache2; then bad="$bad apache2(mod_php)"; fi ;;
        mysql)      systemctl is-active --quiet mysql || systemctl is-active --quiet mariadb || bad="mysql" ;;
        postgresql) any=0
                    for u in $(systemctl list-units 'postgresql@*' --all --no-legend --plain 2>/dev/null | awk '{print $1}'); do
                        any=1; systemctl is-active --quiet "$u" || bad="$bad ${u%.service}"
                    done
                    [ $any = 1 ] || systemctl is-active --quiet postgresql || bad="postgresql" ;;
        samba)      systemctl is-active --quiet smbd || bad="smbd" ;;
        bind9)      systemctl is-active --quiet named || systemctl is-active --quiet bind9 || bad="named" ;;
        mail)       if command -v postconf >/dev/null; then systemctl is-active --quiet postfix@- || systemctl is-active --quiet postfix || bad="postfix"; fi
                    if command -v doveconf >/dev/null; then systemctl is-active --quiet dovecot || bad="$bad dovecot"; fi ;;
        wordpress)  systemctl is-active --quiet apache2 || systemctl is-active --quiet nginx || bad="web server" ;;
        openvpn)    systemctl list-units 'openvpn*@*' --state=active --no-legend 2>/dev/null | grep -q . || bad="openvpn" ;;
        squid)      systemctl is-active --quiet squid || bad="squid" ;;
    esac
    bad="${bad# }"
    if [ -z "$bad" ]; then echo "active"; return 0; fi
    echo "DOWN: $bad"; return 1
}

# listeners: "proc port" pairs from ss (TCP + UDP)
LISTEN="$(ss -Htlunp 2>/dev/null | awk '{ a = $5; sub(/.*:/, "", a); if (match($0, /users:\(\("[^"]+"/)) { p = substr($0, RSTART + 9, RLENGTH - 10); print p, a } }' | sort -u)"
ports_of() {  # ports_of PROC... -> ":22 :2222"
    local p out=""
    for p in "$@"; do out="$out $(echo "$LISTEN" | awk -v p="$p" '$1 == p || index($1, p) == 1 {printf ":%s ", $2}')"; done
    echo "$out" | tr ' ' '\n' | grep -v '^$' | sort -u | xargs
}
# hint SVC -> one line: what is installed, active and listening (a suggestion, never a decision)
hint() {
    local pk="" st="" po="" f
    case "$1" in
        ssh)        pk="openssh-server"; po="$(ports_of sshd)" ;;
        vsftpd)     pk="vsftpd"; po="$(ports_of vsftpd)" ;;
        apache2)    pk="apache2"; po="$(ports_of apache2)" ;;
        nginx)      pk="nginx"; po="$(ports_of nginx)" ;;
        php)        pk="php"; for f in /etc/php/*/*/php.ini; do [ -f "$f" ] && pk="$pk ${f#/etc/php/}"; done; pk="${pk//\/php.ini/}"; po="$(ports_of php-fpm)" ;;
        mysql)      pk="$(dpkg-query -W -f='${Package} ' mysql-server mariadb-server 2>/dev/null | xargs)"; po="$(ports_of mysqld mariadbd)" ;;
        postgresql) pk="postgresql"; for f in /etc/postgresql/*/main; do [ -d "$f" ] && pk="$pk $(basename "$(dirname "$f")")"; done; po="$(ports_of postgres)" ;;
        samba)      pk="samba"; po="$(ports_of smbd nmbd)" ;;
        bind9)      pk="bind9"; po="$(ports_of named)" ;;
        mail)       pk="$(dpkg-query -W -f='${Package} ' postfix dovecot-core 2>/dev/null | xargs)"; po="$(ports_of master dovecot)" ;;
        wordpress)  f="$(find /var/www /srv /usr/share/wordpress /etc/wordpress -maxdepth 5 -name wp-config.php -print -quit 2>/dev/null)"; pk="WordPress ($f)" ;;
        openvpn)    pk="openvpn, server config: $(grep -lE '^[[:space:]]*(server|mode[[:space:]]+server)([[:space:]]|$)' /etc/openvpn/server/*.conf /etc/openvpn/*.conf 2>/dev/null | xargs)"; po="$(ports_of openvpn)" ;;
        squid)      pk="squid"; po="$(ports_of squid)" ;;
    esac
    if is_up "$1" >/dev/null; then st="active"; else st="NOT active"; fi
    echo "$1: $pk installed, $st${po:+, listening on $po}"
}

cp_hdr "Critical services"
if [ ${#ARGS[@]} -gt 0 ]; then
    WANT=" $(norm "${ARGS[*]}") "
    WANT="${WANT/ none / }"
else
    FOUND=(); OTHER=()
    for s in "${ORDER[@]}"; do if installed "$s"; then FOUND+=("$s"); fi; done
    command -v openvpn >/dev/null 2>&1 && ! installed openvpn && OTHER+=("openvpn: installed, but no server config in /etc/openvpn(/server) - nothing to harden")
    if [ ${#FOUND[@]} -eq 0 ]; then cp_ok "None of the 13 hardenable services is installed."; exit 0; fi
    for o in "${OTHER[@]}"; do cp_info "$o"; done
    if [ "$LIST_ONLY" = 1 ]; then for s in "${FOUND[@]}"; do echo "      $(hint "$s")"; done; exit 0; fi
    echo "  Detected services below are suggestions only - the README decides which ones are critical."
    WANT=" "
    for s in "${FOUND[@]}"; do
        case "$s" in
            php)       note=" (PHP serves the apache2/nginx site: yes when the web server is critical)" ;;
            wordpress) note=" (WordPress needs its web server, PHP and database: say yes to those too)" ;;
            *)         note="" ;;
        esac
        echo "  $(hint "$s")$note"
        cp_ask "Run $s.sh (the README must list it as critical)?" n && WANT="$WANT$s "
    done
fi

PLAN=()
for s in "${ORDER[@]}"; do
    [[ "$WANT" == *" $s "* ]] || continue
    if installed "$s"; then PLAN+=("$s"); else cp_warn "$s: not installed / nothing to harden here - skipped"; fi
done
echo "  Plan: ${PLAN[*]:-(nothing)}"
[ "$LIST_ONLY" = 1 ] && exit 0
[ ${#PLAN[@]} -gt 0 ] || { cp_info "Nothing chosen - no service hardened."; exit 0; }

# ------------------------------------------------------------ run them --
declare -A RES UP DUR
T0=$SECONDS; LAST_START=""
mkdir -p "$CP_STATE_DIR/svc" && chmod 700 "$CP_STATE_DIR"
for s in "${PLAN[@]}"; do
    # each script backs up into /root/cp-backups/<second>/: never start two in the same second
    while [ "$(date +%Y%m%d_%H%M%S)" = "$LAST_START" ]; do sleep 0.2; done
    LAST_START="$(date +%Y%m%d_%H%M%S)"
    rm -f "$CP_STATE_DIR/svc/$s.result"
    t=$SECONDS
    echo
    echo "${CP_C_CYN}################ $s ################${CP_C_OFF}"
    bash "$SCRIPT_DIR/$s.sh"; rc=$?
    DUR[$s]=$((SECONDS - t))
    r="$(cat "$CP_STATE_DIR/svc/$s.result" 2>/dev/null)"
    case "$r" in
        OK*)       RES[$s]="hardened ok" ;;
        ROLLBACK*) RES[$s]="ROLLED BACK: ${r#ROLLBACK }" ;;
        FAIL*)     RES[$s]="FAILED: ${r#FAIL }" ;;
        *)         if [ $rc -eq 0 ]; then RES[$s]="finished"; else RES[$s]="FAILED: exit $rc"; fi ;;
    esac
    UP[$s]="$(is_up "$s")"
done

# ------------------------------------------------------------ summary --
cp_hdr "Critical services summary ($((SECONDS - T0))s)"
BAD=0
for s in "${PLAN[@]}"; do
    st="${UP[$s]%%:*}"   # active | DOWN
    line="$(printf '  %-10s %-6s %-46.46s %4ss' "$s" "$st" "${RES[$s]}" "${DUR[$s]}")"
    if [[ "${UP[$s]}" == DOWN* ]]; then
        echo "${CP_C_RED}$line  <- FIX NOW (${UP[$s]#DOWN: })${CP_C_OFF}"; BAD=1
        cp_todo "CRITICAL service $s is ${UP[$s]} - journalctl -xe; restore from /root/cp-backups if needed"
    elif [[ "${RES[$s]}" == FAILED* || "${RES[$s]}" == ROLLED* ]]; then
        echo "${CP_C_YEL}$line${CP_C_OFF}"; BAD=1
    else
        echo "$line"
    fi
done
exit $BAD
