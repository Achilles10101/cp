#!/bin/bash
# critical.sh - harden every CRITICAL service from the README, in a safe order, with one summary.
#
# Usage (from inside competition/):
#   sudo bash services/critical.sh              # every service in SERVICES (README answers)
#   sudo bash services/critical.sh ssh vsftpd   # only these (no implied extras)
#   sudo bash services/critical.sh --list       # show the plan, change nothing
#   sudo bash services/critical.sh --auto       # same as CP_AUTO=1 (always-right steps not asked)
#
# SERVICES comes from /root/cp-state/readme.conf (written by readme.sh). If it is missing this
# script offers to run ../readme.sh, otherwise asks once and stores the answer.
# Order: ssh, vsftpd, databases (mysql, postgresql) before the web stack (apache2, nginx, php,
# wordpress), then samba, bind9, mail, openvpn, squid. From the README list:
#   wordpress -> also apache2 (or nginx), php and mysql when installed (WordPress needs them)
#   apache2/nginx + PHP installed -> also php
# Every service script validates its config, restarts once, checks the service answers and
# rolls back from /root/cp-backups on failure; this script only orders them and reports.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../cp-common.sh
source "$SCRIPT_DIR/../cp-common.sh" 2>/dev/null || { echo "ERROR: cp-common.sh not found (keep the repo layout intact)"; exit 1; }
cp_require_root

ORDER=(ssh vsftpd mysql postgresql apache2 nginx php wordpress samba bind9 mail openvpn squid)
LIST_ONLY=0; ARGS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --list|-n) LIST_ONLY=1 ;;
        --auto|-a) export CP_AUTO=1 ;;
        -h|--help) sed -n '2,19p' "$0"; exit 0 ;;
        *) ARGS+=("$1") ;;
    esac
    shift
done
export CP_AUTO="${CP_AUTO:-0}"

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

cp_hdr "Critical services"

# ------------------------------------------------------------ which services --
# ask_services -> sets WANT from a TYPED answer. Enter alone is not an answer (asked again, max 3 times);
# "none" while service packages are installed needs a [y/N] confirmation. Returns 1 = nothing usable typed.
ask_services() {
    local ans inst="" s
    for s in "${ORDER[@]}"; do installed "$s" && inst="$inst $s"; done
    echo "  Names: ${ORDER[*]} (or none)"
    [ -n "$inst" ] && echo "  Installed here:$inst"
    for _ in 1 2 3; do
        ans="$(cp_read "Critical services listed in the README (names, or none)" "")"
        if [ -z "$ans" ]; then cp_warn "No answer - type the README's critical services (e.g. OpenSSH), or: none"; continue; fi
        WANT="$(norm "$ans")"
        [ -n "$WANT" ] || { cp_warn "No known service name in '$ans'"; continue; }
        WANT="$(echo " $WANT " | sed 's/ none / /' | xargs)"        # names typed together with "none" win
        if [ -z "$WANT" ]; then
            if [ -n "$inst" ] && ! cp_ask "README lists NO critical service, but these are installed:$inst. Save 'none' (later scripts then offer to remove/stop them)?" n; then
                continue
            fi
            WANT=none
        fi
        return 0
    done
    return 1
}
if [ ${#ARGS[@]} -gt 0 ]; then
    WANT="$(norm "${ARGS[*]}")"
    EXPLICIT=1
else
    EXPLICIT=0
    # readme.sh: asked on a terminal; without one it can only take the CP_* environment (test harness)
    if ! cp_cfg_has SERVICES && [ -f "$CP_ROOT/readme.sh" ]; then
        if { [ -t 0 ] && cp_ask "README answers not recorded yet. Run readme.sh now?" y; } \
           || { [ ! -t 0 ] && [ -n "${CP_ADMINS:-}${CP_USERS:-}${CP_SERVICES:-}" ]; }; then
            bash "$CP_ROOT/readme.sh" || cp_warn "readme.sh did not finish"
        fi
    fi
    if ! cp_cfg_has SERVICES; then
        # Only a real answer is ever saved: "none" makes fileandpackage.sh/portandmisc.sh offer to remove/stop
        # every service, so Enter, a typo or a missing terminal must never turn into SERVICES=none.
        ENVW=""; [ -n "${CP_SERVICES:-}" ] && ENVW="$(norm "$CP_SERVICES")"
        if [ -n "$ENVW" ]; then
            WANT="$ENVW"; cp_cfg_set SERVICES "$WANT"; cp_info "SERVICES from the environment: $WANT"
        elif [ ! -t 0 ]; then
            cp_warn "The README's critical services are not recorded and there is no terminal to ask - nothing saved, nothing hardened."
            cp_todo "critical.sh: the README's critical services are not recorded - run sudo bash readme.sh (or critical.sh in a terminal), then sudo bash services/critical.sh"
            exit 1
        elif ask_services; then
            cp_cfg_set SERVICES "$WANT"
        else
            cp_warn "No critical services entered - nothing saved, nothing hardened."
            cp_todo "critical.sh: the README's critical services were not entered - re-run sudo bash services/critical.sh (or readme.sh)"
            exit 1
        fi
    fi
    WANT="$(norm "$(cp_cfg_get SERVICES)")"
fi
if [ -z "$WANT" ] || [ "$WANT" = none ]; then
    cp_ok "README lists no critical services - nothing to harden here."
    echo "  (Unneeded services are removed by fileandpackage.sh. Wrong? sudo bash services/critical.sh ssh ...)"
    exit 0
fi
WANT=" ${WANT/none/} "

declare -A WHY
for s in $WANT; do WHY[$s]="README"; done
[ "$EXPLICIT" = 1 ] && for s in $WANT; do WHY[$s]="asked"; done
if [ "$EXPLICIT" = 0 ]; then
    if [[ "$WANT" == *" wordpress "* ]]; then
        if installed apache2; then [[ "$WANT" == *" apache2 "* ]] || { WANT="$WANT apache2 "; WHY[apache2]="for wordpress"; }
        elif installed nginx; then [[ "$WANT" == *" nginx "* ]] || { WANT="$WANT nginx "; WHY[nginx]="for wordpress"; }; fi
        installed mysql && { [[ "$WANT" == *" mysql "* ]] || { WANT="$WANT mysql "; WHY[mysql]="for wordpress"; }; }
        installed php && { [[ "$WANT" == *" php "* ]] || { WANT="$WANT php "; WHY[php]="for wordpress"; }; }
    fi
    if { [[ "$WANT" == *" apache2 "* ]] || [[ "$WANT" == *" nginx "* ]]; } && installed php && [[ "$WANT" != *" php "* ]]; then
        WANT="$WANT php "; WHY[php]="PHP serves the site"
    fi
fi

PLAN=(); MISSING=()
for s in "${ORDER[@]}"; do
    [[ "$WANT" == *" $s "* ]] || continue
    if installed "$s"; then PLAN+=("$s"); else MISSING+=("$s"); fi
done
echo "  Plan: ${PLAN[*]:-(nothing installed)}"
for s in "${PLAN[@]}"; do [ "${WHY[$s]}" != README ] && [ "${WHY[$s]}" != asked ] && echo "        $s (${WHY[$s]})"; done
# why_missing SVC -> why there is nothing to harden: the software is absent, or present without a config
why_missing() {
    case "$1" in
        openvpn)    command -v openvpn >/dev/null 2>&1 && { echo "installed, but no server config found in /etc/openvpn or /etc/openvpn/server"; return; } ;;
        wordpress)  echo "no wp-config.php found under /var/www, /srv, /usr/share/wordpress, /etc/wordpress"; return ;;
        php)        compgen -G '/usr/bin/php*' >/dev/null && { echo "installed, but no /etc/php/*/*/php.ini found"; return; } ;;
        postgresql) compgen -G '/usr/lib/postgresql/*/bin/postgres' >/dev/null && { echo "installed, but no /etc/postgresql/<ver>/main cluster found"; return; } ;;
    esac
    echo "NOT INSTALLED"
}
declare -A WHYMISS
for s in "${MISSING[@]}"; do
    WHYMISS[$s]="$(why_missing "$s")"
    if [ "${WHYMISS[$s]}" = "NOT INSTALLED" ]; then
        cp_todo "README lists '$s' as critical but it is NOT installed - install it (apt install ...) and re-run: sudo bash services/critical.sh $s"
    else
        cp_todo "README lists '$s' as critical: ${WHYMISS[$s]} - nothing to harden; check the README / where its config lives"
    fi
done
[ "$LIST_ONLY" = 1 ] && exit 0
[ ${#PLAN[@]} -gt 0 ] || exit 1

cp_screenshot_prompt critical
# The screenshot question is asked once, here: cp_screenshot_prompt skips the question when
# CP_SHOT_ASKED equals CP_START_STEP (start.sh sets CP_START_STEP; standalone we use "critical").
# With a scoring report on the image every script still saves its own score snapshot.
export CP_START_STEP="${CP_START_STEP:-critical}"
export CP_SHOT_ASKED="$CP_START_STEP"

# ------------------------------------------------------------ run them --
declare -A RES UP DUR TODOS
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
    TODOS[$s]="$(grep -c "^\[$s.sh\]" "$CP_TODO_FILE" 2>/dev/null)"
done

# ------------------------------------------------------------ summary --
cp_hdr "Critical services summary ($((SECONDS - T0))s)"
BAD=0
for s in "${PLAN[@]}"; do
    st="${UP[$s]%%:*}"   # active | DOWN
    line="$(printf '  %-10s %-6s %-46.46s %4ss' "$s" "$st" "${RES[$s]}" "${DUR[$s]}")"
    [ "${TODOS[$s]:-0}" -gt 0 ] 2>/dev/null && line="$line  ${TODOS[$s]} TODO"
    if [[ "${UP[$s]}" == DOWN* ]]; then
        echo "${CP_C_RED}$line  <- FIX NOW (${UP[$s]#DOWN: })${CP_C_OFF}"; BAD=1
        cp_todo "CRITICAL service $s is ${UP[$s]} - journalctl -xe; restore from /root/cp-backups if needed"
    elif [[ "${RES[$s]}" == FAILED* || "${RES[$s]}" == ROLLED* ]]; then
        echo "${CP_C_YEL}$line${CP_C_OFF}"; BAD=1
    else
        echo "$line"
    fi
done
for s in "${MISSING[@]}"; do printf '  %-10s %-6s %s\n' "$s" "-" "${WHYMISS[$s]} (README says critical)"; BAD=1; done
[ -s "$CP_TODO_FILE" ] && echo "  Open TODOs (all scripts): $(wc -l < "$CP_TODO_FILE")  ->  cat $CP_TODO_FILE"
exit $BAD
