#!/bin/bash
# systemconfig.sh - system hardening. Run as root from inside competition/:  sudo bash systemconfig.sh
# Research-doc items: SYS1-SYS10, G1 (in-place edits), G3 (UFW application profiles).
#
# Round 5 (2026-11-11, Max's redesign): no shared README state - the script asks what it needs.
#   * Every fix is a normal [Y/n]/[y/N] question with the right default for a CyberPatriot image; lists are
#     one question (y/n/e = each). Detection is shown as a hint line above the question, never used silently.
#   * Firewall: the server daemons found installed/listening are listed with the UFW rule each needs, and
#     you choose (one batch; default yes for a daemon that is actually listening), plus extra ports.
#   * README-dependent questions: firewall rules, extra ports, IPv6, GRUB passwords, other firewall rules.
#   * Everything that needs apt (unattended-upgrades, libpam-pwquality, auditd) runs LAST in one apt call
#     (libpam-pwquality before common-password is edited, 2026-10-21 fix 7). Debian: sources.list rewrite first.
#   * Manual follow-ups go to the TODO list (cp_todo); backups to /root/cp-backups/<timestamp>/.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=cp-common.sh
source "$SCRIPT_DIR/cp-common.sh" 2>/dev/null || { echo "ERROR: cp-common.sh not found next to systemconfig.sh"; exit 1; }

cp_require_root
cp_screenshot_prompt

# CyberPatriot scoring client - NEVER scanned, listed, quarantined, killed or disabled by these scripts:
# CCS images keep it in /opt/CyberPatriot (README.desktop, ScoringReport.html, gain.wav, alarm.wav, Icon.png,
# the CCSClient service), aeacus practice images in /opt/aeacus (phocus). Matched case-insensitively.
SCORING_RE='^/opt/(cyberpatriot|aeacus)(/|$)|(^|/)(ccs|css)client|(^|/)phocus|aeacus'
is_scoring() { local x; for x in "$@"; do [[ "${x,,}" =~ $SCORING_RE ]] && return 0; done; return 1; }

T_START=$SECONDS
bk() { cp_backup "$@" >/dev/null; }          # quiet backup; the folder is printed once at the end
since() { echo "$(( SECONDS - $1 ))s"; }

echo "Starting system hardening..."

# ===================================================================== SYS10 ld.so.preload (first) ==
# a planted /etc/ld.so.preload hooks EVERY command this script runs. The scored item is usually the rootkit
# library itself (e.g. PathExistsNot /usr/src/evil_rabbit.so). baseline.sh --review may already have moved
# ld.so.preload to /root/cp-quarantine/etc/ld.so.preload - the libraries listed there are handled too.
preload_libs() { grep -vE '^[[:space:]]*(#|$)' "$1" 2>/dev/null | tr ' :' '\n\n' | grep -v '^$'; }
PRELOAD_LIBS=""
QPRELOAD=/root/cp-quarantine/etc/ld.so.preload
if [ -s /etc/ld.so.preload ] || [ -s "$QPRELOAD" ]; then cp_hdr "SYS10 /etc/ld.so.preload"; fi
if [ -s /etc/ld.so.preload ]; then
    cp_warn "/etc/ld.so.preload is set (LD_PRELOAD rootkit?):"; sed 's/^/        /' /etc/ld.so.preload
    if cp_ask "Empty /etc/ld.so.preload (stock Ubuntu/Mint has none)?" y; then
        PRELOAD_LIBS="$(preload_libs /etc/ld.so.preload)"
        bk /etc/ld.so.preload; : > /etc/ld.so.preload; cp_ok "Emptied /etc/ld.so.preload"
    fi
fi
if [ -s "$QPRELOAD" ]; then
    cp_info "baseline --review already quarantined ld.so.preload ($QPRELOAD) - checking the libraries it listed"
    PRELOAD_LIBS="$PRELOAD_LIBS $(preload_libs "$QPRELOAD")"
fi
for lib in $(printf '%s\n' $PRELOAD_LIBS | sort -u); do
    [ -f "$lib" ] || continue
    if cp_owned "$lib" || cp_owned "$(readlink -f "$lib")"; then cp_warn "$lib belongs to a package - not deleting"; continue; fi
    is_scoring "$lib" && { cp_warn "$lib is part of the scoring engine - not deleting"; continue; }
    cp_ask "Delete the preloaded library $lib (no package owns it)?" y && { bk "$lib"; rm -f "$lib"; cp_ok "Deleted $lib (backup in $CP_BACKUP_ROOT/$CP_TS)"; }
done

# ===================================================================== firewall (UFW) ==
# Rules come from the daemons found + your answer (G3: application profiles first, they are what the
# scoring regexes match, e.g. "OpenSSH *ALLOW *Anywhere").
FW_ADDED=()                                   # the "ufw allow ..." rules this run asked for
fw_ssh_ports() {
    local p
    p="$(sshd -T 2>/dev/null | awk '$1 == "port" {print $2}' | sort -u | tr '\n' ' ')"
    [ -z "$p" ] && p="$(grep -hiE '^[[:space:]]*Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | awk '{print $2}' | sort -u | tr '\n' ' ')"
    echo "${p:-22}"
}
fw_openvpn() {   # prints "port/proto" of the first OpenVPN server config (default 1194/udp)
    local f port="" proto=""
    for f in /etc/openvpn/server/*.conf /etc/openvpn/*.conf; do
        [ -f "$f" ] || continue
        port="$(awk '$1 == "port" {print $2; exit}' "$f")"; proto="$(awk '$1 == "proto" {print $2; exit}' "$f")"
        break
    done
    case "$proto" in tcp*) proto=tcp ;; *) proto=udp ;; esac
    echo "${port:-1194}/$proto"
}
# Detection -> suggestions. "name port" of every listening process, read once.
FW_LST="$(ss -Htulpn 2>/dev/null | awk '{n = split($5, a, ":"); nm = ""; if (match($0, /\(\("[^"]*"/)) nm = substr($0, RSTART + 3, RLENGTH - 4); print nm, a[n]}' | sort -u)"
lports() { awk -v re="$1" '$1 ~ re {print ":" $2}' <<< "$FW_LST" | sort -u -t: -k2n | tr '\n' ' ' | sed 's/ $//'; }
FW_CAND=()   # "DEFAULT|LABEL|PROFILE|PORTS|HINT"
fw_cand() { FW_CAND+=("$1|$2|$3|$4|$5"); }
fw_detect() {
    local lp p mn mx d
    if cp_pkg_installed openssh-server; then
        lp="$(lports '^sshd$')"; d=n; [ -n "$lp" ] && d=y
        fw_cand $d "OpenSSH" "OpenSSH" "22/tcp" "openssh-server installed${lp:+, sshd listening on $lp}"
        for p in $(fw_ssh_ports); do [ "$p" = 22 ] || fw_cand $d "SSH port $p" "" "$p/tcp" "sshd_config Port $p"; done
    fi
    if cp_pkg_installed apache2; then lp="$(lports '^apache2$')"; d=n; [ -n "$lp" ] && d=y
        fw_cand $d "Apache Full" "Apache Full" "80/tcp 443/tcp" "apache2 installed${lp:+, listening on $lp}"; fi
    if cp_pkg_installed nginx-core || cp_pkg_installed nginx; then lp="$(lports '^nginx')"; d=n; [ -n "$lp" ] && d=y
        fw_cand $d "Nginx Full" "Nginx Full" "80/tcp 443/tcp" "nginx installed${lp:+, listening on $lp}"; fi
    if cp_pkg_installed vsftpd; then lp="$(lports '^vsftpd$')"; d=n; [ -n "$lp" ] && d=y
        fw_cand $d "vsftpd" "vsftpd" "21/tcp" "vsftpd installed${lp:+, listening on $lp}"
        mn="$(cp_get /etc/vsftpd.conf pasv_min_port eq)"; mx="$(cp_get /etc/vsftpd.conf pasv_max_port eq)"
        [ -n "$mn" ] && [ -n "$mx" ] && fw_cand $d "FTP passive range" "" "$mn:$mx/tcp" "vsftpd.conf pasv_min/max_port"; fi
    if cp_pkg_installed samba; then lp="$(lports '^(smbd|nmbd)$')"; d=n; [ -n "$lp" ] && d=y
        fw_cand $d "Samba" "Samba" "137,138/udp 139,445/tcp" "samba installed${lp:+, listening on $lp}"; fi
    if cp_pkg_installed bind9; then lp="$(lports '^named$')"; d=n; [ -n "$lp" ] && d=y
        fw_cand $d "Bind9" "Bind9" "53" "bind9 installed${lp:+, named listening on $lp}"; fi
    if cp_pkg_installed postfix; then lp="$(lports '^(master|smtpd)$')"; d=n; [ -n "$lp" ] && d=y
        fw_cand $d "Postfix" "Postfix" "25/tcp" "postfix installed${lp:+, listening on $lp}"
        fw_cand $d "Postfix Submission" "Postfix Submission" "587/tcp" "postfix submission port"; fi
    if cp_pkg_installed dovecot-core; then lp="$(lports '^dovecot$')"
        d=n; [[ " $lp " == *" :143 "* || " $lp " == *" :993 "* ]] && d=y
        fw_cand $d "Dovecot IMAP" "Dovecot IMAP" "143/tcp" "dovecot installed${lp:+, listening on $lp}"
        fw_cand $d "Dovecot Secure IMAP" "Dovecot Secure IMAP" "993/tcp" "IMAPS"
        d=n; [[ " $lp " == *" :110 "* || " $lp " == *" :995 "* ]] && d=y
        fw_cand $d "Dovecot POP3" "Dovecot POP3" "110/tcp" "POP3 - only if the README needs POP3"
        fw_cand $d "Dovecot Secure POP3" "Dovecot Secure POP3" "995/tcp" "POP3S - only if the README needs POP3"; fi
    if cp_pkg_installed openvpn; then lp="$(lports '^openvpn$')"; d=n; [ -n "$lp" ] && d=y
        fw_cand $d "OpenVPN" "OpenVPN" "$(fw_openvpn)" "openvpn installed${lp:+, listening on $lp}"; fi
    if cp_pkg_installed squid || cp_pkg_installed squid-openssl; then lp="$(lports '^squid$')"; d=n; [ -n "$lp" ] && d=y
        # the "Squid" UFW profile opens 5 ports (2048,3128,3130,3401,4827) - open only http_port
        p="$(awk '$1 == "http_port" {print $2; exit}' /etc/squid/squid.conf 2>/dev/null)"; p="${p##*:}"
        fw_cand $d "Squid" "" "${p:-3128}/tcp" "squid installed${lp:+, listening on $lp}"; fi
    if cp_pkg_installed mysql-server || cp_pkg_installed mariadb-server || ls /var/lib/dpkg/info/mysql-server-core-*.list >/dev/null 2>&1; then
        fw_cand n "MySQL (remote)" "" "3306/tcp" "MySQL/MariaDB installed - only if the README needs REMOTE database access"; fi
    if ls /var/lib/dpkg/info/postgresql-[0-9]*.list >/dev/null 2>&1; then
        fw_cand n "PostgreSQL (remote)" "PostgreSQL" "5432/tcp" "PostgreSQL installed - only if the README needs REMOTE database access"; fi
}
fw_allow() {   # fw_allow PROFILE PORTS...
    local prof="$1" p; shift
    if [ -n "$prof" ] && ufw app list 2>/dev/null | sed 's/^[[:space:]]*//' | grep -qxF "$prof"; then
        ufw allow "$prof" >/dev/null && { cp_ok "UFW: allowed profile '$prof'"; FW_ADDED+=("$prof"); }
    else
        for p in "$@"; do ufw allow "$p" >/dev/null && { cp_ok "UFW: allowed $p${prof:+ (no '$prof' profile)}"; FW_ADDED+=("$p"); }; done
    fi
}
# fw_delete "allow 'Apache Full'" -> ufw delete allow 'Apache Full'. The words are split by xargs (which
# understands the quotes ufw prints), never by eval: nothing in a rule string is run as shell code.
fw_delete() {
    printf '%s\n' "$1" | xargs ufw delete >/dev/null 2>&1 && cp_ok "Deleted rule: $1" || cp_err "could not delete rule: $1"
}
firewall() {
    cp_hdr "Firewall (UFW)"
    local r prof extra tok line other=() a t t0=$SECONDS d lbl ports hint nY=0 pick=()
    fw_detect
    ufw default deny incoming >/dev/null; ufw default allow outgoing >/dev/null
    if [ ${#FW_CAND[@]} -eq 0 ]; then
        cp_info "No server daemons detected - only the extra ports you type are opened"
    else
        echo "  Server daemons found (SSH first) - [Y] = listening now. Allow only what the README needs:"
        for r in "${FW_CAND[@]}"; do
            IFS='|' read -r d lbl prof ports hint <<< "$r"
            [ "$d" = y ] && nY=$((nY + 1))
            printf "    [%s] %-22s %-24s %s\n" "${d^^}" "$lbl" "($ports)" "$hint"
        done
        # opening a port is a README decision: default no (Enter opens nothing); y = the [Y] suggestions, e = each
        case "$(ask3 "Allow the $nY [Y] rule(s)? (y = all [Y], e = decide each - usually e: only what the README needs)" n)" in
            y) for r in "${FW_CAND[@]}"; do [ "${r%%|*}" = y ] && pick+=("$r"); done ;;
            e) for r in "${FW_CAND[@]}"; do IFS='|' read -r d lbl prof ports hint <<< "$r"; cp_ask "Allow $lbl ($ports)?" "$d" && pick+=("$r"); done ;;
        esac
        for r in "${pick[@]}"; do
            IFS='|' read -r d lbl prof ports hint <<< "$r"
            # shellcheck disable=SC2086
            fw_allow "$prof" $ports
        done
    fi
    extra="$(cp_read "Extra ports the README needs (e.g. 8080/tcp, space separated), Enter = none" "")"
    for tok in $extra; do ufw allow "$tok" >/dev/null && { cp_ok "UFW: allowed $tok"; FW_ADDED+=("$tok"); } || cp_err "ufw rejected '$tok'"; done
    ufw logging on >/dev/null 2>&1; ufw logging high >/dev/null 2>&1
    ufw --force enable >/dev/null && cp_ok "UFW enabled: deny incoming, allow outgoing, logging high" || cp_err "ufw enable failed"
    # rules nobody asked for (planted, or left from the image) - "ufw show added" lists them as "ufw allow X"
    while IFS= read -r line; do
        [[ "$line" == "ufw "* ]] || continue
        a="${line#ufw allow }"; a="${a#\'}"; a="${a%\'}"
        for t in "${FW_ADDED[@]}"; do [ "$a" = "$t" ] && continue 2; done
        other+=("${line#ufw }")
    done < <(ufw show added 2>/dev/null)
    if [ ${#other[@]} -gt 0 ]; then
        cp_warn "Other firewall rules (not chosen above): ${other[*]}"
        case "$(ask3 "Delete these ${#other[@]} rule(s)?" n)" in
            y) for r in "${other[@]}"; do fw_delete "$r"; done ;;
            e) for r in "${other[@]}"; do cp_ask "Delete rule '$r'?" n && fw_delete "$r"; done ;;
        esac
    fi
    ufw status 2>/dev/null | grep -E 'Status|ALLOW|DENY' | sed 's/^/        /'
    cp_info "firewall done ($(since $t0))"
}
# ask3 "Question" DEFAULT -> echoes y, n or e (default on no terminal)
ask3() {
    local q="$1" def="$2" hint ans
    if [ "$def" = y ]; then hint="[Y/n/e]"; else hint="[y/N/e]"; fi
    [ -t 0 ] || { echo "$def"; return; }
    while true; do
        read -r -p "  ? $q $hint: " ans
        ans="${ans:-$def}"
        case "$ans" in [Yy]*) echo y; return ;; [Nn]*) echo n; return ;; [Ee]*) echo e; return ;; esac
    done
}
FW_DEFERRED=0
if command -v ufw >/dev/null 2>&1; then firewall; else FW_DEFERRED=1; cp_warn "ufw is not installed - it is installed with the other packages at the end"; fi

# ===================================================================== SYS6 display manager ==
if systemctl list-unit-files 2>/dev/null | grep -q "lightdm.service"; then
    cp_hdr "LightDM (guest / autologin)"
    LIGHTDM_CONF="/etc/lightdm/lightdm.conf"
    # Mint ships its settings in lightdm.conf.d and may have no lightdm.conf at all - create it
    if [ ! -f "$LIGHTDM_CONF" ]; then
        cp_info "$LIGHTDM_CONF not found - creating it"
        mkdir -p /etc/lightdm
        printf '[Seat:*]\n' > "$LIGHTDM_CONF"
    fi
    grep -q '^\[Seat:\*\]' "$LIGHTDM_CONF" || printf '\n[Seat:*]\n' >> "$LIGHTDM_CONF"

    # backup goes to /root/cp-backups: a lightdm.conf.backup next to it kept the planted
    # autologin/guest lines inside /etc/lightdm, where a directory-wide check still finds them
    bk "$LIGHTDM_CONF"
    [ -f "${LIGHTDM_CONF}.backup" ] && { bk "${LIGHTDM_CONF}.backup"; rm -f "${LIGHTDM_CONF}.backup"; }

    # LightDM (GKeyFile) also accepts "key = value" - match optional spaces
    sed -i -E '/^[[:space:]]*(allow-guest|greeter-hide-users|greeter-allow-guest|greeter-show-manual-login|autologin-guest|autologin-user|autologin-user-timeout|autologin-session|xserver-allow-tcp)[[:space:]]*=/d' "$LIGHTDM_CONF"

    sed -i '/^\[Seat:\*\]/a \
allow-guest=false\
greeter-hide-users=true\
greeter-allow-guest=false\
greeter-show-manual-login=true\
autologin-guest=false\
autologin-user=NONE\
xserver-allow-tcp=false' "$LIGHTDM_CONF"

    # SYS6 / B3: drop-in files override lightdm.conf - remove insecure lines there too
    LDM_BAD='^[[:space:]]*((allow-guest|greeter-allow-guest|autologin-guest|xserver-allow-tcp)[[:space:]]*=[[:space:]]*true|autologin-user[[:space:]]*=[[:space:]]*([^N[:space:]].*|N[^O].*|)|autologin-user-timeout[[:space:]]*=.*)[[:space:]]*$'
    for f in /etc/lightdm/lightdm.conf.d/*.conf /usr/share/lightdm/lightdm.conf.d/*.conf; do
        [ -f "$f" ] || continue
        if grep -qE "$LDM_BAD" "$f"; then
            bk "$f"
            sed -i -E "/$LDM_BAD/d" "$f"
            cp_ok "Removed guest/autologin/TCP settings from drop-in $f"
        fi
    done
    cp_ok "LightDM: no guest, no autologin, users hidden, manual login, no X over TCP"
fi

# SYS6: GDM3 (Ubuntu desktop: custom.conf; Debian 12: daemon.conf) - every one that exists
for GDM_CONF in /etc/gdm3/custom.conf /etc/gdm3/daemon.conf /etc/gdm/custom.conf; do
    [ -f "$GDM_CONF" ] || continue
    cp_hdr "GDM ($GDM_CONF)"
    bk "$GDM_CONF"
    cp_set "$GDM_CONF" AutomaticLoginEnable False eq 0 0 daemon
    cp_unset "$GDM_CONF" AutomaticLogin eq 0 0 daemon
    cp_set "$GDM_CONF" TimedLoginEnable false eq 0 0 daemon
    cp_unset "$GDM_CONF" User eq 0 0 daemon
    cp_unset "$GDM_CONF" Group eq 0 0 daemon
    cp_set "$GDM_CONF" DisallowTCP true eq 0 0 security
    cp_set "$GDM_CONF" AllowRoot false eq 0 0 security
    cp_ok "GDM: no automatic login, no custom User/Group, DisallowTCP=true, AllowRoot=false"
done

# ===================================================================== UMASK / login.defs ==
cp_hdr "UMASK, login.defs"
if [ -f /etc/login.defs ]; then
    bk /etc/login.defs
    if grep -q "^UMASK" /etc/login.defs; then
        sed -i 's/^UMASK.*/UMASK\t\t027/' /etc/login.defs
    else
        echo "UMASK     027" >> /etc/login.defs
    fi
    # SYS3: hashing algorithm and login retries (scored in practice images)
    cp_set /etc/login.defs ENCRYPT_METHOD SHA512 space
    cp_set /etc/login.defs LOGIN_RETRIES 3 space
    # Checklist password aging, automated. MAX 30 (not 90): Aperture's check only accepts 1-30,
    # and 30 also passes any "<= 90" style check. MIN 7 (>= 5 required there), WARN 14.
    cp_set /etc/login.defs PASS_MAX_DAYS 30 space
    cp_set /etc/login.defs PASS_MIN_DAYS 7 space
    cp_set /etc/login.defs PASS_WARN_AGE 14 space
    cp_ok "login.defs: UMASK 027, SHA512, LOGIN_RETRIES 3, PASS_MAX/MIN/WARN 30/7/14"
else
    cp_err "/etc/login.defs not found - skipped"
fi
if [ -f /etc/profile ]; then
    bk /etc/profile
    grep -q "^umask 027" /etc/profile || sed -i '1i umask 027' /etc/profile
    cp_ok "/etc/profile: umask 027"
else
    cp_err "/etc/profile not found - skipped"
fi

# ===================================================================== SYS1/SYS2 sysctl ==
cp_hdr "Kernel parameters (sysctl)"
[ -f /etc/sysctl.conf ] && bk /etc/sysctl.conf || touch /etc/sysctl.conf

# SYS1 / G1: every key is set IN PLACE in /etc/sysctl.conf (a planted "ip_forward=1" line is
# replaced, not left above our value) and removed from /etc/sysctl.d/*.conf, where a later
# file would silently override it.
SYSCTL_SETTINGS=(
    # Security Hardening Parameters (original list)
    "fs.file-max = 65535"
    "fs.suid_dumpable = 0"
    "kernel.core_uses_pid = 1"
    "kernel.dmesg_restrict = 1"
    "kernel.sysrq = 0"
    "kernel.randomize_va_space = 2"
    "kernel.pid_max = 65536"
    "net.core.rmem_max = 8388608"
    "net.core.wmem_max = 8388608"
    "net.core.netdev_max_backlog = 5000"
    "net.ipv4.tcp_rmem = 10240 87380 12582912"
    "net.ipv4.tcp_wmem = 10240 87380 12582912"
    "net.ipv4.tcp_window_scaling = 1"
    "net.ipv4.conf.all.accept_redirects = 0"
    "net.ipv4.conf.all.accept_source_route = 0"
    "net.ipv4.conf.all.log_martians = 1"
    "net.ipv4.conf.all.secure_redirects = 0"
    "net.ipv4.conf.all.send_redirects = 0"
    "net.ipv4.conf.default.accept_redirects = 0"
    "net.ipv4.conf.default.accept_source_route = 0"
    "net.ipv4.conf.default.log_martians = 1"
    "net.ipv4.conf.default.secure_redirects = 0"
    "net.ipv4.conf.default.send_redirects = 0"
    "net.ipv4.icmp_echo_ignore_all = 1"
    "net.ipv4.icmp_echo_ignore_broadcasts = 1"
    "net.ipv4.icmp_ignore_bogus_error_responses = 1"
    "net.ipv4.ip_forward = 0"
    "net.ipv4.ip_local_port_range = 2000 65000"
    "net.ipv4.tcp_max_syn_backlog = 2048"
    "net.ipv4.tcp_synack_retries = 2"
    "net.ipv4.tcp_syncookies = 1"
    "net.ipv4.tcp_syn_retries = 5"
    "net.ipv4.tcp_timestamps = 1"
    # SYS2: scored in practice images
    "net.ipv4.tcp_rfc1337 = 1"
    "net.ipv4.conf.all.rp_filter = 1"
    "net.ipv4.conf.default.rp_filter = 1"
    "kernel.kptr_restrict = 2"
    "kernel.kexec_load_disabled = 1"
    "dev.tty.ldisc_autoload = 0"
    "kernel.perf_event_paranoid = 3"
    "fs.protected_hardlinks = 1"
    "fs.protected_symlinks = 1"
    "kernel.yama.ptrace_scope = 1"
    # Does not exist on modern kernels (sysctl prints one harmless error), but Aperture Science scored it
    "kernel.exec-shield = 1"
)

# sysctl.conf is loaded as 99-sysctl.conf, so earlier package files cannot override it; only planted
# (unowned) files and files sorting after 99-sysctl.conf can. Worked out ONCE (was dpkg-query -S per key per file).
SYSCTL_D_CHECK=()
for f in /etc/sysctl.d/*.conf; do
    [ -f "$f" ] || continue
    [ "$(readlink -f "$f")" = "$(readlink -f /etc/sysctl.conf)" ] && continue
    if cp_owned "$f" && [[ "$(basename "$f")" < "99-sysctl.conf" ]]; then continue; fi
    SYSCTL_D_CHECK+=("$f")
done
trim() { local s="$1"; s="${s#"${s%%[![:space:]]*}"}"; echo "${s%"${s##*[![:space:]]}"}"; }
apply_sysctl_list() {
    local kv k v f cur
    for kv in "$@"; do
        k="$(trim "${kv%%=*}")"; v="$(trim "${kv#*=}")"
        cp_set /etc/sysctl.conf "$k" "$v" eqs
        for f in "${SYSCTL_D_CHECK[@]}"; do
            cur="$(cp_get "$f" "$k")"
            if [ -n "$cur" ] && [ "$cur" != "$v" ]; then
                bk "$f"
                cp_warn "$f overrides $k = $cur - removing it there"
                cp_unset "$f" "$k"
            fi
        done
    done
}
apply_sysctl_list "${SYSCTL_SETTINGS[@]}"
cp_ok "${#SYSCTL_SETTINGS[@]} parameters set in place in /etc/sysctl.conf"

# Planted sysctl.d files that no package owns (B3): conflicting keys are gone; anything left is for a human
for f in /etc/sysctl.d/*.conf; do
    [ -f "$f" ] && [ ! -L "$f" ] || continue
    cp_owned "$f" && continue
    if grep -qvE '^[[:space:]]*(#|$)' "$f"; then
        cp_warn "sysctl.d file not owned by any package: $f"; grep -vE '^[[:space:]]*(#|$)' "$f" | sed 's/^/        /'
        cp_todo "Review $f (no package owns it; conflicting keys already removed)"
    fi
done

# IPv6 - README-dependent; default: disable (scored, e.g. Aperture "IPv6 disabled"). With disable_ipv6=1 the
# wildcard [::] still binds (stock vsftpd listen_ipv6=YES, nginx "listen [::]:80", dovecot "listen = *, ::"), only a
# SPECIFIC IPv6 address (e.g. ::1) fails with EADDRNOTAVAIL - so the default is "no" only when a critical
# service's live config binds one. (The no-IPv6 test containers are a kernel without IPv6 at all - different.)
V6_HEX='[0-9a-fA-F:]*(:[0-9a-fA-F]|[0-9a-fA-F]:)[0-9a-fA-F:]*'        # an IPv6 literal with at least one digit = not "::"
v6_specific() {   # v6_specific SVC -> prints "file: line" when SVC's config binds a specific IPv6 address
    local f
    case "$1" in
        nginx)   grep -rsHE "^[[:space:]]*listen[[:space:]]+\[${V6_HEX}\]" /etc/nginx/nginx.conf /etc/nginx/conf.d /etc/nginx/sites-enabled ;;
        apache2) grep -rsHE "^[[:space:]]*(Listen|<VirtualHost)[[:space:]].*\[${V6_HEX}\]" /etc/apache2/ports.conf /etc/apache2/sites-enabled /etc/apache2/conf-enabled ;;
        vsftpd)  grep -sHE "^[[:space:]]*listen_address6[[:space:]]*=[[:space:]]*${V6_HEX}[[:space:]]*$" /etc/vsftpd.conf | grep -vE '=[[:space:]]*::[[:space:]]*$' ;;
        mail)    grep -rsHE "^[[:space:]]*listen[[:space:]]*=.*(^|[ ,=])\[?${V6_HEX}\]?([ ,]|$)" /etc/dovecot/dovecot.conf /etc/dovecot/conf.d
                 grep -sHE "^[[:space:]]*inet_interfaces[[:space:]]*=.*\[${V6_HEX}\]" /etc/postfix/main.cf ;;
        ssh)     grep -sHE "^[[:space:]]*ListenAddress[[:space:]]+\[?${V6_HEX}\]?" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf ;;
        squid)   grep -sHE "^[[:space:]]*http_port[[:space:]]+\[${V6_HEX}\]" /etc/squid/squid.conf ;;
        mysql)   grep -rsHE "^[[:space:]]*bind[-_]address[[:space:]]*=[[:space:]]*${V6_HEX}[[:space:]]*$" /etc/mysql | grep -vE '=[[:space:]]*::[[:space:]]*$' ;;
        postgresql) for f in /etc/postgresql/*/main/postgresql.conf; do
                       grep -sHE "^[[:space:]]*listen_addresses[[:space:]]*=.*['\", ]${V6_HEX}['\", ]" "$f" | grep -vE "['\", ]::['\", ]"
                    done ;;
    esac 2>/dev/null
}
V6_DEF=y; V6_WHY=""
V6_SVCS="nginx apache2 vsftpd mail ssh squid mysql postgresql"     # only configs that exist are read
for s in $V6_SVCS; do
    hit="$(v6_specific "$s" | head -1)"
    [ -n "$hit" ] || continue
    V6_DEF=n; V6_WHY="${V6_WHY:+$V6_WHY; }$s binds a specific IPv6 address ($hit)"
done
[ -n "$V6_WHY" ] && cp_warn "IPv6: default is 'no' because $V6_WHY - it would not start with IPv6 disabled"
if cp_ask "Disable IPv6 (scored on some images; n = keep it, hardened)?" "$V6_DEF"; then
    apply_sysctl_list \
        "net.ipv6.conf.all.disable_ipv6 = 1" \
        "net.ipv6.conf.default.disable_ipv6 = 1" \
        "net.ipv6.conf.lo.disable_ipv6 = 1"
    cp_ok "IPv6 disabled"
else
    apply_sysctl_list \
        "net.ipv6.conf.all.disable_ipv6 = 0" \
        "net.ipv6.conf.default.disable_ipv6 = 0" \
        "net.ipv6.conf.default.router_solicitations = 0" \
        "net.ipv6.conf.default.accept_ra_rtr_pref = 0" \
        "net.ipv6.conf.default.accept_ra_pinfo = 0" \
        "net.ipv6.conf.default.accept_ra_defrtr = 0" \
        "net.ipv6.conf.default.autoconf = 0" \
        "net.ipv6.conf.default.dad_transmits = 0" \
        "net.ipv6.conf.default.max_addresses = 1"
    cp_ok "IPv6 kept, hardened"
fi

if sysctl --system > /dev/null 2>&1; then
    cp_ok "Applied (sysctl --system: same order as at boot)"
else
    cp_warn "Some parameters failed (kernel.exec-shield always does on modern kernels):"
    sysctl --system 2>&1 | grep -iE 'cannot|invalid|error|denied' | grep -v 'exec-shield' | sed 's/^/        /' || true
fi

# ===================================================================== SYS3 PAM (no packages needed) ==
cp_hdr "SYS3 PAM backdoors"
if ! grep -qE '^[[:space:]]*auth[[:space:]]+requisite[[:space:]]+pam_deny\.so' /etc/pam.d/common-auth; then
    cp_warn "common-auth has no 'auth requisite pam_deny.so' - failed passwords may be accepted:"
    grep -vE '^[[:space:]]*(#|$)' /etc/pam.d/common-auth | sed 's/^/        /'
    if grep -qE '^[[:space:]]*auth[[:space:]]+requisite[[:space:]]+pam_permit\.so' /etc/pam.d/common-auth; then
        if cp_ask "Replace 'requisite pam_permit.so' with 'requisite pam_deny.so' (stock line)?" y; then
            bk /etc/pam.d/common-auth
            sed -i -E 's/^([[:space:]]*auth[[:space:]]+requisite[[:space:]]+)pam_permit\.so/\1pam_deny.so/' /etc/pam.d/common-auth
            cp_ok "pam_deny restored"
        fi
    else
        cp_todo "common-auth has no 'auth requisite pam_deny.so' line - compare with a stock common-auth"
    fi
fi
PAM_EXEC_FILES=()
for f in /etc/pam.d/common-auth /etc/pam.d/common-account /etc/pam.d/common-password /etc/pam.d/common-session /etc/pam.d/common-session-noninteractive /etc/pam.d/sshd /etc/pam.d/login /etc/pam.d/sudo /etc/pam.d/su; do
    [ -f "$f" ] || continue
    grep -qE '^[[:space:]]*[a-z]+[[:space:]].*pam_exec\.so' "$f" || continue
    PAM_EXEC_FILES+=("$f")
    grep -nE '^[[:space:]]*[a-z]+[[:space:]].*pam_exec\.so' "$f" | sed "s|^|        $f:|"
done
if [ ${#PAM_EXEC_FILES[@]} -gt 0 ] && cp_ask "Remove these pam_exec lines (stock Ubuntu/Mint has none)?" y; then
    for f in "${PAM_EXEC_FILES[@]}"; do
        bk "$f"; sed -i -E '/^[[:space:]]*[a-z]+[[:space:]].*pam_exec\.so/d' "$f"; cp_ok "Removed pam_exec from $f"
    done
fi
grep -rlE '^[[:space:]]*[a-z]+[[:space:]].*pam_exec\.so' /etc/pam.d/ 2>/dev/null | while read -r f; do cp_todo "pam_exec still referenced in $f - review"; done
[ ${#PAM_EXEC_FILES[@]} -eq 0 ] && grep -qE '^[[:space:]]*auth[[:space:]]+requisite[[:space:]]+pam_deny\.so' /etc/pam.d/common-auth && cp_ok "pam_deny present, no pam_exec lines"

# ===================================================================== SYS4 sudo ==
cp_hdr "SYS4 sudo.conf / sudoers defaults"
SUDO_LIBS="$(ls /usr/libexec/sudo/libsudo_util.so* /usr/lib/sudo/libsudo_util.so* 2>/dev/null) $(command -v sudo)"
bk /etc/sudo.conf
touch /etc/sudo.conf
for kv in "disable_coredump true" "probe_interfaces false" "developer_mode false"; do
    k="${kv%% *}"
    # only write settings this sudo version knows (unknown settings produce warnings)
    # shellcheck disable=SC2086
    grep -aq "$k" $SUDO_LIBS 2>/dev/null || { cp_info "sudo does not know '$k' - skipped"; continue; }
    sed -i -E "/^[[:space:]]*Set[[:space:]]+${k}[[:space:]]/d" /etc/sudo.conf
    echo "Set $kv" >> /etc/sudo.conf
done
cp_ok "sudo.conf: $(grep -E '^Set ' /etc/sudo.conf | tr '\n' ';')"
bk /etc/sudoers /etc/sudoers.d
for f in /etc/sudoers /etc/sudoers.d/*; do
    [ -f "$f" ] || continue
    if grep -qE '^[[:space:]]*Defaults[[:space:]]+(!env_reset|env_keep[[:space:]]*\+?=[[:space:]]*"?PATH)' "$f"; then
        sed -i -E '/^[[:space:]]*Defaults[[:space:]]+(!env_reset|env_keep[[:space:]]*\+?=[[:space:]]*"?PATH"?)[[:space:]]*$/d' "$f"
        cp_ok "Removed insecure Defaults (!env_reset / env_keep PATH) from $f"
    fi
done
printf 'Defaults use_pty\nDefaults logfile="/var/log/sudo.log"\n' > /etc/sudoers.d/99-cp-hardening
chmod 440 /etc/sudoers.d/99-cp-hardening
if visudo -c >/dev/null 2>&1; then
    cp_ok "sudoers valid (use_pty, logfile=/var/log/sudo.log)"
else
    cp_err "visudo -c failed - restoring sudoers"; cp_restore /etc/sudoers /etc/sudoers.d; rm -f /etc/sudoers.d/99-cp-hardening
fi

# ===================================================================== SYS5 limits ==
bk /etc/security/limits.conf
sed -i -E '/^[[:space:]]*\*[[:space:]]+hard[[:space:]]+(core|nproc)[[:space:]]/d' /etc/security/limits.conf
printf '* hard core 0\n* hard nproc 2500\n' >> /etc/security/limits.conf
cp_ok "limits.conf: * hard core 0, * hard nproc 2500"

# ===================================================================== SYS8 GRUB ==
for f in /boot/grub/grub.cfg /boot/grub2/grub.cfg; do
    [ -f "$f" ] && { chown root:root "$f"; chmod 600 "$f"; cp_ok "$f -> 600 root:root"; }
done
if [ -f /etc/grub.d/40_custom ] && grep -qE '^[[:space:]]*(set[[:space:]]+superusers|password|password_pbkdf2)' /etc/grub.d/40_custom; then
    cp_hdr "SYS8 GRUB passwords"
    cp_warn "GRUB superusers/passwords in /etc/grub.d/40_custom (remove any the README does not authorize):"
    grep -nE '^[[:space:]]*(set[[:space:]]+superusers|password|password_pbkdf2|set[[:space:]]+check_signatures|export)' /etc/grub.d/40_custom | sed 's/^/        /'
    if cp_ask "Remove ALL superuser/password lines from 40_custom?" n; then
        bk /etc/grub.d/40_custom
        sed -i -E '/^[[:space:]]*(set[[:space:]]+superusers|password|password_pbkdf2)/d' /etc/grub.d/40_custom
        update-grub >/dev/null 2>&1 && cp_ok "Removed; grub.cfg regenerated"
    else
        cp_todo "GRUB 40_custom superusers/passwords left as they are - check them against the README"
    fi
fi

# ===================================================================== SYS9 permission plants ==
cp_hdr "SYS9 permissions, root, system accounts"
# Checklist "Enforce permissions" step, automated (a world-readable /etc/shadow is scored)
chown root:shadow /etc/shadow /etc/gshadow 2>/dev/null; chmod 640 /etc/shadow /etc/gshadow
chown root:root /etc/passwd /etc/group; chmod 644 /etc/passwd /etc/group
cp_ok "/etc/shadow + gshadow 640 root:shadow, /etc/passwd + group 644 root:root"
# Checklist "Disable root login" step
# (checked as "root:!" in /etc/shadow - a "*" root hash counts as locked for passwd -S but not for that check)
if grep -q '^root:!' /etc/shadow; then cp_ok "root account already locked (root:! in /etc/shadow)"
elif cp_ask "Lock the root account (passwd -l root)? You keep using sudo" y; then passwd -l root >/dev/null && grep -q '^root:!' /etc/shadow && cp_ok "root locked"; fi
chown root:root /home; chmod 755 /home; cp_ok "/home -> 755 root:root"
[ -f /swapfile ] && { chmod 600 /swapfile; chown root:root /swapfile; cp_ok "/swapfile -> 600"; }
# group passwords in gshadow
GPW="$(awk -F: '$2 != "" && $2 != "!" && $2 != "*" && $2 != "!*" && $2 != "!!" {print $1}' /etc/gshadow | tr '\n' ' ')"
if [ -n "$GPW" ]; then
    cp_warn "Groups with a group password in /etc/gshadow: $GPW"
    if cp_ask "Remove these group passwords?" y; then
        bk /etc/gshadow
        for g in $GPW; do sed -i -E "s/^($g):[^:]*:/\1:!:/" /etc/gshadow; done; cp_ok "Group passwords removed"
    fi
fi
# system accounts: no password, no login shell (README users with a low UID are left alone)
SHELL_FIX=(); PW_FIX=()
while IFS=: read -r u _ uid _ _ _ sh; do
    [[ "$uid" =~ ^[0-9]+$ ]] || continue
    [ "$uid" -lt 1000 ] && [ "$u" != root ] || continue
    case "$u" in sync|shutdown|halt|postgres) continue ;; esac
    if [ -n "$sh" ] && ! [[ "$sh" =~ (nologin|false)$ ]]; then SHELL_FIX+=("$u"); fi
    pw="$(awk -F: -v u="$u" '$1==u{print $2}' /etc/shadow)"
    if [ -n "$pw" ] && [[ "$pw" != \** ]] && [[ "$pw" != \!* ]]; then PW_FIX+=("$u"); fi
done < /etc/passwd
if [ ${#SHELL_FIX[@]} -gt 0 ]; then
    cp_warn "System accounts with a login shell: $(for u in "${SHELL_FIX[@]}"; do printf '%s(%s) ' "$u" "$(getent passwd "$u" | cut -d: -f7)"; done)"
    case "$(ask3 "Set their shell to /usr/sbin/nologin (e = each; a README user with a low UID keeps it)?" y)" in
        y) for u in "${SHELL_FIX[@]}"; do usermod -s /usr/sbin/nologin "$u" && cp_ok "$u -> nologin"; done ;;
        e) for u in "${SHELL_FIX[@]}"; do cp_ask "Set $u's shell to nologin?" y && usermod -s /usr/sbin/nologin "$u" && cp_ok "$u -> nologin"; done ;;
    esac
fi
if [ ${#PW_FIX[@]} -gt 0 ]; then
    cp_warn "System accounts with a password hash: ${PW_FIX[*]}"
    case "$(ask3 "Remove their passwords (set to '*'; e = each)?" y)" in
        y) for u in "${PW_FIX[@]}"; do usermod -p '*' "$u" && cp_ok "$u password removed"; done ;;
        e) for u in "${PW_FIX[@]}"; do cp_ask "Remove the password of $u?" y && usermod -p '*' "$u" && cp_ok "$u password removed"; done ;;
    esac
fi
# SUID/SGID on binaries that should never have it
SUID_FIX=()
for b in cp mv wget curl date nano vim vi find bash sh dash python3 perl less more tar zip unzip nmap awk gawk sed tee dd chmod chown env nc netcat socat; do
    p="$(command -v "$b" 2>/dev/null)"; [ -n "$p" ] || continue; p="$(readlink -f "$p")"
    { [ -u "$p" ] || [ -g "$p" ]; } || continue
    [[ " ${SUID_FIX[*]} " == *" $p "* ]] || SUID_FIX+=("$p")
done
if [ ${#SUID_FIX[@]} -gt 0 ]; then
    cp_warn "SUID/SGID on: $(for p in "${SUID_FIX[@]}"; do printf '%s(%s) ' "$p" "$(stat -c %A "$p")"; done)"
    if cp_ask "Remove SUID/SGID from these binaries (never set on stock)?" y; then
        for p in "${SUID_FIX[@]}"; do chmod u-s,g-s "$p" && cp_ok "Fixed $p"; done
    fi
fi
# File ACLs (a FACL on /usr/bin/sudo was scored). Stock Ubuntu/Mint has no ACLs on system binaries
# or /etc -> strip those. /home and /var/www are ONLY listed: a scored image REQUIRED a
# restrictive ACL there (getfacl /home/glados must contain group:testsubjects:---).
if command -v getfacl >/dev/null 2>&1; then
    SYSACL="$(getfacl -R -s -p /usr/bin /usr/sbin /bin /sbin /usr/local/bin /usr/local/sbin /etc 2>/dev/null | sed -n 's/^# file: //p' | sort -u)"
    if [ -n "$SYSACL" ]; then
        cp_warn "Extended ACLs on system files:"
        for f in $SYSACL; do echo "        $f: $(getfacl -p -c "$f" 2>/dev/null | grep -vE '^(user|group|other|mask)::' | tr '\n' ' ')"; done
        if cp_ask "Strip these ACLs (setfacl -b; stock has none)?" y; then
            for f in $SYSACL; do setfacl -b "$f"; done; cp_ok "ACLs removed from system files"
        fi
    fi
    USRACL="$(getfacl -R -s -p /home /var/www /srv 2>/dev/null | sed -n 's/^# file: //p' | head -50)"
    [ -n "$USRACL" ] && cp_todo "ACLs under /home, /var/www, /srv - compare with the README (some may be REQUIRED): $(echo "$USRACL" | head -5 | tr '\n' ' ')$( [ "$(echo "$USRACL" | wc -l)" -gt 5 ] && echo '...')"
fi

# ===================================================================== SYS10 persistence ==
cp_hdr "SYS10 persistence spots"
DKMS="$(ls /lib/modules/"$(uname -r)"/updates/dkms/ 2>/dev/null | tr '\n' ' ')"
[ -n "$DKMS" ] && cp_todo "DKMS kernel modules (keylogger?): $DKMS - check /lib/modules/$(uname -r)/updates/dkms"
# stock Ubuntu/Mint system-wide shell files contain no active aliases -> any alias there is suspicious
ALIAS_FILES=()
for f in /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh /etc/bash_aliases /etc/environment; do
    [ -f "$f" ] || continue
    grep -qE '^[[:space:]]*alias[[:space:]]' "$f" || continue
    ALIAS_FILES+=("$f")
    grep -nE '^[[:space:]]*alias[[:space:]]' "$f" | sed "s|^|        $f:|"
done
if [ ${#ALIAS_FILES[@]} -gt 0 ] && cp_ask "Remove these system-wide aliases (stock files have none)?" y; then
    for f in "${ALIAS_FILES[@]}"; do bk "$f"; sed -i -E '/^[[:space:]]*alias[[:space:]]/d' "$f"; cp_ok "Removed aliases from $f"; done
fi
UALIAS="$(grep -nE '^[[:space:]]*alias[[:space:]]' /root/.bashrc /home/*/.bashrc /home/*/.bash_aliases 2>/dev/null \
    | grep -vE "alias (ls|grep|fgrep|egrep|dir|vdir)='(ls|grep|fgrep|egrep|dir|vdir) --color=auto'|alias (ll|la|l)='ls -(alF|A|CF)'|alias alert='notify-send")"
[ -n "$UALIAS" ] && { echo "$UALIAS" | sed 's/^/        /'; cp_todo "Review aliases in user shell files: $(echo "$UALIAS" | cut -d: -f1 | sort -u | tr '\n' ' ')"; }
HOSTS="$(grep -vE '^[[:space:]]*(#|$)|^(127\.0\.0\.1|127\.0\.1\.1)[[:space:]]+(localhost|'"$(hostname)"')|^::1|^(fe00|ff0[0-2])::' /etc/hosts)"
HOSTS="$(echo "$HOSTS" | grep -viE 'cyberpatriot|aeacus|scoring')"     # scoring server entries: never a TODO
[ -n "$HOSTS" ] && cp_todo "Review /etc/hosts entries (hijack?): $(echo "$HOSTS" | tr -s ' \t' ' ' | tr '\n' ';')"
HOLDS="$(apt-mark showhold 2>/dev/null | tr '\n' ' ')"
[ -n "$HOLDS" ] && cp_info "apt holds: $HOLDS(fileandpackage.sh unholds what it removes and lists the rest as TODO)"
# Cron (checklist "Check cron"): jobs no package installed, plus every user crontab
BACKDOOR_RE='(\bnc(at)?(\.traditional|\.openbsd)?\b.*-[a-z]*[el]|socat|/dev/tcp/|bash -i|sh -i|python[0-9.]* -c|perl -e|curl[^|]*\|[[:space:]]*(ba)?sh|wget[^|]*\|[[:space:]]*(ba)?sh|mkfifo|chmod [0-7]*[4-7][0-7]{3} )'
CRON_BD=()
for f in /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* /var/spool/cron/crontabs/*; do
    [ -f "$f" ] || continue
    case "$f" in */.placeholder) continue ;; esac
    if is_scoring "$f" || grep -qiE '/opt/(cyberpatriot|aeacus)|(ccs|css)client|phocus' "$f" 2>/dev/null; then
        cp_info "Cron file $f belongs to the scoring engine - not touched"; continue
    fi
    if [ "$f" != /etc/crontab ] && cp_owned "$f"; then continue; fi
    [ "$f" = /etc/crontab ] && dpkg --verify cron 2>/dev/null | grep -q ' /etc/crontab$' || [ "$f" != /etc/crontab ] || continue
    cp_warn "Cron file not from any package (or modified): $f"
    grep -vE '^[[:space:]]*(#|$)' "$f" | sed 's/^/          /' | head -10
    if grep -qE "$BACKDOOR_RE" "$f" && [ "$f" != /etc/crontab ]; then CRON_BD+=("$f")
    else cp_todo "Review cron file $f (not from any package)"; fi
done
if [ ${#CRON_BD[@]} -gt 0 ] && cp_ask "Delete these backdoor cron files (reverse shell / download-and-run): ${CRON_BD[*]}?" y; then
    for f in "${CRON_BD[@]}"; do bk "$f"; rm -f "$f"; cp_ok "Deleted $f (backup in /root/cp-backups/$CP_TS)"; done
fi

# ===================================================================== apt phase (last) ==
# APT sources, Debian only (merged from Max's Mac copy, 2026-11-10): rewritten every run on purpose - a planted or
# changed sources.list is a scored item and the official lines are known. Ubuntu/Mint are skipped: Debian lines
# would break apt there. Runs before the installs below, which need working sources.
debian_sources() {
    local id codename f t0=$SECONDS extra=() conf
    id="$(. /etc/os-release 2>/dev/null; echo "${ID:-unknown}")"
    codename="$(. /etc/os-release 2>/dev/null; echo "${VERSION_CODENAME:-}")"
    if [ "$id" != debian ]; then cp_info "APT sources: $id - sources.list left alone (the Debian rewrite is for Debian images only)"; return 0; fi
    cp_hdr "APT sources.list (Debian)"
    [ -n "$codename" ] || codename=bookworm
    bk /etc/apt/sources.list /etc/apt/sources.list.d
    cat > /etc/apt/sources.list <<SRCEOF
deb http://deb.debian.org/debian $codename main non-free-firmware
deb http://deb.debian.org/debian $codename-updates main non-free-firmware
deb http://security.debian.org/debian-security $codename-security main non-free-firmware
SRCEOF
    chown root:root /etc/apt/sources.list; chmod 644 /etc/apt/sources.list
    cp_ok "/etc/apt/sources.list rewritten: $codename, $codename-updates, $codename-security (main non-free-firmware, as stock Debian 12)"
    # anything in sources.list.d is a second source of packages (incl. a debian.sources that now duplicates sources.list)
    for f in /etc/apt/sources.list.d/*; do [ -f "$f" ] && extra+=("$f"); done
    if [ ${#extra[@]} -gt 0 ]; then
        cp_warn "Extra repository files in /etc/apt/sources.list.d (keep one only if the README needs that repository):"
        for f in "${extra[@]}"; do echo "        $f: $(grep -hE '^(deb |URIs:|Suites:)' "$f" 2>/dev/null | tr -s ' ' | tr '\n' ';')"; done
        if cp_ask "Move these ${#extra[@]} file(s) aside (to $CP_BACKUP_ROOT/$CP_TS/disabled-sources)?" y; then
            mkdir -p "$CP_BACKUP_ROOT/$CP_TS/disabled-sources"
            for f in "${extra[@]}"; do mv -f "$f" "$CP_BACKUP_ROOT/$CP_TS/disabled-sources/" && cp_ok "Moved aside: $f"; done
        else
            cp_todo "Extra APT repositories kept in /etc/apt/sources.list.d - check them against the README"
        fi
    fi
    # apt may also be pointed elsewhere through apt.conf (a rogue proxy / insecure repositories)
    conf="$(grep -rnEi 'Acquire::(http|https)::Proxy|AllowInsecureRepositories|AllowUnauthenticated|trusted=yes' /etc/apt/apt.conf /etc/apt/apt.conf.d 2>/dev/null)"
    if [ -n "$conf" ]; then
        cp_warn "apt.conf proxy / insecure-repository settings:"; echo "$conf" | sed 's/^/        /'
        cp_todo "Review apt.conf proxy/insecure-repository lines: $(echo "$conf" | cut -d: -f1,2 | tr '\n' ' ')"
    fi
    cp_info "apt-get update (log: $CP_STATE_DIR/apt-update.log)"
    if DEBIAN_FRONTEND=noninteractive cp_apt update >"$CP_STATE_DIR/apt-update.log" 2>&1; then cp_ok "apt-get update OK ($(since $t0))"
    else cp_warn "apt-get update reported errors:"; grep -E '^(E|W):' "$CP_STATE_DIR/apt-update.log" | tail -5 | sed 's/^/        /'; fi
}
debian_sources

cp_hdr "Packages + automatic updates"
NEED=()
for p in unattended-upgrades libpam-pwquality auditd; do cp_pkg_installed "$p" || NEED+=("$p"); done
[ "$FW_DEFERRED" = 1 ] && NEED+=(ufw)
APT_LOG="$CP_STATE_DIR/apt-systemconfig.log"; mkdir -p "$CP_STATE_DIR"
if [ ${#NEED[@]} -gt 0 ] && cp_ask "Install ${NEED[*]} (needed for automatic updates, the password rules, auditd)?" y; then
    t0=$SECONDS
    cp_info "apt-get install ${NEED[*]} - waits for any background apt job (log: $APT_LOG)"
    if ! DEBIAN_FRONTEND=noninteractive cp_apt install -y "${NEED[@]}" >"$APT_LOG" 2>&1; then
        for p in "${NEED[@]}"; do DEBIAN_FRONTEND=noninteractive cp_apt install -y "$p" >>"$APT_LOG" 2>&1 || cp_err "could not install $p (see $APT_LOG)"; done
    fi
    cp_ok "apt done ($(since $t0)): $(for p in "${NEED[@]}"; do cp_pkg_installed "$p" && printf '%s ' "$p"; done)installed"
fi
[ "$FW_DEFERRED" = 1 ] && { command -v ufw >/dev/null 2>&1 && firewall || cp_todo "ufw could not be installed - set up the firewall by hand"; }

# unattended-upgrades: same answer as "dpkg-reconfigure unattended-upgrades -> Yes", without the dialog
if cp_pkg_installed unattended-upgrades; then
    echo "unattended-upgrades unattended-upgrades/enable_auto_updates boolean true" | debconf-set-selections 2>/dev/null
    DEBIAN_FRONTEND=noninteractive dpkg-reconfigure -f noninteractive unattended-upgrades >/dev/null 2>&1
fi
bk /etc/apt/apt.conf.d/20auto-upgrades /etc/apt/apt.conf.d/50auto-upgrades
cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
cat >/etc/apt/apt.conf.d/50auto-upgrades <<'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id} stable";
    "${distro_id} ${distro_codename}-security";
    "${distro_id} ${distro_codename}-updates";
};
EOF
# Ubuntu's 10periodic (update-notifier) sets the same keys: a "0" there must not be what a checker reads
if [ -f /etc/apt/apt.conf.d/10periodic ]; then
    bk /etc/apt/apt.conf.d/10periodic
    sed -i -E 's/^([[:space:]]*APT::Periodic::(Update-Package-Lists|Download-Upgradeable-Packages|Unattended-Upgrade))[[:space:]]+"[0-9]+";/\1 "1";/' /etc/apt/apt.conf.d/10periodic
fi
cp_ok "Automatic updates: daily package list update + unattended-upgrade (20auto-upgrades)"

# Linux Mint: Update Manager > Preferences > Automation is what Mint images score
# (1984: PathExists /var/lib/linuxmint/mintupdate-automatic-upgrades-enabled). Same as the GUI toggles.
if command -v mintupdate-automation >/dev/null 2>&1; then
    if cp_ask "Linux Mint: turn on Update Manager automatic updates + automatic removal of old kernels (same as the GUI Automation tab)?" y; then
        mintupdate-automation upgrade enable >/dev/null 2>&1
        mintupdate-automation autoremove enable >/dev/null 2>&1
        [ -e /var/lib/linuxmint/mintupdate-automatic-upgrades-enabled ] && cp_ok "Mint automatic updates enabled" \
            || cp_todo "Mint automation did not enable - Update Manager > Edit > Preferences > Automation"
    fi
    if command -v gsettings >/dev/null 2>&1 && [ -n "${SUDO_USER:-}" ]; then
        sudo -u "$SUDO_USER" dbus-launch gsettings set com.linuxmint.updates refresh-schedule-enabled true >/dev/null 2>&1 \
            && cp_ok "Update Manager: refresh the list of updates automatically (for $SUDO_USER)"
    fi
fi

# SYS3 password quality. pwquality was installed FIRST (above): its postinst runs pam-auth-update,
# which writes a fresh pam_pwquality line (only "retry=3") - arguments added before the install never
# reached that line (Mint has no pwquality by default).
# Checklist step "add minlen=12 remember=5 to pam_unix" automated, plus the pam_pwquality arguments
# that a 1984-style check looks for on the common-password line itself. minlen 12 (was 10) merged from
# Max's Mac copy 2026-11-10; existing minlen values are replaced, not left behind.
CPW=/etc/pam.d/common-password
if [ -f "$CPW" ]; then
    bk "$CPW"
    grep -qE '^[[:space:]]*password.*pam_unix\.so.*remember=' "$CPW" \
        && sed -i -E '/^[[:space:]]*password.*pam_unix\.so/ s/remember=[0-9]+/remember=5/' "$CPW" \
        || sed -i -E '/^[[:space:]]*password.*pam_unix\.so/ s/$/ remember=5/' "$CPW"
    grep -qE '^[[:space:]]*password.*pam_unix\.so.*minlen=' "$CPW" \
        && sed -i -E '/^[[:space:]]*password.*pam_unix\.so/ s/minlen=[0-9]+/minlen=12/' "$CPW" \
        || sed -i -E '/^[[:space:]]*password.*pam_unix\.so/ s/$/ minlen=12/' "$CPW"
    sed -i -E '/^[[:space:]]*password.*pam_pwquality\.so/ s/minlen=[0-9]+/minlen=12/' "$CPW"
    # retry=3 normally comes from the libpam-pwquality install (pam-auth-update); make sure it is there either way
    grep -qE '^[[:space:]]*password.*pam_pwquality\.so.*retry=' "$CPW" \
        && sed -i -E '/^[[:space:]]*password.*pam_pwquality\.so/ s/retry=[0-9]+/retry=3/' "$CPW" \
        || sed -i -E '/^[[:space:]]*password.*pam_pwquality\.so/ s/$/ retry=3/' "$CPW"
    for a in "dictcheck=1" "usercheck=1" "minlen=12" "ucredit=-1" "lcredit=-1" "dcredit=-1" "ocredit=-1"; do
        k="${a%%=*}"
        grep -qE "^[[:space:]]*password.*pam_pwquality\.so.*[[:space:]]${k}=" "$CPW" || sed -i -E "/^[[:space:]]*password.*pam_pwquality\.so/ s/\$/ ${a}/" "$CPW"
    done
    cp_ok "common-password: pam_unix remember=5 minlen=12; pam_pwquality retry=3 minlen=12 dictcheck/usercheck/credits"
    grep -qE '^[[:space:]]*password.*pam_pwquality\.so' "$CPW" || cp_todo "common-password has no pam_pwquality line (libpam-pwquality not installed?)"
    grep -qE '^[[:space:]]*password.*pam_unix\.so.*remember=5' "$CPW" || cp_todo "common-password: no pam_unix password line took remember=5 minlen=12 - add them by hand"
fi
if [ -f /etc/security/pwquality.conf ] || cp_pkg_installed libpam-pwquality; then
    bk /etc/security/pwquality.conf
    for kv in "minlen=12" "ucredit=-1" "lcredit=-1" "dcredit=-1" "ocredit=-1" "dictcheck=1" "usercheck=1"; do
        cp_set /etc/security/pwquality.conf "${kv%%=*}" "${kv#*=}" eqs
    done
    cp_ok "pwquality.conf: minlen 12, 1 upper/lower/digit/other, dictcheck, usercheck"
fi

# SYS7 services that must be running
[ -f /etc/audit/auditd.conf ] && { bk /etc/audit/auditd.conf; cp_set /etc/audit/auditd.conf local_events yes eqs; }
for s in apparmor auditd ufw unattended-upgrades; do
    systemctl enable --now "$s" >/dev/null 2>&1 && cp_ok "$s enabled and running" || cp_warn "could not enable $s"
done

echo
cp_ok "System hardening complete in $(since $T_START). Backups: $CP_BACKUP_ROOT/$CP_TS/"
