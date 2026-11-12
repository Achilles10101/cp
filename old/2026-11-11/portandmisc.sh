#!/bin/bash
# portandmisc.sh - who is listening on this machine, and should they be? Optional lynis / nmap.
#
# Fast mode (2026-11): no menu. Enter runs the useful fast check:
#   * every listening socket with its process, executable, package and systemd unit, classified as
#       critical  - belongs to a README critical service (readme.conf SERVICES)       -> kept
#       system    - stock desktop/system daemon (resolved, cups, avahi, dhcp, ...)    -> kept
#       service   - packaged service the README does not list                         -> offer stop+disable
#       backdoor  - interpreter/netcat/unowned program, or a unit no package installed -> offer stop+disable
#       unknown   - anything else (e.g. a custom app the README may need)              -> TODO, default keep
#   * stopped units are disabled (package units also masked); units no package installed and processes
#     without their own unit (cron, rc.local ...) become TODO items (find and delete what starts them).
#   * then one optional question: lynis in the background (log file) and/or an nmap localhost scan.
#     nmap is a scored hacking tool: it is purged right after the scan and never left installed.
#
# Usage: sudo bash portandmisc.sh            fast port check + optional lynis/nmap
#        sudo bash portandmisc.sh --scan     report only (changes nothing)
#        sudo bash portandmisc.sh --lynis    only start lynis in the background
#        sudo bash portandmisc.sh --nmap     only the nmap localhost scan (nmap purged afterwards)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/cp-common.sh" \
    || { echo "cp-common.sh not found - keep the competition folder intact"; exit 1; }

cp_require_root
MODE="${1:-}"
SCAN_ONLY=0
[ "$MODE" = "--scan" ] && SCAN_ONLY=1
[ -t 0 ] || SCAN_ONLY=1
[ "$SCAN_ONLY" = 1 ] || [ -n "$MODE" ] || cp_screenshot_prompt

T_START=$SECONDS
since() { echo "$(( SECONDS - $1 ))s"; }
mkdir -p "$CP_STATE_DIR" 2>/dev/null
README_KNOWN=0; cp_cfg_has SERVICES && README_KNOWN=1
# CyberPatriot scoring client - NEVER scanned, listed, quarantined, killed or disabled by these scripts:
# CCS images keep it in /opt/CyberPatriot (README.desktop, ScoringReport.html, gain.wav, alarm.wav, Icon.png,
# the CCSClient service), aeacus practice images in /opt/aeacus (phocus). Matched case-insensitively.
SCORING_RE='^/opt/(cyberpatriot|aeacus)(/|$)|(^|/)(ccs|css)client|(^|/)phocus|aeacus'
is_scoring() { local x; for x in "$@"; do [[ "${x,,}" =~ $SCORING_RE ]] && return 0; done; return 1; }

# ask3 "Question" DEFAULT -> echoes y, n or e (default on no terminal)
ask3() {
    local q="$1" def="$2" hint ans
    if [ "$def" = "y" ]; then hint="[Y/n/e]"; else hint="[y/N/e]"; fi
    [ -t 0 ] || { echo "$def"; return; }
    while true; do
        read -r -p "  ? $q $hint: " ans
        ans="${ans:-$def}"
        case "$ans" in [Yy]*) echo y; return ;; [Nn]*) echo n; return ;; [Ee]*) echo e; return ;; esac
    done
}

# ------------------------------------------------------------------ nmap --
NMAP_PKGS="nmap nmap-common zenmap ndiff"
nmap_purge() {   # nmap is prohibited software on CP images: purge it and prove it with dpkg-query
    local p left=""
    # shellcheck disable=SC2086
    DEBIAN_FRONTEND=noninteractive cp_apt purge -y $NMAP_PKGS >/dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive cp_apt autoremove --purge -y >/dev/null 2>&1
    for p in $NMAP_PKGS; do cp_pkg_installed "$p" && left+="$p "; done
    if [ -n "$left" ]; then cp_err "still installed: $left"; cp_todo "Purge $left(scored hacking tool): sudo apt-get purge $left"
    else cp_ok "nmap purged (dpkg-query: not installed)"; fi
}
nmap_scan() {
    cp_hdr "nmap localhost scan"
    local t0=$SECONDS installed_here=0
    if ! command -v nmap >/dev/null 2>&1; then
        cp_info "Installing nmap for the scan - it is purged again right after (scored hacking tool)"
        trap 'echo; nmap_purge; exit 130' INT TERM
        if ! DEBIAN_FRONTEND=noninteractive cp_apt install -y nmap >"$CP_STATE_DIR/apt-nmap.log" 2>&1; then
            cp_err "nmap install failed (see $CP_STATE_DIR/apt-nmap.log)"; nmap_purge; trap - INT TERM; return
        fi
        installed_here=1
    fi
    nmap -sS -sV -T4 -p- --open 127.0.0.1 2>&1 | grep -vE '^(Starting|Nmap done|Service detection performed|Host is up)' | sed '/^$/d'
    cp_info "nmap took $(since $t0)"
    [ "$installed_here" = 1 ] && { nmap_purge; trap - INT TERM; }
}

# ----------------------------------------------------------------- lynis --
lynis_bg() {
    cp_hdr "lynis (background)"
    local log="$CP_STATE_DIR/lynis.log" t0=$SECONDS
    if ! command -v lynis >/dev/null 2>&1; then
        cp_info "Installing lynis (log: $CP_STATE_DIR/apt-lynis.log)"
        DEBIAN_FRONTEND=noninteractive cp_apt install -y lynis >"$CP_STATE_DIR/apt-lynis.log" 2>&1 \
            || { cp_err "lynis install failed (see $CP_STATE_DIR/apt-lynis.log)"; return; }
        cp_info "installed in $(since $t0)"
    fi
    setsid nohup lynis audit system --quick --no-colors > "$log" 2>&1 < /dev/null &
    cp_ok "lynis is running in the background (pid $!) - takes a few minutes; output: $log"
    cp_todo "When lynis is done: grep -E '^(warning|suggestion)' /var/log/lynis-report.dat (and purge lynis if the README is strict about extra software)"
}

case "$MODE" in
    --lynis) lynis_bg; exit 0 ;;
    --nmap)  nmap_scan; exit 0 ;;
esac

# ============================================================ listening sockets ==
cp_hdr "Listening ports (process, package, unit)"
command -v ss >/dev/null 2>&1 || { cp_err "'ss' not found (package iproute2)"; exit 1; }

# package names of the README critical services (regex per services/*.sh name)
crit_pkg_re() {
    local re="" s
    for s in $(cp_cfg_get SERVICES); do
        case "$s" in
            ssh)        re+="|openssh-server" ;;
            apache2)    re+="|apache2|apache2-bin" ;;
            nginx)      re+="|nginx|nginx-core|nginx-full|nginx-light|nginx-extras" ;;
            vsftpd)     re+="|vsftpd" ;;
            samba)      re+="|samba|winbind" ;;
            bind9)      re+="|bind9" ;;
            mail)       re+="|postfix|dovecot-core|exim4-daemon-.*|sendmail-bin" ;;
            mysql)      re+="|mysql-server-core-.*|mysql-server|mariadb-server-core.*|mariadb-server" ;;
            postgresql) re+="|postgresql-[0-9]+" ;;
            squid)      re+="|squid|squid-openssl" ;;
            openvpn)    re+="|openvpn" ;;
            php)        re+="|php[0-9.]+-fpm" ;;
            wordpress)  re+="|apache2|apache2-bin|nginx-core|mysql-server-core-.*|mariadb-server-core.*|php[0-9.]+-fpm" ;;
        esac
    done
    [ -n "$re" ] && echo "^(${re#|})$" || echo '^$'
}
CRIT_RE="$(crit_pkg_re)"
# stock desktop/system daemons (CUPS/avahi are disabled by fileandpackage.sh [3], not here)
SYSTEM_RE='^(systemd|systemd-resolved|systemd-timesyncd|cups-daemon|cups-browsed|cups|avahi-daemon|network-manager|isc-dhcp-client|dhcpcd-base|dhcpcd5|chrony|ntp|ntpsec|openntpd|dnsmasq-base)$'
INTERP_RE='^(python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|php[0-9.]*|bash|sh|dash|zsh|ksh|busybox|nc|nc\.traditional|nc\.openbsd|netcat|ncat|socat|lua[0-9.]*|tclsh[0-9.]*|awk|gawk|mawk|telnet)$'

# one line per (proto, port, pid): proto addr:port pid name
ss -Htulpn 2>/dev/null | awk '{
    proto = $1; local = $5; proc = $0
    pid = ""; name = ""
    if (match(proc, /pid=[0-9]+/)) pid = substr(proc, RSTART + 4, RLENGTH - 4)
    if (match(proc, /\(\("[^"]*"/)) name = substr(proc, RSTART + 3, RLENGTH - 4)
    n = split(local, a, ":"); port = a[n]
    addr = substr(local, 1, length(local) - length(port) - 1)
    key = proto "/" port "/" pid
    if (!(key in seen)) { seen[key] = 1; print proto "\t" addr "\t" port "\t" pid "\t" name }
}' | sort -t$'\t' -k3,3n -k1,1 > "$CP_STATE_DIR/listeners.tsv"

# executables -> package, in ONE dpkg-query call (usr-merge: try /bin and /usr/bin spellings)
declare -A EXE_PKG=()
mapfile -t PIDS < <(cut -f4 "$CP_STATE_DIR/listeners.tsv" | grep -E '^[0-9]+$' | sort -u)
EXES=()
for pid in "${PIDS[@]}"; do
    e="$(readlink -f "/proc/$pid/exe" 2>/dev/null)"; [ -n "$e" ] || continue
    EXES+=("$e"); case "$e" in /usr/*) EXES+=("${e#/usr}") ;; esac
done
if [ ${#EXES[@]} -gt 0 ]; then
    while IFS= read -r l; do
        pk="${l%%: *}"; f="${l#*: }"; pk="${pk%%:*}"; pk="${pk%%,*}"
        EXE_PKG["$f"]="$pk"; EXE_PKG["/usr$f"]="${EXE_PKG["/usr$f"]:-$pk}"
    done < <(dpkg-query -S "${EXES[@]}" 2>/dev/null | grep -v '^diversion')
fi

pid_unit() {   # systemd unit of a pid from its cgroup (service/socket/scope), "" if none
    sed -n 's#^[0-9]*:[^:]*:.*/\([^/]*\.\(service\|socket\|scope\)\)$#\1#p' "/proc/$1/cgroup" 2>/dev/null | tail -1
}

KEEP_N=0; BD=(); SVC=(); UNK=(); ACTED=(); declare -A DONE_UNIT=()
printf "  %-5s %-22s %-28s %-22s %s\n" PROTO ADDRESS:PORT "PROCESS (PID)" PACKAGE "UNIT  -> verdict"
while IFS=$'\t' read -r proto addr port pid name; do
    exe=""; cmd=""; pkg=""; unit=""; frag=""; ufile_owned=1
    if [ -n "$pid" ] && [ -d "/proc/$pid" ]; then
        exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null)"
        cmd="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | cut -c1-90)"
        pkg="${EXE_PKG["$exe"]:-}"
        unit="$(pid_unit "$pid")"
    fi
    case "$unit" in *.service|*.socket)
        frag="$(systemctl show -p FragmentPath --value "$unit" 2>/dev/null)"
        [ -n "$frag" ] && ! cp_owned "$frag" && ufile_owned=0 ;;
    esac
    bn="$(basename "${exe:-$name}")"
    # does the process have its OWN unit? (not cron, a login session, the user manager, the display
    # manager - a shell started from those lives in their cgroup but is not that service)
    own_unit=1
    case "$unit" in
        ""|cron.service|anacron.service|atd.service|user@*.service|rc-local.service|lightdm.service|display-manager.service|*.scope) own_unit=0 ;;
        ssh.service|sshd.service) [ "$bn" = sshd ] || own_unit=0 ;;
    esac
    verdict="unknown"
    if is_scoring "$exe" "$frag" "$unit" "$name" "${cmd%% *}" "$(echo "$cmd" | awk '{print $2}')"; then verdict="scoring"   # never touched
    elif [ -n "$pkg" ] && [ "$ufile_owned" = 1 ] && [ "$own_unit" = 1 ] && [[ "$pkg" =~ $CRIT_RE ]]; then verdict="critical"
    elif [ -n "$pkg" ] && [ "$ufile_owned" = 1 ] && [[ "$pkg" =~ $SYSTEM_RE ]]; then verdict="system"
    elif [ "$ufile_owned" = 0 ]; then verdict="backdoor"                                  # unit file no package installed
    elif [ -n "$exe" ] && [ -z "$pkg" ]; then verdict="backdoor"                           # program no package installed
    elif [[ "$exe" =~ ^/(tmp|var/tmp|dev/shm|home|root)/ ]]; then verdict="backdoor"
    elif [[ "$bn" =~ $INTERP_RE ]] && [ "$own_unit" = 0 ]; then verdict="backdoor"         # python/nc/socat/bash from cron, a session ...
    elif [ -n "$pkg" ] && [ "$own_unit" = 1 ]; then verdict="service"                       # packaged service, not critical
    fi
    printf "  %-5s %-22s %-28s %-22s %s\n" "$proto" "$addr:$port" "${name:-?} (${pid:-?})" "${pkg:-(no package)}" "${unit:--}  -> $verdict"
    [ "$verdict" = backdoor ] || [ "$verdict" = unknown ] && [ -n "$cmd" ] && echo "          cmd: $cmd${frag:+   unit file: $frag$([ "$ufile_owned" = 0 ] && echo ' (no package)')}"
    item="$proto/$port|$pid|$unit|$own_unit|$ufile_owned|$frag|$cmd"
    case "$verdict" in
        critical|system|scoring) KEEP_N=$((KEEP_N + 1)) ;;
        backdoor) BD+=("$item") ;;
        service)  SVC+=("$item") ;;
        unknown)  UNK+=("$item") ;;
    esac
done < "$CP_STATE_DIR/listeners.tsv"
[ -s "$CP_STATE_DIR/listeners.tsv" ] || cp_ok "Nothing is listening"
[ "$README_KNOWN" = 1 ] || cp_warn "README critical services unknown (run readme.sh) - nothing is treated as critical"

# stop_item "proto/port|pid|unit|own_unit|ufile_owned|frag|cmd"
stop_item() {
    local proto_port pid unit own ufo frag cmd trig
    IFS='|' read -r proto_port pid unit own ufo frag cmd <<< "$1"
    is_scoring "$unit" "$frag" "$cmd" && { cp_warn "$proto_port belongs to the scoring engine - not touched"; return; }
    ACTED+=("$proto_port")
    if [ "$own" = 1 ] && [ -n "$unit" ]; then
        [ -n "${DONE_UNIT[$unit]:-}" ] && return; DONE_UNIT[$unit]=1
        # socket-activated services: the .socket would start them again
        trig="$(systemctl show -p TriggeredBy --value "$unit" 2>/dev/null)"
        # shellcheck disable=SC2086
        systemctl disable --now "$unit" $trig >/dev/null 2>&1
        if [ "$ufo" = 1 ]; then
            # shellcheck disable=SC2086
            systemctl mask "$unit" $trig >/dev/null 2>&1 && cp_ok "$unit stopped, disabled and masked ($proto_port)"
        else
            cp_ok "$unit stopped and disabled ($proto_port)"
            cp_todo "Delete unit file $frag (no package installed it; runs: $cmd) and what it starts, then: systemctl daemon-reload"
        fi
    elif [ -n "$pid" ]; then
        kill "$pid" 2>/dev/null; sleep 1; kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null
        cp_ok "killed pid $pid ($proto_port: $cmd)"
        cp_todo "Find what started '$cmd' ($proto_port, was in ${unit:-no unit}) - cron job, rc.local, user crontab, profile? - and remove it"
    fi
}
act_on() {   # act_on DEFAULT QUESTION ITEMS...
    local def="$1" q="$2" x; shift 2
    case "$(ask3 "$q" "$def")" in
        y) for x in "$@"; do stop_item "$x"; done ;;
        e) for x in "$@"; do
               if cp_ask "Stop ${x%%|*} ($(unit_of "$x"): $(echo "$x" | cut -d'|' -f7 | cut -c1-50))?" "$def"; then stop_item "$x"
               else cp_todo "Listener ${x%%|*} kept: $(echo "$x" | cut -d'|' -f7) - stop it unless the README needs it"; fi
           done ;;
        *) for x in "$@"; do cp_todo "Listener ${x%%|*} kept: $(echo "$x" | cut -d'|' -f7) - stop it unless the README needs it"; done ;;
    esac
}
unit_of() { local u; u="$(echo "$1" | cut -d'|' -f3)"; echo "${u:-no unit}"; }
short() { local x; for x in "$@"; do printf '%s ' "${x%%|*}($(unit_of "$x"))"; done; }

echo
cp_info "$KEEP_N listener(s) are critical services, stock system daemons or the scoring engine"
if [ "$SCAN_ONLY" = 1 ]; then
    for x in "${BD[@]}" "${SVC[@]}" "${UNK[@]}"; do cp_todo "Listener ${x%%|*} ($(unit_of "$x")): $(echo "$x" | cut -d'|' -f7) - stop it unless the README needs it"; done
else
    [ ${#BD[@]} -gt 0 ] && act_on y "Stop + disable these backdoor-looking listeners: $(short "${BD[@]}")?" "${BD[@]}"
    # SSH is never stopped by default (a wrong/empty SERVICES answer must not cut it off with one Enter)
    SSHX=(); OTH=()
    for x in "${SVC[@]}"; do case "$(unit_of "$x")" in ssh.service|sshd.service|ssh.socket) SSHX+=("$x") ;; *) OTH+=("$x") ;; esac; done
    if [ ${#OTH[@]} -gt 0 ]; then
        def=n; [ "$README_KNOWN" = 1 ] && def=y
        act_on "$def" "Stop + disable these services the README does not list: $(short "${OTH[@]}")?" "${OTH[@]}"
    fi
    [ ${#SSHX[@]} -gt 0 ] && act_on n "Stop + disable the SSH server (the README facts do not list ssh as critical - check!): $(short "${SSHX[@]}")?" "${SSHX[@]}"
    [ ${#UNK[@]} -gt 0 ] && act_on n "Stop these unknown listeners (could be a custom app the README needs): $(short "${UNK[@]}")?" "${UNK[@]}"
    if [ ${#ACTED[@]} -gt 0 ]; then
        sleep 1
        STILL="$(ss -Htulpn 2>/dev/null | awk '{n = split($5, a, ":"); print $1 "/" a[n]}' | sort -u)"
        for x in $(printf '%s\n' "${ACTED[@]}" | sort -u); do
            if grep -qxF "$x" <<< "$STILL"; then cp_err "$x is still listening"; cp_todo "$x still listening after stop - check: ss -tulpn | grep ':${x#*/} '"
            else cp_ok "$x closed"; fi
        done
    fi
fi

# ============================================================ optional + nmap guard ==
if [ "$SCAN_ONLY" = 0 ]; then
    opt="$(cp_read "Optional: l = lynis in the background, n = nmap localhost scan (purged after), ln = both, Enter = skip" "")"
    [[ "$opt" == *l* ]] && lynis_bg
    [[ "$opt" == *n* ]] && nmap_scan
fi
# nmap must never stay installed (scored hacking tool) - whoever installed it
if cp_pkg_installed nmap || cp_pkg_installed nmap-common || cp_pkg_installed zenmap; then
    cp_warn "nmap is installed (scored hacking tool)"
    if [ "$SCAN_ONLY" = 0 ] && cp_auto "Purge nmap now?" y; then nmap_purge; else cp_todo "Purge nmap (scored hacking tool): sudo apt-get purge nmap nmap-common"; fi
fi
echo
cp_ok "portandmisc done in $(since $T_START). Listener table: $CP_STATE_DIR/listeners.tsv"
