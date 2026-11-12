#!/bin/bash
# fileandpackage.sh - unauthorized packages and services, network shares, unauthorized files,
# SUID/SGID/sticky bits.
#
# Package handling (rewritten 2026-10-20 after a test run on a live image):
#   * dpkg is the source of truth. Detection reads dpkg-query and matches WHOLE PACKAGE NAMES.
#     (The old `dpkg -l | grep -w "^ii.*nc"` matched any word in any line, including other
#     packages' names and descriptions.)
#   * Every entry is a FAMILY. `apt remove wireshark` only removes the package literally called
#     wireshark; wireshark-qt, wireshark-common, tshark, libwireshark15 ... stay.
#   * Before anything is removed you see everything apt would take with them (preview).
#   * Removal = apt-get purge, then every package is re-checked with dpkg-query, then
#     autoremove, then leftover configs (dpkg state "rc") are purged, then the scan runs again.
#
# Round 5 (2026-11-11, Max's redesign): the script asks what it needs, nothing is read from other scripts.
#   * Hacking tools, remote access, P2P and games: ONE "remove" list, default yes (e = per family/package).
#   * SERVICE families (apache2, vsftpd, samba, mail ...): one list, default NO (keep), each with a hint line
#     (installed / running / listening on :port) - remove what the README does not need. OpenSSH: own [y/N].
#   * Desktop defaults (CUPS, avahi) and review items: a list, default no.
#   * The purge asks (default yes) after the preview; it defaults to NO when the preview takes a desktop,
#     metapackage or a service package you did not select.
#   * Services ([3]): stop + disable lists, default no, with state and ports as hints. SSH: own [y/N].
#   * Files ([5]): media in user folders (and unowned media hidden in system folders) -> /root/cp-quarantine
#     in one go (restorable); password-looking files -> TODO. [5b] pyrdp outside apt.
#   * [5], [5b] and [6] share ONE filesystem pass; SUID/SGID shows only unexpected files.
#
# Usage: sudo bash fileandpackage.sh          interactive
#        sudo bash fileandpackage.sh --scan   report only, removes nothing (also used with no TTY)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/cp-common.sh" \
    || { echo "cp-common.sh not found - keep the competition folder intact"; exit 1; }

cp_require_root

SCAN_ONLY=0
[ "${1:-}" = "--scan" ] && SCAN_ONLY=1
[ -t 0 ] || SCAN_ONLY=1
[ "$SCAN_ONLY" = 1 ] || cp_screenshot_prompt

echo "File, Package, and SUID/GUID Scanner"
T_START=$SECONDS
since() { echo "$(( SECONDS - $1 ))s"; }

# Call the real binaries by full path: a planted /usr/local/bin/apt-get (or dpkg-query) comes
# before /usr/bin in sudo's secure_path. Section [0] reports such shadow copies.
# (cp_apt is /usr/bin/apt-get with the dpkg-lock wait and a wait for any running "apt-get update".)
DPKGQ=/usr/bin/dpkg-query
DPKG=/usr/bin/dpkg
APTMARK=/usr/bin/apt-mark
APTCACHE=/usr/bin/apt-cache
export DEBIAN_FRONTEND=noninteractive
NATIVE_ARCH="$($DPKG --print-architecture 2>/dev/null)"
TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"; cp_todo_recap' EXIT
QUAR=/root/cp-quarantine
mkdir -p "$CP_STATE_DIR" 2>/dev/null
# CyberPatriot scoring client - NEVER scanned, listed, quarantined, killed or disabled by these scripts:
# CCS images keep it in /opt/CyberPatriot (README.desktop, ScoringReport.html, gain.wav, alarm.wav, Icon.png,
# the CCSClient service), aeacus practice images in /opt/aeacus (phocus). Matched case-insensitively.
SCORING_RE='^/opt/(cyberpatriot|aeacus)(/|$)|(^|/)(ccs|css)client|(^|/)phocus|aeacus'
is_scoring() { local x; for x in "$@"; do [[ "${x,,}" =~ $SCORING_RE ]] && return 0; done; return 1; }
for d in /opt/*; do [ -e "$d" ] && is_scoring "$d" && cp_info "Scoring engine: $d - never touched (excluded from every scan)"; done

# ------------------------------------------------------------------ catalog --
# CATEGORY ; DEFAULT ; LABEL ; REGEX (ERE, matched against the WHOLE package name, no :arch) ; NOTE ; UNITS
#   DEFAULT y = suggested removal. n = check the README first.   REGEX "SECTION:<s>" matches by dpkg section.
#   UNITS = systemd units of the family, only for the hint line (running? listening on which port?).
#   SERVICE families are README decisions: listed with hints, default keep. SSHD (OpenSSH) gets its own [y/N].
#   Deliberately NOT listed: samba-libs, libsmbclient, smbclient, samba-common(-bin) (smbclient and the
#   Linux Mint metapackages depend on them - autoremove takes them once the samba server is gone), mysql-common, bind9-dnsutils/
#   bind9-host/bind9-libs (dig), dnsmasq-base - client libraries the desktop itself uses
#   (file manager, NetworkManager). The removal preview shows anything else apt would pull out.
CATALOG='
TOOL;y;john;john|john-data|johnny;;
TOOL;y;hydra;hydra|hydra-gtk;;
TOOL;y;nmap;nmap|nmap-common|zenmap|ndiff;;
TOOL;y;wireshark;wireshark|wireshark-.*|tshark|termshark|libwireshark.*|libwiretap.*|libwsutil.*;;
TOOL;y;netcat;netcat|netcat-traditional|netcat-openbsd|ncat|cryptcat|pwncat|socat;netcat-openbsd ships with Ubuntu (removing it is fine;
TOOL;y;password crackers;ophcrack|ophcrack-cli|truecrack|hashcat|hashcat-data|fcrackzip|pdfcrack|rarcrack|sucrack|crack|crack-common|crack-md5|medusa|ncrack|patator|crunch|cewl|samdump2|bkhive|chntpw|hashid|rainbowcrack;;
TOOL;y;wireless attack;aircrack-ng|kismet|kismet-.*|reaver|pixiewps|wifite|mdk3|mdk4|cowpatty|pyrit|bully|fern-wifi-cracker|airgraph-ng;;
TOOL;y;scanners/exploit;nikto|sqlmap|wpscan|dirb|dirbuster|gobuster|ffuf|wfuzz|skipfish|whatweb|wapiti|zaproxy|metasploit-framework|exploitdb|armitage|beef-xss|burpsuite|openvas.*|gvm|masscan|zmap|netdiscover|arp-scan|nbtscan|unicornscan|hping3|xprobe|xprobe2|p0f|amap|dnsenum|dnsrecon|fierce|enum4linux|smbmap|onesixtyone|nuclei|maltego|recon-ng|theharvester;;
TOOL;y;sniff/MITM/backdoor;ettercap-common|ettercap-graphical|ettercap-text-only|dsniff|bettercap|yersinia|responder|mitmproxy|sslstrip|driftnet|macchanger|thc-ipv6|doona|pyrdp|pyrdp-mitm|python3-pyrdp|weevely|backdoor-factory|veil|shellter|nishang|powersploit|mimikatz|tor|torbrowser-launcher|proxychains|proxychains4;;
REMOTE;y;VNC/RDP servers;tightvncserver|x11vnc|vnc4server|tigervnc-standalone-server|tigervnc-scraping-server|tigervnc-xorg-extension|xrdp|xorgxrdp|teamviewer|anydesk;;
REMOTE;y;telnet/rsh/finger;telnet|telnetd|inetutils-telnet|inetutils-telnetd|telnet-ssl|telnetd-ssl|rsh-client|rsh-server|rsh-redone-client|rsh-redone-server|rlogin|rwho|rwhod|talk|talkd|inetutils-talk|inetutils-talkd|finger|fingerd|efingerd|cfingerd;telnet ships with some Ubuntu releases (the preview shows the metapackage it takes along);
REMOTE;y;inetd/tftp/NIS;xinetd|openbsd-inetd|inetutils-inetd|rinetd|tftpd|tftpd-hpa|atftpd|tftp|tftp-hpa|nis|ypserv;;
P2P;y;P2P/torrent;vuze|azureus|frostwire|deluge|deluge-.*|deluged|qbittorrent|qbittorrent-nox|transmission|transmission-.*|ktorrent|amule|amule-.*|rtorrent|tixati|bittorrent|bittornado|nicotine|limewire|gnutella|gtk-gnutella|freenet;transmission-gtk ships with Ubuntu desktop - remove unless the README needs it;
GAME;y;AisleRiot (prohibited);aisleriot|aisleriot-.*;;
GAME;y;minetest/luanti;minetest|minetest-.*|luanti|luanti-.*;;
GAME;n;other games (dpkg section "games");SECTION:games;Ubuntu ships a few (gnome-mines, gnome-sudoku, gnome-mahjongg;
SSHD;n;OpenSSH server;openssh-server|openssh-sftp-server;keep if the README needs SSH;ssh
SERVICE;n;samba (server);samba|samba-dsdb-modules|samba-vfs-modules|samba-ad-.*|samba-testsuite|python3-samba|winbind|libnss-winbind|libpam-winbind|ctdb;KEEP if the README lists Samba/file sharing as critical;smbd nmbd samba-ad-dc winbind
SERVICE;n;NFS/rpcbind;nfs-kernel-server|nfs-common|rpcbind;KEEP if the README lists NFS;nfs-server rpcbind
SERVICE;n;apache2;apache2|apache2-bin|apache2-data|apache2-utils|apache2-doc|libapache2-mod-.*;KEEP if the README lists a web server / website;apache2
SERVICE;n;nginx;nginx|nginx-common|nginx-core|nginx-full|nginx-light|nginx-extras|libnginx-mod-.*;KEEP if the README lists a web server / website;nginx
SERVICE;n;other web/app servers;lighttpd|tomcat[0-9]*|tomcat[0-9]*-.*|jetty[0-9]*|phpmyadmin|node-red|webmin;;lighttpd tomcat9 tomcat10
SERVICE;n;PHP;php|php[0-9.]+|php[0-9.]+-.*|php-.*;KEEP if the README lists PHP, WordPress or a PHP website;php*-fpm
SERVICE;n;MySQL/MariaDB;mysql-server|mysql-server-.*|mysql-client|mysql-client-.*|mariadb-server|mariadb-server-.*|mariadb-client|mariadb-client-.*|galera-.*;KEEP if the README lists MySQL/MariaDB or WordPress;mysql mariadb
SERVICE;n;PostgreSQL;postgresql|postgresql-[0-9]+|postgresql-client|postgresql-client-[0-9]+|postgresql-common|postgresql-client-common|postgresql-contrib|postgresql-contrib-.*;KEEP if the README lists PostgreSQL;postgresql
SERVICE;n;other databases/caches;redis-server|redis|memcached|mongodb|mongodb-.*|couchdb|elasticsearch|influxdb;;redis-server memcached mongod
SERVICE;n;FTP servers;vsftpd|pure-ftpd|pure-ftpd-.*|proftpd|proftpd-.*|wu-ftpd|ftpd|inetutils-ftpd|tnftpd;KEEP if the README lists FTP;vsftpd pure-ftpd proftpd
SERVICE;n;mail;postfix|postfix-.*|sendmail|sendmail-.*|exim4|exim4-.*|dovecot-.*|courier-.*|opensmtpd|citadel-server;KEEP if the README lists mail. exim4 is the Debian default MTA;postfix dovecot exim4 sendmail
SERVICE;n;DNS servers;bind9|bind9-doc|bind9utils|dnsmasq|unbound|pdns-server|pdns-backend-.*|nsd;KEEP if the README lists DNS;named bind9 dnsmasq unbound
SERVICE;n;SNMP;snmpd|snmp|snmptrapd;;snmpd
SERVICE;n;squid;squid|squid-common|squid3|squid-openssl|squidclient;KEEP if the README lists a proxy;squid
SERVICE;n;IRC servers;inspircd|ircd-hybrid|ircd-irc2|ircd-ircu|ngircd|unrealircd|charybdis|solanum;;inspircd ngircd
DESKTOP;n;CUPS printing;cups|cups-daemon|cups-browsed|cups-client|cups-bsd;desktop default - [3] disables the service instead (scored as "disabled or removed");cups cups-browsed
DESKTOP;n;avahi;avahi-daemon|avahi-utils|avahi-autoipd;desktop default - [3] disables the service instead;avahi-daemon
REVIEW;n;misc review;tcpdump|vino|ftp|tnftp|lftp|ncftp|filezilla;tcpdump/ftp ship with Ubuntu;
'

# ------------------------------------------------------------------ helpers --
# Snapshot of every package dpkg knows: STATUS<TAB>binary:Package<TAB>Package<TAB>Section
#   STATUS = db:Status-Abbrev, e.g. "ii " installed, "hi " installed+held, "rc " config only,
#   "iU"/"iF"/"iH" half-installed/broken. "Present" = 2nd char is not n (not-installed) or c (config).
snapshot() {
    $DPKGQ -W -f='${db:Status-Abbrev}\t${binary:Package}\t${Package}\t${Section}\n' 2>/dev/null > "$TMPD/inst"
}
base() { echo "${1%%:*}"; }

# pkg_state NAME -> "ii", "hi", "rc", "iU", ... or "" when dpkg has no record (fully gone)
pkg_state() {
    local s
    s="$($DPKGQ -W -f='${db:Status-Abbrev}' "$1" 2>/dev/null | head -c2)"
    [ "$s" = "un" ] && s=""
    echo "$s"
}

# family_members REGEX -> present packages (binary:Package names) of that family
family_members() {
    local re="$1"
    if [[ "$re" == SECTION:* ]]; then
        awk -F'\t' -v s="${re#SECTION:}" 'substr($1,2,1)!="n" && substr($1,2,1)!="c" && $4 ~ ("(^|/)" s "$") {print $2}' "$TMPD/inst"
    else
        awk -F'\t' -v re="^(${re})$" 'substr($1,2,1)!="n" && substr($1,2,1)!="c" && $3 ~ re {print $2}' "$TMPD/inst"
    fi
}

# scan_catalog -> fills FAM_* arrays with every family that has at least one present package.
# A package is only listed under the first family that matches it.
scan_catalog() {
    FAM_CAT=(); FAM_DEF=(); FAM_LABEL=(); FAM_PKGS=(); FAM_NOTE=(); FAM_UNITS=(); FAM_RE=()
    declare -gA SEEN=()
    local cat def label re note units p keep
    while IFS=';' read -r cat def label re note units; do
        [ -z "$cat" ] && continue
        keep=()
        while IFS= read -r p; do
            [ -z "$p" ] && continue
            [ -n "${SEEN[$p]:-}" ] && continue
            SEEN[$p]=1; keep+=("$p")
        done < <(family_members "$re")
        [ ${#keep[@]} -eq 0 ] && continue
        FAM_CAT+=("$cat"); FAM_DEF+=("$def"); FAM_LABEL+=("$label"); FAM_NOTE+=("$note")
        FAM_UNITS+=("$units"); FAM_RE+=("$re")
        FAM_PKGS+=("${keep[*]}")
    done <<< "$CATALOG"
}

# fam_class I -> remove | service | review | sshd
fam_class() {
    local i="$1"
    case "${FAM_CAT[$i]}" in
        TOOL|REMOTE|P2P) echo remove ;;
        GAME) [ "${FAM_DEF[$i]}" = y ] && echo remove || echo review ;;
        SERVICE) echo service ;;
        SSHD) echo sshd ;;
        *) echo review ;;
    esac
}

# ---- hints: is a unit running, and on which ports? (pid -> port map from ss, read once)
SS_PIDPORT="$(ss -Htulpn 2>/dev/null | awk '{n = split($5, a, ":"); port = a[n]; s = $0
    while (match(s, /pid=[0-9]+/)) { print substr(s, RSTART + 4, RLENGTH - 4), port; s = substr(s, RSTART + RLENGTH) } }' | sort -u)"
systemctl list-unit-files --no-legend --type=service,socket 2>/dev/null | awk '{print $1}' > "$TMPD/units"
unit_ports() {   # unit_ports UNIT -> ":22 :80" (ports of every process in the unit's cgroup)
    local cg pids
    cg="$(systemctl show -p ControlGroup --value "$1" 2>/dev/null)"; [ -n "$cg" ] || return 0
    pids="$(find "/sys/fs/cgroup$cg" -name cgroup.procs -exec cat {} + 2>/dev/null | sort -u)"
    [ -n "$pids" ] || return 0
    awk 'NR == FNR { p[$1] = 1; next } ($1 in p) { print ":" $2 }' <(echo "$pids") <(echo "$SS_PIDPORT") | sort -u -t: -k2n | tr '\n' ' ' | sed 's/ $//'
}
unit_state() {   # unit_state UNIT -> "running on :80" | "enabled (stopped)" | "stopped" | "" (no such unit)
    local u="$1" pt
    grep -qxF "$u.service" "$TMPD/units" || grep -qxF "$u.socket" "$TMPD/units" || return 0
    if systemctl is-active --quiet "$u" 2>/dev/null; then pt="$(unit_ports "$u")"; echo "running${pt:+ on $pt}"
    elif systemctl is-enabled --quiet "$u" 2>/dev/null; then echo "enabled (stopped)"
    else echo "stopped"; fi
}
fam_hint() {     # fam_hint I -> "apache2 running on :80; ..." (or "installed, no service")
    local i="$1" u m out="" st
    for u in ${FAM_UNITS[$i]}; do
        if [[ "$u" == *'*'* ]]; then
            for m in $(grep -E "^${u//\*/.*}\.service$" "$TMPD/units" | sed 's/\.service$//'); do st="$(unit_state "$m")"; [ -n "$st" ] && out+="$m $st; "; done
        else st="$(unit_state "$u")"; [ -n "$st" ] && out+="$u $st; "; fi
    done
    echo "${out:-installed, no service unit}" | sed 's/; $//'
}

print_held_flag() {  # prints " (HELD)" when dpkg/apt has the package on hold
    case "$(pkg_state "$1")" in h*) echo " (HELD)";; esac
}
fam_line() {  # fam_line I -> "[CAT] label: pkg pkg (HELD) ..."
    local i="$1" p out=""
    for p in ${FAM_PKGS[$i]}; do out+=" $p$(print_held_flag "$p")"; done
    printf "    [%-7s] %s:%s\n" "${FAM_CAT[$i]}" "${FAM_LABEL[$i]}" "$out"
}

# ask3 "Question" DEFAULT -> echoes y, n or e (default on no terminal)
ask3() {
    local q="$1" def="$2" hint ans
    if [ "$def" = "y" ]; then hint="[Y/n/e]"; else hint="[y/N/e]"; fi
    [ -t 0 ] || { echo "$def"; return; }
    while true; do
        read -r -p "  ? $q $hint: " ans
        ans="${ans:-$def}"
        case "$ans" in
            [Yy]*) echo y; return ;;
            [Nn]*) echo n; return ;;
            [Ee]*) echo e; return ;;
        esac
    done
}

declare -A TARGET_SET=()
TARGETS=()
add_target() {
    local p="$1"
    [ -n "${TARGET_SET[$(base "$p")]:-}" ] && return
    TARGET_SET[$(base "$p")]=1
    TARGETS+=("$p")
}
# select_family I DEFAULT -> y = whole family, e = each package
select_family() {
    local i="$1" def="$2" p
    case "$(ask3 "Remove ${FAM_LABEL[$i]} (${FAM_PKGS[$i]})?" "$def")" in
        y) for p in ${FAM_PKGS[$i]}; do add_target "$p"; done ;;
        e) for p in ${FAM_PKGS[$i]}; do cp_ask "Remove $p?" "$def" && add_target "$p"; done ;;
    esac
}
# select_batch DEFAULT QUESTION I... -> one question for a whole list; e = per family (then per package)
select_batch() {
    local def="$1" q="$2" i p; shift 2
    case "$(ask3 "$q" "$def")" in
        y) for i in "$@"; do for p in ${FAM_PKGS[$i]}; do add_target "$p"; done; done ;;
        e) for i in "$@"; do select_family "$i" "$def"; done ;;
    esac
}

# simulate ARGS... -> package names apt-get WOULD remove (no :native-arch suffix), one per line
simulate() {
    cp_apt -s "$@" 2>"$TMPD/simerr" | awk '/^(Purg|Remv) /{print $2}' | sed "s/:${NATIVE_ARCH}\$//" | sort -u
}

# Packages that must never go as a side effect: the desktop (Cinnamon/LightDM/NetworkManager, also
# GNOME/MATE/Xfce/KDE), core tools; service packages apt would take along unasked are checked by services_in.
# Desktop metapackages are listed too (M12): if the preview takes one, the purge is asked, never automatic.
META_RE='mint-meta-.*|ubuntu-desktop.*|ubuntu-standard|ubuntu-minimal|(k|x|l|ed)ubuntu-desktop.*|ubuntu-(mate|budgie|unity|gnome)-desktop.*|xubuntu-core|.*-desktop-environment(-.*)?|task-.*-desktop|task-desktop'
PROTECT_RE='cinnamon|cinnamon-core|cinnamon-session|cinnamon-common|muffin|nemo|lightdm|slick-greeter|lightdm-gtk-greeter|network-manager|network-manager-gnome|xserver-xorg|xserver-xorg-core|xorg|gdm3|gnome-shell|gnome-session|ubuntu-session|mate-session-manager|xfce4-session|xfwm4|plasma-desktop|sddm|sudo|systemd|systemd-sysv|dbus|apt|dpkg|login|passwd|policykit-1|polkitd'
crit_re() { echo "^($PROTECT_RE|$META_RE)$"; }
protected_in() {  # protected_in PKG... -> prints the protected ones
    local re p; re="$(crit_re)"
    for p in "$@"; do [[ "$(base "$p")" =~ $re ]] && echo "$(base "$p")"; done
}
# service packages (SERVICE/SSHD families) - protected when apt would take them along without being chosen
SERVICE_RE="^($(awk -F';' '($1 == "SERVICE" || $1 == "SSHD") && $4 !~ /^SECTION:/ {printf "%s%s", (n++ ? "|" : ""), $4}' <<< "$CATALOG"))$"
services_in() { local p; for p in "$@"; do [[ "$(base "$p")" =~ $SERVICE_RE ]] && echo "$(base "$p")"; done; }

# UFW rules of a service family that was just purged (M16): profile names and their ports. Port rules go only
# when nothing listens on that port any more. Deleted with xargs word splitting, never eval.
declare -A FW_OF=(
    ["OpenSSH server"]="OpenSSH 22/tcp"
    ["apache2"]="Apache|Apache Full|Apache Secure 80/tcp 443/tcp 80,443/tcp"
    ["nginx"]="Nginx HTTP|Nginx HTTPS|Nginx Full 80/tcp 443/tcp 80,443/tcp"
    ["FTP servers"]="vsftpd 21/tcp 20/tcp 20:21/tcp"
    ["samba (server)"]="Samba 137,138/udp 139,445/tcp 445/tcp 139/tcp"
    ["DNS servers"]="Bind9|DNS 53 53/tcp 53/udp"
    ["mail"]="Postfix|Postfix SMTPS|Postfix Submission|Dovecot IMAP|Dovecot POP3|Dovecot Secure IMAP|Dovecot Secure POP3 25/tcp 465/tcp 587/tcp 110/tcp 143/tcp 993/tcp 995/tcp"
    ["squid"]="Squid 3128/tcp"
    ["PostgreSQL"]="PostgreSQL 5432/tcp"
    ["MySQL/MariaDB"]="MySQL 3306/tcp"
)
fw_delete() {
    printf '%s\n' "$1" | xargs ufw delete >/dev/null 2>&1 && cp_ok "UFW: deleted rule '$1'" || cp_err "could not delete UFW rule: $1"
}
ufw_cleanup() {   # after the purge: drop the firewall rules of removed service families
    command -v ufw >/dev/null 2>&1 || return 0
    local i p gone spec profs ports line arg n q inuse listen
    local -a added=()
    mapfile -t added < <(ufw show added 2>/dev/null | sed -n 's/^ufw //p')
    [ ${#added[@]} -gt 0 ] || return 0
    listen="$(ss -Htuln 2>/dev/null | awk '{n = split($5, a, ":"); print a[n]}' | sort -u)"
    for i in "${!FAM_LABEL[@]}"; do
        spec="${FW_OF[${FAM_LABEL[$i]}]:-}"; [ -n "$spec" ] || continue
        # only when the family is gone completely: removing exim4 (mail) must not drop a kept dovecot's rules
        gone=0; left=0
        for p in ${FAM_PKGS[$i]}; do
            if [ -n "$(pkg_state "$p" | grep -v '^rc')" ]; then left=1
            elif [ -n "${TARGET_SET[$(base "$p")]:-}" ]; then gone=1; fi
        done
        [ "$gone" = 1 ] && [ "$left" = 0 ] || continue
        profs="${spec%% [0-9]*}"; ports="${spec#"$profs"}"
        for line in "${added[@]}"; do
            arg="${line#allow }"; arg="${arg#\'}"; arg="${arg%\'}"
            [ "$arg" != "$line" ] || continue
            if [[ "|$profs|" == *"|$arg|"* ]]; then fw_delete "$line"; continue; fi
            for n in $ports; do
                [ "$arg" = "$n" ] || continue
                # a port rule stays while something still listens there (e.g. nginx on 80 after apache2 is gone)
                inuse=0; for q in $(tr ',:' '  ' <<< "${n%%/*}"); do grep -qx "$q" <<< "$listen" && inuse=1; done
                [ "$inuse" = 1 ] && { cp_info "UFW rule '$line' kept - port still in use"; continue; }
                fw_delete "$line"
            done
        done
    done
}

# Metapackages (ubuntu-desktop, ubuntu-minimal, ubuntu-standard, mint-meta-*, task-*) get removed
# when one of their dependencies is removed (e.g. telnet -> ubuntu-standard). After that,
# autoremove would remove EVERYTHING they pulled in. Mark their other dependencies as manually
# installed so autoremove leaves them alone.
protect_metapackages() {
    local m sec deps d marked=()
    declare -A rm_set=()
    for d in "$@"; do rm_set[$(base "$d")]=1; done
    for m in "$@"; do
        m="$(base "$m")"
        sec="$($DPKGQ -W -f='${Section}' "$m" 2>/dev/null)"
        if [[ "$sec" == *metapackages* ]] || [[ "$m" =~ ^(ubuntu|kubuntu|xubuntu|lubuntu|ubuntu-mate|ubuntu-budgie|edubuntu|mint|mint-meta|cinnamon|task)- ]]; then
            deps="$($APTCACHE depends --installed --no-suggests --no-conflicts --no-breaks --no-replaces --no-enhances "$m" 2>/dev/null \
                    | awk '$1 ~ /^\|?(Depends|PreDepends|Recommends):$/ {print $2}' | grep -v '^<' | sed 's/:.*//' | sort -u)"
            for d in $deps; do
                [ -n "${rm_set[$d]:-}" ] && continue
                [ -n "$(pkg_state "$d")" ] || continue
                marked+=("$d")
            done
            cp_warn "Metapackage '$m' will be removed along with your list."
        fi
    done
    if [ ${#marked[@]} -gt 0 ]; then
        $APTMARK manual "${marked[@]}" >/dev/null 2>&1
        cp_ok "Marked ${#marked[@]} of its dependencies as manually installed so autoremove keeps them"
    fi
}

# ============================================================ [0] tool sanity ==
cp_hdr "[0] Package tool sanity (can apt/dpkg be trusted on this image?)"
SANE=1
for c in apt apt-get apt-mark apt-cache dpkg dpkg-query sudo; do
    while IFS= read -r p; do
        case "$p" in /usr/bin/*|/bin/*|/usr/sbin/*|/sbin/*) ;;
            *) owner="$($DPKGQ -S "$p" 2>/dev/null | cut -d: -f1)"
               if [ -n "$owner" ] && $DPKG --verify "$owner" 2>/dev/null | grep -qF " $p"; then
                   cp_warn "'$c' at $p belongs to package $owner but was MODIFIED - inspect it"; SANE=0
                   cp_todo "Inspect $p (package $owner, modified) - it runs instead of /usr/bin/$c"
               elif [ -n "$owner" ]; then
                   cp_info "'$c' at $p is from package $owner (Linux Mint's apt wrapper is normal) - unmodified"
               else
                   cp_warn "Shadow copy of '$c' at $p (runs before /usr/bin/$c) - inspect and delete it"; SANE=0
                   cp_todo "Delete the shadow copy $p (runs before /usr/bin/$c) after a look at it"
               fi ;;
        esac
    done < <({ type -ap "$c" 2>/dev/null; for d in /usr/local/bin /usr/local/sbin; do [ -e "$d/$c" ] && echo "$d/$c"; done; } | sort -u)
done
for c in apt apt-get dpkg dpkg-query; do
    [ -x "/usr/bin/$c" ] || { cp_err "/usr/bin/$c is missing"; SANE=0; }
done
div="$(/usr/bin/dpkg-divert --list 2>/dev/null | grep -E '/(apt|apt-get|apt-mark|apt-cache|dpkg|dpkg-query|sudo) ')"
[ -n "$div" ] && { cp_warn "dpkg diversions on package tools:"; echo "$div" | sed 's/^/        /'; SANE=0; cp_todo "dpkg diversions on package tools - remove with dpkg-divert --remove"; }
alias_hits="$(grep -nsHE '^[[:space:]]*(alias[[:space:]]+(apt|apt-get|dpkg|dpkg-query|sudo)=|(function[[:space:]]+)?(apt|apt-get|dpkg|dpkg-query|sudo)[[:space:]]*\(\))' \
    /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh /etc/environment /root/.bashrc /root/.bash_aliases /root/.profile \
    /home/*/.bashrc /home/*/.bash_aliases /home/*/.profile /home/*/.zshrc 2>/dev/null)"
[ -n "$alias_hits" ] && { cp_warn "Aliases/functions overriding apt/dpkg/sudo:"; echo "$alias_hits" | sed 's/^/        /'; SANE=0; cp_todo "Delete the apt/dpkg/sudo alias/function lines: $(echo "$alias_hits" | cut -d: -f1,2 | tr '\n' ' ')"; }
for f in /etc/apt/apt.conf /etc/apt/apt.conf.d/* /etc/apt/preferences /etc/apt/preferences.d/*; do
    [ -f "$f" ] || continue
    cp_owned "$f" && continue
    # written by a package's postinst through ucf and unchanged since (50unattended-upgrades, 20auto-upgrades ...)
    uh="$(awk -v f="$f" '$2 == f {print $1; exit}' /var/lib/ucf/hashfile 2>/dev/null)"
    [ -n "$uh" ] && [ "$uh" = "$(md5sum "$f" | cut -d' ' -f1)" ] && continue
    # Linux Mint copies this pin file from mintsystem at install
    [ "$f" = /etc/apt/preferences.d/official-package-repositories.pref ] && cmp -s "$f" /usr/share/linuxmint/mintsystem/apt/official-package-repositories.pref && continue
    if grep -qiE 'Invoke|Pre-Install-Pkgs|Pin-Priority|AllowUnauthenticated|AllowInsecure|Trusted' "$f" 2>/dev/null; then
        cp_warn "APT config not owned by any package: $f"; grep -nviE '^[[:space:]]*(//|#|$)' "$f" | head -8 | sed 's/^/        /'; SANE=0
        cp_todo "Review APT config $f (hook/pin/insecure option, no package owns it)"
    fi
done
held="$($APTMARK showhold 2>/dev/null)"
[ -n "$held" ] && cp_warn "Packages on HOLD (unheld automatically if you remove them): $(echo $held)"
aud="$($DPKG --audit 2>/dev/null)"
[ -n "$aud" ] && { cp_warn "dpkg --audit reports broken/half-installed packages (fix: sudo dpkg --configure -a; sudo apt-get -f install):"; echo "$aud" | head -15 | sed 's/^/        /'; }
# conffiles ("c") and docs/man/locale (stripped on minimized images) are ignored
ver="$($DPKG --verify dpkg apt 2>/dev/null | awk '$2 != "c" && $NF !~ /^\/usr\/share\/(doc|man|locale|info|lintian)\//')"
[ -n "$ver" ] && { cp_warn "dpkg/apt files differ from their package (tampered?):"; echo "$ver" | sed 's/^/        /'; SANE=0; cp_todo "dpkg/apt files modified - reinstall: apt-get install --reinstall dpkg apt"; }
[ "$SANE" = 1 ] && cp_ok "apt/dpkg binaries, diversions, aliases and APT hooks look normal"

# ============================================================ [1] discovery ==
cp_hdr "[1] Unauthorized packages (dpkg-query, whole package names)"
snapshot
scan_catalog
[ ${#FAM_LABEL[@]} -eq 0 ] && cp_ok "No catalog packages installed"

# Programs that did NOT come from dpkg (dpkg/apt can't see or remove these)
OUTSIDE=""
if command -v snap >/dev/null 2>&1; then
    snaps="$(snap list 2>/dev/null | awk 'NR>1 && $1 !~ /^(core[0-9]*|snapd|bare|gtk-common-themes|gnome-[0-9-]+|snapd-desktop-integration|firmware-updater|snap-store|mesa-.*|gtk2-common-themes)$/ {print $1}')"
    [ -n "$snaps" ] && OUTSIDE+="snap (snap remove): $(echo $snaps); "
fi
if command -v flatpak >/dev/null 2>&1; then
    fp="$(flatpak list --app --columns=application 2>/dev/null)"
    [ -n "$fp" ] && OUTSIDE+="flatpak (flatpak uninstall): $(echo $fp); "
fi
# (pyrdp is left to [5b], which uninstalls and quarantines it)
l="$(find /usr/local/bin /usr/local/sbin /usr/local/games -maxdepth 1 \( -type f -o -type l \) 2>/dev/null | sort | cp_unowned | grep -viE "$SCORING_RE|pyrdp")"
[ -n "$l" ] && OUTSIDE+="$(echo $l); "
l="$(find /opt -mindepth 1 -maxdepth 1 2>/dev/null | sort | cp_unowned | grep -viE "$SCORING_RE|pyrdp")"
[ -n "$l" ] && OUTSIDE+="/opt: $(echo $l); "
for t in john hydra nmap ncat nc netcat wireshark tshark ophcrack hashcat aircrack-ng nikto sqlmap medusa ettercap msfconsole zenmap minetest luanti; do
    p="$(command -v "$t" 2>/dev/null)" || continue
    r="$(readlink -f "$p")"
    cp_owned "$p" || cp_owned "$r" || OUTSIDE+="'$t' at $r (hand-installed tool!); "
done
[ -n "$OUTSIDE" ] && cp_todo "Software installed outside dpkg - remove by hand if unauthorized: $OUTSIDE"

# ============================================================ [2] removal ==
if [ "$SCAN_ONLY" = 1 ]; then
    for i in "${!FAM_LABEL[@]}"; do fam_line "$i"; done
    echo
    cp_info "Scan-only mode (--scan or no terminal): nothing removed."
else
    cp_hdr "[2] Build the removal list"
    REMOVE_I=(); SVC_I=(); REVIEW_I=(); SSHD_I=()
    for i in "${!FAM_LABEL[@]}"; do
        case "$(fam_class "$i")" in
            remove)  REMOVE_I+=("$i") ;;
            service) SVC_I+=("$i") ;;
            review)  REVIEW_I+=("$i") ;;
            sshd)    SSHD_I+=("$i") ;;
        esac
    done
    if [ ${#REMOVE_I[@]} -gt 0 ]; then
        echo "  Hacking tools, remote access, P2P, games:"
        for i in "${REMOVE_I[@]}"; do fam_line "$i"; done
        select_batch y "Remove all of these (e = choose per family)?" "${REMOVE_I[@]}"
    fi
    if [ ${#SVC_I[@]} -gt 0 ]; then
        echo "  Services - remove only what the README does NOT list as critical:"
        for i in "${SVC_I[@]}"; do fam_line "$i"; echo "              ↳ $(fam_hint "$i")"; done
        select_batch n "Remove these service packages (e = choose per family)?" "${SVC_I[@]}"
    fi
    if [ ${#REVIEW_I[@]} -gt 0 ]; then
        echo "  Review - usually kept (desktop defaults, tools that ship with Ubuntu/Mint):"
        for i in "${REVIEW_I[@]}"; do fam_line "$i"; [ -n "${FAM_NOTE[$i]}" ] && echo "              note: ${FAM_NOTE[$i]}"; done
        select_batch n "Remove these too?" "${REVIEW_I[@]}"
    fi
    for i in "${SSHD_I[@]}"; do
        fam_line "$i"; echo "              ↳ $(fam_hint "$i")"
        if cp_ask "Remove the OpenSSH server? Only if the README does not need SSH!" n; then
            for p in ${FAM_PKGS[$i]}; do add_target "$p"; done
        fi
    done

    while true; do
        line="$(cp_read "Other packages to remove (names/globs, ?word = search), Enter = none" "")"
        [ -z "$line" ] && break
        for tok in $line; do
            if [[ "$tok" == \?* ]]; then
                awk -F'\t' -v w="${tok#?}" 'substr($1,2,1)!="n" && substr($1,2,1)!="c" && index(tolower($3), tolower(w)) {print "      " $2}' "$TMPD/inst"
                continue
            fi
            found=0
            while IFS=$'\t' read -r st name; do
                [ -z "$name" ] && continue
                case "${st:1:1}" in n|c) continue ;; esac
                add_target "$name"; found=1; echo "      added $name"
            done < <($DPKGQ -W -f='${db:Status-Abbrev}\t${binary:Package}\n' "$tok" 2>/dev/null)
            [ "$found" = 0 ] && cp_warn "'$tok' is not installed (dpkg has no installed package by that name)"
        done
    done

    if [ ${#TARGETS[@]} -eq 0 ]; then
        cp_info "Nothing selected for removal."
    else
        cp_hdr "Removal preview (apt-get -s purge)"
        echo "  Your list (${#TARGETS[@]}): ${TARGETS[*]}" | fold -s -w 110
        mapfile -t SIM < <(simulate purge --allow-change-held-packages "${TARGETS[@]}")
        if [ -s "$TMPD/simerr" ] && grep -q '^E:' "$TMPD/simerr"; then
            cp_err "apt-get refused the simulated removal:"; sed 's/^/        /' "$TMPD/simerr"
        fi
        EXTRA=()
        for s in "${SIM[@]}"; do [ -z "${TARGET_SET[$(base "$s")]:-}" ] && EXTRA+=("$s"); done
        if [ ${#EXTRA[@]} -gt 0 ]; then
            cp_warn "apt would ALSO remove ${#EXTRA[@]} package(s) that depend on your list:"
            echo "${EXTRA[@]}" | fold -s -w 100 | sed 's/^/        /'
        else
            cp_ok "Nothing else would be removed."
        fi
        BAD="$(protected_in "${SIM[@]}" | tr '\n' ' ')"
        SVCDEP="$(services_in "${EXTRA[@]}" | tr '\n' ' ')"
        [ -n "$SVCDEP" ] && { cp_err "apt would also remove service packages you did not choose: $SVCDEP"; BAD+="$SVCDEP"; }
        META_ONLY=1; for b in $BAD; do [[ "$b" =~ ^($META_RE)$ ]] || META_ONLY=0; done
        PURGE_OK=1
        if [ -n "$BAD" ] && [ "$META_ONLY" = 1 ]; then
            cp_warn "This also removes desktop METAPACKAGE(s): $BAD - the guard marks everything they pulled in as manually installed, so the desktop stays"
            cp_ask "Purge (including the metapackage)?" y || PURGE_OK=0
        elif [ -n "$BAD" ]; then
            cp_err "This would remove DESKTOP / CRITICAL-SERVICE packages: $BAD"
            cp_ask "Purge anyway (normally: answer n, then rerun and choose with e)?" n || PURGE_OK=0
        elif [ ${#EXTRA[@]} -gt 15 ]; then
            cp_warn "That is a lot - check nothing the README needs is in there."
            cp_ask "Purge these ${#SIM[@]} package(s)?" n || PURGE_OK=0
        else
            cp_ask "Purge these ${#SIM[@]} package(s) (no desktop/critical package among them)?" y || PURGE_OK=0
        fi
        if [ "$PURGE_OK" = 1 ]; then
            t0=$SECONDS
            protect_metapackages "${SIM[@]}"
            for p in "${TARGETS[@]}"; do
                case "$(pkg_state "$p")" in h*) $APTMARK unhold "$(base "$p")" >/dev/null 2>&1 && cp_info "Unheld $p";; esac
            done
            cp_info "apt-get purge ${#TARGETS[@]} package(s) (waits for any background apt job; log: $CP_STATE_DIR/apt-purge.log)"
            if ! cp_apt purge -y --allow-change-held-packages "${TARGETS[@]}" >"$CP_STATE_DIR/apt-purge.log" 2>&1; then
                cp_warn "apt-get purge failed - repairing dpkg state and retrying once"
                $DPKG --configure -a >>"$CP_STATE_DIR/apt-purge.log" 2>&1
                cp_apt -f install -y >>"$CP_STATE_DIR/apt-purge.log" 2>&1
                cp_apt purge -y --allow-change-held-packages "${TARGETS[@]}" >>"$CP_STATE_DIR/apt-purge.log" 2>&1
            fi
            cp_info "purge took $(since $t0)"

            # Verify with dpkg-query (not apt)
            LEFT=(); GONE=0
            for p in "${TARGETS[@]}" "${EXTRA[@]}"; do
                st="$(pkg_state "$p")"
                case "$st" in
                    ""|rc) GONE=$((GONE + 1)) ;;
                    *)     cp_err "$p: STILL INSTALLED (dpkg state '$st')"; LEFT+=("$p") ;;
                esac
            done
            cp_ok "dpkg-query: $GONE of $(( ${#TARGETS[@]} + ${#EXTRA[@]} )) packages gone"
            ufw_cleanup
            for p in "${LEFT[@]}"; do
                if cp_ask "Try 'dpkg --purge $p' directly?" y; then
                    $DPKG --purge "$p" || { cp_err "dpkg refused (the error above names what depends on it - remove that too, or leave $p)"; cp_todo "$p is still installed - see dpkg --purge $p"; }
                fi
            done
        fi
    fi

    # Autoremove: dependencies nothing needs any more (libwireshark*, samba deps, ...)
    mapfile -t AUTO < <(simulate autoremove --purge)
    if [ ${#AUTO[@]} -gt 0 ]; then
        cp_hdr "apt-get autoremove --purge (dependencies nothing needs any more)"
        echo "  Would remove ${#AUTO[@]}:"; echo "${AUTO[@]}" | fold -s -w 100 | sed 's/^/        /'
        BAD="$(protected_in "${AUTO[@]}" | tr '\n' ' ')$(services_in "${AUTO[@]}" | tr '\n' ' ')"
        # (removing wireshark/ophcrack/minetest alone frees ~60 libraries; the desktop is guarded by
        #  protect_metapackages + the protected-package check, so only a huge list still asks)
        if [ -n "$BAD" ] || [ ${#AUTO[@]} -gt 150 ]; then
            [ -n "$BAD" ] && cp_err "The list contains desktop/critical packages: $BAD"
            [ ${#AUTO[@]} -gt 150 ] && cp_warn "Very large list - make sure the desktop/critical services are not in it."
            DO_AUTO=n; cp_ask "Run autoremove?" n && DO_AUTO=y
        else
            DO_AUTO=n; cp_ask "Run autoremove (${#AUTO[@]} unused dependencies, no desktop/critical package)?" y && DO_AUTO=y
        fi
        [ "$DO_AUTO" = y ] && { cp_apt autoremove --purge -y >>"$CP_STATE_DIR/apt-purge.log" 2>&1 && cp_ok "autoremove done"; }
    fi

    # Leftover configs of removed packages ("rc" in dpkg -l)
    mapfile -t RC < <($DPKGQ -W -f='${db:Status-Abbrev}\t${binary:Package}\n' 2>/dev/null | awk -F'\t' '$1 ~ /^rc/ {print $2}')
    if [ ${#RC[@]} -gt 0 ]; then
        cp_info "Removed packages with config files left (rc): ${RC[*]}" | fold -s -w 110
        cp_ask "Purge their config files (dpkg --purge)?" y && $DPKG --purge "${RC[@]}" >/dev/null 2>&1 && cp_ok "Purged"
    fi

    # Re-scan: the proof
    cp_hdr "Re-scan after removal"
    snapshot
    scan_catalog
    if [ ${#FAM_LABEL[@]} -eq 0 ]; then
        cp_ok "No catalog packages installed any more"
    else
        KEPT=""
        for i in "${!FAM_LABEL[@]}"; do
            for p in ${FAM_PKGS[$i]}; do
                if [ -n "${TARGET_SET[$(base "$p")]:-}" ]; then
                    cp_err "$p (${FAM_LABEL[$i]}) - you chose to remove it but it is STILL INSTALLED"
                    cp_todo "$p is still installed although you chose to remove it"
                else KEPT+="$p "; fi
            done
        done
        [ -n "$KEPT" ] && cp_info "Kept: $KEPT" | fold -s -w 110
    fi
    held="$($APTMARK showhold 2>/dev/null | tr '\n' ' ')"
    [ -n "$held" ] && cp_todo "Packages still on hold: $held- apt-mark unhold them unless the README requires the hold (holds block updates)"
fi

# ============================================================ [3] services ==
cp_hdr "[3] Unauthorized services (exact unit names)"
# remote-access daemons are never README-critical in practice (like the REMOTE package families: default yes);
# server services and desktop defaults are README decisions (default no); SSH gets its own question.
REMOTE_UNITS=" xinetd inetd openbsd-inetd inetutils-inetd telnet tftpd-hpa atftpd xrdp x11vnc vncserver tor "
DESKTOP_UNITS=" cups cups-browsed avahi-daemon "
SUSPICIOUS_UNITS=(
    xinetd inetd openbsd-inetd inetutils-inetd postfix sendmail exim4 nfs-server nfs-kernel-server rpcbind
    smbd nmbd samba samba-ad-dc winbind postgresql vsftpd pure-ftpd proftpd apache2 nginx lighttpd
    mysql mariadb snmpd dovecot named bind9 dnsmasq unbound avahi-daemon cups cups-browsed xrdp x11vnc
    vncserver inspircd ngircd squid telnet tftpd-hpa atftpd redis-server memcached mongod tomcat9 tor ssh
)
for f in $(grep -E '^php[0-9.]*-fpm\.service$' "$TMPD/units" | sed 's/\.service$//'); do SUSPICIOUS_UNITS+=("$f"); done
REM_U=(); SRV_U=(); DSK_U=(); SSH_U=()
for u in "${SUSPICIOUS_UNITS[@]}"; do
    st=""
    for unit in "$u.service" "$u.socket"; do
        grep -qxF "$unit" "$TMPD/units" || continue
        if systemctl is-active --quiet "$unit" 2>/dev/null; then pt="$(unit_ports "$u")"; st="active${pt:+ on $pt}"; break
        elif systemctl is-enabled --quiet "$unit" 2>/dev/null; then st="enabled"; fi
    done
    [ -z "$st" ] && continue
    if [ "$u" = ssh ]; then SSH_U+=("$u ($st)")
    elif [[ "$REMOTE_UNITS" == *" $u "* ]]; then REM_U+=("$u ($st)")
    elif [[ "$DESKTOP_UNITS" == *" $u "* ]]; then DSK_U+=("$u ($st)")
    else SRV_U+=("$u ($st)"); fi
done
disable_units() {  # disable_units "unit (state)"... -> stop + disable unit.service/.socket/.path
    local x u k
    for x in "$@"; do
        u="${x%% *}"
        for k in "$u.socket" "$u.path" "$u.service"; do
            systemctl list-unit-files "$k" --no-legend 2>/dev/null | grep -q . || continue
            systemctl disable --now "$k" >/dev/null 2>&1
        done
        systemctl is-active --quiet "$u" 2>/dev/null && cp_err "$u is still running" || cp_ok "$u stopped and disabled"
    done
}
pick_units() {  # pick_units DEFAULT QUESTION ITEMS...
    local def="$1" q="$2" x; shift 2
    case "$(ask3 "$q" "$def")" in
        y) disable_units "$@" ;;
        e) for x in "$@"; do cp_ask "Stop + disable $x?" "$def" && disable_units "$x"; done ;;
    esac
}
if [ $(( ${#REM_U[@]} + ${#SRV_U[@]} + ${#DSK_U[@]} + ${#SSH_U[@]} )) -eq 0 ]; then
    cp_ok "No suspicious services active or enabled"
elif [ "$SCAN_ONLY" = 1 ]; then
    for x in "${REM_U[@]}" "${SRV_U[@]}" "${DSK_U[@]}" "${SSH_U[@]}"; do echo "    $x"; done
    cp_info "(If the README needs it: keep it. Otherwise: sudo systemctl disable --now <unit>, or remove its package.)"
else
    [ ${#REM_U[@]} -gt 0 ] && { echo "  Remote-access daemons: ${REM_U[*]}"; pick_units y "Stop + disable these ${#REM_U[@]} remote-access service(s)?" "${REM_U[@]}"; }
    [ ${#SRV_U[@]} -gt 0 ] && { echo "  Server services - stop only what the README does NOT need: ${SRV_U[*]}"; pick_units n "Stop + disable these ${#SRV_U[@]} server service(s) (e = each)?" "${SRV_U[@]}"; }
    [ ${#DSK_U[@]} -gt 0 ] && { echo "  Desktop defaults (printing / zeroconf; disabling is scored on some images): ${DSK_U[*]}"; pick_units n "Stop + disable these ${#DSK_U[@]} desktop service(s)?" "${DSK_U[@]}"; }
    [ ${#SSH_U[@]} -gt 0 ] && { echo "  SSH: ${SSH_U[*]}"; cp_ask "Stop + disable the SSH server? Only if the README does not need SSH!" n && disable_units "${SSH_U[@]}"; }
fi

# ============================================================ [4] shares ==
cp_hdr "[4] Mounted network shares"
MOUNTED_SHARES="$(mount | grep -E "type (nfs|nfs4|cifs|smbfs|fuse.sshfs)" 2>/dev/null)"
if [ -z "$MOUNTED_SHARES" ]; then
    cp_ok "No mounted network shares"
else
    echo "$MOUNTED_SHARES" | sed 's/^/    /'
    cp_todo "Mounted network shares found ($(echo "$MOUNTED_SHARES" | awk '{print $3}' | tr '\n' ' ')) - unmount/remove from /etc/fstab unless the README needs them"
fi

# ============================================================ [5]+[6] one filesystem pass ==
cp_hdr "[5] Unauthorized files  +  [6] SUID/SGID/sticky (one pass over the filesystem)"
t0=$SECONDS
# (a) places people keep files: every media/archive/script file is listed
# (b) system dirs: only media/archive files that NO package installed (a planted file hidden in
#     /usr/share/... used to be pruned; listing every file there drowned the real ones in thousands of icons)
MEDIA_RE='.*\.(mp3|mp4|m4a|m4v|avi|mkv|mov|wmv|flv|webm|wav|ogg|oga|ogv|flac|aac|wma|opus|mpg|mpeg|3gp|zip|rar|7z|tar|tgz|gz|bz2|xz|iso|torrent|jpg|jpeg|png|gif|bmp|webp|heic|py|sh|exe|txt|csv|doc|docx|xls|xlsx|pdf)$'
SYS_RE='.*\.(mp3|mp4|m4a|avi|mkv|mov|wmv|flv|webm|wav|ogg|flac|aac|wma|opus|mpg|mpeg|zip|rar|7z|torrent|iso|exe)$'
MEDIA_ONLY='\.(mp3|mp4|m4a|m4v|avi|mkv|mov|wmv|flv|webm|wav|ogg|oga|ogv|flac|aac|wma|opus|mpg|mpeg|3gp|torrent)$'
# our own folder + its sibling tools/ (test harness) are skipped - never their parent, which may be a whole home folder
PRUNE=(/proc /sys /dev /run /snap /var/lib/docker /var/lib/snapd "$CP_BACKUP_ROOT" "$QUAR" "$CP_BASELINE_DIR" "$CP_STATE_DIR" "$CP_ROOT")
[ -d "$CP_ROOT/../tools/verify" ] && PRUNE+=("$(cd "$CP_ROOT/../tools" && pwd)")
while read -r m; do PRUNE+=("$m"); done < <(mount | awk '$5 ~ /^(nfs|nfs4|cifs|smbfs|fuse\.sshfs)$/ {print $3}')
PRUNE_EXPR=(); for d in "${PRUNE[@]}"; do PRUNE_EXPR+=(-o -path "$d"); done
PRUNE_EXPR+=(-o -ipath /opt/cyberpatriot -o -ipath /opt/aeacus)          # scoring engine (case-insensitive)
find / -regextype posix-extended \( "${PRUNE_EXPR[@]:1}" \) -prune -o \( \
      \( -iname '*pyrdp*' -fprint "$TMPD/nonapt" \) , -type f \( \
      \( -perm /7000 -fprintf "$TMPD/perm" '%M\t%u:%g\t%p\n' \) , \
      \( \( -path '/home/*' -o -path '/root/*' -o -path '/srv/*' -o -path '/var/www/*' -o -path '/opt/*' -o -path '/tmp/*' \
            -o -path '/var/tmp/*' -o -path '/media/*' -o -path '/mnt/*' -o -path '/usr/local/*' \) -iregex "$MEDIA_RE" -fprint "$TMPD/userfiles0" \) , \
      \( -iregex "$SYS_RE" -fprint "$TMPD/sysall" \) , \
      \( -name cp-common.sh -fprint "$TMPD/cpcopies" \) \) \) 2>/dev/null
# copies of our own competition folder (a second download, a USB copy ...): its baseline pack has accounts.txt
# files and scripts that would show up as "password files" / "other files" -> drop everything under such a copy
: > "$TMPD/ourdirs"
while IFS= read -r c; do
    d="$(dirname "$c")"; [ -d "$d/baseline" ] || continue
    echo "$d/" >> "$TMPD/ourdirs"; [ -d "$d/../tools/verify" ] && echo "$(cd "$d/../tools" && pwd)/" >> "$TMPD/ourdirs"
done < "$TMPD/cpcopies"
if [ -s "$TMPD/ourdirs" ]; then
    for f in userfiles0 sysall perm nonapt; do
        [ -f "$TMPD/$f" ] || continue
        awk -F'\t' 'NR == FNR { p[++n] = $0; next } { path = (NF >= 3) ? $3 : $0; for (i = 1; i <= n; i++) if (index(path, p[i]) == 1) next; print }' \
            "$TMPD/ourdirs" "$TMPD/$f" > "$TMPD/$f.y" && mv -f "$TMPD/$f.y" "$TMPD/$f"
    done
fi
# belt and braces: nothing of the scoring client ever reaches a list or a delete offer
for f in userfiles0 sysall perm nonapt; do [ -f "$TMPD/$f" ] && { grep -viE "$SCORING_RE" "$TMPD/$f" > "$TMPD/$f.x"; mv -f "$TMPD/$f.x" "$TMPD/$f"; }; done
sort -o "$TMPD/userfiles" "$TMPD/userfiles0" 2>/dev/null || : > "$TMPD/userfiles"
# system folders minus user/data folders and caches/databases; then only what no package installed
grep -E '^/(usr|var|etc|boot|lib|lib32|lib64|libx32|bin|sbin)/' "$TMPD/sysall" 2>/dev/null \
    | grep -vE '^(/var/lib/dpkg|/var/lib/apt|/var/cache|/var/log|/var/lib/swcatalog|/var/lib/app-info|/var/lib/flatpak|/var/lib/snapd|/var/tmp|/var/www|/usr/local|/var/lib/mysql|/var/lib/postgresql)/' \
    | sort | cp_unowned > "$TMPD/sysfiles"
cp_info "filesystem pass took $(since $t0)"

grep -iE "$MEDIA_ONLY" "$TMPD/userfiles" > "$TMPD/usermedia"
# hidden config dirs (~/.config, ~/.local ...) are skipped here - media in them is still listed above
grep -viE "$MEDIA_ONLY" "$TMPD/userfiles" | grep -v '/\.' > "$TMPD/other"
cp "$TMPD/usermedia" "$CP_STATE_DIR/files-media.txt"; cp "$TMPD/sysfiles" "$CP_STATE_DIR/files-system-unowned.txt"; cp "$TMPD/other" "$CP_STATE_DIR/files-other.txt"
echo "  Media files in user/data folders ($(wc -l < "$TMPD/usermedia")) - usually scored:"
sed 's/^/    /' "$TMPD/usermedia" | head -40
echo "  Media/archives in system folders that NO package installed ($(wc -l < "$TMPD/sysfiles")) - planted:"
sed 's/^/    /' "$TMPD/sysfiles" | head -40
n_other=$(wc -l < "$TMPD/other")
echo "  Other files in user/data folders ($n_other: archives, scripts, documents, images) - first 25, full list $CP_STATE_DIR/files-other.txt:"
sed 's/^/    /' "$TMPD/other" | head -25

# Quarantine instead of rm: /root/cp-quarantine/<original path>, restore with mv. Works for directories too.
quarantine() {
    local f="$1" d="$QUAR$1"
    is_scoring "$f" && { cp_warn "$f belongs to the scoring engine - not touched"; return 1; }
    [ -e "$d" ] || [ -L "$d" ] && d="$d.$CP_TS"          # never move a directory INTO an older copy
    mkdir -p "$(dirname "$d")" && chmod 700 "$QUAR" && mv -f -- "$f" "$d" && cp_ok "Moved $f -> $d"
}
# Media in web roots may be site content -> human decision; everything else is offered in one go.
grep -vE '^/(var/www|srv)/' "$TMPD/usermedia" > "$TMPD/delmedia"
grep -iE "$MEDIA_ONLY" "$TMPD/sysfiles" >> "$TMPD/delmedia"
grep -E '^/(var/www|srv)/' "$TMPD/usermedia" | while IFS= read -r f; do cp_todo "Media in a web/data root (site content?): $f - delete if the README doesn't need it"; done
grep -viE "$MEDIA_ONLY" "$TMPD/sysfiles" | while IFS= read -r f; do cp_todo "Archive/executable no package installed: $f - delete if unauthorized"; done
mapfile -t DELM < <(grep -viE "$SCORING_RE" "$TMPD/delmedia")
if [ ${#DELM[@]} -gt 0 ]; then
    if [ "$SCAN_ONLY" = 1 ]; then
        for f in "${DELM[@]}"; do cp_todo "Media file: $f - delete unless the README needs it"; done
    else
        case "$(ask3 "Delete these ${#DELM[@]} media file(s) (moved to $QUAR, restorable)?" y)" in
            y) for f in "${DELM[@]}"; do quarantine "$f"; done ;;
            e) for f in "${DELM[@]}"; do cp_ask "Delete $f?" y && quarantine "$f"; done ;;
        esac
        for f in "${DELM[@]}"; do [ -e "$f" ] && cp_todo "Media file kept: $f - delete unless the README needs it"; done
    fi
fi
# [5b] Non-apt hacking tools (merged from Max's Mac copy, 2026-11-10): PyRDP (pyrdp-mitm, an RDP
# man-in-the-middle tool) usually comes from pip, pipx or a git clone, which dpkg never sees. Paths named
# *pyrdp* came out of the single filesystem pass above; package-owned ones belong to python3-pyrdp ([2]).
sort -u "$TMPD/nonapt" 2>/dev/null | cp_unowned > "$TMPD/pyrdp"
if [ -s "$TMPD/pyrdp" ]; then
    cp_warn "[5b] pyrdp installed outside apt (pip/pipx/git clone - prohibited software): $(wc -l < "$TMPD/pyrdp") path(s)"
    sed 's/^/    /' "$TMPD/pyrdp" | head -20
    if [ "$SCAN_ONLY" = 1 ]; then
        cp_todo "pyrdp outside apt: pip3 uninstall pyrdp-mitm; pipx uninstall pyrdp-mitm; then delete: $(head -5 "$TMPD/pyrdp" | tr '\n' ' ')"
    elif cp_ask "Uninstall pyrdp (pip/pipx) and quarantine these paths?" y; then
        for pp in pip3 pip; do
            command -v "$pp" >/dev/null 2>&1 || continue
            "$pp" uninstall -y --break-system-packages pyrdp-mitm pyrdp >/dev/null 2>&1 \
                || "$pp" uninstall -y pyrdp-mitm pyrdp >/dev/null 2>&1      # pip < 23 has no --break-system-packages
        done
        command -v pipx >/dev/null 2>&1 && pipx uninstall pyrdp-mitm >/dev/null 2>&1
        # root's pip/pipx only see root's installs: per-user installs and git clones are moved away by path
        while IFS= read -r pth; do
            [ -e "$pth" ] || [ -L "$pth" ] || continue            # gone with pip, or inside a directory already moved
            quarantine "$pth" >/dev/null
        done < "$TMPD/pyrdp"
        left=0; while IFS= read -r pth; do [ -e "$pth" ] || [ -L "$pth" ] && { cp_err "still present: $pth"; left=1; }; done < "$TMPD/pyrdp"
        [ "$left" = 0 ] && cp_ok "pyrdp removed (pip/pipx uninstall + moved to $QUAR)" || cp_todo "pyrdp still present - see the paths above"
    else
        cp_todo "pyrdp kept: $(head -5 "$TMPD/pyrdp" | tr '\n' ' ')- remove it unless the README authorizes it"
    fi
fi

# Plaintext password files (scored on intro images): by name, or text files in homes that mention passwords
{
    grep -iE '/[^/]*(pass(word)?s?|passwd|pwd|creds?|credentials?|secrets?|logins?|accounts?)[^/]*$' "$TMPD/other"
    grep -E '^/(home|root)/' "$TMPD/other" | grep -iE '\.(txt|csv)$' | head -300 | while IFS= read -r f; do
        [ "$(stat -c %s "$f" 2>/dev/null || echo 0)" -lt 1048576 ] && grep -qiE 'pass(word|wd)?[[:space:]]*[:=]|^[a-z_][a-z0-9_.-]*:[^[:space:]:]{4,}$' "$f" 2>/dev/null && echo "$f"
    done
} | sort -u | while IFS= read -r f; do cp_todo "Plaintext password file? $f - delete it if the README doesn't need it"; done
[ "$n_other" -gt 0 ] && cp_todo "Glance over $n_other other files in user folders: $CP_STATE_DIR/files-other.txt (archives, scripts, documents)"

# [6] SUID/SGID: stock Ubuntu/Mint helpers are counted, not listed. Unexpected ones are shown.
STOCK_SUID_RE='/(passwd|chsh|chfn|gpasswd|newgrp|su|sudo|sudoedit|mount|umount|fusermount|fusermount3|pkexec|ssh-keysign|dbus-daemon-launch-helper|polkit-agent-helper-1|Xorg\.wrap|dmcrypt-get-device|pppd|ntfs-3g|snap-confine|at|crontab|chage|expiry|wall|write|write\.ul|bsd-write|ssh-agent|unix_chkpwd|pam_extrausers_chkpwd|dotlockfile|mlocate|plocate|utempter|mail-lock|mail-unlock|mail-touchlock|postdrop|postqueue|camel-lock-helper-1\.2|chrome-sandbox|vmware-user-suid-wrapper|mount\.nfs|mount\.cifs|mount\.ecryptfs_private|exim4|newuidmap|newgidmap|bwrap|Xorg|lockfile|procmail|screen|ksu|staprun|spice-client-glib-usb-acl-helper|gnome-pty-helper|lxc-user-nic|qemu-bridge-helper|xscreensaver|ping|ping6|arping|traceroute6\.iputils)$'
: > "$TMPD/perm.own"; : > "$TMPD/perm.unown"
if [ -s "$TMPD/perm" ]; then
    cut -f3 "$TMPD/perm" | sort -u | cp_unowned > "$TMPD/perm.unownpaths"
    awk -F'\t' 'NR == FNR { u[$0] = 1; next } { print > ((($3 in u) ? "'"$TMPD"'/perm.unown" : "'"$TMPD"'/perm.own")) }' "$TMPD/perm.unownpaths" "$TMPD/perm"
fi
cp "$TMPD/perm" "$CP_STATE_DIR/files-suid-sgid.txt" 2>/dev/null
n_perm=$(wc -l < "$TMPD/perm" 2>/dev/null || echo 0)
grep -vE "$STOCK_SUID_RE" "$TMPD/perm.own" | awk -F'\t' '$1 ~ /^-..[sS]|^-.....[sS]/' > "$TMPD/perm.odd"
grep -E "$STOCK_SUID_RE" "$TMPD/perm.unown" | awk -F'\t' '$1 ~ /^-..[sS]|^-.....[sS]/' > "$TMPD/perm.unownstock"
grep -vE "$STOCK_SUID_RE" "$TMPD/perm.unown" | awk -F'\t' '$1 ~ /^-..[sS]|^-.....[sS]/' > "$TMPD/perm.strip"
awk -F'\t' '$1 ~ /[tT]$/' "$TMPD/perm" > "$TMPD/perm.sticky"
cp_info "$n_perm SUID/SGID/sticky files (full list: $CP_STATE_DIR/files-suid-sgid.txt); stock helpers not shown"
# SUID/SGID files writable by group/others = anyone in that group can replace e.g. sudo (never so on stock;
# also what a lost/planted ACL mask leaves behind: -rwsrwxr-x)
mapfile -t WRIT < <(awk -F'\t' '$1 ~ /^-..[sS]|^-.....[sS]/ && ($1 ~ /^-....w/ || $1 ~ /^-.......w/) {print $3}' "$TMPD/perm")
if [ ${#WRIT[@]} -gt 0 ]; then
    cp_warn "SUID/SGID files writable by group/others: $(for f in "${WRIT[@]}"; do printf '%s(%s) ' "$f" "$(stat -c %A "$f")"; done)"
    if [ "$SCAN_ONLY" = 1 ]; then cp_todo "chmod go-w on writable SUID/SGID files: ${WRIT[*]}"
    elif cp_ask "Remove group/other write permission from them (chmod go-w; never writable on stock)?" y; then
        for f in "${WRIT[@]}"; do chmod go-w "$f" && cp_ok "chmod go-w $f -> $(stat -c %A "$f")"; done
    fi
fi
if [ -s "$TMPD/perm.strip" ]; then
    cp_warn "SUID/SGID files that NO package installed (planted?):"; sed 's/^/    /' "$TMPD/perm.strip"
    mapfile -t STRIP < <(cut -f3 "$TMPD/perm.strip")
    if [ "$SCAN_ONLY" = 1 ]; then cp_todo "SUID/SGID files no package installed: ${STRIP[*]}"
    else
        case "$(ask3 "Remove the SUID/SGID bit from these ${#STRIP[@]} file(s)?" y)" in
            y) for f in "${STRIP[@]}"; do chmod u-s,g-s "$f" && cp_ok "chmod u-s,g-s $f"; done ;;
            e) for f in "${STRIP[@]}"; do cp_ask "chmod u-s,g-s $f?" y && chmod u-s,g-s "$f" && cp_ok "Fixed $f"; done ;;
            *) cp_todo "SUID/SGID files no package installed: ${STRIP[*]}" ;;
        esac
    fi
fi
if [ -s "$TMPD/perm.odd" ]; then
    cp_warn "SUID/SGID on package files that are not stock SUID helpers:"; sed 's/^/    /' "$TMPD/perm.odd"
    cp_todo "Check SUID/SGID on: $(cut -f3 "$TMPD/perm.odd" | tr '\n' ' ')(chmod u-s,g-s <file> unless it's a known helper)"
fi
[ -s "$TMPD/perm.unownstock" ] && cp_todo "SUID/SGID helpers no package installed (copies?): $(cut -f3 "$TMPD/perm.unownstock" | tr '\n' ' ')"
[ -s "$TMPD/perm.sticky" ] && { cp_warn "Regular files with the sticky bit:"; sed 's/^/    /' "$TMPD/perm.sticky"; cp_todo "Sticky bit on regular files: $(cut -f3 "$TMPD/perm.sticky" | tr '\n' ' ')"; }
[ -s "$TMPD/perm.strip" ] || [ -s "$TMPD/perm.odd" ] || [ -s "$TMPD/perm.sticky" ] || [ ${#WRIT[@]} -gt 0 ] || cp_ok "Only stock SUID/SGID helpers found"

echo
cp_ok "fileandpackage done in $(since $T_START)$( [ -d "$QUAR" ] && echo ". Quarantined files: $QUAR (restore: mv $QUAR/<path> /<path>)")"
