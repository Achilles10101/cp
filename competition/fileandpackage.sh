#!/bin/bash
# fileandpackage.sh - unauthorized packages and services, network shares, unauthorized files,
# SUID/SGID/sticky bits.
#
# Package handling was rewritten 2026-10-20 after a test run on a live image:
#   * dpkg is the source of truth. Detection reads dpkg-query and matches WHOLE PACKAGE NAMES.
#     (The old `dpkg -l | grep -w "^ii.*nc"` matched any word in any line, including other
#     packages' names and descriptions: "nc" matched "libxcb-sync1 ... sync extension", so
#     packages kept being reported after they were removed.)
#   * Every entry is a FAMILY. `apt remove wireshark` only removes the package literally called
#     wireshark; wireshark-qt, wireshark-common, tshark, libwireshark15, libwiretap12 ... stay.
#   * You are asked about every family found (or each package in it) and can add your own
#     packages. Before anything is removed you see everything apt would take with them.
#   * Removal = apt-get purge, then every package is re-checked with dpkg-query, then
#     autoremove, then leftover configs (dpkg state "rc") are purged, then the scan runs again.
#
# Usage: sudo bash fileandpackage.sh          interactive
#        sudo bash fileandpackage.sh --scan   report only, removes nothing (also used with no TTY)

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/cp-common.sh" \
    || { echo "cp-common.sh not found - keep the competition folder intact"; exit 1; }

cp_require_root
cp_screenshot_prompt

SCAN_ONLY=0
[ "${1:-}" = "--scan" ] && SCAN_ONLY=1
[ -t 0 ] || SCAN_ONLY=1

echo "File, Package, and SUID/GUID Scanner"

# Call the real binaries by full path: a planted /usr/local/bin/apt-get (or dpkg-query) comes
# before /usr/bin in sudo's secure_path. Section [0] reports such shadow copies.
DPKGQ=/usr/bin/dpkg-query
DPKG=/usr/bin/dpkg
APTGET=/usr/bin/apt-get
APTMARK=/usr/bin/apt-mark
APTCACHE=/usr/bin/apt-cache
APT_OPTS=(-o DPkg::Lock::Timeout=120)
NATIVE_ARCH="$($DPKG --print-architecture 2>/dev/null)"
TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT

# ------------------------------------------------------------------ catalog --
# CATEGORY ; DEFAULT ; LABEL ; REGEX (ERE, matched against the WHOLE package name, no :arch) ; NOTE
#   DEFAULT y = suggested removal. n = check the README first (it may be a CRITICAL service, or a
#   stock Ubuntu/Mint package).   REGEX "SECTION:<s>" matches by dpkg section instead of name.
#   Deliberately NOT listed: samba-libs, libsmbclient, smbclient, samba-common(-bin) (smbclient and the
#   Linux Mint metapackages depend on them - autoremove takes them once the samba server is gone), mysql-common, bind9-dnsutils/
#   bind9-host/bind9-libs (dig), dnsmasq-base - client libraries the desktop itself uses
#   (file manager, NetworkManager). The removal preview shows anything else apt would pull out.
CATALOG='
TOOL;y;john;john|john-data|johnny;
TOOL;y;hydra;hydra|hydra-gtk;
TOOL;y;nmap;nmap|nmap-common|zenmap|ndiff;
TOOL;y;wireshark;wireshark|wireshark-.*|tshark|termshark|libwireshark.*|libwiretap.*|libwsutil.*;
TOOL;y;netcat;netcat|netcat-traditional|netcat-openbsd|ncat|cryptcat|pwncat|socat;netcat-openbsd ships with Ubuntu (removing it is fine; the preview shows the metapackage it takes along)
TOOL;y;password crackers;ophcrack|ophcrack-cli|truecrack|hashcat|hashcat-data|fcrackzip|pdfcrack|rarcrack|sucrack|crack|crack-common|crack-md5|medusa|ncrack|patator|crunch|cewl|samdump2|bkhive|chntpw|hashid|rainbowcrack;
TOOL;y;wireless attack;aircrack-ng|kismet|kismet-.*|reaver|pixiewps|wifite|mdk3|mdk4|cowpatty|pyrit|bully|fern-wifi-cracker|airgraph-ng;
TOOL;y;scanners/exploit;nikto|sqlmap|wpscan|dirb|dirbuster|gobuster|ffuf|wfuzz|skipfish|whatweb|wapiti|zaproxy|metasploit-framework|exploitdb|armitage|beef-xss|burpsuite|openvas.*|gvm|masscan|zmap|netdiscover|arp-scan|nbtscan|unicornscan|hping3|xprobe|xprobe2|p0f|amap|dnsenum|dnsrecon|fierce|enum4linux|smbmap|onesixtyone|nuclei|maltego|recon-ng|theharvester;
TOOL;y;sniff/MITM/backdoor;ettercap-common|ettercap-graphical|ettercap-text-only|dsniff|bettercap|yersinia|responder|mitmproxy|sslstrip|driftnet|macchanger|thc-ipv6|doona|weevely|backdoor-factory|veil|shellter|nishang|powersploit|mimikatz|tor|torbrowser-launcher|proxychains|proxychains4;
REMOTE;y;VNC/RDP servers;tightvncserver|x11vnc|vnc4server|tigervnc-standalone-server|tigervnc-scraping-server|tigervnc-xorg-extension|xrdp|xorgxrdp|teamviewer|anydesk;
REMOTE;y;telnet/rsh/finger;telnet|telnetd|inetutils-telnet|inetutils-telnetd|telnet-ssl|telnetd-ssl|rsh-client|rsh-server|rsh-redone-client|rsh-redone-server|rlogin|rwho|rwhod|talk|talkd|inetutils-talk|inetutils-talkd|finger|fingerd|efingerd|cfingerd;telnet ships with some Ubuntu releases (the preview shows the metapackage it takes along)
REMOTE;y;inetd/tftp/NIS;xinetd|openbsd-inetd|inetutils-inetd|rinetd|tftpd|tftpd-hpa|atftpd|tftp|tftp-hpa|nis|ypserv;
P2P;y;P2P/torrent;vuze|azureus|frostwire|deluge|deluge-.*|deluged|qbittorrent|qbittorrent-nox|transmission|transmission-.*|ktorrent|amule|amule-.*|rtorrent|tixati|bittorrent|bittornado|nicotine|limewire|gnutella|gtk-gnutella|freenet;transmission-gtk ships with Ubuntu desktop - remove unless the README needs it
GAME;y;minetest/luanti;minetest|minetest-.*|luanti|luanti-.*;
GAME;n;other games (dpkg section "games");SECTION:games;Ubuntu ships a few (aisleriot, gnome-mines, gnome-sudoku, gnome-mahjongg)
SERVICE;n;samba (server);samba|samba-dsdb-modules|samba-vfs-modules|samba-ad-.*|samba-testsuite|python3-samba|winbind|libnss-winbind|libpam-winbind|ctdb;KEEP if the README lists Samba/file sharing as critical
SERVICE;n;NFS/rpcbind;nfs-kernel-server|nfs-common|rpcbind;KEEP if the README lists NFS
SERVICE;n;apache2;apache2|apache2-bin|apache2-data|apache2-utils|apache2-doc|libapache2-mod-.*;KEEP if the README lists a web server / website
SERVICE;n;nginx;nginx|nginx-common|nginx-core|nginx-full|nginx-light|nginx-extras|libnginx-mod-.*;KEEP if the README lists a web server / website
SERVICE;n;other web/app servers;lighttpd|tomcat[0-9]*|tomcat[0-9]*-.*|jetty[0-9]*|phpmyadmin|node-red|webmin;
SERVICE;n;PHP;php|php[0-9.]+|php[0-9.]+-.*|php-.*;KEEP if the README lists PHP, WordPress or a PHP website
SERVICE;n;MySQL/MariaDB;mysql-server|mysql-server-.*|mysql-client|mysql-client-.*|mariadb-server|mariadb-server-.*|mariadb-client|mariadb-client-.*|galera-.*;KEEP if the README lists MySQL/MariaDB or WordPress
SERVICE;n;PostgreSQL;postgresql|postgresql-[0-9]+|postgresql-client|postgresql-client-[0-9]+|postgresql-common|postgresql-client-common|postgresql-contrib|postgresql-contrib-.*;KEEP if the README lists PostgreSQL
SERVICE;n;other databases/caches;redis-server|redis|memcached|mongodb|mongodb-.*|couchdb|elasticsearch|influxdb;
SERVICE;n;FTP servers;vsftpd|pure-ftpd|pure-ftpd-.*|proftpd|proftpd-.*|wu-ftpd|ftpd|inetutils-ftpd|tnftpd;KEEP if the README lists FTP
SERVICE;n;mail;postfix|postfix-.*|sendmail|sendmail-.*|exim4|exim4-.*|dovecot-.*|courier-.*|opensmtpd|citadel-server;KEEP if the README lists mail. exim4 is the Debian default MTA
SERVICE;n;DNS servers;bind9|bind9-doc|bind9utils|dnsmasq|unbound|pdns-server|pdns-backend-.*|nsd;KEEP if the README lists DNS
SERVICE;n;SNMP;snmpd|snmp|snmptrapd;
SERVICE;n;squid;squid|squid-common|squid3|squid-openssl|squidclient;KEEP if the README lists a proxy
SERVICE;n;IRC servers;inspircd|ircd-hybrid|ircd-irc2|ircd-ircu|ngircd|unrealircd|charybdis|solanum;
SERVICE;n;CUPS printing;cups|cups-daemon|cups-browsed|cups-client|cups-bsd;Ubuntu desktop default - checklist says disable, removing is optional
SERVICE;n;avahi;avahi-daemon|avahi-utils|avahi-autoipd;Ubuntu desktop default
REVIEW;n;misc review;tcpdump|vino|ftp|tnftp|lftp|ncftp|filezilla;tcpdump/ftp ship with Ubuntu; vino = GNOME VNC server on older releases
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
    FAM_CAT=(); FAM_DEF=(); FAM_LABEL=(); FAM_PKGS=(); FAM_NOTE=()
    declare -gA SEEN=()
    local cat def label re note p keep
    while IFS=';' read -r cat def label re note; do
        [ -z "$cat" ] && continue
        keep=()
        while IFS= read -r p; do
            [ -z "$p" ] && continue
            [ -n "${SEEN[$p]:-}" ] && continue
            SEEN[$p]=1; keep+=("$p")
        done < <(family_members "$re")
        [ ${#keep[@]} -eq 0 ] && continue
        FAM_CAT+=("$cat"); FAM_DEF+=("$def"); FAM_LABEL+=("$label"); FAM_NOTE+=("$note")
        FAM_PKGS+=("${keep[*]}")
    done <<< "$CATALOG"
}

print_held_flag() {  # prints " (HELD)" when dpkg/apt has the package on hold
    case "$(pkg_state "$1")" in h*) echo " (HELD)";; esac
}

# ask3 "Question" DEFAULT -> echoes y, n or e
ask3() {
    local q="$1" def="$2" hint ans
    if [ "$def" = "y" ]; then hint="[Y/n/e]"; else hint="[y/N/e]"; fi
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

# simulate ARGS... -> package names apt-get WOULD remove (no :native-arch suffix), one per line
simulate() {
    $APTGET -s "$@" 2>"$TMPD/simerr" | awk '/^(Purg|Remv) /{print $2}' | sed "s/:${NATIVE_ARCH}\$//" | sort -u
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
               elif [ -n "$owner" ]; then
                   cp_info "'$c' at $p is from package $owner (Linux Mint's apt wrapper is normal) - unmodified"
               else
                   cp_warn "Shadow copy of '$c' at $p (runs before /usr/bin/$c) - inspect and delete it"; SANE=0
               fi ;;
        esac
    done < <({ type -ap "$c" 2>/dev/null; for d in /usr/local/bin /usr/local/sbin; do [ -e "$d/$c" ] && echo "$d/$c"; done; } | sort -u)
done
for c in apt apt-get dpkg dpkg-query; do
    [ -x "/usr/bin/$c" ] || { cp_err "/usr/bin/$c is missing"; SANE=0; }
done
div="$(/usr/bin/dpkg-divert --list 2>/dev/null | grep -E '/(apt|apt-get|apt-mark|apt-cache|dpkg|dpkg-query|sudo) ')"
[ -n "$div" ] && { cp_warn "dpkg diversions on package tools:"; echo "$div" | sed 's/^/        /'; SANE=0; }
alias_hits="$(grep -nsHE '^[[:space:]]*(alias[[:space:]]+(apt|apt-get|dpkg|dpkg-query|sudo)=|(function[[:space:]]+)?(apt|apt-get|dpkg|dpkg-query|sudo)[[:space:]]*\(\))' \
    /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh /etc/environment /root/.bashrc /root/.bash_aliases /root/.profile \
    /home/*/.bashrc /home/*/.bash_aliases /home/*/.profile /home/*/.zshrc 2>/dev/null)"
[ -n "$alias_hits" ] && { cp_warn "Aliases/functions overriding apt/dpkg/sudo (delete these lines):"; echo "$alias_hits" | sed 's/^/        /'; SANE=0; }
for f in /etc/apt/apt.conf /etc/apt/apt.conf.d/* /etc/apt/preferences /etc/apt/preferences.d/*; do
    [ -f "$f" ] || continue
    $DPKGQ -S "$f" >/dev/null 2>&1 && continue
    # written by a package's postinst through ucf and unchanged since (50unattended-upgrades, 20auto-upgrades ...)
    uh="$(awk -v f="$f" '$2 == f {print $1; exit}' /var/lib/ucf/hashfile 2>/dev/null)"
    [ -n "$uh" ] && [ "$uh" = "$(md5sum "$f" | cut -d' ' -f1)" ] && continue
    # Linux Mint copies this pin file from mintsystem at install
    [ "$f" = /etc/apt/preferences.d/official-package-repositories.pref ] && cmp -s "$f" /usr/share/linuxmint/mintsystem/apt/official-package-repositories.pref && continue
    if grep -qiE 'Invoke|Pre-Install-Pkgs|Pin-Priority|AllowUnauthenticated|AllowInsecure|Trusted' "$f" 2>/dev/null; then
        cp_warn "APT config not owned by any package: $f"; grep -nviE '^[[:space:]]*(//|#|$)' "$f" | head -8 | sed 's/^/        /'; SANE=0
    fi
done
held="$($APTMARK showhold 2>/dev/null)"
[ -n "$held" ] && { cp_warn "Packages on HOLD (apt refuses to remove/upgrade them; this script unholds the ones you remove):"; echo "$held" | sed 's/^/        /'; }
aud="$($DPKG --audit 2>/dev/null)"
[ -n "$aud" ] && { cp_warn "dpkg --audit reports broken/half-installed packages (fix: sudo dpkg --configure -a; sudo apt-get -f install):"; echo "$aud" | head -15 | sed 's/^/        /'; }
# conffiles ("c") and docs/man/locale (stripped on minimized images) are ignored
ver="$($DPKG --verify dpkg apt 2>/dev/null | awk '$2 != "c" && $NF !~ /^\/usr\/share\/(doc|man|locale|info|lintian)\//')"
[ -n "$ver" ] && { cp_warn "dpkg/apt files differ from their package (tampered?):"; echo "$ver" | sed 's/^/        /'; SANE=0; }
[ "$SANE" = 1 ] && cp_ok "apt/dpkg binaries, diversions, aliases and APT hooks look normal"

# ============================================================ [1] discovery ==
cp_hdr "[1] Scanning for unauthorized packages (dpkg-query, whole package names)"
snapshot
scan_catalog
if [ ${#FAM_LABEL[@]} -eq 0 ]; then
    cp_ok "No catalog packages installed"
else
    for i in "${!FAM_LABEL[@]}"; do
        printf "  [%-7s] %s:\n" "${FAM_CAT[$i]}" "${FAM_LABEL[$i]}"
        for p in ${FAM_PKGS[$i]}; do echo "              $p$(print_held_flag "$p")"; done
    done
fi

# Programs that did NOT come from dpkg (dpkg/apt can't see or remove these)
echo
cp_info "Software installed outside dpkg (remove by hand if unauthorized):"
if command -v snap >/dev/null 2>&1; then
    snaps="$(snap list 2>/dev/null | awk 'NR>1 && $1 !~ /^(core[0-9]*|snapd|bare|gtk-common-themes|gnome-[0-9-]+|snapd-desktop-integration|firmware-updater|snap-store|mesa-.*|gtk2-common-themes)$/ {print $1}')"
    [ -n "$snaps" ] && echo "      snap (sudo snap remove <name>): $(echo $snaps)"
fi
if command -v flatpak >/dev/null 2>&1; then
    fp="$(flatpak list --app --columns=application 2>/dev/null)"
    [ -n "$fp" ] && echo "      flatpak (sudo flatpak uninstall <id>): $(echo $fp)"
fi
for d in /usr/local/bin /usr/local/sbin /usr/local/games; do
    l="$(find "$d" -maxdepth 1 \( -type f -o -type l \) 2>/dev/null | sort)"
    [ -n "$l" ] && echo "      $d: $(echo $l | sed "s#$d/##g")"
done
l="$(find /opt -mindepth 1 -maxdepth 1 2>/dev/null)"
[ -n "$l" ] && echo "      /opt: $(echo $l)"
for t in john hydra nmap ncat nc netcat wireshark tshark ophcrack hashcat aircrack-ng nikto sqlmap medusa ettercap msfconsole zenmap minetest luanti; do
    p="$(command -v "$t" 2>/dev/null)" || continue
    r="$(readlink -f "$p")"
    owned=0
    # dpkg records some files under /bin or /sbin (usr-merge): try every spelling
    for q in "$p" "$r" "${r/#\/usr\/bin\//\/bin\/}" "${r/#\/usr\/sbin\//\/sbin\/}"; do
        $DPKGQ -S "$q" >/dev/null 2>&1 && { owned=1; break; }
    done
    [ "$owned" = 1 ] || cp_warn "'$t' at $r is not from any package (installed by hand?)"
done

# ============================================================ [2] removal ==
if [ "$SCAN_ONLY" = 1 ]; then
    echo
    cp_info "Scan-only mode (--scan or no terminal): nothing removed."
else
    cp_hdr "[2] Build the removal list"
    echo "  Answer per family: y = remove all listed, n = keep all, e = ask for each package."
    echo "  Services marked SERVICE: keep anything the README lists as a critical service!"
    for i in "${!FAM_LABEL[@]}"; do
        echo
        printf "  [%s] %s: %s\n" "${FAM_CAT[$i]}" "${FAM_LABEL[$i]}" "${FAM_PKGS[$i]}"
        [ -n "${FAM_NOTE[$i]}" ] && echo "      note: ${FAM_NOTE[$i]}"
        a="$(ask3 "Remove?" "${FAM_DEF[$i]}")"
        case "$a" in
            y) for p in ${FAM_PKGS[$i]}; do add_target "$p"; done ;;
            e) for p in ${FAM_PKGS[$i]}; do cp_ask "Remove $p?" "${FAM_DEF[$i]}" && add_target "$p"; done ;;
        esac
    done

    echo
    echo "  Add any other packages to remove. Names or globs (e.g. 'zenmap', 'freeciv*'), space separated."
    echo "  '?word' lists installed packages whose name contains word. Empty line = done."
    while true; do
        read -r -p "  + " line
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
        echo "  Your list (${#TARGETS[@]}): ${TARGETS[*]}"
        mapfile -t SIM < <(simulate purge --allow-change-held-packages "${TARGETS[@]}")
        if [ -s "$TMPD/simerr" ] && grep -q '^E:' "$TMPD/simerr"; then
            cp_err "apt-get refused the simulated removal:"; sed 's/^/        /' "$TMPD/simerr"
        fi
        EXTRA=()
        for s in "${SIM[@]}"; do [ -z "${TARGET_SET[$(base "$s")]:-}" ] && EXTRA+=("$s"); done
        if [ ${#EXTRA[@]} -gt 0 ]; then
            cp_warn "apt would ALSO remove ${#EXTRA[@]} package(s) that depend on your list:"
            echo "${EXTRA[@]}" | fold -s -w 90 | sed 's/^/        /'
            [ ${#EXTRA[@]} -gt 15 ] && cp_warn "That is a lot - check nothing the README needs (desktop, critical services) is in there."
        else
            cp_ok "Nothing else would be removed."
        fi
        if cp_ask "Purge these ${#SIM[@]} package(s)?" n; then
            protect_metapackages "${SIM[@]}"
            for p in "${TARGETS[@]}"; do
                case "$(pkg_state "$p")" in h*) $APTMARK unhold "$(base "$p")" >/dev/null 2>&1 && cp_info "Unheld $p";; esac
            done
            if ! $APTGET purge -y --allow-change-held-packages "${APT_OPTS[@]}" "${TARGETS[@]}"; then
                cp_warn "apt-get purge failed - repairing dpkg state and retrying once"
                $DPKG --configure -a
                $APTGET -f install -y "${APT_OPTS[@]}"
                $APTGET purge -y --allow-change-held-packages "${APT_OPTS[@]}" "${TARGETS[@]}"
            fi

            cp_hdr "Verify with dpkg-query (not apt)"
            LEFT=()
            for p in "${TARGETS[@]}" "${EXTRA[@]}"; do
                st="$(pkg_state "$p")"
                case "$st" in
                    "")  cp_ok "$p: gone" ;;
                    rc)  cp_info "$p: removed, config files left (purged below)" ;;
                    *)   cp_err "$p: STILL INSTALLED (dpkg state '$st')"; LEFT+=("$p") ;;
                esac
            done
            for p in "${LEFT[@]}"; do
                if cp_ask "Try 'dpkg --purge $p' directly?" y; then
                    $DPKG --purge "$p" || cp_err "dpkg refused (the error above names what depends on it - remove that too, or leave $p)"
                fi
            done
        fi
    fi

    # Autoremove: dependencies nothing needs any more (libwireshark*, samba deps, ...)
    cp_hdr "apt-get autoremove --purge (dependencies nothing needs any more)"
    mapfile -t AUTO < <(simulate autoremove --purge)
    if [ ${#AUTO[@]} -eq 0 ]; then
        cp_ok "Nothing to autoremove"
    else
        echo "  Would remove ${#AUTO[@]}:"; echo "${AUTO[@]}" | fold -s -w 90 | sed 's/^/        /'
        def=y; [ ${#AUTO[@]} -gt 40 ] && { def=n; cp_warn "Large list - make sure the desktop/critical services are not in it."; }
        cp_ask "Run autoremove?" "$def" && $APTGET autoremove --purge -y "${APT_OPTS[@]}"
    fi

    # Leftover configs of removed packages ("rc" in dpkg -l)
    mapfile -t RC < <($DPKGQ -W -f='${db:Status-Abbrev}\t${binary:Package}\n' 2>/dev/null | awk -F'\t' '$1 ~ /^rc/ {print $2}')
    if [ ${#RC[@]} -gt 0 ]; then
        echo; cp_info "Removed packages with config files left (rc): ${RC[*]}" | fold -s -w 100
        cp_ask "Purge their config files (dpkg --purge)?" y && $DPKG --purge "${RC[@]}" >/dev/null && cp_ok "Purged"
    fi

    # Re-scan: the proof
    cp_hdr "Re-scan after removal"
    snapshot
    scan_catalog
    if [ ${#FAM_LABEL[@]} -eq 0 ]; then
        cp_ok "No catalog packages installed any more"
    else
        for i in "${!FAM_LABEL[@]}"; do
            for p in ${FAM_PKGS[$i]}; do
                if [ -n "${TARGET_SET[$(base "$p")]:-}" ]; then cp_err "$p (${FAM_LABEL[$i]}) - you chose to remove it but it is STILL INSTALLED"
                else echo "  [kept] $p (${FAM_LABEL[$i]})"; fi
            done
        done
    fi
fi

# ============================================================ [3] services ==
cp_hdr "[3] Scanning for unauthorized services (exact unit names)"
SUSPICIOUS_UNITS=(
    xinetd inetd openbsd-inetd inetutils-inetd postfix sendmail exim4 nfs-server nfs-kernel-server rpcbind
    smbd nmbd samba samba-ad-dc winbind postgresql vsftpd pure-ftpd proftpd apache2 nginx lighttpd
    mysql mariadb snmpd dovecot named bind9 dnsmasq unbound avahi-daemon cups cups-browsed xrdp x11vnc
    vncserver inspircd ngircd squid telnet tftpd-hpa atftpd redis-server memcached mongod tomcat9 tor
)
systemctl list-unit-files --no-legend --type=service,socket 2>/dev/null | awk '{print $1}' > "$TMPD/units"
for f in $(grep -E '^php[0-9.]*-fpm\.service$' "$TMPD/units" | sed 's/\.service$//'); do SUSPICIOUS_UNITS+=("$f"); done
any=0
for u in "${SUSPICIOUS_UNITS[@]}"; do
    for unit in "$u.service" "$u.socket"; do
        grep -qxF "$unit" "$TMPD/units" || continue
        if systemctl is-active --quiet "$unit" 2>/dev/null; then
            echo "  [ALERT] $unit is ACTIVE"; any=1
        elif systemctl is-enabled --quiet "$unit" 2>/dev/null; then
            echo "  [WARNING] $unit is ENABLED but not running"; any=1
        fi
    done
done
[ "$any" = 0 ] && cp_ok "No suspicious services active or enabled"
echo "  (If the README needs it: keep it. Otherwise: sudo systemctl disable --now <unit>, or remove its package.)"
echo ""

# 4. Mounted Network Share Scan
echo "[4] Scanning for mounted network shares..."

MOUNTED_SHARES=$(mount | grep -E "type (nfs|cifs|smbfs)" 2>/dev/null)
SHARE_COUNT=$(echo "$MOUNTED_SHARES" | grep -c '^' 2>/dev/null)

if [ -z "$MOUNTED_SHARES" ] || [ "$SHARE_COUNT" -eq 0 ]; then
    echo "  No mounted network shares found"
else
    echo "  Found ${SHARE_COUNT} mounted network share(s):"
    echo "$MOUNTED_SHARES" | while read -r share; do
        echo "    $share"
    done
fi
echo ""

# 5. Unauthorized File Scan
echo "[5] Scanning for unauthorized files..."
# (a) places people keep files: every media/archive/script file is listed
# (b) system dirs: only media/archive files that NO package installed (a planted file hidden in
#     /usr/share/... used to be pruned; listing every file there drowned the real ones in thousands of icons)
MEDIA_RE='.*\.(mp3|mp4|m4a|m4v|avi|mkv|mov|wmv|flv|webm|wav|ogg|oga|ogv|flac|aac|wma|opus|mpg|mpeg|3gp|zip|rar|7z|tar|tgz|gz|bz2|xz|iso|torrent|jpg|jpeg|png|gif|bmp|webp|heic|py|sh|exe|txt|csv|doc|docx|xls|xlsx|pdf)$'
USER_DIRS="/home /root /srv /var/www /opt /tmp /var/tmp /media /mnt /usr/local"
REPO_ROOT="$CP_ROOT"; [ -d "$CP_ROOT/../tools/verify" ] && REPO_ROOT="$(cd "$CP_ROOT/.." && pwd)"   # skip our own repo
find $USER_DIRS -xdev \( -path /root/cp-backups -o -path /root/baseline -o -path "$REPO_ROOT" \) -prune -o \
    -type f -regextype posix-extended -iregex "$MEDIA_RE" -print 2>/dev/null | sort > "$TMPD/userfiles"
cat /var/lib/dpkg/info/*.list 2>/dev/null | sort -u > "$TMPD/owned"
find /usr /var /etc /boot /lib /bin /sbin -xdev \( -path /var/lib/dpkg -o -path /var/lib/apt -o -path /var/cache -o -path /var/log -o -path /var/lib/swcatalog -o -path /var/lib/app-info -o -path /var/lib/flatpak -o -path /var/lib/snapd -o -path /var/lib/docker -o -path /var/tmp -o -path /var/www -o -path /usr/local -o -path /var/lib/mysql -o -path /var/lib/postgresql \) -prune -o \
    -type f -regextype posix-extended -iregex '.*\.(mp3|mp4|m4a|avi|mkv|mov|wmv|flv|webm|wav|ogg|flac|aac|wma|opus|mpg|mpeg|zip|rar|7z|torrent|iso|exe)$' -print 2>/dev/null \
    | sort | comm -23 - "$TMPD/owned" | while IFS= read -r f; do
        # usr-merge: dpkg may record /lib/x or /bin/x for /usr/lib/x, /usr/bin/x
        alt="$(echo "$f" | sed -E 's#^/usr/(lib|bin|sbin)/#/\1/#')"
        grep -qxF "$alt" "$TMPD/owned" || echo "$f"
    done > "$TMPD/sysfiles"
FILE_COUNT=$(( $(wc -l < "$TMPD/userfiles") + $(wc -l < "$TMPD/sysfiles") ))
if [ "$FILE_COUNT" -eq 0 ]; then
    echo "  No unauthorized files found"
else
    MEDIA_ONLY='\.(mp3|mp4|m4a|m4v|avi|mkv|mov|wmv|flv|webm|wav|ogg|oga|ogv|flac|aac|wma|opus|mpg|mpeg|3gp|torrent)$'
    echo "  Media files in user/data folders (usually scored - check the README before deleting):"
    grep -iE "$MEDIA_ONLY" "$TMPD/userfiles" | sed 's/^/    /'
    echo "  Media/archives in system folders that NO package installed (planted):"
    sed 's/^/    /' "$TMPD/sysfiles"
    echo "  Other files in user/data folders (archives, scripts, documents, images - review; passwords.txt-style files are scored):"
    # hidden config dirs (~/.config, ~/.local ...) are skipped here - media in them is still listed above
    grep -viE "$MEDIA_ONLY" "$TMPD/userfiles" | grep -v '/\.' > "$TMPD/other"
    sed 's/^/    /' "$TMPD/other" | head -150
    n_other=$(wc -l < "$TMPD/other"); [ "$n_other" -gt 150 ] && echo "    ... $((n_other - 150)) more (full list: find $USER_DIRS -type f | less)"
fi
echo ""

# 6. SUID/SGID/Sticky Bit Scan
echo "[6] Scanning for SUID/SGID/Sticky bit files..."

# Find SUID files (chmod 4000)
SUID_FILES=$(find / -type f -perm -4000 2>/dev/null)
SUID_COUNT=$(echo "$SUID_FILES" | grep -c '^' 2>/dev/null)

# Find SGID files (chmod 2000)
SGID_FILES=$(find / -type f -perm -2000 2>/dev/null)
SGID_COUNT=$(echo "$SGID_FILES" | grep -c '^' 2>/dev/null)

# Find Sticky bit files (chmod 1000)
STICKY_FILES=$(find / -type f -perm -1000 2>/dev/null)
STICKY_COUNT=$(echo "$STICKY_FILES" | grep -c '^' 2>/dev/null)

# SUID Results
if [ -z "$SUID_FILES" ] || [ "$SUID_COUNT" -eq 0 ]; then
    echo "  No SUID files found"
else
    echo "  Found ${SUID_COUNT} SUID file(s):"
    echo "$SUID_FILES" | while read -r file; do
        ls -lh "$file" 2>/dev/null | awk '{print "    " $1 " " $3 ":" $4 " " $9}'
    done
fi

# SGID Results
if [ -z "$SGID_FILES" ] || [ "$SGID_COUNT" -eq 0 ]; then
    echo "  No SGID files found"
else
    echo "  Found ${SGID_COUNT} SGID file(s):"
    echo "$SGID_FILES" | while read -r file; do
        ls -lh "$file" 2>/dev/null | awk '{print "    " $1 " " $3 ":" $4 " " $9}'
    done
fi

# Sticky Bit Results
if [ -z "$STICKY_FILES" ] || [ "$STICKY_COUNT" -eq 0 ]; then
    echo "  No Sticky bit files found"
else
    echo "  Found ${STICKY_COUNT} Sticky bit file(s):"
    echo "$STICKY_FILES" | while read -r file; do
        ls -lh "$file" 2>/dev/null | awk '{print "    " $1 " " $3 ":" $4 " " $9}'
    done
fi

echo ""
echo "=== Scan Complete ==="
