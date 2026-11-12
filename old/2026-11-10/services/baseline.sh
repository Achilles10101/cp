#!/bin/bash
# baseline.sh - SERVICE BASELINING (research doc section B). DETECTION ONLY: changes nothing.
#
#   "To find evil, you must know good." Compares every critical service on the image with a
#   known-good default and writes a report per service. Run this BEFORE any hardening script;
#   the service scripts refuse to run until the service has a baseline (B-4).
#
# Usage:
#   sudo bash services/baseline.sh                 # every detected service (+ "system")
#   sudo bash services/baseline.sh ssh apache2     # only these
#   sudo bash services/baseline.sh --meld ssh      # also open pristine-vs-live diffs in Meld
#   sudo bash services/baseline.sh --no-download   # never apt-get download pristine packages
#   sudo bash services/baseline.sh --capture DIR   # B10: run on a CLEAN VM to build a baseline pack
#   sudo bash services/baseline.sh --list          # show service names and whether detected
#
# Output (per service): /root/baseline/<svc>/
#   report.txt   findings; lines starting with "!!" need a human decision
#   diff.patch   unified diffs pristine -> live for every changed config file
#   pairs.txt    "pristine|live" file pairs (for Meld)
#   before/      snapshot of the service's config taken the FIRST time it was baselined (B9)
#   runs/<ts>/   snapshots from later re-runs (the first "before" is never overwritten)
#
# Sources of "known good", in priority order:
#   1. baseline pack in this repo:   baseline/<os-id>/<svc>/{pristine/,stat.txt,accounts.txt,listen.txt}
#   2. pristine copies already on the image (ucf templates, php.ini-production, *.sample, ...)
#   3. apt-get download of the installed package version, extracted to /root/baseline/_pristine/

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../cp-common.sh
source "$SCRIPT_DIR/../cp-common.sh" 2>/dev/null || { echo "ERROR: cp-common.sh not found in competition/"; exit 1; }
cp_require_root

OSID="$(cp_os_id)"
PACK_DIR="$CP_ROOT/baseline/$OSID"
if [ ! -d "$PACK_DIR" ]; then
    # same distro + major version: linuxmint-21.1 / 21.2 use the linuxmint-21.3 pack (all are Ubuntu jammy)
    _c="$(ls -d "$CP_ROOT/baseline/${OSID%%.*}".* 2>/dev/null | tail -1)"
    [ -n "$_c" ] && PACK_DIR="$_c"
fi
PRISTINE_DEBS="$CP_BASELINE_DIR/_pristine"
DO_MELD=0; DO_DOWNLOAD=1; CAPTURE_DIR=""; LIST_ONLY=0
TARGETS=()

while [ $# -gt 0 ]; do
    case "$1" in
        --meld) DO_MELD=1 ;;
        --no-download) DO_DOWNLOAD=0 ;;
        --capture) CAPTURE_DIR="$2"; shift ;;
        --list) LIST_ONLY=1 ;;
        -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
        *) TARGETS+=("$1") ;;
    esac
    shift
done

# ------------------------------------------------------------ registry --
declare -A PKGS DIRS UNITS PORTS PROCS CONTENT EXTRA
SVC_ORDER=(ssh vsftpd apache2 nginx php mysql postgresql samba bind9 postfix dovecot openvpn squid wordpress system)

PKGS[ssh]="openssh-server openssh-sftp-server"
DIRS[ssh]="/etc/ssh /etc/pam.d/sshd /etc/default/ssh"
UNITS[ssh]="ssh.service ssh.socket sshd.service"
PORTS[ssh]="22"; PROCS[ssh]="sshd"
EXTRA[ssh]="/etc/ssh/sshd_config"

PKGS[vsftpd]="vsftpd"
DIRS[vsftpd]="/etc/vsftpd.conf /etc/vsftpd /etc/vsftpd.chroot_list /etc/vsftpd.userlist /etc/vsftpd.user_list /etc/ftpusers /etc/pam.d/vsftpd"
UNITS[vsftpd]="vsftpd.service"; PORTS[vsftpd]="21"; PROCS[vsftpd]="vsftpd"
CONTENT[vsftpd]="/srv/ftp"

PKGS[apache2]="apache2 apache2-bin apache2-data apache2-utils"
DIRS[apache2]="/etc/apache2"
UNITS[apache2]="apache2.service"; PORTS[apache2]="80 443"; PROCS[apache2]="apache2"
CONTENT[apache2]="/var/www"

PKGS[nginx]="nginx nginx-common nginx-core nginx-full nginx-light nginx-extras"
DIRS[nginx]="/etc/nginx"
UNITS[nginx]="nginx.service"; PORTS[nginx]="80 443"; PROCS[nginx]="nginx"
CONTENT[nginx]="/var/www /usr/share/nginx/html"

DIRS[php]="/etc/php"; PROCS[php]="php-fpm php-fpm8.1 php-fpm8.2 php-fpm8.3 php-fpm8.4"
DIRS[mysql]="/etc/mysql"; UNITS[mysql]="mysql.service mariadb.service"; PORTS[mysql]="3306 33060"; PROCS[mysql]="mysqld mariadbd"
DIRS[postgresql]="/etc/postgresql /etc/postgresql-common"; PORTS[postgresql]="5432"; PROCS[postgresql]="postgres"

PKGS[samba]="samba samba-common samba-common-bin"
DIRS[samba]="/etc/samba"
UNITS[samba]="smbd.service nmbd.service samba-ad-dc.service"; PORTS[samba]="137 138 139 445"; PROCS[samba]="smbd nmbd"
EXTRA[samba]="/etc/samba/smb.conf"

PKGS[bind9]="bind9 bind9-utils"
DIRS[bind9]="/etc/bind /etc/default/named /etc/default/bind9"
UNITS[bind9]="named.service bind9.service"; PORTS[bind9]="53 953"; PROCS[bind9]="named"

PKGS[postfix]="postfix"
DIRS[postfix]="/etc/postfix /etc/mailname /etc/aliases"
UNITS[postfix]="postfix.service postfix@-.service"; PORTS[postfix]="25 465 587"; PROCS[postfix]="master smtpd"
EXTRA[postfix]="/etc/postfix/main.cf"

DIRS[dovecot]="/etc/dovecot"; UNITS[dovecot]="dovecot.service"; PORTS[dovecot]="110 143 993 995 4190"; PROCS[dovecot]="dovecot"

PKGS[openvpn]="openvpn"
DIRS[openvpn]="/etc/openvpn /etc/default/openvpn"
UNITS[openvpn]="openvpn.service"; PORTS[openvpn]="1194"; PROCS[openvpn]="openvpn"

PKGS[squid]="squid squid-common"
DIRS[squid]="/etc/squid"; UNITS[squid]="squid.service"; PORTS[squid]="3128"; PROCS[squid]="squid"

# "system" = the non-service drop-in dirs named in B3 (sysctl.d, sudoers.d, lightdm, apt, pam ...)
PKGS[system]="libpam-modules libpam-modules-bin libpam-runtime sudo procps login passwd"
DIRS[system]="/etc/sysctl.conf /etc/sysctl.d /etc/sudoers /etc/sudoers.d /etc/sudo.conf /etc/lightdm /etc/gdm3 /etc/apt/apt.conf.d /etc/apt/sources.list /etc/apt/sources.list.d /etc/pam.d /etc/security /etc/profile.d /etc/ld.so.preload /etc/ld.so.conf.d /etc/cron.d /etc/crontab /etc/hosts /etc/bash.bashrc /etc/profile /etc/environment /etc/polkit-1"

# Dynamic package lists (versioned packages)
dyn_pkgs() {  # dyn_pkgs PATTERN... -> installed package names
    dpkg-query -W -f='${Package} ${Status}\n' "$@" 2>/dev/null | awk '/install ok installed/{print $1}' | tr '\n' ' '
}
PKGS[php]="$(dyn_pkgs 'php[0-9]*-common' 'php[0-9]*-fpm' 'php[0-9]*-cli' 'libapache2-mod-php[0-9]*' 'php-common')"
UNITS[php]="$(systemctl list-unit-files 'php*-fpm.service' 2>/dev/null | awk '/fpm\.service/{print $1}' | tr '\n' ' ')"
PKGS[mysql]="$(dyn_pkgs 'mysql-server*' 'mariadb-server*' 'mysql-common' 'mariadb-common')"
PKGS[postgresql]="$(dyn_pkgs 'postgresql-[0-9]*' 'postgresql-common')"
UNITS[postgresql]="postgresql.service $(systemctl list-units --all 'postgresql@*' 2>/dev/null | awk '/postgresql@/{print $1}' | tr '\n' ' ')"
PKGS[dovecot]="$(dyn_pkgs 'dovecot-*')"
UNITS[openvpn]+=" $(systemctl list-units --all 'openvpn*@*' 2>/dev/null | awk '/openvpn.*@/{print $1}' | tr '\n' ' ')"
EXTRA[php]="$(ls /etc/php/*/*/php.ini 2>/dev/null | tr '\n' ' ')"
EXTRA[postgresql]="$(ls /etc/postgresql/*/main/{pg_hba.conf,pg_ident.conf,postgresql.conf} 2>/dev/null | tr '\n' ' ')"

WP_CONFIGS="$(find /var/www /srv /usr/share/wordpress /etc/wordpress -maxdepth 5 -name wp-config.php 2>/dev/null | tr '\n' ' ')"
if [ -n "$WP_CONFIGS" ]; then
    DIRS[wordpress]="$WP_CONFIGS /etc/wordpress"
    CONTENT[wordpress]="$(for f in $WP_CONFIGS; do dirname "$f"; done | sort -u | tr '\n' ' ')"
    PKGS[wordpress]="$(dyn_pkgs wordpress)"
fi

detected() {
    local s="$1" p
    [ "$s" = "system" ] && return 0
    [ "$s" = "wordpress" ] && { [ -n "$WP_CONFIGS" ]; return; }
    for p in ${PKGS[$s]:-}; do cp_pkg_installed "$p" && return 0; done
    return 1
}

if [ "$LIST_ONLY" = 1 ]; then
    for s in "${SVC_ORDER[@]}"; do detected "$s" && echo "  $s  (detected)" || echo "  $s"; done
    exit 0
fi

# --------------------------------------------------------------- report --
REPORT=""; PATCH=""; PAIRS=""
r()    { echo "$*" >> "$REPORT"; }
rhdr() { echo "" >> "$REPORT"; echo "## $*" >> "$REPORT"; }
flag() { echo "!! $*" >> "$REPORT"; FLAGS=$((FLAGS + 1)); }

installed_pkgs() {  # installed subset of a service's package list
    local p out=""
    for p in ${PKGS[$1]:-}; do cp_pkg_installed "$p" && out+="$p "; done
    echo "$out"
}

existing_paths() { local p; for p in "$@"; do [ -e "$p" ] && echo "$p"; done; }

# dpkg-owned? Ubuntu 22.04 / Mint 21 record unit files etc. under /lib, /bin, /sbin while the same file is
# reached as /usr/lib/... (usr-merge) - try every spelling before calling a file "unowned".
owned() {
    local f="$1" a
    dpkg-query -S "$f" >/dev/null 2>&1 && return 0
    case "$f" in
        /usr/lib/*|/usr/bin/*|/usr/sbin/*) a="${f#/usr}" ;;
        /lib/*|/bin/*|/sbin/*) a="/usr$f" ;;
        *) return 1 ;;
    esac
    dpkg-query -S "$a" >/dev/null 2>&1
}
# identical to the clean-VM pack copy? (then B2 already covers it and it is not a planted file)
in_pack_same() { local c="$PACK_DIR/$1/pristine$2"; [ -f "$c" ] && cmp -s "$c" "$2"; }
# live mode/owner equal to the clean-VM capture (pack stat.txt: "mode user:group path")?
pack_stat_same() {
    local svc="$1" f="${2%/}" st="$PACK_DIR/$1/stat.txt"
    [ -f "$st" ] || return 1
    awk -v p="$f" -v live="$(stat -c '%a %U:%G' "$f" 2>/dev/null)" '$3 == p { found=1; if ($1" "$2 == live) ok=1 } END { exit !(found && ok) }' "$st"
}

# --------------------------------------------------------- pristine lookup --
ucf_hash() { awk -v f="$1" '$2 == f {print $1; exit}' /var/lib/ucf/hashfile 2>/dev/null; }

fetch_deb() {  # extract a pristine copy of PKG (installed version if possible) -> dir path
    local pkg="$1" ver dest="$PRISTINE_DEBS/$1" deb
    if [ -d "$dest/root" ]; then echo "$dest"; return 0; fi
    [ "$DO_DOWNLOAD" = 1 ] || return 1
    mkdir -p "$dest" && ver="$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null)"
    ( cd "$dest" && { timeout 60 apt-get download -qq "$pkg=$ver" >/dev/null 2>&1 || timeout 60 apt-get download -qq "$pkg" >/dev/null 2>&1; } )
    deb="$(ls "$dest"/*.deb 2>/dev/null | head -1)"
    [ -n "$deb" ] || return 1
    dpkg-deb -x "$deb" "$dest/root" 2>/dev/null && dpkg-deb -c "$deb" > "$dest/listing.txt" 2>/dev/null
    echo "$dest"
}

# pristine_for FILE SVC PKG -> path of a known-good copy (empty if none)
pristine_for() {
    local f="$1" svc="$2" pkg="$3" c v sapi d
    # 1. baseline pack
    c="$PACK_DIR/$svc/pristine$f"; [ -f "$c" ] && { echo "$c"; return; }
    # 2. on-image pristine sources
    case "$f" in
        /etc/ssh/sshd_config) c=/usr/share/openssh/sshd_config ;;
        /etc/samba/smb.conf) c=/usr/share/samba/smb.conf ;;
        /etc/php/*/*/php.ini) v="$(echo "$f" | cut -d/ -f4)"; sapi="$(echo "$f" | cut -d/ -f5)"
            c="/usr/lib/php/$v/php.ini-production"; [ "$sapi" = cli ] && [ -f "/usr/lib/php/$v/php.ini-production.cli" ] && c="/usr/lib/php/$v/php.ini-production.cli" ;;
        /etc/postgresql/*/main/pg_hba.conf|/etc/postgresql/*/main/pg_ident.conf|/etc/postgresql/*/main/postgresql.conf)
            v="$(echo "$f" | cut -d/ -f4)"; c="/usr/share/postgresql/$v/$(basename "$f").sample" ;;
        /etc/postfix/main.cf) c=/usr/share/postfix/main.cf.debian ;;
        /etc/dovecot/*) c="/usr/share/dovecot/${f#/etc/dovecot/}" ;;
        *) c="" ;;
    esac
    [ -n "$c" ] && [ -f "$c" ] && { echo "$c"; return; }
    c="/var/lib/ucf/cache/$(echo "$f" | sed 's#/#:#g')"; [ -f "$c" ] && { echo "$c"; return; }
    # 3. downloaded package
    if [ -n "$pkg" ] && d="$(fetch_deb "$pkg")" && [ -f "$d/root$f" ]; then echo "$d/root$f"; return; fi
}

record_diff() {  # record_diff PRISTINE LIVE
    local p="$1" l="$2" n
    n="$(diff -u "$p" "$l" 2>/dev/null | tee -a "$PATCH" | grep -c '^[+-][^+-]')"
    echo "$p|$l" >> "$PAIRS"
    r "     diff vs $p : $n changed line(s) (see diff.patch)"
}

# ================================================================ B1 --
b1_integrity() {
    local svc="$1" pkgs out
    rhdr "B1 package integrity (dpkg --verify) - binaries, PAM modules, shipped files"
    pkgs="$(installed_pkgs "$svc")"
    [ -n "${pkgs// /}" ] || { r "   (no package for this service)"; return; }
    r "   packages: $pkgs"
    # shellcheck disable=SC2086
    out="$(dpkg --verify $pkgs 2>/dev/null)"
    if [ -z "$out" ]; then r "   all package files match their md5sums"; return; fi
    while IFS= read -r line; do
        if [[ "$line" =~ [[:space:]]c[[:space:]] ]]; then r "   conffile changed: $line"
        elif [[ "$line" =~ missing ]]; then
            [[ "$line" =~ /usr/share/(doc|man|locale|info|lintian)/ ]] && continue   # often excluded by dpkg path-exclude
            flag "B1 package file missing: $line"
        else flag "B1 NON-CONFIG package file modified (possible trojan): $line"; fi
    done <<< "$out"
}

# ================================================================ B2 --
b2_config() {
    local svc="$1" pkg f md5 cur p seen=" "
    rhdr "B2 config content vs pristine default"
    for pkg in $(installed_pkgs "$svc"); do
        while read -r f md5 obs; do
            [ -n "$f" ] || continue
            case "$f" in /etc/*) ;; *) continue ;; esac
            seen+="$f "
            if [ ! -e "$f" ]; then flag "B2 conffile deleted: $f ($pkg)"; continue; fi
            cur="$(md5sum "$f" 2>/dev/null | cut -d' ' -f1)"
            [ "$obs" = "obsolete" ] && continue
            if [ "$cur" != "$md5" ]; then
                flag "B2 conffile modified since install: $f ($pkg)"
                p="$(pristine_for "$f" "$svc" "$pkg")"
                if [ -n "$p" ]; then record_diff "$p" "$f"; else r "     (no pristine copy found - review by hand)"; fi
            fi
        done < <(dpkg-query -W -f='${Conffiles}\n' "$pkg" 2>/dev/null)
    done
    # ucf-managed / generated files that dpkg does not track as conffiles
    for f in ${EXTRA[$svc]:-}; do
        [ -f "$f" ] || continue
        [[ "$seen" == *" $f "* ]] && continue
        md5="$(ucf_hash "$f")"; cur="$(md5sum "$f" | cut -d' ' -f1)"
        p="$(pristine_for "$f" "$svc" "$(installed_pkgs "$svc" | awk '{print $1}')")"
        if [ -n "$md5" ] && [ "$md5" = "$cur" ]; then r "   unchanged since install (ucf): $f"; continue; fi
        if [ -n "$p" ]; then
            if cmp -s "$p" "$f"; then r "   identical to pristine: $f"
            else flag "B2 differs from pristine default: $f"; record_diff "$p" "$f"; fi
        else
            r "   no pristine copy available for $f - review by hand"
        fi
    done
    # postfix: show only non-default parameters (postconf -n vs -d)
    if [ "$svc" = postfix ] && command -v postconf >/dev/null; then
        r "   postconf non-default parameters:"
        comm -13 <(postconf -d 2>/dev/null | sort) <(postconf -n 2>/dev/null | sort) | sed 's/^/     /' >> "$REPORT"
    fi
    # Anything else in the pack's pristine tree that differs
    if [ -d "$PACK_DIR/$svc/pristine" ]; then
        while IFS= read -r p; do
            f="${p#"$PACK_DIR/$svc/pristine"}"
            [[ "$seen" == *" $f "* ]] && continue
            if [ ! -e "$f" ]; then flag "B2 file from clean-VM pack missing on image: $f"
            elif ! cmp -s "$p" "$f"; then flag "B2 differs from clean-VM pack: $f"; record_diff "$p" "$f"; fi
        done < <(find "$PACK_DIR/$svc/pristine" -type f 2>/dev/null)
    fi
}

# ================================================================ B3 --
b3_unowned() {
    local svc="$1" f tgt
    rhdr "B3 files in config dirs that NO package owns (planted drop-ins?)"
    local list paths; list="$(mktemp)"
    # shellcheck disable=SC2086
    paths="$(existing_paths ${DIRS[$svc]})"; [ -n "$paths" ] || { r "   (no config paths)"; rm -f "$list"; return; }
    # shellcheck disable=SC2086
    find $paths -xdev \( -type f -o -type l \) 2>/dev/null \
        | grep -vE '\.bak\.[0-9_]+$|/ssh_host_[a-z0-9]+_key(\.pub)?$|\.dpkg-(dist|old|bak)$' > "$list"
    while IFS= read -r f; do
        owned "$f" && continue
        if in_pack_same "$svc" "$f"; then r "   generated at install, identical to clean VM: $f"; continue; fi
        if [ -L "$f" ]; then
            tgt="$(readlink "$f")"
            # a2enmod/a2ensite/nginx style symlinks: fine if they point at the matching *-available file
            if [[ "$f" =~ -enabled/ ]] && [[ "$tgt" =~ -available/$(basename "$f")$ ]]; then continue; fi
            # phpenmod style: conf.d/20-zip.ini -> mods-available/zip.ini
            if [[ "$f" =~ /conf\.d/[0-9]+-(.+\.ini)$ ]] && [[ "$tgt" =~ mods-available/${BASH_REMATCH[1]}$ ]]; then continue; fi
            [[ "$f" == /etc/mysql/my.cnf ]] && continue
            # nginx module symlinks: modules-enabled/50-mod-x.conf -> /usr/share/nginx/modules-available/mod-x.conf
            [[ "$f" == /etc/nginx/modules-enabled/* && "$tgt" == /usr/share/nginx/modules-available/* && -e "$tgt" ]] && continue
            [[ "$f" == /etc/postfix/makedefs.out && "$tgt" == /usr/share/postfix/makedefs.out ]] && continue
            [[ "$tgt" == */ssl-cert-snakeoil.* ]] && continue   # created by postinst scripts
            flag "B3 unowned symlink: $f -> $tgt"
        else
            case "$f" in
                /etc/php/*/mods-available/*.ini)
                    # generated by phpenmod from /usr/share/php<ver>-<pkg>/<pkg>/<ext>.ini
                    v="$(echo "$f" | cut -d/ -f4)"
                    tpl="$(ls /usr/share/php"$v"-*/*/"$(basename "$f")" /usr/share/php"$v"-*/"$(basename "$f")" 2>/dev/null | head -1)"
                    if [ -n "$tpl" ] && cmp -s "$tpl" "$f"; then continue
                    elif [ -n "$tpl" ]; then flag "B2 differs from php module template: $f"; record_diff "$tpl" "$f"
                    else flag "B3 not owned by any package: $(stat -c '%A %U:%G %y' "$f" | cut -c1-45) $f"; fi ;;
                /etc/dovecot/*)
                    tpl="/usr/share/dovecot/${f#/etc/dovecot/}"
                    if [ -f "$tpl" ] && cmp -s "$tpl" "$f"; then continue
                    elif [ -f "$tpl" ]; then flag "B2 differs from dovecot template: $f"; record_diff "$tpl" "$f"
                    else flag "B3 not owned by any package: $(stat -c '%A %U:%G %y' "$f" | cut -c1-45) $f"; fi ;;
                /etc/bind/rndc.key|/etc/mysql/debian.cnf|/etc/ssh/sshd_config|/etc/samba/smb.conf|/etc/postfix/main.cf|/etc/php/*/*/php.ini|/etc/postgresql/*|/etc/sudoers.d/README|/etc/ld.so.conf.d/*|/etc/apt/sources.list.d/*.sources|/etc/security/opasswd|\
                /etc/apt/apt.conf.d/20auto-upgrades|/etc/apt/apt.conf.d/50unattended-upgrades|/etc/apt/apt.conf.d/02autoremove-postgresql|/etc/apt/sources.list|/etc/apt/sources.list.d/official-package-repositories.list|\
                /etc/pam.d/common-auth|/etc/pam.d/common-account|/etc/pam.d/common-password|/etc/pam.d/common-session|/etc/pam.d/common-session-noninteractive|\
                /etc/hosts|/etc/profile|/etc/environment|/etc/postgresql-common/createcluster.conf|/etc/postgresql-common/root.crt|\
                /etc/postfix/master.cf|/etc/postfix/main.cf.proto|/etc/postfix/master.cf.proto|/etc/postfix/dynamicmaps.cf|/etc/aliases)
                    if [ -f "$PACK_DIR/$svc/pristine$f" ]; then
                        r "   generated at install, DIFFERS from clean VM (flagged in B2): $f"
                    else
                        r "   generated at install (expected - review content by hand / with the pack): $f"
                    fi ;;
                *) flag "B3 not owned by any package: $(stat -c '%A %U:%G %y' "$f" | cut -c1-45) $f" ;;
            esac
        fi
    done < "$list"
    rm -f "$list"
}

# ================================================================ B4 --
b4_perms() {
    local svc="$1" paths f exp live
    rhdr "B4 permissions / ownership vs default"
    # shellcheck disable=SC2086
    paths="$(existing_paths ${DIRS[$svc]} ${CONTENT[$svc]:-})"
    [ -n "$paths" ] || { r "   (no paths)"; return; }
    # shellcheck disable=SC2086
    while IFS= read -r f; do flag "B4 world-writable: $(stat -c '%a %U:%G' "$f") $f"; done \
        < <(find $paths -xdev -perm -0002 ! -type l ! -path '/tmp/*' 2>/dev/null | head -100)
    # shellcheck disable=SC2086
    while IFS= read -r f; do flag "B4 SUID/SGID inside service path: $(stat -c '%a %U:%G' "$f") $f"; done \
        < <(find $paths -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null)
    # config dirs owned by unexpected users (content dirs may legitimately be www-data)
    # shellcheck disable=SC2086
    while IFS= read -r f; do
        case "$svc:$(stat -c %U "$f")" in
            postgresql:postgres|bind9:bind|mysql:mysql|squid:proxy|dovecot:dovecot) continue ;;
        esac
        flag "B4 config file not owned by root: $(stat -c '%a %U:%G' "$f") $f"
    done < <(p2="$(existing_paths ${DIRS[$svc]})"; [ -n "$p2" ] && find $p2 -xdev ! -user root ! -type l 2>/dev/null | head -50)
    # compare with the package's own listing (mode + owner), when a pristine .deb was fetched
    local pkg d B4SEEN="|"
    for pkg in $(installed_pkgs "$svc"); do
        d="$(fetch_deb "$pkg")" || continue; [ -f "$d/listing.txt" ] || continue
        while read -r mode owner _ _ _ path; do
            f="${path#.}"; [ -e "$f" ] && [ ! -L "$f" ] || continue
            case "$f" in /etc/*|/srv/*|/var/www/*) ;; *) continue ;; esac
            [[ "$B4SEEN" == *"|$f|"* ]] && continue; B4SEEN+="|$f|"
            exp="$mode ${owner}"; live="$(stat -c '%A %U/%G' "$f")"
            case "$f:$live" in "/etc/bind/:drwxr-sr-x root/bind") continue ;; esac   # set by bind9 postinst
            pack_stat_same "$svc" "$f" && continue                                   # same as the clean VM
            case "$f:$live" in   # changed by the package's own postinst (no pack needed)
                "/etc/sudoers:-r--r----- root/root"|/etc/bind/named.conf*:"-rw-r--r-- root/bind"|"/etc/postgresql/:drwxr-xr-x postgres/postgres"|"/etc/dovecot/private/:drwx------ root/root") continue ;;
            esac
            [ "$exp" = "$live" ] || flag "B4 differs from package default: $f  default[$exp] live[$live]"
        done < <(awk '$1 !~ /^l/' "$d/listing.txt")
    done
    # compare with a clean-VM capture (baseline pack stat.txt: "mode user:group path")
    if [ -f "$PACK_DIR/$svc/stat.txt" ]; then
        while read -r mode own path; do
            [ -e "$path" ] || continue
            live="$(stat -c '%a %U:%G' "$path")"
            [ "$mode $own" = "$live" ] || flag "B4 differs from clean VM: $path clean[$mode $own] live[$live]"
        done < "$PACK_DIR/$svc/stat.txt"
    fi
    # data dirs that must be private (blog: raw database data directories)
    for f in /var/lib/mysql /var/lib/postgresql/*/main; do
        [ -d "$f" ] || continue
        case "$svc:$f" in mysql:/var/lib/mysql|postgresql:/var/lib/postgresql/*) ;; *) continue ;; esac
        [ "$(stat -c %a "$f")" = 700 ] || flag "B4 data dir not 700: $(stat -c '%a %U:%G' "$f") $f"
    done
}

# ================================================================ B5 --
b5_units() {
    local svc="$1" u props exe
    rhdr "B5 systemd units (ExecStart / User / drop-ins / sandboxing)"
    for u in ${UNITS[$svc]:-}; do
        systemctl cat "$u" >/dev/null 2>&1 || continue
        props="$(systemctl show "$u" -p FragmentPath -p DropInPaths -p ExecStart -p User -p Group -p ProtectSystem -p NoNewPrivileges 2>/dev/null)"
        r "   $u:"; echo "$props" | sed 's/^/     /' >> "$REPORT"
        systemctl cat "$u" > "$SVC_DIR/unit-$u.txt" 2>/dev/null
        local frag; frag="$(echo "$props" | sed -n 's/^FragmentPath=//p')"
        if [[ "$frag" == /etc/systemd/system/* ]]; then
            if [ "$(readlink -f "$frag")" = /dev/null ]; then r "     $u is masked (-> /dev/null)"; else flag "B5 $u vendor unit is overridden by $frag"; fi
        fi
        local drop; drop="$(echo "$props" | sed -n 's/^DropInPaths=//p')"
        [ -n "$drop" ] && flag "B5 $u has drop-in(s): $drop  (check for ExecStart/User changes)"
        exe="$(echo "$props" | sed -n 's/^ExecStart={ path=\([^ ;]*\).*/\1/p' | head -1)"
        if [ -n "$exe" ] && [ -e "$exe" ] && ! owned "$exe"; then
            flag "B5 $u runs a binary no package owns: $exe"
        fi
        echo "$props" | grep -q 'argv\[\]=.*\.conf' && r "     note: ExecStart passes an explicit config file - make sure it's the one you harden"
    done
    if [ "$svc" = system ]; then
        r "   systemd-delta (overridden / extended / redirected / masked units):"
        systemd-delta --no-pager --type=overridden,extended,redirected,masked 2>/dev/null | sed 's/^/     /' >> "$REPORT"
        local f
        while IFS= read -r f; do
            owned "$f" || flag "B5 unit file not owned by any package: $f"
        done < <(find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system -maxdepth 1 -type f \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.path' \) -exec readlink -f {} \; 2>/dev/null | sort -u)
    fi
}

# ================================================================ B6 --
ALL_PROCS=""
b6_ports() {
    local svc="$1" line proc port addr p
    rhdr "B6 listening sockets vs expected"
    if [ "$svc" = system ]; then
        r "   expected service processes: $ALL_PROCS"
        while IFS= read -r line; do
            proc="$(echo "$line" | sed -n 's/.*users:(("\([^"]*\)".*/\1/p')"
            [ -z "$proc" ] && continue
            [[ " $ALL_PROCS systemd-resolve systemd-resolved cupsd cups-browsed avahi-daemon chronyd dhclient NetworkManager dnsmasq rpcbind ntpd "  == *" $proc "* ]] && continue
            flag "B6 unexpected listener: $line"
        done < <(ss -H -tulpn 2>/dev/null)
        return
    fi
    local found=0
    while IFS= read -r line; do
        proc="$(echo "$line" | sed -n 's/.*users:(("\([^"]*\)".*/\1/p')"
        [[ " ${PROCS[$svc]} " == *" $proc "* ]] || [[ "$svc" == php && "$proc" == php-fpm* ]] || continue
        found=1
        addr="$(echo "$line" | awk '{print $5}')"; port="${addr##*:}"
        r "   $proc listening on $addr"
        [[ " ${PORTS[$svc]:-} " == *" $port "* ]] || { [ "$svc" = vsftpd ] && [ "$port" -ge 1024 ] 2>/dev/null; } \
            || { [ "$svc" = squid ] && [[ "$line" == udp* ]] && [ "$port" -ge 32768 ] 2>/dev/null; } \
            || flag "B6 $proc on unexpected port $addr (expected: ${PORTS[$svc]:-none})"
        case "$svc" in mysql|postgresql)
            [[ "$addr" == 0.0.0.0:* || "$addr" == "[::]:"* || "$addr" == "*:"* ]] && flag "B6 $proc listens on ALL interfaces ($addr) - should normally be localhost" ;;
        esac
    done < <(ss -H -tulpn 2>/dev/null)
    [ "$found" = 1 ] || r "   (service is not listening - is it running? a critical service must stay up)"
    if [ -f "$PACK_DIR/$svc/listen.txt" ]; then r "   clean-VM listeners:"; sed 's/^/     /' "$PACK_DIR/$svc/listen.txt" >> "$REPORT"; fi
}

# ================================================================ B7 --
accounts_raw() {  # prints service-internal accounts, one per line
    case "$1" in
        mysql) mysql -NBe "SELECT CONCAT(user,'@',host) FROM mysql.user" 2>/dev/null | sort ;;
        postgresql) sudo -u postgres psql -AtXc "SELECT rolname||' super='||rolsuper||' createrole='||rolcreaterole||' login='||rolcanlogin FROM pg_roles WHERE rolname !~ '^pg_'" 2>/dev/null | sort ;;
        samba) pdbedit -L 2>/dev/null | cut -d: -f1 | sort ;;
        wordpress)
            local cfg db user pass host pre
            for cfg in $WP_CONFIGS; do
                db="$(sed -n "s/.*define( *['\"]DB_NAME['\"] *, *['\"]\([^'\"]*\)['\"].*/\1/p" "$cfg")"
                user="$(sed -n "s/.*define( *['\"]DB_USER['\"] *, *['\"]\([^'\"]*\)['\"].*/\1/p" "$cfg")"
                pass="$(sed -n "s/.*define( *['\"]DB_PASSWORD['\"] *, *['\"]\([^'\"]*\)['\"].*/\1/p" "$cfg")"
                host="$(sed -n "s/.*define( *['\"]DB_HOST['\"] *, *['\"]\([^'\"]*\)['\"].*/\1/p" "$cfg")"
                pre="$(sed -n "s/^[[:space:]]*\$table_prefix[[:space:]]*=[[:space:]]*['\"]\([^'\"]*\)['\"].*/\1/p" "$cfg")"; pre="${pre:-wp_}"
                MYSQL_PWD="$pass" mysql -N -B -u "$user" -h "${host:-localhost}" "$db" -e \
                  "SELECT CONCAT(u.user_login,' role=',m.meta_value) FROM ${pre}users u JOIN ${pre}usermeta m ON m.user_id=u.ID AND m.meta_key='${pre}capabilities'" 2>/dev/null \
                  | sed "s#^#$cfg: #"
            done ;;
    esac
}

b7_accounts() {
    local svc="$1" a def
    case "$svc" in mysql|postgresql|samba|wordpress) ;; *) return ;; esac
    rhdr "B7 service-internal accounts vs defaults"
    case "$svc" in
        mysql) def=" root@localhost mysql.sys@localhost mysql.session@localhost mysql.infoschema@localhost debian-sys-maint@localhost mysql@localhost mariadb.sys@localhost " ;;
        postgresql) def=" postgres " ;;
        samba) def=" " ;;
        wordpress) def="" ;;
    esac
    local out; out="$(accounts_raw "$svc")"
    [ -n "$out" ] || { r "   (could not query accounts - is the service running / reachable as root?)"; return; }
    while IFS= read -r a; do
        if [ "$svc" = wordpress ]; then
            [[ "$a" == *administrator* ]] && flag "B7 WordPress administrator (check README): $a" || r "   $a"
            continue
        fi
        if [[ "$def" == *" ${a%% *} "* ]]; then r "   default: $a"
        else flag "B7 non-default $svc account (check README): $a"; fi
        [[ "$svc" == mysql && "$a" == *@% ]] && flag "B7 MySQL account reachable from ANY host: $a"
        [[ "$svc" == postgresql && "$a" == *super=t* && "${a%% *}" != postgres ]] && flag "B7 PostgreSQL SUPERUSER that is not postgres: $a"
    done <<< "$out"
    if [ -f "$PACK_DIR/$svc/accounts.txt" ]; then
        comm -13 <(sort "$PACK_DIR/$svc/accounts.txt") <(echo "$out" | sort) | while IFS= read -r a; do flag "B7 account not on clean VM: $a"; done
    fi
}

# ================================================================ B8 --
b8_content() {
    local svc="$1" d f
    [ -n "${CONTENT[$svc]:-}" ] || return
    rhdr "B8 web / FTP content vs default (full list: $SVC_DIR/content.txt)"
    : > "$SVC_DIR/content.txt"
    for d in ${CONTENT[$svc]}; do
        [ -d "$d" ] || continue
        find "$d" -xdev -type f -printf '%TY-%Tm-%Td %TH:%TM %u:%g %m %p\n' 2>/dev/null | sort >> "$SVC_DIR/content.txt"
    done
    local count; count="$(wc -l < "$SVC_DIR/content.txt")"
    r "   $count file(s) in content dirs (a clean install ships only index.html / index.nginx-debian.html)"
    [ "$count" -le 40 ] && sed 's/^/     /' "$SVC_DIR/content.txt" >> "$REPORT"
    for d in ${CONTENT[$svc]}; do
        [ -d "$d" ] || continue
        while IFS= read -r f; do flag "B8 phpinfo() file: $f"; done < <(grep -rlsiE 'phpinfo[[:space:]]*\(' "$d" 2>/dev/null)
        while IFS= read -r f; do flag "B8 webshell indicator: $f"; done < <(grep -rlsE 'eval[[:space:]]*\(|base64_decode[[:space:]]*\(|shell_exec[[:space:]]*\(|passthru[[:space:]]*\(|system[[:space:]]*\(\$_|\$_(GET|POST|REQUEST)\[[^]]*\][[:space:]]*\(' "$d" --include='*.php' --include='*.phtml' --include='*.inc' 2>/dev/null | head -30)
        while IFS= read -r f; do flag "B8 unusual owner: $(stat -c '%U:%G %a' "$f") $f"; done < <(find "$d" -xdev ! -user root ! -user www-data ! -user ftp ! -group www-data 2>/dev/null | head -30)
        while IFS= read -r f; do flag "B8 hidden file/dir: $f"; done < <(find "$d" -xdev -name '.*' ! -name '.htaccess' ! -name '.well-known' 2>/dev/null | head -30)
        while IFS= read -r f; do r "   .htaccess present (review, do not blindly delete): $f"; done < <(find "$d" -xdev -name '.htaccess' 2>/dev/null)
    done
}

# ================================================================ B9 --
b9_snapshot() {
    local svc="$1" dest p
    if [ -d "$SVC_DIR/before" ]; then dest="$SVC_DIR/runs/$CP_TS"; else dest="$SVC_DIR/before"; fi
    mkdir -p "$dest"
    # shellcheck disable=SC2086
    for p in $(existing_paths ${DIRS[$svc]}); do cp -a --parents "$p" "$dest/" 2>/dev/null; done
    for p in ${UNITS[$svc]:-}; do systemctl cat "$p" > "$dest/unit-$p.txt" 2>/dev/null || rm -f "$dest/unit-$p.txt"; done
    ss -tulpn > "$dest/listening.txt" 2>/dev/null
    [ -f "$SVC_DIR/content.txt" ] && cp "$SVC_DIR/content.txt" "$dest/"
    accounts_raw "$svc" > "$dest/accounts.txt" 2>/dev/null
    rhdr "B9 snapshot of live state saved to $dest (rollback point + FQ evidence)"
}

# ============================================================ capture (B10) --
capture_pack() {
    local out="$1/$OSID" s p
    echo "Capturing baseline pack for $OSID into $out (run this on a CLEAN VM!)"
    mkdir -p "$out"
    dpkg -l > "$out/dpkg-l.txt"
    systemctl list-unit-files --no-pager > "$out/unit-files.txt" 2>/dev/null
    ss -tulpn > "$out/listening-all.txt" 2>/dev/null
    find / -xdev -perm -0002 ! -type l ! -path '/proc/*' ! -path '/tmp/*' ! -path '/var/tmp/*' ! -path '/dev/*' 2>/dev/null | sort > "$out/world-writable.txt"
    find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | sort > "$out/suid-sgid.txt"
    for s in "${SVC_ORDER[@]}"; do
        detected "$s" || continue
        echo "  - $s"
        mkdir -p "$out/$s/pristine" "$out/$s/hardened"
        # shellcheck disable=SC2086
        for p in $(existing_paths ${DIRS[$s]}); do cp -a --parents "$p" "$out/$s/pristine/" 2>/dev/null; done
        # shellcheck disable=SC2086
        p="$(existing_paths ${DIRS[$s]} ${CONTENT[$s]:-} /var/lib/mysql /var/lib/postgresql)"
        [ -n "$p" ] && find $p -maxdepth 3 -printf '%m %u:%g %p\n' 2>/dev/null | sort > "$out/$s/stat.txt"
        accounts_raw "$s" > "$out/$s/accounts.txt" 2>/dev/null
        ss -H -tulpn 2>/dev/null | grep -E "\"($(echo "${PROCS[$s]:-none}" | tr ' ' '|'))\"" > "$out/$s/listen.txt"
        dpkg-query -W $(installed_pkgs "$s") > "$out/$s/packages.txt" 2>/dev/null
        [ -f "$out/$s/hardened/README.txt" ] || cat > "$out/$s/hardened/README.txt" <<EOF
B11: put YOUR hardened versions of the files from ../pristine/ here, same paths
(e.g. hardened/etc/ssh/sshd_config). At competition time open a 3-way Meld:
  meld <pack>/$s/pristine/<file> /<file> <pack>/$s/hardened/<file>
EOF
    done
    echo "Done. Copy $1 into the repo's competition/baseline/ folder."
}

if [ -n "$CAPTURE_DIR" ]; then capture_pack "$CAPTURE_DIR"; exit 0; fi

# ================================================================= main --
if [ ${#TARGETS[@]} -eq 0 ]; then
    for s in "${SVC_ORDER[@]}"; do detected "$s" && TARGETS+=("$s"); done
fi
for s in "${SVC_ORDER[@]}"; do detected "$s" && [ "$s" != system ] && ALL_PROCS+="${PROCS[$s]:-} "; done

echo "Baselining (detection only - nothing is changed). OS: $OSID"
[ -d "$PACK_DIR" ] && echo "Using baseline pack: $PACK_DIR" || echo "No baseline pack for $OSID in $CP_ROOT/baseline/ (using on-image sources / apt-get download)"
[ -d "$CP_ROOT/baseline" ] || true

SUMMARY=()
for svc in "${TARGETS[@]}"; do
    if [ -z "${DIRS[$svc]+x}" ]; then echo "Unknown service '$svc' (try --list)"; continue; fi
    if ! detected "$svc"; then echo "Skipping $svc: not installed"; continue; fi
    SVC_DIR="$CP_BASELINE_DIR/$svc"; mkdir -p "$SVC_DIR"; chmod 700 "$CP_BASELINE_DIR"
    REPORT="$SVC_DIR/report.txt"; PATCH="$SVC_DIR/diff.patch"; PAIRS="$SVC_DIR/pairs.txt"
    : > "$REPORT"; : > "$PATCH"; : > "$PAIRS"; FLAGS=0
    echo "  -> $svc"
    r "Baseline report: $svc   host: $(hostname)   os: $OSID   time: $(date)"
    r "Lines starting with '!!' are findings that need a decision. Nothing was changed."
    b1_integrity "$svc"
    b2_config "$svc"
    b3_unowned "$svc"
    b4_perms "$svc"
    b5_units "$svc"
    b6_ports "$svc"
    b7_accounts "$svc"
    b8_content "$svc"
    b9_snapshot "$svc"
    SUMMARY+=("$(printf '%-11s %3d finding(s)   %s' "$svc" "$FLAGS" "$REPORT")")
    if [ "$DO_MELD" = 1 ] && [ -s "$PAIRS" ]; then
        if ! command -v meld >/dev/null; then
            cp_ask "Meld is not installed. Install it (apt-get install meld)?" y && apt-get install -y meld >/dev/null 2>&1
        fi
        if command -v meld >/dev/null && [ -n "${DISPLAY:-}" ]; then
            while IFS='|' read -r p l; do
                cp_ask "Open Meld: $l ?" y && meld "$p" "$l" >/dev/null 2>&1
            done < "$PAIRS"
        else
            echo "     (Meld needs a desktop session: run from a terminal in the GUI as root, e.g. 'sudo -E')"
        fi
    fi
done

echo
echo "=== Baseline summary (reports in $CP_BASELINE_DIR) ==="
printf '  %s\n' "${SUMMARY[@]}"
echo "Review each report ('!!' lines) and the diff.patch files, then run the matching hardening script."
