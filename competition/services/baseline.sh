#!/bin/bash
# baseline.sh - SERVICE BASELINING (research doc section B, B1-B11).  "To find evil, you must know good."
#
#   Just run it, no arguments needed:  sudo ./baseline.sh  (from services/)  or  sudo bash services/baseline.sh
#   The SCAN compares every installed critical service (plus the "system" drop-in dirs) with a known-good
#   default and prints the findings. The scan is DETECTION ONLY: it changes nothing. On a terminal it then asks
#   ONE question: go through the findings now? (y = the review: fix / quarantine / skip each finding).
#   With no TTY (background, logs) it only scans and prints. Service scripts refuse to harden a service that
#   has no baseline (cp_baseline_gate scans it automatically).
#
#   Known good, in order: 1. baseline pack baseline/<os-id>/<svc>/ (clean-VM capture, no network)
#                         2. pristine copies on the image (ucf cache, php.ini-production, *.sample ...)
#                         3. only for services no pack covers: apt-get download (parallel, 20 s cap)
#
#   /root/baseline/FINDINGS.txt   START HERE: every finding, FIX NOW first, one line each + what to do
#   /root/baseline/<svc>/         report.txt ("!!" = finding), findings.tsv, diff.patch, pairs.txt (Meld),
#                                 before/ (snapshot of the FIRST scan: rollback point + FQ evidence), runs/<ts>/
#   /root/baseline/.scan.lock     held (flock) while a scan runs

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../cp-common.sh
source "$SCRIPT_DIR/../cp-common.sh" 2>/dev/null || { echo "ERROR: cp-common.sh not found in competition/"; exit 1; }

usage() {
    cat <<'EOF'
Usage: sudo ./baseline.sh            (from services/; or: sudo bash services/baseline.sh)
       scans every installed service + "system", prints the findings, then on a terminal asks once
       whether to go through them now (fix / quarantine / skip each). Nothing changes without a yes.

Optional:
  ssh apache2 ...     scan only these services
  --review [svc...]   go straight to the review of the last scan's findings: diff, restore pristine
                      (validated, rolled back if the service breaks), quarantine planted files, edit, fix perms
  --meld              after the scan, open every changed config in one Meld window
  --no-download       never apt-get download pristine packages (only used when no pack covers a service)
  --capture DIR       on a CLEAN VM: write a baseline pack to DIR/<os-id>/
  --list              list service names and which are installed

Results: /root/baseline/FINDINGS.txt (start here); details in /root/baseline/<svc>/report.txt
EOF
}

MODE=scan; DO_MELD=0; DO_DOWNLOAD=1; CAPTURE_DIR=""
TARGETS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --review) MODE=review ;;
        --prune) MODE=prune ;;      # internal (cp_baseline_gate): drop findings that are already fixed
        --meld) DO_MELD=1 ;;
        --no-download) DO_DOWNLOAD=0 ;;
        --capture) MODE=capture; CAPTURE_DIR="$2"; [ -n "$2" ] || { usage; exit 2; }; shift ;;
        --list) MODE=list ;;
        -h|--help) usage; exit 0 ;;
        -*) echo "Unknown option: $1"; usage; exit 2 ;;
        *) TARGETS+=("$1") ;;
    esac
    shift
done
cp_require_root

OSID="$(cp_os_id)"
PACK_DIR="$CP_ROOT/baseline/$OSID"
if [ ! -d "$PACK_DIR" ]; then
    # same distro + major version: linuxmint-21.1 / 21.2 use the linuxmint-21.3 pack (all are Ubuntu jammy)
    _c="$(ls -d "$CP_ROOT/baseline/${OSID%%.*}".* 2>/dev/null | tail -1)"
    [ -n "$_c" ] && PACK_DIR="$_c"
fi
PRISTINE_DEBS="$CP_BASELINE_DIR/_pristine"
FINDINGS="$CP_BASELINE_DIR/FINDINGS.txt"
QUAR_DIR="/root/cp-quarantine"

# ------------------------------------------------------------ registry --
# Installed packages, read ONCE (dpkg-query per check was a hot spot). "hold ok installed" counts too.
declare -A INST
while read -r _p; do INST["$_p"]=1; done < <(dpkg-query -W -f='${Package} ${Status}\n' 2>/dev/null | awk '/ ok installed$/{print $1}')
inst() { [ -n "${INST[$1]+x}" ]; }
dyn_pkgs() {  # dyn_pkgs GLOB... -> installed package names matching any glob (sorted)
    local k g
    # shellcheck disable=SC2053
    for k in "${!INST[@]}"; do for g in "$@"; do [[ "$k" == $g ]] && { echo "$k"; break; }; done; done | sort | tr '\n' ' '
}

declare -A PKGS DIRS UNITS PORTS PROCS CONTENT EXTRA
SVC_ORDER=(ssh vsftpd apache2 nginx php mysql postgresql samba bind9 postfix dovecot openvpn squid wordpress system)
declare -A HARDEN=([ssh]=ssh.sh [vsftpd]=vsftpd.sh [apache2]=apache2.sh [nginx]=nginx.sh [php]=php.sh [mysql]=mysql.sh
    [postgresql]=postgresql.sh [samba]=samba.sh [bind9]=bind9.sh [postfix]=mail.sh [dovecot]=mail.sh [openvpn]=openvpn.sh
    [squid]=squid.sh [wordpress]=wordpress.sh)

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

# versioned packages / instance units
PKGS[php]="$(dyn_pkgs 'php[0-9]*-common' 'php[0-9]*-fpm' 'php[0-9]*-cli' 'libapache2-mod-php[0-9]*' 'php-common')"
UNITS[php]="$(systemctl list-unit-files 'php*-fpm.service' 2>/dev/null | awk '/fpm\.service/{print $1}' | tr '\n' ' ')"
PKGS[mysql]="$(dyn_pkgs 'mysql-server*' 'mariadb-server*' 'mysql-common' 'mariadb-common')"
PKGS[postgresql]="$(dyn_pkgs 'postgresql-[0-9]*' 'postgresql-common')"
UNITS[postgresql]="postgresql.service $(systemctl list-units --all --plain --no-legend 'postgresql@*' 2>/dev/null | awk '{print $1}' | tr '\n' ' ')"
PKGS[dovecot]="$(dyn_pkgs 'dovecot-*')"
UNITS[openvpn]+=" $(systemctl list-units --all --plain --no-legend 'openvpn*@*' 2>/dev/null | awk '{print $1}' | tr '\n' ' ')"
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
    for p in ${PKGS[$s]:-}; do inst "$p" && return 0; done
    return 1
}
installed_pkgs() { local p out=""; for p in ${PKGS[$1]:-}; do inst "$p" && out+="$p "; done; echo "$out"; }
existing_paths() { local p; for p in "$@"; do [ -e "$p" ] && echo "$p"; done; }

if [ "$MODE" = list ]; then
    for s in "${SVC_ORDER[@]}"; do if [ "$s" = system ]; then echo "  system  (always)"; elif detected "$s"; then echo "  $s  (installed)"; else echo "  $s"; fi; done
    exit 0
fi

# ============================================================ capture (B10) --
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

capture_pack() {  # output format unchanged since 2026-10-21 (the reader filters stat.txt per service)
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
        # shellcheck disable=SC2086
        [ -n "$p" ] && find $p -maxdepth 3 -printf '%m %u:%g %p\n' 2>/dev/null | sort > "$out/$s/stat.txt"
        accounts_raw "$s" > "$out/$s/accounts.txt" 2>/dev/null
        ss -H -tulpn 2>/dev/null | grep -E "\"($(echo "${PROCS[$s]:-none}" | tr ' ' '|'))\"" > "$out/$s/listen.txt"
        # shellcheck disable=SC2046
        dpkg-query -W $(installed_pkgs "$s") > "$out/$s/packages.txt" 2>/dev/null
        [ -f "$out/$s/hardened/README.txt" ] || cat > "$out/$s/hardened/README.txt" <<EOF
B11: put YOUR hardened versions of the files from ../pristine/ here, same paths
(e.g. hardened/etc/ssh/sshd_config). At competition time open a 3-way Meld:
  meld <pack>/$s/pristine/<file> /<file> <pack>/$s/hardened/<file>
EOF
    done
    echo "Done. Copy $1 into the repo's competition/baseline/ folder."
}
if [ "$MODE" = capture ]; then capture_pack "$CAPTURE_DIR"; exit 0; fi

# ======================================================= findings helpers --
# Per service the scan writes report.txt (human), findings.tsv (one finding per line, read by FINDINGS.txt,
# --review and cp_baseline_gate) and diff.patch / pairs.txt. findings.tsv columns (empty = "-"):
#   prio(1 FIX NOW, 2 REVIEW, 3 INFO) svc kind path aux default-key md5-at-scan what hint details(\x1f-separated)
#   kind: cfgdiff cfgnop cfgmissing planted unit dropin override unitexe perm suid trojan listener account note info
SVC=""; SVC_DIR=""; REPORT=""; PATCH=""; PAIRS=""; TSV=""
r()    { echo "$*" >> "$REPORT"; }
rhdr() { echo "" >> "$REPORT"; echo "## $*" >> "$REPORT"; }
_d()   { [ -n "$1" ] && printf '%s' "$1" || printf '-'; }

# fnd PRIO KIND PATH AUX DEFAULT "what" "hint" [detail lines...]
declare -A FND_SEEN PLANTED
fnd() {
    local prio="$1" kind="$2" path="$3" aux="$4" dflt="$5" what="$6" hint="$7" tag md5="" det="" l key
    shift 7
    if [ "$prio" -le 2 ]; then   # same finding twice (alias units ssh/sshd, named/bind9): report it once
        if [ -n "$path" ]; then key="$kind|$path"; else key="$kind|$aux"; fi
        [ -n "${FND_SEEN[$key]+x}" ] && return 0
        FND_SEEN[$key]=1
        [[ "$kind" == planted || "$kind" == unit || "$kind" == dropin || "$kind" == override ]] && PLANTED[$path]=1
    fi
    case "$prio" in 1) tag="FIX NOW" ;; 2) tag="REVIEW " ;; *) tag="INFO   " ;; esac
    if [ "$prio" -le 2 ]; then echo "!! $tag $what" >> "$REPORT"; else echo "   (info) $what" >> "$REPORT"; fi
    for l in "$@"; do echo "        $l" >> "$REPORT"; det+="${l//$'\t'/ }"$'\x1f'; done
    [ -n "$hint" ] && [ "$prio" -le 2 ] && echo "        -> $hint" >> "$REPORT"
    [ -f "$path" ] && md5="$(md5sum < "$path" 2>/dev/null | cut -c1-32)"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$prio" "$SVC" "$kind" "$(_d "$path")" "$(_d "$aux")" "$(_d "$dflt")" \
        "$(_d "$md5")" "${what//$'\t'/ }" "$(_d "${hint//$'\t'/ }")" "$(_d "${det%$'\x1f'}")" >> "$TSV"
}

# What fixes this file later (shown as the hint)
harden_hint() {
    local s=""
    if [ "$SVC" = system ]; then
        case "$1" in
            /etc/sudoers*) s="usersandsudo.sh checks sudoers" ;;
            /etc/pam.d/*|/etc/security/*|/etc/sysctl*|/etc/lightdm/*|/etc/gdm3/*|/etc/cron*|/etc/ld.so.preload|/etc/login.defs|/etc/bash.bashrc) s="systemconfig.sh also hardens this" ;;
            /etc/apt/*) s="fix APT sources before updating" ;;
        esac
    elif [ -n "${HARDEN[$SVC]:-}" ]; then s="${HARDEN[$SVC]} hardens it"
    fi
    [ -n "$s" ] && echo "$2$s"
}

# Files whose planted content is safe to move away (never README-required, nothing breaks without them)
safe_to_quarantine() {
    case "$1" in
        /etc/ssh/sshd_config.d/*|/etc/sudoers.d/*|/etc/sysctl.d/*|/etc/cron.d/*|/etc/apt/apt.conf.d/*|/etc/profile.d/*|\
        /etc/lightdm/lightdm.conf.d/*|/etc/ld.so.preload|/etc/polkit-1/*|/etc/systemd/system/*.d/*) return 0 ;;
    esac
    return 1
}

# meaningful_diff PRISTINE LIVE -> "+ line" / "- line": changed lines that are not comments/blank and did
# not merely move or change whitespace.
meaningful_diff() {
    diff -U0 "$1" "$2" 2>/dev/null | awk '
        /^(\+\+\+|---|@@)/ { next }
        /^[+-]/ { t = substr($0, 2); gsub(/^[ \t]+|[ \t]+$/, "", t)
                  if (t == "" || t ~ /^(#|;|\/\/)/) next
                  k = t; gsub(/[ \t]+/, " ", k)
                  n++; sign[n] = substr($0, 1, 1); txt[n] = t; key[n] = k; cnt[sign[n] k]++ }
        END { for (i = 1; i <= n; i++) {
                  other = (sign[i] == "+" ? "-" : "+") key[i]
                  if (cnt[other] > 0) { cnt[other]--; continue }
                  print sign[i] " " substr(txt[i], 1, 110) } }'
}

record_diff() {  # record_diff PRISTINE LIVE -> appends to diff.patch / pairs.txt
    diff -u "$1" "$2" >> "$PATCH" 2>/dev/null
    echo "$1|$2" >> "$PAIRS"
}

# The pack's postfix main.cf was generated with the capture VM's hostname: compare (and restore) a copy
# with the hostname the live file was generated with (its own myhostname line, else this machine's).
PACK_HOST="$(sed -n 's/^myhostname = //p' "$PACK_DIR/postfix/pristine/etc/postfix/main.cf" 2>/dev/null | head -1)"
LIVE_FQDN="$(hostname -f 2>/dev/null || hostname)"
norm_pristine() {  # norm_pristine FILE PRISTINE -> PRISTINE, or a hostname-adjusted copy of it
    local f="$1" p="$2" n h lf
    [ -n "$PACK_HOST" ] && [[ "$p" == "$PACK_DIR"/* ]] && grep -qF "$PACK_HOST" "$p" || { echo "$p"; return; }
    lf="$(sed -n 's/^myhostname = //p' "$f" 2>/dev/null | head -1)"; [ -n "$lf" ] || lf="$LIVE_FQDN"
    [ "$lf" = "$PACK_HOST" ] && { echo "$p"; return; }
    h="$(printf '%s' "$PACK_HOST" | sed 's/[.[\*^$/]/\\&/g')"
    n="$SVC_DIR/pristine$f"; mkdir -p "$(dirname "$n")"
    if sed -e "/^myhostname/s/$h/$lf/" -e "s/$h/${lf%%.*}/g" "$p" > "$n"; then echo "$n"; else echo "$p"; fi
}

# report_cfg_change FILE PRISTINE WHY
report_cfg_change() {
    local f="$1" p="$2" why="$3" n lines show
    [ -n "${FND_SEEN["cfgdiff|$f"]+x}" ] && return 0   # already compared by an earlier step
    [ -n "$p" ] && p="$(norm_pristine "$f" "$p")"
    if [ -z "$p" ]; then
        fnd 2 cfgnop "$f" "" s "$f $why - no pristine copy to compare" "open it (e) and check every setting$(harden_hint "$f" "; ")"
        return
    fi
    if cmp -s "$p" "$f"; then r "   identical to pristine: $f"; return; fi
    record_diff "$p" "$f"
    mapfile -t lines < <(meaningful_diff "$p" "$f")
    n=${#lines[@]}
    if [ "$n" -eq 0 ]; then fnd 3 info "$f" "$p" s "$f: only comments/blank lines differ from pristine" ""; return; fi
    show=("${lines[@]:0:6}"); [ "$n" -gt 6 ] && show+=("... $((n - 6)) more (full diff: --review d, or diff.patch)")
    fnd 2 cfgdiff "$f" "$p" s "$f differs from pristine ($n line(s))" "restore (r) or edit (e)$(harden_hint "$f" "; ")" "${show[@]}"
}

# preload_libs FILE -> "unowned|owned|missing PATH" for every absolute path /etc/ld.so.preload lists
preload_libs() {
    local toks=() t
    read -r -a toks <<< "$(sed 's/#.*//' "$1" 2>/dev/null | tr ':\n' '  ')"
    for t in "${toks[@]}"; do
        [[ "$t" == /* ]] || continue
        if [ ! -e "$t" ]; then echo "missing $t"
        elif [ -n "$(printf '%s\n' "$t" | cp_unowned)" ] && [ -n "$(readlink -f "$t" | cp_unowned)" ]; then echo "unowned $t"
        else echo "owned $t"; fi
    done
}

# first non-comment lines of a file (to show what a planted file does)
peek() { grep -avE '^[[:space:]]*([#;]|$)' "$1" 2>/dev/null | head -"${2:-3}" | cut -c1-110 | tr -d '\r'; }

in_pack_same() { local c="$PACK_DIR/$1/pristine$2"; [ -f "$c" ] && cmp -s "$c" "$2"; }
ucf_hash() { awk -v f="$1" '$2 == f {print $1; exit}' /var/lib/ucf/hashfile 2>/dev/null; }
ucf_registered() { awk -v f="$1" '$NF == f {found=1; exit} END {exit !found}' /var/lib/ucf/registry 2>/dev/null; }

# Pristine .deb fallback - ONLY used for services the pack does not cover. Downloads happen up front, in
# parallel (prefetch_debs); during the scan fetch_deb only returns what is already extracted.
deb_has_conf() { grep -qsE '^/(etc|srv|var/www)/' "/var/lib/dpkg/info/$1.list" "/var/lib/dpkg/info/$1:"*.list; }
fetch_deb() { local d="$PRISTINE_DEBS/$1"; [ -d "$d/root" ] && echo "$d"; }
fetch_deb_now() {  # download + extract one package (runs in the background)
    local pkg="$1" dest="$PRISTINE_DEBS/$1" ver deb
    mkdir -p "$dest"; ver="$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null)"
    ( cd "$dest" && timeout 20 sh -c "/usr/bin/apt-get download -qq '$pkg=$ver' || /usr/bin/apt-get download -qq '$pkg'" >/dev/null 2>&1 )
    deb="$(ls "$dest"/*.deb 2>/dev/null | head -1)"
    if [ -n "$deb" ]; then dpkg-deb -x "$deb" "$dest/root" 2>/dev/null && dpkg-deb -c "$deb" > "$dest/listing.txt" 2>/dev/null; fi
    touch "$dest/.tried"
}
pack_covers() { [ -d "$PACK_DIR/$1" ]; }

# pristine_for FILE SVC PKG -> path of a known-good copy (empty if none)
pristine_for() {
    local f="$1" svc="$2" pkg="$3" c v sapi d
    c="$PACK_DIR/$svc/pristine$f"; [ -f "$c" ] && { echo "$c"; return; }
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
    if [ -n "$pkg" ] && d="$(fetch_deb "$pkg")" && [ -f "$d/root$f" ]; then echo "$d/root$f"; return; fi
}

sym2oct() {  # -rwsr-xr-x -> 4755
    local s="${1:1:9}" o=0 i c
    local -a w=(256 128 64 32 16 8 4 2 1)
    for i in 0 1 2 3 4 5 6 7 8; do c="${s:i:1}"; [[ "$c" == [rwxst] ]] && o=$((o + w[i])); done
    [[ "${s:2:1}" == [sS] ]] && o=$((o + 2048)); [[ "${s:5:1}" == [sS] ]] && o=$((o + 1024)); [[ "${s:8:1}" == [tT] ]] && o=$((o + 512))
    printf '%o' "$o"
}

# ================================================================ B1 --
b1_integrity() {
    local pkgs line path pkg
    rhdr "B1 package integrity (dpkg --verify) - binaries, PAM modules, shipped files"
    pkgs="$(installed_pkgs "$SVC")"
    [ -n "${pkgs// /}" ] || { r "   (no package for this service)"; return; }
    r "   packages: $pkgs"
    # shellcheck disable=SC2086
    local out; out="$(dpkg --verify $pkgs 2>/dev/null)"
    [ -z "$out" ] && { r "   all package files match their md5sums"; return; }
    while IFS= read -r line; do
        path="/${line#*/}"
        if [[ "$line" =~ ^.{9}[[:space:]]c[[:space:]] ]]; then r "   conffile changed (see B2): $path"; continue; fi
        pkg="$(dpkg-query -S "$path" 2>/dev/null | head -1 | cut -d: -f1)"
        if [[ "$line" == missing* ]]; then
            [[ "$path" =~ /usr/share/(doc|man|locale|info|lintian)/ ]] && continue   # often excluded by dpkg path-exclude
            fnd 2 trojan "$path" "$pkg" s "package file missing: $path ($pkg)" "reinstall the package (i)"
        else
            fnd 1 trojan "$path" "$pkg" i "NON-CONFIG package file modified (trojan?): $path ($pkg)" "reinstall the package (i)"
        fi
    done <<< "$out"
}

# ================================================================ B2 --
B2_SEEN=" "
b2_config() {
    local pkg f md5 obs cur p
    rhdr "B2 config content vs pristine default"
    B2_SEEN=" "
    local cf; cf="$(mktemp)"
    for pkg in $(installed_pkgs "$SVC"); do
        dpkg-query -W -f='${Conffiles}\n' "$pkg" 2>/dev/null | awk -v p="$pkg" '$1 ~ /^\/etc\// {print $1, $2, ($3 == "obsolete" ? "obsolete" : "-"), p}'
    done > "$cf"
    declare -A CUR=()
    # one md5sum for all existing conffiles
    while read -r md5 f; do CUR["$f"]="$md5"; done < <(awk '{print $1}' "$cf" | while read -r f; do [ -f "$f" ] && echo "$f"; done | xargs -r -d '\n' md5sum 2>/dev/null)
    while read -r f md5 obs pkg; do
        [ -n "$f" ] || continue
        B2_SEEN+="$f "
        [ "$obs" = obsolete ] && continue
        if [ ! -e "$f" ]; then
            p="$(pristine_for "$f" "$SVC" "$pkg")"
            fnd 2 cfgmissing "$f" "$p" s "conffile deleted: $f ($pkg)" "${p:+restore it (r)}"
            continue
        fi
        cur="${CUR[$f]:-}"
        [ "$cur" = "$md5" ] && continue
        report_cfg_change "$f" "$(pristine_for "$f" "$SVC" "$pkg")" "changed since install ($pkg)"
    done < "$cf"
    rm -f "$cf"
    # ucf-managed / generated files that dpkg does not track as conffiles
    local first; first="$(installed_pkgs "$SVC" | awk '{print $1}')"
    for f in ${EXTRA[$SVC]:-}; do
        [ -f "$f" ] || continue
        [[ "$B2_SEEN" == *" $f "* ]] && continue
        B2_SEEN+="$f "
        md5="$(ucf_hash "$f")"; cur="$(md5sum "$f" | cut -d' ' -f1)"
        if [ -n "$md5" ] && [ "$md5" = "$cur" ]; then r "   unchanged since install (ucf): $f"; continue; fi
        p="$(pristine_for "$f" "$SVC" "$first")"
        if [ -n "$p" ]; then report_cfg_change "$f" "$p" "differs from pristine"
        else fnd 3 info "$f" "" s "no pristine copy for $f - review by hand" ""; fi
    done
    if [ "$SVC" = postfix ] && command -v postconf >/dev/null; then
        r "   postconf non-default parameters:"
        comm -13 <(postconf -d 2>/dev/null | sort) <(postconf -n 2>/dev/null | sort) | sed 's/^/     /' >> "$REPORT"
    fi
    # everything else in the clean-VM pack
    local missing=()
    if [ -d "$PACK_DIR/$SVC/pristine" ]; then
        while IFS= read -r p; do
            f="${p#"$PACK_DIR/$SVC/pristine"}"
            [[ "$B2_SEEN" == *" $f "* ]] && continue
            if [ ! -e "$f" ]; then missing+=("$f")
            elif ! cmp -s "$p" "$f"; then report_cfg_change "$f" "$p" "differs from the clean VM"; fi
        done < <(find "$PACK_DIR/$SVC/pristine" -type f 2>/dev/null | sort)
    fi
    if [ ${#missing[@]} -gt 0 ]; then
        fnd 3 info "" "" s "${#missing[@]} file(s) of the clean-VM pack are not on this image (normal when a package is not installed): ${missing[*]:0:4}$([ ${#missing[@]} -gt 4 ] && echo " ...")" ""
        printf '     missing: %s\n' "${missing[@]}" >> "$REPORT"
    fi
}

# ================================================================ B3 --
b3_unowned() {
    local f tgt v tpl paths list
    rhdr "B3 files in config dirs that NO package owns (planted drop-ins?)"
    # shellcheck disable=SC2086
    paths="$(existing_paths ${DIRS[$SVC]})"; [ -n "$paths" ] || { r "   (no config paths)"; return; }
    list="$(mktemp)"
    # one find + one index lookup (cp_unowned) instead of dpkg-query -S per file
    # shellcheck disable=SC2086
    find $paths -xdev \( -type f -o -type l \) 2>/dev/null \
        | grep -vE '\.bak\.[0-9_]+$|/ssh_host_[a-z0-9]+_key(\.pub)?$|\.dpkg-(dist|old|bak)$' | cp_unowned > "$list"
    while IFS= read -r f; do
        if in_pack_same "$SVC" "$f"; then r "   generated at install, identical to clean VM: $f"; continue; fi
        if [ -L "$f" ]; then
            tgt="$(readlink "$f")"
            # a2enmod/a2ensite/nginx style symlinks: fine if they point at the matching *-available file
            if [[ "$f" =~ -enabled/ ]] && [[ "$tgt" =~ -available/$(basename "$f")$ ]]; then continue; fi
            # phpenmod style: conf.d/20-zip.ini -> mods-available/zip.ini
            if [[ "$f" =~ /conf\.d/[0-9]+-(.+\.ini)$ ]] && [[ "$tgt" =~ mods-available/${BASH_REMATCH[1]}$ ]]; then continue; fi
            [[ "$f" == /etc/mysql/my.cnf ]] && continue
            [[ "$f" == /etc/nginx/modules-enabled/* && "$tgt" == /usr/share/nginx/modules-available/* && -e "$tgt" ]] && continue
            [[ "$f" == /etc/postfix/makedefs.out && "$tgt" == /usr/share/postfix/makedefs.out ]] && continue
            [[ "$tgt" == */ssl-cert-snakeoil.* ]] && continue   # created by postinst scripts
            fnd 1 planted "$f" "" s "symlink no package owns: $f -> $tgt" "check where it points; quarantine (q) if planted"
            continue
        fi
        case "$f" in
            /etc/php/*/mods-available/*.ini)
                # generated by phpenmod from /usr/share/php<ver>-<pkg>/<pkg>/<ext>.ini
                v="$(echo "$f" | cut -d/ -f4)"
                tpl="$(ls /usr/share/php"$v"-*/*/"$(basename "$f")" /usr/share/php"$v"-*/"$(basename "$f")" 2>/dev/null | head -1)"
                if [ -n "$tpl" ]; then cmp -s "$tpl" "$f" || report_cfg_change "$f" "$tpl" "differs from its php module template"; continue; fi ;;
            /etc/dovecot/*)
                tpl="/usr/share/dovecot/${f#/etc/dovecot/}"
                if [ -f "$tpl" ]; then cmp -s "$tpl" "$f" || report_cfg_change "$f" "$tpl" "differs from its dovecot template"; continue; fi ;;
            /etc/bind/rndc.key|/etc/mysql/debian.cnf|/etc/ssh/sshd_config|/etc/samba/smb.conf|/etc/postfix/main.cf|/etc/php/*/*/php.ini|/etc/postgresql/*|/etc/sudoers.d/README|/etc/ld.so.conf.d/*|/etc/apt/sources.list.d/*.sources|/etc/security/opasswd|\
            /etc/apt/apt.conf.d/20auto-upgrades|/etc/apt/apt.conf.d/50unattended-upgrades|/etc/apt/apt.conf.d/02autoremove-postgresql|/etc/apt/sources.list|/etc/apt/sources.list.d/official-package-repositories.list|\
            /etc/pam.d/common-auth|/etc/pam.d/common-account|/etc/pam.d/common-password|/etc/pam.d/common-session|/etc/pam.d/common-session-noninteractive|\
            /etc/hosts|/etc/profile|/etc/environment|/etc/postgresql-common/createcluster.conf|/etc/postgresql-common/root.crt|\
            /etc/postfix/master.cf|/etc/postfix/main.cf.proto|/etc/postfix/master.cf.proto|/etc/postfix/dynamicmaps.cf|/etc/aliases)
                if [ -f "$PACK_DIR/$SVC/pristine$f" ]; then r "   generated at install, differs from clean VM (see B2): $f"
                else r "   generated at install (expected - review content by hand / with the pack): $f"; fi
                continue ;;
        esac
        # registered with ucf by a package postinst = generated at install, not planted
        if ucf_registered "$f"; then
            if [ "$(ucf_hash "$f")" = "$(md5sum < "$f" | cut -c1-32)" ]; then r "   generated by a package (ucf), unchanged: $f"
            else report_cfg_change "$f" "$(pristine_for "$f" "$SVC" "")" "changed since install (ucf)"; fi
            continue
        fi
        local d=s; safe_to_quarantine "$f" && d=q
        if [ "$f" = /etc/ld.so.preload ]; then   # name the rootkit library: q moves it together with this file
            local _pl; mapfile -t _pl < <(preload_libs "$f")
            mapfile -t _pk < <(printf '%s\n' "${_pl[@]}" | awk '{ print "preloads " $2 "  (" ($1 == "unowned" ? "no package owns it - quarantined together with this file" : $1) ")" }')
            fnd 1 planted "$f" "" "$d" "file no package owns: $(stat -c '%a %U:%G' "$f") $f - preloads: $(printf '%s\n' "${_pl[@]}" | awk '{printf "%s%s", sep, $2; sep=" "}')" \
                "quarantine (q) = this file + the unowned libraries it lists" "${_pk[@]}"
            continue
        fi
        mapfile -t _pk < <(peek "$f")
        fnd 1 planted "$f" "" "$d" "file no package owns: $(stat -c '%a %U:%G' "$f") $f" "quarantine (q) unless the README needs it" "${_pk[@]}"
    done < "$list"
    rm -f "$list"
}

# ================================================================ B4 --
declare -A B4P B4F B4T
spec_txt() { case "$1" in set:*) local v="${1#set:}"; echo "${v%%:*} ${v#*:}" ;; *) echo "${1#*:}" ;; esac; }
b4_add() {  # b4_add PRIO PATH FIXSPEC TEXT  - one finding per path (lowest prio wins, first text kept)
    local cur="${B4P[$2]:-9}"
    if [ -z "${B4T[$2]+x}" ]; then B4P[$2]="$1"; B4F[$2]="$3"; B4T[$2]="$4"
    elif [ "$1" -lt "$cur" ]; then B4P[$2]="$1"; B4F[$2]="$3"; B4T[$2]="$4"
    elif [[ "$3" == set:* && "${B4F[$2]}" != set:* ]]; then   # keep the finding, but fix to the exact clean-VM value
        B4F[$2]="$3"; B4T[$2]+="  (clean VM: $(spec_txt "$3"))"; fi
}
b4_perms() {
    local paths f exp live mode own path pre
    rhdr "B4 permissions / ownership vs default"
    B4P=(); B4F=(); B4T=()
    # shellcheck disable=SC2086
    paths="$(existing_paths ${DIRS[$SVC]} ${CONTENT[$SVC]:-})"
    [ -n "$paths" ] || { r "   (no paths)"; return; }
    # shellcheck disable=SC2086
    while IFS= read -r f; do [ -n "${PLANTED[$f]+x}" ] || b4_add 1 "$f" "chmod:o-w" "world-writable: $(stat -c '%a %U:%G' "$f") $f"; done \
        < <(find $paths -xdev -perm -0002 ! -type l ! -path '/tmp/*' 2>/dev/null | head -100)
    # shellcheck disable=SC2086
    while IFS= read -r f; do fnd 1 suid "$f" "chmod:u-s,g-s" s "SUID/SGID file inside a service path: $(stat -c '%a %U:%G' "$f") $f" "remove the bit (f) unless the README needs it"; done \
        < <(find $paths -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null)
    # config files owned by unexpected users (content dirs may legitimately be www-data)
    local p2; p2="$(existing_paths ${DIRS[$SVC]})"
    # shellcheck disable=SC2086
    [ -n "$p2" ] && while IFS= read -r f; do
        case "$SVC:$(stat -c %U "$f")" in
            postgresql:postgres|bind9:bind|mysql:mysql|squid:proxy|dovecot:dovecot) continue ;;
        esac
        b4_add 2 "$f" "chown:root" "config file not owned by root: $(stat -c '%a %U:%G' "$f") $f"
    done < <(find $p2 -xdev ! -user root ! -type l 2>/dev/null | head -50)
    # clean-VM capture (pack stat.txt "mode user:group path"), only this service's own paths
    local st="$PACK_DIR/$SVC/stat.txt"
    if [ -f "$st" ]; then
        pre="$(printf '%s\n' ${DIRS[$SVC]} ${CONTENT[$SVC]:-} | tr '\n' '|')"
        case "$SVC" in mysql) pre+="/var/lib/mysql|" ;; postgresql) pre+="/var/lib/postgresql|" ;; esac
        declare -A CLEAN=()
        while IFS=$'\t' read -r mode path; do CLEAN["$path"]="$mode"; done < <(awk -v pre="$pre" 'BEGIN { n = split(pre, P, "|") }
            { path = $0; sub(/^[^ ]+ [^ ]+ /, "", path)
              for (i = 1; i <= n; i++) if (P[i] != "" && (path == P[i] || index(path, P[i] "/") == 1)) { print $1 " " $2 "\t" path; next } }' "$st")
        # one stat for all of them (missing paths are simply not printed)
        while IFS=$'\t' read -r path live; do
            mode="${CLEAN[$path]:-}"; [ -z "$mode" ] || [ "$mode" = "$live" ] && continue
            b4_add 2 "$path" "set:${mode% *}:${mode#* }" "perms differ from the clean VM: $path  clean[$mode] live[$live]"
        done < <(printf '%s\n' "${!CLEAN[@]}" | xargs -r -d '\n' stat -c $'%n\t%a %U:%G' 2>/dev/null)
    else
        # no pack for this service: package listing from an already-downloaded .deb (mode + owner)
        local pkg d B4SEEN="|"
        for pkg in $(installed_pkgs "$SVC"); do
            d="$(fetch_deb "$pkg")" || continue; [ -f "$d/listing.txt" ] || continue
            while read -r mode owner _ _ _ path; do
                f="${path#.}"; [ -e "$f" ] && [ ! -L "$f" ] || continue
                case "$f" in /etc/*|/srv/*|/var/www/*) ;; *) continue ;; esac
                [[ "$B4SEEN" == *"|$f|"* ]] && continue; B4SEEN+="|$f|"
                exp="$mode ${owner}"; live="$(stat -c '%A %U/%G' "$f")"
                case "$f:$live" in   # changed by the package's own postinst
                    "/etc/bind/:drwxr-sr-x root/bind"|"/etc/sudoers:-r--r----- root/root"|/etc/bind/named.conf*:"-rw-r--r-- root/bind"|"/etc/postgresql/:drwxr-xr-x postgres/postgres"|"/etc/dovecot/private/:drwx------ root/root") continue ;;
                esac
                [ "$exp" = "$live" ] || b4_add 2 "${f%/}" "set:$(sym2oct "$mode"):${owner/\//:}" "perms differ from the package default: ${f%/}  default[$exp] live[$live]"
            done < <(awk '$1 !~ /^l/' "$d/listing.txt")
        done
    fi
    # data dirs that must be private (blog: raw database data directories)
    for f in /var/lib/mysql /var/lib/postgresql/*/main; do
        [ -d "$f" ] || continue
        case "$SVC:$f" in mysql:/var/lib/mysql|postgresql:/var/lib/postgresql/*) ;; *) continue ;; esac
        [ "$(stat -c %a "$f")" = 700 ] || b4_add 2 "$f" "chmod:700" "database data dir not 700: $(stat -c '%a %U:%G' "$f") $f"
    done
    for f in "${!B4T[@]}"; do
        local dk=s; [[ "${B4T[$f]}" == world-writable* ]] && dk=f
        fnd "${B4P[$f]}" perm "$f" "${B4F[$f]}" "$dk" "${B4T[$f]}" "fix (f) -> $(spec_txt "${B4F[$f]}")$(harden_hint "$f" "; ")"
    done
}

# ================================================================ B5 --
# The CyberPatriot scoring client (CCS, /opt/CyberPatriot) and aeacus practice engines (/opt/aeacus) are
# unowned by dpkg by design. NEVER offer to stop/move/kill them: that can lose the round's scoring.
# is_scoring PATH|CMDLINE|NAME... -> 0 if any argument is under those dirs, or is a unit/process NAME
# starting with ccs / cyberpatriot / aeacus (case-insensitive).
is_scoring() {
    local a l
    for a in "$@"; do
        [ -n "$a" ] && [ "$a" != - ] || continue
        l="${a,,}"
        [[ "$l" == *"/opt/cyberpatriot"* || "$l" == *"/opt/aeacus"* ]] && return 0
        [[ "$l" == */* || "$l" == *" "* ]] && continue   # plain names only below
        case "$l" in ccs*|cyberpatriot*|aeacus*) return 0 ;; esac
    done
    return 1
}
SCORING_TXT="scoring engine - NEVER touch (stopping it can lose the round's score)"
UNIT_BAD_RE='(^|[ /])(nc|ncat|netcat|nc\.traditional|nc\.openbsd|socat|telnet)( |$)|/dev/tcp|http\.server|SimpleHTTPServer|bash -i|sh -i|/tmp/|/dev/shm/|/var/tmp/'
b5_units() {
    local u props frag drop exe dk show lines
    rhdr "B5 systemd units (ExecStart / User / drop-ins / sandboxing)"
    for u in ${UNITS[$SVC]:-}; do
        props="$(systemctl show "$u" -p LoadState -p FragmentPath -p DropInPaths -p ExecStart -p User -p Group -p ProtectSystem -p NoNewPrivileges 2>/dev/null)"
        [[ "$props" == *LoadState=loaded* || "$props" == *LoadState=masked* ]] || continue
        r "   $u:"; echo "$props" | sed 's/^/     /' >> "$REPORT"
        systemctl cat "$u" > "$SVC_DIR/unit-$u.txt" 2>/dev/null
        frag="$(echo "$props" | sed -n 's/^FragmentPath=//p')"
        if [[ "$frag" == /etc/systemd/system/* ]]; then
            if [ "$(readlink -f "$frag")" = /dev/null ]; then r "     $u is masked (-> /dev/null)"
            elif [ -n "$(echo "$frag" | cp_unowned)" ]; then
                local vendor=""; for vendor in "/lib/systemd/system/$u" "/usr/lib/systemd/system/$u" ""; do [ -f "$vendor" ] && break; done
                mapfile -t lines < <(grep -E '^[[:space:]]*(Exec[A-Za-z]*|User|Group)=' "$frag" | head -3)
                fnd 1 override "$frag" "$vendor" s "$u: vendor unit replaced by $frag" "diff (d) against the vendor unit; quarantine (q) if planted" "${lines[@]}"
            fi
        fi
        drop="$(echo "$props" | sed -n 's/^DropInPaths=//p')"
        local dp
        for dp in $drop; do
            [ -n "$(echo "$dp" | cp_unowned)" ] || { r "     drop-in from a package: $dp"; continue; }
            mapfile -t lines < <(peek "$dp" 4)
            if is_scoring "$dp" "${lines[@]}"; then fnd 3 info "$dp" "" s "$SCORING_TXT: drop-in $dp" ""; continue; fi
            dk=s; grep -qE '^[[:space:]]*Exec[A-Za-z]*=' "$dp" && dk=q
            fnd 1 dropin "$dp" "$u" "$dk" "$u has a drop-in no package owns: $dp" "quarantine (q) if planted (unit is restarted and checked)" "${lines[@]}"
        done
        exe="$(echo "$props" | sed -n 's/^ExecStart={ path=\([^ ;]*\).*/\1/p' | head -1)"
        if [ -n "$exe" ] && is_scoring "$exe" "$(readlink -f "$exe")"; then fnd 3 info "$exe" "" s "$SCORING_TXT: $u runs $exe" ""
        elif [ -n "$exe" ] && [ -e "$exe" ] && [ -n "$(echo "$exe" | cp_unowned)" ] && [ -n "$(readlink -f "$exe" | cp_unowned)" ]; then
            fnd 1 unitexe "$exe" "$u" s "$u runs a binary no package owns: $exe" "check it (d); reinstall the service package or quarantine (q) the binary"
        fi
        echo "$props" | grep -q 'argv\[\]=.*\.conf' && r "     note: ExecStart passes an explicit config file - make sure it's the one you harden"
    done
    if [ "$SVC" = system ]; then
        r "   systemd-delta (overridden / extended / redirected / masked units):"
        systemd-delta --no-pager --type=overridden,extended,redirected,masked 2>/dev/null | sed 's/^/     /' >> "$REPORT"
        local f
        while IFS= read -r f; do
            mapfile -t lines < <(grep -E '^[[:space:]]*(ExecStart|User)=' "$f" | head -2 | cut -c1-110)
            if is_scoring "$f" "$(basename "$f")" "$(grep -E '^[[:space:]]*(Exec[A-Za-z]*|WorkingDirectory)=' "$f")"; then
                fnd 3 info "$f" "" s "$SCORING_TXT: unit $f" "" "${lines[@]}"; continue
            fi
            dk=s; printf '%s\n' "${lines[@]}" | grep -qE "$UNIT_BAD_RE" && dk=q
            fnd 1 unit "$f" "$(basename "$f")" "$dk" "unit file no package owns: $f" "quarantine (q) = stop + disable + move, unless the README needs it" "${lines[@]}"
        done < <(find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system -maxdepth 1 -type f \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.path' \) -exec readlink -f {} + 2>/dev/null | sort -u | cp_unowned)
    fi
}

# ================================================================ B6 --
ALL_PROCS=""
SS_CACHE="$CP_BASELINE_DIR/.ss.txt"
b6_ports() {
    local line proc port addr pid seen=" " cmd unit
    rhdr "B6 listening sockets vs expected"
    if [ "$SVC" = system ]; then
        r "   expected service processes: $ALL_PROCS"
        while IFS= read -r line; do
            proc="$(echo "$line" | sed -n 's/.*users:(("\([^"]*\)".*/\1/p')"
            [ -z "$proc" ] && continue
            [[ " $ALL_PROCS systemd-resolve systemd-resolved cupsd cups-browsed avahi-daemon chronyd dhclient NetworkManager dnsmasq rpcbind ntpd "  == *" $proc "* ]] && continue
            addr="$(echo "$line" | awk '{print $5}')"; port="${addr##*:}"; pid="$(echo "$line" | sed -n 's/.*pid=\([0-9]*\).*/\1/p')"
            [[ "$seen" == *" $proc:$port "* ]] && continue; seen+="$proc:$port "
            cmd="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | cut -c1-100)"; unit="$(ps -o unit= -p "$pid" 2>/dev/null | tr -d " ")"; [ "$unit" = - ] && unit=""
            if is_scoring "$proc" "$unit" "$cmd" "$(readlink "/proc/$pid/exe" 2>/dev/null)" "$(readlink "/proc/$pid/cwd" 2>/dev/null)"; then
                fnd 3 info "" "$pid" s "$SCORING_TXT: listener ${line%% *} $addr $proc (pid $pid)" ""; continue
            fi
            local lk=s exe; exe="$(readlink "/proc/$pid/exe" 2>/dev/null)"
            printf '%s\n' "$proc $cmd" "$exe" | grep -qE "$UNIT_BAD_RE|^/(tmp|dev/shm|var/tmp)/" && lk=k   # nc/socat/http.server/bash -i/tmp binary
            fnd 1 listener "" "$pid" "$lk" "unexpected listener: ${line%% *} $addr  $proc (pid $pid)" "kill/stop it (k) unless the README needs it; also check cron + units" \
                "cmd: ${cmd:-?}" "unit: ${unit:-none}"
        done < "$SS_CACHE"
        return
    fi
    local found=0
    while IFS= read -r line; do
        proc="$(echo "$line" | sed -n 's/.*users:(("\([^"]*\)".*/\1/p')"
        [[ " ${PROCS[$SVC]} " == *" $proc "* ]] || [[ "$SVC" == php && "$proc" == php-fpm* ]] || continue
        found=1
        addr="$(echo "$line" | awk '{print $5}')"; port="${addr##*:}"
        r "   $proc listening on $addr"
        [[ "$seen" == *" $addr "* ]] && continue; seen+="$addr "
        [[ " ${PORTS[$SVC]:-} " == *" $port "* ]] || { [ "$SVC" = vsftpd ] && [ "$port" -ge 1024 ] 2>/dev/null; } \
            || { [ "$SVC" = squid ] && [[ "$line" == udp* ]] && [ "$port" -ge 32768 ] 2>/dev/null; } \
            || fnd 2 note "" "$addr" s "$proc listens on an unexpected port $addr (default: ${PORTS[$SVC]:-none})" "fine if the README sets this port; else ${HARDEN[$SVC]:-the service script} / config"
        case "$SVC" in mysql|postgresql)
            [[ "$addr" == 0.0.0.0:* || "$addr" == "[::]:"* || "$addr" == "*:"* ]] && \
                fnd 1 note "" "$addr" s "$proc listens on ALL interfaces ($addr) - should normally be localhost" "bind to 127.0.0.1 unless the README needs remote DB access (${HARDEN[$SVC]})" ;;
        esac
    done < "$SS_CACHE"
    if [ "$found" = 0 ] && [ "$SVC" != php ]; then   # only with a daemon unit (samba-common alone has none); php-fpm uses a socket
        local u; for u in ${UNITS[$SVC]:-}; do
            [ "$(systemctl show -p LoadState --value "$u" 2>/dev/null)" = loaded ] && { fnd 3 info "" "" s "$SVC is not listening - is it running? (a critical service must stay up)" ""; break; }
        done
    fi
    if [ -f "$PACK_DIR/$SVC/listen.txt" ]; then r "   clean-VM listeners:"; sed 's/^/     /' "$PACK_DIR/$SVC/listen.txt" >> "$REPORT"; fi
}

# ================================================================ B7 --
ACCOUNTS=""
b7_accounts() {
    local a def name
    case "$SVC" in mysql|postgresql|samba|wordpress) ;; *) return ;; esac
    rhdr "B7 service-internal accounts vs defaults"
    case "$SVC" in
        mysql) def=" root@localhost mysql.sys@localhost mysql.session@localhost mysql.infoschema@localhost debian-sys-maint@localhost mysql@localhost mariadb.sys@localhost " ;;
        postgresql) def=" postgres " ;;
        *) def=" " ;;
    esac
    [ -n "$ACCOUNTS" ] || { r "   (could not query accounts - is the service running / reachable as root?)"; return; }
    local clean=""; [ -f "$PACK_DIR/$SVC/accounts.txt" ] && clean=" $(tr '\n' ' ' < "$PACK_DIR/$SVC/accounts.txt") "
    while IFS= read -r a; do
        name="${a%% *}"
        case "$SVC" in
            wordpress)
                local login="${a#*: }"; login="${login%% *}"
                # the scan never knows the README: every WordPress admin is shown for a README check
                if [[ "$a" == *administrator* ]]; then
                    fnd 2 account "" "$login" s "B7 WordPress administrator (check README): $a" "check the README; keep only README admins (wordpress.sh lists admins)"
                else r "   $a"; fi
                continue ;;
            samba)   # clean install has none (pack accounts.txt); the scan never knows the README
                if [ -n "$clean" ] && [[ "$clean" == *" $name "* ]]; then r "   on the clean VM too: $name"; continue; fi
                fnd 2 account "" "$name" s "Samba account not in a default install (check the README): $name" "check the README; remove it (k = smbpasswd -x) if not an authorized user"
                continue ;;
        esac
        if [[ "$def" == *" $name "* ]]; then
            if [ -n "$clean" ] && [[ "$clean" != *" $name "* ]]; then r "   default, but not on the clean VM: $a"; else r "   default: $a"; fi
            continue
        fi
        if [ "$SVC" = mysql ]; then
            fnd 1 account "" "$name" s "MySQL account not in a default install: $name$([[ "$name" == *@% ]] && echo "  - reachable from ANY host")" \
                "DROP it (k) unless the README needs it; mysql.sh audits accounts"
        else
            fnd 1 account "" "$name" s "PostgreSQL role not in a default install: $a$([[ "$a" == *super=t* ]] && echo "  - SUPERUSER")" \
                "DROP it (k) unless the README needs it; postgresql.sh audits roles"
        fi
    done <<< "$ACCOUNTS"
}

# ================================================================ B8 --
b8_content() {
    local d f
    [ -n "${CONTENT[$SVC]:-}" ] || return
    rhdr "B8 web / FTP content vs default (full list: $SVC_DIR/content.txt)"
    : > "$SVC_DIR/content.txt"
    for d in ${CONTENT[$SVC]}; do
        [ -d "$d" ] || continue
        find "$d" -xdev -type f -printf '%TY-%Tm-%Td %TH:%TM %u:%g %m %p\n' 2>/dev/null | sort >> "$SVC_DIR/content.txt"
    done
    local count; count="$(wc -l < "$SVC_DIR/content.txt")"
    r "   $count file(s) in content dirs (a clean install ships only index.html / index.nginx-debian.html)"
    [ "$count" -le 40 ] && sed 's/^/     /' "$SVC_DIR/content.txt" >> "$REPORT"
    local nd; nd="$(grep -cvE ' (/var/www/html/index\.html|/var/www/html/index\.nginx-debian\.html|/usr/share/nginx/html/[^/]+)$' "$SVC_DIR/content.txt")"
    [ "$nd" -gt 0 ] && fnd 3 info "" "" s "$nd non-default file(s) in ${CONTENT[$SVC]} (list: $SVC_DIR/content.txt)" ""
    declare -A SEEN8=()
    for d in ${CONTENT[$SVC]}; do
        [ -d "$d" ] || continue
        while IFS= read -r f; do
            [ -n "${SEEN8[$f]+x}" ] && continue; SEEN8[$f]=1
            fnd 1 planted "$f" "" q "phpinfo() file: $f" "quarantine (q)" "$(grep -m1 -aiE 'phpinfo[[:space:]]*\(' "$f" | cut -c1-100)"
        done < <(grep -rlsiE 'phpinfo[[:space:]]*\(' "$d" 2>/dev/null)
        while IFS= read -r f; do
            [ -n "${SEEN8[$f]+x}" ] && continue; SEEN8[$f]=1
            fnd 1 planted "$f" "" s "webshell indicator: $f" "look (d); quarantine (q) if it is not README site code" \
                "$(grep -m1 -anE 'eval[[:space:]]*\(|base64_decode[[:space:]]*\(|shell_exec[[:space:]]*\(|passthru[[:space:]]*\(|system[[:space:]]*\(\$_|\$_(GET|POST|REQUEST)\[' "$f" | cut -c1-100)"
        done < <(grep -rlsE 'eval[[:space:]]*\(|base64_decode[[:space:]]*\(|shell_exec[[:space:]]*\(|passthru[[:space:]]*\(|system[[:space:]]*\(\$_|\$_(GET|POST|REQUEST)\[[^]]*\][[:space:]]*\(' "$d" --include='*.php' --include='*.phtml' --include='*.inc' 2>/dev/null | head -30)
        while IFS= read -r f; do
            [ -n "${SEEN8[$f]+x}" ] && continue
            fnd 2 perm "$f" "chown:root:root" s "unusual owner in content dir: $(stat -c '%U:%G %a' "$f") $f" "fix (f) -> root:root, or check the README"
        done < <(find "$d" -xdev ! -user root ! -user www-data ! -user ftp ! -group www-data 2>/dev/null | head -30)
        while IFS= read -r f; do
            [ -n "${SEEN8[$f]+x}" ] && continue
            fnd 2 planted "$f" "" s "hidden file/dir in content dir: $f" "look (d); quarantine (q) if planted"
        done < <(find "$d" -xdev -name '.*' ! -name '.htaccess' ! -name '.well-known' 2>/dev/null | head -30)
        while IFS= read -r f; do r "   .htaccess present (review, do not blindly delete): $f"; done < <(find "$d" -xdev -name '.htaccess' 2>/dev/null)
    done
}

# ================================================================ B9 --
b9_snapshot() {
    local dest p
    if [ -d "$SVC_DIR/before" ]; then dest="$SVC_DIR/runs/$CP_TS"; else dest="$SVC_DIR/before.tmp"; fi
    mkdir -p "$dest"
    # shellcheck disable=SC2086
    for p in $(existing_paths ${DIRS[$SVC]}); do cp -a --parents "$p" "$dest/" 2>/dev/null; done
    for p in ${UNITS[$SVC]:-}; do systemctl cat "$p" > "$dest/unit-$p.txt" 2>/dev/null || rm -f "$dest/unit-$p.txt"; done
    cp "$SS_CACHE" "$dest/listening.txt" 2>/dev/null
    [ -f "$SVC_DIR/content.txt" ] && cp "$SVC_DIR/content.txt" "$dest/"
    printf '%s\n' "$ACCOUNTS" > "$dest/accounts.txt"
    # before/ appears only when complete: the gate treats it as "this service has a baseline"
    [ "$dest" = "$SVC_DIR/before.tmp" ] && { mv "$dest" "$SVC_DIR/before"; dest="$SVC_DIR/before"; }
    rhdr "B9 snapshot of live state saved to $dest (rollback point + FQ evidence)"
}

# ============================================================ one service --
scan_svc() {
    SVC="$1"; SVC_DIR="$CP_BASELINE_DIR/$SVC"
    mkdir -p "$SVC_DIR"
    REPORT="$SVC_DIR/report.txt"; PATCH="$SVC_DIR/diff.patch"; PAIRS="$SVC_DIR/pairs.txt"; TSV="$SVC_DIR/findings.tsv.tmp"
    : > "$REPORT"; : > "$PATCH"; : > "$PAIRS"; : > "$TSV"; rm -f "$SVC_DIR/.done"
    r "Baseline report: $SVC   host: $(hostname)   os: $OSID   time: $(date)"
    r "Lines starting with '!!' are findings (FIX NOW / REVIEW). Nothing was changed. Triage: sudo bash services/baseline.sh --review $SVC"
    pack_covers "$SVC" && r "Known good: baseline pack $PACK_DIR/$SVC" || r "Known good: on-image pristine copies / downloaded packages (no pack for $SVC)"
    # services without a pack: wait (max 25 s) for this service's background downloads
    if ! pack_covers "$SVC" && [ "$DO_DOWNLOAD" = 1 ]; then
        local p waited=0
        for p in $(installed_pkgs "$SVC"); do
            deb_has_conf "$p" || continue
            while [ ! -e "$PRISTINE_DEBS/$p/.tried" ] && [ ! -d "$PRISTINE_DEBS/$p/root" ] && [ "$waited" -lt 50 ]; do sleep 0.5; waited=$((waited + 1)); done
        done
    fi
    ACCOUNTS="$(accounts_raw "$SVC")"
    local s
    local t0 t1
    for s in b1_integrity b2_config b3_unowned b4_perms b5_units b6_ports b7_accounts b8_content b9_snapshot; do
        t0="$(date +%s%N)"; "$s"; t1="$(date +%s%N)"
        echo "timing $SVC $s $(( (t1 - t0) / 1000000 )) ms"   # -> scan.log (profiling only)
    done
    dedupe "$TSV" | sort -t$'\t' -k1,1n -s > "$SVC_DIR/findings.tsv"; rm -f "$TSV"
    awk -F'\t' '{c[$1]++} END {printf "%d %d %d\n", c[1], c[2], c[3]}' "$SVC_DIR/findings.tsv" > "$SVC_DIR/.done"
}

# ============================================================ FINDINGS.txt --
# dedupe FILE... -> one line per finding: same kind+path (or svc+kind+aux) once; no separate perm line for a
# file that is already flagged as planted (quarantine handles it)
dedupe() {
    awk -F'\t' 'NR == FNR { if ($3 ~ /^(planted|unit|dropin|override)$/) pl[$4] = 1; next }
         $3 == "perm" && ($4 in pl) { next }
         { k = ($4 != "-") ? $3 "|" $4 : $2 "|" $3 "|" $5; if (k in seen) next; seen[k] = 1; print }' <(cat "$@") <(cat "$@")
}

# all_findings [svc...] -> TSV of every finding (latest scan of each service), de-duplicated across services
all_findings() {
    local s want=" $* " files=()
    for s in "${SVC_ORDER[@]}"; do
        [ $# -gt 0 ] && [[ "$want" != *" $s "* ]] && continue
        [ -f "$CP_BASELINE_DIR/$s/findings.tsv" ] && files+=("$CP_BASELINE_DIR/$s/findings.tsv")
    done
    [ ${#files[@]} -gt 0 ] || return 0
    dedupe "${files[@]}" | sort -t$'\t' -k1,1n -s
}

write_findings() {
    local tmp n1 n2 n3 when
    tmp="$(mktemp)"; when="$(date '+%Y-%m-%d %H:%M')"
    all_findings > "$tmp.tsv"
    n1="$(awk -F'\t' '$1==1' "$tmp.tsv" | wc -l)"; n2="$(awk -F'\t' '$1==2' "$tmp.tsv" | wc -l)"; n3="$(awk -F'\t' '$1==3' "$tmp.tsv" | wc -l)"
    {
        echo "BASELINE FINDINGS   FIX NOW: $n1   REVIEW: $n2   info: $n3      ($when, $OSID, pack: $( [ -d "$PACK_DIR" ] && basename "$PACK_DIR" || echo none))"
        echo "Detection only - nothing was changed.  Triage with one key per finding:  sudo bash services/baseline.sh --review [svc]"
        awk -F'\t' '
            function sect(p,   t) { if (p == cur) return; cur = p
                t = (p == 1) ? "FIX NOW - likely planted, act on these first" : (p == 2) ? "REVIEW - differs from the default; keep only what the README needs" : "INFO - no action needed"
                printf "\n=== %s ===\n", t }
            { sect($1)
              if ($1 == 3) { if (++ni > 15) { more++; next } }
              printf "[%s] %s\n", $2, $8
              if ($10 != "-" && $1 < 3) { n = split($10, d, "\037"); for (i = 1; i <= n; i++) printf "      %s\n", d[i] }
              if ($9 != "-" && $1 < 3) printf "      -> %s\n", $9 }
            END { if (more) printf "  ... %d more info line(s) in the per-service report.txt files\n", more
                  if (NR == 0) print "\nNo findings: every scanned service matches its known-good baseline." }' "$tmp.tsv"
        echo
        echo "Per-service detail: $CP_BASELINE_DIR/<svc>/report.txt   diffs: <svc>/diff.patch"
    } > "$tmp"
    mv -f "$tmp" "$FINDINGS"; chmod 600 "$FINDINGS"; rm -f "$tmp.tsv"
}

# print FINDINGS.txt (optionally only some services' lines), coloured on a TTY
print_findings() {
    local want=" $* "
    awk -v want="$want" -v R="$CP_C_RED" -v Y="$CP_C_YEL" -v C="$CP_C_CYN" -v O="$CP_C_OFF" '
        BEGIN { all = (want == "  ") }
        /^$/ { next }
        /^=== FIX NOW/ { hdr = R $0 O; skip = 1; next }
        /^=== REVIEW/  { hdr = Y $0 O; skip = 1; next }
        /^=== /        { hdr = C $0 O; skip = 1; next }
        /^\[[a-z0-9]+\] / { s = substr($1, 2, length($1) - 2); skip = (!all && index(want, " " s " ") == 0)
                           if (!skip) { shown++; if (hdr != "") { print ""; print hdr; hdr = "" } } }
        /^  \.\.\./ { if (!all) next }
        /^Per-service/ { w = want; gsub(/^ +| +$/, "", w); if (!shown) print "\nNo findings" (all ? "" : " for " w) "."; print ""; skip = 0 }
        /^BASELINE|^Detection/ { skip = 0 }
        /^No findings:/ { shown = 1 }
        !skip' "$FINDINGS"
}

# ============================================================== --review --
rv_key() {  # rv_key "allowed keys" default -> RK. Line input like every other prompt: key + Enter, Enter alone = default
    local line k
    while true; do
        IFS= read -r line || { RK=x; echo; return; }
        k="${line#"${line%%[![:space:]]*}"}"; k="${k:0:1}"; k="${k,,}"
        [ -z "$k" ] && k="$2"
        if [[ "$1" == *"$k"* ]]; then RK="$k"; return; fi
        printf '  ? type one of: %s then Enter (Enter alone = %s) > ' "$(printf '%s' "$1" | sed 's/./& /g')" "$2"
    done
}
yn_key() {  # yn_key "question" [y|n default, n if omitted]
    local d="${2:-n}"; if [ "$d" = y ]; then printf '  %s [Y/n] ' "$1"; else printf '  %s [y/N] ' "$1"; fi
    rv_key "yn" "$d"; [ "$RK" = y ]
}

svc_of_units_active() {  # active units of a service, aliases (ssh/sshd, named/bind9) once
    local u; for u in ${UNITS[$1]:-}; do systemctl is-active --quiet "$u" 2>/dev/null && systemctl show -p Id --value "$u" 2>/dev/null; done | awk '!seen[$0]++'
}
under_dirs() { local d; for d in ${DIRS[$1]:-}; do [[ "$2" == "$d" || "$2" == "$d"/* ]] && return 0; done; return 1; }

# validate_cfg SVC FILE -> 0 if the service config still parses (same checks the service scripts use)
validate_cfg() {
    local svc="$1" f="$2" out rc=0 t b
    case "$f" in
        /etc/sudoers|/etc/sudoers.d/*) out="$(visudo -c 2>&1)" || rc=1 ;;
        /etc/ssh/*) out="$(sshd -t 2>&1)" || rc=1 ;;
        /etc/apache2/*) out="$(apache2ctl configtest 2>&1)" || rc=1 ;;
        /etc/nginx/*) out="$(nginx -t 2>&1)" || rc=1 ;;
        /etc/bind/*|/etc/default/named) out="$(named-checkconf 2>&1)" || rc=1 ;;
        /etc/postfix/*|/etc/aliases|/etc/mailname) out="$(postfix check 2>&1)" || rc=1 ;;
        /etc/dovecot/*) out="$(doveconf -n 2>&1 >/dev/null)" || rc=1 ;;
        /etc/samba/*) out="$(testparm -s 2>&1 >/dev/null)" || rc=1 ;;
        /etc/squid/*) out="$(squid -k parse 2>&1)" || rc=1 ;;
        /etc/vsftpd*|/etc/ftpusers)
            b="$(command -v vsftpd || echo /usr/sbin/vsftpd)"
            if [ -x "$b" ]; then
                t="$(mktemp)"; cp /etc/vsftpd.conf "$t"
                cp_set "$t" listen_port 2121 eq; cp_set "$t" listen YES eq; cp_set "$t" listen_ipv6 NO eq
                timeout 2 "$b" "$t" >/dev/null 2>&1; [ $? -eq 124 ] || { rc=1; out="vsftpd refuses to start with this config"; }
                rm -f "$t"
            fi ;;
        /etc/mysql/*)
            if mysqld --verbose --help 2>/dev/null | grep -q -- '--validate-config'; then out="$(mysqld --validate-config 2>&1)" || rc=1
            else out="$( { mariadbd --help --verbose || mysqld --help --verbose; } 2>&1 >/dev/null | grep -E '\[ERROR\]|unknown (variable|option)')"; [ -z "$out" ] || rc=1; fi ;;
        /etc/php/*)
            for b in /usr/sbin/php-fpm*; do [ -x "$b" ] || continue; out="$("$b" -t 2>&1)" || { rc=1; break; }; done
            [ $rc = 0 ] && command -v apache2ctl >/dev/null && systemctl is-active --quiet apache2 && { out="$(apache2ctl configtest 2>&1)" || rc=1; } ;;
        */wp-config.php) command -v php >/dev/null && { out="$(php -l "$f" 2>&1)" || rc=1; } ;;
    esac
    [ $rc = 0 ] || { echo "$out" | tail -5 | sed 's/^/      /'; cp_err "config check failed for $f"; }
    return $rc
}

# restart_check SVC UNITS... -> restart each unit that was active, confirm it is active again
restart_check() {
    local svc="$1" u ok=0; shift
    for u in "$@"; do
        systemctl restart "$u" 2>/dev/null; sleep 1
        if systemctl is-active --quiet "$u"; then cp_ok "$u restarted and active"; else cp_err "$u is NOT active after restart"; ok=1; fi
    done
    return $ok
}

# undo actions, called directly with quoted arguments (never eval: planted file names can contain quotes)
undo_copy()  { cat -- "$1" > "$2"; }                       # undo_copy BACKUP FILE
undo_mv()    { mv -- "$1" "$2"; }                          # undo_mv QUARANTINED ORIGINAL
undo_rm()    { rm -f -- "$1"; }                            # undo_rm FILE
undo_perms() { chmod "$1" -- "$3"; chown "$2" -- "$3"; }   # undo_perms MODE USER:GROUP FILE

# apply_checked SVC FILE UNDO_FN ARGS... -> validate + restart the service; run the undo (and restart again) on failure
apply_checked() {
    local svc="$1" f="$2" units=(); shift 2
    [ "$svc" = system ] && { validate_cfg "$svc" "$f" && return 0; "$@"; cp_warn "rolled back $f"; return 1; }
    under_dirs "$svc" "$f" || return 0
    mapfile -t units < <(svc_of_units_active "$svc")
    if ! validate_cfg "$svc" "$f"; then "$@"; cp_warn "rolled back $f (nothing restarted)"; return 1; fi
    [ ${#units[@]} -gt 0 ] || return 0
    if ! restart_check "$svc" "${units[@]}"; then
        "$@"; cp_warn "rolled back $f"; restart_check "$svc" "${units[@]}"; return 1
    fi
}

readme_sensitive() {
    case "$1" in
        /etc/ssh/sshd_config|/etc/vsftpd.conf|/etc/vsftpd/*|/etc/vsftpd.*|/etc/ftpusers|/etc/samba/*|/etc/apache2/sites-*|/etc/apache2/ports.conf|\
        /etc/nginx/*|/etc/bind/named.conf*|/etc/bind/db.*|/etc/mysql/*|/etc/postgresql/*|/etc/postfix/*|/etc/aliases|/etc/dovecot/*|\
        /etc/squid/*|/etc/openvpn/*|/etc/php/*|*/wp-config.php) return 0 ;;
    esac
    return 1
}

rv_restore() {  # rv_restore SVC FILE PRISTINE
    local svc="$1" f="$2" p="$3" bk existed=0
    [ -f "$p" ] || { cp_err "no pristine copy"; return 1; }
    if readme_sensitive "$f"; then
        yn_key "$f can hold README-required settings (users, shares, ports, sites, zones). Restore the default anyway?" || return 1
    fi
    [ -e "$f" ] && existed=1
    cp_backup "$f" >/dev/null; bk="$CP_BACKUP_ROOT/$CP_TS$(readlink -f "$f" 2>/dev/null || echo "$f")"
    if [ $existed = 1 ]; then cat "$p" > "$f"
    else install -D -m 644 -o root -g root "$p" "$f"; fi
    if [ $existed = 1 ]; then apply_checked "$svc" "$f" undo_copy "$bk" "$f" || return 1
    else apply_checked "$svc" "$f" undo_rm "$f" || return 1; fi
    cp_ok "restored default content of $f  (backup: $bk)"
}

rv_quarantine() {  # rv_quarantine SVC KIND PATH AUX
    local svc="$1" kind="$2" f="$3" aux="$4" dest unit="" was_active=0 was_enabled=""
    [ -e "$f" ] || [ -L "$f" ] || { cp_warn "$f is already gone"; return 0; }
    case "$kind" in
        dropin) unit="$aux" ;;
        override|unit) unit="$(basename "$f")" ;;
    esac
    # restart afterwards if it was running, or is enabled (a planted drop-in may already have broken it)
    [ -n "$unit" ] && { systemctl is-active --quiet "$unit" || [ "$(systemctl is-enabled "$unit" 2>/dev/null)" = enabled ]; } && was_active=1
    if [ "$kind" = unit ]; then
        was_enabled="$(systemctl is-enabled "$unit" 2>/dev/null)"
        systemctl disable --now "$unit" >/dev/null 2>&1 && cp_ok "stopped + disabled $unit"
    fi
    # /etc/ld.so.preload: the rootkit library it lists goes too (later scripts can no longer find it via the file)
    local libs=() lib
    [ "$f" = /etc/ld.so.preload ] && mapfile -t libs < <(preload_libs "$f" | awk '$1 == "unowned" {print $2}')
    quar_move "$f" "${was_enabled:+  (unit was $was_enabled)}" || return 1
    dest="$QUAR_LAST"
    for lib in "${libs[@]}"; do quar_move "$lib" "  (listed in /etc/ld.so.preload)" && cp_ok "quarantined preloaded library $lib -> $QUAR_LAST"; done
    if [ -n "$unit" ]; then
        systemctl daemon-reload
        if [ "$kind" != unit ] && [ $was_active = 1 ]; then
            if ! restart_check "$svc" "$unit"; then
                undo_mv "$dest" "$f"; systemctl daemon-reload; cp_warn "put $f back"
                printf '%s  put back (service failed without it): %q\n' "$(date '+%F %T')" "$f" >> "$QUAR_DIR/INDEX.txt"
                restart_check "$svc" "$unit"; return 1
            fi
        fi
    elif under_dirs "$svc" "$f"; then
        apply_checked "$svc" "$f" undo_mv "$dest" "$f" || { printf '%s  put back (service failed without it): %q\n' "$(date '+%F %T')" "$f" >> "$QUAR_DIR/INDEX.txt"; return 1; }
    fi
    cp_ok "quarantined $f -> $dest   (undo: mv $(printf '%q %q' "$dest" "$f"))"
}

# quar_move FILE [NOTE] -> move FILE to $QUAR_DIR/<path> (never overwrite), log the undo in INDEX.txt; QUAR_LAST = new path
QUAR_LAST=""
quar_move() {
    local f="$1" dest="$QUAR_DIR$1"
    [ -e "$dest" ] && dest="$dest.$CP_TS"
    mkdir -p "$(dirname "$dest")" && chmod 700 "$QUAR_DIR"
    mv -- "$f" "$dest" || { cp_err "could not move $f"; return 1; }
    printf '%s  %q -> %q%s   undo: mv %q %q\n' "$(date '+%F %T')" "$f" "$dest" "${2:-}" "$dest" "$f" >> "$QUAR_DIR/INDEX.txt"
    QUAR_LAST="$dest"
}

rv_fixperm() {  # rv_fixperm SVC PATH SPEC
    local svc="$1" f="$2" spec="$3" m o om oo
    om="$(stat -c %a "$f")"; oo="$(stat -c %U:%G "$f")"
    mkdir -p "$CP_BACKUP_ROOT/$CP_TS" && printf 'chmod %s %q; chown %s %q\n' "$om" "$f" "$oo" "$f" >> "$CP_BACKUP_ROOT/$CP_TS/PERMS-UNDO.sh"
    case "$spec" in
        chmod:*) chmod "${spec#chmod:}" "$f" ;;
        chown:*) chown "${spec#chown:}" "$f" ;;
        set:*) m="$(echo "$spec" | cut -d: -f2)"; o="$(echo "$spec" | cut -d: -f3-)"; chmod "$m" "$f" && chown "$o" "$f" ;;
    esac || { cp_err "could not change $f"; return 1; }
    if [[ "$spec" != set:* ]] && [ "$svc" != system ]; then apply_checked "$svc" "$f" undo_perms "$om" "$oo" "$f" || return 1; fi
    cp_ok "$f is now $(stat -c '%a %U:%G' "$f")   (undo: $CP_BACKUP_ROOT/$CP_TS/PERMS-UNDO.sh)"
}

rv_edit() {  # rv_edit SVC FILE [PRISTINE]  (editor or meld), then validate + restart
    local svc="$1" f="$2" p="$3" tool="$4" before bk
    before="$(md5sum < "$f" 2>/dev/null)"
    cp_backup "$f" >/dev/null; bk="$CP_BACKUP_ROOT/$CP_TS$(readlink -f "$f")"
    if [ "$tool" = meld ]; then
        local xa="${XAUTHORITY:-}"
        [ -z "$xa" ] && [ -n "${SUDO_USER:-}" ] && xa="$(getent passwd "$SUDO_USER" | cut -d: -f6)/.Xauthority"
        DISPLAY="${DISPLAY:-:0}" XAUTHORITY="$xa" meld "$p" "$f" >/dev/null 2>&1
    else
        "${EDITOR:-$(command -v nano || echo vi)}" "$f"
    fi
    [ "$(md5sum < "$f" 2>/dev/null)" = "$before" ] && { echo "  (unchanged)"; return 1; }
    apply_checked "$svc" "$f" undo_copy "$bk" "$f" || return 1
    cp_ok "saved $f  (backup: $bk)"
}

rv_kill() {  # rv_kill PID [y] - stop its unit or kill the pid; y = confirmation defaults to yes (clearly planted)
    local pid="$1" cd="${2:-n}" unit cmd
    [ -d "/proc/$pid" ] || { cp_ok "process $pid is already gone"; return 0; }
    unit="$(ps -o unit= -p "$pid" 2>/dev/null | tr -d ' ')"; [ "$unit" = - ] && unit=""; cmd="$(tr '\0' ' ' < "/proc/$pid/cmdline" | cut -c1-80)"
    case "$unit" in
        ""|cron.service|anacron.service|atd.service|ssh.service|sshd.service|init.scope|user@*|session-*|systemd-*|lightdm.service|display-manager.service)
            yn_key "kill pid $pid ($cmd)?" "$cd" || return 1
            kill "$pid" 2>/dev/null; sleep 0.5; kill -9 "$pid" 2>/dev/null
            cp_ok "killed $pid - if it comes back, find what starts it (cron, unit, rc.local)" ;;
        *)
            yn_key "stop + disable $unit (pid $pid: $cmd)?" "$cd" || return 1
            systemctl disable --now "$unit" >/dev/null 2>&1; cp_ok "stopped + disabled $unit (undo: systemctl enable --now $unit)" ;;
    esac
}

rv_drop_account() {  # SVC ACCOUNT
    local svc="$1" a="$2" u h
    case "$svc" in
        mysql) u="${a%@*}"; h="${a##*@}"; yn_key "DROP USER '$u'@'$h' ?" || return 1
               mysql -e "DROP USER '${u//\'/\'\'}'@'${h//\'/\'\'}'" && cp_ok "dropped MySQL account $a" ;;
        postgresql) yn_key "DROP ROLE \"$a\" ?" || return 1
               sudo -u postgres psql -Xqc "DROP ROLE \"${a//\"/}\"" && cp_ok "dropped role $a" ;;
        samba) yn_key "remove Samba account $a (smbpasswd -x)?" || return 1
               smbpasswd -x "$a" >/dev/null && cp_ok "removed Samba account $a" ;;
        *) echo "  (do this one by hand: ${HARDEN[$svc]:-})"; return 1 ;;
    esac
}

rv_show() {  # rv_show KIND PATH AUX SVC
    local kind="$1" f="$2" aux="$3" svc="$4" n
    case "$kind" in
        cfgdiff)
            n="$(diff -u "$aux" "$f" | wc -l)"
            diff -u --color=always "$aux" "$f" 2>/dev/null | head -60
            [ "$n" -gt 60 ] && echo "  ... $((n - 60)) more lines: less $CP_BASELINE_DIR/$svc/diff.patch" ;;
        override) diff -u --color=always "$aux" "$f" 2>/dev/null | head -60 ;;
        listener) ps -o pid,user,etime,cmd -p "$aux" 2>/dev/null; echo "  unit: $(ps -o unit= -p "$aux" 2>/dev/null)  exe: $(readlink "/proc/$aux/exe" 2>/dev/null)" ;;
        account) [ "$svc" = mysql ] && mysql -NBe "SHOW GRANTS FOR '${aux%@*}'@'${aux##*@}'" 2>/dev/null | cut -c1-150 ;;
        trojan) ls -l "$f" 2>/dev/null; dpkg --verify "$aux" 2>/dev/null | head ;;
        perm|suid) ls -ld "$f" ;;
        *) if [ -d "$f" ]; then ls -la "$f" | head -20
           elif [ -f "$f" ]; then ls -l "$f"; head -c 3000 "$f" | cat -v | head -40; else echo "  ($f no longer exists)"; fi ;;
    esac
}

# rv_scoring KIND PATH AUX -> 0 if acting on this finding would touch the scoring engine
rv_scoring() {
    case "$1" in
        unit|unitexe|dropin|override) is_scoring "$2" "${2##*/}" "$3" "$(grep -sE '^[[:space:]]*(Exec[A-Za-z]*|WorkingDirectory)=' "$2")" ;;
        listener) is_scoring "$(ps -o comm= -p "$3" 2>/dev/null)" "$(ps -o unit= -p "$3" 2>/dev/null | tr -d ' ')" \
                      "$(tr '\0' ' ' < "/proc/$3/cmdline" 2>/dev/null)" "$(readlink "/proc/$3/exe" 2>/dev/null)" "$(readlink "/proc/$3/cwd" 2>/dev/null)" ;;
        *) return 1 ;;
    esac
}

# rv_resolved KIND PATH AUX SVC -> 0 if the finding no longer applies
# After --review: drop handled findings from findings.tsv (report.txt keeps the record), rebuild FINDINGS.txt
declare -A DONE_KEYS
prune_findings() {  # prune_findings [svc...]
    local f tmp prio svc kind path aux rest pa pp want=" $* "
    for f in "$CP_BASELINE_DIR"/*/findings.tsv; do
        [ -f "$f" ] || continue
        [ $# -gt 0 ] && [[ "$want" != *" $(basename "$(dirname "$f")") "* ]] && continue
        tmp="$(mktemp)"
        while IFS=$'\t' read -r prio svc kind path aux rest; do
            pp="$path"; [ "$pp" = - ] && pp=""; pa="$aux"; [ "$pa" = - ] && pa=""
            if [ "$prio" -le 2 ]; then
                [ -n "${DONE_KEYS["$svc|$kind|$pp|$pa"]+x}" ] && continue
                rv_resolved "$kind" "$pp" "$pa" "$svc" && continue
            fi
            printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$prio" "$svc" "$kind" "$path" "$aux" "$rest"
        done < "$f" > "$tmp"
        cat "$tmp" > "$f"; rm -f "$tmp"
    done
    write_findings
}

rv_resolved() {
    local kind="$1" f="$2" aux="$3"
    case "$kind" in
        planted|unit|dropin|override|unitexe) [ ! -e "$f" ] && [ ! -L "$f" ] ;;
        cfgdiff) [ -f "$aux" ] && cmp -s "$aux" "$f" ;;
        cfgmissing) [ -e "$f" ] ;;
        listener) [ ! -d "/proc/$aux" ] ;;
        trojan) [ -n "$aux" ] && ! dpkg --verify "$aux" 2>/dev/null | grep -qF " $f" ;;
        account)
            case "$4" in
                mysql) local n; n="$(mysql -NBe "SELECT COUNT(*) FROM mysql.user WHERE CONCAT(user,'@',host)='${aux//\'/\'\'}'" 2>/dev/null)"; [ "$n" = 0 ] ;;
                samba) command -v pdbedit >/dev/null && ! pdbedit -L 2>/dev/null | cut -d: -f1 | grep -qxF -- "$aux" ;;
                postgresql) [ "$(sudo -u postgres psql -AtXc "SELECT COUNT(*) FROM pg_roles WHERE rolname='${aux//\'/\'\'}'" 2>/dev/null)" = 0 ] ;;
                *) return 1 ;;
            esac ;;
        suid) [ -e "$f" ] && [ -z "$(find "$f" -maxdepth 0 \( -perm -4000 -o -perm -2000 \))" ] ;;
        perm)
            [ -e "$f" ] || return 0
            case "$aux" in
                chmod:o-w) [ -z "$(find "$f" -maxdepth 0 -perm -0002)" ] ;;
                set:*) [ "$(stat -c '%a %U:%G' "$f")" = "$(echo "$aux" | cut -d: -f2) $(echo "$aux" | cut -d: -f3-)" ] ;;
                chown:root*) [ "$(stat -c %U "$f")" = root ] ;;
                chmod:700) [ "$(stat -c %a "$f")" = 700 ] ;;
                *) return 1 ;;
            esac ;;
        *) return 1 ;;
    esac
}

# --review has run (marker only)
review_ran() {
    touch "$CP_BASELINE_DIR/.reviewed"
}

review_main() {
    if [ ! -t 0 ] || [ ! -t 1 ]; then
        echo "--review is interactive - run it in a terminal. Findings: $FINDINGS"; exit 1
    fi
    trap 'review_ran; cp_todo_recap' EXIT
    local have=0 s
    for s in "${TARGETS[@]:-${SVC_ORDER[@]}}"; do [ -f "$CP_BASELINE_DIR/$s/findings.tsv" ] && have=1; done
    if [ "$have" = 0 ]; then
        echo "No scan results yet - scanning first (detection only)..."
        bash "$0" "${TARGETS[@]}" >/dev/null || { echo "Could not scan ${TARGETS[*]:-anything} (not installed?) - see: sudo bash services/baseline.sh --list"; exit 1; }
    fi
    local items=() total i=0 done_n=0 skip_n=0 auto_n=0 line
    mapfile -t items < <(all_findings "${TARGETS[@]}" | awk -F'\t' '$1 <= 2')
    total=${#items[@]}
    [ "$total" -gt 0 ] || { cp_ok "No FIX NOW / REVIEW findings$([ ${#TARGETS[@]} -gt 0 ] && echo " for ${TARGETS[*]}")."; exit 0; }
    local nfix; nfix="$(printf '%s\n' "${items[@]}" | awk -F'\t' '$1 == 1' | wc -l)"
    echo "Baseline triage: $nfix FIX NOW, then $((total - nfix)) REVIEW (asked once). Type a key + Enter; Enter alone = the [default];"
    echo "x = exit. Every change is backed up, quarantine moves files to $QUAR_DIR (undo in INDEX.txt), services are re-checked."
    local asked_review=""
    for line in "${items[@]}"; do
        i=$((i + 1))
        local prio svc kind path aux dflt md5 what hint det keys menu tag
        IFS=$'\t' read -r prio svc kind path aux dflt md5 what hint det <<< "$line"
        [ "$path" = - ] && path=""; [ "$aux" = - ] && aux=""; [ "$hint" = - ] && hint=""; [ "$det" = - ] && det=""
        if [ "$prio" = 2 ] && [ -z "$asked_review" ]; then   # FIX NOW done: REVIEW items only on request
            asked_review=1
            local nrev=0 l2 p2 k2 pa2 ax2 s2 _r
            for l2 in "${items[@]:$((i - 1))}"; do
                IFS=$'\t' read -r p2 s2 k2 pa2 ax2 _r <<< "$l2"; [ "$pa2" = - ] && pa2=""; [ "$ax2" = - ] && ax2=""
                rv_resolved "$k2" "$pa2" "$ax2" "$s2" || nrev=$((nrev + 1))
            done
            [ "$nrev" -gt 0 ] || break
            echo
            echo "  REVIEW = config/perms that differ from the default. The hardening scripts fix most of these later."
            yn_key "Also go through the $nrev REVIEW item(s)?" || { skip_n=$((skip_n + nrev)); break; }
        fi
        if rv_resolved "$kind" "$path" "$aux" "$svc"; then auto_n=$((auto_n + 1)); continue; fi
        if rv_scoring "$kind" "$path" "$aux"; then echo; echo "  (skipping $what - $SCORING_TXT)"; continue; fi
        local changed=""
        if [ -n "$path" ] && [ -f "$path" ] && [ "$md5" != - ] && [ "$(md5sum < "$path" | cut -c1-32)" != "$md5" ]; then
            changed=1; dflt=s
        fi
        case "$kind" in
            cfgdiff)    keys="drem"; menu="d=diff  r=restore default  e=edit" ;;
            cfgnop)     keys="de";   menu="d=show  e=edit" ;;
            cfgmissing) keys="r";    menu="r=restore default" ;;
            planted|unit|dropin|override|unitexe) keys="dqe"; menu="d=show  q=quarantine  e=edit"
                        [ "$kind" = unit ] && menu="d=show  q=quarantine (stop+disable+move)  e=edit" ;;
            perm|suid)  keys="df";   menu="d=show  f=fix -> $(spec_txt "$aux")" ;;
            trojan)     keys="di";   menu="d=show  i=reinstall $aux" ;;
            listener)   keys="dk";   menu="d=show  k=kill/stop" ;;
            account)    keys="dk";   menu="d=show  k=drop account" ;;
            *)          keys="";     menu="" ;;
        esac
        [ -n "$path" ] && [ -f "$path" ] && [[ "$kind" == cfgdiff ]] && command -v meld >/dev/null && { keys+="m"; menu+="  m=meld"; }
        [[ "$keys" == *"$dflt"* ]] || dflt=s
        local short="${path##*/}"; [ -n "$short" ] || short="$aux"; [ "$kind" = listener ] && short="pid $aux"; short="${short:0:40}"
        [ "$prio" = 1 ] && tag="${CP_C_RED}FIX NOW${CP_C_OFF}" || tag="${CP_C_YEL}REVIEW${CP_C_OFF}"
        echo
        echo "${CP_C_CYN}--- $i/$total${CP_C_OFF}  $tag  [$svc]  $what"
        [ -n "$det" ] && printf '%s\n' "$det" | tr '\037' '\n' | sed 's/^/      /'
        [ -n "$hint" ] && echo "      -> $hint"
        [ -n "$changed" ] && echo "      (changed since the scan - e.g. by a hardening script; default is skip)"
        while true; do
            local dname; case "$dflt" in q) dname=quarantine ;; f) dname=fix ;; i) dname=reinstall ;; r) dname=restore ;; k) dname="kill" ;; *) dname=skip ;; esac
            printf '  %s: %s  s=skip  x=exit  [Enter=%s] > ' "$short" "$menu" "$dname"
            rv_key "${keys}sx" "$dflt"
            local ok=1
            case "$RK" in
                d) rv_show "$kind" "$path" "$aux" "$svc"; continue ;;
                s) skip_n=$((skip_n + 1)); break ;;
                x) echo "  stopped at $i/$total"; break 2 ;;
                r) rv_restore "$svc" "$path" "$aux" && ok=0 ;;
                e) rv_edit "$svc" "$path" "$aux" && ok=0 ;;
                m) rv_edit "$svc" "$path" "$aux" meld && ok=0 ;;
                q) [ "$kind" = unitexe ] && systemctl stop "$aux" 2>/dev/null
                   rv_quarantine "$svc" "$kind" "$path" "$aux" && ok=0 ;;
                f) rv_fixperm "$svc" "$path" "$aux" && ok=0 ;;
                i) echo "  reinstalling $aux (needs working APT sources; waits if another apt job holds the lock)..."
                   cp_backup "$path" >/dev/null
                   if DEBIAN_FRONTEND=noninteractive cp_apt install --reinstall -y -o Dpkg::Options::=--force-confold "$aux" >/tmp/cp-reinstall.log 2>&1 \
                      && ! dpkg --verify "$aux" 2>/dev/null | grep -qF " $path"; then
                       cp_ok "reinstalled $aux - $path matches the package again"; ok=0
                       mapfile -t _u < <(svc_of_units_active "$svc"); [ ${#_u[@]} -gt 0 ] && restart_check "$svc" "${_u[@]}"
                   else cp_err "reinstall failed (tail /tmp/cp-reinstall.log) - fix APT sources first"; fi ;;
                k) if [ "$kind" = listener ]; then rv_kill "$aux" "$([ "$dflt" = k ] && echo y)" && ok=0
                   else rv_drop_account "$svc" "$aux" && ok=0; fi ;;
            esac
            if [ $ok = 0 ]; then done_n=$((done_n + 1)); DONE_KEYS["$svc|$kind|$path|$aux"]=1; break; fi
            dflt=s   # failed / cancelled: same finding again, Enter now skips
        done
    done
    prune_findings
    echo
    cp_ok "Triage done: $done_n changed, $skip_n skipped, $auto_n already resolved."
    echo "  Backups: $CP_BACKUP_ROOT/$CP_TS   Quarantine: $QUAR_DIR/INDEX.txt"
    echo "  Re-scan to confirm: sudo bash services/baseline.sh ${TARGETS[*]}"
}

if [ "$MODE" = review ]; then review_main; exit 0; fi
if [ "$MODE" = prune ]; then   # skip while a scan is writing results (it produces fresh ones anyway)
    exec 9>"$CP_BASELINE_DIR/.scan.lock"; flock -n 9 || exit 0
    prune_findings "${TARGETS[@]}"; exit 0
fi

# ================================================================= scan --
mkdir -p "$CP_BASELINE_DIR" && chmod 700 "$CP_BASELINE_DIR"
START_EPOCH="$(date +%s)"
exec 9>"$CP_BASELINE_DIR/.scan.lock"
if ! flock -n 9; then
    echo "Another baseline scan is running - waiting for it to finish..."
    flock 9
fi
explicit=${#TARGETS[@]}
if [ "$explicit" -eq 0 ]; then
    for s in "${SVC_ORDER[@]}"; do detected "$s" && TARGETS+=("$s"); done
fi
for s in "${SVC_ORDER[@]}"; do detected "$s" && [ "$s" != system ] && ALL_PROCS+="${PROCS[$s]:-} "; done

RUN=(); JUST=()
for svc in "${TARGETS[@]}"; do
    if [ -z "${DIRS[$svc]+x}" ]; then echo "Unknown service '$svc' (see --list)"; continue; fi
    if ! detected "$svc"; then echo "Skipping $svc: not installed"; continue; fi
    # scanned by the run we just waited for?
    if [ -f "$CP_BASELINE_DIR/$svc/.done" ] && [ "$(stat -c %Y "$CP_BASELINE_DIR/$svc/.done")" -ge "$START_EPOCH" ]; then
        echo "  $svc: just scanned by the other run"; JUST+=("$svc"); continue
    fi
    RUN+=("$svc")
done
if [ ${#RUN[@]} -eq 0 ]; then   # nothing left to scan
    if [ ${#JUST[@]} -gt 0 ]; then print_findings "${JUST[@]}"; exit 0; fi
    [ "$explicit" -gt 0 ] && exit 3   # requested service(s) not installed / unknown
    exit 0
fi

echo "Baseline scan - detection only, nothing is changed.  OS: $OSID   services: ${RUN[*]}"
if [ -d "$PACK_DIR" ]; then echo "  known good: baseline pack $(basename "$PACK_DIR") (no network needed)"
else echo "  known good: no pack for $OSID - on-image pristine copies + package downloads"; fi

# shared, read-only inputs for the parallel jobs
cp_owned_index
ss -H -tulpn > "$SS_CACHE" 2>/dev/null

# pristine .debs: only for services the pack does not cover, all in parallel, 20 s cap each
DL=()
if [ "$DO_DOWNLOAD" = 1 ]; then
    for svc in "${RUN[@]}"; do
        pack_covers "$svc" && continue
        for p in $(installed_pkgs "$svc"); do
            deb_has_conf "$p" || continue
            [ -d "$PRISTINE_DEBS/$p/root" ] || [ -e "$PRISTINE_DEBS/$p/.tried" ] || DL+=("$p")
        done
    done
fi
if [ ${#DL[@]} -gt 0 ]; then
    mapfile -t DL < <(printf '%s\n' "${DL[@]}" | sort -u)
    echo "  downloading ${#DL[@]} pristine package(s) in the background (20 s cap each; --no-download skips): ${DL[*]}"
    ( for p in "${DL[@]}"; do
          while [ "$(jobs -rp | wc -l)" -ge 4 ]; do sleep 0.2; done
          fetch_deb_now "$p" &
      done; wait ) &
fi

# per-service scans in parallel (each writes only its own dir); longest first
JOBS="${CP_BASELINE_JOBS:-3}"
ORDERED=(); for s in "${RUN[@]}"; do [ "$s" = system ] && ORDERED+=("$s"); done
for s in "${RUN[@]}"; do [ "$s" != system ] && ORDERED+=("$s"); done
declare -A PID_OF
REMAIN=("${ORDERED[@]}")
reap() {
    local s c
    for s in "${!PID_OF[@]}"; do
        kill -0 "${PID_OF[$s]}" 2>/dev/null && continue
        wait "${PID_OF[$s]}" 2>/dev/null
        if [ -f "$CP_BASELINE_DIR/$s/.done" ]; then
            read -r -a c < "$CP_BASELINE_DIR/$s/.done"
            printf '  [%3ss] %-10s FIX NOW %-3s REVIEW %-3s info %s\n' "$(( $(date +%s) - START_EPOCH ))" "$s" "${c[0]}" "${c[1]}" "${c[2]}"
        else
            printf '  [%3ss] %-10s scan FAILED - see %s\n' "$(( $(date +%s) - START_EPOCH ))" "$s" "$CP_BASELINE_DIR/$s/scan.log"
        fi
        unset "PID_OF[$s]"
    done
}
while [ ${#REMAIN[@]} -gt 0 ] || [ ${#PID_OF[@]} -gt 0 ]; do
    while [ ${#REMAIN[@]} -gt 0 ] && [ ${#PID_OF[@]} -lt "$JOBS" ]; do
        s="${REMAIN[0]}"; REMAIN=("${REMAIN[@]:1}")
        mkdir -p "$CP_BASELINE_DIR/$s"
        ( scan_svc "$s" ) > "$CP_BASELINE_DIR/$s/scan.log" 2>&1 &
        PID_OF[$s]=$!
    done
    sleep 0.3
    reap
done
wait 2>/dev/null

write_findings
echo
if [ "$explicit" -gt 0 ]; then print_findings "${RUN[@]}"; else print_findings; fi
read -r N1 N2 _ < <(all_findings | awk -F'\t' '{c[$1]++} END {printf "%d %d\n", c[1], c[2]}')
echo "Scan finished in $(( $(date +%s) - START_EPOCH ))s.  Saved: $FINDINGS"

# --meld: every changed config of the scanned services in ONE Meld window (tabs)
if [ "$DO_MELD" = 1 ]; then
    MARGS=()
    for s in "${RUN[@]}"; do
        while IFS='|' read -r p l; do [ -f "$p" ] && [ -f "$l" ] && MARGS+=(--diff "$p" "$l"); done < "$CP_BASELINE_DIR/$s/pairs.txt"
    done
    if [ ${#MARGS[@]} -eq 0 ]; then echo "  --meld: no changed config files to compare"
    else
        if ! command -v meld >/dev/null && [ -t 0 ]; then
            cp_ask "Meld is not installed. Install it (apt-get install meld)?" y && cp_apt install -y meld >/dev/null 2>&1
        fi
        if command -v meld >/dev/null; then
            XA="${XAUTHORITY:-}"; [ -z "$XA" ] && [ -n "${SUDO_USER:-}" ] && XA="$(getent passwd "$SUDO_USER" | cut -d: -f6)/.Xauthority"
            echo "  opening $(( ${#MARGS[@]} / 3 )) comparison(s) in Meld (left = default, right = live; save to apply)"
            DISPLAY="${DISPLAY:-:0}" XAUTHORITY="$XA" setsid meld "${MARGS[@]}" >/dev/null 2>&1 &
            echo "  after merging, re-run the service script (it validates + restarts), or use --review for checked restores"
        fi
    fi
fi

# one question on a terminal (stdin AND stdout: the gate and background runs redirect output and are never asked)
if [ -t 0 ] && [ -t 1 ] && [ $((N1 + N2)) -gt 0 ]; then
    echo
    if cp_ask "Go through the findings now (review: fix / quarantine / skip each)?" n; then
        exec 9>&-   # release the scan lock before acting
        [ "$explicit" -gt 0 ] && TARGETS=("${RUN[@]}") || TARGETS=()
        review_main; exit 0
    fi
    echo "  Later: sudo bash services/baseline.sh --review"
fi
exit 0
