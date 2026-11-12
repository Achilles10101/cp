#!/bin/bash
# vsftpd Security Configuration Script
# Research-doc items: FTP1-FTP10, G1-G3, G5 (baseline first: section B)
#
# Usage: sudo bash services/vsftpd.sh [--reask]
# README answers are asked once and kept in /root/cp-state/readme.conf, so a re-run asks nothing:
#   FTP_ANON (YES|NO)  FTP_WRITE (YES|NO)  FTP_FORCE_SSL (YES|NO)  FTP_CHROOT (a|b)  FTP_PASV_MIN  FTP_PASV_MAX
#   --reask   forget those answers and ask again

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../cp-common.sh
source "$SCRIPT_DIR/../cp-common.sh" 2>/dev/null || { echo "ERROR: cp-common.sh not found (keep the repo layout intact)"; exit 1; }

# ---- local helpers (same block in every services/*.sh; cp-common.sh is shared/owned elsewhere) ----
SVC=vsftpd; SVC_T0=$SECONDS
svc_result() { mkdir -p "$CP_STATE_DIR/svc" 2>/dev/null && echo "$*" > "$CP_STATE_DIR/svc/$SVC.result"; }
svc_snap()   { find "$@" -xdev \( -type f -o -type l \) -print0 2>/dev/null | LC_ALL=C sort -z | xargs -0 -r md5sum 2>/dev/null | md5sum | cut -c1-32; }
svc_forget() { [ -f "$CP_CFG" ] && sed -i -E "/^($(echo "$*" | tr ' ' '|'))=/d" "$CP_CFG"; }
svc_keys()   { awk '{ sub(/^[ \t]+/, ""); if ($0 == "" || $0 ~ /^[#;]/) next; p = index($0, "=");
                      if (p) { k = substr($0, 1, p - 1); sub(/[ \t]+$/, "", k) } else k = $1
                      if (!s[k]++) { n++; if (n <= 12) printf "%s ", k } } END { if (n > 12) printf "(+%d more)", n - 12 }'; }
svc_changes() {  # svc_changes PATH... -> one line per config file this run changed (vs. its cp_backup copy)
    local p rp b line bf lf k any=0
    for p in "$@"; do
        rp="$(readlink -f "$p" 2>/dev/null)"; b="$CP_BACKUP_ROOT/$CP_TS$rp"
        [ -n "$rp" ] && [ -e "$b" ] || continue
        while IFS= read -r line; do
            any=1
            case "$line" in
                "Files "*) bf="${line#Files }"; bf="${bf%% and *}"; lf="${line#* and }"; lf="${lf% differ}"
                           k="$(diff "$bf" "$lf" 2>/dev/null | sed -n 's/^> //p' | svc_keys)"; echo "      ~ $lf: ${k:-(lines removed)}" ;;
                "Only in $rp"*) echo "      + new file: $(echo "${line#Only in }" | sed 's#: #/#')" ;;
                "Only in $b"*)  echo "      - removed: $(echo "${line#Only in "$CP_BACKUP_ROOT/$CP_TS"}" | sed 's#: #/#')" ;;
            esac
        done < <(if [ -d "$rp" ]; then diff -rq "$b" "$rp" 2>/dev/null; else cmp -s "$b" "$rp" || echo "Files $b and $rp differ"; fi)
    done
    [ $any = 1 ] || echo "      (no config file changed - already hardened)"
}
# ------------------------------------------------------------------------------------------------

cp_require_root
[ "${1:-}" = "--reask" ] && svc_forget FTP_ANON FTP_WRITE FTP_FORCE_SSL FTP_CHROOT FTP_PASV_MIN FTP_PASV_MAX
cp_hdr "vsftpd hardening"
cp_screenshot_prompt
command -v vsftpd >/dev/null 2>&1 || [ -x /usr/sbin/vsftpd ] || { echo "ERROR: vsftpd is not installed"; svc_result FAIL "not installed"; exit 1; }

cp_baseline_gate vsftpd

# The unit may start vsftpd with a config file other than /etc/vsftpd.conf (B5) - harden the one in use.
CONF="/etc/vsftpd.conf"
UNIT_CONF="$(systemctl cat vsftpd 2>/dev/null | sed -n 's/^ExecStart=[^ ]*vsftpd[[:space:]]\+\([^ ]*\.conf\).*/\1/p' | tail -1)"
if [ -n "$UNIT_CONF" ] && [ "$UNIT_CONF" != "$CONF" ]; then
    cp_warn "vsftpd.service starts vsftpd with $UNIT_CONF (not $CONF)"
    cp_ask "Harden $UNIT_CONF instead?" y && CONF="$UNIT_CONF"
fi
[ -f "$CONF" ] || { echo "ERROR: $CONF not found"; svc_result FAIL "$CONF missing"; exit 1; }

vset() { cp_set "$CONF" "$1" "$2" eq; }   # vsftpd: key=value, no spaces allowed
vget() { cp_get "$CONF" "$1" eq; }
# login_block USER -> prints why PAM/vsftpd would refuse USER's login (nothing = no account-side reason found).
# usersandsudo.sh can expire README users' passwords (passwd -e): PAM then refuses every non-interactive
# login (FTP, IMAP) until the password is changed - check that before blaming the vsftpd config.
login_block() {
    local u="$1" st sh f3 f5 f8 today shell
    id "$u" >/dev/null 2>&1 || { echo "there is no account '$u'"; return; }
    st="$(passwd -S "$u" 2>/dev/null | awk '{print $2}')"
    case "$st" in
        L)  echo "the password of $u is LOCKED (passwd -S: L) - unlock it: passwd -u $u"; return ;;
        NP) echo "$u has NO password set (passwd -S: NP)"; return ;;
    esac
    sh="$(getent shadow "$u")"; today=$(( $(date +%s) / 86400 ))
    f3="$(echo "$sh" | cut -d: -f3)"; f5="$(echo "$sh" | cut -d: -f5)"; f8="$(echo "$sh" | cut -d: -f8)"
    if [ "$f3" = 0 ]; then
        echo "the password of $u is EXPIRED - must be changed at next login (chage -l $u; usersandsudo may have run passwd -e). PAM refuses FTP logins until then: set a new password (passwd $u) or chage -d \$(date +%F) $u"; return
    fi
    if [[ "$f3" =~ ^[0-9]+$ && "$f5" =~ ^[0-9]+$ ]] && [ "$f5" -lt 99999 ] && [ $((f3 + f5)) -lt "$today" ]; then
        echo "the password of $u is EXPIRED (older than PASS_MAX_DAYS=$f5, chage -l $u) - set a new password (passwd $u)"; return
    fi
    if [[ "$f8" =~ ^[0-9]+$ ]] && [ "$f8" -lt "$today" ]; then
        echo "the ACCOUNT $u has expired (chage -l $u) - chage -E -1 $u if the README needs it"; return
    fi
    shell="$(getent passwd "$u" | cut -d: -f7)"
    grep -qxF "$shell" /etc/shells 2>/dev/null || { echo "$u's shell $shell is not in /etc/shells - vsftpd's PAM (pam_shells) refuses it"; return; }
    # /etc/ftpusers: PAM (pam_listfile sense=deny) refuses everyone listed there
    grep -qxF "$u" /etc/ftpusers 2>/dev/null && { echo "$u is listed in /etc/ftpusers (PAM denies FTP to everyone listed there)"; return; }
    # userlist_file only counts with userlist_enable=YES: userlist_deny=YES (default) = deny-list, NO = allow-list
    if [ "$(vget userlist_enable)" = YES ]; then
        local ul; ul="$(vget userlist_file)"; ul="${ul:-/etc/vsftpd.user_list}"
        if [ "$(vget userlist_deny)" = NO ]; then
            grep -qxF "$u" "$ul" 2>/dev/null || { echo "userlist_deny=NO makes $ul an ALLOW-list and $u is not in it"; return; }
        else
            grep -qxF "$u" "$ul" 2>/dev/null && { echo "$u is listed in $ul (userlist_enable=YES, userlist_deny=YES: denied)"; return; }
        fi
    fi
}

cp_backup "$CONF"
cp "$CONF" "/etc/vsftpd.conf.backup.$(date +%Y%m%d_%H%M%S)" 2>/dev/null   # kept for compatibility with the old script
SNAP0="$(svc_snap "$CONF")"

# ---------------------------------------------------------------- README answers (FTP1/4/9/10) --
if cp_cfg_has FTP_ANON && cp_cfg_has FTP_WRITE && cp_cfg_has FTP_FORCE_SSL && cp_cfg_has FTP_CHROOT && cp_cfg_has FTP_PASV_MIN && cp_cfg_has FTP_PASV_MAX; then
    ANON="$(cp_cfg_get FTP_ANON)"; WRITE="$(cp_cfg_get FTP_WRITE)"; FORCE_SSL="$(cp_cfg_get FTP_FORCE_SSL)"
    CHROOT_MODE="$(cp_cfg_get FTP_CHROOT)"; PASV_MIN="$(cp_cfg_get FTP_PASV_MIN)"; PASV_MAX="$(cp_cfg_get FTP_PASV_MAX)"
    cp_info "README answers (stored; --reask to change): anonymous $ANON, uploads $WRITE, force TLS $FORCE_SSL, chroot $CHROOT_MODE, passive $PASV_MIN-$PASV_MAX"
else
    ANON=NO; WRITE=YES; FORCE_SSL=YES; CHROOT_MODE=b
    # an image that already uses a passive range probably got it from the README
    PASV_MIN="$(vget pasv_min_port)"; PASV_MAX="$(vget pasv_max_port)"
    [[ "$PASV_MIN" =~ ^[0-9]+$ && "$PASV_MAX" =~ ^[0-9]+$ ]] || { PASV_MIN=40000; PASV_MAX=50000; }
    echo "  README-dependent FTP settings - Enter keeps all of them:"
    echo "      anonymous login NO | uploads (write_enable) YES | TLS forced for logins+data YES"
    echo "      chroot b (users jailed in their home, allow_writeable_chroot=YES) | passive ports $PASV_MIN-$PASV_MAX"
    if cp_ask "Does the README change any of these (anonymous FTP, uploads, plain FTP, chroot, passive range)?" n; then
        if cp_ask "Does the README require ANONYMOUS FTP?" n; then ANON=YES; else ANON=NO; fi
        if cp_ask "Do FTP users need to UPLOAD / write files (README)?" y; then WRITE=YES; else WRITE=NO; fi   # FTP9
        if cp_ask "Force SSL/TLS for logins and data (plain-FTP clients will stop working)?" y; then FORCE_SSL=YES; else FORCE_SSL=NO; fi  # FTP4
        echo "  Chroot mode (FTP1). vsftpd REFUSES logins when the chroot root is writable by the user:"
        echo "    a) jail each user in /home/<user>/ftp (root-owned, 755) with a writable 'files' subfolder"
        echo "    b) jail users in their home and set allow_writeable_chroot=YES (keeps files where they are)"
        CHROOT_MODE="$(cp_read "Choose a or b" "b")"
        PASV_RANGE="$(cp_read "Passive port range (README may specify one)" "$PASV_MIN-$PASV_MAX")"
        PASV_MIN="${PASV_RANGE%-*}"; PASV_MAX="${PASV_RANGE#*-}"
    fi
    [ "$CHROOT_MODE" = a ] || CHROOT_MODE=b
    [[ "$PASV_MIN" =~ ^[0-9]+$ && "$PASV_MAX" =~ ^[0-9]+$ ]] || { cp_warn "Passive range not understood - using 40000-50000"; PASV_MIN=40000; PASV_MAX=50000; }
    cp_cfg_set FTP_ANON "$ANON"; cp_cfg_set FTP_WRITE "$WRITE"; cp_cfg_set FTP_FORCE_SSL "$FORCE_SSL"
    cp_cfg_set FTP_CHROOT "$CHROOT_MODE"; cp_cfg_set FTP_PASV_MIN "$PASV_MIN"; cp_cfg_set FTP_PASV_MAX "$PASV_MAX"
fi

chown root:root "$CONF"; chmod 600 "$CONF"

# ---------------------------------------------------------------- TLS certificate --
# Reuse a valid certificate from an earlier run (a new 4096-bit key took seconds on every run).
if openssl x509 -checkend 86400 -noout -in /etc/ssl/certs/vsftpd.crt >/dev/null 2>&1 && [ -s /etc/ssl/private/vsftpd.key ]; then
    cp_ok "Using existing certificate /etc/ssl/certs/vsftpd.crt"
elif openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout /etc/ssl/private/vsftpd.key -out /etc/ssl/certs/vsftpd.crt \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=vsftpd" >/dev/null 2>&1; then
    cp_ok "Self-signed certificate created (/etc/ssl/certs/vsftpd.crt)"
else
    cp_err "openssl failed - vsftpd would not start with ssl_enable=YES"; svc_result FAIL "openssl failed"; exit 1
fi
chmod 600 /etc/ssl/private/vsftpd.key

# FTP3: does this vsftpd build have per-version TLS switches?
# TESTED: Ubuntu 24.04 (vsftpd 3.0.5-0ubuntu3.1) accepts ssl_tlsv11/ssl_tlsv12/ssl_tlsv13 and REJECTS
# the spelling the manpage documents (ssl_tlsv1_2 -> vsftpd refuses to start). Debian has neither.
# So detect the real option names from the binary instead of trusting the manpage.
VSFTPD_BIN="$(command -v vsftpd || echo /usr/sbin/vsftpd)"
TLS11=""; TLS12=""; TLS13=""
for cand in ssl_tlsv11 ssl_tlsv1_1; do grep -aqw "$cand" "$VSFTPD_BIN" 2>/dev/null && { TLS11="$cand"; break; }; done
for cand in ssl_tlsv12 ssl_tlsv1_2; do grep -aqw "$cand" "$VSFTPD_BIN" 2>/dev/null && { TLS12="$cand"; break; }; done
for cand in ssl_tlsv13 ssl_tlsv1_3; do grep -aqw "$cand" "$VSFTPD_BIN" 2>/dev/null && { TLS13="$cand"; break; }; done

# Start a throw-away vsftpd on a spare port with the candidate config: it keeps running (timeout
# exit 124) if the config is valid, and exits immediately on an unknown/invalid option.
vsftpd_validate() {
    local t; t="$(mktemp)"; cp "$CONF" "$t"
    cp_set "$t" listen_port 2121 eq; cp_set "$t" listen YES eq; cp_set "$t" listen_ipv6 NO eq
    timeout 1 "$VSFTPD_BIN" "$t" >/dev/null 2>&1; local rc=$?
    rm -f "$t"; [ $rc -eq 124 ]
}

# ---------------------------------------------------------------- settings IN PLACE (G1) --
CONFIG_PARAMS=(
    "listen=YES"
    "listen_ipv6=NO"
    "anonymous_enable=$ANON"
    "local_enable=YES"
    "write_enable=$WRITE"
    "local_umask=022"
    "chroot_local_user=YES"
    "ascii_upload_enable=NO"
    "ascii_download_enable=NO"
    "use_localtime=YES"
    "ssl_enable=YES"
    "rsa_cert_file=/etc/ssl/certs/vsftpd.crt"
    "rsa_private_key_file=/etc/ssl/private/vsftpd.key"
    "require_ssl_reuse=NO"
    "ssl_sslv2=NO"
    "ssl_sslv3=NO"
    "ssl_tlsv1=YES"
    "ssl_ciphers=HIGH"
    "force_local_logins_ssl=$FORCE_SSL"
    "force_local_data_ssl=$FORCE_SSL"
    "allow_anon_ssl=NO"
    "anon_upload_enable=NO"
    "anon_mkdir_write_enable=NO"
    "anon_other_write_enable=NO"
    "hide_ids=YES"
    "ls_recurse_enable=NO"
    "ftpd_banner=Welcome to FTP"
    "max_login_fails=3"
    "delay_failed_login=3"
    "idle_session_timeout=300"
    "data_connection_timeout=120"
    "max_per_ip=5"
    "pasv_enable=YES"
    "pasv_min_port=$PASV_MIN"
    "pasv_max_port=$PASV_MAX"
    "xferlog_enable=YES"
    "xferlog_std_format=NO"
    "log_ftp_protocol=YES"
    "dual_log_enable=YES"
    "pam_service_name=vsftpd"
    "secure_chroot_dir=/var/run/vsftpd/empty"
)
# Keep ssl_tlsv1=YES (it is literally what a scored practice image checks for) and, where
# supported, explicitly enable TLS 1.2/1.3 and disable 1.1. Never add these on Debian - an
# unknown key stops vsftpd from starting.
[ -n "$TLS11" ] && CONFIG_PARAMS+=("$TLS11=NO")
[ -n "$TLS12" ] && CONFIG_PARAMS+=("$TLS12=YES")
[ -n "$TLS13" ] && CONFIG_PARAMS+=("$TLS13=YES")
[ -z "$TLS12$TLS13" ] && cp_info "this vsftpd has no per-version TLS options - using ssl_tlsv1 only"
# remove wrongly-spelled TLS keys (e.g. from older scripts) that would stop vsftpd from starting
for bad in ssl_tlsv1_1 ssl_tlsv1_2 ssl_tlsv1_3 ssl_tlsv11 ssl_tlsv12 ssl_tlsv13; do
    case " $TLS11 $TLS12 $TLS13 " in *" $bad "*) ;; *) cp_unset "$CONF" "$bad" eq ;; esac
done
if [ "$CHROOT_MODE" = "a" ]; then
    CONFIG_PARAMS+=("allow_writeable_chroot=NO" "user_sub_token=\$USER" "local_root=/home/\$USER/ftp")
else
    CONFIG_PARAMS+=("allow_writeable_chroot=YES")
fi
for param in "${CONFIG_PARAMS[@]}"; do
    vset "${param%%=*}" "${param#*=}"
done
mkdir -p /var/run/vsftpd/empty
chmod 600 "$CONF"; chown root:root "$CONF"

# chroot folders for mode a (FTP1)
if [ "$CHROOT_MODE" = "a" ]; then
    n=0
    while IFS=: read -r u _ uid _ _ home _; do
        [ "$uid" -ge 1000 ] && [ "$uid" -lt 60000 ] && [ -d "$home" ] || continue
        mkdir -p "$home/ftp/files"
        chown root:root "$home/ftp"; chmod 755 "$home/ftp"
        chown "$u": "$home/ftp/files"; chmod 750 "$home/ftp/files"
        n=$((n + 1))
    done < /etc/passwd
    cp_ok "Chroot a: root-owned /home/<user>/ftp (+ writable files/) for $n users"
fi

# FTP root directory permissions (FTP2) - the ROOT DIR itself, not only its contents
LOCAL_ROOT="$(vget local_root)"
ANON_ROOT="$(vget anon_root)"
for d in "$LOCAL_ROOT" "$ANON_ROOT" /srv/ftp; do
    [ -n "$d" ] || continue
    [[ "$d" == *'$USER'* ]] && continue
    [ -d "$d" ] || continue
    if [ "$d" = "$LOCAL_ROOT" ]; then chown root:root "$d"; else chown root:"$(stat -c %G "$d")" "$d"; fi
    chmod 755 "$d"
    chmod -R o-w "$d"
    cp_ok "FTP root $d -> $(stat -c '%a %U:%G' "$d") (contents: no world-write)"
done

# chroot exemption list / user lists (FTP5)
if [ "$(vget chroot_list_enable)" = "YES" ]; then
    CL="$(vget chroot_list_file)"; CL="${CL:-/etc/vsftpd.chroot_list}"
    if [ -s "$CL" ]; then
        cp_warn "Users NOT chrooted (listed in $CL; chroot_local_user=YES inverts the list): $(tr '\n' ' ' < "$CL")"
        if cp_ask "Empty $CL so every user is chrooted?" y; then cp_backup "$CL"; : > "$CL"; cp_ok "Emptied $CL"; fi
    fi
fi
if [ "$(vget userlist_enable)" = "YES" ]; then
    UL="$(vget userlist_file)"; UL="${UL:-/etc/vsftpd.user_list}"
    cp_todo "vsftpd userlist_enable=YES, userlist_deny=$(vget userlist_deny) (NO = allow-list): check $UL against the README: $(tr '\n' ' ' < "$UL" 2>/dev/null)"
fi
if [ -f /etc/ftpusers ] && ! grep -qx root /etc/ftpusers; then
    cp_backup /etc/ftpusers; echo root >> /etc/ftpusers; cp_ok "Added root to /etc/ftpusers (denied)"
fi

# Hint: login accounts whose state blocks PAM logins (expired/locked password ...) - FTP refuses them
for u in $(awk -F: '$3 >= 1000 && $3 < 60000 {print $1}' /etc/passwd); do
    why="$(login_block "$u")"
    [ -n "$why" ] && cp_warn "FTP login impossible for $u: $why (fix it if the README needs FTP for $u)"
done

# Allow FTP traffic through UFW (G3)
cp_ufw_allow "vsftpd" 21/tcp
command -v ufw >/dev/null 2>&1 && ufw allow "$PASV_MIN:$PASV_MAX/tcp" >/dev/null 2>&1 && cp_ok "UFW: allowed $PASV_MIN:$PASV_MAX/tcp (passive mode)"

# ---------------------------------------------------------------- validate + restart once (G2) --
if vsftpd_validate; then
    cp_ok "Config test passed (test instance started cleanly)"
else
    cp_err "vsftpd rejects the new config - restoring backup (nothing restarted)"
    cp_restore "$CONF"
    cp_todo "vsftpd.sh: hardened config was rejected by vsftpd and rolled back - check $CONF by hand"
    svc_result ROLLBACK "config test failed"; exit 1
fi
if [ "$(svc_snap "$CONF")" = "$SNAP0" ] && systemctl is-active --quiet vsftpd; then
    cp_ok "vsftpd config unchanged - no restart needed"
elif ! cp_restart vsftpd; then
    cp_err "vsftpd failed with the new config - restoring backup"
    cp_restore "$CONF"
    cp_restart vsftpd
    cp_todo "vsftpd.sh: vsftpd did not start with the hardened config - rolled back; journalctl -xeu vsftpd"
    svc_result ROLLBACK "vsftpd did not start"; exit 1
fi

# G2: functional test
RESULT=OK
if command -v curl >/dev/null 2>&1; then
    # anonymous probe in the background: a refused login costs delay_failed_login (3 s)
    ANON_RC="$(mktemp)"
    ( curl -s --max-time 6 "ftp://127.0.0.1/" -u anonymous:test >/dev/null 2>&1; echo $? > "$ANON_RC" ) &
    ANON_PID=$!
    if b="$(timeout 4 bash -c 'exec 3<>/dev/tcp/127.0.0.1/21; IFS= read -r -t 3 l <&3; echo "$l"' 2>/dev/null)" && [[ "$b" == 220* ]]; then
        cp_ok "FTP answers: ${b%$'\r'}"
    else
        cp_warn "No FTP banner on port 21 (critical service!)"; RESULT="FAIL no banner on port 21"
    fi
    TU="$(cp_read "Test login - FTP username (Enter to skip)" "")"
    if [ -n "$TU" ]; then
        TP=""; [ -t 0 ] && { read -r -s -p "  Password for $TU: " TP; echo; }
        if curl -s --max-time 10 --ssl-reqd -k "ftp://127.0.0.1/" -u "$TU:$TP" >/dev/null; then
            cp_ok "FTPS login for $TU works"
        else
            why="$(login_block "$TU")"
            if [ -n "$why" ]; then
                cp_warn "FTPS login for $TU FAILED: $why"
                cp_todo "vsftpd.sh: FTPS test login for $TU failed: $why"
            else
                cp_warn "FTPS login for $TU FAILED - account looks fine (not locked/expired); check the password, chroot mode, README (journalctl -u vsftpd, /var/log/vsftpd.log)"
                cp_todo "vsftpd.sh: FTPS test login for $TU failed (account not locked/expired) - check the password, chroot mode / README"
            fi
        fi
    fi
    wait "$ANON_PID" 2>/dev/null
    if [ "$(cat "$ANON_RC")" = 0 ]; then
        if [ "$ANON" = YES ]; then cp_ok "Anonymous login works (README requires it)"; else cp_warn "Anonymous login still WORKS - check the config"; fi
    else
        [ "$ANON" = NO ] && cp_ok "Anonymous login refused"
    fi
    rm -f "$ANON_RC"
fi

echo "  Changed:"
svc_changes "$CONF"
svc_result $RESULT
cp_ok "vsftpd hardening complete ($((SECONDS - SVC_T0))s)"
