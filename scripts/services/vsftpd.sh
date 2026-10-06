#!/bin/bash
# vsftpd Security Configuration Script
# Research-doc items: FTP1-FTP10, G1-G3, G5 (baseline first: section B)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../cp-common.sh
source "$SCRIPT_DIR/../cp-common.sh" 2>/dev/null || { echo "ERROR: cp-common.sh not found (keep the repo layout intact)"; exit 1; }

cp_require_root
cp_screenshot_prompt
command -v vsftpd >/dev/null 2>&1 || [ -x /usr/sbin/vsftpd ] || { echo "ERROR: vsftpd is not installed"; exit 1; }

cp_baseline_gate vsftpd

echo "=== Starting vsftpd configuration ==="
echo ""

# The unit may start vsftpd with a config file other than /etc/vsftpd.conf (B5) - harden the one in use.
CONF="/etc/vsftpd.conf"
UNIT_CONF="$(systemctl cat vsftpd 2>/dev/null | sed -n 's/^ExecStart=[^ ]*vsftpd[[:space:]]\+\([^ ]*\.conf\).*/\1/p' | tail -1)"
if [ -n "$UNIT_CONF" ] && [ "$UNIT_CONF" != "$CONF" ]; then
    cp_warn "vsftpd.service starts vsftpd with $UNIT_CONF (not $CONF)"
    cp_ask "Harden $UNIT_CONF instead?" y && CONF="$UNIT_CONF"
fi
[ -f "$CONF" ] || { echo "ERROR: $CONF not found"; exit 1; }

vset() { cp_set "$CONF" "$1" "$2" eq; }   # vsftpd: key=value, no spaces allowed
vget() { cp_get "$CONF" "$1" eq; }

# ---------------------------------------------------------------- questions (README) --
echo "[1/9] README-driven choices"
if cp_ask "Does the README require ANONYMOUS FTP?" n; then ANON=YES; else ANON=NO; fi
if cp_ask "Do FTP users need to UPLOAD / write files (README)?" y; then WRITE=YES; else WRITE=NO; fi   # FTP9
if cp_ask "Force SSL/TLS for logins and data (plain-FTP clients will stop working)?" y; then FORCE_SSL=YES; else FORCE_SSL=NO; fi  # FTP4
echo "  Chroot mode for local users (FTP1). vsftpd REFUSES logins when the chroot root is writable"
echo "  by the user ('500 OOPS: refusing to run with writable root inside chroot()')."
echo "    a) jail each user in /home/<user>/ftp (root-owned, 755) with a writable 'files' subfolder"
echo "    b) jail users in their home and set allow_writeable_chroot=YES (keeps files where they are)"
CHROOT_MODE="$(cp_read "Choose a or b" "b")"
PASV_RANGE="$(cp_read "Passive port range (README may specify one)" "40000-50000")"
PASV_MIN="${PASV_RANGE%-*}"; PASV_MAX="${PASV_RANGE#*-}"
echo ""

# Step: Set restrictive permissions on vsftpd configuration file
echo "[2/9] Setting permissions on $CONF..."
cp_backup "$CONF"
cp "$CONF" "/etc/vsftpd.conf.backup.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
chown root:root "$CONF"
chmod 600 "$CONF"

# Step: Create self-signed SSL certificate
echo "[3/9] Creating self-signed SSL certificate..."
if openssl req -x509 -nodes -days 3650 -newkey rsa:4096 \
    -keyout /etc/ssl/private/vsftpd.key \
    -out /etc/ssl/certs/vsftpd.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=vsftpd" >/dev/null 2>&1; then
    chmod 600 /etc/ssl/private/vsftpd.key
    echo "  + Certificate created"
else
    cp_err "openssl failed - vsftpd would not start with ssl_enable=YES"; exit 1
fi

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
    timeout 2 "$VSFTPD_BIN" "$t" >/dev/null 2>&1; local rc=$?
    rm -f "$t"; [ $rc -eq 124 ]
}

# Step: Update configuration IN PLACE (G1)
echo "[4/9] Updating $CONF with secure settings (in place)..."
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
[ -z "$TLS12$TLS13" ] && echo "  (this vsftpd has no per-version TLS options - using ssl_tlsv1 only)"
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
echo "  + Configuration updated with secure settings"
echo ""

# Step: chroot folders for mode a (FTP1)
if [ "$CHROOT_MODE" = "a" ]; then
    echo "[5/9] Creating root-owned chroot folders /home/<user>/ftp (+ writable files/)"
    while IFS=: read -r u _ uid _ _ home _; do
        [ "$uid" -ge 1000 ] && [ "$uid" -lt 60000 ] && [ -d "$home" ] || continue
        mkdir -p "$home/ftp/files"
        chown root:root "$home/ftp"; chmod 755 "$home/ftp"
        chown "$u": "$home/ftp/files"; chmod 750 "$home/ftp/files"
        echo "  - $home/ftp"
    done < /etc/passwd
else
    echo "[5/9] Chroot in home with allow_writeable_chroot=YES (logins keep working)"
fi

# Step: FTP root directory permissions (FTP2) - the ROOT DIR itself, not only its contents
echo "[6/9] Fixing FTP root directory permissions..."
LOCAL_ROOT="$(vget local_root)"
ANON_ROOT="$(vget anon_root)"
for d in "$LOCAL_ROOT" "$ANON_ROOT" /srv/ftp; do
    [ -n "$d" ] || continue
    [[ "$d" == *'$USER'* ]] && continue
    [ -d "$d" ] || continue
    if [ "$d" = "$LOCAL_ROOT" ]; then chown root:root "$d"; else chown root:"$(stat -c %G "$d")" "$d"; fi
    chmod 755 "$d"
    chmod -R o-w "$d"
    echo "  + $d -> $(stat -c '%a %U:%G' "$d") (contents: no world-write)"
done
[ -z "$LOCAL_ROOT$ANON_ROOT" ] && [ ! -d /srv/ftp ] && echo "  (no local_root/anon_root set and no /srv/ftp)"
echo ""

# Step: chroot exemption list / user lists (FTP5)
echo "[7/9] Auditing chroot_list / userlist / ftpusers..."
if [ "$(vget chroot_list_enable)" = "YES" ]; then
    CL="$(vget chroot_list_file)"; CL="${CL:-/etc/vsftpd.chroot_list}"
    if [ -s "$CL" ]; then
        cp_warn "Users in $CL are NOT chrooted (chroot_local_user=YES inverts the list):"
        sed 's/^/        /' "$CL"
        if cp_ask "Empty $CL so every user is chrooted?" y; then cp_backup "$CL"; : > "$CL"; cp_ok "Emptied $CL"; fi
    fi
fi
if [ "$(vget userlist_enable)" = "YES" ]; then
    UL="$(vget userlist_file)"; UL="${UL:-/etc/vsftpd.user_list}"
    cp_info "userlist_enable=YES, userlist_deny=$(vget userlist_deny) (NO = allow-list). $UL:"
    [ -f "$UL" ] && sed 's/^/        /' "$UL"
fi
if [ -f /etc/ftpusers ] && ! grep -qx root /etc/ftpusers; then
    echo root >> /etc/ftpusers; cp_ok "Added root to /etc/ftpusers (denied)"
fi

# Step: Allow FTP traffic through UFW (G3)
echo "[8/9] Configuring UFW firewall rules..."
cp_ufw_allow "vsftpd" 21/tcp
command -v ufw >/dev/null 2>&1 && ufw allow "$PASV_MIN:$PASV_MAX/tcp" >/dev/null 2>&1 && echo "  + Allowed ports $PASV_MIN:$PASV_MAX/tcp (passive mode)"
echo ""

# Step: Restart vsftpd service
echo "[9/9] Validating and restarting vsftpd service..."
if vsftpd_validate; then
    cp_ok "Config test passed (test instance started cleanly)"
else
    cp_err "vsftpd rejects the new config - restoring backup (nothing restarted)"
    cp_restore "$CONF"
    exit 1
fi
if ! cp_restart vsftpd; then
    cp_err "vsftpd failed with the new config - restoring backup"
    cp_restore "$CONF"
    cp_restart vsftpd
    exit 1
fi

# G2: functional test
if command -v curl >/dev/null 2>&1; then
    if curl -s --max-time 5 "ftp://127.0.0.1/" -u anonymous:test >/dev/null 2>&1; then
        [ "$ANON" = YES ] && cp_ok "Anonymous login works (README requires it)" || cp_warn "Anonymous login still WORKS - check the config"
    else
        [ "$ANON" = NO ] && cp_ok "Anonymous login refused"
    fi
    TU="$(cp_read "Test login - FTP username (Enter to skip)" "")"
    if [ -n "$TU" ]; then
        read -r -s -p "  Password for $TU: " TP; echo
        if curl -s --max-time 10 --ssl-reqd -k "ftp://127.0.0.1/" -u "$TU:$TP" >/dev/null; then
            cp_ok "FTPS login for $TU works"
        else
            cp_warn "FTPS login for $TU FAILED - check chroot mode / README (journalctl -u vsftpd, /var/log/vsftpd.log)"
        fi
    fi
fi
echo ""

echo "=== vsftpd configuration complete! ==="
