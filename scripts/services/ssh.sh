#!/bin/bash
# SSH Security Hardening Script
# Research-doc items: SSH1-SSH13, G1-G3, G5 (baseline first: section B)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../cp-common.sh
source "$SCRIPT_DIR/../cp-common.sh" 2>/dev/null || { echo "ERROR: cp-common.sh not found (keep the repo layout intact)"; exit 1; }

cp_require_root

echo "========================================="
echo "SSH Security Hardening Script"
echo "========================================="
echo ""

cp_screenshot_prompt

if ! command -v sshd >/dev/null 2>&1; then
    echo "ERROR: openssh-server (sshd) is not installed"
    exit 1
fi

cp_baseline_gate ssh

SSHCFG="/etc/ssh/sshd_config"
DROPIN_DIR="/etc/ssh/sshd_config.d"
MATCH_RE='^[[:space:]]*Match[[:space:]]'

echo ""
echo "Step 1: Backing up SSH configuration"
cp_backup "$SSHCFG" "$DROPIN_DIR"
cp "$SSHCFG" /etc/ssh/sshd_config.backup      # kept for compatibility with the old script
echo ""

echo "Step 2: Setting SSH config permissions"
chown root:root "$SSHCFG"
chmod 600 "$SSHCFG"
chmod 755 /etc/ssh
if [ -d "$DROPIN_DIR" ]; then
    chown root:root "$DROPIN_DIR"; chmod 755 "$DROPIN_DIR"
    find "$DROPIN_DIR" -type f -exec chown root:root {} \; -exec chmod 600 {} \;
fi
echo ""

echo "Step 3: Setting host key permissions"
chown root:root /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub 2>/dev/null || true
chmod 600 /etc/ssh/ssh_host_*_key 2>/dev/null || true
chmod 644 /etc/ssh/ssh_host_*_key.pub 2>/dev/null || true
echo ""

echo "Step 4: Configuring user SSH directories"
# SSH1: iterate over real accounts (passwd), not over whatever directories exist in /home.
# A leftover home dir without a user used to make chown fail and abort the whole script.
while IFS=: read -r USERNAME _ UID_ _ _ USER_HOME _; do
    if [ "$USERNAME" != "root" ] && { [ "$UID_" -lt 1000 ] || [ "$UID_" -ge 60000 ]; }; then continue; fi
    [ -d "$USER_HOME" ] || continue
    case "$USER_HOME" in /|/nonexistent|/dev/null) continue ;; esac
    echo "Processing user: $USERNAME"
    if [ ! -d "$USER_HOME/.ssh" ]; then
        mkdir -p "$USER_HOME/.ssh"
        echo "  - Created .ssh directory"
    fi
    chmod 700 "$USER_HOME/.ssh"
    chown "$USERNAME": "$USER_HOME/.ssh" || echo "  ! could not chown $USER_HOME/.ssh"
    echo "  - Set .ssh directory permissions (700)"
    for f in "$USER_HOME/.ssh/authorized_keys" "$USER_HOME/.ssh/authorized_keys2"; do
        [ -f "$f" ] || continue
        chmod 600 "$f"; chown "$USERNAME": "$f"
        echo "  - Set $(basename "$f") permissions (600)"
    done
    # SSH10: every private key type, not only id_rsa
    for f in "$USER_HOME"/.ssh/id_rsa "$USER_HOME"/.ssh/id_ed25519 "$USER_HOME"/.ssh/id_ecdsa "$USER_HOME"/.ssh/id_dsa "$USER_HOME"/.ssh/id_ecdsa_sk "$USER_HOME"/.ssh/id_ed25519_sk; do
        [ -f "$f" ] || continue
        chmod 600 "$f"; chown "$USERNAME": "$f"; echo "  - Set private key permissions (600): $(basename "$f")"
        if [ -f "$f.pub" ]; then chmod 644 "$f.pub"; chown "$USERNAME": "$f.pub"; echo "  - Set public key permissions (644): $(basename "$f").pub"; fi
    done
    echo ""
done < /etc/passwd

echo "Step 4b: Auditing keys and SSH backdoor mechanisms (SSH9) - review with the README"
for f in /root/.ssh/authorized_keys /root/.ssh/authorized_keys2 /home/*/.ssh/authorized_keys /home/*/.ssh/authorized_keys2; do
    [ -s "$f" ] || continue
    cp_warn "$f contains $(grep -cvE '^[[:space:]]*(#|$)' "$f") key(s):"
    awk '!/^[[:space:]]*(#|$)/ {c=$NF; if (NF<3) c="(no comment)"; print "        " substr($0,1,40) "... " c}' "$f"
done
for f in /etc/ssh/sshrc /root/.ssh/rc /home/*/.ssh/rc; do
    [ -f "$f" ] || continue
    cp_warn "SSH login script found (runs on every login): $f"
    sed 's/^/        /' "$f" | head -10
    if cp_ask "Remove $f ?" y; then cp_backup "$f"; rm -f "$f"; cp_ok "Removed $f"; fi
done
grep -rhiE '^[[:space:]]*(AuthorizedKeysFile|AuthorizedKeysCommand|AuthorizedKeysCommandUser|AuthorizedPrincipalsFile|ForceCommand|PermitUserRC|ChrootDirectory)[[:space:]]' "$SSHCFG" "$DROPIN_DIR" 2>/dev/null \
    | while IFS= read -r l; do cp_warn "Review directive: $l"; done
if grep -qE "$MATCH_RE" "$SSHCFG"; then
    cp_warn "Active Match block(s) in $SSHCFG (settings inside only apply to matched users):"
    sed -n "/$MATCH_RE/,\$p" "$SSHCFG" | grep -vE '^[[:space:]]*(#|$)' | sed 's/^/        /'
fi
echo ""

echo "Step 5: Updating SSH security settings"
# README-driven items (SSH8)
PASSAUTH_CUR="$(sshd -T 2>/dev/null | awk '$1=="passwordauthentication"{print $2}')"
if cp_ask "Does the README require SSH KEY-ONLY login (disable password authentication)?" n; then
    PASSAUTH="no"
else
    PASSAUTH="yes"
fi
echo "  PasswordAuthentication -> $PASSAUTH (was: ${PASSAUTH_CUR:-unknown})"
SSH_PORT="$(cp_read "SSH port (README may require a specific one)" "22")"
ALLOW_USERS="$(cp_read "AllowUsers (space separated, Enter = no restriction)" "")"
DENY_USERS="$(cp_read "DenyUsers (Enter = none)" "")"
DENY_GROUPS="$(cp_read "DenyGroups (Enter = none)" "")"
SFTP_ONLY=0
if cp_ask "Does the README require SFTP-only access (ForceCommand internal-sftp + chroot)?" n; then
    SFTP_ONLY=1
    SFTP_DIR="$(cp_read "ChrootDirectory for SFTP (must be root-owned)" "/srv/sftp")"
fi

# Ubuntu banner for CIS 'Banner /etc/issue.net' - must not leak OS info
cp_backup /etc/issue.net
echo "Authorized users only. All activity may be monitored and reported." > /etc/issue.net
chmod 644 /etc/issue.net

# Settings to enforce (existing values kept, missing ones added - research doc SSH4-SSH7)
declare -A SSHD_SETTINGS=(
    ["PermitRootLogin"]="no"
    ["X11Forwarding"]="no"
    ["LoginGraceTime"]="30"
    ["MaxAuthTries"]="3"
    ["LogLevel"]="VERBOSE"
    ["IgnoreRhosts"]="yes"
    ["HostbasedAuthentication"]="no"
    ["PermitEmptyPasswords"]="no"
    ["AllowTcpForwarding"]="no"
    ["ClientAliveInterval"]="300"
    ["ClientAliveCountMax"]="2"
    ["Compression"]="no"
    ["AllowAgentForwarding"]="no"
    ["Protocol"]="2"
    ["PermitUserEnvironment"]="no"
    ["UsePAM"]="yes"
    ["StrictModes"]="yes"
    ["MaxSessions"]="4"
    ["MaxStartups"]="10:30:60"
    ["GSSAPIAuthentication"]="no"
    ["KbdInteractiveAuthentication"]="no"
    ["PubkeyAuthentication"]="yes"
    ["Banner"]="/etc/issue.net"
    ["DisableForwarding"]="yes"
    ["DebianBanner"]="no"
    ["PasswordAuthentication"]="$PASSAUTH"
    ["Port"]="$SSH_PORT"
)
[ -n "$ALLOW_USERS" ] && SSHD_SETTINGS["AllowUsers"]="$ALLOW_USERS"
[ -n "$DENY_USERS" ] && SSHD_SETTINGS["DenyUsers"]="$DENY_USERS"
[ -n "$DENY_GROUPS" ] && SSHD_SETTINGS["DenyGroups"]="$DENY_GROUPS"

# SSH2: drop-ins in sshd_config.d are read FIRST (Include is at the top) and win.
# Remove any of our keys from them so our value is the effective one.
if [ -d "$DROPIN_DIR" ]; then
    for key in "${!SSHD_SETTINGS[@]}"; do
        for f in "$DROPIN_DIR"/*.conf; do
            [ -f "$f" ] || continue
            if [ -n "$(cp_get "$f" "$key" space 1)" ]; then
                cp_warn "Drop-in $f overrides $key ($(cp_get "$f" "$key" space 1)) - removing it"
                cp_unset "$f" "$key" space 1
            fi
        done
    done
fi

# SSH3/G1: edit in place; new keys go ABOVE the first Match block (never inside it).
for key in "${!SSHD_SETTINGS[@]}"; do
    cp_set "$SSHCFG" "$key" "${SSHD_SETTINGS[$key]}" space 1 0 "" "$MATCH_RE"
done

if [ "$SFTP_ONLY" = 1 ]; then
    mkdir -p "$SFTP_DIR"; chown root:root "$SFTP_DIR"; chmod 755 "$SFTP_DIR"
    cp_set "$SSHCFG" ForceCommand "internal-sftp" space 1 0 "" "$MATCH_RE"
    cp_set "$SSHCFG" ChrootDirectory "$SFTP_DIR" space 1 0 "" "$MATCH_RE"
    grep -qiE '^[[:space:]]*Subsystem[[:space:]]+sftp' "$SSHCFG" || cp_set "$SSHCFG" Subsystem "sftp internal-sftp" space 1 0 "" "$MATCH_RE"
fi
# SSH13: SFTP must keep working
grep -qiE '^[[:space:]]*Subsystem[[:space:]]+sftp' "$SSHCFG" || cp_warn "No 'Subsystem sftp' line - SFTP will not work (the default is: Subsystem sftp /usr/lib/openssh/sftp-server)"

echo ""
echo "Step 6: Testing SSH configuration"
# Some keys (DebianBanner, DisableForwarding) do not exist in every
# OpenSSH build. If sshd -t rejects one, drop just that key and try again.
for attempt in 1 2 3 4 5 6; do
    ERR="$(sshd -t 2>&1)"; RC=$?
    [ $RC -eq 0 ] && break
    BAD="$(echo "$ERR" | sed -n 's/.*\(Bad configuration option\|Unsupported option\): *\([A-Za-z0-9]*\).*/\2/p' | head -1)"
    if [ -n "$BAD" ]; then
        cp_warn "This sshd does not support '$BAD' - removing it"
        cp_unset "$SSHCFG" "$BAD" space 1
    else
        break
    fi
done
if sshd -t; then
    echo "SSH configuration test: PASSED"
else
    echo "SSH configuration test: FAILED"
    echo "Restoring backup configuration..."
    cp_restore "$SSHCFG" "$DROPIN_DIR"
    exit 1
fi

echo ""
echo "Step 7: Configuring firewall"
if [ "$SSH_PORT" = "22" ]; then
    cp_ufw_allow "OpenSSH" 22/tcp
else
    command -v ufw >/dev/null 2>&1 && ufw allow "$SSH_PORT/tcp" >/dev/null && cp_ok "UFW: allowed $SSH_PORT/tcp (custom SSH port)"
fi

echo ""
echo "Step 8: Installing fail2ban"
if apt-get update > /dev/null 2>&1 && apt-get install fail2ban -y > /dev/null 2>&1; then
    systemctl enable fail2ban > /dev/null 2>&1
    systemctl start fail2ban > /dev/null 2>&1
    echo "fail2ban installed and started"
else
    echo "Failed to install fail2ban - continuing"
fi

echo ""
echo "Step 9: Restarting SSH service"
# SSH12: Ubuntu 24.04 / Mint 22 use ssh.socket activation - Port changes need the socket restarted
if systemctl is-enabled ssh.socket >/dev/null 2>&1 || systemctl is-active ssh.socket >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl restart ssh.socket 2>/dev/null
fi
systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
sleep 1
if systemctl is-active --quiet ssh || systemctl is-active --quiet sshd || systemctl is-active --quiet ssh.socket; then
    echo "SSH service restarted"
else
    cp_err "SSH is not active after restart! Restoring backup."
    cp_restore "$SSHCFG" "$DROPIN_DIR"
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
    exit 1
fi
echo ""

echo "Step 10: Verifying the EFFECTIVE configuration (sshd -T) - SSH13 / G2"
EFFECTIVE="$(sshd -T 2>/dev/null)"
MISMATCH=0
for key in "${!SSHD_SETTINGS[@]}"; do
    lk="$(echo "$key" | tr '[:upper:]' '[:lower:]')"
    case "$lk" in protocol|debianbanner|allowusers|denyusers|denygroups) continue ;; esac  # not printed / printed differently
    want="$(echo "${SSHD_SETTINGS[$key]}" | tr '[:upper:]' '[:lower:]')"
    have="$(echo "$EFFECTIVE" | awk -v k="$lk" '$1==k {sub(/^[^ ]+ /,""); print; exit}' | tr '[:upper:]' '[:lower:]')"
    [ -z "$have" ] && continue
    if [ "$have" != "$want" ]; then cp_warn "Effective $key is '$have' (wanted '$want')"; MISMATCH=1; fi
done
[ "$MISMATCH" = 0 ] && cp_ok "Effective sshd settings match"
if ss -tlnp 2>/dev/null | grep -q ":$SSH_PORT .*sshd\|:$SSH_PORT .*systemd"; then
    cp_ok "Port $SSH_PORT is listening"
    command -v ssh-keyscan >/dev/null && ssh-keyscan -T 3 -p "$SSH_PORT" localhost >/dev/null 2>&1 && cp_ok "SSH answers on localhost:$SSH_PORT"
else
    cp_warn "Nothing is listening on port $SSH_PORT - check 'ss -tlnp'"
fi

echo ""
echo "SSH hardening complete"
