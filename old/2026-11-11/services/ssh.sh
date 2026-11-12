#!/bin/bash
# SSH Security Hardening Script
# Research-doc items: SSH1-SSH13, G1-G3, G5 (baseline first: section B)
#
# Usage: sudo bash services/ssh.sh [--reask]
# README answers are asked once and kept in /root/cp-state/readme.conf, so a re-run asks nothing:
#   SSH_PORT  SSH_PASSAUTH (yes|no)  SSH_ALLOWUSERS  SSH_DENYUSERS  SSH_DENYGROUPS  SSH_SFTP_DIR (empty = not SFTP-only)
#   SSH_FAIL2BAN=no   you declined fail2ban (not offered again)
#   --reask   forget those answers and ask again

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../cp-common.sh
source "$SCRIPT_DIR/../cp-common.sh" 2>/dev/null || { echo "ERROR: cp-common.sh not found (keep the repo layout intact)"; exit 1; }

# ---- local helpers (same block in every services/*.sh; cp-common.sh is shared/owned elsewhere) ----
SVC=ssh; SVC_T0=$SECONDS
svc_result() { mkdir -p "$CP_STATE_DIR/svc" 2>/dev/null && echo "$*" > "$CP_STATE_DIR/svc/$SVC.result"; }
svc_snap()   { find "$@" -xdev -type f -print0 2>/dev/null | LC_ALL=C sort -z | xargs -0 -r md5sum 2>/dev/null | md5sum | cut -c1-32; }
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
[ "${1:-}" = "--reask" ] && svc_forget SSH_PORT SSH_PASSAUTH SSH_ALLOWUSERS SSH_DENYUSERS SSH_DENYGROUPS SSH_SFTP_DIR SSH_FAIL2BAN

cp_hdr "SSH hardening"
cp_screenshot_prompt

if ! command -v sshd >/dev/null 2>&1; then
    echo "ERROR: openssh-server (sshd) is not installed"
    svc_result FAIL "not installed"; exit 1
fi

cp_baseline_gate ssh

SSHCFG="/etc/ssh/sshd_config"
DROPIN_DIR="/etc/ssh/sshd_config.d"
MATCH_RE='^[[:space:]]*Match[[:space:]]'
ME="$(cp_cfg_get ME)"; ME="${ME:-${SUDO_USER:-}}"
README_USERS="$(echo "$(cp_cfg_get ADMINS) $(cp_cfg_get USERS)" | xargs)"

cp_backup "$SSHCFG" "$DROPIN_DIR" /etc/issue.net
cp "$SSHCFG" /etc/ssh/sshd_config.backup      # kept for compatibility with the old script
SNAP0="$(svc_snap "$SSHCFG" "$DROPIN_DIR")"
EFF_BEFORE="$(sshd -T 2>/dev/null)"

# ------------------------------------------------------------------ README answers (SSH8) --
# Defaults = what the image runs now (sshd -T), so Enter never changes a README-driven setting.
cur() { echo "$EFF_BEFORE" | awk -v k="$1" '$1 == k { sub(/^[^ ]+ /, ""); printf "%s ", $0 }' | xargs; }
if cp_cfg_has SSH_PORT && cp_cfg_has SSH_PASSAUTH && cp_cfg_has SSH_ALLOWUSERS && cp_cfg_has SSH_DENYUSERS && cp_cfg_has SSH_DENYGROUPS && cp_cfg_has SSH_SFTP_DIR; then
    SSH_PORT="$(cp_cfg_get SSH_PORT)"; PASSAUTH="$(cp_cfg_get SSH_PASSAUTH)"
    ALLOW_USERS="$(cp_cfg_get SSH_ALLOWUSERS)"; DENY_USERS="$(cp_cfg_get SSH_DENYUSERS)"; DENY_GROUPS="$(cp_cfg_get SSH_DENYGROUPS)"
    SFTP_DIR="$(cp_cfg_get SSH_SFTP_DIR)"
    cp_info "README answers (stored; --reask to change): Port $SSH_PORT, PasswordAuthentication $PASSAUTH, AllowUsers ${ALLOW_USERS:--}, DenyUsers ${DENY_USERS:--}, DenyGroups ${DENY_GROUPS:--}, SFTP-only ${SFTP_DIR:-no}"
else
    SSH_PORT="$(cur port | awk '{print $1}')"; SSH_PORT="${SSH_PORT:-22}"
    PASSAUTH="$(cur passwordauthentication)"; [ "$PASSAUTH" = no ] || PASSAUTH=yes
    ALLOW_USERS="$(cur allowusers)"; DENY_USERS="$(cur denyusers)"; DENY_GROUPS="$(cur denygroups)"
    SFTP_DIR=""; [ "$(cur forcecommand)" = internal-sftp ] && SFTP_DIR="$(cur chrootdirectory)"; [ "$SFTP_DIR" = none ] && SFTP_DIR=""
    echo "  README-dependent SSH settings (current values) - Enter keeps all of them:"
    echo "      Port $SSH_PORT | $([ "$PASSAUTH" = yes ] && echo 'password login allowed' || echo 'KEY-ONLY login') | AllowUsers ${ALLOW_USERS:-none} | DenyUsers ${DENY_USERS:-none} | DenyGroups ${DENY_GROUPS:-none} | SFTP-only ${SFTP_DIR:-no}"
    if [ -n "$README_USERS" ] && [ -n "$ALLOW_USERS$DENY_USERS$DENY_GROUPS" ]; then
        for u in $ALLOW_USERS; do [[ " $README_USERS " == *" $u "* ]] || cp_warn "AllowUsers lets in '$u', who is not a README user"; done
    fi
    if cp_ask "Does the README change any of these (port, key-only login, allowed/denied users or groups, SFTP-only)?" n; then
        SSH_PORT="$(cp_read "SSH port (README may require a specific one)" "$SSH_PORT")"
        if cp_ask "Does the README require SSH KEY-ONLY login (disable password authentication)?" "$([ "$PASSAUTH" = no ] && echo y || echo n)"; then PASSAUTH=no; else PASSAUTH=yes; fi
        [ -n "$README_USERS" ] && echo "      README users: $README_USERS  (type 'readme' to allow exactly these)"
        ALLOW_USERS="$(cp_read "AllowUsers (space separated, 'none' = no restriction)" "${ALLOW_USERS:-none}")"
        [ "$ALLOW_USERS" = readme ] && ALLOW_USERS="$README_USERS"
        DENY_USERS="$(cp_read "DenyUsers (space separated, 'none' = nobody)" "${DENY_USERS:-none}")"
        DENY_GROUPS="$(cp_read "DenyGroups (space separated, 'none' = no group)" "${DENY_GROUPS:-none}")"
        if cp_ask "Does the README require SFTP-only access (ForceCommand internal-sftp + chroot)?" "$([ -n "$SFTP_DIR" ] && echo y || echo n)"; then
            SFTP_DIR="$(cp_read "ChrootDirectory for SFTP (must be root-owned)" "${SFTP_DIR:-/srv/sftp}")"
        else
            SFTP_DIR=""
        fi
    fi
    [ "$ALLOW_USERS" = none ] && ALLOW_USERS=""; [ "$DENY_USERS" = none ] && DENY_USERS=""; [ "$DENY_GROUPS" = none ] && DENY_GROUPS=""
    # never lock yourself out
    if [ -n "$ME" ] && [ -n "$ALLOW_USERS" ] && [[ " $ALLOW_USERS " != *" $ME "* ]]; then
        cp_warn "AllowUsers did not include you ($ME) - added so you keep SSH access"; ALLOW_USERS="$ALLOW_USERS $ME"
    fi
    if [ -n "$ME" ] && [[ " $DENY_USERS " == *" $ME "* ]]; then
        cp_warn "DenyUsers listed you ($ME) - removed"; DENY_USERS="$(echo " $DENY_USERS " | sed "s/ $ME / /g" | xargs)"
    fi
    cp_cfg_set SSH_PORT "$SSH_PORT"; cp_cfg_set SSH_PASSAUTH "$PASSAUTH"; cp_cfg_set SSH_ALLOWUSERS "$ALLOW_USERS"
    cp_cfg_set SSH_DENYUSERS "$DENY_USERS"; cp_cfg_set SSH_DENYGROUPS "$DENY_GROUPS"; cp_cfg_set SSH_SFTP_DIR "$SFTP_DIR"
fi
case "$SSH_PORT" in ''|*[!0-9]*) cp_warn "SSH port '$SSH_PORT' is not a number - using 22"; SSH_PORT=22 ;; esac
for u in $ALLOW_USERS $DENY_USERS; do id "$u" >/dev/null 2>&1 || cp_warn "SSH user rule names '$u', which is not an account here"; done
if [ -n "$ME" ] && [ -n "$DENY_GROUPS" ]; then
    for g in $DENY_GROUPS; do id -nG "$ME" 2>/dev/null | tr ' ' '\n' | grep -qx "$g" && cp_warn "You ($ME) are in denied group '$g' - you will not be able to SSH in (README wins)"; done
fi

# ------------------------------------------------------------------ permissions (G5, SSH1, SSH10) --
chown root:root "$SSHCFG"; chmod 600 "$SSHCFG"; chmod 755 /etc/ssh
if [ -d "$DROPIN_DIR" ]; then
    chown root:root "$DROPIN_DIR"; chmod 755 "$DROPIN_DIR"
    find "$DROPIN_DIR" -type f -exec chown root:root {} + -exec chmod 600 {} +
fi
chown root:root /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub 2>/dev/null
chmod 600 /etc/ssh/ssh_host_*_key 2>/dev/null; chmod 644 /etc/ssh/ssh_host_*_key.pub 2>/dev/null
# SSH1: iterate over real accounts (passwd), not over whatever directories exist in /home.
NUSERS=0
while IFS=: read -r USERNAME _ UID_ _ _ USER_HOME _; do
    if [ "$USERNAME" != "root" ] && { [ "$UID_" -lt 1000 ] || [ "$UID_" -ge 60000 ]; }; then continue; fi
    [ -d "$USER_HOME" ] || continue
    case "$USER_HOME" in /|/nonexistent|/dev/null) continue ;; esac
    mkdir -p "$USER_HOME/.ssh"; chmod 700 "$USER_HOME/.ssh"
    chown "$USERNAME": "$USER_HOME/.ssh" 2>/dev/null || cp_warn "could not chown $USER_HOME/.ssh"
    for f in "$USER_HOME/.ssh/authorized_keys" "$USER_HOME/.ssh/authorized_keys2"; do
        [ -f "$f" ] && { chmod 600 "$f"; chown "$USERNAME": "$f"; }
    done
    # SSH10: every private key type, not only id_rsa
    for f in "$USER_HOME"/.ssh/id_rsa "$USER_HOME"/.ssh/id_ed25519 "$USER_HOME"/.ssh/id_ecdsa "$USER_HOME"/.ssh/id_dsa "$USER_HOME"/.ssh/id_ecdsa_sk "$USER_HOME"/.ssh/id_ed25519_sk; do
        [ -f "$f" ] || continue
        chmod 600 "$f"; chown "$USERNAME": "$f"
        [ -f "$f.pub" ] && { chmod 644 "$f.pub"; chown "$USERNAME": "$f.pub"; }
    done
    NUSERS=$((NUSERS + 1))
done < /etc/passwd
cp_ok "Perms: sshd_config + drop-ins 600 root, host keys 600/644, ~/.ssh 700 + keys 600 for $NUSERS accounts"

# ------------------------------------------------------------------ keys + backdoors (SSH9) --
for f in /root/.ssh/authorized_keys /root/.ssh/authorized_keys2; do
    [ -s "$f" ] || continue
    n="$(grep -cvE '^[[:space:]]*(#|$)' "$f")"; [ "$n" -gt 0 ] || continue
    c="$(awk '!/^[[:space:]]*(#|$)/ {printf "%s ", (NF >= 3 ? $NF : "(no comment)")}' "$f")"
    if cp_auto "Remove $f ($n key(s): $c)? root never needs SSH keys on a CP image (backed up)" y; then
        cp_backup "$f"; rm -f "$f"; cp_ok "Removed $f"
    else
        cp_todo "Review $n root SSH key(s) in $f"
    fi
done
for f in /home/*/.ssh/authorized_keys /home/*/.ssh/authorized_keys2; do
    [ -s "$f" ] || continue
    n="$(grep -cvE '^[[:space:]]*(#|$)' "$f")"; [ "$n" -gt 0 ] || continue
    owner="$(stat -c %U "$f")"
    note=""; [ -n "$README_USERS" ] && [[ " $README_USERS " != *" $owner "* ]] && note=" - $owner is NOT a README user"
    c="$(awk '!/^[[:space:]]*(#|$)/ {printf "%s%s", sep, (NF >= 3 ? $NF : "(no comment)"); sep=", "}' "$f")"
    cp_todo "SSH keys: $f has $n key(s) [$c]$note - delete keys the README does not mention"
done
for f in /etc/ssh/sshrc /root/.ssh/rc /home/*/.ssh/rc; do
    [ -f "$f" ] || continue
    cp_warn "SSH login script (runs on every login): $f -> $(grep -vE '^[[:space:]]*(#|$)' "$f" | head -3 | tr '\n' ';')"
    if cp_auto "Remove $f ?" y; then cp_backup "$f"; rm -f "$f"; cp_ok "Removed $f"; fi
done
grep -rhiE '^[[:space:]]*(AuthorizedKeysFile|AuthorizedKeysCommand|AuthorizedKeysCommandUser|AuthorizedPrincipalsFile|ForceCommand|PermitUserRC|ChrootDirectory)[[:space:]]' "$SSHCFG" "$DROPIN_DIR" 2>/dev/null \
    | grep -viE "^[[:space:]]*(ForceCommand[[:space:]]+internal-sftp|ChrootDirectory[[:space:]]+${SFTP_DIR:-/nonexistent}|AuthorizedKeysFile[[:space:]]+\.ssh/authorized_keys([[:space:]]+\.ssh/authorized_keys2)?)[[:space:]]*$" \
    | while IFS= read -r l; do cp_todo "sshd directive to check against the README: $l"; done
if grep -qE "$MATCH_RE" "$SSHCFG"; then
    cp_todo "Active Match block in $SSHCFG (settings inside apply only to matched users): $(grep -m1 -E "$MATCH_RE" "$SSHCFG" | xargs) - check it"
fi

# ------------------------------------------------------------------ settings (SSH2-SSH7) --
echo "Authorized users only. All activity may be monitored and reported." > /etc/issue.net
chmod 644 /etc/issue.net

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

# SSH2: drop-ins in sshd_config.d are read FIRST (Include is at the top) and win -> remove our keys there.
if [ -d "$DROPIN_DIR" ]; then
    for f in "$DROPIN_DIR"/*.conf; do
        [ -f "$f" ] || continue
        for key in "${!SSHD_SETTINGS[@]}"; do
            v="$(cp_get "$f" "$key" space 1)"
            [ -n "$v" ] && { cp_warn "Drop-in $f overrode $key $v - removed there"; cp_unset "$f" "$key" space 1 >/dev/null; }
        done
    done
fi
# SSH3/G1: edit in place; new keys go ABOVE the first Match block (never inside it).
for key in "${!SSHD_SETTINGS[@]}"; do
    cp_set "$SSHCFG" "$key" "${SSHD_SETTINGS[$key]}" space 1 0 "" "$MATCH_RE"
done
# README answer "none" -> the global rule goes (sshd_config + drop-ins). Lines inside Match blocks
# (e.g. a README-required SFTP jail for one group) are never touched.
unset_global() {  # unset_global FILE KEY -> 0 if a line was removed
    local t rc=1; t="$(mktemp)"
    awk -v k="$(echo "$2" | tr '[:upper:]' '[:lower:]')" '
        tolower($0) ~ /^[ \t]*match[ \t]/ { m = 1 }
        { if (!m) { l = tolower($0); sub(/^[ \t]+/, "", l); split(l, a, /[ \t]+/); if (a[1] == k) next } print }' "$1" > "$t"
    if ! cmp -s "$t" "$1"; then cat "$t" > "$1"; rc=0; fi
    rm -f "$t"; return $rc
}
EMPTY_KEYS=()
[ -z "$ALLOW_USERS" ] && EMPTY_KEYS+=(AllowUsers); [ -z "$DENY_USERS" ] && EMPTY_KEYS+=(DenyUsers); [ -z "$DENY_GROUPS" ] && EMPTY_KEYS+=(DenyGroups)
[ -z "$SFTP_DIR" ] && [ "$(echo "$EFF_BEFORE" | awk '$1 == "forcecommand" {print $2}')" = internal-sftp ] && EMPTY_KEYS+=(ForceCommand ChrootDirectory)
for key in "${EMPTY_KEYS[@]}"; do
    for f in "$SSHCFG" "$DROPIN_DIR"/*.conf; do
        [ -f "$f" ] && unset_global "$f" "$key" && cp_info "Removed $key from $f (README: none)"
    done
done
if [ -n "$SFTP_DIR" ]; then
    mkdir -p "$SFTP_DIR"; chown root:root "$SFTP_DIR"; chmod 755 "$SFTP_DIR"
    cp_set "$SSHCFG" ForceCommand "internal-sftp" space 1 0 "" "$MATCH_RE"
    cp_set "$SSHCFG" ChrootDirectory "$SFTP_DIR" space 1 0 "" "$MATCH_RE"
    grep -qiE '^[[:space:]]*Subsystem[[:space:]]+sftp' "$SSHCFG" || cp_set "$SSHCFG" Subsystem "sftp internal-sftp" space 1 0 "" "$MATCH_RE"
fi
# SSH13: SFTP must keep working
grep -qiE '^[[:space:]]*Subsystem[[:space:]]+sftp' "$SSHCFG" || cp_warn "No 'Subsystem sftp' line - SFTP will not work (the default is: Subsystem sftp /usr/lib/openssh/sftp-server)"

# ------------------------------------------------------------------ validate (G2) --
# Some keys (DebianBanner, DisableForwarding) do not exist in every OpenSSH build:
# if sshd -t rejects one, drop just that key and try again.
for _ in 1 2 3 4 5 6; do
    ERR="$(sshd -t 2>&1)" && break
    BAD="$(echo "$ERR" | sed -n 's/.*\(Bad configuration option\|Unsupported option\): *\([A-Za-z0-9]*\).*/\2/p' | head -1)"
    [ -n "$BAD" ] || break
    cp_warn "This sshd does not support '$BAD' - removing it"
    cp_unset "$SSHCFG" "$BAD" space 1
done
if ERR="$(sshd -t 2>&1)"; then
    cp_ok "sshd -t: config valid"
else
    cp_err "sshd -t FAILED: $ERR"
    cp_restore "$SSHCFG" "$DROPIN_DIR"
    cp_todo "ssh.sh: new sshd config was invalid and was rolled back ($ERR) - fix by hand, then re-run"
    svc_result ROLLBACK "sshd -t failed"; exit 1
fi

# ------------------------------------------------------------------ firewall (G3, SSH11) --
if [ "$SSH_PORT" = "22" ]; then
    cp_ufw_allow "OpenSSH" 22/tcp
else
    command -v ufw >/dev/null 2>&1 && ufw allow "$SSH_PORT/tcp" >/dev/null && cp_ok "UFW: allowed $SSH_PORT/tcp (custom SSH port)"
fi

# ------------------------------------------------------------------ fail2ban (background) --
if cp_pkg_installed fail2ban; then
    systemctl enable --now fail2ban >/dev/null 2>&1 && cp_ok "fail2ban installed and active"
elif [ "$(cp_cfg_get SSH_FAIL2BAN)" = no ]; then
    cp_info "fail2ban: you said no earlier (--reask to change)"
elif ! cp_auto "Install fail2ban (bans SSH brute force; installs in the background, needs network)?" y; then
    [ "${CP_AUTO:-0}" = 1 ] || cp_cfg_set SSH_FAIL2BAN no
else
    F2B_LOG="$CP_STATE_DIR/fail2ban-install.log"; mkdir -p "$CP_STATE_DIR"
    # cp_apt (full path /usr/bin/apt-get, waits for a running apt-get update and the dpkg lock) in its own
    # session (setsid: survives the terminal closing) with no fd on the terminal, so the round goes on at once
    export -f cp_apt cp_info
    DEBIAN_FRONTEND=noninteractive setsid bash -c 'cp_apt install -y fail2ban || { cp_apt update && cp_apt install -y fail2ban; }
        systemctl enable --now fail2ban && echo "FAIL2BAN OK"' </dev/null >"$F2B_LOG" 2>&1 &
    cp_info "fail2ban is installing in the background (log: $F2B_LOG)"
fi

# ------------------------------------------------------------------ restart once (SSH12) --
if [ "$(svc_snap "$SSHCFG" "$DROPIN_DIR")" = "$SNAP0" ] && { systemctl is-active --quiet ssh || systemctl is-active --quiet sshd; }; then
    cp_ok "sshd config unchanged - no restart needed"
else
    # Ubuntu 24.04 / Mint 22 use ssh.socket activation - Port changes need the socket restarted
    if systemctl is-enabled ssh.socket >/dev/null 2>&1 || systemctl is-active ssh.socket >/dev/null 2>&1; then
        systemctl daemon-reload
        systemctl restart ssh.socket 2>/dev/null
    fi
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
    up=0
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if systemctl is-active --quiet ssh || systemctl is-active --quiet sshd || systemctl is-active --quiet ssh.socket; then up=1; break; fi
        sleep 0.3
    done
    if [ $up = 1 ]; then
        cp_ok "SSH restarted and active"
    else
        cp_err "SSH is not active after restart! Restoring backup."
        cp_restore "$SSHCFG" "$DROPIN_DIR"
        systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
        cp_todo "ssh.sh: sshd did not start with the hardened config - rolled back; check journalctl -xeu ssh"
        svc_result ROLLBACK "sshd did not start"; exit 1
    fi
fi

# ------------------------------------------------------------------ verify (SSH13, G2) --
EFFECTIVE="$(sshd -T 2>/dev/null)"
MISMATCH=0; CHANGED=""
for key in "${!SSHD_SETTINGS[@]}"; do
    lk="$(echo "$key" | tr '[:upper:]' '[:lower:]')"
    case "$lk" in protocol|debianbanner|allowusers|denyusers|denygroups) continue ;; esac  # not printed / printed differently
    want="$(echo "${SSHD_SETTINGS[$key]}" | tr '[:upper:]' '[:lower:]')"
    have="$(echo "$EFFECTIVE" | awk -v k="$lk" '$1==k {sub(/^[^ ]+ /,""); print; exit}' | tr '[:upper:]' '[:lower:]')"
    was="$(echo "$EFF_BEFORE" | awk -v k="$lk" '$1==k {sub(/^[^ ]+ /,""); print; exit}' | tr '[:upper:]' '[:lower:]')"
    [ -n "$was" ] && [ -n "$have" ] && [ "$was" != "$have" ] && CHANGED="$CHANGED $key:$was->$have"
    [ -z "$have" ] && continue
    if [ "$have" != "$want" ]; then cp_warn "Effective $key is '$have' (wanted '$want')"; MISMATCH=1; fi
done
[ "$MISMATCH" = 0 ] && cp_ok "Effective sshd settings (sshd -T) match"
ANSWERS=0
if ss -tlnp 2>/dev/null | grep -q ":$SSH_PORT .*sshd\|:$SSH_PORT .*systemd"; then
    if command -v ssh-keyscan >/dev/null && ssh-keyscan -T 3 -p "$SSH_PORT" localhost 2>/dev/null | grep -q ssh; then
        cp_ok "SSH answers on localhost:$SSH_PORT"; ANSWERS=1
    else
        cp_ok "Port $SSH_PORT is listening"; ANSWERS=1
    fi
else
    cp_warn "Nothing is listening on port $SSH_PORT - check 'ss -tlnp' (critical service!)"
    cp_todo "ssh.sh: nothing listens on port $SSH_PORT after hardening - check sshd"
fi

echo "  Changed (effective):${CHANGED:- nothing}" | fold -s -w 110 | sed '2,$s/^/      /'
svc_changes "$DROPIN_DIR"
if [ $ANSWERS = 1 ]; then svc_result OK; else svc_result FAIL "not listening on $SSH_PORT"; fi
cp_ok "SSH hardening complete ($((SECONDS - SVC_T0))s)"
