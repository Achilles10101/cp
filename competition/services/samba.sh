#!/bin/bash
# Samba Security Hardening Script (new)
# Research-doc items: SMB1-SMB6, G1-G3 (baseline first: section B)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../cp-common.sh
source "$SCRIPT_DIR/../cp-common.sh" 2>/dev/null || { echo "ERROR: cp-common.sh not found (keep the repo layout intact)"; exit 1; }

cp_require_root
cp_screenshot_prompt
command -v smbd >/dev/null 2>&1 || command -v testparm >/dev/null 2>&1 || { echo "ERROR: samba is not installed"; exit 1; }
cp_baseline_gate samba

SMB="$(smbd -b 2>/dev/null | sed -n 's/^[[:space:]]*CONFIGFILE:[[:space:]]*//p')"; SMB="${SMB:-/etc/samba/smb.conf}"
cp_backup "$SMB"

# Samba parameter names are case-insensitive and ignore spaces -> ci=1 norm=1
sset() { cp_set "$SMB" "$1" "$2" eqs 1 1 "${3:-global}"; }
sget() { cp_get "$SMB" "$1" eqs 1 1 "${2:-global}"; }
sdel() { cp_unset "$SMB" "$1" eqs 1 1 "${2:-}"; }

echo "========================================="
echo "Samba Security Hardening ($SMB)"
echo "========================================="

ROLE="$(sget 'server role')"
# ------------------------------------------------------------------ SMB1-SMB3 [global] --
declare -A G=(
    ["server min protocol"]="SMB2_10"
    ["client min protocol"]="SMB2_10"
    ["smb encrypt"]="required"
    ["server signing"]="mandatory"
    ["restrict anonymous"]="2"
    ["map to guest"]="never"
    ["usershare allow guests"]="no"
    ["null passwords"]="no"
    ["ntlm auth"]="ntlmv2-only"
    ["obey pam restrictions"]="yes"
    ["wide links"]="no"
    ["log level"]="2"
    ["log file"]="/var/log/samba/log.%m"
    ["max log size"]="1000"
)
case "$ROLE" in *domain\ controller*) cp_info "server role = $ROLE - not forcing 'security = user'" ;; *) G["security"]="user" ;; esac
for k in "${!G[@]}"; do sset "$k" "${G[$k]}"; done
cp_ok "[global] hardened: SMB2+ only, encryption + signing required, no guests/anonymous, NTLMv2 only"

# SMB5: deprecated parameters are NOT added; remove them if planted (defaults are already secure)
for k in "lanman auth" "encrypt passwords" "raw NTLMv2 auth" "client lanman auth" "client plaintext auth" "client NTLMv2 auth"; do
    [ -n "$(cp_get "$SMB" "$k" eqs 1 1)" ] && { cp_warn "Removing deprecated '$k = $(cp_get "$SMB" "$k" eqs 1 1)'"; sdel "$k"; }
done

if cp_ask "Enable full_audit logging of file operations (vfs objects = full_audit)?" n; then
    sset "vfs objects" "full_audit"
    sset "full_audit:prefix" "%u|%I|%S"
    sset "full_audit:success" "mkdir rmdir openat renameat unlinkat"
    sset "full_audit:failure" "connect"
    sset "full_audit:facility" "local5"
    sset "full_audit:priority" "notice"
fi

# ------------------------------------------------------------------ SMB4 shares --
echo ""
echo "Shares (compare with the README):"
mapfile -t SHARES < <(grep -E '^[[:space:]]*\[[^]]+\]' "$SMB" | sed -E 's/^[[:space:]]*\[([^]]+)\].*/\1/' | grep -viE '^(global)$')
for sh in "${SHARES[@]}"; do
    lsh="$(echo "$sh" | tr '[:upper:]' '[:lower:]')"
    echo ""
    echo "  [$sh]"
    awk -v s="$lsh" '/^[ \t]*\[/{cur=tolower($0); gsub(/^[ \t]*\[|\].*$/,"",cur); next} cur==s && !/^[ \t]*([#;]|$)/' "$SMB" | sed 's/^/      /'
    case "$lsh" in printers|print\$) continue ;; esac
    if [ "$lsh" != homes ] && ! cp_ask "Keep share [$sh] (is it listed in the README)?" y; then
        awk -v s="$lsh" '/^[ \t]*\[/{cur=tolower($0); gsub(/^[ \t]*\[|\].*$/,"",cur)} cur!=s' "$SMB" > "$SMB.tmp" && cat "$SMB.tmp" > "$SMB" && rm -f "$SMB.tmp"
        cp_ok "Removed share [$sh]"; continue
    fi
    sset "guest ok" no "$lsh"
    sdel "public" "$lsh"
    sset "wide links" no "$lsh"
    sset "create mask" 0660 "$lsh"
    sset "directory mask" 0770 "$lsh"
    [[ "$sh" == *\$ ]] && sset "browseable" no "$lsh"
    if ! cp_ask "Does the README need users to WRITE to [$sh]?" n; then sset "read only" yes "$lsh"; sdel "writable" "$lsh"; sdel "writeable" "$lsh"; sdel "write list" "$lsh"; fi
    VU="$(cp_read "valid users for [$sh] (e.g. @groupname user1; Enter = leave as is: '$(sget 'valid users' "$lsh")')" "")"
    [ -n "$VU" ] && sset "valid users" "$VU" "$lsh"
    # command-execution / privilege backdoors
    for k in "root preexec" "preexec" "exec" "postexec" "root postexec" "magic script" "magic output" "force user" "force group" "admin users"; do
        v="$(sget "$k" "$lsh")"
        [ -n "$v" ] || continue
        cp_warn "[$sh] $k = $v"
        if cp_ask "Remove '$k' from [$sh]?" y; then sdel "$k" "$lsh"; cp_ok "Removed $k"; fi
    done
done

# ------------------------------------------------------------------ validate --
echo ""
if ! testparm -s "$SMB" >/dev/null 2>/tmp/testparm.err; then
    cp_err "testparm rejected the config:"; cat /tmp/testparm.err
    cp_restore "$SMB"; exit 1
fi
grep -iE 'unknown parameter|invalid' /tmp/testparm.err && cp_warn "testparm warnings above"
cp_ok "testparm: config valid"
chown root:root "$SMB"; chmod 644 "$SMB"

# ------------------------------------------------------------------ SMB6 samba users --
echo ""
echo "Samba password database (pdbedit -L) - Samba keeps its own users; userdel does not remove them:"
pdbedit -L 2>/dev/null | sed 's/^/      /'
RM="$(cp_read "Samba users to REMOVE (space separated, Enter = none)" "")"
for u in $RM; do pdbedit -x -u "$u" >/dev/null 2>&1 && cp_ok "Removed Samba user $u" || cp_warn "Could not remove $u"; done

cp_ufw_allow "Samba" 137,138/udp 139,445/tcp

for u in smbd nmbd; do systemctl list-unit-files "$u.service" 2>/dev/null | grep -q "^$u" && cp_restart "$u"; done

# G2
if command -v smbclient >/dev/null 2>&1; then
    if smbclient -N -L //127.0.0.1 >/dev/null 2>&1; then cp_warn "Anonymous share listing still works"; else cp_ok "Anonymous access refused"; fi
    TU="$(cp_read "Test an authorized Samba user (Enter to skip)" "")"
    [ -n "$TU" ] && { smbclient -L //127.0.0.1 -U "$TU" >/dev/null && cp_ok "$TU can connect" || cp_warn "$TU cannot connect - check README requirements"; }
fi
echo "Samba hardening complete."
