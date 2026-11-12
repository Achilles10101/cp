#!/bin/bash
# Samba Security Hardening Script
# Research-doc items: SMB1-SMB6, G1-G3 (baseline first: section B)
#
# Usage: sudo bash services/samba.sh [--reask]
# README answers are asked once and kept in /root/cp-state/readme.conf, so a re-run asks nothing
# (only shares that appeared since are asked about):
#   SMB_SHARES (shares kept)  SMB_WRITABLE (shares users may write to)  SMB_AUDIT (yes|no)
#   SMB_USERS_OK (Samba users you already reviewed and kept)
#   --reask   forget those answers and ask again

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../cp-common.sh
source "$SCRIPT_DIR/../cp-common.sh" 2>/dev/null || { echo "ERROR: cp-common.sh not found (keep the repo layout intact)"; exit 1; }

# ---- local helpers (same block in every services/*.sh; cp-common.sh is shared/owned elsewhere) ----
SVC=samba; SVC_T0=$SECONDS
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
[ "${1:-}" = "--reask" ] && svc_forget SMB_SHARES SMB_WRITABLE SMB_AUDIT SMB_USERS_OK
cp_hdr "Samba hardening"
cp_screenshot_prompt
command -v smbd >/dev/null 2>&1 || command -v testparm >/dev/null 2>&1 || { echo "ERROR: samba is not installed"; svc_result FAIL "not installed"; exit 1; }
cp_baseline_gate samba

SMB="$(smbd -b 2>/dev/null | sed -n 's/^[[:space:]]*CONFIGFILE:[[:space:]]*//p')"; SMB="${SMB:-/etc/samba/smb.conf}"
cp_backup "$SMB"
SNAP0="$(svc_snap "$SMB")"
README_USERS="$(echo "$(cp_cfg_get ADMINS) $(cp_cfg_get USERS)" | xargs)"

# Samba parameter names are case-insensitive and ignore spaces -> ci=1 norm=1
sset() { cp_set "$SMB" "$1" "$2" eqs 1 1 "${3:-global}"; }
sget() { cp_get "$SMB" "$1" eqs 1 1 "${2:-global}"; }
sdel() { cp_unset "$SMB" "$1" eqs 1 1 "${2:-}" >/dev/null; }
listed() { [[ " $1 " == *" $2 "* ]]; }   # listed "words" word (case-insensitive callers lower-case first)

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
    [ -n "$(cp_get "$SMB" "$k" eqs 1 1)" ] && { cp_warn "Removed deprecated '$k = $(cp_get "$SMB" "$k" eqs 1 1)'"; sdel "$k"; }
done

if [ "$(cp_cfg_get SMB_AUDIT)" = yes ]; then AUDIT=1
elif cp_cfg_has SMB_AUDIT; then AUDIT=0
elif cp_auto "Enable full_audit logging of file operations (vfs objects = full_audit)?" n; then AUDIT=1; cp_cfg_set SMB_AUDIT yes
else AUDIT=0; [ "${CP_AUTO:-0}" = 1 ] || cp_cfg_set SMB_AUDIT no; fi
if [ "$AUDIT" = 1 ]; then
    sset "vfs objects" "full_audit"
    sset "full_audit:prefix" "%u|%I|%S"
    sset "full_audit:success" "mkdir rmdir openat renameat unlinkat"
    sset "full_audit:failure" "connect"
    sset "full_audit:facility" "local5"
    sset "full_audit:priority" "notice"
fi

# ------------------------------------------------------------------ SMB4 shares --
share_names() { grep -E '^[[:space:]]*\[[^]]+\]' "$SMB" | sed -E 's/^[[:space:]]*\[([^]]+)\].*/\1/' | grep -viE '^(global)$'; }
mapfile -t SHARES < <(share_names)
USER_SHARES=()
for sh in "${SHARES[@]}"; do
    lsh="$(echo "$sh" | tr '[:upper:]' '[:lower:]')"
    case "$lsh" in printers|print\$|homes) continue ;; esac
    USER_SHARES+=("$lsh")
done
if [ ${#USER_SHARES[@]} -gt 0 ]; then
    echo "  Shares (compare with the README):"
    for lsh in "${USER_SHARES[@]}"; do
        echo "      [$lsh] $(awk -v s="$lsh" '/^[ \t]*\[/{cur=tolower($0); gsub(/^[ \t]*\[|\].*$/,"",cur); next} cur==s && !/^[ \t]*([#;]|$)/ {sub(/^[ \t]+/,""); printf "%s; ", $0}' "$SMB")"
    done
    # which shares stay (README) - asked once, a re-run only asks about NEW shares
    KEPT="$(cp_cfg_get SMB_SHARES)"
    NEW=""; for lsh in "${USER_SHARES[@]}"; do listed "$KEPT" "$lsh" || NEW="$NEW $lsh"; done
    if [ -n "$NEW" ]; then
        RM="$(cp_read "Shares NOT in the README to REMOVE (space separated, Enter = keep all)" "")"
        RM="$(echo "$RM" | tr '[:upper:]' '[:lower:]')"
        for lsh in $RM; do
            listed "${USER_SHARES[*]}" "$lsh" || { cp_warn "No share [$lsh]"; continue; }
            awk -v s="$lsh" '/^[ \t]*\[/{cur=tolower($0); gsub(/^[ \t]*\[|\].*$/,"",cur)} cur!=s' "$SMB" > "$SMB.cp-tmp" && cat "$SMB.cp-tmp" > "$SMB"; rm -f "$SMB.cp-tmp"
            cp_ok "Removed share [$lsh]"
        done
        KEPT=""; for lsh in "${USER_SHARES[@]}"; do listed "$RM" "$lsh" || KEPT="$KEPT $lsh"; done
        cp_cfg_set SMB_SHARES "$KEPT"
        WRITABLE="$(cp_read "Shares users must WRITE to (README; space separated, Enter = none, all read-only)" "$(cp_cfg_get SMB_WRITABLE)")"
        cp_cfg_set SMB_WRITABLE "$(echo "$WRITABLE" | tr '[:upper:]' '[:lower:]')"
        if cp_ask "Set 'valid users' on the shares (README names who may use them)?" n; then
            for lsh in $KEPT; do
                VU="$(cp_read "valid users for [$lsh] (e.g. @groupname user1)" "${README_USERS:-$(sget 'valid users' "$lsh")}")"
                [ -n "$VU" ] && sset "valid users" "$VU" "$lsh"
            done
        fi
    else
        cp_info "Answers (stored; --reask to change): keep shares$KEPT, writable: ${WRITABLE:-$(cp_cfg_get SMB_WRITABLE)}"
    fi
    WRITABLE="$(cp_cfg_get SMB_WRITABLE)"
    mapfile -t SHARES < <(share_names)
    for sh in "${SHARES[@]}"; do
        lsh="$(echo "$sh" | tr '[:upper:]' '[:lower:]')"
        case "$lsh" in printers|print\$) continue ;; esac
        sset "guest ok" no "$lsh"
        sdel "public" "$lsh"
        sset "wide links" no "$lsh"
        sset "create mask" 0660 "$lsh"
        sset "directory mask" 0770 "$lsh"
        [[ "$sh" == *\$ ]] && sset "browseable" no "$lsh"
        if [ "$lsh" != homes ] && ! listed "$WRITABLE" "$lsh"; then
            sset "read only" yes "$lsh"; sdel "writable" "$lsh"; sdel "writeable" "$lsh"; sdel "write list" "$lsh"
        fi
        # command-execution / privilege backdoors
        for k in "root preexec" "preexec" "exec" "postexec" "root postexec" "magic script" "magic output" "admin users" "force user" "force group"; do
            v="$(sget "$k" "$lsh")"
            [ -n "$v" ] || continue
            cp_warn "[$sh] $k = $v"
            case "$k" in
                "force user"|"force group")
                    if [ "$v" = root ] || [ "$v" = 0 ]; then cp_auto "Remove '$k = root' from [$sh]?" y && { sdel "$k" "$lsh"; cp_ok "Removed $k"; }
                    elif cp_ask "Remove '$k = $v' from [$sh] (keep it only if the README needs it)?" y; then sdel "$k" "$lsh"; cp_ok "Removed $k"; fi ;;
                *)  cp_auto "Remove '$k' from [$sh] (runs commands / grants root)?" y && { sdel "$k" "$lsh"; cp_ok "Removed $k"; } ;;
            esac
        done
    done
    cp_ok "Shares: guest ok = no, masks 0660/0770, wide links no, read only unless README-writable (${WRITABLE:-none})"
fi

# ------------------------------------------------------------------ validate --
if ! testparm -s "$SMB" >/dev/null 2>/tmp/testparm.err; then
    cp_err "testparm rejected the config:"; cat /tmp/testparm.err
    cp_restore "$SMB"
    cp_todo "samba.sh: hardened smb.conf was rejected by testparm and rolled back - check it by hand"
    svc_result ROLLBACK "testparm failed"; exit 1
fi
grep -iE 'unknown parameter|invalid' /tmp/testparm.err && cp_warn "testparm warnings above"
cp_ok "testparm: config valid"
chown root:root "$SMB"; chmod 644 "$SMB"

# ------------------------------------------------------------------ SMB6 samba users --
SUSERS="$(pdbedit -L 2>/dev/null | cut -d: -f1 | xargs)"
if [ -n "$SUSERS" ]; then
    DEF=""
    if [ -n "$README_USERS" ]; then for u in $SUSERS; do listed "$README_USERS" "$u" || DEF="$DEF $u"; done; DEF="${DEF# }"; fi
    echo "  Samba password database (Samba keeps its own users; userdel does not remove them): $SUSERS"
    NEWU=""; for u in $SUSERS; do listed "$(cp_cfg_get SMB_USERS_OK)" "$u" || NEWU="$NEWU $u"; done
    if [ -n "$README_USERS" ] && [ -z "$DEF" ]; then
        cp_ok "Every Samba user is a README user"
    elif [ -z "$NEWU" ]; then
        cp_info "Samba users already reviewed and kept (--reask to review again): $SUSERS"
    else
        [ -n "$DEF" ] && echo "      not README users: $DEF"
        RM="$(cp_read "Samba users to REMOVE (space separated, Enter = ${DEF:-none})" "$DEF")"
        for u in $RM; do if pdbedit -x -u "$u" >/dev/null 2>&1; then cp_ok "Removed Samba user $u"; else cp_warn "Could not remove $u"; fi; done
        cp_cfg_set SMB_USERS_OK "$(pdbedit -L 2>/dev/null | cut -d: -f1 | xargs)"
    fi
fi

cp_ufw_allow "Samba" 137,138/udp 139,445/tcp

# ------------------------------------------------------------------ restart once (G2) --
RESULT=OK
if [ "$(svc_snap "$SMB")" = "$SNAP0" ] && systemctl is-active --quiet smbd; then
    cp_ok "smb.conf unchanged - no restart needed"
else
    for u in smbd nmbd; do
        systemctl list-unit-files "$u.service" 2>/dev/null | grep -q "^$u" || continue
        [ "$u" = nmbd ] && ! systemctl is-enabled --quiet nmbd 2>/dev/null && ! systemctl is-active --quiet nmbd && continue
        if ! cp_restart "$u"; then
            cp_restore "$SMB"; cp_restart "$u"
            cp_todo "samba.sh: $u did not start with the hardened smb.conf - rolled back"
            svc_result ROLLBACK "$u did not start"; exit 1
        fi
    done
fi
if command -v smbclient >/dev/null 2>&1; then
    if smbclient -N -L //127.0.0.1 >/dev/null 2>&1; then cp_warn "Anonymous share listing still works"; else cp_ok "Anonymous access refused"; fi
    TU="$(cp_read "Test an authorized Samba user (Enter to skip)" "")"
    if [ -n "$TU" ]; then
        if smbclient -L //127.0.0.1 -U "$TU" >/dev/null; then cp_ok "$TU can connect"; else cp_warn "$TU cannot connect - check README requirements"; cp_todo "samba.sh: test login for $TU failed"; fi
    fi
fi
echo "  Changed:"
svc_changes "$SMB"
svc_result $RESULT
cp_ok "Samba hardening complete ($((SECONDS - SVC_T0))s)"
