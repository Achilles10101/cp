#!/bin/bash
# BIND9 (DNS) Security Hardening Script
# Research-doc items: DNS1-DNS3, G1-G3 (baseline first: section B)
#
# Usage: sudo bash services/bind9.sh [--reask]
# README answers are asked once and kept in /root/cp-state/readme.conf:
#   DNS_SECONDARIES (IPs allowed to transfer zones, empty = none)  DNS_AUTHORITATIVE (yes|no)
#   --reask   forget those answers and ask again

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../cp-common.sh
source "$SCRIPT_DIR/../cp-common.sh" 2>/dev/null || { echo "ERROR: cp-common.sh not found (keep the repo layout intact)"; exit 1; }

# ---- local helpers (same block in every services/*.sh; cp-common.sh is shared/owned elsewhere) ----
SVC=bind9; SVC_T0=$SECONDS
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
[ "${1:-}" = "--reask" ] && svc_forget DNS_SECONDARIES DNS_AUTHORITATIVE
cp_hdr "BIND9 hardening"
cp_screenshot_prompt
command -v named >/dev/null 2>&1 || [ -x /usr/sbin/named ] || { echo "ERROR: bind9 (named) is not installed"; svc_result FAIL "not installed"; exit 1; }
cp_baseline_gate bind9

B=/etc/bind
OPT="$B/named.conf.options"
cp_backup "$B" /etc/default/named /etc/default/bind9
SNAP0="$(svc_snap "$B" /etc/default/named /etc/default/bind9)"
UNIT="$(cp_first_unit named bind9)"; UNIT="${UNIT:-named}"

rollback() {
    cp_err "$1 - restoring $B"; cp_restore "$B" /etc/default/named /etc/default/bind9
    systemctl is-active --quiet "$UNIT" || systemctl restart "$UNIT" 2>/dev/null   # never stop a running named
    cp_todo "bind9.sh: $1 - hardening rolled back; check named-checkconf by hand"
    svc_result ROLLBACK "$1"; exit 1
}

# set_option NAME "VALUE" : set "NAME VALUE;" inside options { } (in place; inserted before the
# closing "};" of the options block when absent). Handles values with braces like "{ none; }".
set_option() {
    local name="$1" value="$2" tmp; tmp="$(mktemp)"
    awk -v name="$name" -v value="$value" '
        function strip(s) { sub(/\/\/.*/, "", s); sub(/#.*/, "", s); return s }
        !inopt && /^[ \t]*options[ \t]*\{/ { inopt = 1; depth = 0 }
        inopt {
            line = strip($0)
            # an existing statement for this option (single line) -> replace
            if (depth == 1 && line ~ "^[ \t]*" name "[ \t]") {
                if (!done) { print "\t" name " " value ";"; done = 1 }
                # skip multi-line { ... }; blocks
                o = gsub(/\{/, "{", line); c = gsub(/\}/, "}", line)
                if (o > c) { skipdepth = o - c; skipping = 1 }
                next
            }
            if (skipping) { o = gsub(/\{/, "{", line); c = gsub(/\}/, "}", line); skipdepth += o - c; if (skipdepth <= 0) skipping = 0; next }
            o = gsub(/\{/, "{", line); c = gsub(/\}/, "}", line)
            if (depth + o - c == 0 && c > 0 && depth >= 1) {
                if (!done) { print "\t" name " " value ";"; done = 1 }
                inopt = 0
            }
            depth += o - c
        }
        { print }
    ' "$OPT" > "$tmp" && cat "$tmp" > "$OPT"; rm -f "$tmp"
}

# ------------------------------------------------------------------ README answers (DNS1) --
if cp_cfg_has DNS_SECONDARIES && cp_cfg_has DNS_AUTHORITATIVE; then
    SECONDARIES="$(cp_cfg_get DNS_SECONDARIES)"; AUTH="$(cp_cfg_get DNS_AUTHORITATIVE)"
    cp_info "Answers (stored; --reask to change): zone transfers to ${SECONDARIES:-none}, authoritative-only $AUTH"
else
    SECONDARIES=""; AUTH=no
    echo "  README-dependent DNS settings - Enter keeps all of them:"
    echo "      no zone transfers (allow-transfer none) | recursion for local clients only (localhost; localnets)"
    if cp_ask "Does the README change any of these (secondary DNS servers, authoritative-only server)?" n; then
        SECONDARIES="$(cp_read "Secondary DNS servers allowed to transfer zones (IPs separated by ';', Enter = none)" "")"
        cp_ask "Is this an AUTHORITATIVE-only server (no recursive lookups for clients - check the README)?" n && AUTH=yes
    fi
    cp_cfg_set DNS_SECONDARIES "$SECONDARIES"; cp_cfg_set DNS_AUTHORITATIVE "$AUTH"
fi
if [ -n "$SECONDARIES" ]; then set_option allow-transfer "{ ${SECONDARIES%;}; }"; else set_option allow-transfer "{ none; }"; fi
set_option version '"not disclosed"'
set_option dnssec-validation auto
set_option querylog yes
if [ "$AUTH" = yes ]; then
    set_option recursion no
else
    set_option recursion yes
    set_option allow-recursion "{ localhost; localnets; }"
fi
cp_ok "options: version hidden, zone transfers restricted, recursion $([ "$AUTH" = yes ] && echo off || echo 'local only'), DNSSEC validation auto, query log"

# ------------------------------------------------------------------ DNS2 zones --
for f in "$B"/named.conf.local "$B"/named.conf; do
    [ -f "$f" ] || continue
    if grep -qE 'allow-update[[:space:]]*\{[^}]*[^[:space:]}][^}]*\}' "$f" && ! grep -qE 'allow-update[[:space:]]*\{[[:space:]]*none;[[:space:]]*\}' "$f"; then
        cp_warn "$f allows dynamic updates: $(grep -E 'allow-update' "$f" | xargs)"
        if cp_ask "Set every allow-update to { none; } (say no only if the README needs dynamic DNS/DHCP updates)?" y; then
            sed -i -E 's/allow-update[[:space:]]*\{[^}]*\}[[:space:]]*;/allow-update { none; };/' "$f"; cp_ok "allow-update { none; } in $f"
        fi
    fi
    # zones without allow-update inherit the default (none) - nothing to add
done
ZONES="$(awk '/^[ \t]*zone[ \t]/{gsub(/"/,"",$2); printf "%s ", $2}' "$B"/named.conf.local 2>/dev/null)"
[ -n "$ZONES" ] && cp_info "Local zones: $ZONES"
for z in $(grep -hoE 'file[[:space:]]+"[^"]+"' "$B"/named.conf.local 2>/dev/null | sed -E 's/file[[:space:]]+"([^"]+)"/\1/'); do
    zn="$(grep -B5 "\"$z\"" "$B/named.conf.local" | sed -nE 's/^[[:space:]]*zone[[:space:]]+"([^"]+)".*/\1/p' | tail -1)"
    [ -f "$z" ] || z="$B/$z"; [ -f "$z" ] || continue
    n="$(grep -cvE '^[[:space:]]*(;|$)' "$z")"
    echo "  Records in $z ($n lines):"
    grep -vE '^[[:space:]]*(;|$)' "$z" | head -15 | sed 's/^/        /'
    cp_todo "Review the $n records in DNS zone file $z for rogue entries (compare with the README)"
    if [ -n "$zn" ] && command -v named-checkzone >/dev/null && ! named-checkzone "$zn" "$z" >/dev/null 2>&1; then cp_warn "named-checkzone $zn $z reports errors"; fi
done

# ------------------------------------------------------------------ DNS3 run user + perms --
for d in /etc/default/named /etc/default/bind9; do
    [ -f "$d" ] || continue
    if ! grep -qE '^OPTIONS=.*-u[[:space:]]+bind' "$d"; then
        if grep -q '^OPTIONS=' "$d"; then sed -i -E 's/^OPTIONS="?([^"]*)"?/OPTIONS="\1 -u bind"/' "$d"; else echo 'OPTIONS="-u bind"' >> "$d"; fi
        cp_ok "named runs as user bind ($d)"
    fi
done
chown root:bind "$B"; chmod 2755 "$B"
find "$B" -maxdepth 1 -type f \( -name 'named.conf*' -o -name 'db.*' -o -name '*.zone' -o -name 'zones.rfc1918' -o -name 'bind.keys' \) -exec chown root:bind {} + -exec chmod 644 {} +
find "$B" -maxdepth 1 -type f -name '*.key' -exec chown root:bind {} + -exec chmod 640 {} +
cp_ok "Perms: /etc/bind root:bind 2755, configs/zones 644, keys 640"

# ------------------------------------------------------------------ validate + restart once --
named-checkconf -z "$B/named.conf" >/tmp/named-check.txt 2>&1 || { cat /tmp/named-check.txt; rollback "named-checkconf failed"; }
cp_ok "named-checkconf -z passed"
cp_ufw_allow "Bind9" 53
if [ "$(svc_snap "$B" /etc/default/named /etc/default/bind9)" = "$SNAP0" ] && systemctl is-active --quiet "$UNIT"; then
    cp_ok "BIND config unchanged - no restart needed"
else
    cp_restart "$UNIT" || rollback "named did not start"
fi

RESULT=OK
if command -v dig >/dev/null 2>&1; then
    V="$(dig +short +time=2 +tries=1 @127.0.0.1 version.bind chaos txt 2>/dev/null)"
    if [ "$V" = '"not disclosed"' ]; then cp_ok "DNS answers, version.bind hidden"; else cp_warn "version.bind answer: ${V:-<none>}"; fi
    [ -n "$V" ] || { cp_todo "bind9.sh: named does not answer on 127.0.0.1 - check it (critical service)"; RESULT="FAIL no DNS answer"; }
fi
echo "  Changed:"
svc_changes "$B" /etc/default/named /etc/default/bind9
svc_result $RESULT
cp_ok "BIND9 hardening complete ($((SECONDS - SVC_T0))s)"
