#!/bin/bash
# BIND9 (DNS) Security Hardening Script (new)
# Research-doc items: DNS1-DNS3, G1-G3 (baseline first: section B)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../cp-common.sh
source "$SCRIPT_DIR/../cp-common.sh" 2>/dev/null || { echo "ERROR: cp-common.sh not found (keep the repo layout intact)"; exit 1; }

cp_require_root
cp_screenshot_prompt
command -v named >/dev/null 2>&1 || [ -x /usr/sbin/named ] || { echo "ERROR: bind9 (named) is not installed"; exit 1; }
cp_baseline_gate bind9

B=/etc/bind
OPT="$B/named.conf.options"
cp_backup "$B" /etc/default/named /etc/default/bind9

rollback() { cp_err "$1 - restoring $B"; cp_restore "$B" /etc/default/named /etc/default/bind9; exit 1; }

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

echo "========================================="
echo "BIND9 Security Hardening"
echo "========================================="

# ------------------------------------------------------------------ DNS1 options --
SECONDARIES="$(cp_read "Secondary DNS servers allowed to transfer zones (IPs separated by ';', Enter = none)" "")"
if [ -n "$SECONDARIES" ]; then set_option allow-transfer "{ ${SECONDARIES%;}; }"; else set_option allow-transfer "{ none; }"; fi
set_option version '"not disclosed"'
set_option dnssec-validation auto
set_option querylog yes
if cp_ask "Is this an AUTHORITATIVE-only server (no recursive lookups for clients - check the README)?" n; then
    set_option recursion no
else
    set_option recursion yes
    set_option allow-recursion "{ localhost; localnets; }"
fi
cp_ok "options: version hidden, zone transfers restricted, recursion limited, DNSSEC validation auto, query log"

# ------------------------------------------------------------------ DNS2 zones --
echo ""
echo "Zones:"
for f in "$B"/named.conf.local "$B"/named.conf; do
    [ -f "$f" ] || continue
    awk '/^[ \t]*zone[ \t]/{print "      " FILENAME ": " $0}' "$f"
    if grep -qE 'allow-update[[:space:]]*\{[^}]*[^[:space:]}][^}]*\}' "$f" && ! grep -qE 'allow-update[[:space:]]*\{[[:space:]]*none;[[:space:]]*\}' "$f"; then
        cp_warn "$f allows dynamic updates:"; grep -nE 'allow-update' "$f" | sed 's/^/        /'
        if cp_ask "Set every allow-update to { none; } (say no only if the README needs dynamic DNS/DHCP updates)?" y; then
            sed -i -E 's/allow-update[[:space:]]*\{[^}]*\}[[:space:]]*;/allow-update { none; };/' "$f"; cp_ok "allow-update { none; } in $f"
        fi
    fi
    # zones without allow-update inherit the default (none) - nothing to add
done
for z in $(grep -hoE 'file[[:space:]]+"[^"]+"' "$B"/named.conf.local 2>/dev/null | sed -E 's/file[[:space:]]+"([^"]+)"/\1/'); do
    zn="$(grep -B5 "\"$z\"" "$B/named.conf.local" | sed -nE 's/^[[:space:]]*zone[[:space:]]+"([^"]+)".*/\1/p' | tail -1)"
    [ -f "$z" ] || [ -f "$B/$z" ] || continue
    echo "  Records in $z (review for rogue entries):"
    grep -vE '^[[:space:]]*(;|$)' "$z" 2>/dev/null | sed 's/^/        /' | head -40
    [ -n "$zn" ] && command -v named-checkzone >/dev/null && named-checkzone "$zn" "$z" >/dev/null 2>&1 || true
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
find "$B" -maxdepth 1 -type f \( -name 'named.conf*' -o -name 'db.*' -o -name '*.zone' -o -name 'zones.rfc1918' -o -name 'bind.keys' \) -exec chown root:bind {} \; -exec chmod 644 {} \;
find "$B" -maxdepth 1 -type f -name '*.key' -exec chown root:bind {} \; -exec chmod 640 {} \;
cp_ok "Perms: /etc/bind root:bind 2755, configs/zones 644, keys 640"

# ------------------------------------------------------------------ validate + restart --
echo ""
named-checkconf -z "$B/named.conf" >/tmp/named-check.txt 2>&1 || { cat /tmp/named-check.txt; rollback "named-checkconf failed"; }
cp_ok "named-checkconf -z passed"
cp_ufw_allow "Bind9" 53
UNIT="$(cp_first_unit named bind9)"
cp_restart "${UNIT:-named}" || rollback "named did not start"

if command -v dig >/dev/null 2>&1; then
    V="$(dig +short @127.0.0.1 version.bind chaos txt 2>/dev/null)"
    [ "$V" = '"not disclosed"' ] && cp_ok "version.bind hidden" || cp_warn "version.bind answer: ${V:-<none>}"
fi
echo "BIND9 hardening complete."
