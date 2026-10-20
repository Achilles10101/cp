#!/bin/bash
# Squid Proxy Security Hardening Script (new)
# Research-doc "Other services" quick hits (baseline first: section B)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../cp-common.sh
source "$SCRIPT_DIR/../cp-common.sh" 2>/dev/null || { echo "ERROR: cp-common.sh not found (keep the repo layout intact)"; exit 1; }

cp_require_root
cp_screenshot_prompt
command -v squid >/dev/null 2>&1 || { echo "ERROR: squid is not installed"; exit 1; }
cp_baseline_gate squid

SQ=/etc/squid/squid.conf
cp_backup /etc/squid

echo "========================================="
echo "Squid Security Hardening"
echo "========================================="
# 'allow all' turns the proxy into an open proxy
if grep -qE '^[[:space:]]*http_access[[:space:]]+allow[[:space:]]+all[[:space:]]*$' "$SQ" /etc/squid/conf.d/*.conf 2>/dev/null; then
    sed -i -E 's/^([[:space:]]*http_access[[:space:]]+allow[[:space:]]+all[[:space:]]*)$/# disabled by squid.sh: \1/' "$SQ" /etc/squid/conf.d/*.conf 2>/dev/null
    cp_ok "Removed 'http_access allow all'"
fi
# cache manager only from localhost - must come BEFORE the first allow rule
if ! grep -qE '^[[:space:]]*http_access[[:space:]]+deny[[:space:]]+manager' "$SQ"; then
    FIRST="$(grep -nE '^[[:space:]]*http_access[[:space:]]' "$SQ" | head -1 | cut -d: -f1)"
    if [ -n "$FIRST" ]; then sed -i "${FIRST}i http_access allow localhost manager\nhttp_access deny manager" "$SQ"
    else printf 'http_access allow localhost manager\nhttp_access deny manager\n' >> "$SQ"; fi
    cp_ok "Cache manager restricted to localhost"
fi
# final rule must be deny all
LAST="$(grep -E '^[[:space:]]*http_access[[:space:]]' "$SQ" | tail -1 | xargs)"
if [ "$LAST" != "http_access deny all" ]; then echo "http_access deny all" >> "$SQ"; cp_ok "Added final 'http_access deny all'"; fi
cp_set "$SQ" httpd_suppress_version_string on space
cp_set "$SQ" via off space
cp_set "$SQ" forwarded_for delete space
cp_ok "Version string suppressed, Via/X-Forwarded-For removed"
echo ""
echo "http_access rules now (order matters - compare with the README):"
grep -nE '^[[:space:]]*http_access' "$SQ" | sed 's/^/      /'
PORT="$(awk '$1=="http_port"{print $2; exit}' "$SQ")"
echo "  http_port: ${PORT:-3128} (README may require a specific port)"

if squid -k parse -f "$SQ" >/tmp/squid-parse.txt 2>&1; then
    cp_ok "squid -k parse passed"
else
    grep -iE 'error|fatal' /tmp/squid-parse.txt; cp_err "squid config invalid - restoring"; cp_restore /etc/squid; exit 1
fi
chown -R root:root /etc/squid; chmod 644 "$SQ"
cp_restart squid || { cp_restore /etc/squid; cp_restart squid; exit 1; }
cp_ufw_allow "Squid" "${PORT##*:}/tcp"
echo "Squid hardening complete."
