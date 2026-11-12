#!/bin/bash
# Squid Proxy Security Hardening Script
# Research-doc "Other services" quick hits (baseline first: section B). No README questions.
#
# Usage: sudo bash services/squid.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../cp-common.sh
source "$SCRIPT_DIR/../cp-common.sh" 2>/dev/null || { echo "ERROR: cp-common.sh not found (keep the repo layout intact)"; exit 1; }

# ---- local helpers (same block in every services/*.sh; cp-common.sh is shared/owned elsewhere) ----
SVC=squid; SVC_T0=$SECONDS
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
cp_hdr "Squid hardening"
cp_screenshot_prompt
command -v squid >/dev/null 2>&1 || { echo "ERROR: squid is not installed"; svc_result FAIL "not installed"; exit 1; }
cp_baseline_gate squid

SQ=/etc/squid/squid.conf
cp_backup /etc/squid
SNAP0="$(svc_snap /etc/squid)"

# 'allow all' turns the proxy into an open proxy
if grep -qE '^[[:space:]]*http_access[[:space:]]+allow[[:space:]]+all[[:space:]]*$' "$SQ" /etc/squid/conf.d/*.conf 2>/dev/null; then
    sed -i -E 's/^([[:space:]]*http_access[[:space:]]+allow[[:space:]]+all[[:space:]]*)$/# disabled by squid.sh: \1/' "$SQ" /etc/squid/conf.d/*.conf 2>/dev/null
    cp_ok "Removed 'http_access allow all' (open proxy)"
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
cp_info "http_access rules now (order matters - compare with the README): $(grep -E '^[[:space:]]*http_access' "$SQ" | sed 's/^[[:space:]]*http_access[[:space:]]*//' | tr '\n' ';')"
PORT="$(awk '$1=="http_port"{print $2; exit}' "$SQ")"
cp_info "http_port: ${PORT:-3128} (README may require a specific port)"

if squid -k parse -f "$SQ" >/tmp/squid-parse.txt 2>&1; then
    cp_ok "squid -k parse passed"
else
    grep -iE 'error|fatal' /tmp/squid-parse.txt; cp_err "squid config invalid - restoring"; cp_restore /etc/squid
    cp_todo "squid.sh: hardened squid.conf failed 'squid -k parse' and was rolled back"
    svc_result ROLLBACK "squid -k parse failed"; exit 1
fi
chown -R root:root /etc/squid; chmod 644 "$SQ"
# reload, not restart: a squid restart waits shutdown_lifetime (30 s) for open connections,
# and every change above (http_access, headers, version string) is applied by a reconfigure.
if [ "$(svc_snap /etc/squid)" = "$SNAP0" ] && systemctl is-active --quiet squid; then
    cp_ok "squid config unchanged - no reload needed"
elif systemctl is-active --quiet squid && systemctl reload squid 2>/dev/null && sleep 1 && systemctl is-active --quiet squid; then
    cp_ok "squid reloaded (squid -k reconfigure) and active"
elif ! cp_restart squid; then
    cp_restore /etc/squid; cp_restart squid
    cp_todo "squid.sh: squid did not start with the hardened config - rolled back"
    svc_result ROLLBACK "squid did not start"; exit 1
fi
# UFW: only squid's own http_port(s), like systemconfig.sh - the "Squid" profile opens 5 ports
# (2048,3128,3130,3401,4827). Ports bound to loopback only need no rule.
if command -v ufw >/dev/null 2>&1; then
    ALLP="$(awk '$1 == "http_port" || $1 == "https_port" {print $2}' "$SQ" /etc/squid/conf.d/*.conf 2>/dev/null)"
    [ -n "$ALLP" ] || ALLP=3128                      # squid's default http_port
    PORTS="$(echo "$ALLP" | grep -vE '^(127\.|localhost:|\[::1\]:)' | sed 's/.*://' | grep -E '^[0-9]+$' | sort -u)"
    [ -n "$PORTS" ] || cp_info "squid listens on loopback only - no UFW rule needed"
    for p in $PORTS; do ufw allow "$p/tcp" >/dev/null && cp_ok "UFW: allowed $p/tcp (squid http_port)"; done
fi
echo "  Changed:"
svc_changes /etc/squid
svc_result OK
cp_ok "Squid hardening complete ($((SECONDS - SVC_T0))s)"
