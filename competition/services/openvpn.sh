#!/bin/bash
# OpenVPN Server Security Hardening Script
# Research-doc item: VPN1 (baseline first: section B)
#
# Usage: sudo bash services/openvpn.sh [--reask]
# README answer kept in /root/cp-state/readme.conf: VPN_TLSCRYPT (yes|no)
#   --reask   forget it and ask again

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../cp-common.sh
source "$SCRIPT_DIR/../cp-common.sh" 2>/dev/null || { echo "ERROR: cp-common.sh not found (keep the repo layout intact)"; exit 1; }

# ---- local helpers (same block in every services/*.sh; cp-common.sh is shared/owned elsewhere) ----
SVC=openvpn; SVC_T0=$SECONDS
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
[ "${1:-}" = "--reask" ] && svc_forget VPN_TLSCRYPT
cp_hdr "OpenVPN hardening"
cp_screenshot_prompt
command -v openvpn >/dev/null 2>&1 || { echo "ERROR: openvpn is not installed"; svc_result FAIL "not installed"; exit 1; }
mapfile -t CONFS < <(grep -lE '^[[:space:]]*(server|mode[[:space:]]+server)([[:space:]]|$)' /etc/openvpn/server/*.conf /etc/openvpn/*.conf 2>/dev/null)
[ ${#CONFS[@]} -gt 0 ] || { echo "ERROR: no OpenVPN SERVER config found in /etc/openvpn or /etc/openvpn/server"; svc_result FAIL "no server config"; exit 1; }
cp_baseline_gate openvpn

OVPN_VER="$(openvpn --version 2>/dev/null | awk 'NR==1{print $2}')"
ov_major_minor() { echo "$OVPN_VER" | awk -F. '{printf "%d%02d", $1, $2}'; }
MODERN=0; [ "$(ov_major_minor)" -ge 205 ] && MODERN=1   # data-ciphers / --genkey secret need 2.5+

cp_backup /etc/openvpn
SNAP0="$(svc_snap /etc/openvpn)"
for C in "${CONFS[@]}"; do
    DIR="$(dirname "$C")"
    oset() { cp_set "$C" "$1" "$2" space 0 0; }
    if [ "$MODERN" = 1 ]; then
        oset data-ciphers "AES-256-GCM:AES-128-GCM"
        grep -qE '^[[:space:]]*cipher[[:space:]]' "$C" && oset cipher AES-256-GCM
    else
        oset cipher AES-256-GCM
    fi
    oset auth SHA256
    oset tls-version-min 1.2
    oset user nobody
    oset group nogroup
    oset persist-key __FLAG__
    oset persist-tun __FLAG__
    oset verb 3
    mkdir -p /var/log/openvpn
    oset status /var/log/openvpn/openvpn-status.log
    oset log-append /var/log/openvpn/openvpn.log
    if grep -qE '^[[:space:]]*duplicate-cn' "$C"; then cp_unset "$C" duplicate-cn space >/dev/null; cp_ok "Removed duplicate-cn (one certificate = one client)"; fi
    if ! grep -qE '^[[:space:]]*(tls-auth|tls-crypt)[[:space:]]' "$C"; then
        # README-dependent: every client needs the same key -> asked once
        if cp_cfg_has VPN_TLSCRYPT; then WANT_TC="$(cp_cfg_get VPN_TLSCRYPT)"
        else
            cp_warn "No tls-auth/tls-crypt key (HMAC firewall) configured"
            WANT_TC=no; cp_ask "Generate ta.key and add 'tls-crypt ta.key'? EVERY client then needs the same key (README!)" n && WANT_TC=yes
            cp_cfg_set VPN_TLSCRYPT "$WANT_TC"
        fi
        if [ "$WANT_TC" = yes ]; then
            if [ "$MODERN" = 1 ]; then openvpn --genkey secret "$DIR/ta.key"; else openvpn --genkey --secret "$DIR/ta.key"; fi
            oset tls-crypt "$DIR/ta.key"
            cp_ok "tls-crypt enabled"
            cp_todo "OpenVPN: copy $DIR/ta.key to every client (tls-crypt was enabled)"
        fi
    fi
    find /etc/openvpn -type f \( -name '*.key' -o -name '*.pem' -path '*private*' \) -exec chmod 600 {} + -exec chown root:root {} +
    chmod 640 "$C"
    cp_ok "Hardened $C (AES-GCM, SHA256, TLS 1.2+, nobody:nogroup, logging); key files 600"
done

# restart every server instance (only when a config changed)
RESULT=OK
for C in "${CONFS[@]}"; do
    name="$(basename "$C" .conf)"
    if [[ "$C" == /etc/openvpn/server/* ]]; then unit="openvpn-server@$name"; else unit="openvpn@$name"; fi
    systemctl list-units --all "$unit.service" 2>/dev/null | grep -q "$unit" || systemctl is-enabled "$unit" >/dev/null 2>&1 || continue
    if [ "$(svc_snap /etc/openvpn)" = "$SNAP0" ] && systemctl is-active --quiet "$unit"; then
        cp_ok "$unit config unchanged - no restart needed"
    elif ! cp_restart "$unit"; then
        cp_err "$unit failed - restoring /etc/openvpn"; cp_restore /etc/openvpn; cp_restart "$unit"
        cp_todo "openvpn.sh: $unit did not start with the hardened config - rolled back"
        RESULT="ROLLBACK $unit did not start"
    fi
done
PORT="$(awk '$1=="port"{print $2; exit}' "${CONFS[0]}")"; PROTO="$(awk '$1=="proto"{print $2; exit}' "${CONFS[0]}")"
cp_ufw_allow "OpenVPN" "${PORT:-1194}/${PROTO:-udp}"
echo "  Changed:"
svc_changes /etc/openvpn
svc_result $RESULT
cp_ok "OpenVPN hardening complete ($((SECONDS - SVC_T0))s)"
