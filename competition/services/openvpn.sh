#!/bin/bash
# OpenVPN Server Security Hardening Script (new)
# Research-doc item: VPN1 (baseline first: section B)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../cp-common.sh
source "$SCRIPT_DIR/../cp-common.sh" 2>/dev/null || { echo "ERROR: cp-common.sh not found (keep the repo layout intact)"; exit 1; }

cp_require_root
cp_screenshot_prompt
command -v openvpn >/dev/null 2>&1 || { echo "ERROR: openvpn is not installed"; exit 1; }
mapfile -t CONFS < <(grep -lE '^[[:space:]]*(server|mode[[:space:]]+server)([[:space:]]|$)' /etc/openvpn/server/*.conf /etc/openvpn/*.conf 2>/dev/null)
[ ${#CONFS[@]} -gt 0 ] || { echo "ERROR: no OpenVPN SERVER config found in /etc/openvpn or /etc/openvpn/server"; exit 1; }
cp_baseline_gate openvpn

OVPN_VER="$(openvpn --version 2>/dev/null | awk 'NR==1{print $2}')"
ov_major_minor() { echo "$OVPN_VER" | awk -F. '{printf "%d%02d", $1, $2}'; }
MODERN=0; [ "$(ov_major_minor)" -ge 205 ] && MODERN=1   # data-ciphers / --genkey secret need 2.5+

cp_backup /etc/openvpn
for C in "${CONFS[@]}"; do
    echo ""
    echo "========== $C (OpenVPN $OVPN_VER)"
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
    if grep -qE '^[[:space:]]*duplicate-cn' "$C"; then cp_unset "$C" duplicate-cn space; cp_ok "Removed duplicate-cn (one certificate = one client)"; fi
    if ! grep -qE '^[[:space:]]*(tls-auth|tls-crypt)[[:space:]]' "$C"; then
        cp_warn "No tls-auth/tls-crypt key (HMAC firewall) configured"
        if cp_ask "Generate ta.key and add 'tls-crypt ta.key'? EVERY client then needs the same key (README!)" n; then
            if [ "$MODERN" = 1 ]; then openvpn --genkey secret "$DIR/ta.key"; else openvpn --genkey --secret "$DIR/ta.key"; fi
            oset tls-crypt "$DIR/ta.key"
            cp_ok "tls-crypt enabled - copy $DIR/ta.key to the clients"
        fi
    fi
    find /etc/openvpn -type f \( -name '*.key' -o -name '*.pem' -path '*private*' \) -exec chmod 600 {} \; -exec chown root:root {} \;
    chmod 640 "$C"
    cp_ok "Hardened $C; key files 600"
done

# restart every server instance
for C in "${CONFS[@]}"; do
    name="$(basename "$C" .conf)"
    if [[ "$C" == /etc/openvpn/server/* ]]; then unit="openvpn-server@$name"; else unit="openvpn@$name"; fi
    if systemctl list-units --all "$unit.service" 2>/dev/null | grep -q "$unit" || systemctl is-enabled "$unit" >/dev/null 2>&1; then
        cp_restart "$unit" || { cp_err "$unit failed - restoring /etc/openvpn"; cp_restore /etc/openvpn; cp_restart "$unit"; }
    fi
done
PORT="$(awk '$1=="port"{print $2; exit}' "${CONFS[0]}")"; PROTO="$(awk '$1=="proto"{print $2; exit}' "${CONFS[0]}")"
cp_ufw_allow "OpenVPN" "${PORT:-1194}/${PROTO:-udp}"
echo "OpenVPN hardening complete."
