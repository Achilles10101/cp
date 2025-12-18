#!/bin/bash
set -euo pipefail

info() { printf '[*] %s\n' "$1"; }
ok()   { printf '[+] %s\n' "$1"; }
err()  { printf '[!] %s\n' "$1" >&2; }

(( EUID == 0 )) || { err "Must run as root"; exit 1; }

# Unauthorized UID 0 accounts
info "Checking for unauthorized UID 0 accounts..."
mapfile -t uid0_users < <(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd || true)

for u in "${uid0_users[@]}"; do
    new_uid=2000
    while id -u "$new_uid" &>/dev/null; do new_uid=$((new_uid+1)); done
    if usermod -u "$new_uid" "$u" &>/dev/null; then
        ok "Reassigned $u to $new_uid"
    else
        err "Failed to reassign $u"
    fi
done

(( ${#uid0_users[@]} == 0 )) && ok "No unauthorized UID 0 accounts."

# Prohibited package/service scan
info "Scanning for prohibited software..."
targets=(
john xinetd postfix sendmail nfs-kernel-server nmap vuze frostwire kismet minetest minetest-server medusa hydra
truecrack ophcrack nikto cryptcat nc netcat tightvncserver x11vnc nfs xinetd
samba postgresql vsftpd apache apache2 mysql php snmp dovecot bind9 nginx
wireshark telnet
)

found_any=0
for pkg in "${targets[@]}"; do
    systemctl list-unit-files --type=service 2>/dev/null | grep -qw "$pkg" && {
        printf '[*] Service: %s\n' "$pkg"
        found_any=1
    }

    if command -v dpkg &>/dev/null; then
        dpkg -l 2>/dev/null | awk '{print $2}' | grep -xq "$pkg" && {
            printf '[*] Package: %s\n' "$pkg"
            found_any=1
        }
    elif command -v rpm &>/dev/null; then
        rpm -qa 2>/dev/null | grep -xq "$pkg" && {
            printf '[*] Package: %s\n' "$pkg"
            found_any=1
        }
    fi
done

(( found_any == 0 )) && ok "No prohibited software found."

# Targeted filesystem scan for media and archive files
info "Scanning filesystem for media and archive files (excluding /usr/share)..."
find / -path /usr/share -prune -o -type f \( \
    -iname "*.mp3" -o -iname "*.mp4" -o -iname "*.avi" -o -iname "*.mkv" \
    -o -iname "*.wav" -o -iname "*.ogg" -o -iname "*.flac" \
    -o -iname "*.zip" -o -iname "*.rar" -o -iname "*.7z" -o -iname "*.py" \
    -o -iname "*.png" -o -iname "*.jpg" -o -iname "*.jpeg" -o -iname "*.gif" \
\) -print 2>/dev/null
ok "File scan completed."

# Password aging (single success/failure log)
info "Applying password aging policy..."

current_user=$(logname 2>/dev/null || echo "$SUDO_USER")

mapfile -t users < <(
    getent passwd |
    awk -F: -v cur="$current_user" \
        '$3>=1000 && $3<60000 && $1!=cur && $7!~/(nologin|false)$/ {print $1}' || true
)

aging_success=true

if (( ${#users[@]} > 0 )) && command -v chage &>/dev/null; then
    for u in "${users[@]}"; do
        chage -M 90 -m 7 -W 14 "$u" &>/dev/null || aging_success=false
    done
else
    aging_success=false
fi

$aging_success && ok "Password aging policy applied." || err "Password aging update failed."

# Enumerate human users
getent passwd | awk -F: '$3 >= 1000 && $3 != 65534 {print $1 ":" $6}' | while IFS=: read -r user home; do
    if [[ -d "$home" ]]; then
        chmod 0750 "$home"
        echo "Set secure home on $home (user: $user)"
    else
        echo "Skipping $user — home directory missing: $home"
    fi
done

# Sysctl block
info "Writing sysctl hardening config..."

sysctl_conf="/etc/sysctl.d/99-hardening.conf"
cat > "$sysctl_conf" <<'EOF'
fs.file-max = 65535
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0
kernel.core_uses_pid = 1
kernel.dmesg_restrict = 1
kernel.exec-shield = 1
kernel.sysrq = 0
kernel.randomize_va_space = 2
kernel.pid_max = 65536
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_rmem = 10240 87380 12582912
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_wmem = 10240 87380 12582912
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_all = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.ip_forward = 0
net.ipv4.ip_local_port_range = 2000 65000
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 5
net.ipv4.tcp_timestamps = 9
EOF

chmod 644 "$sysctl_conf"
ok "Sysctl config written."

# IPv6 prompt
read -rp "Is IPv6 required? (y/n): " ipv6_response
if [[ "$ipv6_response" =~ ^[Nn]$ ]]; then
    {
        echo 'net.ipv6.conf.all.disable_ipv6 = 1'
        echo 'net.ipv6.conf.default.disable_ipv6 = 1'
        echo 'net.ipv6.conf.lo.disable_ipv6 = 1'
    } >> "$sysctl_conf"
    ok "IPv6 disabled"
else
    {
        echo 'net.ipv6.conf.default.router_solicitations = 0'
        echo 'net.ipv6.conf.default.accept_ra_rtr_pref = 0'
        echo 'net.ipv6.conf.default.accept_ra_pinfo = 0'
        echo 'net.ipv6.conf.default.accept_ra_defrtr = 0'
        echo 'net.ipv6.conf.default.autoconf = 0'
        echo 'net.ipv6.conf.default.dad_transmits = 0'
        echo 'net.ipv6.conf.default.max_addresses = 1'
    } >> "$sysctl_conf"
    ok "IPv6 restrictions applied"
fi

# Single sysctl reload
info "Reloading sysctl..."
sysctl --system &>/dev/null && ok "Sysctl reloaded." || err "Sysctl reload failed."

# Network shares
info "Checking for network shares..."
mount | grep -E "nfs|cifs|smb" >/dev/null && ok "Network shares detected." || ok "No network shares found."

ok "Script completed."
