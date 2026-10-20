#!/bin/bash
# Must be run as root

set -e

# Prompt the user to confirm they have taken a screenshot of the points
if [ -t 0 ]; then
    while true; do
        read -r -p "Have you taken a screenshot of the points? (y/n): " yn
        case "$yn" in
            [Yy]* ) break ;;
            [Nn]* ) echo "Please take a screenshot of the points before running this script. Exiting."; exit 1 ;;
            * ) echo "Please answer y or n." ;;
        esac
    done
fi

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "This script must be run as root, exiting"
    exit 1
fi

echo "Starting system hardening..."
echo ""

# Enable UFW

sudo ufw enable
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw status verbose
sudo ufw logging on
sudo ufw logging high

# Prompt for UFW ports

while true; do
    echo "Current allowed firewall rules:"
    sudo ufw status | grep ALLOW || echo "No ALLOW rules found."

    read -r -p "Open or Close a port? [o/c/n]: " action
    case "$action" in
        o)
            read -r -p "Port to allow (number only): " port
            sudo ufw allow "${port}/tcp"
            ;;
        c)
            echo "Numbered rules:"
            sudo ufw status numbered
            read -r -p "Rule number to delete: " num
            sudo ufw delete "$num"
            ;;
        n)
            break
            ;;
        *)
            echo "Invalid choice."
            ;;
    esac
done
sudo ufw reload

#Applying APT configuration
echo "Applying APT configuration"

sudo apt install unattended-upgrades
sudo dpkg-reconfigure unattended-upgrades

cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
cat >/etc/apt/apt.conf.d/50auto-upgrades <<'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id} stable";
    "${distro_id} ${distro_codename}-security";
    "${distro_id} ${distro_codename}-updates";
};
EOF


# Disable guest user
if systemctl list-unit-files | grep -q "lightdm.service"; then
    echo "LightDM detected. Configuring..."
    
    LIGHTDM_CONF="/etc/lightdm/lightdm.conf"
    
    if [ ! -f "$LIGHTDM_CONF" ]; then
        echo "LightDM config file not found at $LIGHTDM_CONF"
        exit 1
    fi
    
    cp "$LIGHTDM_CONF" "${LIGHTDM_CONF}.backup"
    
    sed -i '/^allow-guest=/d' "$LIGHTDM_CONF"
    sed -i '/^greeter-hide-users=/d' "$LIGHTDM_CONF"
    sed -i '/^greeter-allow-guest=/d' "$LIGHTDM_CONF"
    sed -i '/^greeter-show-manual-login=/d' "$LIGHTDM_CONF"
    sed -i '/^autologin-guest=/d' "$LIGHTDM_CONF"
    sed -i '/^autologin-user=/d' "$LIGHTDM_CONF"
    
    sed -i '/^\[Seat:\*\]/a \
allow-guest=false\
greeter-hide-users=true\
greeter-allow-guest=false\
greeter-show-manual-login=true\
autologin-guest=false\
autologin-user=NONE' "$LIGHTDM_CONF"
    
    echo "LightDM configuration updated successfully"
else
    echo "LightDM not detected"
fi


# Configure UMASK
echo "[1/4] Configuring UMASK..."

# Backup and modify login.defs
if [ -f /etc/login.defs ]; then
    cp /etc/login.defs /etc/login.defs.backup.$(date +%Y%m%d-%H%M%S)
    
    if grep -q "^UMASK" /etc/login.defs; then
        sed -i 's/^UMASK.*/UMASK\t\t027/' /etc/login.defs
    else
        echo "UMASK     027" >> /etc/login.defs
    fi
else
    echo "  ERROR: /etc/login.defs not found"
    exit 1
fi

# Backup and modify /etc/profile
if [ -f /etc/profile ]; then
    cp /etc/profile /etc/profile.backup.$(date +%Y%m%d-%H%M%S)
    
    if ! grep -q "^umask 027" /etc/profile; then
        sed -i '1i umask 027' /etc/profile
    fi
else
    echo "  ERROR: /etc/profile not found"
    exit 1
fi

echo "  ✓ UMASK configured"

# Configure sysctl
echo "[2/4] Configuring kernel parameters..."

# Backup sysctl.conf
if [ -f /etc/sysctl.conf ]; then
    cp /etc/sysctl.conf /etc/sysctl.conf.backup.$(date +%Y%m%d-%H%M%S)
else
    touch /etc/sysctl.conf
fi

# Add hardening parameters
cat >> /etc/sysctl.conf << 'EOF'

# Security Hardening Parameters

fs.file-max = 65535
fs.suid_dumpable = 0

kernel.core_uses_pid = 1
kernel.dmesg_restrict = 1
kernel.sysrq = 0
kernel.randomize_va_space = 2
kernel.pid_max = 65536

net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
net.core.netdev_max_backlog = 5000

net.ipv4.tcp_rmem = 10240 87380 12582912
net.ipv4.tcp_wmem = 10240 87380 12582912
net.ipv4.tcp_window_scaling = 1

net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0

net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.log_martians = 1
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
net.ipv4.tcp_timestamps = 1

EOF

echo "  ✓ Base parameters configured"

# IPv6 Configuration
echo "[3/4] IPv6 Configuration"
read -p "  Enable IPv6? (y/n): " ipv6_choice

if [[ "$ipv6_choice" =~ ^[Nn]$ ]]; then
    cat >> /etc/sysctl.conf << 'EOF'

# IPv6 Disabled
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

EOF
    echo "  ✓ IPv6 disabled"
elif [[ "$ipv6_choice" =~ ^[Yy]$ ]]; then
    cat >> /etc/sysctl.conf << 'EOF'

# IPv6 Security Parameters
net.ipv6.conf.default.router_solicitations = 0
net.ipv6.conf.default.accept_ra_rtr_pref = 0
net.ipv6.conf.default.accept_ra_pinfo = 0
net.ipv6.conf.default.accept_ra_defrtr = 0
net.ipv6.conf.default.autoconf = 0
net.ipv6.conf.default.dad_transmits = 0
net.ipv6.conf.default.max_addresses = 1

EOF
    echo "  ✓ IPv6 hardened"
else
    echo "  ⚠ Invalid choice, skipping IPv6 configuration"
fi

# Apply sysctl changes
echo "[4/4] Applying changes..."
if sysctl -p > /dev/null 2>&1; then
    echo "  ✓ All parameters applied"
else
    echo "  ⚠ Some parameters failed (see details below):"
    sysctl -p
fi

echo ""
echo "✓ Hardening complete"
