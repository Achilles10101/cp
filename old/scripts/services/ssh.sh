#!/bin/bash

# SSH Security Hardening Script

set -e

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root (use sudo)"
    exit 1
fi

# Prompt for screenshot confirmation
if [ -t 0 ]; then
    while true; do
        read -r -p "Have you taken a screenshot of the points? (y/n): " yn
        case "$yn" in
            [Yy]* ) break ;;
            [Nn]* ) echo "Please take a screenshot first. Exiting."; exit 1 ;;
            * ) echo "Please answer y or n." ;;
        esac
    done
fi

echo "========================================="
echo "SSH Security Hardening Script"
echo "========================================="
echo ""

echo ""
echo "Step 1: Backing up SSH configuration"
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
echo "Backup created: /etc/ssh/sshd_config.backup"
echo ""

echo "Step 2: Setting SSH config permissions"
chown root:root /etc/ssh/sshd_config
chmod 600 /etc/ssh/sshd_config
chmod 755 /etc/ssh
echo ""

echo "Step 3: Setting host key permissions"
chmod 600 /etc/ssh/ssh_host_*_key 2>/dev/null || true
chmod 644 /etc/ssh/ssh_host_*_key.pub 2>/dev/null || true
echo "Step 4: Configuring user SSH directories"

for USER_HOME in /home/*; do
    if [ -d "$USER_HOME" ]; then
        USERNAME=$(basename "$USER_HOME")
        
        echo "Processing user: $USERNAME"
        
        # Create .ssh directory if it doesn't exist
        if [ ! -d "$USER_HOME/.ssh" ]; then
            mkdir -p "$USER_HOME/.ssh"
            echo "  - Created .ssh directory"
        fi
        
        # Set .ssh directory permissions
        chmod 700 "$USER_HOME/.ssh"
        chown "$USERNAME:$USERNAME" "$USER_HOME/.ssh"
        echo "  - Set .ssh directory permissions (700)"
        
        # Set authorized_keys permissions if it exists
        if [ -f "$USER_HOME/.ssh/authorized_keys" ]; then
            chmod 600 "$USER_HOME/.ssh/authorized_keys"
            chown "$USERNAME:$USERNAME" "$USER_HOME/.ssh/authorized_keys"
            echo "  - Set authorized_keys permissions (600)"
        fi
        
        # Set private key permissions if it exists
        if [ -f "$USER_HOME/.ssh/id_rsa" ]; then
            chmod 600 "$USER_HOME/.ssh/id_rsa"
            chown "$USERNAME:$USERNAME" "$USER_HOME/.ssh/id_rsa"
            echo "  - Set private key permissions (600)"
        fi
        
        # Set public key permissions if it exists
        if [ -f "$USER_HOME/.ssh/id_rsa.pub" ]; then
            chmod 644 "$USER_HOME/.ssh/id_rsa.pub"
            chown "$USERNAME:$USERNAME" "$USER_HOME/.ssh/id_rsa.pub"
            echo "  - Set public key permissions (644)"
        fi
        
        echo ""
    fi
done

echo "Step 5: Updating SSH security settings"

SSHCFG="/etc/ssh/sshd_config"

# Settings to enforce
declare -A SSHD_SETTINGS=(
    ["PermitRootLogin"]="no"
    ["X11Forwarding"]="no"
    ["LoginGraceTime"]="30"
    ["MaxAuthTries"]="3"
    ["LogLevel"]="VERBOSE"
    ["IgnoreRhosts"]="yes"
    ["HostbasedAuthentication"]="no"
    ["PermitEmptyPasswords"]="no"
    ["AllowTcpForwarding"]="no"
    ["ClientAliveCountMax"]="2"
    ["Compression"]="no"
    ["AllowAgentForwarding"]="no"
)

# Remove existing entries
for key in "${!SSHD_SETTINGS[@]}"; do
    sed -i "/^[#[:space:]]*${key}[[:space:]=]/Id" "$SSHCFG"
done

# Append our clean entries
for key in "${!SSHD_SETTINGS[@]}"; do
    echo "${key} ${SSHD_SETTINGS[$key]}" >> "$SSHCFG"
done


echo "Step 6: Testing SSH configuration"

if sshd -t; then
    echo "SSH configuration test: PASSED"
else
    echo "SSH configuration test: FAILED"
    echo "Restoring backup configuration..."
    cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
    exit 1
fi

echo ""
echo "Step 7: Configuring firewall"

if command -v ufw > /dev/null 2>&1; then
    ufw allow ssh
    echo "UFW rule added for SSH"
else
    echo "UFW not found - skipping firewall configuration"
fi

echo ""
echo "Step 8: Installing fail2ban"

if apt update > /dev/null 2>&1 && apt install fail2ban -y > /dev/null 2>&1; then
    systemctl enable fail2ban > /dev/null 2>&1
    systemctl start fail2ban > /dev/null 2>&1
    echo "fail2ban installed and started"
else
    echo "Failed to install fail2ban - continuing"
fi

echo ""

echo "Step 9: Restarting SSH service"

systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
echo "SSH service restarted"
echo ""

echo "SSH hardening complete"
