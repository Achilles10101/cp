#!/bin/bash
# vsftpd Security Configuration Script

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

# Define configuration parameters
CONFIG_PARAMS=(
    "listen=YES"
    "listen_ipv6=NO"
    "anonymous_enable=NO"
    "local_enable=YES"
    "write_enable=YES"
    "local_umask=022"
    "chroot_local_user=YES"
    "allow_writeable_chroot=NO"
    "ascii_upload_enable=NO"
    "ascii_download_enable=NO"
    "use_localtime=YES"
    "ssl_enable=YES"
    "rsa_cert_file=/etc/ssl/certs/vsftpd.crt"
    "rsa_private_key_file=/etc/ssl/private/vsftpd.key"
    "require_ssl_reuse=NO"
    "ssl_sslv2=NO"
    "ssl_sslv3=NO"
    "ssl_tlsv1=YES"
    "force_local_logins_ssl=YES"
    "force_local_data_ssl=YES"
    "pasv_enable=YES"
    "pasv_min_port=40000"
    "pasv_max_port=50000"
    "xferlog_enable=YES"
    "xferlog_std_format=NO"
    "log_ftp_protocol=YES"
    "dual_log_enable=YES"
)

echo "=== Starting vsftpd configuration ==="
echo ""

# Step 1: Set restrictive permissions on vsftpd configuration file
echo "[1/7] Setting permissions on /etc/vsftpd.conf..."
chown root:root /etc/vsftpd.conf
chmod 600 /etc/vsftpd.conf
# Step 2: Configure local_root directory permissions
echo "[2/7] Configuring local_root directory permissions..."
LOCAL_ROOT=$(grep "^local_root=" /etc/vsftpd.conf 2>/dev/null | cut -d'=' -f2 || echo "")

if [ -n "$LOCAL_ROOT" ]; then
    echo "  Found local_root: $LOCAL_ROOT"
    chown root:root "$LOCAL_ROOT"
    chmod 755 "$LOCAL_ROOT"/*
    echo "  ✓ Permissions set on $LOCAL_ROOT"
else
    echo "  ⚠ WARNING: local_root not defined in /etc/vsftpd.conf"
    echo "  → Manually set chmod 755 on your vsftpd root directory"
fi
echo ""

# Step 3: Allow FTP traffic through UFW
echo "[3/7] Configuring UFW firewall rules..."
ufw allow 21/tcp >/dev/null 2>&1
ufw allow 40000:50000/tcp >/dev/null 2>&1
echo "  ✓ Allowed port 21/tcp"
echo "  ✓ Allowed ports 40000:50000/tcp (passive mode)"
echo ""

# Step 4: Create self-signed SSL certificate
echo "[4/7] Creating self-signed SSL certificate..."
openssl req -x509 -nodes -days 3650 -newkey rsa:4096 \
    -keyout /etc/ssl/private/vsftpd.key \
    -out /etc/ssl/certs/vsftpd.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=vsftpd" \
    >/dev/null 2>&1
echo "  ✓ Certificate created"
echo ""

# Step 5: Backup existing configuration
echo "[5/7] Backing up existing vsftpd.conf..."
BACKUP_FILE="/etc/vsftpd.conf.backup.$(date +%Y%m%d_%H%M%S)"
cp /etc/vsftpd.conf "$BACKUP_FILE"
echo "  ✓ Backup saved: $BACKUP_FILE"
echo ""

# Step 6: Update vsftpd.conf with secure parameters
echo "[6/7] Updating /etc/vsftpd.conf with secure settings..."

# Remove existing instances of all configuration keys
TEMP_CONFIG=$(mktemp)
cp /etc/vsftpd.conf "$TEMP_CONFIG"

for param in "${CONFIG_PARAMS[@]}"; do
    KEY=$(echo "$param" | cut -d'=' -f1)
    sed -i "/^${KEY}=/d" "$TEMP_CONFIG"
done

# Append new configuration values
for param in "${CONFIG_PARAMS[@]}"; do
    echo "$param" >> "$TEMP_CONFIG"
done

# Replace original config with updated version
mv -f "$TEMP_CONFIG" /etc/vsftpd.conf
chmod 600 /etc/vsftpd.conf
chown root:root /etc/vsftpd.conf

echo "  ✓ Configuration updated with secure settings"
echo ""

# Step 7: Restart vsftpd service
echo "[7/7] Restarting vsftpd service..."
if systemctl restart vsftpd 2>/dev/null; then
    sleep 1
    if systemctl is-active --quiet vsftpd; then
        echo "  ✓ vsftpd service restarted successfully"
    else
        echo "  ✗ ERROR: vsftpd service is not active after restart"
        exit 1
    fi
else
    echo "  ✗ ERROR: Failed to restart vsftpd service"
    exit 1
fi
echo ""

echo "=== vsftpd configuration complete! ==="