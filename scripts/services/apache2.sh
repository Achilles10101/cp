#!/bin/bash

set -euo pipefail

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (use sudo)"
    exit 1
fi

# Check if Apache is installed
if ! command -v apache2ctl &> /dev/null; then
    echo "ERROR: Apache2ctl is not installed on this system"
    exit 1
fi

echo ""
echo "=========================================="
echo "  Apache Security Hardening Script"
echo "=========================================="
echo ""
echo "Apache2 detected"

# Configure security.conf
echo ""
echo "Configuring /etc/apache2/conf-available/security.conf"

SECURITY_CONF="/etc/apache2/conf-available/security.conf"
if [[ ! -f "$SECURITY_CONF" ]]; then
    echo "ERROR: Security configuration file not found: $SECURITY_CONF"
    exit 1
fi

# Backup before editing
cp "$SECURITY_CONF" "${SECURITY_CONF}.backup"
echo "  Backed up to: ${SECURITY_CONF}.backup"

# Remove existing directives
sed -i '/^ServerTokens/d' "$SECURITY_CONF"
sed -i '/^ServerSignature/d' "$SECURITY_CONF"
sed -i '/^TraceEnable/d' "$SECURITY_CONF"

# Add security directives
cat >> "$SECURITY_CONF" << 'EOF'

# Security hardening directives
ServerTokens Prod
ServerSignature Off
TraceEnable Off
EOF

echo "  ✓ Security configuration updated"

# Configure apache2.conf
echo ""
echo "Configuring /etc/apache2/apache2.conf"

APACHE_CONF="/etc/apache2/apache2.conf"
if [[ ! -f "$APACHE_CONF" ]]; then
    echo "ERROR: Apache configuration file not found: $APACHE_CONF"
    exit 1
fi

# Backup before editing
cp "$APACHE_CONF" "${APACHE_CONF}.backup"
echo "  Backed up to: ${APACHE_CONF}.backup"

# Remove existing security headers and settings (to avoid duplicates)
sed -i '/Header set X-Content-Type-Options/d' "$APACHE_CONF"
sed -i '/Header set X-Frame-Options/d' "$APACHE_CONF"
sed -i '/Header set X-XSS-Protection/d' "$APACHE_CONF"
sed -i '/Header set Referrer-Policy/d' "$APACHE_CONF"
sed -i '/Header always set Permissions-Policy/d' "$APACHE_CONF"
sed -i '/Header set Content-Security-Policy/d' "$APACHE_CONF"
sed -i '/^LogLevel info/d' "$APACHE_CONF"

# Add security headers and log level
cat >> "$APACHE_CONF" << 'EOF'

Header always set Content-Security-Policy "default-src 'self'; \
script-src 'self'; \
style-src 'self' 'unsafe-inline'; \
img-src 'self' data:; \
font-src 'self' data:; \
connect-src 'self'; \
object-src 'none'; \
frame-ancestors 'none'; \
base-uri 'self'; \
form-action 'self'"

Header set Content-Security-Policy "
  default-src 'self';
  style-src 'self' 'unsafe-inline';
  script-src 'self';
  img-src 'self' data:;
  font-src 'self' data:;
  object-src 'none';
  frame-ancestors 'none';
  base-uri 'self';
"

# Logging level
LogLevel info
EOF

echo "  ✓ Security headers configured"

# Add directory restrictions
echo ""
echo "Adding directory restrictions"

# Remove old directory blocks if they exist
sed -i '/<Directory \/>/,/<\/Directory>/d' "$APACHE_CONF"
sed -i '/<Directory \/var\/www\/html>/,/<\/Directory>/d' "$APACHE_CONF"

# Add directory restrictions
cat >> "$APACHE_CONF" << 'EOF'

# Directory access restrictions
<Directory />
    AllowOverride None
    Require all denied
</Directory>

<Directory /var/www/>
    Options -Indexes -ExecCGI -Includes -FollowSymLinks
    AllowOverride None
    Require all granted
    <LimitExcept GET POST HEAD>
        Require all denied
    </LimitExcept>
</Directory>
EOF

echo "  ✓ Directory restrictions configured"

# Remove .htaccess files
echo ""
echo "Removing .htaccess files from /var/www"
HTACCESS_COUNT=$(find /var/www -name ".htaccess" 2>/dev/null | wc -l)
if [[ $HTACCESS_COUNT -gt 0 ]]; then
    find /var/www -name ".htaccess" -delete 2>/dev/null || echo "  ⚠ Some .htaccess files could not be deleted"
    echo "  ✓ Removed $HTACCESS_COUNT .htaccess file(s)"
else
    echo "  No .htaccess files found"
fi

# Enable headers module
echo ""
echo "Enabling headers module"
a2enmod headers &>/dev/null || echo "  ⚠ Failed to enable headers module"

# Enable security configuration
echo "Enabling security configuration"
a2enconf security &>/dev/null || echo "  ⚠ Failed to enable security.conf"

# Set proper permissions
echo ""
echo "Setting proper permissions on /var/www"
chown -R root:root /var/www || echo "  ⚠ Failed to change ownership"
chmod -R 755 /var/www || echo "  ⚠ Failed to set directory permissions"
find /var/www -type f -exec chmod 644 {} \; || echo "  ⚠ Failed to set file permissions"
echo "  ✓ Permissions configured"

# Test Apache configuration
echo ""
echo "Testing Apache configuration"
if apachectl configtest 2>&1; then
    echo "  ✓ Apache configuration test passed"
else
    echo "ERROR: Apache configuration test failed"
    exit 1
fi

# Restart Apache
echo ""
echo "Restarting Apache2 service"
if systemctl restart apache2; then
    echo "  ✓ Apache2 restarted successfully"
else
    echo "ERROR: Failed to restart Apache2"
    exit 1
fi

# Verify Apache is running
sleep 2
if systemctl is-active --quiet apache2; then
    echo "  ✓ Apache2 is running"
else
    echo "ERROR: Apache2 is not running after restart"
    exit 1
fi

# Summary
echo ""
echo "=========================================="
echo "Apache hardening completed successfully!"
echo "=========================================="
echo ""
echo "Backup files created:"
echo "  - ${SECURITY_CONF}.backup"
echo "  - ${APACHE_CONF}.backup"
echo ""
