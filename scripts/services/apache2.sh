#!/bin/bash
# Apache Security Hardening Script
# Research-doc items: WEB1-WEB10, G1-G5 (baseline first: section B)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../cp-common.sh
source "$SCRIPT_DIR/../cp-common.sh" 2>/dev/null || { echo "ERROR: cp-common.sh not found (keep the repo layout intact)"; exit 1; }

cp_require_root
cp_screenshot_prompt

# Check if Apache is installed
if ! command -v apache2ctl &> /dev/null; then
    echo "ERROR: Apache2ctl is not installed on this system"
    exit 1
fi

cp_baseline_gate apache2

echo ""
echo "=========================================="
echo "  Apache Security Hardening Script"
echo "=========================================="
echo ""
echo "Apache2 detected"

SECURITY_CONF="/etc/apache2/conf-available/security.conf"
APACHE_CONF="/etc/apache2/apache2.conf"
cp_backup /etc/apache2          # whole tree, so a failed configtest can be rolled back completely
cp "$SECURITY_CONF" "${SECURITY_CONF}.backup" 2>/dev/null
cp "$APACHE_CONF" "${APACHE_CONF}.backup"

rollback() {
    cp_err "$1 - rolling back /etc/apache2"
    cp_restore /etc/apache2
    systemctl restart apache2 2>/dev/null
    exit 1
}

# ---------------------------------------------------------------- README questions --
echo ""
if cp_ask "Does a web app on this server use .htaccess rewrites (WordPress permalinks, Joomla, etc.)?" n; then APP_HTACCESS=1; else APP_HTACCESS=0; fi
if cp_ask "Enable HTTPS (mod_ssl + default-ssl site, TLS 1.2/1.3 only)?" y; then ENABLE_TLS=1; else ENABLE_TLS=0; fi
if cp_ask "Add a strict Content-Security-Policy header (can break sites that load CDN assets)?" y; then ADD_CSP=1; else ADD_CSP=0; fi

# Module removal (the repo version had removed this step; it is now opt-in)
if cp_ask "Review and disable unneeded Apache modules (status, info, autoindex, cgi, userdir, dav...)?" n; then
# Display currently loaded modules
echo ""
echo "Currently loaded Apache modules:"
echo ""
apache2ctl -M 2>/dev/null || { echo "ERROR: Failed to list Apache modules"; exit 1; }
echo ""

# Get user input for custom modules to disable
echo ""
echo "Enter comma-separated list of additional modules to disable (or press Enter to skip):"
modules_input=""; [ -t 0 ] && read -r modules_input

CUSTOM_MODULES=()
if [[ -n "$modules_input" ]]; then
    IFS=',' read -ra CUSTOM_MODULES <<< "$modules_input"
    for i in "${!CUSTOM_MODULES[@]}"; do CUSTOM_MODULES[$i]=$(echo "${CUSTOM_MODULES[$i]}" | xargs); done
fi

# Standard modules recommended for removal (WEB6 adds info, dav, dav_fs)
STANDARD_MODULES=("status" "info" "autoindex" "negotiation" "cgi" "cgid" "userdir" "dav" "dav_fs")

echo ""
echo "Standard modules recommended for removal:"
for mod in "${STANDARD_MODULES[@]}"; do echo "  - $mod"; done

echo ""
echo "Enter comma-separated list of modules to EXCLUDE from removal (or press Enter to remove all):"
exclude_input=""; [ -t 0 ] && read -r exclude_input

EXCLUDED_MODULES=()
if [[ -n "$exclude_input" ]]; then
    IFS=',' read -ra EXCLUDED_MODULES <<< "$exclude_input"
    for i in "${!EXCLUDED_MODULES[@]}"; do EXCLUDED_MODULES[$i]=$(echo "${EXCLUDED_MODULES[$i]}" | xargs); done
fi

MODULES_TO_DISABLE=("${CUSTOM_MODULES[@]+"${CUSTOM_MODULES[@]}"}")
for mod in "${STANDARD_MODULES[@]}"; do
    skip=false
    for excluded in "${EXCLUDED_MODULES[@]+"${EXCLUDED_MODULES[@]}"}"; do
        [[ "$mod" == "$excluded" ]] && { skip=true; break; }
    done
    [[ "$skip" == false ]] && MODULES_TO_DISABLE+=("$mod")
done

if [[ ${#MODULES_TO_DISABLE[@]} -gt 0 ]]; then
    echo ""
    echo "Disabling Apache modules..."
    for module in "${MODULES_TO_DISABLE[@]}"; do
        [[ -z "$module" ]] && continue
        if a2query -m "$module" &>/dev/null; then
            if a2dismod -f "$module" &>/dev/null; then echo "  + Disabled: $module"; else echo "  ! Failed to disable: $module"; fi
        else
            echo "  - Module not enabled or not found: $module"
        fi
    done
fi
fi   # end of opt-in module removal

# ------------------------------------------------------------------ security.conf (G1) --
echo ""
echo "Configuring $SECURITY_CONF (in place)"
cp_set "$SECURITY_CONF" ServerTokens Prod space 1
cp_set "$SECURITY_CONF" ServerSignature Off space 1
cp_set "$SECURITY_CONF" TraceEnable Off space 1
cp_set "$SECURITY_CONF" FileETag None space 1                 # WEB6
cp_set "$SECURITY_CONF" LimitRequestBody 10485760 space 1     # WEB6: 10 MB request body cap
# Conflicting copies elsewhere would silently win (later file wins in Apache)
for f in /etc/apache2/conf-enabled/*.conf /etc/apache2/sites-enabled/*.conf "$APACHE_CONF"; do
    [ -f "$f" ] || continue
    [ "$(readlink -f "$f")" = "$(readlink -f "$SECURITY_CONF")" ] && continue
    for k in ServerTokens ServerSignature TraceEnable; do
        v="$(cp_get "$f" "$k" space 1)"
        [ -n "$v" ] && { cp_warn "$f also sets $k $v - removing"; cp_unset "$f" "$k" space 1; }
    done
done
echo "  + Security configuration updated"

# ------------------------------------------------------------------ apache2.conf --
echo ""
echo "Configuring $APACHE_CONF"
cp_set "$APACHE_CONF" Timeout 60 space 1                      # WEB6 (default 300)
cp_set "$APACHE_CONF" LogLevel info space 1

# Security headers (dedicated block, replaced on every run)
sed -i '/^# BEGIN cp-hardening headers/,/^# END cp-hardening headers/d' "$APACHE_CONF"
sed -i '/Header set X-Content-Type-Options/d; /Header set X-Frame-Options/d; /Header set X-XSS-Protection/d; /Header set Referrer-Policy/d; /Header always set Permissions-Policy/d; /Header \(always \)\?set Content-Security-Policy/d; /^#Security headers$/d' "$APACHE_CONF"
{
    echo "# BEGIN cp-hardening headers"
    echo 'Header set X-Content-Type-Options "nosniff"'
    echo 'Header set X-Frame-Options "DENY"'
    echo 'Header set X-XSS-Protection "0"'          # WEB7: legacy header; "0" is the current recommendation
    echo 'Header set Referrer-Policy "no-referrer"'
    echo 'Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"'
    [ "$ADD_CSP" = 1 ] && echo "Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'\""
    echo "# END cp-hardening headers"
} >> "$APACHE_CONF"
echo "  + Security headers configured"

# ------------------------------------------------------------------ directory restrictions --
echo ""
echo "Adding directory restrictions"
if [ "$APP_HTACCESS" = 1 ]; then
    HTML_OPTS="Options -Indexes -ExecCGI -Includes +SymLinksIfOwnerMatch"; HTML_OVERRIDE="AllowOverride All"
else
    HTML_OPTS="Options -Indexes -ExecCGI -Includes -FollowSymLinks"; HTML_OVERRIDE="AllowOverride None"
fi
sed -i '/<Directory \/>/,/<\/Directory>/d' "$APACHE_CONF"
sed -i '/<Directory \/var\/www\/html>/,/<\/Directory>/d' "$APACHE_CONF"
# WEB3: the stock <Directory /var/www/> block keeps "Options Indexes FollowSymLinks" for every
# vhost under /var/www - fix it in place (all options must be +/- signed or none).
sed -i '/<Directory \/var\/www\/>/,/<\/Directory>/{s/^\([[:space:]]*\)Options .*/\1Options -Indexes +SymLinksIfOwnerMatch -ExecCGI -Includes/}' "$APACHE_CONF"
cat >> "$APACHE_CONF" << EOF

# Directory access restrictions
<Directory />
    AllowOverride None
    Require all denied
</Directory>

<Directory /var/www/html>
    $HTML_OPTS
    $HTML_OVERRIDE
    Require all granted
    <LimitExcept GET POST HEAD>
        Require all denied
    </LimitExcept>
</Directory>
EOF
grep -lE '^[[:space:]]*Options[^#]*[^-+]Indexes' /etc/apache2/sites-enabled/*.conf /etc/apache2/conf-enabled/*.conf 2>/dev/null \
    | while read -r f; do cp_warn "Directory listing (Options Indexes) still enabled in $f - review"; done
echo "  + Directory restrictions configured"

# ------------------------------------------------------------------ .htaccess (WEB1) --
echo ""
echo "Reviewing .htaccess files in /var/www (NOT deleting - they can be required or protective)"
find /var/www -name ".htaccess" 2>/dev/null | while read -r f; do
    cp_warn "$f:"; grep -vE '^[[:space:]]*(#|$)' "$f" | head -8 | sed 's/^/        /'
done
[ "$APP_HTACCESS" = 0 ] && echo "  (AllowOverride None: .htaccess files under /var/www/html are ignored anyway)"

# ------------------------------------------------------------------ run user (WEB5) --
echo ""
echo "Checking the Apache run user"
RUNU="$(sed -n 's/^export APACHE_RUN_USER=//p' /etc/apache2/envvars | tr -d '"')"
RUNG="$(sed -n 's/^export APACHE_RUN_GROUP=//p' /etc/apache2/envvars | tr -d '"')"
if [ "$RUNU" != "www-data" ] || [ "$RUNG" != "www-data" ]; then
    cp_warn "Apache runs as $RUNU:$RUNG (default www-data:www-data)"
    if cp_ask "Set APACHE_RUN_USER/GROUP back to www-data?" y; then
        sed -i 's/^export APACHE_RUN_USER=.*/export APACHE_RUN_USER=www-data/; s/^export APACHE_RUN_GROUP=.*/export APACHE_RUN_GROUP=www-data/' /etc/apache2/envvars
        cp_ok "Run user reset to www-data"
    fi
else
    cp_ok "Apache runs as www-data"
fi
grep -rnE '^[[:space:]]*(User|Group)[[:space:]]+[^$]' /etc/apache2/*.conf /etc/apache2/conf-enabled /etc/apache2/sites-enabled 2>/dev/null \
    | while read -r l; do cp_warn "Hard-coded User/Group directive: $l"; done
grep -rnE '^[[:space:]]*(DocumentRoot|Alias)[[:space:]]+"?(/|/etc|/root|/home[^ ]*|/var/log)"?([[:space:]]|$)' /etc/apache2/sites-enabled /etc/apache2/conf-enabled 2>/dev/null \
    | while read -r l; do cp_warn "Suspicious DocumentRoot/Alias (WEB10): $l"; done

# ------------------------------------------------------------------ TLS (WEB4) --
if [ "$ENABLE_TLS" = 1 ]; then
    echo ""
    echo "Enabling HTTPS"
    [ -f /etc/ssl/certs/ssl-cert-snakeoil.pem ] || make-ssl-cert generate-default-snakeoil --force-overwrite 2>/dev/null
    a2enmod ssl &>/dev/null
    SSL_MOD_CONF=/etc/apache2/mods-available/ssl.conf
    cp_set "$SSL_MOD_CONF" SSLProtocol "-all +TLSv1.2 +TLSv1.3" space 1
    cp_set "$SSL_MOD_CONF" SSLHonorCipherOrder on space 1
    cp_set "$SSL_MOD_CONF" SSLCompression off space 1
    if ! grep -lqs 'SSLEngine[[:space:]]\+on' /etc/apache2/sites-enabled/*.conf; then
        a2ensite default-ssl &>/dev/null && echo "  + Enabled site default-ssl"
    fi
    for f in /etc/apache2/sites-available/*.conf; do
        grep -q '<VirtualHost[^>]*:443' "$f" 2>/dev/null || continue
        grep -q 'Strict-Transport-Security' "$f" || sed -i '0,/<VirtualHost[^>]*:443[^>]*>/s//&\n\t\tHeader always set Strict-Transport-Security "max-age=31536000"/' "$f"
    done
    echo "  + mod_ssl: TLS 1.2/1.3 only, HSTS on :443 vhosts"
fi

# ------------------------------------------------------------------ optional WAF (WEB9) --
if cp_ask "Install optional mod_security2 (+CRS) and mod_evasive? (no scoring evidence; needs network)" n; then
    if apt-get install -y libapache2-mod-security2 modsecurity-crs libapache2-mod-evasive >/dev/null 2>&1; then
        [ -f /etc/modsecurity/modsecurity.conf ] || cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
        sed -i 's/^SecRuleEngine .*/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf
        a2enmod security2 evasive &>/dev/null
        cp_ok "mod_security2 (SecRuleEngine On) + mod_evasive enabled"
    else
        cp_warn "Install failed - skipped"
    fi
fi

# Enable headers module / security configuration
echo ""
a2enmod headers &>/dev/null || echo "  ! Failed to enable headers module"
a2enconf security &>/dev/null || echo "  ! Failed to enable security.conf"

# ------------------------------------------------------------------ permissions (WEB2, WEB8, G5) --
echo ""
echo "Setting proper permissions"
KEEP_WRITABLE=()
while IFS= read -r d; do KEEP_WRITABLE+=("$d"); done < <(find /var/www -type d -user www-data \( -name uploads -o -name cache -o -name tmp -o -name sessions -o -name files \) 2>/dev/null)
if [ ${#KEEP_WRITABLE[@]} -gt 0 ]; then
    echo "  Directories the web app writes to (owned by www-data):"; printf '      %s\n' "${KEEP_WRITABLE[@]}"
    cp_ask "Keep these writable by www-data (recommended, apps break otherwise)?" y || KEEP_WRITABLE=()
fi
if cp_ask "Reset /var/www to root ownership, dirs 755 / files 644 (except the folders above)?" y; then
    chown -R root:root /var/www || echo "  ! Failed to change ownership"
    find /var/www -type d -exec chmod 755 {} \; || echo "  ! Failed to set directory permissions"
    find /var/www -type f -exec chmod 644 {} \; || echo "  ! Failed to set file permissions"
    for d in "${KEEP_WRITABLE[@]+"${KEEP_WRITABLE[@]}"}"; do chown -R www-data:www-data "$d"; chmod 755 "$d"; done
    echo "  + /var/www permissions configured"
fi
find /etc/apache2 -type d -exec chmod 755 {} \; ; find /etc/apache2 -type f -exec chmod 644 {} \; ; chown -R root:root /etc/apache2
[ -d /var/log/apache2 ] && { chown root:adm /var/log/apache2; chmod 750 /var/log/apache2; }
[ -d /etc/ssl/private ] && { chown root:ssl-cert /etc/ssl/private 2>/dev/null; chmod 710 /etc/ssl/private; find /etc/ssl/private -type f -exec chmod 640 {} \; ; }
echo "  + /etc/apache2 root 755/644, /var/log/apache2 750 root:adm, /etc/ssl/private keys 640"

# ------------------------------------------------------------------ web content (WEB10) --
cp_web_scan /var/www

# ------------------------------------------------------------------ firewall (G3) --
echo ""
# G3: a scored image checked for the exact profile "Apache Secure" (HTTPS only) - ask which one
if [ "$ENABLE_TLS" = 1 ]; then
    if cp_ask "HTTPS ONLY (UFW profile 'Apache Secure', port 80 closed)? No = 'Apache Full' (80+443)" n; then
        cp_ufw_allow "Apache Secure" 443/tcp
    else
        cp_ufw_allow "Apache Full" 80/tcp 443/tcp
    fi
else
    cp_ufw_allow "Apache" 80/tcp
fi

# Test Apache configuration
echo ""
echo "Testing Apache configuration"
if apachectl configtest 2>&1; then
    echo "  + Apache configuration test passed"
else
    rollback "Apache configuration test failed"
fi

# Restart Apache
echo ""
echo "Restarting Apache2 service"
cp_restart apache2 || rollback "Apache2 did not come back up"

# G2: functional test
echo ""
if command -v curl >/dev/null 2>&1; then
    H="$(curl -sI --max-time 5 http://127.0.0.1/ 2>/dev/null)"
    if [ -n "$H" ]; then
        cp_ok "HTTP answers: $(echo "$H" | head -1 | tr -d '\r')"
        echo "$H" | grep -i '^Server:' | grep -qiE 'apache/[0-9]' && cp_warn "Server header still shows a version" || cp_ok "Server header hides the version"
        [ "$(curl -s -o /dev/null -w '%{http_code}' -X TRACE --max-time 5 http://127.0.0.1/)" = 405 ] && cp_ok "TRACE disabled (405)"
    else
        cp_warn "No HTTP answer from 127.0.0.1 - check the site (critical service!)"
    fi
    [ "$ENABLE_TLS" = 1 ] && curl -skI --max-time 5 https://127.0.0.1/ >/dev/null && cp_ok "HTTPS answers"
fi

echo ""
echo "=========================================="
echo "Apache hardening completed successfully!"
echo "=========================================="
echo ""
echo "Backups: $CP_BACKUP_ROOT/$CP_TS/etc/apache2  ${SECURITY_CONF}.backup  ${APACHE_CONF}.backup"
echo ""
