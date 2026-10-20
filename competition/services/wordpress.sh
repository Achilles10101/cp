#!/bin/bash
# WordPress Security Hardening Script (new)
# Research-doc items: WP1-WP3, B7/B8 follow-up (baseline first: section B)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../cp-common.sh
source "$SCRIPT_DIR/../cp-common.sh" 2>/dev/null || { echo "ERROR: cp-common.sh not found (keep the repo layout intact)"; exit 1; }

cp_require_root
cp_screenshot_prompt
mapfile -t CONFIGS < <(find /var/www /srv /usr/share/wordpress /etc/wordpress -maxdepth 5 -name wp-config.php 2>/dev/null)
[ ${#CONFIGS[@]} -gt 0 ] || { echo "ERROR: no wp-config.php found under /var/www, /srv, /usr/share/wordpress, /etc/wordpress"; exit 1; }
cp_baseline_gate wordpress

HTTPS=0; cp_ask "Is the WordPress site served over HTTPS (FORCE_SSL_ADMIN)?" n && HTTPS=1

# wp_define FILE NAME VALUE : replace define('NAME', ...) in place, or insert it before "That's all"
wp_define() {
    local f="$1" name="$2" value="$3"
    if grep -qE "define\([[:space:]]*['\"]${name}['\"]" "$f"; then
        sed -i -E "s/define\([[:space:]]*['\"]${name}['\"][[:space:]]*,[^)]*\)/define( '$name', $value )/" "$f"
    elif grep -q "That's all, stop editing" "$f"; then
        sed -i "/That's all, stop editing/i define( '$name', $value );" "$f"
    else
        sed -i "0,/require_once/s//define( '$name', $value );\n&/" "$f"
    fi
}

wpcli() { [ -x /usr/local/bin/wp ] && sudo -u www-data /usr/local/bin/wp --path="$ROOT" "$@" 2>/dev/null; }

for CFG in "${CONFIGS[@]}"; do
    ROOT="$(dirname "$CFG")"
    echo ""
    echo "========== WordPress at $ROOT"
    cp_backup "$CFG"

    # ------------------------------------------------------------------ WP1 wp-config --
    wp_define "$CFG" DISALLOW_FILE_EDIT true
    wp_define "$CFG" WP_DEBUG false
    [ "$HTTPS" = 1 ] && wp_define "$CFG" FORCE_SSL_ADMIN true
    if grep -q "put your unique phrase here" "$CFG"; then
        for k in AUTH_KEY SECURE_AUTH_KEY LOGGED_IN_KEY NONCE_KEY AUTH_SALT SECURE_AUTH_SALT LOGGED_IN_SALT NONCE_SALT; do
            s="$(openssl rand -base64 48 | tr -d '\n/+=' | cut -c1-64)"
            sed -i -E "s/define\([[:space:]]*'$k'[[:space:]]*,[[:space:]]*'put your unique phrase here'[[:space:]]*\)/define( '$k', '$s' )/" "$CFG"
        done
        cp_ok "Generated unique salts/keys"
    fi
    if php -l "$CFG" >/dev/null 2>&1 || ! command -v php >/dev/null 2>&1; then
        cp_ok "wp-config.php: DISALLOW_FILE_EDIT, WP_DEBUG false$([ "$HTTPS" = 1 ] && echo ', FORCE_SSL_ADMIN')"
    else
        cp_err "wp-config.php no longer parses - restoring"; cp_restore "$CFG"
    fi
    chown root:www-data "$CFG"; chmod 640 "$CFG"
    cp_ok "wp-config.php -> 640 root:www-data"

    # ------------------------------------------------------------------ WP2 updates, plugins, users --
    for f in readme.html license.txt wp-config-sample.php; do
        [ -f "$ROOT/$f" ] && cp_ask "Remove $ROOT/$f (version leak)?" y && rm -f "$ROOT/$f" && cp_ok "Removed $f"
    done
    if [ ! -x /usr/local/bin/wp ] && cp_ask "Download wp-cli (github.com/wp-cli, ~7 MB) to update core/plugins/themes?" n; then
        curl -sSL -o /usr/local/bin/wp https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar && chmod 755 /usr/local/bin/wp
    fi
    if [ -x /usr/local/bin/wp ]; then
        echo "  Core: $(wpcli core version)"
        cp_ask "Update WordPress core, plugins and themes now?" y && { wpcli core update; wpcli plugin update --all; wpcli theme update --all; }
        wpcli plugin list --fields=name,status,version,update
        wpcli user list --role=administrator --fields=ID,user_login,user_email
    else
        echo "  Plugins installed (remove any the README does not need):"
        for p in "$ROOT"/wp-content/plugins/*/; do [ -d "$p" ] && echo "      $(basename "$p")"; done
        echo "  Administrators (from the database - compare with the README):"
        grep "WordPress administrator" /root/baseline/wordpress/report.txt 2>/dev/null | sed 's/^!!/     /'
    fi
    RMP="$(cp_read "Plugin folders to DELETE from wp-content/plugins (space separated, Enter = none)" "")"
    for p in $RMP; do
        [[ "$p" == */* || "$p" == .* ]] && continue
        [ -d "$ROOT/wp-content/plugins/$p" ] && rm -rf "${ROOT:?}/wp-content/plugins/$p" && cp_ok "Deleted plugin $p"
    done

    # ------------------------------------------------------------------ WP3 no PHP in uploads --
    UP="$ROOT/wp-content/uploads"
    if [ -d /etc/apache2 ] && [ -d "$UP" ]; then
        CONF=/etc/apache2/conf-available/wp-uploads-nophp.conf
        grep -qs "$UP" "$CONF" || cat >> "$CONF" <<EOF
# Added by services/wordpress.sh - never execute PHP from uploads
<Directory "$UP">
    <FilesMatch "\.(php|phtml|phar|php[0-9])$">
        Require all denied
    </FilesMatch>
</Directory>
EOF
        a2enconf wp-uploads-nophp >/dev/null 2>&1
        cp_ok "Apache: PHP execution blocked in $UP (server config, not .htaccess)"
    fi
    if [ -d /etc/nginx ] && [ -d "$UP" ]; then
        cp_warn "nginx: add inside the WordPress server block:  location ~* ^/wp-content/uploads/.*\\.php\$ { deny all; }"
    fi
    find "$UP" -name '*.php' 2>/dev/null | while read -r f; do cp_warn "PHP file inside uploads (likely webshell): $f"; done
done

# Restart the web server that serves WordPress
if [ -d /etc/apache2 ] && systemctl is-active --quiet apache2; then
    apache2ctl configtest >/dev/null 2>&1 && cp_restart apache2 || { cp_err "apache configtest failed"; a2disconf wp-uploads-nophp >/dev/null 2>&1; }
fi
command -v curl >/dev/null && echo "  Site check: HTTP $(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1/)"
echo "WordPress hardening complete."
