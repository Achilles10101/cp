#!/bin/bash
# WordPress Security Hardening Script
# Research-doc items: WP1-WP3, B7/B8 follow-up (baseline first: section B)
#
# Usage: sudo bash services/wordpress.sh [--reask]
# Answers kept in /root/cp-state/readme.conf: WP_HTTPS (yes|no), WP_CLI (no = do not offer the download again),
#   WP_PLUGINS_OK (plugins you already reviewed and kept)
#   --reask   forget those answers and ask again

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../cp-common.sh
source "$SCRIPT_DIR/../cp-common.sh" 2>/dev/null || { echo "ERROR: cp-common.sh not found (keep the repo layout intact)"; exit 1; }

# ---- local helpers (same block in every services/*.sh; cp-common.sh is shared/owned elsewhere) ----
SVC=wordpress; SVC_T0=$SECONDS
svc_result() { mkdir -p "$CP_STATE_DIR/svc" 2>/dev/null && echo "$*" > "$CP_STATE_DIR/svc/$SVC.result"; }
svc_snap()   { find "$@" -xdev -type f -print0 2>/dev/null | LC_ALL=C sort -z | xargs -0 -r md5sum 2>/dev/null | md5sum | cut -c1-32; }
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
[ "${1:-}" = "--reask" ] && svc_forget WP_HTTPS WP_CLI WP_PLUGINS_OK
cp_hdr "WordPress hardening"
cp_screenshot_prompt
mapfile -t CONFIGS < <(find /var/www /srv /usr/share/wordpress /etc/wordpress -maxdepth 5 -name wp-config.php 2>/dev/null)
[ ${#CONFIGS[@]} -gt 0 ] || { echo "ERROR: no wp-config.php found under /var/www, /srv, /usr/share/wordpress, /etc/wordpress"; svc_result FAIL "no wp-config.php"; exit 1; }
cp_baseline_gate wordpress

# README answer, asked once (HTTPS-only from apache2.sh's 'Apache Secure' answer when known)
if cp_cfg_has WP_HTTPS; then
    HTTPS=0; [ "$(cp_cfg_get WP_HTTPS)" = yes ] && HTTPS=1
elif [ "$(cp_cfg_get APACHE_UFW)" = secure ]; then
    HTTPS=1; cp_cfg_set WP_HTTPS yes; cp_info "Site is HTTPS-only (apache2.sh answer) -> FORCE_SSL_ADMIN"
else
    HTTPS=0; cp_ask "Is the WordPress site served over HTTPS (FORCE_SSL_ADMIN)?" n && HTTPS=1
    cp_cfg_set WP_HTTPS "$([ $HTTPS = 1 ] && echo yes || echo no)"
fi

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

APACHE_CHANGED=0
for CFG in "${CONFIGS[@]}"; do
    ROOT="$(dirname "$CFG")"
    cp_info "WordPress at $ROOT"
    cp_backup "$CFG"

    # ------------------------------------------------------------------ WP1 wp-config --
    wp_define "$CFG" DISALLOW_FILE_EDIT true
    wp_define "$CFG" WP_DEBUG false
    [ "$HTTPS" = 1 ] && wp_define "$CFG" FORCE_SSL_ADMIN true
    if grep -q "put your unique phrase here" "$CFG"; then
        for k in AUTH_KEY SECURE_AUTH_KEY LOGGED_IN_KEY NONCE_KEY AUTH_SALT SECURE_AUTH_SALT LOGGED_IN_SALT NONCE_SALT; do
            s="$(openssl rand -base64 48 | tr -d '\n/+=' | cut -c1-64)"
            sed -i -E "s/define\([[:space:]]*['\"]${k}['\"][[:space:]]*,[[:space:]]*['\"]put your unique phrase here['\"][[:space:]]*\)/define( '$k', '$s' )/" "$CFG"
        done
        cp_ok "Generated unique salts/keys"
    fi
    if php -l "$CFG" >/dev/null 2>&1 || ! command -v php >/dev/null 2>&1; then
        cp_ok "wp-config.php: DISALLOW_FILE_EDIT, WP_DEBUG false$([ "$HTTPS" = 1 ] && echo ', FORCE_SSL_ADMIN')"
    else
        cp_err "wp-config.php no longer parses - restoring"; cp_restore "$CFG"
        cp_todo "wordpress.sh: $CFG did not parse after the edit and was restored - edit it by hand"
    fi
    chown root:www-data "$CFG"; chmod 640 "$CFG"
    cp_ok "wp-config.php -> 640 root:www-data"

    # ------------------------------------------------------------------ WP2 version leaks, updates, plugins, users --
    LEAKS=(); for f in readme.html license.txt wp-config-sample.php; do [ -f "$ROOT/$f" ] && LEAKS+=("$f"); done
    if [ ${#LEAKS[@]} -gt 0 ] && cp_auto "Remove ${LEAKS[*]} from $ROOT (version leak)?" y; then
        for f in "${LEAKS[@]}"; do cp_backup "$ROOT/$f"; rm -f "${ROOT:?}/$f"; done; cp_ok "Removed ${LEAKS[*]}"
    fi
    if [ ! -x /usr/local/bin/wp ] && ! cp_cfg_has WP_CLI; then
        if cp_auto "Download wp-cli (github.com/wp-cli, ~7 MB) to update core/plugins/themes?" n; then
            curl -sSL --max-time 60 -o /usr/local/bin/wp https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar && chmod 755 /usr/local/bin/wp
        elif [ "${CP_AUTO:-0}" != 1 ]; then cp_cfg_set WP_CLI no; fi
    fi
    if [ -x /usr/local/bin/wp ]; then
        cp_info "Core: $(wpcli core version)"
        cp_ask "Update WordPress core, plugins and themes now?" y && { wpcli core update; wpcli plugin update --all; wpcli theme update --all; }
        wpcli plugin list --fields=name,status,version,update
        wpcli user list --role=administrator --fields=ID,user_login,user_email
        cp_todo "WordPress at $ROOT: compare the administrators above with the README"
    else
        ADMINS_WP="$(grep "WordPress administrator" /root/baseline/wordpress/report.txt 2>/dev/null | sed 's/^!!//' | xargs)"
        cp_todo "WordPress at $ROOT: compare its administrator accounts with the README${ADMINS_WP:+ ($ADMINS_WP)} (Users page in wp-admin)"
    fi
    PLUGINS="$(for p in "$ROOT"/wp-content/plugins/*/; do [ -d "$p" ] && basename "$p"; done | xargs)"
    NEWP=""; for p in $PLUGINS; do [[ " $(cp_cfg_get WP_PLUGINS_OK) " == *" $ROOT/$p "* ]] || NEWP="$NEWP $p"; done
    if [ -n "$PLUGINS" ] && [ -z "$NEWP" ]; then
        cp_info "Plugins already reviewed and kept (--reask to review again): $PLUGINS"
    elif [ -n "$PLUGINS" ]; then
        echo "  Plugins installed (remove any the README does not need): $PLUGINS"
        RMP="$(cp_read "Plugin folders to DELETE from wp-content/plugins (space separated, Enter = none)" "")"
        for p in $RMP; do
            [[ "$p" == */* || "$p" == .* ]] && continue
            [ -d "$ROOT/wp-content/plugins/$p" ] && cp_backup "$ROOT/wp-content/plugins/$p" && rm -rf "${ROOT:?}/wp-content/plugins/$p" && cp_ok "Deleted plugin $p"
        done
        KEPTP="$(cp_cfg_get WP_PLUGINS_OK)"
        for p in "$ROOT"/wp-content/plugins/*/; do [ -d "$p" ] && KEPTP="$KEPTP $ROOT/$(basename "$p")"; done
        cp_cfg_set WP_PLUGINS_OK "$(echo $KEPTP | tr ' ' '\n' | sort -u | xargs)"
    fi

    # ------------------------------------------------------------------ WP3 no PHP in uploads --
    UP="$ROOT/wp-content/uploads"
    if [ -d /etc/apache2 ] && [ -d "$UP" ]; then
        CONF=/etc/apache2/conf-available/wp-uploads-nophp.conf
        if ! grep -qs "$UP" "$CONF"; then
            cp_backup "$CONF"
            cat >> "$CONF" <<WPEOF
# Added by services/wordpress.sh - never execute PHP from uploads
<Directory "$UP">
    <FilesMatch "\.(php|phtml|phar|php[0-9])$">
        Require all denied
    </FilesMatch>
</Directory>
WPEOF
            APACHE_CHANGED=1
        fi
        [ -e /etc/apache2/conf-enabled/wp-uploads-nophp.conf ] || { a2enconf wp-uploads-nophp >/dev/null 2>&1; APACHE_CHANGED=1; }
        cp_ok "Apache: PHP execution blocked in $UP (server config, not .htaccess)"
    fi
    if [ -d /etc/nginx ] && [ -d "$UP" ]; then
        cp_todo "nginx serves WordPress? add inside its server block:  location ~* ^/wp-content/uploads/.*\\.php\$ { deny all; }"
    fi
    find "$UP" -name '*.php' 2>/dev/null | while read -r f; do cp_todo "PHP file inside WordPress uploads (likely webshell): $f"; done
done

# Reload the web server only when its config changed
RESULT=OK
if [ "$APACHE_CHANGED" = 1 ] && [ -d /etc/apache2 ] && systemctl is-active --quiet apache2; then
    if apache2ctl configtest >/dev/null 2>&1 && cp_restart apache2; then
        :
    else
        cp_err "apache configtest/restart failed - removing wp-uploads-nophp.conf"
        a2disconf wp-uploads-nophp >/dev/null 2>&1; systemctl restart apache2
        cp_todo "wordpress.sh: the uploads no-PHP rule broke Apache and was disabled"; RESULT="ROLLBACK apache rule disabled"
    fi
fi
if command -v curl >/dev/null; then
    for CFG in "${CONFIGS[@]}"; do
        rel="${CFG#/var/www/html}"; rel="${rel%/wp-config.php}"
        [[ "$CFG" == /var/www/html/* ]] && cp_info "Site check http://127.0.0.1$rel/ -> HTTP $(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1$rel/")"
    done
fi
echo "  Changed:"
svc_changes "${CONFIGS[@]}" /etc/apache2/conf-available/wp-uploads-nophp.conf
svc_result $RESULT
cp_ok "WordPress hardening complete ($((SECONDS - SVC_T0))s)"
