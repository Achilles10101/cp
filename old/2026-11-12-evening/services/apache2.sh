#!/bin/bash
# Apache Security Hardening Script
# Research-doc items: WEB1-WEB10, G1-G5 (baseline first: section B)
#
# Usage: sudo bash services/apache2.sh [--reask]
# Answers are asked once and kept in /root/cp-state/readme.conf, so a re-run asks nothing:
#   APACHE_HTACCESS (yes|no)  APACHE_CSP (yes|no)  APACHE_UFW (full|secure)  APACHE_MODS (yes|no)
#   APACHE_WWW_PERMS (yes|no)  APACHE_WAF (yes|no)
#   --reask   forget those answers and ask again

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../cp-common.sh
source "$SCRIPT_DIR/../cp-common.sh" 2>/dev/null || { echo "ERROR: cp-common.sh not found (keep the repo layout intact)"; exit 1; }

# ---- local helpers (same block in every services/*.sh; cp-common.sh is shared/owned elsewhere) ----
SVC=apache2; SVC_T0=$SECONDS
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
[ "${1:-}" = "--reask" ] && svc_forget APACHE_HTACCESS APACHE_CSP APACHE_UFW APACHE_MODS APACHE_WWW_PERMS APACHE_WAF
cp_hdr "Apache hardening"
cp_screenshot_prompt

# Check if Apache is installed
if ! command -v apache2ctl &> /dev/null; then
    echo "ERROR: Apache2ctl is not installed on this system"
    svc_result FAIL "not installed"; exit 1
fi

cp_baseline_gate apache2

SECURITY_CONF="/etc/apache2/conf-available/security.conf"
APACHE_CONF="/etc/apache2/apache2.conf"
cp_backup /etc/apache2 /etc/ssl/private          # whole tree, so a failed configtest can be rolled back completely
cp "$SECURITY_CONF" "${SECURITY_CONF}.backup" 2>/dev/null
cp "$APACHE_CONF" "${APACHE_CONF}.backup"
SNAP0="$(svc_snap /etc/apache2)"

rollback() {
    cp_err "$1 - rolling back /etc/apache2"
    cp_restore /etc/apache2
    # restart only if Apache is down: if the OLD config is broken too, a restart would take a running site down
    systemctl is-active --quiet apache2 || systemctl restart apache2 2>/dev/null
    cp_todo "apache2.sh: $1 - hardening rolled back; fix by hand (apachectl configtest) and re-run"
    svc_result ROLLBACK "$1"
    exit 1
}
# cfg_yn KEY "Question" default -> stored yes/no answer, asked (and stored) once
cfg_yn() {
    if cp_cfg_has "$1"; then [ "$(cp_cfg_get "$1")" = yes ]; return; fi
    if cp_ask "$2" "$3"; then cp_cfg_set "$1" yes; return 0; fi
    cp_cfg_set "$1" no; return 1
}

# ---------------------------------------------------------------- TLS (always right, WEB4) --
ENABLE_TLS=0
if [ -e /etc/apache2/mods-enabled/ssl.load ]; then
    ENABLE_TLS=1
elif ss -Htlnp 2>/dev/null | awk '{print $4, $6}' | grep -E '[:.]443 ' | grep -qv apache2; then
    cp_warn "Port 443 is used by another program - not enabling Apache HTTPS"
    cp_todo "apache2.sh: HTTPS not enabled because port 443 is taken: $(ss -Htlnp 2>/dev/null | grep -E '[:.]443 ' | head -1)"
elif cp_ask "Enable HTTPS (mod_ssl + default-ssl site, TLS 1.2/1.3 only)?" y; then
    ENABLE_TLS=1
fi

# ---------------------------------------------------------------- README / site answers --
WP=0; [ -n "$(find /var/www -maxdepth 5 -name wp-config.php -print -quit 2>/dev/null)" ] && WP=1
APP=0; [ -n "$(find /var/www -maxdepth 6 -name '*.php' -print -quit 2>/dev/null)" ] && APP=1
HT=0; grep -rlqs --include=.htaccess -i 'RewriteEngine' /var/www 2>/dev/null && HT=1
if cp_cfg_has APACHE_HTACCESS && cp_cfg_has APACHE_CSP && cp_cfg_has APACHE_UFW; then
    APP_HTACCESS=0; [ "$(cp_cfg_get APACHE_HTACCESS)" = yes ] && APP_HTACCESS=1
    ADD_CSP=0; [ "$(cp_cfg_get APACHE_CSP)" = yes ] && ADD_CSP=1
    UFW_MODE="$(cp_cfg_get APACHE_UFW)"
    cp_info "Answers (stored; --reask to change): .htaccess apps $(cp_cfg_get APACHE_HTACCESS), strict CSP $(cp_cfg_get APACHE_CSP), firewall $UFW_MODE"
else
    APP_HTACCESS=0; { [ $WP = 1 ] || [ $HT = 1 ]; } && APP_HTACCESS=1
    ADD_CSP=1; [ $APP = 1 ] && ADD_CSP=0       # a strict CSP breaks WordPress/PHP apps (inline scripts)
    UFW_MODE=full
    echo "  Site-dependent Apache settings (detected: WordPress=$WP, PHP files=$APP, .htaccess rewrites=$HT) - Enter keeps all:"
    echo "      .htaccess rewrites allowed: $([ $APP_HTACCESS = 1 ] && echo yes || echo no) | strict Content-Security-Policy: $([ $ADD_CSP = 1 ] && echo yes || echo no) | firewall: 'Apache Full' (80+443)"
    if cp_ask "Does the README or the site need any of these changed (.htaccess apps, CDN assets, HTTPS-only)?" n; then
        if cp_ask "Does a web app on this server use .htaccess rewrites (WordPress permalinks, Joomla, etc.)?" "$([ $APP_HTACCESS = 1 ] && echo y || echo n)"; then APP_HTACCESS=1; else APP_HTACCESS=0; fi
        if cp_ask "Add a strict Content-Security-Policy header (can break sites that load CDN assets)?" "$([ $ADD_CSP = 1 ] && echo y || echo n)"; then ADD_CSP=1; else ADD_CSP=0; fi
        # G3: a scored image checked for the exact profile "Apache Secure" (HTTPS only)
        if [ "$ENABLE_TLS" = 1 ] && cp_ask "HTTPS ONLY (UFW profile 'Apache Secure', port 80 closed)? No = 'Apache Full' (80+443)" n; then UFW_MODE=secure; fi
    fi
    cp_cfg_set APACHE_HTACCESS "$([ $APP_HTACCESS = 1 ] && echo yes || echo no)"
    cp_cfg_set APACHE_CSP "$([ $ADD_CSP = 1 ] && echo yes || echo no)"
    cp_cfg_set APACHE_UFW "$UFW_MODE"
fi

# ---------------------------------------------------------------- modules (opt-in, WEB6) --
STANDARD_MODULES=("status" "info" "autoindex" "negotiation" "cgi" "cgid" "userdir" "dav" "dav_fs")
ENABLED_STD=()
for mod in "${STANDARD_MODULES[@]}"; do [ -e "/etc/apache2/mods-enabled/$mod.load" ] && ENABLED_STD+=("$mod"); done
if [ ${#ENABLED_STD[@]} -gt 0 ]; then
    if cp_cfg_has APACHE_MODS; then
        MODS_ANS="$(cp_cfg_get APACHE_MODS)"
    else
        MODS_ANS="$(cp_read "Disable unneeded Apache modules (${ENABLED_STD[*]})? y = all, e = choose each, n = keep" "n")"
        case "$MODS_ANS" in [Yy]*) MODS_ANS=yes ;; [Ee]*) MODS_ANS=each ;; *) MODS_ANS=no ;; esac
        [ "$MODS_ANS" = each ] || cp_cfg_set APACHE_MODS "$MODS_ANS"
    fi
    MODULES_TO_DISABLE=()
    case "$MODS_ANS" in
        yes)  MODULES_TO_DISABLE=("${ENABLED_STD[@]}") ;;
        each) for mod in "${ENABLED_STD[@]}"; do cp_ask "Disable module $mod?" y && MODULES_TO_DISABLE+=("$mod"); done
              extra="$(cp_read "Other modules to disable (comma separated, Enter = none)" "")"
              IFS=',' read -ra EXTRA_MODS <<< "$extra"
              for mod in "${EXTRA_MODS[@]+"${EXTRA_MODS[@]}"}"; do mod="$(echo "$mod" | xargs)"; [ -n "$mod" ] && MODULES_TO_DISABLE+=("$mod"); done ;;
    esac
    for module in "${MODULES_TO_DISABLE[@]+"${MODULES_TO_DISABLE[@]}"}"; do
        if a2query -m "$module" &>/dev/null; then
            if a2dismod -f "$module" &>/dev/null; then cp_ok "Disabled module $module"; else cp_warn "Failed to disable module $module"; fi
        fi
    done
fi

# ------------------------------------------------------------------ security.conf (G1) --
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
        [ -n "$v" ] && { cp_warn "$f also set $k $v - removed"; cp_unset "$f" "$k" space 1 >/dev/null; }
    done
done

# ------------------------------------------------------------------ apache2.conf --
cp_set "$APACHE_CONF" Timeout 60 space 1                      # WEB6 (default 300)
cp_set "$APACHE_CONF" LogLevel info space 1

# Our two blocks (security headers, directory restrictions) are removed and re-appended on every run.
sed -i '/^# BEGIN cp-hardening headers/,/^# END cp-hardening headers/d' "$APACHE_CONF"
sed -i '/Header set X-Content-Type-Options/d; /Header set X-Frame-Options/d; /Header set X-XSS-Protection/d; /Header set Referrer-Policy/d; /Header always set Permissions-Policy/d; /Header \(always \)\?set Content-Security-Policy/d; /^#Security headers$/d' "$APACHE_CONF"
sed -i '/<Directory \/>/,/<\/Directory>/d' "$APACHE_CONF"
sed -i '/<Directory \/var\/www\/html>/,/<\/Directory>/d' "$APACHE_CONF"
sed -i '/^# Directory access restrictions$/d' "$APACHE_CONF"
# WEB3: the stock <Directory /var/www/> block keeps "Options Indexes FollowSymLinks" for every
# vhost under /var/www - fix it in place (all options must be +/- signed or none).
sed -i '/<Directory \/var\/www\/>/,/<\/Directory>/{s/^\([[:space:]]*\)Options .*/\1Options -Indexes +SymLinksIfOwnerMatch -ExecCGI -Includes/}' "$APACHE_CONF"
# squeeze the blank lines left behind and drop trailing ones, so re-runs do not grow the file
T="$(mktemp)"
cat -s "$APACHE_CONF" | awk '{ a[NR] = $0 } END { n = NR; while (n > 0 && a[n] ~ /^[ \t]*$/) n--; for (i = 1; i <= n; i++) print a[i] }' > "$T" && cat "$T" > "$APACHE_CONF"
rm -f "$T"
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

# ------------------------------------------------------------------ directory restrictions --
if [ "$APP_HTACCESS" = 1 ]; then
    HTML_OPTS="Options -Indexes -ExecCGI -Includes +SymLinksIfOwnerMatch"; HTML_OVERRIDE="AllowOverride All"
else
    HTML_OPTS="Options -Indexes -ExecCGI -Includes -FollowSymLinks"; HTML_OVERRIDE="AllowOverride None"
fi
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
    | while read -r f; do cp_todo "Directory listing (Options Indexes) still enabled in $f - change to -Indexes unless the README needs it"; done

# ------------------------------------------------------------------ .htaccess (WEB1) --
# NOT deleted - they can be required (WordPress) or protective. Only suspicious ones are flagged.
mapfile -t HTF < <(find /var/www -name ".htaccess" 2>/dev/null)
if [ ${#HTF[@]} -gt 0 ]; then
    cp_info ".htaccess files ($([ "$APP_HTACCESS" = 1 ] && echo active || echo 'ignored, AllowOverride None' ) under /var/www/html): ${HTF[*]}"
    for f in "${HTF[@]}"; do
        grep -qiE 'auto_(prepend|append)_file|AddHandler|AddType|SetHandler|php_(flag|value)[[:space:]]+engine|Options[^#]*\+?Indexes|RewriteRule.*(https?:|base64)' "$f" \
            && cp_todo "Suspicious .htaccess $f: $(grep -iE 'auto_|AddHandler|AddType|SetHandler|engine|Indexes|RewriteRule' "$f" | head -2 | tr '\n' ';')"
    done
fi

# ------------------------------------------------------------------ run user (WEB5) --
RUNU="$(sed -n 's/^export APACHE_RUN_USER=//p' /etc/apache2/envvars | tr -d '"')"
RUNG="$(sed -n 's/^export APACHE_RUN_GROUP=//p' /etc/apache2/envvars | tr -d '"')"
if [ "$RUNU" != "www-data" ] || [ "$RUNG" != "www-data" ]; then
    cp_warn "Apache runs as $RUNU:$RUNG (default www-data:www-data)"
    if cp_ask "Set APACHE_RUN_USER/GROUP back to www-data?" y; then
        sed -i 's/^export APACHE_RUN_USER=.*/export APACHE_RUN_USER=www-data/; s/^export APACHE_RUN_GROUP=.*/export APACHE_RUN_GROUP=www-data/' /etc/apache2/envvars
        cp_ok "Run user reset to www-data"
    fi
fi
grep -rnE '^[[:space:]]*(User|Group)[[:space:]]+[^$]' /etc/apache2/*.conf /etc/apache2/conf-enabled /etc/apache2/sites-enabled 2>/dev/null \
    | while read -r l; do cp_todo "Hard-coded Apache User/Group directive: $l"; done
grep -rnE '^[[:space:]]*(DocumentRoot|Alias)[[:space:]]+"?(/|/etc|/root|/home[^ ]*|/var/log)"?([[:space:]]|$)' /etc/apache2/sites-enabled /etc/apache2/conf-enabled 2>/dev/null \
    | while read -r l; do cp_todo "Suspicious DocumentRoot/Alias (WEB10), compare with the README: $l"; done

# ------------------------------------------------------------------ TLS (WEB4) --
if [ "$ENABLE_TLS" = 1 ]; then
    [ -f /etc/ssl/certs/ssl-cert-snakeoil.pem ] || make-ssl-cert generate-default-snakeoil --force-overwrite 2>/dev/null
    a2enmod ssl &>/dev/null
    SSL_MOD_CONF=/etc/apache2/mods-available/ssl.conf
    cp_set "$SSL_MOD_CONF" SSLProtocol "-all +TLSv1.2 +TLSv1.3" space 1
    cp_set "$SSL_MOD_CONF" SSLHonorCipherOrder on space 1
    cp_set "$SSL_MOD_CONF" SSLCompression off space 1
    if ! grep -lqs 'SSLEngine[[:space:]]\+on' /etc/apache2/sites-enabled/*.conf; then
        a2ensite default-ssl &>/dev/null && cp_ok "Enabled site default-ssl"
    fi
    for f in /etc/apache2/sites-available/*.conf; do
        grep -q '<VirtualHost[^>]*:443' "$f" 2>/dev/null || continue
        grep -q 'Strict-Transport-Security' "$f" || sed -i '0,/<VirtualHost[^>]*:443[^>]*>/s//&\n\t\tHeader always set Strict-Transport-Security "max-age=31536000"/' "$f"
    done
fi

# ------------------------------------------------------------------ optional WAF (WEB9) --
if [ -e /etc/apache2/mods-enabled/security2.load ]; then
    :
elif cp_cfg_has APACHE_WAF; then
    :
elif cp_ask "Install optional mod_security2 (+CRS) and mod_evasive? (no scoring evidence; needs network)" n; then
    cp_cfg_set APACHE_WAF yes
    if cp_apt install -y libapache2-mod-security2 modsecurity-crs libapache2-mod-evasive >/dev/null 2>&1; then
        [ -f /etc/modsecurity/modsecurity.conf ] || cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
        sed -i 's/^SecRuleEngine .*/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf
        a2enmod security2 evasive &>/dev/null
        cp_ok "mod_security2 (SecRuleEngine On) + mod_evasive enabled"
    else
        cp_warn "Install failed - skipped"
    fi
else
    cp_cfg_set APACHE_WAF no
fi

# Enable headers module / security configuration
a2enmod headers &>/dev/null || cp_warn "Failed to enable headers module"
a2enconf security &>/dev/null || cp_warn "Failed to enable security.conf"

# ------------------------------------------------------------------ permissions (WEB2, WEB8, G5) --
KEEP_WRITABLE=()
while IFS= read -r d; do KEEP_WRITABLE+=("$d"); done < <(find /var/www -type d -user www-data \( -name uploads -o -name cache -o -name tmp -o -name sessions -o -name files \) 2>/dev/null)
# folders the app writes to stay www-data (apps break otherwise) - listed, never asked
[ ${#KEEP_WRITABLE[@]} -gt 0 ] && cp_info "Folders the web app writes to (stay owned by www-data): ${KEEP_WRITABLE[*]}"
if cfg_yn APACHE_WWW_PERMS "Reset /var/www to root ownership, dirs 755 / files 644 (app folders above stay writable)?" y; then
    mapfile -t WPCFG < <(find /var/www -name wp-config.php 2>/dev/null)
    chown -R root:root /var/www || cp_warn "Failed to change ownership"
    find /var/www -type d -exec chmod 755 {} + || cp_warn "Failed to set directory permissions"
    find /var/www -type f -exec chmod 644 {} + || cp_warn "Failed to set file permissions"
    for d in "${KEEP_WRITABLE[@]+"${KEEP_WRITABLE[@]}"}"; do chown -R www-data:www-data "$d"; chmod 755 "$d"; done
    # wp-config.php holds the DB password: never world-readable (WP1, same as wordpress.sh)
    for f in "${WPCFG[@]+"${WPCFG[@]}"}"; do chown root:www-data "$f"; chmod 640 "$f"; done
    cp_ok "/var/www root-owned, 755/644$([ ${#KEEP_WRITABLE[@]} -gt 0 ] && echo ", app folders stay www-data")$([ ${#WPCFG[@]} -gt 0 ] && echo ", wp-config.php 640 root:www-data")"
fi
find /etc/apache2 -type d -exec chmod 755 {} + ; find /etc/apache2 -type f -exec chmod 644 {} + ; chown -R root:root /etc/apache2
[ -d /var/log/apache2 ] && { chown root:adm /var/log/apache2; chmod 750 /var/log/apache2; }
[ -d /etc/ssl/private ] && { chown root:ssl-cert /etc/ssl/private 2>/dev/null; chmod 710 /etc/ssl/private; find /etc/ssl/private -type f -exec chmod 640 {} + ; }
cp_ok "Perms: /etc/apache2 root 755/644, /var/log/apache2 750 root:adm, /etc/ssl/private keys 640"

# ------------------------------------------------------------------ web content (WEB10) --
cp_web_scan /var/www

# ------------------------------------------------------------------ firewall (G3) --
if [ "$ENABLE_TLS" = 1 ]; then
    if [ "$UFW_MODE" = secure ]; then cp_ufw_allow "Apache Secure" 443/tcp; else cp_ufw_allow "Apache Full" 80/tcp 443/tcp; fi
else
    cp_ufw_allow "Apache" 80/tcp
fi

# ------------------------------------------------------------------ validate + restart once (G2) --
if OUT="$(apachectl configtest 2>&1)"; then
    cp_ok "apachectl configtest: Syntax OK"
else
    echo "$OUT" | grep -v AH00558 | sed 's/^/      /'
    rollback "Apache configuration test failed"
fi
if [ "$(svc_snap /etc/apache2)" = "$SNAP0" ] && systemctl is-active --quiet apache2; then
    cp_ok "Apache config unchanged - no restart needed"
else
    cp_restart apache2 || rollback "Apache2 did not come back up"
fi

RESULT=OK
if command -v curl >/dev/null 2>&1; then
    H="$(curl -sI --max-time 5 http://127.0.0.1/ 2>/dev/null)"
    if [ -n "$H" ]; then
        S="$(echo "$H" | grep -i '^Server:' | tr -d '\r')"
        cp_ok "HTTP answers: $(echo "$H" | head -1 | tr -d '\r') | ${S:-no Server header}$([ "$(curl -s -o /dev/null -w '%{http_code}' -X TRACE --max-time 5 http://127.0.0.1/)" = 405 ] && echo ' | TRACE 405')"
        echo "$S" | grep -qiE 'apache/[0-9]' && cp_warn "Server header still shows a version"
    else
        cp_warn "No HTTP answer from 127.0.0.1 - check the site (critical service!)"
        cp_todo "apache2.sh: no HTTP answer from 127.0.0.1 after hardening - check the site"
        RESULT="FAIL no HTTP answer"
    fi
    [ "$ENABLE_TLS" = 1 ] && curl -skI --max-time 5 https://127.0.0.1/ >/dev/null && cp_ok "HTTPS answers"
fi

echo "  Changed:"
svc_changes /etc/apache2
svc_result $RESULT
cp_ok "Apache hardening complete ($((SECONDS - SVC_T0))s). Backups: $CP_BACKUP_ROOT/$CP_TS/etc/apache2"
