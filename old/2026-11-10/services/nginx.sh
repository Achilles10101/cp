#!/bin/bash
# Nginx Security Hardening Script (new)
# Research-doc items: NGX1-NGX3, WEB10 (content scan), G1-G3 (baseline first: section B)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../cp-common.sh
source "$SCRIPT_DIR/../cp-common.sh" 2>/dev/null || { echo "ERROR: cp-common.sh not found (keep the repo layout intact)"; exit 1; }

cp_require_root
cp_screenshot_prompt
command -v nginx >/dev/null 2>&1 || { echo "ERROR: nginx is not installed"; exit 1; }
cp_baseline_gate nginx

NGX=/etc/nginx
MAIN="$NGX/nginx.conf"
cp_backup "$NGX"      # whole tree (sites-enabled includes EVERY file, so no .bak copies inside it)

rollback() { cp_err "$1 - restoring $NGX"; cp_restore "$NGX"; systemctl reload nginx 2>/dev/null || systemctl restart nginx; exit 1; }

# set_http_directive NAME VALUE : set "NAME VALUE;" inside the http {} block of nginx.conf (in place)
set_http_directive() {
    local name="$1" value="$2"
    if grep -qE "^[[:space:]]*${name}[[:space:]]" "$MAIN"; then
        sed -i -E "s|^([[:space:]]*)${name}[[:space:]].*;|\1$name $value;|" "$MAIN"
    elif grep -qE "^[[:space:]]*#[[:space:]]*${name}[[:space:]]" "$MAIN"; then
        sed -i -E "0,/^([[:space:]]*)#[[:space:]]*${name}[[:space:]].*/s||\1$name $value;|" "$MAIN"
    else
        sed -i -E "0,/^[[:space:]]*http[[:space:]]*\{/s||&\n\t$name $value;|" "$MAIN"
    fi
}

echo "========================================="
echo "Nginx Security Hardening"
echo "========================================="

# NGX1 - hide version
set_http_directive server_tokens off
cp_ok "server_tokens off"

# NGX3 - TLS / misc (http context)
set_http_directive ssl_protocols "TLSv1.2 TLSv1.3"
set_http_directive ssl_prefer_server_ciphers on
set_http_directive client_max_body_size 10m
grep -rlE '^[[:space:]]*ssl_protocols' "$NGX"/sites-enabled "$NGX"/conf.d 2>/dev/null | while read -r f; do
    sed -i -E 's/^([[:space:]]*)ssl_protocols[[:space:]].*;/\1ssl_protocols TLSv1.2 TLSv1.3;/' "$f"; cp_info "ssl_protocols fixed in $f"
done
grep -rlE '^[[:space:]]*autoindex[[:space:]]+on' "$NGX" 2>/dev/null | while read -r f; do
    sed -i -E 's/^([[:space:]]*)autoindex[[:space:]]+on[[:space:]]*;/\1autoindex off;/' "$f"; cp_ok "autoindex off in $f"
done
CUR_USER="$(sed -n -E 's/^[[:space:]]*user[[:space:]]+([^ ;]+).*/\1/p' "$MAIN" | head -1)"
if [ "$CUR_USER" != "www-data" ]; then
    cp_warn "nginx worker user is '${CUR_USER:-<unset>}'"
    if cp_ask "Set 'user www-data;'?" y; then
        if [ -n "$CUR_USER" ]; then sed -i -E 's/^([[:space:]]*)user[[:space:]]+[^;]+;/\1user www-data;/' "$MAIN"
        else sed -i '1i user www-data;' "$MAIN"; fi
        cp_ok "user www-data"
    fi
fi

# Hardening snippet included in every server block: dotfiles, methods, headers
mkdir -p "$NGX/snippets"
cat > "$NGX/snippets/cp-hardening.conf" <<'EOF'
# Added by services/nginx.sh
location ~ /\.(?!well-known) { deny all; }
if ($request_method !~ ^(GET|HEAD|POST)$) { return 405; }
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "no-referrer" always;
EOF
if cp_ask "Include the hardening snippet (deny dotfiles, only GET/HEAD/POST, security headers) in every server block?" y; then
    for f in "$NGX"/sites-enabled/* "$NGX"/conf.d/*.conf; do
        [ -f "$f" ] || continue
        grep -q 'snippets/cp-hardening.conf' "$f" && continue
        f="$(readlink -f "$f")"
        sed -i -E '/^[[:space:]]*server[[:space:]]*\{/a\    include snippets/cp-hardening.conf;' "$f"
        cp_ok "Snippet included in $f"
    done
fi

# NGX2 - off-by-slash alias traversal, and roots that point at system dirs
echo ""
echo "Checking location/alias pairs (off-by-slash LFI) and root/alias targets"
for f in "$MAIN" "$NGX"/sites-enabled/* "$NGX"/conf.d/*.conf; do
    [ -f "$f" ] || continue
    f="$(readlink -f "$f")"
    # "location /x {" (no trailing slash) whose block has "alias .../;" -> vulnerable
    awk '
        /^[[:space:]]*location[[:space:]]+\/[^ \t{]*[^\/ \t{][[:space:]]*\{/ { loc = FNR; path = $2; depth = 1; next }
        loc { n = gsub(/\{/, "{"); m = gsub(/\}/, "}"); depth += n - m
              if ($0 ~ /^[[:space:]]*alias[[:space:]]+[^;]*\/[[:space:]]*;/) print loc ":" path
              if (depth <= 0) loc = 0 }
    ' "$f" | while IFS=: read -r ln path; do
        cp_warn "$f:$ln  'location $path' + 'alias .../' -> path traversal via '$path../'"
        if cp_ask "Change it to 'location $path/'?" y; then
            sed -i "${ln}s|location[[:space:]]\+${path}[[:space:]]*{|location $path/ {|" "$f" && cp_ok "Fixed $f:$ln"
        fi
    done
    grep -nE '^[[:space:]]*(root|alias)[[:space:]]+' "$f" | while IFS= read -r l; do
        echo "      $f:$l"
        echo "$l" | grep -qE '(root|alias)[[:space:]]+(/|/etc[^ ;]*|/root[^ ;]*|/home[^ ;]*|/var/log[^ ;]*|/proc[^ ;]*)/?[[:space:]]*;' \
            && cp_warn "   ^ serves a system/home directory - compare with the README"
    done
done

# WEB10/B8 action
ROOTS="$(grep -rhoE '^[[:space:]]*root[[:space:]]+[^;]+' "$NGX"/sites-enabled "$NGX"/conf.d 2>/dev/null | awk '{print $2}' | sort -u)"
# shellcheck disable=SC2086
cp_web_scan /var/www $ROOTS

# G3
cp_ufw_allow "Nginx Full" 80/tcp 443/tcp

echo ""
echo "Testing nginx configuration"
nginx -t 2>&1 || rollback "nginx -t failed"
cp_restart nginx || rollback "nginx did not come back up"

if command -v curl >/dev/null 2>&1; then
    H="$(curl -sI --max-time 5 http://127.0.0.1/)"
    if [ -n "$H" ]; then
        cp_ok "HTTP answers: $(echo "$H" | head -1 | tr -d '\r')"
        echo "$H" | grep -qiE '^Server: nginx/[0-9]' && cp_warn "Server header still shows the version" || cp_ok "Server header hides the version"
    else
        cp_warn "No HTTP answer from 127.0.0.1 - check the site (critical service!)"
    fi
fi
echo "Nginx hardening complete."
