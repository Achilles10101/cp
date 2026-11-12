#!/bin/bash
# Nginx Security Hardening Script
# Research-doc items: NGX1-NGX3, WEB10 (content scan), G1-G3 (baseline first: section B)
# No README questions: every question here defaults to the answer that is right on a CyberPatriot image.
#
# Usage: sudo bash services/nginx.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../cp-common.sh
source "$SCRIPT_DIR/../cp-common.sh" 2>/dev/null || { echo "ERROR: cp-common.sh not found (keep the repo layout intact)"; exit 1; }

# ---- local helpers (same block in every services/*.sh; cp-common.sh is shared/owned elsewhere) ----
SVC=nginx; SVC_T0=$SECONDS
svc_result() { mkdir -p "$CP_STATE_DIR/svc" 2>/dev/null && echo "$*" > "$CP_STATE_DIR/svc/$SVC.result"; }
svc_snap()   { find "$@" -xdev \( -type f -o -type l \) -print0 2>/dev/null | LC_ALL=C sort -z | xargs -0 -r md5sum 2>/dev/null | md5sum | cut -c1-32; }
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
cp_hdr "Nginx hardening"
cp_screenshot_prompt
command -v nginx >/dev/null 2>&1 || { echo "ERROR: nginx is not installed"; svc_result FAIL "not installed"; exit 1; }
cp_baseline_gate nginx

NGX=/etc/nginx
MAIN="$NGX/nginx.conf"
cp_backup "$NGX"      # whole tree (sites-enabled includes EVERY file, so no .bak copies inside it)
SNAP0="$(svc_snap "$NGX")"
# Validate BEFORE changing anything: when the existing config already fails "nginx -t", no change of ours
# could be validated - report it as already broken (not our snippet) and change nothing.
if ! PRE="$(nginx -t 2>&1)"; then
    E1="$(echo "$PRE" | grep -m1 -E 'emerg|error' | cut -c1-160)"
    cp_err "nginx config was ALREADY broken before any change: $E1"
    cp_todo "nginx.sh: the existing nginx config already fails 'nginx -t' ($E1) - fix that first, then re-run; nothing was changed"
    svc_result FAIL "config was already broken (nginx -t)"; exit 1
fi

rollback() {
    cp_err "$1 - restoring $NGX"; cp_restore "$NGX"
    # only (re)start when nginx is down: if the OLD config is broken too, a restart would take a running site down
    systemctl is-active --quiet nginx || systemctl restart nginx 2>/dev/null
    cp_todo "nginx.sh: $1 - hardening rolled back; check nginx -t by hand"
    svc_result ROLLBACK "$1"; exit 1
}

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

# NGX1 - hide version; NGX3 - TLS / misc (http context)
set_http_directive server_tokens off
set_http_directive ssl_protocols "TLSv1.2 TLSv1.3"
set_http_directive ssl_prefer_server_ciphers on
set_http_directive client_max_body_size 10m
grep -rlE '^[[:space:]]*ssl_protocols' "$NGX"/sites-enabled "$NGX"/conf.d 2>/dev/null | while read -r f; do
    sed -i -E 's/^([[:space:]]*)ssl_protocols[[:space:]].*;/\1ssl_protocols TLSv1.2 TLSv1.3;/' "$f"
done
grep -rlE '^[[:space:]]*autoindex[[:space:]]+on' "$NGX" 2>/dev/null | while read -r f; do
    sed -i -E 's/^([[:space:]]*)autoindex[[:space:]]+on[[:space:]]*;/\1autoindex off;/' "$f"; cp_ok "autoindex off in $f"
done
cp_ok "server_tokens off, ssl_protocols TLSv1.2 TLSv1.3, ssl_prefer_server_ciphers on, client_max_body_size 10m"
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
cat > "$NGX/snippets/cp-hardening.conf" <<'NGXEOF'
# Added by services/nginx.sh
location ~ /\.(?!well-known) { deny all; }
if ($request_method !~ ^(GET|HEAD|POST)$) { return 405; }
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "no-referrer" always;
NGXEOF
SNIPPET_FILES=(); NEED=()
for f in "$NGX"/sites-enabled/* "$NGX"/conf.d/*.conf; do
    [ -f "$f" ] || continue
    f="$(readlink -f "$f")"
    grep -q 'snippets/cp-hardening.conf' "$f" || NEED+=("$f")
done
if [ ${#NEED[@]} -gt 0 ] && cp_ask "Include the hardening snippet (deny dotfiles, only GET/HEAD/POST, security headers) in every server block?" y; then
    for f in "${NEED[@]}"; do
        sed -i -E '/^[[:space:]]*server[[:space:]]*\{/a\    include snippets/cp-hardening.conf;' "$f"
        SNIPPET_FILES+=("$f")
    done
    cp_ok "Snippet included in: ${SNIPPET_FILES[*]}"
fi

# NGX2 - off-by-slash alias traversal, and roots that point at system dirs
for f in "$MAIN" "$NGX"/sites-enabled/* "$NGX"/conf.d/*.conf; do
    [ -f "$f" ] || continue
    f="$(readlink -f "$f")"
    # "location /x {" (no trailing slash) whose block has "alias .../;" -> vulnerable
    while IFS=: read -r ln path <&3; do
        [ -n "$ln" ] || continue
        cp_warn "$f:$ln  'location $path' + 'alias .../' -> path traversal via '$path../'"
        if cp_ask "Change it to 'location $path/'?" y; then
            sed -i "${ln}s|location[[:space:]]\+${path}[[:space:]]*{|location $path/ {|" "$f" && cp_ok "Fixed $f:$ln"
        fi
    done 3< <(awk '
        /^[[:space:]]*location[[:space:]]+\/[^ \t{]*[^\/ \t{][[:space:]]*\{/ { loc = FNR; path = $2; depth = 1; next }
        loc { n = gsub(/\{/, "{"); m = gsub(/\}/, "}"); depth += n - m
              if ($0 ~ /^[[:space:]]*alias[[:space:]]+[^;]*\/[[:space:]]*;/) print loc ":" path
              if (depth <= 0) loc = 0 }
    ' "$f")   # fd 3: the prompt inside the loop must still read the keyboard
    grep -nE '^[[:space:]]*(root|alias)[[:space:]]+(/|/etc[^ ;]*|/root[^ ;]*|/home[^ ;]*|/var/log[^ ;]*|/proc[^ ;]*)/?[[:space:]]*;' "$f" \
        | while IFS= read -r l; do cp_todo "nginx serves a system/home directory - compare with the README: $f:$(echo "$l" | xargs)"; done
done

# WEB10/B8 action
ROOTS="$(grep -rhoE '^[[:space:]]*root[[:space:]]+[^;]+' "$NGX"/sites-enabled "$NGX"/conf.d 2>/dev/null | awk '{print $2}' | sort -u)"
# shellcheck disable=SC2086
cp_web_scan /var/www $ROOTS

# G3
cp_ufw_allow "Nginx Full" 80/tcp 443/tcp

# ------------------------------------------------------------------ validate + restart once (G2) --
if ! OUT="$(nginx -t 2>&1)"; then
    # it passed before our changes, so one of them broke it: try without the snippet first
    if [ ${#SNIPPET_FILES[@]} -gt 0 ]; then
        cp_warn "nginx -t failed - retrying without the hardening snippet: $(echo "$OUT" | grep -m1 emerg)"
        for f in "${SNIPPET_FILES[@]}"; do sed -i '/include snippets\/cp-hardening.conf;/d' "$f"; done
        cp_todo "nginx.sh: the hardening snippet broke nginx -t ($(echo "$OUT" | grep -m1 emerg | cut -c1-80)) and was left out"
    fi
    OUT="$(nginx -t 2>&1)" || { echo "$OUT" | sed 's/^/      /'; rollback "nginx -t failed"; }
fi
cp_ok "nginx -t: config valid"
if [ "$(svc_snap "$NGX")" = "$SNAP0" ] && systemctl is-active --quiet nginx; then
    cp_ok "nginx config unchanged - no restart needed"
else
    cp_restart nginx || rollback "nginx did not come back up"
fi

RESULT=OK
PORT="$(grep -rhoE '^[[:space:]]*listen[[:space:]]+[0-9.:]*[0-9]+' "$NGX"/sites-enabled "$NGX"/conf.d 2>/dev/null | grep -oE '[0-9]+$' | head -1)"
if command -v curl >/dev/null 2>&1; then
    H="$(curl -sI --max-time 5 "http://127.0.0.1:${PORT:-80}/")"
    if [ -n "$H" ]; then
        cp_ok "HTTP answers on :${PORT:-80}: $(echo "$H" | head -1 | tr -d '\r')"
        echo "$H" | grep -qiE '^Server: nginx/[0-9]' && cp_warn "Server header still shows the version"
    else
        cp_warn "No HTTP answer from 127.0.0.1:${PORT:-80} - check the site (critical service!)"
        cp_todo "nginx.sh: no HTTP answer on port ${PORT:-80} after hardening - check the site"; RESULT="FAIL no HTTP answer"
    fi
fi
echo "  Changed:"
svc_changes "$NGX"
svc_result $RESULT
cp_ok "Nginx hardening complete ($((SECONDS - SVC_T0))s)"
