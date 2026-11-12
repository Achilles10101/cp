#!/bin/bash
# PHP Security Hardening Script
# Research-doc items: PHP1-PHP4, G1, G2 (baseline first: section B)
#
# Usage: sudo bash services/php.sh [--reask]
# Answers are asked once and kept in /root/cp-state/readme.conf, so a re-run asks nothing:
#   PHP_URL_FOPEN (On|Off)  PHP_DISABLE_FN (1|0)  PHP_BASEDIR (1|0)  PHP_UPLOADS (On|Off)  PHP_COOKIE_SECURE (1|0)
#   --reask   forget those answers and ask again

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../cp-common.sh
source "$SCRIPT_DIR/../cp-common.sh" 2>/dev/null || { echo "ERROR: cp-common.sh not found (keep the repo layout intact)"; exit 1; }

# ---- local helpers (same block in every services/*.sh; cp-common.sh is shared/owned elsewhere) ----
SVC=php; SVC_T0=$SECONDS
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
[ "${1:-}" = "--reask" ] && svc_forget PHP_URL_FOPEN PHP_DISABLE_FN PHP_BASEDIR PHP_UPLOADS PHP_COOKIE_SECURE
cp_hdr "PHP hardening"
cp_screenshot_prompt

mapfile -t INIS < <(ls /etc/php/*/*/php.ini 2>/dev/null)
[ ${#INIS[@]} -gt 0 ] || { echo "ERROR: no /etc/php/*/*/php.ini found - is PHP installed?"; svc_result FAIL "not installed"; exit 1; }

cp_baseline_gate php

PHPDIRS=(); for ini in "${INIS[@]}"; do PHPDIRS+=("$(dirname "$ini")"); done
cp_info "php.ini files: ${INIS[*]}"
SNAP0="$(svc_snap "${PHPDIRS[@]}")"

# ---------------------------------------------------------------- README / app answers (PHP2) --
# applied to web SAPIs only (apache2 / fpm / cgi), never to cli
if cp_cfg_has PHP_URL_FOPEN && cp_cfg_has PHP_DISABLE_FN && cp_cfg_has PHP_BASEDIR && cp_cfg_has PHP_UPLOADS && cp_cfg_has PHP_COOKIE_SECURE; then
    URL_FOPEN="$(cp_cfg_get PHP_URL_FOPEN)"; DISABLE_FN="$(cp_cfg_get PHP_DISABLE_FN)"; BASEDIR="$(cp_cfg_get PHP_BASEDIR)"
    UPLOADS="$(cp_cfg_get PHP_UPLOADS)"; COOKIE_SECURE="$(cp_cfg_get PHP_COOKIE_SECURE)"
    cp_info "Answers (stored; --reask to change): allow_url_fopen $URL_FOPEN, disable_functions $DISABLE_FN, open_basedir $BASEDIR, file_uploads $UPLOADS, cookie_secure $COOKIE_SECURE"
else
    URL_FOPEN=Off; DISABLE_FN=1; BASEDIR=0; UPLOADS=On; COOKIE_SECURE=0
    # HTTPS-only site (apache2.sh answer 'Apache Secure') -> secure session cookies
    [ "$(cp_cfg_get APACHE_UFW)" = secure ] && COOKIE_SECURE=1
    echo "  App-dependent PHP settings - Enter keeps all of them:"
    echo "      allow_url_fopen Off | exec/system/shell_exec... disabled | no open_basedir | file uploads On | session.cookie_secure $([ $COOKIE_SECURE = 1 ] && echo 1 || echo '0 (site also on HTTP)')"
    if cp_ask "Does the README or the web app need any of these changed (remote URL reads, exec(), open_basedir, no uploads, HTTPS cookies)?" n; then
        if cp_ask "Disable allow_url_fopen (remote file reads; most apps use curl instead)?" y; then URL_FOPEN=Off; else URL_FOPEN=On; fi
        if cp_ask "Disable dangerous functions (exec, system, shell_exec, passthru, proc_open, popen, pcntl_exec)?" y; then DISABLE_FN=1; else DISABLE_FN=0; fi
        if cp_ask "Restrict PHP to /var/www and /tmp with open_basedir (can break apps that read elsewhere)?" n; then BASEDIR=1; else BASEDIR=0; fi
        if cp_ask "Does the README require FILE UPLOADS through the web app?" y; then UPLOADS=On; else UPLOADS=Off; fi
        if cp_ask "Is the site served over HTTPS ONLY (sets session.cookie_secure)?" "$([ $COOKIE_SECURE = 1 ] && echo y || echo n)"; then COOKIE_SECURE=1; else COOKIE_SECURE=0; fi
    fi
    cp_cfg_set PHP_URL_FOPEN "$URL_FOPEN"; cp_cfg_set PHP_DISABLE_FN "$DISABLE_FN"; cp_cfg_set PHP_BASEDIR "$BASEDIR"
    cp_cfg_set PHP_UPLOADS "$UPLOADS"; cp_cfg_set PHP_COOKIE_SECURE "$COOKIE_SECURE"
fi

# PHP1 (all SAPIs) + PHP3
declare -A COMMON=(
    [expose_php]=Off
    [display_errors]=Off
    [display_startup_errors]=Off
    [log_errors]=On
    [allow_url_include]=Off
    [session.cookie_httponly]=1
    [session.use_strict_mode]=1
    [session.use_only_cookies]=1
    [session.cookie_samesite]=Strict
)
[ "$COOKIE_SECURE" = 1 ] && COMMON[session.cookie_secure]=1

for ini in "${INIS[@]}"; do
    sapi="$(basename "$(dirname "$ini")")"; ver="$(basename "$(dirname "$(dirname "$ini")")")"
    cp_backup "$ini" "$(dirname "$ini")/conf.d"
    declare -A SET=()
    for k in "${!COMMON[@]}"; do SET[$k]="${COMMON[$k]}"; done
    if [ "$sapi" != "cli" ]; then
        SET[allow_url_fopen]="$URL_FOPEN"
        SET[file_uploads]="$UPLOADS"
        [ "$DISABLE_FN" = 1 ] && SET[disable_functions]="exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec"
        [ "$BASEDIR" = 1 ] && SET[open_basedir]="/var/www/:/tmp/:/usr/share/php/"
        [ "$sapi" = "fpm" ] && SET[cgi.fix_pathinfo]=0
    fi
    for k in "${!SET[@]}"; do
        cp_set "$ini" "$k" "${SET[$k]}" eqs 0 0
        # G1 / B3: a conf.d/*.ini (possibly planted) loaded after php.ini would override us
        for f in "$(dirname "$ini")"/conf.d/*.ini; do
            [ -f "$f" ] || continue
            if [ -n "$(cp_get "$f" "$k" eqs 0 0)" ]; then
                cp_warn "$(readlink -f "$f") overrode $k - removed there"
                cp_unset "$(readlink -f "$f")" "$k" eqs 0 0 >/dev/null
            fi
        done
    done
    unset SET
    # Validate the file parses (php -c uses exactly this ini)
    PHPBIN="$(command -v "php$ver" || command -v php)"
    if [ -n "$PHPBIN" ] && "$PHPBIN" -c "$ini" -r 'exit(0);' 2>&1 | grep -qiE 'parse error|syntax error'; then
        cp_err "$ini no longer parses - restoring"; cp_restore "$ini"
        cp_todo "php.sh: $ini did not parse after hardening and was restored - check it by hand"
    fi
done

# ---------------------------------------------------------------- PHP4: restart what runs PHP --
restore_all() { for ini in "${INIS[@]}"; do cp_restore "$ini" "$(dirname "$ini")/conf.d"; done; }
RESULT=OK
if [ "$(svc_snap "${PHPDIRS[@]}")" = "$SNAP0" ]; then
    cp_ok "php.ini files unchanged - no restart needed"
else
    if compgen -G "/etc/apache2/mods-enabled/php*.load" >/dev/null; then
        if apache2ctl configtest >/dev/null 2>&1 && ! cp_restart apache2; then
            cp_err "apache2 (mod_php) did not come back - restoring php.ini files"; restore_all; cp_restart apache2
            cp_todo "php.sh: apache2 failed after the PHP change - rolled back"; RESULT="ROLLBACK apache2 failed"
        fi
    fi
    for u in $(systemctl list-unit-files 'php*-fpm.service' --no-legend 2>/dev/null | awk '{print $1}'); do
        u="${u%.service}"
        systemctl is-enabled --quiet "$u" 2>/dev/null || systemctl is-active --quiet "$u" || continue
        if command -v "$u" >/dev/null 2>&1 && ! "$u" -t >/dev/null 2>&1; then
            cp_err "$u -t failed - restoring php.ini files"; restore_all
            cp_todo "php.sh: $u -t failed after the PHP change - rolled back"; RESULT="ROLLBACK $u -t failed"; continue
        fi
        if ! cp_restart "$u"; then
            restore_all; cp_restart "$u"
            cp_todo "php.sh: $u failed after the PHP change - rolled back"; RESULT="ROLLBACK $u failed"
        fi
    done
fi

# G2: functional check - X-Powered-By must be gone
if command -v curl >/dev/null 2>&1; then
    H="$(curl -sI --max-time 5 http://127.0.0.1/ 2>/dev/null)"
    if [ -n "$H" ]; then
        if echo "$H" | grep -qi '^X-Powered-By: PHP'; then cp_warn "X-Powered-By still exposes PHP"; else cp_ok "No X-Powered-By header"; fi
    fi
fi
for ini in "${INIS[@]}"; do
    echo "  $ini: expose_php=$(cp_get "$ini" expose_php) display_errors=$(cp_get "$ini" display_errors) allow_url_include=$(cp_get "$ini" allow_url_include) allow_url_fopen=$(cp_get "$ini" allow_url_fopen)"
done
echo "  Changed:"
svc_changes "${PHPDIRS[@]}"
svc_result $RESULT
cp_ok "PHP hardening complete ($((SECONDS - SVC_T0))s)"
