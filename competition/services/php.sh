#!/bin/bash
# PHP Security Hardening Script (new)
# Research-doc items: PHP1-PHP4, G1, G2 (baseline first: section B)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../cp-common.sh
source "$SCRIPT_DIR/../cp-common.sh" 2>/dev/null || { echo "ERROR: cp-common.sh not found (keep the repo layout intact)"; exit 1; }

cp_require_root
cp_screenshot_prompt

mapfile -t INIS < <(ls /etc/php/*/*/php.ini 2>/dev/null)
[ ${#INIS[@]} -gt 0 ] || { echo "ERROR: no /etc/php/*/*/php.ini found - is PHP installed?"; exit 1; }

cp_baseline_gate php

echo "========================================="
echo "PHP Security Hardening"
echo "========================================="
printf '  %s\n' "${INIS[@]}"
echo ""

# README-driven (PHP2) - applied to web SAPIs only (apache2 / fpm / cgi), never to cli
if cp_ask "Disable allow_url_fopen (remote file reads; most apps use curl instead)?" y; then URL_FOPEN=Off; else URL_FOPEN=On; fi
if cp_ask "Disable dangerous functions (exec, system, shell_exec, passthru, proc_open, popen, pcntl_exec)?" y; then DISABLE_FN=1; else DISABLE_FN=0; fi
if cp_ask "Restrict PHP to /var/www and /tmp with open_basedir (can break apps that read elsewhere)?" n; then BASEDIR=1; else BASEDIR=0; fi
if cp_ask "Does the README require FILE UPLOADS through the web app?" y; then UPLOADS=On; else UPLOADS=Off; fi
if cp_ask "Is the site served over HTTPS (sets session.cookie_secure)?" n; then COOKIE_SECURE=1; else COOKIE_SECURE=0; fi

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
    echo "Hardening $ini"
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
                cp_warn "$(readlink -f "$f") overrides $k - removing it there"
                cp_unset "$(readlink -f "$f")" "$k" eqs 0 0
            fi
        done
    done
    unset SET
    # Validate the file parses (php -c uses exactly this ini)
    if command -v "php$ver" >/dev/null 2>&1 || command -v php >/dev/null 2>&1; then
        PHPBIN="$(command -v "php$ver" || command -v php)"
        if "$PHPBIN" -c "$ini" -r 'exit(0);' 2>&1 | grep -qiE 'parse error|syntax error'; then
            cp_err "$ini no longer parses - restoring"; cp_restore "$ini"
        fi
    fi
done

# PHP4: restart whatever actually runs PHP
echo ""
if a2query -m 'php*' >/dev/null 2>&1 || ls /etc/apache2/mods-enabled/php*.load >/dev/null 2>&1; then
    apache2ctl configtest >/dev/null 2>&1 && cp_restart apache2
fi
for u in $(systemctl list-unit-files 'php*-fpm.service' 2>/dev/null | awk '/fpm\.service/{print $1}'); do
    if command -v "${u%.service}" >/dev/null 2>&1 && ! "${u%.service}" -t >/dev/null 2>&1; then
        cp_err "${u%.service} -t failed - check the FPM config"; continue
    fi
    cp_restart "${u%.service}"
done

# G2: functional check - X-Powered-By must be gone
if command -v curl >/dev/null 2>&1; then
    H="$(curl -sI --max-time 5 http://127.0.0.1/ 2>/dev/null)"
    if [ -n "$H" ]; then
        echo "$H" | grep -qi '^X-Powered-By: PHP' && cp_warn "X-Powered-By still exposes PHP" || cp_ok "No X-Powered-By header"
    fi
fi
echo ""
echo "PHP hardening complete. Effective values (apache2/fpm):"
for ini in "${INIS[@]}"; do
    echo "  $ini: expose_php=$(cp_get "$ini" expose_php) display_errors=$(cp_get "$ini" display_errors) allow_url_include=$(cp_get "$ini" allow_url_include) allow_url_fopen=$(cp_get "$ini" allow_url_fopen)"
done
