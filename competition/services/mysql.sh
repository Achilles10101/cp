#!/bin/bash

# MySQL/MariaDB Security Configuration Script
# Research-doc items: DB1-DB10, G1, G2, G5 (baseline first: section B)
#
# Usage: sudo bash services/mysql.sh [--reask]
# Answers are asked once and kept in /root/cp-state/readme.conf, so a re-run asks nothing:
#   MYSQL_REMOTE (yes|no)  MYSQL_REQ_TLS (ON|OFF)  MYSQL_GENLOG (1|0)
#   MYSQL_ACCOUNTS_OK (non-default accounts you already reviewed and kept - only new ones are asked about)
#   --reask   forget those answers and ask again

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../cp-common.sh
source "$SCRIPT_DIR/../cp-common.sh" 2>/dev/null || { echo "ERROR: cp-common.sh not found (keep the repo layout intact)"; exit 1; }

# ---- local helpers (same block in every services/*.sh; cp-common.sh is shared/owned elsewhere) ----
SVC=mysql; SVC_T0=$SECONDS
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

# FUNCTIONS

check_root() { cp_require_root; }

# DB1: status messages go to STDERR so that $(detect_database_type) captures only the type.
detect_database_type() {
    if mysqld --version 2>/dev/null | grep -qi mariadb || mariadbd --version 2>/dev/null | grep -qi mariadb || \
       mysql --version 2>/dev/null | grep -qi mariadb; then
        echo "mariadb"
    elif mysqld --version 2>/dev/null | grep -qi mysql || mysql --version 2>/dev/null | grep -qi mysql; then
        echo "mysql"
    else
        echo "ERROR: Could not determine database type" >&2
        exit 1
    fi
}

sql() { mysql -NBe "$1"; }

configure_database_security() {
    # DB2: account statements instead of UPDATE/DELETE on mysql.user (a VIEW on MariaDB >= 10.4)
    sql "DROP USER IF EXISTS ''@'localhost', ''@'%', ''@'$(hostname)', ''@'$(hostname -f 2>/dev/null || hostname)';" || true
    if [ -n "$(sql "SELECT 1 FROM mysql.user WHERE user='root' AND host='localhost'")" ]; then
        for h in $(sql "SELECT host FROM mysql.user WHERE user='root' AND host NOT IN ('localhost','127.0.0.1','::1')"); do
            sql "DROP USER IF EXISTS 'root'@'$h';" && cp_ok "Dropped remote root account root@$h"
        done
    else
        cp_warn "root@localhost does not exist - not touching other root accounts (would lock you out)"
    fi
    # DB3: the old script created 'admin'@'localhost' WITH GRANT OPTION and a hard-coded password.
    # That step is removed. If an earlier run created it, offer to drop it.
    if [ -n "$(sql "SELECT 1 FROM mysql.user WHERE user='admin' AND host='localhost'")" ]; then
        cp_warn "Account admin@localhost exists (older versions of this script created it)"
        cp_ask "Drop admin@localhost? (say no only if the README lists an 'admin' DB user)" y && sql "DROP USER 'admin'@'localhost';" && cp_ok "Dropped admin@localhost"
    fi
    sql "DROP DATABASE IF EXISTS test;" || true
    sql "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';" 2>/dev/null || true
    sql "FLUSH PRIVILEGES;" || true
    cp_ok "Anonymous accounts, remote root and the test database removed"
}

audit_accounts() {
    # DB10 - act on the B7 account diff. Only accounts a default install does not have are shown.
    local DEFAULTS="'root','mysql.sys','mysql.session','mysql.infoschema','debian-sys-maint','mariadb.sys','mysql'"
    local extra
    extra="$(sql "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE user NOT IN ($DEFAULTS) ORDER BY user, host;" 2>/dev/null)"
    local reviewed new_acc="" a
    reviewed="$(cp_cfg_get MYSQL_ACCOUNTS_OK)"
    for a in $extra; do [[ " $reviewed " == *" $a "* ]] || new_acc="$new_acc $a"; done
    if [ -z "$extra" ]; then
        cp_ok "Only default MySQL accounts exist (root, mysql.*, debian-sys-maint)"
    elif [ -z "$new_acc" ]; then
        cp_info "Non-default MySQL accounts already reviewed and kept (--reask to review again): $(echo $extra)"
    else
        echo "  Accounts a default install does NOT have (compare with the README / the web app's DB_USER):"
        mysql -t -e "SELECT user, host, plugin,
                        IF(authentication_string='' AND plugin NOT IN ('unix_socket','auth_socket'),'EMPTY','set') AS password,
                        Super_priv AS super, File_priv AS file, Process_priv AS process, Grant_priv AS grant_opt
                     FROM mysql.user WHERE user NOT IN ($DEFAULTS) ORDER BY user, host;" 2>/dev/null | sed 's/^/      /'
        local drop a
        drop="$(cp_read "Accounts to DROP (user@host, comma separated; Enter = none)" "")"
        IFS=',' read -ra ACC <<< "$drop"
        for a in "${ACC[@]}"; do
            a="$(echo "$a" | xargs)"; [ -n "$a" ] || continue
            sql "DROP USER IF EXISTS '${a%@*}'@'${a#*@}';" && cp_ok "Dropped $a"
        done
        local priv
        priv="$(sql "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE user NOT IN ($DEFAULTS) AND (Super_priv='Y' OR File_priv='Y' OR Process_priv='Y' OR Grant_priv='Y');" 2>/dev/null | tr '\n' ',' | sed 's/,$//')"
        if [ -n "$priv" ]; then
            local rev
            rev="$(cp_read "Accounts to strip SUPER/FILE/PROCESS/GRANT OPTION from (user@host, comma separated; Enter = none; have them: $priv)" "")"
            IFS=',' read -ra ACC <<< "$rev"
            for a in "${ACC[@]}"; do
                a="$(echo "$a" | xargs)"; [ -n "$a" ] || continue
                sql "REVOKE SUPER, FILE, PROCESS ON *.* FROM '${a%@*}'@'${a#*@}';" 2>/dev/null
                sql "REVOKE GRANT OPTION ON *.* FROM '${a%@*}'@'${a#*@}';" 2>/dev/null
                cp_ok "Revoked global SUPER/FILE/PROCESS/GRANT OPTION from $a"
            done
        fi
        cp_cfg_set MYSQL_ACCOUNTS_OK "$(sql "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE user NOT IN ($DEFAULTS);" 2>/dev/null | xargs)"
    fi
    for a in $(sql "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE user NOT IN ($DEFAULTS) AND (host='%' OR Super_priv='Y' OR Grant_priv='Y');" 2>/dev/null); do
        cp_todo "MySQL account $a can log in from anywhere or has SUPER/GRANT - drop it or strip it unless the README needs it"
    done
    # plaintext credential leftovers
    for f in /root/.mysql_history /home/*/.mysql_history; do
        [ -f "$f" ] || continue
        if cp_ask "Delete $f (may contain passwords; backed up)?" y; then cp_backup "$f"; rm -f "$f" && cp_ok "Deleted $f"; fi
    done
    for f in /root/.my.cnf /home/*/.my.cnf; do
        [ -f "$f" ] && grep -qi password "$f" && chmod 600 "$f" && cp_todo "$f stores a plaintext MySQL password (now mode 600) - remove it unless needed"
    done
    [ -f /etc/mysql/debian.cnf ] && chmod 600 /etc/mysql/debian.cnf && chown root:root /etc/mysql/debian.cnf
}

set_directory_permissions() {
    chown -R mysql:mysql /var/lib/mysql
    chmod 700 /var/lib/mysql
    # DB4: mysqld runs as user 'mysql' - it MUST still be able to read its own config.
    chown -R root:mysql /etc/mysql
    find /etc/mysql -type d -exec chmod 750 {} +
    find /etc/mysql -type f -name '*.cnf' -exec chmod 640 {} +
    [ -f /etc/mysql/debian.cnf ] && { chown root:root /etc/mysql/debian.cnf; chmod 600 /etc/mysql/debian.cnf; }
    local unreadable=0 f
    while IFS= read -r f; do
        [ "$f" = /etc/mysql/debian.cnf ] && continue
        su -s /bin/sh mysql -c "cat '$f'" >/dev/null 2>&1 || { cp_warn "mysql user cannot read $f"; unreadable=1; }
    done < <(find -L /etc/mysql -type f -name '*.cnf')
    if [ "$unreadable" = 1 ]; then
        cp_warn "Falling back to the Debian default (755/644) so mysqld does not silently ignore its config"
        find /etc/mysql -type d -exec chmod 755 {} + ; find /etc/mysql -type f -name '*.cnf' -exec chmod 644 {} +
        chmod 600 /etc/mysql/debian.cnf 2>/dev/null
    fi
    mkdir -p /var/log/mysql
    touch /var/log/mysql/error.log
    chown -R mysql:adm /var/log/mysql
    chmod 2750 /var/log/mysql
    chmod 640 /var/log/mysql/*.log
    cp_ok "Perms: /var/lib/mysql 700 mysql, /etc/mysql root:mysql 750/640 (debian.cnf 600), /var/log/mysql 2750 mysql:adm"
}

generate_ssl_certificates() {
    # reuse the certificates of an earlier run (regenerating them on every run cost time for nothing)
    if [ -s /etc/mysql/ssl/server-key.pem ] && openssl x509 -checkend 86400 -noout -in /etc/mysql/ssl/server-cert.pem >/dev/null 2>&1 \
       && openssl x509 -noout -in /etc/mysql/ssl/ca.pem >/dev/null 2>&1; then
        cp_ok "Using existing TLS certificates in /etc/mysql/ssl"
    else
        mkdir -p /etc/mysql/ssl
        (
            cd /etc/mysql/ssl || exit 1
            openssl genrsa 2048 > ca-key.pem 2>/dev/null
            openssl req -new -x509 -nodes -days 3650 -key ca-key.pem -out ca.pem -subj "/CN=mysql-ca" 2>/dev/null
            openssl req -newkey rsa:2048 -days 3650 -nodes -keyout server-key.pem -out server-req.pem -subj "/CN=$(hostname)" 2>/dev/null
            openssl rsa -in server-key.pem -out server-key.pem 2>/dev/null
            openssl x509 -req -in server-req.pem -days 3650 -CA ca.pem -CAkey ca-key.pem -set_serial 01 -out server-cert.pem 2>/dev/null
        )
        cp_ok "TLS certificates generated in /etc/mysql/ssl"
    fi
    chmod 644 /etc/mysql/ssl/*.pem
    chmod 600 /etc/mysql/ssl/*-key.pem
    chown -R mysql:mysql /etc/mysql/ssl
    chmod 750 /etc/mysql/ssl
}

write_configuration() {
    local db_type=$1
    local config_file=""
    if [ "$db_type" = "mariadb" ]; then
        config_file="/etc/mysql/mariadb.conf.d/50-server.cnf"
    else
        config_file="/etc/mysql/mysql.conf.d/mysqld.cnf"
    fi
    [ -f "$config_file" ] || { mkdir -p "$(dirname "$config_file")"; printf '[mysqld]\n' > "$config_file"; }
    CONFIG_FILE="$config_file"

    # README / app answers, asked once (DB6, DB9)
    local BIND="127.0.0.1" REQ_TLS="OFF" GENLOG="0"
    if cp_cfg_has MYSQL_REMOTE && cp_cfg_has MYSQL_REQ_TLS && cp_cfg_has MYSQL_GENLOG; then
        [ "$(cp_cfg_get MYSQL_REMOTE)" = yes ] && BIND="0.0.0.0"
        REQ_TLS="$(cp_cfg_get MYSQL_REQ_TLS)"; GENLOG="$(cp_cfg_get MYSQL_GENLOG)"
        cp_info "Answers (stored; --reask to change): remote access $(cp_cfg_get MYSQL_REMOTE), require_secure_transport $REQ_TLS, general_log $GENLOG"
    else
        echo "  README-dependent MySQL settings - Enter keeps all of them:"
        echo "      local connections only (bind-address 127.0.0.1) | TLS not forced for TCP clients | general_log off"
        if cp_ask "Does the README change any of these (remote DB access, TLS-only clients, query logging)?" n; then
            cp_ask "Does the README require REMOTE database access?" n && BIND="0.0.0.0"
            cp_ask "Require TLS for every TCP connection (require_secure_transport)? Breaks apps that use 127.0.0.1 without TLS" n && REQ_TLS="ON"
            cp_ask "Enable general_log (logs EVERY query, including passwords in CREATE/ALTER USER)?" n && GENLOG="1"
        fi
        cp_cfg_set MYSQL_REMOTE "$([ "$BIND" = 0.0.0.0 ] && echo yes || echo no)"
        cp_cfg_set MYSQL_REQ_TLS "$REQ_TLS"; cp_cfg_set MYSQL_GENLOG "$GENLOG"
    fi

    local -a SETTINGS=(
        "bind-address=$BIND"
        "ssl-ca=/etc/mysql/ssl/ca.pem"
        "ssl-cert=/etc/mysql/ssl/server-cert.pem"
        "ssl-key=/etc/mysql/ssl/server-key.pem"
        "require_secure_transport=$REQ_TLS"
        "local-infile=0"
        "secure_file_priv=/var/lib/mysql-files"
        "skip-symbolic-links=__FLAG__"
        "sql_mode=STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION"
        "general_log=$GENLOG"
        "general_log_file=/var/log/mysql/mysql.log"
        "log_error=/var/log/mysql/error.log"
        "performance_schema=OFF"
    )
    if [ "$db_type" = "mariadb" ]; then SETTINGS+=("log_warnings=2"); else SETTINGS+=("log_error_verbosity=3"); fi

    local kv k v f
    mapfile -t CNFS < <(find -L /etc/mysql -type f -name '*.cnf')
    for kv in "${SETTINGS[@]}"; do
        k="${kv%%=*}"; v="${kv#*=}"
        # G1: remove conflicting copies of the same option from every OTHER cnf file
        for f in "${CNFS[@]}"; do
            [ "$(readlink -f "$f")" = "$(readlink -f "$config_file")" ] && continue
            if [ -n "$(cp_get "$f" "$k" eqs 0 1)" ] || grep -qiE "^[[:space:]]*${k//[-_]/[-_]}[[:space:]]*$" "$f"; then
                cp_warn "$f also set $k - removed there"; cp_unset "$f" "$k" eqs 0 1 >/dev/null
                sed -i -E "/^[[:space:]]*${k//[-_]/[-_]}[[:space:]]*$/d" "$f"
            fi
        done
        sed -i -E "/^[[:space:]]*${k//[-_]/[-_]}[[:space:]]*$/d" "$config_file"   # bare flag form
        cp_set "$config_file" "$k" "$v" eqs 0 1 mysqld
    done

    # DB7: dangerous options anywhere in /etc/mysql
    for f in "${CNFS[@]}"; do
        for k in skip-grant-tables old_passwords old-passwords skip-networking symbolic-links; do
            if grep -qiE "^[[:space:]]*${k//[-_]/[-_]}([[:space:]]*=.*)?$" "$f"; then
                case "$k" in
                    skip-networking) cp_todo "$f contains skip-networking (TCP disabled) - keep only if the README/app allows it" ;;
                    *) cp_warn "$f contained $k - removed"
                       sed -i -E "/^[[:space:]]*${k//[-_]/[-_]}([[:space:]]*=.*)?$/d" "$f" ;;
                esac
            fi
        done
    done

    mkdir -p /var/lib/mysql-files && chown mysql:mysql /var/lib/mysql-files && chmod 750 /var/lib/mysql-files
    chmod 640 "$config_file"
}

validate_configuration() {
    # DB8: validate BEFORE restarting so a typo cannot take the critical service down
    local db_type=$1 out
    if [ "$db_type" = "mysql" ] && mysqld --verbose --help 2>/dev/null | grep -q -- '--validate-config'; then
        out="$(mysqld --validate-config 2>&1)" || { cp_err "mysqld --validate-config failed:"; echo "$out"; return 1; }
    else
        # only real errors: "[ERROR]" lines / unknown variables (Notes like 'Error-log destination' and
        # warnings mentioning ERROR_FOR_DIVISION_BY_ZERO used to roll back every change)
        out="$( { mariadbd --help --verbose || mysqld --help --verbose; } 2>&1 >/dev/null | grep -E '\[ERROR\]|unknown (variable|option)' )"
        [ -z "$out" ] || { cp_err "Config check failed:"; echo "$out"; return 1; }
    fi
    cp_ok "Configuration is valid"
}

db_unit() { if [ "$1" = "mariadb" ]; then cp_first_unit mariadb mysql; else cp_first_unit mysql mysqld; fi; }
restart_database_service() {
    local unit; unit="$(db_unit "$1")"
    cp_restart "${unit:-mysql}"
}

# Main Execution
cp_require_root
[ "${1:-}" = "--reask" ] && svc_forget MYSQL_REMOTE MYSQL_REQ_TLS MYSQL_GENLOG MYSQL_ACCOUNTS_OK
cp_hdr "MySQL/MariaDB hardening"
cp_screenshot_prompt
command -v mysqld >/dev/null 2>&1 || command -v mariadbd >/dev/null 2>&1 || command -v mysql >/dev/null 2>&1 \
    || { echo "ERROR: MySQL/MariaDB is not installed"; svc_result FAIL "not installed"; exit 1; }
cp_baseline_gate mysql

DB_TYPE=$(detect_database_type) || { svc_result FAIL "unknown database type"; exit 1; }
cp_info "Database type: $DB_TYPE"

# Config first (a planted bad option can even break the mysql client), then accounts.
cp_backup /etc/mysql
SNAP0="$(svc_snap /etc/mysql)"
set_directory_permissions
generate_ssl_certificates
write_configuration "$DB_TYPE"
UNIT="$(db_unit "$DB_TYPE")"; UNIT="${UNIT:-mysql}"
if [ "$(svc_snap /etc/mysql)" = "$SNAP0" ] && systemctl is-active --quiet "$UNIT"; then
    cp_ok "MySQL config unchanged - no restart needed"
    # still validate: a planted bad option only bites at the next restart/reboot
    validate_configuration "$DB_TYPE" >/dev/null 2>&1 || {
        cp_warn "The CURRENT MySQL config does not validate - mysqld would not start after a reboot"
        cp_todo "mysql.sh: /etc/mysql does not validate (mysqld --validate-config / --help --verbose) - find the bad option before any restart"; }
elif ! validate_configuration "$DB_TYPE" || ! restart_database_service "$DB_TYPE"; then
    cp_err "Rolling back /etc/mysql"
    cp_restore /etc/mysql
    # restart only if it is down (validation failed BEFORE any restart -> the running server is untouched)
    systemctl is-active --quiet "$UNIT" || restart_database_service "$DB_TYPE"
    cp_todo "mysql.sh: hardened config failed validation/restart and was rolled back - check /etc/mysql by hand"
    svc_result ROLLBACK "validate/restart failed"; exit 1
fi

if mysql -NBe "SELECT 1" >/dev/null 2>&1; then
    configure_database_security
    audit_accounts
else
    cp_err "Cannot log in as root through the socket - account hardening skipped. Fix access, then re-run."
    cp_todo "mysql.sh: root cannot log in through the socket - account hardening skipped"
fi

# G2: functional test + effective values
RESULT=OK
if mysql -NBe "SELECT 1" >/dev/null 2>&1; then
    cp_ok "Database answers queries: $(mysql -NBe "SELECT CONCAT('bind_address=',@@bind_address,' local_infile=',@@local_infile,' secure_file_priv=',IFNULL(@@secure_file_priv,'NULL'),' have_ssl=',@@have_ssl,' general_log=',@@general_log)" 2>/dev/null)"
else
    cp_warn "Database does not answer 'SELECT 1' as root - check it (critical service!)"
    systemctl is-active --quiet "$UNIT" || RESULT="FAIL $UNIT not active"
fi
echo "  Changed:"
svc_changes /etc/mysql
svc_result $RESULT
cp_ok "MySQL hardening complete ($((SECONDS - SVC_T0))s)"
