#!/bin/bash

# MySQL/MariaDB Security Configuration Script
# Research-doc items: DB1-DB10, G1, G2, G5 (baseline first: section B)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../cp-common.sh
source "$SCRIPT_DIR/../cp-common.sh" 2>/dev/null || { echo "ERROR: cp-common.sh not found (keep the repo layout intact)"; exit 1; }

# FUNCTIONS

check_root() { cp_require_root; }

# DB1: status messages go to STDERR so that $(detect_database_type) captures only the type.
detect_database_type() {
    echo "Detecting database server type..." >&2
    if mysqld --version 2>/dev/null | grep -qi mariadb || mariadbd --version 2>/dev/null | grep -qi mariadb || \
       mysql --version 2>/dev/null | grep -qi mariadb; then
        echo "Found: MariaDB" >&2
        echo "mariadb"
    elif mysqld --version 2>/dev/null | grep -qi mysql || mysql --version 2>/dev/null | grep -qi mysql; then
        echo "Found: MySQL" >&2
        echo "mysql"
    else
        echo "ERROR: Could not determine database type" >&2
        exit 1
    fi
}

sql() { mysql -NBe "$1"; }

configure_database_security() {
    echo ""
    echo "Configuring database security..."

    # DB2: account statements instead of UPDATE/DELETE on mysql.user (a VIEW on MariaDB >= 10.4)
    echo "  - Removing anonymous users"
    sql "DROP USER IF EXISTS ''@'localhost', ''@'%', ''@'$(hostname)', ''@'$(hostname -f 2>/dev/null || hostname)';" || true

    echo "  - Restricting root to localhost only"
    if [ -n "$(sql "SELECT 1 FROM mysql.user WHERE user='root' AND host='localhost'")" ]; then
        for h in $(sql "SELECT host FROM mysql.user WHERE user='root' AND host NOT IN ('localhost','127.0.0.1','::1')"); do
            sql "DROP USER IF EXISTS 'root'@'$h';" && echo "    dropped root@$h"
        done
    else
        cp_warn "root@localhost does not exist - not touching other root accounts (would lock you out)"
    fi

    # DB3: the old script created 'admin'@'localhost' WITH GRANT OPTION and a hard-coded password.
    # That step is removed. If an earlier run created it, offer to drop it.
    if [ -n "$(sql "SELECT 1 FROM mysql.user WHERE user='admin' AND host='localhost'")" ]; then
        cp_warn "Account admin@localhost exists (older versions of this script created it)"
        cp_ask "Drop admin@localhost? (say no only if the README lists an 'admin' DB user)" y && sql "DROP USER 'admin'@'localhost';" && echo "    dropped admin@localhost"
    fi

    echo "  - Removing test database"
    sql "DROP DATABASE IF EXISTS test;" || true
    sql "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';" 2>/dev/null || true

    echo "  - Flushing privileges"
    sql "FLUSH PRIVILEGES;" || true
}

audit_accounts() {
    # DB10 - act on the B7 account diff
    echo ""
    echo "Auditing accounts (compare with the README and /root/baseline/mysql/report.txt):"
    mysql -t -e "SELECT user, host, plugin,
                    IF(authentication_string='' AND plugin NOT IN ('unix_socket','auth_socket'),'EMPTY','set') AS password,
                    Super_priv AS super, File_priv AS file, Process_priv AS process, Grant_priv AS grant_opt
                 FROM mysql.user ORDER BY user, host;" 2>/dev/null
    local drop
    drop="$(cp_read "Accounts to DROP (user@host, comma separated; Enter = none)" "")"
    IFS=',' read -ra ACC <<< "$drop"
    for a in "${ACC[@]}"; do
        a="$(echo "$a" | xargs)"; [ -n "$a" ] || continue
        sql "DROP USER IF EXISTS '${a%@*}'@'${a#*@}';" && cp_ok "Dropped $a"
    done
    local rev
    rev="$(cp_read "Accounts to strip SUPER/FILE/PROCESS/GRANT OPTION from (user@host, comma separated; Enter = none)" "")"
    IFS=',' read -ra ACC <<< "$rev"
    for a in "${ACC[@]}"; do
        a="$(echo "$a" | xargs)"; [ -n "$a" ] || continue
        sql "REVOKE SUPER, FILE, PROCESS ON *.* FROM '${a%@*}'@'${a#*@}';" 2>/dev/null
        sql "REVOKE GRANT OPTION ON *.* FROM '${a%@*}'@'${a#*@}';" 2>/dev/null
        cp_ok "Revoked global SUPER/FILE/PROCESS/GRANT OPTION from $a"
    done
    # plaintext credential leftovers
    for f in /root/.mysql_history /home/*/.mysql_history; do
        [ -f "$f" ] || continue
        cp_warn "$f exists (may contain passwords)"
        cp_ask "Delete $f ?" y && rm -f "$f" && cp_ok "Deleted $f"
    done
    for f in /root/.my.cnf /home/*/.my.cnf; do
        [ -f "$f" ] && grep -qi password "$f" && cp_warn "$f stores a plaintext password - review (mode $(stat -c %a "$f"))" && chmod 600 "$f"
    done
    [ -f /etc/mysql/debian.cnf ] && chmod 600 /etc/mysql/debian.cnf && chown root:root /etc/mysql/debian.cnf
}

set_directory_permissions() {
    echo ""
    echo "Setting directory and file permissions..."

    echo "  - Setting data directory permissions"
    chown -R mysql:mysql /var/lib/mysql
    chmod 700 /var/lib/mysql

    # DB4: mysqld runs as user 'mysql' - it MUST still be able to read its own config.
    echo "  - Setting config directory permissions (root:mysql, dirs 750, *.cnf 640)"
    chown -R root:mysql /etc/mysql
    find /etc/mysql -type d -exec chmod 750 {} \;
    find /etc/mysql -type f -name '*.cnf' -exec chmod 640 {} \;
    [ -f /etc/mysql/debian.cnf ] && { chown root:root /etc/mysql/debian.cnf; chmod 600 /etc/mysql/debian.cnf; }
    local unreadable=0 f
    while IFS= read -r f; do
        [ "$f" = /etc/mysql/debian.cnf ] && continue
        su -s /bin/sh mysql -c "cat '$f'" >/dev/null 2>&1 || { cp_warn "mysql user cannot read $f"; unreadable=1; }
    done < <(find -L /etc/mysql -type f -name '*.cnf')
    if [ "$unreadable" = 1 ]; then
        cp_warn "Falling back to the Debian default (755/644) so mysqld does not silently ignore its config"
        find /etc/mysql -type d -exec chmod 755 {} \; ; find /etc/mysql -type f -name '*.cnf' -exec chmod 644 {} \;
        chmod 600 /etc/mysql/debian.cnf 2>/dev/null
    fi

    echo "  - Creating and setting log directory"
    mkdir -p /var/log/mysql
    touch /var/log/mysql/error.log
    chown -R mysql:adm /var/log/mysql
    chmod 2750 /var/log/mysql
    chmod 640 /var/log/mysql/*.log
}

generate_ssl_certificates() {
    echo ""
    echo "Generating SSL certificates..."
    mkdir -p /etc/mysql/ssl
    (
        cd /etc/mysql/ssl || exit 1
        echo "  - Generating CA key"
        openssl genrsa 2048 > ca-key.pem 2>/dev/null
        echo "  - Generating CA certificate"
        openssl req -new -x509 -nodes -days 3650 -key ca-key.pem -out ca.pem -subj "/CN=mysql-ca" 2>/dev/null
        echo "  - Generating server key"
        openssl req -newkey rsa:2048 -days 3650 -nodes -keyout server-key.pem -out server-req.pem -subj "/CN=$(hostname)" 2>/dev/null
        openssl rsa -in server-key.pem -out server-key.pem 2>/dev/null
        echo "  - Generating server certificate"
        openssl x509 -req -in server-req.pem -days 3650 -CA ca.pem -CAkey ca-key.pem -set_serial 01 -out server-cert.pem 2>/dev/null
        echo "  - Setting certificate permissions"
        chmod 644 ./*.pem
        chmod 600 ./*-key.pem
        chown -R mysql:mysql /etc/mysql/ssl
        chmod 750 /etc/mysql/ssl
    )
}

write_configuration() {
    local db_type=$1
    local config_file=""

    echo ""
    echo "Writing configuration (in place - DB5)..."

    if [ "$db_type" = "mariadb" ]; then
        config_file="/etc/mysql/mariadb.conf.d/50-server.cnf"
    else
        config_file="/etc/mysql/mysql.conf.d/mysqld.cnf"
    fi
    [ -f "$config_file" ] || { mkdir -p "$(dirname "$config_file")"; printf '[mysqld]\n' > "$config_file"; }
    CONFIG_FILE="$config_file"
    cp_backup /etc/mysql
    echo "  - Editing: $config_file ([mysqld] section)"

    local BIND="127.0.0.1"
    cp_ask "Does the README require REMOTE database access?" n && BIND="0.0.0.0"
    local REQ_TLS="OFF"
    cp_ask "Require TLS for every TCP connection (require_secure_transport)? Breaks apps that use 127.0.0.1 without TLS" n && REQ_TLS="ON"
    local GENLOG="0"
    cp_ask "Enable general_log (logs EVERY query, including passwords in CREATE/ALTER USER)?" n && GENLOG="1"

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
    for kv in "${SETTINGS[@]}"; do
        k="${kv%%=*}"; v="${kv#*=}"
        # G1: remove conflicting copies of the same option from every OTHER cnf file
        while IFS= read -r f; do
            [ "$(readlink -f "$f")" = "$(readlink -f "$config_file")" ] && continue
            if [ -n "$(cp_get "$f" "$k" eqs 0 1)" ] || grep -qiE "^[[:space:]]*${k//[-_]/[-_]}[[:space:]]*$" "$f"; then
                cp_warn "$f also sets $k - removing"; cp_unset "$f" "$k" eqs 0 1
                sed -i -E "/^[[:space:]]*${k//[-_]/[-_]}[[:space:]]*$/d" "$f"
            fi
        done < <(find -L /etc/mysql -type f -name '*.cnf')
        sed -i -E "/^[[:space:]]*${k//[-_]/[-_]}[[:space:]]*$/d" "$config_file"   # bare flag form
        cp_set "$config_file" "$k" "$v" eqs 0 1 mysqld
    done

    # DB7: dangerous options anywhere in /etc/mysql
    while IFS= read -r f; do
        for k in skip-grant-tables old_passwords old-passwords skip-networking symbolic-links; do
            if grep -qiE "^[[:space:]]*${k//[-_]/[-_]}([[:space:]]*=.*)?$" "$f"; then
                case "$k" in
                    skip-networking) cp_warn "$f contains skip-networking (TCP disabled) - keep only if the README/app allows it" ;;
                    *) cp_warn "$f contains $k - removing"
                       sed -i -E "/^[[:space:]]*${k//[-_]/[-_]}([[:space:]]*=.*)?$/d" "$f" ;;
                esac
            fi
        done
    done < <(find -L /etc/mysql -type f -name '*.cnf')

    mkdir -p /var/lib/mysql-files && chown mysql:mysql /var/lib/mysql-files && chmod 750 /var/lib/mysql-files
    chmod 640 "$config_file"
}

validate_configuration() {
    # DB8: validate BEFORE restarting so a typo cannot take the critical service down
    local db_type=$1 out
    echo ""
    echo "Validating configuration..."
    if [ "$db_type" = "mysql" ] && mysqld --help 2>/dev/null | grep -q -- '--validate-config'; then
        out="$(mysqld --validate-config 2>&1)" || { cp_err "mysqld --validate-config failed:"; echo "$out"; return 1; }
    else
        out="$( { mariadbd --help --verbose || mysqld --help --verbose; } 2>&1 >/dev/null | grep -iE 'error|unknown' )"
        [ -z "$out" ] || { cp_err "Config check failed:"; echo "$out"; return 1; }
    fi
    cp_ok "Configuration is valid"
}

restart_database_service() {
    local db_type=$1 unit
    echo ""
    echo "Restarting database service..."
    if [ "$db_type" = "mariadb" ]; then unit="$(cp_first_unit mariadb mysql)"; else unit="$(cp_first_unit mysql mysqld)"; fi
    cp_restart "${unit:-mysql}"
}

# Main Execution
echo "MySQL/MariaDB Security Configuration"
echo ""

cp_screenshot_prompt
check_root
cp_baseline_gate mysql

DB_TYPE=$(detect_database_type) || exit 1
echo "Database type: $DB_TYPE"

# Config first (a planted bad option can even break the mysql client), then accounts.
set_directory_permissions
generate_ssl_certificates
write_configuration "$DB_TYPE"
if ! validate_configuration "$DB_TYPE" || ! restart_database_service "$DB_TYPE"; then
    cp_err "Rolling back /etc/mysql"
    cp_restore /etc/mysql
    restart_database_service "$DB_TYPE"
    exit 1
fi

if mysql -NBe "SELECT 1" >/dev/null 2>&1; then
    configure_database_security
    audit_accounts
else
    cp_err "Cannot log in as root through the socket - account hardening skipped. Fix access, then re-run."
fi

# G2: functional test + effective values
echo ""
if mysql -NBe "SELECT 1" >/dev/null 2>&1; then
    cp_ok "Database answers queries"
    mysql -t -e "SHOW VARIABLES WHERE Variable_name IN ('bind_address','local_infile','secure_file_priv','have_symlink','require_secure_transport','have_ssl','general_log','log_error');" 2>/dev/null
else
    cp_warn "Database does not answer 'SELECT 1' as root - check it (critical service!)"
fi

echo "Configuration completed successfully!"
echo ""
