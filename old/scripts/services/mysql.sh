#!/bin/bash

# MySQL/MariaDB Security Configuration Script

set -e

# FUNCTIONS

check_root() {
    if [ "$EUID" -ne 0 ]; then 
        echo "ERROR: This script must be run as root or with sudo"
        exit 1
    fi
}

# Prompt for screenshot confirmation
if [ -t 0 ]; then
    while true; do
        read -r -p "Have you taken a screenshot of the points? (y/n): " yn
        case "$yn" in
            [Yy]* ) break ;;
            [Nn]* ) echo "Please take a screenshot first. Exiting."; exit 1 ;;
            * ) echo "Please answer y or n." ;;
        esac
    done
fi

detect_database_type() {
    echo "Detecting database server type..."
    
    if mysqld --version 2>/dev/null | grep -qi mariadb || \
       mysql --version 2>/dev/null | grep -qi mariadb; then
        echo "Found: MariaDB"
        echo "mariadb"
    elif mysqld --version 2>/dev/null | grep -qi mysql || \
         mysql --version 2>/dev/null | grep -qi mysql; then
        echo "Found: MySQL"
        echo "mysql"
    else
        echo "ERROR: Could not determine database type"
        exit 1
    fi
}

configure_database_security() {
    echo ""
    echo "Configuring database security..."
    
    echo "  - Removing anonymous users"
    mysql -e "SELECT User, Host FROM mysql.user WHERE User='';" 2>/dev/null | grep -v User | while read user host; do
        mysql -e "DROP USER IF EXISTS ''@'$host';" 2>/dev/null || true
    done
    # Fallback for older versions or if no anonymous users found
    mysql -e "DROP USER IF EXISTS ''@'localhost';" 2>/dev/null || true
    mysql -e "DROP USER IF EXISTS ''@'$(hostname)';" 2>/dev/null || true
    
    echo "  - Restricting root to localhost only"
    # Remove root users with non-localhost hosts
    mysql -e "DROP USER IF EXISTS 'root'@'%';" 2>/dev/null || true
    mysql -e "DROP USER IF EXISTS 'root'@'$(hostname)';" 2>/dev/null || true
    mysql -e "DROP USER IF EXISTS 'root'@'127.0.0.1';" 2>/dev/null || true
    mysql -e "DROP USER IF EXISTS 'root'@'::1';" 2>/dev/null || true
    # Ensure localhost root exists
    mysql -e "CREATE USER IF NOT EXISTS 'root'@'localhost' IDENTIFIED BY '';" 2>/dev/null || true
    mysql -e "GRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost' WITH GRANT OPTION;" 2>/dev/null || true
    
    echo "  - Creating admin user"
    mysql -e "CREATE USER IF NOT EXISTS 'admin'@'localhost' IDENTIFIED BY 'Cyb3rPatr3ot@2026!';"
    mysql -e "GRANT ALL PRIVILEGES ON *.* TO 'admin'@'localhost' WITH GRANT OPTION;"
    
    echo "  - Removing test database"
    mysql -e "DROP DATABASE IF EXISTS test;"
    mysql -e "DROP DATABASE IF EXISTS \`test\\_%\`;" 2>/dev/null || true
    
    echo "  - Applying changes"
    mysql -e "FLUSH PRIVILEGES;"
}

set_directory_permissions() {
    echo ""
    echo "Setting directory and file permissions..."
    
    echo "  - Setting data directory permissions"
    chown -R mysql:mysql /var/lib/mysql
    chmod 700 /var/lib/mysql
    
    echo "  - Setting config directory permissions"
    chmod 750 /etc/mysql
    if [ -f /etc/mysql/my.cnf ]; then
        chmod 640 /etc/mysql/my.cnf
    fi
    
    echo "  - Creating and setting log directory"
    mkdir -p /var/log/mysql
    touch /var/log/mysql/mysql.log /var/log/mysql/error.log
    chown -R mysql:mysql /var/log/mysql
    chmod 640 /var/log/mysql/*.log
}

generate_ssl_certificates() {
    echo ""
    echo "Generating SSL certificates..."
    
    mkdir -p /etc/mysql/ssl
    cd /etc/mysql/ssl
    
    echo "  - Generating CA key"
    openssl genrsa 2048 > ca-key.pem 2>/dev/null
    
    echo "  - Generating CA certificate"
    openssl req -new -x509 -nodes -days 3650 -key ca-key.pem -out ca.pem \
        -subj "/CN=mysql-ca" 2>/dev/null
    
    echo "  - Generating server key"
    openssl req -newkey rsa:2048 -days 3650 -nodes -keyout server-key.pem \
        -out server-req.pem -subj "/CN=$(hostname)" 2>/dev/null
    openssl rsa -in server-key.pem -out server-key.pem 2>/dev/null
    
    echo "  - Generating server certificate"
    openssl x509 -req -in server-req.pem -days 3650 -CA ca.pem \
        -CAkey ca-key.pem -set_serial 01 -out server-cert.pem 2>/dev/null
    
    echo "  - Setting certificate permissions"
    chmod 600 *-key.pem
    chmod 644 *.pem
    chown -R mysql:mysql /etc/mysql/ssl
}

write_configuration() {
    local db_type=$1
    local config_file=""
    local config_dir=""
    
    echo ""
    echo "Writing configuration file..."
    
    if [ "$db_type" = "mariadb" ]; then
        config_dir="/etc/mysql/mariadb.conf.d"
        config_file="$config_dir/50-server.cnf"
    else
        config_dir="/etc/mysql/mysql.conf.d"
        config_file="$config_dir/mysqld.cnf"
    fi
    
    mkdir -p "$config_dir"
    
    if [ -f "$config_file" ]; then
        backup_file="${config_file}.backup.$(date +%Y%m%d_%H%M%S)"
        echo "  - Backing up existing config to: $backup_file"
        cp "$config_file" "$backup_file"
    fi
    
    echo "  - Writing to: $config_file"
    
    cat > "$config_file" << 'EOF'
[mysqld]
bind-address = 127.0.0.1
ssl-ca = /etc/mysql/ssl/ca.pem
ssl-cert = /etc/mysql/ssl/server-cert.pem
ssl-key = /etc/mysql/ssl/server-key.pem
require_secure_transport = ON

local-infile = 0
sql_mode = STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION

general_log = 1
general_log_file = /var/log/mysql/mysql.log
log_error = /var/log/mysql/error.log

performance_schema = OFF
EOF

    chmod 644 "$config_file"
}

restart_database_service() {
    local db_type=$1
    
    echo ""
    echo "Restarting database service..."
    
    if [ "$db_type" = "mariadb" ]; then
        systemctl restart mariadb
    else
        systemctl restart mysql
    fi
}


# Main Execution
echo "MySQL/MariaDB Security Configuration"
echo ""

# Prompt the user to confirm they have taken a screenshot of the points
if [ -t 0 ]; then
    while true; do
        read -r -p "Have you taken a screenshot of the points? (y/n): " yn
        case "$yn" in
            [Yy]* ) break ;;
            [Nn]* ) echo "Please take a screenshot of the points before running this script. Exiting."; exit 1 ;;
            * ) echo "Please answer y or n." ;;
        esac
    done
fi

check_root

DB_TYPE=$(detect_database_type)

configure_database_security
set_directory_permissions
generate_ssl_certificates
write_configuration "$DB_TYPE"
restart_database_service "$DB_TYPE"

echo "Configuration completed successfully!"
echo ""
echo "Admin credentials:"
echo "  Username: admin"
echo "  Password: Cyb3rPatr3ot@2026!"
echo ""
