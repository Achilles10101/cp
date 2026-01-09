#!/bin/bash

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
else
    echo "No interactive terminal detected; proceeding without screenshot confirmation."
fi

echo "File, Package, and SUID/GUID Scanner"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Not running as root, exiting."
    exit 1
fi

# 1. Package and Service Scan
echo "[1] Scanning for unauthorized packages and services..."

# List of packages/services to check
SUSPICIOUS_ITEMS=(
    "john" "xinetd" "postfix" "sendmail" "nfs-kernel-server" 
    "nmap" "vuze" "frostwire" "kismet" "minetest" "minetest-server" 
    "medusa" "hydra" "truecrack" "ophcrack" "nikto" "cryptcat" 
    "nc" "netcat" "tightvncserver" "x11vnc" "nfs" 
    "samba" "postgresql" "vsftpd" "apache" "apache2" 
    "mysql" "php" "snmp" "dovecot" "bind9" "nginx" 
    "wireshark" "telnet"
)

FOUND_PACKAGES=()
FOUND_SERVICES=()

for item in "${SUSPICIOUS_ITEMS[@]}"; do
    # Check if package is installed (dpkg for Debian/Ubuntu)
    if command -v dpkg &> /dev/null; then
        if dpkg -l | grep -qw "^ii.*${item}"; then
            echo "  [ALERT] Package '${item}' is INSTALLED"
            FOUND_PACKAGES+=("$item")
        fi
    fi
     
    # Check if service is active
    if systemctl list-unit-files 2>/dev/null | grep -qw "${item}"; then
        if systemctl is-active --quiet "${item}" 2>/dev/null; then
            echo "  [ALERT] Service '${item}' is ACTIVE"
            FOUND_SERVICES+=("$item")
        elif systemctl is-enabled --quiet "${item}" 2>/dev/null; then
            echo "  [WARNING] Service '${item}' is ENABLED but not running"
            FOUND_SERVICES+=("$item")
        fi
    fi
done

if [ ${#FOUND_PACKAGES[@]} -eq 0 ] && [ ${#FOUND_SERVICES[@]} -eq 0 ]; then
    echo "  No suspicious packages or services found"
fi
echo ""

# 2. Unauthorized File Scan
echo "[2] Scanning for unauthorized files..."

UNAUTH_FILES=$(find / \
    -path /usr/share -prune -o \
    -path /usr/src -prune -o \
    -path /usr/lib -prune -o \
    -type f \( \
        -iname "*.mp3" -o -iname "*.mp4" -o -iname "*.avi" -o -iname "*.mkv" \
        -o -iname "*.wav" -o -iname "*.ogg" -o -iname "*.flac" \
        -o -iname "*.zip" -o -iname "*.rar" -o -iname "*.7z" -o -iname "*.py" \
        -o -iname "*.png" -o -iname "*.jpg" -o -iname "*.jpeg" -o -iname "*.gif" \
    \) -print 2>/dev/null)

FILE_COUNT=$(echo "$UNAUTH_FILES" | grep -c '^' 2>/dev/null)

if [ -z "$UNAUTH_FILES" ] || [ "$FILE_COUNT" -eq 0 ]; then
    echo "  No unauthorized files found"
else
    echo "  Found ${FILE_COUNT} unauthorized file(s):"
    echo "$UNAUTH_FILES"
fi
echo ""

# 3. SUID/SGID/Sticky Bit Scan
echo "[3] Scanning for SUID/SGID/Sticky bit files..."

# Find SUID files (chmod 4000)
SUID_FILES=$(find / -type f -perm -4000 2>/dev/null)
SUID_COUNT=$(echo "$SUID_FILES" | grep -c '^' 2>/dev/null)

# Find SGID files (chmod 2000)
SGID_FILES=$(find / -type f -perm -2000 2>/dev/null)
SGID_COUNT=$(echo "$SGID_FILES" | grep -c '^' 2>/dev/null)

# Find Sticky bit files (chmod 1000)
STICKY_FILES=$(find / -type f -perm -1000 2>/dev/null)
STICKY_COUNT=$(echo "$STICKY_FILES" | grep -c '^' 2>/dev/null)

# SUID Results
if [ -z "$SUID_FILES" ] || [ "$SUID_COUNT" -eq 0 ]; then
    echo "  No SUID files found"
else
    echo "  Found ${SUID_COUNT} SUID file(s):"
    echo "$SUID_FILES" | while read -r file; do
        ls -lh "$file" 2>/dev/null | awk '{print "    " $1 " " $3 ":" $4 " " $9}'
    done
fi

# SGID Results
if [ -z "$SGID_FILES" ] || [ "$SGID_COUNT" -eq 0 ]; then
    echo "  No SGID files found"
else
    echo "  Found ${SGID_COUNT} SGID file(s):"
    echo "$SGID_FILES" | while read -r file; do
        ls -lh "$file" 2>/dev/null | awk '{print "    " $1 " " $3 ":" $4 " " $9}'
    done
fi

# Sticky Bit Results
if [ -z "$STICKY_FILES" ] || [ "$STICKY_COUNT" -eq 0 ]; then
    echo "  No Sticky bit files found"
else
    echo "  Found ${STICKY_COUNT} Sticky bit file(s):"
    echo "$STICKY_FILES" | while read -r file; do
        ls -lh "$file" 2>/dev/null | awk '{print "    " $1 " " $3 ":" $4 " " $9}'
    done
fi

echo ""
echo "=== Scan Complete ==="
