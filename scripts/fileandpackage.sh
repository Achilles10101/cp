#!/bin/bash

echo "File, package, and SUID/GUID scanner script"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Warning: Not running as root. Some checks may be incomplete."
    echo ""
fi

# 1. Package and Service Scan
echo "[1] Scanning for unauthorized packages and services..."
echo ""

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
    echo "Checking: ${item}"
    
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

echo ""
echo "Package/Service Scan Summary:"
if [ ${#FOUND_PACKAGES[@]} -eq 0 ] && [ ${#FOUND_SERVICES[@]} -eq 0 ]; then
    echo "No suspicious packages or services found"
else
    if [ ${#FOUND_PACKAGES[@]} -gt 0 ]; then
        echo "Found ${#FOUND_PACKAGES[@]} suspicious package(s):"
        printf '%s\n' "${FOUND_PACKAGES[@]}" | sed 's/^/  - /'
    fi
    if [ ${#FOUND_SERVICES[@]} -gt 0 ]; then
        echo "Found ${#FOUND_SERVICES[@]} suspicious service(s):"
        printf '%s\n' "${FOUND_SERVICES[@]}" | sed 's/^/  - /'
    fi
fi
echo ""

# 2. Unauthorized File Scan
echo "[2] Scanning for unauthorized files..."
echo "This may take several minutes..."
echo ""

UNAUTH_FILES=$(find / -path /usr/share -prune -o -type f \( \
    -iname "*.mp3" -o -iname "*.mp4" -o -iname "*.avi" -o -iname "*.mkv" \
    -o -iname "*.wav" -o -iname "*.ogg" -o -iname "*.flac" \
    -o -iname "*.zip" -o -iname "*.rar" -o -iname "*.7z" -o -iname "*.py" \
    -o -iname "*.png" -o -iname "*.jpg" -o -iname "*.jpeg" -o -iname "*.gif" \
\) -print 2>/dev/null)

FILE_COUNT=$(echo "$UNAUTH_FILES" | grep -c '^' 2>/dev/null)

echo "Unauthorized File Scan Summary:"
if [ -z "$UNAUTH_FILES" ] || [ "$FILE_COUNT" -eq 0 ]; then
    echo "No unauthorized files found"
else
    echo "Found ${FILE_COUNT} unauthorized file(s):"
    echo "$UNAUTH_FILES" | head -20
    if [ "$FILE_COUNT" -gt 20 ]; then
        echo "... and $((FILE_COUNT - 20)) more files"
    fi
fi
echo ""

# 3. SUID/SGID/Sticky Bit Scan
echo "[3] Scanning for SUID/SGID/Sticky bit files..."
echo "This may take several minutes..."
echo ""

# Find SUID files (chmod 4000)
echo "Scanning for SUID files..."
SUID_FILES=$(find / -type f -perm -4000 2>/dev/null)

# Find SGID files (chmod 2000)
echo "Scanning for SGID files..."
SGID_FILES=$(find / -type f -perm -2000 2>/dev/null)

# Find Sticky bit files (chmod 1000)
echo "Scanning for Sticky bit files..."
STICKY_FILES=$(find / -type f -perm -1000 2>/dev/null)

SUID_COUNT=$(echo "$SUID_FILES" | grep -c '^' 2>/dev/null)
SGID_COUNT=$(echo "$SGID_FILES" | grep -c '^' 2>/dev/null)
STICKY_COUNT=$(echo "$STICKY_FILES" | grep -c '^' 2>/dev/null)

echo ""
echo "SUID/SGID/Sticky Bit Scan Summary:"

# SUID Results
if [ -z "$SUID_FILES" ] || [ "$SUID_COUNT" -eq 0 ]; then
    echo "No SUID files found"
else
    echo "Found ${SUID_COUNT} SUID file(s):"
    echo "$SUID_FILES" | while read -r file; do
        ls -lh "$file" 2>/dev/null | awk '{print "  " $1 " " $3 ":" $4 " " $9}'
    done
fi

echo ""

# SGID Results
if [ -z "$SGID_FILES" ] || [ "$SGID_COUNT" -eq 0 ]; then
    echo "No SGID files found"
else
    echo "Found ${SGID_COUNT} SGID file(s):"
    echo "$SGID_FILES" | while read -r file; do
        ls -lh "$file" 2>/dev/null | awk '{print "  " $1 " " $3 ":" $4 " " $9}'
    done
fi

echo ""

# Sticky Bit Results
if [ -z "$STICKY_FILES" ] || [ "$STICKY_COUNT" -eq 0 ]; then
    echo "No Sticky bit files found"
else
    echo "Found ${STICKY_COUNT} Sticky bit file(s):"
    echo "$STICKY_FILES" | while read -r file; do
        ls -lh "$file" 2>/dev/null | awk '{print "  " $1 " " $3 ":" $4 " " $9}'
    done
fi

echo ""
echo "Scan Complete, review all output."
