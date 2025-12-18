#!/bin/bash

# Security Scanner Script
# Scans for unauthorized packages, services, files, and permission issues

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  System Security Scanner${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${YELLOW}Warning: Not running as root. Some checks may be incomplete.${NC}"
    echo ""
fi

# ============================================
# 1. Package and Service Scan
# ============================================
echo -e "${BLUE}[1] Scanning for unauthorized packages and services...${NC}"
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
    echo -e "Checking: ${item}"
    
    # Check if package is installed (dpkg for Debian/Ubuntu)
    if command -v dpkg &> /dev/null; then
        if dpkg -l | grep -qw "^ii.*${item}"; then
            echo -e "  ${RED}[ALERT]${NC} Package '${item}' is INSTALLED"
            FOUND_PACKAGES+=("$item")
        fi
    fi
     
    # Check if service is active
    if systemctl list-unit-files 2>/dev/null | grep -qw "${item}"; then
        if systemctl is-active --quiet "${item}" 2>/dev/null; then
            echo -e "  ${RED}[ALERT]${NC} Service '${item}' is ACTIVE"
            FOUND_SERVICES+=("$item")
        elif systemctl is-enabled --quiet "${item}" 2>/dev/null; then
            echo -e "  ${YELLOW}[WARNING]${NC} Service '${item}' is ENABLED but not running"
            FOUND_SERVICES+=("$item")
        fi
    fi
done

echo ""
echo -e "${BLUE}Package/Service Scan Summary:${NC}"
if [ ${#FOUND_PACKAGES[@]} -eq 0 ] && [ ${#FOUND_SERVICES[@]} -eq 0 ]; then
    echo -e "${GREEN}✓ No suspicious packages or services found${NC}"
else
    if [ ${#FOUND_PACKAGES[@]} -gt 0 ]; then
        echo -e "${RED}Found ${#FOUND_PACKAGES[@]} suspicious package(s):${NC}"
        printf '%s\n' "${FOUND_PACKAGES[@]}" | sed 's/^/  - /'
    fi
    if [ ${#FOUND_SERVICES[@]} -gt 0 ]; then
        echo -e "${RED}Found ${#FOUND_SERVICES[@]} suspicious service(s):${NC}"
        printf '%s\n' "${FOUND_SERVICES[@]}" | sed 's/^/  - /'
    fi
fi
echo ""

# ============================================
# 2. Unauthorized File Scan
# ============================================
echo -e "${BLUE}[2] Scanning for unauthorized files...${NC}"
echo -e "${YELLOW}This may take several minutes...${NC}"
echo ""

UNAUTH_FILES=$(find / -path /usr/share -prune -o -type f \( \
    -iname "*.mp3" -o -iname "*.mp4" -o -iname "*.avi" -o -iname "*.mkv" \
    -o -iname "*.wav" -o -iname "*.ogg" -o -iname "*.flac" \
    -o -iname "*.zip" -o -iname "*.rar" -o -iname "*.7z" -o -iname "*.py" \
    -o -iname "*.png" -o -iname "*.jpg" -o -iname "*.jpeg" -o -iname "*.gif" \
\) -print 2>/dev/null)

FILE_COUNT=$(echo "$UNAUTH_FILES" | grep -c '^' 2>/dev/null)

echo -e "${BLUE}Unauthorized File Scan Summary:${NC}"
if [ -z "$UNAUTH_FILES" ] || [ "$FILE_COUNT" -eq 0 ]; then
    echo -e "${GREEN}✓ No unauthorized files found${NC}"
else
    echo -e "${RED}Found ${FILE_COUNT} unauthorized file(s):${NC}"
    echo "$UNAUTH_FILES" | head -20
    if [ "$FILE_COUNT" -gt 20 ]; then
        echo -e "${YELLOW}... and $((FILE_COUNT - 20)) more files${NC}"
    fi
fi
echo ""

# ============================================
# 3. SUID/SGID/Sticky Bit Scan
# ============================================
echo -e "${BLUE}[3] Scanning for SUID/SGID/Sticky bit files...${NC}"
echo -e "${YELLOW}This may take several minutes...${NC}"
echo ""

# Find SUID files (chmod 4000)
echo -e "Scanning for SUID files..."
SUID_FILES=$(find / -type f -perm -4000 2>/dev/null)

# Find SGID files (chmod 2000)
echo -e "Scanning for SGID files..."
SGID_FILES=$(find / -type f -perm -2000 2>/dev/null)

# Find Sticky bit files (chmod 1000)
echo -e "Scanning for Sticky bit files..."
STICKY_FILES=$(find / -type f -perm -1000 2>/dev/null)

SUID_COUNT=$(echo "$SUID_FILES" | grep -c '^' 2>/dev/null)
SGID_COUNT=$(echo "$SGID_FILES" | grep -c '^' 2>/dev/null)
STICKY_COUNT=$(echo "$STICKY_FILES" | grep -c '^' 2>/dev/null)

echo ""
echo -e "${BLUE}SUID/SGID/Sticky Bit Scan Summary:${NC}"

# SUID Results
if [ -z "$SUID_FILES" ] || [ "$SUID_COUNT" -eq 0 ]; then
    echo -e "${GREEN}✓ No SUID files found${NC}"
else
    echo -e "${RED}Found ${SUID_COUNT} SUID file(s):${NC}"
    echo "$SUID_FILES" | while read -r file; do
        ls -lh "$file" 2>/dev/null | awk '{print "  " $1 " " $3 ":" $4 " " $9}'
    done
fi

echo ""

# SGID Results
if [ -z "$SGID_FILES" ] || [ "$SGID_COUNT" -eq 0 ]; then
    echo -e "${GREEN}✓ No SGID files found${NC}"
else
    echo -e "${RED}Found ${SGID_COUNT} SGID file(s):${NC}"
    echo "$SGID_FILES" | while read -r file; do
        ls -lh "$file" 2>/dev/null | awk '{print "  " $1 " " $3 ":" $4 " " $9}'
    done
fi

echo ""

# Sticky Bit Results
if [ -z "$STICKY_FILES" ] || [ "$STICKY_COUNT" -eq 0 ]; then
    echo -e "${GREEN}✓ No Sticky bit files found${NC}"
else
    echo -e "${YELLOW}Found ${STICKY_COUNT} Sticky bit file(s):${NC}"
    echo "$STICKY_FILES" | while read -r file; do
        ls -lh "$file" 2>/dev/null | awk '{print "  " $1 " " $3 ":" $4 " " $9}'
    done
fi

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Scan Complete${NC}"
echo -e "${BLUE}========================================${NC}"
