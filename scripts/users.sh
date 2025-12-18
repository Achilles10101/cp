#!/bin/bash

# Cybersecurity Hardening Script
# High verbosity logging for competition use

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to log messages
log() {
    echo -e "${2}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

# Function to log headers
log_header() {
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}========================================${NC}"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    log "ERROR: This script must be run as root" "$RED"
    exit 1
fi

log_header "LINUX SECURITY HARDENING SCRIPT"
log "Script started by user: $SUDO_USER" "$BLUE"

# Create temporary user list file
USER_LIST_FILE="/tmp/user_categories_$$.txt"

# Create template
cat > "$USER_LIST_FILE" << 'EOF'
# ADMINISTRATOR USERS
# List administrator usernames below (one per line)
# Example:
# john
# alice

#administrators


# NORMAL USERS
# List normal user usernames below (one per line)
# Example:
# bob
# charlie

#normalusers


EOF

log_header "STEP 1: USER CATEGORIZATION"
log "Opening nano editor for user categorization..." "$BLUE"
echo ""

# Open nano for user input
nano "$USER_LIST_FILE"

# Parse the user list
ADMINS=()
NORMAL_USERS=()
CURRENT_SECTION=""

while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    
    if [[ "$line" == "#administrators"* ]]; then
        CURRENT_SECTION="admin"
        continue
    elif [[ "$line" == "#normalusers"* ]]; then
        CURRENT_SECTION="normal"
        continue
    fi
    
    [[ "$line" =~ ^#.* ]] && continue
    
    if [[ "$CURRENT_SECTION" == "admin" ]]; then
        ADMINS+=("$line")
    elif [[ "$CURRENT_SECTION" == "normal" ]]; then
        NORMAL_USERS+=("$line")
    fi
done < "$USER_LIST_FILE"

log "Administrators: ${ADMINS[*]}" "$GREEN"
log "Normal users: ${NORMAL_USERS[*]}" "$GREEN"

# Step 2: Verify user permissions
log_header "STEP 2: VERIFYING USER PERMISSIONS"

for user in "${ADMINS[@]}"; do
    if id "$user" &>/dev/null; then
        groups_list=$(groups "$user" 2>/dev/null)
        
        if [[ "$groups_list" =~ sudo ]] || [[ "$groups_list" =~ admin ]] || [[ "$groups_list" =~ wheel ]]; then
            log "✓ Admin $user is in administrative group" "$GREEN"
        else
            log "✗ Admin $user is NOT in sudo/admin groups" "$RED"
            read -p "Add $user to sudo group? (y/n): " response
            if [[ "$response" == "y" ]]; then
                usermod -aG sudo "$user"
                log "✓ Added $user to sudo group" "$GREEN"
            fi
        fi
    else
        log "✗ Administrator $user does not exist" "$RED"
    fi
done

for user in "${NORMAL_USERS[@]}"; do
    if id "$user" &>/dev/null; then
        groups_list=$(groups "$user" 2>/dev/null)
        
        if [[ "$groups_list" =~ sudo ]] || [[ "$groups_list" =~ admin ]] || [[ "$groups_list" =~ wheel ]] || [[ "$groups_list" =~ adm ]]; then
            log "✗ Normal user $user is in administrative groups" "$RED"
            read -p "Remove $user from administrative groups? (y/n): " response
            if [[ "$response" == "y" ]]; then
                gpasswd -d "$user" sudo 2>/dev/null
                gpasswd -d "$user" admin 2>/dev/null
                gpasswd -d "$user" wheel 2>/dev/null
                gpasswd -d "$user" adm 2>/dev/null
                log "✓ Removed $user from administrative groups" "$GREEN"
            fi
        else
            log "✓ Normal user $user has no admin privileges" "$GREEN"
        fi
    else
        log "✗ Normal user $user does not exist" "$RED"
    fi
done

# Step 3: Check for UID 0 users
log_header "STEP 3: CHECKING FOR UNAUTHORIZED UID 0 USERS"

uid_zero_users=$(awk -F: '$3 == 0 {print $1}' /etc/passwd)

for user in $uid_zero_users; do
    if [ "$user" == "root" ]; then
        log "✓ $user (UID 0) - Expected" "$GREEN"
    else
        log "✗ CRITICAL: $user has UID 0!" "$RED"
        read -p "Change $user's UID to a non-zero value? (y/n): " response
        if [[ "$response" == "y" ]]; then
            new_uid=$(awk -F: '{print $3}' /etc/passwd | sort -n | tail -1)
            new_uid=$((new_uid + 1))
            usermod -u "$new_uid" "$user"
            log "✓ Changed $user's UID to $new_uid" "$GREEN"
        fi
    fi
done

# Step 4: Audit sudoers file
log_header "STEP 4: AUDITING SUDOERS CONFIGURATION"

SUDOERS_CONTENT=$(mktemp)
cat /etc/sudoers > "$SUDOERS_CONTENT" 2>/dev/null

if [ -d /etc/sudoers.d ]; then
    for file in /etc/sudoers.d/*; do
        [ -f "$file" ] && cat "$file" >> "$SUDOERS_CONTENT" 2>/dev/null
    done
fi

# Check for NOPASSWD
nopasswd_lines=$(grep -n "NOPASSWD" "$SUDOERS_CONTENT" 2>/dev/null)
if [ -n "$nopasswd_lines" ]; then
    log "✗ Found NOPASSWD entries:" "$RED"
    echo "$nopasswd_lines"
    read -p "Open sudoers with visudo to review? (y/n): " response
    [[ "$response" == "y" ]] && visudo
else
    log "✓ No NOPASSWD entries" "$GREEN"
fi

# Check for !authenticate
auth_lines=$(grep -n "!authenticate" "$SUDOERS_CONTENT" 2>/dev/null)
if [ -n "$auth_lines" ]; then
    log "✗ Found !authenticate entries:" "$RED"
    echo "$auth_lines"
    read -p "Open sudoers with visudo to review? (y/n): " response
    [[ "$response" == "y" ]] && visudo
else
    log "✓ No !authenticate entries" "$GREEN"
fi

# Check for group entries
group_lines=$(grep -n "^%" "$SUDOERS_CONTENT" 2>/dev/null)
if [ -n "$group_lines" ]; then
    log "! Found group entries:" "$YELLOW"
    echo "$group_lines"
fi

# Check for specific commands
cmd_lines=$(grep -E "^\s*[^#%].*=.*/" "$SUDOERS_CONTENT" | grep -v "ALL" 2>/dev/null)
if [ -n "$cmd_lines" ]; then
    log "! Found specific command grants:" "$YELLOW"
    echo "$cmd_lines"
fi

rm -f "$SUDOERS_CONTENT"

# Step 5: Audit administrative groups
log_header "STEP 5: AUDITING ADMINISTRATIVE GROUPS"

# Check sudo group
if getent group sudo >/dev/null; then
    log "Auditing 'sudo' group:" "$BLUE"
    sudo_members=$(getent group sudo | cut -d: -f4)
    
    if [ -n "$sudo_members" ]; then
        IFS=',' read -ra members <<< "$sudo_members"
        for member in "${members[@]}"; do
            if [[ " ${ADMINS[@]} " =~ " ${member} " ]]; then
                log "✓ $member (Authorized)" "$GREEN"
            else
                log "✗ $member is in sudo group but not authorized!" "$RED"
                read -p "Remove $member from sudo group? (y/n): " response
                if [[ "$response" == "y" ]]; then
                    gpasswd -d "$member" sudo
                    log "✓ Removed $member from sudo group" "$GREEN"
                fi
            fi
        done
    fi
fi

# Check admin group
if getent group admin >/dev/null; then
    log "Auditing 'admin' group:" "$BLUE"
    admin_members=$(getent group admin | cut -d: -f4)
    
    if [ -n "$admin_members" ]; then
        IFS=',' read -ra members <<< "$admin_members"
        for member in "${members[@]}"; do
            if [[ " ${ADMINS[@]} " =~ " ${member} " ]]; then
                log "✓ $member (Authorized)" "$GREEN"
            else
                log "✗ $member is in admin group but not authorized!" "$RED"
                read -p "Remove $member from admin group? (y/n): " response
                if [[ "$response" == "y" ]]; then
                    gpasswd -d "$member" admin
                    log "✓ Removed $member from admin group" "$GREEN"
                fi
            fi
        done
    fi
fi

# Check adm group
if getent group adm >/dev/null; then
    log "Auditing 'adm' group:" "$BLUE"
    adm_members=$(getent group adm | cut -d: -f4)
    
    if [ -n "$adm_members" ]; then
        IFS=',' read -ra members <<< "$adm_members"
        for member in "${members[@]}"; do
            if [[ " ${ADMINS[@]} " =~ " ${member} " ]]; then
                log "✓ $member (Authorized)" "$GREEN"
            else
                log "✗ $member is in adm group but not authorized!" "$RED"
                read -p "Remove $member from adm group? (y/n): " response
                if [[ "$response" == "y" ]]; then
                    gpasswd -d "$member" adm
                    log "✓ Removed $member from adm group" "$GREEN"
                fi
            fi
        done
    fi
fi

# Cleanup
rm -f "$USER_LIST_FILE"

log_header "USER HARDENING SCRIPT COMPLETED"
echo ""
echo -e "${GREEN}Users checks complete!${NC}"
