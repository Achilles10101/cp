#!/bin/bash

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "ERROR: This script must be run as root"
    exit 1
fi

echo "=== User Audit Script ==="

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

# Create temporary user list file
USER_LIST_FILE="/tmp/user_categories_$$.txt"

cat > "$USER_LIST_FILE" << 'EOF'
# ADMINISTRATOR USERS
# List administrator usernames below administrators (one per line)
#administrators


# NORMAL USERS
# List normal user usernames below normalusers(one per line)
#normalusers


EOF

echo ""
echo "=== STEP 1: User Categorization ==="
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

echo "Administrators: ${ADMINS[*]:-none}"
echo "Normal users: ${NORMAL_USERS[*]:-none}"
echo ""

# Step 2: Check for unauthorized human users
echo "Scanning for unauthorized users"

# Get all human users (UID >= 1000, excluding nobody)
HUMAN_USERS=$(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd)
UNAUTHORIZED=()

for user in $HUMAN_USERS; do
    if [[ ! " ${ADMINS[@]} " =~ " ${user} " ]] && [[ ! " ${NORMAL_USERS[@]} " =~ " ${user} " ]]; then
        UNAUTHORIZED+=("$user")
    fi
done

if [ ${#UNAUTHORIZED[@]} -gt 0 ]; then
    echo "Found unauthorized users: ${UNAUTHORIZED[*]}"
    read -p "Remove these users? (y/n): " response
    if [[ "$response" == "y" ]]; then
        for user in "${UNAUTHORIZED[@]}"; do
            userdel -r "$user" 2>/dev/null
            if [ $? -eq 0 ]; then
                echo "✓ Removed $user"
            else
                echo "✗ Failed to remove $user"
            fi
        done
    fi
else
    echo "✓ No unauthorized users"
fi
echo ""

# Step 3: Verify administrator permissions
echo "Checking admin permissions"

for user in "${ADMINS[@]}"; do
    if id "$user" &>/dev/null; then
        groups_list=$(groups "$user" 2>/dev/null)
        
        if [[ "$groups_list" =~ sudo ]] || [[ "$groups_list" =~ admin ]] || [[ "$groups_list" =~ wheel ]]; then
            echo "✓ $user has admin access"
        else
            echo "✗ $user missing admin access"
            read -p "Add $user to sudo group? (y/n): " response
            if [[ "$response" == "y" ]]; then
                usermod -aG sudo "$user"
                echo "✓ Added to sudo group"
            fi
        fi
    else
        echo "✗ $user does not exist"
    fi
done
echo ""

# Step 4: Verify normal user permissions
echo "Checking user permissions"

for user in "${NORMAL_USERS[@]}"; do
    if id "$user" &>/dev/null; then
        groups_list=$(groups "$user" 2>/dev/null)
        
        if [[ "$groups_list" =~ sudo ]] || [[ "$groups_list" =~ admin ]] || [[ "$groups_list" =~ wheel ]] || [[ "$groups_list" =~ adm ]]; then
            echo "✗ $user has admin privileges"
            read -p "Remove from admin groups? (y/n): " response
            if [[ "$response" == "y" ]]; then
                gpasswd -d "$user" sudo 2>/dev/null
                gpasswd -d "$user" admin 2>/dev/null
                gpasswd -d "$user" wheel 2>/dev/null
                gpasswd -d "$user" adm 2>/dev/null
                echo "✓ Removed admin privileges"
            fi
        else
            echo "✓ $user is standard user"
        fi
    else
        echo "✗ $user does not exist"
    fi
done
echo ""

# Step 5: Check for UID 0 users
echo "UID 0 Check"

uid_zero_users=$(awk -F: '$3 == 0 {print $1}' /etc/passwd)

for user in $uid_zero_users; do
    if [ "$user" == "root" ]; then
        echo "✓ root (expected)"
    else
        echo "✗ CRITICAL: $user has UID 0"
        read -p "Change UID? (y/n): " response
        if [[ "$response" == "y" ]]; then
            new_uid=$(awk -F: '{print $3}' /etc/passwd | sort -n | tail -1)
            new_uid=$((new_uid + 1))
            usermod -u "$new_uid" "$user"
            echo "✓ Changed to UID $new_uid"
        fi
    fi
done
echo ""

# Step 6: Audit sudoers file
echo "Auditing sudoers"

# Check main sudoers file for NOPASSWD
nopasswd_main=$(grep -c "NOPASSWD" /etc/sudoers 2>/dev/null)
if [ "$nopasswd_main" -gt 0 ]; then
    echo "✗ Found $nopasswd_main NOPASSWD entries in /etc/sudoers"
    read -p "Review with visudo? (y/n): " response
    [[ "$response" == "y" ]] && visudo
fi

# Check main sudoers file for !authenticate
auth_main=$(grep -c "!authenticate" /etc/sudoers 2>/dev/null)
if [ "$auth_main" -gt 0 ]; then
    echo "✗ Found $auth_main !authenticate entries in /etc/sudoers"
    read -p "Review with visudo? (y/n): " response
    [[ "$response" == "y" ]] && visudo
fi

# Check sudoers.d files
if [ -d /etc/sudoers.d ]; then
    for file in /etc/sudoers.d/*; do
        [ -f "$file" ] || continue
        
        nopasswd_count=$(grep -c "NOPASSWD" "$file" 2>/dev/null)
        if [ "$nopasswd_count" -gt 0 ]; then
            echo "✗ Found $nopasswd_count NOPASSWD entries in $file"
            read -p "Edit $file with vim? (y/n): " response
            [[ "$response" == "y" ]] && vim "$file"
        fi
        
        auth_count=$(grep -c "!authenticate" "$file" 2>/dev/null)
        if [ "$auth_count" -gt 0 ]; then
            echo "✗ Found $auth_count !authenticate entries in $file"
            read -p "Edit $file with vim? (y/n): " response
            [[ "$response" == "y" ]] && vim "$file"
        fi
    done
fi

# Check for specific commands (excluding Defaults lines)
SUDOERS_CONTENT=$(mktemp)
cat /etc/sudoers > "$SUDOERS_CONTENT" 2>/dev/null

if [ -d /etc/sudoers.d ]; then
    for file in /etc/sudoers.d/*; do
        [ -f "$file" ] && cat "$file" >> "$SUDOERS_CONTENT" 2>/dev/null
    done
fi

cmd_lines=$(grep -E "^\s*[^#%].*=.*/" "$SUDOERS_CONTENT" | grep -v "ALL" | grep -v "^Defaults" 2>/dev/null)
cmd_count=$(echo "$cmd_lines" | grep -c . 2>/dev/null)
if [ "$cmd_count" -gt 0 ]; then
    echo "! Found $cmd_count specific command grants"
fi

rm -f "$SUDOERS_CONTENT"

# Summary for NOPASSWD/!authenticate
if [ "$nopasswd_main" -eq 0 ] && [ -z "$(find /etc/sudoers.d -type f -exec grep -l "NOPASSWD" {} \; 2>/dev/null)" ]; then
    echo "✓ No NOPASSWD entries"
fi

if [ "$auth_main" -eq 0 ] && [ -z "$(find /etc/sudoers.d -type f -exec grep -l "!authenticate" {} \; 2>/dev/null)" ]; then
    echo "✓ No !authenticate entries"
fi

echo ""

# Step 7: Audit administrative groups
echo "Administrative groups"

# Check sudo group
if getent group sudo >/dev/null; then
    sudo_members=$(getent group sudo | cut -d: -f4)
    
    if [ -n "$sudo_members" ]; then
        IFS=',' read -ra members <<< "$sudo_members"
        for member in "${members[@]}"; do
            if [[ " ${ADMINS[@]} " =~ " ${member} " ]]; then
                echo "✓ sudo: $member"
            else
                echo "✗ sudo: $member (unauthorized)"
                read -p "Remove? (y/n): " response
                if [[ "$response" == "y" ]]; then
                    gpasswd -d "$member" sudo
                    echo "✓ Removed"
                fi
            fi
        done
    fi
fi

# Check admin group
if getent group admin >/dev/null; then
    admin_members=$(getent group admin | cut -d: -f4)
    
    if [ -n "$admin_members" ]; then
        IFS=',' read -ra members <<< "$admin_members"
        for member in "${members[@]}"; do
            if [[ " ${ADMINS[@]} " =~ " ${member} " ]]; then
                echo "✓ admin: $member"
            else
                echo "✗ admin: $member (unauthorized)"
                read -p "Remove? (y/n): " response
                if [[ "$response" == "y" ]]; then
                    gpasswd -d "$member" admin
                    echo "✓ Removed"
                fi
            fi
        done
    fi
fi

# Check adm group
if getent group adm >/dev/null; then
    adm_members=$(getent group adm | cut -d: -f4)
    
    if [ -n "$adm_members" ]; then
        IFS=',' read -ra members <<< "$adm_members"
        for member in "${members[@]}"; do
            if [[ " ${ADMINS[@]} " =~ " ${member} " ]]; then
                echo "✓ adm: $member"
            else
                echo "✗ adm: $member (unauthorized)"
                read -p "Remove? (y/n): " response
                if [[ "$response" == "y" ]]; then
                    gpasswd -d "$member" adm
                    echo "✓ Removed"
                fi
            fi
        done
    fi
fi

# Cleanup
rm -f "$USER_LIST_FILE"

echo ""
echo "=== Script Complete ==="
