#!/bin/bash

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "ERROR: This script must be run as root"
    exit 1
fi

echo "Starting script"

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

# Create temporary user list file
USER_LIST_FILE="/tmp/user_categories_$$.txt"

cat > "$USER_LIST_FILE" << 'EOF'
# ADMINISTRATOR USERS
# List administrator usernames below (one per line)

#administrators


# NORMAL USERS
# List normal user usernames below (one per line)

#normalusers


EOF

echo ""
echo "STEP 1: USER CATEGORIZATION"
echo "Opening nano editor for user categorization..."
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

echo "Administrators: ${ADMINS[*]}"
echo "Normal users: ${NORMAL_USERS[*]}"

# Step 2: Verify user permissions
echo "Verifying user permissions"

for user in "${ADMINS[@]}"; do
    if id "$user" &>/dev/null; then
        groups_list=$(groups "$user" 2>/dev/null)
        
        if [[ "$groups_list" =~ sudo ]] || [[ "$groups_list" =~ admin ]] || [[ "$groups_list" =~ wheel ]]; then
            echo "✓ Admin $user is in administrative group"
        else
            echo "✗ Admin $user is NOT in sudo/admin groups"
            read -p "Add $user to sudo group? (y/n): " response
            if [[ "$response" == "y" ]]; then
                usermod -aG sudo "$user"
                echo "✓ Added $user to sudo group"
            fi
        fi
    else
        echo "✗ Administrator $user does not exist"
    fi
done

for user in "${NORMAL_USERS[@]}"; do
    if id "$user" &>/dev/null; then
        groups_list=$(groups "$user" 2>/dev/null)
        
        if [[ "$groups_list" =~ sudo ]] || [[ "$groups_list" =~ admin ]] || [[ "$groups_list" =~ wheel ]] || [[ "$groups_list" =~ adm ]]; then
            echo "✗ Normal user $user is in administrative groups"
            read -p "Remove $user from administrative groups? (y/n): " response
            if [[ "$response" == "y" ]]; then
                gpasswd -d "$user" sudo 2>/dev/null
                gpasswd -d "$user" admin 2>/dev/null
                gpasswd -d "$user" wheel 2>/dev/null
                gpasswd -d "$user" adm 2>/dev/null
                echo "✓ Removed $user from administrative groups"
            fi
        else
            echo "✓ Normal user $user has no admin privileges"
        fi
    else
        echo "✗ Normal user $user does not exist"
    fi
done

# Step 3: Check for UID 0 users
echo "Checking for unauthorized UID 0 users"

uid_zero_users=$(awk -F: '$3 == 0 {print $1}' /etc/passwd)

for user in $uid_zero_users; do
    if [ "$user" == "root" ]; then
        echo "✓ $user (UID 0) - Expected"
    else
        echo "✗ CRITICAL: $user has UID 0!"
        read -p "Change $user's UID to a non-zero value? (y/n): " response
        if [[ "$response" == "y" ]]; then
            new_uid=$(awk -F: '{print $3}' /etc/passwd | sort -n | tail -1)
            new_uid=$((new_uid + 1))
            usermod -u "$new_uid" "$user"
            echo "✓ Changed $user's UID to $new_uid"
        fi
    fi
done

# Step 4: Audit sudoers file

echo "Auditing sudoers file"

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
    echo "✗ Found NOPASSWD entries:"
    echo "$nopasswd_lines"
    read -p "Open sudoers with visudo to review? (y/n): " response
    [[ "$response" == "y" ]] && visudo
else
    echo "✓ No NOPASSWD entries"
fi

# Check for !authenticate
auth_lines=$(grep -n "!authenticate" "$SUDOERS_CONTENT" 2>/dev/null)
if [ -n "$auth_lines" ]; then
    echo "✗ Found !authenticate entries:"
    echo "$auth_lines"
    read -p "Open sudoers with visudo to review? (y/n): " response
    [[ "$response" == "y" ]] && visudo
else
    echo "✓ No !authenticate entries"
fi

# Check for group entries
group_lines=$(grep -n "^%" "$SUDOERS_CONTENT" 2>/dev/null)
if [ -n "$group_lines" ]; then
    echo "! Found group entries:"
    echo "$group_lines"
fi

# Check for specific commands
cmd_lines=$(grep -E "^\s*[^#%].*=.*/" "$SUDOERS_CONTENT" | grep -v "ALL" 2>/dev/null)
if [ -n "$cmd_lines" ]; then
    echo "! Found specific command grants:"
    echo "$cmd_lines"
fi

rm -f "$SUDOERS_CONTENT"

# Step 5: Audit administrative groups
echo "Auditing administrative groups"

# Check sudo group
if getent group sudo >/dev/null; then
    echo "Auditing 'sudo' group:"
    sudo_members=$(getent group sudo | cut -d: -f4)
    
    if [ -n "$sudo_members" ]; then
        IFS=',' read -ra members <<< "$sudo_members"
        for member in "${members[@]}"; do
            if [[ " ${ADMINS[@]} " =~ " ${member} " ]]; then
                echo "✓ $member (Authorized)"
            else
                echo "✗ $member is in sudo group but not authorized!"
                read -p "Remove $member from sudo group? (y/n): " response
                if [[ "$response" == "y" ]]; then
                    gpasswd -d "$member" sudo
                    echo "✓ Removed $member from sudo group"
                fi
            fi
        done
    fi
fi

# Check admin group
if getent group admin >/dev/null; then
    echo "Auditing 'admin' group:"
    admin_members=$(getent group admin | cut -d: -f4)
    
    if [ -n "$admin_members" ]; then
        IFS=',' read -ra members <<< "$admin_members"
        for member in "${members[@]}"; do
            if [[ " ${ADMINS[@]} " =~ " ${member} " ]]; then
                echo "✓ $member (Authorized)"
            else
                echo "✗ $member is in admin group but not authorized!"
                read -p "Remove $member from admin group? (y/n): " response
                if [[ "$response" == "y" ]]; then
                    gpasswd -d "$member" admin
                    echo "✓ Removed $member from admin group"
                fi
            fi
        done
    fi
fi

# Check adm group
if getent group adm >/dev/null; then
    echo "Auditing 'adm' group:"
    adm_members=$(getent group adm | cut -d: -f4)
    
    if [ -n "$adm_members" ]; then
        IFS=',' read -ra members <<< "$adm_members"
        for member in "${members[@]}"; do
            if [[ " ${ADMINS[@]} " =~ " ${member} " ]]; then
                echo "✓ $member (Authorized)"
            else
                echo "✗ $member is in adm group but not authorized!"
                read -p "Remove $member from adm group? (y/n): " response
                if [[ "$response" == "y" ]]; then
                    gpasswd -d "$member" adm
                    echo "✓ Removed $member from adm group"
                fi
            fi
        done
    fi
fi

# Cleanup
rm -f "$USER_LIST_FILE"

echo "Script completed"
