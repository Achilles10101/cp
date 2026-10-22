#!/bin/bash

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "ERROR: This script must be run as root"
    exit 1
fi

echo "=== User Audit Script ==="

# Output helpers used by the password-aging step (they were called but never defined)
ok()  { echo "✓ $*"; }
err() { echo "✗ $*"; }

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

# Step 2b: Check for suspicious system users (UID < 1000)
echo "Checking for suspicious system users with unexpected home directories"

SUSPICIOUS_SYSTEM_USERS=()

while IFS=: read -r username _ uid gid _ home shell; do
    # Skip standard system accounts (UID < 1000); root is expected (UID 0 duplicates are handled in the UID 0 check)
    if (( uid < 1000 )) && [[ "$username" != "root" ]]; then
        # Check if home directory exists and is not a standard system path
        if [[ -d "$home" ]]; then
            # Flag if home is in /home, /root, /tmp, or other user-like paths
            if [[ "$home" =~ ^/home/ ]] || [[ "$home" =~ ^/root$ ]] || [[ "$home" =~ ^/tmp/ ]] || [[ "$home" =~ ^/var/tmp/ ]]; then
                SUSPICIOUS_SYSTEM_USERS+=("$username:$uid:$home")
            fi
        fi
        
        # Flag if shell is not a nologin or false shell (indicates login capability)
        if [[ "$shell" != *"nologin"* ]] && [[ "$shell" != *"false"* ]] && [[ "$shell" != "/bin/sync" ]]; then
            # Only flag if we haven't already flagged this user
            if [[ ! " ${SUSPICIOUS_SYSTEM_USERS[*]} " =~ " $username: " ]]; then
                SUSPICIOUS_SYSTEM_USERS+=("$username:$uid:interactive_shell:$shell")
            fi
        fi
    fi
done < /etc/passwd

if [ ${#SUSPICIOUS_SYSTEM_USERS[@]} -gt 0 ]; then
    echo "✗ Found suspicious system users:"
    for entry in "${SUSPICIOUS_SYSTEM_USERS[@]}"; do
        echo "  - $entry"
    done
    read -p "Review these users manually (press Enter to continue): " 
else
    echo "✓ No suspicious system users detected"
fi
echo ""

# Step 3: Verify administrator permissions
echo "Checking admin permissions"

for user in "${ADMINS[@]}"; do
    if id "$user" &>/dev/null; then
        # exact group names - "admin" used to match "lpadmin" (Mint/Ubuntu desktop default group)
        if id -nG "$user" 2>/dev/null | tr ' ' '\n' | grep -qxE 'sudo|admin|wheel'; then
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
        if id -nG "$user" 2>/dev/null | tr ' ' '\n' | grep -qxE 'sudo|admin|wheel|adm'; then
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
        echo "✗ CRITICAL: $user has UID 0 (a second root account)"
        # usermod/userdel refuse here ("user is currently used by process 1"): UID 0 always has processes.
        BK="/root/cp-backups/uid0_$(date +%Y%m%d_%H%M%S)"; mkdir -p "$BK"
        read -p "Delete account $user (recommended unless the README names it)? (y/n): " response
        if [[ "$response" == "y" ]]; then
            cp -a /etc/passwd /etc/shadow /etc/group /etc/gshadow "$BK/"
            sed -i "/^${user}:/d" /etc/passwd /etc/shadow
            pwck -r >/dev/null 2>&1
            if getent passwd "$user" >/dev/null; then echo "✗ $user still exists - remove its line from /etc/passwd by hand"; else echo "✓ Deleted $user (backup: $BK)"; fi
        else
            read -p "Give $user a normal UID instead? (y/n): " response
            if [[ "$response" == "y" ]]; then
                cp -a /etc/passwd "$BK/"
                new_uid=1500; while getent passwd "$new_uid" >/dev/null; do new_uid=$((new_uid + 1)); done
                sed -i -E "s/^(${user}:[^:]*:)0:/\1${new_uid}:/" /etc/passwd
                [ "$(id -u "$user" 2>/dev/null)" = "$new_uid" ] && echo "✓ Changed $user to UID $new_uid" || echo "✗ Could not change the UID of $user - fix /etc/passwd by hand"
            fi
        fi
    fi
done
echo ""

# Step 6: Audit sudoers file
echo "Auditing sudoers"

SUDOERS_CONTENT=$(mktemp)
cat /etc/sudoers > "$SUDOERS_CONTENT" 2>/dev/null

if [ -d /etc/sudoers.d ]; then
    for file in /etc/sudoers.d/*; do
        [ -f "$file" ] && cat "$file" >> "$SUDOERS_CONTENT" 2>/dev/null
    done
fi

# Check for NOPASSWD / !authenticate - per file, because plain "visudo" only opens /etc/sudoers.
# Linux Mint ships /etc/sudoers.d/mintupdate with 3 NOPASSWD lines for its own update helpers - those are stock.
MINT_STOCK='^[[:space:]]*ALL[[:space:]]+ALL[[:space:]]*=[[:space:]]*NOPASSWD:[[:space:]]*/usr/(bin/mint-refresh-cache|lib/linuxmint/mintUpdate/(synaptic-workaround\.py|dpkg_lock_check\.sh))[[:space:]]*$'
SUDO_HIT_FILES=()
for f in /etc/sudoers /etc/sudoers.d/*; do
    [ -f "$f" ] || continue
    hits="$(grep -nE '^[^#]*(NOPASSWD|!authenticate)' "$f" 2>/dev/null)"
    [ -n "$hits" ] || continue
    real="$(echo "$hits" | cut -d: -f2- | grep -vE "$MINT_STOCK")"
    if [ -z "$real" ]; then
        echo "  (stock Linux Mint NOPASSWD lines in $f - leave them)"
        continue
    fi
    echo "✗ $f:"
    echo "$hits" | grep -vE ":${MINT_STOCK#^}" | sed 's/^/    line /'
    SUDO_HIT_FILES+=("$f")
done
if [ ${#SUDO_HIT_FILES[@]} -eq 0 ]; then
    echo "✓ No NOPASSWD / !authenticate entries (other than Mint stock)"
else
    for f in "${SUDO_HIT_FILES[@]}"; do
        read -p "Open $f in visudo to remove them? (y/n): " response
        [[ "$response" == "y" ]] || continue
        if [ "$f" = /etc/sudoers ]; then visudo; else visudo -f "$f"; fi
    done
    for f in "${SUDO_HIT_FILES[@]}"; do
        grep -qE '^[^#]*(NOPASSWD|!authenticate)' "$f" 2>/dev/null && grep -nE '^[^#]*(NOPASSWD|!authenticate)' "$f" | grep -vqE ":${MINT_STOCK#^}" && echo "✗ still present in $f"
    done
fi

# Check for specific commands (excluding Defaults lines)
cmd_lines=$(grep -E "^\s*[^#%].*=.*/" "$SUDOERS_CONTENT" | grep -v "ALL" | grep -v "^Defaults" 2>/dev/null)
cmd_count=$(echo "$cmd_lines" | grep -c . 2>/dev/null)
if [ "$cmd_count" -gt 0 ]; then
    echo "! Found $cmd_count specific command grants"
fi
# Output sudoers file for further examination
echo "Full sudoers output, review:"
echo ""
cat "$SUDOERS_CONTENT"
rm -f "$SUDOERS_CONTENT"
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
            if (( $(id -u "$member" 2>/dev/null || echo 1000) < 1000 )); then
                echo "✓ adm: $member (system account - stock, e.g. syslog needs adm to write logs)"
            elif [[ " ${ADMINS[@]} " =~ " ${member} " ]]; then
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

# Empty passwords: anyone can log in as these users
echo ""
echo "Checking for empty passwords"
EMPTY_PW=$(awk -F: '$2 == "" {print $1}' /etc/shadow)
if [ -n "$EMPTY_PW" ]; then
    for u in $EMPTY_PW; do
        echo "✗ $u has an EMPTY password"
        read -p "Set a password for $u now (you type it; write it down)? (y/n): " response
        if [[ "$response" == "y" ]]; then
            passwd "$u" && echo "✓ Password set for $u" || echo "✗ passwd failed for $u"
        else
            read -p "Lock $u instead (passwd -l)? (y/n): " response
            [[ "$response" == "y" ]] && passwd -l "$u" >/dev/null && echo "✓ Locked $u"
        fi
    done
else
    echo "✓ No empty passwords"
fi

# Cleanup
rm -f "$USER_LIST_FILE"

# Password aging policy
echo "Applying password aging policy and forcing all users to change password on next logon..."

current_user="${SUDO_USER:-$(logname 2>/dev/null)}"
if [ -z "$current_user" ] || [ "$current_user" = root ]; then
    luid="$(cat /proc/self/loginuid 2>/dev/null)"
    [ -n "$luid" ] && [ "$luid" != 4294967295 ] && current_user="$(getent passwd "$luid" | cut -d: -f1)"
fi
echo "Your account (excluded from forced password change): ${current_user:-UNKNOWN}"

# Get all regular users except the current user
users=()
while IFS=: read -r username _ uid _ _ _ shell; do
    if (( uid >= 1000 && uid < 60000 )) && [[ $username != "$current_user" ]] && [[ $shell != *nologin* && $shell != *false ]]; then
        users+=("$username")
    fi
done < /etc/passwd

aging_success=true

if (( ${#users[@]} == 0 )); then
    echo "  (no other login users to apply it to)"
elif command -v chage &>/dev/null; then
    for u in "${users[@]}"; do
        chage -M 30 -m 7 -W 14 "$u" &>/dev/null || aging_success=false
        sudo passwd -e "$u" &>/dev/null || aging_success=false
    done
else
    aging_success=false
fi

if (( ${#users[@]} )); then
    $aging_success && ok "Password aging policy applied and ${#users[@]} user(s) forced to change password on next logon" || err "Password aging update or password change force failed."
fi

# Set home directory permissions
getent passwd | awk -F: '$3 >= 1000 && $3 != 65534 {print $1 ":" $6}' | while IFS=: read -r user home; do
    if [[ -d "$home" ]]; then
        chmod 0750 "$home"
        chown "$user" "$home"/
        echo "Set secure home on $home (user: $user)"
    else
        echo "Skipping $user — home directory missing: $home"
    fi
done

echo ""
echo "=== Script Complete ==="
