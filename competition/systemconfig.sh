#!/bin/bash
# Must be run as root
# System hardening. Research-doc items added: SYS1-SYS10, G1 (in-place sysctl edits).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=cp-common.sh
source "$SCRIPT_DIR/cp-common.sh" 2>/dev/null || { echo "ERROR: cp-common.sh not found next to systemconfig.sh"; exit 1; }

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

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root, exiting"
    exit 1
fi

echo "Starting system hardening..."
echo ""

# SYS10 (runs first): a planted /etc/ld.so.preload hooks EVERY command this script runs
if [ -s /etc/ld.so.preload ]; then
    cp_warn "/etc/ld.so.preload is set (LD_PRELOAD rootkit?):"; sed 's/^/        /' /etc/ld.so.preload
    PRELOAD_LIBS="$(grep -vE '^[[:space:]]*(#|$)' /etc/ld.so.preload | tr ' :' '\n\n' | grep -v '^$')"
    if cp_ask "Empty /etc/ld.so.preload?" y; then
        cp_backup /etc/ld.so.preload; : > /etc/ld.so.preload; cp_ok "Emptied"
        # the scored item is usually the rootkit library itself (e.g. PathExistsNot /usr/src/evil_rabbit.so)
        for lib in $PRELOAD_LIBS; do
            [ -f "$lib" ] || continue
            dpkg-query -S "$lib" >/dev/null 2>&1 && { cp_warn "$lib belongs to a package - not deleting"; continue; }
            cp_ask "Delete the preloaded library $lib ?" y && { cp_backup "$lib"; rm -f "$lib"; cp_ok "Deleted $lib"; }
        done
    fi
fi

# Enable UFW

sudo ufw enable
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw status verbose
sudo ufw logging on
sudo ufw logging high

# Prompt for UFW ports

while [ -t 0 ]; do
    echo "Current allowed firewall rules:"
    sudo ufw status | grep ALLOW || echo "No ALLOW rules found."

    read -r -p "Open or Close a port? [o/c/n]: " action
    case "$action" in
        o)
            read -r -p "Port to allow (number only): " port
            sudo ufw allow "${port}/tcp"
            ;;
        c)
            echo "Numbered rules:"
            sudo ufw status numbered
            read -r -p "Rule number to delete: " num
            sudo ufw delete "$num"
            ;;
        n)
            break
            ;;
        *)
            echo "Invalid choice."
            ;;
    esac
done
sudo ufw reload

#Applying APT configuration
echo "Applying APT configuration"

sudo apt install unattended-upgrades
sudo dpkg-reconfigure unattended-upgrades

cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
cat >/etc/apt/apt.conf.d/50auto-upgrades <<'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id} stable";
    "${distro_id} ${distro_codename}-security";
    "${distro_id} ${distro_codename}-updates";
};
EOF


# Linux Mint: Update Manager > Preferences > Automation is what Mint images score
# (1984: PathExists /var/lib/linuxmint/mintupdate-automatic-upgrades-enabled). Same as the GUI toggles.
if command -v mintupdate-automation >/dev/null 2>&1; then
    if cp_ask "Linux Mint: turn on Update Manager automatic updates + automatic removal of old kernels (same as the GUI Automation tab)?" y; then
        mintupdate-automation upgrade enable >/dev/null 2>&1
        mintupdate-automation autoremove enable >/dev/null 2>&1
        [ -e /var/lib/linuxmint/mintupdate-automatic-upgrades-enabled ] && cp_ok "Mint automatic updates enabled" || cp_warn "Mint automation did not enable - use Update Manager > Edit > Preferences > Automation"
    fi
    if command -v gsettings >/dev/null 2>&1 && [ -n "${SUDO_USER:-}" ]; then
        sudo -u "$SUDO_USER" dbus-launch gsettings set com.linuxmint.updates refresh-schedule-enabled true >/dev/null 2>&1 \
            && cp_ok "Update Manager: refresh the list of updates automatically (for $SUDO_USER)"
    fi
fi

# Disable guest user
if systemctl list-unit-files | grep -q "lightdm.service"; then
    echo "LightDM detected. Configuring..."

    LIGHTDM_CONF="/etc/lightdm/lightdm.conf"

    # Mint ships its settings in lightdm.conf.d and may have no lightdm.conf at all -
    # create it instead of aborting the whole script (the old version exited here).
    if [ ! -f "$LIGHTDM_CONF" ]; then
        echo "LightDM config file not found at $LIGHTDM_CONF - creating it"
        mkdir -p /etc/lightdm
        printf '[Seat:*]\n' > "$LIGHTDM_CONF"
    fi
    grep -q '^\[Seat:\*\]' "$LIGHTDM_CONF" || printf '\n[Seat:*]\n' >> "$LIGHTDM_CONF"

    # backup goes to /root/cp-backups: a lightdm.conf.backup next to it kept the planted
    # autologin/guest lines inside /etc/lightdm, where a directory-wide check still finds them
    cp_backup "$LIGHTDM_CONF"
    [ -f "${LIGHTDM_CONF}.backup" ] && { cp_backup "${LIGHTDM_CONF}.backup"; rm -f "${LIGHTDM_CONF}.backup"; }

    # LightDM (GKeyFile) also accepts "key = value" - match optional spaces
    sed -i -E '/^[[:space:]]*(allow-guest|greeter-hide-users|greeter-allow-guest|greeter-show-manual-login|autologin-guest|autologin-user|autologin-user-timeout|autologin-session|xserver-allow-tcp)[[:space:]]*=/d' "$LIGHTDM_CONF"

    sed -i '/^\[Seat:\*\]/a \
allow-guest=false\
greeter-hide-users=true\
greeter-allow-guest=false\
greeter-show-manual-login=true\
autologin-guest=false\
autologin-user=NONE\
xserver-allow-tcp=false' "$LIGHTDM_CONF"

    # SYS6 / B3: drop-in files override lightdm.conf - remove insecure lines there too
    for f in /etc/lightdm/lightdm.conf.d/*.conf /usr/share/lightdm/lightdm.conf.d/*.conf; do
        [ -f "$f" ] || continue
        LDM_BAD='^[[:space:]]*((allow-guest|greeter-allow-guest|autologin-guest|xserver-allow-tcp)[[:space:]]*=[[:space:]]*true|autologin-user[[:space:]]*=[[:space:]]*([^N[:space:]].*|N[^O].*|)|autologin-user-timeout[[:space:]]*=.*)[[:space:]]*$'
        if grep -qE "$LDM_BAD" "$f"; then
            cp_backup "$f"
            sed -i -E "/$LDM_BAD/d" "$f"
            echo "  Removed guest/autologin/TCP settings from drop-in $f"
        fi
    done

    echo "LightDM configuration updated successfully"
else
    echo "LightDM not detected"
fi

# SYS6: GDM3 (Ubuntu desktop)
GDM_CONF=""
for f in /etc/gdm3/custom.conf /etc/gdm/custom.conf; do [ -f "$f" ] && GDM_CONF="$f" && break; done
if [ -n "$GDM_CONF" ]; then
    echo "GDM detected ($GDM_CONF). Configuring..."
    cp_backup "$GDM_CONF"
    cp_set "$GDM_CONF" AutomaticLoginEnable False eq 0 0 daemon
    cp_unset "$GDM_CONF" AutomaticLogin eq 0 0 daemon
    cp_set "$GDM_CONF" TimedLoginEnable false eq 0 0 daemon
    cp_unset "$GDM_CONF" User eq 0 0 daemon
    cp_unset "$GDM_CONF" Group eq 0 0 daemon
    cp_set "$GDM_CONF" DisallowTCP true eq 0 0 security
    cp_set "$GDM_CONF" AllowRoot false eq 0 0 security
    cp_ok "GDM: no automatic login, no custom User/Group, DisallowTCP=true, AllowRoot=false"
fi


# Configure UMASK
echo "[1/4] Configuring UMASK..."

# Backup and modify login.defs
if [ -f /etc/login.defs ]; then
    cp /etc/login.defs /etc/login.defs.backup.$(date +%Y%m%d-%H%M%S)

    if grep -q "^UMASK" /etc/login.defs; then
        sed -i 's/^UMASK.*/UMASK\t\t027/' /etc/login.defs
    else
        echo "UMASK     027" >> /etc/login.defs
    fi
    # SYS3: hashing algorithm and login retries (scored in practice images)
    cp_set /etc/login.defs ENCRYPT_METHOD SHA512 space
    cp_set /etc/login.defs LOGIN_RETRIES 3 space
    # Checklist password aging, automated. MAX 30 (not 90): Aperture's check only accepts 1-30,
    # and 30 also passes any "<= 90" style check. MIN 7 (>= 5 required there), WARN 14.
    cp_set /etc/login.defs PASS_MAX_DAYS 30 space
    cp_set /etc/login.defs PASS_MIN_DAYS 7 space
    cp_set /etc/login.defs PASS_WARN_AGE 14 space
else
    echo "  ERROR: /etc/login.defs not found"
    exit 1
fi

# Backup and modify /etc/profile
if [ -f /etc/profile ]; then
    cp /etc/profile /etc/profile.backup.$(date +%Y%m%d-%H%M%S)

    if ! grep -q "^umask 027" /etc/profile; then
        sed -i '1i umask 027' /etc/profile
    fi
else
    echo "  ERROR: /etc/profile not found"
    exit 1
fi

echo "  ✓ UMASK configured"

# Configure sysctl
echo "[2/4] Configuring kernel parameters..."

# Backup sysctl.conf
if [ -f /etc/sysctl.conf ]; then
    cp /etc/sysctl.conf /etc/sysctl.conf.backup.$(date +%Y%m%d-%H%M%S)
else
    touch /etc/sysctl.conf
fi

# SYS1 / G1: every key is set IN PLACE in /etc/sysctl.conf (a planted "ip_forward=1" line is
# replaced, not left above our value) and removed from /etc/sysctl.d/*.conf, where a later
# file would silently override it.
SYSCTL_SETTINGS=(
    # Security Hardening Parameters (original list)
    "fs.file-max = 65535"
    "fs.suid_dumpable = 0"
    "kernel.core_uses_pid = 1"
    "kernel.dmesg_restrict = 1"
    "kernel.sysrq = 0"
    "kernel.randomize_va_space = 2"
    "kernel.pid_max = 65536"
    "net.core.rmem_max = 8388608"
    "net.core.wmem_max = 8388608"
    "net.core.netdev_max_backlog = 5000"
    "net.ipv4.tcp_rmem = 10240 87380 12582912"
    "net.ipv4.tcp_wmem = 10240 87380 12582912"
    "net.ipv4.tcp_window_scaling = 1"
    "net.ipv4.conf.all.accept_redirects = 0"
    "net.ipv4.conf.all.accept_source_route = 0"
    "net.ipv4.conf.all.log_martians = 1"
    "net.ipv4.conf.all.secure_redirects = 0"
    "net.ipv4.conf.all.send_redirects = 0"
    "net.ipv4.conf.default.accept_redirects = 0"
    "net.ipv4.conf.default.accept_source_route = 0"
    "net.ipv4.conf.default.log_martians = 1"
    "net.ipv4.conf.default.secure_redirects = 0"
    "net.ipv4.conf.default.send_redirects = 0"
    "net.ipv4.icmp_echo_ignore_all = 1"
    "net.ipv4.icmp_echo_ignore_broadcasts = 1"
    "net.ipv4.icmp_ignore_bogus_error_responses = 1"
    "net.ipv4.ip_forward = 0"
    "net.ipv4.ip_local_port_range = 2000 65000"
    "net.ipv4.tcp_max_syn_backlog = 2048"
    "net.ipv4.tcp_synack_retries = 2"
    "net.ipv4.tcp_syncookies = 1"
    "net.ipv4.tcp_syn_retries = 5"
    "net.ipv4.tcp_timestamps = 1"
    # SYS2: scored in practice images
    "net.ipv4.tcp_rfc1337 = 1"
    "net.ipv4.conf.all.rp_filter = 1"
    "net.ipv4.conf.default.rp_filter = 1"
    "kernel.kptr_restrict = 2"
    "kernel.kexec_load_disabled = 1"
    "dev.tty.ldisc_autoload = 0"
    "kernel.perf_event_paranoid = 3"
    "fs.protected_hardlinks = 1"
    "fs.protected_symlinks = 1"
    "kernel.yama.ptrace_scope = 1"
    # Does not exist on modern kernels (sysctl prints one harmless error), but Aperture Science scored it
    "kernel.exec-shield = 1"
)

apply_sysctl_list() {
    local kv k v f
    for kv in "$@"; do
        k="$(echo "${kv%%=*}" | xargs)"; v="$(echo "${kv#*=}" | xargs)"
        cp_set /etc/sysctl.conf "$k" "$v" eqs
        for f in /etc/sysctl.d/*.conf; do
            [ -f "$f" ] || continue
            [ "$(readlink -f "$f")" = "$(readlink -f /etc/sysctl.conf)" ] && continue
            # sysctl.conf is loaded as 99-sysctl.conf, so earlier package files cannot override it;
            # only planted (unowned) files and files sorting after 99-sysctl.conf can.
            if dpkg-query -S "$f" >/dev/null 2>&1 && [[ "$(basename "$f")" < "99-sysctl.conf" ]]; then continue; fi
            if [ -n "$(cp_get "$f" "$k")" ] && [ "$(cp_get "$f" "$k")" != "$v" ]; then
                cp_backup "$f"
                cp_warn "$f overrides $k = $(cp_get "$f" "$k") - removing it there"
                cp_unset "$f" "$k"
            fi
        done
    done
}
apply_sysctl_list "${SYSCTL_SETTINGS[@]}"

# Planted sysctl.d files that no package owns (B3) - show them
for f in /etc/sysctl.d/*.conf; do
    [ -f "$f" ] || continue
    [ -L "$f" ] && continue
    dpkg-query -S "$f" >/dev/null 2>&1 || { cp_warn "sysctl.d file not owned by any package: $f"; grep -vE '^[[:space:]]*(#|$)' "$f" | sed 's/^/        /'; }
done

echo "  ✓ Base parameters configured"

# IPv6 Configuration
echo "[3/4] IPv6 Configuration"
ipv6_choice=""
[ -t 0 ] && read -p "  Enable IPv6? (y/n): " ipv6_choice

if [[ "$ipv6_choice" =~ ^[Nn]$ ]]; then
    apply_sysctl_list \
        "net.ipv6.conf.all.disable_ipv6 = 1" \
        "net.ipv6.conf.default.disable_ipv6 = 1" \
        "net.ipv6.conf.lo.disable_ipv6 = 1"
    echo "  ✓ IPv6 disabled"
elif [[ "$ipv6_choice" =~ ^[Yy]$ ]]; then
    apply_sysctl_list \
        "net.ipv6.conf.all.disable_ipv6 = 0" \
        "net.ipv6.conf.default.disable_ipv6 = 0" \
        "net.ipv6.conf.default.router_solicitations = 0" \
        "net.ipv6.conf.default.accept_ra_rtr_pref = 0" \
        "net.ipv6.conf.default.accept_ra_pinfo = 0" \
        "net.ipv6.conf.default.accept_ra_defrtr = 0" \
        "net.ipv6.conf.default.autoconf = 0" \
        "net.ipv6.conf.default.dad_transmits = 0" \
        "net.ipv6.conf.default.max_addresses = 1"
    echo "  ✓ IPv6 hardened"
else
    echo "  ⚠ Invalid choice, skipping IPv6 configuration"
fi

# Apply sysctl changes
echo "[4/4] Applying changes..."
if sysctl --system > /dev/null 2>&1; then
    echo "  ✓ All parameters applied (sysctl --system: same order as at boot)"
else
    echo "  ⚠ Some parameters failed (see details below):"
    sysctl --system 2>&1 | grep -iE 'cannot|invalid|error|denied' || true
fi

# ====================================================================== SYS3 PAM / passwords ==
cp_hdr "SYS3 PAM and password quality"
if ! grep -qE '^[[:space:]]*auth[[:space:]]+requisite[[:space:]]+pam_deny\.so' /etc/pam.d/common-auth; then
    cp_warn "common-auth has no 'auth requisite pam_deny.so' - failed passwords may be accepted:"
    grep -vE '^[[:space:]]*(#|$)' /etc/pam.d/common-auth | sed 's/^/        /'
    if grep -qE '^[[:space:]]*auth[[:space:]]+requisite[[:space:]]+pam_permit\.so' /etc/pam.d/common-auth && cp_ask "Replace 'requisite pam_permit.so' with 'requisite pam_deny.so'?" y; then
        cp_backup /etc/pam.d/common-auth
        sed -i -E 's/^([[:space:]]*auth[[:space:]]+requisite[[:space:]]+)pam_permit\.so/\1pam_deny.so/' /etc/pam.d/common-auth
        cp_ok "pam_deny restored"
    fi
fi
for f in /etc/pam.d/common-auth /etc/pam.d/common-account /etc/pam.d/common-password /etc/pam.d/common-session /etc/pam.d/common-session-noninteractive /etc/pam.d/sshd /etc/pam.d/login /etc/pam.d/sudo /etc/pam.d/su; do
    [ -f "$f" ] || continue
    grep -nE '^[[:space:]]*[a-z]+[[:space:]].*pam_exec\.so' "$f" | while IFS= read -r l; do cp_warn "pam_exec line in $f (stock Ubuntu/Mint has none): $l"; done
    if grep -qE '^[[:space:]]*[a-z]+[[:space:]].*pam_exec\.so' "$f" && cp_ask "Remove the pam_exec line(s) from $f?" y; then
        cp_backup "$f"; sed -i -E '/^[[:space:]]*[a-z]+[[:space:]].*pam_exec\.so/d' "$f"; cp_ok "Removed pam_exec from $f"
    fi
done
grep -rlE '^[[:space:]]*[a-z]+[[:space:]].*pam_exec\.so' /etc/pam.d/ 2>/dev/null | while read -r f; do cp_warn "pam_exec still referenced in $f - review"; done
# Install pwquality FIRST: its postinst runs pam-auth-update, which writes a fresh pam_pwquality line
# (only "retry=3") - arguments added before the install never reached that line (Mint has no pwquality by default).
if ! dpkg -s libpam-pwquality >/dev/null 2>&1; then
    cp_ask "Install libpam-pwquality (needed for pwquality.conf rules)?" y && apt-get install -y libpam-pwquality >/dev/null 2>&1
fi
# Checklist step "add minlen=10 remember=5 to pam_unix" automated, plus the pam_pwquality arguments
# that a 1984-style check looks for on the common-password line itself.
CPW=/etc/pam.d/common-password
if [ -f "$CPW" ]; then
    cp_backup "$CPW"
    grep -qE '^[[:space:]]*password.*pam_unix\.so.*remember=' "$CPW" \
        && sed -i -E '/^[[:space:]]*password.*pam_unix\.so/ s/remember=[0-9]+/remember=5/' "$CPW" \
        || sed -i -E '/^[[:space:]]*password.*pam_unix\.so/ s/$/ remember=5/' "$CPW"
    grep -qE '^[[:space:]]*password.*pam_unix\.so.*minlen=' "$CPW" || sed -i -E '/^[[:space:]]*password.*pam_unix\.so/ s/$/ minlen=10/' "$CPW"
    for a in "dictcheck=1" "usercheck=1" "minlen=10" "ucredit=-1" "lcredit=-1" "dcredit=-1" "ocredit=-1"; do
        k="${a%%=*}"
        grep -qE "^[[:space:]]*password.*pam_pwquality\.so.*[[:space:]]${k}=" "$CPW" || sed -i -E "/^[[:space:]]*password.*pam_pwquality\.so/ s/\$/ ${a}/" "$CPW"
    done
    cp_ok "common-password: pam_unix remember=5 minlen=10; pam_pwquality dictcheck/usercheck/minlen/credits"
    grep -E '^[[:space:]]*password.*(pam_unix|pam_pwquality)' "$CPW" | sed 's/^/        /'
fi
if [ -f /etc/security/pwquality.conf ] || dpkg -s libpam-pwquality >/dev/null 2>&1; then
    cp_backup /etc/security/pwquality.conf
    for kv in "minlen=10" "ucredit=-1" "lcredit=-1" "dcredit=-1" "ocredit=-1" "dictcheck=1" "usercheck=1"; do
        cp_set /etc/security/pwquality.conf "${kv%%=*}" "${kv#*=}" eqs
    done
    cp_ok "pwquality.conf: minlen 10, 1 upper/lower/digit/other, dictcheck, usercheck"
fi

# ====================================================================== SYS4 sudo ==
cp_hdr "SYS4 sudo.conf / sudoers defaults"
SUDO_LIBS="$(ls /usr/libexec/sudo/libsudo_util.so* /usr/lib/sudo/libsudo_util.so* 2>/dev/null) $(command -v sudo)"
cp_backup /etc/sudo.conf
touch /etc/sudo.conf
for kv in "disable_coredump true" "probe_interfaces false" "developer_mode false"; do
    k="${kv%% *}"
    # only write settings this sudo version knows (unknown settings produce warnings)
    # shellcheck disable=SC2086
    grep -aq "$k" $SUDO_LIBS 2>/dev/null || { cp_info "sudo does not know '$k' - skipped"; continue; }
    sed -i -E "/^[[:space:]]*Set[[:space:]]+${k}[[:space:]]/d" /etc/sudo.conf
    echo "Set $kv" >> /etc/sudo.conf
done
cp_ok "sudo.conf: $(grep -E '^Set ' /etc/sudo.conf | tr '\n' ';')"
cp_backup /etc/sudoers /etc/sudoers.d
for f in /etc/sudoers /etc/sudoers.d/*; do
    [ -f "$f" ] || continue
    if grep -qE '^[[:space:]]*Defaults[[:space:]]+(!env_reset|env_keep[[:space:]]*\+?=[[:space:]]*"?PATH)' "$f"; then
        sed -i -E '/^[[:space:]]*Defaults[[:space:]]+(!env_reset|env_keep[[:space:]]*\+?=[[:space:]]*"?PATH"?)[[:space:]]*$/d' "$f"
        cp_ok "Removed insecure Defaults (!env_reset / env_keep PATH) from $f"
    fi
done
printf 'Defaults use_pty\nDefaults logfile="/var/log/sudo.log"\n' > /etc/sudoers.d/99-cp-hardening
chmod 440 /etc/sudoers.d/99-cp-hardening
if visudo -c >/dev/null 2>&1; then
    cp_ok "sudoers valid (use_pty, logfile=/var/log/sudo.log)"
else
    cp_err "visudo -c failed - restoring sudoers"; cp_restore /etc/sudoers /etc/sudoers.d; rm -f /etc/sudoers.d/99-cp-hardening
fi

# ====================================================================== SYS5 limits ==
cp_hdr "SYS5 limits.conf"
cp_backup /etc/security/limits.conf
sed -i -E '/^[[:space:]]*\*[[:space:]]+hard[[:space:]]+(core|nproc)[[:space:]]/d' /etc/security/limits.conf
printf '* hard core 0\n* hard nproc 2500\n' >> /etc/security/limits.conf
cp_ok "* hard core 0, * hard nproc 2500"

# ====================================================================== SYS7 required services ==
cp_hdr "SYS7 services that must be running"
command -v auditctl >/dev/null 2>&1 || { cp_ask "Install auditd?" y && apt-get install -y auditd >/dev/null 2>&1; }
if [ -f /etc/audit/auditd.conf ]; then cp_set /etc/audit/auditd.conf local_events yes eqs; fi
for s in apparmor auditd ufw unattended-upgrades; do
    systemctl enable --now "$s" >/dev/null 2>&1 && cp_ok "$s enabled and running" || cp_warn "could not enable $s"
done

# ====================================================================== SYS8 GRUB ==
cp_hdr "SYS8 GRUB"
for f in /boot/grub/grub.cfg /boot/grub2/grub.cfg; do
    [ -f "$f" ] && { chown root:root "$f"; chmod 600 "$f"; cp_ok "$f -> 600 root:root"; }
done
if [ -f /etc/grub.d/40_custom ] && grep -qE '^[[:space:]]*(set[[:space:]]+superusers|password|password_pbkdf2)' /etc/grub.d/40_custom; then
    cp_warn "GRUB superusers/passwords in /etc/grub.d/40_custom (remove any the README does not authorize):"
    grep -nE '^[[:space:]]*(set[[:space:]]+superusers|password|password_pbkdf2|set[[:space:]]+check_signatures|export)' /etc/grub.d/40_custom | sed 's/^/        /'
    if cp_ask "Remove ALL superuser/password lines from 40_custom?" n; then
        cp_backup /etc/grub.d/40_custom
        sed -i -E '/^[[:space:]]*(set[[:space:]]+superusers|password|password_pbkdf2)/d' /etc/grub.d/40_custom
        update-grub >/dev/null 2>&1 && cp_ok "Removed; grub.cfg regenerated"
    fi
fi

# ====================================================================== SYS9 permission plants ==
cp_hdr "SYS9 permission plants"
# Checklist "Enforce permissions" step, automated (a world-readable /etc/shadow is scored)
chown root:shadow /etc/shadow /etc/gshadow 2>/dev/null; chmod 640 /etc/shadow /etc/gshadow
chown root:root /etc/passwd /etc/group; chmod 644 /etc/passwd /etc/group
cp_ok "/etc/shadow + gshadow 640 root:shadow, /etc/passwd + group 644 root:root"
# Checklist "Disable root login" step
# (checked as "root:!" in /etc/shadow - a "*" root hash counts as locked for passwd -S but not for that check)
if grep -q '^root:!' /etc/shadow; then cp_ok "root account already locked (root:! in /etc/shadow)"
elif cp_ask "Lock the root account (passwd -l root)? You keep using sudo" y; then passwd -l root >/dev/null && grep -q '^root:!' /etc/shadow && cp_ok "root locked"; fi
chown root:root /home; chmod 755 /home; cp_ok "/home -> 755 root:root"
[ -f /swapfile ] && { chmod 600 /swapfile; chown root:root /swapfile; cp_ok "/swapfile -> 600"; }
# group passwords in gshadow
awk -F: '$2 != "" && $2 != "!" && $2 != "*" && $2 != "!*" && $2 != "!!" {print $1}' /etc/gshadow | while read -r g; do
    cp_warn "Group '$g' has a group password in /etc/gshadow"
    cp_ask "Remove the password from group $g?" y && { cp_backup /etc/gshadow; sed -i -E "s/^($g):[^:]*:/\1:!:/" /etc/gshadow; cp_ok "Removed"; }
done
# system accounts: no password, no login shell
while IFS=: read -r u _ uid _ _ _ sh; do
    [ "$uid" -lt 1000 ] && [ "$u" != root ] || continue
    case "$u" in sync|shutdown|halt|postgres) continue ;; esac
    if [ -n "$sh" ] && ! [[ "$sh" =~ (nologin|false)$ ]]; then
        cp_warn "System account $u has login shell $sh"
        cp_ask "Set $u's shell to /usr/sbin/nologin?" y && usermod -s /usr/sbin/nologin "$u" && cp_ok "$u -> nologin"
    fi
    pw="$(awk -F: -v u="$u" '$1==u{print $2}' /etc/shadow)"
    if [ -n "$pw" ] && [[ "$pw" != \** ]] && [[ "$pw" != \!* ]]; then
        cp_warn "System account $u has a password hash"
        cp_ask "Remove the password of $u (set to '*')?" y && usermod -p '*' "$u" && cp_ok "$u password removed"
    fi
done < /etc/passwd
# SUID/SGID on binaries that should never have it
for b in cp mv wget curl date nano vim vi find bash sh dash python3 perl less more tar zip unzip nmap awk gawk sed tee dd chmod chown env nc netcat socat; do
    p="$(command -v "$b" 2>/dev/null)"; [ -n "$p" ] || continue; p="$(readlink -f "$p")"
    if [ -u "$p" ] || [ -g "$p" ]; then
        cp_warn "$p has SUID/SGID ($(stat -c %A "$p"))"
        cp_ask "Remove SUID/SGID from $p?" y && chmod u-s,g-s "$p" && cp_ok "Fixed $p"
    fi
done
# File ACLs (a FACL on /usr/bin/sudo was scored). Stock Ubuntu/Mint has no ACLs on system binaries
# or /etc -> strip those by default. /home and /var/www are ONLY listed: a scored image REQUIRED a
# restrictive ACL there (getfacl /home/glados must contain group:testsubjects:---).
if command -v getfacl >/dev/null 2>&1; then
    SYSACL="$(getfacl -R -s -p /usr/bin /usr/sbin /bin /sbin /usr/local/bin /usr/local/sbin /etc 2>/dev/null | sed -n 's/^# file: //p' | sort -u)"
    if [ -n "$SYSACL" ]; then
        cp_warn "Extended ACLs on system files:"
        for f in $SYSACL; do echo "        $f: $(getfacl -p -c "$f" 2>/dev/null | grep -vE '^(user|group|other|mask)::' | tr '\n' ' ')"; done
        if cp_ask "Strip these ACLs (setfacl -b)?" y; then
            for f in $SYSACL; do setfacl -b "$f"; done; cp_ok "ACLs removed from system files"
        fi
    fi
    USRACL="$(getfacl -R -s -p /home /var/www /srv 2>/dev/null | sed -n 's/^# file: //p' | head -50)"
    [ -n "$USRACL" ] && { cp_warn "ACLs under /home, /var/www, /srv (compare with the README - some may be REQUIRED):"; echo "$USRACL" | sed 's/^/        /'; }
fi

# ====================================================================== SYS10 persistence ==
cp_hdr "SYS10 persistence spots"
ls /lib/modules/"$(uname -r)"/updates/dkms/ 2>/dev/null | sed 's/^/        DKMS module (review): /'
# stock Ubuntu/Mint system-wide shell files contain no active aliases -> any alias there is suspicious
for f in /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh /etc/bash_aliases /etc/environment; do
    [ -f "$f" ] || continue
    grep -nE '^[[:space:]]*alias[[:space:]]' "$f" | while IFS= read -r l; do cp_warn "System-wide alias in $f: $l"; done
    if grep -qE '^[[:space:]]*alias[[:space:]]' "$f" && cp_ask "Remove all aliases from $f?" y; then
        cp_backup "$f"; sed -i -E '/^[[:space:]]*alias[[:space:]]/d' "$f"; cp_ok "Removed aliases from $f"
    fi
done
grep -nE '^[[:space:]]*alias[[:space:]]' /root/.bashrc /home/*/.bashrc /home/*/.bash_aliases 2>/dev/null \
    | grep -vE "alias (ls|grep|fgrep|egrep|dir|vdir)='(ls|grep|fgrep|egrep|dir|vdir) --color=auto'|alias (ll|la|l)='ls -(alF|A|CF)'|alias alert='notify-send" \
    | sed 's/^/        alias (review): /'
grep -vE '^[[:space:]]*(#|$)|^(127\.0\.0\.1|127\.0\.1\.1)[[:space:]]+(localhost|'"$(hostname)"')|^::1|^(fe00|ff0[0-2])::' /etc/hosts | sed 's|^|        /etc/hosts entry (review): |'
HOLDS="$(apt-mark showhold 2>/dev/null)"; [ -n "$HOLDS" ] && echo "        apt holds (README may require these): $HOLDS"
# Cron (checklist "Check cron"): jobs no package installed, plus every user crontab
BACKDOOR_RE='(\bnc(at)?(\.traditional|\.openbsd)?\b.*-[a-z]*[el]|socat|/dev/tcp/|bash -i|sh -i|python[0-9.]* -c|perl -e|curl[^|]*\|[[:space:]]*(ba)?sh|wget[^|]*\|[[:space:]]*(ba)?sh|mkfifo|chmod [0-7]*[4-7][0-7]{3} )'
for f in /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* /var/spool/cron/crontabs/*; do
    [ -f "$f" ] || continue
    case "$f" in */.placeholder) continue ;; esac
    if [ "$f" != /etc/crontab ] && dpkg-query -S "$f" >/dev/null 2>&1; then continue; fi
    [ "$f" = /etc/crontab ] && dpkg --verify cron 2>/dev/null | grep -q ' /etc/crontab$' || [ "$f" != /etc/crontab ] || continue
    cp_warn "Cron file not from any package (or modified): $f"
    grep -vE '^[[:space:]]*(#|$)' "$f" | sed 's/^/          /' | head -10
    if grep -qE "$BACKDOOR_RE" "$f" && [ "$f" != /etc/crontab ]; then
        cp_ask "It looks like a backdoor (reverse shell / download-and-run). Delete $f?" y && { cp_backup "$f"; rm -f "$f"; cp_ok "Deleted $f"; }
    fi
done

echo ""
echo "✓ Hardening complete"
