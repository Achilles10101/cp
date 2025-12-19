#!/bin/bash

# Debian Hardening Script
# Must be run as root

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    print_error "This script must be run as root"
    exit 1
fi

print_info "Starting Debian Hardening Script..."
echo ""

# ===========================
# 1. Configure UMASK
# ===========================

print_info "Configuring UMASK settings..."

# Backup login.defs
if [ -f /etc/login.defs ]; then
    print_info "Creating backup of /etc/login.defs..."
    cp /etc/login.defs /etc/login.defs.backup.$(date +%Y%m%d-%H%M%S)
    print_success "Backup created"
    
    # Modify UMASK in login.defs
    print_info "Setting UMASK to 027 in /etc/login.defs..."
    if grep -q "^UMASK" /etc/login.defs; then
        sed -i 's/^UMASK.*/UMASK\t\t027/' /etc/login.defs
        print_success "UMASK updated in /etc/login.defs"
    else
        echo "UMASK		027" >> /etc/login.defs
        print_success "UMASK added to /etc/login.defs"
    fi
else
    print_error "/etc/login.defs not found"
    exit 1
fi

# Backup and modify /etc/profile
if [ -f /etc/profile ]; then
    print_info "Creating backup of /etc/profile..."
    cp /etc/profile /etc/profile.backup.$(date +%Y%m%d-%H%M%S)
    print_success "Backup created"
    
    print_info "Adding umask 027 to /etc/profile..."
    if grep -q "^umask 027" /etc/profile; then
        print_warning "umask 027 already exists in /etc/profile"
    else
        sed -i '1i umask 027' /etc/profile
        print_success "umask 027 added to top of /etc/profile"
    fi
else
    print_error "/etc/profile not found"
    exit 1
fi

echo ""

# ===========================
# 2. Configure sysctl
# ===========================

print_info "Configuring kernel parameters in /etc/sysctl.conf..."

# Backup sysctl.conf
if [ -f /etc/sysctl.conf ]; then
    print_info "Creating backup of /etc/sysctl.conf..."
    cp /etc/sysctl.conf /etc/sysctl.conf.backup.$(date +%Y%m%d-%H%M%S)
    print_success "Backup created"
else
    print_warning "/etc/sysctl.conf not found, creating new file..."
    touch /etc/sysctl.conf
fi

# Add header to sysctl.conf
print_info "Adding hardening parameters to /etc/sysctl.conf..."
cat >> /etc/sysctl.conf << 'EOF'

# ===========================
# Security Hardening Parameters
# Added by hardening script
# ===========================

# Filesystem Parameters
fs.file-max = 65535
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0

# Kernel Parameters
kernel.core_uses_pid = 1
kernel.dmesg_restrict = 1
kernel.exec-shield = 1
kernel.sysrq = 0
kernel.randomize_va_space = 2
kernel.pid_max = 65536

# Network Core Parameters
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
net.core.netdev_max_backlog = 5000

# IPv4 TCP Parameters
net.ipv4.tcp_rmem = 10240 87380 12582912
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_wmem = 10240 87380 12582912

# IPv4 Security Parameters - All Interfaces
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0

# IPv4 Security Parameters - Default
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# IPv4 ICMP Parameters
net.ipv4.icmp_echo_ignore_all = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# IPv4 Routing and Connection Parameters
net.ipv4.ip_forward = 0
net.ipv4.ip_local_port_range = 2000 65000
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 5
net.ipv4.tcp_timestamps = 9

EOF

print_success "Base hardening parameters added to /etc/sysctl.conf"

echo ""

# ===========================
# 3. IPv6 Configuration
# ===========================

print_info "IPv6 Configuration"
echo ""
read -p "Do you need IPv6 enabled? (y/n): " ipv6_choice

if [[ "$ipv6_choice" =~ ^[Nn]$ ]]; then
    print_info "Disabling IPv6..."
    cat >> /etc/sysctl.conf << 'EOF'

# IPv6 Disabled
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

EOF
    print_success "IPv6 disabled parameters added"
elif [[ "$ipv6_choice" =~ ^[Yy]$ ]]; then
    print_info "Hardening IPv6 settings..."
    cat >> /etc/sysctl.conf << 'EOF'

# IPv6 Security Parameters
net.ipv6.conf.default.router_solicitations = 0
net.ipv6.conf.default.accept_ra_rtr_pref = 0
net.ipv6.conf.default.accept_ra_pinfo = 0
net.ipv6.conf.default.accept_ra_defrtr = 0
net.ipv6.conf.default.autoconf = 0
net.ipv6.conf.default.dad_transmits = 0
net.ipv6.conf.default.max_addresses = 1

EOF
    print_success "IPv6 hardening parameters added"
else
    print_warning "Invalid choice. Skipping IPv6 configuration."
fi

echo ""

# ===========================
# 4. Apply sysctl changes
# ===========================

print_info "Applying sysctl changes..."
if sysctl -p > /dev/null 2>&1; then
    print_success "All sysctl parameters applied successfully"
else
    print_warning "Some sysctl parameters may have failed to apply"
    print_info "Running sysctl -p with output:"
    sysctl -p
fi

echo "Script completed!"
