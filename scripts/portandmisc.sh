#!/bin/bash

echo "==========================================="
echo "  Linux Port Analyzer"
echo "==========================================="
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "WARNING: Not running as root."
    exit 1
fi

# Main menu
main_menu() {
    while true; do
        echo ""
        echo "MAIN MENU:"
        echo "  1) Run Lynis Security Audit"
        echo "  2) Analyze Listening Ports"
        echo "  3) Run Nmap Scan on Localhost"
        echo "  4) Exit"
        echo ""
        read -p "Select option [1-4]: " choice
        
        case $choice in
            1) run_lynis ;;
            2) analyze_ports ;;
            3) nmap_scan ;;
            4) echo "Exiting..."; exit 0 ;;
            *) echo "Invalid option. Try again." ;;
        esac
    done
}

# Run Lynis audit
run_lynis() {
    echo ""
    echo "=== LYNIS SECURITY AUDIT ==="
    echo ""
    
    if ! command -v lynis &> /dev/null; then
        echo "Lynis is not installed."
        read -p "Install it now? (y/n): " install
        
        if [[ $install =~ ^[Yy]$ ]]; then
            echo "Installing Lynis..."
            sudo apt update && sudo apt install -y lynis
            
            if [[ $? -ne 0 ]]; then
                echo "ERROR: Failed to install Lynis."
                read -p "Press Enter to continue..."
                return
            fi
        else
            return
        fi
    fi
    
    echo "Running Lynis system audit..."
    sudo lynis audit system
    
    echo ""
    echo "Audit complete."
    read -p "Press Enter to continue..."
}

# Analyze listening ports
analyze_ports() {
    echo ""
    echo "=== LISTENING PORTS ANALYSIS ==="
    echo ""
    
    # Check for required tools
    if ! command -v ss &> /dev/null && ! command -v netstat &> /dev/null; then
        echo "ERROR: Neither 'ss' nor 'netstat' is available."
        read -p "Press Enter to continue..."
        return
    fi
    
    # Get port information
    temp_file=$(mktemp)
    
    if command -v ss &> /dev/null; then
        ss -tulpn 2>/dev/null > "$temp_file"
    else
        netstat -tulpn 2>/dev/null > "$temp_file"
    fi
    
    # Display normal ports (<=1024 or port 5353)
    echo "--- NORMAL PORTS (<=1024) ---"
    echo ""
    
    count=0
    while IFS= read -r line; do
        # Skip headers
        if [[ $line =~ ^(Netid|Proto|Active) ]] || [[ -z $line ]]; then
            continue
        fi
        
        local_addr=$(echo "$line" | awk '{print $5}')
        port=$(echo "$local_addr" | grep -oP ':\K[0-9]+$')
        
        if [[ -n $port ]] && ([[ $port -le 1024 ]] || [[ $port -eq 5353 ]]); then
            count=$((count + 1))
            display_port_info "$line" "$count"
        fi
    done < "$temp_file"
    
    if [[ $count -eq 0 ]]; then
        echo "No normal ports found."
    fi
    echo ""
    echo "Total normal ports: $count"
    
    # Display suspicious ports (>1024, excluding 5353)
    echo ""
    echo "--- SUSPICIOUS PORTS (>1024) ---"
    echo ""
    
    count=0
    while IFS= read -r line; do
        if [[ $line =~ ^(Netid|Proto|Active) ]] || [[ -z $line ]]; then
            continue
        fi
        
        local_addr=$(echo "$line" | awk '{print $5}')
        port=$(echo "$local_addr" | grep -oP ':\K[0-9]+$')
        
        if [[ -n $port ]] && [[ $port -gt 1024 ]] && [[ $port -ne 5353 ]]; then
            count=$((count + 1))
            display_port_info "$line" "$count"
        fi
    done < "$temp_file"
    
    if [[ $count -eq 0 ]]; then
        echo "No suspicious ports found."
    fi
    echo ""
    echo "Total suspicious ports: $count"
    
    rm -f "$temp_file"
    
    echo ""
    read -p "Press Enter to continue..."
}

# Display port information
display_port_info() {
    local line=$1
    local num=$2
    
    proto=$(echo "$line" | awk '{print $1}')
    state=$(echo "$line" | awk '{print $2}')
    local_addr=$(echo "$line" | awk '{print $5}')
    port=$(echo "$local_addr" | grep -oP ':\K[0-9]+$')
    process_info=$(echo "$line" | awk '{for(i=7;i<=NF;i++) printf "%s ", $i}')
    
    # Extract PID
    pid=$(echo "$process_info" | grep -oP 'pid=\K[0-9]+')
    
    # Get process details
    if [[ -n $pid ]] && [[ -f "/proc/$pid/cmdline" ]]; then
        cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
        exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null)
        user=$(ps -o user= -p "$pid" 2>/dev/null)
    else
        cmdline="N/A"
        exe="N/A"
        user="N/A"
        pid="N/A"
    fi
    
    # Get service name
    service_name=$(getent services "$port" 2>/dev/null | awk '{print $1}')
    
    echo "[$num] Port: $port | Protocol: $proto | State: $state"
    echo "    Address: $local_addr"
    echo "    PID: $pid | User: $user"
    
    if [[ "$exe" != "N/A" ]]; then
        echo "    Executable: $exe"
    fi
    
    if [[ "$cmdline" != "N/A" ]] && [[ -n "$cmdline" ]]; then
        echo "    Command: ${cmdline:0:100}"
    fi
    
    if [[ -n "$service_name" ]]; then
        echo "    Service: $service_name"
    fi
    
    echo ""
}

# Nmap scan
nmap_scan() {
    echo ""
    echo "=== NMAP LOCALHOST SCAN ==="
    echo ""
    
    if ! command -v nmap &> /dev/null; then
        echo "Nmap is not installed."
        read -p "Install it now? (y/n): " install
        
        if [[ $install =~ ^[Yy]$ ]]; then
            echo "Installing Nmap..."
            sudo apt update && sudo apt install -y nmap
            
            if [[ $? -ne 0 ]]; then
                echo "ERROR: Failed to install Nmap."
                read -p "Press Enter to continue..."
                return
            fi
        else
            return
        fi
    fi
    
    echo "Running Nmap scan on localhost..."
    echo "Scan type: TCP SYN scan with version detection"
    echo ""
    
    sudo nmap -sS -sV -O -T4 -p- localhost
    
    echo ""
    echo "Scan complete."
    read -p "Press Enter to continue..."
}

# Start the script
main_menu
