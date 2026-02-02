#!/bin/bash
# =============================================================================
# AIDN - AI Defense Network Installation Script
# =============================================================================
# DDoS Protection Suite for Game Servers (Arma Reforger)
#
# Usage: sudo bash install.sh [options]
#   --iptables    Use iptables (legacy)
#   --nftables    Use nftables (modern, recommended)
#   --dry-run     Show what would be done without making changes
#   --uninstall   Remove AIDN protection
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
AIDN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIREWALL_TYPE=""
DRY_RUN=false
UNINSTALL=false

# Logging
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_header() { echo -e "\n${BLUE}=== $1 ===${NC}\n"; }

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --iptables)
                FIREWALL_TYPE="iptables"
                shift
                ;;
            --nftables)
                FIREWALL_TYPE="nftables"
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --uninstall)
                UNINSTALL=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

show_help() {
    cat << EOF
AIDN - AI Defense Network Installation Script

Usage: sudo bash install.sh [options]

Options:
    --iptables    Use iptables for firewall rules (legacy)
    --nftables    Use nftables for firewall rules (modern, recommended)
    --dry-run     Show what would be done without making changes
    --uninstall   Remove AIDN protection
    -h, --help    Show this help message

Example:
    sudo bash install.sh --nftables
    sudo bash install.sh --iptables --dry-run

EOF
}

# Detect system information
detect_system() {
    log_header "System Detection"

    # Detect distro
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        DISTRO_VERSION=$VERSION_ID
        log_info "Detected: $PRETTY_NAME"
    else
        log_warn "Could not detect distribution"
        DISTRO="unknown"
    fi

    # Detect package manager
    if command -v apt-get &> /dev/null; then
        PKG_MANAGER="apt"
        PKG_INSTALL="apt-get install -y"
        PKG_UPDATE="apt-get update"
    elif command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
        PKG_INSTALL="dnf install -y"
        PKG_UPDATE="dnf check-update || true"
    elif command -v yum &> /dev/null; then
        PKG_MANAGER="yum"
        PKG_INSTALL="yum install -y"
        PKG_UPDATE="yum check-update || true"
    else
        log_error "No supported package manager found"
        exit 1
    fi
    log_info "Package manager: $PKG_MANAGER"

    # Detect available firewall
    if [ -z "$FIREWALL_TYPE" ]; then
        if command -v nft &> /dev/null; then
            FIREWALL_TYPE="nftables"
        elif command -v iptables &> /dev/null; then
            FIREWALL_TYPE="iptables"
        else
            log_warn "No firewall detected, will install nftables"
            FIREWALL_TYPE="nftables"
        fi
    fi
    log_info "Firewall type: $FIREWALL_TYPE"

    # Detect network interface
    MAIN_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    log_info "Main network interface: $MAIN_INTERFACE"
}

# Install dependencies
install_dependencies() {
    log_header "Installing Dependencies"

    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would install: fail2ban, $FIREWALL_TYPE, conntrack"
        return
    fi

    log_info "Updating package lists..."
    $PKG_UPDATE

    case $PKG_MANAGER in
        apt)
            PACKAGES="fail2ban conntrack ipset"
            if [ "$FIREWALL_TYPE" = "nftables" ]; then
                PACKAGES="$PACKAGES nftables"
            else
                PACKAGES="$PACKAGES iptables iptables-persistent"
            fi
            ;;
        dnf|yum)
            PACKAGES="fail2ban conntrack-tools ipset"
            if [ "$FIREWALL_TYPE" = "nftables" ]; then
                PACKAGES="$PACKAGES nftables"
            else
                PACKAGES="$PACKAGES iptables iptables-services"
            fi
            ;;
    esac

    log_info "Installing: $PACKAGES"
    $PKG_INSTALL $PACKAGES
}

# Install kernel hardening
install_sysctl() {
    log_header "Installing Kernel Hardening"

    local SYSCTL_FILE="/etc/sysctl.d/99-ddos-protection.conf"

    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would copy sysctl config to $SYSCTL_FILE"
        return
    fi

    # Backup existing if present
    if [ -f "$SYSCTL_FILE" ]; then
        cp "$SYSCTL_FILE" "${SYSCTL_FILE}.backup.$(date +%Y%m%d%H%M%S)"
        log_info "Backed up existing sysctl config"
    fi

    # Copy new config
    cp "$AIDN_DIR/sysctl/99-ddos-protection.conf" "$SYSCTL_FILE"

    # Update interface name in config
    if [ -n "$MAIN_INTERFACE" ]; then
        log_info "Network interface detected: $MAIN_INTERFACE"
    fi

    # Apply settings
    log_info "Applying sysctl settings..."
    sysctl -p "$SYSCTL_FILE" 2>/dev/null || log_warn "Some sysctl settings may not be available on this kernel"

    log_info "Kernel hardening installed"
}

# Install firewall rules
install_firewall() {
    log_header "Installing Firewall Rules"

    if [ "$FIREWALL_TYPE" = "nftables" ]; then
        install_nftables
    else
        install_iptables
    fi
}

install_nftables() {
    local NFT_FILE="/etc/nftables.conf"

    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would install nftables rules to $NFT_FILE"
        return
    fi

    # Backup existing config
    if [ -f "$NFT_FILE" ]; then
        cp "$NFT_FILE" "${NFT_FILE}.backup.$(date +%Y%m%d%H%M%S)"
        log_info "Backed up existing nftables config"
    fi

    # Copy and customize config
    cp "$AIDN_DIR/firewall/nftables-ddos.conf" "$NFT_FILE"

    # Update interface name
    if [ -n "$MAIN_INTERFACE" ]; then
        sed -i "s/define WAN_IF = \"eth0\"/define WAN_IF = \"$MAIN_INTERFACE\"/" "$NFT_FILE"
    fi

    # Apply rules
    log_info "Applying nftables rules..."
    nft -f "$NFT_FILE"

    # Enable service
    systemctl enable nftables
    systemctl start nftables

    log_info "nftables firewall installed and enabled"
}

install_iptables() {
    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would install iptables rules"
        return
    fi

    # Copy script
    cp "$AIDN_DIR/firewall/iptables-ddos.rules" /usr/local/sbin/aidn-firewall.sh
    chmod +x /usr/local/sbin/aidn-firewall.sh

    # Update interface name
    if [ -n "$MAIN_INTERFACE" ]; then
        sed -i "s/INTERFACE=\"eth0\"/INTERFACE=\"$MAIN_INTERFACE\"/" /usr/local/sbin/aidn-firewall.sh
    fi

    # Run firewall script
    log_info "Applying iptables rules..."
    /usr/local/sbin/aidn-firewall.sh

    # Save rules for persistence
    case $PKG_MANAGER in
        apt)
            netfilter-persistent save
            systemctl enable netfilter-persistent
            ;;
        dnf|yum)
            service iptables save
            systemctl enable iptables
            ;;
    esac

    # Create systemd service for loading on boot
    cat > /etc/systemd/system/aidn-firewall.service << 'EOF'
[Unit]
Description=AIDN DDoS Protection Firewall
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/aidn-firewall.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable aidn-firewall

    log_info "iptables firewall installed and enabled"
}

# Install fail2ban configuration
install_fail2ban() {
    log_header "Installing Fail2ban Configuration"

    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would install fail2ban configuration"
        return
    fi

    # Create directories
    mkdir -p /etc/fail2ban/jail.d
    mkdir -p /etc/fail2ban/filter.d

    # Copy configurations
    cp "$AIDN_DIR/fail2ban/jail.d/aidn-gameserver.conf" /etc/fail2ban/jail.d/
    cp "$AIDN_DIR/fail2ban/filter.d/"*.conf /etc/fail2ban/filter.d/

    # Create log directories if they don't exist
    mkdir -p /var/log/arma-reforger

    # Restart fail2ban
    log_info "Restarting fail2ban..."
    systemctl enable fail2ban
    systemctl restart fail2ban

    # Check status
    sleep 2
    if systemctl is-active --quiet fail2ban; then
        log_info "Fail2ban is running"
        fail2ban-client status | head -5
    else
        log_warn "Fail2ban may not be running properly. Check: systemctl status fail2ban"
    fi
}

# Create status script
create_status_script() {
    log_header "Creating Management Scripts"

    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would create status script"
        return
    fi

    cat > /usr/local/bin/aidn-status << 'EOF'
#!/bin/bash
# AIDN Status Script

echo "========================================="
echo "      AIDN DDoS Protection Status"
echo "========================================="
echo ""

echo "=== Firewall Status ==="
if command -v nft &> /dev/null && nft list ruleset &> /dev/null; then
    echo "nftables: ACTIVE"
    echo "Rules loaded: $(nft list ruleset | grep -c 'rule')"
elif command -v iptables &> /dev/null; then
    echo "iptables: ACTIVE"
    echo "Rules loaded: $(iptables -L -n | grep -c 'Chain\|DROP\|ACCEPT')"
else
    echo "Firewall: NOT DETECTED"
fi
echo ""

echo "=== Fail2ban Status ==="
if systemctl is-active --quiet fail2ban; then
    echo "Status: RUNNING"
    fail2ban-client status 2>/dev/null | grep "Jail list" || echo "No jails active"
    echo ""
    echo "Currently banned IPs:"
    fail2ban-client status 2>/dev/null | grep -A100 "Jail list" | while read jail; do
        jail_name=$(echo "$jail" | awk -F: '{print $1}' | tr -d ' ')
        if [ -n "$jail_name" ] && [ "$jail_name" != "Jail list" ]; then
            banned=$(fail2ban-client status "$jail_name" 2>/dev/null | grep "Banned IP" | awk -F: '{print $2}')
            if [ -n "$banned" ] && [ "$banned" != " " ]; then
                echo "  $jail_name: $banned"
            fi
        fi
    done
else
    echo "Status: STOPPED"
fi
echo ""

echo "=== Connection Statistics ==="
echo "Established connections: $(ss -s | grep 'estab' | awk '{print $2}')"
echo "UDP sockets: $(ss -u -a | wc -l)"
if command -v conntrack &> /dev/null; then
    echo "Tracked connections: $(conntrack -C 2>/dev/null || echo 'N/A')"
fi
echo ""

echo "=== System Load ==="
uptime
echo ""

echo "=== Recent Drops (last 10) ==="
dmesg | grep -i 'drop\|reject\|ddos\|flood' | tail -10 || echo "No recent drops in kernel log"
EOF

    chmod +x /usr/local/bin/aidn-status
    log_info "Created /usr/local/bin/aidn-status"

    # Create unban script
    cat > /usr/local/bin/aidn-unban << 'EOF'
#!/bin/bash
# AIDN Unban Script
# Usage: aidn-unban <ip-address>

if [ -z "$1" ]; then
    echo "Usage: aidn-unban <ip-address>"
    echo "Example: aidn-unban 192.168.1.100"
    exit 1
fi

IP="$1"
echo "Unbanning $IP from all jails..."

# Get all jails
JAILS=$(fail2ban-client status | grep "Jail list" | sed 's/.*://;s/,/ /g')

for jail in $JAILS; do
    jail=$(echo "$jail" | tr -d ' ')
    if [ -n "$jail" ]; then
        fail2ban-client set "$jail" unbanip "$IP" 2>/dev/null && echo "Unbanned from $jail"
    fi
done

# Also remove from iptables/nftables if present
if command -v nft &> /dev/null; then
    nft delete element inet filter syn_meter "{ $IP }" 2>/dev/null
    nft delete element inet filter udp_meter "{ $IP }" 2>/dev/null
fi

echo "Done."
EOF

    chmod +x /usr/local/bin/aidn-unban
    log_info "Created /usr/local/bin/aidn-unban"
}

# Uninstall function
uninstall() {
    log_header "Uninstalling AIDN"

    if [ "$DRY_RUN" = true ]; then
        log_info "[DRY-RUN] Would remove AIDN configuration"
        return
    fi

    # Remove firewall rules
    if command -v nft &> /dev/null; then
        nft flush ruleset
        rm -f /etc/nftables.conf
        if [ -f /etc/nftables.conf.backup.* ]; then
            BACKUP=$(ls -t /etc/nftables.conf.backup.* | head -1)
            mv "$BACKUP" /etc/nftables.conf
            log_info "Restored nftables backup"
        fi
    fi

    # Remove iptables service
    if [ -f /etc/systemd/system/aidn-firewall.service ]; then
        systemctl disable aidn-firewall
        rm -f /etc/systemd/system/aidn-firewall.service
        rm -f /usr/local/sbin/aidn-firewall.sh
        iptables -F
        iptables -X
    fi

    # Remove fail2ban configs
    rm -f /etc/fail2ban/jail.d/aidn-gameserver.conf
    rm -f /etc/fail2ban/filter.d/arma-*.conf
    rm -f /etc/fail2ban/filter.d/udp-flood.conf
    rm -f /etc/fail2ban/filter.d/portscan.conf
    systemctl restart fail2ban

    # Remove sysctl config
    rm -f /etc/sysctl.d/99-ddos-protection.conf
    sysctl --system

    # Remove scripts
    rm -f /usr/local/bin/aidn-status
    rm -f /usr/local/bin/aidn-unban

    log_info "AIDN has been uninstalled"
    log_warn "You may need to reboot for all changes to take effect"
}

# Main installation
main() {
    parse_args "$@"
    check_root

    echo ""
    echo "============================================"
    echo "  AIDN - AI Defense Network Installer"
    echo "  DDoS Protection for Game Servers"
    echo "============================================"
    echo ""

    if [ "$UNINSTALL" = true ]; then
        uninstall
        exit 0
    fi

    detect_system
    install_dependencies
    install_sysctl
    install_firewall
    install_fail2ban
    create_status_script

    log_header "Installation Complete!"

    echo ""
    echo "AIDN DDoS Protection has been installed."
    echo ""
    echo "Important commands:"
    echo "  aidn-status    - Check protection status"
    echo "  aidn-unban IP  - Unban an IP address"
    echo ""
    echo "Configuration files:"
    echo "  Firewall: /etc/nftables.conf or /usr/local/sbin/aidn-firewall.sh"
    echo "  Sysctl:   /etc/sysctl.d/99-ddos-protection.conf"
    echo "  Fail2ban: /etc/fail2ban/jail.d/aidn-gameserver.conf"
    echo ""
    echo "Customize the firewall rules for your specific ports!"
    echo "Edit GAME_PORT, STEAM_QUERY_PORT, and RCON_PORT as needed."
    echo ""

    if [ "$DRY_RUN" = true ]; then
        log_warn "This was a DRY RUN - no changes were made"
    fi
}

main "$@"
