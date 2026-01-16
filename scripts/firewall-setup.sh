#!/bin/bash
#
# AIDN - Firewall Setup Script
# Configures iptables/nftables with strict DROP policy on Debian servers
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration file
AIDN_CONFIG="/etc/aidn/firewall.conf"

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

install_dependencies() {
    log_info "Installing iptables and dependencies..."
    apt-get update -qq
    apt-get install -y -qq iptables iptables-persistent netfilter-persistent
    log_info "Dependencies installed"
}

create_config_dir() {
    mkdir -p /etc/aidn
}

load_config() {
    if [[ -f "$AIDN_CONFIG" ]]; then
        source "$AIDN_CONFIG"
        log_info "Loaded configuration from $AIDN_CONFIG"
    else
        log_warn "No configuration found, using defaults"
        # Defaults
        SSH_PORT="10022"
        ADMIN_IPS=""
        GAME_PORTS=""
    fi
}

flush_rules() {
    log_info "Flushing existing firewall rules..."
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
}

set_default_policies() {
    log_info "Setting default DROP policies..."
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
}

setup_loopback() {
    log_info "Allowing loopback interface..."
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
}

setup_established() {
    log_info "Allowing established connections..."
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
}

allow_ssh() {
    local port="${1:-10022}"
    log_info "Allowing SSH on port $port..."
    iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
}

allow_admin_ip() {
    local ip="$1"
    local comment="${2:-Admin}"
    log_info "Allowing full access from $ip ($comment)..."
    iptables -A INPUT -s "$ip" -m comment --comment "$comment" -j ACCEPT
}

allow_port_tcp() {
    local port="$1"
    local source="${2:-0.0.0.0/0}"
    local comment="${3:-}"

    if [[ -n "$comment" ]]; then
        iptables -A INPUT -p tcp -s "$source" --dport "$port" -m comment --comment "$comment" -j ACCEPT
    else
        iptables -A INPUT -p tcp -s "$source" --dport "$port" -j ACCEPT
    fi
    log_info "Allowed TCP port $port from $source"
}

allow_port_udp() {
    local port="$1"
    local source="${2:-0.0.0.0/0}"
    local comment="${3:-}"

    if [[ -n "$comment" ]]; then
        iptables -A INPUT -p udp -s "$source" --dport "$port" -m comment --comment "$comment" -j ACCEPT
    else
        iptables -A INPUT -p udp -s "$source" --dport "$port" -j ACCEPT
    fi
    log_info "Allowed UDP port $port from $source"
}

block_ip() {
    local ip="$1"
    local comment="${2:-Blocked}"
    log_info "Blocking IP: $ip ($comment)..."
    iptables -I INPUT -s "$ip" -m comment --comment "$comment" -j DROP
}

allow_icmp_from() {
    local ip="$1"
    log_info "Allowing ICMP from $ip..."
    iptables -A INPUT -p icmp -s "$ip" -j ACCEPT
}

create_fail2ban_chain() {
    local chain_name="$1"
    log_info "Creating fail2ban chain: $chain_name..."

    iptables -N "$chain_name" 2>/dev/null || true
    iptables -A "$chain_name" -j RETURN
}

setup_game_server_rules() {
    # Example: Arma Reforger ports
    local game_ports="${1:-2001,2002,17777,19999}"

    log_info "Setting up game server rules for ports: $game_ports"

    # Create fail2ban chain for game protection
    create_fail2ban_chain "f2b-game-server"

    # Add jump to fail2ban chain for game ports
    IFS=',' read -ra PORTS <<< "$game_ports"
    for port in "${PORTS[@]}"; do
        iptables -A INPUT -p udp --dport "$port" -j f2b-game-server
        iptables -A INPUT -p udp --dport "$port" -j ACCEPT
        log_info "  - UDP port $port enabled"
    done
}

save_rules() {
    log_info "Saving firewall rules..."

    # Save using iptables-persistent
    if command -v netfilter-persistent &> /dev/null; then
        netfilter-persistent save
    else
        iptables-save > /etc/iptables/rules.v4
    fi

    log_info "Rules saved to /etc/iptables/rules.v4"
}

show_rules() {
    echo ""
    echo "=================================================="
    echo "Current Firewall Rules"
    echo "=================================================="
    iptables -L -n -v --line-numbers | head -50
}

interactive_setup() {
    echo "=============================================="
    echo "AIDN - Interactive Firewall Setup"
    echo "=============================================="
    echo ""

    # SSH Port
    read -p "SSH Port [10022]: " input_ssh_port
    SSH_PORT="${input_ssh_port:-10022}"

    # Admin IP
    echo ""
    read -p "Your admin IP address (full access): " ADMIN_IP

    if [[ -z "$ADMIN_IP" ]]; then
        log_error "Admin IP is required for safe firewall setup!"
        exit 1
    fi

    # Confirm
    echo ""
    echo "Configuration:"
    echo "  SSH Port: $SSH_PORT"
    echo "  Admin IP: $ADMIN_IP"
    echo ""

    read -p "Proceed with firewall setup? [y/N]: " -n 1 -r
    echo

    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_warn "Aborted"
        exit 0
    fi

    # Apply rules
    flush_rules
    set_default_policies
    setup_loopback
    setup_established

    # IMPORTANT: Allow admin IP FIRST (before SSH restriction)
    allow_admin_ip "$ADMIN_IP" "Admin"

    # Allow SSH
    allow_ssh "$SSH_PORT"

    # Save configuration
    cat > "$AIDN_CONFIG" << EOF
# AIDN Firewall Configuration
SSH_PORT="$SSH_PORT"
ADMIN_IP="$ADMIN_IP"
EOF

    save_rules
    show_rules

    echo ""
    echo -e "${GREEN}Firewall configured successfully!${NC}"
    echo ""
    echo -e "${RED}WARNING:${NC} Default INPUT policy is DROP"
    echo "Your IP ($ADMIN_IP) has been whitelisted for full access."
    echo ""
}

# Quick commands
cmd_allow_ip() {
    check_root
    allow_admin_ip "$1" "${2:-Manual}"
    save_rules
}

cmd_block_ip() {
    check_root
    block_ip "$1" "${2:-Manual block}"
    save_rules
}

cmd_allow_port() {
    check_root
    local proto="${3:-tcp}"
    if [[ "$proto" == "udp" ]]; then
        allow_port_udp "$1" "${2:-0.0.0.0/0}"
    else
        allow_port_tcp "$1" "${2:-0.0.0.0/0}"
    fi
    save_rules
}

print_usage() {
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  setup          Interactive firewall setup"
    echo "  allow-ip IP    Allow full access from IP"
    echo "  block-ip IP    Block IP address"
    echo "  allow-port P   Allow port (default: TCP)"
    echo "  show           Show current rules"
    echo "  save           Save current rules"
    echo ""
    echo "Examples:"
    echo "  $0 setup"
    echo "  $0 allow-ip 192.168.1.100 \"Home\""
    echo "  $0 allow-port 8080"
    echo "  $0 allow-port 27015 0.0.0.0/0 udp"
    echo ""
}

main() {
    check_root
    create_config_dir

    case "${1:-}" in
        setup)
            install_dependencies
            interactive_setup
            ;;
        allow-ip)
            cmd_allow_ip "$2" "$3"
            ;;
        block-ip)
            cmd_block_ip "$2" "$3"
            ;;
        allow-port)
            cmd_allow_port "$2" "$3" "$4"
            ;;
        show)
            show_rules
            ;;
        save)
            save_rules
            ;;
        *)
            print_usage
            ;;
    esac
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
