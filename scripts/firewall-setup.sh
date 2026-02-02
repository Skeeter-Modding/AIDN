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

# Track if we're in setup mode for cleanup
SETUP_IN_PROGRESS=false

# Logging functions (defined early for use in cleanup)
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Cleanup handler for unexpected exits during setup
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]] && [[ "$SETUP_IN_PROGRESS" == "true" ]]; then
        log_error "Setup failed with exit code $exit_code"
        log_warn "Firewall may be in an inconsistent state!"
        log_warn "Run 'iptables -F && iptables -P INPUT ACCEPT' to reset if needed"
    fi
}
trap cleanup EXIT

# Input validation functions
validate_ip() {
    local ip="$1"

    if [[ -z "$ip" ]]; then
        return 1
    fi

    # IPv4 validation (with optional CIDR)
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
        local IFS='.'
        read -ra octets <<< "${ip%%/*}"
        for octet in "${octets[@]}"; do
            if (( octet > 255 )); then
                return 1
            fi
        done
        return 0
    fi

    # IPv6 validation (simplified - accepts common formats)
    if [[ "$ip" =~ ^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$ ]] || \
       [[ "$ip" =~ ^::([0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$ ]] || \
       [[ "$ip" =~ ^[0-9a-fA-F]{1,4}::$ ]]; then
        return 0
    fi

    return 1
}

validate_port() {
    local port="$1"

    if [[ -z "$port" ]]; then
        return 1
    fi

    # Check if it's a valid port number (1-65535)
    if [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )); then
        return 0
    fi

    return 1
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
    # Default values
    SSH_PORT="10022"
    ADMIN_IP=""
    GAME_PORTS=""

    if [[ -f "$AIDN_CONFIG" ]]; then
        # Safely parse config file instead of sourcing it (security fix)
        while IFS='=' read -r key value; do
            # Skip comments and empty lines
            [[ "$key" =~ ^#.*$ ]] && continue
            [[ -z "$key" ]] && continue

            # Remove quotes from value
            value="${value#\"}"
            value="${value%\"}"

            case "$key" in
                SSH_PORT)
                    if validate_port "$value" 2>/dev/null; then
                        SSH_PORT="$value"
                    fi
                    ;;
                ADMIN_IP)
                    if validate_ip "$value" 2>/dev/null; then
                        ADMIN_IP="$value"
                    fi
                    ;;
                GAME_PORTS)
                    GAME_PORTS="$value"
                    ;;
            esac
        done < "$AIDN_CONFIG"
        log_info "Loaded configuration from $AIDN_CONFIG"
    else
        log_warn "No configuration found, using defaults"
    fi
}

flush_rules() {
    log_info "Flushing existing firewall rules..."
    # IPv4
    iptables -F
    iptables -X 2>/dev/null || true
    iptables -t nat -F
    iptables -t nat -X 2>/dev/null || true
    iptables -t mangle -F
    iptables -t mangle -X 2>/dev/null || true

    # IPv6
    ip6tables -F
    ip6tables -X 2>/dev/null || true
    ip6tables -t nat -F 2>/dev/null || true
    ip6tables -t nat -X 2>/dev/null || true
    ip6tables -t mangle -F
    ip6tables -t mangle -X 2>/dev/null || true
}

set_default_policies() {
    log_info "Setting default DROP policies..."
    # IPv4
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT

    # IPv6
    ip6tables -P INPUT DROP
    ip6tables -P FORWARD DROP
    ip6tables -P OUTPUT ACCEPT
}

setup_loopback() {
    log_info "Allowing loopback interface..."
    # IPv4
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    # IPv6
    ip6tables -A INPUT -i lo -j ACCEPT
    ip6tables -A OUTPUT -o lo -j ACCEPT
}

setup_established() {
    log_info "Allowing established connections..."
    # IPv4
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # IPv6
    ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Allow ICMPv6 for neighbor discovery (required for IPv6)
    ip6tables -A INPUT -p icmpv6 --icmpv6-type neighbor-solicitation -j ACCEPT
    ip6tables -A INPUT -p icmpv6 --icmpv6-type neighbor-advertisement -j ACCEPT
    ip6tables -A INPUT -p icmpv6 --icmpv6-type router-solicitation -j ACCEPT
    ip6tables -A INPUT -p icmpv6 --icmpv6-type router-advertisement -j ACCEPT
}

allow_ssh() {
    local port="${1:-10022}"

    if ! validate_port "$port"; then
        return 1
    fi

    # Check if rule already exists (idempotency)
    if iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null; then
        log_info "SSH on port $port already allowed (skipping)"
        return 0
    fi

    log_info "Allowing SSH on port $port..."
    iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
    ip6tables -A INPUT -p tcp --dport "$port" -j ACCEPT
}

allow_admin_ip() {
    local ip="$1"
    local comment="${2:-Admin}"

    if ! validate_ip "$ip"; then
        return 1
    fi

    # Check if rule already exists (idempotency)
    if iptables -C INPUT -s "$ip" -j ACCEPT 2>/dev/null; then
        log_info "IP $ip already allowed (skipping)"
        return 0
    fi

    log_info "Allowing full access from $ip ($comment)..."
    iptables -A INPUT -s "$ip" -m comment --comment "$comment" -j ACCEPT
}

allow_port_tcp() {
    local port="$1"
    local source="${2:-0.0.0.0/0}"
    local comment="${3:-}"

    if ! validate_port "$port"; then
        return 1
    fi

    # Check if rule already exists (idempotency)
    if iptables -C INPUT -p tcp -s "$source" --dport "$port" -j ACCEPT 2>/dev/null; then
        log_info "TCP port $port from $source already allowed (skipping)"
        return 0
    fi

    if [[ -n "$comment" ]]; then
        iptables -A INPUT -p tcp -s "$source" --dport "$port" -m comment --comment "$comment" -j ACCEPT
    else
        iptables -A INPUT -p tcp -s "$source" --dport "$port" -j ACCEPT
    fi

    # Also allow on IPv6 (for any source)
    if [[ "$source" == "0.0.0.0/0" ]]; then
        ip6tables -A INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || true
    fi

    log_info "Allowed TCP port $port from $source"
}

allow_port_udp() {
    local port="$1"
    local source="${2:-0.0.0.0/0}"
    local comment="${3:-}"

    if ! validate_port "$port"; then
        return 1
    fi

    # Check if rule already exists (idempotency)
    if iptables -C INPUT -p udp -s "$source" --dport "$port" -j ACCEPT 2>/dev/null; then
        log_info "UDP port $port from $source already allowed (skipping)"
        return 0
    fi

    if [[ -n "$comment" ]]; then
        iptables -A INPUT -p udp -s "$source" --dport "$port" -m comment --comment "$comment" -j ACCEPT
    else
        iptables -A INPUT -p udp -s "$source" --dport "$port" -j ACCEPT
    fi

    # Also allow on IPv6 (for any source)
    if [[ "$source" == "0.0.0.0/0" ]]; then
        ip6tables -A INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null || true
    fi

    log_info "Allowed UDP port $port from $source"
}

block_ip() {
    local ip="$1"
    local comment="${2:-Blocked}"

    if ! validate_ip "$ip"; then
        return 1
    fi

    # Check if rule already exists (idempotency)
    if iptables -C INPUT -s "$ip" -j DROP 2>/dev/null; then
        log_info "IP $ip already blocked (skipping)"
        return 0
    fi

    log_info "Blocking IP: $ip ($comment)..."
    iptables -I INPUT -s "$ip" -m comment --comment "$comment" -j DROP
}

allow_icmp_from() {
    local ip="$1"

    if ! validate_ip "$ip"; then
        return 1
    fi

    log_info "Allowing ICMP from $ip..."
    iptables -A INPUT -p icmp -s "$ip" -j ACCEPT
}

create_fail2ban_chain() {
    local chain_name="$1"

    # Check if chain already exists (idempotency)
    if iptables -L "$chain_name" -n >/dev/null 2>&1; then
        log_info "Fail2ban chain $chain_name already exists (skipping)"
        return 0
    fi

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

    # Ensure directory exists
    mkdir -p /etc/iptables

    # Save using iptables-persistent
    if command -v netfilter-persistent &> /dev/null; then
        netfilter-persistent save
    else
        iptables-save > /etc/iptables/rules.v4
        ip6tables-save > /etc/iptables/rules.v6
    fi

    log_info "Rules saved to /etc/iptables/rules.v4 and rules.v6"
}

show_rules() {
    echo ""
    echo "=================================================="
    echo "Current Firewall Rules (IPv4)"
    echo "=================================================="
    iptables -L -n -v --line-numbers | head -50

    echo ""
    echo "=================================================="
    echo "Current Firewall Rules (IPv6)"
    echo "=================================================="
    ip6tables -L -n -v --line-numbers | head -30
}

interactive_setup() {
    echo "=============================================="
    echo "AIDN - Interactive Firewall Setup"
    echo "=============================================="
    echo ""

    # SSH Port
    local input_ssh_port
    while true; do
        read -p "SSH Port [10022]: " input_ssh_port
        SSH_PORT="${input_ssh_port:-10022}"
        if validate_port "$SSH_PORT" 2>/dev/null; then
            break
        fi
        echo "Please enter a valid port number (1-65535)"
    done

    # Admin IP
    echo ""
    local input_admin_ip
    while true; do
        read -p "Your admin IP address (full access): " input_admin_ip
        if [[ -z "$input_admin_ip" ]]; then
            log_error "Admin IP is required for safe firewall setup!"
            continue
        fi
        if validate_ip "$input_admin_ip" 2>/dev/null; then
            ADMIN_IP="$input_admin_ip"
            break
        fi
        echo "Please enter a valid IPv4 address (e.g., 192.168.1.100)"
    done

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

    # Mark setup in progress for cleanup handler
    SETUP_IN_PROGRESS=true

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

    # Mark setup complete
    SETUP_IN_PROGRESS=false

    show_rules

    echo ""
    echo -e "${GREEN}Firewall configured successfully!${NC}"
    echo ""
    echo -e "${RED}WARNING:${NC} Default INPUT policy is DROP (IPv4 and IPv6)"
    echo "Your IP ($ADMIN_IP) has been whitelisted for full access."
    echo ""
}

# Quick commands
cmd_allow_ip() {
    check_root
    if [[ -z "$1" ]]; then
        log_error "IP address required"
        exit 1
    fi
    if ! allow_admin_ip "$1" "${2:-Manual}"; then
        exit 1
    fi
    save_rules
}

cmd_block_ip() {
    check_root
    if [[ -z "$1" ]]; then
        log_error "IP address required"
        exit 1
    fi
    if ! block_ip "$1" "${2:-Manual block}"; then
        exit 1
    fi
    save_rules
}

cmd_allow_port() {
    check_root
    if [[ -z "$1" ]]; then
        log_error "Port number required"
        exit 1
    fi
    local proto="${3:-tcp}"
    if [[ "$proto" == "udp" ]]; then
        if ! allow_port_udp "$1" "${2:-0.0.0.0/0}"; then
            exit 1
        fi
    else
        if ! allow_port_tcp "$1" "${2:-0.0.0.0/0}"; then
            exit 1
        fi
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
            if [[ -z "$2" ]]; then
                log_error "IP address required"
                echo "Usage: $0 allow-ip IP [COMMENT]"
                exit 1
            fi
            if ! validate_ip "$2"; then
                log_error "Invalid IP address: $2"
                exit 1
            fi
            cmd_allow_ip "$2" "$3"
            ;;
        block-ip)
            if [[ -z "$2" ]]; then
                log_error "IP address required"
                echo "Usage: $0 block-ip IP [COMMENT]"
                exit 1
            fi
            if ! validate_ip "$2"; then
                log_error "Invalid IP address: $2"
                exit 1
            fi
            cmd_block_ip "$2" "$3"
            ;;
        allow-port)
            if [[ -z "$2" ]]; then
                log_error "Port number required"
                echo "Usage: $0 allow-port PORT [SOURCE] [PROTOCOL]"
                exit 1
            fi
            if ! validate_port "$2"; then
                log_error "Invalid port number: $2 (must be 1-65535)"
                exit 1
            fi
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
