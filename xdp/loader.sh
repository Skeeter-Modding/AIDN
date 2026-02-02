#!/bin/bash
#
# AIDN XDP Loader
# Loads/unloads the XDP eBPF program on network interfaces
#

set -e

XDP_OBJ="/opt/aidn/xdp/aidn_xdp.o"
XDP_SECTION="xdp"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[AIDN-XDP]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[AIDN-XDP]${NC} $1"; }
log_error() { echo -e "${RED}[AIDN-XDP]${NC} $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Must be run as root"
        exit 1
    fi
}

detect_interface() {
    # Find main network interface
    local iface=$(ip route | grep default | awk '{print $5}' | head -1)
    if [[ -z "$iface" ]]; then
        log_error "Could not detect network interface"
        exit 1
    fi
    echo "$iface"
}

check_xdp_support() {
    local iface="$1"

    # Check if interface supports XDP
    if ! ip link show "$iface" | grep -q "xdp"; then
        log_warn "Interface $iface may not support XDP native mode"
        log_warn "Will use generic (skb) mode - slower but compatible"
        return 1
    fi
    return 0
}

load_xdp() {
    local iface="${1:-$(detect_interface)}"
    local mode="xdpgeneric"  # Default to generic mode for compatibility

    log_info "Loading XDP program on interface: $iface"

    # Check for native XDP support
    if check_xdp_support "$iface" 2>/dev/null; then
        mode="xdpdrv"
        log_info "Using native XDP mode (maximum performance)"
    else
        log_info "Using generic XDP mode (software fallback)"
    fi

    # Check if already loaded
    if ip link show "$iface" | grep -q "xdp"; then
        log_warn "XDP program already loaded on $iface, unloading first..."
        unload_xdp "$iface"
    fi

    # Load the XDP program
    if ! ip link set dev "$iface" "$mode" obj "$XDP_OBJ" sec "$XDP_SECTION"; then
        log_error "Failed to load XDP program"
        log_error "Trying with generic mode..."
        if ! ip link set dev "$iface" xdpgeneric obj "$XDP_OBJ" sec "$XDP_SECTION"; then
            log_error "XDP load failed completely"
            exit 1
        fi
    fi

    log_info "XDP program loaded successfully on $iface"

    # Pin maps for userspace access
    mkdir -p /sys/fs/bpf/aidn
    bpftool map pin name whitelist /sys/fs/bpf/aidn/whitelist 2>/dev/null || true
    bpftool map pin name blacklist /sys/fs/bpf/aidn/blacklist 2>/dev/null || true
    bpftool map pin name rate_limits /sys/fs/bpf/aidn/rate_limits 2>/dev/null || true
    bpftool map pin name stats /sys/fs/bpf/aidn/stats 2>/dev/null || true
    bpftool map pin name config /sys/fs/bpf/aidn/config 2>/dev/null || true
    bpftool map pin name events /sys/fs/bpf/aidn/events 2>/dev/null || true

    log_info "BPF maps pinned to /sys/fs/bpf/aidn/"
}

unload_xdp() {
    local iface="${1:-$(detect_interface)}"

    log_info "Unloading XDP program from interface: $iface"

    # Remove XDP program
    ip link set dev "$iface" xdp off 2>/dev/null || true
    ip link set dev "$iface" xdpgeneric off 2>/dev/null || true
    ip link set dev "$iface" xdpdrv off 2>/dev/null || true

    # Unpin maps
    rm -rf /sys/fs/bpf/aidn 2>/dev/null || true

    log_info "XDP program unloaded"
}

show_status() {
    local iface="${1:-$(detect_interface)}"

    echo "=============================================="
    echo "AIDN XDP Status"
    echo "=============================================="
    echo ""

    echo "Interface: $iface"
    ip link show "$iface" | grep -E "(xdp|state)"

    echo ""
    echo "BPF Programs:"
    bpftool prog list 2>/dev/null | grep -A2 "aidn" || echo "No AIDN programs loaded"

    echo ""
    echo "BPF Maps:"
    ls -la /sys/fs/bpf/aidn/ 2>/dev/null || echo "No maps pinned"

    echo ""
    echo "Statistics:"
    if [[ -e /sys/fs/bpf/aidn/stats ]]; then
        bpftool map dump pinned /sys/fs/bpf/aidn/stats 2>/dev/null || echo "Cannot read stats"
    fi
}

show_maps() {
    echo "=============================================="
    echo "AIDN XDP Maps"
    echo "=============================================="

    echo ""
    echo "Whitelist entries:"
    bpftool map dump pinned /sys/fs/bpf/aidn/whitelist 2>/dev/null | head -20 || echo "Empty or not loaded"

    echo ""
    echo "Blacklist entries:"
    bpftool map dump pinned /sys/fs/bpf/aidn/blacklist 2>/dev/null | head -20 || echo "Empty or not loaded"

    echo ""
    echo "Rate limit entries (sample):"
    bpftool map dump pinned /sys/fs/bpf/aidn/rate_limits 2>/dev/null | head -20 || echo "Empty or not loaded"
}

add_whitelist() {
    local ip="$1"
    if [[ -z "$ip" ]]; then
        log_error "IP address required"
        exit 1
    fi

    # Convert IP to hex for bpftool
    local hex_ip=$(printf '%02x %02x %02x %02x' $(echo "$ip" | tr '.' ' '))
    local timestamp=$(date +%s)

    log_info "Adding $ip to whitelist..."
    bpftool map update pinned /sys/fs/bpf/aidn/whitelist \
        key hex $hex_ip \
        value hex $(printf '%016x' $timestamp | sed 's/../& /g') 2>/dev/null

    if [[ $? -eq 0 ]]; then
        log_info "Added $ip to whitelist"
    else
        log_error "Failed to add to whitelist"
    fi
}

add_blacklist() {
    local ip="$1"
    local duration="${2:-3600}"  # Default 1 hour

    if [[ -z "$ip" ]]; then
        log_error "IP address required"
        exit 1
    fi

    local hex_ip=$(printf '%02x %02x %02x %02x' $(echo "$ip" | tr '.' ' '))
    local expiry=$(($(date +%s) + duration))

    log_info "Adding $ip to blacklist for ${duration}s..."
    bpftool map update pinned /sys/fs/bpf/aidn/blacklist \
        key hex $hex_ip \
        value hex $(printf '%016x' $expiry | sed 's/../& /g') 2>/dev/null

    if [[ $? -eq 0 ]]; then
        log_info "Added $ip to blacklist (expires in ${duration}s)"
    else
        log_error "Failed to add to blacklist"
    fi
}

remove_whitelist() {
    local ip="$1"
    if [[ -z "$ip" ]]; then
        log_error "IP address required"
        exit 1
    fi

    local hex_ip=$(printf '%02x %02x %02x %02x' $(echo "$ip" | tr '.' ' '))

    bpftool map delete pinned /sys/fs/bpf/aidn/whitelist key hex $hex_ip 2>/dev/null
    log_info "Removed $ip from whitelist"
}

remove_blacklist() {
    local ip="$1"
    if [[ -z "$ip" ]]; then
        log_error "IP address required"
        exit 1
    fi

    local hex_ip=$(printf '%02x %02x %02x %02x' $(echo "$ip" | tr '.' ' '))

    bpftool map delete pinned /sys/fs/bpf/aidn/blacklist key hex $hex_ip 2>/dev/null
    log_info "Removed $ip from blacklist"
}

print_usage() {
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  load [interface]        Load XDP program"
    echo "  unload [interface]      Unload XDP program"
    echo "  status [interface]      Show XDP status"
    echo "  maps                    Show map contents"
    echo "  whitelist-add IP        Add IP to whitelist"
    echo "  whitelist-del IP        Remove IP from whitelist"
    echo "  blacklist-add IP [sec]  Add IP to blacklist"
    echo "  blacklist-del IP        Remove IP from blacklist"
    echo ""
}

# Main
check_root

case "${1:-}" in
    load)
        load_xdp "$2"
        ;;
    unload)
        unload_xdp "$2"
        ;;
    status)
        show_status "$2"
        ;;
    maps)
        show_maps
        ;;
    whitelist-add)
        add_whitelist "$2"
        ;;
    whitelist-del)
        remove_whitelist "$2"
        ;;
    blacklist-add)
        add_blacklist "$2" "$3"
        ;;
    blacklist-del)
        remove_blacklist "$2"
        ;;
    *)
        print_usage
        ;;
esac
