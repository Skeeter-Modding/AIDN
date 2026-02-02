#!/bin/bash
#
# AIDN AI Defense Network - AI Components Installer
# Installs and configures the AI-powered DDoS protection system
#
# This script installs:
# - XDP/eBPF high-speed packet filter
# - AI traffic analysis engine
# - Real-time monitoring dashboard
# - Systemd services for automatic startup
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/aidn"
CONFIG_DIR="/etc/aidn"
DATA_DIR="/var/lib/aidn"
LOG_DIR="/var/log/aidn"

# Logging
log_info() { echo -e "${GREEN}[AIDN]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[AIDN]${NC} $1"; }
log_error() { echo -e "${RED}[AIDN]${NC} $1"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }

# Check root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Detect OS
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    else
        log_error "Cannot detect OS"
        exit 1
    fi
    log_info "Detected OS: $OS $OS_VERSION"
}

# Install dependencies
install_dependencies() {
    log_step "Installing dependencies..."

    case $OS in
        ubuntu|debian)
            apt-get update -qq

            # Essential packages
            apt-get install -y -qq \
                python3 \
                python3-pip \
                python3-venv \
                clang \
                llvm \
                libbpf-dev \
                linux-headers-$(uname -r) \
                bpftool \
                iproute2 \
                curl \
                jq

            # Python ML packages
            pip3 install --quiet \
                numpy \
                scikit-learn \
                scipy
            ;;

        centos|rhel|fedora)
            if command -v dnf &> /dev/null; then
                PKG_MGR="dnf"
            else
                PKG_MGR="yum"
            fi

            $PKG_MGR install -y -q \
                python3 \
                python3-pip \
                clang \
                llvm \
                libbpf-devel \
                kernel-headers \
                bpftool \
                iproute \
                curl \
                jq

            pip3 install --quiet \
                numpy \
                scikit-learn \
                scipy
            ;;

        *)
            log_error "Unsupported OS: $OS"
            exit 1
            ;;
    esac

    log_info "Dependencies installed"
}

# Create directories
create_directories() {
    log_step "Creating directories..."

    mkdir -p "$INSTALL_DIR"/{xdp,ai-engine,bin}
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$DATA_DIR"
    mkdir -p "$LOG_DIR"

    # Set permissions
    chmod 755 "$INSTALL_DIR"
    chmod 700 "$CONFIG_DIR"
    chmod 700 "$DATA_DIR"
    chmod 755 "$LOG_DIR"

    log_info "Directories created"
}

# Install XDP components
install_xdp() {
    log_step "Installing XDP/eBPF components..."

    # Copy XDP source
    cp -r "$SCRIPT_DIR/xdp/"* "$INSTALL_DIR/xdp/"

    # Compile XDP program
    cd "$INSTALL_DIR/xdp"

    if make check-deps 2>/dev/null; then
        log_info "Compiling XDP program..."
        if make; then
            log_info "XDP program compiled successfully"
        else
            log_warn "XDP compilation failed - will use fallback iptables"
        fi
    else
        log_warn "XDP dependencies not available - will use fallback iptables"
    fi

    # Make loader executable
    chmod +x "$INSTALL_DIR/xdp/loader.sh"

    cd "$SCRIPT_DIR"
}

# Install AI engine
install_ai_engine() {
    log_step "Installing AI engine..."

    # Copy AI engine files
    cp "$SCRIPT_DIR/ai-engine/"*.py "$INSTALL_DIR/ai-engine/"

    # Make executable
    chmod +x "$INSTALL_DIR/ai-engine/aidn_engine.py"
    chmod +x "$INSTALL_DIR/ai-engine/monitor.py"

    # Create symlinks
    ln -sf "$INSTALL_DIR/ai-engine/aidn_engine.py" "$INSTALL_DIR/bin/aidn-engine"
    ln -sf "$INSTALL_DIR/ai-engine/monitor.py" "$INSTALL_DIR/bin/aidn-monitor"

    log_info "AI engine installed"
}

# Install configuration
install_config() {
    log_step "Installing configuration..."

    # Only install config if not exists (preserve user changes)
    if [[ ! -f "$CONFIG_DIR/aidn.conf" ]]; then
        cp "$SCRIPT_DIR/config/aidn.conf" "$CONFIG_DIR/"
        log_info "Configuration installed to $CONFIG_DIR/aidn.conf"
    else
        log_info "Preserving existing configuration"
    fi
}

# Create systemd services
create_services() {
    log_step "Creating systemd services..."

    # AIDN XDP Service
    cat > /etc/systemd/system/aidn-xdp.service << 'EOF'
[Unit]
Description=AIDN XDP Packet Filter
After=network.target
Wants=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/opt/aidn/xdp/loader.sh load
ExecStop=/opt/aidn/xdp/loader.sh unload
ExecReload=/opt/aidn/xdp/loader.sh unload && /opt/aidn/xdp/loader.sh load

[Install]
WantedBy=multi-user.target
EOF

    # AIDN AI Engine Service
    cat > /etc/systemd/system/aidn-engine.service << 'EOF'
[Unit]
Description=AIDN AI Defense Engine
After=network.target aidn-xdp.service
Wants=aidn-xdp.service

[Service]
Type=simple
ExecStart=/opt/aidn/bin/aidn-engine run
Restart=always
RestartSec=5
User=root
WorkingDirectory=/opt/aidn

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/aidn /var/log/aidn /sys/fs/bpf
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd
    systemctl daemon-reload

    log_info "Systemd services created"
}

# Create management script
create_management_script() {
    log_step "Creating management script..."

    cat > "$INSTALL_DIR/bin/aidn" << 'SCRIPT'
#!/bin/bash
#
# AIDN - AI Defense Network Management Tool
#

INSTALL_DIR="/opt/aidn"
CONFIG_DIR="/etc/aidn"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

case "${1:-}" in
    start)
        echo "Starting AIDN..."
        systemctl start aidn-xdp
        systemctl start aidn-engine
        echo -e "${GREEN}AIDN started${NC}"
        ;;

    stop)
        echo "Stopping AIDN..."
        systemctl stop aidn-engine
        systemctl stop aidn-xdp
        echo -e "${YELLOW}AIDN stopped${NC}"
        ;;

    restart)
        echo "Restarting AIDN..."
        systemctl restart aidn-engine
        systemctl restart aidn-xdp
        echo -e "${GREEN}AIDN restarted${NC}"
        ;;

    status)
        echo "======================================"
        echo "AIDN Status"
        echo "======================================"
        echo ""
        echo "XDP Service:"
        systemctl status aidn-xdp --no-pager -l 2>/dev/null || echo "Not running"
        echo ""
        echo "AI Engine Service:"
        systemctl status aidn-engine --no-pager -l 2>/dev/null || echo "Not running"
        echo ""
        echo "XDP Program:"
        "$INSTALL_DIR/xdp/loader.sh" status 2>/dev/null || echo "Not loaded"
        ;;

    monitor)
        "$INSTALL_DIR/bin/aidn-monitor" "${@:2}"
        ;;

    whitelist)
        if [[ -z "$2" ]]; then
            echo "Usage: aidn whitelist <add|del|list> [IP]"
            exit 1
        fi
        case "$2" in
            add)
                "$INSTALL_DIR/xdp/loader.sh" whitelist-add "$3"
                ;;
            del)
                "$INSTALL_DIR/xdp/loader.sh" whitelist-del "$3"
                ;;
            list)
                "$INSTALL_DIR/xdp/loader.sh" maps | grep -A100 "Whitelist"
                ;;
        esac
        ;;

    blacklist)
        if [[ -z "$2" ]]; then
            echo "Usage: aidn blacklist <add|del|list> [IP] [duration]"
            exit 1
        fi
        case "$2" in
            add)
                "$INSTALL_DIR/xdp/loader.sh" blacklist-add "$3" "${4:-3600}"
                ;;
            del)
                "$INSTALL_DIR/xdp/loader.sh" blacklist-del "$3"
                ;;
            list)
                "$INSTALL_DIR/xdp/loader.sh" maps | grep -A100 "Blacklist"
                ;;
        esac
        ;;

    learning)
        if [[ "$2" == "on" ]]; then
            sed -i 's/^learning_mode = 0/learning_mode = 1/' "$CONFIG_DIR/aidn.conf"
            echo "Learning mode enabled - restart AIDN to apply"
        elif [[ "$2" == "off" ]]; then
            sed -i 's/^learning_mode = 1/learning_mode = 0/' "$CONFIG_DIR/aidn.conf"
            echo "Learning mode disabled - restart AIDN to apply"
        else
            grep "^learning_mode" "$CONFIG_DIR/aidn.conf"
        fi
        ;;

    logs)
        journalctl -u aidn-engine -f
        ;;

    stats)
        "$INSTALL_DIR/bin/aidn-monitor" --json
        ;;

    *)
        echo "AIDN - AI Defense Network"
        echo ""
        echo "Usage: aidn <command> [options]"
        echo ""
        echo "Commands:"
        echo "  start              Start AIDN protection"
        echo "  stop               Stop AIDN protection"
        echo "  restart            Restart AIDN"
        echo "  status             Show service status"
        echo "  monitor            Open monitoring dashboard"
        echo "  whitelist <cmd>    Manage whitelist (add/del/list)"
        echo "  blacklist <cmd>    Manage blacklist (add/del/list)"
        echo "  learning <on|off>  Toggle learning mode"
        echo "  logs               View live logs"
        echo "  stats              Show JSON statistics"
        echo ""
        echo "Examples:"
        echo "  aidn start"
        echo "  aidn whitelist add 192.168.1.100"
        echo "  aidn blacklist add 1.2.3.4 3600"
        echo "  aidn monitor"
        echo ""
        ;;
esac
SCRIPT

    chmod +x "$INSTALL_DIR/bin/aidn"
    ln -sf "$INSTALL_DIR/bin/aidn" /usr/local/bin/aidn

    log_info "Management script installed"
}

# Enable services
enable_services() {
    log_step "Enabling services..."

    read -p "Enable AIDN services to start on boot? [Y/n]: " -n 1 -r
    echo

    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        systemctl enable aidn-xdp
        systemctl enable aidn-engine
        log_info "Services enabled for automatic start"
    fi
}

# Start in learning mode
start_learning_mode() {
    log_step "Starting in learning mode..."

    read -p "Start AIDN in learning mode now? (recommended for first run) [Y/n]: " -n 1 -r
    echo

    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        # Enable learning mode in config
        sed -i 's/^learning_mode = 0/learning_mode = 1/' "$CONFIG_DIR/aidn.conf"

        # Start services
        systemctl start aidn-xdp 2>/dev/null || log_warn "XDP service start failed (may need recompilation)"
        systemctl start aidn-engine

        log_info "AIDN started in learning mode"
        log_info "The system will learn normal traffic patterns before enabling protection"
        log_info "Run 'aidn learning off && aidn restart' when ready to enable protection"
    fi
}

# Print summary
print_summary() {
    echo ""
    echo "=============================================="
    echo -e "${GREEN}AIDN AI Defense Network - Installation Complete${NC}"
    echo "=============================================="
    echo ""
    echo "Installation paths:"
    echo "  Programs:     $INSTALL_DIR"
    echo "  Config:       $CONFIG_DIR/aidn.conf"
    echo "  Data:         $DATA_DIR"
    echo "  Logs:         $LOG_DIR"
    echo ""
    echo "Management commands:"
    echo "  aidn start        - Start protection"
    echo "  aidn stop         - Stop protection"
    echo "  aidn status       - Check status"
    echo "  aidn monitor      - Open dashboard"
    echo "  aidn whitelist    - Manage trusted IPs"
    echo "  aidn blacklist    - Manage blocked IPs"
    echo ""
    echo "Services:"
    echo "  systemctl status aidn-xdp"
    echo "  systemctl status aidn-engine"
    echo ""
    echo -e "${YELLOW}IMPORTANT:${NC}"
    echo "  1. Edit $CONFIG_DIR/aidn.conf to configure game ports"
    echo "  2. Run 'aidn start' to begin protection"
    echo "  3. Start in learning mode for the first hour"
    echo "  4. Add your admin IP: aidn whitelist add YOUR_IP"
    echo ""
}

# Main
main() {
    echo ""
    echo "=============================================="
    echo "AIDN - AI Defense Network Installer"
    echo "=============================================="
    echo ""

    check_root
    detect_os

    echo ""
    echo "This will install the AIDN AI-powered DDoS protection system."
    echo ""
    read -p "Continue with installation? [Y/n]: " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Nn]$ ]]; then
        log_warn "Installation cancelled"
        exit 0
    fi

    install_dependencies
    create_directories
    install_xdp
    install_ai_engine
    install_config
    create_services
    create_management_script
    enable_services
    start_learning_mode
    print_summary
}

# Run
main "$@"
