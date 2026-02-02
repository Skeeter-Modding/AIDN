# AIDN - AI Defense Network

**Real-time AI-powered DDoS protection for dedicated game servers.**

AIDN provides military-grade DDoS protection using XDP/eBPF for line-rate packet filtering (capable of handling 1Tbps+ attacks) combined with machine learning for intelligent threat detection that learns your players' behavior to avoid false positives.

## Features

### Multi-Layer Defense Architecture

| Layer | Technology | Capability |
|-------|------------|------------|
| **XDP/eBPF** | Kernel bypass filtering | 10+ million packets/sec, sub-microsecond latency |
| **AI Engine** | Machine learning | Anomaly detection, player behavior learning |
| **Adaptive Rate Limiting** | Real-time learning | Automatic threshold adjustment |
| **Traffic Fingerprinting** | Pattern recognition | Identifies attack tools vs legitimate players |
| **Kernel Hardening** | sysctl tuning | TCP/UDP stack optimization |
| **Application Layer** | fail2ban | Log-based pattern matching |

### What AIDN Protects Against

| Attack Type | Protection | Method |
|-------------|------------|--------|
| **SYN Flood** | ✅ Excellent | XDP rate limiting, SYN cookies |
| **UDP Flood** | ✅ Excellent | Per-IP rate limiting, ML detection |
| **ICMP Flood** | ✅ Excellent | Strict ICMP rate limiting |
| **Amplification** | ✅ Excellent | Anti-spoofing, source validation |
| **Port Scanning** | ✅ Excellent | Auto-detection and ban |
| **Slowloris** | ✅ Good | Connection limits, timeouts |
| **Application Layer** | ✅ Good | ML anomaly detection |
| **Botnet Attacks** | ✅ Good | Traffic fingerprinting |

### Player-Friendly Protection

AIDN is designed to **never ban legitimate players**:

- **Behavioral Learning**: Learns what normal player traffic looks like
- **Trust Scoring**: Players build trust over time through normal gameplay
- **Auto-Whitelisting**: Trusted players are automatically whitelisted
- **Confidence Thresholds**: Only blocks with 90%+ confidence
- **Adaptive Limits**: Rate limits adjust based on learned patterns

## Quick Start

```bash
# Clone the repository
git clone https://github.com/Skeeter-Modding/AIDN.git
cd AIDN

# Install base protection (firewall, fail2ban, kernel hardening)
sudo bash install.sh --nftables

# Install AI components (ML engine, XDP filter)
sudo bash install-ai.sh

# Start protection in learning mode
aidn start

# Add your admin IP to whitelist
aidn whitelist add YOUR_IP_ADDRESS
```

## Architecture

```
Internet Traffic
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│                    XDP/eBPF Filter                          │
│  • Line-rate packet processing (10+ Mpps)                   │
│  • Whitelist/Blacklist enforcement                          │
│  • Rate limiting per IP                                     │
│  • Invalid packet rejection                                 │
└─────────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│                  AI Traffic Analyzer                        │
│  • ML anomaly detection (Isolation Forest)                  │
│  • Player behavior tracking                                 │
│  • Attack signature matching                                │
│  • Adaptive rate limit tuning                               │
└─────────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│                    Kernel Stack                             │
│  • Hardened TCP/UDP (sysctl tuning)                         │
│  • Connection tracking                                      │
│  • SYN cookies                                              │
└─────────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│                  Game Server                                │
│  • Protected application                                    │
│  • Fail2ban log monitoring                                  │
└─────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
AIDN/
├── ai-engine/                  # AI/ML components
│   ├── aidn_engine.py         # Main AI engine
│   ├── fingerprint.py         # Traffic fingerprinting
│   └── monitor.py             # Real-time dashboard
├── xdp/                        # XDP/eBPF components
│   ├── aidn_xdp.c             # XDP packet filter
│   ├── loader.sh              # XDP loader script
│   └── Makefile               # Build system
├── config/                     # Configuration
│   └── aidn.conf              # Main config file
├── firewall/                   # Firewall rules
│   ├── iptables-ddos.rules    # iptables rules
│   └── nftables-ddos.conf     # nftables rules
├── fail2ban/                   # Fail2ban configs
│   ├── jail.d/                # Jail configurations
│   └── filter.d/              # Custom filters
├── sysctl/                     # Kernel tuning
│   └── 99-ddos-protection.conf
├── docker/                     # Docker configs
├── scripts/                    # Setup scripts
├── install.sh                  # Base installer
├── install-ai.sh              # AI components installer
└── README.md
```

## Commands

### Service Management

```bash
aidn start              # Start all protection
aidn stop               # Stop all protection
aidn restart            # Restart services
aidn status             # Check status
```

### IP Management

```bash
aidn whitelist add IP   # Add trusted IP
aidn whitelist del IP   # Remove from whitelist
aidn whitelist list     # Show whitelist

aidn blacklist add IP [seconds]  # Block IP
aidn blacklist del IP            # Unblock IP
aidn blacklist list              # Show blacklist
```

### Monitoring

```bash
aidn monitor            # Open real-time dashboard
aidn stats              # Show JSON statistics
aidn logs               # View live logs
```

### Learning Mode

```bash
aidn learning on        # Enable learning mode
aidn learning off       # Enable protection mode
```

## Configuration

Edit `/etc/aidn/aidn.conf`:

```ini
[network]
# Your game server ports
game_ports = 2001,2002,17777
query_port = 17777
rcon_port = 19999
ssh_port = 10022

[rate_limits]
# Packets per second limits per IP
global_pps = 10000
syn_pps = 100
udp_pps = 5000
game_traffic_multiplier = 5.0

[ai]
# ML confidence thresholds
confidence_rate_limit = 0.70
confidence_block = 0.90
auto_whitelist_threshold = 85

[player_protection]
# Avoid false positives
learn_players = 1
min_sessions_for_trust = 3
max_false_positive_rate = 0.001
```

## How the AI Works

### Learning Phase

1. AIDN starts in **learning mode** for the first hour
2. Collects baseline traffic patterns
3. Learns what normal player behavior looks like
4. Trains ML model on legitimate traffic

### Protection Phase

1. **Traffic Analysis**: Every packet is analyzed in real-time
2. **Anomaly Detection**: ML model scores traffic patterns
3. **Confidence Scoring**: Actions only taken with high confidence
4. **Trust System**: Known players get benefit of the doubt

### Avoiding False Positives

| Mechanism | Description |
|-----------|-------------|
| **Trust Scores** | Players earn trust through normal gameplay |
| **Session Learning** | Remembers legitimate player fingerprints |
| **Confidence Thresholds** | 90%+ confidence required to block |
| **Auto-Whitelist** | Trusted players automatically whitelisted |
| **Grace Periods** | New IPs get lenient treatment initially |

## Requirements

- **OS**: Debian 10+, Ubuntu 20.04+, RHEL/CentOS 8+
- **Kernel**: 5.0+ (for XDP native mode)
- **Python**: 3.8+
- **RAM**: 2GB+ recommended
- **Root access**

## Performance

| Metric | Value |
|--------|-------|
| Packet Processing | 10+ million pps |
| Latency (XDP) | < 1 microsecond |
| Memory (1M tracked IPs) | ~500 MB |
| CPU Impact | < 5% on modern hardware |
| Time to Block Attack | < 100ms |

## Troubleshooting

### Players getting blocked

```bash
# Check if player is banned
aidn blacklist list | grep PLAYER_IP

# Unban player
aidn blacklist del PLAYER_IP

# Add to permanent whitelist
aidn whitelist add PLAYER_IP
```

### High CPU usage

```bash
# Check connection tracking
conntrack -C

# If near max, increase limit in sysctl
sysctl -w net.netfilter.nf_conntrack_max=2000000
```

### XDP not loading

```bash
# Check XDP status
aidn status

# Try generic mode (slower but compatible)
# Edit /etc/aidn/aidn.conf: mode = generic
aidn restart
```

## Upstream Protection

For attacks exceeding your bandwidth, consider:

| Provider | Best For | Notes |
|----------|----------|-------|
| **OVH Game** | Game servers | Excellent built-in DDoS protection |
| **Path.net** | UDP games | Low latency, gaming focused |
| **Hyperfilter** | Competitive | High-end game protection |

For support go to discord.gg/triplethreat  and look for Skeeter
## License

Apache 2.0 - See [LICENSE](LICENSE)

## Contributing

Pull requests welcome! Please test on non-production servers first.
