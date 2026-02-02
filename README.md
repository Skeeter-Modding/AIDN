# AIDN - AI Defense Network

DDoS protection suite for dedicated game servers running Arma Reforger (and other game servers) in Docker containers.

## Overview

AIDN provides multiple layers of DDoS protection:

1. **Network-level filtering** (iptables/nftables) - Rate limiting, connection tracking, packet validation
2. **Kernel hardening** (sysctl) - TCP/UDP stack tuning against floods
3. **Application-level protection** (fail2ban) - Automatic IP banning based on log patterns
4. **Docker security** - Container isolation and resource limits
# AIDN

AI Defense Network to protect your dedicated servers.

## Features

- **SSH Hardening** - RSA key authentication, disabled password auth, non-standard ports
- **Firewall Management** - iptables with strict DROP policy, IP whitelisting
- **Fail2ban Integration** - Automatic IP banning for brute force and flood protection

## Quick Start

```bash
# Clone the repository
git clone https://github.com/your-repo/AIDN.git
cd AIDN

# Install with nftables (recommended)
sudo bash install.sh --nftables

# Or with iptables (legacy)
sudo bash install.sh --iptables

# Check status
aidn-status
```

## What This Protects Against

| Attack Type | Protection Level | Method |
|-------------|------------------|--------|
| SYN Flood | High | SYN cookies, rate limiting, connection limits |
| UDP Flood | High | Rate limiting per IP, hashlimit rules |
| ICMP Flood | High | ICMP rate limiting |
| Port Scanning | High | Detection and auto-ban |
| Slowloris | Medium | Connection timeouts, limits |
| Amplification | High | Anti-spoofing rules |
| Application Layer | Medium | fail2ban + log analysis |

## What This Does NOT Protect Against

- **Volumetric attacks exceeding your bandwidth** - If attackers send more traffic than your pipe can handle, you need upstream protection
- **Attacks targeting your hosting provider's infrastructure**
- **Sophisticated application-layer attacks** that mimic legitimate traffic

For these, you need **upstream DDoS protection** (see below).

## Configuration

### Firewall Ports

Edit the configuration files to match your server ports:

**For nftables** (`/etc/nftables.conf`):
```
define GAME_PORT = 2001
define STEAM_QUERY_PORT = 17777
define RCON_PORT = 19999
```

**For iptables** (`/usr/local/sbin/aidn-firewall.sh`):
```bash
GAME_PORT="2001"
STEAM_QUERY_PORT="17777"
RCON_PORT="19999"
```

### Whitelisting IPs

Add trusted IPs (your home IP, admin IPs) to bypass filtering:

**nftables:**
```
define WHITELIST = { 1.2.3.4, 5.6.7.8 }
```

**iptables:**
```bash
WHITELIST_IPS="1.2.3.4 5.6.7.8"
```

### Adjusting Rate Limits

If legitimate players are being rate-limited, increase the limits:

- `50/second` for game traffic is reasonable for most servers
- `10/second` for query traffic prevents query floods
- Adjust based on your player count and traffic patterns

## Directory Structure

```
AIDN/
├── firewall/
│   ├── iptables-ddos.rules    # iptables rules script
│   └── nftables-ddos.conf     # nftables configuration
├── sysctl/
│   └── 99-ddos-protection.conf # Kernel hardening
├── fail2ban/
│   ├── jail.d/
│   │   └── aidn-gameserver.conf # Jail configuration
│   └── filter.d/
│       ├── arma-reforger.conf   # Game server filter
│       ├── arma-rcon.conf       # RCON filter
│       ├── udp-flood.conf       # UDP flood detection
│       └── portscan.conf        # Port scan detection
├── docker/
│   ├── docker-compose.example.yml
│   └── daemon.json.example
├── install.sh                  # Installation script
└── README.md
```

## Commands

```bash
# Check protection status
aidn-status

# Unban an IP address
aidn-unban 192.168.1.100

# View banned IPs
fail2ban-client status

# View firewall rules
nft list ruleset          # nftables
iptables -L -n -v         # iptables

# View connection tracking
conntrack -L | head -20

# Monitor in real-time
watch -n1 'conntrack -C; ss -s'
```

## Upstream DDoS Protection (Recommended for Serious Deployments)

Local protection is good, but for serious game servers you should also consider upstream protection:

### Provider-Specific Protection

| Provider | Built-in Protection | Notes |
|----------|---------------------|-------|
| **OVH / SoYouStart / Kimsufi** | OVH Game DDoS Protection | Excellent for game servers, auto-enabled |
| **Hetzner** | Basic DDoS protection | Good baseline, may need additional |
| **Vultr** | DDoS protection add-on | Available for extra cost |
| **AWS** | AWS Shield | Standard is free, Advanced is $3k/month |

### Third-Party DDoS Protection Services

For dedicated upstream filtering:

| Service | Best For | Pricing | Notes |
|---------|----------|---------|-------|
| **Path.net** | Game servers | ~$50-200/mo | Excellent UDP protection, low latency |
| **Hyperfilter** | Game servers | ~$100-500/mo | Gaming-focused, good for Arma |
| **Cloudflare Spectrum** | TCP/UDP apps | ~$1/GB | Good but expensive for high traffic |
| **Voxility** | Dedicated servers | Varies | Raw upstream filtering |
| **Combahton** | Game servers | ~EUR50-200/mo | European focus |

### Recommendations by Scenario

**Small community server (< 32 players):**
- This AIDN setup is probably sufficient
- Consider OVH Game hosting for built-in protection

**Medium server (32-64 players):**
- AIDN + OVH/Hetzner built-in protection
- Consider Path.net if you get targeted

**Large/competitive server (64+ players, tournaments):**
- AIDN + Dedicated upstream provider (Path.net, Hyperfilter)
- Consider multiple server locations with anycast

**Under active attack:**
- Enable AIDN immediately
- Contact your hosting provider
- Consider emergency migration to OVH Game or Path.net

## Honeypots

Honeypots are **not useful for DDoS protection**. They are designed for:
- Detecting intrusion attempts
- Gathering threat intelligence
- Security research

For DDoS, focus on:
- Rate limiting (this project)
- Upstream filtering (cloud providers)
- Anycast/load balancing (for large deployments)

## Troubleshooting

### Legitimate players can't connect

1. Check if they're banned: `fail2ban-client status arma-reforger`
2. Unban them: `aidn-unban <their-ip>`
3. Whitelist persistent IPs in firewall config
4. Increase rate limits if needed

### High CPU usage

1. Check conntrack table: `conntrack -C`
2. If near max, increase: `net.netfilter.nf_conntrack_max`
3. Reduce timeouts in sysctl config

### fail2ban not banning

1. Check log paths match your setup
2. Verify log format matches filter regex
3. Test filter: `fail2ban-regex /path/to/log /etc/fail2ban/filter.d/arma-reforger.conf`

### Docker containers can't communicate

1. Ensure Docker networks are whitelisted in firewall
2. Check `docker0` and `br-*` interfaces are allowed

## Uninstall

```bash
sudo bash install.sh --uninstall
```

## License

MIT License - See LICENSE file

## Contributing

Pull requests welcome! Please test changes on a non-production server first.
git clone https://github.com/Skeeter-Modding/AIDN.git
cd AIDN

# Make scripts executable
chmod +x scripts/*.sh

# Run SSH hardening
./scripts/ssh-hardening.sh

# Setup firewall
./scripts/firewall-setup.sh setup

# Configure fail2ban
./scripts/fail2ban-setup.sh setup
```

## Scripts

| Script | Purpose |
|--------|---------|
| `scripts/ssh-hardening.sh` | Configure secure SSH with RSA key authentication |
| `scripts/firewall-setup.sh` | Setup iptables firewall with DROP policy |
| `scripts/fail2ban-setup.sh` | Configure fail2ban for SSH and game server protection |

## Documentation

See [docs/setup-guide.md](docs/setup-guide.md) for detailed setup instructions.

## Requirements

- Debian/Ubuntu Linux
- Root access
- RSA key pair for authentication

## License

See [LICENSE](LICENSE) for details.
