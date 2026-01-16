# AIDN

AI Defense Network to protect your dedicated servers.

## Features

- **SSH Hardening** - RSA key authentication, disabled password auth, non-standard ports
- **Firewall Management** - iptables with strict DROP policy, IP whitelisting
- **Fail2ban Integration** - Automatic IP banning for brute force and flood protection

## Quick Start

```bash
# Clone the repository
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
