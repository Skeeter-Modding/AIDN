# AIDN Server Security Setup Guide

This guide covers setting up SSH RSA key authentication, firewall configuration, and fail2ban protection for dedicated Linux servers.

## Prerequisites

- Debian/Ubuntu-based Linux server
- Root access
- RSA key pair generated (PuTTYgen or ssh-keygen)

## 1. SSH Hardening

### Generate RSA Keys (Client Side)

**Using PuTTYgen (Windows):**
1. Open PuTTYgen
2. Select RSA, 4096 bits
3. Click Generate and move mouse to create randomness
4. Save private key (.ppk)
5. Copy the public key text

**Using ssh-keygen (Linux/Mac):**
```bash
ssh-keygen -t rsa -b 4096 -C "your-email@example.com"
```

### Deploy Public Key to Server

```bash
# Create .ssh directory
mkdir -p ~/.ssh
chmod 700 ~/.ssh

# Add your public key
echo "ssh-rsa AAAA...your-key..." >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

### Run SSH Hardening Script

```bash
cd /path/to/AIDN
chmod +x scripts/ssh-hardening.sh

# Set custom SSH port (optional)
export SSH_PORT=10022

# Run the script
./scripts/ssh-hardening.sh
```

This script will:
- Configure SSH on a non-standard port (default: 10022)
- Disable password authentication
- Enable RSA key authentication only
- Set strict security parameters
- Backup your existing configuration

### Verify SSH Access

**Before closing your current session**, open a new terminal and test:

```bash
ssh -p 10022 -i /path/to/private_key root@your-server-ip
```

## 2. Firewall Configuration

### Run Firewall Setup

```bash
chmod +x scripts/firewall-setup.sh
./scripts/firewall-setup.sh setup
```

The interactive setup will ask for:
- SSH port number
- Your admin IP address (whitelisted for full access)

### Firewall Quick Commands

```bash
# Allow an IP full access
./scripts/firewall-setup.sh allow-ip 192.168.1.100 "Home"

# Block an IP
./scripts/firewall-setup.sh block-ip 1.2.3.4 "Attacker"

# Allow a specific port
./scripts/firewall-setup.sh allow-port 8080

# Show current rules
./scripts/firewall-setup.sh show

# Save rules (persist across reboots)
./scripts/firewall-setup.sh save
```

### Default Policy

The firewall uses a **DROP** policy by default:
- All incoming traffic is blocked unless explicitly allowed
- Your admin IP has full access
- SSH port is open to all (protected by fail2ban)
- Outbound traffic is allowed

## 3. Fail2ban Protection

### Run Fail2ban Setup

```bash
chmod +x scripts/fail2ban-setup.sh
./scripts/fail2ban-setup.sh setup
```

This configures:
- **sshd** jail - Protects against SSH brute force
- **sshd-ddos** jail - Protects against SSH connection floods
- **recidive** jail - Extended bans for repeat offenders

### Fail2ban Quick Commands

```bash
# Check status
./scripts/fail2ban-setup.sh status

# Ban an IP manually
./scripts/fail2ban-setup.sh ban 1.2.3.4 sshd

# Unban an IP
./scripts/fail2ban-setup.sh unban 1.2.3.4

# Restart fail2ban
./scripts/fail2ban-setup.sh restart
```

### Game Server Protection (Arma Reforger)

The setup script can optionally configure protection for Arma Reforger servers:
- Connection flood detection
- RCON brute force protection
- Automatic IP banning

## Security Checklist

- [ ] RSA key authentication configured
- [ ] Password authentication disabled
- [ ] SSH on non-standard port
- [ ] Firewall DROP policy enabled
- [ ] Admin IP whitelisted
- [ ] Fail2ban active and protecting SSH
- [ ] Regular rules saved for persistence

## Troubleshooting

### Locked Out?

If you lose access:
1. Use server provider's console/VNC access
2. Restore SSH config: `cp /etc/ssh/sshd_config.backup.* /etc/ssh/sshd_config`
3. Restart SSH: `systemctl restart sshd`

### Check Fail2ban Bans

```bash
# See banned IPs
fail2ban-client status sshd

# Unban yourself
fail2ban-client set sshd unbanip YOUR_IP
```

### Firewall Issues

```bash
# List all rules
iptables -L -n -v --line-numbers

# Flush rules (emergency - opens everything)
iptables -F
iptables -P INPUT ACCEPT
```

## File Locations

| Component | Config Location |
|-----------|-----------------|
| SSH | `/etc/ssh/sshd_config` |
| Firewall rules | `/etc/iptables/rules.v4` |
| Fail2ban jails | `/etc/fail2ban/jail.local` |
| AIDN config | `/etc/aidn/firewall.conf` |
