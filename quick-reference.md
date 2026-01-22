# Debian 13 Hardening - Quick Reference Guide

## Daily Operations

### Check System Security Status
```bash
# SSH service
systemctl status sshd

# Firewall status
ufw status verbose

# Fail2Ban status
fail2ban-client status
fail2ban-client status sshd

# Audit daemon
systemctl status auditd
auditctl -l | head -20

# AppArmor status
aa-status
```

### Monitor Failed Login Attempts
```bash
# Recent failed SSH attempts
grep "Failed password" /var/log/auth.log | tail -20

# Fail2Ban banned IPs
fail2ban-client status sshd

# Unban an IP (if needed)
fail2ban-client set sshd unbanip 192.168.1.100
```

### Review Security Logs
```bash
# Recent authentication events
journalctl -u ssh -n 50

# System errors
journalctl -p err -b

# Audit summary
aureport --summary --start today

# Recent audit events
ausearch -ts today -m USER_LOGIN
```

## Firewall Management

### View Current Rules
```bash
# UFW status
ufw status numbered

# Raw iptables rules
iptables -L -n -v
```

### Add New Rules
```bash
# Allow specific port
ufw allow 8080/tcp comment 'Application Server'

# Allow from specific IP
ufw allow from 192.168.1.0/24 to any port 3306 comment 'MySQL - Internal'

# Allow service by name
ufw allow http
ufw allow https

# Deny specific IP
ufw deny from 203.0.113.0

# Delete rule by number
ufw status numbered
ufw delete [number]
```

### Port Ranges
```bash
# Allow port range
ufw allow 8000:8100/tcp comment 'Development services'

# Application profile
ufw app list
ufw allow 'Apache Full'
```

## SSH Key Management

### Generate New SSH Key
```bash
# Ed25519 (recommended)
ssh-keygen -t ed25519 -C "your_email@example.com"

# RSA 4096-bit (legacy compatibility)
ssh-keygen -t rsa -b 4096 -C "your_email@example.com"
```

### Add Key to Server
```bash
# From local machine
ssh-copy-id -i ~/.ssh/id_ed25519.pub user@server

# Manual method (on server)
cat >> ~/.ssh/authorized_keys << 'EOF'
ssh-ed25519 AAAAC3... your_email@example.com
EOF
chmod 600 ~/.ssh/authorized_keys
```

### Test SSH Configuration
```bash
# Test config without restarting
sshd -t

# View effective SSH configuration
sshd -T

# Check specific user's SSH config
sshd -T -C user=username
```

## Audit System

### Generate Audit Reports
```bash
# Summary report
aureport --summary

# Failed login attempts
aureport --login --failed

# Authentication report
aureport --auth

# File access report
aureport --file

# User command execution
aureport --executable

# Time-based report (last 24 hours)
aureport --start yesterday --end today
```

### Search Audit Logs
```bash
# Search by event type
ausearch -m USER_LOGIN

# Search by user
ausearch -ua username

# Search by file
ausearch -f /etc/passwd

# Search time range
ausearch --start today --end now

# Search for failed events
ausearch --success no
```

### Custom Audit Rules
```bash
# Add temporary rule (lost on reboot)
auditctl -w /etc/shadow -p wa -k shadow_changes

# Make permanent (add to /etc/audit/rules.d/custom.rules)
echo "-w /etc/shadow -p wa -k shadow_changes" >> /etc/audit/rules.d/custom.rules
augenrules --load

# List current rules
auditctl -l

# Delete all rules (temporary)
auditctl -D
```

## File Integrity Monitoring (AIDE)

### Manual AIDE Operations
```bash
# Run integrity check
aide --check

# Update database after legitimate changes
aide --update
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Compare two databases
aide --compare

# Initialize new database
aideinit
```

### AIDE Configuration
```bash
# Edit AIDE config
nano /etc/aide/aide.conf

# Common exclusions (add to config)
!/var/log
!/var/cache
!/var/tmp
!/home/.cache
```

## Rootkit Detection

### rkhunter Operations
```bash
# Manual scan
rkhunter --check --skip-keypress

# Update database
rkhunter --update
rkhunter --propupd

# Check specific item
rkhunter --check /usr/bin/suspicious-file

# View warnings
rkhunter --check --report-warnings-only
```

### chkrootkit
```bash
# Run full check
chkrootkit

# Check specific rootkit
chkrootkit -q rootkit_name

# Expert mode (less false positives)
chkrootkit -x
```

## User Account Management

### Password Management
```bash
# Force password change at next login
passwd -e username

# Lock account
passwd -l username

# Unlock account
passwd -u username

# Set password expiry
chage -M 90 username
chage -m 1 username
chage -W 14 username

# View password status
chage -l username
```

### Account Lockout Management
```bash
# View failed login attempts
faillock --user username

# Reset failed attempts
faillock --user username --reset

# Global reset
faillock --reset
```

### User Activity Monitoring
```bash
# Currently logged in users
w

# Login history
last -20

# Failed login attempts
lastb -20

# Last login per user
lastlog

# User activity statistics
ac -p
```

## Process Accounting

### View Process Statistics
```bash
# Summary of commands run
sa -u

# Per-user statistics
sa -m

# Most used commands
sa -c

# Detailed accounting
lastcomm

# Specific user's commands
lastcomm username
```

## Kernel Security Parameters

### View Current Settings
```bash
# All kernel parameters
sysctl -a

# Security-related parameters
sysctl -a | grep -E "(randomize|dmesg|kptr|ptrace)"

# Network parameters
sysctl -a | grep net.ipv4

# Specific parameter
sysctl kernel.randomize_va_space
```

### Modify Parameters
```bash
# Temporary change (until reboot)
sysctl -w net.ipv4.ip_forward=0

# Permanent change
echo "net.ipv4.ip_forward=0" >> /etc/sysctl.d/99-custom.conf
sysctl -p /etc/sysctl.d/99-custom.conf

# Reload all sysctl configs
sysctl --system
```

## AppArmor Management

### Profile Management
```bash
# List loaded profiles
aa-status

# Set profile to complain mode (permissive)
aa-complain /etc/apparmor.d/usr.bin.application

# Set profile to enforce mode
aa-enforce /etc/apparmor.d/usr.bin.application

# Disable profile
aa-disable /etc/apparmor.d/usr.bin.application

# Reload profile
apparmor_parser -r /etc/apparmor.d/usr.bin.application
```

### Troubleshoot AppArmor
```bash
# View AppArmor denials
grep "DENIED" /var/log/syslog | tail -20

# Generate profile for application
aa-genprof /usr/bin/application

# Update existing profile
aa-logprof

# Scan logs for violations
aa-notify -s 1 -v
```

## Package Security

### Vulnerability Scanning
```bash
# Scan for known vulnerabilities
debsecan

# Detailed vulnerability report
debsecan --suite=trixie --format=detail

# Only show high priority
debsecan --suite=trixie | grep "urgency=high"
```

### Package Verification
```bash
# Verify installed package checksums
debsums -c

# Check specific package
debsums -c openssh-server

# Generate checksums for packages without them
debsums -g
```

### Security Updates
```bash
# List available security updates
apt list --upgradable | grep security

# Install security updates only
unattended-upgrades --dry-run
unattended-upgrades

# Check last update time
stat /var/lib/apt/periodic/update-success-stamp
```

## System Hardening Verification

### Quick Security Checklist
```bash
#!/bin/bash
# Save as: security-check.sh

echo "=== Security Status Check ==="
echo ""

echo "[SSH]"
systemctl is-active sshd && echo "✓ SSH running" || echo "✗ SSH not running"
grep "PasswordAuthentication no" /etc/ssh/sshd_config.d/99-hardening.conf &>/dev/null && echo "✓ Password auth disabled" || echo "✗ Password auth enabled"

echo ""
echo "[Firewall]"
ufw status | grep -q "Status: active" && echo "✓ UFW active" || echo "✗ UFW inactive"

echo ""
echo "[Fail2Ban]"
systemctl is-active fail2ban && echo "✓ Fail2Ban running" || echo "✗ Fail2Ban not running"

echo ""
echo "[Audit]"
systemctl is-active auditd && echo "✓ Auditd running" || echo "✗ Auditd not running"

echo ""
echo "[AppArmor]"
aa-enabled 2>/dev/null && echo "✓ AppArmor enabled" || echo "✗ AppArmor disabled"

echo ""
echo "[Updates]"
systemctl is-enabled unattended-upgrades &>/dev/null && echo "✓ Auto-updates enabled" || echo "✗ Auto-updates disabled"
```

### Network Security Scan
```bash
# Check listening ports
ss -tulpn

# Identify services
netstat -tulpn | grep LISTEN

# Check for suspicious connections
ss -tan state established

# Network statistics
netstat -s
```

## Emergency Procedures

### Restore from Backup
```bash
# Find backup directory
ls -ld /root/hardening-backups-*

# List backups
ls -lh /root/hardening-backups-YYYYMMDD-HHMMSS/

# Restore SSH config
cp /root/hardening-backups-*/sshd_config.bak /etc/ssh/sshd_config
systemctl restart sshd

# Restore sysctl
cp /root/hardening-backups-*/sysctl.conf.bak /etc/sysctl.conf
sysctl -p
```

### Temporary Security Relaxation
```bash
# Temporarily allow password SSH (emergency access)
cat >> /etc/ssh/sshd_config.d/99-emergency.conf << EOF
PasswordAuthentication yes
EOF
systemctl restart sshd
# REMEMBER TO REMOVE THIS FILE LATER!

# Temporarily disable firewall (troubleshooting)
ufw disable
# DO NOT FORGET TO RE-ENABLE: ufw enable

# Stop Fail2Ban (if blocking legitimate access)
systemctl stop fail2ban
# Remember to restart: systemctl start fail2ban
```

### Security Incident Response
```bash
# 1. Check for active threats
ps aux | grep -E "(nc|netcat|nmap)"
ss -tulpn | grep -v "127.0.0.1"

# 2. Review recent logins
last -20
lastb -20

# 3. Check for new users
awk -F: '$3 >= 1000 {print $1}' /etc/passwd

# 4. Review sudo usage
grep sudo /var/log/auth.log | tail -50

# 5. Check for modified system files
debsums -c -s

# 6. Review audit logs
ausearch --start recent -i

# 7. Check scheduled tasks
crontab -l
ls -la /etc/cron.*
```

## Performance Monitoring

### Resource Usage
```bash
# CPU and memory usage
top -b -n 1 | head -20

# Disk usage
df -h

# Inode usage
df -i

# Disk I/O
iostat -x 2 5

# Memory details
free -h
cat /proc/meminfo
```

### Security Service Impact
```bash
# Audit system overhead
auditctl -s

# AppArmor profile count
aa-status --profiled

# Fail2Ban statistics
fail2ban-client status
```

## Compliance Reporting

### Generate Compliance Report
```bash
#!/bin/bash
# compliance-report.sh

REPORT_FILE="compliance-report-$(date +%Y%m%d).txt"

cat > "$REPORT_FILE" <<EOF
Security Compliance Report
Generated: $(date)
Hostname: $(hostname)
Kernel: $(uname -r)

=== CIS Benchmark Checks ===

[1.1] Filesystem Configuration
$(mount | grep -E "(nodev|nosuid|noexec)")

[4.1] Auditd Status
$(systemctl is-active auditd)

[5.2] SSH Configuration
$(grep -E "^(Protocol|PermitRootLogin|PasswordAuthentication)" /etc/ssh/sshd_config.d/99-hardening.conf)

[5.4] Password Policy
$(grep -E "^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE)" /etc/login.defs)

=== Security Services ===
SSH: $(systemctl is-active sshd)
Firewall: $(ufw status | grep Status)
Fail2Ban: $(systemctl is-active fail2ban)
Auditd: $(systemctl is-active auditd)
AppArmor: $(aa-enabled && echo "enabled" || echo "disabled")

=== Recent Security Events ===
$(ausearch --start today --summary 2>/dev/null | head -20)

=== Known Vulnerabilities ===
$(debsecan 2>/dev/null | wc -l) vulnerabilities found

EOF

echo "Report generated: $REPORT_FILE"
cat "$REPORT_FILE"
```

## Maintenance Scripts

### Weekly Maintenance
```bash
#!/bin/bash
# weekly-maintenance.sh

echo "=== Weekly Security Maintenance ==="
echo "Date: $(date)"
echo ""

echo "1. Updating package lists..."
apt update -qq

echo "2. Checking for security updates..."
apt list --upgradable 2>/dev/null | grep -i security

echo "3. Reviewing failed logins..."
lastb -5

echo "4. Checking disk space..."
df -h | grep -E "(Filesystem|/dev/)"

echo "5. Reviewing audit summary..."
aureport --summary --start this-week 2>/dev/null

echo "6. Checking banned IPs..."
fail2ban-client status sshd

echo "7. Updating rkhunter..."
rkhunter --update --quiet

echo ""
echo "=== Maintenance Complete ==="
```

## Log Rotation Management

### Configure Log Rotation
```bash
# Create custom logrotate config
cat > /etc/logrotate.d/security-logs <<EOF
/var/log/debian13-hardening/*.log {
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
}
EOF

# Test logrotate
logrotate -d /etc/logrotate.d/security-logs

# Force rotation
logrotate -f /etc/logrotate.conf
```

---

**Quick Command Reference Card**

```
# Service Status
systemctl status sshd|fail2ban|auditd

# View Logs  
journalctl -u <service> -n 50
aureport --summary

# Firewall
ufw status numbered
ufw allow <port>/tcp

# Failed Logins
lastb -20
fail2ban-client status sshd

# Security Scans
debsecan
rkhunter --check
aide --check

# User Management
passwd -e <user>
chage -l <user>

# Backups
ls /root/hardening-backups-*
```

Save this file and refer to it for daily operations!
