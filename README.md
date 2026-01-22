# Debian 13 Enterprise Security Hardening Script

Attack surface reduction and security monitoring for Debian 13 servers designed for environments with professional security standards.

## Features

- **16 Modular Hardening Components** - Enable/disable specific security controls
- **Enterprise Compliance** - CIS Benchmark, BIO2 (Dutch Government), ISO 27001 alignment
- **SIEM Integration** - Wazuh agent with pre-configured monitoring
- **Threat Intelligence** - CrowdSec collaborative security with automatic IP blocking
- **Docker-Aware Firewall** - Native Docker networking support with UFW
- **Comprehensive Logging** - Detailed execution logs and compliance reports
- **Pre/Post Validation** - Automated security checks before and after hardening
- **Idempotent Design** - Safe to run multiple times
- **Backup Management** - Automatic backup of all modified configurations
- **Production Ready** - Suitable for both homelab and production environments
- **Interactive Firewall Manager** - User-friendly UFW management with templates

## Quick Start

```bash
# Download the script
wget https://raw.githubusercontent.com/yourusername/debian-hardening/main/debian13-hardening.sh

# Make it executable
chmod +x debian13-hardening.sh

# Run as root
sudo ./debian13-hardening.sh
```

## Hardening Modules

### 1. System Updates & Package Management
- Updates all system packages
- Installs security essentials (debsums, debsecan, apt-listchanges)
- **Compliance**: CIS 1.8, BIO2 12.6, ISO 27001 A.12.6.1

### 2. SSH Hardening
- Disables root login and password authentication
- Implements FIPS 140-2 compliant ciphers
- Configures key-based authentication only
- Removes weak host keys (DSA, ECDSA)
- Generates strong moduli (4096-bit)
- Sets connection limits and timeouts
- **Compliance**: CIS 5.2, BIO2 9.4, ISO 27001 A.9.4.2

### 3. Firewall Configuration (UFW)
- Default deny incoming policy
- Configures stateful firewall rules
- Implements SYN flood protection
- ICMP rate limiting
- Invalid packet dropping
- **Compliance**: CIS 3.5, BIO2 13.1, ISO 27001 A.13.1.3

### 4. Fail2Ban
- SSH brute-force protection
- Automatic IP banning after failed attempts
- Configurable ban times and retry limits
- Email notifications
- **Compliance**: CIS 4.2.4, BIO2 12.4, ISO 27001 A.12.4.1

### 5. Automatic Security Updates
- Unattended security patch installation
- Daily update checks
- Automatic cleanup of old packages
- Optional automatic reboots
- **Compliance**: CIS 1.8, BIO2 12.6, ISO 27001 A.12.6.1

### 6. Kernel Hardening (sysctl)
- Network stack hardening
- Disables IP forwarding (unless router)
- SYN cookies for SYN flood protection
- Reverse path filtering
- ASLR (Address Space Layout Randomization)
- Kernel pointer protection
- Core dump restrictions
- File system security enhancements
- **Compliance**: CIS 3.1-3.3, BIO2 12.6, ISO 27001 A.12.6.1

### 7. File System Security
- Secure permissions on sensitive files (/etc/shadow, /etc/passwd, etc.)
- Hardened cron directory permissions
- Removal of world-writable permissions
- SUID/SGID file auditing
- Disables uncommon file systems
- /tmp hardening with noexec, nosuid, nodev
- **Compliance**: CIS 1.1, BIO2 9.4, ISO 27001 A.9.4.5

### 8. User Account Policies
- Password complexity requirements (14+ chars, mixed case, numbers, symbols)
- Password aging (90-day maximum, 1-day minimum)
- Account lockout after 3 failed attempts
- Session timeout (15 minutes)
- Restrictive default umask (027)
- Inactive account reporting
- **Compliance**: CIS 5.4, BIO2 9.2, ISO 27001 A.9.2.1

### 9. Audit Logging (auditd)
- Comprehensive system call auditing
- User/group change monitoring
- Network configuration tracking
- Login/logout event logging
- Permission change auditing
- Privileged command monitoring
- File deletion tracking
- Kernel module loading surveillance
- **Compliance**: CIS 4.1, BIO2 12.4, ISO 27001 A.12.4.1

### 10. Rootkit Detection
- rkhunter installation and configuration
- chkrootkit deployment
- Daily automated scans
- Database updates
- **Compliance**: BIO2 12.2, ISO 27001 A.12.2.1

### 11. AppArmor (Mandatory Access Control)
- AppArmor profile enforcement
- Additional security profiles
- Application confinement
- **Compliance**: CIS 1.6, BIO2 9.4, ISO 27001 A.9.4.5

### 12. Process Accounting
- Command execution logging
- User activity tracking
- Process resource monitoring
- **Compliance**: ISO 27001 A.12.4.1

### 13. AIDE (File Integrity Monitoring)
- File integrity baseline creation
- Daily integrity checks
- Cryptographic hash verification
- Change detection and alerting
- **Compliance**: CIS 1.3, BIO2 12.4, ISO 27001 A.12.4.1

### 14. Wazuh Agent Integration (Optional)
- SIEM agent installation and configuration
- Pre-configured log monitoring
- System call auditing integration
- File integrity monitoring
- Security event correlation
- Connection to Wazuh manager
- Enhanced monitoring capabilities:
  - Authentication logs
  - System logs
  - UFW firewall logs
  - Network connections
  - User activity
  - Disk usage
- **Compliance**: BIO2 12.4, ISO 27001 A.12.4.1, A.12.4.3

**Configuration Required:**
- Set `ENABLE_WAZUH=1`
- Set `WAZUH_MANAGER_IP="192.168.1.100"` (your Wazuh manager IP)
- Optional: Set `WAZUH_REGISTRATION_PASSWORD` if using password authentication

### 15. CrowdSec Integration (Optional)
- Collaborative threat intelligence platform
- Automatic IP reputation checking
- Community-driven attack detection
- Integration with multiple log sources
- Firewall bouncer for automatic blocking
- Pre-configured collections:
  - Linux baseline security
  - SSH brute-force detection
  - Nginx attack patterns
  - Apache attack patterns
- Optional console enrollment for centralized management
- **Compliance**: BIO2 12.2, ISO 27001 A.12.2.1

**Configuration Required:**
- Set `ENABLE_CROWDSEC=1`
- Optional: Set `CROWDSEC_ENROLL_KEY="your-key"` for console integration
- Optional: Customize `CROWDSEC_COLLECTIONS` for specific scenarios

**Note**: CrowdSec and Fail2Ban provide similar functionality. If both are enabled, consider disabling Fail2Ban or configuring them for different services to avoid conflicts.

### 16. Docker-Aware Firewall Configuration (Optional)
- Automatic Docker installation and configuration
- Security-enhanced Docker daemon settings
- UFW configuration for Docker compatibility
- Docker bridge network integration
- Container-to-container communication control
- Container-to-host access management
- Published port management
- Security features:
  - Disabled inter-container communication (configurable)
  - No new privileges flag
  - Userland proxy disabled
  - Log rotation configured
  - Live restore enabled
- **Compliance**: CIS Docker Benchmark, ISO 27001 A.13.1.3

**Configuration Required:**
- Set `ENABLE_DOCKER_NETWORKING=1`
- Optional: Customize `DOCKER_NETWORK_CIDR` (default: 172.17.0.0/16)
- Optional: Set `DOCKER_ALLOW_INTERNAL=0` to block container-to-container communication
- Optional: Set `DOCKER_ALLOW_HOST_ACCESS=0` to block container-to-host access

## Configuration

Edit the script to enable/disable specific modules:

```bash
# Hardening modules - set to 1 to enable, 0 to disable
ENABLE_SYSTEM_UPDATES=1
ENABLE_SSH_HARDENING=1
ENABLE_FIREWALL=1
ENABLE_FAIL2BAN=1
ENABLE_AUTO_UPDATES=1
ENABLE_KERNEL_HARDENING=1
ENABLE_FILESYSTEM_SECURITY=1
ENABLE_USER_POLICIES=1
ENABLE_AUDIT_LOGGING=1
ENABLE_ROOTKIT_DETECTION=1
ENABLE_APPARMOR=1
ENABLE_PROCESS_ACCOUNTING=1
ENABLE_AIDE=1
```

## Output Files

All logs and reports are stored in `/var/log/debian13-hardening/`:

- `hardening-YYYYMMDD-HHMMSS.log` - Main execution log
- `compliance-report-YYYYMMDD-HHMMSS.txt` - Compliance framework mappings
- `hardening-summary.txt` - Executive summary
- `system-info.txt` - System information
- `security-vulnerabilities.txt` - Known vulnerabilities (debsecan output)
- `suid-sgid-files.txt` - SUID/SGID binary inventory
- `world-writable-files.txt` - World-writable files audit
- `inactive-users.txt` - Inactive user accounts
- `apparmor-status.txt` - AppArmor profile status

## Backups

All modified configuration files are backed up to:
```
/root/hardening-backups-YYYYMMDD-HHMMSS/
```

## Pre-Flight Checks

The script performs the following validations before execution:

1. **Root Privileges** - Ensures script runs as root
2. **Debian Version** - Verifies Debian 13 (warns on other versions)
3. **Disk Space** - Requires minimum 5GB free space
4. **Internet Connectivity** - Tests connection to debian.org
5. **Container Detection** - Warns if running in Docker/LXC

## Post-Flight Validation

After hardening, the script validates:

1. SSH service status
2. UFW firewall active state
3. Fail2Ban operational status
4. Auditd running verification
5. AppArmor enforcement
6. Security vulnerability scan
7. World-writable file check
8. System information collection

## Important Warnings

**CRITICAL**: This script makes significant security changes:

1. **SSH Access**: Password authentication is DISABLED
   - Ensure SSH key authentication is configured
   - Test SSH access in a NEW session before closing current session
   
2. **Root Login**: Direct root SSH login is DISABLED
   - Use sudo from a regular user account

3. **Firewall**: UFW will be enabled with default deny
   - Only SSH port will be allowed by default
   - Add additional rules for services before running

4. **Password Policies**: New password requirements apply
   - Minimum 14 characters
   - Must contain uppercase, lowercase, numbers, symbols

## Common Usecases

### Homelab Server Setup
```bash
# Full hardening for homelab infrastructure
sudo ./debian13-hardening.sh
```

### Selective Hardening
```bash
# Edit script to disable modules you don't need
# For example, disable AIDE for performance-sensitive systems
nano debian13-hardening.sh
# Set ENABLE_AIDE=0
sudo ./debian13-hardening.sh
```

### Development Server
```bash
# Consider disabling:
# - AIDE (performance impact)
# - Rootkit detection (false positives in dev)
# Keep all other security controls active
```

## Troubleshooting

### SSH Connection Issues
If you get locked out:

1. Access via console (KVM, IPMI, physical access)
2. Restore SSH config from backup:
   ```bash
   cp /root/hardening-backups-*/sshd_config.bak /etc/ssh/sshd_config
   systemctl restart sshd
   ```

### Firewall Blocking Services
```bash
# Check UFW status
sudo ufw status verbose

# Allow additional ports
sudo ufw allow 80/tcp comment 'HTTP'
sudo ufw allow 443/tcp comment 'HTTPS'

# Reload firewall
sudo ufw reload
```

### AIDE Database Initialization Slow
AIDE can take 15-30 minutes on first run. This is normal. To check progress:
```bash
tail -f /var/log/debian13-hardening/hardening-*.log
```

### Kernel Parameter Conflicts
If virtualization or containers don't work after hardening:
```bash
# Check current settings
sysctl -a | grep <parameter>

# Temporarily modify
sysctl -w <parameter>=<value>

# Permanent change
nano /etc/sysctl.d/99-hardening.conf
sysctl -p /etc/sysctl.d/99-hardening.conf
```

## Compliance Frameworks

### CIS Benchmark
This script implements numerous CIS Debian Linux Benchmark controls including:
- 1.1 - Filesystem configuration
- 1.3 - Filesystem integrity checking
- 1.6 - Mandatory access controls
- 1.8 - Software updates
- 3.1-3.5 - Network configuration
- 4.1 - Configure system accounting
- 4.2 - Configure logging
- 5.2 - SSH server configuration
- 5.4 - User accounts and environment

### ISO 27001:2013
Information security controls:
- A.9.2.1 - User registration and de-registration
- A.9.4.2 - Secure log-on procedures
- A.9.4.5 - Access control to program source code
- A.12.2.1 - Controls against malware
- A.12.4.1 - Event logging
- A.12.6.1 - Management of technical vulnerabilities
- A.13.1.3 - Segregation in networks

### BIO2 (Baseline Informatiebeveiliging Overheid)
Dutch government security baseline compliance:
- 9.2 - User access management
- 9.4 - Access control to systems and applications
- 12.2 - Protection from malware
- 12.4 - Logging and monitoring
- 12.6 - Technical vulnerability management
- 13.1 - Network security management

## Best Practices

1. **Test in Non-Production First** - Always test in a lab environment
2. **Backup Before Hardening** - The script creates backups, but have your own
3. **Document Customizations** - Keep notes on disabled modules and why
4. **Regular Reviews** - Run monthly to apply updates and scan for issues
5. **Monitor Logs** - Check `/var/log/debian13-hardening/` regularly
6. **Update Script** - Check for updates to the script periodically

## Post-Hardening Tasks

After running the script:

1. **Configure Additional Firewall Rules**
   
   **Option A: Manual Configuration**
   ```bash
   sudo ufw allow from 192.168.1.0/24 to any port 3000 comment 'Internal app'
   ```
   
   **Option B: Interactive UFW Manager (Recommended)**
   ```bash
   chmod +x ufw-manager.sh
   sudo ./ufw-manager.sh
   ```
   
   The UFW Manager provides:
   - Interactive menu-driven interface
   - Service templates for common applications
   - Docker-aware rule management
   - Source-based access control
   - Bulk operations for service stacks
   - Real-time Docker network integration
   - Rule import/export capabilities

2. **Set Up SSH Keys** (if not already done)
   ```bash
   ssh-keygen -t ed25519 -C "your_email@example.com"
   ssh-copy-id user@server
   ```

3. **Configure Email Alerts**
   ```bash
   # Install mail utilities
   apt install mailutils
   
   # Test notifications
   echo "Test" | mail -s "Test Alert" root@localhost
   ```

4. **Review Audit Rules**
   ```bash
   auditctl -l
   aureport --summary
   ```

5. **Schedule Regular Scans**
   ```bash
   # Already configured via cron.daily:
   # - rkhunter
   # - AIDE
   # - debsecan (via unattended-upgrades)
   ```

6. **Integrate with Monitoring**
   - Consider Prometheus node_exporter
   - Grafana dashboards
   - Centralized logging (Graylog, ELK stack)

## System Requirements

- **OS**: Debian 13 (Trixie) or compatible
- **Memory**: 2GB minimum (4GB recommended for AIDE)
- **Disk**: 5GB free space minimum
- **Network**: Internet connection for package downloads
- **Access**: Root or sudo privileges

## Performance Impact

Expected performance impact by module:

- **Low Impact**: SSH, Firewall, Fail2Ban, Auto Updates, User Policies
- **Medium Impact**: Kernel Hardening, Filesystem Security, AppArmor, Process Accounting
- **High Impact**: Audit Logging (continuous), AIDE (during scans), Rootkit Detection (during scans)

For performance-sensitive workloads, consider:
- Disabling AIDE or running scans during maintenance windows
- Reducing audit rule verbosity
- Adjusting rkhunter scan frequency

## Security Maintenance

### Weekly Tasks
- Review failed login attempts: `fail2ban-client status sshd`
- Check audit summaries: `aureport --summary`
- Review system logs: `journalctl -p err -b`

### Monthly Tasks
- Review AIDE reports
- Update rkhunter database: `rkhunter --update`
- Scan for vulnerabilities: `debsecan`
- Review SUID/SGID binaries
- Check for inactive user accounts

### Quarterly Tasks
- Review and update firewall rules
- Audit user permissions
- Review AppArmor profiles
- Test backup restoration
- Update hardening script

## Support

For issues or questions:
1. Check `/var/log/debian13-hardening/` logs
2. Review this README troubleshooting section
3. Restore from backups if needed: `/root/hardening-backups-*/`

## License

This script is provided as-is for educational and operational use. Modify as needed for your environment.

## Contributing

Improvements and suggestions welcome! Key areas:

- Additional CIS benchmark controls
- SELinux alternative to AppArmor
- Cloud provider-specific hardening
- Container-specific adaptations
- Additional compliance frameworks

## Credits

Developed by Securitypilot for enterprise-grade server security.

## Version History

- **1.0.0** (2026-01-22) - Initial release
  - 13 hardening modules
  - CIS, BIO2, ISO 27001 compliance
  - Comprehensive logging and validation


---

**Remember**: Security is a process, not a product. This script provides a strong foundation, but ongoing monitoring and updates are essential.
