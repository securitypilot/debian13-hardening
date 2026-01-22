# Wazuh & CrowdSec Operations Guide

## Wazuh Agent Management

### Prerequisites
- Wazuh Manager installed and running (separate server)
- Network connectivity to Wazuh Manager on port 1514 (default)
- Optional: Wazuh Console enrollment key

### Configuration

Before enabling Wazuh in the hardening script, set these variables:

```bash
ENABLE_WAZUH=1
WAZUH_MANAGER_IP="192.168.1.100"  # Your Wazuh manager IP
WAZUH_MANAGER_PORT="1514"         # Default Wazuh port
WAZUH_REGISTRATION_PASSWORD=""    # Optional: agent registration password
```

### Post-Installation Verification

```bash
# Check Wazuh agent status
systemctl status wazuh-agent

# View agent configuration
cat /var/ossec/etc/ossec.conf

# Check agent logs
tail -f /var/ossec/logs/ossec.log

# Verify connection to manager
grep "Connected to" /var/ossec/logs/ossec.log
```

### Agent Management Commands

```bash
# Start agent
systemctl start wazuh-agent

# Stop agent
systemctl stop wazuh-agent

# Restart agent
systemctl restart wazuh-agent

# View agent info
/var/ossec/bin/agent-control -i

# Get agent authentication key
cat /var/ossec/etc/client.keys
```

### Manual Agent Registration

If automatic registration fails:

```bash
# On Wazuh Manager server
/var/ossec/bin/manage_agents
# Follow prompts to add agent
# Extract agent key

# On Agent (this server)
/var/ossec/bin/manage_agents
# Import the key
systemctl restart wazuh-agent
```

### Monitored Logs (Default Configuration)

The hardening script configures monitoring for:
- `/var/log/auth.log` - Authentication events
- `/var/log/syslog` - System logs
- `/var/log/ufw.log` - Firewall logs
- Disk usage (every 6 hours)
- Network listening ports (every 6 hours)
- Recent logins (every 6 hours)

### Adding Custom Log Monitoring

Edit `/var/ossec/etc/ossec.conf`:

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/custom-app.log</location>
</localfile>
```

Then restart the agent:
```bash
systemctl restart wazuh-agent
```

### Wazuh Agent on Docker Hosts

If Docker is installed, additional monitoring capabilities:

```bash
# Add Docker socket monitoring (advanced)
cat >> /var/ossec/etc/ossec.conf <<'EOF'
<localfile>
  <log_format>full_command</log_format>
  <command>docker ps --format "{{.Names}}\t{{.Status}}\t{{.Ports}}"</command>
  <alias>docker containers</alias>
  <frequency>300</frequency>
</localfile>
EOF

systemctl restart wazuh-agent
```

### Troubleshooting Wazuh

**Agent not connecting:**
```bash
# Check network connectivity
telnet ${WAZUH_MANAGER_IP} 1514

# Check firewall on manager
# On Wazuh Manager:
firewall-cmd --list-ports  # Should include 1514/tcp

# Check agent logs for errors
tail -50 /var/ossec/logs/ossec.log
```

**Agent key issues:**
```bash
# Verify key exists
cat /var/ossec/etc/client.keys

# Re-register if needed (see Manual Agent Registration above)
```

**Performance impact:**
```bash
# Check agent resource usage
ps aux | grep wazuh
top -p $(pgrep -d',' wazuh)

# Adjust monitoring frequency in ossec.conf if needed
```

### Wazuh Dashboard Integration

Access your Wazuh dashboard (typically https://wazuh-manager:443) to:
- View security events in real-time
- Monitor agent health
- Create custom rules and decoders
- Generate compliance reports
- Configure alerting

---

## CrowdSec Management

### Prerequisites
- Internet connectivity to CrowdSec API
- Optional: CrowdSec Console account for centralized management

### Configuration

Before enabling CrowdSec in the hardening script:

```bash
ENABLE_CROWDSEC=1
CROWDSEC_ENROLL_KEY=""  # Optional: Get from https://app.crowdsec.net
CROWDSEC_COLLECTIONS="crowdsecurity/linux crowdsecurity/sshd"
```

### Post-Installation Verification

```bash
# Check CrowdSec status
systemctl status crowdsec

# Check bouncer status
systemctl status crowdsec-firewall-bouncer-nftables
# or
systemctl status crowdsec-firewall-bouncer-iptables

# View CrowdSec metrics
cscli metrics

# List installed collections
cscli collections list

# View active decisions (bans)
cscli decisions list
```

### CrowdSec CLI (cscli) Commands

**Hub Management:**
```bash
# Update hub
cscli hub update

# List available collections
cscli collections list -a

# Install collection
cscli collections install crowdsecurity/nginx

# Remove collection
cscli collections remove crowdsecurity/apache2

# Upgrade all
cscli hub upgrade
```

**Scenarios (Detection Rules):**
```bash
# List scenarios
cscli scenarios list

# Install specific scenario
cscli scenarios install crowdsecurity/ssh-bf

# Inspect scenario
cscli scenarios inspect crowdsecurity/ssh-bf
```

**Parsers (Log Processors):**
```bash
# List parsers
cscli parsers list

# Install parser
cscli parsers install crowdsecurity/syslog-logs
```

**Decision Management:**
```bash
# View all decisions (bans)
cscli decisions list

# View decisions for specific IP
cscli decisions list --ip 1.2.3.4

# View decisions by type
cscli decisions list --type ban

# Delete decision (unban)
cscli decisions delete --ip 1.2.3.4

# Delete all decisions
cscli decisions delete --all

# Add manual ban
cscli decisions add --ip 1.2.3.4 --duration 24h --reason "Manual ban"

# Ban IP range
cscli decisions add --range 1.2.3.0/24 --duration 48h --reason "Malicious subnet"
```

**Alerts:**
```bash
# View alerts
cscli alerts list

# View alert details
cscli alerts inspect [alert-id]

# Flush old alerts
cscli alerts flush
```

**Machine Management:**
```bash
# List machines (agents)
cscli machines list

# Add new machine
cscli machines add [machine-name]

# Delete machine
cscli machines delete [machine-name]
```

**Bouncer Management:**
```bash
# List bouncers
cscli bouncers list

# Add bouncer
cscli bouncers add [bouncer-name]

# Delete bouncer
cscli bouncers delete [bouncer-name]
```

### CrowdSec Console Integration

Enroll with CrowdSec Console for:
- Centralized management
- Multi-instance overview
- Threat intelligence sharing
- Advanced analytics

```bash
# Enroll (if not done during installation)
cscli console enroll [your-enrollment-key]

# Check enrollment status
cscli console status
```

Get your enrollment key from: https://app.crowdsec.net

### Monitored Logs (Default Configuration)

The hardening script configures:
- `/var/log/auth.log` - SSH attacks
- `/var/log/syslog` - System events
- `/var/log/ufw.log` - Firewall logs
- `/var/log/nginx/*.log` - Web attacks (if Nginx present)
- `/var/log/apache2/*.log` - Web attacks (if Apache present)

### Custom Log Sources

Edit `/etc/crowdsec/acquis.yaml`:

```yaml
---
filenames:
  - /var/log/myapp/*.log
labels:
  type: syslog
```

Then reload CrowdSec:
```bash
systemctl reload crowdsec
```

### Integration with Fail2Ban

If both CrowdSec and Fail2Ban are enabled:

**Option 1: Disable Fail2Ban**
```bash
systemctl stop fail2ban
systemctl disable fail2ban
```

**Option 2: Configure for different services**
- Use Fail2Ban for SSH only
- Use CrowdSec for web services, database, etc.

**Option 3: Use CrowdSec exclusively (recommended)**
CrowdSec provides more advanced features and community intelligence.

### Troubleshooting CrowdSec

**Service not starting:**
```bash
# Check logs
journalctl -u crowdsec -n 50

# Validate configuration
cscli config show

# Test acquisition files
cscli metrics
```

**No detections:**
```bash
# Check if parsers are working
cscli metrics --parser

# Verify log files are being read
tail -f /var/log/crowdsec.log

# Test with manual attack simulation
# (from another machine)
ssh attacker@your-server  # Try wrong password 5+ times

# Check for new decisions
cscli decisions list
```

**Bouncer not blocking:**
```bash
# Check bouncer status
systemctl status crowdsec-firewall-bouncer-*

# Verify bouncer registration
cscli bouncers list

# Check firewall rules were added
iptables -L crowdsec-chain
# or for nftables:
nft list chain ip crowdsec crowdsec-chain

# Restart bouncer
systemctl restart crowdsec-firewall-bouncer-*
```

**Performance issues:**
```bash
# Check resource usage
ps aux | grep crowdsec
systemctl status crowdsec

# View metrics
cscli metrics

# Reduce log sources if needed
# Edit /etc/crowdsec/acquis.yaml
```

### CrowdSec Dashboard (Optional)

Install Metabase for local dashboard:

```bash
# Install Metabase
cscli dashboard setup --listen 0.0.0.0:3000

# Access at http://your-server:3000
# Default credentials: crowdsec / <generated-password>

# Remove dashboard
cscli dashboard remove
```

### Notification Setup

Configure notifications for decisions:

```bash
# Install notification plugin (Slack example)
cscli notifications install slack

# Configure in /etc/crowdsec/notifications/slack.yaml
# Then reload
systemctl reload crowdsec
```

Available plugins: Slack, Discord, Email, Webhook, Splunk, etc.

### Testing Detection

**SSH brute-force test:**
```bash
# From another machine
for i in {1..10}; do
  ssh wronguser@your-server
done

# Check decisions
cscli decisions list
```

**HTTP attack test (if web server running):**
```bash
# From another machine
for i in {1..20}; do
  curl http://your-server/../../etc/passwd
done

# Check alerts
cscli alerts list
```

---

## Wazuh + CrowdSec Integration

### Combined Benefits

Using both provides defense in depth:

**Wazuh:**
- Comprehensive SIEM capabilities
- File integrity monitoring
- Configuration assessment
- Regulatory compliance reporting
- Log correlation
- Incident response

**CrowdSec:**
- Real-time IP reputation
- Automatic blocking
- Community threat intelligence
- Lightweight operation
- API-first architecture

### Recommended Architecture

```
[Hardened Server]
    ├── Wazuh Agent ──> [Wazuh Manager] ──> [Wazuh Dashboard]
    └── CrowdSec ──────> [CrowdSec Console]
            └── Firewall Bouncer ──> [UFW/iptables]
```

### Log Flow

```
Application Logs
    ├── /var/log/auth.log ──> Wazuh (SIEM) + CrowdSec (Detection)
    ├── /var/log/syslog ────> Wazuh (SIEM) + CrowdSec (Detection)
    └── /var/log/ufw.log ───> Wazuh (SIEM)

Wazuh: Stores, analyzes, alerts, reports
CrowdSec: Detects patterns, makes block decisions, executes via bouncer
```

### Avoiding Overlap

Configure different responsibilities:

**Wazuh monitors:**
- All logs for SIEM
- File integrity (AIDE integration)
- Configuration drift
- Compliance scanning
- Vulnerability detection

**CrowdSec handles:**
- Active threat blocking
- IP reputation
- Real-time decisions
- Community intelligence

**No conflict because:**
- Wazuh = Detection + Alerting + Analysis
- CrowdSec = Detection + Blocking + Prevention

### Performance Considerations

**Combined Resource Usage:**
- Wazuh Agent: ~50-100MB RAM, minimal CPU
- CrowdSec: ~30-50MB RAM, minimal CPU
- Total overhead: <150MB RAM, <5% CPU (typical)

**Optimization:**
- Adjust Wazuh agent command frequencies
- Tune CrowdSec parsers to monitored services only
- Use log rotation to prevent disk fill

### Centralized Monitoring

**Wazuh Dashboard:**
- Primary SIEM interface
- View all security events
- Generate compliance reports
- Create custom alerts

**CrowdSec Console:**
- View blocked IPs across fleet
- Access community intelligence
- Manage multiple instances
- Track blocking effectiveness

---

## Quick Reference

### Daily Operations

```bash
# Check Wazuh
systemctl status wazuh-agent
tail /var/ossec/logs/ossec.log

# Check CrowdSec
cscli metrics
cscli decisions list
cscli alerts list | head -20

# Check both services
systemctl status wazuh-agent crowdsec
```

### Security Incident Response

```bash
# 1. Check current blocks
cscli decisions list

# 2. Review recent alerts
cscli alerts list --limit 50

# 3. Check Wazuh for correlation
tail -100 /var/ossec/logs/alerts/alerts.json

# 4. Manual block if needed
cscli decisions add --ip <malicious-ip> --duration 72h

# 5. Report to Wazuh Manager for investigation
# (via Wazuh Dashboard)
```

### Weekly Maintenance

```bash
# Update CrowdSec hub
cscli hub update
cscli hub upgrade

# Check Wazuh agent health
/var/ossec/bin/agent_control -l

# Review blocked IPs
cscli decisions list --type ban

# Clean old decisions
cscli decisions delete --type ban --origin cscli --duration 0
```

---

## Support Resources

**Wazuh:**
- Documentation: https://documentation.wazuh.com/
- Community: https://groups.google.com/g/wazuh
- GitHub: https://github.com/wazuh/wazuh

**CrowdSec:**
- Documentation: https://docs.crowdsec.net/
- Community: https://discourse.crowdsec.net/
- GitHub: https://github.com/crowdsecurity/crowdsec

**Integration Questions:**
- Check logs: `journalctl -u wazuh-agent -u crowdsec`
- Review configurations in this guide
- Test with known attack patterns
