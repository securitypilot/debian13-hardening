#!/bin/bash

################################################################################
# Debian 13 Enterprise Security Hardening Script
# Author: Securitypilot
# Version: 1.0.0
# Description: Attack surface reduction and security monitoring capabilities for Debian 13 servers
# Compliance: CIS Benchmark, BIO2, ISO 27001
################################################################################

set -euo pipefail

# Configuration
SCRIPT_NAME="debian13-hardening"
LOG_DIR="/var/log/${SCRIPT_NAME}"
LOG_FILE="${LOG_DIR}/hardening-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/hardening-backups-$(date +%Y%m%d-%H%M%S)"
COMPLIANCE_REPORT="${LOG_DIR}/compliance-report-$(date +%Y%m%d-%H%M%S).txt"

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
ENABLE_WAZUH=0
ENABLE_CROWDSEC=0
ENABLE_DOCKER_NETWORKING=0

# Wazuh Configuration
WAZUH_MANAGER_IP=""  # Set to your Wazuh manager IP (e.g., "192.168.1.100")
WAZUH_MANAGER_PORT="1514"
WAZUH_REGISTRATION_PASSWORD=""  # Optional: Set registration password

# CrowdSec Configuration
CROWDSEC_ENROLL_KEY=""  # Optional: Your CrowdSec console enrollment key
CROWDSEC_COLLECTIONS="crowdsecurity/linux crowdsecurity/sshd crowdsecurity/nginx crowdsecurity/apache2"

# Docker Networking Configuration
DOCKER_NETWORK_CIDR="172.17.0.0/16"  # Docker default bridge network
DOCKER_ALLOW_INTERNAL=1  # Allow containers to communicate with each other
DOCKER_ALLOW_HOST_ACCESS=1  # Allow containers to access host services

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

################################################################################
# Utility Functions
################################################################################

log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "${LOG_FILE}"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $*" | tee -a "${LOG_FILE}"
}

log_error() {
    echo -e "${RED}[✗]${NC} $*" | tee -a "${LOG_FILE}"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $*" | tee -a "${LOG_FILE}"
}

log_info() {
    echo -e "${BLUE}[i]${NC} $*" | tee -a "${LOG_FILE}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_debian() {
    if [[ ! -f /etc/debian_version ]]; then
        log_error "This script is designed for Debian systems"
        exit 1
    fi
    
    DEBIAN_VERSION=$(cat /etc/debian_version | cut -d. -f1)
    if [[ "${DEBIAN_VERSION}" != "13" ]] && [[ "${DEBIAN_VERSION}" != "trixie/sid" ]]; then
        log_warning "This script is optimized for Debian 13, detected version: $(cat /etc/debian_version)"
    fi
}

create_backup() {
    local file=$1
    if [[ -f "${file}" ]]; then
        mkdir -p "${BACKUP_DIR}"
        cp -p "${file}" "${BACKUP_DIR}/$(basename ${file}).bak"
        log_info "Backed up ${file} to ${BACKUP_DIR}"
    fi
}

add_compliance_note() {
    local control=$1
    local frameworks=$2
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ${control} - Frameworks: ${frameworks}" >> "${COMPLIANCE_REPORT}"
}

################################################################################
# Pre-Flight Validation
################################################################################

pre_flight_checks() {
    log_info "=== Pre-Flight Validation ==="
    
    # Check disk space
    local available_space=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
    if [[ ${available_space} -lt 5 ]]; then
        log_error "Insufficient disk space. Need at least 5GB free"
        exit 1
    fi
    log_success "Disk space check passed (${available_space}GB available)"
    
    # Check internet connectivity
    if ! ping -c 1 -W 2 debian.org &> /dev/null; then
        log_error "No internet connectivity detected"
        exit 1
    fi
    log_success "Internet connectivity check passed"
    
    # Check if running in container
    if [[ -f /.dockerenv ]] || grep -q docker /proc/1/cgroup 2>/dev/null; then
        log_warning "Container environment detected - some hardening may not apply"
    fi
    
    # Create log directory
    mkdir -p "${LOG_DIR}"
    chmod 750 "${LOG_DIR}"
    
    log_success "Pre-flight checks completed"
    add_compliance_note "Pre-flight validation" "Internal Security Policy"
}

################################################################################
# Module 1: System Updates
################################################################################

harden_system_updates() {
    if [[ ${ENABLE_SYSTEM_UPDATES} -eq 0 ]]; then
        log_warning "System updates module disabled"
        return
    fi
    
    log_info "=== System Updates & Package Management ==="
    
    # Update package lists
    log_info "Updating package lists..."
    apt-get update -qq
    
    # Upgrade all packages
    log_info "Upgrading installed packages..."
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq
    
    # Install essential security packages
    log_info "Installing security essentials..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        apt-transport-https \
        ca-certificates \
        curl \
        gnupg \
        lsb-release \
        software-properties-common \
        debsums \
        debsecan \
        apt-listchanges
    
    log_success "System updates completed"
    add_compliance_note "System patching and updates" "CIS 1.8, BIO2 12.6, ISO 27001 A.12.6.1"
}

################################################################################
# Module 2: SSH Hardening
################################################################################

harden_ssh() {
    if [[ ${ENABLE_SSH_HARDENING} -eq 0 ]]; then
        log_warning "SSH hardening module disabled"
        return
    fi
    
    log_info "=== SSH Hardening ==="
    
    # Install OpenSSH if not present
    if ! command -v sshd &> /dev/null; then
        log_info "Installing OpenSSH server..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-server
    fi
    
    create_backup "/etc/ssh/sshd_config"
    
    # Create hardened SSH config
    cat > /etc/ssh/sshd_config.d/99-hardening.conf <<EOF
# SSH Hardening Configuration
# Generated by debian13-hardening script

# Protocol and Encryption
Protocol 2
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

# Ciphers and Algorithms (FIPS 140-2 compliant)
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256

# Authentication
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
AuthenticationMethods publickey

# Connection Settings
MaxAuthTries 3
MaxSessions 5
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2

# Security Options
X11Forwarding no
PermitUserEnvironment no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
StrictModes yes
IgnoreRhosts yes
HostbasedAuthentication no

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Banner
Banner /etc/ssh/banner
EOF

    # Create SSH banner
    cat > /etc/ssh/banner <<EOF
###############################################################################
#                         AUTHORIZED ACCESS ONLY                              #
#                                                                             #
# This system is for authorized use only. All activity is monitored and      #
# logged. Unauthorized access is prohibited and will be prosecuted.          #
###############################################################################
EOF

    # Generate new moduli (this can take a while)
    log_info "Regenerating SSH moduli (this may take several minutes)..."
    if [[ ! -f /etc/ssh/moduli.bak ]]; then
        cp /etc/ssh/moduli /etc/ssh/moduli.bak
        ssh-keygen -M generate -O bits=4096 /etc/ssh/moduli.candidates 2>/dev/null || true
        ssh-keygen -M screen -f /etc/ssh/moduli.candidates /etc/ssh/moduli 2>/dev/null || true
        rm -f /etc/ssh/moduli.candidates
    fi
    
    # Remove weak host keys
    log_info "Removing weak SSH host keys..."
    rm -f /etc/ssh/ssh_host_dsa_key* /etc/ssh/ssh_host_ecdsa_key*
    
    # Regenerate strong host keys if they don't exist
    [[ ! -f /etc/ssh/ssh_host_rsa_key ]] && ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N "" -q
    [[ ! -f /etc/ssh/ssh_host_ed25519_key ]] && ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" -q
    
    # Test SSH configuration
    if sshd -t; then
        systemctl restart sshd
        log_success "SSH hardening completed"
    else
        log_error "SSH configuration test failed - not applying changes"
        rm /etc/ssh/sshd_config.d/99-hardening.conf
        return 1
    fi
    
    add_compliance_note "SSH hardening" "CIS 5.2, BIO2 9.4, ISO 27001 A.9.4.2"
}

################################################################################
# Module 3: Firewall Configuration
################################################################################

harden_firewall() {
    if [[ ${ENABLE_FIREWALL} -eq 0 ]]; then
        log_warning "Firewall module disabled"
        return
    fi
    
    log_info "=== Firewall Configuration (UFW) ==="
    
    # Install UFW
    if ! command -v ufw &> /dev/null; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ufw
    fi
    
    # Reset UFW to default
    log_info "Configuring UFW firewall..."
    ufw --force reset &>/dev/null
    
    # Default policies
    ufw default deny incoming
    ufw default allow outgoing
    ufw default deny routed
    
    # Allow SSH (adjust port if needed)
    SSH_PORT=$(grep -E "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    SSH_PORT=${SSH_PORT:-22}
    ufw allow "${SSH_PORT}/tcp" comment 'SSH access'
    
    # Enable UFW
    ufw --force enable
    
    # Additional iptables hardening
    log_info "Applying additional iptables rules..."
    
    # Prevent syn flood attacks
    iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT || true
    
    # Prevent ping floods
    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT || true
    
    # Drop invalid packets
    iptables -A INPUT -m state --state INVALID -j DROP || true
    
    # Save iptables rules
    if command -v iptables-save &> /dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi
    
    log_success "Firewall configuration completed"
    add_compliance_note "Network firewall" "CIS 3.5, BIO2 13.1, ISO 27001 A.13.1.3"
}

################################################################################
# Module 4: Fail2Ban
################################################################################

harden_fail2ban() {
    if [[ ${ENABLE_FAIL2BAN} -eq 0 ]]; then
        log_warning "Fail2ban module disabled"
        return
    fi
    
    log_info "=== Fail2Ban Configuration ==="
    
    # Install Fail2Ban
    if ! command -v fail2ban-client &> /dev/null; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq fail2ban
    fi
    
    create_backup "/etc/fail2ban/jail.local"
    
    # Create jail.local configuration
    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
destemail = root@localhost
sendername = Fail2Ban
action = %(action_mwl)s

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
maxretry = 3
bantime = 7200

[sshd-ddos]
enabled = true
port = ssh
logpath = %(sshd_log)s
maxretry = 2
EOF

    # Start and enable Fail2Ban
    systemctl enable fail2ban
    systemctl restart fail2ban
    
    log_success "Fail2Ban configuration completed"
    add_compliance_note "Intrusion prevention" "CIS 4.2.4, BIO2 12.4, ISO 27001 A.12.4.1"
}

################################################################################
# Module 5: Automatic Security Updates
################################################################################

harden_auto_updates() {
    if [[ ${ENABLE_AUTO_UPDATES} -eq 0 ]]; then
        log_warning "Automatic updates module disabled"
        return
    fi
    
    log_info "=== Automatic Security Updates ==="
    
    # Install unattended-upgrades
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq unattended-upgrades apt-listchanges
    
    create_backup "/etc/apt/apt.conf.d/50unattended-upgrades"
    
    # Configure unattended-upgrades
    cat > /etc/apt/apt.conf.d/50unattended-upgrades <<EOF
Unattended-Upgrade::Origins-Pattern {
    "origin=Debian,codename=\${distro_codename},label=Debian-Security";
    "origin=Debian,codename=\${distro_codename}-security,label=Debian-Security";
};

Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
Unattended-Upgrade::SyslogEnable "true";
Unattended-Upgrade::SyslogFacility "daemon";
EOF

    # Enable automatic updates
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

    log_success "Automatic security updates configured"
    add_compliance_note "Automated patch management" "CIS 1.8, BIO2 12.6, ISO 27001 A.12.6.1"
}

################################################################################
# Module 6: Kernel Hardening (sysctl)
################################################################################

harden_kernel() {
    if [[ ${ENABLE_KERNEL_HARDENING} -eq 0 ]]; then
        log_warning "Kernel hardening module disabled"
        return
    fi
    
    log_info "=== Kernel Hardening (sysctl) ==="
    
    create_backup "/etc/sysctl.conf"
    
    cat > /etc/sysctl.d/99-hardening.conf <<EOF
# Kernel Hardening Configuration
# Generated by debian13-hardening script

# Network Security
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# IP Forwarding (disable unless router)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# ICMP
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Reverse Path Filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# TCP/IP Stack Hardening
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 4096

# Log Martians (packets with impossible addresses)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# IPv6 Router Advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# Kernel Security
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
kernel.kexec_load_disabled = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# Address Space Layout Randomization
kernel.randomize_va_space = 2

# Core Dumps
kernel.core_uses_pid = 1
fs.suid_dumpable = 0

# File System Hardening
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
EOF

    # Apply sysctl settings
    sysctl -p /etc/sysctl.d/99-hardening.conf &>/dev/null
    
    log_success "Kernel hardening completed"
    add_compliance_note "Kernel parameter hardening" "CIS 3.1-3.3, BIO2 12.6, ISO 27001 A.12.6.1"
}

################################################################################
# Module 7: File System Security
################################################################################

harden_filesystem() {
    if [[ ${ENABLE_FILESYSTEM_SECURITY} -eq 0 ]]; then
        log_warning "Filesystem security module disabled"
        return
    fi
    
    log_info "=== File System Security ==="
    
    # Set secure permissions on sensitive files
    log_info "Setting secure file permissions..."
    
    chmod 644 /etc/passwd
    chmod 644 /etc/group
    chmod 600 /etc/shadow
    chmod 600 /etc/gshadow
    chmod 600 /boot/grub/grub.cfg 2>/dev/null || true
    chmod 600 /etc/ssh/sshd_config
    
    # Secure cron
    chmod 600 /etc/crontab
    chmod 700 /etc/cron.d
    chmod 700 /etc/cron.daily
    chmod 700 /etc/cron.hourly
    chmod 700 /etc/cron.monthly
    chmod 700 /etc/cron.weekly
    
    # Remove world-writable permissions from system files
    log_info "Removing world-writable permissions..."
    find / -xdev -type f -perm -0002 -exec chmod o-w {} \; 2>/dev/null || true
    
    # Find and report SUID/SGID files
    log_info "Auditing SUID/SGID files..."
    find / -xdev \( -perm -4000 -o -perm -2000 \) -type f > "${LOG_DIR}/suid-sgid-files.txt" 2>/dev/null || true
    
    # Disable uncommon filesystems
    log_info "Disabling uncommon filesystems..."
    cat > /etc/modprobe.d/filesystem-hardening.conf <<EOF
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install udf /bin/true
install vfat /bin/true
EOF

    # Configure /tmp with security options
    log_info "Hardening /tmp mount..."
    if ! grep -q "tmpfs /tmp" /etc/fstab; then
        echo "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev,size=2G 0 0" >> /etc/fstab
    fi
    
    log_success "File system security hardening completed"
    add_compliance_note "File system permissions and security" "CIS 1.1, BIO2 9.4, ISO 27001 A.9.4.5"
}

################################################################################
# Module 8: User Account Policies
################################################################################

harden_user_policies() {
    if [[ ${ENABLE_USER_POLICIES} -eq 0 ]]; then
        log_warning "User policies module disabled"
        return
    fi
    
    log_info "=== User Account Policies ==="
    
    # Install libpam-pwquality for password complexity
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq libpam-pwquality
    
    create_backup "/etc/pam.d/common-password"
    create_backup "/etc/login.defs"
    
    # Configure password complexity
    cat > /etc/security/pwquality.conf <<EOF
# Password Quality Requirements
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
minclass = 4
maxrepeat = 3
maxsequence = 3
gecoscheck = 1
dictcheck = 1
usercheck = 1
enforcing = 1
EOF

    # Configure password aging
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs
    
    # Set default umask
    sed -i 's/^UMASK.*/UMASK           027/' /etc/login.defs
    
    # Configure account lockout
    if ! grep -q "pam_faillock" /etc/pam.d/common-auth; then
        cat >> /etc/pam.d/common-auth <<EOF

# Account lockout policy
auth required pam_faillock.so preauth silent audit deny=3 unlock_time=900
auth required pam_faillock.so authfail audit deny=3 unlock_time=900
account required pam_faillock.so
EOF
    fi
    
    # Set session timeout
    cat > /etc/profile.d/timeout.sh <<EOF
# Session timeout - 15 minutes
TMOUT=900
readonly TMOUT
export TMOUT
EOF
    chmod 644 /etc/profile.d/timeout.sh
    
    # Disable unused accounts
    log_info "Checking for inactive user accounts..."
    lastlog -b 90 -t 365 > "${LOG_DIR}/inactive-users.txt" 2>/dev/null || true
    
    log_success "User account policies configured"
    add_compliance_note "User account management and password policies" "CIS 5.4, BIO2 9.2, ISO 27001 A.9.2.1"
}

################################################################################
# Module 9: Audit Logging (auditd)
################################################################################

harden_audit_logging() {
    if [[ ${ENABLE_AUDIT_LOGGING} -eq 0 ]]; then
        log_warning "Audit logging module disabled"
        return
    fi
    
    log_info "=== Audit Logging (auditd) ==="
    
    # Install auditd
    if ! command -v auditctl &> /dev/null; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq auditd audispd-plugins
    fi
    
    create_backup "/etc/audit/rules.d/audit.rules"
    
    # Create comprehensive audit rules
    cat > /etc/audit/rules.d/hardening.rules <<EOF
# Audit Rules - Enterprise Security
# Generated by debian13-hardening script

# Remove any existing rules
-D

# Buffer Size
-b 8192

# Failure Mode (0=silent 1=printk 2=panic)
-f 1

# Audit the audit logs
-w /var/log/audit/ -k auditlog

# System calls
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# User and group changes
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Network configuration
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network -p wa -k system-locale

# Login/Logout events
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

# Session initiation
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins

# Permission changes
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

# Unauthorized access attempts
-a always,exit -F arch=b64 -S open -S openat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S open -S openat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S open -S openat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S open -S openat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

# Privileged commands
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-passwd
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-sudo
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-su

# File deletion by users
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

# System administration
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope

# Kernel module loading
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# Make configuration immutable
-e 2
EOF

    # Load audit rules
    augenrules --load &>/dev/null || true
    
    # Enable and start auditd
    systemctl enable auditd
    systemctl restart auditd
    
    log_success "Audit logging configured"
    add_compliance_note "Security event logging and monitoring" "CIS 4.1, BIO2 12.4, ISO 27001 A.12.4.1"
}

################################################################################
# Module 10: Rootkit Detection
################################################################################

harden_rootkit_detection() {
    if [[ ${ENABLE_ROOTKIT_DETECTION} -eq 0 ]]; then
        log_warning "Rootkit detection module disabled"
        return
    fi
    
    log_info "=== Rootkit Detection ==="
    
    # Install rkhunter and chkrootkit
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq rkhunter chkrootkit
    
    # Configure rkhunter
    create_backup "/etc/rkhunter.conf"
    
    sed -i 's/^UPDATE_MIRRORS=.*/UPDATE_MIRRORS=1/' /etc/rkhunter.conf
    sed -i 's/^MIRRORS_MODE=.*/MIRRORS_MODE=0/' /etc/rkhunter.conf
    sed -i 's/^WEB_CMD=.*/WEB_CMD=""/' /etc/rkhunter.conf
    
    # Update rkhunter database
    log_info "Updating rkhunter database..."
    rkhunter --update &>/dev/null || true
    rkhunter --propupd &>/dev/null || true
    
    # Create daily check cron job
    cat > /etc/cron.daily/rkhunter-check <<EOF
#!/bin/bash
/usr/bin/rkhunter --cronjob --update --quiet
EOF
    chmod 755 /etc/cron.daily/rkhunter-check
    
    log_success "Rootkit detection configured"
    add_compliance_note "Malware and rootkit detection" "BIO2 12.2, ISO 27001 A.12.2.1"
}

################################################################################
# Module 11: AppArmor
################################################################################

harden_apparmor() {
    if [[ ${ENABLE_APPARMOR} -eq 0 ]]; then
        log_warning "AppArmor module disabled"
        return
    fi
    
    log_info "=== AppArmor Mandatory Access Control ==="
    
    # Install AppArmor
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra
    
    # Enable AppArmor
    systemctl enable apparmor
    systemctl start apparmor
    
    # Set all profiles to enforce mode
    log_info "Enabling AppArmor profiles..."
    aa-enforce /etc/apparmor.d/* 2>/dev/null || true
    
    # Check AppArmor status
    aa-status > "${LOG_DIR}/apparmor-status.txt" 2>&1 || true
    
    log_success "AppArmor configured and enabled"
    add_compliance_note "Mandatory Access Control" "CIS 1.6, BIO2 9.4, ISO 27001 A.9.4.5"
}

################################################################################
# Module 12: Process Accounting
################################################################################

harden_process_accounting() {
    if [[ ${ENABLE_PROCESS_ACCOUNTING} -eq 0 ]]; then
        log_warning "Process accounting module disabled"
        return
    fi
    
    log_info "=== Process Accounting ==="
    
    # Install acct package
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq acct
    
    # Enable process accounting
    systemctl enable acct
    systemctl start acct
    
    log_success "Process accounting enabled"
    add_compliance_note "Process execution logging" "ISO 27001 A.12.4.1"
}

################################################################################
# Module 13: AIDE (File Integrity Monitoring)
################################################################################

harden_aide() {
    if [[ ${ENABLE_AIDE} -eq 0 ]]; then
        log_warning "AIDE module disabled"
        return
    fi
    
    log_info "=== AIDE File Integrity Monitoring ==="
    
    # Install AIDE
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq aide aide-common
    
    # Initialize AIDE database (this can take a while)
    log_info "Initializing AIDE database (this may take several minutes)..."
    aideinit &>/dev/null || true
    
    if [[ -f /var/lib/aide/aide.db.new ]]; then
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    fi
    
    # Create daily AIDE check
    cat > /etc/cron.daily/aide-check <<EOF
#!/bin/bash
/usr/bin/aide --check | mail -s "AIDE Report for \$(hostname)" root
EOF
    chmod 755 /etc/cron.daily/aide-check
    
    log_success "AIDE file integrity monitoring configured"
    add_compliance_note "File integrity monitoring" "CIS 1.3, BIO2 12.4, ISO 27001 A.12.4.1"
}

################################################################################
# Module 14: Wazuh Agent Integration
################################################################################

harden_wazuh() {
    if [[ ${ENABLE_WAZUH} -eq 0 ]]; then
        log_warning "Wazuh agent module disabled"
        return
    fi
    
    log_info "=== Wazuh Agent Installation & Configuration ==="
    
    # Validate Wazuh manager IP
    if [[ -z "${WAZUH_MANAGER_IP}" ]]; then
        log_error "WAZUH_MANAGER_IP not set. Skipping Wazuh installation."
        log_error "Set WAZUH_MANAGER_IP in the script configuration section."
        return 1
    fi
    
    # Check if Wazuh agent is already installed
    if command -v wazuh-agent &> /dev/null; then
        log_warning "Wazuh agent already installed"
        return 0
    fi
    
    log_info "Installing Wazuh agent..."
    
    # Install dependencies
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl apt-transport-https lsb-release gnupg2
    
    # Add Wazuh repository
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
    chmod 644 /usr/share/keyrings/wazuh.gpg
    
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
    
    # Update package lists
    apt-get update -qq
    
    # Set Wazuh manager configuration
    if [[ -n "${WAZUH_REGISTRATION_PASSWORD}" ]]; then
        export WAZUH_MANAGER="${WAZUH_MANAGER_IP}"
        export WAZUH_REGISTRATION_PASSWORD="${WAZUH_REGISTRATION_PASSWORD}"
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wazuh-agent
    else
        export WAZUH_MANAGER="${WAZUH_MANAGER_IP}"
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wazuh-agent
    fi
    
    # Configure Wazuh agent
    log_info "Configuring Wazuh agent..."
    
    create_backup "/var/ossec/etc/ossec.conf"
    
    # Update ossec.conf with manager settings
    sed -i "s/<address>.*<\/address>/<address>${WAZUH_MANAGER_IP}<\/address>/" /var/ossec/etc/ossec.conf
    sed -i "s/<port>.*<\/port>/<port>${WAZUH_MANAGER_PORT}<\/port>/" /var/ossec/etc/ossec.conf
    
    # Enable additional monitoring
    cat >> /var/ossec/etc/ossec.conf <<'EOF'

  <!-- Enhanced monitoring for hardened systems -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/ufw.log</location>
  </localfile>

  <localfile>
    <log_format>command</log_format>
    <command>df -P</command>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>netstat -tulpn | grep LISTEN</command>
    <alias>netstat listening ports</alias>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>last -n 20</command>
    <frequency>360</frequency>
  </localfile>
EOF

    # Enable and start Wazuh agent
    systemctl daemon-reload
    systemctl enable wazuh-agent
    systemctl start wazuh-agent
    
    # Verify connection
    sleep 5
    if systemctl is-active --quiet wazuh-agent; then
        log_success "Wazuh agent installed and connected to ${WAZUH_MANAGER_IP}"
        log_info "Agent ID will be assigned by manager on first connection"
    else
        log_error "Wazuh agent failed to start"
        systemctl status wazuh-agent --no-pager
    fi
    
    add_compliance_note "Security monitoring - Wazuh SIEM" "BIO2 12.4, ISO 27001 A.12.4.1, A.12.4.3"
}

################################################################################
# Module 15: CrowdSec Integration
################################################################################

harden_crowdsec() {
    if [[ ${ENABLE_CROWDSEC} -eq 0 ]]; then
        log_warning "CrowdSec module disabled"
        return
    fi
    
    log_info "=== CrowdSec Installation & Configuration ==="
    
    # Check if CrowdSec is already installed
    if command -v cscli &> /dev/null; then
        log_warning "CrowdSec already installed"
        return 0
    fi
    
    log_info "Installing CrowdSec..."
    
    # Install dependencies
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl gnupg apt-transport-https
    
    # Add CrowdSec repository
    curl -fsSL https://packagecloud.io/crowdsec/crowdsec/gpgkey | gpg --dearmor > /usr/share/keyrings/crowdsec-archive-keyring.gpg
    
    echo "deb [signed-by=/usr/share/keyrings/crowdsec-archive-keyring.gpg] https://packagecloud.io/crowdsec/crowdsec/debian/ $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/crowdsec.list
    
    # Update and install
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq crowdsec
    
    log_info "Installing CrowdSec collections..."
    
    # Install default collections
    for collection in ${CROWDSEC_COLLECTIONS}; do
        cscli collections install ${collection} &>/dev/null || log_warning "Failed to install collection: ${collection}"
    done
    
    # Install bouncers for integration
    log_info "Installing CrowdSec firewall bouncer..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq crowdsec-firewall-bouncer-nftables || \
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq crowdsec-firewall-bouncer-iptables
    
    # Configure log monitoring
    log_info "Configuring CrowdSec acquisitions..."
    
    cat > /etc/crowdsec/acquis.yaml <<EOF
---
# SSH logs
filenames:
  - /var/log/auth.log
  - /var/log/syslog
labels:
  type: syslog

# UFW firewall logs
---
filenames:
  - /var/log/ufw.log
labels:
  type: syslog

# Nginx logs (if present)
---
filenames:
  - /var/log/nginx/*.log
labels:
  type: nginx

# Apache logs (if present)
---
filenames:
  - /var/log/apache2/*.log
labels:
  type: apache2
EOF

    # Enroll in CrowdSec console if key provided
    if [[ -n "${CROWDSEC_ENROLL_KEY}" ]]; then
        log_info "Enrolling with CrowdSec console..."
        cscli console enroll "${CROWDSEC_ENROLL_KEY}" &>/dev/null || log_warning "Console enrollment failed"
    fi
    
    # Enable and start services
    systemctl enable crowdsec
    systemctl restart crowdsec
    
    # Verify installation
    sleep 5
    if systemctl is-active --quiet crowdsec; then
        log_success "CrowdSec installed and running"
        
        # Display metrics
        log_info "CrowdSec hub status:"
        cscli hub list -o raw 2>&1 | head -20 | tee -a "${LOG_FILE}"
        
        # Display decisions (bans)
        log_info "Current CrowdSec decisions:"
        cscli decisions list 2>&1 | tee -a "${LOG_FILE}"
    else
        log_error "CrowdSec failed to start"
        systemctl status crowdsec --no-pager
    fi
    
    # Integration with Fail2Ban warning
    if [[ ${ENABLE_FAIL2BAN} -eq 1 ]]; then
        log_warning "Both CrowdSec and Fail2Ban are enabled"
        log_warning "Consider disabling Fail2Ban to avoid conflicts, or configure them to work on different services"
    fi
    
    add_compliance_note "Collaborative threat intelligence - CrowdSec" "BIO2 12.2, ISO 27001 A.12.2.1"
}

################################################################################
# Module 16: Docker-Aware Firewall Configuration
################################################################################

harden_docker_networking() {
    if [[ ${ENABLE_DOCKER_NETWORKING} -eq 0 ]]; then
        log_warning "Docker networking module disabled"
        return
    fi
    
    log_info "=== Docker-Aware Firewall Configuration ==="
    
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        log_warning "Docker not detected - installing Docker engine..."
        
        # Install Docker
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
            ca-certificates \
            curl \
            gnupg
        
        # Add Docker GPG key
        install -m 0755 -d /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        chmod a+r /etc/apt/keyrings/docker.gpg
        
        # Add Docker repository
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
        
        # Install Docker
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
        
        log_success "Docker installed"
    fi
    
    log_info "Configuring Docker daemon for security..."
    
    # Create Docker daemon configuration
    mkdir -p /etc/docker
    create_backup "/etc/docker/daemon.json"
    
    cat > /etc/docker/daemon.json <<EOF
{
  "icc": ${DOCKER_ALLOW_INTERNAL},
  "userland-proxy": false,
  "no-new-privileges": true,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "live-restore": true,
  "iptables": true,
  "ip-forward": true
}
EOF

    # Configure UFW for Docker
    log_info "Configuring UFW for Docker compatibility..."
    
    # Backup UFW configuration
    create_backup "/etc/ufw/after.rules"
    create_backup "/etc/default/ufw"
    
    # Enable forwarding in UFW
    sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
    
    # Add Docker rules to UFW
    cat >> /etc/ufw/after.rules <<'DOCKERRULES'

# BEGIN DOCKER RULES
*nat
:POSTROUTING ACCEPT [0:0]
:DOCKER - [0:0]

# Docker networks
-A POSTROUTING ! -o docker0 -s 172.17.0.0/16 -j MASQUERADE

# Allow Docker containers to communicate
-A DOCKER -i docker0 -j ACCEPT

COMMIT
# END DOCKER RULES
DOCKERRULES

    # Allow Docker bridge network
    ufw allow from ${DOCKER_NETWORK_CIDR} comment 'Docker bridge network'
    
    # Allow Docker containers to access host services if enabled
    if [[ ${DOCKER_ALLOW_HOST_ACCESS} -eq 1 ]]; then
        log_info "Allowing Docker containers to access host services..."
        ufw allow from ${DOCKER_NETWORK_CIDR} to any comment 'Docker host access'
    fi
    
    # Restart services
    systemctl daemon-reload
    systemctl restart docker
    ufw reload
    
    # Verify Docker is running
    if systemctl is-active --quiet docker; then
        log_success "Docker configured with security-enhanced networking"
        
        # Display Docker network info
        log_info "Docker networks:"
        docker network ls 2>&1 | tee -a "${LOG_FILE}"
    else
        log_error "Docker failed to start"
        systemctl status docker --no-pager
    fi
    
    add_compliance_note "Container network security" "CIS Docker Benchmark, ISO 27001 A.13.1.3"
}

################################################################################
# Post-Flight Validation
################################################################################

post_flight_validation() {
    log_info "=== Post-Flight Validation ==="
    
    local validation_failed=0
    
    # Check SSH
    if ! systemctl is-active --quiet sshd; then
        log_error "SSH service is not running"
        validation_failed=1
    else
        log_success "SSH service is running"
    fi
    
    # Check firewall
    if command -v ufw &> /dev/null; then
        if ufw status | grep -q "Status: active"; then
            log_success "UFW firewall is active"
        else
            log_warning "UFW firewall is not active"
        fi
    fi
    
    # Check fail2ban
    if command -v fail2ban-client &> /dev/null; then
        if systemctl is-active --quiet fail2ban; then
            log_success "Fail2Ban is running"
        else
            log_warning "Fail2Ban is not running"
        fi
    fi
    
    # Check auditd
    if command -v auditctl &> /dev/null; then
        if systemctl is-active --quiet auditd; then
            log_success "Auditd is running"
        else
            log_warning "Auditd is not running"
        fi
    fi
    
    # Check AppArmor
    if command -v aa-status &> /dev/null; then
        if aa-status --enabled 2>/dev/null; then
            log_success "AppArmor is enabled"
        else
            log_warning "AppArmor is not enabled"
        fi
    fi
    
    # Generate security scan
    log_info "Running security scan..."
    if command -v debsecan &> /dev/null; then
        debsecan --suite=$(lsb_release -cs) --format detail > "${LOG_DIR}/security-vulnerabilities.txt" 2>&1 || true
    fi
    
    # Check for world-writable files
    log_info "Scanning for world-writable files..."
    find / -xdev -type f -perm -0002 2>/dev/null > "${LOG_DIR}/world-writable-files.txt" || true
    local writable_count=$(wc -l < "${LOG_DIR}/world-writable-files.txt")
    if [[ ${writable_count} -gt 0 ]]; then
        log_warning "Found ${writable_count} world-writable files (see ${LOG_DIR}/world-writable-files.txt)"
    else
        log_success "No world-writable files found"
    fi
    
    # System info
    log_info "Collecting system information..."
    cat > "${LOG_DIR}/system-info.txt" <<EOF
Hostname: $(hostname)
Kernel: $(uname -r)
Distribution: $(lsb_release -ds 2>/dev/null || cat /etc/debian_version)
Hardening Date: $(date)
Uptime: $(uptime)
EOF

    if [[ ${validation_failed} -eq 0 ]]; then
        log_success "Post-flight validation completed successfully"
    else
        log_warning "Post-flight validation completed with warnings"
    fi
}

################################################################################
# Generate Summary Report
################################################################################

generate_summary() {
    log_info "=== Hardening Summary ==="
    
    cat > "${LOG_DIR}/hardening-summary.txt" <<EOF
================================================================================
Debian 13 Security Hardening Summary
================================================================================
Execution Date: $(date)
Hostname: $(hostname)
Kernel: $(uname -r)
Distribution: $(lsb_release -ds 2>/dev/null || cat /etc/debian_version)

Hardening Modules Applied:
- System Updates: $([ ${ENABLE_SYSTEM_UPDATES} -eq 1 ] && echo "✓ Enabled" || echo "✗ Disabled")
- SSH Hardening: $([ ${ENABLE_SSH_HARDENING} -eq 1 ] && echo "✓ Enabled" || echo "✗ Disabled")
- Firewall (UFW): $([ ${ENABLE_FIREWALL} -eq 1 ] && echo "✓ Enabled" || echo "✗ Disabled")
- Fail2Ban: $([ ${ENABLE_FAIL2BAN} -eq 1 ] && echo "✓ Enabled" || echo "✗ Disabled")
- Automatic Updates: $([ ${ENABLE_AUTO_UPDATES} -eq 1 ] && echo "✓ Enabled" || echo "✗ Disabled")
- Kernel Hardening: $([ ${ENABLE_KERNEL_HARDENING} -eq 1 ] && echo "✓ Enabled" || echo "✗ Disabled")
- Filesystem Security: $([ ${ENABLE_FILESYSTEM_SECURITY} -eq 1 ] && echo "✓ Enabled" || echo "✗ Disabled")
- User Policies: $([ ${ENABLE_USER_POLICIES} -eq 1 ] && echo "✓ Enabled" || echo "✗ Disabled")
- Audit Logging: $([ ${ENABLE_AUDIT_LOGGING} -eq 1 ] && echo "✓ Enabled" || echo "✗ Disabled")
- Rootkit Detection: $([ ${ENABLE_ROOTKIT_DETECTION} -eq 1 ] && echo "✓ Enabled" || echo "✗ Disabled")
- AppArmor: $([ ${ENABLE_APPARMOR} -eq 1 ] && echo "✓ Enabled" || echo "✗ Disabled")
- Process Accounting: $([ ${ENABLE_PROCESS_ACCOUNTING} -eq 1 ] && echo "✓ Enabled" || echo "✗ Disabled")
- AIDE: $([ ${ENABLE_AIDE} -eq 1 ] && echo "✓ Enabled" || echo "✗ Disabled")
- Wazuh Agent: $([ ${ENABLE_WAZUH} -eq 1 ] && echo "✓ Enabled (Manager: ${WAZUH_MANAGER_IP})" || echo "✗ Disabled")
- CrowdSec: $([ ${ENABLE_CROWDSEC} -eq 1 ] && echo "✓ Enabled" || echo "✗ Disabled")
- Docker Networking: $([ ${ENABLE_DOCKER_NETWORKING} -eq 1 ] && echo "✓ Enabled" || echo "✗ Disabled")

Compliance Frameworks:
- CIS Benchmark for Debian
- Dutch BIO2 (Baseline Information Security Government)
- ISO 27001:2013

Log Files:
- Main Log: ${LOG_FILE}
- Compliance Report: ${COMPLIANCE_REPORT}
- System Info: ${LOG_DIR}/system-info.txt
- Security Vulnerabilities: ${LOG_DIR}/security-vulnerabilities.txt
- SUID/SGID Files: ${LOG_DIR}/suid-sgid-files.txt
- World-Writable Files: ${LOG_DIR}/world-writable-files.txt
- Inactive Users: ${LOG_DIR}/inactive-users.txt
- AppArmor Status: ${LOG_DIR}/apparmor-status.txt

Backups: ${BACKUP_DIR}

Next Steps:
1. Review all log files in ${LOG_DIR}
2. Test SSH connectivity before closing current session
3. Review firewall rules: ufw status verbose
4. Check fail2ban status: fail2ban-client status
5. Review audit logs: aureport --summary
6. Scan for vulnerabilities: debsecan
7. Run rkhunter: rkhunter --check
8. Consider additional hardening for specific services

IMPORTANT WARNINGS:
- SSH password authentication has been disabled
- Ensure you have SSH key access configured before logging out
- Root login via SSH is disabled
- Review firewall rules to ensure required services are allowed

================================================================================
EOF

    cat "${LOG_DIR}/hardening-summary.txt"
    
    log_success "Hardening summary generated: ${LOG_DIR}/hardening-summary.txt"
    log_success "Compliance report: ${COMPLIANCE_REPORT}"
}

################################################################################
# Main Execution
################################################################################

main() {
    clear
    echo -e "${BLUE}"
    cat <<'EOF'
================================================================================
    ____  ____  ____  _____    _   _   _____   _   _    _    ____  ____  
   |  _ \| __ )|_ _|/ _ \ \  / | / | |___ /  | | | |  / \  |  _ \|  _ \ 
   | | | |  _ \ | || | | \ \/ /  | | |  |_ \  | |_| | / _ \ | |_) | | | |
   | |_| | |_) || || |_| |\  /   | | | ___) | |  _  |/ ___ \|  _ <| |_| |
   |____/|____/|___|\___/  \/    |_| ||____/  |_| |_/_/   \_\_| \_\____/ 
                                                                           
   Debian 13 Enterprise Security Hardening Script
   Securitypilot Solutions
   Version 1.0.0
================================================================================
EOF
    echo -e "${NC}"
    
    log_info "Starting Debian 13 hardening process..."
    log_info "Script version: 1.0.0"
    log_info "Execution started: $(date)"
    
    # Preliminary checks
    check_root
    check_debian
    pre_flight_checks
    
    # Execute hardening modules
    harden_system_updates
    harden_ssh
    harden_firewall
    harden_fail2ban
    harden_auto_updates
    harden_kernel
    harden_filesystem
    harden_user_policies
    harden_audit_logging
    harden_rootkit_detection
    harden_apparmor
    harden_process_accounting
    harden_aide
    harden_wazuh
    harden_crowdsec
    harden_docker_networking
    
    # Validation and reporting
    post_flight_validation
    generate_summary
    
    log_info "Hardening process completed at: $(date)"
    
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║           Debian 13 Hardening Completed Successfully!              ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}CRITICAL: Before logging out, verify SSH access in a new session!${NC}"
    echo ""
}

# Execute main function
main "$@"
