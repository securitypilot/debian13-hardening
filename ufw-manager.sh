#!/bin/bash

################################################################################
# UFW Firewall Management Script
# Author: Securitypilot
# Description: Interactive firewall rule management with Docker awareness
################################################################################

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Check root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}This script must be run as root${NC}"
    exit 1
fi

# Check if UFW is installed
if ! command -v ufw &> /dev/null; then
    echo -e "${RED}UFW is not installed${NC}"
    exit 1
fi

################################################################################
# Display Functions
################################################################################

show_banner() {
    clear
    echo -e "${BLUE}"
    cat <<'EOF'
╔══════════════════════════════════════════════════════════════════════╗
║                  UFW Firewall Management Console                     ║
║                    Docker-Aware Configuration                        ║
╚══════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

show_status() {
    echo -e "${CYAN}=== Firewall Status ===${NC}\n"
    ufw status verbose
    echo ""
}

show_rules() {
    echo -e "${CYAN}=== Current Rules (Numbered) ===${NC}\n"
    ufw status numbered
    echo ""
}

show_docker_info() {
    echo -e "${CYAN}=== Docker Network Information ===${NC}\n"
    
    if command -v docker &> /dev/null; then
        echo "Docker Networks:"
        docker network ls
        echo ""
        
        echo "Docker Bridge Network Details:"
        docker network inspect bridge | grep -A 5 "IPAM" | grep -E "(Subnet|Gateway)"
        echo ""
        
        echo "Running Containers:"
        docker ps --format "table {{.Names}}\t{{.Ports}}\t{{.Networks}}"
    else
        echo -e "${YELLOW}Docker not installed${NC}"
    fi
    echo ""
}

################################################################################
# Service Templates
################################################################################

COMMON_SERVICES=(
    "SSH:22:tcp:SSH access"
    "HTTP:80:tcp:Web server"
    "HTTPS:443:tcp:Secure web server"
    "DNS:53:tcp,udp:DNS server"
    "SMTP:25:tcp:Mail server"
    "IMAP:143:tcp:IMAP mail"
    "IMAPS:993:tcp:IMAP over SSL"
    "POP3:110:tcp:POP3 mail"
    "POP3S:995:tcp:POP3 over SSL"
    "MySQL:3306:tcp:MySQL database"
    "PostgreSQL:5432:tcp:PostgreSQL database"
    "MongoDB:27017:tcp:MongoDB database"
    "Redis:6379:tcp:Redis cache"
    "Elasticsearch:9200:tcp:Elasticsearch"
    "Kibana:5601:tcp:Kibana"
    "Grafana:3000:tcp:Grafana"
    "Prometheus:9090:tcp:Prometheus"
    "Docker:2375:tcp:Docker API (insecure)"
    "Docker-TLS:2376:tcp:Docker API (TLS)"
    "Kubernetes-API:6443:tcp:Kubernetes API"
    "RDP:3389:tcp:Remote Desktop"
    "VNC:5900:tcp:VNC remote access"
    "NFS:2049:tcp:NFS file sharing"
    "Samba:445:tcp:Samba/CIFS"
    "LDAP:389:tcp:LDAP"
    "LDAPS:636:tcp:LDAP over SSL"
    "Rsync:873:tcp:Rsync"
    "Git:9418:tcp:Git protocol"
    "Wireguard:51820:udp:Wireguard VPN"
    "OpenVPN:1194:udp:OpenVPN"
    "Plex:32400:tcp:Plex Media Server"
    "Jellyfin:8096:tcp:Jellyfin Media Server"
    "Nextcloud:8080:tcp:Nextcloud"
    "Portainer:9000:tcp:Portainer"
    "Traefik:8080:tcp:Traefik dashboard"
    "Nginx-Proxy:80,443:tcp:Nginx Proxy Manager"
    "MinIO:9000:tcp:MinIO object storage"
    "Jenkins:8080:tcp:Jenkins CI/CD"
    "GitLab:80,443,22:tcp:GitLab"
    "Proxmox:8006:tcp:Proxmox web interface"
    "Cockpit:9090:tcp:Cockpit web admin"
    "Home-Assistant:8123:tcp:Home Assistant"
    "Pi-hole:53,80,443:tcp,udp:Pi-hole DNS/Web"
)

DOCKER_SERVICES=(
    "Traefik:80,443,8080:tcp:Traefik reverse proxy"
    "Nginx-Proxy:80,443:tcp:Nginx reverse proxy"
    "Portainer:9000,9443:tcp:Portainer container management"
    "Registry:5000:tcp:Docker registry"
    "Watchtower:none:none:Container updater (no ports)"
    "Organizr:80:tcp:Service organizer"
    "Heimdall:80,443:tcp:Application dashboard"
    "Netdata:19999:tcp:System monitoring"
)

################################################################################
# Rule Management Functions
################################################################################

add_simple_rule() {
    echo -e "${CYAN}=== Add Simple Firewall Rule ===${NC}\n"
    
    read -p "Enter port number(s) (e.g., 80 or 80,443): " ports
    read -p "Enter protocol (tcp/udp/both) [tcp]: " protocol
    protocol=${protocol:-tcp}
    read -p "Enter comment/description: " comment
    
    if [[ "${protocol}" == "both" ]]; then
        ufw allow ${ports} comment "${comment}"
    else
        ufw allow ${ports}/${protocol} comment "${comment}"
    fi
    
    echo -e "${GREEN}Rule added successfully${NC}"
}

add_source_rule() {
    echo -e "${CYAN}=== Add Source-Based Rule ===${NC}\n"
    
    read -p "Enter source IP or CIDR (e.g., 192.168.1.0/24): " source
    read -p "Enter destination port (or 'any' for all): " port
    read -p "Enter protocol (tcp/udp/any) [tcp]: " protocol
    protocol=${protocol:-tcp}
    read -p "Enter comment/description: " comment
    
    if [[ "${port}" == "any" ]]; then
        ufw allow from ${source} comment "${comment}"
    elif [[ "${protocol}" == "any" ]]; then
        ufw allow from ${source} to any port ${port} comment "${comment}"
    else
        ufw allow from ${source} to any port ${port} proto ${protocol} comment "${comment}"
    fi
    
    echo -e "${GREEN}Rule added successfully${NC}"
}

add_template_rule() {
    echo -e "${CYAN}=== Add Rule from Template ===${NC}\n"
    
    echo "Common Services:"
    for i in "${!COMMON_SERVICES[@]}"; do
        IFS=':' read -r name port proto desc <<< "${COMMON_SERVICES[$i]}"
        printf "%2d) %-20s - %s (Port: %s/%s)\n" $((i+1)) "$name" "$desc" "$port" "$proto"
    done
    
    echo ""
    read -p "Select service number (or 0 to cancel): " selection
    
    if [[ ${selection} -eq 0 ]]; then
        return
    fi
    
    if [[ ${selection} -lt 1 || ${selection} -gt ${#COMMON_SERVICES[@]} ]]; then
        echo -e "${RED}Invalid selection${NC}"
        return
    fi
    
    IFS=':' read -r name port proto desc <<< "${COMMON_SERVICES[$((selection-1))]}"
    
    read -p "Allow from specific source? (y/N): " source_limit
    if [[ "${source_limit}" =~ ^[Yy]$ ]]; then
        read -p "Enter source IP or CIDR: " source
        
        if [[ "${proto}" == *","* ]]; then
            # Multiple protocols
            IFS=',' read -ra PROTOCOLS <<< "$proto"
            for p in "${PROTOCOLS[@]}"; do
                ufw allow from ${source} to any port ${port} proto ${p} comment "${desc}"
            done
        else
            ufw allow from ${source} to any port ${port} proto ${proto} comment "${desc}"
        fi
    else
        if [[ "${port}" == *","* ]]; then
            # Multiple ports
            IFS=',' read -ra PORTS <<< "$port"
            for p in "${PORTS[@]}"; do
                if [[ "${proto}" == *","* ]]; then
                    IFS=',' read -ra PROTOCOLS <<< "$proto"
                    for pr in "${PROTOCOLS[@]}"; do
                        ufw allow ${p}/${pr} comment "${desc}"
                    done
                else
                    ufw allow ${p}/${proto} comment "${desc}"
                fi
            done
        else
            if [[ "${proto}" == *","* ]]; then
                IFS=',' read -ra PROTOCOLS <<< "$proto"
                for pr in "${PROTOCOLS[@]}"; do
                    ufw allow ${port}/${pr} comment "${desc}"
                done
            else
                ufw allow ${port}/${proto} comment "${desc}"
            fi
        fi
    fi
    
    echo -e "${GREEN}Service rule added: ${name}${NC}"
}

add_docker_rule() {
    echo -e "${CYAN}=== Add Docker Container Rule ===${NC}\n"
    
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}Docker not installed${NC}"
        return
    fi
    
    echo "Docker Service Templates:"
    for i in "${!DOCKER_SERVICES[@]}"; do
        IFS=':' read -r name port proto desc <<< "${DOCKER_SERVICES[$i]}"
        printf "%2d) %-20s - %s\n" $((i+1)) "$name" "$desc"
    done
    
    echo ""
    read -p "Select service (or 0 to enter custom): " selection
    
    if [[ ${selection} -eq 0 ]]; then
        read -p "Enter published port(s) (e.g., 8080 or 8080,8443): " ports
        read -p "Enter protocol (tcp/udp) [tcp]: " protocol
        protocol=${protocol:-tcp}
        read -p "Enter description: " desc
    elif [[ ${selection} -lt 1 || ${selection} -gt ${#DOCKER_SERVICES[@]} ]]; then
        echo -e "${RED}Invalid selection${NC}"
        return
    else
        IFS=':' read -r name ports protocol desc <<< "${DOCKER_SERVICES[$((selection-1))]}"
    fi
    
    if [[ "${ports}" == "none" ]]; then
        echo -e "${YELLOW}This service doesn't expose ports${NC}"
        return
    fi
    
    read -p "Allow from Docker network only? (Y/n): " docker_only
    
    if [[ ! "${docker_only}" =~ ^[Nn]$ ]]; then
        # Get Docker bridge network
        docker_network=$(docker network inspect bridge | grep "Subnet" | awk '{print $2}' | tr -d '",')
        
        IFS=',' read -ra PORT_ARRAY <<< "$ports"
        for port in "${PORT_ARRAY[@]}"; do
            ufw allow from ${docker_network} to any port ${port} proto ${protocol} comment "Docker: ${desc}"
        done
        echo -e "${GREEN}Docker internal rule added${NC}"
    else
        IFS=',' read -ra PORT_ARRAY <<< "$ports"
        for port in "${PORT_ARRAY[@]}"; do
            ufw allow ${port}/${protocol} comment "Docker: ${desc}"
        done
        echo -e "${GREEN}Docker public rule added${NC}"
    fi
}

delete_rule() {
    echo -e "${CYAN}=== Delete Firewall Rule ===${NC}\n"
    
    show_rules
    
    read -p "Enter rule number to delete (or 0 to cancel): " rule_num
    
    if [[ ${rule_num} -eq 0 ]]; then
        return
    fi
    
    read -p "Are you sure you want to delete rule #${rule_num}? (y/N): " confirm
    if [[ "${confirm}" =~ ^[Yy]$ ]]; then
        ufw --force delete ${rule_num}
        echo -e "${GREEN}Rule deleted${NC}"
    fi
}

################################################################################
# Docker Integration Functions
################################################################################

configure_docker_integration() {
    echo -e "${CYAN}=== Configure Docker Integration ===${NC}\n"
    
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}Docker not installed${NC}"
        read -p "Would you like to install Docker? (y/N): " install_docker
        if [[ "${install_docker}" =~ ^[Yy]$ ]]; then
            echo "Installing Docker..."
            curl -fsSL https://get.docker.com | sh
            systemctl enable docker
            systemctl start docker
        else
            return
        fi
    fi
    
    echo "Current Docker network configuration:"
    docker network ls
    echo ""
    
    docker_bridge=$(docker network inspect bridge | grep "Subnet" | awk '{print $2}' | tr -d '",')
    echo "Docker bridge network: ${docker_bridge}"
    echo ""
    
    echo "Docker Integration Options:"
    echo "1) Allow Docker containers to access each other (default bridge)"
    echo "2) Allow Docker containers to access host services"
    echo "3) Allow Docker published ports through firewall"
    echo "4) Configure custom Docker network rules"
    echo "5) Enable Docker daemon API (WARNING: Security risk)"
    echo "0) Back to main menu"
    echo ""
    
    read -p "Select option: " docker_opt
    
    case ${docker_opt} in
        1)
            ufw allow from ${docker_bridge} to ${docker_bridge} comment "Docker inter-container"
            echo -e "${GREEN}Docker inter-container communication allowed${NC}"
            ;;
        2)
            ufw allow from ${docker_bridge} comment "Docker to host"
            echo -e "${GREEN}Docker to host access allowed${NC}"
            ;;
        3)
            add_docker_rule
            ;;
        4)
            read -p "Enter custom Docker network CIDR: " custom_net
            read -p "Enter destination (host IP or 'any'): " dest
            read -p "Enter comment: " comment
            
            if [[ "${dest}" == "any" ]]; then
                ufw allow from ${custom_net} comment "${comment}"
            else
                ufw allow from ${custom_net} to ${dest} comment "${comment}"
            fi
            echo -e "${GREEN}Custom Docker rule added${NC}"
            ;;
        5)
            echo -e "${YELLOW}WARNING: Enabling Docker API is a security risk!${NC}"
            read -p "Allow Docker API on port 2376 (TLS)? (y/N): " enable_api
            if [[ "${enable_api}" =~ ^[Yy]$ ]]; then
                read -p "From which source (IP/CIDR or 'any'): " api_source
                if [[ "${api_source}" == "any" ]]; then
                    ufw allow 2376/tcp comment "Docker API (TLS)"
                else
                    ufw allow from ${api_source} to any port 2376 proto tcp comment "Docker API (TLS)"
                fi
                echo -e "${GREEN}Docker API rule added${NC}"
                echo -e "${YELLOW}Remember to configure TLS for Docker daemon!${NC}"
            fi
            ;;
    esac
}

################################################################################
# Bulk Operations
################################################################################

bulk_operations() {
    echo -e "${CYAN}=== Bulk Operations ===${NC}\n"
    
    echo "1) Allow common web services (80, 443)"
    echo "2) Allow common database access from subnet"
    echo "3) Allow monitoring stack (Grafana, Prometheus, etc.)"
    echo "4) Allow media server stack (Plex, Jellyfin, etc.)"
    echo "5) Reset to default (deny all, allow SSH only)"
    echo "0) Back to main menu"
    echo ""
    
    read -p "Select operation: " bulk_opt
    
    case ${bulk_opt} in
        1)
            ufw allow 80/tcp comment "HTTP"
            ufw allow 443/tcp comment "HTTPS"
            echo -e "${GREEN}Web services allowed${NC}"
            ;;
        2)
            read -p "Enter allowed subnet (e.g., 192.168.1.0/24): " subnet
            ufw allow from ${subnet} to any port 3306 proto tcp comment "MySQL"
            ufw allow from ${subnet} to any port 5432 proto tcp comment "PostgreSQL"
            ufw allow from ${subnet} to any port 27017 proto tcp comment "MongoDB"
            ufw allow from ${subnet} to any port 6379 proto tcp comment "Redis"
            echo -e "${GREEN}Database access allowed from ${subnet}${NC}"
            ;;
        3)
            read -p "Enter allowed subnet (e.g., 192.168.1.0/24): " subnet
            ufw allow from ${subnet} to any port 3000 proto tcp comment "Grafana"
            ufw allow from ${subnet} to any port 9090 proto tcp comment "Prometheus"
            ufw allow from ${subnet} to any port 9100 proto tcp comment "Node Exporter"
            ufw allow from ${subnet} to any port 19999 proto tcp comment "Netdata"
            echo -e "${GREEN}Monitoring stack allowed from ${subnet}${NC}"
            ;;
        4)
            ufw allow 32400/tcp comment "Plex"
            ufw allow 8096/tcp comment "Jellyfin"
            ufw allow 8989/tcp comment "Sonarr"
            ufw allow 7878/tcp comment "Radarr"
            ufw allow 9117/tcp comment "Jackett"
            echo -e "${GREEN}Media server stack allowed${NC}"
            ;;
        5)
            read -p "This will reset UFW to defaults. Continue? (yes/NO): " confirm
            if [[ "${confirm}" == "yes" ]]; then
                ufw --force reset
                ufw default deny incoming
                ufw default allow outgoing
                ssh_port=$(grep -E "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
                ssh_port=${ssh_port:-22}
                ufw allow ${ssh_port}/tcp comment "SSH"
                ufw --force enable
                echo -e "${GREEN}UFW reset to defaults${NC}"
            fi
            ;;
    esac
}

################################################################################
# Advanced Options
################################################################################

advanced_options() {
    echo -e "${CYAN}=== Advanced Options ===${NC}\n"
    
    echo "1) Enable/Disable logging"
    echo "2) Set logging level"
    echo "3) Configure rate limiting"
    echo "4) Manage application profiles"
    echo "5) Export/Import rules"
    echo "6) View connection tracking"
    echo "0) Back to main menu"
    echo ""
    
    read -p "Select option: " adv_opt
    
    case ${adv_opt} in
        1)
            current_logging=$(ufw status verbose | grep "Logging:" | awk '{print $2}')
            echo "Current logging: ${current_logging}"
            read -p "Enable logging? (y/N): " enable_log
            if [[ "${enable_log}" =~ ^[Yy]$ ]]; then
                ufw logging on
            else
                ufw logging off
            fi
            ;;
        2)
            echo "Logging levels: off, low, medium, high, full"
            read -p "Enter logging level: " log_level
            ufw logging ${log_level}
            ;;
        3)
            read -p "Enter port to rate limit (e.g., 22 for SSH): " rate_port
            ufw limit ${rate_port}/tcp comment "Rate limited"
            echo -e "${GREEN}Rate limiting applied to port ${rate_port}${NC}"
            ;;
        4)
            ufw app list
            ;;
        5)
            echo "1) Export rules to file"
            echo "2) Import rules from file"
            read -p "Select: " exp_imp
            if [[ ${exp_imp} -eq 1 ]]; then
                backup_file="/root/ufw-rules-$(date +%Y%m%d-%H%M%S).txt"
                ufw status numbered > "${backup_file}"
                echo -e "${GREEN}Rules exported to ${backup_file}${NC}"
            fi
            ;;
        6)
            echo "Active connections:"
            ss -tulpn | grep ESTABLISHED
            ;;
    esac
}

################################################################################
# Main Menu
################################################################################

main_menu() {
    while true; do
        show_banner
        show_status
        
        echo -e "${CYAN}Main Menu:${NC}"
        echo "1)  View rules (numbered)"
        echo "2)  Add simple rule (port/protocol)"
        echo "3)  Add source-based rule (IP/CIDR)"
        echo "4)  Add rule from template"
        echo "5)  Add Docker container rule"
        echo "6)  Delete rule"
        echo ""
        echo "7)  Configure Docker integration"
        echo "8)  View Docker network info"
        echo "9)  Bulk operations"
        echo "10) Advanced options"
        echo ""
        echo "11) Enable firewall"
        echo "12) Disable firewall"
        echo "13) Reload firewall"
        echo ""
        echo "0)  Exit"
        echo ""
        
        read -p "Select option: " choice
        
        case ${choice} in
            1) show_rules; read -p "Press Enter to continue..." ;;
            2) add_simple_rule; read -p "Press Enter to continue..." ;;
            3) add_source_rule; read -p "Press Enter to continue..." ;;
            4) add_template_rule; read -p "Press Enter to continue..." ;;
            5) add_docker_rule; read -p "Press Enter to continue..." ;;
            6) delete_rule; read -p "Press Enter to continue..." ;;
            7) configure_docker_integration; read -p "Press Enter to continue..." ;;
            8) show_docker_info; read -p "Press Enter to continue..." ;;
            9) bulk_operations; read -p "Press Enter to continue..." ;;
            10) advanced_options; read -p "Press Enter to continue..." ;;
            11) ufw enable; echo -e "${GREEN}Firewall enabled${NC}"; read -p "Press Enter to continue..." ;;
            12) ufw disable; echo -e "${YELLOW}Firewall disabled${NC}"; read -p "Press Enter to continue..." ;;
            13) ufw reload; echo -e "${GREEN}Firewall reloaded${NC}"; read -p "Press Enter to continue..." ;;
            0) echo "Exiting..."; exit 0 ;;
            *) echo -e "${RED}Invalid option${NC}"; read -p "Press Enter to continue..." ;;
        esac
    done
}

# Run main menu
main_menu
