#!/bin/bash

#############################################
# AIDAHAR Installation Script
# Author: nurlanulyoff
#############################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   AIDAHAR Installation Script          ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] This script must be run as root${NC}" 
   exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo -e "${RED}[!] Cannot detect OS${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Detected OS: $OS${NC}"

# Install dependencies based on OS
install_deps() {
    echo -e "${BLUE}[*] Installing dependencies...${NC}"
    
    case $OS in
        kali|debian|ubuntu)
            apt-get update
            apt-get install -y nmap hydra nikto sqlmap metasploit-framework \
                dirb enum4linux smbclient curl wget git
            ;;
        fedora|rhel|centos)
            yum install -y nmap hydra nikto sqlmap metasploit dirb \
                samba-client curl wget git
            ;;
        arch|manjaro)
            pacman -Sy --noconfirm nmap hydra nikto sqlmap metasploit \
                dirb smbclient curl wget git
            ;;
        *)
            echo -e "${RED}[!] Unsupported OS: $OS${NC}"
            echo -e "${YELLOW}[!] Please install dependencies manually${NC}"
            exit 1
            ;;
    esac
}

# Create directories
setup_dirs() {
    echo -e "${BLUE}[*] Setting up directories...${NC}"
    mkdir -p ~/aidahar_reports
    mkdir -p /opt/aidahar
    chmod 755 /opt/aidahar
    echo -e "${GREEN}[+] Directories created${NC}"
}

# Copy files
install_files() {
    echo -e "${BLUE}[*] Installing AIDAHAR...${NC}"
    cp aidahar.sh /opt/aidahar/
    chmod +x /opt/aidahar/aidahar.sh
    
    # Create symlink
    ln -sf /opt/aidahar/aidahar.sh /usr/local/bin/aidahar
    
    echo -e "${GREEN}[+] AIDAHAR installed to /opt/aidahar/${NC}"
}

# Update Metasploit database
update_msf() {
    echo -e "${BLUE}[*] Initializing Metasploit database...${NC}"
    msfdb init 2>/dev/null || echo -e "${YELLOW}[!] Metasploit DB already initialized${NC}"
}

# Main installation
main() {
    echo -e "${YELLOW}[*] Starting installation...${NC}"
    echo ""
    
    install_deps
    setup_dirs
    install_files
    update_msf
    
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║   Installation Complete!               ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Run AIDAHAR with:${NC}"
    echo -e "${WHITE}  sudo aidahar${NC}"
    echo -e "${WHITE}  or${NC}"
    echo -e "${WHITE}  sudo /opt/aidahar/aidahar.sh${NC}"
    echo ""
    echo -e "${YELLOW}Reports will be saved to: ~/aidahar_reports/${NC}"
    echo ""
}

main
