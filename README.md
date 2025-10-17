# ZHYLAN - Automated Penetration Testing Framework

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)

**ZHYLAN** is a comprehensive automated penetration testing framework designed for security professionals, ethical hackers, and students learning cybersecurity.

## Author

**nurlanulyoff**

## Features

### Core Modules

- **Network Reconnaissance**
  - Host discovery
  - OS detection
  - Network mapping

- **Port Scanning**
  - Quick scan (top 1000 ports)
  - Full scan (all 65535 ports)
  - Stealth SYN scan
  - Aggressive scan with OS detection
  - UDP port scanning

- **Service Enumeration**
  - Service version detection
  - NSE script scanning
  - SMB enumeration
  - Banner grabbing

- **Vulnerability Scanning**
  - Automated vulnerability detection
  - SMB vulnerability checks
  - SSL/TLS vulnerability testing
  - Common CVE detection

- **Web Application Testing**
  - Nikto web scanner
  - Directory brute forcing
  - SQL injection testing
  - XSS detection

- **Brute Force Attacks**
  - SSH brute force
  - FTP brute force
  - RDP brute force
  - MySQL/PostgreSQL brute force
  - SMB brute force
  - Custom protocol support

- **Exploitation Module**
  - EternalBlue (MS17-010)
  - BlueKeep (CVE-2019-0708)
  - Payload generation
  - Metasploit integration

- **Automated Scanning**
  - Full automated penetration test
  - Comprehensive vulnerability assessment
  - Automated report generation

## Installation

### Prerequisites

- Linux operating system (Kali Linux recommended)
- Root/sudo privileges
- Internet connection

### Quick Install

\`\`\`bash
# Clone the repository
git clone https://github.com/nurlanulyoff/zhylan.git
cd zhylan

# Make executable
chmod +x zhylan.sh

# Run the installer (optional)
chmod +x install.sh
sudo ./install.sh

# Run ZHYLAN
sudo ./zhylan.sh
\`\`\`

### Manual Installation

Install required dependencies:

\`\`\`bash
# Debian/Ubuntu/Kali
sudo apt-get update
sudo apt-get install -y nmap hydra nikto sqlmap metasploit-framework dirb enum4linux smbclient

# Red Hat/CentOS/Fedora
sudo yum install -y nmap hydra nikto sqlmap metasploit dirb samba-client

# Arch Linux
sudo pacman -S nmap hydra nikto sqlmap metasploit dirb smbclient
\`\`\`

## Usage

### Basic Usage

\`\`\`bash
sudo ./zhylan.sh
\`\`\`

### Quick Start Guide

1. **Launch ZHYLAN**
   \`\`\`bash
   sudo ./zhylan.sh
   \`\`\`

2. **Accept Legal Disclaimer**
   - Read and accept the terms of use

3. **Enter Target**
   - Provide target IP address or domain
   - Example: `192.168.1.100` or `example.com`

4. **Select Module**
   - Choose from the main menu options
   - For beginners: Start with option 8 (Full Automated Scan)

### Example Workflow

\`\`\`bash
# Full automated scan
sudo ./zhylan.sh
# Enter target: 192.168.1.100
# Select option: 8 (Full Automated Scan)

# Manual testing workflow
sudo ./zhylan.sh
# 1. Network Reconnaissance
# 2. Port Scanning (Full scan)
# 3. Service Enumeration
# 4. Vulnerability Scanning
# 6. Brute Force (if credentials needed)
# 9. Generate Report
\`\`\`

## Testing Environment

### Recommended Lab Setup

For safe and legal testing, use these vulnerable machines:

1. **Metasploitable 2/3**
   - Download: https://sourceforge.net/projects/metasploitable/
   - Pre-configured vulnerable Linux system

2. **DVWA (Damn Vulnerable Web Application)**
   - Download: https://github.com/digininja/DVWA
   - Web application security testing

3. **VulnHub Machines**
   - Browse: https://www.vulnhub.com/
   - Various difficulty levels

4. **HackTheBox / TryHackMe**
   - Online platforms with legal targets
   - https://hackthebox.com
   - https://tryhackme.com

### Virtual Lab Setup

\`\`\`bash
# Install VirtualBox
sudo apt-get install virtualbox

# Create network
# 1. Kali Linux (attacker) - NAT + Host-Only
# 2. Metasploitable (target) - Host-Only
# 3. Run ZHYLAN from Kali against Metasploitable
\`\`\`

## Reports

All scan results are saved in `~/zhylan_reports/` with timestamps:

\`\`\`
~/zhylan_reports/
├── zhylan_report_20250118_143022.txt
├── full_auto_scan_20250118_143022.txt
├── vuln_scan_20250118_143022.txt
└── summary_20250118_143022.txt
\`\`\`

## Legal Disclaimer

**IMPORTANT: READ BEFORE USE**

This tool is provided for **EDUCATIONAL PURPOSES ONLY** and for **AUTHORIZED SECURITY TESTING**.

- ✅ Use on systems you own
- ✅ Use on systems with written permission
- ✅ Use in authorized penetration testing engagements
- ✅ Use in controlled lab environments

- ❌ Unauthorized access to computer systems is ILLEGAL
- ❌ Using this tool without permission may result in criminal charges
- ❌ The author is NOT responsible for misuse or illegal activities

**Always obtain explicit written authorization before testing any system.**

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Roadmap

- [ ] Wireless network testing module
- [ ] Advanced exploitation frameworks
- [ ] Machine learning-based vulnerability detection
- [ ] Web GUI interface
- [ ] Docker container support
- [ ] Custom plugin system
- [ ] Integration with additional tools (Burp Suite, ZAP)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Offensive Security for Kali Linux
- Rapid7 for Metasploit Framework
- The Nmap Project
- All open-source security tool developers

## Support

For issues, questions, or contributions:

- GitHub Issues: [Report a bug](https://github.com/nurlanulyoff/zhylan/issues)
- Email: nurlanulyoff@example.com

## Disclaimer

The author and contributors are not responsible for any misuse or damage caused by this program. Use responsibly and ethically.

---

**Made with ❤️ by nurlanulyoff for the cybersecurity community**
