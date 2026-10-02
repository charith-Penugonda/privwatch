# PrivWatch v1.0 - Prototype

**Privilege Escalation Reconnaissance Tool**  
*Dual-mode security assessment framework for Red Team operations and Blue Team defense*

---

## 📋 Overview

PrivWatch is a Python-based security tool designed to identify privilege escalation vectors in Linux systems. It operates in two distinct modes:

- **Red Team Mode**: Offensive reconnaissance to identify potential privilege escalation paths
- **Blue Team Mode**: Defensive auditing to detect security vulnerabilities and misconfigurations

## 🎯 Key Features

### Implemented Attack Vectors (v1.0)

1. **SUID/SGID Binary Analysis**
   - Scans for binaries with SUID/SGID permissions
   - Identifies potentially exploitable binaries (vim, find, python, etc.)
   - Highlights dangerous configurations

2. **Sudo Misconfigurations**
   - Checks sudo privileges for current user
   - Detects NOPASSWD entries
   - Identifies dangerous sudo permissions

3. **Writable PATH Directories**
   - Scans PATH environment variable
   - Identifies writable directories that could enable PATH hijacking
   - Flags potential privilege escalation vectors

4. **Cron Job Analysis**
   - Checks user crontab
   - Scans system cron directories
   - Identifies writable cron files

### Dual-Mode Operation

**Red Team Mode**: Focuses on identifying exploitation opportunities
- Color-coded findings (yellow for exploitable items)
- Prioritizes actionable intelligence
- Groups findings by risk level

**Blue Team Mode**: Focuses on security hardening
- Critical alerts for dangerous configurations
- Provides remediation recommendations
- Emphasizes defense-in-depth

## 🚀 Installation & Usage

### Prerequisites
```bash
# Python 3.6 or higher
python3 --version

# No external dependencies required (uses standard library only)
```

### Quick Start

```bash
# Make executable
chmod +x privwatch.py

# Run in Red Team mode (default)
python3 privwatch.py --mode red

# Run in Blue Team mode
python3 privwatch.py --mode blue

# View help
python3 privwatch.py --help
```

### Recommended Usage

For comprehensive scans, run with sudo privileges:
```bash
sudo python3 privwatch.py --mode red
```

*Note: Some checks are limited without root privileges*

## 📊 Sample Output

### Red Team Mode
```
╔═══════════════════════════════════════════════╗
║           PrivWatch v1.0 - Prototype          ║
║     Privilege Escalation Recon Tool           ║
║     Mode:              RED                    ║
╚═══════════════════════════════════════════════╝

[✓] Starting RED team scan...

[*] Scanning for SUID/SGID binaries...
[+] Found 47 SUID/SGID binaries
[+] Potentially exploitable: 3
    → /usr/bin/find
    → /usr/bin/vim.basic
    → /usr/bin/python3.9

==================================================
SCAN SUMMARY - RED TEAM MODE
==================================================

HIGH RISK: 3
MEDIUM RISK: 2

Total Findings: 5
```

### Blue Team Mode
```
[!] ALERT: 3 risky SUID binaries detected
    ⚠ /usr/bin/find
    ⚠ /usr/bin/vim.basic
    ⚠ /usr/bin/python3.9

RECOMMENDATIONS:
  • SUID: Review necessity, remove SUID bit if not required
  • SUDO: Apply principle of least privilege
  • PATH: Remove write permissions for non-privileged users
```

## 🏗️ Technical Architecture

### Core Components

```
PrivWatch
├── Scanner Engine
│   ├── SUID/SGID Enumeration
│   ├── Sudo Configuration Parser
│   ├── PATH Analysis
│   └── Cron Job Scanner
│
├── Reporting Module
│   ├── Risk Classification
│   ├── Finding Aggregation
│   └── Recommendation Engine
│
└── Output Handler
    ├── Color-coded Terminal Output
    ├── Mode-specific Formatting
    └── Summary Generation
```

### Design Principles

- **No external dependencies**: Uses only Python standard library
- **Non-destructive**: Read-only operations, no system modifications
- **Portable**: Works on any Linux distribution with Python 3
- **Fast execution**: Optimized scan times with timeout protection
- **Clear output**: Color-coded, easy-to-read terminal output

## 🔬 Use Cases

### For Red Teams
- Initial reconnaissance on compromised systems
- Quick privilege escalation vector identification
- Penetration testing assessments
- CTF challenges

### For Blue Teams
- Security auditing and compliance
- Identifying misconfigurations before attackers do
- Regular security posture assessments
- Hardening validation

### For Students & Researchers
- Learning privilege escalation techniques
- Understanding Linux security mechanisms
- Security research and analysis
- Academic projects

## 📈 Future Enhancements (Roadmap)

### Planned Features
- **Timeline Mode**: Track security posture changes over time
- **Additional Vectors**: Kernel exploits, capabilities, Docker breakouts
- **Export Formats**: JSON, CSV, HTML reports
- **Automated Remediation**: One-click security fixes for Blue Team
- **Plugin System**: Extensible architecture for custom checks
- **Network Scanning**: Remote system assessment capabilities

## ⚠️ Legal Disclaimer

**IMPORTANT**: This tool is designed for:
- Authorized security assessments
- Educational purposes
- Personal lab environments
- CTF competitions

**DO NOT** use this tool on systems without explicit authorization. Unauthorized access to computer systems is illegal and unethical.

## 🎓 Educational Value

This project demonstrates:
- Python system programming
- Linux security concepts
- Privilege escalation vectors
- Secure coding practices
- Dual-perspective security thinking (offense + defense)

## 📝 Project Information

- **Author**: Charith
- **Version**: 1.0 (Prototype)
- **Language**: Python 3
- **License**: Educational Use
- **Submission Date**: 2026-09-30

## 🤝 Acknowledgments

Developed as part of BTech CSE curriculum project focusing on:
- Applied cybersecurity concepts
- Real-world security tool development
- Red Team / Blue Team methodologies

---

## 📞 Contact & Support

For questions about this project, please contact through academic channels.
email- cherumaddy@gmail.com
contact- 7396792869

**Remember**: Always practice ethical hacking and obtain proper authorization before testing any system.
