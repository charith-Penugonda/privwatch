# PrivWatch v2.0

**Privilege Escalation Detection & Forensics Tool**

A comprehensive three-mode security tool that combines red team enumeration with blue team log forensics and attack timeline reconstruction.

## Features

### 🔴 Red Team Mode
Enumerates privilege escalation vectors from an attacker's perspective:
- **SUID/SGID Binaries** - Finds exploitable binaries with GTFOBins integration
- **Sudo Misconfigurations** - Detects dangerous sudo permissions
- **Password Files** - Checks for writable /etc/passwd and /etc/shadow
- **Cron Jobs** - Identifies writable cron jobs and scripts
- **Kernel Exploits** - Maps kernel version to known CVEs
- **Linux Capabilities** - Detects dangerous capabilities on binaries

### 🔵 Blue Team Mode
Analyzes system logs for exploitation attempts:
- Parses `/var/log/auth.log` and `/var/log/syslog`
- Detects suspicious sudo activity and brute force attempts
- Identifies SUID binary execution patterns
- Monitors password file access
- Tracks cron job modifications
- Flags kernel-level attack indicators

### ⏱️ Timeline Mode
Reconstructs chronological attack sequences:
- Correlates events from multiple log sources
- Detects attack patterns (e.g., failed sudo → successful sudo)
- Builds visual timeline of privilege escalation attempts
- Exports timeline data for further analysis

## Architecture

```
privwatch/
├── privwatch_v2.py          # Main CLI (complete integration)
├── config/
│   ├── settings.py          # Configuration constants
│   └── vectors.json         # Vector definitions & severity ratings
├── core/
│   ├── scanner.py           # Base scanner class
│   ├── log_parser.py        # Base log parser class
│   └── logger.py            # Colored logging utilities
├── modules/
│   ├── red_mode/            # 6 Red Team scanners
│   │   ├── suid_scanner.py
│   │   ├── sudo_scanner.py
│   │   ├── passwd_scanner.py
│   │   ├── cron_scanner.py
│   │   ├── kernel_scanner.py
│   │   └── capabilities_scanner.py
│   ├── blue_mode/           # 6 Blue Team detectors
│   │   ├── suid_detector.py
│   │   ├── sudo_detector.py
│   │   ├── passwd_detector.py
│   │   ├── cron_detector.py
│   │   ├── kernel_detector.py
│   │   └── capabilities_detector.py
│   └── timeline/
│       ├── event_correlator.py
│       └── timeline_builder.py
├── utils/
│   ├── gtfobins.py          # GTFOBins database integration
│   ├── system_info.py       # System enumeration helpers
│   └── file_utils.py        # File permission checks
├── reports/
│   ├── json_exporter.py
│   └── pdf_generator.py
└── requirements.txt
```

## Installation

```bash
# Clone or copy the project
cd privwatch

# No external dependencies required!
# Optional: Install PDF support
# pip install reportlab
# OR
# pip install fpdf2
```

## Usage

### Basic Usage

```bash
# Red Team Mode - Enumerate privilege escalation vectors
python3 privwatch_v2.py --mode red

# Blue Team Mode - Analyze logs for attacks
sudo python3 privwatch_v2.py --mode blue

# Timeline Mode - Reconstruct attack timeline
sudo python3 privwatch_v2.py --mode timeline
```

### Advanced Options

```bash
# Generate both JSON and PDF reports
python3 privwatch_v2.py --mode red --format both

# Custom output directory
python3 privwatch_v2.py --mode blue --output /tmp/reports

# Full example
sudo python3 privwatch_v2.py --mode timeline --format both --output ./security_audit
```

## Output

Reports are generated in the specified output directory:
- `privwatch_red_YYYYMMDD_HHMMSS.json` - Red team findings
- `privwatch_blue_YYYYMMDD_HHMMSS.json` - Blue team findings
- `timeline_YYYYMMDD_HHMMSS.json` - Attack timeline data

## Permissions

- **Red Mode**: Can run as regular user (limited) or root (full access)
- **Blue Mode**: Requires root or sudo to read system logs
- **Timeline Mode**: Requires root or sudo to read system logs

## Lab Testing

PrivWatch is designed for security research and testing:
- Test on your Kali Linux system
- Deploy to Termux phones for mobile testing
- Use in CTF challenges and pentesting labs

## Example Output

```
╔═══════════════════════════════════════════════════════════╗
║                  PrivWatch v2.0                           ║
║        Privilege Escalation Detection & Forensics         ║
║                  Mode: RED TEAM                           ║
╚═══════════════════════════════════════════════════════════╝

[*] [16:30:45] Target: Linux 6.1.0-kali9-amd64

════════════════════════════════════════════════════════════
Scanning: SUID/SGID Binaries
════════════════════════════════════════════════════════════

[!!] [16:30:46] Exploitable SUID binary: find
[!] [16:30:47] Found 47 findings (3 CRITICAL, 8 HIGH)

════════════════════════════════════════════════════════════
SCAN SUMMARY
════════════════════════════════════════════════════════════

CRITICAL: 5
HIGH: 12
MEDIUM: 8
LOW: 3

Total Findings: 28
```

## GTFOBins Integration

PrivWatch includes a built-in GTFOBins database for instant exploit lookup:
- 14+ commonly exploitable binaries
- SUID and sudo exploitation techniques
- Direct command examples for privilege escalation

## Security Note

PrivWatch is designed for:
- ✅ Authorized security testing
- ✅ CTF challenges
- ✅ Educational purposes
- ✅ Your own systems and lab environments

**Do not use on systems you don't own or have explicit permission to test.**

## Author

Built for cybersecurity research and education.

## License

For educational and authorized security testing only.

---

**Version**: 2.0  
**Status**: Production Ready ✨
