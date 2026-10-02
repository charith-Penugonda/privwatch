#!/usr/bin/env python3
"""
PrivWatch - Privilege Escalation Reconnaissance Tool
Dual-mode tool for Red Team enumeration and Blue Team defense
"""

import os
import sys
import subprocess
import argparse
from pathlib import Path
from datetime import datetime

# Color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

class PrivWatch:
    def __init__(self, mode='red'):
        self.mode = mode
        self.findings = []

    def banner(self):
        """Display tool banner"""
        banner_text = f"""
{Colors.CYAN}╔═══════════════════════════════════════════════╗
║           PrivWatch v1.0 - Prototype          ║
║     Privilege Escalation Recon Tool           ║
║     Mode: {self.mode.upper():^30s}          ║
╚═══════════════════════════════════════════════╝{Colors.RESET}
"""
        print(banner_text)

    def log(self, message, level='info'):
        """Colored logging based on severity"""
        timestamp = datetime.now().strftime('%H:%M:%S')

        if level == 'critical':
            prefix = f"{Colors.RED}[!]{Colors.RESET}"
        elif level == 'high':
            prefix = f"{Colors.YELLOW}[+]{Colors.RESET}"
        elif level == 'success':
            prefix = f"{Colors.GREEN}[✓]{Colors.RESET}"
        else:
            prefix = f"{Colors.BLUE}[*]{Colors.RESET}"

        print(f"{prefix} [{timestamp}] {message}")

    def run_command(self, cmd):
        """Execute shell command and return output"""
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.stdout
        except Exception as e:
            return f"Error: {str(e)}"

    def check_suid_binaries(self):
        """Vector 1: Check for SUID/SGID binaries"""
        self.log("Scanning for SUID/SGID binaries...", 'info')

        cmd = "find / -type f \\( -perm -4000 -o -perm -2000 \\) 2>/dev/null"
        output = self.run_command(cmd)

        if output:
            binaries = output.strip().split('\n')

            # Known dangerous SUID binaries
            dangerous = ['nmap', 'vim', 'nano', 'find', 'bash', 'more', 'less',
                        'python', 'perl', 'ruby', 'cp', 'mv', 'awk', 'sed']

            found_dangerous = []
            for binary in binaries:
                for danger in dangerous:
                    if danger in binary.lower():
                        found_dangerous.append(binary)

            if self.mode == 'red':
                self.log(f"Found {len(binaries)} SUID/SGID binaries", 'success')
                if found_dangerous:
                    self.log(f"Potentially exploitable: {len(found_dangerous)}", 'high')
                    for binary in found_dangerous[:5]:  # Show first 5
                        print(f"    {Colors.YELLOW}→{Colors.RESET} {binary}")
                        self.findings.append({
                            'vector': 'SUID',
                            'item': binary,
                            'risk': 'HIGH'
                        })
            else:  # Blue team mode
                if found_dangerous:
                    self.log(f"ALERT: {len(found_dangerous)} risky SUID binaries detected", 'critical')
                    for binary in found_dangerous:
                        print(f"    {Colors.RED}⚠{Colors.RESET} {binary}")
                        self.findings.append({
                            'vector': 'SUID',
                            'item': binary,
                            'risk': 'HIGH',
                            'recommendation': 'Review necessity, remove SUID bit if not required'
                        })
                else:
                    self.log("SUID binary configuration appears safe", 'success')

    def check_sudo_config(self):
        """Vector 2: Check sudo misconfigurations"""
        self.log("Checking sudo configuration...", 'info')

        # Check sudo -l
        output = self.run_command("sudo -l 2>/dev/null")

        if output and "may run the following" in output.lower():
            if self.mode == 'red':
                self.log("User has sudo privileges", 'high')

                # Check for NOPASSWD
                if "NOPASSWD" in output:
                    self.log("NOPASSWD entries found - potential vector", 'high')
                    print(f"{Colors.YELLOW}{output}{Colors.RESET}")
                    self.findings.append({
                        'vector': 'SUDO',
                        'item': 'NOPASSWD configuration',
                        'risk': 'HIGH'
                    })

                # Check for dangerous commands
                dangerous_cmds = ['ALL', 'vim', 'nano', 'find', 'python', 'perl', 'bash']
                for cmd in dangerous_cmds:
                    if cmd in output:
                        self.findings.append({
                            'vector': 'SUDO',
                            'item': f'Sudo access to {cmd}',
                            'risk': 'HIGH'
                        })
            else:  # Blue team mode
                if "NOPASSWD" in output or "ALL" in output:
                    self.log("Overly permissive sudo configuration detected", 'critical')
                    self.findings.append({
                        'vector': 'SUDO',
                        'item': 'Permissive sudo rules',
                        'risk': 'HIGH',
                        'recommendation': 'Apply principle of least privilege'
                    })
        else:
            self.log("No sudo privileges for current user", 'info')

    def check_writable_paths(self):
        """Vector 3: Check for writable system paths"""
        self.log("Scanning for writable directories in PATH...", 'info')

        path_var = os.environ.get('PATH', '')
        paths = path_var.split(':')

        writable = []
        for path in paths:
            if os.path.exists(path) and os.access(path, os.W_OK):
                writable.append(path)

        if writable:
            if self.mode == 'red':
                self.log(f"Found {len(writable)} writable PATH directories", 'high')
                for path in writable:
                    print(f"    {Colors.YELLOW}→{Colors.RESET} {path}")
                    self.findings.append({
                        'vector': 'PATH',
                        'item': path,
                        'risk': 'MEDIUM'
                    })
            else:  # Blue team mode
                self.log(f"WARNING: {len(writable)} writable directories in PATH", 'critical')
                for path in writable:
                    print(f"    {Colors.RED}⚠{Colors.RESET} {path}")
                    self.findings.append({
                        'vector': 'PATH',
                        'item': path,
                        'risk': 'MEDIUM',
                        'recommendation': 'Remove write permissions for non-privileged users'
                    })
        else:
            self.log("PATH configuration appears secure", 'success')

    def check_cron_jobs(self):
        """Vector 4: Check for cron job misconfigurations"""
        self.log("Checking cron jobs...", 'info')

        # Check user crontab
        output = self.run_command("crontab -l 2>/dev/null")

        # Check system cron directories
        cron_dirs = ['/etc/cron.d/', '/etc/cron.daily/', '/etc/cron.hourly/']
        writable_crons = []

        for cron_dir in cron_dirs:
            if os.path.exists(cron_dir):
                try:
                    for item in os.listdir(cron_dir):
                        full_path = os.path.join(cron_dir, item)
                        if os.path.isfile(full_path) and os.access(full_path, os.W_OK):
                            writable_crons.append(full_path)
                except PermissionError:
                    pass

        if writable_crons:
            if self.mode == 'red':
                self.log(f"Found {len(writable_crons)} writable cron files", 'high')
                for cron in writable_crons[:3]:
                    print(f"    {Colors.YELLOW}→{Colors.RESET} {cron}")
                    self.findings.append({
                        'vector': 'CRON',
                        'item': cron,
                        'risk': 'HIGH'
                    })
            else:  # Blue team mode
                self.log(f"ALERT: {len(writable_crons)} writable cron files", 'critical')
                for cron in writable_crons:
                    print(f"    {Colors.RED}⚠{Colors.RESET} {cron}")
                    self.findings.append({
                        'vector': 'CRON',
                        'item': cron,
                        'risk': 'HIGH',
                        'recommendation': 'Restrict write permissions to root only'
                    })

    def generate_report(self):
        """Generate summary report"""
        print(f"\n{Colors.BOLD}{'='*50}")
        print(f"SCAN SUMMARY - {self.mode.upper()} TEAM MODE")
        print(f"{'='*50}{Colors.RESET}\n")

        if not self.findings:
            self.log("No significant findings", 'success')
            return

        # Group by risk level
        high_risk = [f for f in self.findings if f['risk'] == 'HIGH']
        medium_risk = [f for f in self.findings if f['risk'] == 'MEDIUM']

        print(f"{Colors.RED}HIGH RISK: {len(high_risk)}{Colors.RESET}")
        print(f"{Colors.YELLOW}MEDIUM RISK: {len(medium_risk)}{Colors.RESET}")
        print(f"\nTotal Findings: {len(self.findings)}\n")

        if self.mode == 'blue':
            print(f"{Colors.BOLD}RECOMMENDATIONS:{Colors.RESET}")
            for finding in self.findings[:5]:  # Show top 5
                if 'recommendation' in finding:
                    print(f"  • {finding['vector']}: {finding['recommendation']}")

    def run_scan(self):
        """Execute full scan based on mode"""
        self.banner()

        start_time = datetime.now()
        self.log(f"Starting {self.mode.upper()} team scan...\n", 'success')

        # Run all checks
        self.check_suid_binaries()
        print()
        self.check_sudo_config()
        print()
        self.check_writable_paths()
        print()
        self.check_cron_jobs()

        # Generate report
        self.generate_report()

        elapsed = (datetime.now() - start_time).total_seconds()
        print(f"\n{Colors.GREEN}Scan completed in {elapsed:.2f} seconds{Colors.RESET}\n")

def main():
    parser = argparse.ArgumentParser(
        description='PrivWatch - Privilege Escalation Reconnaissance Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Red Team Mode:  python3 privwatch.py --mode red
  Blue Team Mode: python3 privwatch.py --mode blue
        """
    )

    parser.add_argument(
        '--mode',
        choices=['red', 'blue'],
        default='red',
        help='Operation mode: red (offensive recon) or blue (defensive audit)'
    )

    args = parser.parse_args()

    # Check if running as root (recommended for full scans)
    if os.geteuid() != 0:
        print(f"{Colors.YELLOW}[!] Not running as root - some checks may be limited{Colors.RESET}\n")

    scanner = PrivWatch(mode=args.mode)
    scanner.run_scan()

if __name__ == '__main__':
    main()
