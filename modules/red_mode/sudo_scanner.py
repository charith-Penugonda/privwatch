"""
Sudo Misconfiguration Scanner - Red Team Mode
Checks for dangerous sudo permissions
"""

import re
from typing import List
from core.scanner import BaseScanner, Finding
from utils.gtfobins import GTFOBins
from config.settings import (SEVERITY_CRITICAL, SEVERITY_HIGH,
                             SEVERITY_MEDIUM, VECTOR_SUDO, DANGEROUS_SUDO)


class SudoScanner(BaseScanner):
    """Scanner for sudo privilege escalation vectors"""

    def __init__(self):
        super().__init__(VECTOR_SUDO)

    def scan(self) -> List[Finding]:
        """Execute sudo configuration scan"""
        # Check sudo -l output
        output = self.run_command("sudo -l 2>/dev/null")

        if not output or "may run the following" not in output.lower():
            return self.findings

        # Parse sudo rules
        self._analyze_sudo_rules(output)

        # Check /etc/sudoers if readable
        self._check_sudoers_file()

        return self.findings

    def _analyze_sudo_rules(self, sudo_output: str):
        """Analyze sudo -l output for dangerous configurations"""
        lines = sudo_output.split('\n')

        # Check for NOPASSWD
        if "NOPASSWD" in sudo_output:
            nopasswd_lines = [l for l in lines if "NOPASSWD" in l]

            for line in nopasswd_lines:
                # Check if dangerous commands are allowed
                if "ALL" in line:
                    self.add_finding(
                        severity=SEVERITY_CRITICAL,
                        title="Sudo NOPASSWD with ALL commands",
                        description="User can run ALL commands as root without password. "
                                   "Immediate privilege escalation possible.",
                        evidence=line.strip(),
                        remediation="Remove NOPASSWD or restrict to specific safe commands"
                    )
                else:
                    # Check for specific dangerous commands
                    for dangerous_cmd in DANGEROUS_SUDO:
                        if dangerous_cmd.lower() in line.lower():
                            gtfo_entry = GTFOBins.lookup(dangerous_cmd)
                            exploit_info = ""
                            if gtfo_entry:
                                exploit_cmd = GTFOBins.get_exploit_command(dangerous_cmd, 'sudo')
                                exploit_info = f"\nExploit: {exploit_cmd}"

                            self.add_finding(
                                severity=SEVERITY_CRITICAL,
                                title=f"Dangerous sudo NOPASSWD: {dangerous_cmd}",
                                description=f"User can run {dangerous_cmd} as root without password. "
                                           f"This can be exploited for privilege escalation.",
                                evidence=line.strip() + exploit_info,
                                remediation=f"Remove NOPASSWD for {dangerous_cmd} or remove sudo access entirely"
                            )
                            break

        # Check for sudo access to shells
        shells = ['bash', 'sh', 'dash', 'zsh', 'fish']
        for shell in shells:
            if shell in sudo_output.lower():
                self.add_finding(
                    severity=SEVERITY_CRITICAL,
                    title=f"Sudo access to shell: {shell}",
                    description=f"User has sudo access to {shell}, allowing direct root shell.",
                    evidence=f"Command: sudo {shell}",
                    remediation=f"Remove sudo access to {shell}"
                )

        # Check for environment variable preservation
        if "env_keep" in sudo_output.lower() or "SETENV" in sudo_output:
            self.add_finding(
                severity=SEVERITY_HIGH,
                title="Sudo environment variable preservation enabled",
                description="User can preserve environment variables, potentially allowing "
                           "LD_PRELOAD or LD_LIBRARY_PATH exploitation.",
                evidence="SETENV or env_keep detected in sudo configuration",
                remediation="Restrict environment variable preservation"
            )

    def _check_sudoers_file(self):
        """Check /etc/sudoers if readable"""
        sudoers_path = "/etc/sudoers"

        # Try to read sudoers file
        output = self.run_command(f"cat {sudoers_path} 2>/dev/null")

        if output and len(output) > 10:
            # We can read sudoers - this itself is a finding
            self.add_finding(
                severity=SEVERITY_HIGH,
                title="/etc/sudoers is readable",
                description="The /etc/sudoers file is readable by current user. "
                           "This reveals sudo configuration and potential attack vectors.",
                evidence=f"File: {sudoers_path} is readable",
                remediation=f"Restrict permissions on {sudoers_path} to root only"
            )
