"""
Capabilities Scanner - Red Team Mode
Checks for dangerous Linux capabilities on binaries
"""

import os
from typing import List
from core.scanner import BaseScanner, Finding
from config.settings import (SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM,
                             VECTOR_CAPABILITIES, DANGEROUS_CAPABILITIES)


class CapabilitiesScanner(BaseScanner):
    """Scanner for Linux capabilities privilege escalation vectors"""

    # Capability exploitation techniques
    CAP_EXPLOITS = {
        'cap_setuid': {
            'description': 'Allows changing UID, direct privilege escalation',
            'exploit': 'Binary can call setuid(0) to become root',
            'severity': SEVERITY_CRITICAL
        },
        'cap_setgid': {
            'description': 'Allows changing GID, can escalate to privileged groups',
            'exploit': 'Binary can call setgid() to join privileged groups',
            'severity': SEVERITY_CRITICAL
        },
        'cap_dac_override': {
            'description': 'Bypass file read/write/execute permission checks',
            'exploit': 'Can read/write any file including /etc/shadow',
            'severity': SEVERITY_HIGH
        },
        'cap_dac_read_search': {
            'description': 'Bypass file read and directory search checks',
            'exploit': 'Can read sensitive files like /etc/shadow',
            'severity': SEVERITY_HIGH
        },
        'cap_sys_admin': {
            'description': 'Wide range of administrative operations',
            'exploit': 'Can mount filesystems, modify kernel parameters',
            'severity': SEVERITY_CRITICAL
        },
        'cap_sys_ptrace': {
            'description': 'Can trace arbitrary processes',
            'exploit': 'Inject code into root processes',
            'severity': SEVERITY_HIGH
        },
        'cap_sys_module': {
            'description': 'Load and unload kernel modules',
            'exploit': 'Load malicious kernel module for root access',
            'severity': SEVERITY_CRITICAL
        },
        'cap_chown': {
            'description': 'Change file ownership',
            'exploit': 'Take ownership of sensitive files',
            'severity': SEVERITY_HIGH
        },
        'cap_fowner': {
            'description': 'Bypass permission checks on file operations',
            'exploit': 'Modify protected files',
            'severity': SEVERITY_HIGH
        }
    }

    def __init__(self):
        super().__init__(VECTOR_CAPABILITIES)

    def scan(self) -> List[Finding]:
        """Execute capabilities scan"""
        # Check if getcap is available
        getcap_check = self.run_command("which getcap")
        if not getcap_check:
            self.add_finding(
                severity=SEVERITY_MEDIUM,
                title="getcap tool not available",
                description="The getcap tool is not installed. Cannot check for capabilities.",
                evidence="getcap command not found",
                remediation="Install libcap2-bin: apt-get install libcap2-bin"
            )
            return self.findings

        # Find all files with capabilities set
        self._find_capabilities()

        return self.findings

    def _find_capabilities(self):
        """Find binaries with capabilities set"""
        # Search system for files with capabilities
        cmd = "getcap -r / 2>/dev/null"
        output = self.run_command(cmd, timeout=60)

        if not output:
            self.add_finding(
                severity=SEVERITY_MEDIUM,
                title="No capabilities found",
                description="No binaries with capabilities detected on the system.",
                evidence="getcap scan completed with no results",
                remediation="System appears secure from capabilities exploitation"
            )
            return

        lines = output.strip().split('\n')

        for line in lines:
            if '=' not in line:
                continue

            # Parse: /path/to/binary = cap_name+ep
            parts = line.split('=')
            if len(parts) < 2:
                continue

            binary_path = parts[0].strip()
            caps_str = parts[1].strip()

            self._analyze_capability(binary_path, caps_str)

    def _analyze_capability(self, binary_path: str, caps_str: str):
        """Analyze a binary with capabilities"""
        binary_name = os.path.basename(binary_path)

        # Parse capabilities
        caps = self._parse_capabilities(caps_str)

        # Check each capability
        for cap in caps:
            cap_lower = cap.lower()

            if cap_lower in self.CAP_EXPLOITS:
                exploit_info = self.CAP_EXPLOITS[cap_lower]

                self.add_finding(
                    severity=exploit_info['severity'],
                    title=f"Dangerous capability on {binary_name}: {cap}",
                    description=f"Binary {binary_path} has {cap} capability set.\n"
                               f"{exploit_info['description']}\n\n"
                               f"Exploitation: {exploit_info['exploit']}",
                    evidence=f"Binary: {binary_path}\n"
                            f"Capability: {caps_str}\n"
                            f"Risk: {exploit_info['exploit']}",
                    remediation=f"Remove capability: setcap -r {binary_path}\n"
                               f"Or exploit if red teaming"
                )
            else:
                # Non-critical capability but still worth noting
                self.add_finding(
                    severity=SEVERITY_MEDIUM,
                    title=f"Capability found on {binary_name}: {cap}",
                    description=f"Binary {binary_path} has {cap} capability. "
                               f"Review for potential exploitation.",
                    evidence=f"Binary: {binary_path}\nCapability: {caps_str}",
                    remediation=f"Research exploitation techniques for {cap}"
                )

    def _parse_capabilities(self, caps_str: str) -> List[str]:
        """Parse capability string into list of capabilities"""
        # Format: cap_name1,cap_name2+ep
        # Remove the +ep/+eip suffix
        caps_clean = caps_str.split('+')[0]

        # Split by comma
        caps = [c.strip() for c in caps_clean.split(',') if c.strip()]

        return caps
