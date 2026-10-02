"""
SUID/SGID Binary Scanner - Red Team Mode
Enumerates SUID/SGID binaries and identifies exploitable ones
"""

import os
from typing import List
from core.scanner import BaseScanner, Finding
from utils.gtfobins import GTFOBins
from utils.file_utils import is_suid, is_sgid, get_permission_string
from config.settings import SEVERITY_CRITICAL, SEVERITY_HIGH, VECTOR_SUID


class SuidScanner(BaseScanner):
    """Scanner for SUID/SGID privilege escalation vectors"""

    def __init__(self):
        super().__init__(VECTOR_SUID)

    def scan(self) -> List[Finding]:
        """Execute SUID/SGID binary scan"""
        # Find all SUID/SGID binaries
        cmd = "find / -type f \\( -perm -4000 -o -perm -2000 \\) 2>/dev/null"
        output = self.run_command(cmd, timeout=60)

        if not output:
            return self.findings

        binaries = [b.strip() for b in output.split('\n') if b.strip()]

        # Analyze each binary
        for binary in binaries:
            self._analyze_binary(binary)

        return self.findings

    def _analyze_binary(self, binary_path: str):
        """Analyze a single SUID/SGID binary for exploitability"""
        if not os.path.exists(binary_path):
            return

        binary_name = os.path.basename(binary_path)
        perms = get_permission_string(binary_path)

        # Check if binary is in GTFOBins
        gtfo_entry = GTFOBins.lookup(binary_name)

        if gtfo_entry:
            # This is a known exploitable binary
            exploit_cmd = GTFOBins.get_exploit_command(binary_name, 'suid')

            self.add_finding(
                severity=SEVERITY_CRITICAL,
                title=f"Exploitable SUID binary: {binary_name}",
                description=f"The binary {binary_path} has SUID bit set and is known to be exploitable. "
                           f"{gtfo_entry.get('description', '')}",
                evidence=f"Binary: {binary_path}\n"
                        f"Permissions: {perms}\n"
                        f"Exploit: {exploit_cmd if exploit_cmd else 'Multiple methods available'}",
                remediation=f"Remove SUID bit: chmod u-s {binary_path}\n"
                           f"Or review if elevated privileges are necessary for this binary."
            )
        else:
            # Non-GTFOBins SUID binary - still worth noting
            self.add_finding(
                severity=SEVERITY_HIGH,
                title=f"SUID binary found: {binary_name}",
                description=f"Binary {binary_path} has SUID/SGID bit set. "
                           f"May be exploitable if vulnerable or misconfigured.",
                evidence=f"Binary: {binary_path}\nPermissions: {perms}",
                remediation=f"Review necessity of SUID bit for {binary_path}"
            )
