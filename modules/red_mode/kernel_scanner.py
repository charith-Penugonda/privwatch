"""
Kernel Exploit Scanner - Red Team Mode
Checks for vulnerable kernel versions with known exploits
"""

import re
from typing import List, Dict, Optional
from core.scanner import BaseScanner, Finding
from utils.system_info import get_kernel_version, get_os_info
from config.settings import SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, VECTOR_KERNEL


class KernelScanner(BaseScanner):
    """Scanner for kernel exploit privilege escalation vectors"""

    # Known vulnerable kernel versions with public exploits
    KNOWN_EXPLOITS = {
        'DirtyCOW': {
            'versions': ['2.6.22', '3.', '4.0', '4.1', '4.2', '4.3', '4.4', '4.5', '4.6', '4.7', '4.8'],
            'cve': 'CVE-2016-5195',
            'description': 'Race condition in memory subsystem allows privilege escalation',
            'severity': SEVERITY_CRITICAL,
            'exploit_url': 'https://github.com/dirtycow/dirtycow.github.io'
        },
        'DirtyCred': {
            'versions': ['5.8', '5.9', '5.10', '5.11', '5.12', '5.13', '5.14', '5.15', '5.16', '5.17', '5.18', '6.0'],
            'cve': 'CVE-2022-0847',
            'description': 'Kernel credentials switching vulnerability',
            'severity': SEVERITY_CRITICAL,
            'exploit_url': 'https://github.com/Markakd/DirtyCred'
        },
        'OverlayFS': {
            'versions': ['3.', '4.', '5.0', '5.1', '5.2', '5.3', '5.4', '5.5', '5.6', '5.7', '5.8', '5.9', '5.10'],
            'cve': 'CVE-2021-3493',
            'description': 'OverlayFS allows privilege escalation via capabilities',
            'severity': SEVERITY_HIGH,
            'exploit_url': 'https://github.com/briskets/CVE-2021-3493'
        },
        'PwnKit': {
            'versions': ['2.6', '3.', '4.', '5.'],
            'cve': 'CVE-2021-4034',
            'description': 'pkexec vulnerability (not kernel but related)',
            'severity': SEVERITY_CRITICAL,
            'exploit_url': 'https://github.com/arthepsy/CVE-2021-4034'
        }
    }

    def __init__(self):
        super().__init__(VECTOR_KERNEL)

    def scan(self) -> List[Finding]:
        """Execute kernel vulnerability scan"""
        kernel_version = get_kernel_version()
        os_info = get_os_info()

        # Check kernel version
        self._check_kernel_version(kernel_version, os_info)

        # Check for kernel exploit suggester tools
        self._suggest_exploit_tools(kernel_version)

        return self.findings

    def _check_kernel_version(self, kernel_version: str, os_info: Dict):
        """Check if kernel version is vulnerable to known exploits"""
        # Report kernel info
        self.add_finding(
            severity=SEVERITY_MEDIUM,
            title=f"Kernel version: {kernel_version}",
            description=f"System information:\n"
                       f"Kernel: {kernel_version}\n"
                       f"System: {os_info.get('system', 'Unknown')}\n"
                       f"Machine: {os_info.get('machine', 'Unknown')}",
            evidence=f"uname -r output: {kernel_version}",
            remediation="Check kernel version against known exploits"
        )

        # Check against known exploits
        for exploit_name, exploit_info in self.KNOWN_EXPLOITS.items():
            if self._is_version_vulnerable(kernel_version, exploit_info['versions']):
                self.add_finding(
                    severity=exploit_info['severity'],
                    title=f"Potentially vulnerable to {exploit_name} ({exploit_info['cve']})",
                    description=f"{exploit_info['description']}\n\n"
                               f"Kernel {kernel_version} may be vulnerable to {exploit_name}. "
                               f"Public exploit available.",
                    evidence=f"Kernel version: {kernel_version}\n"
                            f"CVE: {exploit_info['cve']}\n"
                            f"Exploit: {exploit_info['exploit_url']}",
                    remediation=f"1. Download exploit from: {exploit_info['exploit_url']}\n"
                               f"2. Compile and run the exploit\n"
                               f"3. Defense: Update kernel to latest stable version"
                )

    def _is_version_vulnerable(self, kernel_version: str, vulnerable_patterns: List[str]) -> bool:
        """Check if kernel version matches vulnerable patterns"""
        for pattern in vulnerable_patterns:
            if kernel_version.startswith(pattern):
                return True
        return False

    def _suggest_exploit_tools(self, kernel_version: str):
        """Suggest using kernel exploit enumeration tools"""
        self.add_finding(
            severity=SEVERITY_MEDIUM,
            title="Kernel exploit enumeration recommended",
            description="Use specialized tools for comprehensive kernel exploit checking:\n"
                       "• linux-exploit-suggester\n"
                       "• Linux Kernel CVE Exploits\n"
                       "• searchsploit",
            evidence=f"Current kernel: {kernel_version}",
            remediation="Run: searchsploit linux kernel {}\n"
                       "Or: wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh\n"
                       "chmod +x linux-exploit-suggester.sh && ./linux-exploit-suggester.sh".format(
                           kernel_version.split('-')[0])
        )
