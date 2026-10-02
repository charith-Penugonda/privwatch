"""
Password File Scanner - Red Team Mode
Checks for writable /etc/passwd and /etc/shadow
"""

import os
from typing import List
from core.scanner import BaseScanner, Finding
from utils.file_utils import is_world_writable
from config.settings import SEVERITY_CRITICAL, SEVERITY_HIGH, VECTOR_PASSWD


class PasswdScanner(BaseScanner):
    """Scanner for password file vulnerabilities"""

    def __init__(self):
        super().__init__(VECTOR_PASSWD)

    def scan(self) -> List[Finding]:
        """Execute password file security scan"""
        # Check /etc/passwd
        self._check_passwd_file()

        # Check /etc/shadow
        self._check_shadow_file()

        # Check for backup files
        self._check_backup_files()

        return self.findings

    def _check_passwd_file(self):
        """Check /etc/passwd for write access and misconfigurations"""
        passwd_path = "/etc/passwd"

        # Check if writable
        if os.access(passwd_path, os.W_OK):
            self.add_finding(
                severity=SEVERITY_CRITICAL,
                title="/etc/passwd is writable",
                description="The /etc/passwd file is writable by current user. "
                           "This allows creating new root users or modifying existing accounts. "
                           "Immediate privilege escalation possible.",
                evidence=f"File: {passwd_path}\nWritable by current user",
                remediation="Exploit: echo 'hacker:x:0:0:root:/root:/bin/bash' >> /etc/passwd\n"
                           "Defense: chmod 644 /etc/passwd"
            )

        # Check for world-writable
        if is_world_writable(passwd_path):
            self.add_finding(
                severity=SEVERITY_CRITICAL,
                title="/etc/passwd is world-writable",
                description="The /etc/passwd file has world-write permissions.",
                evidence=f"File: {passwd_path}\nWorld-writable permissions detected",
                remediation="chmod 644 /etc/passwd"
            )

        # Check for empty password fields
        try:
            with open(passwd_path, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    if line.strip() and not line.startswith('#'):
                        parts = line.split(':')
                        if len(parts) >= 2 and parts[1] == '':
                            username = parts[0]
                            self.add_finding(
                                severity=SEVERITY_CRITICAL,
                                title=f"User with empty password: {username}",
                                description=f"User {username} has an empty password field in /etc/passwd. "
                                           f"This may allow passwordless login.",
                                evidence=f"Line {line_num}: {line.strip()}",
                                remediation=f"Set a password for {username} or disable the account"
                            )
        except Exception:
            pass

    def _check_shadow_file(self):
        """Check /etc/shadow for read/write access"""
        shadow_path = "/etc/shadow"

        # Check if writable
        if os.access(shadow_path, os.W_OK):
            self.add_finding(
                severity=SEVERITY_CRITICAL,
                title="/etc/shadow is writable",
                description="The /etc/shadow file is writable by current user. "
                           "This allows password hash modification for privilege escalation.",
                evidence=f"File: {shadow_path}\nWritable by current user",
                remediation="chmod 640 /etc/shadow and chown root:shadow /etc/shadow"
            )

        # Check if readable
        if os.access(shadow_path, os.R_OK):
            self.add_finding(
                severity=SEVERITY_HIGH,
                title="/etc/shadow is readable",
                description="The /etc/shadow file is readable by current user. "
                           "Password hashes can be extracted for offline cracking.",
                evidence=f"File: {shadow_path}\nReadable by current user",
                remediation="Extract hashes: cat /etc/shadow\n"
                           "Crack with: john --wordlist=/usr/share/wordlists/rockyou.txt shadow.txt\n"
                           "Defense: chmod 640 /etc/shadow"
            )

    def _check_backup_files(self):
        """Check for readable backup password files"""
        backup_files = [
            "/etc/passwd-", "/etc/passwd.bak", "/etc/passwd.old",
            "/etc/shadow-", "/etc/shadow.bak", "/etc/shadow.old",
            "/var/backups/passwd.bak", "/var/backups/shadow.bak"
        ]

        for backup_path in backup_files:
            if os.path.exists(backup_path) and os.access(backup_path, os.R_OK):
                self.add_finding(
                    severity=SEVERITY_HIGH,
                    title=f"Readable password backup: {os.path.basename(backup_path)}",
                    description=f"Backup password file {backup_path} is readable. "
                               f"May contain old credentials or configuration.",
                    evidence=f"File: {backup_path}\nReadable by current user",
                    remediation=f"Secure or remove backup file: {backup_path}"
                )
