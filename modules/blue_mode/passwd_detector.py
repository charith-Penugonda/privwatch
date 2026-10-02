"""
Password File Log Analyzer - Blue Team Mode
Analyzes logs for /etc/passwd and /etc/shadow access
"""

import re
from typing import List
from core.log_parser import LogParser, Finding
from config.settings import (SEVERITY_CRITICAL, SEVERITY_HIGH,
                             VECTOR_PASSWD, LOG_SYSLOG, LOG_AUTH)


class PasswdDetector(LogParser):
    """Detector for password file access and modifications"""

    def __init__(self):
        super().__init__(VECTOR_PASSWD)

    def parse(self, log_file: str = LOG_AUTH) -> List[Finding]:
        """Parse logs for password file access"""
        log_files = [LOG_AUTH, LOG_SYSLOG]

        for log_path in log_files:
            try:
                with open(log_path, 'r') as f:
                    lines = f.readlines()

                for line in lines:
                    self._analyze_passwd_access(line, log_path)
            except Exception:
                continue

        return self.findings

    def _analyze_passwd_access(self, line: str, source: str):
        """Analyze line for password file access"""
        passwd_patterns = [
            (r'/etc/passwd', 'Access to /etc/passwd'),
            (r'/etc/shadow', 'Access to /etc/shadow'),
            (r'useradd', 'User account creation'),
            (r'usermod', 'User account modification'),
            (r'passwd\s+\w+', 'Password change command')
        ]

        for pattern, description in passwd_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                timestamp = self.parse_syslog_timestamp(line)

                severity = SEVERITY_CRITICAL if '/etc/shadow' in line else SEVERITY_HIGH

                self.add_finding(
                    severity=severity,
                    title=description,
                    description=f"Detected password file access or modification",
                    evidence=line.strip(),
                    remediation="Review activity and verify authorization"
                )

                if timestamp:
                    self.add_event(
                        timestamp=timestamp,
                        event_type='PASSWD_ACCESS',
                        source=source,
                        details={'activity': description, 'log_line': line.strip()}
                    )
                break
