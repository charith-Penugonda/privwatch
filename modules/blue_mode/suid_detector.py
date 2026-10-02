"""
SUID Log Analyzer - Blue Team Mode
Analyzes system logs for SUID binary execution patterns
"""

import re
from typing import List
from core.log_parser import LogParser, Finding
from config.settings import (SEVERITY_HIGH, SEVERITY_MEDIUM,
                             VECTOR_SUID, LOG_SYSLOG)


class SuidDetector(LogParser):
    """Detector for SUID binary exploitation attempts"""

    def __init__(self):
        super().__init__(VECTOR_SUID)

    def parse(self, log_file: str = LOG_SYSLOG) -> List[Finding]:
        """Parse syslog for SUID-related activity"""
        try:
            with open(log_file, 'r') as f:
                lines = f.readlines()
        except Exception as e:
            self.add_finding(
                severity=SEVERITY_MEDIUM,
                title=f"Cannot read {log_file}",
                description=f"Unable to analyze SUID logs: {str(e)}",
                evidence=str(e),
                remediation="Check file permissions and path"
            )
            return self.findings

        # Track suspicious patterns
        suspicious_binaries = ['nmap', 'vim', 'find', 'python', 'perl', 'bash']

        for line in lines:
            # Look for execution of known dangerous SUID binaries
            for binary in suspicious_binaries:
                if binary in line.lower():
                    timestamp = self.parse_syslog_timestamp(line)

                    self.add_finding(
                        severity=SEVERITY_HIGH,
                        title=f"Execution of potentially exploitable binary: {binary}",
                        description=f"Detected execution of {binary}, which is known to be "
                                   f"exploitable when SUID bit is set.",
                        evidence=line.strip(),
                        remediation=f"Investigate if {binary} has SUID bit and review execution context"
                    )

                    if timestamp:
                        self.add_event(
                            timestamp=timestamp,
                            event_type='SUID_EXECUTION',
                            source=log_file,
                            details={'binary': binary, 'log_line': line.strip()}
                        )
                    break

        return self.findings
