"""
Capabilities Log Analyzer - Blue Team Mode
Analyzes logs for suspicious capability usage
"""

import re
from typing import List
from core.log_parser import LogParser, Finding
from config.settings import SEVERITY_HIGH, SEVERITY_MEDIUM, VECTOR_CAPABILITIES, LOG_SYSLOG


class CapabilitiesDetector(LogParser):
    """Detector for Linux capabilities exploitation attempts"""

    def __init__(self):
        super().__init__(VECTOR_CAPABILITIES)

    def parse(self, log_file: str = LOG_SYSLOG) -> List[Finding]:
        """Parse logs for capability-related activity"""
        try:
            with open(log_file, 'r') as f:
                lines = f.readlines()
        except Exception:
            return self.findings

        # Look for capability-related log entries
        cap_patterns = [
            (r'cap_setuid', 'CAP_SETUID usage detected'),
            (r'cap_sys_admin', 'CAP_SYS_ADMIN usage detected'),
            (r'cap_dac_override', 'CAP_DAC_OVERRIDE usage detected'),
            (r'setcap', 'Capability modification'),
            (r'getcap', 'Capability enumeration'),
        ]

        for line in lines:
            for pattern, description in cap_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    timestamp = self.parse_syslog_timestamp(line)

                    self.add_finding(
                        severity=SEVERITY_HIGH,
                        title=description,
                        description=f"Detected capability-related activity in logs",
                        evidence=line.strip(),
                        remediation="Review capability usage and verify authorization"
                    )

                    if timestamp:
                        self.add_event(
                            timestamp=timestamp,
                            event_type='CAPABILITY_ACTIVITY',
                            source=log_file,
                            details={'pattern': pattern, 'log_line': line.strip()}
                        )
                    break

        return self.findings
