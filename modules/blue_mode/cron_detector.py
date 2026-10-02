"""
Cron Job Log Analyzer - Blue Team Mode
Analyzes cron logs for suspicious job execution
"""

import re
from typing import List
from core.log_parser import LogParser, Finding
from config.settings import SEVERITY_HIGH, SEVERITY_MEDIUM, VECTOR_CRON, LOG_SYSLOG


class CronDetector(LogParser):
    """Detector for suspicious cron job activity"""

    def __init__(self):
        super().__init__(VECTOR_CRON)

    def parse(self, log_file: str = LOG_SYSLOG) -> List[Finding]:
        """Parse syslog for cron activity"""
        try:
            with open(log_file, 'r') as f:
                lines = f.readlines()
        except Exception:
            return self.findings

        cron_jobs = []

        for line in lines:
            if 'CRON' in line or 'cron' in line:
                cron_jobs.append(line)
                self._analyze_cron_execution(line)

        if len(cron_jobs) > 0:
            self.add_finding(
                severity=SEVERITY_MEDIUM,
                title=f"Cron activity detected",
                description=f"Found {len(cron_jobs)} cron job executions in logs",
                evidence=f"Total cron jobs: {len(cron_jobs)}",
                remediation="Review cron jobs for unauthorized modifications"
            )

        return self.findings

    def _analyze_cron_execution(self, line: str):
        """Analyze cron job execution"""
        # Look for suspicious commands in cron execution
        suspicious_patterns = [
            'bash', 'sh', 'nc', 'netcat', 'wget', 'curl',
            'python', 'perl', 'reverse', 'shell'
        ]

        for pattern in suspicious_patterns:
            if pattern in line.lower():
                timestamp = self.parse_syslog_timestamp(line)

                self.add_finding(
                    severity=SEVERITY_HIGH,
                    title=f"Suspicious cron job execution: {pattern}",
                    description=f"Cron job contains potentially malicious command: {pattern}",
                    evidence=line.strip(),
                    remediation="Investigate cron job and verify authorization"
                )

                if timestamp:
                    self.add_event(
                        timestamp=timestamp,
                        event_type='CRON_SUSPICIOUS',
                        source=LOG_SYSLOG,
                        details={'pattern': pattern, 'log_line': line.strip()}
                    )
                break
