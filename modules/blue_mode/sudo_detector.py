"""
Sudo Log Analyzer - Blue Team Mode
Analyzes auth.log for suspicious sudo activity
"""

import re
from typing import List
from datetime import datetime, timedelta
from collections import defaultdict
from core.log_parser import LogParser, Finding
from config.settings import (SEVERITY_CRITICAL, SEVERITY_HIGH,
                             SEVERITY_MEDIUM, VECTOR_SUDO, LOG_AUTH)


class SudoDetector(LogParser):
    """Detector for sudo-based privilege escalation attempts"""

    def __init__(self):
        super().__init__(VECTOR_SUDO)

    def parse(self, log_file: str = LOG_AUTH) -> List[Finding]:
        """Parse auth.log for sudo activity"""
        try:
            with open(log_file, 'r') as f:
                lines = f.readlines()
        except Exception as e:
            self.add_finding(
                severity=SEVERITY_MEDIUM,
                title=f"Cannot read {log_file}",
                description=f"Unable to analyze sudo logs: {str(e)}",
                evidence=str(e),
                remediation="Check file permissions and path"
            )
            return self.findings

        # Track sudo activity patterns
        sudo_commands = []
        failed_attempts = []
        password_prompts = []

        for line in lines:
            # Parse sudo command execution
            if 'sudo:' in line and 'COMMAND=' in line:
                sudo_commands.append(line)
                self._analyze_sudo_command(line)

            # Parse failed sudo attempts
            if 'sudo:' in line and ('authentication failure' in line or
                                    'incorrect password' in line or
                                    '3 incorrect password attempts' in line):
                failed_attempts.append(line)
                self._analyze_failed_sudo(line)

            # Parse password prompt bypasses (NOPASSWD)
            if 'sudo:' in line and 'NOPASSWD' in line:
                password_prompts.append(line)
                self._analyze_nopasswd_usage(line)

        # Analyze patterns
        self._analyze_sudo_patterns(sudo_commands)
        self._analyze_brute_force_attempts(failed_attempts)

        return self.findings

    def _analyze_sudo_command(self, line: str):
        """Analyze a sudo command execution"""
        timestamp = self.parse_syslog_timestamp(line)

        # Extract user and command
        user_match = re.search(r'(\w+)\s*:\s*TTY', line)
        cmd_match = re.search(r'COMMAND=(.+)$', line)

        if not user_match or not cmd_match:
            return

        user = user_match.group(1)
        command = cmd_match.group(1).strip()

        # Check for dangerous commands
        dangerous_patterns = [
            ('bash', 'Shell access via sudo'),
            ('sh', 'Shell access via sudo'),
            ('/bin/bash', 'Direct shell execution'),
            ('/bin/sh', 'Direct shell execution'),
            ('vim', 'Text editor with shell escape'),
            ('nano', 'Text editor with command execution'),
            ('python', 'Scripting language with OS access'),
            ('perl', 'Scripting language with OS access'),
            ('find.*-exec', 'File search with command execution'),
            ('chmod', 'Permission modification'),
            ('chown', 'Ownership change'),
            ('su ', 'User switching'),
            ('passwd', 'Password change attempt')
        ]

        for pattern, description in dangerous_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                self.add_finding(
                    severity=SEVERITY_HIGH,
                    title=f"Suspicious sudo command: {pattern}",
                    description=f"User {user} executed potentially dangerous command via sudo.\n"
                               f"{description}",
                    evidence=f"Timestamp: {timestamp}\nUser: {user}\nCommand: {command}",
                    remediation="Review sudo policy and investigate user activity"
                )

                # Add event for timeline
                if timestamp:
                    self.add_event(
                        timestamp=timestamp,
                        event_type='SUDO_COMMAND',
                        source=LOG_AUTH,
                        details={'user': user, 'command': command}
                    )
                break

    def _analyze_failed_sudo(self, line: str):
        """Analyze failed sudo attempt"""
        timestamp = self.parse_syslog_timestamp(line)

        user_match = re.search(r'(\w+)\s*:', line)
        if user_match:
            user = user_match.group(1)

            self.add_finding(
                severity=SEVERITY_MEDIUM,
                title=f"Failed sudo attempt by {user}",
                description=f"User {user} failed sudo authentication",
                evidence=line.strip(),
                remediation="Investigate if this is a brute force attempt or misconfiguration"
            )

            if timestamp:
                self.add_event(
                    timestamp=timestamp,
                    event_type='SUDO_FAILED',
                    source=LOG_AUTH,
                    details={'user': user}
                )

    def _analyze_nopasswd_usage(self, line: str):
        """Analyze NOPASSWD sudo usage"""
        timestamp = self.parse_syslog_timestamp(line)

        user_match = re.search(r'(\w+)\s*:', line)
        if user_match:
            user = user_match.group(1)

            self.add_finding(
                severity=SEVERITY_HIGH,
                title=f"NOPASSWD sudo usage by {user}",
                description=f"User {user} executed sudo command without password requirement",
                evidence=line.strip(),
                remediation="Review NOPASSWD configuration in /etc/sudoers"
            )

    def _analyze_sudo_patterns(self, sudo_commands: List[str]):
        """Analyze patterns in sudo command history"""
        if len(sudo_commands) > 100:
            self.add_finding(
                severity=SEVERITY_MEDIUM,
                title="High volume of sudo commands",
                description=f"Detected {len(sudo_commands)} sudo command executions. "
                           f"This may indicate enumeration or automated attacks.",
                evidence=f"Total sudo commands: {len(sudo_commands)}",
                remediation="Review sudo logs for patterns and anomalies"
            )

    def _analyze_brute_force_attempts(self, failed_attempts: List[str]):
        """Detect sudo brute force attempts"""
        if len(failed_attempts) > 10:
            # Group by user
            user_failures = defaultdict(int)
            for line in failed_attempts:
                user_match = re.search(r'(\w+)\s*:', line)
                if user_match:
                    user_failures[user_match.group(1)] += 1

            for user, count in user_failures.items():
                if count >= 5:
                    self.add_finding(
                        severity=SEVERITY_CRITICAL,
                        title=f"Possible sudo brute force: {user}",
                        description=f"User {user} has {count} failed sudo attempts. "
                                   f"This may indicate a brute force attack or compromised account.",
                        evidence=f"Failed attempts: {count}",
                        remediation="Lock account, review logs, check for compromised credentials"
                    )
