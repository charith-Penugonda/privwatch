"""
System Information Utilities
Helper functions for system enumeration
"""

import os
import subprocess
import platform
from typing import Dict, Optional


def run_command(cmd: str, timeout: int = 30) -> str:
    """Execute shell command safely"""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout.strip()
    except Exception:
        return ""


def get_kernel_version() -> str:
    """Get kernel version"""
    return platform.release()


def get_os_info() -> Dict[str, str]:
    """Get OS information"""
    return {
        'system': platform.system(),
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine()
    }


def get_current_user() -> str:
    """Get current username"""
    return os.getenv('USER', 'unknown')


def is_root() -> bool:
    """Check if running as root"""
    return os.geteuid() == 0


def get_sudo_version() -> Optional[str]:
    """Get sudo version if available"""
    output = run_command("sudo -V 2>/dev/null | head -1")
    if output:
        return output
    return None


def get_shell() -> str:
    """Get current shell"""
    return os.getenv('SHELL', '/bin/sh')


def check_file_writable(file_path: str) -> bool:
    """Check if file is writable by current user"""
    return os.access(file_path, os.W_OK)


def check_file_readable(file_path: str) -> bool:
    """Check if file is readable by current user"""
    return os.access(file_path, os.R_OK)


def get_file_permissions(file_path: str) -> Optional[str]:
    """Get file permissions in octal format"""
    try:
        stat_info = os.stat(file_path)
        return oct(stat_info.st_mode)[-4:]
    except Exception:
        return None
