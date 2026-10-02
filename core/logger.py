"""
Logging utilities for PrivWatch
Colored logging and progress tracking
"""

from datetime import datetime
from typing import Optional
import sys


class Logger:
    """Colored logger for terminal output"""

    # Color codes
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

    @staticmethod
    def _timestamp() -> str:
        """Get formatted timestamp"""
        return datetime.now().strftime('%H:%M:%S')

    @staticmethod
    def info(message: str):
        """Log info message"""
        prefix = f"{Logger.BLUE}[*]{Logger.RESET}"
        print(f"{prefix} [{Logger._timestamp()}] {message}")

    @staticmethod
    def success(message: str):
        """Log success message"""
        prefix = f"{Logger.GREEN}[✓]{Logger.RESET}"
        print(f"{prefix} [{Logger._timestamp()}] {message}")

    @staticmethod
    def warning(message: str):
        """Log warning message"""
        prefix = f"{Logger.YELLOW}[!]{Logger.RESET}"
        print(f"{prefix} [{Logger._timestamp()}] {message}")

    @staticmethod
    def error(message: str):
        """Log error message"""
        prefix = f"{Logger.RED}[✗]{Logger.RESET}"
        print(f"{prefix} [{Logger._timestamp()}] {message}")

    @staticmethod
    def critical(message: str):
        """Log critical finding"""
        prefix = f"{Logger.RED}[!!]{Logger.RESET}"
        print(f"{prefix} [{Logger._timestamp()}] {message}")

    @staticmethod
    def header(message: str):
        """Print section header"""
        print(f"\n{Logger.CYAN}{Logger.BOLD}{'='*60}")
        print(f"{message}")
        print(f"{'='*60}{Logger.RESET}\n")

    @staticmethod
    def banner(mode: str, version: str = "1.0"):
        """Display tool banner"""
        banner_text = f"""
{Logger.CYAN}╔═══════════════════════════════════════════════════════════╗
║                  PrivWatch v{version}                       ║
║        Privilege Escalation Detection & Forensics         ║
║                  Mode: {mode.upper():^30s}                ║
╚═══════════════════════════════════════════════════════════╝{Logger.RESET}
"""
        print(banner_text)
