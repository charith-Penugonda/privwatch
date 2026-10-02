"""
PrivWatch Configuration Settings
Global constants and configuration parameters
"""

# Severity Levels
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"

# Vector Names
VECTOR_SUID = "SUID/SGID"
VECTOR_SUDO = "SUDO"
VECTOR_PASSWD = "PASSWD/SHADOW"
VECTOR_CRON = "CRON"
VECTOR_KERNEL = "KERNEL"
VECTOR_CAPABILITIES = "CAPABILITIES"

# System Paths
LOG_AUTH = "/var/log/auth.log"
LOG_SYSLOG = "/var/log/syslog"
LOG_SECURE = "/var/log/secure"
FILE_PASSWD = "/etc/passwd"
FILE_SHADOW = "/etc/shadow"
FILE_SUDOERS = "/etc/sudoers"
FILE_SUDOERS_D = "/etc/sudoers.d/"

# Cron Paths
CRON_DIRS = [
    "/etc/cron.d/",
    "/etc/cron.daily/",
    "/etc/cron.hourly/",
    "/etc/cron.weekly/",
    "/etc/cron.monthly/",
    "/var/spool/cron/crontabs/"
]

# Known dangerous SUID binaries (GTFOBins)
DANGEROUS_SUID = [
    'nmap', 'vim', 'nano', 'find', 'bash', 'sh', 'dash',
    'more', 'less', 'python', 'python2', 'python3', 'perl',
    'ruby', 'cp', 'mv', 'awk', 'sed', 'ed', 'env', 'nice',
    'ionice', 'look', 'logsave', 'lua', 'node', 'expect',
    'rpm', 'gdb', 'ftp', 'ssh', 'nc', 'netcat', 'wget',
    'curl', 'gcc', 'ld', 'as', 'ar', 'make', 'tar', 'zip',
    'gzip', 'bzip2', 'xxd', 'base64', 'base32'
]

# Known dangerous sudo commands
DANGEROUS_SUDO = [
    'ALL', 'vim', 'nano', 'emacs', 'vi', 'find', 'python',
    'perl', 'ruby', 'bash', 'sh', 'dash', 'zsh', 'awk',
    'sed', 'less', 'more', 'man', 'git', 'docker', 'mount',
    'systemctl', 'journalctl', 'apt', 'yum', 'dnf', 'rpm',
    'pip', 'easy_install', 'gem', 'cpan', 'npm', 'nmap',
    'tcpdump', 'wireshark', 'gdb', 'strace', 'ltrace'
]

# Capabilities that can lead to privilege escalation
DANGEROUS_CAPABILITIES = [
    'cap_setuid', 'cap_setgid', 'cap_dac_override',
    'cap_dac_read_search', 'cap_sys_admin', 'cap_sys_ptrace',
    'cap_sys_module', 'cap_chown', 'cap_fowner'
]

# Scanning Timeouts
COMMAND_TIMEOUT = 30  # seconds
SUID_SCAN_TIMEOUT = 60  # seconds for filesystem scans

# Report Settings
REPORT_FORMAT_JSON = "json"
REPORT_FORMAT_PDF = "pdf"
REPORT_FORMAT_HTML = "html"

# Timeline Settings
TIMELINE_MAX_EVENTS = 10000
TIMELINE_TIME_WINDOW = 86400  # 24 hours in seconds

# Color Codes for Terminal
COLOR_RED = '\033[91m'
COLOR_GREEN = '\033[92m'
COLOR_YELLOW = '\033[93m'
COLOR_BLUE = '\033[94m'
COLOR_MAGENTA = '\033[95m'
COLOR_CYAN = '\033[96m'
COLOR_BOLD = '\033[1m'
COLOR_RESET = '\033[0m'
