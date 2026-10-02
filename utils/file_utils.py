"""
File Utilities for PrivWatch
Permission checking and file analysis helpers
"""

import os
import stat
from pathlib import Path
from typing import List, Tuple


def is_suid(file_path: str) -> bool:
    """Check if file has SUID bit set"""
    try:
        st = os.stat(file_path)
        return bool(st.st_mode & stat.S_ISUID)
    except Exception:
        return False


def is_sgid(file_path: str) -> bool:
    """Check if file has SGID bit set"""
    try:
        st = os.stat(file_path)
        return bool(st.st_mode & stat.S_ISGID)
    except Exception:
        return False


def is_world_writable(file_path: str) -> bool:
    """Check if file is world-writable"""
    try:
        st = os.stat(file_path)
        return bool(st.st_mode & stat.S_IWOTH)
    except Exception:
        return False


def get_file_owner(file_path: str) -> Tuple[int, int]:
    """Get file owner UID and GID"""
    try:
        st = os.stat(file_path)
        return (st.st_uid, st.st_gid)
    except Exception:
        return (-1, -1)


def get_permission_string(file_path: str) -> str:
    """Get human-readable permission string"""
    try:
        st = os.stat(file_path)
        mode = st.st_mode

        perms = []
        # Owner
        perms.append('r' if mode & stat.S_IRUSR else '-')
        perms.append('w' if mode & stat.S_IWUSR else '-')
        perms.append('s' if mode & stat.S_ISUID else ('x' if mode & stat.S_IXUSR else '-'))
        # Group
        perms.append('r' if mode & stat.S_IRGRP else '-')
        perms.append('w' if mode & stat.S_IWGRP else '-')
        perms.append('s' if mode & stat.S_ISGID else ('x' if mode & stat.S_IXGRP else '-'))
        # Others
        perms.append('r' if mode & stat.S_IROTH else '-')
        perms.append('w' if mode & stat.S_IWOTH else '-')
        perms.append('x' if mode & stat.S_IXOTH else '-')

        return ''.join(perms)
    except Exception:
        return "??????????"


def find_writable_files_in_path(path_dir: str) -> List[str]:
    """Find all writable files in a directory"""
    writable = []
    try:
        for item in os.listdir(path_dir):
            full_path = os.path.join(path_dir, item)
            if os.path.isfile(full_path) and os.access(full_path, os.W_OK):
                writable.append(full_path)
    except Exception:
        pass
    return writable


def is_parent_writable(file_path: str) -> bool:
    """Check if parent directory is writable"""
    try:
        parent = str(Path(file_path).parent)
        return os.access(parent, os.W_OK)
    except Exception:
        return False
