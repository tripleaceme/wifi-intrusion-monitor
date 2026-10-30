"""One copy only: a second copy would find the decoy ports taken and fight over alerts."""

from __future__ import annotations

import sys
from pathlib import Path


def acquire(lock_path: Path):
    """Returns an open lock handle to keep for the life of the app, or None if another copy runs."""
    handle = open(lock_path, "a+")
    try:
        if sys.platform == "win32":
            import msvcrt
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        return None
    return handle
