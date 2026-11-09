#!/usr/bin/env python3
"""Global admission lock shared by the two vprlab VM runners.

The lock is a single root-owned file (default ``/run/vprlab/run.lock``, mode
0600).  ``provision.py`` and ``run_phase.py`` hold it for the complete guest
lifecycle; ``login_url.py`` refuses to touch the guest agent while a phase
holds it.  ``flock(2)`` makes the check atomic, so two controllers cannot both
observe "no QEMU running" and then start a guest.

This module only wraps ``open``/``flock``; it never starts a process or touches
the network.
"""

from __future__ import annotations

import errno
import fcntl
import os
import pathlib

RUN_DIR = pathlib.Path("/run/vprlab")
RUN_LOCK = RUN_DIR / "run.lock"
OWNER_FILE = RUN_DIR / "owner.json"
LOCK_MODE = 0o600


class LockError(RuntimeError):
    """The lock file could not be opened or is owned by the wrong user."""


class LockBusy(LockError):
    """Another leak-lab run currently holds the global lock."""


def _open_lock(path: str | pathlib.Path) -> int:
    path = pathlib.Path(path)
    if os.geteuid() == 0:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, LOCK_MODE)
    except OSError as exc:
        raise LockError(
            f"cannot open the run lock {path}: {exc.__class__.__name__}"
        ) from exc
    try:
        os.fchmod(descriptor, LOCK_MODE)
        info = os.fstat(descriptor)
        if os.geteuid() == 0 and info.st_uid != 0:
            raise LockError(f"run lock {path} must be owned by root")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def acquire(path: str | pathlib.Path = RUN_LOCK) -> int:
    """Take the exclusive lock without blocking; return its descriptor."""
    descriptor = _open_lock(path)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        os.close(descriptor)
        if exc.errno in (errno.EACCES, errno.EAGAIN):
            raise LockBusy(
                "another leak-lab run holds the global phase lock"
            ) from exc
        raise LockError(
            f"cannot lock the run lock: {exc.__class__.__name__}"
        ) from exc
    return descriptor


def release(descriptor: int | None) -> None:
    if descriptor is None:
        return
    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    except OSError:
        pass
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def ensure_unlocked(path: str | pathlib.Path = RUN_LOCK) -> None:
    """Refuse when a runner holds the lock, then release a probe lock."""
    descriptor = acquire(path)
    release(descriptor)
