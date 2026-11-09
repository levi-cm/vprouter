#!/usr/bin/env python3
"""Descriptor-anchored root path handling for the vprlab VM runners.

The runner writes evidence as root underneath a directory that must be
trusted all the way to ``/``.  Checking only the final component is not
enough: an ancestor owned by the operator can rename or replace the whole
subtree after the check.  Every directory used here is therefore opened one
component at a time with ``O_NOFOLLOW`` from an anchor (``/`` in production)
and every later file operation uses ``dir_fd``-relative opens.

Nothing in this module starts a process.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import stat
from typing import Any, Iterable

_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIR_FLAGS = os.O_RDONLY | _DIRECTORY | _NOFOLLOW


class PathError(RuntimeError):
    """A path is not a trustworthy root-owned directory tree."""


def _component_name(name: str) -> str:
    if (
        not isinstance(name, str)
        or not name
        or name in (".", "..")
        or "/" in name
        or "\x00" in name
    ):
        raise PathError(f"invalid path component {name!r}")
    return name


def _check_directory(info: os.stat_result, path: str, expected_uid: int) -> None:
    if not stat.S_ISDIR(info.st_mode):
        raise PathError(f"{path} is not a directory")
    if expected_uid != 0:
        # Offline tests run as the operator; the security contract is enforced
        # by the production root caller.  Symlinks are still refused by every
        # O_NOFOLLOW open below.
        return
    if info.st_uid != expected_uid:
        raise PathError(f"{path} is not owned by uid {expected_uid}")
    if info.st_mode & 0o022:
        raise PathError(f"{path} is group/other writable")


def _path_below(path: pathlib.Path, anchor: pathlib.Path) -> list[str]:
    """Return the components of ``path`` below ``anchor`` (anchor excluded)."""
    try:
        relative = path.relative_to(anchor)
    except ValueError as exc:
        raise PathError(f"{path} is not below the anchor {anchor}") from exc
    if relative == pathlib.Path("."):
        return []
    parts = list(relative.parts)
    if any(part in ("", ".", "..") for part in parts):
        raise PathError(f"path {path} contains an unsafe component")
    return parts


def _anchor_and_path(
    path: str | os.PathLike[str], anchor: str | os.PathLike[str] | None
) -> tuple[pathlib.Path, pathlib.Path]:
    target = pathlib.Path(os.path.abspath(os.fspath(path)))
    if anchor is None:
        return pathlib.Path("/"), target
    base = pathlib.Path(os.path.abspath(os.fspath(anchor)))
    return base, target


def validate_ancestry(
    path: str | os.PathLike[str],
    *,
    expected_uid: int | None = None,
    anchor: str | os.PathLike[str] | None = None,
) -> None:
    """Validate ``path`` and every component between ``anchor`` and it.

    Each component must exist, be a directory, be owned by ``expected_uid``
    (root in production) and must not be group/other writable.  Symlinks are
    refused because they are opened component-wise with ``O_NOFOLLOW``.
    """
    if expected_uid is None:
        expected_uid = os.geteuid()
    base, target = _anchor_and_path(path, anchor)
    parts = _path_below(target, base)
    current = base
    try:
        info = base.lstat()
    except OSError as exc:
        raise PathError(f"{base} is unavailable: {exc.__class__.__name__}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise PathError(f"{base} is a symlink")
    if parts:
        _check_directory(info, str(base), expected_uid)
    for part in parts:
        current = current / part
        try:
            info = current.lstat()
        except OSError as exc:
            raise PathError(f"{current} is unavailable: {exc.__class__.__name__}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise PathError(f"{current} is a symlink")
        _check_directory(info, str(current), expected_uid)


def open_directory(
    path: str | os.PathLike[str],
    *,
    create: bool = False,
    mode: int = 0o700,
    expected_uid: int | None = None,
    anchor: str | os.PathLike[str] | None = None,
) -> int:
    """Open ``path`` as a directory fd without following any component.

    Missing components are created only when ``create`` is true.  Intermediate
    directories are created 0755; the final directory uses ``mode``.  Every
    component (including newly created ones) is checked for ownership and
    group/other write permission before it is used.
    """
    if expected_uid is None:
        expected_uid = os.geteuid()
    base, target = _anchor_and_path(path, anchor)
    parts = _path_below(target, base)
    try:
        base_info = base.lstat()
    except OSError as exc:
        raise PathError(f"{base} is unavailable: {exc.__class__.__name__}") from exc
    if stat.S_ISLNK(base_info.st_mode):
        raise PathError(f"{base} is a symlink")
    if parts:
        _check_directory(base_info, str(base), expected_uid)
    opened: list[int] = []
    try:
        descriptor = os.open(base, _DIR_FLAGS)
        opened.append(descriptor)
        for index, part in enumerate(parts):
            final = index == len(parts) - 1
            child_mode = mode if final else 0o755
            try:
                info = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                if not create:
                    raise PathError(f"{target} does not exist") from None
                try:
                    os.mkdir(part, child_mode, dir_fd=descriptor)
                except FileExistsError:
                    pass
                info = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode):
                raise PathError(f"{target} contains a symlink")
            _check_directory(info, str(target), expected_uid)
            child = os.open(part, _DIR_FLAGS, dir_fd=descriptor)
            if final:
                os.fchmod(child, mode)
                info = os.fstat(child)
                _check_directory(info, str(target), expected_uid)
            opened.append(child)
            descriptor = child
        return opened[-1]
    except OSError as exc:
        raise PathError(
            f"cannot open {target} without following links: {exc.__class__.__name__}"
        ) from exc
    finally:
        for held in opened[:-1]:
            try:
                os.close(held)
            except OSError:
                pass


def open_file_at(
    directory_fd: int,
    name: str,
    flags: int,
    mode: int = 0o600,
) -> int:
    """Open ``name`` relative to ``directory_fd`` without following links."""
    _component_name(name)
    return os.open(name, flags | _NOFOLLOW, mode, dir_fd=directory_fd)


def write_bytes_at(
    directory_fd: int,
    name: str,
    data: bytes,
    *,
    mode: int = 0o600,
    exclusive: bool = True,
) -> None:
    flags = os.O_WRONLY | os.O_CREAT
    flags |= os.O_EXCL if exclusive else os.O_TRUNC
    descriptor = open_file_at(directory_fd, name, flags, mode)
    try:
        os.fchmod(descriptor, mode)
        os.write(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_json_at(directory_fd: int, name: str, document: Any, *, mode: int = 0o600) -> None:
    payload = json.dumps(document, indent=2, sort_keys=True) + "\n"
    write_bytes_at(directory_fd, name, payload.encode("utf-8"), mode=mode)


def read_bytes_at(directory_fd: int, name: str) -> bytes:
    descriptor = open_file_at(directory_fd, name, os.O_RDONLY)
    try:
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def hash_file_at(directory_fd: int, name: str, algorithm: str = "sha256") -> str:
    digest = hashlib.new(algorithm)
    descriptor = open_file_at(directory_fd, name, os.O_RDONLY)
    try:
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def file_size_at(directory_fd: int, name: str) -> int:
    descriptor = open_file_at(directory_fd, name, os.O_RDONLY)
    try:
        return os.fstat(descriptor).st_size
    finally:
        os.close(descriptor)


def proc_path(directory_fd: int, name: str) -> str:
    """Return a path that traverses the retained directory fd, not its name."""
    _component_name(name)
    return f"/proc/self/fd/{directory_fd}/{name}"


def make_run_directory(
    root_fd: int,
    name: str,
    *,
    expected_uid: int | None = None,
    mode: int = 0o700,
) -> int:
    """Create and open one evidence run directory below ``root_fd``."""
    if expected_uid is None:
        expected_uid = os.geteuid()
    _component_name(name)
    try:
        os.mkdir(name, mode, dir_fd=root_fd)
    except OSError as exc:
        raise PathError(
            f"cannot create evidence run directory: {exc.__class__.__name__}"
        ) from exc
    try:
        descriptor = os.open(name, _DIR_FLAGS, dir_fd=root_fd)
    except OSError as exc:
        raise PathError(
            f"cannot open evidence run directory: {exc.__class__.__name__}"
        ) from exc
    try:
        os.fchmod(descriptor, mode)
        _check_directory(os.fstat(descriptor), name, expected_uid)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def ancestry_records(path: str | os.PathLike[str]) -> list[dict[str, Any]]:
    """Return lstat-shaped ancestry records for tests and ``--check`` tools."""
    target = pathlib.Path(os.path.abspath(os.fspath(path)))
    records: list[dict[str, Any]] = []
    for component in list(reversed(target.parents)) + [target]:
        try:
            info = component.lstat()
        except OSError:
            records.append(
                {
                    "path": str(component),
                    "exists": False,
                    "is_symlink": False,
                    "uid": None,
                    "mode": None,
                }
            )
            continue
        records.append(
            {
                "path": str(component),
                "exists": True,
                "is_symlink": stat.S_ISLNK(info.st_mode),
                "uid": info.st_uid,
                "mode": stat.S_IMODE(info.st_mode),
            }
        )
    return records


def ancestry_problems(
    records: Iterable[dict[str, Any]], *, expected_uid: int = 0
) -> list[str]:
    """Return every problem with supplied ``lstat``-shaped records."""
    problems: list[str] = []
    for record in records:
        path = record.get("path")
        if not isinstance(path, str) or not path:
            problems.append("ancestry record without a path")
            continue
        if record.get("exists") is not True:
            problems.append(f"{path} is missing")
            continue
        if record.get("is_symlink") is True:
            problems.append(f"{path} is a symlink")
            continue
        if record.get("uid") != expected_uid:
            problems.append(f"{path} is not owned by uid {expected_uid}")
        mode = record.get("mode")
        if not isinstance(mode, int):
            problems.append(f"{path} has no mode")
        elif mode & 0o022:
            problems.append(f"{path} is group/other writable")
    return problems
