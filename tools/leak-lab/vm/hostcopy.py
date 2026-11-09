#!/usr/bin/env python3
"""Root-side copy, manifest and ELF-dependency checks for the vprlab host plan.

This module is used two ways:

* imported by ``hostsetup.py`` (and its tests), and
* embedded verbatim in the generated root shell script, which calls it as
  ``python3 - <verb> ...`` after a heredoc.

It never executes another program.  Copying opens every source leaf with
``O_NOFOLLOW``, requires a regular file, hashes the exact bytes it writes and
re-hashes the completed destination file before it is published.  Symbolic
links are never followed: they must be relative and their full ``realpath``
chain must stay inside the copied tree (a chain that only resolves inside
lexically is still refused).  Links are recreated as links and recorded with
their targets in a separate link manifest.  A hardlinked source is copied as
independent content: the destination has no hardlink relationship to the
source or to another destination file.  ``verify_tree`` also reports any
destination entry that neither manifest lists.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import struct
import sys
from typing import Any, Iterable

SCHEMA = 1
CHUNK = 1024 * 1024
TEMP_PREFIX = ".vprlab-copy-"

#: The three staged tools whose direct shared-library dependencies are checked.
STAGED_TOOLS = (
    "usr/bin/qemu-system-x86_64",
    "usr/bin/qemu-img",
    "usr/bin/genisoimage",
)
STAGED_LIBRARY_DIR = "usr/lib/x86_64-linux-gnu"
#: Base libraries every Debian host provides through the trusted dynamic
#: loader.  Anything else must exist inside the copied library directory.
HOST_BASE_LIBRARIES = frozenset(
    {
        "ld-linux-x86-64.so.2",
        "libc.so.6",
        "libdl.so.2",
        "libm.so.6",
        "libpthread.so.0",
        "libresolv.so.2",
        "librt.so.1",
    }
)


class HostcopyError(RuntimeError):
    """A source tree, link target or manifest cannot be trusted."""


class ElfError(ValueError):
    """The supplied bytes are not a parseable ELF dynamic object."""


# ---------------------------------------------------------------------------
# Minimal ELF reader


def elf_needed_sonames(data: bytes) -> list[str]:
    """Return the ``DT_NEEDED`` strings of a 32/64-bit ELF image.

    Only the program headers and the ``PT_DYNAMIC`` segment are read; section
    headers, ``readelf`` and the target architecture are not required.
    """
    if not isinstance(data, (bytes, bytearray)) or len(data) < 16:
        raise ElfError("not an ELF image")
    data = bytes(data)
    if data[:4] != b"\x7fELF":
        raise ElfError("not an ELF image")
    elf_class = data[4]
    encoding = data[5]
    if elf_class not in (1, 2) or encoding not in (1, 2):
        raise ElfError("unsupported ELF class or byte order")
    endian = "<" if encoding == 1 else ">"
    is64 = elf_class == 2
    try:
        if is64:
            phoff = struct.unpack_from(endian + "Q", data, 32)[0]
            phentsize = struct.unpack_from(endian + "H", data, 54)[0]
            phnum = struct.unpack_from(endian + "H", data, 56)[0]
            minimum = 56
        else:
            phoff = struct.unpack_from(endian + "I", data, 28)[0]
            phentsize = struct.unpack_from(endian + "H", data, 42)[0]
            phnum = struct.unpack_from(endian + "H", data, 44)[0]
            minimum = 32
    except struct.error as exc:
        raise ElfError("truncated ELF header") from exc
    if phentsize < minimum or phnum == 0 or phnum > 4096:
        raise ElfError("invalid ELF program header table")
    if phoff + phentsize * phnum > len(data):
        raise ElfError("truncated ELF program headers")
    dynamic: tuple[int, int] | None = None
    for index in range(phnum):
        offset = phoff + index * phentsize
        try:
            if is64:
                p_type = struct.unpack_from(endian + "I", data, offset)[0]
                p_offset = struct.unpack_from(endian + "Q", data, offset + 8)[0]
                p_filesz = struct.unpack_from(endian + "Q", data, offset + 32)[0]
            else:
                p_type = struct.unpack_from(endian + "I", data, offset)[0]
                p_offset = struct.unpack_from(endian + "I", data, offset + 4)[0]
                p_filesz = struct.unpack_from(endian + "I", data, offset + 16)[0]
        except struct.error as exc:
            raise ElfError("truncated ELF program header") from exc
        if p_type == 2:  # PT_DYNAMIC
            if dynamic is not None:
                raise ElfError("multiple PT_DYNAMIC segments")
            dynamic = (p_offset, p_filesz)
    if dynamic is None:
        return []
    offset, size = dynamic
    if offset + size > len(data):
        raise ElfError("truncated PT_DYNAMIC segment")
    entry_size = 16 if is64 else 8
    if size % entry_size:
        raise ElfError("malformed PT_DYNAMIC segment")
    fmt = endian + ("qQ" if is64 else "iI")
    entries: list[tuple[int, int]] = []
    for index in range(size // entry_size):
        try:
            tag, value = struct.unpack_from(fmt, data, offset + index * entry_size)
        except struct.error as exc:
            raise ElfError("truncated dynamic entry") from exc
        if tag == 0:  # DT_NULL
            break
        entries.append((tag, value))
    else:
        raise ElfError("PT_DYNAMIC has no DT_NULL terminator")
    strtab = next((value for tag, value in entries if tag == 5), None)
    if strtab is None:
        if any(tag == 1 for tag, _value in entries):
            raise ElfError("DT_NEEDED without DT_STRTAB")
        return []
    if strtab >= len(data):
        raise ElfError("DT_STRTAB is outside the image")
    needed: list[str] = []
    for tag, value in entries:
        if tag != 1:  # DT_NEEDED
            continue
        start = strtab + value
        if start >= len(data):
            raise ElfError("DT_NEEDED offset is outside the string table")
        end = data.find(b"\x00", start)
        if end < 0:
            raise ElfError("unterminated DT_NEEDED string")
        try:
            name = data[start:end].decode("ascii")
        except UnicodeDecodeError as exc:
            raise ElfError("non-ASCII DT_NEEDED string") from exc
        if not name:
            raise ElfError("empty DT_NEEDED string")
        needed.append(name)
    return needed


# ---------------------------------------------------------------------------
# Staged tool dependency check


def _read_regular_nofollow(path: str | os.PathLike[str]) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise HostcopyError(f"cannot open {path}: {exc.__class__.__name__}") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise HostcopyError(f"{path} is not a regular file")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, CHUNK)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _staged_library_present(library_dir: str | os.PathLike[str], soname: str) -> bool:
    if not soname or "/" in soname or soname in (".", ".."):
        return False
    library_dir = os.path.abspath(os.fspath(library_dir))
    candidate = os.path.join(library_dir, soname)
    if not os.path.lexists(candidate):
        return False
    resolved = os.path.realpath(candidate)
    if resolved != library_dir and not resolved.startswith(library_dir + os.sep):
        return False
    try:
        info = os.stat(resolved)
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode)


def check_staged_tools(root: str | os.PathLike[str]) -> list[str]:
    """Return every unresolved direct ``DT_NEEDED`` of the staged tools."""
    root = os.fspath(root)
    library_dir = os.path.join(root, STAGED_LIBRARY_DIR)
    problems: list[str] = []
    for relative in STAGED_TOOLS:
        path = os.path.join(root, relative)
        try:
            data = _read_regular_nofollow(path)
        except HostcopyError as exc:
            problems.append(str(exc))
            continue
        try:
            needed = elf_needed_sonames(data)
        except ElfError as exc:
            problems.append(f"{relative} is not a usable ELF image: {exc}")
            continue
        for soname in needed:
            if _staged_library_present(library_dir, soname):
                continue
            if soname in HOST_BASE_LIBRARIES:
                continue
            problems.append(
                f"{relative} needs {soname}, which is neither in the copied "
                "library directory nor a host-provided base library"
            )
    return problems


# ---------------------------------------------------------------------------
# Tree copy and manifests


def _relative_parts(relative: str) -> tuple[str, ...]:
    if not isinstance(relative, str) or not relative:
        raise HostcopyError("empty relative path")
    if "\\" in relative or "\x00" in relative:
        raise HostcopyError(f"invalid relative path {relative!r}")
    parts = tuple(relative.split("/"))
    if any(part in ("", ".", "..") for part in parts):
        raise HostcopyError(f"untrusted relative path {relative!r}")
    return parts


def _resolve_link(relative: str, target: str) -> str:
    """Return the normalized in-tree path a relative link must resolve to."""
    if not target or "\x00" in target or "\\" in target:
        raise HostcopyError(f"invalid link target for {relative}")
    if os.path.isabs(target):
        raise HostcopyError(f"{relative} is an absolute symlink")
    parts = list(relative.split("/")[:-1])
    for part in target.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if not parts:
                raise HostcopyError(f"{relative} escapes the copied tree")
            parts.pop()
        else:
            parts.append(part)
    if not parts:
        raise HostcopyError(f"{relative} escapes the copied tree")
    return "/".join(parts)


def _verify_link_confinement(root: str, links: dict[str, str]) -> None:
    """Resolve every link's full chain and refuse one that leaves ``root``.

    The lexical :func:`_resolve_link` check cannot see a chain such as
    ``a/b/s -> ../../top`` plus ``a/b/k -> s/../..`` which resolves outside
    the tree.  ``realpath`` follows the chain, so it closes that gap.
    """
    root_real = os.path.realpath(root)
    for relative in sorted(links):
        path = os.path.join(root, *relative.split("/"))
        resolved = os.path.realpath(path)
        if resolved != root_real and not resolved.startswith(root_real + os.sep):
            raise HostcopyError(
                f"{relative} resolves outside the copied tree ({resolved})"
            )


def _collect(
    source: str,
    only: Iterable[str] | None = None,
) -> tuple[dict[str, os.stat_result], dict[str, str], set[str]]:
    """Return ``(regular files, symlinks, directories)`` from a source tree.

    Every regular file is recorded with its ``lstat`` identity so the copy can
    refuse a file that was swapped after this listing.  Symlink targets are
    recorded for the same reason.
    """
    files: dict[str, os.stat_result] = {}
    links: dict[str, str] = {}
    directories: set[str] = set()

    def add_directory(relative: str) -> None:
        parts = _relative_parts(relative)
        for index in range(1, len(parts) + 1):
            directories.add("/".join(parts[:index]))

    def walk(relative: str) -> None:
        directory = os.path.join(source, relative) if relative else source
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            raise HostcopyError(
                f"cannot list {directory}: {exc.__class__.__name__}"
            ) from exc
        for entry in entries:
            child = f"{relative}/{entry.name}" if relative else entry.name
            _relative_parts(child)
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise HostcopyError(
                    f"cannot inspect {child}: {exc.__class__.__name__}"
                ) from exc
            if stat.S_ISLNK(info.st_mode):
                try:
                    target = os.readlink(os.path.join(source, child))
                except OSError as exc:
                    raise HostcopyError(
                        f"cannot read link {child}: {exc.__class__.__name__}"
                    ) from exc
                _resolve_link(child, target)
                links[child] = target
            elif stat.S_ISDIR(info.st_mode):
                add_directory(child)
                walk(child)
            elif stat.S_ISREG(info.st_mode):
                files[child] = info
            else:
                raise HostcopyError(f"{child} is not a regular file, directory or link")

    if only is not None:
        for relative in only:
            _relative_parts(relative)
            path = os.path.join(source, relative)
            try:
                info = os.lstat(path)
            except OSError as exc:
                raise HostcopyError(
                    f"cannot inspect {relative}: {exc.__class__.__name__}"
                ) from exc
            if stat.S_ISLNK(info.st_mode):
                target = os.readlink(path)
                _resolve_link(relative, target)
                links[relative] = target
            elif stat.S_ISREG(info.st_mode):
                files[relative] = info
            else:
                raise HostcopyError(f"{relative} is not a regular file or link")
            if "/" in relative:
                add_directory(relative.rsplit("/", 1)[0])
    else:
        walk("")
    return files, links, directories


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise HostcopyError("short write while copying")
        view = view[written:]


def _hash_file(path: str, algorithm: str = "sha256") -> str:
    digest = hashlib.new(algorithm)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise HostcopyError(f"{path} is not a regular file")
        while True:
            chunk = os.read(descriptor, CHUNK)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _copy_regular(
    source_path: str,
    destination_path: str,
    expected: os.stat_result,
    *,
    file_mode: int | None,
    sequence: int,
    algorithm: str,
) -> str:
    source_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        source_fd = os.open(source_path, source_flags)
    except OSError as exc:
        raise HostcopyError(
            f"cannot open {source_path} without following links: "
            f"{exc.__class__.__name__}"
        ) from exc
    try:
        info = os.fstat(source_fd)
        if not stat.S_ISREG(info.st_mode):
            raise HostcopyError(f"{source_path} is no longer a regular file")
        if (info.st_dev, info.st_ino) != (expected.st_dev, expected.st_ino):
            raise HostcopyError(f"{source_path} changed while it was being copied")
        mode = (
            file_mode
            if file_mode is not None
            else stat.S_IMODE(info.st_mode) & 0o755
        )
        temporary = os.path.join(
            os.path.dirname(destination_path),
            f"{TEMP_PREFIX}{os.getpid()}-{sequence}",
        )
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
        )
        destination_fd = os.open(temporary, flags, mode or 0o600)
        digest = hashlib.new(algorithm)
        try:
            while True:
                chunk = os.read(source_fd, CHUNK)
                if not chunk:
                    break
                digest.update(chunk)
                _write_all(destination_fd, chunk)
            os.fchmod(destination_fd, mode or 0o600)
            os.fsync(destination_fd)
        finally:
            os.close(destination_fd)
        expected_digest = digest.hexdigest()
        if _hash_file(temporary, algorithm) != expected_digest:
            os.unlink(temporary)
            raise HostcopyError(f"copy of {source_path} did not verify")
        os.replace(temporary, destination_path)
        return expected_digest
    finally:
        os.close(source_fd)


def _copy_link(source_path: str, destination_path: str, target: str) -> None:
    try:
        current = os.readlink(source_path)
    except OSError as exc:
        raise HostcopyError(
            f"cannot re-read link {source_path}: {exc.__class__.__name__}"
        ) from exc
    if current != target:
        raise HostcopyError(f"{source_path} changed while it was being copied")
    try:
        if os.path.islink(destination_path) or os.path.lexists(destination_path):
            os.unlink(destination_path)
    except IsADirectoryError as exc:
        raise HostcopyError(f"{destination_path} is a directory") from exc
    os.symlink(target, destination_path)


def _write_manifests(
    manifest: str,
    links_manifest: str,
    digests: dict[str, str],
    links: dict[str, str],
) -> None:
    manifest_text = "".join(
        f"{digest}  {relative}\n" for relative, digest in sorted(digests.items())
    )
    with open(manifest, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(manifest_text)
    link_document = {"schema": SCHEMA, "links": dict(sorted(links.items()))}
    with open(links_manifest, "w", encoding="utf-8", newline="\n") as stream:
        json.dump(link_document, stream, indent=2, sort_keys=True)
        stream.write("\n")


def _remove_manifest_leftovers(destination: str, manifest: str, links: str) -> None:
    """Keep manifests out of the copied tree's own content listing."""
    for path in (manifest, links):
        try:
            if os.path.isdir(path) and not os.path.islink(path):
                raise HostcopyError(f"{path} is a directory")
        except OSError:
            pass
    os.makedirs(os.path.dirname(manifest), mode=0o755, exist_ok=True)
    os.makedirs(os.path.dirname(links), mode=0o755, exist_ok=True)
    del destination


def copy_tree(
    source: str | os.PathLike[str],
    destination: str | os.PathLike[str],
    manifest: str | os.PathLike[str],
    links_manifest: str | os.PathLike[str],
    *,
    file_mode: int | None = None,
    only: Iterable[str] | None = None,
    algorithm: str = "sha256",
) -> dict[str, Any]:
    """Copy a complete tree (regular files and confined relative symlinks)."""
    source = os.path.abspath(os.fspath(source))
    destination = os.path.abspath(os.fspath(destination))
    manifest = os.path.abspath(os.fspath(manifest))
    links_manifest = os.path.abspath(os.fspath(links_manifest))
    if not os.path.isdir(source) or os.path.islink(source):
        raise HostcopyError(f"source {source} is not a real directory")
    if algorithm not in {"sha256", "sha512"}:
        raise HostcopyError(f"unsupported manifest digest {algorithm!r}")
    files, links, directories = _collect(
        source, None if only is None else list(only)
    )
    _verify_link_confinement(source, links)
    os.makedirs(destination, mode=0o755, exist_ok=True)
    if os.path.islink(destination):
        raise HostcopyError(f"destination {destination} is a symlink")
    for relative in sorted(directories):
        path = os.path.join(destination, *relative.split("/"))
        try:
            existing = os.lstat(path)
        except FileNotFoundError:
            os.mkdir(path, 0o755)
            continue
        if stat.S_ISLNK(existing.st_mode) or not stat.S_ISDIR(existing.st_mode):
            raise HostcopyError(f"{path} is not a real directory")
    digests: dict[str, str] = {}
    for sequence, relative in enumerate(sorted(files)):
        source_path = os.path.join(source, *relative.split("/"))
        destination_path = os.path.join(destination, *relative.split("/"))
        os.makedirs(os.path.dirname(destination_path), mode=0o755, exist_ok=True)
        digests[relative] = _copy_regular(
            source_path,
            destination_path,
            files[relative],
            file_mode=file_mode,
            sequence=sequence,
            algorithm=algorithm,
        )
    for relative in sorted(links):
        target = links[relative]
        _resolve_link(relative, target)
        destination_path = os.path.join(destination, *relative.split("/"))
        os.makedirs(os.path.dirname(destination_path), mode=0o755, exist_ok=True)
        _copy_link(
            os.path.join(source, *relative.split("/")), destination_path, target
        )
    # The links now exist in the destination; verify their full chains there
    # too, so a link whose target is another planted link cannot escape.
    _verify_link_confinement(destination, links)
    _remove_manifest_leftovers(destination, manifest, links_manifest)
    _write_manifests(manifest, links_manifest, digests, links)
    return {"files": sorted(digests), "links": dict(sorted(links.items()))}


def _read_manifest(path: str, algorithm: str = "sha256") -> dict[str, str]:
    digests: dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8") as stream:
            lines = stream.read().splitlines()
    except OSError as exc:
        raise HostcopyError(
            f"cannot read {path}: {exc.__class__.__name__}"
        ) from exc
    for line in lines:
        if not line:
            continue
        expected_length = 128 if algorithm == "sha512" else 64
        digest, separator, relative = line.partition("  ")
        if not separator or len(digest) != expected_length:
            raise HostcopyError(f"malformed manifest line in {path}")
        try:
            int(digest, 16)
        except ValueError as exc:
            raise HostcopyError(f"malformed manifest digest in {path}") from exc
        _relative_parts(relative)
        if relative in digests:
            raise HostcopyError(f"duplicate manifest entry {relative}")
        digests[relative] = digest.lower()
    return digests


def _read_links(path: str) -> dict[str, str]:
    try:
        with open(path, "r", encoding="utf-8") as stream:
            document = json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise HostcopyError(
            f"cannot read {path}: {exc.__class__.__name__}"
        ) from exc
    if (
        not isinstance(document, dict)
        or document.get("schema") != SCHEMA
        or not isinstance(document.get("links"), dict)
    ):
        raise HostcopyError(f"{path} is not a link manifest")
    links: dict[str, str] = {}
    for relative, target in document["links"].items():
        _relative_parts(relative)
        if not isinstance(target, str):
            raise HostcopyError(f"link target for {relative} is not a string")
        _resolve_link(relative, target)
        links[relative] = target
    return links


def _hash_at(directory: str, relative: str, algorithm: str = "sha256") -> str:
    return _hash_file(
        os.path.join(directory, *relative.split("/")), algorithm
    )


def verify_tree(
    directory: str | os.PathLike[str],
    manifest: str | os.PathLike[str],
    links_manifest: str | os.PathLike[str],
    *,
    algorithm: str = "sha256",
) -> list[str]:
    """Return every file-hash or link-target problem in a copied tree."""
    directory = os.fspath(directory)
    problems: list[str] = []
    if algorithm not in {"sha256", "sha512"}:
        return [f"unsupported manifest digest {algorithm!r}"]
    try:
        digests = _read_manifest(os.fspath(manifest), algorithm)
        links = _read_links(os.fspath(links_manifest))
    except HostcopyError as exc:
        return [str(exc)]
    overlap = set(digests) & set(links)
    for relative in sorted(overlap):
        problems.append(f"{relative} is listed as both a file and a link")
    for relative, digest in sorted(digests.items()):
        path = os.path.join(directory, *relative.split("/"))
        try:
            info = os.lstat(path)
        except OSError:
            problems.append(f"{relative} is missing")
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            problems.append(f"{relative} is not a regular file")
            continue
        try:
            if _hash_at(directory, relative, algorithm) != digest:
                problems.append(f"{relative} hash mismatch")
        except HostcopyError as exc:
            problems.append(str(exc))
    for relative, target in sorted(links.items()):
        path = os.path.join(directory, *relative.split("/"))
        try:
            info = os.lstat(path)
        except OSError:
            problems.append(f"{relative} link is missing")
            continue
        if not stat.S_ISLNK(info.st_mode):
            problems.append(f"{relative} is not a symbolic link")
            continue
        try:
            actual = os.readlink(path)
        except OSError as exc:
            problems.append(f"{relative} link cannot be read: {exc.__class__.__name__}")
            continue
        if actual != target:
            problems.append(
                f"{relative} link target is {actual!r}, expected {target!r}"
            )
        try:
            _resolve_link(relative, actual)
        except HostcopyError as exc:
            problems.append(str(exc))
    try:
        _verify_link_confinement(directory, links)
    except HostcopyError as exc:
        problems.append(str(exc))
    # A destination entry that neither manifest lists was not produced by
    # this copy.  It may be stale from an earlier run or a planted file; a
    # root-owned tree must not silently publish it.
    manifest_path = os.path.abspath(os.fspath(manifest))
    links_path = os.path.abspath(os.fspath(links_manifest))
    known = set(digests) | set(links)
    known_directories: set[str] = set()
    for relative in known:
        parts = relative.split("/")
        for index in range(1, len(parts)):
            known_directories.add("/".join(parts[:index]))
    for current, directories, entries in os.walk(directory, followlinks=False):
        symlinked_directories = [
            name for name in directories if os.path.islink(os.path.join(current, name))
        ]
        for name in entries + symlinked_directories:
            path = os.path.join(current, name)
            relative = os.path.relpath(path, directory).replace(os.sep, "/")
            if os.path.abspath(path) in (manifest_path, links_path):
                continue
            if relative in known or relative in known_directories:
                continue
            problems.append(f"{relative} is an extra destination entry")
    return problems


# ---------------------------------------------------------------------------
# Command-line driver (also used from the generated shell)


def _usage() -> int:
    sys.stderr.write(
        "usage: hostcopy.py copy-tree SOURCE DEST MANIFEST LINKS "
        "[--file-mode=OCTAL] [--algorithm=sha256|sha512] | "
        "copy-named SOURCE DEST MANIFEST LINKS NAME... | "
        "verify DIRECTORY MANIFEST LINKS [--algorithm=...] | "
        "elfcheck TOOLS_ROOT\n"
    )
    return 2


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments:
        return _usage()
    verb = arguments[0]
    try:
        if verb == "copy-tree":
            if len(arguments) < 5:
                return _usage()
            source, destination, manifest, links = arguments[1:5]
            file_mode = None
            algorithm = "sha256"
            for option in arguments[5:]:
                if option.startswith("--file-mode="):
                    file_mode = int(option.split("=", 1)[1], 8)
                    if not 0 <= file_mode <= 0o777:
                        raise HostcopyError("file mode is out of range")
                elif option.startswith("--algorithm="):
                    algorithm = option.split("=", 1)[1]
                else:
                    return _usage()
            copy_tree(
                source,
                destination,
                manifest,
                links,
                file_mode=file_mode,
                algorithm=algorithm,
            )
        elif verb == "copy-named":
            if len(arguments) < 6:
                return _usage()
            source, destination, manifest, links = arguments[1:5]
            copy_tree(
                source,
                destination,
                manifest,
                links,
                only=arguments[5:],
            )
        elif verb == "verify":
            if len(arguments) not in (4, 5):
                return _usage()
            algorithm = "sha256"
            if len(arguments) == 5:
                if not arguments[4].startswith("--algorithm="):
                    return _usage()
                algorithm = arguments[4].split("=", 1)[1]
            problems = verify_tree(
                arguments[1], arguments[2], arguments[3], algorithm=algorithm
            )
            for problem in problems:
                sys.stderr.write(f"vprlab: {problem}\n")
            return 1 if problems else 0
        elif verb == "elfcheck":
            if len(arguments) != 2:
                return _usage()
            problems = check_staged_tools(arguments[1])
            for problem in problems:
                sys.stderr.write(f"vprlab: {problem}\n")
            return 1 if problems else 0
        else:
            return _usage()
    except (HostcopyError, OSError, ValueError) as exc:
        sys.stderr.write(f"vprlab: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
