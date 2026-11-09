#!/usr/bin/env python3
"""Plan-only generator for the root-owned vprlab host layout.

This program never executes anything (except when the printed script is run by
the operator).  It prints a standalone ``#!/bin/sh`` script that creates:

* the dedicated ``vprlab-qemu`` system account (no login shell, no home,
  member of ``kvm`` only);
* ``/opt/vprlab-tools`` (root:root 0755) with a complete verified copy of the
  staged QEMU tools, their libraries/modules and confined relative symlinks;
* ``/opt/vprlab-tools/leaklab`` with a verified root-owned copy of the leak-lab
  runtime modules used by ``run_phase.py``;
* ``/var/lib/vprlab/images`` (root 0755, files 0644 after verification) with
  the verified base image and ``SHA512SUMS``;
* ``/var/lib/vprlab/evidence`` (root 0700) and ``/run/vprlab`` (root 0700).
  ``/var/lib/vprlab`` itself is root 0755; the plan never creates
  ``vm-NNN``, because ``provision.py`` must create each state directory
  exclusively and then hand it to the QEMU user;
* file and link manifests (``SHA256SUMS``/``SHA512SUMS`` and
  ``SYMLINKS.json``) plus a post-copy verification of every copied file hash
  and every recreated link target.

``--check`` validates a supplied stat/group inventory instead of rendering the
script.  Inventory JSON shapes::

    {"stat": {"/opt": {"type": "dir", "uid": 0, "gid": 0, "mode": "0755"},
              "/opt/vprlab-tools/SHA256SUMS": {"type": "file", ...}},
     "users": {"vprlab-qemu": {"uid": 123, "gid": 123,
                               "shell": "/usr/sbin/nologin",
                               "home_missing": true,
                               "primary_group": "vprlab-qemu",
                               "supplementary": ["kvm"]}}}

``stat`` keys must cover every ancestor of the lab paths; a missing record is
a problem, never an assumption.

Teardown is the generated script's ``teardown`` subcommand.  It takes and
holds the run lock for the whole teardown, refuses while a QEMU process for the
lab account exists (``pgrep`` must be installed), then removes exactly the
lab's own tools/images directories, the VM state directories and the dedicated
account.  ``/var/lib/vprlab/evidence`` is deliberately retained as audit
evidence; remove it only by hand after reviewing it.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shlex
import stat
import sys
from typing import Any

import hostcopy

QEMU_USER = "vprlab-qemu"
QEMU_GROUP = "vprlab-qemu"
KVM_GROUP = "kvm"
FORBIDDEN_GROUPS = frozenset(
    {"sudo", "wheel", "adm", "docker", "lxd", "libvirt", "disk"}
)
NOLOGIN_SHELLS = frozenset(
    {"/usr/sbin/nologin", "/sbin/nologin", "/usr/bin/false", "/bin/false"}
)
TOOLS_SOURCE = "/DATA/vprouter-lab/lab-tools/root"
IMAGES_SOURCE = "/DATA/vprouter-lab/lab-images"
BASE_IMAGE_NAME = "debian-13-genericcloud-amd64-20261021-2638.qcow2"
BASE_IMAGE_SHA512 = (
    "16e0965312c56feb331049d45d2b1b5778f3f942a33d4300eedbb97527707f2bea"
    "87c0006f3e4cc7a25fadbff739c4e235a51fb9bcd1b66fd554f7f8e80ba45c"
)

TOOLS_ROOT = "/opt/vprlab-tools"
LEAKLAB_ROOT = TOOLS_ROOT + "/leaklab"
STATE_ROOT = "/var/lib/vprlab"
IMAGES_ROOT = STATE_ROOT + "/images"
EVIDENCE_ROOT = STATE_ROOT + "/evidence"
RUN_ROOT = "/run/vprlab"

#: Runtime modules installed below ``LEAKLAB_ROOT``.  They are the only files
#: ``run_phase.py`` is allowed to execute as the scanner.
LEAK_LAB_FILES = (
    "control.py",
    "netplan.py",
    "pcapscan.py",
    "policy.py",
    "policy.schema.json",
    "tsnames.py",
    "vm/guest.py",
    "vm/hostcheck.py",
    "vm/hostcopy.py",
    "vm/hostsetup.py",
    "vm/login_url.py",
    "vm/provision.py",
    "vm/qga.py",
    "vm/rootfs.py",
    "vm/runlock.py",
    "vm/run_phase.py",
)

ROOT_DIRECTORIES = (
    "/",
    "/opt",
    TOOLS_ROOT,
    LEAKLAB_ROOT,
    "/var",
    "/var/lib",
    STATE_ROOT,
    IMAGES_ROOT,
    EVIDENCE_ROOT,
    "/run",
    RUN_ROOT,
)


class LayoutError(ValueError):
    """A requested value or supplied inventory cannot describe the layout."""


_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_PATH_COMPONENT_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def _valid_name(value: object, what: str) -> str:
    if not isinstance(value, str) or _NAME_RE.fullmatch(value) is None:
        raise LayoutError(f"{what} must be 1..64 characters of [A-Za-z0-9._-]")
    if value in (".", ".."):
        raise LayoutError(f"{what} must not be . or ..")
    return value


def _valid_path(value: object, what: str) -> str:
    """Accept an absolute path of strict, non-``..`` components only."""
    if (
        not isinstance(value, str)
        or not value
        or "\n" in value
        or "\r" in value
        or not value.startswith("/")
    ):
        raise LayoutError(f"{what} must be an absolute single-line path")
    if value == "/":
        return value
    parts = value.split("/")[1:]
    if any(_PATH_COMPONENT_RE.fullmatch(part) is None for part in parts):
        raise LayoutError(
            f"{what} must contain only [A-Za-z0-9._-] path components"
        )
    if any(part in (".", "..") for part in parts):
        raise LayoutError(f"{what} must not contain . or .. components")
    return value


def _mode_text(mode: Any) -> int | None:
    if isinstance(mode, int) and not isinstance(mode, bool):
        return mode & 0o7777
    if isinstance(mode, str):
        try:
            return int(mode, 8) & 0o7777
        except ValueError:
            return None
    return None


def _record_is_root_directory(record: Any, *, mode: int | None = None) -> list[str]:
    problems: list[str] = []
    if not isinstance(record, dict):
        return ["record is missing"]
    if record.get("type") != "dir":
        problems.append("is not a directory")
    if record.get("uid") != 0 or record.get("gid") != 0:
        problems.append("is not owned by root:root")
    parsed = _mode_text(record.get("mode"))
    if parsed is None:
        problems.append("has no valid mode")
    else:
        if parsed & 0o022:
            problems.append("is group/other writable")
        if mode is not None and parsed != mode:
            problems.append(f"mode is {parsed:04o}, expected {mode:04o}")
    return problems


def check_layout(
    stat_inventory: object,
    group_inventory: object,
    *,
    qemu_user: str = QEMU_USER,
    indices: tuple[int, ...] = (1,),
) -> list[str]:
    """Return every problem with the supplied host layout inventories."""
    problems: list[str] = []
    stats = stat_inventory.get("stat") if isinstance(stat_inventory, dict) else None
    users = group_inventory.get("users") if isinstance(group_inventory, dict) else None
    if not isinstance(stats, dict):
        return ["stat inventory has no object 'stat' map"]
    if not isinstance(users, dict):
        return ["group inventory has no object 'users' map"]

    user = users.get(qemu_user)
    if not isinstance(user, dict):
        problems.append(f"dedicated QEMU account {qemu_user!r} is missing")
        qemu_uid = qemu_gid = None
    else:
        qemu_uid = user.get("uid")
        qemu_gid = user.get("gid")
        if isinstance(qemu_uid, bool) or not isinstance(qemu_uid, int):
            problems.append("QEMU account uid is not an integer")
            qemu_uid = None
        elif qemu_uid == 0:
            problems.append("QEMU account must not be uid 0")
        if isinstance(qemu_gid, bool) or not isinstance(qemu_gid, int):
            problems.append("QEMU account gid is not an integer")
            qemu_gid = None
        if user.get("shell") not in NOLOGIN_SHELLS:
            problems.append("QEMU account must have a nologin shell")
        if user.get("home_missing") is not True:
            problems.append("QEMU account must not have a home directory")
        primary = user.get("primary_group")
        if not isinstance(primary, str) or not primary:
            problems.append("QEMU account has no primary group")
        elif primary in FORBIDDEN_GROUPS:
            problems.append(f"QEMU account primary group {primary!r} is forbidden")
        supplementary = user.get("supplementary", [])
        if not isinstance(supplementary, list) or not all(
            isinstance(item, str) for item in supplementary
        ):
            problems.append("QEMU account supplementary groups are malformed")
        else:
            for group in supplementary:
                if group in FORBIDDEN_GROUPS:
                    problems.append(
                        f"QEMU account is a member of forbidden group {group!r}"
                    )
                elif group != KVM_GROUP:
                    problems.append(
                        f"QEMU account has an unexpected group {group!r}"
                    )
            if KVM_GROUP not in supplementary:
                problems.append("QEMU account is not a member of kvm")

    for path in ROOT_DIRECTORIES:
        record = stats.get(path)
        required_mode = None
        if path == EVIDENCE_ROOT or path == RUN_ROOT:
            required_mode = 0o700
        elif path in (TOOLS_ROOT, LEAKLAB_ROOT, IMAGES_ROOT, STATE_ROOT):
            required_mode = 0o755
        # ``/`` itself is only required to be root-owned and not group/other
        # writable; a hardened host may use a stricter mode than 0755.
        for problem in _record_is_root_directory(record, mode=required_mode):
            problems.append(f"{path} {problem}")

    # ``vm-NNN`` is created exclusively by provision.py.  Before provisioning
    # it is absent; afterwards it must be a QEMU-owned 0700 directory.  Both
    # lifecycle states are valid, but a present record is never taken on
    # trust.
    for index in indices:
        vm_path = f"{STATE_ROOT}/vm-{index:03d}"
        record = stats.get(vm_path)
        if not isinstance(record, dict):
            continue
        if record.get("type") != "dir":
            problems.append(f"{vm_path} is not a directory")
        if qemu_uid is not None and record.get("uid") != qemu_uid:
            problems.append(f"{vm_path} is not owned by the QEMU user")
        if qemu_gid is not None and record.get("gid") != qemu_gid:
            problems.append(f"{vm_path} is not in the QEMU user's group")
        parsed = _mode_text(record.get("mode"))
        if parsed != 0o700:
            problems.append(f"{vm_path} mode is not 0700")

    for path, record in stats.items():
        if not isinstance(path, str):
            problems.append("stat inventory path is not a string")
            continue
        if not isinstance(record, dict):
            problems.append(f"{path} record is not an object")
            continue
        if record.get("type") != "file":
            continue
        parsed = _mode_text(record.get("mode"))
        if record.get("uid") != 0:
            problems.append(f"{path} file is not owned by root")
        if parsed is None:
            problems.append(f"{path} file has no valid mode")
        elif parsed & 0o6022:
            # Root may write and execute; group/other may read/execute but
            # never write, and setuid/setgid bits are refused.  The 0755 tools
            # this plan installs are therefore valid.
            problems.append(f"{path} file mode {parsed:04o} is unsafe")
        if path.startswith(IMAGES_ROOT + "/") and parsed != 0o644:
            problems.append(f"{path} image file mode is not 0644")
    return problems


_CHECK_SCRIPT = r"""
check_ancestry() {
  python3 - "$1" <<'PY'
import os, stat, sys
path = sys.argv[1]
parts = os.path.abspath(path).split("/")
root_info = os.lstat("/")
if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != 0 or root_info.st_mode & 0o022:
    raise SystemExit("vprlab: / is not a trusted root directory")
current = "/"
for part in parts[1:]:
    current = os.path.join(current, part)
    info = os.lstat(current)
    if stat.S_ISLNK(info.st_mode):
        raise SystemExit("vprlab: %s is a symlink" % current)
    if not stat.S_ISDIR(info.st_mode):
        raise SystemExit("vprlab: %s is not a directory" % current)
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise SystemExit("vprlab: %s is not root-owned or is writable" % current)
PY
}

require_root() {
  [ "$(id -u)" -eq 0 ] || { echo "vprlab: setup must run as root" >&2; exit 1; }
}

check_account() {
  python3 - "$QEMU_USER" <<'PY'
import grp, os, pwd, sys
name = sys.argv[1]
user = pwd.getpwnam(name)
if user.pw_uid == 0:
    raise SystemExit("vprlab: QEMU account must not be uid 0")
if user.pw_dir not in ("", "/nonexistent", "/var/empty") and os.path.exists(user.pw_dir):
    raise SystemExit("vprlab: QEMU account must not have a home directory")
if user.pw_shell not in ("/usr/sbin/nologin", "/sbin/nologin", "/usr/bin/false", "/bin/false"):
    raise SystemExit("vprlab: QEMU account must have a nologin shell")
primary = grp.getgrgid(user.pw_gid).gr_name
for group in grp.getgrall():
    if name not in group.gr_mem:
        continue
    if group.gr_name in ("sudo", "wheel", "adm", "docker", "lxd", "libvirt", "disk"):
        raise SystemExit("vprlab: QEMU account is in forbidden group " + group.gr_name)
    if group.gr_name != "kvm":
        raise SystemExit("vprlab: QEMU account has unexpected group " + group.gr_name)
if not any(name in group.gr_mem for group in grp.getgrall() if group.gr_name == "kvm"):
    raise SystemExit("vprlab: QEMU account is not a member of kvm")
if primary in ("sudo", "wheel", "adm", "docker", "lxd", "libvirt", "disk"):
    raise SystemExit("vprlab: QEMU primary group is forbidden")
PY
}

hostcopy() {
  python3 - "$@" <<'VPRLAB_PY'
{hostcopy_source}
VPRLAB_PY
}

copy_tree() {
  SOURCE="$1"
  DEST="$2"
  MANIFEST="$3"
  LINKS="$4"
  shift 4
  [ -d "$SOURCE" ] || { echo "vprlab: missing source $SOURCE" >&2; return 1; }
  mkdir -p "$(dirname "$MANIFEST")"
  hostcopy copy-tree "$SOURCE" "$DEST" "$MANIFEST" "$LINKS" "$@"
}

copy_named() {
  SOURCE="$1"
  DEST="$2"
  MANIFEST="$3"
  LINKS="$4"
  shift 4
  [ -d "$SOURCE" ] || { echo "vprlab: missing source $SOURCE" >&2; return 1; }
  mkdir -p "$(dirname "$MANIFEST")"
  hostcopy copy-named "$SOURCE" "$DEST" "$MANIFEST" "$LINKS" "$@"
}

verify_manifest() {
  DIRECTORY="$1"
  MANIFEST="$2"
  LINKS="$3"
  shift 3
  hostcopy verify "$DIRECTORY" "$MANIFEST" "$LINKS" "$@"
}

check_elf_deps() {
  hostcopy elfcheck "$1"
}
"""


def _hostcopy_source() -> str:
    path = pathlib.Path(__file__).with_name("hostcopy.py")
    try:
        source = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise LayoutError(
            f"cannot read the embedded copy helper: {exc.__class__.__name__}"
        ) from exc
    if "VPRLAB_PY" in source:
        raise LayoutError("copy helper collides with the shell heredoc delimiter")
    return source


def render_setup_script(
    *,
    qemu_user: str = QEMU_USER,
    indices: tuple[int, ...] = (1,),
    tools_source: str = TOOLS_SOURCE,
    images_source: str = IMAGES_SOURCE,
    leak_lab_source: str | None = None,
    base_image_name: str = BASE_IMAGE_NAME,
    base_image_sha512: str = BASE_IMAGE_SHA512,
    tools_root: str = TOOLS_ROOT,
    state_root: str = STATE_ROOT,
    run_root: str = RUN_ROOT,
) -> str:
    if not _valid_user(qemu_user):
        raise LayoutError("qemu_user must be a conventional account name")
    if not indices or any(
        isinstance(index, bool) or not isinstance(index, int) or not 1 <= index <= 99
        for index in indices
    ):
        raise LayoutError("indices must be integers in 1..99")
    if not _valid_sha512(base_image_sha512):
        raise LayoutError("base_image_sha512 must be 128 lowercase hex characters")
    base_image_name = _valid_name(base_image_name, "base_image_name")
    if leak_lab_source is None:
        leak_lab_source = str(pathlib.Path(__file__).resolve().parent.parent)
    tools_root = _valid_path(tools_root, "tools_root")
    state_root = _valid_path(state_root, "state_root")
    run_root = _valid_path(run_root, "run_root")
    for label, value in (
        ("tools_root", tools_root),
        ("state_root", state_root),
        ("run_root", run_root),
    ):
        if value.rstrip("/") in ("", "/"):
            raise LayoutError(f"{label} must not be /")
    tools_source = _valid_path(tools_source, "tools_source")
    images_source = _valid_path(images_source, "images_source")
    leak_lab_source = _valid_path(leak_lab_source, "leak_lab_source")
    images_root = state_root.rstrip("/") + "/images"
    evidence_root = state_root.rstrip("/") + "/evidence"
    tools_root = tools_root.rstrip("/")
    leaklab_root = tools_root + "/leaklab"
    index_words = " ".join(str(index) for index in sorted(set(indices)))
    leak_lab_words = " ".join(LEAK_LAB_FILES)
    check_script = _CHECK_SCRIPT.replace(
        "{hostcopy_source}", _hostcopy_source()
    )
    return f"""#!/bin/sh
# vprlab root-owned host layout (PLAN ONLY; review before running as root).
# Generated by tools/leak-lab/vm/hostsetup.py.  Re-running setup is safe: the
# account is reused and every destination file is verified after copying.
set -eu

QEMU_USER={shlex.quote(qemu_user)}
QEMU_GROUP='vprlab-qemu'
KVM_GROUP='kvm'
TOOLS_ROOT={shlex.quote(tools_root)}
LEAKLAB_ROOT={shlex.quote(leaklab_root)}
STATE_ROOT={shlex.quote(state_root)}
IMAGES_ROOT={shlex.quote(images_root)}
EVIDENCE_ROOT={shlex.quote(evidence_root)}
RUN_ROOT={shlex.quote(run_root)}
TOOLS_SOURCE={shlex.quote(tools_source)}
IMAGES_SOURCE={shlex.quote(images_source)}
LEAKLAB_SOURCE={shlex.quote(leak_lab_source)}
BASE_IMAGE_NAME={shlex.quote(base_image_name)}
BASE_IMAGE_SHA512={shlex.quote(base_image_sha512)}
INDICES={shlex.quote(index_words)}
LEAKLAB_FILES={shlex.quote(leak_lab_words)}
{check_script}

teardown() {{
  if [ -e "$RUN_ROOT" ]; then
    if ! command -v flock >/dev/null 2>&1; then
      echo "vprlab: cannot verify $RUN_ROOT/run.lock without flock; refusing teardown" >&2
      return 1
    fi
    # Hold the lock for the whole teardown, not just for a probe.
    exec 9>>"$RUN_ROOT/run.lock"
    if ! flock -n 9 2>/dev/null; then
      echo "vprlab: a phase holds $RUN_ROOT/run.lock; refusing teardown" >&2
      return 1
    fi
  fi
  if ! command -v pgrep >/dev/null 2>&1; then
    echo "vprlab: cannot inspect QEMU processes without pgrep; refusing teardown" >&2
    return 1
  fi
  if pgrep -u "$QEMU_USER" -f qemu-system >/dev/null 2>&1; then
    echo "vprlab: a QEMU process for $QEMU_USER is running; refusing teardown" >&2
    return 1
  fi
  rm -rf -- "$IMAGES_ROOT" "$TOOLS_ROOT"
  rm -rf -- "$STATE_ROOT"/vm-[0-9][0-9][0-9]
  for index in $INDICES; do
    suffix=$(printf '%03d' "$index")
    rm -rf -- "$STATE_ROOT/vm-$suffix"
  done
  # Evidence is retained deliberately: it is the audit record of past phases.
  echo "vprlab: retaining evidence at $EVIDENCE_ROOT" >&2
  rmdir -- "$STATE_ROOT" "$RUN_ROOT" 2>/dev/null || true
  if getent passwd "$QEMU_USER" >/dev/null 2>&1; then
    if ! userdel "$QEMU_USER"; then
      echo "vprlab: userdel $QEMU_USER failed; the account was retained" >&2
      return 1
    fi
  fi
  echo "vprlab: teardown complete"
  return 0
}}

if [ "${{1:-}}" = "teardown" ]; then
  require_root
  teardown
  exit $?
fi

require_root

# Setup is exclusive with a running phase or QEMU just like teardown: a
# re-run must never copy over a tool tree that a live guest has mapped.
install -d -m 0700 -o root -g root "$RUN_ROOT"
if ! command -v flock >/dev/null 2>&1; then
  echo "vprlab: cannot verify $RUN_ROOT/run.lock without flock; refusing setup" >&2
  exit 1
fi
exec 9>>"$RUN_ROOT/run.lock"
if ! flock -n 9 2>/dev/null; then
  echo "vprlab: a phase holds $RUN_ROOT/run.lock; refusing setup" >&2
  exit 1
fi
if ! command -v pgrep >/dev/null 2>&1; then
  echo "vprlab: cannot inspect QEMU processes without pgrep; refusing setup" >&2
  exit 1
fi
if pgrep -u "$QEMU_USER" -f qemu-system >/dev/null 2>&1; then
  echo "vprlab: a QEMU process for $QEMU_USER is running; refusing setup" >&2
  exit 1
fi

if ! getent group "$QEMU_GROUP" >/dev/null 2>&1; then
  groupadd --system "$QEMU_GROUP"
fi
if ! getent passwd "$QEMU_USER" >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin \\
    --gid "$QEMU_GROUP" "$QEMU_USER"
fi
usermod -aG "$KVM_GROUP" "$QEMU_USER"
check_account

# Every destination ancestor must already be root-owned and not writable by
# the operator before any file is placed below it.
for directory in "$(dirname "$TOOLS_ROOT")" "$(dirname "$STATE_ROOT")" \\
    "$(dirname "$RUN_ROOT")"; do
  check_ancestry "$directory"
done
for directory in "$TOOLS_ROOT" "$LEAKLAB_ROOT" "$STATE_ROOT" "$IMAGES_ROOT" \\
    "$EVIDENCE_ROOT" "$RUN_ROOT"; do
  if [ -e "$directory" ] || [ -L "$directory" ]; then
    check_ancestry "$directory"
  fi
done

install -d -m 0755 -o root -g root "$TOOLS_ROOT" "$LEAKLAB_ROOT" \\
  "$STATE_ROOT" "$IMAGES_ROOT"
install -d -m 0700 -o root -g root "$EVIDENCE_ROOT" "$RUN_ROOT"
# The plan deliberately does not create vm-NNN: provision.py must create each
# state directory exclusively and then chown it to the QEMU user.
for directory in "$TOOLS_ROOT" "$LEAKLAB_ROOT" "$STATE_ROOT" "$IMAGES_ROOT" \\
    "$EVIDENCE_ROOT" "$RUN_ROOT"; do
  check_ancestry "$directory"
done

# Complete tool tree: regular files and confined relative symlinks.  Every
# source file is opened O_NOFOLLOW, hashed while it is copied, re-hashed after
# writing, and then recorded in SHA256SUMS; every link target is recorded in
# SYMLINKS.json.
copy_tree "$TOOLS_SOURCE" "$TOOLS_ROOT" "$TOOLS_ROOT/SHA256SUMS" \\
  "$TOOLS_ROOT/SYMLINKS.json"
verify_manifest "$TOOLS_ROOT" "$TOOLS_ROOT/SHA256SUMS" \\
  "$TOOLS_ROOT/SYMLINKS.json" --exclude=leaklab
check_elf_deps "$TOOLS_ROOT"
chown -R root:root "$TOOLS_ROOT"
find "$TOOLS_ROOT" -type d -exec chmod 0755 {{}} +
find "$TOOLS_ROOT" -type f -exec chmod go-w {{}} +

# Root-owned runtime copy of the leak-lab modules.  run_phase executes
# pcapscan.py from here and verifies this manifest before use.
copy_named "$LEAKLAB_SOURCE" "$LEAKLAB_ROOT" "$LEAKLAB_ROOT/SHA256SUMS" \\
  "$LEAKLAB_ROOT/SYMLINKS.json" $LEAKLAB_FILES
# Cached bytecode would shadow the verified sources; run_phase refuses it.
find "$LEAKLAB_ROOT" \\( -name __pycache__ -o -name '*.pyc' -o -name '*.pyo' \\) \\
  -prune -exec rm -rf -- {{}} +
verify_manifest "$LEAKLAB_ROOT" "$LEAKLAB_ROOT/SHA256SUMS" \\
  "$LEAKLAB_ROOT/SYMLINKS.json"
chown -R root:root "$LEAKLAB_ROOT"
find "$LEAKLAB_ROOT" -type d -exec chmod 0755 {{}} +
find "$LEAKLAB_ROOT" -type f -exec chmod 0644 {{}} +

# Images are copied with a private 0600 mode and only become world-readable
# after both the pinned digest and the full manifest verify.
copy_tree "$IMAGES_SOURCE" "$IMAGES_ROOT" "$IMAGES_ROOT/SHA512SUMS" \\
  "$IMAGES_ROOT/SYMLINKS.json" --file-mode=0600 --algorithm=sha512
actual=$(sha512sum "$IMAGES_ROOT/$BASE_IMAGE_NAME" | awk '{{print $1}}')
[ "$actual" = "$BASE_IMAGE_SHA512" ] || {{
  echo "vprlab: base image SHA-512 does not match the pinned digest" >&2
  exit 1
}}
verify_manifest "$IMAGES_ROOT" "$IMAGES_ROOT/SHA512SUMS" \\
  "$IMAGES_ROOT/SYMLINKS.json" --algorithm=sha512
chown -R root:root "$IMAGES_ROOT"
find "$IMAGES_ROOT" -type d -exec chmod 0755 {{}} +
find "$IMAGES_ROOT" -type f -exec chmod 0644 {{}} +
echo "vprlab: host layout ready; provision.py creates vm-NNN as the QEMU user"
"""


def _valid_user(user: str) -> bool:
    import re

    return isinstance(user, str) and re.fullmatch(
        r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}", user
    ) is not None and user != "root"


def _valid_sha512(value: str) -> bool:
    import re

    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{128}", value) is not None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="plan the root-owned vprlab layout")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--stat-json", metavar="FILE")
    parser.add_argument("--groups-json", metavar="FILE")
    parser.add_argument("--qemu-user", default=QEMU_USER)
    parser.add_argument(
        "--index",
        type=int,
        action="append",
        dest="indices",
        help="VM state index to create/check (repeatable, default 1)",
    )
    parser.add_argument("--tools-source", default=TOOLS_SOURCE)
    parser.add_argument("--images-source", default=IMAGES_SOURCE)
    parser.add_argument(
        "--leak-lab-source",
        default=str(pathlib.Path(__file__).resolve().parent.parent),
        help="tools/leak-lab tree installed below /opt/vprlab-tools/leaklab",
    )
    parser.add_argument("--base-image-name", default=BASE_IMAGE_NAME)
    parser.add_argument("--base-image-sha512", default=BASE_IMAGE_SHA512)
    parser.add_argument("--tools-root", default=TOOLS_ROOT)
    parser.add_argument("--state-root", default=STATE_ROOT)
    parser.add_argument("--run-root", default=RUN_ROOT)
    arguments = parser.parse_args(argv)
    indices = tuple(arguments.indices or (1,))

    if arguments.check:
        if not arguments.stat_json or not arguments.groups_json:
            print(
                "hostsetup: --check needs --stat-json and --groups-json",
                file=sys.stderr,
            )
            return 2
        try:
            stat_inventory = json.loads(
                pathlib.Path(arguments.stat_json).read_text(encoding="utf-8")
            )
            group_inventory = json.loads(
                pathlib.Path(arguments.groups_json).read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as exc:
            print(f"hostsetup: {exc.__class__.__name__}: {exc}", file=sys.stderr)
            return 2
        problems = check_layout(
            stat_inventory,
            group_inventory,
            qemu_user=arguments.qemu_user,
            indices=indices,
        )
        for problem in problems:
            print(f"LAYOUT: {problem}")
        if problems:
            return 1
        print("OK: root-owned vprlab layout is valid")
        return 0

    try:
        script = render_setup_script(
            qemu_user=arguments.qemu_user,
            indices=indices,
            tools_source=arguments.tools_source,
            images_source=arguments.images_source,
            leak_lab_source=arguments.leak_lab_source,
            base_image_name=arguments.base_image_name,
            base_image_sha512=arguments.base_image_sha512,
            tools_root=arguments.tools_root,
            state_root=arguments.state_root,
            run_root=arguments.run_root,
        )
    except LayoutError as exc:
        print(f"hostsetup: {exc}", file=sys.stderr)
        return 2
    sys.stdout.write(script)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
