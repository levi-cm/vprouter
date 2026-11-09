#!/usr/bin/env python3
"""Plan-only generator for the root-owned vprlab host layout.

This program never executes anything (except when the printed script is run by
the operator).  It prints a standalone ``#!/bin/sh`` script that creates:

* the dedicated ``vprlab-qemu`` system account (no login shell, no home,
  member of ``kvm`` only);
* ``/opt/vprlab-tools`` (root:root 0755) with a verified copy of the staged
  QEMU tools and their library/module trees;
* ``/var/lib/vprlab/images`` (root 0755, files 0644) with the verified base
  image and ``SHA512SUMS``;
* ``/var/lib/vprlab/vm-NNN`` (QEMU user 0700), ``/var/lib/vprlab/evidence``
  (root 0700) and ``/run/vprlab`` (root 0700);
* a manifest (``SHA256SUMS`` for tools, ``SHA512SUMS`` for images) and a
  post-copy hash verification of every copied file.

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

Teardown is the generated script's ``teardown`` subcommand.  It refuses while
``/run/vprlab/run.lock`` is held by a phase and while a QEMU process for the
lab account exists, then removes exactly the lab's own directories and the
dedicated account.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import stat
import sys
from typing import Any

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
STATE_ROOT = "/var/lib/vprlab"
IMAGES_ROOT = STATE_ROOT + "/images"
EVIDENCE_ROOT = STATE_ROOT + "/evidence"
RUN_ROOT = "/run/vprlab"

ROOT_DIRECTORIES = (
    "/",
    "/opt",
    TOOLS_ROOT,
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
        elif path in (TOOLS_ROOT, IMAGES_ROOT, STATE_ROOT):
            required_mode = 0o755
        elif path == "/":
            required_mode = 0o755
        for problem in _record_is_root_directory(record, mode=required_mode):
            problems.append(f"{path} {problem}")

    for index in indices:
        vm_path = f"{STATE_ROOT}/vm-{index:03d}"
        record = stats.get(vm_path)
        if not isinstance(record, dict):
            problems.append(f"{vm_path} is missing")
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
        elif parsed & 0o133:
            # Files must never be executable/writable outside root.
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

copy_tools() {
  SOURCE="$1"
  DEST="$2"
  MANIFEST="$3"
  HASHER="$4"
  [ -d "$SOURCE" ] || { echo "vprlab: missing tool source $SOURCE" >&2; return 1; }
  mkdir -p "$(dirname "$MANIFEST")"
  : > "$MANIFEST.tmp"
  ( cd "$SOURCE" && find . -type f -print ) | while IFS= read -r relative; do
    relative=${relative#./}
    src="$SOURCE/$relative"
    dst="$DEST/$relative"
    mkdir -p "$(dirname "$dst")"
    cp -p "$src" "$dst"
    expected=$("$HASHER" "$src" | awk '{print $1}')
    actual=$("$HASHER" "$dst" | awk '{print $1}')
    [ "$expected" = "$actual" ] || {
      echo "vprlab: hash mismatch after copying $relative" >&2
      return 1
    }
    printf '%s  %s\n' "$actual" "$relative" >> "$MANIFEST.tmp"
  done
  mv "$MANIFEST.tmp" "$MANIFEST"
  chmod 0644 "$MANIFEST"
}

verify_manifest() {
  DIRECTORY="$1"
  MANIFEST="$2"
  HASHER="$3"
  ( cd "$DIRECTORY" && "$HASHER" -c "$MANIFEST" )
}
"""


def render_setup_script(
    *,
    qemu_user: str = QEMU_USER,
    indices: tuple[int, ...] = (1,),
    tools_source: str = TOOLS_SOURCE,
    images_source: str = IMAGES_SOURCE,
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
    if not base_image_name or "/" in base_image_name or base_image_name in (".", ".."):
        raise LayoutError("base image name must be a plain file name")
    for label, value in (
        ("tools_root", tools_root),
        ("state_root", state_root),
        ("run_root", run_root),
    ):
        if not isinstance(value, str) or not value.startswith("/") or "\n" in value:
            raise LayoutError(f"{label} must be an absolute single-line path")
        if value.rstrip("/") in ("", "/"):
            raise LayoutError(f"{label} must not be /")
        if "'" in value:
            raise LayoutError(f"{label} must not contain a single quote")
    for label, value in (
        ("tools_source", tools_source),
        ("images_source", images_source),
    ):
        if not isinstance(value, str) or not value or "\n" in value or "'" in value:
            raise LayoutError(f"{label} must be a single-line path without quotes")
    images_root = state_root.rstrip("/") + "/images"
    evidence_root = state_root.rstrip("/") + "/evidence"
    index_words = " ".join(str(index) for index in sorted(set(indices)))
    return f"""#!/bin/sh
# vprlab root-owned host layout (PLAN ONLY; review before running as root).
# Generated by tools/leak-lab/vm/hostsetup.py.  Re-running setup is safe: the
# account is reused and every destination file is verified after copying.
set -eu

QEMU_USER='{qemu_user}'
QEMU_GROUP='vprlab-qemu'
KVM_GROUP='kvm'
TOOLS_ROOT='{tools_root}'
STATE_ROOT='{state_root}'
IMAGES_ROOT='{images_root}'
EVIDENCE_ROOT='{evidence_root}'
RUN_ROOT='{run_root}'
TOOLS_SOURCE='{tools_source}'
IMAGES_SOURCE='{images_source}'
BASE_IMAGE_NAME='{base_image_name}'
BASE_IMAGE_SHA512='{base_image_sha512}'
INDICES='{index_words}'
{_CHECK_SCRIPT}

teardown() {{
  if [ -e "$RUN_ROOT/run.lock" ] && command -v flock >/dev/null 2>&1; then
    if ! flock -n "$RUN_ROOT/run.lock" true 2>/dev/null; then
      echo "vprlab: a phase holds $RUN_ROOT/run.lock; refusing teardown" >&2
      return 1
    fi
  fi
  if command -v pgrep >/dev/null 2>&1 && pgrep -u "$QEMU_USER" -f qemu-system >/dev/null 2>&1; then
    echo "vprlab: a QEMU process for $QEMU_USER is running; refusing teardown" >&2
    return 1
  fi
  rm -rf -- "$EVIDENCE_ROOT" "$IMAGES_ROOT" "$TOOLS_ROOT"
  rm -rf -- "$STATE_ROOT"/vm-[0-9][0-9][0-9]
  for index in $INDICES; do
    suffix=$(printf '%03d' "$index")
    rm -rf -- "$STATE_ROOT/vm-$suffix"
  done
  rmdir -- "$STATE_ROOT" "$RUN_ROOT" 2>/dev/null || true
  if getent passwd "$QEMU_USER" >/dev/null 2>&1; then
    userdel "$QEMU_USER" || true
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
for directory in "$TOOLS_ROOT" "$STATE_ROOT" "$IMAGES_ROOT" "$EVIDENCE_ROOT" \\
    "$RUN_ROOT"; do
  if [ -e "$directory" ] || [ -L "$directory" ]; then
    check_ancestry "$directory"
  fi
done

install -d -m 0755 -o root -g root "$TOOLS_ROOT" "$STATE_ROOT" "$IMAGES_ROOT"
install -d -m 0700 -o root -g root "$EVIDENCE_ROOT" "$RUN_ROOT"
for index in $INDICES; do
  suffix=$(printf '%03d' "$index")
  install -d -m 0700 -o "$QEMU_USER" -g "$QEMU_GROUP" \\
    "$STATE_ROOT/vm-$suffix"
done
for directory in "$TOOLS_ROOT" "$STATE_ROOT" "$IMAGES_ROOT" "$EVIDENCE_ROOT" \\
    "$RUN_ROOT"; do
  check_ancestry "$directory"
done

copy_tools "$TOOLS_SOURCE" "$TOOLS_ROOT" "$TOOLS_ROOT/SHA256SUMS" sha256sum
verify_manifest "$TOOLS_ROOT" "$TOOLS_ROOT/SHA256SUMS" sha256sum
chown -R root:root "$TOOLS_ROOT"
find "$TOOLS_ROOT" -type d -exec chmod 0755 {{}} +
find "$TOOLS_ROOT" -type f -exec chmod go-w {{}} +

copy_tools "$IMAGES_SOURCE" "$IMAGES_ROOT" "$IMAGES_ROOT/SHA512SUMS" sha512sum
actual=$(sha512sum "$IMAGES_ROOT/$BASE_IMAGE_NAME" | awk '{{print $1}}')
[ "$actual" = "$BASE_IMAGE_SHA512" ] || {{
  echo "vprlab: base image SHA-512 does not match the pinned digest" >&2
  exit 1
}}
verify_manifest "$IMAGES_ROOT" "$IMAGES_ROOT/SHA512SUMS" sha512sum
chown -R root:root "$IMAGES_ROOT"
find "$IMAGES_ROOT" -type f -exec chmod 0644 {{}} +
chmod 0755 "$IMAGES_ROOT"
echo "vprlab: host layout ready; run the phase runner as root"
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
