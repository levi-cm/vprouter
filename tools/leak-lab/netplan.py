#!/usr/bin/env python3
"""Plan-only generator for the isolated vprlab host network.

This program never executes a command, never changes a link and never touches
nftables or iptables.  It prints the exact privileged commands as a standalone
``#!/bin/sh`` script for a human to review and run, plus a
``--check-name-collisions`` preflight that only reads JSON produced by
``ip -j link``, ``ip -j addr``, ``ip -j route show table all``,
``nft -j list tables`` and an ``iptables-save`` dump.

Every setup run creates a fresh owner record in ``/run/vprlab/owner.json``
(exclusive create, mode 0600, 32 hexadecimal characters from ``/dev/urandom``).
Every object the run creates carries the exact string
``vprlab-owned:<token>``: the ``ifalias`` of ``vprlab0`` and ``vprlab-tap0``,
the ``inet vprlab`` nft table comment, and the two ``DOCKER-USER`` rule
comments.  Teardown reads that token and verifies every existing object before
it mutates anything.

The generated nftables table is ``inet vprlab``.  Nothing here resets the
ruleset, edits a table other than Docker's ``DOCKER-USER`` chain (where it
inserts and later removes only its own exactly tagged rules), or deletes an
object it did not create.  The scoped DOCKER-USER accepts are required because
Docker on Debian 13 installs an iptables-nft FORWARD policy of DROP that an
accept in another nft base chain cannot override.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import pathlib
import re
import shlex
import sys
from typing import Any

BRIDGE = "vprlab0"
TAP = "vprlab-tap0"

#: Fixed lab MAC addresses.  The bridge MAC is set explicitly before either
#: link comes up, so a policy does not silently change from run to run.
BRIDGE_MAC = "52:54:00:76:70:01"
VM_WAN_MAC = "52:54:00:76:70:02"

TABLE_FAMILY = "inet"
TABLE_NAME = "vprlab"
BRIDGE_ADDRESS = "10.250.0.1/24"
LAB_SUBNET_TEXT = "10.250.0.0/24"
LAB_SUBNET = ipaddress.IPv4Network(LAB_SUBNET_TEXT)
OWNER_PREFIX = "vprlab-owned:"
DEFAULT_RUN_DIR = "/run/vprlab"
DEFAULT_TAP_USER = "vprlab-qemu"
#: The M1 plan's own foreground capture lives in the root-owned run directory
#: (created before the capture starts), never in the operator's working
#: directory.  ``$RUN_DIR`` is expanded by the generated shell script.
DEFAULT_CAPTURE = "$RUN_DIR/manual-capture.pcap"
VM_WAN_IPV4 = "10.250.0.2"

_IFACE_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,15}$")
_TAP_USER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}$")
_SAFE_COMPONENT_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class NetplanError(ValueError):
    """A requested name or a supplied inspection document is invalid."""


def _safe_path_parts(value: str, what: str, *, allow_run_dir: bool) -> str:
    """Validate a shell-inserted path and return it unchanged.

    Only ``[A-Za-z0-9._-]`` components are accepted and ``.``/``..`` are
    refused, so no shell metacharacter, whitespace or command substitution can
    reach the generated script.  ``--capture-file`` may name a path below the
    generated ``$RUN_DIR`` variable; callers that do not create that variable
    must require an absolute path.
    """
    if not isinstance(value, str) or not value or "\n" in value or "\r" in value:
        raise NetplanError(f"{what} must be a non-empty single-line path")
    prefix = ""
    remainder = value
    if allow_run_dir and value.startswith("$RUN_DIR/"):
        prefix = "$RUN_DIR/"
        remainder = value[len(prefix):]
    elif value.startswith("/"):
        prefix = "/"
        remainder = value[1:]
    else:
        raise NetplanError(f"{what} must be absolute or below $RUN_DIR")
    parts = remainder.split("/")
    if not parts or any(_SAFE_COMPONENT_RE.fullmatch(part) is None for part in parts):
        raise NetplanError(
            f"{what} must contain only [A-Za-z0-9._-] path components"
        )
    if any(part in (".", "..") for part in parts):
        raise NetplanError(f"{what} must not contain . or .. components")
    return prefix + "/".join(parts)


def _shell_quote_always(part: str) -> str:
    """Quote every component, even one shlex would leave bare."""
    quoted = shlex.quote(part)
    return quoted if quoted.startswith("'") else "'" + part + "'"


def _shell_path(path: str) -> str:
    """Render a validated path as a quoted shell word.

    ``$RUN_DIR`` is the one variable the generated script defines, so it is
    composed as ``"$RUN_DIR"/'basename'`` rather than embedded unquoted.
    """
    if path.startswith("$RUN_DIR/"):
        remainder = path[len("$RUN_DIR/"):]
        return '"$RUN_DIR"/' + "/".join(
            _shell_quote_always(part) for part in remainder.split("/")
        )
    return shlex.quote(path)


def _validate_iface(name: str, what: str) -> str:
    if not isinstance(name, str) or _IFACE_RE.fullmatch(name) is None:
        raise NetplanError(
            f"{what} must be 1..15 characters of [A-Za-z0-9_.:@-]"
        )
    if name in (".", "..") or name.startswith("-"):
        raise NetplanError(f"{what} must be a real interface name, not {name!r}")
    if name == "lo":
        raise NetplanError(f"{what} must not be the loopback interface")
    if name in (BRIDGE, TAP):
        raise NetplanError(f"{what} must not be the lab interface name {name!r}")
    return name


def _validate_tap_user(user: str) -> str:
    if not isinstance(user, str) or _TAP_USER_RE.fullmatch(user) is None:
        raise NetplanError("tap user must be a conventional account name")
    if user == "root" or (user.isdigit() and int(user) == 0):
        raise NetplanError("tap user must not be root or uid 0")
    return user


def capture_argv(capture_file: str = DEFAULT_CAPTURE) -> list[str]:
    """Return the exact tcpdump argv the plan prints.

    There is deliberately no BPF filter expression, no ``-s`` short snaplen
    and no packet-count limit: every frame the tap sees must be written.
    """
    _safe_path_parts(capture_file, "capture_file", allow_run_dir=True)
    return [
        "tcpdump",
        "-i",
        TAP,
        "-nn",
        "-U",
        "--immediate-mode",
        "-B",
        "8192",
        "-s",
        "0",
        "-w",
        capture_file,
    ]


def check_capture_argv(argv: Any, pcap_path: str | os.PathLike[str] | None = None) -> str | None:
    """Compare a submitted argv with :func:`capture_argv`.

    Returns ``None`` when it matches exactly except for the ``-w`` path,
    ``capture_argv_invalid`` when the value is not a non-empty list of
    non-empty strings, and ``capture_argv_mismatch`` for any other difference.
    When ``pcap_path`` is supplied, the ``-w`` value must resolve to exactly
    that file (``realpath`` equality), tying the declared command to the pcap
    that was actually scanned.
    """
    if (
        not isinstance(argv, list)
        or not argv
        or not all(isinstance(item, str) and item for item in argv)
    ):
        return "capture_argv_invalid"
    expected = capture_argv(DEFAULT_CAPTURE)
    if len(argv) != len(expected):
        return "capture_argv_mismatch"
    write_index = expected.index("-w") + 1
    for index, (got, want) in enumerate(zip(argv, expected)):
        if index == write_index:
            continue
        if got != want:
            return "capture_argv_mismatch"
    if pcap_path is not None:
        try:
            expected_path = os.path.realpath(os.fspath(pcap_path))
        except TypeError:
            return "capture_argv_mismatch"
        if os.path.realpath(argv[write_index]) != expected_path:
            return "capture_argv_mismatch"
    return None


# ---------------------------------------------------------------------------
# Embedded helpers for the generated POSIX shell script.
#
# These snippets use double quotes only: they are wrapped in ``python3 -c '...'``
# single quotes in the generated script.  Keeping them out of the f-string also
# keeps shell ``${...}`` and nft ``{ ... }`` braces readable.
# ---------------------------------------------------------------------------
_CREATE_OWNER_CODE = """\
import datetime, json, os, sys
run_dir = sys.argv[1]
owner_file = os.path.join(run_dir, "owner.json")
os.makedirs(run_dir, mode=0o700, exist_ok=True)
os.chmod(run_dir, 0o700)
token = open("/dev/urandom", "rb").read(16).hex()
created = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
document = {"schema": 1, "token": token, "created": created}
try:
    fd = os.open(owner_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
except FileExistsError:
    print("netplan: " + owner_file + " already exists; refusing setup", file=sys.stderr)
    sys.exit(1)
with os.fdopen(fd, "w", encoding="utf-8") as handle:
    os.fchmod(handle.fileno(), 0o600)
    json.dump(document, handle, sort_keys=True)
    handle.write("\\n")
if os.geteuid() == 0:
    os.chown(run_dir, 0, 0)
    os.chown(owner_file, 0, 0)
print("vprlab-owned:" + token)
"""

_READ_OWNER_CODE = """\
import json, re, sys
try:
    with open(sys.argv[1], "r", encoding="utf-8") as handle:
        document = json.load(handle)
except Exception:
    sys.exit(1)
token = document.get("token") if isinstance(document, dict) else None
if (
    not isinstance(document, dict)
    or document.get("schema") != 1
    or not isinstance(token, str)
    or re.fullmatch(r"[0-9a-f]{32}", token) is None
    or not isinstance(document.get("created"), str)
):
    sys.exit(1)
print("vprlab-owned:" + token)
"""

_LINK_CHECK_CODE = """\
import json, sys
name, owner, kind = sys.argv[1:4]
try:
    document = json.load(sys.stdin)
except Exception:
    sys.exit(1)
if not isinstance(document, list):
    sys.exit(1)
entries = [entry for entry in document if isinstance(entry, dict) and entry.get("ifname") == name]
if len(entries) != 1:
    sys.exit(1)
entry = entries[0]
info = entry.get("linkinfo")
kind_ok = True
if isinstance(info, dict):
    kind_ok = info.get("info_kind") == kind
    if kind == "tun":
        data = info.get("info_data")
        if isinstance(data, dict):
            kind_ok = kind_ok and data.get("type") == "tap"
ok = entry.get("ifalias") == owner and kind_ok
sys.exit(0 if ok else 1)
"""

_NFT_CHECK_CODE = """\
import json, sys
owner = sys.argv[1]
try:
    document = json.load(sys.stdin)
except Exception:
    sys.exit(1)
if not isinstance(document, dict):
    sys.exit(1)
tables = [entry["table"] for entry in document.get("nftables", []) if isinstance(entry, dict) and isinstance(entry.get("table"), dict)]
ok = (
    len(tables) == 1
    and tables[0].get("family") == "inet"
    and tables[0].get("name") == "vprlab"
    and tables[0].get("comment") == owner
)
sys.exit(0 if ok else 1)
"""

_NEIGH_CHECK_CODE = """\
import json, sys
ip, mac = sys.argv[1:3]
try:
    document = json.load(sys.stdin)
except Exception:
    sys.exit(1)
if not isinstance(document, list):
    sys.exit(1)
entries = [entry for entry in document if isinstance(entry, dict) and entry.get("dst") == ip]
if not entries:
    sys.exit(0)
if len(entries) != 1:
    sys.exit(1)
entry = entries[0]
state = entry.get("state") if isinstance(entry.get("state"), list) else []
state = [str(item).lower() for item in state]
permanent = str(entry.get("nud_state", "")).lower() == "permanent" or "permanent" in state
sys.exit(0 if entry.get("lladdr") == mac and permanent else 1)
"""

_NEIGH_PRESENT_CODE = """\
import json, sys
try:
    document = json.load(sys.stdin)
except Exception:
    sys.exit(1)
sys.exit(0 if isinstance(document, list) and document else 1)
"""

_TAP_MASTERED_CODE = """\
import json, sys
name = sys.argv[1]
try:
    document = json.load(sys.stdin)
except Exception:
    sys.exit(1)
if not isinstance(document, list):
    sys.exit(1)
entries = [entry for entry in document if isinstance(entry, dict) and entry.get("ifname") == name]
if len(entries) != 1:
    sys.exit(1)
sys.exit(0 if entries[0].get("master") else 1)
"""

#: Full-inventory lookups.  Exit 0 means present, 1 means proved absent from a
#: complete successful inventory, and 2 means the inventory itself failed.
#: Only 1 may be read as "the object is gone"; a failed inventory retains
#: protection.
_INVENTORY_LINK_CODE = """\
import json, sys
name = sys.argv[1]
try:
    document = json.load(sys.stdin)
except Exception:
    sys.exit(2)
if not isinstance(document, list):
    sys.exit(2)
present = False
for entry in document:
    if not isinstance(entry, dict) or not isinstance(entry.get("ifname"), str):
        sys.exit(2)
    if entry["ifname"] == name:
        present = True
sys.exit(0 if present else 1)
"""

_INVENTORY_NEIGH_CODE = """\
import json, sys
ip = sys.argv[1]
dev = sys.argv[2]
try:
    document = json.load(sys.stdin)
except Exception:
    sys.exit(2)
if not isinstance(document, list):
    sys.exit(2)
present = False
for entry in document:
    if not isinstance(entry, dict):
        sys.exit(2)
    if entry.get("dst") == ip and entry.get("dev") == dev:
        present = True
sys.exit(0 if present else 1)
"""

_ISOLATED_CHECK_CODE = """\
import json, sys
name = sys.argv[1]
try:
    document = json.load(sys.stdin)
except Exception:
    sys.exit(1)
if not isinstance(document, list):
    sys.exit(1)
entries = [entry for entry in document if isinstance(entry, dict) and entry.get("ifname") == name]
if len(entries) != 1:
    sys.exit(1)
entry = entries[0]
ok = str(entry.get("operstate", "")).lower() == "down" and not entry.get("master")
sys.exit(0 if ok else 1)
"""


_PLAN_TEMPLATE = """#!/bin/sh
set -eu
# vprlab host network setup plan
# PLAN ONLY: netplan.py never executes anything. This file is a standalone
# script for review and deliberate execution as root on the debdev host.
# not for interactive paste: `set -eu` would stay active in your shell. The
# capture point is the host tap, outside the router VM.
#
# Host default/WAN interface: @@WAN@@
#
# Required preflight before running any command below. Generate the inventories
# locally, then run the collision check; setup must abort unless it prints OK:
#   ip -j link > links.json
#   ip -j addr > addresses.json
#   ip -j route show table all > routes.json
#   nft -j list tables > tables.json
#   iptables-save > iptables.txt
#   python3 -B tools/leak-lab/netplan.py --check-name-collisions \\
#     --wan-interface @@WAN@@ \\
#     --links-json links.json --addresses-json addresses.json \\
#     --routes-json routes.json --tables-json tables.json \\
#     --iptables-save iptables.txt
# The preflight rejects an existing @@LAB_SUBNET@@ address or route in ANY
# routing table, an existing bridge/tap name or altname, an existing inet
# vprlab table, a non-existent or loopback WAN interface, malformed inventory
# JSON, and any host where DOCKER-USER is absent or is not jumped to from
# FORWARD before Docker's own rules.
#
# Required kernel setting (this plan never changes it):
#   sysctl -n net.ipv4.ip_forward
# must print 1. If it prints 0, the plan requires 1 for the phase; enable it
# and restore exactly this value after teardown:
#   sysctl -w net.ipv4.ip_forward=1
#   ... run the phase ...
#   sysctl -w net.ipv4.ip_forward=0
#
# Run ownership: setup creates @@RUN_DIR@@ (0700 root) and
# @@RUN_DIR@@/owner.json exclusively (O_EXCL, 0600) with
#   {"schema":1,"token":"<32 hex from /dev/urandom>","created":"<UTC>"}
# Every object created by the run carries the exact string
#   @@OWNER_PREFIX@@<token>
# in the vprlab0/vprlab-tap0 ifalias, the inet vprlab table comment and both
# DOCKER-USER rule comments. Teardown reads that token and verifies every
# existing object before any mutation; any mismatch aborts with no changes.
# Setup first creates the links DOWN with their aliases, then the nft table
# (input drop, output drop, forward restrictions, scoped masquerade), then the
# DOCKER-USER accepts, then the permanent host neighbour, and only then brings
# the links up.

RUN_DIR="${VPRLAB_RUN_DIR:-@@RUN_DIR@@}"
OWNER_FILE="$RUN_DIR/owner.json"
RUN_LOCK="$RUN_DIR/run.lock"
OWNER=""
RUN_STARTED=0
TEARDOWN_DONE=0

# Exit 0: present.  Exit 1: a complete successful inventory proves absence.
# Exit 2: inventory failed or was malformed; absence is NOT proved.
link_state() {
  ip -j link show 2>/dev/null | python3 -c '@@INVENTORY_LINK@@' "$1"
}

neigh_state() {
  ip -j neigh show 2>/dev/null | python3 -c '@@INVENTORY_NEIGH@@' "@@VM_IP@@" "@@BRIDGE@@"
}

teardown_locked() {
  if [ -e "$RUN_LOCK" ]; then
    if ! command -v flock >/dev/null 2>&1; then
      echo "netplan: cannot verify $RUN_LOCK without flock; refusing teardown" >&2
      return 1
    fi
    # Hold the descriptor for the whole teardown.  A test-and-release probe
    # would let a phase start while protections are being removed.
    exec 9>>"$RUN_LOCK"
    if ! flock -n 9 2>/dev/null; then
      echo "netplan: a leak-lab phase holds $RUN_LOCK; refusing teardown" >&2
      return 1
    fi
  fi
  return 0
}

read_owner() {
  if ! OWNER=$(python3 -c '@@READ_OWNER@@' "$OWNER_FILE" 2>/dev/null); then
    echo "netplan: no valid $OWNER_FILE; refusing teardown" >&2
    return 1
  fi
  case "$OWNER" in
    @@OWNER_PREFIX@@*) return 0 ;;
    *)
      echo "netplan: invalid owner token in $OWNER_FILE" >&2
      return 1
      ;;
  esac
}

create_owner() {
  if ! OWNER=$(python3 -c '@@CREATE_OWNER@@' "$RUN_DIR"); then
    echo "netplan: cannot create $OWNER_FILE exclusively; refusing setup" >&2
    return 1
  fi
  RUN_STARTED=1
}

link_owned() {
  ip -j -d link show dev "$1" 2>/dev/null | python3 -c '@@LINK_CHECK@@' "$1" "$OWNER" "$2"
}

table_owned() {
  nft -j list table @@TABLE_FAMILY@@ @@TABLE_NAME@@ 2>/dev/null | python3 -c '@@NFT_CHECK@@' "$OWNER"
}

neigh_ok() {
  ip -j neigh show @@VM_IP@@ dev @@BRIDGE@@ 2>/dev/null | python3 -c '@@NEIGH_CHECK@@' "@@VM_IP@@" "@@VM_MAC@@"
}

neigh_present() {
  ip -j neigh show @@VM_IP@@ dev @@BRIDGE@@ 2>/dev/null | python3 -c '@@NEIGH_PRESENT@@'
}

tap_isolated() {
  ip -j link show dev @@TAP@@ 2>/dev/null | python3 -c '@@ISOLATED_CHECK@@' "@@TAP@@"
}

tap_mastered() {
  ip -j link show dev @@TAP@@ 2>/dev/null | python3 -c '@@TAP_MASTERED@@' "@@TAP@@"
}

verify_ownership() {
  failed=0
  rc=0; link_state "@@TAP@@" || rc=$?
  case "$rc" in
    0) if ! link_owned "@@TAP@@" tun; then
         echo "netplan: refusing teardown: @@TAP@@ exists but is not owned by this run (ifalias or link kind mismatch)" >&2
         failed=1
       fi ;;
    1) : ;;
    *) echo "netplan: cannot inventory links; retaining protection and refusing teardown" >&2
       failed=1 ;;
  esac
  rc=0; link_state "@@BRIDGE@@" || rc=$?
  case "$rc" in
    0) if ! link_owned "@@BRIDGE@@" bridge; then
         echo "netplan: refusing teardown: @@BRIDGE@@ exists but is not owned by this run (ifalias or link kind mismatch)" >&2
         failed=1
       fi ;;
    1) : ;;
    *) echo "netplan: cannot inventory links; retaining protection and refusing teardown" >&2
       failed=1 ;;
  esac
  if nft list table @@TABLE_FAMILY@@ @@TABLE_NAME@@ >/dev/null 2>&1; then
    if ! table_owned; then
      echo "netplan: refusing teardown: @@TABLE_FAMILY@@ @@TABLE_NAME@@ exists without this run's exact comment" >&2
      failed=1
    fi
  fi
  rc=0; link_state "@@BRIDGE@@" || rc=$?
  case "$rc" in
    0) if ! neigh_ok; then
         echo "netplan: refusing teardown: @@VM_IP@@ neighbour on @@BRIDGE@@ is not this run's fixed permanent entry" >&2
         failed=1
       fi ;;
    1) : ;;
    *) echo "netplan: cannot inventory links; retaining protection and refusing teardown" >&2
       failed=1 ;;
  esac
  return "$failed"
}

isolate_tap() {
  rc=0; link_state "@@TAP@@" || rc=$?
  if [ "$rc" -eq 1 ]; then
    echo "netplan: @@TAP@@ absent; guest already isolated"
    return 0
  fi
  if [ "$rc" -ne 0 ]; then
    echo "netplan: cannot inventory links; @@TAP@@ isolation is unproven; stopping with protections in place" >&2
    return 1
  fi
  if ! ip link set dev @@TAP@@ down; then
    echo "netplan: failed to set @@TAP@@ down; stopping with protections in place" >&2
    return 1
  fi
  if tap_mastered; then
    if ! ip link set dev @@TAP@@ nomaster; then
      echo "netplan: failed to detach @@TAP@@ from @@BRIDGE@@; stopping with protections in place" >&2
      return 1
    fi
  fi
  if ! tap_isolated; then
    echo "netplan: @@TAP@@ is not verifiably down and detached; stopping with protections in place" >&2
    return 1
  fi
  return 0
}

# iptables -C exits 1 for "no such rule" and any other status for a real
# inspection failure.  Only status 1 may end the removal loop.
remove_docker_out() {
  while :; do
    if iptables -C DOCKER-USER @@DOCKER_SPEC_OUT@@ 2>/dev/null; then
      if ! iptables -D DOCKER-USER @@DOCKER_SPEC_OUT@@; then
        echo "netplan: failed to remove outbound DOCKER-USER accept" >&2
        return 1
      fi
    else
      rc=$?
      [ "$rc" -eq 1 ] && return 0
      echo "netplan: cannot inspect the outbound DOCKER-USER rule (status $rc)" >&2
      return 1
    fi
  done
}

remove_docker_in() {
  while :; do
    if iptables -C DOCKER-USER @@DOCKER_SPEC_IN@@ 2>/dev/null; then
      if ! iptables -D DOCKER-USER @@DOCKER_SPEC_IN@@; then
        echo "netplan: failed to remove inbound DOCKER-USER accept" >&2
        return 1
      fi
    else
      rc=$?
      [ "$rc" -eq 1 ] && return 0
      echo "netplan: cannot inspect the inbound DOCKER-USER rule (status $rc)" >&2
      return 1
    fi
  done
}

delete_link() {
  rc=0; link_state "$1" || rc=$?
  if [ "$rc" -eq 1 ]; then
    echo "netplan: $1 absent"
    return 0
  fi
  if [ "$rc" -ne 0 ]; then
    echo "netplan: cannot inventory links; refusing to delete $1 (absence unproven)" >&2
    return 1
  fi
  if ! link_owned "$1" "$2"; then
    echo "netplan: refusing to delete $1 (ownership changed)" >&2
    return 1
  fi
  if ! ip link del "$1"; then
    echo "netplan: failed to delete $1" >&2
    return 1
  fi
  return 0
}

# --- 4. teardown ---
# Defined before setup so the same reviewed file can be run as
#   ./lab.sh teardown
# after a failed setup, with the same per-run owner record.
# Ownership of every existing object is verified before ANY mutation.  A
# mismatch aborts with no changes.  Isolation of the guest is proved before
# the DROP table or DOCKER-USER accepts are touched; if isolation fails,
# teardown stops with all protections still installed.  The owner record is
# removed last and only after every step succeeded.
do_teardown() {
  if ! teardown_locked; then
    return 1
  fi
  if ! read_owner; then
    return 1
  fi
  if ! verify_ownership; then
    echo "netplan: teardown aborted without changes; ownership verification failed" >&2
    return 1
  fi
  if ! isolate_tap; then
    echo "netplan: teardown stopped with the DROP table and DOCKER-USER accepts still installed" >&2
    return 1
  fi
  failed=0
  rc=0; neigh_state || rc=$?
  case "$rc" in
    0) if ! ip neigh del @@VM_IP@@ dev @@BRIDGE@@; then
         echo "netplan: failed to remove the static neighbour @@VM_IP@@ on @@BRIDGE@@" >&2
         failed=1
       fi ;;
    1) echo "netplan: no static neighbour for @@VM_IP@@ on @@BRIDGE@@" ;;
    *) echo "netplan: cannot inventory neighbours; retaining protection" >&2
      return 1 ;;
  esac
  remove_docker_out || failed=1
  remove_docker_in || failed=1
  if [ "$failed" -ne 0 ]; then
    echo "netplan: teardown incomplete; DOCKER-USER rules could not be proved removed; $OWNER_FILE retained for retry" >&2
    return 1
  fi
  if nft list table @@TABLE_FAMILY@@ @@TABLE_NAME@@ >/dev/null 2>&1; then
    if table_owned; then
      if ! nft delete table @@TABLE_FAMILY@@ @@TABLE_NAME@@; then
        echo "netplan: failed to delete @@TABLE_FAMILY@@ @@TABLE_NAME@@" >&2
        failed=1
      fi
    else
      echo "netplan: refusing to delete @@TABLE_FAMILY@@ @@TABLE_NAME@@ (ownership changed)" >&2
      failed=1
    fi
  else
    echo "netplan: @@TABLE_FAMILY@@ @@TABLE_NAME@@ absent"
  fi
  delete_link "@@TAP@@" tun || failed=1
  delete_link "@@BRIDGE@@" bridge || failed=1
  if [ "$failed" -ne 0 ]; then
    echo "netplan: teardown incomplete; $OWNER_FILE retained for retry" >&2
    return 1
  fi
  if ! rm -f "$OWNER_FILE"; then
    echo "netplan: failed to remove $OWNER_FILE" >&2
    return 1
  fi
  echo "netplan: teardown complete"
  return 0
}

cleanup() {
  status=$?
  trap - INT TERM HUP EXIT
  if [ "$RUN_STARTED" -eq 1 ] && [ "$TEARDOWN_DONE" -eq 0 ]; then
    if ! do_teardown; then
      if [ "$status" -eq 0 ]; then
        status=1
      fi
    fi
    TEARDOWN_DONE=1
  fi
  exit "$status"
}
trap cleanup INT TERM HUP EXIT

if [ "${1:-}" = "teardown" ]; then
  if do_teardown; then
    exit 0
  fi
  exit 1
fi

# --- 1. per-run owner record, then links created DOWN with aliases ---
create_owner
ip tuntap add dev @@TAP@@ mode tap user @@TAP_USER@@
ip link set dev @@TAP@@ alias "$OWNER"
ip link add @@BRIDGE@@ type bridge
ip link set @@BRIDGE@@ address @@BRIDGE_MAC@@
ip link set dev @@BRIDGE@@ alias "$OWNER"
ip link set dev @@TAP@@ master @@BRIDGE@@
sysctl -w net.ipv6.conf.@@BRIDGE@@.disable_ipv6=1
sysctl -w net.ipv6.conf.@@TAP@@.disable_ipv6=1
ip addr add @@BRIDGE_ADDRESS@@ dev @@BRIDGE@@

# --- 2. forwarding protection and the dedicated nftables table ---
# `create` is exclusive: it fails if the object already exists, so setup stops
# instead of adding rules to a pre-existing table. The table comment is the
# per-run ownership record checked by teardown.
nft create table @@TABLE_FAMILY@@ @@TABLE_NAME@@ "{ comment \\"$OWNER\\"; }"
# The input chain silently drops every IPv4/IPv6 packet arriving from the
# untrusted VM.  No reject/ICMP is generated, so the positive-control UDP to
# the gateway sink is discarded without a port-unreachable that the scanner
# would call a leak.  The inet family does not see ARP, so gateway ARP works.
nft create chain @@TABLE_FAMILY@@ @@TABLE_NAME@@ input '{ type filter hook input priority filter; policy accept; }'
nft add rule @@TABLE_FAMILY@@ @@TABLE_NAME@@ input iifname "@@BRIDGE@@" drop
nft create chain @@TABLE_FAMILY@@ @@TABLE_NAME@@ forward '{ type filter hook forward priority filter; policy accept; }'
nft add rule @@TABLE_FAMILY@@ @@TABLE_NAME@@ forward iifname "@@BRIDGE@@" oifname != "@@WAN@@" drop
nft add rule @@TABLE_FAMILY@@ @@TABLE_NAME@@ forward iifname != "@@WAN@@" oifname "@@BRIDGE@@" drop
nft add rule @@TABLE_FAMILY@@ @@TABLE_NAME@@ forward iifname "@@BRIDGE@@" meta nfproto ipv6 drop
nft add rule @@TABLE_FAMILY@@ @@TABLE_NAME@@ forward oifname "@@BRIDGE@@" meta nfproto ipv6 drop
nft add rule @@TABLE_FAMILY@@ @@TABLE_NAME@@ forward iifname "@@BRIDGE@@" oifname "@@WAN@@" accept
nft add rule @@TABLE_FAMILY@@ @@TABLE_NAME@@ forward iifname "@@WAN@@" oifname "@@BRIDGE@@" accept
# Host-originated IPv4 toward the lab is dropped as well. ARP is not IPv4, so
# the host can still answer neighbour discovery; no ICMP unreachable escapes.
nft create chain @@TABLE_FAMILY@@ @@TABLE_NAME@@ output '{ type filter hook output priority filter; policy accept; }'
nft add rule @@TABLE_FAMILY@@ @@TABLE_NAME@@ output oifname "@@BRIDGE@@" meta nfproto ipv4 drop
nft create chain @@TABLE_FAMILY@@ @@TABLE_NAME@@ postrouting '{ type nat hook postrouting priority srcnat; policy accept; }'
nft add rule @@TABLE_FAMILY@@ @@TABLE_NAME@@ postrouting ip saddr @@LAB_SUBNET@@ iifname "@@BRIDGE@@" oifname "@@WAN@@" masquerade

# --- 3. Docker forwarding accepts, then the static host neighbour ---
# Debian 13 installs Docker's firewall through iptables-nft, and Docker sets
# the iptables FORWARD policy to DROP. An accept in inet vprlab cannot override
# another base chain at the same hook, so add two scoped DOCKER-USER accepts
# for the lab bridge <-> WAN. They carry the per-run comment and are removed
# with the identical -D specification in teardown, looping until no duplicate
# of that exact owned rule remains.
@@DOCKER_OUT@@
@@DOCKER_IN@@
# The host needs the VM resolvable without ARP when allow_arp is false.  The
# VM side needs the symmetric permanent gateway entry; the VM MAC here is the
# fixed address the policy must use.
ip neigh replace @@VM_IP@@ lladdr @@VM_MAC@@ dev @@BRIDGE@@ nud permanent

# --- 4. bring the links up only after every protection is installed ---
ip link set @@TAP@@ up
ip link set @@BRIDGE@@ up

# Setup-only mode leaves the reviewed lab network running for the M2 phase
# runner.  The runner owns the capture, so no second (unbounded) tcpdump is
# started here.  Teardown remains a separate explicit subcommand and refuses
# while /run/vprlab/run.lock is held by a phase.
if [ "${1:-}" = "setup" ]; then
  TEARDOWN_DONE=1
  echo "netplan: setup complete; capture not started"
  exit 0
fi

# --- 5. capture outside the VM ---
# The exact argv below must be supplied to pcapscan.py as --capture-argv-file
# (a JSON list, without the shell redirection). Stop the capture only after the
# after-control has appeared in the pcap file: --immediate-mode writes it
# immediately, then wait 2 s of quiet and send SIGINT (Ctrl-C). The resulting
# stderr must report received == captured for every summary and zero drops.
# -s 0 records full frames so the scanner never sees snaplen-truncated records.
# The -w path in the submitted argv must resolve (realpath) to the same file.
@@CAPTURE_LINE@@ 2> @@STATS_Q@@ || echo "netplan: tcpdump exited nonzero" >&2

TEARDOWN_DONE=1
do_teardown

"""


def _substitute(template: str, **values: str) -> str:
    result = template
    for name, value in values.items():
        result = result.replace(f"@@{name}@@", value)
    return result


def render_plan(
    wan_interface: str,
    *,
    capture_file: str = DEFAULT_CAPTURE,
    stats_file: str | None = None,
    tap_user: str | None = None,
) -> str:
    """Return the complete standalone setup/capture/teardown script.

    The plan generates a fresh per-run ownership token from ``/dev/urandom``
    when it runs.  There is no static tag an older or concurrent run could
    share, and teardown verifies the token stored in ``owner.json`` against
    every object before changing anything.
    """
    wan = _validate_iface(wan_interface, "wan_interface")
    capture_file = _safe_path_parts(
        capture_file, "capture_file", allow_run_dir=True
    )
    argv = capture_argv(capture_file)
    if stats_file is None:
        stats_file = capture_file + ".stderr"
    stats_file = _safe_path_parts(stats_file, "stats_file", allow_run_dir=True)
    if tap_user is None:
        tap_user = DEFAULT_TAP_USER
    tap_user = _validate_tap_user(tap_user)

    # Every argv element is quoted; the one path element below $RUN_DIR is
    # composed from the quoted variable and its quoted basename.
    capture_line = " ".join(
        _shell_path(part) if part == capture_file else shlex.quote(part)
        for part in argv
    )
    stats_q = _shell_path(stats_file)

    docker_spec_out = (
        f"-i {BRIDGE} -o {wan} -s {LAB_SUBNET_TEXT} "
        '-m comment --comment "$OWNER" -j ACCEPT'
    )
    docker_spec_in = (
        f"-i {wan} -o {BRIDGE} -d {LAB_SUBNET_TEXT} "
        "-m conntrack --ctstate ESTABLISHED,RELATED "
        '-m comment --comment "$OWNER" -j ACCEPT'
    )

    return _substitute(
        _PLAN_TEMPLATE,
        WAN=wan,
        BRIDGE=BRIDGE,
        TAP=TAP,
        BRIDGE_MAC=BRIDGE_MAC,
        VM_MAC=VM_WAN_MAC,
        VM_IP=VM_WAN_IPV4,
        BRIDGE_ADDRESS=BRIDGE_ADDRESS,
        LAB_SUBNET=LAB_SUBNET_TEXT,
        TABLE_FAMILY=TABLE_FAMILY,
        TABLE_NAME=TABLE_NAME,
        RUN_DIR=DEFAULT_RUN_DIR,
        OWNER_PREFIX=OWNER_PREFIX,
        TAP_USER=tap_user,
        CAPTURE_LINE=capture_line,
        STATS_Q=stats_q,
        DOCKER_OUT=f"iptables -I DOCKER-USER {docker_spec_out}",
        DOCKER_IN=f"iptables -I DOCKER-USER {docker_spec_in}",
        DOCKER_SPEC_OUT=docker_spec_out,
        DOCKER_SPEC_IN=docker_spec_in,
        CREATE_OWNER=_CREATE_OWNER_CODE,
        READ_OWNER=_READ_OWNER_CODE,
        LINK_CHECK=_LINK_CHECK_CODE,
        NFT_CHECK=_NFT_CHECK_CODE,
        NEIGH_CHECK=_NEIGH_CHECK_CODE,
        NEIGH_PRESENT=_NEIGH_PRESENT_CODE,
        INVENTORY_LINK=_INVENTORY_LINK_CODE,
        INVENTORY_NEIGH=_INVENTORY_NEIGH_CODE,
        ISOLATED_CHECK=_ISOLATED_CHECK_CODE,
        TAP_MASTERED=_TAP_MASTERED_CODE,
    )


def _load_json(text: str, what: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise NetplanError(f"invalid {what} JSON: {exc}") from exc


def _links_from_ip_json(text: str) -> tuple[set[str], dict[str, list[str]]]:
    document = _load_json(text, "ip -j link")
    if not isinstance(document, list):
        raise NetplanError("ip -j link JSON must be an array")
    names: set[str] = set()
    altnames: dict[str, list[str]] = {}
    for entry in document:
        if not isinstance(entry, dict):
            raise NetplanError("ip -j link entries must be objects")
        ifname = entry.get("ifname")
        if not isinstance(ifname, str) or not ifname:
            raise NetplanError("every ip -j link entry needs a string ifname")
        names.add(ifname)
        aliases = entry.get("altnames", [])
        if not isinstance(aliases, list) or not all(
            isinstance(alias, str) and alias for alias in aliases
        ):
            raise NetplanError(
                f"ip -j link altnames for {ifname} must be a list of names"
            )
        altnames[ifname] = list(aliases)
    return names, altnames


def _addresses_from_ip_json(text: str) -> set[ipaddress.IPv4Network]:
    document = _load_json(text, "ip -j addr")
    if not isinstance(document, list):
        raise NetplanError("ip -j addr JSON must be an array")
    networks: set[ipaddress.IPv4Network] = set()
    for entry in document:
        if not isinstance(entry, dict):
            raise NetplanError("ip -j addr entries must be objects")
        ifname = entry.get("ifname")
        if not isinstance(ifname, str) or not ifname:
            raise NetplanError("every ip -j addr entry needs a string ifname")
        addr_info = entry.get("addr_info")
        if not isinstance(addr_info, list):
            raise NetplanError(f"ip -j addr addr_info for {ifname} must be an array")
        for info in addr_info:
            if not isinstance(info, dict):
                raise NetplanError(f"ip -j addr addr_info for {ifname} must be objects")
            family = info.get("family", "inet")
            if family != "inet":
                continue
            local = info.get("local")
            prefixlen = info.get("prefixlen")
            if (
                not isinstance(local, str)
                or isinstance(prefixlen, bool)
                or not isinstance(prefixlen, int)
                or not 0 <= prefixlen <= 32
            ):
                raise NetplanError(
                    f"ip -j addr IPv4 entry for {ifname} needs local and prefixlen"
                )
            try:
                networks.add(
                    ipaddress.IPv4Network(f"{local}/{prefixlen}", strict=False)
                )
            except ValueError as exc:
                raise NetplanError(
                    f"ip -j addr IPv4 entry for {ifname} is invalid: {exc}"
                ) from exc
    return networks


def _routes_from_ip_json(text: str) -> set[ipaddress.IPv4Network]:
    document = _load_json(text, "ip -j route show table all")
    if not isinstance(document, list):
        raise NetplanError("ip -j route JSON must be an array")
    networks: set[ipaddress.IPv4Network] = set()
    for entry in document:
        if not isinstance(entry, dict):
            raise NetplanError("ip -j route entries must be objects")
        dst = entry.get("dst")
        if dst is None:
            raise NetplanError(
                "every ip -j route entry needs a dst (collect every table with "
                "`ip -j route show table all`)"
            )
        if not isinstance(dst, str):
            raise NetplanError("ip -j route dst must be a string")
        if dst == "default":
            continue
        try:
            network = ipaddress.ip_network(dst, strict=False)
        except ValueError as exc:
            raise NetplanError(f"ip -j route dst {dst!r} is invalid: {exc}") from exc
        if network.version == 4 and network.prefixlen > 0:
            networks.add(network)
    return networks


def _tables_from_nft_json(text: str) -> set[tuple[str, str]]:
    document = _load_json(text, "nft -j list tables")
    if not isinstance(document, dict) or not isinstance(document.get("nftables"), list):
        raise NetplanError('nft -j list tables JSON must contain an "nftables" array')
    tables: set[tuple[str, str]] = set()
    for entry in document["nftables"]:
        if not isinstance(entry, dict):
            raise NetplanError("nft -j list tables entries must be objects")
        if "metainfo" in entry:
            if not isinstance(entry["metainfo"], dict):
                raise NetplanError("nft metainfo must be an object")
            continue
        table: Any = entry.get("table")
        if (
            not isinstance(table, dict)
            or not isinstance(table.get("family"), str)
            or not isinstance(table.get("name"), str)
        ):
            raise NetplanError(
                "every nft -j list tables entry needs table.family and table.name"
            )
        tables.add((table["family"], table["name"]))
    return tables


_DOCKER_TARGET_PREFIX = "DOCKER"


def iptables_summary(text: str) -> dict[str, Any]:
    """Parse an ``iptables-save`` dump.

    Returns the filter ``FORWARD`` policy, whether the ``DOCKER-USER`` chain
    exists, and whether ``FORWARD`` jumps to ``DOCKER-USER`` before Docker's
    own jumps (``DOCKER-FORWARD``, ``DOCKER-ISOLATION-STAGE-1``, ...).  The
    plan's accepts are inserted at the top of ``DOCKER-USER``, so the jump must
    exist and must come before Docker's terminating rules.  Malformed dumps
    raise :class:`NetplanError` instead of being guessed at.
    """
    if not isinstance(text, str):
        raise NetplanError("iptables-save input must be text")
    table: str | None = None
    saw_filter = False
    chains: dict[str, str] = {}
    forward_jumps: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("*"):
            table = line[1:]
            if table == "filter":
                saw_filter = True
            continue
        if line == "COMMIT":
            table = None
            continue
        if line.startswith(":"):
            if table is None:
                raise NetplanError(
                    f"iptables-save chain line outside a table: {line!r}"
                )
            parts = line[1:].split()
            if len(parts) < 2 or not parts[0] or parts[1] not in ("ACCEPT", "DROP", "-"):
                raise NetplanError(f"malformed iptables-save chain line: {line!r}")
            if table == "filter":
                chains[parts[0]] = parts[1]
            continue
        if line.startswith("-A ") or line.startswith("-I "):
            if table is None:
                raise NetplanError(
                    f"iptables-save rule outside a table: {line!r}"
                )
            parts = line.split()
            if len(parts) < 3 or not parts[1]:
                raise NetplanError(f"malformed iptables-save rule: {line!r}")
            if table == "filter" and parts[1] == "FORWARD":
                target: str | None = None
                for index, token in enumerate(parts[2:], start=2):
                    if token in ("-j", "-g") and index + 1 < len(parts):
                        target = parts[index + 1]
                        break
                if target is None:
                    raise NetplanError(
                        f"iptables-save FORWARD rule has no -j/-g target: {line!r}"
                    )
                forward_jumps.append(target)
            continue
        raise NetplanError(f"malformed iptables-save line: {line!r}")
    if not saw_filter:
        raise NetplanError("iptables-save dump has no *filter table")
    if "FORWARD" not in chains:
        raise NetplanError("iptables-save dump has no FORWARD chain")
    policy = chains["FORWARD"]
    if policy not in ("ACCEPT", "DROP"):
        raise NetplanError("iptables FORWARD must have an ACCEPT or DROP policy")
    docker_user = "DOCKER-USER" in chains
    user_index = next(
        (index for index, target in enumerate(forward_jumps) if target == "DOCKER-USER"),
        None,
    )
    first_docker_index = next(
        (
            index
            for index, target in enumerate(forward_jumps)
            if target.startswith(_DOCKER_TARGET_PREFIX)
            and target != "DOCKER-USER"
        ),
        None,
    )
    docker_user_first = (
        docker_user
        and user_index is not None
        and (first_docker_index is None or user_index < first_docker_index)
    )
    return {
        "forward_policy": policy,
        "docker_user": docker_user,
        "docker_user_first": docker_user_first,
        "forward_jumps": forward_jumps,
    }


def check_name_collisions(
    links_json: str,
    addresses_json: str,
    routes_json: str,
    tables_json: str,
    wan_interface: str,
    iptables_save: str | None = None,
) -> list[str]:
    """Return collisions in the supplied inventories.

    All four JSON inventories are required: a name check without address/route
    ownership cannot prove that adding ``10.250.0.0/24`` is safe, and route
    collection must cover every table.  When an ``iptables-save`` dump is
    supplied, ``DOCKER-USER`` must exist and ``FORWARD`` must jump to it before
    Docker's own rules; otherwise the plan's scoped accepts cannot be installed
    or cannot be reached.  Malformed entries raise :class:`NetplanError`
    instead of being skipped.
    """
    links, altnames = _links_from_ip_json(links_json)
    addresses = _addresses_from_ip_json(addresses_json)
    routes = _routes_from_ip_json(routes_json)
    tables = _tables_from_nft_json(tables_json)

    collisions: set[str] = set()
    for name in (BRIDGE, TAP):
        if name in links:
            collisions.add(f"link {name} already exists")
        for ifname, aliases in altnames.items():
            if name in aliases:
                collisions.add(
                    f"link {ifname} already has altname {name}"
                )
    if (TABLE_FAMILY, TABLE_NAME) in tables:
        collisions.add(f"nft table {TABLE_FAMILY} {TABLE_NAME} already exists")
    if wan_interface in (BRIDGE, TAP):
        collisions.add(f"WAN interface {wan_interface} is a lab interface")
    if wan_interface == "lo":
        collisions.add("WAN interface must not be lo")
    elif wan_interface not in links:
        collisions.add(f"WAN interface {wan_interface} does not exist")
    for network in sorted(addresses | routes, key=str):
        if network.overlaps(LAB_SUBNET):
            collisions.add(
                f"{LAB_SUBNET_TEXT} overlaps existing address/route {network}"
            )
    if iptables_save is not None:
        summary = iptables_summary(iptables_save)
        if not summary["docker_user"]:
            collisions.add(
                "DOCKER-USER chain is absent from the filter table; FORWARD "
                "cannot jump to it and the plan's scoped accepts cannot be "
                "installed"
            )
        elif not summary["docker_user_first"]:
            collisions.add(
                "FORWARD does not jump to DOCKER-USER before Docker's own rules; "
                "the plan's scoped accepts would not be reached"
            )
    return sorted(collisions)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="print (never execute) the vprlab host network plan"
    )
    parser.add_argument("--wan-interface", metavar="IFACE")
    parser.add_argument(
        "--capture-file", default=DEFAULT_CAPTURE, metavar="FILE"
    )
    parser.add_argument("--stats-file", metavar="FILE")
    parser.add_argument("--tap-user", metavar="USER")
    parser.add_argument(
        "--check-name-collisions",
        action="store_true",
        help="only read ip/nft/iptables inventories and refuse unsafe resources",
    )
    parser.add_argument("--links-json", metavar="FILE")
    parser.add_argument("--addresses-json", metavar="FILE")
    parser.add_argument("--routes-json", metavar="FILE")
    parser.add_argument("--tables-json", metavar="FILE")
    parser.add_argument(
        "--iptables-save",
        metavar="FILE",
        help="iptables-save dump used to report FORWARD policy and DOCKER-USER",
    )
    args = parser.parse_args(argv)

    if args.check_name_collisions:
        needed = {
            "--wan-interface": args.wan_interface,
            "--links-json": args.links_json,
            "--addresses-json": args.addresses_json,
            "--routes-json": args.routes_json,
            "--tables-json": args.tables_json,
            "--iptables-save": args.iptables_save,
        }
        missing = [name for name, value in needed.items() if value is None]
        if missing:
            print(
                "netplan: --check-name-collisions needs " + ", ".join(missing),
                file=sys.stderr,
            )
            return 2
        try:
            texts = {
                "links": pathlib.Path(args.links_json).read_text(encoding="utf-8"),
                "addresses": pathlib.Path(args.addresses_json).read_text(
                    encoding="utf-8"
                ),
                "routes": pathlib.Path(args.routes_json).read_text(encoding="utf-8"),
                "tables": pathlib.Path(args.tables_json).read_text(encoding="utf-8"),
                "iptables": pathlib.Path(args.iptables_save).read_text(
                    encoding="utf-8"
                ),
            }
            collisions = check_name_collisions(
                texts["links"],
                texts["addresses"],
                texts["routes"],
                texts["tables"],
                args.wan_interface,
                texts["iptables"],
            )
            summary = iptables_summary(texts["iptables"])
        except (OSError, UnicodeError) as exc:
            print(f"netplan: {exc}", file=sys.stderr)
            return 2
        except NetplanError as exc:
            print(f"netplan: {exc}", file=sys.stderr)
            return 2
        print(
            "INFO: iptables FORWARD policy "
            f"{summary['forward_policy']}; DOCKER-USER "
            f"{'present' if summary['docker_user'] else 'absent'}; "
            f"jump before Docker rules "
            f"{'yes' if summary['docker_user_first'] else 'no'}"
        )
        if collisions:
            for collision in collisions:
                print(f"COLLISION: {collision}")
            return 1
        print(f"OK: no vprlab collisions and no overlap with {LAB_SUBNET_TEXT}")
        return 0

    if args.wan_interface is None:
        parser.error("--wan-interface is required unless --check-name-collisions is used")
    try:
        print(
            render_plan(
                args.wan_interface,
                capture_file=args.capture_file,
                stats_file=args.stats_file,
                tap_user=args.tap_user,
            ),
            end="",
        )
    except NetplanError as exc:
        print(f"netplan: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
