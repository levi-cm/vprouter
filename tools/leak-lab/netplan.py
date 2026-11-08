#!/usr/bin/env python3
"""Plan-only generator for the isolated vprlab host network.

This program never executes a command, never changes a link and never touches
nftables or iptables.  It prints the exact privileged commands as a standalone
``#!/bin/sh`` script for a human to review and run, plus a
``--check-name-collisions`` preflight that only reads JSON produced by
``ip -j link``, ``ip -j addr``, ``ip -j route show table all``,
``nft -j list tables`` and an ``iptables-save`` dump.

The generated nftables table is ``inet vprlab``.  Nothing here resets the
ruleset, edits a table other than Docker's ``DOCKER-USER`` chain (where it
inserts and later removes only its own exactly tagged rules), or deletes an
object it did not create: the table and the two links carry a per-run ownership
tag, are created exclusively, and teardown verifies exact structured ownership
before deleting anything.  The scoped DOCKER-USER accepts are required because
Docker on Debian 13 installs an iptables-nft FORWARD policy of DROP that an
accept in another nft base chain cannot override.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import pathlib
import re
import shlex
import sys
from typing import Any

BRIDGE = "vprlab0"
TAP = "vprlab-tap0"
TABLE_FAMILY = "inet"
TABLE_NAME = "vprlab"
BRIDGE_ADDRESS = "10.250.0.1/24"
LAB_SUBNET_TEXT = "10.250.0.0/24"
LAB_SUBNET = ipaddress.IPv4Network(LAB_SUBNET_TEXT)
OWNER_TAG = "vprlab-leak-lab-m1"
IPTABLES_COMMENT = "vprlab-owned"
DEFAULT_CAPTURE = "vprlab-capture.pcap"

_IFACE_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,15}$")
_TAP_USER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}$")


class NetplanError(ValueError):
    """A requested name or a supplied inspection document is invalid."""


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
    return user


def capture_argv(capture_file: str = DEFAULT_CAPTURE) -> list[str]:
    """Return the exact tcpdump argv the plan prints.

    There is deliberately no BPF filter expression, no ``-s`` short snaplen
    and no packet-count limit: every frame the tap sees must be written.
    """
    if not isinstance(capture_file, str) or not capture_file or "\n" in capture_file:
        raise NetplanError("capture_file must be a non-empty single-line path")
    return [
        "tcpdump",
        "-i",
        TAP,
        "-nn",
        "-U",
        "--immediate-mode",
        "-s",
        "0",
        "-w",
        capture_file,
    ]


def check_capture_argv(argv: Any) -> str | None:
    """Compare a submitted argv with :func:`capture_argv`.

    Returns ``None`` when it matches exactly except for the ``-w`` path,
    ``capture_argv_invalid`` when the value is not a non-empty list of
    non-empty strings, and ``capture_argv_mismatch`` for any other difference.
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
    return None


def render_plan(
    wan_interface: str,
    *,
    capture_file: str = DEFAULT_CAPTURE,
    stats_file: str | None = None,
    tap_user: str | None = None,
    owner_tag: str | None = None,
) -> str:
    """Return the complete standalone setup/capture/teardown script.

    ``owner_tag`` defaults to the fixed ``vprlab-leak-lab-m1`` string shared
    with the M2 runner.  It may be overridden for tests; teardown always
    compares the exact string, never a substring.
    """
    wan = _validate_iface(wan_interface, "wan_interface")
    argv = capture_argv(capture_file)
    if stats_file is None:
        stats_file = capture_file + ".stderr"
    if not isinstance(stats_file, str) or not stats_file or "\n" in stats_file:
        raise NetplanError("stats_file must be a non-empty single-line path")
    if owner_tag is None:
        owner_tag = OWNER_TAG
    if (
        not isinstance(owner_tag, str)
        or re.fullmatch(r"vprlab-leak-lab-m1(?:-[a-z0-9]+)?", owner_tag) is None
    ):
        raise NetplanError("owner_tag must be vprlab-leak-lab-m1 with an optional suffix")
    tap_user_option = ""
    if tap_user is not None:
        tap_user_option = " user " + _validate_tap_user(tap_user)

    capture_line = " ".join(shlex.quote(part) for part in argv)
    stats_q = shlex.quote(stats_file)

    docker_out = (
        f"iptables -I DOCKER-USER -i {BRIDGE} -o {wan} "
        f"-s {LAB_SUBNET_TEXT} -m comment --comment {IPTABLES_COMMENT} -j ACCEPT"
    )
    docker_in = (
        f"iptables -I DOCKER-USER -i {wan} -o {BRIDGE} "
        f"-d {LAB_SUBNET_TEXT} -m conntrack --ctstate ESTABLISHED,RELATED "
        f"-m comment --comment {IPTABLES_COMMENT} -j ACCEPT"
    )
    docker_out_del = docker_out.replace("-I DOCKER-USER", "-D DOCKER-USER", 1)
    docker_in_del = docker_in.replace("-I DOCKER-USER", "-D DOCKER-USER", 1)

    nft_owner_check = f"""python3 -c '
import json, sys
try:
    doc = json.load(sys.stdin)
except Exception:
    sys.exit(1)
tables = [e["table"] for e in doc.get("nftables", []) if isinstance(e, dict) and "table" in e]
ok = len(tables) == 1 and tables[0].get("family") == "inet" and tables[0].get("name") == "vprlab" and tables[0].get("comment") == "{owner_tag}"
sys.exit(0 if ok else 1)
'"""

    link_owner_check = f"""python3 -c '
import json, sys
name = sys.argv[1]
try:
    doc = json.load(sys.stdin)
except Exception:
    sys.exit(1)
if not isinstance(doc, list):
    sys.exit(1)
entries = [e for e in doc if isinstance(e, dict) and e.get("ifname") == name]
ok = len(entries) == 1 and (entries[0].get("alias") == "{owner_tag}" or "{owner_tag}" in entries[0].get("altnames", []))
sys.exit(0 if ok else 1)
'"""

    return f"""#!/bin/sh
set -eu
# vprlab host network setup plan
# PLAN ONLY: netplan.py never executes anything. This file is a standalone
# script for review and deliberate execution as root on the debdev host.
# not for interactive paste: `set -eu` would stay active in your shell. The
# capture point is the host tap, outside the router VM.
#
# Host default/WAN interface: {wan}
#
# Required preflight before running any command below. Generate the inventories
# locally, then run the collision check; setup must abort unless it prints OK:
#   ip -j link > links.json
#   ip -j addr > addresses.json
#   ip -j route show table all > routes.json
#   nft -j list tables > tables.json
#   iptables-save > iptables.txt
#   python3 -B tools/leak-lab/netplan.py --check-name-collisions \\
#     --wan-interface {wan} \\
#     --links-json links.json --addresses-json addresses.json \\
#     --routes-json routes.json --tables-json tables.json \\
#     --iptables-save iptables.txt
# The preflight rejects an existing {LAB_SUBNET_TEXT} address or route in ANY
# routing table, an existing bridge/tap name or altname, an existing inet
# vprlab table, a non-existent or loopback WAN interface, malformed inventory
# JSON, and a Docker FORWARD-DROP host whose DOCKER-USER chain is absent.
#
# Required kernel setting (this plan never changes it):
#   sysctl -n net.ipv4.ip_forward
# must print 1. If it prints 0, the plan requires 1 for the phase; enable it
# and restore exactly this value after teardown:
#   sysctl -w net.ipv4.ip_forward=1
#   ... run the phase ...
#   sysctl -w net.ipv4.ip_forward=0

# --- 4. teardown ---
# Defined before setup so the same reviewed file can be run as
#   ./lab.sh teardown
# after a failed setup, with the same ownership tag.
# Every step is independent: absent objects are reported, failures do not
# stop the remaining steps, and ownership is checked against exact
# structured fields (table comment, link ifname + alias/altname).
do_teardown() {{
# Every step is independent: absent objects are reported, failures do not stop
# the remaining steps, and ownership is checked against exact structured
# fields (table comment, link ifname + alias/altname), never a substring.
#
# 4a. isolate the guest FIRST, while the DROP rules are still installed.
if ip link show dev {TAP} >/dev/null 2>&1; then
  ip link set dev {TAP} down || echo "netplan: failed to set {TAP} down" >&2
  ip link set dev {TAP} nomaster || echo "netplan: failed to detach {TAP} from {BRIDGE}" >&2
else
  echo "netplan: {TAP} absent; guest already isolated"
fi

# 4b. remove the optional static neighbour and the exact DOCKER-USER rules.
ip neigh del 10.250.0.2 dev {BRIDGE} 2>/dev/null || echo "netplan: no static neighbour for 10.250.0.2 on {BRIDGE}"
{docker_out_del} || echo "netplan: outbound DOCKER-USER accept not present"
{docker_in_del} || echo "netplan: inbound DOCKER-USER accept not present"

# 4c. delete the nft table only when its exact table comment is ours.
if nft list table {TABLE_FAMILY} {TABLE_NAME} >/dev/null 2>&1; then
  if nft -j list table {TABLE_FAMILY} {TABLE_NAME} 2>/dev/null | {nft_owner_check}
  then
    nft delete table {TABLE_FAMILY} {TABLE_NAME} || echo "netplan: failed to delete {TABLE_FAMILY} {TABLE_NAME}" >&2
  else
    echo "netplan: refusing to delete {TABLE_FAMILY} {TABLE_NAME} (exact ownership comment absent)" >&2
  fi
else
  echo "netplan: {TABLE_FAMILY} {TABLE_NAME} absent"
fi

# 4d. delete the links only when the exact ifname and alias/altname are ours.
if ip -j -d link show dev {TAP} >/dev/null 2>&1; then
  if ip -j -d link show dev {TAP} 2>/dev/null | {link_owner_check} "{TAP}"
  then
    ip link del {TAP} || echo "netplan: failed to delete {TAP}" >&2
  else
    echo "netplan: refusing to delete {TAP} (exact ownership alias absent)" >&2
  fi
else
  echo "netplan: {TAP} absent"
fi
if ip -j -d link show dev {BRIDGE} >/dev/null 2>&1; then
  if ip -j -d link show dev {BRIDGE} 2>/dev/null | {link_owner_check} "{BRIDGE}"
  then
    ip link del {BRIDGE} || echo "netplan: failed to delete {BRIDGE}" >&2
  else
    echo "netplan: refusing to delete {BRIDGE} (exact ownership alias absent)" >&2
  fi
else
  echo "netplan: {BRIDGE} absent"
fi
}}
if [ "${{1:-}}" = "teardown" ]; then
  do_teardown
  exit 0
fi


# --- 1. isolated bridge and tap (the bridge has no physical ports) ---
ip tuntap add dev {TAP} mode tap{tap_user_option}
ip link set dev {TAP} alias "{owner_tag}"
ip link add {BRIDGE} type bridge
ip link set dev {BRIDGE} alias "{owner_tag}"
ip link set {TAP} master {BRIDGE}
sysctl -w net.ipv6.conf.{BRIDGE}.disable_ipv6=1
sysctl -w net.ipv6.conf.{TAP}.disable_ipv6=1
ip link set {TAP} up
ip link set {BRIDGE} up
ip addr add {BRIDGE_ADDRESS} dev {BRIDGE}

# --- 2. forwarding protection and the dedicated nftables table ---
# Debian 13 installs Docker's firewall through iptables-nft, and Docker sets
# the iptables FORWARD policy to DROP. An accept in inet vprlab cannot override
# another base chain at the same hook, so add two scoped DOCKER-USER accepts
# for the lab bridge <-> WAN. They carry an exact comment tag and are removed
# with the identical -D specification in teardown.
{docker_out}
{docker_in}
# `create` is exclusive: it fails if the object already exists, so setup stops
# instead of adding rules to a pre-existing table. The table comment is the
# ownership record checked by teardown.
nft create table {TABLE_FAMILY} {TABLE_NAME} '{{ comment "{owner_tag}"; }}'
# The input chain silently drops every IPv4/IPv6 packet arriving from the
# untrusted VM.  No reject/ICMP is generated, so the positive-control UDP to
# the gateway sink is discarded without a port-unreachable that the scanner
# would call a leak.  The inet family does not see ARP, so gateway ARP works.
nft create chain {TABLE_FAMILY} {TABLE_NAME} input '{{ type filter hook input priority filter; policy accept; }}'
nft add rule {TABLE_FAMILY} {TABLE_NAME} input iifname "{BRIDGE}" drop
nft create chain {TABLE_FAMILY} {TABLE_NAME} forward '{{ type filter hook forward priority filter; policy accept; }}'
nft add rule {TABLE_FAMILY} {TABLE_NAME} forward iifname "{BRIDGE}" oifname != "{wan}" drop
nft add rule {TABLE_FAMILY} {TABLE_NAME} forward iifname != "{wan}" oifname "{BRIDGE}" drop
nft add rule {TABLE_FAMILY} {TABLE_NAME} forward iifname "{BRIDGE}" meta nfproto ipv6 drop
nft add rule {TABLE_FAMILY} {TABLE_NAME} forward oifname "{BRIDGE}" meta nfproto ipv6 drop
nft add rule {TABLE_FAMILY} {TABLE_NAME} forward iifname "{BRIDGE}" oifname "{wan}" accept
nft add rule {TABLE_FAMILY} {TABLE_NAME} forward iifname "{wan}" oifname "{BRIDGE}" accept
# Host-originated IPv4 toward the lab is dropped as well. ARP is not IPv4, so
# the host can still answer neighbour discovery; no ICMP unreachable escapes.
nft create chain {TABLE_FAMILY} {TABLE_NAME} output '{{ type filter hook output priority filter; policy accept; }}'
nft add rule {TABLE_FAMILY} {TABLE_NAME} output oifname "{BRIDGE}" meta nfproto ipv4 drop
nft create chain {TABLE_FAMILY} {TABLE_NAME} postrouting '{{ type nat hook postrouting priority srcnat; policy accept; }}'
nft add rule {TABLE_FAMILY} {TABLE_NAME} postrouting ip saddr {LAB_SUBNET_TEXT} iifname "{BRIDGE}" oifname "{wan}" masquerade
# Static neighbours (only needed when the policy uses allow_arp: false). The
# VM side needs the symmetric permanent gateway entry. With allow_arp: true
# the gateway_mac policy field and the ARP rules do the same job.
#   ip neigh replace 10.250.0.2 lladdr <vm-mac> dev {BRIDGE} nud permanent

# --- 3. capture outside the VM ---
# The exact argv below must be supplied to pcapscan.py as --capture-argv-file
# (a JSON list, without the shell redirection). Stop the capture only after the
# after-control has appeared in the pcap file: --immediate-mode writes it
# immediately, then wait 2 s of quiet and send SIGINT (Ctrl-C). The resulting
# stderr must report received == captured and zero drops.
# -s 0 records full frames so the scanner never sees snaplen-truncated records.
{capture_line} 2> {stats_q} || echo "netplan: tcpdump exited nonzero" >&2

do_teardown

"""


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


def iptables_summary(text: str) -> dict[str, Any]:
    """Parse an ``iptables-save`` dump.

    Returns the filter ``FORWARD`` policy and whether the ``DOCKER-USER`` chain
    exists.  Malformed dumps raise :class:`NetplanError` instead of being
    guessed at.
    """
    if not isinstance(text, str):
        raise NetplanError("iptables-save input must be text")
    table: str | None = None
    saw_filter = False
    chains: dict[str, str] = {}
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
            continue
        raise NetplanError(f"malformed iptables-save line: {line!r}")
    if not saw_filter:
        raise NetplanError("iptables-save dump has no *filter table")
    if "FORWARD" not in chains:
        raise NetplanError("iptables-save dump has no FORWARD chain")
    policy = chains["FORWARD"]
    if policy not in ("ACCEPT", "DROP"):
        raise NetplanError("iptables FORWARD must have an ACCEPT or DROP policy")
    return {
        "forward_policy": policy,
        "docker_user": "DOCKER-USER" in chains,
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
    supplied, a Docker-style FORWARD DROP without a ``DOCKER-USER`` chain is a
    collision because the plan's scoped accepts cannot be installed.  Malformed
    entries raise :class:`NetplanError` instead of being skipped.
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
        if summary["forward_policy"] == "DROP" and not summary["docker_user"]:
            collisions.add(
                "iptables FORWARD policy is DROP and the DOCKER-USER chain is "
                "absent; the plan's scoped DOCKER-USER accepts cannot be "
                "installed and Docker would blackhole the lab WAN"
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
        except OSError as exc:
            print(f"netplan: {exc}", file=sys.stderr)
            return 2
        except NetplanError as exc:
            print(f"netplan: {exc}", file=sys.stderr)
            return 2
        print(
            "INFO: iptables FORWARD policy "
            f"{summary['forward_policy']}; DOCKER-USER "
            f"{'present' if summary['docker_user'] else 'absent'}"
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
