#!/usr/bin/env python3
"""Plan-only generator for the isolated vprlab host network.

This program never executes a command, never changes a link and never touches
nftables.  It prints the exact privileged commands for a human to review and run,
plus a ``--check-name-collisions`` preflight that only reads JSON produced by
``ip -j link``, ``ip -j addr``, ``ip -j route`` and ``nft -j list tables``.

The generated nftables table is ``inet vprlab``.  Nothing here resets the
ruleset, edits another table, or deletes an object it did not create: the table
and the two links carry an ownership tag, are created exclusively, and teardown
verifies the tag before deleting anything.
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


def render_plan(
    wan_interface: str,
    *,
    capture_file: str = "vprlab-capture.pcap",
    stats_file: str | None = None,
    tap_user: str | None = None,
) -> str:
    """Return the complete setup/capture/teardown plan as text."""
    wan = _validate_iface(wan_interface, "wan_interface")
    if not isinstance(capture_file, str) or not capture_file or "\n" in capture_file:
        raise NetplanError("capture_file must be a non-empty single-line path")
    if stats_file is None:
        stats_file = capture_file + ".stderr"
    if not isinstance(stats_file, str) or not stats_file or "\n" in stats_file:
        raise NetplanError("stats_file must be a non-empty single-line path")
    tap_user_option = ""
    if tap_user is not None:
        tap_user_option = " user " + _validate_tap_user(tap_user)

    capture_q = shlex.quote(capture_file)
    stats_q = shlex.quote(stats_file)

    return f"""# vprlab host network setup plan
# PLAN ONLY: this tool never executes anything. Review these commands and run
# them manually as root on the debdev host. The capture point is the host tap,
# outside the router VM. Run sections 1-3 for a test phase; run section 4 later.
#
# Host default/WAN interface: {wan}
#
# Required preflight before running any command below. Generate the inventories
# locally, then run the collision check; setup must abort unless it prints OK:
#   ip -j link > links.json
#   ip -j addr > addresses.json
#   ip -j route > routes.json
#   nft -j list tables > tables.json
#   python3 -B tools/leak-lab/netplan.py --check-name-collisions \\
#     --wan-interface {wan} \\
#     --links-json links.json --addresses-json addresses.json \\
#     --routes-json routes.json --tables-json tables.json
# The preflight rejects an existing {LAB_SUBNET_TEXT} address or route, an
# existing bridge/tap name or altname, an existing inet vprlab table, a
# non-existent or loopback WAN interface, and malformed inventory JSON.
#
# Required kernel setting (this plan never changes it):
#   sysctl -n net.ipv4.ip_forward
# must print 1. If it prints 0, the plan requires 1 for the phase; enable it
# and restore exactly this value after teardown:
#   sysctl -w net.ipv4.ip_forward=1
#   ... run the phase ...
#   sysctl -w net.ipv4.ip_forward=0

# --- 1. isolated bridge and tap (the bridge has no physical ports) ---
set -eu
ip tuntap add dev {TAP} mode tap{tap_user_option}
ip link set dev {TAP} alias "{OWNER_TAG}"
ip link add {BRIDGE} type bridge
ip link set dev {BRIDGE} alias "{OWNER_TAG}"
ip link set {TAP} master {BRIDGE}
sysctl -w net.ipv6.conf.{BRIDGE}.disable_ipv6=1
sysctl -w net.ipv6.conf.{TAP}.disable_ipv6=1
ip link set {TAP} up
ip link set {BRIDGE} up
ip addr add {BRIDGE_ADDRESS} dev {BRIDGE}

# --- 2. dedicated nftables table (own table only; never resets or edits others) ---
# `create` is exclusive: it fails if the object already exists, so setup stops
# instead of adding rules to a pre-existing table. The table comment is the
# ownership record checked by teardown.
nft create table {TABLE_FAMILY} {TABLE_NAME} '{{ comment "{OWNER_TAG}"; }}'
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

# --- 3. capture outside the VM ---
# tcpdump writes "N packets captured" and the drop counters to stderr when it
# exits. Stop it with SIGINT (Ctrl-C), then pass both files to pcapscan.py:
#   --pcap <capture> --tcpdump-stats <stats>
# --immediate-mode makes the after-control reach the file before SIGINT; -s 0
# records full frames so the scanner never sees snaplen-truncated records.
tcpdump -i {TAP} -nn -U --immediate-mode -s 0 -w {capture_q} 2> {stats_q}

# --- 4. teardown ---
# Idempotent per object: absent objects are skipped, objects carrying this
# plan's ownership tag are deleted, and same-name objects without the tag are
# left untouched and reported.
if nft list table {TABLE_FAMILY} {TABLE_NAME} >/dev/null 2>&1; then
  if nft list table {TABLE_FAMILY} {TABLE_NAME} | grep -Fq 'comment "{OWNER_TAG}"'; then
    nft delete table {TABLE_FAMILY} {TABLE_NAME}
  else
    echo "netplan: refusing to delete {TABLE_FAMILY} {TABLE_NAME} (ownership tag absent)" >&2
  fi
fi
if ip -d link show dev {TAP} >/dev/null 2>&1; then
  if ip -d link show dev {TAP} | grep -Fq '{OWNER_TAG}'; then
    ip link del {TAP}
  else
    echo "netplan: refusing to delete {TAP} (ownership tag absent)" >&2
  fi
fi
if ip -d link show dev {BRIDGE} >/dev/null 2>&1; then
  if ip -d link show dev {BRIDGE} | grep -Fq '{OWNER_TAG}'; then
    ip link del {BRIDGE}
  else
    echo "netplan: refusing to delete {BRIDGE} (ownership tag absent)" >&2
  fi
fi
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
    document = _load_json(text, "ip -j route")
    if not isinstance(document, list):
        raise NetplanError("ip -j route JSON must be an array")
    networks: set[ipaddress.IPv4Network] = set()
    for entry in document:
        if not isinstance(entry, dict):
            raise NetplanError("ip -j route entries must be objects")
        dst = entry.get("dst")
        if dst is None or dst == "default":
            continue
        if not isinstance(dst, str):
            raise NetplanError("ip -j route dst must be a string")
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


def check_name_collisions(
    links_json: str,
    addresses_json: str,
    routes_json: str,
    tables_json: str,
    wan_interface: str,
) -> list[str]:
    """Return collisions in the four supplied inventories.

    All four inventories are required: a name check without address/route
    ownership cannot prove that adding ``10.250.0.0/24`` is safe.  Malformed
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
    return sorted(collisions)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="print (never execute) the vprlab host network plan"
    )
    parser.add_argument("--wan-interface", metavar="IFACE")
    parser.add_argument(
        "--capture-file", default="vprlab-capture.pcap", metavar="FILE"
    )
    parser.add_argument("--stats-file", metavar="FILE")
    parser.add_argument("--tap-user", metavar="USER")
    parser.add_argument(
        "--check-name-collisions",
        action="store_true",
        help="only read ip/nft JSON files and refuse existing/overlapping resources",
    )
    parser.add_argument("--links-json", metavar="FILE")
    parser.add_argument("--addresses-json", metavar="FILE")
    parser.add_argument("--routes-json", metavar="FILE")
    parser.add_argument("--tables-json", metavar="FILE")
    args = parser.parse_args(argv)

    if args.check_name_collisions:
        needed = {
            "--wan-interface": args.wan_interface,
            "--links-json": args.links_json,
            "--addresses-json": args.addresses_json,
            "--routes-json": args.routes_json,
            "--tables-json": args.tables_json,
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
            }
            collisions = check_name_collisions(
                texts["links"],
                texts["addresses"],
                texts["routes"],
                texts["tables"],
                args.wan_interface,
            )
        except OSError as exc:
            print(f"netplan: {exc}", file=sys.stderr)
            return 2
        except NetplanError as exc:
            print(f"netplan: {exc}", file=sys.stderr)
            return 2
        if collisions:
            for collision in collisions:
                print(f"COLLISION: {collision}")
            return 1
        print("OK: no vprlab collisions and no overlap with 10.250.0.0/24")
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
