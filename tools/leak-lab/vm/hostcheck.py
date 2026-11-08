#!/usr/bin/env python3
"""Host-side preflight checks shared by the vprlab VM runners.

Only parsers and process inspection live here.  The callers execute ``ip``,
``nft`` and tcpdump as root; nothing in this module runs by itself.
"""

from __future__ import annotations

import pathlib
import re
from typing import Any

from guest import (
    BRIDGE,
    GATEWAY_IPV4,
    GATEWAY_MAC,
    TAP,
    VM_IPV4,
    VM_MAC,
)

OWNER_TAG = "vprlab-leak-lab-m1"
REQUIRED_CHAINS = ("input", "forward", "output", "postrouting")


class Refusal(RuntimeError):
    """A precondition is not satisfied; the phase must not start."""


def _decode(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [entry for entry in value if isinstance(entry, str)]
    return []


def find_qemu_processes(
    proc_root: pathlib.Path = pathlib.Path("/proc"), *, self_pid: int | None = None
) -> list[dict[str, Any]]:
    """Return other QEMU system processes.

    An unreadable ``/proc/<pid>/cmdline`` fails closed: a hidden process could
    own the overlay or the tap, so the runner must not start a second guest.
    """
    root = pathlib.Path(proc_root)
    found: list[dict[str, Any]] = []
    for entry in root.iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if self_pid is not None and pid == self_pid:
            continue
        try:
            raw = (entry / "cmdline").read_bytes()
        except FileNotFoundError:
            continue
        except PermissionError as exc:
            raise Refusal(f"cannot inspect process {pid}") from exc
        except OSError as exc:
            raise Refusal(f"cannot inspect process {pid}: {exc.__class__.__name__}") from exc
        if b"qemu-system" not in raw:
            continue
        arguments = [part.decode("utf-8", "replace") for part in raw.split(b"\0") if part]
        found.append({"pid": pid, "argv": arguments})
    return found


def refuse_if_qemu_running(
    proc_root: pathlib.Path = pathlib.Path("/proc"), *, self_pid: int | None = None
) -> None:
    running = find_qemu_processes(proc_root, self_pid=self_pid)
    if running:
        pids = ", ".join(str(entry["pid"]) for entry in running)
        raise Refusal(f"another QEMU process is running: {pids}")


def _links(document: object) -> dict[str, dict[str, Any]]:
    if not isinstance(document, list):
        raise Refusal("ip -j link output must be a JSON array")
    links: dict[str, dict[str, Any]] = {}
    for entry in document:
        if not isinstance(entry, dict) or not isinstance(entry.get("ifname"), str):
            raise Refusal("ip -j link entry without a string ifname")
        links[entry["ifname"]] = entry
    return links


def _link_kind(entry: dict[str, Any]) -> str:
    linkinfo = entry.get("linkinfo")
    if not isinstance(linkinfo, dict):
        return ""
    kind = linkinfo.get("info_kind")
    return kind if isinstance(kind, str) else ""


def verify_host_network(
    links_document: object,
    table_document: object,
    neighbor_document: object,
    *,
    addresses_document: object = None,
    bridge: str = BRIDGE,
    tap: str = TAP,
    gateway_ipv4: str = GATEWAY_IPV4,
    gateway_mac: str = GATEWAY_MAC,
    vm_ipv4: str = VM_IPV4,
    vm_mac: str = VM_MAC,
    owner_tag: str = OWNER_TAG,
) -> list[str]:
    """Return every problem with the already-created host lab network."""
    problems: list[str] = []
    links = _links(links_document)

    bridge_entry = links.get(bridge)
    if bridge_entry is None:
        problems.append(f"bridge {bridge} is missing")
    else:
        if _link_kind(bridge_entry) != "bridge":
            problems.append(f"{bridge} is not a bridge")
        if str(bridge_entry.get("address", "")).lower() != gateway_mac:
            problems.append(f"{bridge} MAC is not the fixed gateway MAC {gateway_mac}")
        if "UP" not in _decode(bridge_entry.get("flags")):
            problems.append(f"{bridge} is not up")
        addresses = None
        if addresses_document is not None:
            if not isinstance(addresses_document, list):
                problems.append("ip -j addr output must be a JSON array")
            else:
                for entry in addresses_document:
                    if (
                        isinstance(entry, dict)
                        and entry.get("ifname") == bridge
                        and isinstance(entry.get("addr_info"), list)
                    ):
                        addresses = entry["addr_info"]
                        break
        if addresses is None:
            addresses = bridge_entry.get("addr_info")
        if not isinstance(addresses, list):
            problems.append(f"{bridge} has no addr_info array")
        else:
            expected = {
                "family": "inet",
                "local": gateway_ipv4,
                "prefixlen": 24,
            }
            if not any(
                isinstance(address, dict)
                and all(address.get(key) == value for key, value in expected.items())
                for address in addresses
            ):
                problems.append(f"{bridge} does not carry {gateway_ipv4}/24")

    tap_entry = links.get(tap)
    if tap_entry is None:
        problems.append(f"tap {tap} is missing")
    else:
        if _link_kind(tap_entry) != "tap":
            problems.append(f"{tap} is not a tap")
        if "UP" not in _decode(tap_entry.get("flags")):
            problems.append(f"{tap} is not up")
        master = tap_entry.get("master")
        if master is not None and master != bridge:
            problems.append(f"{tap} is attached to {master}, not {bridge}")

    if not isinstance(table_document, dict) or not isinstance(
        table_document.get("nftables"), list
    ):
        problems.append('nft -j list table inet vprlab has no "nftables" array')
    else:
        table = None
        chains: set[str] = set()
        for entry in table_document["nftables"]:
            if not isinstance(entry, dict):
                problems.append("nft output contains a non-object entry")
                continue
            if "table" in entry:
                candidate = entry["table"]
                if (
                    isinstance(candidate, dict)
                    and candidate.get("family") == "inet"
                    and candidate.get("name") == "vprlab"
                ):
                    table = candidate
            if "chain" in entry:
                candidate = entry["chain"]
                if (
                    isinstance(candidate, dict)
                    and candidate.get("family") == "inet"
                    and candidate.get("table") == "vprlab"
                    and isinstance(candidate.get("name"), str)
                ):
                    chains.add(candidate["name"])
        if table is None:
            problems.append("nft table inet vprlab is missing")
        elif table.get("comment") != owner_tag:
            problems.append("nft table inet vprlab does not carry the ownership tag")
        for chain in REQUIRED_CHAINS:
            if chain not in chains:
                problems.append(f"nft table inet vprlab is missing chain {chain}")

    if not isinstance(neighbor_document, list):
        problems.append("ip -j neigh output must be a JSON array")
    else:
        permanent = None
        for entry in neighbor_document:
            if (
                isinstance(entry, dict)
                and entry.get("dst") == vm_ipv4
                and entry.get("dev") == bridge
            ):
                permanent = entry
                break
        if permanent is None:
            problems.append(
                f"host static neighbor for {vm_ipv4} on {bridge} is missing"
            )
        else:
            if str(permanent.get("lladdr", "")).lower() != vm_mac:
                problems.append(
                    f"host neighbor for {vm_ipv4} does not use the VM MAC {vm_mac}"
                )
            if "PERMANENT" not in _decode(permanent.get("state")):
                problems.append(f"host neighbor for {vm_ipv4} is not PERMANENT")
    return problems


def validate_tap_owner(link_entry: dict[str, Any], user: str) -> str:
    """Best-effort tap-owner check; netplan.py's ``--tap-user`` sets this."""
    # iproute2 does not expose the tun owner in ``ip -j``.  The runner instead
    # relies on the tap being created with netplan.py --tap-user and on QEMU's
    # own failure if it cannot attach.  This helper exists so a future iproute2
    # field can be wired in without changing callers.
    return user


def parse_ipv4(text: str) -> str:
    if not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", text):
        raise Refusal(f"not a dotted-quad IPv4 literal: {text!r}")
    return text
