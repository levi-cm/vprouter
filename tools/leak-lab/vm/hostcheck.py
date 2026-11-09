#!/usr/bin/env python3
"""Host-side preflight checks shared by the vprlab VM runners.

Only parsers and process inspection live here.  The callers execute ``ip``,
``nft`` and tcpdump as root; nothing in this module runs by itself.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import stat
from typing import Any

from guest import (
    BRIDGE,
    CLIENT_BRIDGE,
    CLIENT_BRIDGE_MAC,
    CLIENT_GATEWAY_IPV4,
    GATEWAY_IPV4,
    GATEWAY_MAC,
    QEMU_USER,
    TAP,
    VM_IPV4,
    VM_MAC,
)

OWNER_IFALIAS_PREFIX = "vprlab-owned:"
OWNER_FILE = pathlib.Path("/run/vprlab/owner.json")
REQUIRED_CHAINS = ("input", "forward", "output", "postrouting")
_OWNER_TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")


def expected_owner_tag(owner_token: str) -> str:
    """Return the exact per-run tag used by every M1-owned object."""
    if not isinstance(owner_token, str) or _OWNER_TOKEN_RE.fullmatch(owner_token) is None:
        raise Refusal("owner token must be 32 lowercase hex characters")
    return OWNER_IFALIAS_PREFIX + owner_token


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


def _is_tap(entry: dict[str, Any]) -> bool:
    """Accept the real iproute2 shape for a persistent tap.

    Linux represents a tap as link kind ``tun`` with
    ``linkinfo.info_data.type == "tap"``.  Some tooling prints ``info_kind:
    "tap"``; accept that too, but never a plain tun device.
    """
    linkinfo = entry.get("linkinfo")
    if not isinstance(linkinfo, dict):
        return False
    if linkinfo.get("info_kind") == "tap":
        return True
    if linkinfo.get("info_kind") != "tun":
        return False
    info_data = linkinfo.get("info_data")
    return isinstance(info_data, dict) and info_data.get("type") == "tap"


def load_owner_token(
    path: str | pathlib.Path = OWNER_FILE, *, require_root: bool | None = None
) -> str:
    """Read the M1 ownership document: schema 1 and a 32-hex token."""
    path = pathlib.Path(path)
    try:
        info = path.lstat()
    except OSError as exc:
        raise Refusal("owner document is missing") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise Refusal("owner document must be a regular file")
    if info.st_mode & 0o077:
        raise Refusal("owner document must be mode 0600")
    if require_root is None:
        require_root = os.geteuid() == 0
    if require_root and info.st_uid != 0:
        raise Refusal("owner document must be owned by root")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            document = json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise Refusal("owner document is not valid JSON") from exc
    if not isinstance(document, dict):
        raise Refusal("owner document must be an object")
    if document.get("schema") != 1:
        raise Refusal("owner document schema must be 1")
    token = document.get("token")
    if not isinstance(token, str) or _OWNER_TOKEN_RE.fullmatch(token) is None:
        raise Refusal("owner document token must be 32 lowercase hex characters")
    return token


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
    owner_token: str | None = None,
    owner_tag: str | None = None,
    tap_user: str | None = QEMU_USER,
) -> list[str]:
    """Return every problem with the already-created host lab network.

    ``owner_token`` is the per-run token from ``owner.json``.  The nft table
    comment and both ifaliases must be exactly ``vprlab-owned:<token>``; the
    old fixed ``vprlab-leak-lab-m1`` tag authorizes nothing.
    """
    problems: list[str] = []
    links = _links(links_document)

    if owner_token is not None:
        expected_ifalias = expected_owner_tag(owner_token)
    elif owner_tag is not None:
        expected_ifalias = owner_tag
    else:
        expected_ifalias = None
        problems.append("owner token is required to verify the lab network")

    table_tag = expected_ifalias

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
        if (
            expected_ifalias is not None
            and bridge_entry.get("ifalias") != expected_ifalias
        ):
            problems.append(f"{bridge} does not carry the lab ownership ifalias")
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
        if not _is_tap(tap_entry):
            problems.append(f"{tap} is not a tap")
        if "UP" not in _decode(tap_entry.get("flags")):
            problems.append(f"{tap} is not up")
        if (
            expected_ifalias is not None
            and tap_entry.get("ifalias") != expected_ifalias
        ):
            problems.append(f"{tap} does not carry the lab ownership ifalias")
        if tap_entry.get("master") != bridge:
            problems.append(f"{tap} is not enslaved to {bridge}")
        if tap_user is not None:
            problem = validate_tap_owner(tap_entry, tap_user)
            if problem is not None:
                problems.append(problem)

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
        elif table.get("comment") != table_tag:
            problems.append("nft table inet vprlab does not carry the per-run ownership tag")
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


def verify_client_network(
    links_document: object,
    neighbor_document: object,
    *,
    addresses_document: object = None,
    owner_token: str | None = None,
    owner_tag: str | None = None,
    bridge: str = CLIENT_BRIDGE,
    bridge_mac: str = CLIENT_BRIDGE_MAC,
    gateway_ipv4: str = CLIENT_GATEWAY_IPV4,
    taps: dict[str, tuple[str, str]] | None = None,
    tap_user: str | None = QEMU_USER,
) -> list[str]:
    """Return every problem with the M3 client bridge and its taps.

    ``taps`` maps a tap name to ``(client IPv4, client MAC)`` and is required
    for every client that is expected to be configured.  The same exact
    ownership rule as the router bridge applies: every existing object must
    carry ``vprlab-owned:<token>``.
    """
    problems: list[str] = []
    links = _links(links_document)
    if owner_token is not None:
        expected_ifalias = expected_owner_tag(owner_token)
    elif owner_tag is not None:
        expected_ifalias = owner_tag
    else:
        expected_ifalias = None
        problems.append("owner token is required to verify the client network")
    taps = dict(taps or {})

    bridge_entry = links.get(bridge)
    if bridge_entry is None:
        problems.append(f"client bridge {bridge} is missing")
    else:
        if _link_kind(bridge_entry) != "bridge":
            problems.append(f"{bridge} is not a bridge")
        if str(bridge_entry.get("address", "")).lower() != bridge_mac:
            problems.append(
                f"{bridge} MAC is not the fixed client gateway MAC {bridge_mac}"
            )
        if "UP" not in _decode(bridge_entry.get("flags")):
            problems.append(f"{bridge} is not up")
        if (
            expected_ifalias is not None
            and bridge_entry.get("ifalias") != expected_ifalias
        ):
            problems.append(f"{bridge} does not carry the lab ownership ifalias")
        addresses = None
        if addresses_document is not None and isinstance(addresses_document, list):
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
        expected = {"family": "inet", "local": gateway_ipv4, "prefixlen": 24}
        if not isinstance(addresses, list) or not any(
            isinstance(address, dict)
            and all(address.get(key) == value for key, value in expected.items())
            for address in addresses
        ):
            problems.append(f"{bridge} does not carry {gateway_ipv4}/24")

    for tap, (client_ipv4, client_mac) in sorted(taps.items()):
        tap_entry = links.get(tap)
        if tap_entry is None:
            problems.append(f"client tap {tap} is missing")
            continue
        if not _is_tap(tap_entry):
            problems.append(f"{tap} is not a tap")
        if "UP" not in _decode(tap_entry.get("flags")):
            problems.append(f"{tap} is not up")
        if (
            expected_ifalias is not None
            and tap_entry.get("ifalias") != expected_ifalias
        ):
            problems.append(f"{tap} does not carry the lab ownership ifalias")
        if tap_entry.get("master") != bridge:
            problems.append(f"{tap} is not enslaved to {bridge}")
        if tap_user is not None:
            problem = validate_tap_owner(tap_entry, tap_user)
            if problem is not None:
                problems.append(problem)
        if not isinstance(neighbor_document, list):
            problems.append("ip -j neigh output must be a JSON array")
            break
        permanent = next(
            (
                entry
                for entry in neighbor_document
                if isinstance(entry, dict)
                and entry.get("dst") == client_ipv4
                and entry.get("dev") == bridge
            ),
            None,
        )
        if permanent is None:
            problems.append(
                f"host static neighbor for {client_ipv4} on {bridge} is missing"
            )
        else:
            if str(permanent.get("lladdr", "")).lower() != client_mac:
                problems.append(
                    f"host neighbor for {client_ipv4} does not use the client MAC "
                    f"{client_mac}"
                )
            if "PERMANENT" not in _decode(permanent.get("state")):
                problems.append(
                    f"host neighbor for {client_ipv4} is not PERMANENT"
                )
    return problems


def validate_tap_owner(link_entry: dict[str, Any], user: str) -> str | None:
    """Return a problem when iproute2 reports a different tun owner.

    ``ip -d -j link`` exposes ``linkinfo.info_data.user``/``group`` for tun
    devices.  Older iproute2 versions omit them; absence is not proof of a
    wrong owner (QEMU still fails to attach a tap it does not own), so only a
    present, different owner is refused.
    """
    linkinfo = link_entry.get("linkinfo")
    if not isinstance(linkinfo, dict):
        return None
    info_data = linkinfo.get("info_data")
    if not isinstance(info_data, dict):
        return None
    owner = info_data.get("user")
    if owner is None:
        return None
    if isinstance(owner, int) and not isinstance(owner, bool):
        import pwd

        try:
            owner = pwd.getpwuid(owner).pw_name
        except KeyError:
            return f"tap owner uid {owner} has no account"
    if owner != user:
        return f"tap owner is {owner!r}, not {user!r}"
    return None


def parse_ipv4(text: str) -> str:
    if not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", text):
        raise Refusal(f"not a dotted-quad IPv4 literal: {text!r}")
    return text
