#!/usr/bin/env python3
"""Generate positive-control nonces and the exact in-VM command that emits them.

This module only generates text.  It never opens a socket and never executes the
command it prints.  The controller runs the printed lines inside the router VM;
SO_BINDTODEVICE makes the UDP marker leave through the raw WAN device instead of
the tunnel, so the host-side tap capture must see it.

A nonce is single-use.  ``--pair`` generates a fresh before/after pair for one
phase, and ``--nonce`` (kept only for deterministic reproduction) refuses a
nonce listed in ``--used-nonces``.  The tool never reads or writes the pcap.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import secrets
import sys

import policy as policy_mod

_DEVICE_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,15}$")


def generate_nonce(used: set[str] | None = None) -> str:
    """Return 16 random bytes as 32 lowercase hex characters, not in ``used``."""
    used = used or set()
    while True:
        nonce = secrets.token_hex(16)
        if nonce not in used:
            return nonce


def generate_pair(used: set[str] | None = None) -> dict[str, str]:
    """Return distinct fresh ``before``/``after`` nonces for one phase."""
    used = set(used or ())
    before = generate_nonce(used)
    used.add(before)
    after = generate_nonce(used)
    return {"before": before, "after": after}


def load_used_nonces(path: str | pathlib.Path) -> set[str]:
    """Read one nonce per line from ``path``; reject malformed entries."""
    try:
        text = pathlib.Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise policy_mod.PolicyError(f"cannot read used-nonces file: {exc}") from exc
    used: set[str] = set()
    for number, line in enumerate(text.splitlines(), start=1):
        entry = line.strip()
        if not entry:
            continue
        if not policy_mod.is_control_nonce(entry):
            raise policy_mod.PolicyError(
                f"used-nonces line {number} is not 32 lowercase hex characters"
            )
        used.add(entry)
    return used


def _validate_device(device: str) -> str:
    if not isinstance(device, str) or _DEVICE_RE.fullmatch(device) is None:
        raise policy_mod.PolicyError(
            "WAN device must be 1..15 characters of [A-Za-z0-9_.:@-]"
        )
    return device


def build_command(
    nonce: str,
    device: str,
    vm_ipv4: str,
    sink_ipv4: str,
    sink_udp_port: int,
) -> str:
    """Return one copy-pasteable shell command for execution inside the VM."""
    if not policy_mod.is_control_nonce(nonce):
        raise policy_mod.PolicyError(
            "nonce must be exactly 32 lowercase hexadecimal characters"
        )
    device = _validate_device(device)
    if not policy_mod.is_ipv4_literal(vm_ipv4):
        raise policy_mod.PolicyError("vm_ipv4 must be a dotted-quad IPv4 literal")
    if not policy_mod.is_ipv4_literal(sink_ipv4):
        raise policy_mod.PolicyError("sink_ipv4 must be a dotted-quad IPv4 literal")
    if (
        isinstance(sink_udp_port, bool)
        or not isinstance(sink_udp_port, int)
        or not 1 <= sink_udp_port <= 65535
    ):
        raise policy_mod.PolicyError("sink_udp_port must be in 1..65535")

    payload = policy_mod.CONTROL_PREFIX.decode("ascii") + nonce
    code = (
        "import socket;"
        f'd=b"{payload}";'
        "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
        's.setsockopt(socket.SOL_SOCKET,getattr(socket,"SO_BINDTODEVICE",25),'
        f'b"{device}\\x00");'
        f's.bind(("{vm_ipv4}",0));'
        f's.sendto(d,("{sink_ipv4}",{sink_udp_port}));'
        "print(d.decode())"
    )
    return "python3 -c '" + code + "'"


def _entry(nonce: str, command: str) -> dict[str, str]:
    return {
        "nonce": nonce,
        "command": command,
        "payload_hex": (
            policy_mod.CONTROL_PREFIX + nonce.encode("ascii")
        ).hex(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="generate vprlab positive-control nonce(s) and in-VM commands"
    )
    parser.add_argument("--policy", metavar="POLICY.json")
    parser.add_argument("--device", required=True, metavar="IFACE")
    parser.add_argument(
        "--nonce",
        metavar="HEX",
        help="single explicit nonce for reproduction; requires --used-nonces",
    )
    parser.add_argument(
        "--used-nonces",
        metavar="FILE",
        help="file of nonces already used; a reused nonce is refused",
    )
    parser.add_argument(
        "--pair",
        action="store_true",
        help="generate a fresh distinct before/after pair for one phase",
    )
    parser.add_argument("--vm-ip", metavar="IPV4")
    parser.add_argument("--sink-ip", metavar="IPV4")
    parser.add_argument("--sink-port", type=int, metavar="PORT")
    parser.add_argument(
        "--json",
        action="store_true",
        help="print canonical JSON instead of the human-readable form",
    )
    args = parser.parse_args(argv)

    if args.pair and args.nonce is not None:
        print("control: --pair and --nonce are mutually exclusive", file=sys.stderr)
        return 2
    if args.nonce is not None and args.used_nonces is None:
        print(
            "control: --nonce requires --used-nonces; nonces are single-use",
            file=sys.stderr,
        )
        return 2

    used: set[str] = set()
    if args.used_nonces is not None:
        try:
            used = load_used_nonces(args.used_nonces)
        except policy_mod.PolicyError as exc:
            print(f"control: {exc}", file=sys.stderr)
            return 2

    vm_ipv4 = args.vm_ip
    sink_ipv4 = args.sink_ip
    sink_port = args.sink_port
    if args.policy is not None:
        try:
            loaded = policy_mod.load_policy(args.policy)
        except (OSError, policy_mod.PolicyError) as exc:
            print(f"control: policy: {exc}", file=sys.stderr)
            return 2
        vm_ipv4 = vm_ipv4 or loaded.vm_wan_ipv4
        sink_ipv4 = sink_ipv4 or loaded.positive_control.sink_ipv4
        sink_port = sink_port or loaded.positive_control.sink_udp_port
    missing = [
        name
        for name, value in (
            ("--vm-ip", vm_ipv4),
            ("--sink-ip", sink_ipv4),
            ("--sink-port", sink_port),
        )
        if value is None
    ]
    if missing:
        parser.error("missing " + ", ".join(missing) + " (or provide --policy)")

    try:
        if args.pair:
            pair = generate_pair(used)
            entries = {
                role: _entry(
                    nonce,
                    build_command(nonce, args.device, vm_ipv4, sink_ipv4, sink_port),
                )
                for role, nonce in pair.items()
            }
            if args.json:
                sys.stdout.write(
                    json.dumps(
                        entries,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n"
                )
            else:
                for role in ("before", "after"):
                    print(f"# {role}-control")
                    print(entries[role]["command"])
                    print(f"nonce: {entries[role]['nonce']}")
            return 0

        if args.nonce is not None:
            if args.nonce in used:
                print(
                    "control: refusing a nonce that already appears in "
                    "--used-nonces",
                    file=sys.stderr,
                )
                return 2
            nonce = args.nonce
        else:
            nonce = generate_nonce(used)
        command = build_command(nonce, args.device, vm_ipv4, sink_ipv4, sink_port)
    except policy_mod.PolicyError as exc:
        print(f"control: {exc}", file=sys.stderr)
        return 2

    if args.json:
        sys.stdout.write(
            json.dumps(
                _entry(nonce, command),
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )
    else:
        print(command)
        print(f"nonce: {nonce}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
