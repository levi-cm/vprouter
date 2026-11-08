#!/usr/bin/env python3
"""Strict policy loader for the vprlab external leak monitor.

The hand-written loader in this module is the binding validator.  The sibling
``policy.schema.json`` mirrors the same closed shape for editors and CI tools,
but this loader rejects duplicate JSON keys and cross-field ambiguity that JSON
Schema cannot express.

Run ``python3 policy.py --check POLICY.json`` to validate a policy file.
"""

from __future__ import annotations

import ipaddress
import json
import pathlib
import re
import sys
from dataclasses import dataclass
from typing import Any, Mapping

SCHEMA_VERSION = 1

#: The fixed private subnet of the isolated vprlab bridge.  The host bridge is
#: ``10.250.0.1`` and the router VM is another host address in this subnet.
LAB_SUBNET = ipaddress.IPv4Network("10.250.0.0/24")
LAB_SUBNET_TEXT = "10.250.0.0/24"

#: Address classes that can never be the VM, the gateway or a relay endpoint.
_SPECIAL_NETWORKS = (
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("224.0.0.0/4"),
    ipaddress.IPv4Network("240.0.0.0/4"),
    ipaddress.IPv4Network("169.254.0.0/16"),
)

#: Exact positive-control payload prefix.  The full payload is the prefix
#: followed by 32 lowercase hexadecimal characters (16 random bytes).
CONTROL_PREFIX = b"VPRLEAKCTL1:"
CONTROL_NONCE_HEX_LEN = 32
CONTROL_PAYLOAD_LEN = len(CONTROL_PREFIX) + CONTROL_NONCE_HEX_LEN

#: Labels reserved by the report (ARP pseudo-label and control bookkeeping).
RESERVED_LABELS = frozenset({"arp", "positive-control"})

_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$"
)
_MAC_RE = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$")
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
_NONCE_RE = re.compile(r"^[0-9a-f]{32}$")

_TOP_KEYS = frozenset(
    {
        "schema_version",
        "vm_wan_mac",
        "vm_wan_ipv4",
        "gateway_ipv4",
        "allowed",
        "allow_arp",
        "positive_control",
        "ipv6_allowed",
    }
)
_FLOW_KEYS = frozenset({"proto", "dst_ipv4", "dst_port", "label"})
_CONTROL_KEYS = frozenset({"sink_ipv4", "sink_udp_port"})


class PolicyError(ValueError):
    """A policy document is malformed or ambiguous."""


def is_ipv4_literal(value: Any) -> bool:
    """Return True only for a dotted-quad IPv4 literal without leading zeros."""
    return isinstance(value, str) and _IPV4_RE.fullmatch(value) is not None


def is_control_nonce(value: Any) -> bool:
    """Return True only for exactly 32 lowercase hexadecimal characters."""
    return isinstance(value, str) and _NONCE_RE.fullmatch(value) is not None


def control_payload(nonce: str) -> bytes:
    """Build the exact positive-control payload for a validated nonce."""
    if not is_control_nonce(nonce):
        raise PolicyError("control nonce must be 32 lowercase hexadecimal characters")
    return CONTROL_PREFIX + nonce.encode("ascii")


@dataclass(frozen=True, slots=True)
class Flow:
    """One explicitly allowed WireGuard UDP flow to a relay endpoint."""

    dst_ipv4: str
    dst_port: int
    label: str
    proto: str = "udp"

    def to_dict(self) -> dict[str, Any]:
        return {
            "proto": self.proto,
            "dst_ipv4": self.dst_ipv4,
            "dst_port": self.dst_port,
            "label": self.label,
        }


@dataclass(frozen=True, slots=True)
class PositiveControl:
    """The controller-facing endpoint used to prove the monitor sees packets."""

    sink_ipv4: str
    sink_udp_port: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "sink_ipv4": self.sink_ipv4,
            "sink_udp_port": self.sink_udp_port,
        }


@dataclass(frozen=True, slots=True)
class Policy:
    """Validated, immutable leak-monitor policy."""

    schema_version: int
    vm_wan_mac: str
    vm_wan_ipv4: str
    gateway_ipv4: str
    allowed: tuple[Flow, ...]
    allow_arp: bool
    positive_control: PositiveControl
    ipv6_allowed: bool = False

    def outbound_allowed(self) -> dict[tuple[str, int], str]:
        """Map (destination IPv4, destination UDP port) -> label."""
        return {(flow.dst_ipv4, flow.dst_port): flow.label for flow in self.allowed}

    def inbound_allowed(self) -> dict[tuple[str, int], str]:
        """Map (source IPv4, source UDP port) -> label for return traffic."""
        return {(flow.dst_ipv4, flow.dst_port): flow.label for flow in self.allowed}

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "vm_wan_mac": self.vm_wan_mac,
            "vm_wan_ipv4": self.vm_wan_ipv4,
            "gateway_ipv4": self.gateway_ipv4,
            "allowed": [flow.to_dict() for flow in self.allowed],
            "allow_arp": self.allow_arp,
            "positive_control": self.positive_control.to_dict(),
            "ipv6_allowed": self.ipv6_allowed,
        }


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise PolicyError(f"non-finite JSON number {value!r} is not allowed")


def _require_closed_object(value: Any, keys: frozenset[str], where: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise PolicyError(f"{where} must be a JSON object")
    missing = sorted(keys - set(value))
    extra = sorted(set(value) - keys)
    if missing:
        raise PolicyError(f"{where} is missing required keys: {', '.join(missing)}")
    if extra:
        raise PolicyError(f"{where} has unknown keys: {', '.join(extra)}")
    return value


def _require_port(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PolicyError(f"{where} must be an integer")
    if not 1 <= value <= 65535:
        raise PolicyError(f"{where} must be in 1..65535")
    return value


def _require_ipv4(value: Any, where: str) -> str:
    if not is_ipv4_literal(value):
        raise PolicyError(f"{where} must be a dotted-quad IPv4 literal (no hostname)")
    return value


def _require_unicast_ipv4(value: Any, where: str) -> str:
    """Reject unspecified, loopback, multicast, reserved, broadcast and link-local."""
    address = ipaddress.IPv4Address(_require_ipv4(value, where))
    for network in _SPECIAL_NETWORKS:
        if address in network:
            raise PolicyError(
                f"{where} must be a unicast address; {value} is in reserved {network}"
            )
    return value


def _require_lab_host(value: Any, where: str) -> str:
    address = ipaddress.IPv4Address(_require_unicast_ipv4(value, where))
    if address not in LAB_SUBNET:
        raise PolicyError(f"{where} must be inside the lab subnet {LAB_SUBNET_TEXT}")
    if address in (LAB_SUBNET.network_address, LAB_SUBNET.broadcast_address):
        raise PolicyError(f"{where} must be a usable host address, not {address}")
    return value


def _require_unicast_mac(value: Any) -> str:
    if not isinstance(value, str) or _MAC_RE.fullmatch(value) is None:
        raise PolicyError("vm_wan_mac must be six colon-separated hex octets")
    octets = bytes.fromhex(value.replace(":", ""))
    if octets[0] & 0x01:
        raise PolicyError("vm_wan_mac must be a unicast MAC (multicast bit is set)")
    if not any(octets):
        raise PolicyError("vm_wan_mac must not be the all-zero MAC")
    return value.lower()


def _require_label(value: Any, where: str) -> str:
    if not isinstance(value, str) or _LABEL_RE.fullmatch(value) is None:
        raise PolicyError(
            f"{where} must be 1..64 characters of [a-z0-9-], "
            "starting and ending with [a-z0-9]"
        )
    if value in RESERVED_LABELS:
        raise PolicyError(f"{where} uses reserved label {value!r}")
    return value


def _decode_policy(source: bytes | str | Mapping[str, Any]) -> Mapping[str, Any]:
    if isinstance(source, bytes):
        try:
            text = source.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PolicyError(f"policy is not valid UTF-8: {exc}") from exc
        try:
            value = json.loads(
                text,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_constant,
            )
        except json.JSONDecodeError as exc:
            raise PolicyError(f"policy is not valid JSON: {exc}") from exc
        return value
    if isinstance(source, str):
        try:
            value = json.loads(
                source,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_constant,
            )
        except json.JSONDecodeError as exc:
            raise PolicyError(f"policy is not valid JSON: {exc}") from exc
        return value
    if isinstance(source, Mapping):
        return source
    raise PolicyError("policy source must be bytes, str or a mapping")


def parse_policy(source: bytes | str | Mapping[str, Any]) -> Policy:
    """Parse and fully validate a policy document."""
    raw = _decode_policy(source)
    obj = _require_closed_object(raw, _TOP_KEYS, "policy")

    schema_version = obj["schema_version"]
    if isinstance(schema_version, bool) or not isinstance(schema_version, int):
        raise PolicyError("schema_version must be the integer 1")
    if schema_version != SCHEMA_VERSION:
        raise PolicyError(f"unsupported schema_version {schema_version!r}; expected 1")

    mac = _require_unicast_mac(obj["vm_wan_mac"])

    wan_ipv4 = _require_lab_host(obj["vm_wan_ipv4"], "vm_wan_ipv4")
    gateway_ipv4 = _require_lab_host(obj["gateway_ipv4"], "gateway_ipv4")
    if wan_ipv4 == gateway_ipv4:
        raise PolicyError("vm_wan_ipv4 and gateway_ipv4 must be different hosts")

    allow_arp = obj["allow_arp"]
    if not isinstance(allow_arp, bool):
        raise PolicyError("allow_arp must be a JSON boolean")

    if obj["ipv6_allowed"] is not False:
        raise PolicyError(
            "ipv6_allowed must be the literal JSON value false; IPv6 is never allowed"
        )

    allowed_raw = obj["allowed"]
    if not isinstance(allowed_raw, list):
        raise PolicyError("allowed must be a JSON array")
    if len(allowed_raw) > 256:
        raise PolicyError("allowed must contain at most 256 flows")
    flows: list[Flow] = []
    seen_endpoints: set[tuple[str, int]] = set()
    seen_labels: set[str] = set()
    for index, item in enumerate(allowed_raw):
        where = f"allowed[{index}]"
        flow_obj = _require_closed_object(item, _FLOW_KEYS, where)
        if flow_obj["proto"] != "udp":
            raise PolicyError(f"{where}.proto must be the literal string \"udp\"")
        dst_ipv4 = _require_unicast_ipv4(
            flow_obj["dst_ipv4"], f"{where}.dst_ipv4"
        )
        if ipaddress.IPv4Address(dst_ipv4) in LAB_SUBNET:
            raise PolicyError(
                f"{where}.dst_ipv4 must not be inside the lab subnet {LAB_SUBNET_TEXT}"
            )
        if dst_ipv4 in (wan_ipv4, gateway_ipv4):
            raise PolicyError(
                f"{where}.dst_ipv4 must not be the VM or the gateway address"
            )
        dst_port = _require_port(flow_obj["dst_port"], f"{where}.dst_port")
        label = _require_label(flow_obj["label"], f"{where}.label")
        endpoint = (dst_ipv4, dst_port)
        if endpoint in seen_endpoints:
            raise PolicyError(f"{where} duplicates allowed endpoint {dst_ipv4}:{dst_port}")
        if label in seen_labels:
            raise PolicyError(f"{where}.label {label!r} is duplicated")
        seen_endpoints.add(endpoint)
        seen_labels.add(label)
        flows.append(Flow(dst_ipv4=dst_ipv4, dst_port=dst_port, label=label))

    control_obj = _require_closed_object(
        obj["positive_control"], _CONTROL_KEYS, "positive_control"
    )
    sink_ipv4 = _require_ipv4(control_obj["sink_ipv4"], "positive_control.sink_ipv4")
    sink_port = _require_port(
        control_obj["sink_udp_port"], "positive_control.sink_udp_port"
    )
    if sink_ipv4 != gateway_ipv4:
        raise PolicyError(
            "positive_control.sink_ipv4 must equal gateway_ipv4: the host bridge "
            "silently drops the control datagram"
        )
    if (sink_ipv4, sink_port) in seen_endpoints:
        raise PolicyError(
            "positive_control endpoint must not duplicate an allowed relay flow"
        )

    return Policy(
        schema_version=schema_version,
        vm_wan_mac=mac,
        vm_wan_ipv4=wan_ipv4,
        gateway_ipv4=gateway_ipv4,
        allowed=tuple(flows),
        allow_arp=allow_arp,
        positive_control=PositiveControl(sink_ipv4=sink_ipv4, sink_udp_port=sink_port),
        ipv6_allowed=False,
    )


def load_policy(path: str | pathlib.Path) -> Policy:
    """Read and validate a policy file.  OSError is left to the caller."""
    return parse_policy(pathlib.Path(path).read_bytes())


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="validate a vprlab leak policy")
    parser.add_argument("--check", metavar="POLICY.json", required=True)
    args = parser.parse_args(argv)
    try:
        policy = load_policy(args.check)
    except (OSError, PolicyError) as exc:
        print(f"policy: {exc}", file=sys.stderr)
        return 2
    print(
        "ok: "
        f"{len(policy.allowed)} allowed flow(s), "
        f"control {policy.positive_control.sink_ipv4}:{policy.positive_control.sink_udp_port}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
