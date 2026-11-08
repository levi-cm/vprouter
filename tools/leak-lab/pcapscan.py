#!/usr/bin/env python3
"""Pure-Python classic-libpcap reader and leak verdict engine.

The monitor is deliberately independent of the router: it reads a capture taken
outside the VM (on the host tap) and classifies every frame by the declared VM
WAN MAC/IP.  Anything that is not an explicitly allowed WireGuard UDP flow (or
an exact gateway ARP exchange when enabled) is a leak finding.

Evidence rules (M1):

* a tcpdump stats file is mandatory; every summary line is parsed, every drop
  counter must be zero, and ``packets captured`` must equal the number of
  complete pcap records;
* exactly one ``control-before`` and one ``control-after`` nonce are mandatory,
  they must differ, each must be seen exactly once, ``ts(before) < ts(after)``,
  and every non-control record must lie strictly between them;
* any leak finding makes the verdict ``LEAK`` even when the capture is also
  invalid (``invalid_reasons`` reports the capture defects alongside);
* a complete record with a malformed frame is a ``malformed_frame`` finding and
  scanning continues.  Only pcap-structure damage (bad global header,
  truncated record header/body, snaplen-truncated record) stops the scan and is
  ``INVALID``.

Classic libpcap only: both byte orders, microsecond and nanosecond magic,
linktype 1 (Ethernet) only.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import pathlib
import re
import struct
import sys
from dataclasses import dataclass
from typing import Any

import policy as policy_mod

MAX_FINDINGS = 200

#: Non-first fragments only associate with a first fragment seen at most this
#: many seconds earlier, with no completed datagram and no reuse in between.
FRAGMENT_WINDOW_SECONDS = 30.0

#: Minimum Ethernet frame without FCS.  The L3 payload area is 46 bytes; zero
#: padding inside that minimum is the only trailer this monitor accepts.
MIN_ETHERNET_FRAME = 60

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_QINQ = 0x88A8

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17

# file magic bytes -> (struct endianness, timestamp divisor, resolution, label)
_PCAP_MAGIC: dict[bytes, tuple[str, int, str, str]] = {
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000, "microsecond", "big"),
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000, "microsecond", "little"),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000, "nanosecond", "big"),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000, "nanosecond", "little"),
}

_STATS_LINE_RE = re.compile(
    r"^\s*(\d+)\s+packets?\s+"
    r"(captured|received by filter|dropped by kernel|dropped by interface)"
    r"\s*$",
    re.IGNORECASE,
)
_STATS_COUNTER_NAME = {
    "captured": "captured",
    "received by filter": "received",
    "dropped by kernel": "dropped_kernel",
    "dropped by interface": "dropped_interface",
}
_STATS_COUNTER_SHAPE_RE = re.compile(r"^\s*\d+\s+packets?\b", re.IGNORECASE)
_STATS_ERROR_RE = re.compile(
    r"(?:error|pcap_loop|disappeared|went down|permission denied|"
    r"no such device|biocsetif failed)",
    re.IGNORECASE,
)
_STATS_REQUIRED = ("captured", "received", "dropped_kernel")


class CaptureInvalid(Exception):
    """The capture cannot be trusted as complete evidence."""


@dataclass(slots=True)
class _L4Result:
    label: str | None = None
    reason: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    udp_length: int | None = None
    detail: str | None = None


@dataclass(slots=True)
class _FragmentState:
    first_ts: float
    covered_end: int
    label: str | None
    reason: str | None
    udp_length: int | None
    src: str
    dst: str
    proto_name: str
    complete: bool = False
    reported: bool = False


def _mac(raw: bytes) -> str:
    return ":".join(f"{octet:02x}" for octet in raw)


def _u16(raw: bytes, offset: int) -> int:
    return (raw[offset] << 8) | raw[offset + 1]


def _ipv4(raw: bytes) -> str:
    return ".".join(str(octet) for octet in raw)


def _proto_name(protocol: int) -> str:
    if protocol == IPPROTO_UDP:
        return "udp"
    if protocol == IPPROTO_TCP:
        return "tcp"
    if protocol == IPPROTO_ICMP:
        return "icmp"
    return "ipv4"


def parse_tcpdump_stats(text: str) -> tuple[dict[str, int | None], str | None]:
    """Parse every tcpdump 4.99 stderr summary line.

    Returns ``(stats, problem)``.  A non-empty ``problem`` is an INVALID reason.

    The parser is deliberately all-or-nothing: every recognised counter line is
    collected, and *any* of the following makes the capture invalid:

    * a tcpdump error line (``pcap_loop``, interface disappeared, ...);
    * a counter-shaped line that does not match the supported format;
    * a missing ``captured``, ``received by filter`` or ``dropped by kernel``
      counter;
    * a nonzero kernel or interface drop counter (checked over every summary);
    * the same counter reported with two different values (concatenated or
      stale summaries are contradictory evidence).

    ``received by filter`` is recorded but is not required to equal
    ``captured + drops``: libpcap receive-counter semantics can differ while
    packets are still queued.
    """
    values: dict[str, set[int]] = {
        "captured": set(),
        "received": set(),
        "dropped_kernel": set(),
        "dropped_interface": set(),
    }
    error_line = False
    shape_problem = False
    for line in text.splitlines():
        match = _STATS_LINE_RE.match(line)
        if match is not None:
            key = _STATS_COUNTER_NAME[match.group(2).lower()]
            values[key].add(int(match.group(1)))
            continue
        if not line.strip():
            continue
        if line.lstrip().startswith("tcpdump:") and _STATS_ERROR_RE.search(line):
            error_line = True
            continue
        if _STATS_COUNTER_SHAPE_RE.match(line):
            shape_problem = True

    stats: dict[str, int | None] = {
        key: (max(found) if found else None) for key, found in values.items()
    }
    if error_line:
        return stats, "stats_error_line"
    if shape_problem:
        return stats, "stats_unparseable"
    if not any(values.values()):
        return stats, "stats_unparseable"
    if any(not values[key] for key in _STATS_REQUIRED):
        return stats, "stats_incomplete"
    if (stats["dropped_kernel"] or 0) or (stats["dropped_interface"] or 0):
        return stats, "packet_drops"
    if any(len(found) > 1 for found in values.values()):
        return stats, "stats_contradictory"
    return stats, None


class _Scanner:
    def __init__(self, policy: policy_mod.Policy, before: str, after: str):
        self.policy = policy
        self.before = before
        self.after = after
        self.allowed_out = policy.outbound_allowed()
        self.allowed_in = policy.inbound_allowed()
        self.allowed_counts: dict[str, int] = {
            flow.label: 0 for flow in policy.allowed
        }
        if policy.allow_arp:
            self.allowed_counts["arp"] = 0
        self.findings: list[dict[str, Any]] = []
        self.findings_total = 0
        self.packets = 0
        self.first_ts: float | None = None
        self.last_ts: float | None = None
        self.records: list[tuple[int, float, bool]] = []
        self.control_sightings: dict[str, list[dict[str, Any]]] = {
            "before": [],
            "after": [],
        }
        self.control_packets = 0
        self.seen_control_order: list[str] = []
        self.fragment_states: dict[
            tuple[str, str, int, int], _FragmentState
        ] = {}
        self._current_is_control = False

    # ------------------------------------------------------------------ utils
    def observe_timestamp(self, ts: float) -> None:
        if self.first_ts is None:
            self.first_ts = ts
        self.last_ts = ts

    def add_finding(
        self,
        ts: float,
        src: Any,
        dst: Any,
        proto: str,
        src_port: int | None,
        dst_port: int | None,
        reason: str,
        **extra: Any,
    ) -> None:
        self.findings_total += 1
        if len(self.findings) >= MAX_FINDINGS:
            return
        finding: dict[str, Any] = {
            "ts": ts,
            "src": src,
            "dst": dst,
            "proto": proto,
            "src_port": src_port,
            "dst_port": dst_port,
            "reason": reason,
        }
        finding.update(extra)
        self.findings.append(finding)

    def _malformed(
        self,
        ts: float,
        detail: str,
        *,
        src: Any = None,
        dst: Any = None,
        proto: str = "ether",
    ) -> None:
        self.add_finding(
            ts, src, dst, proto, None, None, "malformed_frame", detail=detail
        )

    def _check_trailer(
        self,
        ts: float,
        l3: bytes,
        consumed: int,
        min_l3: int,
        src: Any,
        dst: Any,
        proto: str,
    ) -> None:
        """Account for every Ethernet byte after the declared L3 payload.

        Only zero padding that brings the frame to the 60-byte Ethernet
        minimum is accepted.  Anything longer, or any nonzero padding byte, is
        a finding: the monitor cannot prove those bytes are harmless.
        """
        total = len(l3)
        if total <= consumed:
            return
        trailer = l3[consumed:]
        limit = max(consumed, min_l3)
        if total > limit or any(trailer):
            self.add_finding(
                ts,
                src,
                dst,
                proto,
                None,
                None,
                "ethernet_trailer",
                trailer_len=len(trailer),
                nonzero_padding=any(trailer),
            )

    # --------------------------------------------------------------- Ethernet
    def parse_frame(self, frame: bytes, ts: float, index: int) -> None:
        self._current_is_control = False
        self._parse_frame(frame, ts, index)
        self.records.append((index, ts, self._current_is_control))

    def _parse_frame(self, frame: bytes, ts: float, index: int) -> None:
        if len(frame) < 14:
            self._malformed(ts, "truncated_ethernet_header")
            return
        dst_mac = _mac(frame[0:6])
        src_mac = _mac(frame[6:12])
        ethertype = _u16(frame, 12)
        offset = 14
        vlan: int | None = None
        if ethertype == ETHERTYPE_VLAN:
            if len(frame) < 18:
                self._malformed(
                    ts,
                    "truncated_vlan_header",
                    src=src_mac,
                    dst=dst_mac,
                )
                return
            tci = _u16(frame, 14)
            vlan = tci & 0x0FFF
            ethertype = _u16(frame, 16)
            offset = 18
            if ethertype in (ETHERTYPE_VLAN, ETHERTYPE_QINQ):
                reason = (
                    "unsupported_encapsulation"
                    if self.policy.vm_wan_mac in (src_mac, dst_mac)
                    else "foreign_frame"
                )
                self.add_finding(
                    ts,
                    src_mac,
                    dst_mac,
                    "ether",
                    None,
                    None,
                    reason,
                    vlan=vlan,
                    ethertype=f"0x{ethertype:04x}",
                )
                return
        l3 = frame[offset:]
        min_l3 = MIN_ETHERNET_FRAME - offset

        if ethertype == ETHERTYPE_ARP:
            self._parse_arp(ts, l3, src_mac, dst_mac, vlan, min_l3)
        elif ethertype == ETHERTYPE_IPV4:
            self._parse_ipv4(ts, index, l3, src_mac, dst_mac, vlan, min_l3)
        elif ethertype == ETHERTYPE_IPV6:
            self._parse_ipv6(ts, l3, src_mac, dst_mac, vlan)
        else:
            extra: dict[str, Any] = {"ethertype": f"0x{ethertype:04x}"}
            if vlan is not None:
                extra["vlan"] = vlan
            reason = (
                "unexpected_ethertype"
                if self.policy.vm_wan_mac in (src_mac, dst_mac)
                else "foreign_frame"
            )
            self.add_finding(
                ts,
                src_mac,
                dst_mac,
                "ether",
                None,
                None,
                reason,
                **extra,
            )

    # -------------------------------------------------------------------- ARP
    def _parse_arp(
        self,
        ts: float,
        l3: bytes,
        src_mac: str,
        dst_mac: str,
        vlan: int | None,
        min_l3: int,
    ) -> None:
        if len(l3) < 8:
            self._malformed(
                ts, "truncated_arp_header", src=src_mac, dst=dst_mac, proto="arp"
            )
            return
        htype = _u16(l3, 0)
        ptype = _u16(l3, 2)
        hlen = l3[4]
        plen = l3[5]
        needed = 8 + 2 * hlen + 2 * plen
        if len(l3) < needed:
            self._malformed(
                ts, "truncated_arp_body", src=src_mac, dst=dst_mac, proto="arp"
            )
            return
        self._check_trailer(ts, l3, needed, min_l3, src_mac, dst_mac, "arp")
        extra: dict[str, Any] = {}
        if vlan is not None:
            extra["vlan"] = vlan
        if htype != 1 or ptype != ETHERTYPE_IPV4 or hlen != 6 or plen != 4:
            self.add_finding(
                ts,
                src_mac,
                dst_mac,
                "arp",
                None,
                None,
                "unsupported_arp",
                **extra,
            )
            return
        operation = _u16(l3, 6)
        sender_mac = _mac(l3[8:14])
        sender_ip = _ipv4(l3[14:18])
        target_mac = _mac(l3[18:24])
        target_ip = _ipv4(l3[24:28])
        extra.update(
            src_mac=sender_mac,
            dst_mac=target_mac,
            arp_operation=operation,
        )
        allowed = False
        if self.policy.allow_arp and src_mac == sender_mac and operation in (1, 2):
            vm_to_gateway = (
                sender_mac == self.policy.vm_wan_mac
                and sender_ip == self.policy.vm_wan_ipv4
                and target_ip == self.policy.gateway_ipv4
            )
            gateway_to_vm = (
                sender_ip == self.policy.gateway_ipv4
                and target_ip == self.policy.vm_wan_ipv4
                and (operation != 2 or target_mac == self.policy.vm_wan_mac)
            )
            allowed = vm_to_gateway or gateway_to_vm
        if allowed:
            self.allowed_counts["arp"] = self.allowed_counts.get("arp", 0) + 1
        else:
            self.add_finding(
                ts,
                sender_ip,
                target_ip,
                "arp",
                None,
                None,
                "arp_not_allowed",
                **extra,
            )

    # ------------------------------------------------------------------- IPv4
    def _parse_ipv4(
        self,
        ts: float,
        index: int,
        l3: bytes,
        src_mac: str,
        dst_mac: str,
        vlan: int | None,
        min_l3: int,
    ) -> None:
        if len(l3) < 20:
            self._malformed(
                ts, "truncated_ipv4_header", src=src_mac, dst=dst_mac, proto="ipv4"
            )
            return
        version = l3[0] >> 4
        ihl = (l3[0] & 0x0F) * 4
        if version != 4:
            self._malformed(
                ts, "invalid_ipv4_version", src=src_mac, dst=dst_mac, proto="ipv4"
            )
            return
        if ihl < 20:
            self._malformed(
                ts, "invalid_ipv4_ihl", src=src_mac, dst=dst_mac, proto="ipv4"
            )
            return
        if len(l3) < ihl:
            self._malformed(
                ts, "truncated_ipv4_options", src=src_mac, dst=dst_mac, proto="ipv4"
            )
            return
        total_length = _u16(l3, 2)
        if total_length < ihl:
            self._malformed(
                ts,
                "invalid_ipv4_total_length",
                src=src_mac,
                dst=dst_mac,
                proto="ipv4",
            )
            return
        if total_length > len(l3):
            self._malformed(
                ts, "truncated_ipv4_packet", src=src_mac, dst=dst_mac, proto="ipv4"
            )
            return
        src = _ipv4(l3[12:16])
        dst = _ipv4(l3[16:20])
        protocol = l3[9]
        self._check_trailer(ts, l3, total_length, min_l3, src, dst, "ipv4")
        identification = _u16(l3, 4)
        fragment_field = _u16(l3, 6)
        more_fragments = bool(fragment_field & 0x2000)
        fragment_offset = (fragment_field & 0x1FFF) * 8
        payload = l3[ihl:total_length]
        extra: dict[str, Any] = {}
        if vlan is not None:
            extra["vlan"] = vlan

        if ihl > 20:
            self.add_finding(
                ts,
                src,
                dst,
                _proto_name(protocol),
                None,
                None,
                "ipv4_options",
                ihl=ihl,
                **extra,
            )
            return

        vm_ip = self.policy.vm_wan_ipv4
        if src == vm_ip and dst == vm_ip:
            self.add_finding(
                ts, src, dst, _proto_name(protocol), None, None, "vm_to_vm", **extra
            )
            return
        if src == vm_ip:
            direction = "out"
        elif dst == vm_ip:
            direction = "in"
        else:
            self.add_finding(
                ts,
                src,
                dst,
                _proto_name(protocol),
                None,
                None,
                "foreign_frame",
                **extra,
            )
            return

        proto_name = _proto_name(protocol)
        if fragment_offset > 0:
            self._handle_nonfirst_fragment(
                ts,
                src,
                dst,
                protocol,
                proto_name,
                identification,
                fragment_offset,
                payload,
                more_fragments,
                extra,
            )
            return

        result = self._classify_l4(
            ts,
            index,
            protocol=protocol,
            payload=payload,
            src=src,
            dst=dst,
            direction=direction,
            fragmented=more_fragments,
        )
        if more_fragments:
            self._register_first_fragment(
                ts,
                src,
                dst,
                protocol,
                (src, dst, protocol, identification),
                len(payload),
                result,
            )
        if result.label is not None:
            self.allowed_counts[result.label] += 1
        elif result.reason is not None:
            self.add_finding(
                ts,
                src,
                dst,
                proto_name,
                result.src_port,
                result.dst_port,
                result.reason,
                **({"detail": result.detail} if result.detail else {}),
                **extra,
            )

    # --------------------------------------------------------------- fragments
    def _register_first_fragment(
        self,
        ts: float,
        src: str,
        dst: str,
        protocol: int,
        key: tuple[str, str, int, int],
        payload_length: int,
        result: _L4Result,
    ) -> None:
        state = self.fragment_states.get(key)
        if (
            state is not None
            and not state.complete
            and ts - state.first_ts <= FRAGMENT_WINDOW_SECONDS
        ):
            self.add_finding(
                ts,
                src,
                dst,
                _proto_name(protocol),
                None,
                None,
                "fragment_duplicate_first",
                fragment_key=list(key),
            )
            return
        self.fragment_states[key] = _FragmentState(
            first_ts=ts,
            covered_end=payload_length,
            label=result.label,
            reason=result.reason,
            udp_length=result.udp_length,
            src=src,
            dst=dst,
            proto_name=_proto_name(protocol),
            complete=False,
        )

    def _handle_nonfirst_fragment(
        self,
        ts: float,
        src: str,
        dst: str,
        protocol: int,
        proto_name: str,
        identification: int,
        fragment_offset: int,
        payload: bytes,
        more_fragments: bool,
        extra: dict[str, Any],
    ) -> None:
        key = (src, dst, protocol, identification)
        state = self.fragment_states.get(key)
        reason: str | None = None
        detail: str | None = None
        if state is None:
            reason = "fragment_without_first"
        elif ts < state.first_ts:
            reason = "fragment_without_first"
        elif ts - state.first_ts > FRAGMENT_WINDOW_SECONDS:
            reason = "fragment_stale_association"
        elif state.reason is not None:
            reason = "fragment_of_disallowed_flow"
            detail = state.reason
        elif state.complete:
            reason = "fragment_after_complete"
        elif more_fragments and len(payload) % 8:
            reason = "malformed_frame"
            detail = "invalid_fragment_length"
        elif fragment_offset < state.covered_end:
            reason = "fragment_overlap"
        elif fragment_offset > state.covered_end:
            reason = "fragment_gap"
        else:
            end = fragment_offset + len(payload)
            if state.udp_length is not None:
                if end > state.udp_length:
                    reason = "fragment_out_of_range"
                elif not more_fragments and end != state.udp_length:
                    reason = "fragment_incomplete"
                elif more_fragments and end >= state.udp_length:
                    reason = "fragment_out_of_range"
            if reason is None:
                state.covered_end = end
                if not more_fragments:
                    state.complete = True
                if state.label is not None:
                    self.allowed_counts[state.label] += 1
                return
        if state is not None:
            state.reported = True
        self.add_finding(
            ts,
            src,
            dst,
            proto_name,
            None,
            None,
            reason,
            **({"detail": detail} if detail else {}),
            **extra,
        )

    def finalize_fragments(self) -> None:
        """Reject an allowed fragmented datagram that never completed.

        Only called after the whole pcap was read.  If the capture itself was
        structurally truncated, incompleteness is expected and the verdict is
        INVALID rather than an inferred LEAK.  Only datagrams whose first
        fragment lies inside a valid control window are judged: an
        out-of-window fragment cannot turn an already-INVALID capture into a
        LEAK merely because the phase boundary cut it.
        """
        before = self.control_sightings["before"]
        after = self.control_sightings["after"]
        if not before or not after:
            return
        before_ts = before[0]["ts"]
        after_ts = after[0]["ts"]
        if not before_ts < after_ts:
            return
        for state in self.fragment_states.values():
            if not before_ts < state.first_ts < after_ts:
                continue
            if (
                state.label is not None
                and not state.complete
                and not state.reported
            ):
                self.add_finding(
                    state.first_ts,
                    state.src,
                    state.dst,
                    state.proto_name,
                    None,
                    None,
                    "fragment_incomplete",
                    detail="datagram_not_completed",
                )

    # --------------------------------------------------------------- IPv4 L4
    def _classify_l4(
        self,
        ts: float,
        index: int,
        protocol: int,
        payload: bytes,
        src: str,
        dst: str,
        direction: str,
        *,
        fragmented: bool,
    ) -> _L4Result:
        if protocol == IPPROTO_UDP:
            src_port: int | None = None
            dst_port: int | None = None
            udp_length: int | None = None
            if len(payload) >= 8:
                src_port = _u16(payload, 0)
                dst_port = _u16(payload, 2)
                udp_length = _u16(payload, 4)

            control = self.policy.positive_control
            is_control_destination = (
                direction == "out"
                and dst == control.sink_ipv4
                and dst_port == control.sink_udp_port
            )
            if is_control_destination:
                if src_port is None or udp_length is None or udp_length < 8:
                    return _L4Result(
                        reason="malformed_frame",
                        src_port=src_port,
                        dst_port=dst_port,
                        detail="udp_length_mismatch",
                    )
                if fragmented:
                    return _L4Result(
                        reason="malformed_control",
                        src_port=src_port,
                        dst_port=dst_port,
                    )
                if udp_length != len(payload):
                    return _L4Result(
                        reason="malformed_frame",
                        src_port=src_port,
                        dst_port=dst_port,
                        detail="udp_length_mismatch",
                    )
                udp_data = payload[8:]
                if (
                    len(udp_data) == policy_mod.CONTROL_PAYLOAD_LEN
                    and udp_data.startswith(policy_mod.CONTROL_PREFIX)
                ):
                    nonce_bytes = udp_data[len(policy_mod.CONTROL_PREFIX) :]
                    try:
                        nonce = nonce_bytes.decode("ascii")
                    except UnicodeDecodeError:
                        nonce = ""
                    if policy_mod.is_control_nonce(nonce):
                        self._record_control(
                            ts, index, nonce, src, dst, src_port, dst_port
                        )
                        if nonce in (self.before, self.after):
                            return _L4Result(
                                src_port=src_port,
                                dst_port=dst_port,
                                udp_length=udp_length,
                            )
                        return _L4Result(
                            reason="unexpected_control_nonce",
                            src_port=src_port,
                            dst_port=dst_port,
                        )
                return _L4Result(
                    reason="malformed_control",
                    src_port=src_port,
                    dst_port=dst_port,
                )

            if src_port is None or dst_port is None:
                return _L4Result(reason="udp_header_incomplete")
            if direction == "out":
                label = self.allowed_out.get((dst, dst_port))
            else:
                label = self.allowed_in.get((src, src_port))
            if label is not None:
                # A first fragment legitimately declares a UDP length longer
                # than the bytes present in that fragment; every other allowed
                # datagram must account for exactly the IP payload.
                length_ok = (
                    udp_length is not None
                    and udp_length >= 8
                    and (
                        udp_length >= len(payload)
                        if fragmented
                        else udp_length == len(payload)
                    )
                )
                if not length_ok:
                    return _L4Result(
                        reason="malformed_frame",
                        src_port=src_port,
                        dst_port=dst_port,
                        detail="udp_length_mismatch",
                    )
                return _L4Result(
                    label=label,
                    src_port=src_port,
                    dst_port=dst_port,
                    udp_length=udp_length,
                )
            return _L4Result(
                reason="udp_not_allowed", src_port=src_port, dst_port=dst_port
            )

        if protocol == IPPROTO_TCP:
            src_port = None
            dst_port = None
            if len(payload) >= 4:
                src_port = _u16(payload, 0)
                dst_port = _u16(payload, 2)
            return _L4Result(
                reason="tcp_not_allowed", src_port=src_port, dst_port=dst_port
            )

        if protocol == IPPROTO_ICMP:
            return _L4Result(reason="icmp_not_allowed")

        return _L4Result(reason="ip_protocol_not_allowed")

    # -------------------------------------------------------------- controls
    def _record_control(
        self,
        ts: float,
        index: int,
        nonce: str,
        src: str,
        dst: str,
        src_port: int,
        dst_port: int,
    ) -> None:
        self.control_packets += 1
        if nonce == self.before:
            role = "before"
        elif nonce == self.after:
            role = "after"
        else:
            return
        sightings = self.control_sightings[role]
        sightings.append({"ts": ts, "packet": index})
        self._current_is_control = True
        if nonce not in self.seen_control_order:
            self.seen_control_order.append(nonce)
        if len(sightings) > 1:
            self.add_finding(
                ts,
                src,
                dst,
                "udp",
                src_port,
                dst_port,
                "replayed_control",
                nonce=nonce,
                role=role,
            )

    # ------------------------------------------------------------------- IPv6
    def _parse_ipv6(
        self,
        ts: float,
        l3: bytes,
        src_mac: str,
        dst_mac: str,
        vlan: int | None,
    ) -> None:
        if len(l3) < 40:
            self._malformed(
                ts, "truncated_ipv6_header", src=src_mac, dst=dst_mac, proto="ipv6"
            )
            return
        if l3[0] >> 4 != 6:
            self._malformed(
                ts, "invalid_ipv6_version", src=src_mac, dst=dst_mac, proto="ipv6"
            )
            return
        src = str(ipaddress.IPv6Address(l3[8:24]))
        dst = str(ipaddress.IPv6Address(l3[24:40]))
        extra: dict[str, Any] = {"next_header": l3[6]}
        if vlan is not None:
            extra["vlan"] = vlan
        self.add_finding(
            ts,
            src,
            dst,
            "ipv6",
            None,
            None,
            "ipv6_not_allowed",
            **extra,
        )


def _read_pcap(data: bytes, scanner: _Scanner, meta: dict[str, Any]) -> None:
    if len(data) < 24:
        raise CaptureInvalid("truncated_global_header")
    magic = data[0:4]
    if magic not in _PCAP_MAGIC:
        raise CaptureInvalid("unsupported_pcap_magic")
    endian, divisor, resolution, byte_order = _PCAP_MAGIC[magic]
    version_major, version_minor, _thiszone, _sigfigs, snaplen, network = struct.unpack(
        endian + "HHiIII", data[4:24]
    )
    meta.update(
        {
            "format": "pcap",
            "version": f"{version_major}.{version_minor}",
            "endianness": byte_order,
            "timestamp_resolution": resolution,
            "snaplen": snaplen,
            "linktype": network,
            "linktype_name": "ethernet" if network == 1 else None,
        }
    )
    if (version_major, version_minor) != (2, 4):
        raise CaptureInvalid("unsupported_pcap_version")
    if snaplen == 0:
        raise CaptureInvalid("invalid_snaplen")
    if network != 1:
        raise CaptureInvalid(f"unsupported_linktype_{network}")

    offset = 24
    while offset < len(data):
        if len(data) - offset < 16:
            raise CaptureInvalid("truncated_record_header")
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(
            endian + "IIII", data[offset : offset + 16]
        )
        offset += 16
        if ts_frac >= divisor:
            raise CaptureInvalid("invalid_timestamp_fraction")
        if incl_len > orig_len:
            raise CaptureInvalid("record_length_inconsistent")
        if incl_len > snaplen:
            raise CaptureInvalid("record_exceeds_snaplen")
        if len(data) - offset < incl_len:
            raise CaptureInvalid("truncated_record_data")
        if incl_len < orig_len:
            # The capture itself is known to be missing wire bytes.  This is
            # not a frame-content problem: stop and mark the evidence INVALID.
            raise CaptureInvalid("snaplen_truncated_record")
        frame = data[offset : offset + incl_len]
        offset += incl_len
        ts = float(ts_sec) + (ts_frac / divisor)
        index = scanner.packets
        scanner.packets += 1
        scanner.observe_timestamp(ts)
        scanner.parse_frame(frame, ts, index)
    meta["packets_read"] = scanner.packets


def _control_report(scanner: _Scanner, role: str) -> dict[str, Any]:
    sightings = scanner.control_sightings[role]
    nonce = scanner.before if role == "before" else scanner.after
    return {
        "nonce": nonce,
        "seen": bool(sightings),
        "packets": len(sightings),
        "first_packet": sightings[0]["packet"] if sightings else None,
        "last_packet": sightings[-1]["packet"] if sightings else None,
        "first_ts": sightings[0]["ts"] if sightings else None,
        "last_ts": sightings[-1]["ts"] if sightings else None,
    }


def scan_capture(
    data: bytes,
    policy: policy_mod.Policy,
    control_before: str,
    control_after: str,
    *,
    tcpdump_stats_text: str | None,
    stats_error: str | None = None,
    stats_source: str | None = None,
    source: str | None = None,
    policy_sha256: str | None = None,
) -> dict[str, Any]:
    """Scan a classic pcap and return the canonical report as a dict.

    ``control_before`` and ``control_after`` are mandatory, must be distinct
    valid nonces, and each must be seen exactly once.  ``tcpdump_stats_text``
    is mandatory unless ``stats_error`` records why it could not be read.
    """
    if not isinstance(policy, policy_mod.Policy):
        raise TypeError("policy must be a policy.Policy instance")
    if not policy_mod.is_control_nonce(control_before) or not policy_mod.is_control_nonce(
        control_after
    ):
        raise ValueError(
            "control nonces must be 32 lowercase hexadecimal characters"
        )
    if control_before == control_after:
        raise ValueError("control-before and control-after nonces must be distinct")
    if tcpdump_stats_text is None and stats_error is None:
        raise ValueError(
            "a tcpdump stats file is required; pass tcpdump_stats_text or stats_error"
        )

    scanner = _Scanner(policy, control_before, control_after)
    meta: dict[str, Any] = {"format": "pcap"}
    invalid_reasons: list[str] = []
    structural_invalid = False
    try:
        _read_pcap(data, scanner, meta)
    except CaptureInvalid as exc:
        structural_invalid = True
        invalid_reasons.append(str(exc))
        meta["packets_read"] = scanner.packets
    if not structural_invalid:
        scanner.finalize_fragments()

    stats: dict[str, int | None] | None = None
    stats_problem: str | None = stats_error
    stats_sha256: str | None = None
    if stats_problem is None and tcpdump_stats_text is not None:
        stats, stats_problem = parse_tcpdump_stats(tcpdump_stats_text)
        stats_sha256 = hashlib.sha256(tcpdump_stats_text.encode("utf-8")).hexdigest()
    if stats_problem is not None:
        invalid_reasons.append(stats_problem)
    if (
        stats_problem is None
        and stats is not None
        and stats["captured"] != scanner.packets
    ):
        invalid_reasons.append("stats_packet_count_mismatch")
    if scanner.packets == 0:
        invalid_reasons.append("zero_packets")

    before_sightings = scanner.control_sightings["before"]
    after_sightings = scanner.control_sightings["after"]
    if before_sightings and after_sightings:
        before_ts = before_sightings[0]["ts"]
        after_ts = after_sightings[0]["ts"]
        if not before_ts < after_ts:
            invalid_reasons.append("control_order")
        else:
            outside = [
                (index, ts)
                for index, ts, is_control in scanner.records
                if not is_control and not (before_ts < ts < after_ts)
            ]
            if outside:
                invalid_reasons.append("outside_control_window")

    missing = []
    if not before_sightings:
        missing.append(control_before)
    if not after_sightings:
        missing.append(control_after)
    if missing:
        invalid_reasons.append("missing_positive_controls")

    if scanner.findings_total:
        verdict = "LEAK"
    elif invalid_reasons:
        verdict = "INVALID"
    else:
        verdict = "PASS"

    meta.update(
        {
            "source": source,
            "source_sha256": hashlib.sha256(data).hexdigest(),
            "policy_sha256": policy_sha256,
            "control_before": control_before,
            "control_after": control_after,
            "controls": {
                "before": _control_report(scanner, "before"),
                "after": _control_report(scanner, "after"),
            },
            "missing_controls": missing,
            "positive_control_packets": scanner.control_packets,
            "first_ts": scanner.first_ts,
            "last_ts": scanner.last_ts,
            "stats": stats,
            "stats_source": stats_source,
            "stats_sha256": stats_sha256,
            "invalid_reasons": invalid_reasons,
        }
    )
    if stats_problem is not None:
        meta["stats_problem"] = stats_problem
    if invalid_reasons:
        meta["invalid_reason"] = invalid_reasons[0]

    return {
        "verdict": verdict,
        "packets": scanner.packets,
        "allowed_counts": dict(scanner.allowed_counts),
        "findings": scanner.findings,
        "findings_total": scanner.findings_total,
        "findings_truncated": scanner.findings_total > len(scanner.findings),
        "positive_controls_seen": scanner.seen_control_order,
        "capture_meta": meta,
    }


# Convenience aliases used by callers/tests.
scan = scan_capture
scan_pcap = scan_capture


def canonical_json(report: dict[str, Any]) -> str:
    """Render a report as deterministic JSON with a trailing newline."""
    return json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="classify a classic libpcap capture against a leak policy"
    )
    parser.add_argument("--policy", required=True, metavar="POLICY.json")
    parser.add_argument("--pcap", required=True, metavar="CAPTURE.pcap")
    parser.add_argument(
        "--control-before",
        required=True,
        metavar="NONCE",
        help="nonce of the marker sent immediately before the test action",
    )
    parser.add_argument(
        "--control-after",
        required=True,
        metavar="NONCE",
        help="nonce of the marker sent immediately after the test action",
    )
    parser.add_argument(
        "--tcpdump-stats",
        required=True,
        metavar="STATS.txt",
        help="tcpdump stderr summary written by the capture command",
    )
    args = parser.parse_args(argv)

    try:
        policy_bytes = pathlib.Path(args.policy).read_bytes()
        policy = policy_mod.parse_policy(policy_bytes)
    except (OSError, policy_mod.PolicyError) as exc:
        print(f"pcapscan: policy: {exc}", file=sys.stderr)
        return 2

    for label, nonce in (
        ("--control-before", args.control_before),
        ("--control-after", args.control_after),
    ):
        if not policy_mod.is_control_nonce(nonce):
            print(
                f"pcapscan: {label} must be 32 lowercase hex characters",
                file=sys.stderr,
            )
            return 2
    if args.control_before == args.control_after:
        print(
            "pcapscan: --control-before and --control-after must be distinct",
            file=sys.stderr,
        )
        return 2

    try:
        data = pathlib.Path(args.pcap).read_bytes()
    except OSError as exc:
        print(f"pcapscan: capture: {exc}", file=sys.stderr)
        return 2

    stats_text: str | None = None
    stats_error: str | None = None
    try:
        stats_text = pathlib.Path(args.tcpdump_stats).read_text(
            encoding="utf-8", errors="replace"
        )
    except OSError:
        stats_error = "stats_unreadable"

    report = scan_capture(
        data,
        policy,
        args.control_before,
        args.control_after,
        tcpdump_stats_text=stats_text,
        stats_error=stats_error,
        stats_source=args.tcpdump_stats,
        source=args.pcap,
        policy_sha256=hashlib.sha256(policy_bytes).hexdigest(),
    )
    sys.stdout.write(canonical_json(report))
    return {"PASS": 0, "LEAK": 1, "INVALID": 2}[report["verdict"]]


if __name__ == "__main__":
    raise SystemExit(main())
