#!/usr/bin/env python3
"""Pure-Python classic-libpcap reader and leak verdict engine.

The monitor is deliberately independent of the router: it reads a capture taken
outside the VM (on the host tap) and classifies every frame by the declared VM
WAN MAC/IP.  Anything that is not an explicitly allowed WireGuard UDP flow (or
an exact gateway ARP exchange when enabled) is a leak finding.

Evidence rules (M1, round 3):

* a tcpdump stats file is mandatory; every summary form is parsed in full,
  including the one-line SIGUSR1 form, every summary must have ``captured ==
  received by filter`` and zero drops, counters must be non-decreasing across
  summaries in order, the final summary's ``captured`` must equal the number of
  complete pcap records, and the single ``listening on vprlab-tap0, link-type
  EN10MB`` banner must be the first non-empty line;
* the capture argv supplied with ``--capture-argv-file`` must equal the exact
  argv ``netplan.py`` prints, except that the ``-w`` path must resolve
  (``realpath``) to the submitted pcap; its hash is bound into the report;
* exactly one ``control-before`` and one ``control-after`` nonce are mandatory,
  they must differ, each must be seen exactly once, ``ts(before) < ts(after)``,
  and record timestamps must never decrease;
* all records are classified.  Allowed flows that fall outside the control
  window are counted as ``outside_window_allowed`` instead of invalidating the
  capture; any finding anywhere in the capture is still ``LEAK``;
* an allowed relay tuple additionally requires the exact tunnel L2 shape
  (outbound: source ``vm_wan_mac``, destination ``gateway_mac``; inbound: the
  reverse; no 802.1Q tag), otherwise it is ``allowed_tuple_wrong_l2`` and is
  not counted;
* an allowed-tuple datagram must also have a WireGuard message shape (type
  1/2/3/4 with zero reserved bytes and the fixed/data lengths), otherwise it
  is ``allowed_tuple_not_wireguard``; this is a shape check, not cipher
  authentication;
* ``--expect-tunnel up`` requires allowed traffic in both directions inside the
  window on the same flow label, ``--expect-tunnel down`` requires no inbound
  allowed flow;
* an incomplete allowed fragment association is ``fragment_incomplete``
  wherever it lies relative to the control window;
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
import io
import ipaddress
import json
import pathlib
import re
import struct
import sys
from dataclasses import dataclass
from typing import Any

import netplan as netplan_mod
import policy as policy_mod

MAX_FINDINGS = 200
#: The scanner keeps at most this many outside-window packet indexes; the
#: total is still counted.  Fragment associations are capped at 4096 live
#: datagrams.  Exhausting either bound is a local resource finding, never a
#: reason to forget evidence.
MAX_OUTSIDE_WINDOW_INDEXES = 1000
MAX_FRAGMENT_ASSOCIATIONS = 4096

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

#: The exact tcpdump banner the host plan's capture command emits.  Anything
#: else (wrong interface, wrong link type, no banner) leaves the capture
#: provenance unproven.
REQUIRED_STATS_BANNER = "listening on vprlab-tap0, link-type EN10MB"
_STATS_BANNER_RE = re.compile(
    r"^tcpdump: listening on vprlab-tap0, link-type EN10MB \(Ethernet\)"
    r"(?:, snapshot length [0-9]+ bytes)?$"
)
_STATS_BANNER_LIKE_RE = re.compile(r"listening on", re.IGNORECASE)

#: Expected tunnel evidence values for ``--expect-tunnel``.
EXPECT_TUNNEL_VALUES = ("up", "down", "any")

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
#: tcpdump's one-line SIGUSR1 summary:
#: ``tcpdump: 2 packets captured, 5 packets received by filter, 3 packets dropped by kernel``
_STATS_ONELINE_RE = re.compile(
    r"^\s*tcpdump:\s*(\d+)\s+packets?\s+captured,\s*"
    r"(\d+)\s+packets?\s+received by filter,\s*"
    r"(\d+)\s+packets?\s+dropped by kernel\s*$",
    re.IGNORECASE,
)
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
    udp_data_prefix: bytes = b""


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
    wg_type: int | None = None


#: WireGuard message types and the exact total message lengths for the three
#: fixed-size handshake/cookie messages.  Type 4 (transport data) is
#: ``16 + 16*n`` bytes with at least one encrypted block.  This is a *shape*
#: check only: it cannot and does not authenticate the ciphertext.
WIREGUARD_MESSAGE_TYPE_LENGTHS = {1: 148, 2: 92, 3: 64}
WIREGUARD_DATA_MIN = 32
WIREGUARD_DATA_HEADER = 16


def wireguard_payload_problem(payload: bytes, *, complete: bool = True) -> str | None:
    """Return why ``payload`` is not a plausible WireGuard message shape."""
    if len(payload) < 4:
        return "short" if complete else None
    kind = payload[0]
    if kind not in (1, 2, 3, 4):
        return "type"
    if payload[1:4] != b"\x00\x00\x00":
        return "reserved"
    if not complete:
        return None
    return wireguard_length_problem(kind, len(payload))


def wireguard_length_problem(kind: int, length: int) -> str | None:
    if kind in WIREGUARD_MESSAGE_TYPE_LENGTHS:
        return None if length == WIREGUARD_MESSAGE_TYPE_LENGTHS[kind] else "length"
    if kind == 4:
        # WireGuard pads plaintext to a multiple of 16 but clamps the padding
        # at the tunnel MTU (kernel: padded = min(ALIGN(len, 16), mtu)), so a
        # full-size packet at MTU 1420/1500 is not 16-aligned. Only the
        # minimum (header + Poly1305 tag) is a structural requirement.
        if length < WIREGUARD_DATA_MIN:
            return "length"
        return None
    return "type"


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


def check_stats_banner(text: str) -> bool:
    """Validate the capture banner line as a whole.

    tcpdump writes exactly one ``listening on vprlab-tap0, link-type EN10MB
    (Ethernet), snapshot length ...`` line and it is the first non-empty line
    of stderr.  A banner for another interface/link type, a banner that is not
    first, or any additional ``listening on`` line (including the same banner
    repeated or a foreign line containing that text) fails provenance.
    """
    nonempty = [line.strip() for line in text.splitlines() if line.strip()]
    if not nonempty:
        return False
    if _STATS_BANNER_RE.fullmatch(nonempty[0]) is None:
        return False
    return not any(_STATS_BANNER_LIKE_RE.search(line) for line in nonempty[1:])


def parse_tcpdump_stats(text: str) -> tuple[dict[str, int | None], str | None]:
    """Parse every tcpdump 4.99 stderr summary line.

    Returns ``(stats, problem)``.  A non-empty ``problem`` is an INVALID reason.

    The parser is deliberately all-or-nothing.  tcpdump may emit several
    summaries: one multi-line summary at exit, and one-line SIGUSR1 summaries
    during the run (``tcpdump: N packets captured, M packets received by
    filter, K packets dropped by kernel``).  Every summary is parsed fully and
    must satisfy all of the following:

    * it contains ``captured``, ``received by filter`` and ``dropped by
      kernel`` (``dropped by interface`` is optional);
    * ``captured == received by filter`` (otherwise ``unread_capture_tail``:
      packets passed the filter but were never written to the pcap);
    * both drop counters are zero (``packet_drops``);
    * counters never decrease from one summary to the next
      (``stats_contradictory``; concatenated or stale summaries are not
      evidence).

    The final summary is the binding one: its ``captured`` value is compared
    with the number of pcap records by :func:`scan_capture`.  A one-line
    SIGUSR1 summary is therefore just as binding as a multi-line summary when
    it is the last one.  A legitimate mid-run summary carries values no larger
    than the final summary and is accepted.
    """
    summaries: list[tuple[dict[str, int], bool]] = []
    current: dict[str, int] = {}
    current_conflict = False
    any_drop = False
    error_line = False
    shape_problem = False

    def flush() -> None:
        nonlocal current, current_conflict
        if current:
            summaries.append((dict(current), current_conflict))
            current = {}
            current_conflict = False

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if _STATS_BANNER_RE.fullmatch(stripped) is not None:
            continue
        match = _STATS_LINE_RE.match(line)
        if match is not None:
            key = _STATS_COUNTER_NAME[match.group(2).lower()]
            value = int(match.group(1))
            if key == "captured" and "captured" in current:
                # A new multi-line summary starts when "captured" repeats.
                flush()
            if key in current and current[key] != value:
                current_conflict = True
            current[key] = value
            if key in ("dropped_kernel", "dropped_interface") and value:
                any_drop = True
            continue
        one_line = _STATS_ONELINE_RE.match(line)
        if one_line is not None:
            flush()
            summaries.append(
                (
                    {
                        "captured": int(one_line.group(1)),
                        "received": int(one_line.group(2)),
                        "dropped_kernel": int(one_line.group(3)),
                    },
                    False,
                )
            )
            continue
        if line.lstrip().startswith("tcpdump:") and _STATS_ERROR_RE.search(line):
            error_line = True
            continue
        if _STATS_COUNTER_SHAPE_RE.match(line):
            shape_problem = True
    flush()

    final = summaries[-1][0] if summaries else {}
    stats: dict[str, int | None] = {
        "captured": final.get("captured"),
        "received": final.get("received"),
        "dropped_kernel": final.get("dropped_kernel"),
        "dropped_interface": final.get("dropped_interface"),
    }
    if error_line:
        return stats, "stats_error_line"
    if shape_problem:
        return stats, "stats_unparseable"
    if not summaries:
        return stats, "stats_unparseable"
    if any_drop or any(
        summary.get("dropped_kernel", 0) or summary.get("dropped_interface", 0)
        for summary, _conflict in summaries
    ):
        return stats, "packet_drops"
    if any(
        any(key not in summary for key in _STATS_REQUIRED)
        for summary, _conflict in summaries
    ):
        return stats, "stats_incomplete"
    if any(conflict for _summary, conflict in summaries):
        return stats, "stats_contradictory"
    if any(
        summary["captured"] != summary["received"]
        for summary, _conflict in summaries
    ):
        return stats, "unread_capture_tail"
    previous: dict[str, int] = {}
    for summary, _conflict in summaries:
        for key, value in summary.items():
            if key in previous and value < previous[key]:
                return stats, "stats_contradictory"
            previous[key] = value
    return stats, None


class _Scanner:
    def __init__(self, policy: policy_mod.Policy, before: str, after: str):
        self.policy = policy
        self.before = before
        self.after = after
        self.allowed_out = policy.outbound_allowed()
        self.allowed_in = policy.inbound_allowed()
        self.allowed_counts: dict[str, dict[str, int]] = {
            flow.label: {"outbound": 0, "inbound": 0} for flow in policy.allowed
        }
        if policy.allow_arp:
            self.allowed_counts["arp"] = {"outbound": 0, "inbound": 0}
        self.findings: list[dict[str, Any]] = []
        self.findings_total = 0
        self.leak_findings_total = 0
        self.packets = 0
        self.first_ts: float | None = None
        self.last_ts: float | None = None
        self.non_monotonic_timestamps = False
        #: Bounded live classification.  No per-packet tuple is retained: the
        #: in-window counts are accumulated as packets are parsed, and the
        #: outside-window index list is capped.
        self.window_counts: dict[str, dict[str, int]] = {
            flow.label: {"outbound": 0, "inbound": 0} for flow in policy.allowed
        }
        self.outside_window_allowed_indexes: list[int] = []
        self.outside_window_allowed_total = 0
        self.outside_window_other_total = 0
        self.before_ts: float | None = None
        self.after_ts: float | None = None
        self.control_sightings: dict[str, list[dict[str, Any]]] = {
            "before": [],
            "after": [],
        }
        self.control_packets = 0
        self.seen_control_order: list[str] = []
        self.fragment_states: dict[
            tuple[str, str, int, int], _FragmentState
        ] = {}
        self.fragment_table_overflow = False
        self._current_is_control = False
        self._current_allowed: tuple[str, str] | None = None

    # ------------------------------------------------------------------ utils
    def observe_timestamp(self, ts: float) -> None:
        if self.first_ts is None:
            self.first_ts = ts
        elif ts < self.last_ts:  # type: ignore[operator]
            self.non_monotonic_timestamps = True
        self.last_ts = ts

    def count_allowed(self, label: str, direction: str) -> None:
        key = "outbound" if direction in ("out", "outbound") else "inbound"
        counts = self.allowed_counts.setdefault(
            label, {"outbound": 0, "inbound": 0}
        )
        counts[key] += 1
        self._current_allowed = (label, key)

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
        if reason == "fragment_table_overflow":
            self.fragment_table_overflow = True
        else:
            self.leak_findings_total += 1
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
        self._current_allowed = None
        findings_before = self.findings_total
        self._parse_frame(frame, ts, index)
        label, direction = self._current_allowed or (None, None)
        if self._current_is_control:
            return
        in_window = (
            self.before_ts is not None
            and self.after_ts is None
            and ts > self.before_ts
        )
        if in_window:
            if label in self.window_counts and direction is not None:
                self.window_counts[label][direction] += 1
            elif label is None and self.findings_total == findings_before:
                # A non-allowed frame inside the window is classified by its
                # own finding (or by outside_control_window when reported).
                pass
            return
        if label is not None:
            self.outside_window_allowed_total += 1
            if len(self.outside_window_allowed_indexes) < MAX_OUTSIDE_WINDOW_INDEXES:
                self.outside_window_allowed_indexes.append(index)
        elif self.findings_total == findings_before:
            self.outside_window_other_total += 1

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
        allowed_direction: str | None = None
        if self.policy.allow_arp and src_mac == sender_mac and operation in (1, 2):
            vm_to_gateway = (
                sender_mac == self.policy.vm_wan_mac
                and sender_ip == self.policy.vm_wan_ipv4
                and target_ip == self.policy.gateway_ipv4
            )
            gateway_to_vm = (
                self.policy.gateway_mac is not None
                and sender_mac == self.policy.gateway_mac
                and sender_ip == self.policy.gateway_ipv4
                and target_ip == self.policy.vm_wan_ipv4
                and (operation != 2 or target_mac == self.policy.vm_wan_mac)
            )
            if vm_to_gateway:
                allowed_direction = "outbound"
            elif gateway_to_vm:
                allowed_direction = "inbound"
        if allowed_direction is not None:
            self.count_allowed("arp", allowed_direction)
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
                direction,
                src_mac,
                dst_mac,
                vlan,
            )
            return

        if more_fragments and not payload:
            self.add_finding(
                ts,
                src,
                dst,
                proto_name,
                None,
                None,
                "zero_payload_fragment",
                fragment_key=[src, dst, protocol, identification],
                **extra,
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
        if result.label is not None:
            l2_problem = self._allowed_l2_problem(
                direction, src_mac, dst_mac, vlan
            )
            if l2_problem is not None:
                self.add_finding(
                    ts,
                    src,
                    dst,
                    proto_name,
                    result.src_port,
                    result.dst_port,
                    "allowed_tuple_wrong_l2",
                    detail=l2_problem,
                    **extra,
                )
                result = _L4Result(
                    reason="allowed_tuple_wrong_l2",
                    src_port=result.src_port,
                    dst_port=result.dst_port,
                    udp_length=result.udp_length,
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
            self.count_allowed(result.label, direction)
        elif result.reason is not None:
            if result.reason != "allowed_tuple_wrong_l2":
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
    def _allowed_l2_problem(
        self,
        direction: str,
        src_mac: str,
        dst_mac: str,
        vlan: int | None,
    ) -> str | None:
        """Return why an allowed-tuple frame is not a real tunnel frame.

        The tap sits on the host bridge, so a genuine outbound frame from the
        VM has Ethernet source ``vm_wan_mac`` and destination ``gateway_mac``;
        a genuine inbound frame is the reverse.  The host never tags lab
        traffic, so any 802.1Q tag on an allowed tuple is also wrong.  A VM can
        still spoof these MACs, but an accidental or replayed/forged frame with
        the VM's own MAC as the inbound source is rejected.
        """
        if vlan is not None:
            return "vlan_tagged"
        if direction == "out":
            if src_mac == self.policy.vm_wan_mac and dst_mac == self.policy.gateway_mac:
                return None
        else:
            if src_mac == self.policy.gateway_mac and dst_mac == self.policy.vm_wan_mac:
                return None
        return "mac_mismatch"

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
        if state is None and len(self.fragment_states) >= MAX_FRAGMENT_ASSOCIATIONS:
            # Completed datagrams are no longer live.  Evict them first; only a
            # table full of unfinished datagrams is a resource failure.
            for completed_key in [
                candidate
                for candidate, value in self.fragment_states.items()
                if value.complete
            ]:
                del self.fragment_states[completed_key]
            if len(self.fragment_states) >= MAX_FRAGMENT_ASSOCIATIONS:
                self.add_finding(
                    ts,
                    src,
                    dst,
                    _proto_name(protocol),
                    None,
                    None,
                    "fragment_table_overflow",
                    live_associations=len(self.fragment_states),
                    limit=MAX_FRAGMENT_ASSOCIATIONS,
                )
                return
        if state is not None and not state.complete:
            if ts - state.first_ts <= FRAGMENT_WINDOW_SECONDS:
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
            # Expiring/replacing an unfinished allowed datagram is itself a
            # finding: otherwise a new datagram reusing the same key would
            # erase the fact that the earlier one never completed.
            if state.label is not None and not state.reported:
                self.add_finding(
                    ts,
                    state.src,
                    state.dst,
                    state.proto_name,
                    None,
                    None,
                    "incomplete_fragment",
                    detail="datagram_not_completed",
                    fragment_key=list(key),
                )
        prefix = result.udp_data_prefix
        wg_type = prefix[0] if len(prefix) >= 4 else None
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
            wg_type=wg_type,
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
        direction: str,
        src_mac: str,
        dst_mac: str,
        vlan: int | None,
    ) -> None:
        key = (src, dst, protocol, identification)
        state = self.fragment_states.get(key)
        reason: str | None = None
        detail: str | None = None
        if not payload:
            self.add_finding(
                ts,
                src,
                dst,
                proto_name,
                None,
                None,
                "zero_payload_fragment",
                fragment_key=list(key),
                **extra,
            )
            return
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
        elif (l2_problem := self._allowed_l2_problem(
            direction, src_mac, dst_mac, vlan
        )) is not None:
            self.add_finding(
                ts,
                src,
                dst,
                proto_name,
                None,
                None,
                "allowed_tuple_wrong_l2",
                detail=l2_problem,
                **extra,
            )
            state.reported = True
            return
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
            if reason is None and not more_fragments and state.label is not None:
                if state.wg_type is None:
                    # A fragmented allowed datagram whose first fragment did
                    # not even expose the four-byte WireGuard header cannot
                    # be shape-checked; fail closed rather than certify it.
                    reason = "allowed_tuple_not_wireguard"
                    detail = "short"
                elif (
                    state.udp_length is not None
                    and wireguard_length_problem(
                        state.wg_type, state.udp_length - 8
                    )
                    is not None
                ):
                    reason = "allowed_tuple_not_wireguard"
                    detail = "length"
            if reason is None:
                state.covered_end = end
                if not more_fragments:
                    state.complete = True
                if state.label is not None:
                    self.count_allowed(state.label, direction)
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
        """Reject any allowed fragmented datagram that never completed.

        Only called after the whole pcap was read.  If the capture itself was
        structurally truncated, incompleteness is expected and the verdict is
        INVALID rather than an inferred LEAK.  Every unfinished allowed
        association is judged, wherever it lies relative to the control
        window: an out-of-window boundary must not erase missing-tail
        evidence, and the finding is reported regardless of whether the
        capture also has an invalid reason.
        """
        for state in self.fragment_states.values():
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
                # datagram must account for exactly the IP payload.  With MF
                # set, the declared length must leave a genuine remainder.
                length_ok = (
                    udp_length is not None
                    and udp_length >= 8
                    and (
                        udp_length > len(payload)
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
                # A packet on the allowed tuple must at least look like a
                # WireGuard message.  This stops a plaintext payload from
                # being certified as tunnel traffic; it is not a cipher
                # authentication check.
                udp_data = payload[8:]
                shape_problem = wireguard_payload_problem(
                    udp_data, complete=not fragmented
                )
                if shape_problem is not None:
                    return _L4Result(
                        reason="allowed_tuple_not_wireguard",
                        src_port=src_port,
                        dst_port=dst_port,
                        detail=shape_problem,
                    )
                return _L4Result(
                    label=label,
                    src_port=src_port,
                    dst_port=dst_port,
                    udp_length=udp_length,
                    udp_data_prefix=udp_data[:4],
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
        if role == "before" and self.before_ts is None:
            self.before_ts = ts
        if role == "after" and self.after_ts is None:
            self.after_ts = ts
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


def _read_exact(stream, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining > 0:
        chunk = stream.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_pcap_stream(stream, scanner: _Scanner, meta: dict[str, Any], digest) -> None:
    """Classify every record from ``stream`` without loading the file.

    ``digest`` is updated with the exact bytes consumed, so the runner can
    bind the report to the capture it hashed.
    """

    def consumed(length: int) -> bytes:
        data = _read_exact(stream, length)
        digest.update(data)
        return data

    header = consumed(24)
    if len(header) < 24:
        raise CaptureInvalid("truncated_global_header")
    magic = header[0:4]
    if magic not in _PCAP_MAGIC:
        raise CaptureInvalid("unsupported_pcap_magic")
    endian, divisor, resolution, byte_order = _PCAP_MAGIC[magic]
    version_major, version_minor, _thiszone, _sigfigs, snaplen, network = struct.unpack(
        endian + "HHiIII", header[4:24]
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

    while True:
        record_header = consumed(16)
        if not record_header:
            break
        if len(record_header) < 16:
            raise CaptureInvalid("truncated_record_header")
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(
            endian + "IIII", record_header
        )
        if ts_frac >= divisor:
            raise CaptureInvalid("invalid_timestamp_fraction")
        if incl_len > orig_len:
            raise CaptureInvalid("record_length_inconsistent")
        if incl_len > snaplen:
            raise CaptureInvalid("record_exceeds_snaplen")
        frame = consumed(incl_len)
        if len(frame) < incl_len:
            raise CaptureInvalid("truncated_record_data")
        if incl_len < orig_len:
            # The capture itself is known to be missing wire bytes.  This is
            # not a frame-content problem: stop and mark the evidence INVALID.
            raise CaptureInvalid("snaplen_truncated_record")
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


def scan_capture_stream(
    stream,
    policy: policy_mod.Policy,
    control_before: str,
    control_after: str,
    *,
    expect_tunnel: str,
    tcpdump_stats_text: str | None,
    capture_argv: list[str],
    pcap_path: str | None = None,
    stats_error: str | None = None,
    stats_source: str | None = None,
    source: str | None = None,
    policy_sha256: str | None = None,
    capture_argv_file_sha256: str | None = None,
) -> dict[str, Any]:
    """Scan a classic pcap from a stream and return the canonical report.

    The file is never loaded whole: one global header, one 16-byte record
    header and one frame are held at a time.  The retained per-run state is
    counters, at most 1000 outside-window indexes and at most 4096 unfinished
    fragment associations.
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
    if expect_tunnel not in EXPECT_TUNNEL_VALUES:
        raise ValueError(
            "expect_tunnel must be one of " + ", ".join(EXPECT_TUNNEL_VALUES)
        )

    scanner = _Scanner(policy, control_before, control_after)
    meta: dict[str, Any] = {"format": "pcap"}
    invalid_reasons: list[str] = []
    structural_invalid = False
    source_digest = hashlib.sha256()
    try:
        _read_pcap_stream(stream, scanner, meta, source_digest)
    except CaptureInvalid as exc:
        structural_invalid = True
        invalid_reasons.append(str(exc))
        meta["packets_read"] = scanner.packets
    source_sha256 = source_digest.hexdigest()
    if not structural_invalid and not scanner.fragment_table_overflow:
        scanner.finalize_fragments()
    if scanner.fragment_table_overflow:
        invalid_reasons.append("fragment_table_overflow")

    stats: dict[str, int | None] | None = None
    stats_problem: str | None = stats_error
    stats_sha256: str | None = None
    stats_banner_ok = False
    if tcpdump_stats_text is not None:
        stats_banner_ok = check_stats_banner(tcpdump_stats_text)
        if not stats_banner_ok:
            invalid_reasons.append("capture_banner_mismatch")
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

    argv_problem = netplan_mod.check_capture_argv(capture_argv, pcap_path)
    if argv_problem is not None:
        invalid_reasons.append(argv_problem)
    # Evidence hashes always cover the exact file bytes.  The controller
    # hashes the argv file as written (which may be indented and newline
    # terminated); this value must therefore come from the caller that read
    # the file, never from a re-encoding of the parsed list.
    if capture_argv_file_sha256 is not None and (
        not isinstance(capture_argv_file_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", capture_argv_file_sha256) is None
    ):
        raise ValueError(
            "capture_argv_file_sha256 must be 64 lowercase hexadecimal characters"
        )
    capture_argv_canonical_sha256: str | None = None
    if isinstance(capture_argv, list) and all(
        isinstance(item, str) for item in capture_argv
    ):
        capture_argv_canonical_sha256 = hashlib.sha256(
            json.dumps(capture_argv, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ).hexdigest()

    if scanner.non_monotonic_timestamps:
        invalid_reasons.append("non_monotonic_timestamps")
    if scanner.packets == 0:
        invalid_reasons.append("zero_packets")

    flow_labels = {flow.label for flow in policy.allowed}
    window_counts: dict[str, dict[str, int]] = {
        label: {"outbound": 0, "inbound": 0} for label in flow_labels
    }
    for label, counts in scanner.window_counts.items():
        if label in window_counts:
            window_counts[label] = dict(counts)
    outside_window_allowed = scanner.outside_window_allowed_total
    outside_window_allowed_packets = list(scanner.outside_window_allowed_indexes)

    before_sightings = scanner.control_sightings["before"]
    after_sightings = scanner.control_sightings["after"]
    if before_sightings and after_sightings:
        before_ts = before_sightings[0]["ts"]
        after_ts = after_sightings[0]["ts"]
        if not before_ts < after_ts:
            invalid_reasons.append("control_order")
        else:
            if scanner.outside_window_other_total:
                invalid_reasons.append("outside_control_window")

    outbound_in_window = sum(
        counts["outbound"] for counts in window_counts.values()
    )
    inbound_in_window = sum(counts["inbound"] for counts in window_counts.values())
    labels_both_directions = sorted(
        label
        for label, counts in window_counts.items()
        if counts["outbound"] > 0 and counts["inbound"] > 0
    )
    inbound_total = sum(
        counts["inbound"]
        for label, counts in scanner.allowed_counts.items()
        if label != "arp"
    )
    if expect_tunnel == "up":
        # Both directions must be on the same declared relay flow: outbound
        # to relay A and inbound from relay B is not one tunnel.
        tunnel_satisfied = bool(labels_both_directions)
    elif expect_tunnel == "down":
        # A "down" phase must show no inbound allowed flow anywhere in the
        # capture: a keepalive after the after-control is still tunnel evidence.
        tunnel_satisfied = inbound_total == 0
    else:
        tunnel_satisfied = True
    if not tunnel_satisfied:
        invalid_reasons.append("tunnel_not_observed")

    missing = []
    if not before_sightings:
        missing.append(control_before)
    if not after_sightings:
        missing.append(control_after)
    if missing:
        invalid_reasons.append("missing_positive_controls")

    if scanner.leak_findings_total:
        verdict = "LEAK"
    elif invalid_reasons:
        verdict = "INVALID"
    else:
        verdict = "PASS"

    meta.update(
        {
            "source": source,
            "source_sha256": source_sha256,
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
            "non_monotonic_timestamps": scanner.non_monotonic_timestamps,
            "outside_window_allowed": outside_window_allowed,
            "outside_window_allowed_packets": outside_window_allowed_packets,
            "outside_window_allowed_truncated": (
                outside_window_allowed > len(outside_window_allowed_packets)
            ),
            "outside_window_other": scanner.outside_window_other_total,
            "tunnel_expectation": {
                "value": expect_tunnel,
                "outbound_in_window": outbound_in_window,
                "inbound_in_window": inbound_in_window,
                "labels_both_directions": labels_both_directions,
                "inbound_total": inbound_total,
                "satisfied": tunnel_satisfied,
            },
            "stats": stats,
            "stats_source": stats_source,
            "stats_sha256": stats_sha256,
            "stats_banner_ok": stats_banner_ok,
            "capture_argv": capture_argv,
            "capture_argv_sha256": capture_argv_file_sha256,
            "capture_argv_canonical_sha256": capture_argv_canonical_sha256,
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
def scan_capture(
    data: bytes,
    policy: policy_mod.Policy,
    control_before: str,
    control_after: str,
    **kwargs,
) -> dict[str, Any]:
    """Scan in-memory pcap bytes (compatibility wrapper around the stream API)."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("scan_capture data must be bytes")
    return scan_capture_stream(
        io.BytesIO(bytes(data)), policy, control_before, control_after, **kwargs
    )


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
    parser.add_argument(
        "--capture-argv-file",
        required=True,
        metavar="ARGV.json",
        help="JSON list of the exact tcpdump argv from netplan.py (only -w may differ)",
    )
    parser.add_argument(
        "--expect-tunnel",
        required=True,
        choices=EXPECT_TUNNEL_VALUES,
        help="up: require allowed traffic both ways inside the window; down: no inbound; any: report only",
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
        stream = open(args.pcap, "rb")
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

    try:
        capture_argv_bytes = pathlib.Path(args.capture_argv_file).read_bytes()
    except OSError as exc:
        print(f"pcapscan: capture argv file: {exc}", file=sys.stderr)
        return 2
    try:
        capture_argv = json.loads(capture_argv_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        print(f"pcapscan: capture argv file is not valid JSON: {exc}", file=sys.stderr)
        return 2
    capture_argv_file_sha256 = hashlib.sha256(capture_argv_bytes).hexdigest()

    try:
        with stream:
            report = scan_capture_stream(
                stream,
                policy,
                args.control_before,
                args.control_after,
                tcpdump_stats_text=stats_text,
                capture_argv=capture_argv,
                pcap_path=args.pcap,
                expect_tunnel=args.expect_tunnel,
                stats_error=stats_error,
                stats_source=args.tcpdump_stats,
                source=args.pcap,
                policy_sha256=hashlib.sha256(policy_bytes).hexdigest(),
                capture_argv_file_sha256=capture_argv_file_sha256,
            )
    except OSError as exc:
        print(f"pcapscan: capture: {exc}", file=sys.stderr)
        return 2
    sys.stdout.write(canonical_json(report))
    return {"PASS": 0, "LEAK": 1, "INVALID": 2}[report["verdict"]]


if __name__ == "__main__":
    raise SystemExit(main())
