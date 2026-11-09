#!/usr/bin/env python3
"""Offline acceptance tests for the vprlab external leak-monitor tooling.

Run from the repository root:

    python3 -B -W error -m unittest tools/leak-lab/test_leak_lab.py -v

Every capture is synthesized in memory with struct; nothing here touches the
network, a VM, nftables or the host configuration.  Regression tests are named
after the review finding they close (C1, I1..I8, F-01..F-14, M1..M9 and the
round-2 gpt/opus/pi identifiers).
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO

HERE = pathlib.Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
VM_TOOLS = HERE / "vm"
if str(VM_TOOLS) not in sys.path:
    sys.path.insert(0, str(VM_TOOLS))

import control  # noqa: E402
import hostcheck  # noqa: E402
import netplan  # noqa: E402
import pcapscan  # noqa: E402
import policy  # noqa: E402
import tsnames  # noqa: E402

VM_MAC = "52:54:00:76:70:02"
GW_MAC = "52:54:00:76:70:01"
VM_IP = "10.250.0.2"
GW_IP = "10.250.0.1"
WG_IP = "185.65.134.10"  # public Mullvad relay endpoint (outer WireGuard peer)
WG_PORT = 51820
SINK_IP = GW_IP
SINK_PORT = 39001
NONCE_A = "0123456789abcdef" * 2
NONCE_B = "fedcba9876543210" * 2
NONCE_C = "11111111111111111111111111111111"

#: The exact tcpdump argv `netplan.py` prints (minus the shell redirection).
CAPTURE_ARGV = [
    "tcpdump",
    "-i",
    "vprlab-tap0",
    "-nn",
    "-U",
    "--immediate-mode",
    "-B",
    "8192",
    "-s",
    "0",
    "-w",
    "vprlab-capture.pcap",
]
CAPTURE_BANNER = (
    "tcpdump: listening on vprlab-tap0, link-type EN10MB (Ethernet), "
    "snapshot length 262144 bytes\n"
)


# --------------------------------------------------------------------------
# policy fixtures
# --------------------------------------------------------------------------
def policy_document(**overrides):
    document = {
        "schema_version": 1,
        "vm_wan_mac": VM_MAC,
        "gateway_ipv4": GW_IP,
        "vm_wan_ipv4": VM_IP,
        "gateway_mac": GW_MAC,
        "allowed": [
            {"proto": "udp", "dst_ipv4": WG_IP, "dst_port": WG_PORT, "label": "mullvad-wg"}
        ],
        "allow_arp": True,
        "positive_control": {"sink_ipv4": SINK_IP, "sink_udp_port": SINK_PORT},
        "ipv6_allowed": False,
    }
    document.update(overrides)
    return document


def make_policy(**overrides):
    return policy.parse_policy(policy_document(**overrides))


# --------------------------------------------------------------------------
# packet builders
# --------------------------------------------------------------------------
def ethernet(payload, ethertype, *, src=VM_MAC, dst=GW_MAC, vlan=None):
    if vlan is not None:
        header = (
            bytes.fromhex(dst.replace(":", ""))
            + bytes.fromhex(src.replace(":", ""))
            + struct.pack("!HHH", 0x8100, vlan, ethertype)
        )
    else:
        header = (
            bytes.fromhex(dst.replace(":", ""))
            + bytes.fromhex(src.replace(":", ""))
            + struct.pack("!H", ethertype)
        )
    return header + payload


def ipv4_packet(
    src,
    dst,
    protocol,
    payload,
    *,
    ident=1,
    more_fragments=False,
    frag_units=0,
    total_length=None,
    ihl_bytes=None,
):
    flags = 0x2000 if more_fragments else 0
    if total_length is None:
        total_length = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        ident,
        flags | (frag_units & 0x1FFF),
        64,
        protocol,
        0,
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )
    if ihl_bytes is not None:
        header = header[:0] + bytes([ihl_bytes]) + header[1:]
    return header + payload


def udp_segment(sport, dport, payload=b"", *, length=None):
    if length is None:
        length = 8 + len(payload)
    return struct.pack("!HHHH", sport, dport, length, 0) + payload


def tcp_segment(sport, dport):
    return struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 0x50, 0x02, 8192, 0, 0)


def arp_packet(operation, sender_mac, sender_ip, target_mac, target_ip):
    return (
        struct.pack("!HHBBH", 1, 0x0800, 6, 4, operation)
        + bytes.fromhex(sender_mac.replace(":", ""))
        + socket.inet_aton(sender_ip)
        + bytes.fromhex(target_mac.replace(":", ""))
        + socket.inet_aton(target_ip)
    )


def ipv4_frame(
    l4,
    *,
    src_ip=VM_IP,
    dst_ip=WG_IP,
    protocol=17,
    src_mac=VM_MAC,
    dst_mac=GW_MAC,
    ident=1,
    more_fragments=False,
    frag_units=0,
    total_length=None,
    vlan=None,
    ihl_bytes=None,
):
    packet = ipv4_packet(
        src_ip,
        dst_ip,
        protocol,
        l4,
        ident=ident,
        more_fragments=more_fragments,
        frag_units=frag_units,
        total_length=total_length,
        ihl_bytes=ihl_bytes,
    )
    return ethernet(packet, 0x0800, src=src_mac, dst=dst_mac, vlan=vlan)


def wg_data(blocks=1):
    """A plausible WireGuard transport-data message (type 4)."""
    return b"\x04\x00\x00\x00" + b"\x00" * 12 + b"\x00" * (16 * blocks)


def wg_initiation():
    return b"\x01\x00\x00\x00" + b"\x00" * 144


def wg_response():
    return b"\x02\x00\x00\x00" + b"\x00" * 88


def wg_cookie_reply():
    return b"\x03\x00\x00\x00" + b"\x00" * 60


def wg_outbound(**kwargs):
    return ipv4_frame(udp_segment(40000, WG_PORT, wg_data()), **kwargs)


def wg_inbound(**kwargs):
    return ipv4_frame(
        udp_segment(WG_PORT, 40000, wg_data()),
        src_ip=WG_IP,
        dst_ip=VM_IP,
        src_mac=GW_MAC,
        dst_mac=VM_MAC,
        **kwargs,
    )


def dns_outbound():
    return ipv4_frame(udp_segment(40000, 53, b"\x00" * 12), dst_ip="1.1.1.1")


def control_frame(nonce=NONCE_A, payload=None, **kwargs):
    if payload is None:
        payload = policy.control_payload(nonce)
    return ipv4_frame(
        udp_segment(40000, SINK_PORT, payload), dst_ip=SINK_IP, **kwargs
    )


def arp_frame(operation, sender_mac, sender_ip, target_mac, target_ip, *,
              src_mac=None, dst_mac="ff:ff:ff:ff:ff:ff"):
    return ethernet(
        arp_packet(operation, sender_mac, sender_ip, target_mac, target_ip),
        0x0806,
        src=sender_mac if src_mac is None else src_mac,
        dst=dst_mac,
    )


def pcap_from_records(
    records,
    *,
    linktype=1,
    snaplen=262144,
    endian="<",
    nsec=False,
    timestamps=None,
):
    magic = 0xA1B23C4D if nsec else 0xA1B2C3D4
    data = bytearray(struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, snaplen, linktype))
    for index, (frame, incl_len, orig_len) in enumerate(records):
        if timestamps is None:
            ts_sec, ts_frac = 1_700_000_000 + index, 0
        else:
            value = timestamps[index]
            ts_sec = int(value)
            ts_frac = round((value - ts_sec) * (1_000_000_000 if nsec else 1_000_000))
        data += struct.pack(endian + "IIII", ts_sec, ts_frac, incl_len, orig_len)
        data += frame
    return bytes(data)


def pcap(frames, **kwargs):
    return pcap_from_records(
        [(frame, len(frame), len(frame)) for frame in frames], **kwargs
    )


def zero_stats(captured, *, received=None, kernel=0, interface=0):
    """A real tcpdump 4.99 (Debian 13) stderr summary."""
    if received is None:
        received = captured
    return (
        CAPTURE_BANNER
        + f"{captured} packets captured\n"
        f"{received} packets received by filter\n"
        f"{kernel} packets dropped by kernel\n"
        f"{interface} packets dropped by interface\n"
    )


def phase_frames(*middle, before=NONCE_A, after=NONCE_B):
    return [control_frame(before), *middle, control_frame(after)]


def scan(frames, pol=None, *, before=NONCE_A, after=NONCE_B, stats=None, **kwargs):
    if stats is None:
        stats = zero_stats(len(frames))
    kwargs.setdefault("capture_argv", CAPTURE_ARGV)
    kwargs.setdefault("expect_tunnel", "any")
    return pcapscan.scan_capture(
        pcap(frames),
        pol if pol is not None else make_policy(),
        before,
        after,
        tcpdump_stats_text=stats,
        **kwargs,
    )


def scan_middle(middle, pol=None, **kwargs):
    return scan(phase_frames(*middle), pol, **kwargs)


def scan_bytes(data, pol, before, after, **kwargs):
    """scan_capture with the mandatory provenance defaults for the fixture."""
    kwargs.setdefault("capture_argv", CAPTURE_ARGV)
    kwargs.setdefault("expect_tunnel", "any")
    return pcapscan.scan_capture(data, pol, before, after, **kwargs)


def directions(report, label):
    counts = report["allowed_counts"][label]
    return counts["outbound"], counts["inbound"]


def reasons(report):
    return [finding["reason"] for finding in report["findings"]]


def invalid_reasons(report):
    return report["capture_meta"]["invalid_reasons"]


# --------------------------------------------------------------------------
# pcap framing, stats, controls, verdict precedence
# --------------------------------------------------------------------------
class PcapScanTests(unittest.TestCase):
    def test_allowed_wg_both_directions_passes_with_controls(self):
        report = scan(
            [
                control_frame(NONCE_A),
                wg_outbound(),
                wg_inbound(),
                control_frame(NONCE_B),
            ]
        )
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["packets"], 4)
        self.assertEqual(directions(report, "mullvad-wg"), (1, 1))
        self.assertEqual(report["allowed_counts"]["mullvad-wg"]["outbound"], 1)
        self.assertEqual(report["allowed_counts"]["arp"], {"outbound": 0, "inbound": 0})
        self.assertEqual(report["positive_controls_seen"], [NONCE_A, NONCE_B])
        self.assertEqual(report["findings"], [])
        self.assertEqual(invalid_reasons(report), [])

    def test_dns_udp_is_leak(self):
        report = scan_middle([dns_outbound()])
        self.assertEqual(report["verdict"], "LEAK")
        self.assertEqual(report["findings"][0]["reason"], "udp_not_allowed")
        self.assertEqual(report["findings"][0]["dst"], "1.1.1.1")
        self.assertEqual(report["findings"][0]["dst_port"], 53)

    def test_inbound_dns_udp_is_leak(self):
        dns = ipv4_frame(
            udp_segment(53, 40000, b"\x00" * 12),
            src_ip="1.1.1.1",
            dst_ip=VM_IP,
            src_mac=GW_MAC,
            dst_mac=VM_MAC,
        )
        report = scan_middle([dns])
        self.assertEqual(report["verdict"], "LEAK")
        self.assertEqual(report["findings"][0]["reason"], "udp_not_allowed")

    def test_tcp_443_is_leak(self):
        tcp = ipv4_frame(tcp_segment(40000, 443), dst_ip="93.184.216.34", protocol=6)
        report = scan_middle([tcp])
        self.assertEqual(report["verdict"], "LEAK")
        self.assertEqual(report["findings"][0]["reason"], "tcp_not_allowed")
        self.assertEqual(report["findings"][0]["dst_port"], 443)

    def test_icmp_is_leak(self):
        icmp = ipv4_frame(
            struct.pack("!BBH", 8, 0, 0) + b"ping", dst_ip="1.1.1.1", protocol=1
        )
        report = scan_middle([icmp])
        self.assertEqual(report["verdict"], "LEAK")
        self.assertEqual(report["findings"][0]["reason"], "icmp_not_allowed")

    def test_opus_m5_inbound_icmp_error_is_a_finding(self):
        # A WAN-path PMTU/unreachable error is indistinguishable from injected
        # traffic; the phase contract allows only the declared outer UDP flows.
        error = ipv4_frame(
            struct.pack("!BBH", 3, 4, 0) + b"\x00" * 8,
            src_ip="203.0.113.1",
            dst_ip=VM_IP,
            src_mac=GW_MAC,
            dst_mac=VM_MAC,
            protocol=1,
        )
        report = scan_middle([error])
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("icmp_not_allowed", reasons(report))
        self.assertEqual(report["findings"][0]["src"], "203.0.113.1")

    def test_allowed_ip_wrong_port_is_leak(self):
        wrong_port = ipv4_frame(udp_segment(40000, WG_PORT + 1, b"x"))
        report = scan_middle([wrong_port])
        self.assertEqual(report["verdict"], "LEAK")
        self.assertEqual(report["findings"][0]["reason"], "udp_not_allowed")
        self.assertEqual(report["findings"][0]["dst_port"], WG_PORT + 1)

    def test_ipv6_frame_is_leak(self):
        ipv6 = struct.pack(
            "!IHBB16s16s",
            6 << 28,
            0,
            17,
            64,
            socket.inet_pton(socket.AF_INET6, "2001:db8::2"),
            socket.inet_pton(socket.AF_INET6, "2001:db8::1"),
        )
        report = scan_middle([ethernet(ipv6, 0x86DD)])
        self.assertEqual(report["verdict"], "LEAK")
        self.assertEqual(report["findings"][0]["reason"], "ipv6_not_allowed")
        self.assertEqual(report["findings"][0]["proto"], "ipv6")

    def test_8021q_tagged_leak_detected(self):
        dns = ipv4_frame(
            udp_segment(40000, 53, b"\x00" * 12), dst_ip="1.1.1.1", vlan=100
        )
        report = scan_middle([dns])
        self.assertEqual(report["verdict"], "LEAK")
        self.assertEqual(report["findings"][0]["reason"], "udp_not_allowed")
        self.assertEqual(report["findings"][0]["vlan"], 100)

    def test_opus_m2_vlan_tagged_allowed_wg_is_a_finding(self):
        # The host never tags lab traffic; a tagged frame on an allowed tuple
        # cannot be genuine tunnel traffic.
        report = scan_middle([wg_outbound(vlan=100), wg_inbound(vlan=100)])
        self.assertEqual(report["verdict"], "LEAK")
        self.assertEqual(
            reasons(report),
            ["allowed_tuple_wrong_l2", "allowed_tuple_wrong_l2"],
        )
        self.assertEqual(directions(report, "mullvad-wg"), (0, 0))

    def test_missing_after_control_is_invalid(self):
        report = scan([control_frame(NONCE_A), wg_outbound()])
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("missing_positive_controls", invalid_reasons(report))
        self.assertEqual(report["capture_meta"]["missing_controls"], [NONCE_B])

    def test_missing_before_control_is_invalid(self):
        report = scan([wg_outbound(), control_frame(NONCE_B)])
        self.assertEqual(report["verdict"], "INVALID")
        self.assertEqual(report["capture_meta"]["missing_controls"], [NONCE_A])

    def test_wrong_control_nonce_is_leak(self):
        report = scan([control_frame(NONCE_C), control_frame(NONCE_B)])
        self.assertEqual(report["verdict"], "LEAK")
        self.assertEqual(report["findings"][0]["reason"], "unexpected_control_nonce")
        self.assertEqual(report["positive_controls_seen"], [NONCE_B])

    def test_malformed_control_payload_is_leak(self):
        bad = policy.CONTROL_PREFIX + NONCE_A.upper().encode("ascii")
        report = scan([control_frame(payload=bad), control_frame(NONCE_B)])
        self.assertEqual(report["verdict"], "LEAK")
        self.assertEqual(report["findings"][0]["reason"], "malformed_control")

    def test_nsec_and_big_endian_pcaps_parse(self):
        frames = phase_frames(wg_outbound(), wg_inbound())
        for endian, nsec, resolution, byte_order in (
            ("<", False, "microsecond", "little"),
            ("<", True, "nanosecond", "little"),
            (">", False, "microsecond", "big"),
            (">", True, "nanosecond", "big"),
        ):
            with self.subTest(endian=endian, nsec=nsec):
                report = scan_bytes(
                    pcap(frames, endian=endian, nsec=nsec),
                    make_policy(),
                    NONCE_A,
                    NONCE_B,
                    tcpdump_stats_text=zero_stats(len(frames)),
                )
                self.assertEqual(report["verdict"], "PASS")
                self.assertEqual(
                    report["capture_meta"]["timestamp_resolution"], resolution
                )
                self.assertEqual(report["capture_meta"]["endianness"], byte_order)

    def test_non_ethernet_linktype_is_invalid(self):
        report = scan_bytes(
            pcap([], linktype=101),
            make_policy(),
            NONCE_A,
            NONCE_B,
            tcpdump_stats_text=zero_stats(0),
        )
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("unsupported_linktype_101", invalid_reasons(report))

    def test_zero_packets_is_invalid(self):
        report = scan_bytes(
            pcap([]), make_policy(), NONCE_A, NONCE_B, tcpdump_stats_text=zero_stats(0)
        )
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("zero_packets", invalid_reasons(report))

    def test_foreign_frame_is_finding(self):
        foreign = ethernet(
            ipv4_packet("192.0.2.10", "192.0.2.20", 17, udp_segment(1234, 53, b"")),
            0x0800,
            src="02:00:00:00:00:01",
            dst="02:00:00:00:00:02",
        )
        report = scan_middle([foreign])
        self.assertEqual(report["verdict"], "LEAK")
        self.assertEqual(report["findings"][0]["reason"], "foreign_frame")
        self.assertEqual(report["findings"][0]["src"], "192.0.2.10")

    def test_findings_are_capped_at_200(self):
        middle = [dns_outbound() for _ in range(205)]
        report = scan_middle(middle)
        self.assertEqual(report["verdict"], "LEAK")
        self.assertEqual(len(report["findings"]), 200)
        self.assertEqual(report["findings_total"], 205)
        self.assertTrue(report["findings_truncated"])

    def test_canonical_json_roundtrip(self):
        report = scan_middle([wg_outbound()])
        self.assertEqual(
            pcapscan.canonical_json(report),
            json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n",
        )

    # ---------------------------------------------------------------- C1/I1
    def test_c1_every_drop_summary_is_checked_kernel(self):
        stats = zero_stats(3) + (
            "3 packets captured\n9 packets received by filter\n"
            "6 packets dropped by kernel\n"
        )
        report = scan_middle([wg_outbound()], stats=stats)
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("packet_drops", invalid_reasons(report))

    def test_c1_every_drop_summary_is_checked_interface(self):
        stats = zero_stats(3) + (
            "0 packets dropped by interface\n7 packets dropped by interface\n"
        )
        report = scan_middle([wg_outbound()], stats=stats)
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("packet_drops", invalid_reasons(report))

    def test_i1_incomplete_stats_without_kernel_counter_is_invalid(self):
        report = scan_middle(
            [wg_outbound()], stats="0 packets dropped by interface\n"
        )
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("stats_incomplete", invalid_reasons(report))

    def test_i1_stats_without_captured_counter_is_invalid(self):
        stats = "0 packets received by filter\n0 packets dropped by kernel\n"
        report = scan_middle([wg_outbound()], stats=stats)
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("stats_incomplete", invalid_reasons(report))

    def test_i1_captured_count_must_equal_records(self):
        report = scan_middle([wg_outbound()], stats=zero_stats(300))
        self.assertEqual(report["packets"], 3)
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("stats_packet_count_mismatch", invalid_reasons(report))

    def test_i1_contradictory_summaries_are_invalid(self):
        # Counters are cumulative in a real tcpdump run: a later summary may
        # stay equal or grow, never shrink.
        stats = zero_stats(4) + (
            "3 packets captured\n3 packets received by filter\n"
            "0 packets dropped by kernel\n"
        )
        report = scan_middle([wg_outbound()], stats=stats)
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("stats_contradictory", invalid_reasons(report))

    def test_pi_i1_oneline_captured_and_received_are_parsed(self):
        # SIGUSR1 one-line: captured=4, received=100 is an unread ring tail.
        frames = phase_frames(wg_outbound(), wg_inbound())
        stats = zero_stats(4) + (
            "tcpdump: 4 packets captured, 100 packets received by filter, "
            "0 packets dropped by kernel\n"
        )
        report = scan(frames, stats=stats, expect_tunnel="up")
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("unread_capture_tail", invalid_reasons(report))
        self.assertEqual(report["capture_meta"]["stats"]["captured"], 4)
        self.assertEqual(report["capture_meta"]["stats"]["received"], 100)

    def test_pi_i1_oneline_captured_must_equal_records(self):
        frames = phase_frames(wg_outbound(), wg_inbound())
        stats = zero_stats(4) + (
            "tcpdump: 100 packets captured, 100 packets received by filter, "
            "0 packets dropped by kernel\n"
        )
        report = scan(frames, stats=stats, expect_tunnel="up")
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("stats_packet_count_mismatch", invalid_reasons(report))

    def test_pi_i1_oneline_as_final_summary_is_binding(self):
        frames = phase_frames(wg_outbound(), wg_inbound())
        good = CAPTURE_BANNER + (
            "tcpdump: 4 packets captured, 4 packets received by filter, "
            "0 packets dropped by kernel\n"
        )
        report = scan(frames, stats=good, expect_tunnel="up")
        self.assertEqual(report["verdict"], "PASS")
        short = CAPTURE_BANNER + (
            "tcpdump: 3 packets captured, 3 packets received by filter, "
            "0 packets dropped by kernel\n"
        )
        report = scan(frames, stats=short, expect_tunnel="up")
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("stats_packet_count_mismatch", invalid_reasons(report))

    def test_pi_i1_oneline_counters_must_not_decrease(self):
        frames = phase_frames(wg_outbound(), wg_inbound())
        stats = zero_stats(4) + (
            "tcpdump: 3 packets captured, 3 packets received by filter, "
            "0 packets dropped by kernel\n"
        )
        report = scan(frames, stats=stats, expect_tunnel="up")
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("stats_contradictory", invalid_reasons(report))

    def test_pi_i1_legitimate_midrun_oneline_is_accepted(self):
        frames = phase_frames(wg_outbound(), wg_inbound())
        stats = (
            CAPTURE_BANNER
            + "tcpdump: 2 packets captured, 2 packets received by filter, "
            "0 packets dropped by kernel\n"
            + "4 packets captured\n4 packets received by filter\n"
            "0 packets dropped by kernel\n0 packets dropped by interface\n"
        )
        report = scan(frames, stats=stats, expect_tunnel="up")
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["capture_meta"]["stats"]["captured"], 4)

    def test_pi_i1_every_summary_must_be_internally_consistent(self):
        frames = phase_frames(wg_outbound(), wg_inbound())
        stats = zero_stats(4) + (
            "tcpdump: 4 packets captured, 3 packets received by filter, "
            "0 packets dropped by kernel\n"
        )
        report = scan(frames, stats=stats, expect_tunnel="up")
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("unread_capture_tail", invalid_reasons(report))

    def test_f01_valid_prefix_with_larger_captured_count_is_invalid(self):
        frames = phase_frames(wg_outbound())
        prefix = frames[:3]
        report = scan_bytes(
            pcap(prefix),
            make_policy(),
            NONCE_A,
            NONCE_B,
            tcpdump_stats_text=zero_stats(4),
        )
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("stats_packet_count_mismatch", invalid_reasons(report))

    def test_received_must_equal_captured_unread_tail_is_invalid(self):
        # A ring tail that tcpdump counted as received but never wrote is a
        # blind spot: the unread packets are not in the pcap and are never
        # classified.  The controller decision is strict equality.
        report = scan_middle(
            [wg_outbound()],
            stats=zero_stats(3, received=100),
        )
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("unread_capture_tail", invalid_reasons(report))
        self.assertEqual(report["capture_meta"]["stats"]["received"], 100)
        self.assertEqual(report["capture_meta"]["stats"]["captured"], 3)

    def test_received_equal_to_captured_passes(self):
        report = scan_middle([wg_outbound()], stats=zero_stats(3, received=3))
        self.assertEqual(report["verdict"], "PASS")

    def test_received_less_than_captured_is_invalid(self):
        report = scan_middle([wg_outbound()], stats=zero_stats(3, received=2))
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("unread_capture_tail", invalid_reasons(report))

    def test_m1_tcpdump_error_line_is_invalid(self):
        stats = zero_stats(3) + "tcpdump: pcap_loop: The interface disappeared\n"
        report = scan_middle([wg_outbound()], stats=stats)
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("stats_error_line", invalid_reasons(report))

    def test_m3_sigusr1_one_line_with_drops_is_packet_drops(self):
        stats = zero_stats(3) + (
            "tcpdump: 3 packets captured, 3 packets received by filter, "
            "2 packets dropped by kernel\n"
        )
        report = scan_middle([wg_outbound()], stats=stats)
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("packet_drops", invalid_reasons(report))

    def test_m3_sigusr1_one_line_with_zero_drops_is_accepted(self):
        stats = zero_stats(3) + (
            "tcpdump: 3 packets captured, 3 packets received by filter, "
            "0 packets dropped by kernel\n"
        )
        report = scan_middle([wg_outbound()], stats=stats)
        self.assertEqual(report["verdict"], "PASS")

    def test_tcpdump_listening_banner_is_not_an_error(self):
        report = scan_middle([wg_outbound()], stats=zero_stats(3))
        self.assertEqual(report["verdict"], "PASS")
        self.assertTrue(report["capture_meta"]["stats_banner_ok"])

    def test_banner_must_name_the_lab_tap_and_ethernet(self):
        for banner in (
            "",
            "tcpdump: listening on eth0, link-type EN10MB (Ethernet), "
            "snapshot length 262144 bytes\n",
            "tcpdump: listening on vprlab-tap0, link-type LINUX_SLL (Linux cooked), "
            "snapshot length 262144 bytes\n",
        ):
            with self.subTest(banner=banner):
                stats = (
                    banner
                    + "3 packets captured\n3 packets received by filter\n"
                    "0 packets dropped by kernel\n0 packets dropped by interface\n"
                )
                report = scan_middle([wg_outbound()], stats=stats)
                self.assertEqual(report["verdict"], "INVALID")
                self.assertIn("capture_banner_mismatch", invalid_reasons(report))

    def test_banner_must_be_unique(self):
        stats = zero_stats(3) + CAPTURE_BANNER
        report = scan_middle([wg_outbound()], stats=stats)
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("capture_banner_mismatch", invalid_reasons(report))

    def test_gpt_m1_banner_must_be_first_nonempty_line(self):
        stats = (
            "3 packets captured\n3 packets received by filter\n"
            "0 packets dropped by kernel\n0 packets dropped by interface\n"
            + CAPTURE_BANNER
        )
        report = scan_middle([wg_outbound()], stats=stats)
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("capture_banner_mismatch", invalid_reasons(report))

    def test_gpt_m1_banner_substring_inside_another_line_is_rejected(self):
        stats = zero_stats(3) + (
            "unrelated: " + pcapscan.REQUIRED_STATS_BANNER + " garbage\n"
        )
        report = scan_middle([wg_outbound()], stats=stats)
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("capture_banner_mismatch", invalid_reasons(report))

    def test_gpt_m1_second_foreign_listening_line_is_rejected(self):
        stats = zero_stats(3) + (
            "tcpdump: listening on eth0, link-type EN10MB (Ethernet), "
            "snapshot length 262144 bytes\n"
        )
        report = scan_middle([wg_outbound()], stats=stats)
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("capture_banner_mismatch", invalid_reasons(report))

    def test_capture_argv_must_match_netplan_exactly(self):
        report = scan_middle([wg_outbound()])
        self.assertEqual(report["verdict"], "PASS")
        argv = report["capture_meta"]["capture_argv"]
        self.assertEqual(argv, CAPTURE_ARGV)
        self.assertIsNone(report["capture_meta"]["capture_argv_sha256"])
        self.assertEqual(
            report["capture_meta"]["capture_argv_canonical_sha256"],
            pcapscan.hashlib.sha256(
                json.dumps(CAPTURE_ARGV, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
        )

    def test_capture_argv_sha256_is_the_exact_file_bytes(self):
        report = scan_middle(
            [wg_outbound()], capture_argv_file_sha256="a" * 64
        )
        self.assertEqual(
            report["capture_meta"]["capture_argv_sha256"], "a" * 64
        )

    def test_capture_argv_filter_or_wrong_format_is_invalid(self):
        cases = (
            CAPTURE_ARGV[:2] + ["udp"] + CAPTURE_ARGV[2:],
            [item for item in CAPTURE_ARGV if item != "--immediate-mode"],
            [item for item in CAPTURE_ARGV if item != "-U"],
            [item for item in CAPTURE_ARGV if item != "-nn"],
            [item if item != "-s" else "-snaplen" for item in CAPTURE_ARGV],
            [item if item != "0" else "65535" for item in CAPTURE_ARGV],
            [item if item != "vprlab-tap0" else "eth0" for item in CAPTURE_ARGV],
            # the pre-buffer argv (libpcap's 2 MiB default ring) and a smaller ring
            [item for item in CAPTURE_ARGV if item not in ("-B", "8192")],
            [item if item != "8192" else "2048" for item in CAPTURE_ARGV],
            CAPTURE_ARGV[:-1] + [""],
            "tcpdump -i vprlab-tap0",
        )
        for argv in cases:
            with self.subTest(argv=argv):
                report = scan_middle([wg_outbound()], capture_argv=argv)
                self.assertEqual(report["verdict"], "INVALID")
                self.assertTrue(
                    {"capture_argv_invalid", "capture_argv_mismatch"}
                    & set(invalid_reasons(report))
                )

    def test_capture_argv_file_path_may_differ(self):
        argv = CAPTURE_ARGV[:-1] + ["/var/tmp/phase-17.pcap"]
        report = scan_middle(
            [wg_outbound()],
            capture_argv=argv,
            pcap_path="/var/tmp/phase-17.pcap",
        )
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["capture_meta"]["capture_argv"][-1], "/var/tmp/phase-17.pcap")

    def test_opus_m7_capture_argv_w_must_realpath_match_pcap(self):
        report = scan_middle(
            [wg_outbound()],
            capture_argv=CAPTURE_ARGV,
            pcap_path="/var/tmp/phase-17.pcap",
        )
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("capture_argv_mismatch", invalid_reasons(report))
        for path in ("/dev/null", "-"):
            with self.subTest(path=path):
                argv = CAPTURE_ARGV[:-1] + [path]
                report = scan_middle(
                    [wg_outbound()],
                    capture_argv=argv,
                    pcap_path="/var/tmp/phase-17.pcap",
                )
                self.assertEqual(report["verdict"], "INVALID")
                self.assertIn("capture_argv_mismatch", invalid_reasons(report))

    def test_m1_stats_hash_and_source_recorded(self):
        report = scan_middle(
            [wg_outbound()],
            stats=zero_stats(3),
            stats_source="phase.stderr",
        )
        meta = report["capture_meta"]
        self.assertEqual(meta["stats_source"], "phase.stderr")
        self.assertEqual(
            meta["stats_sha256"],
            pcapscan.hashlib.sha256(zero_stats(3).encode()).hexdigest(),
        )

    def test_f03_api_requires_stats_text(self):
        with self.assertRaises(ValueError):
            scan_bytes(
                pcap([control_frame(NONCE_A), control_frame(NONCE_B)]),
                make_policy(),
                NONCE_A,
                NONCE_B,
                tcpdump_stats_text=None,
            )

    def test_stats_unreadable_is_invalid(self):
        report = scan_bytes(
            pcap([control_frame(NONCE_A), control_frame(NONCE_B)]),
            make_policy(),
            NONCE_A,
            NONCE_B,
            tcpdump_stats_text=None,
            stats_error="stats_unreadable",
        )
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("stats_unreadable", invalid_reasons(report))

    # ------------------------------------------------------------- controls
    def test_f04_before_and_after_nonced_controls_are_required(self):
        report = scan([control_frame(NONCE_A), wg_outbound()])
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("missing_positive_controls", invalid_reasons(report))

    def test_i6_duplicate_before_and_after_nonce_is_rejected(self):
        with self.assertRaises(ValueError):
            scan([control_frame(NONCE_A)], before=NONCE_A, after=NONCE_A)

    def test_i6_nonces_must_be_well_formed(self):
        with self.assertRaises(ValueError):
            scan([control_frame(NONCE_A)], before="A" * 32, after=NONCE_B)

    def test_f05_replayed_control_is_a_leak_finding(self):
        frames = [
            control_frame(NONCE_A),
            control_frame(NONCE_A),
            wg_outbound(),
            control_frame(NONCE_B),
        ]
        report = scan(frames)
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("replayed_control", reasons(report))
        self.assertEqual(report["capture_meta"]["controls"]["before"]["packets"], 2)

    def test_control_order_is_enforced(self):
        frames = [control_frame(NONCE_B), control_frame(NONCE_A)]
        report = scan(frames)
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("control_order", invalid_reasons(report))

    def test_outside_window_allowed_flow_is_counted_not_invalid(self):
        # A live tunnel keeps sending keepalives/handshakes outside the marker
        # window.  Those records are still fully classified, so an allowed one
        # is informational evidence rather than an invalid capture.
        frames = [wg_outbound(), control_frame(NONCE_A), control_frame(NONCE_B)]
        report = scan(frames)
        self.assertEqual(report["verdict"], "PASS")
        self.assertNotIn("outside_control_window", invalid_reasons(report))
        self.assertEqual(report["capture_meta"]["outside_window_allowed"], 1)
        self.assertEqual(
            report["capture_meta"]["outside_window_allowed_packets"], [0]
        )
        self.assertEqual(directions(report, "mullvad-wg"), (1, 0))

    def test_trailing_allowed_record_outside_window_is_counted_not_invalid(self):
        frames = [control_frame(NONCE_A), control_frame(NONCE_B), wg_inbound()]
        report = scan(frames)
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["capture_meta"]["outside_window_allowed"], 1)
        self.assertEqual(directions(report, "mullvad-wg"), (0, 1))

    def test_leak_outside_window_is_leak(self):
        frames = [dns_outbound(), control_frame(NONCE_A), control_frame(NONCE_B)]
        report = scan(frames)
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("udp_not_allowed", reasons(report))
        self.assertNotIn("outside_control_window", invalid_reasons(report))

    def test_gpt_i6_cold_neighbour_arp_before_control_is_allowed(self):
        request = arp_frame(1, VM_MAC, VM_IP, "00:00:00:00:00:00", GW_IP)
        reply = arp_frame(2, GW_MAC, GW_IP, VM_MAC, VM_IP, dst_mac=VM_MAC)
        report = scan(
            [request, reply, control_frame(NONCE_A), wg_outbound(), control_frame(NONCE_B)]
        )
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["capture_meta"]["outside_window_allowed"], 2)
        self.assertEqual(
            report["allowed_counts"]["arp"], {"outbound": 1, "inbound": 1}
        )
        self.assertEqual(invalid_reasons(report), [])

    def test_non_monotonic_timestamps_are_invalid(self):
        frames = [control_frame(NONCE_B), wg_outbound(), control_frame(NONCE_A)]
        report = scan_bytes(
            pcap_from_records(
                [(frame, len(frame), len(frame)) for frame in frames],
                timestamps=[1_700_000_103.0, 1_700_000_102.0, 1_700_000_101.0],
            ),
            make_policy(),
            NONCE_A,
            NONCE_B,
            tcpdump_stats_text=zero_stats(3),
        )
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("non_monotonic_timestamps", invalid_reasons(report))

    def test_reversed_control_order_with_monotonic_clock_is_control_order(self):
        frames = [control_frame(NONCE_B), wg_outbound(), control_frame(NONCE_A)]
        report = scan(frames)
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("control_order", invalid_reasons(report))
        self.assertNotIn("non_monotonic_timestamps", invalid_reasons(report))

    # --------------------------------------------- tunnel expectation (I-2)
    def test_expect_tunnel_up_requires_both_directions(self):
        report = scan_middle(
            [wg_outbound(), wg_inbound()], expect_tunnel="up"
        )
        self.assertEqual(report["verdict"], "PASS")
        evidence = report["capture_meta"]["tunnel_expectation"]
        self.assertEqual(evidence["value"], "up")
        self.assertEqual(evidence["outbound_in_window"], 1)
        self.assertEqual(evidence["inbound_in_window"], 1)
        self.assertEqual(evidence["labels_both_directions"], ["mullvad-wg"])
        self.assertTrue(evidence["satisfied"])

    def test_opus_m2_allowed_tuple_wrong_l2_is_a_finding(self):
        # The VM can emit an inbound-shaped frame with its own MAC; that is not
        # real return traffic and must not satisfy --expect-tunnel up.
        forged = ipv4_frame(
            udp_segment(WG_PORT, 40000, wg_data()),
            src_ip=WG_IP,
            dst_ip=VM_IP,
            src_mac=VM_MAC,
            dst_mac=GW_MAC,
        )
        report = scan_middle(
            [wg_outbound(), forged], expect_tunnel="up"
        )
        self.assertEqual(report["verdict"], "LEAK")
        self.assertEqual(reasons(report), ["allowed_tuple_wrong_l2"])
        self.assertEqual(directions(report, "mullvad-wg"), (1, 0))
        evidence = report["capture_meta"]["tunnel_expectation"]
        self.assertEqual(evidence["inbound_in_window"], 0)
        self.assertFalse(evidence["satisfied"])

    def test_opus_m2_allowed_tuple_requires_exact_directional_macs(self):
        cases = (
            ("outbound-wrong-src", wg_outbound(src_mac=GW_MAC), "out"),
            ("outbound-wrong-dst", wg_outbound(dst_mac="02:00:00:00:00:99"), "out"),
            (
                "inbound-wrong-src",
                ipv4_frame(
                    udp_segment(WG_PORT, 40000, wg_data()),
                    src_ip=WG_IP,
                    dst_ip=VM_IP,
                    src_mac=VM_MAC,
                    dst_mac=VM_MAC,
                ),
                "in",
            ),
            (
                "inbound-wrong-dst",
                ipv4_frame(
                    udp_segment(WG_PORT, 40000, wg_data()),
                    src_ip=WG_IP,
                    dst_ip=VM_IP,
                    src_mac=GW_MAC,
                    dst_mac=GW_MAC,
                ),
                "in",
            ),
        )
        for name, frame, direction in cases:
            with self.subTest(case=name):
                report = scan_middle([frame])
                self.assertEqual(report["verdict"], "LEAK")
                self.assertEqual(reasons(report), ["allowed_tuple_wrong_l2"])
                self.assertEqual(
                    directions(report, "mullvad-wg"),
                    (0, 0),
                )

    def test_opus_m2_up_requires_same_allowed_label_both_directions(self):
        second_relay = "195.65.134.10"
        pol = make_policy(
            allowed=[
                {
                    "proto": "udp",
                    "dst_ipv4": WG_IP,
                    "dst_port": WG_PORT,
                    "label": "relay-a",
                },
                {
                    "proto": "udp",
                    "dst_ipv4": second_relay,
                    "dst_port": WG_PORT,
                    "label": "relay-b",
                },
            ]
        )
        out_a = ipv4_frame(udp_segment(40000, WG_PORT, wg_data()))
        in_b = ipv4_frame(
            udp_segment(WG_PORT, 40000, wg_data()),
            src_ip=second_relay,
            dst_ip=VM_IP,
            src_mac=GW_MAC,
            dst_mac=VM_MAC,
        )
        report = scan_middle(
            [out_a, in_b], pol, expect_tunnel="up"
        )
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("tunnel_not_observed", invalid_reasons(report))
        evidence = report["capture_meta"]["tunnel_expectation"]
        self.assertEqual(evidence["outbound_in_window"], 1)
        self.assertEqual(evidence["inbound_in_window"], 1)
        self.assertEqual(evidence["labels_both_directions"], [])
        self.assertFalse(evidence["satisfied"])
        in_a = ipv4_frame(
            udp_segment(WG_PORT, 40000, wg_data()),
            src_ip=WG_IP,
            dst_ip=VM_IP,
            src_mac=GW_MAC,
            dst_mac=VM_MAC,
        )
        report = scan_middle([out_a, in_a], pol, expect_tunnel="up")
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(
            report["capture_meta"]["tunnel_expectation"]["labels_both_directions"],
            ["relay-a"],
        )

    def test_opus_m6_api_expect_tunnel_is_required(self):
        with self.assertRaises(TypeError):
            pcapscan.scan_capture(
                pcap(phase_frames(wg_outbound(), wg_inbound())),
                make_policy(),
                NONCE_A,
                NONCE_B,
                tcpdump_stats_text=zero_stats(4),
                capture_argv=CAPTURE_ARGV,
            )

    def test_expect_tunnel_up_without_inbound_is_invalid(self):
        report = scan_middle([wg_outbound()], expect_tunnel="up")
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("tunnel_not_observed", invalid_reasons(report))
        evidence = report["capture_meta"]["tunnel_expectation"]
        self.assertEqual(evidence["outbound_in_window"], 1)
        self.assertEqual(evidence["inbound_in_window"], 0)
        self.assertFalse(evidence["satisfied"])

    def test_expect_tunnel_up_ignores_outside_window_traffic(self):
        frames = [
            control_frame(NONCE_A),
            wg_outbound(),
            control_frame(NONCE_B),
            wg_inbound(),
        ]
        report = scan(frames, expect_tunnel="up")
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("tunnel_not_observed", invalid_reasons(report))
        self.assertEqual(report["capture_meta"]["outside_window_allowed"], 1)

    def test_expect_tunnel_down_requires_zero_inbound(self):
        report = scan_middle(
            [wg_outbound(), wg_inbound()], expect_tunnel="down"
        )
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("tunnel_not_observed", invalid_reasons(report))

    def test_expect_tunnel_down_sees_inbound_outside_the_window(self):
        frames = [
            control_frame(NONCE_A),
            wg_outbound(),
            control_frame(NONCE_B),
            wg_inbound(),
        ]
        report = scan(frames, expect_tunnel="down")
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("tunnel_not_observed", invalid_reasons(report))
        self.assertEqual(
            report["capture_meta"]["tunnel_expectation"]["inbound_total"], 1
        )

    def test_expect_tunnel_down_with_outbound_only_passes(self):
        report = scan_middle([wg_outbound()], expect_tunnel="down")
        self.assertEqual(report["verdict"], "PASS")
        evidence = report["capture_meta"]["tunnel_expectation"]
        self.assertTrue(evidence["satisfied"])

    def test_expect_tunnel_any_reports_only(self):
        report = scan([control_frame(NONCE_A), control_frame(NONCE_B)], expect_tunnel="any")
        self.assertEqual(report["verdict"], "PASS")
        evidence = report["capture_meta"]["tunnel_expectation"]
        self.assertEqual(evidence["value"], "any")
        self.assertTrue(evidence["satisfied"])

    def test_expect_tunnel_rejects_unknown_value(self):
        with self.assertRaises(ValueError):
            scan_middle([wg_outbound()], expect_tunnel="sideways")

    def test_arp_is_not_tunnel_evidence(self):
        request = arp_frame(1, VM_MAC, VM_IP, "00:00:00:00:00:00", GW_IP)
        reply = arp_frame(2, GW_MAC, GW_IP, VM_MAC, VM_IP, dst_mac=VM_MAC)
        report = scan_middle([request, reply], expect_tunnel="up")
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("tunnel_not_observed", invalid_reasons(report))
        self.assertEqual(report["capture_meta"]["tunnel_expectation"]["outbound_in_window"], 0)
        self.assertEqual(report["capture_meta"]["tunnel_expectation"]["inbound_in_window"], 0)

    def test_f13_per_control_timestamps_are_reported(self):
        report = scan_middle([wg_outbound()])
        controls = report["capture_meta"]["controls"]
        self.assertTrue(controls["before"]["seen"])
        self.assertTrue(controls["after"]["seen"])
        self.assertEqual(controls["before"]["first_packet"], 0)
        self.assertEqual(controls["after"]["first_packet"], 2)
        self.assertLess(controls["before"]["first_ts"], controls["after"]["first_ts"])

    # ---------------------------------------- malformed frame vs INVALID (I3)
    def test_i3_malformed_frame_is_a_finding_and_scan_continues(self):
        bad = ethernet(b"\x45" + b"\x00" * 9, 0x0800)
        report = scan_middle([bad, dns_outbound(), dns_outbound()])
        self.assertEqual(report["packets"], 5)
        self.assertEqual(report["verdict"], "LEAK")
        self.assertEqual(reasons(report).count("malformed_frame"), 1)
        self.assertEqual(reasons(report).count("udp_not_allowed"), 2)

    def test_i3_bad_ihl_is_a_finding_not_invalid(self):
        bad = ipv4_frame(udp_segment(40000, WG_PORT, wg_data()), ihl_bytes=0x44)
        report = scan_middle([bad, dns_outbound()])
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("malformed_frame", reasons(report))
        self.assertIn("udp_not_allowed", reasons(report))

    def test_i3_short_ipv4_is_a_finding_not_invalid(self):
        bad = ethernet(b"\x45" + b"\x00" * 9, 0x0800)
        report = scan_middle([bad])
        self.assertEqual(report["verdict"], "LEAK")
        self.assertEqual(reasons(report), ["malformed_frame"])
        self.assertEqual(report["findings"][0]["detail"], "truncated_ipv4_header")

    def test_i3_bad_ipv4_total_length_is_a_finding(self):
        bad = ipv4_frame(udp_segment(40000, WG_PORT, wg_data()), total_length=10)
        report = scan_middle([bad])
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("malformed_frame", reasons(report))

    def test_i3_snaplen_truncated_record_stops_scanning_as_invalid(self):
        full = wg_outbound() + b"SECRET" * 50
        records = [
            (control_frame(NONCE_A), len(control_frame(NONCE_A)), len(control_frame(NONCE_A))),
            (full[:86], 86, len(full)),
            (control_frame(NONCE_B), len(control_frame(NONCE_B)), len(control_frame(NONCE_B))),
        ]
        report = scan_bytes(
            pcap_from_records(records, snaplen=86),
            make_policy(),
            NONCE_A,
            NONCE_B,
            tcpdump_stats_text=zero_stats(3),
        )
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("snaplen_truncated_record", invalid_reasons(report))
        self.assertEqual(report["packets"], 1)

    def test_i3_finding_plus_drop_is_leak_with_invalid_reasons(self):
        report = scan_middle(
            [dns_outbound()],
            stats=zero_stats(3, kernel=1),
        )
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("udp_not_allowed", reasons(report))
        self.assertIn("packet_drops", invalid_reasons(report))

    def test_i3_partial_record_header_is_invalid(self):
        data = pcap([control_frame(NONCE_A), control_frame(NONCE_B)])[:-5]
        report = scan_bytes(
            data, make_policy(), NONCE_A, NONCE_B,
            tcpdump_stats_text=zero_stats(2),
        )
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("truncated_record_data", invalid_reasons(report))

    def test_i3_finding_then_structural_truncation_is_leak(self):
        data = pcap([control_frame(NONCE_A), dns_outbound()]) + b"\x00" * 8
        report = scan_bytes(
            data, make_policy(), NONCE_A, NONCE_B,
            tcpdump_stats_text=zero_stats(3),
        )
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("udp_not_allowed", reasons(report))
        self.assertIn("truncated_record_header", invalid_reasons(report))
        self.assertIn("missing_positive_controls", invalid_reasons(report))

    def test_truncated_record_is_invalid(self):
        data = pcap(phase_frames(wg_outbound()))
        report = scan_bytes(
            data[:-5], make_policy(), NONCE_A, NONCE_B,
            tcpdump_stats_text=zero_stats(3),
        )
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("truncated_record_data", invalid_reasons(report))

    # ------------------------------------------------- Ethernet trailers (I2)
    def test_i2_arbitrary_ethernet_trailer_is_a_finding(self):
        report = scan_middle([wg_outbound() + b"SECRET" * 50])
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("ethernet_trailer", reasons(report))

    def test_i2_zero_padding_to_minimum_frame_is_allowed(self):
        arp = arp_frame(1, VM_MAC, VM_IP, GW_MAC, GW_IP)
        report = scan_middle([arp + b"\x00" * (60 - len(arp))])
        self.assertEqual(report["verdict"], "PASS")

    def test_i2_nonzero_padding_is_a_finding(self):
        report = scan_middle([wg_outbound() + b"\x00" * 8 + b"X"])
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("ethernet_trailer", reasons(report))

    # ------------------------------------------------------- UDP lengths (I3)
    def test_i3_allowed_flow_bad_udp_length_is_malformed_frame(self):
        for length in (0, 1, 7, 65535):
            with self.subTest(length=length):
                frame = ipv4_frame(
                    udp_segment(40000, WG_PORT, wg_data(), length=length)
                )
                report = scan_middle([frame])
                self.assertEqual(report["verdict"], "LEAK")
                self.assertIn("malformed_frame", reasons(report))
                self.assertEqual(directions(report, "mullvad-wg"), (0, 0))

    def test_i3_control_extra_ip_payload_is_rejected(self):
        payload = policy.control_payload(NONCE_A) + b"PLAIN_SECRET"
        a_extra = ipv4_frame(
            udp_segment(
                40000,
                SINK_PORT,
                payload,
                length=8 + policy.CONTROL_PAYLOAD_LEN,
            ),
            dst_ip=SINK_IP,
        )
        report = scan([a_extra, control_frame(NONCE_B)])
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("malformed_frame", reasons(report))
        self.assertEqual(
            report["positive_controls_seen"], [NONCE_B]
        )

    def test_control_udp_length_bad_is_malformed_frame(self):
        frame = ipv4_frame(
            udp_segment(40000, SINK_PORT, policy.control_payload(NONCE_A), length=1),
            dst_ip=SINK_IP,
        )
        report = scan([frame, control_frame(NONCE_B)])
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("malformed_frame", reasons(report))

    # --------------------------------------------------- IPv4 options (I5/M2)
    def test_i5_ipv4_options_are_a_finding(self):
        l4 = udp_segment(40000, WG_PORT, wg_data())
        base = bytearray(ipv4_packet(VM_IP, WG_IP, 17, l4))
        base[0] = 0x46
        base[2:4] = struct.pack("!H", len(base) + 4)
        options = bytes([0x83, 7, 4]) + socket.inet_aton("1.1.1.1") + bytes([0])
        frame = ethernet(bytes(base[:20]) + options + bytes(base[20:]), 0x0800)
        report = scan_middle([frame])
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("ipv4_options", reasons(report))

    def test_ipv4_options_on_disallowed_flow_still_finding(self):
        l4 = udp_segment(40000, 53, b"x")
        base = bytearray(ipv4_packet(VM_IP, "1.1.1.1", 17, l4))
        base[0] = 0x46
        base[2:4] = struct.pack("!H", len(base) + 4)
        frame = ethernet(bytes(base[:20]) + b"\x01\x01\x01\x00" + bytes(base[20:]), 0x0800)
        report = scan_middle([frame])
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("ipv4_options", reasons(report))

    # ------------------------------------------------------- fragments (I4)
    def _first(self, ident=77, udp_len=40, data=None):
        if data is None:
            data = wg_data()[:8]
        return ipv4_frame(
            udp_segment(40000, WG_PORT, data, length=udp_len),
            ident=ident,
            more_fragments=True,
        )

    @staticmethod
    def _fragment_rest():
        return wg_data()[8:]

    def test_i4_valid_contiguous_complete_fragments_are_allowed(self):
        report = scan_middle(
            [self._first(), ipv4_frame(self._fragment_rest(), ident=77, frag_units=2)]
        )
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(directions(report, "mullvad-wg"), (2, 0))

    def test_i4_gap_fragment_is_a_finding(self):
        report = scan_middle(
            [self._first(), ipv4_frame(self._fragment_rest(), ident=77, frag_units=3)]
        )
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("fragment_gap", reasons(report))

    def test_i4_orphan_after_complete_is_a_finding(self):
        report = scan_middle(
            [
                self._first(),
                ipv4_frame(self._fragment_rest(), ident=77, frag_units=2),
                ipv4_frame(b"PLAIN_SECRET" * 8, ident=77, frag_units=8000),
            ]
        )
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("fragment_after_complete", reasons(report))

    def test_i4_conflicting_final_overlap_is_a_finding(self):
        report = scan_middle(
            [
                self._first(),
                ipv4_frame(self._fragment_rest(), ident=77, frag_units=2),
                ipv4_frame(self._fragment_rest(), ident=77, frag_units=2),
            ]
        )
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("fragment_after_complete", reasons(report))

    def test_i4_nonfirst_before_first_is_a_finding(self):
        report = scan_middle(
            [ipv4_frame(self._fragment_rest(), ident=79, frag_units=2), self._first(79)]
        )
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("fragment_without_first", reasons(report))

    def test_i4_stale_fragment_association_is_a_finding(self):
        frames = [
            control_frame(NONCE_A),
            self._first(),
            ipv4_frame(self._fragment_rest(), ident=77, frag_units=2),
            control_frame(NONCE_B),
        ]
        times = [1_700_000_000.0, 1_700_000_001.0, 1_700_000_040.0, 1_700_000_041.0]
        report = scan_bytes(
            pcap_from_records(
                [(frame, len(frame), len(frame)) for frame in frames],
                timestamps=times,
            ),
            make_policy(),
            NONCE_A,
            NONCE_B,
            tcpdump_stats_text=zero_stats(4),
        )
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("fragment_stale_association", reasons(report))

    def test_i4_incomplete_final_fragment_is_a_finding(self):
        report = scan_middle(
            [self._first(udp_len=32), ipv4_frame(self._fragment_rest()[:4], ident=77, frag_units=2)]
        )
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("fragment_incomplete", reasons(report))

    def test_fragment_first_payload_too_short_for_udp_header(self):
        report = scan_middle(
            [ipv4_frame(b"abc", ident=9, more_fragments=True)]
        )
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("udp_header_incomplete", reasons(report))

    def test_i4_first_fragment_without_rest_is_incomplete(self):
        report = scan_middle([self._first()])
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("fragment_incomplete", reasons(report))

    def test_i4_duplicate_first_fragment_is_a_finding(self):
        report = scan_middle([self._first(ident=55), self._first(ident=55)])
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("fragment_duplicate_first", reasons(report))

    # ------------------------- fragment expiry/replacement and zero payload
    def test_replaced_incomplete_fragment_association_is_a_finding(self):
        # gpt I2: the earlier datagram at t=101 never completes; a new first
        # fragment for the same key at t=132 silently overwrote its state.
        frames = [
            control_frame(NONCE_A),
            self._first(),
            self._first(),
            ipv4_frame(self._fragment_rest(), ident=77, frag_units=2),
            control_frame(NONCE_B),
        ]
        times = [100.0, 101.0, 132.0, 133.0, 134.0]
        report = scan_bytes(
            pcap_from_records(
                [(frame, len(frame), len(frame)) for frame in frames],
                timestamps=times,
            ),
            make_policy(),
            NONCE_A,
            NONCE_B,
            tcpdump_stats_text=zero_stats(5),
        )
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("incomplete_fragment", reasons(report))
        self.assertEqual(directions(report, "mullvad-wg"), (3, 0))

    def test_expired_incomplete_fragment_association_is_a_finding(self):
        frames = [
            control_frame(NONCE_A),
            self._first(ident=66),
            control_frame(NONCE_B),
        ]
        times = [100.0, 101.0, 140.0]
        report = scan_bytes(
            pcap_from_records(
                [(frame, len(frame), len(frame)) for frame in frames],
                timestamps=times,
            ),
            make_policy(),
            NONCE_A,
            NONCE_B,
            tcpdump_stats_text=zero_stats(3),
        )
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("fragment_incomplete", reasons(report))

    def test_gpt_i1_opus_m3_incomplete_fragment_outside_window_is_a_finding(self):
        # gpt I1 / opus M-3 / pi M2: an unfinished allowed association is a
        # finding wherever its first fragment lies relative to the control
        # window, including exactly at either marker timestamp.
        inside = phase_frames(self._first(), wg_outbound(), wg_inbound())
        outside_before = [
            self._first(),
            *phase_frames(wg_outbound(), wg_inbound()),
        ]
        outside_after = [
            *phase_frames(wg_outbound(), wg_inbound()),
            self._first(),
        ]
        at_before = [
            control_frame(NONCE_A),
            self._first(),
            wg_outbound(),
            wg_inbound(),
            control_frame(NONCE_B),
        ]
        at_after = [
            control_frame(NONCE_A),
            wg_outbound(),
            wg_inbound(),
            self._first(),
            control_frame(NONCE_B),
        ]
        cases = (
            ("inside", inside, None),
            ("before", outside_before, None),
            ("after", outside_after, None),
            ("at-before", at_before, [100.0, 100.0, 101.0, 102.0, 103.0]),
            ("at-after", at_after, [100.0, 101.0, 102.0, 103.0, 103.0]),
        )
        for name, frames, times in cases:
            with self.subTest(case=name):
                report = scan_bytes(
                    pcap_from_records(
                        [(frame, len(frame), len(frame)) for frame in frames],
                        timestamps=times,
                    ),
                    make_policy(),
                    NONCE_A,
                    NONCE_B,
                    tcpdump_stats_text=zero_stats(len(frames)),
                    expect_tunnel="up",
                )
                self.assertEqual(report["verdict"], "LEAK")
                self.assertIn("fragment_incomplete", reasons(report))

    def test_zero_payload_final_fragment_is_a_finding(self):
        # gpt M2: an empty final fragment must not complete or extend a
        # datagram.
        report = scan_middle(
            [self._first(ident=78), ipv4_frame(b"", ident=78, frag_units=2)]
        )
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("zero_payload_fragment", reasons(report))
        self.assertEqual(directions(report, "mullvad-wg"), (1, 0))

    def test_zero_payload_middle_fragment_is_a_finding(self):
        report = scan_middle(
            [
                self._first(),
                ipv4_frame(b"", ident=77, frag_units=2, more_fragments=True),
                ipv4_frame(self._fragment_rest(), ident=77, frag_units=3),
            ]
        )
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("zero_payload_fragment", reasons(report))

    def test_zero_payload_first_fragment_is_a_finding(self):
        report = scan_middle(
            [ipv4_frame(b"", ident=91, more_fragments=True)]
        )
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("zero_payload_fragment", reasons(report))

    def test_first_fragment_with_no_remainder_is_a_finding(self):
        # MF set while the declared UDP length equals the bytes present: the
        # fragment leaves no genuine remainder and can only be malformed.
        report = scan_middle(
            [self._first(ident=92, udp_len=16), ipv4_frame(b"", ident=92, frag_units=2)]
        )
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("malformed_frame", reasons(report))
        self.assertEqual(directions(report, "mullvad-wg"), (0, 0))

    # ---------------------------------------------------- structural pcap tests
    def test_record_length_inconsistent_is_invalid(self):
        frame = wg_outbound()
        data = pcap_from_records([(frame, len(frame), len(frame) - 1)])
        report = scan_bytes(
            data, make_policy(), NONCE_A, NONCE_B,
            tcpdump_stats_text=zero_stats(1),
        )
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("record_length_inconsistent", invalid_reasons(report))

    def test_record_exceeds_snaplen_is_invalid(self):
        frame = wg_outbound()
        data = pcap_from_records([(frame, len(frame), len(frame))], snaplen=10)
        report = scan_bytes(
            data, make_policy(), NONCE_A, NONCE_B,
            tcpdump_stats_text=zero_stats(1),
        )
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("record_exceeds_snaplen", invalid_reasons(report))

    def test_zero_snaplen_is_invalid(self):
        report = scan_bytes(
            pcap([], snaplen=0), make_policy(), NONCE_A, NONCE_B,
            tcpdump_stats_text=zero_stats(0),
        )
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("invalid_snaplen", invalid_reasons(report))

    def test_truncated_global_header_is_invalid(self):
        report = scan_bytes(
            b"\xd4\xc3\xb2\xa1", make_policy(), NONCE_A, NONCE_B,
            tcpdump_stats_text=zero_stats(0),
        )
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("truncated_global_header", invalid_reasons(report))

    def test_unsupported_magic_is_invalid(self):
        report = scan_bytes(
            b"XXXX" + b"\x00" * 40, make_policy(), NONCE_A, NONCE_B,
            tcpdump_stats_text=zero_stats(0),
        )
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("unsupported_pcap_magic", invalid_reasons(report))

    def test_unsupported_pcap_version_is_invalid(self):
        data = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 3, 0, 0, 262144, 1)
        report = scan_bytes(
            data, make_policy(), NONCE_A, NONCE_B,
            tcpdump_stats_text=zero_stats(1),
        )
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("unsupported_pcap_version", invalid_reasons(report))

    def test_interface_drop_line_is_optional(self):
        report = scan_middle(
            [wg_outbound()],
            stats=(
                CAPTURE_BANNER + "3 packets captured\n3 packets received by filter\n"
                "0 packets dropped by kernel\n"
            ),
        )
        self.assertEqual(report["verdict"], "PASS")

    def test_missing_received_counter_is_incomplete(self):
        report = scan_middle(
            [wg_outbound()],
            stats="3 packets captured\n0 packets dropped by kernel\n",
        )
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("stats_incomplete", invalid_reasons(report))

    def test_vm_to_vm_is_a_finding(self):
        frame = ipv4_frame(udp_segment(1, 2, b"x"), dst_ip=VM_IP)
        report = scan_middle([frame])
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("vm_to_vm", reasons(report))

    def test_unexpected_ethertype_is_a_finding(self):
        frame = ethernet(b"\x00" * 46, 0x88CC)
        report = scan_middle([frame])
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("unexpected_ethertype", reasons(report))

    def test_qinq_encapsulation_is_a_finding(self):
        inner = ethernet(b"\x00" * 46, 0x0800)
        frame = ethernet(inner[14:], 0x88A8, vlan=10)
        report = scan_middle([frame])
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("unsupported_encapsulation", reasons(report))

    def test_truncated_arp_is_malformed_frame(self):
        frame = ethernet(b"\x00" * 6, 0x0806)
        report = scan_middle([frame])
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("malformed_frame", reasons(report))

    def test_truncated_ethernet_header_is_malformed_frame(self):
        report = scan_middle([b"\x00" * 10])
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("malformed_frame", reasons(report))

    # ------------------------------------------------------------- ARP (M4)
    def test_decision5_vm_arp_for_gateway_is_allowed(self):
        frame = arp_frame(1, VM_MAC, VM_IP, "00:00:00:00:00:00", GW_IP)
        report = scan_middle([frame])
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["allowed_counts"]["arp"], {"outbound": 1, "inbound": 0})

    def test_decision5_gateway_arp_reply_to_vm_is_allowed(self):
        frame = arp_frame(2, GW_MAC, GW_IP, VM_MAC, VM_IP, dst_mac=VM_MAC)
        report = scan_middle([frame])
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["allowed_counts"]["arp"], {"outbound": 0, "inbound": 1})

    def test_decision5_vm_claiming_gateway_ip_is_a_finding(self):
        frame = arp_frame(2, VM_MAC, GW_IP, GW_MAC, GW_IP)
        report = scan_middle([frame])
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("arp_not_allowed", reasons(report))

    def test_decision5_gratuitous_other_ip_is_a_finding(self):
        frame = arp_frame(2, VM_MAC, VM_IP, "00:00:00:00:00:00", "10.250.0.99")
        report = scan_middle([frame])
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("arp_not_allowed", reasons(report))

    def test_decision5_third_party_arp_is_a_finding(self):
        frame = arp_frame(
            1,
            "02:00:00:00:00:01",
            "10.250.0.50",
            "00:00:00:00:00:00",
            GW_IP,
            dst_mac="ff:ff:ff:ff:ff:ff",
        )
        report = scan_middle([frame])
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("arp_not_allowed", reasons(report))

    def test_decision5_ethernet_sender_mismatch_is_a_finding(self):
        frame = arp_frame(
            1,
            VM_MAC,
            VM_IP,
            "00:00:00:00:00:00",
            GW_IP,
            src_mac="02:00:00:00:00:01",
        )
        report = scan_middle([frame])
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("arp_not_allowed", reasons(report))

    def test_decision5_unsupported_arp_opcode_is_a_finding(self):
        frame = arp_frame(65535, VM_MAC, VM_IP, "00:00:00:00:00:00", GW_IP)
        report = scan_middle([frame])
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("arp_not_allowed", reasons(report))

    def test_decision5_allow_arp_false_makes_every_arp_a_finding(self):
        frame = arp_frame(1, VM_MAC, VM_IP, "00:00:00:00:00:00", GW_IP)
        report = scan_middle([frame], make_policy(allow_arp=False))
        self.assertEqual(report["verdict"], "LEAK")
        self.assertEqual(reasons(report), ["arp_not_allowed"])

    def test_f11_foreign_mac_claiming_vm_ip_is_a_finding(self):
        frame = arp_frame(
            2,
            "02:00:00:00:00:01",
            VM_IP,
            VM_MAC,
            VM_IP,
            dst_mac=VM_MAC,
        )
        report = scan_middle([frame])
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("arp_not_allowed", reasons(report))

    # --------------------------------------- gateway MAC binding (gpt I3)
    def test_vm_mac_claiming_gateway_ip_is_a_finding_both_ops(self):
        for operation in (1, 2):
            with self.subTest(operation=operation):
                frame = arp_frame(
                    operation,
                    VM_MAC,
                    GW_IP,
                    VM_MAC,
                    VM_IP,
                    dst_mac=VM_MAC,
                )
                report = scan_middle([frame])
                self.assertEqual(report["verdict"], "LEAK")
                self.assertIn("arp_not_allowed", reasons(report))
                self.assertEqual(
                    report["allowed_counts"]["arp"], {"outbound": 0, "inbound": 0}
                )

    def test_foreign_mac_claiming_gateway_ip_is_a_finding(self):
        frame = arp_frame(2, "02:00:00:00:00:01", GW_IP, VM_MAC, VM_IP, dst_mac=VM_MAC)
        report = scan_middle([frame])
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("arp_not_allowed", reasons(report))

    def test_gateway_mac_claiming_vm_ip_is_a_finding(self):
        frame = arp_frame(2, GW_MAC, VM_IP, VM_MAC, VM_IP, dst_mac=VM_MAC)
        report = scan_middle([frame])
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("arp_not_allowed", reasons(report))

    def test_gateway_arp_request_to_vm_is_allowed(self):
        frame = arp_frame(1, GW_MAC, GW_IP, "00:00:00:00:00:00", VM_IP)
        report = scan_middle([frame])
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(
            report["allowed_counts"]["arp"], {"outbound": 0, "inbound": 1}
        )

    def test_unsupported_arp_hardware_is_a_finding(self):
        body = struct.pack("!HHBBH", 6, 0x86DD, 6, 4, 1) + b"\x00" * 20
        frame = ethernet(body, 0x0806)
        report = scan_middle([frame])
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("unsupported_arp", reasons(report))


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
class CliTests(unittest.TestCase):
    def _write(self, root, name, data):
        path = root / name
        if isinstance(data, bytes):
            path.write_bytes(data)
        else:
            path.write_text(data, encoding="utf-8")
        return path

    def _command(self, root, pcap_path, stats_path, *, before=NONCE_A, after=NONCE_B,
                 expect_tunnel="any"):
        policy_path = root / "policy.json"
        if not policy_path.exists():
            self._write(root, "policy.json", json.dumps(policy_document()))
        argv_path = root / "capture-argv.json"
        argv = CAPTURE_ARGV[:-1] + [str(pcap_path)]
        self._write(root, "capture-argv.json", json.dumps(argv))
        return [
            sys.executable,
            "-B",
            str(HERE / "pcapscan.py"),
            "--policy",
            str(policy_path),
            "--pcap",
            str(pcap_path),
            "--tcpdump-stats",
            str(stats_path),
            "--capture-argv-file",
            str(argv_path),
            "--expect-tunnel",
            expect_tunnel,
            "--control-before",
            before,
            "--control-after",
            after,
        ]

    def test_cli_exit_codes_and_canonical_json(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            stats = self._write(root, "stats.txt", zero_stats(3))

            pass_pcap = self._write(
                root, "pass.pcap", pcap(phase_frames(wg_outbound()))
            )
            result = subprocess.run(
                self._command(root, pass_pcap, stats),
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            parsed = json.loads(result.stdout)
            self.assertEqual(parsed["verdict"], "PASS")
            self.assertEqual(result.stdout, pcapscan.canonical_json(parsed))

            leak_pcap = self._write(
                root, "leak.pcap", pcap(phase_frames(dns_outbound()))
            )
            result = subprocess.run(
                self._command(root, leak_pcap, stats),
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(json.loads(result.stdout)["verdict"], "LEAK")

            invalid_pcap = self._write(
                root, "invalid.pcap", pcap(phase_frames(wg_outbound()))[:-5]
            )
            result = subprocess.run(
                self._command(root, invalid_pcap, stats),
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(json.loads(result.stdout)["verdict"], "INVALID")

    def test_cli_requires_stats_and_both_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self._write(root, "policy.json", json.dumps(policy_document()))
            self._write(root, "cap.pcap", pcap(phase_frames(wg_outbound())))
            base = [
                sys.executable,
                "-B",
                str(HERE / "pcapscan.py"),
                "--policy",
                str(root / "policy.json"),
                "--pcap",
                str(root / "cap.pcap"),
            ]
            result = subprocess.run(base, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 2)

            result = subprocess.run(
                base
                + [
                    "--tcpdump-stats",
                    str(self._write(root, "stats.txt", zero_stats(3))),
                    "--control-before",
                    NONCE_A,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 2)

    def test_cli_expect_tunnel_up_fails_without_inbound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            stats = self._write(root, "stats.txt", zero_stats(3))
            cap = self._write(root, "cap.pcap", pcap(phase_frames(wg_outbound())))
            result = subprocess.run(
                self._command(root, cap, stats, expect_tunnel="up"),
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            parsed = json.loads(result.stdout)
            self.assertEqual(parsed["verdict"], "INVALID")
            self.assertIn("tunnel_not_observed", parsed["capture_meta"]["invalid_reasons"])

    def test_cli_requires_capture_argv_and_expect_tunnel(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self._write(root, "policy.json", json.dumps(policy_document()))
            self._write(root, "cap.pcap", pcap(phase_frames(wg_outbound())))
            stats = self._write(root, "stats.txt", zero_stats(3))
            base = [
                sys.executable,
                "-B",
                str(HERE / "pcapscan.py"),
                "--policy",
                str(root / "policy.json"),
                "--pcap",
                str(root / "cap.pcap"),
                "--tcpdump-stats",
                str(stats),
                "--control-before",
                NONCE_A,
                "--control-after",
                NONCE_B,
            ]
            result = subprocess.run(base, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 2)
            self.assertIn("--capture-argv-file", result.stderr)
            result = subprocess.run(
                base
                + [
                    "--capture-argv-file",
                    str(self._write(root, "argv.json", json.dumps(CAPTURE_ARGV))),
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("--expect-tunnel", result.stderr)

    def test_cli_rejects_malformed_capture_argv_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            stats = self._write(root, "stats.txt", zero_stats(3))
            cap = self._write(root, "cap.pcap", pcap(phase_frames(wg_outbound())))
            argv_path = self._write(root, "argv.json", "not json")
            command = self._command(root, cap, stats)
            index = command.index("--capture-argv-file")
            command[index + 1] = str(argv_path)
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 2)

    def test_cli_capture_argv_hash_covers_the_exact_file_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            stats = self._write(root, "stats.txt", zero_stats(3))
            cap = self._write(root, "cap.pcap", pcap(phase_frames(wg_outbound())))
            command = self._command(root, cap, stats)
            argv_path = pathlib.Path(
                command[command.index("--capture-argv-file") + 1]
            )
            # EvidenceDirectory.write_json writes indented JSON plus a newline;
            # the scanner must hash these exact bytes, not a compact re-encoding.
            expected_argv = CAPTURE_ARGV[:-1] + [str(cap)]
            raw = (json.dumps(expected_argv, indent=2) + "\n").encode()
            argv_path.write_bytes(raw)
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=30
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            parsed = json.loads(result.stdout)
            self.assertEqual(parsed["verdict"], "PASS")
            self.assertEqual(
                parsed["capture_meta"]["capture_argv_sha256"],
                pcapscan.hashlib.sha256(raw).hexdigest(),
            )
            self.assertNotEqual(
                parsed["capture_meta"]["capture_argv_sha256"],
                parsed["capture_meta"]["capture_argv_canonical_sha256"],
            )

    def test_cli_opus_m7_rejects_w_path_that_differs_from_pcap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            stats = self._write(root, "stats.txt", zero_stats(3))
            cap = self._write(root, "cap.pcap", pcap(phase_frames(wg_outbound())))
            command = self._command(root, cap, stats)
            argv_path = root / "capture-argv.json"
            for path in ("/dev/null", str(root / "other.pcap"), "-"):
                with self.subTest(path=path):
                    argv = CAPTURE_ARGV[:-1] + [path]
                    argv_path.write_text(json.dumps(argv), encoding="utf-8")
                    result = subprocess.run(
                        command, capture_output=True, text=True, timeout=30
                    )
                    self.assertEqual(result.returncode, 2)
                    parsed = json.loads(result.stdout)
                    self.assertEqual(parsed["verdict"], "INVALID")
                    self.assertIn(
                        "capture_argv_mismatch",
                        parsed["capture_meta"]["invalid_reasons"],
                    )

    def test_cli_rejects_equal_control_nonces(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            stats = self._write(root, "stats.txt", zero_stats(2))
            cap = self._write(root, "cap.pcap", pcap([control_frame(NONCE_A)] * 2))
            result = subprocess.run(
                self._command(root, cap, stats, before=NONCE_A, after=NONCE_A),
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("distinct", result.stderr)

    def test_cli_unreadable_stats_is_invalid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self._write(root, "policy.json", json.dumps(policy_document()))
            cap = self._write(
                root,
                "cap.pcap",
                pcap([control_frame(NONCE_A), control_frame(NONCE_B)]),
            )
            result = subprocess.run(
                self._command(root, cap, root / "missing-stats.txt"),
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 2)
            self.assertEqual(json.loads(result.stdout)["verdict"], "INVALID")


# --------------------------------------------------------------------------
# policy tests
# --------------------------------------------------------------------------
class PolicyTests(unittest.TestCase):
    def test_valid_policy_roundtrips(self):
        first = make_policy()
        second = policy.parse_policy(first.to_dict())
        self.assertEqual(first, second)
        self.assertFalse(first.ipv6_allowed)
        self.assertEqual(first.vm_wan_mac, VM_MAC.lower())
        self.assertEqual(first.gateway_ipv4, GW_IP)

    def test_unknown_top_level_key_rejected(self):
        with self.assertRaises(policy.PolicyError):
            make_policy(unexpected=True)

    def test_unknown_nested_key_rejected(self):
        document = policy_document()
        document["allowed"][0]["extra"] = "x"
        with self.assertRaises(policy.PolicyError):
            policy.parse_policy(document)
        document = policy_document()
        document["positive_control"]["extra"] = "x"
        with self.assertRaises(policy.PolicyError):
            policy.parse_policy(document)

    def test_ipv6_allowed_true_rejected(self):
        with self.assertRaises(policy.PolicyError):
            make_policy(ipv6_allowed=True)

    def test_ipv6_allowed_must_be_literal_false(self):
        with self.assertRaises(policy.PolicyError):
            make_policy(ipv6_allowed=0)

    def test_hostname_instead_of_ipv4_rejected(self):
        with self.assertRaises(policy.PolicyError):
            make_policy(vm_wan_ipv4="router.example")
        document = policy_document()
        document["allowed"][0]["dst_ipv4"] = "relay.example.com"
        with self.assertRaises(policy.PolicyError):
            policy.parse_policy(document)
        with self.assertRaises(policy.PolicyError):
            make_policy(vm_wan_ipv4="010.0.0.1")

    def test_duplicate_json_key_rejected(self):
        text = json.dumps(policy_document())
        text = text.replace('"allow_arp": true', '"allow_arp": true, "allow_arp": false')
        with self.assertRaises(policy.PolicyError):
            policy.parse_policy(text.encode())

    def test_duplicate_label_or_endpoint_rejected(self):
        document = policy_document()
        document["allowed"].append(dict(document["allowed"][0]))
        with self.assertRaises(policy.PolicyError):
            policy.parse_policy(document)
        document = policy_document()
        document["allowed"].append(
            {"proto": "udp", "dst_ipv4": "185.65.134.20", "dst_port": WG_PORT, "label": "mullvad-wg"}
        )
        with self.assertRaises(policy.PolicyError):
            policy.parse_policy(document)

    def test_control_endpoint_must_not_overlap_allowed_flow(self):
        document = policy_document()
        document["allowed"].append(
            {
                "proto": "udp",
                "dst_ipv4": SINK_IP,
                "dst_port": SINK_PORT,
                "label": "ambiguous",
            }
        )
        with self.assertRaises(policy.PolicyError):
            policy.parse_policy(document)

    # ------------------------------------------------------ gateway (decision 5)
    def test_gateway_ipv4_is_required(self):
        document = policy_document()
        del document["gateway_ipv4"]
        with self.assertRaises(policy.PolicyError):
            policy.parse_policy(document)

    def test_gateway_ipv4_is_exactly_the_plan_bridge_address(self):
        with self.assertRaises(policy.PolicyError):
            make_policy(
                gateway_ipv4="10.250.0.9",
                positive_control={"sink_ipv4": "10.250.0.9", "sink_udp_port": SINK_PORT},
            )
        with self.assertRaises(policy.PolicyError):
            make_policy(gateway_ipv4="10.250.0.254")

    # ------------------------------------------- gateway MAC (gpt I3)
    def test_gateway_mac_required_when_arp_is_allowed(self):
        document = policy_document()
        del document["gateway_mac"]
        with self.assertRaises(policy.PolicyError):
            policy.parse_policy(document)

    def test_opus_m2_gateway_mac_is_required_even_without_arp(self):
        document = policy_document(allow_arp=False)
        del document["gateway_mac"]
        with self.assertRaises(policy.PolicyError):
            policy.parse_policy(document)
        loaded = policy.parse_policy(policy_document(allow_arp=False))
        self.assertFalse(loaded.allow_arp)
        self.assertEqual(loaded.gateway_mac, GW_MAC)
        self.assertEqual(loaded.to_dict()["gateway_mac"], GW_MAC)

    def test_gateway_mac_must_be_unicast_and_differ_from_vm(self):
        for mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", "01:00:5e:00:00:01", VM_MAC, None):
            with self.subTest(mac=mac):
                with self.assertRaises(policy.PolicyError):
                    make_policy(gateway_mac=mac)

    # --------------------------------- public destinations and ports (M-2)
    def test_allowed_destination_must_be_public_unicast(self):
        for address in (
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "100.100.100.100",
            "192.0.0.8",
            "192.0.2.10",
            "198.18.0.1",
            "198.51.100.10",
            "203.0.113.10",
            "127.0.0.1",
            "169.254.1.1",
            "224.0.0.1",
            "240.0.0.1",
        ):
            with self.subTest(address=address):
                document = policy_document()
                document["allowed"][0]["dst_ipv4"] = address
                with self.assertRaises(policy.PolicyError):
                    policy.parse_policy(document)

    def test_allowed_destination_service_ports_are_rejected(self):
        for port in (53, 853, 123, 5353, 5355):
            with self.subTest(port=port):
                document = policy_document()
                document["allowed"][0]["dst_port"] = port
                with self.assertRaises(policy.PolicyError):
                    policy.parse_policy(document)

    def test_control_sink_must_equal_gateway(self):
        with self.assertRaises(policy.PolicyError):
            make_policy(
                positive_control={"sink_ipv4": "10.250.0.9", "sink_udp_port": SINK_PORT}
            )

    def test_vm_must_differ_from_gateway(self):
        with self.assertRaises(policy.PolicyError):
            make_policy(vm_wan_ipv4=GW_IP)

    def test_vm_and_gateway_must_be_in_lab_subnet(self):
        with self.assertRaises(policy.PolicyError):
            make_policy(vm_wan_ipv4="10.250.1.2")
        with self.assertRaises(policy.PolicyError):
            make_policy(gateway_ipv4="10.250.1.1")

    def test_special_addresses_are_rejected(self):
        for address in (
            "0.0.0.0",
            "0.1.2.3",
            "127.0.0.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "169.254.1.1",
        ):
            with self.subTest(where="vm", address=address):
                with self.assertRaises(policy.PolicyError):
                    make_policy(vm_wan_ipv4=address)
            with self.subTest(where="allowed", address=address):
                document = policy_document()
                document["allowed"][0]["dst_ipv4"] = address
                with self.assertRaises(policy.PolicyError):
                    policy.parse_policy(document)

    def test_allowed_endpoint_must_not_be_vm_gateway_or_lab_subnet(self):
        for address in (VM_IP, GW_IP, "10.250.0.7"):
            with self.subTest(address=address):
                document = policy_document()
                document["allowed"][0]["dst_ipv4"] = address
                with self.assertRaises(policy.PolicyError):
                    policy.parse_policy(document)

    def test_non_unicast_vm_mac_rejected(self):
        for mac in ("ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:01", "00:00:00:00:00:00"):
            with self.subTest(mac=mac):
                with self.assertRaises(policy.PolicyError):
                    make_policy(vm_wan_mac=mac)

    def test_schema_is_closed_and_mirrors_gateway(self):
        schema = json.loads((HERE / "policy.schema.json").read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["ipv6_allowed"], {"const": False})
        self.assertFalse(schema["properties"]["allowed"]["items"]["additionalProperties"])
        self.assertIn("ipv6_allowed", schema["required"])
        self.assertIn("gateway_ipv4", schema["required"])
        self.assertIn("gateway_ipv4", schema["properties"])
        self.assertEqual(
            schema["properties"]["gateway_ipv4"]["const"], "10.250.0.1"
        )
        self.assertIn("gateway_mac", schema["properties"])
        self.assertIn("gateway_mac", schema["required"])
        self.assertNotIn("allOf", schema)
        self.assertIn(
            "not", schema["$defs"]["unicast_ipv4"]["allOf"][1]
        )


# --------------------------------------------------------------------------
# hostname tests
# --------------------------------------------------------------------------
class TsnamesTests(unittest.TestCase):
    def test_generates_base_and_suffix(self):
        self.assertEqual(tsnames.generate(3), "zz-vprtest-03-do-not-use")
        self.assertEqual(
            tsnames.generate(3, "mullvad-hot-dingo"),
            "zz-vprtest-03-do-not-use-mullvad-hot-dingo",
        )
        self.assertTrue(tsnames.is_test_node(tsnames.generate(99)))

    def test_refuses_overlong_instead_of_truncating(self):
        base = tsnames.generate(1)
        room = 63 - len(base) - 1
        self.assertEqual(len(tsnames.generate(1, "a" * room)), 63)
        with self.assertRaises(ValueError) as caught:
            tsnames.generate(1, "a" * (room + 1))
        self.assertIn("refusing", str(caught.exception))

    def test_rejects_bad_index_and_suffix(self):
        for index in (0, 100, -1, True):
            with self.assertRaises(ValueError):
                tsnames.generate(index)
        for suffix in ("-leading", "trailing-", "double--hyphen", "Upper", "under_score"):
            with self.assertRaises(ValueError):
                tsnames.generate(1, suffix)

    def test_decision7_exact_regex(self):
        accepted = (
            "zz-vprtest-01-do-not-use",
            "zz-vprtest-99-do-not-use",
            "zz-vprtest-01-do-not-use-prod",
            "zz-vprtest-42-do-not-use-a-b-c9",
        )
        for name in accepted:
            with self.subTest(name=name):
                self.assertTrue(tsnames.is_test_node(name))
        rejected = (
            "zz-vprtest-1-do-not-use",
            "vprtest-01",
            "zz-vprtest-01-do-not-use.evil",
            "zz-vprtest-01-do-not-use.tailnet.ts.net",
            "zz-vprtest-00-do-not-use",
            "zz-vprtest-100-do-not-use",
            "ZZ-vprtest-01-do-not-use",
            "zz-vprtest-01-do-not-use-",
            "zz-vprtest-01-do-not-use--x",
            "",
            None,
        )
        for name in rejected:
            with self.subTest(name=name):
                self.assertFalse(tsnames.is_test_node(name))

    def test_total_length_is_limited_to_63(self):
        self.assertFalse(tsnames.is_test_node("zz-vprtest-01-do-not-use-" + "a" * 40))


# --------------------------------------------------------------------------
# netplan tests
# --------------------------------------------------------------------------
def _links(*names, altnames=None):
    document = []
    for name in names:
        entry = {"ifname": name}
        if altnames and name in altnames:
            entry["altnames"] = altnames[name]
        document.append(entry)
    return json.dumps(document)


_STUB_SOURCE = '''#!/usr/bin/env python3
import json
import os
import re
import sys
import time

STATE_PATH = os.environ["STUB_STATE"]
LOG_PATH = os.environ["STUB_LOG"]
FAILURES = {item for item in os.environ.get("STUB_FAIL", "").split(",") if item}
NAME = os.path.basename(sys.argv[0])
ARGS = sys.argv[1:]

with open(LOG_PATH, "a", encoding="utf-8") as handle:
    handle.write(" ".join([NAME, *ARGS]) + "\\n")
    probe = os.environ.get("STUB_LOCK_PROBE")
    if probe:
        import fcntl

        try:
            probe_fd = os.open(probe, os.O_RDWR)
            try:
                fcntl.flock(probe_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                result = "free"
            except OSError:
                result = "held"
            finally:
                os.close(probe_fd)
        except OSError:
            result = "unreadable"
        handle.write("LOCKPROBE " + result + "\\n")


def load():
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        return {}


def save(state):
    with open(STATE_PATH, "w", encoding="utf-8") as handle:
        json.dump(state, handle, sort_keys=True)


def split_options(args):
    options = set()
    rest = []
    for item in args:
        if not rest and item.startswith("-"):
            options.add(item)
        else:
            rest.append(item)
    return options, rest


def after(rest, token):
    return rest[rest.index(token) + 1]


def fail(name):
    return name in FAILURES


state = load()
state.setdefault("links", {})
state.setdefault("neigh", {})
state.setdefault("rules", [])

if NAME == "sysctl":
    sys.exit(0)

if NAME == "tcpdump":
    delay = float(os.environ.get("STUB_TCPDUMP_SLEEP", "0"))
    if delay:
        time.sleep(delay)
    sys.exit(int(os.environ.get("STUB_TCPDUMP_EXIT", "0")))

if NAME == "ip":
    options, rest = split_options(ARGS)
    if not rest:
        sys.exit(99)
    command = rest[0]
    if command == "tuntap":
        name = after(rest, "dev")
        if fail("tuntap_add"):
            sys.exit(1)
        state["links"][name] = {
            "ifalias": None,
            "operstate": "DOWN",
            "kind": "tun",
            "tap_type": "tap",
            "master": None,
            "address": "52:54:00:76:70:02",
        }
        save(state)
        sys.exit(0)
    if command == "addr":
        sys.exit(0)
    if command == "link":
        action = rest[1]
        if action == "add":
            name = after(rest, "add")
            if fail("link_add"):
                sys.exit(1)
            state["links"][name] = {
                "ifalias": None,
                "operstate": "DOWN",
                "kind": "bridge",
                "tap_type": None,
                "master": None,
                "address": "52:54:00:76:70:01",
            }
            save(state)
            sys.exit(0)
        if action == "del":
            name = after(rest, "del")
            if fail("del_tap" if name.startswith("vprlab-tap") else "del_bridge"):
                sys.exit(1)
            state["links"].pop(name, None)
            save(state)
            sys.exit(0)
        if action == "show":
            def document_for(name, entry):
                document = {
                    "ifindex": 9 if name == "vprlab-tap0" else 8,
                    "ifname": name,
                    "flags": ["BROADCAST", "MULTICAST"],
                    "mtu": 1500,
                    "operstate": entry.get("operstate", "DOWN"),
                    "linkmode": "DEFAULT",
                    "group": "default",
                    "txqlen": 1000,
                    "link_type": "ether",
                    "address": entry.get("address", "52:54:00:76:70:02"),
                    "broadcast": "ff:ff:ff:ff:ff:ff",
                }
                if entry.get("ifalias") is not None:
                    document["ifalias"] = entry["ifalias"]
                if entry.get("master"):
                    document["master"] = entry["master"]
                if "-d" in options:
                    info = {"info_kind": entry.get("kind", "tun"), "info_data": {}}
                    if entry.get("kind") == "tun":
                        info["info_data"] = {
                            "type": entry.get("tap_type", "tap"),
                            "user": "vprlab-qemu",
                        }
                    document["linkinfo"] = info
                return document
            if "dev" in rest:
                name = after(rest, "dev")
                entry = state["links"].get(name)
                if entry is None:
                    sys.exit(1)
                if "-j" not in options:
                    sys.stdout.write(name + "\\n")
                    sys.exit(0)
                sys.stdout.write(json.dumps([document_for(name, entry)]) + "\\n")
                sys.exit(0)
            if fail("link_inventory"):
                sys.stderr.write("RTNETLINK answers: No buffer space available\\n")
                sys.exit(2)
            if fail("link_inventory_json"):
                sys.stdout.write("not json\\n")
                sys.exit(0)
            if "-j" not in options:
                for name in state["links"]:
                    sys.stdout.write(name + "\\n")
                sys.exit(0)
            sys.stdout.write(
                json.dumps(
                    [document_for(name, entry) for name, entry in state["links"].items()]
                )
                + "\\n"
            )
            sys.exit(0)
        if action == "set":
            if "dev" in rest:
                name = after(rest, "dev")
                target = rest[rest.index("dev") + 2]
            else:
                name = rest[2]
                target = rest[3]
            entry = state["links"].get(name)
            if entry is None:
                sys.exit(1)
            if target == "alias":
                entry["ifalias"] = rest[rest.index("alias") + 1]
            elif target == "address":
                entry["address"] = rest[rest.index("address") + 1]
            elif target == "master":
                entry["master"] = rest[rest.index("master") + 1]
            elif target == "up":
                entry["operstate"] = "UP"
            elif target == "down":
                if fail("tap_down"):
                    sys.exit(1)
                entry["operstate"] = "DOWN"
            elif target == "nomaster":
                if fail("nomaster"):
                    sys.exit(1)
                entry["master"] = None
            else:
                sys.exit(99)
            save(state)
            sys.exit(0)
        sys.exit(99)
    if command == "neigh":
        action = rest[1]
        if action == "replace":
            ip = rest[2]
            mac = after(rest, "lladdr")
            state["neigh"][ip] = {"lladdr": mac, "permanent": True}
            save(state)
            sys.exit(0)
        if action == "del":
            state["neigh"].pop(rest[2], None)
            save(state)
            sys.exit(0)
        if action == "show":
            entries = []
            selected = None
            if len(rest) > 2:
                selected = rest[2]
            for ip, entry in state["neigh"].items():
                if selected is not None and ip != selected:
                    continue
                entries.append(
                    {
                        "dst": ip,
                        "dev": after(rest, "dev") if "dev" in rest else "vprlab0",
                        "lladdr": entry["lladdr"],
                        "nud_state": "permanent",
                        "state": ["PERMANENT"],
                    }
                )
            if "-j" in options:
                sys.stdout.write(json.dumps(entries) + "\\n")
            sys.exit(0)
        sys.exit(99)
    sys.exit(99)

if NAME == "nft":
    options, rest = split_options(ARGS)
    if not rest:
        sys.exit(99)
    command = rest[0]
    if command == "create" and rest[1] == "table":
        if fail("nft_create") or state.get("table") is not None:
            sys.exit(1)
        joined = " ".join(rest)
        match = re.search(r'comment\\s+"([^"]+)"', joined)
        if match is None:
            sys.exit(1)
        state["table"] = {
            "family": rest[2],
            "name": rest[3],
            "comment": match.group(1),
        }
        save(state)
        sys.exit(0)
    if command == "delete" and rest[1] == "table":
        if fail("nft_delete"):
            sys.exit(1)
        state["table"] = None
        save(state)
        sys.exit(0)
    if command == "list" and rest[1] == "table":
        table = state.get("table")
        if table is None:
            sys.exit(1)
        if "-j" in options:
            sys.stdout.write(
                json.dumps(
                    {
                        "nftables": [
                            {"metainfo": {"version": "1.1.3"}},
                            {"table": table},
                        ]
                    }
                )
                + "\\n"
            )
        else:
            sys.stdout.write("table " + table["family"] + " " + table["name"] + "\\n")
        sys.exit(0)
    if command in ("create", "add"):
        sys.exit(0)
    sys.exit(99)

if NAME == "iptables":
    if len(ARGS) < 2:
        sys.exit(99)
    action = ARGS[0]
    spec = " ".join(ARGS[1:])
    if action == "-I":
        state["rules"].append(spec)
        save(state)
        sys.exit(0)
    if action == "-C":
        if fail("iptables_check"):
            sys.exit(2)
        sys.exit(0 if spec in state["rules"] else 1)
    if action == "-D":
        if fail("iptables_delete"):
            sys.exit(1)
        if spec not in state["rules"]:
            sys.exit(1)
        state["rules"].remove(spec)
        save(state)
        sys.exit(0)
    sys.exit(99)

sys.exit(99)
'''


def _prepare_stub_lab(root, plan):
    bin_dir = root / "bin"
    bin_dir.mkdir()
    stub = bin_dir / "stub.py"
    stub.write_text(_STUB_SOURCE, encoding="utf-8")
    stub.chmod(0o755)
    for name in ("ip", "nft", "iptables", "sysctl", "tcpdump"):
        (bin_dir / name).symlink_to("stub.py")
    script = root / "lab.sh"
    script.write_text(plan, encoding="utf-8")
    script.chmod(0o755)
    return bin_dir, script


def _stub_env(root, bin_dir, **extra):
    log_path = root / "calls.log"
    state_path = root / "state.json"
    environment = dict(os.environ)
    environment["PATH"] = str(bin_dir) + ":" + environment.get("PATH", "")
    environment["STUB_LOG"] = str(log_path)
    environment["STUB_STATE"] = str(state_path)
    environment["VPRLAB_RUN_DIR"] = str(root / "run")
    environment.update({key: str(value) for key, value in extra.items()})
    return environment, log_path, state_path


def _write_state(path, state):
    path.write_text(json.dumps(state), encoding="utf-8")


def _read_state(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _valid_owner(root, token="a" * 32):
    run_dir = root / "run"
    run_dir.mkdir()
    (run_dir / "owner.json").write_text(
        json.dumps(
            {
                "schema": 1,
                "token": token,
                "created": "2026-11-09T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    return "vprlab-owned:" + token


def _owned_state(owner):
    return {
        "links": {
            "vprlab-tap0": {
                "ifalias": owner,
                "operstate": "UP",
                "kind": "tun",
                "tap_type": "tap",
                "master": "vprlab0",
                "address": "52:54:00:76:70:02",
            },
            "vprlab0": {
                "ifalias": owner,
                "operstate": "UP",
                "kind": "bridge",
                "tap_type": None,
                "master": None,
                "address": "52:54:00:76:70:01",
            },
        },
        "neigh": {
            "10.250.0.2": {
                "lladdr": "52:54:00:76:70:02",
                "permanent": True,
            }
        },
        "table": {
            "family": "inet",
            "name": "vprlab",
            "comment": owner,
        },
        "rules": [
            "DOCKER-USER -i vprlab0 -o eth0 -s 10.250.0.0/24 -m comment --comment "
            + owner
            + " -j ACCEPT",
            "DOCKER-USER -i eth0 -o vprlab0 -d 10.250.0.0/24 -m conntrack "
            "--ctstate ESTABLISHED,RELATED -m comment --comment "
            + owner
            + " -j ACCEPT",
        ],
    }


def _addresses(*entries):
    return json.dumps(list(entries))


def _routes(*entries):
    return json.dumps(list(entries))


CLEAN_LINKS = _links("lo", "eth0")
CLEAN_ADDRS = _addresses(
    {"ifname": "eth0", "addr_info": [{"family": "inet", "local": "192.0.2.10", "prefixlen": 24}]}
)
CLEAN_ROUTES = _routes({"dst": "192.0.2.0/24", "dev": "eth0"})
CLEAN_TABLES = json.dumps({"nftables": [{"metainfo": {"version": "1.1.1"}}]})
CLEAN_IPTABLES = """# Generated by iptables-save v1.8.9 on Mon Nov  9 00:00:00 2026
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:DOCKER-USER - [0:0]
-A FORWARD -j DOCKER-USER
COMMIT
"""
DOCKER_DROP_IPTABLES = """*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:DOCKER-USER - [0:0]
-A FORWARD -j DOCKER-USER
COMMIT
"""
DOCKER_DROP_NO_USER = """*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A FORWARD -j DOCKER-USER
COMMIT
"""


class NetplanTests(unittest.TestCase):
    def test_plan_contains_required_objects_and_capture(self):
        plan = netplan.render_plan("eth0")
        for expected in (
            "ip link add vprlab0 type bridge",
            "ip link set vprlab0 address 52:54:00:76:70:01",
            "ip addr add 10.250.0.1/24 dev vprlab0",
            "ip tuntap add dev vprlab-tap0 mode tap user vprlab-qemu",
            "ip link set dev vprlab-tap0 master vprlab0",
            "sysctl -w net.ipv6.conf.vprlab0.disable_ipv6=1",
            'nft create table inet vprlab',
            'nft add rule inet vprlab postrouting ip saddr 10.250.0.0/24 iifname "vprlab0" oifname "eth0" masquerade',
            'nft add rule inet vprlab forward iifname "vprlab0" oifname "eth0" accept',
            'nft add rule inet vprlab forward iifname "eth0" oifname "vprlab0" accept',
            "tcpdump -i vprlab-tap0 -nn -U --immediate-mode -B 8192 -s 0 -w "
            "\"$RUN_DIR\"/'manual-capture.pcap'",
        ):
            self.assertIn(expected, plan)
        self.assertNotIn("flush ruleset", plan)
        self.assertNotIn("flush", plan.lower())

    def test_teardown_is_a_standalone_script(self):
        plan = netplan.render_plan("eth0")
        self.assertTrue(plan.startswith("#!/bin/sh\n"))
        self.assertIn("set -eu", plan.splitlines()[1])
        self.assertIn("# not for interactive paste", plan)
        self.assertIn("tcpdump -i vprlab-tap0 -nn -U --immediate-mode -B 8192 -s 0 -w", plan)
        self.assertIn('if [ "${1:-}" = "teardown" ]; then', plan)
        self.assertIn("\ndo_teardown\n", plan)

    def test_owner_record_is_per_run_and_setup_refuses_existing(self):
        plan = netplan.render_plan("eth0")
        self.assertIn("/run/vprlab", plan)
        self.assertIn('RUN_DIR="${VPRLAB_RUN_DIR:-/run/vprlab}"', plan)
        self.assertIn('os.O_WRONLY | os.O_CREAT | os.O_EXCL', plan)
        self.assertIn("0o600", plan)
        self.assertIn("os.makedirs(run_dir, mode=0o700, exist_ok=True)", plan)
        self.assertIn("os.chmod(run_dir, 0o700)", plan)
        self.assertIn('open("/dev/urandom", "rb").read(16).hex()', plan)
        self.assertIn('"schema": 1', plan)
        self.assertIn('print("vprlab-owned:" + token)', plan)
        # No fixed tag from an older run may authorize anything.
        self.assertNotIn("vprlab-leak-lab-m1", plan)
        # The owner record is created before any link exists.
        self.assertLess(
            plan.index("create_owner\n"),
            plan.index("ip tuntap add dev vprlab-tap0"),
        )
        self.assertLess(
            plan.index("create_owner\n"),
            plan.index("ip link add vprlab0 type bridge"),
        )

    def test_opus_m5_setup_creates_links_down_then_protection_then_up(self):
        plan = netplan.render_plan("eth0")
        body = plan.split('if [ "${1:-}" = "teardown" ]; then', 1)[1]
        owner = body.index("create_owner\n")
        tap_alias = body.index('ip link set dev vprlab-tap0 alias "$OWNER"')
        bridge_alias = body.index('ip link set dev vprlab0 alias "$OWNER"')
        table = body.index("nft create table inet vprlab")
        input_drop = body.index('nft add rule inet vprlab input iifname "vprlab0" drop')
        output_drop = body.index(
            'nft add rule inet vprlab output oifname "vprlab0" meta nfproto ipv4 drop'
        )
        masquerade = body.index("masquerade")
        docker = body.index("iptables -I DOCKER-USER")
        neigh = body.index("ip neigh replace 10.250.0.2")
        tap_up = body.index("ip link set vprlab-tap0 up")
        bridge_up = body.index("ip link set vprlab0 up")
        self.assertLess(owner, tap_alias)
        self.assertLess(owner, bridge_alias)
        self.assertLess(bridge_alias, table)
        self.assertLess(table, input_drop)
        self.assertLess(input_drop, output_drop)
        self.assertLess(output_drop, masquerade)
        for command in (
            'nft add rule inet vprlab forward iifname "vprlab0" oifname "eth0" accept',
            'nft add rule inet vprlab forward iifname "eth0" oifname "vprlab0" accept',
        ):
            self.assertLess(body.index(command), masquerade)
        self.assertLess(masquerade, docker)
        self.assertLess(docker, neigh)
        self.assertLess(neigh, tap_up)
        self.assertLess(tap_up, bridge_up)
        # Links are not brought up before the protections exist.
        for command in (
            "ip link set vprlab-tap0 up",
            "ip link set vprlab0 up",
        ):
            self.assertGreater(body.index(command), docker)

    @staticmethod
    def _embedded_check(plan, marker):
        text = plan.split(marker, 1)[1]
        needle = "python3 -c '"
        start = text.index(needle) + len(needle)
        end = text.index("\n'", start)
        return text[start:end]

    def _run_embedded(self, code, document, *args):
        return subprocess.run(
            [sys.executable, "-c", code, *args],
            input=json.dumps(document),
            capture_output=True,
            text=True,
            timeout=30,
        ).returncode

    @staticmethod
    def _tap_detail(ifalias, *, kind="tun", tap="tap"):
        return [
            {
                "ifindex": 9,
                "ifname": netplan.TAP,
                "flags": ["BROADCAST", "MULTICAST"],
                "mtu": 1500,
                "operstate": "DOWN",
                "linkmode": "DEFAULT",
                "ifalias": ifalias,
                "group": "default",
                "txqlen": 1000,
                "link_type": "ether",
                "address": "52:54:00:76:70:02",
                "broadcast": "ff:ff:ff:ff:ff:ff",
                "linkinfo": {
                    "info_kind": kind,
                    "info_data": {"type": tap},
                },
            }
        ]

    @staticmethod
    def _bridge_detail(ifalias):
        return [
            {
                "ifindex": 8,
                "ifname": netplan.BRIDGE,
                "flags": ["BROADCAST", "MULTICAST"],
                "mtu": 1500,
                "operstate": "DOWN",
                "linkmode": "DEFAULT",
                "ifalias": ifalias,
                "group": "default",
                "txqlen": 1000,
                "link_type": "ether",
                "address": "52:54:00:76:70:01",
                "broadcast": "ff:ff:ff:ff:ff:ff",
                "linkinfo": {"info_kind": "bridge", "info_data": {}},
            }
        ]

    def test_gpt_i2_opus_i1_embedded_checks_use_ifalias_and_real_shapes(self):
        plan = netplan.render_plan("eth0")
        owner = netplan.OWNER_PREFIX + "a" * 32
        nft_code = self._embedded_check(
            plan, "nft -j list table inet vprlab 2>/dev/null |"
        )
        self.assertEqual(
            self._run_embedded(
                nft_code,
                {
                    "nftables": [
                        {
                            "table": {
                                "family": "inet",
                                "name": "vprlab",
                                "comment": owner,
                            }
                        }
                    ]
                },
                owner,
            ),
            0,
        )
        # A comment on a rule elsewhere in the table is not table ownership.
        self.assertEqual(
            self._run_embedded(
                nft_code,
                {
                    "nftables": [
                        {
                            "table": {
                                "family": "inet",
                                "name": "vprlab",
                                "comment": "other",
                            }
                        },
                        {"rule": {"comment": owner}},
                    ]
                },
                owner,
            ),
            1,
        )
        link_code = self._embedded_check(plan, "link_owned() {")
        self.assertEqual(
            self._run_embedded(
                link_code,
                self._tap_detail(owner),
                netplan.TAP,
                owner,
                "tun",
            ),
            0,
        )
        # Minimal two-field iproute2 JSON is still exact ifalias ownership.
        self.assertEqual(
            self._run_embedded(
                link_code,
                [{"ifname": netplan.TAP, "ifalias": owner}],
                netplan.TAP,
                owner,
                "tun",
            ),
            0,
        )
        # The key iproute2 actually emits is ifalias, not alias.
        alias_only = self._tap_detail(owner)
        alias_only[0]["alias"] = alias_only[0].pop("ifalias")
        self.assertEqual(
            self._run_embedded(
                link_code,
                alias_only,
                netplan.TAP,
                owner,
                "tun",
            ),
            1,
        )
        # A NOT-OWNED-<tag>-backup style value is not exact ownership.
        self.assertEqual(
            self._run_embedded(
                link_code,
                self._tap_detail("NOT-OWNED-" + owner + "-backup"),
                netplan.TAP,
                owner,
                "tun",
            ),
            1,
        )
        # Same ifname and ifalias but the wrong link kind is refused.
        self.assertEqual(
            self._run_embedded(
                link_code,
                self._tap_detail(owner, kind="bridge"),
                netplan.TAP,
                owner,
                "tun",
            ),
            1,
        )
        self.assertEqual(
            self._run_embedded(
                link_code,
                [{"ifname": "other0", "ifalias": owner}],
                netplan.TAP,
                owner,
                "tun",
            ),
            1,
        )
        bridge_code = link_code
        self.assertEqual(
            self._run_embedded(
                bridge_code,
                self._bridge_detail(owner),
                netplan.BRIDGE,
                owner,
                "bridge",
            ),
            0,
        )
        self.assertEqual(
            self._run_embedded(
                bridge_code,
                self._bridge_detail("foreign"),
                netplan.BRIDGE,
                owner,
                "bridge",
            ),
            1,
        )

    def test_teardown_verifies_before_mutation_and_isolates_first(self):
        plan = netplan.render_plan("eth0")
        teardown = plan.split("# --- 4. teardown ---", 1)[1]
        verify = teardown.index("if ! verify_ownership; then")
        isolation = teardown.index("if ! isolate_tap; then")
        neigh = teardown.index("ip neigh del")
        docker = teardown.index("remove_docker_out || failed=1")
        table = teardown.index("nft delete table inet vprlab")
        tap_del = teardown.index('delete_link "vprlab-tap0" tun')
        bridge_del = teardown.index('delete_link "vprlab0" bridge')
        owner_rm = teardown.index('rm -f "$OWNER_FILE"')
        self.assertLess(verify, isolation)
        self.assertLess(isolation, neigh)
        self.assertLess(neigh, docker)
        self.assertLess(docker, table)
        self.assertLess(table, tap_del)
        self.assertLess(tap_del, bridge_del)
        self.assertLess(bridge_del, owner_rm)
        # Isolation failure stops immediately; protections are not touched.
        isolation_block = teardown[
            isolation : teardown.index("failed=0", isolation)
        ]
        self.assertNotIn("nft delete", isolation_block)
        self.assertNotIn("iptables -D", isolation_block)
        self.assertIn("still installed", isolation_block)
        # Ownership failure also stops before any mutation.
        verify_block = teardown[verify:isolation]
        self.assertNotIn("ip link set", verify_block)
        self.assertNotIn("ip neigh del", verify_block)
        self.assertNotIn("nft delete", verify_block)
        self.assertNotIn("iptables -D", verify_block)
        self.assertIn("without changes", verify_block)
        # Duplicate owned DOCKER-USER rules are removed until none remain.
        self.assertIn("if iptables -C DOCKER-USER", plan)
        self.assertIn("iptables -D DOCKER-USER", plan)
        self.assertIn('echo "netplan: cannot inspect the outbound DOCKER-USER rule', plan)
        # The owner record is removed only after every step succeeded.
        self.assertIn("teardown incomplete; $OWNER_FILE retained for retry", teardown)
        # The script traps signals and runs teardown of what this run created.
        self.assertIn("trap cleanup INT TERM HUP EXIT", plan)
        self.assertIn("RUN_STARTED=1", plan)

    def _run_lab(self, root, plan, state, *, args=(), fails="", extra=None, timeout=30):
        bin_dir, script = _prepare_stub_lab(root, plan)
        environment, log_path, state_path = _stub_env(
            root, bin_dir, STUB_FAIL=fails
        )
        if extra:
            environment.update({key: str(value) for key, value in extra.items()})
        _write_state(state_path, state)
        result = subprocess.run(
            ["sh", str(script), *args],
            env=environment,
            cwd=root,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        log = log_path.read_text(encoding="utf-8") if log_path.exists() else ""
        return result, log, _read_state(state_path), root / "run" / "owner.json"

    def test_gpt_i2_setup_refuses_existing_owner_record(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            owner_path = root / "run" / "owner.json"
            owner_path.parent.mkdir()
            original = json.dumps(
                {"schema": 1, "token": "b" * 32, "created": "2026-11-09T00:00:00Z"}
            )
            owner_path.write_text(original, encoding="utf-8")
            result, log, _state, _owner = self._run_lab(
                root, netplan.render_plan("eth0"), {}
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("already exists", result.stderr)
            self.assertNotIn("tuntap add", log)
            self.assertNotIn("link add", log)
            self.assertEqual(owner_path.read_text(encoding="utf-8"), original)

    def test_gpt_i2_opus_i1_teardown_aborts_before_any_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            owner = _valid_owner(root)
            state = _owned_state(owner)
            state["links"]["vprlab-tap0"]["ifalias"] = "foreign-owner"
            result, log, state_after, owner_path = self._run_lab(
                root, netplan.render_plan("eth0"), state, args=("teardown",)
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("refusing teardown", result.stderr)
            self.assertIn("aborted without changes", result.stderr)
            for line in log.splitlines():
                self.assertNotIn("link set", line)
                self.assertNotIn("neigh del", line)
                self.assertNotIn("nft delete", line)
                self.assertNotIn("iptables -D", line)
            self.assertTrue(owner_path.exists())
            self.assertEqual(state_after, state)

    def test_gpt_i3_teardown_isolation_failure_keeps_protection(self):
        for failure in ("tap_down", "nomaster"):
            with self.subTest(failure=failure):
                with tempfile.TemporaryDirectory() as directory:
                    root = pathlib.Path(directory)
                    owner = _valid_owner(root)
                    state = _owned_state(owner)
                    result, log, state_after, owner_path = self._run_lab(
                        root,
                        netplan.render_plan("eth0"),
                        state,
                        args=("teardown",),
                        fails=failure,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("protections", result.stderr)
                    for line in log.splitlines():
                        self.assertNotIn("neigh del", line)
                        self.assertNotIn("nft delete", line)
                        self.assertNotIn("iptables -D", line)
                        self.assertNotIn("link del", line)
                    self.assertTrue(owner_path.exists())
                    self.assertIsNotNone(state_after["table"])
                    self.assertEqual(len(state_after["rules"]), 2)
                    self.assertEqual(len(state_after["links"]), 2)

    def test_gpt_i3_teardown_removes_duplicates_then_owner_record(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            owner = _valid_owner(root)
            state = _owned_state(owner)
            # Older duplicate copies of this run's exact owned rules.
            state["rules"] = state["rules"] * 3
            result, _log, state_after, owner_path = self._run_lab(
                root, netplan.render_plan("eth0"), state, args=("teardown",)
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(state_after["rules"], [])
            self.assertIsNone(state_after["table"])
            self.assertEqual(state_after["links"], {})
            self.assertEqual(state_after["neigh"], {})
            self.assertFalse(owner_path.exists())
            self.assertIn("teardown complete", result.stdout)

    def test_gpt_i3_teardown_failure_returns_nonzero_and_keeps_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            owner = _valid_owner(root)
            state = _owned_state(owner)
            result, log, _state_after, owner_path = self._run_lab(
                root,
                netplan.render_plan("eth0"),
                state,
                args=("teardown",),
                fails="del_bridge",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("teardown incomplete", result.stderr)
            self.assertIn("retained for retry", result.stderr)
            self.assertTrue(owner_path.exists())
            self.assertIn("nft delete table inet vprlab", log)

    def test_opus_m1_trap_runs_teardown_after_signal(self):
        for stop_signal in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            with self.subTest(signal=stop_signal.name):
                with tempfile.TemporaryDirectory() as directory:
                    root = pathlib.Path(directory)
                    bin_dir, script = _prepare_stub_lab(
                        root, netplan.render_plan("eth0")
                    )
                    environment, log_path, state_path = _stub_env(
                        root, bin_dir, STUB_TCPDUMP_SLEEP="30"
                    )
                    _write_state(state_path, {})
                    process = subprocess.Popen(
                        ["sh", str(script)],
                        env=environment,
                        cwd=root,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        start_new_session=True,
                    )
                    try:
                        deadline = time.monotonic() + 10
                        while time.monotonic() < deadline:
                            if log_path.exists() and "tcpdump" in log_path.read_text(
                                encoding="utf-8"
                            ):
                                break
                            time.sleep(0.05)
                        else:
                            self.fail("setup never reached tcpdump")
                        owner_path = root / "run" / "owner.json"
                        self.assertTrue(owner_path.exists())
                        owner_doc = json.loads(owner_path.read_text(encoding="utf-8"))
                        self.assertEqual(owner_doc["schema"], 1)
                        self.assertRegex(owner_doc["token"], r"^[0-9a-f]{32}$")
                        self.assertTrue(owner_doc["created"].endswith("Z"))
                        self.assertEqual(owner_path.stat().st_mode & 0o777, 0o600)
                        self.assertEqual(
                            (root / "run").stat().st_mode & 0o777, 0o700
                        )
                        os.killpg(process.pid, stop_signal)
                        process.wait(timeout=20)
                    finally:
                        if process.poll() is None:
                            process.kill()
                            process.wait(timeout=10)
                    log = log_path.read_text(encoding="utf-8")
                    self.assertIn("ip link set dev vprlab-tap0 down", log)
                    self.assertFalse((root / "run" / "owner.json").exists())
                    state_after = _read_state(state_path)
                    self.assertEqual(state_after["links"], {})
                    self.assertIsNone(state_after["table"])

    def test_opus_m1_normal_setup_tears_down(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            result, _log, state_after, owner_path = self._run_lab(
                root, netplan.render_plan("eth0"), {}
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(owner_path.exists())
            self.assertEqual(state_after["links"], {})
            self.assertIsNone(state_after["table"])
            self.assertEqual(state_after["rules"], [])
            self.assertEqual(state_after["neigh"], {})

    def test_opus_m1_exit_trap_tears_down_after_setup_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            result, log, state_after, owner_path = self._run_lab(
                root,
                netplan.render_plan("eth0"),
                {},
                fails="nft_create",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("ip link set dev vprlab-tap0 down", log)
            self.assertFalse(owner_path.exists())
            self.assertEqual(state_after["links"], {})
            self.assertIsNone(state_after.get("table"))

    def test_gpt_i2_docker_user_rules_are_scoped_and_removed_by_run_token(self):
        plan = netplan.render_plan("eno1")
        insert = [
            line.strip()
            for line in plan.splitlines()
            if line.strip().startswith("iptables -I DOCKER-USER")
        ]
        self.assertEqual(len(insert), 2)
        for expected in (
            "-i vprlab0 -o eno1 -s 10.250.0.0/24",
            "-i eno1 -o vprlab0 -d 10.250.0.0/24 -m conntrack --ctstate ESTABLISHED,RELATED",
        ):
            self.assertTrue(any(expected in line for line in insert), expected)
        for line in insert:
            self.assertIn('-m comment --comment "$OWNER"', line)
            self.assertIn("-j ACCEPT", line)
        teardown = plan.split("# --- 4. teardown ---", 1)[1]
        # Teardown checks and deletes the identical owned specification in a
        # loop, so duplicate copies of this run's exact rule do not remain.
        for expected in (
            "-i vprlab0 -o eno1 -s 10.250.0.0/24",
            "-i eno1 -o vprlab0 -d 10.250.0.0/24 -m conntrack --ctstate ESTABLISHED,RELATED",
        ):
            self.assertIn(f"iptables -C DOCKER-USER {expected}", plan)
            self.assertIn(f"iptables -D DOCKER-USER {expected}", plan)
        self.assertNotIn("--comment vprlab-owned", plan)
        self.assertIn('-m comment --comment "$OWNER"', plan)
        self.assertIn("iptables-nft", plan)
        self.assertIn("DOCKER-USER", plan)
        self.assertNotIn("iptables -F", plan)

    def test_capture_argv_matches_printed_command(self):
        plan = netplan.render_plan("eth0", capture_file="/var/tmp/phase.pcap")
        self.assertEqual(
            netplan.capture_argv("/var/tmp/phase.pcap"),
            [
                "tcpdump",
                "-i",
                "vprlab-tap0",
                "-nn",
                "-U",
                "--immediate-mode",
                "-B",
                "8192",
                "-s",
                "0",
                "-w",
                "/var/tmp/phase.pcap",
            ],
        )
        self.assertIsNone(
            netplan.check_capture_argv(netplan.capture_argv("/var/tmp/x.pcap"))
        )
        self.assertEqual(
            netplan.check_capture_argv(
                ["tcpdump", "-i", "vprlab-tap0", "-nn", "-s", "0", "-w", "/var/tmp/x.pcap"]
            ),
            "capture_argv_mismatch",
        )
        self.assertEqual(
            netplan.check_capture_argv("tcpdump"),
            "capture_argv_invalid",
        )
        self.assertIn(
            "tcpdump -i vprlab-tap0 -nn -U --immediate-mode -B 8192 -s 0 -w /var/tmp/phase.pcap",
            plan,
        )

    def test_tap_user_option(self):
        plan = netplan.render_plan("eth0", tap_user="vprouterlab")
        self.assertIn("ip tuntap add dev vprlab-tap0 mode tap user vprouterlab", plan)
        default = netplan.render_plan("eth0")
        self.assertIn("ip tuntap add dev vprlab-tap0 mode tap user vprlab-qemu", default)
        for user in ("root", "0", "00", "-root", "root\n"):
            with self.subTest(user=user):
                with self.assertRaises(netplan.NetplanError):
                    netplan.render_plan("eth0", tap_user=user)

    def test_rejects_lab_interface_as_wan(self):
        with self.assertRaises(netplan.NetplanError):
            netplan.render_plan("vprlab0")

    def test_rejects_loopback_and_dash_wan(self):
        for name in ("lo", ".", "-x", ".."):
            with self.subTest(name=name):
                with self.assertRaises(netplan.NetplanError):
                    netplan.render_plan(name)

    # --------------------------------------------------- input/output (I4/F-06)
    def test_input_chain_drops_all_lab_ingress(self):
        plan = netplan.render_plan("eth0")
        self.assertIn(
            'nft create chain inet vprlab input { type filter hook input priority filter; policy accept; }',
            plan.replace('"', "").replace("'", ""),
        )
        self.assertIn(
            'nft add rule inet vprlab input iifname "vprlab0" drop', plan
        )
        executable = [
            line for line in plan.splitlines() if line.strip().startswith("nft")
        ]
        self.assertFalse(any("reject" in line for line in executable))

    def test_output_chain_drops_host_ipv4_to_lab(self):
        plan = netplan.render_plan("eth0")
        self.assertIn(
            'nft create chain inet vprlab output { type filter hook output priority filter; policy accept; }',
            plan.replace('"', "").replace("'", ""),
        )
        self.assertIn(
            'nft add rule inet vprlab output oifname "vprlab0" meta nfproto ipv4 drop',
            plan,
        )

    # ---------------------------------------------------------- scope (I7/F-08)
    def test_masquerade_is_scoped_to_lab_ingress_and_subnet(self):
        plan = netplan.render_plan("eth0")
        rule = next(
            line
            for line in plan.splitlines()
            if line.strip().startswith("nft add rule") and "masquerade" in line
        )
        self.assertIn('iifname "vprlab0"', rule)
        self.assertIn("ip saddr 10.250.0.0/24", rule)
        self.assertIn('oifname "eth0"', rule)

    # ------------------------------------------------------ ownership (I8/F-14)
    def test_table_creation_is_exclusive_and_marked_with_the_run_token(self):
        plan = netplan.render_plan("eth0")
        self.assertIn(
            'nft create table inet vprlab "{ comment \\"$OWNER\\"; }"', plan
        )
        self.assertIn(netplan.OWNER_PREFIX, plan)
        self.assertNotIn("nft add table", plan)
        self.assertNotIn("vprlab-leak-lab-m1", plan)

    def test_links_carry_the_run_token_as_ifalias(self):
        plan = netplan.render_plan("eth0")
        self.assertIn('ip link set dev vprlab0 alias "$OWNER"', plan)
        self.assertIn('ip link set dev vprlab-tap0 alias "$OWNER"', plan)
        self.assertNotIn('alias "vprlab-leak-lab-m1"', plan)
        self.assertIn('entry.get("ifalias") == owner', plan)

    def test_opus_m8_plan_uses_fixed_macs_and_installs_neighbour(self):
        plan = netplan.render_plan("eth0")
        self.assertEqual(netplan.BRIDGE_MAC, "52:54:00:76:70:01")
        self.assertEqual(netplan.VM_WAN_MAC, "52:54:00:76:70:02")
        bridge_mac = plan.index(
            "ip link set vprlab0 address 52:54:00:76:70:01"
        )
        tap_up = plan.index("ip link set vprlab-tap0 up")
        bridge_up = plan.index("ip link set vprlab0 up")
        self.assertLess(bridge_mac, tap_up)
        self.assertLess(bridge_mac, bridge_up)
        neighbour = (
            "ip neigh replace 10.250.0.2 lladdr 52:54:00:76:70:02 "
            "dev vprlab0 nud permanent"
        )
        self.assertIn(neighbour, plan)
        self.assertLess(plan.index(neighbour), tap_up)
        # Teardown removes the same neighbour only after ownership checks.
        teardown = plan.split("# --- 4. teardown ---", 1)[1]
        self.assertIn("ip neigh del 10.250.0.2 dev vprlab0", teardown)

    def test_ip_forward_is_checked_not_changed(self):
        plan = netplan.render_plan("eth0")
        self.assertIn("sysctl -n net.ipv4.ip_forward", plan)
        self.assertIn("sysctl -w net.ipv4.ip_forward=1", plan)
        self.assertIn("sysctl -w net.ipv4.ip_forward=0", plan)
        executable = [
            line.strip()
            for line in plan.splitlines()
            if line.strip()
            and not line.strip().startswith("#")
            and "sysctl -w net.ipv4.ip_forward" in line
        ]
        self.assertEqual(executable, [])

    def test_ipv6_is_disabled_before_lab_links_come_up(self):
        plan = netplan.render_plan("eth0")
        tap_sysctl = plan.index("sysctl -w net.ipv6.conf.vprlab-tap0.disable_ipv6=1")
        tap_up = plan.index("ip link set vprlab-tap0 up")
        self.assertLess(tap_sysctl, tap_up)

    # --------------------------------------------------- collision (I8/F-08)
    def test_clean_preflight(self):
        self.assertEqual(
            netplan.check_name_collisions(
                CLEAN_LINKS, CLEAN_ADDRS, CLEAN_ROUTES, CLEAN_TABLES, "eth0", CLEAN_IPTABLES
            ),
            [],
        )

    def test_preflight_requires_all_inventories(self):
        with self.assertRaises(TypeError):
            netplan.check_name_collisions(CLEAN_LINKS)
        with self.assertRaises(TypeError):
            netplan.check_name_collisions(CLEAN_LINKS, CLEAN_ADDRS)

    def test_malformed_links_inventory_rejected(self):
        for text in ("[null, {}, 7]", "{}", '[{"ifname": 3}]'):
            with self.subTest(text=text):
                with self.assertRaises(netplan.NetplanError):
                    netplan.check_name_collisions(
                        text, CLEAN_ADDRS, CLEAN_ROUTES, CLEAN_TABLES, "eth0", CLEAN_IPTABLES
                    )

    def test_malformed_tables_inventory_rejected(self):
        for text in (
            '{"nftables":[{"table":{"family":"inet"}}]}',
            '{"nftables":[null]}',
            '[]',
        ):
            with self.subTest(text=text):
                with self.assertRaises(netplan.NetplanError):
                    netplan.check_name_collisions(
                        CLEAN_LINKS, CLEAN_ADDRS, CLEAN_ROUTES, text, "eth0", CLEAN_IPTABLES
                    )

    def test_malformed_address_and_route_inventory_rejected(self):
        with self.assertRaises(netplan.NetplanError):
            netplan.check_name_collisions(
                CLEAN_LINKS,
                '[{"ifname":"eth0","addr_info":[{"local":3}]}]',
                CLEAN_ROUTES,
                CLEAN_TABLES,
                "eth0",
                CLEAN_IPTABLES,
            )
        with self.assertRaises(netplan.NetplanError):
            netplan.check_name_collisions(
                CLEAN_LINKS,
                CLEAN_ADDRS,
                '[{"dst": "not-a-route"}]',
                CLEAN_TABLES,
                "eth0",
                CLEAN_IPTABLES,
            )

    def test_altname_collision_is_detected(self):
        links = _links("lo", "eth0", "eth1", altnames={"eth1": ["vprlab0"]})
        collisions = netplan.check_name_collisions(
            links, CLEAN_ADDRS, CLEAN_ROUTES, CLEAN_TABLES, "eth0"
        )
        self.assertTrue(any("vprlab0" in item for item in collisions))

    def test_default_route_is_not_a_subnet_collision(self):
        routes = _routes(
            {"dst": "default", "dev": "eth0"},
            {"dst": "0.0.0.0/0", "dev": "eth0"},
        )
        self.assertEqual(
            netplan.check_name_collisions(
                CLEAN_LINKS, CLEAN_ADDRS, routes, CLEAN_TABLES, "eth0", CLEAN_IPTABLES
            ),
            [],
        )

    def test_address_and_route_subnet_overlap_detected(self):
        addrs = _addresses(
            {"ifname": "eth0", "addr_info": [{"family": "inet", "local": "10.250.0.7", "prefixlen": 24}]}
        )
        collisions = netplan.check_name_collisions(
            CLEAN_LINKS, addrs, CLEAN_ROUTES, CLEAN_TABLES, "eth0"
        )
        self.assertTrue(any("10.250.0.0/24" in item for item in collisions))

        routes = _routes({"dst": "10.250.0.0/16", "dev": "eth0"})
        collisions = netplan.check_name_collisions(
            CLEAN_LINKS, CLEAN_ADDRS, routes, CLEAN_TABLES, "eth0", CLEAN_IPTABLES
        )
        self.assertTrue(any("10.250.0.0/24" in item for item in collisions))

    def test_wan_interface_must_exist_and_not_be_loopback(self):
        collisions = netplan.check_name_collisions(
            CLEAN_LINKS, CLEAN_ADDRS, CLEAN_ROUTES, CLEAN_TABLES, "lo", CLEAN_IPTABLES
        )
        self.assertTrue(any("lo" in item for item in collisions))
        collisions = netplan.check_name_collisions(
            CLEAN_LINKS, CLEAN_ADDRS, CLEAN_ROUTES, CLEAN_TABLES, "eno9", CLEAN_IPTABLES
        )
        self.assertTrue(any("eno9" in item for item in collisions))

    def test_existing_lab_objects_are_collisions(self):
        links = json.dumps(
            [
                {"ifname": "lo"},
                {"ifname": "eth0"},
                {"ifname": "vprlab0"},
                {"ifname": "vprlab-tap0"},
            ]
        )
        tables = json.dumps(
            {
                "nftables": [
                    {"metainfo": {"version": "1.0.9"}},
                    {"table": {"family": "inet", "name": "vprlab", "handle": 1}},
                ]
            }
        )
        collisions = netplan.check_name_collisions(
            links, CLEAN_ADDRS, CLEAN_ROUTES, tables, "eth0"
        )
        self.assertEqual(len(collisions), 3)

    def test_plan_preflight_collects_all_routing_tables(self):
        plan = netplan.render_plan("eth0")
        self.assertIn("ip -j route show table all > routes.json", plan)
        self.assertNotIn("ip -j route > routes.json", plan)

    def test_empty_route_object_is_rejected(self):
        for text in ('[{}]', '[{"dst": null}]', '[{"dst": "10.0.0.0/8", "table": 200}, {}]'):
            with self.subTest(text=text):
                with self.assertRaises(netplan.NetplanError):
                    netplan.check_name_collisions(
                        CLEAN_LINKS, CLEAN_ADDRS, text, CLEAN_TABLES, "eth0",
                        CLEAN_IPTABLES,
                    )

    def test_policy_route_table_overlap_is_detected(self):
        routes = _routes(
            {"dst": "10.250.0.0/24", "table": 52, "dev": "tailscale0"},
        )
        collisions = netplan.check_name_collisions(
            CLEAN_LINKS, CLEAN_ADDRS, routes, CLEAN_TABLES, "eth0", CLEAN_IPTABLES
        )
        self.assertTrue(any("10.250.0.0/24" in item for item in collisions))

    def test_docker_forward_drop_requires_docker_user(self):
        # Docker sets the FORWARD policy to DROP; without DOCKER-USER the
        # plan's -I DOCKER-USER fails and the lab has no WAN path.
        collisions = netplan.check_name_collisions(
            CLEAN_LINKS, CLEAN_ADDRS, CLEAN_ROUTES, CLEAN_TABLES, "eth0",
            DOCKER_DROP_NO_USER,
        )
        self.assertTrue(any("DOCKER-USER" in item for item in collisions))
        self.assertTrue(any("FORWARD" in item for item in collisions))

    def test_forward_drop_with_docker_user_is_clean(self):
        self.assertEqual(
            netplan.check_name_collisions(
                CLEAN_LINKS, CLEAN_ADDRS, CLEAN_ROUTES, CLEAN_TABLES, "eth0",
                DOCKER_DROP_IPTABLES,
            ),
            [],
        )

    def test_gpt_m2_docker_user_must_exist_even_with_accept_policy(self):
        text = CLEAN_IPTABLES.replace(":DOCKER-USER - [0:0]\n", "").replace(
            "-A FORWARD -j DOCKER-USER\n", ""
        )
        collisions = netplan.check_name_collisions(
            CLEAN_LINKS, CLEAN_ADDRS, CLEAN_ROUTES, CLEAN_TABLES, "eth0", text
        )
        self.assertTrue(any("DOCKER-USER" in item for item in collisions))
        self.assertTrue(any("FORWARD" in item for item in collisions))

    def test_gpt_m2_forward_must_jump_to_docker_user_before_docker_rules(self):
        text = CLEAN_IPTABLES.replace("-A FORWARD -j DOCKER-USER\n", "")
        collisions = netplan.check_name_collisions(
            CLEAN_LINKS, CLEAN_ADDRS, CLEAN_ROUTES, CLEAN_TABLES, "eth0", text
        )
        self.assertTrue(any("DOCKER-USER" in item for item in collisions))
        self.assertTrue(any("FORWARD" in item for item in collisions))

        after = CLEAN_IPTABLES.replace(
            "-A FORWARD -j DOCKER-USER\n",
            "-A FORWARD -j DOCKER-FORWARD\n-A FORWARD -j DOCKER-USER\n",
        )
        collisions = netplan.check_name_collisions(
            CLEAN_LINKS, CLEAN_ADDRS, CLEAN_ROUTES, CLEAN_TABLES, "eth0", after
        )
        self.assertTrue(any("DOCKER-USER" in item for item in collisions))
        summary = netplan.iptables_summary(after)
        self.assertTrue(summary["docker_user"])
        self.assertFalse(summary["docker_user_first"])

    def test_gpt_m2_docker_user_first_before_other_docker_rules(self):
        summary = netplan.iptables_summary(DOCKER_DROP_IPTABLES)
        self.assertTrue(summary["docker_user"])
        self.assertTrue(summary["docker_user_first"])
        self.assertEqual(summary["forward_jumps"], ["DOCKER-USER"])
        self.assertEqual(summary["forward_policy"], "DROP")

    def test_malformed_iptables_save_is_rejected(self):
        for text in ("", "not iptables", "*nat\nCOMMIT\n", "*filter\n-X\nCOMMIT\n"):
            with self.subTest(text=text):
                with self.assertRaises(netplan.NetplanError):
                    netplan.check_name_collisions(
                        CLEAN_LINKS, CLEAN_ADDRS, CLEAN_ROUTES, CLEAN_TABLES, "eth0",
                        text,
                    )

    def test_iptables_summary_reports_forward_policy_and_docker_user(self):
        summary = netplan.iptables_summary(DOCKER_DROP_IPTABLES)
        self.assertEqual(summary["forward_policy"], "DROP")
        self.assertTrue(summary["docker_user"])
        summary = netplan.iptables_summary(CLEAN_IPTABLES)
        self.assertEqual(summary["forward_policy"], "ACCEPT")
        self.assertTrue(summary["docker_user"])

    def test_docs_require_static_neighbours_on_both_sides(self):
        document = (HERE.parents[1] / "docs/rust-v2/leak-lab.md").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "ip neigh replace 10.250.0.2 lladdr <vm-mac> dev vprlab0 nud permanent",
            document,
        )
        self.assertIn(
            "ip neigh replace 10.250.0.1 lladdr <gateway-mac> dev eth0 nud permanent",
            document,
        )

    def test_docs_match_fixed_macs_owner_record_and_l2_contract(self):
        document = (HERE.parents[1] / "docs/rust-v2/leak-lab.md").read_text(
            encoding="utf-8"
        )
        for expected in (
            "52:54:00:76:70:01",
            "52:54:00:76:70:02",
            "/run/vprlab/owner.json",
            "vprlab-owned:<token>",
            "ifalias",
            "allowed_tuple_wrong_l2",
            "allowed flow label",
        ):
            self.assertIn(expected, document)
        self.assertNotIn("vprlab-leak-lab-m1", document)

    def test_check_mode_reads_files_and_returns_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            paths = {}
            for name, text in (
                ("links", CLEAN_LINKS),
                ("addresses", CLEAN_ADDRS),
                ("routes", CLEAN_ROUTES),
                ("tables", CLEAN_TABLES),
                ("iptables", CLEAN_IPTABLES),
            ):
                path = root / f"{name}.json"
                path.write_text(text, encoding="utf-8")
                paths[name] = path

            def run():
                output = StringIO()
                errors = StringIO()
                with redirect_stdout(output), redirect_stderr(errors):
                    status = netplan.main(
                        [
                            "--check-name-collisions",
                            "--wan-interface",
                            "eth0",
                            "--links-json",
                            str(paths["links"]),
                            "--addresses-json",
                            str(paths["addresses"]),
                            "--routes-json",
                            str(paths["routes"]),
                            "--tables-json",
                            str(paths["tables"]),
                            "--iptables-save",
                            str(paths["iptables"]),
                        ]
                    )
                return status, output.getvalue()

            status, output = run()
            self.assertEqual(status, 0)
            self.assertIn("OK", output)

            paths["tables"].write_text(
                json.dumps({"nftables": [{"table": {"family": "inet", "name": "vprlab"}}]}),
                encoding="utf-8",
            )
            status, output = run()
            self.assertEqual(status, 1)
            self.assertIn("COLLISION", output)

            paths["tables"].write_text(CLEAN_TABLES, encoding="utf-8")
            paths["links"].write_text("not json", encoding="utf-8")
            status, output = run()
            self.assertEqual(status, 2)

    def test_pi_m7_non_utf8_inventory_is_clean_exit_2(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            paths = {}
            for name, text in (
                ("links", CLEAN_LINKS),
                ("addresses", CLEAN_ADDRS),
                ("routes", CLEAN_ROUTES),
                ("tables", CLEAN_TABLES),
                ("iptables", CLEAN_IPTABLES),
            ):
                path = root / f"{name}.txt"
                path.write_text(text, encoding="utf-8")
                paths[name] = path
            paths["links"].write_bytes(b"\xff\xfe\x00not-utf8")
            errors = StringIO()
            with redirect_stdout(StringIO()), redirect_stderr(errors):
                status = netplan.main(
                    [
                        "--check-name-collisions",
                        "--wan-interface",
                        "eth0",
                        "--links-json",
                        str(paths["links"]),
                        "--addresses-json",
                        str(paths["addresses"]),
                        "--routes-json",
                        str(paths["routes"]),
                        "--tables-json",
                        str(paths["tables"]),
                        "--iptables-save",
                        str(paths["iptables"]),
                    ]
                )
            self.assertEqual(status, 2)
            self.assertNotIn("Traceback", errors.getvalue())
            self.assertIn("netplan:", errors.getvalue())

    def test_check_mode_requires_every_inventory(self):
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            rc = netplan.main(["--check-name-collisions", "--wan-interface", "eth0"])
        self.assertEqual(rc, 2)

    def test_check_mode_requires_iptables_save(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            command = ["--check-name-collisions", "--wan-interface", "eth0"]
            for name, text in (
                ("links", CLEAN_LINKS),
                ("addresses", CLEAN_ADDRS),
                ("routes", CLEAN_ROUTES),
                ("tables", CLEAN_TABLES),
            ):
                path = root / f"{name}.json"
                path.write_text(text, encoding="utf-8")
                command += [f"--{name}-json", str(path)]
            errors = StringIO()
            with redirect_stdout(StringIO()), redirect_stderr(errors):
                rc = netplan.main(command)
            self.assertEqual(rc, 2)
            self.assertIn("--iptables-save", errors.getvalue())

    def test_gpt_i8_failed_link_inventory_is_never_absence(self):
        for failure in ("link_inventory", "link_inventory_json"):
            with self.subTest(failure=failure):
                with tempfile.TemporaryDirectory() as directory:
                    root = pathlib.Path(directory)
                    owner = _valid_owner(root)
                    state = _owned_state(owner)
                    result, log, state_after, owner_path = self._run_lab(
                        root,
                        netplan.render_plan("eth0"),
                        state,
                        args=("teardown",),
                        fails=failure,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("cannot inventory", result.stderr)
                    for line in log.splitlines():
                        self.assertNotIn("neigh del", line)
                        self.assertNotIn("nft delete", line)
                        self.assertNotIn("iptables -D", line)
                        self.assertNotIn("link del", line)
                    self.assertTrue(owner_path.exists())
                    self.assertIsNotNone(state_after["table"])
                    self.assertEqual(len(state_after["rules"]), 2)
                    self.assertEqual(len(state_after["links"]), 2)

    def test_iptables_check_error_is_not_rule_absence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            owner = _valid_owner(root)
            state = _owned_state(owner)
            result, log, state_after, owner_path = self._run_lab(
                root,
                netplan.render_plan("eth0"),
                state,
                args=("teardown",),
                fails="iptables_check",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cannot inspect", result.stderr)
            self.assertTrue(owner_path.exists())
            self.assertEqual(len(state_after["rules"]), 2)
            self.assertIsNotNone(state_after["table"])
            self.assertIn("iptables -C", log)
            self.assertNotIn("iptables -D", log)

    def test_teardown_refuses_while_a_phase_holds_the_run_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            owner = _valid_owner(root)
            state = _owned_state(owner)
            import fcntl

            lock_path = root / "run" / "run.lock"
            descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                result, log, state_after, owner_path = self._run_lab(
                    root,
                    netplan.render_plan("eth0"),
                    state,
                    args=("teardown",),
                )
            finally:
                os.close(descriptor)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("holds", result.stderr)
            self.assertIn("refusing teardown", result.stderr)
            self.assertTrue(owner_path.exists())
            self.assertIsNotNone(state_after["table"])
            self.assertEqual(state_after, state)
            self.assertNotIn("link del", log)

    def test_teardown_holds_the_run_lock_for_its_whole_duration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            owner = _valid_owner(root)
            state = _owned_state(owner)
            lock_path = root / "run" / "run.lock"
            lock_path.write_text("", encoding="utf-8")
            result, log, _state_after, owner_path = self._run_lab(
                root,
                netplan.render_plan("eth0"),
                state,
                args=("teardown",),
                extra={"STUB_LOCK_PROBE": lock_path},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(owner_path.exists())
            probes = [
                line for line in log.splitlines() if line.startswith("LOCKPROBE ")
            ]
            self.assertGreater(len(probes), 1)
            self.assertNotIn("LOCKPROBE free", probes)
            self.assertEqual(set(probes), {"LOCKPROBE held"})

    def test_check_mode_reports_docker_forward_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            command = ["--check-name-collisions", "--wan-interface", "eth0"]
            for name, text in (
                ("links", CLEAN_LINKS),
                ("addresses", CLEAN_ADDRS),
                ("routes", CLEAN_ROUTES),
                ("tables", CLEAN_TABLES),
                ("iptables-save", DOCKER_DROP_IPTABLES),
            ):
                path = root / f"{name}.txt"
                path.write_text(text, encoding="utf-8")
                command += [f"--{name}", str(path)] if name == "iptables-save" else [
                    f"--{name}-json",
                    str(path),
                ]
            output = StringIO()
            with redirect_stdout(output), redirect_stderr(StringIO()):
                rc = netplan.main(command)
            self.assertEqual(rc, 0)
            self.assertIn("FORWARD policy DROP", output.getvalue())
            self.assertIn("DOCKER-USER present", output.getvalue())


# --------------------------------------------------------------------------
# Resource bounds (gpt I9)
# --------------------------------------------------------------------------
class ResourceBoundTests(unittest.TestCase):
    def test_50k_record_stream_scan_is_memory_bounded(self):
        import tracemalloc

        frames = [control_frame(NONCE_A)]
        frames += [wg_outbound() for _ in range(50_000)]
        frames.append(control_frame(NONCE_B))
        data = pcap(frames)
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "large.pcap"
            path.write_bytes(data)
            tracemalloc.start()
            baseline = tracemalloc.get_traced_memory()[0]
            with path.open("rb") as stream:
                report = pcapscan.scan_capture_stream(
                    stream,
                    make_policy(),
                    NONCE_A,
                    NONCE_B,
                    tcpdump_stats_text=zero_stats(len(frames)),
                    capture_argv=CAPTURE_ARGV,
                    expect_tunnel="any",
                )
            _current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
        self.assertEqual(report["packets"], 50_002)
        self.assertEqual(report["verdict"], "PASS")
        # Per-packet tuples and the whole file are no longer retained.
        self.assertLess(peak - baseline, 8 * 1024 * 1024)

    def test_fragment_table_overflow_is_a_finding_and_invalid(self):
        frames = [control_frame(NONCE_A)]
        for ident in range(4097):
            frames.append(
                ipv4_frame(
                    udp_segment(40000, WG_PORT, wg_data(), length=64),
                    ident=ident,
                    more_fragments=True,
                )
            )
        frames.append(control_frame(NONCE_B))
        report = scan(frames)
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("fragment_table_overflow", invalid_reasons(report))
        self.assertIn("fragment_table_overflow", reasons(report))
        self.assertTrue(
            any(
                finding.get("limit") == pcapscan.MAX_FRAGMENT_ASSOCIATIONS
                for finding in report["findings"]
            )
        )

    def test_outside_window_indexes_are_capped_with_a_total(self):
        frames = [control_frame(NONCE_A), control_frame(NONCE_B)]
        frames += [wg_outbound() for _ in range(pcapscan.MAX_OUTSIDE_WINDOW_INDEXES + 500)]
        report = scan(frames)
        meta = report["capture_meta"]
        self.assertEqual(meta["outside_window_allowed"], 1500)
        self.assertEqual(
            len(meta["outside_window_allowed_packets"]),
            pcapscan.MAX_OUTSIDE_WINDOW_INDEXES,
        )
        self.assertTrue(meta["outside_window_allowed_truncated"])


# --------------------------------------------------------------------------
# M1 -> M2 ownership integration
# --------------------------------------------------------------------------
class OwnershipIntegrationTests(unittest.TestCase):
    def _documents(self, state, token, *, tap_user="vprlab-qemu"):
        owner = netplan.OWNER_PREFIX + token
        links = []
        order = [netplan.BRIDGE, netplan.TAP]
        for name in order:
            entry = state["links"][name]
            document = {
                "ifname": name,
                "address": entry.get("address", ""),
                "flags": ["UP"] if entry.get("operstate") == "UP" else [],
                "ifalias": entry.get("ifalias"),
            }
            if entry.get("master"):
                document["master"] = entry["master"]
            if name == netplan.BRIDGE:
                document["linkinfo"] = {"info_kind": "bridge"}
                document["addr_info"] = [
                    {"family": "inet", "local": netplan.BRIDGE_ADDRESS.split("/")[0],
                     "prefixlen": 24}
                ]
            else:
                document["linkinfo"] = {
                    "info_kind": "tun",
                    "info_data": {
                        "type": entry.get("tap_type", "tap"),
                        "user": tap_user,
                    },
                }
            links.append(document)
        table = {
            "nftables": [
                {
                    "table": {
                        "family": "inet",
                        "name": "vprlab",
                        "comment": state["table"]["comment"],
                    }
                }
            ]
            + [
                {"chain": {"family": "inet", "name": name, "table": "vprlab"}}
                for name in hostcheck.REQUIRED_CHAINS
            ]
        }
        neighbours = [
            {
                "dst": ip,
                "dev": netplan.BRIDGE,
                "lladdr": entry["lladdr"],
                "state": ["PERMANENT"] if entry.get("permanent") else ["STALE"],
            }
            for ip, entry in state["neigh"].items()
        ]
        return links, table, neighbours

    def _verify(self, documents, token="e" * 32):
        return hostcheck.verify_host_network(
            documents[0], documents[1], documents[2], owner_token=token
        )

    def test_generated_m1_setup_is_accepted_by_m2_and_every_mutation_is_refused(self):
        import copy

        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            result, _log, state, owner_path = NetplanTests()._run_lab(
                root,
                netplan.render_plan("eth0"),
                {},
                args=("setup",),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(owner_path.exists())
            token = json.loads(owner_path.read_text())["token"]
            self.assertRegex(token, r"^[0-9a-f]{32}$")
            self.assertIn(netplan.OWNER_PREFIX + token, state["table"]["comment"])
            documents = self._documents(state, token)
            self.assertEqual(self._verify(documents, token), [])

            def mutate(change):
                cloned = copy.deepcopy(documents)
                change(cloned[0], cloned[1], cloned[2])
                return cloned

            mutations = {
                "old fixed table tag": lambda links, table, neigh: table["nftables"][0][
                    "table"
                ].__setitem__("comment", "vprlab-leak-lab-m1"),
                "missing table comment": lambda links, table, neigh: table[
                    "nftables"
                ][0]["table"].pop("comment"),
                "missing table": lambda links, table, neigh: table.__setitem__(
                    "nftables", [entry for entry in table["nftables"] if "table" not in entry]
                ),
                "missing chain": lambda links, table, neigh: table["nftables"].pop(),
                "bridge ifalias": lambda links, table, neigh: links[0].__setitem__(
                    "ifalias", "vprlab-owned:" + "f" * 32
                ),
                "tap ifalias": lambda links, table, neigh: links[1].__setitem__(
                    "ifalias", None
                ),
                "bridge MAC": lambda links, table, neigh: links[0].__setitem__(
                    "address", "52:54:00:76:70:09"
                ),
                "bridge down": lambda links, table, neigh: links[0].__setitem__(
                    "flags", []
                ),
                "bridge address": lambda links, table, neigh: links[0][
                    "addr_info"
                ][0].__setitem__("local", "10.250.0.9"),
                "tap master": lambda links, table, neigh: links[1].pop("master"),
                "plain tun": lambda links, table, neigh: links[1]["linkinfo"][
                    "info_data"
                ].__setitem__("type", "tun"),
                "tap owner": lambda links, table, neigh: links[1]["linkinfo"][
                    "info_data"
                ].__setitem__("user", "opsec"),
                "neighbour MAC": lambda links, table, neigh: neigh[0].__setitem__(
                    "lladdr", "52:54:00:76:70:09"
                ),
                "neighbour state": lambda links, table, neigh: neigh[0].__setitem__(
                    "state", ["STALE"]
                ),
                "neighbour absent": lambda links, table, neigh: neigh.clear(),
            }
            for label, change in mutations.items():
                with self.subTest(label=label):
                    self.assertNotEqual(self._verify(mutate(change), token), [])
            with self.subTest(label="wrong run token"):
                self.assertNotEqual(self._verify(documents, "f" * 32), [])


# --------------------------------------------------------------------------
# control tests
# --------------------------------------------------------------------------
class ControlTests(unittest.TestCase):
    def test_nonce_generation(self):
        nonce = control.generate_nonce()
        self.assertTrue(policy.is_control_nonce(nonce))
        self.assertEqual(len(nonce), 32)
        self.assertNotEqual(nonce, control.generate_nonce())

    def test_generate_pair_is_distinct_and_fresh(self):
        used = {"0" * 32}
        pair = control.generate_pair(used)
        self.assertNotEqual(pair["before"], pair["after"])
        self.assertNotIn(pair["before"], used)
        self.assertNotIn(pair["after"], used)

    def test_command_is_single_line_and_binds_device(self):
        command = control.build_command(NONCE_A, "eth0", VM_IP, SINK_IP, SINK_PORT)
        self.assertNotIn("\n", command)
        self.assertTrue(command.startswith("python3 -c '"))
        self.assertTrue(command.endswith("'"))
        self.assertIn("SO_BINDTODEVICE", command)
        self.assertIn('b"eth0\\x00"', command)
        self.assertIn(NONCE_A, command)
        self.assertIn(f's.bind(("{VM_IP}",0))', command)
        self.assertIn(f's.sendto(d,("{SINK_IP}",{SINK_PORT}))', command)
        self.assertNotIn("sudo", command)

    def test_used_nonces_file_returns_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "used.txt"
            path.write_text(f"{NONCE_A}\n\n{NONCE_B}\n", encoding="utf-8")
            self.assertEqual(control.load_used_nonces(path), {NONCE_A, NONCE_B})

    def test_missing_used_nonces_file_is_created_0600(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "used.txt"
            self.assertEqual(control.load_used_nonces(path), set())
            self.assertTrue(path.exists())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            # The created file is then used normally: a nonce in it is refused.
            path.write_text(NONCE_A + "\n", encoding="utf-8")
            self.assertEqual(control.load_used_nonces(path), {NONCE_A})
            output = StringIO()
            with redirect_stdout(output), redirect_stderr(StringIO()):
                status = control.main(
                    [
                        "--device",
                        "eth0",
                        "--vm-ip",
                        VM_IP,
                        "--sink-ip",
                        SINK_IP,
                        "--sink-port",
                        str(SINK_PORT),
                        "--nonce",
                        NONCE_A,
                        "--used-nonces",
                        str(path),
                    ]
                )
            self.assertEqual(status, 2)

    def test_cli_refuses_reused_nonce(self):
        with tempfile.TemporaryDirectory() as directory:
            used = pathlib.Path(directory) / "used.txt"
            used.write_text(NONCE_A + "\n", encoding="utf-8")
            output = StringIO()
            with redirect_stdout(output), redirect_stderr(StringIO()):
                status = control.main(
                    [
                        "--device",
                        "eth0",
                        "--vm-ip",
                        VM_IP,
                        "--sink-ip",
                        SINK_IP,
                        "--sink-port",
                        str(SINK_PORT),
                        "--nonce",
                        NONCE_A,
                        "--used-nonces",
                        str(used),
                    ]
                )
            self.assertEqual(status, 2)
            self.assertEqual(output.getvalue(), "")

    def test_cli_nonce_requires_used_nonces_file(self):
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            status = control.main(
                [
                    "--device",
                    "eth0",
                    "--vm-ip",
                    VM_IP,
                    "--sink-ip",
                    SINK_IP,
                    "--sink-port",
                    str(SINK_PORT),
                    "--nonce",
                    NONCE_A,
                ]
            )
        self.assertEqual(status, 2)

    def test_cli_pair_prints_two_distinct_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            used = pathlib.Path(directory) / "used.txt"
            used.write_text("", encoding="utf-8")
            output = StringIO()
            with redirect_stdout(output):
                status = control.main(
                    [
                        "--device",
                        "eth0",
                        "--vm-ip",
                        VM_IP,
                        "--sink-ip",
                        SINK_IP,
                        "--sink-port",
                        str(SINK_PORT),
                        "--pair",
                        "--used-nonces",
                        str(used),
                        "--json",
                    ]
                )
            self.assertEqual(status, 0)
            document = json.loads(output.getvalue())
            self.assertNotEqual(document["before"]["nonce"], document["after"]["nonce"])
            for role in ("before", "after"):
                self.assertEqual(
                    bytes.fromhex(document[role]["payload_hex"]),
                    policy.control_payload(document[role]["nonce"]),
                )

    def test_cli_pair_creates_missing_used_nonces_file(self):
        with tempfile.TemporaryDirectory() as directory:
            used = pathlib.Path(directory) / "used.txt"
            self.assertFalse(used.exists())
            output = StringIO()
            with redirect_stdout(output):
                status = control.main(
                    [
                        "--device",
                        "eth0",
                        "--vm-ip",
                        VM_IP,
                        "--sink-ip",
                        SINK_IP,
                        "--sink-port",
                        str(SINK_PORT),
                        "--pair",
                        "--used-nonces",
                        str(used),
                        "--json",
                    ]
                )
            self.assertEqual(status, 0)
            self.assertTrue(used.exists())
            self.assertEqual(used.stat().st_mode & 0o777, 0o600)
            document = json.loads(output.getvalue())
            self.assertNotEqual(document["before"]["nonce"], document["after"]["nonce"])

    def test_main_prints_command_and_nonce(self):
        with tempfile.TemporaryDirectory() as directory:
            used = pathlib.Path(directory) / "used.txt"
            used.write_text(NONCE_B + "\n", encoding="utf-8")
            output = StringIO()
            with redirect_stdout(output):
                status = control.main(
                    [
                        "--device",
                        "eth0",
                        "--vm-ip",
                        VM_IP,
                        "--sink-ip",
                        SINK_IP,
                        "--sink-port",
                        str(SINK_PORT),
                        "--nonce",
                        NONCE_A,
                        "--used-nonces",
                        str(used),
                    ]
                )
            self.assertEqual(status, 0)
            lines = output.getvalue().splitlines()
            self.assertEqual(
                lines[0],
                control.build_command(NONCE_A, "eth0", VM_IP, SINK_IP, SINK_PORT),
            )
            self.assertEqual(lines[1], f"nonce: {NONCE_A}")

    def test_invalid_nonce_rejected(self):
        with self.assertRaises(policy.PolicyError):
            control.build_command("A" * 32, "eth0", VM_IP, SINK_IP, SINK_PORT)


class WireGuardShapeTests(unittest.TestCase):
    def test_plaintext_on_the_allowed_tuple_is_a_leak(self):
        # GPT S4 reproducer: the outer tuple alone used to certify this.
        frames = [
            control_frame(NONCE_A),
            ipv4_frame(udp_segment(40000, WG_PORT, b"CLEAR_TEXT_NOT_WIREGUARD")),
            ipv4_frame(
                udp_segment(WG_PORT, 40000, b"CLEAR_REPLY"),
                src_ip=WG_IP,
                dst_ip=VM_IP,
                src_mac=GW_MAC,
                dst_mac=VM_MAC,
            ),
            control_frame(NONCE_B),
        ]
        report = scan(frames, expect_tunnel="up")
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("allowed_tuple_not_wireguard", reasons(report))
        self.assertEqual(directions(report, "mullvad-wg"), (0, 0))

    def test_realistic_wireguard_shapes_pass(self):
        for payload in (
            wg_initiation(),
            wg_response(),
            wg_cookie_reply(),
            wg_data(1),
            wg_data(3),
        ):
            with self.subTest(length=len(payload)):
                out = ipv4_frame(udp_segment(40000, WG_PORT, payload))
                inbound = ipv4_frame(
                    udp_segment(WG_PORT, 40000, payload),
                    src_ip=WG_IP,
                    dst_ip=VM_IP,
                    src_mac=GW_MAC,
                    dst_mac=VM_MAC,
                )
                report = scan_middle([out, inbound], expect_tunnel="up")
                self.assertEqual(report["verdict"], "PASS", reasons(report))
                self.assertEqual(directions(report, "mullvad-wg"), (1, 1))

    def test_mtu_clamped_full_size_data_packets_pass(self):
        # Opus/Pi r4 A-0: the kernel pads to 16 but clamps at the tunnel MTU,
        # so full-size data at MTU 1420 (1452 B) and 1500 (1532 B) is valid.
        for inner_mtu in (1420, 1500, 1380):
            payload = b"\x04\x00\x00\x00" + b"\x00" * 12 + b"\x00" * (inner_mtu + 16)
            with self.subTest(mtu=inner_mtu, length=len(payload)):
                out = ipv4_frame(udp_segment(40000, WG_PORT, payload))
                inbound = ipv4_frame(
                    udp_segment(WG_PORT, 40000, payload),
                    src_ip=WG_IP,
                    dst_ip=VM_IP,
                    src_mac=GW_MAC,
                    dst_mac=VM_MAC,
                )
                report = scan_middle([out, inbound], expect_tunnel="up")
                self.assertEqual(report["verdict"], "PASS", reasons(report))

    def test_wrong_wireguard_shapes_are_leaks(self):
        cases = {
            "type 0": b"\x00\x00\x00\x00" + b"\x00" * 28,
            "type 5": b"\x05\x00\x00\x00" + b"\x00" * 28,
            "nonzero reserved": b"\x04\x01\x00\x00" + b"\x00" * 28,
            "short data": b"\x04\x00\x00\x00" + b"\x00" * 12 + b"\x00" * 15,
            "initiation 147": b"\x01\x00\x00\x00" + b"\x00" * 143,
            "response 91": b"\x02\x00\x00\x00" + b"\x00" * 87,
            "cookie 65": b"\x03\x00\x00\x00" + b"\x00" * 61,
        }
        for name, payload in cases.items():
            with self.subTest(case=name):
                report = scan_middle(
                    [ipv4_frame(udp_segment(40000, WG_PORT, payload))]
                )
                self.assertEqual(report["verdict"], "LEAK")
                self.assertIn("allowed_tuple_not_wireguard", reasons(report))


class NetplanInjectionTests(unittest.TestCase):
    def test_capture_file_command_substitution_is_refused(self):
        payloads = (
            "$RUN_DIR/$(printf SAFETY_INJECTED).pcap",
            "$RUN_DIR/`id`.pcap",
            "$RUN_DIR/a;id.pcap",
            "$RUN_DIR/../escape.pcap",
            "/tmp/$(id).pcap",
            "/tmp/a'b.pcap",
            "relative.pcap",
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                with self.assertRaises(netplan.NetplanError):
                    netplan.render_plan("eth0", capture_file=payload)

    def test_run_dir_capture_is_composed_from_a_quoted_variable(self):
        plan = netplan.render_plan("eth0", capture_file="$RUN_DIR/manual-capture.pcap")
        self.assertIn("-w \"$RUN_DIR\"/'manual-capture.pcap'", plan)
        self.assertNotIn("$(printf", plan)
        self.assertNotIn("SAFETY_INJECTED", plan)


if __name__ == "__main__":
    unittest.main()


class IcmpQuoteAllowanceTests(unittest.TestCase):
    """User decision 2026-11-09 after the first live LEAK: an ICMP port-
    unreachable from the VM to the allowed endpoint that quotes that endpoint's
    own WireGuard datagram is reported separately, not as a leak."""

    def _quote(self, *, icmp_type=3, code=3, quoted_src=WG_IP, quoted_dst=VM_IP,
               sport=WG_PORT, payload=None, options=False):
        payload = wg_initiation() if payload is None else payload
        inner = ipv4_packet(quoted_src, quoted_dst, 17, udp_segment(sport, 40410, payload),
                            ihl_bytes=24 if options else None)
        return bytes([icmp_type, code, 0, 0, 0, 0, 0, 0]) + inner

    def _scan(self, icmp, **frame):
        return scan_middle(
            [ipv4_frame(icmp, protocol=1, **frame),
             ipv4_frame(udp_segment(40000, WG_PORT, wg_initiation())),
             ipv4_frame(udp_segment(WG_PORT, 40000, wg_initiation()), src_ip=WG_IP,
                        dst_ip=VM_IP, src_mac=GW_MAC, dst_mac=VM_MAC)],
            expect_tunnel="up",
        )

    def test_live_shape_is_allowed_and_reported_separately(self):
        report = self._scan(self._quote())
        self.assertEqual(report["verdict"], "PASS", reasons(report))
        self.assertEqual(report["allowed_icmp_quotes"], {"mullvad-wg": 1})

    def test_every_other_shape_stays_a_leak(self):
        cases = {
            "echo request": self._quote(icmp_type=8, code=0),
            "host unreachable": self._quote(code=1),
            "quote from another ip": self._quote(quoted_src="198.51.100.7"),
            "quote to another ip": self._quote(quoted_dst="10.250.0.9"),
            "quote from another port": self._quote(sport=53),
            "quote not wireguard": self._quote(payload=b"PLAINTEXTDATA"),
            "quote with ip options": self._quote(options=True),
        }
        for name, icmp in cases.items():
            with self.subTest(case=name):
                report = self._scan(icmp)
                self.assertEqual(report["verdict"], "LEAK", name)
                self.assertIn("icmp_not_allowed", reasons(report))

    def test_quote_to_a_non_endpoint_destination_is_a_leak(self):
        report = self._scan(self._quote(quoted_src="198.51.100.7"), dst_ip="198.51.100.7")
        self.assertEqual(report["verdict"], "LEAK")

    def test_inbound_icmp_is_still_a_leak(self):
        report = self._scan(self._quote(quoted_src=VM_IP, quoted_dst=WG_IP),
                            src_ip=WG_IP, dst_ip=VM_IP, src_mac=GW_MAC, dst_mac=VM_MAC)
        self.assertEqual(report["verdict"], "LEAK")

    def test_quote_with_wrong_l2_is_a_finding(self):
        report = self._scan(self._quote(), dst_mac="52:54:00:00:00:99")
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("allowed_tuple_wrong_l2", reasons(report))

    def test_quote_alone_is_not_tunnel_evidence(self):
        report = scan_middle([ipv4_frame(self._quote(), protocol=1)], expect_tunnel="up")
        self.assertNotEqual(report["verdict"], "PASS")
