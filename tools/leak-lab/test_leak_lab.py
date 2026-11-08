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
import pathlib
import re
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO

HERE = pathlib.Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import control  # noqa: E402
import netplan  # noqa: E402
import pcapscan  # noqa: E402
import policy  # noqa: E402
import tsnames  # noqa: E402

VM_MAC = "52:54:00:12:34:56"
GW_MAC = "52:54:00:65:43:21"
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


def wg_outbound(**kwargs):
    return ipv4_frame(udp_segment(40000, WG_PORT, b"wireguard"), **kwargs)


def wg_inbound(**kwargs):
    return ipv4_frame(
        udp_segment(WG_PORT, 40000, b"wireguard"),
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

    def test_8021q_tagged_allowed_wg_passes(self):
        report = scan_middle([wg_outbound(vlan=100), wg_inbound(vlan=100)])
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(directions(report, "mullvad-wg"), (1, 1))

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
        stats = zero_stats(3) + (
            "4 packets captured\n4 packets received by filter\n"
            "0 packets dropped by kernel\n"
        )
        report = scan_middle([wg_outbound()], stats=stats)
        self.assertEqual(report["verdict"], "INVALID")
        self.assertIn("stats_contradictory", invalid_reasons(report))

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

    def test_capture_argv_must_match_netplan_exactly(self):
        report = scan_middle([wg_outbound()])
        self.assertEqual(report["verdict"], "PASS")
        argv = report["capture_meta"]["capture_argv"]
        self.assertEqual(argv, CAPTURE_ARGV)
        self.assertEqual(
            report["capture_meta"]["capture_argv_sha256"],
            pcapscan.hashlib.sha256(
                json.dumps(CAPTURE_ARGV, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
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
        report = scan_middle([wg_outbound()], capture_argv=argv)
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["capture_meta"]["capture_argv"][-1], "/var/tmp/phase-17.pcap")

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
        self.assertTrue(evidence["satisfied"])

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
        bad = ipv4_frame(udp_segment(40000, WG_PORT, b"x"), ihl_bytes=0x44)
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
        bad = ipv4_frame(udp_segment(40000, WG_PORT, b"x"), total_length=10)
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
        report = scan_middle([wg_outbound() + b"\x00" * 9])
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
                    udp_segment(40000, WG_PORT, b"PLAIN_SECRET", length=length)
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
        l4 = udp_segment(40000, WG_PORT, b"a" * 16)
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
    def _first(self, ident=77, udp_len=24, data=b"abcdefgh"):
        return ipv4_frame(
            udp_segment(40000, WG_PORT, data, length=udp_len),
            ident=ident,
            more_fragments=True,
        )

    def test_i4_valid_contiguous_complete_fragments_are_allowed(self):
        report = scan_middle(
            [self._first(), ipv4_frame(b"ijklmnop", ident=77, frag_units=2)]
        )
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(directions(report, "mullvad-wg"), (2, 0))

    def test_i4_gap_fragment_is_a_finding(self):
        report = scan_middle(
            [self._first(), ipv4_frame(b"ijklmnop", ident=77, frag_units=3)]
        )
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("fragment_gap", reasons(report))

    def test_i4_orphan_after_complete_is_a_finding(self):
        report = scan_middle(
            [
                self._first(),
                ipv4_frame(b"ijklmnop", ident=77, frag_units=2),
                ipv4_frame(b"PLAIN_SECRET" * 8, ident=77, frag_units=8000),
            ]
        )
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("fragment_after_complete", reasons(report))

    def test_i4_conflicting_final_overlap_is_a_finding(self):
        report = scan_middle(
            [
                self._first(),
                ipv4_frame(b"ijklmnop", ident=77, frag_units=2),
                ipv4_frame(b"cccccccc", ident=77, frag_units=2),
            ]
        )
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("fragment_after_complete", reasons(report))

    def test_i4_nonfirst_before_first_is_a_finding(self):
        report = scan_middle(
            [ipv4_frame(b"ijklmnop", ident=79, frag_units=2), self._first(79)]
        )
        self.assertEqual(report["verdict"], "LEAK")
        self.assertIn("fragment_without_first", reasons(report))

    def test_i4_stale_fragment_association_is_a_finding(self):
        frames = [
            control_frame(NONCE_A),
            self._first(),
            ipv4_frame(b"ijklmnop", ident=77, frag_units=2),
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
            [self._first(udp_len=32), ipv4_frame(b"ijkl", ident=77, frag_units=2)]
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
            ipv4_frame(b"ijklmnop", ident=77, frag_units=2),
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
                ipv4_frame(b"ijklmnop", ident=77, frag_units=3),
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
        if not argv_path.exists():
            self._write(root, "capture-argv.json", json.dumps(CAPTURE_ARGV))
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

    def test_gateway_mac_may_be_absent_when_arp_is_disabled(self):
        document = policy_document(allow_arp=False)
        del document["gateway_mac"]
        loaded = policy.parse_policy(document)
        self.assertFalse(loaded.allow_arp)
        self.assertIsNone(loaded.gateway_mac)

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
        self.assertIn("allOf", schema)
        self.assertNotIn(
            "gateway_mac", schema["required"]
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
            "ip addr add 10.250.0.1/24 dev vprlab0",
            "ip tuntap add dev vprlab-tap0 mode tap",
            "ip link set vprlab-tap0 master vprlab0",
            "sysctl -w net.ipv6.conf.vprlab0.disable_ipv6=1",
            'nft create table inet vprlab',
            'nft add rule inet vprlab postrouting ip saddr 10.250.0.0/24 iifname "vprlab0" oifname "eth0" masquerade',
            'nft add rule inet vprlab forward iifname "vprlab0" oifname "eth0" accept',
            'nft add rule inet vprlab forward iifname "eth0" oifname "vprlab0" accept',
            "tcpdump -i vprlab-tap0 -nn -U --immediate-mode -s 0 -w vprlab-capture.pcap",
        ):
            self.assertIn(expected, plan)
        self.assertNotIn("flush ruleset", plan)
        self.assertNotIn("flush", plan.lower())

    def test_teardown_is_a_standalone_script(self):
        plan = netplan.render_plan("eth0")
        self.assertTrue(plan.startswith("#!/bin/sh\n"))
        self.assertIn("set -eu", plan.splitlines()[1])
        self.assertIn("# not for interactive paste", plan)
        self.assertIn("tcpdump -i vprlab-tap0 -nn -U --immediate-mode -s 0 -w", plan)
        self.assertIn('if [ "${1:-}" = "teardown" ]; then', plan)
        self.assertIn("\ndo_teardown\n", plan)

    def test_teardown_deletes_only_owned_objects_with_exact_matches(self):
        plan = netplan.render_plan("eth0", owner_tag=netplan.OWNER_TAG)
        teardown = plan.split("# --- 4. teardown ---", 1)[1]
        # No substring/whole-output matching: the old grep -Fq guard accepted
        # a rule comment anywhere in the table and an alias suffix on a link.
        self.assertNotIn("grep", teardown)
        self.assertIn('tables[0].get("comment") == "vprlab-leak-lab-m1"', teardown)
        self.assertIn('entries[0].get("alias") == "vprlab-leak-lab-m1"', teardown)
        self.assertIn('e.get("ifname") == name', teardown)
        self.assertIn("refusing to delete", teardown)

    def test_owner_tag_defaults_to_the_fixed_static_tag(self):
        plan = netplan.render_plan("eth0")
        alias = re.search(r'ip link set dev vprlab0 alias "([^"]+)"', plan)
        self.assertIsNotNone(alias)
        self.assertEqual(alias.group(1), netplan.OWNER_TAG)
        custom = netplan.render_plan("eth0", owner_tag=netplan.OWNER_TAG + "-run1")
        self.assertIn(
            f'ip link set dev vprlab0 alias "{netplan.OWNER_TAG}-run1"', custom
        )
        with self.assertRaises(netplan.NetplanError):
            netplan.render_plan("eth0", owner_tag="foreign-tag")

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

    def test_embedded_ownership_checks_use_exact_structured_fields(self):
        plan = netplan.render_plan("eth0", owner_tag=netplan.OWNER_TAG)
        nft_code = self._embedded_check(plan, "nft -j list table inet vprlab 2>/dev/null |")
        self.assertEqual(
            self._run_embedded(
                nft_code,
                {
                    "nftables": [
                        {"table": {"family": "inet", "name": "vprlab", "comment": netplan.OWNER_TAG}}
                    ]
                },
            ),
            0,
        )
        # A comment on a rule elsewhere in the table is not table ownership.
        self.assertEqual(
            self._run_embedded(
                nft_code,
                {
                    "nftables": [
                        {"table": {"family": "inet", "name": "vprlab", "comment": "other"}},
                        {"rule": {"comment": netplan.OWNER_TAG}},
                    ]
                },
            ),
            1,
        )
        link_code = self._embedded_check(
            plan, "ip -j -d link show dev vprlab-tap0 2>/dev/null |"
        )
        self.assertEqual(
            self._run_embedded(
                link_code,
                [{"ifname": netplan.TAP, "alias": netplan.OWNER_TAG}],
                netplan.TAP,
            ),
            0,
        )
        # The old grep accepted any output containing the tag as a substring.
        self.assertEqual(
            self._run_embedded(
                link_code,
                [{"ifname": netplan.TAP, "alias": "NOT-OWNED-" + netplan.OWNER_TAG + "-backup"}],
                netplan.TAP,
            ),
            1,
        )
        self.assertEqual(
            self._run_embedded(
                link_code,
                [{"ifname": "other0", "alias": netplan.OWNER_TAG}],
                netplan.TAP,
            ),
            1,
        )

    def test_teardown_isolates_tap_before_removing_protection(self):
        plan = netplan.render_plan("eth0")
        teardown = plan.split("# --- 4. teardown ---", 1)[1]
        down = teardown.index("ip link set dev vprlab-tap0 down")
        nomaster = teardown.index("ip link set dev vprlab-tap0 nomaster")
        neigh = teardown.index("ip neigh del")
        iptables = teardown.index("iptables -D DOCKER-USER")
        table = teardown.index("nft delete table inet vprlab")
        tap_del = teardown.index("ip link del vprlab-tap0")
        bridge_del = teardown.index("ip link del vprlab0")
        self.assertLess(down, nomaster)
        self.assertLess(nomaster, neigh)
        self.assertLess(nomaster, iptables)
        self.assertLess(iptables, table)
        self.assertLess(table, tap_del)
        self.assertLess(tap_del, bridge_del)
        # Every risky teardown step is guarded so teardown continues after a
        # failure instead of stopping at the first one.
        for command in (
            "ip link set dev vprlab-tap0 down",
            "ip link set dev vprlab-tap0 nomaster",
            "iptables -D DOCKER-USER",
            "nft delete table inet vprlab",
            "ip link del",
        ):
            for line in teardown.splitlines():
                if command in line and not line.lstrip().startswith("#"):
                    self.assertIn("||", line, f"unguarded teardown step: {line}")

    def test_docker_user_rules_are_scoped_tagged_and_removed_exactly(self):
        plan = netplan.render_plan("eno1")
        insert = [
            line.strip()
            for line in plan.splitlines()
            if line.strip().startswith("iptables -I DOCKER-USER")
        ]
        delete = [
            line.strip()
            for line in plan.splitlines()
            if line.strip().startswith("iptables -D DOCKER-USER")
        ]
        self.assertEqual(len(insert), 2)
        self.assertEqual(len(delete), 2)
        for expected in (
            "-i vprlab0 -o eno1 -s 10.250.0.0/24",
            "-i eno1 -o vprlab0 -d 10.250.0.0/24 -m conntrack --ctstate ESTABLISHED,RELATED",
        ):
            self.assertTrue(any(expected in line for line in insert), expected)
            self.assertTrue(any(expected in line for line in delete), expected)
        for line in insert + delete:
            self.assertIn("-m comment --comment vprlab-owned", line)
            self.assertIn("-j ACCEPT", line)
        # Teardown -D specs must equal the -I specs exactly.
        for line in insert:
            spec = line.replace("-I DOCKER-USER", "-D DOCKER-USER")
            self.assertTrue(any(item.startswith(spec + " ||") for item in delete), spec)
        teardown = plan.split("# --- 4. teardown ---", 1)[1]
        self.assertIn("iptables-nft", plan)
        self.assertIn("DOCKER-USER", plan.split("# --- 2.", 1)[1].split("# --- 3.", 1)[0])
        self.assertNotIn("iptables -F", plan)

    def test_capture_argv_matches_printed_command(self):
        plan = netplan.render_plan("eth0", capture_file="phase.pcap")
        self.assertEqual(
            netplan.capture_argv("phase.pcap"),
            [
                "tcpdump",
                "-i",
                "vprlab-tap0",
                "-nn",
                "-U",
                "--immediate-mode",
                "-s",
                "0",
                "-w",
                "phase.pcap",
            ],
        )
        self.assertIsNone(netplan.check_capture_argv(netplan.capture_argv("x.pcap")))
        self.assertEqual(
            netplan.check_capture_argv(
                ["tcpdump", "-i", "vprlab-tap0", "-nn", "-s", "0", "-w", "x.pcap"]
            ),
            "capture_argv_mismatch",
        )
        self.assertEqual(
            netplan.check_capture_argv("tcpdump"),
            "capture_argv_invalid",
        )
        self.assertIn("tcpdump -i vprlab-tap0 -nn -U --immediate-mode -s 0 -w phase.pcap", plan)

    def test_tap_user_option(self):
        plan = netplan.render_plan("eth0", tap_user="vprouterlab")
        self.assertIn("ip tuntap add dev vprlab-tap0 mode tap user vprouterlab", plan)

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
        rule = next(line for line in plan.splitlines() if "masquerade" in line)
        self.assertIn('iifname "vprlab0"', rule)
        self.assertIn("ip saddr 10.250.0.0/24", rule)
        self.assertIn('oifname "eth0"', rule)

    # ------------------------------------------------------ ownership (I8/F-14)
    def test_table_creation_is_exclusive_and_marked(self):
        plan = netplan.render_plan("eth0")
        self.assertIn('nft create table inet vprlab', plan)
        self.assertIn("vprlab-leak-lab-m1", plan)
        self.assertNotIn("nft add table", plan)

    def test_links_carry_ownership_marker(self):
        plan = netplan.render_plan("eth0", owner_tag=netplan.OWNER_TAG)
        self.assertIn('ip link set dev vprlab0 alias "vprlab-leak-lab-m1"', plan)
        self.assertIn('ip link set dev vprlab-tap0 alias "vprlab-leak-lab-m1"', plan)

    # ---------------------------------------------------- forwarding (M7/F-09)
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


if __name__ == "__main__":
    unittest.main()
