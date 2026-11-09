#!/usr/bin/env python3
"""M3 client-capture scanner: stats binding, controls and the plaintext marker.

This scanner does not classify client WAN traffic: the client tap legitimately
carries Tailscale/DERP UDP, retries and TLS.  It proves three things only:

* the client capture's tcpdump stats are complete (banner, zero drops,
  ``captured == received``, final count equals the record count);
* exactly one client before-control and one client after-control datagram
  (``VPRLEAKCTL1:<nonce>``) appear on the client tap, in order;
* the per-phase plaintext marker (``VPRCLIENTMARK1:<32 hex>``) appears in no
  frame of either the client or the router capture.  A single clear
  occurrence is a real-IP/untunnelled-traffic leak.

The raw bytes of every record in both pcaps are searched.  A marker split
across two frames is out of scope (documented in the M3 design) because the
client sends it in one HTTP request.

The scanner reuses :mod:`pcapscan`'s strict pcap walker, tcpdump-stats parser
and :mod:`netplan`'s exact capture-argv check.  It never executes a command.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
from typing import Any

import netplan
import pcapscan
import policy as policy_mod

MAX_MARKER_FINDINGS = 200


def _sightings(entries: list[dict[str, Any]], nonce: str) -> list[dict[str, Any]]:
    return [entry for entry in entries if entry["nonce"] == nonce]


def _control_report(entries: list[dict[str, Any]], nonce: str) -> dict[str, Any]:
    found = _sightings(entries, nonce)
    return {
        "nonce": nonce,
        "seen": bool(found),
        "packets": len(found),
        "first_packet": found[0]["packet"] if found else None,
        "last_packet": found[-1]["packet"] if found else None,
        "first_ts": found[0]["ts"] if found else None,
        "last_ts": found[-1]["ts"] if found else None,
    }


def _scan_raw(
    stream,
    *,
    where: str,
    marker: bytes,
    controls: dict[str, bytes],
) -> dict[str, Any]:
    """Walk one pcap and return packets, digests, controls and marker hits."""
    digest = hashlib.sha256()
    meta: dict[str, Any] = {}
    control_sightings: list[dict[str, Any]] = []
    marker_hits: list[dict[str, Any]] = []
    packets = 0
    try:
        for index, ts, frame in pcapscan.iter_pcap_records(
            stream, digest=digest, meta=meta
        ):
            packets += 1
            for nonce, payload in controls.items():
                position = frame.find(payload)
                while position >= 0:
                    control_sightings.append(
                        {
                            "nonce": nonce,
                            "packet": index,
                            "ts": ts,
                            "capture": where,
                        }
                    )
                    position = frame.find(payload, position + 1)
            position = frame.find(marker)
            while position >= 0:
                if len(marker_hits) < MAX_MARKER_FINDINGS:
                    marker_hits.append(
                        {"capture": where, "packet": index, "ts": ts}
                    )
                position = frame.find(marker, position + 1)
        structural = None
    except pcapscan.CaptureInvalid as exc:
        structural = str(exc)
    return {
        "packets": packets,
        "sha256": digest.hexdigest(),
        "meta": meta,
        "controls": control_sightings,
        "marker_hits": marker_hits,
        "structural_invalid": structural,
    }


def scan_client_capture(
    client_stream,
    router_stream,
    *,
    interface: str,
    marker: str,
    control_before: str,
    control_after: str,
    client_stats_text: str | None,
    client_stdio_error: str | None = None,
    client_capture_argv: Any,
    client_pcap_path: str | None = None,
    client_source: str | None = None,
    router_source: str | None = None,
    capture_argv_file_sha256: str | None = None,
    stats_source: str | None = None,
) -> dict[str, Any]:
    """Scan both captures and return the canonical client-scan report."""
    if not isinstance(marker, str) or not policy_mod.is_control_nonce(
        marker.replace("VPRCLIENTMARK1:", "", 1)
    ) or not marker.startswith("VPRCLIENTMARK1:"):
        raise ValueError("marker must be VPRCLIENTMARK1:<32 lowercase hex>")
    for label, nonce in (
        ("control-before", control_before),
        ("control-after", control_after),
    ):
        if not policy_mod.is_control_nonce(nonce):
            raise ValueError(f"{label} must be 32 lowercase hex characters")
    if control_before == control_after:
        raise ValueError("client controls must be distinct")
    if client_stats_text is None and client_stdio_error is None:
        raise ValueError("a client tcpdump stats file is required")

    marker_bytes = marker.encode("ascii")
    controls = {
        control_before: policy_mod.CONTROL_PREFIX + control_before.encode("ascii"),
        control_after: policy_mod.CONTROL_PREFIX + control_after.encode("ascii"),
    }
    client = _scan_raw(
        client_stream, where="client", marker=marker_bytes, controls=controls
    )
    router = _scan_raw(
        router_stream, where="router", marker=marker_bytes, controls=controls
    )
    invalid_reasons: list[str] = []
    findings: list[dict[str, Any]] = []

    for capture in (client, router):
        if capture["structural_invalid"] is not None:
            invalid_reasons.append(capture["structural_invalid"])
    if client["packets"] == 0:
        invalid_reasons.append("zero_packets")
    if router["packets"] == 0:
        invalid_reasons.append("router_zero_packets")

    stats: dict[str, int | None] | None = None
    stats_problem: str | None = client_stdio_error
    stats_sha256: str | None = None
    stats_banner_ok = False
    if client_stats_text is not None:
        stats_banner_ok = pcapscan.check_stats_banner(
            client_stats_text, interface
        )
        if not stats_banner_ok:
            invalid_reasons.append("capture_banner_mismatch")
    if stats_problem is None and client_stats_text is not None:
        stats, stats_problem = pcapscan.parse_tcpdump_stats(
            client_stats_text, interface
        )
        stats_sha256 = hashlib.sha256(
            client_stats_text.encode("utf-8")
        ).hexdigest()
    if stats_problem is not None:
        invalid_reasons.append(stats_problem)
    if (
        stats_problem is None
        and stats is not None
        and stats["captured"] != client["packets"]
    ):
        invalid_reasons.append("stats_packet_count_mismatch")

    argv_problem = netplan.check_capture_argv(
        client_capture_argv, client_pcap_path, interface=interface
    )
    if argv_problem is not None:
        invalid_reasons.append(argv_problem)

    marker_occurrences = client["marker_hits"] + router["marker_hits"]
    for occurrence in marker_occurrences[:MAX_MARKER_FINDINGS]:
        findings.append(
            {
                "reason": "marker_in_clear",
                "capture": occurrence["capture"],
                "packet": occurrence["packet"],
                "ts": occurrence["ts"],
            }
        )
    if marker_occurrences:
        findings.insert(
            0,
            {
                "reason": "marker_in_clear",
                "capture": "both",
                "occurrences": len(marker_occurrences),
            },
        )

    client_controls = client["controls"]
    before = _control_report(client_controls, control_before)
    after = _control_report(client_controls, control_after)
    missing = []
    if not before["seen"]:
        missing.append(control_before)
    if not after["seen"]:
        missing.append(control_after)
    if missing:
        invalid_reasons.append("missing_client_controls")
    if before["seen"] and after["seen"]:
        if not before["first_ts"] < after["first_ts"]:
            invalid_reasons.append("client_control_order")
    replayed = before["packets"] > 1 or after["packets"] > 1
    if replayed:
        findings.append({"reason": "client_control_replayed"})
    # A control seen on the router tap too is not expected and means the client
    # control was routed beyond its own bridge; keep it visible as a finding.
    if router["controls"]:
        findings.append({"reason": "client_control_on_router_tap"})

    if findings:
        verdict = "LEAK"
    elif invalid_reasons:
        verdict = "INVALID"
    else:
        verdict = "PASS"

    meta = {
        "interface": interface,
        "source": client_source,
        "source_sha256": client["sha256"],
        "router_source": router_source,
        "router_source_sha256": router["sha256"],
        "stats_source": stats_source,
        "stats": stats,
        "stats_sha256": stats_sha256,
        "stats_banner_ok": stats_banner_ok,
        "capture_argv": client_capture_argv,
        "capture_argv_sha256": capture_argv_file_sha256,
        "client_packets": client["packets"],
        "router_packets": router["packets"],
        "client_pcap": client["meta"],
        "router_pcap": router["meta"],
        "controls": {"before": before, "after": after},
        "missing_controls": missing,
        "marker_occurrences": len(marker_occurrences),
        "invalid_reasons": invalid_reasons,
    }
    if stats_problem is not None:
        meta["stats_problem"] = stats_problem
    if invalid_reasons:
        meta["invalid_reason"] = invalid_reasons[0]
    return {
        "verdict": verdict,
        "client_packets": client["packets"],
        "router_packets": router["packets"],
        "controls": {"before": before, "after": after},
        "marker_occurrences": marker_occurrences[:MAX_MARKER_FINDINGS],
        "findings": findings,
        "capture_meta": meta,
    }


def canonical_json(report: dict[str, Any]) -> str:
    return json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="scan the M3 client capture and both plaintext-marker views"
    )
    parser.add_argument("--client-pcap", required=True)
    parser.add_argument("--router-pcap", required=True)
    parser.add_argument("--client-tcpdump-stats", required=True)
    parser.add_argument("--client-capture-argv-file", required=True)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--marker", required=True)
    parser.add_argument("--client-control-before", required=True)
    parser.add_argument("--client-control-after", required=True)
    args = parser.parse_args(argv)

    try:
        client_stream = open(args.client_pcap, "rb")
    except OSError as exc:
        print(f"clientscan: client capture: {exc}", file=sys.stderr)
        return 2
    try:
        router_stream = open(args.router_pcap, "rb")
    except OSError as exc:
        client_stream.close()
        print(f"clientscan: router capture: {exc}", file=sys.stderr)
        return 2

    stats_text: str | None = None
    stats_error: str | None = None
    try:
        stats_text = pathlib.Path(args.client_tcpdump_stats).read_text(
            encoding="utf-8", errors="replace"
        )
    except OSError:
        stats_error = "stats_unreadable"
    try:
        argv_bytes = pathlib.Path(args.client_capture_argv_file).read_bytes()
        capture_argv = json.loads(argv_bytes.decode("utf-8"))
        argv_sha256 = hashlib.sha256(argv_bytes).hexdigest()
    except OSError as exc:
        client_stream.close()
        router_stream.close()
        print(f"clientscan: capture argv file: {exc}", file=sys.stderr)
        return 2
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        client_stream.close()
        router_stream.close()
        print(f"clientscan: capture argv file is not JSON: {exc}", file=sys.stderr)
        return 2

    try:
        with client_stream, router_stream:
            report = scan_client_capture(
                client_stream,
                router_stream,
                interface=args.interface,
                marker=args.marker,
                control_before=args.client_control_before,
                control_after=args.client_control_after,
                client_stats_text=stats_text,
                client_stdio_error=stats_error,
                client_capture_argv=capture_argv,
                client_pcap_path=args.client_pcap,
                client_source=args.client_pcap,
                router_source=args.router_pcap,
                capture_argv_file_sha256=argv_sha256,
                stats_source=args.client_tcpdump_stats,
            )
    except OSError as exc:
        print(f"clientscan: capture: {exc}", file=sys.stderr)
        return 2
    sys.stdout.write(canonical_json(report))
    return {"PASS": 0, "LEAK": 1, "INVALID": 2}[report["verdict"]]


if __name__ == "__main__":
    raise SystemExit(main())
