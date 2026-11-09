#!/usr/bin/env python3
"""Strict parser and verdict engine for the M3 client probe log.

The client VM runs ``/usr/local/sbin/vprlab-client-traffic``, which appends one
JSON line per probe to ``/var/lib/vprouter/client-probe.jsonl``.  The runner
reads the file through QGA only after the traffic unit stopped and passes the
exact bytes here.  Nothing in this module executes a command or reads a file.

Line shapes (exactly, no extra keys, duplicate keys refused)::

    {"t":<epoch>,"k":"exit","ok":true|false,"m":true|false|null[,"h":<12 hex>]}
    {"t":<epoch>,"k":"marker","ok":true|false}

Verdict rules:

* any successful exit probe whose ``m`` is not ``true`` is a real-IP leak
  (``ok`` with ``m`` null is an untrusted success and therefore also a leak);
* without a pre-fault exit probe that succeeded with a Mullvad exit the phase
  is INVALID (``client_not_routed``);
* otherwise PASS.  Failed probes are expected while an exit node is gone and
  are only counted.

A malformed, oversized or duplicate-key log is INVALID.  A non-Mullvad IP is
never recorded: the optional ``h`` field is only the first 12 hex characters
of its SHA-256.
"""

from __future__ import annotations

import json
import re
import sys
from typing import Any

MARKER_PREFIX = "VPRCLIENTMARK1:"
MARKER_RE = re.compile(r"^VPRCLIENTMARK1:[0-9a-f]{32}$")
MAX_PROBE_LOG_BYTES = 1024 * 1024
MAX_PROBE_LINE_BYTES = 4096
_HEX12_RE = re.compile(r"^[0-9a-f]{12}$")
_EXIT_KEYS = frozenset({"t", "k", "ok", "m", "h"})
_EXIT_REQUIRED = frozenset({"t", "k", "ok", "m"})
_MARKER_KEYS = frozenset({"t", "k", "ok"})
_KINDS = ("exit", "marker")
_PHASES = ("before", "after")


class ProbeError(ValueError):
    """The probe log cannot be trusted as evidence."""


def is_marker(value: object) -> bool:
    return isinstance(value, str) and MARKER_RE.fullmatch(value) is not None


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProbeError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _is_epoch(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def parse_line(raw: bytes, number: int) -> dict[str, Any]:
    """Parse one JSONL line; raise :class:`ProbeError` on any deviation."""
    if len(raw) > MAX_PROBE_LINE_BYTES:
        raise ProbeError(f"line {number} is oversized")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProbeError(f"line {number} is not UTF-8") from exc
    try:
        document = json.loads(text, object_pairs_hook=_pairs)
    except ProbeError:
        raise
    except json.JSONDecodeError as exc:
        raise ProbeError(f"line {number} is not valid JSON") from exc
    if not isinstance(document, dict):
        raise ProbeError(f"line {number} is not a JSON object")
    kind = document.get("k")
    if kind not in _KINDS:
        raise ProbeError(f"line {number} has an unknown kind")
    keys = set(document)
    if "h" in keys and kind != "exit":
        raise ProbeError(f"line {number} carries an h field for a marker probe")
    required = _EXIT_REQUIRED if kind == "exit" else _MARKER_KEYS
    if not required <= keys or not keys <= (required | {"h"}):
        raise ProbeError(f"line {number} has an unexpected key set")
    if not _is_epoch(document.get("t")):
        raise ProbeError(f"line {number} has an invalid timestamp")
    if not isinstance(document.get("ok"), bool):
        raise ProbeError(f"line {number} has a non-boolean ok")
    if kind == "exit":
        mullvad = document.get("m")
        if mullvad is not None and not isinstance(mullvad, bool):
            raise ProbeError(f"line {number} has an invalid mullvad flag")
        if "h" in document and (
            not isinstance(document["h"], str)
            or _HEX12_RE.fullmatch(document["h"]) is None
        ):
            raise ProbeError(f"line {number} has an invalid hash prefix")
    return document


def parse_probe_log(data: bytes) -> list[dict[str, Any]]:
    """Return every parsed line; any malformed content raises."""
    if not isinstance(data, (bytes, bytearray)):
        raise ProbeError("probe log must be bytes")
    if len(data) > MAX_PROBE_LOG_BYTES:
        raise ProbeError("probe log exceeds 1 MiB")
    entries: list[dict[str, Any]] = []
    for number, raw in enumerate(bytes(data).splitlines(), start=1):
        if not raw.strip():
            raise ProbeError(f"line {number} is empty")
        entries.append(parse_line(raw, number))
    return entries


def _empty_counts() -> dict[str, dict[str, int]]:
    return {
        kind: {
            phase: {
                "total": 0,
                "ok": 0,
                "mullvad": 0,
                "non_mullvad": 0,
                "failed": 0,
            }
            for phase in _PHASES
        }
        for kind in _KINDS
    }


def evaluate_probe_log(
    data: bytes, *, fault_epoch: int | None = None
) -> dict[str, Any]:
    """Return the client probe verdict, counts and reasons.

    ``fault_epoch`` is the client's own wall-clock second immediately before
    the fault was applied.  It is used only to split the counts into
    before/after; the leak rule and the pre-fault Mullvad requirement apply to
    the whole log.  When it is ``None`` every line counts as pre-fault (the
    caller had no usable clock and the phase is INVALID for that independently).
    """
    try:
        entries = parse_probe_log(data)
    except ProbeError as exc:
        return {
            "verdict": "INVALID",
            "reason": "probe_log_malformed",
            "detail": str(exc),
            "counts": _empty_counts(),
            "fault_epoch": fault_epoch,
            "pre_fault_mullvad": False,
        }
    counts = _empty_counts()
    pre_fault_mullvad = False
    leak = False
    for entry in entries:
        kind = entry["k"]
        phase = (
            "before"
            if fault_epoch is None or int(entry["t"]) <= int(fault_epoch)
            else "after"
        )
        bucket = counts[kind][phase]
        bucket["total"] += 1
        if entry["k"] == "exit":
            if entry["ok"]:
                bucket["ok"] += 1
                if entry["m"] is True:
                    bucket["mullvad"] += 1
                    if phase == "before":
                        pre_fault_mullvad = True
                else:
                    bucket["non_mullvad"] += 1
                    leak = True
            else:
                bucket["failed"] += 1
        else:
            if entry["ok"]:
                bucket["ok"] += 1
            else:
                bucket["failed"] += 1
    if leak:
        verdict = "LEAK"
        reason = "client_real_ip"
    elif not pre_fault_mullvad:
        verdict = "INVALID"
        reason = "client_not_routed"
    else:
        verdict = "PASS"
        reason = None
    return {
        "verdict": verdict,
        "reason": reason,
        "counts": counts,
        "fault_epoch": fault_epoch,
        "pre_fault_mullvad": pre_fault_mullvad,
    }


def main(argv: list[str] | None = None) -> int:
    import argparse
    import pathlib

    parser = argparse.ArgumentParser(description="evaluate a client probe log")
    parser.add_argument("--probe-log", required=True)
    parser.add_argument("--fault-epoch", type=int)
    args = parser.parse_args(argv)
    try:
        data = pathlib.Path(args.probe_log).read_bytes()
    except OSError as exc:
        print(f"clientprobe: {exc.__class__.__name__}", file=sys.stderr)
        return 2
    report = evaluate_probe_log(data, fault_epoch=args.fault_epoch)
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return {"PASS": 0, "LEAK": 1, "INVALID": 2}[report["verdict"]]


if __name__ == "__main__":
    raise SystemExit(main())
