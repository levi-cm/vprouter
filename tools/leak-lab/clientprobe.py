#!/usr/bin/env python3
"""Strict parser and verdict engine for the M3 client probe log.

The client VM runs ``/usr/local/sbin/vprlab-client-traffic``, which appends one
JSON line per probe to ``/var/lib/vprlab/client-probe.jsonl``.  The runner
deletes that file before launching the traffic unit, reads it through QGA only
after the unit stopped, and passes the exact bytes here.  Nothing in this module
executes a command or reads a file.

Line shapes (exactly, no extra keys, duplicate keys refused)::

    {"k":"exit","m":true|false|null,"ok":true|false,"r":"<32 hex>","s":<n>,"t":<epoch>}
    {"k":"marker","ok":true|false,"r":"<32 hex>","s":<n>,"t":<epoch>}
    {"k":"overflow","r":"<32 hex>","s":<n>,"t":<epoch>}

``r`` is the phase marker id (32 lowercase hex characters) and ``s`` is a
sequence number starting at 1 with no gaps.  A non-Mullvad IP is never
recorded: only the boolean answer is kept.

Verdict rules:

* any well-formed successful exit probe whose ``m`` is not ``true`` is a
  real-IP leak (``ok`` with ``m`` null is an untrusted success and therefore
  also a leak).  A malformed or truncated tail never masks such a line;
* without a pre-fault exit probe that succeeded with a Mullvad exit the phase
  is INVALID (``client_not_routed``);
* without a pre-fault successful marker probe the phase is INVALID
  (``client_marker_not_sent``); it proves the marker really went out;
* every line must carry this phase's ``r``, a gap-free ``s`` sequence and a
  non-decreasing timestamp inside the observed launch/stop window; probes must
  keep trying (no gap above 15 s) and the post-fault attempts are bound to the
  sequence number the runner read after the fault action.  At least one exit
  and one marker attempt must have ``s > S_fault`` and the hold must contain
  ``floor(hold / 15)`` exit attempts with ``S_fault < s <= S_end``;
* the guest clocks must be ordered ``clock_start <= fault_epoch <=
  post_fault_epoch <= clock_stop``; a same-second boundary can never satisfy
  both sides of the action on its own;
* otherwise PASS.  Failed probes are expected while an exit node is gone and
  are only counted.

Diagnostics are fixed error codes and line numbers only.  Raw guest bytes are
never part of a reason or detail string.
"""

from __future__ import annotations

import json
import re
import sys
from typing import Any

MARKER_PREFIX = "VPRCLIENTMARK1:"
MARKER_RE = re.compile(r"^VPRCLIENTMARK1:[0-9a-f]{32}$")
RUN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
MAX_PROBE_LOG_BYTES = 1024 * 1024
MAX_PROBE_LINE_BYTES = 4096
MAX_PROBE_GAP_SECONDS = 15

_EXIT_KEYS = frozenset({"t", "k", "ok", "m", "r", "s"})
_MARKER_KEYS = frozenset({"t", "k", "ok", "r", "s"})
_OVERFLOW_KEYS = frozenset({"t", "k", "r", "s"})
_KINDS = ("exit", "marker")
_PHASES = ("before", "after")


class ProbeError(ValueError):
    """The probe log cannot be trusted as evidence.

    ``code`` is a fixed local token and ``line`` is the 1-based line number.
    Neither ever contains guest-supplied bytes.
    """

    def __init__(self, code: str, line: int | None = None):
        self.code = code
        self.line = line
        super().__init__(f"line {line}: {code}" if line is not None else code)


def is_marker(value: object) -> bool:
    return isinstance(value, str) and MARKER_RE.fullmatch(value) is not None


def marker_run_id(marker: str) -> str:
    """Return the 32-hex phase id carried as ``r`` on every probe line."""
    if not is_marker(marker):
        raise ProbeError("invalid_marker")
    return marker.split(":", 1)[1]


class _DuplicateKey(Exception):
    pass


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey()
        result[key] = value
    return result


def _is_epoch(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def parse_line(raw: bytes, number: int) -> dict[str, Any]:
    """Parse one JSONL line; raise :class:`ProbeError` on any deviation."""
    if len(raw) > MAX_PROBE_LINE_BYTES:
        raise ProbeError("line_oversized", number)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProbeError("not_utf8", number) from exc
    try:
        document = json.loads(text, object_pairs_hook=_pairs)
    except _DuplicateKey as exc:
        raise ProbeError("duplicate_key", number) from exc
    except json.JSONDecodeError as exc:
        raise ProbeError("invalid_json", number) from exc
    if not isinstance(document, dict):
        raise ProbeError("not_object", number)
    kind = document.get("k")
    if kind not in _KINDS and kind != "overflow":
        raise ProbeError("unknown_kind", number)
    keys = set(document)
    if kind == "exit":
        if keys != _EXIT_KEYS:
            raise ProbeError("unexpected_keys", number)
    elif kind == "marker":
        if keys != _MARKER_KEYS:
            raise ProbeError("unexpected_keys", number)
    elif keys != _OVERFLOW_KEYS:
        raise ProbeError("unexpected_keys", number)
    if not _is_epoch(document.get("t")):
        raise ProbeError("invalid_timestamp", number)
    if not isinstance(document.get("r"), str) or RUN_ID_RE.fullmatch(
        document["r"]
    ) is None:
        raise ProbeError("invalid_run_id", number)
    sequence = document.get("s")
    if (
        isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or sequence < 1
    ):
        raise ProbeError("invalid_sequence", number)
    if kind != "overflow":
        if not isinstance(document.get("ok"), bool):
            raise ProbeError("invalid_ok", number)
    if kind == "exit":
        mullvad = document.get("m")
        if mullvad is not None and not isinstance(mullvad, bool):
            raise ProbeError("invalid_mullvad", number)
    return document


def parse_probe_log_partial(
    data: bytes,
) -> tuple[list[tuple[int, dict[str, Any]]], list[dict[str, Any]]]:
    """Parse every complete line and return ``(entries, problems)``.

    A malformed line is retained as a fixed ``{"line", "code"}`` problem; later
    lines are still parsed so a real-IP leak can never be masked by a bad tail.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise ProbeError("probe_log_not_bytes")
    raw = bytes(data)
    problems: list[dict[str, Any]] = []
    if len(raw) > MAX_PROBE_LOG_BYTES:
        problems.append({"line": 0, "code": "probe_log_oversized"})
        raw = raw[:MAX_PROBE_LOG_BYTES]
    if raw and not raw.endswith(b"\n"):
        problems.append({"line": len(raw.splitlines()), "code": "missing_final_newline"})
    entries: list[tuple[int, dict[str, Any]]] = []
    for number, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            problems.append({"line": number, "code": "empty_line"})
            continue
        try:
            entries.append((number, parse_line(line, number)))
        except ProbeError as exc:
            problems.append({"line": number, "code": exc.code})
    return entries, problems


def parse_probe_log(data: bytes) -> list[dict[str, Any]]:
    """Return every parsed line; any malformed content raises."""
    entries, problems = parse_probe_log_partial(data)
    if problems:
        first = problems[0]
        raise ProbeError(first["code"], first["line"] or None)
    return [entry for _number, entry in entries]


def _empty_counts() -> dict[str, dict[str, dict[str, int]]]:
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


def _add_reason(reasons: list[str], reason: str) -> None:
    if reason not in reasons:
        reasons.append(reason)


def evaluate_probe_log(
    data: bytes,
    *,
    fault_epoch: int | None = None,
    run_id: str,
    clock_start: int | None = None,
    clock_stop: int | None = None,
    post_fault_epoch: int | None = None,
    fault_sequence: int | None = None,
    end_sequence: int | None = None,
    hold_seconds: int | None = None,
    max_gap: int = MAX_PROBE_GAP_SECONDS,
) -> dict[str, Any]:
    """Return the client probe verdict, counts and fixed-code reasons.

    ``fault_epoch`` is the client's own wall-clock second immediately before
    the fault was applied.  ``post_fault_epoch`` is the client clock read after
    the fault action finished.  ``clock_start``/``clock_stop`` bracket the
    traffic unit's observed life.  All four are guest-clock seconds; host and
    guest clocks may differ and are never compared with each other.

    ``fault_sequence`` is the last complete probe sequence number read through
    QGA after the fault action and its postcondition finished.  A post-fault
    attempt must have a strictly greater ``s``; ``end_sequence`` is the last
    complete sequence number read at the end of the hold.  This binds the
    coverage to the log itself, so a same-second or frozen guest clock cannot
    certify a hold in which no probe ran.  ``hold_seconds`` sets the required
    exit-attempt density (one per ``MAX_PROBE_GAP_SECONDS``).
    """
    if not isinstance(run_id, str) or RUN_ID_RE.fullmatch(run_id) is None:
        raise ProbeError("invalid_run_id")
    entries, problems = parse_probe_log_partial(data)
    counts = _empty_counts()
    invalid_reasons: list[str] = []
    problem_list = [
        {"line": problem["line"], "code": problem["code"]}
        for problem in problems
    ]
    for problem in problems:
        code = problem["code"]
        if code == "missing_final_newline":
            _add_reason(invalid_reasons, "probe_log_truncated")
        elif code == "probe_log_oversized":
            _add_reason(invalid_reasons, "probe_log_oversized")
        else:
            _add_reason(invalid_reasons, "probe_log_malformed")

    leak = False
    pre_fault_mullvad = False
    pre_fault_marker = False
    post_fault_exit_attempts = 0
    post_fault_marker_attempts = 0
    expected_sequence = 1
    previous_timestamp: int | None = None
    previous_sequence_problem = False
    timestamps: list[int] = []

    def _is_post_fault_attempt(entry: dict[str, Any], value: int) -> bool:
        """A post-fault attempt is bound by sequence, not only by the clock."""
        if post_fault_epoch is None or value < int(post_fault_epoch):
            return False
        if fault_sequence is None or entry["r"] != run_id:
            return False
        sequence = int(entry["s"])
        if sequence <= int(fault_sequence):
            return False
        if end_sequence is not None and sequence > int(end_sequence):
            return False
        return True

    for number, entry in entries:
        kind = entry["k"]
        value = int(entry["t"])
        run_matches = run_id is None or entry["r"] == run_id
        if not run_matches:
            _add_reason(invalid_reasons, "probe_run_mismatch")
        if entry["s"] != expected_sequence and not previous_sequence_problem:
            _add_reason(invalid_reasons, "probe_sequence_gap")
            previous_sequence_problem = True
        expected_sequence = int(entry["s"]) + 1
        if previous_timestamp is not None and value < previous_timestamp:
            _add_reason(invalid_reasons, "probe_timestamp_regression")
        previous_timestamp = value
        timestamps.append(value)
        if kind == "overflow":
            _add_reason(invalid_reasons, "probe_log_overflow")
            continue
        phase = (
            "before"
            if fault_epoch is None or value <= int(fault_epoch)
            else "after"
        )
        bucket = counts[kind][phase]
        bucket["total"] += 1
        if kind == "exit":
            if entry["ok"]:
                bucket["ok"] += 1
                if entry["m"] is True:
                    bucket["mullvad"] += 1
                    if phase == "before" and run_matches:
                        pre_fault_mullvad = True
                else:
                    bucket["non_mullvad"] += 1
                    # LEAK is independent of every quality flag: one
                    # well-formed non-Mullvad success is enough, even when
                    # its ``r`` does not match (a stale or tampered line is
                    # also an INVALID binding defect, but never hides a leak).
                    leak = True
            else:
                bucket["failed"] += 1
            if _is_post_fault_attempt(entry, value):
                post_fault_exit_attempts += 1
        else:
            if entry["ok"]:
                bucket["ok"] += 1
                if phase == "before" and run_matches:
                    pre_fault_marker = True
            else:
                bucket["failed"] += 1
            if _is_post_fault_attempt(entry, value):
                post_fault_marker_attempts += 1

    if fault_epoch is None:
        _add_reason(invalid_reasons, "probe_fault_epoch_missing")
    if post_fault_epoch is None:
        _add_reason(invalid_reasons, "probe_post_epoch_missing")
    if fault_sequence is None:
        _add_reason(invalid_reasons, "probe_fault_sequence_missing")
    if end_sequence is None:
        _add_reason(invalid_reasons, "probe_end_sequence_missing")
    if hold_seconds is None:
        _add_reason(invalid_reasons, "probe_hold_missing")
    if clock_start is None or clock_stop is None:
        _add_reason(invalid_reasons, "probe_window_missing")
    else:
        start = int(clock_start)
        stop = int(clock_stop)
        if stop < start:
            _add_reason(invalid_reasons, "probe_window_invalid")
        if any(value < start or value > stop for value in timestamps):
            _add_reason(invalid_reasons, "probe_timestamp_outside_window")
        ordered = [start, *timestamps, stop]
        if any(
            later - earlier > int(max_gap)
            for earlier, later in zip(ordered, ordered[1:])
        ):
            _add_reason(invalid_reasons, "probe_gap")
    if None not in (clock_start, clock_stop, fault_epoch, post_fault_epoch):
        if not (
            int(clock_start)
            <= int(fault_epoch)
            <= int(post_fault_epoch)
            <= int(clock_stop)
        ):
            _add_reason(invalid_reasons, "probe_clock_order")
    if not pre_fault_mullvad:
        _add_reason(invalid_reasons, "client_not_routed")
    if not pre_fault_marker:
        _add_reason(invalid_reasons, "client_marker_not_sent")
    if post_fault_epoch is not None:
        if post_fault_exit_attempts == 0:
            _add_reason(invalid_reasons, "probe_post_fault_exit_missing")
        if post_fault_marker_attempts == 0:
            _add_reason(invalid_reasons, "probe_post_fault_marker_missing")
    if hold_seconds is not None:
        required = max(1, int(hold_seconds) // int(max_gap))
        if post_fault_exit_attempts < required:
            _add_reason(invalid_reasons, "probe_hold_coverage")

    if leak:
        verdict = "LEAK"
        reason = "client_real_ip"
    elif invalid_reasons:
        verdict = "INVALID"
        reason = invalid_reasons[0]
    else:
        verdict = "PASS"
        reason = None
    return {
        "verdict": verdict,
        "reason": reason,
        "invalid_reasons": invalid_reasons,
        "problems": problem_list,
        "counts": counts,
        "fault_epoch": fault_epoch,
        "post_fault_epoch": post_fault_epoch,
        "fault_sequence": fault_sequence,
        "end_sequence": end_sequence,
        "hold_seconds": hold_seconds,
        "clock_start": clock_start,
        "clock_stop": clock_stop,
        "run_id": run_id,
        "pre_fault_mullvad": pre_fault_mullvad,
        "pre_fault_marker": pre_fault_marker,
        "pre_fault_marker_ok": pre_fault_marker,
        "post_fault_exit_attempts": post_fault_exit_attempts,
        "post_fault_marker_attempts": post_fault_marker_attempts,
        "leak": leak,
    }


def probe_prefix_flags(data: bytes, *, run_id: str | None = None) -> dict[str, bool]:
    """Tolerant look at a log that is still being written.

    Only complete, well-formed lines are considered.  Positive controls must
    carry this run's ``r``; a non-Mullvad success is a leak regardless of the
    run id so a stale or malformed tail cannot hide it.
    """
    entries, _problems = parse_probe_log_partial(data)
    flags = {"leak": False, "mullvad": False, "marker": False}
    for _number, entry in entries:
        if entry["k"] != "exit":
            if (
                entry["k"] == "marker"
                and entry.get("ok") is True
                and (run_id is None or entry["r"] == run_id)
            ):
                flags["marker"] = True
            continue
        if entry.get("ok") is not True:
            continue
        if entry.get("m") is not True:
            flags["leak"] = True
        elif run_id is None or entry["r"] == run_id:
            flags["mullvad"] = True
    return flags


def main(argv: list[str] | None = None) -> int:
    import argparse
    import pathlib

    parser = argparse.ArgumentParser(description="evaluate a client probe log")
    parser.add_argument("--probe-log", required=True)
    parser.add_argument("--fault-epoch", type=int, required=True)
    parser.add_argument("--post-fault-epoch", type=int, required=True)
    parser.add_argument("--fault-sequence", type=int, required=True)
    parser.add_argument("--end-sequence", type=int, required=True)
    parser.add_argument("--hold-seconds", type=int, required=True)
    parser.add_argument("--clock-start", type=int, required=True)
    parser.add_argument("--clock-stop", type=int, required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args(argv)
    if RUN_ID_RE.fullmatch(args.run_id) is None:
        print("clientprobe: invalid run id", file=sys.stderr)
        return 2
    if args.hold_seconds < 0 or args.fault_sequence < 0 or args.end_sequence < 0:
        print("clientprobe: invalid sequence or hold", file=sys.stderr)
        return 2
    try:
        data = pathlib.Path(args.probe_log).read_bytes()
    except OSError as exc:
        print(f"clientprobe: {exc.__class__.__name__}", file=sys.stderr)
        return 2
    report = evaluate_probe_log(
        data,
        fault_epoch=args.fault_epoch,
        post_fault_epoch=args.post_fault_epoch,
        clock_start=args.clock_start,
        clock_stop=args.clock_stop,
        fault_sequence=args.fault_sequence,
        end_sequence=args.end_sequence,
        hold_seconds=args.hold_seconds,
        run_id=args.run_id,
    )
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return {"PASS": 0, "LEAK": 1, "INVALID": 2}[report["verdict"]]


if __name__ == "__main__":
    raise SystemExit(main())
