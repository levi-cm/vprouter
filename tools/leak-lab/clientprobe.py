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
  keep trying (no guest-clock gap above 15 s).  At least one exit and one
  marker attempt must have ``s > S_fault``;
* coverage is host-observed, never guest-clock based (fix round 4): the
  runner takes a trusted prefix sample of the log (exact size + SHA-256)
  immediately before the fault action (``S_pre``), at least every 15 s of
  host monotonic time while the action and its postcondition run, after the
  action (``S_fault``), during the hold, and finally at most
  :data:`HOLD_END_MARGIN` seconds before the hold deadline (``S_end``).  Every
  window between consecutive samples must be at most 15 s long and must
  contain a new exit attempt (an exit line with ``s`` above the previous
  sample's last ``s``).  The deadline sample must finish its size read at or
  before the deadline, so a line first written after the hold never counts
  as coverage (it is still parsed for a LEAK).  Every sample must also report
  that the client still had exactly the router exit node selected
  (``exit_node_ok``).  The evaluator recomputes every sample from the
  evidence bytes it is given: each sample's prefix hash must match, so a
  sample can never claim a line the evidence does not contain.  Windows of at
  most 15 s bound the spacing of individual exit attempts only to about two
  windows in the worst case (an attempt just after one sample and the next
  just before the sample after next); the 15 s guest-clock gap rule bounds
  the spacing of the rows themselves;
* the guest clocks must be ordered ``clock_start <= fault_epoch <=
  post_fault_epoch <= clock_stop`` and must advance across the hold
  (``clock_stop - post_fault_epoch >= hold - 2``).  These are extra INVALID
  conditions only; coverage never depends on the guest clock;
* otherwise PASS.  Failed probes are expected while an exit node is gone and
  are only counted.

Diagnostics are fixed error codes and line numbers only.  Raw guest bytes are
never part of a reason or detail string.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import sys
from typing import Any

MARKER_PREFIX = "VPRCLIENTMARK1:"
MARKER_RE = re.compile(r"^VPRCLIENTMARK1:[0-9a-f]{32}$")
RUN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
MAX_PROBE_LOG_BYTES = 1024 * 1024
MAX_PROBE_LINE_BYTES = 4096
MAX_PROBE_GAP_SECONDS = 15
# Host-observed hold coverage: no window between two trusted prefix samples
# may be longer than this, measured from the start of the earlier sample's
# size read to the end of the later sample's size read.
MAX_HOLD_SAMPLE_WINDOW = 15.0
# The deadline sample (S_end) starts its size read at most this many seconds
# before the hold deadline and must finish it at or before the deadline: a
# size read that ends after the deadline could credit lines first written
# after the hold (GPT R4-I1).
HOLD_END_MARGIN = 3.0
# Recorded host offsets are rounded to milliseconds.
_OFFSET_ROUNDING = 0.001
SAMPLE_KINDS = ("pre", "action", "fault", "hold", "end")
# The guest clock must advance across the hold, within this tolerance.
CLOCK_STALL_TOLERANCE = 2
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

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


def complete_lines(data: bytes) -> bytes:
    """Return only the newline-terminated part of ``data``.

    A sequence boundary is taken only from complete lines: a partial last
    line may still be being written by the guest.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise ProbeError("probe_log_not_bytes")
    raw = bytes(data)
    end = raw.rfind(b"\n")
    return raw[: end + 1] if end >= 0 else b""


def prefix_observation(data: bytes, *, run_id: str) -> dict[str, Any]:
    """Observe a TRUSTED prefix: last sequence, last exit attempt, controls.

    Only complete, well-formed lines carrying ``run_id`` count.  The caller
    must only pass bytes whose size and SHA-256 the guest confirmed; leak
    detection over untrusted bytes is :func:`probe_prefix_flags`.
    """
    if not isinstance(run_id, str) or RUN_ID_RE.fullmatch(run_id) is None:
        raise ProbeError("invalid_run_id")
    entries, _problems = parse_probe_log_partial(complete_lines(data))
    sequence = 0
    exit_sequence: int | None = None
    mullvad = False
    marker = False
    for _number, entry in entries:
        if entry["r"] != run_id:
            continue
        value = int(entry["s"])
        sequence = max(sequence, value)
        if entry["k"] == "exit":
            exit_sequence = value if exit_sequence is None else max(exit_sequence, value)
            if entry["ok"] is True and entry["m"] is True:
                mullvad = True
        elif entry["k"] == "marker" and entry["ok"] is True:
            marker = True
    return {
        "sequence": sequence,
        "exit_sequence": exit_sequence,
        "mullvad": mullvad,
        "marker": marker,
    }


def _is_count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_offset(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and float(value) >= 0.0
    )


def _valid_sample(sample: object) -> bool:
    if not isinstance(sample, dict):
        return False
    if sample.get("kind") not in SAMPLE_KINDS:
        return False
    if not _is_count(sample.get("sequence")) or not _is_count(sample.get("size")):
        return False
    exit_sequence = sample.get("exit_sequence")
    if exit_sequence is not None and (
        not _is_count(exit_sequence) or exit_sequence < 1
    ):
        return False
    digest = sample.get("sha256")
    if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
        return False
    start = sample.get("stat_start")
    end = sample.get("stat_end")
    if not _is_offset(start) or not _is_offset(end):
        return False
    return float(end) >= float(start)


def _fault_index(samples: list[dict[str, Any]]) -> int | None:
    """Return the S_fault index when the kinds are pre, action*, fault, hold*, end."""
    kinds = [sample["kind"] for sample in samples]
    if len(kinds) < 3 or kinds[0] != "pre" or kinds[-1] != "end":
        return None
    if kinds.count("fault") != 1:
        return None
    fault = kinds.index("fault")
    if any(kind != "action" for kind in kinds[1:fault]):
        return None
    if any(kind != "hold" for kind in kinds[fault + 1 : -1]):
        return None
    return fault


def _check_hold_samples(
    raw: bytes,
    samples: object,
    *,
    run_id: str,
    fault_sequence: int | None,
    end_sequence: int | None,
    hold_seconds: int | None,
    max_window: float,
    reasons: list[str],
) -> int | None:
    """Verify host-observed coverage from S_pre to S_end against the evidence.

    Returns the index of the S_fault sample, or None when the samples cannot
    be used at all.
    """
    if not isinstance(samples, list) or len(samples) < 3:
        _add_reason(reasons, "probe_hold_samples_missing")
        return None
    if not all(_valid_sample(sample) for sample in samples):
        _add_reason(reasons, "probe_hold_samples_invalid")
        return None
    fault = _fault_index(samples)
    if fault is None:
        _add_reason(reasons, "probe_hold_samples_invalid")
        return None
    # Opus R4 M-2: the exit-node binding is part of the evidence; every
    # sample must say the client still had exactly the router selected.
    if any(sample.get("exit_node_ok") is not True for sample in samples):
        _add_reason(reasons, "client_exit_node_lost")
    if (
        fault_sequence is None
        or end_sequence is None
        or samples[fault]["sequence"] != fault_sequence
        or samples[-1]["sequence"] != end_sequence
    ):
        _add_reason(reasons, "probe_hold_samples_invalid")
    observed: list[dict[str, Any]] = []
    for sample in samples:
        size = int(sample["size"])
        prefix = raw[:size]
        if len(prefix) != size or hashlib.sha256(prefix).hexdigest() != sample["sha256"]:
            # The sample is not a prefix of this evidence: nothing it claims
            # can be checked, so it covers nothing.
            _add_reason(reasons, "probe_hold_prefix_mismatch")
            return fault
        observation = prefix_observation(prefix, run_id=run_id)
        if (
            observation["sequence"] != sample["sequence"]
            or observation["exit_sequence"] != sample["exit_sequence"]
        ):
            _add_reason(reasons, "probe_hold_samples_invalid")
        observed.append(observation)
    for earlier, later in zip(samples, samples[1:]):
        if (
            later["size"] < earlier["size"]
            or later["sequence"] < earlier["sequence"]
            or float(later["stat_start"]) < float(earlier["stat_start"])
        ):
            _add_reason(reasons, "probe_hold_samples_invalid")
    # Every window from S_pre to S_end, through the fault action, its
    # postcondition and the hold, needs a new exit attempt.
    for index in range(1, len(samples)):
        window = float(samples[index]["stat_end"]) - float(
            samples[index - 1]["stat_start"]
        )
        if window > float(max_window):
            _add_reason(reasons, "probe_hold_window_late")
        newest_exit = observed[index]["exit_sequence"]
        if newest_exit is None or newest_exit <= observed[index - 1]["sequence"]:
            _add_reason(reasons, "probe_hold_window_empty")
    if hold_seconds is not None:
        base = float(samples[fault]["stat_start"])
        deadline = base + float(hold_seconds)
        end_start = float(samples[-1]["stat_start"])
        end_stop = float(samples[-1]["stat_end"])
        if end_start < deadline - HOLD_END_MARGIN - _OFFSET_ROUNDING:
            _add_reason(reasons, "probe_hold_short")
        if end_stop > deadline + _OFFSET_ROUNDING:
            # GPT R4-I1: the size read may observe the log anywhere inside
            # [stat_start, stat_end]; one that ends after the deadline could
            # credit a line first written after the hold.
            _add_reason(reasons, "probe_hold_deadline_late")
    return fault


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
    hold_samples: list[dict[str, Any]] | None = None,
    max_gap: int = MAX_PROBE_GAP_SECONDS,
    max_window: float = MAX_HOLD_SAMPLE_WINDOW,
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
    complete sequence number of the deadline sample.  ``hold_samples`` are the
    runner's trusted prefix samples in order: ``pre`` (immediately before the
    fault action), any ``action`` samples taken while the action and its
    postcondition ran, exactly one ``fault`` (S_fault), any ``hold`` samples
    and the ``end`` sample (S_end).  Each carries ``kind``, ``sequence``,
    ``exit_sequence``, ``size``, ``sha256``, ``exit_node_ok`` and the host
    monotonic ``stat_start``/``stat_end`` of its size read (seconds relative
    to the S_pre sample).  The hold deadline is the S_fault size read's start
    plus ``hold_seconds``.  Coverage is decided only from those samples,
    re-derived from ``data``: a same-second or frozen guest clock, a burst
    followed by silence, a silent fault action, or lines first written after
    the deadline can never certify the phase.
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
    if None not in (clock_stop, post_fault_epoch, hold_seconds):
        # Extra guest-clock condition (Opus R3-3); coverage never uses it.
        if int(clock_stop) - int(post_fault_epoch) < int(hold_seconds) - CLOCK_STALL_TOLERANCE:
            _add_reason(invalid_reasons, "probe_clock_stalled")
    if not pre_fault_mullvad:
        _add_reason(invalid_reasons, "client_not_routed")
    if not pre_fault_marker:
        _add_reason(invalid_reasons, "client_marker_not_sent")
    if post_fault_epoch is not None:
        if post_fault_exit_attempts == 0:
            _add_reason(invalid_reasons, "probe_post_fault_exit_missing")
        if post_fault_marker_attempts == 0:
            _add_reason(invalid_reasons, "probe_post_fault_marker_missing")
    raw = bytes(data[:MAX_PROBE_LOG_BYTES])
    fault_index = _check_hold_samples(
        raw,
        hold_samples,
        run_id=run_id,
        fault_sequence=fault_sequence,
        end_sequence=end_sequence,
        hold_seconds=hold_seconds,
        max_window=max_window,
        reasons=invalid_reasons,
    )

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
        "hold_windows": (
            len(hold_samples) - 1 - fault_index if fault_index is not None else 0
        ),
        "coverage_windows": (
            len(hold_samples) - 1 if fault_index is not None else 0
        ),
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
    parser.add_argument(
        "--hold-samples",
        required=True,
        help="JSON file with the phase record's client.hold_samples list",
    )
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
        samples = json.loads(pathlib.Path(args.hold_samples).read_bytes())
    except (OSError, ValueError) as exc:
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
        hold_samples=samples if isinstance(samples, list) else None,
        run_id=args.run_id,
    )
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return {"PASS": 0, "LEAK": 1, "INVALID": 2}[report["verdict"]]


if __name__ == "__main__":
    raise SystemExit(main())
