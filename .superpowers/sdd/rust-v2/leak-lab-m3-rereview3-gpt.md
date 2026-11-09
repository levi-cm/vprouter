# Leak-lab M3 focused adversarial re-review, round 3

Target: `rust/v2`, `37bafc2ba28789834a1df1ecef599bf872c8c7ce`. Initial checkout clean.

Scope: offline stdlib reproducers and the requested two-file diff only; no runtime/network qualification. Report is written incrementally.

Status: COMPLETE. **FAIL — two new Critical coverage false PASS paths (R3-C1, R3-C2).** All named round-2 regression reproducers are fixed; both required suites pass. These are offline findings, not live leak qualification.

## Required suites (executed once each)

- `cd tools/leak-lab && python3 -B -W error -m unittest test_leak_lab`: **329 tests, OK**, 14.562 s.
- `cd tools/leak-lab && python3 -B -W error -m unittest vm.test_vm`: **266 tests, OK**, 14.690 s.

Both used `TMPDIR=/var/tmp/leaklab-m3r3-gpt`. Offline tests only.

The supplied prior partial report contains prose descriptions, not embedded source for `adversarial.py`; the named conditions are reconstructed below using the current fake-QGA harness, real runner, real probe evaluator and real client scanner. No production helper/scanner verdict is replaced.

`NEW_stop_failure_later_leak`

```json
{
  "end_sequence": 62,
  "errors": [
    "client_traffic_stop_failed",
    "phase_exception:Refusal",
    "probe_snapshot_untrusted",
    "client_real_ip"
  ],
  "exit": 1,
  "fault_sequence": 2,
  "guest_leak": true,
  "latch": true,
  "log_read": null,
  "persisted_leak": true,
  "post_exits": 30,
  "post_markers": 30,
  "probe": "LEAK",
  "reasons": [],
  "result": "LEAK",
  "stop_proven": false,
  "trusted": false
}
```

`NEW_same_second_no_post_fault_probes`

```json
{
  "end_sequence": 2,
  "errors": [
    "probe_post_fault_exit_missing"
  ],
  "exit": 2,
  "fault_sequence": 2,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 0,
  "post_markers": 0,
  "probe": "INVALID",
  "reasons": [
    "probe_post_fault_exit_missing",
    "probe_post_fault_marker_missing",
    "probe_hold_coverage"
  ],
  "result": "INVALID",
  "stop_proven": true,
  "trusted": true
}
```

`NEW_prefault_leak_then_hash_failure`

```json
{
  "end_sequence": null,
  "errors": [
    "client_real_ip",
    "phase_exception:Refusal",
    "probe_log_unreadable"
  ],
  "exit": 1,
  "fault_sequence": null,
  "guest_leak": true,
  "latch": true,
  "log_read": null,
  "persisted_leak": true,
  "post_exits": 0,
  "post_markers": 0,
  "probe": "LEAK",
  "reasons": [
    "probe_fault_epoch_missing",
    "probe_post_epoch_missing",
    "probe_fault_sequence_missing",
    "probe_end_sequence_missing",
    "client_not_routed",
    "probe_hold_coverage"
  ],
  "result": "LEAK",
  "stop_proven": true,
  "trusted": true
}
```

`NEW_nonzero_cat_contains_leak`

```json
{
  "end_sequence": 62,
  "errors": [
    "client_real_ip"
  ],
  "exit": 1,
  "fault_sequence": 2,
  "guest_leak": true,
  "latch": true,
  "log_read": "exact",
  "persisted_leak": true,
  "post_exits": 30,
  "post_markers": 30,
  "probe": "LEAK",
  "reasons": [],
  "result": "LEAK",
  "stop_proven": true,
  "trusted": true
}
```

`same_second_exact_old_fixture`

```json
{
  "invalid_reasons": [
    "probe_post_fault_exit_missing",
    "probe_post_fault_marker_missing",
    "probe_hold_coverage"
  ],
  "post_fault_exit_attempts": 0,
  "post_fault_marker_attempts": 0,
  "verdict": "INVALID"
}
```

`same_second_30s_no_new_sequences`

```json
{
  "invalid_reasons": [
    "probe_post_fault_exit_missing",
    "probe_post_fault_marker_missing",
    "probe_hold_coverage"
  ],
  "post_fault_exit_attempts": 0,
  "post_fault_marker_attempts": 0,
  "verdict": "INVALID"
}
```

`unordered_clock_fixture`

```json
{
  "invalid_reasons": [
    "probe_clock_order"
  ],
  "post_fault_exit_attempts": 1,
  "post_fault_marker_attempts": 1,
  "verdict": "INVALID"
}
```

`same_second_genuinely_new_sequences_positive_control`

```json
{
  "invalid_reasons": [],
  "post_fault_exit_attempts": 2,
  "post_fault_marker_attempts": 2,
  "verdict": "PASS"
}
```

### Harness correction and authoritative rerun

The first nonzero-cat wrapper patched a second import of run_phase rather than the module used by test_vm, so that first run did not inject cat failure (`log_read=exact`). Corrected to `rp = tv.run_phase`; the following rerun is authoritative. The other initial conditions were passed directly to the harness and did execute.

`NEW_stop_failure_later_leak`

```json
{
  "end_sequence": 62,
  "errors": [
    "client_traffic_stop_failed",
    "phase_exception:Refusal",
    "probe_snapshot_untrusted",
    "client_real_ip"
  ],
  "exit": 1,
  "fault_sequence": 2,
  "guest_leak": true,
  "latch": true,
  "log_read": null,
  "persisted_leak": true,
  "post_exits": 30,
  "post_markers": 30,
  "probe": "LEAK",
  "reasons": [],
  "result": "LEAK",
  "stop_proven": false,
  "trusted": false
}
```

`NEW_same_second_no_post_fault_probes`

```json
{
  "end_sequence": 2,
  "errors": [
    "probe_post_fault_exit_missing"
  ],
  "exit": 2,
  "fault_sequence": 2,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 0,
  "post_markers": 0,
  "probe": "INVALID",
  "reasons": [
    "probe_post_fault_exit_missing",
    "probe_post_fault_marker_missing",
    "probe_hold_coverage"
  ],
  "result": "INVALID",
  "stop_proven": true,
  "trusted": true
}
```

`NEW_prefault_leak_then_hash_failure`

```json
{
  "end_sequence": null,
  "errors": [
    "client_real_ip",
    "phase_exception:Refusal",
    "probe_log_unreadable"
  ],
  "exit": 1,
  "fault_sequence": null,
  "guest_leak": true,
  "latch": true,
  "log_read": null,
  "persisted_leak": true,
  "post_exits": 0,
  "post_markers": 0,
  "probe": "LEAK",
  "reasons": [
    "probe_fault_epoch_missing",
    "probe_post_epoch_missing",
    "probe_fault_sequence_missing",
    "probe_end_sequence_missing",
    "client_not_routed",
    "probe_hold_coverage"
  ],
  "result": "LEAK",
  "stop_proven": true,
  "trusted": true
}
```

`NEW_nonzero_cat_contains_leak`

```json
{
  "end_sequence": 62,
  "errors": [
    "probe_log_unreadable",
    "client_real_ip"
  ],
  "exit": 1,
  "fault_sequence": 2,
  "guest_leak": true,
  "latch": true,
  "log_read": null,
  "persisted_leak": true,
  "post_exits": 30,
  "post_markers": 30,
  "probe": "LEAK",
  "reasons": [],
  "result": "LEAK",
  "stop_proven": true,
  "trusted": true
}
```

`same_second_exact_old_fixture`

```json
{
  "invalid_reasons": [
    "probe_post_fault_exit_missing",
    "probe_post_fault_marker_missing",
    "probe_hold_coverage"
  ],
  "post_fault_exit_attempts": 0,
  "post_fault_marker_attempts": 0,
  "verdict": "INVALID"
}
```

`same_second_30s_no_new_sequences`

```json
{
  "invalid_reasons": [
    "probe_post_fault_exit_missing",
    "probe_post_fault_marker_missing",
    "probe_hold_coverage"
  ],
  "post_fault_exit_attempts": 0,
  "post_fault_marker_attempts": 0,
  "verdict": "INVALID"
}
```

`unordered_clock_fixture`

```json
{
  "invalid_reasons": [
    "probe_clock_order"
  ],
  "post_fault_exit_attempts": 1,
  "post_fault_marker_attempts": 1,
  "verdict": "INVALID"
}
```

`same_second_genuinely_new_sequences_positive_control`

```json
{
  "invalid_reasons": [],
  "post_fault_exit_attempts": 2,
  "post_fault_marker_attempts": 2,
  "verdict": "PASS"
}
```

## Round-2 regression disposition

| Named condition | Status on 37bafc2 | Actual result |
|---|---|---|
| NEW_stop_failure_later_leak | **fixed** | LEAK, exit 1; late leak persisted; failed-stop snapshot untrusted |
| NEW_same_second_no_post_fault_probes | **fixed** | INVALID, exit 2; S_fault=S_end=2; zero post-fault attempts |
| Same-second evaluator fixture, 5 s and adapted 30 s | **fixed** | INVALID; post-fault exit/marker missing and hold coverage missing |
| Unordered-clock evaluator fixture | **fixed** | INVALID, probe_clock_order |
| NEW_prefault_leak_then_hash_failure | **fixed** | LEAK, exit 1; latch true despite probe_log_unreadable |
| NEW_nonzero_cat_contains_leak | **fixed** | LEAK, exit 1; nonzero final cat bytes persisted, probe_log_unreadable |

Zero-duration orchestration is now rejected before execution; the adapted same-second run uses the minimum accepted 30 s hold. A positive control with genuinely new same-second sequences returns PASS (2 exits, 2 markers), as the new contract permits.

## New false-PASS hunt (incremental)

Testing whether a partial fault-boundary read underestimates S_fault and lets the later exact snapshot reclassify pre-fault rows as post-fault coverage.

`fault_boundary_read_details_1`

```json
{
  "actual_last": 6,
  "flags": {
    "leak": false,
    "marker": true,
    "mullvad": true
  },
  "problem": "probe_log_unreadable",
  "sequence": 2
}
```

`R3_partial_failed_fault_boundary_no_hold_probes`

```json
{
  "end_sequence": 6,
  "errors": [],
  "exit": 0,
  "fault_sequence": 2,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 2,
  "post_markers": 2,
  "probe": "PASS",
  "reasons": [],
  "result": "PASS",
  "stop_proven": true,
  "trusted": true
}
```

`fault_boundary_read_details_0`

```json
{
  "actual_last": 6,
  "flags": {
    "leak": false,
    "marker": true,
    "mullvad": true
  },
  "problem": null,
  "sequence": 2
}
```

`R3_partial_success_fault_boundary_no_hold_probes`

```json
{
  "end_sequence": 6,
  "errors": [],
  "exit": 0,
  "fault_sequence": 2,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 2,
  "post_markers": 2,
  "probe": "PASS",
  "reasons": [],
  "result": "PASS",
  "stop_proven": true,
  "trusted": true
}
```

## Critical R3-C1 — A partial boundary read reclassifies old probes as hold coverage

**Locations:** `tools/leak-lab/vm/run_phase.py:3381` accepts any positive parsed sequence even with a read error; `:4433` ignores that error when a sequence was returned; `:3295` reads a size but never checks the returned byte count against it. `tools/leak-lab/clientprobe.py:281` and `:382` then trust the understated S_fault and count the old rows toward floor(hold/15).

**Executed reproducer:** `R3_partial_failed_fault_boundary_no_hold_probes` above. Start the real runner with stop-router, 30 s, a silent active traffic unit and frozen guest clock. Three successful pairs (s=1..6) are written before the fault. Only the fault-boundary cat returns a two-row prefix with exit 1; stat still reports the real full size. The real boundary helper returns `(2, flags, "probe_log_unreadable")` immediately rather than retrying; the caller suppresses the problem because S_fault is non-null. End read and exact final size/hash/cat are normal and return all six pre-fault rows. **Actual: PASS, exit 0, errors [], S_fault=2, S_end=6, 2 post-fault exits and 2 post-fault markers, trusted exact snapshot**, despite zero post-fault probes. `R3_partial_success_fault_boundary_no_hold_probes` also PASSes when the truncated cat exits 0. These are coverage false PASSes; the fixture does not claim an observed real-IP leak. A silent/unobserved fault hold must not qualify as tested fail-closed operation.

**Suggested fix:** distinguish tolerant bytes used to latch LEAK from a trusted sequence-boundary read. A failed or incomplete transfer must never establish S_fault or S_end. Retry or invalidate it, latch leaks on every attempt, and propagate boundary-quality errors even when a prefix has a positive sequence. For a growing append-only file, read a guest-side bounded snapshot/prefix with its own size/hash or otherwise prove the boundary includes every complete record present at sampling; at minimum reject returned bytes shorter than the pre-read stat size. Add regressions with a genuine pre-fault backlog, not just a single pair.

`R3_early_burst_then_29s_silent`

```json
{
  "end_sequence": 6,
  "errors": [],
  "exit": 0,
  "fault_sequence": 2,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 2,
  "post_markers": 2,
  "probe": "PASS",
  "reasons": [],
  "result": "PASS",
  "stop_proven": true,
  "trusted": true
}
```

`R3_zero_hold_probes_two_pairs_during_end_status`

```json
{
  "end_sequence": 6,
  "errors": [],
  "exit": 0,
  "fault_sequence": 2,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 2,
  "post_markers": 2,
  "probe": "PASS",
  "reasons": [],
  "result": "PASS",
  "stop_proven": true,
  "trusted": true
}
```

`R3_complete_boundary_backlog_negative_control`

```json
{
  "end_sequence": 6,
  "errors": [
    "probe_post_fault_exit_missing"
  ],
  "exit": 2,
  "fault_sequence": 6,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 0,
  "post_markers": 0,
  "probe": "INVALID",
  "reasons": [
    "probe_post_fault_exit_missing",
    "probe_post_fault_marker_missing",
    "probe_hold_coverage"
  ],
  "result": "INVALID",
  "stop_proven": true,
  "trusted": true
}
```

`R3_end_exit_recheck_missing`

```json
{
  "end_sequence": 62,
  "errors": [
    "client_exit_node_lost"
  ],
  "exit": 2,
  "fault_sequence": 2,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 30,
  "post_markers": 30,
  "probe": "PASS",
  "reasons": [],
  "result": "INVALID",
  "stop_proven": true,
  "trusted": true
}
```

`R3_end_exit_recheck_wrong_id`

```json
{
  "end_sequence": 62,
  "errors": [
    "client_exit_node_lost"
  ],
  "exit": 2,
  "fault_sequence": 2,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 30,
  "post_markers": 30,
  "probe": "PASS",
  "reasons": [],
  "result": "INVALID",
  "stop_proven": true,
  "trusted": true
}
```

`R3_end_exit_recheck_wrong_ip`

```json
{
  "end_sequence": 62,
  "errors": [
    "client_exit_node_lost"
  ],
  "exit": 2,
  "fault_sequence": 2,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 30,
  "post_markers": 30,
  "probe": "PASS",
  "reasons": [],
  "result": "INVALID",
  "stop_proven": true,
  "trusted": true
}
```

`R3_end_exit_recheck_offline`

```json
{
  "end_sequence": 62,
  "errors": [
    "client_exit_node_lost"
  ],
  "exit": 2,
  "fault_sequence": 2,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 30,
  "post_markers": 30,
  "probe": "PASS",
  "reasons": [],
  "result": "INVALID",
  "stop_proven": true,
  "trusted": true
}
```

`R3_end_exit_recheck_malformed`

```json
{
  "end_sequence": 62,
  "errors": [
    "client_exit_node_lost"
  ],
  "exit": 2,
  "fault_sequence": 2,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 30,
  "post_markers": 30,
  "probe": "PASS",
  "reasons": [],
  "result": "INVALID",
  "stop_proven": true,
  "trusted": true
}
```

## Critical R3-C2 — Total sequence count does not prove traffic covered the hold

**Locations:** `tools/leak-lab/clientprobe.py:358` checks gaps only with the guest wall clock; `:382` requires only a total number of exits, with no temporal distribution. `tools/leak-lab/vm/run_phase.py:4440` measures the hold with host monotonic time, but `:4453` performs a potentially blocking status read before `:4466` samples S_end. There is no host-observed progress within the hold.

**Executed reproducer 1:** `R3_early_burst_then_29s_silent`: normal complete boundary reads, 30 s stop-router phase, frozen guest clock. The active loop emits two post-boundary pairs in the first two 0.25 s sleep steps, then emits nothing for the remaining 29.5 s. Both S boundaries, final exact read and stop proof are untouched. **Actual: PASS, exit 0, errors [], S_fault=2, S_end=6, 2 exits and 2 markers.** A >15 s unobserved tail passes because all guest timestamps are equal and two early exits satisfy floor(30/15).

**Executed reproducer 2:** `R3_zero_hold_probes_two_pairs_during_end_status`: the active loop is silent throughout the entire 30 s host hold. Only when the runner calls the end-of-hold status recheck does the fake guest emit two pairs, modelling recovery of a stalled loop during that QGA call. The same frozen-clock condition is used; all reads and stop results are normal. **Actual: PASS, exit 0, errors [], S_fault=2, S_end=6, 2 purported hold exits and markers**, although none occurred in the hold. This variant also demonstrates that S_end is sampled after the intended observation interval.

These do not require a truncated transfer and therefore remain after R3-C1 is fixed. They do not demonstrate an observed real-IP leak; they demonstrate a false claim of traffic coverage in which a fault-period leak can go untested. This is the same frozen-clock/silent-active-unit threat model explicitly addressed by round 2, with a short burst or delayed recovery instead of permanent silence.

**Suggested fix:** establish progress against host monotonic time throughout the hold (bounded sequence observations per <=15 s interval, with conservative treatment of read latency and missed windows), or a trustworthy independent monotonic probe-time protocol. Require activity through the end of the interval; aggregate floor(hold/15) counts alone cannot establish it. Freeze the end boundary before unrelated status-check delays and do not credit probes first seen after the hold deadline as evidence for a silent hold. Keep LEAK precedence on every read.

### Controls and other scoped checks

- Full fault-boundary read over the same six-row pre-fault backlog: **INVALID**, S_fault=S_end=6, zero post-fault attempts. This isolates R3-C1 to the boundary-underread path.
- End-of-hold ExitNodeStatus missing, wrong ID, wrong IP, Online=false, or malformed: all five **INVALID**, exit 2, client_exit_node_lost. The probe object stays PASS on these healthy-traffic controls, but the combined phase correctly refuses PASS.

### Realistic cadence confirmation for R3-C2

The first burst above used two 0.25 s steps to isolate the count logic. Repeat with probes only at host +1 s and +2 s (then 28 s silence), and separately with a 1 s delay before each of the two probes during the end status call. This keeps the script cadence at 1 Hz and the status call below its 20 s QGA timeout. Results follow.

`R3_1Hz_early_burst_then_28s_silent`

```json
{
  "end_sequence": 6,
  "errors": [],
  "exit": 0,
  "fault_sequence": 2,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 2,
  "post_markers": 2,
  "probe": "PASS",
  "reasons": [],
  "result": "PASS",
  "stop_proven": true,
  "trusted": true
}
```

`R3_zero_hold_probes_two_pairs_during_end_status`

```json
{
  "end_sequence": 6,
  "errors": [],
  "exit": 0,
  "fault_sequence": 2,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 2,
  "post_markers": 2,
  "probe": "PASS",
  "reasons": [],
  "result": "PASS",
  "stop_proven": true,
  "trusted": true
}
```

`R3_stop_reports_success_but_stays_active`

```json
{
  "end_sequence": 62,
  "errors": [
    "client_traffic_stop_failed",
    "phase_exception:Refusal",
    "probe_snapshot_untrusted",
    "probe_log_read_quality"
  ],
  "exit": 2,
  "fault_sequence": 2,
  "guest_leak": false,
  "latch": false,
  "log_read": null,
  "persisted_leak": false,
  "post_exits": 30,
  "post_markers": 30,
  "probe": "INVALID",
  "reasons": [],
  "result": "INVALID",
  "stop_proven": false,
  "trusted": false
}
```

`R3_boundary_1_leak_then_final_read_failure`

```json
{
  "end_sequence": 63,
  "errors": [
    "probe_log_unreadable",
    "probe_gap"
  ],
  "exit": 1,
  "fault_sequence": 3,
  "guest_leak": true,
  "latch": true,
  "log_read": null,
  "persisted_leak": false,
  "post_exits": 0,
  "post_markers": 0,
  "probe": "INVALID",
  "reasons": [
    "probe_gap",
    "client_not_routed",
    "client_marker_not_sent",
    "probe_post_fault_exit_missing",
    "probe_post_fault_marker_missing",
    "probe_hold_coverage"
  ],
  "result": "LEAK",
  "stop_proven": true,
  "trusted": true
}
```

`R3_boundary_2_leak_then_final_read_failure`

```json
{
  "end_sequence": 63,
  "errors": [
    "probe_log_unreadable",
    "probe_gap"
  ],
  "exit": 1,
  "fault_sequence": 2,
  "guest_leak": true,
  "latch": true,
  "log_read": null,
  "persisted_leak": false,
  "post_exits": 0,
  "post_markers": 0,
  "probe": "INVALID",
  "reasons": [
    "probe_gap",
    "client_not_routed",
    "client_marker_not_sent",
    "probe_post_fault_exit_missing",
    "probe_post_fault_marker_missing",
    "probe_hold_coverage"
  ],
  "result": "LEAK",
  "stop_proven": true,
  "trusted": true
}
```

### Final stop/latch controls

- Successful stop command while traffic stays active: **INVALID**, exit 2, traffic_stop_proven=false, snapshot untrusted.
- A real current-run non-Mullvad success injected immediately before the fault boundary read, followed by a final read returning no bytes: combined **LEAK**, exit 1, latch=true even though the final probe object is INVALID.
- The same injection immediately before the end boundary read: combined **LEAK**, exit 1, latch=true.
- No additional Critical/Important finding in stop proof or the tested latch/recheck paths. No Minor findings raised. Login URL stderr is accepted and was not reviewed as a defect.

## Embedded reproducers

All commands below run from the repository root at 37bafc2. Create `/var/tmp/leaklab-m3r3-gpt`, save each block under its indicated filename, and run with `TMPDIR=/var/tmp/leaklab-m3r3-gpt python3 -B -W error <script>`. The harness creates only temporary fake evidence and intercepts guest/process/network operations; the client scanner and phase decision logic run for real. `repro.py` also supplies shared definitions to the other scripts. These scripts append results to this report; save a copy before rerunning if preserving this review artifact.

### repro.py

```python
import contextlib
import json
import pathlib
import sys
from unittest import mock
sys.path.insert(0, str(pathlib.Path.cwd() / 'tools/leak-lab'))
from vm import test_vm as tv
rp = tv.run_phase
import clientprobe as cp
REPORT = pathlib.Path('.superpowers/sdd/rust-v2/leak-lab-m3-rereview3-gpt.md')

def record(name, data):
    line = name + ': ' + json.dumps(data, sort_keys=True)
    print(line, flush=True)
    with REPORT.open('a') as f:
        f.write('\n`' + name + '`\n\n```json\n' + json.dumps(data, sort_keys=True, indent=2) + '\n```\n')

def phase(name, kwargs, phase='stop-router', patches=None, duration=30):
    case = tv.ClientRunPhaseTests('test_client_idle_passes_with_both_captures_and_the_probe_log')
    case.setUp()
    try:
        with contextlib.ExitStack() as stack:
            if patches:
                patches(stack)
            code, r, client, events, out, err, evidence = case._run(phase, duration=duration, client_kwargs=kwargs)
        c = r['client']
        data = (evidence / tv.guest.CLIENT_PROBE_FILE).read_bytes()
        result = dict(exit=code, result=r['result'], errors=r['errors'],
                      probe=c.get('probe', {}).get('verdict'),
                      reasons=c.get('probe', {}).get('invalid_reasons'),
                      fault_sequence=c.get('fault_sequence'), end_sequence=c.get('hold_sequence_end'),
                      post_exits=c.get('probe', {}).get('post_fault_exit_attempts'),
                      post_markers=c.get('probe', {}).get('post_fault_marker_attempts'),
                      stop_proven=c.get('traffic_stop_proven'), trusted=c.get('probe_snapshot_trusted'),
                      log_read=c.get('probe_log_read'), latch=c.get('probe_leak_observed'),
                      guest_leak=b'"m":false' in client.log, persisted_leak=b'"m":false' in data)
        record(name, result)
        return result
    finally:
        case.doCleanups()

phase('NEW_stop_failure_later_leak', {'stop_fail_at':2, 'stop_suffix':tv.client_leak_suffix})
phase('NEW_same_second_no_post_fault_probes', {'silent_hold':True, 'frozen_clock':True})
phase('NEW_prefault_leak_then_hash_failure', {'leak_only':True, 'digest_fail':True})
# Fail only the final cat; preserve the original successful pre-fault wait.
def final_cat_patch(stack):
    original = rp.stop_client_traffic
    def stop(client):
        stopped = original(client)
        if getattr(client, 'stop_count', 0) >= 2:
            client.cat_exit = 1
        return stopped
    stack.enter_context(mock.patch.object(rp, 'stop_client_traffic', side_effect=stop))
phase('NEW_nonzero_cat_contains_leak', {'stop_suffix':tv.client_leak_suffix}, patches=final_cat_patch)

rid='a'*32
def blob(rows):
    return b''.join(json.dumps(dict(r=rid,s=i+1,**row),separators=(',',':')).encode()+b'\n' for i,row in enumerate(rows))
pair=[dict(t=100,k='exit',ok=True,m=True),dict(t=100,k='marker',ok=True)]
base=dict(run_id=rid,clock_start=99,clock_stop=105,fault_epoch=100,post_fault_epoch=100,fault_sequence=2,end_sequence=2,hold_seconds=5)
for name,rows,changes in [
    ('same_second_exact_old_fixture',pair,{}),
    ('same_second_30s_no_new_sequences',pair,dict(hold_seconds=30)),
    ('unordered_clock_fixture',pair+[dict(t=102,k='exit',ok=False,m=None),dict(t=102,k='marker',ok=False)],dict(fault_epoch=103,post_fault_epoch=100,end_sequence=4)),
    ('same_second_genuinely_new_sequences_positive_control',pair+pair+pair,dict(end_sequence=6,hold_seconds=30)),
]:
    kw=dict(base,**changes)
    r=cp.evaluate_probe_log(blob(rows),**kw)
    record(name, {k:r[k] for k in ('verdict','invalid_reasons','post_fault_exit_attempts','post_fault_marker_attempts')})
```

### hunt.py

```python
# Load only definitions from the companion repro script (do not rerun its cases).
from pathlib import Path
exec(Path('/var/tmp/leaklab-m3r3-gpt/repro.py').read_text().split("phase('NEW_stop_failure_later_leak'")[0])

# Traffic has written three pairs before the fault, then remains silent.
# QGA returns only the first pair on the fault-boundary cat.
def boundary_patch(stack, exitcode=1):
    original_wait = rp.wait_client_probe_control
    original_sequence = rp.read_client_probe_sequence
    def wait(client, run_id, **kw):
        flags = original_wait(client, run_id, **kw)
        client.probe_pair()
        client.probe_pair()
        return flags
    calls = [0]
    def sequence(client, run_id):
        calls[0] += 1
        if calls[0] != 1:
            return original_sequence(client, run_id)
        execute = client.execute
        def partial(program, args=(), **kw):
            if args and args[-1].strip() == f'cat {tv.guest.CLIENT_PROBE_LOG}':
                prefix = b''.join(client.log.splitlines(keepends=True)[:2])
                return tv.ExecResult(exitcode, prefix, b'')
            return execute(program, args, **kw)
        with mock.patch.object(client, 'execute', side_effect=partial):
            result = original_sequence(client, run_id)
        record('fault_boundary_read_details_'+str(exitcode), dict(sequence=result[0], flags=result[1], problem=result[2], actual_last=client.sequence))
        return result
    stack.enter_context(mock.patch.object(rp, 'wait_client_probe_control', side_effect=wait))
    stack.enter_context(mock.patch.object(rp, 'read_client_probe_sequence', side_effect=sequence))

phase('R3_partial_failed_fault_boundary_no_hold_probes', dict(silent_hold=True, frozen_clock=True), patches=lambda s: boundary_patch(s, 1))
phase('R3_partial_success_fault_boundary_no_hold_probes', dict(silent_hold=True, frozen_clock=True), patches=lambda s: boundary_patch(s, 0))
```

### hunt2.py

```python
from pathlib import Path
exec(Path('/var/tmp/leaklab-m3r3-gpt/repro.py').read_text().split("phase('NEW_stop_failure_later_leak'")[0])

def burst_patch(stack):
    original = rp.start_client_traffic
    def start(client, **kw):
        original(client, **kw)
        calls = [0]
        def burst(now):
            calls[0] += 1
            if calls[0] in (4, 8):
                client.probe_pair()
        client.maybe_probe = burst
    stack.enter_context(mock.patch.object(rp, 'start_client_traffic', side_effect=start))
phase('R3_1Hz_early_burst_then_28s_silent', dict(frozen_clock=True), patches=burst_patch)

# End status check occurs only after hold_deadline. Simulate a stalled probe
# loop recovering during that QGA status call, with zero rows in the hold.
def after_hold_patch(stack):
    original = rp.read_client_status
    def status(client):
        if client.traffic_active:
            rp.time.sleep(1.0)
            client.probe_pair()
            rp.time.sleep(1.0)
            client.probe_pair()
        return original(client)
    stack.enter_context(mock.patch.object(rp, 'read_client_status', side_effect=status))
phase('R3_zero_hold_probes_two_pairs_during_end_status', dict(silent_hold=True,frozen_clock=True), patches=after_hold_patch)

```

### controls.py

```python
from pathlib import Path
exec(Path('/var/tmp/leaklab-m3r3-gpt/repro.py').read_text().split("phase('NEW_stop_failure_later_leak'")[0])
phase('R3_stop_reports_success_but_stays_active', dict(stop_lies_at=2))
for at in (1,2):
    def latch_patch(stack, at=at):
        original=rp.read_client_probe_sequence
        calls=[0]
        def sequence(client,run_id):
            calls[0]+=1
            if calls[0]==at:
                client.append_probe('exit',ok=True,m=False)
            return original(client,run_id)
        stack.enter_context(mock.patch.object(rp,'read_client_probe_sequence',side_effect=sequence))
        stack.enter_context(mock.patch.object(rp,'read_client_probe_log_exact',return_value=(None,'probe_log_unreadable')))
    phase('R3_boundary_'+str(at)+'_leak_then_final_read_failure', {}, patches=latch_patch)
```

## Review boundary and final disposition

New code hunt was limited to `git diff 605cce8..37bafc2 -- tools/leak-lab/clientprobe.py tools/leak-lab/vm/run_phase.py`, with surrounding helper context and existing fake harness read only to execute the specified checks. No live network, QEMU, privileged tooling, production state, credentials, archives or keys were used. The required two full suites ran once each; subsequent commands were focused stdlib reproducers. The only repository file written is this report.

**Disposition:** round-2 C1/C2/I1 reproducers fixed; new R3-C1 and R3-C2 remain Critical. Passing unit suites do not establish the missing observation coverage.

Scratch `/var/tmp/leaklab-m3r3-gpt` deleted after all reproducers completed. Final HEAD and workspace preservation checks follow.

Final checks: HEAD remains `37bafc2ba28789834a1df1ecef599bf872c8c7ce`, branch `rust/v2`; ordinary git status remains clean. The completed report is ignored by repository rules (`!!` for this exact path), exists on disk, and contains the reproducers before scratch deletion. No stage/commit/push performed.

Verdict: FAIL
