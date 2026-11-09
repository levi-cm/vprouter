# M3 adversarial re-review (GPT)

Target: rust/v2, 605cce870ab1b5bb7b2332750c2968c6bf2e2199. Offline review only; no runtime/network qualification.

Report created before investigation. Results appended incrementally.

## First completed checks

HEAD is exactly 605cce870ab1b5bb7b2332750c2968c6bf2e2199; initial tracked/untracked status was clean. No relevant historical M3 memory entry was found; findings use current source and supplied reports.

Required suites executed once each, with TMPDIR under review scratch:
- `cd tools/leak-lab && python3 -B -W error -m unittest test_leak_lab`: **320 tests, OK**, 13.275 s.
- `cd tools/leak-lab && python3 -B -W error -m unittest vm.test_vm`: **252 tests, OK**, 12.972 s.

Extracted and executed the earlier report's `scanners.py` and `matrix.py` verbatim. C1 non-Ethernet controls, reversed records with forged timestamps, and both controls in one raw frame now return INVALID. M1 duplicate controls now returns INVALID. All seven intact-marker fixtures still return LEAK. Missing/reordered controls, drops, counts and argv mismatches all return INVALID. All 54 recognized-verdict/error combinations pass; M2 missing side now returns INVALID (LEAK still wins). Router-only `_run_phase_locked` and `scan_evidence` ASTs still match 888f0d4.

Legacy probe fixtures lack the newly mandatory r/s keys and therefore all return INVALID (including legacy m=false/null and malformed-tail examples). This is a schema change, not proof of leak precedence; schema-updated equivalent reproducers follow below. Legacy orchestration scripts also need the renamed pre-fault helper adapted; the exact injected QGA/status conditions will be retained.

## New Critical C1 — Failed traffic stop leaves a leak-bearing tail outside exact evidence

Location: `tools/leak-lab/vm/run_phase.py:3174` (`stop_client_traffic`), `:4232` (stop then collect), `:3253` (collection cache).

Executed fake-QGA reproducer `adversarial.py: NEW_stop_failure_later_leak`: use the normal real start and log stream. Intercept the first `systemctl stop vprlab-client-traffic...` command and return exit 1 without stopping the traffic unit. On the second stop (cleanup), append a well-formed current-run non-Mullvad success, then perform the normal fake stop. Do not change the final size/hash/cat replies or either scanner. **Result: phase PASS, exit 0, errors [], probe PASS, probe_log_read exact; guest log contains m:false, persisted client-probe.jsonl does not.** The real client scanner ran over the harness pcaps.

The stop helper ignores the execute result, and its shell command masks systemctl failures with `|| true; ...; true`. The caller sets traffic_started false and freezes evidence without verifying the unit became inactive. Cleanup can then stop a still-running unit after the snapshot; `probe_collected` prevents a new read. Size+SHA+newline certify only the earlier snapshot.

Suggested fix: stop without hiding failure, verify the unit is inactive/dead before the exact snapshot, and refuse PASS if termination cannot be proved. Preserve readable leaks on this path and only freeze collection once the writer is quiescent. A late cleanup stop must not silently validate an earlier live-writer snapshot.

## New Critical C2 — Same-second pre-fault probes also satisfy the post-fault requirement

Location: `tools/leak-lab/clientprobe.py:278` (before uses t <= fault_epoch), `:302` and `:317` (post uses t >= post_fault_epoch); `tools/leak-lab/vm/run_phase.py:4163`, `:4212` (integer-second clocks).

Executed real evaluator fixture: only two current-run rows, s=1 exit ok/m=true and s=2 marker ok=true, both t=100. Supply clock_start=99, fault_epoch=100, post_fault_epoch=100, clock_stop=105. **Result: PASS, no invalid reasons**, despite no probes after the action. Both rows are counted before the fault and as post-fault attempts. A 5 s tail is below the 10 s gap allowance.

Executed fake-QGA `NEW_same_second_no_post_fault_probes`: normal start produces only its pre-fault pair; subsequent `date +%s` reads remain in the same second; the end-of-hold is-active call returns success without adding probes. Real `stop-router` action and scanners otherwise run unchanged. **Result: phase PASS, exit 0, errors [], probe PASS**, with no added post-fault pair. Zero duration is explicitly supported by the runner. The direct fixture also demonstrates the hole for a positive 5 s observation window.

Additional real evaluator edge: fault_epoch=103, post_fault_epoch=100 with a valid window 99..103 and normal rows at 100/102 also returns **PASS**: the action clock boundaries themselves are never ordered/validated.

Suggested fix: bind post-action attempts to an independently recorded sequence boundary or a guest-written action boundary, and require new exit/marker records after it. If retaining coarse clocks, require strictly later timestamps and wait long enough to obtain them; validate clock_start <= fault_epoch <= post_fault_epoch <= clock_stop. Do not let a single sample satisfy both sides of the action.

## New Important I1 — Already observed/read LEAK still disappears on final read errors

Location: `tools/leak-lab/vm/run_phase.py:4150` (pre-fault leak reduced to an error note), `:3239`/`:3245` (final read discards bytes), `:4480` (combination depends only on final probe report).

Executed `NEW_prefault_leak_then_hash_failure`: real start, replace the stream with a valid current-run m:false success; permit pre-fault stat/cat to read it, then return exit 1/empty output from sha256sum. **Result: INVALID, exit 2, errors include client_real_ip and probe_log_unreadable, final probe INVALID; guest contains leak, persisted log is empty.** Thus an explicitly recognized leak is downgraded by a later quality failure.

Executed `NEW_nonzero_cat_contains_leak`: append a valid current-run m:false line at stop; final cat returns the whole leak-bearing log with exit 1. **Result: INVALID, exit 2, probe_log_unreadable; received leak bytes are discarded.** Size/hash mismatch paths preserve returned bytes, but the nonzero-cat path does not.

Suggested fix: latch every recognized LEAK independently of final collection quality and feed it into combination; retain bounded stdout for tolerant leak parsing even when cat exits nonzero. Read-quality problems remain INVALID evidence quality and must never overwrite LEAK.
