# Task 14: offline performance preparation

Status: REVIEW ROUND 6 IMPLEMENTED / OFFLINE GREEN / PARTIAL pending independent re-review / OFFLINE_PREPARATION_ONLY. Final results are in Review round 6 below; earlier sections retain their historical evidence, including superseded round-5 claims where explicitly noted. No performance claim; real runs NOT_RUN; release_ready=false.

## Binding inputs and design

Read the full task brief, IMPLEMENTATION.md (work package 11), performance-measurement.md, baseline.md and three baseline JSONs. Historical resource samples cover about 20 seconds of uncontrolled traffic and exclude runtime/kernel/observer overhead; the comparison microbenchmark is a standalone function test. Neither is a controlled baseline. The historical resource inventory is not current credential authority: this task has no real credentials and Task 8c runtime/ARM/client acceptance remains OPEN.

Use Python standard library under existing `tools/performance/`, matching the existing performance and release_engineering tooling. No Rust edits or dependency/build cost. Add a pure accounting model with explicit bounded schema, strict native-text parsers, deterministic statistics/comparison, and separate bounded I/O/loopback adapters. Existing raw collector/monitoring validator remain unchanged; the new schema needs a reviewed guest producer before runtime use. No runtime optimization is justified without measurements.

## Files (initial plan; final inventory below)

- tools/performance/accounting.py: pure native parsers, run schema/accounting, statistics, comparison.
- tools/performance/offline.py: bounded JSON CLI and exclusive atomic publication.
- tools/performance/loopback.py: bounded localhost harness self-test only.
- tools/performance/test_accounting.py and test_offline.py: synthetic behavioral regressions.
- tools/performance/fixtures/: explicitly synthetic input.
- docs/rust-v2/performance-harness.md: schema, statistics, workload and owned-guest runner specifications; NOT_RUN commands/prerequisites.
- docs/rust-v2/performance-measurement.md: link and distinguish this preparation layer.

## Test evidence

Initial checkpoint: behavioral REDs were pending before production implementation; actual results follow. Commands use `python3 -B -I`. Tests only create temporary local files and ephemeral loopback sockets. Every real benchmark and runtime gate remains NOT_RUN.

## Threshold-boundary table

Initial checkpoint: planned exact/inside/outside cases for CPU 50%, memory 100%, control PSS 16/48 MiB, throughput 95%, latency 105%, and zero lifecycle events. No six-exit control PSS target is invented.

## NOT_RUN / open risks

Repeated 600s measured Python/Rust steady/load 1/5/6-exit runs; actual supervision CPU, total memory, PSS, traffic, latency, monitoring/restart/OOM acceptance; Task 8c runtime/ARM/client tests; owned guest qualification; migration/canary/24h soak; credentials and reviewed real workload/producer are absent. Native counters/coverage declarations alone cannot establish causal attribution or authenticate a producer. Existing uncontrolled baselines cannot be promoted.

## Final validation (initial checkpoint)

Initial validation was pending at report creation. Final measured results are recorded below. No claim that any product performance threshold is met.

### RED 1 (before accounting implementation)

`python3 -B -I -m unittest discover -s tools/performance -p test_accounting.py -v` -> exit 1, 9 methods / 30 assertion failures (including subtests), no import errors. Missing strict parser/statistics/accounting/gate APIs failed explicit behavioral preconditions. Full local log: `/tmp/task14-red-1.log`. RED cases cover invalid native units/duplicate keys/overflow/wrap, missing fields, timestamps/gaps/resets, contamination, disjoint accounting, warmup and every numeric threshold boundary.

### RED 2 / accounting GREEN

After implementing parsers/statistics/accounting/gates, first pass found two fixture mutations violated additional bracket/CPU-consistency invariants before their intended regression check. Corrected the synthetic mutation to keep those independent fields valid. Added suite-comparison REDs: `python3 -B -I -m unittest discover -s tools/performance -p test_accounting.py -v` -> exit 1, 12 methods / 14 expected assertion failures for missing suite comparator; previous accounting/parser/statistic/threshold cases passed. Logs `/tmp/task14-red-2.log`, `/tmp/task14-green-1.log` retained locally.

### GREEN 2 / RED 3 / GREEN 3

Accounting suite after comparator: exit 0, 12 methods, 12.067s (`/tmp/task14-green-2.log`).
Atomic CLI and loopback behavioral REDs: first run exit 1 (four failures and a missing-CLI output-file error); added the same explicit missing-API precondition as other REDs, then exit 1 / five expected assertion failures, no errors (`/tmp/task14-red-3.log`). Implemented adapters: exit 0 / five methods / 0.136s (`/tmp/task14-green-3.log`). Real temp files exercise fsync ordering, no-overwrite rename, concurrent publishers, symlink refusal and write-failure cleanup. Local TCP/UDP/DNS-like self-test uses literal loopback addresses, ephemeral ports, fixed protocol content, socket timeouts, at most 20 iterations and a 2s checked deadline; no external sockets/resolver/services.

### Additional completeness REDs

Before finalization, add cgroup member-list cross-checking (so a missing process cannot reduce PSS), instrumentation binding, per-process tick/wakeup/thread/fd/USS reporting and OOM retention across discarded warm-up. Expanded synthetic schema fixtures intentionally fail until these checks/reporting are implemented. No existing runtime/collector code is changed.

### GREEN 4

Expanded accounting suite: `python3 -B -I -m unittest discover -s tools/performance -p test_accounting.py -v` -> exit 0, 17 methods / 17.269s (`/tmp/task14-green-4.log`). The preceding schema-extension RED exited 1 (33 failures, five downstream KeyErrors from intentionally incompatible fixtures; `/tmp/task14-red-4.log`). The new behavior cross-checks cgroup member PIDs against every process snapshot, suppresses control PSS if coverage is incomplete, pins instrumentation across the suite, reports per-process overhead, and preserves cgroup OOM events from warm-up. Additional positive and negative integration tests exercise original source-specific Python/Rust monitoring validators with in-memory synthetic receipts; those receipts are never exported as real evidence.

## Implementation inventory / current evidence

Added `accounting.py`, `offline.py`, `loopback.py`, `test_accounting.py`, `test_offline.py`, `run-schema.json`, `fixtures/synthetic-short-run.json`, and `docs/rust-v2/performance-harness.md`; appended the explicit preparation link/policy distinction to `performance-measurement.md`. The new structural JSON schema accompanies normative Python semantic validation. No Rust, collector, analyzer, runtime, service, baseline JSON or acceptance ledger edits.

The comparator requires all steady/load 1/5/6 cases, six matched IDs each (72 real runs), strict same-host/environment/config/workload/Tailscale/instrumentation/accounting binding, sequential windows and complete original runtime evidence. It conservatively compares worst candidate to best baseline and retains all outliers. Repetition median confidence intervals use exact distribution-free binomial order statistics; n<6 has no finite 95% interval. Percentiles are nearest rank, no interpolation. Unknown/invalid measurements or contamination take precedence as INSUFFICIENT_DATA, while independently failing gates remain visible. No new six-exit PSS target. Existing legacy direct-mode limitations remain blocking.

### Threshold-boundary table (arithmetic fixture results)

| Gate | Exactly at | Just inside | Just outside | Missing/invalid |
| --- | --- | --- | --- | --- |
| CPU baseline 100 | 50 PASS | 49 PASS | 51 FAIL | INSUFFICIENT_DATA |
| Total memory baseline 1000 | 1000 PASS | 999 PASS | 1001 FAIL | INSUFFICIENT_DATA |
| One-exit control PSS (raw record) | 16777216 PASS | -1 KiB PASS | +1 KiB FAIL | INSUFFICIENT_DATA |
| Five-exit control PSS (raw record) | 50331648 PASS | -1 KiB PASS | +1 KiB FAIL | INSUFFICIENT_DATA |
| Throughput baseline 1000 | 950 PASS | 951 PASS | 949 FAIL | INSUFFICIENT_DATA |
| p95 latency baseline 1000 | 1050 PASS | 1049 PASS | 1051 FAIL | INSUFFICIENT_DATA |
| Monitor misses, unexpected restarts, OOM, either side | 0 PASS | negative invalid | 1 FAIL | INSUFFICIENT_DATA |

These are synthetic arithmetic expectations, not measured product results. The
raw-record control-PSS boundary is a 1 KiB quantum because `smaps_rollup`
prints integer kB; the direct metric API retains the abstract ±1 B boundaries.
Conservative CPU read brackets can make a nominal counter ratio at 50% fail to
demonstrate the bound; no uncertainty is rounded away.

### Integration checks

`python3 -B -I -m unittest discover -s tools/performance -p test_accounting.py -v` -> exit 0, 20 methods / 25.117s (`/tmp/task14-integration.log`). Positive fake Python/Rust original-monitor records both integrate; deleting each required runtime evidence class is insufficient. A complete one-exit scenario can pass in an in-memory synthetic test, while a 10% latency regression fails that scenario and absent suite shapes keep the suite insufficient. Exported fixtures remain explicitly synthetic.

### Mutation and strictness evidence

`python3 -B -I -m unittest discover -s tools/performance -p test_accounting_mutations.py -v` -> exit 0, two methods / 0.582s. In-memory AST mutants (product files never changed) remove each of 17 comparator insufficiency reason guards and change each numeric threshold in both directions / make inclusive comparisons exclusive (12 numeric mutants). Boundary/reason corpora distinguish all 29 mutants from the correct implementation.

Initial complete performance suite before mutation/last strictness additions: exit 0, 109 methods / 26.037s (`/tmp/task14-all-tests.log`). Final strictness RED: two expected assertion failures, exit 1 (`/tmp/task14-red-5.log`), for unknown host labels and aggregate overflow. Added aggregate u64 checks, unknown-label refusal, native stopped/terminal-process refusal and smaps address-range validation. Focused GREEN: exit 0, two methods / 0.540s (`/tmp/task14-green-5.log`). Missing process aggregate measurements remain null, not zero.


## Final validation

All results below are fresh on the final implementation (2026-11-06):

| Check / command | Real result |
| --- | --- |
| `python3 -B -I -m unittest discover -s tools/performance -p 'test_*.py' -v` | Exit 0; **113 tests** / 28.193s; includes all 84 existing tests plus 29 new methods, table-driven negative cases and 29 in-memory comparator mutants. |
| AST + `py_compile.compile(..., doraise=True)` under `python3 -B -I` | Exit 0; all 10 `tools/performance/*.py`; compilation output confined to a TemporaryDirectory, no repo bytecode. |
| Strict JSON decode under `python3 -B -I` | Exit 0; run-schema.json, synthetic-short-run.json, the three required baseline/inventory JSONs and acceptance.json (six files). Structural required-key/schema-object closure check passed. No third-party JSON Schema validator was installed or run; semantic Python validator is normative. |
| Synthetic fixture semantic validation | Exit 0 in assertion script; `INSUFFICIENT_DATA` with exactly synthetic_evidence, short_run and missing_runtime_evidence; fake measured span 2s. |
| `python3 -B -I tools/performance/loopback.py --iterations 3` | Exit 0; SELF_TEST_PASS, exactly three TCP/UDP/DNS-like local exchanges each; performance_evidence=false, release_ready=false. |
| `git diff --check` | Exit 0. New files separately checked for trailing whitespace in the final inventory check. |
| `git diff --cached --quiet` / HEAD | Exit 0, no staged changes; HEAD still cb91c79855fb1482e61f3becef6f8b71495e049e. No commit/push. |
| Acceptance identity | SHA256 **3d467451dd03d1663e3c79b24eea6a18aac461f9291f8fdfe1031e1da6e86e97** unchanged from initial read; release_ready=false. |
| Rust fmt/clippy/workspace tests | NOT_RUN / NOT_APPLICABLE: no Rust, Cargo manifests or lockfile touched. |

Durable local logs: `.superpowers/sdd/rust-v2/task-14-evidence/` contains RED,
intermediate GREEN, integration, mutation and final test logs plus SHA256SUMS.
This report/evidence directory is ignored by the repository's pre-existing
`/.superpowers/` rule; it exists on disk and was not staged. The implementation
and docs are visible as one tracked modification plus nine new files. Tests
create temporary filesystem fixtures and ephemeral literal-loopback sockets only.
No actual service/resource sampling, credentials, network outside loopback, sudo,
VM operations, long benchmark, service stop/restart, namespace or privilege use.

## Remaining risks / NOT_RUN (final)

- Fresh controlled Python and Rust baseline/candidate runs are absent; **all
  product thresholds remain NOT_RUN**, with no performance improvement claim.
- The owned-guest runner and real-client workload/measurement producer are
  specifications only. Exact proposed commands and prerequisite refusal rules
  are in performance-harness.md. Current executable collector format is not
  silently accepted as the new schema; a reviewed producer is required.
- Task 8c runtime/ARM/client acceptance remains OPEN; guest qualification,
  credentials, true independent profiles/approvals, reviewed workload/captures,
  migration/canary/release integration and 24h mixed soak are NOT_RUN.
- Six-exit Python legacy direct baseline/monitor is unsupported by the existing
  source-specific validator; a genuine independently reviewed baseline is needed.
  Five-copy legacy isolation/overhead also needs independent review.
- cgroup coverage, kernel attribution, native identity brackets, process
  classification and immutable evidence provenance depend on the future reviewed
  producer/operator; hashes and self-declarations cannot authenticate them.
  Unmeasurable thermal/swap/kernel/observer startup-tail costs block completeness.
- Memory peaks are sampled, not guaranteed transient maxima; exec/membership ABA
  and snapshot churn require raw evidence review. No counter gaps are repaired.
- Six repetitions permit a finite distribution-free median CI, but do not prove
  independence or power. No significance claim or automatic outlier exclusion.
- Independent implementation review is NOT_RUN by this delegate: no subagents
  were started, as instructed. Parent review remains a separate process gate.

Task 14 preparation deliverables are implemented and offline-validated; actual
performance/runtime/client/release acceptance is not delivered or claimed.

## Review round 1

Status: IN_PROGRESS (2026-11-06). Independent review read in full; I1/I2/I3/M1/M2 reproduced scenarios are binding regressions. Original verdict above is superseded by that FAIL until this round is validated. Base/branch and initial task-only dirty inventory verified; review file is read-only. No delegates, network, sudo, VM, Rust or Git writes authorized.

Class closure before implementation:

1. Raw counter rates, duration bounds, gate ratios, order selection, medians/MAD and outlier comparisons use integers/Fractions end to end. Exact rational JSON output is explicit; legacy floating rate projections cannot drive verdicts. Sweep every WP11 gate at equality and +/-1 raw unit, ordinary and 2**53+1/2**63/2**64 scales (u64 overflow must refuse).
2. Preserve full-run events from every declared domain, including observer/workload and discarded warm-up. Add explicit per-domain/kernel signals where schema 1 lacked a representation. Missing event evidence must refuse; enumerate domains x signals.
3. Check redundant CPU tick/cgroup/time-capacity, charged memory/member/system, I/O/member/cgroup, and PID/thread counts. Where meanings differ, require explicit residual accounting, with no invented equality between RSS/PSS and cgroup charges. Document tick/skew tolerance and unsupported producer requirements.
4. Mutate every distinct nested schema position (including both inherited monitoring variants): type/range/absence/duplicates/nonfinite/huge. Exercise the actual CLI adapter and publication boundary; malformed inputs must redact, return nonzero and leave no output file.
5. Integer statistics use exact medians and deviations, including huge constants, one-unit spreads and explicit MAD=0 behavior.

RED/GREEN evidence and validation pending. Checkpoints will be appended incrementally; all actual benchmark/runtime/release gates remain NOT_RUN.

### Review round 1 RED checkpoint

`python3 -B -I -m unittest discover -s tools/performance -p test_accounting.py -k ReviewRoundOne -v` -> **exit 1**, five methods, 13 assertion failures and one reproduced uncaught AttributeError (M1), 1.017s. Raw six-repetition tests reproduce both wrong throughput directions and CPU equality; raw observer/workload OOM tests reproduce dropping both oom/oom_kill; stable member ticks contradicting zero cgroup still PASS; exact huge median/spread tests fail. Log: `task-14-evidence/review-round1-red.log`. No production fix preceded these REDs.

### Review round 1 intermediate GREEN

Class REDs: accounting `-k ReviewClassClosure -v` -> exit 1 / three assertion failures (new exact unit API and missing reconciliation/failure evidence contract); offline `-k ReviewFailureProtocol -v` -> exit 1 / two assertion failures, including actual malformed legacy CLI exit 1 instead of redacted exit 2. Logs `review-round1-class-red.log`, `review-round1-cli-red.log`.

After fixes, `python3 -B -I -m unittest discover -s tools/performance -p test_accounting.py -k Review -v` -> **exit 0**, eight methods / 3.365s (`review-round1-intermediate.log`). Includes 176 threshold cases; required component+kernel signal matrix; both-direction reconciliation and tick tolerance tests. Whole-schema mutation expansion and original-suite regression checks still pending.

Contract change: this uncommitted draft schema 1 now requires full-run per-component+kernel failure counts, aligned per-process block I/O, cgroup pids.current, measured exited CPU/other I/O/memory residuals, and host busy ticks/outside CPU. Missing new fields refuses old incomplete records. No residual is inferred from the mismatch. Actual producer remains SPEC ONLY / NOT_RUN. Schema/docs/fixture synchronization pending at this checkpoint.

### Review round 1 class sweep / reconciliation checkpoint

`python3 -B -I -m unittest discover -s tools/performance -p test_accounting.py -v` -> exit 0, **30 methods**, 44.797s (`review-round1-accounting.log`); comparator mutation file -> exit 0, two methods / 0.847s (`review-round1-mutants.log`). This checkpoint preceded four added pair/sweep methods.

Additional behavioral RED: `-k ReviewAdditionalPairs -v` -> exit 1 / two memory-breakdown failures, four methods / 6.030s (`review-round1-pairs-red.log`). Refining the CPU split test to preserve all other fields exposed two more real deficit failures; `-k test_native_cpu_parts -v` -> exit 1 / four failures, 0.122s (`review-round1-parts-red.log`). Fixed symmetric native CPU component tolerance and required independent memory.stat residual. `-k ReviewAdditionalPairs -v` -> exit 0 / four methods / 6.108s (`review-round1-pairs-green.log`). Includes **120 raw-record cases** before exact gate comparison, both-direction I/O with nonzero original counters, exited CPU residual, and exact rational JSON serialization; large scales are constructed arithmetic inputs, not claimed workloads. Exact gate helper sweep adds 176 cases. For integer ratios, raw equality uses the nearest lower multiple of 20; odd-scale rational equalities are separately exercised directly. Raw u64 overflow refuses, never PASS.

CLI corpus initially used full-sized receipts; interrupted the owned test process with TERM (exit 143) after an unchanged nullable-field mutation created a valid file and caused cascading fixture failures. No product failure was inferred from that flawed test. Retained `review-round1-offline.log`. Corrected the corpus to skip unchanged values, isolate cleanup, and use a compact original-monitor window. Full accounting qualification tests remain 600 synthetic seconds. `test_offline.py -v` then exit 0 / seven methods / 7.858s, **4695** failure-protocol cases (`review-round1-offline-compact.log`). Numeric same-value type cases and semantic-rejection assertions are being expanded; final validation pending. This is bounded deterministic schema mutation, not a claim of exhaustive input-space fuzz proof.

### Review round 1 semantic mutation RED / fixes

Adding semantic-rejection assertions (so short_run cannot mask malformed-field acceptance) exposed **16** equal-value numeric-type aliases in inherited equality-only binding/window/contract checks: `python3 -B -I -m unittest discover -s tools/performance -p test_offline.py -k test_whole_nested -v` -> exit 1 / 14.455s (`review-round1-semantic-fuzz-red.log`). Fixed with bounded exact-integer evidence-tree validation before source-specific replay. A subsequent corpus run had one remaining assertion from deleting an optional surplus pre-window receipt, which legitimately preserves coverage; not a product bug. The branch corpus similarly found four legal surplus-observation deletions. Restricted absence mutation to schema fields (all required fields still covered); actual sample/coverage gaps remain separately tested. Unchanged nullable values are not invalid mutations. Logs retained, not relabeled as product REDs.

The final corpus includes distinct conditional shapes for both original monitoring implementations: normal, triggered (Rust), abort before/after delay, blocked health/watchdog/legacy-host paths; nonzero per-device I/O and optional discard counters; exact nested duplicate-key injection; numeric aliases, wrong types, nulls, negative ranges, huge integers, NaN, and required-field absence. Each well-formed malformed mutation must add a semantic refusal reason beyond short_run, then exercise the real file/CLI main/publication path for redacted stdout, empty stderr, exit 2, no result/temp file. A separate actual subprocess checks the reviewer's null legacy router case. Final counts/results pending.

### Review round 1 final RED/GREEN and validation

Final arithmetic representation edge: a u64 byte count over `600000000001` ns
has an exact bytes/s numerator larger than u64 after unit conversion. Requiring
that derived input numerator to fit u64 was unnecessarily restrictive. A
behavioral test using the raw `{bytes,duration_ns}` rate representation first
failed: `python3 -B -I -m unittest discover -s tools/performance -p test_accounting.py -k ReviewDerivedNumerators -v`
-> exit 1 / one expected assertion / 0.034s (`review-round1-derived-red.log`).
Implemented exact raw-unit projections without widening any raw counter bound;
same command -> exit 0 / one method / 0.047s (`review-round1-derived-green.log`).
One-byte corruption of that projection refuses. Final fuzz includes integer,
numerator/denominator and raw bytes/duration projection shapes.

All following results are fresh after the final Python changes:

| Required validation | Result / log under task-14-evidence/ |
| --- | --- |
| `python3 -B -I -m unittest discover -s tools/performance -p test_accounting.py` | **exit 0**, **36 methods**, 51.794s; `review-round1-verified-accounting.log`. Original tests plus five direct review regressions, exact units/helper + raw sweeps, all-role failures, reconciliation, rational serialization and duration uncertainty. |
| `python3 -B -I -m unittest discover -s tools/performance -p test_accounting_mutations.py` | **exit 0**, **2 methods**, 0.818s; `review-round1-verified-mutants.log`. All existing 29 comparator mutants remain distinguished. |
| `python3 -B -I -m unittest discover -s tools/performance -p test_offline.py` | **exit 0**, **7 methods**, 21.625s; `review-round1-verified-offline.log`; **7652** bounded whole-schema mutation cases, semantic refusal beyond short_run plus redacted CLI/no-publication checks. Includes real subprocess M1 and existing atomic publication/local loopback checks. |
| `python3 -B -I /tmp/task14-round1-validate.py` | **exit 0**; `review-round1-static.log`. AST all **10** performance Python files; strict JSON all **6** files (schema, synthetic fixture, three baseline/source JSONs, acceptance); closed required object fields, valid schema refs, schema/fixture field agreement; no bytecode writes. No third-party JSON Schema validator was installed/run; Python semantics remain normative. |
| Synthetic fixture semantic check | **exit 0** in static script; exactly missing_runtime_evidence, short_run, synthetic_evidence. No benchmark/qualification inference. |
| `git diff --check`; `git diff --cached --quiet`; branch/HEAD/acceptance checks | **exit 0** in static script. Index empty; branch rust/v2; HEAD cb91c79855fb1482e61f3becef6f8b71495e049e. Acceptance byte-identical to HEAD, SHA256 3d467451dd03d1663e3c79b24eea6a18aac461f9291f8fdfe1031e1da6e86e97; release_ready=false. Review file SHA256 5537c2c4dc79f1250785da49322e5addebffa0aaf88bb63f91ebed6441e7212c; never edited. |

Round 1 touched only accounting.py, offline.py, test_accounting.py,
test_offline.py, run-schema.json, fixtures/synthetic-short-run.json,
performance-harness.md, the existing Task 14 appendix in performance-measurement.md,
and this ignored report/evidence directory. Other initial Task 14 files and all
unrelated work are preserved. No Rust, original measurement/collector code,
acceptance, review, Git index/commits/remotes, services or VMs changed. The only
socket activity is the existing bounded literal-loopback test required by
`test_offline.py`; no external network or resolver use was performed.

### Review round 1 disposition / open risks

I1/I2/I3/M1/M2 are fixed against the reproduced cases and the expanded classes.
This is the implementation delegate's offline result, **not an independent
re-review verdict**. No delegate was started. The reviewer's original scratch
scripts remain unmodified; their prior raw schema/float projections no longer
meet the revised mandatory evidence contract. Equivalent raw scenarios are
retained in the repository tests, with explicit new accounting sources; no claim
that the old scratch scripts pass unchanged or constitute a fresh review.

The draft schema change is intentionally incompatible with earlier incomplete
records and legacy floating traffic projections. A future reviewed producer must
supply original full-run per-role/kernel failure coverage; normalized private
charge ownership; aligned per-device block I/O, pids.current and memory residuals;
transient/exited CPU and outside-host CPU residuals. Residual declarations and
hashes cannot authenticate evidence or establish alignment. Missing or impossible
acquisition must remain unavailable, not zero. Memory/I/O/PID skew has no assumed
rate bound: discrepancies refuse, potentially rejecting legitimate unsynchronized
observations. CPU tolerances are consistency bounds, never threshold epsilons.
Sampled memory peaks, transient/ABA provenance, platform counter semantics,
independence/power, original traffic/source receipts and six-exit Python direct
support still require independent producer/runtime review.

Fresh controlled Python/Rust 600s benchmarks, guest/client/ARM acceptance,
credentials/workload/producer qualification, migration/canary/24h soak and release
integration remain **NOT_RUN / OPEN**. No actual performance threshold or release
acceptance is delivered or claimed. Round 1 implementation and requested offline
validation are complete; parent independent review remains the next gate.

## Review round 2 — implementation complete (offline validation only)

Read task-14-rereview.md and task-14-review.md in full. Baseline rust/v2 at
cb91c79855fb1482e61f3becef6f8b71495e049e; original dirty Task 14 inventory retained.
Review hashes: first 5537c2c4dc79f1250785da49322e5addebffa0aaf88bb63f91ebed6441e7212c;
second b18eba608ba95fba0342f97da8c2bdfc679b2a9f0aaeaecfe35639e46dd6683e.
No subagents, Rust, sudo, VM, external network, Git staging/commit/push authorized.

First behavioural RED: `python3 -B -I -m unittest discover -s tools/performance -p test_accounting.py -k ReviewRoundTwo -v`
returned unittest exit 1, 3 methods / 4 assertion failures (0.255s): accumulated
one-tick/sec member CPU, IRQ and softirq individually beyond host busy, and
aggregate PSS beyond RAM each incorrectly returned PASS. Log:
`task-14-evidence/review-round2-findings-red.log`. No enforcement changed before
these REDs. Registry/property/whole-window extensions and validation pending.

Round 2 incremental GREEN: the same ReviewRoundTwo command now returns exit 0,
3 methods, 0.455s; log `review-round2-findings-green.log`. Decimal decoder RED
(`test_offline.py -k decimal_tokens -v`) returned unittest exit 1 / four expected
assertions, 0.011s, before replacing floating JSON decoding with immediate decimal
rejection. Registry completeness/raw signed-boundary tests were RED before the
registry existed (2 expected missing-registry assertions). Initial registry run
identified a test tolerance setup error (240001 us versus the documented 480000 us
host allowance); corrected the test boundary, retained original progress log.
Full property tests, final GREEN and schema/docs/static verification pending.

Round 2 progress: signed raw registry boundary suite GREEN (1 method, 6.047s,
`review-round2-boundary-progress.log`); every initial 35-family case exercised at
+/-1 beyond a boundary and large excursions on both operands/directions. The
registry subsequently expanded to 40 families to include numeric domains,
clock consistency, coverage, availability and failure evidence. Aggregate host
task-ceiling RED: one method, exit 1, 0.049s (`review-round2-tasks-red.log`), then
added sum-of-threads enforcement. Expanded completeness RED: one method, exit 1,
missing the five new registry families (`review-round2-coverage-red.log`).
Initial numeric property run GREEN: 6,108 signed boundary probes across all
numeric schema positions / both adapters, 4,626 registered/numeric violations,
272.082s (`review-round2-property-progress.log`). This was against the earlier
35-family snapshot; final 40-family full three-file validation is running.

Intermediate broad runs retained as progress evidence, not final GREENs:
old arithmetic fixtures had huge CPU-count-derived idle counters beyond u64,
unbound huge payloads, stale exited-user/host CPU splits, and a 10s short fixture
whose payload exceeded its newly required network evidence. Updated only those
synthetic producer inputs (including serialization headroom for integer byte
counter increments). No physical rule was weakened to retain an impossible PASS.
The JSON decoder now refuses all decimal/exponent tokens before float conversion.

### Review round 2 invariant registry (44 final families)

This is the normative code-data table from `INVARIANT_REGISTRY` in
`tools/performance/accounting.py`. Each family expands over every applicable
sample/process/domain/device/CPU category and adjacent AND original/measured
anchored endpoints. `check_invariants` consumes `physical_constraints`; existing
`_summarize`, `validate_domain_sample`, parsers and `check_reconciliation` retain
structural/native validation. Contradictions produce **INSUFFICIENT_DATA**;
malformed structure/range encountered before the named check produces the fixed
`invalid_run` reason (CLI redacts it as `invalid_input_or_publication`). No reason
suppression can promote insufficient evidence into a measured PASS.

All rows bind to `PhysicalRegistryTests.test_raw_signed_boundary_mutations` and
its independently maintained `physical_cases` case of the same ID. Each is
exercised with smallest representable violations (one byte/tick/us/task/counter
unit beyond the relevant bound) and large excursions (`2**40`) in both signs or
on both inequality operands. Availability has no numeric distance: one missing
FD/wakeup measurement and a large set of missing measurements exercise both
coverage directions. Coverage tests omit a member or add an undeclared member.
The completeness test resolves the function and test, checks an independent
expected ID set, and requires live constraint rows; signed raw tests require the
named predicate to break, so another refusal cannot mask its omission. The
consumer mutation test changes each registry reason and verifies that live
verdict enforcement consumes it.

| ID / mutation case | Physical/accounting invariant | Enforced by | INSUFFICIENT_DATA reason |
| --- | --- | --- | --- |
| `cpu_members` | abs(domain usage - stable ticks - exited CPU) <= endpoint tolerance | `check_invariants` | `cpu_accounting_contradiction` |
| `cpu_user` | member user ticks <= domain user; sum domain user <= host user, endpoint tolerance | `check_invariants` | `cpu_component_contradiction` |
| `cpu_system` | member system ticks <= domain system; sum domain system <= host system, endpoint tolerance | `check_invariants` | `cpu_component_contradiction` |
| `cpu_parts` | abs(user+system-usage) <= 2 us at snapshot, <=4 us across endpoints | `check_invariants` | `cpu_inconsistent` |
| `cpu_exited` | exited user+system = exited usage | `check_invariants` | `cpu_exited_contradiction` |
| `cpu_busy_parts` | host user+system+irq+softirq+steal = busy | `check_invariants` | `cpu_breakdown_contradiction` |
| `cpu_irq_subset` | irq+softirq <= busy (same atomic host read) | `check_invariants` | `cpu_subset_contradiction` |
| `cpu_host_charge` | abs(host busy - disjoint domain CPU - outside CPU) <= endpoint tolerance | `check_invariants` | `system_cpu_contradiction` |
| `cpu_capacity` | busy+idle <= elapsed*ncpu + endpoint tick allowance | `check_invariants` | `cpu_time_contradiction` |
| `domain_capacity` | domain usage <= elapsed*ncpu | `check_invariants` | `cpu_time_contradiction` |
| `pss_ram` | sum process PSS <= MemTotal | `check_invariants` | `system_memory_contradiction` |
| `uss_ram` | sum process USS <= MemTotal | `check_invariants` | `system_memory_contradiction` |
| `rss_ram` | each process RSS <= MemTotal (never sum RSS) | `check_invariants` | `system_memory_contradiction` |
| `uss_pss` | 0 <= USS <= PSS | `check_invariants` | `process_memory_inconsistent` |
| `pss_rss` | 0 <= PSS <= RSS | `check_invariants` | `process_memory_inconsistent` |
| `memory_charge` | sum member USS + nonnegative charge residual = memory.current | `check_invariants` | `memory_accounting_contradiction` |
| `memory_parts` | anon+file+kernel+other = memory.current | `check_invariants` | `memory_breakdown_contradiction` |
| `memory_sock` | sock <= memory.current | `check_invariants` | `memory_breakdown_contradiction` |
| `charges_ram` | sum disjoint memory.current <= MemTotal | `check_invariants` | `system_memory_contradiction` |
| `swap_order` | 0 <= process SwapPss <= Swap | `check_invariants` | `swap_accounting_contradiction` |
| `swap_ram` | 0 <= host swap used <= swap total | `check_invariants` | `swap_accounting_contradiction` |
| `swap_pss` | sum process SwapPss <= host swap used | `check_invariants` | `swap_accounting_contradiction` |
| `swap_charge` | sum disjoint cgroup swap.current <= host swap used | `check_invariants` | `swap_accounting_contradiction` |
| `pids_threads` | sum member threads = pids.current | `check_invariants` | `pids_accounting_contradiction` |
| `pid_bound` | 1 <= PID <= pid_max | `check_invariants` | `pids_accounting_contradiction` |
| `fds_bound` | 0 <= each FD entry count <= max_fd_entries | `check_invariants` | `fd_accounting_contradiction` |
| `threads_bound` | 1 <= threads <= pid_max | `check_invariants` | `pids_accounting_contradiction` |
| `io_conservation` | per-device completed IO = member IO + original residual | `check_invariants` | `io_accounting_contradiction` |
| `counter_monotonic` | all CPU, IO, event counters nondecreasing with fixed keys/identities | `check_invariants` | `counter_regression` |
| `wakeups_monotonic` | wakeups nonnegative, nondecreasing for stable identity | `check_invariants` | `counter_regression` |
| `network_monotonic` | physical link RX/TX bytes nondecreasing | `check_invariants` | `counter_regression` |
| `network_capacity` | each direction bytes*8 <= bps*elapsed (full duplex) | `check_invariants` | `network_capacity_contradiction` |
| `network_payload` | delivered payload <= physical link RX+TX bytes | `check_invariants` | `network_payload_contradiction` |
| `swap_quiet` | no swap usage, swap-in or swap-out anywhere in run | `check_invariants` | `swap_contamination` |
| `thermal_quiet` | temperature < limit; no thermal throttle events | `check_invariants` | `thermal_contamination` |
| `numeric_domain` | every numeric leaf is an unsigned u64 integer; semantic minima also validated | `check_invariants` | `invalid_run` |
| `sample_clock` | ordered nonoverlapping brackets, cadence, duration and boottime/wall coherence | `check_invariants` | `clock_accounting_contradiction` |
| `coverage` | stable identities; complete disjoint domains, membership and component coverage | `check_invariants` | `incomplete_process_coverage` |
| `metric_availability` | all mandatory physical measurements available, never zero-filled | `check_invariants` | `missing_metric` |
| `failure_quiet` | no measured failure in any role, domain, traffic or warm-up | `check_invariants` | `measured_domain_failure` |
| `process_start` | process start tick <= current boot-clock tick | `check_invariants` | `process_lifetime_contradiction` |
| `process_lifetime_cpu` | process cumulative CPU <= lifetime*ncpu + 2*ncpu ticks | `check_invariants` | `process_lifetime_contradiction` |
| `host_boot_cpu` | host cumulative busy+idle <= boot elapsed*ncpu + 16*ncpu ticks | `check_invariants` | `cpu_time_contradiction` |
| `domain_boot_cpu` | cgroup cumulative CPU <= boot elapsed*ncpu | `check_invariants` | `cpu_time_contradiction` |

No process IRQ/softirq/steal/idle attribution is fabricated: those are host CPU
categories. The recorded host category sum is busy exactly; IRQ+softirq is a busy
subset; domain/user/system components and stable member deltas reconcile; all
busy+idle CPU is bounded by elapsed host capacity. RSS is duplicated across shared
mappings and must not be summed against RAM; PSS/USS must. Cgroup ownership is not
PSS: only private USS plus original charge residual equals memory.current under
the required isolated private-charge policy. SwapPss is proportional while raw
Swap can duplicate shared swapped pages. FD entries can share file descriptions,
so file-nr is not a valid sum-of-FD bound. Thread/FD gauges may fall; wakeups have
no universal rate ceiling, only availability, u64 and stable-identity monotonicity.
No unmeasured physical maximum for wakeups or block I/O is invented.

### Review round 2 endpoint tolerance derivation

Let `H` be tick_hz, `C` logical CPUs, `N` stable members, `w0,w1` endpoint read
widths in ns and `E = last.read_end_ns - first.mono_ns`.
Process cumulative user/system ticks are truncated; each endpoint error lies in
one tick interval. The difference of endpoint errors is <1 tick/field, hence
<2 ticks/member for user+system. The member/domain tolerance in microseconds is
`2*N*10**6/H + (w0+w1)*C/1000`. Original exited CPU (including user/system split)
is added to observed member deltas, never inferred from discrepancy.

For host busy use conservative symmetric one-tick endpoint error for each of
six categories (user/nice/system/irq/softirq/steal): two endpoints times six
categories times C gives `12*C` ticks. Host busy/domain tolerance in us is
`12*C*10**6/H + (w0+w1)*C/1000`. User/nice and system subset bounds use
`4*C*10**6/H` plus the same read-skew term, conservatively allowing two fields.
Adding idle and iowait gives the busy+idle capacity allowance `16*C` ticks:
`(delta_busy+delta_idle)/H <= E*C/10**9 + 16*C/H` CPU seconds. Domain microsecond
usage itself is bounded by `E*C/1000`. Capacity uses the outer acquisition
bracket so does not add read skew again. Same-atomic-read category identities
and IRQ+softirq subset checks are exact, without cross-read tolerance.

Every original and measured anchored prefix, including the WHOLE RUN, receives
this allowance ONCE. The number of intervals is absent from every formula.
Adjacent checks are retained to reject local contradictions; they do not supply
an accumulating full-run budget. Positive memory/PID/FD/I/O/network tolerances
are zero because read brackets alone cannot bound memory/task/device/packet
churn. Wire-byte counts must describe serialized bytes on the reviewed physical
link; each duplex direction has the bound `delta_bytes*8 <= link_bps*E/10**9`.
Actual NIC offload/packet completion counters cannot be relabeled as these bytes
without independent acquisition review. Process proportional rounding down
cannot explain aggregate PSS exceeding RAM.

### Review round 2 property and exactness boundaries

The generic property traverses every numeric schema position in both Python and
Rust recordings, retaining each domain/process component, each distinct nested
receipt shape and first/last endpoints. Equivalent interior array instances
share a schema position; they are not claimed as an exhaustive permutation of
JSON arrays. Signed perturbations include value +/-1, value +/-2**40, -1 and
2**64. For every violated registered predicate the real summary cannot PASS;
independent retained synthetic/failure blockers also cannot become PASS through
another numeric change. Fixing the sole bad input can legitimately restore PASS;
this property does not introduce a permanent verdict latch. Separate hand-derived
raw mutations establish each equation; the property intentionally reuses the
registered predicates to verify their verdict consumer, so it is not an
independent spec oracle. The adapted independent reviewer builders provide a
separate oracle for R-I1/R-I2/R-I3.

The decoder refuses decimal/exponent tokens before conversion (including tiny
underflow exponents). AST tests prohibit float constants/construction in
accounting.py/offline.py; runtime return tracing and recursively checked summaries
cover the reused monitor replay. Legacy floating `number`, `validate_traffic`
and `enrich_summary` helpers are made fatal during both adapter checks. The only
true division in accounting.py is median arithmetic with Fraction operands.
Grep has two text matches, both COMMENTS: Linux version 6.1 and the explanation
of Python's 5.0 equality alias. Neither is executable numeric code. Historical
schema-2 resource snapshots contain decimal JSON and are validated as JSON with
Decimal in the static checker; they are not accepted as new schema-1 raw runs,
modified, or used as a benchmark baseline.

### Review round 2 fresh verification (final mutation run still pending)

| Command / evidence | Fresh result |
| --- | --- |
| `python3 -B -I -m unittest discover -s tools/performance -p test_accounting.py` | **exit 0, 39 methods, 102.184s**, `task-14-evidence/review-round2-final-accounting.log`; includes the three new raw review regressions (four subcases), all retained round-1 regressions, exact threshold arithmetic, reconciliation and duration tests. |
| `python3 -B -I -m unittest discover -s tools/performance -p test_offline.py` | **exit 0, 9 methods, 78.398s**, `review-round2-final-offline.log`; **8,128** malformed-schema/failure-protocol cases, decimal-token RED/GREEN and exactness AST/runtime tracing, original redaction/publication tests and bounded literal-loopback self-test. |
| `python3 -B -I /tmp/task14-round2-independent-repros.py` | **exit 0**, 24 candidate raw summaries plus 24 matched baseline uses and four one-exit comparison scenarios all refuse the intended contradiction. `review-round2-independent.log` / `review-round2-independent-results.json`. Original independent common.py/receipt builders loaded read-only and explicitly extended with new mandatory fields before applying the original mutations. Positive controls qualify first. No original scratch script or result overwritten. |
| `python3 -B -I /tmp/task14-round2-static.py` | **exit 0**, all **10** performance Python ASTs; **6** JSON files; **21** closed required schema objects and **9** resolved refs; fixture/schema field agreement (including host), exactly the original fixture refusal reasons. `review-round2-static.log` / `review-round2-static-results.json`. No third-party schema validator installed/run. |
| `rg -n '\bfloat\(|[0-9]+\.[0-9]+|[0-9]+e[-+]?[0-9]+' tools/performance/accounting.py tools/performance/offline.py` | Two comment-only matches documented above, no executable floating literal/construction; `review-round2-float-grep.log`. AST and live verdict-path tests are the stronger executable checks. |
| Preservation checks in static script | **PASS**: rust/v2 @ cb91c79855fb1482e61f3becef6f8b71495e049e, `git diff --check`, `git diff --cached --quiet`, acceptance HEAD-identical and release_ready=false; both immutable review SHA256 values match initial snapshot. |

The initial static script attempt correctly refused historical decimal snapshots
when passed to the new integer-only raw decoder. The final static checker
separates JSON validity (strict duplicate/nonfinite rejection with Decimal for
historical files) from the schema-1 decoder contract. No historical file or
production code changed for that check. The raw grep command naturally matches
decimal-looking text in comments; an initial empty-output assertion was an
incorrect static-test assumption, corrected by AST classification, not by
removing comments or permitting floating verdict arithmetic.

### Review round 2 final class extension — cumulative offsets

The 40-family full mutation run passed **7 methods / 307.566s**, 6,108 probes,
4,996 registered/numeric violations (`review-round2-verified-mutations.log`).
A later thermal-boundary refinement also exercised equality with the exclusive
thermal limit, rather than only one unit above it (`review-round2-boundaries-final.log`).
This is retained intermediate evidence, superseded by the final 44-family checks.

A final offset audit found that plausible deltas could mask impossible starting
counters. Added a behavioural RED with stable future process start ticks, stable
process CPU offset, host CPU offset and cgroup CPU offset. All four incorrectly
returned PASS: `python3 -B -I -m unittest discover -s tools/performance -p test_accounting.py -k boot_clock -v`
returned exit 1, one method / four assertions / 0.294s
(`review-round2-uptime-red.log`). Added four registry families for lifetime and
boot-clock ceilings. The same command is GREEN, exit 0 / 0.314s
(`review-round2-uptime-green.log`). The registry now has **44**, with fresh full
three-file validation restarted after this production change. Earlier 40-family
full validation above is not claimed as validation of the final implementation.

| Additional ID / raw mutation case | Invariant | Enforced by | INSUFFICIENT_DATA reason |
| --- | --- | --- | --- |
| `process_start` | start_ticks <= read_end_ns*H/NS | check_invariants / physical_constraints | process_lifetime_contradiction |
| `process_lifetime_cpu` | utime+stime <= (read_end_ns*H/NS-start_ticks)*C + 2*C ticks | check_invariants / physical_constraints | process_lifetime_contradiction |
| `host_boot_cpu` | cumulative busy+idle <= read_end_ns*H*C/NS + 16*C ticks | check_invariants / physical_constraints | cpu_time_contradiction |
| `domain_boot_cpu` | cumulative cgroup usage_usec <= read_end_ns*C/1000 | check_invariants / physical_constraints | cpu_time_contradiction |

These four entries have the same signed one-unit/large raw boundary test and
completeness/consumer/property bindings as the original table. The lifetime
bound uses the start tick's lower endpoint (already conservative) and two extra
ticks per CPU for cumulative process quantization. The host boot bound uses the
same 16*C endpoint allowance as host capacity. Since CLOCK_BOOTTIME includes
suspend, it overestimates available CPU and is a conservative upper bound.
The reviewed host contract must exclude CPU hotplug since boot or supply a
conservative fixed CPU ceiling; current CPU count alone cannot authenticate that
contract. No producer or host history is qualified by this offline analyzer.

### Review round 2 open risks and scope

This is an implementation delegate's offline result, not an independent review
verdict or a benchmark. The normalized evidence equations and finite mutation
corpus do not authenticate original producers, raw receipts, alignment,
private-charge ownership, exited work, unobserved transient/ABA activity or peaks,
kernel/platform accounting semantics, physical-link byte semantics, fixed CPU
history, repetition independence or statistical power. There is still no
executable reviewed producer for the expanded schema. Draft records without the
new mandatory measurements are intentionally incompatible and refuse; there is
no fallback, inferred residual, inferred zero, or automatic legacy upgrade.

The analyzer conservatively refuses unsynchronized memory/I/O/PID/network data;
read width alone cannot establish their churn rate. New physical-link and
since-boot capacity contracts require independent producer/platform review,
including CPU hotplug history. This may reject legitimate acquisitions that do
not establish those contracts; it must not guess favorable quantities instead.
The inherited Python six-exit/direct monitoring restriction remains blocking.

No actual 600-second workload, guest/client/ARM collection, producer/workload
qualification, tuning, migration/canary/24h soak, or release integration ran.
All such performance/runtime/release gates remain **NOT_RUN / OPEN** and
`release_ready=false`. No Rust, collector, measurement.py, test_measurement.py,
loopback implementation, acceptance file, original review, Git index/HEAD,
service or VM changed. No child/delegated agent was started. All Python commands
used `python3 -B -I`; the requested existing test_offline suite's bounded literal
127.0.0.1 self-test was the only socket activity. No external network or resolver,
sudo, VM operation, Git staging/commit/push, or unrelated edits occurred.

Round 2 task-touched files: accounting.py, offline.py, run-schema.json,
fixtures/synthetic-short-run.json, test_accounting.py,
test_accounting_mutations.py, test_offline.py, performance-harness.md,
the Task 14 appendix of performance-measurement.md, and this ignored report/
evidence directory. A final source SHA256 manifest is retained at
`task-14-evidence/review-round2-final-source-sha256.json`. Unrelated initial dirty
work is retained. Original reviewer scratch files/results remain untouched.


### Review round 2 FINAL GREEN / disposition

The following results supersede all intermediate 35/40-family runs above. They
were run after the final production Python changes, against all **44 registry
families**. No source/test change followed these full runs; only documentation,
report, source-manifest and read-only preservation verification followed.

| Required command | Final result / retained evidence under task-14-evidence/ |
| --- | --- |
| `python3 -B -I -m unittest discover -s tools/performance -p test_accounting.py` | **exit 0, 40 methods, 107.513s**, `review-round2-final44-accounting.log`. Original/re-review regressions, boot/lifetime offset RED/GREEN class extension, all retained exact arithmetic, parser, coverage and reconciliation checks. |
| `python3 -B -I -m unittest discover -s tools/performance -p test_accounting_mutations.py` | **exit 0, 7 methods, 321.249s**, `review-round2-final44-mutations.log`. **176** signed small/large raw boundary cases across 44 families, live registry completeness, 44 reason-consumer mutations, host aggregate task limit, original **29** comparator mutants; **6,108** numeric schema boundary probes / **4,996** registered or numeric-domain violations. Every probe also retained a separate insufficiency blocker; retained FAIL checks never promoted to PASS. |
| `python3 -B -I -m unittest discover -s tools/performance -p test_offline.py` | **exit 0, 9 methods, 79.484s**, `review-round2-final44-offline.log`. **8,128** schema/failure-protocol cases; no decimal conversion, no float verdict path, publication/redaction and required bounded literal-loopback checks. |
| `python3 -B -I /tmp/task14-round2-static.py` | **exit 0**, final 44-family snapshot: **10** ASTs, **6** valid JSON files, **21** closed objects / **9** resolved refs; synthetic fixture exactly missing_runtime_evidence/short_run/synthetic_evidence. `review-round2-static.log` and `review-round2-static-results.json`. Historical decimals validated with Decimal, never accepted as new raw measurements. |
| `python3 -B -I /tmp/task14-round2-independent-repros.py` | **exit 0**, rerun against final production code. Four independent-builder scenarios: accumulated CPU, IRQ, softirq and aggregate PSS each yield the intended INSUFFICIENT_DATA reason in all six candidate summaries and matched comparison scenario. `review-round2-independent.log` / `review-round2-independent-results.json`. |
| Final grep + exactness | `review-round2-float-grep.log`: only two comment matches. AST reports one true division, Fraction median /2. Live exactness test forbids legacy float helpers and checks both original monitor adapters and derived reports. |
| Final preservation | `git diff --check` / `git diff --cached --quiet` pass; rust/v2 @ cb91c79855fb1482e61f3becef6f8b71495e049e; both review hashes and HEAD-identical acceptance bytes unchanged; release_ready=false. Source manifest matches final source/docs bytes. |

R-I1, R-I2 and R-I3 are fixed in this implementation and freshly reproduced
against the expanded schema using the independent original builders. The physical
class is covered by the explicit registry, signed raw boundaries, anchored and
lifetime equations, generic numeric property and completeness/consumer checks.
This is the final implementation fix round, with no independent PASS verdict
claimed. All producer, actual benchmark, runtime and release limits listed above
remain **NOT_RUN / OPEN**. No further task work or authorized check is pending.

## Controller disposition (2026-11-06): PARTIAL harness, NOT ACCEPTED

Three independent review rounds each returned FAIL for completeness: round 1
(`task-14-review.md`: I1-I3, M1-M2), round 2 (`task-14-rereview.md`: R-I1..R-I3), round 3
(`task-14-rereview2.md`: T3-I1 missing host CPU time passes the one-sided capacity check;
T3-I2 impossible cumulative process/cgroup CPU hidden by valid deltas; T3-I3 accepted native
subfields can contradict their containing totals; T3-I4 completed block-I/O bytes with zero
operations qualify). Every earlier finding was fixed each round (44-family executable invariant
registry; suite now 40 accounting tests, mutation probes, 8,128 failure-protocol cases) but each
round found contradictory raw recordings that still qualify, so the invariant set is not
provably complete. The 3-attempt limit for this step was reached; no fourth round was run.
T3-I1..T3-I4 stay OPEN. Consequence: the harness is committed as a strict PARTIAL accounting
layer; it must not be used to qualify a real run until T3-I1..T3-I4 are fixed and re-reviewed.
No performance claim exists; baseline vs candidate data are absent; release_ready=false.


## Review round 3

IMPLEMENTATION COMPLETE / OFFLINE GREEN, 2026-11-06. Independent re-review pending.
Started clean on rust/v2 @35c3bef. Historical checkpoints below retain their original status. Read all three
independent reviews and Review round 1/2 above before edits. Own only performance
tools, the two performance documents and this report; concurrent lab tools are
out of scope. No subagents, network, sudo, VM, Rust, staging/commit/push.

Tests first: added eleven EXACT independent reviewer recordings (T3-I1 both
implementations, T3-I2, five T3-I3 variants, three T3-I4 variants), losslessly
deduplicated with per-record canonical SHA256 in fixtures/review-round3.json.
No production code changed before the following RED run. Model generation,
completeness/mutation/property tests and final validation pending. This remains
a PARTIAL, unaccepted offline harness pending validation and independent review.
Real performance/producer/runtime/release checks NOT_RUN; release_ready=false.

Round 3 RED checkpoint (before production edits):

| Command | Result |
| --- | --- |
| `python3 -B -I -m unittest discover -s tools/performance -p test_accounting.py -k ReviewRoundThree -v` | exit 1, 4 methods, **11 reproduced false PASS assertions**, 0.389s. `/tmp/task14-round3-red.log`. |
| `python3 -B -I -m unittest discover -s tools/performance -p test_accounting_mutations.py -k QuantityModel -v` | exit 1, 3 methods, three expected missing-model assertions. `/tmp/task14-round3-model-red.log`. |

Model design: close native key sets, enumerate numeric schema positions including
optional native subfields, generate width/presence/monotonic/physical checks and
partition/subset/CPU-snapshot/completed-I/O relations from model data. New required
host `cpu_clock_contract=constant_online_no_suspend` is a producer requirement,
not authenticated by this analyzer: missing/unknown online/suspend history must
remain insufficient. Whole-run lower CPU-clock conservation applies only with
that contract. Existing reviewed fixtures will also be checked with this one new
nonnumeric declaration to demonstrate numeric refusal rather than old-schema
rejection. Counter snapshots are subsets of host totals, never equated to current
cgroup lifetime counters (migration would invalidate that stronger equation).

Round 3 incremental implementation checkpoint:

- Exact-review regression test is GREEN (4 methods, exit 0, 0.054s). Its old
  recordings are also missing the new clock contract. The stronger generated
  relationship test adds ONLY that nonnumeric declaration, preserves every raw
  numeric recording, and is GREEN (1 method, exit 0, 3.373s): all eleven cases
  break their intended generated relationship, and removing that model rule
  removes the named predicate. No old-schema rejection is counted as the fix.
- Initial model inventory/check-removal run: exit 0, 160 numeric entries / 160
  killed entry removals, 37.469s (`/tmp/task14-round3-inventory-progress.log`).
  Initial relation mutation run: exit 0, 66/66 killed relation removals, 70.595s
  (`/tmp/task14-round3-relations-progress.log`). These are superseded snapshots;
  the model now also exposes previously opaque receipt numeric fields and adds
  partial-sibling and declarative I/O conservation checks.
- Current model: **247 numeric positions**, including both original monitoring
  adapters and conditional retry/rate forms; **68 relation templates**. Every
  supported optional native field is explicitly listed; unknown native keys and
  unknown numeric receipt paths refuse. All eleven conditional receipt positive
  controls freshly PASS. Required physical values are never zero-filled.
- Found one invalid prior positive fixture: io_other.rbytes advanced with zero
  io_other.rios. Supplied its original residual operations and included them in
  cgroup operations. No production rule was weakened to retain this fixture.
- Broader accounting progress has this expected fixture failure and remains a
  progress log, not a final GREEN. Superseded property progress was stopped after
  model expansion. An exactness progress run was stopped because its trace
  recursively rewalked the entire run at every context-generator yield; the
  trace now checks arithmetic/boolean/predicate returns without that quadratic
  traversal. Original logs retained; no terminated run is claimed as PASS.
- `PERFORMANCE_OFFLINE_NO_NETWORK=1` skips ONLY the existing socket loopback test
  in test_offline.py. This task forbids network, so its runtime self-test will be
  reported NOT_RUN. No socket activity has been performed by this round.

Full 3-file validation, final model/registry tables, syntax/JSON and preservation
checks remain pending. Producer authenticity, clock/online history review,
real measurements and all release gates remain NOT_RUN; release_ready=false.

Round 3 expanded targeted GREEN checkpoint (not yet final three-file result):

| Command (all use `python3 -B -I -m unittest discover -s tools/performance`) | Result |
| --- | --- |
| `-p test_accounting_mutations.py -k test_schema_inventory_and_model_check_mutation_completeness -v` | exit 0, 1 method / 80.355s, **247/247 entry-removal mutants killed**, exact schema numeric inventory. `validation-output/round3/inventory-expanded.log`. |
| `-p test_accounting_mutations.py -k test_relation_boundaries_and_consumer_mutations -v` | exit 0, 1 method / 109.135s, **68/68 relation-removal mutants killed**. `validation-output/round3/relations-expanded.log`. |
| `-p test_accounting_mutations.py -k test_model_consumer_native_unknowns_and_clock_absence -v` | exit 0, 1 method / 2.983s. All eleven exact-numeric review cases refuse; disabling ONLY model verdict consumption restores false PASS. Missing clock contract, unknown native keys and unknown numeric receipt paths refuse. `validation-output/round3/consumer-progress.log`. |
| `-p test_offline.py` with `PERFORMANCE_OFFLINE_NO_NETWORK=1` | exit 0, 9 methods / 176.999s, one socket self-test **SKIPPED / NOT_RUN**, **8142** failure-protocol cases; exactness AST/runtime tracing, decimals, redaction, exclusive publication all pass. `validation-output/round3/offline-progress.log`. |

System `/tmp` tmpfs reached 100% independently of this task (owned round-3 logs
are only tens of KiB). Two attempts to redirect/run there returned exit **120**
before producing useful output. No existing evidence was deleted. Logs copied to
owned ignored `tools/performance/validation-output/round3/`; subsequent tests use
that directory for logs and an owned TMPDIR. Interrupted/superseded runs are
retained as progress evidence, never promoted to final validation. Final runs
have separate `final-*.log` and `final-*.exit` files. No network sockets ran.

Model notes: the whole-host lower bound includes both endpoint quantization and
outer/inner read uncertainty, exactly `16*C+(w0+w1)*C*H/10**9` ticks. Native PID/
thread fields retain signed-32-bit positive ceilings alongside the u64 recording
representation. Known receipt object/number projection alternatives are explicit;
unknown numeric paths refuse. Property-test rebinding updates ONLY the digest,
never repairs the mutated projection, and duplicate injections target the actual
field (or its nearest containing array field).

Round 3 final audit RED/GREEN before final restart:
`-p test_accounting_mutations.py -k test_count_bytes_and_optional_presence_boundaries -v`
returned exit **1**, 1 method / four assertions, 0.879s: three raw process/domain/
residual cases had more completed operations than bytes, and an optional native
byte field disappeared mid-run without a generated refusal. Same command after
generic pair/map enforcement: exit **0**, 1 method / 0.873s, including missing
process I/O device coverage. Logs `final-audit-red.log`, `final-audit-green.log`.
Completed data operations now require `0 <= operations <= bytes` and zero iff
zero; native field/device sets are stable by identity over the complete run.
This follows the model's explicit data-I/O semantics, not a disk bandwidth guess.

Superseded final runs were stopped (exit 143) and renamed `superseded-final-*`
after the audit changed enforcement; none are final results. The older expanded
property progress run was also stopped; its log is retained. The generic DSL
compiler now builds exact callables from the same data (no eval/code generation),
avoiding repeated interpretation during the full mutation suite. Final validation
must cover that refactoring and all audit changes. All requested work remains
inside the owned paths; concurrent lab edits are preserved.

### Review round 3 model and generated registry tables

Complete machine-readable per-quantity rows are in `tools/performance/quantity-model.json`; each has name, canonical schema path, exact source file/field, kind, unit, recorded and kernel width, monotonicity, parent, siblings, upper bound, absence and check/mutation bindings. Recorded values use u64; native PID/task fields additionally enforce the positive signed-32-bit domain. Conditional receipt alternatives retain the original source-specific validation.

| Quantity group | Numeric positions | Generated check binding |
| --- | ---: | --- |
| Acquisition clocks | 4 | `quantity:<canonical name>`; width/presence and applicable monotonicity |
| Cgroup and original residual quantities | 52 | `quantity:<canonical name>`; width/presence and applicable monotonicity |
| Full-run role and kernel failure evidence | 45 | `quantity:<canonical name>`; width/presence and applicable monotonicity |
| Manifest, binding, host limits and traffic | 26 | `quantity:<canonical name>`; width/presence and applicable monotonicity |
| Original traffic and monitor receipts | 87 | `quantity:<canonical name>`; width/presence and applicable monotonicity |
| Stable process quantities | 18 | `quantity:<canonical name>`; width/presence and applicable monotonicity |
| Whole-host samples | 15 | `quantity:<canonical name>`; width/presence and applicable monotonicity |
| **Total** | **247** | All require an overflow witness and killed entry-removal mutant |

Native closed/stable maps are separately generated from the model:

| Map ID | Modeled location |
| --- | --- |
| `cpu` | `/samples/*/domains/*/cpu` |
| `memory_stat` | `/samples/*/domains/*/memory_stat` |
| `memory_events` | `/samples/*/domains/*/memory_events` |
| `domain_io_devices` | `/samples/*/domains/*/io` |
| `domain_io_tuple` | `/samples/*/domains/*/io/*` |
| `residual_io_devices` | `/samples/*/domains/*/io_other` |
| `residual_io_tuple` | `/samples/*/domains/*/io_other/*` |
| `process_io_devices` | `/samples/*/processes/*/io` |
| `process_io_tuple` | `/samples/*/processes/*/io/*` |

Every relation below expands by its scope, consumes model expression data and requires a raw witness plus killed rule-removal mutant. `partition` means BOTH signed inequalities. Complete byte/count partitions have zero tolerance; CPU partitions have derived endpoint allowances. `subset` is encoded as a partition with zero (or quantized CPU) upper allowance and a lower remainder bound equal to its parent; it does not fabricate complete sibling evidence. Optional overlapping fields are only summed when the stated sibling set is disjoint. Exact expressions and bounds are in the JSON, not reconstructed from the ID.

| Generated relation ID | Expansion scope | Relation / bound source |
| --- | --- | --- |
| `host_clock` | `interval` | two-sided partition; endpoint CPU quantization/read skew |
| `host_boot` | `sample` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `host_parts` | `sample` | two-sided partition; exact aligned partition |
| `snapshot_domain_cpu` | `sample` | subset; endpoint CPU quantization/read skew |
| `snapshot_process_usage` | `sample` | subset; endpoint CPU quantization/read skew |
| `snapshot_domain_user` | `sample` | subset; endpoint CPU quantization/read skew |
| `snapshot_process_user` | `sample` | subset; endpoint CPU quantization/read skew |
| `snapshot_domain_system` | `sample` | subset; endpoint CPU quantization/read skew |
| `snapshot_process_system` | `sample` | subset; endpoint CPU quantization/read skew |
| `sum_pss_bytes` | `sample` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `sum_uss_bytes` | `sample` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `sum_charges` | `sample` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `sum_threads` | `sample` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `swap_host` | `sample` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `swap_pss` | `sample` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `swap_charges` | `sample` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `uss_pss` | `process` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `pss_rss` | `process` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `rss_ram` | `process` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `swap_order` | `process` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `fd_limit` | `process` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `pid_limit` | `process` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `thread_limit` | `process` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `process_start` | `process` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `process_lifetime` | `process` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `domain_parts` | `domain` | two-sided partition; endpoint CPU quantization/read skew |
| `exited_parts` | `domain` | two-sided partition; exact aligned partition |
| `memory_parts` | `domain` | two-sided partition; exact aligned partition |
| `memory_charge` | `domain` | two-sided partition; exact aligned partition |
| `pids` | `domain` | two-sided partition; exact aligned partition |
| `domain_boot` | `domain` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `native_sock` | `domain` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `native_shmem` | `domain` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `native_anon_thp` | `domain` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `native_file_thp` | `domain` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `native_shmem_thp` | `domain` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `native_kernel_stack` | `domain` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `native_pagetables` | `domain` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `native_sec_pagetables` | `domain` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `native_percpu` | `domain` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `native_vmalloc` | `domain` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `native_slab` | `domain` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `native_slab_reclaimable` | `domain` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `native_slab_unreclaimable` | `domain` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `native_file_mapped` | `domain` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `native_file_dirty` | `domain` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `native_file_writeback` | `domain` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `native_slab_subset` | `domain` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `native_slab_parts` | `domain` | two-sided partition; exact aligned partition |
| `native_kernel_components` | `domain` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `native_throttled_periods` | `domain` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `native_throttled_period_deltas` | `domain_interval` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `io_read` | `io` | completed data count/bytes; each completed data operation transfers at least one byte: 0 <= operations <= bytes, and zero iff zero; no device bandwidth assumption |
| `io_read_delta` | `io_interval` | completed data count/bytes; each completed data operation transfers at least one byte: 0 <= operations <= bytes, and zero iff zero; no device bandwidth assumption |
| `io_write` | `io` | completed data count/bytes; each completed data operation transfers at least one byte: 0 <= operations <= bytes, and zero iff zero; no device bandwidth assumption |
| `io_write_delta` | `io_interval` | completed data count/bytes; each completed data operation transfers at least one byte: 0 <= operations <= bytes, and zero iff zero; no device bandwidth assumption |
| `io_discard` | `io` | completed data count/bytes; each completed data operation transfers at least one byte: 0 <= operations <= bytes, and zero iff zero; no device bandwidth assumption |
| `io_discard_delta` | `io_interval` | completed data count/bytes; each completed data operation transfers at least one byte: 0 <= operations <= bytes, and zero iff zero; no device bandwidth assumption |
| `member_cpu_usage` | `domain_interval` | two-sided partition; endpoint CPU quantization/read skew |
| `member_cpu_user` | `domain_interval` | two-sided partition; endpoint CPU quantization/read skew |
| `member_cpu_system` | `domain_interval` | two-sided partition; endpoint CPU quantization/read skew |
| `host_charge` | `interval` | two-sided partition; endpoint CPU quantization/read skew |
| `domain_user_delta` | `interval` | subset; endpoint CPU quantization/read skew |
| `domain_system_delta` | `interval` | subset; endpoint CPU quantization/read skew |
| `domain_capacity` | `domain_interval` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `network_rx` | `interval` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `network_tx` | `interval` | subset; subset: omitted siblings are nonnegative and at most the whole parent |
| `io_conservation` | `device_interval` | two-sided partition; exact aligned partition |

Production model-generated refusal reasons have the stable `quantity_model:` prefix and the generated predicate ID. Structural/native/receipt failures can also refuse first. The old 44-family registry is retained as redundant independent equations; it is not a completeness oracle and was not extended with T3 case-specific code. All complete partitions, supported native subsets, byte/count pairs and known numeric domains are model data. No empirical performance, producer authenticity or universe-wide physical-completeness claim follows from this finite registry.

A speculative extra audit (`native-event-red.log`) proposed inequalities between
throttled duration/period events and between group-OOM/task-kill counters. These
are **not accepted invariants or reproduced defects**: kernel event timing and
attribution can differ, and the proposed relationships were not established by
the normalized contract. The temporary proposal test was withdrawn, not used to
change enforcement. The supported quantities retain their modeled width, presence,
stable-key and cumulative nonregression requirements. No arbitrary event-count/
duration equality or unproven native event subset is imposed.

Final static checkpoint: exit **0** for AST/strict JSON/ref resolution and
idempotent authoring checks. **12 Python ASTs**, **5 performance JSON files**,
**247 numeric positions**, **68 relations**, **9 native-map templates**.
`validation-output/round3/static-results.json` retains file lists, hashes and
results. Model SHA256 `9b1fd3ed3e5ef69e0c7c71f68acb07cc83db4d570388009eb84137e79bfa3a42`;
schema SHA256 `c2bf1f470134a032dbcc7a317b5921b65cfb831ef0b071a2ab6aa365cbd74e5a`.
The authoring rerun left both files byte-identical. Branch rust/v2, HEAD
35c3befd8e8bee60b00630d0a9171eefaad199ac. All three review files and acceptance
remain HEAD-identical; acceptance SHA256
3d467451dd03d1663e3c79b24eea6a18aac461f9291f8fdfe1031e1da6e86e97 and
release_ready=false. `git diff --check` and empty-index checks pass. Concurrent
lab tool/report changes are visible and untouched.

Final offline suite: `PERFORMANCE_OFFLINE_NO_NETWORK=1 python3 -B -I -m unittest discover -s tools/performance -p test_offline.py`
(with owned TMPDIR) -> exit **0**, **9 methods / 177.752s**, one loopback socket
method **SKIPPED / NOT_RUN**, **8142** failure-protocol cases. Log/exit files:
`validation-output/round3/final-offline.log` and `.exit`. This includes exactness
tracing through compiled model arithmetic, both receipt adapters, decimal
rejection, redaction and atomic exclusive publication. Full accounting/mutation
results remain pending at this checkpoint.

Final accounting suite: `python3 -B -I -m unittest discover -s tools/performance -p test_accounting.py`
(with owned TMPDIR) -> exit **0**, **44 methods / 332.652s**. All eleven exact
reviewer recordings, numeric-targeted refusals with the new clock declaration,
all earlier review regressions, exact threshold boundaries and positive controls
pass. Log/exit files: `validation-output/round3/final-accounting.log` and `.exit`.
The final mutation suite remains running at this checkpoint (CPU-active, no
failure output). No final implementation-complete or independent PASS claim yet.


### Review round 3 FINAL GREEN and disposition

All commands below used only `python3 -B -I`, from the repository root, with
`TMPDIR=/DATA/AppData/vprouter-rust-v2/tools/performance/validation-output/round3/tmp`.
No network sockets, sudo, VM, Rust, delegates or Git mutations were used by this
implementation. The loopback test was intentionally NOT_RUN under the task's
no-network constraint. Durations are test execution time, not workload results.

| Exact validation command | Exit / final result |
| --- | --- |
| `python3 -B -I -m unittest discover -s tools/performance -p test_accounting.py` | **0**, **44 tests**, 332.652s. All original review cases and eleven exact round-three recordings GREEN. `validation-output/round3/final-accounting.log`. |
| `python3 -B -I -m unittest discover -s tools/performance -p test_accounting_mutations.py` | **0**, **13 tests**, 1763.932s. Existing **6108** numeric probes / **4996** violations; new fixed-seed **4104** +/-1/zero/huge/absence/duplicate probes / **2022** generated violations; **247/247** quantity-entry and **68/68** relation-removal mutants killed. `validation-output/round3/final-mutations.log`. |
| `PERFORMANCE_OFFLINE_NO_NETWORK=1 python3 -B -I -m unittest discover -s tools/performance -p test_offline.py` | **0**, **9 tests**, 177.752s; **8 executed PASS, 1 loopback NOT_RUN**; **8142** failure-protocol cases. Exactness AST/runtime tracing includes the compiled model and both original monitor adapters. `validation-output/round3/final-offline.log`. |
| `python3 -B -I tools/performance/validation-output/round3/static-check.py` | **0**, 12 Python ASTs, 5 strict performance JSON files, resolved schema refs, no model/schema decimals, idempotent model authoring, final source/docs manifest unchanged, acceptance/reviews preserved, empty index, diff whitespace checks clean. `final-static.log` / `static-results.json` in the same directory. |

Every final unit run has its actual `.exit` file alongside the log. The final
source/docs manifest matches the final verified bytes. Production semantics
remained fixed during final validation. The speculative test addition described
above was withdrawn; final test-source content matches the version loaded by
the final runs. Documentation/report checkpoints and ignored evidence artifacts
were updated as results arrived.

Preservation qualification: during the long mutation run another actor advanced
HEAD from **35c3befd8e8bee60b00630d0a9171eefaad199ac** to
**848b46852d229ce5557998283053b60ebbee4e08**, commit `feat(rust): witness validator
round 4 with observation binding registry`. Its changed paths are exclusively
lab tools and their reports/progress, outside this task's ownership. No owned
performance path changed in that commit. The first final static attempt returned
exit **1** solely because its original HEAD-unchanged assertion detected this
external commit (`static-external-head-change.log`). Replaced that shared-tree
assumption with an explicit check that concurrent commits did not alter ANY
owned baseline path, while retaining exact live source-manifest verification.
The corrected final static run is exit **0**; this implementation performed no
staging, commit or push. Concurrent lab dirty/new files were preserved. All three
review files and acceptance remain unchanged; release_ready=false and acceptance
SHA256 3d467451dd03d1663e3c79b24eea6a18aac461f9291f8fdfe1031e1da6e86e97.

T3-I1, T3-I2, T3-I3 and T3-I4 are **implemented and offline GREEN** against the
reviewer's exact numeric recordings, not merely refused for the new clock-field
absence. Suppressing only model enforcement restores each reproduced false PASS.
The numeric schema/model inventory, closed/stable native maps, per-entry/rule
mutation coverage and seeded property now provide a derived completeness basis
for the supported recorded semantics. No new case-specific physical check was
added to accounting.py's legacy registry.

This is the implementation delegate's result, **not independent acceptance**.
The controller's earlier PARTIAL / NOT ACCEPTED disposition remains authoritative
until independent re-review. The finite model is not a proof of every possible
kernel relationship. Producer authenticity/alignment, constant-online/no-suspend
history, native peak/transient accounting, omitted guest/iowait detail, original
platform/cgroup semantics, independent repetition power, and the six-exit Python
direct adapter remain unqualified. No opaque native extension can silently
qualify; extending supported semantics requires model and witness updates.

**Real Python/Rust performance runs, producer/runtime/client/ARM/migration/soak and
release qualification remain NOT_RUN / OPEN. No performance claim is made;
release_ready=false.** All authorized implementation and offline validation work
for this task is complete. Independent re-review is the next gate.

## Controller disposition after round 4 (2026-11-06 14:50): still PARTIAL

Round 4 (`task-14-rereview3.md`): T3-I1..T3-I4 fixed; the quantity model's numeric
inventory is complete relative to run-schema.json (247 entries, 247/247 removal mutants
killed) but the reviewer reproduced three omitted accounting RELATIONS — T4-I1 cumulative CPU
residuals can exceed all CPU ever recorded, T4-I2 cumulative residual block I/O can exceed a
zero containing counter, T4-I3 socket memory has no place in the accepted charge partition —
plus T4-M1 (FD-entry quantities omit the native descriptor-number universe) and T4-M2
(smaps byte values need not be representable by the named source). These stay OPEN. The
harness is checkpointed as a strictly stronger PARTIAL layer; it must not qualify a real run.
A fifth round, if authorised, should add residual/socket-memory relations to the model and a
relation-completeness oracle derived from kernel accounting identities, not from the schema.


## Review round 4

IMPLEMENTATION COMPLETE / OFFLINE GREEN, 2026-11-07; independent re-review pending. Implementation delegate; no children. Started clean on
rust/v2 @eb2f50e3d83fd9439f9f120052e716e9d5f9e95c. All four reviews and the
report Review rounds 1-3 read in full. Own only tools/performance/**, the two
performance docs and this report. Concurrent witness-validator work is untouched.
No network (including loopback), sudo, VM, Rust or Git writes. Python uses only
`python3 -B -I`. Earlier /tmp reviewer fixtures were lost on reboot; reconstruct
from review text, do not claim recovery of their exact original bytes.

### RED checkpoint

Before production changes, added test_kernel_identities.py reconstructing all
nine review variants: outside CPU, exited user/system CPU, read/write/discard
residual IO, socket partition, FD universe and PSS byte quantum.
`python3 -B -I -m unittest discover -s tools/performance -p test_kernel_identities.py`
returned **exit 1, 6 methods, 10 assertion failures**, all nine false PASSes plus
the missing catalog. Log: tools/performance/validation-output/round4/red-confirmed.log;
actual exit in .exit. Initial PSS fixture failed an unrelated USS bound; corrected
its positive USS/charge context before recording the confirmed RED, retaining
red.log. No source fix preceded either run.

Catalog design: document Linux source identities independently of the schema,
including absent quantities and explicit non-identities/overlaps. Distinguish
kernel guarantees from the harness's stricter aligned acquisition/attribution
contracts. Derive checks from catalog bindings, audit both directions, and add
fixed-seed independent boundary witnesses. No performance claim. All real runs
and producer/runtime/client/ARM/migration/soak/release checks remain NOT_RUN;
release_ready=false. Independent re-review remains required.

### Catalog and independent boundary checkpoint

Initial catalog-derived regressions GREEN: same six-method file -> **exit 0,
6 tests / 1.716s**, green-progress.log. This was a targeted checkpoint, not final.
Catalog now records **127 source identities: 120 applicable/generated and seven
explicitly unavailable**. Bidirectional coverage test -> **exit 0, 1 method /
0.072s**, coverage-progress.log, including every generated relation removal and
unknown citation, plus all seven hypothetical schema-availability gates.

The independent fixed-seed property (0x144EB2F50E) has literal source-derived
witness recipes for **all 120 applicable identities**, not expectations chosen
by production predicates. Its first run -> **exit 1, 1 method, 240 probes /
49.479s**, property-red.log: the new cumulative host-accounted check had an upper
bound but omitted the residual definition's lower equality. Changed the catalog
template to a two-sided aligned snapshot partition, preserving separate outside
containment and anchored delta checks. This is a real additional RED, not a
passing model test relabeled as completeness. All source citations are paraphrases
from documentation knowledge, without network or local kernel-version validation.
Native counter semantics and the harness's stricter attribution/epoch/alignment
contracts are distinguished; no invented RLIMIT-current or pids.current<=max
snapshot law is asserted.

FD native-parser audit also RED: `python3 -B -I -m unittest discover -s tools/performance -p test_kernel_identities.py -k native_FD_names`
-> **exit 1**, one expected assertion (fd-parser-red.log). Added the signed-int
number ceiling to native fd enumeration as well as the count-universe relation.
Final GREEN pending. Real runs and release remain NOT_RUN / release_ready=false.

Expanded source audit adds physical-link delivered-payload containment and explicit
host CPU/swap cumulative identities, plus the unavailable SwapFree equality.
Final catalog snapshot for validation: **137 identities, 129 applicable generated
relations, eight unavailable source identities; 247 quantity entries**. The early
120-identity progress file is GREEN (**11 tests / 73.907s**, identities-progress.log),
including 240 signed probes, 54 candidate summaries, nine six-repetition scenarios
and nine actual CLI refusals with no publication. It is superseded by final runs.
The old relation-progress process was terminated with TERM after catalog expansion;
its exit/log remain progress evidence, never final validation. Broad accounting
progress was loaded before the PSS fixture correction: raw PSS boundaries now use
+/-1024 bytes (native kB); direct metric API retains +/-1-byte arithmetic tests.
No production threshold or quantum was weakened to admit an impossible raw source.


### Review round 4 catalog / identity tables

The complete machine-readable table is tools/performance/kernel-identities.json.
Each row has ID, source document/section/paraphrase, source-bound quantities,
assumptions, identity statement and check templates (or an explicit unavailable
reason). It was authored from Linux documentation knowledge, without network;
not a fetched quotation or running-kernel qualification. The model's 129 relation
rows are derived by kernel_identities.py and cite their catalog identity exactly.
The authoring tool no longer contains a handwritten relation list. Import-time
catalog/model consistency is a mandatory generated verdict gate.

| Catalog source family | Identities | Available generated checks |
| --- | ---: | ---: |
| `events` | 6 | 6 |
| `fds` | 3 | 2 |
| `host_cpu` | 21 | 19 |
| `io` | 26 | 26 |
| `memory` | 23 | 23 |
| `net` | 5 | 5 |
| `pids` | 5 | 4 |
| `process_cpu` | 29 | 28 |
| `smaps` | 12 | 10 |
| `swap` | 7 | 6 |
| **Total** | **137** | **129** |

| New/strengthened identity | Source and normalized contract | Generated checks |
| --- | --- | --- |
| Host cumulative residual definition | /proc/stat classes; aligned boot origin, residual=host busy-sum(disjoint domains), 0<=residual<=parent | outside_cpu_snapshot; snapshot_host_accounted (both signed bounds); counter_samples_host_other_cpu_usec |
| Exited/transient CPU | cpu.stat usage/user/system and original cgroup-origin tracker; each residual<=its containing cumulative class with 2us truncation bound; usage=user+system | exited_usage_snapshot; exited_user_snapshot; exited_system_snapshot; exited_parts; three catalog cumulative checks |
| Per-device IO residual | io.stat rbytes/wbytes/rios/wios/dbytes/dios; same domain attribution epoch, no lifetime process/cgroup equality | io_residual_snapshot expands all present devices/counters; existing io_conservation deltas and six residual cumulative checks |
| Socket container | memory.stat + memory.current; reviewed aligned anon/file/kernel/other partition | socket_container: sock<=kernel+other, retaining native_sock<=current; never add sock twice |
| FD number universe | proc PID/fd; nonnegative signed-int namespace independent of loose manifest | fd_native_universe: count<=2**31; parse_fd_entries additionally requires numbers<=INT_MAX |
| smaps representability | proc smaps_rollup integer kB; private clean+dirty defines USS | smaps_pss/rss/uss/swap/swap_pss_quantum: divisible by1024; no assumed4096-byte PSS quantum |
| Native cumulative sources | stat, cpu.stat, memory.events, completed io.stat, sched wakeups and net/vmstat source contracts | 47 source-bound monotonic relations, including residuals and every supported memory.events key; width/map checks retained |
| Delivered network payload | reviewed physical serialized-link normalization; native net/dev is not universally wire bytes | network_payload over actual post-warm-up endpoints; network_rx/network_tx remain separately duplex bounded |

| Catalog identity unavailable in this schema | Missing source evidence / no invented law |
| --- | --- |
| `native_guest_user` | Schema folds user+nice and does not record guest separately. |
| `native_idle_iowait` | Folded iowait is not separately recorded; native reliability remains a producer gate. |
| `native_waited_children` | Only utime/stime recorded; original exited tracker must avoid waited-child duplication. |
| `native_smaps_resident_partition` | Only USS aggregate recorded. Shared/private native pieces not available to verify separately. |
| `native_smaps_page_quantum` | No page-size contract in schema. Enforce 1024-byte output quantum only; never assume 4096-byte PSS. |
| `native_fd_allocation_limit` | Descriptor numbers, allocation-time limits and limit history are absent. Do not invent count <= current RLIMIT_NOFILE. |
| `native_pids_limit` | pids.max/history absent; no invalid snapshot bound is generated. |
| `native_swap_used` | SwapFree is not recorded separately; only the used<=total subset can be checked. |

Residual definitions are not values fabricated by the analyzer. Cumulative
residuals require common containing-counter attribution origins, nonnegative
values, snapshot containment and stable-identity nonregression. Member lifetimes
may predate the current cgroup: reconcile attributed member deltas, not false
snapshot equality of current cgroup and process lifetime totals. Memory residuals
are gauges. Unknown origin/alignment/ownership remains a producer blocker; a hash
and declaration do not prove it. All eight hypothetical newly available source
identities are explicitly rejected by the coverage audit until implemented.

### Review round 4 validation checkpoints

| Exact command (repo root; all use python3 -B -I) | Fresh result / retained log |
| --- | --- |
| `python3 -B -I -m unittest discover -s tools/performance -p test_kernel_identities.py` | Initial final snapshot **exit0, 11 tests /81.065s**; 129-identity independent table, **258** unconditional signed probes, 129 relation-removal/reverse-citation audits, eight unavailable-source gates; 54 candidate summaries, nine six-repetition scenarios and nine actual CLI redacted/no-publication refusals. final-kernel_identities.log. A strengthened matched-FD-baseline/positive-scenario check is running with separate final log. |
| `python3 -B -I -m unittest discover -s tools/performance -p test_measurement.py` | **exit0, 84 tests /1.327s**, final-measurement.log. Existing source-specific adapters. |
| `PERFORMANCE_OFFLINE_NO_NETWORK=1 python3 -B -I -m unittest discover -s tools/performance -p test_offline.py` | **exit0, 9 tests /177.016s, one skipped**; 8142 failure-protocol cases, exact verdict trace/AST (including new catalog compiler), redaction, atomic exclusive publication and cleanup. Loopback self-test NOT_RUN. final-offline.log. |
| `python3 -B -I tools/performance/validation-output/round4/static-check.py` | Progress **exit0**, 14 AST/compile checks (bytecode confined to owned temporary directory), strict JSON, nine schema refs, scratch-only byte-identical model/schema generation, three fresh-interpreter deterministic summaries, acceptance/review/index preservation. static-progress.log. Final rerun includes historical baseline-resource-sample.json and the last test-only refinement. |

All log/exit artifacts are retained in tools/performance/validation-output/round4.
Full accounting and mutation results are pending. The earlier accounting-progress
run exited1, 44 methods/320.023s, only the now-corrected unrepresentable raw PSS
fixture; it is not claimed as final GREEN. Production arithmetic remained exact;
only raw PSS test values moved to native-kB representable neighbors.

Final accounting suite: **exit0, 44 tests /340.492s**, final-accounting.log. This
run used the corrected native-kB raw PSS neighbors and all final production
semantics. Full mutation suite remains CPU-active/pending; no completion claim.

Strengthened matched-scenario identity file: **exit0, 11 tests /80.974s**,
final-kernel-identities-matched.log. FD baseline/candidate use the same 2**40
manifest bound and a positive six-repetition scenario passes first. Added a
retained lossless reconstruction bundle, fixtures/review-round4.json (nine
base-plus-patches payloads with canonical SHA256). It is explicitly constructed
regression input, not recovered reviewer bytes or real evidence. A new replay
method checks all nine retained hashes and refusals; final twelve-method file
and final static check are running. These are test/artifact refinements only;
production and all other test source bytes remain unchanged since their final
runs. No test-only refinement is claimed as proof about producer authenticity.

Final retained-fixture identity run: **exit0, 12 tests /96.164s**, final-identities.log.
All 258 independently expected boundary refusals, 129 forward/reverse check
mutations, eight availability gates, nine retained fixture SHA256 replays, 54
candidate summaries, nine correctly matched six-repetition scenarios and nine
CLI subprocess refusal/no-publication cases pass. Baseline positive control
qualifies first; no FD host-contract mismatch masks the actual finding.

Final static run: **exit0**, final-static.log / static-results.json. **14 Python
ASTs and explicit temporary-bytecode compiles; 11 strict JSON files**, including
the catalog, schema/model, both review fixture bundles, synthetic fixture,
example manifest, three historical baseline/source files and acceptance.
Historical decimal values are inspected with Decimal, never used in verdicts;
catalog/schema/model contain no decimal tokens. Nine schema refs resolve;
scratch-only authoring regenerates schema/model byte-identically. Three fresh
isolated interpreters produce identical canonical summaries (SHA256
53d4fe02092e4f9f3ab1de74f0242f3edebf2875f6a4967de8b0042809562e21).
source-hashes.json binds all final source/test/docs/fixture bytes. The earlier
source manifest is retained as source-hashes-before-fixture-refinement.json.
All four reviews and acceptance retain baseline bytes; acceptance SHA256
3d467451dd03d1663e3c79b24eea6a18aac461f9291f8fdfe1031e1da6e86e97 and
release_ready=false. Index empty; git diff --check passes. Concurrent lab edits
are visible and untouched. Full mutation file remains in progress.

Late descriptive-metadata correction: the FD quantity's physical_upper_bound
still carried the old generic "no universal tighter physical bound" text despite
its kernel_width and catalog relation correctly describing/enforcing 2**31.
Corrected that description in the author and regenerated the model. **No guard,
map, clock contract, relation template or verdict code changed.** Compared every
quantity field consumed by generated_constraints, all native maps, clock contract
and all catalog-derived relations against the retained pre-edit model; exact
structured equality PASS. fd-metadata-equivalence.json and
pre-metadata-verdict-semantics.json record the comparison; old model and source
manifest are retained in round4/. Final static manifest/AST/JSON/idempotence and
fresh-interpreter checks were refreshed. Existing/final in-flight unit results
apply to these identical executable predicates, not a changed implementation.

### Additional mutation RED: unavailable measured-window anchor

The first full mutation sweep reached the generated-model property and produced
an ERROR (not a false-PASS): the newly added measured network identity used next()
inside a context generator without a default. A warm-up boundary beyond the last
sample caused StopIteration to become RuntimeError under PEP479, escaping the
pure generated-constraint API's failure protocol. Public structural validation
already refused that warm-up; the direct generated-constraint API still must not
crash. Added an explicit behavioral regression before the fix:

`python3 -B -I -m unittest discover -s tools/performance -p test_kernel_identities.py -k unavailable_warmup_anchor`
-> **exit1, one ERROR /0.111s**, warmup-anchor-red.log. Same command after using an
explicit missing anchor and ValueError (converted to a failed network predicate)
-> **exit0, one method /0.121s**, warmup-anchor-green.log. No favorable last/zero
anchor is inferred. This is a production change, so earlier broad results are
retained but superseded for final verification.

Stopped the owned old mutation process with TERM; superseded-anchor-mutations.log
and .exit are retained, never claimed as final PASS. Revalidating accounting,
identity and offline files after this fix. Mutation file is now run by its three
independent unittest classes in separate processes, each through the requested
`python3 -B -I -m unittest discover -s tools/performance -p test_accounting_mutations.py -k CLASS -v`
interface. Together these cover all 13 methods: ComparatorMutationTests (2),
PhysicalRegistryTests (5), QuantityModelTests (6). The split removes serial waiting
between independent test classes, without changing seed/case counts, fixtures,
assertions or test semantics. No agent/delegate is involved. All post-fix results
and actual exits use post-anchor-* names. Full final source manifest and static
check will be rebound after this fix. All real runs remain NOT_RUN; release_ready=false.

Post-anchor broad GREEN checkpoint (all exit0):

| Exact command suffix after `python3 -B -I -m unittest discover -s tools/performance` | Result / final post-fix log |
| --- | --- |
| `-p test_kernel_identities.py -v` | **13 tests /81.166s**; post-anchor-identities.log. New unavailable-anchor regression plus all nine reviewer payloads, retained bundle hashes, 258 identity probes and 129 coverage/citation mutations pass. |
| `-p test_accounting.py -v` | **44 tests /336.517s**; post-anchor-accounting.log. All earlier rounds and exact thresholds/positive controls pass after the production fix. |
| `-p test_offline.py -v` (`PERFORMANCE_OFFLINE_NO_NETWORK=1`) | **9 tests /165.991s, one skipped**; post-anchor-offline.log. 8142 failure-protocol cases, exactness trace/AST, redaction/atomic publication. Loopback NOT_RUN. |
| `-p test_accounting_mutations.py -k ComparatorMutationTests -v` | **2 tests /2.867s**; post-anchor-comparator-mutants.log. Existing 29 comparator mutants killed. |

`python3 -B -I tools/performance/validation-output/round4/static-check.py` ->
**exit0** after the anchor fix; post-anchor-static.log / static-results.json.
All 14 Python AST/compile checks, 11 strict JSON files, nine refs, exact regenerated
model/schema, deterministic fresh-interpreter summaries, final source hashes and
acceptance/review/index checks pass. PhysicalRegistryTests and QuantityModelTests
remain pending; their class-filtered commands preserve all original methods,
fixed seeds and case counts. No final completion/acceptance claim yet.

Physical mutation class after the fix is GREEN:
`python3 -B -I -m unittest discover -s tools/performance -p test_accounting_mutations.py -k PhysicalRegistryTests -v`
-> **exit0, 5 tests /766.594s**, post-anchor-physical-mutants.log. **6108 numeric
schema boundary probes /4996 expected registered-or-numeric violations**, all
176 signed small/large registry witnesses, 44 live enforcement mutations and
aggregate task controls pass. Only the six-method QuantityModelTests class
remains pending. No source changes since the anchor fix.

### Review round 4 final GREEN and handoff

All final commands below exited **0** after the last production change (the
missing measured-window anchor refusal). Each command uses the requested isolated
Python interpreter. The mutation file's three class-filtered discovery commands
cover all 13 methods; their results are not represented as a single serial run.
Logs and actual process exit files are retained under
`tools/performance/validation-output/round4/`.

| Command | Final result | Log basename (`.log` and `.exit`) |
| --- | --- | --- |
| `python3 -B -I -m unittest discover -s tools/performance -p test_kernel_identities.py -v` | 13 tests /81.166s; 258 fixed-seed signed probes, nine reconstructed variants, coverage/citation checks | post-anchor-identities |
| `python3 -B -I -m unittest discover -s tools/performance -p test_accounting.py -v` | 44 tests /336.517s | post-anchor-accounting |
| `PERFORMANCE_OFFLINE_NO_NETWORK=1 python3 -B -I -m unittest discover -s tools/performance -p test_offline.py -v` | 9 tests /165.991s, one network test skipped; 8142 malformed-input cases | post-anchor-offline |
| `python3 -B -I -m unittest discover -s tools/performance -p test_accounting_mutations.py -k ComparatorMutationTests -v` | 2 tests /2.867s; 29 comparator mutants killed | post-anchor-comparator-mutants |
| `python3 -B -I -m unittest discover -s tools/performance -p test_accounting_mutations.py -k PhysicalRegistryTests -v` | 5 tests /766.594s; 6108 probes, 4996 expected violations | post-anchor-physical-mutants |
| `python3 -B -I -m unittest discover -s tools/performance -p test_accounting_mutations.py -k QuantityModelTests -v` | 6 tests /1182.170s; 4104 probes, 2042 violations; 129/129 relation-removal and 247/247 quantity-removal mutants killed | post-anchor-quantity-mutants |
| `python3 -B -I -m unittest discover -s tools/performance -p test_measurement.py` | 84 tests /1.106s | post-anchor-measurement |
| `python3 -B -I tools/performance/validation-output/round4/static-check.py` | 14 AST/compile checks; 11 strict JSON files; nine schema refs; byte-identical regeneration; three deterministic isolated-interpreter summaries; preservation PASS | final-preservation |

The static result binds the final source/test/docs/fixture hashes in
source-hashes.json. Acceptance SHA256 remains
`3d467451dd03d1663e3c79b24eea6a18aac461f9291f8fdfe1031e1da6e86e97`;
all four review files retain their baseline hashes. HEAD remains
`eb2f50e3d83fd9439f9f120052e716e9d5f9e95c`. The index is empty and
`git diff --check` passes. This report's final prose is outside the source hash
manifest; a final static check follows the report update.

Final task-touched publication inventory (14 owned paths):

- `tools/performance/kernel-identities.json`, `kernel_identities.py`: cited
  source identity catalog, schema availability and bidirectional coverage audit.
- `tools/performance/build_quantity_model.py`, `quantity-model.json`,
  `quantity_model.py`, `accounting.py`: derived relations and generic exact
  enforcement, native FD parser ceiling and fail-closed missing-window handling.
- `tools/performance/test_kernel_identities.py`, `fixtures/review-round4.json`:
  tests-first findings, hashed reconstructed fixtures and independent signed
  identity witnesses; no original lost scratch bytes are claimed.
- `tools/performance/test_accounting.py`, `test_accounting_mutations.py`,
  `test_offline.py`: native-kB raw PSS boundary fixtures and exactness coverage
  for the catalog compiler.
- `docs/rust-v2/performance-harness.md`,
  `docs/rust-v2/performance-measurement.md`, and this report: contracts, evidence,
  unavailable identities and qualification limits.

Local validation artifacts remain in the owned ignored validation-output tree.
Concurrent witness/lab files and their report were not edited by this delegate.
No subagents, network, sudo, VM, Rust, staging, commit or push were used.

Residual limits: the catalog is a documentation-knowledge transcription with
source citations and explicit acquisition assumptions, not a fetched quotation
or running-kernel qualification. Completeness is relative to its reviewed
identity inventory and schema availability; the tests cannot prove that Linux
has no additional identities. Eight catalog identities remain unavailable
because the schema does not record their inputs (table above). Raw declarations,
hashes and arithmetic consistency do not authenticate a producer, establish
common residual origins, demonstrate atomic aligned collection, or capture
unobserved transient peaks. PSS is checked at native 1024-byte output granularity;
no page size is invented. Current RLIMIT_NOFILE and pids.max are not universal
snapshot ceilings. Real producer, performance, runtime/client/ARM, migration and
soak qualification remain **NOT_RUN**. Task status stays **PARTIAL pending
independent re-review**, with **no performance claim** and **release_ready=false**.


## Review round 5

IMPLEMENTATION COMPLETE / OFFLINE GREEN, 2026-11-07; independent re-review
pending. Implementation delegate; no children. Started on `rust/v2` @
`e016617` with the round-5 harness changes uncommitted in the working tree.
Read `task-14-rereview4.md` in full, including R5-I1, R5-I2, the catalog audit
and the Minor notes. Own only `tools/performance/**`, the two performance docs
and this report. Concurrent witness/lab files, review files and acceptance were
not edited. No Git stage/commit/push, network (including loopback), sudo, VM,
Rust or real workload. Python used only `python3 -B -I`. All recordings below
are constructed input-domain records, never measurements.

### R5-I1 and R5-I2 fixes

R5-I1 is closed with the one-way identity `native_throttle_time_count`:
`throttled_usec > 0 => nr_throttled > 0`. The converse is **not** asserted.
The exact rule is evaluated at every domain sample **after the first
acquisition sample** (`scope: domain_tail`). `cpu.stat` is not read as one
cross-field atomic snapshot; a single first sample may catch an update between
fields, so exactly that sample is exempt. A contradiction sustained at later
samples is not a read-order artifact and is refused. The catalog citation now
states the cgroup-v2.rst meanings of `nr_periods`, `nr_throttled` and
`throttled_usec`, the first-sample exemption and its justification; it no longer
relies on the generic `usage_usec` sentence.

R5-I2 is closed by one surviving one-way containment plus the independent
absolute-zero policy:

- `native_group_kill_oom_kill`: `oom_group_kill <= oom_kill`, under the
  documented nonempty-victim group-kill assumption (a group kill selects at
  least one process).

The round-5 `native_group_kill_oom` (`oom_group_kill <= oom`) identity was
removed in round 6: `oom` counts limit-reached allocation-failure events, not
OOM kills, and a system-wide OOM group kill can leave this cgroup's own `oom`
zero. That counter pair is now an explicit `no_native_relation`. The surviving
containment is not an ordered partition. `oom_kill <= oom`, `oom <= oom_kill`,
`oom_group_kill <= oom` and their converses are explicitly not asserted. The
catalog citations now record the documented `memory.events` meanings and the
subtree/nonempty-victim assumptions.

The gate policy is fixed independently. `failure_quiet` now requires absolute
zero for `oom`, `oom_kill` and `oom_group_kill` in every declared cgroup at every
sample, instead of equality to the first sample. `domain_oom` retains the
last-minus-first delta but separately retains the absolute first-sample sum in
the reported OOM metric and adds the explicit
`oom_baseline_contaminated` reason. A constant pre-existing nonzero OOM count can
therefore never qualify as a zero baseline. `performance-harness.md` records the
policy.

### Generic operators and class closure

`quantity_model.py` now compiles two generic catalog operators, with no
measurement-name switches:

- `implies_positive` with `antecedent`/`consequent`: exact `a > 0 => b > 0`; no
  converse, no rate bound, fail-closed on non-integer operands (native schema
  quantities separately reject negative counters).
- `containment` with `parent`/`children`: `0 <= sum(children) <= parent`; it is
  one-way and does not claim a complete partition.

`containment` uses the optional-field `when_present` and `presence_pairs`
guards. `implies_positive` uses a one-way presence rule added in round 6: an
absent antecedent is vacuous, but a present positive antecedent requires a
present positive consequent; a symmetric `when_present` gate is not accepted
there. `domain_tail` adds every domain sample after the first acquisition
sample. The operators are exercised by a hand-derived truth table
(not by asking the production predicate) and by the existing per-relation raw
witness/removal mutants.

The counter-pair class is closed by an explicit catalog table rather than by
adding only the two reported instances:

- `counter_sources` assigns every recorded monotonic counter to exactly one
  co-located native source object.
- `counter_pairs` contains **all 159** within-source pairs. Each is either
  `identity` (naming the catalog identity whose operands relate the pair) or
  `no_native_relation` with a source-semantic reason.
- `kernel_identities.counter_pair_problems()` audits the table at import:
  exact pair coverage, source membership, no duplicate/extraneous pair, every
  monotonic counter assigned, identity operands present, and a reason for every
  no-native decision. Round 6 also refuses a `no_native_relation` label for any
  pair covered by an identity as parent/child, antecedent/consequent, or two
  distinct siblings under one partition/containment. Two operands combined
  inside one child expression are not siblings for this audit.
  `test_kernel_identities.py` independently repeats the enumeration from the
  model and catalog and mutates covered pairs to prove the audit catches them.

The audit scope is stated: pairs co-located in one recorded native source
object. Cross-source pairs are not two observations of one counter object and
are not claimed to have a native ordering.

| Source | Pairs | Identity | No native relation |
| --- | ---: | ---: | ---: |
| `cpu_stat` | 15 | 5 | 10 |
| `domain_exited_cpu` | 3 | 3 | 0 |
| `domain_io` | 15 | 3 | 12 |
| `domain_io_other` | 15 | 3 | 12 |
| `host_counters` | 78 | 17 | 61 |
| `memory_events` | 15 | 1 | 14 |
| `process_counters` | 3 | 0 | 3 |
| `process_io` | 15 | 3 | 12 |
| **Total** | **159** | **35** | **124** |

The complete per-pair decision table is in the appendix below. It includes every
pair that was previously related only by individual monotonicity checks; no pair
is silently unrelated. The 124 no-native decisions are grouped by reason:
time vs throttle events, period count vs throttle duration, OOM limit events vs
killed tasks, OOM limit events vs group kills (a system-wide OOM can group-kill
without the cgroup's own `oom`), memory threshold crossings, independent
read/write/discard IO streams,
idle vs busy/outside populations, outside residual vs a specific busy class,
full-duplex RX/TX, network/swap/thermal vs unrelated counters, independent
swap-in/out, independent process CPU classes, and wakeups vs CPU. None of these
is a kernel inequality, so none is invented.

### Event-counter gate baseline sweep

Every event counter consumed by a zero/qualification gate was checked for the
same constant-nonzero-baseline blind spot:

| Event counter(s) | Gate consumer | Absolute baseline treatment |
| --- | --- | --- |
| cgroup `memory_events.oom`, `oom_kill`, `oom_group_kill` | `failure_quiet`, `domain_oom`, reported `oom_events` metric | **Fixed**: absolute zero at every sample; first-sample sum kept separately; `oom_baseline_contaminated` |
| `traffic.oom_events`, `monitor_misses`, `unexpected_restarts` | direct zero gate in `evaluate_metrics` | Already absolute; nonzero fails regardless of history |
| all `failure_domains.*` signals (`memory_oom_kills`, `kernel_oom_kills`, `unexpected_restarts`, `monitor_misses`, `missing_samples`) | per-domain loop adds `measured_domain_failure` | Already absolute; each nonzero value is summed and refused |
| runtime proof `monitoring.deadline_misses`, `unexpected_restarts`, `oom_events` | proof/traffic equality and zero gate | Absolute; equality to a nonzero proof value still fails the zero gate, mismatch is `invalid_runtime_evidence` |
| host `thermal_throttle_count` | `thermal_quiet` | Already absolute `== 0` |
| host `swap_in_pages`, `swap_out_pages`, `swap_used_bytes` | `swap_quiet` | Already absolute `== 0` |
| process `wakeups` | monotonic-only check | Not a zero gate; no baseline blind spot |

The only constant-baseline blind spot was the cgroup `memory_events` family; it
is now closed by the policy above. `low`, `high` and `max` are not consumed by a
qualification gate and therefore are outside this gate sweep; they remain
monotonic counters with no invented ordering.

### Tests-first RED evidence

The two finding reproductions and the generic-operator truth table were written
before any production change. The containment-satisfying group-baseline variant
was added during the class sweep and is covered by the same GREEN run; its
pre-fix behavior is included in the supplementary scratch reconstruction.

`python3 -B -I -m unittest discover -s tools/performance -p test_kernel_identities.py -k ReviewRoundFive -v`
-> **exit 1**, 4 tests / 0.880 s, **4 failures + 3 errors**. Log:
`tools/performance/validation-output/round5/red-r5-findings.log`, exit in
`red-r5-findings.exit`.

- R5-I1 constant: `summarize` **PASS** in the primary RED; the supplementary
  reconstruction also returns a six-repetition scenario **PASS**.
- R5-I1 increasing: `summarize` **PASS** in the primary RED; the supplementary
  reconstruction also returns a six-repetition scenario **PASS**.
- R5-I2 `oom_group_kill=1, oom=oom_kill=0`: `summarize` **PASS** in the primary
  RED; the supplementary reconstruction also returns a scenario **PASS**.
- R5-I2 `oom=oom_kill=1, oom_group_kill=2`: `summarize` **PASS** in the primary
  RED; the supplementary reconstruction also returns a scenario **PASS**.
- Constant `oom=oom_kill=1, oom_group_kill=0`, `oom=0, oom_kill=1,
  oom_group_kill=0` and `oom=oom_kill=oom_group_kill=1`: the test first required
  the (then absent) containment identities, producing explicit errors on the
  first two; the legacy equality-to-first and delta gates were otherwise blind.
  The third variant satisfied both round-5 containments at the pre-fix state,
  so only the absolute-baseline policy could refuse it; the pre-fix scratch
  reproduction confirms PASS. Round 6 removed the invalid `oom` containment;
  the variant still satisfies the surviving one.
- The pair-coverage test errored on the absent `counter_sources`, not on a
  passing production predicate.

Because a failing `subTest` aborts its remaining statements, the primary RED log
reaches the `summarize` assertion (and, where the absent relation raised, the
relation lookup) but not the scenario or CLI assertion. A supplementary
reconstruction removes exactly the round-5 enforcement additions from a scratch
copy (three identities, counter tables, import audit and gate policy; scratch
catalog returns to 137 identities / 129 relations). In that copy, all seven
constructed variants (the six finding/gate variants plus the
containment-satisfying group baseline) return `summarize` **PASS**, a
six-repetition **PASS** scenario with all eight gates PASS and empty reasons
(`prefix-compare-red.json`), and the real `offline.py summarize` CLI exits
**0**, publishing a **PASS** summary with empty reasons and empty stderr
(`prefix-cli-red.json`). The positive control also PASSes. These are scratch
reconstructions, not recovered pre-edit bytes and not real evidence.

`python3 -B -I -m unittest discover -s tools/performance -p test_accounting_mutations.py -k new_operator_truth_tables -v`
-> **exit 1**, 1 test / 0.006 s, one error: `compile_relation` had no
`implies_positive`/`containment` operator and raised `KeyError: 'parent'`.
Log `red-r5-operators.log`, exit `red-r5-operators.exit`.

### GREEN evidence

Targeted new tests before the broad runs:

| Command suffix after `python3 -B -I -m unittest discover -s tools/performance` | Result |
| --- | --- |
| `-p test_kernel_identities.py -k ReviewRoundFive -v` | **exit 0**, 5 tests / 14.910 s; 159 explicit pairs / 36 identity pairs; first-sample tearing and no-converse valid half-space PASS |
| `-p test_accounting_mutations.py -k new_operator_truth_tables -v` | **exit 0**, 1 test / 0.000 s; exact implication/containment truth tables |

Broad files after the round-5 production changes (historical round-5 state;
current counts and identities are superseded by Review round 6):

| Command | Result / log |
| --- | --- |
| `python3 -B -I -m unittest discover -s tools/performance -p test_kernel_identities.py -v` | **exit 0**, 18 tests / 103.583 s; **132 applicable identities**, eight unavailable, 132 removal/reverse-citation mutants, **264 signed boundary probes**, 159 pair decisions; `progress-kernel-identities.log` |
| `python3 -B -I -m unittest discover -s tools/performance -p test_accounting.py -v` | **exit 0**, 44 tests / 333.894 s; `progress-accounting.log` |
| `PERFORMANCE_OFFLINE_NO_NETWORK=1 python3 -B -I -m unittest discover -s tools/performance -p test_offline.py -v` | **exit 0**, 9 tests / 164.927 s, one loopback test skipped (network prohibited); 8,142 failure-protocol cases; exactness trace, atomic exclusive publication; `progress-offline.log` |
| `python3 -B -I -m unittest discover -s tools/performance -p test_measurement.py -v` | **exit 0**, 84 tests / 1.157 s; `progress-measurement.log` |
| `python3 -B -I -m unittest discover -s tools/performance -p test_accounting_mutations.py -v` | **exit 0**, 14 tests / 1989.944 s; numeric schema boundary probes: 6108 registered/number violations: 4996; model fixed-seed +/-1/zero/huge/absent/duplicate probes: 4104 generated violations: 2046; model relation removal mutants killed: 132; model numeric entries and killed entry removals: 247. `final-accounting-mutations.log`. |

The mutation file covers all three classes in one run. Its relation-removal and
quantity-removal mutants now include the three new identities; the operator
truth tables are independent of the production predicate.

Static/AST/JSON validation was run with `python3 -B -I` over all 14 Python files
in `tools/performance` (parse + in-memory compile) and seven strict JSON
documents (duplicate keys, decimals, nonfinite values rejected). All nine schema
`$ref` values resolve. `accounting.py`, `quantity_model.py`,
`kernel_identities.py` and `offline.py` contain no float constants or `float()`
calls. Log `static-check.log`, exit 0. Regenerating `run-schema.json` and
`quantity-model.json` from the catalog in place produced byte-identical files
(SHA256 check `OK` for both).

Fresh-interpreter determinism: three isolated runs of the same constructed
summary produced identical SHA256
`4ce862452e0286cd0ba3be9c8002d9161a8d2a894cd45a85200afaafd73a553b`
(`determinism.log`). Atomic exclusive publication, fsync ordering, refusal to
overwrite and symlink/path refusal remain covered by `test_offline.py`.

### New and changed identities

| Identity | Check | Scope / guard | Generated rules |
| --- | --- | --- | --- |
| `native_throttle_time_count` | `implies_positive` | `domain_tail`, one-way presence | 1 |
| `native_group_kill_oom_kill` | `containment` | `domain`, both fields present | 1 |

Round 6 removed `native_group_kill_oom`; it was not a kernel identity because a
system-wide OOM group kill can occur with this cgroup's own `oom` count zero.
Catalog totals are **139 identities, 131 available/generated relations, eight
explicitly unavailable source identities, 247 numeric model positions and 159
counter-pair decisions (35 identity, 124 no-native)**.
`counter_pair_problems()` is part of the import-time catalog audit; removing the
audit call, any pair decision, or labelling a covered pair (including two
siblings under one partition) as no-native is caught by the coverage and
mutation tests.

### Documentation

`performance-harness.md` records the exact one-way throttle rule, its one-way
presence rule, the first-sample exemption and its torn-read justification, the
surviving OOM-kill containment and nonempty-victim assumption, the
`memory.events` no-exemption over-refusal, the absolute event-baseline policy,
the counter-pair table and the residual `pid_max` one-unit looseness and
normalized idle/iowait smoothing requirement. `performance-measurement.md`
carries the updated 139/131/159 counts, the removal of the false
`oom_group_kill <= oom` identity and the same one-way/containment policy. The catalog
source list now also names `man getrlimit(2)` (Minor citation metadata), and the
`cpu.stat` throttling rows cite the specific `nr_periods`/`nr_throttled`/
`throttled_usec` definitions rather than only the generic `usage_usec` sentence.
Both documents retain **no performance claim**, real runs **NOT_RUN** and
`release_ready=false`.

### Preservation

`git diff --check` passes; the index stays empty; branch `rust/v2` and HEAD
`e016617` are unchanged. No review file or acceptance file was edited. The only
new repository writes in this round are under the owned paths above. All
retained logs and exits are under
`tools/performance/validation-output/round5/`.

### Residual limits

The catalog remains a documentation-knowledge transcription, not a fetched
quotation, running-kernel proof or proof that no other Linux identity exists.
The 124 `no_native_relation` decisions are reasoned judgments; they are explicit
and audited for coverage, not a proof of absence of every conceivable kernel
relation. The throttle rule exempts the first sample by policy: a torn read at a
later sample would be refused (deliberate over-refusal), while a persistent
contradiction is refused as required. The one-way presence rule refuses
`throttled_usec > 0` with `nr_throttled` absent but accepts `nr_throttled > 0`
with `throttled_usec` absent. `oom_group_kill <= oom_kill` depends on the
nonempty-victim group-kill assumption. The `memory.events` containments have no
first-sample read-order exemption: a one-sample `oom_group_kill`/`oom_kill` tear
would be refused, accepted over-refusal because any nonzero OOM event is already
refused by the absolute-zero policy. `oom_group_kill <= oom` is not asserted:
`oom` is a limit-reached allocation-failure event, and a system-wide OOM group
kill can leave it zero. Any cgroup with a nonzero pre-existing OOM
count in the measured window is now deliberately treated as contaminated and
cannot qualify; a clean-window producer must start from zero counters.
`pid_max` is still one unit looser than the native PID wrap, normalized idle
still requires producer iowait smoothing, and native page size, current
RLIMIT_NOFILE, pids.max, transient peaks, producer authenticity/alignment and
statistical independence remain unqualified. No real performance, release,
producer, runtime, client, ARM, migration or soak acceptance follows from this
round; all such gates remain **NOT_RUN** with **no performance claim** and
**release_ready=false**.

### Appendix: complete co-located counter-pair decision table

| Source | Pairs | Identity | No native relation |
| --- | ---: | ---: | ---: |
| `cpu_stat` | 15 | 5 | 10 |
| `domain_exited_cpu` | 3 | 3 | 0 |
| `domain_io` | 15 | 3 | 12 |
| `domain_io_other` | 15 | 3 | 12 |
| `host_counters` | 78 | 17 | 61 |
| `memory_events` | 15 | 2 | 13 |
| `process_counters` | 3 | 0 | 3 |
| `process_io` | 15 | 3 | 12 |

| Source | Pair | Decision |
| --- | --- | --- |
| `cpu_stat` | `usage_usec / user_usec` | identity: `domain_parts` |
| `cpu_stat` | `usage_usec / system_usec` | identity: `domain_parts` |
| `cpu_stat` | `usage_usec / nr_periods` | no native relation: `cpu_time_vs_throttle_events` |
| `cpu_stat` | `usage_usec / nr_throttled` | no native relation: `cpu_time_vs_throttle_events` |
| `cpu_stat` | `usage_usec / throttled_usec` | no native relation: `cpu_time_vs_throttle_events` |
| `cpu_stat` | `user_usec / system_usec` | identity: `domain_parts` |
| `cpu_stat` | `user_usec / nr_periods` | no native relation: `cpu_time_vs_throttle_events` |
| `cpu_stat` | `user_usec / nr_throttled` | no native relation: `cpu_time_vs_throttle_events` |
| `cpu_stat` | `user_usec / throttled_usec` | no native relation: `cpu_time_vs_throttle_events` |
| `cpu_stat` | `system_usec / nr_periods` | no native relation: `cpu_time_vs_throttle_events` |
| `cpu_stat` | `system_usec / nr_throttled` | no native relation: `cpu_time_vs_throttle_events` |
| `cpu_stat` | `system_usec / throttled_usec` | no native relation: `cpu_time_vs_throttle_events` |
| `cpu_stat` | `nr_periods / nr_throttled` | identity: `native_throttled_periods` |
| `cpu_stat` | `nr_periods / throttled_usec` | no native relation: `period_vs_throttle_duration` |
| `cpu_stat` | `nr_throttled / throttled_usec` | identity: `native_throttle_time_count` |
| `domain_exited_cpu` | `cpu_exited_usec / cpu_exited_user_usec` | identity: `exited_parts` |
| `domain_exited_cpu` | `cpu_exited_usec / cpu_exited_system_usec` | identity: `exited_parts` |
| `domain_exited_cpu` | `cpu_exited_user_usec / cpu_exited_system_usec` | identity: `exited_parts` |
| `memory_events` | `low / high` | no native relation: `threshold_counts_independent` |
| `memory_events` | `low / max` | no native relation: `threshold_counts_independent` |
| `memory_events` | `low / oom` | no native relation: `threshold_counts_independent` |
| `memory_events` | `low / oom_kill` | no native relation: `threshold_counts_independent` |
| `memory_events` | `low / oom_group_kill` | no native relation: `threshold_counts_independent` |
| `memory_events` | `high / max` | no native relation: `threshold_counts_independent` |
| `memory_events` | `high / oom` | no native relation: `threshold_counts_independent` |
| `memory_events` | `high / oom_kill` | no native relation: `threshold_counts_independent` |
| `memory_events` | `high / oom_group_kill` | no native relation: `threshold_counts_independent` |
| `memory_events` | `max / oom` | no native relation: `threshold_counts_independent` |
| `memory_events` | `max / oom_kill` | no native relation: `threshold_counts_independent` |
| `memory_events` | `max / oom_group_kill` | no native relation: `threshold_counts_independent` |
| `memory_events` | `oom / oom_kill` | no native relation: `oom_events_vs_killed_tasks` |
| `memory_events` | `oom / oom_group_kill` | no native relation: `oom` limit events vs `oom_group_kill` (a system-wide OOM group kill can leave this cgroup's `oom` zero; round 6 removed the false identity) |
| `memory_events` | `oom_kill / oom_group_kill` | identity: `native_group_kill_oom_kill` |
| `domain_io` | `rbytes / wbytes` | no native relation: `io_streams_independent` |
| `domain_io` | `rbytes / rios` | identity: `io_read` |
| `domain_io` | `rbytes / wios` | no native relation: `io_streams_independent` |
| `domain_io` | `rbytes / dbytes` | no native relation: `io_streams_independent` |
| `domain_io` | `rbytes / dios` | no native relation: `io_streams_independent` |
| `domain_io` | `wbytes / rios` | no native relation: `io_streams_independent` |
| `domain_io` | `wbytes / wios` | identity: `io_write` |
| `domain_io` | `wbytes / dbytes` | no native relation: `io_streams_independent` |
| `domain_io` | `wbytes / dios` | no native relation: `io_streams_independent` |
| `domain_io` | `rios / wios` | no native relation: `io_streams_independent` |
| `domain_io` | `rios / dbytes` | no native relation: `io_streams_independent` |
| `domain_io` | `rios / dios` | no native relation: `io_streams_independent` |
| `domain_io` | `wios / dbytes` | no native relation: `io_streams_independent` |
| `domain_io` | `wios / dios` | no native relation: `io_streams_independent` |
| `domain_io` | `dbytes / dios` | identity: `io_discard` |
| `domain_io_other` | `rbytes / wbytes` | no native relation: `io_streams_independent` |
| `domain_io_other` | `rbytes / rios` | identity: `io_read` |
| `domain_io_other` | `rbytes / wios` | no native relation: `io_streams_independent` |
| `domain_io_other` | `rbytes / dbytes` | no native relation: `io_streams_independent` |
| `domain_io_other` | `rbytes / dios` | no native relation: `io_streams_independent` |
| `domain_io_other` | `wbytes / rios` | no native relation: `io_streams_independent` |
| `domain_io_other` | `wbytes / wios` | identity: `io_write` |
| `domain_io_other` | `wbytes / dbytes` | no native relation: `io_streams_independent` |
| `domain_io_other` | `wbytes / dios` | no native relation: `io_streams_independent` |
| `domain_io_other` | `rios / wios` | no native relation: `io_streams_independent` |
| `domain_io_other` | `rios / dbytes` | no native relation: `io_streams_independent` |
| `domain_io_other` | `rios / dios` | no native relation: `io_streams_independent` |
| `domain_io_other` | `wios / dbytes` | no native relation: `io_streams_independent` |
| `domain_io_other` | `wios / dios` | no native relation: `io_streams_independent` |
| `domain_io_other` | `dbytes / dios` | identity: `io_discard` |
| `process_io` | `rbytes / wbytes` | no native relation: `io_streams_independent` |
| `process_io` | `rbytes / rios` | identity: `io_read` |
| `process_io` | `rbytes / wios` | no native relation: `io_streams_independent` |
| `process_io` | `rbytes / dbytes` | no native relation: `io_streams_independent` |
| `process_io` | `rbytes / dios` | no native relation: `io_streams_independent` |
| `process_io` | `wbytes / rios` | no native relation: `io_streams_independent` |
| `process_io` | `wbytes / wios` | identity: `io_write` |
| `process_io` | `wbytes / dbytes` | no native relation: `io_streams_independent` |
| `process_io` | `wbytes / dios` | no native relation: `io_streams_independent` |
| `process_io` | `rios / wios` | no native relation: `io_streams_independent` |
| `process_io` | `rios / dbytes` | no native relation: `io_streams_independent` |
| `process_io` | `rios / dios` | no native relation: `io_streams_independent` |
| `process_io` | `wios / dbytes` | no native relation: `io_streams_independent` |
| `process_io` | `wios / dios` | no native relation: `io_streams_independent` |
| `process_io` | `dbytes / dios` | identity: `io_discard` |
| `host_counters` | `busy_ticks / user_ticks` | identity: `host_parts` |
| `host_counters` | `busy_ticks / system_ticks` | identity: `host_parts` |
| `host_counters` | `busy_ticks / irq_ticks` | identity: `host_parts` |
| `host_counters` | `busy_ticks / softirq_ticks` | identity: `host_parts` |
| `host_counters` | `busy_ticks / steal_ticks` | identity: `host_parts` |
| `host_counters` | `busy_ticks / idle_ticks` | identity: `host_clock` |
| `host_counters` | `busy_ticks / other_cpu_usec` | identity: `outside_cpu_snapshot` |
| `host_counters` | `busy_ticks / network_rx_bytes` | no native relation: `network_vs_cpu_swap_thermal` |
| `host_counters` | `busy_ticks / network_tx_bytes` | no native relation: `network_vs_cpu_swap_thermal` |
| `host_counters` | `busy_ticks / swap_in_pages` | no native relation: `swap_vs_cpu_network_thermal` |
| `host_counters` | `busy_ticks / swap_out_pages` | no native relation: `swap_vs_cpu_network_thermal` |
| `host_counters` | `busy_ticks / thermal_throttle_count` | no native relation: `thermal_vs_other_counters` |
| `host_counters` | `user_ticks / system_ticks` | identity: `host_parts` |
| `host_counters` | `user_ticks / irq_ticks` | identity: `host_parts` |
| `host_counters` | `user_ticks / softirq_ticks` | identity: `host_parts` |
| `host_counters` | `user_ticks / steal_ticks` | identity: `host_parts` |
| `host_counters` | `user_ticks / idle_ticks` | no native relation: `idle_is_busy_complement` |
| `host_counters` | `user_ticks / other_cpu_usec` | no native relation: `outside_bounded_by_busy_only` |
| `host_counters` | `user_ticks / network_rx_bytes` | no native relation: `network_vs_cpu_swap_thermal` |
| `host_counters` | `user_ticks / network_tx_bytes` | no native relation: `network_vs_cpu_swap_thermal` |
| `host_counters` | `user_ticks / swap_in_pages` | no native relation: `swap_vs_cpu_network_thermal` |
| `host_counters` | `user_ticks / swap_out_pages` | no native relation: `swap_vs_cpu_network_thermal` |
| `host_counters` | `user_ticks / thermal_throttle_count` | no native relation: `thermal_vs_other_counters` |
| `host_counters` | `system_ticks / irq_ticks` | identity: `host_parts` |
| `host_counters` | `system_ticks / softirq_ticks` | identity: `host_parts` |
| `host_counters` | `system_ticks / steal_ticks` | identity: `host_parts` |
| `host_counters` | `system_ticks / idle_ticks` | no native relation: `idle_is_busy_complement` |
| `host_counters` | `system_ticks / other_cpu_usec` | no native relation: `outside_bounded_by_busy_only` |
| `host_counters` | `system_ticks / network_rx_bytes` | no native relation: `network_vs_cpu_swap_thermal` |
| `host_counters` | `system_ticks / network_tx_bytes` | no native relation: `network_vs_cpu_swap_thermal` |
| `host_counters` | `system_ticks / swap_in_pages` | no native relation: `swap_vs_cpu_network_thermal` |
| `host_counters` | `system_ticks / swap_out_pages` | no native relation: `swap_vs_cpu_network_thermal` |
| `host_counters` | `system_ticks / thermal_throttle_count` | no native relation: `thermal_vs_other_counters` |
| `host_counters` | `irq_ticks / softirq_ticks` | identity: `host_parts` |
| `host_counters` | `irq_ticks / steal_ticks` | identity: `host_parts` |
| `host_counters` | `irq_ticks / idle_ticks` | no native relation: `idle_is_busy_complement` |
| `host_counters` | `irq_ticks / other_cpu_usec` | no native relation: `outside_bounded_by_busy_only` |
| `host_counters` | `irq_ticks / network_rx_bytes` | no native relation: `network_vs_cpu_swap_thermal` |
| `host_counters` | `irq_ticks / network_tx_bytes` | no native relation: `network_vs_cpu_swap_thermal` |
| `host_counters` | `irq_ticks / swap_in_pages` | no native relation: `swap_vs_cpu_network_thermal` |
| `host_counters` | `irq_ticks / swap_out_pages` | no native relation: `swap_vs_cpu_network_thermal` |
| `host_counters` | `irq_ticks / thermal_throttle_count` | no native relation: `thermal_vs_other_counters` |
| `host_counters` | `softirq_ticks / steal_ticks` | identity: `host_parts` |
| `host_counters` | `softirq_ticks / idle_ticks` | no native relation: `idle_is_busy_complement` |
| `host_counters` | `softirq_ticks / other_cpu_usec` | no native relation: `outside_bounded_by_busy_only` |
| `host_counters` | `softirq_ticks / network_rx_bytes` | no native relation: `network_vs_cpu_swap_thermal` |
| `host_counters` | `softirq_ticks / network_tx_bytes` | no native relation: `network_vs_cpu_swap_thermal` |
| `host_counters` | `softirq_ticks / swap_in_pages` | no native relation: `swap_vs_cpu_network_thermal` |
| `host_counters` | `softirq_ticks / swap_out_pages` | no native relation: `swap_vs_cpu_network_thermal` |
| `host_counters` | `softirq_ticks / thermal_throttle_count` | no native relation: `thermal_vs_other_counters` |
| `host_counters` | `steal_ticks / idle_ticks` | no native relation: `idle_is_busy_complement` |
| `host_counters` | `steal_ticks / other_cpu_usec` | no native relation: `outside_bounded_by_busy_only` |
| `host_counters` | `steal_ticks / network_rx_bytes` | no native relation: `network_vs_cpu_swap_thermal` |
| `host_counters` | `steal_ticks / network_tx_bytes` | no native relation: `network_vs_cpu_swap_thermal` |
| `host_counters` | `steal_ticks / swap_in_pages` | no native relation: `swap_vs_cpu_network_thermal` |
| `host_counters` | `steal_ticks / swap_out_pages` | no native relation: `swap_vs_cpu_network_thermal` |
| `host_counters` | `steal_ticks / thermal_throttle_count` | no native relation: `thermal_vs_other_counters` |
| `host_counters` | `idle_ticks / other_cpu_usec` | no native relation: `idle_vs_outside_populations` |
| `host_counters` | `idle_ticks / network_rx_bytes` | no native relation: `network_vs_cpu_swap_thermal` |
| `host_counters` | `idle_ticks / network_tx_bytes` | no native relation: `network_vs_cpu_swap_thermal` |
| `host_counters` | `idle_ticks / swap_in_pages` | no native relation: `swap_vs_cpu_network_thermal` |
| `host_counters` | `idle_ticks / swap_out_pages` | no native relation: `swap_vs_cpu_network_thermal` |
| `host_counters` | `idle_ticks / thermal_throttle_count` | no native relation: `thermal_vs_other_counters` |
| `host_counters` | `other_cpu_usec / network_rx_bytes` | no native relation: `network_vs_cpu_swap_thermal` |
| `host_counters` | `other_cpu_usec / network_tx_bytes` | no native relation: `network_vs_cpu_swap_thermal` |
| `host_counters` | `other_cpu_usec / swap_in_pages` | no native relation: `swap_vs_cpu_network_thermal` |
| `host_counters` | `other_cpu_usec / swap_out_pages` | no native relation: `swap_vs_cpu_network_thermal` |
| `host_counters` | `other_cpu_usec / thermal_throttle_count` | no native relation: `thermal_vs_other_counters` |
| `host_counters` | `network_rx_bytes / network_tx_bytes` | no native relation: `network_directions_independent` |
| `host_counters` | `network_rx_bytes / swap_in_pages` | no native relation: `network_vs_cpu_swap_thermal` |
| `host_counters` | `network_rx_bytes / swap_out_pages` | no native relation: `network_vs_cpu_swap_thermal` |
| `host_counters` | `network_rx_bytes / thermal_throttle_count` | no native relation: `thermal_vs_other_counters` |
| `host_counters` | `network_tx_bytes / swap_in_pages` | no native relation: `network_vs_cpu_swap_thermal` |
| `host_counters` | `network_tx_bytes / swap_out_pages` | no native relation: `network_vs_cpu_swap_thermal` |
| `host_counters` | `network_tx_bytes / thermal_throttle_count` | no native relation: `thermal_vs_other_counters` |
| `host_counters` | `swap_in_pages / swap_out_pages` | no native relation: `swap_directions_independent` |
| `host_counters` | `swap_in_pages / thermal_throttle_count` | no native relation: `thermal_vs_other_counters` |
| `host_counters` | `swap_out_pages / thermal_throttle_count` | no native relation: `thermal_vs_other_counters` |
| `process_counters` | `utime_ticks / stime_ticks` | no native relation: `process_cpu_classes_independent` |
| `process_counters` | `utime_ticks / wakeups` | no native relation: `process_wakeups_vs_cpu` |
| `process_counters` | `stime_ticks / wakeups` | no native relation: `process_wakeups_vs_cpu` |

## Review round 6

IMPLEMENTATION COMPLETE / OFFLINE GREEN, 2026-11-07; independent re-review
pending. Implementation delegate; no children. Started on `rust/v2` @
`e01661755097452952c1e4ca89dc4097d67c771f` with the rounds 5+6 harness changes
uncommitted in the working tree. Read `task-14-rereview5.md` in full, including
R6-I1, R6-M1 to R6-M6, the kernel semantics audit, the counter-pair audit and
the disposition. Own only `tools/performance/**`, the two performance documents
and this report. No review file, acceptance file, Git index, branch or HEAD was
modified. No network (including loopback), sudo, VM, Rust or real workload was
run. Python used only `python3 -B -I`; the offline suite used
`PERFORMANCE_OFFLINE_NO_NETWORK=1`. Every recording below is a constructed
input-domain record, never a measurement. Real Python/Rust performance,
producer/runtime/client/ARM/migration/soak/release qualification remain
**NOT_RUN / OPEN**, with **no performance claim** and `release_ready=false`.

### R6-I1: remove the false `oom_group_kill <= oom` identity

The identity, its generated relation and its counter-pair `identity` decision
were removed. The `memory.events.oom / oom_group_kill` pair is now an explicit
`no_native_relation` whose reason records the documented `oom` meaning: the
number of times the cgroup's memory usage reached the limit and the allocation
was about to fail (a single event, not per process). It is not an OOM-kill
count. During a system-wide OOM the OOM killer can select this cgroup and, with
`memory.oom.group=1`, kill the whole group without this cgroup's own limit being
reached, so `oom_group_kill` can increase while `oom` stays zero.
`native_group_kill_oom_kill` (`oom_group_kill <= oom_kill`) remains under the
documented nonempty-victim assumption, as does the independent absolute-zero
OOM policy.

Every citation and document was corrected, not just the deleted identity: the
`native_group_kill_oom_kill` citation, the six `memory.events` counter rows,
the `oom / oom_kill` no-native reason, `performance-harness.md`,
`performance-measurement.md`, this report's round-5 claim and its appendix.
The catalogue totals changed from 140/132/36/123 to
**139 identities / 131 generated relations / 35 identity pairs / 124 no-native
pairs**; 159 pairs, 247 quantities and eight unavailable identities are
unchanged. The witness table, availability audit and mutation tests were
updated: **131 applicable identities and 262 signed boundary probes**.

Evidence. The constructed valid global-OOM group-kill records
`oom=0, oom_kill=1, oom_group_kill=1` (SHA256
`8104ca6536a4318a24ed1eb991ba5309a19736c5a8a5625361023c71d8b21b6a`) and
`oom=0, oom_kill=2, oom_group_kill=1` (SHA256
`c33c7e5b6252a54a398b28807a322e15580a131d4dfe7c8b0d23405c6b15a861`) both
summarize **INSUFFICIENT_DATA** with reasons
`['measured_domain_failure', 'oom_baseline_contaminated']` and reported
`oom_events` 2 and 3. Neither record contains
`quantity_model:relation:native_group_kill_oom`; the surviving
`native_group_kill_oom_kill` relation is satisfied and is not a reason. This is
still a refusal by the OOM policy, not by a false native contradiction.

### R6-M1: one-way presence in `implies_positive`

`quantity_model.py` now implements one-way presence for `implies_positive`: an
absent antecedent is vacuous; a present nonpositive antecedent is vacuous; a
present positive antecedent requires a present positive consequent; a present
positive antecedent with an absent consequent **fails**. The converse presence
requirement is not asserted, so the valid half-space `nr_throttled > 0` with
`throttled_usec` absent still PASSes. The catalog check now records
`presence_rule: positive_antecedent_requires_present_positive_consequent` and no
longer relies on a symmetric `when_present` gate. The compiler rejects a
`when_present` field on `implies_positive` rather than silently ignoring it.

Evidence. A constructed record with `throttled_usec=1000000` and both
`nr_throttled` and `nr_periods` absent at every control sample was a false PASS
before the change (the reproduced R6-M1); it is now INSUFFICIENT_DATA with the
single relation reason `quantity_model:relation:native_throttle_time_count`
(no other relation masks it). The valid half-space `nr_periods=1,
nr_throttled=1, throttled_usec` absent PASSes, as does the both-absent and
all-zero forms. The independent operator truth table covers all presence
combinations: antecedent absent (consequent absent/zero/positive) vacuous;
antecedent zero (consequent absent/zero/positive) vacuous; antecedent positive
with consequent absent or zero refused; antecedent positive with consequent
positive accepted.

### R6-M2: generate presence-operand `relation_checks`

`build_quantity_model.py` now includes `antecedent` and `consequent` in the
machine-readable relation cross-reference scan, in addition to `parent`,
`children` and `path`. `samples.*.domains.*.cpu.nr_throttled` and
`samples.*.domains.*.cpu.throttled_usec` now list `native_throttle_time_count`
in `relation_checks`. `run-schema.json` and `quantity-model.json` were
regenerated only with `python3 -B -I build_quantity_model.py`; the schema was
byte-identical, and repeated regeneration produced byte-identical files
(SHA256 `c2bf1f470134a032dbcc7a317b5921b65cfb831ef0b071a2ab6aa365cbd74e5a`
and `8eced2f8a1c14ec59f7a1d1df00899f089c86c042e1d8ea8df0a3227e3976b77 (corrected per review R7-M1; the round-6 value was stale)`).

### R6-M3: audit covered sibling counter pairs

`kernel_identities.counter_pair_problems()` now treats a pair as covered when
its two operands are one parent-side and one child-side operand of a check, one
antecedent and one consequent, or two distinct siblings under one
partition/containment. A `no_native_relation` decision for any covered pair is
reported as `counter_pair_unrelated_but_identity`. Two operands summed inside
one child expression (process `utime_ticks`+`stime_ticks` inside one usage
child) are deliberately not treated as siblings; the existing
`process_cpu_classes_independent` decision remains valid. A scratch-catalog
mutation test changes four covered pairs (host `user_ticks`/`system_ticks`
siblings, `nr_periods`/`nr_throttled` parent/child, `nr_throttled`/
`throttled_usec` antecedent/consequent, `oom_kill`/`oom_group_kill`
containment) from `identity` to `no_native_relation` and requires all four to
be caught. The overstated round-5 report sentence "any pair decision is caught"
was replaced with the exact covered-pair scope above.

### R6-M4 and R6-M5: torn-read policy documented

`performance-harness.md` now states explicitly that the `cpu.stat` throttle
implication exempts exactly the first acquisition sample; a later single-sample
tear is deliberately over-refused because the policy does not infer read
ordering beyond that documented exemption. It also states that the
`memory.events` containments have **no** first-sample read-order exemption: a
one-sample `oom_group_kill`/`oom_kill` tear would be refused, and that
over-refusal is accepted because the independent absolute-zero OOM policy
already prevents any nonzero OOM event from PASSing. The same limits are
recorded in this report's residual limits.

### R6-M6: correct the arithmetic table

The arithmetic table now labels the raw-record control-PSS boundary as a
**1 KiB quantum**, because `smaps_rollup` prints integer kB; the direct metric
API retains the abstract ±1 B boundaries. The raw-record test and the report
table now agree.

### RED evidence

Tests were written before the production changes and run with
`python3 -B -I -m unittest discover -s tools/performance`:

| RED command suffix | Exit | Result / log |
| --- | ---: | --- |
| `-p test_kernel_identities.py -k ReviewRoundSix -v` | 1 | 4 tests, **6 failures / 0.698 s**: both global-OOM variants exposed the false `native_group_kill_oom` row; the missing-consequent record was **PASS**; both throttle `relation_checks` lacked `native_throttle_time_count`; the sibling-pair mutation returned no problem. `/tmp/opencode/task14-r6/red-r6-kernel.log` |
| `-p test_accounting_mutations.py -k test_new_operator_truth_tables -v` | 1 | 1 test, **6 errors / 0.001 s**: absent-antecedent and absent-consequent contexts raised `KeyError('a')`/`KeyError('b')` instead of the one-way presence result. `/tmp/opencode/task14-r6/red-r6-truth.log` |

No production file was changed before these RED runs. The RED kernel log
includes the reproduced R6-M1 false PASS, the false `oom_group_kill <= oom`
row, the missing cross-reference and the uncaught sibling mutation, matching
the re-review's four findings.

### GREEN evidence

Targeted runs after the production, catalog and regeneration changes:

| Command suffix | Exit | Result / log |
| --- | ---: | --- |
| `-p test_kernel_identities.py -k ReviewRoundSix -v` | 0 | 4 tests / 4.777 s; R6-I1 (including the six-repetition and CLI OOM-policy refusals), M1, M2, M3 pass; `/tmp/opencode/task14-r6/green-r6-kernel-six.log` |
| `-p test_kernel_identities.py -k ReviewRoundFive -v` | 0 | 5 tests / 13.744 s; 159 pairs / **35 identity pairs**; first-sample tearing and valid half-spaces still PASS; `/tmp/opencode/task14-r6/green-r6-kernel-five.log` |
| `-p test_accounting_mutations.py -k test_new_operator_truth_tables -v` | 0 | 1 test / 0.000 s; presence truth table passes; `/tmp/opencode/task14-r6/green-r6-truth.log` |

Every test file was then run to completion:

| Full command | Exit | Result / log |
| --- | ---: | --- |
| `python3 -B -I -m unittest discover -s tools/performance -p test_kernel_identities.py -v` | 0 | **22 tests / 99.638 s**; 131 applicable identities, eight unavailable, 131 removal/reverse-citation mutants, **262 signed boundary probes**, 159 pair decisions; `/tmp/opencode/task14-r6/green-kernel-full.log` |
| `python3 -B -I -m unittest discover -s tools/performance -p test_accounting.py -v` | 0 | **44 tests / 313.066 s** (5m13.144 s wall); `/tmp/opencode/task14-r6/green-accounting.log` |
| `PERFORMANCE_OFFLINE_NO_NETWORK=1 python3 -B -I -m unittest discover -s tools/performance -p test_offline.py -v` | 0 | **9 tests / 158.452 s** (2m38.500 s wall), **one loopback test skipped and NOT_RUN**; 8,142 failure-protocol cases; `/tmp/opencode/task14-r6/green-offline.log` |
| `python3 -B -I -m unittest discover -s tools/performance -p test_measurement.py -v` | 0 | **84 tests / 1.033 s**; `/tmp/opencode/task14-r6/green-measurement.log` |
| `python3 -B -I -m unittest discover -s tools/performance -p test_accounting_mutations.py -v` | 0 | **14 tests / 1,880.763 s** (31m20.843 s wall); numeric schema probes 6,108 registered / 4,996 violations; model fixed-seed probes 4,104 generated / 2,046 violations; **131 relation-removal mutants killed** and 247 quantity-removal mutants; `/tmp/opencode/task14-r6/green-accounting-mutations.log` |

Static/AST/strict-JSON check (`/tmp/opencode/task14-r6/static_check.py`, exit 0):
14 Python files parsed and compiled, seven performance JSON documents decoded
strictly (duplicate keys, decimals and nonfinite values rejected), all nine
schema `$ref` values resolved, no float constants or `float()` calls in
`accounting.py`, `quantity_model.py`, `kernel_identities.py`, `offline.py` or
`build_quantity_model.py`, and `catalog_coverage()` returned `[]`. Regenerating
`run-schema.json` and `quantity-model.json` twice produced byte-identical files;
three fresh interpreters produced identical constructed-summary SHA256
`53d4fe02092e4f9f3ab1de74f0242f3edebf2875f6a4967de8b0042809562e21`.

### Documentation

Both performance documents now state the corrected `oom` meaning, the removed
`oom_group_kill <= oom` identity, the surviving `oom_group_kill <= oom_kill`
containment, the one-way presence rule, the two torn-read policies, the
covered-pair audit scope and the updated 139/131/35/124/159 counts. Both retain
**no performance claim**, real runs **NOT_RUN** and `release_ready=false`.
`acceptance.json` was not edited.

### Preservation

`git diff --check` exits 0; the Git index is empty; branch `rust/v2` and HEAD
`e01661755097452952c1e4ca89dc4097d67c771f` are unchanged. No Git
stage/commit/push, review-file edit, acceptance edit or new unowned repository
write was made. All logs and evidence above are outside the repository under
`/tmp/opencode/task14-r6/`.

### Residual limits

The `oom` definitions and the system-wide OOM group-kill path are paraphrases
from knowledge of `Documentation/admin-guide/cgroup-v2.rst` and the kernel
implementation; they were not fetched or version-verified, so a future
reviewer must re-check them for the target kernel. Removing the false identity
does not add any new positive claim about `oom` versus `oom_kill` or
`oom_group_kill`. The covered-pair audit is finite and within-source: it does
not prove that every conceivable cross-source kernel relation is absent. The
`cpu.stat` first-sample exemption still over-refuses a later single-sample
tear; the `memory.events` containments have no read-order exemption and
deliberately over-refuse a one-sample tear; `oom_group_kill <= oom_kill` still
depends on the nonempty-victim assumption. Any cgroup with a nonzero
pre-existing or in-window OOM event remains contaminated and cannot qualify.
`pid_max` remains one unit looser than the native PID wrap, normalized idle
still requires producer iowait smoothing, and native page size, current
RLIMIT_NOFILE, pids.max, transient peaks, producer authenticity/alignment and
statistical independence remain unqualified. No real performance, release,
producer, runtime, client, ARM, migration or soak acceptance follows from this
round; all such gates remain **NOT_RUN** with **no performance claim** and
**release_ready=false**.

## Review round 7 disposition (controller, 2026-11-07)

Independent re-review `task-14-rereview6.md` (OpenCode DeepSeek v4.1 flash max): **PASS** — R6-I1
and R6-M1..M6 closed by reproduction; no Critical/Important findings. Minor findings fixed by the
controller:

- R7-M1: report hash for the round-6 `quantity-model.json` corrected above.
- R7-M2: `build_quantity_model.py` `relation_checks` now use exact operand extraction
  (`relation_operands`: dotted references, path rules, `present_sum` key lists) instead of substring
  matching; test `test_R7_M2_relation_checks_are_exact_operand_matches` (RED before, GREEN after).
  Regenerated `quantity-model.json` SHA256
  `c6a6b5ac1a592044b1601ec014c230b17ce7a23fbb90d58b356b6466e6a1a5f7`, byte-identical on regeneration;
  `run-schema.json` unchanged (`c2bf1f47...`).
- R7-M3: `test_R7_M3_import_time_coverage_runs_the_counter_pair_audit` asserts the import-time
  `coverage()` path reports a mutated covered pair; RED with the `counter_pair_problems` call removed,
  GREEN restored.
- R7-M4: the second presence policy (symmetric `presence_pairs`) is now documented in
  `performance-harness.md`.

The harness remains an offline preparation layer: no performance claim; real runs NOT_RUN;
release_ready=false.
