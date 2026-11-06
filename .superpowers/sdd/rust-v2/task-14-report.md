# Task 14: offline performance preparation

Status: REVIEW ROUND 1 FIXED / OFFLINE_PREPARATION_ONLY; final requested checks PASS, independent re-review pending. The original implementation and its failed-review history follow; the current evidence is in Review round 1 below. Base `cb91c79855fb1482e61f3becef6f8b71495e049e`, branch `rust/v2`, initially clean. No subagents, network, sudo, VM, service changes, long benchmarks, staging or commits. `release_ready=false`; `acceptance.json` must remain byte-identical.

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
| One-exit control PSS | 16777216 PASS | -1 B PASS | +1 B FAIL | INSUFFICIENT_DATA |
| Five-exit control PSS | 50331648 PASS | -1 B PASS | +1 B FAIL | INSUFFICIENT_DATA |
| Throughput baseline 1000 | 950 PASS | 951 PASS | 949 FAIL | INSUFFICIENT_DATA |
| p95 latency baseline 1000 | 1050 PASS | 1049 PASS | 1051 FAIL | INSUFFICIENT_DATA |
| Monitor misses, unexpected restarts, OOM, either side | 0 PASS | negative invalid | 1 FAIL | INSUFFICIENT_DATA |

These are synthetic arithmetic expectations, not measured product results. Conservative CPU read brackets can make a nominal counter ratio at 50% fail to demonstrate the bound; no uncertainty is rounded away.

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
