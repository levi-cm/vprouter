# Task 14 independent review

Verdict: **FAIL** — three Important findings and two Minor findings reproduced.
No Critical findings. This verdict concerns the offline preparation layer only;
no actual Python/Rust performance, guest, client, migration, or release acceptance
was exercised or inferred.

Reviewed 2026-11-06 in `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`, HEAD
`cb91c79855fb1482e61f3becef6f8b71495e049e`. Read the Task 14 brief/report directly
from the ignored directory, IMPLEMENTATION.md package 11, both performance docs,
new accounting/CLI/loopback/schema/fixture/tests, and the reused measurement
contracts. Treated the implementation report as unverified. Started no agents.

## Important findings (all REPRODUCED)

### I1. Rate conversion destroys exact threshold boundaries before rational comparison

Locations: `tools/performance/accounting.py:369`, `:371`, `:373`, `:446`;
`docs/rust-v2/performance-harness.md:194`.

The raw counter/duration fractions become binary floats in summaries. Later
`Fraction(str(value))` compares decimal renderings of those rounded floats, not
the original quantities. The advertised avoidance of float boundary rounding is
therefore false despite the arithmetic helper passing ordinary boundary tests.

Three independent raw-record reproductions, each with six matching repetitions
per side, 600 measured seconds, zero read uncertainty, valid source-specific
monitoring receipt shapes, and other gates passing:

- CPU: Python control CPU delta 200,000,000 us and Rust delta 100,000,000 us.
  Exact rates are 1/3 and 1/6 core: precisely 50% reduction, expected PASS.
  Summaries hold `0.3333333333333333` and `0.16666666666666666`;
  the supervision gate and one-exit steady scenario return **FAIL**.
- Throughput: Python 60,080 B and Rust 57,076 B. Exact ratio is 19/20,
  expected PASS. Rates become `100.13333333333334` and
  `95.12666666666667` B/s; throughput gate/scenario return **FAIL**.
- Large but permitted u64 counters: Python 18,000,000,000,000,000,000 B;
  Rust 17,099,999,999,999,999,999 B, exactly one byte below 95%.
  `100*C - 95*B == -100`, expected FAIL. Rounded rates produce throughput
  gate/scenario **PASS**. This is an input-domain test, not a physically claimed
  workload; the two ordinary-sized counter examples already establish the bug.

Keep numerator/denominator quantities exact through worst-run selection and gate
comparison, including conservative CPU read-duration bounds. Convert only
presentation values to floats. Do not repair this with an epsilon that accepts
just-outside values.

### I2. OOMs in measured observer/workload domains disappear from qualification

Location: `tools/performance/accounting.py:386` (iteration restricted to
`service`, ending at line 387).

Incremented `memory_events.oom` from 0 to 1 in all samples after the first in the
candidate's declared observer domain, keeping all members, counters, receipt
bindings, and remaining measurements valid. Repeated independently for the
workload domain. With six baseline/candidate records, both cases return:

- one-exit steady scenario: **PASS**;
- `oom_events` gate: **PASS**;
- reported worst candidate `oom_events`: **0**.

The same mutation in control, runtime/container, or Tailscale domains correctly
reports 1 and FAIL. The exclusion is therefore specific to nonservice domains,
not an unavailable-proof or repetition artifact. An instrument/workload OOM
contaminates the measurement even if no persistent sampled member disappears.
The input already contains the event; this is not a request to authenticate an
unrecorded producer assertion.

Retain OOM evidence from every declared measurement domain over the entire run,
including warm-up. Nonservice OOMs may be represented as contamination rather
than charged as service OOMs, but must prevent PASS.

### I3. Stable member CPU contradicts cgroup CPU yet qualifies as complete

Locations: `tools/performance/accounting.py:328` (process counter validation),
`:359` (accepted control delta), `:405` (process delta only reported).

For six candidate records, kept all control members and identities stable and
matching cgroup member lists. Their aggregate process CPU increases by 24,000
ticks at the declared 100 Hz over 600 seconds: 240 CPU seconds, or 0.4 core.
Every corresponding control cgroup CPU counter remains zero throughout.
All counters are finite, nonnegative, monotonic, and within bounds.

After updating the accounting record digest, each run summarizes as **PASS**,
reports supervision CPU **0.0**, and the six-repetition scenario and supervision
reduction gate also return **PASS** against the 1-core Python baseline. Thus
already-present evidence of expensive control work does not prevent a claimed
100% reduction from a contradictory zero counter.

Check a conservative per-domain lower bound from stable process tick deltas
against cgroup usage, allowing clock ticks/read brackets and boundary uncertainty.
Equality is unnecessary because cgroups also capture transient children. Reject
an impossible deficit rather than presenting such data as complete accounting.
This finding concerns internal consistency, not proof of producer authenticity.

## Minor findings (all REPRODUCED)

### M1. Malformed nested legacy evidence escapes the redacted failure protocol

Locations: `tools/performance/accounting.py:381`, `:385`, `:424`;
`tools/performance/offline.py:133`. Underlying dereference:
`tools/performance/measurement.py:352` (existing reused contract).

Set `runtime_evidence.monitoring.router_cycles = [null]` in an otherwise valid
synthetic-in-memory Python record. `summarize` raises uncaught
`AttributeError: 'NoneType' object has no attribute 'get'` instead of returning
INSUFFICIENT_DATA. Running the actual offline CLI on a scratch file reproduces
exit **1**, empty stdout, and a traceback containing absolute repository/source
paths. The input-file pathname itself was not present in that traceback.

Validate nested item types before dereferences and preserve the adapter's fixed,
redacted INSUFFICIENT_DATA response for malformed supported JSON inputs. Ordinary
parser rejection tests do not exercise this inherited exception path.

### M2. Float medians falsely mark identical large integers as outliers

Locations: `tools/performance/accounting.py:189`, `:200`.

`describe([9007199254740993] * 6)` reports median `9007199254740992.0`, MAD 0,
and flags all six identical observations as outliers. A singleton or six copies
of `2**64-1` similarly reports median `1.8446744073709552e19` (2**64, beyond the
accepted u64 maximum) and flags every observation. Inputs are expressly allowed
by the statistics validator. No observation can be an outlier from an identical
constant sample, including at n=1.

Preserve integer/half-integer median precision for supported values or explicitly
reject/document a narrower statistics domain. The ordinary-valued CI ranks,
nearest-rank percentiles, and raw MAD definition passed independent checks;
this finding concerns numeric representation and diagnostic accuracy.

## Independent oracle and requirements assessment

The comparator oracle was written from IMPLEMENTATION.md:77-79 and the explicit
Task 14 brief, independently of the implementer's threshold tests. Only the
pre-existing schema-2 test module's monitoring-receipt generators were reused to
exercise the complex inherited receipt contract; raw accounting records,
threshold expectations, mutations, CI calculations, and parser probes were
independently constructed under `/tmp`.

Binding interpretation checked:

- CPU reduction is at least 50% versus a newly measured, matched Python
  **supervision/control CPU quantity**, not versus total Python service CPU,
  Tailscale CPU, a configured CPU limit, or historical uncontrolled samples.
  The implementation aggregates domains containing only supervision/workers/
  guard/init_shim. The brief makes the CPU reduction gate one-exit specific.
- Total service memory must be <= baseline; targets are candidate control PSS
  <=16 MiB for one exit and <=48 MiB for five. No invented six-exit PSS target.
- Throughput >=95% baseline (higher is better); p95 latency <=105% baseline
  (lower is better); zero monitor misses, unexpected restarts, and OOMs on
  either side. All threshold equalities are inclusive.
- Repeated >=600-second measured post-warm-up windows for steady/load 1/5/6;
  six matched repetitions per side is this preparation layer's documented
  stricter policy. Worst candidate versus best baseline is conservative.

438 independent arithmetic-helper cases covered each numeric threshold at,
inside, outside, missing/invalid; both event sides; 1/5/6 applicability; and
zero/tiny baseline handling. These helper results matched the oracle. I1 is in
raw-to-summary conversion before that helper, a gap not caught by its mutation
corpus. All claimed reproduced scenario PASS/FAIL results here concern the
one-exit steady shape; the **whole suite remained INSUFFICIENT_DATA**, because
other shapes were deliberately absent. No complete-suite or real-runtime PASS
is asserted. The documented inherited Python six-exit/direct restriction remains
blocking and was not bypassed.

## Verification ledger

| Check | Fresh result and limits |
| --- | --- |
| `python3 -B -I -m unittest discover -s tools/performance -p test_accounting.py` | PASS, **22 tests**, 26.068s, exit 0. |
| `python3 -B -I -m unittest discover -s tools/performance -p test_accounting_mutations.py` | PASS, **2 tests**, 0.616s, exit 0. |
| `python3 -B -I -m unittest discover -s tools/performance -p test_offline.py` | PASS, **5 tests**, 0.151s, exit 0. |
| Independent scratch corpus | `python3 -B -I /tmp/task14-independent-review.py`, exit 0; 438 helper-oracle cases; reproduced I1/I2 and direct I3/M1 paths. Structured results `/tmp/task14-independent-results.json`. |
| Follow-up adversarial checks | `python3 -B -I /tmp/task14-review-followup.py`, exit 0; I3 scenario, M1 actual CLI, M2, publication races, schema closure, fresh-interpreter determinism. Results `/tmp/task14-review-followup-results.json`; log `/tmp/task14-review-followup.log`. |
| Outlier retention | `python3 -B -I /tmp/task14-outlier-check.py`, exit 0. One candidate p95=106 ns versus five at 100 retained as outlier, n=6; gate/scenario FAIL against baseline 100 ns. Results `/tmp/task14-outlier-results.json`. |
| Statistics | Independent exact binomial enumeration for n=1..100 matches CI ranks; nearest-rank p95/p99 match; n<6 null CI, n=6 range, n=20 [6,15]; raw unscaled MAD=1.5 for [1,2,3,4,5,100]. No Gaussian MAD scaling is claimed or required. Ordinary zero-MAD outliers retained. M2 remains. |
| Missing/invalid/raw inputs | Independent probes reject omitted process, null PSS, missing CPU counter, unknown field, short window, missing sample, 32-bit ticks, process reset, thermal threshold, swap, unknown temperature, absent runtime proof, NaN, negative, u64 overflow, omitted component. Mismatched host/config/workload/Tailscale/instrumentation and fewer than six repetitions are insufficient. |
| Process coverage | Removing a process while keeping cgroup members prevents PASS and cannot yield a qualified reduced PSS. Component deletion also refused. Unobserved/dishonest producer data still require the documented future producer/original-evidence review; I3 involves an observed contradiction. |
| Native parsers | Independent reordered smaps fields and stat comm containing spaces/nested/trailing parentheses parse correctly. Duplicate smaps keys, wrong units, large overflow, and 32-bit tick overflow refused. Existing tests add cgroup units/duplicates/reset and other boundaries. There is no new `/proc/PID/status` consumer/parser to qualify; threads come from stat, wakeups from sched, fds from entry enumeration. |
| Strict JSON and AST | All **10** `tools/performance/*.py` parse with ast; strict decode of schema, synthetic fixture, three baseline/source JSONs, acceptance ledger (**6 JSON files**) succeeds. Duplicate keys, nonfinite/overflow, and depth>32 negative probes reject. Named schema object fields are required/closed. No third-party JSON Schema validator run; Python semantic validation is normative. |
| Loopback confinement/resource bounds | Instrumented real self-test with 20 iterations: every bind/connect/sendto address asserted literal 127.0.0.1; resolver calls made fatal; SELF_TEST_PASS with performance_evidence=false and release_ready=false. Source bounds 1..20, 0.1s socket timeouts, checked 2s deadline; no configurable external target. No outside-network call made. |
| Atomic publication | Supplied tests pass exclusive create, permissions 0600, file/directory fsync order, no overwrite, symlink refusal, competing publishers, failure cleanup. Additional real temp-dir races: creating destination just before rename preserves existing bytes; renaming parent and replacing its pathname with a symlink still publishes to pinned original directory, not redirected directory. No defect reproduced under documented private/approved output-directory use. |
| Determinism | Reversing both raw argument lists yields byte-identical canonical comparison output. Three fresh `-B -I` interpreters yield identical fixture summary bytes. |
| Documentation honesty | Actual baseline/candidate absent and all real performance gates NOT_RUN are explicit; runner is SPEC ONLY; self-test cannot qualify traffic; no optimization/performance/release claim. Threshold numbers/directions and absent six-exit PSS target correct. Exact-rate-rounding claim contradicted by I1. |
| Acceptance preservation | Acceptance file byte-identical to `git show HEAD:docs/rust-v2/acceptance.json`; SHA256 `3d467451dd03d1663e3c79b24eea6a18aac461f9291f8fdfe1031e1da6e86e97`; release_ready=false. |
| Checkout preservation | `git diff --check` passes; branch/HEAD and original tracked/untracked task file inventory unchanged. Only repository write by this review is this ignored report. No git writes, staging, commit/push, sudo, VM, service operation, benchmark, or delegation. |
| Real workloads/platform/release | **NOT_RUN**, explicitly outside authorization and this offline preparation review. No 10-minute wall-clock benchmark was performed; 600s fixtures are constructed timestamps. No broader Rust build/test run needed for Python/docs-only review. |

Scratch reproduction scripts (all outside repository):

- `/tmp/task14-independent-review.py`, SHA256 `9a99c6e63dcab9bfa3f119593ac6aeae2b8ca77e3e19df97bbc191b37873cca7`.
- `/tmp/task14-review-followup.py`, SHA256 `b3432b39a24fac288507f9ae738fb0d14cbdb8650d6001aaff45574ffeed5108`.
- `/tmp/task14-outlier-check.py`, SHA256 `096c546f49b56a695e41e8106d5a9e6267f96fe9b08a3da68b4d32651696f564`.

No source fixes were made. Address I1-I3 and rerun the independent raw-record
reproductions before accepting this offline layer. Real performance and release
gates remain NOT_RUN regardless of the offline review outcome.
