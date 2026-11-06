# Task 14 independent re-review

Verdict: **FAIL — three Important findings REPRODUCED.** No Critical findings.
The five original scenarios are fixed, but the claimed redundant-quantity class
closure is incomplete. This verdict applies to the **offline preparation layer**.
It says nothing about actual Python/Rust performance or runtime/client/migration/
release acceptance; those remain **NOT_RUN / OPEN**, with `release_ready=false`.

Reviewed 2026-11-06, `/DATA/AppData/vprouter-rust-v2`, `rust/v2` at
`cb91c79855fb1482e61f3becef6f8b71495e049e`, including uncommitted Task 14 sources,
both performance docs, the brief, IMPLEMENTATION.md WP11, original failed review,
and implementation report including Review round 1. Started no agents. The only
repository write by this re-review is this report. All independent scripts,
constructed records, results and logs are in `/tmp`; all Python commands use
`python3 -B -I`. No source fixes, sudo, external network, VM/service operations,
Git writes, or long benchmarks were performed. The requested `test_offline.py`
includes its built-in bounded literal-127.0.0.1 socket self-test; no product or
external traffic was generated.

## Important findings — all REPRODUCED

### R-I1. Per-interval CPU tolerance accumulates into a false full-run reduction

Locations: `tools/performance/accounting.py:275`, `:281`, `:282`, `:493`, `:517`.

The reconciliation compares only adjacent samples. It grants the full endpoint
quantization allowance again for every pair, without checking the stable
processes against the cgroup over the measured window. Tick quantization at the
first/last endpoints cannot explain an error that grows with the sample count.

Fresh independent raw reproduction, six repetitions on each side:

- 601 samples at 1-second cadence, 600 measured seconds, 100 Hz ticks, four stable
  control members, zero read-bracket width, no exited CPU, complete new residual
  and failure evidence, and valid original Python/Rust monitoring receipt shapes.
- Python control CPU is 6,000,000 us: 0.01 core. Candidate control cgroup CPU is
  identically zero. The candidate supervision process nevertheless gains one
  tick each second, totaling 600 ticks / **6 CPU seconds**. Other control members
  stay at zero. Host busy counters reconcile with the declared cgroup totals.
- Each local 10,000-us discrepancy fits the allowance of
  `2 * 4 * 1,000,000 / 100 = 80,000 us`. Across the full stable window the
  unexplained deficit is **6,000,000 us**, versus the same **80,000-us** endpoint
  allowance. Read skew and transient CPU cannot explain it.
- Every baseline and candidate raw summary returns **PASS**. The one-exit steady
  scenario and supervision gate return **PASS**, reporting candidate CPU **0**
  and an apparent 100% reduction despite observed member CPU equaling baseline.

The actual offline CLI comparison also publishes that scenario PASS. Its overall
exit/status is **2 / INSUFFICIENT_DATA** because the other suite shapes are absent;
this is not a claimed complete-suite PASS.

Add an anchored/full-window reconciliation for stable identities and original
exited-CPU evidence, using the endpoint-derived quantization/read-skew bound.
Retain local checks, but do not sum their rounding allowances as a full-run bound.
The same issue can affect whole-host tick reconciliation, which also grants a
fresh allowance on each pair; only the concrete member/cgroup case above is
asserted here.

Reproduction: `/tmp/task14-rereview-originals.py` (`NEW_accumulated_CPU_tolerance`)
and `/tmp/task14-rereview-suite.py` (actual CLI comparison).

### R-I2. IRQ/softirq CPU can exceed the whole-host busy total and still qualify

Locations: `tools/performance/accounting.py:301`, `:303`, `:308`, `:495`, `:503`;
contract: `docs/rust-v2/performance-harness.md:162`.

The documented host busy total includes IRQ and softirq ticks. Those already
recorded components are checked for monotonicity, but never bounded by that total.
The new host/domain/outside-CPU equation therefore accepts mutually impossible
kernel CPU evidence.

Fresh independent raw reproduction, separately for IRQ and softirq, each with six
matching baseline/candidate repetitions, 61 aligned samples over 600 seconds,
100 Hz ticks and zero read uncertainty:

- Candidate host busy delta: **26,400 ticks = 264 CPU seconds**, exactly equal to
  all declared domain CPU; outside-host CPU is zero.
- Set just `irq_ticks`, then independently just `softirq_ticks`, to increase by
  1,000 ticks per ten-second interval: **60,000 ticks = 600 CPU seconds** overall.
  Each is a subset of the advertised busy total, yet exceeds that total by
  **33,600 ticks**. This is not a possible quantization/read-bracket difference.
- All candidate summaries and the one-exit steady scenario return **PASS**, with
  no contamination or contradiction reason.

Cross-check recorded IRQ+softirq against whole-host busy CPU under the same
clock/units, with an acquisition-derived bound where needed. Refuse impossible
subset totals; do not add IRQ CPU to service totals and double count it. This is
an internal contradiction in available evidence, not a request to authenticate
an unobserved kernel producer.

Reproduction: `/tmp/task14-rereview-subsets.py`, `irq_ticks` and `softirq_ticks`.
The complete suite remains insufficient because unconstructed shapes are absent.

### R-I3. Aggregate PSS exceeds host RAM while the memory scenario passes

Locations: `tools/performance/accounting.py:263`, `:267`, `:299`, `:484`, `:521`,
`:554`.

The reconciliation bounds each process RSS and the sum of cgroup charges by host
RAM, but omits the aggregate PSS bound. Unlike summed RSS, proportional resident
memory apportions shared pages: summed PSS for a subset of processes cannot
materially exceed all host RAM at an aligned instant. This reproduction uses
zero read skew, zero swap, and a gross excess, so page rounding or changing
observations do not explain it.

Fresh independent raw reproduction, six candidate and six baseline repetitions:

- Host RAM: **1,024 MiB**. Keep control PSS at **8 MiB** and simultaneous service
  cgroup charges at **60 MiB**; all domain charges including observer/workload
  total 64 MiB. Existing USS/residual and memory.stat reconciliations remain exact.
- Set only the container and tailscaled processes to **600 MiB PSS/RSS each**.
  Each individual process satisfies `USS <= PSS <= RSS <= host RAM`.
- Service process PSS is now **1,208 MiB**; all recorded process PSS is
  **1,210 MiB = 1,268,776,960 B**, exceeding the 1,073,741,824-B host. The input
  process inventory, domain membership and all identities remain stable.
- Every candidate summary returns **PASS**. Total-memory gate, control-PSS gate
  and one-exit steady scenario all return **PASS**. The contradictory large
  Tailscale/runtime resident footprint does not prevent qualification.

Check aggregate PSS against the physical host ceiling under the required aligned
acquisition/rounding contract. Preserve the distinction between PSS, duplicated
RSS and cgroup charge ownership; this finding does not require equating PSS with
cgroup charges or substituting RSS for PSS.

Reproduction: `/tmp/task14-rereview-subsets.py`, `aggregate_PSS`. Complete-suite
status remains insufficient because other shapes are absent.

## Original findings: exact scenarios freshly re-run

`/tmp/task14-rereview-originals.py` independently constructs raw recordings with
the revised mandatory fields. Existing schema-2 receipt generators from
`test_measurement.py` supply only the complex original monitor receipt shapes;
no Task 14 fixture, reconciliation helper, threshold test or oracle is imported.
Each positive recording is qualified before mutation. Old scratch scripts were
not relabeled as passing against an incompatible schema.

| Earlier finding | Fresh result |
| --- | --- |
| I1 CPU equality: 200,000,000 / 100,000,000 us over 600s | **FIXED**: exact 1/3 and 1/6 core, gate/scenario PASS. |
| I1 throughput equality: 60,080 / 57,076 B | **FIXED**: exact 95%, gate/scenario PASS. |
| I1 large throughput: 18,000,000,000,000,000,000 / 17,099,999,999,999,999,999 B | **FIXED**: one byte below 95%, gate/scenario FAIL. |
| I2 observer/workload OOM | **FIXED**: independently inject oom, oom_kill and oom_group_kill; count retained as 1, OOM gate FAIL, scenario INSUFFICIENT_DATA. |
| I3 stable process gains 24,000 ticks while cgroup stays zero | **FIXED for original case**: cpu_accounting_contradiction, scenario INSUFFICIENT_DATA. R-I1 shows remaining class gap. |
| M1 legacy router_cycles=[null] | **FIXED**: actual subprocess exit 2, fixed redacted INSUFFICIENT_DATA stdout, empty stderr, no output file. |
| M2 identical huge integers | **FIXED**: n=1/6 for 2**53+1 and 2**64-1 retain exact median and no outliers. |

## Independent spec oracle

Written afresh in `/tmp/task14-rereview-oracle.py` from IMPLEMENTATION.md WP11,
Task 14 brief and the explicitly documented conservative qualification policy,
without reading/importing the implementer's threshold tests as an oracle.
Fixed property seed: **0x14B791**.

The equations independently require candidate supervision CPU <= half the Python
**supervision** CPU for one exit; total memory <= baseline; candidate control PSS
<=16/48 MiB for one/five; throughput >=baseline-baseline/20; p95 latency
<=baseline+baseline/20; and zero misses/restarts/OOM on both sides. Equalities are
inclusive. There is no invented six-exit CPU/PSS target. Unknown/invalid metrics
and documented tiny/zero baselines are insufficient, with insufficient status
precedence over a separate failed gate. CPU uses baseline lower and candidate
upper duration bounds. Worst candidate is compared with best baseline, with all
outliers retained.

- **12,036 exact metric cases**: every shape (1/5/6 exits x steady/load), every
  gate, both sides, equality and +/-1 integer or raw-rate unit, small scales,
  2**53+1, 2**63 and u64 maximum; fractions with large numerators; missing/null,
  bool/float/string/Decimal/object aliases, overflow, nonfinite and zero/tiny
  cases; plus 1,600 fixed-seed random vectors per shape. All gates and verdicts
  match the independent oracle.
- **350 randomized full-suite comparator cases**, each using 72 compact
  summaries, compare all six scenario verdicts and the suite verdict with the
  independent worst/best oracle. Unknown quantities never become PASS.
- **126 full-suite single-gate boundary cases** isolate equality/inside/outside
  so another failure cannot mask a wrong threshold. Per-scenario gate maps and
  suite verdicts match the oracle, including 1/5/6 applicability.
- **72 separately bound raw synthetic recordings**: six repetitions per side
  per shape. One/five-exit steady/load scenarios PASS; both six-exit scenarios
  remain **INSUFFICIENT_DATA**, because Python legacy receipts cannot represent
  the required direct exit. Whole suite is therefore INSUFFICIENT_DATA.
- To exercise six-exit arithmetic and possible full-suite PASS independently
  from that known source restriction, the 350+126 comparator-only cases use
  **hypothetically qualified compact summaries** for six-exit Python. These are
  not raw-qualified evidence; no monitor validator was changed or bypassed in
  the raw tests. All 72 'runs' above are constructed records, not real runs.

Threshold arithmetic passes this independent oracle. The evidence-qualification
oracle must refuse the three internally contradictory inputs in R-I1–R-I3;
the implementation instead accepts their scenarios. Thus the overall re-review
fails even though arithmetic comparison itself agrees.

## Fresh adversarial sweep and verification ledger

| Check | Result and practical limit |
| --- | --- |
| `python3 -B -I -m unittest discover -s tools/performance -p test_accounting.py` | **PASS**, exit 0, **36 tests**, 52.001s. `/tmp/task14-rereview-accounting.log`. |
| `python3 -B -I -m unittest discover -s tools/performance -p test_accounting_mutations.py` | **PASS**, exit 0, **2 tests**, 0.851s. `/tmp/task14-rereview-mutations.log`. |
| `python3 -B -I -m unittest discover -s tools/performance -p test_offline.py` | **PASS**, exit 0, **7 tests**, 21.570s, reported **7,652** schema/failure-protocol cases. `/tmp/task14-rereview-offline.log`. |
| Original cases / new CPU variant | `python3 -B -I /tmp/task14-rereview-originals.py`, **exit 0**. Structured results `/tmp/task14-rereview-originals-results.json`. All five original findings' scenarios fixed; R-I1 reproduced. |
| Independent oracle | `python3 -B -I /tmp/task14-rereview-oracle.py`, **exit 0**; 12,036 metric +350 randomized suite +126 isolated boundary cases. `/tmp/task14-rereview-oracle-results.json`, log of same stem. |
| Fresh semantic/type/failure sweep | `python3 -B -I /tmp/task14-rereview-adversarial.py`, **exit 0**; **1,735** numeric alias probes at independently selected nested leaves, all refused; **45** role x failure-signal cases plus **30** all-cgroup warm-up OOM variants. `/tmp/task14-rereview-adversarial-results.json`. The type sweep samples first/last list elements and is not an exhaustive JSON-space proof. |
| Decimal/Fraction/string/JSON injections | Raw values cannot coerce to measurements. Tagged objects, strings, zero denominator, overflowing numerators, zero/bool durations and underflow floats refuse. Fractions are permitted only in derived Python arithmetic APIs; raw JSON cannot instantiate them. Five additional real CLI numeric mutations return redacted exit 2 with no result/temp file. |
| Remaining floats: grep + trace | `accounting.py` has one true division, its Fraction median /2 at line 192. Rate/bound/selection/gate paths remain exact. `offline.py:27` still parses JSON decimals using float; all probed raw numeric uses refuse them. Reused monitoring replay has integer arithmetic; old float traffic/enrichment/number paths are made fatal in 12 fresh shape checks and are not reached. No remaining floating verdict defect reproduced. |
| Bounded huge inputs | 200,000-digit integer and positive exponent reject; negative exponent decodes to finite float zero but cannot qualify a raw integer. Each parser probe finishes below 0.007s on this host. Depth 33, nested duplicate keys and u64 overflow reject. This is bounded input testing, not an unbounded DoS proof. |
| Units / PSS vs RSS | Native kB converts by 1024; KiB/MiB/KB/kb/B tokens refuse. Missing PSS/USS with valid RSS remains insufficient. No RSS fallback. R-I3 separately reproduces missing aggregate-PSS physical bound. Mislabeling an otherwise plausible numeric producer value cannot be authenticated by an analyzer alone. |
| Expensive components / domain overlap | Explicit guard/tailscaled removal, omitted recorded member and unavailable kernel accounting refuse. Equal native identity, equal scope and parent/child scope refuse. A dishonest producer's undeclared process/cgroup remains a producer-review issue; no such unrecorded assertion is used as a blocking finding. |
| Gaps / wrap / resets / reconciliation | Sampling gap; process/cgroup/host counter regression; unsupported 32-bit ticks; service/observer/workload counter resets; both-direction memory/I/O/pids/large CPU mismatches refuse. Small repeated CPU errors escape as R-I1. Recorded kernel subset contradictions escape as R-I2. |
| 72-record matching and ordering | `python3 -B -I /tmp/task14-rereview-suite.py`, **exit 0**, **27** matching/contamination/outlier checks plus **20** fixed-seed argument permutations. Missing/duplicate/unmatched repetitions, duplicate raw/run identity, wrong implementation, same-host/host-contract/source/artifact/workload/config/peer/network/Tailscale/instrumentation/accounting/coverage changes, same-boot overlap/equal endpoints and unknown/invalid input cannot qualify. Results `/tmp/task14-rereview-suite-results.json`. |
| Outlier retention | One candidate p95=106 vs five at 100 remains an outlier and makes the p95/scenario FAIL. No median-based exclusion. |
| Subset contradictions | `python3 -B -I /tmp/task14-rereview-subsets.py`, **exit 0**; IRQ, softirq and aggregate PSS scenarios all wrongly PASS. `/tmp/task14-rereview-subsets-results.json`. |
| Integer statistics | Independent exact-binomial enumeration for n=1..100 agrees on median CI ranks, exact medians, nearest-rank p95/p99; original huge-constant outlier cases fixed. No Gaussian MAD scaling or traffic-sample independence is inferred. |
| Determinism | 20 complete raw-summary argument permutations give identical canonical bytes. Three actual CLI/fresh-interpreter summaries give identical bytes. Note: `-I` ignores PYTHONHASHSEED, so the latter proves fresh-interpreter determinism, not controlled hash-seed values. |
| Atomic publication | Supplied tests pass. Fresh late destination race preserves old bytes and removes temp; parent rename+symlink replacement publishes only into pinned original directory; file remains 0600; injected directory-fsync failure retains renamed bytes with reported failure as documented. No publication defect reproduced for the documented output-directory contract. |
| JSON / AST / schema | `python3 -B -I /tmp/task14-rereview-static.py`, **exit 0**. **10** Python ASTs, **6** strict JSON files (schema, synthetic fixture, three historical baseline/source files, acceptance), **21** closed named schema objects and **9** resolved refs. Fixture fields agree; semantic reasons exactly missing_runtime_evidence/short_run/synthetic_evidence. No third-party JSON Schema validator installed/run; Python semantics are normative. `/tmp/task14-rereview-static-results.json`. |
| Preservation | Branch/HEAD unchanged; git diff --check and git diff --cached --quiet pass. Original tracked/untracked task inventory retained. Acceptance HEAD-identical, SHA256 `3d467451dd03d1663e3c79b24eea6a18aac461f9291f8fdfe1031e1da6e86e97`, release_ready=false. Original review SHA256 `5537c2c4dc79f1250785da49322e5addebffa0aaf88bb63f91ebed6441e7212c`. Reviewed input hashes: `/tmp/task14-rereview-reviewed-hashes.json`. |
| Runtime / producer / real 72 runs / platform / release | **NOT_RUN**, outside this offline review. No 600-second wall-clock benchmark, Rust build, guest collection, credential operation, tuning, migration, soak or release qualification. All raw times and receipt shapes are constructed synthetic input-domain tests, even where a schema field says actual_runtime to reach validation. |

## Minor notes / residual limits

No additional Minor defect is asserted. Producer authenticity, sample alignment,
unobserved transient/ABA activity or memory peaks, actual kernel counter semantics,
independent repetition power and the six-exit Python direct adapter remain future
producer/runtime gates. They were not independently qualified here and are not
promoted into reproduced findings. Hashes and residual declarations cannot prove
honest acquisition; the three Important findings instead use contradictions
already present in the submitted data.

Fix R-I1–R-I3 and re-run their independent raw cases before accepting this offline
layer. Real benchmark and release gates remain NOT_RUN regardless of that result.

Scratch script SHA256 values:

- common.py: `c7bfd265600b44d46596d978a841ae95dbaf85ff9188101374971335c5cb93f3`
- originals.py: `bc8a998fc9b40b515b382c8bf1c6bb2fb4742ba1f8e6e226e6bf15108063f993`
- oracle.py: `b003ab7cf93c6ed0db5a4e410c5ea7273db3776521ecfa733fa5f0cf3b19af23`
- adversarial.py: `b815446f479f5cf6c170a7b9b89d141ee807198d91776f0839f65747a334efab`
- suite.py: `97e92f7b74d5ea01b6c1827f25e044f9209a9a0fdfe5ff3341da8fd19cd88b47`
- subsets.py: `c2041ab0a5fd01ad3af8101b9d08866ac0e0f924ca25d2afa589e9eebb35dc97`
- static.py: `3f046f26397cf46f67e07380bc905115e110e419afb3c11a47726160be4f26cf`

All names above have prefix `/tmp/task14-rereview-`.
