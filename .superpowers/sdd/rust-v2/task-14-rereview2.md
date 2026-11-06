# Task 14 independent review — round 3

Verdict: **FAIL — four Important findings, all REPRODUCED.** No Critical findings.
The earlier specific defects are fixed. The 44-family invariant registry is
executable, but incomplete: contradictory raw recordings still qualify and
publish. This verdict concerns the **offline preparation layer only**. Runtime,
client, migration, benchmark and release acceptance remain NOT_RUN / OPEN;
`release_ready=false`. No runtime evidence is demanded by this review.

Reviewed 2026-11-06 in `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`, HEAD
`cb91c79855fb1482e61f3becef6f8b71495e049e`, including the uncommitted Task 14 work,
brief, both earlier reviews, implementation report including both review rounds,
both performance documents and IMPLEMENTATION.md WP11:77–79. Started no agents.
Only this report was written in the repository. Scripts, constructed inputs,
results and logs are under `/tmp/task14-rereview2-*`. No sudo, external network,
VM/service actions, Git writes, source fixes or long benchmarks. The requested
`test_offline.py` includes its bounded literal-loopback socket self-test; there
was no external traffic. All displayed 600-second timelines are constructed
input records, not wall-clock runs or authentic runtime evidence.

## Important findings — REPRODUCED

All counterexamples below use the earlier independent raw builder, adapted only
for the new mandatory acquisition fields. Each has 61 samples over 600 measured
seconds, 100 Hz counters, four declared logical CPUs, zero acquisition width,
stable process/domain identities and valid original monitor receipt shapes.
Six matched Python/Rust repetitions qualify the one-exit steady scenario.
All eight arithmetic gates PASS, the raw summaries PASS, and no registered
predicate fails. Other shapes are deliberately absent, so the **whole suite is
INSUFFICIENT_DATA**. A scenario PASS is not reported as a whole-suite PASS.

### T3-I1. Missing host CPU time passes the one-sided capacity check

Locations: `tools/performance/accounting.py:47`, `:408`, `:471`–`:472`;
`tools/performance/test_accounting_mutations.py:153`–`:155`;
`docs/rust-v2/performance-harness.md:170`–`:181`.

`cpu_capacity` and `host_boot_cpu` check only upper bounds. Set `idle_ticks=0`
throughout each otherwise qualifying recording. Every domain/member/host-busy
reconciliation remains exact, but the total CPU clock is grossly incomplete:

- Candidate: busy+idle advances **26,400 ticks = 264 CPU seconds**, versus
  **240,000 ticks = 2,400 CPU seconds** for 600 seconds on four CPUs. Deficit:
  **213,600 ticks**, compared with the stated endpoint allowance of **64 ticks**.
- Independently mutate the Python side: total advances only **62,400 ticks =
  624 CPU seconds**, a **177,600-tick** deficit. Its legacy CLOCK_MONOTONIC ↔
  BOOTTIME brackets retain a constant offset to within 20 ns across the complete
  window. The missing hundreds of awake seconds cannot be explained by suspend.

Both sets of six raw summaries and their comparison scenarios PASS. The actual
CLI `summarize --output` exits **0**, writes the PASS summary and emits no stderr
for each representative. This also shows that an internally unqualified baseline
can qualify the comparison, not just a candidate.

Require two-sided total-clock conservation under a verified online-CPU and
awake-clock contract, with endpoint quantization/read uncertainty. If suspend or
CPU history prevents a lower bound, retain that uncertainty as insufficient;
BOOTTIME alone is not evidence that all elapsed time was available CPU time.
The current signed tests both construct an *excess* above the upper bound; they
do not exercise missing total ticks.

Reproductions: `lost_idle`, `lost_idle_python` in
`/tmp/task14-rereview2-probes.py`; raw representative files of the same names.

### T3-I2. Impossible cumulative process/cgroup CPU is hidden by valid deltas

Locations: `tools/performance/accounting.py:408`, `:424`–`:425`, `:445`,
`:478`–`:499`.

The new boot/lifetime checks bound each counter separately by uptime capacity;
all host/member/cgroup conservation checks still compare **deltas only**.
A constant contradictory offset therefore survives every anchored prefix.

In every candidate sample:

1. Add **2,000,000,000 us** to control cgroup usage and user CPU; add the equivalent
   **200,000 ticks** to the supervision process's cumulative user CPU.
2. Give host busy/user a **10,000-tick** initial offset (100 CPU seconds), and
   set idle so host busy+idle equals exactly `BOOTTIME * 4 * 100` at every sample.
3. Keep all original deltas, cgroup user+system equations, memory, traffic and
   monitor receipts unchanged; rebind the accounting digest.

At the first sample, BOOTTIME is **2,000 seconds**. The supervision process and
its cgroup each claim **2,000 CPU seconds**, while the entire host has recorded
only **100 user/busy CPU seconds since boot**. At the final sample those claims
are 2,240 seconds versus host busy/user **364 seconds**. Process/cgroup CPU is
below the independent 8,000/10,400-second uptime ceilings; host total time is
exact. Nevertheless no process can have accumulated twenty times the whole
host's user CPU. Process migration between cgroups does not explain a process
counter exceeding the entire host counter.

All six candidate summaries and the scenario PASS; actual CLI publication exits
**0**, writes a PASS summary and has empty stderr.

Add snapshot-level member/host and disjoint-cgroup/host cumulative subset checks,
with the correct class and endpoint uncertainty, in addition to the existing
interval reconciliation. Do not require process lifetime CPU to equal the current
cgroup lifetime counter: migration makes that stronger equation unjustified.

Reproduction: `snapshot_cpu` in `/tmp/task14-rereview2-probes.py`;
`/tmp/task14-rereview2-snapshot_cpu.json`.

### T3-I3. Accepted native subfields can contradict their containing totals

Locations: `tools/performance/accounting.py:277`–`:280`, `:449`–`:451`,
`:486`; `tools/performance/run-schema.json:237`–`:253`;
`tools/performance/test_accounting_mutations.py:329`–`:349`.

The native counter maps accept bounded extensions, but the registry checks only
selected required fields. Independently set the following known memory.stat
fields in the control domain at **every** sample:

| Present field | Submitted amount | Present containing field |
| --- | ---: | ---: |
| `shmem` | 600 MiB | `file = 0` |
| `anon_thp` | 600 MiB | `anon = 20 MiB` |
| `kernel_stack` | 600 MiB | `kernel = 0` |
| `slab` | 600 MiB | `kernel = 0` |

The containing cgroup's memory.current remains **20 MiB**. Each mutation
separately produces six PASS raw summaries, a PASS scenario, no failed registered
predicate, and a CLI-published PASS summary (exit 0, empty stderr). Existing
anon+file+kernel+residual reconciliation and host-RAM ceilings remain unchanged.
These are recorded native byte gauges, not additional memory to sum again.

A second independently reproduced variant adds native cpu.stat fields
`nr_periods=j`, `nr_throttled=100*j` to each sample. Final counters claim
**6,000 throttled periods out of 60 total periods**. All six summaries and the
scenario PASS. Both fields are in range and monotonic; that does not make their
relationship possible.

Enforce the supported native subfield relationships or refuse unrepresented
native fields/semantics. Include optional map keys in the independent invariant
corpus. The current numeric-leaf sweep traverses keys present in two fixtures;
it does not enumerate these accepted native subfields. Its expected-violation
check also calls the production `physical_constraints`, so it cannot discover a
missing physical relationship independently.

Reproductions: `shmem`, `anon_thp`, `kernel_stack`, `slab` in
`/tmp/task14-rereview2-probes.py`; CPU variant in
`/tmp/task14-rereview2-cpu_periods.json` and corresponding results JSON.

### T3-I4. Completed block-I/O bytes with zero operations qualify

Locations: `tools/performance/accounting.py:298`–`:304`, `:504`–`:514`;
`docs/rust-v2/performance-harness.md:207`–`:215`.

Per-device equality is enforced independently for each counter. There is no
relationship between completed bytes and operation counts within the same
submitted native I/O tuple.

For device `8:0`, set the supervision process's and control cgroup's `rbytes`
to `sample_index * 1 MiB`, leave `rios=0` throughout, and keep the independently
recorded `io_other` counters zero. Repeat independently for `wbytes/wios`, and
for optional `dbytes/dios`. Each counter starts at zero, is monotonic, remains
within u64 and reconciles exactly between members, residual and cgroup.

At the end each variant reports **60 MiB of completed block I/O and zero
corresponding operations over the entire 600 seconds**. Under this contract's
explicit completed-I/O semantics and exact aligned observations, that tuple is
contradictory. This does not compare logical syscall bytes with physical bytes
or assume an unknown device bandwidth ceiling.

Each variant produces six PASS candidate summaries, all eight scenario gates
PASS, no failed registry predicate, and an actual CLI-published PASS summary
(exit 0, empty stderr).

Validate supported byte/operation relationships at aligned snapshots and under
the reviewed native acquisition semantics. Do not impose an arbitrary disk
throughput limit or invent one from elapsed time.

Reproductions: `read_bytes_no_ops`, `write_bytes_no_ops`, `discard_bytes_no_ops`
in `/tmp/task14-rereview2-probes.py`, with raw representatives of the same names.

## Earlier reproductions freshly replayed

Original scratch files remain present and unchanged. I replayed their actual
mutation payloads from `/tmp/task14-rereview-originals.py`,
`/tmp/task14-rereview-subsets.py` and the original review/follow-up scripts through
the independent builder in `/tmp/task14-rereview-common.py`. New mandatory host,
swap and exited-class fields were added in `/tmp/task14-rereview2-common.py`;
records were digest-rebound. An old-schema rejection alone was not counted as a
fix. `/tmp/task14-rereview2-replay.py` contains the current executable replay.
Valid equality examples must now PASS; “refused” applies to contradictions and
out-of-threshold comparisons, not to those legitimate boundary inputs.

| Earlier case | Fresh outcome |
| --- | --- |
| I1 CPU 200,000,000 / 100,000,000 us | Exact 50% equality: raw summaries and scenario PASS. |
| I1 throughput 60,080 / 57,076 B | Exact 95% equality: raw summaries and scenario PASS. |
| I1 u64-sized one-byte-below-95% | Throughput gate and scenario FAIL. Raw physical-link counters and matching declared capacity were also supplied to reach this arithmetic case. |
| I2 observer/workload OOM | All six role × oom/oom_kill/oom_group_kill variants: insufficient scenario, retained OOM count and failed OOM gate. |
| I3 original 24,000 member ticks against zero cgroup | Refused: cpu_accounting_contradiction and cpu_component_contradiction. |
| M1 legacy router_cycles=[null] | Real subprocess exit 2, fixed redacted insufficient JSON, empty stderr, no output file. |
| M2 huge identical integers | n=1/6, 2**53+1 and u64 max: exact medians, no outliers. |
| R-I1 601 samples accumulating 600 ticks against zero cgroup | All six candidates and scenario refused with cpu_accounting_contradiction. |
| R-I2 IRQ and softirq separately > busy | Both six-record scenarios refused with cpu_subset_contradiction/cpu_breakdown_contradiction. |
| R-I3 1,210 MiB aggregate PSS on 1,024 MiB host | All six candidates and scenario refused with system_memory_contradiction. |

## Independent invariant audit

The list below was derived from units, physical subsets, conservation, native
counter meanings and the stated workload contract. It was not derived by treating
the registry's own ID list as a completeness oracle. An additional **60 raw
negative cases** independently verify the listed refusal paths; see
`/tmp/task14-rereview2-audit.py` and its results JSON.

| Required relationship | Registry/enforcement and assessment |
| --- | --- |
| Process user/system deltas, original exited classes, cgroup user+system/usage | cpu_members/user/system/parts/exited, anchored at original and measured first samples, accounting.py:482–499. Earlier accumulating error refused. Cumulative host subsets missing: **T3-I2**. |
| Host classes, IRQ/softirq/steal, guest and iowait | cpu_busy_parts/irq_subset, :441–443 and :473. user includes nice and guest; guest/guest_nice must not be added twice. idle includes iowait. Separate guest/iowait fields are not representable, so their independent per-class subsets cannot be established by this schema; see Minor notes. |
| Host busy+idle versus elapsed × CPUs; cgroup capacity; boot/process lifetime bounds | cpu_capacity/domain_capacity/host_boot_cpu/domain_boot_cpu/process_start/process_lifetime_cpu. Upper bounds enforced. Missing lower total-clock conservation: **T3-I1**. Counter offsets also escape host subsets: **T3-I2**. |
| Stable per-process USS <= PSS <= RSS, each RSS <= MemTotal, aggregate PSS/USS <= MemTotal | uss_pss/pss_rss/rss_ram/pss_ram/uss_ram at :418–430; correctly avoids summed-RSS ceiling. Fresh ordering/ceiling negatives refused. |
| Cgroup private USS + original residual = memory.current; native byte breakdown; disjoint current <= RAM | memory_charge/parts/sock/charges_ram at :421, :449–451. No general equation PSS=current: shared charge ownership differs. Accepted subfield relationships missing: **T3-I3**. |
| memory.current <= native memory.peak; peak nonregression and reset identity | **Not represented**. Closed domain schema has no memory.peak. Reported peak is max sampled current, accounting.py:770. No submitted peak contradiction can be replayed; Minor scope note below. |
| SwapPss <= Swap, aggregate proportional swap and disjoint cgroup swap <= host used <= total | swap_order/ram/pss/charge; zero-use/in/out contamination policy enforced across all samples. Fresh process/cgroup/host swap mutations refused. |
| pids.current = sum member threads; positive threads/PIDs within host ceiling; aggregate task ceiling; FD count ceiling | pids_threads/pid_bound/threads_bound/fds_bound at :416–417, :431–434, :448. Fresh limits and mismatch negatives refused. Per-process RLIMIT_NOFILE/system file-table ceilings are not recorded; no stronger ceiling inferred. |
| Stable completed per-device I/O counters and original residual conservation | io_conservation/counter_monotonic at :504–514; map/key changes and regressions refused. Byte/operation tuple relationship missing: **T3-I4**. No finite device-capacity bound is possible without recorded device capacity. |
| Physical-link RX/TX monotonic and individually <= capacity × elapsed; delivered payload <= link bytes | network_monotonic/capacity/payload at :468–470 and :519–520. Full-duplex directions bounded separately. Fresh regression/capacity/payload mutations refused. |
| Wakeup counters available/nonnegative/monotonic for stable identity | metric_availability/wakeups_monotonic at :409–410, :503. Fresh missing/regression negatives refused. No hardware-independent wakeups-per-second ceiling is invented. |
| Ordered, nonoverlapping read brackets; clock-offset intersection; cadence; exact duration/warm-up boundary | sample_clock plus _summarize at :659 onward. Fresh gap/regression/overlap/clock-step/short-window cases refused. |
| Unsigned u64 counters, no wrap/reset, stable keys and identities, no decimal aliases | integer/native validators, numeric_domain/counter_monotonic. CLI decimals/exponents/nonfinite/duplicate/deep/overflow JSON refused. No wrapping arithmetic used. |
| Member leaders match bracketed cgroup.procs; no duplicate PID/native cgroup identity; no parent/child scope overlap; complete component inventory | coverage plus _summarize domain/process checks. Fresh omitted/extra member, changed executable, duplicate PID/native ID and nested scope mutations refused. No unobserved producer activity inferred. |
| No failure in any role, observer/workload/kernel, including warm-up; retain unknowns | failure_quiet and failure_totals/OOM reduction. Original OOM cases refused; missing runtime proof/metric, synthetic origin and explicit failures cannot qualify. |

The completeness test at test_accounting_mutations.py:269–279 proves that the
44 enumerated IDs have rows and callable bindings. It does not prove the list
exhausts physical relationships. The signed boundary and 6,108-leaf tests run and
pass, but all T3-I1–I4 counterexamples have **zero broken registered predicates**.
That is a direct reproduced limit of the claimed completeness, not an objection
to property testing in principle.

## Independent WP11 oracle

`/tmp/task14-rereview2-oracle.py` was written afresh from WP11 and the brief,
without using the implementation's threshold tests or threshold table as an
oracle. Fixed seed **0x143CB91**. Expectations use exact independent equations:
candidate supervision CPU <= Python supervision CPU/2 for one exit; candidate
memory <= baseline; throughput >= baseline - baseline/20; latency <= baseline +
baseline/20; control PSS <=16/48 MiB for one/five exits; zero events on both sides.
All equalities are inclusive. No six-exit CPU/PSS threshold is invented.

- **8,436 metric cases**, across steady/load 1/5/6 shapes: equality and ±1 integer
  or raw-rate unit, tiny/zero baselines, large integer/fraction boundaries through
  u64, missing/None/bool/string/float/nonfinite/object/negative/overflow inputs,
  each side, and fixed-seed random vectors. Every gate and aggregate verdict
  equals the independent oracle; unknown/insufficient applicable metrics never
  become PASS.
- **200 randomized 72-summary comparator cases** verify conservative selection:
  best baseline versus worst candidate; baseline CPU lower bound versus candidate
  upper bound; retained failures/unknowns. Every scenario gate/status and suite
  status equals the oracle.
- **126 isolated full-suite boundary cases**, one gate at a time, prevent other
  failures masking a threshold or direction error.
- **72 separately bound raw records**: four one/five-exit scenarios PASS, both
  six-exit scenarios remain insufficient because the Python legacy adapter does
  not represent direct mode. Whole raw suite insufficient. Comparator-only tests
  use explicitly hypothetical qualified six-exit summaries to exercise that
  arithmetic; no raw receipt validator is bypassed or called runtime evidence.
- Independent binomial enumeration for **n=1..100** matches finite median CI
  ranks, exact medians and nearest-rank p95/p99. Huge-constant original outlier
  defect is fixed. No statistical power or independence claim is inferred.

Arithmetic comparison passes. Raw evidence qualification fails T3-I1–I4.

## Verification ledger

| Fresh command/check | Result and limit |
| --- | --- |
| `python3 -B -I -m unittest discover -s tools/performance -p test_accounting.py -v` | **PASS**, exit 0, **40 tests**, 106.683s. `/tmp/task14-rereview2-test_accounting.py.log`. |
| `python3 -B -I -m unittest discover -s tools/performance -p test_accounting_mutations.py -v` | **PASS**, exit 0, **7 tests**, 323.779s. **6,108** numeric probes / **4,996** registered-or-number violations, 176 signed boundaries across 44 families. `/tmp/task14-rereview2-test_accounting_mutations.py.log`. |
| `python3 -B -I -m unittest discover -s tools/performance -p test_offline.py -v` | **PASS**, exit 0, **9 tests**, 79.840s; **8,128** schema/failure-protocol cases. `/tmp/task14-rereview2-test_offline.py.log`. Tests were launched concurrently; durations are observed, not benchmark timings. |
| `python3 -B -I /tmp/task14-rereview2-replay.py` | **PASS**, exit 0; earlier payloads replayed with current mandatory fields, expected valid boundaries and refusals as above. `replay-results.json` and `replay.log` under the same scratch prefix. |
| `python3 -B -I /tmp/task14-rereview2-probes.py` | Exit 0; **10** independently mutated scenario families reproduced PASS. Actual CLI publication confirms each representative. `probes-results.json`, `probes.log` and raw representatives under the same prefix. |
| `python3 -B -I /tmp/task14-rereview2-audit.py` | **PASS**, exit 0; **60** independent raw refusal cases; additional raw cpu.stat period-subset contradiction reproduced. Six-repetition CPU-period confirmation saved separately as `cpu_periods-results.json`. |
| `python3 -B -I /tmp/task14-rereview2-oracle.py` | **PASS**, exit 0; 8,436 metric +200 random comparator +126 isolated boundary cases; 72 raw records; statistics n=1..100. `oracle-results.json` and `oracle.log` under the same prefix. |
| `python3 -B -I /tmp/task14-rereview2-static.py` | **PASS**, exit 0; **10 Python ASTs**, **6 strict JSON documents**, **21 closed named objects**, **9 resolved schema refs**, fixture/schema field agreement. Historical JSON decimal values parsed as Decimal for syntax checks; schema-1 CLI inputs remain integer-only. No third-party JSON Schema validator run; Python semantic validation is normative. |
| Float path | Only accounting true division is Fraction median /2 at :248. Legacy float number/traffic/enrichment helpers made fatal in 12 raw shape checks; none reached. Eight direct decimal/exponent/nonfinite/duplicate/depth/overflow decode probes refuse. Supplied offline trace/AST tests also PASS. No float verdict defect reproduced. |
| Preservation | HEAD/branch and index unchanged; `git diff --check` and cached-diff check PASS. Acceptance HEAD-identical, release_ready=false, SHA256 `3d467451dd03d1663e3c79b24eea6a18aac461f9291f8fdfe1031e1da6e86e97`. Reviewed input hashes in `/tmp/task14-rereview2-reviewed-hashes.json`; final comparison verifies those bytes unchanged. An unrelated untracked `tools/acceptance/` appeared during review; not inspected or modified. |
| Runtime/guest/producer/real repetitions/platform/soak/release | **NOT_RUN**, outside this offline review. No runtime optimization or real performance claim. |

## Minor notes / unproven concerns

- **Scope gap, not a reproduced measured-peak violation:** memory.peak is absent
  from the closed domain schema (`run-schema.json:407–422`); sampled current
  maxima are reported as memory_peak_bytes (`accounting.py:770`). Thus native
  current<=peak, peak resets and transient maxima cannot be independently checked.
  I did not manufacture a hidden spike and call it reproduced. Explicitly retain
  this limitation or add a reviewed original peak measurement before claiming
  this registry covers native peak accounting. PSS/current equality is not a
  substitute for charge-ownership review.
- **Per-class visibility limitation:** host guest/guest_nice and iowait are folded
  into user/nice and idle; no independent guest subset/iowait counter is supplied
  (`performance-harness.md:163–165`). No separately recorded guest/iowait
  contradiction was reproduced. Honest acquisition and CPU hotplug/suspend
  history remain producer/host-contract gates, not assumed runtime evidence.
- Per-process RLIMIT_NOFILE, system file-table limits and device I/O capacity are
  not recorded. This review verifies only supplied host ceilings and does not
  invent missing limits. Stable sampled threads also do not prove maximum
  historical thread concurrency, so no per-process lifetime CPU ceiling based on
  one sampled thread count was asserted.

Fix the four reproduced qualification gaps and extend the independent invariant
corpus before accepting the offline layer. The earlier specific reproductions
and WP11 arithmetic are fixed; they do not establish physical completeness.
