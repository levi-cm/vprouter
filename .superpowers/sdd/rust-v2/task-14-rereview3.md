# Task 14 independent review — round 4

Verdict: **FAIL — three Important and two Minor findings, all REPRODUCED.**
No Critical findings. T3-I1–T3-I4 and the earlier reported defects are fixed for
their actual reproductions. The new quantity model is executable and its numeric
inventory is complete relative to the current schema, but it omits accounting
relations for recorded residuals and socket memory. Contradictory recordings
still receive and publish PASS summaries and PASS comparison scenarios.

This review concerns the **offline preparation layer only**. Real performance,
producer/runtime/client/ARM/migration/soak/release qualification remain
**NOT_RUN / OPEN**, with `release_ready=false`. No runtime evidence is required
for this review. All apparent 600-second recordings below are constructed test
inputs, including those labeled actual_runtime to exercise qualification code;
they are not actual measurements or evidence of performance.

Reviewed 2026-11-06 in `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`, HEAD
`848b46852d229ce5557998283053b60ebbee4e08`, including uncommitted performance
sources, quantity model/authoring tool, schema, fixtures/tests, both performance
documents, Task 14 brief/report (including Review round 3), all three previous
reviews and IMPLEMENTATION.md WP11. Started no agents. Only repository write:
this report. Scratch scripts, raw reproductions, summaries, machine-readable
results and logs: `/tmp/task14-r4/`. Concurrent lab edits and the running guest
were ignored. No lab-state access, QEMU operation, sudo, service action, external
network request, benchmark, Git mutation or source fix was performed. The
requested offline suite includes its short literal-loopback socket self-test.

## Important findings — REPRODUCED

Each reproduction uses six Python and six Rust repetitions, 61 samples over
600 seconds, 100 Hz ticks, four declared CPUs, zero acquisition width, stable
identities/membership, matching host and accounting contracts, the new clock
declaration, and valid original monitoring receipts. The independently built
raw records are based on the retained reviewer builder, not the implementer's
quantity-model fixtures. Only the specified measurement is changed and the
accounting digest rebound. Every candidate summary is PASS with no reasons,
every generated predicate is true, and the one-exit steady scenario and all eight
arithmetic gates PASS. The other suite shapes are absent, so overall suite status
is **INSUFFICIENT_DATA**, never asserted here as a complete-suite PASS.

For every representative, the real `offline.py summarize INPUT --output NEW_PATH`
exits **0**, publishes the PASS summary, and emits empty stderr. Scripts and
stored raw files allow replay without collecting any host/runtime evidence.

### T4-I1. Cumulative CPU residuals can exceed all CPU ever recorded

Locations: `tools/performance/build_quantity_model.py:187`, `:200`, `:223`,
`:226`; `tools/performance/quantity_model.py:171`;
`tools/performance/accounting.py:334`, `:370`.

The new snapshot subsets cover cgroup and process CPU, but omit the recorded
outside-domain and exited/transient CPU accumulators. Those receive width,
nonregression and split/delta checks, without cumulative containing-total bounds.
A constant impossible offset cancels in every adjacent and anchored equation.

Two independent reproductions:

- `outside_cpu_offset`: add **1,000,000,000,000 us = 1,000,000 CPU seconds**
  to host `other_cpu_usec` at every sample. The complete host busy counter is
  **0 CPU seconds at the first sample**, and **264 seconds at the last**.
  The independently recorded CPU *outside* the measured domains cannot exceed
  all host CPU. Even the first sample's full four-CPU boot-time ceiling is only
  8,000 CPU seconds. Host busy/idle clock conservation remains unchanged.
- `exited_cpu_offset`: set control `cpu_exited_usec` and
  `cpu_exited_user_usec` to that same constant; system remains zero. The
  containing cgroup usage/user counters are **0 us initially** and
  **240,000,000 us finally**. A cumulative subset attributed to exited work in
  that cgroup exceeds the entire cgroup and host history. The split is exact and
  every exited delta is zero. A separate system-class variant also PASSes.

This does not require equating a surviving process's lifetime CPU with its
current cgroup's lifetime CPU; process migration is irrelevant to the two
originally recorded residual subsets. Under the stated cumulative attribution
contract, enforce appropriate snapshot residual-to-containing-total bounds and
CPU-class bounds, with justified endpoint uncertainty. If an independent tracker
uses a different origin/epoch, bind that origin and refuse unavailable alignment;
a free additive offset must not qualify as measured cumulative CPU.

Evidence: `probes.py`, `extra.py`, `probes-results.json`, `extra-results.json`;
raw `outside_cpu_offset.json`, `exited_cpu_offset.json`,
`exited_cpu_system_offset.json` and their published summaries in the scratch
directory. These payloads satisfy both the generated model and legacy registry.

### T4-I2. Cumulative residual block I/O can exceed a zero containing counter

Locations: `tools/performance/build_quantity_model.py:217`, `:231`;
`tools/performance/accounting.py:350`, `:358`;
`tools/performance/quantity_model.py:124`.

Byte/count checks now reject the earlier zero-operation examples, but cumulative
`io_other` is still reconciled with the cgroup only through endpoint differences.
There is no snapshot subset check for this original independently recorded
within-domain residual.

For device `8:0`, keep domain `rbytes=rios=0` throughout the recording and record
constant residual `rbytes=2**60` and `rios=2**40`. Both values are valid u64s,
monotonic, paired, positive and satisfy operations <= bytes. Every delta is zero;
per-device reconciliation is exact. Nevertheless a cgroup with **zero completed
reads ever** contains a residual claiming **1,152,921,504,606,846,976 completed
bytes and 1,099,511,627,776 operations**. Independent write and discard variants
also return six PASS summaries, a PASS scenario, and successful PASS publication.

Bound each recorded cumulative residual device/counter by its containing cgroup
counter, under the aligned original residual contract. Retain the delta checks.
No per-process lifetime-to-current-cgroup equality or unknown device bandwidth
limit is needed. If residual epochs cannot be related, the input is unavailable.

Evidence: `io_residual_offset.json`, `io_write_residual_offset.json`,
`io_discard_residual_offset.json`; `probes.py`, `extra.py` and their results.

### T4-I3. Socket memory has no possible place in the accepted charge partition

Locations: `tools/performance/build_quantity_model.py:201`, `:205`;
`tools/performance/accounting.py:330`;
`docs/rust-v2/performance-harness.md:196`.

The documented normalized contract says socket charge belongs either in the
reviewed kernel total or the measured charge residual. The model only checks
`sock <= memory.current`, even when all recorded containing candidates are zero.

At every control-domain observation set `memory_stat.sock = 10 MiB`, retaining:

| Recorded quantity | Value |
| --- | ---: |
| memory.current | 20 MiB |
| anon | 20 MiB |
| file | 0 |
| kernel | 0 |
| memory_stat_other_bytes | 0 |

The anon/file/kernel/residual partition still sums exactly to 20 MiB, yet the
additional recorded socket charge has **zero kernel-plus-residual bytes** in
which it can reside. All model/native-map checks and the old registry accept
this contradiction; total service memory remains 60 MiB and the memory gate PASSes.
This is a violation of the explicitly documented aligned charge contract, not
an assertion that unqualified native kernel snapshots are perfectly synchronized.

Enforce a conservative containing bound such as sock <= kernel + the residual
outside anon/file/kernel under this contract, or explicitly model/refuse the
alternative attribution. Do not blindly add sock to kernel/current and double
count a charge already included there.

Evidence: `sock_no_kernel_or_residual.json`, its CLI-published summary,
`extra.py` and `extra-results.json`.

## Minor findings — REPRODUCED

### T4-M1. FD-entry quantities omit the native descriptor-number universe

Locations: `tools/performance/build_quantity_model.py:143`, `:196`;
`tools/performance/quantity_model.py:171`.

The model gives per-process `fds` a u64 domain and only the manifest ceiling.
Give both sides the same conservative `max_fd_entries=2**40`, then set one
candidate process's FD-entry count to **4,294,967,296 (2^32)** at every sample. All six raw
summaries and the comparison scenario PASS; the actual CLI publishes PASS.
The sum of recorded FDs remains below u64, so this is not an aggregate overflow.

Linux file descriptors are nonnegative signed-int identifiers. Even the entire
32-bit signed-int namespace has only 2**31 nonnegative values; a process cannot
have 2**32 distinct FD directory entries. A loose declared upper bound cannot
remove this independent native ceiling. The model correctly narrows PID/task
identifiers but does not represent this bound for FD-entry counts. The native
parser's own finite enumeration limit does not protect raw JSON normalization.

Evidence: `widths.py`, `widths-results.json`, `fd_int_universe.json` and its
published summary. A corresponding out-of-width PID control is correctly refused.

### T4-M2. Recorded smaps byte values need not be representable by the named source

Locations: `tools/performance/build_quantity_model.py:147`;
`tools/performance/quantity_model.py:171`;
`tools/performance/accounting.py:161`.

The model names `/proc/PID/smaps_rollup Pss` as the source and correctly describes
checked native kB-to-byte conversion, but generates no conversion-granularity
check. Change one process's PSS from 2,097,152 to **2,097,151 bytes** at every
sample. USS <= PSS <= RSS and all aggregate bounds remain valid. All six
summaries, the comparison scenario and actual CLI publication PASS.

An integer `Pss: ... kB` converted by the supplied native parser must yield a
multiple of 1024 bytes. The accepted value cannot come from that declared source.
Represent normalized source quanta, or explicitly define a different supported
source/precision before allowing it. This is a provenance/normalization
consistency gap; it does not reproduce a floating threshold error.

Evidence: `smaps_byte_quantum.json`, its published summary, `probes.py` and results.

## Independent inventory and relation audit

I independently traversed every schema applicator and resolved JSON pointer
reference, collecting numeric positions without calling the model compiler or
the authoring inventory. Result: **247 schema positions = 247 distinct model
entries; no missing/extra numeric path**. The model has **68 relations and nine
native-map templates**. The independently derived list is retained in
`independent-schema-inventory.json`. Scratch-only authoring regenerates model
and schema byte-identically; the repository authoring tool was not run in place.

Numeric-position coverage is therefore confirmed. Physical-relation coverage is
not complete: each new counterexample is a satisfying assignment for every
existing generated predicate and simultaneously violates a containing-total or
native-source relation. No count of emitted predicates can discover those
omitted equations by itself.

| Recorded family / independently derived relation | Fresh assessment |
| --- | --- |
| Host busy = user/nice + system + IRQ + softirq + steal; guest/guest_nice not added again; idle includes iowait | Recorded aggregate partition enforced. Guest and iowait are folded, not separately recorded; the docs disclose this limitation. No invented subcategory evidence required. |
| busy+idle delta versus elapsed * online CPUs; endpoint skew; cumulative boot upper bound | Two-sided recorded-window model check now present; original/measured prefixes and adjacent endpoints checked. No unsupported boot-history lower bound inferred. |
| Domain/process cumulative user/system/usage versus host classes; process CPU versus lifetime | New snapshot subsets enforced; original T3-I2 refused. Residual accumulators omitted: T4-I1. Do not equate current-cgroup and process lifetimes. |
| Member tick deltas + independently measured exited CPU versus domain CPU; split classes; outside-domain CPU versus host busy | Anchored and adjacent delta checks enforced. Cumulative residual containment missing: T4-I1. |
| PSS/USS/RSS, MemTotal, memory.current, anon/file/kernel, supported optional native subsets | Aggregate PSS/USS and disjoint charges bounded by RAM; RSS bounded individually; private-charge and native partitions enforced. Socket containment omitted: T4-I3. Smaps normalization quantum omitted: T4-M2. |
| memory.peak and transient memory maxima | Not recorded; reported maxima are sampled memory.current/PSS. Docs explicitly disclose missing native peak/transient proof. This is not a new runtime requirement. |
| Swap/SwapPss, host swap and cgroup swap.current | Ordering/subset and mandatory no-swap checks enforced; unknown does not become zero. |
| PID/threads/FD counts; member lists versus recursive cgroup.procs; task population | Stable inventory, duplicate/exact-membership, thread-count partition and declared ceilings enforced. FD native universe omitted: T4-M1. |
| Completed read/write/discard operations and bytes; residual reconciliation | Snapshot/delta byte/count pairs enforced; no invented disk bandwidth ceiling. Cumulative residual containment omitted: T4-I2. Native block-I/O time is not a recorded field and is not claimed as evidence. |
| Physical-link RX/TX bytes | Monotonic, separately full-duplex capacity bounded; delivered payload bounded by measured RX+TX. Recorded link semantics still require future producer review. |
| Wakeups, events, width/wrap | Stable-identity cumulative nonregression and raw widths enforced. No ungrounded wakeups/second or native event-duration inequality imposed. |
| Acquisition timestamps and intervals | Ordering, nonoverlap, regular cadence, warm-up boundary, duration and wall/boot coherence enforced by structural/legacy validators in addition to model-dependent CPU bounds. |
| Disjoint domains, native identity, process exec/reuse/movement | Overlap/duplicate native-domain identity, inventory changes, changed executable/start/domain/component and member mismatches refuse. Unobserved exec/membership ABA remains explicitly unqualified; no sampled proof is promoted to continuous coverage. |

The supplied per-leaf property uses generated predicates to decide whether a
physical mutation must refuse (`test_accounting_mutations.py:458`). That verifies
consumer consistency with the existing model, not independent completeness of
its physical equations. Its relation-removal witnesses mostly use 0/u64-overflow
and assert that a named predicate disappears (`:568`); that is narrower evidence
than demonstrating that each isolated semantic rule is necessary for the final
verdict. These are test-scope notes, not additional unreproduced Important defects.

An independent schema-derived fixed-seed property (`0x14F04`) covered **all 247
numeric positions**, at first/last available positions, with **1,560 negative,
overflow, bool and float mutations**. Every one was refused. It does not use
production predicates to decide expected invalidity. Optional native fields were
populated from the schema; supplied branch fixtures were used only to reach
conditional receipt shapes. This domain test passes while the missing physical
relations above still admit PASS.

## Earlier fixtures and independent WP11 oracle

Freshly replayed retained reviewer payloads from all three rounds, adapting only
new mandatory acquisition fields and rebinding digests. Round-three raw JSON
files were read directly from the retained reviewer scratch files, rather than
trusting the new checked-in bundle. Adding only the clock declaration retains
each numeric payload and produces a **generated relation violation**; rejecting
an old record merely for missing the new declaration was not counted as a fix.

| Earlier finding / fixture | Fresh result |
| --- | --- |
| I1 CPU 200,000,000 / 100,000,000 us; throughput 60,080 / 57,076 B | Valid inclusive equalities PASS exactly. These are positive controls, not records that should be refused. |
| I1 one byte below 95% at u64-scale | Throughput gate/scenario FAIL; raw counters remain representable under matched high link ceilings. |
| I2 observer and workload oom/oom_kill/oom_group_kill, independently | All six variants prevent PASS and retain failure evidence. |
| I3 zero cgroup CPU with 24,000 stable member ticks | INSUFFICIENT_DATA. |
| M1 legacy router_cycles=[null] | Actual subprocess exit 2, fixed redacted refusal, empty stderr, no output file. |
| M2 huge constant medians, n=1/6, 2**53+1 and u64 maximum | Exact median, no false outliers. |
| R-I1 per-interval tolerance accumulation | INSUFFICIENT_DATA under whole-window reconciliation. |
| R-I2 IRQ and softirq independently exceeding busy | Both INSUFFICIENT_DATA. |
| R-I3 aggregate PSS over RAM | INSUFFICIENT_DATA. |
| T3-I1 lost_idle and lost_idle_python | Both INSUFFICIENT_DATA; generated host_clock violations with the declaration present. |
| T3-I2 snapshot_cpu | INSUFFICIENT_DATA; generated cumulative snapshot subset violations. |
| T3-I3 shmem, anon_thp, kernel_stack, slab and cpu_periods | All five INSUFFICIENT_DATA with generated containing/subset violations. |
| T3-I4 read/write/discard bytes with zero operations | All three INSUFFICIENT_DATA with generated snapshot/delta byte/count violations. |

Retained independent WP11 oracle, refreshed in scratch with the new acquisition
contract, uses seed **0x143CB91**. Its expected results come from the brief/WP11
and conservative qualification policy, not the implementer's threshold tests:

- Candidate one-exit supervision CPU <= half of newly measured Python
  **supervision** CPU; baseline lower and candidate upper duration bounds.
- Simultaneous service memory <= baseline; control PSS <=16/48 MiB for one/five;
  no six-exit PSS target or invented five/six-exit CPU gate.
- Throughput >=19/20 baseline; p95 latency <=21/20 baseline; zero misses,
  unexpected restarts and OOMs on both sides. Every equality is inclusive.
- Worst candidate versus best baseline; all repetitions/outliers retained;
  invalid/missing/tiny baselines and retained insufficiency dominate PASS.

**8,436 exact metric cases**, **200 randomized compact full-suite cases** and
**126 isolated suite-boundary cases** match the independent oracle gate-for-gate
and verdict-for-verdict. Cases include every shape, both directions, equality,
just-inside/outside rational/integer values, both event sides, huge counters,
missing/invalid/unknown values and documented floor boundaries. Independent
exact binomial/median/percentile checks pass for n=1..100.

The 72 raw shape/repetition checks produce four PASS shapes and two insufficient
six-exit shapes because the Python direct adapter remains unrepresented. The
hypothetical compact six-exit arithmetic controls in the oracle do not qualify
raw receipts or close that blocker. No raw complete-suite PASS is claimed.

## Verification ledger

| Check | Fresh result / limits |
| --- | --- |
| `python3 -B -I -m unittest discover -s tools/performance -p test_accounting.py` | **PASS**, exit 0, **44 tests / 305.570s**. |
| `python3 -B -I -m unittest discover -s tools/performance -p test_accounting_mutations.py` | **PASS**, exit 0, **13 tests / 1779.935s**; 6,108 existing numeric probes / 4,996 violations; 4,104 model property probes / 2,022 generated violations; 68 relation and 247 quantity-entry removal checks reported GREEN. |
| `python3 -B -I -m unittest discover -s tools/performance -p test_offline.py` | **PASS**, exit 0, **9 tests / 161.984s**; 8,142 failure-protocol cases; bounded loopback method executed, no skipped method. |
| Earlier replay | `replay.py`, `replay3.py`: exit 0; all original defects refused, valid equality controls PASS. All eleven round-three recordings independently replayed. |
| Independent WP11 oracle | `oracle.py`: exit 0; 8,436 metric + 326 compact suite cases; all comparator outputs equal oracle. |
| Independent schema numeric-domain property | `leaf-property.py`: exit 0; fixed seed 0x14F04; 247/247 positions, 1,560 independently invalid probes refused. |
| Independent physical/coverage negatives | `audit.py`: exit 0; 60 hand-derived refusal cases plus corrected native throttled-period subset. New missing-relation counterexamples are separately retained, not filtered from the report. |
| New false-PASS reproductions | `probes.py`, `extra.py`, `widths.py`: exit 0; recorded PASS raw/scenario/gates and real CLI PASS publication. PID out-of-width control correctly refused. |
| AST / strict JSON / schema refs | `static.py`: exit 0; **12 Python ASTs**, **9 JSON files**, nine resolved schema references, exact 247-entry inventory match, no schema/model decimal tokens. Historical baseline JSON decimals are parsed exactly as Decimal for syntax inspection, never verdict evidence. |
| Model authoring determinism | Scratch mirror regenerated schema/model byte-identically; no in-place repository write. |
| Exactness grep / independent runtime trace | `exactness.py`: exit 0; 171 executed code objects, 2,091,543 profiled returns across both receipt adapters and generated arithmetic. No floating result; legacy float helpers not executed. The true division at accounting.py:253 has explicit Fraction operands and remains exact; grep alone is not treated as proof. |
| Atomic exclusive publication | `publication.py`: exit 0; eight competing 100,000-byte publishers yield exactly one intact 0600 result; no temp residue. Last-instant destination creation preserves original bytes. Parent rename/symlink replacement publishes only in pinned original directory. Supplied tests also check file/directory fsync ordering and cleanup. Documented post-rename directory-fsync durability limitation is honest. |
| Determinism / redaction | Three fresh isolated interpreters produce byte-identical summary bytes; reversed compact comparison inputs are canonical-byte-identical. Four additional malformed actual subprocess inputs produce fixed refusal, empty stderr, no private marker/path and no output. |
| Documentation honesty | Explicit no performance claim, real runs NOT_RUN, producer and native peak/ABA/platform limits disclosed, no release gate closed. Numerical equality/direction documentation matches oracle. Physical completeness remains limited by reproduced omissions above. |
| Acceptance | HEAD-identical; `release_ready=false`; SHA256 `3d467451dd03d1663e3c79b24eea6a18aac461f9291f8fdfe1031e1da6e86e97`. |
| Preservation / final source binding | All **21** initially hashed owned source/docs/fixture/acceptance files remain byte-identical to `initial-hashes.json`; branch/HEAD unchanged. This report is the only repository write. Concurrent lab edits remain outside review scope. |
| Runtime / real workloads / release | **NOT_RUN**, outside this offline review. No real 10-minute workload, VM/guest probe or release qualification was attempted. |

`review-round4.json` retains a compact base-plus-patches bundle of nine new
false-PASS payloads with canonical SHA256 bindings, independently reconstructed
against the stored raw files. Logs and `.exit` files are alongside the script's results. PASSes above
are test/preparation results only. No source fixes were made; resolve the missing
relations and rerun the retained raw counterexamples before accepting this layer.
