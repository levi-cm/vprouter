# Task 14 independent review — round 5

Verdict: **FAIL — two Important findings, both REPRODUCED.** No Critical
findings. The round-4 findings T4-I1, T4-I2, T4-I3, T4-M1 and T4-M2 are fixed
for their reported reproductions. The catalog is executable, source-derived and
internally consistent (137 identities, 129 generated relations, eight explicit
unavailability entries), and the 163-method offline suite passes. It is still
not semantically complete: two native counter relations are absent, so
contradictory raw recordings still receive and publish PASS summaries and PASS
six-repetition scenarios.

This verdict concerns the **offline preparation layer only**. Real Python/Rust
performance, producer/runtime/client/ARM/migration/soak/release qualification
remain **NOT_RUN / OPEN**, with `release_ready=false`. Every apparent 600-second
recording below is a constructed input-domain record, not a real measurement.

Reviewed 2026-11-07 in `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`, HEAD
`eb2f50e3d83fd9439f9f120052e716e9d5f9e95c`, including the uncommitted
round-5 changes under `tools/performance/**`, both performance documents,
`docs/rust-v2/IMPLEMENTATION.md` WP11, the Task 14 report's Review round 4
section, and all four previous reviews. Concurrent witness-validator edits under
`tools/rust-v2-lab/` and `task-8c-run410-witness-*.md` were ignored. Only this
report was written in the repository. All scratch inputs, results and logs are
under `/tmp/task14-r5-review/`. No Git write, network, sudo, VM, service
operation, real workload or source fix was performed. The requested
`test_offline.py` includes its short literal-127.0.0.1 socket self-test; no
external traffic was generated.

## Important findings — both REPRODUCED

Both reproductions use the independently qualified `reconciled_record` carrier:
61 aligned samples over 600 measured seconds, 100 Hz counters, four declared
CPUs, zero acquisition width, stable process/domain identities and membership,
valid original monitoring receipts, and a rebound accounting digest. The
unmodified carrier qualifies as PASS first. Six matching Python and Rust
repetitions pass the one-exit steady scenario and all eight arithmetic gates.
Other suite shapes are deliberately absent, so the whole suite remains
**INSUFFICIENT_DATA**, never reported as a complete-suite PASS. Raw files,
published summaries and hashes are retained under
`/tmp/task14-r5-review/evidence/`.

### R5-I1. `cpu.stat` accepts accumulated throttle time with zero throttled periods

Locations: `tools/performance/kernel-identities.json:2666`, `:2703`
(`native_throttled_periods` and `native_throttled_period_deltas` are the only non-monotonic throttling relations), `:5508`, `:5542`
(`nr_throttled` and `throttled_usec` have monotonic checks only);
`tools/performance/quantity-model.json:9025`, `:10579`;
`tools/performance/build_quantity_model.py:13`, `:132`;
`tools/performance/quantity_model.py:258`–`:268`;
`docs/rust-v2/performance-harness.md:561`.

The model relates `nr_throttled` to `nr_periods` and separately requires each
counter not to regress. It never relates `throttled_usec` to `nr_throttled`.
The catalog citations for this subfamily
(`kernel-identities.json:2688`–`:2700`, `:2744`–`:2756`, `:5520`–`:5526`, `:5554`–`:5560`) quote only the generic
"usage_usec, user_usec and system_usec are cumulative CPU time" sentence (plus an
unrelated proc-stat sentence), which does not define either throttling counter; the omission is therefore not an explicitly
documented unavailable identity.

Reproduction: at every sample of the six candidate repetitions, set the control
domain `cpu.nr_periods=0`, `cpu.nr_throttled=0`, `cpu.throttled_usec=1000000`
(one second of accumulated throttle time). A variant sets `throttled_usec` to
`index * 10000` during the run and keeps `nr_throttled=0`. Results:

- `summarize` returns **PASS**, empty reasons.
- `offline.py summarize` exits **0**, writes the PASS summary, empty stderr.
- Six Python / six Rust repetitions: one-exit steady scenario **PASS**, all eight
  gates PASS (`supervision_cpu`, `total_memory`, `control_pss`, `throughput`,
  `p95_latency`, `monitor_misses`, `unexpected_restarts`, `oom_events`).
- Raw SHA256: `12da1e57bf1c45fda87cbd69553548efb874265686716d2cd936abdee1f405b7`;
  scenario report SHA256:
  `72d93d7bb10751851d4d92fcee357489258a231cccc948cddee516f2acdba8a6`.

`throttled_usec` is the total duration for which the cgroup was throttled;
`nr_throttled` is the number of enforcement intervals that were throttled.
Accumulated throttle time cannot exist without at least one throttled interval.
A single `cpu.stat` read can be torn across field updates, so a one-sample
`nr_throttled=0, throttled_usec>0` could conceivably be a read-order artifact.
This reproduction holds the contradiction constant over all 61 samples in each
of six repetitions on each side, which that explanation cannot cover. The valid
one-way relation is `throttled_usec > 0 => nr_throttled > 0`. The converse
(`nr_throttled > 0 => throttled_usec > 0`) is **not** asserted, because a read
can catch a currently throttled period before its time is added.

The implementer considered this in round 3 and withdrew it:
`validation-output/round3/native-event-red.log` contains the proposed
`native_throttle_time_count` rule, and the report lines 787–794 say the
speculative event inequalities were not accepted because "kernel event timing
and attribution can differ". That explains a single torn snapshot; it does not
explain a 600-second persistent contradiction. The harness document's "no
invented ... event-duration inequality" (line 561) does not apply: this is the
defining containment between a duration and its period count, not an invented
rate or bound.

Fix: add the source identity and a one-way generated relation (with the existing
optional-field `when_present` guard), plus a signed witness, or explicitly mark
`throttled_usec`/`nr_throttled` semantics unavailable/contamination instead of
qualifying them.

### R5-I2. `memory.events` accepts a group OOM kill with no OOM event

Locations: `tools/performance/kernel-identities.json:5288`, `:5344`
(`oom` and `oom_group_kill` have monotonic identities only);
`tools/performance/accounting.py:400`–`:403` (`failure_quiet` compares each
event count with the first sample, so a constant nonzero is accepted);
`tools/performance/accounting.py:767`–`:769` (`domain_oom` uses only
last-minus-first deltas);
`docs/rust-v2/performance-harness.md:271`–`:273`, `:561`.

Reproduction: at every sample of the six candidate repetitions, set the control
domain `memory_events.oom=0`, `memory_events.oom_kill=0`,
`memory_events.oom_group_kill=1`. A second variant sets
`oom=1, oom_kill=1, oom_group_kill=2`. Results:

- `summarize` returns **PASS**, empty reasons; reported `oom_events` is **0**.
- `offline.py summarize` exits **0**, publishes PASS, empty stderr.
- Six Python / six Rust repetitions of the first variant: one-exit steady
  scenario **PASS**, including the `oom_events` gate PASS. The second variant is
  a summarize-level counterexample (the same structural path with a different
  counter triple).
- Raw SHA256: `12baf8e7e536a2e2df8e3f0fbe18fd435eed174ae3b8a85839ad40ab13229fef`;
  scenario report SHA256:
  `485ddf258a96bc3984112964b6edcf03e484a09c2fb67e49799a551dec36f552`.

The catalog's own `memory.events` citation says "oom_kill counts killed
processes; oom_group_kill counts group OOM events". A group OOM event in a
cgroup's own subtree is an OOM event in that subtree, so
`oom_group_kill <= oom` is a containment relation, not an ordered partition.
A group kill also kills at least one task, so `oom_group_kill <= oom_kill` is
defensible under the documented nonempty-victim group-kill semantics; do **not**
assert the invalid converse/orderings `oom_kill <= oom` or `oom <= oom_kill`.
The constant 61-sample, six-repetition-per-side reproduction excludes a
single-read ordering artifact; a persistent group-kill count above the containing OOM-event count is
not explainable by timing or attribution in the same subtree.

The implementer's round-3 withdrawn proposal also named `native_group_kills`
(`validation-output/round3/native-event-red.log`). The withdrawal argument
("kernel event timing and attribution can differ") covers a single torn read,
not a constant contradiction. `failure_quiet` only checks equality to the first
sample and `domain_oom` only checks deltas, so a constant pre-existing nonzero
event is invisible to the OOM gate.

Fix: add `oom_group_kill <= oom` (and preferably `<= oom_kill` with its
nonempty-victim assumption) as a source identity, with an optional-field guard;
and/or treat any nonzero absolute OOM/group-kill count at the first sample as
pre-existing contamination that prevents PASS rather than as a zero baseline.
The second is a policy choice; the containment is the native relation.

## Round-4 findings freshly replayed

The nine round-4 variants were independently reconstructed from the values in
`task-14-rereview3.md` on the qualifying carrier, not by trusting the checked-in
fixture. Each mutation is refused, and the named generated relation is false:

| Round-4 finding | Fresh result |
| --- | --- |
| T4-I1 `outside_cpu_offset` (+10^12 us outside) | INSUFFICIENT; `relation:outside_cpu_snapshot`, `relation:snapshot_host_accounted` |
| T4-I1 `exited_cpu_user_offset` (+10^12 us) | INSUFFICIENT; `relation:exited_usage_snapshot`, `relation:exited_user_snapshot` |
| T4-I1 `exited_cpu_system_offset` (+10^12 us) | INSUFFICIENT; `relation:exited_usage_snapshot`, `relation:exited_system_snapshot` |
| T4-I2 `io_read_offset` (2^60 bytes/2^40 ops residual) | INSUFFICIENT; `relation:io_residual_snapshot` |
| T4-I2 `io_write_offset` (same) | INSUFFICIENT; `relation:io_residual_snapshot` |
| T4-I2 `io_discard_offset` (same) | INSUFFICIENT; `relation:io_residual_snapshot` |
| T4-I3 `sock_no_container` (10 MiB sock, 0 kernel+residual) | INSUFFICIENT; `relation:socket_container` |
| T4-M1 `fd_int_universe` (2^32 FD entries) | INSUFFICIENT; `relation:fd_native_universe` |
| T4-M2 `smaps_byte_quantum` (PSS 2,097,151 bytes) | INSUFFICIENT; `relation:smaps_pss_quantum` |

With the quantity-model checker disabled, the same nine payloads return PASS
under the legacy/structural gates, as the implementer's test also demonstrates;
the new catalog relations are the actual enforcement. Raw hashes and status are
in `/tmp/task14-r5-review/evidence/results.json`. The positive control
(unmutated carrier) is PASS. The earlier I1/I2/I3, M1/M2, R-I1–R-I3 and
T3-I1–T3-I4 replays in `test_accounting.py` and `test_kernel_identities.py`
also pass.

## Independent catalog audit

- Counts verified directly from the files: **137 identities, 129 available
  generated relations, eight unavailable identities, 247 numeric quantity
  entries, nine native-map templates**. `quantity_model.catalog_coverage()` is
  empty. Regenerating the schema/model from a scratch copy of
  `tools/performance/` with `python3 -B -I build_quantity_model.py` produced
  byte-identical `run-schema.json` and `quantity-model.json`; the repository
  files were not modified.
- Citations were checked against known Linux semantics: `/proc/stat` guest
  folding and iowait unreliability, `/proc/PID/stat` utime/cutime, smaps
  proportional PSS/SwapPss and integer-kB output, `memory.current`/`memory.stat`
  overlap, pids task counting, fd descriptor numbers, `io.stat` bytes/ops,
  meminfo swap, and network device counters are correctly paraphrased. One live
  read-only host cross-check supports the memory identities:
  `/sys/fs/cgroup/.../memory.stat` had `kernel 99,741,696` versus
  `kernel_stack+pagetables+sec_pagetables+percpu+vmalloc+slab = 99,287,328`,
  `slab = slab_reclaimable + slab_unreclaimable`, and
  `anon+file+kernel = 530,464,768 <= memory.current = 532,054,016`;
  `/proc/self/smaps_rollup` had
  `Rss = Private_Clean+Private_Dirty+Shared_Clean+Shared_Dirty`, `USS <= Pss <=
  Rss`, and every value a multiple of 1024. This is local `/proc`/`/sys`
  inspection, not VM or network evidence.
- The eight unavailable identities are genuinely not derivable from recorded
  quantities: `native_guest_user` and `native_idle_iowait` (guest/guest_nice and
  iowait are not separately present), `native_waited_children` (cutime/cstime
  absent), `native_smaps_resident_partition` (Private/Shared pieces absent),
  `native_smaps_page_quantum` (page size absent), `native_fd_allocation_limit`
  (RLIMIT/history absent), `native_pids_limit` (`pids.max` absent) and
  `native_swap_used` (SwapFree absent).
  The corresponding residual limits are also disclosed in the docs. The
  `native_swap_used` entry correctly retains the available
  `swap_used <= swap_total` subset rather than inventing equality.
- The missing-relation audit covered the recorded families. Two native
  containments are missing (R5-I1, R5-I2). The catalog's existing 258 signed
  boundary probes and 129 relation-removal/reverse-citation checks are complete
  only **relative to the 129 catalog IDs**: `test_kernel_identities.py:379`
  asserts `applicable == set(boundary_witnesses())`, so an identity omitted from
  the catalog is also omitted from the witness set. The implementer's own
  withdrawn `native_throttle_time_count` and `native_group_kills` proposal is
  direct evidence that these two identities were considered and dropped, not
  that they were never relevant.

The `cpu.stat` throttling citations are also incomplete: the
`nr_periods`/`nr_throttled`/`throttled_usec` rows cite only the
usage/user/system sentence (`kernel-identities.json:2699`, `:2755`, `:5526`, `:5560`). The catalog
`"sources"` list (`:6747`) omits `man getrlimit(2)`, although
`native_fd_allocation_limit` cites it (`:5155`). These are citation-metadata
defects, not independent false PASSes; they are listed as Minor below.

## Independent WP11 oracle

A fresh oracle was written from `IMPLEMENTATION.md:77–79` and the Task 14 brief,
without using the implementer's threshold tests as an oracle:

- One-exit supervision CPU <= baseline supervision CPU / 2; no invented
  five/six-exit CPU gate.
- Simultaneous service memory <= baseline; control PSS <= 16 MiB (one exit) or
  48 MiB (five exits); no six-exit PSS target.
- Throughput >= 19/20 baseline; p95 latency <= 21/20 baseline; zero monitor
  misses, unexpected restarts and OOMs on both sides. All equalities inclusive.
- Conservative selection: best baseline versus worst candidate; baseline CPU
  lower duration bound versus candidate upper; invalid/missing/unknown metrics
  are INSUFFICIENT and dominate PASS; outliers are retained.

**2,400 exact metric cases** across exits 1/5/6, every gate, both sides,
equality and one-unit inside/outside, tiny/zero baselines, large integers,
Fractions, bool/float/string/None/negative/overflow inputs, and **360
six-repetition scenario cases** with independent worst/best selection matched
the comparator gate-for-gate and verdict-for-verdict. No unknown or insufficient
metric became PASS. The comparator arithmetic is exact; R5-I1/R5-I2 are evidence
qualification gaps before that arithmetic. The threshold code checked is
`accounting.py:820`–`:838` (50/100/95/105, 16/48 MiB, zero events).

## Exactness, determinism, publication, documentation

- **Exactness:** `accounting.py` has no float constants; the only true division
  is the explicit `Fraction` median at `:253`. `quantity_model.py` has no
  float arithmetic. `evaluate_metrics` uses int/Fraction only; `offline.decode`
  rejects JSON decimals, exponents and nonfinite values. The three
  exactness/redaction/publication tests pass. The legacy float helpers in
  `measurement.py` are outside the exact verdict path for accepted receipts.
- **Determinism:** three fresh `python3 -B -I` interpreters produced identical
  summary SHA256 `317d44c044e4a5709befbe0dc88271c3e8b4ca771662fe4d0f0f11e4e1e48f96`;
  reversed comparison argument order produced byte-identical reports.
- **Atomic exclusive publication:** two concurrent publishers of different PASS
  summaries produced exactly one exit 0 and one exit 2, one intact 0600 file,
  no temp residue, and the file matched the winner's summary. A pre-existing
  destination retained its bytes and the second publish refused; a repeated
  evidence run with an existing summary correctly returned the fixed refusal
  rather than overwriting. This is the documented exclusive contract; it is not
  a durability proof after a successful rename+directory-fsync.
- **Documentation honesty:** both docs state no performance claim, real runs
  **NOT_RUN**, producer/native-peak/page-size/epoch limits, and
  `release_ready=false`. Acceptance SHA256 is still
  `3d467451dd03d1663e3c79b24eea6a18aac461f9291f8fdfe1031e1da6e86e97`,
  HEAD-identical, `release_ready=false`. The report's "OFFLINE GREEN" is a
  test-result claim, not a performance claim; the two Important findings
  contradict a final acceptance claim.

## Verification ledger

| Fresh command/check | Result and limits |
| --- | --- |
| `python3 -B -I -m unittest discover -s tools/performance -p test_kernel_identities.py -v` | **PASS**, exit 0, **13 tests /79.572 s**; 258 probes, 129 coverage/citation mutants, nine round-4 refusals, nine CLI refusals. Log `/tmp/task14-r5-review/test_kernel.log`. |
| `python3 -B -I -m unittest discover -s tools/performance -p test_accounting.py -v` | **PASS**, exit 0, **44 tests /325.368 s**. Log `test_accounting.log`. |
| `python3 -B -I -m unittest discover -s tools/performance -p test_offline.py -v` | **PASS**, exit 0, **9 tests /162.810 s**; 8,142 failure-protocol cases; bounded loopback self-test executed. Log `test_offline.log`. |
| `python3 -B -I -m unittest discover -s tools/performance -p test_measurement.py -v` | **PASS**, exit 0, **84 tests /1.105 s**. Log `test_measurement.log`. |
| `... -p test_accounting_mutations.py -k ComparatorMutationTests -v` | **PASS**, exit 0, **2 tests /2.740 s**. Log `mut_comparator.log`. |
| `... -p test_accounting_mutations.py -k PhysicalRegistryTests -v` | **PASS**, exit 0, **5 tests /774.451 s**; 6,108 numeric probes /4,996 expected violations. Log `mut_physical.log`. |
| `... -p test_accounting_mutations.py -k QuantityModelTests -v` | **PASS**, exit 0, **6 tests /1182.294 s**; 4,104 probes /2,042 violations; 129 relation and 247 quantity removals killed. Log `mut_quantity.log`. |
| `... -p test_accounting_mutations.py -v` (single full-file run) | **PASS**, exit 0, **13 tests /1920.059 s**; same 6,108 + 4,104 probes and 129/247 removals as the class-split runs. Combined with the other files this is the report's **163-method** offline suite. Log `test_accounting_mutations.log`. |
| Independent T4/event/pid probes (`probes.py`) | Exit 0; positive control PASS; all nine T4 variants INSUFFICIENT with named relations; `oom_group_kill=1, oom=0` and `pid=pid_max` PASS (findings). `/tmp/task14-r5-review/probes-results.json`. |
| Six-repetition throttle/group-kill probes (`probes2.py`) | Exit 0; both scenarios PASS all eight gates; both CLI summaries exit 0; both suite statuses remain INSUFFICIENT because other shapes are absent. `probes2-results.json`. |
| Retained evidence (`evidence.py`) | Exit 0; nine T4 raw files and hashes; group-kill and throttle raw files, summaries and compare reports; scenario PASS, suite INSUFFICIENT. `evidence/results.json`. |
| Independent WP11 oracle (`oracle.py`) | Exit 0; **2,400 metric + 360 scenario** cases all match; no PASS on INSUFFICIENT. `oracle-results.txt`. |
| AST/JSON/schema (`static.py`) | Exit 0; **14 Python ASTs**, seven performance JSON documents strict-decoded with duplicate/float rejection, nine schema refs resolved. `static-results.json`. |
| Exactness/determinism/publication (`determinism.py`) | Exit 0; identical fresh-interpreter hashes; reversed compare identical; race one winner 0600/no temp; existing destination preserved. `determinism-results.json`. |
| Valid outside-CPU positive control (`outside.py`) | Exit 0; host user and system advancing outside the domains, with `other_cpu_usec` and idle adjusted, remains PASS; this checks the `domain_user_delta`/`domain_system_delta` direction rather than assuming it. `outside-results.json`. |
| Catalog/model authoring | Scratch-copy regeneration byte-identical; repository files untouched; `catalog_coverage()` empty; counts 137/129/8/247/9. |
| Preservation | `git diff --check` passes, index empty; branch/HEAD unchanged; only this report is a new repository write. Acceptance HEAD-identical, SHA above, `release_ready=false`. |
| Runtime/real workloads/release | **NOT_RUN**, outside this offline review. No real 600-second workload, guest, VM, Rust build, migration, soak or release qualification. |

## Minor notes and residual limits

- **R5-M1 (reproduced, contract ambiguity): `pid_max` off-by-one.** The docs
  define the field as "inclusive pid_max (maximum allowed PID and host task
  population)" (`performance-harness.md:236`), but the catalog citation
  (`kernel-identities.json:1354`, `:1380` for `pid_limit`) and the source name
  `/proc/sys/kernel/pid_max` describe the PID wrap value, which is one greater
  than the maximum PID. Setting `pid = pid_max = 4194304` on every sample and
  keeping membership/pids consistent returns **PASS**. If the field is the
  sysctl value, PID equal to it is impossible; if it is redefined as the maximum
  PID, the normalization must be stated and the producer must subtract one. The
  same one-unit looseness affects `threads <= pid_max` and
  `sum_threads <= pid_max` (at most `pid_max-1` live tasks). Low performance
  impact, but it is a native source-representability boundary. Raw probe:
  `probes.py` `pid_equal_pid_max`.
- **Idle/iowait monotonicity (unreproduced over-refusal).** The model marks
  `idle_ticks` monotonic (`build_quantity_model.py:123`) and the legacy
  `counter_monotonic` includes it (`accounting.py:470`), while the catalog and
  docs say native iowait may decrease and is folded into normalized idle
  (`performance-harness.md:557`, `native_idle_iowait`). A sufficiently large
  iowait correction under low idle growth would make normalized idle decrease
  and be refused. The 10-tick decrease tested on the 10-second carrier was
  absorbed by normal idle growth, so no qualified raw refusal is asserted here;
  the model should either not require normalized idle monotonicity or explicitly
  document that the producer must smooth/reclassify iowait.
- **Citation metadata.** The `cpu.stat` throttling rows cite only the
  usage/user/system sentence (`kernel-identities.json:2699`, `:2755`, `:5526`, `:5560`), not the
  `nr_periods`/`nr_throttled`/`throttled_usec` definitions. The catalog
  `"sources"` list omits `man getrlimit(2)` while
  `native_fd_allocation_limit` cites it. Both are Minor metadata defects; the
  citation contents for the memory, smaps, pids, fd, io, net, swap and proc-stat
  families checked out against known semantics.
- **Honest unavailability.** smaps page-size divisibility, RLIMIT_NOFILE
  history, `pids.max`, SwapFree and native memory.peak/transient maxima are not
  recorded; the catalog/docs mark them unavailable rather than inventing a
  bound. The model's 1024-byte smaps output quantum is the correct native kB
  representability check; it is not a 4096-byte page claim.
- **Test-scope note.** The 258 signed witnesses and 129 relation-removal
  mutants establish consistency with the 129 catalog identities, not semantic
  completeness. R5-I1/R5-I2 are satisfying assignments for every generated
  predicate and every legacy gate; only an external source-derived identity
  audit finds them. The implementer's own withdrawn `native_throttle_time_count`
  and `native_group_kills` proposal is the clearest evidence of the gap.
- **Residual runtime/producer limits.** Raw declarations/hashes do not
  authenticate a producer, common residual origins, aligned atomic reads,
  transient peaks, CPU hotplug/suspend history or physical-link semantics; the
  six-exit Python direct adapter remains unrepresented; real repetitions and
  platform/client/ARM/release acceptance are NOT_RUN. These remain future
  producer/runtime gates, not reproduced offline findings.

## Disposition

Fix R5-I1 and R5-I2 by adding the one-way source containments
(`throttled_usec > 0 => nr_throttled > 0`, `oom_group_kill <= oom`, and the
defensible `oom_group_kill <= oom_kill`) with optional-field guards and signed
raw witnesses, then re-run the retained six-repetition reproductions and the
full suite. Do not add the invalid converses (`nr_throttled > 0 =>
throttled_usec > 0` at a torn snapshot, `oom_kill <= oom`, or an arbitrary
event-duration bound). The round-4 T4-I1–T4-M2 fixes and the WP11 arithmetic
oracle are accepted as offline test results; the overall layer remains
**PARTIAL / FAIL pending those relations**. No real performance, release or
runtime acceptance follows from this review; all such gates remain **NOT_RUN**
with `release_ready=false`.
