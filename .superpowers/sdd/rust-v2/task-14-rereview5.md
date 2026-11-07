# Task 14 independent re-review — round 6

Verdict: **FAIL — one Important finding, REPRODUCED; six Minor notes.** No
Critical findings. The round-5 behavioural reproductions (R5-I1 throttle time
without a throttled period; R5-I2 group kill without an OOM event) are now
refused through `summarize`, the six-repetition scenario comparator and the
`offline.py` CLI, and the absolute-zero OOM baseline policy closes the constant
pre-existing OOM baseline blind spot. However, the new `native_group_kill_oom`
identity (`oom_group_kill <= oom`) is not a valid kernel identity, and the
catalog, both documents and the report assert it with an incorrect paraphrase of
`memory.events.oom`. This is fail-closed (any OOM already prevents PASS) rather
than a false PASS, but it is a false source identity in the normative catalog
and must be removed; `oom_group_kill <= oom_kill` is defensible and remains.

Reviewed 2026-11-07 in `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`, HEAD
`e01661755097452952c1e4ca89dc4097d67c771f`, including the uncommitted rounds 5+6
changes under `tools/performance/**`, both performance documents, and the
Review round 5 section of `.superpowers/sdd/rust-v2/task-14-report.md`. Only this
report was written in the repository; all scratch inputs, logs and evidence are
under `/tmp/task14-r6-review/`. No Git write, external network, sudo, VM,
service operation or real workload was performed. The requested
`test_offline.py` ran its built-in literal-127.0.0.1 socket self-test; no
external traffic was generated. Every recording below is a constructed
input-domain record, not a measurement. Real Python/Rust performance,
producer/runtime/client/ARM/migration/soak/release qualification remain
**NOT_RUN / OPEN**, with `release_ready=false`.

## Important finding

### R6-I1. `native_group_kill_oom` asserts a false kernel containment — REPRODUCED

Locations: `tools/performance/kernel-identities.json:8319`, `:8322`, `:8336`,
`:8345` (identity, parent `d.memory_events.oom`, citation, statement);
`:284-292` (the `oom / oom_group_kill` counter-pair decision is `identity:
native_group_kill_oom`); `tools/performance/quantity-model.json:10922-10937`
(generated relation); `docs/rust-v2/performance-harness.md:576`, `:586`, `:609`,
`:654-657`; `docs/rust-v2/performance-measurement.md:523-524`;
`.superpowers/sdd/rust-v2/task-14-report.md:1237-1243`, `:1424`, `:1463`,
`:1521`; `tools/performance/test_kernel_identities.py:259-263`, `:379`,
`:568-580`, `:591-594`.

Kernel semantics audit (from knowledge of
`Documentation/admin-guide/cgroup-v2.rst`, `memory.events`; not fetched or
version-verified): the documented definitions are

- `oom`: "The number of times the cgroup's memory usage was reached the limit
  and the allocation was about to fail. This is counted as a single event, not
  per process."
- `oom_kill`: "The number of processes belonging to this cgroup killed by any
  kind of OOM killer."
- `oom_group_kill`: "The number of times the OOM killer killed all processes
  belonging to the cgroup. This can happen when `memory.oom.group` is set to 1.
  This is counted as a single event, not per process."

`oom` is the cgroup-limit/charge-failure event, not an OOM-kill count. A
system-wide (global) OOM does not reach another cgroup's own memory limit, so
that cgroup's `oom` stays 0; the OOM killer can nevertheless select a victim in
the cgroup and, when `memory.oom.group=1`, kill all processes in the group,
incrementing `oom_group_kill` and the killed-process `oom_kill` for the
affected subtree. From knowledge of the kernel implementation, group-kill selection is also
invoked with the OOM domain unset for a system-wide OOM (the
`mem_cgroup_get_oom_group(..., NULL)` path), so this is a real system-wide
path, not a hypothetical. Therefore
`oom_group_kill <= oom` is false in general. The catalog's premise "A group OOM
kill is an OOM event in the same subtree" conflates the OOM-kill event with the
`oom` counter, and its citation's "oom counts the number of times the cgroup was
OOM-killed" is not the documented meaning. This confirms the controller's
concern.

`oom_group_kill <= oom_kill` is defensible under the catalog's documented
nonempty-victim assumption: a group-kill event selects a victim in the group and
kills at least one process, and the hierarchical `oom_kill` count includes
processes killed by that OOM killer. That identity can stay; the converse and
`oom_kill <= oom`/`oom <= oom_kill` must not be asserted. The same incorrect
`oom` paraphrase appears in the `native_group_kill_oom_kill` citation
(`kernel-identities.json:8376`) and in the `oom / oom_kill` no-native reason
(`:278`), even though that pair's decision is correct.

Reproduction. The independently qualified `reconciled_record` carrier (61
aligned samples over 600 s, 100 Hz counters, four CPUs, zero acquisition width,
stable identities, original monitoring receipts, rebound digest) is PASS
unmodified. Setting the control domain `memory_events` to `oom=0,
oom_kill=1, oom_group_kill=1` at every sample (a valid global-OOM group-kill
recording on the documented semantics) produces
`/tmp/task14-r6-review/evidence/valid-global-oom-group-kill.json`
(SHA256 `f2a4d3a5f1fd81f9c131c613341ed09f4d754c044c5f7f4e0c545ae4f983c646`):

- `summarize` returns **INSUFFICIENT_DATA**; the generated relation rows include
  `relation:native_group_kill_oom` false at every sample, while
  `relation:native_group_kill_oom_kill` is true. The absolute-zero policy
  independently adds `measured_domain_failure` and
  `oom_baseline_contaminated`.
- The six-repetition one-exit scenario is **INSUFFICIENT_DATA** with
  `quantity_model:relation:native_group_kill_oom` (plus the policy reasons), and
  the `oom_events` gate is FAIL.
- `offline.py summarize` exits **2**, writes no result, empty stderr. The
  six-repetition scenario above is the direct comparator result; the four R5
  finding variants were also exercised through the `offline.py compare` CLI
  (below), which exits 2 and writes only an INSUFFICIENT diagnostic report.
- A second valid recording (`oom=0, oom_kill=2, oom_group_kill=1`) behaves the
  same; only the false `<= oom` relation fails among the two containments.

This is over-refusal (fail-closed), not a false PASS: any nonzero OOM event is
already refused by the absolute-zero policy. The defect is that the catalog and
docs claim a false native identity and misstate `oom`; a future producer cannot
distinguish this from a genuine contradiction, and the report's "R5-I2 is closed
with two one-way containments" is only half right. The R5-I2 variants
themselves are still refused by `native_group_kill_oom_kill` and the policy
without this identity.

Fix: remove `native_group_kill_oom` and its counter-pair `identity` decision;
reclassify `memory_events.oom / oom_group_kill` as `no_native_relation` with a
correct reason (oom is a limit-reached allocation-failure event; a global OOM
group kill can occur without it); keep `native_group_kill_oom_kill` and the
absolute-zero policy; correct the `oom` paraphrase in both citations, the
`memory.events` documentation rows, the measurement document, the report, and
the `oom / oom_kill` no-native reason; update the witness table and the
R5-I2 baseline assertions (the `group_baseline` variant still fails the policy);
regenerate `quantity-model.json`; and update the counts from 140/132/36/123 to
139/131/35/124 (159 pairs and 247 quantities unchanged).

The current tests cannot catch this: `boundary_witnesses` encodes the same
false identity (`test_kernel_identities.py:259-263`), and
`applicable == set(boundary_witnesses())` (`:379`) is circular with respect to
it; `test_R5_I2_group_kill_is_contained_by_oom_and_killed_tasks` and the
baseline test assert the `native_group_kill_oom` reason. A source-semantics
audit, not a predicate/witness count, is the only way to find it.

## Minor notes

- **R6-M1 (reproduced): optional-field vacuity in `native_throttle_time_count`.**
  `quantity_model.py:110-118` and `:129-137` return true when a `when_present`
  path is absent; `kernel-identities.json:8325-8328` lists both throttle paths
  but `presence_pairs` is empty, and `run-schema.json:240-259` makes the
  throttle fields optional. A recording with `cpu.throttled_usec=1000000` on
  every control sample and no `nr_throttled` or `nr_periods` returns **PASS**
  (`/tmp/task14-r6-review/evidence/operator-mutations.json`,
  `throttle_partial_usec_only`). This is a documented optional-evidence policy
  (`performance-harness.md:563-565`), not a fully recorded contradiction; the older
  `native_throttled_periods` uses a symmetric presence pair. A symmetric pair
  here would over-refuse the valid `nr_throttled>0, throttled_usec` absent
  half-space, so the fix needs a one-way presence rule (antecedent present and
  consequent absent) or a producer requirement that `cpu.stat` throttle fields
  be captured together.
- **R6-M2 (reproduced by inspection): missing `relation_checks` cross-reference.**
  `build_quantity_model.py:170` scans only `parent`/`children`/`path`; the new
  identity uses `antecedent`/`consequent`. `quantity-model.json:4715-4719`
  (`nr_throttled`) and `:4748-4750` (`throttled_usec`) do not list
  `native_throttle_time_count` in `relation_checks`. The relation is enforced;
  only the machine-readable cross-reference is incomplete. Include
  `antecedent`/`consequent` in the scan.
- **R6-M3 (reproduced with a scratch catalog): sibling counter-pair decisions
  are not audited.** `kernel_identities.py:149-155` only flags a `no_native`
  decision when one operand is on a check's parent side and the other on its
  child side (or antecedent/consequent). Changing the `host_counters`
  `user_ticks / system_ticks` pair (both children of `host_parts`) from
  `identity` to `no_native_relation` with a reason yields
  `counter_pair_problems() == []`; the report's "any pair decision is caught"
  (`task-14-report.md:1429-1430`) is therefore overstated. The current table is
  correct; extend the audit/test to cover sibling pairs covered by a partition.
- **R6-M4 (reproduced): a later-sample single-sample throttle tear is refused.**
  `quantity_model.py:191-197` exempts only sample 0. A record with
  `nr_throttled=0, throttled_usec=10^6` at sample 1 and a coherent state from
  sample 2 onward returns **INSUFFICIENT_DATA** with
  `relation:native_throttle_time_count` (`later_sample_only_tear`). The report's
  residual limits disclose this possible over-refusal
  (`task-14-report.md:1457-1463`); no false PASS. Keep or document the policy.
- **R6-M5 (unreproduced verdict change; Minor note): `memory.events`
  containments have no read-order exemption.** `quantity_model.py:124-143`
  evaluates `scope: domain` at every sample. A one-sample `oom_group_kill=1,
  oom_kill=0` read-order tear would be refused; the absolute-zero OOM policy
  independently refuses any nonzero event, so no false PASS exists. The docs
  discuss the `cpu.stat` first-sample tear but not the analogous `memory.events`
  read; document or accept the over-refusal.
- **R6-M6 (test/table consistency; Minor note):** the raw smaps PSS threshold
  test now uses ±1 KiB (`test_accounting.py:776`) so raw values remain
  integer-kB, while the report's arithmetic table (`:68-74`) still labels the
  abstract boundary ±1 B. The direct metric API tests retain ±1 B and the smaps
  quantum requires multiples of 1024; this is not a false PASS.

## Round-5 findings replayed

Both R5-I1 variants and both R5-I2 variants were rebuilt from the descriptions
in `task-14-rereview4.md` on the qualified carrier, with direct mutations rather
than the checked-in helper values, and run through all three paths. The
positive control is PASS; the two raw hashes reported in rereview4 (R5-I1
constant `12da1e57...`, R5-I2 group-only `12baf8e7...`) reproduce exactly.

| Variant | `summarize` | Six-repetition scenario | `offline.py summarize` |
| --- | --- | --- | --- |
| R5-I1 constant (`nr_throttled=0`, `throttled_usec=10^6` every sample; SHA `12da1e57...`) | INSUFFICIENT, `quantity_model:relation:native_throttle_time_count` | INSUFFICIENT, same reason; all eight gates PASS | exit 2, no result, empty stderr, redacted output |
| R5-I1 increasing (`throttled_usec=index*10000`; SHA `ee588a71...`) | same | same | same |
| R5-I2 group-only (`oom=0, oom_kill=0, oom_group_kill=1`; SHA `12baf8e7...`) | INSUFFICIENT, both containments + `oom_baseline_contaminated` + `measured_domain_failure` | INSUFFICIENT; `oom_events` FAIL | exit 2, no result |
| R5-I2 group-over-oom (`oom=1, oom_kill=1, oom_group_kill=2`; SHA `709600ef...`) | INSUFFICIENT, both containments + policy | INSUFFICIENT; `oom_events` FAIL | exit 2, no result |

The four finding variants' `offline.py compare` CLI also exits 2 and writes
only an INSUFFICIENT diagnostic report; the valid global-OOM record was
exercised through summarize and the scenario API and was not published. Valid half-spaces remain accepted: a first-sample-only tear
(contradiction only at sample 0) PASSes; `nr_throttled>0, throttled_usec=0`
PASSes (no converse); `oom_group_kill` absent PASSes; and
`oom_kill >= oom_group_kill` PASSes the `oom_kill` containment, though the false
`<= oom` identity refuses the valid global-OOM group-kill record above. No PASS
publication occurs for any finding variant.

## Counter-pair table audit

Directly enumerated from `kernel-identities.json` and the model: 49 recorded
monotonic counters, 159 within-source pairs, 36 identity decisions and 123
`no_native_relation` decisions; `counter_pair_problems()` and
`catalog_coverage()` are empty; 140 identities, 132 generated relations, eight
unavailable identities, 247 numeric model positions and nine native maps.
Regenerating `run-schema.json` and `quantity-model.json` in a scratch copy of
`tools/performance` with `python3 -B -I build_quantity_model.py` produced
byte-identical files; the repository files were not modified.

Every pair has exactly one decision, every identity operand is in the pair's
source, and every no-native reason is source-semantic. No missing valid relation
was found among the recorded families: `cpu_stat` usage/user/system partition,
`nr_throttled <= nr_periods`, `throttled_usec>0 => nr_throttled>0`; exited-CPU
partition; I/O byte/operation pairs per stream; host busy/user/system/irq/
softirq/steal partition, busy+idle capacity, busy/outside containment; memory
threshold counts; OOM group-kill/killed-process containment. The nearest
no-native decisions (`nr_periods` vs `throttled_usec` without the unrecorded
`cpu.max` period; `oom` vs `oom_kill`; `low/high/max` vs OOM events;
read/write/discard cross-stream; RX/TX; swap-in/out; CPU classes; wakeups vs
CPU) are correctly not related by a documented inequality. Constructed
violations of the valid relations (`nr_throttled>nr_periods`,
`oom_group_kill>oom_kill`, `usage != user+system`) are refused. The one invalid
decision is the `oom / oom_group_kill` identity (R6-I1); the sibling-decision
audit gap is R6-M3.

## Exactness, determinism, publication, documentation

- **Exactness:** AST checks over all 14 performance Python files and a targeted
  grep found no float constants/`float()` in `accounting.py`,
  `quantity_model.py`, `kernel_identities.py`, `offline.py` or
  `build_quantity_model.py`; the new operators use ints and the only division is
  the existing explicit `Fraction`. Strict JSON decoding accepts seven
  performance JSON documents with duplicate/decimal/nonfinite rejection; all
  nine schema `$ref` values resolve; `test_offline`'s exactness test passes.
- **Determinism:** three fresh `python3 -B -I` interpreters produced identical
  summary SHA256 `2e5d282cb1ad77d3b3abec4d83983c204aef0aabee5b748fc942fed0e1c820a8`;
  a reversed same-role six-repetition comparison produced byte-identical report
  hashes `49172778eaf60c01121abd382bfde40fa18db7300f9d723647f7e62dd9996826`.
- **Atomic exclusive publication:** two concurrent publishers of different PASS
  inputs produced exactly one exit 0 and one exit 2, one 0600 destination, no
  temp residue, and the winner matched one input; a pre-existing destination
  retained its bytes and the republish refused. `test_offline.py`'s fsync,
  no-overwrite and symlink tests pass.
- **Documentation honesty:** both documents state no performance claim, real
  runs **NOT_RUN**, and `release_ready=false`; `acceptance.json` remains
  `3d467451dd03d1663e3c79b24eea6a18aac461f9291f8fdfe1031e1da6e86e97` with
  `release_ready=false`. The false `oom_group_kill <= oom` claim in both
  documents and the report is the R6-I1 documentation defect; the rest of the
  round-5 documentation is accurate about constructed-evidence limits.
- **Preservation:** `git diff --check` passes, the index is empty, branch/HEAD
  are unchanged, and only this review file was written.

## Verification ledger

| Fresh command/check | Result |
| --- | --- |
| `python3 -B -I -m unittest discover -s tools/performance -p test_kernel_identities.py -v` | **PASS**, 18 tests / 98.841 s; 132 applicable identities, eight unavailable, 132 removal/reverse-citation mutants, 264 signed probes, 159 pairs / 36 identities, nine round-4 refusals and nine CLI refusal/no-publication cases. |
| `... -p test_accounting.py -v` | **PASS**, 44 tests / 328.583 s. |
| `... -p test_offline.py -v` | **PASS**, 9 tests / 162.430 s; 8,142 failure-protocol cases; built-in literal-127.0.0.1 loopback self-test executed. |
| `... -p test_measurement.py -v` | **PASS**, 84 tests / 1.099 s. |
| `... -p test_accounting_mutations.py -v` | **PASS**, 14 tests / 1949.229 s; numeric schema probes 6,108/4,996 violations, model fixed-seed probes 4,104/2,046 violations, 132 relation-removal and 247 quantity-removal mutants. |
| Static/AST/JSON (`/tmp/task14-r6-review/static_check.py`) | Exit 0; 14 ASTs, seven strict JSONs, nine schema refs, counts 140/132/8/247/9, empty coverage/pair problems, byte-identical scratch regeneration. |
| R5 reproduction (`reproduce_r5.py`, `cli_compare_r5.py`) | Exit 0; four finding variants refused through summarize, scenario and both CLI paths; positive control and valid half-spaces PASS. |
| Kernel semantics audit | Confirms `oom_group_kill <= oom` is false (global-OOM group kill), and `oom_group_kill <= oom_kill` is defensible under nonempty victims. |
| Operator mutations (`operator_mutations.py`) | Exit 0; optional-field vacuity PASS reproduced; bool/string/None/negative/huge inputs refused; later-sample tear over-refused; no false PASS. |
| Counter-pair audit (`pair_audit.py`) | Exit 0; 49/159/36/123; no missing valid relation; sibling-decision audit gap reproduced. |
| Determinism/publication (`determinism_pub.py`) | Exit 0; identical fresh-interpreter hashes; reversed compare identical; race one winner 0600/no temp; existing destination preserved. |
| Preservation | `git diff --check` OK, index empty, branch `rust/v2`, HEAD `e016617`; only this report is a new repository write. |
| Runtime/real workloads/release | **NOT_RUN**; no real 600 s workload, VM, Rust build, migration, soak or release qualification. |

## Disposition

**FAIL pending removal of `native_group_kill_oom` and correction of the `oom`
paraphrase/citation.** The R5-I1 behavioural fix (`native_throttle_time_count`)
and the R5-I2 refusal are accepted for their reproduced cases: all four finding
variants are refused, no finding variant publishes a PASS, and the absolute-zero
OOM baseline policy closes the constant-nonzero blind spot. The remaining
Important finding is a false source identity in the normative catalog and its
documentation, not a false PASS; it is fail-closed but must not be accepted as a
kernel identity. `native_group_kill_oom_kill` and the independent absolute-zero
policy should remain. The Minor notes are evidence-completeness, metadata,
test-coverage and over-refusal limits; none is a Critical defect. This review
does not qualify any real performance, producer, runtime, client, ARM,
migration, soak or release gate; all remain **NOT_RUN** with **no performance
claim** and **release_ready=false**.
