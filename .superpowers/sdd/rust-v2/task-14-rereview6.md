# Task 14 independent re-review — round 7

**Verdict: PASS.** All six round-6 Minor findings and the round-6 Important
finding R6-I1 are closed by reproduction. No Critical or Important finding was
found. Four Minor notes remain, all reproduced below; none is a false PASS, a
false kernel identity, or a publication defect. The previously failing
`native_group_kill_oom` identity is gone, the valid system-wide-OOM group-kill
shape is refused only by the independent absolute-zero OOM policy, the one-way
presence rule and sibling-pair audit work as claimed, and the documents remain
honest about the constructed/offline scope. Real Python/Rust performance,
producer/runtime/client/ARM/migration/soak/release qualification remain
**NOT_RUN / OPEN**, with **no performance claim** and `release_ready=false`.

Reviewed 2026-11-07 in `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`, HEAD
`e01661755097452952c1e4ca89dc4097d67c771f`, including the uncommitted rounds 5–7
changes under `tools/performance/**`, both performance documents and the
**Review round 6** section of `.superpowers/sdd/rust-v2/task-14-report.md`.
Only this report was written in the repository. All scratch inputs, logs,
scripts and evidence are under `/tmp/task14-r7-review/`. No Git write, external
network, sudo, VM, service operation or real workload was performed. The
requested offline suite used `PERFORMANCE_OFFLINE_NO_NETWORK=1`; its one literal
127.0.0.1 loopback self-test was skipped and is reported **NOT_RUN**. Every
recording below is a constructed input-domain record, never a measurement. The
controller's own full suite ran concurrently; wall times below are under that
contention and are not performance results.

## Round-6 findings: closure by reproduction

### R6-I1 — CLOSED. The false `oom_group_kill <= oom` identity is removed

The catalog's `memory.events.oom / oom_group_kill` pair is now
`no_native_relation` with the corrected reason at
`tools/performance/kernel-identities.json:288`: `oom` counts cgroup
limit-reached allocation-failure events, not OOM kills; a system-wide OOM can
group-kill the cgroup while its own `oom` stays zero. The identity and its
generated relation are absent; the surviving containment is
`native_group_kill_oom_kill` at `kernel-identities.json:8316`, `:8337` and
`quantity-model.json:10924`, parent `d.memory_events.oom_kill`, child
`d.memory_events.oom_group_kill`. The generated throttle relation is at
`quantity-model.json:10911`. Counts are 139 identities / 131 generated
relations / 35 identity pairs / 124 no-native pairs / 159 pairs / 247
quantities / eight unavailable identities, matching the documents and report.

Two constructed valid global-OOM group-kill recordings were exercised
(`oom=0, oom_kill=1, oom_group_kill=1` and `oom=0, oom_kill=2,
oom_group_kill=1`), with the exact SHA256 values reported by the implementation
(`8104ca6536a4318a24ed1eb991ba5309a19736c5a8a5625361023c71d8b21b6a` and
`c33c7e5b6252a54a398b28807a322e15580a131d4dfe7c8b0d23405c6b15a861`):

- `summarize` returns **INSUFFICIENT_DATA** with exactly
  `['measured_domain_failure', 'oom_baseline_contaminated']`; the reported
  `oom_events` are 2 and 3. No `relation:native_group_kill_oom` row exists at
  all; the surviving `native_group_kill_oom_kill` relation is true at every
  domain sample (305/305 rows).
- The six-repetition one-exit scenario is **INSUFFICIENT_DATA** with the same
  two policy reasons and `oom_events` gate **FAIL**; it contains no
  `quantity_model:relation:native_group_kill_oom` reason.
- `offline.py summarize` exits **2**, writes no destination, empty stderr,
  status INSUFFICIENT_DATA. `offline.py compare` exits **2**, writes an
  INSUFFICIENT report whose scenario is INSUFFICIENT with the same policy
  reasons and no false native reason.

The R5-I2 variants are still refused without the removed identity:
`group_only` (`0,0,1`) and `group_over_oom` (`1,1,2`) fail the surviving
`native_group_kill_oom_kill` containment and the absolute-zero policy; the
constant-baseline variants `group_baseline` (`1,1,1`), `oom_baseline` (`1,1,0`)
and `oom_kill_baseline` (`0,1,0`) are refused by the policy; `oom_group_kill`
absent and all-zero events PASS; a nonzero event only in the non-control
`runtime` domain is caught by the policy. A genuine containment violation
(`oom_kill=1, oom_group_kill=2`) fails the containment. No global-OOM or R5-I2
variant publishes a PASS. This closes R6-I1 and the R5-I2 false-identity
concern. I re-checked the current kernel-semantics paraphrase from knowledge
(not fetched): `oom` is the limit-reached allocation-failure event, and the
system-wide group-kill path can leave it zero, so `oom_group_kill <= oom` is not
a kernel identity; `oom_group_kill <= oom_kill` remains defensible under the
documented nonempty-victim assumption.

### R6-M1 — CLOSED. One-way presence in `implies_positive`

`quantity_model.py:102-131` now accepts an absent or nonpositive antecedent
vacuously and requires a present positive consequent only when the antecedent is
present and positive. The catalog records
`presence_rule: positive_antecedent_requires_present_positive_consequent` and
does not rely on a symmetric `when_present` gate; `compile_relation` rejects a
`when_present` field on `implies_positive` (`quantity_model.py:112-113`).

Reproduction on the qualified carrier (all constructed):

- The manual R6-M1 shape — `throttled_usec=1000000`, both `nr_throttled` and
  `nr_periods` absent at every control sample — has SHA256
  `f183166f50e73653b079da6650983adf946973ccd8e44b6291747418e627cac1` and
  summarizes **INSUFFICIENT_DATA** with the single reason
  `quantity_model:relation:native_throttle_time_count`; `offline.py summarize`
  exits 2, writes no result and empty stderr; the six-repetition scenario is
  INSUFFICIENT_DATA with the same single reason. No other relation masks it.
- The valid half-spaces PASS: `nr_periods=1, nr_throttled=1,
  throttled_usec` absent; all three throttling fields absent; all three zero;
  the first-sample-only tear.
- A fresh 121-case direct sweep (11 antecedent states × 11 consequent states:
  absent, zero, 1, 2, −1, string, float, bool, None, list, dict) matched the
  specified semantics in **121/121** cases, including fail-closed wrong types
  and negative antecedent. A synthetic `presence_pairs` gate matched in 18/18
  cases; the single-key form in 4/4; the containment form in 9/9.
- Ten wrong-type/negative/huge record mutations through `summarize` were all
  **INSUFFICIENT_DATA** with `invalid_run` (no false PASS).

The later-sample tear remains deliberately over-refused: a coherent run with
`nr_throttled=0` at samples 0–1 and 1 afterwards, `throttled_usec=1000` at all
samples, is INSUFFICIENT with only
`quantity_model:relation:native_throttle_time_count`; the first-sample-only
tear PASSes. This matches the documented R6-M4 policy.

### R6-M2 — CLOSED for the reported entries

`build_quantity_model.py:170` now includes `antecedent` and `consequent` in the
cross-reference scan. `samples.*.domains.*.cpu.nr_throttled` and
`samples.*.domains.*.cpu.throttled_usec` list `native_throttle_time_count` in
`relation_checks`, and `test_kernel_identities.ReviewRoundSix.test_R6_M2`
passes. A scratch mutation restoring the old scan (only `parent`, `children`,
`path`) makes that test fail on both entries, confirming the test catches the
reported regression. The scan remains substring-based, so other cross-reference
noise remains; see Minor R7-M2. No enforcement depends on `relation_checks`.

### R6-M3 — CLOSED. Covered sibling pairs are audited

`kernel_identities.py:75-83` defines child-expression groups and
`:149-177` treats a pair as covered by one parent/child, antecedent/consequent,
or two distinct sibling groups. `counter_pair_problems()` returns `[]` on the
checked-in catalog. The four in-memory catalog mutations (host
`user_ticks/system_ticks` siblings, `nr_periods/nr_throttled` parent/child,
`nr_throttled/throttled_usec` antecedent/consequent,
`oom_kill/oom_group_kill` containment) each produce
`counter_pair_unrelated_but_identity:<pair>` and the R6-M3 test passes.

Independent scratch confirmation:

- Restoring the old audit (only parent/child/antecedent-consequent, no sibling
  scan) makes `test_R6_M3` fail on the `sibling partition` subtest with
  `[]` problems.
- Mutating the scratch catalog's host `user_ticks/system_ticks` pair from
  `identity` to `no_native_relation` makes `test_R6_M3` fail on its baseline
  assertion, and makes the import-time `CATALOG_PROBLEMS` nonempty.
- The valid `process utime_ticks/stime_ticks` no-native decision is not treated
  as a sibling pair because both are summed inside one child expression; the
  full suite's baseline `[]` confirms no current false positive.

The report's wording that removing the *audit call* is caught is not correct;
see Minor R7-M3.

### R6-M4 and R6-M5 — CLOSED as documentation/over-refusal disclosure

`docs/rust-v2/performance-harness.md:584-595` states the exact `cpu.stat`
first-sample exemption and the deliberate later-tear over-refusal;
`:597-612` and the `memory.events` table row at `:637` state that the
`memory.events` containment has no first-sample read-order exemption and that a
one-sample tear is over-refused because any nonzero OOM event is independently
refused. The report's residual limits repeat both.

Reproduction: a coherent one-sample `oom_group_kill=1 / oom_kill=0` tear at
sample 1 (no counter regression; group becomes 1 and kill becomes 1 only
afterwards) is **INSUFFICIENT_DATA** with
`quantity_model:relation:native_group_kill_oom_kill` plus
`measured_domain_failure`; the coherent `oom_kill=1` version is refused by the
policy. This is over-refusal, not a false PASS. A later throttle tear is
over-refused as above; the first-sample throttle tear PASSes.

### R6-M6 — CLOSED. Arithmetic table matches the ±1 KiB raw test

The report's table now labels the raw-record control-PSS boundary as
`-1 KiB / +1 KiB` at `task-14-report.md:70-71` with the explanation at `:76-78`;
`test_accounting.py:773-781` uses `(-1024, 0, 1024)` for raw records and keeps
the abstract ±1-byte boundaries for the direct metric API. The test passes.

## Fresh adversarial sweep (beyond the round-6 reproductions)

- **Presence logic:** 121/121 direct `implies_positive` cases as above; 18/18
  synthetic `presence_pairs`; 4/4 single-key; 9/9 containment presence; all
  absent/zero/positive/negative/wrong-type shapes behaved as documented, with
  no false PASS.
- **Throttled period partition:** valid `nr_throttled <= nr_periods` and valid
  delta shapes PASS; `nr_throttled > nr_periods`, negative values, one-sided
  presence and a string child are refused. The one-sided presence refusal is
  fail-closed and is Minor R7-M4 below.
- **Throttle interval relation:** a valid increasing run with
  `nr_periods=i, nr_throttled=i//2, throttled_usec=0` until throttling starts
  PASSes; invalid delta shapes are refused by
  `relation:native_throttled_period_deltas`.
- **OOM containment/policy:** `group_only` and `group_over_oom` fail the
  containment plus policy; `global_group_kill`/`global_group_kill_two` fail only
  policy; `oom=1` alone is policy-refused; `oom_group_kill` absent PASSes;
  `oom_kill` absent is `invalid_run`; `oom_kill`/`oom_group_kill` wrong types and
  negatives are refused.
- **Throttle in a non-control domain:** a positive `throttled_usec` without
  `nr_throttled` in the `workload` domain is refused with
  `relation:native_throttle_time_count`, so the rule is not control-only.
- **No false PASS** was found in any catalog relation touched in rounds 5–7.
  All observed over-refusals are fail-closed and documented (except the
  presence-pair documentation precision in R7-M4).

## Minor findings (all reproduced; none blocks)

### R7-M1 (Minor) — the report's regenerated `quantity-model.json` SHA256 is wrong

`task-14-report.md:1767-1768` claims repeated regeneration produced SHA256
`c2bf1f470134a032dbcc7a317b5921b65cfb831ef0b071a2ab6aa365cbd74e5a` for
`run-schema.json` and
`415f0c02333aef96e7c41ebcc585a53e087cc2cd3fde675cd70e8826fe405aaa` for
`quantity-model.json`. The run-schema value is correct; the actual
`quantity-model.json` in the repository, and two fresh
`python3 -B -I build_quantity_model.py` regenerations in a scratch copy, are
byte-identical to
`8eced2f8a1c14ec59f7a1d1df00899f089c86c042e1d8ea8df0a3227e3976b77` (391,183
bytes). Regeneration is deterministic and byte-identical; only the report's
evidence hash is stale/wrong. No functional impact.

### R7-M2 (Minor) — `relation_checks` cross-references are substring matches and include false positives

`build_quantity_model.py:170` tests `entry['path'].split('/')[-1] in
json.dumps([...])`, i.e. substring containment, not exact operand-name
extraction. The generated model therefore contains false machine-readable
cross-references, including the identity at the centre of R6-I1:

- `samples.*.domains.*.memory_events.oom` (`quantity-model.json:5443`) lists
  `native_group_kill_oom_kill` (`:5452`), although that containment's operands
  are only `oom_kill` and `oom_group_kill`; `oom` is not an operand. The match
  is the substring `oom` inside `oom_kill`/`oom_group_kill`.
- `samples.*.domains.*.memory_events.max` (`:5411`) lists `sum_threads`,
  `fd_limit`, `pid_limit` and `thread_limit` because `max` occurs in
  `max_fd_entries` and `pid_max`.
- `traffic.bytes` (`:7447`) lists dozens of byte-counter checks because
  `bytes` is a substring of every `*bytes` operand; the monitoring
  `...observations.*.time` row lists process-tick identities because `time`
  occurs in `utime_ticks`/`stime_ticks`; `cpu.user_usec` lists `exited_parts`
  and the exited-CPU monotonic row; `pagetables` lists `native_sec_pagetables`.

No production code reads `relation_checks`; enforcement uses `relations`, so
there is no false PASS. The specific R6-M2 omission is fixed, but the field is
not the exact cross-reference the build comment claims. Fix by extracting exact
operand names (including bare `present_sum` keys and the final component of
`path` rules) and adding a test that, for example, `oom` is not listed for
`native_group_kill_oom_kill`.

### R7-M3 (Minor) — removing the counter-pair audit call is not caught

`kernel_identities.py:215` is the only import-time call to
`counter_pair_problems`. `task-14-report.md:1451-1454` says "removing the audit
call, any pair decision, or labelling a covered pair ... is caught by the
coverage and mutation tests", and `:1784-1785` says the round-5 overstatement
was replaced with the exact scope. I removed only the
`problems.extend(counter_pair_problems(catalog, schema, model))` call in a
scratch copy of `tools/performance`; the complete
`test_kernel_identities.py` then still ran **22 tests, exit 0**, and
`quantity_model.CATALOG_PROBLEMS` was `[]`. A catalog pair mutation is caught
(`CATALOG_PROBLEMS` becomes the expected
`counter_pair_unrelated_but_identity:...`), so the audit itself is live today;
the missing piece is a regression test for the call. The report's claim is
therefore inaccurate. Add a test that removes/patches the call or asserts
`coverage()` contains the pair problems.

### R7-M4 (Minor note) — the symmetric `presence_pairs` policy is not covered by the "one exception" documentation

`docs/rust-v2/performance-harness.md:566-571` says optional fields expand only
where present and that "the one exception is the documented one-way presence
rule of `implies_positive`." `native_throttled_periods` also has a symmetric
`presence_pairs` gate (`kernel-identities.json:4195-4203`, compiled at
`quantity_model.py:137-145`): a schema-valid record with `nr_periods=1` present
and both `nr_throttled` and `throttled_usec` absent is **INSUFFICIENT_DATA**
with `quantity_model:relation:native_throttled_periods`; so is the mirror
one-sided form. This is fail-closed over-refusal, not a false PASS, but the
catalog assumption "optional native fields are checked only when present" and
the document's "one exception" sentence do not describe the both-or-neither
rule. Either document the symmetric pair as a second presence policy or make
the checkable half-space expand as `when_present` does; add the one-sided
record to the truth table.

## Verification ledger

| Fresh command / check | Result |
| --- | --- |
| `python3 -B -I -m unittest discover -s tools/performance -p 'test_kernel_identities.py' -v` | **PASS**, 22 tests / 107.290 s; 131 applicable identities, eight unavailable, 131 removal/reverse-citation mutants, 262 signed boundary probes, 159 pairs / 35 identity pairs. |
| `... -p 'test_accounting.py' -v` | **PASS**, 44 tests / 323.414 s. |
| `PERFORMANCE_OFFLINE_NO_NETWORK=1 ... -p 'test_offline.py' -v` | **PASS**, 9 tests / 165.158 s; one literal-127.0.0.1 loopback test skipped and **NOT_RUN**; 8,142 failure-protocol cases; fsync/no-overwrite/symlink tests pass. |
| `... -p 'test_measurement.py' -v` | **PASS**, 84 tests / 1.143 s. |
| `... -p 'test_accounting_mutations.py' -v` | **PASS**, 14 tests / 1,958.775 s (32m38.890 s wall); numeric schema probes 6,108 registered / 4,996 violations; model fixed-seed probes 4,104 generated / 2,046 violations; 131 relation-removal mutants killed and 247 quantity-removal mutants. |
| `/tmp/task14-r7-review/repro_r6.py` | Exit 0; R6-I1 global-OOM/containment/scenario/CLI, R6-M1 presence/121-case sweep, wrong types, R5-I1/R5-I2 variants, partition/containment cases, pair mutations. |
| `/tmp/task14-r7-review/cli_determinism.py` | Exit 0; CLI compare refusal for R5-I1 constant/increasing, R5-I2 group-only/group-over-oom, global OOM; PASS control scenario; one-winner 0600 race; no temp residue; republish/retain and symlink refusal. |
| `/tmp/task14-r7-review/static_check.py` | Exit 0; 14 Python files parsed/compiled, seven strict JSON documents (duplicate/decimal/nonfinite rejection), nine schema `$ref` values resolved, no float constants/`float()` in the five production files, counts 139/131/35/124/159/247/8, `catalog_coverage()==[]`, two byte-identical regenerations. |
| Scratch audit mutations (R6-M3) | Old audit (no sibling scan) → `test_R6_M3` fails on `sibling partition`; scratch catalog pair mutation → test and import-time `CATALOG_PROBLEMS` fail; both confirm the test catches the reported audit gap. |
| Scratch old scan (R6-M2) | Restoring the old `parent/children/path` scan → `test_R6_M2` fails on both throttle entries. |
| Scratch no-call audit (R7-M3) | Removing the `counter_pair_problems` call → full `test_kernel_identities.py` still 22 tests, exit 0; the report's removal claim is not covered. |
| Determinism | Three fresh `python3 -B -I` interpreters on the same PASS input produced identical summary SHA256 `928db3057c51958811c18464c7ff9b9ce2fc294eb3bdbbc1c122d78a79b888ed`; two CLI comparisons produced identical report SHA256 `141496659d0fc9777100ff7cbfcfab989dbc59d4fa68e640f1ceb64d298020bf`. |
| Regeneration | Two `build_quantity_model.py` runs in scratch produced `run-schema.json` `c2bf1f47...` and `quantity-model.json` `8eced2f8...`, byte-identical to the repository; the report's `415f0c02...` claim is wrong (R7-M1). |
| Preservation | `git diff --check` exits 0; the index is empty; branch `rust/v2` and HEAD `e016617...` are unchanged; only this review file is a new repository write. |
| Documentation honesty | Both documents state no performance claim, real runs **NOT_RUN** and `release_ready=false`; `docs/rust-v2/acceptance.json` remains `3d467451dd03d1663e3c79b24eea6a18aac461f9291f8fdfe1031e1da6e86e97` with `release_ready=false`. |
| Runtime/real workloads/release | **NOT_RUN**; no real 600 s workload, VM, Rust build, migration, soak or release qualification. |

Durations are wall-clock under the controller's concurrent full-suite run and
are not measurements of product performance.

## Disposition

**PASS.** R6-I1 is closed: the false `oom_group_kill <= oom` identity, its
generated relation and its counter-pair identity decision are gone; the valid
global-OOM group-kill shape is refused by the independent absolute-zero OOM
policy and not by a false native contradiction; the surviving nonempty-victim
`oom_group_kill <= oom_kill` containment and the corrected `oom` citations are
retained. R6-M1–R6-M6 are closed by the reproduced scenarios above. The four
Minor notes are evidence-metadata, test-coverage/documentation precision issues;
none is a false PASS, a false source identity, or a publication defect. This
review does not qualify any real performance, producer, runtime, client, ARM,
migration, soak or release gate; all remain **NOT_RUN** with **no performance
claim** and **release_ready=false**.
