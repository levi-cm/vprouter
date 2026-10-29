# Owner-cost diagnosis and requirements readiness review

2026-10-29. Independent read-only review before source dispatch. The only file
written by this reviewer is this report. No source edit, Git operation, test,
build, helper-main, VM, SSH, Docker, privileged action, resource/profile change,
native experiment or subagent was used. Root retains dispatch and all later
acceptance decisions. This review does not authorize an optimizer or parser
experiment.

## Exact inputs and scope

Requested worktree `/DATA/AppData/vprouter-rust-v2`; supplied branch `rust/v2`
and HEAD `debb316d9eb734bc5f2345df6953720ca1091cd2`. Git was not queried.
The raw run binds source commit
`51c15016353936288067f5cd3e4c2a6715be1061`, archive
`f5cecc2f3af90a7e638f9bfdcb1d2db3a70abb7666d678b2133fe88601d9aa7c`,
203 verified tracked build inputs and aggregate
`d9fe3200b57f73d8cf5c6e847277dbf463c5ab672559f208383c49f81de12167`.
These are the recorded run binding, not a new coherent-artifact verification.

Independently calculated SHA256 values:

| Input | SHA256 |
| --- | --- |
| `.superpowers/sdd/rust-v2/task-8c-bootstrap407-diagnosis.md` | `c1151644386a6a6cb142dcfc51de7f2269ffe7fb91a746800c5143f6d7330b87` |
| `.superpowers/sdd/rust-v2/task-8c-owner-cost-brief.md` | `6ef36bc5defba7c337f1dca92f45aceee5ce57a2037b3cb8e20c9518e59f2aed` |
| `docs/rust-v2/IMPLEMENTATION.md` | `353f0e82d9dcf7b3e1216c27ac4c505bdc8fa6ee06ee3e6b833f1d3e11594125` |
| `target/lab-state/actual-program-run-407.json` | `4c16ab618e83a95bc56121e850494c2efde15c6711eedcaeffc9212bffe6e922` |
| `target/task8c-digest-hex-root-20261029/bootstrap407-closed-metadata.json` | `2a61b8c7774c5461c99ac2ed51d73a1200e2492da5bfd283a8ff90d5a33a32ff` |
| `target/task8c-digest-hex-implementation/rust-after.json` | `f31ce696bd7f647a841da2904f8a383d4ab8fee37662d3678539e86a6ac03b3b` |
| `crates/vprouter-launch/src/supervision.rs` | `4f864fa5bce9140dd426fc584303f5ce4ee4c03ec08338009e00ff24bf619ef0` |
| `crates/vprouter-launch/src/owned/preparation/lab_cost.rs` | `a7e5d4f832559d66d7cc6fa4193b2c82d051b4629850c0021ef47e5999601f68` |
| `crates/vprouter-launch/src/owned/preparation/quarantine.rs` | `f7ec6cddcf345ceacd26b448844d49598b8fe3cafd60f9cf0c785f3de20e0336` |
| `crates/vprouter-launch/src/attachment/operational/bootstrap.rs` | `da65fe12514a8f668f10d83cb4a668d9d59f0dd6faa26edf6487d9edab6f9d22` |
| Existing independent407 preservation review | `a8185132c0ace018259441cfd493e78c2cfbc761e8b7a053e1fa1beebc2a6aa5` |

All179 current `crates/**/*.rs` paths exactly match the frozen manifest's path
set, and every file hashes to its recorded value: zero changed/missing/extra
Rust paths. This is a present source-byte observation. The prior independent407
preservation review was only hash-identified; its resource/preservation audit
was not duplicated.

## Verdicts

- **Diagnosis: PASS for diagnostic readiness.** The observed failure and the
  attribution gap support measuring owner internals. The diagnosis does not
  identify the exact failing clock predicate or establish a parser root cause.
- **Specification: PASS.** The exact two-file cfg(test) slice is feasible against
  the frozen source. Five boundaries and15 fixed rows can be added while retaining
  original expressions, errors, evaluation order and normal-build behavior.
- **Quality plan: PASS, implementation unreviewed.** Separate selected-row cells,
  existing session tokens, bounded stopped output and focused collector checks
  are suitable. All implementation/test/build conclusions remain NOT_RUN here.
- **Requirements: PASS for Root to consider explicit diagnostic dispatch.** The
  brief preserves local-only testing, existing identities/state/credentials,
  bounded provider retry repair, production and release gates. It grants no
  runtime, optimizer, parser, provider or acceptance change.
- **Sensitivity: PASS for the specified closed schema.** New output contains
  fixed labels and bounded counts/durations only. It must not include record
  contents, native identifiers, paths, credentials or dynamic debug text.

No blocking finding in the brief. The checks below are implementation acceptance
conditions, not evidence that an implementation already satisfies them.

## Evidence limits and reason for the diagnostic

Independently parsed the stored raw stderr and compared all13 wrapper,30 nested
and24 retained rows with closed metadata: exact ordered equality for all67 rows.
Run407 is recorded FAIL, exit1, zero completed case markers. Its boundary remains
HOST `native_poll` / `reading` / `Deadline`. Original request
204882.642003901 and deadline204884.642003901 retain the original2.0-second
window. Boundary observation204884.651831267 is a later observation, not an exact
inner clock-check timestamp. The19.377-second outer run wall time includes setup.

The retained owner rows are query4292/223044898ns,
policy3924/218390253ns and other442/21460135ns. They are the largest measured
same-entry-count Binding parts; they include verification, native IO, cloning,
observers and scheduling. Other may include pre-window work. Nested/retained
totals overlap wrappers and must not be added or subtracted into exclusive cost.
No row isolates parser share, exclusive CPU time, native time saved, causal
speedup, absence of resource contention, or a two-second fit. Query verification
and the incomplete policy result must remain separate, as in the diagnosis.

The owner method is global: `capture` calls `verify`, and `record` calls `verify`
then clones; other callers can contribute during the active session. New rows
therefore cannot be assumed equal in count to the retained Binding owner row or
to one another. Their purpose is broad attribution, not exact Deadline tracing.

## Evaluation-order and early-error requirements

The frozen `OwnerDomain::verify` sequence is host_preflight, record.validate,
host_namespace_identities and its comparison, then the final native predicate
chain. `record` calls verify before cloning. No later work may become eager.

1. Scope the host-preflight timer around only its original call. A `?` failure
   must drop that timer and return the same original error; later rows stay zero.
2. Scope record-validation the same way, after preflight succeeds.
3. The namespace timer must end after the existing function expression, before
   comparison with `self.namespaces`. Both function errors and comparison-false
   behavior must retain their original outcomes; the comparison is not measured.
4. Put one timer around the complete original final boolean expression. Preserve
   the left-to-right `||` short circuit: current process, boot, pinned group,
   named group, then self-cgroup read/comparison. Every existing `?` and mismatch
   retains its original error. Do not extract operands or add live observations.
   A mismatch return after the condition is outside that timer's intended scope.
5. Clone timing starts only after verify succeeds and ends after the existing
   clone expression, before wrapping it in `Ok`. Do not time the whole record
   method under this key or change clone/drop ownership.

RAII blocks can meet all five rules, including `?` early returns and existing
unwinding. Removing only new cfg(test) statements and minimal expression braces
must reconstruct the original supervision source. Relative `super::owned::...`
paths preserve the existing nesting convention; crate-root-specific paths can
break admission fixtures that include the launch module under another module.
No helper-main edit is needed or authorized.

## Collector, child and session requirements

The current lab_cost module is excluded by its parent `#[cfg(test)]`. It already
provides the necessary crate-visible entry point without changing visibility
outside tests. Add a distinct five-key enum,15 selected-row cells and an owner
timer. Retain old State layout and old Timer/RetainedTimer behavior, and do not
copy the new table on every timer operation. Necessary snapshot-field
initialization, reset and stopped-snapshot plumbing must remain additive; they
are not permission to refactor existing collector logic or row-emitter loops.

Capture the existing creator/epoch/family token at timer entry. No borrow, lock
or table reference may span instrumented work. Update only the selected new row
on drop after checking the existing active/creator/epoch contract; saturate both
u64 calls and u128 elapsed_ns. Reset on every arm, including the epoch-exhaustion
path; inactive, stopped and stale timers cannot contribute. Family is captured
at timer entry from the cached loop-entry family, not reclassified at drop.

Do not add getpid to timer construction/drop. Fork descendants inherit a copy
of metadata and cells; local writes may succeed only in their COW-private copy.
They must never merge into or export the parent's totals. The existing actual
creator PID check at unrestricted stop/export boundaries must still disable a
foreign stop and refuse a snapshot. The publisher filter permits clock_gettime
but not getpid; no filter, permission or unwind-path change is justified.

New checks should exercise nested/error entries, family capture, arm/reset,
stale epochs, inactive/stopped drop, session-drop isolation, saturation and
foreign-creator/COW-private accounting, including preservation of parent rows.
They should verify counts/state rather than impose elapsed-time thresholds.
Retain meaningful old tests. No test or build was executed for this review.

## Output preservation and sensitivity

The existing failure path stops collection before obtaining stderr and emitting
the boundary,13 wrappers and the snapshot's30 nested plus24 retained rows. Append
the15 owner rows after these old rows at that same snapshot emitter. Preserve
old labels, field names, order and measurement meaning. Actual elapsed values
will be affected by the added observer; old-output preservation does not imply
unchanged numerical timings on a later run.

Emit query,policy,other, each with keys in brief order, using exactly
family/category/calls/elapsed_ns/measurement/grouping and the stated literals
`inclusive_owner_elapsed` and `lab_loop_entry_step_family`. With u64/u128 decimal
maxima, ASCII labels and one newline per row, the added15 rows occupy at most
**3434 bytes**, and the longest line is235 bytes. This byte bound does not bound
stderr blocking time. Ignore writer errors as before; diagnostics must not mask
the original error. No output while collection is active, per-call text,
collection-time formatting or new secret-bearing values are permitted.

The additional Instant/token/cell work, TLS access, cache footprint, COW pages
and scheduler delays perturb measured inclusive elapsed time, including existing
outer rows. Pure validation and cloning can be small relative to that observer.
No exact CPU share, sum-of-parts wall estimate or native performance claim can
be inferred from the new rows alone.

## Dispatch and remaining gates

Before an authorized edit, freeze all179 source hashes again. Afterward prove
exactly the owned two paths changed and177 unowned paths stayed byte-identical,
reconstruct supervision, and retain exact diff/hashes/full launch-library test,
fmt and strict launch lib/tests Clippy logs. Root separately owns reader support,
independent source review, fresh workspace/coherent-artifact checks, the authored
60-link preservation baseline, checkpoint/push/tag and any next local VM run.

Original398-407 FAIL records, original window and prior resources remain
preserved. This review neither repeats the407 preservation audit nor validates
new archival state. Full8c, ARM, real clients, migration, benchmark, soak and
release gates remain open/NOT_RUN. There is no native two-second-fit or causal
speedup proof. The parser/pure-optimizer experiment remains an unimplemented,
separately authorized proposal.
