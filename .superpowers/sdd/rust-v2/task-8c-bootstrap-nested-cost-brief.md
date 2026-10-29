# Bootstrap nested elapsed-cost diagnostic

Worktree `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`, base `46239ec`.
Read this first as the bounded requirements, then the403 diagnosis and binding
IMPLEMENTATION.md. This is diagnostic preparation within active8c, not a fix.

Run403 proves native_poll/intent/Deadline after the original query hold/release
and policy two held polls/twelve negatives. Its wrapper totals cannot attribute
the cost to immutable encoding, full-history validation or live custody checks.
Do not implement the proposed immutable-record cache without that attribution.

## Required diagnostic behavior

Add only cfg(test) fixed-label elapsed counters around existing nested work.
Measure both query and policy paths. Distinguish full allocation/anchor memory
validation, Binding service custody, Binding retained verification, exact owned
progress, typed Bootstrap progress, original proof rechecks, bounded record JSON
encoding, record SHA256, and native journal advancement. A small additional
expected-record encoding label inside the owned-progress verifier may separate
immutable expected serialization from the global encoding total.

Use a closed enum and fixed bounded array of counts and saturating nanosecond
totals, process/thread-local to this test only. Entry/drop timers must cover
early Result errors without changing the returned Error. Timer state must not
hold a borrow across the original call or introduce locks, authority, fallible
logging, dynamic/unbounded allocation or per-poll output. Inactive outside this
Bootstrap lab invocation; stop collecting before emitting a snapshot. Emit at
most one fixed table on the already instrumented first helper failure. Label it
inclusive nested elapsed time; categories overlap and must never be summed as
disjoint wall/CPU costs. Do not log caller strings, paths, identities, requests,
descriptors, profiles or credentials. Preserve the existing13 wrapper rows.

Every new production-location statement/import/item must be explicitly cfg(test)
and absent from normal builds. Existing statements, expression evaluation order,
short-circuit behavior, errors and all clock observations remain unchanged. Keep
original2s windows, live source/slot/ancestry/canonical/proposed/pending checks,
all ownership/IO/registry/frame/fence checks, required held polls, negatives,
release points, child/journal operations, failure latch/collection and lab tail.
No optimization, verification cache, timeout change or additional native action.

## Owned boundaries

Proposed bounded paths (confirm minimal final list in report):

- `crates/vprouter-launch/src/owned.rs`: allocation-memory, encode_record and
  record_digest entry timers only.
- `crates/vprouter-launch/src/owned/preparation.rs`: cfg(test) diagnostic module,
  Native advancement and OriginalWrite proof entry timers only.
- `crates/vprouter-launch/src/owned/preparation/quarantine.rs`: service-custody,
  retained, owned-progress and expected encoding timers only.
- `crates/vprouter-launch/src/owned/preparation/bootstrap.rs`: typed Bootstrap
  progress entry timer only.
- `crates/vprouter-launch/src/owned/preparation/lab_cost.rs`: new cfg(test) fixed
  diagnostic support if needed.
- `crates/vprouter-launch/src/attachment/operational/bootstrap.rs`: cfg(test)
  lab start/stop/snapshot hooks at existing diagnostic boundary only.

No other source path, manifest, dependency, controller, golden result, acceptance
gate, retry repair or resource may change. No Git mutation/build freeze/VM/SSH/
Docker/privileged test; Root owns these. No subagents.

## Verification and report

Before editing snapshot all Rust source hashes. Verify exactly the owned paths
changed and prove normal-build source semantics identical after removing only
new cfg(test) instrumentation. Run focused launch library tests, format and
strict launch lib/tests Clippy; retain exact commands and full logs under an
ignored target directory. Existing meaningful tests compile the actual paths;
do not add log-text mirror tests. New timer-helper tests only if needed to prove
nontrivial bounded/reentrant/inactive behavior. Native runtime remains NOT_RUN.

Write `task-8c-bootstrap-nested-cost-report.md` with final owned hashes, exact
diff artifact, unchanged protected-source proof, diagnostic scope/limits,
commands/results, self-review and remaining native gates. Freeze source and
report for independent spec/quality review. Root alone freezes artifacts,
authors preservation from403 exact canonical endpoint, pushes the milestone,
and runs the next owned local VM experiment after review.
