# Bootstrap nested elapsed-cost diagnostic

2026-10-29. Implemented only the diagnostic authorized by
`task-8c-bootstrap-nested-cost-brief.md`, against the supplied semantic base
`46239ec` (later Root docs-only checkpoints did not change that source).
Source and this report are frozen for independent spec and quality review.
Run403 remains FAIL. The next native cost witness is **NOT_RUN**. No cache,
performance correction, clock change or acceptance claim was implemented.

## Exact owned source

Exactly the five existing authorized Rust files changed, and the one authorized
test-only support file was added:

| Path under crates/vprouter-launch/src | Final SHA256 |
| --- | --- |
| attachment/operational/bootstrap.rs |`da65fe12514a8f668f10d83cb4a668d9d59f0dd6faa26edf6487d9edab6f9d22`|
| owned.rs |`1e2b547bc2df30a6a128184eae9b6569452d12ec80bc59f9ff71e90a18f0636e`|
| owned/preparation.rs |`5379370d500f09a826fb3717b0949a355801823bbf40f63d1d8b3e6664c1b97a`|
| owned/preparation/bootstrap.rs |`0602f7630e895bee5f6834371ee4323025837363e439a4d7e97979918eaa0a53`|
| owned/preparation/quarantine.rs |`965e04b90a4048418a27a24439b5d4b754121acb17219e4c00644d8d9142a52f`|
| owned/preparation/lab_cost.rs (new) |`b1c0860166ed46d127d16095e788593558fb8928dc0264a435737f96a8fb2796`|

The complete pre-edit178-file Rust hash snapshot and copies of all five existing
owned files are retained under `target/task8c-nested-cost-local`. The final
179-file comparison proves exactly those six paths differ; the other173
existing Rust files, including unowned receipts/ancestry/protected paths, are
unchanged. No other source, dependency, manifest, controller or acceptance
result changed.

Exact unified diff artifact:
`target/task8c-nested-cost-local/source.diff`, SHA256
`84efdde3f26dd1c184d961dce9afd793fa8d2f4e292be6aa02018a2d5c17c34f`.
This was generated from saved pre-edit bytes with Python difflib, without Git.

## Production exclusion and original semantics

Every added statement in a production function has an explicit `#[cfg(test)]`.
The new module declaration is also `#[cfg(test)]`; the complete new support file
is absent from normal builds. No new production import, field, type, signature,
authority constructor or live operation was added.

`target/task8c-nested-cost-local/verify-source.py` verifies exact owned scope,
trailing whitespace, hashes and exclusion. Removing only the11 newly added
cfg(test) timer/drop statements and the new cfg(test) module declaration makes
owned.rs, preparation.rs, preparation/bootstrap.rs and preparation/quarantine.rs
**byte-identical** to their saved pre-edit source. The operational/bootstrap.rs
production prefix before the existing test-only LAB_LABELS is byte-identical;
its only edits are in the existing test-only lab_run and diagnostic module.
This demonstrates normal-build source identity without relying solely on a
passing compilation.

The expected-record encoding keeps its exact original statement at its exact
position. A cfg(test) guard starts immediately before it and is dropped
immediately after success; an early encoding Error drops the guard while
returning the same original Error. All other additions are entry/Drop timers.
No original expression, short-circuit operand, Result, error mapping, clock
sample, writer/child operation, release point, failure latch/collection or lab
tail was changed. The original2s windows and every custody, Source, Pins, slot,
ancestry, canonical/proposed/pending, phase/start/member, registry/IO/frame/
deadline/fence check remain. Held-query/policy counts and all negatives remain.

Exclusion artifact `cfg-exclusion.json`, SHA256
`889bcaa92d41f51d4359996b8aaf0b9db3c14c6d723dc1ebac72b205c630a10c`.
Pre-edit hash snapshot SHA256
`b06937ca3c86cc6941e0459a3bbace2096d44941306018ede13408dc68f5d657`;
final snapshot SHA256
`760de42c6cdff8128c2023a7b48d4d82bc3084e9baaf1602096ecf19e41bb462`.

## Fixed categories, family interpretation and lifetime

The module has one closed10-key enum and three closed families. Thirty fixed
rows contain saturating u64 completed-call counts and saturating u128 elapsed
nanoseconds. No dynamic/unbounded diagnostic storage, descriptor, lock or borrow
is retained across any original call. Cell state is copied only within short
diagnostic entry/drop operations; no mutable borrow survives into original work.
Timers and session guards are thread-affine through allocation-free
PhantomData<Rc<()>> markers.

The10 fixed categories are:

- `allocation_anchor_memory`: Transaction::require_allocation_memory, including
  its original Record::bind_anchor and complete retained-history validation.
  This captures the expensive delegation from Native::require_creator without
  adding a separate timer outside the brief's allowed entry boundaries.
- `binding_service_custody`: Binding::verify_service_custody.
- `binding_retained`: Binding::verify_retained.
- `owned_progress`: Native::verify_owned_progress, shared by query and policy.
- `typed_bootstrap_progress`: Binding::verify_bootstrap_progress.
- `original_proof`: OriginalWrite::verify_origin, including repeated proof uses.
- `record_json_encode`: global bounded encode_record calls.
- `expected_record_json_encode`: the original expected encoding inside owned
  progress; this is a subset of the global encoding category.
- `record_sha256`: global record_digest calls.
- `journal_advance`: the original preparation Native::advance.

Shared categories execute on both query and policy paths. Root additionally
authorized an infallible family hook at the existing lab-loop entry, using only
the already retained n.step. QueryIntent/Birth/Reading/Result select `query`;
Intent/Birth/Reading/Result select `policy`; Next/Complete select `other`.
Initial collection is explicitly armed as `other` immediately before the
PendingBootstrap constructor. Every timer captures its entry family.

This grouping is labelled `lab_loop_entry_step_family`. A native poll may
transition or perform setup for the next stage, so the family is not the exact
inner-operation phase. No fallible getter or extra verification establishes it.
The new fixed label is `LAB_SECRET_BOOTSTRAP_NESTED_TOTAL`, with
`measurement=inclusive_nested_elapsed`. Categories overlap and **must not be
summed** as disjoint elapsed time or CPU cost. Expected encoding also includes
the nested global timer/accounting overhead; subtracting rows does not produce
an exact exclusive cost.

Collection is inactive before arm and outside this lab invocation. Session Drop
disables collection on every ordinary Result exit, including errors outside the
instrumented helper boundary. The existing first-error handler stops collection
and copies its fixed snapshot **before** constructing/emitting diagnostics. The
existing13 wrapper rows remain unchanged; the stopped nested snapshot emits
exactly30 rows once afterward, including zero rows. There is no per-poll or
success-path output. Subsequent collection/refusal work cannot update the stopped
snapshot. New output is best effort, ignoring IO failure and never replacing
the original Error. Epoch tokens prevent an old timer/session from contaminating
a later session; epoch exhaustion disables diagnostics rather than reusing a
token. Counts and duration totals saturate without altering original control.

## Fork copy and role syscall boundary

Root approved COW-private child accumulation with creator-checked export, rather
than a new fork hook or filter permission. Source inspection found that
JournalIo::run calls global record_digest after the journal child installs
publisher_filter. That filter permits clock_gettime but does not permit getpid
(`kernel.rs` publisher_filter). Therefore timer entry/drop deliberately performs
**no process-ID syscall**. It uses only existing TLS state and Instant timing;
clock_gettime is already permitted for the journal role. No role/filter source
was changed and no new role syscall permission is needed.

Creator is observed only at arm/stop/snapshot/session cleanup in the unrestricted
lab boundary. A copied child may update only its COW-private diagnostic state;
there is no merge, IPC export or write into parent state. A foreign creator
cannot obtain a snapshot. The actual journal child branch ends in kernel::die
after its original fixed result handling (`kernel.rs:1757-1915` in the403 base),
so it does not unwind the parent lab/session stack or invoke the parent failure
handler. No actual fork or privileged filter experiment was run here; this is
source proof plus the meaningful copied-state/foreign-export test below.

Child-private timer work can still add scheduling/CPU overhead and therefore
affect parent elapsed observations. Parent timers and fixed-state copies also
add observer overhead. These are inclusive elapsed diagnostics, not precise
predicate CPU attribution or proof that any proposed cache would be fast enough.
No cache, moved/removed check or deadline relaxation has been authorized here.

## Local checks and retained logs

All commands ran in `/DATA/AppData/vprouter-rust-v2`. Final source:

```text
cargo test -p vprouter-launch --lib
cargo clippy -p vprouter-launch --lib --tests -- -D warnings
rustfmt --edition 2024 --config skip_children=true --check crates/vprouter-launch/src/owned.rs crates/vprouter-launch/src/owned/preparation.rs crates/vprouter-launch/src/owned/preparation/quarantine.rs crates/vprouter-launch/src/owned/preparation/bootstrap.rs crates/vprouter-launch/src/owned/preparation/lab_cost.rs crates/vprouter-launch/src/attachment/operational/bootstrap.rs
python3 target/task8c-nested-cost-local/verify-source.py
```

- Final library suite: PASS,152 passed,0 failed,0 ignored;148 existing tests and
  four new timer-helper tests.
- Strict launch library/tests Clippy: PASS. This also compiles the non-test
  library with instrumentation excluded.
- Focused six-file formatting: PASS; skip_children prevented formatting unowned
  module descendants.
- Exact source scope, cfg exclusion and whitespace checks: PASS.

The four new tests exercise inactive timers; nested timers dropped through an
early Result error; stopping before a live timer drops; foreign copied-state
snapshot refusal and parent-state isolation; captured entry family; saturated
counts/durations; epoch exhaustion; old timer/session isolation from a later
session; and inactive state after Session Drop. They do not assert copied log
text or manufacture ownership authority. Foreign creator/copy behavior is tested
without a real privileged fork. Normal-build, native/runtime filter and complete
Bootstrap behavior remain independently gated.

An initial151-test run passed before the fourth helper test was added. Initial
strict Clippy failed solely on an immediately invoked closure inside the test.
That was replaced by a real nested Result helper exercising `?` and Drop; no
lint suppression or production behavior change was used. The original failure
log is retained.

Logs under `target/task8c-nested-cost-local`:

| File | SHA256 |
| --- | --- |
| lib-final.log |`4dce1c3963154b0a7b893501b59aee131afd7f27d8253ef2d6df4098ec63bd41`|
| clippy-final.log |`b5d9950c1eba6f7b08b960053f5601ed94d096bff7c1b368e50bf2fa43d4c95a`|
| clippy-initial.log (retained failure) |`8ff4ced0b91a9e2fbae39410983961d15778b39b2b0291f9bdddcf5cd0beb834`|
| fmt-final.log |`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`|
| source-verification-final.log |`8edc23693f1c5112dd7083cecdcdd637f2229c2f60dbcea6cc76ba9c84fa153a`|
| verify-source.py |`17c62d17f35cf31ed7c956efa3dfb27cd8e1c95e97d4e1fc514de7da56371257`|

## Self-review and limits

The exact diff contains only cfg(test) diagnostic statements, hooks and support.
All original production bytes reconstruct as described; all unowned Rust bytes
are unchanged. No timer holds verification authority or changes an original
Result. Fixed output contains no caller strings, paths, identities, descriptors,
raw requests, profiles or credentials. The existing helper/error/Step/original
clock/counter snapshot and13 wrapper rows are preserved.

Only local focused cargo compilation/tests/Clippy and source checks were run.
No Git, VM/SSH/Docker, privileged/profile/identity action, standalone/static/
cross-architecture build, native retry, controller/manifests or subagent work was
performed. Offline microbenchmark remains NOT_RUN. No prior failure was erased
or promoted to success. Root owns403 resource preservation, its expected next
baseline, independent review, coherent builds/artifact binding, checkpoints and
the next native cost witness. Full Bootstrap/task8c, real-client, runtime,
migration and release gates remain open.
