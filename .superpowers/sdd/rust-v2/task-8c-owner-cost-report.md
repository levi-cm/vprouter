# Owner-inner diagnostic implementation

2026-10-29. Implemented only the reviewed two-file cfg(test) owner diagnostic
slice under Root's explicit authorization. Source is now frozen for independent
specification/quality review. All approved local checks pass. No optimizer,
parser/call/cache/FD/resource/native/deadline/profile change or acceptance claim.

## Binding and owned scope

- Requirements `.superpowers/sdd/rust-v2/task-8c-owner-cost-brief.md`, SHA256
  `6ef36bc5defba7c337f1dca92f45aceee5ce57a2037b3cb8e20c9518e59f2aed`.
- Readiness `.superpowers/sdd/rust-v2/task-8c-owner-cost-plan-review.md`, SHA256
  `e6e342b0c5a13dd84113f099fc324aab8ae68631cb24a3631dc0cd7a909c381a`.
- Fresh pre-edit179-file snapshot exactly matched the frozen source51c15016
  digest-implementation manifest. No Git was queried or modified here.
- Owned `crates/vprouter-launch/src/supervision.rs`:
  before `4f864fa5bce9140dd426fc584303f5ce4ee4c03ec08338009e00ff24bf619ef0`;
  after `12e52aa5088da60bbf651cfb7953f418cf9ff95df5aeadf6758cde4afaca3fa3`.
- Owned `crates/vprouter-launch/src/owned/preparation/lab_cost.rs`:
  before `a7e5d4f832559d66d7cc6fa4193b2c82d051b4629850c0021ef47e5999601f68`;
  after `c6dda51f852a9593d7e0a7fb8ccf708d28359d6f7ca781cd905c4156b6773470`.

No other Rust file changed; all177 unowned files are byte-identical, and all179
paths still match (zero added/missing). The helper remains excluded by its
existing parent cfg(test). The supervision import/timer statements and narrowly
scoped Clippy allowance are test-only; minimal expression blocks remain in normal
source with the original calls and predicates. The inverse proof removes those
additions/braces, undoes indentation and its one rustfmt line wrap, and reconstructs
the entire original supervision.rs byte-for-byte. This is source proof, not a
normal/native artifact equivalence or acceptance claim.

## Exact measured boundaries

Five RAII scopes retain original expressions and evaluation order:

1. owner_host_preflight: only the existing host_preflight call, including its
   original `?`; errors drop the timer without reaching later boundaries.
2. owner_record_validate: only the existing record.validate call after preflight.
3. owner_namespace_identities: only host_namespace_identities, ending before
   comparison with self.namespaces and the existing mismatch return.
4. owner_current_identity_chain: the complete original left-to-right `||` chain
   with current process, boot, pinned/named cgroup and self-cgroup read/comparison.
   No operand is eager; all original `?` errors and short circuits remain. The
   timer ends before the existing OwnershipMismatch return.
5. owner_record_clone: only record.clone after verify succeeds, ending before Ok.

Relative `super::owned::preparation::lab_cost` import supports nested admission
fixtures; strict Clippy compiled those lib/test targets. The final condition
has only a scoped `cfg_attr(test, allow(clippy::blocks_in_conditions))`: the first
strict run rejected this intentionally scoped expression block. A binding or
predicate refactor was avoided; this test-only lint allowance changes no runtime
permission, call, error or normal-build expression.

## Collection and output

OwnerKey/OwnerTotals/OwnerTimer add a separate15-row selected-Cell table. Original
State layout, Timer/RetainedTimer implementations, old output loops and all old
tests are byte-preserved; only additive snapshot initialization/plumbing appears
in State.stop_snapshot. No larger old-State copy, lock, heap allocation, live
borrow across measured work, timer/counter getpid, child merge/export or per-call
output was added. Arm resets owner rows even when epoch exhaustion disables the
session. Entry captures the existing creator/epoch/family token; drop checks the
existing active contract, updates only its row and saturates u64/u128 totals.
Foreign stop still disables collection and refuses export at the existing actual
creator boundary; inherited bookkeeping remains COW-private.

Original13 wrapper rows are in unmodified source. Original30 nested and24 retained
rows and their order/meaning are preserved. At the existing stopped Snapshot.emit,
exactly15 LAB_SECRET_BOOTSTRAP_OWNER_TOTAL rows follow: query/policy/other, each
with the five keys above in order. Exactly family/category/calls/elapsed_ns/
measurement/grouping; measurement=inclusive_owner_elapsed and
grouping=lab_loop_entry_step_family. Fixed labels and bounded numbers only.
Writer errors are ignored as before. Maximum added output is3434 bytes including
newlines; longest line235 bytes including newline. This byte bound does not bound
stderr blocking time. There is no new active-collection output.

## Validation and retained failures

Full logs and command/result records: `target/task8c-owner-cost-local/`.

- Initial new output behavior test: expected FAIL,54 rows versus69; retained
  `red-output.log`. It passed after implementation.
- Focused owner selection:12 tests PASS (five new collector tests plus seven
  existing matching tests), `owner-focused.log`.
- Meaningful no-record mutation: OwnerTimer drop recording temporarily disabled;
  two new collector tests FAIL and three PASS, `mutation-no-owner-record.log`.
  Exact restoration verified before final checks; no mutant remains.
- Final `cargo test -p vprouter-launch --lib`:164 PASS, zero failed/ignored;
  `launch-lib-test.log` and command/result JSON.
- Final `cargo fmt -p vprouter-launch -- --check`:PASS; `launch-fmt.log` and JSON.
- Final `cargo clippy -p vprouter-launch --lib --tests -- -D warnings`:PASS;
  `launch-clippy.log` and JSON. Initial Clippy failure and earlier passing logs
  remain in the corresponding `*-initial` files.
- Final `check_scope.py`:PASS, `source-scope-check.log`/`source-preserved.json`.
  Its first inverse-check attempt missed rustfmt's indentation-only wrap; the
  checker was corrected without changing source. History is recorded in
  `verification-history.json`.

Five new tests exercise real collector behavior: closed output/order, nested
error entries and entry-family capture, inactive/stopped/stale/session reset,
foreign stop and epoch exhaustion, selected-row saturation, independent copied
child accounting with unchanged parent totals, reset, maximum output and writer
failure. They use no timing threshold or unsafe fork/native experiment. The
copied-child check is an in-memory contract test, not a native fork/filter proof.

## Frozen evidence

All paths below are under `target/task8c-owner-cost-local/`:

| Artifact | SHA256 |
| --- | --- |
| rust-before.json | f31ce696bd7f647a841da2904f8a383d4ab8fee37662d3678539e86a6ac03b3b |
| rust-after.json | a2470282e09505560cb37a0568fcccb58b6b7b318ff82873e0ec35fbeaf8fc7e |
| source.diff | 01096cb590694a0ae53d2755fe1cda38b4e14645a4850afdd415dd9e3780cf7b |
| source-preserved.json | 6989dbca922a34f6ae4511e0eb694e99c3110197654ce44fe5123e764642a0f1 |
| artifact-hashes.json | 191a24f290ae72e591f0e5f3ee65bfd5ec4232fb2e995d6017444aa6df6a229e |

Artifact manifest binds every retained evidence file (including exact original
source copies, restored helper copy, reconstruction, scope script and full logs).

## Interpretation and remaining gates

Rows measure global OwnerDomain methods: capture and non-Binding callers, early
errors and different boundary counts can contribute. They overlap existing
measurements and cannot be summed/subtracted into exclusive wall/CPU or an exact
Deadline predicate. Instant/TLS/token/cell work, existing old-State copies, cache
footprint, COW and scheduling perturb measurements; pure validation/clone cost
may be small relative to that observer. No parser share, saved budget, native
speedup, absence of contention or two-second fit is established.

No Git, coherent build, manifest/controller/parser/golden/dependency/acceptance
edit, VM/SSH/Docker/privileged/profile/resource operation or subagent was used.
Root owns separate reader/source reviews, fresh workspace/coherent checks,
artifacts, authored60-link baseline, push/tag and any next VM experiment. Native
execution of this changed candidate is NOT_RUN. Original398-407 failures remain
FAIL; full8c/ARM/real-client/migration/performance/soak/release gates remain open.
