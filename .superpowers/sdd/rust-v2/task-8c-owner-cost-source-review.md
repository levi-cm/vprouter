# Owner-cost source specification and quality review

2026-10-29. Independent review of the frozen two-file owner-inner diagnostic.
**Specification: PASS. Source quality: PASS. Sensitivity: PASS for the closed
schema. No blocking finding.** These verdicts cover this diagnostic source slice
and retained local checks, not native behavior, performance or release acceptance.

Only this report was written. The reviewer did not edit source, run tests or
builds, invoke the retained scope checker, query/mutate Git, run helper-main,
use VM/SSH/Docker/privilege, alter resources/profiles, run native experiments or
spawn subagents. Verification used source reads and independent, read-only
in-memory hashing/comparison. Root owns fresh workspace/coherent-artifact checks
and any subsequent authorized local experiment.

## Exact review binding

Worktree `/DATA/AppData/vprouter-rust-v2`; supplied branch `rust/v2` and HEAD
`ca07c27dde254ac1eb0d3977aec0fd58cf0438a5` identify the documentation/parser
checkpoint. Git was not queried. The prior actual-program source remains
`51c15016353936288067f5cd3e4c2a6715be1061`; this review does not treat the
checkpoint, changed source, or saved library checks as a newly tested native
artifact.

All following SHA256 values were independently calculated in this review:

| Input | SHA256 |
| --- | --- |
| `.superpowers/sdd/rust-v2/task-8c-owner-cost-brief.md` | `6ef36bc5defba7c337f1dca92f45aceee5ce57a2037b3cb8e20c9518e59f2aed` |
| `.superpowers/sdd/rust-v2/task-8c-owner-cost-report.md` | `336af09e1e8d3b04f4f493a00528a927d5dcddfe70cb91e5e42b59db8172fa00` |
| `.superpowers/sdd/rust-v2/task-8c-owner-cost-plan-review.md` | `e6e342b0c5a13dd84113f099fc324aab8ae68631cb24a3631dc0cd7a909c381a` |
| `.superpowers/sdd/rust-v2/task-8c-bootstrap407-diagnosis.md` | `c1151644386a6a6cb142dcfc51de7f2269ffe7fb91a746800c5143f6d7330b87` |
| `docs/rust-v2/IMPLEMENTATION.md` | `353f0e82d9dcf7b3e1216c27ac4c505bdc8fa6ee06ee3e6b833f1d3e11594125` |
| `target/task8c-owner-cost-local/source.diff` | `01096cb590694a0ae53d2755fe1cda38b4e14645a4850afdd415dd9e3780cf7b` |
| `crates/vprouter-launch/src/supervision.rs` | `12e52aa5088da60bbf651cfb7953f418cf9ff95df5aeadf6758cde4afaca3fa3` |
| `crates/vprouter-launch/src/owned/preparation/lab_cost.rs` | `c6dda51f852a9593d7e0a7fb8ccf708d28359d6f7ca781cd905c4156b6773470` |

The brief was read first, followed by the diagnosis and binding implementation
contract. Readiness review context was read, but the source was assessed directly
against the original copies, exact diff and brief rather than adopting its
prospective verdict as implementation evidence.

## Scope and normal-source preservation: PASS

Independently enumerated and hashed all current `crates/**/*.rs` files. The
before/after/live path sets each contain exactly 179 paths, with no missing or
added path. The current files exactly match `rust-after.json`; precisely the two
owned paths differ from `rust-before.json`, and all 177 unowned paths remain
byte-identical. The before manifest itself is byte-identical to the prior
`target/task8c-digest-hex-implementation/rust-after.json`. An independently
regenerated in-memory unified diff exactly equals the frozen `source.diff`.

For supervision, independently removed only the added test import, five test
timer declarations, narrow test-only lint attribute and minimal expression/call
braces, undoing their indentation and one rustfmt line wrap. The result is
byte-identical to the entire original `supervision.rs.before`, SHA256
`4f864fa5bce9140dd426fc584303f5ce4ee4c03ec08338009e00ff24bf619ef0`.
It also matches the retained reconstruction. This establishes source inversion;
it is not a normal/native binary equivalence claim.

The helper remains excluded from normal builds by the unchanged parent
`#[cfg(test)] pub(crate) mod lab_cost` at preparation.rs:1889. Supervision's
import, five timer declarations and lint allowance are explicitly test-only.
The remaining braces house original expressions, as the brief permits.
No other Rust path, parser, manifest, controller, dependency, golden or acceptance
source is part of this diff. This is not a fresh non-Rust workspace audit.

## Measured boundaries and original behavior: PASS

Inspection of supervision.rs:128-179 confirms the exact five requested scopes:

1. `owner_host_preflight` contains only the original host-preflight call with its
   original `?`. The timer drops on success or early error before any later
   verification boundary can begin.
2. `owner_record_validate` contains only the original validation call and `?`,
   after preflight. It neither stores nor reuses a verdict.
3. `owner_namespace_identities` surrounds only the original function expression.
   Its block ends before comparison with `self.namespaces`; the existing
   NamespaceMismatch return remains outside the timed scope. Function errors
   still propagate at the original `?`.
4. `owner_current_identity_chain` surrounds the original complete `||` expression.
   Current process identity, boot ID, pinned group identity, freshly opened named
   group identity, and self-cgroup read/comparison retain their left-to-right
   short circuit and original error mappings. No later operand is evaluated
   eagerly; no native observation is pooled, cached, hoisted or removed. The
   timer ends before the existing OwnershipMismatch return. Original expression
   temporaries remain within this condition; no named binding extends their
   lifetime into the mismatch body or later verification work.
5. `owner_record_clone` starts only after `self.verify(domains)?` succeeds and
   contains only the original clone expression. Its block ends before the clone
   result is wrapped in `Ok`; no clone is introduced, skipped or cached.

The original bodies outside these minimal scopes are reconstructed exactly.
The host-namespace loop, all original live calls, comparisons, ordering, errors,
clock/deadline sources and successful return values remain intact. New
`Instant` readings provide diagnostic elapsed time only and grant no validation
or deadline authority. RAII records reached error/unwind entries without moving
the original fallible operations or changing their error values.

The sole `#[cfg_attr(test, allow(clippy::blocks_in_conditions))]` is attached
directly to the final `if`, covering the deliberate timed predicate block. It
is not a method/module-wide allowance or native permission change. The relative
`super::owned::preparation::lab_cost` import is consistent with nested launch
module fixtures; retained strict lib/tests Clippy compiled those targets.

## Collector, session and child accounting: PASS

The new `OwnerKey` list is closed and has the required five labels in order.
`OwnerTotals` has exactly 3 families times 5 keys, represented by 15 independent
`Cell<Total>` rows. A record operation selects only the entry token's family/key
row and saturates u64 calls and u128 nanoseconds. No new table is embedded in
the old 30-row `State` copied by old or new timer operations.

Independent byte comparisons confirm the old State definition/behavior is
unchanged apart from additive zero initialization of the new Snapshot field;
old `Timer` and `RetainedTimer` implementations are byte-identical. OwnerTimer
copies the existing active/creator/epoch/family token at entry, retains only
that token, key and Instant plus the thread-affinity marker, and takes no live
borrow across measured work. Drop checks the existing active/creator/epoch
contract before recording; family is captured at entry rather than reread at
drop. No owner timer/counter getpid, lock, heap allocation, formatting or output
is added. Owner recording copies the original State, whose size is unchanged.

Arm resets every owner row, including when epoch exhaustion disables the new
session. Inactive/stopped tokens cannot enter or record; stale epochs and stale
Session drops cannot affect the next session. The existing stop boundary first
disables collection and checks the actual creator PID, then copies owner rows
only for a permitted snapshot. A foreign stop disables collection without
exporting a snapshot. Fork-inherited metadata/rows can receive only COW-private
updates: there is no child merge, IPC or alternate export path. Existing filter,
unrestricted process-ID boundaries and error/unwind machinery are unchanged.

The new copied-child check is a model of separate State/Cell copies, explicitly
not proof of an actual fork, filter or native execution. The implementation's
source follows the existing collector contract; native behavior remains unrun.

## Old rows, new output and sensitivity: PASS

Independent comparison verifies the original Snapshot emitter loops and all
pre-existing helper tests remain byte-identical. The 177 unchanged paths include
the wrapper measurement/failure implementation. Its original failure path
stops collection before acquiring stderr, emitting the boundary and 13 wrapper
rows, then emitting the snapshot. Thus the old 13 wrapper, 30 nested and 24
retained row order/labels/meaning are preserved at the existing boundary.

Exactly 15 appended `LAB_SECRET_BOOTSTRAP_OWNER_TOTAL` rows follow the old tables,
ordered query/policy/other then the brief's five keys. Each has exactly
family/category/calls/elapsed_ns/measurement/grouping, with
`measurement=inclusive_owner_elapsed` and
`grouping=lab_loop_entry_step_family`. All labels are fixed ASCII literals;
only bounded unsigned counts/durations vary. No identifiers, paths, record
contents, credentials, dynamic text or per-call/poll output enters these rows.

Independently calculated maximum added output is 3434 bytes including newlines;
the longest line is 235 bytes. This bounds bytes, not stderr blocking time.
Every new write result is discarded like the old writes, so ordinary writer
errors do not replace the original application error. No new collection-time
output or additional emission site was introduced.

## Retained checks and evidence quality: PASS with stated limits

No test/build was rerun in this review. All 26 artifacts named by the frozen
artifact manifest were rehashed and match; the manifest SHA256 is
`191a24f290ae72e591f0e5f3ee65bfd5ec4232fb2e995d6017444aa6df6a229e`.
The retained command/result records and log contents show:

- Final `cargo test -p vprouter-launch --lib`: exit 0, 164 passed,
  zero failed/ignored. Full log SHA256
  `6d407d102f373af767a6b29f40722115f8d529a322f7820d3ec335551a552bfc`.
- Final `cargo fmt -p vprouter-launch -- --check`: exit 0; empty log SHA256
  `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
- Final `cargo clippy -p vprouter-launch --lib --tests -- -D warnings`: exit 0.
  Full log SHA256
  `7b6549508cf060d8fa40c40dc34a56de66d9aa12bb3dbcb7cd61b3448270041a`.
- Focused owner selection: 12 passed, including five new collector tests and
  seven pre-existing matching tests. The five new tests cover fixed row schema
  and order; nested/error/family behavior; inactive, stopped and stale tokens;
  session resets and stale Session drop; foreign stop and exhausted epoch;
  saturating selected-row accounting and independent copied-child state;
  maximum output and ignored writer failure. They impose no timing threshold.
- The initial output behavior test failed with 54 versus required 69 rows;
  `red-output.log` SHA256
  `74ad967b8fc653b95d2bfb8de8f537d61527e704d52b5fdae952ab4a02703968`.
  Disabling OwnerTimer drop recording produced two failing new behavior tests
  and three passing tests, rather than an artificial compilation failure;
  `mutation-no-owner-record.log` SHA256
  `b58315a36fbf207c4959831c96ab6b5f42ce27ec2b69b44f45623614d78d528f`.
  The retained pre-mutation helper and current helper are identical, with the
  reviewed final hash. No disabled recorder remains in the frozen diff.

The initial strict Clippy block-condition rejection is retained, including
nested integration fixtures, and resolved only by the narrow test-only
attribute. The scope-checker's initial missed inverse line wrap is documented;
this reviewer independently reconstructed the original rather than relying on
the checker's PASS. Frozen scope-proof SHA256 is
`6989dbca922a34f6ae4511e0eb694e99c3110197654ce44fe5123e764642a0f1`;
before/after manifest SHA256 values are respectively
`f31ce696bd7f647a841da2904f8a383d4ab8fee37662d3678539e86a6ac03b3b`
and `a2470282e09505560cb37a0568fcccb58b6b7b318ff82873e0ec35fbeaf8fc7e`.

## Findings and remaining limits

No blocking specification, correctness, maintainability or sensitivity finding
was identified in this exact source slice. The additive table and narrow scopes
meet the requested diagnostic purpose without a semantic optimizer.

These are global OwnerDomain-method measurements: capture/verify and callers
outside the measured Binding expression can contribute, including early errors.
Boundary counts can differ. These rows overlap existing inclusive measurements;
they cannot be added/subtracted into exclusive wall time, CPU shares or parser
shares, nor used to identify the exact inner Deadline predicate. Instant/TLS/
token/Cell work, unchanged old-State copies, extra cache footprint, COW and
scheduling perturb both inner and outer measurements. Observer effects can
dominate small validation/clone costs. No saved-budget or causal speedup claim
is supported.

Run407 remains the recorded FAIL with zero cases at HOST/native_poll/reading/
Deadline and the original two-second window. This review does not repeat the
native failure/preservation/resource audit, adopt live fields, or claim new
archival/coherent-artifact evidence. Original398-407 failures remain failures.
Native execution of this changed candidate, full Bootstrap/task8c, ARM, real
clients, migration, performance comparisons, soak and release acceptance remain
open/NOT_RUN. No native CPU share, optimizer justification, two-second fit,
absence of contention or acceptance is established.

Local-only testing, Root-only VM authority, production, existing identities and
credentials, and bounded retry repair remain binding. Root separately owns
reader review, fresh workspace checks, coherent artifacts, the independently
authored 60-link preservation baseline, checkpoint/push/tag and any subsequent
authorized local VM experiment. This PASS does not dispatch those actions.
