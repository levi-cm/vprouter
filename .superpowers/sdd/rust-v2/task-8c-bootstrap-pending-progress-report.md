# Original-owner pending Bootstrap progress candidate

2026-10-29. Implemented the bounded pending-progress brief in
`/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`. Semantic source base is
`ae8450cfbdb44e16c481e51c3bd419563a308f99`; Root advanced documentation/tooling
only during implementation, with HEAD `880776cb0ff59879322ea2b28f90bfbe3c987962`
at final verification. The thirteen Rust paths below are unstaged and frozen
for fresh independent spec/quality review. This report is the only repository
non-source file written by this implementer for this increment.

Local component checks pass. Coherent static builds, connected native Bootstrap
execution, real clients, full8c and release acceptance remain **NOT_RUN/open**.
Runs398/399/400 and their resources remain retained failures. Run398's original
pre-constructor failure remains unexplained. Run400's source-established pending
conflict remains a strongly matching runtime explanation, not a captured
process-local stack/predicate witness. Durable Intent on disk is not parent ACK.

## Final behavior and authority boundary

The completed HOST owner now exposes a private, retained custody view containing
only the original Binding and Server. Its original completed HOST chain,
generation, creator and producer-binding custody are still checked. Ordinary
Context construction additionally obtains the original Source and verifies its
strict acknowledged history, as before.

OperationalOwner's six closed query/policy Intent/Birth/Result polling operations
require its completed original handoff and exact20 reservation/resources. They
obtain that original custody, validate the exact typed Binding progress, and
poll only the retained Server. No arbitrary mutable Source/service getter is
exposed through OperationalOwner. Bootstrap uses these operations in its six
writer phases; idle/new-operation and post-ACK boundaries retain strict Context,
Source, Request and receipt verification. Its original failure latch, quarantine,
collection, retention and clocks are unchanged.

Policy progress needs Source/Pins/Request verification while its own writer is
pending. `OriginalWrite` is a borrowed, nonserializable object with private fields
holding the original Server, exact expected Record, phase and original start.
Only the closed Bootstrap policy progress verifier constructs it after proving
the exact typed proposal. Every use revalidates the same SharedJournal Rc/member
and original pending/queued progress. Bootstrap Request additionally requires
pointer identity with the original Rc<Request> retained in that continuation.
It cannot be constructed from wire data, scalar IDs or public histories.

The progress-specific producer Receipt verifier checks the original Source and
intent origin, creator, exact request/birth/group/verification, committed producer
history and fence after that proof. Its ordinary `verify_history` function is
unchanged, including unconditional refusal when shared pending is present.
Source's ordinary acknowledged-history method, ordinary Request verification
and ordinary Pins verification remain strict. Both Pins paths retain all eight
descriptor identity, inventory, ancestry, type, mode, cgroup and Source checks.

For policy Result, native Verified exposes only observational evidence from its
original completed native child to form the expected typed proposal. After exact
write proof, the progress path checks Request/Pins/Source and original completion
custody. Ordinary Verified verification still calls strict Request verification.
The evidence getter does not acknowledge a writer, issue a receipt, admit a child
or create policy/UP/placement/READY authority.

The existing `Native::verify_owned_progress` continues to enforce creator,
original two-second frame, issued original result, service membership, exact
continuation phase/start, no unrelated publication, exact proposed full Record,
canonical before digest, original queue state and exact shared pending Record.
Its pending branch now calls a shared borrowed `PendingWriter` core enforcing
actual mutation/nonfailed/unfenced state, phase/start/deadline and immutable child
IO binding. The child must own the actual counted/inventory-retained MutatorLease,
same native-job registry Rc/member and registered Born Journal ticket with the
original shared native state Rc. This is stronger than comparing IO scalars alone.
NativeJobs' type is now `pub(super)` for the module-family access needed by this
borrowed check; its fields remain private. No lease, clock or deadline is renewed.

## Regression evidence and its limits

The existing rootless gated Journal/OFD/lease/native-job regression now exercises
the same production pending-writer validation core using its actual original
child and native registry. The child remains behind its initial release gate;
it is never released into privileged isolation or the fixed writer role.

It accepts that original writer and refuses a foreign registry/member, wrong
phase/start, altered before/after digest, changed deadline, nonmutation, failed
and fenced observations. Rechecking the original still succeeds afterward.
The existing fixture then checks actual reap and original reservation/OFD/resource
retention after wrapper drop, including OFD busy after native death and release
only through its existing collection path. The same fixture also runs its HOST
and journal post-clone parent-failure branches.

This is a partial native ownership/core regression. It does **not** create an
OperationalOwner, Source or OriginalWrite from scalar identities, and it does
not prove complete typed Request/Rc matching, strict Source history refusal or
connected policy progress. Its phase/start/fence/flags are controlled borrowed
observations around the real gated child; canonical Record/proposal, original
Request and full owner-chain validation remain outside this rootless fixture.

Root also authorized connected native fixture extensions, compiled locally but
**NOT_RUN natively** by this implementer:

- First Bootstrap HOST query Intent, original writer index87, is held through the
  existing before-sync checkpoint with no additional native child or resource.
  Closed original typed query progress is checked at every checkpoint/poll.
  The same writer identity must persist. Strict ordinary Context and a Source Rc
  retained from that original owner before pending both refuse while held.
  Two held polls plus the release checkpoint yield six refusal checks. Existing
  successful completion validation then requires writer87 actual status0 and
  ACK verification. Added additive witness `own_query_intent_polling` has the
  same index/pid/start/queued_polls/held_pending_polls/negative_checks/released
  shape as the existing policy witness; expected negatives6, held polls2.
- First policy Intent writer90 retains its existing hold, two pending polls,
  release and ACK requirements. Its four queued and four held original
  stage/start/proposal/strict-Binding negatives remain. The held check additionally
  requires strict Context, Source acknowledged history, Request and Pins to
  refuse, while exact typed policy progress succeeds. Existing witness
  `own_intent_polling.negative_checks` therefore changes from8 to12. The source
  oracle explicitly requires12; the witness schema otherwise remains unchanged.
- The DATA Result held-failure fixture uses exact original typed progress to reach
  its existing checkpoint instead of eagerly re-entering strict Context. Its
  unacknowledged writer charge, original error and failed retention oracle remain.

Full native wrong-Rc Request testing remains **NOT_RUN**. These original native
request/custody types are not Clone, and no fixture authority constructor or new
descriptor duplication was added just to manufacture a second request. Original
Rc/pointer matching remains enforced in production. Root must run the connected
held/query/policy and fault family on reviewed coherent artifacts; compiled lab
assertions and rootless component success are not native Bootstrap acceptance.

## Red/green and final local checks

The implementation used the test-driven-development and
verification-before-completion skills. Earlier pre-compaction invocations are
retained in the session tool evidence; they were not recreated as fabricated
logs:

1. Added the actual gated-writer ownership regression with a safely refusing
   original-writer checker. `cargo test -p vprouter-launch --test actual_lab --
   --inspection-filter-selftest` exited1 at runtime with
   `LAB_PENDING_WRITE_REGRESSION exact_original_writer_refused=true`.
   Implementing the original lease/native-ticket/Rc/member/IO check made that
   same command pass, exit0, before the final shared-core extension.
2. Added the production-core regression with a test-only always-refuse stub.
   The same command compiled and exited1 at runtime with ownership_mismatch
   (session97461, build8.76s). That stub was replaced by the shared production
   PendingWriter validation and positive/negative gated-child checks.
3. Shared-core GREEN: same command exit0, build8.09s, log
   `/tmp/task8c-pending-core-green.log`, with
   `LAB_PENDING_WRITE_CORE original_writer=true foreign_owner_phase_start_io_deadline_fence_refused=true child_held=true`.

After the final authorized native-fixture assertion additions and formatting:

| Check | Result | Retained local log |
| --- | --- | --- |
| `cargo test -p vprouter-launch --lib` | exit0;147 passed,0 failed; runtime2.11s | `/tmp/task8c-pending-final2-lib.log` |
| `cargo test -p vprouter-launch --test actual_lab -- --inspection-filter-selftest` | exit0; build4.93s; shared-core marker and final exact-filter PASS | `/tmp/task8c-pending-final2-rootless.log` |
| `cargo clippy -p vprouter-launch --lib --tests -- -D warnings` | exit0;7.89s | `/tmp/task8c-pending-final2-clippy.log` |
| `rustfmt --check --edition 2024 --config skip_children=true` on exactly the thirteen owned paths | exit0; no output | tool result |
| `git diff --check` | exit0; no output | tool result |

The rootless exact-filter suite intentionally emits its existing negative
inventory/descriptor diagnostics. Its final PASS and exit0 were verified; those
expected negatives are not suppressed or represented as clean runtime output.
An earlier coherent147-test pass and strict Clippy pass before the last fixture
addition also remain in `/tmp/task8c-pending-final-lib.log` and
`/tmp/task8c-pending-final-clippy.log`. Final checks above supersede them.

Final local log SHA256 values:

```text
b7b26924ca1b7ed4a6133750bd69eda626315a08e220768623301ce1e741c162 /tmp/task8c-pending-final2-lib.log
89ad675e05a88cb8f837930b7a5c1fe033896293281f70e54eec8e66ee0e59e0 /tmp/task8c-pending-final2-rootless.log
d18b08c06d87d5fd519edf319aac4faf9bb09f6e7f3376010451d49f5bdece6f /tmp/task8c-pending-final2-clippy.log
```

No static/coherent build, manifest/context edit, VM/SSH/Docker/privileged action,
protected profile/credential/identity access, Git mutation or cleanup was performed.
Root's concurrent documentation/tooling/provenance changes were preserved. No
subagents were used. Live production and the six approved receipt source files
were untouched.

## Frozen source inventory

Final delta:13 Rust paths,738 insertions,79 deletions relative to current HEAD;
Root's intervening checkpoints contain no semantic source change to this base.
All paths below are relative to `crates/vprouter-launch/src/`.

| Owned path | SHA256 |
| --- | --- |
| `attachment/host_addition.rs` | `c60a040392e180d1c1a3f1dd17000fed008262f5f76ce8c262a21a720daf37f6` |
| `attachment/host_addition/operation.rs` | `16b4d60b0cc2019141d9cf60399652ad89946f340d91a2a682a6c976c978edf7` |
| `attachment/operational.rs` | `1dadf82010a122c8dac4a25dec1bec05f55bacc0f51ba7f0d66ed56204aabe65` |
| `attachment/operational/bootstrap.rs` | `a69afe95279995aff491c1e153473af9398cabbc8a6342407266a522dd836759` |
| `attachment/operational/producer.rs` | `345b9ebef44114bc6a6d5e4c1664136532839e07a8055eeda1f0ea367db699b2` |
| `kernel.rs` | `37916163a0180446c5adf607a0a08409639b3788e6003a19368c62233a5dc56c` |
| `kernel/bootstrap.rs` | `a35735c97bb6333d229dbefccc5eb7e0cb05781e019c68eaa0e01d1b3a18a945` |
| `kernel/producer_creation.rs` | `b920940062802760cffafd5720c687880211183be92dfe2e2be003cac55031ea` |
| `owned.rs` | `5da0e197f19ec6acc5bd30c562b3a76740f12b8e98c7de9206ff6ce49f562d79` |
| `owned/preparation.rs` | `3e0c97eb359e07e93553911a354ce9e6db2e162f2e2e9f9a2e41af7728c871f0` |
| `owned/preparation/bootstrap.rs` | `1c291ad751fa5d403fcd41134cd7d91113872b258f4b061c2f0639cce605ee69` |
| `owned/preparation/producer_creation.rs` | `05de7f090c82b99d9eab48080a6db96ae631249c67b51ebbea4fbf577a8a3544` |
| `owned/preparation/quarantine.rs` | `1131d929ff44b0359f7c97cfa8d994de6ce1c13a082f907bd3f188558da2c2ac` |

All six approved task8c.1 receipt files were rehashed and match their frozen
implementer/reviewer values exactly; their Git diff is empty:

```text
2ec561f7beac44fe84a542baff1c0d37152303f22dffa323b32d7422e85c1771 crates/vprouter-worker/src/operation.rs
5b7045736012a472573af427ad65b20f1e70fd8d5e63957607ffc2ea477b894a crates/vprouter-worker/src/engine.rs
dd3e39bfb7d3e6f1b26cff59656d8bfa46e25e1972c157c8dac38cb5b76196b9 crates/vprouter-worker/src/engine/tests.rs
da8e6c7b07bcbe3eca9bc44ed398e4eaaa33cd98a9b7162950671adf1a6585c7 crates/vprouter-launch/src/handoff.rs
ba7d139e1370205ec223a0c13236713b8fdadf28ccaaebd0d1419cac296b51ab crates/vprouter-launch/src/transport.rs
914033572568cfa628bda81a7f38b1611286a581df3493d90f1950a8f105ba21 crates/vprouter-launch/src/expiry.rs
```

Fresh independent review, Root's coherent source/artifact inventory, static
x86_64/ARM64 builds/checks, connected native held query/policy and failure-family
execution, clients, full lifecycle/recovery and release gates remain open.
