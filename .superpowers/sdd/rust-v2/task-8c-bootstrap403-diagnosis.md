# Run403: original HOST window expires through the native-poll boundary

2026-10-29. Read-only diagnosis requested by Root. Only this report was written.
No Rust edit, test, compilation, Git, VM/SSH/Docker/privileged action, retry or
subagent was performed. Source remains frozen. No semantic fix is selected.

Run403 proves a native-poll Deadline at the first HOST policy Intent after both
required held polls and all12 policy negative checks completed. Policy release
had not been called. The elapsed wrapper totals identify substantial work in
the original two-second window; they do not identify the failing inner predicate,
per-predicate CPU cost, or the cause of run402's different outer-helper failure.

## Exact evidence

- Raw `target/lab-state/actual-program-run-403.json`, SHA256
  `8e63c00123fca75a1fbf8347566fd226e794cfd214a87c0e1b7f085654901241`.
- Source `c6f3c5e8917f81ee7b4b9070388ee3c524531b8b`.
- Source archive SHA256
  `56c1c02b4806c4d490100b098b9e9c1ac7dca4d42bd4fec7b047a7fc6844d633`.
- 202 verified build inputs, source aggregate
  `f1a84685bb540b74b23f1a6393470b4a845b9ed11523a21f1f1ec8d65c54b57a`.
- Artifact SHA256
  `9486d7e15faeaa6c855ca72bd465d68f285a27e5e55e8bc8f0dcecc1314c5a86`.
- Directory
  `target/continuation-20261029T153856Z/bootstrap-helper-diagnostic-20261029`;
  its `directory-binding.json` SHA256
  `8ca913a787143e340c1578bc0e38f4487f6b830881584e5bb09e8b1e3d66d5d7`
  agrees with the raw source/archive/artifact binding.
- Summary `target/task8c-helper-diagnostic-20261029T153811Z/bootstrap-summary.json`,
  SHA256 `c8c3a32b08f3e07c30a474b8dca6a4ce1971fcce962d6c32e6890a0a6f97997d`.
- Root's read-only snapshot `target/lab-state/secret-bootstrap-failure-run-403.json`,
  SHA256 `80ad66bd3d10804cdde2b3adea39ba925332cf1ca6ea4832c73075f1fca05431`,
  binds the same raw record. Its canonical collection is allocations.json and
  namespaces.json. No pending journal content was read by this implementer.
- Current `operational/bootstrap.rs` SHA256 remains the reviewed diagnostic
  candidate `88320812125ab5f735a70ee6e1d0a935699dcc27f7ea4d9d7f3bca72f539e142`.

Result is FAIL, exit1, zero case witnesses, `secret_bootstrap_success` component
mode, outer wall13.92s, real-client acceptance NOT_RUN. The full stderr has320
lines and91 inventory/verified pairs. These counts use the exact existing
`LAB_JOURNAL_STAGE stage=io_inventory` and `io_inventory_verified` records.

## Captured boundary and completed lab operations

The new first-error record says:

```text
helper=native_poll step=intent reason=Deadline
query_present=true query_child_present=true query_accepted_present=true
policy_present=true
query_queued=true query_held=2 query_negatives=6 query_released=true
own_queued=true own_held=2 own_negatives=12 own_released=false
original_requested_at=Some(197538.988574814)
original_deadline=Some(197540.988574814)
observed_boot_now=197540.99594918
```

It is followed by the13 fixed metric rows and the original diagnostics:

```text
LAB_SECRET_BOOTSTRAP_POLL_FAILURE step=intent reason=Deadline request_present=true query_child_present=true
LAB_SECRET_BOOTSTRAP_FAILURE scope=Host reason=Deadline requested_at=197538.988574814 deadline=197540.988574814 now=197540.99599542
secret_bootstrap_lab: deadline
```

This proves that the measured main `PendingBootstrap::poll` returned the
original Deadline. The existing poll error handler is reached and its Request
is present. It is not an outer helper error in403. By source control flow,
`PendingBootstrap::poll` latches/collects an advance failure before returning it;
there is no missing helper diagnostic in this record.

The cached counters prove that the query hold reached its required two pending
polls, six negative checks and release. The policy hold completed queued and
held negative checks (total12) and two held pending polls. Policy identity was
queried twice and release zero times. The second held-poll increment precedes
the next measured native poll; that poll fails before the subsequent outer
checkpoint/identity/release opportunity. No hold count or negative requirement
needs to be reduced to explain this result.

These are completed orchestration counters, not an instantaneous post-failure
child/ACK trace: failure collection can run before the log. `query_child_present`
is the retained Docker-query child slot, not evidence that a policy child was
spawned. There is no successful policy Intent ACK/acceptance witness, policy
Birth witness or completed Bootstrap scope. The retained canonical first HOST
query has Birth/facts/verified_at; later query slots are null, and no committed
Bootstrap policy history was captured. The91-writer prefix is consistent with
query Intent/Birth/Result indices87/88/89 and held first policy Intent90.

Run402 remains an outer-helper Deadline whose exact helper was not logged.
403's native-poll label must not be backfilled into402. The failure boundary
can vary as the same original window is consumed; this pair does not prove
that instrumentation, ancestry correction, scheduling or any one operation
caused that variation. Outer whole-run wall time is not a scope budget measure.

## Original window and measured elapsed cost

Root's retained first-query public times are:

| Event | Boot time | Since original request |
| --- | ---: | ---: |
| Request |197538.988574814|0|
| Query child birth |197540.086969863|1.098395049s|
| Query Verified observation |197540.29587329|1.307298476s|
| Original deadline |197540.988574814|2s|
| First boundary-error observation |197540.99594918|2.007374366s|

At query verification only0.692701524s remains. That remainder must still cover
query Result acceptance, Request construction, first policy progress, and the
rest of the HOST policy under the same original window. There is no new policy
window. The first diagnostic boot observation is7.374366ms after the deadline;
the subsequent existing failure log is7.420606ms after it. Neither is the exact
failing predicate's clock sample.

The complete wrapper table is:

| Fixed wrapper | Calls | Total elapsed ms |
| --- | ---: | ---: |
| query_source |1|15.984562|
| query_hold |1|37.325416|
| query_checkpoint |4|502.650387|
| query_identity |3|78.430660|
| query_held_negatives |3|50.120254|
| query_release |1|38.039119|
| policy_hold |1|44.260971|
| policy_queued_negatives |1|32.587417|
| policy_checkpoint |3|127.978111|
| policy_held_negatives |1|51.625076|
| policy_identity |2|57.096796|
| policy_release |0|0|
| native_poll |13|923.556681|

Query outer wrappers sum0.722550398s; policy outer wrappers sum0.313548371s;
native polls sum0.923556681s. All timed wrappers sum1.959655450s,97.9827725%
of the original two-second budget. The difference between that sum and the
first boundary observation is about47.718916ms. It includes unmeasured
construction/inter-wrapper work, sleeps, accounting and scheduling; it must not
be assigned to a particular operation or treated as a precise clock identity
because the durations and original window use separate monotonic observations.

The outer wrappers and native polls are disjoint top-level measurement intervals.
Query wrappers precede query child spawn by source order; policy wrappers follow
accepted-query/Request construction. Thus over1.036s of measured elapsed time
is spent in the outer lab orchestration itself, including its nested production
validation. This is real elapsed budget consumption, not a separate lab timeout.
It does not establish that all that time is avoidable or that serialization is
the dominant CPU consumer.

Query checkpoint is the largest helper total,502.650387ms across four calls;
native poll is923.556681ms across13. No individual call durations or native Step
totals were retained, so averages cannot identify an outlier, child wait, IO stall
or specific native phase. The native total also includes its original failure
latch/collection on the failed call. Measurements stop at the first instrumented
error and exclude later diagnostics/collection. Remaining whole-VM samples, if
collected by Root, must retain their original sampling limits.

## Inner Deadline candidates and repeated work

At Step::Intent, `Native::advance` in `operational/bootstrap.rs` performs:

1. the original query deadline check;
2. `OperationalOwner::verify_policy_progress`;
3. `OperationalOwner::poll_policy_intent`, which repeats typed policy progress;
4. `Server::poll_bootstrap_intent`, which also repeats typed policy progress,
   then calls preparation `poll_inspection/advance` for the exact Intent phase;
5. the original final query deadline check if the earlier work returns normally.

Each typed policy progress path retains original custody, Request/Accepted
checks, exact typed expected record, same continuation/proposal/phase/start,
OriginalWrite and original pending-writer proof, Source/Pins and binding checks.
`Request::verify_write` first requires the original Bootstrap proof, then checks
the Request, verifies the original Source directly and through Pins, checks
slots/ancestry and checks the Request again. Producer receipts each recheck
`OriginalWrite::verify_origin`. For a successful complete Intent verification,
the exact expected record reaches `Native::verify_owned_progress` at least four
times: initial progress, Request proof, direct Source proof and Pins Source proof.
These are existing closed proof checks; they must not be replaced by a caller
boolean or a cached successful verification.

`Native::verify_owned_progress` (`preparation/quarantine.rs:1058ff`) serializes
the immutable expected record on every invocation. It separately serializes the
current continuation proposal, current canonical journal and actual pending
proposal, checks their exact relationships, and validates actual pending writer
IO/registry/member/phase/start/deadline. `encode_record` (`owned.rs:2153ff`) is
bounded262144-byte JSON encoding; it does not itself perform the live custody
checks. This identifies repeated pure representation work in source, not its
measured share of the wrapper totals.

Possible Deadline returns in the failed poll still include original query
entry/exit checks, Accepted/Request checks, `original_frame` in progress/proof
checks, and the preparation writer's original-frame/job-deadline checks. With
policy release uncalled, successful completion of that held writer is not
proved; failure before or while polling it remains possible. The new record
does not distinguish entry expiry from expiry during validation or the final
check after a pending return. All use the original query window. No clock
weakening, renewal or ancestry blame follows from these measurements.

## Bounded optimization candidate for a separately reviewed brief

The narrowest identified candidate is to derive and reuse the immutable expected
record's encoded bytes and digest only inside one synchronous, closed
`verify_bootstrap_progress`/OriginalWrite invocation. The current proof already
retains the same immutable expected Record throughout that invocation. Reusing
its exact bounded encoding can avoid repeating that same pure serialization
and expected digest derivation for every use of the existing proof.

This candidate should satisfy all of the following constraints if authorized:

- Keep the typed expected-history construction and exact byte-equality relation;
  preserve encoding/error/size-limit semantics and original short-circuit/error
  ordering. A representation cache is not a successful-verification cache.
- Keep every existing proof invocation, creator/custody check, original clock
  observation, phase/start/member/registry/IO/deadline/fence check, actual writer
  check, Source/Pins/slot/ancestry check, and outer wrapper/held assertion.
- Freshly encode/check the live canonical record, continuation and actual
  pending proposal on every existing proof use. Do not reuse those live values
  or a previous OriginalWrite result across proof uses, helpers or polls.
- The representation must remain private to the existing closed proof and be
  dropped before the progress call returns. No durable/global/Rc cache, new
  authority constructor, broad pending-history allowance or public byte getter.
- Do not alter any journal resource, child, writer count, release/ACK boundary,
  clock or hold/negative count. Keep the diagnostic table and all old failures.

Likely source boundaries would be the existing OriginalWrite definition/use in
`owned/preparation.rs`, the typed proof construction in
`owned/preparation/bootstrap.rs`, and the existing progress checker in
`owned/preparation/quarantine.rs`. This is a proposal, not authorization to touch
those protected paths, and no implementation has been made.

No speedup or sufficient remaining budget is demonstrated. Query wrappers account
for a larger measured share than policy wrappers; the proposed policy-proof
representation reuse does not by itself eliminate repeated query custody work.
The502ms query-checkpoint total may also include scheduling/IO delay. If Root
requires a measured mechanism before even this pure-work refactor, the next
diagnostic should use fixed accumulated nested timers for custody/retained work,
expected encoding/digest, live-record encoding/digest, typed proof and native
writer advancement, emitted only on error. It should retain the exact existing
checks and avoid per-poll output. No claim of serialization dominance is justified
without that evidence.

A later optimization brief should require meaningful equivalence/limit tests for
the immutable representation and retain all current foreign owner/proposal,
wrong phase/start/IO/deadline/fence, live-resource and held-writer refusals. Tests
must show reuse cannot outlive its one original proof invocation, not merely
assert log text or duplicate an implementation. Root would then review coherent
source/artifact bindings and own a new native attempt. Completion still requires
the remaining HOST work and all other scopes, not just moving past this failure.

No full Bootstrap, task8c, real-client, runtime, migration or release gate is
passed by403 or this diagnosis. Root owns preservation/inspection of retained
resources and55-link baseline; this report makes no cleanup or exact parent-ACK
claim. Source and every failed run remain preserved.

## Addendum: source-count proof and next diagnostic, not cache approval

The repeated-encoding count can be made exact for completed positive calls.
Source spans in the frozen candidate are:

- `preparation/bootstrap.rs:657-754`: complete typed policy progress; the initial
  owned check and OriginalWrite construction are at742-748.
- `operational/bootstrap.rs:162-179`: Request proof use, direct Source proof and
  Pins proof. `preparation.rs:494-514` sends each proof-origin check to the same
  owned progress verifier.
- `preparation/producer_creation.rs:425-430`: each Source receipt invokes the
  original proof. `operational/producer.rs:126-134` repeats that Source proof
  through Pins.
- `preparation/quarantine.rs:1058-1125`: one expected encoding at1068 on every
  owned-progress use, proposal encoding at1077, canonical encoding/digest at1081,
  expected digest at1109 and pending encoding at1110-1116 in the held branch.
- `operational/bootstrap.rs:352-368`, `operational.rs:136-144`, and
  `preparation/bootstrap.rs:500-508`: the three complete typed policy progress
  calls in a successful pending Intent native poll.

One complete positive typed policy progress therefore encodes the identical
immutable expected Record exactly four times. The completed outer wrappers
prove ten full positive calls: hold1, checkpoint3, identity2, queued negatives2
(outer positive plus inner positive) and held negatives2. Three policy checkpoint
loop entries also prove that the first two associated Intent native polls
returned successfully pending before the third failed. Each completed pending
native poll has three full positive progress calls, giving another six.

Thus at least16 complete positive policy progress calls produced64 immutable
expected-record encodings before the failing call. A hypothetical same-call
representation reuse would reduce those64 to16, removing48 encodings. This
excludes extra negative/partial checks. In the held owned-progress core, four
records are encoded on each use; four proof uses mean16 core record encodings
per full policy verification. Reusing only the expected representation removes
three of those16,18.75% of that restricted core's encoding call count. It does
**not** prove18.75% elapsed time or CPU savings, and it says nothing about the
unmeasured cost of other serializers, retained metadata or full-history checks.

Root identified another repeated source path that needs attribution:
`preparation.rs:1033-1037` Native::require_creator calls
`owned.rs:1556-1581` Transaction::require_allocation_memory, which calls
`Record::bind_anchor` (`owned.rs:777ff`) and validates retained preparation
history. Binding::verify_retained also performs complete preparation validation.
This may dominate pure expected encoding, particularly in the query helpers.
Neither source multiplicity nor a serde_json::Value shape proxy can establish
the native typed-record/live-custody elapsed share. Offline microbenchmark is
**NOT_RUN**; no experiment files or benchmark binary were created.

The preferred next step is now Root's concrete
`task-8c-bootstrap-nested-cost-brief.md`, not the hypothetical cache. Its bounded
six paths are owned.rs; preparation.rs; preparation/quarantine.rs;
preparation/bootstrap.rs; new cfg(test) preparation/lab_cost.rs; and
operational/bootstrap.rs. Fixed inclusive counters will distinguish allocation/
anchor memory validation, Binding custody/retained checks, owned/typed Bootstrap
progress, original proof rechecks, record encoding/SHA (with an expected-encoding
subcategory), and native writer advancement. Shared paths cover query and policy;
the existing first-error boundary emits one stopped snapshot with no per-poll
logging. Inclusive categories overlap and cannot be summed as disjoint elapsed
or CPU cost. All original operations, proof checks, clocks and negative coverage
remain fixed. Timer helper tests, if needed, should test inactive, bounded,
nested/early-return and foreign-creator behavior rather than copied log text.

Root has authorized that next diagnostic as a separate increment. This403
diagnosis is frozen before that implementation; its source evidence refers to
the unchanged403 candidate, not to future instrumentation. No semantic cache
has been authorized or implemented.
