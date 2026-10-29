# Independent spec and quality review: original-owner pending Bootstrap progress

2026-10-29. Scope: the thirteen frozen Rust source paths in
`target/task8c-pending-20261029T133358Z/root-frozen-source-hashes.json`, relative
to semantic base `ae8450cfbdb44e16c481e51c3bd419563a308f99`. Reviewed on branch
`rust/v2`, observed HEAD `880776cb0ff59879322ea2b28f90bfbe3c987962`.

**SPEC verdict: PASS for this bounded source repair and its source-level native
assertions. QUALITY verdict: PASS for the reviewed increment. No blocking source
findings.** This clears this source-review gate only. Connected native execution
of this candidate remains **NOT_RUN** at review time; no Bootstrap-family,
full8c, runtime, client, cleanup, migration or release acceptance is granted.

Read the pending-progress requirements brief first. Requirements and context
also read: run400 diagnosis, parent task8c/task8 briefs and
`docs/rust-v2/IMPLEMENTATION.md`. Reviewed the implementer report and complete
frozen diff, then only unchanged dependencies needed to trace the changed
custody, polling, ACK, retention and native-job checks. This was not a broad
foundation re-review. No source, VM, privileged, Git, manifest/context, build or
test mutation was performed. This review document is the only file written.
All thirteen source hashes were checked again after writing and remain frozen.

## Findings and verification boundary

No P0/P1/P2/P3 defect attributable to this increment was identified in the
reviewed source. The following are explicit evidence limits, not hidden passes:

- **Native behavior NOT_RUN:** complete original OperationalOwner/Source/Request
  progress, strict-history refusals and writer87/writer90 ACK assertions are
  compiled fixture assertions, not observations of an executed native candidate.
  See `attachment/operational/bootstrap.rs:678-737,963-981,1130-1147` under
  `crates/vprouter-launch/src/`.
- **Wrong original Request execution NOT_RUN:** the production checks compare
  the original `Rc<Request>` and the exact borrowed Request pointee
  (`owned/preparation/bootstrap.rs:665-671`,
  `owned/preparation.rs:502-514`). The new rootless fixture does not exercise a
  second real Bootstrap Request or a complete foreign OperationalOwner. It must
  not be described as proving those cases dynamically.
- **Run400 predicate not captured:** source establishes the eager strict-history
  conflict, but this review does not determine the precise executed return in
  run400. Its durable Intent remains distinct from parent ACK. No old failure or
  retained resource is superseded by this source review.

## Frozen inventory and report checks

Independently recomputed all thirteen source SHA256 values. Each matches both
Root's JSON snapshot and the implementer report. The frozen review diff hash is
`c19a2814a176bcd3543dc1a8d39400c99248775d62012e52faee8518b510e351`, matching
Root's snapshot. The diff is byte-for-byte identical to
`git diff --unified=10 ae8450cfbdb44e16c481e51c3bd419563a308f99 -- <13 paths>`.
Its thirteen paths and 738 insertions/79 deletions match the report.

The exact reviewed paths, all beneath `crates/vprouter-launch/src/`, are:

```text
attachment/host_addition.rs
attachment/host_addition/operation.rs
attachment/operational.rs
attachment/operational/bootstrap.rs
attachment/operational/producer.rs
kernel.rs
kernel/bootstrap.rs
kernel/producer_creation.rs
owned.rs
owned/preparation.rs
owned/preparation/bootstrap.rs
owned/preparation/producer_creation.rs
owned/preparation/quarantine.rs
```

The six approved8c.1 receipt source files were independently rehashed against
the report and compared to the semantic base; all six hashes match and all six
diffs are empty: worker `operation.rs`, `engine.rs`, `engine/tests.rs`, and
launch `handoff.rs`, `transport.rs`, `expiry.rs`.

The three retained final local logs also match their reported SHA256 values:
`/tmp/task8c-pending-final2-lib.log` records 147 passed/0 failed;
`/tmp/task8c-pending-final2-rootless.log` contains the shared production-core
marker and final exact-filter PASS;
`/tmp/task8c-pending-final2-clippy.log` records successful completion. These are
verified retained implementer logs, not reviewer-run tests. Earlier red runs
were reported from session evidence; this reviewer did not independently replay
or authenticate that earlier red sequence. Root owns the fresh full-workspace,
format and strict-Clippy checks; they were not duplicated here.

Before this review was handed back, Root reported a fresh workspace result of
396 passed/0 failed/2 ignored, passing format and strict workspace Clippy, and
separate independent provenance approval for candidate `cc0081ba` at
`target/continuation-20261029T134857Z` (202 source/build inputs and both payloads/
contexts). These are Root's reported checks; this source reviewer did not repeat
the artifact audit. Root reported no VM action pending this source gate.

## Source-level spec assessment

**All six pending phases are covered.**
`OperationalOwner::custody` checks creator, original completed handoff, failure,
five retired suffix jobs and retained reservation resources before forwarding
through the original HostAddedPrimary/HostLinkedAssembly. Its mutable service
access remains private to the operational module. Each closed query/policy poll
validates the typed progress before polling the same retained Server
(`attachment/operational.rs:64-166`). The original HOST chain, generation Rc,
producer-binding custody and completed HOST receipts remain checked
(`attachment/host_addition/operation.rs:227-279`).

`Native::advance` uses those paths for query Intent/Birth/Result and policy
Intent/Birth/Result (`attachment/operational/bootstrap.rs:352-484`). New query
construction, accepted-query Request construction, child release, reading,
post-ACK acceptance and completed-chain checks retain their strict checks. For
policy Intent and Result, the lower Server polling methods also use typed
progress before polling, then restore ordinary Request/Verified validation only
after ACK clears shared pending
(`owned/preparation/bootstrap.rs:500-523,577-605`). Birth binds the original
child and verifies its strict Gate after the original writer ACK
(`owned/preparation/bootstrap.rs:539-556`, `kernel/bootstrap.rs:237-273`).

**The exception cannot be constructed from history, IDs or a caller boolean.**
`OriginalWrite` has private fields, no serialization or scalar constructor, and
borrows the actual Server. The sole construction site first checks the original
Binding and continuation Request Rc, constructs the exact typed stage proposal,
and verifies it against native progress
(`owned/preparation/bootstrap.rs:657-754`). Every proof use checks the same
SharedJournal Rc/member and original continuation again; Request use also checks
the exact original pointee (`owned/preparation.rs:373-381,494-515`).

The native verifier still requires creator/allocation memory, original
two-second frame, issued result, service membership, no failure/fence, exact
phase/start, absence of unrelated publication, byte-identical complete proposed
Record and canonical-before digest. It distinguishes a sole original queued
entry from an original pending writer and rejects ambiguous combinations
(`owned/preparation/quarantine.rs:1058-1124`). The pending branch additionally
requires the actual original JournalChild's immutable IO binding, counted and
inventory-retained MutatorLease, registry Rc/member, and the registered Born
Journal ticket with identical native state Rc
(`owned/preparation.rs:384-419`, `owned.rs:1235-1254`,
`kernel.rs:1653-1676,2342-2347`). Its booleans are private observations read from
the actual pending job/shared state, not caller-supplied authority. No clock,
lease or deadline is renewed.

**Global historical readers remain strict.**
The ordinary producer Receipt `verify_history` is unchanged and unconditionally
refuses any shared pending writer (`owned/preparation/producer_creation.rs:461-487`).
Ordinary Source acknowledged-history verification, Context, Request and Pins
continue through it. The separate receipt write verifier first requires
OriginalWrite, then checks original Source/intent origin, creator, exact
request/birth/group/verification, fence and committed producer history
(`owned/preparation/producer_creation.rs:425-455`). Request write verification
retains source-binding/source-pointer and group checks; both Pins routes call
the same eight-slot descriptor/inventory/type/mode/cgroup/ancestry validation
(`attachment/operational/bootstrap.rs:143-179`,
`attachment/operational/producer.rs:119-181`). Descriptor getters still use
ordinary strict Pins verification (`producer.rs:183-212`).

Policy Result's new `write_evidence` only reads the original native completion
after checking its retained registrations, actual successful original reap,
completed/result state and original acceptance window. Exact Request and Source
checks follow under OriginalWrite. It creates neither a receipt nor child,
ACK, placement or policy authority (`kernel/bootstrap.rs:389-444`). There is
only one production call site, the closed Result proposal verifier.

**Exact20 custody, failure and kernel boundaries remain.**
The unchanged reservation requires the original fifteen transferred resources
and exact five-job extension, same epoch/member/shared owner, nonfailed/unfenced
state and exact retained transfer tickets
(`owned/preparation/assembly.rs:317-387,415-473`). All new operational polls
check that reservation. Original failure latching/cancellation/collection is
unchanged: errors return through PendingBootstrap, fence the original pending
writer and retain its proposal/charge/resources
(`attachment/operational/bootstrap.rs:286-309,566-594`,
`owned/preparation.rs:1039-1065`). Actual reap and ACK digest validation still
precede canonical update and clearing shared pending
(`owned/preparation.rs:1254-1289`).

The delta adds no unsafe block, syscall, capability, namespace operation,
secret ingress, role/filter broadening, child spawn route, public descriptor
getter or cleanup authority. The kernel additions only compare existing native
ownership receipts and immutable constructor IO. No runtime/UP/Ready authority
is added.

## Regression and native assertion assessment

The rootless addition exercises the production `PendingWriter` validation core
around a real original gated JournalChild, real lease/native registry and
immutable constructor IO. It accepts the original, rejects foreign
registry/member, phase/start, before/after, deadline, nonmutation, failed and
fenced observations, then rechecks the original. It leaves the child behind its
initial gate (`owned/preparation.rs:423-492`, `owned.rs:7936-7975`). The existing
same fixture still checks actual reap and OFD/reservation retention after wrapper
drop, including OFD busy after death and release only through collection
(`owned.rs:7977-8023`). This is meaningful partial native ownership/core evidence.
It does not instantiate a SharedJournal continuation, complete owner, Source,
Request or OriginalWrite; its phase/start/flags are controlled borrowed test
observations. The report accurately states that limit.

The first query fixture retains its original Source before pending, arms the
existing before-sync checkpoint, verifies typed progress at checkpoint/identity/
release and every normal poll, and checks unchanged writer identity across held
observations. Strict Context and Source must each refuse on two held polls and
the release checkpoint: **2 x 3 = 6**. Its final oracle requires writer index87,
same PID/start, actual status0, ACK verification, held count2 and released=true
(`attachment/operational/bootstrap.rs:678-711,963-973,1130-1138`). No extra native
child or resource is introduced.

The policy fixture retains the existing four negatives at the queued boundary
and four at the held boundary: strict Binding, wrong phase, changed original
start and changed proposal. At the held boundary it adds strict Context,
Source-history, Request and Pins refusals: **4 + 4 + 4 = 12**
(`owned/preparation/bootstrap.rs:801-829`,
`attachment/operational.rs:376-394`,
`attachment/operational/bootstrap.rs:29-39,713-737`). The final oracle requires
writer index90, matching PID/start, actual status0, ACK verification, held count2
and negative count12 (`bootstrap.rs:974-981,1130-1138`). The DATA Result failure
checkpoint now reaches its original writer through typed Result progress and
retains its existing failed-charge oracle (`bootstrap.rs:748-759`).

These native assertions are suitable for Root's next coherent-artifact local
execution gate. They have not passed natively in this review. Root must retain
fresh failures, original clocks and resource evidence if that execution fails;
component success and this source verdict cannot replace it.
