# Run400: strict source receipt conflicts with an owned pending query writer

2026-10-29. Local read-only source/evidence investigation. Only this report was
written. No source edit, build/test, VM/SSH/Docker/privileged operation,
profile/credential/identity access, cleanup/retry or Git mutation was performed.
Source remains frozen pending Root's checkpoint and next brief.

## Evidence and conclusion

`target/lab-state/actual-program-run-400.json` binds source
`fbfa3bbc75abe2878216e520f5be6534083cf600`, archive
`308352254ed9d003f261d9084d955b2c5b39e08d0a73bce82deb6ecd30c4b3e4`,
202 verified inputs and aggregate
`d27095ae6d003bf734f9fd2eeb089ce2493774d06e2b3113a69d6404bbc7e0ef`.
It records exit1, zero PASS/case witnesses and outer wall5.046s. Its stderr has
68 earlier phase marker lines; all earlier instrumented groups complete,88 journal inventory/verified pairs,48
attachment phase records, and:

```text
LAB_SECRET_BOOTSTRAP_POLL_FAILURE step=query_intent reason=OwnershipMismatch request_present=false query_child_present=false
secret_bootstrap_lab: ownership_mismatch
```

There is no `bootstrap.query_intent` success, query-spawn or Birth-queue marker.
The original error is now preserved. All host, exact20 handoff and initial
Bootstrap constructor boundaries complete. No native query child or Bootstrap
policy operation is proved born by this attempt.

Root's retained public snapshot
`target/lab-state/secret-bootstrap-failure-run-400.json` binds run record SHA256
`213688dcfaae8868045737a3dfb1fa00cdb8c97dcdafb837d1d581a67f2b1afc`.
It has first HostRecheck query Intent on disk, with birth/facts/verified_at
absent, remaining query slots null and no Bootstrap operations. The six
selectors and original gateway are retained according to Root's observation.
This agent performed no native inspection itself.

There is a concrete source-level failure mechanism matching runs399/400: the
Bootstrap loop obtains a context that eagerly verifies the strict producer
Source receipt before checking its own typed pending query continuation. That
receipt deliberately rejects **any** shared pending journal proposal. Therefore
the next poll after an incomplete first Intent writer returns OwnershipMismatch
before it can poll and accept that writer. This is a misplaced strict idle
receipt check, not justification to relax that check globally.

The failing pending boolean was not logged directly in run400, so this is a
source-established mechanism and a strongly matching runtime explanation, not a
captured stack trace identifying the exact executed return statement. The new
markers still permit a post-ACK Intent-construction/verification error in
principle. A deterministic held-writer regression should distinguish the
mechanism before promoting a fix to native acceptance.

## Exact source path and predicate

The normal QueryIntent loop in `attachment/operational/bootstrap.rs` first calls
`self.input.context()?.service` at line322, then `binding.verify_progress`, then
the mutable-service `poll_inspection_intent` expression. Before the latter can
return Some, the new query-intent success marker is absent on any error.

The eager context path is:

1. `OperationalOwner::context` (`attachment/operational.rs:141`) checks creator,
   failure, completed five-job suffix and retained reservation resources, then
   forwards to the original HostAddedPrimary owner.
2. `HostLinkedAssembly::operational_context`
   (`attachment/host_addition/operation.rs:258-267`) verifies the retained
   original HOST chain and completed host custody, then constructs Context with
   `source: input.operational_source()?`.
3. `ProducerBoundAssembly::operational_source`
   (`attachment/producer_binding.rs:322-328`) retains the same original Source,
   binds its service and calls `source.verify_acknowledged_history()`.
4. `kernel/producer_creation.rs:293-299` invokes the original private receipt's
   `verify_history`.
5. `owned/preparation/producer_creation.rs:429-442` checks the exact creator,
   original Source request/birth/group/verification and rejects
   `self.shared.pending.borrow().is_some()` at line439 with OwnershipMismatch.

The first query polling call creates writer88 and installs
`shared.pending = Some(proposed)` **before** releasing that original child
(`owned/preparation.rs:1089-1099`). `JournalChild::poll` returns None while the
original child has not been reaped (`kernel.rs:1698-1704`), which is normal
asynchronous behavior. The next Bootstrap poll enters the strict Source path
above with pending still present; its own `Binding::verify_progress` and the
writer's poll are never reached.

`OperationalOwner::service_mut` also re-enters context, and the lower
`HostLinkedAssembly::operational_service_mut` explicitly calls
`operational_context` again (`operation.rs:269-271`). Fixing only the first
immutable context call would leave the same conflict in mutable polling.

## Durable disk record is not parent ACK

The Journal IO child executes `job.run`, which writes/fsyncs/renames the public
record, then writes the ACK (`kernel.rs:1840-1851`). The parent separately waits
for actual child reap, validates the ACK/digest and only then updates its
in-memory canonical record and clears `shared.pending`
(`owned/preparation.rs:1111-1145`). A durable file may therefore contain Intent
while the retained parent's pending writer has not been accepted. Failure can
then cancel/collect that same child while preserving its written file and
proposal; the failure latch does not retroactively create acceptance.

Accordingly, earlier shorthand that the run399/400 disk snapshot proved
"Intent ACK accepted" was too strong. It proves a durable Intent record, not
in-memory acceptance or a successful `poll_inspection_intent` return. The
separate post-ACK path remains: after writer acceptance,
`poll_inspection_intent` selects history, retains its original allocation lease,
and verifies Intent (`inspection.rs:893-915`) before returning Some.

## Proposed bounded fix interfaces, preserving strict receipt checks

Keep `Receipt::verify_history` and all existing strict Source methods unchanged.
Do not add a general pending Source getter or a caller boolean waiver.

For a query-only prerequisite increment:

1. Split the existing retained HOST custody/service view from eager Source
   acquisition inside `HostLinkedAssembly`. The custody-only view still proves
   the original heap owner, creator, complete HOST chain, binding, generation,
   producer-binding custody and same Server; it never reconstructs state or
   returns descriptors. Forward that narrow private view through
   HostAddedPrimary. Existing idle Context construction keeps its strict Source
   verification.
2. Add closed OperationalOwner query-poll operations for Intent, Birth and Result.
   Each validates the exact20 reservation/resources, obtains that original
   custody-only service, and uses the existing `Binding::verify_progress` with
   the exact original Rc query plus typed stage/child/result. This preserves
   original member, epoch, queued/pending phase, proposal digest, original
   writer IO binding, resource receipts and request deadline checks in
   `Native::verify_owned_progress`. Only then poll that same retained Server's
   matching inspection operation. No general mutable Source or descriptor
   access is needed.
3. The internal mutable-service route must use the same custody view rather
   than accidentally re-enter eager Context. Keep it private to the closed
   typed operation; preserve fail/collect/retention and error propagation.
4. Have the three query-writer phases use these closed operations. Idle query
   construction and accepted-query Request construction keep strict Context and
   Source checks. No clock, lease, namespace, admission or resource is renewed.

These changes would touch the original HOST custody forwarding and operational
query polling interfaces, not the global Source receipt verifier. Interface
names and precise edit set require Root's next brief and review; this is not
an implementation claim.

There is a related scope limit: later Bootstrap policy-writer progress calls
`Request::verify_retained`, whose Source check is also strict, and
`Pins::verify_retained` repeats that check. `Binding::verify_bootstrap_progress`
calls `request.verify`. A query-only repair must not be called full Bootstrap
acceptance or silently relax those methods. A broader correction would need a
closed, original-Server typed policy-progress proof for those paths, retaining
the strict global verifiers. No semantic change to them is proposed without an
explicit scope decision.

## Meaningful unprivileged regression and native qualification

An existing rootless pattern is `owned.rs::lab_native_job_drop_retention`
(`:7840-7997`): it creates a real `spawn_journal_io` child held behind its release
gate, using a memfd OFD, original MutatorLease/reservation/native-job ownership
and fixed public IO. It never releases the child into chroot/drop-identity or
the privileged writer role. It already checks original before/after/deadline
binding and actual reap/lease retention. Reuse this pattern rather than invent
an OperationalOwner from deserialized identities.

The regression should exercise the production pending-progress proof core with
that real gated writer and the retained original fixture owner:

- The exact original member/request/phase/proposal/epoch/IO binding is permitted
  to retain custody and keep polling Pending; strict Source history remains
  unavailable while shared pending is present.
- A different Rc request with identical values, wrong phase, foreign member or
  owner, changed before/after digest, changed deadline and fenced/failed state
  are refused without releasing the child, moving resources, changing counts or
  renewing any clock.
- While pending and after actual child reap, its original parent owner retains
  the OFD/reservation/resource bundle until the explicit existing collection
  path; an independent OFD acquisition stays busy as appropriate.

If direct full OperationalOwner construction requires privileged native
resources, extract/test the same narrow pending-writer proof core with this
real native gated child and retain that limitation explicitly. Do not replace
the original owner with a fixture-only production authority constructor or
claim a scalar/predicate test proves the full native chain. Root must separately
run the connected original-owner held QueryIntent/Birth/Result fixture, exact
foreign-pending refusals and eventual normal ACK path on coherent reviewed
artifacts. No such regression or native run was executed by this investigation.

Runs398/399/400 and their resources remain retained failures. Run398's original
pre-constructor OwnershipMismatch remains unexplained. Full8c, autonomous
recovery, clients and release acceptance remain open.
