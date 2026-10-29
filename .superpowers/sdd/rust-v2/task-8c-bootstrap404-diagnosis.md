# Run404: retained validation fanout, original HOST Result Deadline

2026-10-29. Read-only source/evidence diagnosis requested by Root. Only this
report was written for the diagnosis. No application source edit, test,
compilation, VM/SSH/Docker/privileged operation, Git action or retry was performed.
Source remains frozen. A separately authorized ignored-target pure-comparison
benchmark is pending and will have separate evidence; it is not part of this
frozen base diagnosis.

404 fails through native_poll with Step::Result and the original Deadline,
after both held regressions and their releases completed. This is later within
this run than403's Intent failure; no semantic fix was made, scheduling differs,
and neither the later boundary nor shorter whole-run wall proves improvement.
The new inclusive rows identify repeated retained validation as a larger elapsed
category than expected-record encoding. They do not identify predicate CPU,
the exact failing inner clock check, or a proven sufficient optimization.

## Exact evidence and preservation boundary

- Raw `target/lab-state/actual-program-run-404.json`, SHA256
  `b476430ff8ce442397bdde466df102bb9306bf999554099323a0702d0305efd1`.
- Source `4451c8a75bcedcc330d4b59087a85f0bb5dca342`; Root identifies diagnostic
  milestone `0af1b9f` and this exact source tag as remotely confirmed.
- Source archive SHA256
  `4fc3b75ebc397c0857cdc83d9c20eb335f23ed23f1b648d6ce8b985a48f4abcf`.
- 203 verified inputs, source aggregate
  `4e28ac6571e0be8928ecc476aaf310120ba953b859b1c2c1f741763601f581e3`.
- Artifact SHA256
  `649ab51fbafc89b58b783a41fc468d3f31c20288cfdd4712fd75d4ddfeaba860`.
- Directory binding
  `target/continuation-20261029T161134Z/bootstrap-nested-cost-20261029/directory-binding.json`,
  SHA256 `2e1291afad99decb7da8c24d8cf2c9285e24c78c5bd33df0d57f9ff1d84eadca`,
  agrees with source/archive/artifact/raw binding.
- Root's unchanged read-only inspection
  `target/lab-state/secret-bootstrap-failure-run-404.json`, SHA256
  `7d58bdc2bf9d6153346427664ad8876831894626b0abb7d547e8d23f0ea3edfb`,
  binds the same raw record. Its canonical collection is allocations.json and
  namespaces.json; this implementer read no pending-journal content.

Result is FAIL, exit1, outer wall8.69s, zero case witnesses, success component
mode, real-client acceptance NOT_RUN. Complete stderr has354 lines and93 exact
inventory/verified pairs. Root's fixture auditor separately reports source203,
controller/baseline and unchanged inspection/resource preservation PASS. All six
selectors were present at the pre-archival inspection. Root's later receipt
`target/lab-state/secret-bootstrap-selector-archive-run-404.json`, SHA256
`42fd4d4f689773965123934430327590eff163d59c3229883d0c80adca187bac`,
records exactly six selectors archived, with container/state/profiles/canonical
records/mounts retained and no signal/unmount or private profile reads. That
independent preservation work is not duplicated here and does not convert this
failed component run into acceptance.

Current hashes of the six diagnostic source files still match the frozen
nested-cost report: owned.rs `1e2b547bc2df30a6a128184eae9b6569452d12ec80bc59f9ff71e90a18f0636e`;
preparation.rs `5379370d500f09a826fb3717b0949a355801823bbf40f63d1d8b3e6664c1b97a`;
preparation/bootstrap.rs `0602f7630e895bee5f6834371ee4323025837363e439a4d7e97979918eaa0a53`;
preparation/quarantine.rs `965e04b90a4048418a27a24439b5d4b754121acb17219e4c00644d8d9142a52f`;
preparation/lab_cost.rs `b1c0860166ed46d127d16095e788593558fb8928dc0264a435737f96a8fb2796`;
operational/bootstrap.rs `da65fe12514a8f668f10d83cb4a668d9d59f0dd6faa26edf6487d9edab6f9d22`.

## What the boundary establishes

The process-local first-error record is:

```text
helper=native_poll step=result reason=Deadline
query_present=true query_child_present=true query_accepted_present=true policy_present=true
query_queued=true query_held=2 query_negatives=6 query_released=true
own_queued=true own_held=2 own_negatives=12 own_released=true
original_requested_at=Some(199575.470574895)
original_deadline=Some(199577.470574895)
observed_boot_now=199577.470916398
```

The existing POLL_FAILURE also reports result/Deadline with Request and query
child slots present. The subsequent HOST failure log observes199577.470991449.
The first observation is341.503us after the deadline; the second416.554us after.
They occur after the returned error and accounting, not at its exact predicate.

The query completed its two held polls/six negatives and release. Policy
completed its two held polls/twelve negatives and release. Policy checkpoint
ran four times, identity three times, release once. No required hold, negative,
clock or ownership coverage was dropped to reach Result. The retained query
child slot is not evidence of a currently running policy child.

The canonical snapshot contains the first HOST query and one HOST Bootstrap
history with birth, original start/end, and null result/verified_at. Later query
slots are null. Durable fields alone prove neither parent ACK acceptance nor a
completed scope. The process-local Step::Result is additional control-flow
evidence: Verified child work and Result queueing precede that Step assignment.
The93-writer prefix is consistent with three query writers and policy Intent,
Birth and Result after the87-writer prefix. It is not an independently captured
Result writer ACK or an accepted policy receipt. No Bootstrap scope witness or
final case witness exists.

The failed native poll may return Deadline from original query entry/exit,
Accepted/Request/proof frame checks, pending writer checks, Result receipt
acceptance or subsequent current checks. The post-call Step is not the exact
entry Step or inner failing method. Although the fixed writer sequence supports
reaching Result journal work, the exact predicate remains unlocalized. No new
diagnostic category or predicate CPU attribution is proposed here.

## Window observations and disjoint wrapper totals

| Retained public observation | Boot time | Since original request |
| --- | ---: | ---: |
| Request |199575.470574895|0|
| Query birth |199576.06407901|0.593504115s|
| Query Verified |199576.25115348|0.780578585s|
| Policy birth |199577.163418628|1.692843733s|
| Original deadline |199577.470574895|2s|

Query verification leaves1.219421415s; policy birth leaves0.307156267s. All
policy continuation/Result work retains the same original query window. The
public birth is not a fresh clock or a success witness.

The13 disjoint outer wrappers sum1.946622354s: query wrappers0.354637758s,
policy wrappers0.405169077s, and19 native polls1.186815519s. These are elapsed
wrapper costs including nested validation, scheduling and IO, not CPU time.
The new nested table must not be added to them.

Compared with403, the same four query checkpoint calls have147.309784ms total
in404 versus502.650387ms in403. Query verification occurs about0.527s earlier
within404's own original window. Source changed only diagnostics; the observed
variation is not a measured semantic optimization or proof of its cause.

## All30 inclusive rows

Families mean the cached lab-loop-entry Step. A poll can transition or set up a
following stage; these are not exact inner phases. Initial constructor work is
labelled other and can precede the original query request. Categories overlap,
including expected encoding within global record encoding. Do not sum them as
disjoint wall or CPU cost, subtract them to manufacture exclusive CPU, or treat
them as an application acceptance benchmark.

| Category | Query calls | Query ms | Policy calls | Policy ms | Other calls | Other ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| allocation_anchor_memory |2153|42.761363|2053|41.476553|226|4.468368|
| binding_service_custody |283|66.386503|256|59.170999|30|7.119276|
| binding_retained |4292|335.094473|4396|339.254664|442|33.610994|
| owned_progress |25|10.703375|143|54.108351|0|0|
| typed_bootstrap_progress |0|0|32|134.031549|0|0|
| original_proof |0|0|105|39.972156|0|0|
| record_json_encode |116|11.292640|521|46.909786|1|0.105970|
| expected_record_json_encode |25|2.747405|143|13.715089|0|0|
| record_sha256 |66|0.710214|239|2.415867|1|0.009521|
| journal_advance |8|5.938277|7|5.504856|0|0|

Binding retained is entered9130 times overall and allocation/anchor memory4432
times. These count completed timer drops, including Result-error exits; they
are not an exact count of successful validations or of each inner serializer.
Expected encoding is a much smaller observed elapsed category than retained
binding. The old hypothetical expected-record cache therefore has no demonstrated
priority or sufficient benefit. Its source-count multiplicity did not establish
its elapsed share;404 supplies that missing caution.

All costs retain the diagnostic observer limits: each timer and fixed TLS-state
copy adds work; foreign child counters are COW-private and never merged/exported,
but child timer work can affect parent elapsed scheduling. No role/filter syscall
permission changed. No exact CPU share or speedup follows from these rows.

## Source trace of the retained-validation fanout

This is finite repeated call composition, not evidence of an ownership cycle:

1. OperationalOwner::custody (`operational.rs:64-81`) delegates through
   HostAddedPrimary to HostLinkedAssembly::operational_custody
   (`host_addition/operation.rs:227-280`). Its retained owner and Generation
   checks, producer-bound host custody, and four completed host receipts all
   revalidate retained authority. Mutable service access repeats custody.
2. ProducerBoundAssembly::host_custody/operational_source
   (`producer_binding.rs:309-334`) validates producer-bound custody, and the
   Source path separately validates acknowledged history. Completed host
   custody (`preparation/host_link.rs:442-472`) checks Binding service custody,
   full preparation history and each original receipt.
3. Binding::verify_service_custody (`preparation/quarantine.rs:41-54`) checks
   transport custody, creator/allocation memory, exact owner/shared/member,
   then calls Binding::verify_retained.
4. Source::identity (`kernel/producer_creation.rs:368-370`) calls
   Source::verify_retained and then native source() again. The first verification
   already calls native source() (`:338-350`). Both native source() calls
   (`:107-121`) invoke verify_created_group, which begins with producer
   Request::verify_retained (`quarantine/producer.rs:154ff`). That Request
   checks current parent custody then Binding::verify_retained (`:70-78`).
   Thus one successful identity() alone reaches Binding retained twice and
   still performs the required original live group checks.
5. Acknowledged Source receipt verification, direct Source proof, Pins Source
   proof, Pins slot/group verification, Request identity and completed receipt
   comparisons compose those same checks again. For example
   operational/bootstrap.rs:162-179 and operational/producer.rs:126-181 keep
   their direct Source, Pins, identity and ancestry checks. Ordinary historical
   receipt paths remain pending-refusing; no proposal relaxes them.
6. Every Binding::verify_retained (`preparation/quarantine.rs:56-101`) rechecks
   retained transport/data pins, allocation equality, owner/services, host
   descriptor and the entire selected preparation History. History::validate
   (`preparation.rs:90-219`) recomputes allocation digest and walks prior
   inspection/mount/transport, five WireGuard histories, queries, producer,
   six filter operations, four host operations, Bootstrap histories and input
   identity constraints. Allocation-memory checks separately call
   Record::bind_anchor (`owned.rs:1556-1582`, `:777-883`), which also validates
   preparation history.

These paths explain why a few outer helper/poll calls cause thousands of retained
checks. Their current live checks and negative coverage are required. The safe
target is pure representation work repeated inside them, not memoizing their
successful result or skipping repeated source/custody checks.

## Narrow pure-work candidate, not implemented

The proposed first candidate is **owned.rs only**, changing the private
same_allocation helper at644-646. It currently creates two JSON Vec allocations
and compares the encoded bytes on every call. Binding retained invokes it at69;
Record::bind_anchor also invokes it before full history validation. These are
the measured hot retained/anchor paths, unlike the much smaller expected-record
encoding category. Every existing call site, live observation and validation
would remain in place.

Replace only that pure serialization comparison with exact comparison of the
current four AllocationRecord fields and all current ExitAllocation fields,
including exit vector length/order. Use exhaustive destructuring with no `..`
so adding a field forces a compile-time review. Do not add validation caches,
allocation identity tokens, canonicalization, sorting, hashing, new authority or
public APIs. Do not derive whole-record/ExitAllocation equality and assume that
it matches serialized identity: state_dir is a PathBuf, whose component equality
can collapse textual path distinctions that JSON preserves.

Equivalence requires two details:

- Validate every state_dir.to_str() in record A and then B before returning any
  field/length mismatch. Current Serde Path serialization explicitly errors on
  non-UTF8 paths; same_allocation maps that error to OwnershipMismatch. Returning
  false before encountering a malformed later path would change that contract.
  The locked local serde_core1.0.228 Path/PathBuf serializer implementation
  (`ser/impls.rs:908-925`) was read to verify this boundary.
- Compare valid path strings/OS bytes exactly, including repeated separators,
  dot components and trailing separators. Strings and option strings are exact;
  mode variants have distinct fixed serialization; ordered vectors and every
  scalar field must be compared. No path normalization or collection as a set.

All current types are simple derived serialized fields (allocation.rs:29-49),
with no custom serializers or skipped allocation/exit fields; invalid UTF8 in
state_dir is the relevant typed serialization error. This supports a closed
field-equivalence proof and removes both temporary JSON buffers per successful
comparison. It does not establish their measured share of335/339ms, a particular
speedup, or sufficient time for all remaining Bootstrap work. Timer-entry counts
cannot be multiplied into an asserted exact serializer count because they also
include early errors and other work.

Root has separately authorized a bounded ignored-target experiment comparing
the exact old helper with this candidate using public AllocationRecord/
ExitAllocation fixtures and the same host toolchain. Its output must retain
shape, compiler, allocator and scheduling limits; actual native equality share
will remain unmeasured. No application source change is authorized by this
diagnosis, and no benchmark result is claimed here.

## Focused equivalence and runtime requirements for a future brief

Before any implementation, the bounded experiment should check the old serializer
as an oracle for exact clones; every allocation/exit field mutation; mode and
None/Some distinctions; length, order and duplicate exits; empty/control/Unicode
strings; path dot/repeated/trailing separators; and invalid UTF8 in either record,
including malformed paths hidden behind an earlier scalar or vector mismatch.
The comparator must return the same Result/Error as the original, not merely
reject the same valid fixture. No actual fixture resource or native authority
is constructed by those pure values.

A later one-file implementation brief should retain differential oracle tests
and all existing meaningful ownership/frame/IO/deadline/fence and held-negative
tests. No regression may be removed to fit the original2s window. Root owns
independent review, coherent builds/source binding and a new native witness with
the original diagnostic table and preserved prior failures. Runtime must prove
the actual selected mechanism's effect and the complete remaining scopes; this
report provides no speedup or acceptance substitute.

Full Bootstrap/task8c, real-client, runtime, migration and release gates remain
open. Root and the fixture auditor own resource preservation. No selector,
identity, canonical endpoint, retained child, pending artifact or failure record
was changed by this diagnosis.
