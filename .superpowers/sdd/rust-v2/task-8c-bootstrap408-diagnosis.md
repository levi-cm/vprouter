# Run408: Result Deadline; no functional remedy justified

2026-10-29. Root-authorized read-only diagnosis/proposal. Only this diagnosis and
the separately requested driver-measurement brief were written. No application
source, tests/builds, Git, native/VM, resource/profile or acceptance action.

408 remains FAIL/zero completed cases/HOST/native_poll/Deadline after all required
held negatives and releases. The process-local Step advances to Result, but the
durable HOST policy result and verified_at remain null. Owner-inner rows locate
large elapsed regions in current live verification; they do not justify caching,
removing/reordering observations or another speculative pure optimizer.
No functional source remedy follows from408. The defensible next experiment is
a separately reviewed driver-only measurement of parent-thread CPU, elapsed time
around the exact existing sleeps, and the post-constructor original-clock gap.
It answers parent-on-CPU versus combined off-CPU/oversleep, not scheduler-specific
causality or whether the original two-second window can fit.

## Evidence binding and preservation

Independently hashed:

- Raw `target/lab-state/actual-program-run-408.json`:
  `d102dbdb315bd00ab43de263f286136a13b378406c72ce178b497fa4ea1f61db`.
- Closed `target/task8c-owner-cost-root-20261029/bootstrap408-closed-metadata.json`:
  `2bdb9551e9950564c2c565aa78b62f6c64b4e4af347e3ab340a9f92a45d13208`.
- Public `docs/rust-v2/task8c-bootstrap-attempt408.json`, as read:
  `bbbb153b5eb88281eabc57faba4428cf96e544dda5e5c7a4b63ac1a0a189d2e7`.
- Inspector `target/lab-state/secret-bootstrap-failure-run-408.json`:
  `8054ec9ef306bfc23795513173cdd931ab5f61bc8430c3b0bcc88eab07cb4279`.
- Prior `.superpowers/sdd/rust-v2/task-8c-bootstrap407-cadence-audit.md`:
  `b3102e368ec9c1b187716778915efe39f884a24f776fbbd0392547107bdffaa0`.

Raw/closed/public independently agree on all ordered13 wrapper,30 nested,24
retained and15 owner rows. Stderr has391 lines:73 phase,184 journal,48 attachment,
one boundary,82 cost and three final failure lines. The92 journal inventory/
verified pairs alternate exactly. They are writer stages, not receipt ACKs.

Run source4d9658fce6d206161023ec3487409680a30f4c23; source archive
86619f5d49cbfac7bae6a73d1c1d118734f62d4a2617d05d90e32c336a49d901;
203 verified inputs; aggregate
f33ab8a6dc390fd63626eed25353f9f649d5e40ab4120d3cf516ed594637cc4f;
amd64 artifact732133c8ceebe17f95054d2c00229c4fc869e00df94ac83027a3dfd9535fa615.
Debian clean x86_64, exit1, runner wall12.618s, synthetic success component mode,
provider_profiles_used=false and real clients NOT_RUN. Runner wall includes setup;
it is not the HOST window. Current all179 Rust hashes and path set exactly equal
`target/task8c-owner-cost-local/rust-after.json`, SHA256
a2470282e09505560cb37a0568fcccb58b6b7b318ff82873e0ec35fbeaf8fc7e.
No changed/missing/extra Rust path was observed in this diagnosis.

Inspector-time six fixed selectors and two canonical files are present; gateway
running, owner unit inactive/not-found, owner cgroup absent. This is an inspection
snapshot, not a new outer-preservation or later archival audit. Public record as
read has archival NOT_RUN and review PENDING; Root owns subsequent reconciliation.
No prior failure/resource preservation operation was duplicated.

## Window and meaning of Result

```text
helper=native_poll step=result reason=Deadline
query_present=true query_child_present=true query_accepted_present=true policy_present=true
query_queued=true query_held=2 query_negatives=6 query_released=true
own_queued=true own_held=2 own_negatives=12 own_released=true
original_requested_at=Some(206716.420116665)
original_deadline=Some(206718.420116665)
observed_boot_now=206718.444920353
```

Boundary observation is24.803688ms beyond deadline; later HOST observation
206718.445080733 is24.964068ms beyond. Neither is the exact failed clock check.

| Durable public observation | Boot time | Since request | Remaining budget |
| --- | ---: | ---: | ---: |
| HOST query Birth |206717.031619732|0.611503067s|1.388496933s|
| HOST query Verified |206717.213226563|0.793109898s|1.206890102s|
| HOST policy Birth |206718.123355717|1.703239052s|0.296760948s|

Canonical HOST query slot0 has facts/non-null verified_at above; later slots null.
HOST policy history0 has Birth, result=null and verified_at=null. Keep these
query/policy statuses separate.

Frozen operational/bootstrap.rs:466-472 assigns Result only after the child poll
yields Verified and start_bootstrap_source returns. That queueing path verifies
its source and prepares result publication; it does not prove durable publication,
receipt acceptance or HOST completion. The same advance may fail its trailing
query deadline after assigning Result; a later poll may fail its initial deadline,
Result progress validation, source receipt work, final proofs or clock checks.
Result narrows progress beyond407 Reading; it still does not identify that exact
predicate or show that poll_policy_result returned a receipt. Zero scopes/cases
completed. PendingBootstrap.poll also performs fail/collect before returning its
error, so native wrapper elapsed can include post-error work.

The prior cadence audit's source/clock findings remain applicable: operational
bootstrap.rs SHA256 da65fe12514a8f668f10d83cb4a668d9d59f0dd6faa26edf6487d9edab6f9d22,
owned/preparation/bootstrap.rs0602f7630e895bee5f6834371ee4323025837363e439a4d7e97979918eaa0a53,
kernel/bootstrap.rs a35735c97bb6333d229dbefccc5eb7e0cb05781e019c68eaa0e01d1b3a18a945.
Shared query/policy deadlines remain requested_at+2, with original progress checks
before/after step work. The audit found no driver or clock-origin defect;408 does
not supply contrary evidence. No renewed deadline or reduced held coverage.

## What the owner rows resolve, and what they do not

| Global method category | Query calls / ms | Policy calls / ms | Other calls / ms |
| --- | ---: | ---: | ---: |
|owner_host_preflight|4577 /104.160254|4731 /105.537400|472 /9.725899|
|owner_record_validate|4577 /3.033698|4731 /3.320276|472 /0.283740|
|owner_namespace_identities|4577 /59.777043|4731 /59.659576|472 /5.669226|
|owner_current_identity_chain|4577 /62.628717|4731 /63.283881|472 /6.027531|
|owner_record_clone|4577 /0.774841|4731 /0.810635|472 /0.072208|

These global OwnerDomain.verify/record boundaries include non-Binding callers,
constructor/capture paths and errors. Their4577/4731/472 entries differ from the
retained Binding owner4292/4465/442 entries (218.649273/222.484016/20.765826ms).
They cannot be divided into, summed with, or subtracted from those retained rows.
Equal five-key counts within a family do not establish an exact invocation
bijection, unchanged work or absence of early errors. Other can precede the
original window; cached loop-entry family is not an exact semantic phase.

Pure record validation and clone are small observed regions beside preflight,
namespace opens and the final native chain. Preflight itself mixes current IO
with pure parsing; no parser-only cost or safe optimization saving is measured.
Each native check is intentional fresh custody/identity evidence. Retained
observations cannot be pooled, cached or skipped from elapsed counts. Fixed path
formatting/parser/allocation rewrites remain unproved hypotheses. The rows include
Instant/TLS/token/cell overhead, old-State copies, caches, COW, IO and scheduling;
no exclusive CPU attribution, counterfactual saved budget or fit follows. Do not
use the small pure rows or the24.8ms late observation as a counterfactual bound.

## Concrete causal gap and bounded next experiment

The43 sequential wrappers total1.969851274s: query13calls/0.367559312s,
policy11calls/0.406241131s, native19calls/1.196050831s. Held helper validations
therefore still occupy observed window time; they are not removable waiting.
With zero prior success,19 native polls ending in failure imply18 earlier
Ok(None) outcomes and18 reached sleep calls requesting1ms each. Actual elapsed
sleep was not measured. The post-error collection sleep is fault-gated and is
not reached by this unarmed success-mode Deadline path.

Request-to-boundary is2.024803688s. Subtracting wrappers gives54.952414ms of mixed
post-clock constructor/queue, sleeps, loop/family/counter work and bookkeeping.
It is arithmetic, not measured off-CPU or constructor time. Subtracting nominal
18ms would not create a measured residual. BOOTTIME includes suspend while Instant
does not, so exact reconciliation additionally needs that clock distinction.

The question is now: do the measured wrappers mostly consume parent-thread CPU,
or do they include substantial combined off-CPU time? Is actual sleep elapsed
materially above the nominal requests, and is there a substantial unbracketed
post-clock constructor prefix? The separate task-8c-driver-cost-brief.md specifies
one additive cfg(test), driver-only measurement to discriminate those hypotheses.
It preserves all original checks, clocks, wrappers, call/sleep placement, held2+2,
negatives6+12, ownership/custody and failure propagation. It does not add another
owner/parser probe or recommend an optimizer. Implementation/native use require
fresh plan review and Root dispatch.

CPU close to wrapper elapsed would support parent execution in those intervals,
including kernel work and observers; it would not distinguish necessary native
checks from instrumentation. Low CPU with large elapsed would support combined
blocking/preemption/child-progress effects, not scheduler starvation specifically.
A large measured sleep excess would support a sleep-associated gap; a small one
would redirect investigation toward wrapper blocking or the constructor prefix.
Sampling loss/overhead or missing evidence remains unknown, never zero cost.
No off-CPU result alone permits resource tuning, check removal or fit claims.

An observer-disabled control would answer a different question. It is NOT
proposed for dispatch here: collection/stop/output/parser and exact test semantics
would first require a separate equivalence design. No observer-off experiment
is authorized. Original398-408 FAIL evidence and production/identity/credentials/
retry repair remain preserved; full8c/ARM/clients/migration/performance/release
acceptance remains open/NOT_RUN where unaccepted.
