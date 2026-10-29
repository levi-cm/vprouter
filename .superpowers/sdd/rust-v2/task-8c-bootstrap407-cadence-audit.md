# Run407: Bootstrap driver cadence and original window audit

2026-10-29. Independent read-only causal-perspective investigation of the frozen
Bootstrap driver and original clock placement. Only this report was written.
No source/test/controller edit, Git operation, build/test, helper main, VM,
profile/credential/resource access, privileged/native action or subagent was
performed. The concurrent owner-inner diagnostic implementation in
supervision.rs/lab_cost.rs is outside this audit; it was neither implemented nor
reviewed here. Current lab_cost WIP is not used as run407 evidence.

Run407 establishes a real failure in the HOST native-poll Reading state after
both held-writer sequences completed. It does not establish a driver/test-clock
defect, actual sleep overshoot, CPU cost or a performance correction. The useful
alternate perspective is that the lab's typed hold/checkpoint/identity/negative/
release work itself executes inside the original shared query/policy window,
while some initial constructor work is outside all outer wrapper timers.

## Exact evidence binding

The raw record `target/lab-state/actual-program-run-407.json` independently
hashes to
`4c16ab618e83a95bc56121e850494c2efde15c6711eedcaeffc9212bffe6e922`.
The closed record
`target/task8c-digest-hex-root-20261029/bootstrap407-closed-metadata.json`
hashes to
`2a61b8c7774c5461c99ac2ed51d73a1200e2492da5bfd283a8ff90d5a33a32ff`.
Their source-binding objects agree; all 13 outer wrapper rows independently
parsed from raw stderr exactly match the closed table.

Both bind source commit `51c15016353936288067f5cd3e4c2a6715be1061`, 203 verified
tracked build inputs, aggregate
`d9fe3200b57f73d8cf5c6e847277dbf463c5ab672559f208383c49f81de12167`,
and source archive
`f5cecc2f3af90a7e638f9bfdcb1d2db3a70abb7666d678b2133fe88601d9aa7c`.
Independently hashed retained `target/continuation-20261029T174000Z/source.tar`:
it has exactly that archive hash. The raw artifact hash is
`fe3567ab22819b05ecf0523ddcfb6dd14fea8869d6b6a6e7f77b9804b2a926d3`;
this audit did not rebuild or inspect that artifact.

The following source members were read and hashed in the retained archive. Each
is byte-identical to its current worktree counterpart, so references below use
those current line numbers. Paths are relative to crates/vprouter-launch/src
except the explicit core path.

| Path | Frozen SHA256 |
| --- | --- |
| attachment/operational/bootstrap.rs | da65fe12514a8f668f10d83cb4a668d9d59f0dd6faa26edf6487d9edab6f9d22 |
| attachment.rs | 785606fd8659e6b1bf1ad276f856ab98ad23fcffb6546f883879314ec1522aef |
| attachment/quarantine.rs | e1d8748e45f091cbd731d031d48ad55d0852fc77c9439c6f4fef17f5fb5c6705 |
| attachment/operational.rs | 1dadf82010a122c8dac4a25dec1bec05f55bacc0f51ba7f0d66ed56204aabe65 |
| attachment/operational/producer.rs | 345b9ebef44114bc6a6d5e4c1664136532839e07a8055eeda1f0ea367db699b2 |
| owned/preparation.rs | 4ad1d063d86907e14ce8a2067f7c2baf231b0bfa6850d332c1b18bf1f1321369 |
| owned/preparation/bootstrap.rs | 0602f7630e895bee5f6834371ee4323025837363e439a4d7e97979918eaa0a53 |
| kernel/docker_query.rs | 88d1529f67d72ab96ac8ab8051994381fc08df2b906764fc874b0b60ba775237 |
| kernel/bootstrap.rs | a35735c97bb6333d229dbefccc5eb7e0cb05781e019c68eaa0e01d1b3a18a945 |
| crates/vprouter-core/src/health.rs | 36de1fed33a0c8bcb70a4074a8f4ec82fba97ef06e9e538e2e4d2e9b04435dfa |

Frozen owned/preparation/lab_cost.rs SHA256 is
`a7e5d4f832559d66d7cc6fa4193b2c82d051b4629850c0021ef47e5999601f68`.
Only its frozen family/token/timer behavior is used below. Its current worktree
counterpart is changing for the separately owned diagnostic increment.

## Clock and call placement

`lab_run` first completes `super::lab_handoff(fault)` (bootstrap.rs:640).
The nested measurement session arms as Family::Other at :663-665, then
PendingBootstrap::new executes at :692 before the first measured outer wrapper.
The complete/context work at :508-513 and the first require_complete/context
inside InspectionRequest::for_bootstrap (quarantine.rs:284-285) precede the new
HOST query clock. Their duration must not be charged wholly to that new window.

The original clock starts in owned_policy_query at quarantine.rs:293, using
InspectionRequest::start_clock (attachment.rs:916-926). It is an actual boot-time
observation after existing admission/single-thread checks, not a lab mock clock.
After that start, binding verification, original process revalidation, staging
serialization/deserialization, digest creation, retained request construction and
final service/deadline checks (:294-331) consume the same original window.
PendingBootstrap then retains its bundle, obtains its service and starts the
original inspection (:523-563). These post-clock constructor/queue portions are
also inside the window but outside the outer measured! intervals.

The deadline remains requested_at+2 (attachment.rs:988-1000). Native::advance
checks it before step work and at return (bootstrap.rs:352,:500). QueryResult
acceptance constructs the policy Request and queues policy Intent in the same
native poll (:420-439). Request::new starts Pins from the accepted query's
original requested_at (:76); Request::requested_at/deadline simply return the
accepted query's times (:221-225). Thus policy Intent/Birth/Reading/Result do not
receive another two-second window. Step::Next creates a new scope-specific query
only after completion of the prior scope (:322-350); run407 did not reach that
transition for HOST. No clock renewal, independent lab clock, or demonstrated
clock-origin defect was found in this path.

At the top of each loop, the diagnostic family is selected from the entry Step
(:709-719). It is an attribution label, not a clock. A native poll may change
Step internally: the QueryResult poll performs policy Request construction while
still labelled Query; a Next poll may perform new-query work while labelled
Other. Family rows therefore cannot be read as exact semantic phase boundaries.
For run407, initial Other rows include constructor work both before and after
the original start. Their inclusive nested durations cannot quantify the active
constructor gap, be summed together, or be added to the outer wrapper total.

## Held cadence and sleeps actually established

The fixed driver runs its hold/checkpoint/negative/identity/release helpers
before each main native poll. Those helpers begin with original typed query or
policy progress validation (operational.rs:324-426). Their elapsed totals are
real wrapper work in the active window, including nested production checks,
lab oracles, IO and scheduling. They are not pure waiting for the lab checkpoint.

Run407 recorded four query checkpoints and three query identities/negative
wrappers. With the unchanged successful control flow this means one false
checkpoint and three true checkpoints. At the first and second true checkpoint,
query_held advances to 1 then 2 and the still-held writer is polled; at the third,
identity/negatives run again and release occurs (bootstrap.rs:734-781).
The three two-check negative rounds yield 6. Policy likewise has four checkpoints,
three identity calls, two held polls, then release (:784-829). Its queued oracle
has 4 checks; the first-held oracle has 4 plus the 4 pending-history/context
refusals, yielding 12 (operational.rs:376-394 and preparation/bootstrap.rs:803-831).
The captured held/release counters are therefore consistent with the original
cadence: query 2/6/released and policy 2/12/released. They are neither weakened nor
proof of completed HOST policy result acceptance.

Every Ok(None) native poll is followed by an unconditional requested 1 ms sleep
(:852-859), even if that poll made internal progress. Eighteen native polls end
in an error, with no earlier success/return; the first 17 consequently returned
Ok(None) and each reached one sleep. This establishes 17 sleep calls and 17 ms
of nominal requested duration, not 17 ms of measured elapsed sleeping. It includes
the two held-query and two held-policy polls, and also ordinary transition or
waiting polls. The final error is not followed by that sleep. The separate
post-error collection sleep at :922 is fault-gated and is not reached by this
unarmed success-mode Deadline path.

## Run407 arithmetic and causal limits

Raw407 is FAIL/exit1, zero completed case witnesses, outer runner wall 19.377 s.
Its single boundary and existing native-poll failure markers agree on
native_poll/reading/Deadline; the later fixed scope label is HOST. Original
request 204882.642003901, deadline 204884.642003901, and post-failure observation
204884.651831267 imply 2.009827366 s request-to-observation and 9.827366 ms past
the deadline at that observation. This is not the exact failed-predicate time.

| Sequential outer intervals | Calls | Elapsed ms |
| --- | ---: | ---: |
| Query helpers combined |13|354.023115|
| Policy helpers combined |11|442.623541|
| Native polls |18|1160.007688|
| All outer wrappers |42|1956.654344|

Checkpoints across both families total 326.974139 ms; identity wrappers total
168.861258 ms; query-held plus policy-queued/held negative wrapper labels total
129.099390 ms. These selected rows are subsets of the table, not additional
costs. The wrappers are sequential nonoverlapping outer intervals, unlike the
nested/retained rows. The outer helper contribution 796.646656 ms is evidence
that cadence validation occupies a substantial part of the original window;
it does not establish removable overhead or an equivalent production-only run.

Subtracting the outer total from request-to-observation yields 53.173022 ms of
unaccounted arithmetic difference. With comparable unsuspended clocks, this
contains actual sleep elapsed, post-clock initial constructor/queue work,
loop/counter/family/anchor work outside brackets, and final bookkeeping before
the observation. It is not a measured sleep total, scheduler-latency value,
constructor duration or CPU residual. Instant excludes suspend; the enforcement
BOOTTIME includes it (core health.rs:184-189), so exact interval reconciliation
also needs that clock distinction. Subtracting nominal 17 ms does not turn the
remaining 36.173022 ms into a measured category.

Likewise the 19.377 s runner wall includes the earlier fixture/handoff and
orchestration; it is not the HOST two-second window. Existing phase log records
show order, not phase timestamps. Diagnostic timers and logs themselves consume
time, with some logs inside native wrappers and constructor logs outside; no
control measurement quantifies that perturbation. No CPU samples or scheduler
observations were captured by these metrics. Owner-record parsing versus native
owner validation share remains unmeasured in run407. None of these totals proves
a CPU bottleneck, scheduler starvation, child IO stall, exact nested predicate,
causal optimization saving or budget fit.

## Narrow next proposal, not implemented

Retain the existing held counts, negative rounds, call order, sleep placement and
original clock/deadline. No driver semantic correction is justified by407 alone.
Complete the separately owned owner-inner diagnostic first; this report proposes
no duplicate inner instrumentation or formatting optimization.

If CPU versus off-CPU time remains unresolved afterwards, a separately reviewed
cfg(test) driver-only measurement could add fixed aggregate parent-thread CPU
samples around the existing outer wrappers, actual elapsed sampling around the
existing 17-or-more sleep calls, and a single original-request-to-first-wrapper
observation after construction. Emit one bounded table on the original error;
keep optional sampling failure diagnostic-only and preserve that Error. These
observations must add no validation, retry, delay, request window or authority.
Sampling belongs at the unrestricted lab-driver boundary, never inside restricted
journal-child/hash/native callbacks; validate the additional clock syscall and
measurement overhead before any Root-owned native invocation.

Thread CPU deltas could separate time spent executing this parent thread from
elapsed intervals, but wall-minus-thread-CPU still combines scheduling, blocking
IO and child progress, and omits other processes' CPU. Attribution specifically
to scheduling would require contemporaneous, scope-bound scheduler/run-queue
observations in a later Root-owned measurement; whole-VM post-run counters are
insufficient. A first-wrapper original-clock observation would bound active
constructor time without charging all Other rows to it. Actual sleep sampling
would test overshoot without altering temporal held coverage. These are evidence
proposals only, not permission to extend deadlines, cache proofs, remove checks,
weaken held tests, change controllers, or claim future budget fit.

Run407 and all failure evidence remain retained. Production, identities,
credentials, repair state and resource gates are unchanged. Full8c remains
ACTIVE; subsequent native work and all acceptance decisions remain Root-owned.
