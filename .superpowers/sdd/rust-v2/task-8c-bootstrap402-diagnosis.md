# Run402: Deadline escapes the held-policy lab orchestration

2026-10-29. Read-only source/evidence diagnosis requested by Root. Only this
report was written. No Rust edit, test/build, VM/SSH/Docker/privileged action,
Git mutation, retry, cleanup or subagent was performed. Source remains frozen.

The capture localizes the missing diagnostic to an outer lab orchestration error
path, strongly consistent with the first held policy Intent. The helpers invoke
the original production deadline checks; they have no independent lab clock.
No exact failing helper, predicate, current error time or operation cost was
captured. No deadline or enforcement change is justified by this evidence.

## Captured evidence

Raw record `target/lab-state/actual-program-run-402.json`, SHA256
`21cbaeefd26ce18bf4474066fb49ece9556b1d796d196fd1028ff3c626da5269`,
binds source `ab20f1d7ce5f366da327c7b0193a489810cb67a8`, archive
`7e284b0dbd88a935cc55cee9a0328588541c15647b6e8ffe855fae7b5a542ffb`,
202 verified build inputs, aggregate
`e7bf990e30d3c36c3cfd3f25eb110692f62a6c4b5d1b3bc9ef08e2dc9c62c6f3`,
artifact
`82e0e3b644794540798a9a050dc404b5d7aad8627a2f17320e42fb4357703199`.
Directory binding is
`target/continuation-20261029T141400Z/bootstrap-ancestry-20261029/directory-binding.json`.
Root's checkpoint at this investigation's start was
`fdf1d894556221977b6b382e6a3ec999cfa96e3b`.

Run402 is FAIL, exit1, zero completed case witnesses, success-mode component run,
outer wall17.65s. Its complete captured stderr has304 lines,91 journal inventory
and verified pairs, and **zero** `POLL_FAILURE` markers anywhere. The final
sequence contains query Intent success, query spawn success, Birth queue success,
then three journal inventory pairs and:

```text
secret_bootstrap_lab: deadline
```

There is no completed Bootstrap witness or captured policy constructor marker.
The fixed source writer sequence has87 writers before Bootstrap, query
Intent/Birth/Result at indices87/88/89, and first policy Intent at90. Accordingly
the91st inventory pair strongly indicates that first policy Intent writer was
being constructed after query acceptance and policy Request construction. This
is a source/counter inference, not an independently logged writer90 phase/ACK or
exact failing helper trace. There is no identical retry.

Root's retained public snapshot
`target/lab-state/secret-bootstrap-failure-run-402.json`, SHA256
`6a9725ab70be368518d7f8f0a4eb734bd76471c40dc638dc7469d0de277ad681`,
binds the same raw record. It has first HOST query Birth/facts/verification,
later query slots null, and no canonical Bootstrap policy history. Its fixed
canonical collection contains allocations.json/namespaces.json only; no
`.owner-journal.pending` contents were read. The absence of policy history is
consistent with a first policy Intent writer held before fsync/rename. It does
not independently prove whether that child reached the checkpoint, was released,
nor whether the parent accepted any particular writer ACK.

The original inert gateway remains retained/running. Owner-unit absence at the
later read-only inspection is post-failure state, not proof of a causal service
or cgroup loss. Root reports all six selectors archived and all other fixture
resources retained. This implementer performed no guest inspection itself.

## Exact window and observed timing limits

First HOST query public times are:

| Event | Original boot time |
| --- | --- |
| requested |192447.082556088|
| deadline |192449.082556088|
| original query child born |192448.167185036|
| query Verified observation |192448.377320811|

Thus query birth is1.084628948s after request, and query verification is
1.294764723s after request, leaving0.705235277s of the original window at that
observation. That remainder still must cover Result journal acceptance, Request
construction, first policy writer/progress and all remaining same-scope work.
These are differences of retained original observations, not attribution of
elapsed cost to an individual operation or to the new ancestry checks.

`Request::requested_at/deadline` (`operational/bootstrap.rs:221-225`) return the
same accepted query's original times. Pins are started from that same request
time; policy continuations and writer IO also retain it. The policy has no new
two-second window. Whole-VM environment sampling starts after the operation at
192449.102457476, about19.901ms after the query end. That sample explicitly has
`sampled_during_native_operation=false` and `whole_vm_only=true`; it is not the
error clock, an owner return witness or a per-phase performance measurement.

## Why the existing poll diagnostic is absent

`lab_run` (`operational/bootstrap.rs:671-765`) calls the query and policy hold,
checkpoint, negatives, identity and release helpers using `?` directly in the
outer function. Only `PendingBootstrap::poll` errors become `break Err(error)`
at line763. The `POLL_FAILURE` diagnostic lives in the subsequent `match outcome`
error branch (`:773-806`). An error in an earlier helper therefore returns from
lab_run before that handler is entered.

`PendingBootstrap::poll` itself catches every `Native::advance` error, latches it,
collects and returns it (`:566-584`); a normal production error returned through
that call would reach the existing diagnostic. The missing marker therefore
distinguishes the reporting path, not the class of clock being enforced.
An error from an outer helper still propagates real production validation. The
later Drop retention path calls `fail(Interrupted)` when no prior Bootstrap
failure was latched; the outer returned Deadline is currently not accompanied
by a captured Bootstrap failure latch. This is another reason to preserve the
original returned error in the next diagnostic, without inferring its exact
retained error state from the final text alone.

## Deadline sites by path

The literal/direct deadline predicates relevant to this phase are:

- `InspectionRequest::check_deadline` (`attachment.rs:987-994`): current boot
  time must be finite, no earlier than original requested_at, and strictly before
  original requested_at+2. `Accepted::require` delegates to it
  (`kernel/docker_query.rs:306-310`). Bootstrap Request::check calls that Accepted
  check (`operational/bootstrap.rs:128-141`), including checks at the start and
  end of progress-specific Request verification.
- `owned::original_frame` (`owned.rs:2087-2097`): finite current/original times,
  original start nonnegative, current no earlier than start and strictly before
  start+2. `Native::verify_owned_progress` calls it before checking the proposal
  (`preparation/quarantine.rs:1064-1065`); pending branch `PendingWriter::verify`
  calls the same function (`preparation.rs:419`). OriginalWrite proof use repeats
  that exact original progress check. These are the same window, not new clocks.
- `Pins::check` (`operational/producer.rs:87-99`) applies the same finite/nonnegative
  original-start/current ordering and start+2 end during fresh pin acquisition,
  identities/selection and ordinary current verification. Retained/write-specific
  Pins checks alone do not create a fresh window.
- The production preparation writer's `advance` uses original_frame at entry,
  rejects a failed writer or now>=its original job deadline, then checks the same
  frame again after actual reap/ACK (`preparation.rs:1067ff,1254-1263`). Policy
  queue/release gate validation also retains original requested_at/end.

The stored times are finite and ordered; nothing in the capture suggests a NaN,
negative time or clock reversal. Actual expiry is the strongest explanation,
but the exact evaluated predicate/time was not recorded.

### Lab calls before the native poll

Every closed query/policy helper first invokes typed progress. For policy this
is `Binding::verify_bootstrap_progress` (`preparation/bootstrap.rs:657-754`),
which checks Request::check, exact original proposal/continuation, OriginalWrite
and retained Request/Pins/Source, then Request::check again. Those calls can
propagate the deadline predicates above **before** accessing the bare lab hook.

At the first policy hold, these outer calls can return Deadline directly:

| Outer helper in lab_run | Relevant production validation |
| --- | --- |
| hold policy Intent, line716 | typed original queued Intent progress |
| queued negatives, line717 | initial positive typed progress, then negative oracle |
| policy checkpoint, line720 | typed original queued/held Intent progress |
| first held negatives, line722 | initial positive typed progress, then negative oracle |
| policy writer identity, line726 | typed original held Intent progress |
| policy release, line729 | typed original held Intent progress |

Given the91st writer inference, hold and queued-negative setup had to precede
that writer. The remaining likely error locations after its creation are the
checkpoint wrapper, first held-negatives positive verification, identity wrapper,
or release wrapper. `own_held` and the exact helper are not recorded on failure.

The bare Server checkpoint (`preparation.rs:1380-1386`), JournalChild waiting/
release (`kernel.rs:2034-2054`), pending writer identity (`preparation.rs:1396-1412`)
and hold/release bookkeeping (`:1845-1880`) introduce no Deadline predicate.
`owner_admission_permitted` reports Interrupted on stop request, not Deadline.
The deadline is therefore in the surrounding shared typed validation or a
propagated original retained check, not a separate checkpoint timeout.

The negative oracle's initial positive call propagates Deadline directly.
Its later expected-refusal branches require specifically OwnershipMismatch
(`preparation/bootstrap.rs:806-827`): if a malformed phase/start/proposal attempt
instead returns Deadline, the oracle returns OwnershipMismatch. Likewise strict
historical-read mismatch assertions map unexpected error classes to
OwnershipMismatch. Those expected-negative mismatch branches do not explain the
final bare Deadline; the initial positive checks remain candidates.

First-query helper errors have the same bypass pattern, but progress beyond that
query's Birth/Result and to the91st writer strongly places this failure later.
The DATA result hold/injected-fault and bounded failure-collection Deadline branch
are guarded by other fault modes and are unavailable in run402's success mode.
Post-completion evidence/oracle reads require the completed three-scope chain
(105 writers); they do not fit the fixed91-writer prefix.

### Production query/new first-policy work

Deadline can also arise inside Native::advance: query checks, Result receipt and
Accepted checks, Pins/Request construction, policy Intent queue/progress/writer
ACK, policy child construction/release/read, and final current Request/query
checks. Every such error returned by PendingBootstrap::poll would reach the
existing POLL_FAILURE marker. Pins/Request construction failures would leave
the step at QueryResult; policy work would use Intent/Birth/Reading/Result as
appropriate. Those markers are absent in402.

The new ancestry implementation itself performs identity/trust/named-edge
comparisons; it contains no new deadline or renewal. Its additional original
process revalidation remains as before. The supplied evidence does not quantify
its runtime cost. Low-level netfilter/native-role timeout errors also have their
existing NetworkOperation/DescriptorPolicy mappings in kernel/bootstrap.rs;
the outer bare Deadline does not by itself prove a confined child timed out.

## Smallest next increment proposal, not implemented

Add a **cfg(test) diagnostic only** at the existing outer helper error boundaries.
Use fixed labels for query hold/checkpoint/identity/release and policy hold,
queued-negatives/checkpoint/held-negatives/identity/release, plus the existing
native poll boundary. On an actual error emit once:

- fixed helper label, current fixed Step label and original Error class;
- cached query/policy presence and own/query held/released/queued counters;
- original requested_at/deadline and one current boot-time observation.

Use only already retained scalar getters/counters. Do not call Context, Source,
Request verification, a writer getter or any other fallible method to construct
the failure log. Preserve the original Error exactly and retain existing error,
drop, collection and resource ownership behavior. Existing native-poll error
logging can remain; the new helper diagnostic must not relabel a helper failure
as a proved native-poll failure. No per-pending-poll output is needed.

Optionally accumulate bounded cfg(test) call counts and elapsed boot-time totals
for the wrappers, emitting those totals only once on error. Measurements should
bracket the actual calls without renewing a clock, adding a retry or changing
which validations run. They would distinguish repeated validation cost from
scheduling/IO delay; current whole-VM samples cannot do so.

This next increment should change no clock/deadline, test coverage requirement,
enforcement check, typed ownership proof or held-writer count. It should not
silently disable the held-query/policy regression, add a new request window or
permit work after expiry. After an exact helper/timing witness, any performance
or orchestration correction needs a separately reviewed concrete mechanism; none
is selected by this diagnosis. Root owns its new coherent source/artifact binding
and any subsequent native attempt. No identical retry is proposed.

All original402 failure evidence and resources remain preserved. Native full
Bootstrap, full8c, recovery/runtime/client and release gates remain open.
