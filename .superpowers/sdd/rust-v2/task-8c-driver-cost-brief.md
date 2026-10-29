# Driver CPU, existing sleep and constructor-prefix measurement brief

2026-10-29. Proposal only, requested by Root after408. Requires independent
requirements review and explicit Root source dispatch. No implementation, tests,
CPU sampling, native run or observer-disabled control is authorized by this file.
Read task-8c-bootstrap408-diagnosis.md and binding IMPLEMENTATION.md first.

## Causal question and scope

408 remains HOST/native_poll/result/Deadline, zero completed cases, with all
required held/negative/release witnesses. New global owner rows locate current
native observations, not a removable check or parser root cause. Distinguish:

- parent-thread execution within the existing outer wrapper intervals;
- combined off-CPU time within those intervals (blocking, preemption and child
  progress cannot be separated by thread CPU alone);
- elapsed time associated with the exact existing1ms sleeps;
- the original-clock post-constructor prefix before the first outer wrapper.

This is one driver-level hypothesis test, not another owner-inner probe, optimizer,
resource remedy, renewed deadline, polling change or two-second-fit claim.

If later authorized, own only existing source
`crates/vprouter-launch/src/attachment/operational/bootstrap.rs`, specifically its
already-cfg(test) lab_run/lab_diagnostics. Frozen file SHA256
da65fe12514a8f668f10d83cb4a668d9d59f0dd6faa26edf6487d9edab6f9d22.
Do not edit normal Native/PendingBootstrap/Request code, other Rust files,
manifests/dependencies, controllers/readers, goldens, acceptance or runtime config.
Root owns any separately reviewed reader extension and all future native actions.

## Preserve semantics and existing measurement boundaries

Retain every existing call/expression, `?`, error, authoritative boot clock,
original requested_at/deadline, native custody/check order and left-to-right
short circuit. Preserve held query2/negative6 and policy2/negative12, all identities,
negative oracles, queue/release ordering and their exact live observations. No
extra validation/context lookup, cache, new FD/path, ownership adoption, eager
operand, retry, resource change or sleep removal/shortening/repositioning.
Preserve old13 wrapper/30 nested/24 retained/15 owner rows/order/schema and existing
timers/collector activity; new observers necessarily perturb elapsed values.

1. At each existing measured! invocation, sample parent-thread CPU immediately
   before the existing `let started = Instant::now()`. Preserve that Instant,
   `$call`, and original measurements.record(...) statement in their original
   order; sample CPU immediately after that record and before existing error
   handling/output. Record one pair under the existing13 helper labels. This
   intentionally brackets the original interval plus its Instant/record work;
   it is not exact call-only CPU. End clock/syscall overhead also perturbs it.
   Do not clamp CPU to wall elapsed or assert CPU <= elapsed. The new CPU table
   records no family/child CPU and performs no nested/native callback sampling.
2. Around only the exact existing success-loop Ok(None) sleep at line858, add
   elapsed Instant observations while leaving the original sleep call/duration
   untouched. Accumulate actual elapsed, requested1,000,000ns per reached call,
   and call count. Do not instrument fault-gated post-error collection sleeps,
   add a sleep, move the sleep, busy-poll, or skip sleeping after step progress.
3. Immediately before the first existing measured! invocation, before its CPU
   start, attempt one BOOTTIME observation and read only the existing retained
   query requested_at scalar (no context()/verify/deadline calls). Record their
   nonnegative difference as the post-clock request-to-first-wrapper prefix.
   Attempt exactly once; failure does not retry or delay. Constructor pre-clock
   work is excluded; initial queue/loop work after the original clock is included.
   Keep the existing constructor/queue/anchor/family placement unchanged. This
   does not add a measurement/output path for constructor errors that currently
   return before any measured! failure.

Do not add an inner timer or CPU sampling inside supervision, parsers, hash,
journal-child or restricted native callbacks. No observer-off branch or arm-mode
switch is in scope.

## Safe optional samples and storage

Use the existing rustix time feature; no new dependency or unsafe allowance.
The installed rustix1.1.4 exposes safe fallible clock_gettime_dynamic with
DynamicClockId::Known(ClockId::ThreadCPUTime), and Boottime for the first-wrapper
sample. Treat syscall failure, malformed/negative Timespec, backwards CPU pairs,
invalid/nonfinite original scalar, negative delta or unrepresentable conversion
as a diagnostic sample error only. Do not propagate such an error with `?`, panic,
log raw OS text, change the original Error, mint authority or substitute a clock
for enforcement. Validate nanoseconds and use checked conversion/delta arithmetic.
The constructor's f64 original requested_at has finite precision: document the
result as diagnostic nanoseconds with conversion/clock precision limits.

Use a separate fixed13-row CPU table and fixed sleep/prefix scalars, local to
the lab driver. Reuse helper labels; do not enlarge/refactor any existing nested/
retained/owner collector State. For each original wrapper invocation, increment
calls once, take at most one start/end CPU pair, increment samples if valid else
sample_errors once, and saturate u64 counts/u128 nanoseconds. Before saturation,
samples+sample_errors equals calls. A valid zero CPU delta remains a valid sample.
Store no raw timestamps or dynamic values in output. Failed pairs contribute no
CPU duration, and absent samples must never be described as zero CPU cost.

Save creator identity only at an unrestricted driver boundary; no per-call/timer
getpid/gettid. Do not share/move the table across threads. Fork copies are private
and never merged. Refuse export of the new table from a foreign creator using
actual creator checking only at the existing unrestricted stop/export boundary.
No new thread, process, FD, inventory entry, lock, heap table, live borrow across
measured work, signal/cleanup or resource setting. Verify clock_gettime and the
chosen clock ID are allowed on the actual parent boundary in both target ABIs;
no filter widening is permitted. In particular, a restricted publisher-child
path must never acquire these samples. Sample failure stays diagnostic-only if
the platform/syscall is unavailable; unsupported samples cannot become evidence.

## Closed output contract

At the existing first-error Measurements.failure path, stop nested/retained/owner
collection exactly as before, freeze new driver scalars, and append after all
old13+30+24+15 rows. Preserve the existing first-error emitted guard, native error
and return path. No output while collection is active, during a wrapper/sleep,
or from a child. Writer failure cannot mask the original Error or panic.

Emit exactly15 new rows, in this order:

1. Thirteen `LAB_SECRET_BOOTSTRAP_DRIVER_CPU` rows, existing helper order
   query_source,query_hold,query_checkpoint,query_identity,query_held_negatives,
   query_release,policy_hold,policy_queued_negatives,policy_checkpoint,
   policy_held_negatives,policy_identity,policy_release,native_poll. Exactly fields
   helper/calls/samples/cpu_ns/sample_errors/measurement/grouping; unsigned decimal
   u64 counts/u128 cpu_ns; measurement=bracketing_parent_thread_cpu,
   grouping=wrapper_helper. Zero/unavailable rows remain present.
2. One `LAB_SECRET_BOOTSTRAP_DRIVER_SLEEP` row. Exactly fields calls/requested_ns/
   elapsed_ns/measurement/grouping; u64 calls/u128 nanoseconds;
   measurement=existing_sleep_elapsed, grouping=driver_loop.
3. One `LAB_SECRET_BOOTSTRAP_DRIVER_CONSTRUCTOR` row. Exactly fields samples/
   elapsed_ns/sample_errors/measurement/grouping; samples and sample_errors each
   0 or1, at most one attempted sample; u128 elapsed_ns, zero when unavailable;
   measurement=original_request_to_first_wrapper, grouping=driver_once.

ASCII fixed labels, one separating space, canonical decimal and newline only.
No IDs, PID/start, absolute timestamps, paths, requests, records, keys, credentials,
exception payloads or per-call text. Proposed maximum added output is3761 bytes
including newlines; longest line266 bytes including newline (u64/u128 maxima,
constructor0/1). Independently verify the bound and emitted field order in review.
Byte bounds do not bound stderr blocking time. Reader schema support is separately
Root-owned and required before any new run; do not relax the old reader here.

## Verification and freeze required after separate source dispatch

Freeze fresh all179 Rust hashes before editing and prove one owned changed path,
178 unowned unchanged, zero new/missing Rust paths. Reconstruct the original normal
source prefix byte-for-byte; all changes remain within existing cfg(test) code.
Preserve old driver call/timer/sleep sequence and output loops by exact diff review.

Add only meaningful tests of the new collector's valid/error/backwards/missing
pairs, per-helper attribution/counts, saturation, first-prefix-attempt-only,
constructor error conversion, stopped/foreign export and writer errors. Use
literal supplied clock samples for error arithmetic; do not impose elapsed/CPU
thresholds or tests that merely mirror source. Prove original outcomes survive
optional sampling failures. A focused meaningful mutation check is appropriate
only where needed. Preserve existing tests. Run approved launch lib tests, fmt,
strict launch lib/tests Clippy with full logs, including nested admission fixtures.
No native clock/filter experiment, helper-main, workspace/coherent artifact build,
VM/SSH/Docker/privilege or Git operation belongs to the implementer.

Freeze exact diff, source hashes, 178-file proof and full check logs/report for
independent spec/quality review. Root separately owns fresh workspace/static and
coherent artifacts, runtime clock/filter/preflight evidence, original-resource/
identity preservation baseline and archive gates, reader extension, checkpoint/
remote confirmation and any single new owned local VM hypothesis experiment.
No repeated unchanged run, runtime control or experiment is authorized now.

## Interpretation and stop rules

Compare CPU with the existing all-call wall total only for a complete, unsaturated
helper row: samples=calls, sample_errors=0, and neither counts nor accumulated
CPU/wall totals at their integer maximum. Incomplete or saturated rows retain
bounded counters/durations only and are unavailable for CPU/wall attribution.
Report completeness, saturation limits and bracketing observer effects. High
parent CPU supports execution in those intervals, including kernel/observer work. Low CPU supports
combined blocking/preemption/child-progress time; it does not identify scheduler
starvation, specific child IO, guest steal or host contention. CPU excludes child
process execution. Parent CPU sampling itself can be a syscall with measurable
cost; no overhead-free or production-only claim follows.

Actual sleep elapsed versus requested duration tests a sleep-associated gap,
without altering temporal held coverage. Constructor prefix isolates previously
unbracketed active-window time. New CPU spans are not identical to original wall
spans; no exact off-CPU subtraction, exclusive CPU/wall sum or fit claim. BOOTTIME
and Instant differ under suspend. Missing samples, clock mismatch and observer
perturbation remain limitations. A low-CPU result may motivate a later scope-bound
scheduler/child observation, separately reviewed and Root-owned; it does not
permit immediate tuning or removal of live checks. High CPU likewise does not
justify an optimizer without an exact preserved-semantics mechanism.

An observer-disabled control would need its own exact normal/test/output/parser
semantics proof and causal design; it is explicitly outside this proposal and
not authorized. Keep failures398-408, production, original credentials/identities,
retry repair, original2s windows and all custody/held negatives. Full8c/ARM/client/
migration/performance/release acceptance remains open/NOT_RUN where unaccepted.
