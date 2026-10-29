# Driver-cost diagnosis and requirements review

2026-10-29. Independent read-only review; Root retains source/native dispatch.
Only this report was written. No source edit, test/build, Git, VM/SSH/Docker,
helper-main, resource/profile or production action was performed.

## Frozen inputs and scope

Read `docs/rust-v2/IMPLEMENTATION.md` first, then diagnosis and brief. Independently
verified SHA256:

- diagnosis: `ffe0996c3258f003127ec0c3cce3bc9c7ae762c47496d8f4f7f996f038ef1d4b`;
- brief: `07bd8a06fdeb74269207ee0d4b4fb162d1e99dfb1ab07b14fc6171d52f393d8e`;
- operational/bootstrap.rs: `da65fe12514a8f668f10d83cb4a668d9d59f0dd6faa26edf6487d9edab6f9d22`;
- exact raw408: `d102dbdb315bd00ab43de263f286136a13b378406c72ce178b497fa4ea1f61db`;
- closed408: `2bdb9551e9950564c2c565aa78b62f6c64b4e4af347e3ab340a9f92a45d13208`.

This reviews the bounded driver experiment, not whole-branch acceptance or a
duplicate candidate/preservation audit. The diagnosis explicitly binds an earlier
public-record read; subsequent archival PASS does not change the native FAIL.

## Verdicts

- Diagnosis accuracy: PASS. Exact raw/closed408 retain zero cases, HOST,
  native_poll/result/Deadline, original requested_at+2s, query held2/negatives6/
  released and policy held2/negatives12/released. Closed wrapper total is
  1,969,851,274ns. The 24.803688ms boundary lateness is a later observation,
  not the failed predicate or a sufficient counterfactual saving.
- Hypothesis/evidence: PASS. Result is assigned after verified child output and
  start_bootstrap_source, before durable result acceptance. The trailing original
  deadline can still fail in that advance. Owner elapsed rows do not identify
  removable checks, pure parsing cost, exclusive CPU or scheduler starvation.
  Eighteen reached success-loop sleeps follow nineteen failing-prefix native
  polls; nominal requests do not measure their actual duration.
- Specification requirements: PASS WITH F1 below. Safe optional observations,
  fixed storage, first-error output and narrow ownership are implementable.
- Task-plan quality: PASS WITH F1. Proposed meaningful arithmetic, failure,
  saturation, creator/export and writer checks cover material new behavior;
  preservation review and existing checks remain necessary after implementation.
- Sensitivity: PASS. Fixed labels and unsigned aggregate values disclose no
  identity, path, timestamp, credential or request. Error text is not emitted.
  Existing old rows remain untouched; this is not a review of their prior schema.
- Source dispatch readiness: READY ONLY WHEN Root binds F1 in the source dispatch
  or revised brief. No new experiment or resource action is authorized here.

## F1: incomplete pairs cannot be matched to the old wall total

Medium, interpretation requirement. The CPU table sums only valid pairs while
the unchanged old wall table sums every call. If a helper has a failed CPU pair,
its CPU sum cannot be compared to that helper's all-call wall sum as a matched
execution/off-CPU observation. A failed expensive call could falsely suggest low
parent CPU even with sample completeness disclosed.

Require CPU-versus-wall attribution only for a helper whose samples==calls,
sample_errors==0 and whose relevant counts/durations are unsaturated. Otherwise
report CPU coverage and valid CPU subtotal only; classify that helper's CPU/wall
attribution as unavailable. Do not extrapolate, fill missing CPU with zero or
derive a ratio/off-CPU residual. No new output field, extra sample or matched-wall
collector is needed for this restriction. Even complete rows have different CPU
and wall brackets and permit only the qualified interpretation already stated.

## Implementability and boundary checks

The existing macro permits CPU start before its original Instant and CPU end
after its unchanged record call, before first-error handling. A separate fixed
array and local scalars can avoid collector-state changes and borrows across
native work. Instrument only the existing Ok(None) sleep; fault-gated collection
sleeps remain untouched. First-prefix sampling can read n.query.requested_at()
immediately before the first QuerySource wrapper without context/revalidation or
an eager native operand. Fault4/5 or pre-wrapper constructor errors need no new
output path. Preserve constructor, anchor, loop-family and all short-circuit order.

Workspace rustix1.1.4 already enables time. Installed sources expose safe fallible
clock_gettime_dynamic(DynamicClockId::Known(ClockId::ThreadCPUTime)) and
DynamicClockId::Boottime. Unlike the infallible clock_gettime path, dynamic errors
return Result. Use checked Timespec/u128 arithmetic and explicitly reject invalid
f64 conversion/range, negative/nonfinite values and backwards deltas; Rust float
casts alone silently saturate and do not satisfy that requirement. Samples grant
no enforcement authority. BOOTTIME/Instant suspend differences and original f64
precision prevent exact reconciliation.

Keep the driver state non-Send/non-Sync (for example the existing Rc marker
pattern), save creator PID only at the unrestricted boundary and check actual PID
again only at export. That combination prevents ordinary thread transfer and
foreign fork export without introducing getpid/gettid in samples. Native child
callbacks never reenter the driver macro: fork copies remain private and no child
totals are merged. PID-only checking without the thread-locality restriction would
not establish parent-thread attribution.

Runtime syscall availability remains a Root preflight gate on both target ABIs.
A fallible API cannot turn seccomp KILL/TRAP into a diagnostic Result; unsupported
samples are optional only where the actual boundary permits a recoverable clock
attempt. Do not infer filter compatibility merely from a vDSO success, and never
widen filters. No runtime clock/filter check was performed by this review.

Independent ASCII maximum-length calculation confirms 15 added lines, 3761 bytes
including newlines and maximum 266-byte line (policy_queued_negatives). It uses
u64=20 and u128=39 decimal digits, constructor 0/1 fields, the exact proposed field
order and fixed helper order. No output-time bound follows from a byte bound.
Freeze/export after the existing collector stop; best-effort writes must retain
the native error. Reader extension and coherent/native verification remain Root
work before any new local VM hypothesis run.

No other blocking requirement finding. Preserve original2s windows, all custody,
held negatives, failure propagation, production credentials/identities and local
retry repair. No observer-off run, pure optimizer, new resource setting or deadline
remedy follows. Full8c/ARM/client/migration/performance/release remain unaccepted
or NOT_RUN as applicable.

## Scoped re-review: F1/M1 addressed; optional reader proposal

2026-10-29. Revised driver brief SHA256
`d7e6584e4f6f25943773b489131a3640ffe1a01900eb0d74c4b661546bba25e6`.
Replacing only its first Interpretation paragraph with the original paragraph
reconstructs the initial brief SHA256
`07bd8a06fdeb74269207ee0d4b4fb162d1e99dfb1ab07b14fc6171d52f393d8e`.
Thus the exact delta is the reported paragraph replacement, with no schema,
probe, source or other brief change. It now restricts comparison to complete
unsaturated helpers, requires samples=calls and sample_errors=0, excludes counts
and accumulated CPU/wall totals at their integer maxima, and makes incomplete
or saturated attribution unavailable. F1 (Root's M1): ADDRESSED. Driver source
requirements/readiness: PASS/READY for separate Root source dispatch. All prior
preservation and runtime-preflight requirements remain binding.

Read proposed reader brief SHA256
`a9bb80820ac625394b9e48a10fcfbd991b80e406d277946ab97f40a795612329`
and the existing parser, without executing it. Reader requirements/readiness:
PASS/READY for separate Root reader dispatch. The exact fifteen-row all-or-none
extension, strict occurrence/field/order recognition, u64/u128 bounds, saturating
CPU completeness, cross-wrapper call equality, unavailable-duration rules and
constructor sum<=1 are coherent with the writer proposal. The sleep requested
relation correctly distinguishes unsaturated and saturated u64 call counts.
No CPU<=wall, sleep threshold or off-CPU arithmetic is required or permitted.

The existing parser supports append-only optional keys after old output keys;
extension absence can preserve historical output byte-for-byte. New matching
must reject malformed/foreign driver marker occurrences rather than letting them
appear absent, and enforce the approved extension's placement after the old rows
as well as its internal order. The brief incorporates the exact writer contract;
this is an implementation acceptance point, not a new schema requirement.
Fixed driver_scope text must retain the corrected complete/unsaturated-only
interpretation and bracketing/child/clock/observer limitations. No dynamic raw
clock, identity or error payload belongs in output. Existing failed-run admission,
exclusive destination preservation and private0600 output requirements remain.

Proposed valid/error/malformed/saturation/compatibility checks exercise meaningful
parser boundaries. Frozen build-input preservation, old405/407/408 byte equality,
destination bytes/mode preservation and independent implementation review remain
required before native use. No additional blocking finding; no implementation,
test, runtime or acceptance claim is made by this scoped re-review.

Publication-scope sensitivity: PASS for exactly the diagnosis, revised driver
brief, reader brief, this review and the progress.md append. Reviewed ledger tail
SHA256 `1243b488104204dbe242639998f5697d5d8d1fe01f179d2b24e947ff2c160e02`;
stripping the new paragraph and its separating blank line reconstructs prior
SHA256 `036fe2f21b377a1c6fbb168bdcd0314d6068fd44d110c0720b2c1faaf60a51f7`.
its conditional dispatch/push and pending-review wording is accurate at that
snapshot. Root may append the final scoped PASS and completion state after this
review; that future append is not covered by this hash. These five documents use
bounded diagnostic facts, source/evidence hashes and local artifact references;
they contain no credential, profile contents, raw private evidence or native
authorization beyond the stated Root gates. Exclude all target data and unrelated
dirty files from publication. No full historical-ledger sensitivity re-audit or
Git/publication action was performed here.

## Final immutable publication audit

2026-10-29. PASS/no findings. Current progress.md SHA256
`594fcfdc421565fe0d5213e6f94731f6e78fb9003a959c4b281f3249f1ae80f0`
preserves the exact prior1243b488 prefix and appends only the factual scoped-PASS
completion paragraph. Its reference to reviewf19571fb names the immediately prior
review freeze; this appended audit does not invalidate that historical reference.
The paragraph correctly records M1 addressed, reader/source readiness after the
checkpoint push, and preserved FAIL/release gates without widening authorization.
Its fresh203 input check is Root-reported; this narrowly scoped audit did not
repeat the application-input audit. Diagnosis ffe0996c, driver brief d7e6584e and
reader brief a9bb8082 remain byte-identical to the reviewed versions. Final
five-document scope and sensitivity PASS; all target data and unrelated changes
remain excluded. Only this review append was written; no implementation, test,
Git, resource or native operation occurred.
