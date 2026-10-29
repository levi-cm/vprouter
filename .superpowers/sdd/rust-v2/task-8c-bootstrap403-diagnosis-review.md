# Run403 diagnosis: independent source/count/evidence review

2026-10-29. Narrow read-only review requested by Root. Only this review written.
No source edit,tests/builds,helper main,VM/SSH/Docker/privileged action,resource
operation,Git mutation or subagent work. No optimization approval.

**SPEC PASS. QUALITY PASS. EVIDENCE PASS within the stated diagnostic scope.**
No findings. No Bootstrap/native-family/runtime/client/release gate is promoted.
Full8c remains ACTIVE; run403 remains FAIL/zero completed cases.

## Exact reviewed artifacts

| Artifact | SHA256 |
| --- | --- |
| task-8c-bootstrap403-diagnosis.md | 88e085660892f310f96bb60ab02cc13044580805a0361a258863fd2f53865ed8 |
| task-8c-bootstrap-nested-cost-brief.md | 6783fdd07dbb5275eb85eaed0fca64c260a5490ed63901f2f27576a88649a7ad |
| task-8c-report.md | a83361d571608832d4572f6de38d71a5d16b8565b748d0ce28f1f2ad7bb2db9d |
| progress.md | f9d38fcf53b8f86cbc633ecaf86e76c583b60420c130551d5dd0879aae6489e9 |

Paths above are under .superpowers/sdd/rust-v2. Diagnosis author confirmed the
final addendum was frozen before nested-cost source work. This review binds the
unchanged run403 candidate source,not future instrumentation. At source/count
inspection,all202 frozen root-proof hashes equalled archive and current bytes.
The diagnosis's raw/source/archive/aggregate/artifact/directory-binding/summary/
inspection/bootstrap.rs hashes independently agree with saved evidence,including
raw8e63c001,summaryc8c3a32b,inspection80ad66bd and source88320812.

## Failure and interval evidence

The diagnosis accurately reports FAIL/exit1/13.92s,zero case witnesses,320 stderr
lines and91 exact inventory/verified pairs. NativePoll/intent/Deadline,accepted
query/policy presence,query held2/negative6/released and policy held2/negative12/
not released match exact raw first-error fields. Existing poll/failure diagnostics
confirm Host scope with the original requested_at/deadline and no renewed window.

PendingBootstrap::poll latches and collects the original advance error before
returning it. Cached retained counters do not show an instantaneous post-error
child/ACK trace. The diagnosis correctly distinguishes retained Docker-query
child slot from an actual policy child. Canonical birth/facts/verified_at are
durable observations;they are not alone proof of parent ACK/cleared pending/
accepted receipt. Writer indices87/88/89/90 are qualified source/counter inference,
not a newly captured pending journal. Exact inner deadline predicate remains open;
run403 does not identify run402's missing outer-helper boundary.

All13 ordered wrapper counts and durations equal raw403. Query wrappers sum
722550398ns,policy wrappers313548371ns,native polls923556681ns,total1959655450ns.
97.9827725% is the correct ratio of that sum to2s. First boundary observation
minus original request minus the sum is47.718916ms. The diagnosis correctly
qualifies this subtraction as separate monotonic observations,not exact phase
accounting or attribution of the remainder. Canonical query observation interval
1.307298476s and remainder0.692701524s are arithmetically correct;the remainder
still includes later query acceptance and policy work.

Disjointness is supported by frozen source:the measured macro is local to the
outer synchronous lab_run loop. Each outer helper or NativePoll expression
finishes and records its duration before the next measured expression begins;
NativePoll does not recursively invoke that local macro. Query outer wrappers
occur while QueryIntent precedes spawn;policy outer wrappers follow accepted
query/Request construction. Their sum is valid top-level elapsed accounting,
including nested work/IO/scheduling,not CPU attribution. The failed native poll
includes its latch/collection;later diagnostic/collection work is excluded.

## Exactly four expected encodings; sixteen positive calls lower bound

A successful full typed Intent verify_bootstrap_progress reaches
Native::verify_owned_progress exactly four times through these closed paths:

1. Initial typed expected-record verification in preparation/bootstrap.rs.
2. Request::verify_write -> OriginalWrite::require_bootstrap -> verify_origin.
3. Direct Source::verify_acknowledged_write -> producer Receipt::verify_write
   -> OriginalWrite::verify_origin.
4. Pins::verify_write -> its original Source receipt -> verify_origin.

Each reaches exactly one encode_record(expected). No Result-stage Verified proof
is selected for Intent. These four calls are existing live proof checks and
cannot be replaced by a cached successful verdict. The addendum's exact source
spans agree with the frozen candidate. OriginalWrite retains the immutable Record
inside this synchronous proof while every origin use rechecks current state.

The successful outer policy wrappers establish ten complete positive typed calls:
hold1 + checkpoints3 + identities2 + queued negatives2 + held negatives2.
Each negatives helper performs its outer positive check and one internal positive
check before its negative cases. The first native Intent poll starts the queued
writer;the second remains pending while held;the third fails after the second
held increment. Three checkpoint loop entries therefore imply two prior successful
pending native Intent polls. Each performs three typed progress calls:advance's
initial check,OperationalOwner::poll_policy_intent and Server::poll_bootstrap_intent.
That contributes six more complete positives.

Thus at least16 complete positive calls entail64 immutable expected encodings.
Failed/negative partial paths are excluded. Hypothetical same-call representation
reuse could remove48 of those64 by encoding once per call;this is a count-only
counterfactual,not measured savings or cache authorization. In the fully held
core branch,each owned-progress use encodes expected/proposal/canonical/pending:
four uses yield16 core record encodings;removing three expected repetitions is
18.75% of that restricted call count only. Queued branches and failed partial
checks are not claimed to have that same four-record count.

Native::require_creator -> Transaction::require_allocation_memory -> bind_anchor,
and Binding::verify_retained's complete preparation validation,are real repeated
source mechanisms. Their presence establishes alternatives to pure serialization
cost,not which mechanism dominates. Offline microbenchmark remains NOT_RUN;no
benchmark result/speedup/sufficient remaining budget is claimed or accepted here.

## Separate nested-cost requirements and public scope

The exact nested-cost brief receives a bounded **requirements/scope PASS** only.
It confines work to six named source paths,cfg(test)-only fixed bounded labels/
state,no normal-build statements or dependencies,and both query/policy paths.
It requires inactive-outside-lab behavior,early-error-safe timers,no borrow held
across original calls,stop-before-snapshot,at most one table and no per-poll output.
It preserves all13 wrapper rows,checks/clocks/errors/holds/negatives/child and
journal operations. Nested categories are explicitly inclusive and overlapping;
they must not be summed as disjoint walltime or CPU. No cache,optimization,
clock renewal,acceptance weakening or native action is granted by this review.
Implementation correctness and source equivalence need their separate review.

Root's current task-8c-report.md addendum explicitly corrects the earlier399
queryIntent-acknowledged overstatement:canonical bytes establish durable history;
parent ACK needs separate evidence. It retains original failures and403FAIL,
limits wrapper evidence and authorizes diagnostic preparation only. Ledger
records403 archival completion/retained resources,full8c ACTIVE/releasefalse and
requires attribution before optimization. Earlier chronology remains visible;
latest reconciliation controls current claims. Root's remote-confirmed milestone
statements retain their actor-reported scope;this auditor performed no fresh
remote publication action or live production check.

The frozen diagnosis and brief were fully read;the two older documents' new
reconciliation/ruling sections were contextually reviewed. Bounded credential
pattern checks across all four files found no embedded credentials/private
profiles. No raw runtime/private artifact is added to public scope. Final
`git diff --check` passes. Review frozen for Root staging.
