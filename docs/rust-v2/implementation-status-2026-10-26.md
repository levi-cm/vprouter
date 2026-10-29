# Rust v2 implementation status — in progress

Dated update, 2026-10-29: all saved source is checkpointed on fork/rust/v2.
Latest coherent test source is `b51b5d7dd7a127d88a6e770f0b8780951190805b`, 202
exact inputs, independently verified AMD64/ARM64 static payloads and contexts.
Local owned Debian actual-program397 passes 17 cases, including four live post-pin
faults/revocation, with six independent captures/112 packets/zero forbidden
markers/zero kernel drops. The ARM64 Bootstrap syscall-name compile error was
fixed without widening policy; original failure is retained. Fresh ordinary
workspace 393 tests and focused 12 native-role tests pass, as do fmt/strictClippy;
84 performance-tool unit tests pass without benchmark acceptance.
Task8b2 independently passes against 836210a through reviewed 90a7dcc/run396;
new current-source regression review is separate. New Bootstrap native execution,
operational/runtime/client/migration/performance/release acceptance remain open.
See `testing-2026-10-29.md/json` and the dated task8b2 reviews for source limits.

## Historical checkpoint notes recorded before 2026-10-29

Current frozen source candidate: `90a7dcc756f073cccd3a1c34959676f001eb7601`,
worktree `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`.
Root passes 388 workspace tests (zero failures, two ignored), all 195 source
inputs, both immutable contexts and exact AMD64/ARM64 nine-report preflights.
Independent frozen source review passes. These are source and mechanical checks;
corrected connected HOST mutation cases have not run yet. Original 387 remains failed.

The first connected HOST native case, registration-failure run 387, failed.
The exact unit journal records main-process signal 11/SEGV; no native witness
or canonical root exists. The external controller verifies unchanged HOST state
and original gateway identity. Six exact public selectors were archived after
fresh owner/cgroup absence checks; all resources remain retained. Independent
review verified the 16-file failure index. The original kernel fault instruction maps to the entry stack probe in
`movement::lab_build`, beneath 7,545,776 bytes of active caller frames. Including
that new frame requires 8,700,312 bytes; the original stack limit was not observed.
No unchanged native retry or larger stack/deadline/capacity limit is authorized
by this evidence. The reviewed correction stores the same private owners in Box allocations. The
exact new AMD64 binary reserves 94,144 bytes across six named nested entry frames,
down from 9,075,680; this excludes wrappers, saved registers and dynamic use.
Full Root tests, immutable binding and independent frozen review pass. Corrected
actual HOST behavior and daemon compatibility still require native testing.

The baseline controller corrections and outer collector are independently
reviewed: 153 synthetic collector checks and 19 focused controller checks pass.
Debian and Arch authored templates preserve known foreign state. A separate
retained-Debian metadata-only projection first refused with `network_operation`.
The separately frozen diagnostic now identifies `poll_read` / `Oversized`,
without identifying which bounded limit fired. No declaration or host authority
was granted, and no bound was increased.

The preceding producer-binding checkpoint remains closed: all four modes on
clean Debian, retained Debian, Arch and emulated ARM pass (16 cases), with a
226-file index. Debian and Arch packet regressions each pass 17 named cases,
with six captures, valid controls, zero forbidden markers and zero kernel drops.
Earlier failures and retained resources remain preserved without new attribution.

Managed Docker/JSON copy repairs are included in the reviewed frozen candidate;
their source review and tests pass, but frozen daemon compatibility and
the universal legacy fork boundary remain open. Performance measurement tooling
passes 84 Root tests; actual comparisons and the 24-hour soak remain NOT_RUN.
All nine release areas below remain open. No runtime performance improvement,
real-client acceptance or release readiness is claimed.

Priority summary (release acceptance remains open):

| Priority | Area | Next required result |
|---|---|---|
| 1 | Operational runtime | Fix native startup failure, then connect owned resources to guard, publisher, CLI and recovery. |
| 1 | Client leak protection | Prove persistent real-client WAN, DNS, IPv6 and proxy fallback refusal. |
| 1 | Shared host and exits | Run five independent VPN exits plus explicit direct mode, churn and restart. |
| 1 | Secret boundary | Close remaining Docker/decoder copies and legacy fork/raw-WireGuard paths. |
| 2 | Failure matrix | Verify drift, crashes, freezes, suspend and interruptions under continuous traffic. |
| 2 | Health propagation | Prove worker-to-guard-to-publisher-to-CLI status through fault and recovery. |
| 2 | Migration | Apply, resume and roll back two local legacy installations while preserving identity. |
| 2 | Lifecycle/platforms | Verify systemd, runit and ARM install/update/reboot/rollback/uninstall. |
| 3 | Performance and soak | Run repeated same-host ten-minute 1/5/6 comparisons and actual 24-hour mixed soak. |

Earlier checkpoint notes (historical state at each checkpoint):

Current corrected frozen candidate: `a95ac923cb0bbf0e0aa69fcb2926fd3c6b3e3fbf`.
Root passes 369 workspace tests, all 177 exact inputs, both immutable contexts
and exact AMD64/ARM64 seven-report preflights; independent frozen review passes.
Postbirth-fault run 367 now passes strict and independent review: the failed
original owner refuses two retries, preserves its request, step and error,
creates no new child and keeps charges `[1,1]` through final Drop.
Result-writer fault run 368 fails a separate fixture charge expectation. The
failed pending writer correctly retains one launch charge, producing `[2,1]`
with the binding role. Source and independent review confirm this retention
path; no production charge release is justified. The batch stopped, evidence
and resources are preserved, and a narrow fixture correction with explicit
original failed-writer proof is being prepared. Registration and success modes
remain NOT_RUN on a95. Earlier 365/366/368 remain failed historical records.
No operational runtime, client, release or complete secret-boundary acceptance
is inferred from these component checks. All nine release areas remain open.

Latest producer-binding checkpoints: `7f9bfed5a1d841a7ddee8a53118b8157af2e2be0`
and diagnostic `71d69a68373dfcfef7e65385e94f910461e9726f`.
Both pass Root's 369-test workspace suite (zero failures, two ignored), all
177 frozen inputs, immutable contexts and exact AMD64/ARM64 seven-report
mechanical preflights. Independent frozen review passes.
Native success 364 verifies the same original group is bound in canonical
Creating state after its fresh observation and durable writer acknowledgement:
75 writers, 18 original windows, 25 canonical refusal checks and seven retained
owner anchors. This grants no placement, readiness, UP or resource reuse.
Postbirth-fault runs 365 and 366 fail and remain preserved. Diagnostic 366
localizes an incorrect fixture expectation: a constructor failure latches the
local owner's failure, while the global mutation fence remains false when no
journal write is pending. Production behavior is unchanged. The narrow fixture
correction also proves two retries retain the same failed request, step and
error without new births or capacity changes. Focused source checks and 81
collector checks pass; corrected native verification is pending. Run 365's
unobserved child status and precise failing postcondition remain unknown.
All nine release areas remain open, including operational multi-exit runtime,
actual-client leak protection, migrations, lifecycle, secret-copy closure,
controlled performance comparisons and the actual 24-hour soak.

Worktree: `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`.
Latest frozen assembly candidate: `bdc3f32a17670641829b0b76b01b6f96512e4fe7`.
Root passes 367 workspace tests (zero failures, two ignored), all 172 exact
inputs, immutable contexts and AMD64/ARM64 six-report mechanical preflights.
Independent frozen review passes. All four assembly modes pass strict collection
and independent review on fresh Debian AMD64, retained Debian AMD64, Arch AMD64
and emulated Debian ARM64: 16 cases (346–361), indexed by 231 file hashes.
The original 69 writers and 17 windows are preserved. Fifteen exact original
resource jobs retire 15 launch and 11 lower charges to zero on success; pretransfer
and partial failures fence further retirement while retaining 15/11 or 14/11.
Duplicate reservation is refused. Eligible foreign-child and gated/failed-child
capacity refusals are verified. Retained resources remain nonquiet through final
Drop; capacity retirement grants no collection, publication, placement or UP.
Fresh AMD64 and Arch also pass the existing 17-case packet regression, each with
six captures/112 records, positive controls and zero forbidden markers or drops;
independent supplemental review passes. Actual shared-owner 1/5/6 runtime,
provider/client protection and all nine release acceptance areas remain open.
Implementation now connects fresh producer/quarantine observation and exact
canonical binding of the same original group, without reconstructing old owners.

Preceding frozen diagnostic candidate: `4c7021cf68c7d8ebc86e25da8632c9f07666f7b7`.
Root passes 364 workspace tests (zero failures, two ignored), all 168 exact
inputs, immutable contexts and both architecture five-report preflights.
Independent frozen source review passes. All four quarantine/producer modes pass
strict collection and independent review on fresh Debian AMD64, retained Debian
AMD64, Arch AMD64 and emulated Debian ARM64: 16 component cases (328–343).
The partial checkpoint binds 222 files by hash. Successful cases verify 69
writers under 17 original windows, six netfilter receipts, original producer
group creation and five retained-context Drop proofs; fault cases retain their
original failed/unfinished owners and resources.
These diagnostics change no timing behavior. Earlier 322/323 failures were not
reproduced, and their causes remain unestablished. Implementation continues the
exact 15-ticket resource/capacity handoff with the original active-job cap of 64.
Fresh Debian AMD64 and Arch also pass independently reviewed 17-case packet
regressions, each with six captures, 112 records, positive controls and zero
forbidden markers or kernel drops. A 23-file supplement preserves the closed
222-file component index. All nine release acceptance areas remain open.

Preceding frozen repair candidate: `55cf31cbb4f70016eb8f6372fc5f23d1390eecde`.
Root passes 363 workspace tests (zero failures, two ignored), all 167 exact
inputs, immutable contexts and AMD64/ARM64 five-report mechanical preflights.
Independent source review confirms the typed own-operation polling repair keeps
idle admission and original request, phase, proposal, writer and deadline checks.
Fresh Debian passes all four quarantine/producer component modes (318–321).
Success has 69 acknowledged writers under 17 original two-second windows, six
netfilter receipts, original group creation and retained contexts after drop.
The real first Intent writer is held across repeated polls and released by the
fixture; 12 queued/held mismatches are refused. These are component proofs only:
no operational publication, producer exception, UP or full requirement 8 claim.

ARM322 fails during movement, 10.209 ms past its shared original deadline. Its
canonical Move result predates the deadline by 139.472 ms, which does not prove
the original writer ACK/reap or final process check. Arch323 fails 1.084 ms past
the first quarantine deadline with writer42 pending; its cached queue flags do
not establish the cause. Both batches stopped immediately. Exact failure records,
public canonical evidence and selectors are retained; no timer relaxation or
unchanged retry is authorized. Focused pre-cancellation diagnostics are in progress.
Retained Debian also passes all four modes (324–327) on the same artifact;
independent review passes. The partial checkpoint binds 155 evidence files,
eight component passes and the two preserved failures.
Assembly capacity transfer and all nine release acceptance areas remain open.

Preceding frozen diagnostic candidate: `d69662906a3e0c559f1088e4a70e8ba8cd01b210`.
Root passes 363 workspace tests, all 167 exact inputs, immutable contexts and
exact AMD64/ARM64 five-report mechanical preflights. Native317 remains failed.
It localizes the first quarantine conflict: after queuing its own netfilter
intent, the next poll invokes an idle-only transport binding and rejects its own
queued state before writer construction. The record has 42 cached successful
writers, eight original jobs, no netfilter history and no netfilter child.
The typed polling repair must preserve idle admission and bind the exact owned
request, phase, original clock, proposal and writer. No native nft failure is
inferred. Its partial index binds 51 files, with zero native program passes.

Preceding frozen candidate: `6c648eebab2e08b714d788f49391aa898d641ee7`.
Root passes 363 workspace tests and all 167 source inputs after isolating the
permanent-ingress test in a separate integration binary. A trace reproduces
transient pre-exec inheritance of a CLOEXEC allocation lock from another test;
production locking and all allocation assertions remain unchanged. Native316
commits the five WireGuard operations, then fails initial quarantine before any
netfilter intent. The failure remains preserved; its partial index binds 46 files.
All failed namespaces, mounts, gateways, synthetic profiles and canonical state
remain retained. Exact public selectors were archived after fresh owner absence
and original gateway checks. Native quarantine/producer acceptance is still open.

Latest frozen inventory repair: `dbcac60c3e660ae7082fdd38f56503cacb356b38`.
Both exact binaries pass five mechanical reports, and independent frozen review
matches all 166 inputs. Root workspace testing fails after 20 passing tests in
`two_writers_cannot_commit_the_same_generation`: the final read sees `LockBusy`
after both writers join. Core source is unchanged; the cause is being diagnosed.
The corrected privileged pipeline has not run. No passing workspace claim is
made for this candidate.

Preceding quarantine candidate: `af54fa733a08a7b8458f67b89183bbd68397b5b6`.
Root passes 363 workspace tests, all 166 inputs, exact AMD64/ARM64 mechanical
preflights and frozen review. Native315 fails during earlier Provision: original
child20871/start5478281 exits zero, but no canonical result is accepted. About
47 ms into the original two-second window, inventory accesses an empty consumed
child wrapper while the original Completed state is retained for asynchronous
readback. Independent review identifies this defect in the frozen source and
in Query/Move too. The repair preserves original descriptors, registration tokens
and deadlines, and requires repeated post-completion inventory evidence.
Run315 remains failed. Its exact five public selectors were archived after fresh
owner absence and original gateway identity checks; namespaces, mounts, gateway,
synthetic profiles and canonical resources remain retained. No native quarantine
or producer acceptance follows from this checkpoint.

Latest natively verified movement candidate: `2e44c7a5d4be47f8a78ae5ced5d9befc7235f35f`.
Root passes **356 workspace tests** (zero failures, two ignored), all 155 exact
inputs, immutable contexts, exact static preflights and independent frozen review.
Fresh-Debian native 297 moves the owned WireGuard object, still DOWN, from its
original TRANSPORT into original DATA. Strict collection and independent review
verify 42 writer receipts under ten original windows, fresh policy/process checks,
exact two-pair socket custody and both final retained-context proofs. All four
movement modes now pass independent review on fresh Debian AMD64, ARM64 TCG,
Arch and the retained Debian lab: 16 reviewed cases. Fresh Debian and Arch each
pass the 17-case packet suite with six captures, 112 records, zero forbidden
markers and zero kernel drops. The exact frozen four-socket syscall preflight
also passes unprivileged on Void. The partial index binds 256 evidence files. No UP, host links/
routes, provider/client, cleanup/reuse or full secret-lifetime acceptance is claimed.

Preceding frozen candidate: `ee9e454441a1c3a83298f223b7a225b53a196e2a`.
Root passes **354 workspace tests** (zero failures, two ignored), all 152 exact
build inputs, both immutable contexts, static preflights and independent frozen
review. All four fresh-Debian AMD64 provisioning modes pass independent native
review: success, constructor-birth failure, result-writer failure and partial
registration before clone. Success verifies 33 ordered writers under eight
original deadlines, original child reaps and identical DOWN WireGuard provision/
query results bound to externally generated synthetic public keys. All four modes
also pass independent native review on ARM64 TCG, Arch, and the retained Debian
lab: 16 reviewed cases across four routes. Fresh Debian additionally passes the
17-case component packet suite with six captures, 112 records, zero forbidden
markers and zero kernel drops; the corresponding Arch regression also passes
with the same counts. The partial index binds 225 evidence files by hash.
These results confirm the protected filename-hint correction.
DATA movement, UP, real provider/client use and full secret-boundary closure remain
open. Failed 273, 277 and 278 evidence and resources remain preserved.

Preceding frozen diagnostic candidate: `d49e23ca3542e096d9b2485a64e6bc52eeacf011`.
Root passes **352 workspace tests** (zero failures, two ignored), all 152 exact
source checks, both immutable contexts, static AMD/ARM preflights and independent
frozen review. Native 278 captures an original child exit 122 during profile load,
with a bound `Drifted` error before network creation. Profile-reload parity is
being investigated; no full-report comparison or original deadline is relaxed.
This diagnostic failure is preserved alongside the earlier failures.

Preceding frozen candidate: `efd8bf696388124df9a9a1d5abe97b7560de861c`.
Root passes **349 workspace tests** (zero failures, two ignored), all 152 exact
archive/commit/current input checks, both immutable contexts, exact static AMD/ARM
selftests and independent frozen review. Its first fresh-Debian provisioning run
273 fails during Provision about 31 ms into the original two-second window.
Canonical transport creation/mount and socket result are present; Provision birth
is present with no accepted result. The exact native child failure is unobserved.
The sequence stops for diagnosis; original resources and evidence are retained.
No provisioning or full secret-boundary acceptance is claimed. Independent
attachment ACK-regression testing continues on this frozen candidate.

Preceding frozen component candidate: `a8a26700741087c98c2b13ecc7fc71c52dd40542`.
Root passes **342 workspace tests**, all 133 frozen input checks, both immutable
contexts, exact static AMD/ARM selftests and independent frozen source review.
Admission checks now consume pending signals without a fixed 50 ms wait; existing
timed waits retain their behavior. Six isolated native regressions cover signal
consumption and permanent stop/error latches, including a real denied syscall.
Three AMD64 attachment cases pass independent review: successful publication,
placeholder-write failure, and publication-write failure with retained ownership.
ARM successful attachment also passes. Its next attempt expires during inspection
before the intended fault; the original two-second limit remains unchanged and
the failed resources are retained. ARM signal-stop retention, 17-case capture suite and ten-case owner inspection
pass, including all three timely terminal completions. A separate retirement
cleanup failure remains localized to verification before WireGuard deletion.
Arch and the retained Debian lab pass successful attachment; Arch also passes
the placeholder fault. Its publication-fault run exposed a source-confirmed test
harness ACK-consumption race, with that intended fault still unverified there.
Further regressions, the harness correction and finer cost measurements continue. The microtiming check establishes
polling behavior only; router performance and all nine acceptance areas remain open.

Current operational integration is **incomplete and not natively accepted**. The next
connected path adds original NETFILTER socket custody, durable exclusive initial
quarantine and producer creation to the retained live DOWN movement owner.
Initial quarantine refuses any existing table and carries no producer or permit.
Both generation-bracketed verification passes now run in the original fixed
child; its observation time remains distinct from parent acceptance. A protected
public WAN declaration uses the exact Rust allocation digest. Its 16 local
schema checks and independent read-only review pass; native admission is pending.

Independent source review found a scheduling defect in the older Query,
Provision and Move roles: parent-side preparation/completion calls could perform
synchronous native link/address/route reads for the remaining original two-second
budget without yielding to siblings. The current unfrozen repair uses retained,
bounded nonblocking readbacks with the same predicates, socket sequences and
original deadlines. Explicit socket/creator binding now passes scoped source
rereview; native sibling-progress verification remains pending. The finding does not invalidate previous component
passes or identify a past failure's cause. Multi-exit nonstarvation acceptance
remains open. A typed assembly handoff must also release
only fully reaped, durably acknowledged operation capacity while retaining all
original ownership evidence; the global 64-slot cap remains unchanged.

Preceding frozen diagnostic candidate: `924f92962e11a457237ebcb7e8f606d0924aad31`.
Root passes **342 workspace tests**, all 133 frozen input checks, exact static
selftests and independent source review. Native 255 pinpoints the deadline:
final request-binding verification takes 50.425 ms with only 38.646 ms remaining,
finishing 12.546 ms late. All nine original writer ACKs/reaps occur within their
original deadlines; no namespace attachment begins. Source inspection identifies
a fixed 50 ms `sigtimedwait` in every admission signal check. A separate nonblocking
check is being tested, retaining signal consumption, permanent stop latches and
the existing timed-wait callers. No deadline or security check is relaxed.

Preceding frozen component candidate: `6c5226488322b7b16810d42378b4e7322b32bd1d`.
Root passes **342 workspace tests** (zero failures, two ignored), all 133 frozen
build-input checks, immutable contexts and exact ARM native selftests.
The listener-origin correction has independent scoped review. Run 254 progresses
through both Docker query results but fails a deadline before any canonical
attachment history appears. The durable recheck leaves 322.6 ms before its end;
the exact expired function and last writer ACK/reap are not yet proven. Fixed
parent-side timing diagnostics are next. Original clocks remain unchanged, and
failed 253/254 containers, profiles and journals are retained.

The preceding frozen component candidate is
`3c948aa9828ca6a04d9d1c601af7b85561d59899`.
Root passes **340 workspace tests** (zero failures, two ignored), all 133 frozen
build-input checks, both immutable image inventories and exact ARM rootless
selftests. Independent scoped source and controller reviews pass.
Integrated Debian run 253 fails before the first Docker-query child is born.
The new code rejects PID 1 socket origins; a later native metadata check confirms
this Docker listener has a live, atomic PID 1 origin. The correction distinguishes
listener origin from the process serving HTTP, retaining atomic pins and fixed
policy checks. Failed 253, its inert container, profiles and journal are preserved.
No namespace attachment or public runtime acceptance is claimed for this candidate.

Previous frozen validation candidate: `62dae90586206c21e395edc0c8122c0297c69ac8`.
It passes **333 workspace tests**, with zero failures and two ignored tests,
all 126 build-input checks, both immutable artifact inventories and independent
scoped source review. It connects pre-resource protected profile validation to
original child reaps and a durable public result while retaining the same service.
All six native validation modes pass on fresh Debian (226–231), Arch (232–237),
emulated ARM (238–243) and the original Debian lab (245–250): 24 cases independently
reviewed against frozen source and saved controllers. Strict collectors verify
original deadlines, actual child reaps, service retention and the different failure
fences. First run 225 stopped before
validation because the Root controller omitted the required lab admission record;
that failure and its inputs remain preserved. The corrected controller passed
independent review. Packet regressions 244, 251 and 252 each pass 17 cases with
six captures/112 records, zero forbidden markers and zero kernel drops. The
partial checkpoint index binds 248 evidence entries by hash. This does not complete
the secret boundary, provisioning, recovery or public runtime.

The preceding frozen component candidate is
`ed78d4087759188e4611f2c7098e659799600265`.
Root passes **324 workspace tests**, both exact static selftests, all 122 frozen
build-input checks, immutable image inventories and independent scoped review.
Debian 215, Arch 218 and ARM 220 pass a controlled audit spanning actual B link removal: the
same original job returns B's old link with B addresses/routes absent, within its
unchanged deadline. A fresh ticket rejects that mixed observation, and a later
native audit verifies the final shape. Final retirement/writer reap also pass.
Debian 216 and ARM 221 pass real SIGTERM after a durable retirement driver is dropped:
three polls retain the unconsumed permit, canonical bytes and service, with no new
native child. Later guard reap is explicit fixture containment. This does not test
inventory corruption. Normal runs 222–224 pass all 17 component cases on ARM,
Debian and Arch; each has six captures/112 records with zero forbidden markers
or kernel drops. These remain synthetic components with no real-client acceptance.
ARM 219 stops before guards at an existing retained `/32` route collision; all
partial resources and the failure remain preserved. Its successor uses a bounded,
source-checked lab input preflight, which grants no runtime allocation authority.

The preceding frozen 01292f candidate establishes the following retirement results.
Fresh Debian native 211 passes the complete consuming retirement path: original
guard and expiry reaps, native link cleanup, empty producer-group removal, final
durable Retired state and actual final-writer collection. The LinksRemoved writer
is held across two successful pending parent polls and completes within its
original two-second deadline. Neighbor A completes three fresh audits during
cleanup and three more after final reap. Arch native 213 passes the same case.
ARM native 212 fails the unchanged cleanup deadline. New instrumented 217 also
fails: cleanup remains deliberately paused while A completes only two of the
required three audits before the original two-second deadline. This explains 217;
212 lacks the corresponding timing record and remains separately unproven. Its three canonical completions are timely and all three deny
tables remain present. The stopped surviving guard is precisely killed without
resume after the retiring guard and expiry actors are verified absent. Failed
resources are retained; ARM retirement remains unaccepted.

This corrects native 207's confirmed phase defect: LinksCleaned rejected its own
pending journal writer. The repair preserves pre-queue native quiet, fresh native
identity proofs and original deadlines. Failed 207 and its resources are retained.
Separate fresh-Debian runs 208–210 pass queued-retirement failure, writer-failure
uncertainty retention and host-audit reservation retention through actual collection.
Strict collectors bind these results to their exact frozen source and executable.
Retirement 211 retains namespaces and quarantine, uses an empty producer cohort,
and grants no operational reuse. It does not prove an A dump spanning host deletion.

The preceding frozen d5f7838 component checkpoint passes 316 workspace tests.
Native runs 194–199 pass registered and partial expiry Drop on fresh Debian, emulated
ARM and Arch. Active held host-audit regressions 200/201 also pass on Debian/ARM. Strict source-bound collectors
verify original identities and deadlines, actual parent reap receipts, retained
completion/context ownership, no expiry signals/resume, full guard-bundle drainage,
original removed-scope observations and three further neighbor audits. Canonical
completion count remains zero and cleanup/reuse remains unauthorized.

The ordering repair follows exact native diagnosis: files return ENODEV before
their cached descriptor paths acquire a deleted suffix. Fresh lookup through the
original directory returns ENOENT and updates those paths. Moving that existing
lookup before the deleted-path check preserves every final proof predicate.
Failed runs 191/192/193 attempts and their original resources remain preserved. Normal
suites 202/203/204 each pass 17 cases and six captures/112 records with zero forbidden
markers or kernel drops. Fresh Debian 205 passes all 10 owner cases and three
original-deadline durable completions. ARM 206 fails sender reinspection: its
last successful journal RPC leaves 64,367 microseconds in the initial permission
budget; the next inspector reports stage 60 PlacementFailed. The exact inner
check and duration were not logged in 206. New frozen 01292f ARM run 214 records
stage60/substage2: the exact pinned sender is already exited before verification.
That inspection RPC uses 64,760 microseconds and still has 1,935,239 remaining;
the enclosing initial-permission budget is already zero before it starts. The
sender exit cause remains unproven; 214 does not retroactively identify 206's check.
The later 60-second test-envelope timeout is secondary. Its three canonical
containment completions are timely; Root verifies all expiry actors absent and
three terminal deny tables before killing only the exact stopped guard without
resume. All resources and failed 206 evidence remain preserved.

Prior frozen f89d component gates pass owner-drop/birth-failure and original
host-audit cases on x86/ARM, x86 journal, and 17 normal cases on Debian/ARM/Arch
with six captures/112 records and zero forbidden markers or drops per suite.
Fresh Debian also passes ten owner cases and three timely durable completions.
These are isolated component proofs; real-client acceptance remains not run.
ARM 186's original two-second sender-permission failure and AMD 185's over-limit
host projection remain open. An additional fresh VM preserves the old lab state;
no size cap or deadline was raised.

The sole writer has connected typed retirement through native link cleanup,
empty-producer cgroup removal and final durable retirement with actual writer
reaping. The narrow lifecycle repair passes native 211 on fresh Debian and 213 on Arch.
ARM three-audit stress failures 212/217 remain recorded; controlled audit-span
retirement now passes on all three platforms. Live-producer retirement remains open. Audit-ticket retention and fixed
cleanup filters have source and rootless coverage. Parent-death reconciliation,
fresh-resource preparation and operational assembly remain in progress.
The secret boundary
must exclude both profile keys and raw WireGuard replies from fork-capable
processes before real-profile activation. Public startup remains refused.
Real providers/clients, five exits plus direct, two local migrations, service
lifecycle, repeated router workloads and the actual 24-hour soak remain open.
The Python production router and existing identities remain unchanged.
The real-client release matrix still has 284 scenario entries marked `NOT_RUN`
across its four configurations. Positive controls and boot captures also remain
`NOT_RUN`; the component results above do not satisfy those release gates.

| Priority | Area | Implemented and verified | Still required |
|---|---|---|---|
| 1 | Operational runtime | Parent-owned journal/host/inspection/expiry; complete native bundles and constructor-origin shared reap receipts; tested owner Drop/birth-failure retention and Debian/Arch consuming retirement; exact guard descriptor isolation and fixed LocalAPI discovery; periodic Engine and protected enrollment components | Durable parent-death recovery, asynchronous fresh preparation and live-producer retirement/reuse; actual shared-owner 1/5/6 runtime and native provider/enrolled operation; protected declared host policy, staged start/stop and public CLI |
| 2 | Persistent client protection | Fail-closed design boundaries retained | Real install/select/status; persistent IPv4/DNS/IPv6 and proxy-bypass/no-fallback protection with actual clients |
| 3 | Shared host and multi-exit ownership | Authenticated parent journal/host authority and PIDfd placement; native two-exit audits; parent-owned three-executor completion and surviving-writer barriers | Five concurrent real exits; authorized updates to the immutable peer roster/native peer-route declaration; add/remove/restart without disturbing neighbors; explicit direct runtime |
| 4 | Migration and rollback | Inspection/planning and protected identity boundaries; uncertain terminal ownership refuses reuse | Durable apply/resume/rollback, compatible real release restoration, interruptions on two independent local legacy installations |
| 5 | Health publication | Shared versioned binding; authenticated Starting worker→guard→isolated publisher→CLI; strict phases and expiry; stale/replay rejection | Native operational periodic producer/reader and real provider/structural evidence |
| 6 | Hostile faults | Four live post-pin drift faults; exact guard freeze; independent three-scope terminal policies and original-deadline completion; guard death/sole-survivor flock/durable barriers; live hot-add private-channel isolation and sibling progress on x86/ARM | Integrated worker/provider/daemon/native-stall faults, suspend/reboot, continuous traffic and full real-client matrix |
| 7 | Platforms and lifecycle | Static x86/ARM builds; current Debian/Arch/emulated ARM 17-case component suites and captures; Void rootless exact static constructor/syscall preflight passes; unsupported platform activation still refuses | cgroupfs/runit adapter; install/update/rollback/uninstall services; reboot and ARM64 runtime lifecycle acceptance (current ARM evidence uses emulation) |
| 8 | Secret lifetime | Compiler-resistant profile/raw-buffer/SET erasure and duplicate tracking; GET decoder neutralizes keys before typed allocation; fixed no-fork profile validator through durable result passes 24 reviewed native cases; fixed DOWN WireGuard provision/query and three constructor/writer faults pass 16 reviewed cases across four local routes; secret-free-parent fixed Docker query/native namespace attachment passes reviewed AMD64 success/failure and ARM success cases; fixed DOWN movement passes four modes across four local platforms; initial quarantine/producer passes four independently reviewed modes on all four local platform routes | Complete secret-free parents and integrate the verified fixed provision/raw-query and Docker/attachment roles throughout startup and recovery; integrate the verified DOWN movement into guarded startup/recovery and finish remaining ARM deadline diagnosis. Docker inspect includes raw environment fields before projection; Hyper-owned copies also need cleanup review. Cover every helper/error/pre-exec/hot-add path and whole-branch verification |
| 9 | Performance and soak | Snapshot comparison optimization with exact correctness coverage; source/artifact-bound component evidence; read-only CPU/PSS instrumentation and summary integrity checks prepared | Same-host Python/Rust 1/5/6-exit repeated ten-minute workloads, CPU/PSS/throughput/p95 measurements and actual mixed 24-hour soak |

## Evidence boundaries

- **Void d5f783 ABI preflight:** The exact frozen static x86 payload passes its
  expanded rootless syscall, descriptor, constructor-receipt and retention
  selftests on Void kernel6.12.114_1 as UID1000. The original process1501/start
  7574709 is actually reaped with no timeout. This adds no runit/cgroupfs adapter
  or service-lifecycle acceptance. The record is under the frozen candidate's
  `native-preflight-void-x86_64` directory.
- **d5f783 final component regression checkpoint:** All six expiry cases194–199
  and both active held host-audit cases200/201 pass. Debian202, ARM203 and Arch204
  each pass17 normal cases and six captures/112 records with zero forbidden
  markers/drops. Fresh Debian205 passes10 owner cases, three durable timely
  completions and a complete profile: sender pin156ms, verification839ms,
  final original budget1003731us. ARM206 fails during retained sender reinspection:
  four completed disjoint phases total1670509us; the last logged journal RPC
  takes76567us and leaves64367us, then stage60 PlacementFailed. Its profile has
  only21 successful rows and no final summary; the missing sender duration and
  exact private failure-job binding remain NOT_LOGGED. The incomplete sidecar
  makes no full-verification or proven worker-timeout claim. Native inspector
  actual reap is recorded. Three canonical completions precede original84189.9528;
  exact deny tables and absent expiry actors are verified before the stopped
  guard is killed without resume. All actor/owner units/cgroups are absent before
  failed nonce archival. This remains a PARTIAL checkpoint; current owned-store/
  retirement edits are unfrozen and independently outside this evidence.
- **d5f783 ordering repair:** Root316 workspace tests, exact static x86/ARM
  preflights and strict source/context checks pass; independent frozen review
  confirms the one-file repair. Native194 fresh Debian registered expiry passes:
  all three original expiry children have actual wait status31232, three timely
  original completion records remain retained, and A progresses9→12. Native195
  partial constructor failure passes with original failed-birth context retained
  after actual status31232 and A5→8. Native196 emulated ARM registered case also
  passes with three actual status31232 receipts and A9→12. Every collected case
  verifies original removed guard scope and complete guard-bundle drainage,
  journal drainage, no expiry signals/resume and no cleanup or reuse authority.
  Remaining platform/regression gates are not inferred from these passes.
- **f638b8 diagnostic:** Root119 launch tests, both exact static selftests,
  source/input checks and independent three-file review pass. Native193 fails
  at `events_target` after paired original ENODEV19 with matching native pins,
  filesystem and stored metadata; scope0 has actual parent wait status31232.
  The exact-order kernel experiment on the same fresh Debian kernel uses
  production-length scope names and tests both a direct child and a live
  grandchild surviving parent reap. It observes normal retained-file targets
  before exact-directory lookup and deleted targets after that lookup returns
  ENOENT. This diagnoses check ordering; it supplies no member cleanup authority.
  Native193's three expiry actors are absent and its three terminal deny tables
  remain present. Two exactly identified stopped guards are killed without
  resume, then all five actor/owner units and cgroups are verified absent before
  nonce archival. New native gates remain pending after the reviewed repair.
- **df33fe repaired expiry fixture:** Independent frozen review confirms only
  two test-only hunks changed from95efad. Root119 launch tests and both exact
  static selftests pass. Native192 reaches all three expiry placements and
  canonical acknowledgments before its post-Drop CgroupMismatch. A separate
  kernel-only original-handle experiment confirms retained-file metadata,
  filesystem and deleted targets, and both offset-zero pread and seek/read
  ENODEV behavior on the fresh Debian VM. It does not identify192's failing
  predicate; bounded in-process diagnostics are required. Original clock and
  population-proof predicates remain unchanged. Failed192 actor/journal/deny
  records and original nonce are retained; all network resources are preserved.
- **95efad expiry slice:** 316 workspace tests, both exact static selftests,
  all120 source checks and scoped review pass. Native191 fails before any expiry
  birth because the new fixture does not install B's HostService. B's first
  HostAudit returns OwnershipMismatch; A continues making audits until the test
  envelope times out. No expiry-retention or RemovedOriginal native PASS is
  claimed. The two stopped guards are precisely identified and killed without
  resume; native exit observation does not mint a new parent waitpid receipt.
  All actor/owner units and cgroups are then absent before nonce archival.
- **f89d lifecycle component:** New native cases178–181 pass owner-drop and
  initial birth-write failure on x86/ARM, including actual SIGKILL wait receipts,
  original birth/gate binding, unchanged failed Planned records, no release or
  resume, audit/OFD retention and three fresh neighbor checks. Uncertain scope
  bundles remain retained and grant no cleanup. Original host-audit182/183 and
  journal184 regressions pass. ARM187, Arch188 and fresh Debian190 each pass 17
  normal cases and captures; fresh Debian189 passes10 owner cases and three
  timely durable completions. ARM186 remains a genuine original-budget failure:
  pin 197 ms leaves 1766 ms, full verification 1769 ms ends at zero. Its failed-profile
  sidecar retains all 23 spans; no deadline extension or cached approval is used.
- **Fork-copy secret lifetime:** `ValidatedConfiguration` owns inline profile keys
  across fixed-helper forks. Ordinary key/buffer Drop zeroization leaves inherited
  copies outside its coverage; fixed `_exit` paths skip the enclosing destructors.
  The inspected fixtures use synthetic keys and public launch remains refused.
  An enforced secret-free fork boundary or rigorously excluded secret storage is
  required before real-profile runtime and hot-add; no real-key exposure was
  demonstrated by this source-only audit.
- **Additional fresh Debian lab:** AMD185's host projection measures 131392 bytes
  on two read-only observations, 320 bytes above the 131072 limit, with 650 records
  and valid individual field bounds. No parser limit was changed. New isolated
  `debian-clean-x86_64` uses a fresh overlay of the checksum-verified original base;
  old VMs, failed resources and approved identities are preserved. Its kernel,
  systemd, Docker and cgroup/AppArmor preflight match the supported Debian setup.
- **Measurement tooling:** A separate read-only cgroup/PSS collector passes nine
  native instrumentation cases and independent source review. It records native
  identity changes, counter windows, observer cost and invalid/duplicate samples;
  short runs are ineligible for ten-minute or day-long evidence. Actual router
  workload comparisons and the 24-hour soak remain not run.
- **Retirement investigation:** The exact PIDFD-based manager experiment on
  Debian x86 and ARM retains original cgroup handles through child reap and scope
  removal. The directory link count stays two; fresh opens fail ENOENT and
  retained file reads fail ENODEV. A live grandchild keeps the original scope
  populated after its parent is actually reaped. These observations characterize
  the handles; they do not grant cleanup, reuse or full quiescence. Deleted or
  uncertain scope bundles remain retained while lifecycle implementation continues.
- **Void compatibility preflight:** The exact frozen6d83 x86 musl full syscall,
  descriptor and retention selftest passes as UID1000 on Void kernel6.12.114_1.
  The root process is actually reaped. This checks ABI compatibility only;
  the required runit/cgroupfs adapter and service lifecycle remain unimplemented.
- **Getter candidate 6d835a9:** Paired measurements and semantic checks support
  replacing only CLOEXEC retrieval with fresh `F_GETFD`. Fresh statat metadata,
  token/epoch checks, filters, hashes, leases and deadlines remain unchanged;
  scoped review independently confirms the narrow diff. Root passes 312 workspace
  tests and exact x86/ARM fixed-filter selftests. Baseline paired ARM metadata
  time falls about74% for this operation, not the router. Native169/170/171 run
  the same optimized artifact through all ten ARM owner cases: full permission
  takes1706/1709/1757 ms, leaving110.974/113.407/64.442 ms compared with
  baseline168's43.208 ms. All three timely durable witness sets are collected.
  Native172 x86 owner passes ten cases,173/174 ARM/Arch strong stop tests pass,
  and175/176/177 Debian/ARM/Arch normal suites pass 17 cases each with six
  captures/112 records/zero forbidden markers/zero drops. Final source checks
  match all120 inputs. This is improved observed margin, not a latency
  guarantee, whole-router performance result or release acceptance. Failed167
  and the initial low-FD benchmark failure remain preserved.
- **ARM168 diagnostic result:** Snapshot d717458 passes all ten owner cases and
  three timely durable terminal completions. The sender permission check takes
  1773 ms and leaves only 43.208 ms; this is a tight pass, not a latency fix.
  The five disjoint verification phases total 1772.364 ms: base254.786,
  daemon-before520.218, host/native-shape259.500, daemon-after553.133 and
  sender184.727. The two nested native-daemon RPCs total800.779 ms; journal
  RPCs individually take51–76 ms. Timings are source/artifact bound in
  `handoff-profile-run-168.json`; nested RPCs must not be double-counted.
  A bounded paired metadata measurement is next. Production optimization,
  deadline changes, cached approval and verification skips are not authorized
  by this pass. Failure167 remains preserved.
- **Current performance blocker, ARM167:** The full owner suite passes native
  daemon verification, then the sender bootstrap misses its original two-second
  deadline: pinning takes 140 ms and full permission verification takes 1859 ms,
  leaving zero budget. The later 60-second fixture timeout is secondary. The
  earlier observed 39 ms headroom has become an actual failure. Nested fresh
  daemon/sender, journal, host and network checks remain required. Bounded phase
  timing and an immediate pre-drain error diagnostic are being implemented;
  no deadline extension or cached approval is authorized. All three durable
  containment completions are present before their original deadlines. Root
  verifies three terminal deny tables and absent expiry actors, kills only the
  exact stopped guard without resume, and archives the nonce after every actor
  unit/cgroup is absent. Resources and failed167 evidence remain preserved.
- **Test-only follow-ups, f1d8c81/44eb146:** Exact native waitpid receipts allow
  setup tests163/164 to pass on x86/ARM when the failed inspector is legitimately
  reaped before asynchronous admission completes; both require three later
  neighbor inspections. Failure162 remains preserved. Journal165 exposed a stale
  wrapper-lifetime assumption; test-only correction44eb keeps production code
  unchanged. Native166 verifies that the lock and reservation remain busy after
  actual writer reap while its wrapper lives, then become free only after the
  wrapper is dropped, with exact readback and late-temp checks. Failure165 remains
  preserved. All frozen sources, artifacts and narrow diffs are independently
  bound and reviewed; these results are not operational acceptance.
- **d0e83a2 admission slice:** Root independently passes 311 workspace tests,
  exact musl preflight and strict frozen-source/context checks. Scoped review
  passes. Strong shutdown tests156/157/161 pass on Debian x86, ARM and Arch:
  an actually stopped journal reader is killed/reaped without resume or ACK,
  its original progress remains recorded, both journals drain, and the pending
  guard is reaped without release. Held-inspector tests158/159/160 also pass on
  those platforms with original deadlines and continued neighbor progress.
  These demonstrate durable admission ordering, but record zero completed A
  inspections during B construction, so worst-case admission non-starvation
  remains unverified. The host-audit drain assertion has no active host audit
  in this fixture; constructor/Drop and live cancellation remain open. Native162
  setup fails on an old pending-child assumption after asynchronous collection.
  Its exact guards are killed without resume after native identity checks; all
  resources remain. A reviewed test-only exact-waitpid-receipt correction is
  being frozen; native162 remains FAIL.
- **Active admission work, 34d395c/726f9cc:** Root's full workspace run passes
  311 tests on 34d3, and exact x86/ARM static selftests include journal-I/O
  retention through actual reap. Scoped reviews pass. New source adds owner
  epoch/attempt binding, asynchronous prepared-member placement and a persistent
  shutdown latch. Native154 correctly refuses an unregistered owner-cgroup FD
  before guard creation; the narrow registration-order fix is 726f9cc. Native155
  then verifies no pending-guard release, no new guard birth and actual pending
  reap, but its stronger all-I/O drainage claim is withheld: A's reader was not
  explicitly collected by the fixture. Post-service native checks find no exact
  payload processes or recorded actor units/cgroups; this does not replace the
  missing in-process reap assertion. The writer is fixing terminal completion
  and strengthening the held-reader test. Fresh-resource preparation, native
  retirement, parent-death reconciliation and operational acceptance remain open.
- **f0056a6:** Two-file guest-test correction passes scoped review: the combined
  actual-inspection fixture gets one fixed 60-second aggregate wait and explicit
  BOOTTIME diagnostics; synthetic-only remains 30 seconds. Product code, timers,
  leases and later 3/10-second assertions are byte-identical to c99d. Root verifies
  all 120 inputs, exact musl preflight and both immutable contexts. Native150 ARM
  passes ten cases, a 31.003-second checkpoint with no owner-terminal error, and
  three durable completions before their original deadlines, without resume.
  Native151 Debian, 152 ARM and 153 Arch each pass 17 normal cases and six captures
  containing 112 records, zero forbidden markers and zero kernel drops. These are
  Starting/unenrolled component captures, not real-client acceptance. The final
  source/HEAD/index check passes at 04:24:57 UTC. Root then authorizes connected
  durable-recovery/operational implementation; all nine remain active.
- **c99dd81:** Root independently verifies all 120 frozen/current inputs, both
  immutable contexts, 308 workspace tests, exact x86 musl selftest/descriptor and
  the expanded static ARM selftest running natively as an unprivileged lab user.
  Scoped review covers all 17 changed files. Native144/146 held and 145/147 setup
  tests pass on x86/ARM, each with two passing labels plus one witness. Guard B
  starts after A's private factories exist; exact private-descriptor exclusion,
  foreign journal refusal and collector progress are source/artifact bound in
  `guard-hot-add-run-144.json` through `147.json`. The held branches prove copied
  installed-Service Drop; setup has no installed Service and proves retention
  after constructor failure. No expired actor resumes. Parent-death durable
  recovery, nonblocking dynamic admission and all-nine operational acceptance
  remain open. Native148 x86 passes all ten owner cases and three timely durable
  completions. ARM149 passes six cases, including genuine daemon/sender discovery,
  then fails on `Deadline`; the enclosing test-only 30-second checkpoint wait is
  under investigation. Root observes all three exact terminal deny tables and
  absent expiry actors, kills/reaps only the exact stopped guard without resume,
  then archives its nonce after every recorded actor unit is absent. Journal
  completions are empty; no completion or overall ARM PASS is claimed. All
  resources and failed evidence remain. The normal regressions subsequently pass
  on f0056, whose production code is unchanged.
- **d57e2a9:** Root full workspace305/0fail/2ignored, exact musl expanded startup/
  retention/reap/FD-reuse selftest, strict descriptor, 120 matching source inputs,
  unchanged HEAD/index, static builds and scoped review pass. Publisher readiness
  requires exact ACK128 plus EOF under one original deadline; constructor errors
  retain complete registered native ownership until actual reap. Arch138,
  Debian139 and ARM143 normal suites pass 17 cases and six captures/112 records
  each, with zero forbidden markers/drops. Journal140 passes its native gate;
  the exact static ARM expanded selftest also passes natively as an unprivileged
  lab user, separately from the functional oracle counter.
  x86141 and ARM142 held placement prove original expiry, no grant/registration,
  actual helper/target reap and neighbor progress. Witness events are not extra
  passing cases; shared OFD evidence is not a sole-survivor claim. Generic
  `Child::Drop` can still discard ownership after bounded reap failure; root-child
  reap is not descendant death. That broader lifecycle repair is active before
  public assembly. Initial bootstrap's `Instant` contract does not establish
  suspend-inclusive BOOTTIME protection. No real-provider/client or router
  performance acceptance is implied.
- **e4123fc:** Root independently verifies 300 workspace tests, exact musl
  filter/retention/reap/FD-reuse preflight and 120 matching source inputs. The
  fresh-hash optimization passes scoped review: both descriptors must retain the
  original full security metadata around one fresh ELF/role/hash read; both
  separate Handoff checks remain. ARM130 still fails before sender permission.
  The recorded phase improves from ARM129's 2081/2127 ms to 1477/1506 ms; this is
  component timing, not a router performance comparison or handshake PASS.
  Both failed ARM attempts retain empty durable-completion lists and resources;
  Root observes three terminal tables, kills/reaps only each exact stopped guard
  without resume, and verifies all actor-unit absence before nonce archival.
- **5597465:** Independent workspace298, exact musl preflight and transfer review
  pass. Native125 post-spawn setup failure retains the actual helper/guard and
  prepared expiry authority (zero active expiry actors), actually reaps the
  helper, then B completes three fresh inspections. Native126 holds A to its
  original deadline with 19 B inspections during and two after; Native127 passes
  all ten positive cases and Root copies three timely durable completions with
  no resume. ARM128 held test passes with 18 B inspections during and two after.
  Runtime event counts include separate witness and result labels. ARM129's
  positive test fails before sender permission; its daemon positive alone does
  not establish ARM inspection acceptance.
- **0059fbf:** Strict source/artifact binding and exact musl preflight pass;
  one-file restore correction passes scoped review. Native122 passes ten cases.
  Root copies the protected public witness with three verified-before-deadline
  completions and no expired-actor resume. Provider/recovery health is synthetic.
  Native123 held-inspector test observes A terminal 36.67 ms after its original
  deadline, actual reap/revocation/no ACK, and B completing 19 fresh inspections
  during the stall plus two afterward. Three runtime events include a witness
  and label, not three different fault shapes. Native124 fails after injected
  post-spawn setup error: retained socket fd92 is unregistered and blocks B.
  Root observes the helper already absent, kills/reaps only two exact stopped
  guards by PIDfd, and proves unit/cgroup absence before nonce archival. No
  setup-failure neighbor-progress PASS is claimed; resources remain.
- **45bd707:** Root independently verifies all 120 archive/current inputs,
  exact commit binding, exact musl filter preflight and 298 passing workspace
  tests. Strict static checks and scoped review pass, including the d722 fixes.
  Native120 passes three cases, including genuine reduced-guard daemon inspection
  and fresh reinspection, then fails before sender acceptance. Pure native debug
  stderr output panics under the intended filter; no stderr allowance is added.
  Root observes all three exact terminal tables and absent expiry actors, but
  journal completions are empty: no durable-completion PASS is claimed. Root
  kills/reaps only the exact stopped guard by retained PIDfd, without resume;
  all actor units/cgroups are absent before nonce archival. Resources stay.
- **d72297f, held:** 120 archived inputs match current source at freeze. Static
  x86/ARM builds and both init stability checks pass; the agent reports 100 launch
  tests, strict clippy and formatting passing. Root independently reproduces
  failure of the exact x86 musl filter preflight; debug/glibc passing does not
  override it. Review also identifies consuming inspector attachment losing
  existing owner handles on failure, a blocking held-fixture checkpoint and an
  insufficiently specific dead-peer rejection oracle. Corrections and a fresh
  freeze/review are required before native execution. All failed evidence stays.
- **173acb9:** Root reran the full workspace: 290 pass, 0 fail, 2 ignored;
  all 118 current inputs match. Strict lint/format/static builds pass. Scoped
  review passes the held-placement fixture. Native x86 114 and ARM 115 expire A
  at its original Spawn deadline, actually reap helper and gated target, deny
  control/registration, and keep B auditing during/after. Shared OFD proof is
  explicitly not a sole-survivor claim. Current regressions: x86 host 116 passes
  three cases, journal 117 passes six, concurrent legal mutations 118 passes two.
  ARM normal 119 passes 17 cases with six captures/112 records, zero
  forbidden markers and zero kernel drops; this is Starting/observer/daemon
  component evidence, not real-client acceptance. These remain component gates.
- **b518b15:** Scope placement uses the actual retained PIDfd via `PIDFDs`,
  with no numeric fallback. Scoped source/codec review passes; Debian terminal
  111 passes seven cases, Arch scope 112 and ARM scope 113 each pass. Independent
  native readbacks retain identity, cgroup and kill-policy checks.
- **6716872:** Guard-death test 109 passes seven cases, including all three
  timely durable completions, actual sibling drainage and sole-survivor OFD
  retention until kill/reap. The controlled death fixture uses a disclosed
  test-only self-stop after containment; no expired actor is resumed. Full90
  watchdog 110 passes, actual stopped state 1.64 ms after original deadline.
- **38556ef:** Regular terminal 107 passes seven cases: parent-owned native
  expiry, synthetic Ready/recovery/publication and exact durable completion
  while the guard remains frozen. Guard-death 108 retains three timely verified
  completions but fails its self-stop fixture; the corrected 109 is separate.
  Native105 StopFailed outcomes and 106 preflight route collision remain failed;
  old routes/tables/resources are retained. New terminal endpoints are unique.
- **97946a1:** 279 ordinary tests plus strict checks/static builds and scoped
  review pass. Native x86 run 98 passes all three component cases. The fixed
  observer is route-only, caps0, NNP and exact-FD confined; a routing mutation on
  its actual socket is denied. A's held observation expires at its original
  deadline and is drained; B completes two more fresh host audits before actual
  owned MTU drift is rejected against the canonical model. Both guard identities
  are stopped and killed/reaped exactly. Earlier native 96 exposed a missing
  seccomp readback permission; 97 exposed a test-only asynchronous-stop race.
  Both failed histories and resources remain, with exact actor-drain proofs.
  ARM run 99 passes the same three cases; full90 and affected source-specific
  regressions remain pending. Full90 run 100 reached its original deadline but
  failed an immediate stopped-state test witness; a test-only bounded witness
  fix and another full wait are required.
- **ea2f85e:** 271 ordinary tests and strict lint/format/static builds pass;
  independent fixture/ordering review passes. Native x86 run 94 activates two
  members to Bootstrap through real producer/link/quarantine paths and audits A
  again after B. Both separately scoped guards issue overlapping authenticated
  legal BeginTerminal requests: the first writer is held until the second is
  queued, then both durable ACKs complete within their original two-second
  deadlines. Final protected disk reopen matches exact canonical bytes and both
  guard identities; both guards exit zero and are reaped. This tests a shared
  parent host model against a test-learned VM baseline, not production authority
  admission or routed/provider/client acceptance. ARM run 95 passes the same
  two cases, including both original deadlines, disk identities and clean reaps.
  Earlier run 93 correctly refused an unregistered directory FD; fixture ordering
  was corrected without descriptor exceptions, and all failed resources remain.
- **9a13491:** 270 ordinary tests and strict lint/format/static builds pass,
  including both init hash-stability assertions. Independent scoped review accepts
  both concurrency fixes: authenticated mutations queue within their original
  deadlines; reads crossing neighboring commits use bounded owner-authorized
  digest windows and revalidate the selected entry. Native journal run 89 passes
  all six component cases. Deployment run 90 passes the actual held-reader/
  neighboring atomic-intent commit and stalled-A/surviving-B checks; B completes
  39 fresh reads after A expires. ARM run 92 also passes both cases; B completes
  31 fresh reads after A expires. These are component checks. A genuine pair of
  Bootstrap guards issuing overlapping legal mutations remains pending. The
  same-source full 90-second watchdog run 91 passes: actual stopped state was
  observed 31 ms after the original deadline, followed by exact kill/reap.
- **4ce0755:** 263 ordinary tests and strict lint/format/static builds pass. Native
  two-guard tests pass on x86 (87) and ARM (88): B completes 38/32 fresh read
  requests after A stops at its original deadline. This is control/I/O proof,
  not routed neighbor acceptance. Review found that overlapping valid mutations
  freeze B; a neighboring commit can also invalidate an in-flight read. Both
  remain unfixed at this frozen source and are the fresh implementer's first task.
  Owner service identity is deployment-stable; dynamic allocation transitions
  remain gated.
- **46e87aa:** 261 ordinary tests, strict lint/format/static builds and scoped
  independent review pass. Native journal run 85 passes six cases: actual fork
  refusal, three guard-to-owner read jobs, confined successful atomic write and
  fsync/readback, independent reads beside a stopped writer, and retained lock
  until writer death. Stale pending-entry reads are rejected. This remains an
  I/O component gate; legal routed lifecycle mutation and multi-guard operation
  have not been accepted.
- **e47e6ed:** 256 ordinary tests and strict lint/format/static builds pass;
  property-interface/readback fix passes independent review. Native scope placement
  passes on Debian (75) and Arch (79), including exact process/cgroup, actual kill
  policy and stopped-state proof. Debian watchdog run 76 passes the original full
  90 seconds (90.915 seconds controller elapsed), with the guard observed stopped
  49.5 ms after its original deadline and then reaped. Arch run 80 passes all 17
  component cases; restricted socket profiles pass x86 (77) and ARM (78). These
  do not implement or certify operational owner/journal/host-model integration.
- **ea749adc:** 255 ordinary tests, strict lint/format/static builds and independent
  dependency-fix review pass. Native Debian run 72 passes all 17 cases; six captures
  contain 112 records, zero forbidden markers and zero kernel drops. The persistent
  descriptor leak is resolved through minimal dependency features. Owner scope run
  73 found an incorrect systemd property interface, corrected at e47e6ed. ARM run
  74 also passes all 17 cases with six captures/112 records/zero forbidden markers
  or kernel drops.
- **e932 / e68:** init was isolated from host supervision; both static builds and
  manifest hash-stability checks pass. e68 has 253 passing ordinary tests and a
  scoped source review pass. Native normal and scope probes expose unexpected
  persistent Unix sockets from the D-Bus dependency enabling Tokio process support.
  A fresh-process regression reproduces the leak; minimal dependency features are
  being implemented. Full native regression and the 90-second watchdog remain
  pending. Failed attempts and ownership records are retained.
- **7ee4e502:** 250 ordinary tests passed, 0 failed, 2 ignored; strict lint,
  formatting, static x86/ARM builds and independent source/context binding passed.
  The two integration review findings are fixed; scoped independent re-review
  accepts both with no new blocking findings. External owner/lifecycle work has
  resumed. This checkpoint adds no enrolled provider/client acceptance.
- **bc10ba95:** 244 ordinary tests and strict lint/format/static builds passed.
  Debian x86_64 run 64 and emulated ARM run 65 passed the exact zero-capability
  operational socket profile: Unix/UDP/TCP positives and prohibited syscall/socket
  negatives. Provider, enrolled runtime and clients were not exercised. Independent
  scoped review found two Important orchestration defects (in-flight heartbeat
  cancellation on ordinary failure; final ACK aggregate deadline). Both were corrected and independently accepted at 7ee4e502.
- **6cdaeb4c:** 244 ordinary tests passed, 0 failed, 2 ignored; strict lint,
  formatting and both static builds passed. Debian actual run 62 passed all 17
  normal component cases; run 63 passed seven terminal cases, including exact
  post-enforcement Ready publication and repeated Ready validation. These use
  synthetic provider evidence, not actual operational provider/client traffic.
- **a996d925:** 233 ordinary tests passed, 0 failed, 2 ignored; strict lint and
  both static builds passed. Debian actual run 61 passed all 17 component cases,
  including real kernel WireGuard GET after secret-buffer sanitization.
- **8e6b250b:** actual run 60 passed six synthetic native guard/Ready/recovery/
  independent-expiry cases. Provider responses are synthetic; this is not real
  provider, application traffic or operational readiness proof.
- **cd5a246d:** observed guard-freeze run 58 and guard-death run 59 each passed
  four cases. The death test verifies the sole surviving writer retains the lock;
  all writers exiting does not clear the durable reuse/cleanup barrier.
- **55b006:** emulated ARM run 56 passed all 17 Starting-component cases after
  strict deadline-completion fixes. The aggregate emulated suite cap is 120
  seconds; product phase/health/handshake/watchdog deadlines are unchanged.
- **66d8f676:** Debian run 45 and Arch run 46 each passed 17 component cases.
  Six captures per run contained 112 packet records, no forbidden markers and no
  kernel drops. These captures use owned synthetic fixtures, not real clients.
- **e898e935:** seven transport scenarios passed; 42 capture summaries contain
  864 packet records, no forbidden markers and no kernel drops.
- **Void run 54:** prerequisites passed after configuring the owned identity-free
  VM for nft-compatible Docker; product admission refused UnsupportedPlatform.
  This is not a platform PASS.

Results apply to their exact frozen sources. Failed attempts, test weaknesses and
review corrections are preserved; a later pass does not erase earlier evidence.
No static/component result substitutes for outstanding end-to-end acceptance.

Accepted component handoff: `.superpowers/sdd/implementation-2026-10-26/process-inspection-report.md`.
Active continuation brief: `.superpowers/sdd/implementation-2026-10-26/operational-assembly-brief.md`.
Intermediate handoff: `.superpowers/sdd/implementation-2026-10-26/operational-assembly-report.md`.
Active writer report: `.superpowers/sdd/implementation-2026-10-26/fork-boundary-report.md`.
Controller ledger: `.superpowers/sdd/implementation-2026-10-26/progress.md`.
