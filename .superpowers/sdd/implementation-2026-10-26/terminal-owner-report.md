# Terminal owner continuation — source report and handoff

Current status: SOURCE_PAUSED / NEEDS_CONTEXT at173acb9; see FINAL handoff at end.
The interim sections below are historical and their pending statements are
superseded by the later source-specific records. All nine remain active.

Initial implementation status: no new source freeze/native oracle yet. Prior accepted source14851d67f9e207076bf0d37a825b89df533b502c and native
979 evidence remain exactly as recorded in host-authority-report.md. Native102
copied-Journal failure is the observed RED for this connected repair. No old actor
has been resumed, no privileged lab commands/credentials/production writes used.
Real HEAD/index untouched; source is dirty work in the existing rust/v2 worktree.

## Current connected code

- `owned.rs`: remote retained executor lease uses matched original Revalidate ACK
  then only native AllocationTransaction OFD duplication, never copied Journal
  revalidation. Local authority retains its native creator checks.
- `owner.rs`/`transport.rs`: HostAuditClient carries privately bound Domains. Both
  GuardTransport and ObservationAudit choose explicit Local/Remote expiry paths;
  the remote path requests parent-created actors in all three native sibling roles.
  Public Admission launch continues to refuse operational activation.
- New `expiry_owner.rs`: parent factory retains fixed policies/ns pins/binding/OFD
  lease. Parent BeginTerminal original Progress.sent_at is the ONE lifetime anchor,
  returned unchanged to guard and used for all three Session/90s clocks. No first
  Spawn caller-selected timestamp or new job-completion anchor is accepted.
- Fixed actor fork occurs AFTER guard fork. Its completion writer is never present
  in guard memory/FDs. Only original parent-control and retained pidfd descriptors
  cross the authenticated original Spawn reply. Exact two SCM_RIGHTS, bounded
  packet, no CTRUNC/TRUNC/extra ancillary kinds, CMSG_CLOEXEC; PIDfd fdinfo/start
  verified. Ordinary replies reject all executor metadata/rights and remain poisoned.
- Parent actor joins exact namespace but remains behind a private gate. Separate
  fixed placement process performs authenticated PID1 scope placement and complete
  policy readback; parent polls its retained pidfd and requires clean EXIT0 and
  original Spawn two-second budget before private receipt decode and actual
  cgroup/ns/PID-start verification. Private FixedRegistration enters existing FIFO
  durable journal BEFORE release or control grant. Guard then confirms Registered.
- Original deadline covers placement, queue, durable write, confinement and final
  Spawn ACK. Shared owner loop never blocks awaiting the placement D-Bus roundtrip.
  No actor scope/capacity/lease is released on cancellation or signal request.
- Fixed executor sends Started, original accepted Health/Liveness notices, then
  original terminal result/deadline/finished_at over its dedicated completion
  endpoint. Parent reconstructs LeaseClock state. Only private non-deserializable
  FixedCompletion can enter completion persistence; ordinary guard CompleteExecutor
  is rejected. Completion journal polling is independent of guard-live RPC polling.
  Original finished_at+2 bounds durable enqueue/IO. Existing global uncertain-write
  fence is retained and never cleared to force a completion append.
- Per-actor malformed/EOF failure is retained; valid earlier/sibling receipts are
  not discarded. Member completion persistence failures retain queued receipt and
  terminalize that member while the deployment loop continues other members.
  Standalone supervisor returns retained TerminalGuard on completion failure.
- Guard drops SYS_PTRACE from permitted/effective/inheritable/bounding and sets
  NNP; owner and fixed expiry children are nondumpable. Distinct exact native Guard
  credential role is required (not a relaxed setup preflight). Publisher admits
  the two explicit valid native Setup/Guard roles. Native fixture asserts guard
  pidfd_getfd(11) EPERM and proc fd11/mem denial. Positive daemon/sender operational
  inspection under reduced guard privilege remains a pending runtime gate.
- Executor stop now proves actual original guard pidfd death OR exact PID/start
  stat T read via preopened read-only FD13 before containment. Signal delivery
  alone is not counted. Dead guard is a legitimate terminal case. Outcomes remain
  VerifiedBeforeDeadline/LateVerified/Failed/StopFailed with original deadline.
- Early setup: clone3(CLONE_PIDFD) atomically returns exact pidfd at fixed expiry/
  placement birth. Pre-release inventory failure stores exact pidfd+control in a
  bounded early-fork quarantine, requests kill and waits for real nonblocking reap.
  Factory stores UnregisteredActor BEFORE fallible inventory/identity extraction.
  Cancelled placement/target handles remain until actual drain; no scope reuse.

## Native fixtures changed, not yet run

Terminal/TerminalDeath use protected existing nonce -> launchlab-<nonce12>, one
fresh task8b2-PID directory, real ExternalOwner+JournalServer+HostAuthority. Parent
polls nonblocking during guard setup/Ready/health/publication; guard remains frozen
or dead during all three containment/completion writes. No SIGCONT exists in the
expiry fixture. Frozen-guard case proves exact tables and three durable original
completions then kills/reaps guard. Death case deliberately stops host executor
AFTER native containment and its authentic completion notice, requires other two
actual pidfd exits/reaps, drops parent/guard leases, proves sole-survivor OFD lock,
then kills/reaps survivor (never resumes), proves re-lock and durable reuse/cleanup
refusals. Synthetic evidence remains component-only, never provider/client Ready.

## Review dispositions

1. Privileged guard SCM_CREDENTIALS forgery: replaced proposed inherited writers
   with parent-created endpoints after guard birth, plus native no-ptrace boundary.
2. Guard-chosen first timestamp: replaced with canonical BeginTerminal frame time.
3. Completion failure aborting shared loop: scoped member terminal handling.
4. Transfer/release before durable registration: private parent registration and
   original FIFO write now precede fixed actor release/control transfer.
5. Completion client latch: malformed operation-specific payload re-poisons client.
6. Valid receipt discarded by later sibling failure: per-actor result isolation;
   journal enqueue borrows front and removes only after success.
7. Early postfork failure loses actor: atomic pidfd birth and retained early/
   unregistered slots. This new failure handling still requires native validation.

## Checks so far (ordinary, unprivileged)

- cargo check -p vprouter-launch --all-targets --offline: PASS before latest
  retention/atomic-fork refinements; covering full rerun follows.
- Existing launch lib suite: 82 PASS before added adversarial tests.
- Latest cargo test -p vprouter-launch --lib --offline: 87 PASS / 0 failed,
  `/tmp/terminal-tests3.log`. Added real framed unexpected descriptor/metadata
  poisoning tests; native Guard role credential tests; private receipt original
  binding/deadline/outcome and stale/future/NaN notice-time rejection.
- Intermediate cargo test --workspace --offline: PASS before final five added
  tests/retention refinements; NOT final coverage (`/tmp/terminal-workspace1.log`).
- cargo fmt --all run after edits. Strict clippy, covering whole workspace,
  static x86/ARM, BOTH init hash stability, exact source freeze and independent
  scoped review: still pending. No new privileged/native oracle executed.

## Unsafe/capability/FD inventory

Unsafe stays kernel.rs boundary: capget/capset/bounding removal, dumpable/NNP,
atomic clone3 pidfd, fixed pre-fork descriptor duplication, exact direct-child
waitpid, fixed pidfd signal and cfg(test) negative FD access. Placement role fixed
FD0..2 null,3 private reply,4 exact target pidfd,5 original OFD lease, then bounded
PID1 D-Bus/cgroup descriptors tracked by native inventory. Parent remains canonical
owner. Expiry fixed FD0..2 null,3 guard control,4 original guard pidfd,5 OFD lease,
6/7 primary netfilter socket/timer,8/9 recovery socket/timer,10 BOOTTIME timer,
11 parent-only completion writer (remote only),13 preopened original guard stat.
Cfg(test) post-containment host checkpoint adds only self pidfd12 and exact self
SIGSTOP filter permission. Production seccomp permits completion sendto11 and
read-only pread13; no lease write/close/dup/flock, sendmsg or exec authority added.
Expiry remains NET_ADMIN-only; placement is a fixed temporary host setup role.

## All-nine status / next steps

1 secret lifetime/shared health: earlier implementation retained; final integrated
   verification still required.
2 shared host authority: accepted predecessor native gates retained; new connected
   terminal runtime gate pending. Durable dynamic allocation cohorts NOT implemented.
3 operational runtime: connected terminal owner source under test. Full staged
   public lifecycle, recovery, retirement, provider/real clients NOT complete.
4 five Mullvad+explicit direct: not integrated/accepted; no fallback gate unchanged.
5 persistent clients: real kernel/userspace enforcement and traffic acceptance open.
6 identity-preserving migration: two independent local legacy apply/resume/rollback,
   adapters/real releases/interruption matrix open.
7 supported platforms/services/provenance: prior component x86/ARM evidence only;
   Arch/Void actual lifecycle/update/reboot/rollback/uninstall open.
8 hostile traffic/captures: full1/5/direct/6 and fault matrix open.
9 repeated 10-minute same-host comparisons/optimization/real24h mixed soak: open.

Continue with strict tests, exact freeze and Root native105+ terminal/death gates;
then durable cohorts/staged lifecycle/retirement and remaining all-nine work.
Do not call this a complete task. If context runs out, persist exact paused source,
errors and next commands; final fresh whole-branch verification only after all work.

## Exact corrected freeze 5ceb — source PAUSED for scoped/native gates

Final current source **5cebfc1c82e8ac03a76995539f3090eaf9d39874**;
`target/continuation-20261026T222908Z/candidate.json`. Direct tar/current comparison
confirmed **118 files, 0 mismatches**. Source tar SHA256
`dde18d3185f4d279f97c08c6fa7fd9833f98c4c9db38745b391a50c99cece15b`.
Real HEAD remains c6a138c00b70163ba3cbfdf350e5cf8e2f3a3c6a; real index preserved.

Both static musl payload builds and BOTH original init-hash-stability checks PASS.
AMD64 payload SHA256
`add435a9d9c9d8d80f00c71b0645f09b7532fbd64aade3eea8801e2607f34480`;
ARM64 payload SHA256
`5e5b97fe2c62e8373e4d99e03ef4774846c6b1d7a884a77078c71f899324c227`.
Context hashes unchanged from b727 (guard payload is external to gateway image):
amd64 `6593aadb09f616687b196a340f32a57f598ec49db0d4ac189421f085ffc1b14d`,
arm64 `e269cadc6153415474ed9404ebe577d2b4f9ec869a9893b1d6f92727eb49b919`.
Root must copy candidate-local contexts and strict-verify four roles/source binding
before fixed owner-terminal105. Source stays PAUSED pending scoped/native gates.

Predecessor b727aaf72a52f0c8d462c7e2f5fd82c17c55b835 at
`target/continuation-20261026T222449Z/candidate.json` is retained, no native run.
Scoped review found remaining persistence-error drain bypass after that freeze;
5ceb fixes it: actor collection/reap runs even when persistence is disabled; valid
receipts retain original timestamps; finished includes all unregistered and cancelled
placement slots and cannot bypass through completion_error. Failed unregistered
reap is retained per slot, so other actor polls continue. Global early-fork errors
retain terminal owners and continue deployment polling; global early slots must be
actually drained before the all-terminal return predicate succeeds. No deadline
reanchor or shared fence clearing.

Latest commands/results:
- `/tmp/terminal-workspace2.log`: covering workspace **286 PASS / 0 failed /
  2 existing ignored** before final scoped drain-only correction.
- `/tmp/terminal-tests5.log`: corrected source launch lib **89 PASS / 0 failed**.
- `/tmp/terminal-clippy4.log`: corrected strict workspace/all-target clippy PASS.
- cargo fmt --all --check: corrected PASS.
- `/tmp/terminal-build2.log`: corrected both static builds/init assertions PASS.
- Added regression coverage for valid/error/valid sibling receipt retention and
  rejected durable enqueue retaining original queue front, in addition to the five
  earlier new tests. Runtime provenance remains a native gate, not a unit assertion.

Next root oracles: exact owner-terminal105; owner-terminal-death106 only after
first positive. Fixed runners already exist. Neither has run on this source yet.
Then affected full original90 watchdog, host/Bootstrap/journal/normal regressions.
Native held-placement A with B progress remains **NOT_RUN and no fixture switch
implemented yet**: asynchronous placement architecture is source evidence only.
Positive actual daemon/sender native inspection under reduced guard privilege is
also pending; retain the negative endpoint access proof as well. These belong to
continued connected runtime work, not a public-launch or all-nine completion claim.

All-nine table above remains authoritative for outstanding implementation. This
is a frozen connected component awaiting runtime proof, not overall DONE.

Read-only continuation trace while5ceb source stays paused: Handoff.prepare and
Handoff.verify call Process.revalidate, which reopens actual proc namespace/root
objects; daemon.verify_current reopens daemon ns/exe/root/etc/tailscale.json; Sender
verify reopens ns/net/exe. Actual roles use UID65534/nondumpable peers. The guard's
new no-SYS_PTRACE boundary likely requires an owner-held native process-inspection
receipt for these operational checks. Do NOT restore guard ptrace or skip/reuse
cached inspection assertions to obtain Ready. Positive actual daemon/sender
inspection and negative private-endpoint access must both be demonstrated before
operational lifecycle admission. Synthetic terminal Ready/publication does not
exercise these positives. No changes were made for this next slice while frozen.

## Native105 on5ceb FAILED; original evidence retained

Root ran fixed owner-terminal105 on exact5ceb. PASS6 included two Bootstrap cases,
real three owned placements/leases, synthetic repeated Ready/publication, ordinary
provider failure and four fresh recovery samples, then actual frozen guard.
Final oracle returned `actual_lab:interrupted`. Root read-only artifact:
`target/lab-state/terminal105-actor-journal-reference.json`; retained guest fixture
`/var/lib/vprouter-v2-lab/task8b2-70623`.

All three original executor completions were durably persisted as **StopFailed**,
with common ORIGINAL deadline209631.587893973 and finished_at values
209626.594429683 /209626.590685048 /209626.590684299 (approximately5s before deadline).
Root proved guard70770/start20962037 actually T, sole cgroup member/inode191119,
exact5ceb payload SHA; all3 expiry processes/cgroups/units actually gone. Source
native loop reached final journal assertion only after three exact terminal table
checks, canonical three completions and three actual reaps. Root independently
inspects native deny tables before exact stopped-guard kill/reap; no SIGCONT.
No retrospective bounded-containment/full PASS is assigned to this failed run.

Code-backed cause: stop_terminal_guard first called generic kernel::wait_ready,
which calls libc::poll. On x86 that issues SYS_poll; terminal_filter intentionally
allows SYS_ppoll used by existing rustix event polling, not SYS_poll. All3 checks
therefore failed immediately under seccomp before actual T/death proof. The real
frozen guard and timely terminal writes do not turn their recorded StopFailed
outcomes into successful receipts.

Correction currently building: dedicated rustix ppoll predicate for original guard
pidfd before/after SIGSTOP and the dead-between-check-and-signal race. Filter is
NOT widened. Exact PID/start stat T remains required unless actual pidfd death.
Same predicate now runs immediately under the installed terminal filter before
Registered, so incompatibility refuses initialization/Ready instead of appearing
at expiry. Focused BPF test keeps SYS_poll denied while ppoll and read-only stat13
are permitted and pread on control/lease/completion descriptors denied.
`/tmp/terminal-tests6.log`: launch90 PASS; `/tmp/terminal-clippy5.log`: strict
workspace/all-target clippy PASS; fmt PASS. `/tmp/terminal-build3.log` is the new
static/source freeze build; source edits pause while it runs. New native counter
is Root-controlled (likely106 terminal rerun; death follows first positive).

### PPOLL correction frozen dcec — SOURCE PAUSED

Exact candidate **dcec1ba7c60a29f545d66a4f63a39c0ede3800f1**,
`target/continuation-20261026T223927Z/candidate.json`;118files/current0mismatch.
Source tar SHA256
`bcc2bdfeddcc4bba46f4e7461ccddf666d656e064ee3a3c4873279910625c298`.
AMD64 payload `7916050378b46c5ecbb7470678bba1efd82e7b4477917a9faa1c46d11e56ba72`;
ARM64 payload `be581b1652393a6a359989d405d8cefc154c684f46691b990d385fe36c6a36d2`.
Both static builds and BOTH init-stability assertions PASS. Context hashes remain
6593aadb.../e269cadc..., but Root must retain candidate-local strict verified copies.
Diff5ceb..dcec changes only kernel.rs for the explained stop-observation syscall
correction/native pre-registration positive/filter regression. Root requested
next-counter terminal rerun after105 exact drain and scoped review; no new source
edits while these gates run. No native PASS yet for dcec.

Root105 final retention/drain update: `target/lab-state/terminal105-deny-reference.json`
records independent read-only proof of all3 exact owned terminal tables using the
journal-pinned namespace identities. All3 expiry process/cgroup/unit absences were
already proven. Root reverified original guard T/sole member/start/inode/executable,
used only that retained pidfd SIGKILL (no SIGCONT), observed actual exit, then
proved all4 scopes plus owner unit/cgroup absent before nonce archive105 PASS.
Resources and all3 StopFailed durable records remain retained. This drainage and
native containment evidence does not reinterpret native105 as a passing oracle.
Root has copied/strict-verified dcec contexts; scoped ppoll review and native106
terminal rerun are pending. No source edits after dcec freeze.

## Native106 preflight blocked; nonce-specific terminal fixture

Native106 on dcec did not execute a child or owner probe and created no nonce or
fixture directory: root preflight rejected the fixed185.65.134.88 route retained
from105. This is a preflight block, not a second runtime failure of the stop fix.
Root preserves105 routes/resources and changes only terminal/death runner nonce
selection: at most16 read-only collision checks, then protected nonce creation.
Normal actual runner keeps its original strict fixed-route check.

Authorized cfg(test)-only fixture correction uses one nonce_wan_pair helper shared
with Bootstrap: endpoint185.66.<nonce byte0>.<nonce byte1>, host lastbyte XOR1.
Terminal/Death read the protected nonce once for allocation and WAN setup and pass
this endpoint through profile, validated allocation, host authority Plan, missing-
DNS rejection and actual guard activation. Expiry lab health configuration takes
its endpoint from that exact guard's retained native Plan. This prevents a fixed
profile from silently changing the health binding. resources.json includes
synthetic_endpoint/synthetic_host. WAN namespace/link/address/route construction
remains exclusive add; no route replace/delete or previous-evidence cleanup.
Normal scenarios still choose fixed ENDPOINT/HOST_WAN before the same helpers.

Focused regression checks exact mapping for00/12/ff byte examples, malformed
nonces, profile endpoint, validated allocation/config agreement, Plan endpoint,
and valid health binding. Initial RED failed on absent endpoint APIs; GREEN then
passed. Launch91 PASS (/tmp/terminal-tests8.log), strict workspace/all-target
clippy PASS (/tmp/terminal-clippy7.log), fmt PASS. Initial clippy6 found a dead
wrapper introduced during refactor, removed before the passing rerun. No unsafe,
production authority, terminal outcomes, deadline, or role FD changes in this
slice. Static x86/ARM freeze builder /tmp/terminal-build4.log running, BOTH original
init-stability assertions preserved. Source edits paused pending exact freeze and
root scoped review/native107. Native dcec stop-fix positive and terminal-death
positive remain NOT_RUN; all-nine outstanding table unchanged.

### Nonce endpoint fixture frozen3855 — SOURCE PAUSED

Candidate38556ef48c3dac63370f3eaaa3c002e4b1d4c2f9 at
`target/continuation-20261026T224935Z/candidate.json`. Staticboth/BOTH init-hash
assertions PASS, source archive118files/current0mismatch, realHEAD unchanged.
Source SHA1498ed88199b69205a719da9e43ae531527d7b88d3ce669fa14c2aaea3d44914;
amd64 payload da62a1f138c083886b82dfc0a4349086726679dfd2e144e687fa98681384e80f;
arm64 payload76f59a7107960b787d8c9dfa13404501fb3e2541ae02b7b7b2964c060f1a6498.
Contexts remain6593aadb.../e269cadc...; Root notified to copy and strict-bind both.
Diffdcec..3855 only transport_lab.rs/expiry.rs cfg(test) fixture plumbing/test.
Root native107 terminal after scoped review, then death positive if accepted.
No source edits until gate feedback; overall all-nine task remains active.

Root native107 on exact38556ef PASS7, retained fixture
`/var/lib/vprouter-v2-lab/task8b2-71163`. Passed real parent-owned placements,
synthetic Ready/recovery/publication, actual guard stop and native three-plane
containment, then final independent_frozen_guard_terminal_host_transport_data_
exact_parent_durable_completion_without_resume. This is the first accepted full
positive for dcec ppoll fix and legitimate parent completion collection. Native105
StopFailed records remain unchanged; native106 remains preflight-only blocked.
Scoped review dcec..3855 PASS with no Critical/Important findings. Root native108
owner-terminal-death now running, same immutable source/contexts. Source stays
paused through death and affected full90/host/journal regression gates. This is
synthetic terminal lifecycle proof, not real provider/client or public activation.

## Native108 death fixture FAILED; cfg(test) checkpoint filter correction

Root native108 exact3855 reached the same first6 positive cases, expected guard
ChildFailed after exact kill, and3 completion writes, then final Deadline. Fixture
`/var/lib/vprouter-v2-lab/task8b2-71481`; root reference
`target/lab-state/terminal108-actor-journal-reference.json`. Root read-only verified
all4 process/cgroup/unit absences including host (not T), all3 durable
VerifiedBeforeDeadline receipts: transport210761.894957979,
host210761.896673629,data210761.896295199; originaldeadline210768.74013077.
This establishes retained successful containment/collection but NOT sole-survivor
lease PASS. Root archives using actual all4 absence; no signal/resume needed.

Code cause is test-only BPF composition: exact_args(fd4,SIGSTOP) rejects mismatched
fd12 immediately, so the later exact_args(fd12,SIGSTOP) checkpoint block is never
reached. Host emits receipt, attempts self-stop, receives EPERM and exits. Oracle
correctly waits for exactly2 reaped actors, not3; there is NO finished() circular
wait. Death loop never calls production finished(). No assertions are omitted.

RED `/tmp/terminal-checkpoint-red.log` reproduces checkpoint=true fd12 denied.
Fix cfg(test) prepends exact checkpoint alternative whose mismatch jumps to the
syscall reload then unchanged production fd4 rule. No production filter change;
false still denies fd12. GREEN `/tmp/terminal-checkpoint-green.log`. Tests cover
fd4/fd12 valid stops, SIGCONT/SIGKILL refusal, nonnull siginfo, flags, highword
variants of all constrained args, and other descriptors. Same durable3 original
VerifiedBeforeDeadline/actual host T/other2 actual deaths/OFD sole-survivor lock/
exact host kill/final durable reuse+cleanup refusal requirements remain intact.

### Checkpoint correction frozen6716 — SOURCE PAUSED

Exact6716872277acacc3e38b81dc189769ccc71d65cb,
`target/continuation-20261026T225806Z/candidate.json`;118files/current0mismatch.
SourceSHA02ffc1312dbadd44660b83ccb7af7a20c76f7216e33f8dbe62c0a6c8877602fc;
amd64payload ea2220b870dda90390418514a1864921c0f4a1e3731e21c83a27c3a208b9d790;
ARMpayload89303e754b3aaa74693154c873bb02baae62e9fbc04dd7ff0a1f80dd210f795d.
Launch92 `/tmp/terminal-tests9.log`, strictclippy `/tmp/terminal-clippy8.log`, fmt,
staticboth/BOTH initstability `/tmp/terminal-build5.log` PASS. Diff3855..6716 only
kernel.rs cfg(test) correction+test. Root notified to retain/strict-bind contexts;
next109 death after scoped review. Root108 archive PASS with actual all4 plus
owner unit/cgroup absences and no signals necessary. Source remains paused while
terminal-death/full90/affected regressions run. Parent ProcessInspection broker
plan remains read-only until death/full90/held-placement neighbor gates.

Root native109 on6716 death PASS7, fixture task8b2-71873, including actual guard
death, three native scopes contained, three original timely parent-persisted
receipts, actual host self-stop, other2 death, sole-survivor OFD lease until exact
host SIGKILL, no SIGCONT. Scoped checkpoint correction PASS. Root full original90
native110 now running on same6716. No mutable context refresh permitted during it.

Next small mechanism: official systemd v257 dbus-scope.c lines129-164 accepts
transient PIDFDs array 'h' and calls pidref_set_pidfd/unit_pid_attachable:
https://raw.githubusercontent.com/systemd/systemd/v257/src/core/dbus-scope.c .
Root read-only native authenticated D-Bus Manager.Version reports Debianx86/ARM
257.13-1~deb13u1, Arch262-1-arch. Replacing numeric PIDs with actual retained pidfd
prevents delayed StartTransientUnit requests attaching a reused numeric PID; no
unsupported-property fallback permitted. Existing manager authentication/unit
fail mode/full native property/start/cgroup readbacks remain required. A new
serialization RED regression was added only; production still unchanged while110
runs. Current workspace has this RED test beyond frozen6716; no new freeze yet.

Root full90 native110 on6716 PASS: original guard72198/start21146075,
deadline211550.763380587, observed actual T211550.765018148 (+1.64ms), exact
kill/reap PASS, no rearm. Root clears PIDFDs production adaptation and next held-
placement gate; native109 death and107 regular terminal positives remain scoped.

PIDFDs adaptation now implemented in supervision.rs only: parent duplicates the
actual retained child pidfd, inventories it, keeps its own Rc pin while the
manager future borrows the duplicate through zbus::Fd. The request encodes
PIDFDs:ah with one SCM_RIGHTS FD. Same authenticated unique PID1 owner, existing
properties/unit fail mode/active+policy+native membership/start readbacks and
original deadlines remain. Unsupported PIDFDs yields failure, never numeric
fallback. A delayed request retains original kernel identity even after reaping.
No new unsafe or permission restoration. Placement helper gains one temporary
registered duplicate during the bounded manager call; all existing role FDs and
completion endpoint isolation remain. This does not reconcile arbitrary failed
scope state or grant cleanup; original intents/lease/slots remain retained.

Serialization regression verifies exact ah variant, header UnixFds1, FD list1,
received pidfd native identity and own fdinfo Pid, and absence of PIDs. Initial RED
also caught zbus6 builder API mismatch in test; corrected before GREEN. Launch93
PASS `/tmp/terminal-tests10.log`; strictclippy `/tmp/terminal-clippy9.log`, fmt PASS.
Standard both-static/initstability builder `/tmp/terminal-build6.log` running.
Announced mutable-context refresh to Root; source paused for small scoped review
and actual PID1 placement support proof before layering held-placement fixture.

### PIDFDs adaptation frozenb518 — SOURCE PAUSED

Exactb518b15d7566c4f3d98c512761d7051de6a22286,
`target/continuation-20261026T230759Z/candidate.json`;118files/current0mismatch.
SourceSHA9742bfcee5e61bcfd1464a4304adbfd608d272405905390609234805c9f35b77;
amd64payload aa522ca2d02404217bd2e6cecc09e304d93eb355e71065f36352d9bfa685de44;
ARMpayloadd3e4eae975b0e209a94390b1114189480907cc2fb980acc19bbca80e0d722e7d.
Both static builds/BOTH original initstability assertions PASS. Only supervision.rs
changed vs6716. Root notified for candidate-local strict copies/scoped review and
actual native3 scope placement/terminal positive before adding held fixture.
Root dedicated held-placement runner CLI `--ignored-owner-expiry-placement`, mode
`owner-expiry-placement`, existing Bootstrap descriptor/fresh nonce/two-member
fixture, expected zero task8b2 new dirs. Not implemented/run yet. No source edits
while current mechanism gates run; all-nine scope remains incomplete.
Scoped independent review6716..b518 PASS/no new Critical or Important: retained
pidfd lifetime/FD inventory through manager postchecks, actual ah/SCM_RIGHTS, no
numeric fallback, independent live/start/cgroup verification confirmed. Native
PIDFD support/held-placement gate still pending; no source mutation after freeze.

Root native111 onb518 PIDFDs FULL regular terminal PASS7, all4 actual scope
placements plus syntheticReady/recovery/original durable completion. Native112
Arch262 scope support running; ARM scope/Host gates scheduled by Root. PIDFDs
native support now demonstrated on Debianx86; other results not yet received.

## Held-placement native fixture implemented (cfg(test), not yet run)

Root-cleared dedicated CLI `--ignored-owner-expiry-placement` uses existing
Bootstrap descriptor/fresh nonce/two-member config; no new task8b2 directory.
OwnerExecutors one-shot test flag reaches fixed placement helper. After exact
retained target identity check and BEFORE Domains::place/PID1 request, helper
writes127 on private channel3 then waits forever. No release command exists.
Parent polls checkpoint, requests exact helper pidfd SIGSTOP, then polls native T
without a blocking wait. A's authentic BeginTerminal+first Spawn retains original
sent_at+2; no grace/rearm. B continues authenticated shared HostAuthority audits.

Native oracle requires >=2 B audits during hold, >=2 fresh audits after A's exact
Deadline (within existing0.5s observation tolerance), actual A T, cancelled helper
and gated target actual reaps, no release/transfer/Started/scope receipt, and zero
durable executor/acknowledged/completion entries. Final strict disk bytes match
parent canonical journal, terminal guard PID/start matches retained guard, and
both guards actual T then exact pidfd kill/reap. It stops B through test-only
normal owner termination after progress proof, drains B's read-only host job, and
retains both Bootstrap resources and A BeginTerminal intent. Shared deployment
OFD busy is checked during hold and afterward, explicitly sole_survivor_claim=false
because B/parent retain copies; accepted109 separately proves sole surviving
executor's independent OFD lease. No cleanup or reuse permission is inferred.

Changes are cfg(test) kernel/expiry_owner/owner introspection plus owned.rs native
oracle and transport_lab/actual_lab_main dispatch. No production owner-loop,
clock, policy, native completion, registration or cancellation semantics changed.
Launch93 `/tmp/terminal-tests11.log`, strictclippy `/tmp/terminal-clippy10.log`, fmt
and diff-check PASS. Initial compile caught test-only field-name typo acknowledged,
fixed before passing checks. Native held-placement is the behavioral regression;
ordinary tests do not stand in for it. Staticboth/initstability builder
`/tmp/terminal-build7.log` running after announcing context refresh. Source paused.

### Held-placement fixture frozen173a — SOURCE PAUSED

Exact173acb9f52ee173ef6f368cc3b029636533e4aee,
`target/continuation-20261026T231812Z/candidate.json`;118files/current0mismatch.
SourceSHA4aa716354a9bd020436eb530089647c0ee0fd71ba61d9ae53c36c1a89b6ae2f1;
amd64payload b116923722cfab2bee90673d846e0976b6bf088f91b58ec57c21597d3d86b580;
ARMpayload389e42ae5e563768e8a3fd85be2462b2bd78c2d88f5246e37294a8ab508ee30a.
Staticboth/BOTHinit stability PASS. Root copy/strict-bind requested; next114.
Independent scoped b518..173a PASS/no Critical/Important: checkpoint origin,
original timing, B progress, actual reaps/no grants, strict disk and both guard
actual T→KILL/reap accepted; native114 remains separate pending evidence.
Root112 Arch262 PIDFD scope PASS;113 ARM257 PIDFD scope PASS1 (guard9518/start3995744,
authenticated PID1/exact cgroup/T/reap). Native PIDFD support now proven on all3
current systemd platform guests, component only; not platform release acceptance.
No source edits since173a; next ProcessInspection remains read-only design.

Root native114 on173a held-placement PASS3 (one JSON witness plus2 case labels).
Original A Spawndeadline212448.103504806, terminal212448.14115376 (+37.65ms).
B completed2audits at hold,14at A terminal,16final:12during/2after. Helper72859/
start21244610 and gated target72858/start21244610 actually reaped; no control or
durable executor registration; exact disk digest da0c6646... in Root evidence.
Guards72845/start21244581 and72846/start21244584 both actualT then exact kill/reap.
No resume. Shared OFD observation remains non-sole. Scoped/component gate accepted;
ARM held run and affected host/journal/Bootstrap regressions pending with Root.
All173a contexts copied/strict-bound; source stays paused for remaining gates.
Root native115 ARM173a held-placement PASS3: A originaldeadline40399.513359757,
terminal40399.555053211 (+41.69ms); B2atHold/9atTerminal/11final (7during/2after).
Helper9813/start4039755, target9812/start4039754 actual reaped; no control/executor
registration/resume; diskd793aa... retained by Root. Guards9799/start4039649 and
9800/start4039674 both actualT/kill/reap. Root116 x86HostAudit regression now
running, then Journal/Bootstrap/ARMnormal where legacy fixed endpoint is free.
173a source stays paused through these affected regressions. Parent native process
broker plan accepted for future work; no guard SYS_PTRACE restoration authorized.

## FINAL — SOURCE_PAUSED / NEEDS_CONTEXT, terminal component accepted

No broker code or partial preparation was written. Fresh sole writer must continue
approved parent-native ProcessInspection, connected real runtime and ALL nine.
Concrete handoff: `process-inspection-brief.md` in this same directory. It covers
exact native/FD/capability interfaces, all operational caller paths (including both
ProducerGroup::release_child admission rechecks), pure-native vs Journal factoring,
original2s/private endpoint/peer lineage/no-raw-FD requirements and remaining gates.
Root explicitly agreed fresh context after this accepted connected terminal chunk.

Final current frozen source173acb9f52ee173ef6f368cc3b029636533e4aee,
`target/continuation-20261026T231812Z/candidate.json`;118source inputs/current0
mismatch. No mutable source edits after that freeze; only reports/handoff changed.
SourceSHA4aa716354a9bd020436eb530089647c0ee0fd71ba61d9ae53c36c1a89b6ae2f1;
amd64 b116923722cfab2bee90673d846e0976b6bf088f91b58ec57c21597d3d86b580;
ARM389e42ae5e563768e8a3fd85be2462b2bd78c2d88f5246e37294a8ab508ee30a.
Both context copies already strict/source-bound by Root; preserved realHEAD/index.
Local launch93/strict workspace-alltargets clippy/fmt/staticboth/BOTH original init
stability PASS. Root independently ran full `cargo test --locked --workspace`
current173:290PASS/0failed/2ignored, logs
`target/terminal-owner-root-verification-20261027/workspace-173a.log` and.json.
This is checkpoint verification, NOT final whole-branch all-nine acceptance.

Accepted source-specific native gates retained:
-1073855 regular terminal PASS7, authentic parent persistence while guard frozen.
-1096716 death PASS7, all3 original timely completions, post-containment host T,
 other2 actual dead, true sole-survivor OFD until exact kill/reap, durable reuse/
 cleanup refusal and no resume.
-1106716 full original90 watchdog PASS; actualT+1.64ms, exact kill/reap/no rearm.
-111b518 Debian PIDFDs actual4 scopes+regular terminal PASS7;112Arch262 and113ARM257
 native PIDFD scopes PASS1each. No numeric PID fallback or ownership exception.
-114173 x86 held-placement PASS3;115173 ARM held-placement PASS3. Private pre-PID1
 checkpoint, original2s A freeze, B fresh audits during/after, actual helper+gated
 target reaps, no control or durable registration, strict disk, both guards T/kill.
 Shared OFD claim explicitly non-sole; native109 is the sole actor lock proof.
-116173HostAudit PASS3;117173Journal PASS6;118173 two actualBootstrap overlapping
 FIFO original2s durable ACK/exact disk/EXIT0 reaps PASS2.
-119173ARM normal PASS17; Root readonly capture collector PASS6files112records,
 0forbidden0drops. Starting/component only, NOT enrolled provider/client acceptance.
All failed105/106/108 and their original outcomes remain retained as documented;
no retroactive PASS, SIGCONT, production change or discarded failure resources.

Source boundaries remain: parent factory/async placement/durable registration
before grant; fixed original executor completion authority; no-ptrace guard and
private endpoints; per-member failure isolation and actor drain even after journal
persistence failure; native actual death before capacity reuse; original lifecycle
and IO deadlines; shared canonical host authority/Journal FIFO/global uncertain
writer fence; terminal outcome distinctions. PIDFDs prevents delayed PID reuse
attachment but does not grant scope cleanup or resolve arbitrary uncertain state.

Next functional work is approved: authenticated owner ProcessInspection for
actual.launch/Handoff/LiveDaemon/Sender and producer release checks, fixed async
read-only native jobs with retained peer policy/pidfds and private Local/Remote
receipts; no guard ptrace restoration, cached profile approval or raw proc FD
return. Need positive real confined daemon/sender inspections plus continued
negative endpoint access proof and neighbor-progress faults, then complete staged
runtime/durable cohorts/retirement and all-nine matrix. Public launch remains
refused until actual prerequisites hold. Migration, clients, platform lifecycle,
full hostile traffic, repeated10m benchmark and real24h soak remain open. Final
fresh whole-branch verification only AFTER all implementation/testing. Overall NOT
DONE. Root solely controls next native counter, credentials and localVM mutations.
