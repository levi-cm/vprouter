# Continue all nine: owner transactions, then operational integration

User explicitly requested a subagent implement all verification findings, test,
then an independent verification subagent. This is a fresh context handoff, NOT
completion. You are the SOLE implementation writer in
/DATA/AppData/vprouter-rust-v2 on rust/v2. Prior implement_owner_runtime is paused
at 4ce0755c953f810205bf2da154a71019f14d872d and writing its final handoff. No
nested agents. Root exclusively runs privileged/credential-bearing LOCAL VM work.
You implement source, ordinary tests, static builds, self-review and exact freezes.

Read constraints.md, binding docs/rust-v2/IMPLEMENTATION.md and approved plan
implementation-2026-10-26.md. Read FINAL handoff in owner-runtime-report.md or
owner-deployment-handoff.md (parent will identify exact final file), plus original
owner-runtime-brief.md and original task8c..15 briefs as needed. Do not restart
completed foundation work or narrow the authorized scope to another preparation
API. No permission stall for authorized source/local lab work. All nine remain
active and final whole-branch verification still follows implementation/testing.

## Preservation

Never reset/clean/discard dirty changes, alter real Git index/HEAD, publish/push,
mutate original Python production/services/container/network/state/keys/accounts,
or access a remote installation. Real HEAD remains c6a138c. Existing alternate-
index candidate refs/source archives preserve exact test bytes. Root alone uses
owned loopback VMs and profiles/approved identities; no credential read by you.
No keys/auth URLs/state bodies in argv/env/logs/reports/build contexts. Keep failed
runs, old containers, namespace pins, temps, journals and process evidence.

## Exact latest checkpoint and evidence

4ce0755c953f810205bf2da154a71019f14d872d at
 target/continuation-20261026T200354Z/candidate.json.
263 ordinary PASS/0failed/2ignored, strict workspace/all-target clippy-Dwarnings,
fmt, static musl x86+ARM and BOTH init manifest hash-stability assertions PASS.
Root copied both contexts candidate-local and independently strictchecked four
fixed image roles and source binding. You may refresh mutable gateway-context
paths after announcing a new freeze; root must copy each before next refresh.

- Native87 x86 two-guard control/IO PASS: A read actor stopped at private
  checkpoint, originaldeadline200768.759641218, Aterminal200768.76769063;
  B completed37reads before Aterminal and75total =>38after; Aguard66974/start
  20076666, Bguard66975/start20076670, stoppedIO66976/start20076681. All exact
  stopped/drained assertions pass. routed_neighbor_acceptance=false.
- Native88 same source ARM/TCG PASS original2s: deadline28775.14600628,
  Aterminal28775.196922169; B32before/64total =>32after. No product budget
  relaxation. Emulated ABI execution, not physical ARM performance proof.
- Source46e87aa/candidate194326Z:261ordinary/clippy/fmt/staticboth/hashstable,
  independent855..46e scopedreviewPASS. Native85 PASS6: actual fork copied-Journal
  creatorPID refusal;3 guard-owner isolated reads; successful confined same-
  canonical-record temp write/fsync/rename/directoryfsync ACK128+EXIT0/exactbytes/
  root0600/newinode/noTemp before ORIGINAL BOOTTIME2s; writer caps0/NNP/seccomp/
  chroot FD0..6; independent reader beside stopped writer; noSIGCONT + sole OFD
  lock busy after parentTx drop until actual writer kill/reap, lateTemp retained.
  This is NOT full legal JournalRPC mutation or routed runtime acceptance.
- Native86 same46e PASS17 normal init/daemon/observer/Starting monitor/publisher/
  4 live post-pin drift/container death regression.
- Sourcee47e/candidate182533Z:256ordinary+strictchecks/staticboth/hashstable,
  independentpropertyreviewPASS. Native75Debian and79Arch actualauthenticated
  system-bus PID1 scope/group/policy/observedT/kill+reap PASS. Native76 full90s
  watchdog PASS (90.915s controller elapsed), originaldeadline195013.053372829,
  observedT195013.102849944; exact guard killed/reaped. This MUST be rerun on
  final changed owner-loop bytes, not transferred. Native77x86/78ARM exact zero-
  cap OperationalMonitor Unix/UDP/TCP positive + prohibitedsyscall negatives PASS.
- NewTokio dependency46e uses pinned zbus6.0.0 minimal onlytokio(defaultsoff),
  pinnedTokio1.53.3. Earlierzbus5 enabledTokio process -> persistent global signal
  sockets -> nativeDescriptorPolicy. FreshsubprocessRED/GREEN+both-target resolved
  feature graph regression fix it without any FD allowance. NativeDebian72 and
  ARM74 on ea749 eachPASS17; each6captures112records0forbidden0drops. Arche47e80
  same17/capturecounts PASS. Historical failures66..73 remain.

## Current implementation facts

- Public Admission::launch STILL refuses. Actual periodic Engine/provider channel,
  protected enrollment and guard FSM/publication exist but not connected to a
  complete public staged lifecycle/external owner/retirement. No actual enrolled
  provider/client acceptance in this continuation. Do not transfer component Ready.
- ExternalOwner now has bounded service_once and DeploymentOwner polling all guards/
  journals with5ms idle waits, individual failure fencing and global process-stop.
  It retains terminated guard/journal handles rather than authorizing cleanup.
- Owner service identity is deployment-stable SHA256(domainseparator+validated
  deployment_id), emitted by --owner-domains-descriptor; current fixtureunit
  vprouter-v2-owner@9bc1c45b9af87c0af159ba1e394cfa3dc1f568853c7cf9a19bfa205778201b13.service.
  Guard/expiry scopes and RPC still bind full allocation digest/gen/lifecycle.
  Full journal allocation equality remains strict. Hot-add is NOT implemented by
  this naming change; explicit durable generation/coexistence transition required.
- Journal local calls refuse creatorPID mismatch afterfork. Child guards use one
  authenticated sequence space for progress+fixedjournalRPC. Owner stages changes;
  separate fixed root-directory-confined caps0/NNP/seccomp IOchildren validate old
  snapshot and allocation, use originalBOOT2s throughcompletion, retain allocation
  OFDlease through actualdeath; latewriter pendingrecord remains fenced.
- Existing requested scope policy now uses correct Service/Scope interfaces,
  GetAll(Unit)+GetAll(Scope) strict actualkill/delegation/dependency readback, native
  PID/start/cgroup/inode verification. zbus binds unique systemd owner PID1/UID0
  and reply sender, protected bus endpoint before/after, same2s + FD/thread checks.
  SO_PEERCRED PID1 can be listener creator via socket activation, not dispatcher.
- Inert PID1 was split into shared reviewed error.rs/kernel_base.rs (16 original
  primitive bodies independently verified equivalent) and standalone init_main,
  avoiding whole host-library coupling and preserving stable four-role manifests.

## FIRST fix two unresolved multi-journal defects

These are UNFIXED at4ce. Do NOT implement further HostAuthority/runtime features
until fixes are tested and independent re-review accepts them.

1. Reviewer Important: ordinary mutation contention freezes a healthy member.
   owned.rs JournalServer::start1153 returns LockBusy whenever a shared mutation
   ispending. owner.rs service_once307 propagates, DeploymentOwner414 terminates/
   SIGSTOPs B. Two valid A/B BeginTerminal/RegisterExecutor/ACK requests can freeze
   B even if both fit original2s. Fairly queue authenticated per-member requests
   behind ordinary activewriter, retaining ORIGINAL sequence/sent_at/deadline. Do
   not create a fresh2s on admission or confuse normalcontention with uncertain/
   fencedwriter. Preserve all stale-writer/lock/drain barriers. Meaningful two-
   member overlapping legal mutation regression and native gate required. Current
   native87/88 exercises ONLY RequireNoExecutors reads and cannot establish this.
2. Independently confirmed acknowledged race: readonly IOjob captures before/
   alternate atstart (owned1176) and exact-checks that frozen set (453). A different
   member can commit a valid new record while the read is in flight; child rejects
   whole bytes even if selected B unchanged. Need fair writer/read-generation
   handling that does not block unrelated reads/watchdogs behind a stalled A.
   Possible architecture: authenticated exact observed-record digest from fixed
   reader, bounded owner-retained canonical generations, sharedbinding+selected-
   entry predicate validation against accepted snapshot; or a rigorously safe
   alternative. Never adopt caller snapshots/digests as authority, accept unknown
   disk states, unbounded history, or weaken original2s/latewriterfencing. Test a
   read crossing a neighboring commit, changed-selected/sharedbinding rejection,
   uncertain-writer cases and fair progress. The earlier stale pending-entry bug
   is FIXED: alternate allowed only when sharedbinding and selected entry bytes
   identical (real second-member positive/changed/unknown negatives).

Root independent reviewer review_foundation is available for scoped fixes; root
alone dispatches. Save RED/GREEN logs and frozen candidate, then wait ONLY for
root exact native/re-review result before new functional phase. Read-only design
prep can continue while root tests. Do not park after fixes once accepted.

## Then complete concrete operational integration and all nine

Implement actual owner-backed HostAuthority, persistent PID1-host namespace pins,
protected staged start/stop/containerdeath, same-nonce3expirychildren before grant,
periodic real provider/ads/approval/Ready and source-bound native proof. Keep owner
loop serviceable during disk/Docker/native IO stalls; per-exit guards, not one
shared stopped guard; no inheritedRc journal/HostAuthority writes. No persistent
SYS_ADMIN/fullsetupcaps in steady runtime. Source current capsule proofs are not
that capability proof. Native owner/guard unit death must leave independent3scope
writers alive; owner must retain exact outcomes/pidfds/ns/lease and reconcile only
after all old mutators+IOwriters dead/drained. Old terminal lifecycle never rearms;
exact kernel markers/generations and replacement Offline BEFORE deletion of ONLY
owned old terminal tables. Durable interruption/reboot/restart handling required.

Host model addition/removal/hot restart cannot learn arbitrary aliases: stage
exact owned shapes/indices or equivalent authenticated generation-bound native
transition BEFORE live kernel mutation; in-progress B must not falsely drift A.
Current activate_quarantined mutates before HostModel.add; initial all-member
activation is not later add/remove proof. Owner identity stable but allocation/
config/health generation transitions still need explicit authority. Startup or
new placement cannot monopolize active guard2s RPC/watchdog loop. Host audit may
be per-guard native observation checked against OWNER-held model over bounded
IPC, never caller-supplied expected Snapshot as authority. Preserve original
checked_at times; ARM each full40MB daemon audit~1.2s, schedule bounded phases
rather than remove checks/relax2s frames/6s publication/health45/handshake180/90.

Continue independent5Mullvad + explicitdirect runtime, persistent kernel/userspace
client noWAN/DNS/IPv6/proxy fallback guards, two local identity-preserving legacy
migrations/real release+state rollback, systemd/runit/ARM lifecycle/reboot/update/
uninstall, whole native hostile+real-client four-config capture matrix, repeated
10min1/5/6exit Python/Rust CPU/PSS/throughput/p95 benchmarks and true24h mixed soak.
These are required behavior+acceptance, not rows to mark NOT_RUN and call DONE.
No remote installation SSH or production activation. Final fresh whole-branch
verification follows completed implementation/testing, not this component review.

Fleet budget later: approved LocalAPI raw status60750bytes/48peers near64KiB;
adding fleet nodes likely exceeds. Keep enrollment64KiB distinct, bounded status
bytes+parser nodes/strings, no bodylogging. Current JSON decoder materializes full
Value; don't merely raise cap without accounting memory.256peer authority cap.

## Root lab/controller boundary and exact commands

Owned local Debianx86/Arch/ARM-TCG/Void-runit VMs remain available; root onlySSH.
Root production check active/max-vprouter healthy/uplinkrunning; no mutations.
Five imported protected profiles5distinct publicdeviceidentities/currentprimary
matches0 (17:25publicinventory); actual subscription/othernamespaces/provider
connections NOTtested. Approved existing gateway n8P8U86ryZ11CNTRL in Debian,
IP100.101.230.31 +logical fd7a:115c:a1e0::9438:e621, state bind host
/var/lib/vprouter-v2-lab/gateway-primary -> /var/lib/tailscale. Preserve without
reenroll/clones. Root reference48peers/4expired/44nativeIPv4routes+DNS, full
peerids/ips/predicates in approved-enrollment-reference.json; not authorization.
Existing approved disposable client also root-controlled, unchanged.

Root controller scripts target/platform-lab/run-frozen-platform-actual.py candidate
platform label mode. Modes actual,terminal,terminal-death,operational-profile,
owner-domains,owner-watchdog,owner-journal,owner-deployment. Owner modes require
payloadrootexacthash+protected isolated-acceptance, owner descriptor exactservice,
Slice=system.slice/KillModecontrol-group/nullinput/root0600regularstdio, protected
owner-domain-nonce64lowerhex/no newline; no journald/socketstdio. Root creates and
keeps public outputs/diagnostics and failure nonce. Owner journal/deployment fixed
runners x86+ARM. Full90 currently Debianonly. Oracles run SEQUENTIALLY (shared
actual-program-run-N). Root copy-frozen-contexts.py strictchecks both archcontexts.

IMPORTANT stableownerhash is NOT guardallocationhash. Every new test logs
LAB_GUARD_SCOPE_INTENT before PID1placement with exactunit/lifecycle/exit/role/
allocation/PID/start. Root archive-failed-owner-nonce.py uses ALL exact intents+
actualpolicyreadback, verifiesactorunits/cgroupsabsent before archivingfixednonce;
never infer childnames from ownername. Namespace .mount units persist deliberately
and must NOT be mistaken for processactors/deleted. Native81postexit NSFSinode
match proof saved; old nonce81archive first overbroadmatch corrected without any
resource deletion. Failed retries82/83 also actor-dead archived; alltemps/pins kept.

Builder target/implementation-20261026-build.py includes newcratefiles, alternate
index only,4fixedimageroles. Report exact commands/source/logs and unsafe/cap/
subprocess/FD inventory in owner-transactions-report.md. Root copies contexts
before refresh and tests frozenbytes only. If genuinely contextfull, write precise
NEEDS_CONTEXT handoff; no overallDONE. Continue autonomous authorized scope.
