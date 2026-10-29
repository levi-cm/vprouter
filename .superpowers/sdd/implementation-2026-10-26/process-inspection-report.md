# Process inspection implementation — active

## Authority and checkpoint

Sole source writer for user-authorized ALL NINE, starting from accepted immutable
173acb9f52ee173ef6f368cc3b029636533e4aee (118 inputs). Real HEAD/index unchanged;
Root exclusively owns privileged/credential local VM operations. No acceptance
or overall completion claimed. Accepted native 107–119 evidence remains as brief.

## Concrete API plan

- `InspectionPolicy::new` validates legitimate parent Admission, transaction,
  producer, namespaces, reviewed bundle and fixed configuration before guard birth.
- `ExternalOwner::with_inspection(policy)` binds exact retained guard identity and
  spawns a private fixed inspector after guard birth. One bounded actor/member,
  fixed operations only, original request sequence/time, nonblocking owner poll.
- `Transaction::inspect_container` dispatches local native or private owner RPC;
  actual launch, both Handoff checks and both release_child checks use it.
- `release_child` registers native direct-child birth while its placement gate is
  still held. PID/role hints never create authority; inspector independently pins
  pidfd/start/proc directory and checks guard parent and producer membership.
- `LiveDaemon`/`Sender` use explicit Local native versus Remote opaque-token state.
  Native daemon/sender verification is factored independently of Journal methods.
  Every remote revalidation performs fresh full native verification.
- Inspector retains bounded original peer pins and tombstones. It cannot remint a
  revoked/dead peer. Replies contain token/operation/seq/original-time only, never
  process/root/executable descriptors or serialized process assertions.
- Inspector closes unrelated inherited descriptors before reading requests. Keep
  only legitimate native policy pins and private channel. Read-only openat masks;
  deny openat2, write/mutation, ptrace, pidfd_getfd, process_vm_writev, exec,
  network creation and namespace changes. Output limited to exact receipt channel.
- Original 2s applies across queue, expensive reads, fresh final checks and ACK.
  Cancellation retains actor/capacity until native actual reap. Neighbor service
  and independent expiry collection continue. No restart of cancelled inspector.

Pending: implementation, focused tests, static builds/freeze, independent scoped
review, Root positive actual daemon/sender and held-A/healthy-B native gates, then
remaining actual runtime/all-nine work. Final whole-branch verification occurs
only after required implementation/testing, not this checkpoint.

## Implemented source checkpoint (2026-10-27, pre-freeze)

Production dispatch now covers actual.launch, Handoff.prepare/verify, both
ProducerGroup.release_child admission checks, LiveDaemon.pin/verify/revalidate,
and Sender pin/verify. ProducerGroup.create remains legitimate parent setup.
Transaction inspection selection uses its existing private remote JournalClient;
actual native checks do not invoke copied Journal or Transaction authority.

`inspection.rs` installs immutable real Admission/bundle/configuration references
and private duplicated producer/namespace pins before guard creation. Its canonical
owner registry binds 32-byte incarnation, bounded slot, fixed operation, request
sequence and original sent_at; duplicate PID/role registration and remint refuse.
The fixed persistent actor is forked only after guard birth, retaining exact native
guard pidfd/proc/start and bounded child/daemon/sender pins. RegisterChild happens
while the exact launched child is still held at its placement release gate. Native
four-process daemon and sender ancestry reaches that retained direct guard child.
Parent replies contain only matched private token metadata; raw peer FDs never
reach the guard. Every Reinspect performs fresh native checks and final native
liveness/start/ancestry/membership checks; tokens are not cached approval.

NativeDaemon is factored from journal checks and also retains/checks the actual
root object. NativeSender preserves maps/cgroup/netns/fixed role executable/final
checks and now explicitly checks UID/GID65534, groups empty, caps0, NNP1, seccomp2,
AppArmor docker-default. Private Local/Remote variants have no pretend native pins.

Kernel inspection actor closes every unrelated inherited FD before command reads.
Only typed native policy/guard pins and its post-guard-fork private endpoint remain
(plus a fixed empty test eventfd in cfgtest). Role retains only DAC_READ_SEARCH and
SYS_PTRACE for proc reads; parent checks UID/GID0/groups0/exact caps/NNP/seccomp/LSM.
The BPF filter permits scalar read-only openat flags; openat2, legacy open, writes,
ptrace, pidfd_getfd, process_vm operations, socket creation/sendmsg, exec, namespace
changes, signals and writable shared/executable mappings refuse. Only the fixed
private channel can receive/send bounded frames. fcntl allows only F_GETFD.
No guard capability was restored. Atomic clone3 pidfd and early-fork retention
also cover actor constructor/drop failures. Cancellation retains exact native
handles until actual waitpid reap, with no inspector restart in the incarnation.

Owner loops service expiry actors independently. Inspector drain errors are kept
in a separate role error slot and cannot suppress expiry polling/receipt retention
or neighboring members. RPC mismatch/late/unsolicited/malformed/dead actor causes
member termination, registry revocation and native cancellation/drain. Guard
Client.failed remains latched after malformed matched inspection replies, including
wrong Reinspect token, wrong token shape or unexpected descriptors/executor data.

## Review-driven fixes and local evidence

- Reviewer found reused kernel wait_ready used SYS_poll under a ppoll-only role;
  replaced with dedicated rustix ppoll, without allowing SYS_poll.
- Expanded actual-filter process-read test exposed rustix fs::open selecting legacy
  SYS_open on x86. Strace retained in target/inspection-filter-native-read*.strace.
  Native proc-directory opens now explicitly use openat(CWD), preserving flags.
  Exact fcntl F_GETFD supports native OwnedFd debug validity checks; all mutation
  and duplication commands remain denied.
- Reviewer found inspector drain `?` before expiry collector; independent_collection
  now records that error but always polls the independent expiry actors. Regression
  proves helper control flow with retained original synthetic receipt tuples; it
  is explicitly not actual kernel drain-failure/expiry evidence.
- Reviewer found wrong top-level token accepted on matched Reinspect ACK; exact
  operation token and bounded slot/incarnation shape checks now poison the client.
  Real framed socket regression exercises wrong token followed by denied progress.
- `cargo test --locked -p vprouter-launch --lib`: 100 PASS, no failures/ignores.
  Log target/process-inspection-launch-tests.log. Focused checkpoint, not final
  ALL NINE whole-branch acceptance.
- `cargo clippy --locked --workspace --all-targets -- -D warnings`: PASS.
  Log target/process-inspection-clippy.log. `cargo fmt --all -- --check`: PASS.
- `cargo test --locked -p vprouter-launch --test actual_lab -- --inspection-filter-selftest`:
  PASS actual installed filter, idle/EAGAIN -> request -> idle -> request, native
  Process::open/verify and descriptor inventory, forbidden opens/FD-steal/socket/
  writes. Root independently reran earlier version; current expanded pass includes
  native process and inventory operations. This remains unprivileged role-filter
  evidence, not positive target inspection with CAP_SYS_PTRACE in the guest.

## Fixed native fixtures awaiting Root

`--ignored-owner-process-inspection`: existing actual-image/nonce endpoint path,
exactly ONE new task8b2 directory. Adds actual reduced-guard daemon plus observer
launch and owner-native fresh peer inspections; then genuine target stop/reap and
old-token Reinspect must revoke the inspector, freeze the guard and actually drain
the inspector. Existing parent-owned three expiry actors, private completion FD
steal denial and original seven-second terminal proof remain connected. Expected
10 cases total (old terminal7 + actual daemon/sender/dead-peer3). Health Ready in
that terminal fixture remains explicitly synthetic; no provider/client claim.

`--ignored-owner-inspection-held`: existing exact nonce/two-Bootstrap fixture,
ZERO task8b2 directories. Private fixed actor checkpoint before native inspection;
parent observes/stops exact inspector A, original request2s freezes A and kills/
actually reaps the inspector, registry remains revoked and no held ACK is granted.
B performs fresh inspections during and after A failure; both guards exact T/kill/
reap, exact journal bytes unchanged. Expected2 cases including Bootstrap witness.
No SIGCONT, cleanup, reactivation or identity/credential access.

Public bounded native diagnostics identify actor PID/start, fixed role, original
sequence/sent_at/deadline and actual reaping. Failure stage plus enum-only reason
travels private channel and can be read after exit solely for diagnostics; failure
is never a receipt or approval. Source-specific native results remain NOT_RUN.

## Build notice

Root notified BEFORE standard `target/implementation-20261026-build.py` mutable
context refresh and cleared it (no active oracle; old contexts retained). Both
original init-stability assertions and four-role manifest handling are preserved.
Prebuild real HEAD c6a138c00b70163ba3cbfdf350e5cf8e2f3a3c6a; real index SHA256
59f3aec05fa66f161482e5705f1a3c50c68c528980a51b5da4a869a510a24692, recorded in
`target/process-inspection-preserved-git.json`. Static AMD64/ARM64 build and exact
freeze pending at this paragraph. ALL NINE remain active; runtime/provider,
cohorts/retirement, five+direct, clients, migrations, platforms, hostile traffic,
benchmark and actual24h soak are not completed by this inspection checkpoint.

## d722 failed preflight and corrected candidate in progress

The first static candidate was d72297fa860d15def78ec4b5a0ea43efe0925609,
`target/continuation-20261027T001626Z/candidate.json` (120 archive inputs,
zero current mismatches; both init stability and four-role contexts passed).
Root copied both contexts. Exact retained AMD64 musl selftest FAILED ChildFailed;
strace located legacy SYS_stat from std::fs::metadata in inventory::observed.
This candidate has NO native acceptance; native120 remains unused. Glibc/debug
passing was insufficient. The inventory now uses explicit statat(CWD) and bounded
readonly openat fdinfo reads, preserving native dev/ino/type/CLOEXEC validation;
legacy stat/open remain denied. Standard builder now requires exact retained
AMD64 musl-byte-copy installed-filter preflight before context publication.

Frozen review also identified two fixture gaps and new setup ownership loss:
- Held inspector checkpoint now sends STOP once and checks exact PID/start/live/T
  on later owner turns, with zero waiting and original request deadline unchanged.
- Native dead-peer rejection now carries fixed FailureKind::DeadPinnedPeer only
  after the exact retained target pidfd reports death, bound to original Job,
  operation/token/sequence/sent_at and a bounded finished_at. Owner requires this
  exact notice and original live deadline to classify ProcessUnavailable; generic
  timeout/malformed/exit failure cannot pass the dead-peer oracle. A late/dead actor
  may supply diagnostics only, never a successful receipt. A focused test rejects
  wrong reason/kind/job/token/operation/time.
- install_inspection and install_host_audit mutate an already-retained owner;
  any setup error terminalizes in place and preserves guard, scopes, collectors,
  original identity and terminal reason. Deployment accepts already-terminal
  canonical slots for drain only, never restarts or services their requests.
- The two fixed internal expiry attachment sites now use install_expiry in place.
  Each site attaches once to a fresh owner; no request/loop appends attachments.
  Rejected incoming ownership/receipts remain separate from journal authority and
  are collected even after errors; no wrong-allocation adoption/persistence.
- ExternalOwner validates fallible scalar watchdog setup before native guard birth.
  Global early-fork collector is serviced each deployment turn and completion
  requires its actual drainage even when owner.inspection is None.

New fixed `--ignored-owner-inspection-setup`: TWO cases, ZERO task8b2 dirs.
Constructor injection occurs after atomic clone and successful retained Actor
creation; Actor Drop transfers exact pidfd/private channel to early-fork retention.
Fixture asserts pending retention before polling, same A guard identity and
original DescriptorPolicy terminal reason, retained prepared expiry authority,
actual early-fork waitpid reap, and B >=3 fresh completions AFTER actual drainage.
Prepared expiry has ZERO started actors, explicitly emitted. It does not claim
active expiry actor retention nor B completions during a held setup failure; the
separate held-inspector fixture supplies during/after progress evidence. Native
setup/held/actual process tests all remain NOT_RUN pending corrected freeze.

Corrected source focused checks: 101 launch lib tests PASS (v2 log), strict
workspace/all-target Clippy PASS, debug installed-filter expanded selftest PASS;
final tiny original-deadline/pre-birth scalar changes are included in subsequent
build/check. Root notified BEFORE second standard mutable context refresh.

## Corrected freeze 45bd — SOURCE PAUSED for Root native/review

Candidate `target/continuation-20261027T003800Z/candidate.json`:
source 45bd707b61c6e538138109fcbe30c90aec3c811b;
source.tar SHA256 ad05c6aafee7180a8b47656bd862ecf05c79a20f09936461ec4a379b35878e1b.
AMD64 payload 837e6ce3b9e9a433f4d14d877ddbe8c3583569f8248a421f2eacb5ba0da4cd25;
ARM64 payload 3ecb060eade4413663e9c2b02b10bf826636ee8cb29dbf6aca5ca72c123627c4.
Both static no INTERP, BOTH original init stability assertions PASS. Exact retained
AMD64 musl byte copy installed-filter preflight PASS, candidate-local log retained.
Contexts unchanged from copied d722. Writer independently compared all120 archived
inputs with current bytes: zero mismatches; real HEAD/index unchanged as above.
Verification record `target/process-inspection-frozen-verification-v2.json`.
Final strict workspace/all-target Clippy and fmt PASS after final scalar/deadline
adjustments. Root notified of exact freeze and source remains paused. Native120
and all actual process/held/setup gates remain NOT_RUN at this checkpoint.

Root checkpoint: independent corrected-candidate archive/commit/current120 input
checks, exact-musl preflight and strict BOTH contexts PASS. Root full workspace
298 PASS/0 failed/2 ignored (`target/process-inspection-root-verification-20261027/workspace-45bd.*`).
Independent reviewer compared frozen45bd to173: source spec/quality PASS, no
Critical/Important; attachment loss, held blocking and dead-peer oracle findings
ADDRESSED, ppoll/token/collector fixes retained. Native120 positive is RUNNING
under Root only; no native outcome claimed yet. Source remains paused45bd.

## Read-only next connected runtime slice

After broker positive/held/setup acceptance, reuse existing Handoff operational
path rather than invent a second protocol: parent validates prepared immutable
PreservedEnrollment policy, retains owner expiry/publisher/host model; guard uses
prepare_operational, launch_daemon, fresh owner PinDaemon, launch_monitor and
serve_operational. This path already starts parent-owned expiry before monitor
release and carries original host-audit validity through ready publication.
Production assembly still needs typed fixed daemon PID discovery, protected staged
runtime descriptor and canonical health/enrollment binding, actual startup and
fault tests, then Root-only preserved enrollment/provider/client evidence. Public
Admission::launch still refuses and CLI remains observational; do not remove that
refusal on component-only evidence. Durable dynamic cohorts/preauthorized host
shapes, retirement/reconciliation and all later nine-area work remain unfinished.

## Native120 failure and narrow post-filter diagnostic correction

Root native120 on exact45bd failed after THREE cases: missing resolver,
durable Bootstrap, and genuine no-ptrace guard/native daemon inspection passed;
observer/sender case not reached. Record `target/lab-state/actual-program-run-120.json`,
task dir73768. Last owner sequence105 ended DescriptorPolicy; inspector73909,
start21725775 actually reaped. Root separately confirmed guard73908/start21725772
stopped T, all three expiry scopes/actors absent, all three acknowledged journal
registrations but EMPTY completion list. This is NOT containment/durable completion
acceptance. Root owns exact failed-run drain/archive; no SIGCONT/cleanup by writer.

Source diagnosis: NativeSender::verify retained an unconditional cfg(test) timing
eprintln after executable verification. Inside fixed inspector stderr write is
EPERM; eprintln panics, producing no private Failure Notice, matching EOF-derived
DescriptorPolicy. Its sender_check error logging and NativeDaemon LSM error logging
had the same forbidden side effect. Removed direct stdio from pure native verifiers;
fixed private stage/reason remains the diagnostic path. No filter widening. Expanded
actual filter selftest requires both write and writev to stdout, stderr and private
channel to fail EPERM; private framed sendto remains the only allowed output. Owner
request metadata now names fixed operations (including PinSender), no payloads.
Pure native call-path audit found no other direct logging reachable after filter;
inventory diagnostic output occurs before filter setup or separate selftest only.

Post-fix launch101 PASS, expanded debug installed-filter PASS, strict workspace/
all-target Clippy PASS (`target/process-inspection-*-v3.log`). Root notified BEFORE
third standard builder/context refresh; corrected exact musl gate and both init
stability assertions remain mandatory. Source-specific native retry remains pending.

## Corrected freeze 5f3d — SOURCE PAUSED

`target/continuation-20261027T004554Z/candidate.json`, exact source
5f3d49eb6a05d453a50d772d9c1787140b951b25; source archive SHA256
ca305db07fe8f9f1a8b1db02aaaae9fdd53060778d0564d719ddf93fe69bebe9.
AMD64 payload408a99e4f2856d115230382a5b97a04790edcd192796c2460a4f6f8a0bc20555;
ARM64 payload8c6b9c165346631784a3a7e3cfd91a05593396e80633b93ae5ef74e41cf68218.
Both static/no INTERP and BOTH original init-stability assertions PASS. Exact
retained AMD64 musl installed-filter preflight PASS, including new stdout/stderr
write/writev EPERM. 120 current/archive inputs, zero mismatches; preserved real
HEAD/index unchanged. Evidence `target/process-inspection-frozen-verification-v3.json`.
Four-file byte delta from45bd only: daemon, producer, owner fixed diagnostics,
kernel/inspection negative checks. Contexts unchanged. Source PAUSED for Root.

Root native120 recovery completed: all four scopes plus owner unit/cgroup absent;
exact guard T/start/inode/payload confirmed before pidfd SIGKILL and actual exit.
Expiry actors already absent; native exact pinned terminal tables observed with
host12/transport3/data3 drops. Journal completions EMPTY preserved; no durable
completion PASS. Root references terminal120-actor-journal-reference.json,
terminal120-deny-reference.json, owner-actor-drain-run-120.json. No resource cleanup,
SIGCONT or credential action by writer. Next counter121; retries/held/setup remain
pending on source5f3d. All nine remain active and final review is still later.

## Native121 failure and fixed fixture restoration authority

Root native121 on5f3d failed after FOUR cases: genuine native daemon AND sender /
authenticated one-use observation passed. Failure occurred afterward in fixed
lab_resume_bootstrap: `LAB_NATIVE_FAILURE stage=lab_restore_audit reason=Foreign`.
Record `target/lab-state/actual-program-run-121.json`, dir74229. Direct call to
ActiveLinks::audit attempted the fork-copied parent HostAuthority whose creator-PID
check correctly rejects Remote guard use. It was not native process inspection
failure and no host shape was adopted. All4 actors/scopes already absent; Root
read-only archive confirmed all4+owner units absent, journal completions EMPTY.
No Root signals for121, resources retained and nonce archived. Full gate FAIL.

Root-authorized narrow transport.rs lab helper fix: enforce Offline FIRST, obtain
one original HostEvidence via existing Local/Remote capability, exact producer and
journal link binding, Local full audit only for legitimate creator or Remote
namespace audit with private matched HostAuditReceipt. Verify exact Offline, then
restore Bootstrap and re-read native expected shapes plus exact Bootstrap policy;
check SAME original receipt before each phase and after each complete verification.
Any error enforces Offline. No new baseline, skipped check, deadline reset or
production authorization. Launch101 and strict workspace/all-target Clippy PASS
(v4 logs). Root notified BEFORE next standard context refresh,5f3d contexts retained.
Next native counter122 pending new frozen candidate; held/setup still NOT_RUN.

## Corrected freeze0059 — SOURCE PAUSED

`target/continuation-20261027T005225Z/candidate.json`, exact source
0059fbfeaeeeb336148296ccb97210c3c9be4ec8; source archive SHA256
4c490e896dfd288b002b48504f45dcdefc660e223e252b08ccefb7eac15c69c9.
AMD64 d3eb6d6b106accccd5a0565ab237f4ce72c4c82ea5f9e76d2ca3387c20f25d3a;
ARM64 fce048847af1741bfc347fc1a8184feb850db08d68121c821708d7a41427bbce.
Both static/no INTERP, BOTH init stability and exact AMD64 musl filter preflight
PASS. Contexts unchanged.120current/archive inputs, zero mismatches; original
HEAD/index preserved. Evidence target/process-inspection-frozen-verification-v4.json.
Only transport.rs differs from5f3d. Launch101/strict workspace-all-target Clippy/fmt
PASS. Source PAUSED for Root exactpreflight/scopedreview/native122; held/setup and
ALL NINE completion remain pending. No active writer test/build processes remain.

## Native122 and123 accepted components on exact0059

Root native122 positive PASS10 (`target/lab-state/actual-program-run-122.json`,
dir74675, exit0,19.386s): genuine no-ptrace guard daemon ancestry/config/fresh
inspection; authenticated native sender observation; exact reaped peer rejected
with private stage60/process_unavailable, owner terminal ProcessUnavailable,
inspector74818/start21807305 actually reaped; independent three expiry durable
completion and no resume. Synthetic health/provider portions remain synthetic;
record real_client_acceptance NOT_RUN, PASS_PARTIAL_ACTUAL_PROGRAMS.

Root native123 held PASS (two test shapes; Bootstrap+held witness+label events):
inspector75293/start21813791 actually reaped, registry revoked, no held ACK/resume;
original deadline218140.326836771, terminal218140.363507362 (+36.67ms).
B completed3 at hold,22 at A terminal,24 final:19 during and2 after. Guards75291/
start21813786 and75292/start21813790 exact stopped/killed/reaped. Journal disk
unchanged (Root records complete SHA). This is actual healthy-neighbor progress,
not only synthetic collector control-flow. Native124 setup RUNNING under Root at
this note; ARM/affected native gates pending. Source remains PAUSED0059.

## Native124 setup failure and exact registration ownership transfer

Native1240059 setup FAILED after Bootstrap: actual postspawn helper75580/
start21817137 injection retained its live native socket but dropped the old
Registration tokens. Inventory correctly rejected socket fd92 / socket629709
as unregistered while starting B; B progress is NOT PROVEN by124. Exact mechanism:
Actor Drop moved child.pinned/channel only; Survivor._inventory and Actor._inventory
were dropped, while EarlyFork had no inventory owner. Re-registering before those
old token drops would also be wrong (duplicate/stale unregister), so no exceptions
or raw-fd allowance were added.

Fix transfers all existing registration owners AND complete corresponding Process
pins plus pidfd/control into EarlyFork until actual waitpid removal. Partial
inspector construction and placement-child constructor failures transfer already
created tokens too. Only genuinely missing exact native descriptors are registered;
registration failure retains handles/error and collector still reaps. Per-actor
collector errors no longer prevent later retained actors being polled.64-child
pre-fork bound remains, no slot release before native reap, no wrong authority reuse.

Expanded same `--inspection-filter-selftest` now runs a real atomic-fork Actor
through shared production bind_actor, Drop transfer, inventory.verify while still
pending/unreaped, actual waitpid reap, inventory.verify afterward, then exact numeric
FD reuse with a fresh registration and another verify. Child has parent-death kill,
fixed idle/filter code; no harness global FD mocks. Debug expanded selftest PASS,
launch101 PASS, strict workspace/all-target Clippy PASS (v5 logs). Exact retained
musl builder gate includes this real regression too. Root notified BEFORE refresh.

Root124 independent recovery: helper already absent; both exact guards75578/
start21817132 and75579/start21817136 actualT, solecgroupinodes209614/209690 and
payload d3eb verified before pidfd SIGKILL+actualexit; no SIGCONT. All2+owner units/
cgroups absent, nonce archived, all resources preserved. No expiry actors started.
Next counter125;122positive/123held remain accepted on0059, setup still pending
corrected frozen source. Source/build correction is four files; all nine active.

## Registration correction freeze5597 — SOURCE PAUSED

`target/continuation-20261027T010440Z/candidate.json`, exact source
559746510203ada7ed3ad09ac522a6a3a611f7ac, source archive SHA256
de92dcac8872833c8be1f6f7a5af8afb5ee046a77f16106419d219524c93310d.
AMD64 3d99b717e0835788e7d21a38a9d80be65c904f6574b7d1e2b817f6f253ff7571;
ARM64 865fd278b0fc4029200c31244e21efe8790d2471cc005869a33f7f5d942406b6.
Both static/no INTERP and BOTH init-stability assertions PASS; exact AMD64 musl
expanded filter plus actual retention/reap/exactFDreuse selftest PASS. Candidate-local
preflight log and target/process-inspection-frozen-verification-v5.json retained.
120 current/archive inputs, zero mismatches; original HEAD/index unchanged. Contexts
unchanged. Launch101, strict Clippy and fmt PASS. Source PAUSED for Root scoped0059..
5597 review, independent exact preflight and native125 SETUP first, then current-
source held/positive, ARM and affected inventory regressions. No overall DONE.

## Exact5597 setup regression accepted; same-source remaining gates running

Root independent full workspace298PASS/0fail/2ignored, exact expanded AMD64 musl
preflight,120inputs/current0mismatch and strict both contexts PASS. Independent
0059..5597 scoped review PASS/no CriticalImportant: full native bundle/token move,
partial constructors, no collector suppression and actual descriptor-reuse test.

Root native125 SETUP PASS (two shapes plus witness): failed postspawn actor75983/
start21885451 actually reaped; A original DescriptorPolicy and prepared expiry
ownership retained; active expiry actors ZERO. B0 at actual drain then3 fresh
inspections after; guards75981/start21885445 and75982/start21885450 exact drained.
This resolves124's native setup regression without relaxing inventory or filters.
Native126 held RUNNING at this note; same5597 positive127, ARM and affected native
inventory/placement regressions still pending. Source remains PAUSED5597.

Same5597 native126 HELD PASS: deadline218900.542273748, terminal218900.579916508
(+37.64ms), inspector76266/start21889816 reaped/revoked/noACK/noresume; B3→22→24
(19during2after), guards76264/76265 exact drain, journal unchanged. Native127
full positive PASS10, with Root protected public terminal witness all3
verified_before_deadline/noresume (`terminal-witness-run127`). Thus same-source
x86 setup125/held126/positive127 components accepted. Native128 ARM held running;
ARM positive/setup and affected normal/journal/placement inventory regressions
remain pending. Production public launch/provider/client/all-nine remain unfinished.

Read-only next-runtime detail agreed with Root: fixed verified LocalAPI socket
SO_PEERCRED provides only a bounded PID hint, then existing owner NativeDaemon
attestation retains original clock, pidfd/start/proc-dir/native final checks. Runtime
must use protected explicit route-only host declaration/cohort policy, never fixture
live-baseline learning. HostAuthority presently binds complete allocation generation;
durable dynamic transitions must preauthorize each cohort before canonical mutation.

Native128 actual ARM5597 HELD PASS: inspector10617/start4695087 reaped/revoked,
noACK/noresume; original deadline46953.547345091, terminal46953.592461983
(+45.12ms); B3→21→23 (18during2after); guards10615/start4695045 and10616/
start4695066 exact drain, journal unchanged. Native129 ARM positive RUNNING.

## Nine-area status at the process-inspection checkpoint

| Required area | Implemented/evidence retained | Still required |
| --- | --- | --- |
| 1 Secret lifetime | Earlier compiler-resistant zeroization/parser work retained | Final integration and secret-lifetime review with completed runtime |
| 2 Shared health contract | Authenticated bridge, original deadlines, publisher and expiry component evidence | Actual provider/worker/public status integration acceptance |
| 3 Shared host authority | Creator-bound canonical model, private native audit, concurrent Bootstrap members | Protected declaration/cohort policy, durable add/remove and retirement/reconciliation |
| 4 Operational runtime and exits | Actual daemon/sender inspection, parent expiry, guard confinement and failures; x86 positive/setup/held accepted, ARM underway | Owned operational monitor/provider lifecycle, public staged operations, five Mullvad plus explicit direct, real clients |
| 5 Persistent clients | Existing observational/config components preserved | Managed kernel and scoped userspace client install/select/status enforcement and real fault traffic |
| 6 Migration | Inspect and non-applicable review plan retained | Durable locked apply/resume/rollback/adapters, two independent identity-preserving local migrations |
| 7 Services/platform artifacts | Static x86/ARM, immutable exact candidate/context bindings, systemd native component placement | Full systemd/runit lifecycle, install/update/rollback/uninstall/provenance, real platform reboot/restart gates |
| 8 Hostile acceptance | Prior component transport/fault evidence plus current native inspector isolation | Completed runtime's one/five/direct/six configuration traffic and interruption/capture matrix |
| 9 Performance and soak | No new performance acceptance claimed | Repeated same-host ten-minute comparisons/optimization and actual24h mixed soak |

The process-inspection checkpoint does not finish these nine areas. Root remains
sole privileged/credential controller; final whole-branch review follows completed
implementation/testing. No production/public activation or credential writes done.

## Native129 ARM pre-response expiry and fresh same-inode hash deduplication

Native1295597 ARM positive FAILED after3 cases; daemon positive passed, sender
positive NOT accepted. seq105 PinSender succeeded and authenticated-peer stage
logs preceded seq106..115 verify_daemon, then seq116journal/117 senderReinspect
reported native stage60/process_unavailable. This is BEFORE Response::ObserveOnce
write, not post-ACK exit: observer's original2s response window expired while
verify_daemon performed two native verifications, each hashing BOTH current exe
and retained descriptor of the same40MB inode. Earlier same run measured2127ms for
before_release_daemon_verification. The native dead-peer rejection was correct;
no alive/deadline rule is weakened.

Root approved narrow fresh hash dedup: ReviewedBundle::verify_pinned first requires
both descriptors' same full native fingerprint (dev/ino/uid/gid/mode/nlink/size/rdev/
blocks/blocksize/mtime+ctime nanoseconds), performs ONE fresh full ELF/role/hash
validation of that same inode, then checks both complete fingerprints again.
Atime excluded because the check's pread may update it. Nothing cached across jobs;
BOTH Handoff verifications around host audit and all final pidfd/start/parent/
UID/caps/NNP/seccomp/LSM/namespace/root/config checks remain. Two native memfd tests
prove same-inode distinctFD positive, identical bytes/different inode rejection,
and deterministic ftruncate/fchmod mutation through either FD rejection. These
prove pair identity/mutation binding; full role/hash acceptance remains native-gated.
Launch103 and strict Clippy PASS (v6 logs). Only programs.rs and daemon.rs changed.
Root notified BEFORE next static/context refresh; exact musl and BOTH init gates kept.

Root129 ARM recovery: exact3 pinned terminal policies host12/trans3/data3 observed;
all3 expiry actors absent, journal completions EMPTY. Exact guard10867/start4699214T,
solecgroup30137/exe865fd... reverified before pidfd SIGKILL/actualexit/noresume.
All4+owner units/cgroups absent and nonce archived, resources preserved. No writer
signals/credentials/cleanup. Next130; ARM sender/fullpositive and ARMsetup remain
pending corrected source.128 ARM held is accepted only within its exact scope.

## Same-inode fresh-hash freezee412 — SOURCE PAUSED

`target/continuation-20261027T012102Z/candidate.json`, exact source
e4123fce8b447109794a34fb38fb80b854e566bd; source archive SHA256
97972c974bc33eb49666158bb9a6417baf29bff80e0bf06fcc82bee559fcb643.
AMD64 45a71945f460cc4b2e68fb886a27b67c1be574bca548f883685a76a0eefafbbe;
ARM64 e93f5268b79752da9cea62e77245325c0f414a93aba4002d0fe3e1f33d5bfcdb.
Both static/no INTERP and BOTH init stability PASS. Exact AMD64 musl expanded
filter+retention/reap/fdreuse preflight PASS;103launch/strictClippy/fmt PASS.
120current/archive inputs0mismatch; real HEAD/index preserved. Contexts unchanged;
evidence target/process-inspection-frozen-verification-v6.json. Only programs.rs
and daemon.rs changed from5597; no Handoff/filter/deadline changes. Source PAUSED
for Root scopedreview/preflight/native130 ARMpositive direct regression. All nine
remain active and final verification is still after full implementation/testing.

## Native130 ARM still exceeds aggregate original handshake; preaccept factoring

Native130e412 ARM positive FAILED at same pre-response seq117 dead sender,
fullgate FAIL. Fresh same-inode dedup reduced before_release_daemon_verification
from~2127ms to1477/1506ms, but the aggregate original observer2s still expired.
These are bounded diagnostic timings, not a general runtime performance claim.
Root130 exact terminal tables12/3/3 observed; expiry actors absent, journalcompletions
EMPTY. Guard11344/start4766968T/cgroup32465/exacte93f reverified before Root-only
pidfd SIGKILL/actualexit/noresume. All4+owner units absent, nonce archived/resources
preserved. Next131; no writer signals/credentials/cleanup.

Root approved minimal preaccept factoring only (optional daemon-container duplicate
removal deferred). Handoff.verify_placement retains exact protected placement
parent/file/socket IDs, file metadata+config digest and enrollment binding. Before
accept it performs this cheap fixed binding; after bounded authenticated request,
complete Handoff.verify still checks journal/namespace/producer/container and final
placement identities, BOTH fresh daemon verifications around host audit, and sender
native verification BEFORE first Response. No prior approval is reused. New
initial_reply gate preserves original accepted-frame end through verification,
serialization/write and postwrite check; no fresh2s write anchor. Fixed public phase
elapsed/remaining metadata added without config contents. Only handoff.rs changed.

Real framed UnixStream tests: forged config/nonce and injected placement verifier
failure emit ZERO permission bytes; success must invoke full verifier; late success
cannot write after original deadline. This is protocol/control-flow evidence, NOT
native root-owned filesystem-tamper proof. Native hostile config/path substitution
remains part of later all-nine acceptance. Launch105 and strict Clippy PASS (v7logs).
Root notified BEFORE static/context refresh; e412 contexts retained; no oracle.

## Preaccept factoring freeze3c153 — SOURCE PAUSED

`target/continuation-20261027T013554Z/candidate.json`, exact source
3c1536a1b77213f58aebe9efc06c3424201d94a7; source archive SHA256
5d9d31a52e49239634a0103d51d2ba5059b02cfa2015d25595b38ae0d8a91fa7.
AMD64 4eb6276f85aed2330b7d41b91a3f3707f1a917fccaa8448a4b65887045c05817;
ARM64 996e250f05ffce2072a7dbbbae1a9be7ed726a0ea1d47fbc4696b05bb380cf66.
Both static/no INTERP, BOTH init stability, exact AMD64 musl expanded filter and
retention/reap/fdreuse PASS. Launch105, strict workspace-all-target Clippy, fmt PASS.
120current/archive inputs0mismatch; HEAD/index preserved; contexts unchanged.
Evidence target/process-inspection-frozen-verification-v7.json. One-file Handoff
change frome412; optional per-job container dedup NOT implemented. Source PAUSED
for Root exactpreflight/scopedreview/ARM131positive; no native acceptance for3c153
yet and no overall completion. Root e412 wholeworkspace300 checkpoint remains
recorded separately from these focused105 checks.

Root3c153 independent whole-workspace302PASS/0fail/2ignored, exact musl expanded
preflight,120source/current matching and strict both contexts PASS. Scoped e412..
3c153 review PASS/no CriticalImportant; full checks mandatory before first Response.
Clock precision: bootstrap Request carries schema/digest/nonce only, NOT a BOOTTIME
sent_at. Its worker and guard first-response budgets remain their original Instant
ends. Owner inspection/host-audit RPCs and operational publication frames separately
retain BOOTTIME constraints. The first-response factoring makes no new BOOTTIME
claim. Native131 ARMpositive pending; source remains PAUSED3c153.

Native131 actual ARM3c153 record reports PASS_PARTIAL_ACTUAL_PROGRAMS/exit0,
40.806s full fixture (`target/lab-state/actual-program-run-131.json`). First-response
fixed diagnostics: preaccept placement0ms; PinSender175ms with1816ms original
remaining; full permission verification1687ms with126ms original remaining. Later
native stage60/process_unavailable is expected explicit dead-peer rejection. This
proves current first-response path within its unchanged deadline in this run;
not general throughput, performance SLO, suspend, provider or real-client proof.
Root final witness acceptance and remaining platform/regression gates are separate.
Source remains PAUSED3c153; optional container dedup still not implemented.

Root confirms131 ARMpositive PASS10 and protected public terminal witness all3
verified_before_deadline/noresume (`terminal-witness-run131`). Native132 ARM3c153
setup PASS (two shapes+witness): inspector12274/start4875552 actually reaped,
original reason+prepared expiry retained/active actors0, B0 at drain→3 fresh after;
guards12272/start4875515 and12273/start4875534 exact drained. Native133 current
x863c153 positive PASS10/dir77020 and Root protected terminal witness3 timely/noresume.
Both-architecture current positive components accepted. Native134 ARM normal17
regression RUNNING; Arch normal17/journal6/placement affected regressions follow.
Source remains PAUSED3c153 pending controller clearance to resume actual runtime.


## Native134 Local guard inventory regression and narrow correction

Root native134 ARM normal17 FAILED after6cases at actual_observer_authenticated_launch:
`inventory: mismatched_fd=10, registered=false, mode=0, cloexec=true, anon_inode:[pidfd]`.
Record target/lab-state/actual-program-run-134.json retained. Read-only cause confirmed:
local LiveDaemon retained a separately opened guard Process without registering its
procdir+pidfd. NativeDaemon registered only its chain/exe/root/config/namespaces;
remote inspection role already registered guard pins separately. No prior remote
positive is claimed to cover this failed local path.

Root approved LocalGuard RAII wrapper, fixed current-process constructor registering
exact two Process descriptors, with Registration field before Process. Local pin and
verify use the same retained Process; native ancestry/role checks/filter unchanged.
Existing --inspection-filter-selftest now also calls production LocalGuard constructor,
verifies full inventory while live, after drop, then exact numeric pidfd slot reuse with
new eventfd registration and final drop/inventory. Debug selftest PASS; native local
actual-daemon regression remains pending.

Root also authorized normal-only Scenario::Actual WAN collision avoidance while
preserving failed-run artifacts and older retained WANs such as Debian105. Later
Root inspection found134/135's endpoint routes and addresses already absent; their
route persistence must not be inferred from the retained records. Before mutation, choose
up to16 internal random nonce-derived185.66 pairs via existing nonce_wan_pair. For each
intended allocation/profile, native readonly metadata checks both addresses against
existing addresses/covering prefixes/broadcast and every non-default route prefix,
source and gateway, any table. Observation errors fail closed; all attempts exhausted
fail without mutation. Default route alone is allowed. Existing exclusive ADD setup
remains; no replacing/deleting retained resource or accepting observed policy shape.
Deployment stays transportlab{PID}; intended endpoint is passed to actual publisher
and monitor configuration so profile/allocation/plan/binding hashes agree. Other
transport scenarios and supplied owner-nonce paths are unchanged.

Fixed pure readonly --normal-fixture-descriptor emits closed capability metadata only:
schema1 / endpoint_policy bounded-nonce-18566-v1 / candidate_limit16 /
exclusive_add_onlytrue. This flag performs no admission, file or native operation and
is never runtime authority. Root controller will retain old18565 collision checks for
old unknown-flag payloads, and require exact metadata for the new source guard.

Focused launch106 PASS, strict workspace/all-target Clippy PASS; same existing nonce
mapping/hash binding tests plus new synthetic address/route collision negatives pass.
These synthetic collision tests are not native hostile-host acceptance. Five source
inputs changed from3c153; real HEAD/index unchanged. Builder refresh announced to Root
before any mutable context refresh. All-nine scope active; no final acceptance claim.


## Local guard and normal fixture freeze f803 — SOURCE PAUSED

`target/continuation-20261027T020026Z/candidate.json`, exact source
f803b4aef470a7eb16494fa3497e02e996440496. Source archive SHA256
e1c4b14b7506fb74d1b263d8049c15d845651b7c52b32ae68f68f2408c32450e.
AMD64 payload78eb971c92b6b65a5e1733da34c2b9336745f668778ea09e1ffd5505485c534b;
ARM64 payload0a0b6c82ba26f1ab2887528e9c5e02ecb7bf72a9f1b8372e58325a311facbd44.
Static both/noINTERP, BOTH original init stability, exact AMD64 musl expanded
installed-filter + real early-fork retention/reap/reuse + LocalGuard live/drop/reuse
PASS. Exact retained musl --normal-fixture-descriptor returns intended closed JSON.
120current/archive inputs0mismatch; real HEAD/index unchanged. Both context hashes
unchanged. Evidence target/process-inspection-frozen-verification-v8.json; v8 logs.
Focused launch106/strict Clippy/fmt PASS; no current-f803 whole workspace claim.
Source PAUSED for Root independent preflight/scopedreview/native135 direct ARMnormal
regression. All nine remain active, actual runtime resumes after affected gates.

Root f803 independent whole-workspace303PASS/0failed/2ignored, exact musl expanded
filter/retention/LocalGuard reuse and strict normal descriptor PASS; archivecommit,
current120 and both candidate-local strict contexts PASS. Scoped five-file review
plus Root controller compatibility review pending; native135ARMnormal held until
clear. Root134 readonly confirms main12377gone, daemon12526gone, native producer
cgroup gone; basecontainer12418 running and owned resources retained. No Root
signals/cleanup for134. Existing failed134 evidence remains FAIL.

Scoped f803 source/five-file + six Root controllers review PASS/no CriticalImportant;
Root native135ARMnormal started. During paused follow-through writer found missed
normal-only packet positive-control destination: actual_packet_controls still uses
fixed ENDPOINT185.65.134.88:51820 for VR8B2_POSITIVE_PLAINTEXT_CAPTURE instead of
selected intended Plan.endpoint. Root and reviewer notified immediately while135
active; source unchanged. One-line intended-plan destination correction proposed,
all capture controls retained. Normal f803 complete acceptance is pending and this
is a source-confirmed fixture defect regardless of135 eventual result. Other fixed
literals belong to unchanged non-Actual transport faults/fixtures or unit tests.

Root native135f803 ARMnormal FAILED late after15cases at actualpacketcontrols:
network_operation. LocalGuard inventory path, authenticated observer, preexec/LocalAPI,
four postpin drift cases, exact reaping and monitor lifecycle all passed; full17gate
FAIL remains recorded. This matches the identified fixed positive-control endpoint.
Root authorized one-line correction to immutable g.lab_plan().endpoint(), with all
positive captures/negative controls unchanged. Normal callgraph audit found remaining
fixed endpoint references only in non-Actual transport branch (Actual returns before
it), its fault suite, and fixed unit-test wrapper. Actual publisher/monitor profile
binding already uses intended selected endpoint. Root-only135 actor metadata checks
pending; source ordinary focused tests running. Next136 controlled by Root.


## Correct packet target freeze bd095 — SOURCE PAUSED

Exact source bd09504736511f11634d57731be209e7af6c6523;
`target/continuation-20261027T020926Z/candidate.json`, source archive SHA256
08161cb7cfd9cfe6de9194733917d444f6ee6f3bc2106d84718adf4b74cf08c4.
AMD payload4f6d02745cb809a754774c382913dd3ee9c2c986e3ad3c4190c83282e249402c;
ARM payloadff9b19d0690529c4f9050c5a73f2a3c69897efb3ed6116bd8b4f9df223e6c83a.
Only logical change fromf803 is actual_packet_controls direct plaintext positive
send destination from fixed ENDPOINT to immutable Plan.endpoint; rustfmt collapses
call formatting. Every positive capture/negative assertion unchanged. Launch106,
strict workspace/all-target Clippy, fmt PASS. Static both/noINTERP, BOTH original
init stability, exact AMD musl expanded filter/retention/LocalGuard selftest and
strict descriptor PASS.120current/archive inputs0mismatch; real HEAD/index preserved;
context hashes unchanged. target/process-inspection-frozen-verification-v9.json.
SOURCE PAUSED for Root exact preflight/scoped one-line review/native136ARMnormal;
135 fullgate FAIL retained, no broad runtime/all-nine acceptance claim.

Root bd095 independent exact archive/current120/commit/musl+LocalGuard/descriptor
and strict both contexts PASS; frozen one-line review PASS with actual direct call
path checked. Native136bd095 ARMnormal PASS17/dir13105. Root capture collector
read-only pending; native137Archx86 normal17 running. Native135 fullgate FAIL retained;
Root135 main+daemon+producer already gone, no Root signals/resources retained.
Remaining AMDnormal/journal6/held-placement x86+ARM regressions pending. Source
still PAUSEDbd095; all-nine operational runtime resumes after controller clearance.


## Native137 Arch publisher startup descriptor race

Root136 ARMnormal PASS17 capture metadata accepted:6files/112records/0forbidden/
0kernel drops, Starting/unenrolled component only. Native137bd095 Archnormal FAILED
after2cases: publisher child_fds=[0,1,2,3,4,5], fixture expected0..4. Read-only source
cause: fixed startup fd5 writes ACK128 then closes; parent previously returned after
reading128 and require_live, so it could observe fd5 before its close. This is the
private startup ACK writer, not an accepted additional steady-state descriptor.
Root137 readonly main4224gone, exactbd095 payload actorsNONE, native producer group
matched andEMPTY; basecontainer/resources retained. No Root signals/cleanup.

Root approved contained startup correction: publisher_pipe nonblocking reader,
publisher_ready exact128 then EOF on same exclusive native pipe under the same
original deadline, final exact Survivor.require_live and deadline check before Child
construction. Early EOF, trailing byte, held writer, readerror or expired deadline
reject; no sleep/retry/extra-FD exception in production. Fixture still requires0..4.

Publisher constructor now uses existing atomic fork_with_pidfd/64 pre-fork capacity.
Private cache-directory duplicate and its registration plus IPC registration are
owned before fork. finish_publisher owns pidfd/ACKreader/control/cache and existing
registrations before fallible validation; every postfork registration/readiness/
liveness error transfers complete bundle into existing early-fork collector. Its
private extra-pins vector is empty for previous roles, exactly ACKreader+cache here,
covered by original or narrowly missing-only Registration. Collector retains handles
through actual waitpid and isolates per-actor errors as before. Successful constructor
returns original socket Registration to sole Publisher::spawn caller, avoiding a
re-register gap. No helper/filter/protected file policy changed by this correction.

Meaningful tests: actual pipes test fixed byte+closure, held writer after ACK,
trailing/wrong bytes, earlyEOF, already expired original end and readerror. Dedicated
rootless standalone selftest forks real child that writes128 then holds writer,
invokes production finish constructor, verifies full pending inventory, actually
reaps through collector, verifies inventory and exact numeric FD reuse. This is
native ownership/barrier evidence, NOT proof of privileged publisher role setup.
Expanded debug selftest PASS, launch108 PASS, strict Clippy/fmt PASS. Static refresh
announced to Root before execution; freeze/native138 Archnormal pending.

KNOWN UNFINISHED runtime ownership issue: generic Child::Drop still kills then
waits up to3s and can drop native pins if reap fails. Publisher startup failure now
avoids that consuming path; this patch does NOT close generic all-actor ownership.
Resolve retained terminal ownership for that path BEFORE public runtime launch.


## Publisher ready/ownership freeze d57e — SOURCE PAUSED

Source d57e2a94f332a67a39f0bb963778ebac461c37fe;
`target/continuation-20261027T023222Z/candidate.json`, source archive SHA256
769999d373066781782e794cfef6482b5de92ea57b41c9297d48e9073926f425.
AMD35035ed617193309da8c30b5195a5db533b7e796f083f0cbcf02dd113059ca23;
ARM268212de7999b813de2ec82ad60e651a91c2200ca8b7ff6177fd43f6ed54d3cb.
Staticboth/noINTERP/BOTH original init stability/exact AMD musl expanded selftest
including actual heldACK failed-startup complete inventory/reap/reuse PASS; closed
normal descriptor PASS.120current/archive0mismatch, real HEAD/index preserved;
context hashes unchanged. Launch108/strict workspace-alltarget Clippy/fmt PASS.
Evidence target/process-inspection-frozen-verification-v10.json; v10 logs. Three-file
source delta frombd095: kernel.rs, kernel/inspection.rs selftest hookup, publisher.rs.
Only kernel spawn caller Publisher::spawn consumes original channel registration.
Existing Publisher::spawn callers are test-only actual_lab; production assembly must
own and continue collecting early forks rather than exit/discard retained ownership.
Generic Child::Drop retention gap remains open before public launch. Source PAUSED
for Root full current workspace/preflight/scopedreview/native138Archnormal.

Root d57e independent FULLworkspace305PASS/0failed/2ignored; exact musl heldACK /
startup ownership + prior retention/LocalGuard/descriptor preflight PASS,120source
and both strict candidate contexts PASS. Scoped bd095..d57e review PASS/no Critical
Important, complete tokens/native bundle retained through actual waitpid. Native138
Archnormal RUNNING; remaining AMDnormal/journal+placement regressions pending.
Source PAUSEDd57e. Generic Child::Drop gap remains explicitly open; full all-nine
verification remains after actual runtime and all required implementation/testing.

Root native138d57e Archnormal PASS17/dir4539; protected capture metadata6files /
112records /0forbidden /0kernel drops, Starting component only. This directly
regresses137 publisher-ready FD5 race under actual privileged role. Native139same
source Debianx86normal running; journal6 and held-placement x86+ARM sharedretention
regressions follow. Source stays PAUSEDd57e. Generic Child::Drop gap is explicit in
operational-assembly-brief.md and must be resolved before public runtime launch.


## FINAL sole-writer handoff — SOURCE PAUSED / NEEDS_CONTEXT

Root requested fresh sole writer for the next substantial operational assembly.
Exact source d57e2a94f332a67a39f0bb963778ebac461c37fe; candidate and hashes above.
Fresh final read-only comparison:120archived/current build inputs, ZERO mismatches.
Real HEAD c6a138c00b70163ba3cbfdf350e5cf8e2f3a3c6a and real index SHA256
59f3aec05fa66f161482e5705f1a3c50c68c528980a51b5da4a869a510a24692 unchanged.
Evidence target/process-inspection-final-handoff.json. No active writer builds/tests
and NO more Rust/manifests/build edits. Root owns current native139Debiannormal17;
138Archnormal17+6captures112records/0forbidden/0drops PASS, Startingcomponent only.
Journal6 and held-placement x86/ARM shared-retention regressions are still PENDING;
Root will finish them and dispatch the fresh writer. Do not infer their results.

Implemented process inspector/private LocalRemote factoring and accepted source /
component gates are detailed above. Latest d57e Rootfullworkspace305PASS/0fail/
2ignored, launch108, strictClippy/fmt/staticboth/initboth/exactmusl expanded startup
retention PASS, scopedreviewPASS. No final whole-branch/all-nine acceptance claimed.
Native failed120/121/124/129/130/134/135/137 remain FAIL with exact history retained;
normal135missed endpoint and137publisher ready race were actual findings subsequently
corrected, never skipped assertions. No production writes, credentials, cleanup,
SIGCONT, real HEAD/index changes or nested agents by this writer.

Next writer MUST read operational-assembly-brief.md and original constraints/spec /
8c..15 requirements. That brief is READ-ONLY PLANNING, NOT implemented runtime.
Mandatory FIRST substantial repair: generic kernel::Child::Drop bounded3s reap can
still drop native pins on reap failure. Extend retained terminal ownership and
actual collectors to that path, preserving sibling progress/original deadlines,
BEFORE public launch. Publisher startup-specific repair does not close this gap.
Then actual fixed LocalAPI PIDhint/full owner-native proof, operational monitor /
provider/owner assembly, protected explicit host cohorts, public lifecycle, clients,
migrations, platforms, hostile matrices, performance and actual24h soak. All nine
remain active. Final fresh whole-branch verification follows complete implementation
and testing, not this broker checkpoint. Public launch still refuses intentionally.
