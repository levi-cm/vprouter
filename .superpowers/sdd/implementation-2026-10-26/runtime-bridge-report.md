# Runtime continuation — IN PROGRESS

Latest authoritative resume: **Handoff checkpoint2752df5894 — NEEDS_CONTEXT**
at the end of this report. Earlier sections preserve milestone history.

Baseline frozen candidate899a874; preserved rust/v2 HEAD/index/unfinished source.
No production, credentials, privileged lab or remote operations by implementer.
No operational readiness or completed nine-area claim.

## Implemented so far

- `launch/owned.rs`: one `Rc<SharedJournal>` owns the deployment allocation flock,
  namespace record and descriptor registration; `Transaction` now holds a unique
  exit lease. `for_exit` verifies the exact existing allocation generation and
  reserves a different member without acquiring another flock. Every transaction
  API verifies its selected exit. `Journal` remains the existing native durable
  implementation. Duplicate exit leases reject; failed durable records remain.
  Runtime mutation remains single threaded and RefCell conflicts return LockBusy.
- `launch/execution_lab.rs`: existing two-exit actual execution oracle now uses
  separate leases on the shared journal. Added duplicate-lease rejection,
  cross-exit transaction rejection and external allocation flock exclusion.
  Producer harness similarly releases its second lease before cleanup/reopen.
  These privileged cases are compiled but NOT_RUN by implementer.
- `core/health.rs`: bounded strict `HealthMessage` with per-process lifecycle
  nonce, channel sequence, sent_at, optional shared Snapshot. `Session` pins
  Binding+lifecycle and validates all publications/replays. Heartbeats do not
  refresh verification age; new publications cannot reserialize old evidence
  to extend verification/recovery. Verification/heartbeat expiry44s (margin
  below45), backward clock, mismatch or replay irreversibly revokes the session.
  This is data validation, NOT authenticated process or enforcement authority.

## Current verification and pending authority

Latest tested immutable bridge milestone: e898e935f94cfdf1380a087ec085a08e0fcf63d7
(107 source inputs), full ordinary209PASS/0failures/2ignored. Both static targets
build and init-byte stability assertions PASS. Root actual30 (x86) and actual32
(ARM) passed both new publisher cases including frozen writer containment, then
failed a test-only positive proc predicate. Raw31/33 diagnosed native syscall and
mount-option rendering/overmount selection; corrected source freeze follows.
Root e898 transport:7scenariosPASS,42capturefiles/864packetrecords,zero forbidden
prefixes or capture drops, including actual Ready application roundtrip followed
by Offline. Root prior71b3 execution/producer shared-lease labs PASS. These are
component evidence, not single-exit operational or real-client acceptance.

The distinct fixed monitor initial publication bridge is implemented and compiled:
protected bootstrap -> retained sender -> Session -> verified Offline -> isolated
host writer -> lifecycle-bound quarantined-stop ACK. Actual end-to-end monitor
case is still NOT_RUN past the earlier proc test failure. Periodic Engine/native
WG observation bridge, independent expiry executors, authenticated operational
identity loader and CLI/service activation remain incomplete; public launch and
worker start refusals are preserved. Native WG GET remains guard-only. No imported
credential, production Python router or real remote installation was touched by
implementer.

## Nine-area status (current)

1. Secret erasure: prior implementation and ordinary tests passed; runtime
   integrated failure evidence still follows operational integration.
2. Shared health: versioned wire, replay/lifecycle/earliest handshake expiry,
   real host publisher and initial authenticated monitor bridge implemented;
   publisher actualPASS, initial monitor actualpending; periodic bridge incomplete.
3. Shared host: aggregate authority/shared journal exit leases implemented;
   native two-exit execution/producer testsPASS; dynamic add/remove/generation
   lifecycle remains incomplete.
4. Operational guard/worker/init/watchdog/CLI/direct: Ready native actuation and
   fixed roles implemented; periodic monitor/independent44s+90s enforcement,
   protected identity loading and public activation/direct remain incomplete.
5. Persistent client protections: pending after real single-exit runtime.
6. Identity-preserving migration: pending; all existing state remains preserved.
7. Platform/services/releases: staticAMD/ARM PASS; actual platform compatibility
   fixes and proc checks under test; Arch/Void adapters and services pending.
8. Hostile faults: actual post-pin, shared lease, publisher freeze and all7
   transport scenariosPASS at their frozen sources; integrated runtime hostile
   matrix, expiry/guard/native IO/clock/suspend/death cases pending.
9. Whole-router benchmarks/24h soak: pending; no performance or sustained-health
   acceptance inferred from finite components.

## Additional implemented runtime components (same continuation)

### Exact enrolled daemon projection

`network/guarded.rs`: public data `DaemonPeer` and validated `DaemonDeclaration`
(self node ID+CGNAT IPv4, <=256 unique peer node/IP pairs; duplicate/reserved DNS
or public addresses refused). `ActiveLinks::pin_operational_metadata` retains
this declaration in DaemonLinks. Both pin observations and every later audit
require exact pre-daemon baseline plus fixed TUN, four IPv4 rules, exact self /32
and local kernel route, explicit peer /32 table52 routes and fixed DNS100.100.100.100.
No arbitrary table52 entry, prefix, IPv6 address/route/rule, or recaptured baseline
is accepted. Existing observation API remains strictly unenrolled/no-address.
This is structural data, not a live identity/health capability. Production guard
must load protected declaration and verify actual pinned-daemon LocalAPI identity.

Root provided `approved-kernel-shape-ipv4.json` and
`approved-peer-route-predicates.json`: actual suppressed fixture has one selfIPv4,
45table52IPv4 routes (44nonexpired peers+fixedDNS), zeroIPv6routes and base2IPv6rules.
Existing broad normal-Docker IPv6/netmap fixture is NOT a production baseline.
Root must verify native projected route protocol/fields against this derived model.
The runtime protected declaration loader and live LocalAPI self/peer binding are
still missing; these functions do not bypass that dependency.

### Actual Ready enforcement transition

`netfilter/actuator.rs`: tracks released state separately from quarantine table
projection, validates exact Ready permit and absence of both ordinary/emergency
quarantine after generation-CAS release, restores quarantine on verification error.
`verify_staged_ready` requires exact offline deny layers plus Ready permits.
`netfilter/enforcement.rs::ready`: verifies old Bootstrap+producer/cooperation,
installs full Offline on all three scopes, stages+verifies every Ready permit,
revalidates producer/cooperation, releases data/transport/host in that order,
post-verifies all Ready scopes and producer/cooperation. Any error attempts all
scopes Offline. `verify(Stage::Ready)` now performs actual native verification.
This is a real actuation API with retained native handles, not a readiness token.
Production launch/worker/guard entry points remain refused until authenticated
health and independent runtime watchdog are integrated.

The Reversible transport harness now closes the original negative captures, runs
actual three-scope Ready, positive application roundtrip, Offline application
receive timeout, and Bootstrap restoration before normal exact cleanup. It is a
component oracle only; no worker health or operational readiness is synthesized.

### Fixed independent host cache publisher child

New `launch/publisher.rs`; fixed spawn/confinement in sole unsafe `kernel.rs`.
Parent `Publisher::spawn(binding)` opens exact canonical root-owned private cache
directory, requires normal host preflight/single-threaded setup, then starts a
fixed fork role. No arbitrary executable/argv/callback. Child retains only null
stdio, pathless inherited AF_UNIX seqpacket channel3, cache directory4; setupACK5
is closed before steady state. All other descriptors close and exact inventory
is checked BEFORE chroot. Child chroots to exact selected directory, clears env,
keeps root owner identity solely for root-owned cache writes while all groups,
capabilities/bounding/ambient sets drop to0, locked securebits and NNP enabled.
Fixed seccomp denies exec/fork/socket-creation/namespace changes; binds openat and
renameat to dir4 and IPC to3; executable mmap/mprotect refused. Parent-death SIGKILL
is retained. Temporary descriptor owners are ManuallyDrop because child closes
those descriptors explicitly then _exits.

Parent submit/poll uses nonblocking private IPC; exactly one outstanding message
and a2s CLOCK_BOOTTIME deadline, no worker thread/fork collision and no fsync in
host guard. Child validates shared Snapshot/binding/freshness and strict sequence,
checks existing file owner/type/mode/nlink, exclusively creates .health.pending,
writes+fsyncs, renames health.json and fsyncs directory, then ACKs sequence. Existing
pending files and substituted symlink/hardlink cache refuse; interruption evidence
is preserved. Parent verifies retained child pidfd/liveness and canonical directory
identity before queueing and accepting completion. Child termination uses existing
bounded pidfd SIGKILL/reap semantics. Guard must treat publication errors as an
Offline/revocation event; that periodic runtime wiring remains unfinished.

`linux/status.rs::expected_binding` now supplies the exact same config/node/boot/
generation binding used by the status reader and new native host publisher oracle.
No cache gains guard_runtime or activation_ready authority.

### Controller-reported platform regressions and review fix

- ARM frozen899a874 run28 trace proved first /proc/1/root openat=>ENOENT after
  successful seccomp query, before Goexec. Test-only actual_profile_negative now
  accepts ENOENT only after positive own /proc/self/stat/PID parsing, procfs magic,
  private /proc mount with exact hidepid2, and parentPID1. Successful access,
  arbitrary error, missing mount, wrong procfs or parent remain rejected. Production
  process confinement unchanged. Regression test covers exact predicates.
- Arch Docker29.9.2 uses name=apparmor,profile=default. evidence::daemon accepts
  this exact full marker set as AppArmorBuiltinSeccomp alongside legacy spelling;
  custom/unconfined/extra/duplicate/combined variants reject. Container still must
  bind docker-default. Behavioral RED then GREEN test verified correction.
- Post-pin TUN/address/route/rule actual lab faults now call read-only
  Handoff::assert_offline immediately after the FIRST verification rejection,
  before repair or another authority check can retry quarantine. It verifies the
  exact retained independent emergency Offline policies without mutation/retry.

## Current ordinary verification and failed attempts

- `cargo test --workspace --locked`:202PASS,0failed,2ignored native tests plus
  intentionally skipped controller-only external harnesses.
  Log target/runtime-bridge-tests.log.
- `cargo fmt --all --check`:PASS.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`:PASS.
  Log target/runtime-bridge-clippy.log.
- Final static/artifact freeze running via target/implementation-20261026-build.py;
  target/continue-nine-area-build.py mentioned in brief does NOT exist.
- Failed attempts retained here: initial test compile used missing LaunchSpec::clone
  (test fixed to fresh fixture); publisher recv returned tuple rather than length
  (adapted exact copied/full lengths with MSG_TRUNC); transport oracle initially
  referenced nonexistent expect_none (replaced explicit bounded receive timeout);
  clippy rejected unit blocks (fixed); first whole-suite run found expected-binding
  refactor changed wrong-boot error code (removed redundant eager validation,
  preserving prior SnapshotBindingMismatch semantics). No failed VM evidence removed.

## Frozen milestone2 artifact result

Static x86_64-musl and ARM64-musl builds PASS. Frozen input comparison105files
and immutable init-byte verification PASS. Source/branch index unchanged except
existing isolated test-candidate ref created by established alternate-index driver.

```json
{
  "source_commit": "71b3e5d71973c77045520d8f03f66fbe7e921f6f",
  "source": "/DATA/AppData/vprouter-rust-v2/target/continuation-20261026T130553Z/source.tar",
  "source_sha256": "d59e4d52eab3b26f4f63017bd401dc6cb47761f311d9c69c7a85b9ed686fe21f",
  "binding": {
    "source_commit": "71b3e5d71973c77045520d8f03f66fbe7e921f6f",
    "source_archive_sha256": "d59e4d52eab3b26f4f63017bd401dc6cb47761f311d9c69c7a85b9ed686fe21f",
    "tracked_build_inputs_verified": 105,
    "source_aggregate_sha256": "9f15af9544ec8945fbd76eef813d999339d951c36b730ad34040e7903ea637ec"
  },
  "platforms": {
    "amd64": {
      "artifact": "/DATA/AppData/vprouter-rust-v2/target/continuation-20261026T130553Z/amd64.payload",
      "artifact_sha256": "908d2d75b30c061863c2bfafc78928a634b9e581f2552df17de690303b3b82d6",
      "context": "/DATA/AppData/vprouter-rust-v2/target/gateway-context/amd64/context.tar",
      "context_sha256": "9d8827331c20f4001e122802e6149379ba991ca12132f5434d486b4dde7b3b80"
    },
    "arm64": {
      "artifact": "/DATA/AppData/vprouter-rust-v2/target/continuation-20261026T130553Z/arm64.payload",
      "artifact_sha256": "4ae6e41f99c0776f1eea107f0a8d7b647d2f4666142d9b275d6fd7858b62b59a",
      "context": "/DATA/AppData/vprouter-rust-v2/target/gateway-context/arm64/context.tar",
      "context_sha256": "097c345f36a948aa92c41fe00859f33717d4cd02cac660d36172509a355f08e3"
    }
  }
}
```

Root requested to run actual_lab (Debian/Arch/ARM64), Reversible transport plus
remaining transport regressions, execution_lab and producer_lab for shared leases.
Controller results are pending. These are component/private-role tests, not an
operational worker/guard/client or release acceptance claim.

## Post-freeze continuation (71b3e5d regressions and expiry decision)

Root reported actual29 InvalidSpec before publisher and reversible Ready EAGAIN.
Both are fixture defects, reproduced in ordinary behavioral tests before fixes:
health_configuration used client mode mullvad instead of protected; Continuous's
dup inherited O_NONBLOCK into the original application socket and never restored
it after join. Fixed client mode; retained socket restores its original status
only after sender joins. No firewall relaxation. Both targeted tests now pass.
Root also reports frozen71b3 shared-journal execution/producer labs PASS; retained
summary under target/continuation-20261026T130553Z/shared-leases/summary.json.

Selected independent expiry implementation direction BEFORE implementing it:
three fixed per-scope emergency executor children, spawned during single-threaded
setup with separately opened, namespace-bound native nft sockets and exact owned
emergency policies. Each gets only its fixed scope socket, private guard IPC,
retained guard pidfd, bounded health binding/lifecycle and minimal NET_ADMIN
credentials under the same root UID as guard (signal permission is independently
verified; NET_ADMIN does not grant permission to signal another owner); unrelated FDs/caps are removed. No arbitrary commands, paths, policy
or namespace input. CLOCK_BOOTTIME and Session's original verification timestamps
control health expiry; heartbeat never renews verification. Executors run in
parallel, independently of guard/provider/publisher/native audit stalls. Budget
five seconds for native quarantine and start at verification age39 so verified
containment completes before44 (<45); this is an enforcement margin, not a change
to provider cadence5/retry1/handshake180 or the separate90s liveness watchdog.
Before expiry mutation the executor stops the exact guard through retained pidfd,
preventing new Ready release work. Design review corrected the original fence:
install_quarantine's already-Matching branch is a no-op, not a generation fence,
and signal delivery does not drain an in-flight kernel transaction. Therefore
use a distinct lifecycle-owned terminal-expiry deny table that ordinary Ready
release NEVER deletes. Generation-CAS still protects ownership, but stale release
cannot remove the terminal deny regardless of commit order. Never duplicate the
guard's netlink socket or rely on assumed Actuator phases: use a separately opened
scope socket and narrow terminal policy authority. One absolute earliest
CLOCK_BOOTTIME deadline must span stop, mutation and verification; existing
Instant-only native timeouts are not sufficient proof of suspend containment.
A5s native budget is not an established runtime bound until actual fault tests.
Surviving writers must retain durable lifecycle/recovery barriers so guard restart
cannot reuse an allocation until containment and exact child reaping are proved.
Children must survive guard death until containment attempts finish. Independent
90s guard-liveness failure follows the same quarantine-first path. Ready admission
must require all three executor registrations/ACKs and sufficient remaining lease;
any child/IPC/deadline/authority error prevents Ready, with no restart/rearm of an
expired lifecycle. This mechanism is NOT IMPLEMENTED or runtime-tested yet. It is
a prerequisite to periodic monitor Ready activation, and must be reviewed against
actual stop/death/native stall tests before public startup is enabled.

Current additional source (unfrozen): optional distinct WorkerMonitor role and
exact role-bound Sender; protected health_binding optional bootstrap field with
cross-allocation/generation/mode rejection; private authenticated Placed
constructor accessible only through admitted monitor bootstrap; monitor fixed
exec argv, zero-cap observer-equivalent confinement. Initial monitor publication
bridge is being connected and accepts Starting only, enforces Offline before
host publication, and returns only a quarantined-stop acknowledgement. Continued
monitor sampling and operational Ready remain refused, not claimed implemented.

Intermediate independent review found Session missing handshake expiry while
heartbeats continued. Independently reproduced t116/age179 accepting check117;
new test was RED before change. Session now retains structural_at+(180-age),
checks it on every heartbeat/check at the exact boundary, permanently revokes,
and rejects nonfinite/unrepresentable deadline addition. Seven health_wire tests
PASS including exact boundary, heartbeat, post-revoke clock regression and
f64::MAX arithmetic. Emergency executors must use the earliest individual
deadline, including this one; Ready is refused when <=5s containment budget
remains. At expiry they must stop the exact guard before claiming containment; healthy
lease setup does not stop the guard. If stop fails, attempt all scope denies and
report failure, with no positive containment/Ready claim. Durable allocation ownership and actual scope namespace
bindings must be checked at setup; no observed table or namespace is adopted.

Unfrozen initial bridge APIs now implemented: GuardTransport::prepare_monitor,
Handoff::launch_monitor and serve_monitor_initial, MonitorAdmission private
bootstrap token, Placed::authenticated, fixed vprouter-worker-monitor executable,
WorkerMonitor role pinned in Sender, health-binding config validation, host
Session and Publisher publication. Initial bridge allows Starting sequence1 only,
verifies daemon/sender again around publication, enforces Offline first, and
returns a lifecycle/sequence-bound QuarantinedStop. This does not yet continue
Engine sampling; it is a real initial worker-to-host publication component, not
operational Ready authority. Actual lab adds fixed monitor startup after previous
observer/daemon baseline tests and requires root cache/status reader and exact
Offline proof; privileged result remains NOT_RUN for this source.

Ordinary full workspace before final initial-gate test:208 PASS,0failures,2ignored;
clippy all-targets -Dwarnings PASS. New initial-monitor state/replay gate unit test
also PASS (209 total expected at next full run). Logs runtime-bridge-progress-tests,
runtime-bridge-progress-clippy, runtime-bridge-initial-tests under target/.
First fourth-role static build failed existing init-byte stability assertion
on 3-to-4 manifest layout migration, retained runtime-bridge-monitor-build.log;
no source candidate was emitted and no lab acceptance claimed from that attempt.

## Native checkpoint 66d8f676 (2026-10-26 14:20 UTC)

The initial authenticated monitor bridge is now implemented and actually proved
on Debian x86_64: frozen 8fd2161 actual39 and exact-source repetitions42/43/44
all passed17 cases. This includes fixed zero-cap Monitor executable admission,
Starting-only Session, isolated host publisher, CLI cache reader and verified
Offline stop. It does not include periodic sampling or operational Ready. Root
retains evidence under target/continuation-20261026T140033Z/. Actual44 captures
contain112 records, zero forbidden payloads and zero kernel drops. Earlier
ConfinementPolicy failure36 remains retained; subsequent successes did not erase
it. Root/reviewer then identified and separately reproduced the proc superblock
race: plain child readonly remount made the parent's proc attr open fail EROFS,
whereas bind-remount kept the parent writable and child readonly. Current source
uses MS_REMOUNT|MS_BIND|RDONLY|NOSUID|NODEV|NOEXEC. Actual test setup now forces the
child remount to complete before PID1's LSM transition using a private fixed pipe;
the gate is closed before exact final FD inventory. The ordinary binaries have
no test gate. Fixed role/operation/errno enums diagnose a failed LSM transition.
No confinement rule, provider budget, worker2s deadline or negative check relaxed.

Platform compatibility corrections already proved in previous root attempts:
ARM hidepid denial is accepted only after positive procfs/root/actualFDmountID,
readonly+nosuid+nodev+noexec, parentPID1 and selfPID checks. Kernel's exact hidepid
spellings2/invisible are accepted; historical overmount rows are not adopted.
Test reads use explicit openat, preserving denial of legacy SYS_open. ARM null
stdio permits only its native O_LARGEFILE0x20000 (x86_64 uses0x8000), retaining
exact /null chrdev1:3 and O_RDWR semantics. These passed the previous ARM faults.

Arch diagnostic40 identified new RTM_GETLINK fields. Current source retains
exact plain attribute66/u32 MAX_PACING_OFFLOAD_HORIZON,68/u16 HEADROOM,69/u16
TAILROOM in canonical Link metadata, distinguishing absent from zero. Duplicate,
malformed, flagged and unknown attributes remain rejected. Host and owned-link
drift includes all three. Root's read-only numeric evidence is retained under
target/platform-lab/arch-x86_64/. Ordinary RED UnsupportedLinkAttribute66 -> GREEN
plus malformed/duplicate/unknown/drift tests; actual checkpoint result pending.

ARM41 passed preexec setup/profile but failed before authenticated peer inspect.
New test-only sender diagnostics separate alive pidfd, stat/start, uid/gid maps,
cgroup membership and executable checks, with bounded elapsed milliseconds for
hashing and postlaunch/preaccept daemon verification. Strong hypothesis from
review: the fixed worker2s deadline competes with repeated hashing of the same
43MB daemon (eight full reads across these verification calls). This is not yet
measured/proved; the deadline remains2s. Any immutable verified-executable token
optimization needs retained FD/inode/read-only/provenance proof plus review and
fault regressions, not removal of admission checks.

Prior frozen e898e935 transport regressions all7 PASS,42 capture files/864 packet
records, zero forbidden payloads/drops; positive controls/counters verified.
The Ready fixture correction restored the original socket flags after the joined
continuous sender, avoiding shared O_NONBLOCK on the original client socket.
No firewall relaxation. Root execution/producer shared-journal labs on71b3 PASS.

Current frozen source66d8f676fcd3f39ed5c05daf8a3e8a2f61925aed:
- candidate target/continuation-20261026T142011Z/candidate.json,107 source inputs;
  source archive SHA dcfaee26c089775a3bd58cc4cdad394dbaf1adadf3f9549c75bf06ebd24f7a0e.
- source aggregate SHA1bc66b00a362b0e051777093cb4d35db12427b8c175ff72e1e4f115bdc1c04cd.
- cargo test --workspace --locked:214 PASS,0 failures,2 ignored (includes doc
  tests); target/runtime-bridge-race-tests.log.
- cargo clippy --workspace --all-targets --locked -- -D warnings PASS;
  target/runtime-bridge-race-clippy.log. cargo fmt --all completed.
- static x86_64/aarch64 musl, fixed four-role manifests and contexts PASS;
  target/runtime-bridge-race-build.log. Root has exact context copy request.

Session::expires_at now exposes its earliest absolute BOOTTIME deadline, using
heartbeat+44, minimumverification+44 and structural+180-handshake_age. Permanent
revocation and representable finite addition checks remain; fresh heartbeat
cannot extend a near-expiry handshake. No deadline API alone grants permission.

Exact next implementation APIs/work:
1. New narrow vprouter-netfilter TerminalQuarantine authority opens its own
   namespace socket; generated lifecycle-owned distinct terminal deny table,
   no release/delete API. Refactor exact table inspection for reuse without
   constructing an Actuator or assuming live Bootstrap/Ready phase. This writer
   must perform a generation-changing terminal commit even if already matching;
   ordinary release never references/removes its table.
2. Absolute BOOTTIME deadline for every socket wait/send/receive and terminal
   stop/mutate/verify sequence, retaining finite native exchange limits. Suspend
   and kernel-blocking behavior still need actual proof; do not claim a5s bound.
3. Fixed per-scope children opened/registered before confinement, private bounded
   IPC, exact guard pidfd and sameUID signal check, minimal capabilities, terminal
   expiry at earliest deadline minus5s, quarantine-first death/stall semantics.
   Durable journal records/recovery barriers retain allocation ownership until
   containment and exact reaping; never pass a duplicated active guard socket.
4. Connect authenticated monitor Engine sampling and privileged guard-owned WG
   structural observations. Admit Ready only after all three lease registrations
   and sufficient deadline, verified fullOffline -> staged permits -> owned CAS
   release -> re-audit. Publisher/provider/native stalls cannot renew evidence.
5. Actual single-exit runtime gate, then remaining original nine-area work.

Nine-area status at checkpoint (all remain in scope):
1. Health/state/provider semantics: core validation and Starting bridge proved;
   periodic real monitor, native structural channel and independent expiry OPEN.
2. Kernel routing/filter enforcement: native scoped policies/Ready component
   proved; terminal executor and operational Ready authority OPEN.
3. Guard/worker/init lifecycle and publication: fixed roles/confinement/publisher
   proved in components; periodic operational orchestration/watchdog OPEN.
4. Multi-exit allocation/journal: shared unique leases component proved; five
   concurrent real exits and runtime reconciliation/recovery OPEN.
5. Direct protected mode and bypass prevention: operational implementation and
   actual protected client path OPEN; public unsupported paths remain refused.
6. Platform integration: Debian component PASS; Arch/ARM pending new checkpoint;
   Void runit/cgroupfs adapter and native service/reboot proof OPEN.
7. Real client DNS/IPv6/no-fallback/leak controls: transport component capture
   evidence only; enrolled operational client/end-to-end acceptance OPEN.
8. Migration/rollback/identity preservation: approved identity retained by root;
   actual cutover/rollback/reboot tests OPEN, production untouched.
9. Performance/soak/release evidence: ordinary/static/component results retained;
   benchmark/soak/full final independent verifier and release acceptance OPEN.

No public runtime start path was enabled. Parent remains the exclusive controller
for privileged tests and enrolled identities. Continue from this worktree without
resetting or adopting observed network state as authorization.

## Handoff checkpoint 2752df5894 — NEEDS_CONTEXT (2026-10-26 14:34 UTC)

This section supersedes older 'unfrozen' and pending-result language above.
Source edits are paused for the parent-requested fresh implementation context.
Overall task is INCOMPLETE. All nine areas remain authorized and active.

### Exact source, tests, and retained native results

Current frozen source2752df5894c57d24e24dddac014920f127164dae,108 source inputs.
Candidate: target/continuation-20261026T143406Z/candidate.json.
Source archive SHA4e6209690f1ef50ec590286c3de9a2fd582e28233a2b57f0e1ee41121534d110.
Source aggregate SHA0c84ab7bbc9317fe95c2d2a4fcc2df39d5414e2361a446db7c8e7f0fd1ba9c66.
AMD64 payload SHA317a093462df8a2c448e77b7a46b58999884bd877919ef4d9e0ed2fb85485ccb;
ARM64 payload SHAa7071577c7f1f58af9e73f6548e080d4845dcb8ebfc7104f74b8770469531fe5.
Contexts copied/independently verified by root against exact four-role whitelist:
AMD64 SHA432514b2c6c65aecce3fb76b711cfc239749cdf9962a2226e168fb6b14aa070f;
ARM64 SHAa0b5edc9d082b97b3cf2cf6f848445e4746c0e9cd3236d4e83ab1ecf0416ec0f.
Static release musl builds/context consistency passed both architectures;
log target/runtime-bridge-terminal-gated-build.log. Real index/HEAD unchanged.

Ordinary tests:217 PASS,0 failures,2 ignored including doc tests;
target/runtime-bridge-gated-tests.log. All-target clippy -Dwarnings PASS at
target/runtime-bridge-gated-clippy.log. cargo fmt --all completed. Targeted
terminal tests are in target/terminal-{red,green}.log (initial missing-API RED,
then GREEN), terminal-netfilter-tests.log (24 PASS,1 ignored), terminal-clippy.log.
The final ignored-lab assertion was tightened to exact GenerationChanged after
these ordinary tests; static test compilation passed, native execution pending.

Root results on preceding immutable66d8f676:
- Debian actual45 PASS all17, including forced-order proc readonly-before-PID1
  LSM transition, both profiles, four post-pin faults, monitor Starting host
  publication and container-death cleanup. Directory task8b2-58666, exact
  directory provenance under ...142011Z/debian-x86_64-actual/.
- Arch actual46 PASS all17 with strict new canonical attributes66/68/69.
  Directory task8b2-1817, evidence ...142011Z/arch-x86_64-actual/.
- ARM actual47 failed before sender admission: measured post-spawn daemon check
  1234ms + preaccept1192ms =2426ms, exceeding the worker's fixed2s exchange.
  Directory task8b2-4936, ...142011Z/debian-arm64-actual/. This confirms scheduling
  pressure; no speculative immutable-byte cache or timeout widening was applied.
- Independent reviewer PASS/no findings on66d8 proc fix/forced-order regression,
  exact attributes and Session deadline. Historical36 raw errno remains unknown;
  root separately reproduced the shared-superblock race mechanism before fix.
- Void actual48 did NOT execute product: controller prerequisite lacked nft
  ip/filter/FORWARD because VM defaulted to iptables-legacy. Root is switching
  only its identity-free owned VM to supported nft alternative. Cgroupfs adapter
  still not implemented; expected native admission refusal is not a PASS.

Root is running ARM actual on2752df first, Debian next, and building/running the
native netfilter test from exact immutable archive. Results PENDING here. Root
will supply them to the next implementer; preserve all failed attempt records.

### Exact implementation added after66d8

`vprouter-netfilter::BootDeadline::at(f64)` represents one absolute BOOTTIME
boundary, conservatively rounded down1ns, rejecting invalid/unrepresentable
values. `check()` reads CLOCK_BOOTTIME. `Socket::open_terminal` newly opens its
own native NETFILTER socket plus nonblocking CLOEXEC BOOTTIME timerfd. A terminal
socket refuses all IO before one-time deadline binding. Every native wait polls
both the socket and absolute timer; send/recv have before/after BOOTTIME checks.
The existing five-second Instant native bound remains an additional cap. Rebind
is refused. Existing ordinary Actuator sockets have no extra timer descriptor.
Ordinary UNIX-pair test proves silent peer wait terminates on real timerfd and
an expired/rearmed budget cannot regain IO. Synthetic time check rejects a large
resume jump. Actual suspend/kernel blocked syscall proof is still NOT_RUN.
BOOTTIME timerfd is not an alarm clock and by itself is not proof that no first
packet can pass during resume scheduling; do not claim that acceptance yet.

`TerminalQuarantine::open(&Policy,lifecycle,(dev,ino))` validates64lowerhex
lifecycle, verifies actual current network namespace before/after separately
opening its socket/timer, and creates fixed Offline-equivalent terminal table.
Name = ordinary quarantine name + '_terminal_' + lifecycle; marker also binds
terminal domain+lifecycle alongside existing deployment/exit/generation/scope.
All rules exactly retain the selected exit's fullOffline semantics; host scope
still preserves unrelated traffic. No ordinary Ready release/cleanup references
this distinct name. `descriptors()` gives borrowed socket/timer handles solely
for future fixed child inventory; no duplicated active socket constructor.
`contain(&mut self,BootDeadline)` is one-shot, snapshots exact ownership/state
and generation, commits Absent-create or Matching-delete+create atomically,
requires actual changed generation, then exact table/chain/rule/extra-object
inspection with stable generation and remaining deadline. Matching is a REAL
mutation, not a no-op fence. Foreign/drift/unknown rejects. Error/deadline/lostACK
consumes the writer; it never implies contained or cleaned. There is NO product
terminal deletion API, executor process, Ready registration or journal binding
yet. `actuator::inspect_table_from` was factored to reuse exact existing semantic
verification without constructing an Actuator with assumed live phase.

Ignored native netfilter harness now, in each of3scopes, creates terminal deny,
checks writer reuse refusal, tests an old prepared release generation fails
exact GenerationChanged, runs a later fresh ordinary release and proves terminal
remains, opens a second terminal writer solely to prove Matching commits, then
uses exact test-only cleanup. Mandatory emitted case:
terminal_commit_fences_stale_release_and_survives_fresh_release.
This tests component persistence, not guard scheduling/expiry. Existing Actuator
Ready verification does not yet know terminal registrations; it must not be
used as operational readiness after expiry. The actual future guard must require
all independent executors active and prevent stopped/revoked lifecycle rearm.

ARM correction retains all executable hashes and all full daemon checks:
`actual::launch` now runs a PRIVATE before-release check in host parent while
the exact child is still held at existing five-second placement gate. Only
Handoff supplies the bound role/daemon/allocation verification for observers/
monitors; fixed daemon launch uses its existing admission. Any check error
terminates the gated child. Handoff performs the former post-spawn AND preaccept
full checks there (two iterations), before ProducerGroup verifies/moves/releases
child. It duplicates/registers only its exact placement directory so mutable
native audit can run while launch retains its mount input. `worker_launched`
private state is set only after actual launch/setup succeeds; serve consumes the
one-use attempt and refuses if no successful fixed-role launch. It still
revalidates current handoff identity before accept and, after authenticated
request/optional inspect, performs full daemon AND sender checks before ANY
ObserveOnce/Monitor permission. Worker2s and placement5s budgets unchanged.
Authored before_release_daemon_verification timings replace previous late timings.

Known next ARM timing concern: initial monitor health publication still performs
a full daemon audit before Offline/publisher submission AND another after fsync
ACK before QuarantinedStop; two full audits measured individually~1.2s on ARM.
The worker health ACK read also has2s. This checkpoint preserves both checks and
may expose this next deadline after startup is fixed. Diagnose actual output;
do not silently extend deadlines or use heartbeat as fresh verification. A
protocol phase or genuinely proved immutable-executable token may be needed;
never cache bytes on mere path/inode identity without immutable provenance.

### Exact next implementation sequence

1. Read parent results/review for2752df. Fix any actual terminal/native failure
   or gated-role ordering issue with focused regressions. Root owns all VM runs.
   Actual-program runner remains exact four roles; netfilter harness command is
   in docs/rust-v2/netfilter.md:124. Build frozen-source test executable using
   cargo test --locked --release -p vprouter-netfilter --lib --no-run; root alone
   runs it under a disposable guest netns with --ignored --exact
   isolated_kernel_integration::native_acceptance --nocapture. Preserve source,
   payload, context and executable hashes, parsed framing and failed attempts.
2. Add dedicated fixed host emergency-executor role in launch/kernel.rs plus
   private expiry.rs lifecycle controller. Spawn during verified single-threaded
   setup, three children (host/data/transport) each entering exact retained scope
   and calling TerminalQuarantine::open there; never inherit/dup guard's active
   netlink channels. Before confinement retain only null0–2, private bounded IPC,
   exact guard pidfd, terminal socket+timer and justified allocation lease FD.
   All unrelated proc/root/state/native FDs close. Restrict to necessary
   NET_ADMIN capability under same rootUID as guard, fixed seccomp/syscalls;
   sameUID/pidfd identity proves SIGSTOP authority. NET_ADMIN alone is not enough.
   Children must survive parent death until containment attempt; do not use
   generic Child parent-death-kill behavior or ordinary Drop cleanup assumptions.
3. Extend owned.rs Entry with exact lifecycle/executor durable intent and each
   child's pid/start/boot/scope/netns identity, without storing secrets. Journal
   acquire currently permits existing Phase::Offline only; transport_cleaned
   sets Offline/clears links+producer. Both paths must refuse reuse/cleanup while
   terminal executor barriers exist. Register intent BEFORE spawn/Ready, persist
   exact child completion identity only after authenticated ACK; every uncertain
   transition remains Interrupted. Keep deployment flock alive across surviving
   children or an equally proved barrier: Rc<SharedJournal> itself is parent
   memory and does not preserve lock after guard death. Add a narrow borrowed/
   duplicated lock lease API internally if needed, and fixed-FD seccomp so that
   holding it is not arbitrary write authority. Never allow allocation generation
   reuse merely because a guard process disappeared.
4. Define bounded private lifecycle/sequence IPC, bind shared health Binding and
   Session to each child. Child accepts original HealthMessage evidence and uses
   Session::expires_at earliest deadline, including handshake; new heartbeats
   cannot renew verification. Refuse Ready lease if remaining<=5s. Start terminal
   attempt at deadline-5s and pass SAME absolute earliest deadline through exact
   guard pidfd stop, mutate and verify. Stop at expiry before claiming containment
   (never stop a healthy guard during lease grant). SIGSTOP delivery is not kernel
   transaction drainage; distinct terminal table and completed generation-changing
   commit are the fence. On stop failure still attempt deny, no positive bounded
   containment claim. Late/deadline failures need explicit bounded best-effort
   containment handling; current Terminal writer is consumed and cannot rearm.
   Separate90s guard-liveness timer is not a replacement for44s health expiry.
5. Require all three live registered executor ACKs/leases and durable ownership
   before Ready transition; expiry is terminal for that lifecycle. Ordinary
   guard, native blocking, provider and publisher must not refresh lease evidence
   or remove terminal table. Add actual faults: frozen/dead guard, publisher stall,
   provider stall, native-audit/netlink blocking, child death, closed IPC, stale
   sequence, boundary/handshake expiry, suspend/resume and late containment.
   Capture packet continuity/zero leak and strict first-failure containment, not
   a later repair. Do not enable public runtime until these enforce the contract.
6. Integrate monitor Engine cadence5/retry1/provider12, host-owned privileged WG
   GET and bound structural freshness to zero-cap monitor. Add authenticated
   operational enrolled declaration loader/LocalAPI route predicates (existing
   declaration type and root metadata are not live authority). Single-exit actual
   runtime is next gate, then full original nine-area implementation and tests.

### Nine-area state at this handoff

| Area | Implemented/proved | Required next |
|---|---|---|
|1 health/provider|Strict shared Session, handshake deadline, Starting bridge, provider components|Periodic real Engine + bound structural channel + independent expiry|
|2 routing/filter|Scoped Offline/Bootstrap/Ready component; terminal writer compiled and ordinary tested|Native terminal proof, fixed executors and operational Ready lease enforcement|
|3 guard/worker/init|Fixed roles, confinement, publisher, Starting host cache proven Debian/Arch|2752df gated ARM result, full runtime lifecycle and separate90s watchdog|
|4 multi-exit|Shared journal unique leases actual execution/producer component PASS|Durable surviving-executor barrier; five real concurrent exits/recovery|
|5 protected direct|Unsupported operational path stays refused|Actual direct policy/runtime and no-fallback client proof|
|6 platforms|Debian/Arch17case PASS; ARM diagnosed; Void VM staged|ARM timing integration; exact cgroupfs/runit adapter; service/reboot tests|
|7 real client|Seven transport scenarios/capture controls PASS|Enrolled operational client IPv4/DNS/IPv6/TCP/UDP and no-leak acceptance|
|8 migration|Approved identities preserved by root; production untouched|Actual migration/cutover/rollback/reboot gates|
|9 release evidence|217 ordinary, lint/static, retained component source bindings|Performance/benchmark/soak, final independent verifier and full acceptance|

No production source/service/container/state/network was touched by implementer.
No public runtime start enabled, no fake readiness, no overall completion claim.

Late controller result for2752df: ARM actual49 now passes all14 pre-monitor
cases, including authenticated observer and four live post-pin drift faults.
Before-release daemon checks measured1247/1255ms and fit the existing5s gate.
The monitor authenticates and reaches repeated sender checks, then fails
LAB_SENDER_FAILURE verify_initial_pidfd_alive / placement_failed before final
monitor case. Exact directory task8b2-5322, evidence
...143406Z/debian-arm64-actual/controller.json. This strongly matches the separately
predicted health-frame ACK budget pressure, but preserve exact phase evidence
and add bounded publisher/daemon timing diagnostics if needed. Do not loosen
worker2s or drop daemon checks. Native netfilter and Debian results still pending
at final handoff. Parent will route them to the next implementer.
