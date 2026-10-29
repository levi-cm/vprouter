# Operational runtime continuation

Status NEEDS_CONTEXT. Source paused at final checkpoint below; all nine remain open.
Sole source writer, isolated rust/v2. No privileged/credential
or production operations; no real index/HEAD mutation, publishing, agents, reset
or clean. All nine remain active. This is not operational Ready/release evidence.

## Current source work

- New launch/enrollment.rs authorizes only a protected fixed enrollment.json,
  binding full allocation digest, container, reviewed bundle and complete health
  Binding. Root file is reread for digest equality during Handoff validation.
  Exact input schema: operational-enrollment-schema.md in this directory.
- Enrollment includes complete preserved self and peer node/IP identities;
  logical Tailscale IPv6 identity data is distinct from IPv4-only native TUN/routes.
  Operational LocalAPI GET independently matches identity before every PATCH.
- New worker/operation.rs owns bounded framed async IPC, lifecycle/frame binding,
  poison-on-cancellation, original native check times/handshake age, and finite
  three-stage publication. No worker native privileged socket is constructed.
- Actual Engine/Provider now has an operational path via authenticated bootstrap,
  5s cadence, original34s operation bound, one eligible1s retry with fresh guard
  structure each side, and actual LocalAPI offered+approved observation.
- Handoff compiles a periodic operational server against retained sender, daemon,
  allocation, namespace, policy and same-nonce3expiry children registered BEFORE
  operational grant. Native structure is fresh and original times survive IPC;
  guard validates exact issued structure when accepting worker health. Guard FSM
  and actual three leases authorize Ready. Failure prepares Offline BEFORE worker
  withdrawal; current implementation remains unavailable to public start.
- Protected execution_policy explicitly distinguishes observer/Starting/operational
  networking. New private OperationalMonitor role uses same pinned monitor binary,
  root authorization before release, zero caps, exact Unix-stream/IPv4 TCP+UDP
  sockets only. No AF_NETLINK/raw/IPv6/packet socket permission in this role.
  Existing observer/Starting behavior and four executable context roles retained.
- Separate preserved-enrollment daemon configuration enables only the authorized
  existing identity, with DNS/route acceptance, netfilter, SSH, SNAT changes pinned.
  Existing locked disabled unenrolled config remains the initial-test behavior.

## Supervision/reconciliation decision before any staged activation

No production owner exists yet. Current terminal children can SIGSTOP exact guard
but the stopped guard cannot resume itself, and all current actors inherit the
launcher's host service kill domain. Those facts prohibit enabling public start.
A future recovery owner must be separate from the mutable guard's kill domain,
retain exact guard pidfd/PID/start/boot, all3terminal children, namespace pins and
allocation lock, and own the90s watchdog. It must never rearm an expired lifecycle.
On original expiry it waits for exact three-scope terminal outcomes, kills/reaps
ONLY the retained stopped guard, drains every old mutator, and starts reconciliation
under the same durable owner. Missing/late/failed outcomes remain explicit.

Concrete intended authority split: a fixed root owner service retains protected
configuration/journal and host-visible durable namespace pins; guard runs in its
own exact admitted child cgroup. Independent expiry processes stay outside that
guard cgroup. Owner service stop policy must leave fixed expiry actors alive until
containment; systemd/runit adapters must prove this rather than assuming fork
survival. A replacement owner first acquires the surviving flock and pins old
actors from recorded boot/PID/start; live writers block recovery. No generic prefix
cleanup and no caller PID/state/bool can retire a lifecycle. Same-boot process death
must be established with retained pidfds or fresh exact recorded identity checks;
reboot is a separate explicit reconciliation path, never old PID reinterpretation.

Safe terminal retirement sequence still to implement: verify all mutators dead
and no outstanding writer, retain exact namespace pins, verify exact lifecycle
markers and kernel generations in3scopes, install/read back replacement Offline,
then delete ONLY matching old terminal policies with generation-checked batches.
Durably record each boundary before exposing new-lifecycle authority. Ordinary
old links/producers/namespace pins also need exact-owned teardown/reconstruction;
merely clearing terminal journal fields or adopting current live shape is refused.
The old guard and writers must not be revived after containment. New samples and
three-success recovery are required in the new lifecycle.

Intended controller native gate, BEFORE approved identity move: freeze the exact
live guard, kill guard unit/cgroup, kill owner separately, stop/restart service,
leave one writer frozen, then kill/reap writers and attempt new owner. Observe exact
PID/start/pidfd/stopped/exited states, all3terminal policies/generations, namespace
pin persistence without unrelated keeper processes, original deadlines, retained
flock and reboot/interrupted retirement. Prove independent writers survive guard
service kill, old lifecycle never rearms, foreign/drifted table refuses deletion,
and replacement Offline precedes retirement/new monitoring. Native packet positive
controls plus prohibited marker capture remain required; ordinary tests cannot
establish service kill-domain or first-packet behavior.

## Current checks and preserved failures

- Initial LocalAPI regression RED: PATCH occurred before independent identity GET;
  target/operational-localapi-identity-red.log. Corrected prewrite identity binding,
  GREEN50worker tests in operational-localapi-identity-green.log.
- Structural wire RED nonfinite clock accepted; corrected original-time validation,
  operational-structural-wire-{red,green}.log.
- Enrollment RED direct accepted by operational declaration; now explicitly Mullvad,
  operational-enrollment-red.log and later full suites.
- Integrated worker tests55PASS: operational-integrated-worker-tests.log, actual
  framed sockets through same Engine/recovery, original timestamp preservation,
  ACK-before-withdrawal, replay/cancellation and mismatched Commit refusal.
- Operational socket profile RED upper32bits bypass/old socket permissions;
  operational-monitor-socket-red.log. New exact profile GREEN in
  operational-monitor-socket-green2.log. First attempted GREEN failed borrow
  checking; preserved operational-monitor-socket-green.log.
- First workspace compile failed harness missing operation import; preserved
  operational-first-workspace-tests.log. Second/third full suites passed prior
  latest peer/profile additions. First strict clippy passed at that earlier state.
- Peer/profile integration suite caught old monitor fixture retaining observer
  execution_policy, operational-peer-binding-tests.log; fixture now explicitly
  proves profile mismatch refusal before assigning Starting policy.
- Final ordinary/static/frozen candidate and native tests NOT YET RUN for latest
  source. No native PASS transferred from a996 or earlier bytes.

## Original all-nine requirements

| Requirement | Implemented/evidence | Still open |
|---|---|---|
|1 secret lifetime|Prior a996 nativeGET+independent review PASS reported by root; no secret input read here; zeroizing buffers retained|Final branch verification including later bytes|
|2 shared health|Original Binding/Session and actual Starting bridge retained; new authenticated periodic Engine/channel/guard/publisher integration compiles; focused framed tests|Exact-source native operational cadence/provider/cache/fault proof|
|3 shared host authority|Generation-bound shared model and earlier native scoped preservation retained|Live adding/removing independent exits, terminal reconciliation preserving neighbors|
|4 operational runtime/multi/direct|New protected enrollment, privileged structure channel, periodic Engine and host loop, same-nonce registered executors; fixed isolated operational role|Invokable staged start, external owner/watchdog/stop/reconcile, actual provider/ads/Ready; independent5exits; explicit direct runtime|
|5 persistent clients|Existing protected boundaries retained, no new readiness claim|Owned kernel/userspace guards and full real-client no-fallback matrix|
|6 migration|Existing identity/state/production preserved, uncertain terminal state still blocks reuse|Two local independent preserved legacy installs, actual inspect/plan/apply/resume/rollback/cutover|
|7 services/platforms|Earlier pinned4role/staticx86+ARM and Debian/Arch/ARM component evidence retained; initial public launch refusal retained|New exactsource builds/native checks, external service owner/cgroup placement, Void adapter, release/install/reboot/update/rollback/uninstall|
|8 hostile faults/clients|Earlier observed terminal freeze/death/sole-survivor barriers retained; new channel replay/cancellation/original-time ordinary tests|Operational crash/freeze/provider/control/daemon/service/reboot/retirement faults and4configuration real packet matrix|
|9 performance/release|Failure logs/source distinctions preserved, no shortened soak claim|1/5/6exit repeated10min comparisons, optimization and actual24hmixedsoak, final independent all-nine verification|

## Unsafe/capability/subprocess inventory

No new unsafe block outside kernel.rs. Operational native observations remain in
host guard. Monitor zero caps retains private namespace/cgroup/root, fixed binary;
new seccomp builder only adjusts selected OperationalMonitor socket allowlist and
strict full-width arguments. Protected daemon retains onlyNET_ADMIN. Existing
3terminal NET_ADMIN processes and publisher zero-cap process are reused. New
periodic loop uses current-thread Tokio; no shell/subprocess/provider pool across
exits. Native lifecycle owner/service-domain changes are NOT implemented yet.


## FINAL bc10ba95 handoff — authoritative over earlier pending checks

Source is paused for the fresh sole writer. This is NEEDS_CONTEXT, not DONE.
No public start, owner/watchdog, service kill-domain change, terminal retirement,
identity move, credential read, production action, or privileged lab action was
performed by this writer. Parent retains exclusive controller authority.

Frozen source `bc10ba9592f59da42e69cfe413bd38e25351036b`:
`target/continuation-20261026T170654Z/candidate.json`.

- source archive SHA256 `67308b90c3b72c55d17751bd762972d08cfad2266e3390351564c5d28282125c`
- 111 verified source/build inputs; aggregate `61d4d3c3f935188406137c4772f21e661bc3135c4cfe4345c50293c25533f652`
- amd64 payload `2043374730d55175efe7c9a5bdcfb8bc71155e89df16ec1a21da625739d9028b`
- amd64 context `9020a8c0112c8eb265474b6a355a8c3937a7b66f0a4bdd2da77fb859c32f84c3`
- arm64 payload `2bcb8dff26630c68c2496c5578360e5d108379f90f7628fd5cbdb92f2f5ba00a`
- arm64 context `052116549d3ed548c81dfe3291add248fdc88d52948bdb5ffe17b2f161f3079e`

Parent confirmed both contexts are copied candidate-local and strict four-role
inventory/source binding verified. Mutable gateway-context paths may only be
refreshed after that copy; the parent has completed it for this checkpoint.
Actual real Git HEAD/index were preserved; source object/ref uses alternate index.

Ordinary verification: 244 passed, zero failed, two ignored across 23 result
suites in `target/operational-profile-workspace-tests.log`. Final strict clippy
`target/operational-profile-workspace-clippy2.log` PASS, fmt PASS, native/static
x86+ARM builds PASS in `target/operational-profile-static-build2.log`. The full
ordinary suite preceded only a test-boundary ioctl constant cast for musl ABI;
that cast was followed by strict all-target clippy and both static builds.
Frozen-source diff check versus 6cda is clean. No privileged probe was run here.

Previous exact checkpoint `6cdaeb4cee64b67240bdafb3fc666d877574cfec` remains
separately bound to `target/continuation-20261026T164855Z/candidate.json`:
244 ordinary PASS, strict clippy/fmt/static x86+ARM PASS. Parent reported Debian
actual62 PASS17 at `debian-x86_64-actual`, actual63 PASS7 at
`debian-x86_64-terminal` in that candidate directory. The terminal suite proves
native repeated Ready revalidation/private exact-snapshot publication binding,
synthetic provider recovery, and observed stopped-guard containment. It is not
actual enrollment/provider/client/service acceptance, and its PASS does not
transfer to later source bytes. Independent review of 6cda is parent-controlled.

### Exact-profile audit and new controller request

Latest production corrections after 6cda:

1. `operation::Channel::new` now calls the existing fcntl-based
   `bootstrap::nonblocking`, preserving status flags. std set_nonblocking used
   FIONBIO, correctly denied by the protected operational profile. The helper is
   crate-private; no caller can select operational permission from it.
2. OperationalMonitor alone admits SYS_shutdown for Tokio TCP/Unix AsyncWrite
   half-close/EOF. Existing other roles remain unchanged. The expected-allow
   regression failed before the fix (`operational-shutdown-red.log`) and passed
   afterward (`operational-profile-green3.log`). SYS_bind was already admitted
   in the common runtime list: the file named `operational-dns-bind-red.log` is
   a PASS regression, not evidence of a previously missing bind permission.

Audited pinned Tokio1.52.3/Mio1.2.4 Linux paths: socket with SOCK_NONBLOCK and
SOCK_CLOEXEC, bind, connect, getsockname/getpeername, getsockopt(SO_ERROR),
setsockopt(TCP_NODELAY), read/readv/write/writev, sendto/recvfrom and sendmsg/recvmsg,
shutdown, epoll_create1/ctl/wait (ARM libc uses admitted epoll_pwait), eventfd2,
fcntl, ppoll/poll, clock_gettime and memory/signal/runtime calls already admitted.
The actual DNS implementation binds unspecified IPv4, connects the fixed private
resolver, sends and receives a bounded datagram; the provider creates IPv4 TCP,
then rustls/Hyper over that stream. getrandom/ring and fixed root-store parsing
remain within existing runtime calls. No general ioctl/listen/accept permission
was added. No native TLS/provider success is inferred from this audit.

New test-only actual_lab entry: `--ignored-operational-profile`. Parent's request:
`run-frozen-platform-actual.py <candidate> debian-x86_64
 debian-x86_64-operational-profile operational-profile`, with the fixed
`run-operational-profile-debian.py`. Uses the SAME exact-artifact/root-private
`isolated-acceptance` plus `task8b2-host-acceptance` admission. Requires no
credentials, enrollment, gateway image activation or persistent task directory.

Probe construction: dedicated synchronous admitted process creates a fresh empty
network namespace and raises only its loopback interface, then creates private
Unix IPC and loopback UDP/TCP fixtures. A forked client closes inherited host
and fixture descriptors except its IPC/diagnostics; it applies EXACT
`actual_capabilities(OperationalMonitor)` (UID/GID65534, all cap sets empty,
securebits locked, no_new_privs) and EXACT `runtime_filter(OperationalMonitor)`.
Credentials and installed seccomp mode are independently checked. No additional
filter exception or production bypass exists. Parent namespace is restored on
success/failure; child cleanup uses retained pidfd and direct-child reaping.
Overall parent deadline six seconds, async client deadline four seconds; cleanup
has a separate three-second bound. All fixture sockets are inside the new empty
namespace, never host/external/provider networking.

Positive scope: fcntl bootstrap framing with original bounded deadline, Tokio
runtime/epoll/timer initialization, async Unix echo/shutdown, UDP local address,
unconnected send_to/recv_from and connected send/recv, IPv4 TCP connect/address,
SO_ERROR, TCP_NODELAY, write/read, half-close and EOF, refused-connect SO_ERROR,
and timer wakeup. Negative scope: FIONBIO/ioctl, IPv6, NETLINK, raw IPv4, AF_PACKET,
Unix datagram, listen, accept4 must fail EPERM. Existing interpreted filter tests
also exhaustively check allowed families/types/protocols/flags and upper32bits.
This is capabilities/syscalls only: it does NOT prove actual exec placement,
LSM/private-root/cgroup, immutable enrollment handoff, DNS parsing/TLS/provider,
native routing/lease/Ready, service ownership or client protection. Parent controller reported exact bc10 Debian x86_64 actual64 PASS and ARM
TCG actual65 PASS for this probe, all positive/negative stages, zero persistent
task directories. Evidence is under candidate170654Z/
`debian-x86_64-operational-profile` and `debian-arm64-operational-profile`.
Both ABI runtime paths were checked; physical ARM performance remains unverified.
These results are NOT real enrolled monitor/provider acceptance and do not
relabel the prior normal17 suite as operational networking proof.

Additional preserved failures: initial probe compilation had wrong lab helper
name/address conversion (`operational-profile-{green,compile}.log`); subsequent
syntax typo (`green2/compile2`); first static build found musl ioctl request ABI
constant types (`operational-profile-static-build.log`, `musl-errors.log`). The
corrected build used explicit platform-inferred casts only for fixed SIOC flags.
Failed candidate directory `continuation-20261026T170605Z` remains intact.
Intermediate 26946d32 at164549Z had an all-target unused-import failure and was
explicitly not submitted for native execution; 6cda corrected it. No failure
history was deleted or overwritten with a success claim.

### Exact next source owner and lifecycle work

Start from `owner-runtime-brief.md`, original constraints and this FINAL section.
The complete enrollment schema is fixed in `operational-enrollment-schema.md`.
Root has `approved-enrollment-reference.json` with48 full peer identities,4expired,
all in-map and44 eligible native IPv4 routes. It is a reference, not authorization.
The legacy state host bind is `/var/lib/vprouter-v2-lab/gateway-primary` to container
`/var/lib/tailscale`; root must preserve the complete stopped state, logical self
IPv6 metadata, node/IP/approval and nonreuse of the live primary provider key.

Usable private integration points are `GuardTransport::prepare_operational`,
`Handoff::{launch_daemon,pin_daemon,launch_monitor,serve_operational}` and
`AuthorizedEnrollment::load`. `launch_monitor` registers original same-nonce
three expiry children before operational permission release. `serve_operational`
runs authenticated fresh structural checks, guard FSM and enforced publication;
worker Engine runs real provider/LocalAPI paths. Public `Admission::launch`
continues to return LaunchUnavailable. Do not enable it by merely calling these
private pieces from the existing self-stoppable launcher.

Next implement actual separate root owner, exact guard/expiry kill domains,
independent original90s watchdog, retained lock/process/ns identity and durable
host-visible namespace pins. Implement protected staged Admission/release,
bounded stop/container death and crash recovery, then terminal retirement and
new-lifecycle reconciliation. Old writers/guard must be genuinely dead/drained;
verify exact3scope terminal generations/policies, establish/read back replacement
Offline BEFORE removing only exact-owned old terminal tables, durably record each
boundary, and refuse foreign/drifted state. Never clear a journal or rearm an old
expired lifecycle to make tests pass. Guard SIGSTOP cannot resume itself. Service
kill must preserve surviving containment writers; the namespace cannot vanish
merely because the last old guard/writer exited. The native fault matrix in the
supervision section above remains mandatory before approved identity activation.

Then root may construct the protected exact binding and stage the approved
stopped identity. Prove actual DNS/TLS provider cadence/retry, advertisement and
fresh offered+approved state, original health/handshake expiry, same-lifecycle
fresh recovery, terminal/new-lifecycle recovery and real packets. Continue every
original all-nine requirement: shared authority, five independent exits/direct,
kernel+userspace clients, preserved migration/rollback, systemd/runit/platform
lifecycle, hostile faults, repeated workloads and actual24hsoak. All-nine table
above remains the explicit status matrix: items1-3 have component evidence but
final verification remains open; items4-9 still have substantial implementation
and native acceptance gaps. No entire item or whole task is newly marked DONE.
