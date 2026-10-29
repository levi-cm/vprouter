# Owner runtime continuation — review-fix checkpoint

This is an intermediate checkpoint, NOT overall DONE. All nine requirements remain
active. Public Admission::launch still refuses. No owner/service/watchdog/pin/
retirement functionality has yet been added in this continuation. The root
controller alone handles privileged or credential-bearing LOCAL VM work.

## Fixes to the independent bc10 integration review

Baseline immutable source: bc10ba9592f59da42e69cfe413bd38e25351036b.
Only crates/vprouter-worker/src/engine.rs, its engine/tests.rs and launch/handoff.rs
have functional/test changes. Existing untracked source remains preserved. Real
Git index/HEAD, production Python, containers, networks, state and identities were
not changed; no credentials read, no agents spawned, no publishing.

1. **Shared heartbeat cancellation.** Extracted the existing production sample
   driver unchanged into private operational_sample so the exact control flow
   could be tested. A real Unix framed Channel regression withheld its heartbeat
   ACK until an ordinary Engine error was processed. On baseline behavior,
   operational_publish returned GuardUnavailable instead of publishing Blocked.
   The fix retains and finishes the SAME bounded heartbeat future when sample
   finishes. During the wait before sample finishes, sample/provider timers remain
   concurrently polled. No request deadline, sample timeout, evidence timestamp,
   cadence or retry rule is reset. Channel poison-on-cancellation remains intact.
   The regression covers both ProviderNegative and LocalAPI Identity error,
   successful Blocked Prepare/withdraw/Persist/Commit, then four fresh samples to
   Ready on the same lifecycle and monotonically increasing framed stream.
   A second regression uses a real framed heartbeat and controlled Tokio clock:
   sample cancellation happens exactly at original34s while the heartbeat reply
   is outstanding. Initial attempts at this additional test let Tokio auto-advance
   on socket readiness (34.984s observation), corrected by keeping the executor
   runnable while only explicit advances control time; production was unchanged.

2. **Publication aggregate deadline.** Extracted the existing final verification/
   ACK boundary into operational_reply, and request read into operational_read;
   initial helper retained old frame-only behavior. Three tests went RED: delayed
   final verification emitted Persisted/Enforced after the original aggregate,
   delayed ACK serialization emitted after it, and a pending Commit read accepted
   a new frame after the original aggregate. The common deadline now takes the
   minimum of frame and original pending publication end. The pending deadline
   survives Commit taking its state. Read, poll, intermediate native verification,
   Persist proof/submit/poll, Commit apply, final sender/executor verification and
   ACK/postcompletion retain that same bound. Synchronous native operations are
   not made preemptible; expired completion is rejected before any subsequent
   operation/ACK. The ordinary positive control still emits a valid timely frame.
   Each frame remains2s and aggregate6s. Evidence and lease deadlines unchanged.

## Ordinary evidence and failures

- target/owner-heartbeat-red.log: expected RED at Blocked publication, actual
  GuardUnavailable versus expected success.
- target/owner-heartbeat-green.log: provider and LocalAPI race/recovery PASS.
- target/owner-heartbeat-deadline.log and deadline2.log: test-clock scheduling
  failures retained; deadline3.log corrected controlled-clock PASS.
- target/owner-publication-red.log: all3 expected deadline regressions fail.
- target/owner-publication-green.log: all3 PASS after fix.
- target/owner-review-workspace-tests.log: cargo test --locked --workspace PASS,
  250 passed, zero failed, two ignored; privileged lab entrypoints explicitly SKIP.
- target/owner-review-clippy.log: cargo clippy --locked --workspace --all-targets
  -- -D warnings PASS.
- target/owner-review-fmt.log: cargo fmt --all -- --check PASS.
- target/owner-review-static-build.log: static x86+ARM frozen build in progress;
  exact candidate will be recorded below. Root confirmed bc10 contexts copied
  and authorized refresh before this builder invocation.

No new unsafe block, syscall, capability, process, FD authority or runtime role
was introduced by these fixes. No operational provider/client/service/runtime
acceptance is claimed by ordinary tests. Source-specific native checks are root
controlled; older PASS does not transfer to this candidate.

## Remaining nine areas

| Area | Status at this review-fix checkpoint |
| --- | --- |
| Secret lifetime | Earlier sanitizer implementation reviewed; no new secret work; final whole-runtime acceptance open. |
| Shared health contract | Operational channel/publication implemented; two reviewed integration fixes here; native operational provider gate open. |
| Shared host authority | Existing shared lease components; independent five-exit live host behavior still open. |
| Operational runtime and multi/direct | Actual external owner/watchdog, distinct kill domains, durable namespace pins, protected staged start/stop, terminal reconciliation next; five exits/direct remain open after single-exit gate. |
| Persistent clients | Kernel and userspace guards plus real no-fallback acceptance remain open. |
| Migration | Two local existing identities, real release/state transaction and rollback remain open. |
| Services/platforms/artifacts | Systemd/runit lifecycle and boot containment, Void verified adapter, immutable updates/uninstall remain open; static binaries alone are not this proof. |
| Hostile and real-client acceptance | Existing component matrices only; owner/service faults and IPv4/DNS/IPv6/TCP/UDP four-shape capture matrix remain open. |
| Performance and soak | Repeated actual10min one/five/six-exit comparisons and true24h mixed soak remain open; no shortened substitute. |

## Next sequence

Freeze tested candidate; root copies immutable contexts; independent reviewer
checks these two fixes. Do not begin new functional owner source until accepted.
Read-only architecture preparation may continue. Then implement owner-runtime-
brief.md in full: external root owner and original90s watchdog, exact guard/writer
kill separation, host-visible namespace pins, invokable protected staged runtime,
bounded terminal stop/death, all-old-mutators-dead safe reconstruction under
unchanged allocation lock, original generation/three-scope policy proof and
replacement Offline-before-old-terminal deletion. Root receives source-bound
native payloads for service/guard/owner death, freeze, survivor, interruption,
foreign drift and persistent pins BEFORE approved identity/provider activation.
After reviewed actual single-exit gate continue every remaining area above.

## Frozen review candidate 7ee4e502

Source is frozen pending root/reviewer acceptance of these two fixes.

Candidate: `target/continuation-20261026T172031Z/candidate.json`.
Source: `7ee4e5029880a1a8d8597520f13e72765eb85d7c`; source archive SHA256 `bc8697905ec3ceac59c0b43e182a247d712ba85121e7eb4e7c76d4ff28fb0a64`.
Binding: `{"source_aggregate_sha256": "ab2cbb73637e354b1b5a2a189e6bfe9f1911a89e7205902c715b8ff4057bfbeb", "source_archive_sha256": "bc8697905ec3ceac59c0b43e182a247d712ba85121e7eb4e7c76d4ff28fb0a64", "source_commit": "7ee4e5029880a1a8d8597520f13e72765eb85d7c", "tracked_build_inputs_verified": 111}`.
- amd64: payload SHA256 `f26efba37bbfe2c68fb7977d77fe9f103550d1641604f2361dbe5f29566dde37`, context SHA256 `a4af2fe638c9258771289a15cd39fc62d1bf7ffbf9f43d57bfce9fee024765d5`.
- arm64: payload SHA256 `11945e22b8dd7794a176bcd9bf1554e55aa499e483a3d7d97a5266e92f77d21f`, context SHA256 `8cb806bd0e225a70f7816eb3ea4f78183709e58663e0d1535fec9702aaecdb73`.

Both static musl builds and exact source-input binding PASS. Frozen diff check
versus bc10 PASS. HEAD remains c6a138c00b70163ba3cbfdf350e5cf8e2f3a3c6a.
No additional owner functionality or new native acceptance is implied.

## Native owner/domain checkpoint in progress

Independent scoped reviewer accepted7ee4e502: both Important findings addressed,
no new Critical/Important. Root copied/strictchecked both immutable contexts.
Source work continued only after that acceptance.

New production code (not yet an operational public start): supervision.rs uses
pinned zbus5.19.0, default-features=false, tokio+p2p, direct /run/systemd/private.
Protected socket path identity is checked before/after connect and actual
SO_PEERCRED must be PID1/UID0/GID0. Current root host mount/network/user/PID
namespaces must match PID1. Fixed owner unit is allocation-digest-bound, its
ControlGroup/MainPID/KillMode are read from authenticated PID1. Exact fork child
scope creation is lifecycle-bound, separate from owner, BindsTo/PartOf empty;
job completion is polled within original2s manager deadline, including final
completion. Successful D-Bus return alone is insufficient: nsfs/cgroup2fs,
root-owned exact cgroup inode and exact PID membership are independently checked.
No raw root cgroup writes or service-manager shell invocation.

The native connection lives only in a fresh current-thread Tokio runtime, closes
before runtime drop, and thread/registered-FD inventory is checked before and
after. zbus's Tokio backend uses task spawning; the async-io executor thread and
blocking APIs are disabled. No manual executor tick is needed. New fork work
remains inside reviewed kernel.rs, after one-task and FD inventory checks.

kernel::spawn_owned_guard holds a fixed closure behind a private seqpacket gate
until scope placement/readback. Owner death installs SIGSTOP, never SIGCONT;
failed pre-release placement kills only the exact held gated child. Scope kill
signal is SIGKILL, so terminating a stopped lifecycle cannot execute old guard
code. ManagedGuard retains its pidfd/control channel/scope; dropping it does not
remove containment or resume a stopped guard. owner.rs adds ExternalOwner real
poll/signal loop plus original90s watchdog and bounded Progress/ACK; a frozen owner
cannot be hidden by unacknowledged one-way progress. Watchdog invalid/replayed/
stale/future messages and expiry irrevocably terminate the lifecycle. Terminal
return retains owner rather than minting cleanup permission.

An owned expiry path now places each real fixed writer behind its own pre-start
scope gate and retains scope evidence in Executors. Existing baseline component
path remains for old tests. The new path is NOT YET wired into operational Handoff
and public Admission::launch remains refused. Full stop/reaping/retirement is
unfinished, as are durable host-pin startup and runit adapter. No service/kernel
or provider acceptance is claimed before root executes new frozen probes.

### Multi-exit authority decision (binding continuation requirement)

A single mutable deployment guard would preserve Rc coherence but conflicts with
per-exit terminal SIGSTOP and mandatory neighbor/direct fault isolation. Therefore
the final multi design uses separate per-exit guards, with one actual external
owner holding authoritative Journal and HostAuthority. Guards must use bounded,
authenticated lifecycle/allocation/generation/sequence-bound IPC for journal
transitions and shared host membership/audit; they may NOT persist inherited
copies of Rc/RefCell state. Inherited OFD flock is NOT interprocess serialization.
Single-exit native gate can precede this conversion; it cannot certify multi.
Before adding exitB, move these authorities into the owner's request handler and
verify failedA does not stop or stale-overwrite B/direct. This change is required
implementation, not an optional optimization or a dropped requirement.

### Early controller payload contract

New actual_lab modes:
- --owner-domains-descriptor: read-only exact owner service name JSON, no host
  mutation, can be run on the frozen architecture payload before creating unit.
- --ignored-owner-domains: authenticated PID1 service/sibling scope placement,
  gated guard release, native identity/membership, actual stopped-state witness,
  exact SIGKILL/reap. Component-only, no provider/namespace/network activation.
- --ignored-owner-watchdog: real external-owner IPC plus original full90s without
  further progress, observed stopped guard before any test signal, exact reap.
  Allow120s outer controller wall clock; product90s unchanged.

Both actual modes require the existing root-private isolated-acceptance and exact
artifact/network-bound task8b2-host-acceptance files. Additional fixed public nonce
file /var/lib/vprouter-v2-lab/owner-domain-nonce must be root0600 and contain EXACT
64lowerhex bytes (no newline). Use a fresh nonce for each probe; no old scope reuse.
Controller creates ONLY the exact descriptor-provided owner@allocationhash.service
in owned VM, after refusing a preexisting unit. Use Type=exec or simple,
KillMode=control-group, root, no PrivateMounts/PrivateNetwork/UserNamespace, bounded
RuntimeMaxSec120. Source is passed as exact admitted payload argv plus one mode.
Scope names/PID/start are emitted by the probe before cleanup. Guard scope
is separate from owner service. Root may kill only exact created service/scope
actors after identity verification if a probe fails; no prefix cleanup.

The probe does NOT prove3writer survival, service restart/stop, durable pins,
retirement, operational start or real client behavior. Those remain mandatory.

### Ordinary evidence for owner/domain code

- owner-scope-red.log: exact valid child membership rejected by missing feature;
  owner-scope-green.log: intermediate closure lifetime compilation errors;
  owner-scope-green2.log: scoped allocation/lifecycle/PID/sibling negatives PASS.
- owner-watchdog-red.log: expected RED (expired original deadline accepted);
  owner-watchdog-green.log: original90s, originalsent_at, irreversible expiry and
  invalid/replay/stale/future message negatives PASS.
- owner-zbus-{dependency,peer-dependency,check}.log retain dependency resolution
  and initial build; only default-disabled tokio+p2p features enabled.
- owner-supervise-check.log retains an intermediate missing Result type annotation.
- owner-domain-workspace-tests2.log:252ordinaryPASS,0failed,2ignored; no privileged
  tests executed. This precedes only bounded systemd job-completion polling.
- owner-domain-clippy.log failed too-many-arguments after scoped terminal path;
  fixed by using existing typed ChildBinding. owner-domain-clippy2.log and
  owner-domain-clippy3.log PASS; latter includes bounded job completion.
- owner-domain-fmt2.log PASS before final formatted bounded job helper; final fmt
  will be rechecked with frozen candidate.
- owner-domain-static-build.log: frozen static build underway, exact result below.

Official primary API sources consulted:
https://systemd.io/CGROUP_DELEGATION/ (single-writer/delegation requirement),
https://freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html
(StartTransientUnit/GetUnit/properties), https://docs.rs/crate/zbus/5.19.0
(Tokio runtime, p2p and executor features). Native assertions remain decisive.

## Init build-boundary failure and structural correction

First owner-domain-static-build.log FAILED the preserved builder assertion after
first manifest rewrite and inert init rebuild. Current init binary contained no
current role hash/manifest JSON prefix/private D-Bus path; direct embedding of
selfhash was NOT established. Whole-library coupling still made immutable
four-role hash stability invalid. No assertion was removed or weakened and no
fixed-point hash loop was introduced. Failed candidate directory is retained.

Corrective packaging change: error.rs contains the unchanged shared Error enum;
kernel_base.rs contains the one shared implementation of the existing inert PID1
and Linux primitives. Host kernel imports those primitives; standalone init_main
uses only Error+kernel_base, no whole vprouter_launch host-library call. Unsafe
boundary is now kernel.rs plus this reviewed shared kernel_base.rs. No new unsafe
logic was introduced by extraction. Sixteen function bodies match7ee4e502 exactly
after whitespace and process::single_threaded qualification normalization;
target/owner-init-shared-boundary-equivalence.json records every comparison.
The single_threaded implementation moved from process.rs without predicate or
flag changes; process.rs delegates to it. Exact cap/LSM/FD/seccomp/signal/reaping
behavior remains. Old security tests consume the SAME moved functions.

owner-init-workspace-tests.log:252ordinaryPASS,0failed,2ignored after extraction.
owner-init-clippy.log: orphaned moved gateway_init doccomment failure retained;
comment moved to its function; owner-init-clippy2.log is the corrected check.
owner-domain-static-build2.log PASSboth; BOTH original init hash-stability checks
passed on each architecture, with115verified source inputs. Intermediate a02a3e98
candidate175231Z is retained but not requested for native use because its doccomment
clippy failure preceded the final corrected freeze. Root will run actual init/
Starting regression on both x86 and ARM plus scope/watchdog probes against final
frozen bytes. Native PASS from earlier source cannot be transferred.

## Frozen early-native source e93201bc — current authoritative checkpoint

Source `e93201bc4ca45e1115880aa58a697c0a089539ad`; candidate `target/continuation-20261026T175445Z/candidate.json`.
Archive SHA256 `f4af3dda78dda3892ce5474aca7ab9319ae6750b3cf47a4fdc75b07c2c9c6e59`; binding `{"source_aggregate_sha256": "a9ebddbd0d7314ca52aafd03f3b3c2b0d711c97d319b396ed9ee46f6d6847a53", "source_archive_sha256": "f4af3dda78dda3892ce5474aca7ab9319ae6750b3cf47a4fdc75b07c2c9c6e59", "source_commit": "e93201bc4ca45e1115880aa58a697c0a089539ad", "tracked_build_inputs_verified": 115}`.
- amd64: payload `744476200b8ceabd89ac5ae578d5d8be87036557030a36f8ab2c1a0cc013c168`; context `16333678b5b86de64a660f71c6c566fe487a94396e71f026256c16d685a48042`.
- arm64: payload `439448b5c4c206e49258db6752b6025d81a10642e1423bb498be90003edf4d79`; context `49d8cfaa1d7f77c69df2b0961c7fc7afb5e1531c6bce746f61b48864aeba28ce`.

252ordinaryPASS/0failed/2ignored, strict clippy owner-init-clippy2.log PASS,
fmt owner-init-fmt2.log PASS, both staticmusl builds and BOTH original init hash
stability assertions owner-domain-static-build3.log PASS. Full ordinary suite
preceded only doccomment relocation; strict all-target clippy followed relocation.
No real index/HEAD changes; HEAD remains c6a138c. Old failing/intermediate snapshots
are preserved. Root notified to copy contexts then run native exact-source tests.

Controller stdio constraint: inventory::verify rejects sockets onFD0/1/2, so default
journald stdout is NOT an accepted owner startup environment. Root prepared exact
Typeexec owner units with StandardInput=null and StandardOutput/StandardError
regular, root0600, exclusive nonce-bound files. No notify/socket-activation FDs.
Retain this contract in product service artifacts; do not widen it for the probe.

Native e932 evidence remains PENDING at write time. No old PASS is transferred.
New observer, provider, client, migration, service-restart or retirement acceptance
has not been claimed. Source paused for early-native tests/review; all nine remain
active and this checkpoint is NOT overall DONE.

### Exact functional continuation points

1. First address concrete e932 native/reviewer failures, preserve logs, refreeze.
   Native probe paths: actual_lab_main --owner-domains-descriptor,
   transport_lab::{run_owner_domains,run_owner_watchdog}; supervision::lab_run,
   owner::lab_watchdog. Root alone runs privileged LOCAL VM/service operations.
2. supervision::Domains currently verifies only systemd exact owner service and
   lifecycle scopes. Implement actual verified PID1runit/cgroupfs adapter; do not
   accept arbitrary caller cgroup paths or bypass real namespace/ownership checks.
   Process cgroup_path/ProducerGroup::path/evidence::daemon still systemd-only.
3. Wire owner::ExternalOwner to a protected, user-invokable staged start. It must
   retain allocation lock, namespace pins and process/child identities before
   guard release. Current public Admission::launch and StagingEvidence::parse
   still refuse; leave them refused until genuine prerequisites exist, then wire
   real approved four-role bundle/Docker admission/config/enrollment/host policy.
   Do not substitute a cfg(test)-only runtime or another caller evidence flag.
4. Create OwnedNamespaces pins via Transaction::acquire ONLY after verified host
   mount namespace equality with PID1 and BEFORE fork/private-mount changes, so
   pins survive all actor deaths without unrelated keeper processes. Persist
   namespace IDs plus same-boot process IDs/start/pidfds/cgroup identities and
   immutable lifecycle in the durable transaction. No old PID reuse on reboot.
5. Handoff::prepare currently generates its own nonce. Operational prepare must
   receive the exact GuardOwner capability and bind the intended lifecycle once.
   Its launch_monitor must call existing Executors::spawn_owned (not old baseline
   spawn); ObservationAudit::expiry needs that typed domain authority. All3writer
   scope placement+registration/journal ACK must precede Operational permission.
   GuardOwner::heartbeat has actual bounded Progress/ACK and should be integrated
   without extending current per-frame2s or publication6s/provider deadlines.
6. ExternalOwner::supervise currently stops exact guard and returns TerminalGuard;
   this does NOT authorize cleanup. Add actual bounded containment observation,
   old process drain and exact reap, including workers/daemon in producer Docker
   subgroup. Retain same flock and namespace pins; require all old mutators/writers
   genuinely dead before reload/mutation. Never SIGCONT old terminal guard.
7. Implement safe durable terminal retirement/reconstruction. Existing
   TerminalQuarantine::verify_existing is read-only; no production delete exists.
   Verify exact3scope policy/lifecycle/kernel-generation witnesses, install/read
   back replacement Offline FIRST, then CAS-delete ONLY matching old terminal
   tables. Persist each boundary and make interrupted replay idempotent. Unknown/
   foreign/drifted state retains records+Offline. Verify and tear down exact old
   links/producer/daemon/pins rather than adopting their live shape or clearing
   terminal fields. Same-boot and reboot reconciliation remain separate paths.
8. Before multi-exit, replace copied Rc Journal/HostAuthority writes with actual
   single owner authority + authenticated bounded per-exit guard IPC as specified
   above. Separate per-exit guards are required because terminal writers stop
   their exact guard; one shared mutable guard would violate neighbor isolation.
9. After reviewed native+provider single-exit gate, finish independent5exits,
   explicitdirect, persistent kernel/userspace clients, two real local preserved
   identity migrations and transactional release/state rollback, systemd+runit
   boot/update/uninstall, full hostile client/capture matrix, repeated10min whole
   router one/five/six workload comparisons and true24h mixed soak. None is dropped.

New unsafe operations beyond extraction: kernel::spawn_owned_guard gated fork,
fixed parent-death SIGSTOP (neverCONT), exact pre-release failure SIGKILL/reap.
OwnerSignals wraps existing blocked_signals/pending implementation. Scoped real
terminal spawn adds pre-start gate and holds registered exact guard pidfd; terminal
cap/filter/socket/timer algorithm remains unchanged. zbus manager runtime creates
short-lived async sockets/epoll/timers only; no descriptor survives its runtime
into the next fork and inventory/thread checks enforce this. The host owner is
still privileged setup code, not a newly broadened worker role. Gateway4roles and
worker OperationalMonitor zero-cap profile unchanged.

### Native early checkpoint failures and diagnostics (18:xx UTC)

All failures retained, no old PASS transferred:
- e932 actual66 normal Debian failed DescriptorPolicy after two initial cases,
  before cache/publisher case; directory task8b2-63608, no health.json. Root
  independent source review PASS/16 moved function bodies equivalent does not
  override this native failure.
- e932 actual67 owner service lacked explicit Slice=system.slice; default template
  slice violated required exact owner cgroup. Root verified dead actors and fixed
  fixture Slice only; production predicate unchanged.
- e932 actual68 explicit-slice probe reached zbus5.19 private socket and panicked
  in message/fields.rs219 Invalid field reconstruction / Invalid unique name.
  No actual scope/watchdog PASS. Do not catch or suppress that parser panic.
- Diagnostic b398dea57592a9f44884933ec8351c196b952831 frozen at
  target/continuation-20261026T180423Z/candidate.json. Both static builds + both
  init hash assertions PASS; diagnostic clippy/fmt PASS. Root copied both contexts.
  Actual69 reproduces normal failure precisely before publisher fork:
  before_spawn -> before_inventory -> mismatched_fd=7, registered=false.
  Child-ready FD5 race hypothesis ruled out for this failure; no guessed fix.
  Diagnostic target readlink/type/CLOEXEC added for next run; no file contents.

Native system-bus correction in progress: fixed protected root-owned
/run/dbus/system_bus_socket, listener creator SO_PEERCRED PID1/root is NOT treated
as proof of bus dispatcher identity (socket activation retains creator creds).
GetNameOwner returns immutable unique manager connection; GetConnectionCredentials
must report ProcessID1 and UnixUserID0. All work targets that unique name, every
reply sender is exact; manager owner+credentials and endpoint inode rechecked
before returning. Entire connect/auth/query/mutation/readback remains within same
original2s manager deadline. Runtime dropped then thread/FD checks unchanged.
Official protocol reference https://dbus.freedesktop.org/doc/dbus-specification.html
Root platform references: system-bus-authority-reference.json (Debian/Arch/ARM).
Native full90 watchdog still NOT_RUN. This is not functional operational start.

Frozen bus correction/diagnostic candidate e68b166e4a4baa054a1c1cac57df0080cb9687b2: target/continuation-20261026T180848Z/candidate.json. Covering commands cargo test --locked --workspace (253 PASS,0 failed,2 ignored); cargo clippy --locked --workspace --all-targets -- -D warnings PASS; cargo fmt --all -- --check PASS. Logs target/owner-bus-{workspace-tests,clippy,fmt}.log. python3 target/implementation-20261026-build.py PASS (target/owner-system-bus-static-build.log), both static architectures and BOTH init-stability assertions. Native normal/scope/watchdog PENDING root run; initial credential-negative tests do not substitute actual D-Bus proof.
Source archive SHA256 3d4ba0d62d41aef5200324e4b60113f10b320560650fe3a0cfefeadbc27572ba
amd64 payload 6fc8602aafaa341510ee58da2037d122cc2cbcaf881907dca7a59aa76699a35d context 16333678b5b86de64a660f71c6c566fe487a94396e71f026256c16d685a48042
arm64 payload 39d59611062dcb2336aa3491406f99729df08df4737289ad34a24482ede61a37 context 49d8cfaa1d7f77c69df2b0961c7fc7afb5e1531c6bce746f61b48864aeba28ce

### Native FD regression diagnosed and repaired at dependency boundary

Root actual70 e68 normal: mismatched FD7 was CLOEXEC socket, target socket:[426861].
Actual71 e68 scope: post-manager inventory rejected CLOEXEC socket FD6 [428022].
Root proposed Tokio global signal driver and local source confirmed it: zbus5.19
Tokio dependency enables process unconditionally; Tokio1.52.3 Driver::new creates
signal Driver, globals() permanently owns UnixStream::pair. Runtime drop closes
its clone, not the two global sockets. This explains normal path failures even
without invoking zbus: Cargo unifies dependency features across the binary.
No unexpected FD was allowed, registered, closed behind another owner, or ignored.

Meaningful fresh-subprocess RED test dropped_native_io_runtime_leaves_no_global_descriptors:
minimal current-thread enable_io/enable_time runtime, before {0,1,2}, after
{0,1,2,6,7}; target/owner-runtime-fd-red.log. Process freshness prevents earlier
Tokio tests from hiding initialization. GREEN target/owner-runtime-fd-green.log.
Pinned supported zbus6.0.0 with only tokio and no default features; its minimum
Tokio1.53.3 also pinned in workspace. No local vendoring or registry modification.
Primary release reference https://docs.rs/crate/zbus/6.0.0 and upstream upgrade
https://z-galaxy.github.io/zbus/upgrading-to-6.html explicitly describe process/fs/
rt-multi-thread/tracing removal, unixexec/ibus opt-in. Local cargo info output
saved target/owner-zbus6-availability.log. V6 renames wire Value->Variant and
OwnedValue->OwnedVariant; native UnixStream builder takes std stream, converted
from same already-verified Tokio stream. Removed obsolete internal_executor API;
only Tokio current-thread backend exists in enabled features, no default runtime.

Added both-musl-target dependency graph regression prohibiting Tokio process,
signal, rt-multi-thread, fs and zbus default/default-rt/unixexec/ibus/p2p/multithread.
First version used cargo metadata; it includes inactive optional-feature edges,
so false failure retained target/owner-zbus6-workspace-tests.log. Corrected to
cargo tree --locked --target <target> --invert <package> --depth0 --format {f},
which reflects actual resolved build graph. Saved both target feature trees.
Full final ordinary suite255 PASS/0failed/2ignored, clippy-Dwarnings/fmt PASS:
owner-zbus6-workspace-tests2.log, owner-zbus6-clippy2.log, owner-zbus6-fmt2.log.
Intermediate b01403c14718aa308383d52005cedc94b5f1c64b (candidate181540Z) superseded,
NOT supplied for native runs: final graph test was corrected during that build.
Fresh sequential freeze owner-zbus6-static-build2.log follows completed checks.
All four role bytes must be reverified on new source; no old native PASS transfer.

Final sequential dependency fix freeze ea749adc1fc58ecf28e6e63433759b52c2b38009 at target/continuation-20261026T181728Z/candidate.json; 255/0/2 ordinary, final clippy/fmt PASS; owner-zbus6-static-build2.log botharch/BOTH init-stability PASS. Root copied and independently strictchecked both immutable contexts. Native/review PENDING; previous failures preserved.
Source archive SHA256 c8d53f31ed0b947f79183cf5244c43f7558566b9226722c7d8945db86a3bfd25
amd64 payload a494aa12454b3fdba3f2efefcf96be3ced87160850d69b23f860ba9caf725edd context 1fd18bc3f50ea2383f9a7f5ff3e49dd47888924dcd508276256e783d19f3acb3
arm64 payload 9085aea90c65dc735668ab418baaeb01a2bde003a5942b1b8f131c8688c1877f context 32535ff8ebc19edbfbf62e2d8efcf20d766f5588d5ec68ac70a557da164c0396

### Scope property binding correction after native73

Exact ea749 native72 Debian actual17 PASS, including publisher exact FD0..4,
actual immutable daemon/observer/Starting monitor/drift/container death. It proves
unneeded global-signal-feature removal fixed native pre-fork inventory, with
no descriptor allowlist change. Native73 scope FAILED CgroupMismatch. Root's
actual host introspection plus upstream API confirms ControlGroup belongs to
Service/Scope, not Unit. Public signatures captured on all3systemd guests in
service-property-signature-reference.json; runtime checks still query live PID1.
Source correction: owner ControlGroup reads Service. Scope batches GetAll(Unit)
and GetAll(Scope) to bind Id/Transient/BindsTo/PartOf and exact scoped group plus
Slice/KillMode/KillSignal/TimeoutStopUSec/SendSIGHUP/Delegate/SendSIGKILL. No global
Service GetAll (avoids fetching unrelated Environment/ExecStart). Explicit
SendSIGKILL=true requested along with prior properties. Same original2s budget.

Meaningful validator RED retained owner-scope-policy-red2.log: prior validation
accepted actual KillMode=process even though request was control-group. GREEN
owner-scope-policy-green2.log rejects wrong/missing/mistyped policy, wrong property
interface, wrongunit and dependencies. Initial extraction compile error (helper
shadowed request properties local) preserved red.log/green.log; renamed helper
before semantic RED. Test-only LAB_SCOPE_POLICY_READBACK prints a fixed whitelist
of OBSERVED parsed values before release/reap; it does not print requested-only
constants or whole property maps. No new production override or bypass.
Native source remains a component checkpoint. Original full90 watchdog NOT_RUN,
operational start/provider/client/reconciliation all still required.

### e47e native component boundary established

Root exact e47e6ed9082159097fefc94dc2cf94f80aed3f98 at candidate182533Z:
Debian native75 scope PASS actual guard65550/start19483980, native policy whitelist
matches all requested properties, exact sibling placement/stop/kill/reap.
Full ORIGINAL90s native76 PASS guard65644/start19492304, original deadline
195013.053372829, observed stopped195013.102849944 (+49.5ms). No shortened clock.
Independent property review PASS. Arch scope79 PASS. Operational profile77x86/
78ARM PASS. Arch actual80 PASS17/6captures112records/0forbidden/0drops. Exact ea749
Debian72 + ARM74 PASS17 each, ARM74 also6captures112records/0forbidden/0drops.
These are source-bound components only: no operational enrollment/provider/client
proof, operational staged start or reconciliation. Public launch remains refused.

### Central journal and bounded IO actor implementation checkpoint

owner.rs now has private request/reply frames bound to allocation digest (including
full generation), explicit selected exit, lifecycle, one monotonic sequence space
shared by progress/journal RPC, exact original sent_at. Client poison on failure;
checks BOTH Instant timeout and BOOTTIME age before/after reply (suspend counted).
Owner rejects invalid binding/replay before mutation; no ACK until durable child
completion inside original sent_at+2. New JournalServer is a concrete typed
service, not an arbitrary synchronous callback. No synchronous fsync is invoked
by owner service polling. Raw server response contains no readiness boolean.

owned::Transaction can mint fork_remote ONLY with actual gated GuardOwner, only
in a different process from Journal creator. Inherited Local Journal::persist,
local Transaction mutation/revalidate/new-exit lease reject creator PID mismatch.
Parent JournalServer stages canonical record change, restores committed record,
and gates one fixed IO child; only successful original-deadline child ACK commits
RAM/response. Once server attaches, direct local persistence/mutation is refused;
all durable post-bootstrap changes route through owner service. Shared pending
record prevents another writer; on any late/failing write it is fenced/retained.
Readonly jobs can verify current or exact pending atomic snapshot, allowing
unchanged-member read service beside a stopped writer. This does NOT yet implement
multi-guard owner polling or HostAuthority RPC; it is not proof healthy exit B
continues in a real multi-exit runtime. Those remain mandatory next work.

kernel::spawn_journal_io is new reviewed unsafe boundary: one-task gated fork,
retained exact pidfd, default parent-death SIGKILL, fixed chroot to protected
journal directory, UID/GID0 groups[], all caps0/bounding0, no-new-privileges,
existing publisher seccomp extended only with read for fixed record files.
After setup only null0..2, ACK3, directory4, allocation OFD lease5 survive; open
record/temp6 is transient. No arbitrary callback/exec/path, no setns/mount or
persistent SYS_ADMIN needed by this actor. Parent still requires setup rights
for the fixed chroot; overall owner/guard steady capability reduction is NOT yet
implemented and must precede public steady loop. Parent stores pending state
BEFORE releasing child gate. No cancel/Drop waits on stuck IO; exact SIGKILL
fences writer and held OFD lease prevents successor lifecycle until actual death.
JournalIo child validates exact allocation + expected old snapshot, O_EXCL temp,
write/fsync, BOOTTIME original deadline before rename, directory fsync and final
original deadline. Late nonpreemptible IO retains uncertainty/temp/pending/lease,
not a fresh budget or automatic retry. Production terminal retirement/restart
readback/reconciliation still NOT implemented.

Ordinary real SEQPACKET tests exercise shared progress/journal sequencing, wrong
allocation/exit/lifecycle/replay/original timestamp, poisoned reuse, actual2s late
reply. Mutation-check RED deliberately removed allocation response check and
failed the real framed negative test: owner-journal-binding-red.log; restored full
workspace259 PASS/0failed/2ignored owner-journal-workspace-tests3.log, strict clippy
owner-journal-clippy4.log, fmt owner-journal-fmt3.log PASS. Earlier compile/clippy
failures preserved (record Clone, boxed large operation variant/test pattern).
No claim these ordinary tests establish privileged child confinement/durability.

New exact native mode --ignored-owner-journal uses existing descriptor owner unit
and owner-domain-nonce, actual fixed privileged service/rootstdio runner. It creates
only /var/lib/vprouter-v2-lab/owner-journal-<nonce>, root0700 records, exact allocation
and real durable namespace pins; all artifacts retained. Five cases expected:
1 actual fork copied Journal persist/revalidate/new-exit refusal before write;
2 actual gated guard->owner RPC + three independent allocation/journal read jobs;
3 stopped writer actual root/caps0/NNP/seccomp/null+ACK+dir+lease+temp FD inspection;
4 writer stopped AFTER temp write BEFORE fsync while separate read job succeeds;
5 original BOOTTIME2s elapsed, no SIGCONT, retained lease Busy after parent tx drop,
  exact writer SIGKILL/reap, only then lock reacquire; old journal unchanged and
  interrupted temp retained. Expected ~<20s x86, outer45s. NOT provider/client or
full neighbor fault-isolation proof. Native NOT_RUN pending final frozen build.

### Journal review/native81 correction checkpoint 8555280

Exact 3f9f native81 FAILED AllocationMismatch after only the actual copied-Journal
creator-PID refusal case passed. No scope policy event was emitted. Root retained
journal/pins and archived nonce only after owner+guard unit/cgroup absence proof.
Host-visible nsfs pins survived owner exit and matched the Offline journal: data
(host fixture) dev4/ino4026531840, distinct transport dev4/ino4026542454; this is
persistent-pin component evidence, not operational or terminal-recovery proof.
Source cause: health_configuration unconditionally declared Mullvad whereas this
native owner journal fixture's allocation is Direct. Production JournalServer
binding-mode rejection was correct and remains unchanged. Fixture now declares
its explicit allocation mode and matching client policy. Meaningful RED:
owner-journal-fixture-red.log, AllocationConflict. Final positive checks cover
valid complete Direct and Mullvad allocations (including mode-specific WG link).
An intermediate test changed only mode without recomputing complete allocation;
its legitimate rejection remains in owner-journal-review-fixes-launch.log.

Independent 3f9f review found exactly two Important/no Critical:
1. Pending readonly jobs evaluated predicates on committed RAM but could accept
   a changed selected entry in the pending disk candidate. RED captured in
   owner-journal-pending-read-red.log. Before evaluating any readonly predicate,
   both snapshots must now have exact schema/allocation/primary/base bindings and
   one existing, byte-equivalent selected entry. Changed selected terminal state,
   missing/duplicate entry, or changed shared binding is refused. A real second
   allocation member with unchanged entry may still read either atomic snapshot.
2. The test-only writer pause used raise(SIGSTOP) after confinement, requiring
   forbidden signal syscalls. Replaced with fixed FD3 SEQPACKET checkpoint byte127
   and permitted blocking read; parent receives checkpoint and SIGSTOPs the exact
   retained pidfd, then verifies actual T state/start identity. Parent never sends
   a resume byte or SIGCONT. No production syscall filter allowance was added.
   Actual native paused writer verification remains required; no ordinary test
   claim substitutes for it.

Covering commands/results on frozen 85552801523ae64432bd436ce38b4e823bf0cde7:
- cargo test --locked --workspace: 260 PASS,0 failed,2 ignored;
  target/owner-journal-review-fixes-workspace.log.
- cargo clippy --locked --workspace --all-targets -- -D warnings: PASS;
  target/owner-journal-review-fixes-clippy.log.
- cargo fmt --all -- --check: PASS; target/owner-journal-review-fixes-fmt.log.
- python3 target/implementation-20261026-build.py: both static targets PASS,
  BOTH init-manifest hash stability assertions retained/PASS;
  target/owner-journal-review-fixes-static-build.log.
- Exact source/payload/context bindings:
  target/continuation-20261026T192417Z/candidate.json.
Native corrected journal probe NOT_RUN pending root; same fixed owner unit/mode,
nonce policy and five expected cases apply. No public launch or all-nine DONE.
Source paused for independent scoped review and native correction verification.

### Native82 retained failure and diagnostic-only checkpoint 77f7fc3

Independent 8555280 scoped rereview PASS: both Important findings addressed, no
additional finding. Native82 FAILED DescriptorPolicy after copied-fork refusal;
actual guard scope policy readback now present, so allocation helper correction
reached real placement. The three-RPC case did not emit and remains NOT_RUN.
Root retained failed nonce until owner+guard units/cgroups were proven gone;
failed-actor-metadata.json is beside candidate192417Z/native controller evidence.
No old role/probe PASS is transferred to this source.

77f7fc36dadfb16990a51c6e9e20a53097a37af2 is diagnostic-only (cfg(test), apart from
an equivalent named allocation read buffer). No filter or authority change.
Fixed logs show request sequence/kind, owner terminal reason, completed job count,
spawn inventory stage. Failed confined child sends only stage/error bytes on
existing private ACK3; stderr stays null and no path/record/key bytes are emitted.
Setup stages1–7; allocation open21/metadata31/read41/parse22; journal open23/
metadata33/read43/compare24; temp/fsync/rename/dir-fsync/final deadline25–29.
Child error byte uses existing kernel stage_byte mapping, fallback206.
This also distinguishes a possible harness EOF-before-pidfd-exit terminal-reason
race from an actual read/filter/registry failure; no such cause is yet claimed.

260 ordinary PASS/0failed/2ignored, strict clippy/fmt and both static builds +
BOTH init hash assertions PASS. Logs target/owner-journal-native82-diagnostic-
{workspace,clippy2,fmt,static-build}.log. Frozen bindings:
target/continuation-20261026T193343Z/candidate.json. Corrected native83 pending root.
All-nine runtime/multi/client/migration/platform/performance/soak scope unchanged.

### Native83 diagnosis and narrow EOF oracle correction a666b38

77f7 native83 FAILED only final fixture category assertion: observed sequence1
progress, sequences2/3/4 journal jobs, all3 completed, then DescriptorPolicy from
socket EOF arriving before pidfd exit readiness. No IO/filter error diagnostic.
The failed run is retained under candidate193343Z/debian-x86_64-owner-journal-
diagnostic/controller.json. This proves the earlier generic reason was not enough
to diagnose a child-filter defect. No filter/protocol predicate was changed.

Native fixture now first requires no pending job/drain and actual retained pidfd
waitpid EXITED(0), then permits either ChildFailed or DescriptorPolicy terminal
category only with exactly3 completed jobs. Nonzero/stopped child is never accepted.
Meaningful real SEQPACKET RED in owner-journal-native83-eof-red.log: three fully
acknowledged requests followed by peer EOF reproduce DescriptorPolicy and failed
the old fixture category. GREEN also rejects fewer completed jobs and Deadline.
Existing native exit-proof path is mandatory and independent of this category.

Frozen a666b3854af67bdc8021800ebf5984ec5d417f9c at
 target/continuation-20261026T193854Z/candidate.json.
261 ordinary PASS/0failed/2ignored; strict clippy/fmt; static x86/ARM and both
init-manifest stability assertions PASS. Logs target/owner-journal-native83-eof-
{workspace,clippy,fmt,static-build}.log. Corrected native84 pending root. All-nine
scope and public-start refusal remain unchanged. Source paused for native gate.

### Native84 passed bounded journal components; positive durability coverage46e87aa

Exact a666 native84 PASS_PARTIAL_ACTUAL_PROGRAMS in3.711s: copied creator-PID
refusal, actual gated guard3fresh IO read RPCs, exact stopped writer confinement,
independent read beside stop, original2s expiry/no resume/leaseBusy until actual
SIGKILL/reap/temp retained. Native terminal metadata retains DescriptorPolicy
EOF category and completed3; exact waitpid EXITED(0) passed before proceeding.
These establish the stated components only. No real healthy neighboring guard,
JournalRPC legal mutation, HostAuthority IPC or operational start proof yet.

Root identified coverage gap: a stop before fsync cannot verify successful
fsync/rename/ACK. Added one native positive BEFORE the stopped writer: fixed child
atomically replaces the journal with the identical canonical record, file sync,
rename and directory sync complete within original BOOTTIME2s, child ACK128 and
EXITED(0) observed. Parent verifies root0600 exact bytes, same device/changed
inode, no pending temp, final original deadline. This is an actual durable IO
positive, not legal post-bootstrap JournalRPC mutation or terminal retirement.
Six expected native cases now; new case is
actual_confined_journal_write_fsync_atomic_rename_directory_fsync_ack_exit0_exact_readback.

Frozen46e87aaf2e0cc2b9f77092d32e311a2596064a59:
target/continuation-20261026T194326Z/candidate.json. 261ordinary PASS/0failed/2ignored,
strict clippy/fmt, bothstatic+BOTH initstability PASS. Logs target/owner-journal-
positive-{workspace,clippy,fmt,static-build}.log. New native positive NOT_RUN pending
root. Source paused for this small native coverage checkpoint; remaining work is
still the full owner runtime and all-nine sequence, not a completed replacement.

### Actual85 positive completion and current deployment-loop work

Root confirms exact46e87 native85 all6 PASS, independent855..46e rereview PASS.
Positive write finished199505.642083836 before original199507.629569893 (~1.987s
remaining), inode140710→140709 sameFS, exact ACK/bytes/root0600/temp absence.
Paused writer66511/start19950564 original199507.642097727; separate read and
sole retained lease until actual SIGKILL verified. This is concrete confined
IO proof; full legal JournalRPC transition/runtime remains open.

Production ExternalOwner now has a single bounded service_once, pending frame and
retained terminal state. DeploymentOwner validates one declared allocation with
unique exit/lifecycle slots, polls every live member once, fences only failed
member's IO/guard, and treats process-stop as deployment-wide. It keeps all handles
and records fencing errors; no terminal status grants retirement. Idle loops use
bounded5ms polls, rechecking unchanged absolute BOOTTIME deadlines on every wake.
No background worker threads or new unsafe boundary were added. Dynamic admission
is NOT implemented by synchronously calling placement from this loop.

Domains.owner_unit now uses a domain-separated digest of validated deployment_id,
not full allocation hash. RED generation-transition test proved old key changed
and would require owner restart/SIGSTOP of healthy guards. Guard scopes and all
RPCs retain full allocation digest/generation/lifecycle. Full Journal equality
stays strict: durable authorized coexistence/reconfiguration is still required
before changing a running allocation. A stable unit name alone does NOT authorize
adoption or claim hot-add. Existing fixed owner fixture now describes
vprouter-v2-owner@9bc1c45b9af87c0af159ba1e394cfa3dc1f568853c7cf9a19bfa205778201b13.service.
The public --owner-domains-descriptor remains the controller authority.

Controller MUST NOT derive child scope names from this stable owner key.
Cfg(test) LAB_GUARD_SCOPE_INTENT is emitted before every Domains.place PID1 call
and gate release: exact unit, lifecycle, exit_id, role, allocation_digest, pid,
start_time. It covers guard and all expiry roles. Archive only after all exact
source-bound intent units/cgroups and owner are dead; B uses another lifecycle.
No credentials or entire manager property maps are logged.

New ignored native --ignored-owner-deployment creates a real2-member allocation,
four persistent namespace pins, two actual sibling guards and shared Journal.
A's first read actor blocks at private checkpoint and is parent-pidfd-stopped;
original2s must fence only A and actually stop A's guard. B must complete at least
5 additional fresh journal RPCs AFTER A terminal, exit0, and both exact guards/IO
actors must drain. Records must remain byte-identical. All fixed fixture paths
under /var/lib/vprouter-v2-lab/owner-deployment-<nonce>, same protected nonce/admit
contract. One emitted case, expected4–6s, outer45s. This is control-plane isolation,
NOT routed healthy-neighbor/provider/client acceptance. Fixture missing B policy
caught by ordinary RED before VM, fixed complete declaration; both bindings now
validated by ordinary test. Intermediate1504b276/candidate195856Z is superseded,
NOT_RUN native; final intent+fixture build pending.

### Remaining host/multi transition constraint (must not be lost)

Copied HostAuthority is still not a cross-process canonical authority. Proposed
concrete next boundary: guard native observation through an opaque bound client,
owner-held canonical model comparison over authenticated bounded IPC; no arbitrary
caller callback or supplied expected Snapshot authorizes acceptance. Owner must
not block its other slots on native audit/Docker/durable IO. Current executor
Scope::verify reads exact proc/cgroup identities; it does not itself call D-Bus
(an earlier planning message incorrectly suggested that).

Central IPC alone does not solve legitimate add/remove races: activation mutates
host before HostModel.add. A concurrent A audit could reject in-progress B if B
stalls. Removal can retain exact before/after declared shapes only behind proven
A Offline. Addition needs exact predeclared staged ownership/indices or equivalent
bounded generation-bound transition proof BEFORE mutation, not learning or
ignoring arbitrary new aliases. Initial all-member activation before guards avoids
startup interference only; it does NOT satisfy hot-add/restart isolation. Startup
placement also cannot block existing members'2s RPCs/90s watchdog. These explicit
transition requirements remain in all-nine operational scope.

### Frozen deployment-loop checkpoint4ce0755

Final source4ce0755c953f810205bf2da154a71019f14d872d, frozen bindings
 target/continuation-20261026T200354Z/candidate.json.
- cargo test --locked --workspace:263 PASS,0failed,2ignored;
  target/owner-deployment-final-workspace.log.
- cargo clippy --locked --workspace --all-targets -- -D warnings:PASS;
  target/owner-deployment-final-clippy.log.
- cargo fmt --all -- --check:PASS; target/owner-deployment-final-fmt.log.
- python3 target/implementation-20261026-build.py: static x86+ARM and BOTH
  init-manifest hash stability assertions PASS; target/owner-deployment-final-static-build.log.
- RED owner key change: target/owner-deployment-identity-red.log.
- RED missing second fixture client declaration: target/owner-deployment-fixture-red.log.
Initial borrow-check compile failures retained in owner-deployment-loop-check.log;
intermediate build1504 is superseded and has no native PASS claim.

Native two-guard loop and stable owner name are NOT_RUN pending root, as is scoped
review of46e87..4ce0755. First x86 then ARM original2s path needed; no deadline
increase. Existing journal/90s/native-role results belong to their stated earlier
sources. Source paused for native+review. Public launch remains refused; all-nine
scope remains active and incomplete.

### Native87 two-guard loop and read/write-generation gap

Root exact4ce0755 native87 x86 PASS: A originaldeadline200768.759641218,
terminal200768.76769063 (+8.05ms); Aguard66974/start20076666,
Bguard66975/start20076670. B completed37 fresh read RPCs before A terminal and75
total (38 afterward), exact scoped stop/drain assertions PASS. Explicit
routed_neighbor_acceptance=false. ARM88 same-source original2s pending root;
independent deployment-loop review pending. Functional source remains paused.

Read-only self-review found a separate required journal write-concurrency fix:
readonly child captures its whole before/alternate candidates at start. Another
member may commit a new whole record while that read is in flight, causing the
child to reject unchanged-selected-entry reads. The current two-read native probe
does not cover this. At completion, selected-entry predicate stability must also
be rechecked if another service could have changed it after start. Unique live
exit slots currently limit that same-member scenario, but it must not become an
implicit assumption during future admission/reconfiguration.
Before legal concurrent write integration, either reserve read generations so
writer admission cannot invalidate in-flight reads (without blocking unrelated
reads/watchdogs), or return exact observed-record digest from the fixed child and
validate against bounded retained canonical generations plus unchanged selected
entry. No unbounded history or arbitrary caller snapshot may confer authority.
This remains implementation work;87 is not concurrent read/write preservation.

## FINAL HANDOFF — NEEDS_CONTEXT at4ce0755 (NOT overall DONE)

Source is paused. Fresh sole implementation writer must FIRST fix the two
journal-concurrency issues below, test/freeze them, and obtain root native/scoped
verification BEFORE HostAuthority or other functional features. The user already
authorized the full plan; do not ask permission to continue. No nested agents.
Root alone performs privileged/credential-bearing LOCAL actions and review.

### Exact current state

- Workspace /DATA/AppData/vprouter-rust-v2, branch rust/v2.
- Real HEAD still c6a138c00b70163ba3cbfdf350e5cf8e2f3a3c6a. Never mutate real index/
  HEAD/reset/clean; preserve all uncommitted and untracked implementation files.
- Frozen source4ce0755c953f810205bf2da154a71019f14d872d:
  target/continuation-20261026T200354Z/candidate.json.
- Both exact contexts copied candidate-local by root and strict4role/sourcechecked.
  Mutable target/gateway-context may be refreshed after notifying root.
- Fresh direct archive-to-files comparison:115 source inputs,0 mismatches.
  Git diff against candidate misleadingly lists untracked new files as deleted
  because real index intentionally was never updated; do NOT delete/recreate them.
- 263ordinary PASS,0failed,2ignored; clippy-Dwarnings/fmt and bothstatic targets,
  BOTH init-manifest stability assertions PASS. Final covering logs above.
- Native87 x86 two-guard control isolation PASS; native88 ARM same-source PASS:
  originaldeadline28775.14600628, Aterminal28775.196922169 (+50.9ms), B32 reads
  after A terminal (64total/32before), actual AguardT/exact cleanup assertions.
  Source-specific directories in candidate200354Z/debian-{x86_64,arm64}-owner-deployment.
  Neither establishes routed/client acceptance or concurrent journal mutations.
- Independent scoped review FINAL: changes requested, one new Important normal
  write-contention defect. Read-generation race independently identified here;
  root explicitly requires fixing both together. Both are UNFIXED.
- Same-source full90 watchdog MUST be rerun AFTER these fixes because owner loop
  changed from spin to bounded poll. Old e47e/native76 does not transfer.
- Public Admission::launch and staging remain refused. No real operational
  provider/enrollment/client proof, terminal reconciliation or all-nine completion.

### FIRST mandatory repair: normal contention must queue, never freeze B

owned.rs JournalServer::start around1129–1155 treats shared.pending.is_some() as
LockBusy for a mutation. owner.rs service_once around273/307 propagates that;
DeploymentOwner::poll_once around404/414 terminates/freezes B. Thus legitimate
A/B overlapping writes that could both finish within original2s incorrectly stop
B. SharedJournal around510 has only pending/fenced, no fair admission queue.

Add authenticated bounded fair per-member admission. Retain the SAME accepted
sequence/sent_at/original2s while waiting; do not reissue Progress, mint fresh
sent_at, reset deadline or ACK before actual durable completion. A guard has one
in-flight request. Dead/terminal/cancelled members must lose queued admission
without rearming. Queued normal contention differs from uncertain/fenced writer:
never grant a new write from fenced/uncertain state or clear pending on mere
child death. Keep actual writer lease until actual death, pending record until
strong explicit readback/reconciliation. Failed A does not freeze/read-starve B.

### SECOND mandatory repair: read generations across a neighbor commit

JournalIo around391 captures whole before/alternate byte vectors; run compares
actual record bytes to those. Another member may start+commit a new canonical
record after a read starts, causing unchanged-member reads to fail. The previous
review fix unchanged_selected_entry around1034 checks selected entry only when
read starts with an already-known pending candidate. It is NOT enough for a
later neighbor commit. Also ensure a selected predicate cannot be ACKed after
that selected entry changes between start and completion (do not rely silently
on current unique live slots during future admission/reconfiguration).

Possible concrete approach for fresh writer to evaluate: fixed readonly child
returns only a bounded exact observed-record digest over private ACK channel;
owner matches it to bounded retained canonical current/pending/previous versions,
with exact whole binding plus selected-entry equivalence to the original request
AND current permitted state. Register a pending candidate before releasing any
writer, so a legitimate atomic rename can be recognized even before parent ACK.
Keep digest/selected-entry facts bounded in count AND bytes, hold versions needed
by in-flight reads, reject unknown/foreign digests, and never adopt arbitrary
received records. History exhaustion needs bounded admission/backpressure using
original frame time, while unchanged read/audit/watchdog service stays available.
This is a design option, not implemented or preapproved code. A read-reservation
alternative must not hold a guard global lock across IO, starve B's reads, or turn
ordinary writer waiting into terminal failure. Do not solve availability by
accepting any shared pending/new record or skipping selected-entry checks.

JournalServer::poll around1301 currently returns bool from fixed child ACK128;
owner ExternalOwner.pending retains Progress only. Review how queued requests,
original immutable request binding, exact observed digest, completion/fence/drain
and canonical history fit these types. All syscall/fork/confinement changes stay
in kernel.rs/kernel_base.rs; no unsafe elsewhere. Child roles remain fixed, no
arbitrary callback/exec/path. Preserve parent single-task/FD inventory and no
persistent Tokio process/signal backend. Native scope verifier uses proc/cgroup
reads, NOT D-Bus; do not remove checks based on prior mistaken planning statement.

Required meaningful regressions:
1. Two real members' overlapping VALID mutations, both durable/ACKed inside their
   own original2s; no B freeze from normal contention. Fairness and queue bounds.
2. A read crossing a legitimate neighbor commit still proves unchanged selected
   entry; selected-entry change/foreign bytes/unknown history must fail.
3. Queued expiry/cancellation/replay/changed original time cannot obtain a grant;
   uncertain/fenced writer never permits another mutation or late-writer reuse.
4. Native gate if possible, then final same-source full90 and scoped rereview.
   Do not invent a production noop-write API solely to make a test pass. Current
   ignored fixture is Offline and cannot legitimately BeginTerminal; constructing
   schema-only Bootstrap records is not native activation proof. Root can stage
   genuine Bootstrap/native prerequisites when a fixed payload is ready.

### Existing native contracts to retain

--owner-domains-descriptor now emits deployment-stable9bc1...service for launchlab.
--ignored-owner-journal verifies6 component cases including real atomic write,
actual scope/3read RPCs, confined stopped writer, independent reader, original2s,
no SIGCONT, retained OFD lease until actual death. --ignored-owner-deployment is
new two-real-guard read/control isolation. --ignored-owner-watchdog is ORIGINAL90.
Root runner uses exact immutable admitted payload, Type=exec, Slice=system.slice,
regular root0600 stdout/stderr, stdin null (no journald/pipe/notify FDs), fresh
64lowerhex owner-domain-nonce and protected artifact/network acceptance files.
Actual native component contexts/source must always match; no old PASS transfer.

LAB_GUARD_SCOPE_INTENT BEFORE placement emits exact unit/lifecycle/exit/role/
allocation/PID/start. Root archival uses all exact intent/readback units across
ALL lifecycles, never derives scope from stable owner hash or blindly scans nonce
substrings (persistent namespace.mount units are not live actor scopes). Failed
nonces and namespace/journal artifacts stay until actual typed actor/cgroup death
proof, then nonce may be archived. Do not remove failed history or pins yourself.

### Functional continuation AFTER these fixes are reviewed

1. Wire actual canonical HostAuthority IPC and staged lifecycle. Separate per-exit
   guards remain mandatory; one shared guard would allow A's expiry SIGSTOP to
   stop B/direct. Copied Rc/RefCell is not shared authority; inherited OFD flock is
   not cross-process serialization. Owner keeps canonical journal/host model;
   guard sends only authenticated bounded selected-member requests/observations.
   Native network audit/Docker/fsync cannot block all owner slots/watchdogs.
2. Solve host model add/remove transitions and allocation coexistence explicitly.
   Stable owner unit avoids parent restart on new generation, but full record
   equality and host mutations-before-HostModel.add still need authorized durable
   transitions. Do not learn new aliases or pretend initial all-at-once startup
   proves hot-add. Dynamic placement/activation must run independently while
   existing slots keep their original2s/90s budgets.
3. Wire protected user-invokable staged launch through actual Docker/native setup,
   exact immutable4roles, config/enrollment/profile loading, persistent host pins,
   producer/daemon placement. Guard converts Transaction via fork_remote and uses
   Executors::spawn_owned to place all3 independent expiry scopes BEFORE any
   Operational grant; integrate owner progress. Current GuardTransport/Handoff
   still uses ordinary expiry spawn and copied local host authority.
4. Drop SYS_ADMIN/full setup capabilities before actual public steady loops.
   Current owner/root lab loops are not confinement proof. Journal child already
   has caps0/NNP/private chroot/filter/fixed FDs; parent still needs setup rights.
5. Implement real terminal owner/guard/service death and bounded stop paths, exact
   all3 writer containment, actual quiescence, drain. Guard alreadyExited vs
   observedT must come from retained pidfd/process evidence, never caller bool;
   existing expiry stop_terminal_guard can report StopFailed for alreadyExited.
   NEVER SIGCONT old guard, and NEVER rearm old lifecycle.
6. Implement durable terminal retirement/reconciliation: all old writers/mutators
   actually dead, exact pinned namespace/policy/lifecycle/generation proof, install
   + verify replacement Offline BEFORE deleting ONLY matching old terminal policy,
   every boundary durable/idempotent, foreign/uncertain stays Offline/retained.
   Reboot identity differs from same-boot PID; no old PID reinterpretation.
7. Add verified runit/cgroupfs adapter (Void remains unsupported), full supported
   platform install/boot/update/rollback/uninstall and owner separation. Root has
   Debian/Arch/ARM systemd and Void/runit owned guests; never touch production.
8. Before real multi, fix LocalAPI fleet budget: actual48peer status60750 near64KiB;
   enrollment64KiB is separate. Choose justified status cap/minimal strategy with
   >64KiB valid-fleet and oversize tests AND JSON materialization/memory accounting.
   json::decode currently materializes full duplicate-key-checked Value first;
   raising byte cap alone omits amplification bounds. Enrolled peers capped256.
9. Continue actual single provider/client gate, then independent5exit+explicit
   direct, protected kernel/userspace clients with IPv4/DNS/IPv6/TCP/UDP captures,
   two LOCAL legacy identity-preserving migrations and transactional rollback,
   hostile/service/reboot matrix, repeated real10min1/5/6 whole-router comparisons,
   TRUE24h mixed soak. All nine original areas remain active. Component/static
   PASS and NOT_RUN labels cannot substitute for requested functionality.

Read owner-runtime-brief.md, constraints.md, docs/rust-v2/IMPLEMENTATION.md and this
report. Build only with existing alternate-index frozen builder; notify root
before context refresh. Root credentials/profile inventory exists and shows5
independent non-production keys; do NOT read credentials. Source is ready for the
next SOLE writer; no other implementation writer is active after this handoff.
