# Autonomous single-exit guard, protocol and lifecycle

PREPARATION ONLY. Dispatch after independently approved task8a and task8b.
Workdir /DATA/AppData/vprouter-rust-v2, rust/v2. No subagents. Read this first
as requirements, then binding docs/rust-v2/IMPLEMENTATION.md, task-8-brief.md
and reviewed 8a/8b reports/interfaces. Root alone executes privileged local-VM
or credential-bearing tests. No remote tests, production changes, identity cloning
or new enrollment. Keep production invocation unavailable until release staging.

Complete task8's actual independent Rust host guard, joining retained native
transport/ownership authority, real fixed launch manifests, container init and
native worker. This must run and enforce autonomously rather than provide another
caller-driven preparation API. One gateway/one primary Mullvad exit; no placeholder
extra exit processes, namespaces, timers or state. Preserve primary base network
namespace and container/service compatibility. All unsafe Linux operations remain
in the sole reviewed kernel module; no async setns or steady-state shell/CLI.

Guard retains allocation/generation/deployment locks, exact process/cgroup/netns/
producer identity, protected profile and pinned endpoint/server authority, native
policy/netlink descriptors and durable intent. Independently reconcile after an
interruption before activation. Full quarantine precedes transport; real bootstrap
permits only authorized health/control producer, blocks local consumer OUTPUT and
Tailscale application forwarding. Both main permit and quarantine filters must
independently preserve bootstrap restrictions; missing/drifted policy cannot leave
broad application OUTPUT exposed. Native Docker cooperation remains narrowly owned
and verified. Ambiguous ownership/cleanup retains independent quarantine and stops;
never prefix-delete foreign resources or restart unrelated Docker/services.

Implement a bounded protected cross-process protocol with exact inherited/socket
provenance, SO_PEERCRED/process/cgroup/namespace/program identity, exit/generation,
monotonic sequence/replay protection and fresh observations. Worker ACK recording
is not enforcement authority. Guard responses identify actually enforced offline,
bootstrap or ready policy. No caller boolean, lab feature or synthetic constructor
may mint readiness. A received heartbeat cannot refresh provider verification age.
Guard independently enforces heartbeat and complete verification expiry below45s
and the90s host watchdog even when worker/provider/Docker/fsync operations stall.
Bounded request cancellation and shutdown must not wait forever for blocking IO.

Native worker checks every5s, handshake<180s, exact expected provider server, bounded
HTTPS/certificate/body/deadline, one eligible retry after1s with fresh interface/
route/handshake checks; permanent/negative/malformed/structural failures quarantine.
Three fresh complete successes permit guarded advertisement, then a fresh same
identity with actual offered AND approved status is required before READY. A
withdrawn node's ExitNodeOptionfalse is normal during recovery. Failure order is
independent quarantine FIRST, advertisement withdrawal/child stop afterwards.
Actual readonly status/probe must report verification age and reason codes without
releasing policy or changing lifecycle; DNS/IPv6 are independently tested or
explicitly not_tested. Ready/advertised status is not real-client egress proof.

Implement owned start/recovery/stop/container-death/watchdog paths and bounded
signal/reap semantics. Actual process freeze/crash/OOM, malformed/delayed health,
Docker unavailable, stale evidence with responsive worker, route/interface/peer/
policy/producer drift must withdraw safe authority. Include an actual preexisting
startup resource-name collision and real process SIGKILL at durable activation/
cleanup boundaries; 8a deterministic checkpoints and WG-to-foreign-dummy
replacement do not independently prove these integrated startup cases. Actual
Tailscale forwarding must include spoofed-source packets, not only policy units.
Full cleanup only after exact
current ownership verification; stopped state/intent survives interruption. Keep
provider controls and enforcement independent; no one slow query may starve guard
expiry or emergency quarantine. Socket pools remain inside their owning namespace.

Root first runs fixed exact-source/artifact local synthetic kernel/protocol/fault
payloads, then coordinates an explicit stopped-state move of the existing approved
lab gateway identity for actual Mullvad/client validation. Never open that identity
concurrently or reuse enrollment-only namespace for synthetic tests. Preserve its
node ID/IP/state and the approved disposable client; use supplied distinct-device
profile only through protected root files outside repo/build context. No secrets in
argv, environment dumps, output or journals. User has authorized local testing and
interactive enrollment; do not reenroll approved identities. If actual protected
traffic checks require client-side guards, retain that gate as unavailable until
client task; synthetic tests cannot replace mandatory real-client acceptance.

Focused offline tests must cover protocol spoof/replay/generation mismatch, stale
verification despite heartbeats, guard-first failure ordering, three-success
recovery, API timeout/cancellation, bounded shutdown and interrupted ownership.
Owned-guest tests exercise actual guard/worker/tailscaled/container failures,
quarantine stages, native network/policy drift, failed atomic updates and foreign
collision. Continuous IPv4/DNS/IPv6/TCP/UDP markers with independent positive
capture controls at operational data/transport/WAN observation points; retain every
failed attempt and exact source/artifact/capture evidence. Full single-exit parity
requires real disposable Tailscale client traffic; clearly report unperformed
cases. Do not enable multiple/direct/migration runtime before fulltask8 approval.

Focused fmt/tests/clippy, static x86_64 and ARM64 checks/builds, exact pinned image/
program inventory, source/artifact hashes, commands/results, unsafe/capability/
subprocess inventory, self-review and explicit owned-file commits. Report to
.superpowers/sdd/rust-v2/task-8c-report.md; reconcile parent task-8-report.md with
8a/8b evidence and explicit remaining release/platform/performance/client gates.
Root obtains fresh independent spec+quality review before task9.
