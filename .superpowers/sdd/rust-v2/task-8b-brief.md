# Real worker/daemon placement and kernel authority

PREPARATION ONLY. Dispatch only after task8a independent approval. Part of
task8, not completion of single-exit guard parity. Workdir
/DATA/AppData/vprouter-rust-v2, rust/v2. No subagents. Read this first as your
requirements, then binding docs/rust-v2/IMPLEMENTATION.md and task-8-brief.md.
Root alone runs privileged tests in the owned local guest. No remote testing,
production state/profile access, identity cloning or enrollment in this task.

Join the reviewed launch/execution and guarded transport with actual Rust worker
and pinned Tailscale1.102.5 executables. Preserve the separate host-guard and
namespace-worker failure boundaries, base namespace compatibility, independent
private PID/proc/mount/state views, resource accounting, bounded signal/reap
behavior and verified descriptor closure from6b. No synthetic feature, caller
boolean, ACK or arbitrary supplied binary may mint production authority. Retain
production CLI refusal until full8c and release staging gates are proved.

Supply fixed reviewed per-program manifests and an immutable minimal gateway
image from pinned OCI base(s). Exact checksummed worker/daemon/init bytes,
architecture, launch policy and image content must be bound together. No Python,
shell supervisor, Docker socket, host networking, privileged container or
persistent CAP_SYS_ADMIN. A general multithreaded executor never enters namespaces.
Keep unavoidable unsafe Linux operations in the sole reviewed kernel module.
Review the actual Rust/Go syscall, LSM, UID/GID, capability, TUN, descriptor,
resolver, config and mount needs. Retain only demonstrated capabilities, verify
their reduction before execution, and refuse unsupported confinement instead of
silently disabling it. Probe-only seccomp/AppArmor evidence cannot certify Go.

Place actual worker and tailscaled in8a's exact owned health/control cgroup
subgroup before any client/socket creation. Bind admission, allocation generation,
container parent, namespace and producer group through retained authority.
Preserve parent Docker accounting; do not enable controllers or restructure its
parent. Unrelated same-network-namespace producers remain outside that authority.
Worker/daemon state must be inaccessible to other exits; no host namespace or
control descriptors survive execution. Public credentials never cross argv,
environment, build context, diagnostics or logs.

Implement the narrow authenticated placement/config handoff needed for the
actual worker to construct its namespace-local native clients. It must validate
descriptor type/provenance, peer/process identity, exit/generation/namespace and
immutable program binding before clients. Config uses only protected descriptors
or files. Approved DNS comes from validated8a resolver authority, with no host
resolver or generic WAN DNS exception. Do not read a secret WG profile in a
worker merely to duplicate host configuration; pass only the minimum required
verified monitoring configuration. HTTPS clients stay local to their exit.

Actual Tailscale kernel interfaces/routes/rules must be observed and admitted by
explicit structural authority. Use the recorded kernel-rule oracle as orientation
and collect a fresh actual-daemon witness. Do not accept arbitrary table52, mark,
route, interface or IPv6 metadata simply because Tailscale commonly creates it.
Validate exact namespace, owned WG peer/key/endpoint and preserved daemon identity;
unexpected routes/interfaces/rules quarantine. IPv6 forwarding remains blocked.
Reject or suppress unwanted IPv6 metadata without broadening application permits.
Approval requires offered AND approved identity; a withdrawn node is normally not
ExitNodeOption. Preserve the worker's45s expiry,180s handshake,5s cadence, one
eligible retry after1s with fresh structural checks, exact provider server and
three fresh successes. Heartbeat receipt cannot refresh provider verification age.

Deliver actual bootstrap placement tests, not activation-ready authority. Real
fresh daemon state may remain unenrolled for this task's structural/placement
oracles. Reuse the previously approved lab gateway only in a later explicit
stopped-state identity-transfer test; never concurrently open its identity or
silently borrow its enrollment-only container/netns for synthetic tests.
Root coordinates any later approved-identity phase separately.

Focused tests cover rejected manifests/program substitution, descriptor/config
provenance, capability/cgroup/namespace/state isolation, socket construction only
after admission, actual Go startup/netfilter preference/route observation,
unexpected metadata, same-namespace unauthorized traffic, signals/reaping and
container death. Run exact-hash ignored payloads only when root requests; retain
failed attempts and explicit ownership cleanup/quarantine evidence. Synthetic
packets are not real protected Tailscale-client acceptance.

Focused fmt/tests/clippy, x86_64 static artifacts and ARM64 checks/builds; exact
source/artifact hashes, commands/results, unsafe/capability/subprocess inventory,
unperformed platform/runtime checks and self-review in
.superpowers/sdd/rust-v2/task-8b-report.md. Commit explicit owned files. Root
obtains independent spec+quality review before8c. Autonomous guard/protocol/
watchdog/lifecycle, actual provider/approved-client traffic and full single-exit
fault acceptance still belong to8c; multi-exit/direct/migration gates stay closed.
