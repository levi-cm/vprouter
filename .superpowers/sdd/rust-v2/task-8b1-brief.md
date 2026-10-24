# Fixed program binding, producer release gate and observation handoff

Task8b1 is the first bounded part of task8b, dispatched from150dc7a to
/root/real_worker_placement. Workdir /DATA/AppData/vprouter-rust-v2, rust/v2.
Read parent task-8b-brief.md and binding docs/rust-v2/IMPLEMENTATION.md. No
subagents. Root alone runs privileged tests in the owned local VM. All testing
is local; no production changes, secret profile/state reads or identity enrollment.

This brief records the split already ruled in progress.md. It does not complete
task8b, single-exit parity or a release gate. Actual fixed Go/Rust execution,
private root/mount/state/capability/LSM/seccomp confinement, final immutable image,
fresh actual-daemon kernel metadata and live observer handoff are task8b2.
Autonomous guard/protocol/watchdog, readiness and real-client traffic are task8c.

Deliver fixed per-platform manifests binding the observation-only Rust worker
and pinned Tailscale1.102.5 program bytes, architecture and explicit role policy.
Use docs/rust-v2/pinned-program-inventory.json for public upstream bytes. Reject
substitution, unsupported roles, paths, arguments, manifests and malformed or
duplicate entries. Caller-supplied values and lab features cannot mint production
placement, monitoring-engine, advertisement or readiness authority. Go execution
must remain unavailable until its actual confinement is implemented and verified.

Extend the retained8a producer authority with an unreleased child placement gate.
Bind exact container parent, allocation/generation, namespaces and producer group;
join and freshly verify the child before release to exec. Refuse mismatches and
dead/replaced children. Preserve parent Docker accounting without enabling parent
controllers or changing its limits. Continue6b exact descriptor closure, private
process/state views and bounded shutdown; all unsafe Linux operations stay in the
sole reviewed kernel module. No multithreaded namespace entry or steady-state CLI.

Implement a protected one-use host/worker observation handoff. Host retains
allocation, namespace, process and producer authority; authenticate the current
peer with kernel credentials and exact process/starttime/executable/namespace/
cgroup identity rather than trusting message claims. Bind configuration digest,
exit/generation, manifest and a fresh nonce; reject replay and changed authority.
Before constructing native clients, worker validates its protected immutable
configuration, own fixed executable, namespace, UID/capability/NNP and local
cgroup view. The host independently verifies the actual host producer membership;
namespace-visible cgroup text is only an additional predicate. No host namespace
or control descriptors survive exec. Configuration has only required nonsecret
monitoring metadata and approved profile-derived resolver authority; no WG private
key or host resolver/environment fallback. Requests/responses are bounded and
observation-only. A successful reply cannot release quarantine or forwarding.

The8b1 ignored kernel payload may exercise the producer gate using the existing6b
fixed probe and exact8a producer authority, without enabling transport or starting
an actual daemon/observer. Prove blocked-before-release, child membership before
exec, killed gated child nonexecution, mismatch refusal, inherited confinement,
bounded lifecycle, container-death handling and exact cleanup. Label this probe
evidence precisely. Actual worker configuration mounting and live credential/
executable authentication remain unverified8b2 tests if not actually executed.
Do not infer an observer/Go runtime result from unit tests or the6b probe.

Focused tests cover malformed program/config/protocol data, substitution and
replay/refusal boundaries. Run fmt, focused/workspace checks, clippy, x86_64 static
and ARM64 builds. Give root the exact frozen source archive, artifact hashes,
fixed ignored-payload command, prerequisite hashes, marker checks and cleanup
expectations before privileged testing. Retain unsuccessful attempts. Report
commands/results, source bindings, unsafe/capability/subprocess inventory,
self-review and explicit runtime/platform gaps in task-8b1-report.md. Commit
explicit owned files; preserve controller evidence and other edits. Carry the
two task8a Minor documentation corrections from task-8b-brief.md. Independent
spec and quality review is required before dispatching8b2.
