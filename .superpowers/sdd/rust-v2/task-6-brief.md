# Dedicated single-threaded namespace and container launch helper

Preparation brief, to implement only after task5 passes independent review.
Workdir /DATA/AppData/vprouter-rust-v2, rust/v2. No subagents. Read this brief,
docs/rust-v2/IMPLEMENTATION.md and task5's final report/interfaces when assigned.
This is a security boundary for WP3/5, not an active migration or complete guard.
No production changes, no real state/profile reads, no host network mutations.
Root controller alone runs ignored harness in owned isolated guest.

Own a small dedicated Linux-operation crate and launch-helper executable,
minimal additions to native Linux Docker inspection needed for launch admission,
workspace/lock updates, docs/rust-v2/launch-helper.md and task6 report. Audited
unavoidable unsafe syscalls must all reside in ONE narrow reviewed module with
safety contracts; all other modules forbid unsafe. Exact-pinned dependencies,
no shell/CLI subprocesses in production helper. Do not put setns in an async
executor. Main starts single-threaded and verifies exactly one task before any
namespace operation. The helper has no broad public arbitrary-command exec API.

Inputs must come from protected root-owned files or inherited descriptors, not
secrets in argv/environment. Validate entire allocation, generation and exact exit
membership. Validate live Docker-owned container ID, labels, pinned image, running
PID/start-time/pidfd, root filesystem, all namespace identities and cgroup2
membership. Gateway ownership labels use existing native vocabulary: io.vprouter.deployment
exactly the deployment ID and io.vprouter.role=gateway. One container serves
multiple exits; do not require its exit label to equal each worker exit. Resolve
pinned OCI image references to the expected platform content ID through protected
staging evidence/native image inspection, rather than naively comparing a
multiarch manifest digest with Docker Inspect.Image. Validate read-only root,
no privileged/host-network/host-PID/socket mount, and allowed mounts/capabilities.
Name alone never proves ownership. Obtain PID-bound /proc descriptors
without following untrusted paths; recheck process liveness/start-time and refuse
ambiguous PID reuse or container replacement. Existing GET-only CLI commands must
remain observational and guard_runtime:false. Unsupported userns/rootless/remapped
or other environments must fail closed with explicit reason, not pretend support.
Do not expose an activation CLI that bypasses missing guard/quarantine integration.

Support opening owned data/transport namespace handles and creating absent owned
namespaces ONLY under root-owned private deployment records with locks/generation,
exclusive names and persisted inode/dev identity. Pin namespaces with descriptor-
relative safe mounts/handles, not guessed path ownership. Task5 accepts direct
proc-netns FDs: after validating/entering a persisted bind handle in the dedicated
helper, reopen /proc/thread-self/ns/net before constructing NamespaceTarget. A
/run/netns bind handle itself renders a path, not the required net:[inode] form. Existing foreign or
ambiguous handles refused; partial creation retained as quarantined/offline and
reconciled. Primary data may use validated gateway base network namespace to
preserve legacy --network container consumers; extra exits must be independent.
Never bridge data namespaces or create a usable transport path in this task.
No generic namespace cleanup bypass; absence/ownership must be proven first.

Launch sequence must validate everything before entry, then enter only owned
container namespaces/rootfs and selected data netns. Use private mount/state view,
join verified container cgroup (or owned child cgroup), verify accounting and PID
placement, close host/namespace descriptors, drop capabilities/bounding set and
execute only a fixed verified Rust worker image path via stable executable FD.
Worker image hash/provenance must be part of protected launch spec. Unknown worker
binaries refused; an arbitrary root-owned executable is not enough. If the actual
worker is not implemented, provide a test-only static probe payload and keep
production launch unavailable until valid manifest integration exists.

State isolation requires more than separate mounts: same-UID processes sharing
/proc can inspect another process root/state through /proc/PID/root. Use private
per-exit PID+mount namespaces and a proc mount for that PID namespace (or prove an
equally strong concrete mechanism). A dedicated child PID1 supervisor must reap
and forward signals correctly. Worker+tailscaled see only their selected state,
not peer state or host /run/netns; no other exit namespace descriptors inherited.
Preserve base NETWORK namespace for the primary even if PID/mount views are private.
No inherited host root directory descriptors, Docker socket, old-root mount,
namespace FDs or unneeded sockets. Required config/health descriptors must use an
explicit small allowlist and close-on-exec policy; validate the final FD inventory.
No raw host/environment/secret dumps in errors or probes.

Drop persistent SYS_ADMIN and all unrelated caps before worker execution; no
privileged Docker, host networking or Docker socket inside container. Set and
verify no_new_privs, effective/permitted/inheritable/ambient/bounding caps and
intended UID/GID. Choose retained NET_ADMIN/NET_RAW only if justified by upcoming
worker/Tailscale requirements. Ensure exec cannot regain dropped capabilities.
Never rely on Rust's type system as proof namespace/firewall semantics are safe.
Kill/reap failed launch children; host guard must quarantine independently before
cleanup. Signal-forwarding/reaping must be bounded, including frozen workers.
After failed placement/capability/FD/state verification, execute nothing.

Normal tests must not setns/unshare/mount/mutate host. Meaningful tests for strict
launch-spec parsing/redaction, process identity/cgroup/path/manifest mismatch,
closed-FD policy and lifecycle decisions. Build static x86_64 probe for Alpine
Tailscale image if needed (pinned1.97.0 musl targets are installed; Rust self-
contained linker avoids external C toolchain). Provide ignored isolated harness
with root-owned lab marker and self-vs-PID1 network namespace admission. It must
use only NEW disposable test containers/namespaces/cgroups and synthetic state,
fixed test-only Docker/ip commands allowed. Root runs it. Positive checks actual
/proc placement/cgroup accounting/caps/FD inventory/signal/reaping and two-exit
state isolation including adversarial /proc/PID/root attempts. Foreign container,
changed PID/starttime/namespace/cgroup, bad manifests and malformed descriptors
must fail. Verify container death cleans/reaps children while quarantine remains
later integration; any missing kernel check is explicit NOT_RUN.

Run covering fmt/test/clippy and commit explicit files; force-add report binding
exact code hashes, commands/results, unsafe/subprocess inventory and unperformed
runtime gates. No production deployment/release readiness claims. Escalate real
technical gaps early; avoid partial unsafe APIs whose invariants are caller bools.
