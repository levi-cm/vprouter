# Owned namespaces and isolated launch execution boundary

PREPARATION ONLY; dispatch after task6 independent review gate. Workdir
/DATA/AppData/vprouter-rust-v2, rust/v2, no subagents. Read this first, then
.superpowers/sdd/rust-v2/task-6-launch-full-requirements.md (complete requirements)
and approved task6 report/interfaces. Binding docs/rust-v2/IMPLEMENTATION.md.
Own privileged helper/namespace ownership and minimal Rust init; no production
changes, real secret/state/profile reads or arbitrary command execution. Root
controller alone runs ignored harness in owned isolated guest. No usable network
path/address/default/link activation in this task; guard integration is later.

Build on non-clonable private Admission evidence from vprouter-launch, not a second
container inspector. Revalidate immediately before placement and after placement.
Preserve native Docker GET-only compatibility CLI. Production manifest loading
must not accept synthetic probes; actual worker/tailscaled manifest integration
may remain unavailable until worker/image exists, but no production flag can
bypass it. Test-built probe exercises the same execution code after its test-only
staging loader. Hash/provenance fixed program identity, never arbitrary root-owned
binary or argv. Clear inherited environment; exact small safe environment/argument
arrays, no proxy/env/secret inheritance. Public CLI activation remains unavailable
until guard/quarantine integration exists.

All unavoidable unsafe Linux syscalls in ONE narrow reviewed module, with safety
contracts and no fallback subprocesses; every other module forbids unsafe. Use
maintained safe syscall interfaces where suitable. Dedicated single-threaded
helper only; do not setns/unshare/fork from an async/multithreaded runtime. Runtime
and all host sockets must be dropped before namespace entry. Verify exactly one
OS task and identity at every boundary where required.

Namespace ownership: root-owned private per-deployment records, allocation lock,
generation and exact exit membership, persisted dev/inode and interrupted states,
atomic replacement+fsync. Pin namespace mounts descriptor-relatively. Exclusive
creation only, refuse foreign/ambiguous names/handles; retained failed creation
remains offline. Primary data namespace may be admitted gateway base NETWORK ns;
extra data and all transport namespaces independent. No bridges/data veths in
Mullvad data. No usable link/path created here. Return direct proc-netns FDs only
after validating and entering owned persisted handles in the dedicated helper;
raw /run/netns bind FD text is insufficient for native network NamespaceTarget.
No generic cleanup API; prove resources unused/absent/owned before unpin. Retain
quarantine/ownership on ambiguous failure, never broadly delete names by prefix.

Place child in actual verified container cgroup or owned child cgroup; verify from
host proc/cgroup2 views and ensure Docker kill removes/reaps all launch children.
Join admitted namespaces/root then create private per-exit PID+mount views and
procfs for that PID namespace. Preserve primary gateway base network despite
private PID/mount. Root read-only; writable state mapping includes only selected
exit, never peer state or host /run/netns. No old-root mount or host root directory
FD remains. Separate mount views alone fail same-UID /proc/PID/root isolation;
actual private PID/proc boundary is mandatory unless an equally strong mechanism
is demonstrated. Worker cannot access host Docker socket, namespace handles,
peer mount roots/state or unrelated daemons.

Minimal Rust PID1 forwards signals and reaps descendants. Children are fixed
verified worker/daemon roles; if absent use test-only static probe. Bounded
termination including frozen descendants, kill/reap on failed placement or parent
loss; avoid PID reuse by pinned children/process groups in private PID namespace.
Keep separate independent host guard failure boundary; no successful status query
is an enforcement action. Host quarantine remains later external integration.

Before exec close all host/root/namespace/cgroup/old-root/socket descriptors and
validate final FD inventory against explicit small config/health allowlist. Reject
bad/inherited directories, namespace/socket FDs or ambiguous CLOEXEC policy.
Executable FD may be CLOEXEC and consumed by fixed fd-based exec. Fail closed via
bounded child exit, never unwind into code that assumes closed FDs remain owned.
Apply and verify no_new_privs, UID/GID, supplementary groups, capability effective/
permitted/inheritable/ambient/bounding masks and securebits as required. Drop
SYS_ADMIN and all unrelated caps; retained NET_ADMIN/NET_RAW only if justified by
upcoming worker/Tailscale. No exec regain of dropped privileges. Probe verifies
post-exec reality; types/caller assertions alone do not prove capability safety.

Offline tests cover record/ownership/generation/interruption and lifecycle
semantics, manifest/FD/state/capability errors without actual namespace operations.
Ignored admitted-guest harness uses NEW disposable containers/cgroups/namespaces
and synthetic state. Positive actual placement, cgroup accounting, private root/
PID/proc mounts, capability/FD inventory, primary network preservation, two-exit
state isolation including adversarial /proc/PID/root, signal forwarding/reaping,
freeze/kill/parent/container death cleanup. Negative foreign handles, changed
process/cgroup/root/manifest, inherited host/peer descriptors and placement failure
must execute nothing. Fixed external tools only test code, no production shell or
CLI. Root runs exact static payload, preserves failed attempts and checks no
residual owned test resources. No real client/traffic or release acceptance claim.

Commit explicit owned code/docs/lock files, report task-6b-report.md with exact
code/payload hashes, focused commands/output summaries, unsafe/syscall inventory,
known boundaries and unperformed gates. Escalate structural gaps early. Do not
paper over missing guard/quarantine contracts with caller booleans.
