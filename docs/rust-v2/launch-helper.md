# Launch admission and isolated execution boundary

The public `vprouter-launch` CLI admits container/process evidence only and
always refuses activation. A private experimental executor now implements owned
namespace and isolated static-probe execution for the test-built guest harness.
Production staging still has no executable worker/policy integration, and no
public activation method can bypass the missing independent guard/quarantine.
The existing compatibility CLI remains observational with `guard_runtime:false`.

The standalone `vprouter-launch-admit SPEC STAGING` accepts two absolute paths to
root-owned private (no group/other, execute or special permission bits),
single-link JSON files beneath root-owned non-writable
ancestors. No command, argv, environment, namespace path, secret, or profile field
is accepted. It always exits nonzero with a fixed redacted reason and
`activation_ready:false`. Production staging currently returns
`launch_unavailable`: the actual Rust worker and its reviewed artifact manifest
integration do not yet exist. A root-owned arbitrary executable cannot enable
admission or execution. There is no runtime synthetic-probe flag or Cargo feature.
Only the custom, test-built ignored lab can construct probe staging evidence.

The strict schema1 launch document carries the complete validated schema2
`AllocationRecord`, matching generation and exact selected `ExitAllocation`, full
container ID, exact Docker RFC3339 UTC start string, proc start-time ticks, pinned
OCI reference and worker SHA256. It validates every allocation entry, resource
name and exit membership. Staging schema1 binds pinned manifest reference to OS,
architecture and platform content ID, exact fixed
`/usr/local/bin/vprouter-worker`, protected artifact path, length, SHA256 and
artifact kind. No state/profile path is opened. These are reviewed snapshots;
authoritative allocation locking, live generation reconciliation and selected-exit
namespace authorization remain task6b/integration requirements.

The native Docker API uses separate enforcement projections; observational
inventory requirements and serialization remain unchanged. Every request is
GET-only, bounded to 1 MiB and 9 seconds, with 3-second stages, explicit API1.45
and engine>=26 negotiation. IDs cannot be short names or endpoint fragments.
Image inspection independently binds RepoDigests, content ID, Linux OS and native
amd64/arm64 architecture. A multiarch manifest digest is never compared directly
to container `Inspect.Image`.

The intentionally narrow accepted layout is rootful Docker/runc, initial UID/GID
maps, cgroup2 with systemd and exact
`/system.slice/docker-FULL_CONTAINER_ID.scope`, overlay read-only rootfs, isolated
Docker mount/net/PID/UTS/IPC/cgroup namespaces, one of two exact masked-path profiles (Docker26 default11 or those11 plus
`/proc/interrupts`) and the exact five default readonly paths,
capdropALL and no-new-privileges. Privileged, host modes, remapping/rootless,
extra capabilities/devices/options/mounts and unknown functional HostConfig keys
are refused. Known inactive resource fields accept only enumerated default
values. Daemon SecurityOptions must be exactly one of two unordered sets:
`name=seccomp,profile=builtin` + `name=cgroupns`, or those two plus `name=apparmor`.
Missing, duplicate, unknown, rootless/userns, custom or unconfined seccomp options
fail closed. The first profile requires an empty container AppArmorProfile; the
AppArmor profile requires exactly `docker-default`. Admission retains this private
profile evidence, refreshes native daemon inspection on every revalidation and
refuses profile drift before rebinding the container. The AppArmor profile was
observed in the disposable guest; no-AppArmor profile has offline fixture coverage
only and remains kernel-unverified here. Docker26 omits inactive `Mounts`, `Init`, `Tmpfs`, `Sysctls`; absence means
inactive only for those fields. Required security flags and capability arrays
must be present. A gateway is deployment-owned with role `gateway` and serves all
exits; its exit label is not an authorization constraint. The lab alone allows
one exact private static probe RO bind. Normal production staging is unavailable.
Void/cgroupfs, other cgroup layouts, alternate Docker runtimes, rootfs drivers,
security configurations and additional mounts remain unsupported. This is not
completion of the required release platform matrix.

Admission opens numeric PID directories beneath descriptor-validated procfs and
pins a pidfd. Proc start time is checked before and after collection; namespace
magiclinks are opened only relative to that pinned process and must resolve to
actual nsfs descriptors. All eight namespace descriptors are retained. Initial
UID/GID maps plus the PID1 user-namespace identity exclude remapping. Required
Docker namespaces must differ from the helper's own. Exact-one-task inventory
is checked before admission and every public revalidation. The standalone helper
uses a current-thread runtime without a blocking pool, signal thread or task
creation. Async HTTP tasks share that one OS thread.

A pinned root descriptor is compared with the target's read-only overlay root
mountinfo identity. A trusted cgroup2 mount is validated against helper mountinfo;
the exact Docker-owned cgroup must have the same superblock/device and contain the
PID in cgroup.procs. The fixed worker path is opened beneath pinned root using
openat2 BENEATH/NO_SYMLINKS. Artifact ancestors are root-owned non-writable
non-symlink directories. Both artifact and worker must be root:root regular
executable files with no write/set-ID bits, exact bounded size, matching SHA256
and supported static ELF64 machine without PT_INTERP/PT_DYNAMIC. Maximum read is
64 MiB. File metadata/inodes are rechecked after hashing. No raw descriptor or
inode assertion constructor, Clone, Debug or Serialize exists on admitted handles.
Every admission descriptor is close-on-exec and released by RAII. Internal
one-thread registrations bind retained host FD numbers to device/inode/type and
CLOEXEC policy. Execution rejects all unregistered directories, namespace FDs,
sockets and other authority, including unexpected duplicate peer handles.

`Admission::revalidate` rechecks exact task count, pidfd readiness, start time,
UID/GID maps, all namespace identities, root identity/read-only mount, exact cgroup
membership/identity, pinned executable/artifact metadata, a newly opened worker
path/hash and fresh Docker ownership/PID/start/configuration. The private test
executor calls it immediately before and after placement, then verifies placement
again before release. Process death can occur immediately after success. No admitted object proves an exit was
selected or a future worker remained alive.

The concurrency trust boundary is the root operator and Docker daemon (including
members of its socket group). They must not maliciously replace mounts, images,
container configuration, protected manifests or artifacts during admission. The
read-only API cannot make Docker inspect and kernel observation atomic; final
rechecks detect observed replacement/restart/drift but cannot prevent a privileged
change after the check. The private executor adds generation locking, placement
checks, private PID1/mount/state views and FD/capability reduction. It can only consume a
cfg(test)-constructed, protected manifest-bound probe profile. Independent host
quarantine and genuine worker/Tailscale manifest integration remain mandatory
before production activation.

## Verification and ignored guest lab

Default tests are offline: no Docker requests, profile reads, namespace entry,
network or netfilter mutations. Controlled Unix HTTP servers verify actual GET
method/path parsing and content/image projections. Synthetic fixtures exercise
schema, allocation/generation/member mismatches, redaction, mandatory flags,
unknown functional configuration, platform/content mismatch, proc stat names,
UID maps, exact cgroup paths, mount identity, ELF/hash/size and pidfd/task evidence.

Build the custom ignored test (libtest itself would add an OS task), probe and
standalone fail-closed helper:

```sh
cargo rustc -p vprouter-launch --release --target x86_64-unknown-linux-musl --test admission_lab -- -C relocation-model=static
cargo rustc -p vprouter-launch --release --target x86_64-unknown-linux-musl --example static_probe -- -C relocation-model=static
cargo rustc -p vprouter-launch --release --target x86_64-unknown-linux-musl --bin vprouter-launch-admit -- -C relocation-model=static
```

Controller alone transfers hashes and installs the probe root:root0555 at
`/var/lib/vprouter-v2-lab/launch-probe` and the custom test executable root0555 at
`/var/lib/vprouter-v2-lab/launch-admission-lab` in an owned disposable guest.
The existing lab directory must be root0700 and `isolated-acceptance` marker
root:root0600/single-link beneath safe ancestors. Execute only with self/PID1
network namespaces distinct:

```sh
unshare --net /var/lib/vprouter-v2-lab/launch-admission-lab --ignored
```

No argument means skipped. The marker and namespace checks precede API calls and
subprocesses. Only test code uses fixed Docker argv, no shell: it creates NEW
network-none/read-only/capdropALL/nnp containers from
`tailscale/tailscale@sha256:c507f3a2a6ab1cabd8d809b98edeb41edbd5c3fb6ad9632ffd098b4c7d0b4065`
(Tailscale1.102.5), with the synthetic static probe as init. No enrollment or real
state is reused. Native API and actual proc/FD evidence must positively admit the
owned container; wrong retained namespace/cgroup descriptors, artifact hash,
start time, manifest/container identity and a separate real foreign-labeled
container must fail. Pause and death must invalidate retained handles. Cleanup
removes only newly created exact container IDs and synthetic lab directory.
The probe never sends traffic and is not a real worker/Tailscale runtime test.
Controller execution evidence and initial failures belong in the task6 report.
## Private owned-namespace executor (test-probe boundary)

There is no production constructor for `VerifiedProgram`. The production staging
parser continues returning `launch_unavailable`. No Cargo feature, operator JSON
boolean, arbitrary binary, argv or environment can turn on launch. The test
staging record additionally binds `execution_policy_sha256` to the exact compiled
probe and wait-role seccomp BPF bytes plus the fixed UID/GID/capability/LSM/
environment/resolver policy.
Changing either artifact bytes or confinement policy invalidates that evidence.

Namespace records live beside authoritative allocations under an existing
root:root0700 directory. The existing allocation flock is held throughout entry
and launch admission. `AllocationTransaction::verify_directory` compares the
retained directory directly against its actual locked store, without an FD getter
or caller assertion. `namespaces.json` stores the complete allocation, immutable
explicit `primary_exit_id`, base-network dev/inode and exact exit names/identities.
The primary is never inferred from ID spelling or vector order. Exact generation,
membership and base identity are required on reopening. Record replacement is
O_EXCL temporary creation, fsync, rename, directory fsync. Interrupted temporaries
and Creating entries remain offline; no adoption-by-prefix or generic cleanup API
exists. Initial mount pins require exclusive placeholders beneath the retained
directory. Reopening verifies nsfs device/inode, enters the pinned handle in the
one-task helper, reopens `/proc/thread-self/ns/net`, then restores the original
network namespace. Only direct proc network FDs reach native network code.
Primary data preserves the admitted gateway base network; other data and all
transport namespaces are independent and remain unaddressed/unactivated.

A launch recreates a current-thread API runtime solely for revalidation, drops it
and every socket, verifies one OS task, checks exact inherited FD inventory, then
forks a placement-gated child. Host proc/cgroup2 views must prove actual membership
in the retained exact Docker cgroup. Fresh admission and allocation validation
follow placement before release. Child setup joins admitted IPC/UTS/cgroup/mount
and selected network namespaces. PID-for-children is joined first and an
intermediate fork establishes an active container PID namespace; a subsequent
private PID+mount unshare and fork creates per-exit PID1 nested beneath it.

Mount trees must be cloned in their source-owning namespace. The selected state
tree is detached with safe rustix `open_tree(AT_EMPTY_PATH|CLONE|CLOEXEC)` in the host
context; the manifest-verified image executable tree is detached after entering
the admitted mount namespace and before private unshare. Safe `move_mount` uses
retained source/destination descriptors, with no source-path fallback. A private
tmpfs root contains only the fixed image executable, selected state, private proc
and a fixed read-only test resolver file. Original root is pivoted out and
immediately detached; the resulting root is read-only. Mount propagation is
recursively private. State-root ancestors are protected and allocation validation
rejects overlap with all peers; nested mounts are refused. The test layout has a
protected exit root and a fixed `worker` child owned65534:65534/mode0700 mapped at
`/state`. Production migration/state authority has not yet adopted this layout.

PID1 and worker explicitly establish docker-default AppArmor and the reviewed
probe seccomp policy; host namespace entry never counts as inherited Docker
confinement. The test profile has UID/GID65534, no supplementary groups and zero
effective/permitted/inheritable/ambient/bounding capabilities. Securebits0xef and
no_new_privs are set and verified. Child stdio is fixed `/dev/null`; worker FD3 is
a pipe for fixed health/error bytes; CLOEXEC FD4 is the verified executable and
is consumed via fixed `execveat(AT_EMPTY_PATH)`. All other descriptors are closed
and final inventory verified. Fixed argv is `vprouter-worker --isolated-probe`;
fixed environment is exactly `LANG=C`, `PATH=/bin`. No inherited secret/proxy env
is passed. Parent readiness requires both explicit confined-PID1 readiness and
post-exec worker verification and both reduced wrapper readiness messages.
Post-closure failures `_exit`, never unwind through inherited FD owners.

PID1 closure uses strict native enumeration: any entry, numeric parsing or close
failure refuses readiness. Only the exact temporary scan FD is excluded. An
independent scan before and after seccomp requires precisely approved null
stdio plus the retained CLOEXEC health pipe; identity/type and descriptor flags
are checked separately. The health descriptor is closed with a checked operation
after readiness, leaving no host authority.

Synchronous blocked-signal handling forwards TERM/INT/HUP and PID1 reaps adopted
descendants. Shutdown retains the earliest monotonic deadline across repeated
signals and worker exit. PID1 escalates after 500 ms; intermediate and outer wait
roles allow 1000ms and1500 ms respectively, so inner reaping precedes outer
escalation. Post-escalation waits are also bounded. Signal, wait and close errors
are fatal; only explicit no-target/observed pinned-child-exit races are benign.
Bounded escalation kills frozen descendants. pidfds avoid host PID
reuse, PDEATHSIG links the launch chain, and private PID1 death kills its PID
namespace. Actual kernel behavior, not Docker GET/status, is the evidence gate.
Independent host guard/quarantine remains a separate future failure boundary.

The two surviving placement wrappers each create an independent empty read-only
tmpfs root and cwd, pivot out and detach their old root. Neither retains proc,
state, host root, namespace or cgroup descriptors. After setting approved null
stdio and establishing confinement, the only extra descriptor is an exact child
pidfd. A separate wait-role filter denies all pathname operations, namespace
changes, network access, fork and exec. All roles clear the inherited environment;
only the fixed worker exec receives the two-entry safe environment. Credential
changes re-arm PDEATHSIG and the retained parent pidfd is checked before closure.
The host-side guest harness audits the full container cgroup, including the outer
wrapper whose active PID namespace remains the host namespace. Empty roots and
cwd, mount readonly state, exact FDs, credentials, capabilities, LSM and seccomp
must all agree with the fixed role policy. These are implementation requirements;
the run evidence separately states which runtime cases reached completion.

Probe seccomp denies network sockets, mount/setns/unshare, capset, ptrace, bpf,
open_by_handle_at, io_uring and pathname exec. Ordinary fork clone flags alone are
allowed; namespace/VM/ptrace clone and x32/foreign architecture calls are refused.
The exact instruction list and unsafe syscall inventory are in `kernel.rs` and the
6b report. Only that internal module allows unsafe; every other module forbids it.
Safe maintained rustix wrappers provide namespace entry and detached mount APIs.

Mandatory docker-default AppArmor and zero capabilities describe this TEST-PROBE
profile only. They do not certify a final Debian/Arch/Void platform policy.
No-AppArmor execution, genuine Rust worker/Go Tailscale policies, validated
production resolver derivation, migration authority, independent guard and network
activation remain unavailable/unperformed. TEST-NET resolver192.0.2.53 is a
synthetic file and provides no usable path. No address/link/default mutator exists.

Build additional static test artifacts with pinned1.97.0/musl:

```sh
cargo rustc -p vprouter-launch --release --target x86_64-unknown-linux-musl --test execution_lab -- -C relocation-model=static
cargo rustc -p vprouter-launch --release --target x86_64-unknown-linux-musl --test execution_probe -- -C relocation-model=static
```

Controller alone installs current exact hashes under protected lab paths
`launch-execution-lab` and `launch-execution-probe`, then runs:

```sh
unshare --net /var/lib/vprouter-v2-lab/launch-execution-lab --ignored
```

The harness creates only new disposable network-none containers and synthetic
`task6b-PID` state. Normal tests never run it. Failed attempts retain ownership
records/mount pins offline for explicit ownership-safe controller cleanup. A
successful run unpins only its exact records after container/process death and
verifying no live process uses each network identity. Historical failed attempts
are not replaced by later successes. See controller evidence and task6b report for
actual per-case PASS/FAIL/NOT_RUN; this document is not kernel acceptance proof.

The strengthened signal case requires host-observed stopped state for each exact
worker's descendant before signals, a fixed selected-state witness written by
the worker after actually receiving forwarded TERM, and a separate test-only
PID1 witness written after actual descendant waitpid. Repeated TERM/INT/HUP
continue until both launch chains naturally exit successfully within 2 seconds.
The harness cannot invoke force termination to establish that result; forced
cleanup remains a failure path. These witnesses use existing admitted syscalls
and selected synthetic state, with no policy or capability expansion.
