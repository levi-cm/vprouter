# Launch admission boundary

`vprouter-launch` admits container/process evidence only. It does not enter or
create namespaces, mount filesystems, place tasks in cgroups, reduce capabilities,
execute a worker, install quarantine, authorize an exit, or activate migration.
The existing CLI remains observational with `guard_runtime:false`.

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
values. Docker26 omits inactive `Mounts`, `Init`, `Tmpfs`, `Sysctls`; absence means
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
Every opened descriptor is close-on-exec and released by RAII.

`Admission::revalidate` rechecks exact task count, pidfd readiness, start time,
UID/GID maps, all namespace identities, root identity/read-only mount, exact cgroup
membership/identity, pinned executable/artifact metadata, a newly opened worker
path/hash and fresh Docker ownership/PID/start/configuration. The future executor
MUST call it immediately before placement and verify placement afterward. Process
death can occur immediately after success. No admitted object proves an exit was
selected or a future worker remained alive.

The concurrency trust boundary is the root operator and Docker daemon (including
members of its socket group). They must not maliciously replace mounts, images,
container configuration, protected manifests or artifacts during admission. The
read-only API cannot make Docker inspect and kernel observation atomic; final
rechecks detect observed replacement/restart/drift but cannot prevent a privileged
change after the check. Task6b must add generation locks, placement checks, private
PID1/mount/state views, FD and capability reduction, signal/reaping, and independent
host quarantine before any worker launch. No descriptor escapes into a worker in
this component because nothing executes.

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
