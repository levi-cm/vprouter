# Verify the real internal cgroup parent edge

Workdir /DATA/AppData/vprouter-rust-v2 branch rust/v2, base e986cfda4c0fe3f29c6167541e1ff5698d859b4b.
Read task-8c-bootstrap401-diagnosis.md first, parent8c brief and binding contract.
Root current-only oracles are target/task8c-pending-20261029T133358Z/
cgroup-root-dotdot-oracle.json and cgroup-internal-parent-oracle.json. They prove
root '..' differs, system.slice '..' equals original cgroup2 root, and the original
inert gateway's PID/start/membership/exactDocker scope still agree. Neither is an
original owner executed-return trace.401 remains FAIL; no identical retry.

Fix the concrete false mount-root self-parent predicate in BOTH host admission
and confined Bootstrap ancestry. Owned scope:
- crates/vprouter-launch/src/process.rs
- crates/vprouter-native-role/src/producer_bootstrap.rs
- crates/vprouter-native-role/src/filter.rs (test-only changes allowed here)

Host verifier: replace (root,"..",root) by (system,"..",root). Retain original
PinnedProcess revalidation, same original root FD/identity, directory trust,
cgroup2 filesystem, exact root->system.slice and system.slice->originalDocker
scope checks and all no-follow/openat2 restrictions.
Confined verifier: check system_slice relative '..' against original root.
Change ONLY first actual Ancestry-generated syscall rule directory FD from root
to system_slice for its same fixed immutable '..' pointer/NOFOLLOW flags. Keep
exact four rules, remaining forward scope/group edges, original root/type/mode/
filesystem/inventory/identity/deadline/confinement checks. Do not allow both FDs
or broaden any syscall/path/flags/oldrole. Private constant rename allowed.

Meaningful RED/GREEN regression must execute the shared production named-edge
core with real borrowed directory FDs, an external parent distinct from root,
and internal system.slice/exact Docker-shaped scope/group hierarchy. Old self-
parent code must fail; real reverse edge plus existing forward edges must pass.
Refuse foreign root/system/scope FDs, replacement/rename/symlink names; preserve
existing negative coverage. Do not manufacture full PinnedProcess/Source/Owner
or confined-role authority from fixture metadata. Private helper extraction is
allowed only for those borrowed comparisons; production retains all admission,
creator/root ownership, cgroup2/trust and pinned identity checks outside it.
Exact filter regression must consume actual Ancestry::rules, not a generic mock
array: correct systemFD/fixed '..'/NOFOLLOW allowed; former rootFD/same pointer,
foreignFD/name pointer/follow flags/high words denied; old roles and forbidden
operations unchanged. Actual filter execution remains Root native gate.

Do not modify the previous13pending-progress source paths or six approved8c.1
receipt files. No new runtime/placement/UP/Ready/recovery/cleanup authority, clock
renewal, policy bypass or generic helper. No source claim that401exactreturn is
captured. No subagents/Git/manifests/contexts/staticbuilds/VM/SSH/Docker/profile/
identity/privileged actions. Local focused tests/fmt/clippy allowed.
Write task-8c-bootstrap-ancestry-fix-report.md with exact owned hashes, red-green
checks and retained logs, test/core limits and NOT_RUN boundaries. Freeze for
fresh independent spec+quality review. Root owns coherent botharch builds,
protected preserved54-link baseline, newnative run and checkpoint/push.
