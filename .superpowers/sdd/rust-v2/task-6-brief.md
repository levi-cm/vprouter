# Launch admission: pinned container, process, cgroup and executable evidence

Workdir /DATA/AppData/vprouter-rust-v2, rust/v2. No subagents. Read this brief
first, binding docs/rust-v2/IMPLEMENTATION.md, then
.superpowers/sdd/rust-v2/task-6-launch-full-requirements.md for the eventual
execution boundary. This task implements ADMISSION ONLY. A following task6b owns
actual namespace creation/entry, mounts/private PID1, cgroup placement, capability
and FD reduction, exec/signal/reaping. Do not implement partial unsafe exec APIs
or activate any path. Production migration and launch remain unavailable.

Own new crates/vprouter-launch (admission library and fail-closed helper entry),
minimal additions to native Docker inspection, workspace/lock changes,
docs/rust-v2/launch-helper.md, .superpowers/sdd/rust-v2/task-6-report.md. Exact-pin
dependencies. No production unsafe, setns, unshare, mounts or subprocesses here;
future unavoidable unsafe belongs in ONE reviewed Linux module. Default tests
never mutate network/kernel, read real profiles or touch production. Controller
alone runs ignored harness in isolated guest. No broad code changes.

Strict protected versioned launch spec, no secrets/argv/env fields; full reviewed
AllocationRecord+generation and exact exit membership. Inputs protected root-owned
files or inherited descriptors. Fixed redacted errors, no raw Docker/process/env
payloads. Stable reason codes. Preserve GET-only CLI observational behavior and
guard_runtime:false. Standalone helper validates/advises only and returns explicit
launch_unavailable until execution/guard/runtime manifest integration is complete.
No arbitrary command or namespace path fields from untrusted input.

Native Docker Unix API: validate expected FULL container ID, exact
io.vprouter.deployment label, io.vprouter.role=gateway, running PID, started-at,
content image ID, read-only root, network none, no privileged/host PID/host user
namespace/remapping/rootless, no Docker socket, exact allowed mount/capability/
security configuration. One gateway serves all exits; no per-exit container label
requirement. Unknown functional configurations must fail closed. API projection
must retain required fields and reject missing/malformed ones, without changing
old observational status into an enforcement query. Bounded native requests,
no CLI. Resolve pinned configured manifest digest to expected OS/architecture
content image ID through root-owned staging evidence AND native image inspection;
do not compare multiarch manifest digest directly with Inspect.Image. Exact
worker image path/hash and protected staging artifact evidence required: root-owned
arbitrary executable alone insufficient. Native image inspect binding RepoDigests,
ID, OS and architecture; reject ambiguity/platform mismatch/untrusted staging.

Open PID-bound proc directory without untrusted symlink traversal; pidfd pins
liveness, stat start-time before/after, proc UID/GID maps and namespace identities,
rootfs and cgroup v2. Exact-one-task single-threaded caller admission before any
future namespace entry, recheck process liveness/start-time and native Docker
identity before admitting. Validate trusted procfs/nsfs/cgroup2 mount identities;
userns/rootless/remapped/unsupported layouts refuse explicitly. Descriptor-relative
safe paths with no .. or untrusted intermediates. Do not trust /proc/PID/root or
namespace magiclink text without pinned process identity+fd metadata validation.
Open exact namespace FDs and rootfs/cgroup descriptors; retain non-clonable private
handles in admitted object for future helper. No public constructor from caller
booleans or raw numeric inodes, no Debug/Serialize leaking handle/path details.
Process can die after admission; expose bounded liveness/revalidation that future
executor MUST use immediately before placement. Documentation must describe the
residual trusted Docker/root concurrency model and evidence lifetime.

Verify cgroup membership from pinned proc matches expected Docker-owned cgroup
layout and same cgroup2 superblock. Do not infer ownership merely from container
name or matching substring. Validate root directory identity and read-only mount
from pinned mountinfo. Open fixed worker executable through pinned root FD,
regular/nonwritable ownership/size/architecture/ELF-static constraints, hash exact
bytes under bounded read, retain stable executable FD, recheck inode/metadata.
Synthetic probe manifest may stand in for absent worker ONLY in ignored test
harness, never a production root-file flag/boolean bypass. Secrets/state paths not
read. Exact private state and namespace authorization/creation remain task6b;
admitted container descriptors alone must not claim selected exit placement.

Meaningful offline tests: strict spec+staging parsing unknown fields/schema,
allocation/generation/exit mismatch, secret-error redaction, native Docker HTTP
projection/admission missing/malformed config flags, pinned manifest-to-content
mapping/platform, proc stat parser tricky comm names, cgroup/path/UID map mismatch,
ELF/hash mismatch and bounded reads, liveness/revalidation decisions. Controlled
Unix HTTP server checks real method/path parsing. No test that merely mirrors a
constructor assignment or asserts unconditional launch_unavailable alone.

Provide ignored owned-guest harness with existing root-only lab-marker and
self-vs-PID1 netns admission. Fixed external Docker commands allowed ONLY test
code, no shell. Create NEW labeled disposable network-none/read-only/capdropALL
container from pinned known image with synthetic static Rust probe. Native API
and proc/FD evidence must positively admit correct configuration and refuse
foreign label/container, wrong image/manifest/hash/starttime/cgroup/namespace.
Revalidate after container exit to prove stale handles do not authorize launch.
Do not reuse enrollment container or its state. Controller executes harness and
records failures/passing payload hash; no real traffic or runtime gate claim.

Run covering tests/fmt/check/clippy, static harness build, compile ARM64 admission
library if practical. No redundant reruns absent changed source/failure. Explicit
owned-path commits only (root ledger/evidence untouched), force-add report with
exact code hashes, full commands/output summaries, FD/unsafe/subprocess inventory,
known boundaries and NOT_RUN checks. Return only status/commits/short tests/concerns.
