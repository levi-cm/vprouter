# Task6 launch admission implementer report

Latest review-fix implementation: `338dcba280dbe0699640def7c63f9ed7f17e16c3`.
Round1 sole Important finding (daemon security-profile admission) is fixed;
controller exact-payload attempt5 passed. Original implementation/evidence below
is preserved historically; the appended round1 section binds current code/tests.

Status: DONE_WITH_CONCERNS. Admission ONLY; namespace entry/creation, placement,
execution, independent host guard, production runtime and migration remain
unavailable. `guard_runtime:false`, `activation_ready:false` throughout.

Exact code commit: `5dbcccb9d37af11d11cb5e0f0fc766a89f71ea87`
(`feat: add descriptor-backed container launch admission without execution`).
Parent: `64a5515` (controller's independent kernel-oracle evidence); assigned
reviewed base was `47381e8`. Worktree `/DATA/AppData/vprouter-rust-v2`, `rust/v2`.
Only owned paths were staged/committed. Controller progress/ledger and independent
lab evidence files were left untouched. This report is a separate report-only
commit so the exact implementation hash is immutable.

## Implemented boundary

- New exact-pinned workspace crate with protected strict schema1 launch/staging
  inputs, full validated AllocationRecord+generation+exact exit member, fixed
  executable path and redacted enum-only errors. No arbitrary argv/env/namespace
  fields, no profile/state reads. Production staging cannot approve arbitrary
  root-owned bytes: reviewed Rust worker manifest integration is absent and
  returns `launch_unavailable`. Synthetic staging constructor exists only in
  cfg(test), not a Cargo feature, production root-file flag or public admission
  constructor. Public admission takes protected file paths, not caller evidence
  booleans or raw inode/FD assertions.
- Separate bounded native Docker enforcement projections/methods for complete
  container ID, exact deployment/gateway label (one gateway serves all exits),
  live PID/start time, image/configuration, image content ID/RepoDigests/platform
  and daemon rootful/systemd/cgroup2 information. Original observational inventory
  and GET-only CLI were not converted into enforcement queries.
- Enumerated exact supported Docker functional configuration: network none,
  read-only overlay root, isolated namespaces, runc, capdropALL+nnp, no devices,
  unexpected mounts, host/remapped/rootless modes or unknown HostConfig options.
  Known inert resource options allow only exact defaults. Docker26 omits inactive
  Mounts/Init/Tmpfs/Sysctls; those four are optional/inactive when absent. Required
  security flags/capability arrays remain mandatory. Exactly two mask profiles
  are admitted: observed Docker26 11-path default, or those11+/proc/interrupts;
  arbitrary subsets/supersets fail. Exact five readonly paths remain required.
- PID-bound proc directory, pidfd liveness, before/after start time, initial
  UID/GID maps, actual nsfs identities for eight pinned namespaces, comparison
  against PID1 user namespace, required isolation versus helper namespaces,
  validated procfs/cgroup2 mount identities, pinned readonly overlay root,
  exact full-ID systemd Docker cgroup path+same-superblock+PID membership.
- Fixed worker opened beneath pinned root through openat2 BENEATH/NO_SYMLINKS;
  separately protected artifact evidence. Root:root regular nonwritable executable,
  supported static ELF64 machine without PT_INTERP/PT_DYNAMIC, bounded64MiB exact
  size/SHA256 and before/after metadata/inode verification. Stable FD retained.
- Non-clonable private Admission/process handles without Debug/Serialize/raw-FD
  getters; exact-one-task process inventory; bounded liveness/revalidation API
  rechecks Docker/kernel identity and newly opened worker bytes. Future executor
  MUST revalidate immediately before placement and verify after placement. An
  admitted container does not authorize an exit namespace, state or execution.
- Standalone fail-closed helper/current-thread runtime. Ignored harness has custom
  main because libtest runner itself adds a second OS task; ordinary tests skip
  it. Only test-built private modules can load synthetic probe evidence.

## Verification commands and results

Commands executed in assigned worktree using pinned Rust1.97.0:

```
cargo test -p vprouter-launch --lib
cargo test -p vprouter-launch -p vprouter-linux
cargo test -p vprouter-linux docker::tests::launch_image_and_daemon_native_http_keep_fixed_get_paths
cargo test --workspace --all-targets
cargo fmt --all
cargo fmt --all -- --check
cargo clippy -p vprouter-launch -p vprouter-linux --all-targets -- -D warnings
cargo clippy --workspace --all-targets -- -D warnings
cargo check --workspace --all-targets
cargo check -p vprouter-launch --lib --target aarch64-unknown-linux-musl
cargo build -p vprouter-launch --lib --target aarch64-unknown-linux-musl
cargo rustc -p vprouter-launch --release --target x86_64-unknown-linux-musl --test admission_lab -- -C relocation-model=static
cargo rustc -p vprouter-launch --release --target x86_64-unknown-linux-musl --example static_probe -- -C relocation-model=static
cargo rustc -p vprouter-launch --release --target x86_64-unknown-linux-musl --bin vprouter-launch-admit -- -C relocation-model=static
file target/x86_64-unknown-linux-musl/release/deps/admission_lab-7b47b108a92e3a1f target/x86_64-unknown-linux-musl/release/vprouter-launch-admit
readelf -l target/x86_64-unknown-linux-musl/release/examples/static_probe
git diff --check
```

Final full suite: **101 passed, 0 failed, 2 existing kernel tests ignored**;
new custom admission lab printed explicit skipped without --ignored. New launch
unit tests8 and native Linux tests17 pass. Workspace check/clippy/fmt and diff
checks pass. ARM64 admission library typechecked AND code-generated into rlib;
no ARM64 kernel execution claim. x86_64 musl payload/helper/probe are ELF EXEC,
statically linked; probe program headers contain no INTERP or DYNAMIC.

Tests cover strict unknown/schema fields and redaction, full allocation/member/
generation mismatch, missing required Docker flags/malformed projection,
unsupported defaults and unknown functional keys, exact11/12 masks versus a
wrong subset, one shared gateway exit-label independence, image manifest versus
platform content identity/architecture/ambiguity, actual controlled Unix GET
/version,/images/FULL_CONTENT_ID/json,/info,/containers/FULL_ID/json parsing,
missing enforcement fields, proc stat comm containing parentheses/newlines,
UID maps/cgroup exact paths, mount identities, ELF architecture/dynamic/truncated
headers, actual file/hash/size checks, pidfd readiness and real extra-task refusal.
Default tests do not enter namespaces, mutate networking/netfilter or read real
profiles. Positive root executable ownership/hash is proved by guest kernel run;
non-root ordinary unit test does not pretend to prove root ownership.

Early local compiler/clippy/test feedback was corrected before final checks:
sha2 digest formatting, empty-string style, nested test-module warnings,
Option presence semantics and one initial missing-CapDrop test failure. These
were development failures, not passing evidence. An intermediate fmt --check
reported formatting after extending the HTTP test; cargo fmt then final fmt check
passed. No final unresolved compiler/test/clippy failure remains.

## Exact artifacts and controller guest execution

Final implementation5dbcccb artifacts:

| Artifact | SHA256 |
|---|---|
| `target/x86_64-unknown-linux-musl/release/deps/admission_lab-7b47b108a92e3a1f` | `cc51f123326640a730639171d138f4132d09ca71dff98d243f14a2de2928605b` |
| `target/x86_64-unknown-linux-musl/release/examples/static_probe` | `2c1068174b100fd21339c6a633a76f5318c0fa0ff02bd71dafcec0a6d22cc362` |
| `target/x86_64-unknown-linux-musl/release/vprouter-launch-admit` | `fe62bbd7704e66b20145c47703825b309f59b29fb17ded9f1a5e48ad4d2e375e` |
| `target/aarch64-unknown-linux-musl/debug/libvprouter_launch.rlib` | `d1fbdd4ceed375bca57d628067648833b51ddd6c32f050249efd76d04d6776c9` |

Controller alone transferred and installed exact root:root0555 lab/probe files
under existing root0700 `/var/lib/vprouter-v2-lab`, checked root:root0600/single-link
`isolated-acceptance` marker, then ran in owned disposable Debian13 KVM guest:

```
sudo unshare --net /var/lib/vprouter-v2-lab/launch-admission-lab --ignored
```

Pinned known image:
`tailscale/tailscale@sha256:c507f3a2a6ab1cabd8d809b98edeb41edbd5c3fb6ad9632ffd098b4c7d0b4065`
(Tailscale1.102.5). Native API resolves actual platform content ID/RepoDigests;
no assumed manifest-to-content comparison. Fresh disposable network-none,
read-only, capdropALL+nnp containers only; no enrollment/container state reused.
Probe has no network operations or credentials. Controller owns cleanup evidence.

All attempts are preserved in independent controller evidence
`docs/rust-v2/launch-admission-lab-evidence.json` (controller-owned, not modified
by implementer):

1. FAIL, exit1/0.698s SSHwall, payload
   `223d4c87dc61c9d10c4b189b4d5f758af83be32be30b283ff99ba0478aa2eb91`.
   Stages admitted_owned_isolated_guest/create_new_disposable_pinned_container;
   fixed reason docker_unavailable, no positive case. Focused disposable-container
   metadata diagnostics proved valid Docker26 omitted inactive nullable fields.
   Corrected only those four optional fields; no raw inspect/env/process payloads.
2. FAIL, exit1/0.626s SSHwall, payload
   `ca9b082473a8e97bdd6d99535959855b651f1aaeb3e0b1eac6b6ee42716ed691`.
   Native container/image parsing succeeded; positive-admission stage refused
   unsupported_configuration. Exact mask diagnostics showed Docker26 default11
   omits /proc/interrupts versus original12. Controller stat-only check found
   /proc/interrupts regular0444/rdev0, no exact mountinfo entry; no contents read.
   Corrected explicit reviewed11/12 profiles, with wrong-subset regression.
3. PASS, exit0/1.279s SSHwall, payload
   `4185cb908d271309b0bebe0dba530e8e5156b7c42e2250ecdf8f1c8185e00375`.
   All six kernel/native cases below passed. Subsequent Linux cfg(test) HTTP test
   extension changed Rust dependency metadata/symbol hashes on rebuild, so this
   pass is preserved but not substituted for final artifact evidence.
4. **PASS**, exit0/1.139s SSHwall, exact code5dbcccb/final payload
   `cc51f123326640a730639171d138f4132d09ca71dff98d243f14a2de2928605b`.
   Controller confirmed all six cases and final guard_runtime:false/activation:false.
   No further implementation source change after this exact build/run.

Six cases: native Docker/proc/root/cgroup/ns/static executable positively admitted;
actual wrong retained namespace/cgroup descriptor substitution refused;
actual artifact bytes/hash mismatch refused; changed start-time/container/manifest/
hash bindings refused; separately created real foreign-deployment container
refused; pause and container death invalidate retained handles. Wrong retained FD
controls are test-only, not claims of malicious privileged namespace movement or
real cgroup placement. Container death checks stale-handle refusal, not child
reaping/quarantine cleanup (no child executor exists yet).

## FD, unsafe and subprocess inventory

Production unsafe blocks: **zero**, enforced by forbid(unsafe_code) in library,
helper and custom lab entry. All kernel access is through safe rustix APIs.
No setns, unshare, mount, namespace creation, exec, fork, capset/capdrop mutation,
cgroup write, network/netfilter mutation or production subprocess exists here.
Future unavoidable unsafe must be isolated to one reviewed Linux module in6b.

A successfully admitted object retains15 private non-clonable CLOEXEC descriptors:
proc directory1, pidfd1, namespace FDs8 (mnt/net/pid/user/uts/ipc/cgroup/time),
rootfs1, cgroup root1, exact container cgroup1, worker executable1, staging
artifact1. Intermediate proc/ns/ancestor/read/check descriptors and Docker Unix
sockets are bounded-scope RAII. Revalidation temporarily opens exact counterparts;
failed paths release their handles. Test-only wrong-cgroup control temporarily
uses dup and drops it before any subprocess. No admitted raw-FD public accessor,
Debug, Serialize or Clone exists. Standard helper FDs remain0/1/2; final allowed
FD inventory/closing before exec is explicitly NOT_IMPLEMENTED task6b.

Only cfg(test) `lab.rs` imports Command::new("docker"), with fixed native argv,
never a shell: fresh run/foreign-run, pause/unpause, kill, rm --force exact created
full IDs. Docker CLI stdout/stderr are not printed; only bounded static stage/
reason labels emitted. Test CLI output-size check happens after collection and
there is no internal subprocess timeout; the controller must bound lab execution.
Production native requests have explicit time/body bounds. Static probe only
sleeps; it does not execute children or inspect state.

## Explicit concerns and NOT_RUN

- Production worker artifact manifest integration does not exist. Production
  staging returns launch_unavailable; standalone helper can never activate a
  worker. This is the intended fail-closed preparation boundary.
- Only rootful systemd/cgroup2/runc/overlay/default-security layout is admitted.
  Void/cgroupfs and other required release environments remain unsupported,
  explicitly NOT_RUN; ARM64 kernel runtime also NOT_RUN (library built only).
- Reviewed allocation/generation is a protected snapshot, not an authoritative
  live allocation-store lock. Generation locking/reconciliation, private state
  ownership and exact selected exit namespace persistence/creation are6b/future
  integration and cannot be inferred from container descriptors.
- Trusted concurrency boundary: root operator, Docker daemon/socket group.
  Docker/API/kernel observations are not atomic, a process may die immediately
  after success, privileged changes can race final checks. Executor must perform
  immediate revalidation and post-placement accounting; no no-race claim.
- Private per-exit PID1/proc/mount/state isolation, cross-exit /proc/PID/root
  attack tests, cgroup placement/accounting, FD/capability reduction, exec-by-FD,
  signal forwarding/reaping and launch-child cleanup: NOT_IMPLEMENTED/NOT_RUN.
- Independent quarantine integration, enabled guard/runtime, real worker and
  tailscaled operation, real traffic/leak/acceptance tests, production migration,
  performance matrix/soak/reboot/rollout/release acceptance: NOT_RUN/unavailable.
- Scope deviation: initial AGENTS pathname lookup used overly broad
  `find .. -name AGENTS.md`, enumerating sibling directory pathnames and hitting
  Permission denied on `../vprouter/tailscale/{files,profile-data,certs}`. No file
  contents/secrets/production Docker/runtime/API/profile data were read. That
  search should have been scoped to ancestors/assigned worktree; subsequent work
  stayed in assigned Rust worktree. No production mutation occurred.


## Independent review fix round1: exact inherited daemon security profile

Review verdict before fix: specification FAIL / quality Needs fixes; sole
Important finding: original daemon admission only denied known rootless/userns
markers, so empty/unknown SecurityOptions or a custom inherited seccomp default
could pass with container SecurityOpt=[no-new-privileges]. No Critical/Minor
finding was assigned in this round. This section records the implemented fix,
not an independent re-review acceptance claim.

Exact fix code commit: `338dcba280dbe0699640def7c63f9ed7f17e16c3`
(`fix: bind launch admission to exact daemon security profiles`), parent
`a28e309` (controller's intervening evidence/next-boundary preparation).
Owned source changes only: evidence.rs, lib.rs, tests.rs, launch-helper.md.
Controller ledger/evidence/task6b brief changes remain untouched.

The rootful/systemd/cgroup2/Linux gate now produces private enumerated profile
evidence only for these exact unordered SecurityOptions sets:

- `name=seccomp,profile=builtin` + `name=cgroupns`.
- Those two plus exactly one `name=apparmor`.

Missing mandatory markers, empty arrays, duplicates, unknown markers, SELinux,
rootless/userns, custom/unconfined/extra seccomp options fail closed with fixed
unsupported_configuration. The profile without AppArmor requires an empty
container AppArmorProfile; the AppArmor profile requires exactly docker-default.
Admission stores the private enum, refreshes native daemon evidence on every
revalidation, rejects profile drift, then checks the matching container profile.
No public evidence assertion, new activation/exec path or synthetic production
flag was introduced. Production staging still returns launch_unavailable.

Controller selected-field read-only guest evidence before fix was exactly:
SecurityOptions=["name=apparmor","name=seccomp,profile=builtin","name=cgroupns"].
A new disposable synthetic container's AppArmorProfile was exactly docker-default;
controller removed its exact newly created ID after diagnosis. No raw daemon/
container/env payloads were emitted. This binds the kernel-exercised supported
profile. The no-AppArmor profile has positive/negative offline fixtures but
**kernel verification remains NOT_RUN**; it is not a verified release platform.

Focused verification commands/results for exact fix source:

```
cargo fmt --all
cargo test -p vprouter-launch -p vprouter-linux
cargo clippy -p vprouter-launch -p vprouter-linux --all-targets -- -D warnings
cargo fmt --all -- --check
cargo check -p vprouter-launch -p vprouter-linux --all-targets
cargo rustc -p vprouter-launch --release --target x86_64-unknown-linux-musl --test admission_lab -- -C relocation-model=static
cargo rustc -p vprouter-launch --release --target x86_64-unknown-linux-musl --bin vprouter-launch-admit -- -C relocation-model=static
git diff --check
```

All pass: launch9+Linux17 = **26 tests passed**, 0 failures; custom lab skipped
without explicit ignored argument. Focused profile fixtures cover serialization
order, both exact positive sets, missing/malformed native list, duplicate markers,
unknown and conflicting profiles, custom/unconfined seccomp, missing mandatory
seccomp/cgroupns, explicit rootless/userns and AppArmor/container mismatch.
Error output remains fixed/redacted even for a synthetic secret-shaped custom
seccomp path. Original workspace101-test evidence above is historical; no claim
of a new full workspace or ARM64 artifact rebuild in this focused review fix.

Final static lab (same path as original) SHA256:
`312d59da7caa0e3ea97bfecc1e97be234c69a32608283517efcfcc6b26790144`.
Final standalone fail-closed helper SHA256:
`5e96e8ad423613456b5143042e7ed1c204bd4ef447d9533b2bcdba761b01cb18`.
Probe unchanged SHA256:
`2c1068174b100fd21339c6a633a76f5318c0fa0ff02bd71dafcec0a6d22cc362`.

Controller alone installed exact protected payload and ran unchanged admitted
owned-guest command:

```
sudo unshare --net /var/lib/vprouter-v2-lab/launch-admission-lab --ignored
```

**Attempt5 PASS**, exit0/1.362s SSHwall, exact code338dcba/payload312d59.
All six prior admission/kernel cases pass and final guard_runtime:false,
activation:false. The new gate is exercised against the actual observed
AppArmor+builtin-seccomp+cgroupns daemon and docker-default container profile.
No subsequent implementation source changes. Controller records attempt5 and
cleanup in its independent evidence; implementer does not edit that evidence.

FD/unsafe/subprocess inventory is unchanged (15 private production descriptors,
zero unsafe or production subprocesses, zero namespace entry/mutation/exec).
Revalidation adds a bounded native GET-only daemon query and retains a private
profile enum, no extra persistent descriptors. All original task6b/runtime,
trusted-root concurrency, no-AppArmor kernel, unsupported layouts and release
acceptance limitations remain. Independent scoped re-review is controller-owned
and not claimed completed by this report.
