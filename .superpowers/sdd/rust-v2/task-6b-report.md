# Task 6b implementation report

The initial candidate 20 report is retained below. The appended round 1 review-fix
report supersedes its source/test identities and signal-forwarding/reaping claim.

Status: DONE_WITH_CONCERNS. Exact candidate 20 passed the controller's isolated
kernel smoke test; the 19 earlier failed attempts remain preserved. Independent
review of the final diff remains controller-owned and pending.
This report is not release acceptance or production activation authorization.

## Scope and authority

Worktree `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`; reviewed task6 base
`c4b2236748c737837d5b613e2020cb4c4239cbcb`. Implementer never ran the privileged
harness locally, touched production runtime, read real state/profiles, enrolled a
device, or created a usable network path. Controller alone runs exact static
artifacts inside the owned disposable Debian 13 guest. Controller-owned attempt
records and cleanup evidence are in `docs/rust-v2/launch-execution-lab-evidence.json`
and `target/lab-state/launch-execution-run-N.json`. Historical failures remain
evidence; later code does not overwrite them.

The production staging decoder still returns `launch_unavailable`, public
`Admission::launch` always refuses, compatibility CLI remains GET-only with
`guard_runtime:false`, and no production program constructor, feature, caller
boolean, arbitrary binary/argv/environment or activation switch was added.

## Implemented boundary

- Private allocation-locked namespace records bind the entire allocation,
  generation, exact exit, explicit immutable primary exit ID, admitted base-netns
  dev/inode and every data/transport identity. Root mode 0700 directory and root mode 0600
  exclusive records/pins are verified descriptor-relatively. Creating state and
  interrupted temporaries stay offline; no generic cleanup/adoption-by-prefix.
  Reopening enters a verified pinned namespace then reopens the direct proc-netns
  FD before restoring the original network namespace. Primary data preserves the
  admitted gateway base network; extra data/all transport namespaces are distinct.
- Minimal core `AllocationTransaction::verify_directory(BorrowedFd)` binds the
  retained ownership directory to the actual locked store by device/inode,
  protected mode/type/owner; it exposes no raw store/lock descriptor. Internal
  thread-local RAII registration binds exact retained FD numbers, identity/type
  and CLOEXEC. Unknown directories, peer netns duplicates and sockets fail before
  fork; there is no caller-supplied allowlist.
- Private fixed test program admission binds artifact digest and actual compiled
  probe AND wait-role BPF instruction bytes plus fixed UID/GID/LSM/env/resolver
  policy into the protected staging policy hash. Its only constructor is cfg(test).
  Revalidation creates/drops a current-thread native API runtime before namespace
  entry and verifies exactly one OS task at fork/exec boundaries.
- Actual child cgroup placement is gated: forked child cannot enter/exec before
  host cgroup.procs placement, host proc/cgroup checks, fresh admission and locked
  allocation checks succeed. Failed placement kills/reaps without release.
  Test-only killed-child fault leaves the PID unreaped until the actual failed
  write and normal cleanup, preventing PID reuse during the fault.
- Mount trees are detached with maintained safe rustix open_tree/move_mount:
  selected state in its host owning namespace, verified executable after entry
  into its admitted container mount namespace and before private unshare. There
  is no source-path fallback. Private PID1 is nested under admitted Docker PID
  namespace. Private mount root contains only fixed executable, private procfs,
  selected worker-state directory and fixed test resolver; original root is
  pivoted out/detached, mounts recursively private, root read-only.
- Each surviving outer/intermediate wait role also gets its OWN empty private
  readonly tmpfs root/cwd, no proc/state/old-root and no host authority descriptor.
  Fixed null stdio and exact child pidfd3 are its final inventory. Retained parent
  pidfd is checked after identity changes re-arm PDEATHSIG, then closed. Separate
  wait BPF forbids paths, namespaces, network, fork and exec. Its only prctl is an
  exact 64-bit PR_GET_SECCOMP query for post-install verification.
- PID1/worker/wrappers establish exact docker-default AppArmor and manifest-bound
  seccomp; host namespace entry never counts as inheriting Docker confinement.
  All IDs are 65534, supplementary groups empty, effective/permitted/inheritable/
  ambient/bounding caps zero, securebits0xef locked, no_new_privs=1. Identity changes
  re-arm parent-death protection; pinned parent liveness is checked before closure.
- Worker has fixed argv `vprouter-worker --isolated-probe`, exact env LANG=C and
  PATH=/bin, null0..2, health pipe3 and CLOEXEC executable4 consumed by execveat.
  Null identity uses actual character-device/rdev1:3 plus retained inode provenance,
  not rendered path strings. Exact pre/post-exec FD numeric sets are verified by
  explicit native openat/getdents, avoiding both musl and Rustix x86_64 `open`'s
  denied legacy SYS_open. Every filtered status/label/resolver/state file operation
  likewise uses explicit bounded openat and owned-file read/write. Binary oracles
  established actual x86_64 libc behavior; API names were not syscall proof.
- Readiness requires post-exec worker verification, confined PID1 AND both
  reduced wait-role messages. Fixed error enums only cross health pipe. After FD
  closure all paths `_exit`, never unwind into inherited FD owners. Synchronous
  blocked signals forward TERM/INT/HUP; PID1 reaps, bounded escalation kills frozen
  descendants; pidfds/PDEATHSIG and private-PID1 death bind child/container loss.

## Verification

Final executable source commit:
`bff77724213f0c275ecc1b1b119a3fcb605871fe`.
Final documentation/report changes do not alter that source or either payload.
The `file` command independently identifies both payloads as statically linked
ELF64 x86-64 executables; final SHA256 rechecks match the controller-run values.

All final ordinary commands below passed against that exact source:

- `cargo fmt --all --check`: clean.
- `cargo test --workspace --all-targets`: 109 passed, 0 failed, 2 explicitly
  ignored Rust kernel tests. Three standalone admission/execution/probe entrypoints
  safely printed ignored notices; no privileged local harness ran.
- `cargo clippy --workspace --all-targets -- -D warnings`: clean.
- `cargo check -p vprouter-launch --lib --target aarch64-unknown-linux-musl`:
  passed; ARM64 runtime remains NOT_RUN.
- Both exact static release builds below passed. The workspace test/clippy/ARM64
  checks afterward did not overwrite the release payloads.

| Static x86_64 musl artifact | SHA256 |
| --- | --- |
| `target/x86_64-unknown-linux-musl/release/deps/execution_lab-4bd2e8f5005f802d` | `a49a89a3e5db007e20242615422fed039f06bdf7e9dd32a33e324b9285e38be8` |
| `target/x86_64-unknown-linux-musl/release/deps/execution_probe-1a715b67f9c47d78` | `7c6a7d16c02a48963dfbe79babbc353d46d37c78c2202dd28f85cd82ab42ae1c` |

Controller run 20 at `2026-10-24T14:20:51.053726+00:00` bound that exact commit and
both hashes: exit code 0 in 2.187 seconds, all 11 cases PASS including terminal
isolated acceptance.
The controller independently verified zero launch-lab containers and zero owned
namespace pins afterward. Harness self-cleanup completed without controller
deletion. Evidence result is `PASS_PARTIAL_SMOKE`; release acceptance is NOT_RUN,
`guard_runtime:false`, `activation:false`, `production_changes:false`.

The 11 cases cover locked primary/extra namespace ownership; wrong selected-exit
token rejection; unexpected host directory/peer namespace/socket rejection;
killed placement-gated child never released/executed; actual cgroup/private PID/
proc/root/state/FD/cap/seccomp/AppArmor; post-exec adversarial proc-root/two-exit
isolation; every surviving wrapper's empty readonly root/cwd/exact pidfd/null/IDs/
caps/LSM/seccomp; signal forwarding/PID1/frozen descendant reaping; launcher loss;
container loss; and final ownership-safe cleanup/terminal acceptance.

Exact commands:

```sh
cargo fmt --all --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo check -p vprouter-launch --lib --target aarch64-unknown-linux-musl
cargo rustc -p vprouter-launch --release --target x86_64-unknown-linux-musl --test execution_lab -- -C relocation-model=static
cargo rustc -p vprouter-launch --release --target x86_64-unknown-linux-musl --test execution_probe -- -C relocation-model=static
```

Meaningful offline tests cover manifest/policy binding, interpreter-verifiable
network/namespace/privilege/clone/architecture denials, exact wait-role post-install
syscall sequence and forbidden prctl mutators, unknown FD authority, exact primary/
base/generation/member/interruption records, and locked-directory substitution
or permission drift. Existing task6 tests retain process/root/cgroup/ELF/hash/
manifest/daemon-profile rejection coverage. No new TDD mandate was present;
kernel failures and each correcting exact payload are retained in controller
evidence rather than described as passing tests.

The execution harness additionally proves selected worker /state dev/inode equals
its selected host directory (so swapped exit mounts cannot pass identical marker
checks), distinct roots, nested PID parent, private proc numeric visibility,
post-exec credentials/env/FD/LSM/seccomp/network denial, entire-cgroup wrapper
root/cwd/mount/cap/FD inventories, signal/frozen-child reaping, launcher loss and
Docker kill. An actual case PASS requires its fixed case result in controller
output; unvisited cases remain NOT_RUN. Overall smoke PASS additionally requires
the terminal acceptance case, exit code 0 and independent absence-of-residual checks.
Attempts 18/19 reached ten case PASS results but failed overall cleanup.

## Retained failed iterations

| Attempt | Code | Observed failure / implication |
| --- | --- | --- |
| 1 | e9e5a47 | mount_isolation; namespace ownership passed |
| 2 | 5c495a0 | mount_isolation, fixed setup diagnostics |
| 3 | 1440fcb | mount_executable |
| 4 | 051c40f | executable bind EINVAL: source mount belonged another namespace |
| 5 | 041806d | executable clone before source-owning mount namespace |
| 6 | 9785b7c | descriptor_policy after detached mount transfer succeeded |
| 7 | 56fcb5c | descriptor_stdio: old-root detach changed rendered null path |
| 8 | df4716e | descriptor_inventory after inode-bound null fix |
| 9 | 8f8afd1 | confinement_policy; killed placement-gated-child check passed |
| 10 | e1f5b41 | wait_filter: verification PR_GET_SECCOMP itself was denied |
| 11 | e473304 | descriptor_scan_denied; binary oracle confirmed musl SYS_open |
| 12 | 2a38658 | mount_isolation after native openat scan succeeded |
| 13 | 775af5c | mount_isolation outside the newly instrumented probe checks |
| 14 | 3a49908 | descriptor_scan_denied: Rustix open uses SYS_open on x86_64 |
| 15 | e515c86 | capability_policy after scan succeeded |
| 16 | f5503e1 | probe_after_exec status_read: std File::open uses musl SYS_open |
| 17 | 98176e7 | exact probe_proc_hidden_init: visible PID set was only self2 |
| 18 | f803f5b | ten execution/lifecycle cases PASS; cleanup ownership_mismatch |
| 19 | 97fd1b8 | ten execution/lifecycle cases PASS; exact first-data-pin unmount busy |
| 20 | bff7772 | all 11 cases PASS, exit code 0, exact self-cleanup plus independent zero residuals |

Full commit IDs, artifact hashes, stdout/stderr, timestamps and cleanup records
remain in controller evidence; the table is a navigation aid, not a replacement.

Two substantive self-review corrections are deliberately recorded. First, PID1
and its intermediate initially shared a mount namespace after fork; PID1 could
pivot/detach the intermediate's old root before that wrapper unshared. PID1 now
unshares its mount namespace before ANY init-root mutation, with no scheduling
sleep. Host proof requires all six wrapper/init mount namespaces and roots
distinct, with each worker sharing its own private PID1's exact root/mount/PID
identity. Second, hidepid=2 intentionally hides nondumpable PID1 even from same
UID65534. Exact observed self-only set in attempt 17 justified controller ruling:
require ownPID2 and exactly {2} or {1,2}, reject every other visible PID; every
accessible visible root must equal own dev/inode or fail with explicit
PermissionDenied. Host separately proves actual private PID1 NSpid1 exists with
the selected root/mount/PID namespace. No hidepid/dumpable/LSM policy was loosened.

Preflight enumeration now excludes only its exact owned temporary scan FD and
fails on every other observation error. A regression proves a disappeared real
high-numbered FD is an error, never silently ignored via Path::exists. Death
checks likewise accept explicit NotFound only and reject ambiguous metadata errors.

The final cleanup correction drops only the exact validated local proof FD after
pin dev/inode and zero-live-user verification, before normal umount2. That FD had
itself retained the bind mount and caused attempt 19 EBUSY. Locked root mode 0700
directory/name ownership remains held. No lazy detach, force unmount, generic
namespace cleanup or alternate-path fallback was added.

## Unsafe/syscall and subprocess inventory

`kernel.rs` is the sole allowed-unsafe module under library deny(unsafe_code).
Other implementation modules forbid unsafe. Safety contracts require one OS
task, no runtime, live pinned borrowed FDs, fixed strings and initialized buffers,
exclusive child descriptor tables, and `_exit` after closure/failure. The module
is large (2166 lines including BPF and test helpers); its focused internal
roles are a review concern, not permission for an unplanned restructuring.

Raw operations: fork/clone(test-only fixed SIGCHLD), pipe2, pidfd_open/
pidfd_send_signal, bounded poll/read/write, waitpid, _exit, signal masks and
sigtimedwait, private-namespace kill(-1), fcntl/dup3/close/close_range, unshare,
mount/pivot_root/umount2/chroot/fchdir/chdir, prctl securebits/cap bounding+ambient/
NNP/PDEATHSIG/dumpable/seccomp, setgroups/setresgid/setresuid, capset and fixed
execveat; test-only NS_GET_PARENT ioctl/socket-denial witness/exact unpin helpers.
Maintained rustix supplies namespace entry, namespace/proc file operations,
openat2, detached mount APIs, safe FD ownership and native directory enumeration.
No production shell, docker/ip/nsenter/kill subprocess or arbitrary-command API.
Only ignored test harnesses use fixed Docker argv to create/remove exact NEW
disposable resources from the pinned image. Root controller alone runs them.

## Changed files and final source identities

Implementer-owned source/lock changes relative to the reviewed task6 base are
listed below. `docs/rust-v2/launch-helper.md` documents the implemented boundary;
this report records verification. Controller-owned ledger, enrollment, oracle,
progress and later-task briefs are not implementer-owned changes. Source hashes
were read after final ordinary checks and match executable source commit bff7772.

| Source/lock file | SHA256 |
| --- | --- |
| `Cargo.lock` | `827410cab3f37d102c78eeebdbb2d7f3b9adf27e2e2c8de9698126b9b90cd0b6` |
| `crates/vprouter-core/src/allocation.rs` | `edf98a87ceb30d7864c661644a59812a3fbfb417022ab1064c4e8c5aaec3a0bd` |
| `crates/vprouter-launch/Cargo.toml` | `1904d4082558da83b2782c58db01b97aa7966071c64600e39094feea7f7ca71f` |
| `crates/vprouter-launch/src/evidence.rs` | `f2007fcd7683fc7620d1c510e0f4096fbcf346c697a406ae63145c24f8ff8d6b` |
| `crates/vprouter-launch/src/execution.rs` | `4742ace4473f53de368997b477117a061ef2362fa0e88e520f732aca55c93d46` |
| `crates/vprouter-launch/src/execution_lab.rs` | `50d1bf004b42e6c2b1d2206ec98115eb3b484d79ddf7e57f6fc00a9ff03a4773` |
| `crates/vprouter-launch/src/execution_lab_main.rs` | `caf5305fceadfb58299dde0dcd5c757cf1d99cc2ff3b734fdbf19b76f1e0de6e` |
| `crates/vprouter-launch/src/execution_probe_main.rs` | `89691e65977ea801e935d807e9d17afdb67caac8157668c8a7db3d8ca5df7b6a` |
| `crates/vprouter-launch/src/inventory.rs` | `c6f714bab70943cb5156014546fc16e75dde2f56bea8da1fa12ca7b60c8bee07` |
| `crates/vprouter-launch/src/kernel.rs` | `22f55e738bf728323a4ffca08285ddde27b433b897972b1a5662cb7c39b6bf65` |
| `crates/vprouter-launch/src/lab.rs` | `ed3951705d0174fbb9d38c48f666fc60146ab5fb52a9dc991ee3e884c8b9a98d` |
| `crates/vprouter-launch/src/lab_main.rs` | `9631045f77b661f91a140360054e21e0441894a80c4046fefef3b0e5d57883b8` |
| `crates/vprouter-launch/src/lib.rs` | `d4bf3d1f6396c8cf993ca15fbfe017eeafcf27ddaa1ea464e72eda0cccfa22de` |
| `crates/vprouter-launch/src/owned.rs` | `194872ab534829b49c4ccbbb5868baadad01ff39477067fec1a78bc19d76549d` |
| `crates/vprouter-launch/src/probe.rs` | `0f23c71a46083a2a1a4657baecc96d8993af5a598413a9596abc0acbf252e1d8` |
| `crates/vprouter-launch/src/process.rs` | `3c6337c208f7a04e1fb402a2635fd89f2344606da235912330da852832fefc3f` |
| `crates/vprouter-launch/src/spec.rs` | `c240cfa6a501ffa9b7aaa6c813886a5a9cf4e6fcaa3f5daab91a38d44e63a40e` |
| `crates/vprouter-launch/src/tests.rs` | `0cacb0f0540edbaccb9a406d68cb46298991dc63b276dc15c373a449f66dfc36` |

## Unperformed gates / known boundaries

- Genuine Rust worker and Go Tailscale artifact/policy integration, production
  resolver derivation, migration/state layout authority, independent host guard/
  quarantine/enforcement and activation remain unavailable. No successful status
  query is enforcement. Fixed192.0.2.53 resolver is test-only and unconnected.
- Mandatory docker-default plus zero caps is ONLY the synthetic TEST-PROBE
  profile, not final Debian/Arch/Void policy. No-AppArmor execution is unsupported;
  ordinary admission fixture coverage does not certify runtime execution.
- ARM64 library check/codegen is not ARM64 kernel runtime. Platform release matrix,
  real networking/client/traffic/kill-leak and end-to-end migration remain NOT_RUN.
- The allocation lock/records protect against ordinary races, not a malicious root
  operator/Docker daemon. Fresh identity checks cannot make inspect+kernel views
  atomic against privileged mutation after validation.
- Independent review of this exact final diff remains controller-owned and pending.

## Round 1 independent-review fixes (current implementation)

Status: DONE_WITH_CONCERNS; all three Important and both Minor findings in
`.superpowers/sdd/rust-v2/task-6b-review.md` have implementation changes and fresh
kernel evidence. Controller-owned independent re-review is pending. Reviewed
baseline was `6a2cbb30af1bf803aaf22a4bed80204b115b96e1`; current executable source is
`b62cc5c81b40151f9d85c8191400436612c5f56e`.

The historical 19 failures and candidate 20/run 20 output remain preserved. Run 20's
signal case used forced cleanup before disappearance checks, so its output did
not establish the claimed forwarding/PID1 reaping behavior. Run 21 replaces that
claim with the stronger witness and natural-completion checks below. None of this
is production, guard or release acceptance.

### Changes mapped to findings

1. **Strict close and PID1 final inventory.** `close_except` now uses explicit
   native openat/getdents, propagates every enumeration/numeric-parsing failure,
   rejects duplicate/missing scan entries and excludes only its exact owned scan
   FD. It collects a complete inventory before closing inherited entries. Every
   selected close is checked; Linux close errors are fatal without an unsafe
   retry of an already-consumed descriptor. PID1 independently scans immediately
   after closure and again after seccomp: exactly null stdio plus its retained
   health descriptor are permitted. Each stdio's retained device identity and
   non-CLOEXEC flags, and health FIFO type/CLOEXEC flags, are verified separately.
   Failed closure/inventory/confinement exits directly without dropping inherited
   FD owners; health close after readiness is checked too.
2. **Monotonic lifecycle bound.** Shared earliest-deadline logic takes the minimum
   of existing/new deadlines. Repeated TERM/INT/HUP cannot move it later, including
   after the immediate deadline from main-worker exit. PID1 gets 500 ms before
   escalation and 400 ms afterward; intermediate/outer wrappers get 1000/1500 ms
   before escalation and 1000 ms afterward. Ordering lets inner escalation/reaping
   finish before wrappers intervene. Synchronous wait errors, forwarding errors,
   poll invalid/error flags, escalation failures and waitpid failures are explicit.
   Only EAGAIN/EINTR for timed signal wait, ESRCH for no descendant targets, and an
   ESRCH plus actually-ready pinned child during forwarding are benign. Successful
   PID1 completion requires actual ECHILD after reaping the main worker; successful
   wrappers require their own direct child to exit normally with status 0.
3. **Unmasked guest signal proof.** Before signaling, the host polls actual
   protected proc status and requires exactly each worker's namespace-PID3 child
   to have State T (stopped). The fixed probe blocks shutdown signals before
   readiness, synchronously observes forwarded TERM and writes only the fixed
   `/state/forwarded-signal` marker. It remains alive alongside its frozen child,
   so worker default signal exit cannot hide a moved escalation deadline. PID1
   writes `/state/reaped-descendant` only after actual waitpid returns that extra
   descendant. The harness repeatedly delivers TERM/INT/HUP every 25 ms and requires
   both marker sets plus natural exit status 0 for both launch chains within a
   fixed 2 second total bound. It performs no forced termination on the success
   path; Child Drop/force cleanup is reserved for errors. Disappearance checks
   follow successful natural completion, rather than making force-kill success
   look like signal forwarding/reaping.
4. **Minor findings.** The crate summary now states public admission refusal and
   private synthetic staged execution accurately. Section boundaries identify
   namespace/mount setup, lifecycle, descriptor closure, identity/LSM, BPF, fixed
   exec, test-only helpers and offline regressions inside the sole unsafe module.
   No module split or broad restructuring was performed.

Changed owned files: `crates/vprouter-launch/src/{execution.rs,execution_lab.rs,
kernel.rs,lib.rs,probe.rs}`, `docs/rust-v2/launch-helper.md`, and this report.
`execution.rs` only adds a test-only safe natural-wait wrapper. Synthetic signal/
reap witnesses use already allowed signal-mask/timed-wait/openat/write operations;
no syscall list, BPF instruction policy, capability, UID/LSM policy, production
constructor or public activation path was widened. All unsafe stays in kernel.rs.

### Covering verification on exact source b62cc5c

The three added offline regressions are:

- `descriptor_scan_errors_and_malformed_names_are_fatal`: injects an iteration
  failure after valid entries, invalid UTF8/numeric/negative/overflow names,
  duplicate scan entries and missing actual scan FD; none can silently succeed.
- `descriptor_close_failure_cannot_reach_success_and_final_inventory_is_exact`:
  injects a selected-close error, checks immediate failure with no success path,
  verifies a real invalid-close failure, and rejects unexpected/missing PID1 FDs.
- `repeated_signals_never_extend_shutdown_or_worker_exit_deadline`: repeated later
  deadlines preserve the first, and later signals preserve an earlier worker-exit
  deadline. Fresh actual frozen-child execution is separately required below.

Commands/results (final outputs clean):

```text
cargo test -p vprouter-launch --lib
  18 passed; 0 failed; 0 ignored
cargo clippy -p vprouter-launch --all-targets -- -D warnings
  passed
cargo fmt --all --check
  passed
cargo test --workspace --all-targets
  112 passed; 0 failed; 2 ignored Rust kernel tests
  3 standalone lab/probe entrypoints safely skipped
cargo clippy --workspace --all-targets -- -D warnings
  passed
cargo check -p vprouter-launch --lib --target aarch64-unknown-linux-musl
  passed (ARM64 kernel runtime NOT_RUN)
cargo rustc -p vprouter-launch --release --target x86_64-unknown-linux-musl --test execution_lab -- -C relocation-model=static
  passed
cargo rustc -p vprouter-launch --release --target x86_64-unknown-linux-musl --test execution_probe -- -C relocation-model=static
  passed
```

The focused tests/clippy and both static builds preceded the fresh controller
run. After run 21 succeeded, full exact-source fmt/workspace tests/workspace
clippy/ARM64 checks passed. The release payloads were preserved; `file` identifies
both as statically linked ELF64 x86-64 executables, and final `sha256sum` checks
match the controller's payloads:

| Static payload | SHA256 |
| --- | --- |
| `target/x86_64-unknown-linux-musl/release/deps/execution_lab-4bd2e8f5005f802d` | `ccd0bcb8c75fc90d91b0bc7660e88828c36667d50a01d08fdc5eb520bc282fa9` |
| `target/x86_64-unknown-linux-musl/release/deps/execution_probe-1a715b67f9c47d78` | `808789d0d5d59b673c7f6fd55b306c3ecfc05ef0bbdd65731cff2ae7695bd828` |

Controller run 21 observed at `2026-10-24T14:32:50.384492+00:00` bound source
b62cc5c and both hashes: all 11 cases PASS, exit code 0, overall 1.648 seconds, including:

```text
LAB_SIGNAL_PROOF stopped_forwarded_reaped_natural repeated_signals elapsed_ms=529
```

The controller independently verified zero residual launch-lab containers and
zero owned namespace pins. Harness self-cleanup completed; the controller deleted
nothing. Full output/identities are retained in `target/lab-state/launch-execution-run-21.json`
and the committed controller evidence ledger. Result remains `PASS_PARTIAL_SMOKE`,
release acceptance NOT_RUN, guard_runtime:false, activation:false, production
changes:false. The implementer ran no privileged harness locally.

### Current changed-source SHA256 identities

These supersede the five corresponding candidate 20 source entries above; all
other implementer source/lock entries are unchanged.

| Source file | SHA256 |
| --- | --- |
| `crates/vprouter-launch/src/execution.rs` | `6c738894993c91342482aac45e485e244e26aed06dba64c46fb3eb34d897cfa1` |
| `crates/vprouter-launch/src/execution_lab.rs` | `ac6bf948e466de909691c57eae43493a243ec69d8ea35c7a0c864e07cfb42d52` |
| `crates/vprouter-launch/src/kernel.rs` | `3c0d3621f583d10ccce7e04cbde5c734d0d36852481fa4a354b3cca27350b833` |
| `crates/vprouter-launch/src/lib.rs` | `46899ccb7268871d470c6f2250159932194d96a4fdaffc7459beae910888f38d` |
| `crates/vprouter-launch/src/probe.rs` | `80e301163916f7e883de03f34ff5597852954273be67f3f0d36555c1271efcfc` |

### Remaining concerns and unperformed gates

The sole unsafe module is now 2439 lines including BPF/test helpers; sectioning
improves navigation but its size remains an independent-review concern. The
unsafe/syscall/subprocess inventory above still applies: no new privileged
syscall class or production subprocess. Re-review of 6a2cbb3..finalfixHEAD belongs
to the controller and is pending. ARM64 execution, final Debian/Arch/Void policy,
actual Rust worker/Go Tailscale artifacts and policies, production resolver/state
migration authority, independent guard/quarantine, usable networking/real-client
leakage and release acceptance remain unavailable or NOT_RUN. Public production
launch continues to refuse; ordinary tests and one successful synthetic kernel
run do not accept these later gates.
