# Task 9 implementation report

Status: OFFLINE_PREPARATION_ONLY. No activation/runtime acceptance. Task8c
I9/I10/M2 witness gaps and runtime/ARM/client acceptance remain OPEN. Work is
uncommitted for controller review; no git commit/push/staging was performed.
Base: `rust/v2` at `0b52bfd60de6db7d5d4dadc55e1b1ed02131b1ec`, initially clean.

## Intended file list

- `crates/vprouter-core/src/lib.rs`
- `crates/vprouter-core/src/config.rs`
- `crates/vprouter-core/src/allocation.rs`
- `crates/vprouter-core/src/transaction.rs` (new)
- `crates/vprouter-core/src/fleet.rs` (new)
- `crates/vprouter-core/tests/support/mod.rs` (new)
- `crates/vprouter-core/tests/transactions.rs` (new)
- `crates/vprouter-core/tests/fleet.rs` (new)
- `crates/vprouter-core/tests/fleet_owned_guest.rs` (new)
- `docs/rust-v2/multi-exit-preparation.md` (new)
- `.superpowers/sdd/rust-v2/task-9-report.md` (this report; existing .gitignore
  excludes `.superpowers`, so controller publication requires explicit force-add)

Cargo manifests/lock, native-role/Linux/launch/network/netfilter/worker runtime,
CLI, acceptance ledger, controller progress, production and credentials unchanged.
Ignored build/check logs live under `target/task9-checks/` and are not publication
inputs or runtime evidence. No subagents, sudo, VM/QEMU/lab execution or external
network/provider/Tailscale operations were used.

## Reviewable increments (suggested commit boundaries; no commits made)

1. **Configuration and atomic preparation transactions.** Strict bounded JSON
   add/remove/enable/disable and explicit pin_server over existing schema2, full
   profile/key validation including disabled members, stable allocation
   reservations and all-hostname reconciliation. Duplicate node selection across
   exits also refuses. Existing naming is reused, including stable-ID suffix on
   every collision and DNS<=63 rejection without truncation. Single-exit planning
   reserves only its configured exit. Synthetic distinct device keys may share
   provider endpoint and inner /32; transport /30 collision remains refused.
   Existing root-owned AllocationStore/flock/FD checks and atomic writer are
   extended rather than forked. One preparation bundle atomically commits both
   configuration and matching allocation snapshot, using generation plus prior
   canonical-record SHA256 CAS. Live allocations.json refuses preparation writes.
   Temps remain untouched; malformed commits refuse; reopen sees complete old
   or new bundle. Removal has no credential/state filesystem operation.
2. **Independent offline lifecycle/deadline policy.** Reuses core HealthMachine,
   Binding/Snapshot/HealthMessage/Session and existing worker cadence/retry
   contracts. Up to five enabled slots; disabled identities remain reservations,
   absent/disabled exits have no machine/session/deadline. Opaque correlation
   tokens bind policy instance/exit/epoch. Strict public binding, node/lifecycle
   uniqueness, generation/config fingerprint/name/server/boot validation precede
   scheduling. Session validation and independent reconstructed recovery streaks
   prevent received READY flags from authorizing readiness. Failure/malformed/
   wrong-binding/replay/expiry blocks only the selected exit. Cleanup ambiguity
   is terminal; container failure/90s watchdog/clock failure requests emergency
   quarantine and stop for all active exits. Late callbacks cannot weaken it.
   No I/O/await in poll; inspect all enforcement deadlines before sample work.
   Five-second stable staggering, no overlapping samples or catch-up bursts;
   whole-sample34s deadline, existing44s health margin and handshake<180s.
   Eligible single retry after1s/fresh audits remains the reviewed worker's job;
   this policy does not retry whole failed samples or create provider clients.
   Explicit fresh-lifecycle restart invalidates old tokens. Retired lifecycle
   history caps at1024; exhaustion refuses restart and retains blocked state.
3. **Evidence boundary and acceptance specifications.** Document APIs/limits and
   retained gates; add four ignored, fail-if-forced owned-guest specifications.
   Native launch, retained quarantine, no-fork secret loading and namespace-local
   socket authority remain in existing reviewed crates. No native executor,
   placement constructor, privileged syscall/unsafe/module, CLI activation flag,
   optional verification boolean, direct mode or provider/server fallback added.

## Test-first development inventory

All build/test commands used `CARGO_BUILD_JOBS=4`, `--locked --offline -j 4`.
Formatting uses `CARGO_BUILD_JOBS=4 cargo fmt --all` (cargo-fmt does not accept the
build flags). Commands below are exact, from the repository root.

- `cargo test --locked --offline -j 4 -p vprouter-core --test transactions`:
  initial exit101, absent transaction module (test-first API compile failure,
  not a behavioral RED). One implementation compile iteration exit101 for a
  partially moved enum was corrected. Then exit0/3 tests; after added pin/name/
  record/identity cases exit0/5 tests. The reader uses only committed synthetic
  example bytes, with parser validation retained; no credentials are read.
- `cargo test --locked --offline -j 4 -p vprouter-core --lib preparation_`:
  initial exit101, absent read_preparation/commit_preparation APIs; then exit0,
  2 tests. Real temporary-file commits/reopens test generation/content CAS,
  orphan partial temp preservation, no live-allocation file creation, existing
  live-allocation refusal, malformed committed file and symlink refusal without
  repairing or touching foreign bytes. These simulate write interruption, not
  SIGKILL/power-loss durability. Existing lock/permission/hardlink tests also run
  in final full suites.
- `cargo test --locked --offline -j 4 -p vprouter-core --test fleet`:
  initial exit101, absent fleet module; first implementation exit101/4 pass and
  1 fixture failure because disabled config correctly changed its fingerprint.
  Fixed fixture (production fingerprint validation unchanged): exit0/5 tests;
  expanded final focused result exit0/9 tests.
- `cargo test --locked --offline -j 4 -p vprouter-core --test fleet repeated_restarts_have_a_finite_memory_budget`:
  behavioral RED exit101 (restart1024 wrongly accepted); bounded-history fix,
  full fleet suite exit0/8 tests.
- `cargo test --locked --offline -j 4 -p vprouter-core --test fleet late_cleanup_and_cancel_cannot_weaken_container_emergency`:
  behavioral RED exit101 (late cancel changed FAILED to STOPPING); terminal
  callback guard fix, full fleet suite exit0/9 tests.

Focused fleet cases include independent READY recovery for five synthetic
bindings, scoped crash/malformed/cross-exit message refusal, foreign-instance
and stale-epoch tokens, premature READY rejection, handshake deadline, stale
health, watchdog, blocked-provider scheduling isolation, cadence/no overlap,
observational status, disabled/absent slots, terminal cleanup, cancellation,
fresh-lifecycle restart and bounded restart history. Existing worker tests
provide actual loopback retry timing/fresh structural checks and cancellation;
policy unit tests cannot prove native enforcement or process isolation.

## Final validation

Completed by the controller (the implementer's provider session died with a
409 `unsafe_affinity_unavailable` error just before this section; the work tree and
report survived). All from the repository root with `CARGO_BUILD_JOBS=4`, logs in
ignored `target/task9-checks/`:

| Command | Exit | Result |
| --- | --- | --- |
| `cargo fmt --all -- --check` | 0 | clean |
| `cargo clippy --locked --offline -j 4 -p vprouter-core --all-targets -- -D warnings` | 0 | clean |
| `cargo test --locked --offline -j 4 -p vprouter-core --all-targets` | 0 | all pass |
| `cargo test --locked --offline -j 4 --workspace --all-targets` | 0 | 449 passed, 0 failed, 6 ignored |

x86_64-musl tests and ARM64 build/link were NOT run for this increment (host
memory budget: nested guest ~5.7 GB with other projects' cargo jobs competing);
this change touches only `vprouter-core` and adds no native/privileged code.

## Review round 1

The independent review in `task-9-review.md` failed with Important findings I1
and I2. That review is retained unchanged. This round changes only
`crates/vprouter-core/src/fleet.rs`, `crates/vprouter-core/tests/fleet.rs`,
`docs/rust-v2/multi-exit-preparation.md` and this report; all other pre-existing
Task9 work is preserved. No staging, commits, pushes, subagents, sudo, network
or VM operations were performed.

**I1 — host-clock callbacks.** One monotonic host-time high-water mark now covers
`observe`, `observe_bytes`, `sample_finished`, `restart` and `poll`. Validation
precedes token/transition checks and wire decoding, so a malformed frame cannot
bypass host-clock enforcement. NaN, infinities, negative or regressing host time
enters terminal fleet emergency, retaining one emergency-quarantine-and-stop
action per enabled exit. Late observations, completion, restart, worker failure,
cancel and cleanup callbacks cannot downgrade FAILED or re-arm drained emergency
actions. Constructor time still refuses invalid input before a fleet exists.
Status/deadline queries remain observational; worker evidence timestamps remain
separate per-exit input. `last_poll` remains a separate enforcement-watchdog
anchor: observations do not renew it. Existing READY fixtures now interleave
all exits at each host instant instead of rewinding host time for each exit.

**I2 — skipped in-flight cadence.** Successful completion discards all elapsed
cadence slots while preserving the existing stagger phase. A completion exactly
on a slot may dispatch at that slot. The single-exit reproduction now emits no
sample at9.999s and resumes at10s; five READY exits demonstrate that a sample
spanning three missed ticks resumes at its next stable slot, with each of the
other four exits sampling at least three times and remaining READY.

Tests were written and executed before production fixes. Eight new behavioral
tests cover the two reviewer reproductions, completion before the last poll or
sample start, NaN completion, invalid times at all five entry points, a6x5
cross-callback/exit high-water matrix (including malformed bytes), terminal late
callbacks, observational status and independent watchdog controls, and one/five
exit no-burst scheduling. Six tests failed on requirement assertions before the
fix; the two status/watchdog controls passed. All eight passed after the fix.

Commands ran from the repository root. Build/test/clippy invocations use
`--locked --offline -j 4`; cargo-fmt does not accept these build flags. Build
and test invocations were run sequentially. Logs are under ignored
`target/task9-checks/review-round-1/`:

| Phase | Exact command | Exit | Result / log |
| --- | --- | --- | --- |
| RED, before production fixes | `cargo test --locked --offline -j 4 -p vprouter-core --test fleet review_` | 101 | 6 assertion failures, 2 passing controls; `red.log` |
| GREEN, after production fixes | `cargo test --locked --offline -j 4 -p vprouter-core --test fleet review_` | 0 | 8 passed, 0 failed; `green-focused.log` |
| Final core | `cargo test --locked --offline -j 4 -p vprouter-core --all-targets` | 0 | 81 passed, 0 failed, 4 ignored; `core-all-targets.log` |
| Final format | `cargo fmt --all -- --check` | 0 | clean; `fmt-check.log` |
| Final clippy | `cargo clippy --locked --offline -j 4 -p vprouter-core --all-targets -- -D warnings` | 0 | clean; `clippy.log` |
| Final workspace | `cargo test --locked --offline -j 4 --workspace --all-targets` | 0 | 457 passed, 0 failed, 6 ignored; `workspace-all-targets.log` |

The workspace test was the last Cargo invocation. Final `git diff --check`
also passed (exit0). All reviewed pre-existing inputs outside the four files
owned by this round retain their original review-recorded hashes. The unchanged
review SHA256 is
`c8e90cd4198640e12dacb7fdedc569317622b17365f3d249c7a3e48e25a9ba10`.

Final source and retained local evidence SHA256 (paths relative to the repo;
log names below are under `target/task9-checks/review-round-1/`):

```text
406952e435942c8bfbb9f8f6fa6bea0ecb5056179fa3ff1a4a6a9633494d235f  crates/vprouter-core/src/fleet.rs
2980cdd9360c94ec543b9988916b80abec3effa9ddf7185ee294f2c04ba8c9ab  crates/vprouter-core/tests/fleet.rs
e418410bfbec81805b73e941988fd175c6d41b734d563a3e6a4093f43b18fe05  docs/rust-v2/multi-exit-preparation.md
2a6a65d9bf5f08972a888ef27b7d252e1f9000c9ede631b3e7a99d6c19fa06e4  red.log
51b80ba041b57c86ec43c246fb605e85ee69903b9a5c6b3657dd60accead5386  green-focused.log
fedd3c22329d43a62d9202fd561e1715b176b4c8c1bc0cb00fa74c1a26d1847b  core-all-targets.log
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  fmt-check.log
8cdb343a5939a266d92f4651ba563a3507869a441aa7d16c9b8007e77b27586b  clippy.log
cc4c86c19707a21cdbf123b9a3357938d5f36475df263a254a0b4638469200de  workspace-all-targets.log
```

These are source/offline policy results. Native enforcement, real clients,
owned-guest/ARM/runtime, migration, performance and release gates remain OPEN /
NOT_RUN as described below; no activation or runtime acceptance is inferred.

## Explicit NOT_RUN and open risks

`crates/vprouter-core/tests/fleet_owned_guest.rs` has four `#[ignore]` acceptance
specifications with explicit NOT_RUN reasons, each deliberately panicking if
forced. They are requirements placeholders, **not implemented native harnesses**:

- `owned_guest_one_exit_no_absent_allocations` — one gateway/host guard, exact
  primary base netns, continuous markers/independent capture positive controls,
  no absent runtime allocations.
- `owned_guest_five_exits_shared_endpoint_overlapping_inner_ips` — five distinct
  synthetic keys sharing endpoint and inner address, independent positive
  captures/zero drops/zero cross-exit or plaintext markers, healthy exit invariance.
- `owned_guest_every_exit_private_proc_state_root_socket_and_namespace_fds` —
  all ordered exit-pair adversarial proc/root/state/socket/namespace-FD attempts
  with positive own-scope controls before/after exec.
- `owned_guest_faults_quarantine_only_owned_scope_and_retain_ambiguity` — actual
  crash/freeze/restart/stale/wrong-server/handshake, interface/route/rule/nft drift,
  gateway kill and Docker/API failures, interrupted transactions, foreign
  sentinels, exact-owned cleanup/refusal and retained quarantine with captures.

These are NOT_RUN because the Task9 brief is PREPARATION ONLY, single-exit Task8c
acceptance is incomplete, no admitted multi-exit native harness exists, and this
delegate is explicitly forbidden to use privileges/VMs/labs or credentials.
Root/controller alone can design/admit/run later tests after dependency review.
No actual scoped kernel evidence was collected in this task. All real-client,
Mullvad/Tailscale provider, DNS/IPv6/leak, ARM64 kernel/runtime, migration,
performance/overhead, reboot, fault, platform and soak/release gates remain open.
`release_ready=false` is unchanged; no runtime acceptance is claimed.

Public expected bindings and actions are data; policy READY is synthetic policy
state, never retained native authority. A future independent enforcer must apply
quarantine before work, retain verified per-exit authority and generation locks,
prevent dispatch starvation across blocked native calls, perform exact-owned
cleanup, and preserve primary gateway compatibility. This package contains no
such driver, no native journal recovery/import of the preparation snapshot,
no native hostname reconciliation and no CLI/service activation. A malicious
privileged writer/forged public bindings are outside offline validation's proof.

## Spec-resolution notes

- The brief's dependency gates restrict this increment to offline libraries and
  policy. No full multi-exit integration is represented as completed.
- Binding existing schema requires a nonempty configured fleet. Removing the
  final exit refuses; disabling it yields zero enabled slots without changing
  schema. Dangling client-policy removal also refuses rather than silently
  editing client selections. Future native stopped reconfiguration/name changes
  require independent reviewed authority, never caller proof booleans.
- Preparation uses an isolated atomic bundle instead of updating live config
  and allocation files separately. Existing runtime never consumes this file;
  live allocation stores refuse its writes. This avoids a partially applied
  two-file runtime transaction or an implicit activation bypass.
- Required `site=debdev` is used in fixtures; shared schema site rules remain
  unchanged. Direct/mixed documents continue to validate through existing
  general APIs but the new Task9 policy/transaction API refuses them.
- `docs/progress.md` is absent. Platform evidence was read from the required
  `.superpowers/sdd/rust-v2/progress.md` tail and existing reports: ARM64 build/
  link was previously done. Cross checks here are compile/link only.
- Initial ancestor-instruction lookup accidentally used overly broad
  `find .. -name AGENTS.md -print`, listing sibling pathnames and permission
  errors. No sibling file contents, credentials, or production state were read;
  subsequent reads/writes stayed within the assigned repo and skill/memory paths.

## Review round 2 (controller)

`task-9-rereview.md`: I1/I2 confirmed fixed; one Minor (M1: late `cancel` overwrote a
scoped FAILED exit's state/reason, `fleet.rs` cancel). Fixed by the controller:
`cancel` now keeps a FAILED exit FAILED (still revokes the session and requests
quarantine-and-stop); regression `late_cancel_cannot_downgrade_a_scoped_failed_exit`
(fleet suite 18/18). fmt, strict clippy and `-p vprouter-core --all-targets` re-run
clean after the fix. Task 9 remains an OFFLINE_PREPARATION_ONLY policy/transaction
layer: no native multi-exit runtime, no owned-guest tests run (NOT_RUN), no runtime or
release acceptance.
