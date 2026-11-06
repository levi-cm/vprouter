# Task 9 independent re-review

Verdict: **FAIL** — 0 Critical, 0 Important, 1 Minor finding.
**Previous I1 and I2 are fixed in the reproduced scenarios.** The remaining
failure is a per-exit terminal-state/diagnostic regression, not an established
quarantine bypass or path back to READY. FAIL reflects the requested preservation
of FAILED across late callbacks; it does not promote this Minor finding into a
runtime security failure.

Reviewed 2026-11-06, `rust/v2`, HEAD
`0b52bfd60de6db7d5d4dadc55e1b1ed02131b1ec`, including the uncommitted Task 9
files and report's “Review round 1”, against `task-9-brief.md` and
`docs/rust-v2/IMPLEMENTATION.md`. This is a bounded offline preparation-layer
review. No children, sudo, network, VM operations or Git writes were used.
Only this report was written in the repository. Source/input hashes and Git
status were checked against a baseline and remained unchanged.

## Finding

### M1 — Minor: late cancel overwrites a scoped FAILED state and its failure reason

Location: `crates/vprouter-core/src/fleet.rs:306`, specifically the unconditional
`exit.machine.stop()` at `fleet.rs:312`. The preceding scoped failure is created
by `cleanup_failed` at `fleet.rs:301`.

Reproduced with five synthetic READY exits at host time20:

1. `cleanup_failed(token_for_exit_1)` succeeds. Exit1 is
   `FAILED`, reason `AllocationConflict`.
2. `cancel(the_same_current_token)` succeeds. Exit1 becomes
   `STOPPING`, reason `Stopping`; the cleanup ambiguity is no longer reported.
3. A subsequent valid READY observation and explicit restart both refuse.
   `poll(25)` still emits `QuarantineAndStop` for exit1, emits no Sample for it,
   and exit2 remains READY.

The global `self.stopped` guard protects fleet emergency, but it does not cover
an individual exit already FAILED. The late callback therefore loses terminal
failure state and its diagnostic cause. Its reproduced impact is limited:
quarantine-and-stop remains requested, and no revival or peer impact was shown.
Retain an already FAILED exit's state/reason when handling cancel, as the scoped
block path already does. No source fix was made in this review.

Scratch test:
`sweep_failed_cleanup_cannot_be_downgraded_by_late_cancel` fails on the final
FAILED-state assertion, **after** checking the refusal/action/peer controls above.
Evidence: `/tmp/vprouter-task9-rereview.gte5c6oq/final-adversarial.log`.

## I1/I2 reproduction and fix confirmation

Reviewer-authored scenarios from the first review were copied into the new
scratch test, retaining the scenarios/assertions. Synthetic READY setup uses the
current chronological, fleet-interleaved helper; it does not rewind host time
between exits.

- **I1, NaN observation:** after five READY exits and `poll(20)`, a valid message
  observed with host `now=NaN` errors; `poll(21)` emits exactly five
  `EmergencyQuarantineAndStop` actions. Peer state is FAILED.
- **I1, backwards completion:** after `poll(20)` and `poll(22)`, completion at21
  errors; `poll(23)` emits five emergency actions. The old acceptance is gone.
- **I2, in-flight tick:** sample starts at0, remains in flight at5 and completes
  at9.999. Poll at9.999 emits no sample; next deadline is10. Additional fresh
  cases verify exact-slot completion and multiple skipped ticks through33.999.
- The original poll-clock terminal-emergency positive control passes too.

For a regression control, only the scratch `fleet.rs` was temporarily replaced
with the first review's retained pre-fix source, SHA256
`6c9129af31bbbed6c9d9bb58f7aceca92d3b0889185f73b97e026700e6dee993`.
The same original four tests then produced **3 assertion failures / 1 passing
control**, reproducing both original findings. A `finally` block restored current
source; its SHA256 was checked against the repository. The final scratch run
again passes all four original tests. No repository source was changed.

## Fresh adversarial sweep

Apart from M1, no additional concrete defect was established in this boundary.
These conclusions combine source inspection with the fresh core suite and named
scratch scenarios; they do not assert native enforcement.

- **Clock and emergency:** all timed entry points validate host time before token
  selection or wire decoding. Fresh tests use foreign-instance tokens, malformed
  bytes and invalid transitions to confirm neither error paths nor rejected
  callbacks bypass the high-water mark. Host NaN still fails the whole fleet
  with a foreign token. Late worker failure, cleanup, cancel, observation,
  completion and restart do not weaken or re-arm a drained fleet emergency.
  A far-future worker timestamp instead blocks its own exit and does not advance
  host time or fail a healthy peer. Status/deadline reads remain observational.
  Observations do not renew the separate enforcement-poll watchdog.
- **Deadlines/cadence:** fresh tests retain READY immediately before handshake
  expiry and withdraw exactly at180s; input handshake age180 refuses. Health
  withdraws at the existing44s session margin, before45s; the test avoids an
  in-flight timeout masking that boundary. Watchdog89.999999 does not enter
  emergency, while90 does. Sample completion33.999999 succeeds and34 refuses.
  Exact5/10s completion slots dispatch once; elapsed in-flight slots are skipped.
  The core five-exit regression also checks stable stagger resumption and peer
  progress. Poll has no I/O and emits all enforcement actions before samples.
- **Bounds/tokens:** at most5 active slots,128 configured reservations,1024
  retained lifecycle IDs, bounded wire/preparation files and at most10 actions
  per poll remain enforced. The core restart-exhaustion test passes. Fresh
  tests reject old-epoch cancel/cleanup/bytes/completion and reuse of both a
  retired lifecycle and another exit's current lifecycle. Token instance binding
  is checked by retained `Arc` identity, preventing allocator-address reuse
  while an old token remains alive.
- **Transactions/storage:** generation plus canonical-content CAS, exclusive
  flock, descriptor-relative NOFOLLOW access, ownership/private modes, single
  link count and exclusive temp creation remain intact. Fresh real-file tests
  reject a valid same-generation site replacement without overwriting it;
  reject hardlinked, mode0640 and symlinked preparation records on read and
  commit without repairing/changing the bytes; preserve an interrupted first
  temp while reopening a complete generation1 bundle; and refuse after16
  colliding temp symlinks without touching their target or committing a file.
  Core tests additionally cover live-allocation refusal, malformed records,
  lock exclusivity and interrupted subsequent writes. This simulates interrupted
  writes; it is not SIGKILL, disk-full, fsync-fault or power-loss qualification.
- **Validation/removal/naming:** validation completes before a PreparedFleet or
  policy can produce mutations/actions. Fresh tests refuse disabled duplicate
  effective keys and nested state paths, a known transport-pool collision,
  generation overflow and removal leaving a dangling client reference. Core
  tests cover duplicate IDs/nodes/bindings/foreign resources, shared endpoint
  and inner IP with distinct parsed keys, all-duplicate hostname reconciliation,
  explicit server pinning, exact63-byte names and suffix overflow refusal.
  Names use existing `mullvad-{site}-exit-{server}` rules without truncation;
  stable resources derive from deployment/exit IDs. A fresh removal test keeps
  synthetic profile, enrollment and identity sentinel bytes unchanged and
  preserves the retained peer's allocation; the removed profile is never read
  by the preparation callback. State-path checks are lexical; this layer does
  not claim filesystem-alias isolation or runtime identity custody.

No new unsafe code, native activation consumer, direct-mode/fallback path or
credential/state deletion operation was found. The ignored owned-guest tests
remain clearly labeled specifications which panic if forced, not native test
implementations or acceptance evidence.

## Verification ledger

Fresh Cargo invocations ran **sequentially**, compiled/tested only
`vprouter-core`, and used `CARGO_BUILD_JOBS=4` and
`CARGO_TARGET_DIR=/tmp/vprouter-task9-rereview.gte5c6oq/target`.
All build/test/clippy commands used `--locked --offline -j 4`. Formatting checks
workspace source without compiling it; cargo-fmt does not accept those flags.
Scratch copy: `/tmp/vprouter-task9-rereview.gte5c6oq/scratch`.
Logs below are under `/tmp/vprouter-task9-rereview.gte5c6oq/`.

| Location | Command | Exit / observed result | Log |
| --- | --- | --- | --- |
| Repository | `cargo test --locked --offline -j 4 -p vprouter-core` | 0; 81 ordinary tests + 1 compile-fail doctest passed, 4 ignored | `core-test.log` |
| Repository | `cargo fmt --all -- --check` | 0; clean | `fmt-check.log` |
| Repository | `cargo clippy --locked --offline -j 4 -p vprouter-core --all-targets -- -D warnings` | 0; clean | `clippy.log` |
| Current scratch, original reproductions | `cargo test --locked --offline -j 4 -p vprouter-core --test rereview_adversarial review_ -- --nocapture` | 0; 4 passed | `original-reproductions.log` |
| Pre-fix scratch regression control | Same original-reproduction command | 101; 3 failed assertions, 1 passed control | `original-prefixed-red-control.log` |
| Final restored scratch | `cargo test --locked --offline -j 4 -p vprouter-core --test rereview_adversarial -- --nocapture` | 101; 14 passed, only M1 failed | `final-adversarial.log` |
| Current scratch storage | `cargo test --locked --offline -j 4 -p vprouter-core --lib rereview_storage_ -- --nocapture --test-threads=1` | 0; 4 passed | `storage-sweep.log` |
| Repository | `git diff --check` | 0 | inspected output |

The earlier exploratory fresh sweep (`fresh-sweep.log`) gave7 pass/1 fail for
the same M1; the final suite adds transaction/removal controls and verifies M1's
continued quarantine/revival refusal before its assertion. Scratch allocation
production bytes match the repository; only a separate test module was appended.
Scratch fleet/config/transaction production sources match the repository.

### Retained workspace result: plausible, not rerun

Read `target/task9-checks/review-round-1/workspace-all-targets.log`, independently
summed its result lines to **457 passed, 0 failed, 6 ignored**, and checked its
SHA256 against the report:
`cc4c86c19707a21cdbf123b9a3357938d5f36475df263a254a0b4638469200de`.
Its per-core totals match the fresh run (81 ordinary passes/4 ignored; workspace
`--all-targets` omits the doctest). The retained core/fmt/clippy/red/green log
hashes also match the report. Current fleet source/test and preparation-doc
hashes match “Review round 1”; unchanged input hashes match the first review.
This supports the claimed workspace outcome as plausible local log evidence;
this review did **not** rerun the workspace or independently attest the prior
process exit or log provenance.

**NOT_RUN:** other-crate/workspace tests this turn; ignored owned-guest
specifications; native multi-exit enforcement/driver, actual namespace/process/
proc/root/state/socket/FD isolation, packet/capture and fault acceptance, provider
or real Tailscale clients, DNS/IPv6/leaks, ARM64/x86_64-musl cross-build/runtime,
migration, reboot, overhead/performance and soak/release gates. No runtime or
release acceptance is inferred, and the existing open gates remain open.

## Source/evidence binding

SHA256 of reviewed inputs, captured before checks and verified unchanged:

```text
6cdf6e1018dfe8e5d53fa72165c3661f943781c2ed9c42466a477b7b052f04ed  crates/vprouter-core/src/allocation.rs
c9b94b4b8a9c3372cadca95eaf547c5bdac039cd35eceb55c872d531e2057bb1  crates/vprouter-core/src/config.rs
e4acb6fcdaaa6596c120793d61166aa96698c28faf8695a9a3d6a1663f22f844  crates/vprouter-core/src/lib.rs
406952e435942c8bfbb9f8f6fa6bea0ecb5056179fa3ff1a4a6a9633494d235f  crates/vprouter-core/src/fleet.rs
a062b6d30b8688dcc6ada8eb3b83e568ec89b6b1d7b8d790758c9f59a627ec14  crates/vprouter-core/src/transaction.rs
2980cdd9360c94ec543b9988916b80abec3effa9ddf7185ee294f2c04ba8c9ab  crates/vprouter-core/tests/fleet.rs
702fabc99d422e89ad81552ed326bb32c8b483ea441cf3a6ec16ca5eb7600b04  crates/vprouter-core/tests/transactions.rs
de48613c91b565cae510d5708bacb72db175f0435273178073f0d6cd9c42f825  crates/vprouter-core/tests/fleet_owned_guest.rs
f4f50e22a8664abaa4705d4b8bc4b6d8312d96e45b908960ccaf7a787c9b8829  crates/vprouter-core/tests/support/mod.rs
e418410bfbec81805b73e941988fd175c6d41b734d563a3e6a4093f43b18fe05  docs/rust-v2/multi-exit-preparation.md
d3ea0d4fabe2cb8d5b51fe7a6b01e8a79efbb3a20fb203a0cc427c9d4e1efe13  .superpowers/sdd/rust-v2/task-9-brief.md
0b7d776f8c43e9328c31a7d7280aed9fe3b1d2f3b32895df3c2f3f7335f8790e  .superpowers/sdd/rust-v2/task-9-report.md
c8e90cd4198640e12dacb7fdedc569317622b17365f3d249c7a3e48e25a9ba10  .superpowers/sdd/rust-v2/task-9-review.md
353f0e82d9dcf7b3e1216c27ac4c505bdc8fa6ee06ee3e6b833f1d3e11594125  docs/rust-v2/IMPLEMENTATION.md
```

SHA256 of retained scratch evidence (relative to
`/tmp/vprouter-task9-rereview.gte5c6oq/`):

```text
37eeec7475a7cbc1495d001dfc2013fe7ada0acbffa14aedb04d530ad56de77b  core-test.log
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  fmt-check.log
08e03c31dd6a723ef491379cbecece6a2d2d1f3cf4d367746be76692c0a0067a  clippy.log
0ef881c222957169617d8c993e3473acef9ed7b4e0ea576d663d9fd26fd78729  original-reproductions.log
3b30a1adbeebc71b529d68f6e140f8a4b3b21e5a813b02ac04cc66ba05f05c5b  original-prefixed-red-control.log
77a3e3220a6c7c3b66374ef53ffefe977e1853109ab154d597c0b81f96642f86  final-adversarial.log
0749f6fec2cc14ab70073a0373efb38a9db49404525573f9900b771172aef2c0  storage-sweep.log
4413c689f533442766f4b4c882d08c0091681fcd4765ab6d1043a4c6473002d5  scratch/crates/vprouter-core/tests/rereview_adversarial.rs
d57ed12180509b2bbee1a2482a550587c13651793b02152339c165676868cf8d  scratch/crates/vprouter-core/src/allocation.rs
```
