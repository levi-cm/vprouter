# Task 9 independent review

Verdict: **FAIL** — 0 Critical, 2 Important, 0 Minor findings.

Reviewed on 2026-11-06 at `rust/v2`, HEAD
`0b52bfd60de6db7d5d4dadc55e1b1ed02131b1ec`, against
`.superpowers/sdd/rust-v2/task-9-brief.md` and
`docs/rust-v2/IMPLEMENTATION.md`. The implementation report was treated as
unverified. This verdict concerns the authorized bounded offline policy and
preparation transaction layer, not completion of native multi-exit integration.
No source fixes, staging, commits, network, sudo, VM operations or subagents.
The only repository write made by this review is this report.

## Findings

### I1 — Important: callback host-clock failures do not enter fleet-wide emergency

Locations: `crates/vprouter-core/src/fleet.rs:227`,
`crates/vprouter-core/src/fleet.rs:235`, and
`crates/vprouter-core/src/fleet.rs:346` (especially line 351).
The fleet-wide clock check exists only at `fleet.rs:360`.

The callback `now` argument is the host clock, distinct from the worker's
untrusted `sent_at`/evidence timestamps. `observe` handles an invalid host time
through the selected exit's machine/session and then `exit.block()`; it never
calls `container_failed`. `sample_finished` checks time against the sample start
and deadline but not the last enforcement poll.

Reproduced in the scratch copy with five synthetic READY exits:

- After `poll(20)`, `observe(valid_token, valid_message, NaN)` returns an error.
  The following `poll(21)` returns only one ordinary `Quarantine` action;
  exit 2 remains READY. No emergency actions are returned.
- After `poll(20)` starts samples and `poll(22)` checks them,
  `sample_finished(valid_token, 21)` returns **Ok**, accepting a host-clock
  regression. `poll(23)` emits another Sample for that exit and its peer remains
  READY, with no emergency actions.

This violates the requested fleet-wide emergency handling of host-clock failure
and the policy claim in `docs/rust-v2/multi-exit-preparation.md:84`. Malformed
worker timestamps should continue to affect only their own exit; these tests
instead vary the trusted host `now` argument. Centralize host-time validation
and a monotonic high-water mark across operational mutating callbacks, entering
and retaining the existing terminal emergency state when that clock fails.
Keep status queries observational.

Reviewer tests:
`review_nonfinite_host_observation_clock_must_quarantine_entire_fleet` and
`review_backwards_host_completion_clock_must_quarantine_entire_fleet` FAIL.
Positive control `review_poll_clock_failure_is_terminal_positive_control` PASS:
NaN supplied to `poll` produces five emergency actions and late cancel/cleanup
callbacks cannot weaken FAILED.

### I2 — Important: ticks missed during an in-flight sample are replayed on completion

Locations: `crates/vprouter-core/src/fleet.rs:355` and
`crates/vprouter-core/src/fleet.rs:393` (especially lines 399–400).

`next_sample` advances only when a Sample is dispatched. A poll while a sample
is in flight leaves an elapsed cadence tick pending; `sample_finished` merely
clears `in_flight`. The next poll dispatches that missed tick immediately.

Reproduced with one exit: `poll(0)` starts a sample; `poll(5)` sees it in flight;
completion at 9.999 followed by `poll(9.999)` starts a catch-up sample. Complete
that short sample at 9.9995 and `poll(10)` starts another. The last two sample
starts are **0.001 seconds apart**. These are sequential samples, so this finding
does not claim simultaneous overlap.

This contradicts the requested skipped ticks/no catch-up bursts and the claim
in `docs/rust-v2/multi-exit-preparation.md:80`. Consume ticks that elapse while
work is in flight, or advance the phase-preserving next deadline on completion;
the next dispatch in this example should be the 10s tick, without the 9.999s
catch-up dispatch. Preserve deterministic staggering.

Reviewer test `review_long_sample_must_skip_elapsed_cadence_ticks` FAIL.

## Other reviewed behavior

Within the offline boundary, no further concrete defect was established:

- All configured members, including disabled exits, pass schema/profile/key
  validation before a PreparedFleet exists. Duplicate stable IDs, effective
  private keys, lexical overlapping state paths, client node reuse across exits,
  allocation names and transport subnet conflicts refuse. The existing test
  actually compares equal inner addresses/endpoints with distinct parsed keys.
- Naming reuses schema validation: `mullvad-{site}-exit-{server}`, each duplicate
  gets its own stable ID suffix, labels over 63 bytes refuse without truncation.
  Resource identities derive from deployment/exit IDs. Pin changes report all
  resulting hostname changes. Removal has no credential/state deletion, rename
  or copy operation. Disabled exits retain their allocations.
- The single preparation bundle contains configuration plus matching allocations.
  Generation and canonical prior-record SHA256 both participate in commit CAS.
  Retained exclusive flock, descriptor-relative access, NOFOLLOW, private-mode/
  ownership/link-count checks and exclusive temp creation reuse the existing
  store. Independent scratch checks confirmed content CAS and preparation-file
  hardlink/permission refusal. No new exploitable TOCTOU was established within
  the admitted private-store/cooperating-writer boundary.
- Existing tests cover instance/exit/epoch token refusal, per-exit malformed and
  cross-binding failures, handshake expiry, stale health, watchdog, reconstructed
  recovery, disabled/absent slots, terminal cleanup and bounded lifecycle history.
  Inspection confirms no I/O inside poll and no absent runtime slots. The two
  findings above qualify the scheduling/clock guarantees despite those passes.
- No new unsafe code, privileged executor, CLI activation path, optional
  verification switch, direct-mode path or provider/server fallback was added.
  Core still forbids unsafe code. No other crate consumes the new APIs. Retry
  execution remains delegated to the existing worker, outside this core test run.
- Docs/report explicitly retain runtime/client/ARM/release gates. The four
  ignored owned-guest tests deliberately panic if forced and are clearly labeled
  specifications, not runnable native harnesses. No runtime-acceptance overclaim
  was found. The inaccurate policy claims are covered by I1/I2 above.

## Verification ledger

All commands below ran locally, offline, without privileged operations.
`CARGO_BUILD_JOBS=4` and
`CARGO_TARGET_DIR=/tmp/vprouter-task9-review.obnlaq/target` were set for Cargo.
Only vprouter-core was compiled/tested; formatting checked the workspace.
The final fmt/clippy checks ran in sequence. All adversarial edits are confined
to `/tmp/vprouter-task9-review.obnlaq/scratch`; repository sources were not edited.
Scratch fleet tests reuse the synthetic fixture/helper constructors, with
reviewer-authored scenarios and assertions. Scratch storage tests use the
existing test-only current-UID store opener, with reviewer-authored scenarios.

| Directory | Command | Exit / result | Log under `/tmp/vprouter-task9-review.obnlaq/` |
| --- | --- | --- | --- |
| Repository | `cargo test --locked --offline -j 4 -p vprouter-core` | 0; 73 tests + 1 compile-fail doctest passed; 4 ignored | `core-test.log` |
| Repository | `cargo fmt --all -- --check` | 0; clean | `fmt-final.log` |
| Repository | `cargo clippy --locked --offline -j 4 -p vprouter-core --all-targets -- -D warnings` | 0; clean | `clippy-final.log` |
| Scratch | `cargo test --locked --offline -j 4 -p vprouter-core --test review_adversarial review_ -- --nocapture` | 101; 3 requirement assertions failed, 1 positive control passed | `adversarial.log` |
| Scratch | `cargo test --locked --offline -j 4 -p vprouter-core --lib review_ -- --nocapture` | 0; 3 passed | `storage-adversarial.log` |
| Repository | `git diff --check` | 0 | inspected output |

Additional storage tests verified same-generation *valid* record replacement
(site changed) is rejected by SHA256 CAS without overwriting the replacement;
hardlinked and mode0640 preparation files are refused without changing bytes;
and an orphan partial first-write temp remains untouched while reopening yields
a complete generation-1 bundle and no live allocations.json. These are
interrupted-write simulations, not injected SIGKILL/power-loss durability proof.

NOT_RUN: four ignored owned-guest specifications; native enforcement, namespace/
process/socket/FD isolation, packet/capture fault acceptance, real provider and
Tailscale clients, DNS/IPv6/leak acceptance, migration, reboot, soak, overhead,
x86_64-musl and ARM64 cross-build/runtime checks, and other-crate/workspace tests.
None is required to reproduce I1/I2, and no runtime or release acceptance is
inferred from this review.

## Source/evidence binding

SHA256 values for reviewed inputs:

```text
6cdf6e1018dfe8e5d53fa72165c3661f943781c2ed9c42466a477b7b052f04ed  crates/vprouter-core/src/allocation.rs
c9b94b4b8a9c3372cadca95eaf547c5bdac039cd35eceb55c872d531e2057bb1  crates/vprouter-core/src/config.rs
e4acb6fcdaaa6596c120793d61166aa96698c28faf8695a9a3d6a1663f22f844  crates/vprouter-core/src/lib.rs
6c9129af31bbbed6c9d9bb58f7aceca92d3b0889185f73b97e026700e6dee993  crates/vprouter-core/src/fleet.rs
a062b6d30b8688dcc6ada8eb3b83e568ec89b6b1d7b8d790758c9f59a627ec14  crates/vprouter-core/src/transaction.rs
acd5c37059db847dd3e193e99d25a6e7eb864b5310f30a2839c7d6fa0d6c401b  crates/vprouter-core/tests/fleet.rs
702fabc99d422e89ad81552ed326bb32c8b483ea441cf3a6ec16ca5eb7600b04  crates/vprouter-core/tests/transactions.rs
de48613c91b565cae510d5708bacb72db175f0435273178073f0d6cd9c42f825  crates/vprouter-core/tests/fleet_owned_guest.rs
f4f50e22a8664abaa4705d4b8bc4b6d8312d96e45b908960ccaf7a787c9b8829  crates/vprouter-core/tests/support/mod.rs
c5430308b6e92c8ebdc131e37e9f920131badc3d7e3f6cf8564fa1e313f3357b  docs/rust-v2/multi-exit-preparation.md
d3ea0d4fabe2cb8d5b51fe7a6b01e8a79efbb3a20fb203a0cc427c9d4e1efe13  .superpowers/sdd/rust-v2/task-9-brief.md
aefa5aec8f8a82c92e4dd12fddb0509eae7afa5bcdff29afd2e8b59a3f3f7876  .superpowers/sdd/rust-v2/task-9-report.md
353f0e82d9dcf7b3e1216c27ac4c505bdc8fa6ee06ee3e6b833f1d3e11594125  docs/rust-v2/IMPLEMENTATION.md
```

Reviewer-authored scratch evidence SHA256:

```text
1767b3f9c968e1d9f127a98fd8098cab10b67496d5a6c167cf502fc638c746ad  /tmp/vprouter-task9-review.obnlaq/scratch/crates/vprouter-core/tests/review_adversarial.rs
8959f322121d83f3b780d1a28e713c1a3606eab61e0c95d5ff488e4d6f18476e  /tmp/vprouter-task9-review.obnlaq/scratch/crates/vprouter-core/src/allocation.rs
7d9d6f0e159747e4f97bbdf5e9d8171a959a0093c67037d37f2e2e990f3eb82a  /tmp/vprouter-task9-review.obnlaq/adversarial.log
de4f95202b51abdbcae92465baac7e44f577582c9c9d4cf3c852daf449997a1b  /tmp/vprouter-task9-review.obnlaq/storage-adversarial.log
9284128a232334e4b1a712c3650094aa21e8922d695bf59f89cd11d6621fb186  /tmp/vprouter-task9-review.obnlaq/core-test.log
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  /tmp/vprouter-task9-review.obnlaq/fmt-final.log
abfeb40db11fb4a1dbe03bd1de171883b7940977ebcb78bb5039a74119c8bc9a  /tmp/vprouter-task9-review.obnlaq/clippy-final.log
```

The scratch allocation source includes only the extra reviewer storage tests;
its production implementation matches the reviewed repository source. Retained
/tmp paths are local review evidence, not portable runtime acceptance artifacts.
