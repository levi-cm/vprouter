# Task 10 independent review

Verdict: **FAIL — 0 Critical, 0 Important, 1 Minor finding.**

The failure is an observational host-time validation gap exposed by the requested
sweep of every time-bearing entry point. It is not an established quarantine
bypass, automatic fallback, native activation or weakening of the Task 9
operational callbacks. The affected status method is unchanged from HEAD; this
review does not attribute its introduction to Task 10.

Reviewed 2026-11-06, branch `rust/v2`, HEAD
`20936b4a05d789efa659425e8a93ad65a2748537`, including the supplied uncommitted
Task 10 files. Binding inputs: `.superpowers/sdd/rust-v2/task-10-brief.md` and
`docs/rust-v2/IMPLEMENTATION.md`. The implementation report was treated as
unverified. The user's stated bounded offline scope governs this verdict;
unimplemented native integration is an explicit remaining gate, not an extra
finding against this preparation layer.

No sub-agents, sudo, external network, VM operations, Git writes or source fixes.
Only this report was written in the repository. Scratch copies and logs are
retained under `/tmp/vprouter-task10-review-5wwX56/`. No foreign process was killed.

## Finding

### M1 — Minor: status accepts host time older than the fleet high-water mark

Location: `crates/vprouter-core/src/fleet.rs:300` (delegation at line306).
`FleetPolicy::status` delegates directly to `HealthMachine::status`, which checks
its own last evidence-observation time (`state.rs:253`) rather than the fleet's
`last_now`. Mutating callbacks check the shared high-water mark at `fleet.rs:289`.

Reproduced in the scratch copy with one direct and one Mullvad exit:

1. Interleave four valid observations for both exits at5,10,15,20 seconds,
   reaching READY at20. Their evidence and verification timestamps are20.
2. Call `poll(20)` and `poll(22)`. Both statuses at22 remain READY.
3. Call `status("residential", 21)` and `status("mullvad-1", 21)`.
   Both return **Ok(READY)** despite the fleet having accepted host time22.
   The direct status says `direct-exposed`; the Mullvad status says `protected`.
4. A subsequent status query at22 still returns READY: the test confirms that
   queries remain observational and have not changed either lifecycle.

This misses the current review requirement that every time-bearing entry reject
regressing host time across the fleet. It does not show acceptance of stale
worker evidence, revival of FAILED, a native authorization path, or a missing
emergency action from any mutating callback. Its demonstrated impact is limited
to accepting an invalid status-query timestamp. The prior Task 9 contract keeps
queries observational; rejecting a query against the shared high-water mark can
preserve that behavior without advancing time, renewing the watchdog, or
mutating state. Apply the fleet's time-domain/high-water checks as read-only
validation before emitting status.

Reviewer test:
`review_status_must_reject_host_time_before_fleet_high_water_without_mutation`
in scratch `crates/vprouter-core/tests/direct_fleet.rs:670`.
Result: exit101, one assertion failure after printing both returned READY
statuses and checking the observational controls.
Evidence: `/tmp/vprouter-task10-review-5wwX56/status-clock.log`.
The production `status` method has the same implementation in base HEAD.
No source change was made by this review.

## Other reviewed behavior

No additional concrete defect was established within the offline boundary.

- **Public destinations and separation:** inspected the full deny table,
  canonical-prefix parsing, host denials, exact path checks and flow evaluator
  in `direct.rs`. Core range-boundary tests pass. Fresh scratch cases reject
  IPv4-mapped/compatible IPv6, NAT64 and 6to4 forms; Rust's typed address parser
  rejects integer, octal, hexadecimal and shortened IPv4 forms. All IPv6 source
  and destination representations refuse. Fresh tests retain destination
  denials for forged established original tuples and reverse traffic, including
  host public, global local-prefix, infrastructure metadata and special-use
  addresses. DNS uses the same policy. Nonzero ports, exact original/reverse
  protocol/ports, and every FlowScope field are checked. A direct plan cannot
  target a Mullvad member or use any member's reserved host/data/WireGuard
  interface name. Configuration/allocation validation retains distinct IDs,
  lexical state paths, namespaces, interfaces, policy tables and transport
  subnets. These facts concern plans/evaluation, not observed namespace isolation.
- **Explicit selection and witnesses:** enabled exit ID plus exact stable node
  and matching explicit client mode are required; hostname alone and cross-mode
  selections refuse. No fallback branch was found. Mixed/fallback mode fields
  and unattended direct enrollment keys refuse. Fresh tests reject absent
  egress/verification/node, negative reachability, provider server/handshake
  claims in direct mode, and failed DNS evidence, while leaving the provider
  peer unchanged. Unknown/drifted host snapshots block and revoke the selected
  session. Client plans label direct exposure and leave observations not_tested.
- **Transactions:** all changes prepare a revalidated configuration/allocation
  bundle before commit. Existing generation plus canonical-content CAS,
  bounded decoding, exclusive flock, private single-link files, NOFOLLOW,
  exclusive temp creation and fsync/rename persistence remain. New lock and
  temp inode checks do not add unsafe Rust. Fresh real-file tests cover valid
  same-generation content replacement, hardlinks/mode changes/symlinks without
  repair, partial first-write preservation, and bounded temp-name collisions.
  A further direct-only real-file test commits add/disable/enable/remove across
  generations1–5, refuses a stale prepared CAS without changing committed
  bytes, reopens the complete final bundle, and preserves an identity sentinel
  after removal. No live allocations file is created. Fresh duplicate direct
  ID/shared-state cases refuse before profile reads and leave the prior record
  unchanged. Pinning cannot change direct to Mullvad. These tests do not
  simulate SIGKILL, disk exhaustion, fsync failure or power loss.
- **Task 9 regressions:** the repository's fleet target passed all20 tests,
  including its18 retained Task 9 cases and two new checks. The15 retained
  reviewer-authored Task 9 adversarial scenarios were copied from the prior
  scratch evidence and rerun on current production sources: all pass, including
  the formerly failing late-cancel FAILED/reason preservation case. Host-clock
  emergency, scoped failures, deadline boundaries, no catch-up burst, old/foreign
  token refusal, lifecycle reuse, removal preservation and overflow/refusal
  controls pass. The retained fleet tests were not weakened; the transaction
  test's direct-mode refusal was intentionally changed to direct admission.
  No changed Mullvad-only behavior was reproduced by these regression scenarios.
- **Callback/class sweep and bounds:** fresh mixed-six-exit tests exercise all
  six mutating timed entry points with NaN, both infinities, negative time,
  regression and huge finite time. Foreign tokens, malformed wire input and
  invalid transitions do not bypass the host-clock check: all six exits become
  FAILED and exactly one emergency action per exit is drained. Late cancel,
  cleanup, worker failure and repeated container failure cannot downgrade or
  re-arm that emergency. Scoped direct FAILED retains its reason through late
  observation/bytes/completion/restart/cancel/worker callbacks. Existing tests
  cover the1024-lifecycle budget; source retains128 reservations, six active
  slots with at most five Mullvad, bounded metadata/wire input and at most12
  actions/poll. No new unbounded history or background work was found. Status
  queries are the exception described in M1.
- **Native boundary and claims:** the changed/new implementation paths are in
  the core library; `lib.rs` forbids unsafe code. No CLI flag, privileged code,
  new optional verification switch or native activation consumer was added.
  Inspected network/netfilter/worker direct-refusal paths remain present.
  Docs/report clearly distinguish policy intent, caller-supplied expected data,
  synthetic READY, manual deny-range sources and unimplemented native custody
  from runtime qualification. All eight ignored core cases remain specifications
  that panic if forced, not implemented guest harnesses. Native direct isolation,
  host-inventory completeness/freshness and lifecycle/conntrack custody are
  explicitly future obligations; this review does not claim them verified.

## Verification ledger

Cargo invocations ran **sequentially**, with `CARGO_BUILD_JOBS=4` and
`CARGO_TARGET_DIR=/tmp/vprouter-task10-review-5wwX56/target`.
Every build/test/clippy invocation used `--offline --locked -j 4`.
Cargo fmt does not accept those build flags. Logs below are relative to the
retained temporary directory. Scratch root is its `scratch/` subdirectory.
Scratch production bytes match repository bytes; only test code was appended.

| Location | Exact command after environment variables | Exit / observed result | Log |
| --- | --- | --- | --- |
| Repository | `cargo test -p vprouter-core --all-targets --offline --locked -j 4` | 0;102 passed,0 failed,8 ignored | `core-tests.log` |
| Repository | `cargo fmt --all -- --check` | 0;clean | `fmt.log` |
| Repository | `cargo clippy -p vprouter-core --all-targets --offline --locked -j 4 -- -D warnings` | 0;clean | `clippy.log` |
| Scratch | `cargo test -p vprouter-core --test rereview_adversarial --test direct_policy --test direct_fleet --offline --locked -j 4 -- --nocapture` | 0;15 Task 9 reviewer cases +10 direct-policy +14 direct-fleet =39 passed | `adversarial.log` |
| Scratch | `cargo test -p vprouter-core --lib rereview_storage_ --offline --locked -j 4 -- --test-threads=1 --nocapture` | 0;4 passed | `storage.log` |
| Scratch | `cargo test -p vprouter-core --test direct_fleet review_status_must_reject --offline --locked -j 4 -- --nocapture` | 101;1 failed assertion, M1 | `status-clock.log` |
| Scratch | `cargo test -p vprouter-core --lib task10_review_storage --offline --locked -j 4 -- --nocapture` | 0;1 passed | `direct-storage.log` |
| Repository | `git diff --check` | 0 | inspected output |

The39-case pass preceded adding the M1 test; the status failure is additional
review coverage, not a failure of the reported102-test suite. The final storage
test made no production-source change. No scratch-test formatting/clippy claim
is made; the requested fmt/clippy checks concern the reviewed repository.

### Report validation checked without rebuilding other platforms

All13 source/doc SHA256 entries in the Task 10 report match current bytes. Every
listed retained log/JSON hash matches. Independently summing retained result lines
matches102/0/8 for core and x86_64-musl, and478/0/10 for workspace. ARM check/link
logs end with completion/13 linked executables; no ARM execution was inferred.
Fresh core/fmt/clippy results independently confirm those current-source claims.

Cheap retained-artifact inspection also matches all four reported binary hashes,
byte lengths and ELF machines (x86_64=62, AArch64=183), with no PT_INTERP or
PT_DYNAMIC headers. Evidence: `artifact-check.json`. These are existing debug
test binaries. This corroborates the retained report; it does not independently
attest prior command execution or turn those artifacts into release evidence.

**NOT_RUN this review:** workspace/other-crate tests, fresh musl/ARM builds or
executions, doctests (the requested all-targets command omits them), ignored guest
specifications, native driver/packet enforcement, real public/provider/Tailscale
traffic or client/capture acceptance, private-role/namespace/FD/LSM qualification,
full-disk/SIGKILL/power-loss durability, migration/rollback, reboot/platform,
performance/efficiency,24-hour soak or release acceptance. Existing open runtime,
ARM and client gates remain open; no release-readiness claim is made.

## Source and evidence binding

Reviewed input hashes were captured before scratch verification and checked
unchanged afterwards. The final checkout remains at the stated HEAD with the
same13 dirty source/doc paths and no index changes. The only repository write
from this review is this ignored report.

Reviewed source/doc/binding-input SHA256 values:

```text
0cbd64ba94ebb22cfd4d206ea0765e799e3c07d7494040b8e235c822153d40b5  crates/vprouter-core/src/lib.rs
2779591c6f014f403fc9f263ab779446cd431c6504b4de67f33f3577d77c0e9d  crates/vprouter-core/src/config.rs
c53745c9e147c5f68d91997407c126743fbb63561d2198e752727474df11d16f  crates/vprouter-core/src/allocation.rs
bfafb1730846c64bb7cf6628e50f15bca002ba7b3134e6947afbb91f19e583fb  crates/vprouter-core/src/transaction.rs
b6bcc1ebb9e78a1c64ed6679a5bc292e65a551ea863dc27d231f75eac2df597b  crates/vprouter-core/src/fleet.rs
50f0ff5e6b21ec94f0c61cb7ee39b7ba5193f947d29f0d88fa09eaee41c6a942  crates/vprouter-core/src/direct.rs
bcf6bba2ebbf9d6e6c58c8d914605d900ef4a85b3024d4a5225a98c03ee7def1  crates/vprouter-core/tests/transactions.rs
2cdaa68f10297adc3ec57789ba1f49f70421325062f8ed80de3d84a38fbfbeea  crates/vprouter-core/tests/fleet.rs
24f527b3ed39ce85720e81c9ab532ab93a36ec824c3877d14e7e2b03e71e6cf2  crates/vprouter-core/tests/direct_fleet.rs
879ad28bc32d858ffe698355fbd62d9eec5840535bd00ff93e8a1f08c00c22e3  crates/vprouter-core/tests/direct_policy.rs
e3476064fb154a1aa770ed28df99b9a108731c9c96fbcd060d3422045d123e25  crates/vprouter-core/tests/direct_owned_guest.rs
07621dc9f4571e0c38c15ef963dbf21c3aa65d3caf53fe060917de2f92105505  docs/rust-v2/direct-exit-preparation.md
646b04ed9596eef05c604b81c6c9c7a713c8f631acf4fe3cc2794f6da44d6532  docs/rust-v2/multi-exit-preparation.md
353f0e82d9dcf7b3e1216c27ac4c505bdc8fa6ee06ee3e6b833f1d3e11594125  docs/rust-v2/IMPLEMENTATION.md
0a18402ccfc11d1eb2e7d6857772e4a9945ad77bd5991de2f44cfc13372e9065  .superpowers/sdd/rust-v2/task-10-brief.md
7af52dd99f5983e76e7c287f188fba9c5c72c66cbbd09792d0a74ca724365907  .superpowers/sdd/rust-v2/task-10-report.md
```

Evidence SHA256 (relative to `/tmp/vprouter-task10-review-5wwX56/`):

```text
7837ed911e9f0f2a306a31f6e862c8eca643deb17612e507979f5472898ff195  adversarial.log
5822986a2d1a1fefb671686c084ea1cd3752ff6e2e2bb0cee07cdb12565019cd  clippy.log
035bac84bcdf570db214e79bdcb209cc519a415f5cc9acca13ca54d0c0e87fbe  core-tests.log
f9f4a0def01064254e3893fda60cf4a777785f444284ad6a38c94e908756b414  direct-storage.log
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  fmt.log
ed91858f520e0554191a224e39d5f9047a4c4432a5593f19241f71e7863402cc  status-clock.log
9a3f3abafc6d2f1555d4ec09592554d251551f3dd099b61365529f4f500a1e13  storage.log
793c76d57c63ce75494a7962b8f98dd943fe0cb989f68dc576e8a32af9c491d6  artifact-check.json
2f5505f48a5daea8a0be772790d4d73bc1a9bc51be665baa078e2f7466ac3cf9  source-baseline.json
4413c689f533442766f4b4c882d08c0091681fcd4765ab6d1043a4c6473002d5  scratch/crates/vprouter-core/tests/rereview_adversarial.rs
d189330b5a2466d7986d85091c6629228f0b9a4fccf044d14f38f080cc076e49  scratch/crates/vprouter-core/tests/direct_policy.rs
3d482d1f61d6717f145d7cec668a3609fadc064d0882cbdf8bcf45b8156e14fe  scratch/crates/vprouter-core/tests/direct_fleet.rs
cec3e45dabbb0dc044e4882b8efaed062ce4a81053847219e67518297f4c87b5  scratch/crates/vprouter-core/src/allocation.rs
```
