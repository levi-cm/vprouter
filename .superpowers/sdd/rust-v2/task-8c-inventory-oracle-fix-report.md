# Task 8c inventory oracle fix report

2026-11-04. Shared checkout `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`,
starting HEAD `a4f564b6a6fe59c46adec9c475f39982c545a5c7`. The initial checkout
was clean. Implementation and offline verification are complete; runtime Task 8c
and release acceptance remain unproven.

## Diff summary

- `crates/vprouter-launch/src/attachment/host_addition/operation.rs:652` adds
  private `#[cfg(test)] lab_inventory_preserved`. Namespace retains the original
  exact JSON equality. Addresses, routes and rules must be arrays of equal
  length; complete records are recursively canonicalized by object key, serialized
  without dropping fields, sorted, and compared. No deduplication occurs, so
  repeated records retain their multiplicity. Nested arrays retain their order.
  This follows the complete-value multiset semantics of network `audit::same`
  without exposing that crate-private helper or widening a production API.
- `operation.rs:1102` replaces only the old four-key ordered-equality loop with
  the helper call. Link count/content, added-link index/down state, ownership,
  custody, receipt, charge and deadline assertions retain their existing code.
  The helper, caller and new regression module are all `cfg(test)`.
- `operation.rs:1256` adds ten offline Rust tests and a minimal synthetic
  IPv6-first declaration. It illustrates the diagnosed 409 ordering with one
  representative route/rule per family, synthetic namespace `[4,99]`, and
  documentation-range IPv4 addresses. No guest/run evidence is loaded by tests
  or copied into a fixture.
- `tools/rust-v2-lab/fresh-baseline.py:94` decodes the exact request sequence
  `18/0, 22/0, 26/2, 26/10, 34/2, 34/10`. Routes and rules therefore append
  IPv4 before IPv6 regardless of dictionary insertion/serialization order.
  Missing or unexpected dump groups are rejected. Records within each dump,
  including duplicates, retain their original order and full decoded values.
  Collection, remote commands, authoring, comparison and reservation logic are
  unchanged.
- `tools/rust-v2-lab/test-fresh-baseline.py:1` adds five synthetic netlink decoder
  tests. Subprocess execution is blocked in these tests.

The changed decoder does not rewrite or normalize a historical template. Its
deterministic rendering applies to future authoring; 409's original declaration
and bindings must remain preserved. A future coherent candidate/declaration/run
requires the separate gates in the brief.

## Rust regression coverage and original-predicate proof

The original predicate was first extracted verbatim into the test-only helper
and called at the original assertion site, with no behavioral change. The tests
were then executed before replacing that predicate. The complete red run exited
101: **5 passed, 5 failed**. All ten pass after the fix. The first red run, before
splitting route/rule cases, is retained too: 5 passed, 3 failed.

All names below are in `attachment::host_addition::operation::inventory_oracle_tests`.

| Test | Line | What it proves | Original predicate |
| --- | --- | --- | --- |
| `routes_accept_native_ipv4_first_order` | 1318 | IPv6-first authored routes match IPv4-first native order | FAIL |
| `rules_accept_native_ipv4_first_order` | 1323 | The independent rule-family mismatch is also fixed | FAIL |
| `routes_and_rules_accept_native_ipv4_first_order` | 1328 | Both family-order differences can occur together | FAIL |
| `addresses_accept_reordering` | 1333 | Address records also use multiset semantics | FAIL |
| `identical_and_empty_record_collections_match` | 1341 | Identical inventories and empty arrays still match | PASS |
| `missing_extra_duplicated_and_replaced_records_fail` | 1349 | All three collections reject record loss, addition, appended duplicates and same-length replacement | PASS |
| `duplicate_multiplicity_is_preserved_even_with_equal_lengths_and_sets` | 1370 | `[A,B,A]` matches `[B,A,A]`, but rejects `[B,A,B]` despite equal length and set membership | FAIL on the valid permutation |
| `every_record_field_is_compared_including_metric_table_and_flags` | 1387 | Changing/removing each field of both records, or adding a field, fails; includes route metric, rule table and address flags | PASS |
| `namespace_identity_and_order_stay_exact` | 1418 | Changed device, inode or tuple ordering fails | PASS |
| `missing_or_non_array_record_collections_fail` | 1428 | Missing collections and null/object/scalar values fail | PASS |

The negative tests passing against the old predicate is expected: the fix must
retain its rejection of content drift while accepting order-only differences.

## Python regressions and original-decoder proof

`tools/rust-v2-lab/test-fresh-baseline.py` tests:

- Line 53: both sorted and reverse-sorted dump-key insertion orders produce
  complete expected IPv4-first route/rule records.
- Line 60: both insertion orders survive a `json.dumps(..., sort_keys=True)` /
  `json.loads` round-trip with the same explicit family ordering.
- Line 67: within-family record order and multiplicity are retained.
- Line 75: removing any one of the six required dump groups is rejected.
- Line 83: an unexpected group is rejected rather than silently omitted.

Before the decoder change, the suite exited 1 with ten failing subtests across
four test methods. The within-family preservation test already passed. After
the change, all five methods pass. The existing phase 3 suites also pass, including
compilation of the unchanged `fresh-baseline.py` remote template.

## Exact verification commands and results

Logs and machine-readable exact commands/exit codes are under
`target/task8c-inventory-oracle-fix-20261104T162613Z/` (`checks.json`). Shell
redirections only captured stdout/stderr in the corresponding log. Every Cargo
build/test/Clippy invocation used four jobs; Cargo processes ran sequentially.
Python suites used separate processes and temporary synthetic fixtures.

The x86_64 Cargo commands below used this exact environment prefix:

```sh
env CARGO_BUILD_JOBS=4 \
  CC_x86_64_unknown_linux_musl=/home/opsec/.local/share/zig-cross/bin/x86_64-linux-musl-gcc \
  AR_x86_64_unknown_linux_musl=/home/opsec/.local/share/zig-cross/bin/x86_64-linux-musl-ar \
  CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld \
  CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS='-C relocation-model=static' \
  <cargo command>
```

| Exact command (with the prefix above for musl Cargo commands) | Exit | Result / log |
| --- | --- | --- |
| `cargo test -p vprouter-launch --lib --locked --target x86_64-unknown-linux-musl -j 4 inventory_oracle_tests` (original predicate, initial eight tests) | 101 | Expected red; `rust-red.log` |
| Same focused command (original predicate, complete ten tests) | 101 | 5 passed / 5 expected failures; `rust-red-complete.log` |
| `python3 -B tools/rust-v2-lab/test-fresh-baseline.py` (original decoder) | 1 | Expected red; `python-red.log` |
| `rustfmt --edition 2024 crates/vprouter-launch/src/attachment/host_addition/operation.rs` | 0 | Only the owned Rust file formatted |
| `cargo fmt --all --check` | 0 | PASS; `fmt.log` |
| `cargo test -p vprouter-launch --lib --locked --target x86_64-unknown-linux-musl -j 4 inventory_oracle_tests` | 0 | 10 passed; `rust-focused.log` |
| `cargo test -p vprouter-launch --locked --target x86_64-unknown-linux-musl -j 4` | 0 | 181 library tests passed; bin/doc targets passed with zero tests; six standalone guest harnesses skipped; `rust-launch-full.log` |
| `cargo clippy --workspace --all-targets --locked --target x86_64-unknown-linux-musl -j 4 -- -D warnings` | 0 | Workspace strict Clippy PASS, no warnings; `clippy-x86_64-musl.log` |
| `python3 -B tools/rust-v2-lab/test-fresh-baseline.py` | 0 | 5 passed; `python-fresh-baseline.log` |
| `python3 -B tools/rust-v2-lab/test-phase3-fixes.py` | 0 | 8 passed; `python-phase3-fixes.log` |
| `python3 -B tools/rust-v2-lab/test-phase3b-provenance.py` | 0 | 21 passed; `python-phase3b-provenance.log` |
| `git diff --check` | 0 | PASS |

The optional ARM64 build/link check was cheap (7.57 seconds) and passed:

```sh
env CARGO_BUILD_JOBS=4 \
  CC_aarch64_unknown_linux_musl=/home/opsec/.local/share/zig-cross/bin/aarch64-linux-musl-gcc \
  AR_aarch64_unknown_linux_musl=/home/opsec/.local/share/zig-cross/bin/aarch64-linux-musl-ar \
  CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld \
  CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS='-C relocation-model=static' \
  cargo test -p vprouter-launch --lib --locked --target aarch64-unknown-linux-musl -j 4 --no-run
```

Exit 0; `rust-aarch64-build.log`. This compiles and links the library test binary;
ARM64 execution is **NOT_RUN**.

## Preservation verification

The local preservation proof command passed (exit 0):

```sh
python3 -B target/task8c-inventory-oracle-fix-20261104T162613Z/verify-preservation.py
```

`preservation-initial.log` and `preservation-proof.json` establish:

- Exactly one of 181 tracked Rust paths changed (`operation.rs`); the other 180
  match their before hashes, with no tracked Rust path added or missing.
- Removing the new test-only helper/module and restoring the original oracle
  loop reconstructs the entire original `operation.rs` byte-for-byte. Every
  other assertion and all production code are consequently preserved.
- All 12 files in the pre-edit protected snapshot retain their SHA256 hashes:
  run 409's raw result, consumed claim, current/superseded reservations,
  inspection/failure records, supersession records, lock and lab identity files.
  Only hashes were recorded; no key contents were emitted.
- Branch, HEAD, staged diff and index bytes are unchanged. The visible working
  tree changes are the two edited source files and the new Python test.
- Both `git diff --check` and `git diff --cached --check` exited 0.

The same proof is repeated after finalizing this report, with output captured in
`preservation-final.log`; its JSON output records the final report hash. The
evidence directory also contains `rust-before.json`, `rust-after.json`,
`protected-before.json`, `protected-after.json`, `vcs-before.json` and
`source.diff`. `SHA256SUMS` binds the local evidence files.

The report path is ignored by the repository's existing `/.superpowers/` rule;
the report is delivered as a local file. No ignore rule or Git index was changed
to publish it.

## NOT_RUN and scope boundaries

- No guest access, SSH/SCP, sudo, guest mutation, native lab invocation or new
  Bootstrap attempt. The standalone privileged/guest harnesses were skipped.
- No run 409 rerun/reuse, reservation/claim changes, candidate rebuild/freeze,
  410 admission/controller/reservation work, or selector/resource changes.
- No ARM64 execution, browser/client/migration/soak verification, driver-cost
  measurement, performance result or release acceptance. `release_ready=false`
  remains the task boundary.
- No production or credential authentication use, staging, commit, push or
  subagents. Changes remain local and unstaged for review.
