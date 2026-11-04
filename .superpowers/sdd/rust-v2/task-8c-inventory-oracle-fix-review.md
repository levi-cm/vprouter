# Task 8c inventory oracle fix — independent review

2026-11-04. Reviewed `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`, HEAD `a4f564b6a6fe59c46adec9c475f39982c545a5c7`, including the two tracked modifications and untracked `test-fresh-baseline.py`. Read the diagnosis, fix brief and implementation report; conclusions below come from independent source comparison and fresh checks.

**Verdict: PASS**, with one Minor compatibility caveat. The Rust fix implements complete multiset equality for valid inventory records, preserves namespace equality and every other assertion, and remains test-only. No Critical or Important findings. This verdict covers the source fix and offline regressions, not Bootstrap/runtime or release acceptance.

## Findings

- **Critical:** None.
- **Important:** None.
- **Minor M1 — historical `compare` no longer accepts the original IPv6-first template.** `tools/rust-v2-lab/fresh-baseline.py:97` changes decoding to IPv4-first; `tools/rust-v2-lab/fresh-baseline.py:165` still requires ordered canonical equality between the re-decoded inventory and the template. Concrete scenario: re-decode the preserved `target/rebuild-phase3/independent-netlink.json` and compare it with `target/candidates/rebuild-20261103T231415Z/authored-host-baseline-debian-clean-x86_64.json`. The old decoder reproduces that baseline exactly; the new decoder contains identical complete multisets but different route/rule array order, so the line-165 predicate fails. This was verified offline without invoking the controller or rewriting either file. It does not affect templates authored with this new decoder, and is nonblocking for the brief's future coherent candidate. Preserve tool/version binding when reviewing historical templates; if backward-compatible comparison is required, use full multiset comparison at this check rather than rewriting historical evidence. Canonical baseline hashes necessarily change when array order changes. The implementation report already requires fresh bindings; the existing Python suites do not exercise this historical comparison case.

## Comparison strength and scope

`crates/vprouter-launch/src/attachment/host_addition/operation.rs:653–683` checks namespace using the same JSON equality as before, then requires both sides of each addresses/routes/rules collection to be arrays. It compares lengths and sorted vectors of **complete** recursively key-sorted JSON encodings. Sorting does not deduplicate. Therefore a missing/extra record, `[A,B,A]` versus `[A,B,B]`, changed field, added/removed field, or changed scalar type cannot be hidden by reordering. `null` and an absent record field encode differently. Number `1`, string `"1"`, and floating-point `1.0` remain distinct. Nested object key order is normalized; nested array order is preserved.

This matches the full-record, length-preserving multiset semantics of `crates/vprouter-network/src/audit.rs:180–193`, used for addresses/routes/rules by `guarded.rs:1208–1214` and the real host-move acceptance path at `secret_role/veth/movement.rs:493–505`. Canonical string order need not match the typed record's `Ord`: either deterministic total order groups equal complete records correctly. No hashing, selected-field projection or set conversion weakens equality. Collection `null`, missing, object, number, string or boolean is rejected, even when both sides have the same malformed collection.

Namespace remains ordered and type-sensitive for the valid `[device,inode]` tuple. As before, indexing with `Value["namespace"]` is not a standalone schema validator: missing and explicit null namespace both index as null. That inherited behavior is not introduced by this fix; real observations use the typed namespace tuple (`host_observation.rs:12,25`) and existing decode/validation. The new helper likewise compares records rather than validating their schema.

The helper (`operation.rs:652`), caller `lab_build` (`:685`) and regression module (`:1255`) are all `#[cfg(test)]`; no production API or dependency declaration changes. I reconstructed HEAD's entire `operation.rs` byte-for-byte in memory by removing the helper/new test module and replacing the single helper call with the original loop. Consequently all other code, including link count/content, original index/down state (`:1103–1115`), ownership/custody, receipt, charge and deadline assertions, is unchanged. The same reconstruction proves the Python production/collection/authoring/comparison code is unchanged except for selecting dump groups in `decode`.

## Locked serde_json and independent edge cases

`Cargo.toml` pins and `Cargo.lock:1150–1151` locks `serde_json` to **1.0.150**. Fresh `cargo tree -e features -i serde_json` reports only `default` and `std`; `preserve_order`, `arbitrary_precision` and `raw_value` are not enabled. I inspected that exact installed version: `Value::sort_all_objects` is an unconditional public method (`src/value/mod.rs:875`). With default maps it is a no-op because keys are already sorted; with `preserve_order` it sorts each object recursively, traversing arrays without reordering their elements. Serialization retains all object keys, scalar types and null values.

A separate scratch Cargo project compiles the **verbatim extracted helper** against exact serde_json 1.0.150. Four independent tests pass with default features and again with `preserve_order`: pairwise scalar/type/null/absent distinctions; malformed collections on either/both sides; nested object insertion order versus nested array order; and namespace tuple order/type distinctions. This supplements gaps in the submitted test cases without editing repository tests. The extracted-helper hash and source reconstruction checks are in `source-proof.json`.

## Regression effectiveness and 409 representativeness

The ten submitted Rust tests pass on the current musl build. In a temporary workspace I replaced only the helper's body with the exact original four-key ordered predicate, retaining the submitted tests and helper call. A fresh, separate build target then reports **5 passed / 5 failed**, exit 101. Failures are:

- `routes_accept_native_ipv4_first_order`
- `rules_accept_native_ipv4_first_order`
- `routes_and_rules_accept_native_ipv4_first_order`
- `addresses_accept_reordering`
- `duplicate_multiplicity_is_preserved_even_with_equal_lengths_and_sets` (on its valid permutation)

The five other tests still pass against the old predicate, as expected for retained rejection behavior. The replacement is isolated under `/tmp`; no stash, Git index operation or source restoration in the shared worktree was needed.

The fixture at `operation.rs:1260–1292` is a minimal representative, not a full 409 replay: one IPv6-first route/rule and one IPv4 route/rule, complete fields, explicit nulls, integer flags/metrics/tables, and synthetic namespace/documentation addresses. Its address/route/rule field sets exactly match every corresponding record in 409's authored template. The actual native reader's `Routes4 → Routes6 → Rules4 → Rules6` phases (`native/host_read.rs:5–24`) and append behavior (`:83–103`) justify the tested permutations. Real baseline counts are 3 links / 6 addresses / 19 routes / 5 rules; the synthetic fixture deliberately does not reproduce those counts or any live identity.

For Python, all five submitted test methods pass. The unchanged test file run beside HEAD's old decoder in scratch exits 1 with **10 failing subtests across four methods**; within-family record/multiplicity preservation already passes. Thus the test detects the actual sorted-key order bug as well as the new missing/unexpected-group rejection.

## Decoder determinism and phase 3 compatibility

`fresh-baseline.py:97–100` explicitly visits `18/0,22/0,26/2,26/10,34/2,34/10`, matching the collector's exact six groups. Both insertion directions and `sort_keys=True` round-trips are tested. The new key-set assertion rejects incomplete or unexpected groups rather than omitting them. Optimized Python is already refused at module import, so this validation is not silently disabled by `-O`.

I additionally decoded the **saved independent dump** offline using both implementations. The old decoder reproduces the original authored baseline; old/new complete multisets are equal, and namespace, links and addresses are exactly unchanged. All **720 permutations** of the six dump keys produce the same new decoded result; all **720 sorted-key round-trips** also match. No valid record content or duplicate is dropped or changed. Within each group, the original `rows` iteration and field decoding are unchanged. `decoder-proof.json` records these results and the two input hashes, which remained unchanged.

No functions, signatures or return keys were removed. Existing phase 3 regression suites pass: 8 fixes tests and 21 provenance tests, including import/compilation of `fresh-baseline.py`'s unchanged remote template. The only compatibility limitation found is M1's historical ordered comparison; these suites establish offline compatibility, not guest execution.

## Commands and observed results

Evidence root: `/tmp/vprouter-oracle-review/review-uai0edbm/`. `run-check.py` and `checks.jsonl` record working directories, exact argument vectors, exits and durations; named logs contain complete output. Cargo commands ran sequentially with four build jobs, `--locked --offline`, and external build outputs. Environment for musl commands:

```sh
export CARGO_BUILD_JOBS=4
export CARGO_TARGET_DIR=/tmp/vprouter-oracle-review/review-uai0edbm/target
export TMPDIR=/tmp/vprouter-oracle-review/t17qxozjd
export CC_x86_64_unknown_linux_musl=/home/opsec/.local/share/zig-cross/bin/x86_64-linux-musl-gcc
export AR_x86_64_unknown_linux_musl=/home/opsec/.local/share/zig-cross/bin/x86_64-linux-musl-ar
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS='-C relocation-model=static'
```

The actual shorter temporary directory is recorded in `runtime-environment.json`; Python used `-B`/`PYTHONDONTWRITEBYTECODE=1`. The old-predicate check overrides `CARGO_TARGET_DIR` to `/tmp/vprouter-oracle-review/review-uai0edbm/old-target`.

| Command | Exit | Verified result / log |
| --- | --- | --- |
| `cargo fmt --all --check` | 0 | `fmt.log` |
| `cargo test -p vprouter-launch --locked --offline --target x86_64-unknown-linux-musl -j 4 --lib inventory_oracle_tests` | 0 | 10 passed; `rust-focused.log` |
| `cargo test -p vprouter-launch --locked --offline --target x86_64-unknown-linux-musl -j 4` | 0 | 181 library tests passed; binary/doc targets passed with zero tests; six standalone guest harnesses printed their skip messages; `rust-full.log` |
| Same focused command, cwd `old-workspace`, distinct `old-target` | 101 | Expected regression red: 5 passed / 5 failed; `rust-old.log` |
| `cargo clippy --workspace --all-targets --locked --offline --target x86_64-unknown-linux-musl -j 4 -- -D warnings` | 0 | No warnings; `clippy.log` |
| `cargo tree --locked --offline --target x86_64-unknown-linux-musl -e features -i serde_json` | 0 | serde_json 1.0.150, default/std only; `features.log` |
| `python3 -B tools/rust-v2-lab/test-fresh-baseline.py` | 0 | 5 tests; `python-fresh.log` |
| `python3 -B tools/rust-v2-lab/test-phase3-fixes.py` | 0 | 8 tests; existing synthetic remote-template SyntaxWarnings emitted; `python-phase3.log` |
| `python3 -B tools/rust-v2-lab/test-phase3b-provenance.py` | 0 | 21 tests; `python-phase3b.log` |
| `python3 -B test-fresh-baseline.py`, cwd `old-python` | 1 | Expected regression red: 10 failing subtests; `python-old.log` |
| `cargo generate-lockfile --offline`, cwd `canonical-probe` | 0 | Scratch-only lockfile pins exact serde_json 1.0.150; `probe-lock.log` |
| `cargo test --locked --offline --target x86_64-unknown-linux-musl -j 4`, cwd `canonical-probe` | 0 | 4 independent helper tests; `probe-default.log` |
| Same probe command with `--features preserve_order` | 0 | Same 4 tests; `probe-preserve-order.log` |
| `python3 -B /tmp/vprouter-oracle-review/review-uai0edbm/setup-probe.py` | 0 | Source reconstruction and verbatim helper extraction; `source-proof.json` |
| `python3 -B /tmp/vprouter-oracle-review/review-uai0edbm/check-decoder.py` | 0 | Full saved-dump multiset equivalence, 720 permutations plus 720 round-trips and fixture-field comparison; `decoder-proof.json` |
| `git diff --check` | 0 | `diff-check.log` |

Review harness corrections are retained rather than hidden: the initial full test invocation exited 101 (180 passed / 1 failed) because my longer scratch `TMPDIR` exceeded AF_UNIX's pathname limit in the existing local-socket test (`actual.rs:341`). The shorter TMPDIR rerun passed all 181. An initial old-code attempt reused a shared Cargo target and was invalid; a clean separate target first exposed missing copied `docs/rust-v2/programs-*.json` inputs. Copying those unchanged docs into the temporary workspace yielded the genuine five-test assertion failure above. Earlier logs and command records remain in scratch. Neither setup failure is a finding against this patch. Standalone probe non-test builds emit harmless dead-code warnings; workspace strict Clippy remains clean.

## Preservation and limits

Before checks I hashed 878 tracked/untracked source and review-input files and saved branch, HEAD, Git status, tracked/staged diffs and index bytes. They were unchanged after testing; final preservation proof is `preservation-proof.json`. I wrote only this review report in the repository. All copied sources, decoder probes, build products, test fixtures and logs are under `/tmp/vprouter-oracle-review/`. The two historical baseline/dump inputs were read only and retained their hashes. No guest, SSH/SCP, sudo, Bootstrap execution, artifact rewrite, reservation/claim mutation, staging, commit, push or subagent was used.

ARM64 build/link was not independently repeated: **NOT_RUN**. ARM64 execution, a new candidate/freeze, run 410 admission/controller/reservation, runtime Bootstrap, driver-cost/performance, client/migration/soak and release acceptance: **NOT_RUN**. Run 409 was not rerun or reused. This review does not re-establish historical host/guest continuity or retrospective implementation-session preservation claims.
