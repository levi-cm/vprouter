# Task 8c inventory oracle fix brief (toward run 410)

Workspace `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`, HEAD `a4f564b` (pushed). Run 409 is consumed (budget 0) and must never be re-run or reused.

## Read first

- `.superpowers/sdd/rust-v2/task-8c-bootstrap409-diagnosis.md` — full root cause, evidence, recommended steps 1–4.
- `crates/vprouter-launch/src/attachment/host_addition/operation.rs` (~652–656 `lab_build`, ~1065–1088 inventory oracle), `crates/vprouter-network/src/native/host_read.rs`, `crates/vprouter-network/src/secret_role/veth/movement.rs:493–505`, `guarded.rs:1208–1214`, `audit.rs:180–193` (existing multiset semantics).
- `tools/rust-v2-lab/fresh-baseline.py` (~29–31, 60–67, 94–99, 142, 161–167).

## Tasks

1. **Fix the cfg(test) lab inventory oracle** in `operation.rs` per diagnosis step 1: namespace stays exact; addresses/routes/rules compare as complete multisets (every field, multiplicity, length), matching existing `guarded`/`audit` semantics. Reuse the existing multiset helper if it fits; do not widen any production API; keep the change inside cfg(test)/lab code. Keep every other assertion (link/index/down, custody, deadline) unchanged.
2. **Rust regression tests** (offline, no guest): IPv4/IPv6 reordering of routes and rules passes; missing, extra, duplicated, replaced records and changed fields (route metric, rule table, address flags, namespace) fail. A test that uses the actual 409 authored declaration ordering vs native family order is preferred if it can be expressed as a fixture without bringing lab secrets/state into Git (the baseline holds no secrets, but keep fixtures minimal).
3. **Lab hardening:** make `fresh-baseline.py` decode in an explicit request/family order instead of JSON object iteration order; add a test covering both insertion orders and a `sort_keys` round-trip. Do not modify 409's authored baseline, reservation, claim or evidence files.
4. **Verification** (cargo `-j 4` / `CARGO_BUILD_JOBS=4`):
   - `cargo fmt --check`; focused tests for the changed crate(s); `cargo test -p vprouter-launch` (and any crate whose tests reference the oracle) for x86_64 musl; strict Clippy as the project normally runs it (see `progress.md` entries for the exact invocations used before).
   - musl cross env: zig wrappers `~/.local/share/zig-cross/bin/x86_64-linux-musl-{gcc,ar}`; `CC_x86_64_unknown_linux_musl`/`AR_x86_64_unknown_linux_musl` = wrappers, `CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld`, `CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS='-C relocation-model=static'`. aarch64 build/link only if cheap (x86 is the priority).
   - Python: run the new fresh-baseline test and the existing phase 3 tests that touch fresh-baseline.py.

Out of scope here (a later phase does them): new candidate build/freeze, 410 controller/reservation, new guest admission, any guest action. Do not touch the lab guest at all in this task.

## Constraints

No sudo on debdev; no production/credential use; no git staging/commit/push; no subagents; work autonomously without asking for approval.

## Deliverable

`.superpowers/sdd/rust-v2/task-8c-inventory-oracle-fix-report.md`: diff summary with file:line, tests added and what each proves (including that they fail on the old predicate), exact commands with exit codes, NOT_RUN items.
