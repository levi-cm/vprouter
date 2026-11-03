# Task 8c driver diagnostic independent source review

Overall: **PASS** for the frozen source change and local unit/static verification.
Reviewed on 2026-11-03 in `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`.
No runtime, timing, performance, experiment or acceptance conclusion follows.

## Findings

- Critical: none found.
- Important: none found.
- Minor: none found.

There is therefore no defect-specific failure scenario to report. The concrete
failure scenarios checked below include missing/backwards CPU clocks, invalid
constructor scalars, repeated constructor attempts, foreign export, counter
saturation, broken writers and malformed reader input.

## Scope and independent preservation proof

Read the full driver-cost brief, bootstrap408 diagnosis, driver-cost plan review,
implementation report and `docs/rust-v2/IMPLEMENTATION.md`. Treated the report and
its logs as claims; independently checked source and reran the required checks.
The reader/README changes were pre-existing and separately owned.

Independent HEAD/current SHA256 values for
`crates/vprouter-launch/src/attachment/operational/bootstrap.rs` are respectively:

- `da65fe12514a8f668f10d83cb4a668d9d59f0dd6faa26edf6487d9edab6f9d22`
- `ae7bf47ce1868c070333c86fdacfa94d4c92347bbf04e7d4b3de0966b2e7912f`

A fresh comparison of every tracked Rust file with HEAD found 181 paths, exactly
one changed and 180 byte-identical. The brief's historical 179/178 count is stale;
this does not conceal an additional changed Rust path. The only tracked changes
observed are the bootstrap source, reader and reader README. No manifests,
dependencies, filters or other tracked Rust source differ from HEAD.

The 22,394-byte prefix before the existing `#[cfg(test)] lab_run` is byte-identical
(SHA256 `953d3bdf7f8ff25b9bc0a030bf150dde1af87f6084c498fc530edce47a876193`).
The existing test gates are bootstrap.rs:635 and :1293. The diagnostics module
extends to EOF. Removing only the observer additions reconstructs both the full
old lab_run (including the inter-item separator) and old lab_diagnostics
byte-for-byte. Thus every change is inside those existing test-only items;
normal non-test source is unchanged. Reproducible proof and verifier are in
`target/task8c-driver-source-review/preservation.json` and `verify.py`.

## Semantic and sampling checks

All bootstrap.rs references below name the reviewed current file.

- bootstrap.rs:666-694 preserves the exact original `Instant`, `$call`,
  `measurements.record`, first-error handling and returned `result` sequence.
  CPU starts immediately before the original Instant at :668-669 and ends
  immediately after the original record at :671-672. There is no eager native
  operand or diagnostic `?` added to the macro. Optional sample failure changes
  only the CPU row, never the original Result or Error.
- The reconstructed full lab_run retains every pre-existing call, `?`, error,
  deadline check, custody observation, short circuit and order. In particular,
  query held/negative/release logic at :756-788 and policy queued/held/release
  logic at :792-835 are unchanged. Constructor/anchor/family placement at
  :696-724 is unchanged. No original enforcement clock or deadline is replaced.
- bootstrap.rs:866-870 wraps exactly the pre-existing Ok(None) sleep. The call
  remains `std::thread::sleep(Duration::from_millis(1))` in that match arm, after
  each successful pending poll, with the original control-flow position. Only
  elapsed observations/bookkeeping surround it. The fault-gated post-error sleep
  at :934 is unchanged and uninstrumented. No sleep was added, skipped or moved.
- bootstrap.rs:1349-1370 uses existing safe, fallible rustix time APIs. Its `?`
  operators are confined to Option-returning conversion helpers. Negative
  seconds/nanoseconds, nanoseconds >= 1e9 and failed checked conversion are
  unavailable samples; no raw OS error is printed. bootstrap.rs:1415-1426 uses
  checked subtraction, counts backwards/missing pairs once as sample_errors,
  retains zero deltas as samples and saturates u64/u128 aggregates. All 13 helper
  discriminants/labels/order remain unchanged at :1299-1348. There is no CPU/wall
  clamping or assertion.
- bootstrap.rs:727-730 attempts the prefix immediately before the first existing
  measured invocation and its CPU start. Only `boot_time()` and the retained
  requested_at scalar are read. The accessor at :221-222 performs no validation
  or context lookup. The lazy closure at :1436-1444 is invoked at most once,
  including after an unsuccessful attempt. Constructor errors at :697 still
  return before this observer/output path. Conversion at :1373-1378 rejects
  nonfinite/negative seconds, nonfinite products and the exclusive 2^128 upper
  bound; checked subtraction rejects a negative delta. The comment documents
  retained f64 precision limits. No new authority is derived from this value.

## Storage, export, output and filter checks

bootstrap.rs:1380-1413 adds one inline fixed 13-row array and fixed scalars.
PhantomData<Rc<()>> prevents Send/Sync without allocating an Rc. No new dependency,
unsafe code, process, thread, FD, lock or heap table is introduced by the observer.
There is no borrow held across measured native work. The two new process-ID reads
are creation at :1409 and the unrestricted first-error stop boundary at :1523;
none occur during clock sampling. Fork copies are private, never merged.

The existing first-error emitted guard and stop_snapshot order remain at
bootstrap.rs:1518-1523. New state is stopped and creator-checked there before
output; :1446-1454 refuses active/foreign export and freezes collection. The old
13 wrapper rows remain at :1561-1569; the unchanged snapshot emission at
:1570-1572 emits the old 30 nested, 24 retained and 15 owner rows (see
`crates/vprouter-launch/src/owned/preparation/lab_cost.rs:445-490`). New output is
appended only at :1573 after those rows. There is no success/constructor-error
output path added.

bootstrap.rs:1456-1480 emits exactly 13 CPU, one sleep and one constructor row,
in the brief's helper order, field order and fixed measurement/grouping literals.
Integer Display and writeln produce canonical unsigned decimal ASCII, one space
between fields and newline termination. New rows contain no PIDs, timestamps,
paths, dynamic labels or error payloads. Constructor counts are each 0/1 and sum
at most one in reachable state. Missing samples produce zero stored duration
with explicit errors, not a zero-cost claim.

Writer errors may stop the new row stream partway through; the original Error
still survives because :1573 discards only the emitter's IO Result and the macro
returns its original result at :693. No unwrap/panic is used in that path. As with
the old diagnostics, successful writes are necessary to obtain complete rows;
a fixed byte bound does not bound blocking time.

Independently reconstructed the literal Rust formatter output in the scratch
verifier (integer/string Display has no locale-dependent formatting). Maximum
u64/u128 widths are 20/39 digits; constructor counts occupy one digit each.
Thirteen CPU rows total 3356 bytes, sleep 221 and constructor 184: **3761 bytes
including newlines**, **15 rows**, maximum **266 bytes including newline** at
policy_queued_negatives. Constructor samples=1/errors=0 has the same width as the
bound fixture's two one-digit fields. The independent maximum fixture is
`target/task8c-driver-source-review/maximum-driver-rows.txt`.

Source-only seccomp verification:

- `crates/vprouter-launch/src/transport_lab.rs:2403-2405` calls admit(true) and
  then the driver. admit at :127-167 checks single-threading, identity and artifact
  admission and installs no seccomp filter.
- `crates/vprouter-launch/src/kernel_base.rs:221-249` checks the AMD64
  0xc000003e / ARM64 0xc00000b7 architecture and loads syscall number. Its common
  list includes libc::SYS_clock_gettime at :342. The match/ALLOW loop at :360-373
  does not read arguments; neither clock ID 3 (thread CPU) nor 7 (BOOTTIME) is
  restricted. The earlier special branch concerns clone only.
- `crates/vprouter-launch/src/kernel.rs:7353-7354` reuses that architecture/syscall
  preamble. Its preceding special branches concern other syscall numbers. The
  runtime list includes clock_gettime at :7680 and permits it through :7715-7717;
  allow_syscall at :7263-7278 checks only the syscall number and returns ALLOW.
  This applies to both target ABIs through libc's architecture syscall constant.
- Publisher/job filters are installed in fork-child branches at kernel.rs:1490
  and :1855, followed by publisher::run_child / job.run at :1494 and :1856.
  These callbacks contain none of the added sampling, and do not reenter the
  measured driver. No filter source differs from HEAD.

These are source permission facts, not proof about additional inherited filters,
live syscall availability, seccomp execution or runtime compatibility.

## Test quality and reader compatibility

All seven new tests are meaningful and use literal supplied clocks/durations,
with no elapsed/CPU threshold. They check behavioral boundaries rather than
source text:

- bootstrap.rs:1580: positive/zero deltas and every missing/backwards pair;
- :1602: distinct per-helper counts and durations, catching accidental merging;
- :1617: malformed Timespec and invalid/nonfinite/out-of-range f64 conversion;
- :1642: successful/zero/invalid prefixes and no retry after failure;
- :1660: independent count/duration saturation and exact requested sleep charge;
- :1690: active/foreign export refusal, stop idempotence and frozen collection;
- :1712: byte bounds and BrokenPipe propagation from emit.

Original error preservation is established by exact macro/control-flow review,
together with Option-only failure handling and discarded writer errors; these
unit tests do not claim an end-to-end forced-syscall-failure runtime exercise.
All existing tests remain. Both nested bounded-stack admission fixtures passed.

The scratch verifier generated synthetic stderr containing the boundary, all
82 old rows and 15 new rows directly from the writer's literal format strings.
It exercised the actual current reader CLI, not a reader reimplementation:

- valid complete zero-CPU samples: accepted, exit 0;
- unavailable CPU/prefix samples with explicit errors: accepted, exit 0;
- corrupted query_source CPU calls versus old wrapper calls: refused, exit 1;
- corrupted CPU measurement literal: refused, exit 1.

Rejected variants created no output. Accepted outputs are mode 0600 under the
reader's normal behavior. Fixtures/logs/results are confined to
`target/task8c-driver-source-review/`. Reader source references:
`tools/rust-v2-lab/parse-bootstrap-cost-diagnostics.py:196-248` validates the new
fields/counts; :266-269 creates the exclusive output and applies its mode. This
compatibility check does not replace the reader's separate independent review.

## Commands and results

Fresh required commands, executed sequentially by the scratch Python runner;
full combined stdout/stderr logs are retained in the review scratch directory:

```text
cargo test -p vprouter-launch --lib --locked
  exit 0; 171 passed, 0 failed, 0 ignored; cargo-test.log
cargo fmt --all --check
  exit 0; cargo-fmt.log
cargo clippy -p vprouter-launch --lib --tests --locked -- -D warnings
  exit 0; cargo-clippy.log
python3 target/task8c-driver-source-review/verify.py
  exit 0; preservation, byte-bound and four reader assertions passed
```

The exact four reader invocations made by verify.py (absolute scratch paths were
passed by the script; shown here relative to this worktree for readability):

```text
python3 tools/rust-v2-lab/parse-bootstrap-cost-diagnostics.py target/task8c-driver-source-review/valid.json target/task8c-driver-source-review/valid-parsed.json
python3 tools/rust-v2-lab/parse-bootstrap-cost-diagnostics.py target/task8c-driver-source-review/corrupt_cpu_count.json target/task8c-driver-source-review/corrupt_cpu_count-parsed.json
python3 tools/rust-v2-lab/parse-bootstrap-cost-diagnostics.py target/task8c-driver-source-review/corrupt_literal.json target/task8c-driver-source-review/corrupt_literal-parsed.json
python3 tools/rust-v2-lab/parse-bootstrap-cost-diagnostics.py target/task8c-driver-source-review/unavailable.json target/task8c-driver-source-review/unavailable-parsed.json
```

Read-only Git commands used: `git status --short`, `git diff -- crates/`,
`git diff --name-only`, `git diff --check`, `git branch --show-current`,
`git ls-files '*.rs'`, and `git show HEAD:<path>` for each tracked Rust path.
All succeeded; diff --check reported no whitespace errors. Inspection used
`cat`, `nl -ba`, `sed -n`, `rg -n`, `rg --files`, Python pathlib/hashlib/json and
subprocess. Initial lookups of root IMPLEMENTATION.md, tests/transport_lab.rs and
lab_admission.rs found no such path; corrected to the actual files above. These
lookup errors did not affect verification. No Git mutation was performed.

The existing ARM64 log was read, not rerun:
`target/task8c-driver-source-local/cargo-arm64.log` reports ring's missing
`aarch64-linux-musl-gcc`. This known cross-C-toolchain blocker is noted without
failing this source review. No ARM64-specific source defect was found; ARM64
compilation remains unverified. No installation or workaround was attempted.

Only this new review document and permitted scratch files were written. No
tracked source edit, commit/stash/push/checkout, subagent, VM, SSH, Docker,
privileged action or native lab execution was performed.

PASS: frozen driver diagnostic source satisfies the reviewed brief.
Preservation: one changed Rust file; normal source and original driver semantics retained.
Checks: 171 tests, formatting and strict Clippy passed independently.
Output: 15 rows, 3761/266-byte bounds; valid reader input accepted and corrupt input refused.
Limits: ARM64 cross-toolchain blocked; runtime, timing and acceptance remain unverified.
