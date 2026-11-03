# Task 8c driver diagnostic source report

Implemented the approved driver-only diagnostic in the existing cfg(test)
lab_run and lab_diagnostics code of `crates/vprouter-launch/src/attachment/operational/bootstrap.rs`. No other Rust source was edited.
This report records source/unit/static verification only. Native/VM/filter-clock
experiments, timing evidence, performance and acceptance are NOT_RUN.

## Change and preservation

Added a separate fixed 13-entry CPU array and fixed sleep/constructor scalars.
ThreadCPUTime samples immediately precede the original Instant start and follow
the unchanged original measurements.record statement. Exactly the existing
success-loop Ok(None) 1ms sleep receives elapsed observations; its call and
requested duration remain intact. A lazy once-only BOOTTIME/requested_at sample
precedes the first QuerySource wrapper. The original requested_at scalar is
read without context/deadline/revalidation. Constructor errors before that
wrapper retain their original no-driver-output path.

All sample failures become absent optional values; malformed/negative Timespec,
missing/backwards pairs, nonfinite/negative/out-of-range scalar conversions are
rejected. Option-local checked arithmetic cannot propagate into the native
Result. The macro still returns its original result, retains all original `?`
operators and error handling, and its original error is copied into the unchanged
failure call. Writer errors are ignored only at the existing failure boundary.
The original emitted guard, old output loops, native calls, short circuits,
constructor/queue/anchor/family placement, held coverage and post-error collection
sleep are unchanged by exact diff inspection.

The new state has a PhantomData<Rc<()>> marker (neither Send nor Sync), saves PID
at Measurements creation, and checks actual PID exactly at the existing
unrestricted stop/export boundary after the old stop_snapshot. It freezes there;
foreign creators cannot export. No sample gets PID/TID. There is no new thread,
FD, dependency, lock, heap table, unsafe code or collector-State change.

Before-edit SHA256: `da65fe12514a8f668f10d83cb4a668d9d59f0dd6faa26edf6487d9edab6f9d22`.
After-edit SHA256: `ae7bf47ce1868c070333c86fdacfa94d4c92347bbf04e7d4b3de0966b2e7912f`.

The fresh tracked set contains **181** Rust paths, rather than the brief's stale
179. The all-path before/after SHA256 maps prove exactly this one changed path,
**180 unchanged**, zero added and zero missing tracked Rust paths. Evidence:
`target/task8c-driver-source-local/rust-before.json`, `rust-after.json`,
`preservation-proof.json`, `bootstrap-before.rs`, and `bootstrap.diff`.
The 22,394-byte source prefix preceding the existing cfg(test) lab_run is
byte-identical, SHA256 `953d3bdf7f8ff25b9bc0a030bf150dde1af87f6084c498fc530edce47a876193`. The separator between
lab_run and the existing cfg(test) lab_diagnostics module is also byte-identical;
that module extends to EOF. Thus every changed byte is inside the two existing
test-only items. Removing exactly the added CPU/prefix statements and sleep wrapper also reconstructs the original lab_run byte-for-byte (recorded in preservation-proof.json). No normal-source body changed. Existing reader/README dirty
work was not edited. No Git mutation was performed.

## Syscall/filter source findings

AMD64 and ARM64: PASS for source permission of the selected clock IDs, without
filter changes. `transport_lab.rs:2403` enters the driver after `admit(true)`;
admission checks single-threading, identity and artifact binding and installs no
filter. Restricted publisher/job filters are installed in fork child branches
(`kernel.rs:1490`, `:1855`), which run the fixed publisher/job and do not reenter
lab_run or measured!. Parent samples remain outside those child callbacks.

Additionally, the base filter in `kernel_base.rs:221` validates AMD64 arch
0xc000003e or ARM64 arch 0xc00000b7 and lists libc::SYS_clock_gettime at line342.
Its common allow loop returns SECCOMP_RET_ALLOW on syscall-number match, with
no arg0 clock restriction. The runtime filter (`kernel.rs:7353`) likewise lists
clock_gettime at line7680 and uses allow_syscall at line7716, without a clock-ID
restriction. Thus CLOCK_THREAD_CPUTIME_ID (3) and CLOCK_BOOTTIME (7) are allowed
for both target ABIs; libc selects the ABI syscall number. Base seccomp is
installed by seccomp() in worker_exec; runtime_filter(role) is installed by
actual_exec. No claim is made about an external host's additional inherited
filter or runtime clock availability. No clock/filter experiment was run.

## Output and tests

At the old first-error path, the new rows follow the old wrapper loop and nested
snapshot.emit (which emits nested/retained/owner rows). In helper order they emit
13 CPU rows, then sleep, then constructor, with the brief's exact markers,
field order, fixed measurement/grouping literals, unsigned decimal and newline.
No raw clock, identity or OS error payload is printed by the new code.

The writer was exercised with u64/u128 maximum counters/durations and constructor
0/1 counters: **15 lines, 3761 bytes including newlines, longest line 266 bytes**,
exactly the brief's 3761/266 bound. The bound fixture also covers a BrokenPipe
writer. Seven added tests use literal clock/duration values and cover valid/zero,
missing/error/backwards pairs, distinct per-helper counts, malformed Timespec,
scalar conversion errors and range, constructor once-only even after failure,
independent count/duration saturation, active/stopped/foreign export, freeze after
stop and writer failure. No clock-duration thresholds are added. Existing tests
are retained, including both nested bounded-stack admission fixtures. The
optional synthetic reader invocation was not needed/run; reader source was only
read and remains owned by its separate reviewer.

## Exact checks and results

All full stdout/stderr logs and exact source diff are under
`target/task8c-driver-source-local/`.

- `cargo test -p vprouter-launch --lib --locked`: exit 0; `cargo-test.log`.
- `cargo fmt --all --check`: exit 0; `cargo-fmt.log`.
- `cargo clippy -p vprouter-launch --lib --tests --locked -- -D warnings`: exit 0; `cargo-clippy.log`.
- `rustup target list --installed`: exit 0; `installed-targets.log`.
- `cargo check -p vprouter-launch --lib --tests --locked --target aarch64-unknown-linux-musl`: exit 101; `cargo-arm64.log`.

Final launch lib result: 171 passed, 0 failed, 0 ignored (including the seven new
collector tests and the nested admission fixtures). Formatting and strict Clippy
passed. Read-only `git diff --check` also exited 0. Formatting was applied only to
the owned file with `rustfmt --edition 2024` before the required workspace check.

The first test invocation passed 170 tests before the distinct-helper test was
added; its full log is cargo-test-initial.log. Initial strict Clippy rejected the
test module placement; moved that module to the end of lab_diagnostics, retained
cargo-clippy-initial.log, and reran the approved checks on the final source.
The initial Clippy failure is reproduced verbatim:

```text
error: items after a test module
    --> crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1484:5
     |
1484 |     mod driver_tests {
     |     ^^^^^^^^^^^^^^^^
...
1643 |     pub(super) struct Counters {
     |     ^^^^^^^^^^^^^^^^^^^^^^^^^^
...
1653 |     pub(super) struct Measurements {
     |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
...
1658 |     impl Measurements {
     |     ^^^^^^^^^^^^^^^^^
     |
     = help: for further information visit https://rust-lang.github.io/rust-clippy/rust-1.97.0/index.html#items_after_test_module
     = note: `-D clippy::items-after-test-module` implied by `-D warnings`
     = help: to override `-D warnings` add `#[allow(clippy::items_after_test_module)]`
     = help: move the items to before the test module was defined

error: could not compile `vprouter-launch` (lib test) due to 1 previous error
warning: build failed, waiting for other jobs to finish...
error: could not compile `vprouter-launch` (test "producer_lab") due to 1 previous error
error: could not compile `vprouter-launch` (test "admission_lab") due to 1 previous error
error: could not compile `vprouter-launch` (test "actual_lab") due to 1 previous error
error: could not compile `vprouter-launch` (test "execution_probe") due to 1 previous error
error: could not compile `vprouter-launch` (test "transport_lab") due to 1 previous error
error: could not compile `vprouter-launch` (test "execution_lab") due to 1 previous error
```

Installed targets: aarch64-unknown-linux-musl, x86_64-unknown-linux-gnu,
x86_64-unknown-linux-musl. ARM64 lib/tests compilation was attempted as required,
but blocked by the missing cross C compiler in ring's build dependency. No
installation or workaround/retry was performed. The failure is reproduced
verbatim below; cargo-arm64.log retains the entire check output:

```text
error: failed to run custom build command for `ring v0.17.14`

Caused by:
  process didn't exit successfully: `/DATA/AppData/vprouter-rust-v2/target/debug/build/ring-df8216736a5915c3/build-script-build` (exit status: 1)
  --- stdout
  cargo:rerun-if-env-changed=CARGO_MANIFEST_DIR
  cargo:rerun-if-env-changed=CARGO_PKG_NAME
  cargo:rerun-if-env-changed=CARGO_PKG_VERSION_MAJOR
  cargo:rerun-if-env-changed=CARGO_PKG_VERSION_MINOR
  cargo:rerun-if-env-changed=CARGO_PKG_VERSION_PATCH
  cargo:rerun-if-env-changed=CARGO_PKG_VERSION_PRE
  cargo:rerun-if-env-changed=CARGO_MANIFEST_LINKS
  cargo:rerun-if-env-changed=RING_PREGENERATE_ASM
  cargo:rerun-if-env-changed=OUT_DIR
  cargo:rerun-if-env-changed=CARGO_CFG_TARGET_ARCH
  cargo:rerun-if-env-changed=CARGO_CFG_TARGET_OS
  cargo:rerun-if-env-changed=CARGO_CFG_TARGET_ENV
  cargo:rerun-if-env-changed=CARGO_CFG_TARGET_ENDIAN
  cargo:rerun-if-env-changed=CC_aarch64-unknown-linux-musl
  CC_aarch64-unknown-linux-musl = None
  cargo:rerun-if-env-changed=CC_aarch64_unknown_linux_musl
  CC_aarch64_unknown_linux_musl = None
  cargo:rerun-if-env-changed=TARGET_CC
  TARGET_CC = None
  cargo:rerun-if-env-changed=CC
  CC = None
  cargo:rerun-if-env-changed=CROSS_COMPILE
  CROSS_COMPILE = None
  cargo:rerun-if-env-changed=CC_ENABLE_DEBUG_OUTPUT
  cargo:warning=Compiler family detection failed due to error: ToolNotFound: failed to find tool "aarch64-linux-musl-gcc": No such file or directory (os error 2)
  cargo:rerun-if-env-changed=CPATH
  cargo:rerun-if-env-changed=C_INCLUDE_PATH
  cargo:rerun-if-env-changed=CPLUS_INCLUDE_PATH
  cargo:rerun-if-env-changed=OBJC_INCLUDE_PATH
  cargo:rerun-if-env-changed=OBJCPLUS_INCLUDE_PATH
  cargo:rerun-if-env-changed=COMPILER_PATH
  cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH
  cargo:rerun-if-env-changed=GCC_EXEC_PREFIX
  cargo:rerun-if-env-changed=CRATE_CC_NO_DEFAULTS
  CRATE_CC_NO_DEFAULTS = None
  cargo:rerun-if-env-changed=CC_ENABLE_DEBUG_OUTPUT
  cargo:warning=Compiler family detection failed due to error: ToolNotFound: failed to find tool "aarch64-linux-musl-gcc": No such file or directory (os error 2)
  CRATE_CC_NO_DEFAULTS = None
  cargo:rerun-if-env-changed=CFLAGS
  CFLAGS = None
  cargo:rerun-if-env-changed=TARGET_CFLAGS
  TARGET_CFLAGS = None
  cargo:rerun-if-env-changed=CFLAGS_aarch64_unknown_linux_musl
  CFLAGS_aarch64_unknown_linux_musl = None
  cargo:rerun-if-env-changed=CFLAGS_aarch64-unknown-linux-musl
  CFLAGS_aarch64-unknown-linux-musl = None
  CFLAGS = None
  TARGET_CFLAGS = None
  CFLAGS_aarch64_unknown_linux_musl = None
  CFLAGS_aarch64-unknown-linux-musl = None
  cargo:warning=Compiler family detection failed due to error: ToolNotFound: failed to find tool "aarch64-linux-musl-gcc": No such file or directory (os error 2)
  cargo:warning=Compiler family detection failed due to error: ToolNotFound: failed to find tool "aarch64-linux-musl-gcc": No such file or directory (os error 2)

  --- stderr


  error occurred in cc-rs: failed to find tool "aarch64-linux-musl-gcc": No such file or directory (os error 2)


warning: build failed, waiting for other jobs to finish...
```

## Limits

No native or VM run, production action, privileged operation, SSH/Docker action,
workspace-wide artifact build, commit/stash/push/checkout, or subagent was used.
ARM64 compilation is unverified because of the toolchain blocker. Source filter
permission does not prove live syscall availability. Byte bounds do not bound
stderr blocking time. f64 requested_at conversion loses clock/representation
precision; BOOTTIME and Instant differ under suspend. CPU includes observer and
kernel work, excludes children, and uses a broader bracket than the original wall
interval. CPU/wall attribution is available only for complete, unsaturated rows
(samples=calls, sample_errors=0, all relevant counters/durations below maxima).
Missing or saturated samples provide no zero-cost inference, exact off-CPU
subtraction, scheduler diagnosis, two-second fit, runtime or acceptance claim.
Root retains reader review, independent source review, runtime preflight, coherent
artifacts and all later experiment/acceptance gates.
