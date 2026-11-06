# Task 13 implementation report

## Review round 1

OFFLINE FIXES VALIDATED (2026-11-06); independent rereview NOT_RUN.
Full independent review read; I1/I2/M1 confirmed
against the supplied preparation source. Starting HEAD c0c730d2a216d68ac493a785de732a055f660d3e,
branch rust/v2; index empty. Existing Task13 dirty docs/examples and untracked
release tools preserved. No Rust edits, subagents, network, sudo, VM or Git writes.
The earlier frozen hashes/27-test validation below describe the pre-review source.

Class closure is specified up front in docs/rust-v2/release-review-closure.md:
durable syscall/replay postconditions, all lifecycle plan transitions, and bounded
ELF64 admission/mutation coverage. Native install/update/rollback/uninstall and
reboot recovery have NO executor: their fault-free property is pure blocked
planning, not simulated native durability. Fixture publication/recovery are the
only mutating surfaces. New tests precede production edits. RED/GREEN and final
validation commands/exit codes will be appended here incrementally; logs are
retained under /tmp/task13-review-round1/.

RED checkpoint (production release.py still untouched):
`python3 -B -I tools/release_engineering/test_release.py ReviewLifecycle ReviewDurability ReviewELF`
exit 1, 6 tests, 167 behavioral subcase failures, zero errors
(`/tmp/task13-review-round1/red-behavior.log`). Exact rollback reverse transition
and both managers lack required steps; all four rmdir/final-fsync same-handle/
reopen cases skip parent fsync; existing publish replay also skips root fsync;
both architectures accept malformed newly anchored sizes and header mutations.
Initial test-authoring run had 167 failures and two unsupported reboot-plan
errors; corrected to explicit behavioral refusal assertions before production
edits. Removed an invalid test expectation: increasing p_memsz alone is legal;
out-of-file p_filesz and overflowing virtual ranges are the actual invalid cases.

Syscall RED checkpoint: `python3 -B -I tools/release_engineering/test_release.py ReviewSyscallSweep`
exit 1, 1 test / 8 behavioral failures, zero errors, 15.996s
(`/tmp/task13-review-round1/red-syscalls.log`). Enumerated 215 publication,
67 recovery, 51 publication-replay, 11 empty-recovery and 32 bundle-recovery
boundaries including lock and descriptor cleanup. Each tested before EIO/ENOSPC/
EINTR, after-real-call interruption, same-object/reopen, plus write zero/short.
Eight failures are unsynced root after interrupted rmdir or failed final fsync.
Initial harness run's five EBADF errors were test reuse of already-closed handles
after close interruption; the corrected harness reopens those handles and the
production code was still unchanged throughout RED reproduction.

Focused GREEN checkpoint: `python3 -B -I tools/release_engineering/test_release.py ReviewLifecycle ReviewDurability ReviewELF`
exit 0, 6 tests, 0.106s (`green-behavior.log`).
Rollback now selects/binds retained compatible backup, restores and verifies it
while stopped before controlled restart. All five lifecycle plans carry ordered
quarantine/ownership/stop/verify and explicit compatible release+state-or-offline
failure policy; reboot recovery is a pure current-pair declaration. Both empty
recovery and identical publish replay fsync root before success. ELF admission
validates complete headers, sizes, bounded tables/ranges, static membership,
address overflow, LOAD overlap/entry and section shape for both targets.

Full GREEN checkpoint: `python3 -B -I tools/release_engineering/test_release.py`
exit 0, 34 tests, 23.228s (`green-full.log`), including the exhaustive syscall
sweep: 215 publish, 67 recover, 52 publish-replay, 12 empty-recovery and 32
bundle-recovery boundaries. The two added boundaries are replay root fsyncs.

Related ELF-class RED: extended sweep to all256 values of each e_ident byte,
both minimal and section-bearing prefix truncations, physical overflow and valid
large memory declarations. Added valid TLS/PHDR/array fixtures and invalid TLS
filesz>memsz, PHDR table binding, and fixed-width array entry sizes.
`python3 -B -I tools/release_engineering/test_release.py ReviewELF` exit 1,
4 tests / 14 behavioral failures, no errors, 0.038s (`red-elf-related.log`).
These related size invariants were fixed before final validation (next checkpoint).

Related ELF GREEN: `python3 -B -I tools/release_engineering/test_release.py ReviewELF`
exit 0, 4 tests, 0.036s (`green-elf-related.log`). Subsequent full run exit 0,
35 tests / 22.666s (`final-python.log`), including 3096 syscall fault/replay
cases across 378 enumerated boundaries (before faults/after interruptions,
same-handle/reopened, zero/positive-short writes).

Final field-mask self-review expanded section flags to EVERY bit with independent
gABI OS/processor masks. RED command:
`python3 -B -I tools/release_engineering/test_release.py ReviewELF.test_generated_reserved_flag_bits_and_valid_os_processor_bits`
exit 1, 1 test / 40 behavioral failures, zero errors (`red-elf-flags.log`):
the newly added shape parser's section flag mask was shifted one byte, admitting
reserved high bits and refusing valid OS/processor bits. Corrected the mask;
rerunning all five ReviewELF methods is recorded in `green-elf-final.log`.
No such mask defect was present in the original parser (which did no flag checks).

### Review round 1 validation and limits

`python3 -B -I tools/release_engineering/test_release.py ReviewELF`: exit 0,
5 tests / 0.043s (`green-elf-final.log`). Full final2 run: exit 0,
36 tests / 23.579s (`final2-python.log`), 378 durable syscall boundaries and
3096 injected fault/replay cases. Every ident byte is swept over all256 values
(8192 cases over both architectures), plus all header-field boundary mutations,
section fields/flag bits, program flags, static segments, LOAD overlap, PHDR/TLS,
array sizes, overflow and both fixture prefix truncations. Both newly anchored
malformed-size packaging scenarios refuse for both targets.

The lifecycle test additionally traps ALL filesystem/lock syscall families used
by this module while producing install/update/rollback/uninstall/reboot-recovery
plans for both managers, and asserts zero reboot writes/removals/exchange. A
fresh full run after that test strengthening is recorded below before handoff.

FINAL GREEN: `python3 -B -I tools/release_engineering/test_release.py` exit 0,
36 tests / 22.496s (`/tmp/task13-review-round1/final3-python.log`); 378 durable
syscall boundaries / 3096 fault-replay cases. This supersedes final2. No
implementation or test changes followed this run. Source bindings:

```text
db5c876a3f30a734385d357a6beffdea5ac0c38b3ceb54d3a98d6fddea5ad582  tools/release_engineering/release.py
617d8b8a587f0113db0de329530c5328a1b260cfc58de88abb6fb5c20bae12a2  tools/release_engineering/test_release.py
```

Required checks (all Python uses -B -I):

| Command | Exit | Evidence |
| --- | --- | --- |
| `cargo fmt --all -- --check` | 0 | `final-fmt.log`; no builds/tests/Clippy repeated |
| `python3 -B -I /tmp/task13-review-round1/update-evidence.py` | 0 | updates only public preparation evidence; anchor unchanged |
| `python3 -B -I /tmp/task13-review-round1/validate.py` | 0 | `final-validation.log`; py_compile both Python files to private temporary bytecode, JSON parsing both new Task13 JSON files, rebuilt fixture exact anchor/member sizes/hashes, source hashes, preserved review/lock/acceptance and owned-file whitespace |
| `git diff --check` | 0 | tracked whitespace clean |
| `git diff --name-only -- '*.rs' Cargo.lock Cargo.toml rust-toolchain.toml` | 0 / empty | no Rust/Cargo/toolchain changes; earlier workspace tests remain applicable |
| `git diff --cached --name-only` | 0 / empty | index preserved; no staging/commit/push |

Review file SHA256 remains
`eae8a5230eb76c2d01ccbb969933575efbc600c465675c9cef86590b55c9fa42`.
HEAD/branch remain c0c730d2a216d68ac493a785de732a055f660d3e / rust/v2.
Cargo.lock, acceptance ledger and fixture anchor remain exactly as frozen below.
Preparation evidence now records the failed first review and fixes awaiting
rereview; it does not imply an independent PASS. Round1 touched only:
tools/release_engineering/{release.py,test_release.py}, this report,
docs/rust-v2/{release-preparation.md,release-validation-recovery.md,
release-security-tests.md,release-preparation-evidence.json,release-review-closure.md}.
Existing agent-guide/configuration/schema/compatibility/examples work was retained.

Remaining risks / NOT_RUN: native lifecycle syscall fault sweeps have no executor
to exercise; pure-plan invariants and fixture storage are the implemented scope.
Reopen injection models descriptor teardown/control-flow interruption, not
SIGKILL, lost device writes or physical crash durability. ELF checks are a bounded
shape profile, not all symbol/relocation/instruction semantics, real compilation,
static functionality or ARM execution. Native compatible state restoration,
ownership receipts, install/reboot/update/rollback/uninstall, systemd/runit
enforcement, hardware durability, platform/client/capture/performance/canary/soak
and release acceptance remain NOT_RUN. No privileges, network, VM, subagents,
Git writes, services, signing or publication occurred; release_ready remains false.

Status: IMPLEMENTED / OFFLINE_PREPARATION_ONLY; final required validation PASS. Base rust/v2
c0c730d2a216d68ac493a785de732a055f660d3e; initially clean tree and index.
Task8c runtime/ARM/client acceptance OPEN. acceptance.json must remain unchanged.
No subagents, network, sudo, services, VM, publication, signing or Git writes.

## Design and owned files (incremental)

Python standard library under tools/release_engineering, following existing
Python offline artifact/context tools. No persistent Python/runtime dependency,
Rust dependency or activation CLI. Pure bytes/manifest functions generate disabled
service drafts and hypothetical ownership-checked plans; no plan executor exists.
Only fixture-marked private tempdirs can publish/verify bundles. No archives
are emitted, eliminating tar/zip extraction/member-name ambiguity.

Service drafts use inert /usr/bin/false entrypoints and runit down files; missing
native readiness/cgroup/watchdog enforcement is explicitly blocked, never implied
by ordering text. Minimal draft bounding set is empty because no native launch
is authorized; integrated helper capabilities remain a future reviewed gate.
Artifact metadata is canonical, sorted, bounded and epoch-fixed; unsigned integrity
can never establish release readiness. SBOM derives offline from Cargo.lock and
both pinned program inventories. Expected external bundle digest anchors mutation
checks; no unsigned self-consistency check authenticates a publisher.

## Test inventory and RED evidence

Pending: service/ownership, artifact mutation/path/type/time, publication fault
and recovery/idempotence tests, schema/examples checks; exact commands/logs below.

## NOT_RUN and open risks

All real installation/update/reboot/rollback/uninstall, systemd/runit behavior,
watchdog/crash/freeze/OOM/Docker restart/capture/client, actual migration/state
backup/restore, ARM execution, performance/canary/soak and release qualification
NOT_RUN: preparation-only scope and Task8c OPEN; no privileges/network/VM allowed.
Real static release builds pending memory/toolchain assessment. No signing keys.
Filesystem fixture tests cannot prove physical power-loss durability or defeat a
concurrent malicious same-UID/root writer. Plans are public expected data, not
native ownership receipts. Independent review NOT_RUN (no delegation authorized).

## Final validation

PENDING. All Cargo runs will be strictly sequential with CARGO_BUILD_JOBS=4,
--locked --offline -j 4 for builds/tests/Clippy. No foreign process may be killed.

## Implementation checkpoint 1

`python3 -B -I tools/release_engineering/test_release.py`: exit1 behavioral
missing-generator RED (1 failure), log red-services.log; exit0 after generator.
Expanded suite: exit1 (6 explicit missing-API assertions, 1 service pass), log
red-plans-artifacts.log. First implementation found bundle-name grammar excluded
underscore in x86_64 (2 errors, not behavioral RED); fixed grammar. Seven tests
now pass, exit0, green-plans-artifacts.log. Every artifact/member/metadata byte
mutation and missing/extra member, ELF machine/dynamic/header and unsigned release
promotion are exercised. More filesystem and ownership closure tests next.

Toolchain inspection: Rust1.97.0 and both musl Rust targets are installed, but
`target/toolchains` points at an empty retained /DATA/vprouter-lab/toolchains;
no Zig or musl-gcc is on PATH. Existing practice requires cached Zig CC wrappers
plus rust-lld, static relocation (testing-2026-10-26.md, Task7 report).
Memory available ~3443MiB on6741MiB host,12GiB swapped. Full cross-target release
builds NOT_RUN: missing pinned cross-C compiler/wrappers, no network permitted,
and shared memory constraint. Fixture ELF packaging is explicitly not a real
compiled/release artifact or ARM execution claim.

## Checkpoint 2: filesystem publication and behavioral class REDs

Publication test-first suite: exit1, three missing-FixtureStore assertions,
red-publication.log (not an existing-behavior regression). Initial implementation
had development errors: O_NOATIME requires inode ownership on root-owned ancestors;
ancestor traversal now omits it while private fixture data reads retain it.
Internal reserved dot names needed separate admission through the flat-name grammar.
Those two exploratory error outputs were not separately retained on disk; the
session tool outputs retain them. A third failed sweep is retained as
failed-publication-atime.log: tests' ordinary public reads updated access times.
Reproducibility constrains file/directory mtime=epoch0, not read-dependent atime or
unassignable ctime. Both atime/ctime are excluded from published metadata; ctime
still participates in concurrent-read drift pins. green-publication-mtime.log:
exit0,10 tests;156 before/after checkpoints interrupted and recovered, repeated
publish bytes identical. No actual power-loss or process-kill claim.

Class closure behavioral RED: red-class-closure.log, exit1,3 failures: missing
real release-dir ownership; pinned role/path substitution accepted; undeclared
Cargo.lock metadata accepted. Fix adds owned immutable release descriptor and
optional complete binary-hash inventory, exact role/path mapping, strict lock
shape. These are actual assertion failures against implemented behavior.

Filesystem uses descriptor-relative NOFOLLOW checks for ALL ancestors/leaves,
pre-open type/owner/link/mode admission, bounded reads/enumeration, inode/content
checks before/after data access, retained flock identity, root-chain identity,
O_EXCL writes, partial-write loops, file fsync, rename and parent fsync. Explicit
recover validates EVERY pending member/prefix before deletion; unknown evidence
is retained. Store close is terminal. Cooperative same-UID boundary is explicit:
stdlib directory rename plus private lock is not a kernel CAS against malicious
root/same-UID mutation in the final check/rename interval.

## Checkpoint 3: strict boundaries and retained rollback

StrictBoundaries RED: red-strict-boundaries.log, exit1: missing preflight/build
recipe APIs (2 API assertions), and existing FixtureStore accepted changed ancestor
permissions (1 behavioral failure). Corrected retained chain mode/UID/GID checks;
preflight is public-declaration-only, all eligible hosts still install_allowed=false.
Seventeen-test expanded suite passed, exit0, green-strict-boundaries.log.

PreservationAndBounds RED: red-rollback-preservation.log, exit1: pure update plan
incorrectly listed old immutable release paths for removal (behavioral assertion).
Fixed update/rollback retain ALL prior real release paths; uninstall remains exact
current-manifest only. Other controls in the same run passed: directory mtime,
FIFO, sparse oversized file, changed lock bytes, real31-byte short writes and
zero-write refusal with explicit pending recovery. No host resources touched.

Documentation drafts added: release-preparation.md, release-validation-recovery.md,
release-compatibility.md, release-security-tests.md, configuration.schema.json;
agent-guide.md links them. Existing one/five/mixed fixtures reused without keys/
paths being opened. External JSON Schema meta-validation NOT_RUN: jsonschema not
installed; no download allowed. Shape JSON parsing and binding Rust example tests
will run. JSON Schema explicitly supplements, never replaces Rust semantics.

## Checkpoint 4: negative/mutation class completion

Expanded controls passed (23 tests, green-recovery-custody.log, exit0): before/after
each of17 pending-file unlinks (34 recovery interruptions), actual lock contention
without resetting inode, missing-lock refusal, and pre-data-open proof for symlink,
hardlink, FIFO and permissive files. Existing156 publish checkpoints remain covered.
These were controls added to implemented behavior, not claimed as individual REDs.

BundleScope RED: red-sbom-member-scope.log, exit1,2 actual behavioral failures:
SBOM omitted supplied-binary hashes, and unknown extra bundle members were read
before eventual verification refusal. Fix adds separately scoped artifact components
and requires the COMPLETE closed bundle filename set BEFORE any payload data open.
Pinned program inputs remain distinct and cannot stand in for supplied binaries.

No test adds native authority or production commands. All time-related APIs have
zero host-clock inputs; metadata epoch0 only. Staging/recovery operate on bounded
raw bytes so truncated encodings need no permissive decode. Every public path/name
boundary has reject-only grammar; no normalization, archive extractor or symlink
activation exists. Actual same-UID hostile check/rename CAS remains explicitly
outside the private cooperative fixture boundary.

STARTED `cargo fmt --all -- --check`; log `final-fmt.log`.

Command checkpoint: `cargo fmt --all -- --check`; exit 0; 4.155s; `target/task13-checks/final-fmt.log`.

STARTED `cargo clippy --locked --offline -j 4 --workspace --all-targets -- -D warnings`; log `final-clippy.log`.

Command checkpoint: `cargo clippy --locked --offline -j 4 --workspace --all-targets -- -D warnings`; exit 0; 49.26s; `target/task13-checks/final-clippy.log`.

STARTED `python3 -B -I tools/release_engineering/test_release.py`; log `final-python.log`.

STARTED `cargo test --locked --offline -j 4 --workspace --all-targets`; log `final-workspace.log`.

Command checkpoint: `python3 -B -I tools/release_engineering/test_release.py`; exit 0; 7.113s; `target/task13-checks/final-python.log`.

## Final implementation / unsafe-capability-subprocess inventory

Owned code: tools/release_engineering/{release.py,test_release.py}. Owned docs:
docs/rust-v2/{release-preparation.md,release-validation-recovery.md,
release-compatibility.md,release-security-tests.md,release-preparation-evidence.json,
configuration.schema.json}; small links appended to agent-guide.md,
configuration.md and examples/v2/README.md. This ignored report is retained on disk.
Cargo manifests/lock, Rust runtime/CLI and acceptance ledger remain untouched.

Python imports only standard library, opens no socket, starts no thread/task/
process, uses no ctypes/FFI/unsafe and invokes no subprocess. Pure recipes contain
Cargo argv but execute nothing. Only FixtureStore has filesystem effects, inside
an existing marked private fixture under retained existing flock: descriptor
open/read/write/stat/readdir, fcntl flock, chmod/utime, fsync, mkdir/rename/unlink/
rmdir; no service manager, /etc or /usr path is opened/written. Generated service
path strings and /usr/bin/false scripts are data only. Zero new production Rust
unsafe/capability/seccomp/LSM/syscall code. Draft CapabilityBoundingSet and ambient
sets empty; no claimed native launcher/guard capability profile or runit parity.
Tests temporarily patch own stdlib calls for controlled local faults and execute
real writes/reads in tempdirs; no real secrets, profiles, state or identities.

Actual measured fixture coverage on final code:156 publish before/after fault
boundaries +34 recovery before/after unlink boundaries; 17-file bundle, both
ELF machines62/183,10 synthetic binaries. Fixture anchor SHA256(SHA256SUMS):
7ed7acfb5fee20def96d4c88a3c0762171577daca3042e4fc9d0c326c1fb4962.
Public specimen manifest/SBOM/provenance/checksums retained under
`target/task13-checks/fixture-*`; only synthetic bytes, never executable validation.
Tracked redacted release-preparation-evidence.json binds the same hashes and
honest native/platform/migration NOT_RUN statuses. No private data appears there.

### Mutation and negative-test matrix

| Class | Test / evidence | Result / limit |
| --- | --- | --- |
| Unit/script injection and name/path/encoding aliases | Services, Plans, StrictBoundaries; newline/quote/%/$/slash/dot/Unicode/NUL/oversize | rejects; no command execution |
| Foreign/mutated ownership, unsafe destination, incompatible state, unknown op | Plans, StrictBoundaries | rejects; exact expected records only, not authenticated native receipts |
| Retained rollback release mistakenly deleted | PreservationAndBounds; red-rollback-preservation.log exit1 | fixed; old real release paths explicitly retained |
| Source inventory role/path confusion and undeclared lock metadata | ClassClosure; red-class-closure.log exit1/3 failures | fixed; strict declarations; public data not signed provenance |
| Artifact/manifest/SBOM/provenance/checksum mutation, extra/missing member | Artifacts table on all17 members | rejects, externally retained anchor required |
| Supplied binary missing from SBOM | BundleScope; red-sbom-member-scope.log exit1 | fixed, binary subjects separate from pinned inputs |
| Unknown extra payload read before refusal | BundleScope; same RED log | fixed, exact filename set before payload data open |
| ELF wrong target/type/segment/header, absent target/binary | Artifacts | rejects; minimal valid ELF is still not compilation proof |
| Symlink/hardlink/FIFO/mode/mtime/sparse size/rename-over | FixturePublication, PreservationAndBounds, RecoveryAndCustody | refuses before data open for unsafe types/links/modes; no host policy effects |
| Root/ancestor/lock replacement and permission drift | FixturePublication, StrictBoundaries; red-strict-boundaries.log | fixed; private cooperative-lock boundary, not malicious-root kernel CAS |
| Partial/zero writes, all publish and unlink recovery interruptions |156+34 fault boundaries, real31-byte short writes | repeat recover/publish identical; unknown evidence retained |
| Lock contention/missing lock; terminal close | RecoveryAndCustody, StrictBoundaries | never reset/recreate/delete lock; closed store refuses |
| Host clocks and nonreproducible metadata | zero host-clock inputs, fixed epoch0; changed file/directory mtime refuses | access time/ctime not reproducibility fields; ctime still concurrent-read pin |
| Unsigned input made release-ready | Artifacts, preflight/plan results | ALWAYS refused; no signer/publisher/activation API |

### Validation in progress

Fresh final Python25/25, fmt and workspace strict Clippy pass (command records
above). No Rust crate was touched; workspace Clippy is broader than requested.
Workspace all-target tests currently running strictly after Clippy; exact final
result will be appended. JSON/Python AST parse and final fixture specimen
regeneration PASS. External JSON Schema meta-validation NOT_RUN (package absent).

STARTED `python3 -B -I tools/release_engineering/test_release.py`; log `final2-python.log`.

Command checkpoint: `python3 -B -I tools/release_engineering/test_release.py`; exit 0; 6.881s; `target/task13-checks/final2-python.log`.

## Final self-review: exact scalar types

While the unchanged Rust workspace suite ran, source review found Python dict
comparison treated boolean/int/float aliases as identical ownership records.
`python3 -B -I tools/release_engineering/test_release.py ExactTypes` was RED,
exit1,6 subcase failures (red-exact-types.log): schema true, release_ready0,
uid false, gid0.0, mode420.0 and program inventory schema true were accepted.
Fixed ownership manifest/observation comparisons with canonical typed bytes and
strict integer inventory schema version. This changes only Python preparation
code; Rust source/manifests tested by current workspace run are unchanged.
Final Python suite expanded to27 tests; final2-python log supersedes final-python.

## Frozen source binding

HEAD/branch remain c0c730d2a216d68ac493a785de732a055f660d3e / rust/v2.
Index is empty; Cargo.lock and acceptance.json hashes match baseline, and
acceptance.release_ready is false. Eleven owned code/doc files are bound below.
This incremental report excludes its own hash.

```text
e374bec5f4f1fe3b0f8c0f1bbb636193853eabd8feee5ae6d50b3c583ff87d1e  docs/rust-v2/agent-guide.md
e20c76760cf14d19fb252cc3332ce090dc8f409582f46e92cf2180981d285d51  docs/rust-v2/configuration.md
4b227130745cc4a7f1737ac1b088edd1c7858c58016b12ca8312224a279bc503  docs/rust-v2/configuration.schema.json
17b5ee23e67d42ddf58f2d1d620db121648877584d65c2580cf8da721e1d1c9f  docs/rust-v2/release-compatibility.md
99d5ceeb2b67b87211ed70a45dd96930edc1688dda28af01989dda801eff8632  docs/rust-v2/release-preparation-evidence.json
b2bf6e3611996d00681b80bf7d95c71edcab4076860f8241ef1260f349440b7b  docs/rust-v2/release-preparation.md
05ab11f7e309ab7f87f07c0766e1cc7fc039dd2f0bb6f2249266e2543642baef  docs/rust-v2/release-security-tests.md
94e6165b01a804d236defc10de46086d2287fe253c4ba91d7069a7f83f962e70  docs/rust-v2/release-validation-recovery.md
4bf44a11239adb241a7e5822ef59311580cfbf02a95534e46bf242449aac3d66  examples/v2/README.md
fbe52b26aa4397db347191b4e84411f8e1b9e9fcae68ad3ad6fa8f6110439129  tools/release_engineering/release.py
81125c95dc79c50d3a4e3c6e087ba16d1b0de7b2a36ce2081ca38a81d882acba  tools/release_engineering/test_release.py
```

New documentation local links PASS after excluding code examples from the
checker (the first naive Markdown regex mistook a Python indexing/call expression
for a link and exited1; no broken link was found). JSON and Python AST parsing
PASS. `jsonschema` import exited1/ModuleNotFoundError; meta-validation remains
NOT_RUN, no package was fetched. Rust examples are covered by workspace tests.

### Direct Python command inventory (development checkpoints)

All below from repo root, with `python3 -B -I tools/release_engineering/test_release.py`
as the exact prefix. Unfiltered invocations omit a class argument.

| Class argument | Log | Exit | Observed scope |
| --- | --- | --- | --- |
| none | red-services.log | 1 | missing-generator assertion; not a runtime regression |
| none | red-plans-artifacts.log | 1 |6 missing-API assertions; service control passed |
| none | green-plans-artifacts.log | 0 |7 tests |
| none | red-publication.log | 1 |3 missing-store assertions; other controls passed |
| none | failed-publication-atime.log | 1 |156 subcase errors from ordinary-read atime changes; corrected mtime-only reproducibility contract |
| none | green-publication-mtime.log | 0 |10 tests |
| ClassClosure | red-class-closure.log | 1 |3 actual behavior failures |
| none | green-class-closure.log | 0 |13 tests |
| StrictBoundaries | red-strict-boundaries.log | 1 |2 missing APIs +1 actual ancestor-mode failure;1 control passed |
| none | green-strict-boundaries.log | 0 |17 tests |
| PreservationAndBounds | red-rollback-preservation.log | 1 |retained rollback deletion failure;2 controls passed |
| none | green-preservation.log | 0 |20 tests |
| none | green-recovery-custody.log | 0 |23 tests |
| BundleScope | red-sbom-member-scope.log | 1 |2 actual behavior failures |
| none | green-sbom-member-scope.log | 0 |25 tests |
| ExactTypes | red-exact-types.log | 1 |6 actual scalar-alias subcase failures |

The final frozen Python command/log supersedes earlier successful suite counts.

Command checkpoint: `cargo test --locked --offline -j 4 --workspace --all-targets`; exit 0; 654.535s; `target/task13-checks/final-workspace.log`.

## Final validation — final source

All required local checks PASS. No Rust source was edited during this task,
including during Cargo validation. Python exact-type self-review fix received
a fresh full27-test run; final2-python supersedes initial25-test result.

| Exact command (CARGO_BUILD_JOBS=4 for Cargo) | Exit | Seconds | Result / log |
| --- | --- | --- | --- |
| `cargo fmt --all -- --check` | 0 | 4.155 | clean; `final-fmt.log` |
| `cargo clippy --locked --offline -j 4 --workspace --all-targets -- -D warnings` | 0 | 49.26 | workspace strict Clippy clean; `final-clippy.log` |
| `python3 -B -I tools/release_engineering/test_release.py` | 0 | 6.881 | 27 passed; 0 failures; `final2-python.log` |
| `cargo test --locked --offline -j 4 --workspace --all-targets` | 0 | 654.535 | 569 passed; 0 failed; 17 ignored; `final-workspace.log` |

Workspace totals count ordinary libtest summaries; custom guest harness SKIP
outputs and ignored native tests are NOT_RUN, not runtime evidence. Existing
workspace Unix/TLS/loopback fixtures ran locally; no external/provider traffic,
real credential/identity access, sudo, VM or service operation was performed.
Every Cargo build/test/Clippy invocation used --locked --offline -j4 with
CARGO_BUILD_JOBS=4 and ran sequentially. Fmt uses its supported arguments only.
No foreign process was killed; existing migration tests signal only their own
fixture children. Python module starts no subprocesses or sockets.

Frozen11-file hashes rechecked after validation: identical to Frozen source
binding above. HEAD/branch/index, lock/toolchain/Rust source and acceptance ledger
unchanged; acceptance.release_ready=false. New/modified owned-file whitespace
checks and git diff --check PASS. No Git staging/commit/push was performed.

### Final NOT_RUN / limitations

Real x86_64+ARM64 release compilation and repeat binary reproducibility: NOT_RUN
(pinned cross-C wrappers/Zig/musl-gcc absent; no network; shared memory constraint).
Synthetic ELF fixture metadata is not a compiled artifact or ARM runtime claim.
External JSON Schema/CycloneDX formal schema validation: NOT_RUN (validator absent).
Independent review: NOT_RUN (implementation delegate must start no subagents).
Systemd/runit install/start/hardening/watchdog/cgroup/LSM enforcement, native
quarantine and client guards, real migration/identity backup/restoration, actual
install/interrupted-update/reboot/rollback/uninstall and ownership recovery,
Docker restart, guard crash/freeze/OOM, hardware torn-write/ENOSPC/EIO/power loss,
ARM execution/platform/client/capture, workload benchmarks/performance/canary/24h
soak and release acceptance: NOT_RUN. PREPARATION ONLY; Task8c remains OPEN.

Runit parity is deliberately unimplemented/blocked; generated down/run/finish
files never imply enforcement. Fixture publication relies on private directories
and a cooperative retained lock; no malicious-root final-rename CAS is claimed.
Unsigned checksums/provenance authenticate no publisher and cannot become
release-ready. Complete prebuilt Go dependency/licenses and executed-build
attestation remain unavailable. Current exact agent instruction for both
managers remains offline validation only. No release/migration guide was published.

## Review round 2 (controller)

`task-13-rereview.md`: I1/I2/M1 confirmed fixed; two Minor reproduced. M2: SHT_REL/SHT_RELA
section headers accepted a zero/wrong sh_entsize. Fixed by the controller in
release.py (`invalid ELF relocation section header`: entsize 24 for RELA, 16 for REL,
size multiple of it) with `ReviewELF.test_relocation_section_headers_require_the_fixed_entry_size`
(RED: 16 subtest failures with the check disabled; GREEN with it; whole suite 37 tests OK,
3096 publication fault/replay cases). M3: inner ELF note-record structure is not parsed;
resolved by narrowing the documented claim (release-preparation.md) rather than adding a
parser. No Rust source changed in this task (git diff -- crates empty), so the earlier
workspace result (569 passed, 0 failed, 17 ignored) stands. Real cross builds, systemd/
runit execution, signing and release acceptance remain NOT_RUN; release_ready=false.
