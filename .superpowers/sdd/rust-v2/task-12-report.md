# Task 12 implementation report

Status: REVIEW ROUND 1 REVISED / OFFLINE_PREPARATION_ONLY; required validation PASS.
Independent re-review remains NOT_RUN. See the Review round 1 section below. Base rust/v2
69d4c29012a4a04f2ba1468413df8c84f5c7dde7; initial tree/index clean.
Task8c runtime/ARM/client acceptance remains OPEN. No subagents, sudo, network,
VM, Git staging/commit/push, production paths or real credentials authorized.

## Design checkpoint

Extend vprouter-core's existing schema/allocation preparation layer and descriptor
backed deployment lock. Fixture-only marker required. Inspection reads a closed
allowlist of public legacy assets and metadata ONLY for opaque synthetic state/
profile entries. No secret open/read/copy/delete API. A bounded fingerprinted
plan stages a real public release directory; atomic directory exchange selects
one complete release/config/service/hooks/wrapper set. Identity remains in place.
A checksum journal with generation/step binding records replayable operations;
explicit resume/rollback, never age-based lock breaking. Kernel flock is never
unlinked. All lifecycle actions are typed public obligations/receipts, NOT native
authority. No executor, CLI activation or optional verification flags.

No wall-clock inputs: transaction order uses bounded counters. Adapter timeouts
are bounded integer declarations, not elapsed host observations. No timestamps
in fingerprints. No host clock failure can expire a lock or waive obligations.

## Planned files

core src/migration/{mod,contract,storage}.rs; tests/migration.rs and fixture support;
minimal allocation/lib integration; docs/rust-v2/migration-preparation.md; this
ignored report. Cargo manifests/lock and acceptance ledger must remain unchanged.

## Tests / commands

Commands will run strictly sequentially, CARGO_BUILD_JOBS=4 and
--locked --offline -j 4 for build/test/check/clippy; logs target/task12-checks/.
Behavioral REDs and final exits appended as observed, never inferred.

## Fault-injection coverage (initial plan; final measurements below)

Before/after each create, write chunk, file fsync, rename/exchange, directory fsync
and recovery cleanup. Abrupt process termination and injected I/O errors; resume
and rollback, repeated replay, active tree old-or-new, opaque bytes unchanged.
This is synthetic local filesystem evidence, not hardware power-loss acceptance.

## NOT_RUN / open gates

Owned-guest local legacy deployment with its own established identity/adapters;
real stopped-state backups/restoration; native quarantine/service/identity users;
real clients/captures; Task8c; ARM runtime; platform/reboot/performance/soak and
release acceptance: NOT_RUN. Ignored tests will be fail-if-forced specifications.
Independent review pending. No runtime acceptance or release readiness claimed.

## Final validation

See final results appended below.

Command checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration`; exit 101; 2.18s; `target/task12-checks/red-initial.log`.

Command checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration`; exit 101; 0.45s; `target/task12-checks/red-behavior.log`.

Command checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration`; exit 101; 0.82s; `target/task12-checks/red-classes.log`.

Command checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration`; exit 0; 26.66s; `target/task12-checks/green-initial.log`.

Command checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration recorded_start`; exit 101; 0.42s; `target/task12-checks/red-replay-classes.log`.

Command checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration terminal_reads`; exit 101; 0.07s; `target/task12-checks/red-terminal-drift.log`.

Command checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration recorded_start`; exit 0; 1.21s; `target/task12-checks/green-replay.log`.

Command checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration legacy_optional`; exit 101; 0.28s; `target/task12-checks/red-optional-hostname.log`.

Command checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration json_dispatch`; exit 101; 1.85s; `target/task12-checks/red-json.log`.

Command checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration -- --nocapture`; exit 101; 9.16s; `target/task12-checks/green-expanded.log`.

## Behavioral RED / first GREEN checkpoint

Initial API compilation failed for two test typos (SHA2 array hex formatting and
JSON Value assignment); not behavioral evidence. Corrected scaffold compiled:
red-behavior.log exit101, six failures plus one refusal control; expanded
red-classes.log exit101, eleven failures plus one control. First implementation:
green-initial.log exit0, twelve tests, including full before/after I/O error sweep.

Self-review found two additional classes with real REDs: resume after recorded
start stopped the service and skipped restart (red-replay-classes.log); terminal
apply returned success after active-tree drift (red-terminal-drift.log). Recovery
now repeats the entire typed lifecycle and uses the journal cursor only to avoid
regressing durable progress; terminal queries/reapply refuse drift without changing
the terminal journal. Missing legacy optional hostname and library JSON dispatch
also had behavioral REDs (red-optional-hostname.log, red-json.log).

Expanded harness introduced SIGKILL of its OWN same-executable child at every
before/after boundary (never a Cargo or foreign process). An initial run exposed
a TEST harness race: another thread's fork temporarily inherits CLOEXEC flock FDs
until exec; a concurrent test correctly received Busy. Tests now serialize within
this test executable. Another assertion wrongly required a reversal whose intent
had not yet been durably published: resume may correctly see the prior complete
committed state. The harness now accepts either complete state at that boundary,
and explicit rollback then proves reversal. These are fixture expectation fixes,
not relaxed production refusal rules. Intermediate failed log retained.

Command checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration -- --nocapture`; exit 0; 50.64s; `target/task12-checks/green-fault-sweep.log`.

Command checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration recovery_never_deletes`; exit 101; 0.46s; `target/task12-checks/red-opaque-recovery.log`.

Command checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration recovery_never_deletes`; exit 0; 1.7s; `target/task12-checks/green-opaque-recovery.log`.

Command checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration shape_valid_provenance`; exit 101; 7.56s; `target/task12-checks/red-provenance.log`.

Command checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration shape_valid_provenance`; exit 0; 15.78s; `target/task12-checks/green-provenance.log`.

Command checkpoint: `cargo fmt --all`; exit 0; 4.45s; `target/task12-checks/fmt-write.log`.

Command checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration every_name_path`; exit 0; 4.46s; `target/task12-checks/focused-adversarial.log`.

Command checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration directly_deserialized_plan`; exit 101; 4.57s; `target/task12-checks/red-typed-plan.log`.

Command checkpoint: `cargo fmt --all`; exit 0; 4.0s; `target/task12-checks/fmt-final-source.log`.

Command checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration explicit_empty`; exit 101; 2.04s; `target/task12-checks/red-empty-hostname.log`.

Command checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration legacy_tailnet`; exit 101; 0.43s; `target/task12-checks/red-identity-metadata.log`.

Command checkpoint: `cargo fmt --all`; exit 0; 4.32s; `target/task12-checks/fmt-before-lint.log`.

Command checkpoint: `cargo clippy --locked --offline -j 4 -p vprouter-core --all-targets -- -D warnings`; exit 101; 1.95s; `target/task12-checks/clippy-initial.log`.

Command checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration failure_after_service`; exit 101; 2.05s; `target/task12-checks/red-late-failure.log`.

Command checkpoint: `cargo clippy --locked --offline -j 4 -p vprouter-core --all-targets -- -D warnings`; exit 101; 1.91s; `target/task12-checks/clippy-retry.log`.

Command checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration configured_client_selection`; exit 101; 1.19s; `target/task12-checks/red-client-node.log`.

Command checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration terminal_publication`; exit 101; 0.44s; `target/task12-checks/red-final-drift.log`.

Command checkpoint: `cargo fmt --all`; exit 0; 3.74s; `target/task12-checks/fmt-validation-source.log`.

Command checkpoint: `cargo clippy --locked --offline -j 4 -p vprouter-core --all-targets -- -D warnings`; exit 0; 1.26s; `target/task12-checks/final-clippy.log`.

Command checkpoint: `cargo fmt --all -- --check`; exit 0; 3.83s; `target/task12-checks/final-fmt.log`.

## Final design / class closure checkpoint

Eight source/doc paths are owned: core src/allocation.rs, src/lib.rs,
src/migration/{mod,contract,storage}.rs; tests/{migration,migration_owned_guest}.rs;
docs/rust-v2/migration-preparation.md. This report is the ninth, ignored path.
Manifests/lock, native runtime/netfilter/worker/CLI and acceptance ledger untouched.

- Reused the existing allocation store private-directory admission and flock;
  added crate-private existing-lock acquisition and descriptor access only.
- Closed source/image provenance class: exact synthetic public bundle and image
  bytes now match declared hashes, not merely valid hash spelling (behavioral RED).
- Protected opaque inode set is captured using O_PATH and bound from the plan
  before recovery journal loading/deletion. Every mutation rechecks opaque pins;
  moved-profile-over-pending regression was RED and now passes. No opaque bytes
  enter any engine data-read/copy/hash/delete path.
- Added scoped receipts, explicit unknown-hostname refusal, bounded source maps,
  strict nested duplicate-key JSON parsing, public-input inode/content bindings,
  root/lock replacement and before-exchange alias/hardlink/permission attacks.
- Terminal apply/resume refuse drift without weakening journal state, including
  drift during terminal publication (RED). Raw Serde-invalid plans emit no
  obligations (RED); explicit empty hostname is invalid while absence defaults
  (RED). Public tailnet IPv6/approval metadata is preserved without forwarding
  authority (RED); client policies cannot change preserved primary node (RED).
- Late adapter health failure after service start now requires quarantine FIRST,
  then bounded scoped stop/adapters/all-user checks, before terminal offline;
  no service restart after that failure (RED). If independent quarantine cannot
  be affirmed, no stop ordering is assumed; quarantine-required remains mandatory.
- Journal replay repeats the complete lifecycle, never uses durable cursor to
  skip current stop/identity/server/name/start verification. Final fault sweeps
  now include a custom hook and declared adapter, covering journals after ALL
  adapter operations, not just the zero-dependency case.
- Zero host-time callbacks; integer timeout grammar and bounds tested at every
  adapter operation. No timestamps/automatic stale-lock break. Terminal outcomes
  retain quarantine-required and unverified clients. Ordinary offline data cannot
  authenticate native protection, process exclusivity or secret-content custody.

The initial strict Clippy attempt found one large internal enum and collapsible
ifs; retry found two test loop style findings. These were fixed without suppressing
lints. Logs retained. All behavioural RED commands and intermediate failures remain
in commands.jsonl and the command checkpoints above. Final results below supersede
earlier counts, which preceded adapter-inclusive/scope/provenance hardening.

Command checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --all-targets -- --nocapture`; exit 0; 190.93s; `target/task12-checks/final-core.log`.

Command checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration legacy_instance_grammar`; exit 101; 2.79s; `target/task12-checks/red-legacy-label.log`.

Command checkpoint: `cargo fmt --all`; exit 0; 4.05s; `target/task12-checks/fmt-frozen-source.log`.

Command checkpoint: `cargo fmt --all -- --check`; exit 0; 3.91s; `target/task12-checks/final-fmt-frozen.log`.

Command checkpoint: `cargo clippy --locked --offline -j 4 -p vprouter-core --all-targets -- -D warnings`; exit 0; 1.41s; `target/task12-checks/final-clippy-frozen.log`.

Command checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --all-targets -- --nocapture`; exit 0; 180.91s; `target/task12-checks/final-core-frozen.log`.

Frozen core checkpoint: all 34 migration tests passed; actual kernel short-write control passed; 1624 injected I/O errors and 626 own-child SIGKILL recoveries passed. Core aggregate [162, 0, 15] (passed/failed/ignored). Cross-target and workspace validation still pending. Source/doc hashes remain unchanged.

Command checkpoint: `env CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld RUSTFLAGS=-C relocation-model=static cargo test --locked --offline -j 4 -p vprouter-core --all-targets --target x86_64-unknown-linux-musl -- --nocapture`; exit 0; 197.97s; `target/task12-checks/final-x86_64-musl.log`.

Command checkpoint: `cargo check --locked --offline -j 4 -p vprouter-core --all-targets --target aarch64-unknown-linux-musl`; exit 0; 1.76s; `target/task12-checks/final-arm64-check.log`.

Validation progress checkpoint: frozen x86_64-musl suite exited 0; ARM64 core/all-targets compile exited 0. Final workspace/all-targets suite is still running; no workspace result is claimed at this checkpoint. No concurrent Cargo invocation started.

Command checkpoint: `cargo test --locked --offline -j 4 --workspace --all-targets`; exit 0; 557.84s; `target/task12-checks/final-workspace.log`.


## Final validation (frozen source, real results)

All commands below ran sequentially with CARGO_BUILD_JOBS=4. Every build/test/
check/clippy used --locked --offline -j 4. No ignored test was forced and no
foreign process was killed. Workspace tests were the last Cargo invocation.
The earlier final-core log (31 migration tests) precedes the final short-write/
JSON/legacy-label controls and is superseded by this frozen source cut.

| Exact command | Exit | Result | Seconds / log |
| --- | --- | --- | --- |
| `cargo fmt --all -- --check` | 0 | clean | 3.91s; `final-fmt-frozen.log` |
| `cargo clippy --locked --offline -j 4 -p vprouter-core --all-targets -- -D warnings` | 0 | clean | 1.41s; `final-clippy-frozen.log` |
| `cargo test --locked --offline -j 4 -p vprouter-core --all-targets -- --nocapture` | 0 | 162 passed, 0 failed, 15 ignored | 180.91s; `final-core-frozen.log` |
| `env CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld RUSTFLAGS=-C relocation-model=static cargo test --locked --offline -j 4 -p vprouter-core --all-targets --target x86_64-unknown-linux-musl -- --nocapture` | 0 | 162 passed, 0 failed, 15 ignored | 197.97s; `final-x86_64-musl.log` |
| `cargo check --locked --offline -j 4 -p vprouter-core --all-targets --target aarch64-unknown-linux-musl` | 0 | compile only; no execution | 1.76s; `final-arm64-check.log` |
| `cargo test --locked --offline -j 4 --workspace --all-targets` | 0 | 547 passed, 0 failed, 17 ignored | 557.84s; `final-workspace.log` |

Logs are under target/task12-checks/. Existing workspace TLS/Unix tests are
controlled local fixtures, not external provider/client tests. Privileged custom
lab executables explicitly SKIP. New migration_owned_guest tests: 3 ignored, all
NOT_RUN. ARM64 is compilation ONLY, with no link/execution/kernel claim.

The actual kernel short-write positive control lowers only its own exact test
child's RLIMIT_FSIZE to 1024, observes Interrupted plus a 1024-byte pending prefix,
and successfully resumes. It is a preservation control, not a claimed RED. No
disk was filled. Legacy 1/51-character/digit-initial names had a behavioral RED;
legacy validation and wrapper generation now use the same 2–50 lowercase-initial
grammar. JSON dispatch exercises all five operations and preserves unverified
client/quarantine-required labels.

### Fault-injection coverage table

Counts below are actual syscall instances per successful trace; EVERY instance
has BOTH before and after checkpoints. Forward and reverse each have two error
recovery directions AND one SIGKILL/resume run at every checkpoint. Recovery
cleanup has its own every-checkpoint error/resume sweep.

| Operation | Apply instances | Rollback instances | Recovery instances |
| --- | --- | --- | --- |
| CreateDirectory | 2 | 0 | 2 |
| CreateFile | 31 | 18 | 30 |
| Write | 67 | 54 | 64 |
| SyncFile | 44 | 18 | 43 |
| PublishJournal | 18 | 18 | 17 |
| ExchangeRelease | 1 | 1 | 1 |
| SyncDirectory | 22 | 19 | 24 |
| RemoveFile | 0 | 0 | 3 |
| RemoveDirectory | 0 | 0 | 2 |

Actual before/after checkpoint totals: apply 370, rollback 256, recovery 372. Per migration suite: **1624 injected-error cases + 626 own-child SIGKILL cases**, plus one actual kernel short-write control. All recovered active trees are complete old or complete new; replay twice leaves identical journal bytes; fixture opaque bytes are unchanged. Each validation run repeats this suite.

Quarantine/identity/dependency receipts are public fixture assertions. These
results prove the synthetic directory transaction and model ordering only; they
do not authenticate native authority, actual stopped processes, secret-content
custody, power-loss persistence, provider server, clients, real migration or release.
Mounted cross-device/bind-mount attacks, physical disk exhaustion/torn sectors,
systemd/runit integration, fresh local established legacy identity migration and
stopped-state backup/restoration, real captures, ARM runtime, performance/reboot/
soak/canary remain NOT_RUN. All original Task8c runtime/ARM/client gates remain
OPEN. No acceptance ledger field changed. Independent review remains pending.

### Final source binding

Base rust/v2 at 69d4c29012a4a04f2ba1468413df8c84f5c7dde7. Frozen file hashes were
checked unchanged after all validation. Report excluded from self-hash.

```text
91df9689603fa53e483b846286a81f13fdf83aa23614f111ebb8dd1fc4ba4ca7  crates/vprouter-core/src/allocation.rs
0bf99de4dc5a6c29e27104c51ff28d40f8fc4f7665d556b36e3f271a84c87d2e  crates/vprouter-core/src/lib.rs
bd857da746feba711a64050f75542943cfd4b15b9abb92615daad1a0a17416e5  crates/vprouter-core/src/migration/mod.rs
71b4ff476b1153a3ac087672c9e13c9abb6cd8d6f9cc4ba4b28e6a81f22546ab  crates/vprouter-core/src/migration/contract.rs
c31fb56a388051c5df2cda473a923e203d042c907c13863e495db49e2b990728  crates/vprouter-core/src/migration/storage.rs
81b6454276f873a33779bda6db790dc40121873c69359f5a811bac63bc04813b  crates/vprouter-core/tests/migration.rs
9e67f980a08f2b6aab7f2da89a1c0ed6860693627d39cd87ceea8c7f36a1af02  crates/vprouter-core/tests/migration_owned_guest.rs
052ebcf91244eea25c45729e9801aa33188404b44c68acae2697fd6be9b640f2  docs/rust-v2/migration-preparation.md
```

### Executed test artifact binding

| Test executable | SHA256 | Bytes / ELF |
| --- | --- | --- |
| `target/debug/deps/migration-6366048705b13c33` | `a3867c061165d8d3663b3ef59a56d9c4e7407f3db0c835f0aa3c3c6fff337f69` | 34004176; machine 62; INTERP=True, DYNAMIC=True |
| `target/x86_64-unknown-linux-musl/debug/deps/migration-d979dc307dc60155` | `414403f78f1e315c0f2f62cc720282f25b597ce43f003592fc7bd688cb73e942` | 33895960; machine 62; INTERP=False, DYNAMIC=False |

These are debug fixture test executables, not deployable release artifacts.
final-validation.json, fault-coverage.json, artifacts.json and final-source-hashes.json
retain machine-readable bindings. All command/log hashes are in log-hashes.json.

Final read-only Git checks: diff whitespace clean; index unchanged/empty; HEAD and
branch unchanged; manifests/lock and acceptance ledger unchanged. Only the eight
listed source/doc paths and this ignored report are owned writes. No stage,
commit, push, sudo, VM, external network or real identity/credential operation.

## Review round 1

Status: implementation revised; required local validation PASS for frozen source
cut 2. Fresh independent re-review is NOT_RUN. The unchanged review records the
pre-correction FAIL. The following initial checkpoints preserve the RED/GREEN
history; the final source cut 2 validation below supersedes earlier source cuts. Working baseline is the same eight
uncommitted Task 12 paths at 69d4c29, index untouched. Reviewer scratch source
remains available at /tmp/vpr-task12-review-esty29zs/crates/vprouter-core/tests/review_adversarial.rs.
Tests below adapt its vulnerability witnesses into refusal/recovery expectations.
No delegates, identity-material operations, sudo/network/VM or Git writes.

Planned closure: bound recursive metadata-only opaque custody including descendants;
retain initial admission pins for repeated inspection and plan pins for recovery;
metadata exclusion before data open plus NOFOLLOW/fstat at use; strict planned raw
prefix staging cleanup; durable retry-only cleanup intent and complete independent
quarantine/drain/stop/all-user barrier before terminal offline. Add generated rename
permutations and failure coverage, then sequential required validation.

Review round 1 checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration review_round1 -- --nocapture`; exit 101; 16.05s; `target/task12-checks/round1-red-review.log`.

Review round 1 checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration review_round1_unplanned -- --nocapture`; exit 101; 3.33s; `target/task12-checks/round1-red-prefix-custody.log`.

Review round 1 checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration review_round1 -- --nocapture`; exit 0; 4.63s; `target/task12-checks/round1-green-review.log`.

### Review round 1 RED/GREEN checkpoint

`round1-red-review.log`: exit101, six tests compiled and all six failed
behaviourally: pending identity deletion accepted, state bytes exposed by inspect,
nested identity replacement committed, unsafe state leaves admitted, unresolved
drain returned terminal Offline, UTF-8 stage forward recovery returned Invalid.
`round1-red-prefix-custody.log`: exit101, arbitrary pending data was deleted/adopted.
`round1-green-review.log`: exit0, all seven correctness regressions pass.

Custody now recursively captures opaque root, profile, state and every state
descendant, with dev/ino/size/mode/uid/gid/nlink/type; O_PATH handles retained
for tree lifetime prevent inode reuse. Reinspection compares initial admission
pins; plan recovery additionally binds original plan pins before marker/journal
data opens. Bounded directory enumeration is metadata only; leaves never get data
FDs. Public accesses first exclude protected inodes using O_PATH, then NOFOLLOW
open + fstat/named comparison. Pending/staging deletion additionally requires a
valid generated journal prefix or planned public file prefix, checked at unlink.

Lifecycle before/after checkpoints were added to the same fault mechanism as
filesystem operations. A durable cleanup flag is published before cleanup;
unsuccessful quarantine/drain/stop/all-user observations leave a nonterminal
retry-only journal. Affirmative quarantine permits ALL cleanup obligations to be
attempted even when an adapter fails. Offline terminal publication requires every
cleanup obligation to succeed; recovery never starts from durable cleanup intent.

The old partial-stage helper manufactured `{torn`, which cannot be engine output.
It now uses a real `{"` prefix. A separate RED-backed refusal test asserts that
unplanned bytes remain intact. This tightens admission rather than making corrupt
or arbitrary staging content deletable. Expanded full suite is running; old
receipt-mutator expectations may need correction where they previously required
terminal Offline despite unresolved quarantine/all-user obligations.

### Review round 1 interruption/failure obligations

Every mutating syscall and every driver invocation now has BEFORE and AFTER
checkpoints. These bound no-effect failures, completed-effect interruptions and
unknown results; short writes additionally leave planned prefixes. No wall clock
or native retry authority was added. The fixture driver operations are declared
idempotent. Offline requires the full quarantine/drain/pre-stop/service-stop/
post-stop/all-user barrier; committed/rolled-back requires the entire directional
operation sequence and final active-bundle verification.

| Step (apply / rollback / recovery) | Ordering and failure disposition | Idempotent retry | Behavioural tests / injection |
| --- | --- | --- | --- |
| Admission, metadata walk, original plan binding, marker/inventory/public reads | No lifecycle/data access to protected inode; drift/unsafe layout refuses, retains evidence | Exact admitted tree and original plan required | reviewer-derived pending/disclosure/replacement/leaf cases; generated swaps, bounds |
| Journal CAS / generation / encoding | No replacement on drift, bad checksum, overflow, or invalid record; retained and refused | Exact plan and current head | corrupt-journal and parser tests |
| Create pending file | EXCL/NOFOLLOW/private/same-device; an empty file is a valid planned prefix | Explicit recovery validates prefix, removes and parent-fsyncs before retry | every_io_boundary; recovery_cleanup; short_write |
| Each bounded pending write incl ENOSPC/short write | Error maps to Interrupted; old published journal remains; partial bytes not treated as text | Only byte prefixes of valid next envelope may be removed | every_io_boundary before/after; actual kernel RLIMIT_FSIZE short-write child |
| Pending fsync / journal publication / parent fsync | Atomic rename; NOREPLACE first head, checksum CAS thereafter; terminal publication only after complete barriers | Old or new record accepted, repeated fsync; no mixed record | every_io_boundary; SIGKILL; cleanup-intent/terminal sweeps |
| Independent quarantine receipt | Must be affirmative before scoped stop, exchange lifecycle, or terminal offline; failure leaves retry-only cleanup | Retry guard; never release quarantine | each_lifecycle_failure; every_cleanup_failure; lifecycle before/after checkpoints |
| Stage mkdir / host mkdir / each file create | EXCL and private metadata; active current unchanged | Validate entire partial stage, bounded cleanup/recreate | every_io_boundary; SIGKILL; prefix refusal |
| Each staging write incl UTF-8 truncation, ENOSPC, short write | Accept raw planned prefix only; never decode incomplete text or delete unknown bytes | Safe raw-prefix cleanup then recreate complete public stage, or explicit rollback | reviewer UTF-8 RED/GREEN; staging-prefix and actual short-write controls |
| Stage file/host/release/parent fsync | Complete stage required before exchange; fsync error remains recoverable | Re-fsync complete stage or recreate valid prefix tree | every_io_boundary before/after, recovery_cleanup, SIGKILL |
| Drain / pre-start stop (each sorted adapter) | On normal failure request cleanup; after affirmative cleanup guard, continue to scoped service stop even if adapter failed | Retry all cleanup barriers, no start from cleanup intent | all original lifecycle failures; six cleanup barriers x error/malformed receipt cases |
| Scoped service stop / post-stop stop / ALL identity users stopped | Cannot exchange/start without all successful receipts; terminal offline also requires all | Repeat stop and checks; unresolved work remains nonterminal | lifecycle and cleanup failure tests; driver duplicate-start assertions |
| Retained-state / reverse compatibility proof | Exact recursive pins/state-format/old release/public identity required; otherwise cleanup | Repeat original-scope observations, never replace identity | receipt-mutators; nested replacement; rollback identity controls |
| Atomic real-directory exchange / parent fsync | Only complete desired bundle after stopped-state barriers; one syscall, no activation gap | Classify old/new current to avoid exchanging twice, repeat parent fsync | every_io_boundary; SIGKILL; before-mutation swaps |
| Restore identity / rename existing / mode+isolation+clients | Scope-bound receipts before start; failure requests cleanup | Repeat whole stopped lifecycle before retry; no cloning/enrollment | each_lifecycle_failure; receipt-mutators |
| Start / rebind / post-start start / health | Start only after stopped identity restoration; late error cleans up | Scoped stop before any normal restart; durable cleanup never restarts | late-health reviewer RED/GREEN; lifecycle and cleanup failure matrix |
| Publish cleanup intent (new durable field) | Nonterminal intent before cleanup actions; no offline yet | Resume AND rollback retry cleanup only | cleanup-intent error/SIGKILL sweep, failed-drain repeated retry |
| Cleanup quarantine/drain/pre-stop/stop/post-stop/all-users | Guard gates all; adapter errors do not skip other barriers; any failed obligation prevents terminal | All are repeated on recovery until every receipt succeeds | every_cleanup_failure; cleanup-intent/terminal error+SIGKILL sweeps |
| Pending/staging file unlink, host/staged rmdir, cleanup fsync | Entire raw stage validated first; protected-inode exclusion and exact bytes + named-fd check at use | Missing prior removed file/dir accepted as the next valid partial stage; retained old bundle never cleaned | recovery_cleanup every checkpoint; generated identity swaps; unknown-prefix refusal |
| Final terminal record | Commit/reversal only after all operations; Offline only after all cleanup barriers; active drift refuses | Terminal replay has no writes/calls; nonterminal cleanup cannot revive service | baseline repeated-journal controls; terminal drift; failure matrices |

Injected boundary errors exercise the same Interrupted recovery disposition as
ENOSPC/EIO/fsync syscall errors, with no disk filling or forged native durability
claim. Actual kernel short writes are separately controlled in this process's own
child. Real ENOSPC, hardware power loss, mount attacks and native lifecycle remain
NOT_RUN. The complete final measured sweep counts will follow validation.

Review round 1 checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration -- --nocapture`; exit 101; 374.63s; `target/task12-checks/round1-migration-expanded.log`.

Review round 1 checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration review_round1_active_drift -- --nocapture`; exit 101; 2.78s; `target/task12-checks/round1-red-terminal-point.log`.

Review round 1 checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration review_round1_active_drift -- --nocapture`; exit 0; 1.39s; `target/task12-checks/round1-green-terminal-point.log`.

Review round 1 checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration review_round1_every_cleanup -- --nocapture`; exit 0; 5.16s; `target/task12-checks/round1-cleanup-matrix.log`.

Review round 1 checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration review_round1_each_lifecycle -- --nocapture`; exit 0; 7.86s; `target/task12-checks/round1-lifecycle-matrix.log`.

Review round 1 checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration review_round1_actual_short -- --nocapture`; exit 0; 0.29s; `target/task12-checks/round1-short-staging.log`.

### Review round 1 expanded-check checkpoint

`round1-migration-expanded.log`: exit101, 42 passed /1 failed. All filesystem
error sweeps (398 forward,286 reverse,400 recovery checkpoints), all684 apply/
rollback SIGKILL cases, and420 generated rename pairs passed. The single failure
was the old receipt-mutator test requiring terminal Offline on invalid quarantine.
Its expectation was corrected to retain a nonterminal journal on unresolved
quarantine/all-user/ordinal receipts, then prove a valid cleanup retry reaches
Offline without restart. This is the R2 contract change, not a production bypass.

Further behavioural RED: `round1-red-terminal-point.log` exit101, active public
drift injected immediately BEFORE terminal journal publication caused the journal
to be committed and only then rejected. Save now re-verifies the terminal active
bundle inside the publication boundary before rename; the existing after-publish
drift refusal remains. This closes a neighbouring premature-commit case requested
by the class audit.

Added (not yet final validated): each original lifecycle obligation fails before
effect/after effect/with wrong receipt, in both directions; all six cleanup
barriers fail in each style and must remain retry-only across engine reopen;
complete cleanup-intent/terminal error and SIGKILL sweeps; SIGKILL recovery
cleanup; every public staging file at four truncations in both directions;
actual owned-child RLIMIT_FSIZE short staging write splitting a UTF-8 codepoint.
Generated rename tests additionally watch synthetic protected file inodes with
inotify OPEN/ACCESS/MODIFY and a positive-control open after engine refusal.
The watcher must observe no engine data open/read/write.

Review round 1 checkpoint: `cargo fmt --all`; exit 0; 4.07s; `target/task12-checks/round1-fmt-write.log`.

Review round 1 checkpoint: `cargo fmt --all -- --check`; exit 0; 3.70s; `target/task12-checks/round1-fmt-check.log`.

Review round 1 checkpoint: `cargo clippy --locked --offline -j 4 -p vprouter-core --all-targets -- -D warnings`; exit 101; 1.60s; `target/task12-checks/round1-clippy.log`.

Review round 1 checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration review_round1_protected_identity_over_lock -- --nocapture`; exit 101; 6.09s; `target/task12-checks/round1-red-lock-open.log`.

Review round 1 checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration review_round1_protected_identity_over_lock -- --nocapture`; exit 0; 2.00s; `target/task12-checks/round1-green-lock-open.log`.

Review round 1 checkpoint: `cargo fmt --all`; exit 0; 3.83s; `target/task12-checks/round1-fmt-write-2.log`.

Review round 1 checkpoint: `cargo clippy --locked --offline -j 4 -p vprouter-core --all-targets -- -D warnings`; exit 0; 1.86s; `target/task12-checks/round1-clippy-2.log`.

Review round 1 checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration review_round1_generated -- --nocapture`; exit 0; 39.47s; `target/task12-checks/round1-generated-custody.log`.

### Review round 1 lock-admission RED/GREEN

The added inotify control found a real further R1 instance: allocation flock
acquisition opened a synthetic identity inode renamed over `.allocations.lock`
before custody refusal. `round1-red-lock-open.log` exit101 observes an OPEN event.
`round1-green-lock-open.log` exit0 after the correction. Opening a fixture now
captures only metadata custody, without opening/taking the flock. Each operation
passes both admission and ORIGINAL PLAN protected inode sets into lock admission;
lock_existing uses O_PATH exclusion BEFORE RDWR/NOFOLLOW then fstat/named checks.
After flock, the complete metadata tree is rechecked before use. Existing held
lock-name checks now use O_PATH rather than RDONLY. Fresh-engine recovery thus
does not open identity material through the lock name either. This remains the
shared allocation flock, not a second lock or lock recreation.

`round1-green-terminal-point.log`: exit0 for pre-publication active drift refusal.
`round1-cleanup-matrix.log`: exit0,36 combinations across both directions, six
cleanup barriers, and before-effect/after-effect/wrong-receipt failure styles.
`round1-lifecycle-matrix.log`: exit0,87 combinations across all original forward
and reverse obligations and those three failure styles.
`round1-short-staging.log`: exit0; actual kernel short staging write leaves a
1024-byte invalid-UTF-8 planned prefix; forward and reverse recovery both pass.

First strict Clippy found two style issues (tuple type complexity and nested if),
not behaviour failures. Factored RawBundle and collapsed the condition; next
strict Clippy and full validation are pending.

Review round 1 checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration review_round1_all_staging -- --nocapture`; exit 0; 11.77s; `target/task12-checks/round1-all-prefixes.log`.

Review round 1 checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration review_round1_opaque_leaf_custody -- --nocapture`; exit 0; 0.22s; `target/task12-checks/round1-metadata-only.log`.

Review round 1 checkpoint: `cargo fmt --all -- --check`; exit 0; 3.96s; `target/task12-checks/round1-final-fmt.log`.

### Review round 1 frozen validation RUNNING

Source cut is recorded in target/task12-checks/round1-frozen.json (eight owned
source/doc paths plus unchanged review, manifests/lock and acceptance ledger).
Read-only verification confirmed no drift and an empty/unchanged index.
Strict Clippy passed after the lock-admission correction. Focused watch-backed
420 generated swaps,104 staging prefixes and whole-transaction no-data-open
control passed (exit0).

RUNNING sequentially: `cargo test --locked --offline -j 4 -p vprouter-core
--all-targets -- --nocapture`, CARGO_BUILD_JOBS=4; live log
`target/task12-checks/round1-final-core.log`. The initial398/286/400 normal
error checkpoints have passed; new cleanup and SIGKILL cases are still running.
Final-fmt passed. Musl migration and workspace tests have not yet run for this cut.
No task-complete claim is made until their exits are recorded below.

Review round 1 checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --all-targets -- --nocapture`; exit 0; 574.64s; `target/task12-checks/round1-final-core.log`.

Frozen core suite PASS (exit0):182 passed,0 failed,15 ignored. Migration54/54; measured2588 injected-error cases and1494 own-child SIGKILL recoveries. `round1-fault-coverage.json` contains all before/after counts. Available host memory after core:3605MiB; musl migration suite is permitted by current memory conditions and follows sequentially.

Review round 1 STARTED: `env CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld 'RUSTFLAGS=-C relocation-model=static' cargo test --locked --offline -j 4 -p vprouter-core --test migration --target x86_64-unknown-linux-musl -- --nocapture`; CARGO_BUILD_JOBS=4; `target/task12-checks/round1-final-musl.log`.

### Review round 1 measured fault coverage (native frozen core PASS)

Every count below is a syscall/invocation INSTANCE, with BOTH before and after
checkpoints. Forward/reverse/offline each have TWO error recovery directions;
staging-recovery cleanup has one error recovery direction. All FOUR traces have
own-child SIGKILL coverage.

| Step | Apply | Rollback | Stage recovery | Offline cleanup path |
| --- | --- | --- | --- | --- |
| CreateDirectory | 2 | 0 | 2 | 2 |
| CreateFile | 31 | 18 | 30 | 31 |
| ExchangeRelease | 1 | 1 | 1 | 1 |
| Lifecycle | 14 | 15 | 14 | 20 |
| PublishJournal | 18 | 18 | 17 | 18 |
| RemoveDirectory | 0 | 0 | 2 | 0 |
| RemoveFile | 0 | 0 | 3 | 0 |
| SyncDirectory | 22 | 19 | 24 | 22 |
| SyncFile | 44 | 18 | 43 | 44 |
| Write | 67 | 54 | 64 | 67 |
| Before/after total | 398 | 286 | 400 | 410 |

Measured totals:2588 injected errors =2*(398+286+410)+400;1494 own-child
SIGKILL recoveries =398+286+400+410. These extend the original1624/626
sweeps; no original mutation boundary or recovery direction was removed.
Also PASS:420 generated rename cases across six protected inodes and35 names
in staged/retained roles;104 staging prefixes;87 lifecycle and36 cleanup receipt
failure cases; original pending short-write control plus forward/reverse actual
staging short-write controls. All are synthetic local filesystem/model evidence.

Review round 1 checkpoint: `env CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld 'RUSTFLAGS=-C relocation-model=static' cargo test --locked --offline -j 4 -p vprouter-core --test migration --target x86_64-unknown-linux-musl -- --nocapture`; exit 0; 617.64s; `target/task12-checks/round1-final-musl.log`.

Frozen x86_64-musl migration suite PASS (exit0):54 passed,0 failed,0 ignored; all2588 injected errors and1494 own-child SIGKILL cases passed again. Source/doc/review/manifest/acceptance hashes remain unchanged before workspace validation.

Review round 1 STARTED: `cargo test --locked --offline -j 4 --workspace --all-targets`; CARGO_BUILD_JOBS=4; `target/task12-checks/round1-final-workspace.log`.

Review round 1 checkpoint: `cargo test --locked --offline -j 4 --workspace --all-targets`; exit 0; 854.70s; `target/task12-checks/round1-final-workspace.log`.

Review round 1 STARTED: `cargo test --locked --offline -j 4 -p vprouter-core --test task12_capacity_probe capacity_probe -- --nocapture`; CARGO_BUILD_JOBS=4; `target/task12-checks/round1-red-capacity.log`.

Review round 1 checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test task12_capacity_probe capacity_probe -- --nocapture`; exit 101; 8.21s; `target/task12-checks/round1-red-capacity.log`.

### Review round 1 final size-boundary RED / source cut 2

The first frozen cut passed all required checks, including workspace567 passed,
0 failed,17 ignored (`round1-final-workspace.log`, exit0). A final audit of the
encoding step found a further accepted-input capacity failure; the earlier frozen
results are historical and do not bind the following correction.

`round1-red-capacity.log`, exit101: a generated largest accepted public plan was
2097150 bytes and passed planning, but apply returned Invalid before its first I/O
checkpoint because the journal envelope exceeded2MiB. Thus standalone plan bounds
did not reserve space for journal counters/progress/terminal fields. Reproduction
source is retained at /tmp/vpr-task12-capacity-probe.rs; its temporary repo test
wrapper was removed after integration into tests/migration.rs (no foreign file).

Planning now checks the actual full worst-sized journal envelope, using maximum
counter/cursor widths and longest terminal form, before admitting any plan.
Consumer revalidation rebuilds the plan and enforces this on raw Serde plans too.
The generated boundary regression finds the largest admitted plan, interrupts at
the first I/O checkpoint, then requires full forward commit AND rollback.
This closes an encoding-capacity instance of the requested recoverability class.
All required checks will be rerun sequentially for source cut2; old logs are kept.

Review round 1 STARTED: `cargo test --locked --offline -j 4 -p vprouter-core --test migration review_round1_largest -- --nocapture`; CARGO_BUILD_JOBS=4; `target/task12-checks/round1-green-capacity.log`.

Review round 1 checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --test migration review_round1_largest -- --nocapture`; exit 0; 12.29s; `target/task12-checks/round1-green-capacity.log`.

Review round 1 STARTED: `cargo fmt --all`; CARGO_BUILD_JOBS=4; `target/task12-checks/round1-final2-fmt-write.log`.

Review round 1 checkpoint: `cargo fmt --all`; exit 0; 4.04s; `target/task12-checks/round1-final2-fmt-write.log`.

Review round 1 STARTED: `cargo fmt --all -- --check`; CARGO_BUILD_JOBS=4; `target/task12-checks/round1-final2-fmt.log`.

Review round 1 checkpoint: `cargo fmt --all -- --check`; exit 0; 3.75s; `target/task12-checks/round1-final2-fmt.log`.

Review round 1 STARTED: `cargo clippy --locked --offline -j 4 -p vprouter-core --all-targets -- -D warnings`; CARGO_BUILD_JOBS=4; `target/task12-checks/round1-final2-clippy.log`.

Review round 1 checkpoint: `cargo clippy --locked --offline -j 4 -p vprouter-core --all-targets -- -D warnings`; exit 0; 1.57s; `target/task12-checks/round1-final2-clippy.log`.

Source cut2 frozen in round1-final2-frozen.json after formatting/strict Clippy. Largest accepted plan is now2096904 bytes in the generated fixture, with full commit and rollback PASS (`round1-green-capacity.log`, exit0). Starting the complete required validation sequence for this final cut; the earlier frozen source/logs remain intact.

Review round 1 STARTED: `cargo test --locked --offline -j 4 -p vprouter-core --all-targets -- --nocapture`; CARGO_BUILD_JOBS=4; `target/task12-checks/round1-final2-core.log`.

Review round 1 checkpoint: `cargo test --locked --offline -j 4 -p vprouter-core --all-targets -- --nocapture`; exit 0; 596.66s; `target/task12-checks/round1-final2-core.log`.

Final source cut2 core PASS (exit0):183 passed,0 failed,15 ignored. Migration55/55;2588 standard-sweep injected errors and1494 own-child SIGKILL cases unchanged, plus the near-capacity first-boundary interruption control followed by complete commit/reversal. Actual coverage is in round1-final2-fault-coverage.json. Host available memory4145MiB before musl; no concurrent owned Cargo invocation.

Review round 1 STARTED: `env CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld 'RUSTFLAGS=-C relocation-model=static' cargo test --locked --offline -j 4 -p vprouter-core --test migration --target x86_64-unknown-linux-musl -- --nocapture`; CARGO_BUILD_JOBS=4; `target/task12-checks/round1-final2-musl.log`.

Review round 1 checkpoint: `env CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld 'RUSTFLAGS=-C relocation-model=static' cargo test --locked --offline -j 4 -p vprouter-core --test migration --target x86_64-unknown-linux-musl -- --nocapture`; exit 0; 642.21s; `target/task12-checks/round1-final2-musl.log`.

Final source cut2 musl migration PASS (exit0):55 passed,0 failed,0 ignored; all2588 error /1494 own-child SIGKILL sweep cases pass, with native/musl checkpoint maps identical. Frozen source/doc/review/manifest/acceptance hashes reverified unchanged before final workspace run.

Review round 1 STARTED: `cargo test --locked --offline -j 4 --workspace --all-targets`; CARGO_BUILD_JOBS=4; `target/task12-checks/round1-final2-workspace.log`.

Review round 1 checkpoint: `cargo test --locked --offline -j 4 --workspace --all-targets`; exit 0; 697.53s; `target/task12-checks/round1-final2-workspace.log`.

### Review round 1 final validation — frozen source cut 2

R1/R2/R3 implementation corrections and adjacent class findings are fixed in this
source cut. All requested local checks PASS; this is offline fixture preparation
only. The unchanged independent review records the pre-correction FAIL; a NEW
independent re-review is NOT_RUN and no acceptance gate is promoted.

| Exact command | Exit | Result | Seconds / log |
| --- | --- | --- | --- |
| `cargo fmt --all -- --check` | 0 | clean | 3.75s; `round1-final2-fmt.log` |
| `cargo clippy --locked --offline -j 4 -p vprouter-core --all-targets -- -D warnings` | 0 | clean | 1.57s; `round1-final2-clippy.log` |
| `cargo test --locked --offline -j 4 -p vprouter-core --all-targets -- --nocapture` | 0 | 183 passed, 0 failed, 15 ignored | 596.66s; `round1-final2-core.log` |
| `env CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld 'RUSTFLAGS=-C relocation-model=static' cargo test --locked --offline -j 4 -p vprouter-core --test migration --target x86_64-unknown-linux-musl -- --nocapture` | 0 | 55 passed, 0 failed, 0 ignored | 642.21s; `round1-final2-musl.log` |
| `cargo test --locked --offline -j 4 --workspace --all-targets` | 0 | 568 passed, 0 failed, 17 ignored | 697.53s; `round1-final2-workspace.log` |

Every Cargo invocation was sequential with CARGO_BUILD_JOBS=4. Every build/test/
Clippy used --locked --offline -j 4. Workspace was the final Cargo invocation.
No foreign Cargo or other process was killed. Only exact same-executable fixture
children were SIGKILLed; file-size limits affected their own children only.
Core and musl each executed the full2588 error /1494 SIGKILL suite successfully.
Workspace executed all55 migration tests again. Conventional workspace test totals
do not qualify custom harness SKIP paths or ignored native tests as runtime proof.

Source/doc hashes, review, manifests/lock, acceptance ledger, HEAD, branch and
empty index were verified unchanged after all checks against round1-final2-frozen.json.
Tracked and untracked owned-file whitespace checks are clean. No stage, commit,
push, sudo, VM, external network, real credential/profile/state read/hash/copy,
identity recreation, or production operation was performed. Workspace local
Unix/TLS/loopback fixtures are test-only, not provider/client/network acceptance.
Only five source/doc paths were edited in this review round: allocation.rs,
migration/mod.rs, migration/storage.rs, tests/migration.rs, and the migration guide,
plus this ignored report; other original Task12 paths remain preserved.

NOT_RUN: new independent re-review; real native quarantine/service/identity users;
actual ENOSPC/EIO hardware/full-disk/power-loss; mounted attacks; native stopped
state backups/restoration; local established real identity migration; wrappers/
clients/captures; systemd/runit boot; fresh ARM runtime; performance/reboot/soak
and release acceptance. No release readiness or unchanged-secret-content
attestation is inferred from these metadata-only synthetic checks.

### Review round 1 source binding

Base rust/v2 @69d4c29012a4a04f2ba1468413df8c84f5c7dde7. Report excluded
from its own hash. All eight original owned source/doc paths are bound below.

```text
74eb5c7fde441d4ae3d24da1e7f297751a5d3d39a0da1c8e5702318b0c402a87  crates/vprouter-core/src/allocation.rs
0bf99de4dc5a6c29e27104c51ff28d40f8fc4f7665d556b36e3f271a84c87d2e  crates/vprouter-core/src/lib.rs
4379f3afabc1a3f32adcda84930e10d3803d5a03ce7a663caee7aab651bbf5b2  crates/vprouter-core/src/migration/mod.rs
71b4ff476b1153a3ac087672c9e13c9abb6cd8d6f9cc4ba4b28e6a81f22546ab  crates/vprouter-core/src/migration/contract.rs
eab662c84b44b038724610e10ce9af1bb0db6f7ead5c595a457f26fd594ec8cb  crates/vprouter-core/src/migration/storage.rs
1d4c206a661bd084afa8e7220ba01a09d5080d226ef0d4e598c7b4b4b3c3c929  crates/vprouter-core/tests/migration.rs
9e67f980a08f2b6aab7f2da89a1c0ed6860693627d39cd87ceea8c7f36a1af02  crates/vprouter-core/tests/migration_owned_guest.rs
9a66ea0a6bb6eef59e31cdab4c09e907063085aaf46ce2588af96f499b0911af  docs/rust-v2/migration-preparation.md
```

Review file unchanged throughout frozen validation:
`9c08475514b0cc480088bc8c93a300a2e7fd1c6dade7a5aade0ec9e5ed9df344`.

### Review round 1 executed migration test artifacts

| Executable | SHA256 | Bytes / ELF |
| --- | --- | --- |
| `target/debug/deps/migration-6366048705b13c33` | `b2e0a51c774c4f06ce5ed74209da12f5b047e3e05bd11bb3072f089f92e0dd08` | 36969144; machine 62; INTERP=True; DYNAMIC=True |
| `target/x86_64-unknown-linux-musl/debug/deps/migration-d979dc307dc60155` | `47f05d07cc956bdc7cafd504753cf2c5a7b4bc97f900b7a2fb2fd5c49f7cc492` | 36815592; machine 62; INTERP=False; DYNAMIC=False |
| `target/debug/deps/migration-8e68a4ed17ea311c` | `9cdccca86d3ab129ee2be6a3c485a27e553bbc330fc1f8fd9127e77f1c89522f` | 37584120; machine 62; INTERP=True; DYNAMIC=True |

Debug fixture test executables only; no release artifact or deployment claim.
Machine-readable evidence under target/task12-checks/: round1-final2-frozen.json,
round1-final2-fault-coverage.json, round1-final2-validation.json, round1-final2-artifacts.json,
and round1-final2-log-hashes.json. Failed RED and exploratory logs remain intact.

## Review round 2 (controller)

`task-12-rereview.md`: R1-R3 confirmed fixed (original reproductions replayed); one new
Important R4 (custody maps of 129..256 entries were admitted but their plan/journal could
not be decoded by the strict reader's 128-key bound). Fixed by the controller:
`MAX_OPAQUE` lowered 256 -> 128 so admission never exceeds the decoder bound, doc limit
updated, regression `custody_map_admission_bound_matches_the_strict_decoder` (119/120
leaves admitted and apply/resume/rollback + plan round-trip; 121/123 refused at
admission). RED confirmed by restoring 256 (fails at "121 leaves must be refused at
admission"), GREEN with 128. Re-run: fmt, strict clippy and `-p vprouter-core
--all-targets` all clean (migration suite 56 passed). The R4 fix itself did NOT get a
further independent review (3-round limit); R1-R3 were independently re-verified.
Still fixture-only: no real-installation migration, native service/identity restoration or
client protection is validated (NOT_RUN).
