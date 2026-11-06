# Task 12 independent re-review

**Verdict: FAIL — one Important reproduced finding within the supported fixture contract.**

The original R1–R3 reproductions are fixed for the documented cooperative-writer
scope. A fresh accepted-input case still defeats durable recovery: a custody map
with 129 entries is admitted and committed, but its plan and journal cannot be
decoded. No Critical finding was reproduced within that scope. Two Minor notes
below record reproduced syscall races outside the explicitly documented writer
assumption; they are not the reason for this verdict.

Reviewed 2026-11-06, `rust/v2` at
`69d4c29012a4a04f2ba1468413df8c84f5c7dde7`, with the uncommitted Task 12 changes.
Read the brief, original independent review, implementation report including
Review round 1/final source cut 2, migration guide, binding IMPLEMENTATION.md,
core migration/contract/storage, changed allocation lease, structural configuration
validation, and existing production migration entry points. This is an offline
fixture-engine review, not installation or release acceptance. No sub-agents.

Evidence directory: `/tmp/vpr-task12-rereview-h4sk3brf/` (ephemeral).
Independent test copy: `repo/` inside that directory. Engine sources in the copy
were unchanged; only scratch test files and audit helpers were added there.
All Cargo invocations were sequential, with `CARGO_BUILD_JOBS=4` and
`CARGO_TARGET_DIR=/tmp/vpr-task12-rereview-h4sk3brf/target`.
Build/test/Clippy commands used `--offline --locked -j 4`; fmt used its supported
arguments. No sudo, network request, VM, native service, real identity material,
Git mutation command, or signal to an unrelated process was used. Namespace mount
tests used mapped root only inside a new private user/mount namespace and scratch
chroot. The standard crash tests killed only their own exact fixture children.

## Important — R4: admitted custody maps produce unreadable plans and journals. REPRODUCED

Primary: `crates/vprouter-core/src/migration/mod.rs:263`.
Related: `mod.rs:214`, `mod.rs:506`,
`crates/vprouter-core/src/migration/storage.rs:144`, `storage.rs:64`,
`storage.rs:775`. The documented 256-entry custody limit is at
`docs/rust-v2/migration-preparation.md:221`.

Metadata capture and inspection validation permit up to 256 opaque entries.
The strict JSON reader rejects every map with more than 128 keys. Planning and
the new journal-capacity check serialize data and check encoded size, but do not
test whether that accepted encoding can pass the strict reader.

Independent reproduction, with normal private modes, single-link regular leaves,
no races, no fault injection, and no tampered input:

1. Use the collector fixture and add four private directories under `opaque/state`.
2. Distribute synthetic opaque leaves among those directories, with at most 32
   children per directory. The four original opaque entries plus four added
   directories give eight entries before adding these leaves.
3. Open, inspect, plan, encode, apply, resume, and rollback the same fixture.

| Added leaves | Total custody entries | `Plan::parse(plan.encode())` | Typed `apply` | `resume` | `rollback` |
| --- | --- | --- | --- | --- | --- |
| 120 | 128 | succeeds | `CommittedFixture` | `CommittedFixture` | `RolledBackFixture` |
| 121 | 129 | `Invalid` | `CommittedFixture` | `Invalid` | `Invalid` |
| 123 | 131 | `Invalid` | `CommittedFixture` | `Invalid` | `Invalid` |

Thus the library can publish a complete committed journal which its recovery API
cannot load, and its own encoded valid plan does not round-trip. The JSON command
consumer rejects the encoded plan before apply; this does not repair the typed
API's admitted plan or the journal already published by that API. The old bundle
remains retained, but ordinary rollback cannot use it. This contradicts the
binding accepted-plan/idempotent-recovery requirements without needing a crash.

Witness:
`repo/crates/vprouter-core/tests/review_fresh.rs:523`,
`independent_large_custody_map_is_admitted_but_journal_unreadable`.
Outputs: `fresh.log` and `fresh-final.log`, `CUSTODY_MAP_LIMIT` lines. These are
vulnerability-witness assertions: their PASS confirms the failure above.

Required correction: make admitted custody bounds and strict consumer bounds
consistent, and require accepted plans plus generated journals to round-trip
through their real decoder. Cover 128/129 and the intended maximum, including
forward interruption and reversal. A serialized-byte capacity check alone does
not close this structural encoding boundary. No implementation fix was made in
this review.

## Original R1–R3: independently replayed and confirmed fixed

The original review's scratch source was still present. Copied it unchanged into
this review's scratch checkout as `review_original_witnesses.rs` and ran it against
the revised engine. All six assertions demanding the old broken behavior failed;
its independent recovery control passed. This is the expected negative result,
not a failed correctness test. Then ran independent corrected assertions using
the same triggers and fixture/model helpers, in addition to the submitted tests.

| Original finding | Fresh observed result |
| --- | --- |
| R1 state identity moved to pending/public asset | Inspection and recovery refuse; the original inode remains at the attacker-selected name; no lifecycle action is emitted for the pre-operation changes. |
| R1 mid-migration state replacement after `StoppedStateRetained` | Apply and rollback refuse; no successful cutover/rollback with replacement is accepted. |
| R1 state-leaf symlink, hardlink, 0644 permissions | Admission refuses all three layouts. |
| R2 health failure followed by cleanup drain failure | Returns nonterminal `Offline` error, scoped service is stopped, durable cleanup intent remains, terminal is null; resume retries cleanup without start; correcting drain lets rollback finish terminal `Offline`. |
| R3 valid UTF-8 split at actual 4096-byte staging write | The partial file is invalid UTF-8; two forward resumes commit successfully and explicit rollback restores the old bundle. Submitted tests also pass direct reverse recovery and kernel short-write variants. |

Evidence: `original-witnesses.log`, `fresh-final.log`;
scratch tests `independent_original_r1_refusals`,
`review_state_identity_replaced_mid_migration_commits`,
`independent_original_r2_failed_cleanup_drain`, and
`review_partial_utf8_public_stage_is_not_resumable` (historical witness name;
its corrected assertions require successful recovery).

## Minor — M1: data opens remain possible across a hostile final-check race. REPRODUCED; outside documented cooperative-writer assumption

Locations: `crates/vprouter-core/src/migration/storage.rs:468` and
`crates/vprouter-core/src/allocation.rs:394`.
Scope qualification: `docs/rust-v2/migration-preparation.md:215` explicitly says
check-plus-syscall cannot defeat malicious same-UID/root writers bypassing the
private-directory/cooperative-lock boundary.

The independent C ptrace observer follows only its own scratch test child and
threads, observes actual inline Rust syscalls, and retains the original profile
and state identities through O_PATH handles. It does not use inotify, libc
interposition, or engine source hooks. At a selected syscall-entry stop, after
the metadata precheck, the observer moves the original state inode over the
public target and installs a replacement state leaf. The syscall then proceeds
unaltered.

| Target | Observed descriptor | Engine result | Protected reads |
| --- | --- | --- | --- |
| `current/router_runtime.py` immediately before data `openat` | Original state inode opened once, RDONLY; flags `0xa8800` | `UnsafeTree` after fstat | 0 |
| `.allocations.lock` immediately before lock data `openat` | Original state inode opened once, RDWR; flags `0xa8802` | `UnsafeTree` before flock | 0 |

The actual FD check prevents reading the protected bytes, but cannot undo the
data open. Consequently, an unconditional claim that a protected inode is
*never data-opened* is not established across the requested hostile syscall race.
Within the documented writer assumption this is a limitation, not an additional
blocking correctness finding. Evidence: `audit-open.log`, `audit-lock.log`.

## Minor — M2: unlink/publication can remove a protected name across the same hostile race. REPRODUCED; same scope qualification

Locations: `crates/vprouter-core/src/migration/storage.rs:700` and
`storage.rs:825`.

The same observer swaps the original state inode over the target after all
engine checks and immediately before the selected kernel operation:

| Target operation | Fresh observation before test fixture destruction |
| --- | --- |
| Pending cleanup `unlinkat(.journal.pending)` | Engine returns `Drift`; held original state inode has `st_nlink == 0`. |
| Later journal publication `renameat2(.journal.pending, journal.json)` | Engine returns `Drift`; replacing the destination journal unlinks the held original state inode, `st_nlink == 0`. |

An error after the operation does not restore that link. Neither scenario opens
or reads protected file data. These require an adversarial writer to bypass the
documented flock assumption during the final check/syscall gap. They are measured
limitations of that assumption, not new in-scope Critical findings.
Evidence: `audit-unlink.log`, `audit-publish.log`.

For all four races, the observer's rename/replacement is the attack; the engine
performs the subsequent observed open/unlink/publication. No production path or
identity was involved. The worker prints `protected_nlink` before fixture cleanup.
The observer's later final `original_state_nlink` is after ordinary test Drop has
deleted the scratch fixture and is **not** the preservation measurement.

## Fresh adversarial coverage and identity-byte audit

| Class | Executed evidence and result |
| --- | --- |
| Alternate protected names | Independent state relocation to pending, journal, public asset, lock, marker, retained-backup and tmp name refuses before lifecycle; original inode remains. Submitted 420 exhaustive protected-inode/destination permutations also pass. |
| State/root/public-directory swaps | State directory replaced by symlink or real directory; opaque/current replaced by symlink; all refuse before lifecycle. |
| Hardlink after admission | Add an alias of the state leaf after a valid plan; apply/resume/rollback refuse. |
| Mount and cross-device | Inside isolated user/mount namespaces and scratch chroot, actual tmpfs over `opaque/state` is refused by both an existing tree and fresh admission; actual same-device bind replacement is refused by the existing tree. Baseline admission succeeded before each mount; no lifecycle action occurred. |
| Names/depth/fanout | Non-UTF-8, Unicode, percent-encoded, backslash, space/control, 64-byte component, depth-18, and 33-child layouts refuse. Submitted parser/path tests also pass. |
| Size bounds | Sparse 1 TiB opaque leaf is inspected/planned using metadata only; public text limits, generated near-2 MiB journal envelope, and submitted custody bounds pass. The 129-entry round-trip failure is R4 above. |
| Journal corruption/replay | Truncation, generation zero, bad checksum, impossible cursor with correctly recomputed canonical checksum, and replay of a formerly committed journal after rollback refuse without rewriting evidence or emitting lifecycle actions. Two identical terminal resumes leave journal/calls unchanged. |
| Resume/rollback ordering | Twelve independent apply-boundary/reversal-boundary combinations retain a complete active bundle, permit only the durable direction, replay identically, and explicitly finish reversal to the old bundle. |
| Concurrent/stale lock | Submitted lock-replacement, actual competing migrator and crash/recovery tests pass; no timeout/age-based lock breaking. |
| Host/time validation | Supported/unsupported host declarations and integer timeout rejection tests pass. Source inspection finds no host-time operational entry point or elapsed-time authority in this module; production migration commands remain separate. No native host-support qualification is inferred. |
| Offline publication ordering | Original R2 trigger, all submitted lifecycle/cleanup receipt failures, late active drift, and cleanup-intent/terminal crash sweeps pass. Quarantine must be affirmative, scoped stop/all-users remain mandatory, and unresolved cleanup stays retry-only. |

Source search and call-path inspection (`source-byte-operations.txt`) identify
opaque file access as O_PATH metadata custody. Migration configuration validation
uses `validate_structure`, not the profile-loading `validate` path. Hash inputs
are public bundles/plans/journals and serialized metadata pins. Opaque contents
are not intentionally loaded, hashed, copied, or serialized by these reviewed
paths; public nodeID/IP/approval observations are separate from identity files.

In the independent syscall audit of admission, inspection, planning, full apply,
and full rollback, the observer measured **0 protected data opens, 0 protected
reads, and 6488 metadata-only O_PATH opens** of the two protected leaves. The
state link count was 1 before fixture destruction. Six further errno/recovery
traces also measured zero protected data opens/reads. This independently supports
the ordinary metadata-only path without relying on the implementer's inotify
tests. It does not prove a universal no-open statement: M1 reproduces exceptions
under the excluded hostile writer. No secret-byte read/hash/serialization was
reproduced, including those attacks. Synthetic test helpers independently inspect
placeholder contents for their assertions; they are not migration-engine reads.

## Verification ledger

All commands below have completed; no pending run is represented as PASS.
The main migration/fmt/Clippy checks ran from the original repository, using the
temporary target. Independent Cargo tests ran from the scratch copy.

| Verification | Fresh result | Evidence |
| --- | --- | --- |
| `cargo test --offline --locked -j 4 -p vprouter-core --test migration -- --nocapture` | Exit 0; 55 passed, 0 failed, 0 ignored; test execution 588.05s | `migration.log` |
| Standard before/after mutation/lifecycle failure sweeps | 2588 injected boundary errors: `2*(398+286+410)+400`; apply, reverse, cleanup intent/offline, stage recovery | Same log, coverage/count records |
| Standard abrupt termination sweeps | 1494 own-child SIGKILL recoveries: `398+286+410+400` | Same log |
| Standard real kernel short writes | Pending write and UTF-8 staging short-write recovery pass using own-child file-size limits | Same log |
| Standard extra class cases | 420 rename permutations; 87 lifecycle failure cases; 36 cleanup failure cases; all planned staging-prefix checks pass | Same log |
| `cargo test --offline --locked -j 4 -p vprouter-core --test review_original_witnesses -- --nocapture --test-threads=1` | Expected exit 101: 6 old vulnerability-witness assertions fail, 1 recovery control passes | `original-witnesses.log`, `scratch-validation.json` |
| `cargo test --offline --locked -j 4 -p vprouter-core --test review_fresh -- --nocapture --test-threads=1` | Final exit 0; 12 passed: 9 exercised test cases and 3 environment-gated worker no-ops. R4 witness PASS means reproduced bug. Workers separately invoked below. | `fresh-final.log`, `fresh-final-validation.json`; initial 11-test run in `fresh.log` |
| Independent syscall audit | Normal transaction and four hostile-race worker invocations all exit 0 with the measurements above | `audit-*.log`, `audit-validation.json` |
| Actual syscall-return injection | 6/6 exit 0: `ENOSPC` on pending/staging write; `EIO` on pending-file, staging-file, staging-directory and root-directory fsync. Each returns `Interrupted`, then resumes to commit and rolls back successfully. | `fail-*.log`, `errno-validation.json` |
| Actual isolated mounts | Cross-device tmpfs and same-device bind replacement both refuse before lifecycle; each worker exits 0 | `mount-*-final.log`, `mount-final-validation.json`, `run-mount-check.sh` |
| `cargo fmt --all -- --check` | Exit 0; 3.95s | `fmt.log`, `required-checks.json` |
| `cargo clippy --offline --locked -j 4 -p vprouter-core --all-targets -- -D warnings` | Exit 0; 3.69s | `clippy.log`, `required-checks.json` |
| Report source-cut-2 bindings / final source preservation | All 8 source/doc bindings match; original review, implementation report, all captured crate files, manifest/lock and acceptance ledger unchanged | `source-hashes.json`, `binding-check.txt`, final preservation check |

The full boundary sweeps exercise every recorded invocation before/after each
journal/staging mutation and sync. They are generic error/effect interruption
tests, not thousands of real full-disk/fsync hardware faults. The six independent
ptrace errno controls inject actual observed syscall return values without
filling shared storage; they sample the distinct write/fsync paths, not every
syscall instance. Physical ENOSPC, real hardware EIO/power loss, and arbitrary
kernel crash durability remain NOT_RUN. The standard short-write controls do
execute actual kernel-limited writes.

The mount harness initially failed before reaching the engine: binding host
`/proc` into the new namespace was denied, then `chroot` was absent from PATH.
Those outputs are retained in `mount-*.log` and `mount-*-retry.log`. Removing the
unneeded proc bind and using Python's `os.chroot` produced the successful final
tests, with unchanged engine sources and an explicit successful pre-mount
admission control. The scratch test compile emits only a dead-code warning for
an unused copied assertion helper; strict Clippy of the submitted core is clean.

NOT_RUN: native quarantine/service/identity drivers, private stopped-state
backup/restoration, real installation migration, real clients/no-fallback,
production wrappers, systemd/runit boot, ARM runtime, reboot/soak, hardware
durability and release acceptance. No such gate is promoted by these results.

## Reproduction and preservation

Run the fresh scratch suite from
`/tmp/vpr-task12-rereview-h4sk3brf/repo` with the Cargo command above and its
temporary target. The preserved `review_original_witnesses.rs` is byte-identical
to the earlier review's scratch source. The independent tests reuse fixture and
model helpers, not the implementer's new generated-case logic.

`audit-validation.json` and `errno-validation.json` record exact environment-mode
worker command argv; `T12_ARM` names their scratch arm file. Set
`T12_AUDIT_MODE` or `T12_ERRNO_MODE` to the recorded mode. The observer source and
binary are retained as `vpr-task12-ptrace.c` and `vpr-task12-ptrace` in the evidence
directory; the earlier command path `/tmp/vpr-task12-ptrace` also remains. The
observer's later errno extension leaves the earlier race modes unchanged.
`evidence-hashes.json` binds logs, helpers and scratch test sources. Evidence paths
are temporary, not a durable archive or release artifact.

The only review-authored repository file is this report. The original dirty
working files, branch/HEAD and empty staged diff were preserved; no fixes were
applied to the implementation. The original independent review SHA256 remains
`9c08475514b0cc480088bc8c93a300a2e7fd1c6dade7a5aade0ec9e5ed9df344`.
