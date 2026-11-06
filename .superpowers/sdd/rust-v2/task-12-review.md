**Verdict: FAIL — 1 Critical and 2 Important reproduced findings.**

Independent review of `rust/v2` at `69d4c29012a4a04f2ba1468413df8c84f5c7dde7`,
including the uncommitted Task 12 changes, the ignored implementation report,
Task 12 brief, and binding IMPLEMENTATION.md work package 9, Mandatory acceptance,
and local-testing amendment. Reviewed on 2026-11-06. No sub-agents were started.
All reproductions below use synthetic local fixtures. No native service,
installation, real credential, network, sudo, or VM was used.

**Critical — R1: opaque state descendants can be deleted or disclosed, and inode replacement is accepted. REPRODUCED.**

Primary location: `crates/vprouter-core/src/migration/storage.rs:333`.
Related locations: `storage.rs:237`, `storage.rs:301`, `storage.rs:484`;
`docs/rust-v2/migration-preparation.md:47` and `:53` overstate preservation.

`opaque()` pins only the `profile.wg` inode and the `state` directory inode.
It never pins `state/tailscaled.state`. Consequently, `public_pin()`'s protected
inode exclusion does not recognize the identity file. Replacing a directory
entry leaves the directory's recorded inode/mode/owner/size unchanged on the
review host's tmpfs. No narrow check/syscall race or forged checksum is needed.

Reproductions against unchanged engine sources:

1. Prepare a valid plan. Rename `opaque/state/tailscaled.state` to
   `.journal.pending`, then create a replacement file at the original state path.
   Assert the state directory's recorded size remains unchanged and pending has
   the original identity inode. `resume()` returns `Ok(CommittedFixture)` and
   `remove_pending()` unlinks the original identity inode. Pending is gone; the
   state path has a different inode. This mirrors the existing profile-over-pending
   regression test, but exercises the unprotected identity descendant.
2. Rename the same synthetic identity file over `current/router_runtime.py` and
   replace the state entry. `inspect()` succeeds; serializing the Inspection
   contains `SYNTHETIC IDENTITY BYTES - MUST NOT OPEN`. Inspection already read and
   disclosed the bytes, regardless of whether a later plan would reject source
   checksum drift.
3. In the fixture driver, after `StoppedStateRetained`, rename the original state
   file to a retained root filename and create a replacement at its original path.
   Both apply and rollback return their successful terminal outcomes with the
   replacement inode still installed. This is an inode replacement, not the
   documented limitation concerning an in-place same-size content edit.
4. Before inspection, separately install a state-leaf symlink, add a hardlink to
   that leaf, or change its permissions to 0644. All three layouts pass
   open/inspect/plan/apply. The protected-file admission rules do not reach them.

Evidence: scratch tests `review_state_identity_renamed_to_pending_is_deleted_on_resume`,
`review_state_identity_renamed_to_public_asset_is_serialized_by_inspect`,
`review_state_identity_replaced_mid_migration_commits`, and
`review_state_children_symlink_hardlink_and_permissions_are_unchecked`.

Required correction: extend metadata-only protection/custody to identity-bearing
state descendants, or refuse layouts whose descendants cannot be protected.
Recovery must prove a pending/staging inode is public before opening its data or
unlinking it; directory metadata alone cannot supply that proof. Reject replaced,
aliased, symlinked, or permissive identity leaves before cutover and recovery.
Revise the preservation claims until these cases are covered. No secret-byte
reading/hashing/copying should be introduced to solve this.

**Important — R2: a failed cleanup drain prevents service stop, yet publishes irreversible offline. REPRODUCED.**

Primary location: `crates/vprouter-core/src/migration/storage.rs:731`.
Related locations: `storage.rs:739` and `storage.rs:171`.

Use the declared collector fixture. Let ordinary drain/stop/start operations
succeed. Fail its health check after `StartService`, and also fail the next drain
when `offline()` runs. The independent quarantine receipt is valid and accepted.
The cleanup loop breaks at that drain, before `StopService` or
`AllIdentityUsersStopped`. Apply returns `Ok(Offline)` and persists terminal
`offline`, while the fixture driver's `running` state remains true.

Both subsequent resume and rollback return `Ok(Offline)` without any further
lifecycle calls. Thus the remaining stop obligation cannot be retried through
the recovery API. This contradicts the explicit stop-after-late-failure invariant
at `storage.rs:725`. The reproduction measures the fixture lifecycle model, not
an actual running service or authenticated native quarantine.

Evidence: `review_failed_cleanup_adapter_drain_leaves_started_service_running_and_terminal`.
Its observed tail is health-check failure -> accepted quarantine -> drain failure;
there is no subsequent service stop, and resume/rollback preserve that state.

Required correction: after affirmative independent quarantine, a failing adapter
must not prevent attempting the scoped service stop and identity-user check.
Retain unresolved cleanup obligations in a recoverable state instead of publishing
a terminal outcome that permanently suppresses their execution. An adapter error
must not license a restart or weaken quarantine.

**Important — R3: an interrupted UTF-8 staging write makes forward recovery permanently fail. REPRODUCED.**

Primary location: `crates/vprouter-core/src/migration/storage.rs:387`.
Related locations: `storage.rs:574`, `storage.rs:630`, and `storage.rs:465`.

Supply an otherwise valid new public `router_runtime.py` containing 4095 `#`
characters followed by `é` and newline, and recompute its declared source hash.
The complete public text is valid UTF-8 and plan creation succeeds. Inject
`Interrupted` immediately after its first 4096-byte staging write. The staged
file now ends with the first byte of `é` and is invalid UTF-8.

Two successive `resume()` calls return `Err(Invalid)`. `stage()` calls `bundle()`
before cleanup, and `String::from_utf8` rejects this legitimate partial write;
`clear_stage()` also requires `bundle()` to succeed. The complete old current
bundle remains active and explicit rollback succeeds, but forward resume cannot
repair the staged prefix. This violates the claimed recovery after every write
boundary for an input the planner accepts. The baseline sweeps use ASCII assets
and do not exercise this boundary.

Evidence: `review_partial_utf8_public_stage_is_not_resumable`, using the actual
4096-byte write path plus its exposed after-write fault boundary.

Required correction: validate partial staging using bounded raw bytes and the
planned file prefixes before safe cleanup/recreation, or reject non-ASCII public
assets at planning if that is the intended supported grammar. Do not require an
interrupted text file to decode successfully before recovery can repair it.

**Verification ledger**

All Cargo invocations were sequential. Build/test/Clippy commands used
`--offline --locked -j 4`, `CARGO_BUILD_JOBS=4`, and this temporary target:
`/tmp/vpr-task12-review-esty29zs/target`. No unrelated process was signalled.

| Verification | Result | Evidence |
| --- | --- | --- |
| `cargo test --offline --locked -j 4 -p vprouter-core --test migration -- --nocapture` in original repo | PASS, exit 0; 34 passed, 0 failed, 0 ignored; test execution 174.73s | `/tmp/vpr-task12-review-esty29zs/migration.log` |
| Baseline before/after I/O error sweeps, included above | PASS; forward 370 and reverse 256 boundaries, each with two recovery directions, plus 372 cleanup recovery boundaries: 1624 injected errors | Same log, coverage/count lines |
| Baseline own-child SIGKILL sweep, included above | PASS; 370 forward + 256 reverse = 626 recoveries | Same log |
| Baseline actual kernel short-write control, included above | PASS; existing child RLIMIT_FSIZE test | Same log; no disk filling |
| Independent scratch suite in `/tmp` copy, final `cargo test --offline --locked -j 4 -p vprouter-core --test review_adversarial -- --nocapture` | Exit 0; 7 tests: six successful vulnerability-witness tests plus one control test | `/tmp/vpr-task12-review-esty29zs/adversarial-final.log` |
| Independent control: interrupt apply at six selected boundaries, then interrupt rollback at two selected boundaries; resume twice, verify journal idempotence, explicitly complete rollback | PASS; 12 combinations; complete old/new active bundles and final old bundle verified | `INDEPENDENT_FAULT_SAMPLE` in final scratch log |
| `cargo fmt --all -- --check` in original repo | PASS, exit 0 | `/tmp/vpr-task12-review-esty29zs/fmt.log` (empty successful output) |
| `cargo clippy --offline --locked -j 4 -p vprouter-core --all-targets -- -D warnings` in original repo | PASS, exit 0 | `/tmp/vpr-task12-review-esty29zs/clippy.log` |
| Compared reviewed source/doc/report hashes against initial snapshot after checks | PASS; no drift | `/tmp/vpr-task12-review-esty29zs/source-hashes.json` |
| Owned-guest tests, native custody/backups/state restoration, services/wrappers, physical power loss, actual ENOSPC/EIO, ARM runtime, real clients, installation/release acceptance | NOT_RUN | Three ignored owned-guest acceptance specifications remain unexecuted; synthetic results do not close these gates |

The first scratch-suite run exited 101 because its additional recovery control
incorrectly demanded reversal when rollback intent had not yet been published.
The five vulnerability witnesses present in that run succeeded. The control was
corrected to accept the prior complete forward result until reversal publication,
then require explicit rollback and verify old content. Intermediate output is
retained in `adversarial-initial.log`; subsequent six-test output in
`adversarial.log`, and the final seven-test output in `adversarial-final.log`.
No engine source was changed to obtain any result.

Scratch source:
`/tmp/vpr-task12-review-esty29zs/crates/vprouter-core/tests/review_adversarial.rs`
SHA256: `e58b86b54aaaa87366d02cafca645d04be7f40174bde1125b68c4799e1df4b65`.
It reuses fixture/model helpers from the submitted migration tests and adds
independent adversarial cases. Witness assertions deliberately assert the broken
observations above; their passing status confirms reproduction, not correctness.
Re-run from the scratch copy with a fresh temporary CARGO_TARGET_DIR if needed.
Temporary evidence paths are ephemeral.

Source inspection also confirmed a single `renameat2(RENAME_EXCHANGE)` operation
with no non-atomic fallback, explicit parent fsync after exchange/publication,
checked journal generation/checksum, bounded writes, and repeated nonterminal
lifecycle obligations. Baseline tests passed drift refusal, terminal-state
monotonicity, competing migrators, opaque-profile alias refusal, strict parsing,
provenance, and bounded adapter declaration controls. No production activation
flag, executor, unsafe block, or host-time entry point was introduced in this
module. These observations do not qualify hardware crash durability or native
lifecycle behavior; R1-R3 remain blocking despite the passing ordinary sweeps.

No additional unreproduced concern is presented as a correctness finding.
Documentation correctly keeps real migration, runtime, wrapper integration and
release acceptance open, but its opaque-preservation claims need the R1 correction.
The only review-authored repository file is this ignored review. The original
uncommitted implementation and Git state were preserved.
