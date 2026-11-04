# Task 8c rebuild phase 3b brief — fresh-provenance collection path

Date: 2026-11-04. Workspace `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`, HEAD `6ca0073`. Phase 3 changes are unstaged in the worktree; build on them, do not revert them.

## Read first

- `.superpowers/sdd/rust-v2/task-8c-rebuild-phase3-report.md` (all of it) and `task-8c-rebuild-phase3-brief.md`.
- `.superpowers/sdd/rust-v2/task-8c-historical-gap-disposition.md`.
- `target/quarantine_evidence_base.py` (≈line 30–60: the baseline-declaration validator that requires `review['prior_structure_reconstructed'] is review['ordering_only_aligned_after_exact_multiset_comparison'] is True`) and everything that imports it.
- `target/platform-lab/run-frozen-secret-bootstrap.py` (now reservation-aware), `tools/rust-v2-lab/fresh-baseline.py`, `tools/rust-v2-lab/run409-reservation.py`.
- `target/inspect-secret-bootstrap-failure.py`, `target/archive-secret-bootstrap-selectors.py`, `tools/rust-v2-lab/parse-bootstrap-cost-diagnostics.py`.

## Problem

Phase 3 authored a truthful fresh baseline (`prior_structure_reconstructed=false`, alignment false, `historical_continuity=false`). The historical success collector refuses it. Run 409 is one-shot; it must not be consumed while either outcome (success or failure) cannot be collected, inspected and preserved.

## Tasks

1. **Map the full post-run path for run 409.** For each outcome (success; each failure mode the controller can produce, especially Deadline at native_poll/result as in 402–408), list exactly which tools run, in what order, and which of them read the baseline template/reconciliation, the run number, the reservation, or historical-only fields. Record which would refuse the fresh route and why.
2. **Add an explicit fresh-provenance branch** wherever a post-run tool would refuse it: accept the fresh template/reconciliation only when it is bound to the run-409 reservation (reservation SHA, authored template/reconciliation/projection/comparison hashes, the admitted guest boot, `historical_continuity=false`) and the exact multiset comparison passed. Keep every structural, namespace, custody and deadline check. Leave the historical branch byte-for-byte behaviourally unchanged. Never set the historical flags true for fresh data. Mirror every restored-controller change into its archival copy under `tools/rust-v2-lab/target/` and update `tools/rust-v2-lab/source-manifest.json` consistently.
3. **Tests.** Add a versioned offline test (no guest) that feeds synthetic fresh and historical declarations through the changed validators: fresh accepted only with correct bindings; tampered/unbound fresh refused; historical behaviour unchanged; mixing (fresh flags with historical reservation, etc.) refused.
4. **Reservation.** The reservation binds controller/helper bytes, so it will now be stale. Do not delete or edit it in place. Use or add an auditable supersede: retain the old file (renamed with its hash, still budget-unconsumed), record why it was superseded, then create a fresh reservation bound to the new bytes. The one-shot budget for run 409 stays 1 overall; it must be impossible for both the old and new reservation to be consumed.
5. **Re-run the pre-execution gates** that the changes affect: reservation tests, the new offline tests, `--preflight-only` with the new reservation, manifest/archival byte checks, `python3 -O` refusal guards, `git diff --check`, current guest status (read-only).

## Constraints

Same as the phase 3 brief: do not execute run 409 or any guest network/namespace/nft/container mutation; strict confined SSH on every call; no sudo on debdev; no production/credential use; no git staging/commit/push; no cargo unless Rust changes (`-j 4` if so); no subagents; work autonomously without asking for approval.

## Deliverable

`.superpowers/sdd/rust-v2/task-8c-rebuild-phase3b-report.md`: the post-run path map, every change with file:line, test results, exact commands and exit codes, superseded and new reservation hashes, NOT_RUN items and open risks, and the final exact run-409 command.
