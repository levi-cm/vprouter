# Independent review brief — Task 8c rebuild phases 3 + 3b (pre-run409 gate)

Workspace `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`, HEAD `6ca0073`; all phase 3/3b changes are unstaged in the worktree.

## What to review

The implementation briefs are `.superpowers/sdd/rust-v2/task-8c-rebuild-phase3-brief.md` and `task-8c-rebuild-phase3b-brief.md`. Their reports (`task-8c-rebuild-phase3-report.md`, `task-8c-rebuild-phase3b-report.md`) and `task-8c-historical-gap-disposition.md` are the implementers' claims. Verify claims against code and evidence yourself; do not take them as findings.

Code under review (tracked diffs via `git diff`, new files untracked):
- `tools/rust-v2-lab/fresh-baseline.py`, `run409-reservation.py`, `phase3-readonly-preflight.py`, `collect-run409-evidence.py`, `inspect-run409-state.py`, `test-run409-reservation.py`, `test-phase3b-provenance.py`.
- Archived controller diffs under `tools/rust-v2-lab/target/` (`platform-lab/run-frozen-secret-bootstrap.py`, `platform-lab/run-native-inspection-preflight.py`, `quarantine_evidence_base.py`, `inspect-secret-bootstrap-failure.py`, `archive-secret-bootstrap-selectors.py`) and `tools/rust-v2-lab/source-manifest.json`. Restored runtime copies live at the same paths under `target/` (ignored).
- Evidence: `target/rebuild-phase3/`, `target/rebuild-phase3b/`, `target/lab-state/run-409-reservation.json` (+ superseded reservation/tombstone), candidate-local baseline files under `target/candidates/rebuild-20261103T231415Z/`.
- Context: `task-8c-lab-rebuild-assessment.md` (sections 3, 5), `task-8c-driver-cost-brief.md` (what run 409 is meant to measure), `tools/rust-v2-lab/parse-bootstrap-cost-diagnostics.py`.

## Questions the review must answer

1. **Correctness of the run-409 one-shot guarantee:** can run 409 be executed twice, retried, or run against the superseded reservation; can a crash/interruption leave it re-runnable; can any path overwrite a raw record?
2. **Baseline honesty and strength:** is the fresh baseline truthfully labelled, independently collected (not copied from the projection), and is the comparison exact? Are namespace/structural/custody/deadline checks as strong as the historical path?
3. **Historical behaviour unchanged:** do the edits to restored controllers leave the historical branches behaviourally identical? Are archive copies, restored copies and manifest consistent?
4. **Post-run path:** after success and after a Deadline failure (the 402–408 pattern), will the documented C/I/P/F/A sequence actually preserve the raw record and produce the 15 driver-cost rows via the parser? Anything that would refuse or lose evidence?
5. **Safety:** strict confined SSH on every new call; no new guest mutation outside run 409 itself; no secrets in tracked files; `python3 -O` refusal guards; nothing that touches debdev networking/production.
6. **Is run 409 ready to execute?** Give a clear GO / NO-GO with blocking findings.

You may run read-only and offline checks: the tests, `--preflight-only` (it does not consume the reservation — verify that first from the code), `py_compile`, manifest hash checks, `git diff`, `ssh -G`, and read-only guest status via `tools/rust-v2-lab/lab-guest-status.py`. Do NOT execute run 409, consume or create a reservation, mutate the guest, stage/commit/push, use sudo on debdev, or start subagents. Put scratch output under `/tmp/vprouter-phase3-review/`.

## Deliverable

`.superpowers/sdd/rust-v2/task-8c-rebuild-phase3-review.md` (the only file you write outside /tmp): verdict (PASS / FAIL) and GO / NO-GO for run 409, findings as Critical / Important / Minor each with file:line and a concrete failure scenario, then what you verified and how.
