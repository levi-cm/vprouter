# Task 8c run 409 diagnosis brief

Workspace `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`, HEAD `a4f564b` (pushed). Run 409 has been executed once and is consumed; it must never be re-run.

## What happened

`python3 target/platform-lab/run-frozen-secret-bootstrap.py target/candidates/rebuild-20261103T231415Z/candidate.json debian-clean-x86_64 bootstrap409-driver-cost success --reservation target/lab-state/run-409-reservation.json` → exit 1 at 2026-11-04T16:13:48Z.

- Raw record: `target/lab-state/actual-program-run-409.json` (sha256 dcc98329…). stderr tail ends:
  `LAB_SECRET_BOOTSTRAP_PHASE stage=host.inventory event=begin` → `secret_bootstrap_lab: ownership_mismatch`.
- Earlier stages including host.first_writer, operation_summary/receipts, writer_receipts reported ok. Runs 402–408 (old 61-link lab) all failed earlier, on Deadline at native_poll/result; 409 got past that.
- No `LAB_SECRET_BOOTSTRAP_DRIVER_*` rows (they are emitted only on the Deadline path), so the parser correctly refused: `target/run409-exec/parse.*`.
- Post-run steps already done (do not repeat C/I/F; outputs are exclusive):
  - C `collect-run409-evidence.py` → `target/run409-preserved-initial/` (outcome failed_bootstrap_preserved, provenance_valid true).
  - I `inspect-run409-state.py` → `target/lab-state/run-409-state-inspection.json` (inert container running, original identity matches).
  - F `inspect-secret-bootstrap-failure.py 409 …` → `target/lab-state/secret-bootstrap-failure-run-409.json` (owner unit not-found, cgroup absent).
  - Controller/stdout/stderr: `target/run409-exec/`, `target/candidates/rebuild-20261103T231415Z/bootstrap409-driver-cost/`.
- Selector archival (A, `target/archive-secret-bootstrap-selectors.py`) has NOT been run and is out of scope.

## Questions

1. **Root cause of `ownership_mismatch` at host.inventory.** Find where it is produced in the Rust source (crates/, likely vprouter-launch attachment/operational bootstrap and host inventory code) and exactly which comparison failed. Use the raw record, stderr, the fresh baseline (`target/candidates/rebuild-20261103T231415Z/authored-host-baseline-debian-clean-x86_64.json`, reconciliation, projection) and read-only guest inspection to identify the object(s) whose ownership did not match.
2. **Is it a product bug or a lab/environment artifact?** E.g. objects created by Docker/the inert container in the HOST namespace (veth, docker0 routes/addresses) not accounted for, a baseline gap in the fresh baseline, a guest-specific kernel difference (6.12.113 cloud kernel), or a genuine defect in the native bootstrap host inventory/ownership logic that the old lab never reached because it timed out first. Give evidence for and against each hypothesis.
3. **What does 409 tell us about the 402–408 Deadline failure?** The fresh lab has 3 links vs the old 61; say carefully what can and cannot be concluded (no causal speedup claim without evidence; the brief `task-8c-driver-cost-brief.md` sets the attribution rules).
4. **Recommended next step** and its cost: a code fix (where, with a test that reproduces it offline if possible), a baseline/lab correction, and whether a new run (410) is needed, plus what it should measure. Do not implement product code changes in this task; small read-only scripts for analysis are fine.
5. Note the `SyntaxWarning: "is not" with 'str' literal` printed by remote payloads of `inspect-run409-state.py` (line ~20 of its remote program) and `inspect-secret-bootstrap-failure.py` (~24): is it a correctness bug (identity comparison against a str literal) that could have produced a wrong result in the I/F outputs above? Point to the lines.

## Constraints

Read-only on the guest (strict confined SSH: `-F /dev/null`, `GlobalKnownHostsFile=/dev/null`, `IdentitiesOnly=yes`, `IdentityAgent=none`, `-i target/lab-state/id_ed25519`, pinned `UserKnownHostsFile`, `StrictHostKeyChecking=yes`; `sudo -n` inside the guest only for reads). Do not run 409 or any Bootstrap, do not run selector archival, do not clean up guest resources (preserve everything), do not modify reservation/claim/raw files, no sudo on debdev, no git staging/commit/push, no subagents. Cargo only for reading/building tests if needed, `-j 4`, no full release builds. Work autonomously.

## Deliverable

`.superpowers/sdd/rust-v2/task-8c-bootstrap409-diagnosis.md`: root cause with file:line and evidence, hypothesis table, conclusion on 402–408, recommended next step, the SyntaxWarning assessment, and the exact commands you ran.
