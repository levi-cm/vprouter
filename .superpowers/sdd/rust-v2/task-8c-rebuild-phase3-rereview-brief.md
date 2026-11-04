# Independent re-review brief — Task 8c phases 3 + 3b after fixes (run409 gate)

Workspace `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`, HEAD `6ca0073`; all phase 3/3b/fix changes unstaged.

Inputs:
- First review (FAIL / NO-GO): `.superpowers/sdd/rust-v2/task-8c-rebuild-phase3-review.md` — findings C1, I1, M1.
- Fix brief and claims: `task-8c-rebuild-phase3-fixes-brief.md`, `task-8c-rebuild-phase3-fixes-report.md`.
- Original scope: `task-8c-rebuild-phase3-review-brief.md` (same file lists, questions 1–6 and permitted checks apply), phase 3/3b briefs and reports.

Treat the reports as claims. Answer:

1. Is each of C1, I1, M1 actually fixed, with a regression that fails on the pre-fix code? Check the pre-fix behaviour against the reviewer reproductions in `/tmp/vprouter-phase3-review/` where useful.
2. Does the new pre-claim compile gate cover **every** remote program the run-409 execution path sends (inline `python3 -` bodies, SCP'd scripts, guest programs), on fresh and historical paths, and does `--preflight-only` exercise it? Is the historical remote listing byte-identical to HEAD's?
3. Beyond syntax: is there any other deterministic way the exact run-409 command would spend the claim and then fail before Bootstrap produces its raw record (wrong paths, missing files on the guest, permission/ownership, sudo -n requirements, argument mismatch, SCP destination, timeouts shorter than the work)? Trace the execution path after the claim step by step against the current guest state (read-only).
4. Reservation chain: superseded generations preserved, one live reservation bound to current bytes, budget 1 overall, no way to consume an old one.
5. Regressions: anything the fixes broke in historical behaviour, manifest/archive/restored-copy consistency, SSH confinement, `-O` guards.
6. GO / NO-GO for executing run 409 now, with blocking findings.

Permitted: read-only/offline checks, the tests, `--preflight-only` (confirm from code first that it cannot consume), `py_compile`, manifest checks, `git diff`, `ssh -G`, read-only guest inspection over the strict confined SSH (no mutation). Not permitted: executing run 409, consuming/creating a reservation, guest mutation, staging/commit/push, sudo on debdev, subagents. Scratch under `/tmp/vprouter-phase3-rereview/`.

Deliverable: `.superpowers/sdd/rust-v2/task-8c-rebuild-phase3-rereview.md` (only file written outside /tmp): verdict PASS/FAIL, GO/NO-GO, findings Critical/Important/Minor with file:line and concrete failure scenario, then verification ledger.
