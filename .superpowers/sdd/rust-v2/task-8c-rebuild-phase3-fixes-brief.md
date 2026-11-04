# Task 8c rebuild phase 3 fixes brief

Workspace `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`, HEAD `6ca0073`; phase 3/3b changes unstaged — build on them.

Read `.superpowers/sdd/rust-v2/task-8c-rebuild-phase3-review.md` in full (FAIL / NO-GO), plus the phase 3 and 3b briefs/reports for context. Reviewer scratch with reproductions is in `/tmp/vprouter-phase3-review/` (`listing-compile.json`, `failure-route-downgrade-check.py/.json`, `inspector-timeout-check.py`) — reuse the ideas, but make your regressions versioned under `tools/rust-v2-lab/`.

## Fix

1. **C1 (Critical):** the `listing` remote script in `run-frozen-secret-bootstrap.py` (≈:55–62, restored and archived copies) is indented inside the triple-quoted string and fails with IndentationError on the guest, after the one-shot claim. Repair it so the remote program is byte-for-byte what HEAD sent on the historical path (plus only the intended fresh boot prefix on the fresh path).
   - **Systemic guard:** before the claim is consumed, `compile()` every remote Python program the controller will send (listing, and every other inline/guest payload in the execution path: SCP'd scripts, any `python3 -` stdin bodies), on both fresh and historical paths. Any compile failure must refuse before the claim. Audit the other changed tools (`collect-run409-evidence.py`, `inspect-run409-state.py`, `phase3-readonly-preflight.py`, `fresh-baseline.py`, F/A tools) for the same class of bug, and compile-check their remote payloads too.
   - Make `--preflight-only` exercise this compile gate (it currently returns before the listing is assigned), so a dry run would have caught C1.
   - Add an offline regression that extracts the actual generated remote programs (fresh and historical) and compiles them, and that compares the historical listing to HEAD's.
2. **I1 (Important):** in `inspect-secret-bootstrap-failure.py` and `archive-secret-bootstrap-selectors.py`, fresh-branch selection must not hinge on the presence of the `run_reservation` field alone. Run 409, or any record/declaration that is identifiably fresh (route `fresh-lab`, false historical flags, fresh reconciliation), must take the fresh branch and fail if the marker or its bindings are missing; the historical fallback must explicitly reject fresh identity. Add offline tests with SSH blocked (intercept subprocess) for: valid marker → passes to SSH; tampered → refused; marker deleted → refused; mixed provenance → refused, for both tools. Genuine historical branches and existing archival identity checks stay intact.
3. **M1 (Minor):** `inspect-run409-state.py` ≈:79–83 — catch `TimeoutExpired`/`OSError`, keep partial stdout/stderr with an error classification in the exclusive receipt, return failure, keep `archival_authorized=false`. Add an offline test.
4. **Mirror and rebind:** mirror every restored-controller change into `tools/rust-v2-lab/target/` and update `tools/rust-v2-lab/source-manifest.json`. The current reservation is now stale: supersede it through the existing reviewed supersede mechanism (keep every prior generation and tombstone; never edit or delete reservation/claim data in place). Budget stays 1 overall and unspent.
5. **Re-run gates:** all phase 3/3b tests and the new ones, `--preflight-only` with the new reservation (must now include the remote-program compile gate), manifest/archive checks, `python3 -O` guards, `git diff --check`, read-only guest status.

## Constraints

Do NOT execute run 409, consume the reservation, or mutate guest network/namespaces/nft/containers. Strict confined SSH on every call; no sudo on debdev; no production/credential use; no git staging/commit/push; no subagents; cargo only if Rust changes (`-j 4`). Work autonomously without asking for approval.

## Deliverable

`.superpowers/sdd/rust-v2/task-8c-rebuild-phase3-fixes-report.md`: per finding, the fix with file:line and the regression proving it; the systemic compile-gate audit result for every remote payload; reservation chain (old/new hashes, budget); exact commands and exit codes; NOT_RUN items; the final run-409 command.
