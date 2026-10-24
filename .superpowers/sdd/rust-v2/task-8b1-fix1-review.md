### Finding Verdicts

- **Bound connection establishment before the framing deadline — ADDRESSED.** `crates/vprouter-worker/src/bootstrap.rs:456-490` creates the AF_UNIX socket with NONBLOCK|CLOEXEC, rejects a full-backlog EAGAIN and connection refusal, and bounds any pending completion with the existing absolute-deadline poll plus SO_ERROR and connected-peer verification. The real admission path shares one deadline across connect, request write and response read at515-534. Regression tests cover a full backlog, a connected but nonresponding listener, an expired deadline and refused connection at562-577,608-646. The old blocking connect is gone from the changed production path.
- **Required focused replay/binding refusal tests — ADDRESSED.** `crates/vprouter-launch/src/handoff.rs:42-60` extracts the private production one-use state and request-binding predicate; `serve_once` consumes that state before authority verification at236-237 and invokes the tested binding predicate at285. Tests at348-372 check success then second-attempt refusal, consumption before a possible authority failure, wrong digest/nonce/schema and refusal of a later valid retry. `crates/vprouter-worker/src/bootstrap.rs:491-501,533-534` uses the private response predicate in real admission, while579-605 tests framed current/stale digest, nonce and schema responses against that exact predicate. These are focused production-unit tests; live mount/peer integration remains explicitly deferred.

### New Breakage in the Fix Diff

- None found. The new connector is nonblocking from socket creation, retains CLOEXEC, fails closed on connection errors, checks the deadline again after completion, and preserves the existing credential/configuration-before-socket ordering (`crates/vprouter-worker/src/bootstrap.rs:456-534`).
- None found in the one-use refactor: state remains private/non-resettable, consumption still precedes accept/authority validation, and request/response binding checks retain schema, digest, nonce and observation-only permission (`crates/vprouter-launch/src/handoff.rs:42-60,233-237,283-285`; `crates/vprouter-worker/src/bootstrap.rs:491-501,533-534`).
- Both architecture manifests refresh only observer digest/size, retaining exact paths, role policy and pinned upstream daemon bindings (`docs/rust-v2/programs-amd64.json:7-19`; `docs/rust-v2/programs-arm64.json:7-19`). Updated producer evidence distinguishes candidate03/04 and explicitly disclaims observer/runtime certification (`docs/rust-v2/producer-placement-lab-evidence.json:102-146,171-188`).

### Out-of-Scope Observations

- None. No fresh review of untouched implementation was performed.

### Checks Performed

- Read the scoped re-review template, original review, task8b1 brief, appended fix report and all856 lines of the supplied authoritative fix package in bounded passes. The assessed package is base8761fb836c16cf215621af870b24624eed726eb1 through supplied head8d8611fdc470cbcfe654c45fedce0a4030a35ef5. Its textual header uses HEAD and its commit list abbreviates8d8611f; the controller supplied the full SHA without a reviewer git command.
- Checked the appended report names the covering backlog/stalled/refusal and replay/binding tests, reports the original blocking connector RED and fixed connector GREEN, and records final focused/workspace/fmt/clippy/ARM/static-build results (`.superpowers/sdd/rust-v2/task-8b1-report.md:199-272`). No reported suite was rerun.
- Read the exact named `target/review-fix-round1-mutation-red.log`: disabling host consumption makes both host tests fail with an unexpected Ok on a second attempt; removing worker nonce rejection makes the stale-response test fail with true versus false. Both mutations exit101, matching the report. The committed diff retains the checks those mutations removed.
- Accepted the controller's independently verified97-input binding, four static artifacts/manifest bindings, candidate04 eight-case producer refresh and terminal ownership inventory as supplied evidence. Those checks do not certify observer deadline/replay/runtime behavior; the focused unprivileged regressions cover the fixes (`docs/rust-v2/producer-placement-lab-evidence.json:103-146`; `.superpowers/sdd/rust-v2/task-8b1-report.md:259-286`).
- The current report has a later14-line controller-verified bookkeeping append for the candidate04 root result, absent from the package's report hunk but consistent with the public attempt4 evidence already in that package. The controller states this subsequent commit changes no build inputs; this re-review does not extend the source assessment beyond the supplied8d8611f package.
- No tests/builds, privileged actions, network/remote operations, credential/state access, git commands, subagents or checkout/index/HEAD mutations were performed. Only the requested report outside the checkout was written.

### Verdict

**Spec compliance:** Approved for this bounded fix round; both original Important findings are addressed. Actual observer/Go/live handoff/image/ARM runtime/client/readiness evidence remains explicitly NOT_RUN for8b2/8c (`.superpowers/sdd/rust-v2/task-8b1-report.md:270-286`).

**Code quality:** Approved; no new Critical, Important or Minor breakage found in the fix diff.

**Fix round:** All findings addressed, no new Critical/Important breakage. No open findings remain from the original task8b1 review.
