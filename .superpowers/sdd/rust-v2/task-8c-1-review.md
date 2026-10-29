# Task8c.1 independent spec and quality review

2026-10-29. Reviewed against `task-8c-1-brief.md`, its parent `task-8c-brief.md`, and `docs/rust-v2/IMPLEMENTATION.md`. Base: `b678e7bf98e0c311109ce82a3893b40127ef0825`. Scope: the six-file uncommitted delta in `task-8c-1-review-package.txt`; all six current source SHA256 values match that package and `task-8c-slice1-report.md`.

**Spec verdict: PASS for the bounded task8c.1 source slice.**

**Quality verdict: PASS; no blocking findings identified.** Neither verdict grants native runtime, full8c, client, release, or task9 acceptance.

## Findings

No severity findings in the reviewed delta. In particular, no newly introduced authority constructor, recovery caller boolean, retry change, heartbeat evidence renewal, or failure publication ordering defect was identified. The wire format requires coherent host/worker artifacts; an old health-only reply is deliberately rejected. Artifact coherence remains Root's build/deployment gate.

## Verified strengths and requirement coverage

- Complete observational receipts: `crates/vprouter-worker/src/operation.rs:29` defines a mandatory, unknown-field-rejecting receipt containing the existing complete `Binding` and explicit policy stage. `Prepared` and `Enforced` require it at `operation.rs:252` and `operation.rs:259`. Receipt validation at `operation.rs:36` compares the entire binding and stage, rather than just generation or health. Receipt decoding does not create placement, a native lease, or `ReadyPublication` authority.
- Actual readback and guard-first order: `crates/vprouter-launch/src/transport.rs:230` verifies retained native enforcement before constructing the receipt. `crates/vprouter-launch/src/handoff.rs:1126` installs and reads back Offline for non-Ready Prepare; independent health/binding validation occurs at `handoff.rs:1143` before its receipt at `handoff.rs:1148`. The worker validates the bound Offline receipt at `crates/vprouter-worker/src/engine.rs:504` before withdrawal at `engine.rs:518`.
- Failure and healthy policy are separated: `operation.rs:17` classifies failed Blocked, Stopping, and Failed as Offline while healthy Starting/Blocked/Recovering publications use Bootstrap. `transport.rs:277` applies that classification, retaining independent lease and host-evidence checks for Ready at `transport.rs:280`. Ready persistence still obtains the private, exact-snapshot native proof before publisher submission at `handoff.rs:1174`; the serializable receipt is never substituted for it.
- Failure completion and precedence: `engine.rs:589` awaits the full publication transaction before returning the original sample result at `engine.rs:594`. Protocol, receipt, withdrawal, persistence, or commit errors therefore take precedence. The operational loop propagates the result at `engine.rs:678`, terminating on a failed sample instead of resuming provider checks behind full Offline. Same-lifecycle rebootstrap is not silently added.
- Terminal observations and no revival: `crates/vprouter-launch/src/expiry.rs:81` latches the independently reconstructed terminal state. Stopping requires the exact Stopping reason at `expiry.rs:95`; Failed requires a reason at `expiry.rs:100`. A terminal state cannot transition to Starting/Blocked/Recovering/Ready through this observer.
- Existing timing and identity controls remain in place: the delta does not relax frame nonce/lifecycle/sequence/timestamp validation, authenticated sender/daemon/allocation checks, the original publication end, the Ready structural anchor, independent expiry, or the separate liveness watchdog. New receipts pass through the existing final reply verification and deadline path at `handoff.rs:1256`.
- Focused tests use actual framed UnixStreams: the new matrix at `crates/vprouter-worker/src/engine/tests.rs:759` covers wrong Prepare/Commit stages, changed bindings/generations, a missing-policy historical ACK, wrong Commit health, no premature withdrawal, no provider invocation during failure completion, and original-error versus protocol-error precedence. The actual HealthMachine policy test begins at `engine/tests.rs:874`; the independent terminal test begins at `expiry.rs:1366`. The scripted recovery test was accurately renamed and is not presented as native recovery proof.

## Targeted inspection outside the diff

Two concrete risks required checking existing code beyond changed hunks:

1. **Could a terminal snapshot carry evidence or a copied foreign binding into the new terminal path?** Inspected `crates/vprouter-core/src/health.rs:106`, `health.rs:167`, and `health.rs:292`, plus the existing `expiry.rs:487` call order. Session/replay validation compares the complete retained Binding and rejects evidence-bearing Stopping/Failed snapshots before `observe_original` runs. `crates/vprouter-core/src/state.rs:116` independently rejects observations once terminal. This resolves the source-level concern; the new observer test alone would not prove the upstream validation.
2. **Could heartbeats or evidence-free terminal publications refresh complete verification age, or could Engine failure handling withdraw early?** Inspected `health.rs:255`, `health.rs:308`, `expiry.rs:146`, `expiry.rs:164`, and `engine.rs:134`. Only fresh complete evidence updates `verification_at`; evidence-free messages update the message clock without replacing the earlier complete-evidence deadline. Liveness has its own deadline. Engine sample failure cancels pending I/O and blocks its machine without withdrawing; operational withdrawal remains after the validated policy receipt.

No other code exploration was needed. The review package diff was read once; subsequent reads were focused source context for the above ordering, validation, and deadline questions.

## Evidence and cannot-verify items

- The implementer report records worker 62/62, launch 147/147, clippy, fmt, and diff checks passing, and retains the initial formatting and fixture failures explicitly. This review checked the new tests and production wiring against the diff; it did not independently rerun those already-passed suites or promote their reported results to runtime proof. No focused execution was necessary to resolve a remaining concrete source doubt.
- Native kernel execution of the new receipt transaction, real guard/worker publication and failure-to-rebootstrap, coherent newly built artifacts, protected provider/enrolled-daemon/client traffic, SIGKILL/collision/capture checks, static architecture qualification, and full platform/performance/migration/soak acceptance remain **NOT_RUN by this review**. Actual restart/withdrawal/rebootstrap remains task8c.2 under retained native authority.
- This review made no production, profile, identity, credential, network, VM, Docker, SSH, privileged, Git, or source changes. It ran only local read commands and wrote this review report. Existing failed evidence remains preserved. Full8c and runtime/client acceptance remain open.
