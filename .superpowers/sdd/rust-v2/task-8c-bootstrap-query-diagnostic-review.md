# Bootstrap query diagnostics: independent scoped review

2026-10-29. Reviewed `task-8c-bootstrap-query-diagnostic-brief.md`, the implementer report, and the exact frozen one-file diff against `ce41a0ade4a7252b8b9eb75ed61c732fe596d88e`.

**Spec verdict: PASS for this bounded diagnostic correction.**

**Quality verdict: PASS; no blocking source findings.** One informational report-count correction is noted below. These verdicts do not grant native Bootstrap, runtime, full8c, client, or release acceptance.

## Findings

- **Informational, documentation only:** `.superpowers/sdd/rust-v2/task-8c-bootstrap-query-diagnostic-report.md:10` says 32 insertions and 1 deletion; the supplied exact diff reports **31 insertions and 1 deletion**. This does not affect the frozen source/hash or the semantic review. No source correction is needed for this discrepancy.

## Spec and quality evidence

- `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:368` emits the QueryIntent success marker only after the existing `poll_inspection_intent` returns `Some`. The spawn pair at `bootstrap.rs:370` surrounds the same original query spawn, and the Birth-queue pair at `bootstrap.rs:375` surrounds the same original service/Birth queue expression. Each new call is individually `cfg(test)`. Pending `None` polls emit none of these records. No constructor, validation, service access, state transition, or result expression is replaced in this production control flow.
- The changed error handler is wholly inside the existing `cfg(test)` `lab_run` at `bootstrap.rs:614`. Its exhaustive Step match at `bootstrap.rs:722` selects ten fixed literals. The new line at `bootstrap.rs:734` prints only that literal, the original enum error class, and two presence booleans. It adds no IDs, paths, descriptors, profile or credential values, argv/environment, clock reads, or per-pending-poll records.
- `bootstrap.rs:739` now returns the original `Err(error)` when the later policy request is absent, replacing the diagnostic masking `Interrupted`. The native poller already invokes the unchanged `n.fail(e)` and `n.collect()` before returning that error at `bootstrap.rs:559`. The missing-request branch adds no cleanup, cancellation, access call, or custody transfer; its early-return/drop route remains the same.
- With a request present, `bootstrap.rs:742` clones the same original Rc and then follows the previous failure log, injected-fault discriminator, collection, and oracle path beginning at `bootstrap.rs:743`. The existing clock-bearing failure record in that path is unchanged; the increment introduces no clock output. No production ownership/enforcement/error predicate, deadline, retry, failure latch, resource retention, or authority changes are present in the diff.

## Frozen source and preservation

The current sole changed source file hashes to the exact supplied value:

`b30f7d1879950e1e75d335989279954b64a8c46ccc3f15bdaded65d401e099da`

Both earlier diagnostic files (`attachment/host_addition/operation.rs`, `attachment/operational.rs`) and all six approved task8c.1 files were independently rehashed and still match their frozen values. No source or Git mutation was performed by this review.

The only code inspection outside the frozen path was `crates/vprouter-launch/src/error.rs:3`, for the concrete disclosure question raised by the new `{error:?}` field. `Error` is a derived-Debug, payload-free enum, so the new field cannot reveal external error payloads or private values. Within the scoped file, the existing poll/fail/drop context was inspected to verify error preservation and custody; no broader investigation was needed.

## Verification limits

No suites, compiler, artifact build, VM/native test, Docker, SSH, privileged, profile/credential/identity, or resource operation was run. Root's concurrent coherent offline build is separate evidence; this review does not claim it passed. The implementer's reported formatting/diff checks were not rerun, and source inspection is not typechecking or runtime validation. Test-only diagnostic output can add wall-clock overhead without changing deadline logic.

Original runs398 and399 remain preserved failed attempts; this correction does not reconstruct either original error or establish a semantic cause. New native Bootstrap, full8c, runtime/recovery, client, and release gates remain **OPEN**. This review wrote only this report.
