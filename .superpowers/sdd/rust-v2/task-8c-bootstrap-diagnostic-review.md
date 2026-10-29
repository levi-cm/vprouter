# Bootstrap diagnostic increment: independent scoped review

2026-10-29. Reviewed the diagnostic brief, run398 diagnosis, implementer report, and exact frozen diff against `da6672ba14477edff0d3a775423d7f6a0dc93041`. The brief/report identify the earlier implementation base `b318eac5aa48606cc7f0753984920bd1f9303b42`; the review uses Root's supplied preservation checkpoint and exact diff. No semantic cause or fix is assumed.

**Spec verdict: PASS for this diagnostic-only source increment.**

**Quality verdict: PASS; no blocking findings.** This is source approval for the scoped diagnostics, not native Bootstrap/runtime/full8c/client/release acceptance.

## Findings

No severity findings identified in the frozen three-file delta.

The helpers at `crates/vprouter-launch/src/attachment/operational.rs:231` and `operational.rs:236` are `cfg(test)`. Every added caller in an ordinary constructor is individually `cfg(test)`, and the remaining callers are inside the already test-gated `host_addition/operation.rs:641` fixture or `operational.rs:250` handoff fixture. Imports are test-gated. All new phase arguments are fixed string literals. Output consists only of the fixed prefix, fixed phase, derived `begin`/`ok` event, and (for retirement) `retired.min(5)`. No new log reads or prints a private value, identity, path, descriptor, profile, argv, or environment. The new prefix does not equal the existing Bootstrap witness prefix.

The host post-loop assertions remain present and in their original order. The continuation return at `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1109` extracts the same complete owner with the same `OwnershipMismatch` result before the success marker and returns the same owner/witness tuple. No additional validation or ownership transfer was added.

Operational plan/reservation at `operational.rs:94`, retirement at `operational.rs:305`, and final evidence/comparison groups at `operational.rs:321` gain phase markers without changes to reservations, retirement arithmetic, repeated-retirement refusal, failure predicates, capacity limits, reaping, resource custody, or witness contents. The count clamp changes only the printed value.

The Bootstrap constructor markers begin at `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:474`. Its one original `service_mut()?` expression is factored into a local reference at `bootstrap.rs:520` so service access and queueing have separate markers. The same `start_inspection` call remains at `bootstrap.rs:525`; its original `n.fail(e)` and returned error remain unchanged. No new caller authority, evidence, query, or access call is introduced.

The delta adds no clock reads, deadline changes, error conversions, retry behavior, enforcement changes, retention changes, or modified failure latches. Test-only stderr output has ordinary wall-clock overhead; this source review does not establish timing behavior of a future native run. An unmatched phase marker localizes an unfinished group and is not itself an error cause, canonical ACK, PASS, or policy proof. Some groups deliberately contain multiple existing predicates, as the report states.

## Frozen source verification

All three current hashes match the review package and implementer report:

| Path under crates/vprouter-launch/src | SHA256 |
| --- | --- |
| attachment/host_addition/operation.rs | `cf912fadb68570280a64ea27459b8f8f7312c2a5b0a5b051498fe5cd65e2fd56` |
| attachment/operational.rs | `91045ec0fdae02ad9953ba470652160aa5a1793f7598f48309b5957b4896ccaa` |
| attachment/operational/bootstrap.rs | `0e5f1f870a8451e4a0747b3d2da1b2151d305c95ec41df9a6c8007753b9d5fc9` |

All six approved task8c.1 files were independently rehashed and still match their approved hashes: worker `operation.rs`, `engine.rs`, `engine/tests.rs`, and launch `handoff.rs`, `transport.rs`, `expiry.rs`.

## Evidence limits and preserved boundaries

The implementer explicitly records the initial import-order formatting failure and final rustfmt/diff checks; no failure is rewritten as a pass. This review did not rerun test suites, compile, build artifacts, or execute native/VM checks. No concrete source doubt required further code exploration outside the frozen three paths. Root's coherent build remains separate evidence and must not be inferred from this verdict.

The retained run398 `OwnershipMismatch` remains an old-source failed native attempt. This diagnostic increment neither determines that predicate nor establishes native Bootstrap policy readback, recovery, Ready, client traffic, or release acceptance. No native evidence or retained resource was changed or inspected by this review. Full8c and new runtime/client acceptance remain **OPEN**.

Review actions were local document/diff/source reads and hash checks only, followed by writing this report. No source, Git, production, privilege, VM, Docker, SSH, profile, credential, identity, resource, or cleanup actions were performed.
