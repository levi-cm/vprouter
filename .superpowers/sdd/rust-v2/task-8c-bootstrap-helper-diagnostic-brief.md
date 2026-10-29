# Identify the original held-helper error and measured wrapper costs

Workdir /DATA/AppData/vprouter-rust-v2 branch rust/v2, base50cf9c4c7c2caceb3e0f6d406e5f45a66d7db8ee.
Read task-8c-bootstrap402-diagnosis.md first and binding parent8c contract.
402FAIL/zero cases/noPOLL_FAILURE is an outer lab helper reporting path;
helpers still enforce original production clocks. No exact helper/failedclock/
perphasecost/parentACK has been captured. No semantic fix selected.

ONE owned source file: crates/vprouter-launch/src/attachment/operational/bootstrap.rs.
All changes strictly cfg(test), confined to lab orchestration/diagnostics.
Add fixed-label original-error diagnostics around existing query and policy
hold/queued-negatives/checkpoint/held-negatives/identity/release outer calls,
and the existing native-poll boundary. Preserve every original call, ordering,
number of held polls, negative check, original Error and error/drop/collection
behavior. Do not change existing error into Interrupted or a logging error.

On error emit once a closed fixed helper+Step label, original Error class,
cached query/policy presence and own/query held/released/queued counters, original
query requested_at/deadline and one current boot-time observation. Use only
already-retained infallible scalar getters/counters. No fallible Context/Source/
Request/writer getter/verification for logging. No descriptors, identities,
paths, profile/credential material, raw requests, arbitrary strings or per-
pending-poll output. Keep existing native-poll diagnostic; distinguish helper
failure from native-poll failure. No handler that overwrites original failure.

Accumulate bounded cfg(test) call counts and elapsed duration totals around the
actual existing fixed wrappers AND native poll; emit the fixed-size table only
once on error (or one completed final witness). Saturating counters/durations
must not fail or change control flow. Clearly label totals as measured wrapper
cost incl nested validation, not individual predicate CPU or a new clock.
Bracket without extra verification, retries, sleeps, deadline refresh or changed
operations. These metrics identify where time is spent; they grant no authority.

No enforcement/clock/deadline/typed-proof/role/filter/resource/recovery/UP/Ready/
placement/cleanup change. Do not remove or weaken held-query/policy tests to
fit a deadline. All other source paths, including three ancestry corrections,
twelve other pending-progress paths and six approved receipts remain unchanged.
No subagents/Git/manifests/contexts/staticbuilds/VM/SSH/Docker/profile/identity/
privileged operations. Local focused tests/fmt/clippy permitted; avoid tests
that merely assert copied diagnostic text. Root owns coherent build/native gate.

Write task-8c-bootstrap-helper-diagnostic-report.md with exact source hash,
production cfg exclusion, unchanged behavior/error semantics, local checks and
limits. Freeze for independent spec+quality review. Native403 remains NOT_RUN;
Root preserves402 and expected55-link baseline, then checks exact artifacts and
pushes checkpoints before any reviewed new diagnostic native invocation.
