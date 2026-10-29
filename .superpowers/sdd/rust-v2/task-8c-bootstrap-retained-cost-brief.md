# Bootstrap retained-validation diagnostic requirements

Worktree `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`, source milestone
`bf3247b`. Read this first, then frozen task-8c-bootstrap405-diagnosis.md and
the binding IMPLEMENTATION.md. This is diagnostic preparation within active8c.
Source implementation is conditional on independent requirements review and
Root's explicit dispatch. No optimization is authorized.

405 failed HOST/native_poll/result/Deadline with zero cases. Inclusive retained
totals do not separate fresh owner/namespace/cgroup work from pure history and
digest work. Counts differ from404, so there is no controlled native cost effect.

Add a separate fixed table with exactly these eight keys, in this order, for
each existing query/policy/other lab-loop-entry family:

- `retained_transport`: elapsed/count around the existing Binding transport call.
- `retained_data`: elapsed/count around the existing Binding DATA call.
- `retained_owner_record`: elapsed/count around only the existing owner.record
  expression, at its original short-circuit position.
- `retained_history`: elapsed/count around the existing full History.validate call.
- `history_allocation_digest`: elapsed/count around the existing allocation
  serialization and digest expression inside History.validate.
- `created_group_native`: elapsed/count after existing Request.verify_retained
  succeeds, covering the remainder of verify_created_group, including early errors.
- `source_identity_entries`: count only at Source.identity entry.
- `native_source_entries`: count only at Native.source entry.

Emit `LAB_SECRET_BOOTSTRAP_RETAINED_TOTAL` rows only at the existing snapshot
failure boundary, after all existing30 nested rows. Use closed fixed family/key
labels and bounded saturating counts/nanoseconds. All rows carry
`measurement=inclusive_retained_elapsed` and
`grouping=lab_loop_entry_step_family`. Count-only keys have elapsed_ns=0. Retain
all existing13 wrapper and30 nested rows with unchanged order/meaning. No
per-entry/per-poll output, dynamic labels, paths, identifiers or request contents.

Use the existing session/family/epoch/creator boundaries. Do not make the old
timers copy a larger table on every entry/drop; store the additional fixed rows
separately and update selected rows only. No lock, live borrow across measured
work, dynamic/unbounded allocation, fallible logging, new authority or new native
operation. Child copies remain COW-private; no merge/export. No getpid in timer
or counter paths; no syscall/filter changes. Parent stop must disable collection
before output. Existing inactive/reentrant/epoch/error semantics remain exact.
Additional instrumentation overhead must be reported, not interpreted as CPU.

All new instrumentation is cfg(test), absent from normal builds. Keep original
expressions, evaluation/short-circuit order, Result/errors, every call and clock
observation exact. Minimal braces surrounding an original expression may house
cfg(test) RAII timers; never precompute owner.record before earlier conditions.
Do not cache verdicts, remove repeated checks, change deadlines/holds/negatives/
release/ACK/pending/writer/fence/custody checks, or alter failure handling.

Exactly five source paths are owned:

- `crates/vprouter-launch/src/owned/preparation/quarantine.rs`
- `crates/vprouter-launch/src/owned/preparation.rs`
- `crates/vprouter-launch/src/kernel/producer_creation.rs`
- `crates/vprouter-launch/src/attachment/quarantine/producer.rs`
- `crates/vprouter-launch/src/owned/preparation/lab_cost.rs`

No other source, manifest, dependency, controller, parser, golden, acceptance,
retry repair or resource change. No Git mutation, coherent build, VM/SSH/Docker,
profile/identity/privileged/native actions or subagents. Root owns those steps.

Snapshot every Rust source hash before editing. Prove all unowned files unchanged
and reconstruct normal-build source equivalence after excluding new cfg(test)
code/minimal expression braces. Add only meaningful diagnostic-helper tests for
inactive/count-only/early-error/nested/epoch/stopped behavior that needs coverage.
Run launch library tests, fmt and strict launch lib/tests Clippy; retain exact
commands and full logs under ignored target. No native cost witness yet.

Freeze task-8c-bootstrap-retained-cost-report.md, exact diff and final owned/
unowned hashes for independent spec/quality review. Report all observer effects,
overlap (including history/digest and transport/DATA), error-entry counting and
remaining native gates. Root requires review, coherent artifacts, authored
preservation, milestone push and new owned local native experiment before any
cost claim. Full8c/ARM/client/migration/performance/release acceptance stays open.
