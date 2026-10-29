# Task8c prerequisite: Bootstrap boundary diagnostics

2026-10-29. Base `b318eac5aa48606cc7f0753984920bd1f9303b42`, branch
`rust/v2`, workdir `/DATA/AppData/vprouter-rust-v2`. Implemented the authorized
three-file diagnostic plan under `task-8c-bootstrap-diagnostic-brief.md` and
Root's follow-up approval. Source is now frozen for independent scoped review.
No semantic cause or fix is claimed.

## Source changes and frozen hashes

Only these three source paths changed:

| File under crates/vprouter-launch/src | SHA256 |
| --- | --- |
| attachment/host_addition/operation.rs | `cf912fadb68570280a64ea27459b8f8f7312c2a5b0a5b051498fe5cd65e2fd56` |
| attachment/operational.rs | `91045ec0fdae02ad9953ba470652160aa5a1793f7598f48309b5957b4896ccaa` |
| attachment/operational/bootstrap.rs | `0e5f1f870a8451e4a0747b3d2da1b2151d305c95ec41df9a6c8007753b9d5fc9` |

`operational.rs` provides a `cfg(test)` marker helper and a separate bounded
retirement helper. Calls in ordinary constructors are individually
`cfg(test)`; calls in already test-gated fixture bodies inherit that gating.
Imports of the helper are test-gated. No new non-test logging or authority is
introduced.

Two existing expressions were factored to place a success marker accurately:
the test-only host return extracts the same complete owner before logging its
successful return; the Bootstrap constructor stores the result of its existing
single `service_mut()?` access in a local reference before the same
`start_inspection` call. Neither adds a validation/access call, alters the
original Result/error, or changes failure handling. Every original enforcement,
ownership, expiry, history, capacity and witness predicate remains present.

## Diagnostic contract

New stderr records have exactly one of these two text shapes:

```text
LAB_SECRET_BOOTSTRAP_PHASE stage=<fixed literal> event=begin
LAB_SECRET_BOOTSTRAP_PHASE stage=<fixed literal> event=ok
LAB_SECRET_BOOTSTRAP_PHASE stage=handoff.retire event=begin retired=<0..5>
LAB_SECRET_BOOTSTRAP_PHASE stage=handoff.retire event=ok retired=<0..5>
```

The helper receives only fixed stage literals and a completion boolean. The
retirement helper prints only its fixed stage and the existing count clamped to
five for a bounded diagnostic representation; it does not modify stored count
or any branch. There are no added clock reads, error conversions, getters,
descriptor inventories, IDs, paths, profile/credential bytes, argv or env.
The unchanged final error supplies the error class. These are diagnostic phase
events, never PASS, native completion, or canonical ACK witnesses. The prefix
does not equal the existing `LAB_SECRET_BOOTSTRAP ` witness prefix.

The entered boundary without its matching `ok` is the narrowest emitted
unfinished group; enclosing groups can also remain unfinished. `handoff.retire`
is sequential: a successful pair begins with the prior retired count and ends
with the next count. Existing intentional fence fixtures can skip later
boundaries. `handoff.return` and `bootstrap.return` are terminal success markers
and have only `event=ok`.

Stage coverage:

- Host fixture after its native loop: `host.writer_summary`,
  `host.prefix_histories`, `host.intent_oracle`, `host.first_writer`,
  `host.operation_summary`, `host.operation_receipts`, `host.writer_receipts`,
  `host.inventory`, `host.schema_oracle`, `host.charges`, `host.return`.
- Exact20 handoff: `handoff.host`, `handoff.anchors`, `handoff.host_witness`,
  `handoff.construct`; its constructor has nested `handoff.plan` and
  `handoff.reserve`. Retirement uses the bounded count above. Subsequent groups
  are `handoff.final_counts`, `handoff.resource_evidence`,
  `handoff.reservation_evidence`, `handoff.preparation_read`,
  `handoff.preparation_equal`, `handoff.return`.
- Initial Bootstrap constructor: `bootstrap.complete`, `bootstrap.context`,
  `bootstrap.query`, `bootstrap.retain`, `bootstrap.service`, `bootstrap.queue`,
  `bootstrap.return`.

Some boundaries group several existing checks, notably the host schema-negative
oracle and operation receipts. A failing phase identifies that boundary, not
which mutation/check inside it failed. Additional predicate-specific diagnostics
would need a separate evidence-led decision; none was guessed here.

## Checks and preserved scope

- Initial direct `rustfmt --check --edition 2024 --config skip_children=true`
  on the three files returned1 solely because the new test-only Bootstrap
  helper import needed ordering. Corrected that import; the same final check
  returned0 with no output. No other files were formatted.
- `git diff --check` returned0 with no output. Read-only diff/status inspection
  showed precisely the three source paths above modified. No Git index, commit,
  branch, remote or publication operation was performed.
- Rehashed all six approved task8c.1 files; each still matches the frozen
  implementer/reviewer hashes:

```text
2ec561f7beac44fe84a542baff1c0d37152303f22dffa323b32d7422e85c1771 worker/operation.rs
5b7045736012a472573af427ad65b20f1e70fd8d5e63957607ffc2ea477b894a worker/engine.rs
dd3e39bfb7d3e6f1b26cff59656d8bfa46e25e1972c157c8dac38cb5b76196b9 worker/engine/tests.rs
da8e6c7b07bcbe3eca9bc44ed398e4eaaa33cd98a9b7162950671adf1a6585c7 launch/handoff.rs
ba7d139e1370205ec223a0c13236713b8fdadf28ccaaebd0d1419cac296b51ab launch/transport.rs
914033572568cfa628bda81a7f38b1611286a581df3493d90f1950a8f105ba21 launch/expiry.rs
```

Compile, unit/native tests, static/coherent builds and VM execution were
**NOT_RUN** for this increment: Root's latest instruction reserved builds and
native execution to Root after scoped review. Rustfmt parsing and diff checks
are not a typecheck. No subagents, manifest/context edits, privileged calls,
VM/SSH/Docker commands, profile/credential/identity access, cleanup, retry or
production changes were performed. The only other files written by this
assignment were the authorized run398 diagnosis and this report.

Run398 and all retained resources remain preserved. The original old-source
failure is not replaced by these diagnostics. Full8c remains ACTIVE; native
Bootstrap success, runtime/recovery, clients and release acceptance are not
established by this increment.

## Root execution addendum

Independent scoped spec/quality review PASS. Root coherent source `73a352604303796adbe60e4752b27ec6d60ff9de`
verified all202current/archive/Git inputs, bothstatic payloads/strictcontexts,
AMD64filterpreflight, fmt/diff and focusedstrictClippy. Exact reviewed baseline
51links/51addresses/154routes/5rules matched native projection without livefield
substitution. OwnedDebian attempt399 then FAILexit1/zero cases: all68phase events
complete the marked host/handoff/constructor groups;88journalinventorypairs,
final Interrupted. Canonical Host Bootstrap query Intent exists but birth/facts/
verification are absent. Lab handler masks the original pre-policy error by
requiring absent policyrequest. No398semanticfix or Bootstrapacceptance claimed.
Public raw-binding summary: docs/rust-v2/task8c-bootstrap-attempt399.json.
