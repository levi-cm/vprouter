# Bootstrap helper error boundary and measured wrapper diagnostics

2026-10-29. Implemented the diagnostic-only brief against the supplied semantic
base `50cf9c4c7c2caceb3e0f6d406e5f45a66d7db8ee`. Source is now frozen for fresh
independent spec and quality review. Native403 is **NOT_RUN**. Run402 remains
FAIL; its exact helper, failed clock predicate and individual operation costs
are still unproved until Root obtains a new reviewed native witness.

## Owned source and exclusion

The only changed Rust path is
`crates/vprouter-launch/src/attachment/operational/bootstrap.rs`.

- Before SHA256: `a69afe95279995aff491c1e153473af9398cabbc8a6342407266a522dd836759`.
- Final SHA256: `88320812125ab5f735a70ee6e1d0a935699dcc27f7ea4d9d7f3bca72f539e142`.
- Current production prefix, before `#[cfg(test)] const LAB_LABELS`, SHA256:
  `6264d3bc2d5edb1fe63ac587006fe7109dad7959fd9317d8e9e0aa359d807d05`.

All edits are inside the existing `#[cfg(test)] lab_run` or the new complete
`#[cfg(test)] lab_diagnostics` module. No production method, field, enum or
enforcement path changed. Normal non-test compilation excludes the new module,
its types, the local macro, counters, measurements and logging. No production
constructor, authority getter, feature flag or unsafe operation was added.

A pre-edit SHA256 snapshot covered all178 `crates/**/*.rs` files. The final
comparison has exactly this one changed path and no added/deleted Rust paths;
all177 others, including all21 other protected source paths, are unchanged.
Snapshot `/tmp/task8c-helper-diagnostic-before.json`, SHA256
`3927e6b52f53a28c2c89f7ab12651f4ecede6487517be5ec2eb83cec0cfb2002`.
Root owns the independent Git diff/checkpoint check; no Git command was run here.

## Fixed boundaries and emitted data

A closed13-variant helper enum labels these existing operations:

1. query Source acquisition (the original Context call and Source clone);
2. query hold;
3. query checkpoint;
4. query writer identity, including its original missing-writer refusal;
5. the original inline query held-negative checks;
6. query release;
7. policy hold;
8. policy queued-negatives;
9. policy checkpoint;
10. policy held-negatives;
11. policy writer identity, including its original missing-writer refusal;
12. policy release;
13. the main native-poll boundary.

The first error from one of those boundaries emits one
`LAB_SECRET_BOOTSTRAP_BOUNDARY_FAILURE` record. It identifies the fixed helper,
fixed current Step and original enum-only Error class. It includes cached query,
query child, accepted query and policy Request presence; query/own queued,
held-poll, completed-negative and released counters; the original query's
requested_at/deadline; and one current boot-time observation. If the native
bundle is absent, presence is false, Step is the fixed `absent` label, and original
times are `None`; logging does not use a fallible invariant getter to recover it.

Query `queued` is a diagnostic-only boolean set after the existing hold call
succeeds. Own `queued` retains its existing meaning: both policy hold and queued
negative checks completed. Held and negative counts are the original orchestration
counters, read before any following counter increment. They do not claim a
child ACK or reached checkpoint by themselves.

The same first error emits a fixed13-row
`LAB_SECRET_BOOTSTRAP_WRAPPER_TOTAL` table, including zero-call rows. Each row
has a fixed helper label, saturating u64 call count and saturating Duration sum
in nanoseconds. A single emitted flag bounds output to one snapshot/table per
lab invocation. Successful calls and pending polls add no diagnostic output.
The existing `LAB_SECRET_BOOTSTRAP_POLL_FAILURE` and subsequent native-poll
failure handling are unchanged. `helper=native_poll` distinguishes that boundary
from an outer helper error; helper errors still return directly through `?` and
do not enter the native-poll error handler.

## Measurement and error semantics

Each wrapper brackets its actual original call with `Instant::now/elapsed`,
records a saturating count/duration and returns the original Result unchanged.
The main native poll is bracketed in the same way. These are elapsed wrapper
totals including nested validation, IO and scheduling, explicitly labelled
`wrapper_elapsed_including_nested_validation`. They are not predicate CPU
measurements or a replacement enforcement clock. No threshold, deadline refresh,
fresh request window, retry, sleep, verification or child operation was added.

The measured table covers the prefix up to the first instrumented error. It
does not cover PendingBootstrap construction, time between wrappers, sleep time,
logging overhead, later collection or the two existing post-error refusal polls.
The fault2-specific DATA result hold/checkpoint/charge helpers and all later
collection/evidence paths remain untouched. No final-success table was added.

Failure logging reads only cached Option/scalar fields and the original query's
infallible scalar time getters. It never calls Context, Source, Request, Pins,
writer verification or a fallible identity getter to construct the log. Its
boot-time observation is after the failed wrapper and duration accounting; it
is not the exact predicate evaluation time. Fixed formatting emits no descriptor,
identity, path, profile, credential, raw request or caller-supplied text.

New output uses best-effort `writeln!` with its IO Result discarded, so an output
failure cannot replace the original Error with a logging IO error. The Error is
Copy and is returned unchanged. Neither failure latch nor collect/retain/Drop
behavior changed. All original calls, short-circuit negative-check order, two
held polls, negative counters, writer identity checks and releases are retained.
The small closures around existing inline negatives and writer Option refusal
only let their original errors pass through the measurement boundary before the
same outer return. No fixture authority was manufactured and no test was removed
or weakened to fit the original window.

## Local verification

Final candidate:

- `cargo test -p vprouter-launch --lib`: PASS,148 passed,0 failed,0 ignored.
- `cargo clippy -p vprouter-launch --lib --tests -- -D warnings`: PASS.
- `rustfmt --edition 2024 --check crates/vprouter-launch/src/attachment/operational/bootstrap.rs`:
  PASS.
- Source hash comparison: exactly the one owned Rust path changed; other177
  unchanged. No trailing whitespace in the owned source.

No diagnostic-text mirror tests were added. The existing suite compiles the
test-only orchestration and exercises its existing offline behaviors; it does
not execute the full original Bootstrap helper chain or prove the new native
failure record. Strict Clippy also compiles the normal library without the
test-only module. Full native runtime output and costs remain **NOT_RUN** here.

An initial148-test library run also passed before the final best-effort output
and module-placement adjustment. The initial strict Clippy attempt failed solely
with `items_after_test_module`: the cfg(test) diagnostic module preceded
lab_run. The module was moved after lab_run without a lint suppression; final
strict Clippy and the final148-test suite then passed. The original failure log
is retained.

Final logs:

- `/tmp/task8c-helper-diagnostic-lib-final.log`, SHA256
  `b8b20c133ed999314b5bcd2887aae86602f0fa1a3f9eb1d59f3924c1a9d8cbaf`.
- `/tmp/task8c-helper-diagnostic-clippy-final.log`, SHA256
  `6639404a1bec15caf9b8a1ba6e5334e183139a6fbaaf54fc57813cfd319becc1`.
- Initial failed `/tmp/task8c-helper-diagnostic-clippy.log`, SHA256
  `563d3e5ed9c0b48b51564cc8b082dd2886aa1dd3d18be90f209c13d44d2bf245`.

No VM, SSH, Docker, privileged, protected-profile/identity, Git, manifest/context,
standalone/static/cross-architecture build, native invocation or subagent action
was performed. Local cargo test/Clippy compilation was the only compilation.
Root retains run402 and the55-link baseline and owns review, coherent build,
artifact binding, checkpoint publication and any new native invocation. This
increment supplies diagnostics; it selects no semantic performance correction
and proves no Bootstrap/release acceptance gate.
