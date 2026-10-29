# Bootstrap retained-validation diagnostics: frozen implementation

2026-10-29. Root explicitly dispatched the independently reviewed five-file
cfg(test) brief (SHA256
`5624e0e29001744dbb849f7fa08ca7c6ab8db74ad5d605488024d45936932e07`),
with readiness review
`32cf5cff92c78db4cb106b9af77b6f834005bc2548549ce83ef2e907b94d8389`.
Application source base is comparator milestone bf3247b. Root advanced reviewed
publication/parser/docs milestones concurrently; this implementation performed
no Git mutation or tooling/parser change. Only the five owned Rust files changed.

Implementation is frozen for fresh independent spec/quality review. No semantic
optimizer, verdict cache, deadline/call/check removal or native success is claimed.

## Exact measured boundaries

| Fixed key, in emission order | Insertion boundary |
| --- | --- |
| retained_transport | Existing Binding transport.verify_retained call, including its error |
| retained_data | Existing Binding data.verify_retained call, including its error |
| retained_owner_record | Only the owner.record expression at its original short-circuit position; timer drops before equality comparison |
| retained_history | Existing Binding p.validate call, including its error |
| history_allocation_digest | Original Serialize+digest expression, still behind member mismatch and retaining AllocationMismatch mapping |
| created_group_native | After existing Request.verify_retained succeeds; covers unchanged remainder of group verification, including early errors |
| source_identity_entries | Count before Source.identity's original entry check; no time read |
| native_source_entries | Count before Native.source's original entry check; no time read |

The six elapsed regions use test-only RAII. Both counter entry sites use
count_entry without Instant/getpid/native calls. Minimal scopes preserve the
original expressions, `?`, evaluation/short-circuit order and exact check/call
sequence. The owner result is not precomputed; its timer drops before comparing
that result. Group request/binding work stays outside the group-native region.
All original authoritative clocks, pending/writer/fence/custody/native proofs,
holds/negatives/releases/ACKs and failure handling remain intact.

## Separate fixed collector and publication

The added eight keys times three existing query/policy/other families give
exactly24 rows. Added storage is a separate fixed array of per-row Cell<Total>;
recording copies/updates only the selected new row. Existing State layout and
both original Timer implementations are byte-identical: no old timer copies a
larger table. New timers still read the existing State to obtain/check shared
metadata; that existing metadata read can copy its old30-row state. No second
active collector, lock, heap allocation, unbounded collection or live borrow
across instrumented work is introduced.

New rows share the existing active/creator/epoch/family metadata. arm resets
all24 added rows; tokens capture entry family; stopped/stale/foreign metadata
rejects updates. Counts and durations saturate at u64/u128. Count-only rows keep
elapsed_ns=0. Session drop and epoch exhaustion retain the old behavior. Timer/
counter paths perform no getpid, filter change or new authority check. The
unrestricted stop/export boundary retains its existing creator observation and
disables collection before copying added rows or producing output.

Forked child bookkeeping remains COW-private. There is no merge/export path,
shared-memory collector or new child logging. Local tests model copied table/
state independence and foreign export refusal; actual filtered-child/native
runtime behavior has not been rerun by this implementer.

The existing13 wrappers are untouched in their unowned source. The original30
nested-row emitter loop is byte-identical. Added24
LAB_SECRET_BOOTSTRAP_RETAINED_TOTAL rows follow all30 old rows, using only fixed
family/category labels and bounded numeric values, with
measurement=inclusive_retained_elapsed and grouping=lab_loop_entry_step_family.
No per-call/poll output, identifier, path or request content is emitted. Output
errors remain ignored and cannot replace the original error; collection is
already stopped. Conservative maximum added output is5567 bytes even allowing
maximum-width elapsed values for count-only rows (which actually emit zero).
This byte bound does not bound blocking stderr latency.

## Meaningful local verification and retained failures

Three new helper tests cover nested/early-error counts, count-only zero duration,
entry-family capture, stop/drop behavior, selected-row saturation, copied child
independence/foreign refusal, reset/new epochs and old-session/old-timer isolation.
All four preexisting collector tests remain byte-identical. No native fixture
resource is constructed by the new tests and no log-text mirror test was added.

Tests were written first. The initial helper-red.log records exit101 because the
new API/table fields were not yet implemented (60 compile errors); it is not a
claimed behavioral assertion failure. After helper implementation, helper-green
records seven pass. Two deliberately incorrect diagnostic mutations then show
actual assertion sensitivity, and their full failures remain retained:

- Removing count-only duration suppression failed with99 versus0, exit101.
- Removing added-table reset failed with1 versus0, exit101.

Both were restored from exact saved source bytes before final verification.
The initial strict Clippy attempt exposed crate::owned paths that compile in
the library root but fail in integration fixtures nesting source under admission.
That failure is retained as clippy-first-failed.log. Only the new cfg(test) paths
were corrected to relative module paths. Strict Clippy then passed across the
requested library/tests scope. No original application behavior was changed to
make tests pass.

All local artifacts/logs below live in ignored
`target/task8c-retained-cost-local`.

| Command | Final result | Log |
| --- | --- | --- |
| cargo test -p vprouter-launch --lib | exit0; 159 passed, 0 failed | launch-lib-final.log |
| cargo clippy -p vprouter-launch --lib --tests -- -D warnings | exit0; no warning | clippy.log |
| cargo check -p vprouter-launch --lib | exit0; normal non-test library | normal-lib-final.log |
| rustfmt --edition 2024 --config skip_children=true --check [the five owned paths below] | exit0; empty output | fmt-final.log |
| python3 target/task8c-retained-cost-local/check_scope.py | exit0 | scope-final.log |

Strict Clippy passed on the exact restored final source; subsequent deliberate
mutations were restored byte-for-byte and final library/fmt/source/normal checks
confirmed that source. No coherent/static/cross-architecture/native build or
native/VM/SSH/Docker/privileged/profile operation was attempted.

## Source freeze and preservation

All paths in this table are under `crates/vprouter-launch/src`.

| Owned path | Before SHA256 | Final SHA256 |
| --- | --- | --- |
| `owned/preparation/quarantine.rs` | `965e04b90a4048418a27a24439b5d4b754121acb17219e4c00644d8d9142a52f` | `f7ec6cddcf345ceacd26b448844d49598b8fe3cafd60f9cf0c785f3de20e0336` |
| `owned/preparation.rs` | `5379370d500f09a826fb3717b0949a355801823bbf40f63d1d8b3e6664c1b97a` | `4ad1d063d86907e14ce8a2067f7c2baf231b0bfa6850d332c1b18bf1f1321369` |
| `kernel/producer_creation.rs` | `b920940062802760cffafd5720c687880211183be92dfe2e2be003cac55031ea` | `9f37b22c66f3e1bc9f66b93951a90caa95a1f100f1e56423ba34940ec1724e11` |
| `attachment/quarantine/producer.rs` | `54623d8d526c935da5d691c1a1a7e06f05cd0302723b49ed343dd775af7970d2` | `34d66c2f7e91b1c7b0f35766a2c5360b69c048bb07d14f4508a10eda3c1ea018` |
| `owned/preparation/lab_cost.rs` | `b1c0860166ed46d127d16095e788593558fb8928dc0264a435737f96a8fb2796` | `a7e5d4f832559d66d7cc6fa4193b2c82d051b4629850c0021ef47e5999601f68` |

Exact diff `source.diff` SHA256
`941a4638993b585c87b464475c4e06dfccbcefbc922b2f4693b73d58489e351e`.

All179 Rust inputs were snapshotted before editing. Exactly these five changed:
all174 unowned paths are unchanged; no Rust path was added/deleted. The replayable
check_scope.py removes exactly six new cfg(test) timer statements, two new
cfg(test) counter statements and five minimal expression/call scopes. Formatting
normalization then reconstructs each of the four application files byte-for-byte
against its before snapshot. The fifth file remains entirely excluded by the
unchanged existing cfg(test) module declaration. A normal non-test library check
also passes. Existing State layout, Timer implementations,30-row emitter loop
and four helper tests are independently checked byte-identical by that script.

| Evidence | SHA256 |
| --- | --- |
| source-preserved.json | `f2c18c4c18f52727f8d02e2047876970786587ce184541a852873c9a111ab91b` |
| rust-before.json | `e98e5c4e2df75432ebcba66ce99b7a64b6809f46d230fe8f38d49305bc605099` |
| rust-after.json | `0fc869e607e2a987abeaff7724dee2824d0e25d448500f88967b2d5f162ff38d` |
| check_scope.py | `817f64ce756be643b52c3d4c80fc58f001dd44a6d1e0d6c66622c46baba79ada` |
| launch-lib-final.log | `7797f5e0a47d9b787d4206d2f7f1dd9212f88c8002d7909f8b7ab6dd5044e21d` |
| clippy.log | `64733d2ef64c5de6d857c4b7bbead5ace13f0e721195eb296c60a77be20c8d31` |
| normal-lib-final.log | `f430b0f8733faf97df0da221983eed592956d2bff50d546a152101b69976f231` |
| fmt-final.log | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

artifact-hashes.json retains every local artifact/log hash, including initial
compile failures and deliberate mutation failures. Source was rechecked after
all final checks. No unrelated dirty work, controller/parser, manifest, dependency,
fixture identity/resource, credential or production deployment was modified.

## Self-review and limits

Self-review found no scope/check/order/error/clock change, owner precomputation,
wrong timer lifetime, time observation on entry counters, enlarged old State,
per-entry getpid, merge/export, new logging failure propagation or optimizer.
All added application statements are cfg(test); the helper module already was.

Each timer adds clock reads, TLS metadata copies and selected-row bookkeeping;
arm resets24 rows and stop copies24 rows. These operations and child COW/cache/
scheduling effects can alter parent elapsed timings. Counts include early errors
and partial work. Family remains loop-entry Step, not exact inner phase.
Transport can include DATA, and full History includes allocation digest. Added
rows overlap existing rows; they must not be summed/subtracted into exclusive
wall/CPU cost or multiplied into successful validation/ACK counts. No test or
source proof establishes native cost share, speedup, original two-second fit,
accepted receipt, completed Bootstrap scope or release acceptance.

Root owns fresh independent review, coherent artifacts/source binding, authored
preservation, checkpoint/push and any owned local native experiment. Original
398-405 failures remain FAIL; full8c/ARM/client/migration/performance/release gates
remain open/NOT_RUN where unaccepted. No further source work is authorized beyond
this frozen five-file diagnostic scope.
