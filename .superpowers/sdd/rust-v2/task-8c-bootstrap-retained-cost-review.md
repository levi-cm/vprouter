# Bootstrap retained-cost implementation: independent review

2026-10-29. **Spec verdict: PASS. Quality verdict: PASS.** No blocking or
nonblocking findings in the frozen five-file implementation. This is a source
diagnostic verdict, not native Bootstrap, performance or release acceptance.
Original398-405 failures remain FAIL; the next retained-cost witness is NOT_RUN
by this review.

## Exact review binding

Read the retained-cost brief first, then the frozen405 diagnosis, binding
IMPLEMENTATION.md, readiness review, implementation report and complete diff.
The readiness review was context, not a substitute for implementation review.
Root supplied application base bf3247b and current HEAD fd8622d; no Git command
was used by this reviewer.

| Frozen input | Independently verified SHA256 |
| --- | --- |
| `task-8c-bootstrap-retained-cost-brief.md` | `5624e0e29001744dbb849f7fa08ca7c6ab8db74ad5d605488024d45936932e07` |
| `task-8c-bootstrap-retained-cost-report.md` | `b806467156f42010c53cb39c258d5e589bdb91e17854f3ba8417206f22795893` |
| `target/task8c-retained-cost-local/source.diff` | `941a4638993b585c87b464475c4e06dfccbcefbc922b2f4693b73d58489e351e` |
| `docs/rust-v2/IMPLEMENTATION.md` | `353f0e82d9dcf7b3e1216c27ac4c505bdc8fa6ee06ee3e6b833f1d3e11594125` |

All179 current Rust hashes match the retained final snapshot exactly. Comparing
before/final snapshots gives exactly the five authorized changed paths,174
unchanged paths, and no added/deleted Rust path. Each saved before file matches
its before-snapshot hash. Reconstructing the complete unified diff from these
five saved files and current bytes reproduced the retained diff exactly.

Final owned hashes, paths relative to `crates/vprouter-launch/src`:

| Path | SHA256 |
| --- | --- |
| `owned/preparation/quarantine.rs` | `f7ec6cddcf345ceacd26b448844d49598b8fe3cafd60f9cf0c785f3de20e0336` |
| `owned/preparation.rs` | `4ad1d063d86907e14ce8a2067f7c2baf231b0bfa6850d332c1b18bf1f1321369` |
| `kernel/producer_creation.rs` | `9f37b22c66f3e1bc9f66b93951a90caa95a1f100f1e56423ba34940ec1724e11` |
| `attachment/quarantine/producer.rs` | `34d66c2f7e91b1c7b0f35766a2c5360b69c048bb07d14f4508a10eda3c1ea018` |
| `owned/preparation/lab_cost.rs` | `a7e5d4f832559d66d7cc6fa4193b2c82d051b4629850c0021ef47e5999601f68` |

## Specification and expression/drop boundaries

The six timed regions and two count-only entries match the brief:

- Transport and DATA timers surround only their existing Binding calls. Their
  scopes close immediately after success; `?` drops the timer while propagating
  the original error. Full-history timing similarly encloses the original
  `p.validate(&j.record, e)?` call.
- Owner-record timing stays inside the original last `||` operand, behind all
  earlier member/allocation/cardinality checks. The original owner.record
  expression and `?` remain in place. Its block returns the original result and
  drops the timer before equality comparison; no eager owner computation or
  moved live observation is introduced.
- Allocation serialization/digest remains the original expression and error
  mapping inside History.validate. Its block remains behind member mismatch and
  on the same side of the original comparison. Serialization failure still
  yields AllocationMismatch; later conditions remain short-circuited normally.
  The timer ends at this expression block, not the rest of History validation.
- `created_group_native` is declared only after successful existing
  Request.verify_retained. It covers the unchanged remainder, including early
  errors and cleanup of locals declared later. No request/binding work is moved
  into this region and no native metadata/cgroup/ancestry operation is replaced.
- Source.identity and Native.source count at entry, before their original
  checks. Both counters include error entries and call no Instant, process-ID
  getter or new native operation. Their original duplicated live verifications
  remain present.

Independently removed exactly six new cfg(test) timer statements, two cfg(test)
counter statements and only the five approved minimal expression/call scopes
in memory. The four application files then equal their before sources line for
line apart from indentation. The retained check_scope.py additionally records
byte-identical reconstruction after rustfmt normalization; it was inspected,
not executed. The unchanged cfg(test) module declaration excludes all added
lab_cost imports/items/storage from normal builds. Thus the remaining bare
scopes do not introduce a normal-build call, field, authority or operation.

The complete diff preserves original expressions, evaluation/short-circuit
order, Result/error mappings and authoritative clock observations. All original
2s windows, custody/ownership/source/pending/writer/registry/frame/fence proofs,
held polls, negatives, release/ACK points and failure handling remain. No cache,
successful-verdict reuse, comparator/digest optimizer, retry repair or semantic
fix was added. The174 unchanged Rust paths include the operational Bootstrap
lab and its original13 wrapper rows, hold/release/error logic and lab tail.

## Collector, publication and child safety

The added closed eight-key enum has exactly the required order. A separate
24-row `[Cell<Total>; RETAINED_ROWS]` stores the new three-family totals.
Recording reads and updates only the selected new row; it does not copy the
whole added table per event. Independently checked that the old State layout,
original Timer entry/drop implementations, original30-row emission loop and
four original helper tests are byte-identical. Old timers do not copy a larger
table. New paths still read the old State to obtain/check metadata; its old
30-row copy and other observer costs are correctly acknowledged in the report.

New timers capture the existing family/creator/epoch token and retain no live
borrow, lock, descriptor, heap allocation or verification authority across the
original call. Their thread-affine marker prevents cross-thread movement.
Selected-row calls/nanoseconds saturate. Count-only accounting suppresses
duration even if its internal record helper receives a nonzero duration;
RetainedTimer refuses count-only keys, and count_entry refuses timed keys.
Inactive/stopped/stale tokens cannot update new rows. arm resets all24 rows
while retaining the existing epoch behavior; epoch exhaustion disables both
collectors. Session cleanup and old-session isolation use the unchanged active/
epoch checks.

The unrestricted stop/export function stores inactive State before copying
added rows and exposes them only through the successful creator-checked
snapshot. Foreign stop disables collection and returns no snapshot. New
timer/counter paths perform no getpid. The existing publisher filter permits
clock_gettime and omits getpid; no role syscall/filter/fork hook changed.
Both TLS tables are private fork copies, with no shared mapping, merge, IPC
export or new child logger. The existing journal child exits through die/_exit
without unwinding the parent session stack. These are source checks, not a new
fork/filter execution witness.

Publication uses the existing failure snapshot. The13 wrapper rows remain
unchanged; the original30 nested rows are emitted first, followed by exactly24
retained rows in query/policy/other and required-key order. Both required
measurement/grouping fields are literal fixed labels. New output consists only
of those labels and bounded integers; count-only elapsed values remain zero.
There is no per-entry/poll output or caller path/identity/request field. IO
errors remain ignored and cannot replace the original failure.

Independently recomputed the conservative maximum added output as5567 bytes
across24 rows, permitting full u64/u128 widths even for the count-only rows.
This finite byte count does not bound blocking stderr latency. Rows are
inclusive and overlap: transport can include DATA, History includes allocation
digest, and new regions overlap the old broad timers. Counts include errors
and partial work; the family is loop-entry Step rather than exact inner phase.
No sums/subtractions into exclusive CPU or successful ACK counts are justified.

## Retained verification evidence

All27 entries in artifact-hashes.json were independently hash-checked against
the retained files. Important bindings under target/task8c-retained-cost-local:

| Evidence | SHA256 |
| --- | --- |
| `rust-before.json` | `e98e5c4e2df75432ebcba66ce99b7a64b6809f46d230fe8f38d49305bc605099` |
| `rust-after.json` | `0fc869e607e2a987abeaff7724dee2824d0e25d448500f88967b2d5f162ff38d` |
| `source-preserved.json` and identical scope-final.log | `f2c18c4c18f52727f8d02e2047876970786587ce184541a852873c9a111ab91b` |
| `check_scope.py` | `817f64ce756be643b52c3d4c80fc58f001dd44a6d1e0d6c66622c46baba79ada` |
| `launch-lib-final.log` | `7797f5e0a47d9b787d4206d2f7f1dd9212f88c8002d7909f8b7ab6dd5044e21d` |
| `clippy.log` | `64733d2ef64c5de6d857c4b7bbead5ace13f0e721195eb296c60a77be20c8d31` |
| `normal-lib-final.log` | `f430b0f8733faf97df0da221983eed592956d2bff50d546a152101b69976f231` |
| `fmt-final.log` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

The retained final library log contains159 individual ok records and159/0/0
in its summary; the helper-green log contains all seven helper passes. Final
strict library/tests Clippy and the normal non-test library check have completed
dev-profile records without errors. The formatting log is empty, consistent
with the reported successful check; it alone does not encode an exit status.

The three new tests cover actual state/Drop behavior: inactive/error/nested/
count-only/family/stopped paths, saturation, copied-child isolation, reset,
stale epochs/sessions and foreign export refusal. They do not mirror output
text or construct native fixture resources. The initial helper-red log has60
compile errors for the not-yet-defined API, not a behavioral RED claim. Retained
deliberate mutation logs supply stronger assertion evidence: removing count-only
duration suppression produced99 versus0, and removing table reset produced1
versus0, each failing its intended test. Final source hashes match the restored
implementation. The initial Clippy failure was also inspected: absolute
crate::owned paths failed when existing integration fixtures nested source under
admission; final relative paths preserve those fixtures without lint suppression.

No tests, formatter, Clippy, build, Git command, helper script, native/VM/SSH/
Docker/privileged/profile action or subagent was run by this reviewer. Fresh
verification was read-only source/artifact inspection plus in-memory hash/diff/
scope/output-bound checks. This review Markdown is the only file written.

Root's concurrent publication/parser/docs work and future coherent build
artifacts are outside this five-file source review. Actual child/filter runtime,
artifact binding, the next owned local native experiment, real clients, ARM,
migration, performance and release acceptance remain independently gated.
Clock/accounting/TLS/COW/cache/scheduling overhead can perturb parent elapsed
time. Neither these source verdicts nor retained local component logs establish
native cost share, a controlled405 comparison, speedup, original2s fit, accepted
receipt or completed Bootstrap. Root retains ownership of preservation and
native/build gates; existing credentials, identities, production and bounded
provider retry repair receive no new authority or change from this review.
