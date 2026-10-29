# Bootstrap nested-cost diagnostic: independent spec and quality review

2026-10-29. **Spec verdict: PASS. Quality verdict: PASS.** No blocking or
nonblocking source findings in the frozen six-path diagnostic. These verdicts
cover diagnostic preparation only. Run403 remains FAIL; a native nested-cost
witness, full Bootstrap/task8c and release acceptance are not established.

## Reviewed binding and scope

Read the bounded `task-8c-bootstrap-nested-cost-brief.md` first, then the403
diagnosis, `docs/rust-v2/IMPLEMENTATION.md`, the latest ledger interpretations,
the complete source diff and report. The ledger explicitly permits COW-private
child accumulation without parent export/merge, unrestricted-boundary creator
checks, and one infallible cached-Step family hook at the existing lab-loop
entry. No additional fork hook or filter permission is authorized.

Worktree `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`, inspected HEAD
`e213b39c88452a6f32e31aa84a2547271c92d19c`.

- Frozen report `task-8c-bootstrap-nested-cost-report.md`, SHA256
  `bcd7e6f0aa4afbb4111dc41ea5c7bb364502bd5bed033d687d3528d3a471b3a3`.
- Complete `target/task8c-nested-cost-local/source.diff`, SHA256
  `84efdde3f26dd1c184d961dce9afd793fa8d2f4e292be6aa02018a2d5c17c34f`.
- Independent read-only comparison of all178 retained pre-edit Rust hashes
  against Git objects proved exact equality to both semantic base `46239ec`
  and inspected HEAD. Current179 Rust files exactly match the frozen final
  hash snapshot. Exactly five existing owned files changed and the authorized
  test-only support file was added; the other173 existing Rust files match.
- Reconstructed the entire unified diff from saved pre-edit bytes and current
  source with `difflib.unified_diff`; it equals the retained artifact byte for
  byte. This includes the new331-line support file, which is untracked in the
  inspected worktree and therefore cannot be reviewed from `git diff` alone.

Final owned SHA256 values, independently matched to the report:

| Path under `crates/vprouter-launch/src` | SHA256 |
| --- | --- |
| `attachment/operational/bootstrap.rs` | `da65fe12514a8f668f10d83cb4a668d9d59f0dd6faa26edf6487d9edab6f9d22` |
| `owned.rs` | `1e2b547bc2df30a6a128184eae9b6569452d12ec80bc59f9ff71e90a18f0636e` |
| `owned/preparation.rs` | `5379370d500f09a826fb3717b0949a355801823bbf40f63d1d8b3e6664c1b97a` |
| `owned/preparation/bootstrap.rs` | `0602f7630e895bee5f6834371ee4323025837363e439a4d7e97979918eaa0a53` |
| `owned/preparation/quarantine.rs` | `965e04b90a4048418a27a24439b5d4b754121acb17219e4c00644d8d9142a52f` |
| `owned/preparation/lab_cost.rs` | `b1c0860166ed46d127d16095e788593558fb8928dc0264a435737f96a8fb2796` |

## Spec review

All required nested boundaries are instrumented: allocation/anchor memory,
Binding service custody, Binding retained validation, owned progress, typed
Bootstrap progress, original proof, bounded record JSON encoding, record SHA256
and native journal advancement. The optional expected-record encoding category
wraps the original encoding statement. Shared owned/custody/encoding paths
remain reachable from both query and policy work. The allocation timer includes
the original `Record::bind_anchor` and retained-history validation delegated by
`Native::require_creator`; no separate creator hook was added.

The three closed families and ten closed keys produce a fixed30-row snapshot.
Initial collection is armed as `other` before the PendingBootstrap constructor.
The sole family hook reads existing `n.step` at loop entry without a getter,
verification call or clock sample. Each timer captures that entry family.
Output labels explicitly say `grouping=lab_loop_entry_step_family` and
`measurement=inclusive_nested_elapsed`; a poll may transition within that
family. These are overlapping inclusive elapsed observations, not exact inner
phase or CPU costs. Expected encoding also includes nested timer overhead;
row subtraction is not an exclusive-cost measurement.

Independently reconstructed the four production files byte for byte after
removing only the eleven added, individually `#[cfg(test)]` timer/drop
statements and the new `#[cfg(test)]` module declaration. Counts are3/2/1/5
for owned.rs/preparation.rs/preparation/bootstrap.rs/quarantine.rs. The
operational Bootstrap production prefix before the existing test-only
`LAB_LABELS` is identical. Its four insertion hunks are wholly within existing
`#[cfg(test)]` lab_run/lab_diagnostics items. The new support imports, types and
functions are excluded through the cfg-gated module declaration. There is no
new normal-build statement, import, authority, signature or field.

The complete diff is additive instrumentation: every original expression,
short-circuit operand, call and Result/error mapping remains in its original
order. Original clock observations and2s windows, live source/slot/ancestry,
canonical/proposed/pending relations, phase/start/member, registry/IO/frame/
fence and custody checks remain. Query/policy held polls, negatives, release
points, writer/child operations, failure latch/collection and the lab tail are
unchanged. No cache, optimization, timeout or retry-repair change is present.

The original first-error latch remains before diagnostic work. Collection is
stopped and copied before constructing/emitting diagnostics, and the unchanged
13 wrapper rows precede at most one fixed30-row nested table. No per-poll or
success-path output is added. The output contains only closed labels and
numeric counts/times. Existing errors survive ignored diagnostic IO failures.

## Quality and child-path review

`Cell<State>` contains only bounded Copy scalars and a fixed array. Entry/drop
copy state briefly and hold no RefCell borrow, lock, descriptor, allocation or
verification authority across original work. Active timers use Instant; inactive
timers do not sample it. Drop covers ordinary early Result exits, including
the expected-encoding `?`. Calls and nanoseconds saturate. Thread-affine guards
prevent timer/session movement across threads. Epoch checks isolate stale
timers/sessions, and exhaustion disables collection without token reuse.
Session Drop disables collection on ordinary lab returns not routed through
the instrumented failure helper.

Inspected the actual native journal path, not only the helper copy test:

- `kernel.rs:1785` forks with separate VM state; the journal child installs its
  publisher-derived filter before `job.run` at1856.
- `JournalIo::run` ends with global `record_digest` in owned.rs. Thus the new
  SHA timer can execute after filtering. `publisher_filter` allows
  `clock_gettime` and omits `getpid`; its journal extension adds only the
  existing read permission. Timer entry/drop, state accounting and family
  capture call no process-ID function. The new getpid observations occur only
  at unrestricted arm/stop/session-cleanup boundaries.
- The fork child can change its COW-private copied totals. There is no shared
  mapping, merge, diagnostic IPC or child snapshot output. Export requires the
  actual creator ID at the unrestricted snapshot boundary. The child completes
  its original fixed result/diagnostic handling and calls `die`, implemented
  with `libc::_exit`; it does not return through the parent lab stack or drop
  the inherited Session under the publisher filter.

The four helper tests exercise inactive/nested/early-error/stopped behavior,
copied-state foreign export refusal and parent isolation, captured family,
saturation, epoch exhaustion, stale token/session isolation and session cleanup.
They inspect actual state transitions and guard Drop behavior rather than
mirroring log text. Their foreign-copy model is not an executed fork/filter
experiment, as the implementation report correctly states.

## Retained verification and limits

Read and SHA256-checked all reported retained artifacts. The final library log
contains152 individual `ok` records and `152 passed; 0 failed; 0 ignored`.
Final strict launch lib/tests Clippy has a completed dev-profile record. The
initial Clippy failure is retained and concerns only the replaced immediately
invoked test closure; there is no lint suppression. The final formatting log
is empty, consistent with the reported successful check; that empty file alone
does not encode command completion or exit status.

Matched these exact report hashes under `target/task8c-nested-cost-local`:

- `lib-final.log`: `4dce1c3963154b0a7b893501b59aee131afd7f27d8253ef2d6df4098ec63bd41`
- `clippy-final.log`: `b5d9950c1eba6f7b08b960053f5601ed94d096bff7c1b368e50bf2fa43d4c95a`
- `clippy-initial.log`: `8ff4ced0b91a9e2fbae39410983961d15778b39b2b0291f9bdddcf5cd0beb834`
- `fmt-final.log`: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- `source-verification-final.log`: `8edc23693f1c5112dd7083cecdcdd637f2229c2f60dbcea6cc76ba9c84fa153a`
- `verify-source.py`: `17c62d17f35cf31ed7c956efa3dfb27cd8e1c95e97d4e1fc514de7da56371257`
- `before-hashes.json`: `b06937ca3c86cc6941e0459a3bbace2096d44941306018ede13408dc68f5d657`
- `after-hashes.json`: `760de42c6cdff8128c2023a7b48d4d82bc3084e9baaf1602096ecf19e41bb462`
- `cfg-exclusion.json`: `889bcaa92d41f51d4359996b8aaf0b9db3c14c6d723dc1ebac72b205c630a10c`

Root separately reported fresh152 launch tests, workspace formatting, strict
launch Clippy and exclusion success. Inspected its retained logs at
`target/task8c-nested-cost-root-20261029`: launch-tests.log SHA256
`2bd1ab21e9a0f4e5d43630f786bf3d346b9dd626e10f6f6b0293857b1fd18372`
has152/0/0; clippy.log SHA256
`a5f4c585ee974ca44916ac30a98bbc189e067a7e0a6bc6d2e8d6bc525be724af`
has completed dev-profile output; fmt.log is empty; source-check.log matches
the implementer's source-verification log exactly. These are retained Root
checks, not tests run by this reviewer. Root's concurrent coherent builds and
any resulting manifests/artifacts are outside this source review.

No tests, formatter, Clippy, build, native action, VM/SSH/Docker or privileged
command was run by this reviewer. The artifact-producing verify-source.py was
read, not executed; equivalent scope/hash/reconstruction checks were performed
in memory without rewriting artifacts. No source, Git state, credentials,
identities, production resources or unrelated work was changed. This review
Markdown is the only file written. No subagents were used.

Actual fork/filter behavior, both-architecture artifact binding and runtime,
the next native cost witness, complete Bootstrap/task8c, real clients,
migration, benchmarks and release acceptance remain independently gated and
are NOT_RUN by this review. Timer state copies, parent timers and private child
timers can perturb scheduling and elapsed time; no dominant mechanism, exact
CPU attribution, speedup or sufficient remaining2s budget follows from source
review or local component logs. Root owns the next local VM experiment and403
resource preservation. The bounded provider retry repair and all broader
implementation-contract gates remain unchanged.
