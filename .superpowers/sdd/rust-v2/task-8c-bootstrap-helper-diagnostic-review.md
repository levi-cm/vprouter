# Bootstrap held-helper diagnostics: independent spec and quality review

2026-10-29. Fresh review of the diagnostic-only candidate. Read the supplied
helper-diagnostic brief first, then run402 diagnosis, implementation report,
frozen diff, current source, parent task8/8c briefs and binding
`docs/rust-v2/IMPLEMENTATION.md`. Only this review document was written. No source,
Git, VM, build or test mutation, native invocation, privileged operation or
subagent action was performed. Git was used read-only for source comparisons.

**SPEC verdict: PASS for this diagnostic-only increment.**
**QUALITY verdict: PASS; no blocking or nonblocking correctness finding.**
This approves the reviewed source increment for Root's subsequent coherent build
and exact artifact/native gates. It grants no Bootstrap, full8c, client, runtime,
release or performance acceptance, and selects no semantic/deadline correction.

## Exact candidate and scope

- Workdir `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`.
- Observed HEAD `300f576b117e4a5532a796e356d2a223abe4324d`.
- Semantic base `50cf9c4c7c2caceb3e0f6d406e5f45a66d7db8ee`.
- Sole changed Rust path:
  `crates/vprouter-launch/src/attachment/operational/bootstrap.rs`.
- Current source SHA256:
  `88320812125ab5f735a70ee6e1d0a935699dcc27f7ea4d9d7f3bca72f539e142`.
- Base source SHA256:
  `a69afe95279995aff491c1e153473af9398cabbc8a6342407266a522dd836759`.
- Frozen review diff SHA256:
  `ecc9006d379c66c82c06141882788850c70780bf24f870902ccfa078fe87383d`.
  It is byte-identical to the current `git diff --unified=10` against that base.
- Reviewed report SHA256:
  `fe3b6223a62db74b73d3a831e7a260464a3e33d76522c2fd021436c2d5617305`.

The source hash and diff hash match
`target/task8c-helper-diagnostic-20261029T153811Z/root-frozen-source-hashes.json`.
The prefix before `#[cfg(test)] const LAB_LABELS` is byte-identical to the
semantic base, SHA256
`6264d3bc2d5edb1fe63ac587006fe7109dad7959fd9317d8e9e0aa359d807d05`.
Every edit lies inside the existing cfg(test) `lab_run` (`bootstrap.rs:635-1265`)
or the new wholly cfg(test) `lab_diagnostics` module (`:1267-1408`). No production
path is changed or enabled by this patch.

Independently rehashed all178 `crates/**/*.rs` files against the retained
`/tmp/task8c-helper-diagnostic-before.json` snapshot. Snapshot SHA256 matches the
report (`3927e6b52f53a28c2c89f7ab12651f4ecede6487517be5ec2eb83cec0cfb2002`).
Exactly the owned path changed;177 are unchanged, with no added/deleted Rust
paths. Read-only Git comparison against the semantic base independently returns
that same sole changed Rust path. This preserves the other ancestry, pending-
progress and approved-receipt source paths covered by that base/snapshot.

## Spec and behavior checks

The local `measured!` macro (`:663-686`) evaluates each original operation once,
records its elapsed duration, observes an error by shared reference, copies only
the enum Error for logging and returns the original Result unchanged. It adds no
verification, retry, sleep, deadline refresh or authority. The original query
Source call and clone remain one operation (`:708-712`). The two writer Option
refusals remain OwnershipMismatch; the small closures preserve those original
errors before the outer `?` (`:725-733`, `:793-801`).

Query negative checks retain their original short-circuit order and original
Interrupted/OwnershipMismatch outcomes (`:734-752`). The original writer
assignment, negative increments, release threshold and two held polls remain in
place (`:753-767`). Policy hold, queued negatives, checkpoint, first-held
negatives, identity and release retain their order, guards, counters and two-held-
poll threshold (`:770-815`). The new `query_queued` boolean is diagnostic-only and
changes only after the original hold succeeds. It conveys no ACK authority.

The main native poll is bracketed once (`:838-846`) and still enters the original
outcome handler on error. Byte comparison confirms that the existing native-poll
error handler and every following byte of the old lab function are unchanged.
Thus its error latch, collect/refusal polls, failure/drop retention, fault2 work,
evidence collection and cleanup restrictions were neither replaced nor weakened.
Production `PendingBootstrap::poll` and Drop logic (`:566-605`) are untouched.

The closed Helper enum/table has exactly13 variants and fixed labels
(`:1273-1321`), covering the12 query/policy outer boundaries and native poll.
Failure logging (`:1349-1405`) reads retained Option presence, scalar counters,
fixed Step and enum-only Error, the original query's infallible time getters,
and one current boot-time observation. The query getters (`attachment.rs:995-1000`)
read the stored requested_at and compute its original +2 deadline; they do not
verify or refresh it. No Context/Source/Request/writer verification or fallible
identity getter is called to construct the new output. No descriptors, identity,
path, profile, credential, arbitrary string or raw request is emitted.

Measurements use a fixed13-entry array (`:1333-1347`) with saturating u64 calls
and saturating Duration totals. Each actual wrapper/native-poll operation is
between Instant start and elapsed sampling; pending success adds no output.
The first-error flag bounds the new output to one scalar snapshot and one
fixed13-row table (`:1356-1359`, `:1397-1404`). Every row labels its quantity as
`wrapper_elapsed_including_nested_validation`. This is elapsed wrapper time
including nested validation, IO and scheduling, not predicate CPU, a new
enforcement clock or deadline authority. It is not a decomposition of all lab
wall time; Instant does not include suspend time. Logging and time between
wrappers, sleeps, later collection and the existing post-error refusal polls are
outside these totals, as the report describes.

The new writes use best-effort `writeln!` with discarded IO Results
(`:1377-1404`). A write failure therefore cannot turn the original Error into a
logging IO error. Existing native-poll diagnostics remain separate and unchanged;
`helper=native_poll` identifies that boundary without routing helper failures
through its handler. No new production enforcement, clock, typed-proof, role,
filter, placement, resource, UP/Ready, recovery or cleanup semantics were found.

## Verification evidence and limits

Retained logs were read and independently hashed; all three hashes match the
implementation report:

- `/tmp/task8c-helper-diagnostic-lib-final.log`:
  `b8b20c133ed999314b5bcd2887aae86602f0fa1a3f9eb1d59f3924c1a9d8cbaf`;
  final summary148 passed,0 failed,0 ignored.
- `/tmp/task8c-helper-diagnostic-clippy-final.log`:
  `6639404a1bec15caf9b8a1ba6e5334e183139a6fbaaf54fc57813cfd319becc1`;
  final Checking/Finished output and no diagnostic.
- Initial failed `/tmp/task8c-helper-diagnostic-clippy.log`:
  `563d3e5ed9c0b48b51564cc8b082dd2886aa1dd3d18be90f209c13d44d2bf245`;
  preserved items_after_test_module failure, consistent with the report's
  subsequent module relocation rather than a lint suppression.

The report records final strict Clippy and rustfmt PASS. No suite or build was
rerun in this review; Root owns focused independent checks/coherent builds.
The source has no trailing whitespace. The retained test/Clippy logs alone do
not independently establish the exact invocation argv or cryptographically bind
source-at-test-time, and this review does not claim that proof. The existing148
library tests are not a native failure-output witness. No logging-failure
injection or actual wrapper-cost record was executed by this reviewer.

Severity: no source/spec issue found that requires correction in this scope.
The outstanding runtime evidence is an explicit acceptance limit, not a passed
case. Run402 remains FAIL with zero completed cases and no POLL_FAILURE marker
as retained by the reviewed diagnosis. Its exact helper, evaluated clock/error
observation, parent ACK and per-operation costs remain unproved. The new scalar
observation is after a wrapper failure and cannot identify an individual nested
deadline predicate. Native403 remains **NOT_RUN**; full8c remains **ACTIVE**.
The55-link preservation baseline and run402 resources remain Root-owned gates;
this review neither changes nor reauthors them. No native acceptance promotion.
