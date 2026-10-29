# Operational assembly continuation

## Authority and starting evidence

Sole source writer; no nested agents. Root authorized implementation after native143
ARM normal17 PASS. Starting frozen source d57e2a94f332a67a39f0bb963778ebac461c37fe;
all component limitations and failed-run history from process-inspection-report.md
remain. Real HEAD c6a138c00b70163ba3cbfdf350e5cf8e2f3a3c6a and index SHA256
59f3aec05fa66f161482e5705f1a3c50c68c528980a51b5da4a869a510a24692 verified unchanged.
No privileged operations, credentials, production changes or mutable context
refresh during orientation. Root owns all native VM actions and counters.

## Current implementation work

Generic Child Drop's bounded reap can discard live native handles and inventory.
Generic spawn also has postfork pidfd/registration gaps. Successful Publisher
holds its socket registration outside Child, requiring complete bundle retention.
Repair will separate direct-child reaping from producer descendant-drain proof,
retain exact resources and lease/cohort intent through uncertainty, and continue
servicing sibling actors without blocking on one reap. Rootless actual-child
regression precedes changes. This is not operational or release acceptance.

### Working source, not frozen or independently accepted

- Child owns an optional complete native bundle. Drop signals and moves it into
  the process-local retained collector without a three-second wait. Root waitpid
  and exact producer populated/procs emptiness are separate conditions. Capacity
  remains charged while the bundle is retained. Native reap errors stay with the
  failed actor; global registration corruption still returns a fencing error.
- Generic spawn uses atomic clone3+pidfd and registers health/release handles
  before fork. Postfork pidfd registration failure retains the complete gated
  bundle in the early-fork collector. Publisher now keeps its successful socket,
  cache-directory duplicate and all registrations in Child, including stop/drop.
- Parent-created producer hold contains exact native cgroup/parent descriptors,
  allocation OFD lock and a counted same-process exit reservation. It exists before
  guard birth; dropping the canonical producer queues this independent hold in
  the parent's collector. A guard Child has its own retained clone. Inspector
  copies receive no lease; fixed workers close these inherited descriptors.
- Remote Transaction replacement now holds its existing reservation before the
  replaced inherited view drops. This gives no copied Journal mutation authority.
- Guard terminal return services the guard's own TLS collector before exiting;
  it cannot rely on the parent's fork copy. Freeze/death and setup failure still
  require independent canonical parent lifecycle retention and native quiescence
  during operational assembly. A guard-local lease alone proves neither.
- Unscoped synthetic probes retain their explicit lease and remain unretired
  after release when no descendant proof exists. This conservative refusal is
  intentional; it is not a completed generic retirement or runtime acceptance.

Focused evidence so far: new actual fork/drop/inventory/reuse regression returned
`inspection_filter_selftest: child_failed` against the original Drop (RED).
After repair the expanded debug standalone selftest passes, now with two actual
siblings and capacity held until actual reap. Existing launch108 tests passed.
New native memfd flock regression passes: an independently reopened OFD remains
busy and same-shared-journal exit acquisition refuses after the original holder
is dropped; both become available only after the final retained hold drops.
No static refresh, frozen candidate, privileged runtime, or release result yet.

Open repair review: exact per-member native fault regression, hard live capacity
gate test, cleanup ordering of retired handles versus cgroup removal, synthetic
unscoped descendants, parent canonical guard/mutator retirement. Continue with
LocalAPI and actual operational assembly only after ownership invariants are
coherent; ordinary source/checks remain authorized. Root owns next native144.

### Follow-up ownership and LocalAPI implementation

Working source now binds the canonical parent's pre-fork producer hold to the
actual still-gated guard pidfd before release. Parent producer collection requires
that guard dead AND native producer empty; frozen or placement-capable guards do
not release holds. The registry is creator/full-allocation/exit keyed. Child,
early-fork and producer queues are creator-bound; inherited foreign entries remain
inert rather than being reaped or cleared by a sibling guard. Guard constructors
use atomic fork+pidfd and retain partial Scope, native control and registrations
through actual reap. A native cleanup precondition now precedes the FIRST active
transport cleanup and is checked again before producer unlink.

New real isolated regressions pass in the debug standalone selftest: lost actual
waitpid receipt produces retained ECHILD/capacity/inventory while sibling reap
continues; fork B with copied parent A live and pending actors cannot signal/drop
A's native authority and collects only its own child. Hard live64 pre-fork gate
has a focused unit test. Launch110 tests passed before LocalAPI test addition;
new native socket test passes (expected total111 after final focused run).

Fixed LocalAPI discovery now opens the protected daemon socket O_PATH, validates
socket/UID/GID, connects nonblocking through the retained descriptor, bounds poll
and SO_ERROR under one startup deadline, uses SO_PEERCRED as PID HINT only, and
rechecks fixed path/socket/state identities and live launch root afterwards.
All four actual normal/owner discovery paths use it; both full owner-native
Handoff daemon attestations remain. `/proc/comm`/executable scans are no longer
daemon discovery. Native socket unit coverage is not actual-role acceptance;
Root must exercise exact frozen normal/owner paths.

Still unimplemented: parent-DEATH durable unknown-mutator reconciliation and
complete operational startup/retirement assembly. No claim that an in-process
OFD survives canonical parent exit. Unscoped synthetic probes remain conservative
unretired, and parent-loss fixture/independent descendant acceptance requires
connected review. Public launch and production artifact refusal remain intact.

## SOURCE_PAUSED handoff: working source, NOT a frozen candidate

Root requested a precise pause when remaining context cannot safely carry the
substantial inherited-descriptor redesign. No more Rust/manifests/build edits by
this writer after the pause record. No static refresh was announced or performed;
the existing d57e candidate, both contexts and static artifacts remain d57e and
MUST NOT be presented as binaries for these new source edits. No native actual144
was run. Root's d57e ARM rootless preflight is separate baseline evidence.

Final ordinary checks on current source: launch111 PASS/0fail; strict workspace
all-target Clippy PASS; debug actual_lab standalone expanded filter selftest PASS;
fmt check PASS. Initial intentional Drop RED retained in this report. Intermediate
compiler failures (socket vs socket_with arity, one Scope Option registration)
and Clippy failures (nested if, test module placement) were corrected; no test
assertions or baseline build assertions were removed. No new full workspace test,
static-musl/ARM build or privileged runtime acceptance has run for this source.

### Exact blocking boundary finding

`spawn_owned_guard` still inherits all previously registered native descriptors.
The new creator checks make copied TLS entries inert for reap/signal, but do NOT
remove parent/A-only inspector, journal, host audit, guard-control and lease
capabilities from guard B. `inventory::Registration` is still Vec<fd> with
unconditional OWNED.remove(fd); contains() still checks numeric membership only.
Raw closing inherited FDs is unsafe: copied OwnedFd destructors could later close
a reused B descriptor, even if Registration Drop alone becomes epoch-aware.
Current `lab_child_creator_isolation` proves method/collector/capacity separation,
NOT inherited capability exclusion. This is a source freeze blocker.

Root and fresh reviewer conditionally endorse the following next implementation;
NONE of this boundary redesign is implemented yet:

1. Classify every native authority alias using fixed ownership roles: parent/A
   private, exact selected B guard inputs and deliberate shared deployment lease.
   Default refuse unclassified guard inputs; no arbitrary observed-FD adoption.
   Enumerate duplicates and canonical factory channels, not just PIDFDs. Fixed
   public worktree source contains no credentials; never inspect protected state.
2. Registration entries and owners carry exact (origin creator PID, monotonic
   epoch) tokens. Drop removes only a matching origin token; a foreign placeholder
   owner's valid Drop MUST remove its matching placeholder entry. contains() must
   validate exact token/native identity, not number. No blanket foreign-PID no-op.
3. In child B before role execution, verify each original excluded slot/token,
   then replace it with a CLOEXEC /dev/null descriptor using exact dup3. This
   removes native socket/lease/directory authority WITHOUT freeing its numeric
   slot while copied OwnedFd still owns it. Preserve the token and record only
   the verified inert native identity. Placeholder source FD must be outside the
   replaced set and closed/accounted afterwards. Any partial failure exits before
   run; no fallback or arbitrary allowlist widening. Parent copies unchanged.
4. Bind any foreign Actor Drop to creator/role so its copied placeholder cannot
   be re-enqueued as a new real actor. Foreign OwnedFd closes its own occupied
   placeholder; only after that close can B reuse the number. Verify all affected
   owner lifetimes, not just Registration token behavior.
   Reviewer specifically identified kernel/inspection.rs Actor::Drop (must not
   enqueue a copied A actor as B-owned with a placeholder pidfd) and
   JournalServer::Drop (calls fence, potentially nested cancellation). Scope has
   ordinary FD/Registration teardown. All need explicit lifetime coverage.
5. Add actual hot-add test: A factories/private endpoints/lease are live, fork B,
   prove B cannot operate A-only native socket/lease capabilities, drop copied
   owners, reuse exact number for B, exercise stale registration lifetime and
   show B's descriptor+token survive. Parent A remains functional and native
   collectors progress independently under unchanged deadlines. Extend the exact
   static --inspection-filter-selftest where rootless; Root can run additional
   actual owner fixture after a concrete frozen CLI/expected cases are supplied.

### Other exact pending review/work

- Parent GuardLifetime currently uses pidfd POLLIN: **guard exited**, not proof
  of the parent's actual waitpid reap. Describe evidence precisely. Parent guard
  admission now sets a Pending retirement fence BEFORE fork and binds the actual
  guard pidfd BEFORE fallible placement; failed partial setup remains Pending
  conservatively until native reconciliation, never cleared on empty producer.
- Parent-DEATH durable intent/reconciliation is required next connected work:
  no in-process OFD survival claim. Next start must fence unknown mutators using
  durable allocation/member/generation/scope/cgroup/process evidence; free lock
  or old parent death is insufficient cleanup/reuse proof. Preserve uncertainty.
- Unscoped synthetic `execution::launch` now holds a lease and stays unretired
  after possible descendants exist without independent proof. Its legacy
  `lab_parent_loss` path still needs connected redesign/testing, including its
  inherited creator-bound journal use. Do not claim every old synthetic lifecycle
  gate is regressed by the actual_lab standalone test.
- Review successful/failed Scope retention and cleanup fencing on frozen source.
  Scope::place_retained preserves post-pin handles; constructor failures earlier
  in native service placement retain intent and target pins without claiming a
  completed scope. Root owns all privileged verification and actual counter144.
- Fixed LocalAPI source is connected to four actual fixture paths, but exact
  native confinement/UID/socket semantics still require Root normal/owner tests.
- Continue real prepare_operational/daemon/ownerpin/monitor/serve assembly,
  protected declared host policy/cohorts, startup reconciliation, all-nine runtime,
  clients, migrations, platforms, faults, measurements and actual24h soak. This
  pause is context handoff, not completion or an external permission blocker.

Touched Rust files in this writer: actual.rs, actual_lab.rs, execution.rs,
handoff.rs, kernel.rs, kernel/inspection.rs, owned.rs, producer.rs, publisher.rs,
supervision.rs, transport.rs (all under crates/vprouter-launch/src). No changes
to inventory.rs yet: the token/role/placeholder plan is deliberately unapplied.
Final source digest inventory/evidence path:
target/operational-assembly-source-paused.json. Root should independently compare
it before appointing the fresh sole writer. Preserve all existing dirty work,
real HEAD/index, refs, failed resources and production Python as before.

## Nine-area status

| Area | Status |
| --- | --- |
| Secret lifetime/shared health | Existing implementation; integrated review pending |
| Shared host authority/cohorts | Declared authority foundation; public protected policy and transitions pending |
| Actual runtime/provider/public lifecycle | Assembly in progress; public launch refusal retained |
| Multi-Mullvad/direct lifecycle | Components only; actual independent lifecycle pending |
| Persistent client guards | Implementation and real-client acceptance pending |
| Durable migration | Apply/resume/rollback and two local preserved-identity migrations pending |
| Services/platform lifecycle | Debian/Arch/ARM component tests; full lifecycle/Void pending |
| Hostile traffic/fault acceptance | Component evidence only; full client/configuration matrix pending |
| Performance/24-hour soak | Same-host repeated ten-minute comparisons and actual soak NOT_RUN |

No all-nine completion or release claim. Continue connected work after retention,
including fixed LocalAPI PID hints with full owner attestation and protected
operational enrollment/host-policy assembly.
