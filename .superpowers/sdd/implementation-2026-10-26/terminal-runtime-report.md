# Terminal executor and operational runtime continuation

Status: IN_PROGRESS; all nine findings remain active. No public runtime activation,
production mutation, index/HEAD mutation, publication or credential access.
Sole implementer in /DATA/AppData/vprouter-rust-v2, rust/v2. Root exclusively
runs privileged/credential-bearing local VM actions. This report is incremental.

## Starting publication correction and review

ARM49 on2752df published Starting but died during the final ACK: two full daemon
audits of roughly1.2s each shared one2s exchange. Replaced that schedule with a
finite Prepare/Persist/Finalize transaction. Prepared follows full daemon/sender
verification plus exact Offline; Persisted follows the independent publisher's
fsync completion; final QuarantinedStop follows another full daemon/sender audit.
All steps bind original lifecycle/message/snapshot sequence, introduce no health
samples or Ready permission, and retain Session expiry. Each phase has2s and the
whole transaction6s; this startup schedule does not relax future5s monitoring.

Sources403336 and6f298 intermediate candidates retained but not requested for VM.
Source59c61e2ae5888862b383555a182ea314e87eb84c at
`target/continuation-20261026T144932Z/candidate.json`:219 ordinary PASS, lint and
staticboth PASS. Root corrected netfilter native22case PASS. The read-only exact
Matching assertion now occurs immediately AFTER ordinary release and BEFORE any
second writer; second Matching commit must advance generation and reject a batch
using the previous generation. This fixes the review's masked-deletion weakness.

Root ARM51 passed16 cases then controller aggregate60s harness cap ended the run
(exit124); failed/incomplete attempt retained. ARM53 SAME59c bytes passed all17
with explicitly changed controller aggregate120s TCG-suite cap only. Six captures,
112records, zero forbidden markers or drops per root parser. These are Starting
component results, not physical-ARM performance or real-client acceptance.
Void54 passed prepared nft-backend fixture preflight but refused product admission
unsupported_platform before guard activation; exact adapter remains open.

Subsequent review found framing only checked deadlines before IO, and the budget
could advance without proving prior-phase completion. Reproduced with slow actual
Deserialize: `target/terminal-ack-deadline-review-red.log`. Added post-IO and
post-decode checks, retained active-phase deadline, explicit on-time completion
before advancing, irreversible failure, final aggregate check. GREEN in
`target/terminal-ack-deadline-review-green.log`. ARM53 does not prove this later fix.

## First executor candidate55b006 (native results pending)

`target/continuation-20261026T150858Z/candidate.json`, source
55b006aff4d5e3e8f7284ec2dd1ec8b1886ac926. Exact hashes/input bindings in candidate;
immutable contexts copied by root, not by implementer. Logs:
- terminal-executor-workspace-tests.log: ordinary workspace PASS
- terminal-executor-workspace-clippy.log / terminal-executor-final-clippy.log: PASS
- terminal-executor-build.log: static x86/ARM, context/init consistency PASS
- terminal-executors-first-compile.log: retained wrong PollFd borrow failure
- terminal-executors-clippy*.log: retained private-network/unused-unit/enum-size fixes
- terminal-lock-red.log then terminal-lock-green.log: duplicate flock survives
  original transaction drop and excludes fresh allocation writer
- terminal-executor-mmap-red.log: self-review regression found generic anonymous
  allocator rule also permitted writable lock FD mapping; corrected mmap rule
  admits only private anonymous FD-1 RW/nonexecuting allocator mappings

New fixed terminal child is implemented in reviewed unsafe kernel.rs; expiry.rs
is safe orchestration. Three independently forked processes enter exact retained
host/transport/data netns, open their own terminal socket/timer and a separate
preopened one-shot fallback socket/timer, then close all unrelated inherited FDs.
Inventory0–10: null0–2, private seqpacket3, exact guard pidfd4, retained flock5,
primary netfilter6/timer7, bounded best-effort netfilter8/timer9, schedule timer10.
No parent-death kill and no Drop kill. UID/GIDroot permit SIGSTOP of retained root
guard after all caps except NET_ADMIN are dropped. Securebits/no-new-privs,
no dumpability; FD-restricted seccomp prohibits socket/exec/fork/setns/open,
write/flock/dup/close of lease5, and PID-number signals. Only exact guard pidfd4,
SIGSTOP/null siginfo/flags0 can be signaled. SIGSTOP delivery is explicitly not
proof of kernel transaction drainage; only changed nft generation plus exact
read-back is the fence. Fallback success is LateVerified, never original-deadline
success. Neither terminal writer can delete its table in product code.

Child authority is retained fork pidfd plus exact inherited endpoint, not
socketpair SO_PEERCRED (that reports creator PID). Original HealthMessage/Session
and sequence flow to each child. Heartbeats/liveness cannot renew verification.
Each child schedules earliest original expiry minus5s in CLOCK_BOOTTIME; separate
90s liveness watchdog remains. No lease with remaining<=5s is accepted. New
ReadyLease is private, borrowed from the actual controller, requires all three
live registered ACKs and exact durable ownership, and is checked before/after
native Ready transition. Public launch is still refused pending operational
monitor integration and actual containment acceptance.

Journal writes lifecycle/binding intent before spawn, exact scope/PID/start/netns
identity before registration ACK, acknowledged scope only after that private ACK.
Existing Offline reacquire, transport begin/cleanup and test unpin refuse terminal
barriers. Uncertain transitions retain intent. Allocation flock's open-file
description is duplicated into each child, surviving guard death. There is no
product barrier-clear/recovery path yet; that remains required.

New test-only exact-artifact invocation: same actual_lab payload with
`--ignored-terminal`. It uses existing identity-free actual-image/host admission,
creates a separate guard subprocess, leases original synthetic evidence with7s
remaining (does not shorten44s freshness or5s margin), externally SIGSTOPs it,
requires exact read-only terminal tables in all3scopes, verifies recorded identities
and preserves resources. It does not claim actual provider evidence or operational
Ready. Native execution requested from root, not yet claimed here.

## Nine-area status

| Area | Implemented/proved | Still required |
|---|---|---|
|1 health/provider|Strict shared Session, Starting bridge, original handshake expiry; finite ACK transaction|Periodic native Engine/provider and structural channel; original evidence to actual executors; cadence proof|
|2 routing/filter|Scoped offline/bootstrap/ready and corrected native terminal22case PASS|Actual fixed executor containment/deadline/fault proof; terminal recovery and operational Ready|
|3 guard/worker/init|Actual fixed roles/publisher/Starting bridge Debian/Arch; ARM53 all17 on59c|55b post-decode regression actual; executor completion journal; autonomous monitor lifecycle|
|4 multi-exit|Shared host/journal and unique exit leases; surviving lock duplication unit PASS|Native surviving writer barrier/recovery; actual five-exit operation|
|5 protected direct|Operational direct remains refused|Explicit direct runtime/policy/client no-fallback|
|6 platforms|Debian/Arch earlier17case PASS, ARM53 historical17case PASS; staticboth55b|Exact cgroupfs/runit adapter; Void54 correctly unsupported; service/reboot|
|7 real clients|Prior synthetic packet controls, ARM53 six captures112records|Enrolled client IPv4/DNS/IPv6/TCP/UDP/no-fallback real acceptance|
|8 migration|Approved identities/production preserved by root|Actual locked migration/cutover/resume/rollback two local installations|
|9 release evidence|Retained RED/GREEN/failures and frozen candidates|Workload benchmarks, actual24h mixed soak, final independent all-nine verification|

No component/static/short-duration result substitutes for full acceptance.

## FINAL handoff checkpoint a996d925fa (supersedes pending text above)

Status: NEEDS_CONTEXT for continued implementation, NOT overall completion. The
context continued through independent executors, native fault proofs, guarded
Ready/recovery and the newly identified GET secret decoder defect. All nine
requirements remain active. No production action, credentials, real index/HEAD
mutation or publishing occurred. Root owns privileged tests and progress.md.

Latest frozen source: `a996d925fa9b0d4c37406f14bd53912dea912bf9`.
Exact manifest: `target/continuation-20261026T154815Z/candidate.json`.
Source archive SHA256: `879d7a1e1e8fc4e03d0b253b7d635a042f82635535f569559acfa8506e23171f`.
The manifest binds 109 source/build inputs, aggregate
`eaf8cb66c3f9c0ab3e419e01e40f118ed36e3e2b99fd8e5275abc7da5531fd8c`.
AMD64 payload SHA256: `1af2175aaad414deeb51a7eaf16eff0ed3a09f07fa9ff8c242415eac01aeee81`.
ARM64 payload SHA256: `2a0e1a30bda9c194d523f0a203ed5c6ced6079f6b4010aeb88fa65f7a7693342`.
Context paths are mutable build destinations; root must copy and verify against
the manifest before any subsequent refresh. Root was notified of this freeze.

Final ordinary checks:
- `cargo test --locked --workspace`: 233 passed, 0 failed, 2 ignored across 23
  suites including documentation tests; `target/terminal-secret-final-tests.log`.
- `cargo clippy --locked --workspace --all-targets -- -D warnings`: PASS,
  `target/terminal-secret-final-clippy.log`.
- `cargo fmt --all` and approved alternate-index builder
  `python3 target/implementation-20261026-build.py`: static musl x86/ARM and exact
  four-role image context consistency PASS, `target/terminal-secret-final-build.log`.
- Native execution of a996 is requested from root and pending at this checkpoint.
  Do not transfer native PASS from older source bytes to this candidate.

### Preserved native and review history after 55b006

| Frozen candidate | Exact result and limitation |
|---|---|
|55b006, `continuation-20261026T150858Z`|Debian terminal actual55 failed child_failed then deadline before executor proof. Fixed child filter lacked exact PR_GET_SECCOMP needed by shared post-install check. ARM normal actual56 PASS17 with strict post-I/O/decode and phase-completion bounds.|
|dd3af81654fb4013c9d68c6369f545affba5d059, `continuation-20261026T151635Z`|Debian terminal actual57 PASS4, directory task8b2-60228: actual three-scope registration/expiry and durable timely outcomes. Review qualified the freeze claim because SIGSTOP issuance was not an observed stopped state. No Critical or other blocking implementation finding in that scoped review.|
|0b00d04228fbc56a88addcdaba2830891c0bee10, `continuation-20261026T152658Z`|Intermediate stopped-state/death candidate. A late context copy correctly failed hash verification after refresh; root retained the failure and ran no VM with mismatched bytes.|
|cd5a246d655a3ae80518050b116ae47442b1f359, `continuation-20261026T152949Z`|Corrected freeze actual58 PASS4, task8b2-60655; guard-death actual59 PASS4, task8b2-60894. Root owns exact controller, directory binding and witness artifacts in candidate-local platform directories.|
|8e6b250b07abe857d23fa6a15761174614fd0ca0, `continuation-20261026T154104Z`|Terminal actual60 PASS6, task8b2-61355. Native Ready requires all three leases and independent guard recovery streak; ProviderFailure -> quarantine -> health-only Bootstrap -> fresh recovery returns native Ready; observed guard freeze then all three exact policies and original-deadline outcomes. Synthetic provider evidence only.|

Corrected freeze proof binds guard PID/start to retained direct-child pidfd,
observes actual proc state T before terminal-table observation, and requires the
same stopped state immediately before SIGCONT. The test uses read-only
`TerminalQuarantine::verify_existing`, so observation cannot repair missing deny.
The resumed guard consumes queued exact child completion ACKs and journals each
identity, original deadline, actual finish time and result. VerifiedBeforeDeadline
requires finish < original deadline; LateVerified, Failed and StopFailed remain
distinct. No late containment is relabeled timely.

Separate death proof stops one exact executor, kills/reaps the separate guard,
drops the original outer allocation transaction, observes the other two retained
executor pidfds exited, and rechecks the surviving child's exact stopped state.
Only then does it assert fresh allocation flock acquisition is LockBusy. After
resuming that child and observing all three exited, a fresh lock is available but
durable reacquire and transport cleanup still refuse Interrupted. All three
terminal tables are exact. This case explicitly sets bounded_containment_claim
false: dead guard SIGSTOP failure is not a timely completion proof. Durable
barriers are deliberately not cleared by these tests.

### Final implementation additions

`expiry.rs` owns `Executors`, `ReadyLease`, original `LeaseClock`, and independent
guard `HealthMachine`. Health messages must validate against original binding,
lifecycle, sequence and timestamps in the guard and each child. A caller-supplied
Ready state cannot bypass the guard's three-success recovery streak plus next
approved sample. Valid health/liveness channel failures revoke all three private
channels using shutdown, causing independent terminal containment; never renew
expired evidence. `ReadyLease::check` also revokes on failed authority checks.

Shared health validation now permits genuine evidence-bearing recovery samples
to remain Blocked with reason None while the streak rebuilds. Blocked with a
failure reason and evidence is refused; Stopping/Failed evidence remains refused.
Previously every Blocked+evidence frame was rejected, making ordinary recovery
impossible. `GuardTransport::lease_health` applies exact Offline first for
Blocked, validates/distributes original evidence, then permits health-only
Bootstrap. Errors leave Offline. Actual guard-owned structural checks must still
surround operational publication; this component does not mint public start.
Logs preserve `terminal-guard-recovery-{red,green}.log` and
`terminal-recovery-wire-{red,green}.log`.

`owned.rs` persists `TerminalOwnership { lifecycle, binding, executors,
acknowledged, guard_pid, guard_start, completions }`. Every executor binds scope,
PID, start time and retained namespace. Journal validation enforces exact binding,
expected namespaces, uniqueness, ACK membership and outcome/deadline consistency.
`Transaction::{begin_terminal,register_executor,acknowledge_executor,
verify_executors,complete_executor,require_no_executors,retain_executor_lock}`
are the integration points. `GuardTransport::{start_expiry,lease_health,
ready_with_executors,finish_terminal}` expose only crate-internal authority.
No caller boolean grants Ready; no product method deletes terminal policy or
clears an uncertain terminal barrier.

Unsafe/process boundary remains `launch/kernel.rs`: fixed fork/namespace/FD
inventory, capability drop, exact seccomp and BOOTTIME timers described above.
Added read-only exact PR_GET_SECCOMP is required by post-filter verification.
Test-only `lab_terminal_guard`, `lab_stop_and_witness`, `lab_require_stopped`,
`lab_pin_executor`, `lab_wait_dead` and `lab_wait_killed` bind real child evidence.
`process::stat_stopped` accepts T only after exact PID/start parsing, rejecting
running/sleeping/zombie/dead/tracing-stop alternatives. Product survivor Drop
still never kills independent containment writers.

Root identified a preexisting WireGuard GET zeroization gap in dependency
netlink-packet-wireguard 0.5: typed decoding copied private/PSK keys to ordinary
arrays/Vecs, including partial failures and freed Vec-growth allocations before
the existing final scrub. `network/project.rs::sanitized_wireguard` now validates
and copies to one fixed-size Zeroizing buffer, then semantically walks bounded
TLVs and erases private-key bytes BEFORE any typed dependency decoding. It checks
PSK presence/length and rejects nonzero unsupported PSKs before erasure, preserving
zero-key TLV presence. Semantic nested traversal works even without NESTED flags
because the dependency descends by kind. Unknown/nonnative/scalar-nested forms
are refused. Partial/growth typed allocations only receive zero secret slots.
Final typed scrub remains defense in depth; raw request/reply owners already
zeroize. No actual key/profile was read. Regressions cover malformed later scalar,
nested zero/nonzero PSK with/without nesting flag, 65-key Vec growth and malformed
later nested timestamp. `wg-decode-zeroization-{red,green}.log` retain evidence;
first clippy manual_range_patterns failure is retained in
`wg-decode-zeroization-clippy.log`, fixed before final strict clippy PASS.

Changed files for this continuation: worker monitor.rs/bootstrap.rs; launch
expiry.rs (new), kernel.rs, owned.rs, transport.rs, lib.rs, actual_lab_main.rs,
transport_lab.rs, process.rs; core allocation.rs/health.rs/tests/health_wire.rs;
netfilter enforcement.rs/terminal.rs/lab.rs; network project.rs; generated pinned
program manifests. Existing earlier unfinished changes remain preserved.

### Nine requirements at handoff (original numbered requirement mapping)

The earlier thematic table is superseded by this exact mapping to the numbered
requirements in docs/rust-v2/implementation-2026-10-26.md.

| Requirement | Implemented and evidence | Remaining/open |
|---|---|---|
|1 secret lifetime|Earlier parser/SET/raw-buffer zeroization retained; GET typed-decoder gap fixed with predecode erasure and synthetic regressions; final233 ordinary PASS|Final-candidate native GET regression pending; independent review of new fix pending|
|2 shared health|Strict original Session/replay/binding; authenticated Starting publisher/CLI bridge; bounded three phases; recovery wire corrected|Periodic operational producer/reader integration and real provider evidence, cadence/stale tests|
|3 shared host authority|Earlier generation-bound owned model retained; terminal native preservation and stale-generation regression PASS22; exact independent scope policies|Actual adding/removing concurrent independent exits with unaffected peers; recovery reconciliation|
|4 operational runtime/multi/direct|Three actual confined executors, durable leases/outcomes, guard-owned health streak, native Ready/recovery with synthetic samples; actual58/59/60 fault components|Public launch/periodic Engine structural/provider channel, authorized enrollment, autonomous terminal recovery, CLI lifecycle, multi-exit and explicit direct mode|
|5 persistent clients|Earlier boundaries preserved; no new client readiness claimed|Real kernel/userspace client install/select/status, owned persistent enforcement and all no-fallback faults|
|6 migration|Production identities/state preserved; terminal uncertainty prevents unsafe reuse|Two actual independent local legacy installations, inspect/plan/apply/resume/rollback and real release activation|
|7 services/platforms|Static x86/ARM exact four-role artifacts; prior Debian/Arch/ARM Starting component PASS; exact unsupported Void refusal|Bound cgroupfs/runit adapter, native lifecycle services, install/update/rollback/uninstall/reboot and immutable release provenance|
|8 hostile faults/actual clients|Post-pin drift retained; observed guard freeze, guard death, sole-survivor flock and durable Interrupted proofs; original-deadline outcomes|Worker/provider/daemon runtime faults, suspend/kernel-stall first-packet containment, reboot persistence, four configuration shapes and real-client packet matrix|
|9 measured performance/release|Exact failures/source/artifact manifests retained; no shortened soak claim|Repeatable same-host 1/5/6-exit workloads, repeated10min measurements, optimization and actual mixed24h soak after prerequisites|

### Concrete next implementation sequence for the fresh context

1. Obtain root's final a996 native result and independent decoder review; preserve
   any failure and correct real WireGuard GET grammar before runtime activation.
2. Read actual worker engine.rs/monitor.rs, launch handoff.rs/daemon.rs and network
   audit.rs/guarded.rs. The Engine already has provider retry/cadence and LocalAPI
   components, but zero-cap monitor must receive fresh privileged structural
   evidence from the guard; it cannot use privileged NativeNetwork directly.
   Add an authenticated, lifecycle/frame/deadline-bound structural request/reply
   channel. Never attach a fresh wrapper time to old checks. Preserve full daemon,
   sender, routes, interfaces and handshake checks; ARM full audits cost roughly
   1.2s each, so schedule bounded protocol phases rather than removing checks.
3. Add root-owned operational enrollment declaration loading bound to exact
   Binding/config/node/address/peers. `DaemonDeclaration::new` and
   `ActiveLinks::pin_operational_metadata` exist; constructor data is not proof of
   an authorized live identity. Existing `pin_daemon_metadata` is unenrolled test
   authority. Root alone handles approved identities/credentials. LocalAPI must
   independently match preserved identity before mutable prefs/advertisement.
4. Handoff prepare chooses nonce; executor lifecycle must use that same nonce.
   Register actual three children with retained namespaces/transaction/policies
   before granting operational monitor authority. Existing Permission is only
   ObserveOnce/Monitor and public Admission::launch refuses. Do not remove that
   refusal until the actual prerequisites and native runtime loop are wired.
5. Connect periodic Engine/provider publication, independent guard health FSM,
   publisher and ReadyLease. Preserve5s monitoring, one eligible retry after1s
   with fresh checks, handshake<180s, original health<45s and separate90s liveness.
   Heartbeats cannot renew evidence or advance success streak. ProviderFailure
   first quarantines, then health-only bootstrap enables fresh recovery samples.
   Expired/terminal lifecycle never rearms. Add bounded exact-owned new-lifecycle
   cleanup/reconciliation: old guard and writers actually exited/drained, exact
   terminal generation/readback checked, durable barriers reconciled without
   deleting foreign state. Currently no such cleanup API exists; merely clearing
   journal fields would be unsafe. Account for executor reaping after completion.
6. Ask root to exercise real authenticated provider/runtime/advertisement through
   allowed isolated fixtures; separately test crash/freeze/channel closure/late
   completion and autonomous recovery. Do not conflate native synthetic Ready
   tests with real provider/client acceptance. Continue original task8c–15 briefs
   through multi/direct/client/migration/services/performance; all remain scope.

Keep the distinction between BOOTTIME scheduling and actual containment during
suspend/kernel stalls. SIGSTOP delivery is not drainage proof. Current executor
test has no real-client packet proof. No lifecycle can safely become Ready from
a cached file or caller-supplied state, and no terminal record is reusable merely
because all processes eventually exited.
