# Authoritative owner host-audit continuation — ACTIVE, NOT COMPLETE

Sole source writer `implement_host_authority`, worktree rust/v2. Real HEAD remains
c6a138c00b70163ba3cbfdf350e5cf8e2f3a3c6a; real index untouched. Prior ea2f85e
Bootstrap and 9a journal fixes retained. Root exclusively owns privileged/local
VM credentials/actions. No production, identity, service, index, cleanup or
remote-installation writes performed. All nine findings remain active.

## Implemented pending frozen/native review

- Complete typed ROUTE-only HostObservation wire, no WireGuard key/peer fields.
  Original Link/Address/Route/Rule projection reused in full, including optional
  Arch/TUN fields, multiplicity. Private WireObservation Deserialize prevents
  bypass of 128KiB decode cap; records bounded 4096 total, names/alias/nested
  fields bounded. Encoding uses a limited writer rather than allocate-then-check.
  Native parser remains max256KiB packet/4MiB per dump/4096 messages; IPC cap is
  independently stricter, unsupported larger hosts fail rather than truncate.
  Model admission/addition are also bounded before model adoption.
- Exact reference sorting replaces quadratic reordered comparison; ordinary
  unchanged comparison stays linear. RED reversed4096 required33,554,433
  comparisons; GREEN remains under4096*64 and exhaustive duplicate test passes.
- Creator-PID HostAuthority binds full allocation/selected owner/native namespace
  and monotonic model revision. Ticket checks reject fork copies, changes,
  unknown members and actual metadata drift. No caller observation adoption.
- Fixed host child in kernel/host_audit.rs. Exact descriptors0/1/2 null,3 private
  seqpacket,4 protected journal root,5 pinned host netns,6 ROUTE. Close inherited
  channels; chroot, caps0/securebits/NNP, restricted seccomp. Preopened ROUTE is
  native to pin; no GENERIC socket. Original BOOTTIME sent_at+2 also bounds child
  netlink, serialization and response. Parent retains direct child pidfd and
  only decodes after actual clean exit/reap. Parent receive/decode/poll nonblocking.
- HostAudit zeroarg operation shares original Progress sequence/time with
  journal/progress. ExternalOwner has one host actor per member; deployment
  capped MAX_EXITS. Terminal actors are cancelled but retained until actual reap.
  One held member cannot synchronously wait in another member's polling path.
- Private bound Local/Remote authority in GuardTransport/ObservationAudit. Whole
  transport converts via gated GuardOwner and Transaction::fork_remote. Remote
  checks explicitly use namespace-only metadata+WG and existing policy checks,
  then check SAME receipt; no copied Rc fallback. Structural receipt retained.
- Original receipt caps Ready enforcement, lease and ReadyPublication. Earliest
  checked_at survives full-process verification. Publisher receives original
  absolute expiry in fixed binary prefix and checks before/after IO, rename and
  ACK. Handoff retains proof through Persist/Commit and final pre/post ACK.
- Reviewer found consumer stale-success gap: worker now retains guard-matched
  structural_at+2 before message move and checks BOOTTIME before/after each phase
  and final acceptance. Real framed RED regression returned Ok with fresh Commit
  but expired original evidence; GREEN rejects it (250ms actual delayed ACK).

## Tests/build status at this update

- Network39 ordinary PASS +1 ignored, compile-fail doctest PASS.
- Launch82 ordinary PASS (including exact filter/socket FD/memory/privilege paths).
- Full workspace279 ordinary+doctest PASS,0failed,2ignored in
  target/host-authority-evidence/workspace-1.log.
- First strict clippy failed only items-after-test-module in refactored native.rs;
  moved native helpers before tests, retry clippy-2.log underway.
- Formatting run. Static x86/ARM freeze NOT YET RUN; native host-audit NOT YET RUN.
- No claims of full runtime, Ready/provider/client acceptance from these checks.

## Fresh native oracle interface

New `--ignored-owner-host-audit`, existing `--owner-bootstrap-descriptor` schema.
Same fresh protected nonce/new deployment fixture, but selects host test BEFORE
any terminal journal mutation; old `--ignored-owner-bootstrap` unchanged.
Fresh genuine two-Bootstrap activations followed by entire guard remote binding.
Both guards perform actual owner native host audits + local network/policy checks.
After >=2 each, next A child pauses at private checkpoint, exact PID/start STOP;
no SIGCONT. A original2s deadline freezes guard, kills child, retains/reaps actor.
B must complete >=2 fresh audits after A terminal+drain. Then mutate exact retained
owned host veth MTU to1499; B must fail canonical model comparison NetworkPolicy
(with HostDrift diagnostic), not decoder/child failure. Finally exact stopped
old guards killed/reaped; quarantine/namespaces/records/containers retained.
Every successful test child checks caps0/bounding/ambient/NNP/securebits and same
ROUTE socket forbidden RTM_NEWLINK gets EPERM after full positive dumps. Generic
socket creation is rejected by same filter. Native stdout records projection
byte size, exact private actor IDs/start/deadline/terminal timing and B counts.
Root prepared fixed x86+ARM runners for owner-host-audit mode. Freeze forthcoming.

## All nine status (binding scope, not completion)

1 Secret lifetime/shared health: existing foundational changes retained; full
  operational acceptance still pending.
2 Authoritative host model: this new async owner slice implemented; native and
  scoped review pending. Dynamic generations/hot add/remove not implemented.
3 Operational init/worker/provider/public lifecycle/direct+five exits: components
  exist, public launch still refuses; staged full lifecycle/retirement pending.
4 Persistent kernel/userspace clients: real selected clients/leak gates pending.
5 Migration: two independent local legacy installations and real release/state
  apply/resume/rollback/adapters/interruption acceptance pending.
6 Platforms/releases: static both/native labs foundation retained; supported
  install/update/reboot/rollback/uninstall and Void runit adapter pending.
7 Hostile traffic: component faults progressing, full actual traffic/capture
  matrix across1/5/direct/6 exits pending.
8 Performance: repeated same-host Python/Rust10min1/5/6 measured comparisons and
  optimization pending; no benchmark claim.
9 Acceptance/soak: independent final whole-branch verification must follow ALL
  implementation/testing; real24h mixed soak pending, never synthetic substitute.

Next: finish strict tests/build exact frozen candidate; root native x86+ARM and
original90watchdog/affected regressions, independent scoped review; repair only
source-specific findings. Then dynamic exact generation transitions before
mutations, live neighbor proof, staged full lifecycle and typed safe retirement,
then remaining clients/migration/platform/traffic/performance/soak requirements.

## Frozen native candidate 1867485c (source PAUSED for gate)

`target/continuation-20261026T212316Z/candidate.json`, source
1867485cbb44873593768e2d88db8e09338876df. Final workspace-2.log279PASS/0failed/
2ignored; clippy-2.log strictworkspace/alltargets-Dwarnings PASS; fmt-2.log PASS.
static-1.log x86+ARM musl static payload/context build PASS, BOTH unchanged
init-manifest-hash-stability assertions PASS. Fresh source archive comparison117
files/0 mismatches in target/host-authority-evidence/frozen-source-check.json.
Root notified and is copying strict candidate-local contexts before native96.
No runtime acceptance or all-nine completion claim. Source held immutable while
native/scoped reviewer gates run. Private reader/host child fault resources stay
retained; no old stopped guard lifecycle resumed or borrowed for this fixture.

## Native96 RED and exact readback repair

Root's source186 x86 native96 reached genuine two-Bootstrap activation PASS1,
spawned both authentic guard scopes and completed original seq2 journal reads.
Both initial HostAudit seq3 children failed EXIT122, private diagnostic[254,6,205]
(stage6 apply_filter, Error::ConfinementPolicy), before any native audit success.
Code trace: kernel_base::apply_filter installs BPF, then verifies
prctl(PR_GET_SECCOMP)==2. New host filter denied that readonly getter, causing its
mandatory independent readback to fail. No filter-install bypass was added.

Added exact BPF behavior regression: GET_SECCOMP must ALLOW; SET_SECCOMP,
SET_NO_NEW_PRIVS, CAP_AMBIENT and nonzero upper-word GET variants must remain
DENY. RED returned327681(EPERM) vs2147418112(ALLOW). GREEN passes after adding
only exact64-bit arg0 GET_SECCOMP; privileged mutations/socket/FD rules unchanged.
Clippy-3 PASS. Workspace-3 and static-2 running for replacement candidate.

Root's first96 nonce archival correctly REFUSED live guard scopes. Root then
independently reverified exact recorded PID/start/stateT/cgroupinode/payload,
opened pidfds and SIGKILLed only68433/start20547624 and68434/start20547628;
both actualEXIT and subsequent units/cgroups absence proved. No SIGCONT. Root
archived failed96 nonce only after absence, retained other resources and evidence
owner-actor-inspect-run-96.json and owner-actor-drain-run-96.json. These actions
were root-only, not source writer commands. Failed96 remains failed.

Root reports scoped186 review PASS after the two Important deadline integration
issues were corrected; incremental getter diff still needs scoped review. All
native host/Ready/provider/lifecycle claims remain pending.

## Native97 positive host component, failed fault checkpoint

Frozen a3aed00c7f1a119b648d3bf2d5ec5eed0526e74a at
`target/continuation-20261026T212715Z/candidate.json`: workspace279PASS/0failed/
2ignored, clippy3/fmt/staticboth/BOTHinitstability PASS,117inputs/0mismatches.
Root97 x86: genuineBootstrap PASS; FIVE host children actualEXIT0,44774byte exact
public metadata, ROUTE-only positive full dumps and same-role mutationEPERM,
caps0/NNP/securebits/FD0..6 checked. Actual remote guards progressed authenticated
HostAudit seq3 and6 plus subsequent producer/link journal checks. Full fault gate
FAILED `process_changed` before A timeout.

Cause is test-only asynchronous stop race: new lab_checkpoint sent SIGSTOP then
immediately required T, without allowing kernel signal delivery. Repair retains
original exact pidfd/start after private checkpoint, polls identity+actual T on
later owner-loop turns, never waits/sleeps in shared loop, never restarts original
2s or resumes SIGCONT. Applied same real-T polling to final guard kill/reap barrier
so immediate final B freeze cannot race its witness either. Production unchanged
from a3. Native97 is the RED evidence; native98 GREEN pending.

Root independently drained only exact97 stopped guards68828/start20570348 and
68829/start20570351 after intent/currentnonce/pidfd/exesha/solecgroupmember checks;
actual exits and all actor units/cgroups absent before nonce archival. Other
failed resources remain. Source writer did not execute root actions.

Workspace4 again279PASS/0failed/2ignored; strictclippy4 PASS. Final cfg(test)
guard-witness addition covered by launch5/clippy5; static3 build now running.

## Native98 x86 GREEN — source97946 checkpoint fix

Frozen `target/continuation-20261026T213136Z/candidate.json`, source
97946a1f616e7b9bda6b0defba2c00286cfb1525. Production unchanged froma3;
final test-only checkpoint/guard-T witness repairs. Workspace4 279PASS then
final launch5 82PASS, clippy5/fmt/staticboth/BOTHinitstability PASS;117inputs/
0mismatches in source-97946.json. Root scoped checkpoint review PASS no findings.

Root native98 x86 PASS3: genuine two Bootstrap guards/neighbor re-audit; held
A child69223/start20595909, originaldeadline205961.061508329, Aterminal
205961.070469948 (+8.96ms); B15 host completions at Aterminal and17 before drift,
so TWO fresh audits after actual Aterminal+host actor drain. Actual retained
owned host-link MTU drift at205961.346096247 produced canonical model rejection.
Exact guards69207/start20595875 and69208/start20595878 STOP witness, kill/reap
PASS. Positive route dumps, caps0, denied mutation and confinement are exercised
on the same fixed role. Root retains all namespace/container/journal resources.

ARM99 now running. Original90watchdog and affected normal/terminal/journal/
Bootstrap regression gates queued sequentially by root on SAME frozen source.
Source remains PAUSED for these oracles; only report/read-only next-slice planning
continues. No provider/Ready/client/full staged lifecycle/retirement claim.

## ARM99 GREEN and original90 watchdog100 RED witness race

Root ARM99 on same979 source PASS3: held A child9321/start3387172, original
33873.693766943 deadline, terminal33873.734961649 (+41.2ms); B10 host audits at
Aterminal and12 before actual ownedMTU drift33874.260555549, canonical rejection.
Exact guards9305/start3387070 and9306/start3387089 actual-T/kill/reap/drain PASS.
ARM remains emulated ABI runtime proof, not physical performance acceptance.

Root original90watchdog100 ran actual91.043s, reached unchanged owner deadline,
then old test's immediate lab_require_stopped raced signal delivery and failed
process_changed. Root independently found exact guard69370/start20607805 already
T/solecgroupmember186348/executable-bound; exact pidfd SIGKILL/actual exit and
all actor-unit/cgroup absence before archive100. Other resources retained.

Test-only fix now polls retained pidfd/live/start/actualT under ORIGINAL existing
clock.deadline+2 oracle allowance after supervise returns. Product90s timer and
all owner/host-audit logic unchanged; no new deadline/rearm/resume. Native100
remains FAILED until next full90 GREEN. Launch6/clippy6 and static4 underway.
Root normal17 regression101 on immutable979 running concurrently with source
build only; privileged native oracles remain sequential under root control.

## FINAL HANDOFF — source PAUSED, connected terminal continuation required

Source remains exactly frozen at **14851d67f9e207076bf0d37a825b89df533b502c**.
No terminal integration source edits have been made. Candidate:
`target/continuation-20261026T213810Z/candidate.json`.
Final direct byte comparison of all archive members against current working files
confirmed **117 files, 0 mismatches**. Archive SHA256:
`dfdef1461a423dd7570f51cd3a32ed340689708d7deb1e9023a286160507ce01`.
Real HEAD remains `c6a138c00b70163ba3cbfdf350e5cf8e2f3a3c6a`; real index/history
were preserved. Candidate commits use the existing isolated alternate-index build
workflow. Root copied both immutable context archives before this handoff.

Final148 gates: launch6 **82 PASS**, clippy6 strict all-targets **PASS**, fmt
**PASS**, static4 x86+ARM builds **PASS**, both existing gateway-init stability
assertions retained and passed. Earlier covering workspace4 was **279 PASS,
0 failed, 2 ignored**;148 changes only cfg(test) watchdog actual-T polling. The
full original90 runtime rerun on148 remains **NOT_RUN**;100 remains failed even
though root proved the original product timer fired after the real91.043s wait.
Scoped148 watchdog test-only review passed with no findings.

Root's additional native regressions, all on exact97946 source:

- **101 normal PASS17**, six captures,112 records,0 forbidden,0 drops. Component
  lab acceptance only.
- **102 terminal FAILED** after two Bootstrap cases:
  `LAB_TERMINAL_GUARD_FAILURE reason=ownership_mismatch`, then `actual_lab:deadline`.
  Retained fixture `/var/lib/vprouter-v2-lab/task8b2-69928`. Root read-only checks
  found no matching frozen-artifact actors alive, no terminal journal evidence,
  and no synthetic WANroute185.65.134.88; other retained resources remain.
- **103 journal PASS6**.
- **104 Bootstrap PASS2**: genuine two Bootstrap activations and neighbor
  re-audit, overlapping legal BeginTerminal FIFO[0,1]. Original seq3 sent times
  206577.154981204/206577.155020974; durable finishes
  206577.321747472/206577.386687787 before ORIGINAL deadlines
  206579.154981204/206579.155020974. Exact guards70495/start20657701 and
  70496/start20657704 EXIT0/reaped. Root strict disk SHA256
  `8be5efd18dea6508ed32c5517686335eb45150d8a0ca630be389298c9f16f904`.

Together with native98 x86 and99 ARM host fault gates above, these are accepted
component evidence for the exact979 source. They do not prove provider health,
real client Ready, hot-add lifecycle, restart recovery, retirement, migration,
rollback, reboot, or overall all-nine completion.

### Exact terminal102 failure trace and required connected repair

`expiry::lab_run` first rawforks through `kernel::lab_terminal_guard`; the FIRST
child action is `guard.start_expiry`, before any health sample or host audit.
That calls `Transaction::begin_terminal` against a copied Local Journal and
correctly hits creator-PID rejection. The same fixture would later hit copied
HostAuthority. Neither protection may be relaxed and no copied-Rc/Local fallback
is acceptable. Use an actual parent-held ExternalOwner + JournalServer +
HostAuthority, bind the forked guard through the existing authenticated remote
capability, and service the parent loop during all guard setup and RPCs. Existing
synchronous lab_terminal_guard checkpoint wait would deadlock parent servicing;
replace it with bounded private checkpoint polling and retained actor proof.

Additional connected blockers already code-traced:

1. `Transaction::retain_executor_lock` currently gets remote Revalidate ACK then
   still calls copied Journal::revalidate. Remote branch must obtain the actual
   retained allocation OFD duplicate ONLY after matched original owner Revalidate
   ACK, without treating copied Journal records as authority. Local branch keeps
   normal Journal validation. Preserve private spec/allocation binding and the
   actual shared native lease.
2. Remote `GuardTransport::start_expiry` and `ObservationAudit::expiry` currently
   call unowned Executors::spawn. Carry private owner-bound Domains (currently
   HostAuditClient is merely a JournalClient tuple), require exact spec and
   lifecycle, and call existing Executors::spawn_owned for all three siblings.
   Owner registration must verify exact actor pidfd/start, native namespace and
   actual systemd unit/cgroup membership. No caller bool/PID/path bypass.
3. Existing regular terminal fixture SIGCONT's the expired stopped guard to call
   finish_terminal and collect queued executor ACKs. Existing guard-death fixture
   stops host executor, kills guard, proves retained lease, then SIGCONT's the
   expired writer to finish containment. Both expired-actor resumes must be
   removed, not renamed. Signals alone do not prove containment or retirement.
4. Durable completions must remain authentic. Preferred connected design is
   parent-held fixed completion endpoints established before child spawning,
   paired with original registered executor identity/retained pidfd and native
   scope placement. Parent collects the original bounded terminal ACK with exact
   lifecycle, scope, original deadline, finished_at and outcome, and records it
   through the canonical journal. Socketpair SO_PEERCRED is creator identity,
   not proof of the forked sender. Do not manufacture VerifiedBeforeDeadline
   from later policy observation; do not silently discard the existing durable
   three-completion requirement. If no authentic completion can be collected,
   retain explicit durable interruption/quarantine and make that limitation part
   of the gate, with independent native terminal table evidence.
5. For the old guard-death held-writer lease test, checkpoint the selected writer
   AFTER verified containment but BEFORE exit if full containment plus lease is
   claimed. Alternatively keep it explicitly a lease/reuse-barrier test and prove
   full guard-death containment independently without an injected stalled writer.
   Killing an unperformed host writer cannot establish host containment, and the
   old eventual-resume `terminal_host_transport_data_exact=true` claim cannot be
   carried forward.
6. Preserve original Session/handshake expiry and independent90-second owner
   timer. No new sent_at/deadline or stopped lifecycle rearm. Retain all original
   failure actors/resources until exact native drain is proved by root.

Root prepared strict Debian `owner-terminal` / `owner-terminal-death` runners.
CLI flags remain `--ignored-terminal` / `--ignored-terminal-death`; protected
`--owner-bootstrap-descriptor` uses existing owner_unit/deployment/nonce schema,
with deployment `launchlab-<nonce12>`. Terminal source allocation must use that
protected deployment so code runs in the authentic owner systemd service.
Wrapper expects EXACTLY one fresh `task8b2-PID` directory; keep that fixture path.
One exit is sufficient; stable owner unit binds deployment independently of full
allocation. No ARM terminal claim yet. Root controls all privileged oracles.

Fresh sole writer must read root's complete
`.superpowers/sdd/implementation-2026-10-26/terminal-owner-brief.md` and the original
constraints/spec/plan plus reports. Root will replace this writer only AFTER this
FINAL handoff, so there are no overlapping source writers. Notify root BEFORE any
mutable context builder refresh; preserve BOTH init-stability and source-binding
checks. Do not rerun accepted journal/Bootstrap implementation or add Local
exceptions. Gate the connected terminal fix and affected regressions before the
next dynamic-generation/staged-runtime/retirement slice.

**ALL NINE REMAIN ACTIVE.** Host audit implementation and source-scoped component
fault gates are delivered, but connected terminal integration, actual staged
runtime, durable dynamic generation/ownership transitions, retirement and final
whole-branch independent verification remain required. This handoff is
**NEEDS_CONTEXT / SOURCE_PAUSED**, not overall DONE or a compile-only completion.
