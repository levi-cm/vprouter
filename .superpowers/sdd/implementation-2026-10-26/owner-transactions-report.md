# Owner transactions continuation — IN PROGRESS

Sole writer: implement_owner_transactions. Parent exclusively controls privileged
and credential-bearing LOCAL VM operations. User's approved all-nine plan and
`docs/rust-v2/IMPLEMENTATION.md` remain binding. Public launch remains refused;
no release-ready, runtime-complete, or overall DONE claim.

## Starting evidence

Read owner-transactions-brief.md, constraints.md, approved implementation plan,
IMPLEMENTATION.md, owner-runtime-report.md final handoff (762 onward). Confirmed
real HEAD c6a138c00b70163ba3cbfdf350e5cf8e2f3a3c6a; existing dirty history preserved.
Starting frozen candidate4ce0755c953f810205bf2da154a71019f14d872d. Prior native
results remain component evidence only and do not transfer onto changed bytes.

## First repairs (not yet frozen/reviewed)

1. Extracted existing mutation admission decision. Ordinary pending writer was
   treated as LockBusy, propagated through ExternalOwner to freeze healthy B.
   RED `cargo test --locked -p vprouter-launch --lib
   ordinary_neighbor_writer_is_waiting_not_terminal_failure`:
   `target/owner-transactions-evidence/red-contention.log`, actual assertion
   Err(LockBusy) vs expected Ok(false). This is the exact existing admission
   decision; complete native overlapping mutation acceptance is still pending.
2. Fixed IO reader originally accepted only the exact before/alternate captured
   at start. A legal neighboring canonical commit can change whole bytes while
   leaving B's selected predicate unchanged. A reduced pure reproducer uses two
   structurally valid Bootstrap members and a legal neighboring terminal record,
   preserving the old byte-comparison decision. It is not native activation.

Proposed repair: bounded FIFO with one queued authenticated request per member,
retaining ExternalOwner's original Progress (sequence/sent_at/2s), and separate
shared uncertain-writer fence. Fixed confined child reports exact observed
SHA256 over its private inherited ACK endpoint. Only canonical owner-created
current/proposed records populate bounded per-active-read digest windows. Shared
binding and selected entry authority must match at reserve, publication, and
completion; unknown disk digest is never adopted. Per-read limit64, members256;
digest payload ceiling512KiB plus hash-table overhead. Full windows backpressure
writers under their original deadlines; reads/watchdogs remain independently
polled. Pending candidate is registered before child release. Failure retains
writer lease/handle/pending record and global uncertain-writer fence.

## Resource/security inventory (provisional)

No new unsafe block or capability; changed fixed IO acknowledgment from1 byte to
33 bytes (128 +32 SHA256), exact packet size checked. Existing read/write syscall
allowlist, chroot, caps0, NNP, seccomp, parent-death, fixed FD0..5 plus transient
fileFD6 and inherited OFD allocation lease retained. No new subprocess role,
path, callback, exec, caller snapshot/digest authority, or production test flag.

## All-nine status

| Area | Current state / remaining acceptance |
| --- | --- |
| 1 Secret lifetime | Prior implementation retained; changed whole-branch verification pending |
| 2 Health contract | Prior implementation retained; real enrolled runtime acceptance pending |
| 3 Host authority | Owner-held IPC and dynamic generation transitions still required |
| 4 Operational runtime | Journal concurrency repair underway; staged public start/stop, 3 expiry scopes, direct/5 Mullvad and terminal retirement incomplete |
| 5 Clients | Persistent kernel/userspace no-fallback enforcement and actual clients incomplete |
| 6 Migration | Two local identity-preserving legacy cutover/rollback cases incomplete |
| 7 Platforms/services | Component x86/ARM/systemd evidence exists; full lifecycle/runit/reboot/update/uninstall incomplete |
| 8 Hostile/native acceptance | Focused journal gate pending; final source90s watchdog and whole real-client4-configuration matrix required |
| 9 Benchmarks/soak | Repeated real10min1/5/6 whole-router benchmarks and true24h mixed soak not complete |

After checked freeze: root native/scoped independent review is mandatory BEFORE
new functional implementation. Read-only design prep may continue while waiting.

## First checked freeze — 9a13491 (source PAUSED)

Candidate: `target/continuation-20261026T202817Z/candidate.json`.
Source: `9a13491d906cf406247667abb8529173e6620025`.
Archive SHA256: bf82a429bab9a32d4d763b90f1bb1c37b52579d765abccd838428ba0b9bd5602.
115 build inputs verified; source aggregate
0e27ccdc7ab6be9dbac4f187ed04ab35da2558a224d865a9ffa924467339db69.
AMD64 payload cc60dc247c6d76615c3fb3662f20cf22acdde071beaf67b7efc9d0d855060648;
ARM64 payload82b074c5d64e1291c62bf37d3c4a2823daaa1f2364f87f4552d21ceea397607b.
AMD64 context1fd18bc3f50ea2383f9a7f5ff3e49dd47888924dcd508276256e783d19f3acb3;
ARM64 context32535ff8ebc19edbfbf62e2d8efcf20d766f5588d5ec68ac70a557da164c0396.

Commands/results:
- `cargo test --locked -p vprouter-launch --lib ordinary_neighbor_writer_is_waiting_not_terminal_failure`: RED extracted original production decision, log red-contention.log.
- `cargo test --locked -p vprouter-launch --lib crossing_neighbor_commit_capture_only_regression`: RED reduced original frozen whole-byte comparison, log red-crossing-read.log. Both before/after records structurally valid; selected B unchanged. Test replaced by positive owner-generation test after repair.
- `cargo test --locked -p vprouter-launch --lib owned::tests`: GREEN13, green-owned3.log. Includes legal production Record::begin_terminal transition (extracted unchanged) for two members, FIFO/order/cancel/capacity, original2s, canonical neighbor generations, unknown digest, shared and selected changes, pending selected changes, history capacity/backpressure.
- `cargo test --locked --workspace`:270PASS/0failed/2ignored, workspace-tests2.log. Earlier --lib224PASS/2ignored is a subset only.
- `cargo clippy --locked --workspace --all-targets -- -D warnings`:PASS clippy1.log.
- `cargo fmt --all --check`:PASS.
- `python3 target/implementation-20261026-build.py`:PASS static-build1.log, static x86/ARM, BOTH init manifest hash-stability assertions and strict source binding. Alternate index/ref only; real HEAD/index unchanged.
All above logs under `target/owner-transactions-evidence/`.

Changed production files since4ce: owned.rs (queue/read windows/pure terminal
transition extraction), owner.rs (passes retained exact guard to queued polling),
kernel.rs (bounded exact33-byte private IO completion and digest accessor).
Test-only native crossing code is in owned.rs and private checkpoint release in
kernel.rs: read held waiting on its private ACK socket, never SIGSTOP/SIGCONT;
real owner-generated Offline->Activating neighbor intent on actually acquired
namespaces is atomically written/fsynced/renamed by a separate confined child;
reader then must observe new exact hash and pass unchanged-neighbor authority.
Existing stopped-reader/healthy-neighbor loop remains afterward. This proves IO
crossing of legal activation INTENT only; NOT Bootstrap/routed activation.

Root notified before mutable context refresh and sent exact candidate request:
owner-journal, owner-deployment, source-specific full90 watchdog. Native/review
results pending. Parent explicitly authorized a genuine two-member native
GuardTransport activation fixture with synthetic distinct profile keys and new
anonymous inert gateway, shared parent HostAuthority and Journal before guard
fork; root will run privileged fixed payload. No existing genuine two-member
Bootstrap fixture exists. Initial review freeze must be copied/validated first;
read-only design prep continues. Authenticated overlapping mutation native gate
still NOT_RUN, so concurrency acceptance is not claimed complete.

## Read-only design for genuine Bootstrap journal gate

Parent confirmed there is no existing two-member Bootstrap fixture and explicitly
authorized isolated synthetic two-member GuardTransport activation. Proposed
fixed native harness (not implemented at first freeze):

1. Protected nonce-derived unique exit IDs (<=32 chars), constant launchlab
   deployment so stable owner service descriptor remains valid. New exclusive
   private resource directory and allocation record. One new anonymous inert
   gateway with exact reviewed4-role image, network-none, cap-drop ALL, no-new-
   privileges, read-only, TUN. Preserve it/resources on failure.
2. Build two distinct synthetic Mullvad profiles using fixed non-production
   private seeds, exact distinct expected server labels; no approved identity or
   ZIP/profile/account reads. One synthetic WAN peer topology, distinct assigned
   namespace/link/nft/subnet authority per exit. Profiles can share synthetic
   endpoint and tunnel addresses, proving isolation without provider access.
3. Generalize test-only inspect_actual to select an allocation member (existing
   wrapper remains member0). Same container is allowed: first data namespace is
   pinned container base; second acquired owned namespace. Both Admissions exist
   before activation; producer cgroup subgroup names are exit-bound and unique.
4. One parent Transaction plus for_exit, both namespace acquisitions; one shared
   HostAuthority admitted from explicit fixture native declaration. Activate A
   and B via GuardTransport::activate; each path includes real producer cgroup,
   native veth/WireGuard birth/move, quarantine, native indices/readback and
   durable Bootstrap. Audit both again after B activation. This tests initial
   common-parent setup, NOT live hot-add or remote HostAuthority.
5. Borrow guard transports' private journals/namespaces through cfg(test) accessor
   only. Spawn two actual separately scoped guards, each fork_remote then issue
   BeginTerminal with exact expected binding/lifecycle, then fresh revalidate.
   Hold first writer at private before-sync checkpoint (no SIGSTOP), wait until
   second authenticated original frame is queued, then release first and second
   writer gates. Require both durable canonical terminal records, exact guard
   PID/start bindings, original2s acknowledgments, queue emptiness, unfenced
   shared journal and actual successful child reap. Record original deadlines
   and overlap proof. No production noop-write API or seeded Bootstrap record.
6. Leave owned Bootstrap policy/resources retained after component test; no
   service/public operational grant, terminal deletion, provider/enrollment or
   client acceptance claim. Native uncertain-writer/deadline tests and full90
   watchdog remain separate explicit evidence requirements.

Potential fixture integration issue: existing setup_wan uses fixed endpoint
route185.65.134.88/32; historical owned fixtures may retain it. New fixture must
use its own unique synthetic WAN address/subnet or an exact explicitly supplied
owned fixture declaration; never delete/rebind historical routes to make it fit.

## Root results on first freeze9a13491 (reported by root)

- Native89 x86 owner-journal PASS6; exact33-byte ACK path retained old confinement,
  durability, stopped-writer/OFD-lock checks.
- Native90 x86 owner-deployment PASS2: crossing read completed202358.78374 before
  original202360.76883; stalledA deadline+14.3ms, B38reads before/77total=>39after.
- Native91 same-source original90s watchdog PASS: guard67438/start20254192,
  deadline202631.932763513, observedT202631.963714522 (+30.95ms), killed/reaped.
- Native92 ARM/TCG deployment PASS2: crossing30489.20494<30491.15079;
  Aterminal30491.65467 vsoriginal30491.64222 (+12.45ms), B31before62total=>31after.
  ABI execution under emulation, not physical ARM performance evidence.
- Scoped independent reviewer PASS both concurrency fixes; no Critical/Important.
  These gates still did not establish overlapping legal JournalRPC writes from
  actually activated Bootstrap members. New fixture below supplies that gate.

## Genuine Bootstrap native fixture — checked freeze2ce8639

Candidate `target/continuation-20261026T204306Z/candidate.json`, source
`2ce863955c4cf0753fec463ce45316232e02579f`. Source PAUSED pending root native and
frozen incremental review. 271 ordinaryPASS/0failed/2ignored, strict workspace
all-target clippy-Dwarnings/fmt PASS, static musl x86+ARM/BOTH init hash stability
and115 source-input binding PASS. Logs in target/owner-transactions-evidence:
bootstrap-workspace2.log, bootstrap-clippy2.log, bootstrap-static1.log.

Changes after9a are test-only: execution_lab inspect_actual_member; actual_lab
fixed flags; transport lab configuration/WAN/native activation; private
GuardTransport journal accessor; owner queue/frame/checkpoint accessors; owned
mutation checkpoint/completion metadata and actual overlap oracle. No production
behavior, unsafe block, new syscall, capability allowance, IO child FD policy,
image role or public lifecycle grant changed after9a.

The initially planned same-deployment fixture was corrected BEFORE native run:
HostAuthority deliberately refuses any baseline alias under current deployment,
so retained old Bootstrap resources would block repeat attempts even with new
exit IDs. No barrier or retention rule was weakened. Final fixture has unique
`launchlab-<nonce[:12]>` deployment and matching exact service name. Root added
fixed x86/ARM owner-bootstrap runners and protected nonce creation BEFORE the
new descriptor call. No writer changes to those controller files.

Flags:
- `--owner-bootstrap-descriptor`: strict root0600 existing64lowerhex nonce;
  JSON `{schema_version:1,owner_unit:<exact service>,deployment_id:<launchlab-
  nonce12>,nonce:<same64hex>,guard_role:lifecycle_scope,component_only:true}`.
- `--ignored-owner-bootstrap`: exact-hash owned-guest admission, only newfixture.
- `--ignored-owner-deployment`: restored prior two read/control cases unchanged.

Fixture uses one NEW inert exact4-role-image gateway, network-none/read-only/
cap-dropALL/no-new-privileges/TUN, no enrollment or approved identity. Two
synthetic distinct private seeds remain in memory; no profile/ZIP read, no keys
in argv/output. Two actual Admissions captured BEFORE activation; primary data
is container base, additional data is distinct owned namespace, exact separate
producer cgroups and native veth/WireGuard birth/move. Fresh nonce-owned WAN
namespace/interface with exclusive public-form185.66.x.y /32 routes into owned
local peer; no replace/delete, no provider client or application traffic.

HostAuthority baseline is TEST-LEARNED from controlled guest native observation,
then normally admitted/verified and shared by both actual GuardTransport
activations. This proves native model integration and B-add/A-reaudit at initial
common-parent setup ONLY, not independent production host declaration, hot-add,
remote authority, client isolation or Ready. Both activate paths and A-after-B
full native audit remain unrelaxed.

Overlap oracle: both guards use real scope placement and authenticated RPC.
First writer privately waits before sync; second must be actually queued with
its original seq3/sent_at. Only then release first writer; second's original
frame equality checked again at its checkpoint. Both complete BeginTerminal,
two further fresh Revalidates, and actual EXIT0/reap. Canonical terminal records
must bind exact retained guardPID/start; queue/readwindows/pending empty and
shared journal unfenced. Each mutation completion is logged with its ORIGINAL
sent_at+2 deadline and checked timely.

Final oracle independently reopens protected namespaces.json through retained
directory, checks root0600/regular/nlink1, bounds262144, matches EXACT canonical
bytes, parses/binds both specs and validates both terminalPID/start records.
Final event logs strict_disk_sha256, original frames, durable completion times,
writer releases/order, component_only and false provider/routed acceptance.
Owned namespace pins, links, cgroups, Bootstrap policy, journal and gateway are
retained; no inferred terminal cleanup authority. Fixed-stage diagnostics never
log dynamic response bodies or keys. Native gate NOT_RUN until root results.

## Native93 RED and fixture-only ordering repair

Root ran2ce8639 owner-bootstrap x86. Failed before any Bootstrap case with
`descriptor_policy`: inventory mismatched_fd4, registered=false, directory mode,
CLOEXEC, records directory. Stages showed admit_first then admit_second. Actual
trace: both PinnedProcess Admissions register all own descriptors; NEXT
Domains::verify_owner -> supervision::manager -> inventory::verify encounters
AllocationStore.dir opened/committed before Transaction::open registers the exact
store+transaction directory pair and lease. This was fixture lifetime ordering,
not a missing production FD allowance or failed second container admission.

Repair: defer AllocationStore::open/commit until immediately before
Transaction::open, after both Admissions, strict external-owner verification and
exclusive WAN setup. Add fixed `bootstrap_journal_verify_external_owner` stage.
No extra FD registration, numeric allowance, production change or authority
relaxation. Native93 failure and its protected journal/container/nonce retained
under root control; root verifies actor absence before nonce archival.

Covering ordinary271PASS/0failed/2ignored and strictclippy/fmt PASS again:
bootstrap-workspace3.log, bootstrap-clippy3.log. Next static freeze underway,
bootstrap-static2.log; native GREEN pending. Do not transfer source2ce incomplete
Bootstrap claim or label this completed from compilation.

## Native Bootstrap gate ACCEPTED — ea2f85e (root results)

Final frozen candidate: target/continuation-20261026T204621Z/candidate.json,
sourceea2f85e526a6b44eee0531b37e67aef06389c0c6. Full ordinary271PASS/0failed/
2ignored; strictclippy/fmt/staticboth/BOTHinitstability/source115 PASS.

- Native94 x86 PASS2: both genuine GuardTransport Bootstrap activations and
  A-after-B native audit; authenticated overlapping legal BeginTerminal FIFO
  [1,0], original seq3 sent203266.36751/203266.36873, durable completions
  203266.48911/203266.55270 before ORIGINAL203268.36751/203268.36873 deadlines;
  actual guard68010/start20326621 +68011/start20326625 EXIT0/reap. Independent
  strict protected final disk digest prefixf958629c (full in root artifact).
- Native95 ARM/TCG sameea PASS2: genuine two-Bootstrap/re-audit, FIFO[0,1],
  original seq3 sent31131.924218499/31131.925829077, durable completions
  31132.07106448/31132.184740452 before ORIGINAL2s; guard8891/start3113148 and
  8892/start3113167 actual EXIT0/reap, strictdisk digest prefix7e36e7.
- Independent frozen incremental review PASS, no findings; first two mandatory
  journal concurrency defects and this scoped native gate accepted by root.
  ARM is emulated ABI execution, not physical performance evidence.

No provider/client/Ready/public runtime/retirement proof is implied. Both2s
budgets, original90s watchdog, late-writer lease/drain barriers, protected
records, failed93 resources and public launch refusal remain intact. All nine
areas still require their operational and mandatory acceptance work.

## Next concrete vertical slice — owner-held native host audit

Root authorized implementation after94/95; architecture reviewer read-through
has no fundamental blocker and gave the constraints below. This is the next
actual runtime integration slice, not a replacement for dynamic admission or
all-nine scope.

1. Dedicated ROUTE-only native observer: factor existing bounded
   links/addresses/routes/rules dump primitives into a reusable read observer.
   Do not reuse NativeNetwork::open/observe unchanged: it also opens GENERIC
   and may make WG GET calls carrying raw private keys. Host wire projection
   contains only bounded public metadata and namespace identity, no raw replies,
   profile, caller expected Snapshot/digest, key or Ready permission.
2. Fixed isolated child per host audit, launched by the authoritative parent.
   Close inherited guard/control/network/identity FDs; exact private channel,
   required protected root/pin and ROUTE FD only. Caps0/NNP/seccomp/private chroot;
   no persistent SYS_ADMIN or generic-netlink socket. Dedicated native test must
   prove successful full dumps and prohibited mutation under that EXACT role.
   Opening ROUTE after dropping caps is preferable where it preserves exact
   namespace/chroot provenance; Linux NETLINK mutation checks BOTH opener and
   current sender authority, so preopened socket alone is not a cap bypass.
3. Parent keeps canonical HostAuthority; child returns actual projected native
   observation only. Parent compares against retained model, full allocation/
   selected owner/native host identity and model generation. Never compare in
   a fork-copied Rc model as authority or adopt an observation as a baseline.
   Test-only initial fixture baseline remains explicitly learned controlled-VM
   input, not production installation authority.
4. One zero-argument authenticated HostAudit operation in existing per-guard
   sequence space with journal/progress. Per-member pending native job is polled
   nonblocking; no synchronous netlink/child-read wait in DeploymentOwner loop.
   Original sent_at+2s bounds queue, native actor, projection, transport, decode,
   canonical comparison and ACK. Conservative evidence checked_at is original
   request/launch start, never receipt/comparison time. Retained pidfd and fixed
   job identity bind response; socketpair SO_PEERCRED creator is not child ID.
5. Typed launch integration: private HostAuditReceipt minted only after exact
   original frame ACK (Client can internally return matched Progress); bind
   allocation/exit/lifecycle, conservative checked_at and original expiry.
   Refactor ActiveLinks to expose namespace-only transport/data observation
   separately from host comparison. GuardTransport/ObservationAudit in remote
   transaction mode must request and validate owner receipt, then audit local
   namespaces and unchanged policy; they must not rely on inherited Rc host
   authority. Local component setup retains existing native local host audit.
   Receipt proves host observation only, never Ready or a caller bool bypass.
6. Bound child serialization, IPC total/frame bytes, record counts, string sizes,
   decoder memory and concurrent actors. Initial proposed projection cap128KiB,
   maximum4096 projected records with explicit oversize refusal; actual cap must
   be justified/tested against source parser bounds and native fixture output.
   No blocking whole-snapshot send/read in owner loop; child may wait only under
   original deadline and retained drain. Actor admission must remain bounded,
   fair and permit healthy B beside a stalled A; cancelled child retains its
   capacity/identity until actual reap.
7. Meaningful RED/GREEN tests: unknown/changed allocation, namespace, exit/model
   generation; actual metadata changed versus canonical model; expired/NaN/
   future original times; frame/memory/count/string limits; stale/forged frame;
   no caller snapshot adoption; serialization includes no WG/private fields.
   Native: both genuinely activated Bootstrap guards request owner native audits;
   hold A at private checkpoint beyond its original2s, prove A freeze+drain and
   B fresh successful audits after Aterminal. Inject a retained OWNED host link
   drift, require parent model rejection (not parse failure), retain quarantine
   and exact failed evidence. Capture exact cap/FD/seccomp profile and attempted
   forbidden rtnetlink mutation negative alongside successful dumps.
8. Dynamic add/remove/hot-restart remains separate mandatory continuation:
   owner-authorized exact shapes/indices or equivalent generation-bound native
   transitions BEFORE mutation, explicit allocation coexistence, bounded staged
   placement, original deadlines and healthy-neighbor native gate. Initial2
   Bootstrap parent activation cannot justify a refreshed arbitrary model or
   live add/remove. Following this slice: integrate staged public lifecycle,
   independent3expiry scopes, terminal-safe stop/retirement, then direct/5Mullvad,
   clients/migrations/platform lifecycle, full captures/benchmarks/24h soak.

## FINAL HANDOFF — NEEDS_CONTEXT, source PAUSED at ea2f85e (NOT DONE)

Root explicitly agreed a fresh SOLE writer for the larger connected host IPC /
operational runtime slice. No further functional source changes afterea2f85e;
NO HostAuthority IPC implementation has been started in this context. The next
writer must IMPLEMENT the next slice and remaining approved plan, not re-review
or re-implement the accepted journal fixes. No nested agents; root owns all
privileged/credential-bearing LOCAL operations and independent review. No user
permission stall: scope/plan/local testing are already authorized.

### Exact preserved state and commands

- Worktree /DATA/AppData/vprouter-rust-v2, branch rust/v2; real HEAD remains
  c6a138c00b70163ba3cbfdf350e5cf8e2f3a3c6a. Never reset/clean/discard, alter real
  index/HEAD, publish, access remote installations, or touch Python production.
- Accepted sourceea2f85e526a6b44eee0531b37e67aef06389c0c6 at
  target/continuation-20261026T204621Z/candidate.json. Root tested frozen x86/ARM
  contexts. All115 archived build inputs freshly compared to actual files:
  ZERO mismatches. Evidence target/owner-transactions-evidence/final-source-identity.json.
- Full271 ordinaryPASS/0failed/2ignored; strict workspace/all-target clippy
  -Dwarnings, fmt, static musl x86+ARM/BOTH init-manifest stability PASS.
- Latest exact commands: cargo test --locked --workspace; cargo clippy --locked
  --workspace --all-targets -- -D warnings; cargo fmt --all --check; python3
  target/implementation-20261026-build.py. Logs bootstrap-workspace3.log,
  bootstrap-clippy3.log, bootstrap-static2.log. Builder uses alternate index/ref
  only and currently includes115 files/four image roles. If new module added,
  update/reverify input binding instead of repeating115 uncritically.
- Advance-notify root BEFORE each mutable gateway-context refresh. Root must
  copy both contexts candidate-local before another refresh. Never retest
  mutable contexts while source is being edited.
- Root runner mode owner-bootstrap is now available on Debian x86+ARM:
  target/platform-lab/run-frozen-platform-actual.py <candidate> <platform>
  <label> owner-bootstrap. Root alone executes it. New fixed flags and exact
  descriptor schema are above. Parent creates/fsyncs protected nonce FIRST.
- Native93 failed fixture inventory preserved;94x86/95ARM accepted after exact
  ordering repair. Final review PASS. Native89journal/90deployment/91full90/
  92ARMdeployment belong9a, whose production journal logic is unchanged inea;
  ea additions are only native test harness/accessors. Do not transfer these
  proofs onto a later changed owner loop; rerun affected native gates.
- Retained failed/successful fixtures, inert gateways, namespaces, links,
  producer groups, terminal journals, fixed nonce histories and partial artifacts
  MUST remain until typed native retirement authority exists. No cleanup from
  names/PIDs/terminal reason alone. Never SIGCONT an old guard or stopped writer.

### Code-backed next-slice hazards (read these before editing)

The concrete8-step implementation/test plan immediately above remains active.
Additional scoped architecture review identified the following mandatory
integration points; merely adding HostAudit RPC would be incomplete:

1. `transport.rs:75` ObservationAudit currently holds native host/transport/data,
   enforcement, ActiveLinks and Plan, but NO transaction/spec/remote authority.
   Add a private bound authority/reference capability, not a bool or optional
   fallback that can silently select copied-local authority. Only owner/guard
   gated conversion may mint remote mode. Transaction::fork_remote currently
   returns remote Transaction outside GuardTransport; no production method yet
   converts an entire operational GuardTransport/Handoff to that remote mode.
2. `transport.rs:690` GuardTransport::audit_stage calls ActiveLinks::audit.
   `network/guarded.rs:295..400` ActiveLinks audit, pin_daemon_declared,
   audit_daemon_metadata and audit_daemon_health all reach copied Rc host audit.
   Refactor explicit namespace-only native checks and replace host component in
   authenticated remote mode with owner receipt. Keep namespace/producer/WG/
   policy checks. Cover ObservationAudit pin, pin_operational, verify, structural,
   apply_health and ready_publication, not just GuardTransport::audit.
3. `transport.rs:184..194` ReadyPublication currently expires at
   min(executor_lease_expiry, now+2). Once remote host audit exists, it MUST also
   be <= ORIGINAL HostAuditReceipt.expires_at. Recheck receipt after local
   transport/data/WG/policy work and before/after Ready enforcement. A fresh
   now+2 must not rejuvenate owner evidence.
4. `handoff.rs:889..894` Structure saves full-process check start then overwrites
   evidence.checked_at. New behavior must preserve MIN(existing native/host
   receipt anchor, full-process check start), never overwrite earlier host
   evidence with a later start. Keep original 2s frame and6s publication budget.
5. `handoff.rs:970..1000` creates local ReadyPublication then publisher.submit_ready;
   publisher completion loop currently no longer retains that proof.
   `publisher.rs:104..151` submit_ready checks proof only around submit;
   poll checks publisher's pending deadline only. Carry host proof/expiry through
   publication completion, Commit, and `operational_reply` (~1033) final ACK,
   including after pending is consumed. Parent compare/ACK must also be checked
   after decode/comparison, never only before expensive work.
6. Network native.rs:124 opens BOTH ROUTE and GENERIC; observe:301 may issue
   secret-bearing WG GET. Dedicated host observer must be ROUTE-only. Existing
   metadata projection uses exactly links/addresses/routes/rules; each dump
   method is native.rs:198..264 and only needs the route Socket, making exact
   factoring/reuse possible. socket::deadline currently5s: child/parent's
   original BOOTTIME2s remains authoritative; do not relax product deadline.
7. Reuse ALL project.rs Link/Address/Route/Rule fields. Preserve optional absence
   and multiplicities: Link tun_info/alternate_names/controller/port_kind/
   promiscuity/all_multicast/optional pacing/headroom/tailroom; Address flags,
   broadcast, route_priority; Route flags/protocol/metric/nexthop_id/preference/
   source/gateway; every Rule option. guarded::exact compares those vectors
   completely and intentionally omits only Snapshot.wireguard. No reduced schema.
8. `audit.rs:180` same<T> has O(n^2) fallback for reordered records. Bringing up
   to4096 records into owner-loop comparison needs bounded comparison strategy
   (preserve exact multiplicity) or measured worst-case phase budget. Byte/count
   caps alone do not prove healthy-neighbor polling latency. Canonical model
   changes during audit require explicit generation/authorized transition,
   never adopting refreshed actual host state. Full dynamic preauthorization is
   separate from initial2member fixture but cannot be waived in public runtime.
9. Child isolation must close all inherited guard/owner/control/network FDs
   before fixed native observation, retain exact private channel/root/required
   namespace authority, caps0/NNP/seccomp/chroot, no generic socket. Opening
   ROUTE before drop can preserve native namespace provenance then chroot;
   kernel requires BOTH opener and CURRENT sender capability for mutation, but
   exact-profile native mutation-negative is mandatory. Prefer open-after-drop
   where it does not break pinned namespace/chroot verification; no need to
   redesign solely from a disproved opener-credential bypass speculation.
10. Cap/FD and forbidden-mutation native proof must accompany positive complete
    dumps. Host drift test must mutate a retained owned native host resource and
    fail at PARENT canonical comparison, not just child parsing. Hold A's fixed
    host actor beyond original2s and prove B fresh owner audits afterward. No
    synchronous netlink/IPC wait in shared poll loop. Retain cancelled actor and
    its bounded capacity until actual child death/drain; no unlimited spawn.

### Exact current security/resource inventory

Journal writer/reader remains fixed private child: root-confined retained journal
root, caps0/NNP/seccomp, FD0..2 null, FD3 private seqpacket, FD4 directory, FD5 exact
inherited OFD allocation lease, temporary fileFD6. No new cap/syscall allowance
or subprocess type in accepted fix. ACK is exact33bytes:128+observedSHA256,
accepted only after exact childEXIT0 and reaping. Existing private checkpoint
can release a merely waiting child with byte1; stopped fault actors are NEVER
resumed. Allocation lease persists until actual actor death, not owner tx drop.

Parent owns canonical journal, single pending candidate and uncertain fence.
Per-member FIFO holds original immutable request while ExternalOwner holds its
original Progress sequence/sent_at. Limit256 queue entries; actual configuration
currently max128 exits. Per-active-read accepted canonical generation window
max64 exactSHA256 values, max256 windows (512KiB digest payload plus bounded hash
container overhead); no full-record history. Only owner-created current/pending
legal records add digests; shared+selected authority checked and completion must
still match current/pending selected authority. Saturation backpressures writers
under original2s; unrelated reads/watchdogs still run. Every uncertain writer
keeps pending/fence/lease and cannot admit another mutation even after drain.

Guard/owner native test roles still hold setup authority. Accepted journal child
confinement and worker-monitor profiles are NOT public steady-runtime cap proof.
No actual HostAudit child or receipt exists yet. No operational provider/client
results or dynamic model transitions were implemented in this context.

### All-nine continuation state (no scope reduction)

1 Secret lifetime: prior zeroization work retained; whole-branch final review due.
2 Health contract: prior authenticated wire/cache bridge retained; actual enrolled
  operational proof and new host-receipt timestamp propagation still required.
3 Shared host authority: initial common-parent two-member native model/activation
  now proven; owner IPC/native comparison and dynamic transitions NOT implemented.
4 Runtime: journal concurrency/native legal writes fixed; public launch refused.
  Actual staged start/stop, persistent host pins, owner-compatible guard/3expiry
  scopes, original deadlines, steady caps, safe terminal retirement, five
  independent Mullvad + explicit direct remain incomplete.
5 Clients: persistent kernel/userspace no-WAN/DNS/IPv6/proxy-fallback enforcement
  and real clients remain incomplete.
6 Migration: two independently enrolled LOCAL legacy identity-preserving actual
  release/state apply/rollback/interruption cases remain incomplete.
7 Services/platforms: x86/ARM/systemd component proofs exist; runit, install/boot/
  update/rollback/uninstall and production lifecycle not complete. Root saved
  fresh readonly Void reference at runit-native-reference-20261026T2050.json:
  PID1 runit/start24, runsvdir644/start446, dockerd670/start448 under runsv657;
  supervisors cgroup0::/, rootcgroup0555root not0755, eight controllers/subtree
  enabled, /var/service/docker -> root0755/etc/sv/docker. Reverify later; not
  product runit support and not a systemd-style Docker cgroup assumption.
8 Hostile acceptance: scoped journal/native Bootstrap gate accepted; full real
  client4-configuration captures/fault/restart/reboot matrix still required.
9 Performance/soak: repeated10min1/5/6 whole Python/Rust CPU/PSS/throughput/p95 and
  TRUE24h mixed soak remain incomplete. Never mark these DONE from component
  PASS or NOT_RUN rows. Final fresh whole-branch independent verification remains
  after actual implementation/testing, not this scoped foundation review.

Fresh writer first read owner-transactions-brief.md, constraints.md, approved
implementation plan, IMPLEMENTATION.md, this FINAL handoff and next host brief
from root. Preserve accepted9a/ea evidence and failed93; start concrete native
owner-audit slice, then continue all-nine. Source ownership transfers ONLY after
this writer's final NEEDS_CONTEXT response; no concurrent source writer.
