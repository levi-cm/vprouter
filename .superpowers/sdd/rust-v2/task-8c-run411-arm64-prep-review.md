# Task 8c run 411 ARM64 preparation — independent review

2026-11-06. Repository `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`,
HEAD `9f997dd960876619bc57d1910a2d532d224d2498`. Reviewed the uncommitted 411
preparation, restored/archive copies, frozen candidate, retained preparation
receipts and current ARM guest. The concurrently owned witness-validator files
listed in the review brief were excluded from inspection and execution.

**Verdict: FAIL. Execution decision: NO-GO.**

Important I1 violates the requested isolation boundary: the new path guards
exclude 410 but admit 409, and the collector can actually read/copy a poisoned
409 reference before rejecting its bindings. Important G1 is the separate,
already-documented Root checkpoint/publication prerequisite. Neither is cleared
by a successful preflight. No deterministic failure in the *currently bound*
post-claim command was identified; that narrower conclusion does not clear I1,
G1, or qualify ARM Bootstrap timing.

**Run 411 NOT_RUN, budget 1. Runs 409 and 410 remain consumed, budget 0.** No real
claim, raw record, controller-error receipt or `bootstrap411-arm64/` output was
created. No reservation was created or superseded. This review started no
subagents and performed no guest mutation, QEMU command/lifecycle action,
old-disk boot, host sudo, rebuild, staging, commit or push. The only repository
write is this report; scripts, compiled bytecode, synthetic state and logs are
under `/tmp/vprouter-run411-review/`. The cold `/DATA/vprouter-lab/preserved/`
tree was not opened, traversed or rehashed.

## Findings

### Critical

None demonstrated. The current claim/save protocol remains exclusive and
forward-only; no double execution or old raw overwrite was observed or enabled
by any check performed here.

### Important I1 — Run 409 is missing from the promised isolation guards

Locations: `tools/rust-v2-lab/run411-reservation.py:30`, `:49`, `:57`;
`tools/rust-v2-lab/collect-run411-evidence.py:40`, `:60`, `:70`, `:76`.
Related pre-admission reference reads also occur at
`tools/rust-v2-lab/target/platform-lab/run-frozen-secret-bootstrap411.py:41`.

`allowed_path()` and collector `capture()` reject only components containing
`run-410` / `actual-program-run-410`. They accept
`target/lab-state/run-409-consumed.json`, other 409 records, and paths beneath
the preserved tree. Collector reference capture precedes reservation/provenance
validation. Consequently, rejecting an invalid binding later does not prevent
the forbidden read and copy.

Independent reproduction, entirely in temporary synthetic state:
`/tmp/vprouter-run411-review/isolation-probe.py` and
`isolation-probe-result.json`. The real 411 helper successfully created, hashed
and parsed a synthetic `run-409-consumed.json`. Adding that path to a synthetic
411 reservation's bindings caused the real collector to retain its bytes in
`files/target/lab-state/run-409-consumed.json`; only afterward did collection
return 1 for invalid bindings. No real 409/410 state was used by this probe.

Concrete failure scenario: a copied/wrong 409 reference in a 411 binding,
supersession receipt or recursive baseline reference causes C to open and copy
prior evidence into the 411 bundle before the chain rejects it. The helper's
exclusive `save()` also permits creating an absent 409 state pathname. Existing
raw files remain protected by O_EXCL; this finding does **not** assert an
existing 409 claim/raw can be overwritten or that the current valid reservation
actually references it. It does disprove the requested unconditional old-chain
I/O isolation and the completeness of the isolation tests.

Required disposition: enforce the 409/410/preserved-state boundary before every
reference/state open, including the pre-validation capture/read paths. Preserve
the explicit exception for the frozen run410 **candidate** payload/context/source;
that is distinct from either old run's claim, reservation, raw and evidence
chain. Add synthetic negative cases for both old runs and preserved-tree/alias
paths. Keep current raw-first preservation for admitted 411 inputs. This review
makes no implementation change. Any repair to bound bytes requires the existing
unspent forward-only supersession procedure, retaining the old generation and
tombstone; never reset a claim or edit the old chains.

### Important G1 — Reviewed preparation has not passed the Root publication gate

Requirement: `.superpowers/sdd/rust-v2/task-8c-lab-rebuild-assessment.md:86`,
`:125`; `.superpowers/sdd/rust-v2/task-8c-driver-cost-brief.md:154`; the same gate
was enforced at `.superpowers/sdd/rust-v2/task-8c-run410-prep-review.md:39`.
The assessment says, “Checkpoint/push/remote confirmation is required by the
historical Root workflow.”

Observed: HEAD is 9f997dd, while the maintained 411 changes remain modified and
the 411 controller/helper/test/archive sources remain untracked. HEAD therefore
does not checkpoint these execution and post-run bytes. Current remote
confirmation was NOT_RUN in this review. The existing reservation explicitly
sets `execution_authorized_by_this_phase=false`.

Concrete failure scenario: invoking the report's execution argv now consumes
the only attempt with controller/post-run preparation that has not cleared the
required publication checkpoint. Preflight enforces hashes and budget, not this
external workflow gate.

Required disposition: Root completes the scoped checkpoint, push and remote
confirmation after I1 is repaired/reviewed and the reservation is coherently
rebound. Revalidate current identity, selector absence, bound bytes and unspent
state before any separately authorized execution. This is an existing gate,
not a new request for user confirmation or permission to execute from this review.

### Minor M1 — Supplied smoke checksum manifest includes an invalid self-checksum

Location: `/DATA/vprouter-lab/arm64-prep/SHA256SUMS:5`.
The line for `SHA256SUMS` records
`773c4c9c808dc80b4d1005aa7a8917043696b69383d45b62d87b55791adfc882`,
but the current file hashes to
`737a5fc4a302102d0b287316f45e44def752f581503cbcb57ff98e08f29330e1`.
An ordinary full checksum verification therefore fails. All six actual smoke,
bisect and harness files match their entries, including the full-sandbox PASS
serial. This is a supplied-evidence packaging defect, not evidence of a changed
guest, base image or payload, and is not an additional execution blocker.
Preserve this manifest and, if correcting the packaging, add a separately named
manifest excluding itself rather than rewriting the supplied evidence.

## 1. Isolation, reservation and preservation

**Current valid-path observations PASS; unconditional isolation FAIL (I1).**
The audited exact preflight opened no 409/410 state or preserved evidence and
launched no SSH/SCP. Its sole write-capable open was the already-existing 411
lock. Its only subprocess was the read-only frozen-source verifier. These audit
observations establish the current path, not the stronger guard claim disproved
by the synthetic probe.

The fixed tuple is run 411 / `debian-arm64` / `bootstrap411-arm64` / `success` /
`target/candidates/run410-da75562-20261104/candidate.json`. All 35 mandatory
bindings match. Active reservation SHA256:
`2c076f625c15516c31daa6ff14a2985d6906631ab2cba5f553f26875473ee62d`.

There is exactly one supersession, retaining generation
`cb95853c3001e8a6e2c3da424bb1b97aa7938ce4d0b383335a77a253c097ae42`.
Its retained bytes and tombstone hashes validate. Comparing generations shows
only the high-water correction 409→410, supersedes/time metadata and the hash
of `run411-reservation.py` changed. That helper's current code consistently
requires/emits high-water 410. The stated reason is valid: advance metadata past
consumed 410 without binding/reading either old claim. Both generations retain
one-shot budget 1; the one global 411 claim is absent. This is a forward-only
preparation correction, not a reset or an additional execution allowance.

Independently rehashed the implementer's 17 snapshotted old state/candidate
inputs; all match its entry hashes. Both old consumed claims still say budget
0. Reviewer entry/final comparisons additionally cover 668 source/state/candidate
files, including old claims/raw/reservations, current reservation generations,
ARM inputs and pin/process bytes; none changed. HEAD and index bytes are
unchanged. No claim of a fresh full cold-preservation audit is made: the cold
preserved tree was deliberately not accessed, and no 411 executable path inspected
has a legitimate need to access it.

## 2. Fresh ARM guest, provisioning and SSH trust

**PASS at inspection; launcher was reviewed, not invoked.**
`start-clean-debian-arm64.py:32` validates a 411 instance, refuses any existing
state including dangling symlinks, takes the lifecycle lock, rejects live
qemu-system processes and an occupied port, verifies the fixed image SHA512,
and creates a new overlay, seed and private VARS. The base is only a backing
image; CODE and seed attachments are read-only. A simultaneous state-directory
creator would fail the exclusive mkdir rather than reuse it. The lock is held
through launch. No existing overlay/seed/instance is reused.

The base was independently hashed in this review, matching the pinned manifest
and fixed value:
`e66eea33be9e1345e6c8737e65096e5b31031f4bd4f3f7d59a6f8b53f995a9c41996e97c5b4ab89f1587663efed11dfbd10c4d35b7bcc85b2545e58a12cd0e83`.
Both staged Debian packages match staging-record SHA256/lengths. The staged
QEMU/AAVMF files also match their recorded hashes. QEMU version evidence is
10.0.13 (Debian 1:10.0.13+ds-0+deb13u1), not a newly executed version command.

Recorded argv equals the launcher's actual generated argv: TCG multi-thread,
virt/gic3, cortex-a72, 2 CPUs, 1024 MiB; full
`on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny` sandbox;
user netdev with loopback 22034 forwarding and virtio-net-pci. The supplied
bisect/serial evidence supports this full-sandbox/user-net combination; the
`-nic none` halt was not repeated. Minor M1 concerns only checksum packaging.

Current `/proc` checks find exactly one QEMU, PID **493434**, start tick
**5902200**, identical full argv, controller boot
`07dbae6e-6ed8-4bb3-a468-f89265c8dd6b`. Its open base-image FD is read-only;
open lab disk/firmware paths contain no old guest or preserved overlay. This
review used `/proc`, not QMP or any QEMU command.

Strict read-only SSH confirms guest boot
**525e9103-b2f9-4611-a663-ced9d001245a**, machine ID
`f02b6d586b1a4a89969d2dcb038cb8a6`, ARM64, protected marker/root/parents,
cgroup2, systemd Docker driver, active Docker, zero containers, absent fixed
selectors and successful direct clock_gettime syscall113 for clocks3/7.
Docker reports AppArmor plus builtin seccomp, AppArmor is enabled, and packaged
WireGuard/nf_tables modules exist. Loading modules, creating namespaces/mounts,
starting a container or testing native role confinement remains NOT_RUN.

The requested command was independently rerun:

```sh
python3 -B tools/rust-v2-lab/phase3-readonly-preflight.py \
  /tmp/vprouter-run411-review/guest-gates.json --platform debian-arm64 \
  --expected-boot-id 525e9103-b2f9-4611-a663-ced9d001245a
```

Exit 0. The ARM gate truthfully reports `pinned_images_inspected=false`; it
checks a FROM-scratch/offline-inventory route, not registry-image admission.

Console trust was checked against the retained serial snapshot: exactly one
ed25519 key inside cloud-init's host-key block, snapshot SHA, recorded launch
process and exact known_hosts line all match. Pin SHA256:
`bf37ae607c4ff4e5f3de2a4ef2244e8e7dea3919448b22a12cc6690c399200d1`.
No network keyscan/TOFU or trust-file rewrite was performed.

Fresh `ssh -G` verification covers nine actual constructors: prep, baseline,
phase3, inspector, runner, both F/A and both SCP variants translated to SSH
option form. Every site has `-F /dev/null`, GlobalKnownHostsFile=/dev/null,
IdentitiesOnly=yes, IdentityAgent=none, the sole dedicated identity, the single
ARM pin, StrictHostKeyChecking=yes, loopback/22034 and no proxy route. The live
SSH reads prove actual connectivity; SCP configuration proof and the retained
synthetic transfer measurements remain distinct from a new actual transfer.

## 3. Frozen candidate and fresh baseline

**PASS. No rebuild or frozen artifact execution by this review.**

| Input | Independently verified SHA256 |
| --- | --- |
| Candidate JSON | `ea3634b4e4140b3b3db8fdaf12b9c47c1b3757c9862f33001cbc022ef2d225f6` |
| Frozen source | `899dd5c843f6af2d86305e0380ca79006570de874d9356b725f24e91b09d8959` |
| ARM64 payload, 15,235,840 bytes | `5b78458c995556227417cb7939e13cc811dba3ad8dbcdfdd342404df84e09631` |
| ARM64 context, 49,377,280 bytes | `51023de0b7bbab71a40e1882662d50327d8643f1f45051c466655207666f406d` |

Frozen source commit is da75562, distinct from today's checkout HEAD.
The verifier checks all203 frozen application inputs. The payload is ELF64
little-endian machine **183**, with load segments and no interpreter/dynamic
segments. The strict context checker independently verifies all seven files,
four program roles/static ARM ELFs, deterministic Dockerfile/tar metadata,
pinned Tailscale platform/daemon, CA and exact program manifest. Its result
matches `inventory-arm64.json`. Reservation and provenance bind both ARM inputs
and inventory; no newly built payload is substituted.

Independent RTM_GET evidence, authored baseline, projection custody/deadline
validation and exact full multisets all pass. Retained command chronology shows
collection and authoring before the separate frozen projection; authoring code
refuses an already-existing platform projection directory. A new read-only
RTM_GET dump collected during this review also matches every field and
multiplicity: **3 links / 6 addresses / 19 routes / 5 rules**. Baseline SHA256:
`6ea00a3760011e1af3d4c64484e19ce425591da983e6825460d7e1e0075a599b`.
Fresh/historical-authority labels remain truthful and false where required.

Correction to the question's possible NIC assumption: the ARM WAN **name**
is `enp0s1` versus x86 `ens2`; the observed index **2** and MAC
**52:54:00:12:34:56** are the same on these two QEMU guests. Their shared numeric
init namespace tuple `[4,4026531840]` also does not establish continuity across
VMs. Boot/process/instance identities distinguish the fresh guest. The ARM
records contain the actual ARM name rather than copied x86 labels.

The x86 preflight remote program is byte-identical to HEAD's original REMOTE.
The baseline's default x86 platform, port, WAN mapping, dump decoder and
multiset logic remain intact. All four 410 suites and shared baseline/phase3
suites pass again offline; no old x86 guest was booted/contacted.

## 4. Exact execution path, one-shot and pre-claim compilation

Exact execution argv reviewed, **NOT executed**:

```sh
python3 -B target/platform-lab/run-frozen-secret-bootstrap411.py \
  target/candidates/run410-da75562-20261104/candidate.json debian-arm64 \
  bootstrap411-arm64 success --reservation target/lab-state/run-411-reservation.json
```

That exact argv plus final `--preflight-only` exits0 with compile PASS for
`baseline-declaration`, `guest`, `host-declaration`, `listing`, budget1 and
`guest_actions_executed=false`. The independently audited preflight rejects
old-chain opens, any SSH/SCP subprocess and any write-capable open except the
existing lock; it also passes. In source, both preflight paths return before
output creation, listing, transfers or guest execution, and skip the only
`save(CLAIM,...)` site (`run411-reservation.py:185`).

The lock is held through admission/execution; O_EXCL/O_NOFOLLOW claim and raw
creation plus fsync provide the one global consumed marker. Output/raw/claim
collisions, dangling names, stale supersession generations, spent claims,
interrupted supersessions and second attempts refuse. Failure/interruption
never grants another attempt. Compile failure in each of the four exact remote
programs is tested in both modes before claim. Boot prefixes and the embedded
builders are included in the strings actually compiled/reused.

| Step after claim | Code and independently checked implication |
| --- | --- |
| Exclusive output/snapshots | Runner `:73` creates a new output directory and seven source/input snapshots. Parent is owned/writable; output absent. Collision is still an unretryable controller error, not a new claim allowance. |
| First listing | Runner `:77` / `:79`; exact boot-prefixed listing ran read-only against current guest and returned `[]`. Root/mode checks pass; it lists only numeric task directories, not gateway-init artifacts. |
| Payload/context SCP | Runner `:81` / `:82`; fixed ARM hashes, strict22034 pin and home destination. Current home is owned by lab UID, writable, upload names absent, SFTP server present, about22.25GB guest space available. Real transfers NOT_RUN by reviewer. |
| Guest admission/snapshot | Guest `:5` through `:68`; the actual guest program's read-only prefix (using an unused empty CONFIG) ran successfully: parent/root/marker, selector absence and all stable iproute2 snapshots. Boot prefix uses admitted boot. |
| Upload verification/build | Guest `:69`–`:93`; exact payload/context hashes, worker member/size/hash, protected destinations, FROM-scratch build, image ID/entrypoint/manifest checks. Local strict context inspection finds no deterministic mismatch. Writes/build remain NOT_RUN. |
| Synthetic inputs/descriptor | Guest `:94`–`:124`; nonce-derived inputs and fixed selectors, two external synthetic keys/profiles, descriptor-only payload interface. Frozen source contains the exact interface/Bootstrap flag. `wg` and required host tools exist. Native descriptor execution remains NOT_RUN. |
| Authored host/baseline | Guest `:125`–`:147`; actual builder maps ARM to enp0s1/index2/MAC, full projection multiset comparison precedes staging. New independent live dump matches the full authored baseline. Future payload projection/staging NOT_RUN. |
| Gateway/owner/Bootstrap | Guest `:149`–`:178`; no pre-existing containers/owner units, AppArmor/builtin seccomp/cgroup2 prerequisites present. Inert gateway, pidfd/start/netns, owner service and native operation remain NOT_RUN. |
| Raw creation | Runner `:84`–`:99`; guest normal/nonzero/SSH255 and timeout124 are converted to an exclusive fsynced raw411 before stdout parsing/summary/final listing. |
| Other failures | Runner `:113`–`:117`; initial listing, transfer, spawn, output and raw-collision failures preserve an exclusive controller-error receipt with budget0. Final listing failure happens after durable raw. Transport/host failures remain possible. |

An independent harness executes the actual post-claim controller AST with all
SSH/SCP intercepted and all output paths confined to scratch. **11 scenarios
pass**: success, guest nonzero, SSH255, guest timeout, first listing, each SCP,
guest spawn, final listing, raw collision and output collision. It checks exact
program hashes, strict SSH/SCP argv, timeout values, raw/error outcomes and raw
collision preservation. It never calls real admission/claim or a guest subprocess.
This supplements compilation; it does not simulate native Bootstrap correctness.

## 5. TCG budgets and frozen product deadlines

**Lab overhead measurements are credible; native two-second fit is unqualified
and carries substantial risk. No demonstrated deterministic timeout overflow.**
Measurement receipts/reference hashes and the benchmark source were checked;
no benchmark or mutating probe was repeated. The source retains all stated lab
budgets. Uploads finish before the separate guest250s timer starts.

| Path | Frozen/current budget | Retained measured scope |
| --- | ---: | --- |
| Payload SCP | 30s | Exact-size public synthetic15,235,840 bytes:1.751225s |
| Context SCP | 45s | Exact-size public synthetic49,377,280 bytes:2.331300s |
| Guest controller | 250s | Aggregate actual path NOT_RUN |
| FROM-scratch fixture build | 75s | Two cold synthetic48MiB builds:17.137s /19.787s |
| Owner systemd launcher | 120s | `/bin/true` startup/collection only:0.158–0.313s |
| Owner service RuntimeMaxSec | 110s | Actual owner/native duration NOT_RUN |
| Python startup | Within guest250s | Three samples:0.073–0.091s |
| Frozen read-only projection | Its original2s validation | Child span0.127042s; internal GET interval0.086322s |

The build sample has useful headroom but different content and only two samples;
compression/cache/IO behavior is not an exact frozen-context qualification.
75s build plus120s launcher is195s, leaving55s for the other guest work **if
those maxima are approached**; the other bounded subprocess calls and fsyncs
are not an aggregate worst-case proof. The110s owner service can expire before
the120s outer launcher. The broad250s budget cannot extend any product window.

Frozen source confirms each Bootstrap scope inherits the original query's
`requested_at + 2` deadline; query acquisition, retained custody/pin checks,
policy intent, birth/result and final process verification share that clock.
See frozen `crates/vprouter-launch/src/attachment.rs:999`,
`attachment/operational/bootstrap.rs:224`, `:352`, `:484`,
`owned/preparation/bootstrap.rs:85`. The pre-Bootstrap handoff also traverses
host-addition and its earlier fixed windows. The driver adds existing1ms sleeps
while pending and does not restart the deadline (`bootstrap.rs:867`). No frozen
payload/context/deadline was changed by this preparation.

For context only, independently reading the preserved *current lab-state*
raw410 gives final scope-process verification spans1.229125s(host),0.666021s
(transport),0.716202s(data) within their2s windows; host headroom was only0.770875s
on x86/KVM. These historical values are neither ARM samples nor a valid slowdown
conversion. They show why a0.313s `/bin/true` launcher or0.086s GET cannot prove
that repeated custody/history/JSON/hash/process/IPC work under TCG will fit.
TCG can plausibly complete short operations, and the measured GET does fit;
there is insufficient evidence to qualify the complete native windows. A Deadline
failure, potentially before Bootstrap scopes begin, is a credible outcome even
with every lab timeout ample. This is an honest residual experimental risk,
not a request to run Bootstrap early, repeat411, increase its budget or alter
product deadlines. Do not label timing acceptance PASS.

## 6. Collector, inspector, F/A, archive and optimization guards

**PASS for current-bound behavior, subject to I1's I/O boundary defect.**
C is local-only, retains raw/error/output/bindings and immutable generations
before validation, preserves recursive/absolute helper references and reports
preservation separately from witness/runtime acceptance. Its malformed-input
old-reference capture is the specific exception documented in I1.

I requires a consumed411 claim and fresh provenance before strict SSH; absent
owner/gateway identities remain unavailable, not fabricated. Timeout/spawn
errors retain exclusive diagnostic receipts. F/A require explicit run411 before
opening raw records, force the fresh route independently of a removable marker,
require the canonical411 reservation path, compile their remote programs and
prefix the expected boot. A retains original owner absence, gateway
PID/start/StartedAt/pidfd/netns and exact selector inode/hash/mode guards. Actual
C/I/F/A and archival were not run. Failure-only F/A are not generic substitutes
for early/no-raw or successful outcomes; C→I remains the first post-run sequence,
with further failure/archive action conditional on its original evidence/review.

All **300 manifest/restored/archive triples** match hash, size and bytes.
**632 Python source paths** compile via py_compile to scratch; concurrent witness
paths are excluded, explaining the narrower count than the implementer's634.
All **30 optimized-Python probes** (10 runtime entrypoints × -O/-OO/environment)
refuse with `optimized_python_refused` before state or subprocess work.
All **284 entries** in the preparation evidence's own SHA256SUMS match. Its
symlink and `/DATA/vprouter-lab/run411-prep/` are one dataset, not independent
replicas. The supplied smoke manifest's separate self-entry failure is M1.

## Verification ledger

Commands used `python3 -B` with bytecode disabled for imports and temporary
files confined to reviewer scratch. `record.py LABEL COMMAND...` captures exact
argv, UTC, exit code, wall duration and full stdout/stderr as separate files.

| Check / scratch receipt label | Verified result |
| --- | --- |
| `test-run411-launcher`, `test-run411-arm64-baseline` | exit0;4 +2 tests |
| `test-run411-reservation`, `test-run411-provenance`, `test-run411-isolation`, `test-run411-fixes` | exit0;12 checks,21 tests,41 tests,8 groups; tests do not cover I1 |
| `test-run410-reservation`, `test-run410-provenance`, `test-run410-isolation`, `test-run410-fixes` | exit0;12 checks,21 tests,21 tests,8 groups |
| `test-fresh-baseline`, `test-phase3-fixes`, `test-phase3b-provenance` | exit0;5 tests,8 groups,21 tests |
| `live-gates` / `guest-gates.json` | exit0; requested ARM preflight with explicit expected boot |
| `live-trace-corrected`, `live-summary.json`, `guest-extra.json` | exit0; current process/boot, strict SSH, actual read-only guest prefix/listing, independent full live baseline, tools/home/disk/security prerequisites |
| `exact-preflight` | exit0; four exact remote programs, no guest actions, budget1 |
| `audited-preflight` | exit0; current path opens no old chains, no SSH/SCP, no claim/raw/output writes |
| `ssh-G`, `ssh-G.json` | exit0; nine strict confined constructors, no connections |
| `postclaim`, `postclaim-outcomes.json` | exit0;11 intercepted actual-controller scenarios, no real claim or guest subprocess |
| `isolation-probe`, `isolation-probe-result.json` | exit0 means defect reproduced: synthetic409 captured before rejection |
| `static-audit-final`, `static-summary.json`, `optimized.json` | exit0;300 triples,632 compilations,30 optimized refusals,35 bindings,17 protected historical inputs, one supersession, candidate/ARM inventory, base SHA512, package/staged-file hashes, console pin |
| `prep-evidence-checksums.json` | 284/284 preparation evidence rows match |
| Smoke checksums | six evidence files match; supplied manifest self-entry FAIL (M1) |
| `historical410-scope-timing.json` | existing raw410 SHA verified; contextual x86 window spans extracted read-only; no ARM inference |
| `final-preservation.json` | 668 snapshotted files unchanged, HEAD/index unchanged, same QEMU PID/start/argv, 411 claim/raw/error/output absent |
| Scoped `git diff --check` | exit0 for maintained411 diff |

Reviewer harness failures are retained and are distinguished from preparation
defects: initial setup assumed `.git` was a directory instead of using
`git rev-parse --git-path index`; initial live FD comparison used the symlink
spelling instead of the resolved base path; initial supersession comparison
omitted the expected rebound reservation-helper hash. Corrected checks pass.
A subsequent full smoke-manifest check exposed M1; the final static audit
explicitly excludes that defective self-entry and checks all six real files.
No failed run was relabeled or evidence deleted. Literal-substitution
SyntaxWarnings from existing synthetic F/A cases remain in test stderr; all
programs compile and the tests pass.

NOT_RUN: actual411/Bootstrap/claim, any reservation creation/supersession,
actual uploads, exact frozen-context Docker build/gateway/owner/native custody
and two-second runtime qualification, actual post-run C/I/P/F/A, full typed ARM
witness acceptance, driver CPU/sleep/constructor runtime measurements, historical
lost-record replay, old guest boot/cold-tree rehash, provider/production/client/
migration/performance/soak/release acceptance, Root checkpoint/push/remote
confirmation. Guest readings are point-in-time observations, not soak evidence.

**Final disposition: repair/review I1, preserve/rebind the unspent generation,
and complete G1 before considering a separately authorized run. 411 remains
NOT_RUN/budget1; old409/410 remain budget0; `release_ready=false`.**
