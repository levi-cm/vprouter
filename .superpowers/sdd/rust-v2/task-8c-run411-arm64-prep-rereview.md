# Task 8c run 411 ARM64 preparation — independent re-review

2026-11-06. Repository `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`,
HEAD `9f997dd960876619bc57d1910a2d532d224d2498`. Reviewed the uncommitted scope
specified in the first preparation review and the implementer's Review round 1.
The five concurrently owned witness files named in the brief were excluded
from source inspection, compilation, tests and preservation snapshots.

**Verdict: FAIL. Technical execution decision: NO-GO.**

The original poisoned-binding collector reproduction is repaired. The shared
guard also passes independent alias and immediate-open inode-swap probes across
all seven 411 tools. However, **Important I1 remains partially open**: the runner
passes previously checked filenames to downstream consumers that reopen them
without the guard. Eighteen independent scratch cases read synthetic 409/410
evidence through replaced source/context filenames before rejecting it.

**G1 is separate:** scoped checkpoint/push/remote confirmation remains the
controller's gate after an eventual technical GO. This re-review neither
performs that gate nor treats its current incompleteness as a new technical
finding. I1 independently requires NO-GO even if G1 were complete.

**Run 411 remains NOT_RUN, budget 1. Runs 409/410 remain consumed, budget 0.**
No real reservation was created, consumed or superseded. No real claim, raw,
controller-error or `bootstrap411-arm64/` output was created. This review made
no guest mutation, QEMU command/QMP/lifecycle action, old-disk boot, host sudo,
staging, commit or push, and started no subagents. Guest sudo was used only
inside strict SSH for the requested read-only checks. All synthetic documents,
alias changes and instrumented executions were confined to
`/tmp/vprouter-run411-review2/`; the only repository write is this report.
The cold preserved tree was not opened or traversed.

## Findings

### Critical

None demonstrated. The checks found no double-execution allowance, reset of
the real claim, overwrite of old raw evidence, or newly authorized retry.

### Important I1 — downstream filename reopens bypass the repaired guard

Locations:

- `tools/rust-v2-lab/target/platform-lab/run-frozen-secret-bootstrap411.py:44`
  and `:50`, byte-identical to the restored runner at
  `target/platform-lab/run-frozen-secret-bootstrap411.py:44` and `:50`.
- Transitive consumers: `tools/verify-frozen-build-inputs.py:20` and `:34`;
  `tools/rust-v2-lab/target/platform-lab/attachment_context_check.py:10` and
  `:57`, identical to `target/platform-lab/attachment_context_check.py`.
- Guard lifetime: `tools/rust-v2-lab/run411-reservation.py:98`–`:109` protects
  an individual open; it cannot protect a later ordinary pathname reopen.

The runner hashes source/artifact with `path_guard.read_bytes()` at line 31,
uses a guarded source stream at line 32, and hashes the context with the guard
at line 49. These are real improvements. But line 44 gives the source pathname
to a separate verifier, whose `tarfile.open(archive)` and `archive.read_bytes()`
perform ordinary opens. Line 50 gives source/context pathnames to
`context_check()`, whose two `tarfile.open(path)` calls also bypass the guard.
Neither consumer retains the previously checked input descriptor or bytes.

Concrete reproduced scenario: after the valid guarded hash/read, replace the
admitted `source.tar` or `arm64.context.tar` name with a symlink or hardlink to
a synthetic `target/lab-state/actual-program-run-409.json` (and separately 410).
The next ordinary tar open follows that alias and reads the old-evidence
sentinel. Renaming the synthetic old inode onto the admitted name has the same
result. An invalid tar is eventually rejected, but that happens after the
forbidden read. This violates the requested BEFORE-read/copy boundary.

Independent proofs, all using scratch copies and the actual current runner:

- `runner-reopen-probe.py` / `runner-reopen-probe.json`: **12/12 defect
  reproductions** = 409/410 × source/context × symlink/hardlink/regular-inode
  replacement. The instrumentation swaps the scratch name immediately before
  the actual `context_check()` tar open and records the returned read bytes.
- `verifier-reopen-probe.py` / `verifier-reopen-probe.json`: **6/6 defect
  reproductions** = 409/410 × the same three source replacement forms. The
  identical frozen-source verifier body runs in-process for read instrumentation;
  its Git reads remain real read-only subprocesses. The normal runner uses a
  child process, but passes the same unchecked pathname to the same body.

Each reproduction first passes the preceding real guarded checks on valid
copied frozen inputs. The scratch candidate's source path is redirected to
scratch; the real candidate and old chains are never changed. The read logs
contain `REVIEW2-FORBIDDEN-OLD-EVIDENCE-409` or `-410`, followed by tar rejection.
All failures occur before the reservation/admission block, so the reproduction
cannot consume the real attempt. These tests demonstrate a read, not a real
old-evidence copy or a successful Bootstrap. No current bound input is alleged
to be poisoned.

Required disposition: carry guarded, hash-checked bytes or pinned input streams
through the verifier/context consumers, rather than reopening their filenames.
Cover these downstream opens with alias and inode replacement regressions;
include subsequent transfer consumers when establishing end-to-end custody.
Preserve the original 410 chain and frozen payload/context. Any repaired bound
411 bytes require the controller's existing forward-only rebind procedure and
another review; do not reset a claim or edit retained generations. This review
changes no implementation or reservation.

### Controller gate G1 — remains outside this technical decision

The original checkpoint/publication prerequisite still applies:
`.superpowers/sdd/rust-v2/task-8c-lab-rebuild-assessment.md:86`, `:125`, and
`.superpowers/sdd/rust-v2/task-8c-driver-cost-brief.md:154`, as recorded in the
first review. Current HEAD still does not include the uncommitted preparation;
remote confirmation was NOT_RUN. The reservation still records
`execution_authorized_by_this_phase=false`.

The controller completes G1 only after the technical blocker is repaired and
reviewed. Preflight PASS, budget 1 and this report do not authorize execution.
G1 is not a request for additional user approval from this review.

### Minor

No new Minor finding. Original M1 is **closed for the current supplied smoke
manifest**: it contains six evidence rows and no self-checksum; all six hashes
verify. The original self-checksum defect remains documented in the first
review. No smoke file or manifest was rewritten by this reviewer.

## Original reproduction and guarded-path matrix

`poisoned-reference-exact.py` adapts the predecessor's
`/tmp/vprouter-run411-review/isolation-probe.py` to assert refusal rather than
the old defect. It writes a synthetic old record directly, adds its **correct**
SHA256 to a synthetic 411 reservation, and invokes the real collector. Both
409 and 410 return 1 with `run409_access_forbidden` / `run410_access_forbidden`;
neither old record is copied. Reservation save, parse and hash also refuse.

`isolation-independent.py` adds **112 independently instrumented cases**:

- 70 static cases: seven tools × 409/410 × direct, absolute, leaf-symlink,
  parent-symlink and hardlink paths. The tools are reservation, provenance,
  collector, state inspector, failure inspector, selector archiver and runner.
  Forbidden content-open counters remain empty; no poisoned bytes are copied;
  no guest subprocess is permitted by the harness.
- 42 immediate-open races: seven tools × 409/410 × regular-inode, hardlink and
  symlink replacement between the guard's pre-open stat and its open. All
  refuse before a poison-bearing stream is returned for reading. For a
  regular/hardlink replacement, opening a descriptor for metadata inspection
  may occur, but no content read or copy occurs.

The maintained 68-test isolation suite additionally passes its recursive
binding/tombstone/prior_evidence/references/helpers cases, preserved-prefix and
double-slash rejection, storage-bridge checks, and preserved alias refusal.
Its preserved probes intercept access before the OS can traverse the cold tree.
The collector's normal raw-first preservation behavior still passes its tests;
it can retain admitted 411 control files before rejecting a poisoned reference.
“Nothing copied” here means no forbidden old-evidence bytes were copied.

These results close the original literal-path collector scenario. They do not
clear the downstream runner reopens demonstrated by I1.

## Reservation, preflight and unchanged preparation

All **35 mandatory bindings** validate. Active reservation SHA256:
`120188663eb7b2a43a5ab3a8e395d91e0332b9facef17aed350508dc4e430b90`.

The chain has three retained/active generations and two immutable receipts:

1. `cb95853c3001e8a6e2c3da424bb1b97aa7938ce4d0b383335a77a253c097ae42`
   → `2c076f625c15516c31daa6ff14a2985d6906631ab2cba5f553f26875473ee62d`:
   original high-water correction 409→410, helper hash and time/supersedes data.
2. `2c076f625c15516c31daa6ff14a2985d6906631ab2cba5f553f26875473ee62d`
   → current `12018866…`: only time/supersedes metadata and eight binding
   hashes changed: reservation, provenance, collector, state inspector, runner,
   failure inspector, selector archiver and `source-manifest411.json`.

The new receipt's reason explicitly names I1. Retired bytes and receipt hashes
validate; the tuple, guest/controller boot IDs, one-shot budget and other
bindings are unchanged. Supersession tests cover stale generations, spent
claims and interruption after tombstone/link/unlink/replacement. No generation
grants an additional attempt.

Exact command executed, with the mandatory preflight switch:

```sh
python3 -B target/platform-lab/run-frozen-secret-bootstrap411.py \
  target/candidates/run410-da75562-20261104/candidate.json debian-arm64 \
  bootstrap411-arm64 success --reservation target/lab-state/run-411-reservation.json \
  --preflight-only
```

Exit 0: `reservation_preflight=PASS`, `remote_program_compile=PASS`, programs
`baseline-declaration`, `guest`, `host-declaration`, `listing`, budget 1 and
`guest_actions_executed=false`. An independent audit hook refuses old-chain
opens, all writes except opening the existing lock, and every subprocess except
the local frozen-source verifier. The current valid-path preflight passes that
audit. This is not a proof against the injected downstream replacements in I1.

The actual admission block's tests inject compile failure in each of the four
remote programs in both preflight and execution modes; all fail before the
synthetic claim. Both preflight paths return before output creation or guest
calls. The lock, exclusive claim/raw creation, collisions and failure semantics
remain one-shot. An additional isolated execution of the actual post-claim AST
passes 11 mocked success/failure/interruption scenarios; every SSH/SCP call is
intercepted and the real claim function is never invoked.

Frozen inputs independently verified:

| Input | SHA256 / fact |
| --- | --- |
| Candidate JSON | `ea3634b4e4140b3b3db8fdaf12b9c47c1b3757c9862f33001cbc022ef2d225f6` |
| Source tar, commit da75562 | `899dd5c843f6af2d86305e0380ca79006570de874d9356b725f24e91b09d8959`; 203 inputs verified by exact preflight |
| ARM64 payload | `5b78458c995556227417cb7939e13cc811dba3ad8dbcdfdd342404df84e09631`; ELF64 little-endian machine **183**, load segments, no interpreter/dynamic segments |
| ARM64 context | `51023de0b7bbab71a40e1882662d50327d8643f1f45051c466655207666f406d`; strict inventory matches retained ARM inventory |
| SSH pin | `bf37ae607c4ff4e5f3de2a4ef2244e8e7dea3919448b22a12cc6690c399200d1`; retained console key/process binding matches |

All 300 original/additional source/archive/restored triples match bytes, size
and hash. All 284 preparation SHA256SUMS entries and six supplied smoke entries
verify. Base-image SHA512 and staged package/QEMU/AAVMF hashes verify by reads;
no QEMU executable was invoked. The original 17 protected old-state/candidate
hashes still match. The x86 REMOTE is byte-identical to HEAD, baseline x86
defaults/decoder/multiset behavior are preserved, and all four 410 suites pass.

## Live guest and strict SSH

Final requested preflight **PASS**, using:

```sh
python3 -B tools/rust-v2-lab/phase3-readonly-preflight.py \
  /tmp/vprouter-run411-review2/guest-gates-third.json --platform debian-arm64 \
  --expected-boot-id 525e9103-b2f9-4611-a663-ced9d001245a
```

Exit 0, same guest boot **525e9103-b2f9-4611-a663-ced9d001245a** and machine ID
`f02b6d586b1a4a89969d2dcb038cb8a6`. Parent/root/marker protections hold; all eight
fixed selectors are absent; Docker is active with **zero containers**; cgroup2
and direct ARM syscall113 clocks3/7 pass. `pinned_images_inspected=false` remains
truthful for the offline scratch-image route. No image/container/native-role
qualification is inferred.

Separate strict read-only SSH executes only the actual guest's admission/stable
snapshot prefix, the exact boot-prefixed listing, and an independent RTM_GET
dump. The listing is empty, owner units are absent, and current full baseline
multisets match: **3 links / 6 addresses / 19 routes / 5 rules**. The WAN remains
`enp0s1`, index2, MAC `52:54:00:12:34:56`. Home upload names are absent and about
22.25 GB is available. No upload/build/payload/owner invocation occurred.

Read-only `/proc` inspection matches controller boot
`07dbae6e-6ed8-4bb3-a468-f89265c8dd6b`, sole QEMU PID **493434**, start tick
**5902200**, and the recorded full argv. The base-image FD remains read-only;
no open disk/firmware path identifies an old guest or preserved overlay. No
monitor, signal, QMP, lifecycle, disk attachment or executable probe was used.

`ssh -G` passes for all nine actual constructors: preparation SSH/SCP, baseline,
phase3, state inspector, runner SSH/SCP, failure inspector and selector archiver.
Each has `-F /dev/null`, global known_hosts `/dev/null`, sole dedicated identity,
`IdentitiesOnly=yes`, `IdentityAgent=none`, exact ARM known_hosts, strict checking,
loopback22034 and no proxy route. SCP proof here is configuration proof; actual
new transfers remain NOT_RUN.

Two earlier live attempts failed: banner exchange timed out (SSH255), then the
helper hit its 30s subprocess timeout. Those failures are retained and are not
relabeled as successes. Subsequent strict reads and the exact third preflight
passed without any repair or mutation. Guest readiness is a point-in-time
observation; repeat its read-only gates at the controller's execution boundary.

## TCG product-window risk

The timing statement remains **honest, with native 2s fit unqualified**.
`.superpowers/sdd/rust-v2/task-8c-run411-arm64-prep-report.md:157`–`:189`
separates retained overhead samples from Bootstrap timing proof. This review
rehashes the bound measurement references and inspects the frozen source:
`attachment.rs:999` uses `requested_at + 2.`; operational Bootstrap `:225`
inherits it and `:352` / `:484` check it; owned preparation `:85` requires the
same deadline. Pending 1ms sleeps do not renew it.

The measured 0.086s internal GET interval, 0.127s projection span, 0.073–0.091s
Python startup, 0.158–0.313s `/bin/true` launcher, two 17.137/19.787s synthetic
builds and 1.751/2.331s synthetic transfers do not qualify the product's complete
custody/birth/result/process-verification path. Retained x86410 timing is
context only and supplies no ARM slowdown bound. The unchanged lab limits
(SCP30/45s, build75s, launcher120s, RuntimeMaxSec110s, outer250s) cannot extend a
product window. TCG Deadline failure, including before Bootstrap scopes, remains
credible. No deterministic overflow is established and no timing PASS is claimed.
Failure still consumes the sole attempt; no retry or deadline tuning is implied.

## Verification ledger

Scripts/receipts below are under `/tmp/vprouter-run411-review2/`. Python imports
used `-B`; compilation output went to scratch. Test reservation/claim documents
are synthetic fixtures, separate from the real unmodified lab state.

| Check / evidence | Result |
| --- | --- |
| `poisoned-reference-exact.py`, corresponding JSON | Original correct-hash poison scenario repaired for 409 and 410; no forbidden copy |
| `isolation-independent.py`, corresponding JSON | 112/112 guarded entrypoint/path/open-race cases refuse before poisoned read/copy |
| `runner-reopen-probe.py`, corresponding JSON | 12/12 **FAIL boundary** reproductions; actual context consumer reads old sentinel before rejection |
| `verifier-reopen-probe.py`, corresponding JSON | 6/6 **FAIL boundary** reproductions; actual verifier body reads old sentinel before rejection |
| `tests.json`, `test-run410-*.py.log` | Four suites exit0: 8 +21 +21 tests and 12 reservation checks |
| `test-run411-*.py.log` | Six suites exit0: ARM baseline2, fixes8, isolation68, launcher4, provenance21, reservation12 checks |
| Shared suite logs | baseline5, phase3 fixes8, phase3b provenance21, all exit0 |
| `preflight-audit.py`, `preflight.stdout` | exit0; four actual remote programs compile, budget1, no guest action/claim/output |
| `postclaim.py`, `postclaim-outcomes.json` | 11/11 intercepted controller outcomes pass; no real claim or guest subprocess |
| `ssh-proof.py`, `ssh-G.json` | Nine constructors pass real `ssh -G` |
| `guest-gates.json` | First live attempt fails SSH255/banner timeout |
| Second helper invocation | 30s TimeoutExpired; no helper receipt created; failure recorded above |
| `guest-gates-third.json`, stdout/stderr | Exact requested helper exit0; same expected boot and all gates pass |
| `live.py`, `live-summary.json`, `live-{prefix,netlink,listing}.json` | exit0; read-only live admission, empty listing and current full multiset match |
| `audit.py`, `static-summary.json` | exit0; 300 source/archive pairs, 632 Python compilations, 35 bindings, two supersessions, 17 protected hashes, ELF183, strict context, console pin, packages/base |
| `optimized-all.json` | 42/42 refusals: 14 maintained/restored/archive runtime entrypoints × `-O`, `-OO`, `PYTHONOPTIMIZE=1`; `optimized_python_refused` before state/guest actions |
| `evidence-manifests.json` | 284/284 prep hashes and 6/6 smoke hashes verify; no smoke self-entry |
| `frozen-timing-source.json` | Frozen product deadlines/sleeps inspected; runtime fit NOT_RUN |
| Scoped `git diff --check` | exit0 |
| `preservation-final.json` | 708 snapshot paths unchanged in content/protected metadata, including HEAD/index; active reservation unchanged; claim/raw/error/output absent; budget1 |

Harness setup failures are distinct from preparation defects: the initial
snapshot assumed `.git` was a directory; the adapted predecessor audit initially
expected the verifier argv without its newly added `-B`; the first scratch
reopen fixture copied a baseline without restoring its required0600 mode.
After those harness corrections, the reported checks/probes completed as stated.
The failed SSH attempts and all scratch evidence were retained.

NOT_RUN: real411, any real claim/reservation mutation, actual payload/context
SCP, exact frozen-context build, owner/Bootstrap/native protocol, 2s runtime
qualification, actual post-run collection/inspection/selector archival,
full typed ARM witness acceptance, historical replay/cold-tree rehash,
production/provider/client/migration/performance/soak/release acceptance, and
controller checkpoint/push/remote confirmation. `release_ready=false`.

**Disposition: FAIL / NO-GO for I1. Repair and independently re-review the
downstream read boundary; G1 remains the controller's later gate.**
