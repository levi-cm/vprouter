# Task 8c run 411 ARM64 preparation — third independent review

2026-11-06. Repository `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`,
HEAD `9f997dd960876619bc57d1910a2d532d224d2498`. Reviewed the uncommitted
preparation identified by the two preceding reviews and the implementer's
“Review round 2”, including maintained and restored execution sources.

**Verdict: PASS. Technical decision: GO for the single reserved experiment.**
**G1 remains the controller's separate checkpoint/publication gate; execution
is not authorized by this report.** No Critical or Important technical defect
was demonstrated. I1 is closed for both the original forbidden-reference case
and the downstream filename-reopen cases. M1 is closed for the supplied current
smoke manifest. Native ARM Bootstrap success and timing acceptance remain
**NOT_RUN**.

**Run 411 remains NOT_RUN, budget 1. Runs 409/410 remain consumed, budget 0.**
The active reservation is
`85f4502ba9d79f037f9d2c69e97d42822d06079bc8192cc9d4037e32b632aa2b`.
Claim, raw record, controller-error receipt and `bootstrap411-arm64/` output
remain absent. No reservation was created, consumed or superseded. This review
started no subagents and performed no guest mutation, QEMU invocation/QMP/
lifecycle operation, old-disk boot, debdev sudo, staging, commit or push.
Guest sudo occurred only within strict SSH for read-only programs. Scratch is
under `/tmp/vprouter-run411-review3/`; this report is the only repository write.
The concurrently edited witness-validator/contract/report files were excluded
from inspection, compilation and tests. The cold preserved tree was not opened
or traversed.

## Findings and dispositions

### Critical

None demonstrated. Exclusive claim/raw creation and the global claim spanning
all reservation generations remain intact.

### Important I1 — closed

Relevant locations: `tools/rust-v2-lab/run411-reservation.py:44`, `:139`, `:165`,
`:453`, `:462`, `:486`, `:501`;
`tools/rust-v2-lab/target/platform-lab/run-frozen-secret-bootstrap411.py:33`,
`:47`, `:51`, `:83`, `:89`;
`tools/rust-v2-lab/run411-provenance.py:65`;
`tools/rust-v2-lab/collect-run411-evidence.py:46`.
The additional manifest proves the archived runner/F/A sources equal their
restored counterparts; line references apply to both copies.

The concrete previous failure was replacing a previously checked source/context
filename with a symlink, hardlink or renamed old-evidence inode, after which a
tar/verifier/transfer consumer reopened that name. The runner now retains the
acquired source, context and ELF bytes. Source verification uses those bytes
and Git objects; the unchanged context checker receives a bytes-only tar
adapter. Neither consumer receives the checked pathname. SCP receives a sealed
anonymous descriptor with explicit `pass_fds`. SSH identity and pin inputs
are acquired and exclusively written into a private 0700 directory as 0600
files; OpenSSH receives only those private filenames.

At initial acquisition, forbidden prefixes and aliases refuse before content
access. An inode substitution between first lstat and the content open refuses
before `fdopen`/read. A later replacement cannot change already captured bytes.
Thus a downstream replacement may safely finish using the original snapshot;
it need not fail merely because an unused original filename changed. No tested
case reads or copies the forbidden replacement bytes.

Fresh independent evidence:

- `poisoned-reference-exact.py`: both correct-hash 409/410 poisoned collector
  bindings refuse; no forbidden copy. Original save/parse/hash refusals pass.
- `isolation-independent.py`: **112/112** cases across reservation, provenance,
  collector, state inspector, failure inspector, selector archiver and runner.
  Direct/absolute names, leaf/parent symlinks, hardlinks and immediate-open
  regular-inode/hardlink/symlink swaps refuse before forbidden read/copy.
- `preserved-independent.py`: **56/56** additional seven-tool cases. Literal
  `/DATA/vprouter-lab/preserved/` and double-slash spellings and aliases refuse
  without traversal; hardlink/inode races use synthetic preserved evidence.
  Instrumentation counts and intercepts any real preserved-tree attempt before
  the OS can perform it, including exceptions the collector could catch.
- `downstream-independent.py`: **27/27** cases, independently adapted from the
  two predecessor probes: the original **18** source/context/verifier cases
  plus nine synthetic-preserved variants. Replacement occurs immediately before
  the actual bytes-based tar consumer or verifier Git lookup. Every valid
  prefix reaches intercepted admission without reading the poison; real
  admission and guest calls are blocked.
- `test-run411-acquisition.py`: six tests pass, including **45** full-runner
  downstream cases, **9** first-lstat races and **18** SSH staging cases.
  The full-runner matrix also covers artifact/context replacement at SCP,
  checks transferred hashes, descriptor inheritance/seals, and scratch-only
  raw publication. Admission/provenance/network are intercepted there.

### Controller gate G1 — separate, still outstanding

Locations: `.superpowers/sdd/rust-v2/task-8c-lab-rebuild-assessment.md:86`,
`:125`; `.superpowers/sdd/rust-v2/task-8c-driver-cost-brief.md:154`.
Current HEAD still excludes the uncommitted 411 preparation; remote confirmation
was **NOT_RUN**. The live reservation records
`execution_authorized_by_this_phase=false`.

Concrete gate scenario: running the reviewed local bytes before the controller's
scoped checkpoint/push/remote confirmation would bypass the existing publication
prerequisite, even though this technical review passes. The controller must
complete that existing gate and recheck bindings/live admission at execution.
G1 is neither a remaining I1 defect nor a request by this reviewer to create a
new approval flow. This review performs no publication or execution.

### Minor

No new Minor finding. M1 is closed: the supplied ARM smoke `SHA256SUMS` has
exactly six rows, no self-entry, and all six content hashes verify. No manifest
was rewritten by this reviewer.

## Independent remaining-open audit

I ran grep and read the seven complete operative sources and their transitive
verifier/context/baseline/projector paths. `path-audit.txt` retains the search.
The static test is useful regression coverage, not the basis for assuming
unexamined helper code is safe. Its six tests include mutation checks for direct
and implicit file reads, pathname tar, subprocess paths, connection mutations,
code loaders, writes and embedded I/O.

| Remaining by-path operation | Location and judgment |
| --- | --- |
| Input content open | `run411-reservation.py:139`: `allowed_path` first records metadata; directory traversal uses no-follow directory descriptors; the leaf opens with `O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK`. fstat must match the first admitted dev/inode and be regular/single-link before the one read at `:155`; final fstat checks stability. Hash, parsing and compatibility streams consume the captured bytes. Accepted. |
| Directory traversal/fsync | Reservation `:94`, `:202`: opens `/` and directories only, using `O_DIRECTORY|O_NOFOLLOW` for components. Explicit storage bridges validate their targets and translate paths; ordinary symlinks refuse. No directory content stream is read as evidence. Accepted. |
| New outputs | Reservation `:178`, `:210`; collector `:28`; runner `:81`, `:87`, `:116`, `:118`; F/A final output writers: guarded exclusive new files, not content reopens. `O_EXCL|O_NOFOLLOW`, 0600, with durable claim/raw writers. Accepted. |
| Cooperative lock | Reservation `:228`: `O_RDWR|O_CREAT|O_NOFOLLOW`, followed by fstat ownership/type/nlink/mode checks and nonblocking flock. Lock content is never read. Existing lock is the only write-capable open in audited preflight. Accepted. |
| Initial guard imports | Runner `:5`, provenance `:6`, collector `:20`, state inspector `:57`, F/A `:5`: six fixed executable trust-root imports. They accept no reservation/evidence-controlled filename. Python must load trusted executable code before that code can guard evidence; this is an explicit bootstrap exception. Standard-library/Python runtime loading is likewise outside evidence acquisition. Accepted within this trust model. |
| Later helper loading | Reservation `:453`; runner `:42`, `:51`, `:66`; provenance `:7`, `:33`, `:48`, `:65`: compiles acquired bytes. The base validator's callable `validate_baseline_host` is rewritten so its pathname reads use the same guard; its historical fresh validator is replaced. Other historical functions in that module are not called by the 411 lane. Context tar calls receive only bytes; verifier reads local Git objects. No evidence pathname is passed back to an import loader or verifier process. Accepted. |
| SCP source opens | Runner `:90`, `:92`, reservation `:486`: `/proc/self/fd/N` refers to an owned sealed memfd, not an original evidence path. In addition to mocks, actual local `scp -D /usr/lib/openssh/sftp-server` successfully copied 9,216 public synthetic bytes from this helper's inherited descriptor into review scratch. This proves local source-descriptor compatibility; it performs no network/guest action and does not qualify actual ARM transfers. Accepted. |
| OpenSSH identity/pin opens | Reservation `:501`, runner `:83`, state inspector `:82`, F/A final SSH blocks: only private exclusive staged files. Hashes match the guarded originals, permissions and cleanup pass. Real `ssh -G` resolves the sole staged key/pin and strict options at all operative sites. Accepted. |
| Embedded guest reads | State inspector `:17`; F/A embedded scripts; runner boot/listing literals: boot ID, proc stat, cgroup membership, eight public selectors, failure canonical allocations/namespaces. Guest profile paths are metadata-only. These are boot-bound guest proc/public fixtures, not controller old-evidence paths. The unchanged `secret-bootstrap.guest.py` also reads uploads, context/image ID and its own created fixtures/output; those belong to the intended future mutating experiment. Nothing in those guest mutation bodies was executed here. Accepted scope distinction. |

Preparation-only/shared sources were also read, rather than hidden by the
seven-source static test. `start-clean-debian-arm64.py:7`, `:15`, `:37`, `:44`,
`:47`, `:56` and its creation/log/process writes are its fixed bisect/proc/
lifecycle-lock/image/checksum/public-key/new-guest preparation path.
Existing guest state refuses before lifecycle commands; this launcher is not
called by the exact 411 execution command. `fresh-baseline.py` retains ordinary
candidate/dump/template/projection reads and exclusive author/compare outputs;
`phase3-readonly-preflight.py:73` opens its explicitly selected new receipt and
reads its own source for a hash. Their SSH clients retain original dedicated
key/pin names. These are shared preparation/read-only gate tools, not consumers
of reservation-driven post-claim references. Their old x86 behavior must remain
available. I accept their exclusion from the operative seven-tool custody
invariant; I do not claim the static test forbids every pathname read anywhere
in the repository. Test harness fixture reads/copies are likewise outside that
production invariant.

## Reservation, no-regression and frozen-input checks

All **35** mandatory live bindings pass. There are six generations and five
immutable receipts; hashes, retained bytes, links between generations and
global claim/budget invariants validate. Each receipt has a concrete justified
reason, and generation diffs agree with it:

| Transition (digest prefixes) | Verified reason and binding change |
| --- | --- |
| `cb95853c` → `2c076f62` | Correct high-water metadata 409→410; reservation helper hash, creation/supersedes fields. |
| `2c076f62` → `12018866` | Round-1 forbidden-prefix/alias repair; eight execution/helper/manifest binding hashes. |
| `12018866` → `1f18a4c1` | Round-2 captured inputs/helper consumers/descriptor transfer; eight binding hashes. |
| `1f18a4c1` → `80196f9b` | SSH identity/pin staging closure; six binding hashes including manifest. |
| `80196f9b` → `85f4502b` | Preserve state-inspector staging-failure diagnostics before argv exists; inspector binding only. |

Later transitions change only bindings and creation/supersedes metadata; they
do not change tuple, guest/controller boot IDs, claim name or total budget.
`static-summary.json` records full hashes, exact changed binding lists/reasons.
Supersession tests cover stale/spent generations and interruption after
tombstone/link/unlink/replacement. No generation grants another attempt.

Reservation `:349` executes binding/provenance/compile validation while holding
the lock, before its only claim save at `:361`. Runner `:68` compiles the exact
boot-prefixed guest/listing and both builders; `:73` exits preflight before
output, SSH or SCP. Existing tests inject compile failures in each of the four
programs in both modes and verify no claim. Collision, dangling-name, concurrent
lock, wrong tuple, binding drift and second-attempt cases pass.

Exact non-consuming command executed under a rejecting audit hook, exit 0:

```sh
python3 -B target/platform-lab/run-frozen-secret-bootstrap411.py target/candidates/run410-da75562-20261104/candidate.json debian-arm64 bootstrap411-arm64 success --reservation target/lab-state/run-411-reservation.json --preflight-only
```

```json
{"reservation_preflight":"PASS","remote_program_compile":"PASS","compiled_remote_programs":["baseline-declaration","guest","host-declaration","listing"],"run":411,"budget_remaining":1,"guest_actions_executed":false}
```

The hook permits only local `git ls-tree`/`git show` children, rejects old-state
opens, and rejects every write-capable open except the existing 411 lock.
No claim/raw/error/output appeared. The active reservation digest stayed fixed.

| Frozen input | Current verified value |
| --- | --- |
| Candidate JSON | `ea3634b4e4140b3b3db8fdaf12b9c47c1b3757c9862f33001cbc022ef2d225f6` |
| Source tar / da75562 | `899dd5c843f6af2d86305e0380ca79006570de874d9356b725f24e91b09d8959`; all 203 build inputs checked against Git objects |
| ARM64 payload | `5b78458c995556227417cb7939e13cc811dba3ad8dbcdfdd342404df84e09631`; ELF64 little-endian machine **183**, load segment present, no interpreter/dynamic segments |
| ARM64 context | `51023de0b7bbab71a40e1882662d50327d8643f1f45051c466655207666f406d`; strict seven-file/four-role inventory agrees with retained ARM inventory |
| Host pin | `bf37ae607c4ff4e5f3de2a4ef2244e8e7dea3919448b22a12cc6690c399200d1`; console trust/process binding agrees |

All **300** original/additional manifest source/archive/restored pairs match
bytes, lengths and hashes; `source-manifest411.json` is consistent. Original
296-entry manifest and all four 410 suite files equal HEAD. Shared baseline
REMOTE/decoder/canonical multiset functions equal HEAD, and the x86 phase3
REMOTE equals HEAD. All four 410 suites and shared regression suites pass.
Optimization probes refuse with `optimized_python_refused` before actions:
30 maintained/restored probes (`-O`, `-OO`, environment optimization) plus six
additional archived/restored 411 entrypoint `-O` probes.

The separate reviewer-only preservation check rehashed all **17** protected
current-state/candidate references from the preparation entry snapshot; all
match, and both original consumed claims still report budget 0. These direct
reviewer preservation reads are distinct from the instrumented 411 tools,
which never opened those forbidden references. No cold-tree audit is implied.

## Current guest: read-only evidence

Requested command, exit 0:

```sh
python3 -B tools/rust-v2-lab/phase3-readonly-preflight.py /tmp/vprouter-run411-review3/guest-gates.json --platform debian-arm64 --expected-boot-id 525e9103-b2f9-4611-a663-ced9d001245a
```

Boot remains **525e9103-b2f9-4611-a663-ced9d001245a**, machine ID
`f02b6d586b1a4a89969d2dcb038cb8a6`. Parent/root/0600 marker protections hold,
all eight selectors are absent, Docker is active with **zero containers**,
cgroup2 and direct ARM syscall113 clocks3/7 pass, seccomp is 0. Offline scratch
image route truthfully reports `pinned_images_inspected=false`.

Independent strict SSH ran only the unchanged guest program's read-only
admission/stable-host prefix, an independent RTM_GET dump and the exact
boot-prefixed listing. Listing is `[]`; owner units and upload names are absent.
Current full baseline multisets match: **3 links / 6 addresses / 19 routes /
5 rules**, same network namespace. WAN is enp0s1/index2/MAC
`52:54:00:12:34:56`; home is writable by lab UID, SFTP and required commands
exist, and guest available disk is **22,252,679,168 bytes**. No upload, build,
payload/descriptor/owner invocation or container action occurred.

Read-only controller proc inspection confirms controller boot
`07dbae6e-6ed8-4bb3-a468-f89265c8dd6b`, sole QEMU PID **493434**, start tick
**5902200**, full recorded argv and read-only base-image FD. No open old/preserved
disk was found. No executable or control interface of QEMU was invoked.

Real `ssh -G` passes for all **nine** constructors: prep SSH/SCP, baseline,
phase3, state inspector, runner SSH/SCP, failure inspector and selector archiver.
Each uses `-F /dev/null`, global known_hosts `/dev/null`, exactly one dedicated
identity, `IdentitiesOnly=yes`, `IdentityAgent=none`, strict checking, the ARM
pin, loopback22034 and no proxy. Operative private staged copies match original
hashes and are removed afterward. Configuration proof is not a real ARM SCP.

## Exact post-claim trace

The execution command is the preflight argv above with `--preflight-only`
removed. **It was not executed.** The actual post-claim AST was separately
executed with admission absent, all guest subprocesses intercepted, and all
outputs redirected to scratch. Eleven success/failure/interruption scenarios
pass, including first/final listing, each transfer, guest nonzero/SSH255/timeout,
spawn failure, raw collision and output collision. This also checks transfer
descriptor contents and preserves an existing synthetic raw on collision.

| Step | Current evidence and failure behavior |
| --- | --- |
| Runner `:79`–`:83`: exclusive output, seven snapshots, SSH staging | Output absent; bound parent/sources valid, current key/pin acquisition and private staging pass. Existing output or staging failure is a consumed-attempt controller failure, not retry authority. |
| Runner `:85`–`:87`: first boot-bound listing | Exact read-only listing against current guest succeeds and returns `[]`; guarded exclusive local receipt follows. Failure precedes raw and retains controller-error. |
| Runner `:88`–`:92`: payload/context transfers | Captured hashes, sealed inherited descriptors, strict SSH/SCP options and home/SFTP prerequisites check out. Local actual SCP descriptor compatibility passes. Actual guest transfers remain NOT_RUN; 30/45s transport failures consume the attempt and retain controller-error. |
| Runner `:95`, guest `:5`–`:68`: admission/stable snapshot | Exact current read-only prefix succeeds; boot/root/marker/selectors/baseline prerequisites agree. Subsequent guest execution is NOT_RUN. |
| Guest `:69`–`:93`: upload verification, extraction, image build | Current protected destinations/uploads absent; local exact payload/context/worker/Dockerfile inventory matches. No deterministic hash/architecture/interface mismatch identified. Build and image qualification remain NOT_RUN. |
| Guest `:94`–`:147`: synthetic inputs, descriptor, host/baseline | Required host tools exist; frozen source contains the interfaces/flags. Authored ARM WAN mapping and fresh full baseline match. Native descriptor/projection and all writes remain NOT_RUN. |
| Guest `:149`–`:178`: inert gateway and owner Bootstrap | Current containers/owner units absent; cgroup/systemd/Docker prerequisites pass. Gateway/owner/native execution and protocol timing remain NOT_RUN. No deterministic current-input failure established. |
| Runner `:95`–`:106`: raw preservation | Normal/nonzero/SSH255 guest returns and caught outer timeout124 reach exclusive durable raw creation before stdout parsing, summary and final listing. A guest-side assertion/build/product failure normally still yields raw. |
| Runner `:108`–`:128`: postprocessing and errors | Final-listing/parse failure cannot erase already saved raw. Output/listing/SCP/spawn/raw-collision exceptions preserve controller-error with budget0 where the host can write it. Process death/host IO failure cannot guarantee a receipt and never replenishes budget. |

**No deterministic failure before raw creation was identified for the currently
bound inputs and observed guest.** This is source/configuration/read-only and
intercepted-controller evidence, not execution or successful Bootstrap proof.

## TCG timing risk

The preparation states the risk honestly. The product's original two-second
windows remain unqualified under TCG, with credible Deadline failure including
before Bootstrap scopes. Frozen `attachment.rs:999` uses `requested_at + 2.`;
`attachment/operational/bootstrap.rs:225` inherits it and `:352`/`:484` check it;
`owned/preparation/bootstrap.rs:85` requires the same deadline. Existing pending
1ms sleeps do not renew it. This review inspected those exact frozen tar members.

Retained measurements and reference hashes verify: internal GET 0.086s,
projection span 0.127s, Python startup 0.073–0.091s, `/bin/true` launcher
0.158–0.313s, two synthetic builds 17.137/19.787s, synthetic exact-size transfers
1.751/2.331s. None measures the complete product custody/birth/result/process
verification path. They establish neither a worst-case bound nor ARM success.
No deterministic timeout overflow was demonstrated. Unchanged lab limits
30/45/250/75/120/110s cannot extend product windows. Failure consumes the one
attempt; no retry, timing relaxation or native acceptance is implied by GO.

## Verification ledger

All evidence below is in `/tmp/vprouter-run411-review3/`. Python used `-B`;
bytecode output was directed to explicit scratch cfiles. Synthetic claim and
supersession tests operate only on temporary fixtures.

| Command/driver and retained evidence | Fresh result |
| --- | --- |
| `run-checks.py`, `tests.json`, individual logs | All 13 scripts exit0: 410 suites 8/21/21 tests and12 checks; 411 baseline2/fixes9/isolation68/launcher4/provenance21/reservation12; shared baseline5/phase3fixes8/phase3b21 |
| `TMPDIR=/tmp/vprouter-run411-review3 python3 -B tools/rust-v2-lab/test-run411-acquisition.py` | exit0, six tests; 45 downstream,9 acquisition,18 SSH cases; verifier equivalence and static mutation checks |
| `poisoned-reference-exact.py`, JSON/log | exit0, both original correct-hash poison cases refuse without copy |
| `isolation-independent.py`, JSON/log | exit0,112 seven-tool cases pass |
| `preserved-independent.py`, final stdout/stderr and JSON | exit0,56 further cases pass without real preserved-tree access |
| `downstream-independent.py`, final stdout/stderr and JSON | exit0,27 cases including all18 predecessor cases; no poison read, real admission or guest call |
| `preflight-audit.py`, `preflight.stdout`, stderr | exit0; exact preflight PASS, four programs compile, budget1, no claim/guest/output |
| `postclaim.py`, stdout/stderr, `postclaim-outcomes.json` | exit0,11 controller scenarios pass; real claim never called, guest subprocesses intercepted |
| `ssh-proof.py`, `ssh-G.json` | exit0, nine real configuration proofs, staged hashes/cleanup pass |
| Requested phase3 helper, `guest-gates.*` | exit0, expected boot and all ARM gates pass |
| `live.py`, `live-summary.json`, live prefix/netlink/listing receipts | exit0, strict read-only guest prefix/listing/full multiset and process identities pass |
| Local actual `scp -D` probe, `local-sftp-proof.json` | exit0;9,216 synthetic bytes copied from inherited sealed descriptor into scratch; no guest/network |
| `audit.py`, `static-summary.json` | exit0;300 manifest pairs,633 Python compilations,35 bindings, five justified supersessions, ELF183/context/pin/package/base-image verification |
| `optimized.json`, `optimized-archive-restored.json` | 30 maintained/restored optimization refusals plus six archived/restored -O refusals, all expected nonzero |
| `x86-unchanged.json`, source/diff inspection | Original manifest/410 suites and shared x86 remote/decoder/multiset behavior unchanged |
| `prior-preservation.json` | All17 protected hashes match; original409/410 budgets0; reviewer-only reads |
| Smoke hash check, frozen timing/deadline JSON | Six smoke hashes pass, no self-entry; frozen deadlines confirmed |
| Scoped `git diff --check` | exit0 |
| `final-preservation.py`, `preservation-final.json` | exit0;660 snapshot paths unchanged in bytes/metadata excluding access time, including HEAD/index; Git status unchanged; active reservation unchanged; claim/raw/error/output absent; budget1 |

Harness limitation/failure history: initially `/tmp` had about51MiB free, so the
large fixture run was deferred without deleting evidence. Capacity subsequently
became sufficient; the complete suite passed under the requested scratch root.
The first independent downstream harness run incorrectly blocked the Git child
used by `check_output`; its traceback is retained. Allowing only the required
read-only Git children repaired the harness, after which all27 cases passed.
That setup failure is not attributed to the preparation.

NOT_RUN: real411, any real reservation/claim mutation, actual guest payload/
context SCP, exact frozen image build, owner/Bootstrap/native protocol,
two-second ARM qualification, real post-run C/I/F/A, full typed ARM witness
acceptance, cold historical replay/rehash, controller checkpoint/push/remote
confirmation, and production/provider/client/migration/performance/soak/release
acceptance. `release_ready=false`.

**Final disposition: PASS / technical GO for one run only; G1 outstanding;
411 NOT_RUN, budget1; TCG product-window success remains unqualified.**
