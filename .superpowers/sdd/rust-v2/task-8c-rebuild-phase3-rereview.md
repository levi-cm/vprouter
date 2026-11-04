# Independent Task 8c phase 3/3b re-review after fixes

2026-11-04. Workspace `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`,
HEAD `6ca0073fb1f58706a670e9d4e333a831ae0d0628`. Reviewed the current unstaged
changes, new tools, restored controllers, archived copies and retained evidence.

**Implementation re-review: PASS. Execution decision: NO-GO for run409 now.**

C1, I1 and M1 are fixed, with independently reproduced pre-fix failures and
passing current regressions. I found **no additional deterministic code or
current-guest-state failure** in the exact path from claim to raw-record creation.
The remaining execution blocker is the explicitly required Root
checkpoint/push/remote-confirmation gate, which has not covered these unstaged
changes. This is a workflow blocker, not a newly discovered controller defect.

The implementation passes this independent review gate. After Root completes the
existing publication prerequisites for these reviewed bytes, no further code
repair is requested by this review. Guest identity, selector absence, reservation
bindings and unspent state must still hold at execution. A changed bound input
requires the existing preservation/rebinding procedure; never reset the claim.

All reviewer scratch and receipts are under `/tmp/vprouter-phase3-rereview/`.
This report is the only reviewer-written file outside that directory. No real
reservation was created, superseded or consumed; no run409/Bootstrap, guest
mutation, debdev sudo, Cargo operation, subagent, staging, commit, push or remote
publication check occurred. Synthetic claims/reservations exist only in
disposable offline test fixtures under the permitted scratch directory.

## Outstanding findings

### Critical

None remaining in the reviewed implementation.

### Important G1 — Required pre-run checkpoint/publication is still pending

Requirement locations:
`.superpowers/sdd/rust-v2/task-8c-lab-rebuild-assessment.md:74`, `:86`, `:125`;
ownership also stated in `task-8c-driver-cost-brief.md:154` through `:159`.
The assessment explicitly states: “Checkpoint/push/remote confirmation is
required by the historical Root workflow.”

Current evidence: HEAD is still `6ca0073`; six tracked files differ from HEAD,
eight versioned tool/test candidates remain untracked, and the cached diff is
empty. In particular, the current reservation helper, fresh collector/inspector
and fix regressions are not checkpointed in HEAD. The exact inventory is in
`local-preconditions.json` and `entry.json`. No remote verification was performed
in this offline review; it remains **NOT_RUN**. An earlier source/artifact
checkpoint does not checkpoint these new controller/helper bytes.

Concrete gate violation: invoking the recorded command immediately would spend
the one attempt against an uncheckpointed controller/post-run chain while the
documented publication prerequisite remains open. The runner's passing preflight
does not enforce that external workflow requirement. This finding does **not**
predict a deterministic guest failure or invalidate the passing code review.
Root must complete the existing scoped checkpoint/push/remote confirmation before
execution. This review makes no Git changes and requests no additional approval.

### Minor

None remaining from the earlier findings. Historical fixture and runtime-evidence
limits are recorded below rather than relabeled as implementation defects.

## Earlier findings and regression proof

### C1 — Closed

`target/platform-lab/run-frozen-secret-bootstrap.py:5`–`:20` now constructs and
compiles four actual programs: listing, configured guest, embedded host builder,
and embedded baseline builder. The historical listing at `:11` is byte-for-byte
equal to the listing extracted from HEAD, including its final newline. Fresh
listing/guest programs add only the admitted-boot assertion prefix.

The fresh callback at `:62`–`:65` performs provenance validation and compilation
inside reservation admission, before `run409-reservation.py:175` creates the
claim. `--preflight-only` returns at controller `:68`, after this callback. The
historical route compiles at `:72` before output creation or guest access. The
exact compiled listing and guest strings are reused at execution.

The maintained tests at `test-phase3-fixes.py:223`, `:237` and `:274` pass.
They exercise actual generated historical/fresh programs, HEAD listing equality,
and eight injected compilation refusals: each of the four programs, with and
without preflight, before any synthetic claim. The real configured preflight
also returned0 with all four names and `guest_actions_executed=false`.

Independently, I extracted the retained pre-fix listing from
`target/rebuild-phase3-fixes/entry/target/platform-lab/run-frozen-secret-bootstrap.py`.
It exactly equals the first review's reproduction. Compilation fails with
IndentationError at line2 historically and line3 with the fresh prefix; both
fixed forms compile. The maintained C1 generated-program regression also fails
on the pre-fix controller, which lacks the compilation function. Evidence:
`red-green.json`, `red-c1-versioned.json`, `fixes-tests.*`.

### I1 — Closed

`target/quarantine_evidence_base.py:34`–`:42` independently identifies run409,
reservation markers, fresh route/continuity and false historical/reconstruction
flags in either record or reconciliation. F dispatches through it at
`target/inspect-secret-bootstrap-failure.py:14`; A at
`target/archive-secret-bootstrap-selectors.py:13`. Fresh identity requires the
marker and full fresh validation. It cannot enter historical fallback merely by
deleting that marker. Fresh boot assertions use the same independent decision
(F `:65`, A `:52`). Both final generated bodies compile before SSH.

The actual maintained `FreshRoutes.test_routes` passes all 20 intercepted cases:
valid fresh and genuine historical inputs reach blocked SSH; tampering, marker
deletion and mixed/fresh identity cases refuse first. No SSH is performed by
these tests. I reran the same test method against retained pre-fix F/A/shared
validator copies in a scratch checkout. Ten forbidden fresh cases reached the
interceptor and errored with `BlockedSSH`, including marker deletion in both
tools. Thus this regression detects the reported bypass. Evidence:
`red-tests-confirmed.log`, `red-green.json`, `fixes-tests.*`.

The original historical remote bodies, owner/gateway/selector checks, historical
baseline assertion and surrounding validator checks remain. Genuine historical
cases with and without captured reconciliation pass the offline dispatch tests.

### M1 — Closed

`tools/rust-v2-lab/inspect-run409-state.py:80`–`:94` catches TimeoutExpired and
OSError, retains available stdout/stderr, classifies the transport error and
writes an exclusive0600/fsynced receipt. Timeout returns124; process-start error
returns125. `archival_authorized=false` and `runtime_acceptance=false` remain.

The maintained `InspectorErrors.test_transport_receipts` passes both cases,
including invalid UTF-8 replacement, partial output, receipt mode and overwrite
refusal. The same method against the retained pre-fix inspector errors twice
because the original transport exceptions escape. Evidence:
`red-tests-confirmed.log`, `red-green.json`, `fixes-tests.*`.

## Full remote-program coverage

The complete run409 controller has two SSH listing calls, two SCP transfers and
one SSH guest invocation. Its guest dynamically executes exactly the two builder
sources. All four Python programs are covered by the pre-claim gate, on fresh
and historical routes. SCP sends the **static ELF and context tar**, with no
SCP'd Python script. The context contains four static ELF roles, CA data,
program inventory and Dockerfile; it contains no additional Python program.

The guest's direct subprocesses are iproute2, Docker, wg, the frozen ELF,
systemctl and systemd-run. There is no additional Python stdin/-c subprocess in
that guest body. Controller-side source verification and context checking occur
before admission and are local operations. The compiler gate therefore covers
every remote Python program in this exact controller execution path; it does
not claim to prove native execution, Docker build or service behavior.

Additional actual remote templates in fresh-baseline, read-only preflight,
state inspector, native-inspection preflight and frozen host projection compile.
F/A tests compile their actual substituted historical/fresh bodies before
intercepted SSH. C has no remote subprocess. No omitted or malformed Python
payload was found. All 293 manifest pairs match restored/archive bytes, lengths
and hashes;594 Python source paths compile in memory.

## Exact post-claim trace against current state

Line references in this section are to the restored Bootstrap controller and
`target/platform-lab/secret-bootstrap.guest.py`; archived copies are identical.
The command was inspected and simulated offline, **never executed**:

```sh
python3 -B target/platform-lab/run-frozen-secret-bootstrap.py target/candidates/rebuild-20261103T231415Z/candidate.json debian-clean-x86_64 bootstrap409-driver-cost success --reservation target/lab-state/run-409-reservation.json
```

| Step | Source path and verification |
| --- | --- |
| Claim | Controller `:65` calls `admit`; helper `:168`–`:178` holds the cooperative exclusive lock, validates active generation/bindings/collisions/provenance/compilation, then exclusively creates/fsyncs the global budget 0 claim. There is no automatic retry. Preflight skips this creation. |
| Local output/snapshots | Controller `:75`–`:77` creates the absent 0700 label directory and seven exclusive captured inputs. Current candidate/lab-state directories are writable/searchable by the controller, source files are readable, and local free space exceeds300GiB. Output/claim/raw/error paths are absent. No current permission or path collision was found. |
| First listing | `:79`–`:81` sends the exact compiled fresh listing to `sudo -n python3 -I -`, timeout 15. I independently ran only this read-only body: exit0, empty list, no stderr. Root directory is root:root0700; boot assertion matches. |
| Artifact SCP | `:83` sends the readable 14,827,240-byte amd64 ELF to `/home/vprouterlab/secret-attachment-d8ae01f00e540879fe0e3cd68200b2f13677f441e057d2718137ec5d965ba715`, timeout 30. This is exactly the upload name read at guest `:70`/`:75`. |
| Context SCP | `:84` sends the readable 51,804,160-byte candidate-local tar to `/home/vprouterlab/secret-attachment-context-da7c2e8e257e4c243223c3964b9ce7ba7ebc8b574ddeed00e6bff0174fa49e6f`, timeout 45. Guest `:71`/`:75` reads exactly that name. Both destinations are currently absent; no pre-existing root-owned file blocks overwrite. |
| Transfer admission | Guest home is uid/gid1000, mode0700, writable/searchable as the authenticated uid1000. Its filesystem is rw without noexec. Strict confined SFTP authenticated and listed `/home` successfully, with zero transfers. This establishes the available protocol and directory access, not actual SCP transfer completion or speed. |
| Guest entry | `:87` invokes the exact compiled fresh guest through `sudo -n python3 -I -`, timeout 250. The same command form succeeds for read-only probes. I executed only the guest's actual AST prefix through `:68`: imports, helpers, protected-parent/marker/selector checks and stable_host. It passed without guest writes. Required tools python3/ip/docker/wg/systemctl/systemd-run/scp/sudo are present. |
| File/context admission | Guest `:69`–`:81` reads those uploads, checks their configured hashes, creates root-owned 0555 payload/0600 context, and extracts `rootfs/usr/local/bin/vprouter-worker` to the matching `task8b2-<init SHA>.gateway-init`. Both strict context inventories, init digests/sizes and static ELF ABIs pass offline. Guest destinations are absent; no stale incompatible cache file was found. |
| Image build | Guest `:83`–`:93` must build: its build directory/image-id are absent. Docker is active, with no containers; the required tools are present. The exact Dockerfile is FROM scratch/COPY/ENV/LABEL/ENTRYPOINT, with no RUN, external download or missing build script. Actual build, image-id/Entrypoint/label admission remain NOT_RUN. Cached Tailscale images are not treated as proof of a built fixture image. |
| Synthetic inputs/descriptor | Guest `:94`–`:124` generates two synthetic profiles/state paths and markers, then calls the uploaded ELF with `--secret-attachment-descriptor`. That exact argument exists in frozen actual_lab_main.rs; mount.rs's lab_descriptor uses the same selector, configuration, state-root and gateway-init paths. Its program manifest/init evidence matches the context. Random nonce paths are created by the fixture rather than expected to exist beforehand. No deterministic argument/path mismatch was found. These mutating/runtime steps remain NOT_RUN. |
| Host/baseline builders | Guest `:125`–`:147` verifies builder hashes, uses clean-Debian WAN ens2, and compares the native projection against the complete authored shape before staging. Live ens2 index2/MAC52:54:00:12:34:56 and init namespace match. A new read-only RTM_GET dump matches **all four full authored multisets**, including duplicate multiplicity. The native ELF projection inside this future fixture remains NOT_RUN. |
| Container/owner/Bootstrap | Guest `:149`–`:177` validates descriptor/staging, creates the inert network-none gateway and transient owner, then invokes the same payload with `--ignored-secret-bootstrap`. Frozen source recognizes that flag. systemd257, cgroup2, Docker and expected namespace are present. Exact new gateway/PID/pidfd/cgroup, owner birth, nested native custody, held negatives and Bootstrap outcome require future runtime work and are NOT_RUN. |
| Time limits | Build timeout 75 and owner-launch timeout 120/RuntimeMaxSec 110 fit individually within the enclosing guest timeout 250. The outer timer starts after both SCPs. I found no mandatory fixed wait or known current work whose duration deterministically exceeds these limits. Aggregate runtime and transfer speed were not measured; per-command budgets are not a proof that all possible slow paths fit 250. No timeout/deadline was extended. |
| Raw record | Controller `:90`–`:101` exclusively saves raw409 after guest return, including nonzero/SSH255 and captured timeout124. It does so before witness parsing, summaries and the final listing/directory binding. Actual post-claim AST simulation covers success, guest failure, both SCP failures, first/final listing failures, guest timeout and SSH-spawn error. No real subprocess/claim ran in this simulation. |
| Before-raw exceptions | Listing/SCP/output/spawn failures retain the exclusive controller-error receipt at `:115`–`:118`, with budget 0. They cannot permit a retry. Final-listing failure retains both already-written raw and controller error. Synthetic raw overwrite attempts refuse. These possible operational failures still exist; none is deterministically forced by the inspected current state. |

Current live receipts: `guest-inspection.json`, `guest-upload-access.json`,
`sftp-readonly-confirmed.json`, `live-listing.json`, `live-guest-prefix.json`,
`live-netlink.json`, `guest-gates.json`. Exact intercepted controller argv,
payload hashes, destination strings and timeouts are in `controller-path.json`.

The guest has approximately 22GB available disk and 1.7GB available memory at the
inspection. No failed systemd units were listed. Final status at
2026-11-04T16:09:28Z confirms QEMU 2147340/start tick 1616810, matching recorded
argv and loopback 22036, guest boot `e14efc10-050b-41b0-89d8-1e946725098c`,
controller boot `18f40876-a432-4ad1-9ded-03e0df43559a`. These are point-in-time
observations, not a fresh soak or a promise of future host stability.

## Reservation, baseline and historical behavior

The complete immutable chain verifies:

1. Original retained reservation SHA256:
   `3237686154de18668bee6182f24cc405b8c15a2eaa8d8d03e8305b574c1306e4`.
2. Prior phase3b retained reservation SHA256:
   `e3366fd4b99201f828c4ed844630007d54c7f4fed24515b9b9211d9838e36ff6`.
3. Active reservation SHA256:
   `533cdbe2da81b91c61902fcb700739922f30fd451578b7e0aea4b80fc0c664c3`.

Both tombstones and retired files are preserved; all 24 mandatory current bindings
match. One total attempt remains, unspent. Canonical path/parameters/schema and
the verified tombstone replacement SHA prevent admission of either old
generation, including restoring old bytes at the active pathname. Interrupted
supersession fails closed; spent claim blocks supersession. Crash/lock release
does not delete the consumed claim. This is the cooperating controller guarantee,
not protection against someone manually deleting evidence or launching an
unrelated old controller outside this mechanism.

The newly authored baseline remains truthful: links 3 / addresses 6 / routes 19 / rules 5,
namespace `[4,4026531840]`, canonical SHA256
`da3f80f0da4c717443fcb9a2118ed938a6d5c4edeea69d40e755b97291b5a01a`.
I re-decoded the saved independent RTM_GET data, verified its SSH/script-hash
receipt, references/helper hashes, exact equality to the authored template and
complete multiset equality to the retained frozen projection. Command receipts
order independent collection, successful authoring, projection, comparison.
The new live dump also matches. Historical/authority flags stay false.

The fresh validator re-executes the original pure projection-envelope checks:
creator PID/start, clean reap, socket identity, namespace, successful read-only
output/no authority and the original requested_at+2 deadline. Historical baseline
checks before/after the explicit new branch and the original true-flags assertion
are preserved. The other three pre-existing shared-validator functions are
AST-identical to HEAD. Frozen host-projection source is AST-identical to HEAD.
Historical listing bytes are repaired to HEAD. The new native-inspection platform
mapping preserves the three existing mappings. The intentional reservation
guards still restrict unreserved execution while a409 reservation exists.

All 293 source/archive/manifest triples match. All 203 build inputs equal the
frozen source/root verification; amd64/arm64 artifacts and both strict seven-file
contexts pass static checks. Retained amd64 filter-preflight artifact/log hashes
match. This is static/retained evidence, not a new native selftest or ARM runtime.

## Post-run preservation and safety

C copies raw/controller/claim/reservation/tombstone/bound bytes before outcome
validation. It preserves failures, timeout and interrupted/no-raw outcomes;
validation failure leaves a receipt and captured bytes. I now retains transport
failures as well as successful snapshots and grants no archival authority.
P accepts a synthetic source-bound native_poll/result Deadline example with all
13 wrapper / 30 nested / 24 retained / 15 owner / **15 driver** rows and original 2s window;
missing constructor and exit-zero inputs refuse. Frozen source and amd64 artifact
contain all three DRIVER markers. This proves reader compatibility only.

For a real complete Deadline failure, the documented sequence C → I → P → F
remains viable with its original prerequisite rows and directory binding. A
remains subject to the existing exact owner absence, original gateway
PID/start/StartedAt/pidfd/namespace and selector inode/hash/mode gates. Real F/A
were not run. Missing bindings/identities require stopping those steps, not
fabricating receipts. Early/no-raw cases use C/I and skip inapplicable P/F/A.
Success uses C, optionally I, and skips the failure-only parser/inspect/archive
sequence. The driver extension is emitted on first error; success does not
promise 15 diagnostic rows.

C explicitly retains `full_bootstrap_witness_validation=NOT_RUN`,
`runtime_acceptance=false`, `release_ready=false`. A preservation receipt,
parsed diagnostic or direct clock probe cannot establish Bootstrap acceptance.
Historical raw398–408 replay, original live identities and recovered408 archival
proof remain unavailable as explicitly disposed in the gap report. A fresh
three-link measurement cannot establish a causal speedup over old 61-link run408.

Sixteen extracted SSH/SCP-equivalent `ssh -G` variants pass: fixed lab user and
loopback, only dedicated identity, no agent/global trust/ambient SSH config,
explicit pinned known_hosts, strict checking, no ProxyCommand/ProxyJump. These
cover new helpers, F/A's four platforms and actual fresh-controller SSH/SCP argv.
Read-only live calls additionally used BatchMode and UpdateHostKeys=no. No
credential material was added to tracked sources. Thirty-nine optimized-Python
refusals pass: 13 entrypoints each with -O, -OO and PYTHONOPTIMIZE=1, before work.

## Verification ledger

Commands ran from the shared checkout with `python3 -B` and, for tests,
TMPDIR set to the permitted scratch root. `record.py` retains exact argv, exit,
UTC, duration, stdout and stderr in matching `*.command.json`/logs.

| Check / receipt | Result |
| --- | --- |
| `test-run409-reservation.py` / `reservation-tests.*` | exit0; 12 checks |
| `test-phase3b-provenance.py` / `provenance-tests.*` | exit0; 21 tests |
| `test-phase3-fixes.py` / `fixes-tests.*` | exit0; 8 groups, including 20 F/A cases and 8 pre-claim compilation refusals |
| Real exact controller command plus final `--preflight-only` / `bootstrap-preflight.*` | exit0; four remote programs compiled; budget 1; no guest actions |
| Scratch pre-fix regression replay / `red-green-confirmed.*`, `red-c1-versioned.json` | expected pre-fix failures reproduced; helper exit0; current GREEN suite above |
| Independent archive/source/baseline/reservation audit / `independent-audit.*`, `audit.json` | exit0; 293 pairs, 594 compiled paths, 39 optimized refusals, 203 inputs, 2 static architectures/contexts,complete 2-transition chain |
| Actual post-claim controller AST with all subprocesses intercepted / `controller-path.*` | exit0; 8 outcome cases; no claim call, transfer or guest execution |
| Exact read-only listing/guest prefix and live RTM_GET comparison / `live-prefix.*` | exit0; prefix through guest line68; complete live baseline multiset equality |
| Additional read-only guest filesystem/tool/Docker/systemd/upload inspection / `guest-inspect.*` | exit0; strict sudo form and unprivileged home access verified |
| Strict read-only SFTP / `sftp-readonly-confirmed.json` | exit0; directory listing only,zero transfers |
| Supplied read-only guest gates to scratch / `guest-gates.*` | exit0; boot, parents, marker, 8 absent selectors, WAN, images, no containers, cgroup2, direct clock syscalls |
| Synthetic parser example and refusals / `parser-check.*` | exit0; complete 15-driver-row example accepted; missing constructor/success refused |
| Historical validator AST / `historical-validator-check.*` | exit0; original historical checks retained |
| SSH configurations and historical synthetic checks / `ssh-smokes-confirmed.*` | exit0; 16 configuration variants, 26 public-binding checks, 43 pure projection-envelope checks |
| `git -c core.fsmonitor=false diff --check` / `diff-check.*` | exit0 |
| Initial and final `lab-guest-status.py` / `guest-status.*`, `final-guest-status.*` | both exit0; same admitted identities |
| Local paths and uncheckpointed Git inventory / `local-preconditions.json` | current permissions/read access pass; G1 confirmed |

The full historical projection smoke remains **NOT_RUN**: original
`target/continuation-20261028T044917Z/candidate.json` is absent. Its 43 pure
synthetic checks were executed without its file-writing tail or payload calls;
no historical fixture was manufactured. The public smoke's output was redirected
by running the unchanged script in a disposable scratch working directory.

Reviewer-harness corrections remain visible: the first red harness expected the
wrong unittest error/failure counts; its corrected expectation verifies 10 blocked
SSH errors plus 2 escaping transport errors. An initial SFTP listing used its
unsupported `-d` flag; the corrected read-only listing passed. An initial SCP-to-
SSH configuration translation omitted the destination; the corrected 16-variant
check passed. Those initial receipts are retained and are not counted as product
failures or hidden as successful checks.

NOT_RUN: run409/all Bootstrap modes; real claim/supersession; real SCP upload,
Docker build/container creation, synthetic guest inputs, owner service/native
execution, network/namespace/nft/mount mutations, real C/I/P/F/A, driver CPU
sampling, fresh native/filter selftest, ARM runtime, historical raw replay,
provider/client/migration/soak/release acceptance, Git publication and remote
confirmation. Stock exclusive-output candidate verifiers were not rerun; static
equivalents and retained-hash checks were used.

`entry.json` records 1499 input hashes/metadata, HEAD/status/index and the four
absent run409 outputs. The final preservation receipt
`preservation-final.json` verifies those inputs and Git identities unchanged,
all prior reservation/tombstone generations retained, and claim/raw409/controller
error/output directory still absent. No code repair or reservation mutation was
made by this reviewer.
