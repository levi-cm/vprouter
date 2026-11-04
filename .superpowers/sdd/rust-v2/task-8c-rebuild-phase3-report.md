# Task 8c rebuild phase 3 implementation report

2026-11-04. Workspace `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`,
HEAD `6ca0073fb1f58706a670e9d4e333a831ae0d0628` at entry and final audit.
Entry worktree/index were clean; all implementation changes remain unstaged.

**Fresh baseline authored and fully matched; run409 exclusively reserved but NOT_RUN.**
Source/context/static gates, exact x86 frozen rootless inspection/filter mechanics,
current guest admission and reservation-only Bootstrap preflight passed. This is
implementation evidence, not independent phase-3 review or permission to execute
Bootstrap. Independent review/checkpoint and some runtime gates remain open as
specified below. Full Task8c remains ACTIVE; `release_ready=false`.

No subagents, Cargo/Rust changes, git commit/push/staging/ref-write command,
outer-host sudo, production/credential use, guest restart/stop, or guest
network/namespace/nft/container mutation occurred. All remote privileged reads
used `sudo -n` inside the dedicated guest only. New private credentials were
neither acquired nor read. No historical raw record, ID or resource was invented.

Primary evidence is `target/rebuild-phase3/`. Each `*.command.json` contains exact
argv, exit code, UTC observation, duration and full stdout/stderr paths. The
recording helper and all scratch scripts are retained there. Reports are ignored
by Git and have not been force-added. A lightweight memory lookup supplied prior
preservation/confinement context; current operational facts were verified live.
The brief and its specified reports/controllers/schema/context helpers were
consulted; historical authoring helpers were read, not executed.

## A. Guest admission

`admission-status.stdout` and `final-status.stdout`: the guest is the brief's live
QEMU **2147340**, start tick **1616810**, with exact original recorded argv and a
loopback-only `127.0.0.1:22036` listener. Guest boot ID remained
`e14efc10-050b-41b0-89d8-1e946725098c`; controller boot ID remained
`18f40876-a432-4ad1-9ded-03e0df43559a`. No restart helper was necessary or run.
Final status command exited0 at 2026-11-04T15:12:18.861034+00:00.

`admission.json` contains each exact guest command, exit code, stdout/stderr, file
metadata and initial network namespace identities. Every command exited0:

- `uname -a`: kernel `6.12.113+deb13-cloud-amd64`, x86_64; virtualization `kvm`.
- `systemctl --failed --no-pager`: zero failed units. Docker active/running;
  `docker ps -a` empty. Root `/dev/vda1`, ext4, mounted read/write.
- cgroup2fs, controllers `cpuset cpu io memory hugetlb pids rdma misc`;
  systemd257. RAM available **1761767424 bytes**, free filesystem
  **22276796416 bytes** (initial admission). These are context/headroom readings,
  not timing or soak guarantees.
- WAN `ens2`, ifindex2, MAC `52:54:00:12:34:56`, Ethernet; lo1 and docker0/3.
  IPv4 `10.0.2.15/24`, default via `10.0.2.2`; full IPv6/Docker state retained.
- Lab root root:root0700; isolated marker root:root0600, regular, single-link.
  `guest-gates.json` additionally verifies `/`, `/var`, `/var/lib` ownership and
  no group/other writes, guest HOST namespace equals PID1, and all eight fixed
  selectors absent including dangling-symlink checks.

Both images matched the tracked pinned inventory and were inspected again by
exact digest, without pull/create/run:

| Architecture | Manifest digest | Cached config/image ID |
| --- | --- | --- |
| amd64 | `sha256:08a1bc6c82fee62d1a135788fb67fefa9d22deea3830e8a45ebe1a3cb116e325` | `sha256:94603a5a98fa75ef53c4c5b5401c4025b25cd2e54ad2609720ba8d0e5a3febda` |
| arm64 | `sha256:472c549d2ef8cebc000de2c8a94061bbdc864d2454177b2ada713262475449ef` | `sha256:5d3dd33a5cd5ed29514fdada176fa2226d122f19bddd8fe06bc974633083e90e` |

Every new SSH invocation kept `-F /dev/null`,
`GlobalKnownHostsFile=/dev/null`, `IdentitiesOnly=yes`, `IdentityAgent=none`,
`-i target/lab-state/id_ed25519`, explicit clean-Debian `UserKnownHostsFile`,
`StrictHostKeyChecking=yes`, loopback22036 and the fixed lab user. New helper
constructors also set BatchMode, UpdateHostKeys=no and ConnectTimeout5. Exact SSH
argv and input bodies are retained in `admission.stdout`, `admission-remote.py`,
`independent-netlink-ssh.json`, `guest-gates.json`, frozen projector/native-selftest
sources and their SSH receipts. `audit.json` has two additional `ssh -G` effective
configuration proofs for the new helper constructors; these are configuration
checks, separate from actual successful handshakes.

## B. Historical gaps

Created `.superpowers/sdd/rust-v2/task-8c-historical-gap-disposition.md` with one
explicit disposition per historical gate. Missing raw398–408/reader replay,
recovered408 custody/exact-six archival proof, original live-resource identities
and original trust cannot be regenerated. Fresh admission/baseline/reservation
replace only future gates. Original398–408 remain failed. No historical template
helper, failure inspector, selector archiver or placeholder run was executed.

## C. New baseline and provenance

Added `tools/rust-v2-lab/fresh-baseline.py` with collect/author/compare actions.
The design supports only the admitted clean-Debian environment and exact brief
boot. It takes a separate root read-only RTM_GETLINK/GETADDR/GETROUTE/GETRULE dump
and namespace/boot identity, decodes complete structural fields offline, and
checks the link inventory against the separately collected iproute2 admission.
The explicit fresh topology is lo1/ens2/docker0, 3 links/6 addresses/19 routes/
5 rules. Both alternate WAN names are retained. Optional fields and null-vs-value
presence, header flags, address priorities, route nexthop ID and preferences,
rule suppressors/protocol, link head/tailroom/pacing fields and namespace tuple
are retained. No historical values are imported or link counts manufactured.

This establishes a *new declared environment from independent kernel inspection*,
not reconstruction of original history. Helper docstring/provenance describe that
boundary, with `historical_continuity=false`, `projection_used_to_author=false`,
`prior_structure_reconstructed=false`, and alignment=false. The author action
requires that the frozen projection output directory does not yet exist. It
writes bounded schema-validated template/reconciliation files using exclusive
mode0600 creation and fsync. Prior evidence comprises relative target/*.json
paths with exact SHA256; helper/schema hashes are separate. The reconciliation
is an implementer provenance record; independent review remains pending.

Only after authoring did the unchanged frozen projection run. Compare performs
exact full multisets with duplicate counts over namespace/links/addresses/routes/
rules; it never copies projected fields into expected state or rewrites the
baseline. `baseline-comparison.json` and `audit.json` confirm equality. The final
audit independently re-executed only the frozen collector's pure envelope
validator: original PID/start, reaped success, original route-socket identity,
no stderr, original requested_at+2 deadline, original namespace, read-only and
no-authority flags all pass. Retained SSH stdout equals the envelope exactly.

Frozen projection: creator PID **5400**, start **129243**,
namespace **[4, 4026531840]**, route socket **{'dev': 9, 'ino': 26087}**,
requested_at **1292.432222703**, deadline **1294.432222703**,
verified_at **1292.434047785**. A namespace tuple can recur across boots;
the explicit new boot binding, not numeric tuple equality, establishes provenance.

| New artifact | SHA256 |
| --- | --- |
| Canonical baseline | `da3f80f0da4c717443fcb9a2118ed938a6d5c4edeea69d40e755b97291b5a01a` |
| Candidate-local authored-host-baseline-debian-clean-x86_64.json | `4817afb853dea681b52954f863007f59ab286d2896d8358264bd92fc357144e1` |
| Candidate-local host-baseline-reconciliation-debian-clean-x86_64.json | `b2f247d17b1c05ced086611fe88ebda8cadfc5438429cf823fdf2c836afe453d` |
| Candidate-local host-projection-debian-clean-x86_64/record.json | `702cf3176a9828075cb7befb6b5f96be8dff02492b831781da1ab01270891e36` |

New counts are 3/6/19/5, versus the old 61/51/154/5 preservation environment.
This new experiment cannot establish a causal speedup over408. No original failed
endpoint, gateway, namespace or enrollment is preserved by this fresh declaration.
The historical success collector `target/quarantine_evidence_base.py:54` requires
both historical reconstruction/alignment booleans true. It is intentionally
unchanged; it will refuse this fresh baseline. A separately reviewed explicit
fresh-provenance branch is needed before claiming a collected success. Falsifying
the flags to bypass it would be wrong. The Bootstrap runner itself accepts the
truthful strict schema; reservation-only preflight confirms that path.

Two local authoring attempts exited1 before writing baseline outputs: first,
repeated IFLA_ALT_IFNAME entries were incorrectly treated as duplicate scalar
attributes; fixed the property-list decoder to retain both names. Second, the
hand-counted address assertion was7 instead of the actual6 (2 lo+3 ens2+1 docker0);
corrected against retained independent data. Both failures and tracebacks remain
in `baseline-author*.stderr`; neither caused guest mutation or replaced an
existing baseline. The subsequent author and exact multiset comparison exited0.

## D. Explicit run409 reservation

Stock controller scans from1 to the first missing raw JSON after executing the
guest, so an empty lab-state would assign run1 regardless of label. It does not
require an original prior sequence except the historical baseline reference
chain, which is separately replaced by fresh provenance here.

Added `tools/rust-v2-lab/run409-reservation.py`; updated the restored Bootstrap
controller and its archival copy identically, with corresponding source-manifest
size/hash. It supports explicit `--reservation PATH` and `--preflight-only`.
Fresh-candidate unreserved invocation refuses before guest actions; when any409
reservation exists, unreserved fallback also refuses. Historical unreserved
number selection otherwise remains unchanged.

`target/lab-state/run-409-reservation.json` is an exclusive regular0600 file,
run409, label `bootstrap409-driver-cost`, success mode, one-shot budget1,
historical high-water408, raw398–408 unavailable, continuity=fresh-lab. It binds
candidate, authored template/reconciliation, projection, independent comparison,
admission, new helpers, current guest gates, root-verification, source-manifest
and controller bytes. SHA256: `3237686154de18668bee6182f24cc405b8c15a2eaa8d8d03e8305b574c1306e4`.
No actual-program-run-N.json files exist in the fresh lab-state at final audit.

A cooperative exclusive flock spans validation/claim and the future controller
run. Before the first guest action, execution writes `run-409-consumed.json` with
O_EXCL, mode0600, fsync, source reservation hash, PID/controller boot and remaining
budget0. Failure/interruption consumes that attempt; there is no reset/retry API.
Record409 is still written exclusively. Existing or dangling record, consumed
claim, output label directory, wrong parameters, unsafe reservation protection,
input drift or concurrent lock refuse. The lock cannot exclude a malicious or
noncooperating external launcher, but O_EXCL claim and record writes protect
against duplicate cooperating attempts and record replacement.

The new versioned reservation test exercises ten cases: preflight leaves budget
unconsumed, concurrent lock refusal, wrong label, input hash drift, unsafe mode,
dangling record collision, output-directory collision, successful exclusive
claim, retry refusal, duplicate reservation refusal. Tests use a disposable local
temporary directory; the real claim is absent and budget1 remains.

## E. Preflight results and boundaries

Both immutable contexts pass strict four-role/seven-file checks. Independent
candidate verification confirms all203 current build inputs equal the frozen
source commit `1b65709a1189a5fff0fb62c47877e349d4f4f0c4`; its older candidate commit
is deliberate and the application source bytes still match current HEAD.
Source archive `4b0c5af101405476e130c61cbedf041a6542c401e2eb324045982488b9c70807`;
aggregate `4274b1969cb51eddfac9c7fe52442913c0688f1dc1cc24eae8a77c7481e110fd`.
Both payloads are static ELF64, machines62/183, no interpreter/dynamic segment.
No build or candidate ref was recreated.

The unchanged local frozen inspection preflight passed all9 source-selected
mechanical records and the normal-fixture descriptor. Added only the clean
Debian22036 mapping to `run-native-inspection-preflight.py`, mirrored into archive
and manifest; the exact same frozen x86 payload also passed all9 mechanics inside
the guest. This selftest has no netlink transactions, pair creation, actual
namespace movement, actual cgroup creation or quarantine installation. It does
perform bounded rootless socket/filter/process/temporary-file mechanics. Original
negative diagnostics remain intact in its logs.

`phase3-readonly-preflight.py` checks all parent/marker protections, eight selector
absences, WAN, root namespace, pinned image presence, empty containers and cgroup2.
Its root guest process has Seccomp0/filters0/NoNewPrivs0; direct Linux x86 syscall228
clock IDs3 (thread CPU) and7 (BOOTTIME) returned0 with valid timespecs. This proves
chosen syscall/clock availability at that guest process boundary. It does **not**
execute the instrumented frozen Rust driver under its full service/custody path.
ARM64 runtime and a complete instrumented-driver clock sample remain NOT_RUN;
there is no independent clock-only interface in the frozen payload. No Rust/filter
widening or guest provisioning was introduced to manufacture that evidence.

Candidate retained regular single-link owner files are now0600, with the retained
executable preflight500. Existing0644/0664 public logs/metadata were tightened;
`permission-adjustments.json` records each before/after. Template/review are0600
from creation. Previous phase-2 `root-verification.json` and fixed-name frozen
preflight record were moved intact to `phase2-retained-*` under this evidence
directory before invoking the exclusive-output verifiers. No old record was
silently overwritten; `preserved-phase2-verifier-output.json` records the moves.
Original candidate payload/context/source bytes remain unchanged.

Final audit: all293 manifest entries match restored/archive bytes, lengths and
SHA256;590 Python paths compile in memory (586 copies+4 new tools). Five tested
controller/helper `python3 -O` invocations exit1 at the explicit
`optimized_python_refused` guard before execution. New SSH config proofs pass;
baseline full shape/provenance/deadline checks pass; pinned digests match; index is
empty; HEAD unchanged; `git diff --check` exits0.

### Exact future command — recorded only, NOT_RUN

```sh
python3 target/platform-lab/run-frozen-secret-bootstrap.py target/candidates/rebuild-20261103T231415Z/candidate.json debian-clean-x86_64 bootstrap409-driver-cost success --reservation target/lab-state/run-409-reservation.json
```

The same command with final `--preflight-only` **was** executed, exit0. It runs
source/hash/binding, static ELF, immutable context, template protection/schema,
review/ref hashes and guest-program compilation gates, validates reservation and
returns before out.mkdir/SSH listing/SCP/fixture execution. Real claim, raw409 and
label output directory are absent after it. Current guest prechecks independently
pass at the recorded observations; future mutation-dependent gates cannot be
proven by a preflight-only run.

| Gate | Status at handoff |
| --- | --- |
| Source/ELF/context/binding/template/review/reference gates before first guest action | PASS, reservation-only controller exited0 |
| Full authored fresh namespace/structural baseline vs frozen projection | PASS, custody/original two-second read window validated |
| Current guest boot/QEMU, marker/parents, selectors absent, WAN, Docker/images, cgroup/headroom | PASS at observations; must remain true at actual invocation |
| Exact frozen x86 rootless inspection/filter mechanics, controller and guest | PASS; no provisioning/Bootstrap acceptance implied |
| x86 guest chosen CPU/boot clock syscall availability | PASS for direct syscall probe only |
| Full frozen driver clock sampling/service/runtime custody and ARM64 runtime | NOT_RUN; requires future authorized path, ARM is compile/static-only |
| Exclusive409 numbering, parameter/hash/protection/collision checks, one-shot budget1 | PASS; reservation unconsumed |
| Image build, synthetic descriptor/profile/input custody, inert-container birth/PID/namespace, owner/cgroup, held negatives, Bootstrap/deadline/outcome and preservation | NOT_RUN; these require prohibited fixture/runtime actions |
| Independent review of new helpers/template/provenance/reservation and Root checkpoint/push/remote confirmation | NOT_RUN; orchestrator responsibility, no delegation/Git writes allowed here |
| Historical raw replay/original identity/resource preservation | NOT_RUN/UNRECOVERABLE; explicit gap disposition |
| Historical success collector compatibility with fresh provenance | OPEN; explicit new branch/review required, old truthful flags are false |

It would be inaccurate to say every eventual runtime gate is confirmed to pass.
All locally executable pre-execution gates above pass; the enumerated later gates
are explicitly untested. No automatic retry or run409 execution is authorized by
this report/reservation. Host stability remains point-in-time evidence despite the
brief's prior soak. Reboot or drift invalidates these boot-bound observations;
review/rebaseline is required rather than silently editing bound files.

## Exact execution command ledger

All commands below ran from the workspace through
`python3 target/rebuild-phase3/record-command.py LABEL COMMAND...`. The command JSON
and matching `.stdout`/`.stderr` are the full receipts; no output was truncated on
disk. Nested guest argv/return codes are in admission JSON, and source bodies are
retained. Setup/edit Python and shell snippets in the session completed0 except
the explicitly disclosed read-only `rg`/`sed` absent-path searches (exit2) and
ordinary no-match searches. They performed the named evidence creation/moves,
controller/archive/manifest edits and permission changes only.

| Receipt label | Exact command | Exit |
| --- | --- | ---: |
| `admission-status` | `python3 tools/rust-v2-lab/lab-guest-status.py` | 0 |
| `admission` | `python3 target/rebuild-phase3/collect-admission.py` | 0 |
| `independent-collect` | `python3 tools/rust-v2-lab/fresh-baseline.py collect target/candidates/rebuild-20261103T231415Z/candidate.json target/rebuild-phase3` | 0 |
| `baseline-author` | `python3 tools/rust-v2-lab/fresh-baseline.py author target/candidates/rebuild-20261103T231415Z/candidate.json target/rebuild-phase3` | 1 |
| `baseline-author-fixed` | `python3 tools/rust-v2-lab/fresh-baseline.py author target/candidates/rebuild-20261103T231415Z/candidate.json target/rebuild-phase3` | 1 |
| `baseline-author-final` | `python3 tools/rust-v2-lab/fresh-baseline.py author target/candidates/rebuild-20261103T231415Z/candidate.json target/rebuild-phase3` | 0 |
| `frozen-projection` | `python3 target/platform-lab/run-frozen-host-projection.py target/candidates/rebuild-20261103T231415Z/candidate.json debian-clean-x86_64` | 0 |
| `baseline-compare` | `python3 tools/rust-v2-lab/fresh-baseline.py compare target/candidates/rebuild-20261103T231415Z/candidate.json target/rebuild-phase3` | 0 |
| `contexts` | `python3 target/copy-frozen-contexts.py target/candidates/rebuild-20261103T231415Z/candidate.json` | 0 |
| `candidate-verify` | `python3 target/verify-continuation-candidate.py target/candidates/rebuild-20261103T231415Z/candidate.json` | 0 |
| `inspection-preflight` | `python3 target/verify-frozen-inspection-preflight.py target/candidates/rebuild-20261103T231415Z/candidate.json` | 0 |
| `guest-inspection-preflight` | `python3 target/platform-lab/run-native-inspection-preflight.py target/candidates/rebuild-20261103T231415Z/candidate.json debian-clean-x86_64` | 0 |
| `reservation-tests` | `python3 target/rebuild-phase3/test-reservation.py` | 0 |
| `guest-gates` | `python3 tools/rust-v2-lab/phase3-readonly-preflight.py target/rebuild-phase3/guest-gates.json` | 0 |
| `reservation-tests-final` | `python3 tools/rust-v2-lab/test-run409-reservation.py` | 0 |
| `reserve409` | `python3 tools/rust-v2-lab/run409-reservation.py reserve` | 0 |
| `bootstrap-reservation-preflight` | `python3 target/platform-lab/run-frozen-secret-bootstrap.py target/candidates/rebuild-20261103T231415Z/candidate.json debian-clean-x86_64 bootstrap409-driver-cost success --reservation target/lab-state/run-409-reservation.json --preflight-only` | 0 |
| `final-audit` | `python3 target/rebuild-phase3/audit.py` | 0 |
| `final-status` | `python3 tools/rust-v2-lab/lab-guest-status.py` | 0 |

The two authoring exit1 rows are the real local implementation failures described
above. Guard-test exit1 results are expected refusal proofs recorded individually
in `audit.json`. No failed runtime experiment was consumed or relabeled.

## Files changed and retained

Tracked modifications, all unstaged:

- `tools/rust-v2-lab/target/platform-lab/run-frozen-secret-bootstrap.py`: explicit
  reservation/claim/preflight boundary and reserved409 record path/provenance.
- `tools/rust-v2-lab/target/platform-lab/run-native-inspection-preflight.py`: one
  clean-Debian platform mapping, existing confinement/mechanics unchanged.
- `tools/rust-v2-lab/source-manifest.json`: exactly those two archive entries'
  byte counts/SHA256 changed; all293 source/archive entries verified.

New versioned candidates, untracked/unstaged:

- `tools/rust-v2-lab/fresh-baseline.py`, SHA256 `73aedfc65bfa66b72a90b3914d8bf97c87aabd4d7f1f76e054a2a29343942429`.
- `tools/rust-v2-lab/run409-reservation.py`, SHA256 `eed74b21a150813d0ac702b6ea8a10a41e03e28e3f54ef0c83bf5774ed6fa425`.
- `tools/rust-v2-lab/phase3-readonly-preflight.py`, SHA256 `524debb253dcb9fbd60de68f7d807024376ed999ba841d8c7f81e77b97f89bb1`.
- `tools/rust-v2-lab/test-run409-reservation.py`, SHA256 `9065513aea4613fb176d612fc711667c01dd9422839126f71c30f801593a1ad7`.

New ignored reports: this file and `task-8c-historical-gap-disposition.md`.
New/updated ignored state: `target/rebuild-phase3/` including scripts, full raw
admission/netlink/frozen-envelope/check outputs, prior retained outputs and audit;
candidate-local authored template, reconciliation, host projection directory,
new root verification and native-preflight directory; new fixed-name controller
frozen-preflight JSON; restored copies of the two changed archived controllers;
`target/lab-state/run-409-reservation.json` and local cooperative lock. Ordinary
Python imports may create ignored `__pycache__` alongside the relevant tools.
Candidate permission-only changes are explicitly recorded. Existing keys, trust,
disks, seeds, guest identities and process records were not changed.

Guest file-only additions inherently made by the permitted read-only projection
and rootless selftest: retained digest-verified0500 executable copies in new
`/home/vprouterlab/vprouter-host-projection-*` and
`/home/vprouterlab/vprouter-frozen-preflight-*` temporary directories, plus selftest
birth/temporary proof files. Their paths/PID/start/result are in the respective
projector/native-preflight records. These are disclosed file writes; they did not
change guest networking, namespaces, nft or containers. Guest status at handoff
still matches the brief boot and QEMU identity.
