# Task 8c run 411 ARM64 preparation report

2026-11-06, shared checkout `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`.
**Preparation PASS; exact run411 `--preflight-only` PASS. Run411 NOT_RUN;
one-shot budget 1.** The guest remains running for run411. Run409/run410 stay
consumed, budget0; their snapshotted state bytes are unchanged. Task8c runtime,
full Bootstrap witness and release acceptance are not established here.

Evidence: `target/run411-prep/` is a symlink to
`/DATA/vprouter-lab/run411-prep/`; these are the same durable evidence directory,
not two independently collected datasets. `*.command.json` records exact argv,
UTC, cwd, exit, elapsed wall time and complete stdout/stderr filenames. The full
command ledger follows below, including expected red tests and failed probes.
All scratch program sources remain there. `SHA256SUMS` inventories the final
regular evidence files; stateful guest files remain in `target/platform-lab/debian-arm64/`.

No subagents, cargo, debdev sudo, Git staging/commit/push, production changes,
provider enrollment or provider credentials were used. Only this disposable
lab received guest sudo. External network activity was cloud-init apt; no registry image
pull, provider connection or external download was made by this task.

## Scope and shared checkout

Entry HEAD was `35c3befd8e8bee60b00630d0a9171eefaad199ac`. Concurrent witness-validator work later
committed `848b46852d229ce5557998283053b60ebbee4e08`. Its five paths are recorded in
`final-preservation.json`; none belongs to this implementation scope. The index
also changed with that concurrent commit. This task performed no Git writes
and did not restore/reset/stash any shared work. It did not edit
`tools/performance/*`, `validate-run410-witness.py` or its test, witness reports,
or the concurrent progress log.

Task-owned maintained edits: `tools/rust-v2-lab/README.md`,
`fresh-baseline.py`, `phase3-readonly-preflight.py`; new `run411-reservation.py`,
`run411-provenance.py`, `collect-run411-evidence.py`, `inspect-run411-state.py`,
`source-manifest411.json`, six `test-run411-*.py` suites, and the four new archived
`target/` source paths listed by `source-manifest411.json`. The restored copies
are identical to their archives. The original296-entry source manifest and
all original409/410 controller/guest/F/A sources are unchanged.

No access or modification to `/DATA/vprouter-lab/preserved/` was needed.
`verify-preserved-run409.py` was read, not run: rehashing that cold archive was
outside this preparation scope. Entry/final comparisons cover17 current state
and frozen candidate files, including both old consumed claims, raw records,
and reservations; all retained SHA256 values match. New ARM64 baseline and
projection files were added under the existing frozen candidate directory;
`candidate.json`, both frozen ARM64 inputs, and all old x86/410 entries remain
unchanged. The frozen source revision remains da75562, independent of the
shared checkout's later witness-only commit.

## Fresh ARM64 substrate and trust

`start-clean-debian-arm64.py` is a fork of the reviewed fresh410 launcher. It
refuses optimized Python, invalid/non411 instance IDs, any existing state
(including dangling symlinks), an occupied port, an incomplete/unqualified
sandbox bisect, or any live QEMU. It holds the cooperative lifecycle lock from
admission through image/seed creation and launch. No prior overlay is reused.

The supplied bisect output contained `full PASS exit=0 50s` and `BISECT_DONE`,
and no aarch64 QEMU was running before launch. The launcher additionally checked
all qemu-system process names under `/proc`. The selected strongest qualified
sandbox is `on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny`. The earlier unsandboxed/sandbox smoke attempts were
not repeated; the controller's supplied bisect and smoke files were read only.

The base SHA512 was recomputed before creating the fresh overlay, and matched
both the pinned checksum manifest and fixed expected digest:
`e66eea33be9e1345e6c8737e65096e5b31031f4bd4f3f7d59a6f8b53f995a9c41996e97c5b4ab89f1587663efed11dfbd10c4d35b7bcc85b2545e58a12cd0e83`.
Image: `/DATA/AppData/vprouter-rust-v2/target/lab-images/debian-13-genericcloud-arm64-20261021-2638.qcow2`.
A24GiB qcow2 overlay uses that verified base read-only as its backing image.
Fresh cloud-init seed/instance and a private copy of AAVMF VARS were created;
CODE is attached pflash read-only. Guest packages and lab marker/runcmd match
410: docker.io, nftables, iproute2, wireguard-tools, tcpdump, python3, sudo,
openssh-server. No enrollment or identity state was imported.

| Identity | Observed value |
| --- | --- |
| Instance | `vprouter-run411-20261106T1251Z` |
| QEMU PID / start tick | `493434` / `5902200` |
| QEMU | 10.0.13, Debian1:10.0.13+ds-0+deb13u1 |
| Accelerator / machine / CPU | `tcg,thread=multi` / `virt,gic-version=3` / `cortex-a72` |
| vCPUs / RAM | 2 /1024MiB (no increase) |
| Guest boot | `525e9103-b2f9-4611-a663-ced9d001245a` |
| Guest machine | `f02b6d586b1a4a89969d2dcb038cb8a6` |
| Controller boot | `07dbae6e-6ed8-4bb3-a468-f89265c8dd6b` |
| Endpoint | `vprouterlab@127.0.0.1:22034` |
| Host fingerprint | `256 SHA256:gb9fYXx9EPUL8goCdkT8Q9JKVTEE0hHW4tje9aQOwBM [127.0.0.1]:22034 (ED25519)` |
| known_hosts SHA256 | `bf37ae607c4ff4e5f3de2a4ef2244e8e7dea3919448b22a12cc6690c399200d1` |

Launch started at12:50:58.871Z; cloud-init serial reports final completion at
12:54:20Z, guest uptime187.83s (about201s wall from launch command start).
Strict SSH observed `bootstrap-complete` at the12:54:38.587Z status command,
which finished3.941s later. Provisioning therefore completed in under four
minutes, well below the possible20–40min apt interval. The exact cloud-init
finish line and serial remain in the guest state; no reset/restart occurred.

Pinning followed410's owned serial/console method: QEMU PID/start/full argv were
checked, exactly one ed25519 public key was required between cloud-init's host
key markers, then known_hosts was exclusively created and chmod0600. No
network keyscan or TOFU was used. The first premature pin command refused
because zero public key rows had appeared; it wrote no pin. The later console
pin and strict SSH passed. `serial-at-trust.log` and `host-trust.json` retain
this custody chain. `ssh-G.json` proves9 actual constructors (prep, baseline,
phase3 gates, state inspector, runner, F/A, SCP variants), with dedicated key,
explicit single pin, `-F /dev/null`, GlobalKnownHostsFile=/dev/null,
IdentitiesOnly=yes, IdentityAgent=none and strict checking; no proxy route.
Configuration proof is separate from transfer proof.
Real strict SCP of synthetic public bytes was measured separately below.

`substrate.json` records read-only QMP status, block chain, firmware attachments,
1024MiB memory and version. The guest was running with the same PID/start/argv
at handoff. The live state is point-in-time evidence, not a soak guarantee.

## ARM64 admission and independent baseline

`phase3-readonly-preflight.py --platform debian-arm64 --expected-boot-id
525e9103-b2f9-4611-a663-ced9d001245a` passed initial and final checks. The ARM64 route uses
`enp0s1`, index2, MAC52:54:00:12:34:56 and aarch64 clock_gettime syscall113 for
clock3/7. Both direct clock syscalls pass, root Seccomp=0, cgroup2 and Docker
active, protected marker/parent modes pass, all fixed selectors are absent,
and no containers exist. The original x86 default and syscall228 stay intact.
This clock check does not execute the Bootstrap driver.

Deviation from410's guest gates: no registry images were pulled or required
for ARM64 admission, per the apt-only network limit. The runner builds an
explicit `FROM scratch` fixture without RUN/pull/network. Instead, a new local
strict inventory checks the frozen ARM64 context's seven files/four program
roles, fixed daemon/CA pins, ELF machine183, no interpreter/dynamic segments,
manifest, source and payload hashes. Receipt: `inventory-arm64.json`.
`pinned_images_inspected=false` is truthful; no guest registry-image proof is
claimed. `verify-frozen-build-inputs.py` verifies203 frozen application inputs.

| Immutable input | SHA256 |
| --- | --- |
| Candidate | `ea3634b4e4140b3b3db8fdaf12b9c47c1b3757c9862f33001cbc022ef2d225f6` |
| Source | `899dd5c843f6af2d86305e0380ca79006570de874d9356b725f24e91b09d8959` |
| ARM64 payload | `5b78458c995556227417cb7939e13cc811dba3ad8dbcdfdd342404df84e09631` |
| ARM64 context | `51023de0b7bbab71a40e1882662d50327d8643f1f45051c466655207666f406d` |

The independent RTM_GET collection at12:55:00.695Z was cross-checked with
separate iproute2 admission. Authoring at12:55:01.533Z occurred before the
ARM64 frozen projection directory existed. The original frozen projector ran
at12:56:12.225Z, exit0; full multiset comparison at12:56:16.723Z passed.
The stable shape is3links/6addresses/19routes/5rules, namespace
`[4, 4026531840]`, baseline SHA256
`6ea00a3760011e1af3d4c64484e19ce425591da983e6825460d7e1e0075a599b`. Complete namespace/link/address/route/rule
records and multiplicities match; no sorting-only or count-only oracle was used.
The original projection's PID/start/reap/socket/read-only/authority/two-second
validation is also rechecked by411 provenance. Its observed child span was
0.127042s and internal GET interval
0.086322s. No product deadline was extended.

A fresh final kernel dump after all benchmarks still matches the authored
baseline as complete multisets (`final-netlink.json`, `final-live-state.stdout`).
Historical continuity, historical reconstruction, historical ordering alignment,
projection-used-to-author and host authority remain false. Historical ARM
preservation templates were read for conventions; none was reused or relabeled.

## Measured TCG overhead and budgets

No LAB-TIMEOUT-ONLY adjustment was needed. The411 fork keeps410's original
SCP30/45s, guest outer250s, build75s, owner launcher120s and RuntimeMaxSec110s.
The frozen guest program, payload, context and all product deadlines/windows
remain byte-identical to410's frozen inputs.

| Measurement | Samples in seconds | Relevant unchanged lab budget |
| --- | --- | --- |
| Python startup | 0.091101,0.080371,0.073336 | small part of outer250 |
| transient systemd-run /bin/true | 0.312948,0.205799,0.158326 | launcher120 /RuntimeMaxSec110 |
| cold --no-cache FROM-scratch48MiB build | 17.137,19.787 | build75 |
| actual SCP synthetic15,235,840-byte file | 1.751225 | payload30 |
| actual SCP synthetic49,377,280-byte file | 2.331300 | context45 |

The benchmark sources, exact argv, stdout/stderr and guest/controller wall times
are retained in `tcg-bench-remote.py`, `tcg-measurements.json`,
`benchmark-transfer.py`, `scp-measurements.json`, and `tcg-budgets.json`.
The transferred bytes are public synthetic fixtures, verified by size/SHA256
inside the guest; no Bootstrap upload filename or payload was staged by these
measurements. Scratch build inputs are synthetic and FROM scratch, network
none/pull false, no RUN instruction. They created two benchmark images labeled
`run411.prep`; no container or owner Bootstrap ran. Files remain under
`/var/tmp/run411-prep-tcg` and `/home/vprouterlab/run411-prep-transfer-*.bin`;
the images are retained in `final-live-state.stdout`. They cannot hit the
frozen Dockerfile/context cache keys.

Limits: two synthetic builds are not a statistical bound or an exact frozen
context build; systemd /bin/true measures launcher overhead only. The owner
Bootstrap and aggregate250s path remain NOT_RUN. The measurements identify no
forced timeout overflow; they do not prove Bootstrap will meet its protocol
windows. Any real failure consumes411; it never permits a retry or a product
deadline adjustment under the existing reservation.

## Isolated411 chain and compile/preflight gates

Fixed411 tuple: platform `debian-arm64`, label `bootstrap411-arm64`, mode
`success`, candidate `target/candidates/run410-da75562-20261104/candidate.json`.
All35 mandatory bindings include the ARM64 inventory/context/payload hashes,
new guest identity/pin/process, baseline/reconciliation/projection, gates,
budget evidence, execution and post-run controller bytes. Neither prior claim
nor prior raw record is a binding or an input to the411 tooling. Reservation
creation validates fresh411 instance/PID/start/boot identity without reading
410's claim. Its historical high-water mark is410; preserved-prior-run409
metadata describes the cold historical archive and grants no continuity.

Active reservation SHA256:
`2c076f625c15516c31daa6ff14a2985d6906631ab2cba5f553f26875473ee62d`. Schema2, budget1, fresh-lab. There are two
forward-only preparation generations: the initial reservation and one retained
superseded generation correcting a copied high-water mark from409 to410.
`run-411-supersession.json` binds both generations; old bytes remain. No claim
was present during that transition and no claim was created. Supersession
never resets the single global411 claim or replenishes budget. The original
409/410 chains were not read by this implementation path or modified.

The runner requires explicit reservation in both real and preflight modes,
rejects non411/platform/label/mode invocations, and never falls back to scanning
for another run number. The original exclusive lock/claim/fsync, protected
state, exact binding, stale generation, collision and spent-budget checks remain.
Before any claim, it validates fresh provenance and compiles the exact boot-
prefixed listing and configured guest plus both embedded host/baseline builders.
The same four compiled strings are reused. Tests inject a SyntaxError in each
program for both real/preflight paths and verify no claim is created.

`admit(..., preflight=True)` skips its only `save(CLAIM,...)`. The runner then
prints PASS and exits before output directory creation, listing SSH, either SCP,
or guest execution. Code inspection and synthetic compile/admission tests
confirm this; the exact command's output is retained in
`exact411-preflight-final.stdout`:

```json
{"reservation_preflight":"PASS","remote_program_compile":"PASS","compiled_remote_programs":["baseline-declaration","guest","host-declaration","listing"],"run":411,"budget_remaining":1,"guest_actions_executed":false}
```

The exact execution command, **NOT RUN**, is:

```sh
python3 -B target/platform-lab/run-frozen-secret-bootstrap411.py target/candidates/run410-da75562-20261104/candidate.json debian-arm64 bootstrap411-arm64 success --reservation target/lab-state/run-411-reservation.json
```

Only that argv plus final `--preflight-only` was invoked. At final verification
`run-411-consumed.json`, `actual-program-run-411.json`, controller-error receipt,
and candidate output directory `bootstrap411-arm64/` are absent. The cooperative
lock is a preparation artifact, not a claim.

C/I/F/A are411-specific forks. Reservation file I/O and collector capture reject
run410 state paths, including a poisoned binding/reference. F/A reject other
run numbers before opening binding/raw records, and require the canonical411
reservation path before following a provenance marker. They retain original
owner-absence/gateway PID/start/StartedAt/pidfd/namespace and exact selector
inode/hash/mode checks, and compile remote programs before SSH. The state
inspector uses port22034; its test caught and corrected a copied22036 before
reservation. C preserves recursive baseline references and immutable generation
receipts before validation, and reports preservation separately from full
Bootstrap witness/runtime acceptance. Post-run C→I remains first; failure-only
P/F/A require their qualifying evidence/review. Real C/I/P/F/A were NOT_RUN.

## Verification and retained failures

The six411 suites pass: launcher4tests; ARM admission2tests; reservation12checks;
provenance21tests; isolation41tests (includes inherited provenance coverage);
fixes8groups, including four preclaim compile failures in both modes,
F/A downgrade refusal, interrupted generation chains, collection and transport
receipts. The original410 suites pass: reservation12, provenance21,
isolation21, fixes8. Existing fresh-baseline5, phase3-fixes8 and phase3b21 also pass.
634 restored/archive/maintained Python paths pass `py_compile`;334 archived/
maintained sources also compiled in memory during static audit. All300 source
manifest triples pass (original296 plus4 new411 pairs).30 optimized-Python
runtime entrypoint probes refuse under -O/-OO/PYTHONOPTIMIZE=1 before work.
`git diff --check` passes; untracked Python source compilation and manifests
also cover new files that a plain diff cannot see. No Rust/build inputs changed,
so cargo/Rust rebuilds were not run.

Expected TDD red receipts precede missing launcher/tool/platform and safety
implementations. Other retained unsuccessful probes: premature console pin;
first411 historical F/A test expectations (411 deliberately has no historical
run fallback); inspector endpoint regression; static-audit's first optimized
probe mistakenly treated a cwd-dependent test as a runtime entrypoint; final
preservation's first attempt correctly detected the concurrent HEAD change.
The corrected preservation audit reports that change rather than asserting an
unchanged index. A later optional handoff script initially tried to reuse the
411 SHA helper for preservation reads of410 state; the intended run410 access
guard refused it before reading. Its separate corrected scratch script uses
ordinary read-only hashing for the preservation comparison. Both scripts and
the refusal remain; no411 runtime guard was weakened. Sources and error outputs are retained; no failed evidence was
removed or relabeled as success. The high-water correction used an explicit
retained411 supersession, not reservation deletion/overwrite.

## Remaining scope and handoff

The guest remains running at PID493434, start tick5902200, boot
`525e9103-b2f9-4611-a663-ced9d001245a`, with its original fresh overlay, VARS, seed and pin.
`handoff-status.stdout`, `final-preservation.json`, `final-live-state.stdout`,
`final-guest-gates.json` and `substrate.json` contain the evidence. The fresh
fixture root contains only `bootstrap-complete` and `isolated-acceptance`;
there are no containers, secret-attachment uploads, fixed selectors, owner
protocol or inert Bootstrap gateway from this preparation.

NOT_RUN: actual411 Bootstrap/claim, exact frozen-context build and inert gateway,
owner/pidfd/custody/Bootstrap lifecycle, full typed witness acceptance, driver
CPU/sleep/constructor runtime collection, failure archival, historical replay,
real-client/provider/migration/performance/soak/release acceptance. No runtime
success or release readiness is inferred from this preparation.

## Exact preparation/validation command ledger

All commands below ran from the repository root. Paths to complete outputs are
recorded by the correspondingly named `*.command.json` receipt. Exit1 is
preserved for expected red tests or identified failed probes, not omitted.

| UTC start | Exit | Wall seconds | Exact argv |
| --- | ---: | ---: | --- |
| 2026-11-06T12:50:22.456397+00:00 | 1 | 0.270 | `python3 -B tools/rust-v2-lab/test-run411-launcher.py` |
| 2026-11-06T12:50:51.286254+00:00 | 0 | 0.051 | `python3 -B tools/rust-v2-lab/test-run411-launcher.py` |
| 2026-11-06T12:50:58.871337+00:00 | 0 | 1.071 | `python3 -B target/platform-lab/start-clean-debian-arm64.py --instance-id vprouter-run411-20261106T1251Z` |
| 2026-11-06T12:51:19.553789+00:00 | 1 | 0.028 | `python3 -B tools/rust-v2-lab/test-run411-reservation.py` |
| 2026-11-06T12:51:19.597102+00:00 | 1 | 0.101 | `python3 -B tools/rust-v2-lab/test-run411-provenance.py` |
| 2026-11-06T12:51:48.813276+00:00 | 0 | 0.272 | `python3 -B tools/rust-v2-lab/test-run411-reservation.py` |
| 2026-11-06T12:51:49.102481+00:00 | 0 | 1.166 | `python3 -B tools/rust-v2-lab/test-run411-provenance.py` |
| 2026-11-06T12:51:50.291493+00:00 | 0 | 0.566 | `python3 -B tools/rust-v2-lab/test-run411-isolation.py` |
| 2026-11-06T12:51:50.876830+00:00 | 1 | 0.388 | `python3 -B tools/rust-v2-lab/test-run411-fixes.py` |
| 2026-11-06T12:52:22.976460+00:00 | 1 | 0.275 | `python3 -B tools/rust-v2-lab/test-run411-arm64-baseline.py` |
| 2026-11-06T12:52:23.290497+00:00 | 0 | 0.035 | `python3 -B tools/rust-v2-lab/test-run411-arm64-baseline.py` |
| 2026-11-06T12:52:23.340853+00:00 | 0 | 0.416 | `python3 -B tools/rust-v2-lab/test-run411-fixes.py` |
| 2026-11-06T12:52:46.561964+00:00 | 1 | 0.066 | `python3 -B target/run411-prep/pin-host-key.py` |
| 2026-11-06T12:53:27.799864+00:00 | 0 | 0.514 | `python3 -B target/run411-prep/inspect-frozen.py` |
| 2026-11-06T12:53:28.330708+00:00 | 0 | 0.335 | `python3 -B tools/verify-frozen-build-inputs.py target/candidates/run410-da75562-20261104/source.tar da7556282d5fc828a9391a64ab47adab05a55510` |
| 2026-11-06T12:53:50.708619+00:00 | 1 | 0.597 | `python3 -B tools/rust-v2-lab/test-run411-isolation.py` |
| 2026-11-06T12:53:51.334882+00:00 | 0 | 0.580 | `python3 -B tools/rust-v2-lab/test-run411-isolation.py` |
| 2026-11-06T12:54:09.578154+00:00 | 0 | 0.314 | `python3 -B tools/rust-v2-lab/test-run410-isolation.py` |
| 2026-11-06T12:54:09.578943+00:00 | 0 | 0.079 | `python3 -B tools/rust-v2-lab/test-fresh-baseline.py` |
| 2026-11-06T12:54:09.580204+00:00 | 0 | 0.319 | `python3 -B tools/rust-v2-lab/test-phase3-fixes.py` |
| 2026-11-06T12:54:09.583612+00:00 | 0 | 0.389 | `python3 -B tools/rust-v2-lab/test-run410-fixes.py` |
| 2026-11-06T12:54:09.585742+00:00 | 0 | 0.044 | `python3 -B tools/rust-v2-lab/test-run410-reservation.py` |
| 2026-11-06T12:54:09.586680+00:00 | 0 | 0.293 | `python3 -B tools/rust-v2-lab/test-run410-provenance.py` |
| 2026-11-06T12:54:09.589305+00:00 | 0 | 0.266 | `python3 -B tools/rust-v2-lab/test-phase3b-provenance.py` |
| 2026-11-06T12:54:37.799933+00:00 | 1 | 0.354 | `python3 -B tools/rust-v2-lab/test-run411-fixes.py` |
| 2026-11-06T12:54:38.181157+00:00 | 0 | 0.332 | `python3 -B tools/rust-v2-lab/test-run411-fixes.py` |
| 2026-11-06T12:54:38.529117+00:00 | 0 | 0.042 | `python3 -B target/run411-prep/pin-host-key.py` |
| 2026-11-06T12:54:38.587071+00:00 | 0 | 3.941 | `python3 -B target/run411-prep/status.py` |
| 2026-11-06T12:54:56.564370+00:00 | 0 | 3.037 | `python3 -B target/run411-prep/collect-admission.py` |
| 2026-11-06T12:54:59.618841+00:00 | 0 | 1.058 | `python3 -B tools/rust-v2-lab/phase3-readonly-preflight.py target/run411-prep/guest-gates.json --platform debian-arm64 --expected-boot-id 525e9103-b2f9-4611-a663-ced9d001245a` |
| 2026-11-06T12:55:00.694986+00:00 | 0 | 0.807 | `python3 -B tools/rust-v2-lab/fresh-baseline.py --platform debian-arm64 --expected-boot-id 525e9103-b2f9-4611-a663-ced9d001245a collect target/candidates/run410-da75562-20261104/candidate.json target/run411-prep` |
| 2026-11-06T12:55:01.532722+00:00 | 0 | 0.077 | `python3 -B tools/rust-v2-lab/fresh-baseline.py --platform debian-arm64 --expected-boot-id 525e9103-b2f9-4611-a663-ced9d001245a author target/candidates/run410-da75562-20261104/candidate.json target/run411-prep` |
| 2026-11-06T12:55:15.971770+00:00 | 0 | 40.467 | `python3 -B target/run411-prep/tcg-bench.py` |
| 2026-11-06T12:56:12.225445+00:00 | 0 | 4.481 | `python3 -B target/platform-lab/run-frozen-host-projection.py target/candidates/run410-da75562-20261104/candidate.json debian-arm64` |
| 2026-11-06T12:56:16.723449+00:00 | 0 | 0.105 | `python3 -B tools/rust-v2-lab/fresh-baseline.py --platform debian-arm64 --expected-boot-id 525e9103-b2f9-4611-a663-ced9d001245a compare target/candidates/run410-da75562-20261104/candidate.json target/run411-prep` |
| 2026-11-06T12:56:16.846466+00:00 | 0 | 6.021 | `python3 -B target/run411-prep/benchmark-transfer.py` |
| 2026-11-06T12:56:33.410784+00:00 | 0 | 0.069 | `python3 -B target/run411-prep/ssh-proof.py` |
| 2026-11-06T12:57:07.608852+00:00 | 0 | 0.055 | `python3 -B target/run411-prep/author-tcg-budgets.py` |
| 2026-11-06T12:57:07.679135+00:00 | 1 | 1.745 | `python3 -B target/run411-prep/static-audit.py` |
| 2026-11-06T12:57:09.442513+00:00 | 0 | 2.719 | `python3 -B tools/rust-v2-lab/run411-reservation.py reserve` |
| 2026-11-06T12:57:12.190998+00:00 | 0 | 0.567 | `python3 -B target/platform-lab/run-frozen-secret-bootstrap411.py target/candidates/run410-da75562-20261104/candidate.json debian-arm64 bootstrap411-arm64 success --reservation target/lab-state/run-411-reservation.json --preflight-only` |
| 2026-11-06T12:57:57.662175+00:00 | 0 | 2.989 | `python3 -B target/run411-prep/static-audit.py` |
| 2026-11-06T12:58:00.670361+00:00 | 0 | 0.558 | `python3 -B target/run411-prep/substrate.py` |
| 2026-11-06T12:58:20.134041+00:00 | 0 | 3.770 | `python3 -B target/run411-prep/live-final.py` |
| 2026-11-06T12:58:23.920140+00:00 | 0 | 2.017 | `python3 -B tools/rust-v2-lab/phase3-readonly-preflight.py target/run411-prep/final-guest-gates.json --platform debian-arm64 --expected-boot-id 525e9103-b2f9-4611-a663-ced9d001245a` |
| 2026-11-06T12:58:32.950005+00:00 | 0 | 0.024 | `python3 -B tools/rust-v2-lab/test-run411-reservation.py` |
| 2026-11-06T12:58:32.951191+00:00 | 0 | 0.046 | `python3 -B tools/rust-v2-lab/test-run411-arm64-baseline.py` |
| 2026-11-06T12:58:32.951655+00:00 | 0 | 0.083 | `python3 -B tools/rust-v2-lab/test-run411-launcher.py` |
| 2026-11-06T12:58:32.952390+00:00 | 0 | 0.284 | `python3 -B tools/rust-v2-lab/test-run411-provenance.py` |
| 2026-11-06T12:58:32.954699+00:00 | 0 | 0.598 | `python3 -B tools/rust-v2-lab/test-run411-isolation.py` |
| 2026-11-06T12:58:32.955649+00:00 | 0 | 0.360 | `python3 -B tools/rust-v2-lab/test-run411-fixes.py` |
| 2026-11-06T12:58:33.582601+00:00 | 0 | 0.565 | `python3 -B target/run411-prep/pycompile.py` |
| 2026-11-06T12:58:34.163125+00:00 | 0 | 0.006 | `git diff --check` |
| 2026-11-06T12:59:12.841623+00:00 | 1 | 0.026 | `python3 -B tools/rust-v2-lab/test-run411-reservation.py` |
| 2026-11-06T12:59:12.897082+00:00 | 0 | 0.026 | `python3 -B tools/rust-v2-lab/test-run411-reservation.py` |
| 2026-11-06T12:59:12.939503+00:00 | 0 | 0.231 | `python3 -B tools/rust-v2-lab/run411-reservation.py supersede --expected-sha256 cb95853c3001e8a6e2c3da424bb1b97aa7938ce4d0b383335a77a253c097ae42 --reason 'Run411 metadata must advance historical high-water mark from consumed 409 to consumed 410 without reading or binding either prior claim; no budget consumed.'` |
| 2026-11-06T12:59:13.187177+00:00 | 0 | 0.508 | `python3 -B target/platform-lab/run-frozen-secret-bootstrap411.py target/candidates/run410-da75562-20261104/candidate.json debian-arm64 bootstrap411-arm64 success --reservation target/lab-state/run-411-reservation.json --preflight-only` |
| 2026-11-06T12:59:38.086999+00:00 | 0 | 0.298 | `python3 -B tools/rust-v2-lab/test-run411-provenance.py` |
| 2026-11-06T12:59:38.087073+00:00 | 0 | 0.333 | `python3 -B tools/rust-v2-lab/test-run411-fixes.py` |
| 2026-11-06T12:59:38.090218+00:00 | 0 | 0.540 | `python3 -B tools/rust-v2-lab/test-run411-isolation.py` |
| 2026-11-06T12:59:38.709267+00:00 | 0 | 0.572 | `python3 -B target/run411-prep/pycompile.py` |
| 2026-11-06T12:59:39.297851+00:00 | 1 | 0.069 | `python3 -B target/run411-prep/final-preservation.py` |
| 2026-11-06T12:59:39.382888+00:00 | 0 | 1.713 | `python3 -B target/run411-prep/status.py` |
| 2026-11-06T13:00:15.798680+00:00 | 0 | 0.128 | `python3 -B target/run411-prep/final-preservation.py` |
| 2026-11-06T13:02:38.169311+00:00 | 1 | 0.345 | `python3 -B target/run411-prep/handoff-audit.py` |
| 2026-11-06T13:02:38.530601+00:00 | 0 | 0.006 | `git diff --check` |
| 2026-11-06T13:02:55.129084+00:00 | 0 | 0.244 | `python3 -B target/run411-prep/handoff-audit-corrected.py` |


## Review round 1

2026-11-06. Important I1 repaired within the run411 tooling scope. Minor M1 is
the controller's supplied smoke manifest and was skipped. Important G1 remains
Root's scoped checkpoint/push/remote-confirmation gate; this local repair and
preflight do not authorize execution or claim runtime/release acceptance.
No subagents, cargo, sudo, network, guest changes, QEMU commands or Git writes
were performed. Concurrent witness-validator sources/report were not edited.

The reservation helper now owns the common path and inode guard used by
reservation, provenance, collector, state inspector, failure inspector, selector
archiver and runner. It rejects 409 and 410 claims, reservations, consumed
markers, raw records, old evidence directories and the preserved-tree prefix
before content opens/copies. This includes absolute paths, Linux's double-slash
prefix spelling, symlink leaves/parents and hardlink aliases. Every admitted
regular input must have one link; reads compare pre-open and opened inode/dev
and walk every directory using O_NOFOLLOW. Exclusive writes and supersession
link/unlink also use directory descriptors.

The existing four exact target/{lab-state,candidates,run411-prep,platform-lab}
storage bridges are checked by link text and inode identity, then translated to
their exact /DATA/vprouter-lab/ backing directories. No guarded open traverses
these symlinks; unlisted, retargeted or nested symlink aliases are refused.
The frozen candidate exception is limited to candidate/root-verification,
source.tar, ARM64 payload/context and fresh ARM64 baseline/projection/411
output. It does not admit the prior x86 baseline, reconciliation, projection,
native-preflight or bootstrap410 evidence.

Collector reference checks run before following any binding, generation
retained_path or recursive baseline reference. The reviewer's poisoned 409
binding now returns 1 without opening or copying its bytes. The behavioural
matrix covers both runs, direct/symlink/parent-symlink/hardlink variants and
bindings/tombstones/prior_evidence/references/helpers (40 combinations), plus
preserved-prefix/alias refusal and CLI pre-admission paths. Existing tests still
prove raw-first preservation for admitted 411 outcomes that subsequently fail
provenance validation. Archive/restored controller pairs and source-manifest411
were updated together. No frozen candidate/baseline or ARM guest state was edited.

RED/GREEN receipts are under /tmp/run411-review-round1/. All Python invocations
used python3 -B (optimization probes used python3 -B -O). Initial behavioural
RED command, before implementation:

    python3 -B tools/rust-v2-lab/test-run411-isolation.py PriorEvidenceBoundary

Exit 1: red.log records 48 failures and one fixture exception; after allowing
that unrelated synthetic missing-key exception to reach the actual no-open
assertion, red-corrected.log records 49 behavioural failures and no errors.
Both runs' alias failures and the poisoned 409 read/copy were observed.
Additional targeted REDs (all exit 1) cover the double-slash preserved prefix
(red-double-slash.log), old x86 evidence inside the shared candidate
(red-candidate-boundary.log), exact storage-bridge translation
(red-storage-bridge.log), and descriptor-relative supersession mutation
(red-bridge-mutation.log). Their final GREEN results are included in the full
isolation suite below. The first supersession command refused on the existing
storage bridge before opening the lock or writing a tombstone/reservation;
that exit-1 receipt is supersede-refused-storage-bridge.json. The exact bridge
handling was then added under its own RED/GREEN tests before the successful
supersession.

Test-harness incident and correction: the initial RED preserved-prefix probe
mistakenly used /DATA/vprouter-lab/preserved/reference.json for save(). The old
helper successfully created only that new three-byte synthetic file, {} plus
newline, through O_EXCL; no existing file was overwritten. Its exact inode,
content and hashes were checked and recorded, and only that synthetic file was
removed. Correction receipt: accidental-synthetic-file.json under the receipt
directory. No historical preserved file was changed. Parent directory metadata
was affected by creation/removal; this is not a claim that the cold tree was
untouched or fully audited. The harness now intercepts all real preserved-tree
open/lstat attempts and fails before the OS can perform them, even if the
production guard regresses. Other negative cases use temporary synthetic state.

Final regression commands and exit codes:

| Command | Result | Exit |
| --- | --- | --- |
| python3 -B tools/rust-v2-lab/test-run410-fixes.py | 8 tests PASS | 0 |
| python3 -B tools/rust-v2-lab/test-run410-isolation.py | 21 tests PASS | 0 |
| python3 -B tools/rust-v2-lab/test-run410-provenance.py | 21 tests PASS | 0 |
| python3 -B tools/rust-v2-lab/test-run410-reservation.py | script assertions PASS | 0 |
| python3 -B tools/rust-v2-lab/test-run411-arm64-baseline.py | 2 tests PASS | 0 |
| python3 -B tools/rust-v2-lab/test-run411-fixes.py | 8 tests PASS | 0 |
| python3 -B tools/rust-v2-lab/test-run411-isolation.py | 68 tests PASS | 0 |
| python3 -B tools/rust-v2-lab/test-run411-launcher.py | 4 tests PASS | 0 |
| python3 -B tools/rust-v2-lab/test-run411-provenance.py | 21 tests PASS | 0 |
| python3 -B tools/rust-v2-lab/test-run411-reservation.py | script assertions PASS | 0 |
| python3 -B heredoc: py_compile.compile(..., cfile=/tmp/run411-review-round1/pycompile/N.pyc, doraise=True) | all 20 maintained/test/archive/restored Python files PASS; no repository bytecode | 0 |
| python3 -B heredoc: compare source/archive bytes, length and SHA256 against both manifests | original 296 and additional 4 pairs PASS | 0 |
| python3 -B -O TOOL --help for all 14 maintained/archive/restored entry points | all refuse with optimized_python_refused | 1 each, expected |
| git diff --check | PASS | 0 |

Exact test argv and logs: tests.json and test-run41*-*.log. Compilation inputs:
compile.json. Manifest checks: manifest-checks.json. Every optimization probe
argv and expected refusal status: optimized-refusals.json. Checks used only
local saved inputs and synthetic fixtures; they are not an ARM Bootstrap run.

Bound executable bytes necessarily changed, so one forward-only supersession
was required. Command (exit 0; exact argv and reason retained in supersede.json):

    python3 -B tools/rust-v2-lab/run411-reservation.py supersede --expected-sha256 2c076f625c15516c31daa6ff14a2985d6906631ab2cba5f553f26875473ee62d --reason 'Review round 1 Important I1: bind fail-closed 409/410/preserved path and inode guards before reference reads/copies, repaired ARM64 runner/provenance/collector/inspectors and source manifest; preserve all generations and the sole unconsumed global 411 budget.'

Active reservation SHA256: 120188663eb7b2a43a5ab3a8e395d91e0332b9facef17aed350508dc4e430b90. The prior active generation remains
byte-identical at target/lab-state/run-411-reservation.superseded-2c076f625c15516c31daa6ff14a2985d6906631ab2cba5f553f26875473ee62d.json. Its new immutable tombstone is target/lab-state/run-411-supersession-2c076f625c15516c31daa6ff14a2985d6906631ab2cba5f553f26875473ee62d.json.
There are now three generations and two immutable supersession receipts;
all validate. The 35 mandatory bindings validate. The single global claim was
not reset, created or consumed. The 14 pre-existing 409/410 state entries retain
their entry device/inode/size/mtime/link count; final-state.json records this
metadata-only check, which is not a cold preservation/content audit.

Code inspection confirms admit(..., preflight=True) cannot call save(CLAIM,...)
and the runner's preflight exits before output mkdir, listing SSH, either SCP,
or guest execution. The only preflight subprocess is the local read-only frozen
source verifier, now also explicitly using -B. Final exact command:

    python3 -B target/platform-lab/run-frozen-secret-bootstrap411.py target/candidates/run410-da75562-20261104/candidate.json debian-arm64 bootstrap411-arm64 success --reservation target/lab-state/run-411-reservation.json --preflight-only

Exit 0. Actual stdout (preflight.stdout, preflight.json):

```json
{"reservation_preflight": "PASS", "remote_program_compile": "PASS", "compiled_remote_programs": ["baseline-declaration", "guest", "host-declaration", "listing"], "run": 411, "budget_remaining": 1, "guest_actions_executed": false}
```

Post-preflight verification confirms the same active reservation SHA256, all 35
bindings valid, absent claim/raw/controller-error/output, and budget 1.

Run411 remains NOT_RUN with one total remaining budget. Claim/raw/controller-
error/output absence is recorded in final-state.json; generations/tombstones
remain preserved. No execution argv without --preflight-only was invoked.


## Review round 2

2026-11-06; HEAD remains `9f997dd960876619bc57d1910a2d532d224d2498`.
Important I1's demonstrated filename-reopen class is repaired in the seven
executing 411 tools identified by the re-review. This is implementation/test
proof; it does not constitute an independent GO, publication gate G1, runtime
Bootstrap, physical SCP qualification, witness acceptance, or release acceptance.
Run411 remains **NOT_RUN, budget 1**, with execution authorization still false.

### Implementation and custody

The single input primitive is `run411-reservation.py.acquire`. It rejects the
409/410/preserved prefixes and disallowed candidate evidence, refuses unlisted
symlinks and multiply linked inodes, records the first admitted inode metadata,
walks directories with `O_NOFOLLOW|O_DIRECTORY|O_CLOEXEC`, then opens the input
with `O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK`. Before reading it checks the
actual descriptor's type, link count and device/inode against that first
admission snapshot. A replacement between the first lstat and the descriptor
open cannot become the admitted input. After one read it checks inode/link,
size, mtime and ctime stability and returns bytes, SHA256 and fstat metadata.
No content read of the cold preserved tree or real 409/410 records is needed
to reject hardlink aliases or replacement-inode races.

Capture scopes share one acquisition per logical/translated input name across
hashing, JSON parsing, module compilation and validation. A cached acquisition
returns the captured bytes; it never reopens that name for content. The existing
`read_bytes`, `read_text`, `sha`, `protected` and compatibility stream APIs all
use that primitive. Reservation validation/claim admission and each provenance
validation have bounded scopes; collector calls reset their scope between
separate collections, preserving correct repeated-call behavior.

The runner acquires source, ELF, context and protected template once. The source
verifier compares the captured tar bytes against local Git objects; its output
is checked against the unchanged original frozen verifier in regression. The
unchanged context-checker body receives bytes, with a bytes-only tar adapter
that rejects pathname values. ELF checks, tar parsing, hashing and transfers all
use the same snapshots. SCP reads a sealed anonymous memfd through
`/proc/self/fd/<fd>`, with explicit `pass_fds`; the tests verify the transferred
hashes and that writes to each sealed descriptor fail. No checked source,
context or artifact filename is passed to a downstream consumer.

Helper modules are compiled from acquired bytes rather than handed back to an
import loader. The transitive baseline validator's pathname read calls are
rewritten to the same acquisition API in the captured 411 namespace, leaving
the shared historical module on disk unchanged. The collector and both
inspectors share those captured inputs. Controller outputs use exclusive
guarded creation, including the runner's directory lists and summaries.

The last custody audit also removed original identity/known-host filenames from
all four runtime SSH constructors and the runner's SCP options. `ssh_material`
acquires those inputs, writes exclusive 0600 copies in a fresh private 0700
directory, and removes that directory when the external consumers finish.
This private staging also works for SCP's SSH child, which may close inherited
fds. Tests use synthetic identity bytes and mock all external transfers; no
credential content is logged and no actual network operation was performed.

`test-run411-acquisition.py` statically checks all seven sources (reservation,
provenance, collector, state inspector, failure inspector, selector archiver,
runner). It rejects built-in/pathname opens and unguarded reads/writes; tar
opens require captured bytes/file objects. It pins complete subprocess argv
expressions and connection definitions, refuses unreviewed code-loader calls,
and fingerprints each remaining embedded guest I/O literal. Mutation probes
exercise direct/implicit pathname opens, JSON open, pathname tar, direct SCP
and subprocess path arguments, connection changes, and embedded reads.
Archive/restored copies and both manifests are checked independently.

### RED and GREEN evidence

Evidence directory: `/tmp/vprouter-run411-fix2/`. All commands use `python3 -B`;
`-O` is added only for explicit refusal probes. Synthetic fixture files are
confined to temporary directories. The real reservation/claim functions and
raw-record publication are intercepted in the full-runner matrix; real SSH/SCP
are also intercepted. Each successful synthetic case verifies its mock
admission, both transferred hashes, and scratch-only raw output.

| Check / exact command or driver | Result | Exit |
| --- | --- | --- |
| `python3 -B /tmp/vprouter-run411-review2/runner-reopen-probe.py` before changes | RED: all 12 original downstream context-checker cases read the old-evidence sentinel | 0 (original defect-asserting script) |
| `python3 -B /tmp/vprouter-run411-review2/verifier-reopen-probe.py` before changes | RED: all 6 original verifier cases read the sentinel | 0 (original defect-asserting script) |
| `TMPDIR=/var/tmp RUN411_BEFORE_ROOT=/tmp/vprouter-run411-fix2/before/tools/rust-v2-lab python3 -B tools/rust-v2-lab/test-run411-acquisition.py Custody.test_downstream_replacements` | RED against saved pre-fix code: all 45 replacement subcases fail | 1 |
| `RUN411_STATIC_ROOT=/tmp/vprouter-run411-fix2/before/tools/rust-v2-lab python3 -B tools/rust-v2-lab/test-run411-acquisition.py StaticBoundary` | RED: seven source-boundary failures | 1 |
| `TMPDIR=/var/tmp python3 -B tools/rust-v2-lab/test-run411-acquisition.py` | GREEN: full runner, 45 downstream subcases; 9 first-lstat races; 18 SSH staging subcases; verifier equivalence and static checks | 0 |
| `TMPDIR=/var/tmp python3 -B /tmp/vprouter-run411-review2/isolation-independent.py` | GREEN: all 112 independent seven-tool alias/race cases refuse before forbidden read/copy | 0 |
| Original defect-asserting runner/verifier scripts after repair | Their first assertion demanding a poisoned read now fails; the maintained full 45-case test replaces those obsolete positive-defect assertions | 1 each |
| `TMPDIR=/var/tmp python3 -B /tmp/vprouter-run411-fix2/regress.py` | All seven `test-run411-*.py` scripts and all four `test-run410-*.py` scripts pass | 0 |
| `python3 -B /tmp/vprouter-run411-fix2/checks.py` | 25 owned/regression sources py_compile to explicit scratch cfiles; all 300 original/additional manifest pairs match bytes/size/SHA256; 14 production `-B -O` refusal probes; `git diff --check` | 0 |
| `python3 -B /tmp/vprouter-run411-fix2/audit-preflight.py` | Exact runner preflight under rejecting audit hook: only local `git ls-tree`/`git show` children, no old-state opens, only the existing lock opened for writing | 0 |

The 45 downstream cases are 409/410/synthetic-preserved × source/context/
verifier-source/SCP-artifact/SCP-context × symlink/hardlink/regular-inode
replacement. Thus the reviewer's exact 18 combinations are retained, with
transfer and preserved cases added. The 18 SSH cases vary identity/pins × the
same three prior-evidence classes × the same three replacement forms. They
require either refusal before copying or the original captured bytes in the
private stage, and verify permissions and cleanup. The nine first-lstat races
instrument the gap before the content descriptor is opened and refuse before
any content stream is returned.

An intermediate rerun failed because the host `/tmp` tmpfs had less free space
than one frozen-input fixture (`ENOSPC`). Those logs are retained. Tests were
rerun with `TMPDIR=/var/tmp` and passed; no reviewer scratch directory, old
record, or preserved evidence was deleted to make room. Earlier fixture wiring
failures are also retained and superseded by the final recorded GREEN run.
Compilation emits bytecode only to explicit scratch paths; no workspace cache
was created by the Python invocations.

### Remaining by-path opens and their justification

The following list distinguishes content acquisition from deliberately created
outputs and from programs that run only in the guest. There is no remaining
host evidence-content pathname reopen outside `acquire` in the seven-tool chain.

1. `run411-reservation.py.parent_fd`: `/` and each directory component are opened
   for directory traversal only, with no-follow and pinned directory descriptors.
2. `acquire`: the single input leaf open and one descriptor read. The reservation,
   receipts, claims, bound JSON, helper code and `/proc/sys/kernel/random/boot_id`
   are all inputs through this same primitive. The reservation is not an
   unguarded `json.load(open(...))` exception.
3. `open_exclusive`, reached by `write_new`/`save`, collector output and controller
   snapshots: newly created outputs only, with `O_EXCL|O_NOFOLLOW`, mode 0600.
   These include the private SSH staging writer; it never opens the original
   identity/pin input again. `sync_directory` opens directories only for fsync.
4. `lock`: the existing/new run411 lock is opened `O_RDWR|O_CREAT|O_NOFOLLOW`, then
   fstat-checked for ownership, type, nlink and 0600 permissions before flock.
   Its content is not evidence and is not read. It is the sole writable open
   permitted by the exact-preflight audit.
5. Six initial, fixed guard-module bootstrap imports: runner, provenance,
   collector, state inspector, failure inspector and archiver. The guard's own
   trusted executable source must be loaded before it can acquire anything.
   These imports accept no reservation/evidence-controlled filename. Every
   later helper loader compiles captured bytes; the generic collector import
   loader was removed. Standard-library imports are Python runtime loading.
6. SCP's `/proc/self/fd/<fd>` opens refer only to the tool-created sealed memfd,
   never to an original checked path. OpenSSH's identity and known-host opens
   refer only to the tool-created exclusive private staging files. These are
   the descriptor/private-staging cases explicitly allowed by this task.
7. Embedded guest programs retain their original, separately fingerprinted
   path reads: guest boot ID; guest `/proc/<pid>/stat`; guest cgroup.procs;
   the eight fixed public selectors; and the failure inspector's public
   `allocations.json`/`namespaces.json`. The archiver opens its root/input
   directories for fsync. These names are in the boot-bound guest's proc,
   cgroup or root-owned public fixture directories, not host 409/410/preserved
   evidence. No embedded guest program ran in this round. The static test
   requires the exact reviewed literals; changes cannot silently add opens.
8. The test harness deliberately reads/copies valid frozen fixtures and its
   own synthetic scratch files. These are fixture setup/observations, not
   production evidence consumers. The preparation-only launcher, fresh-baseline
   and phase3-readonly-preflight sources were unchanged in this fix round;
   their historical/lifecycle paths are outside the seven runtime consumers
   identified by I1. Their existing regression coverage still runs.

### Forward-only supersession and final preflight

Changed bindings require forward-only generations, not an edit/reset of the
old reservation. Three immutable supersessions were necessary in this round:

- `120188663eb7b2a43a5ab3a8e395d91e0332b9facef17aed350508dc4e430b90`
  → `1f18a4c1ccd60193006ecd328c5161cab2c3f2f63d35d648e718019da4c75f66`
  for captured bytes, helper consumers, descriptor SCP and exclusive outputs.
- `1f18a4c1ccd60193006ecd328c5161cab2c3f2f63d35d648e718019da4c75f66`
  → `80196f9b8f9cadd4cd7313e7931eccf569d99ff16795c4a019692c60b7c33790`
  for the final SSH identity/pin custody closure.
- `80196f9b8f9cadd4cd7313e7931eccf569d99ff16795c4a019692c60b7c33790`
  → `85f4502ba9d79f037f9d2c69e97d42822d06079bc8192cc9d4037e32b632aa2b`
  for preserving a diagnostic when SSH staging fails before an argv exists;
  its new regression verifies no subprocess starts and a receipt survives.

Commands, all exit 0 (full stdout retained in `supersede.log`,
`supersede-final.log`, and `supersede-inspector.log`):

```sh
python3 -B tools/rust-v2-lab/run411-reservation.py supersede --expected-sha256 120188663eb7b2a43a5ab3a8e395d91e0332b9facef17aed350508dc4e430b90 --reason 'Review round 2 Important I1: bind single guarded acquisition snapshots, byte-only source/context consumers, captured helper modules and sealed descriptor SCP sources; preserve every prior generation and the sole unconsumed global run411 budget. No execution authorized.'
python3 -B tools/rust-v2-lab/run411-reservation.py supersede --expected-sha256 1f18a4c1ccd60193006ecd328c5161cab2c3f2f63d35d648e718019da4c75f66 --reason 'Review round 2 final custody audit: exclusively stage guarded SSH identity and host-pin snapshots for all SSH/SCP consumers; no original checked filenames are handed to OpenSSH. Preserve all prior generations and the sole unconsumed global run411 budget; execution remains unauthorized.'
python3 -B tools/rust-v2-lab/run411-reservation.py supersede --expected-sha256 80196f9b8f9cadd4cd7313e7931eccf569d99ff16795c4a019692c60b7c33790 --reason 'Review round 2 staging failure preservation: retain an inspector diagnostic with no spawned argv if guarded SSH staging fails before construction; preserve all generations and the sole unconsumed global run411 budget. No execution authorized.'
```

All six generations/five immutable receipts validate. All retired generation
files and receipts remain present; the starting generation is byte-identical
to the saved pre-change copy. The global claim name and total one-shot budget
are unchanged. Eight binding hashes changed relative to the starting generation:
reservation, provenance, collector, state inspector, runner, failure inspector,
selector archiver and source-manifest411. All 35 final mandatory bindings pass.
The source-manifest411 archive/restored pairs remain identical; the original
296-entry source manifest is unchanged.

Exact final non-consuming command, exit 0:

```sh
python3 -B target/platform-lab/run-frozen-secret-bootstrap411.py target/candidates/run410-da75562-20261104/candidate.json debian-arm64 bootstrap411-arm64 success --reservation target/lab-state/run-411-reservation.json --preflight-only
```

```json
{"reservation_preflight": "PASS", "remote_program_compile": "PASS", "compiled_remote_programs": ["baseline-declaration", "guest", "host-declaration", "listing"], "run": 411, "budget_remaining": 1, "guest_actions_executed": false}
```

Final active SHA256:
`85f4502ba9d79f037f9d2c69e97d42822d06079bc8192cc9d4037e32b632aa2b`.
Claim, raw record, controller-error and bootstrap411-arm64 output remain absent.
`execution_authorized_by_this_phase=false`. The real reservation was never
consumed. No witness-validator file was edited or included in this round's
source inspection/compilation/tests; no QEMU operation, guest mutation, preserved
traversal, cargo, sudo, network, git staging, commit or push was performed. Runs
409/410 and their claims/raw records were not edited or used as new evidence.
