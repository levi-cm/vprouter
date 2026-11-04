# Task 8c rebuild phase 2 independent review

Overall: **FAIL for the complete phase 2 handoff as currently observable.** Inventory recovery, source/artifact coherence and the requested Rust checks pass. The claimed running guest ceased to be observable during this review, so fresh guest Docker/marker/host-key checks could not be completed. This is not evidence that the original provisioning failed, nor attribution of the guest exit to the implementer. No experiment, historical continuity, operational acceptance or release readiness is approved.

Reviewed on 2026-11-04 Europe/Berlin (2026-11-03 UTC), branch `rust/v2`, HEAD `d62ab24e172badb9245fa5f20d71f15930731839`. Read the assessment, phase 1 review including I1 and its phase 2 requirements, staged tool/report, build driver, launcher, both verifiers, context/source validators, and phase 3 projection/authoring/Bootstrap controllers. Scratch and full verification source/results are in `target/rebuild-phase2-review/`. No subagents, Git writes, outer-host sudo, guest lifecycle actions, baseline authoring or Bootstrap execution occurred. The sole requested report is new and unstaged; existing tracked/staged content was preserved. SSH was attempted only at the dedicated endpoint with the report's key/trust and strict checking; connection failed before guest commands ran.

## Findings

### Critical

None found in the reviewed staged implementation.

### Important

**I1 — Current guest availability fails the handoff's running-guest requirement.** `.superpowers/sdd/rust-v2/task-8c-rebuild-phase2-report.md:49` and `:243` describe the guest as left running. The initial independent `verify.py` completed the `/proc/3289270/stat` start-tick and exact argv checks successfully; those results survive in `verification.json`. Subsequently the dedicated strict SSH command exited **255**, `ssh: connect to host 127.0.0.1 port 22036: Connection refused`. Follow-up `ps -p 3289270 ...` exited **1**, `/proc/3289270` was absent, and `ss -ltnp 'sport = :22036'` exited **0** with only its header. Final recorded observation: **2026-11-03T23:25:21.626376+00:00**, `guest-unavailable.json`. The process was therefore present at one review observation and absent at a later one; cause and exact exit time are unknown. The QEMU log was empty. No stop/kill/reboot was sent by this reviewer. Concrete failure: phase 3 cannot obtain a fresh frozen projection or verify current guest admission; reusing an old boot ID or launching a replacement silently would invalidate new identity/provenance assertions. Any recovery must be separately authorized and preserve the disk/evidence; this review does not restart it.

**I2 — Phase 3's unchanged SSH trust path does not consume phase 2's pin.** `target/platform-lab/run-frozen-host-projection.py:121` selects `target/platform-lab/debian-clean-x86_64/known_hosts`; `target/platform-lab/run-frozen-secret-bootstrap.py:9` selects the same path. That file is absent. The actual verified pin is `target/lab-state/known_hosts`, as reported at `.superpowers/sdd/rust-v2/task-8c-rebuild-phase2-report.md:37`. Concrete failure: stock phase 3 commands cannot authenticate the fresh guest using the supplied dedicated pin (or could consult unrelated inherited trust/config instead). This is an inherited next-phase integration prerequisite, not an undisclosed change to the inventory tool. Review an explicit endpoint/key/trust binding for both controllers before running either; keep strict checking and do not silently retarget original port22032 or other platforms. The projection controller also writes a candidate-local directory and a retained executable inside the guest (`:144-185`); it is not a completely file-read-only SSH operation and was not run in this review.

### Minor

**M1 — Outer-host non-change is not independently demonstrated by retained before/after state.** `.superpowers/sdd/rust-v2/task-8c-rebuild-phase2-report.md:5` asserts no host Docker/network/firewall/Tailscale configuration change. The inspected command ledger/helper sources support guest confinement, but no matching pre-phase host address/ruleset/container snapshot is supplied. Fresh `ip -br addr` and `docker ps -a --no-trunc` succeeded and show the existing host network and multiple unrelated workloads; these are current observations, not historical equality proof. `nft list ruleset` could not run because `nft` is absent (127); no installation or sudo was attempted. Concrete failure: an unrelated concurrent host change cannot be distinguished retrospectively from a phase-caused change by these receipts alone. Do not elevate the implementer's statement to independently verified host preservation. This finding does not assert that phase 2 changed the host.

**M2 — Optimized Python disables the new index authentication assertions.** `tools/pinned-tailscale-program-inventory.py:24-37` uses assertions for range/file/index/platform checks without refusing optimized Python. Existing remote isolation/copy checks also use assertions. Under `python3 -O` or `PYTHONOPTIMIZE`, a replacement index can bypass the fixed raw-index digest check before the tool performs guest Docker acquisition; strict SSH itself remains enforced. Both retained actual acquisition receipts bind the ordinary nonoptimized implementation and the independently rehashed correct bytes, so this does not invalidate this phase's recovered inputs or normal default invocation. Future hardening should refuse optimized execution explicitly. No optimized acquisition was executed by this review.

## Inventory-tool review and phase 1 I1 resolution

The phase 1 finding **is resolved for the two recorded phase 2 acquisitions**. The staged delta requires `--ssh-port`, `--ssh-key`, `--ssh-known-hosts`; host/user remain `127.0.0.1`/`vprouterlab`. It specifies `-F /dev/null`, absolute key/trust paths, `IdentitiesOnly=yes`, `BatchMode=yes`, `GlobalKnownHostsFile=/dev/null`, `StrictHostKeyChecking=yes`, and the explicit port. There is no implicit endpoint default or fallback. Running `python3 tools/pinned-tailscale-program-inventory.py amd64` exited **2** before acquisition, naming all three required options. Other endpoints are not rewritten by this change.

Independent AST comparison proves the remote `script` and `cleanup` assignment trees are unchanged from HEAD. The fixed public-file allowlist, stopped-container checks, copy limits, static ELF checks, exact cleanup and timeouts remain. Additional changes are the requested index authentication, tracked platform comparison and endpoint/trust receipt; there is no other remote behavior change. Final source SHA256 is `06d6d9ce68db82f171f00502aba2edc7c3b5170e72afc167fee97d00fa71aebd`, identical in the worktree, index, candidate Git object, retained executed source, and both acquisition receipts. The actual receipts record port22036 and the dedicated key/trust paths.

The index is **1337 bytes**, freshly hashes to **sha256:c507f3a2a6ab1cabd8d809b98edeb41edbd5c3fb6ad9632ffd098b4c7d0b4065**. Its amd64 entry is **sha256:08a1bc6c82fee62d1a135788fb67fefa9d22deea3830e8a45ebe1a3cb116e325**; arm64 is `sha256:472c549d2ef8cebc000de2c8a94061bbdc864d2454177b2ada713262475449ef`. Both equal the tracked inventory's platform manifests. All files under `target/program-inventory` were enumerated: exactly six files, no additional files. Every size/hash matches the tracked pinned inventory and fresh acquisition receipt, including the phase 1 review's CLI values:

| Path under target/program-inventory | Bytes | Recomputed SHA256 |
| --- | ---: | --- |
| tailscale-1.102.5-amd64/tailscaled | 42902060 | b2ec98126c6ee19d7b3603b0cfee97c5dd646874065aed7016653d30ff92a9cd |
| tailscale-1.102.5-amd64/tailscale | 33116853 | 344ac0aadfcc98aa2567aa4ce96b38b3faa9c5fbc849b7b1bd5feaa6c1563a2f |
| tailscale-1.102.5-amd64/ca-certificates.crt | 181724 | 028fca5150ee1915c4474489985d55c54fceaa680c754cc8d1301734f01b2232 |
| tailscale-1.102.5-arm64/tailscaled | 40133663 | 3cf2640069ded59322dc2113be5fa90540937410be22bb40873a614773ab27cc |
| tailscale-1.102.5-arm64/tailscale | 30825099 | b01efc25199dd023e1c9b93e8166b7afbc56dd941f18d4a8f9401933d258ddd7 |
| tailscale-1.102.5-arm64/ca-certificates.crt | 181724 | 028fca5150ee1915c4474489985d55c54fceaa680c754cc8d1301734f01b2232 |

Both receipts report exact owned stopped-container cleanup. Their final Docker empty-container evidence is retained historical phase 2 evidence, not freshly observed guest state.

## Key, trust and guest evidence

The retained `keygen.log`, exact command ledger, phase 1 empty-lab-state evidence and cloud-init user-data support new generation of the dedicated ed25519 key, rather than importing a personal key. The public key fingerprint independently recomputes to `SHA256:oA3DjOssKJEmB7MTEn2s8GyySbx6sS3HG04Ns736nXg`, comment `vprouter-phase2-dedicated-lab-20261103`; this exact public key is provisioned in user-data. Private key and known_hosts modes are 0600. Private bytes and `~/.ssh` were not opened or compared. Thus new lab-only provenance is supported by generation/provisioning records; an absolute historical claim about all copying/use outside the recorded workflow is not independently provable.

Rehashed `serial-at-trust.log` equals `a6bda2b08b4414e75a492473a2992086ec0c062998469ac3815192d52ee3e25c`. Parsing only the region between `BEGIN SSH HOST KEY KEYS` and `END SSH HOST KEY KEYS` yields exactly one ed25519 host key. It exactly equals the sole `[127.0.0.1]:22036` known_hosts row, whose SHA256 is `38b48e872f7876cb68b02b9c823107ccc2969c5d63642b9b74561803688e139e`; `ssh-keygen -lf` gives `SHA256:rk1TQu4ncW/fxBUmvcFu/M3BbOKpqofLaf5glJ86WvA`. Retained `guest-check.stdout` records the same `/etc/ssh/ssh_host_ed25519_key.pub` from the implementer's strict SSH session. Reviewed `pin-host-key.py` obtains trust from the owned file-backed serial console after process/start/argv validation, not network keyscan. This establishes coherent out-of-band provenance and agreement with the recorded guest host key. **Fresh actual-guest fingerprint confirmation is NOT_RUN because SSH was refused.**

The initial live QEMU argv exactly matched `process.json`, PID3289270/start4458761 and the reviewed launcher's argv construction: KVM, host CPU, pc/smm off, 2 CPUs, 2048 MiB, expected overlay/read-only seed, one virtio WAN, user networking with the sole explicit forward `127.0.0.1:22036-:22`, no additional argv devices/forwards. The controller boot ID matched `d211b1fa-ebf8-4673-b016-d2bae5c5fc30`. No QMP commands were issued. The phase 2 retained QMP result reports KVM enabled/present; this review did not freshly query KVM.

Retained guest records report boot ID `a9bf4e20-b253-46c7-a9cf-333a80ed8e29`, Docker26.1.5 active, systemd/cgroup2/overlay2, initial namespace equality, root0700 lab directory, root0600 regular single-link isolation marker, ens2/ifindex2/MAC52:54:00:12:34:56, and completed cloud-init. Those are consistent with launcher provisioning and the report. Current Docker/marker/boot-ID checks remain **NOT_RUN**, not PASS, due to I1. Durable `target/{lab-state,platform-lab,program-inventory,candidates}` symlinks resolve into `/DATA/vprouter-lab`; no mutable guest image was opened for offline inspection.

## Candidate binding and verifier safety

`refs/vprouter-test-candidates/20261103T231415Z` resolves to **1b65709a1189a5fff0fb62c47877e349d4f4f0c4**, parent **d62ab24e172badb9245fa5f20d71f15930731839**. `git diff --name-only HEAD 1b65709` yields only `tools/pinned-tailscale-program-inventory.py`, whose bytes equal the staged implementation. The newly staged phase 2 report is absent from the candidate tree. This is coherent: no Rust/build-input/manifest differences exist; the tool/report are outside the 203 archived build inputs. The ref binds HEAD plus the inventory implementation, not the entire final staged documentation state. It should not be described as the complete eventual published commit.

Fresh `tools/verify-frozen-build-inputs.py` verification returns 203 inputs, source archive SHA256 **4b0c5af101405476e130c61cbedf041a6542c401e2eb324045982488b9c70807**, aggregate **4274b1969cb51eddfac9c7fe52442913c0688f1dc1cc24eae8a77c7481e110fd**. Every archived input also equals current worktree bytes. Both candidate payload/context hashes equal candidate.json:

| Artifact | Recomputed SHA256 |
| --- | --- |
| amd64.payload | d8ae01f00e540879fe0e3cd68200b2f13677f441e057d2718137ec5d965ba715 |
| arm64.payload | a7f3ba5423e707d4af60488f69130c01c780428c7ef9849e25c028092177e7ec |
| amd64.context.tar | da7c2e8e257e4c243223c3964b9ce7ba7ebc8b574ddeed00e6bff0174fa49e6f |
| arm64.context.tar | 51023de0b7bbab71a40e1882662d50327d8643f1f45051c466655207666f406d |

All six candidate Rust program copies match size/SHA256 in `docs/rust-v2/programs-{amd64,arm64}.json`; both payloads pass ELF64/machine/static segment checks. The reviewed context checker was evaluated in memory without import bytecode writes; both contexts pass its exact seven-file inventory/metadata/manifest/CA/program checks. All **18** candidate report-table entries were rehashed and size-checked, including source, candidate metadata and retained verification/preflight records. The retained build log/driver describes the matching musl static Zig/rust-lld build; this review did not rerun the mutating build driver or claim a separate reproducible rebuild.

Neither requested stock verifier is read-only. `target/verify-continuation-candidate.py:80-84` exclusively creates/chmods `root-verification.json` (and can copy/chmod missing contexts at `:58-62`). `target/verify-frozen-inspection-preflight.py:23-24`, `:51-54`, `:77-81`, `:93-96` creates output directories/executable/validator/result files and executes the payload. Both existing exclusive result destinations are already populated. Consequently **both stock reruns are NOT_RUN under the user's conditional read-only instruction**; no original evidence was overwritten or renamed.

Independent `verify.py` reproduced their static source/payload/context assertions, compared retained result bindings, checked the filter copy/log, and reran the reviewed mechanics validator against retained frozen-preflight stdout. The mechanical protocol equals the saved record; descriptor and source-match results are internally consistent. This is validation of retained execution evidence, **not a fresh frozen payload selftest/clock execution**. No frozen verifier or payload execution result is relabeled as newly run.

## Exact commands and results

All commands ran from `/DATA/AppData/vprouter-rust-v2`. The retained scripts contain exact nested commands and assertions; the observation script's guest payload was prepared but never executed remotely.

| Command | Result |
| --- | --- |
| `git status --short`; `git rev-parse HEAD`; `git diff --cached`; `git diff --cached --check` | Read reviewed two-path stage; HEAD d62ab24; whitespace check 0 |
| `python3 target/rebuild-phase2-review/verify.py` | Initial complete invocation 0; 6 public files, 18 candidate files, 203 inputs, live process binding passed; verification.json retained |
| `python3 tools/verify-frozen-build-inputs.py target/candidates/rebuild-20261103T231415Z/source.tar 1b65709a1189a5fff0fb62c47877e349d4f4f0c4` | 0, invoked by verify.py with equivalent absolute source path; exact binding matched |
| `git show -s --format=fuller 1b65709`; `git diff --stat d62ab24 1b65709` | 0; only inventory implementation differs |
| `python3 tools/pinned-tailscale-program-inventory.py amd64` | 2, required SSH arguments absent; no acquisition |
| `ssh-keygen -lf target/lab-state/id_ed25519.pub`; `ssh-keygen -lf target/lab-state/known_hosts` | 0, fingerprints above; invoked by verify.py |
| `python3 target/rebuild-phase2-review/observe.py` | 1 at assertion after SSH exit255; host reads saved, guest connection refused |
| `ip -br addr` | 0; host-ip.stdout |
| `docker ps -a --no-trunc` | 0; host-docker.stdout; read-only host operation |
| `nft list ruleset` | 127, executable absent; no sudo fallback |
| `ps -p 3289270 -o pid,stat,lstart,etime,comm` | 1, no process |
| `ss -ltnp 'sport = :22036'` | 0, no listener |
| `cargo test --workspace --locked` | 0, 425 passed, 2 ignored, 0 failed |
| `cargo fmt --all --check` | 0 |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | 0 |

Exact SSH argv is in `observe.py`: `ssh -F /dev/null -i /DATA/AppData/vprouter-rust-v2/target/lab-state/id_ed25519 -o IdentitiesOnly=yes -o BatchMode=yes -o UserKnownHostsFile=/DATA/AppData/vprouter-rust-v2/target/lab-state/known_hosts -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -o UpdateHostKeys=no -o ConnectTimeout=5 -p 22036 vprouterlab@127.0.0.1 'sudo -n python3 -'`. It failed before the remote command. No alternate key, endpoint, trust relaxation or retry was used. Workspace checks were repeated once to retain explicit exit-code receipts after an earlier invocation's session output was unavailable; final exits are in `cargo-results.json`, full outputs in `cargo-{test,fmt,clippy}.log`. No Bootstrap or bounded guest experiment budget was consumed.

## Phase 3 must provide

1. Resolve guest loss under explicit lifecycle authority, retaining disk/log/private evidence and documenting why it disappeared if determinable. Rebind actual process/start/argv/controller boot, strict host key, guest boot/machine identity, Docker/cgroup/kernel/WAN and protected marker. A reboot/replacement is another live identity discontinuity; do not reuse old claims.
2. Resolve I2 with reviewed explicit projection/Bootstrap endpoint/key/trust wiring. Keep other platform endpoints unchanged and inherit no unrelated SSH configuration. Preserve the original controller bytes and record exact new controller hashes. Projection writes guest/controller files and needs the appropriate scope even though its network request is GET-only.
3. Design and independently review a **fresh** baseline provenance/authoring procedure. `target/author-host-baseline-after-bootstrap-v2.py:23-46` requires a previous directory binding, raw failed run, inspector, old authored template/review and recursive evidence hashes, plus the canonical proven DOWN endpoint. Those original408 inputs/live identities are lost. The unchanged helper is not a fresh-baseline constructor; do not fabricate its inputs or manufacture61 links. Independently declare the fresh guest's intended structure, then reconcile an exact candidate-bound frozen projection with full namespace/link/address/route/rule equality and original deadlines/custody.
4. Retain a reviewed new baseline/template/reconciliation chain bound to current source/artifacts/guest, protected modes and honest historical discontinuity. A live projection alone cannot authorize its own baseline. Explicitly dispose of unavailable historical raw405/407/408 reader replay and original-resource continuity; new synthetic checks cannot replace them or establish a causal speedup over408's accumulated state.
5. Implement/review an exclusive **pre-execution run409 reservation/high-water mark** with collision prevention and discontinuity metadata. `target/platform-lab/run-frozen-secret-bootstrap.py:53-56` still chooses the first missing number starting at1, after guest execution; a label containing409 does not reserve409. Do not fill historical holes with dummy run records or relabel afterward.
6. Refresh owned guest admission immediately before mutation: root-owned0700 lab directory/0600 single-link marker, eight fixed selectors absent, initial guest namespace/WAN identities, exact candidate payload/source/static contexts, capacity and required kernel/cgroup/systemd/Docker capabilities. Independently qualify the exact clock/filter/runtime prerequisites for the instrumentation; retained unprivileged mechanics evidence is not a fresh privileged runtime check.
7. Complete independent source/current candidate/reader/baseline review, explicit evidence-gap disposition, checkpoint/push/remote confirmation required by the historical workflow, and an explicit one-shot synthetic experiment authorization/budget. Preserve original2s windows, negative cases and all identity/custody checks; no timing/policy relaxation or unchanged retry. This review performs no publication or execution authorization.
8. Before execution, establish durable custody for raw records, directory binding, private metadata/resources and failure inspection. After failure, inspect/preserve first; exact-six selector archival requires its own reviewed identity-bound approval. No provider profiles, enrollment, ARM runtime or release/operational acceptance follows from this phase.

Overall: FAIL for the current handoff; static inventory and candidate checks pass.
Findings: 0 Critical, 2 Important, 2 Minor; phase 1 endpoint I1 resolved for acquisition.
Guest: initially process-bound, later absent; fresh SSH/Docker/marker verification blocked.
Checks: 425 tests passed, 2 ignored; formatting and strict Clippy passed.
Next: restore reviewed guest availability, wire phase 3 trust, author baseline and reserve409 before one shot.
