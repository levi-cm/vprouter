# Task 8c rebuild Phase 2 report

Phase 2 completed the fresh guest, exact public inventory recovery, and coherent build/freeze workflow. This is a **new lab identity, discontinuous with the deleted original**. Original guest/live-resource continuity is permanently broken; public-source restoration and new static artifacts do not recover the original evidence. No Bootstrap/run409, baseline authoring, provider connection, Tailscale enrollment or acceptance experiment was performed. `release_ready=false` remains in force.

Workspace `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`; entry and final branch HEAD `d62ab24e172badb9245fa5f20d71f15930731839`. Entry index/worktree were clean. No subagents, outer-host sudo, host package installation, outer-host Docker operation, network/firewall/Tailscale configuration change, `git commit`, push or branch move occurred. The explicitly authorized build workflow created a local candidate commit object with `git commit-tree` and one exclusive candidate ref; neither advances `rust/v2`. Guest cloud-init and remote sudo/Docker were confined to this newly owned guest.

UTC evidence dates are 2026-11-03; Europe/Berlin local date is 2026-11-04. Durable evidence directory: `/DATA/AppData/vprouter-rust-v2/target/lab-state/phase2-evidence-20261103T231103Z` → `/DATA/vprouter-lab/lab-state/phase2-evidence-20261103T231103Z`. Its `commands.jsonl` records exact top-level command argv, exit codes, UTC start/end and full-output log paths. Retained helper sources contain all Python bodies and nested guest commands; logs are not truncated on disk. No private key bytes are reproduced in this report or staged.

## Inputs read and implementation review

Read, in order, the rebuild assessment (especially plan steps 3–6), Phase 1 review/I1 and its complete Phase 2 input list, Phase 1A report, Phase 1B report, and `tools/rust-v2-lab/rebuild-20261103-build.py`. Also read the launcher, inventory tool, tracked pinned inventory, copier, continuation verifier and frozen preflight in full before execution. Read the verification-before-completion skill and applied fresh result checks. A lightweight memory lookup supplied only preservation/evidence conventions; current decisions and all reported operational facts were verified against this checkout and fresh execution.

The only implementation delta is `tools/pinned-tailscale-program-inventory.py`. I1 is resolved with required `--ssh-port`, `--ssh-key`, and `--ssh-known-hosts` options; loopback/user stay fixed. SSH uses the dedicated absolute key/trust paths, `IdentitiesOnly=yes`, `BatchMode=yes`, `StrictHostKeyChecking=yes`, `GlobalKnownHostsFile=/dev/null`, and `-F /dev/null` to avoid unrelated config/proxy/identity overrides. No fallback to port 22032 or inherited host trust remains. It hashes the raw index bytes against the fixed index digest before reading its entries, checks the chosen platform digest against the tracked inventory, and records the explicit endpoint plus trust-file digest in the acquisition receipt.

Implementation self-review: all remote acquisition and exact-container cleanup ASTs remain identical to HEAD (`verify-inventory.py` asserts this), fixed three-file allowlist/static ELF checks and timeouts remain, and all six outputs are independently compared against the tracked inventory. This is self-review, not a new independent review. Executed/final tool SHA256 `06d6d9ce68db82f171f00502aba2edc7c3b5170e72afc167fee97d00fa71aebd`; exact executed source retained as `inventory-tool-executed.py`. A transient local edit adding optimized-Python refusal/removing the now-unused `sys` import was undone before ARM acquisition; it was never used by either acquisition, and the final file hash matches both receipts. Both actual invocations used ordinary, nonoptimized `python3`.

The launcher and build driver needed **no changes**. Exact launcher SHA256 `5db133313f666171adc5227972d681f3aae95b4db2c74e0f92b551ef13b43842`; driver SHA256 `5be9019c509137498f0b43a9357a121125963cacc730808afad41112f08d2c78`. Other invoked controller hashes are retained in `controller-input-hashes.json`. The archived preflight output path was absent; to keep its executable/state/evidence durable without changing the controller, created `target/process-inspection-root-verification-20261027` → `/DATA/vprouter-lab/candidates/phase2-frozen-preflight-20261103T231103Z`. All eight pre-existing durable symlinks remain in place.

## Fresh guest identity and trust provenance

- Guest: `debian-clean-x86_64`, hostname `vprouter-debian-clean-lab`.
- QEMU PID **3289270**, `/proc/PID/stat` start tick **4458761** (SC_CLK_TCK=100); launcher observation `2026-11-03T23:11:12.300234+00:00`.
- Controller boot ID `d211b1fa-ebf8-4673-b016-d2bae5c5fc30`; binds the PID/start-tick record to this controller boot.
- SSH: `vprouterlab@127.0.0.1:22036`; guest boot ID `a9bf4e20-b253-46c7-a9cf-333a80ed8e29`; machine-id `6efc72f8c01340cc91fec545d32e0082`.
- QEMU 10.0.13, `-accel kvm -cpu host -machine pc,smm=off`, 2 vCPU, 2048 MiB RAM, exclusive 24 GiB virtual overlay; user networking forwards only loopback SSH. QMP `query-kvm` returned enabled/present=true and `query-status` running=true; raw replies in `guest-qmp.json`.
- Guest disk, seed, cloud-init files, console and QMP/PID/process records: `target/platform-lab/debian-clean-x86_64` → `/DATA/vprouter-lab/platform-lab/debian-clean-x86_64`. The original `process.json` intentionally retains its launch-time `BOOTING_NOT_VERIFIED`; later `guest-verification.json`, QMP, and `final-audit.json` supply actual boot/running evidence.

Dedicated new lab-only access key generated with `ssh-keygen -t ed25519 -N '' -C vprouter-phase2-dedicated-lab-20261103 -f target/lab-state/id_ed25519`; key mode 0600. No `~/.ssh` keys were reused or read. Public key fingerprint: `SHA256:oA3DjOssKJEmB7MTEn2s8GyySbx6sS3HG04Ns736nXg`. Cloud-init received only this new public key.

Out-of-band host trust: verified the live QEMU PID/start/argv against `process.json`, then parsed the unique ed25519 public host key from the file-backed owned QEMU serial console between cloud-init host-key markers. No `ssh-keyscan`, TOFU, accept-new, disabled checking or network-only key capture was used. Retained serial snapshot `serial-at-trust.log`, SHA256 `a6bda2b08b4414e75a492473a2992086ec0c062998469ac3815192d52ee3e25c`. First strict SSH connection independently returned the same guest host public key.

```text
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH8YmihDdQjkT9ILQk0JMZ/FoYTxNQNUtX2tAl9WjM/8
256 SHA256:rk1TQu4ncW/fxBUmvcFu/M3BbOKpqofLaf5glJ86WvA [127.0.0.1]:22036 (ED25519)
```

Dedicated `target/lab-state/known_hosts` is mode 0600, with only `[127.0.0.1]:22036` and the console-derived ed25519 key; SHA256 `38b48e872f7876cb68b02b9c823107ccc2969c5d63642b9b74561803688e139e`. `host-trust.json` records console/proc provenance and the full launch argv. No old guest trust was imported. The unchanged launcher retains its historical cloud-init instance-id label `vprouter-debian-clean-20261027`; that static label is not identity continuity. The new host key, machine-id, boot ID and fresh overlay identify this new guest.

Cloud-init status was `done`, exit 0, `errors: []`, `recoverable_errors: {}`. It installed exactly the launcher-requested package list (plus APT dependencies): docker.io, nftables, iproute2, wireguard-tools, tcpdump, python3, sudo and openssh-server; enabled Docker; created the root-owned isolated marker and bootstrap-complete file. No manual guest provisioning was needed. Docker 26.1.5+dfsg1 is active, cgroup driver systemd/version 2, overlay2. Guest kernel is `6.12.113+deb13-cloud-amd64`; guest initial network namespace matched PID1. Root directory `/var/lib/vprouter-v2-lab` is root:root 0700; `isolated-acceptance` is root:root 0600, regular, nlink=1; ancestor ownership/modes passed archived checks. Initial guest free space 22,623,834,112 bytes; available RAM 1,728,491,520 bytes. WAN `ens2`/alternate `enp0s2`, ifindex2, MAC `52:54:00:12:34:56`, `10.0.2.15/24`, default via `10.0.2.2`; Docker created its own guest-only `docker0`. Complete bounded observations are in `guest-verification.json`; no preservation baseline was authored from these observations.

Base image `target/lab-images/debian-13-genericcloud-amd64-20261021-2638.qcow2`, 342,294,528 bytes. The unchanged launcher recomputed SHA512 before creating the overlay and matched exactly one checksum-manifest entry:

```text
SHA512 16e0965312c56feb331049d45d2b1b5778f3f942a33d4300eedbb97527707f2bea87c0006f3e4cc7a25fadbff739c4e235a51fb9bcd1b66fd554f7f8e80ba45c
SHA256 d3a5c93cc98b34651421e0fa3a37db428f07355a3bc4cf46d6fbeb001f258e90
SHA512SUMS SHA256 5e22239e7bcb7ac4056324aa1829620f2853bff0c3b77b3af8c4578642c0f359
```

The SHA256 values above were freshly rechecked for this report. Base was used as a backing file, never booted writable. No host sudo/controller privilege was required. Guest is deliberately left running; final-audit PID/start/argv and boot-ID checks passed at `2026-11-03T23:16:11.447119+00:00`. Final guest Docker container list is empty; both verified public platform images remain cached for later work.

## Exact pinned public acquisition and verification

Fetched the OCI index by digest over Docker Hub HTTPS using an anonymous public pull token kept only in process memory (not retained or printed). Request/response metadata in `index-acquisition.json`; raw authenticated-by-digest bytes restored to `target/lab-state/tailscale-1.102.5-manifest-index.json`. Size **1337**, SHA256 **c507f3a2a6ab1cabd8d809b98edeb41edbd5c3fb6ad9632ffd098b4c7d0b4065**; response docker-content-digest agrees. No reserialized/replacement index or release substitution.

| Arch | Platform manifest digest | Docker image/config ID | Stopped extraction container, removed |
| --- | --- | --- | --- |
| amd64 | `sha256:08a1bc6c82fee62d1a135788fb67fefa9d22deea3830e8a45ebe1a3cb116e325` | `sha256:94603a5a98fa75ef53c4c5b5401c4025b25cd2e54ad2609720ba8d0e5a3febda` | `22284135da44fcb7b1a244cb37409e3e54eb540c880fc3b7cb978b84a6d1aa9b` |
| arm64 | `sha256:472c549d2ef8cebc000de2c8a94061bbdc864d2454177b2ada713262475449ef` | `sha256:5d3dd33a5cd5ed29514fdada176fa2226d122f19bddd8fe06bc974633083e90e` | `910b971b2c4bb18f3477b5706f0e9ded2540f49620a41cdb4b0c80b16b70304d` |

ARM64 **public cache only** was required because the unchanged driver/copier/verifier require both architecture contexts. Docker pulled/extracted its files without running an ARM binary or creating an ARM guest. Both extraction containers remained `created`, stopped, `--network none`, read-only, cap-drop ALL, no-new-privileges, no mounts; exact ID/image/label/status checks preceded removal. There was no container start or Tailscale execution/enrollment. Fresh receipts: `target/lab-state/tailscale-program-inventory-{amd64,arm64}.json`; their historical counterparts in the tracked inventory were not overwritten.

Every copied file was recomputed from retained bytes and matched both the tracked inventory and acquisition receipt, including all CLIs. No host CA was substituted. Paths below are relative to `target/program-inventory/`:

| File | Actual bytes = tracked bytes | Actual SHA256 = tracked SHA256 | Result |
| --- | ---: | --- | --- |
| `tailscale-1.102.5-amd64/tailscaled` | 42902060 | `b2ec98126c6ee19d7b3603b0cfee97c5dd646874065aed7016653d30ff92a9cd` | MATCH |
| `tailscale-1.102.5-amd64/tailscale` | 33116853 | `344ac0aadfcc98aa2567aa4ce96b38b3faa9c5fbc849b7b1bd5feaa6c1563a2f` | MATCH |
| `tailscale-1.102.5-amd64/ca-certificates.crt` | 181724 | `028fca5150ee1915c4474489985d55c54fceaa680c754cc8d1301734f01b2232` | MATCH |
| `tailscale-1.102.5-arm64/tailscaled` | 40133663 | `3cf2640069ded59322dc2113be5fa90540937410be22bb40873a614773ab27cc` | MATCH |
| `tailscale-1.102.5-arm64/tailscale` | 30825099 | `b01efc25199dd023e1c9b93e8166b7afbc56dd941f18d4a8f9401933d258ddd7` | MATCH |
| `tailscale-1.102.5-arm64/ca-certificates.crt` | 181724 | `028fca5150ee1915c4474489985d55c54fceaa680c754cc8d1301734f01b2232` | MATCH |

## Candidate and checks

New exclusive candidate: `target/candidates/rebuild-20261103T231415Z/candidate.json` → `/DATA/vprouter-lab/candidates/rebuild-20261103T231415Z/candidate.json`. The previous `rebuild-20261103T225738Z` was not used or modified: recursive file membership/SHA256 snapshot before work equals the final snapshot exactly. New driver ran once and exited 0; all nested commands and output are in `candidate-build.log`. Its `partial-build.json` is the retained intermediate checkpoint (`CONTEXTS_NOT_BUILT` at that instant); the completed `candidate.json`, contexts and root-verification.json establish the later completed static freeze.

For both musl targets, the unchanged driver used the given Zig CC/AR wrappers, `rust-lld`, and both global/target `-C relocation-model=static`; it rebuilt observer/monitor/init and compile-only actual_lab payloads, rechecked init stability, retained the exact x86 filter copy and executed it. All program manifest bytes ended unchanged from HEAD; no source/manifests were edited for a different release or policy. Both contexts pass the strict four-role inventory checker (7 files each); both payloads pass the static ELF64 little-endian/machine62 or183/no PT_DYNAMIC or PT_INTERP check. Both init checks passed per architecture.

Frozen source binding: commit object `1b65709a1189a5fff0fb62c47877e349d4f4f0c4`, source archive SHA256 `4b0c5af101405476e130c61cbedf041a6542c401e2eb324045982488b9c70807`, **203/203** tracked build inputs verified, source aggregate SHA256 `4274b1969cb51eddfac9c7fe52442913c0688f1dc1cc24eae8a77c7481e110fd`. Source bytes also matched the current working build inputs. Temporary-index `read-tree/add/write-tree`, `commit-tree`, exclusive `update-ref ... 000...000`, and `git archive` are the explicitly authorized local freeze writes; ordinary index and branch were preserved until requested final staging.

Every Git ref created (full before/after `git show-ref` comparison, no old ref changed):

- `refs/vprouter-test-candidates/20261103T231415Z` → `1b65709a1189a5fff0fb62c47877e349d4f4f0c4` (receipt `created-ref.json`).

`copy-frozen-contexts.py`, `verify-continuation-candidate.py`, and `verify-frozen-inspection-preflight.py` each exited 0. Frozen preflight reported 203 source matches, exact payload SHA match, normal-fixture descriptor matches the closed policy, and 9 mechanically validated records. Its full stdout/stderr, expected negative diagnostics, actual wait statuses and bounded route-read/filter evidence are retained in `amd64.frozen-preflight.json`; it does not prove privileged provisioning, namespace movement, successful capacity transfer, Bootstrap or router performance. The executable copy/mechanics validator and original result remain in the durable preflight directory. This is the requested unprivileged frozen inspection/mechanics preflight, not a separately invented guest clock qualification. No further timing/acceptance claims are made.

All retained candidate files, freshly SHA256 hashed in `final-audit.json`:

| Candidate-local file | Bytes | SHA256 |
| --- | ---: | --- |
| `amd64.context.tar` | 51804160 | `da7c2e8e257e4c243223c3964b9ce7ba7ebc8b574ddeed00e6bff0174fa49e6f` |
| `amd64.filter-preflight` | 14827240 | `d8ae01f00e540879fe0e3cd68200b2f13677f441e057d2718137ec5d965ba715` |
| `amd64.filter-preflight.log` | 10404 | `055a951981292781181d5374c5405155926c640328bff222a9f8070b3ba265c2` |
| `amd64.frozen-preflight.json` | 16178 | `c0d735c5cd889d2104016c2c509f2b64dc02b895859adccb82b395bc434253a3` |
| `amd64.gateway_init` | 584096 | `ad31d4343c4e7b1eab9fb9c1c7b2e1e75d1ab30eda8bf1f6451abca33e52c792` |
| `amd64.payload` | 14827240 | `d8ae01f00e540879fe0e3cd68200b2f13677f441e057d2718137ec5d965ba715` |
| `amd64.worker_monitor` | 4814272 | `43ff9662baf0909f88a7c11c379fd6d7860b3125ca987c9e5d729b818e372883` |
| `amd64.worker_observer` | 3299544 | `0ed6eccb1825d30a81048391303326fdc24d187679cac9726a17849fa6489ec7` |
| `arm64.context.tar` | 49377280 | `51023de0b7bbab71a40e1882662d50327d8643f1f45051c466655207666f406d` |
| `arm64.gateway_init` | 622744 | `68c3166102ba3987157a16b74d125767a6bb4cf692f503a0078b29a88cd835f9` |
| `arm64.payload` | 15176584 | `a7f3ba5423e707d4af60488f69130c01c780428c7ef9849e25c028092177e7ec` |
| `arm64.worker_monitor` | 4932848 | `9aa5aee63a6d3d7a15633d9d5d2e1077b3dc613b0a27d2996b624b57eabc2f4c` |
| `arm64.worker_observer` | 3482432 | `44f88c23cf7fbe61eef3f6f131517dd8b0732ec04fd378822df9b2b2021cb217` |
| `candidate.json` | 1410 | `f5fed122355d416a76d129a45ce4f64a462899c791f55b0f202ebe177201a1ee` |
| `created-ref.json` | 112 | `3a58cdd37ba8e0f77b012960f8104b5253e811dd9b25f6e03958c5f7d21a8597` |
| `partial-build.json` | 864 | `83895d8ea95349dc6d62aee47b1610e774cca0057c3d83d4a83793ec076443e5` |
| `root-verification.json` | 25538 | `0cdc855216c4ec45890992e9ccc0d69bf3a32c7ad797738e0d902a5bbe3e933a` |
| `source.tar` | 4741120 | `4b0c5af101405476e130c61cbedf041a6542c401e2eb324045982488b9c70807` |

## Commands and results

The following are the exact top-level execution commands after evidence setup, in execution-start order. Each was invoked through `python3 /DATA/AppData/vprouter-rust-v2/target/lab-state/phase2-evidence-20261103T231103Z/run.py LABEL COMMAND...`; full stdout/stderr is in the named durable log and exact argv/timestamps in `commands.jsonl`. Scripts referenced here are retained executable source, not descriptions. The script setup used exclusive evidence-directory creation, entry HEAD/status/ref snapshots, recursive old-partial hashes and saved helper source writes; all completed without exception.

| Command | Exit | Full log |
| --- | ---: | --- |
| `ssh-keygen -t ed25519 -N '' -C vprouter-phase2-dedicated-lab-20261103 -f target/lab-state/id_ed25519` | 0 | `keygen.log` |
| `python3 target/platform-lab/start-additional-clean-debian.py` | 0 | `launch.log` |
| `python3 target/lab-state/phase2-evidence-20261103T231103Z/fetch-index.py` | 0 | `fetch-index.log` |
| `cargo fmt --all --check` | 0 | `cargo-fmt.log` |
| `cargo test --workspace --locked` | 0 | `cargo-test.log` |
| `python3 target/lab-state/phase2-evidence-20261103T231103Z/pin-host-key.py` | 0 | `pin-host-key.log` |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | 0 | `cargo-clippy.log` |
| `python3 target/lab-state/phase2-evidence-20261103T231103Z/verify-guest.py` | 0 | `verify-guest.log` |
| `python3 tools/pinned-tailscale-program-inventory.py amd64 --ssh-port 22036 --ssh-key target/lab-state/id_ed25519 --ssh-known-hosts target/lab-state/known_hosts` | 0 | `inventory-amd64.log` |
| `python3 tools/pinned-tailscale-program-inventory.py arm64 --ssh-port 22036 --ssh-key target/lab-state/id_ed25519 --ssh-known-hosts target/lab-state/known_hosts` | 0 | `inventory-arm64.log` |
| `python3 target/lab-state/phase2-evidence-20261103T231103Z/verify-inventory.py` | 0 | `verify-inventory.log` |
| `python3 tools/rust-v2-lab/rebuild-20261103-build.py` | 0 | `candidate-build.log` |
| `python3 target/copy-frozen-contexts.py target/candidates/rebuild-20261103T231415Z/candidate.json` | 0 | `copy-contexts.log` |
| `python3 target/verify-continuation-candidate.py target/candidates/rebuild-20261103T231415Z/candidate.json` | 0 | `verify-candidate.log` |
| `python3 target/verify-frozen-inspection-preflight.py target/candidates/rebuild-20261103T231415Z/candidate.json` | 0 | `frozen-preflight.log` |
| `python3 target/lab-state/phase2-evidence-20261103T231103Z/retain-artifacts.py` | 0 | `retain-artifacts.log` |
| `python3 target/lab-state/phase2-evidence-20261103T231103Z/final-audit.py` | 0 | `final-audit.log` |

All shown execution commands exited 0. No launch, registry, SSH, acquisition, build or verifier failure occurred. Expected negative-test diagnostics remain verbatim in the preflight logs and result JSON; they were not edited away or counted as command failures. No failed build or candidate was silently repaired/rerun.

Nested driver command sequence (all exited 0, captured verbatim by the driver log; repeated commands intentionally retained):

```sh
cargo build --locked --release --target x86_64-unknown-linux-musl -p vprouter-worker --bin vprouter-worker-observe --bin vprouter-worker-monitor
cargo build --locked --release --target x86_64-unknown-linux-musl -p vprouter-launch --bin vprouter-gateway-init
cargo build --locked --release --target x86_64-unknown-linux-musl -p vprouter-launch --bin vprouter-gateway-init
cargo test --locked --release --target x86_64-unknown-linux-musl -p vprouter-launch --test actual_lab --no-run --message-format=json
cargo build --locked --release --target x86_64-unknown-linux-musl -p vprouter-launch --bin vprouter-gateway-init
cargo build --locked --release --target aarch64-unknown-linux-musl -p vprouter-worker --bin vprouter-worker-observe --bin vprouter-worker-monitor
cargo build --locked --release --target aarch64-unknown-linux-musl -p vprouter-launch --bin vprouter-gateway-init
cargo build --locked --release --target aarch64-unknown-linux-musl -p vprouter-launch --bin vprouter-gateway-init
cargo test --locked --release --target aarch64-unknown-linux-musl -p vprouter-launch --test actual_lab --no-run --message-format=json
cargo build --locked --release --target aarch64-unknown-linux-musl -p vprouter-launch --bin vprouter-gateway-init
git rev-parse HEAD
python3 tools/build-gateway-context.py --architecture amd64
python3 tools/build-gateway-context.py --architecture arm64
git rev-parse HEAD
git read-tree d62ab24e172badb9245fa5f20d71f15930731839
git add -u
git add -- Cargo.toml Cargo.lock rust-toolchain.toml crates examples/v2 docs/rust-v2/programs-amd64.json docs/rust-v2/programs-arm64.json
git write-tree
git update-ref refs/vprouter-test-candidates/20261103T231415Z 1b65709a1189a5fff0fb62c47877e349d4f4f0c4 0000000000000000000000000000000000000000
python3 tools/verify-frozen-build-inputs.py /DATA/AppData/vprouter-rust-v2/target/candidates/rebuild-20261103T231415Z/source.tar 1b65709a1189a5fff0fb62c47877e349d4f4f0c4
```

Additional successful driver subprocesses not printed by its `run()` helper: `amd64.filter-preflight --inspection-filter-selftest` (exact retained payload byte copy, timeout30); `git commit-tree TREE -p d62ab24e172badb9245fa5f20d71f15930731839` (Codex/codex@localhost identity only on this subprocess, message `Local Rust v2 test candidate 20261103T231415Z`); `git archive --format=tar 1b65709a1189a5fff0fb62c47877e349d4f4f0c4 Cargo.toml Cargo.lock rust-toolchain.toml crates examples/v2 docs/rust-v2/programs-amd64.json docs/rust-v2/programs-arm64.json`. Actual exact commit/ref/tree are recoverable from the retained ref/object and log. No repository identity configuration was changed.

Nested guest commands are fully retained in `verify-guest.py`, the inventory tool and `final-audit.py`. Explicitly, both inventory invocations execute strict SSH `sudo python3 -`, then guest Docker `pull --platform linux/ARCH tailscale/tailscale@DIGEST`, `image inspect IMAGE`, `create --network none --read-only --cap-drop ALL --security-opt no-new-privileges --label io.vprouter.lab=public-program-inventory --entrypoint /usr/local/bin/tailscaled IMAGE --version`, `inspect CID`, three `docker cp CID:ALLOWLIST_PATH -` public tar streams, a second inspect and exact `docker rm CID`. All subprocesses used `check=True`; both top-level inventories and final empty-container check succeeded. Cloud-init package/update/service commands and outputs are in the live serial log and its retained snapshot. QMP executed only `qmp_capabilities`, `query-kvm`, `query-status`; no stop/quit/reboot was sent.

Inspection/setup command ledger: `cat`/`sed` reads of the requested reports/controllers/inventory/skills completed; `rg` memory/AGENTS/controller/serial searches were read-only (a search without matches returns 1); entry `git status --short` was empty, `git branch --show-current` returned rust/v2, `git rev-parse HEAD` returned d62ab24e172badb9245fa5f20d71f15930731839; `ls -ld` confirmed all eight durable symlinks; `ls` of the absent preflight output directory returned absence before its new symlink creation; `git check-ignore -v` confirmed this new report needs explicit force-add; `df -h /DATA/vprouter-lab` showed 389G available; `ps -p 3289270 -o pid,lstart,etime,comm` confirmed the owned QEMU; `python3 -m py_compile tools/pinned-tailscale-program-inventory.py`, AST parse, unchanged remote-script AST comparison and `git diff --check` passed. Reversible Python setup/edit helpers wrote only this report, the single inventory-tool delta and ignored durable lab evidence/paths, plus ordinary Python bytecode under target/tools as a result of verification imports. An undone two-line hardening edit is disclosed above; it produced no remaining delta.

Fresh Rust checks: `cargo test --workspace --locked` exited0, 425 passed, 0 failed, 2 ignored across 27 result lines. The actual_lab/localapi guest suites remain skipped/ignored; the host suite is not guest acceptance. `cargo fmt --all --check` exited0 with no output; `cargo clippy --workspace --all-targets --locked -- -D warnings` exited0. They ran on the final inventory-tool implementation; the later driver rewrote manifest files to identical bytes, so no new source delta required a repeat.

## Tracked diff and staging

Exactly two paths are staged: the inventory tool and this new report. Both `programs-*.json` files, Rust source, build driver, archived controllers and acceptance ledger remain byte-identical to HEAD. Staging commands: `git add -- tools/pinned-tailscale-program-inventory.py`; `git add -f -- .superpowers/sdd/rust-v2/task-8c-rebuild-phase2-report.md`; then `git diff --cached --check` and a staged-path/content verification. These final commands must succeed before handback; their command/result receipts live alongside the other evidence. No candidate binaries, key/trust files, guest state or public cache are staged.

Implementation diff SHA256 `5a8b8f46f7f70898dc8f074696ed151173ed7cfe80908d2b256017acfb1c0e7a`; full diff below (display-only blank context whitespace trimmed; the retained diff has exact original bytes):

```diff
diff --git a/tools/pinned-tailscale-program-inventory.py b/tools/pinned-tailscale-program-inventory.py
index 63ee69d..f62053c 100644
--- a/tools/pinned-tailscale-program-inventory.py
+++ b/tools/pinned-tailscale-program-inventory.py
@@ -4,6 +4,7 @@ Creates only a fresh stopped, network-none, state-free container, copies a fixed
 public-file allowlist as tar streams, and removes that exact owned container.
 Never starts a process or accesses any enrolled identity/profile/state directory.
 """
+import argparse
 import hashlib
 import io
 import json
@@ -14,18 +15,32 @@ import subprocess
 import sys
 import tarfile

-assert len(sys.argv) == 2 and sys.argv[1] in ('amd64', 'arm64')
-arch = sys.argv[1]
+parser = argparse.ArgumentParser(description=__doc__)
+parser.add_argument('architecture', choices=('amd64', 'arm64'))
+parser.add_argument('--ssh-port', type=int, required=True)
+parser.add_argument('--ssh-key', type=pathlib.Path, required=True)
+parser.add_argument('--ssh-known-hosts', type=pathlib.Path, required=True)
+args = parser.parse_args()
+assert 1 <= args.ssh_port <= 65535
+assert args.ssh_key.is_file() and args.ssh_known_hosts.is_file()
+arch = args.architecture
 index_digest = 'sha256:c507f3a2a6ab1cabd8d809b98edeb41edbd5c3fb6ad9632ffd098b4c7d0b4065'
 base = pathlib.Path('target/lab-state')
-index = json.loads((base/'tailscale-1.102.5-manifest-index.json').read_text())
+index_bytes = (base/'tailscale-1.102.5-manifest-index.json').read_bytes()
+assert 'sha256:' + hashlib.sha256(index_bytes).hexdigest() == index_digest
+index = json.loads(index_bytes)
 entries = [e for e in index['manifests'] if e['platform'] == {'architecture':arch,'os':'linux'}]
 assert len(entries) == 1 and re.fullmatch(r'sha256:[a-f0-9]{64}', entries[0]['digest'])
 digest = entries[0]['digest']
+pinned = json.loads(pathlib.Path('docs/rust-v2/pinned-program-inventory.json').read_bytes())
+expected = next(p for p in pinned['platforms'] if p['platform']['architecture'] == arch)
+assert 'tailscale/tailscale@' + digest == expected['platform']['platform_manifest']
 image = 'tailscale/tailscale@'+digest
-ssh = ['ssh','-i',str(base/'id_ed25519'),'-o','IdentitiesOnly=yes','-o',
-       'UserKnownHostsFile='+str(base/'known_hosts'),'-o','StrictHostKeyChecking=yes',
-       '-o','ConnectTimeout=5','-p22032','vprouterlab@127.0.0.1']
+ssh = ['ssh','-F','/dev/null','-i',str(args.ssh_key.resolve()),
+       '-o','IdentitiesOnly=yes','-o','BatchMode=yes',
+       '-o','UserKnownHostsFile='+str(args.ssh_known_hosts.resolve()),
+       '-o','GlobalKnownHostsFile=/dev/null','-o','StrictHostKeyChecking=yes',
+       '-o','ConnectTimeout=5','-p',str(args.ssh_port),'vprouterlab@127.0.0.1']
 script = r'''
 import json,os,pathlib,stat,subprocess
 root=pathlib.Path('/var/lib/vprouter-v2-lab')
@@ -77,6 +92,6 @@ subprocess.run(['docker','rm',cid],check=True,stdout=subprocess.DEVNULL,timeout=
 print(json.dumps({'exact_owned_stopped_container_removed':True}))
 '''.replace('CID',repr(cid)).replace('IMAGE_ID',repr(meta['image_id'])).replace('IMAGE',repr(image))
 removed=subprocess.run([*ssh,'sudo python3 -'],input=cleanup,text=True,capture_output=True,check=True,timeout=12)
-report={'schema_version':1,'tailscale_version':'1.102.5','source_index':'tailscale/tailscale@'+index_digest,'inventory_tool_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'platform':meta,'public_files':rows,'cleanup':json.loads(removed.stdout),'runtime_execution':'NOT_RUN','production_changes':False}
+report={'ssh_endpoint':{'host':'127.0.0.1','port':args.ssh_port,'user':'vprouterlab','key':str(args.ssh_key.resolve()),'known_hosts':str(args.ssh_known_hosts.resolve()),'known_hosts_sha256':hashlib.sha256(args.ssh_known_hosts.read_bytes()).hexdigest()},'schema_version':1,'tailscale_version':'1.102.5','source_index':'tailscale/tailscale@'+index_digest,'inventory_tool_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'platform':meta,'public_files':rows,'cleanup':json.loads(removed.stdout),'runtime_execution':'NOT_RUN','production_changes':False}
 (base/('tailscale-program-inventory-'+arch+'.json')).write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps(report,indent=2))
```

## Limits and next-phase boundary

Nothing in tasks A–D remains blocked: the fresh guest is running, exact public bytes recovered, coherent candidate frozen and requested static/preflight commands completed. This does not establish any acceptance or historical preservation result. No Bootstrap/run409 or baseline authoring occurred; ARM64 runtime, historical raw-reader replay, independently authored/reviewed new baseline, run numbering/reservation and all privileged experiment/acceptance gates remain NOT_RUN/pending their separate phase. No original identity, PID, namespace, retained resource or raw historical evidence was recreated. Phase 3 must consume the declared new identity and explicitly handle the historical discontinuity.

## Six-line summary

Fresh Debian x86_64 KVM guest is running: PID 3289270, start tick 4458761, SSH 22036.
Dedicated new ed25519 access key and console-verified strict host trust are retained in durable lab-state.
Pinned index/platform images and all six public files match the tracked sizes and SHA256 values.
New candidate rebuild-20261103T231415Z passed context copy, 203-input binding, static verification and frozen preflight.
One exclusive candidate ref created; rust/v2 stayed at d62ab24; required Rust checks passed; changes staged only.
Old lab identity continuity is permanently broken; no Bootstrap, baseline authoring, enrollment or acceptance claim.
