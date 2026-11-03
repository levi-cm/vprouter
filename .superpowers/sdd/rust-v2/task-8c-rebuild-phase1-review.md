# Independent review: native lab rebuild phase 1

Overall: **PASS for the bounded phase-1 restoration, partial build and guest-free substrate.** This is not approval to run phase 2 unchanged: the Important integration finding below must be resolved before using the archived inventory tool with the additional guest. No coherent candidate, guest execution, historical continuity or runtime/acceptance result is approved.

Reviewed on 2026-11-04 in `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`, HEAD `ab4776cc6a09b88d2fab6fc8a1a789b2c3f8c839`. Both implementer reports were treated as claims. The phase-1A report is also staged, in addition to the three implementation files named in the review request. The phase-1B report is ignored. No tracked or staged content was changed; this new requested review is ignored. Review scratch and fresh command logs are under `target/rebuild-phase1-review/`. No build driver, launcher, inventory acquisition, guest creation/boot, SSH, sudo, Git write, subagent or network mutation was invoked.

## Findings

### Critical

None found within phase 1.

### Important — phase-2 integration prerequisite, inherited rather than introduced

**I1: The archived inventory tool addresses a different guest endpoint.** `tools/pinned-tailscale-program-inventory.py:26-28` fixes SSH to port **22032**, whereas `target/platform-lab/start-additional-clean-debian.py:19` selects **22036**. The inventory tool also requires dedicated `id_ed25519` and strict `known_hosts`, and runs remote sudo/Docker (`:47`, `:53`, `:79`). Current `target/lab-state` is empty. Concrete failure: booting the additional guest and invoking the unmodified inventory tool would fail to connect to that guest; if another correctly trusted endpoint occupied 22032, the tool could operate on that endpoint instead. Phase 2 must explicitly bind its reviewed inventory recovery to the owned fresh guest, port, SSH identity and host key, and verify that guest's isolation marker/Docker before acquisition. Do not weaken strict SSH checking or assume the two tools already fit together. This does not invalidate the acquired guest-free phase-1 substrate.

### Minor

**M1: Historical absence of writes outside the declared paths is not independently established.** `.superpowers/sdd/rust-v2/task-8c-rebuild-phase1a-report.md:15-24` records exact restore destinations and its copying procedure. All 293 recorded destinations and bytes were verified, with no extra top-level `target/*.py` or platform-lab files found. However, neither that restore log nor Git diffs constitute a complete before/after filesystem inventory or syscall write trace. Concrete failure scenario: an unrelated ignored file elsewhere could have been written and would not be detected by those records. No such extra write was observed. The review confirms the current destination set and tracked delta; the stronger historical whole-filesystem negative remains **UNPROVEN**, not silently marked PASS.

**M2: Some driver changes are explicit hardening/diagnostics, not literally forced by vanished paths.** `tools/rust-v2-lab/rebuild-20261103-build.py:11`, `:18`, `:24`, `:75-76`, `:109-111` add optimized-Python refusal, logging, retained failure output and exclusive ref creation/receipt. Concrete behavioral difference: Python `-O` now refuses immediately, and an existing same-name candidate ref now causes failure rather than replacement. These strengthen preservation and checking; they are disclosed in the phase-1A report and acceptable for phase 1. They should not be described as mere path substitutions. No undisclosed check weakening was found.

## Restoration and write scope

Fresh command `python3 target/rebuild-phase1-review/verify.py` exited **0**. It reads every `files` entry in `tools/rust-v2-lab/source-manifest.json`, checks both the archive and original `source_path` against `bytes` and SHA256, checks unique destinations, and audits the current controller path sets. Result: **293 unique entries, 586 file validations, zero mismatches**. Manifest SHA256: `9a30c580290ce3fad2c142c335675283a4f5c25f749b33c2c42a2f0e6f5053e9`.

Fresh `python3 target/rebuild-phase1-review/verify-extra.py` exited **0**, including exact comparison of all 293 restore-log rows to the manifest. No additional top-level controller Python files or files under `target/platform-lab` were found. All eight requested durable paths remain symlinks into `/DATA/vprouter-lab`: lab-state, lab-images, lab-tools, platform-lab, program-inventory, toolchains, gateway-context and candidates. The source manifest contains no restored lab-tools/lab-images destination. See M1 for the limit on historical write attribution.

The only staged paths are:

- `.superpowers/sdd/rust-v2/task-8c-rebuild-phase1a-report.md`
- `docs/rust-v2/programs-amd64.json`
- `docs/rust-v2/programs-arm64.json`
- `tools/rust-v2-lab/rebuild-20261103-build.py`

The staged binary diff and tracked worktree binary diff were snapshotted under review scratch and compared byte-for-byte after the checks: both unchanged. HEAD remained as above. `git diff --cached --check` exited **0**. No Nov3/Nov4 candidate ref exists; older historical candidate refs do exist. This review performed no ref writes.

## Driver comparison

Exact read-only comparison: `diff -u target/implementation-20261026-build.py tools/rust-v2-lab/rebuild-20261103-build.py` (exit **1**, meaning differences found). Original SHA256 `0b6afdae0761439900782a010ec1fa48e27b02037c0305c296cfe5483804fc58`; new SHA256 `5be9019c509137498f0b43a9357a121125963cacc730808afad41112f08d2c78`.

Every diff hunk was reviewed:

1. Shebang/docstring and optimized-Python refusal: adds a check; no weakening (M2).
2. `target/continuation-*` becomes exclusive `target/candidates/rebuild-*`, using the durable candidate symlink. Added path/command logging does not change subprocess return values.
3. CC switches from missing target/toolchains executables to the stated Zig-cross wrappers; adds matching AR and target static flags. Global static flags, rust-lld, locked release commands, target triples and actual_lab compilation remain. This changes the native toolchain/build bytes intentionally; compiled bytes were checked below. There is no alternative-toolchain fallback.
4. Filter preflight still copies the retained exact x86 musl payload, compares its SHA256, uses `--inspection-filter-selftest` and timeout 30. `check=False` is immediately followed, after saving stdout/stderr, by `check_returncode()`: a nonzero exit still aborts. A timeout still aborts. No glibc/debug substitution or ARM execution was introduced.
5. Context creation moves after **both** architecture build/update/stability sequences. This intentionally changes failure timing: missing amd64 public cache now leaves both artifact sets and updated manifests, rather than stopping before ARM64 compilation. Neither context validation is dropped. The added `partial-build.json` explicitly says `CONTEXTS_NOT_BUILT`, native/ARM runtime NOT_RUN and release_ready false; it is not `candidate.json`.
6. Candidate ref creation now uses expected-old zero and writes a receipt (M2). It still creates a local Git object/ref if reached; the driver is not a read-only command. This section was not reached in phase 1 and was not executed by the reviewer.

The three original AST assertion expressions are identical, checked programmatically. Observer **and monitor** builds are retained; all three Rust role hash/size updates remain; both post-manifest init stability assertions per architecture remain. Source freezing still uses a temporary index, read-tree, add/update, write-tree, commit-tree and Git archive, followed by the unchanged `tools/verify-frozen-build-inputs.py` call. The source verifier compares every frozen build-input tar byte to the exact commit and checks complete membership. Candidate writing still occurs only after contexts and source binding succeed. These later paths are statically reviewed, **NOT_RUN**, not runtime-proven. No silent semantic change beyond the enumerated changes was found.

## Program manifests and artifact hashes

Exact command: `git diff --cached -- docs/rust-v2/programs-amd64.json docs/rust-v2/programs-arm64.json` (exit **0**). JSON comparison against HEAD and the index confirms only observer/monitor SHA256 and byte counts changed: four scalar fields per architecture. Staged and working manifest bytes agree. Gateway-init entries, daemon entries, policies, architecture/base bindings and other fields are untouched. No unrelated manifest entry or pinned public input changed.

Fresh SHA256/size computations covered both each driver's `target/<triple>-unknown-linux-musl/release/` output and its retained `target/candidates/rebuild-20261103T225738Z/<arch>.<program>` copy:

| Arch | Program | Bytes | Recomputed SHA256 |
| --- | --- | ---: | --- |
| amd64 | worker-observe | 3299544 | `0ed6eccb1825d30a81048391303326fdc24d187679cac9726a17849fa6489ec7` |
| amd64 | worker-monitor | 4814272 | `43ff9662baf0909f88a7c11c379fd6d7860b3125ca987c9e5d729b818e372883` |
| amd64 | gateway-init | 584096 | `ad31d4343c4e7b1eab9fb9c1c7b2e1e75d1ab30eda8bf1f6451abca33e52c792` |
| arm64 | worker_observer | 3482432 | `44f88c23cf7fbe61eef3f6f131517dd8b0732ec04fd378822df9b2b2021cb217` |
| arm64 | gateway_init | 622744 | `68c3166102ba3987157a16b74d125767a6bb4cf692f503a0078b29a88cd835f9` |
| arm64 | worker_monitor | 4932848 | `9aa5aee63a6d3d7a15633d9d5d2e1077b3dc613b0a27d2996b624b57eabc2f4c` |

All six match their staged manifests and retained copies. Both retained actual_lab payload hashes match `partial-build.json`; the x86 preflight copy matches the x86 payload. All eight retained programs/payloads pass fresh ELF64 little-endian, machine 62/183, PT_LOAD-present and PT_DYNAMIC/PT_INTERP-absent checks. These are static artifact checks. The original local filter-preflight log was inspected, not rerun as part of this review. No claim is made that a later candidate/source freeze exists or that these binaries have passed guest qualification.

## Fresh Rust checks

Commands ran from the repository root, with combined output retained verbatim:

```sh
cargo test --workspace --locked > target/rebuild-phase1-review/cargo-test.log 2>&1
cargo fmt --all --check > target/rebuild-phase1-review/cargo-fmt.log 2>&1
cargo clippy --workspace --all-targets --locked -- -D warnings > target/rebuild-phase1-review/cargo-clippy.log 2>&1
```

All three exited **0**. Cargo test summaries total **425 passed, 0 failed, 2 ignored** across 27 result lines. The log also explicitly says `SKIP: requires controller-owned disposable guest and --ignored`; a successful host test command does not establish the skipped guest checks. Formatting emitted no differences. Clippy completed with warnings denied. No ignored guest suite was enabled.

## Phase 1B substrate

Fresh `verify.py` uses `hashlib.file_digest` to recompute the image SHA512 and requires exactly one matching filename entry in `SHA512SUMS-20261021-2638`. Result **PASS**:

```text
Image: target/lab-images/debian-13-genericcloud-amd64-20261021-2638.qcow2
Bytes: 342294528
SHA512: 16e0965312c56feb331049d45d2b1b5778f3f942a33d4300eedbb97527707f2bea87c0006f3e4cc7a25fadbff739c4e235a51fb9bcd1b66fd554f7f8e80ba45c
SHA256: d3a5c93cc98b34651421e0fa3a37db428f07355a3bc4cf46d6fbeb001f258e90
SHA512SUMS SHA256: 5e22239e7bcb7ac4056324aa1829620f2853bff0c3b77b3af8c4578642c0f359
```

All **95** retained `.deb` files were freshly hashed and sized against `packages-verified.json`, including both expected and recorded actual SHA256, and independently cross-checked against all 95 report table rows: **PASS**, 40,904,756 compressed bytes. `verify-extra.py` additionally streams `dpkg-deb --fsys-tarfile FILE` for qemu-system-x86, qemu-utils and genisoimage and compares each extracted executable's bytes to the installed lab-tree executable: **3/3 PASS**, without extracting or installing anything. This review checks retained package/file integrity; it does not reassert upstream signature verification or repository freshness from the implementer's receipts. The phase-1B report already discloses the expired historical security metadata and unsigned image-manifest verification boundary.

The launcher was read, not imported/executed. The following exact environment and executable commands were run by `verify.py`, each with a 30-second timeout:

```sh
export LD_LIBRARY_PATH=/DATA/AppData/vprouter-rust-v2/target/lab-tools/root/usr/lib/x86_64-linux-gnu
export QEMU_MODULE_DIR=/DATA/AppData/vprouter-rust-v2/target/lab-tools/root/usr/lib/x86_64-linux-gnu/qemu
/DATA/AppData/vprouter-rust-v2/target/lab-tools/root/usr/bin/qemu-system-x86_64 --version
/DATA/AppData/vprouter-rust-v2/target/lab-tools/root/usr/bin/qemu-img --version
/DATA/AppData/vprouter-rust-v2/target/lab-tools/root/usr/bin/genisoimage --version
ldd /DATA/AppData/vprouter-rust-v2/target/lab-tools/root/usr/bin/qemu-system-x86_64
ldd /DATA/AppData/vprouter-rust-v2/target/lab-tools/root/usr/bin/qemu-img
ldd /DATA/AppData/vprouter-rust-v2/target/lab-tools/root/usr/bin/genisoimage
/DATA/AppData/vprouter-rust-v2/target/lab-tools/root/usr/bin/qemu-img info --output=json /DATA/AppData/vprouter-rust-v2/target/lab-images/debian-13-genericcloud-amd64-20261021-2638.qcow2
```

All exited **0**. Outputs report QEMU/qemu-img **10.0.13**, genisoimage **1.1.11**; ldd reports no missing dependencies. `qemu-img info` reads the base as qcow2, virtual size 3,221,225,472, dirty-flag false and corrupt false. No overlay was created. Full stdout/stderr and argv are retained in `verification.json`. Tool version and image-information checks do not prove combined launcher, KVM, networking or guest behavior.

Read-only path enumeration and `/proc/<pid>/comm` scan found:

- `target/platform-lab/debian-clean-x86_64` absent.
- No guest.qcow2, seed.iso, process.json, qemu.pid, qmp.sock, user-data or meta-data under platform-lab/lab-state/lab-images, and no additional qcow2/ISO there.
- Empty `target/lab-state` and `target/gateway-context`; no dedicated lab key, trusted-host file or OCI index present.
- No visible qemu-system process on this host at review time.

This confirms current guest-free state in the declared lab locations and visible process set. It cannot establish that no process existed historically or inspect unrelated hosts/namespaces.

## Correct stopping boundary and exact phase-2 inputs

**The stop is correct.** `tools/build-gateway-context.py:61-73` unconditionally reads all three built Rust roles, pinned tailscaled, then the pinned CA. `checked()` at `:17-44` rejects missing files, wrong size/digest and nonstatic/wrong-machine executable bytes before output creation at `:81-82`. `target/program-inventory` is empty. Thus stock context construction cannot succeed with the present files. The original driver result/log records exit 1 at missing amd64 tailscaled; this review verified the missing dependency statically and did not rerun a driver that would rewrite manifests and eventually Git objects/refs.

Minimum context-cache inputs, with the existing tracked inventory and manifests unchanged:

| Arch | File beneath target/program-inventory/ | Bytes | Required SHA256 |
| --- | --- | ---: | --- |
| amd64 | tailscale-1.102.5-amd64/tailscaled | 42902060 | `b2ec98126c6ee19d7b3603b0cfee97c5dd646874065aed7016653d30ff92a9cd` |
| amd64 | tailscale-1.102.5-amd64/ca-certificates.crt | 181724 | `028fca5150ee1915c4474489985d55c54fceaa680c754cc8d1301734f01b2232` |
| arm64 | tailscale-1.102.5-arm64/tailscaled | 40133663 | `3cf2640069ded59322dc2113be5fa90540937410be22bb40873a614773ab27cc` |
| arm64 | tailscale-1.102.5-arm64/ca-certificates.crt | 181724 | `028fca5150ee1915c4474489985d55c54fceaa680c754cc8d1301734f01b2232` |

These exact public bytes are necessary for the unchanged context builder; a running guest is **not intrinsic** to constructing the tar context from already verified public bytes. However, **the archived inventory acquisition tool does require a running, reachable guest**. Its `:21` reads a local OCI manifest index, `:26-28` fixes the strict SSH identity/trust/endpoint, and `:32-47` requires guest root, protected isolated-acceptance marker and Docker pull/create. Only the *container* remains stopped; that is not a statement that the guest is stopped. It copies a fixed three-file allowlist and removes the exact owned stopped container (`:52-79`). ARM64 extraction does not execute ARM64 binaries.

Phase 2 must provide:

1. A reviewed acquisition route for the exact pinned public bytes. If using the archived inventory tool, restore/authenticate `target/lab-state/tailscale-1.102.5-manifest-index.json` against index `sha256:c507f3a2a6ab1cabd8d809b98edeb41edbd5c3fb6ad9632ffd098b4c7d0b4065` and the tracked platform digests: amd64 `sha256:08a1bc6c82fee62d1a135788fb67fefa9d22deea3830e8a45ebe1a3cb116e325`, arm64 `sha256:472c549d2ef8cebc000de2c8a94061bbdc864d2454177b2ada713262475449ef`. Do not merely trust an arbitrary replacement JSON index: the tool declares `index_digest` but does not itself hash the index file against that value.
2. For that guest-based route, dedicated lab key and explicitly verified known_hosts, the owned isolated fresh Debian guest with Docker and required root-owned marker, and an explicitly reviewed endpoint binding resolving I1. Guest creation/boot, provisioning and remote sudo/Docker operations belong to that later authorized phase. No existing guest, enrolled identity or provider credentials are required or appropriate inputs.
3. Retain and verify all three public files per architecture if running the archived inventory: the table's daemon/CA plus amd64 CLI `tailscale` (33116853 bytes, SHA256 `344ac0aadfcc98aa2567aa4ce96b38b3faa9c5fbc849b7b1bd5feaa6c1563a2f`) and arm64 CLI (30825099 bytes, SHA256 `b01efc25199dd023e1c9b93e8166b7afbc56dd941f18d4a8f9401933d258ddd7`). The CLI is an inventory output, not a context-builder dependency. Preserve acquisition/cleanup provenance and compare all output hashes against the existing tracked pinned inventory; do not substitute current host CA or another Tailscale release.
4. With cache available, execute the reviewed build/freeze workflow in a new exclusive candidate directory under a scope allowing its manifest and Git object/ref writes. Complete both contexts, exact source archive/binding, immutable candidate context copying, `target/verify-continuation-candidate.py` and `target/verify-frozen-inspection-preflight.py`. Keep this phase's partial evidence unchanged. Missing cache is the first blocker, not proof that every later check will succeed.
5. Before any Bootstrap experiment, separately complete fresh baseline authoring/independent review, historical-evidence-gap disposition, numbering/reservation, owned guest admission and one-shot experiment prerequisites in the assessment. Public cache recovery or a complete static candidate cannot restore deleted guest/raw-history continuity.

Current retained `rebuild-20261103T225738Z` contains partial metadata and artifacts, but no candidate.json, source.tar or root-verification.json, and no contexts exist. Candidate verification, full frozen mechanics/clock verification, guest execution, Bootstrap, ARM64 runtime and all release/acceptance gates remain **NOT_RUN** by this review.

## Reproduction and evidence

The complete read/hash/AST/tool-invocation verification is retained as actual executable source in `target/rebuild-phase1-review/verify.py` and `verify-extra.py`; neither imports a restored controller. Fresh review commands and outcomes:

```text
python3 target/rebuild-phase1-review/verify.py                 exit 0
python3 target/rebuild-phase1-review/verify-extra.py           exit 0
cargo test --workspace --locked                              exit 0
cargo fmt --all --check                                      exit 0
cargo clippy --workspace --all-targets --locked -- -D warnings exit 0
git diff --cached --check                                    exit 0
diff -u target/implementation-20261026-build.py tools/rust-v2-lab/rebuild-20261103-build.py
                                                            exit 1 (reviewed differences)
git diff --cached -- docs/rust-v2/programs-amd64.json docs/rust-v2/programs-arm64.json
                                                            exit 0
```

Detailed recomputed values/tool argv/stdout/stderr are in `verification.json`; Rust command outputs are in `cargo-{test,fmt,clippy}.log`; index/worktree snapshots are `index-before.diff` and `worktree-before.diff`. `review-readonly-results.json` records preservation comparisons. No acceptance ledger or historical evidence was rewritten.

Overall: PASS for phase 1 only; no runtime or acceptance approval.
Integrity: 293 restored controllers, six manifest-bound programs, image and 95 packages verified.
Checks: workspace tests 425 passed/2 ignored; fmt and Clippy passed.
Findings: no Critical; one Important phase-2 endpoint prerequisite; two Minor qualifications.
Next: recover exact pinned public inputs, bind the owned guest route, then complete candidate and independent baseline gates.
