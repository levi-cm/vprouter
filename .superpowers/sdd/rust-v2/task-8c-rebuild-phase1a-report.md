# Task 8c rebuild Phase 1A report

Phase 1A completed its local restoration/build work and stopped at the missing public-cache boundary. **No coherent continuation candidate was produced.** No VM/guest was created or booted, no SSH/sudo was used, and no network/firewall/Tailscale settings were changed. No subagents, commit, push, stash, checkout or branch move was performed. Phase 1B's `target/lab-tools` and `target/lab-images` were not touched by this work.

## Source and permanently broken continuity

Worktree: `/DATA/AppData/vprouter-rust-v2`; branch `rust/v2`; initial and final HEAD `ab4776cc6a09b88d2fab6fc8a1a789b2c3f8c839`. The entry worktree/index was clean. Rust sources were not changed. Both program manifests now describe the exact new binaries, including verification of the unchanged init hashes.

The user approved a **fresh baseline**, because the old `target/` was deleted on 2026-11-03 by an unrelated cleanup without a backup. Original guest, raw-record and live-resource continuity is permanently broken. Restored controllers and newly built public binaries do not recover that continuity or prove historical preservation. Historical reader replay, independently authored fresh guest baseline, run409 reservation, guest execution and all runtime/acceptance gates remain outside this phase. No dummy historical run records were created.

Build timestamps use UTC (`20261103T...Z`); local Europe/Berlin date crossed into 2026-11-04 during this work.

## Controller restoration and hash proof

All **293** manifest entries passed archive byte-length and SHA256 validation **before any copying**. Existing destinations, if present, had to match exactly. Each file was then copied with exclusive creation if absent to its original `source_path`, and read back for byte equality. Manifest destinations included the existing `target/platform-lab` symlink directory; no symlink was replaced. No manifest destination was under `target/lab-tools/` or `target/lab-images/`. A subsequent complete destination recheck passed for all 293 files.

- Manifest: `tools/rust-v2-lab/source-manifest.json`, SHA256 `9a30c580290ce3fad2c142c335675283a4f5c25f749b33c2c42a2f0e6f5053e9`.
- Per-file archive/restored paths, sizes, expected hashes and restored hashes: `target/candidates/phase1a-evidence-20261103T225704Z/restore-log.json`.
- Restore log SHA256 `8b0d014d941fd0a759d484e5e0797b49d24206acd961fc661646ada5a7ef5f35`; mismatches: **0**.
- Logs live through `target/candidates` in `/DATA/vprouter-lab/candidates`. Top-level restored ignored controllers remain reconstructible from the tracked archive; `target/platform-lab` is durable through its existing symlink.

The restoration used Python standard-library `json`, `hashlib`, and `pathlib`: read `manifest['files']`, preload and validate every `archive_path` against `bytes`/`sha256`, reject a differing existing `source_path`, then `mkdir(parents=True, exist_ok=True)`, `open('xb')`, and reread/compare. The exact source/destination pairs and both sides' hash proof are retained in the restore log. It did not execute any restored controller.

The core restoration was executed as the following two-pass Python body (inside `python3 - <<'PY'`); `root`, `manifest`, `entries` and the fresh evidence directory were initialized to the paths above. Ref/head snapshots were then saved alongside the restore log.

```python
verified = []
for e in entries:
    data = (root / e['archive_path']).read_bytes()
    assert len(data) == e['bytes'] and hashlib.sha256(data).hexdigest() == e['sha256'], e
    dest = root / e['source_path']
    assert e['source_path'].startswith('target/') and '..' not in pathlib.Path(e['source_path']).parts
    assert not e['source_path'].startswith(('target/lab-tools/', 'target/lab-images/')), e
    if dest.exists():
        assert dest.read_bytes() == data, ('existing destination differs', str(dest))
    verified.append((e, data))
rows = []
for e, data in verified:
    dest = root / e['source_path']
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not dest.exists():
        with dest.open('xb') as f:
            f.write(data)
    actual = dest.read_bytes()
    assert actual == data
    rows.append(dict(e, restored_sha256=hashlib.sha256(actual).hexdigest(), verified_bytes=len(actual)))
```

## New driver and review

New versioned driver: `tools/rust-v2-lab/rebuild-20261103-build.py`.
Original retained unchanged: `target/implementation-20261026-build.py` and its tracked archive.

- Original SHA256 `0b6afdae0761439900782a010ec1fa48e27b02037c0305c296cfe5483804fc58`.
- New SHA256 `5be9019c509137498f0b43a9357a121125963cacc730808afad41112f08d2c78`.
- Full unified diff is pasted below and retained at `target/candidates/phase1a-evidence-20261103T225704Z/driver.diff`.
- Review record: `target/candidates/phase1a-evidence-20261103T225704Z/driver-review.json`. This is implementation self-review, **not an independent review**.

Justification for every change:

1. Add shebang/scope description and reject optimized Python, so the retained assertion checks cannot be disabled with `-O`.
2. Replace `target/continuation-*` with an exclusively created `target/candidates/rebuild-*` directory to satisfy durable storage. Print its path and exact subprocess arguments for retained command evidence.
3. Replace vanished `target/toolchains/*-linux-musl-cc` with `~/.local/share/zig-cross/bin/*-linux-musl-gcc`; set the matching `AR_<target>` wrapper and target-specific static relocation flags. Keep the original global static `RUSTFLAGS` and `rust-lld` linker. No toolchain installation or fallback.
4. Keep the exact retained x86 musl payload copy, digest equality and 30-second preflight timeout. Save combined stdout/stderr before `check_returncode()` so a failure log survives; the same success-exit requirement still applies.
5. Move context construction into a second loop, after both architectures' unchanged build/update/init-stability sequences. The stock copier/verifier require both architectures, so ARM64 remains compile-only. This retains both sets of locally buildable artifacts before the missing-cache boundary without dropping either context check. Add clearly incomplete `partial-build.json`, current parent HEAD, driver digest and discontinuity/NOT_RUN metadata; it is never named or accepted as `candidate.json`.
6. Make the existing candidate ref creation exclusive with an all-zero expected old object id; retain an exact `created-ref.json` receipt if reached. This prevents overwriting an existing freeze ref and meets the requested ref accounting. This code was **not reached**.

All three original AST assertion expressions are identical. Observer **and monitor** builds, all three Rust role updates, both post-manifest init stability assertions per architecture, locked release actual_lab builds, exact x86 retained preflight, context construction, independent Git-index source freeze, `git archive`, and frozen source-binding verification are retained. Later context/freeze checks were not reached and are not reported as passing.

```diff
--- target/implementation-20261026-build.py
+++ tools/rust-v2-lab/rebuild-20261103-build.py
@@ -1,3 +1,5 @@
+#!/usr/bin/env python3
+"""Fresh lab rebuild; ARM64 is compile-only. No VM, SSH or enrollment actions."""
 import datetime
 import hashlib
 import json
@@ -6,15 +8,20 @@
 import subprocess
 import tempfile

+if not __debug__:
+    raise RuntimeError('optimized_python_refused')
+
 root = pathlib.Path.cwd()
 stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
-out = root / 'target' / ('continuation-' + stamp)
+out = root / 'target/candidates' / ('rebuild-' + stamp)
 out.mkdir(mode=0o700)
+print(json.dumps({'build_directory': str(out)}), flush=True)

 def sha(path):
     return hashlib.sha256(path.read_bytes()).hexdigest()

 def run(args, env=None, capture=False):
+    print(json.dumps({'command': args}), flush=True)
     return subprocess.run(args, env=env, check=True, text=True,
                           stdout=subprocess.PIPE if capture else None).stdout

@@ -23,7 +30,10 @@
     target = triple + '-unknown-linux-musl'
     env = dict(os.environ)
     env['RUSTFLAGS'] = '-C relocation-model=static'
-    env['CC_' + target.replace('-', '_')] = str(root / 'target/toolchains' / (triple + '-linux-musl-cc'))
+    cross = pathlib.Path.home() / '.local/share/zig-cross/bin'
+    env['CC_' + target.replace('-', '_')] = str(cross / (triple + '-linux-musl-gcc'))
+    env['AR_' + target.replace('-', '_')] = str(cross / (triple + '-linux-musl-ar'))
+    env['CARGO_TARGET_' + target.replace('-', '_').upper() + '_RUSTFLAGS'] = '-C relocation-model=static'
     env['CARGO_TARGET_' + target.replace('-', '_').upper() + '_LINKER'] = 'rust-lld'
     common = ['cargo', 'build', '--locked', '--release', '--target', target]
     init_args = common + ['-p', 'vprouter-launch', '--bin', 'vprouter-gateway-init']
@@ -60,18 +70,28 @@
         preflight.chmod(0o700)
         assert sha(preflight) == sha(retained_payload)
         checked = subprocess.run([str(preflight), '--inspection-filter-selftest'],
-                                 check=True, text=True, stdout=subprocess.PIPE,
+                                 check=False, text=True, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, timeout=30)
         (out / 'amd64.filter-preflight.log').write_text(checked.stdout)
+        checked.check_returncode()
     run(init_args, env)
     assert sha(root / 'target' / target / 'release/vprouter-gateway-init') == init['sha256']
+    platforms[arch] = {'artifact': str(retained_payload), 'artifact_sha256': sha(retained_payload)}
+
+# Retain both compile-only artifact sets before the public-cache boundary.
+# This is explicitly incomplete evidence, never a continuation candidate.
+partial = {'status': 'CONTEXTS_NOT_BUILT', 'parent_head': run(['git', 'rev-parse', 'HEAD'], capture=True).strip(),
+           'driver_sha256': sha(pathlib.Path(__file__)), 'platforms': platforms,
+           'baseline_discontinuity': 'Old target deleted 2026-11-03 without backup; original guest continuity permanently broken.',
+           'native_bootstrap': 'NOT_RUN', 'arm64_runtime': 'NOT_RUN', 'release_ready': False}
+(out / 'partial-build.json').write_text(json.dumps(partial, indent=2) + '\n')
+for arch in ('amd64', 'arm64'):
     context_dir = root / 'target/gateway-context' / arch
     if context_dir.exists():
         context_dir.rename(context_dir.with_name(stamp + '-previous-' + arch))
     run(['python3', 'tools/build-gateway-context.py', '--architecture', arch])
     context = context_dir / 'context.tar'
-    platforms[arch] = {'artifact': str(retained_payload), 'artifact_sha256': sha(retained_payload),
-                       'context': str(context), 'context_sha256': sha(context)}
+    platforms[arch].update(context=str(context), context_sha256=sha(context))

 # Preserve the branch, index and existing unfinished work. The candidate is an
 # immutable local Git object/ref used solely to bind exact source to test bytes.
@@ -86,7 +106,9 @@
                     GIT_COMMITTER_NAME='Codex', GIT_COMMITTER_EMAIL='codex@localhost')
     source_commit = subprocess.check_output(['git', 'commit-tree', tree, '-p', parent], env=identity,
                        input=('Local Rust v2 test candidate ' + stamp + '\n').encode()).decode().strip()
-    run(['git', 'update-ref', 'refs/vprouter-test-candidates/' + stamp, source_commit])
+    ref = 'refs/vprouter-test-candidates/' + stamp
+    run(['git', 'update-ref', ref, source_commit, '0' * 40])
+    (out / 'created-ref.json').write_text(json.dumps({'ref': ref, 'commit': source_commit}) + '\n')
 source = out / 'source.tar'
 with source.open('xb') as stream:
     subprocess.run(['git', 'archive', '--format=tar', source_commit,
```

## Exact build commands and results

Entry command (one execution, exit **1** at missing cache):

```sh
python3 tools/rust-v2-lab/rebuild-20261103-build.py
```

Full combined stdout/stderr: `target/candidates/phase1a-evidence-20261103T225704Z/build.log`; result receipt: `target/candidates/phase1a-evidence-20261103T225704Z/build-result.json`.

For each `target` (`x86_64-unknown-linux-musl`, then `aarch64-unknown-linux-musl`), the driver set exactly these overrides on the inherited environment (`triple` is `x86_64` or `aarch64`; `T` is the uppercase underscore-form target):

```text
RUSTFLAGS=-C relocation-model=static
CC_<underscore_target>=/home/opsec/.local/share/zig-cross/bin/<triple>-linux-musl-gcc
AR_<underscore_target>=/home/opsec/.local/share/zig-cross/bin/<triple>-linux-musl-ar
CARGO_TARGET_<T>_LINKER=rust-lld
CARGO_TARGET_<T>_RUSTFLAGS=-C relocation-model=static
```

Actual subprocess commands in order (all Cargo commands exited 0; the final context command exited 1):

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
```

Between the x86 actual_lab build and final x86 init rebuild, the driver executed exactly:

```sh
/DATA/AppData/vprouter-rust-v2/target/candidates/rebuild-20261103T225738Z/amd64.filter-preflight --inspection-filter-selftest
```

Exit **0**. It ran a byte-identical retained copy of `amd64.payload`, not a glibc/debug substitute. Log: `target/candidates/rebuild-20261103T225738Z/amd64.filter-preflight.log`, SHA256 `8bdaa9c6bccf8462a50ead9f5fae311260c0ef512e2debc4c30d06fbab6e4f89`. Its terminal success line was `inspection exact filter idle/request/idle/request with native deny checks PASS`. Expected negative-test diagnostics remain verbatim in that log. This proves only that local preflight, not VM Bootstrap or any acceptance gate. ARM64 was not executed.

## Failure, verbatim, and stopping boundary

```text
Traceback (most recent call last):
  File "/DATA/AppData/vprouter-rust-v2/tools/build-gateway-context.py", line 99, in <module>
    build(parser.parse_args().architecture)
    ~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/DATA/AppData/vprouter-rust-v2/tools/build-gateway-context.py", line 64, in build
    data = checked(path,entry,True,machine)
  File "/DATA/AppData/vprouter-rust-v2/tools/build-gateway-context.py", line 17, in checked
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
FileNotFoundError: [Errno 2] No such file or directory: '/DATA/AppData/vprouter-rust-v2/target/program-inventory/tailscale-1.102.5-amd64/tailscaled'
Traceback (most recent call last):
  File "/DATA/AppData/vprouter-rust-v2/tools/rust-v2-lab/rebuild-20261103-build.py", line 92, in <module>
    run(['python3', 'tools/build-gateway-context.py', '--architecture', arch])
    ~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/DATA/AppData/vprouter-rust-v2/tools/rust-v2-lab/rebuild-20261103-build.py", line 25, in run
    return subprocess.run(args, env=env, check=True, text=True,
           ~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                          stdout=subprocess.PIPE if capture else None).stdout
                          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.13/subprocess.py", line 577, in run
    raise CalledProcessError(retcode, process.args,
                             output=stdout, stderr=stderr)
subprocess.CalledProcessError: Command '['python3', 'tools/build-gateway-context.py', '--architecture', 'amd64']' returned non-zero exit status 1.
```

The first unavailable input is `target/program-inventory/tailscale-1.102.5-amd64/tailscaled`. Context construction validates public inputs before creating its output directory, so this failure created no context. The untouched helper also needs the pinned CA bundle. Both architectures' cache directories are missing their public bytes. Required context inputs are:

| Architecture | Missing path | Required bytes | Required SHA256 |
| --- | --- | ---: | --- |
| amd64 | `target/program-inventory/tailscale-1.102.5-amd64/tailscaled` | 42902060 | `b2ec98126c6ee19d7b3603b0cfee97c5dd646874065aed7016653d30ff92a9cd` |
| amd64 | `target/program-inventory/tailscale-1.102.5-amd64/ca-certificates.crt` | 181724 | `028fca5150ee1915c4474489985d55c54fceaa680c754cc8d1301734f01b2232` |
| arm64 | `target/program-inventory/tailscale-1.102.5-arm64/tailscaled` | 40133663 | `3cf2640069ded59322dc2113be5fa90540937410be22bb40873a614773ab27cc` |
| arm64 | `target/program-inventory/tailscale-1.102.5-arm64/ca-certificates.crt` | 181724 | `028fca5150ee1915c4474489985d55c54fceaa680c754cc8d1301734f01b2232` |

`tailscale` CLI files are also absent (recorded in `target/candidates/phase1a-evidence-20261103T225704Z/public-cache-status.json`), but the context builder consumes only daemon and CA from that cache. The stock inventory recovery tool needs the pinned OCI index, isolated running guest, dedicated SSH trust/access and guest Docker; it was read, **not executed**. Obtaining those inputs is assessment step 5 and outside Phase 1A. No alternate daemon, host CA bundle, fabricated inventory, omitted context or fake candidate was substituted.

Requested downstream commands are **NOT_RUN** because there is no `candidate.json`, source tar or context to validate:

```sh
python3 target/copy-frozen-contexts.py CANDIDATE
python3 target/verify-continuation-candidate.py CANDIDATE
python3 target/verify-frozen-inspection-preflight.py CANDIDATE
```

The copier and full verifier were reviewed and require both architectures' context bytes and source binding; invoking them on partial metadata would not verify a candidate. The separate frozen inspection/mechanics verifier also requires a completed frozen source binding. Only the driver's exact retained filter preflight has passed. No full frozen mechanics/clock preflight result is claimed.

## Partial candidate location and artifact proof

Incomplete build directory: `target/candidates/rebuild-20261103T225738Z` → `/DATA/vprouter-lab/candidates/rebuild-20261103T225738Z`.
Metadata: `target/candidates/rebuild-20261103T225738Z/partial-build.json`. It records `CONTEXTS_NOT_BUILT`, parent HEAD, driver hash, payload hashes and permanent discontinuity. **No coherent candidate path exists:** `candidate.json`, `source.tar`, both immutable contexts and `root-verification.json` are absent.

All six built Rust programs were copied byte-identically into this durable directory after the driver stopped (mode 0600); both payloads were already retained by the driver. A bounded offline audit verified each manifest size/hash against its exact binary, both payload hashes, and all eight ELF headers: machine 62/183, ELF64 little-endian, PT_LOAD present and no PT_DYNAMIC/PT_INTERP. This is partial artifact proof only. Record: `target/candidates/phase1a-evidence-20261103T225704Z/partial-artifact-check.json`.

| Architecture | Artifact retained in build directory | Bytes | SHA256 |
| --- | --- | ---: | --- |
| amd64 | `amd64.vprouter-worker-observe` | 3299544 | `0ed6eccb1825d30a81048391303326fdc24d187679cac9726a17849fa6489ec7` |
| amd64 | `amd64.vprouter-worker-monitor` | 4814272 | `43ff9662baf0909f88a7c11c379fd6d7860b3125ca987c9e5d729b818e372883` |
| amd64 | `amd64.vprouter-gateway-init` | 584096 | `ad31d4343c4e7b1eab9fb9c1c7b2e1e75d1ab30eda8bf1f6451abca33e52c792` |
| amd64 | `amd64.payload` | 14827240 | `d8ae01f00e540879fe0e3cd68200b2f13677f441e057d2718137ec5d965ba715` |
| arm64 | `arm64.vprouter-worker-observe` | 3482432 | `44f88c23cf7fbe61eef3f6f131517dd8b0732ec04fd378822df9b2b2021cb217` |
| arm64 | `arm64.vprouter-worker-monitor` | 4932848 | `9aa5aee63a6d3d7a15633d9d5d2e1077b3dc613b0a27d2996b624b57eabc2f4c` |
| arm64 | `arm64.vprouter-gateway-init` | 622744 | `68c3166102ba3987157a16b74d125767a6bb4cf692f503a0078b29a88cd835f9` |
| arm64 | `arm64.payload` | 15176584 | `a7f3ba5423e707d4af60488f69130c01c780428c7ef9849e25c028092177e7ec` |

`amd64.filter-preflight` has the same SHA256 and bytes as `amd64.payload`. Each architecture's `gateway_init` was rebuilt and verified stable twice after the manifest update. Its hash already matched the checked-in value, so that role has no textual manifest diff; observer and monitor hashes/sizes changed in both manifests. No Rust source changed.

## Final workspace checks

The initial checks passed while the build was running. Because the ARM manifest was subsequently updated, all three were repeated after the driver stopped; the final results below apply to the final source/manifests. Logs are retained rather than truncated:

| Exact command | Final exit | Log |
| --- | ---: | --- |
| `cargo test --workspace --locked` | 0 | `target/candidates/phase1a-evidence-20261103T225704Z/test-final.log` |
| `cargo fmt --all --check` | 0 | `target/candidates/phase1a-evidence-20261103T225704Z/fmt-final.log` |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | 0 | `target/candidates/phase1a-evidence-20261103T225704Z/clippy-final.log` |

Python syntax parsing and AST assertion comparison passed. The artifact/controller audits passed after the ref-audit correction below. No guest test, Bootstrap, provider/client, preservation continuity, ARM runtime or release acceptance is claimed; `release_ready=false`.

## Git accounting and audit failure

The driver was inspected before execution: `git read-tree`, `git add`, and `git write-tree` use a temporary independent `GIT_INDEX_FILE`; `git commit-tree` would create a local frozen-source object with current HEAD as parent; `git update-ref` would exclusively create `refs/vprouter-test-candidates/<UTC stamp>`. It does not move `rust/v2` or push. **None of these writes was reached**, because both contexts precede them.

- Candidate refs created by this implementation: **none**.
- Git commit/tag objects deliberately created by this implementation: **none**.
- Branch `rust/v2` and HEAD remain unchanged.
- Initial/follow-up snapshots: `target/candidates/phase1a-evidence-20261103T225704Z/refs-before.txt`, `target/candidates/phase1a-evidence-20261103T225704Z/refs-after.txt`; scoped audit: `target/candidates/phase1a-evidence-20261103T225704Z/preservation-audit.json`.

A first audit overreached by asserting equality of **all** repository refs. It failed after writing the successful artifact proof, because a ref appeared in T3's orchestration checkpoint namespace. Exact failure:

```text
Traceback (most recent call last):
  File "<stdin>", line 20, in <module>
AssertionError
```

Observed added ref (reported without attributing it to the build driver):

- `refs/t3/orchestration-v2/checkpoints/ZGJlOTUyZGZhMDliN2UwOWJmN2EzZTQ0MmNiMGZkZmU/ordinal/11` → `fe6ed42603389f298e341f0c9d752fff9ffd1a9e` (previously absent).

The scoped follow-up allowed only that observed T3 checkpoint namespace and checked unchanged branch/HEAD and unchanged candidate refs; it passed. All 293 restored controllers were independently rechecked at this point. No attempt was made to delete or rewrite the checkpoint. The unified-diff command returned 1 because differences exist, as expected; this was not a failed build/check.

## Files prepared for parent review

Exactly these four repository files are the Phase 1A change set (explicitly staged for tracking/review; **not committed**):

- `tools/rust-v2-lab/rebuild-20261103-build.py` — new durable versioned driver.
- `docs/rust-v2/programs-amd64.json` — exact observer/monitor hashes and sizes; all three Rust roles verified.
- `docs/rust-v2/programs-arm64.json` — compile-only companion required by unchanged two-architecture gates.
- `.superpowers/sdd/rust-v2/task-8c-rebuild-phase1a-report.md` — this report.

The archived driver/controllers are unchanged. Evidence, restored controllers and compiled outputs are ignored artifacts. No run numbering or baseline-authoring controller was changed: those are guest/run admission work outside this local build boundary. Continue with reviewed pinned public-cache recovery, then rerun the driver to a **new** exclusive candidate directory; do not relabel this partial directory as a completed candidate. Independent candidate/baseline review remains required before any future guest experiment.

Final explicit staging command:

```sh
git add -- tools/rust-v2-lab/rebuild-20261103-build.py docs/rust-v2/programs-amd64.json docs/rust-v2/programs-arm64.json .superpowers/sdd/rust-v2/task-8c-rebuild-phase1a-report.md
```

It staged the driver/manifests but refused the new report because `.superpowers` is ignored. Verbatim output:

```text
The following paths are ignored by one of your .gitignore files:
.superpowers
hint: Use -f if you really want to add them.
hint: Disable this message with "git config advice.addIgnoredFile false"
```

The explicitly requested report was then added using the exact path only:

```sh
git add -f -- .superpowers/sdd/rust-v2/task-8c-rebuild-phase1a-report.md
git diff --cached --check
```

No ignored evidence, credentials or unrelated files were staged. The final staged whitespace check passed. This staging is outside the driver; its temporary-index preservation behavior is unchanged.

The first staged whitespace check found the single-space blank context lines inside the pasted unified diff. Verbatim output:

```text
.superpowers/sdd/rust-v2/task-8c-rebuild-phase1a-report.md:82: trailing whitespace.
+
.superpowers/sdd/rust-v2/task-8c-rebuild-phase1a-report.md:92: trailing whitespace.
+
.superpowers/sdd/rust-v2/task-8c-rebuild-phase1a-report.md:95: trailing whitespace.
+
.superpowers/sdd/rust-v2/task-8c-rebuild-phase1a-report.md:100: trailing whitespace.
+
.superpowers/sdd/rust-v2/task-8c-rebuild-phase1a-report.md:142: trailing whitespace.
+
```

Blank context lines in the displayed diff were trimmed; the original full diff remains byte-for-byte in `driver.diff`. The check transcript above displays its `+` markers without their trailing spaces. The subsequent final staged whitespace check passed.

## Six-line summary

Restored 293 controllers; every archived and restored size/SHA256 matched.
Added the reviewed Zig-wrapper driver and refreshed both required program manifests.
Built both musl artifact sets; x86 retained filter preflight and init stability checks passed.
Stopped on missing pinned AMD64 tailscaled; no coherent candidate or frozen contexts exist.
Final workspace tests, fmt and strict Clippy passed; no candidate refs or commits were created.
Original guest continuity is permanently broken; guest/runtime/acceptance work remains NOT_RUN.
