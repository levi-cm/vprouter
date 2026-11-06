# Unreleased service and artifact preparation

DRAFT / OFFLINE_PREPARATION_ONLY. Task8c runtime, ARM execution and client gates
remain OPEN. No supported release, migration, installer, activation flag or native
service driver is supplied. `acceptance.json` remains unchanged and
`release_ready=false`. This document must not be published as a supported guide
until mandatory traffic, performance, independent review and canary gates pass.

The standard-library Python module `tools/release_engineering/release.py` follows
existing offline Python context/inventory tools. It adds no persistent Python
runtime, package dependency, network client, subprocess or privileged operation.
Rust runtime, CLI, lockfile, toolchain and existing private state are unchanged.
There is no install/update/rollback/uninstall/reboot-recovery executor. Planning returns
public expected plans; they cannot authenticate native ownership or protection.

## Offline API and exact local validation

From the repository root, run only the offline tests:

```console
python3 -B -I tools/release_engineering/test_release.py
CARGO_BUILD_JOBS=4 cargo fmt --all -- --check
CARGO_BUILD_JOBS=4 cargo clippy --locked --offline -j 4 --workspace --all-targets -- -D warnings
CARGO_BUILD_JOBS=4 cargo test --locked --offline -j 4 --workspace --all-targets
```

Cargo invocations must be sequential, including architecture builds. Never kill
another project's jobs. The module has no CLI. Import its pure API without
creating bytecode or reading host state:

```python
import runpy
r = runpy.run_path("tools/release_engineering/release.py")
files = r["services"]("systemd", "max-vprouter", "candidate-1")
runit_files = r["services"]("runit", "max-vprouter", "candidate-1")
manifest = r["ownership_manifest"]("systemd", "max-vprouter", "candidate-1", "state-v1")
# These are Python values; no file was installed or written.
```

`services(manager, instance, release)` returns sorted path/content/mode/type/UID/
GID/owner/SHA256 records. Inputs use a bounded lowercase ASCII identifier grammar;
newline, quotes, `%`, environment expansion, slash/dot aliases, Unicode and NUL
refuse. Commands, environment, unit suffixes and paths cannot be interpolated.
Systemd uses the original instance name, plus `-quarantine` and `-capture` units;
runit uses `/etc/sv/<instance>/{quarantine,capture,router}`. Shared `/etc/systemd/
system`, `/etc/sv`, `/opt/vprouter/releases` ancestors must already be trusted;
they are preconditions, never owned or removed by this manifest.

`ownership_manifest(..., artifact_hashes)` optionally takes the COMPLETE five-bin
name-to-SHA256 map for ONE chosen architecture. It adds a root-owned0700 immutable
release directory, root-owned0444 release descriptor and root-owned0555 binaries.
Omitting hashes yields a service/descriptor draft with no binary installation
claim. Full verified binary hashes remain a mandatory planning prerequisite.
Identity, credentials, profile, state, client policies and backups are never
manifest-owned paths. Artifact copies must come from the verified target-specific
bundle; a public hash map alone supplies no admission authority.

`plan(operation, current, desired, observed)` accepts install/update/rollback/
uninstall/reboot-recovery. All current paths must match exact owner/type/mode/content/hash
records. Foreign or missing current paths, conflicting destination ownership,
incompatible state formats, modified manifests and service-name changes refuse.
Unknown canonical observed paths are retained. `install` replay yields no writes
when all desired records already match. Uninstall lists exact owned leaves and
empty directories, deepest first; it never recursively deletes, follows aliases,
deletes state/backups or removes client policy/quarantine. Plans remain
`DRAFT_BLOCKED` and `native_authority:false`, including terminal offline intent.
No callback can revive them or turn a supplied boolean into native authority.

All plans declare quarantine-first failure handling: restore BOTH a compatible
release and stopped state, or remain offline. Rollback explicitly selects a
retained compatible stopped-state backup, verifies its release/state/identity
binding, exchanges the release, restores and verifies stopped state, then verifies
identity before controlled restart. Backup selection/restoration precede restart
while all identity users remain stopped. Missing native backup evidence keeps
the plan blocked. `reboot-recovery` requires identical current/desired manifests,
reconciles ownership for this boot and verifies the current release/state pair;
it performs no exchange or writes and cannot reuse stale boot readiness.
The full transition and durability matrices are in
[review class closure](release-review-closure.md).

## Systemd and runit drafts and reboot contract

Systemd drafts have an empty CapabilityBoundingSet/AmbientCapabilities,
NoNewPrivileges, ProtectSystem=strict, ProtectHome, PrivateTmp, restricted SUID,
UMask0077, RestartSec5, StartLimit3/60s, startup30s/shutdown15s, control-group kill
and CPU/memory/tasks accounting. They contain only `/usr/bin/false` entrypoints,
no Install section and no cleanup ExecStop. They are deliberately unusable.
The independent quarantine draft has Type=notify/WatchdogSec90; the other drafts
require it and order quarantine -> capture -> router -> client target after
network-online. A notify setting cannot make an absent enforcer functional.
The existing worker heartbeat limit45s is a separate guard obligation.

Runit directories contain `down`, inert `run`, and a policy-retaining `finish`.
No `/var/service` symlink is generated. Runit does not implement systemd hardening,
readiness, cgroup killing/accounting, restart throttling, or an independent90s
watchdog by copying these files. Those controls require an admitted native
supervisor, exact cgroup membership/kill verification and actual failure tests;
this package implements none and preflight names that blocker. Do not enable
these directories or claim supervision equivalence. No sleep/shell command is
executed by the generator; generated scripts are disabled draft data only.

Future systemd native integration must put independently authenticated persistent
quarantine/client guards before protected workload launch, not rely on After=
alone. Current network-online ordering assumes protected workloads are separately
barred; it does not protect traffic started by arbitrary network services. Future
runit integration must establish independent quarantine and capture in boot
stage1 before stage2 network/protected services; receipt gates must keep all
usable paths offline until verified. Both must retain quarantine on ordinary
stop/crash/finish and reconcile exact allocation/namespace ownership after reboot.
Ambiguous foreign resources stay quarantined. No foreign nft flush is allowed.
Capture must be operational on an actual observation interface BEFORE protected
traffic for any boot claim. A target/unit name or service enablement is no proof.

`preflight(host)` checks an exact public declaration: Linux6.1+, x86_64/aarch64,
glibc, Debian13/Arch/CachyOS+systemd or Void+runit, cgroupv2, nft, kernelWG, TUN.
Unsupported declarations refuse before planning side effects (there are none).
Eligible declarations still return UNVERIFIED_NATIVE_GATES/install_allowed=false;
no caller can assert that live checks or acceptance passed. Existing native
observational preflight remains the authority for its narrow observations and
currently cannot establish active kernel/host-libc/runtime readiness either.

## Immutable artifact contract

`build_bundle(binaries, lock, inventories, commit, toolchain, builder)` is a pure
bytes-to-bytes mapping. Supply exactly both targets:
`x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`, each containing
`vprouter`, `vprouter-launch-admit`, `vprouter-gateway-init`,
`vprouter-worker-observe`, `vprouter-worker-monitor` under flat
`<target>--<binary>` names. ELF64 EXEC ident/ABI/header sizes, architecture,
program/section table bounds, segment flags/ranges/alignment, address overflow,
LOAD/TLS filesz<=memsz, PHDR binding, executable entry, disjoint LOAD mappings,
section names/links/size shapes and absence of PT_INTERP/PT_DYNAMIC are checked;
bytes are never executed. The deliberately bounded profile rejects extended
section numbering, unsupported flags/types and overlapping LOAD mappings.
SHT_REL/SHT_RELA section headers must carry the fixed ELF64 entry size (16/24), a
size that is a multiple of it, `sh_link` 0 or a symbol table, and `sh_info` indexing
an existing section (0 is valid) regardless of `SHF_INFO_LINK`. It does not validate every instruction, relocation
or symbol payload, and it does not parse inner note records (PT_NOTE/SHT_NOTE
contents; only their outer segment/section ranges are bounded), build IDs or GNU
properties. ELF
shape is not proof of compiler origin, functionality or architecture runtime.
No tar/zip archive or extraction path exists.

The deterministic bundle contains those ten binaries, Cargo.lock, both exact
program inventories, sbom.cdx.json, provenance.json, manifest.json and SHA256SUMS.
Manifest binds each payload/provenance byte, size and mode. Provenance binds
source commit, lock/inventory/SBOM hashes, toolchain1.97.0, builder identifier and
binary subjects. It is an unsigned in-toto-style statement with a private
predicate and explicitly claims packaging inputs only, not observed compilation.
SHA256SUMS covers every other file. Retain `SHA256(SHA256SUMS)` independently;
`verify_bundle(files, expected_digest)` reconstructs the entire bundle and rejects
any mutation, extra/missing member, invalid path/type/encoding/shape or
noncanonical metadata. Checksums alone cannot authenticate a publisher; replacing
the bundle AND untrusted anchor can produce another internally consistent draft.
`require_release=True` ALWAYS refuses UNSIGNED input; there is no sign/publish
API or readiness override.

CycloneDX1.5 JSON derives OFFLINE from Cargo.lock package versions/checksums and
both pinned program inventories, including Tailscale1.102.5 and OCI index/platform
digests. Pinned program components are labelled as input inventory, separately
from newly supplied binaries; older inventory hashes are not claimed to match
new binaries. Cargo.lock has no licenses, and prebuilt Tailscale's embedded Go
transitives/licenses are unavailable here; these remain unverified SBOM scope,
never fabricated. No dependency resolver, license lookup or network is used.

Canonical JSON is ASCII/sorted with a final newline; no host username/path,
wall clock, random IDs or current timestamps are inserted. Metadata epoch is
fixed0 (SOURCE_DATE_EPOCH-style). Public input binaries/lockfiles remain untrusted
public inputs and must themselves be approved secret-free build inputs.
Non-reproducible source inputs cannot be certified by canonical packaging.
Metadata limit4MiB, per-file64MiB, bundle512MiB, directories64 members, lock
packages1024, paths128-byte flat member names bound storage/decoding capacity.

`build_recipe()` returns two inert, sequential --locked --offline -j4 --release
Cargo recipes with CARGO_BUILD_JOBS4, SOURCE_DATE_EPOCH0, Rust1.97.0, rust-lld,
static relocation and existing cached Zig CC wrapper paths. It executes nothing.
Clean source/toolchain/CC-wrapper hashes, stable/remapped source/cache paths,
memory admission and repeated binary comparison are still required before
claiming reproducible compilation. This task's real release builds are NOT_RUN:
retained cross-C wrappers/Zig/musl-gcc absent, nested host memory shared and no
network permitted. Tests package minimal synthetic ELF fixtures; those are not
release binaries, approved programs or ARM execution evidence.

## Fixture publication and explicit recovery

`FixtureStore(root)` accepts only an existing canonical private0700 current-UID/
GID directory, fixed0600 marker `offline-release.fixture` with bytes
`offline-release-fixture-v1\n`, and preexisting0600 single-link `.release.lock`
with bytes `offline-release-lock-v1\n`. Never place a marker in a real release,
identity tree, `/etc`, `/usr` or production path. Tests create markers only in
TemporaryDirectory; this module cannot initialize a store or create ancestors.
It opens every ancestor descriptor-relatively, NOFOLLOW, checks ownership/mode
(including the fixed sticky `/tmp` exception), pins the whole chain and checks
existing flock identity. Missing/replaced locks are never recreated or removed.

`publish(files, anchor)` writes only fixed `.pending` then `bundle` below that
root. Every input file is admitted before a data FD; symlink, hardlink, special,
foreign, mode, size, device and inode drift refuse. O_EXCL0600 creation, bounded
partial-write loops, file fsync,0444/mtime0 normalization, staging fsync,
lock/inode/content rechecks, directory rename and parent fsync publish all-or-none.
Directory mtime is fixed0. Access time is observation-dependent; ctime cannot be
assigned; neither appears in reproducible outputs. Concurrent-read ctime changes
still invalidate pins. Existing identical complete bundles replay without payload
writes and repeat parent fsync, since an earlier post-rename fsync may have failed;
a different bundle refuses. An error after rename may mean publication succeeded
but durability is uncertain: reopen/read, never assume failure means absent.

`.pending` refuses ordinary publish. `recover(files, anchor)` first validates the
ENTIRE pending member set and raw byte-prefix ownership, including truncated
metadata, then removes only those matching public files and the now-empty dir.
Unknown/malformed/symlink/hardlink/replaced evidence remains untouched. Recovery
can repeat after interruption; if bundle already exists, it must exactly match,
with no ambiguous extra staging, before parent fsync repeats. If neither bundle
nor pending remains, recovery still fsyncs root: an earlier rmdir may have
succeeded before a final fsync failure/interruption. Successful recovery never
infers durability from name absence. Closed stores are
terminal. No timestamp, age-based stale-lock break or automatic cleanup exists.

The private directory plus cooperative flock is the concurrency boundary.
Descriptor rechecks detect the tested rename/permission/link replacements, but
Python's directory rename is not atomic NOREPLACE/CAS against a malicious root/
same-UID writer between final check and rename. This fixture publisher must not
be promoted into a privileged installer. Actual power-loss/torn-sector/ENOSPC/EIO
hardware, SIGKILL and hostile mounted-filesystem tests remain NOT_RUN. Test-only
error/short-write injection demonstrates local fixture recovery only.

See [validation/recovery/rollback](release-validation-recovery.md),
[compatibility matrix](release-compatibility.md),
[security-to-test map](release-security-tests.md), and
[redacted evidence](release-preparation-evidence.json).
