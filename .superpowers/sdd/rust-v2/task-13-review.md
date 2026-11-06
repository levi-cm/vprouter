# Task 13 independent review

Verdict: **FAIL — preparation-layer corrections required.**

Reviewed 2026-11-06, `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`,
HEAD `c0c730d2a216d68ac493a785de732a055f660d3e`. No subagents started.
The implementation report was treated as unverified. Binding inputs were
`.superpowers/sdd/rust-v2/task-13-brief.md` and `docs/rust-v2/IMPLEMENTATION.md`,
especially work package 10 and Mandatory acceptance / Artifacts.

This verdict concerns the offline preparation APIs. It does not demand native
activation, production installation, signing or real cross builds in this task.
The explicit native/runit/runtime/release blockers are appropriate; they do not
complete the eventual systemd/runit obligations in the binding specification.

Critical: none reproduced. Important: two reproduced. Minor: one reproduced.
No implementation files were edited. This review is the only repository edit.

## Important findings

### I1. Rollback plan omits compatible stopped-state restoration

Location: `tools/release_engineering/release.py:153`, `:164`, `:169`, `:175`.
Related contract: `docs/rust-v2/IMPLEMENTATION.md:49` and
`docs/rust-v2/release-validation-recovery.md:98`.

Reproduced with independently constructed, valid manifests for candidate-2 and
candidate-1, both state-v1, and exact candidate-2 observations. Compare
`plan('rollback', new, old, observed)` with `plan('update', new, old, observed)`.
Only the `operation` field differs. Both plans emit:

```text
independent_quarantine_and_client_guards
capture_ready_this_boot
drain_adapters
stop_all_identity_users
stopped_state_compatible_backup
stage_complete_release
atomic_exchange
verify_same_identity_then_name
verify_guard_and_client_coverage
protected_workloads
commit
```

Neither `steps` nor `required` requires selecting/verifying a retained compatible
stopped-state backup or restoring it with the selected old release. Taking a new
backup and comparing state-format labels do not describe restoration of the
retained state. Thus the machine-readable rollback procedure omits an obligation
that the accompanying recovery guide correctly states. This is a plan defect;
there is no native executor and no observed identity/state modification.

Required correction: make the rollback plan explicitly require a compatible
retained state backup and its restoration and verification while all identity
users remain stopped, before controlled restart/protected workloads. Keep the
plan blocked. Add a test using a genuine reverse release transition that checks
those obligations and their order. The present test at
`tools/release_engineering/test_release.py:74` checks exchange declarations and
capture ordering, not rollback state restoration.

### I2. Recovery retry skips parent fsync after a failed final fsync

Location: `tools/release_engineering/release.py:624` and `:645`.
Related claim: `docs/rust-v2/release-preparation.md:185`.

Reproduced entirely in a private marked TemporaryDirectory:

1. Interrupt publication at `before_rename`, leaving a complete `.pending`.
2. During `recover`, allow the real unlinks, staging-directory fsync and rmdir,
   but inject `OSError(EIO)` only for `os.fsync(store.root)` at line 646.
3. The first call raises; `.pending` is now absent.
4. Retry `recover(files, anchor)` while tracking real fsync calls. It returns
   `None` with **zero fsync calls**, through lines 624–625.

The retry reports ordinary completion without retrying durability of its prior
parent-directory removal. The existing-bundle branch correctly repeats parent
fsync; the absent-pending branch does not. An interruption after rmdir but before
parent fsync has the same control-flow issue. No physical power-loss or lost-data
outcome is claimed; the reproduced issue is the missing required fsync on replay.

Required correction: after validated root/lock custody, fsync the parent before
successful recovery return when neither bundle nor pending exists. Add an
interruption/EIO test specifically across rmdir and the final parent fsync;
the existing 34 recovery checkpoints cover file unlinks only.

## Minor finding

### M1. Static-ELF admission accepts malformed ELF size fields

Location: `tools/release_engineering/release.py:231` and `:237`.

Starting from the provided synthetic x86_64 ELF, independently change either:

- ELF `e_ehsize` at byte 52 from 64 to 0; or
- the PT_LOAD `p_memsz` at byte 104 from 120 to 0 while leaving `p_filesz=120`.

In each case `build_bundle` accepts the bytes and `verify_bundle` returns
`OFFLINE_INTEGRITY_ONLY` for the newly built bundle's anchor. The latter violates
the ELF load-segment requirement `p_filesz <= p_memsz`; the former is an invalid
ELF64 header-size declaration. Admission checks target, program-table bounds,
file segment bounds and absence of dynamic/interpreter segments, but not these
basic size invariants.

This is Minor because the package explicitly disclaims executable functionality,
compiler origin and runtime qualification, and unchanged-anchor mutation still
refuses these bytes. Tighten these inexpensive shape checks, or explicitly narrow
the advertised malformed-shape rejection. No execution of synthetic bytes occurred.

## Service-manager review

`release.py:41–87` generates data, not a native launch path. Both instance and
release pass the bounded ASCII full-match identifier validator. Independent
probes rejected newline, CR, tab, spaces, Unicode, NUL, quotes, percent specifiers,
`$HOME`/`${HOME}`, slash traversal, backslash and overlength input in BOTH fields
and BOTH managers. No config-derived argv, executable, environment or arbitrary
path parameter exists, so there is no config-value expansion/splitting channel
in this API. Paths with spaces/Unicode are rejected rather than quoted.

Systemd syntax verification passed for all three generated units. Quarantine
orders after network-online; capture requires/orders after quarantine; router
requires quarantine and capture and orders after capture; all precede the named
client target. `Before=` alone is not a client readiness guard. The docs explicitly
state this limitation and require independently barred protected workloads. These
disabled units cannot establish a boot protection claim.

Reviewed declared hardening: empty bounding/ambient capability sets,
NoNewPrivileges, strict system protection/home/private tmp, SUID restriction,
locked personality, private umask, control-group kill, CPU/memory/tasks accounting,
30s startup/15s shutdown, restart-on-failure with 5s delay and 3 starts/60s limit.
Quarantine alone declares notify/watchdog90s. Worker freshness45s remains a
separate obligation. No stop cleanup removes policy. Seccomp/LSM, actual child
confinement, watchdog notifications/enforcement and production capability needs
remain unimplemented/unverified, correctly documented for inert `/usr/bin/false`
drafts; these declarations do not satisfy the native hardening contract.

Runit has each role's `down`, an executable-mode run script ending in
`exec /usr/bin/false`, and finish script returning 0 without policy deletion.
All six scripts passed separate `sh -n` invocations. The nested role directories
are disabled draft layout, not a proven enabled runsvdir installation. There is
no implemented equivalent readiness, independent watchdog, restart limiting or
cgroup enforcement. The docs and eligible Void preflight explicitly block on
that absence. This is honest preparation, not completed runit parity.

## Ownership, filesystem and artifact review

Ownership validation reconstructs exact typed canonical records, fixing
boolean/integer/float equality aliases. Fixed generated paths exclude identity,
credentials, profiles, state and backups; shared ancestors are not owned.
Independent uninstall probes for BOTH managers preserved foreign identity,
credential, state and release-directory sentinel records, emitted only manifest
paths, and left input observations unchanged. Identical inputs produce identical
plans; install replay emits no writes. There is no installer executor or native
ownership receipt. Consequently native symlink/TOCTOU safety or actual atomic
release/state rollback is NOT_RUN. Real-directory exchange is a blocked plan
declaration, not an observed renameat2 transaction. Prior immutable release paths
are retained on update/rollback. I1 limits the rollback contract.

For fixture storage, inspected descriptor-relative NOFOLLOW ancestor/leaf access,
owner/mode/link/type/size checks before payload opens, inode/content/chain pins,
retained nonblocking exclusive flock, O_EXCL writes, positive short-write progress,
file/staging/parent fsync, explicit prefix-only recovery and immutable replay.
The 27-test suite exercises symlinks, hardlinks, FIFOs, sparse oversize, metadata
drift, replaced roots/locks/files, unknown pending evidence, contention, 156
publication checkpoints and 34 recovery-unlink checkpoints. Independent injected
write ENOSPC/EIO/EINTR left recoverable pending evidence; subsequent recovery and
repeat publication passed. I2 is an uncovered recovery fsync boundary.

A malicious same-UID/root final-check/rename race is explicitly excluded, as it
must be for this cooperative fixture interface. No privileged installer, archive
extractor or symlink activation exists. No claim is made that simulated errors
qualify power-loss durability or host filesystem behavior.

Artifact membership is a closed 17-file flat set, excluding separators,
whitespace/newline checksum names, traversal, Unicode/NUL and extra archive names.
Independent interior-bit mutations at first/middle/last byte of every member,
missing members and extra/path aliases all refused under the retained anchor.
Reversed dictionary insertion order produced identical bundle bytes. Supplied
binary bytes are separately hashed in the SBOM and provenance; target machines
62/183 and the exact two-target/five-binary set are checked. M1 limits ELF shape
admission. No archive extraction attack surface is introduced.

Provenance binds declared commit, Cargo.lock, both inventories, SBOM, toolchain
and builder and explicitly attests packaging only. The SBOM copies declared
Cargo registry checksums and pinned program/base digests; it does not fabricate
licenses or claim complete prebuilt Go transitives. Supplied binaries remain
separate from pinned-input components. Metadata inserts no host path/user/clock;
epoch is fixed 0. Source comments/input bytes are still caller-supplied public
materials, not an approved source or executed-build attestation. Verification
requires an independently retained checksum-file digest; unsigned self-consistency
cannot authenticate the publisher. `require_release=True` refused, and every
preflight/plan remained release_ready=false.

## Security-to-test map spot-check (all 12 main rows)

Every named test below exists, was read, and ran in the fresh 27-test invocation.
Abbreviated unqualified methods in the document resolve within the named class.
These are fixture/declaration assertions, never native enforcement evidence.

| Map location | Resolved implementation/test | Observed coverage and limit |
| --- | --- | --- |
| release-security-tests.md:10 | Services at test_release.py:15; Plans:56 | Fixed false entrypoints and injection rejection; actual ordering inspected separately. |
| :11 | Plans:44; ClassClosure:305; StrictBoundaries:360 | Exact removal, real release inventory and complete binary-name map; no authenticated native receipts. |
| :12 | Plans:74 | Exchange/capture declarations present; does not cover state restoration, see I1. Retention itself has a separate test at :396. |
| :13 | StrictBoundaries:330 | Unsupported fields refuse; Void runit blocker present; all eligible installations remain blocked. |
| :14 | Artifacts:110 | Determinism, subjects, unsigned status and release promotion refusal. |
| :15 | Artifacts:126 | Appending/missing every member and unsafe extras refuse; independent probes also changed interior bits. |
| :16 | Artifacts:146 | Wrong machine/interpreter/program-header size/missing binary refuse; malformed size gaps in M1. |
| :17 | ClassClosure:311 and :321 | Role/path swap and undeclared Cargo.lock metadata refuse; not full source/build authentication. |
| :18 | FixturePublication:174 and :244 | Type/link/mode/time/membership/root/lock/replacement refusal within fixture boundary. |
| :19 | FixturePublication:211 | Every offered publish checkpoint recovers; does not cover failed final recovery parent fsync, see I2. |
| :20 | StrictBoundaries:374 | Ancestor mode drift refuses; closed stores reject operations. |
| :21 | StrictBoundaries:346 | Offline locked two-target/four-job recipe data; no builds executed. |

Also inspected RecoveryAndCustody:460/496/512, BundleScope:548/557 and
ExactTypes:585/599 for unlink interruption, lock/type admission, member-set/SBOM
scope and scalar aliases. All passed as part of the suite.

## Verification ledger

| Check | Fresh result |
| --- | --- |
| `python3 -B -I tools/release_engineering/test_release.py` | PASS, exit 0; 27 tests, 7.197s. |
| `python3 -B -I /tmp/task13-independent-review-20261106/adversarial.py` | PASS, exit 0; 7 independent tests, 0.293s, with the injection/mutation/platform/write-fault subcases above. |
| `python3 -B -I /tmp/task13-independent-review-20261106/probes.py` | REPRODUCED I1, I2 and both M1 variants; exit 0; the probe records the defect outcomes and asserts the missing-fsync replay. |
| Python `py_compile.compile(..., cfile=<private /tmp path>, doraise=True)` for both new Python files under `python3 -B -I` | PASS; bytecode written only under TemporaryDirectory, removed afterward. |
| JSON parsing of both new JSON files | PASS: configuration.schema.json and release-preparation-evidence.json. |
| `node /tmp/task13-independent-review-20261106/schema-check.cjs` | PASS using installed Ajv 8.12.0, JSON Schema 2020-12 meta-validation and all one/five/mixed examples. No download/network. Python jsonschema remains absent, but an external validator was locally available. |
| `cargo fmt --all -- --check` | PASS, exit 0. No cargo build/test/clippy run by this reviewer. |
| `systemd-analyze verify --man=no <three /tmp generated units>` | PASS, exit 0. Only unrelated existing CasaOS legacy PIDFile warnings; static parsing, no service start. |
| Separate `sh -n` for each runit run/finish script | PASS, six scripts, exit 0. No script execution. |
| `git diff --check`; tracked diff, full untracked status, empty cached diff | PASS. Only the supplied docs/examples plus new release tools/docs; no Rust/Cargo/toolchain edits. |
| Evidence fixture anchor and every artifact size/hash against independently rebuilt fixture | PASS. Anchor `7ed7acfb5fee20def96d4c88a3c0762171577daca3042e4fc9d0c326c1fb4962`. |
| Cargo.lock and acceptance ledger | Unchanged from HEAD; release_ready=false. SHA256 respectively `c563cc30dbf4f3c56a0fe2e1857e3c02faa6d05eba30006ed5a4cf25f66645e2` and `3d467451dd03d1663e3c79b24eea6a18aac461f9291f8fdfe1031e1da6e86e97`. |
| Real musl cross builds/reproducible compilation; formal CycloneDX schema validation; native service/install/update/reboot/rollback/uninstall; hardware durability; ARM/runtime/client/traffic/identity/platform/security/performance/canary/soak/release acceptance | NOT_RUN, deliberately outside this review. |

Earlier-task class sweep: no host-clock/deadline/age input or queue introduced;
metadata time is fixed, observed mtime/ctime are drift checks rather than wall-clock
expiry. Close is terminal and double close harmless in independent probes. Names,
JSON/files/bundles/directories/inventories have explicit bounds. Partial writes
advance only on positive progress; zero writes and write errors retain evidence.
Recovery's final durability replay remains deficient as I2 documents.

Reviewed source hashes matched the report's frozen source:

```text
fbe52b26aa4397db347191b4e84411f8e1b9e9fcae68ad3ad6fa8f6110439129  tools/release_engineering/release.py
81125c95dc79c50d3a4e3c6e087ba16d1b0de7b2a36ce2081ca38a81d882acba  tools/release_engineering/test_release.py
```

Scratch reproducers and generated service data remain under
`/tmp/task13-independent-review-20261106/`. No sudo, external network, VM,
service mutation, Git staging/commit/push, repository implementation edits,
signing or publishing was performed. Native and release readiness remain false.
