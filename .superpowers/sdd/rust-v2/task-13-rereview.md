# Task 13 independent re-review

Verdict: **FAIL — two Minor ELF admission/documentation corrections remain.**

2026-11-06; `/DATA/AppData/vprouter-rust-v2`; branch `rust/v2`;
HEAD `c0c730d2a216d68ac493a785de732a055f660d3e`.
Critical: none reproduced. Important: none reproduced. Minor: two reproduced.
Earlier I1, I2 and M1: **fixed in the reviewed source**.

This verdict is limited to preparation and the claimed ELF shape/class-closure
contract. It does not demand native installation, runtime qualification or a full
ELF instruction/relocation interpreter. The remaining corrections can be small
shape checks or a precise narrowing of the affected advertised guarantees. They
do not establish a runtime exploit, a durability failure or release readiness.

Read the earlier review, implementation report including Review round 1, brief,
binding `docs/rust-v2/IMPLEMENTATION.md`, release tools/tests and accompanying
release/configuration documents. Treated implementer results as unverified.
Started no agents. No sudo, network, VM, service operation, staging, commit, push
or other Git write. The only repository edit is this report. Scratch scripts,
ELF specimens, baseline and diagnostics are under `/tmp/task13-rereview-20261106/`.
All Python invocations used `python3 -B -I`; bytecode was directed only to `/tmp`.

## Earlier findings: exact scenarios and dispositions

| Earlier item | Independent fresh reproduction scenario | Current result |
| --- | --- | --- |
| I1 | Valid candidate-2 → candidate-1 manifests, same state-v1, exact candidate-2 observations; compare rollback and update. Both managers. | FIXED. Rollback explicitly selects and binds a retained compatible stopped-state backup, restores and verifies stopped state after exchange, before controlled restart/workloads; required evidence includes both backup and restoration. All-user stop verification precedes these steps. Current implementation: `release.py:157`, `:188`, `:197`. |
| I2 | Leave complete pending at before_rename; inject EIO only at recovery's final root fsync, or immediately after the real rmdir. Pending is absent afterward. Retry with retained store and with close/reopen; track real directory fsync. | FIXED. All four variants retry successful root fsync before returning None. `release.py:722`. Publication replay likewise repeats root fsync (`:649`). |
| M1 | Mutate e_ehsize at byte52 to0 or PT_LOAD p_memsz at byte104 to0 with p_filesz120; attempt newly anchored packaging, separately for both targets. | FIXED. All four variants refuse at build admission; unchanged-anchor hashing is not the reason. `release.py:258`, `:283`. |

Commands: `python3 -B -I /tmp/task13-rereview-20261106/adversarial.py`
(three regression methods plus ten independent adversarial methods), and
`python3 -B -I /tmp/task13-rereview-20261106/regression-controls.py`.
The latter also deliberately removes each fix in an **in-memory scratch copy**:
I1/I2/M1 controls produce respectively 1/4/2 behavioral failures, no errors;
all three regression methods pass against untouched current source. These are
explicit defect-injection controls, not a claim to possess/rebuild the exact
historical pre-fix source. Current-source tests reproduce the earlier scenarios
and assert the corrected outcomes.

## Minor findings — reproduced

### M2. RELA section header entry-size admission is incomplete

Locations: `tools/release_engineering/release.py:310`, `:320`, `:322`.
Affected claims: `docs/rust-v2/release-review-closure.md:83`,
`docs/rust-v2/release-preparation.md:132`, `:147` and
`docs/rust-v2/release-security-tests.md:16`.

For BOTH machines62/183, use the independently built section-bearing fixture
in scratch `adversarial.py:elf`, with three section headers at file offset192.
Change section2's type at byte324 to4 (SHT_RELA). Keep sh_size16 at byte352;
set sh_entsize at byte376 to0, or1. The section lies within the file and has a
valid name. ELF64 RELA entries have fixed size24; neither header describes a
valid RELA table. The current generic condition accepts zero unconditionally,
or merely tests size modulo an arbitrary nonzero entry size. Type-specific
checks exist for symbol tables and address arrays, but not REL/RELA headers.

`build_bundle` accepts these binaries and `verify_bundle` accepts their freshly
computed anchors as OFFLINE_INTEGRITY_ONLY, release_ready=false.
Independent `readelf --section-headers` reports:

```text
Error: Section 2 has invalid sh_entsize of 0
(Using the expected size of 18 for the rest of this dump)
```

Here readelf prints hexadecimal18 = decimal24. The sh_entsize1 variant produces
the corresponding error. This is a section **header shape**, not an instruction
or relocation-payload semantics claim. Consequently the stated valid section
entry-size/class-closure wording is broader than the reproduced admission.

Correction: check inexpensive fixed entry sizes for admitted REL/RELA section
headers and their size divisibility, with valid controls, or explicitly enumerate
which section types receive entry-size checks and narrow the broad rejection
claim. No execution of the synthetic ELF occurred. Minor because the package
claims only unsigned preparation integrity, never executable qualification.

### M3. Malformed ELF note records are accepted without an explicit scope exclusion

Locations: `tools/release_engineering/release.py:277`, `:279`, `:310`.
Affected wording: `docs/rust-v2/release-preparation.md:135`, `:147` and
`docs/rust-v2/release-review-closure.md:96`.

Reproduced separately on BOTH target machines, through build_bundle and then
verify_bundle with NEW anchors:

1. Add a PT_NOTE program header with file offset200, filesz=memsz=1,
   alignment4, inside a256-byte file. Its single zero byte cannot contain the
   required12-byte note header.
2. Add a16-byte PT_NOTE at offset200 whose note header declares
   namesz=0xffffffff, descsz=0, type1. The declared name does not fit the segment.
3. Change section2 to SHT_NOTE with sh_size1 in the section-bearing fixture.

All six scenarios return OFFLINE_INTEGRITY_ONLY, release_ready=false.
`readelf --notes` independently warns respectively:

```text
Corrupt note: only 1 byte remains, not enough for a full note
note with invalid namesz and/or descsz found at offset 0
```

The outer segment/section ranges are correctly bounded. Inner note records are
not parsed. Current documentation excludes instruction/relocation/symbol payload
semantics, but does not identify note structure as unchecked, while broadly
saying invalid shape refuses. This is a narrow admission/scope gap, not a claim
that the fixture verifier must authenticate build IDs, GNU properties or execute
notes. Correction: explicitly exclude note-record shape from the advertised
profile, or add bounded header/aligned-name/description range checks with valid
notes and malformed-note controls. Minor for the same preparation-only reason.

Reproduction: `python3 -B -I /tmp/task13-rereview-20261106/elf-notes.py`.
The script asserts all eight original scenarios (three note cases plus zero-size
RELA for each target), writes the specimens and retains readelf diagnostics.
The additional sh_entsize1 probe and its diagnostics are also retained in scratch.
Readelf returned exit0 despite its warnings/errors; the finding relies on the
actual diagnostics and admitted header bytes, not its exit status.

## Fresh adversarial coverage and limits

### Durable namespace publication and retry

Fresh repository suite:36 tests pass, including378 enumerated syscall boundaries
and3096 injected fault/replay cases. Inspected the interposer and its dirty-parent
receipts: it wraps real open/create, mkdir, write, fsync, fchmod, utime, rename,
unlink, rmdir, close and flock calls, injects before/after failures, and tracks
later successful directory fsyncs. Coverage is215 publish,67 recovery,52 publish
replay,12 empty recovery and32 existing-bundle recovery boundaries. It includes
both actual file fsyncs around metadata changes, not just offered checkpoints.

Independent trace checks passed for every parent mutated during complete publish
and interrupted-stage cleanup. For each of17 leaves, the observed order is byte
write → file fsync → fchmod0444 → utime0 → file fsync. Staging directory fsync
precedes rename; root fsync completes publication. Unlink cleanup fsyncs the
pending parent before rmdir and root afterward. Successful retry completes the
parent obligation after a failure; these APIs do not promise synchronous fsync
immediately after every individual namespace mutation before any further call.

Added **actual local process SIGKILL** in seven private-fixture scenarios:
after mkdir, after first create, before first file fsync, after final file fsync,
after rename/before root fsync, after the first real recovery unlink, and after
real rmdir/before root fsync. Each child alone opened the store; the kernel closed
its descriptors/released its flock on death. Parent waited for SIGKILL status,
then opened fresh, recovered and published. All seven reached identical complete
bytes with no remaining traced dirty parent. These test process crash/reopen,
whereas implementer reopen cases model descriptor teardown after injected errors.
Neither test measures power-loss writeback, torn sectors or native transactions.

The source AST call inventory confirms there is NO chown, symlink/link creation,
symlink replacement, journal-file writer, marker/lock creator, installer executor
or external command surface. Existing marker/lock/ancestors are operator-supplied
preconditions; module construction reads/pins them and retains flock. The public
.pending directory is its staging journal. Therefore there is no uncovered
module-owned marker/lock publication or chown ordering to simulate. Those future
native concerns remain unimplemented, not silently passed.

Late same-inode content mutation, same-byte inode replacement, symlink and
hardlink substitution of marker, lock and published Cargo.lock all caused read,
publish and recover refusal. External public identity sentinel bytes remained
unchanged. Unknown root markers/journals and foreign pending/bundle members were
retained. Missing/replaced lock, root/ancestor drift and special-file controls
also ran in the repository suite. No claim is made about a malicious same-UID
writer winning between the final check and rename; docs correctly exclude that
race and forbid promoting this fixture store to a privileged installer.

### Lifecycle, interleavings and uninstall custody

All five plan transitions for both managers remain pure DRAFT_BLOCKED data with
native_authority=false and release_ready=false. The binding lifecycle table and
fresh ReviewLifecycle test agree on quarantine/capture, drain, stop, verify all
users stopped, compatible backup, rollback restoration and failure-to-offline
ordering. Planning performs no filesystem/lock operation. No install/update/
rollback/uninstall syscall fault sweep can honestly be run without an executor.

Independent update/rollback probes covered stale current observations, retained
old/new release records and changed desired/current declarations. Incomplete
old observations refuse a reverse transition; with coherent new observations,
rollback retains the newer release. A stale plan can still be computed where
all old and new public records coexist: native generation/CAS authority is an
explicit required blocker, not provided by this public map. No serialization or
native ownership receipt is invented.

For the mutating fixture surface, a second opener refuses while the first holds
flock. After interruption with differentiating pending bytes, or after rename,
publication/recovery against a different bundle refuse without changing evidence;
correct-input recovery/replay succeeds. An empty pending file is intentionally a
prefix of multiple expected bundles. The first scratch harness wrongly expected
a different anchor to distinguish an empty prefix; corrected that expectation
to a completed differentiating Cargo.lock write. This was a harness assumption,
not a hidden implementation failure; initial log is retained.

Independent uninstall plans preserve identity/credential/state/backup sentinels,
including foreign leaves nested inside an owned release directory. Removals are
only exact manifest paths; directories are empty-only, never recursive. Late
observed symlink/type/hash/extra-link-record drift refuses. The public record
format has no native inode observation authority: real uninstall against a
post-manifest hardlink/symlink or a concurrent replacement is NOT_RUN. Fixture
late-link tests do not substitute for that absent native acceptance.

### Service fields, artifacts, determinism and truthfulness

For both managers, tested newline/CR/tab/space, both quotes, percent specifiers,
$HOME/${HOME}, command-substitution spelling, backslash, traversal, Unicode,
NUL and overlength inputs in instance, release and state-format boundaries;
builder injection also refuses. Existing tests cover foreign binary names and
unsafe observed paths. Generated ExecStart is always /usr/bin/false, Description
is constant, and no Environment directive exists. There is no config-derived
argv/executable/environment/arbitrary-path/description parameter: unsupported
kwargs refuse, and changing valid release names does not change script/unit text.
Schema-accepted adapter argv/path strings are not consumed by this generator.
No inference from schema acceptance to unit-file escaping is made.

All six runit run/finish scripts pass separate sh -n checks; run ends in fixed
exec /usr/bin/false, finish exits0 and performs no policy removal. All three
systemd units pass syntax verification. These remain disabled/inert drafts;
Before/Requires/Watchdog/cgroup declarations do not prove actual protection or
runit parity. All corresponding native/platform/boot acceptance remains blocked.

Changed first/middle/last interior byte of every17 bundle members: all refuse.
Missing/extra/traversal/absolute/slash/backslash/space/tab/CR/newline/Unicode/NUL,
option-like and tar/PAX-looking member aliases refuse. There is no archive
extractor and no tar header/path processing API. Altered checksum separators,
CRLF, reversed content and duplicate checksum rows refuse even with a newly
computed checksum-file anchor. Forged metadata plus recalculated checksum list
and anchor still refuses canonical reconstruction.

Independently verified all ten supplied-binary hashes in SBOM and provenance,
all provenance materials against actual files, explicit packaging-only claim,
UNSIGNED status and refusal of require_release=True. Rebuilt twice under changed
cwd/USER/HOME/TZ/SOURCE_DATE_EPOCH and reversed dictionary order: identical bytes.
Generated metadata contains no host path/user/current date; epoch0 stays fixed.
Caller-supplied source/binary bytes remain public unverified inputs, not approved
source or proof of executed compilation. Complete prebuilt Go transitives/licenses
and formal CycloneDX schema certification remain unavailable, correctly stated.

Additional independent ELF probes rejected out-of-file program/section ranges,
invalid names/alignment/entry-size divisibility, reserved flags and EVERY e_flags
bit independently for BOTH architectures, including aarch64. Implementer tests
also freshly cover section flags, overlap, PHDR and TLS. M2/M3 describe the
remaining reproduced gaps; passing generated mutations is not exhaustive ELF
validation.

## Documentation and security-to-test mapping

Docs accurately retain unreleased/preparation-only status, unsupported-host
refusal, runit parity blocker, native/service/state/identity/platform NOT_RUN,
Task8c OPEN, unsigned provenance and absence of release publication authority.
The reported native lifecycle sweep is explicitly NOT_RUN_NO_EXECUTOR. The
syscall sweep concerns only fixture publication/recovery. No runtime/release
claim was promoted. M2/M3 qualify the stronger ELF shape/class-closure wording.

Spot-checked **all12 main mapping rows**, read the named tests and confirmed they
exist by AST; all ran in the fresh full suite. Abbreviated methods resolve within
the preceding class. Locations refer to current test_release.py:

| Map row in release-security-tests.md | Existing tests | Actual scope |
| --- | --- | --- |
| :10 injection/drafts | Services:16; Plans:56 | Fixed false commands; boundary rejection; declarations only. |
| :11 ownership | Plans:44/56; ClassClosure:305; StrictBoundaries:360 | Exact public record/path inventory; native receipts absent. |
| :12 rollback/lifecycle | Plans:74; ReviewLifecycle:611 | Reverse rollback backup/restore order now checked for both managers. |
| :13 host declarations | StrictBoundaries:330 | Unsupported refuses, Void blocker remains; no live host observation. |
| :14 unsigned readiness | Artifacts:110 | Determinism and release promotion refusal. |
| :15 payload/member integrity | Artifacts:126 | Append/missing/extras; independent probes add interior changes. |
| :16 ELF shape | Artifacts:146; ReviewELF:939/1000/1037/1073/1086 | Exact targets and many shape mutations; incomplete for M2/M3. |
| :17 source/inventory | ClassClosure:311/321 | Role/path swaps and undeclared lock metadata refuse. |
| :18 filesystem custody | FixturePublication:174/244 | Metadata/link/root/lock/pending replacement refusal in fixture scope. |
| :19 durability/replay | FixturePublication:211; ReviewDurability:679/724; ReviewSyscallSweep:827 | Real local calls, parent receipts and replay; no hardware/native proof. |
| :20 ancestor/closed-store | StrictBoundaries:374 | Ancestor permission drift refuses; closed stores terminal. |
| :21 build recipe | StrictBoundaries:346 | Offline locked two-target/four-job recipe data; no builds. |

## Verification ledger

| Fresh check | Result |
| --- | --- |
| python3 -B -I tools/release_engineering/test_release.py | PASS, exit0;36 tests,22.455s;378 syscall boundaries,3096 fault/replay cases. |
| python3 -B -I /tmp/task13-rereview-20261106/adversarial.py | PASS, exit0;13 tests,0.226s, with independent subcases and seven actual local SIGKILL recoveries. |
| python3 -B -I /tmp/task13-rereview-20261106/regression-controls.py | PASS, exit0; all three defect-injected scratch controls detected; three current-source regression tests pass. |
| python3 -B -I /tmp/task13-rereview-20261106/elf-notes.py | REPRODUCED M2/M3, exit0;8 newly anchored admitted malformed variants across both targets; readelf diagnostic files retained. Additional RELA ent1 cases also reproduced. |
| python3 -B -I /tmp/task13-independent-review-20261106/adversarial.py | PASS, exit0;7 earlier independent tests,0.199s, including exact recorded fixture anchor/hashes. |
| py_compile.compile(..., cfile=<private /tmp path>, doraise=True) for release.py and test_release.py under python3 -B -I | PASS; no repository bytecode. AST parse also passes. |
| JSON parse of configuration.schema.json and release-preparation-evidence.json | PASS. |
| node /tmp/task13-independent-review-20261106/schema-check.cjs | PASS, installed Ajv8.12.0; Draft2020-12 meta-validation and one/five/mixed examples; no download. Shape-only acceptance is not Rust semantic validation. |
| cargo fmt --all -- --check | PASS, exit0. No Rust build/test/clippy rerun required for this Python/docs review. |
| systemd-analyze verify --man=no <three scratch generated units> | PASS, exit0; unrelated existing CasaOS legacy PIDFile warnings only; static syntax, no service changes. |
| sh -n <each generated run/finish script> | PASS, six separate commands; no script execution. |
| git diff --check; tracked/untracked/cached diff review | PASS; unchanged three tracked docs/example additions, same untracked preparation files, empty index; no changed Rust/Cargo/toolchain/acceptance paths. |
| All86 baseline-bound tool/docs/lock/toolchain files compared after review | PASS, byte-identical; full tracked diff/index/status match scratch baseline. Report is ignored and verified separately. |
| Real release compilation/reproducible binaries; native lifecycle/uninstall-link enforcement; service/watchdog/cgroup/boot/ARM/client tests; power loss; signing/release acceptance | NOT_RUN; outside this preparation review, no executor or authorization. Local fixture SIGKILL is not native recovery evidence. |

Reviewed source SHA256:

```text
db5c876a3f30a734385d357a6beffdea5ac0c38b3ceb54d3a98d6fddea5ad582  tools/release_engineering/release.py
617d8b8a587f0113db0de329530c5328a1b260cfc58de88abb6fb5c20bae12a2  tools/release_engineering/test_release.py
c563cc30dbf4f3c56a0fe2e1857e3c02faa6d05eba30006ed5a4cf25f66645e2  Cargo.lock
0506c53cddc8435a55513d5f662c302ff6eb4035f012d5d5e5a47e96a7f40420  rust-toolchain.toml
3d467451dd03d1663e3c79b24eea6a18aac461f9291f8fdfe1031e1da6e86e97  docs/rust-v2/acceptance.json
```

Acceptance release_ready remains false. The report requires no native acceptance
claim to change, and no production/service/resource/identity mutation was made.
