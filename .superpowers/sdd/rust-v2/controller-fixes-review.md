# Controller fixes: independent correctness/regression review

**Verdict: FAIL — two reproduced Minor ELF header-admission gaps remain.**

Critical: **0**. Important: **0**. Minor findings: **2**. No unreproduced concern is promoted to a finding. The exact four submitted changes work in the exercised cases; the remaining gaps are within the explicitly requested REL/RELA header review. Tasks 9 M1, 10 M1 and 12 R4 pass this focused review. Task 13's fixed entry-size checks and note-record documentation pass, but its relocation-header validation remains incomplete.

Reviewed 2026-11-06, `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`, HEAD `2e6fb604ce5ec7e49d33b3fdd2b408af4fd6af6b`. The initial worktree was clean. No agents were started. No sudo, network, VM, service operation, process killing or Git write was performed. This report is the only repository edit. Source and tests were not changed.

## Minor findings — reproduced

### M1. Nonzero relocation `sh_link` may identify a string table or the relocation section itself

Locations: `tools/release_engineering/release.py:320`, `:326`; documentation `docs/rust-v2/release-preparation.md:132`; regression-control fixture `tools/release_engineering/test_release.py:940`.

The generic check requires only `link < shcount`. The new SHT_RELA/SHT_REL branch checks entry size and divisibility, without validating the kind of section selected by a **nonzero** `sh_link`. Both machines 62/183 accept a relocation header with `sh_link=1` pointing to SHT_STRTAB, or `sh_link=2` pointing to itself. Both RELA (24-byte entries) and REL (16-byte entries) reproduce this. `build_bundle` and `verify_bundle` with newly calculated anchors also accept all six malformed combinations, returning `OFFLINE_INTEGRITY_ONLY`, `release_ready=false`.

Independent `readelf -SW` confirms:

```text
Warning: [ 2]: Link field (1) should index a symtab section.
```

This is a section-header link/type problem, separate from the explicitly unchecked relocation payload. The documentation's claim that section links are checked is broader than the implemented check. This is Minor because the artifact profile remains unsigned, offline preparation; no runtime exploit or release qualification is asserted.

Suggested correction: validate nonzero relocation links against the supported symbol-table kinds, retaining valid zero-link executable relocation cases, or explicitly narrow the documented header-link guarantee. Add link-kind negative controls.

**Compatibility constraint, reproduced:** a real GNU-linked x86_64 static executable built with `cc -static -no-pie -Wl,--emit-relocs` is accepted. Its `.rela.plt` legitimately has `sh_link=0` (symbol-free static relocations). Requiring every relocation section to have a nonzero symbol-table link would reject this valid control. Mutating the real executable's `.rela.init` link to `.shstrtab` is also accepted by the current checker.

### M2. Clearing `SHF_INFO_LINK` bypasses relocation target-index bounds

Locations: `tools/release_engineering/release.py:320`, `:326`; documentation `docs/rust-v2/release-preparation.md:132`.

For SHT_REL/SHT_RELA, `sh_info` denotes the section to which relocation applies (zero can be valid for executables). The implementation enforces `info < shcount` only when `sflags & 0x40` (`SHF_INFO_LINK`) is set. A relocation header with `shcount=3`, `sh_info=0xffffffff`, correct fixed `sh_entsize`/`sh_size`, and flags zero passes. Setting the flag on the same specimen makes it refuse. Both machines and both relocation kinds reproduce this; fresh bundle construction and verification accept the flag-clear cases.

Independent `readelf -SW` confirms:

```text
Warning: [ 2]: Info field (4294967295) should index a relocatable section.
```

The target index is header metadata, so the relocation-payload exclusion does not explain this acceptance. Suggested correction: bound relocation `sh_info` independently of `SHF_INFO_LINK`, preserving the valid zero value, or explicitly exclude this header relationship from the documented guarantee. Add a flag-clear negative control. Severity is Minor for the same offline-only reason as M1.

### Exact small ELF reproduction

The committed fixture builds three section headers at offset 192; section 2 starts at 320. No specimen is executed. Run from the repository:

```python
# python3 -B -I (execute as a script or stdin)
import importlib.util
import struct
s = importlib.util.spec_from_file_location(
    "review_tests", "tools/release_engineering/test_release.py")
t = importlib.util.module_from_spec(s)
s.loader.exec_module(t)
for machine in (62, 183):
    for kind, entry_size in ((4, 24), (9, 16)):
        for label, link, info, flags in (
            ("M1 string table", 1, 0, 0),
            ("M1 self link", 2, 0, 0),
            ("M2 out of range", 0, 0xffffffff, 0),
            ("M2 checked control", 0, 0xffffffff, 0x40),
        ):
            data = bytearray(t.ReviewELF.three_sections(
                machine, kind, entry_size, entry_size))
            struct.pack_into("<Q", data, 328, flags)
            struct.pack_into("<II", data, 360, link, info)
            try:
                t.r.static_elf(bytes(data), machine)
                result = "ACCEPTED"
            except ValueError:
                result = "REFUSED"
            print(machine, kind, label, result)
```

Observed: each M1/M2 specimen ACCEPTED; each flag-set control REFUSED. End-to-end bundle reproduction and the real static control are in the scratch `elf-probe.py` and `elf-probe.log` identified below.

## Disposition of the four changes

### Task 9 M1 — PASS

`crates/vprouter-core/src/fleet.rs:408`: the stopped guard precedes token selection and all mutation. A container-wide emergency sets `stopped=true`, so late cancel returns `InvalidTransition`, retains FAILED/StructuralFailure and cannot replace or re-arm emergency actions, including after they are drained. `selected` still checks policy-instance identity and exact epoch before returning mutable state.

For a scoped FAILED exit, cancel revokes the session, clears in-flight work and requests `QuarantineAndStop`, retaining the state and reason. Independently exercised both cleanup failure (`AllocationConflict`) and a received FAILED snapshot (`PolicyUnapproved`) after READY. Status retains only the authored reason enum; server/node/egress/verification evidence remains cleared and exposure unverified. Repeated cancel does not restore observations or sample completion. Peers remain READY. Starting, READY, BLOCKED and already STOPPING cases still become/remain STOPPING with reason Stopping. Foreign-policy and old-epoch tokens refuse without changing the selected exit. The submitted regression and independent probes pass.

### Task 10 M1 — PASS

`crates/vprouter-core/src/fleet.rs:311`: status uses the same `time_valid` predicate and strict regression comparison as `accept_host_time`, including the existing 1e12 ceiling. It returns `StaleEvidence` for NaN, both infinities, negative, regressing and over-ceiling clocks. It takes `&self`; neither a refused query nor a future query advances the high-water mark, changes pending work/state, or renews the watchdog. Equal time is accepted. A subsequent operational callback at the existing high-water mark remains valid.

Status remains reportable at a valid time after scoped FAILED, cancel/STOPPING and container failure, before and after emergency actions are drained. It intentionally does not apply the operational `stopped` rejection. READY evidence freshness checks are retained. Repository call-site inspection found no production caller depending on the old weaker clock check; direct-fleet tests exercise the relevant existing mixed/direct semantics and all pass.

`docs/rust-v2/multi-exit-preparation.md:92` explicitly enumerates the six operational callbacks, separately describing observational queries at line 98. `docs/rust-v2/direct-exit-preparation.md:77` likewise limits emergency behavior to six operational entry points. The new read-only refusal is consistent with both; it does not turn a status query into an emergency-triggering callback.

### Task 12 R4 — PASS

`crates/vprouter-core/src/migration/mod.rs:217`, `:266`, `:280`; `storage.rs:121`, `:144`.

128 is the tight per-object custody-map bound of the shared strict decoder. The count includes `/` (the opaque container), `profile.wg`, `state`, every nested directory and every leaf. Object wrappers and the eight fields inside each Pin do not add keys to the custody object. Physical path depth is flattened into custody-map keys; a depth-16 filesystem path is not depth-16 JSON nesting.

| Constructed custody shape | 127 total pins | 128 total pins | 129 total pins |
| --- | --- | --- | --- |
| Four child directories, one filled to 32 leaves | Full cycle PASS | Full cycle PASS | Refused by `FixtureTree::open` |
| Deep branch with leaves at depth 16, one directory filled to 32 leaves | Full cycle PASS | Full cycle PASS | Refused by `FixtureTree::open` |

Here full cycle means actual `Plan::parse(p.encode())`, all three plan-bearing command decoders, apply, persisted-journal resume, and rollback, with original synthetic identity bytes preserved. Separate depth-17 and directory-33 shapes refuse at admission.

Other collection checks: Inventory dependencies/IPs/routes are bounded 16/16/2; migration configuration has one exit, at most 16 adapters and 128 client policies; unique valid client adapter references cannot exceed those 16 adapters; each argv is at most 64. Bundle files are independently capped at 32 and the closed valid new-bundle set reaches 28 files at 16 dependencies. No map or array exceeding the strict 128-element bound was admitted in the probes.

Fresh independent runs accepted 127/128 clients with 16 dependencies and all 16 references per client, and refused 129 clients. A separate accepted case exercised all five adapter actions with 64 arguments of 256 bytes each. A combined case exercised custody128/depth16/directory32/dependencies16/clients128/references16 and argv64 on all 16 adapters simultaneously: plan, command decoding, persisted journal recovery and rollback all passed. Its plan was 182935 bytes; the recursively measured largest object and array were both exactly 128.

Custody also appears in typed `Observation::Retained` receipts. There is no public strict JSON receipt-reader entry point: the fixture driver supplies a typed Receipt and `Plan::accepts` compares its map to the admitted inspection map. The combined probe exercised this receipt and ordinary typed Serde round-trip; its largest object was exactly 128. Receipts are not persisted in a growing journal array. Nested inspection/inventory/journal wrappers do not enlarge the flat custody object. The JSON/envelope byte bounds remain separate admission checks.

`docs/rust-v2/migration-preparation.md:220` accurately states 128 entries including container/roots, directory32 and depth16. No admitted-but-undecodable case was reproduced at the requested boundaries or combined maxima.

### Task 13 M2/M3 — fixed cases PASS; remaining header findings above

`tools/release_engineering/release.py:326`: fixed ELF64 RELA/REL entry sizes 24/16 and size divisibility are correct. The committed negative controls pass. Independent zero/one/two-entry shape controls pass for both architectures, and the real GNU-linked static x86_64 executable with emitted relocations passes. No valid static ELF rejection attributable to this change was reproduced; ARM validity controls were synthetic, not a real ARM toolchain/runtime qualification.

`docs/rust-v2/release-preparation.md:135` accurately describes entry-size validation. Lines 137–139 now explicitly exclude inner PT_NOTE/SHT_NOTE records, build IDs and GNU properties. The source bounds their outer ranges and does not parse those inner records, so the note-record documentation correction is accurate. M1/M2 above concern other header relationships still covered by the broader section-links wording.

## Verification ledger

All Cargo invocations were sequential and used `--offline --locked -j 4`. Successful runs also set `CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0`, and `CARGO_TARGET_DIR=/tmp/vprouter-controller-review-ISzkkq/target`. The shared `/tmp` tmpfs filled during the first two fleet compilation attempts. Only this review's target directory was moved to disk-backed scratch and a symlink retained the required target pathname; no other user's files/processes were touched.

Scratch target backing, sources, executable probes and detailed logs: `/var/tmp/vprouter-controller-review-akgxf86z/`. Command logs and target symlink: `/tmp/vprouter-controller-review-ISzkkq/`. Scratch evidence is ephemeral.

| Check | Fresh result | Evidence |
| --- | --- | --- |
| Initial default-debug fleet build; reduced-debug retry on tmpfs | BLOCKED_BY_HOST: ENOSPC during compilation, exit 101; subsequently resolved for this review with disk-backed scratch | `fleet.log`, `fleet-nodebug.log` under `/tmp/...ISzkkq/` |
| `cargo test --offline --locked -j 4 -p vprouter-core --test fleet` | PASS, 21 tests, exit 0 | `fleet-final.log` under `/tmp/...ISzkkq/` |
| `cargo test --offline --locked -j 4 -p vprouter-core --test migration custody_map` | PASS, 1 test; 55 filtered, exit 0 | `migration.log` under `/tmp/...ISzkkq/` |
| `cargo test --offline --locked -j 4 -p vprouter-core --test direct_fleet` | PASS, 12 tests, exit 0 | `direct-fleet.log` under `/tmp/...ISzkkq/` |
| `python3 -B -I tools/release_engineering/test_release.py` | PASS, 37 tests, exit 0; 3096 durability fault/replay cases | `release.log` under `/tmp/...ISzkkq/` |
| `fleet-probe independent_ --nocapture --test-threads=1` | PASS, 3 independent tests, exit 0 | `fleet-probe.rs`, `fleet-probe.log` under disk-backed scratch |
| `migration-probe independent_ --nocapture --test-threads=1` (before combined probe was added) | PASS, 3 independent tests, exit 0; boundary/depth/directory/other-collection cases above | `migration-probe.rs`, `migration-probe.log` under disk-backed scratch |
| `migration-probe independent_combined --nocapture --test-threads=1` | PASS, 1 additional independent test, exit 0 | `migration-combined.log` under disk-backed scratch |
| `python3 -B -I /var/tmp/vprouter-controller-review-akgxf86z/elf-probe.py` | REPRODUCED M1/M2 for both architectures and relocation kinds; flag-set refusal controls and real static control behave as described, exit 0 | `elf-probe.py`, `elf-probe.log`, ELF specimens under disk-backed scratch |
| `readelf -SW` on malformed RELA specimens | Confirms wrong link kind and out-of-range relocation target independently | `readelf-bad.log`, `readelf-info.log` under disk-backed scratch |
| Native installation, VMs, services, real ARM binaries/runtime, production migration/release acceptance | NOT_RUN; outside this focused offline review | No such acceptance claimed |

Independent Rust probes include the unchanged repository fixture helpers, and were compiled with `rustc --test --edition=2024 -C debuginfo=0`, linking the exact `vprouter_core`, `sha2`, `serde_json` and `rustix` rlibs freshly produced by the successful Cargo runs. No copied or modified implementation was linked. The probe sources remain outside the repository.
