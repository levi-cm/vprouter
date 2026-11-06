# ELF relocation header fix: independent review

**Verdict: PASS. Critical: 0. Important: 0. Minor findings: 0.**

Reviewed only the ELF change in commit `4ae2df3ff9d1716732f3df04888dd51ddd719868`, branch `rust/v2`, on 2026-11-06: `static_elf`, its new regression test, and the relocation-header documentation sentence. The initial worktree was clean. No additional agents, sudo, network, VM operations, or Git writes were used. This report is the only repository edit; scratch sources, binaries and logs are under `/tmp/vprouter-elf-fix-review-GYedG6/`. Generated executables were inspected as bytes and never executed.

## Findings and disposition

No reproduced defect attributable to this change. Controller-review M1 and M2 are resolved.

- **M1 fixed — `tools/release_engineering/release.py:330`.** For machines 62 and 183, both SHT_RELA and SHT_REL now refuse a nonzero `sh_link` identifying the string table or the relocation section itself. All eight exact malformed combinations were accepted by the parent and refused by HEAD. Zero links remain accepted; links to both SHT_SYMTAB (2) and SHT_DYNSYM (11), including forward references, remain accepted when their own headers are valid.
- **M2 fixed — `tools/release_engineering/release.py:330`.** All four architecture/kind combinations with `sh_info=0xffffffff` and `SHF_INFO_LINK` clear were accepted by the parent and refused by HEAD. Flag-set controls refuse in both revisions. Existing in-range indices, including zero, remain accepted with either flag state.
- **Indexing order safe — `tools/release_engineering/release.py:265`, `:306`, `:320`, `:323`, `:330`.** The section-table range/count and string-table index are validated before table construction/indexing. Each iterated section passes the raising `require(link < shcount, ...)` before either symbol-table or relocation `sections[link]` dereference. Python's eager evaluation of the later `require` argument does not bypass the earlier statement. The new expression also short-circuits its dereference for `link == 0`. Every disk field is unsigned; huge values tested include `0x80000000`, `0xfffffffe`, and `0xffffffff`, the field maximum. Bounds/type/order probes produced only expected acceptance or ValueError, with no IndexError, ZeroDivisionError or other unexpected exception.

## Compatibility and header semantics

`tools/release_engineering/release.py:257` already requires ELF64 ET_EXEC; `:277` and `:298` exclude PT_DYNAMIC/PT_INTERP. This is an intentionally bounded static-executable profile, not admission of every valid ELF format.

Built eight real x86_64 executables with Debian GCC 14.2.0 and the system GNU linker. Each flag set below was built both with and without `-Wl,--emit-relocs`; every build succeeded. Commands and complete `readelf -hW -lW -SW` output are retained in scratch.

- `cc -static -no-pie control.c -o ...`: both ET_EXEC binaries accepted by parent and HEAD.
- `cc -static control.c -o ...`: both ET_EXEC binaries accepted by parent and HEAD.
- `cc -fPIE -static -pie control.c -o ...`: this toolchain produces ET_EXEC; both accepted by parent and HEAD. The flags alone were not treated as evidence of an ET_DYN result.
- `cc -fPIE -static-pie control.c -o ...`: both are ET_DYN and refused by both revisions with `wrong ELF target/type`. This is the unchanged documented profile boundary.

The six accepted binaries each have a legitimate `.rela.plt` with `sh_link=0`; emitted-relocation binaries also have `.rela.init`, `.rela.text`, etc. linked to `.symtab`. All remain admitted. Independently changing a real relocation section's link to `.shstrtab`, or its info to `0xffffffff` with SHF_INFO_LINK explicitly cleared, now refuses: 12 real-header negative controls were accepted by the parent and refused by HEAD. No new rejection of a valid in-profile static executable was reproduced.

**`sh_info=0` is appropriate.** For REL/RELA it means no particular target section is specified (permitted for executables), not relocation against the NULL section's contents. A nonzero value identifies a target section, and the new bound enforces that the index exists. It need not be nonzero, and SHF_INFO_LINK is not a prerequisite for the type-specific interpretation of this field. Requiring the flag would reject valid flag-clear headers; trusting its absence would recreate M2. Both states were exercised. In-range SHT_PROGBITS and SHT_NOBITS targets are accepted.

There is no NULL-index ambiguity to fix here: section zero is independently required to be the all-zero SHT_NULL header (`release.py:307`), while additional SHT_NULL sections are outside the existing supported-kind list (`:311`). Four probes changing section zero to non-NULL refused; 16 probes targeting a nonzero SHT_NULL section also refused. The change checks header index bounds, not whether each relocation payload actually addresses the named section. Such payload/target consistency remains explicitly outside this profile; adding that restriction would expand this fix's contract.

**Documentation accurate — `docs/rust-v2/release-preparation.md:135`.** The sentence accurately states fixed entry sizes, divisibility, zero-or-symbol-table links, and unconditional in-range info with zero allowed. The immediately following payload exclusion and ET_EXEC/profile description accurately limit the claim. It does not claim full relocation or executable validity.

## Verification ledger

All commands exited 0 unless an expected parent regression failure is explicitly noted. Scratch logs are ephemeral.

| Check | Fresh result | Evidence under scratch directory |
| --- | --- | --- |
| Exact prior M1/M2 reproduction matrix | 12 formerly admitted malformed specimens now refused; four flag-set controls remain refused; machines 62/183 and REL/RELA covered | `probe.py`, `probe.log`, `results.json` |
| New committed regression against parent / HEAD, swapping only the in-memory module | Parent: 20 expected assertion failures, zero errors; HEAD: passes | `probe.py`, `probe.log` |
| Seven-section relocation cross product: link/info 0..shcount+2 plus huge u32 values, both machines/kinds/flag states, forward/backward links, zero/one/two-entry and malformed lengths | 10,816 cases: 1,008 accepted, 9,808 ValueError; no unexpected exceptions | `probe.log` |
| Submitted three-section fixture bounds cross product | 648 cases, expected outcomes, no unexpected exceptions | `probe.log` |
| Wrong relocation entry sizes / nonzero NULL targets | 320 / 16 expected refusals, no unexpected exceptions | `probe.log` |
| Separate SYMTAB/DYNSYM dereference-path bounds matrix | 1,800 cases: 16 accepted, 1,784 ValueError; no unexpected exceptions | `index-paths.py`, `index-paths.log` |
| Non-NULL section zero with relocation info zero | Four expected refusals | `index-paths.log` |
| Eight real native static builds and byte inspection | Six in-profile ET_EXEC controls accepted; two ET_DYN controls refused identically to parent; 12 real-header mutations now refused | `*.build.log`, `*.readelf.log`, `results.json` |
| `python3 -B -I tools/release_engineering/test_release.py` | PASS: 38 tests in 22.795 seconds, 3,096 durability fault/replay cases | `release-tests.log` |
| `ast.parse` of `release.py` and `test_release.py` using Python `-B -I` | PASS, no bytecode written | `probe.py`, `probe.log` |

**Minor notes / limits (not reproduced findings):** no real ARM64 compiler was found in the standard tool paths checked, so real ARM64 builds are NOT_RUN. Real native relocation sections were RELA; REL acceptance was exercised with synthetic ELF64 fixtures for both machines. The compatibility matrix is evidence for these controls, not a proof over every possible valid ELF. Runtime, VM, production, and release qualification are NOT_RUN and outside this review.
