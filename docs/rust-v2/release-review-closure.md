# Review round 1 class closure contract

OFFLINE PREPARATION ONLY. This matrix was written before fixes. No native
installer exists. `plan` produces blocked public data for both managers; it does
not perform filesystem operations or restore private state. `FixtureStore` is
the only durable writer, confined to operator-created marked private fixtures.
Fault injection below cannot qualify a filesystem against physical power loss.

## Durable publication inventory (I2 class)

Every mutating/durability syscall in release.py is listed below. At **each**
boundary test EIO, ENOSPC and EINTR before the call, and interruption after the
real call, both on the retained descriptor and after close/reopen (crash-control
flow simulation, not a real crash). On write additionally test positive short
progress and zero progress. EIO/ENOSPC at non-storage calls are conservative
injections. A failure must propagate and preserve validated evidence; retry must
not infer durability from a missing or present name. A successful retry must
fsync every affected parent, including mutations performed by the failed run.
Second success must preserve identical artifact bytes, modes and fixed mtimes.

| Step / syscall | Failure / interruption state | Retry after error or reopened process | Required postcondition |
| --- | --- | --- | --- |
| Existing lock open + flock | no authority or retained lock, never recreate/break | reacquire the same pinned inode; contention refuses | marker/lock bytes and inodes unchanged |
| Marker/journal writes | absent: constructor only reads preexisting marker/lock; `.pending` is the public journal | never create replacement marker/lock; unknown journal refuses | no foreign/private evidence deletion |
| mkdir `.pending` | absent or empty pending | explicit recovery validates then removes it | root fsync confirms create/removal |
| O_EXCL temp leaf create | absent or empty owned leaf | validate entire pending set before cleanup | pending parent fsync before removal |
| bounded write | empty, prefix, or complete public bytes | positive short writes advance; zero/error abort; recover prefixes | no partial bundle visible |
| file fsync (before metadata) | bytes present, durability uncertain | recover/remove or republish from exact bytes | complete file fsync before rename |
| fchmod / utime | 0600 or 0444, arbitrary/fixed mtime pending | recover accepts either admitted mode and prefix | committed file 0444 / mtime0 |
| file fsync (after metadata) | final metadata durability uncertain | recover/remove or republish | final metadata and bytes synced |
| staging utime + fsync | complete private pending, maybe metadata uncertain | recover/remove or republish | every created entry's parent synced |
| rename pending to bundle | absent bundle or whole new bundle | validate exact complete bundle; repeat root fsync on recover AND publish replay | root fsync before successful replay |
| root fsync after rename | whole visible bundle, uncertain persistence | never skip root fsync because bundle exists | wholly absent/old or wholly new target |
| unlink each pending leaf | arbitrary validated subset remains | validate remaining set; fsync pending even when empty | removed leaf parent synced |
| pending fsync before rmdir | empty pending, durability uncertain | repeat pending fsync before rmdir | child cleanup synced |
| rmdir pending | empty pending or absent | root fsync even when neither name remains | removal parent synced on every replay |
| final root fsync | pending absent, durability uncertain | repeat root fsync on empty recovery | successful return confirms parent fsync |
| close / lock release | no further publication; close failure may lose handle | fresh open/validated lock required | never treat cleanup exception as durable success |

Read-only open/stat/fstat/read/scandir and descriptor/inode checks precede these
boundaries and refuse drift. They publish no entries. Pure install/update/
rollback/uninstall/reboot-recovery plans must invoke no filesystem/lock syscalls;
native transaction faults at those transitions remain NOT_RUN. Their required
future lock, generation journal, staging fsync, exchange and state restoration
are blockers in plan data, never an implementation claim.

## Lifecycle transition obligations (I1 class)

All transitions begin with independent quarantine/client guards, authenticated
ownership and fresh boot capture, then drain, stop, verify all users stopped,
and take a compatible stopped-state backup. Every failure requires quarantine
first, compatible release AND stopped-state restoration, or remain offline.
Identity, credentials, profiles, state, backups and foreign resources are retained.

| Transition | Additional ordered obligations before protected traffic | Ownership / failure condition |
| --- | --- | --- |
| install | stage full release; verify same identity then name; controlled restart; verify guards; workloads; commit | exact destination ownership; absent/unknown identity never enrolls |
| update | stage full release; real-directory exchange retaining old; verify identity; controlled restart; guards; workloads; commit | exact current records; compatible state; retain old release |
| rollback (new to old) | select retained compatible backup; verify binding; stage old release; exchange; restore stopped state; verify restored state; verify identity; controlled restart; guards; workloads; commit | backup unavailable/ambiguous means offline; restoration while ALL users stopped |
| uninstall | exact owned leaves / empty dirs only; retain all guards; offline | no protected restart; state/backup/foreign paths never removed |
| reboot-recovery | reconcile persistent ownership this boot; verify current release/state pair; verify identity; controlled restart; guards; workloads; commit | ambiguous ownership/pair means offline; no stale boot receipt reuse |

All plans remain DRAFT_BLOCKED, native_authority=false, release_ready=false.
No backup bytes enter this API. Backup selection/binding/restoration are explicit
steps and required native evidence, not invented success observations.

## ELF64 admission matrix (M1 class)

Admission is a bounded little-endian static ET_EXEC shape check for machines
62 (x86_64) and 183 (aarch64), not executable correctness or source provenance.
Tests generate invalid field mutations plus valid alternative fields: not every
bit change is invalid ELF. OSABI accepts System V/Linux, ABI version and reserved
ident bytes zero; architecture flags zero for these targets. Entry addresses,
physical addresses and section names are declarations, not execution evidence.

| Header class | Rejected shape / mutation sweep |
| --- | --- |
| e_ident | magic/class/endian/version; unsupported OSABI, ABI version, nonzero padding |
| e_type/e_machine/e_version/e_flags/e_ehsize | wrong type/target/version, unsupported flags, ELF64 size other than64 |
| e_entry | unsigned address inside an executable PT_LOAD; wrapping/outside/non-executable refuses |
| e_phoff/e_phentsize/e_phnum | overlap ELF header, wrong56 size, zero/excess count, overflow/truncation/outside file |
| e_shoff/e_shentsize/e_shnum/e_shstrndx | canonical absent table or bounded64-byte entries, no extended indices, valid string index; header/program-table overlap refuses |
| section entries | bounded file/address ranges, valid type/flags/alignment/entry-size/link/name/string-table ranges; NOBITS owns no file bytes |
| program entries | bounded file/address ranges, filesz<=memsz for LOAD/TLS, PHDR binding/order/containing LOAD, supported flags/types, power-of-two alignment/congruence; wrapping or overlapping LOAD file/virtual ranges refuses |
| static membership | at least one LOAD, PT_INTERP/PT_DYNAMIC always refused |
| truncation | every prefix of valid minimal fixture refuses; maximum unsigned offsets/sizes refuse without allocation |

Valid minimal fixtures for BOTH targets, a valid section-bearing fixture and
valid permitted field alternatives must be accepted. Mutated binaries are tested
directly and through packaging with a newly generated anchor, so hashing cannot
mask shape-admission defects. Existing fixtures remain byte-identical.
The ident sweep tests all256 values at each of16 positions per architecture.
Standard reserved section-flag bits and OS/processor masks are swept bit-by-bit,
as are reserved program flags and architecture flags. TLS, PHDR and fixed-width
init-array fixtures include both valid and invalid size/binding declarations.
Symbol/relocation/instruction payload semantics remain outside shape admission.
