# Bootstrap ancestry correction: independent spec and quality review

2026-10-29. **Scoped specification PASS; scoped quality PASS.** No Critical,
Important or Minor findings in the reviewed three-source-file increment. This
verdict permits Root's next coherent build/native gates; it does not approve
full8c, runtime activation, clients, recovery or release.

## Reviewed binding and verification

Read the ancestry-fix brief first, then the diagnosis, implementation report,
exact frozen diff, parent8c/task8 requirements and binding
`docs/rust-v2/IMPLEMENTATION.md`. Inspected the unchanged production producer-pin,
native Selected/confinement and filter-builder dependencies needed to evaluate
the extraction and permission boundary. Used the requesting-code-review checklist
without delegation.

Observed branch `rust/v2`, HEAD
`a1b3f46a9468018f481cfc2624dbe80b09c2897c`, semantic base
`e986cfda4c0fe3f29c6167541e1ff5698d859b4b`. Only the following three source
paths differ from that base; Cargo manifests/lockfile do not differ. Root's
intervening document checkpoint is outside this source increment.

| Source path | Independently rehashed SHA256 |
| --- | --- |
| `crates/vprouter-launch/src/process.rs` | `8cc519f527f675d4fe487ea39fb30fdae2279e11e3447c5ee73000131d819cb6` |
| `crates/vprouter-native-role/src/producer_bootstrap.rs` | `443cf5ddd600cbb91138360d113fab1734911412502ca53f27b69331a8ba74af` |
| `crates/vprouter-native-role/src/filter.rs` | `3be35aa790ff9346d9d34a4b9232c255a1201c4bbb7ebf7233fd15f0ca6e9743` |

All three match both the implementer report and Root's
`target/task8c-ancestry-20261029T141252Z/root-frozen-source-hashes.json`.
The snapshot SHA256 is
`fb92657e717ac6fa389c55cff2adf1be58322ed9a948eaf2f3893e4f3342cfe3`.
The report SHA256 is
`a17c212f3e57cba6a8b5281678f978e7788da78c042f98044b2823c64fcb175e`.
Regenerated the three-file source diff read-only with ten context lines and
compared its bytes to `task-8c-bootstrap-ancestry-fix-review.diff`: exact20,083-byte
match, SHA256
`74c2c9c8b7c3ceff607bee543313532749f59c32cafd3573e936861655041519`.

Independently rehashed every prior pending-progress table entry and all six
approved receipt entries against `task-8c-bootstrap-pending-progress-report.md`:
13/13 pending-progress and6/6 receipt paths match. The receipt table also agrees
with the reviewed slice1 report. No protected source was changed by this increment.

## Specification assessment

- Host `process.rs:599-615,873-893`: the first relation is now original
  system.slice-relative `..` equal to original root. The original root comparison,
  process revalidation before/after, directory trust and cgroup2 checks remain in
  the production caller. The extracted private helper compares borrowed named
  edges only. Original root->system.slice and system.slice->exact Docker scope
  checks, the compared identity tuple and NOFOLLOW behavior remain intact.
  Acquisition still uses the original cgroup root and the existing
  BENEATH/NO_SYMLINKS/NO_XDEV openat2 restrictions.
- Confined `producer_bootstrap.rs:236-285`: the same corrected reverse relation
  precedes all three unchanged forward relations, including original scope->exact
  producer group. All four descriptor ownership/type/mode/cgroup2 checks still
  precede the private comparison core. No constructor, creator, original
  identity/inventory, deadline or confinement requirement was removed. Existing
  Selected validation and child setup/install/require paths remain unchanged.
- Actual `Ancestry::rules` still returns exactly four tuples. Only its first FD
  changes from original root to original system_slice; its fixed immutable `..`
  CStr is renamed privately and is shared with the corresponding validation.
  Remaining root/system/scope/group tuples are unchanged. There is no second
  root-FD permission, generic path permission or old-role expansion.
  `filter.rs` production code is byte-for-byte unchanged: its builder still
  checks exact stat syscall, descriptor, pointer and NOFOLLOW flags across both
  argument words.
- No placement, UP/Ready, cleanup/recovery authority, policy bypass, clock renewal
  or new resource is introduced. No fixture constructs a PinnedProcess, Source,
  OperationalOwner or confined role. The native fixture prepares only the
  pre-existing internal descriptor/name selector; its borrowed-edge validation
  is explicitly separated from full cgroup2/confinement admission.

## Regression and quality assessment

The new launch and native tests invoke the very private comparison cores called
by production, using real open directory FDs. Their root has a distinct external
parent, with internal system.slice/docker-<64hex>.scope/health directories. The
old self-parent predicate would fail the initial successful complete-edge check.
They reject substituted root/system/scope (and native group) descriptors, and
renamed, replaced and symlinked named children while retaining the original FDs.
Restoring group/scope names recovers success. Existing individual-link negative
coverage is retained. The fixture does not claim the temporary filesystem is a
cgroup2 mount or mint full production authority from metadata.

`filter.rs:338-395` consumes actual `Ancestry::rules` from that real-FD fixture.
Its positive expected tuple independently selects the original system FD and
fixed internal-parent CStr rather than reading the first generated tuple. It
denies the former root FD with that same pointer, another retained FD, a different
name pointer, follow flags and changed high words of FD/path/flags. All four
generated tuples pass Bootstrap and fail the old WireGuard policy. Existing
forbidden-operation coverage remains, and the new test also checks
openat/write/dup/mkdirat/unlinkat/setns denial. This is interpreted BPF evidence,
not an installed kernel-filter execution.

Private helper extraction is narrow, preserves errors/identity comparisons, and
adds no new public authority API or unsafe operation. Test-sharing visibility is
limited to cfg(test). No quality finding warrants expanding this correction.

Independently read and rehashed retained logs; all hashes match the report:

| Evidence | SHA256 | Observed content |
| --- | --- | --- |
| `/tmp/task8c-ancestry-red.log` | `d3a63ee8e78caa9255800fc74329e0b826bfe41f1a27deca632721dee8ffcbee` | Three compiled runtime regression failures: host CgroupMismatch, native Descriptor, generated policy DENY instead of ALLOW |
| `/tmp/task8c-ancestry-green.log` | `ff1ae1225ff7d982cf0edf814eaaa6e149744674757059cc3e9597cc7c9f39a2` | Same three selected regressions pass |
| `/tmp/task8c-ancestry-final-lib.log` | `ec633f24661f95450b08b03c41e17c0d4fc17f6868563d4a19999229265a675d` | 148 launch +18 native-role passed,0 failed, including the final generated-policy regression |
| `/tmp/task8c-ancestry-final-clippy.log` | `8fce18b5a4ff4680ca593155a7eb68d09c458160c12537409bb2ab3b006b8a8f` | Strict Clippy completed successfully |

These are inspected implementer evidence, not independently rerun suites. The
reported rustfmt/diff checks were not rerun in this review. The exact historical
RED source state was not separately reconstructed; the retained runtime failures
agree with both the old predicates visible in the base diff and the new positive
assertions. Root runs fresh workspace/static verification separately.

## Limits and disposition

Run401 remains FAIL. The diagnosis and report correctly distinguish a concrete
source defect plus Root's current-namespace oracles from an original-owner
executed-return trace. This review does not independently replay either oracle
or prove that this predicate was run401's first error. No identical native retry
was performed.

Reviewer-native execution, actual kernel-filter installation, connected held
query/policy/failure-family success, coherent source/artifact binding,
both-architecture runtime behavior and protected54-link baseline verification are
NOT_RUN here and remain Root's gates. Full8c remains active; original failed
evidence, retained resources, runtime/recovery, real clients and release gates
remain open.

Only this review document was written. No source, index/HEAD/branch, manifests,
contexts, static builds, VM/SSH/Docker, profile/credential/identity, privileged
operation or subagent was used or mutated by this reviewer.
