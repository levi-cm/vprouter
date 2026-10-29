# Bootstrap internal ancestry correction candidate

2026-10-29. Implemented the concrete three-file scope in
`task-8c-bootstrap-ancestry-fix-brief.md`, semantic base
`e986cfda4c0fe3f29c6167541e1ff5698d859b4b`, branch `rust/v2`, workdir
`/DATA/AppData/vprouter-rust-v2`. Root subsequently checkpointed documents only
as `a1b3f46`; the source base did not change. Source is unstaged and frozen for
fresh independent spec/quality review. This report is the only non-source
repository file written for this implementation increment.

Local regression/library/Clippy/format checks pass. Root owns coherent builds,
both-architecture verification and connected native execution. Run401 remains a
retained FAIL. This candidate does not establish its exact original-owner return
trace or full Bootstrap/8c/client/release acceptance.

## Requirements and resulting behavior

The host original-process ancestry verifier now checks the actual internal edge
`system.slice/.. == original cgroup root`, replacing the invalid requirement
`cgroup mount root/.. == cgroup mount root`. It still requires the retained original
root identity, admitted-process revalidation before and after, trusted directories,
cgroup2 filesystems, exact root-to-system.slice identity and exact
system.slice-to-original-Docker-scope identity. Existing no-follow/openat2 controls
are unchanged.

Only the borrowed named-edge comparison loop was extracted into private
`verify_producer_links`. All admission, original root, trust, filesystem and
process checks remain in the production caller. This helper returns validation
only; it cannot construct an admitted process, Source, OperationalOwner or role.

The confined native-role ancestry verifier makes the corresponding internal-edge
check, followed by the unchanged root-to-system.slice, exact Docker scope and
scope-to-exact-producer-group checks. Its complete comparison core was extracted
into private `Ancestry::verify_links`, called after the existing root ownership,
directory type, no-group/world-write and cgroup2 checks over all four original
descriptors. Inventory, original identities, creator, deadline, confinement and
producer-group authority checks elsewhere remain unchanged.

Only the first actual `Ancestry::rules` directory FD changes, from the original
root to the original system_slice. The same fixed immutable `..` pointer is used;
its private constant is renamed `SYSTEM_PARENT`. The list still contains exactly
four entries; all other entries are unchanged. The existing filter builder still
permits only exact syscall/FD/path-pointer/AT_SYMLINK_NOFOLLOW tuples, including
both words of checked arguments. The former root-FD/`..` tuple is not retained.
No additional syscall, path, follow mode, descriptor, old-role permission or
generic authority was added. `filter.rs` changes are test-only.

No placement, UP, READY, lifecycle/recovery/cleanup authority, pending-state waiver,
clock renewal or resource was introduced. The previous thirteen pending-progress
source paths and all six approved8c.1 receipt source files are byte-for-byte
unchanged, verified against the prior frozen report's hashes.

## Real-FD and generated-policy regressions

Three new tests catch the concrete old behavior:

1. Launch's production borrowed-edge core is exercised with actual open directory
   FDs for an isolated temporary root, system.slice, a Docker-shaped scope with a
   literal64-character hex container ID, and a health subgroup. The root's external
   parent is distinct. The complete intended edge set must pass; foreign root,
   system and scope FDs must refuse. Renamed, replaced and symlinked scope and
   system.slice names refuse while stale descriptors remain open. Restoring the
   original names succeeds, proving refusals do not mutate or adopt custody.
2. The confined verifier's production complete edge core uses the same real
   directory hierarchy shape, including the producer subgroup. It refuses foreign
   root/system/scope/group FDs and rename/replacement/symlink of group, Docker
   scope and system.slice. Existing individual named-link negatives remain.
   The test prepares the existing internal Ancestry selector from real directory
   pins/names only; it does not construct a confined role or pass full cgroup2
   verification on temporary directories.
3. The filter regression consumes the **actual** `Ancestry::rules` from that real
   descriptor fixture. Its expected reverse syscall uses the independently
   selected original system_slice FD and fixed internal-parent name pointer,
   rather than taking the expected tuple from the generated list. It allows the
   correct exact reverse stat, denies the former root FD, foreign FD/name pointer,
   follow flags, and nonzero/changed high words of FD/name/flags. All four actual
   generated tuples are accepted by Bootstrap and denied by the old WireGuard
   role. openat/write/dup/mkdirat/unlinkat/setns remain denied. Existing filter
   negatives, old-role and forbidden-operation tests remain unchanged.

The tests validate real borrowed filesystem edges and interpreted generated BPF,
not an actual cgroup hierarchy admission or installed kernel filter. No full
PinnedProcess/Source/OperationalOwner or confined-role authority is manufactured
from fixture metadata. Test utilities live under cfg(test). Root-native kernel
filter execution, both-architecture behavior and the full retained Bootstrap
chain remain **NOT_RUN** for this increment.

## RED/GREEN evidence

First, the old production edge loops were extracted without changing either
false edge or the old generated rule. The three new behavioral regressions then
compiled and failed at runtime, rather than failing compilation:

```text
cargo test --no-fail-fast -p vprouter-launch -p vprouter-native-role --lib original_ancestry
```

RED: exit101; build6.34s. Launch's test returned CgroupMismatch at the positive
full-edge assertion; the confined test returned Descriptor at its positive
full-edge assertion; the actual-generated filter test returned DENY327681 where
ALLOW2147418112 was required for system_slice-relative `..`. All three failed,
with zero passing selected tests. Log: `/tmp/task8c-ancestry-red.log`.

The minimal two-edge and first-rule-FD correction then made the identical command
GREEN: exit0; build3.26s; one launch and two native-role regressions passed.
Log: `/tmp/task8c-ancestry-green.log`. The final filter assertion was additionally
made independent of the generated first tuple's name pointer; the final complete
library run below includes that stronger assertion.

## Final local verification

| Command/check | Result | Retained local log |
| --- | --- | --- |
| `cargo test -p vprouter-launch -p vprouter-native-role --lib` | exit0;148 launch +18 native-role passed,0 failed; build2.92s; test times2.11s/0.02s | `/tmp/task8c-ancestry-final-lib.log` |
| `cargo clippy -p vprouter-launch -p vprouter-native-role --lib --tests -- -D warnings` | exit0;10.92s | `/tmp/task8c-ancestry-final-clippy.log` |
| `rustfmt --check --edition 2024 --config skip_children=true` on exactly the three owned source paths | exit0; no output | tool result |
| `git diff --check` | exit0; no output | tool result |
| Rehash prior thirteen pending-progress plus six approved receipt files | all19 match their prior frozen report hashes | tool result |

Retained log SHA256:

```text
d3a63ee8e78caa9255800fc74329e0b826bfe41f1a27deca632721dee8ffcbee /tmp/task8c-ancestry-red.log
ff1ae1225ff7d982cf0edf814eaaa6e149744674757059cc3e9597cc7c9f39a2 /tmp/task8c-ancestry-green.log
ec633f24661f95450b08b03c41e17c0d4fc17f6868563d4a19999229265a675d /tmp/task8c-ancestry-final-lib.log
8fce18b5a4ff4680ca593155a7eb68d09c458160c12537409bb2ab3b006b8a8f /tmp/task8c-ancestry-final-clippy.log
```

## Exact frozen inventory and remaining gates

Final delta: three source paths,282 insertions and22 deletions; the additional
lines are private comparison extraction, regression fixtures and assertions.

| Owned path | SHA256 |
| --- | --- |
| `crates/vprouter-launch/src/process.rs` | `8cc519f527f675d4fe487ea39fb30fdae2279e11e3447c5ee73000131d819cb6` |
| `crates/vprouter-native-role/src/producer_bootstrap.rs` | `443cf5ddd600cbb91138360d113fab1734911412502ca53f27b69331a8ba74af` |
| `crates/vprouter-native-role/src/filter.rs` | `3be35aa790ff9346d9d34a4b9232c255a1201c4bbb7ebf7233fd15f0ca6e9743` |

Root's bound same-guest oracles prove the current root-parent mismatch and correct
system.slice-parent/original-Docker-scope/PID/start/membership relations. Both
oracles explicitly remain current-namespace observations, not a captured original
owner return trace. Run401 remains preserved; no identical retry was performed.

No Git/index/commit/push operation, manifests/contexts, static/coherent builds,
VM/SSH/Docker/privileged operation, profile/credential/identity access, external
messages or subagents were used by this implementer. Root's concurrent documents
and protected54-link preservation boundary remain untouched.

Fresh independent spec/quality review, coherent source/artifact binding,
both-architecture builds/checks, actual kernel filter execution and a new
Root-authorized native held query/policy/failure family remain open. Full8c,
runtime/recovery, clients and release acceptance remain open.
