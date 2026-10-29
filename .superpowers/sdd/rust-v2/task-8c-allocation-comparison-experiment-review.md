# Saved allocation-comparison experiment and public-scope review

2026-10-29. Independent bounded source/evidence/provenance/publication review.
Only this Markdown written. No application edit, Git mutation, build, test,
benchmark rerun, helper main, VM/SSH/Docker/privilege, profile/credential-content
read, resource action or subagent action. Root owns execution and publication.
The separately authorized owned.rs implementation is outside this review.

**Experiment SPEC PASS / QUALITY PASS / EVIDENCE PASS. Public scope and sensitivity
PASS. No open findings.** These verdicts cover the saved pure-work experiment,
its safe source archive and the listed documentation checkpoint. They do not
approve the separate application implementation or native/runtime/client/release
acceptance. Original404 remains FAIL/zero completed cases; full8c ACTIVE and
release_ready=false remain unchanged.

## Frozen experiment and artifact binding

Reviewed report .superpowers/sdd/rust-v2/task-8c-allocation-comparison-experiment.md
SHA256 cabd9dd40c18874d41905090d3263f4e5a8bd7b236adf4c88e05a94d9bb191b6.
The fully read safe harness tools/rust-v2-lab/allocation-comparison-cost.rs is
byte-identical to ignored target/task8c-allocation-comparison-cost/bench.rs;
both SHA256 dbc0568124d477577c588908dccdb22ae63edee7efc5174dde4be03ea3e883c1.
All following saved artifact hashes independently match the frozen report:

| Artifact under target/task8c-allocation-comparison-cost | SHA256 |
| --- | --- |
| bench executable | c3541815a44fb961d17ad9ba86014124293e238f5bfce76d7322c1ba968e2d05 |
| context.json | 6de05722d0118680d2fcf12c686d54889187d251496a012e55d6d399fcd9b086 |
| primary-allocation.json | bc9aaf73bbe61d64ed56e38baef585c298b3cb01a61f45edd688bb31d8b9c8c5 |
| actual-allocation.json | f5babf6aed7f728ebd33c72211a0273816a6b0f5060e4333b68492e22ff02379 |
| results.jsonl | 7218014ac7d3fae2aaa7fbf0ef567c3d75fc2840d6d9960cc8761ae39a856860 |
| summary.json | 0f4e61c7f9f90ccbb1208b1eeedddf882663ab48e2a8eab06b0d495eb745cc20 |
| build.log and run.stderr, each empty | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| application-source-preserved.json | a49625c761936e549bc5c314c915b37789c67f302229d0633a5c723c4a7c2450 |

Context binds the exact scratch compile argv, host rustc1.97.0 commit
2d8144b7880597b6e6d3dfd63a9a9efae3f533d3, LLVM22.1.6,
x86_64-unknown-linux-gnu and opt-level3. Existing core rlib
libvprouter_core-7cdd24b3d11fb56a.rlib SHA256
8a46a6baa18db5c8e0b7a583b2c81a65dbb2b8c17b7c8344aa02cee990add91e and
serde_json rlib libserde_json-4ae9ad4fa10f6286.rlib SHA256
6e1c0193f21d41f5bced03862840c5b5a73356980cdd3abdc02e1843c49d3b08
both independently match retained bytes. The report records compile/run exit0;
empty logs alone would not prove those exits. No execution was repeated here.
Complete original dependency optimization invocations were not reconstructed.
This is host glibc evidence, not the static musl native artifact/context.

## Fixture and historical source preservation

The actual two-exit fixture equals the allocation in run404's saved canonical
namespaces.json; the primary fixture equals that same allocation with only its
selected primary exit retained. Comparison used only the inspection's public
canonical allocation and primary selector, not profile contents. Both have the
exact four outer and ten exit fields. Compact UTF8 JSON sizes are541 and999
bytes, matching retained results; the files have an additional final newline.
These values grant no resource, ownership, receipt or runtime authority.

The preservation artifact records179 Rust files, changed=[] and reference
 target/task8c-nested-cost-local/after-hashes.json. That reference SHA256 is
760de42c6cdff8128c2023a7b48d4d82bc3084e9baaf1602096ecf19e41bb462.
Its179 paths/hashes all independently match immutable source commit
4451c8a75bcedcc330d4b59087a85f0bb5dca342. The artifact is a saved experiment-time
preservation result, not an independently repeated historical filesystem scan.
It does not assert current application equality: Root subsequently authorized
one-file owned.rs work, subject to its own fresh review. No current source
change is approved or rejected by this historical check.

## Harness spec and quality

The old helper body exactly matches same_allocation in frozen4451c8a owned.rs.
It serializes A and then B, maps errors to OwnershipMismatch and compares Vec
bytes. The scratch-local single Error variant preserves the compared Result
class without linking the launch runtime. Actual AllocationRecord/ExitAllocation
types come from the bound core rlib; this is not a serde_json::Value timing proxy.

The candidate exhaustively destructures all four outer and ten exit fields
without .., validates every A path then every B path before any ordinary false,
and compares raw OsStr spellings plus all other scalar/string/mode/Option fields,
vector length and ordered entries. It adds no serialization buffer, cache,
normalization, filesystem operation, mutation or authority. The current types
have deterministic injective JSON representations for these fields. Locked
serde_core1.0.228 ser/impls.rs908-928 was read: Path requires to_str and PathBuf
delegates to Path. Thus invalid UTF8 must retain OwnershipMismatch even behind
a prior scalar, vector-length or entry mismatch; raw path equality preserves
spellings that component-based Path equality can collapse.

The saved output reports PASS45 differential Result cases. Independently counting
the source gives45: four clone/outer cases, seven exit string-field mutations,
three mode/Option cases, seven exact paths, three differing path spellings,
ten string cases, five vector cases and six invalid-UTF8 cases. The fixture's
original mode and optional interface make the mode/None/empty mutations real.
Cases cover control/NUL/Unicode strings, ordered/empty/duplicate vectors and
invalid paths on either/both sides, late in a vector and behind schema/length
mismatches. The source compares exact old/new Results, not only booleans.

This finite harness is adequate for its reported mechanism experiment. It does
not claim all future serializers, fields or combinations were exhaustively
proven. In particular, the separately reviewed application brief still requires
meaningful invalid-path coverage behind an earlier entry mismatch and all other
focused verification; the saved experiment is not a substitute for that work.

## Independent timing arithmetic and inference limits

The source runs100 warmups per implementation/scenario, then seven alternating
old/new batches of20,000 calls. Parsing, construction and oracle checks are
outside timing; black_box covers inputs/results. Equal inputs use separate
clones. The primary mismatch changes transport_subnet, the final exit field.
Instant measures batch elapsed, not process CPU. Every retained scenario has
seven samples per implementation. Independently dividing by20,000 and computing
min/median/max reproduces summary.json exactly and the report's rounded table:

| Scenario | Old ns/call min / median / max | Candidate ns/call min / median / max |
| --- | --- | --- |
| Primary equal | 577.14375 / 592.3958 / 598.62875 | 18.60355 / 19.568 / 38.19805 |
| Actual two-exit equal | 918.97545 / 963.7315 / 1189.08355 | 34.6875 / 37.42205 / 60.35955 |
| Primary final-field mismatch | 549.83075 / 567.9243 / 588.99125 | 18.044 / 18.085 / 19.0505 |

The result supports eliminating repeated temporary JSON representation work in
this isolated comparison. It does not measure native retained-validation share,
335/339ms savings, a sufficient2s budget, complete Bootstrap performance or a
release speedup. No CPU pinning/load control, native custody/syscall/history/
journaling/diagnostic cost or hardware acceptance experiment is represented.
Native counters cannot turn these host numbers into measured native savings.

## Documentation chronology and publication scope

The report's next-boundary paragraph predates subsequent authorization and is
explicitly frozen. Current progress.md records Root's later acceptance of the
mechanism and exact one-file authorization under the brief, requiring fresh
implementation review/coherent binding before a native attempt. Together they
preserve chronology without claiming this experiment itself authorizes source
work. The current ledger hash at review is
5aa7e0f5ca95c6ddf31424e47ce3b9b484f090a08be9f712fb0e8e8bb4746a7a.

The checkpoint scope reviewed is the safe harness, README paragraph, public
catalog, current ledger, prior404 diagnosis/review, brief, frozen experiment and
this new review. Exact prior diagnosis7274438192f33cc1197f070a35c16bae5b302379a956ae994c28c63ec08b7191,
review30279b0ded925f0724cea63cc793b74682c86aaf7174475a544ea36773d898df
and briefa254476aa537f891546be3b044f16112334bc20eecf7dda3551dec477976ad6f
remain bound. README SHA256
92bd5a8f7bee3f82128f83dc1c9290b55acb770b3f77e2b23660dcf17da691ba
correctly separates the experiment from native VM/release performance and the
historical293-file controller archive. The new harness is outside that manifest.

Public catalog docs/rust-v2/mullvad-lab-catalog-20261029.json remains byte-equal
to Root's retained public-catalog check, both SHA256
d97cac280382677dc73d434e82a5d3db0ff8d9da67beab9d89456c81dc0a5c9e.
Its saved16:32:41.585877UTC observation marks de-fra-wg-402 inactive and the four
other listed supplied relays active. These are saved public catalog flags only;
no fetch or tunnel/handshake/provider test was repeated. Synthetic404 has
provider_profiles_used=false, so no relay cause for its Deadline follows.

Public code/docs were contextually read and bounded credential-pattern checked;
no embedded credentials/private profiles were found. The safe harness embeds
only generic test values and reads the two caller-supplied JSON paths. Raw
fixtures, binary, rlibs, context/logs, private runtime/identity/profile/key/state
artifacts remain excluded from publication. This review publishes only their
bounded bindings and conclusions. No application-source approval is bundled.
Native equivalence/cost effect, remaining Bootstrap scopes, real-client/runtime
and release acceptance stay NOT_RUN/open. Root owns staging/publication.

Final git diff --check passes; the new review also has no trailing whitespace.
Review frozen for Root staging.
