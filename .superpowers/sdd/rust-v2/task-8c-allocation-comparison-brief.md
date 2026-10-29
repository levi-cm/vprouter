# Exact allocation equality without temporary JSON buffers

Worktree `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`, base `ef7a085`.
Read this as the narrow requirements, plus the404 diagnosis and binding contract.
This brief is not implementation authorization until Root accepts the separate
offline mechanism experiment. Sole implementer remains autonomous_guard.

Run404 remains FAIL/zero completed cases at native_poll/result/Deadline. Its
fixed counters locate9130 retained-binding entries, but inclusive elapsed rows
overlap and do not measure the allocation comparator's individual time. The
candidate removes pure representation work inside those unchanged checks. An
offline shape experiment may establish a local mechanism, never native speedup,
sufficient2s budget, release performance or acceptance.

## Owned change

Only `crates/vprouter-launch/src/owned.rs` may change. Replace only the private
same_allocation implementation and add narrowly necessary private comparison
helpers/imports plus focused cfg(test) tests. Keep every call site and every
other production function/statement exactly unchanged, including all nested-cost
instrumentation, actual allocations, canonical serialization, digests, limits,
writer queues, ownership/live checks, clocks, windows and error handling.
No other source, dependency, manifest, controller, fixture, identity or state.
No cache, stored receipt, freshness waiver, authority constructor or descriptor
getter. No path canonicalization, filesystem access or allocation/config mutation.

The comparator must return exactly the same Result<bool> as the old pair of
serde_json::to_vec calls for both input AllocationRecords. All fields, ordered
exit entries, duplicate entries, byte spelling of strings and paths, modes,
Option values and numeric values participate. Use exhaustive destructuring
without `..` for AllocationRecord and ExitAllocation so a new field cannot
silently be omitted. Do not use derived PathBuf/Path equality: component-based
normalization can collapse distinct JSON path spellings.

Before any scalar/length/entry mismatch can return false, validate every
state_dir in A and then every state_dir in B using the same UTF8 prerequisite
as Serde's Path serializer. An invalid path must return OwnershipMismatch even
behind an earlier scalar, vector-length or entry mismatch. Preserve the original
A-then-B validation/error order. Compare valid paths by their exact original
UTF8/OsStr bytes; no lossy conversion, dot/slash removal or Unicode normalization.
Every other field is one of the current injective JSON scalar/string/enum/Option
representations; document that equivalence with source references. Existing
allocation validity and ownership checks remain at their original call sites.

## Focused verification

Use the old serializer as a cfg(test) differential oracle, not as production
fallback. Cover equal records; each outer and exit field independently changed;
ordered/duplicate/empty/differing-length exit vectors; both modes; None/Some and
empty-string Option values; exact dotted/repeated/trailing separator spellings;
Unicode and NUL strings; malformed UTF8 paths on both sides, including behind
earlier scalar, vector-length and entry mismatches. Test real Result behavior,
not log text or a second copy of the new comparison algorithm. Preserve all
existing tests. Where the oracle exposes a historical failure in an attempted
comparison, retain the failing result and fix before freezing.

Run launch library tests, focused formatting and strict launch lib/tests Clippy.
Snapshot all Rust inputs before editing and prove every unowned path unchanged;
within owned.rs prove only comparator/helpers/tests/imports changed. Keep logs
under ignored target paths. No Git mutation, native/VM/SSH/Docker/privileged or
credential-bearing test, source freeze/build manifest update or subagent.
Root owns workspace/static builds and all VM actions after independent review.

Write `task-8c-allocation-comparison-report.md`: exact source/diff hashes,
mechanism and equivalence argument, oracle cases/commands/results, unchanged
source proof, self-review and limits. Freeze for fresh independent spec/quality
review. Original398-404 failures and all remaining Bootstrap/task8c/client/
migration/platform/benchmark/release gates stay unaccepted.
