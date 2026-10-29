# Exact allocation comparison: one-file implementation

2026-10-29. Frozen for Root's fresh independent review. Root authorized the
reviewed task-8c-allocation-comparison-brief.md at application base ef7a085 after
the separate experiment froze. Only `crates/vprouter-launch/src/owned.rs` changed.
No Git mutation, VM/native action, controller, dependency, fixture resource,
credential/profile read, build manifest or subagent was used.

## Mechanism and equivalence

The private same_allocation now compares typed values without constructing two
JSON Vec buffers. Exhaustive patterns cover all four AllocationRecord fields and
all ten ExitAllocation fields, with no `..`. New fields therefore require an
explicit source update. Before any mismatch return, state_dir.to_str is checked
for every exit in A, then every exit in B. Invalid UTF8 returns the same actual
launch Error::OwnershipMismatch as the old serializer. Valid paths compare exact
OsStr spelling; Path/PathBuf equality is deliberately avoided. Exit vector length
and ordered zipped entries preserve order and duplicates. No cache, filesystem
access, canonicalization, mutation or new authority is introduced.

Source basis: core `allocation.rs:29-50` derives ordinary Serialize for both
records; all non-path leaves are u32/u64, String, ExitMode or Option<String>.
Core `config.rs:42-47` gives the two distinct snake_case mode representations.
These fixed numeric/string/enum/Option encodings are injective; None serializes
as null and Some as a string. Fixed field order plus ordered Vec serialization
makes field/length/position equality equivalent to the old JSON-byte equality.
The locked serde_core 1.0.228 `src/ser/impls.rs:908-928` serializes Path using
to_str (invalid UTF8 is an error), and PathBuf delegates to Path. This was checked
against the exact locked registry source, not 1.0.229. No other field has a
fallible custom serializer in the current record. Finite oracle coverage and
this current-type/source argument do not prove equivalence after future custom
serialization changes.

All call sites and all other production statements remain byte-for-byte intact,
including full live verification, histories/digests, nested diagnostic timers,
original two-second windows, queues, held/negative checks and error handling.

## Tests and retained failures

Four new cfg(test) tests exercise 80 input pairs against the exact old serializer
body, using the real launch Result<bool>/Error, and separately check the oracle
against expected results. They cover every scalar field; both modes; None,
Some and Some-empty; unsigned limits; empty/ordered/duplicate/different-length
vectors; exact/repeated/dotted/trailing separator paths; Unicode/decomposed
Unicode/NUL/control strings; invalid UTF8 in A/B/both and late exits; and invalid
paths behind scalar/length/entry mismatches in both argument orientations.

Tests were written before production changes. Because this is a behavior-
preserving refactor, the corrected tests first passed on the original serializer.
The initial characterization failed (exit101, three pass/one fail) because the
shared fixture is Direct/None and the test assumed Mullvad/Some; that log remains
`characterization.log`. Only the local test values were corrected, before any
production edit; `characterization-corrected.log` records four pass.

Two deliberate temporary mutations demonstrate useful oracle sensitivity:

- `a_path == b_path`: path spelling test failed with actual Ok(true) versus
  oracle Ok(false), exit101 (`path-eq-mutation.log`).
- Remove UTF8 precheck: invalid-path test failed with actual Ok(false) versus
  oracle Err(OwnershipMismatch), exit101 (`utf8-precheck-mutation.log`).

Both mutations were restored from exact saved final bytes before final checks;
`mutations.json` preserves their exits. No historical native failure is replaced
or relabeled. An initial source-reconstruction script left the newly inserted
blank line behind and failed its assertion; including that test-block blank line
made reconstruction byte-identical without changing application source.

## Final commands and results

All logs are under ignored `target/task8c-allocation-comparison-local`.

| Command | Result | Log |
| --- | --- | --- |
| cargo test -p vprouter-launch --lib allocation_comparison | exit0; 4 passed | comparator-focused.log |
| cargo test -p vprouter-launch --lib | exit0; 156 passed, 0 failed | launch-lib.log |
| cargo clippy -p vprouter-launch --lib --tests -- -D warnings | exit0; no warning | clippy.log |
| rustfmt --edition 2024 --config skip_children=true --check crates/vprouter-launch/src/owned.rs | exit0; empty output | fmt.log |

## Exact freeze and preservation

| Artifact | SHA256 |
| --- | --- |
| owned.rs before | `1e2b547bc2df30a6a128184eae9b6569452d12ec80bc59f9ff71e90a18f0636e` |
| owned.rs final | `b14900907cba93637bed606130467bdf82dbb864da3e4953129dba1ffdb9b6c7` |
| source.diff | `87b0f28892f304023b3c568d4349bbf6816097d9990a21a6d4706942cd89f010` |
| source-preserved.json | `b1081484ded144dc917dacb71d40c1e16d253f969c4295c1d69b00d03617bd00` |
| rust-before.json | `f7584f3b644f54ad48e7a789b773587e6e90dcce38c6011cb473547e730c12c1` |
| rust-after.json | `e98e5c4e2df75432ebcba66ce99b7a64b6809f46d230fe8f38d49305bc605099` |
| launch-lib.log | `4179536427a84baf5f4ca83db5844b75811c16aa9373edb9cea363e36ea45988` |
| clippy.log | `31f448277faba4fbb11d93a31851c871a75455dcb51a8447145dcf2f46749f59` |
| fmt.log | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

The before/after snapshots cover all179 application Rust paths. Exactly owned.rs
changed: all178 unowned paths are unchanged; no Rust path added/deleted. Replacing
only the changed import/comparator/helper/test insertion with their original
bytes reconstructs all of owned.rs byte-identically, proving every remaining
statement (including the retained nested diagnostics) unchanged. Final hashes
were rechecked after full tests/Clippy/fmt. See artifact-hashes.json for all log
hashes, including both expected mutation failures and characterization history.

Self-review found no omitted current field, short-circuited serialization error,
component-normalized path comparison, vector normalization, check/call-site
change or cache. The extra helper is private and used only by same_allocation.
The serializer oracle exists only inside cfg(test).

## Limits and next boundary

The separate experiment report is task-8c-allocation-comparison-experiment.md,
SHA256 `cabd9dd40c18874d41905090d3263f4e5a8bd7b236adf4c88e05a94d9bb191b6`.
Its45 offline oracle cases and host timings establish a local pure-work mechanism
only. This implementation has no fresh native timing. The native comparator's
cost share, any native speedup and sufficient two-second budget remain unproved.

Root owns fresh workspace/static/cross-architecture checks, independent review,
coherent build/artifact binding/checkpoint/push and any subsequent native run.
Original398-404 failures remain FAIL; complete Bootstrap/task8c, real clients,
migration, platform, benchmark and release acceptance remain open/NOT_RUN. The
synthetic404 did not use provider profiles; relay availability is unrelated to
this offline comparison change. No source is authorized beyond this frozen scope.
