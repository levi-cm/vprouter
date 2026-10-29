# Independent review: retained-cost metadata reader

2026-10-29. **Specification verdict: PASS. Quality verdict: PASS.** No
actionable finding or required implementation revision was identified in the
frozen parser/report scope. Synthetic parsing evidence grants no native cost,
runtime, source-optimization or acceptance authority.

## Exact binding and scope

| Reviewed artifact | Independently verified SHA256 |
| --- | --- |
| `task-8c-retained-reader-brief.md` | `2514849ae47092b22390a3abaf5f501af5252a30b5b9cf44043d1f461c57f0b2` |
| `task-8c-retained-reader-report.md` | `2a9125990fb261b6e74a0113b70928d0c48deb702ddf3776f496b3ab19f51b11` |
| `tools/rust-v2-lab/parse-bootstrap-cost-diagnostics.py` | `4309e4881c9aaeb27191ca35957a23f215a9764d37f5afdb00820aafd0518206` |
| `target/task8c-retained-reader-local/source.diff` | `e867c4adc340a7f95151ae9c62e81f2ec6fe08272b78ffc2b2070b9436057d8e` |
| Saved original parser | `31e70538076ea97538ad4ab09aa8126a74543985e92e6727ad7d0f84d1d3a5d7` |

The complete original and final parser and complete diff were read. A read-only
unified-diff reconstruction from their bytes exactly matched the frozen diff.
The change adds only the retained-category constant, optional validation block
and optional output assignment. Existing input/JSON/binding/clock/wrapper/nested
validation and output creation remain unchanged. Evolving Rust source was not
inspected as part of this review.

## Specification and quality assessment

The optional extension is closed correctly. Every occurrence of the marker
substring in stderr is routed through strict prefix/field parsing. A bare,
tabbed, leading, embedded or suffixed malformed marker therefore raises a
refusal rather than being treated as absent. If no marker occurs, the retained
list remains empty and the original output dictionary and field order remain
unchanged.

Each parsed row must have exactly family/category/calls/elapsed_ns/measurement/
grouping. Existing unique-field handling rejects duplicates. Both fixed
measurement/grouping values are checked before being removed from the output
row. Calls and elapsed use the existing canonical nonnegative decimal reader
and u64/u128 bounds. Zero calls require zero elapsed; both count-only categories
require zero elapsed for all call counts.

The exact ordered tuple check admits only query/policy/other times the eight
required ordered categories: exactly24 rows. Unknown family/category, duplicate,
missing, extra and reordered rows cannot match it. An all-zero valid extension
still has24 rows and therefore produces the optional retained output. All
validation completes before destination creation; no retained sum or authority
is constructed. The implementation is small, explicit and consistent with the
existing reader's validation style.

The existing16MiB input bound, duplicate JSON-key rejection, source bindings,
optional original2s clocks, exact13 wrapper/30 nested rows, wrapper total,
original scope text and success-log behavior are preserved. Existing output
uses exclusive `open('x')`, so an existing destination is not overwritten;
successful output is chmod0600 as before. This extension does not change those
existing filesystem semantics or introduce a new destination mode guarantee
before that chmod. Malformed retained rows cannot reach output creation.

Publication remains limited to four validated fields per retained row: closed
family/category strings and bounded counts/nanoseconds. Raw lines, request
contents, arbitrary text, paths, identifiers and credentials are not copied
from the extension into metadata. Source hashes/boundary data and the local
destination-path success message retain their old meanings. Ignored synthetic
fixtures and raw native records are verification inputs, not intended published
artifacts. Inclusive retained rows are neither summed nor converted into CPU,
successful-check, saved-budget or native-cost claims.

## Retained evidence inspected without duplicate execution

The retained report, verification.json, red-results.json, AST/405/exclusive logs,
synthetic fixtures, accepted outputs and refusal stdout/stderr were inspected.
All98 entries in artifact-hashes.json matched their stored byte lengths and
hashes. This independently binds the evidence read here; it does not rerun it.

- The retained AST/compile log reports PASS without invoking parser main as
  part of that check. Root separately reports a fresh AST check; this reviewer
  did not execute the parser or repeat AST checks.
- Original-parser405 output, updated-parser405 output, historical405 closed
  metadata and Root's `target/task8c-retained-cost-root-20261029/root-reader405.json`
  are independently byte-identical, SHA256
  `f743c668eaefc61a3681dbcf94f2c8e269d6d69bb8c8f26f690aa1fe24c039e3`.
- The three accepted saved cases are normal, all-zero and maximum-bound values.
  Their outputs each contain24 four-field rows, have mode0600, preserve every
  baseline output value except the expected input hash, and add only retained.
  The normal case exactly matches the separately stored expected-retained rows.
- All23 saved refusals report exit1/no destination. Current evidence contains
  no corresponding destination, their stdout is empty and their retained stderr
  terminates in the generic closed-diagnostic ValueError. Covered cases include
  duplicate/foreign/reordered/missing rows, unknown/missing/duplicate fields,
  both count-only durations, numeric bounds/sign/canonical spelling, zero-call
  duration, fixed measurement/grouping and malformed marker variants.
- The exclusive-output log records refusal without overwrite, and the retained
  preexisting destination still contains its original bytes.
- The saved red evidence retains both original-parser failures of the new
  requirements: a valid extension was omitted and a bare marker accepted.
  These observations are not presented as successful new-parser behavior.

## Limits

Only this review Markdown was written. No Git operation, source edit, parser/
helper/test/build execution, VM/profile/native operation or subagent was used.
Fresh checks were restricted to reading, hashes, saved-output comparison and
diff reconstruction. No claim is made that this reviewer reran retained tests.

The three synthetic successes and23 refusals establish reader behavior only.
The separate Rust diagnostics, normal-build/source equivalence, child-filter
behavior, coherent artifacts and future owned local native run require their
own review and evidence. Original failed attempts and Bootstrap/client/runtime/
migration/platform/performance/release gates remain unaccepted where open.
