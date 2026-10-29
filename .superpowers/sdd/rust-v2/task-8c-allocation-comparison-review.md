# Independent review: exact allocation comparison

2026-10-29. Fresh independent specification and quality review of the complete
frozen one-file change. **Specification verdict: PASS. Quality verdict: PASS.**
No actionable finding or required source revision was identified in this scope.
These verdicts cover the source refactor and its retained local evidence only;
they do not grant native, performance, Bootstrap or release acceptance.

## Reviewed identity and scope

Worktree `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`; the initial read-only
HEAD check returned source base `ef7a0859aa6dd28aeaa3a8e7ff60d2711cae7486`.
During review Root advanced HEAD to documentation/experiment checkpoint
`446845bf9a27a5aa6e85b3872dd137aaa5603348`; its path list and unchanged frozen
source/report/diff hashes were checked again. Requirements are
`task-8c-allocation-comparison-brief.md` and the binding preservation/local-test
contract in `docs/rust-v2/IMPLEMENTATION.md`. The earlier source checkpoint
`4451c8a` and native failures are not replaced by this review.

| Frozen artifact | Independently verified SHA256 |
| --- | --- |
| Implementation report | `940b40b64a6b8d3a298368c14a113a0a9013927d4cd14c40f938b750e4320d70` |
| `target/task8c-allocation-comparison-local/source.diff` | `87b0f28892f304023b3c568d4349bbf6816097d9990a21a6d4706942cd89f010` |
| Final `crates/vprouter-launch/src/owned.rs` | `b14900907cba93637bed606130467bdf82dbb864da3e4953129dba1ffdb9b6c7` |
| Saved original `owned.rs` | `1e2b547bc2df30a6a128184eae9b6569452d12ec80bc59f9ff71e90a18f0636e` |

The full diff was read, rather than an implementation summary alone. It changes
one import, the private `same_allocation` body, a private exit-comparison helper,
and a focused test insertion inside the existing `cfg(test)` module.

## Specification assessment

- Both `AllocationRecord` patterns enumerate all four fields, and both
  `ExitAllocation` patterns enumerate all ten fields without `..`. Every current
  field participates. Exhaustive destructuring prevents a newly added field
  from silently compiling out of the comparison.
- The path-validation loops traverse every exit in A and then every exit in B
  before evaluating scalar values, vector lengths or entry comparisons. They
  return the actual launch `Error::OwnershipMismatch` through `Result<bool>`.
  This retains the old serializer's error behavior even behind an otherwise
  decisive mismatch. Neither record is validated conditionally on equality.
- Valid paths compare `as_os_str()` values. No `Path`/`PathBuf` component
  comparison, lossy conversion, filesystem lookup, canonicalization, slash/dot
  removal or Unicode normalization is introduced. Embedded NUL remains a valid
  serialized string value for this comparison, without becoming a filesystem
  operation.
- The explicit vector-length comparison and ordered `zip`/`all` comparison
  preserve empty vectors, order, positions and duplicates. Every outer scalar,
  exit scalar, enum and optional string participates without normalization.
- No cache, stored receipt, freshness waiver, fallback, authority construction,
  descriptor getter, mutation or new I/O appears. The serializer oracle is
  confined to `cfg(test)`.

The equivalence argument was checked against the actual current types in
`crates/vprouter-core/src/allocation.rs:29-50` and `config.rs:42-47`, rather than
assuming derived equality matches serialization. The records derive ordinary
`Serialize`; their non-path leaves are `u32`, `u64`, `String`, the two distinctly
serialized snake_case `ExitMode` variants, and `Option<String>`. Their fixed
JSON representations are injective: unsigned values remain distinct, string
escaping preserves exact string contents, and `None`/`Some("")`/other strings
remain distinct. Ordinary fixed struct fields and ordered vectors preserve the
remaining structure.

`Cargo.lock` pins `serde_core` 1.0.228 and `serde_json` 1.0.150. The exact registry
source `serde_core-1.0.228/src/ser/impls.rs:908-928` was read: `Path` calls
`to_str`, errors on invalid UTF-8, and `PathBuf` delegates to `Path`. The locked
JSON serializer's integer/string/unit-variant/Option/sequence/struct and `to_vec`
implementations were also inspected. There is no other fallible custom leaf
serializer in these current records. Thus checking all paths first preserves
the old A-then-B error order, and exact typed comparisons preserve its successful
JSON-byte equality result for the current schema and serializer. This argument
does not extend automatically to future custom serialization or changed Serde
attributes; such changes still require review despite exhaustive field patterns.

## Preservation assessment

Fresh read-only Python checks independently compared the before/after snapshot
maps and all current application Rust paths: 179 paths, exactly `owned.rs`
changed, all 178 unowned paths unchanged, and no added or removed Rust path.
Every current path hash matched `rust-after.json`. All 14 entries in the retained
`artifact-hashes.json` matched the files read during review.

The saved original bytes matched `git show ef7a085:crates/vprouter-launch/src/owned.rs`.
Recomputing the unified diff from original/current bytes exactly reproduced the
frozen `source.diff`. Independently removing only the new import, comparator/
helper replacement and inserted test block reconstructed the complete original
`owned.rs` byte-for-byte. This corroborates `source-preserved.json` directly.

Accordingly, every other production statement remains unchanged, including all
five production comparator call sites, existing allocation validation, live
ownership checks, canonical serialization/digests, nested diagnostic timers,
clocks, original deadlines, held polls, negative checks, queues and error mapping.
Representative surrounding call-site code was also read. No production,
identity, credential, retry-repair or unrelated-service change is present in
this frozen source diff.

## Quality and retained verification

The implementation is private, allocation-free at the comparison layer and
small enough to audit directly. The explicit UTF-8 pass explains why a tempting
early scalar return would be incorrect, and the exact-path comment explains why
derived path equality is unsuitable. No maintainability or correctness issue
requires revision for the requested scope.

All four new tests and their old-body serializer oracle were read. The oracle
uses the real launch `Result<bool>` and error type, with independent expected
results before comparing the new helper. Counting the loop expansions gives 80
input pairs: 31 scalar/Option cases, seven vector cases, 27 path/string cases,
and 15 invalid-path cases. Coverage includes every current field independently,
both modes, unsigned boundaries, optional empty strings, ordering/duplicates/
length, exact separator spellings, Unicode/decomposed Unicode, NUL/control
strings, and malformed paths in either side, both sides and late entries behind
scalar, length and entry mismatches in both argument orientations.

The retained logs were inspected and hash-verified, without rerunning the same
checks:

| Retained check | Observed log result |
| --- | --- |
| Focused allocation comparison | Four passed, zero failed |
| Complete launch library | 156 passed, zero failed |
| Strict launch lib/tests Clippy | Completed without warnings |
| Focused `rustfmt --check` | Empty retained output, consistent with reported exit0 |
| Deliberate `Path` equality mutation | Expected differential failure: `Ok(true)` vs `Ok(false)`, exit101 recorded |
| Deliberate missing UTF-8 precheck mutation | Expected differential failure: `Ok(false)` vs `Err(OwnershipMismatch)`, exit101 recorded |

The original characterization failure remains available: the expected-result
assertion failed for an incorrect Direct/None fixture assumption, followed by
the corrected four-test pass before the production replacement. Neither that
failure nor the two deliberate mutation failures is hidden or relabeled. Final
source hashes show the reviewed source contains neither mutation. Existing
tests remain byte-identical outside the inserted block.

## Verification limits and acceptance boundary

This reviewer ran only read-only identity/hash/source/preservation checks and
wrote this review file. No tests, lint checks, builds, native attempts, VM,
SSH, Docker or privileged operations were rerun; no application source, Git,
build manifest, resource, credential or service was mutated. Retained command
logs support the reported local results, but are not fresh executions by this
reviewer. Root's concurrent fresh workspace/Clippy checks and subsequent
coherent builds are outside this source review and must carry their own evidence.

The separate experiment report was read. Its offline host timings demonstrate
the pure mechanism of removing temporary JSON buffers; they do not measure this
comparator's share of native retained validation, actual native savings or
sufficient time within the original two-second window. No such conclusion
follows from timer-entry counts or overlapping inclusive diagnostic rows.

Original native cases398-404 remain FAIL, including404 with zero completed cases.
Complete Bootstrap/task8c, real-client, migration, platform, benchmark, runtime
and release gates remain open/NOT_RUN where previously unaccepted. Local-only
testing, Root-only VM actions, preservation of production/identities/credentials,
and the mandatory acceptance gates remain binding. This PASS covers the reviewed
source reasoning within the existing workflow; it is not an acceptance or
deployment claim.
