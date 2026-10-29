# Optional closed retained-cost reader extension

2026-10-29. Frozen for Root's independent specification/quality review under
 task-8c-retained-reader-brief.md. Only the maintained reader
 tools/rust-v2-lab/parse-bootstrap-cost-diagnostics.py was edited. This report is
the requested new Markdown; all local fixtures/logs/diff evidence are ignored
under target/task8c-retained-reader-local. No Rust source, other tool, manifest,
controller, profile/credential, VM/native or resource work was performed; no
subagent or Git mutation. One initial read-only git status inventory occurred;
no further Git command was used for implementation or verification. Root owns
staging/push and the separate diagnostic source/runtime workflow.

## Change and closed contract

The reader now recognizes optional LAB_SECRET_BOOTSTRAP_RETAINED_TOTAL rows.
When present, their ordered family/category tuple must be exactly query, policy,
other times these eight categories: retained_transport, retained_data,
retained_owner_record, retained_history, history_allocation_digest,
created_group_native, source_identity_entries and native_source_entries.
A complete extension therefore has exactly24 rows; missing, duplicate, reordered,
foreign or unknown rows cannot satisfy the tuple check.

Each row has exactly family/category/calls/elapsed_ns/measurement/grouping fields.
Existing unique-field and bounded-integer readers are reused. Measurement must
be inclusive_retained_elapsed and grouping lab_loop_entry_step_family. Calls
are u64, elapsed_ns u128; zero calls require zero elapsed time. The last two
count-only categories require zero elapsed time even with positive calls.
Every occurrence of the marker string is routed through strict row parsing,
so bare/tab/leading/embedded/suffixed malformed markers cannot look absent.
All rows validate before exclusive output creation. No row creates authority.

Validated rows appear only under optional output key retained. They are never
summed. Without new rows, the key is absent and the original output dictionary,
values, order, formatting and success-log behavior are unchanged. Input-size
bounds, duplicate JSON-key handling, original binding/clock checks, exact13
wrapper/30 nested rows, refusals and exclusive0600 output remain unchanged.
The exact diff adds only the closed category constant, optional validation block
and optional output assignment; there is no existing-validation rewrite.

## Test-first evidence and commands

The local bounded checks invoke the real parser subprocess with saved fixtures,
not a source-text mirror or standalone test suite. No new test program was added
to the maintained source tree. A saved original parser copy supplied the baseline.
Before implementation, the valid24-row fixture exited0 but omitted retained;
a bare-marker fixture exited0 and created output. Both new behavior assertions
failed as expected, with red-results.json and their captured stdout/stderr retained.
The unchanged405 baseline already matched saved historical metadata exactly.

After implementation, the complete bounded verification command executed:

- ast.parse and compile on the updated source, without running its main as part
  of the AST check: PASS.
- python3 tools/rust-v2-lab/parse-bootstrap-cost-diagnostics.py
  target/lab-state/actual-program-run-405.json
  target/task8c-retained-reader-local/after/405.json: exit0; exact bytes equal
  original-parser output and existing bootstrap405-closed-metadata.json.
- For each named synthetic fixture, python3 with that same maintained parser,
  target/task8c-retained-reader-local/<case>.json and
  target/task8c-retained-reader-local/after/<case>.json: all26 expectations passed.
- The valid fixture with a preexisting destination: refused without overwriting
  the original bytes. Source whitespace/newline check: PASS.

The three successful synthetic cases are valid, valid_zero and valid_maximums.
Expected typed rows were independently constructed from the brief's fixed labels,
with literal normal/zero/u64-max/u128-max values. Full parsed output equals the
expected original metadata plus the fixture's exact input hash and retained rows;
all other values remain equal. Successful destination mode is0600.

All23 malformed cases exited nonzero without a destination file: duplicate,
foreign_family, foreign_category, reordered, missing, unknown_field, missing_field,
count_only_duration, native_count_only_duration, calls_overflow, elapsed_overflow,
negative_calls, negative_duration, noncanonical_calls, zero_calls_duration,
wrong_measurement, wrong_grouping, duplicate_field, bare_marker, marker_tab,
leading_marker, embedded_marker and marker_suffix. These check observable parser
output/refusal behavior. No malformed fixture was accepted or relabeled PASS.

## Frozen hashes and retained evidence

All following local paths are under target/task8c-retained-reader-local unless
specified otherwise. artifact-hashes.json binds every saved fixture/output/log
and original source copy present at freeze, excluding itself.

| Artifact | SHA256 |
| --- | --- |
| Maintained reader before | 31e70538076ea97538ad4ab09aa8126a74543985e92e6727ad7d0f84d1d3a5d7 |
| Maintained reader after | 4309e4881c9aaeb27191ca35957a23f215a9764d37f5afdb00820aafd0518206 |
| source.diff | e867c4adc340a7f95151ae9c62e81f2ec6fe08272b78ffc2b2070b9436057d8e |
| verification.json | 53a74e674e4d1e6ce2daecd2d80abc1c4e5de5cb729503bd54f22b5285eea27e |
| artifact-hashes.json | 294aacb797d318e3a73d893884295fd9e57c08fa3fd8c65a6165ab2e0f2ea632 |
| red-results.json | aac08e9e8b23c401779aed73de1962cf32872b12470d9a62f908566a976bdb8e |
| expected-retained.json | 1d1c12373915b448b6d62b6e3b237f5b562350db3bf27524dd3e7e38f0a65bed |
| ast-check.log | f38d5156ec5d2ca62c06c2470642bf883b2cce68ed3184e7356dcbab8cffa4c5 |
| 405-compatibility.log | 463790e6513c56dcefca5f418e08d3fcaf4d898eba6b1b44c817ebc66c7125fa |
| exclusive-output.log | 1ffe3feb0aea23e2419fbb5f47609fb2bddb62c8e2761b047b645f6c76faf589 |
| valid.json input | e432abe2929c9392a0dd9f9b663f8411e38e21671b7924137f4941194bd11e61 |
| after/valid.json output | 3eaf474fc27b3a15d2fd63205d74d283455a9779f45358f4a6a0bc8237acf051 |
| after/405.json, original-parser405 and existing saved405 metadata | f743c668eaefc61a3681dbcf94f2c8e269d6d69bb8c8f26f690aa1fe24c039e3 |

The generated unified diff is directly between saved original source bytes and
updated maintained source, without Git mutation. Existing raw405 and historical
closed metadata were only read; no evidence was rewritten. Self-review found no
new dynamic label, authority, retained-row sum, silent malformed-marker absence,
count-only duration allowance, prevalidation output creation or old-output drift.

## Limits

Synthetic rows establish reader acceptance/refusal only; they are not native
retained costs, CPU accounting, profiler-share proof, a source optimization,
saved2s budget or runtime/release acceptance. The proposed Rust diagnostic and
future native experiment require their own independent review/binding. Original
failed attempts and all remaining Bootstrap/client/runtime/release gates remain
unaccepted. Only the maintained parser and this report are intended for Root's
review/publication; ignored fixtures, raw runtime inputs and logs stay excluded.
