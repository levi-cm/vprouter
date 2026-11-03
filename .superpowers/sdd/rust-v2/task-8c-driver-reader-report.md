# Optional closed driver diagnostic reader

2026-10-29. Frozen implementation for Root's independent source, quality and
sensitivity review under task-8c-driver-reader-brief.md and the approved
 task-8c-driver-cost-brief.md SHA256
 d7e6584e4f6f25943773b489131a3640ffe1a01900eb0d74c4b661546bba25e6.
Root explicitly dispatched this reader after the plan review. Maintained edits
are limited to tools/rust-v2-lab/parse-bootstrap-cost-diagnostics.py and its README
paragraph, plus this requested report. No application/Rust/controller/manifest/
lock/golden/acceptance, Git, build, native, VM, SSH, Docker, privileged, resource,
private-profile/credential/state or subagent action was performed. All fixtures,
raw records, synthetic rows and check programs remain private under ignored
 target/task8c-driver-reader-local. Root owns checkpoint/push and native use.

## Reader contract

Any occurrence of LAB_SECRET_BOOTSTRAP_DRIVER in stderr activates strict parsing;
malformed prefixes, bare markers and foreign table names cannot look absent.
Exactly15 rows are required in their relative order:13 CPU rows in the existing
helper order, then sleep and constructor. Every row must have the exact ordered
fields and fixed measurement/grouping literals from the approved brief, one
separating ASCII space, canonical bounded unsigned decimal values and newline.
CR, alternate line separators, missing final newline, malformed/duplicate/extra/
missing/reordered fields, foreign helpers and partial/duplicate/reordered tables
are refused before output creation.

CPU counts are u64 and cpu_ns is u128. Calls match the corresponding old wrapper
calls; saturating(samples + sample_errors) equals calls. Without a valid sample,
cpu_ns must be zero; a valid zero sample remains accepted. Sleep calls are u64,
requested_ns and elapsed_ns u128. Before call saturation, requested_ns equals
calls times1,000,000; at u64max calls the independently accumulated request may
be at least that product. Zero calls require zero elapsed. No elapsed/requested
threshold is imposed. Constructor samples/sample_errors are each0/1 with sum<=1;
its u128 elapsed_ns is zero without a valid sample. Missing, failed, valid-zero
and positive constructor observations remain distinguishable.

Only a complete valid extension appends driver_cpu, driver_sleep,
driver_constructor and fixed driver_scope keys, in that order. The original scope
string, required13 wrappers/30 nested rows, optional24 retained/15 owner rows,
count-only retained constraints, wrapper-only sum, existing binding/clock/refusal
checks and exclusive output/mode0600 logic remain untouched. Removing the two
new parser blocks reconstructs the complete original parser byte-for-byte.
Absent-extension output bytes are unchanged, including serialization/key order.
The exact two-file diff is saved without Git.

The fixed scope explains that CPU brackets the parent thread, includes observer
work, excludes children and cannot identify scheduling. CPU/wall attribution is
limited to complete unsaturated helper rows: samples=calls, sample_errors=0,
all counts below u64max and CPU/wall totals below u128max. Incomplete/saturated
rows remain unattributable. CPU and wall spans differ; clocks, observer effects,
sampling failures and original constructor scalar precision limit inference.
The reader neither clamps CPU to wall nor calculates off-CPU/exclusive sums or
fit. Independent literal maximum-row construction confirms3761 added bytes and
266 bytes for the longest row, including newlines; no timing bound follows.

## Behavioral checks and retained failures

Private checks invoke the real maintained parser as a subprocess. Expectations
use independent brief literals and saved historical metadata, never reader
constants/helpers. Commands and each case's stdout/stderr are retained locally.

- `python3 target/task8c-driver-reader-local/checks.py prepare`: exit0. Existing
 405/407/408 output bytes already matched their saved closed metadata. Three new
 expectations failed as intended against the frozen old parser: a complete
 extension omitted driver keys, a bare CPU marker was silently ignored and an
 incomplete CPU sample count was silently ignored. Each old invocation exited0
 and created output; red-results.json records these expected feature failures.
- `python3 target/task8c-driver-reader-local/checks.py verify`: final exit0.
 AST parse/compile PASS without running main through the AST check; all three
 historical outputs equal both before-change and retained metadata bytes;
45 synthetic successful outputs equal independently expected complete bytes and
 have mode0600;513 new driver refusals and104 prior-contract refusals exit nonzero
 with no destination; exclusive existing destination keeps exact sentinel bytes
 and original0640 mode;203 application inputs retain their original hashes;
 fresh scoped input inventory has zero new/missing paths; retained prior evidence
 remains hash-identical.
- `python3 target/task8c-driver-reader-local/supplemental-checks.py`: exit0.
 Three exact-at-u64max requested-sleep fixtures succeed;21 additional malformed
 cases are refused without output; independent byte-bound calculations PASS.

Totals are48 successful synthetic cases and638 malformed refusals, plus three
historical byte-compatibility checks, AST, exclusive-destination, source/input
freeze and bound checks. No malformed input was accepted as PASS.

Each of the15 successful scenarios runs against405 without optional old tables,
407 with retained rows and408 with retained+owner rows: complete samples with
CPU greater than wall, zero CPU, zero calls, unavailable samples, mixed valid/
error samples, saturated counts/CPU/wall, CPU-only saturation, wall saturation,
saturated requested sleep above the exact product, maximum accumulated requested
sleep, zero sleep, and missing/error/zero/maximum constructor prefix. The separate
three successes cover exact requested sleep at u64max. Positive-call zero sleep
elapsed is accepted, proving no elapsed/requested floor; no timing claim follows.

New refusals cover each missing row, lone tables, duplicate CPU/sleep/constructor,
reordered/interleaved tables, foreign helper/table/measurement/grouping, closed
field order/duplicates/omissions/extras, and every numeric field with negative,
leading-zero, plus, decimal, nonfinite, infinity, empty, overflowing and overlong
values. They also cover CPU count incompleteness/excess/cross-wrapper mismatch,
unavailable positive CPU duration, under/over requested sleep before saturation,
under requested sleep at saturation, zero-call positive sleep duration,
constructor two attempts/unavailable or error positive duration, malformed bare/
tab/leading/embedded/suffixed/double-space/CR/alternate-separator/NUL markers and
missing final newline. Supplemental fixtures also omit prior required/optional
rows while a valid driver extension is present. Prior104 refusals retain62 owner,
23 retained and19 original-contract checks, including both count-only constraints,
input bounds, closed bindings, duplicate/nonfinite JSON and original clocks.

The first verify attempt passed its behavioral cases and then failed a private
fresh-inventory assertion: that discovery rule omitted14 existing non-Rust
manifest/fixture/example/toolchain inputs from the frozen203. This was a check
policy error, not a changed/missing application file or parser failure. The first
attempt's complete per-case logs remain in after-inventory-check-failed/ and the
observed assertion is recorded in inventory-first-failure.log. The private rule
was corrected, without a parser edit, and the full verify command then exited0.
No failed evidence was erased or relabeled as a passing invocation.

## Frozen evidence

All artifact paths below are relative to target/task8c-driver-reader-local
unless explicitly maintained source. artifact-hashes.json binds3481 private
files, including fixtures, exact expected/actual outputs, stdout/stderr for both
verification attempts, source/README snapshots, diff, all scripts and check logs.
It excludes itself and this external report to avoid self-reference. The report
is separately hash-frozen for Root. No target/raw evidence should be published.

| Artifact | SHA256 |
| --- | --- |
| Maintained parser before |4392b39327f3f9c518b5eeb8e0bacbe1eb76d4779e00b45fd2addc84ee6bcd67|
| Maintained parser after |c832da6a9ea287791bc5d8391be8305846611a99422dabf63cd12e51a3f5669f|
| Maintained README before |cc0c77244c491c1512a939a539c9cf3f7ebafd1871fcff257f1e0d3068fbc72e|
| Maintained README after |db28ffcf1efa043051ad823fc561c563856b7174965f74cad302627135c6122b|
| source.diff |e68af65241d219461eb75097d9641b95246c5facde1a5471ef26d9db2d99fd8a|
| inputs-before.json and inputs-after.json |7debfcbfce9fdeda8fc731f2e83f417a43714b4f65346183847bf0b9ad5dbb05|
| source-freeze.json |f0d5e3f0cd8e50f6c0de941e0288c453f3992b44a47f664308e426880fd412d6|
| checks.py |22c74b901fbf3113cebcf9fd420cceaaee6cde2a372097f7eeb66d2d5aa03dd1|
| supplemental-checks.py |966165aec99836904c63e8b538c2f8396dda9e42781faaa8d9677062bdb0d950|
| red-results.json |e9ba714aeb0ec4af9ea3fc15df4f223434a578552f56ed26f80d1d580bc9cb43|
| verification.json |ea9c22a8f945e8a5ff6547beb6448ee4b42e49f45f6671b7cc41b2313c1860b9|
| supplemental-verification.json |cde65471ca1e65a66886e3215af3f894dd1b2bf77560f065d800e2b85daa5492|
| verification-summary.log |104f17882ada1dcf50ed76d058e52355f9bb8fec5799ae626d68a2474a95d90d|
| inventory-first-failure.log |b440fb608db707da339def9a881847d10292817ec733636fb435529a5781b70a|
| public-scope-check.log |94f754bd537c957c83b578ab3befb59ba9f89a0795e9404f8eb4a238747bb898|
| artifact-hashes.json |f64c572280ea1ab78b5279328586dccc75127e31868db9f4a3ff3f49a938bdfe|
| Historical405 output |f743c668eaefc61a3681dbcf94f2c8e269d6d69bb8c8f26f690aa1fe24c039e3|
| Historical407 output |2a61b8c7774c5461c99ac2ed51d73a1200e2492da5bfd283a8ff90d5a33a32ff|
| Historical408 output |2bdb9551e9950564c2c565aa78b62f6c64b4e4af347e3ab340a9f92a45d13208|

Parser, README and exact diff pass bounded credential-pattern self-checks;
maintained sources retain final newlines and no trailing whitespace. No dynamic
labels, IDs, paths, raw timestamps, records or credentials are added to output.
Self-review found no old-byte drift, early destination creation, CPU<=wall
assumption, off-CPU sum or relaxed old table. Independent source/quality/
sensitivity review remains Root's gate.

## Limits

These synthetic fixtures establish reader behavior only. No actual new CPU,
sleep or constructor-prefix native data exists from this work. No runtime,
clock/filter, architecture, observer-overhead, scheduling, benchmark, Bootstrap,
client, migration, performance or release acceptance is established; these remain
NOT_RUN/unaccepted within this task. Original failed runs and acceptance gates
remain intact. No application-source or runtime mechanism was implemented.
Root alone owns independent review, checkpoint/push and any separately authorized
native work.
