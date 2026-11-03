# Independent driver reader review

Overall verdict: **FAIL — required evidence is unavailable for verification.**
The reviewed parser and README pass source review and the independent local
checks below; no parser correctness or sensitivity defect was found. This
verdict withholds full reader-brief acceptance because the required historical
and pre/post input-freeze evidence is missing from this checkout. It does not
assert that the implementer's claimed checks failed.

Reviewed in `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`, on 2026-11-03.
Scope: the two-file uncommitted diff, reader brief, driver-cost brief's closed
output contract and interpretation rules, and implementer report. The report
was treated as claims, not substituted for evidence.

## Ranked findings

### Important — required retained verification artifacts are unavailable

Location: `.superpowers/sdd/rust-v2/task-8c-driver-reader-report.md:62` and
`:68` (historical checks), `:74` (203-input freeze), against
`.superpowers/sdd/rust-v2/task-8c-driver-reader-brief.md:35` and `:45`.

At review time, `target/` does not exist. Consequently neither
`target/lab-state/actual-program-run-405.json` nor the corresponding 407/408
records, nor `target/task8c-driver-reader-local/` and its manifests/check logs,
can be read. The concrete reproduction is `ls -ld target`, which reports
“No such file or directory”. Historical original-versus-modified comparisons,
comparisons against retained metadata, all203 pre/post input hashes and the
private evidence-hash manifest are **NOT_RUN/unverified**. The three independent
synthetic compatibility comparisons below cannot replace the historical checks
or prove the before-edit freeze. Restore the retained artifacts for read-only
verification before claiming full reader-brief acceptance. No parser input is
implicated by this evidence finding, and no source change is requested.

Critical: none found. Other Important findings: none found. Minor: none found.

## Source and contract checks

- Parser lines196–203 activate on every occurrence of the marker substring in
  stderr, including embedded, bare and foreign-table markers. Exactly15
  marker-bearing rows are required; each must end in LF and contain no CR.
  `splitlines(keepends=True)` exposes alternate line separators, which fail the
  LF requirement. Marker-bearing content cannot silently become absent.
- Lines204–218 require the13 exact helper labels in wrapper order, exact field
  order, fixed measurement/grouping values, canonical u64 counts and u128 CPU
  duration. Calls equal corresponding wrapper calls; Python's unbounded sum
  followed by `min(..., u64max)` correctly validates saturating completeness.
  CPU duration must be zero without a valid sample. Valid zero samples, mixed
  samples and CPU greater than wall are accepted; no CPU<=wall rule exists.
- Lines220–233 enforce exact sleep fields/literals. Requested nanoseconds equal
  calls*1000000 below u64max; at u64max equality and larger u128 accumulated
  requests are accepted, smaller requests refused. Zero calls require zero
  elapsed. No elapsed/requested threshold is introduced.
- Lines235–248 enforce exact constructor fields/literals, unsigned counts with
  sum<=1 (therefore each is0/1), and zero duration without a valid sample.
  Missing, error, valid-zero and positive/max-duration prefixes are accepted.
- Lines261–265 append only the four contracted keys. The fixed scope covers
  parent-thread bracketing, child exclusion, observer work, differing wall
  spans, complete/unsaturated attribution, clock/sample/constructor precision
  limits and no scheduling, off-CPU subtraction, exclusive sum or fit claim.
- `fields()` uses exact ASCII-space splitting and rejects duplicate keys via
  `unique()`. Exact ordered-key/literal checks reject extras, omissions,
  reordered fields, non-ASCII separators and malformed tokens. `integer()`'s
  full ASCII decimal match excludes signs, leading zeros, decimals, Unicode
  digits, nonfinite and overlong text; its bound check admits u64/u128 maxima
  and rejects their successors. The39-digit ceiling accommodates all u128s.
- `driver_sleep` and `driver_constructor` are defined only in the activation
  branch and referenced only under the same unchanged `driver_lines` condition.
  There is no unbound-variable path for an absent extension.
- Removing exactly the block beginning with the new driver comment and the
  later output-append block reconstructs `git show HEAD:...` byte-for-byte.
  Existing validation, scope, serialization/key order and exclusive destination
  logic therefore remain unchanged. Existing scope's historical wording is
  preserved as explicitly required by the reader brief.
- README lines21–35 accurately describe the new reader contract and inference
  limits. The added paragraph contains no IDs, private state paths,
  credentials, IPs, dynamic labels or raw diagnostic payloads. This is a source
  sensitivity review, not an assertion about unprovided private artifacts.

## Exact checks run and results

Scratch scripts and private synthesized records are outside the repository:
`/tmp/task8c-driver-reader-review/`. No implementer test script was reused.

1. Read `git diff -- tools/rust-v2-lab`, both briefs, implementer report and
   numbered parser/README; checked cwd/branch and initial/final Git status.
2. Saved the original parser with
   `git show HEAD:tools/rust-v2-lab/parse-bootstrap-cost-diagnostics.py` to
   `/tmp/task8c-driver-reader-review/original.py`. All parser invocations used
   a fresh exclusive output path in that directory, except the two deliberate
   pre-existing-destination preservation probes.
3. Ran `python3 /tmp/task8c-driver-reader-review/check.py`: PASS,879 subprocess
   cases comprising33 valid complete extensions,840 malformed refusals, and
   six original/current absent-extension executions. Literal helper/category
   lists, schemas, values and expected acceptance were independently specified
   from the briefs rather than imported from parser constants.
4. Ran `python3 /tmp/task8c-driver-reader-review/supplement.py`: PASS. Checked
   all33 successful driver outputs against independently decoded input fields,
   accepted one additional saturated-wall case, and refused five cases for
   missing old wrapper/nested/retained/owner rows or a foreign driver table.
   Total:34 valid-extension cases and845 malformed refusals. Every malformed
   case exited nonzero without creating its destination.
5. Synthetic successful scenarios span old required-only, retained and
   retained+owner layouts: complete CPU greater than wall, mixed/unavailable
   CPU, valid-zero CPU, zero calls, missing/error/zero/max constructor prefix,
   saturated CPU counts/duration, exact and above-product sleep at u64max,
   and maximum u128 requested sleep. Positive sleep calls with zero elapsed
   confirm no elapsed/requested floor. Supplemental saturated wall confirms
   saturated rows remain parseable without an attribution assertion.
6. Refusals cover every missing/duplicated row, each adjacent row swap,
   reordered/unknown/duplicate/missing fields, wrong grouping/measurement,
   foreign helper/table and malformed marker-only/extra occurrences. Every
   numeric field was exercised with negative, plus, leading-zero, decimal,
   nonfinite, empty, overflow, overlong and Unicode-digit values. Spacing,
   tabs, leading text, missing LF, CRLF, vertical-tab and Unicode line endings
   were refused. Additional cases check cross-wrapper calls, incomplete/excess
   samples, unavailable nonzero CPU, invalid sleep products/zero-call elapsed,
   and constructor attempt/duration constraints.
7. Three absent-extension synthetic layouts produced byte-identical output
   from original and modified parsers; historical405/407/408: NOT_RUN because
   the conditional retained-record location is absent.
8. Two existing-destination probes (valid and invalid extension) preserved
   exact sentinel bytes including NUL/newline and original0640 mode. All
   successful outputs in the main suite were mode0600.
9. AST parse and Python compile passed without bytecode files. Direct helper
   checks confirmed integer extrema and duplicate/malformed field refusal.
   Removing the two additions reconstructed original parser bytes exactly.
10. Independent maximum-row construction confirmed3761 added bytes and266
    bytes for the longest row, including LF. `git diff --check --
    tools/rust-v2-lab` passed. Parser, README and driver brief hashes match
    the respective hashes stated in the implementer report.

Local result files: `/tmp/task8c-driver-reader-review/results.json` and
`/tmp/task8c-driver-reader-review/supplement-results.json`; main-case stderr
is retained beside its fixture. The scratch scripts retain the exact fixture
construction and assertions; synthesized raw records are not included here.

Reviewed parser SHA256:
`c832da6a9ea287791bc5d8391be8305846611a99422dabf63cd12e51a3f5669f`.
Reviewed README SHA256:
`db28ffcf1efa043051ad823fc561c563856b7174965f74cad302627135c6122b`.

## Preservation and limits

No tracked file was edited, no Git commit/stash/push, subagent, VM, SSH, Docker,
privileged or application/native action was performed. This review document is
the only repository file created by the reviewer. During review Git status
acquired an unrelated modification to
`crates/vprouter-launch/src/attachment/operational/bootstrap.rs`; it was neither
edited nor investigated by this reviewer. The reviewed parser/README hashes
were verified independently of that concurrent change.

These are Python reader and source checks only. No runtime, timing, CPU clock,
ABI/filter, observer overhead, scheduling, benchmark, Bootstrap, migration,
performance or release acceptance is claimed. Missing retained evidence remains
unverified, rather than being inferred from the implementer's report.
