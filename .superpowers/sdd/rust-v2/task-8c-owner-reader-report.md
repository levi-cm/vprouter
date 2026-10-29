# Optional closed owner-cost reader extension

2026-10-29. Frozen for Root's independent specification/quality/public-scope review
under task-8c-owner-reader-brief.md SHA256
5014888be5770c229f6877a086e055e65a6d8db564aba780e139f9376157464f.
Only maintained tools/rust-v2-lab/parse-bootstrap-cost-diagnostics.py was edited,
plus this requested report. All check fixtures/scripts/logs/diff evidence are
private under ignored target/task8c-owner-reader-local. No application source,
README/controller/manifest/lock/golden, Git, VM/native/SSH/Docker/privileged,
profile/credential/state/resource action or subagent. Root owns independent
review, staging/push and any separate emitter source/native workflow.

## Closed optional contract

Optional LAB_SECRET_BOOTSTRAP_OWNER_TOTAL markers require exactly15 rows:
query/policy/other families times owner_host_preflight, owner_record_validate,
owner_namespace_identities, owner_current_identity_chain and owner_record_clone
in that precise order. Missing, duplicated, reordered, foreign and unknown rows
cannot satisfy the closed tuple. Every row has exactly family/category/calls/
elapsed_ns/measurement/grouping fields, measurement=inclusive_owner_elapsed and
grouping=lab_loop_entry_step_family. Existing unique-field and canonical bounded
integer readers enforce u64 calls/u128 duration and zero calls imply zero duration.
No owner category is count-only: all15 accept positive duration in normal/max
fixtures. Every occurrence of the marker is parsed strictly, including malformed
bare/tab/leading/embedded/suffixed occurrences, rather than silently looking absent.

Validated rows appear only under optional key owner; owner/nested rows are not
summed. Without rows, owner is absent. Required13 wrapper/30 nested rows, optional
exact24 retained rows and both retained count-only constraints, original bounds/
bindings/clocks/refusals, wrapper-only sum, exclusive output, mode0600 and prior
field spelling/order/formatting are unchanged. All validation precedes output
creation. Removing precisely the added constant, optional parse block and optional
output assignment reconstructs the entire original parser byte-for-byte; no
existing statement was rewritten. The exact diff is retained without Git.

## Test-first and final saved checks

Target-only checks invoke the real parser subprocess, using read-only saved405
and407 records. Expected owner rows use the brief's independent literals without
importing parser constants/helpers. No maintained source edit occurred before
baseline/red evidence was captured.

Command python3 target/task8c-owner-reader-local/checks.py prepare exited0.
Before implementation, actual405/407 outputs already matched historical bytes.
A valid15-row fixture exited0 but omitted owner; a bare-marker fixture exited0
and created output. Both new behavioral expectations failed as intended and were
recorded in red-results.json with captured stdout/stderr.

After the minimal edit, command
python3 target/task8c-owner-reader-local/checks.py verify exited0 with:

- AST parse/compile PASS without running parser main as part of the AST check.
- Actual405 and407 output bytes identical to both before-change outputs and
  historical metadata; successful destinations mode0600.
- Six synthetic successes: normal7calls/11ns, zero0/0 and maximum u64/u128,
  each against405 without retained rows and407 with them. Full output bytes
  equal independent original metadata plus exact fixture hash and15 typed owner
  rows; all prior values and wrapper total remain unchanged.
- 104 malformed refusals, each nonzero and destination absent:62 owner cases,
  19 original-contract checks and all23 prior retained-reader refusals.
- Valid owner input refused an existing output without changing sentinel bytes
  or its original0640 mode.
- All203 reviewed application build inputs hash-identical; source whitespace/
  final newline PASS.

The62 owner refusals cover31 cases against both405 and407: omission, duplicate,
row/family-block order, foreign family/category, retained-category substitution,
unknown/missing/duplicate fields, wrong measurement/grouping, u64/u128 overflow,
negative/leading-zero calls/duration, plus/decimal/hex/empty/overlong numbers,
zero-call positive duration, double-space/tab fields and malformed marker forms.
The19 existing-contract cases cover exit/result/mode/production, closed binding/
count bounds, original clock window/nonfinite/negative/bound, omitted wrapper/
nested row, duplicate JSON keys/nonfinite JSON, empty and larger-than16MiB input.
All23 prior retained refusals include both original count-only constraints.

There are112 named case results plus separate AST/exclusive-output checks.
Historical raw405/raw407, closed outputs and every artifact in the prior
retained-reader hash manifest remain unchanged; no prior evidence was rewritten.
Synthetic owner rows prove parsing only, with no actual owner-inner native data.

## Frozen source and evidence

All local paths below are under target/task8c-owner-reader-local unless stated.
artifact-hashes.json binds345 saved fixtures/outputs/logs/checks/source snapshots,
excluding itself. Every malformed case has stdout/stderr and no destination.
checks.py stays private under target; no test program enters maintained source.

| Artifact | SHA256 |
| --- | --- |
| Maintained parser before | 4309e4881c9aaeb27191ca35957a23f215a9764d37f5afdb00820aafd0518206 |
| Maintained parser after | 4392b39327f3f9c518b5eeb8e0bacbe1eb76d4779e00b45fd2addc84ee6bcd67 |
| source.diff | 1a84e12cb5c8a99b486ca935151ea587369a663eca49724782ea99b30ac04d30 |
| checks.py | 239022ccad52278ca6f20df432d68789e9d11011322dbcfca27d96ae38d5175f |
| red-results.json | ed4615b4df55a08b2c78eab7966e161a08b07e343f96e62e08735042e1f8ad21 |
| verification.json | 3d5876ca2a06665eda52982a22cced9ff1309b36873a8239448a1eb28fa4c814 |
| source-freeze.json | eaf6169f6d26a09a2db16179a35f0a36f5f9f36121c530f4aa1d89eb30a0fcde |
| artifact-hashes.json | 64cad5f250ad17c177510561dfe2144e57c1e787d98088f762b574486ce57d37 |
| ast-check.log | 4fb63b007fa19a9a2ad9d2bb98aa03c8edbc8e33d239e09c2f1a4a498ece992c |
| compatibility.log | dd7aeee22b64900b582ca61ec670901d626714f1165ce8adf5740c31dd634e7f |
| exclusive-output.log | 362c282e573595135741b27aa5b5bcea08a912101a76a2b0114d9623d8206033 |
| Actual405 compatibility output | f743c668eaefc61a3681dbcf94f2c8e269d6d69bb8c8f26f690aa1fe24c039e3 |
| Actual407 compatibility output | 2a61b8c7774c5461c99ac2ed51d73a1200e2492da5bfd283a8ff90d5a33a32ff |

Self-review found no dynamic label/authority, owner/nested sum, new count-only
assumption, silent malformed-marker absence, prevalidation output creation,
old-output drift or unrelated source rewrite. Only the maintained parser and
this report are intended for publication. Public source/diff/report pass bounded
credential-pattern checks; maintained source/report whitespace and final-newline
checks pass. All target fixtures, raw
runtime inputs, local scripts/logs and captures remain private/excluded. Fresh
independent review remains Root's next gate.

## Limits

No actual owner-inner native data, application optimization, CPU/exclusive-cost
attribution, causal native speedup, saved budget, original-two-second fit,
completed Bootstrap or client/runtime/ARM/release acceptance is established.
The separate diagnostic/emitter source is outside this implementation scope and
requires its own authorization/review/binding. Original407FAIL/zero cases and
all earlier failures/acceptance boundaries remain. Root owns subsequent source
checkpoint/publication and any separately authorized native experiment.
