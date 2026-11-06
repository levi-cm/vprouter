# Task 15 — credential-free acceptance scaffolding

Current status: see **Review round 1** below for the bb02656 review fixes and
latest validation. Earlier sections retain the original implementation history.

Scope: PREPARATION ONLY. No subagents, network, sudo, VM, host execution,
credentials, Rust edits or Git writes. Task 8c runtime/client acceptance is OPEN.
No acceptance evidence exists. `release_ready` remains false.

Baseline: branch rust/v2, HEAD cb91c79855fb1482e61f3becef6f8b71495e049e.
Read-only acceptance.json SHA256:
`3d467451dd03d1663e3c79b24eea6a18aac461f9291f8fdfe1031e1da6e86e97`.
Concurrent Task 14 owns tools/performance, performance docs and task-14 files;
none will be touched here. Owned new paths: tools/acceptance/**,
docs/rust-v2/acceptance-*.md, this report.

Read: full task-15 brief, IMPLEMENTATION (including mandatory acceptance and local
amendment), acceptance.json, security-evidence-map, both testing-*.md documents.
Prior Tasks 9–14 classes: close whole classes with strict parsing, exact arithmetic,
bounded data, monotonic windows, immutable binding, exclusive durable publication,
rule completeness and generic evidence perturbation; synthetic proof never upgrades
runtime claims. Baseline has 284 fault cells, 11 other gates and two global capture
gates; coverage adds traffic and boot-capture scenario rows explicitly.

## Design and files

Implemented below: acceptance.py (pure deterministic validation/status functions and bounded
local-file CLI); test_acceptance.py (behavioral REDs, mutation/property/redaction/
publication tests); evidence-schema.json; canary-plan.json; synthetic fixtures;
acceptance-scaffolding.md. No packet parser or capture execution is planned.

Synthetic oracle PASS will be explicitly separate from acceptance status;
synthetic evidence can never satisfy real-client gates. Manifest binds every
payload byte and scenario/configuration/candidate/ledger/source context. No report
copies untrusted input or filesystem paths. Plan checker never executes commands.

## Rule registry

R01–R26 are implemented and exported in tools/acceptance/invariant-registry.json.
Each entry names enforcement and a behavioral mutation test; the completeness
test resolves every entry and checks unique rule IDs. The full registry follows.

| Rule | Invariant | Enforcement | Mutation test |
|---|---|---|---|
| R01 | Duplicate keys never overwrite a prior verdict | `strict_load` | `BehavioralRed.test_duplicate_keys_cannot_be_silently_overwritten` |
| R02 | Exact bounded integers and strict encoding only | `strict_load` | `Contracts.test_strict_json_rejects_ambiguous_and_unbounded_numbers` |
| R03 | Mandatory matrix and local scope are complete | `load_ledger` | `Contracts.test_ledger_is_exact_and_never_trusts_recorded_pass` |
| R04 | Closed evidence fields and no bool integer aliases | `assess_bundle` | `Contracts.test_closed_evidence_schema_rejects_unknown_fields_and_type_aliases` |
| R05 | Missing or unknown evidence blocks claims | `resolve_status` | `BehavioralRed.test_unbound_pass_is_unverified` |
| R06 | Skipped or unknown status never passes | `resolve_status` | `BehavioralRed.test_unknown_or_skip_is_unverified` |
| R07 | Synthetic evidence cannot satisfy acceptance | `resolve_status` | `Contracts.test_complete_fixture_passes_only_synthetic_oracle` |
| R08 | Positive controls and point exit protocol coverage required | `validate_captures` | `Contracts.test_positive_controls_and_every_point_exit_protocol_are_required` |
| R09 | Any forbidden plaintext cross exit or host Mullvad egress fails | `scan_violations` | `Contracts.test_forbidden_marker_or_host_egress_is_fail_even_with_broken_bundle` |
| R10 | One monotonic epoch and capture ready before traffic | `validate_captures` | `Contracts.test_capture_windows_require_one_monotonic_epoch_and_strict_start_order` |
| R11 | External candidate ledger scenario and bundle hash binding | `validate_context` | `Contracts.test_context_and_manifest_cannot_be_rebound_or_reused_for_another_scenario` |
| R12 | Every immutable payload byte is bound | `validate_manifest` | `Contracts.test_each_leaf_missing_unknown_or_mutated_cannot_pass` |
| R13 | Reports never copy arbitrary secret identity or address data | `report_bytes` | `Contracts.test_redaction_fuzz_never_echoes_secrets_identity_addresses_or_paths` |
| R14 | Failures are retained and observations cannot overwrite rows | `build_ledger` | `Contracts.test_fail_is_preserved_and_bad_observations_cannot_upgrade_the_ledger` |
| R15 | Plan never executes and every prerequisite is required | `preflight` | `Contracts.test_plan_never_runs_and_all_prerequisites_are_required` |
| R16 | Output deterministic without host metadata | `build_ledger` | `Contracts.test_reports_are_deterministic_and_have_no_host_metadata` |
| R17 | Atomic exclusive read only hash named output | `publish` | `Publication.test_publication_is_exclusive_readonly_and_hash_named` |
| R18 | No symlink traversal or unsafe publication directory | `open_directory` | `Publication.test_symlink_and_unsafe_directory_refusal` |
| R19 | Competing publishers never overwrite | `rename_exclusive` | `Publication.test_parallel_publishers_cannot_overwrite_each_other` |
| R20 | File and directory fsync failures cannot claim durability | `publish` | `Publication.test_fsync_failure_cleans_temps_and_preserves_visible_publication` |
| R21 | Bounded stable regular input with no special files | `read_input` | `Publication.test_read_input_refuses_symlinks_special_and_oversized_files` |
| R22 | A colliding temp belongs to another invocation | `publish` | `PublicationRaces.test_colliding_temporary_symlink_is_never_deleted` |
| R23 | Late destination creation preserves existing bytes | `rename_exclusive` | `PublicationRaces.test_late_destination_race_preserves_existing_bytes` |
| R24 | Parent pathname replacement cannot redirect pinned output | `publish` | `PublicationRaces.test_parent_replacement_cannot_redirect_pinned_publication` |
| R25 | Known leak evidence takes priority over malformed unrelated metadata | `scan_violations` | `AdditionalRefusals.test_reported_host_egress_is_not_hidden_by_invalid_other_metadata` |
| R26 | Execution boundary result ownership and selected mode must match | `validate_execution` | `AdditionalRefusals.test_execution_result_and_capture_mode_cannot_be_forged` |

## Test inventory / commands / exit codes

Behavioral RED and subsequent GREEN observations are recorded below; final suite
is 37 tests, including 771 negative cases over 257 bundle leaves and independent
external-binding perturbations. All tests are synthetic/offline.

## NOT_RUN

- All real-client/provider/capture/fault/migration acceptance: no credentials,
  disposable clients, local guests or canary deployments; Task 8c OPEN.
- debdev primary migration and separate local compatibility-deployment migration:
  no preserved-identity hosts/adapters; preparation is not authority to activate.
- 24h mixed soak: no prerequisites and explicitly short offline runs only.
- Supported-platform runtime, performance, independent whole-branch release review:
  outside this scaffold's scope; no release or no-leak claim.

## Open risks

Offline summaries do not establish packet-capture fidelity or producer honesty.
Hash binding proves byte integrity, not trusted acquisition or runtime acceptance.
Future controller and independently reviewed real-client producers are required.

Final validation is recorded at the end of this report.

### RED-1 (before implementation)

Command: `python3 -B -I -m unittest discover -s tools/acceptance -p test_acceptance.py`
Exit **1**, five behavioral assertion failures (not import errors): duplicate
keys accepted, empty evidence passed, unbound PASS retained, SKIP retained, host
IP Mullvad egress passed. Skeleton intentionally lacked enforcement. These are
recorded RED observations, not acceptance results.

### GREEN-1 and broader suite

Initial 24-test run: exit 1, 23 passed; one test-helper error discovered: resealing
replaced the manifest containing the injected unknown field. Corrected the test
so unknown manifest fields reach the actual validator. Also removed an unnecessary
caller ledger-digest override: actual input bytes always determine its binding.
Second run: exit 1, 23 passed and one helper error: attempted to hash a
float through the strict canonicalizer, which correctly refused it. Corrected
that test to send invalid numeric types directly to the bundle validator.
Fresh GREEN result recorded below after execution.

Implemented R01–R21 registry in acceptance.py, named enforcement plus mutation
test for every rule, with registry completeness test. Generic perturbation walks
every bundle leaf and tests deletion, null and mutation against its external hash.
Semantic tests reseal mutated payloads to exercise controls, all exits/points/
protocols, counters, source binding and monotonic boundaries, not just digests.
Atomic output is Linux renameat2(RENAME_NOREPLACE), pinned directory FDs,
private 0700 directory, exclusive temp, readonly 0400 file, file fsync, rename,
directory fsync. No overwrite-capable fallback. Directory-fsync failure retains
visible bytes and reports unknown durability; it never deletes published evidence.

### Fresh GREEN and RED-2 preservation regression

24-test suite GREEN: exit 0, 24 passed, 0.648s.
Added late-destination, pinned-parent replacement and temporary-symlink collision
behavioral tests. Exit **1**, 26 passed / 1 expected regression FAIL: cleanup
removed a pre-existing temporary symlink after O_EXCL refused it. Fixed by
tracking successful creation separately; no failed-create path may unlink a name.
Added registry R22–R24 for these classes. Fresh same unittest command: exit 0,
**27 passed**, 0.7s-class bounded run. The symlink and its target remain intact.

### RED-3 / GREEN-3 leak precedence

32-test run: exit **1**, 31 passed; new behavioral regression showed malformed
unrelated metadata changed a known host-as-Mullvad leak from FAIL to UNVERIFIED.
Moved the bounded, nonrecursive reported-leak scan before structural validation;
its explicit iteration budget prevents unbounded direct-Python traversal. Added
R25 leak precedence and R26 execution/boundary/ownership/mode consistency.
Fresh unittest command: exit 0, **32 passed**, 0.706s.

## Implemented files and design

- tools/acceptance/acceptance.py: strict ledger, synthetic source summaries,
  independent context/manifest verification, status engine, no execution plan
  preflight, redacted reports and pinned exclusive durable publication.
- tools/acceptance/test_acceptance.py: currently 32 offline behavioral tests.
- tools/acceptance/evidence-schema.json: closed Draft 2020-12 structural schema;
  exact parsing and cross-field semantic enforcement stay in Python.
- tools/acceptance/fixtures/{one_mullvad,five_mullvad,one_direct,
  five_mullvad_one_direct}.{bundle,expected}.json: deterministic synthetic marker
  records and separate external bindings; no packets, provider data or real IPs.
- tools/acceptance/canary-plan.json and prerequisites-not-run.json: fixed local-only
  preserved-identity plan with exact argv templates, NOT_RUN declarations and
  explicit unimplemented controller/apply/rollback interfaces; no executor.
- tools/acceptance/security-test-map.json: 12 source-map rows, all nine fault groups
  and all 11 global gates, source hash binding; every runtime result NOT_RUN.
- tools/acceptance/invariant-registry.json: machine-readable export of R01–R26.
- docs/rust-v2/acceptance-scaffolding.md: commands, status boundaries, schema,
  integrity/redaction/custody model, local canary prerequisites and remaining work.

No real-acceptance PASS path is implemented. A structurally complete, exact,
externally bound synthetic bundle can yield oracle_status=PASS but always
acceptance_status=UNVERIFIED. Source PASS alone is never trusted; FAIL is retained.
All 339 rows initially remain NOT_RUN. Published bytes are hash named and 0400;
hashes establish integrity, not acquisition authenticity or filesystem WORM.

## Additional observed command results

- `python3 -B -I tools/acceptance/acceptance.py check --input tools/acceptance/fixtures/one_mullvad.bundle.json --expected tools/acceptance/fixtures/one_mullvad.expected.json`:
  exit 0, oracle PASS, acceptance UNVERIFIED, release_ready false (synthetic only).
- `python3 -B -I tools/acceptance/acceptance.py preflight --plan tools/acceptance/canary-plan.json --declarations tools/acceptance/prerequisites-not-run.json`:
  exit **2**, preflight BLOCKED, status NOT_RUN, 21 exact missing prerequisite IDs,
  execution_supported false. This is an intentional refusal, not a failed host run.
- `python3 -B -I tools/acceptance/acceptance.py rules > tools/acceptance/invariant-registry.json`:
  exit 0; generated controlled registry export only.


## Final validation

All task work is PREPARATION ONLY. No acceptance evidence, no protected-client or
no-leak claim. No subagents or external work, capture, network, sudo, privileges,
VM, service, identity, enrollment, Rust or Git stage/commit/push operation occurred.

| Command | Exit | Observed result |
|---|---|---|
| `python3 -B -I -m unittest discover -s tools/acceptance -p 'test_*.py'` | 0 | **37 passed**, 0.767s final suite run. Includes CLI, schema-subset cross-checks, all four configurations, 26 registry entries, 771 bundle-leaf negatives, binding perturbations, redaction fuzz and filesystem races/fsync errors. |
| AST + JSON + owned-file whitespace command below | 0 | Both Python files parse; all 13 JSON files parse; newline/trailing-space checks pass. Separate strict-load pass also passed all 13 JSON files; no bytecode directories created. |
| `git diff --check -- tools/acceptance docs/rust-v2/acceptance-scaffolding.md .superpowers/sdd/rust-v2/task-15-report.md` | 0 | No tracked diff whitespace issue; the explicit owned-file check also covers untracked new files. |
| `sha256sum docs/rust-v2/acceptance.json` | 0 | Unchanged `3d467451dd03d1663e3c79b24eea6a18aac461f9291f8fdfe1031e1da6e86e97`. |
| `git rev-parse HEAD` | 0 | Unchanged `cb91c79855fb1482e61f3becef6f8b71495e049e`. |

Exact syntax/JSON/whitespace command:

```sh
python3 -B -I - <<'PY'
import ast
import json
from pathlib import Path
for path in sorted(Path('tools/acceptance').glob('*.py')):
    ast.parse(path.read_bytes(), filename=path.name)
for path in sorted(Path('tools/acceptance').rglob('*.json')):
    json.loads(path.read_text(encoding='utf-8'))
paths = list(Path('tools/acceptance').rglob('*')) + [Path('docs/rust-v2/acceptance-scaffolding.md'), Path('.superpowers/sdd/rust-v2/task-15-report.md')]
for path in paths:
    if path.is_file():
        raw = path.read_bytes()
        assert raw.endswith(b'\n'), path.name
        assert all(line.rstrip(b' \t') == line for line in raw.splitlines()), path.name
print('AST, JSON and owned-file whitespace checks PASS')
PY
```

A report-generation shell heredoc initially ended at its embedded example marker
and returned exit 1 before writing the report. Corrected using a distinct quoted
outer delimiter; this was a reporting-command error, not a product syntax failure.

Enumeration result: 339 NOT_RUN, zero PASS/FAIL/UNVERIFIED rows before any supplied
observations; mandatory_acceptance remains UNVERIFIED and release_ready false.
The oracle-only sample check remains PASS/UNVERIFIED, never release acceptance.

Remaining NOT_RUN: every real-client/capture/fault/provider/client-guard gate,
both local preserved-identity migrations, supported-platform lifecycle checks,
benchmark gates, full independent branch release review and 24h mixed soak.
No credentials, canary deployments or guest exist for this task; Task 8c is OPEN.
Full external Draft 2020-12 meta-schema validation is NOT_RUN because jsonschema
is not installed; no dependencies were installed. The authoritative strict Python
validator and independent local declared-schema-subset cross-checks pass.

Residual limitations: synthetic source summaries are not packet observations;
hashes do not prove acquisition or secret-free producer behavior. Future trusted
producers, reviewed host controllers, real credentials/local deployments and full
runtime acceptance are necessary. Publication assumes a cooperative same-UID
operator in a private directory, Linux/glibc renameat2 support, and honest storage
fsync semantics. Failed directory fsync retains visible evidence with no durability
claim. No remote installation acceptance is performed or planned.

## Review round 1

Implementation-fix baseline: rust/v2 @bb026565cd94be2b051f0b7443411c81115b430b.
Full task-15-review.md read; review file and acceptance.json remain read-only.
Scope remains the three owned paths only, offline Python -B -I, no subagents.

### Behavioural RED (before fixes)

Command: `python3 -B -I -m unittest discover -s tools/acceptance -p test_acceptance.py`
Exit **1**, 43 tests, **5 assertion failures**, 1.533s. The five REDs reproduce:

- Actual same-size rewrite after the first real os.read assembled two individually
  invalid bundle versions and the actual CLI returned synthetic oracle PASS.
  No fstat/timestamp mocking or timestamp restoration was used.
- Missing independent container restart, drain, stop, rename and revoked
  identity/control/name rows across all four configurations (28 absent bindings).
- Resealed run-label change passed with unchanged independent run admission absent.
- Published report did not bind the acquired raw input buffer hash.
- No machine-readable spec-phrase requirement table existed.

Expanded every-leaf missing/null/wrong-type/NaN/huge/duplicate-key/cross-scenario
perturbations already pass, extending the earlier three-perturbation sweep.
Identical leaf swaps leave a fully valid bundle and are explicitly allowed only
for synthetic oracle validity; acceptance never passes.

GREEN and remaining custody/run-admission limits will be recorded after fixes.

### GREEN after class fixes

Same unittest command: exit **0**, **45 passed**, 1.818s.
One intermediate GREEN attempt had 44/45 passing: the expanded-row count test
was mistakenly edited to 1615 instead of the hand-counted 1535; corrected the
test expectation. No enforcement was weakened. Before implementation, the added
short-read regression also failed behaviourally (old reader stitched partial reads).
The fstat-change regression was already green on the original implementation.

I1: source-ledger validation preserves all original 71 faults, including the old
combined drain_stop row as historical source data. The supplemental spec inventory
adds independent container restart/drain/stop/rename and revoked identity/control/
name, wrong peer, route drift and Tailscale freeze IDs. Mandatory prose is expanded
phrase by phrase into mandatory-requirements.json; the explicit mapping generator
is build_requirements.py. Every slash item and every listed migration I/O and
lifecycle operation has independently addressable IDs. Apply/resume/rollback and
before/after edges are separate. Artifact/status/scope rows are also supplemental;
none can satisfy real acceptance. The matrix is now **1535 NOT_RUN**, zero PASS,
FAIL or UNVERIFIED rows without observations.

I2: read_snapshot opens with O_NOFOLLOW, obtains shared nonblocking flock, performs
one bounded os.read, refuses short reads and fstat identity/size/time/mode/owner/
link changes, and hashes those exact retained bytes. CLI validation and optional
publication consume only the acquired in-memory bytes; check reports bind raw
input_sha256 and expected_sha256. The race hook does real writes and real reads;
no metadata is fabricated. A second regression replaces the input path content
after acquisition and confirms publication keeps the acquired-buffer hash/verdict.

M1: external expected JSON now requires expected_run with independently supplied
run_id, epoch, not_before_ns and not_after_ns. All capture and traffic windows
must fit that admission, and IDs/epochs match it. Resealing/relabeling alone cannot
change the external admission. Observation inputs must explicitly supply it too.
R27-R29 cover run admission, buffer hash custody and partial/contended reads.
R03/R21 now name the spec inventory and actual mixed-version regression.

Custody limits: producer handoff is explicitly cooperative. Producers must hold
exclusive flock while modifying a handed-off inode, or atomically publish complete
files and leave those inodes unchanged. One read plus metadata equality is not a
kernel atomic-snapshot proof against an arbitrary writer bypassing that protocol.
An external run-admission authority must manage window freshness and one-use
consumption; this offline validator has no wall clock/authentication/replay store.
M2 packet/classifier correctness remains NOT_RUN; byte-identical summary leaves
across scenarios carry no independent packet-origin proof. M3 synthetic content
validity can still say oracle PASS beside row/acceptance UNVERIFIED on SKIP/UNKNOWN.

### Final Review round 1 validation

- `python3 -B -I -m unittest discover -s tools/acceptance -p test_acceptance.py`:
  exit **0**, **46 tests passed**, 2.039s after the last registry change.
  The independent literal inventory covers all 80 expanded semantic faults (plus
  the preserved legacy combined row), all 44 migration operations at both edges
  in all three directions, and every mandatory failure slash item. All applicable
  configuration bindings exist. Schema enums match the full inventory, and the
  formerly missing faults plus a rollback journal-write boundary accept complete
  synthetic fixtures only as oracle PASS / acceptance UNVERIFIED.
- The exact AST/JSON/owned-whitespace Python command in the earlier Final validation
  section was rerun: exit **0**. Now **3 Python files** and **14 JSON files**.
- In-process strict decoder pass over all 14 JSON files, requirement generator
  reproducibility comparison, raw source SHA256 check, row counts, bounded report
  serialization and no-bytecode checks: exit **0**. The complete matrix report
  is 267495 bytes; 1535 NOT_RUN, zero PASS/FAIL/UNVERIFIED source rows.
- `python3 -B -I tools/acceptance/acceptance.py rules > tools/acceptance/invariant-registry.json`:
  exit **0**, controlled export of **R01-R29**; registry completeness and equality
  tests remain green. R12 now names the full seven-perturbation property sweep.
- `python3 -B -I tools/acceptance/acceptance.py check --input tools/acceptance/fixtures/one_mullvad.bundle.json --expected tools/acceptance/fixtures/one_mullvad.expected.json`:
  exit **0**, synthetic oracle PASS, acceptance UNVERIFIED, release_ready false.
  Raw input hash 48cb28b46e425f5a2370b4668e0d321d99d65463d3f882046ad703ae016e7023;
  raw external expected hash 05ced92af5a7cc38cc2b6d07d7e9c05a287c4e6281a2846f7dd2cb4d46609322.
- `git diff --check -- tools/acceptance docs/rust-v2/acceptance-scaffolding.md .superpowers/sdd/rust-v2/task-15-report.md`:
  exit **0**; explicit whitespace check also covers these untracked/ignored files.
- `git diff --exit-code HEAD -- docs/rust-v2/acceptance.json`: exit **0**.
  Its byte hash remains 3d467451dd03d1663e3c79b24eea6a18aac461f9291f8fdfe1031e1da6e86e97.
  `git rev-parse HEAD`: unchanged bb026565cd94be2b051f0b7443411c81115b430b.

Task-touched files: tools/acceptance/acceptance.py, test_acceptance.py,
build_requirements.py, mandatory-requirements.json, evidence-schema.json,
invariant-registry.json, four fixtures/*.expected.json;
docs/rust-v2/acceptance-scaffolding.md and this report. Bundle fixture bytes,
review files, source acceptance.json, Rust and all other paths were not edited.
The table generator is offline, fails on unmapped slash items, and its output was
compared with the checked-in table; source prose line wrapping is whitespace
normalized for that comparison. One initial generator run refused a line-wrapped
slash item until normalization was made explicit; one test normalization assertion
was corrected before its actual missing-scenario RED was observed.

### Open risks after Review round 1

- Cooperative handoff/locking and honest storage remain required. In-memory
  snapshots and exact buffer hashes close the reproduced multi-read assembly,
  not arbitrary concurrent kernel-page mutation by a writer bypassing handoff.
- External run admission binds synthetic freshness but is neither authenticated nor
  consumed here. A real authority must supply fresh independent epochs/windows,
  authenticate producers and prevent reuse; no wall-clock freshness claim.
- The 44-operation migration inventory is derived from the documented contract.
  Actual native writes/generations/files/adapters need per-ordinal kill sweeps by
  a future reviewed producer; no journal/IO runtime acceptance is inferred.
- M2 remains classifier-summary validation only; no packet parser or independent
  cross-exit/host-IP derivation. M3 oracle PASS describes valid synthetic content
  and never upgrades SKIP/UNKNOWN row or acceptance status.
- Real clients/captures/provider faults, both preserved local migrations, lifecycle
  platforms, benchmarks, independent release review and 24h soak remain NOT_RUN.
  External full Draft 2020-12 meta-schema validation remains NOT_RUN; the strict
  validator and independent local schema-subset tests pass. No dependencies added.

No subagents, network, sudo, privileges, VM, Rust, git stage/commit/push or release
activation. Preparation only; no acceptance-PASS path; release_ready remains false.
