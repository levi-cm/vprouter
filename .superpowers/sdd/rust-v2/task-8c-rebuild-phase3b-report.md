# Task 8c rebuild phase 3b implementation report

2026-11-04. Shared checkout `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`.
HEAD remains `6ca0073fb1f58706a670e9d4e333a831ae0d0628`; index remains empty.
All existing phase 3 changes were retained; all new changes are unstaged.

**The reservation-bound fresh-provenance route passes offline and pre-execution
gates. Run 409 is NOT_RUN, with one total attempt still available.** This report
establishes provenance and outcome preservation, not Bootstrap witness/runtime
acceptance, independent review or authorization to execute. `release_ready=false`.

The unfinished `tools/rust-v2-lab/collect-run409-evidence.py` was **replaced**, after
reading and retaining its exact entry bytes. The cancelled attempt also left
unmirrored edits in ignored restored copies of the Bootstrap controller,
quarantine validator, failure inspector and archiver. Those were read, preserved,
then finished/revised here. Entry snapshots/hashes and Git state are in
`target/rebuild-phase3b/continuation-20261104T152211Z/entry.json` and `entry/`.
Previous scratch files `target/rebuild-phase3b/edit.py` and `record-command.py`
remain intact. No historical raw files or flags were manufactured.

No Bootstrap, guest networking/namespace/nft/container mutation, guest lifecycle
action, production/provider credential use, debdev sudo, Git staging/commit/push,
Cargo or subagent occurred. Existing keys, pins, disk, seed, guest identity,
authored baseline/reconciliation/projection/comparison and phase 3 admission
records were not changed. The prior historical-gap disposition still applies.
A memory lookup supplied confinement/preservation context; operational assertions
below were checked in this turn.

## 1. Full path and refusal map

The Bootstrap controller is `target/platform-lab/run-frozen-secret-bootstrap.py`.
Its seven flags are success, postbirth-failure, result-failure,
registration-failure, handoff-fence, handoff-partial and handoff-duplicate.
**Only mode `success` is reserved for fresh run409.** A nonzero outcome of that
mode remains `component_test_mode=secret_bootstrap_success`; it does not become a
fault-injection mode. Every injected fault mode is refused by this reservation
before claim/guest action. These are possible historical controller modes, not
permission for additional fresh experiments.

There is no `target/collect-secret-bootstrap.py` in the restored inventory. The
HOST collector `target/collect-secret-host-addition.py:107` calls
`quarantine_evidence_base.validate_prefix(..., host_addition=True)`. Its mode map
accepts only `secret_host_addition_*`, and its exported witness marker is
`LAB_SECRET_HOST_ADDITION`. Thus a raw Bootstrap record would fail the mode map
**before** reaching the historical declaration check. For HOST records, the old
`validate_baseline_host` required both historical flags true and rejected the
truthful phase 3 reconciliation. Neither problem is solved by renaming a record,
changing its mode or changing those flags. The dedicated fresh collector now
preserves Bootstrap outcomes and validates their actual baseline provenance;
it explicitly leaves full Bootstrap witness validation NOT_RUN.

The controller is sequential; it does not automatically invoke any post-run
collector, failure inspector, parser or selector archiver. The intended external
post-run sequence is as follows. All commands in this section are **NOT_RUN**
against real409, which does not exist.

| Alias | Exact future command and inputs | Reads template/reconciliation; reservation; run; historical fields |
| --- | --- | --- |
| C | `python3 tools/rust-v2-lab/collect-run409-evidence.py target/run409-preserved-initial` | Reads original candidate-local and captured template/reconciliation, hashes, full comparison/projection and admission; active reservation SHA, claim and supersession; fixed409. Requires fresh flags false; never historical reconstruction true. Copies original raw/controller/bound inputs first, then validates. |
| I | `python3 tools/rust-v2-lab/inspect-run409-state.py target/lab-state/run-409-state-inspection.json` | Requires active reservation/claim, candidate-local declaration and comparison; fixed409; if raw exists, validates its bindings. Read-only strict SSH checks admitted boot and captures fixed public selectors, available exact owner/cgroup/gateway identities. Missing early identities stay unavailable; this grants no archival authority. |
| P | `python3 tools/rust-v2-lab/parse-bootstrap-cost-diagnostics.py target/lab-state/actual-program-run-409.json target/lab-state/run-409-cost-diagnostics.json` | Reads raw source binding and closed stderr diagnostics only. No baseline, reconciliation, reservation or historical flags. Input path is explicit, not a numbering scan. Requires exit1/FAIL/success-mode and a complete fixed Deadline diagnostic. |
| F | `python3 target/inspect-secret-bootstrap-failure.py 409 target/candidates/rebuild-20261103T231415Z/bootstrap409-driver-cost/directory-binding.json` | Reads exact run409 and directory binding, captured controller hashes, raw manifest/nonce/host and optional baseline metadata. Fresh-only branch additionally checks captured template/reconciliation, active reservation/claim/comparison and boot. Original public selector/profile metadata, canonical and owner checks remain. No signals, private profile reads or cleanup. |
| A | `python3 target/archive-secret-bootstrap-selectors.py 409 target/candidates/rebuild-20261103T231415Z/bootstrap409-driver-cost/directory-binding.json` | Reads F's exact raw-hash-bound receipt and original run/binding/gateway. Fresh-only branch checks declaration/reservation/claim/boot. Requires owner unit not-found, cgroup absent, original running container PID/start/StartedAt/pidfd/namespace, exact selector inode/hash/size/mode. Links/unlinks only exact inspected public selectors into the same synthetic-input directory and fsyncs. This is a future mutation and was NOT_RUN. |

| Actual controller outcome | Tools in order; stop/skip conditions |
| --- | --- |
| Exit0 with `PASS_PARTIAL_SECRET_BOOTSTRAP`, witness and complete final controller row | C, then I if a live-state snapshot is wanted. Guest fixture itself has already verified host/neighbor preservation, original gateway identity and owner absence, retained resources, and moved its six fixed public selectors into its nonce directory. F/A require failure and must not run for success. P requires failure and is inapplicable. C verifies the actual baseline declaration with the existing structural validator and its new fresh branch; its receipt is preservation evidence, not a complete Bootstrap schema proof. |
| Exit1, Deadline at `native_poll/result` (402–408 pattern) | C → I → P → F when directory-binding and manifest/host rows exist. P retains original two-second boundary and driver diagnostic semantics; F keeps original selectors and canonical metadata. Stop with budget0. A may follow only when its original exact identity/absence gates pass in a later authorized preservation action; F refusal or missing identities cannot authorize A. Keep F/P/A receipts at their exclusive local paths. |
| Other Deadline helper/step with complete closed diagnostic | C → I → P → F under the same availability/gates. P accepts its fixed helper/step lists, not just native_poll/result. No retry. |
| Non-Deadline Rust/constructor/handoff/ownership error; guest assertion; subprocess failure inside the guest; signal; SSH return255; arbitrary nonzero guest exit | C → I; F only with its original binding/manifest/host prerequisites. P is NOT_APPLICABLE unless its exact exit1/Deadline format is present; never rewrite the reason/exit or fabricate rows to feed P. A remains gated by F and its exact live checks. |
| Controller's 250-second guest SSH timeout | Raw record has code124 and captured available stdout/stderr; C → I → F if its inputs exist. P refuses124, so skip it. Timeout/connection loss does not prove the guest owner/child stopped; no retry, cleanup or archive without original gates. |
| Before-guest listing or SCP exception after claim; output snapshot/write error | New exclusive `run-409-controller-error.json` retains exception type, message and available subprocess stdout/stderr. C preserves that, claim, reservation and partial controller files even without raw409 → I. P/F/A require unavailable original raw/binding/identities and must be skipped. |
| Controller interruption/power loss after claim but before raw/error output | C preserves claim and available local files → I once the *same* admitted guest is reachable. No fabricated raw or success/failure result. Missing raw means interrupted/unclassified outcome, with budget0. Host/guest reboot invalidates current-identity inspection and must not be bypassed. |
| Raw saved, but malformed witness JSON, controller-summary generation or final directory-list/binding fails | Raw is exclusive/fsynced before postprocessing. New controller-error receipt preserves that later exception. C works without directory-binding and retains raw before parsing; validation failure is nonzero with an exclusive receipt and captured bytes kept. I can inspect without directory-binding. F/A remain unavailable until their original binding exists; it is not synthesized. |
| Explicit postbirth/result/registration/handoff-fence/handoff-partial/handoff-duplicate controller mode | Historical controller/inspector/archiver mode behavior is retained. The fresh run409 reservation refuses all six modes. No fresh test run is created to exercise them. |
| Pre-execution provenance/source/context/lock/collision refusal | No claim or guest execution; preserve the local refusal. C/I are intentionally post-claim tools and refuse to describe an unconsumed reservation as a run. Repair/review is required, not an automatic run. |

The historical inspectors did not require reconstruction flags; they did not need
those flags relaxed. They did need a narrow *additional* fresh custody check to
avoid accepting an unbound run409 record. F still requires one input manifest and
one public host row, even for early failures; A still requires the owner/gateway
identities. The new I route records early/unavailable state without weakening F/A.
The parser already accepts fresh source-bound raw diagnostics and is unchanged.
Historical raw398–408 replay remains unavailable.

All true import consumers were traced: `collect-secret-quarantine.py`,
`collect-secret-assembly.py`, `collect-secret-producer-binding.py` and
`collect-secret-host-addition.py` share `validate_prefix`; its mode maps and every
other check are unchanged. The HOST collector additionally loads the producer,
assembly, movement, provision, HOST shape/history/native schemas and frozen
selftest mechanics. These do not become Bootstrap collectors. Existing public
and continuation smoke scripts use the unchanged pure validators. Historical
`build-*-partial-index.py` and some smoke dependency lists merely name/hash this
module; they are old publication/synthetic paths, not post409 collection steps.
They were not repurposed or fed invented historical fixtures.

## 2. Implementation and file/line locations

Line references apply identically to restored and archival copies where both are
listed. The archival versions are the tracked review/publication inputs.

- `target/quarantine_evidence_base.py:34` and
  `tools/rust-v2-lab/target/quarantine_evidence_base.py:34`: finish/revise the
  cancelled attempt's fresh validator. Require schema2 active reservation,
  mandatory unique complete binding set, candidate/template/reconciliation hashes,
  admitted boot/namespace, truthful false historical/authority flags, prior refs
  and author-helper hashes. Re-run the original pure projection-envelope checks
  (original PID/start, successful reap, route socket identity, no stderr,
  requested_at+2 deadline, read-only/no authority), validate full shape, recompute
  exact namespace and all four structural multisets including duplicate counts.
  Post-run also requires exact reservation SHA/path, global consumed claim,
  budget0/controller boot, record guest boot, source/artifact/context and all five
  captured controller/helper hash bindings.
- The same two files at `:85` / `:107`: explicit fresh dispatch in
  `validate_baseline_host`; existing metadata, reference, namespace, declaration,
  checksum and size checks remain. Pure historical path retains the **original**
  true-flags assertion. `audit.py` compares ASTs to HEAD and confirms all other
  body checks and three other original validator functions are identical. No
  historical flags in the authored phase 3 files were edited.
- `target/platform-lab/run-frozen-secret-bootstrap.py:43` and
  `tools/rust-v2-lab/target/platform-lab/run-frozen-secret-bootstrap.py:43`:
  perform full fresh provenance validation while holding the reservation lock,
  **before** claim. Boot checks precede guest listing and guest script execution
  (`:44`, `:59`); raw409 includes that boot (`:76`). Fresh raw writes use exclusive
  mode0600/fsync; post-claim controller exceptions retain an exclusive public
  diagnostic (`:96`). Historical unreserved behavior is unchanged.
- `target/inspect-secret-bootstrap-failure.py:9` and
  `tools/rust-v2-lab/target/inspect-secret-bootstrap-failure.py:9`: fresh-record
  declaration/reservation/claim check and explicit run409 check; `:59` checks boot
  before original remote inspection. Historical path and original remote checks
  remain.
- `target/archive-secret-bootstrap-selectors.py:8` and
  `tools/rust-v2-lab/target/archive-secret-bootstrap-selectors.py:8`: equivalent
  fresh check; `:46` checks boot before original archival script. Original owner,
  cgroup, pidfd, gateway PID/start/StartedAt/namespace, selector inode/hash/mode/
  size and fsync checks remain; no archival executed.
- `tools/rust-v2-lab/run409-reservation.py:71`: mandatory 24-file execution and
  post-run binding list. `:98` validates the active generation/tombstone and
  retained old SHA, `:113` rejects incomplete/duplicate/drifted bindings,
  `:137` validates before irrevocable claim, `:165` implements audited supersession.
  This replaces the reviewed phase 3 helper in place as implementation source,
  while the **reservation data** itself is retained/replaced, never edited.
- `tools/rust-v2-lab/collect-run409-evidence.py:33`: replaced the unreviewed draft.
  An exclusive0700 local bundle retains exact raw bytes, available controller
  outputs, claim/supersession/error records and bound input sources in0600 files
  before validation. Handles success, failure, timeout and no-raw interruption.
  Failed validation exits1 with retained bytes/receipt (`:110`); checks captured
  baseline declaration whenever its original descriptor/gateway were emitted.
  Explicit `full_bootstrap_witness_validation=NOT_RUN`, `runtime_acceptance=false`
  and `release_ready=false` prevent promotion into runtime acceptance.
- `tools/rust-v2-lab/inspect-run409-state.py:18` / `:55`: new read-only early/full
  state snapshot with active claim/provenance and admitted-boot check, pinned SSH,
  public selector protections and available exact owner/gateway identities. Saves
  failed SSH stdout/stderr as an exclusive local receipt. It never archives,
  signals, enters a namespace, reads profiles, removes resources or authorizes A.
- `tools/rust-v2-lab/test-phase3b-provenance.py:26` / `:83`: new offline suite,
  21 tests including synthetic declarations/envelopes/claim, historical/fresh
  dispatch, mixed/false historical flags, missing/tampered bindings, boot/run/
  budget errors, namespace/full-shape/deadline refusals, preservation on success,
  early/timeout/error/no-raw paths, parser native_poll/result Deadline, spent and
  interrupted supersession. No guest/real fixture execution. Controller-error
  boundary uses a mocked SSH exception and retains a real local diagnostic.
- `tools/rust-v2-lab/test-run409-reservation.py:1` / `:23`: adapt the existing
  disposable fixture to schema2 and add provenance-before-claim and nonreserved
  fault-mode refusal. All original ten cases remain, now12 checks.
- `tools/rust-v2-lab/source-manifest.json:575`, `:1715`, `:1727`, `:1733`:
  exactly the four phase3b restored-controller entries updated with matching
  archive SHA/length. The prior phase3 native-preflight mapping remains unchanged.
  All293 entries match byte-for-byte and by length/SHA.

Unchanged reviewed inputs: `fresh-baseline.py`, `phase3-readonly-preflight.py`,
all authored phase3 candidate/admission/projection/comparison/root-verification
artifacts and the phase3 native-preflight mapping. `parse-bootstrap-cost-diagnostics.py`
is unchanged. Only local evidence/report files, four restored/archive pairs,
the manifest, the reservation helper/test and three new versioned tools/tests
were added/changed. New local evidence scripts are `sync-archives.py`, `audit.py`
and `write-report.py` under `target/rebuild-phase3b/`; ordinary imports can create
ignored Python caches. The public smoke writes its own fresh exclusive local
synthetic receipt, not an actual-program-run record.

## 3. Reservation replacement and one-shot proof

Old reservation SHA256: `3237686154de18668bee6182f24cc405b8c15a2eaa8d8d03e8305b574c1306e4`.
Retained, byte-identical, at:

`target/lab-state/run-409-reservation.superseded-3237686154de18668bee6182f24cc405b8c15a2eaa8d8d03e8305b574c1306e4.json`

New active reservation: `target/lab-state/run-409-reservation.json`.
SHA256: **`e3366fd4b99201f828c4ed844630007d54c7f4fed24515b9b9211d9838e36ff6`**.
It binds 24 inputs including the new collector/inspector, shared
validator, Bootstrap guest/controller/builders, pure projector, unchanged parser,
source manifest, admission, authored declaration, projection and exact comparison.
The original phase3 reservation lacked those new post-run dependencies and is
stale for the changed controller/helper bytes.

`target/lab-state/run-409-supersession.json` records old/new SHA, retained path,
reason, observed UTC, old budget-unconsumed and **total_one_shot_budget=1**.
The protected receipt/tombstone is fsynced **before** moving the old file. The move
uses an exclusive hard link followed by unlink of the old pathname; the preserved
old file ends single-link0600, with its original bytes/inode retained. Replacement
is O_EXCL0600 + file/directory fsync. A crash between these steps fails closed;
there is no reset/retry API and no second supersession without explicit repair.

Every cooperating invocation must use the canonical active path and schema2,
match the tombstone's replacement SHA and retained old SHA, validate all mandatory
bindings, and use the single global `run-409-consumed.json`. Old pathname use,
restoring the old bytes at the active pathname, partial supersession or an already
consumed budget refuse. Lock covers preflight/validation/claim and execution;
O_EXCL claim prevents duplicate consumption even across generations. Provenance
failure happens before claim. The budget is total1, not one attempt per generation.
A malicious/noncooperating launcher or manual deletion of evidence remains outside
this cooperative mechanism; no stronger protection is claimed.

At handoff, claim, raw409, controller-error409 and output label directory are
absent. No actual-program-run files exist in this fresh lab state. Both old and
new reservations are unconsumed; only the active generation is admissible.

## 4. Verification and boundaries

- Reservation checks: **12/12 PASS**, disposable temporary directory only.
- New offline suite: **21 tests PASS**, including actual changed declaration
  dispatch and historical success/refusal, preservation and supersession cases.
  The first RED run exited1 for absent `binding_paths`/`supersede` APIs; retained
  in `offline-red.*`. Intermediate green receipts show9,16,19 and20 tests as
  coverage expanded; final21 is `offline-final.*`.
- Historical public declaration smoke: **26 checks PASS**, no native acceptance.
- Real new-reservation `--preflight-only`: **exit0**, run409/budget1,
  `guest_actions_executed=false`. This checks frozen inputs/source binding,
  artifact/static ELF/context, template/review/prior refs and generated guest
  compilation, then the active reservation plus fresh provenance/custody/full
  multiset checks. It returns before out.mkdir, SSH, SCP or fixture actions.
- Manifest/archival audit: **293/293 PASS**, **593 Python paths compile in
  memory** (586 restored/archive copies +7 tools); original historical validator
  logic retained as described above. **11 optimized-Python refusals**, each
  exit1 with `optimized_python_refused`, before any work. Exact argv/stderr in
  `target/rebuild-phase3b/audit.json`.
- `git diff --check`: **exit0**. HEAD/index unchanged; prior phase3 authored
  inputs and the two unchanged helpers still match their original bound hashes.
- Current guest status: **exit0**, strict confined SSH; QEMU2147340,
  start tick1616810, exact recorded argv and loopback22036.
  Guest boot `e14efc10-050b-41b0-89d8-1e946725098c`;
  controller boot `18f40876-a432-4ad1-9ded-03e0df43559a`.
  Final status UTC is in `handoff-status.command.json`.
- Read-only guest gates: **exit0** (`current-guest-gates.*`): protected lab parents/
  marker, all eight selectors absent, initial HOST namespace, WAN ens2/index2/MAC,
  Docker active, pinned images inspectable, no containers, cgroup2, Seccomp0 and
  successful direct x86 CPU/BOOTTIME clock syscall probes. This is current guest
  context/direct-clock evidence, not a full frozen-driver clock sample.

An **additional legacy smoke failed, exit1**:
`target/smoke-host-projection-controller.py` expects deleted
`target/continuation-20261028T044917Z/candidate.json`. It fails FileNotFoundError
at its old-candidate negative case, with subprocess entrypoints mocked to refuse;
no guest call occurs and no old fixture was created. Its original pure synthetic
projection checks ran before that missing-fixture failure, but the whole smoke
is **not** reported as PASS. New offline projection-envelope custody/deadline
checks and the real current baseline preflight pass independently. Evidence is
`projection-validator-smoke.stderr`.

### NOT_RUN and open risks

- Run409, all six injected modes, real post-run C/I/P/F/A and all guest
  network/namespace/nft/container mutations: **NOT_RUN by instruction**.
- Full typed Bootstrap witness validation, frozen-driver runtime clock sampling,
  ARM64 runtime, provider enrollment/connection, release/soak/client acceptance:
  **NOT_RUN**. The new collector deliberately validates baseline provenance and
  preserves raw outcomes; its success receipt is not a complete Bootstrap
  witness schema oracle. The historical HOST collector still refuses Bootstrap
  modes. A future requirement for independently validated full Bootstrap witness
  acceptance needs a separately reviewed Bootstrap-specific schema/collector;
  it cannot be satisfied by relabeling a HOST record or this preservation receipt.
- Full original historical replay/resource/identity continuity:
  **NOT_RUN/UNRECOVERABLE**, unchanged gap disposition. Reboot/drift stops current
  boot-bound inspection; it does not authorize reusing the reservation.
- Failure archival: **NOT_RUN**; early failures can lack the exact prerequisite
  identities, so automatic archival is intentionally unavailable. Preserve state,
  report unavailable checks and stop. A timeout/connection loss does not establish
  owner/child death. A power loss may leave no complete raw/error record; claim
  still spends the attempt and preservation labels it interrupted, never retried.
- Independent review/checkpoint/publication: **NOT_RUN**, orchestrator work.
  No subagents or Git writes were authorized. Review the new helpers, restored
  diff/archive/manifest, truthful baseline, tombstone and exact execution path.
  Pre-execution proof is not execution authorization or an outcome guarantee.

## 5. Exact command receipts

Commands below ran from the shared checkout through
`python3 target/rebuild-phase3b/record-command.py LABEL COMMAND...`.
Each named `.command.json` contains exact argv/exit/UTC/duration and paths to full
stdout/stderr. Tool output truncation does not truncate these retained receipts.
Read-only discovery commands and successful setup/edit snippets are reflected in
entry/source evidence; no unreported runtime run was performed.

| Receipt | Exact command | Exit |
| --- | --- | ---: |
| `offline-red` | `python3 tools/rust-v2-lab/test-phase3b-provenance.py` | 1 |
| `offline-green1` | `python3 tools/rust-v2-lab/test-phase3b-provenance.py` | 0 |
| `offline-green2` | `python3 tools/rust-v2-lab/test-phase3b-provenance.py` | 0 |
| `reservation-tests1` | `python3 tools/rust-v2-lab/test-run409-reservation.py` | 0 |
| `offline-green3` | `python3 tools/rust-v2-lab/test-phase3b-provenance.py` | 0 |
| `reservation-tests2` | `python3 tools/rust-v2-lab/test-run409-reservation.py` | 0 |
| `current-status` | `python3 tools/rust-v2-lab/lab-guest-status.py` | 0 |
| `current-guest-gates` | `python3 tools/rust-v2-lab/phase3-readonly-preflight.py target/rebuild-phase3b/guest-gates.json` | 0 |
| `offline-green4` | `python3 tools/rust-v2-lab/test-phase3b-provenance.py` | 0 |
| `audit-before-reservation` | `python3 target/rebuild-phase3b/audit.py --before-reservation` | 0 |
| `audit-before-reservation2` | `python3 target/rebuild-phase3b/audit.py --before-reservation` | 0 |
| `offline-final` | `python3 tools/rust-v2-lab/test-phase3b-provenance.py` | 0 |
| `reservation-final` | `python3 tools/rust-v2-lab/test-run409-reservation.py` | 0 |
| `historical-public-smoke` | `python3 target/smoke-quarantine-public-evidence.py` | 0 |
| `projection-validator-smoke` | `python3 target/smoke-host-projection-controller.py` | 1 |
| `supersede409` | `python3 tools/rust-v2-lab/run409-reservation.py supersede --expected-sha256 3237686154de18668bee6182f24cc405b8c15a2eaa8d8d03e8305b574c1306e4 --reason 'Phase 3b fresh-provenance validation, post-run preservation and inspection helpers, controller error capture, and archival manifest bytes replace stale phase 3 bindings; old generation remains unconsumed; one global claim, no run409 execution.'` | 0 |
| `bootstrap-preflight` | `python3 target/platform-lab/run-frozen-secret-bootstrap.py target/candidates/rebuild-20261103T231415Z/candidate.json debian-clean-x86_64 bootstrap409-driver-cost success --reservation target/lab-state/run-409-reservation.json --preflight-only` | 0 |
| `final-audit` | `python3 target/rebuild-phase3b/audit.py` | 0 |
| `diff-check` | `git diff --check` | 0 |
| `handoff-status` | `python3 tools/rust-v2-lab/lab-guest-status.py` | 0 |

`sync-archives.py` was run twice, exit0 each time; it only copies the four named
restored sources to their archival paths and updates those manifest rows. The
report generator is local-only. The optimized refusal subcommands recorded by
the audit are:

- `/usr/bin/python3 -O tools/rust-v2-lab/fresh-baseline.py` — exit1, expected refusal.
- `/usr/bin/python3 -O tools/rust-v2-lab/run409-reservation.py` — exit1, expected refusal.
- `/usr/bin/python3 -O tools/rust-v2-lab/phase3-readonly-preflight.py` — exit1, expected refusal.
- `/usr/bin/python3 -O tools/rust-v2-lab/test-run409-reservation.py` — exit1, expected refusal.
- `/usr/bin/python3 -O tools/rust-v2-lab/test-phase3b-provenance.py` — exit1, expected refusal.
- `/usr/bin/python3 -O tools/rust-v2-lab/collect-run409-evidence.py` — exit1, expected refusal.
- `/usr/bin/python3 -O tools/rust-v2-lab/inspect-run409-state.py` — exit1, expected refusal.
- `/usr/bin/python3 -O target/quarantine_evidence_base.py` — exit1, expected refusal.
- `/usr/bin/python3 -O target/inspect-secret-bootstrap-failure.py` — exit1, expected refusal.
- `/usr/bin/python3 -O target/archive-secret-bootstrap-selectors.py` — exit1, expected refusal.
- `/usr/bin/python3 -O target/platform-lab/run-frozen-secret-bootstrap.py` — exit1, expected refusal.

## 6. Final exact run409 command — recorded only, NOT_RUN

```sh
python3 target/platform-lab/run-frozen-secret-bootstrap.py target/candidates/rebuild-20261103T231415Z/candidate.json debian-clean-x86_64 bootstrap409-driver-cost success --reservation target/lab-state/run-409-reservation.json
```

The same argv with final `--preflight-only` passed against the new reservation.
Future execution consumes the **single** claim before its first guest action,
including a later listing/SCP failure. Do not retry on failure. Preserve through
the outcome map above; do not turn preservation receipts into runtime acceptance.
