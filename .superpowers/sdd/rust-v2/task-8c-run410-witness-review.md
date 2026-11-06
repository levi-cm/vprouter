# Independent review: run-410 Bootstrap witness validator

2026-11-06. Repository `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`,
HEAD `5e989eeeea3092cc59675bd78ad37e06fce2d7c0`.

**Verdict: FAIL.** The real record passes all 14 groups, and all nine requested
adversarial mutations fail. The validator is useful and preserves the evidence,
but additional independent mutations produce false PASS results for states that
the frozen Rust emitter explicitly rejects, including an invalid fixed-array
size. Do not close full typed witness validation until I1–I3 are addressed.
This verdict concerns the validator's completeness; it does not establish a
failure of the original run-410 execution.

No Critical findings. Three Important findings and one Minor finding follow.
All reproduction fixtures, independent scripts, receipts, and logs are under
`/tmp/vprouter-witness-review/`. No sub-agents were started.

## Important I1: producer-binding results accept the Bootstrap pin-array size

Location: `tools/rust-v2-lab/validate-run410-witness.py:322–326` (shared
`ProducerResult`), used at `:307` and `:915`; related report claim:
`.superpowers/sdd/rust-v2/task-8c-run410-witness-validation.md:64–68`.

The shared result schema accepts `pins6|pins8`. Its producer-binding callers do
not subsequently require six pins or equality with their own six-pin request.
The Rust producer-binding `PublicResult` requires exactly six triples:
`crates/vprouter-launch/src/owned/preparation/producer_binding.rs:7–12`, with
six request pins at `:28`. Bootstrap has a separate eight-pin result and history
in `owned/preparation/bootstrap.rs:8–13,17–30`.

Reproduction: append `[[1,2,3],[4,5,6]]` to
`witness.preparation.producer_binding.result.pins` in a copy of the real record.
`binding_result_8pins.json` exits **0**, verdict **PASS**, **14/14** groups.
That result cannot deserialize into the Rust producer-binding result type.
The report's assertion that final validation enforces the respective sizes is
therefore inaccurate for results, although the request arrays are correctly
sized and the top-level Bootstrap operation/result equality is enforced.

Required correction: use distinct six-pin and eight-pin result schemas at the
respective call sites, and test both result contexts through `validate()`.
A test of a shared object shape alone cannot distinguish these Rust types.

## Important I2: preparation success guards and retained-prefix equality are missing

Location: `tools/rust-v2-lab/validate-run410-witness.py:1593–1599` and
`:1642–1646`; the typed-only fields are declared at `:97–140`.

The Rust success path explicitly checks native children reaped, jobs uncollected,
service reserved, no canonical pending state, no mutation fence, entry phase
`creating`, absent links/attempt/terminal, unchanged producer, and the first 87
writers at `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1028–1047`.
It also compares the retained preparation fields against the host preparation
at `:1049–1069`. The Python validator checks cardinalities and the 18 new
Bootstrap writer phases, but omits these success guards and the retained-prefix
comparisons. Its handoff equality at `validate-run410-witness.py:1521` compares
handoff preparation with host preparation, not the final Bootstrap preparation.

Each independent single-field mutation below exits **0**, verdict **PASS**,
**14/14** groups:

| Fixture | Mutation in final `witness.preparation` |
| --- | --- |
| `preparation_unreaped.json` | `native_children_reaped=false` |
| `preparation_fenced.json` | `mutation_fenced=true` |
| `preparation_pending.json` | `canonical_pending=true` |
| `preparation_phase.json` | `entry_phase="failed"` |
| `retained_prefix_birth.json` | Increment `writers[0].pid`, leaving the retained host/handoff prefix unchanged |

A corrupted record can therefore claim a pending/fenced/failed preparation or a
substituted original writer while receiving full successful witness validation.
These are contradictions in recorded metadata that can be rejected offline;
rejecting them does not require reconstructing native custody.

Required correction: implement the success-path preparation guards and the
specific prefix equalities from the emitter, and add end-to-end mutations for
these omissions. Preserve the historical prefixes' actual continuation/drop
semantics rather than forcing every historical flag true.

## Important I3: held-intent evidence is not bound to its original writer

Location: `tools/rust-v2-lab/validate-run410-witness.py:1480–1483`, with intent
identity fields typed at `:528–535`.

The validator checks held/negative/released/poll counts but never binds the
intent's `index`, `pid`, or `start` to the canonical writer. The emitter explicitly
requires query intent index 87 and its original writer PID/start, and policy
intent index 90 and its original writer PID/start:
`crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1071–1087`.

Independent fixtures `own_intent_identity.json` (increment
`own_intent_polling.pid`) and `query_intent_index.json` (set
`own_query_intent_polling.index=0`) both exit **0**, verdict **PASS**, **14/14**.
The validator consequently accepts held/released-intent evidence associated with
the wrong process or writer slot. The report's intent-contract statement at
`task-8c-run410-witness-validation.md:30` needs this binding before it is complete.

Required correction: enforce the indices and corresponding PID/start equality
with `preparation.writers[87]` and `[90]`, and test both identities and indices.

## Minor M1: handoff source citation points beyond the file

Location: `.superpowers/sdd/rust-v2/task-8c-run410-witness-validation.md:47`.

It cites `attachment/operational.rs:601–607`, but that file ends at line 597 at
this HEAD. The handoff JSON is emitted at **584–588**. A reader following the
citation cannot inspect the cited evidence. Update the reference.

## Read-only and claim-boundary assessment

PASS within the requested offline invocation scope. The validator imports only
standard-library modules and never imports or executes controller/guest code.
Its evidence accesses use `read_bytes()` or `open('rb')`, including reservation,
consumed claim, frozen bindings and candidate artifacts. The only explicit file
write is `save_receipt()` at `validate-run410-witness.py:1787–1798`, using
`O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC`, mode 0600, `fchmod(0600)`, file
fsync and parent-directory fsync. It does not create parent directories,
truncate/replace existing files, mutate budgets, or acquire claims/reservations.

An independent Python audit hook around `validate(real_record)` and
`save_receipt(scratch_receipt, data)` observed 60 read opens and only two
write-open attempts, both to the explicitly selected scratch receipt: one
successful creation and one refused overwrite. The hook rejected subprocess,
network-connect/bind, preserved-path access, other write opens, and filesystem
rename/remove/link/mkdir mutations. None occurred during those calls. Source
inspection additionally covered fd writes and `fchmod`, which that hook does
not independently trace. See `io-review.py` and `io-results.json`.

Receipt mode was 0600. Independent overwrite refusal preserved receipt bytes;
CLI symlink refusal exited 1 and preserved the scratch sentinel target.
Independent `python3 -B -O` and `python3 -B -OO` runs both exited 1 with
`RuntimeError: optimized_python_refused`, before creating a receipt. The
`if not __debug__` refusal remains at lines 17–18.

No access to `/DATA/vprouter-lab/preserved` was needed. No Cargo, sudo, network,
VM, guest command, or Git write was performed. The existing suites' guest
subprocess paths were inspected as mocked; their fixtures are temporary.

## Source cross-check and limits

The three cited Rust files are byte-identical to their copies inside the frozen
candidate's `target/candidates/run410-da75562-20261104/source.tar`; this was
verified by reading the archive without extraction. The guest source checked
was `tools/rust-v2-lab/target/platform-lab/secret-bootstrap.guest.py`, which also
matches its source-manifest hashes. Expectations were checked against these
emitters, not inferred from the one real record.

| Contract | Source and assessment |
| --- | --- |
| 39 canonical negative checks | `owned/preparation/bootstrap.rs:857–889`: three scopes, ten mutations and three null substitutions per scope; `3*(10+3)=39` is correct. |
| Handoff 20 = 15 + 5, charges 5→0 | `attachment/operational.rs:479–483,526–555,584–588`: five retired suffix jobs and five repeat refusals, `[5,5]→[0,0]`; correct. |
| Bootstrap charges 3→3 and retention | `attachment/operational/bootstrap.rs:1213–1222,1248–1287`: fault-zero charges `[3,3]` remain after drop and the four final retention flags become true; correct. |
| Closed field sets | Bootstrap witness JSON at `attachment/operational/bootstrap.rs:1248–1255` matches the top-level schema. Bootstrap history/result fields match `owned/preparation/bootstrap.rs:8–30`; unknown fields and required fields are checked. Producer result context is incorrectly widened, as I1 shows. |
| Original two-second deadlines | `owned/preparation/bootstrap.rs:77–136` and `attachment/operational/bootstrap.rs:1090–1123,1182–1191` support the query/birth/result/writer/process timing checks. The independent expired verification mutation fails. |
| Six vs eight pins | Distinct Rust fixed-array contracts confirmed; Python request contracts are correct, but the shared result union is too permissive (I1). |
| Host unchanged=false | Guest lines 181–191 require preserved routes/rules/addresses/stable neighbors, unchanged prior links, and exactly the planned new down veth on success. Line 198 emits `not changed` and `changed`; false/true is expected. The implementation report's explanation is correct. |

The existing receipt's SHA256 is
`f75a0edf98406455c6c9dcd8cd59442b233f1125865f07e463595bc08b7ccbc0`, mode 0600.
Its `runtime_acceptance=false`, `release_ready=false`, and seven explicit
`does_not_prove` items correctly exclude real-client/leak, multi-exit/direct,
ARM, performance, migration/reboot/rollback/soak, current guest/custody, and
operational authorization/requirement-8 acceptance. The independently generated
scratch receipt retains these limitations. However, the label
`full_bootstrap_witness_validation=PASS` is too strong while I1–I3 remain.

The implementation report's final test commands, exit codes, counts, raw SHA256
and existing receipt SHA256 were reproduced/verified. Its claimed historical
RED-first development sequence and original before/after observations cannot be
reconstructed from the current files; they are not independently attested here.
The receipt-create command listed in that report is historical: rerunning it to
the already existing receipt must fail, as required. I created only a new scratch
receipt. The existing report and `progress.md` were left unchanged.

## Independent mutation ledger

Command: `python3 -B /tmp/vprouter-witness-review/mutations.py`, exit **0**.
The script uses independently authored mutations and invokes the CLI for every
fixture. The script's exit 0 means its required real-pass/nine-fail expectations
held; the extra false-PASS probes are reported, not silently treated as failures
of that harness. Full receipts and stderr are retained per fixture.

| Mutation | CLI exit | Verdict / failing group |
| --- | --- | --- |
| Real copied record | 0 | PASS, 14/14 |
| Flip `placement_authorized` | 1 | FAIL, `no_authority` |
| Change fault 0→1 | 1 | FAIL, `bootstrap_success` |
| Drop controller row | 1 | FAIL, `stdout_rows` |
| Duplicate raw `exit_code` key | 1 | FAIL, `strict_record_json` |
| Change canonical owner boot ID | 1 | FAIL, `owner_identity` |
| Set query verification to deadline | 1 | FAIL, `monotonic_deadlines` and `bootstrap_scopes` |
| Change handoff after-charge | 1 | FAIL, `charge_conservation` |
| Add unknown operation field | 1 | FAIL, `typed_witness` |
| Insert NaN in final verification | 1 | FAIL, `stdout_rows` strict embedded JSON |
| Four preparation success-state contradictions | 0 each | Incorrect PASS, I2 |
| Substitute retained prefix writer PID | 0 | Incorrect PASS, I2 |
| Wrong intent PID / wrong query-intent index | 0 each | Incorrect PASS, I3 |
| Eight-pin producer-binding result | 0 | Incorrect PASS, I1 |
| Six-pin Bootstrap history result only | 1 | FAIL, `bootstrap_scopes` |

Results: `/tmp/vprouter-witness-review/mutation-results.json`.

## Verification ledger

All commands ran from the repository root unless an absolute scratch script is
specified. Every Python command used `-B`; suite temporary files were directed
under `/tmp/vprouter-witness-review` using `TMPDIR`.

| Command/check | Exit | Result |
| --- | --- | --- |
| `python3 -B tools/rust-v2-lab/test-validate-run410-witness.py` | 0 | 13 tests, OK; 11.537 s. |
| `python3 -B tools/rust-v2-lab/test-run410-fixes.py` | 0 | 8 tests, OK; generated-template SyntaxWarnings reproduced. |
| `python3 -B tools/rust-v2-lab/test-run410-isolation.py` | 0 | 21 tests, OK. |
| `python3 -B tools/rust-v2-lab/test-run410-provenance.py` | 0 | 21 tests, OK. |
| `python3 -B tools/rust-v2-lab/test-run410-reservation.py` | 0 | 12 checks; `real_lab_claim_created=false`. |
| `python3 -B -m py_compile tools/rust-v2-lab/validate-run410-witness.py tools/rust-v2-lab/test-validate-run410-witness.py` | 0 | Both compile; `PYTHONPYCACHEPREFIX=/tmp/vprouter-witness-review/pycache`, no repo pyc writes. |
| `python3 -B /tmp/vprouter-witness-review/mutations.py` | 0 | Real PASS, nine required mutations FAIL; eight extra false PASS results found. |
| `python3 -B /tmp/vprouter-witness-review/io-review.py` | 0 | Audited read-only validation; receipt 0600/exclusive, overwrite/symlink/optimized refusals. |
| Source-manifest byte/hash verification (`python3 -B` heredoc) | 0 | 296 manifest rows, both original/archive paths checked: 592 byte/size/hash comparisons. |
| Frozen source archive comparison (`python3 -B` heredoc) | 0 | All three cited Rust files match working source. |
| `git diff --check` | 0 | No tracked whitespace errors. |
| Before/after hash/mode/size comparison (`python3 -B` heredoc) | 0 | All 70 baseline files unchanged: 66 run409/run410/bundle evidence files including original receipt, two tools, implementation report, progress edit. No new files in the snapshotted evidence sets. |
| Branch/HEAD/status before and after | 0 | `rust/v2` at full SHA above; pre-existing dirty paths unchanged. |
| Cargo, sudo, network, VM/native execution, runtime/release acceptance | NOT_RUN | Outside authorized offline review scope. |

Detailed suite output: `test-validate-run410-witness.log`, `test-run410-*.log`,
`suite-results.json`, and `py_compile.log` in the scratch directory. Scratch
artifacts are retained for the implementer. The only repository file written by
this reviewer is this review.
