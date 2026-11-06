# Independent re-review: run-410 Bootstrap witness validator r2

2026-11-06. Repository `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`,
HEAD `5e989eeeea3092cc59675bd78ad37e06fce2d7c0`.

**Verdict: FAIL.** Previous findings I1, I2, I3 and M1 are fixed, including
rejection of every original reviewer mutation. A fresh source-driven sweep
nevertheless found **11 additional false-PASS fixtures**, each exiting 0 with
all 15 check groups PASS. They violate Rust type constraints, canonical
Bootstrap guards, producer bindings, or retained host success evidence.
This is a completeness failure of the offline validator; it does not establish
that the original run-410 execution failed.

No Critical findings. Five new Important findings follow. No new Minor finding.
No subagents were started. Repository writes are limited to this report;
independent scripts, mutated record copies, receipts and logs are under
`/tmp/vprouter-witness-rereview/`. Product code and implementer tests were not
changed. Run410 remains consumed; no experiment was rerun.

## Disposition of the previous review

The original review is
`.superpowers/sdd/rust-v2/task-8c-run410-witness-review.md`. Its actual fixtures
were read directly from `/tmp/vprouter-witness-review/`, without regeneration or
editing, and invoked through the revised validator CLI with `python3 -B`.
`prior-fixture-results.json` records every exit, verdict and failed check.

| Prior finding | Independent re-review result |
| --- | --- |
| I1: six/eight-pin result types | CLOSED. `binding_result_8pins.json` fails `typed_witness`, `preparation_success`, and `bootstrap_scopes`; `bootstrap_result_6pins.json` fails `typed_witness` and `bootstrap_scopes`. Separate result schemas now exist at validator lines322-335 and the call sites use their respective types. |
| I2: preparation guards/prefix | CLOSED. `preparation_unreaped`, `preparation_fenced`, `preparation_pending`, `preparation_phase`, and `retained_prefix_birth` each fail `preparation_success`. Validator lines1497-1515 reproduce the final success guards and listed equalities in `attachment/operational/bootstrap.rs:1028-1069`. Historical continuation/drop flags are not blanket-forced true. |
| I3: held-intent identity/index | CLOSED. `own_intent_identity` and `query_intent_index` fail `bootstrap_success`. Validator lines1487-1494 bind query index87 and policy index90 to their own writer PID/start/status. A newly constructed query-start mutation also fails. |
| M1: handoff citation | CLOSED. The implementation report now cites `attachment/operational.rs:584-588`, which contains the handoff evidence JSON. |

All **18 original mutated fixtures** fail, including the nine originally
requested adversarial fixtures and all nine additional reviewer probes.
The original `real.json` fixture passes 15/15. The actual retained raw record
also passes 15/15; this was checked independently of the implementer's suite.

## Important I4: native birth PID is widened beyond its Rust type

Locations: `tools/rust-v2-lab/validate-run410-witness.py:158` declares
`Birth.pid` as `u64`; `:1595-1597` checks only PID >1 and start >0.
Rust's `ValidationBirth.pid` is **u32** at
`crates/vprouter-launch/src/owned/preparation.rs:78-82`.

Fixture: `bootstrap_query_u32_pid_overflow.json` sets
`queries[0].birth.pid` and
`preparation.bootstrap_queries[0].birth.pid` to **4294967296**. Updating both
copies preserves the query/history equality. Result: exit **0**, **PASS 15/15**.
The history cannot deserialize into the Rust type even though `typed_witness`
reports PASS. This repeats the class of typed-contract problem behind original
I1 for a different field.

Required correction: represent the actual Rust integer widths/ranges in the
static schemas, beginning with birth PID, and test overflow through `validate()`
with all duplicated copies kept consistent. Audit other `u64` substitutions for
narrower Rust fields rather than treating nonnegative integers as interchangeable.

## Important I5: Bootstrap query history accepts forbidden initial evidence

Locations: `tools/rust-v2-lab/validate-run410-witness.py:182` permits
`InspectionInitial|null`; `:1649-1653` checks kind and selected query/history
fields but never requires a Bootstrap query's `initial` to be null.

Fixture: `bootstrap_query_has_initial.json` inserts an `initial` object into
`preparation.bootstrap_queries[0]`, copying that query's request, birth, facts
and verified_at. Result: exit **0**, **PASS 15/15**.

The Rust guard explicitly rejects any initial object in
`crates/vprouter-launch/src/owned/preparation/inspection.rs:27-39`.
Bootstrap history validation calls `completed_bootstrap()` at
`owned/preparation/bootstrap.rs:49-54`, so this is on the successful Bootstrap
path. It is a detectable contradiction in recorded metadata, requiring no live
custody reconstruction.

Required correction: enforce the Bootstrap-specific `initial == null` invariant
for each scope, alongside query/history equality. A shared inspection schema
alone cannot express this contextual restriction.

## Important I6: canonical policy digest is accepted from the wrong kind/scope

Location: `tools/rust-v2-lab/validate-run410-witness.py:1667` checks policy
digest equality against `netfilter[index*2+1]`, but omits the canonical policy
record's kind and scope. Its `kind` schema is an unrestricted string at `:279`.

Two independent fixtures change every retained copy of the host
`initial_quarantine` netfilter history, preserving all prefix equalities and
leaving the digest unchanged:

| Fixture | Mutation | Actual result |
| --- | --- | --- |
| `host_bootstrap_policy_wrong_kind.json` | Change kind from `initial_quarantine` to `sockets` | exit0, PASS15/15 |
| `host_bootstrap_policy_wrong_scope.json` | Change scope from `host` to `data` | exit0, PASS15/15 |

`crates/vprouter-launch/src/owned/preparation/bootstrap.rs:92` obtains the
policy through `bootstrap_policy(scope)`. That guard at
`owned/preparation/quarantine.rs:296-301` requires a completed
`InitialQuarantine` operation **in that scope**. Digest equality alone does not
prove the record is an eligible source for the Bootstrap policy.

Required correction: apply the canonical completion/kind/scope checks before
using each policy, and cover coordinated mutations of retained copies.

## Important I7: binding result/request equality omits the canonical binding chain

Locations: `tools/rust-v2-lab/validate-run410-witness.py:1508` checks only
equality between retained entry-producer copies; `:1627-1636` checks a binding
result against its own request. Neither establishes the request's binding to
the published entry, original producer data, preceding query, and canonical
data policy.

The following independent mutations change all relevant retained copies
together, so prefix equality and result/request equality still hold:

| Fixture | Mutation left inconsistent with original canonical evidence | Actual result |
| --- | --- | --- |
| `entry_producer_binding_mismatch_all_prefixes.json` | Flip byte0 of every entry producer's `binding`, leaving the binding request unchanged | exit0, PASS15/15 |
| `binding_policy_mismatch_canonical_all_prefixes.json` | Flip byte0 of each binding request and result policy, leaving `netfilter[5].policy` unchanged | exit0, PASS15/15 |
| `binding_query_mismatch_all_prefixes.json` | Flip byte0 of each binding operation/history `query`, leaving `producer_binding_query.request` unchanged | exit0, PASS15/15 |
| `binding_data_mismatch_all_prefixes.json` | Increment binding request data namespace inode and result namespace inode, leaving original producer creation/data network unchanged | exit0, PASS15/15 |

Rust's `matches_publication()` at
`crates/vprouter-launch/src/owned/preparation/producer_binding.rs:53-62`
requires the published producer's binding to equal the request and its
parent/group to agree. The additional data/query/policy bindings are explicit
at `:79-98`. Successful Bootstrap validation requires that publication at
`owned/preparation/bootstrap.rs:89-92`; these are prerequisite checks, not
unrelated historical flags.

Required correction: validate the request against the canonical creation,
publication, query and policy as well as validating its result. Keeping
multiple corrupted copies equal is insufficient to establish their origin.

## Important I8: retained host-addition success contract remains unchecked

Locations: `tools/rust-v2-lab/validate-run410-witness.py:410-445` types these
host witness fields; `:1732-1748` checks selected host observations/final link
but omits its success discriminator, canonical negative oracle and held-intent
writer binding.

| Fixture | Single mutation in `host_addition` | Actual result |
| --- | --- | --- |
| `host_fault_nonzero.json` | `fault=1`, while four completed operations and success acknowledgment remain | exit0, PASS15/15 |
| `host_negative_count_zero.json` | `canonical_negative_checks=0` instead of the recorded20 | exit0, PASS15/15 |
| `host_own_intent_identity.json` | `own_intent_polling.pid=2`, leaving writer75 unchanged | exit0, PASS15/15 |

The actual real-record host negative count is **20**. Its derivation is the
16 field mutations plus four replacement/null mutations in
`crates/vprouter-launch/src/owned/preparation/host_link.rs:709-750` and the
following entries of that replacement list. The zero mutation is not a claim
that the original oracle did not run; it demonstrates absent offline checking.

The host success branch and operation cardinalities are checked at
`attachment/host_addition/operation.rs:820,1007`; intent counts and its original
writer75 PID/start/status binding at `:988-1000`; and the schema oracle and
success-dependent witness fields at `:1119-1146`. The retained continuation
returns before drop at `:1149-1153`, so its historical drop flags must retain
their actual false/null semantics. Requiring those drop flags true would be
an incorrect fix.

Required correction: validate the host witness's actual successful continuation
contract and its original intent writer. Extend that contextual review to the
other retained emitter branches rather than treating recursive field typing as
proof of their success guards.

## Read-only behavior and receipt/claim boundaries

PASS within the offline invocation scope. The prior reviewer's audit script
was rerun from a new copy with only its scratch directory changed. Source review
of the revised imports, `validate()` and `save_receipt()` corroborated it.

- `io-results.json` records 60 read opens and two write-open attempts, both to
  `/tmp/vprouter-witness-rereview/independent-receipt.json`: one creation and one
  refused overwrite. `validate()` itself opened no file for writing.
- The active audit hook rejects subprocess/system calls, network connect/bind,
  access to `/DATA/vprouter-lab/preserved`, other write opens and filesystem
  rename/remove/link/mkdir mutations. None occurred in validation/receipt calls.
  Descriptor writes and fchmod were additionally inspected in source; this is
  not a syscall trace of the whole machine.
- `save_receipt()` at validator lines1829-1840 uses
  `O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC`, creation mode0600,
  `fchmod(0600)`, file fsync and directory fsync. The independent receipt was
  mode0600. Existing receipt bytes survived overwrite refusal unchanged.
- CLI symlink receipt creation exited1 and preserved the sentinel target.
  Independent `python3 -B -O` and `python3 -B -OO` runs exited1 with
  `RuntimeError: optimized_python_refused`, with no output receipt created.
  The unconditional optimized-Python refusal remains at lines17-18.
- Both original receipts remain mode0600, with their pre-review hashes:
  first `f75a0edf98406455c6c9dcd8cd59442b233f1125865f07e463595bc08b7ccbc0`;
  r2 `84a38df64f375e2e25043fd3c86b4471a82e44d06080a33e4dc803e915eadeda`.
  Neither was reopened for writing. The r2 object exactly equals fresh
  validation of `target/lab-state/actual-program-run-410.json`.

The report and r2 receipt correctly retain `runtime_acceptance=false` and
`release_ready=false`, explicitly leave runtime/release/requirement8 open, and
retain the first receipt as superseded. Those boundaries pass review.
However, the implementation report's full validation claim and its canonical
query/policy/producer assertions at
`task-8c-run410-witness-validation.md:6-12,40,48,55-56`, and the receipt's
`full_bootstrap_witness_validation=PASS`, overstate coverage in light of I4-I8.
The stored receipt faithfully records what this validator returns; its PASS
does not establish that the omitted contracts were checked.

## Verification ledger

All Python executions used `python3 -B`. No Cargo, sudo, network, VM/guest
operation, Git staging/commit/push or other deliberate Git write occurred.
Existing tests use temporary fixture roots and mock guest subprocess paths;
their read-only `git show HEAD:...` source comparison is not a Git write.

| Verification | Exit/result | Evidence |
| --- | --- | --- |
| Run revised validator CLI against original reviewer's 19 fixture files | Expected exits: real0; all18 mutations1 | `prior-fixture-results.json`, per-fixture stdout/stderr |
| Direct real retained record validation | PASS15/15; r2 receipt exactly equal | `receipt-verification.json`; raw SHA256 `bd3d1819f6387491c69388b371f9b05fa28d5e773658223f950ffd743413f0ff` |
| Fresh independent mutations | 11 unexpected PASS15/15; four rejection controls FAIL | `mutations.py`, `fresh-mutation-results.json`, all15 JSON fixtures and stdout/stderr; script asserts each mutation actually changes the decoded witness |
| Rejection controls | Wrong binding result size; unreserved final preparation; wrong query-intent start; two queued policy-intent polls all rejected | Four `control_*.json` fixtures |
| `python3 -B tools/rust-v2-lab/test-validate-run410-witness.py` | exit0; 19 tests, 16.732s | `test-validate-run410-witness.log` |
| `python3 -B tools/rust-v2-lab/test-run410-fixes.py` | exit0; 8 tests | `test-run410-fixes.log`; existing generated-template SyntaxWarnings retained |
| `python3 -B tools/rust-v2-lab/test-run410-isolation.py` | exit0; 21 tests | `test-run410-isolation.log` |
| `python3 -B tools/rust-v2-lab/test-run410-provenance.py` | exit0; 21 tests | `test-run410-provenance.log` |
| `python3 -B tools/rust-v2-lab/test-run410-reservation.py` | exit0; 12 checks; real_lab_claim_created=false | `test-run410-reservation.log` |
| `PYTHONPYCACHEPREFIX=/tmp/vprouter-witness-rereview/pycache python3 -B -m py_compile` on validator, its test, and all four `test-run410-*.py` | exit0 | Six files compiled; explicit py_compile writes redirected outside repository because `-B` alone does not suppress explicit compilation output |
| Independent IO/receipt/optimized-Python probes | exit0; all assertions pass | `io-review.py`, `io-results.json` |
| Source versus frozen archive | All10 selected Rust files byte-identical | `frozen-source-results.json`; archive read without extraction |
| Preservation | All782 baseline file hashes/sizes/modes unchanged; only this report added within monitored paths | `before.json`, `preservation-results.json` |

The frozen-source comparisons cover `attachment/operational/bootstrap.rs`,
`attachment/operational.rs`, `attachment/host_addition/operation.rs`,
`owned/preparation.rs`, `owned/preparation/{bootstrap,inspection,producer_binding,quarantine}.rs`,
and `kernel/{bootstrap,docker_query}.rs` in the candidate's `source.tar`.
The sweep traced the final Bootstrap success branch, called query/result
emitters, canonical preparation/Bootstrap guards, policy-source and
producer-binding prerequisites, and the retained host continuation.
It is sufficient to demonstrate FAIL; it is not an assertion that these five
findings exhaust all unchecked retained-history contracts.

The preservation baseline includes lab-state, run410 evidence, the candidate
tree, lab tools and SDD reports/progress. The checkout uses an external worktree
Git index; its bytes were not included in the initial file baseline. Initial
and final Git status agree, with no staged changes; no index-byte preservation
claim is made from that file baseline. Existing unrelated
`progress.md` changes and both untracked implementation tools are preserved.
No source/report/receipt fix was made by this reviewer. Current native custody,
guest liveness, runtime/client/leak/fault acceptance, performance, ARM,
migration/reboot/rollback/soak and release readiness remain unproven by this
offline review. This FAIL neither authorizes another run nor consumes a claim.
