# Run410 witness validation r6: semantic fixes, incomplete predicate proof

2026-11-07. Implementation scope: offline recorded consistency only.
`runtime_acceptance=false`; `release_ready=false`.

**Implementation is PARTIAL.** The thirteen round-5 contradictions are rejected,
but the requested general compiler-level closure and mechanical decidability
proof have not been completed. The real record passes the implemented
consistency checks; `full_bootstrap_witness_validation=INCOMPLETE` and
`complete_predicate_validation=false`. Neither a successful test run nor the
retired ID ledger supplies the missing proof. This report supersedes earlier
full-coverage assertions in this file. The five independent reviews and r1-r5
receipts remain historical, unchanged evidence.

## Semantic corrections and red/green evidence

Read all five reports: `task-8c-run410-witness-review.md`, `-rereview.md`,
`-rereview2.md`, `-rereview3.md`, and `-rereview4.md` in this directory.

The first reconstructed CLI test was run before semantic edits. All 96
reconstructed prior negative cases failed; exactly the 13 round-5 cases
returned exit0/PASS. After the semantic corrections, all 109 negatives return
exit1/FAIL with a failed check other than `frozen_bindings`; the real record and
its reserialized copy PASS. These are reconstructed fixtures, **not replay of
lost original reviewer bytes**. The test generator retains the descriptions in
the reports and no longer depends on scratch directories from the previous boot.
Round3's 22 rejection controls were described by family rather than individually
named; the reconstruction uses those families and labels its new control names.
This is not an assertion of byte identity with all 96 lost records.

| Finding | Necessary serialized correction | Reconstructed round-5 cases |
| --- | --- | --- |
| I15 | Whole public WAN declaration: positive index, bounded ASCII name, forbidden and allocated-name exclusions, nonzero unicast MAC; allocation/namespace/digest bindings retained | zero MAC; multicast MAC; zero index; `lo`; `bad/name`; allocated host-interface name |
| I16 | Positive original Link index; WG hardware65534/veth hardware1; absent original WG peer index | WG index0; WG hardware1; veth hardware65534; WG peer999 |
| I17 | Complete public HostObservation namespace/count/string/alternate-name/TUN bounds, using UTF-8 byte lengths | veth TUN payload257; veth TUN count65 |
| I18 | Six-pin original producer-binding group mode requires permission bits0700; inventory now reaches `fixed_producer::observe_group` | six-pin group mode040777, leaving all eight-pin Bootstrap values unchanged |

WAN probes coordinate public declaration and WAN observation, recompute the
canonical declaration digest/size and update matching references. Network probes
coordinate original/retained results and final host inventory. These tests do
not rely on frozen-binding drift to reject correctly typed contradictions.
The earlier guard equivalences, original observations, and native-custody limits
remain separate from these necessary serialized projections.

## Source inventory and call graph

The previous 68-file handpicked inventory is expanded by a transitive,
conservative lexical may-call graph. Roots are all 2,632 non-`#[test]` function
bodies in the original validation/emitter source set; this deliberately includes
more than the successful branch. Calls and local function-item references are
followed across workspace modules; all same-name methods/trait implementations
are included. Closure bodies are scanned; local macros and import aliases are
followed. Each edge names a local target set or an explicitly inventoried
external symbol with a reason. An unrecognized call name, including an unknown
qualified module with a known method name, raises `ValueError` before output.

The generated graph has 4,832 nodes and 56,115 caller/callee edges, reaching191
source files; its unresolved-call-name list is empty. The source inventory has
204 declarations,248 selected source fields,100 schemas and5,699 guards.
The native producer-observation helper and its Report/Pins alias source are now
inside the hashed inventory. Function scanning also fixes a separate omission:
array semicolons in return types such as `Result<[u8;32]>` no longer make a
function disappear.

**This is not a complete Rust call graph proof.** Method resolution uses names,
conservatively overapproximates overloads, and includes unrelated/test helpers
reachable through name collisions. External symbol names do not establish
receiver types. Generic Fn targets, dynamic dispatch, cfg selection, procedural
macros, includes and compiler-resolved import/type identities remain unproved.
The zero unresolved-name count must not be presented as compiler closure
completeness. `call_graph.kind` and `limitations` record this boundary.
The graph regression exercises transitive helpers, trait methods, closures,
local macros, unknown callees and unknown qualified modules. A separate test
checks every generated edge's target resolution.

## Predicate accounting and decidability

Boolean conjunctions/disjunctions and supported any/all closure predicates are
split, retaining their enclosing expression/quantifier context. This preserves
the distinction between an atom and a requirement that every atom be true: e.g.
rejection `a && b` is evaluated in its conjunction context. Error-mapping
closures remain inside the surrounding comparison; `map_err(|_| Error::X)` is
not mistaken for a boolean predicate. Unsupported expressions stay opaque and
pending. There are two explicitly recorded `syntax_unresolved` entries: guards
`98a093ff12075728aff0` (`secret.rs:184`) and `9fc0dadaa9f241e950b4`
(`transport_lab.rs:1177`). Both retain multi-statement validation closures
with comments; normalization/comment masking cannot safely decompose them.

Each predicate has its own stable ID, implementation reference or pending
reason, and decidability report. A guard is `enforced` only if every one of its
predicate entries is enforced; otherwise it is `partial` and enumerates every
skipped predicate. Unknown guard/predicate IDs and stale mappings fail the
inventory check. No coverage is inherited from a function being callable or
from an ancestor observation's registry entry.

| Quantity | r5 | r6 |
| --- | ---: | ---: |
| Extracted guards | 3,378 | 5,699 |
| Guards called fully enforced | 178 | 5 |
| Guards with skipped predicates listed | not represented | 5,694 |
| Guards blanket-classified offline | 3,200 | retired |
| Predicate entries | not represented | 10,714 |
| Explicitly checked predicate projections | not represented | 45 |
| Predicate entries proved offline | not represented | 0 |
| Predicate entries pending proof/implementation | not represented | 10,669 |

These units and source scopes differ. **The offline-list reduction does not
mean that3,200 guards have been implemented.** The earlier178 whole-guard
coverage assertions were also retired rather than silently inherited. Existing
semantic check functions remain active, but their complete per-predicate
coverage has not been independently established.

`field_sources`, `json_builders` and the derived `serialization_index` enumerate
candidate serialization paths. The45 reviewed necessary projections have
explicit source-schema annotations checked mechanically against
`field_sources`. Their implementation references are listed per predicate ID,
but at check-function granularity: e.g. the nineteen WAN predicates share the
same three check names and one generic projection sentence, so the mapping does
not say which check applies which operand (review r6 M8). This covers the corrected public guards without claiming
that the complete mixed native fstat or creation procedure was replayed.

**The requested general decidability classifier remains incomplete.** A matching
field spelling is only candidate lineage, and no matching field spelling is not
an absence proof. The classifier returns `requires_lineage_proof` for other
predicates. Its intrinsic scans identify348 current-process-ID,124 pointer-
identity and69 clock candidate occurrences; they are candidates, not certified
offline cases. Direct-expression absence from JSON builders cannot exclude an
alias/helper serialization path. An explicit regression tests this counterexample.

The remaining certified `unenforceable_offline` list is therefore **empty**;
there is no class with an asserted absence proof. Genuine unrecorded UID/GID,
fstatfs/access modes, raw decoder bytes, creator/Rc/Weak custody, native state,
and live clocks remain limitations requiring operand-level lineage analysis.
They are **pending**, not blanket-certified impossible. A future offline
classification must supply an actual transitive absence certificate; the
validator refuses an `absent_value` decision with no such certificate. The
negative classifier test explicitly checks the serialized Link, TUN and mode
expressions from I16-I18.

## Receipt and preserved evidence

The new target is `target/run410-evidence/witness-validation-r6.json`, created
only through the validator's existing `O_EXCL|O_NOFOLLOW` writer, mode0600,
file fsync and parent-directory fsync. It retains r1-r5 as superseded history,
binds validator/extractor/contract hashes, and reports guard and predicate
counts. `verdict=PASS` means only the implemented recorded-consistency checks
passed; its explicit `verdict_scope`, `complete_predicate_validation=false` and
`full_bootstrap_witness_validation=INCOMPLETE` withhold the broader claim.
It grants no runtime or release acceptance.

Raw record SHA256 remains
`bd3d1819f6387491c69388b371f9b05fa28d5e773658223f950ffd743413f0ff`.
No original record or r1-r5 receipt is overwritten. No subagents, Cargo, sudo,
network, VM/QEMU action, Git write, preserved-tree operation, or live
claim/reservation mutation is part of this implementation. Concurrent
`tools/performance/**` and task14 report changes belong to another delegate.

## Verification ledger

All Python uses `python3 -B`; tests run under `nice -n15` with temporary fixtures.
The full102,334-mutation suite is run once. Explicit py_compile output is
redirected outside the checkout because `-B` does not suppress explicit compile
writes. Full-suite and focused results, receipt/preservation checks and scratch
paths are recorded below after verification.

Final verification evidence is retained in `/tmp/run410-witness-r6-t1bf_lfd`.
The reconstructed fixture generator is permanent in the test source; temporary
fixture bytes are intentionally managed by TemporaryDirectory. This scratch
path is local evidence and will not survive another temporary-directory loss.

| Check | Result |
| --- | --- |
| Pre-edit reconstructed negative CLI probes | Exactly13 round-5 false PASS;96 earlier negative cases rejected |
| Final full witness suite under nice | exit0;46 tests;499.181 seconds |
| Leaf sweep, executed once | 28,782 leaves;102,334 mutations rejected |
| Reconstructed reviewer CLI probes in full suite | 109/109 exit1 with semantic failure; real/reserialized records PASS |
| Contract drift / exhaustive predicate accounting | PASS in full suite |
| Final focused closure/classifier tests | exit0;5 tests,2.554 seconds; includes final unknown-qualified-module regression |
| `test-run410-fixes.py` | exit0;8 tests |
| `test-run410-isolation.py` | exit0;21 tests |
| `test-run410-provenance.py` | exit0;21 tests |
| `test-run410-reservation.py` | exit0;12 checks;real_lab_claim_created=false |
| py_compile | exit0;validator,test,extractor and four run410 tests;cache outside checkout |
| `git diff --check` | exit0 |
| Real record / r6 creation | exit0;24/24 implemented checks;full validation INCOMPLETE;mode0600 |
| Original raw and r1-r5 preservation | All6 hashes/sizes/modes unchanged |
| Runtime/release/native execution | NOT_RUN;not granted |

The full suite started before the last qualified-callee regression was added;
the final focused run verifies that additional assertion and the final graph
and classifier bytes. The leaf validator implementation was unchanged. The
full suite's own contract-drift test also passed after final regeneration.
No second100k sweep was needed.

r6 SHA256:
`96e9cdb25cacbc93d4013fb401268d5e9e14a562c60afbb58808510ad1acf464`.
It records45 enforced and10,669 pending predicates, zero certified offline,
and false runtime/release flags. HEAD remains `eb2f50e`; no staging,
commit, push, reset, stash or Git mutation command was run.

## Residual syntactic limits (M4) and unfinished requirements

The scanner is a bounded lexical inventory, not a Rust parser/type checker.
Selected immediate early-error, assertion, match-guard and validation-call
forms are inventoried; arbitrary tail-expression errors, let-else guards and
conditional bodies with preceding statements are not exhaustively normalized.
An ordinary helper call is now in the call graph but is not itself necessarily
an inventoried boolean guard. Generic/tuple serde declarations, nested inline-
module type identities, rename/flatten semantics, explicit enum discriminants,
const-symbol array lengths, complex raw/nested comments and macro-generated
syntax require further parser/compiler work. Source hashes bind syntax; hashes
do not prove that the inventory understands that syntax. Opaque predicate
entries, overapproximation and missing guard forms are not excused as offline.

Requirements(1) and(3) are **not complete**: the implementation needs compiler-
resolved success-path closure and transitive typed def-use/serialization lineage,
then actual enforcement of every decidable predicate. Requirement(2) is only
complete within the supported boolean inventory; unsupported Rust syntax is
explicitly pending. The thirteen concrete false-PASS cases are fixed, but a
full r6 validation/acceptance claim remains withheld.

## Controller disposition after the round-6 review (2026-11-07)

Independent review r6 (`task-8c-run410-witness-rereview5.md`, OpenCode DeepSeek v4.1 flash max):
**PASS** in the sense that the validator is honest and correct about what it checks. I15-I18
are closed (13 reconstructed round-5 cases now fail semantically); the real record passes
24/24 implemented checks with `full_bootstrap_witness_validation=INCOMPLETE` and
`complete_predicate_validation=false`. Minor findings and their disposition:

- M6 (a decidable pending predicate, `project.rs:322` Link kind/TUN, can be violated with
  verdict PASS): this is the documented meaning of `pending`; the receipt states it. OPEN as
  work, not as an overclaim.
- M7 (stale `predicate_lineage` IDs were not refused): fixed by the controller —
  `guard_dispositions()` now also requires every lineage ID to be an extracted predicate
  (`stale predicate lineage mapping`); test `test_stale_predicate_lineage_id_is_refused`
  (RED with the line removed, GREEN with it).
- M8 (per-predicate traceability wording too strong): wording corrected above.
- M9 (the 96 pre-r6 fixtures are reconstructions, originals lost on reboot): already stated.
- M10 (r1-r5 receipts still say `full_bootstrap_witness_validation=PASS`): the receipts are
  immutable evidence and stay byte-unchanged; `target/run410-evidence/RECEIPT-INDEX.json`
  now records that r1-r5 are superseded and that r6 (`INCOMPLETE`) is authoritative.

Net: the validator is a strict, honest PARTIAL typed validation; 45 predicates enforced,
10,669 pending, 0 certified offline. It is not full typed validation and not acceptance;
runtime_acceptance=false, release_ready=false.
