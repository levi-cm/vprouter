# Task 8c run-410 offline witness validation, revision 5

2026-11-06. Implementation delegate; no subagents. Branch `rust/v2`, starting
HEAD `848b468`. This revision supersedes the r1-r4 validation claims. The four
independent review reports and all r1-r4 receipts remain unchanged. This is an
implementation candidate, not independent review acceptance.

`runtime_acceptance=false`, `release_ready=false`. Run410 remains consumed.
No experiment, claim, reservation, VM, network, QEMU, Cargo, sudo or Git mutation
was performed. The running ARM guest and other delegates' files were untouched.
The six owned outputs are the validator, its test, the new extractor and generated
contract, this report and the exclusively created r5 receipt.

## Method change

`witness-contract-extract.py` reads Rust source without executing Rust/controller
programs or reading private input files. Its stdout is deterministic sorted JSON;
`--output` writes only the explicitly selected contract path. The checked-in
`witness-contract.json` records:

- The conservative source closure and SHA256 of every source file; 81 serde or
  emitted-enum declarations, their exact field Rust types, structured integer
  widths/signedness, Option/nullability, nested array lengths/tuples/vectors,
  enum variants/payloads, serde attributes and source locations.
- 34 selected declaration roots (248 fields) which generate the witness/envelope
  schemas, plus the Origin tagged-enum projection and distinct move/nonmove
  serialization of skipped optional fields. Every parsed serde field overrides
  the reviewed successful JSON-builder adapters. No raw witness shape or value
  is used to generate the contract.
- JSON-builder field expressions with source locations. Reviewed projection
  adapters select wrapper edges and completed/non-null profiles; wrappers built
  with `serde_json::Value` are not misrepresented as Rust Deserialize structs.
- Every conditional early-error guard, require/ensure/verify/validate/assert call
  and guarded match arm found in the selected module closure, with normalized
  expression, exact file/line, enclosing function and referenced field selectors.
- Source-extracted native Link constants, the assembly capacity literal, and
  public peer/endpoint constants from the hash-bound retained guest program.

The parser balances Rust delimiters and masks comments/strings while preserving
locations. Regression probes cover comments/serde attributes, nested fixed
arrays/Options, a nested if-expression in a guard, sibling guards, assertions,
require/ensure calls and successful guarded match arms. Unsupported serialized
type/enum syntax raises instead of silently widening a schema. This is a bounded
syntactic extractor, not a Rust compiler or call-graph/execution proof.

The validator loads this contract as its sole schema/enum/array authority. Its
integer ranges depend only on Rust integer kind and the recorded amd64 pointer
width. Generic `array`/`tuple`/`list`/Option traversal enforces closed field sets.
The test's previous field-name integer width map and hand-enumerated serde root
inventory are removed; the 28,782-leaf sweep traverses contract edges, including
source-typed optional nulls and nonempty synthetic TUN tuples.

Every extracted guard ID is pinned to either named callable checks or an explicit
`unenforceable_offline` reason. IDs bind normalized expression, source location
and guard kind. `guard_dispositions()` rejects missing, duplicate, new and stale
IDs; the test injects an unknown guard and requires refusal. Source changes cannot
inherit a catch-all file/function disposition. The exact lists are
`ENFORCED_GUARDS`, `OFFLINE_GUARDS`, `OFFLINE_GUARD_REASONS` in the validator;
joining IDs with `contract.guards` yields the full expression/location ledger.
The source extractor does not read that ledger to decide what guards exist.

Counts: **3,378 extracted; 178 enforced as whole serialized guards; 3,200
unenforceable offline as whole guards**. The closure deliberately includes native,
private, transient, fault and supporting-module guards, not just the small final
success block. A mixed native/serialized guard is counted offline as a whole even
where separate checks enforce its recorded clauses. The count is not an execution
coverage percentage or a claim that the native clauses were replayed.

The round-4 67-entry binding registry remains. Transport creation, query and
operation field intersections now come from contract schemas; canonical path
selection/aliases remain explicit reviewed relationships. WAN start/end bind to
HOST policy instead of receiving independent-root status. Registry coverage alone
is still not proof of semantic completeness.

## Round-4 corrections

| Finding | Implemented recorded check |
| --- | --- |
| I11 | Every canonical WG/veth Link satisfies source-extracted down/MTU1420/controller0/empty-port/promiscuity0/all_multicast0/no-alternate-name guards and allocated name/ownership alias. WG device index/name equal its Link; public device key equals the primary recorded public input; exactly one peer has the retained guest's planned public key/endpoint and the single IPv4 default allowed IP. Query retains its original complete provision Link; existing original move/publication bindings remain. |
| I12 | WAN requested_at/deadline equal HOST InitialQuarantine's original window; WAN verified_at precedes or equals that child's original Birth. |
| I13 | Each populated original host-addition digest contains a nonzero byte, including coordinated retained copies. |
| I14 | DATA attachment, fresh TRANSPORT creation and TRANSPORT mount have the same original journal directory identity. Existing observation-to-history bindings remain. |
| M3 | Assembly global_child_capacity_limit equals the source-extracted emitter literal64. |

All available peer-plan comparisons are implemented, including public peer key,
endpoint and allowed-prefix regressions beyond the reviewer's counted fixtures.
These are public facts; no private key or live native state was inspected.

## Tests first and fixture accounting

The first edit added end-to-end reviewer regressions and contract-drift/guard
coverage tests, followed by a run against the unchanged r4 validator.
`/dev/shm/vprouter-witness-r5/red.log`: **27 failing subtests** — all26 round-4
semantic cases remained accepted apart from unrelated frozen-helper drift, plus
the missing extractor. Tests explicitly require a failing group other than
`frozen_bindings`, so that drift cannot mask a false semantic PASS. RED test
process exited1 (the surrounding log-display shell returned0).

The fixture total is **96**, not95: 70 retained earlier fixtures plus25 Important
round-4 reproductions **and the separate M3 fixture**. Every exact retained file
is passed to the real `validate()` entry point without rewriting its bytes.
`test_round5_all_96_retained_reviewer_fixtures` reads the earlier reviewer's actual
70-entry failure ledger and explicitly enumerates the26 round-4 paths. No missing
fixture is silently skipped. Real and independently reserialized records must
both PASS, with every group PASS and runtime/release flags false.

After the changes, `semantic-green.log` records both tests passing. Additional
extractor tests failed before handling guarded match arms and passed afterward.
The short pre-full suite found one stale test reference to the removed old
inventory; the final test reads the contract/source declarations instead. That
intermediate run is not final verification evidence.

The source audit additionally exposed a nonprimary allocation false PASS: changing
only the secondary exit's interface name still passed all checks. Four new
end-to-end cases (foreign interface, duplicate exit ID, root state directory,
foreign subnet) failed before the correction (`allocation-red.log`,4 failures)
and pass after (`allocation-green.log`,2 tests including real/reserialized PASS).
`allocation_contract` now checks every exported public allocation exit, labels,
absolute/disjoint state paths, uniqueness, exact deterministic names and /30
subnets, positive generation/schema/cardinality and the canonical Rust serde-order
allocation digest. Hash seed/prime and MAX_EXITS are extracted from source.
Thirteen formerly offline whole guards now map to this implemented check. Native
foreign ResourceClaim inputs and unexported configuration validation remain offline.

The first full suite was deliberately interrupted with SIGINT (exit130) during
its leaf sweep after this additional omission was found; `full-suite.log` is
retained as intermediate evidence only. The final full suite is the second and
last 100k-suite attempt (`final-full-suite.log`). No third sweep was run.

## Frozen historical helpers and source provenance

Run411 work changed `fresh-baseline.py` and `phase3-readonly-preflight.py` from
their run410 reservation hashes. They are not run410 runtime inputs now. For these
two specific historical bindings, `frozen_bindings` verifies the already retained
copies under `target/run410-evidence/files/tools/rust-v2-lab/` against the original
reservation hashes. It does not restore the live files, change the reservation,
fall back to an unbound copy or accept live-helper drift as readiness. All other
32 reservation paths retain their original validation. Receipt scope explicitly
states historical-helper verification and excludes current helper/lab readiness.

The raw record SHA256 remains
`bd3d1819f6387491c69388b371f9b05fa28d5e773658223f950ffd743413f0ff`.
The frozen source archive is read without extraction. **66/68** complete source
files match the archive. The two current core allocation/configuration files have
changes elsewhere; **all34 selected serialized declarations, including those two
files' relevant declarations, match their frozen counterparts** after excluding
location metadata. The conservative guard inventory records the current source
hashes honestly; it is not described as a byte-identical frozen full-source tree.
Evidence: `frozen-source-comparison.json`, `frozen-declaration-comparison.json`.

## Explicit unenforceable_offline list

| Reason category | Whole guards | Why offline validation cannot reproduce it |
| --- | ---: | --- |
| `creator_or_pointer` | 370 | The guard includes current creator PID, Rc/Weak origin or original non-Clone capability. Those are not serialized. Any visible identity projections are checked separately. |
| `live_clock` | 98 | The guard uses the live clock/poll deadline or a running native process. Only serialized monotonic timestamps and original windows are checked offline. |
| `live_descriptor` | 306 | The guard needs live descriptors, token registration, fstat/statfs, access permissions, raw packet/FD inventory or a retained native resource; JSON assertions cannot replay it. |
| `native_validation_call` | 1379 | The call requires a native Request/Receipt/owner/service/lease, parsed original input, or live state-machine transition. The JSON witness is not that capability. |
| `private_history` | 2 | The guard needs the unexported full Record, original PublicValidation/configuration/secret-input digest, or constructor digest regeneration. Recorded nonzero digests and available references are checked separately. |
| `raw_decoder` | 98 | The guard validates raw netlink/socket/protocol bytes or native parsing inputs which the witness does not serialize; only bounded public result structures are available. |
| `transient_or_fault` | 119 | The guard checks a transient pending/intent/Birth state, failure/fault branch, negative-oracle execution or collection transition absent from this completed fault0 continuation. Its emitted endpoint projection is checked where present. |
| `unexported_module_state` | 828 | This conservative module closure also extracts guards for private owner/kernel/supervision/configuration state outside the emitted projection. Operands are not present in the witness; no source-level execution is claimed. |

This list is exhaustive for the extracted guard IDs, not a grant to omit a
serialized clause. In particular no unavailable result is reported as zero and
no native capability is inferred from repeated equal JSON objects. Actual pointer
origin, creator identity, descriptor access/custody/UID/GID/fstatfs, non-Clone
leases, live service/admission state, full before/proposed journal records,
private constructor digest regeneration, original native job/gate/write/ack
execution and post-drop resource survival remain unavailable/NOT_RUN.

The source root list and JSON projection adapters remain a reviewed bounded
profile. The extraction/drift and mutation checks do not prove that a newly
introduced serializer or unrelated Rust module is automatically a supported
run410 profile, nor do they establish authenticity of a wholly fabricated,
internally coherent record. Failures/fault1-6 and future profiles need their own
contract/profile review. No real clients, leak/traffic/fault acceptance, current
lab liveness, ARM runtime, performance, migration/reboot/rollback/soak,
requirement8 or release acceptance follows.

## Verification and r5 receipt

All scratch evidence paths in this report are under
`/dev/shm/vprouter-witness-r5/`, unless explicitly absolute otherwise.

- `nice -n 10 python3 -B tools/rust-v2-lab/test-validate-run410-witness.py`:
  **43 tests PASS in 278.251s**. This includes the deterministic contract re-run,
  exact guard-disposition coverage/refusal, all96 retained reviewer fixtures,
  real/reserialized PASS and **102,334 end-to-end mutations of 28,782 leaves**.
  Evidence: `final-full-suite.log`; final process exit0. This was the second and
  last full-suite attempt.
- All `test-run410-*.py`: fixes **8 PASS**, isolation **21 PASS**, provenance
  **21 PASS**, reservation **12 checks PASS**, `real_lab_claim_created=false`.
  Evidence: `final-test-run410-{fixes,isolation,provenance,reservation}.log`.
- `python3 -B` py_compile of the validator, test, extractor and four run410 test
  scripts: **PASS**, with generated bytecode confined to scratch `pycache/` via
  `PYTHONPYCACHEPREFIX`. `git diff --check`: **PASS**.

Created `target/run410-evidence/witness-validation-r5.json` with the validator's
exclusive-create CLI, exit0: **PASS, 23/23 check groups**, revision5, mode0600,
6,858 bytes. SHA256:
`5c17f8bd1e5cf9ed0250933c83de5246fcde385c2ab166e8a91c951955b980ae`.
Its content equals a fresh validation of the identical relative raw-record path;
guard counts are3378/178/3200. `runtime_acceptance=false` and
`release_ready=false` remain explicit in the receipt.

`final-verification.json` confirms the raw record and all four older receipts
retain their original SHA256, sizes and modes, and all four tested code/contract
hashes equal `final-source-hashes.json`. No earlier receipt was replaced. The
receipt is offline consistency evidence only; the native/runtime residual limits
above remain open for independent review.

The bounded IO audit permits validation reads and one explicitly selected
exclusive receipt write only. It also verifies overwrite/symlink refusal,
mode0600, and `-O`/`-OO` refusal. It is a Python audit plus source inspection,
not a whole-host syscall trace. File-descriptor fchmod/fsync paths remain intact.

## Controller disposition after round 5 (2026-11-06 16:20): still PARTIAL, iteration stopped

Round 5 (`task-8c-run410-witness-rereview4.md`): I11-I14/M3 fixed by construction via the
Rust contract extractor (3,378 guards extracted; 178 enforced whole; 3,200 explicitly
`unenforceable_offline`); all 96 earlier reviewer mutations rejected; the real record passes
23/23 (receipt `witness-validation-r5.json`). The reviewer reproduced 13 new false-PASS
records in four families (I15 WAN declaration guard marked enforced but six predicates
skipped; I16 enforceable native Link invariants classified offline; I17 a pure
HostObservation bounds guard marked live-descriptor-only; I18 the extractor's source closure
omits a called producer-observation helper) plus M4. Five independent rounds have each found
a new family; the validator is checkpointed as the strongest PARTIAL so far and iteration is
stopped here. It is not an acceptance; runtime_acceptance=false; release_ready=false.
