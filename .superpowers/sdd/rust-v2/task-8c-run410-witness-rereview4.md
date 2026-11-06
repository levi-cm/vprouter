# Independent fifth review: run-410 Bootstrap witness validator r5

2026-11-06. Repository `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`,
HEAD `9f997dd960876619bc57d1910a2d532d224d2498`. No subagents started.

**Verdict: FAIL.** The real record passes **23/23** checks. All **96** retained
negative fixtures in the implementation's prior-review ledger fail through the
actual CLI, with semantic failures independent of `frozen_bindings`. The full
suite passes **43 tests, 102,334 end-to-end leaf mutations**. Nevertheless,
independent source-driven mutations reproduce **13 false PASS records in four
Important finding families**. Each exits **0**, verdict **PASS**, all **23/23**
checks PASS. No Critical finding.

The extractor reproduces the contract byte-for-byte, but that establishes
determinism/drift detection, not a complete source closure or implementation of
every mapped predicate. This round independently demonstrates all three gaps:
an incompletely implemented guard marked `enforced`, decidable serialized checks
marked `unenforceable_offline`, and an omitted native helper on the success path.

This is **offline typed validation of recorded witness consistency relative to
the Rust contract**. It is not runtime acceptance. The findings do not establish
that the original execution was incorrect. `runtime_acceptance=false` and
`release_ready=false` remain appropriate.

Only this report was written inside the repository. Scratch scripts, exact
mutation records, stdout/stderr and verification logs are under
`/tmp/vprouter-witness-r5/`. No implementation, historical review/receipt, run-411
tool, guest, QEMU, lab resource, claim or reservation was modified. No Cargo,
sudo, network, VM command or Git write was executed.

## Important I15: the WAN declaration guard is marked enforced but six serialized predicates are skipped

Locations: `tools/rust-v2-lab/validate-run410-witness.py:4870-4886` and
`:3456-3473`; Rust
`crates/vprouter-launch/src/attachment/host_declaration.rs:35-65`.

The extracted guard `d6d1e5ca4c83fab24f8e` includes WAN index, name, MAC and
allocation-disjointness checks. Its disposition says **enforced** by
`baseline_consistency`. That function verifies declaration hash/size,
allocation/namespace references and equality with the WAN observation, but does
not implement the WAN validity predicates. Checking that its named function is
callable does not establish that the complete guard is enforced.

**REPRODUCED**, six distinct fixtures:

| Fixture basename, all `.json` | Mutation |
| --- | --- |
| `wan_zero_mac` | WAN address becomes six zero bytes. |
| `wan_multicast_mac` | WAN address becomes `[1,2,3,4,5,6]`, setting its multicast bit. |
| `wan_index_zero` | WAN index becomes zero. |
| `wan_forbidden_name` | WAN name becomes `lo`. |
| `wan_invalid_name` | WAN name becomes `bad/name`. |
| `wan_allocated_name` | WAN name becomes an allocated vprouter host-interface name. |

Each mutation updates both the public declaration row and original WAN
observation, recomputes that declaration's canonical SHA256/byte length, and
updates every corresponding `host_declaration`/`declaration_digest` reference.
All other evidence, including the frozen reservation, remains unchanged. The
Rust guard explicitly rejects every case using operands already serialized.
All six CLI invocations nevertheless PASS23/23.

Implement the whole public declaration predicate and test coordinated
declaration/digest substitutions. This is not private constructor-digest
regeneration or a request for a live WAN observation. Evidence:
`probe-wan.py`, `wan-probe-results.json`, and individual receipts.

## Important I16: enforceable native Link invariants are classified offline and accepted

Locations: `tools/rust-v2-lab/validate-run410-witness.py:4712-4739`;
`tools/rust-v2-lab/witness-contract-extract.py:1449-1456`;
`crates/vprouter-network/src/project.rs:158-179` and
`crates/vprouter-network/src/native.rs:543-565,624-627`.

The fixed Link adapter extracts selected constants from the token-readback
guard, omitting success constraints elsewhere in the native creation/decoder
path. The guard ledger then categorizes those other constraints as unavailable:

| Extracted guard | Disposition | Available serialized predicate |
| --- | --- | --- |
| `da63da5e218b81640d1e`, `project.rs:178` | `raw_decoder` | `Link.index` is copied directly from `m.header.index`; zero is malformed. |
| `38dbd321a5569913a100`, `native.rs:547` | `live_descriptor` | Created WG hardware type is65534, veth hardware type is1. |
| `1f7d55b8cabcbf933ba4`, `native.rs:625` | `live_descriptor` | Original created WG `peer_index` must be absent. |

The successful confined WG child calls this creation path at
`crates/vprouter-network/src/secret_role/provision.rs:545-551`, then obtains the
public readback at `:555-558`. Creation changes the ownership alias through
`native.rs:567-575`; that operation does not change hardware type or add a peer
index. The parent compares the report's Link to its own readback at
`secret_role/provision.rs:422-430`. These are constraints on the recorded
original result, not a request to replay native custody.

**REPRODUCED**, with every affected original/retained result copy coordinated:

| Fixture basename, all `.json` | Mutation |
| --- | --- |
| `wireguard_index_zero` | Every WG Link index and matching WG device index becomes0. |
| `wireguard_hardware_type_ethernet` | Every WG Link hardware type becomes1. |
| `veth_hardware_type_wireguard` | Every owned veth Link hardware type becomes65534. |
| `wireguard_peer_index_present` | Every WG Link gets `peer_index=999`. |

Each returns PASS23/23. Positive native indices, native creation hardware types
and the absent WG peer index must be checked using the serialized values.
Retain offline limits for the genuinely absent raw bytes and native state.
Evidence: `probe-network.py`, `network-probe-results.json`, individual receipts,
and `guard-ledger.tsv`.

## Important I17: a pure HostObservation bounds guard is incorrectly marked live-descriptor-only

Locations: `tools/rust-v2-lab/validate-run410-witness.py:4502-4508` and
`:4712-4739`; Rust
`crates/vprouter-network/src/host_observation.rs:79-99`.

Guard `4ebb4a306c2040136cd6`, at Rust line83, is entirely a computation on the
serialized observation: record counts, string lengths, alternate names and TUN
attribute/vector lengths. It does not inspect a descriptor. Its disposition is
nevertheless `unenforceable_offline`, category `live_descriptor`.

**REPRODUCED**:

| Fixture basename, all `.json` | Mutation |
| --- | --- |
| `veth_tun_value_257` | Each owned veth Link gets `tun_info=[[1,[0 repeated257 times]]]`. |
| `veth_tun_count_65` | Each owned veth Link gets65 TUN entries with one-byte payloads. |

Copies include the exact added Link in the final host observation, so retained
result equality and baseline-plus-one-Link comparisons still succeed. Both
records return PASS23/23. `HostObservation::validate` explicitly rejects a
payload over256 bytes or more than64 entries; `encode` calls it at line104,
and `decode` calls it at line135. No live information is needed to reject either
fixture. Implement these public bounds and correct the disposition. Evidence:
`probe-bounds.py`, `bounds-probe-results.json`, individual receipts.

## Important I18: the extractor's source closure omits a called producer-observation helper

Locations: `tools/rust-v2-lab/witness-contract-extract.py:1082-1096,1250`;
`tools/rust-v2-lab/validate-run410-witness.py:4638-4643`;
Rust `crates/vprouter-netfilter/src/fixed_producer.rs:341-352,375-387`.

The source set covers launch preparation/attachment, selected launch kernel
files, network, and two core files. It does not include `vprouter-netfilter`.
The actual producer-binding path holds a `PendingProducerObservation` at
`crates/vprouter-launch/src/kernel/producer_binding.rs:33`, calls
`n.pending.poll().map_err(map)?` at `:289`, and serializes the original request
pin triples at `:302-307`. Ordinary `poll` calls and the `observe_group` helper
name do not match the extractor's validation-call name regex.

In the omitted crate, the child calls `observe_group` twice before serializing
its successful report (`fixed_producer.rs:375-387`). The helper requires its
actual pin to equal the recorded expected triple and, for pin1, requires
`st_mode & 0o7777 == 0o700` (`:346-350`). The group mode is therefore available
in the serialized six-pin request/result, even though UID/GID and fstatfs are
not. Bootstrap's separate eight-pin mode check does not validate these earlier
six-pin records.

**REPRODUCED**: `binding_group_mode_writable.json` changes pin1's mode to
`0o40777` in every six-pin producer-binding request/result copy, preserving all
eight-pin Bootstrap values. It returns PASS23/23, although the native helper
cannot accept that recorded mode on the successful binding path.

Running the same extractor directly on the omitted file finds the missing
guard `57accb9e398496441164`; it is absent from the generated contract and
guard-disposition set. Thus drift/unknown-ID tests still pass. The omitted
file also contains a serialized `Report` using the `Pins` type alias at
`fixed_producer.rs:22-31`, outside the claimed source inventory.

Extend the bounded source closure through the actual success-path helpers and
check the recorded group permission bits. Do not claim the full mixed fstat
guard was replayed. Evidence: `probe.py`, `probe-results.json`,
`omitted-helper-guards.json`, `extractor-probes.py`.

## Minor M4: syntactic inventory limits, without additional false-PASS claims

`witness-contract-extract.py:1102,1244-1250,1333` has further independently
reproduced parsing limitations. Synthetic probes retain the results in
`extractor-probes.json`:

- An ordinary `check_integrity()?` call, tail-expression `if { Err(...) } else
  { Ok(...) }`, `let ... else { return Err(...) }`, and a conditional body with
  a statement before `return Err` produce zero guard entries.
- A derived generic struct and tuple struct silently produce no declarations.
  Two same-named types in nested inline modules receive the same file/name ID;
  the `by_id` dictionary can collapse them.
- Field `rename`/`flatten` attributes are recorded as text; schema generation
  uses the Rust field keys. Explicit enum discriminant values are not retained.
  A const-symbol array length raises `ValueError` rather than being resolved.

Control probes correctly extract loops containing immediate early errors,
`matches!` conditionals, `ensure!`, `debug_assert!`, and guards in trait impls.
Real WireGuard `skip_serializing_if` fields are explicitly adapted for the
completed move/nonmove profile. I found no further current-profile false PASS
attributable solely to the synthetic generic/rename/flatten/discriminant cases;
they are limitations, not additional Important findings. I18 is the concrete
current-profile helper omission with a reproduced false PASS.

## Earlier fixtures, drift, offline limits and preservation

The prescribed ledger actually contains96 negative fixtures:70 before round4,
plus25 Important reproductions and the separate M3 capacity fixture. All96
FAIL through the CLI without rewriting or normalizing their bytes, including
duplicate-key and nonfinite probes. All have a failing group other than
`frozen_bindings`. I1-I14 and M2/M3's retained reproductions are closed.

A broader pass replayed **all332 retained record-shaped fixture files** across
the four reviewer scratch directories: **327 FAIL and5 PASS**. The five are the
original real copy, its reserialized copy, and three probes explicitly not
reported as contradictions in the fourth review:

- `host_admission_one_poll.json`: the admission loop does not prove one poll
  impossible (`attachment/host_addition/operation.rs:719-730`).
- `quarantine_intent_too_many_polls.json`:100 satisfies the explicit at-least2
  guard (`attachment/quarantine/producer.rs:825`).
- `host_addition_foreign_nonzero_digest_all_copies.json`: constructor-digest
  regeneration was not established; this review does not promote it to a
  finding. Available nonzero/equality guards are distinct from regeneration.

These three accepted limit probes are not silently counted as rejected prior
negative fixtures. See `all-prior-cli-results.json` and `replay-all.log`.

Regeneration independently produced **68 source files,81 declarations,248
selected source fields,100 schemas and3,378 guards**, byte-identical to the
checked-in contract; `contract-drift.diff` is empty. Its guard counts are
178 enforced and3,200 offline. They are ID-accounting counts, not semantic
coverage. I15 disproves complete enforcement of a mapped guard; I16/I17
disprove the stated impossibility of selected offline predicates. I have not
certified all3,200 reasons individually. Genuine creator/Rc/Weak provenance,
FD custody/access/UID/GID/fstatfs, live clocks and native state transitions
remain outside the serialized evidence. Mixed guards require separate checks
for their decidable projections rather than omission of the entire predicate.

All10 Rust files used to substantiate the Important findings are byte-identical
to their entries in the original candidate `source.tar`, read without
extraction. This includes the omitted `fixed_producer.rs`. The observed
contradictions therefore apply to the frozen implementation, not just today's
working source. `final-verification.json` retains the paths and hashes.

The two historical helper copies are verified against their original
reservation hashes at Python `:3708-3714`. This is explicitly scoped as
historical run410 evidence, not current helper/lab readiness. No helper was
restored or executed by this reviewer. The existing r5 receipt is mode0600 and
has both runtime/release flags false; its full-validation PASS is not justified
while I15-I18 remain.

An independent audit hook around module import, real-record validation and
receipt creation observed66 read opens, one explicit receipt creation plus
its FD wrapper, and two refused overwrite/symlink creation attempts. It
observed no subprocess/network or filesystem-mutation event outside receipt
creation. Mode0600, existing receipt bytes and symlink sentinel bytes were
verified. Source inspection confirms `O_EXCL|O_NOFOLLOW`, fchmod0600, file and
parent fsync at Python `:4956-4967`. `-O` and `-OO` both refuse before receipt
creation via `optimized_python_refused`. The first audit harness mistakenly
rejected the legitimate integer FD passed to `os.fdopen`; the corrected
scratch-only harness resolves its FD target. That harness error is not a
validator finding.

The validator, test, extractor, contract and real record hashes match the
review-start snapshot. The real record remains
`bd3d1819f6387491c69388b371f9b05fa28d5e773658223f950ffd743413f0ff`.
No current guest/lab state or operational acceptance was tested.

## Verification ledger

All Python commands used `python3 -B`; test processes additionally used
`PYTHONDONTWRITEBYTECODE=1`, `TMPDIR=/tmp/vprouter-witness-r5` and `nice -n15`.
Explicit py_compile outputs were redirected with `PYTHONPYCACHEPREFIX` because
`-B` alone does not suppress explicit compilation writes.

| Verification | Exit/result | Scratch evidence |
| --- | --- | --- |
| Real record CLI, initial and final |0; PASS23/23; runtime/release false | `real.stdout`, `final-real.stdout` |
| All96 retained negative fixtures, exact bytes via CLI |96 expected exit1;96 semantic FAIL | `replay.py`, `prior-cli-results.json` |
| All332 retained record-shaped reviewer fixtures via CLI |327 FAIL;2 valid copies PASS;3 documented limit probes PASS | `replay-all.py`, `all-prior-cli-results.json` |
|13 independent new semantic mutations via CLI |13 unexpected exit0/PASS23/23 | `new-false-pass-results.json`, per-fixture stdout/stderr |
| Four Bootstrap mode rejection controls |4 expected FAIL | `probe-results.json` |
| Extractor regeneration and final drift rerun |0; exact byte equality both times | `extracted-contract.json`, `contract-drift.diff`, `final-verification.json` |
| Extractor syntax/helper probes |0; omissions and supported controls recorded | `extractor-probes.json`, `omitted-helper-guards.json` |
| `test-validate-run410-witness.py` |0;43 tests,286.273s;28,782 leaves,102,334 mutations | `full-suite.log` |
| `test-run410-fixes.py` |0;8 tests | `test-run410-fixes.log` |
| `test-run410-isolation.py` |0;21 tests | `test-run410-isolation.log` |
| `test-run410-provenance.py` |0;21 tests | `test-run410-provenance.log` |
| `test-run410-reservation.py` |0;12 checks;real_lab_claim_created=false | `test-run410-reservation.log` |
| Read-only/exclusive0600/symlink/overwrite audit |0 after harness correction | `io-audit2.py`, `io-results.json` |
| Optimized Python CLI refusals |1 each, before receipt creation | `optimized-O.stderr`, `optimized-OO.stderr` |
| Frozen archive comparisons |10/10 source files byte-identical | `final-verification.json` |
| py_compile: validator,test,extractor,four run410 tests |0;7 files;cache outside repo | `py_compile.log`, `final-verification.json` |
| `git diff --check` |0 | `git-diff-check.log` |
| Live/native/runtime/release acceptance |NOT_RUN;not granted | This review's scope |
