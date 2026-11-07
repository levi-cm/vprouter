# Independent sixth review: run-410 Bootstrap witness validator r6

2026-11-07. Repository `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`,
HEAD `eb2f50e`. No subagents started. Review scope is the uncommitted r6
changes only: `tools/rust-v2-lab/validate-run410-witness.py`,
`tools/rust-v2-lab/test-validate-run410-witness.py`,
`tools/rust-v2-lab/witness-contract-extract.py`,
`tools/rust-v2-lab/witness-contract.json`, the newest section of
`.superpowers/sdd/rust-v2/task-8c-run410-witness-validation.md`, and
`target/run410-evidence/witness-validation-r6.json`. Concurrent
`tools/performance/**`, `docs/rust-v2/performance-*.md` and
`task-14-report.md` were ignored. Nothing under `/DATA/vprouter-lab`,
`target/lab-state`, claims, reservations, QEMU or Git was modified. Only this
report was written in the repository; scratch evidence is under
`/tmp/witness-r6-review/`.

## Verdict: PASS

The r6 validator is **honest and correct about what it checks**. The four
round-5 false-PASS families I15-I18 are closed: all thirteen reconstructed
round-5 scenarios now exit 1 with a semantic failure other than
`frozen_bindings`, and the real record passes 24/24 implemented checks. The
`pending` category is real: 10,669 predicates are not enforced, the receipt and
the implementation report say so explicitly, and I reproduced one decidable
pending predicate (`project.rs:322`, Link kind/TUN consistency) that can still
be violated with verdict `PASS`. That is consistent with the receipt's
`complete_predicate_validation=false`, `full_bootstrap_witness_validation=INCOMPLETE`
and 10,669 pending count, so it is **not** an overclaim and not a verdict
failure under this review's definition of PASS.

No Critical and no Important findings. Four Minor findings are recorded below.
The oracle is still **offline recorded-consistency validation**, not runtime or
release acceptance: `runtime_acceptance=false` and `release_ready=false` remain
correct.

## What round 6 built

- Per-predicate dispositions: a guard is `enforced` only when every extracted
  predicate is enforced; otherwise it is `partial` and lists every skipped
  predicate (`validate-run410-witness.py:205-235`).
- Enforced predicates are exactly the 45 IDs in `PREDICATE_CHECKS`
  (`validate-run410-witness.py:62-198`); each requires a
  `serialized_projection` decision and callable check functions
  (`:220-223`). The retired r5's 178 whole-guard IDs and 3,200 blanket-offline
  IDs are not used.
- A conservative lexical call graph with a hard failure on unresolved callees
  (`witness-contract-extract.py:1132-1230`), plus source hashing and drift
  regeneration. The checked-in contract regenerates byte-for-byte.
- A decidability classifier that never returns `absent_value` for an
  unreviewed predicate (`witness-contract-extract.py:1409-1443`); the certified
  offline count is therefore zero and every unreviewed predicate is pending.
- A 24-check receipt with explicit scope fields:
  `full_bootstrap_witness_validation=INCOMPLETE`,
  `complete_predicate_validation=false`, `runtime_acceptance=false`,
  `release_ready=false`, `source_closure="conservative lexical; compiler
  closure NOT_PROVEN"` (`validate-run410-witness.py:1691-1706`).

## Findings

### Minor M6: a decidable pending predicate is not enforced, and a coordinated mutation still PASSes

`crates/vprouter-network/src/project.rs:319-323` has the public Link decoder
guard

```rust
(out.kind == "tun") != tun_info
```

extracted as guard `597961666f27eeb4988a` / predicate
`fc1f203e91626417377d`. It is **pending**: it is absent from
`predicate_lineage` and `PREDICATE_CHECKS`. The validator checks only the
`tun_info` vector/payload bounds (`validate-run410-witness.py:1465-1483`), and
`contract_success`'s `link_guards` (`:1499-1508`) does not check the
kind/TUN relation. `typed_witness` accepts a well-shaped TUN tuple on any Link.

I changed every veth Link object (17 objects) and every wireguard Link object
(28 objects) in the real witness to `tun_info=[[1,[0]]]`. All three records exit
0, verdict `PASS`, 24/24 checks, no failing check:

- `/tmp/witness-r6-review/tun-veth/veth_all_tun_valid_shape.json`
- `/tmp/witness-r6-review/tun-veth/veth_vh_vd_tun_valid_shape.json`
- `/tmp/witness-r6-review/tun-veth/wireguard_tun_valid_shape.json`

This is a genuine violation of the Rust success-path decoder on the recorded
link shape, not a frozen-binding artifact. It is, however, exactly what the
receipt says: 10,669 predicates are pending and
`complete_predicate_validation=false`; the implementation report's
requirements (1) and (3) are explicitly not complete. The doc's I17 row claims
only the public HostObservation bounds, which this mutation does not violate.
Recommendation: add the kind/TUN predicate to the reviewed projections, or
name this concrete example in the pending section so readers do not mistake
"pending" for a theoretical list.

This is the answer to the review question "can a mutation violating a pending
predicate still yield PASS": **yes**, and the receipt does disclose it.

### Minor M7: a stale `predicate_lineage` ID is accepted; only `PREDICATE_CHECKS` is checked for staleness

The report says "Unknown guard/predicate IDs and stale mappings fail the
inventory check"
(`task-8c-run410-witness-validation.md:92-94`). In the implementation,
`guard_dispositions` checks that every ID in `PREDICATE_CHECKS` is present in
the extracted predicates (`validate-run410-witness.py:234`) and that guard IDs
match exactly, but it does not check that every ID in
`contract['predicate_lineage']` is present in an extracted predicate. I
monkeypatched an extra stale lineage ID into a loaded validator and called
`guard_dispositions()`; it returned all 5,699 dispositions without error. Adding
the same stale ID to `PREDICATE_CHECKS` did raise
`ValueError: stale predicate enforcement mapping`.

This cannot create a false enforcement (an extra lineage ID is unused), and the
checked-in contract has exactly the 45 reviewed IDs, so the real record is not
affected. The claim is nevertheless broader than the code. Recommendation:
also require `set(contract['predicate_lineage']) <= seen` and add a test for
that stale-lineage case.

### Minor M8: the report's per-predicate traceability claim is stronger than the mapping

The report says the 45 reviewed projections have "their implementation
references and projection arguments ... listed per predicate"
(`task-8c-run410-witness-validation.md:113-118`). In `PREDICATE_CHECKS`, the
nineteen WAN predicate IDs all map to the same three check names and the same
generic `projection_proof` sentence ("Serialized public declaration and
allocation; canonical digest recomputed; full WAN predicate applied.")
(`validate-run410-witness.py:65-198`). The implementation is correct — I
verified the WAN predicate itself, including the extra cases below — but the
mapping does not identify, per predicate, which check applies which operand.
This is a documentation/traceability issue, not a false-PASS issue.

### Minor M9: "109/109" is a reconstruction, not replay of the original 96 fixtures

The report is explicit that the 96 pre-r6 cases are reconstructed from the
written reports, not byte-replayed, and that the original bytes are lost
(`task-8c-run410-witness-validation.md:20-29, 171-175`). The full suite's
109-case test does pass through the real CLI
(`test-validate-run410-witness.py:389-400`), and I independently reconstructed
all thirteen round-5 cases plus extra WAN variants below. Rereview4 records
332 retained record-shaped fixtures across four review scratch directories,
including 96 negative fixtures; only `/tmp` scratch from this boot survives
(`/tmp/vprouter-witness-r5` is absent), so I could not replay those original
bytes. The report's qualification is honest; this is a scope limit, not a
failure.

### Minor M10: r1-r5 receipts still carry `full_bootstrap_witness_validation=PASS`

`target/run410-evidence/witness-validation.json` through
`witness-validation-r5.json` remain mode 0600, byte-unchanged and list
`full_bootstrap_witness_validation=PASS`. r6's receipt lists all five in
`supersedes`, and the report calls them historical/superseded
(`task-8c-run410-witness-validation.md:11-13, 138-147`). The r6 receipt is the
only one with `INCOMPLETE`; a consumer must select the newest receipt. This is
the correct preservation choice, but a one-line "old receipt scopes are
superseded" note in the r6 receipt's `verdict_scope` or a separate index would
remove the remaining ambiguity.

## I15-I18 reproduction

All commands used `python3 -B`, the real record
`target/lab-state/actual-program-run-410.json`, and the unmodified validator.
Scratch scripts and JSON fixtures are under `/tmp/witness-r6-review/`. Each
fixture was built independently from rereview4's descriptions; the WAN fixtures
also update the declaration SHA256/byte length and every
`host_declaration`/`declaration_digest` reference.

### I15: WAN declaration guard (19 predicates)

`baseline_consistency` now applies positive index, 0 < byte length <= 15,
ASCII `[A-Za-z0-9_.-]`, forbidden `lo`/`tailscale0`, allocated-name
disjointness, nonzero MAC and multicast-bit checks
(`validate-run410-witness.py:1682-1686`). All six rereview4 mutations exit 1,
verdict FAIL, with `baseline_consistency` reporting
`original declared WAN index/name/unicast nonzero MAC/allocation disjointness`:

| Fixture | Exit | Verdict | Failing check |
| --- | ---: | --- | --- |
| `wan_zero_mac` | 1 | FAIL | `baseline_consistency` |
| `wan_multicast_mac` | 1 | FAIL | `baseline_consistency` |
| `wan_index_zero` | 1 | FAIL | `baseline_consistency` |
| `wan_forbidden_name` (`lo`) | 1 | FAIL | `baseline_consistency` |
| `wan_invalid_name` (`bad/name`) | 1 | FAIL | `baseline_consistency` |
| `wan_allocated_name` (host interface) | 1 | FAIL | `baseline_consistency` |

Additional independent WAN cases all FAIL at `baseline_consistency` with the
same WAN predicate unless noted: empty name, 16-byte name, allocated data
interface, allocated wireguard interface, foreign deployment ID, generation 2,
foreign member, schema version 2, zero allocation digest, and host-namespace
mismatch. `wan_host_ino_zero` also fails `canonical_histories`,
`bootstrap_scopes`, `controller_consistency` and `baseline_consistency`; it
changes the gateway namespace consistently with the declaration. A positive
control, `wan_name_dot` (`a.b-c_d`), exits 0/PASS, confirming the guard is not
over-rejecting legal ASCII names.

### I16: serialized native Link success guards

`contract_success`'s `link_guards` checks positive Link index, WG hardware
type 65534, veth hardware type 1, absent original WG peer index, and the
`network_link_fixed` constants (`validate-run410-witness.py:1499-1508`).
Coordinated mutations of every affected original/retained result and final
inventory copy all fail:

| Fixture | Exit | Verdict | Failing check / message |
| --- | ---: | --- | --- |
| `wireguard_index_zero` | 1 | FAIL | `contract_success`: native decoded Link positive index |
| `wireguard_hardware_type_ethernet` | 1 | FAIL | `contract_success`: native created Link hardware type |
| `veth_hardware_type_wireguard` | 1 | FAIL | `contract_success`: native created Link hardware type |
| `wireguard_peer_index_present` | 1 | FAIL | `contract_success`: original created WG has no peer index |

### I17: HostObservation bounds

The new `host_observation_bounds` check implements namespace nonzero, total
record count, name/alias/kind/port-kind lengths, alternate-name count and
element lengths, and TUN vector/payload bounds
(`validate-run410-witness.py:1465-1483`). Both rereview4 fixtures fail:

| Fixture | Exit | Verdict | Failing check / message |
| --- | ---: | --- | --- |
| `veth_tun_value_257` | 1 | FAIL | `host_observation_bounds`: observation Link string/alternate-name/TUN bounds |
| `veth_tun_count_65` | 1 | FAIL | `host_observation_bounds`: same |

The TUN payload/count predicates are enforced, but the separate kind/TUN
predicate (`project.rs:322`) remains pending; see M6.

### I18: producer-observation helper and six-pin mode

`recorded_emitters` now checks every six-pin pins array's pin 1 permission bits
(`validate-run410-witness.py:1403-1406`), and the extractor's source inventory
includes `crates/vprouter-netfilter/src/fixed_producer.rs` and its Report
declaration. The rereview4 fixture changes pin 1's mode to `0o40777` in every
six-pin request/result/observation copy while leaving all eight-pin Bootstrap
values unchanged:

| Fixture | Exit | Verdict | Failing check / message |
| --- | ---: | --- | --- |
| `binding_group_mode_writable` | 1 | FAIL | `recorded_emitters`: original six-pin producer observation group permission bits |

The `fixed_producer::observe_group` guard is guard
`57accb9e398496441164`; only its two predicates (`i == 1`, mode `!= 0o700`) are
enforced. The dev/ino/mode triple, UID, GID and fstatfs predicates remain
pending, as the implementation report says.

## Pending-category judgement

The receipt and report are clear enough:

- `predicate_counts = {extracted: 10714, enforced: 45,
  unenforceable_offline: 0, pending: 10669}`.
- `full_bootstrap_witness_validation: "INCOMPLETE"`,
  `complete_predicate_validation: false`, and
  `verdict_scope: "implemented recorded-consistency checks only; complete
  contract validation INCOMPLETE"`.
- The `contract_guards` check reference says "per-predicate
  enforced/absence-proved/pending accounting; full semantic coverage is
  separate" (`validate-run410-witness.py:1740`).
- The implementation report itself says "Implementation is PARTIAL",
  "A guard is `enforced` only if every one of its predicate entries is
  enforced", and requirements (1) and (3) are not complete
  (`task-8c-run410-witness-validation.md:6-11, 76-136, 213-218`).

I found **no** code path that treats `pending` as enforced. `guard_dispositions`
only uses predicate status to set `partial`/`enforced`; `contract_guards` checks
only accounting/guard IDs; no validation check consults `pending` or
`skipped_predicates`. `pending` rows have no `check_ids`; all enforced rows have
`serialized_projection` and callable check names.

I randomly sampled 20 of the 10,669 pending predicates (seed `20261107`).
Seventeen are live/opaque/synthetic rather than serialized witness values:
`std::process::id()`, live credentials/identities, `Instant`/clock windows,
socket send lengths, `Rc`/`Weak` identity, `verify`/`poll` calls, and synthetic
`lab_*` helpers. Three have serialized field spellings but are constrained
elsewhere: the project route prefix is pinned by the authored baseline and
observation binding; host-addition link containment is checked by
`retained_success`; the Docker query listener UID is checked as
`listener_origin_uid == 0` in `recorded_emitters`. In the sample, none was an
unconstrained trivially-checkable predicate. Outside the sample, M6 is a
concrete decidable pending predicate, and the WAN lease `verified_at` bounds
(`host_declaration.rs:209-228`) are also effectively covered by
`monotonic_deadlines` even though those predicate IDs remain pending. The
pending list is therefore a conservative **per-predicate enforcement/proof
backlog**, not a literal list of 10,669 semantically unchecked values. The
report's wording ("pending proof/implementation") is accurate; the phrase
"unchecked" is stronger than the implementation claims.

The one presentation risk is that `verdict: "PASS"` is the most prominent
receipt field. The scope fields are explicit and I do not treat this as an
overclaim, but a naive consumer that reads only `verdict` and
`checks[].status` could miss the limitation. A `checked_predicates: 45` /
`pending_predicates_unchecked: true` pair, or the same `verdict_scope` string
rendered next to the verdict, would make the limitation unmistakable without
changing the result.

## Extractor closure and drift

- Regenerating the contract with
  `python3 -B tools/rust-v2-lab/witness-contract-extract.py` produced
  byte-identical output to `witness-contract.json` (`cmp` exit 0, SHA256
  `a19efb885138dfaadb9e2f0a3601be54b7b735f7083392ca465498ad10b80b80`).
- The generated graph has 4,832 nodes, 56,115 edges, 2,632 roots, 191 source
  files, 204 declarations, 248 selected source fields, 100 schemas and 5,699
  guards; `call_graph.unresolved` is empty. `source_files` includes
  `crates/vprouter-netfilter/src/fixed_producer.rs`, and the contract contains
  the `observe_group` guard.
- I copied the extractor to `/tmp/witness-r6-review/extractor-mut2.py`, pointed
  its `ROOT` at the repository, removed the only `memchr`/`memmem` external
  mapping, and ran it: exit 1 with
  `ValueError: unresolved validation callees: [{'caller':
  'crates/vprouter-linux/tests/docker_managed_copies.rs:30:inspect', 'callee':
  'memmem', ...}]`. The closure does fail on an unresolved callee rather than
  silently omitting it.
- The test's synthetic closure probe (`unknown_callee()` and
  `missing_module::len()`) also raises `ValueError`; the real-edge test checks
  every edge has a resolved target set or an explicit external reason. The
  full suite passed both.

## Read-only, receipt and flags

- A validation-only `strace` run (`python3 -B validate-run410-witness.py
  target/lab-state/actual-program-run-410.json`) recorded 148 read opens and
  **zero** write/truncate/unlink/rename/mkdir/chmod/fsync syscalls.
- A receipt run recorded exactly one write open:
  `openat(..., O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600)`, followed by
  `fchmod(3, 0600)`, `fsync(3)`, and a second `fsync` for the parent directory.
  No unlink/rename/mkdir/truncate occurred.
- New receipt mode is 0600. A second run against an existing receipt exits 1,
  leaves the existing bytes unchanged. A symlink receipt path exits 1
  (`File exists`) and leaves the target sentinel unchanged, because
  `O_EXCL|O_NOFOLLOW` refuses it.
- `python3 -O` and `python3 -OO` both exit 1 with
  `RuntimeError: optimized_python_refused` before any receipt is created
  (`validate-run410-witness.py:18-19`).
- `target/run410-evidence/witness-validation-r6.json` is mode 0600, 7,653
  bytes, SHA256
  `96e9cdb25cacbc93d4013fb401268d5e9e14a562c60afbb58808510ad1acf464`. Its
  `validator_sha256`, `extractor_sha256`, `contract_sha256` and
  `raw_record_sha256` match the current files/record. `runtime_acceptance` and
  `release_ready` are both `false`. A fresh CLI run produced a byte-identical
  receipt (`cmp` exit 0).
- The raw record remains SHA256
  `bd3d1819f6387491c69388b371f9b05fa28d5e773658223f950ffd743413f0ff`, mode
  0600, 405,554 bytes. r1-r5 receipt hashes/sizes/modes match
  `/tmp/run410-witness-r6-t1bf_lfd/preservation-before.json`.

## Verification ledger

All Python commands used `python3 -B`; the full suite used
`PYTHONDONTWRITEBYTECODE=1`, `TMPDIR=/tmp/witness-r6-review/tmp` and
`nice -n 10`. Explicit py_compile output was redirected with
`PYTHONPYCACHEPREFIX=/tmp/witness-r6-review/pycache`; no cache was written in
the checkout.

| Verification | Result | Evidence |
| --- | --- | --- |
| Real record CLI, initial and receipt run | exit 0; PASS 24/24; `full=INCOMPLETE`; runtime/release false | `/tmp/witness-r6-review/real.stdout`, `r.json`; byte-identical to checked-in r6 |
| Independent I15 six WAN mutations | 6/6 exit 1, FAIL at `baseline_consistency` WAN message | `/tmp/witness-r6-review/fixtures/wan_*.json`, `results.json` |
| Extra independent WAN predicates (empty/16-byte name, allocated data/WG names, deployment/generation/member/schema/digest/host-namespace) | all invalid cases exit 1; `wan_name_dot` positive control PASS | `/tmp/witness-r6-review/wan/` |
| Independent I16 four Link mutations | 4/4 exit 1, FAIL at `contract_success` specific messages | `/tmp/witness-r6-review/fixtures/wireguard_*.json`, `veth_hardware_type_wireguard.json` |
| I17 TUN value/count mutations | 2/2 exit 1, FAIL at `host_observation_bounds` | `/tmp/witness-r6-review/fixtures/veth_tun_*.json` |
| I18 six-pin mode mutation | exit 1, FAIL at `recorded_emitters` | `/tmp/witness-r6-review/fixtures/binding_group_mode_writable.json` |
| Pending predicate mutation | `tun_info=[[1,[0]]]` on 17 veth / 28 WG links still exit 0, PASS 24/24; disclosed as pending | `/tmp/witness-r6-review/tun-veth/` |
| 20-predicate pending sample | 17 live/opaque/synthetic; 3 serialized-but-constrained; no unconstrained sample case | `/tmp/witness-r6-review/pending-sample.txt` |
| Extractor regeneration | exit 0; byte-identical to checked-in contract | `/tmp/witness-r6-review/extract/contract.json`; SHA `a19efb...` |
| Extractor closure mutation | exit 1; `unresolved validation callees` for removed `memmem` | `/tmp/witness-r6-review/extractor-mut2.py`, `extract/mut2.stderr` |
| Full witness suite (`nice -n 10`) | exit 0; 46 tests; 476.430 s; 28,782 leaves; 102,334 end-to-end mutations; 109/109 reconstructed negative CLI cases fail | `/tmp/witness-r6-review/full-suite.log` |
| Focused closure/classifier tests | exit 0; 5 tests; 2.483 s | `/tmp/witness-r6-review/focused.log` |
| `test-run410-fixes.py` | exit 0; 8 tests | `/tmp/witness-r6-review/test-run410-fixes.log` |
| `test-run410-isolation.py` | exit 0; 21 tests | `/tmp/witness-r6-review/test-run410-isolation.log` |
| `test-run410-provenance.py` | exit 0; 21 tests | `/tmp/witness-r6-review/test-run410-provenance.log` |
| `test-run410-reservation.py` | exit 0; 12 checks; `real_lab_claim_created=false` | `/tmp/witness-r6-review/test-run410-reservation.log` |
| `py_compile` (validator, test, extractor, four run410 tests) | exit 0; 7 files; cache outside checkout | `/tmp/witness-r6-review/pycache` |
| `git diff --check` | exit 0 | shell run at review end |
| Read-only `strace` | 148 read opens; zero write syscalls | `/tmp/witness-r6-review/strace-readonly.txt` |
| Receipt `strace` | one `O_EXCL|O_NOFOLLOW` 0600 write open; fchmod; two fsync; no other mutation | `/tmp/witness-r6-review/strace.txt` |
| Overwrite/symlink refusal | exit 1; existing bytes and sentinel unchanged | `/tmp/witness-r6-review/overwrite.stderr`, `symlink.stderr` |
| Optimized Python `-O`/`-OO` | exit 1; `optimized_python_refused`; no receipt | `/tmp/witness-r6-review/optimized-O*.stderr` |
| r1-r5 preservation | 5 receipts plus raw record hashes/sizes/modes unchanged | `/tmp/run410-witness-r6-t1bf_lfd/preservation-before.json`; current hashes match |
| Runtime/native/release acceptance | NOT_RUN; not granted | This review's scope |

## Scope limits

- This is offline recorded-consistency validation relative to the frozen Rust
  contract. It is not runtime acceptance, native custody replay, ARM/guest
  execution, migration/soak acceptance, or release readiness.
- The original 96 reviewer fixture bytes are lost; the 109-case suite is a
  reconstruction from the five reports, and the report says so.
- The extractor remains a bounded lexical inventory, not a Rust parser/type
  checker. M4 limits (tail-expression errors, let-else, conditional bodies with
  preceding statements, generic/tuple serde declarations, nested inline-module
  identities, rename/flatten, discriminants, const-symbol array lengths,
  complex comments and macro-generated syntax) remain and are disclosed in the
  report. The call graph is not a compiler closure proof.
- The 10,669 pending predicates are a real coverage gap. The r6 receipt and
  report disclose it; they do not claim full typed validation. A future round
  should implement the trivially decidable pending projections, beginning with
  the Link kind/TUN predicate in M6, and add a stale-lineage test per M7.
