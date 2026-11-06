# Independent re-review 2: run-410 witness validator, third round

2026-11-06. Repository `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`,
HEAD `5e989eeeea3092cc59675bd78ad37e06fce2d7c0`.

**Verdict: FAIL.** All **29** earlier reviewer mutations now FAIL through the
actual CLI, and the real record PASSES all **19** groups. The implementer's
30-test suite, including its 102,334 leaf mutations, also passes. However, an
independent source-driven sweep reproduced **15 new false PASS fixtures**:
nine contradict the retained transport creation/mount chain; six contradict
WireGuard down-only or original-move evidence. Each exits **0**, verdict
**PASS**, with **19/19** groups. These are two Important findings, not evidence
that the original run failed. No Critical findings. One Minor test/documentation
finding is separate below.

No subagents were started. All Python executions used `python3 -B` (also with
`-O`/`-OO` for refusal checks). Scratch scripts, mutation records, stdout/stderr
and logs are under `/tmp/vprouter-witness-r3/`. Only this report was written
inside the repository. No Cargo, sudo, network, VM/guest/native experiment,
Git staging/commit/push, claim or reservation mutation occurred.

## Important I9: fresh transport observations are not bound to canonical history

Locations: `tools/rust-v2-lab/validate-run410-witness.py:2110-2118`, together
with `:1806-1817`. The latter validates canonical `preparation.fresh_transport`
and its mount, but the former checks only status/EOF/retention/counters on
`TransportWitness` and `MountWitness`. It never binds the separate provision
`transport_creation` and `transport_mount` observations to those histories.

Let `P` be
`host_addition.producer_binding.assembly.quarantine.movement.provision`.
Independent fixtures below change the specified observation, preserving the
canonical preparation and all its retained copies. All return PASS19/19.

| Fixture basename (`.json`) | Concrete mutation |
| --- | --- |
| `transport_creation_source_is_host` | `P.transport_creation.source = P.transport_creation.host` |
| `transport_creation_source_is_data` | `P.transport_creation.source = P.transport_creation.data` |
| `transport_creation_source_foreign` | Increment only the creation observation's source inode by100 |
| `transport_creation_and_mount_foreign_source` | Increment creation source inode by100 and give mount `original_source` the same substituted identity; canonical transport namespace stays original |
| `transport_mount_source_foreign` | Increment only mount `original_source.ino` by100 |
| `transport_creation_host_foreign` | Increment only creation observation's host inode by100 |
| `transport_creation_data_foreign` | Increment only creation observation's data inode by100 |
| `transport_mount_directory_foreign` | Increment only mount `original_directory.ino` by100 |
| `transport_mount_wrong_placeholder_mode` | Set only native mount observation's `placeholder.mode=0o100666`, leaving canonical placeholder mode `0o100600` |

The first five directly violate explicit successful-emitter checks at
`crates/vprouter-launch/src/attachment/provision.rs:878-885`: source must be
distinct from host/data, mount original source must equal creation source, and
preparation transport namespace must equal creation source. The coordinated
foreign-source case satisfies observation-to-observation equality but still
violates preparation-to-observation equality.

The remaining fields are also emitted from the original request and placeholder,
not free-standing observations: `kernel/fresh_transport.rs:498-505` emits source,
host and data; `kernel/fresh_transport_mount.rs:852-861` emits original source,
directory and placeholder. Canonical transport history is checked against the
original request at `owned/preparation/fresh_transport.rs:112-120`; mount
history/request equality is at `owned/preparation/fresh_mount.rs:115-120`.
Publication specifically requires the same native birth and placeholder at
`owned/preparation/fresh_mount.rs:452-453`. Native placeholder mode is required
to be exactly `0o100600` at `kernel/fresh_transport_mount.rs:465-474`.
All the metadata needed to detect these contradictions already exists in JSON.
No new live FD observation is necessary.

Required correction: bind both native transport observations to the original
creation/mount histories, including source/host/data/directory/placeholder and
recorded request, birth and time fields, and reproduce the explicit provision
success guard. Add coordinated source substitution and correctly typed mode
mutations. Existing counter and boolean checks do not establish those bindings.

## Important I10: WireGuard result checks omit down-only and original-move guards

Locations: `tools/rust-v2-lab/validate-run410-witness.py:1828-1835` checks result
namespace and presence of link/WireGuard objects; `:2154-2160` checks inventory
flags/counters and registrations. Neither validates the actual link's down-only
state/kind or the move's equality to the original transport result.

The following fresh fixtures keep all copies of each altered result consistent,
so original-operation/history and retained-prefix equality still hold. Each
returns exit0, PASS19/19.

| Fixture basename (`.json`) | Concrete mutation |
| --- | --- |
| `wireguard_up_all_copies` | Set `up=true` on every WireGuard Link object, leaving `wireguard_down_only=true` and all authority flags false |
| `wireguard_wrong_link_kind_all_copies` | Change each WireGuard Link's kind to `veth`, leaving successful WireGuard operations and results populated |
| `moved_wireguard_name_substitution` | Set only DATA move-result link names and their retained copies to `foreignwg` |
| `moved_wireguard_alias_substitution` | Set only DATA move-result link aliases and their retained copies to `foreign-alias` |
| `moved_wireguard_key_substitution` | Flip byte0 of only DATA move-result WireGuard public keys and their retained copies |
| `moved_wireguard_peers_removed` | Remove only DATA move-result WireGuard peers and their retained copies |

The moved-result mutations leave the original transport provision/query results
unchanged. Rust explicitly rejects these scenarios:
`crates/vprouter-launch/src/attachment/provision.rs:1002-1005` requires the
provision/query result links to be down and kind `wireguard`;
`attachment/movement.rs:824-835` requires the moved link to be down, kind
`wireguard`, and preserve original name, alias, public key and peers.
Checking the emitted `wireguard_down_only` boolean does not check the result.

Required correction: enforce these successful-emitter comparisons against the
original transport query/provision result as well as operation/history equality.
Use the six fixtures as end-to-end regressions. This is a recorded-evidence
consistency gap, not a claim that live WireGuard state was UP or substituted.

## Minor M2: the leaf sweep's Rust-width map misses Route.kind

Location: `tools/rust-v2-lab/test-validate-run410-witness.py:35,116-122`, and the
report's width-map description at
`.superpowers/sdd/rust-v2/task-8c-run410-witness-validation.md:45-47`.
`Route.kind` is `u8` at `crates/vprouter-network/src/project.rs:68`, correctly
listed as such in report row849 and correctly typed by the validator. But
`kind` is absent from `U8_FIELDS`; integer `kind` leaves fall through to64 bits.
The sweep therefore tests overflow `2**64`, not the actual `u8` boundary256.

This is a verified test/documentation limitation, **not a reproduced validator
false PASS**. Independent `route_kind_actual_u8_overflow.json` uses256 and is
correctly rejected by `typed_witness`. Add a contextual numeric Route.kind map
entry and narrow the claim that every overflow mutation uses its Rust width.
No additional suspected validator false PASS is reported without reproduction.

## Earlier-review fixture ledger

`python3 -B /tmp/vprouter-witness-r3/prior-cli.py` directly reads each retained
fixture's bytes and launches `python3 -B tools/rust-v2-lab/validate-run410-witness.py
<fixture>`. It does not import the implementer's tests, regenerate fixtures or
normalize duplicate-key/NaN inputs. The first18 names below are under
`/tmp/vprouter-witness-review/`; the next11 under
`/tmp/vprouter-witness-rereview/`. Full outputs are retained alongside
`prior-cli-results.json`.

| Fixture basename | CLI exit | Verdict | Failed groups |
| --- | --- | --- | --- |
| authorization | 1 | FAIL | no_authority |
| boot_id | 1 | FAIL | preparation_success, owner_identity |
| charge | 1 | FAIL | charge_conservation |
| deadline | 1 | FAIL | monotonic_deadlines, bootstrap_scopes |
| drop_row | 1 | FAIL | stdout_rows |
| duplicate_key | 1 | FAIL | strict_record_json |
| fault | 1 | FAIL | bootstrap_success |
| nan | 1 | FAIL | stdout_rows |
| unknown_field | 1 | FAIL | typed_witness |
| binding_result_8pins | 1 | FAIL | typed_witness |
| bootstrap_result_6pins | 1 | FAIL | typed_witness |
| own_intent_identity | 1 | FAIL | bootstrap_success |
| query_intent_index | 1 | FAIL | bootstrap_success |
| preparation_fenced | 1 | FAIL | preparation_success, canonical_histories |
| preparation_pending | 1 | FAIL | preparation_success, canonical_histories |
| preparation_phase | 1 | FAIL | typed_witness |
| preparation_unreaped | 1 | FAIL | preparation_success, canonical_histories |
| retained_prefix_birth | 1 | FAIL | preparation_success, writer_histories |
| bootstrap_query_u32_pid_overflow | 1 | FAIL | typed_witness |
| bootstrap_query_has_initial | 1 | FAIL | canonical_histories, bootstrap_scopes |
| host_bootstrap_policy_wrong_kind | 1 | FAIL | retained_success, canonical_histories, bootstrap_scopes |
| host_bootstrap_policy_wrong_scope | 1 | FAIL | retained_success, canonical_histories, bootstrap_scopes |
| entry_producer_binding_mismatch_all_prefixes | 1 | FAIL | canonical_histories |
| binding_policy_mismatch_canonical_all_prefixes | 1 | FAIL | canonical_histories |
| binding_query_mismatch_all_prefixes | 1 | FAIL | canonical_histories |
| binding_data_mismatch_all_prefixes | 1 | FAIL | canonical_histories |
| host_fault_nonzero | 1 | FAIL | retained_success |
| host_negative_count_zero | 1 | FAIL | retained_success |
| host_own_intent_identity | 1 | FAIL | retained_success |

The real `target/lab-state/actual-program-run-410.json` independently returns
exit0, PASS19/19. An independently reserialized copy (envelope and every stdout
JSON row/witness reserialized with sorted keys) also returns exit0, PASS19/19.
Thus I1-I8's retained reproductions are closed. M1's corrected handoff citation
`attachment/operational.rs:584-588` contains the emitted evidence JSON.

## Source sweep and table assessment

The review traced successful history validation in `owned/preparation.rs` and
its Bootstrap, inspection, mount, fresh transport/mount, wireguard, movement,
quarantine, producer creation/binding, host-link and assembly modules; the
operational owner and Bootstrap/pin guards; and the retained host-addition
success branch. It then followed the transport and movement result emitters
where the new contradictions originated. Twenty-two relevant Rust files were
compared byte-for-byte with the frozen candidate's `source.tar`, read without
extraction; all match (`frozen-source-results.json`). These findings therefore
apply to the frozen emitter, not just a changed working source.

The independently authored scripts `fresh.py`, `fresh-more.py` and
`fresh-movement.py` generated **37** new mutations. Each asserts that the
mutation changes the decoded witness and invokes the real CLI. **22 are
rejected**, including coordinated u32 birth overflow, writable/duplicate
Bootstrap pins, UP host-veth results, binding-query initial evidence, wrong
policy scope, incorrect host intent count, native u8/u16/u32/u64/i32 boundaries,
invalid origin digests, broken DATA mount source, and true authority. **15 are
incorrectly accepted**, exactly the fixtures in I9/I10. Results are retained in
`fresh-results.json`, `fresh-more-results.json`, `fresh-movement-results.json`,
with each record and per-fixture stdout/stderr. The scripts' exit0 records
successful execution of the probes; it does not mean all probes were rejected.

The following **21 field-table rows** were independently checked at their
literal cited Rust source line, without using the implementer's source inventory
test. All field declarations and reported underlying types match. Optional
fields may be narrowed by the completed-success profile, as the report explains.
`table-spotchecks.json` records the exact Rust declaration and report row.

| Field | Report line | Rust source | Checked type |
| --- | --- | --- | --- |
| Birth.pid | 204 | `crates/vprouter-launch/src/owned/preparation.rs:79` | `u32` |
| Birth.start | 205 | `crates/vprouter-launch/src/owned/preparation.rs:80` | `u64` |
| Birth.born_at | 202 | `crates/vprouter-launch/src/owned/preparation.rs:81` | `f64` |
| Birth.deadline | 203 | `crates/vprouter-launch/src/owned/preparation.rs:82` | `f64` |
| Link.hardware_type | 460 | `crates/vprouter-network/src/project.rs:33` | `u16` |
| Link.index | 462 | `crates/vprouter-network/src/project.rs:27` | `u32` |
| Link.peer_index | 467 | `crates/vprouter-network/src/project.rs:32` | `Option<u32>` |
| Address.prefix | 117 | `crates/vprouter-network/src/project.rs:54` | `u8` |
| Address.route_priority | 118 | `crates/vprouter-network/src/project.rs:50` | `Option<u32>` |
| Route.kind | 849 | `crates/vprouter-network/src/project.rs:68` | `u8` |
| Rule.protocol | 866 | `crates/vprouter-network/src/project.rs:88` | `Option<u8>` |
| OwnerEpoch.pid | 579 | `crates/vprouter-launch/src/supervision.rs:41` | `u32` |
| HostLinkHistory.admission | 391 | `crates/vprouter-launch/src/owned/preparation/host_link.rs:14` | `[f64; 3]` |
| HostLinkHistory.addition | 390 | `crates/vprouter-launch/src/owned/preparation/host_link.rs:17` | `Option<([u8; 32], u32)>` |
| ProducerBindingResult.pins | 679 | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:11` | `[(u64, u64, u32); 6]` |
| BootstrapHistory.pins | 211 | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:27` | `[(u64, u64, u32); 8]` |
| BootstrapResult.pins | 252 | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:12` | `[(u64, u64, u32); 8]` |
| InspectionHistory.initial | 440 | `crates/vprouter-launch/src/owned/preparation/inspection.rs:10` | `Option<Initial>` |
| FreshTransport.source | 318 | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:16` | `Option<Identity>` |
| MountHistory.mounted_at | 476 | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:16` | `Option<f64>` |
| QueryFacts.pid | 833 | `crates/vprouter-launch/src/attachment.rs:793` | `u32` |

The recorded-success ledger also agrees with Rust for final preparation
flags/prefix, Bootstrap's three scope kinds and completed queries, six/eight pin
sizes, canonical InitialQuarantine scope, binding publication, intent87/90
identity, host intent75 and its emitted held count2 (`held_polls-1`), host
inventory/charges and pre-drop continuation, and handoff20=15+5/retirement5.
The report's ledger rows1788-1789 overstate down-only and original transport
coverage because of I9/I10. Typing every leaf is not semantic guard coverage.

The generic sweep description is otherwise accurate: recursive traversal
includes all repeated copies and empty arrays; it tests wrong types, absent
object leaf keys, null populated array leaves, negative integers and overflow
values. The code serializes each temporary record and actually invokes
`validate()`, with eight local Python worker processes and no agent delegation.
An independent traversal reproduces **28,782 leaves** and the mutation formula
**102,334**; the full test run reports the same numbers and passes. This is a
single-leaf structural/range sweep, with the Route.kind width exception above;
it does not establish the omitted correctly typed/coordinated comparisons.
The report's historical RED-first sequence was not independently reconstructed.

## Read-only behavior, receipts and claim boundaries

PASS for offline IO/receipt safety and explicit runtime/release limitations.
The standard-library validator reads the record, frozen reservation/claim,
source and artifacts; it does not import controller code. Source inspection and
a rerun of the prior independent audit hook (scratch directory changed to r3)
observed **61 read opens** and no validation writes. The receipt exercise
observed two write-open attempts to the selected scratch receipt: successful
creation and refused overwrite. The hook rejects subprocess/system calls,
network connect/bind, preserved-tree access, other write opens and filesystem
remove/rename/link/mkdir mutations. None occurred during validation/receipt
calls. FD writes, fchmod and fsync were separately inspected; this is a bounded
Python audit, not a whole-machine syscall trace.

`save_receipt()` at validator lines2390-2401 uses
`O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC`, mode0600, `fchmod(0600)`, file
fsync and parent-directory fsync. Independent CLI creation also succeeds with
mode0600; a second CLI creation exits1 and preserves the bytes. CLI symlink
creation exits1 and leaves its sentinel target unchanged. Independent
`python3 -B -O` and `python3 -B -OO` runs exit1 with
`RuntimeError: optimized_python_refused` and create no receipt; the guard is
unconditional at validator lines17-18. See `io-results.json` and
`cli-receipt-results.json`.

The existing r3 receipt is mode0600, SHA256
`f004b626169bb8481c5d61780c10cbcad382f328a38982bb183e4c2a572b37f6`, and its parsed
object equals fresh CLI validation of the real relative record path. Its
`runtime_acceptance=false`, `release_ready=false`, superseded r1/r2 paths and
seven `does_not_prove` limitations are correct. Source/report explicitly leave
Task8c/requirement8, real clients/leaks, multi-exit/direct/fault runtime, ARM,
performance, migration/reboot/rollback/soak and current custody/liveness open.
Those limits do not excuse the detectable contradictions in I9/I10; the
`full_bootstrap_witness_validation=PASS` label still exceeds checked semantic
coverage. None of this authorizes another experiment or changes run410's
consumed state.

## Verification ledger

| Check | Result | Scratch evidence |
| --- | --- | --- |
| All29 earlier mutation files through actual CLI | All exit1 / FAIL; no regenerated fixtures | `prior-cli.py`, `prior-cli-results.json`, per-fixture CLI outputs |
| Real raw record through actual CLI | exit0, PASS19/19; raw SHA256 `bd3d1819f6387491c69388b371f9b05fa28d5e773658223f950ffd743413f0ff` | `actual-program-run-410.cli.stdout` |
| Independently reserialized real record | exit0, PASS19/19 | `real-reserialized.json`, `real-reserialized.stdout` |
| New independent source-driven mutations | 37 executed; 22 FAIL, 15 false PASS19/19 | Three fresh scripts/results files and all37 fixtures/outputs |
| `python3 -B tools/rust-v2-lab/test-validate-run410-witness.py` | exit0; 30 tests, 353.385s; 102,334 leaf mutations rejected | `test-validate-run410-witness.log` |
| `python3 -B tools/rust-v2-lab/test-run410-fixes.py` | exit0; 8 tests; existing generated-template SyntaxWarnings | `test-run410-fixes.log` |
| `python3 -B tools/rust-v2-lab/test-run410-isolation.py` | exit0; 21 tests | `test-run410-isolation.log` |
| `python3 -B tools/rust-v2-lab/test-run410-provenance.py` | exit0; 21 tests | `test-run410-provenance.log` |
| `python3 -B tools/rust-v2-lab/test-run410-reservation.py` | exit0; 12 checks; `real_lab_claim_created=false` | `test-run410-reservation.log` |
| `python3 -B -m py_compile` validator, new test and all4 `test-run410-*.py` | exit0; explicit compilation output confined with `PYTHONPYCACHEPREFIX=/tmp/vprouter-witness-r3/pycache` | `py_compile.log`, `suite-results.json` |
| `git diff --check` | exit0 | `git-diff-check.log` |
| IO, exclusive0600 receipt, overwrite/symlink refusal, -O/-OO refusal | All independent assertions pass | `io-review.py`, `io-results.json`, `cli-receipt-results.json` |
| Rust source vs frozen archive | All22 selected files byte-identical | `frozen-source-results.json` |
| Literal Rust type-table source spot-check | All21 rows match | `spotcheck.py`, `table-spotchecks.json` |
| Independent leaf inventory/count formula | 28,782 leaves, 102,334 mutations | `leaf-inventory.json` |
| Preservation and Git identity | All784 baseline file hashes/sizes/modes unchanged; only this report added in monitored trees; `rust/v2` at requested HEAD, dirty status unchanged | `baseline.json`, `preservation-results.json` |
| Cargo/sudo/network/VM/runtime/release acceptance | NOT_RUN, outside authorized offline scope | No acceptance inferred from offline PASS results |

Temporary suite writes were directed under the scratch directory using TMPDIR;
`-B` prevents implicit repo bytecode writes, while explicit py_compile output
was separately redirected. The preservation baseline includes lab-state,
run410 evidence, candidate artifacts, lab tools and SDD reports/progress.
The index is external to this worktree and is not part of that file baseline;
no index-byte preservation claim is inferred from status. The pre-existing
progress edit and both untracked tools remain unchanged. No validator, test,
implementation report or original receipt was fixed by this reviewer.
