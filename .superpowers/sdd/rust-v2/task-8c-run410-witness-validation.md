# Task 8c run-410 offline witness validation, revision 4

2026-11-06. Implementation delegate, no subagents. Branch `rust/v2`, HEAD
`35c3befd8e8bee60b00630d0a9171eefaad199ac`.

Revision 4 **supersedes revision 3**, including its full-validation claims and
its final controller disposition leaving I9/I10/M2 open. I9, I10 and M2 are fixed
in this implementation candidate with RED/GREEN evidence below. This is not an
independent fourth-review acceptance or an exhaustive proof of Rust execution.
All three review reports remain unchanged. Task 8c/requirement 8, runtime and
release acceptance remain open: `runtime_acceptance=false`, `release_ready=false`.

Owned changes: `tools/rust-v2-lab/validate-run410-witness.py`, its
`test-validate-run410-witness.py`, this report, and the exclusively created
`target/run410-evidence/witness-validation-r4.json`. Concurrent performance work
is outside this delegate's scope. No staging, commits, Git writes, Cargo, sudo,
network, VM operations or accesses to `/DATA/vprouter-lab/preserved` were used.
Run409/run410 records, claims and reservations were only read.

Raw record: `target/lab-state/actual-program-run-410.json`, SHA256
`bd3d1819f6387491c69388b371f9b05fa28d5e773658223f950ffd743413f0ff`.
Its stdout retains 14 ordered rows; row 13 is the Bootstrap witness. Frozen
candidate source commit: `da7556282d5fc828a9391a64ab47adab05a55510`.
All 24 source files used by the serde inventory and new transport/WireGuard/
Bootstrap checks were compared to `source.tar` without extraction: byte-identical.

| Historical receipt, preserved verbatim | SHA256 | Disposition |
| --- | --- | --- |
| `witness-validation.json` | `f75a0edf98406455c6c9dcd8cd59442b233f1125865f07e463595bc08b7ccbc0` | SUPERSEDED |
| `witness-validation-r2.json` | `84a38df64f375e2e25043fd3c86b4471a82e44d06080a33e4dc803e915eadeda` | SUPERSEDED |
| `witness-validation-r3.json` | `f004b626169bb8481c5d61780c10cbcad382f328a38982bb183e4c2a572b37f6` | SUPERSEDED |

## Tests first: fail before, pass after

The first change was tests, followed by a RED run against the unchanged revision3
validator. `test_round3_fifteen_reviewer_fixtures_through_validate` read the exact
15 reviewer JSON files under `/tmp/vprouter-witness-r3/` without rewriting them.
**All15 falsely passed**, producing15 assertion failures. The same run reproduced
M2's map error (`64 != 8`), missing registry coverage, and eight additional accepted
transport-field substitutions: 25 failing subtests overall. Both the real record
and a reserialized copy passed. Evidence: `/tmp/vprouter-witness-r4/red.log`.
The shell wrapper displayed that log after the test; the unittest log itself
records `FAILED (failures=25)` and the underlying test process exited1.

| Finding | Exact reviewer fixtures exercised through `validate()` | Correction |
| --- | --- | --- |
| I9 | `transport_creation_source_is_host`, `transport_creation_source_is_data`, `transport_creation_source_foreign`, `transport_creation_and_mount_foreign_source`, `transport_mount_source_foreign`, `transport_creation_host_foreign`, `transport_creation_data_foreign`, `transport_mount_directory_foreign`, `transport_mount_wrong_placeholder_mode` | creation and mount observations bind to canonical preparation history, including coordinated source substitution |
| I10 | `wireguard_up_all_copies`, `wireguard_wrong_link_kind_all_copies`, `moved_wireguard_name_substitution`, `moved_wireguard_alias_substitution`, `moved_wireguard_key_substitution`, `moved_wireguard_peers_removed` | actual results must remain down and kind wireguard; moved name/alias/key/peers equal the original query result |
| M2 | Route.kind changed to256 through `validate()`; sweep width asserted independently | validator already rejected256; sweep now uses u8 instead of its former64-bit fallback |

`test_all_transport_observation_binding_fields_through_validate` also independently
mutates each emitted creation/mount binding field: request, source/host/data,
placeholder, original directory/source, complete birth (PID/start), timestamps and
deadline. All14 substitutions are rejected after the fix. Six were already
rejected before by timing/resource constraints; the other eight exposed the
missing binding (the first RED log enumerates those eight accepted cases).

The source-width differential test was then written and failed with241 width
mismatches, including optional null fields. The map now explicitly handles
Route.kind=u8; headroom/tailroom=u16; max_pacing_offload_horizon, fwmark, fwmask,
suppress_ifgroup, goto and realm=u32. These optional fields are null in this
record, so the original leaf sweep alone would not catch a missing map entry.
A source-derived nested TUN tuple test additionally failed for row1's u16
component before correcting the contextual tuple map. Unknown integer field or
array paths now raise, with no implicit64-bit fallback.

The final registry audit also reproduced one additional correctly typed false
PASS: changing only the first inspection observation's kind from Initial to
BootstrapHostRecheck. The canonical Initial sub-history does not carry its own
kind. `initial_query_kind` now binds that observation to the fixed Rust Initial
discriminator (`owned/preparation/inspection.rs:142,864-875`), using the same
generic binder rather than an observation-specific branch. The new test
`test_initial_observation_kind_cannot_claim_another_query_stage` failed before
and passed after, while real/reserialized records still passed. Evidence:
`initial-kind-red.log` and `initial-kind-green.log` in the final scratch directory.

A further RED/GREEN coverage test removes only the transport creation deadline
mapping. Coverage now fails that observation even though its birth remains bound.
New observation objects injected at root and inside fresh_transport also fail
coverage. All tests exercise real validation or the source/registry completeness
mechanism; no receipt verdict or validation function is mocked.

## Rust contracts ported for I9/I10

I9 bindings follow `crates/vprouter-launch/src/kernel/fresh_transport.rs:498-505`
and `kernel/fresh_transport_mount.rs:852-861`: both emit the original request and
native birth facts. Request/history guards are at
`owned/preparation/fresh_transport.rs:112-120` and
`owned/preparation/fresh_mount.rs:115-120`; mount publication requires the same
birth and placeholder at `fresh_mount.rs:452-453`. Exact placeholder mode0100600
is required at `kernel/fresh_transport_mount.rs:465-474`.

Creation compares request/source/host/data/birth/requested_at/deadline/verified_at.
Mount compares original_source->source, original_directory->directory,
placeholder/birth/requested_at/deadline. Full Identity and Birth equality covers
dev/ino, PID/start, born_at and birth deadline. Mount observations do not serialize
request digest/name/directory-name separately: canonical creation/mount names and
directory/source histories remain checked against each other and the allocated
transport name in `canonical_histories`, following
`owned/preparation/fresh_mount.rs:25-36`. No absent observation field is invented.
Together these bindings and the canonical distinctness checks reproduce
`attachment/provision.rs:878-885` (source distinct from host/data, creation source
= mount source = preparation transport namespace).

I10 keeps `owned/preparation/wireguard.rs:65-150`'s kind/namespace/configuration,
predecessor/query/time/result-presence checks and adds the actual result-link
checks from `attachment/provision.rs:1002-1005`. Every populated provision/query/
move result must have `link.up=false`, `link.kind=wireguard`.
`original_wireguard_move` in the generic registry implements
`attachment/movement.rs:824-835`: DATA move name, alias, public key and peers equal
the original TRANSPORT query result, with destination checked canonically.
The network path is `vprouter-network/src/secret_role.rs:164-169,408-412` and
`secret_role/movement.rs:352-425`; this checkout has no wg*.rs submodule. Live
readbacks in those functions remain native-only.

## Explicit binding registry

`BINDING_REGISTRY` is the executable list of67 entries. `bind_observations` is its
single comparison engine; field aliases, array-index captures and historical
prefix projection are data, not per-emitter comparison branches. Existing
semantic success/order/type checks remain complementary. No observation value
chooses its own canonical source. Fixed source discriminators use the explicit
`expected` registry namespace; Initial History omits a kind field, so the first
query is bound to the Rust Initial discriminator there. Full exported registry and coverage results:
`/dev/shm/vprouter-witness-r4/binding-registry.json` and `binding-coverage.json`.

Notation for the complete registry table: `P=witness.preparation`,
`H=witness.host_addition`, `B=H.producer_binding`, `A=B.assembly`,
`Q=A.quarantine`, `M=Q.movement`, `V=M.provision`, `T=V.attachment`.
`*` captures the same array index at both paths. A single field name compares
identically named fields; `left->right` is an alias. `root` explicitly marks
canonical recorded evidence with the named guards; it is never counted as an
equality to a separate serialized object. A root cannot establish live origin.
Projection compares every populated historical field and array prefix to P;
earlier null/empty history slots retain their stage/cardinality guards.

| Observation | Canonical source | Compared fields / mode |
| --- | --- | --- |
| `P` | `canonical root` | attachment, base_network, birth, bootstrap, bootstrap_queries, canonical_owner_epoch, data_network, deadline, entry_producer, fresh_transport, host_link, inspection, member, movement_query, netfilter, producer_binding, producer_binding_query, producer_creation, producer_query, quarantine_query, requested_at, transport_network, wireguard, writers; root; guards=canonical_histories,bootstrap_scopes,owner_identity,writer_histories,monotonic_deadlines |
| `witness.handoff.preparation` | `P` | attachment, base_network, birth, bootstrap, bootstrap_queries, canonical_owner_epoch, data_network, deadline, entry_producer, fresh_transport, host_link, inspection, member, movement_query, netfilter, producer_binding, producer_binding_query, producer_creation, producer_query, quarantine_query, requested_at, transport_network, wireguard, writers; projection; guards=preparation_success,retained_success |
| `H.preparation` | `P` | attachment, base_network, birth, bootstrap, bootstrap_queries, canonical_owner_epoch, data_network, deadline, entry_producer, fresh_transport, host_link, inspection, member, movement_query, netfilter, producer_binding, producer_binding_query, producer_creation, producer_query, quarantine_query, requested_at, transport_network, wireguard, writers; projection; guards=preparation_success,retained_success |
| `B.preparation` | `P` | attachment, base_network, birth, bootstrap, bootstrap_queries, canonical_owner_epoch, data_network, deadline, entry_producer, fresh_transport, host_link, inspection, member, movement_query, netfilter, producer_binding, producer_binding_query, producer_creation, producer_query, quarantine_query, requested_at, transport_network, wireguard, writers; projection; guards=preparation_success,retained_success |
| `A.preparation` | `P` | attachment, base_network, birth, bootstrap, bootstrap_queries, canonical_owner_epoch, data_network, deadline, entry_producer, fresh_transport, host_link, inspection, member, movement_query, netfilter, producer_binding, producer_binding_query, producer_creation, producer_query, quarantine_query, requested_at, transport_network, wireguard, writers; projection; guards=preparation_success,retained_success |
| `Q.preparation` | `P` | attachment, base_network, birth, bootstrap, bootstrap_queries, canonical_owner_epoch, data_network, deadline, entry_producer, fresh_transport, host_link, inspection, member, movement_query, netfilter, producer_binding, producer_binding_query, producer_creation, producer_query, quarantine_query, requested_at, transport_network, wireguard, writers; projection; guards=preparation_success,retained_success |
| `M.preparation` | `P` | attachment, base_network, birth, bootstrap, bootstrap_queries, canonical_owner_epoch, data_network, deadline, entry_producer, fresh_transport, host_link, inspection, member, movement_query, netfilter, producer_binding, producer_binding_query, producer_creation, producer_query, quarantine_query, requested_at, transport_network, wireguard, writers; projection; guards=preparation_success,retained_success |
| `V.preparation` | `P` | attachment, base_network, birth, bootstrap, bootstrap_queries, canonical_owner_epoch, data_network, deadline, entry_producer, fresh_transport, host_link, inspection, member, movement_query, netfilter, producer_binding, producer_binding_query, producer_creation, producer_query, quarantine_query, requested_at, transport_network, wireguard, writers; projection; guards=preparation_success,retained_success |
| `T.preparation` | `P` | attachment, base_network, birth, bootstrap, bootstrap_queries, canonical_owner_epoch, data_network, deadline, entry_producer, fresh_transport, host_link, inspection, member, movement_query, netfilter, producer_binding, producer_binding_query, producer_creation, producer_query, quarantine_query, requested_at, transport_network, wireguard, writers; projection; guards=preparation_success,retained_success |
| `V.transport_creation` | `P.fresh_transport` | request, source, host, data, birth, requested_at, deadline, verified_at |
| `V.transport_mount` | `P.fresh_transport.mount` | birth, requested_at, deadline, placeholder, original_source->source, original_directory->directory |
| `T.mount` | `P.attachment` | birth, requested_at, deadline, placeholder, original_source->source, original_directory->directory |
| `T.validator` | `P` | birth |
| `T.second_query` | `P.inspection` | kind, birth, facts, requested_at, deadline, verified_at |
| `T.postmount_query` | `P.attachment.query` | kind, birth, facts, requested_at, deadline, verified_at |
| `M.movement_query` | `P.movement_query` | kind, birth, facts, requested_at, deadline, verified_at |
| `Q.quarantine_query` | `P.quarantine_query` | kind, birth, facts, requested_at, deadline, verified_at |
| `Q.producer_query` | `P.producer_query` | kind, birth, facts, requested_at, deadline, verified_at |
| `B.query` | `P.producer_binding_query` | kind, birth, facts, requested_at, deadline, verified_at |
| `witness.queries.*` | `P.bootstrap_queries[*]` | kind, birth, facts, requested_at, deadline, verified_at |
| `T.first_query` | `P.inspection.initial` | birth, facts, verified_at |
| `T.first_query` | `expected.initial_query` | kind (fixed Initial discriminator) |
| `T.first_query` | `P.inspection` | requested_at, deadline |
| `V.operations[*]` | `P.wireguard[*]` | birth, kind, request, requested_at, deadline, result, accepted_at->verified_at, original_pid->birth.pid, original_start->birth.start |
| `M.operations[*]` | `P.wireguard[*]` | birth, kind, request, requested_at, deadline, result, accepted_at->verified_at, original_pid->birth.pid, original_start->birth.start |
| `Q.operations[*]` | `P.netfilter[*]` | birth, kind, request, requested_at, deadline, result, accepted_at->verified_at, original_pid->birth.pid, original_start->birth.start, scope |
| `H.operations[*]` | `P.host_link[*]` | birth, kind, request, requested_at, deadline, result, accepted_at->verified_at, original_pid->birth.pid, original_start->birth.start, namespace, host, declaration, admission, addition |
| `witness.operations.*` | `P.bootstrap[*]` | birth, request, requested_at, deadline, result, accepted_at->verified_at, original_pid->birth.pid, original_start->birth.start, namespace, scope, query, policy, pins, group |
| `witness.operations.*` | `P.producer_creation` | parent, name |
| `B.observation` | `P.producer_binding` | birth, request, requested_at, deadline, result, accepted_at->verified_at, original_pid->birth.pid, original_start->birth.start, parent, group, name, data, query, policy, pins |
| `Q.producer` | `P.producer_creation` | request, parent, group, name, data, query, birth, requested_at, deadline, verified_at, original_pid->birth.pid, original_start->birth.start |
| `B` | `P.producer_creation` | original_group->group |
| `H.own_intent_polling` | `P.writers[75]` | pid, start |
| `witness.own_query_intent_polling` | `P.writers[87]` | pid, start |
| `witness.own_intent_polling` | `P.writers[90]` | pid, start |
| `Q.own_intent_polling` | `P.writers[42]` | original_writer.pid->pid, original_writer.start->start, deadline->io_deadline, verified_at, actual_wait_status |
| `A.resources[0]` | `P.attachment.birth` | original_pid->pid, original_start->start |
| `A.resources[1]` | `P.fresh_transport.birth` | original_pid->pid, original_start->start |
| `A.resources[2]` | `P.fresh_transport.mount.birth` | original_pid->pid, original_start->start |
| `A.resources[3]` | `P.wireguard[0].birth` | original_pid->pid, original_start->start |
| `A.resources[4]` | `P.wireguard[1].birth` | original_pid->pid, original_start->start |
| `A.resources[5]` | `P.wireguard[2].birth` | original_pid->pid, original_start->start |
| `A.resources[6]` | `P.wireguard[3].birth` | original_pid->pid, original_start->start |
| `A.resources[7]` | `P.wireguard[4].birth` | original_pid->pid, original_start->start |
| `A.resources[8]` | `P.netfilter[0].birth` | original_pid->pid, original_start->start |
| `A.resources[9]` | `P.netfilter[1].birth` | original_pid->pid, original_start->start |
| `A.resources[10]` | `P.netfilter[2].birth` | original_pid->pid, original_start->start |
| `A.resources[11]` | `P.netfilter[3].birth` | original_pid->pid, original_start->start |
| `A.resources[12]` | `P.netfilter[4].birth` | original_pid->pid, original_start->start |
| `A.resources[13]` | `P.netfilter[5].birth` | original_pid->pid, original_start->start |
| `A.resources[14]` | `P.producer_creation.birth` | original_pid->pid, original_start->start |
| `A.reservation` | `P` | owner_epoch->canonical_owner_epoch, member |
| `witness.handoff.resources.0` | `P.producer_binding.birth` | original_pid->pid, original_start->start |
| `witness.handoff.resources.1` | `P.host_link[0].birth` | original_pid->pid, original_start->start |
| `witness.handoff.resources.2` | `P.host_link[1].birth` | original_pid->pid, original_start->start |
| `witness.handoff.resources.3` | `P.host_link[2].birth` | original_pid->pid, original_start->start |
| `witness.handoff.resources.4` | `P.host_link[3].birth` | original_pid->pid, original_start->start |
| `witness.handoff.reservation` | `P` | owner_epoch->canonical_owner_epoch, member |
| `P.wireguard[4].result` | `P.wireguard[2].result` | link.name, link.alias, wireguard.public_key, wireguard.peers |
| `H.admission` | `P.host_link[0]` | declaration, namespace->host, requested_at->admission.0, deadline->admission.1, accepted_at->admission.2 |
| `H.admission` | `rows.secret_host_baseline.0.declaration` | declared_baseline->baseline, namespace->host_namespace |
| `H.operations[3].host_observation` | `H.admission.declared_baseline` | namespace, addresses, routes, rules |
| `H.operations[3].host_observation` | `canonical root` | links; root; guards=retained_success |
| `Q.wan` | `rows.secret_quarantine_host.0.declaration` | host_namespace, name->wan.name, index->wan.index, address->wan.address |
| `Q.wan` | `canonical root` | requested_at, deadline, verified_at; root; guards=recorded_emitters,monotonic_deadlines |
| `A.foreign_eligibility` | `P.wireguard[0].birth` | eligible_original_pid->pid, eligible_original_start->start |
| `A.foreign_eligibility` | `canonical root` | original_pid, original_start, requested_at, deadline, verified_at; root; guards=recorded_emitters,monotonic_deadlines |

The real witness contains **1,615** observation-shaped objects (including every
retained copy); **0 are uncovered**. Coverage walks the raw witness independently
and recognizes pid/start/dev/ino/deadline/birth plus original/process/IO variants.
Each such object's identity-bearing fields must lie under explicit compared or
canonical-root fields. Traversal follows only declared schema edges, so a new
observation cannot inherit coverage from a parent. Removing an individual binding
field also fails coverage. Coverage is enforced during `validate()`, not merely
printed by the tests. It proves registry accounting, not native provenance or
that every possible relational guard has been independently verified.

## Source-derived sweep widths

`source_width_inventory()` in the test file is the requested extraction script.
It extracts names and types from all29 reachable serde structs (218 declared
fields), decomposes Option/Vec/fixed-array/tuple primitive types, and matches them
to every emitted occurrence, including optional null primitives. The reachable
inventory now includes wireguard History, kernel WireGuard/host PublicResult,
ProducerOwnership and HostObservation in addition to the24 previous shapes.
The private complete preparation journal is projected into this witness rather
than embedded wholesale; absent private-journal fields are not invented.

The independently maintained contextual emitter map is diffed against extracted
Rust primitive widths, including u8 Route.kind. Every one of28,782 actual leaves
has an inventory entry; nonnumeric/empty/null leaves have explicit type markers,
and every integer path must resolve to an explicit width. The source differential
also checks declared optional primitive fields that are null in this record.
The full sweep still serializes102,334 separate mutations and calls `validate()`
on each, including wrong type, missing object keys, null populated array slots,
negative integers and actual-width overflow. Eight local Python processes are
test workers, not delegated agents. A structural leaf sweep is not a substitute
for coordinated semantic mutations or the binding registry.

## Serialized field inventory

The retained field inventory below describes the successful emitted profile. `S` means
`test_every_real_witness_leaf_through_validate`; `R` additionally means
`test_rust_serialized_field_inventory_and_primitive_ranges`. Aggregates recurse
into the rows for their member shapes. Emitter-projection types use their
explicit JSON-builder origin; they are not fictitious Rust Deserialize structs.
Options may be narrowed to populated/null values by this successful-run profile.
HostBaseline is the serialized HostObservation shape, not a second Rust type.

| Field | Rust type / emitted success domain | Rust origin | Validator schema | Mutation test |
| --- | --- | --- | --- | --- |
| Address.address | `IpAddr` | `crates/vprouter-network/src/project.rs:53` | `Address` | S, R |
| Address.broadcast | `Option<Ipv4Addr>` | `crates/vprouter-network/src/project.rs:49` | `Address` | S, R |
| Address.flags | `u32` | `crates/vprouter-network/src/project.rs:51` | `Address` | S, R |
| Address.index | `u32` | `crates/vprouter-network/src/project.rs:52` | `Address` | S, R |
| Address.prefix | `u8` | `crates/vprouter-network/src/project.rs:54` | `Address` | S, R |
| Address.route_priority | `Option<u32>` | `crates/vprouter-network/src/project.rs:50` | `Address` | S, R |
| Address.scope | `u8` | `crates/vprouter-network/src/project.rs:55` | `Address` | S, R |
| Assembly.assembly_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:350` | `Assembly` | S |
| Assembly.charges_after | `emitted list(u64)` | `crates/vprouter-launch/src/attachment/assembly.rs:347` | `Assembly` | S |
| Assembly.charges_after_drop | `emitted null` | `crates/vprouter-launch/src/attachment/assembly.rs:347` | `Assembly` | S |
| Assembly.charges_before | `emitted list(u64)` | `crates/vprouter-launch/src/attachment/assembly.rs:347` | `Assembly` | S |
| Assembly.continued_original_context | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:354` | `Assembly` | S |
| Assembly.duplicate_reservation_counts | `emitted null` | `crates/vprouter-launch/src/attachment/assembly.rs:349` | `Assembly` | S |
| Assembly.duplicate_reservation_refused | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:348` | `Assembly` | S |
| Assembly.fault | `u8` | `crates/vprouter-launch/src/attachment/assembly.rs:346` | `Assembly` | S |
| Assembly.fence_blocked_next_transfer | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:349` | `Assembly` | S |
| Assembly.fence_counts | `emitted null` | `crates/vprouter-launch/src/attachment/assembly.rs:350` | `Assembly` | S |
| Assembly.foreign_eligibility | `emitted ForeignEligibility` | `crates/vprouter-launch/src/attachment/assembly.rs:346` | `Assembly` | S |
| Assembly.global_child_capacity_limit | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/assembly.rs:354` | `Assembly` | S |
| Assembly.handoff_complete | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:348` | `Assembly` | S |
| Assembly.lower_repeat_retirement_refused | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:349` | `Assembly` | S |
| Assembly.movement_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:351` | `Assembly` | S |
| Assembly.multi_exit_runtime_proven | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:354` | `Assembly` | S |
| Assembly.operational_reuse_authorized | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:353` | `Assembly` | S |
| Assembly.original_provision_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:352` | `Assembly` | S |
| Assembly.parent_pristine | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:352` | `Assembly` | S |
| Assembly.preparation | `emitted Preparation` | `crates/vprouter-launch/src/attachment/assembly.rs:346` | `Assembly` | S |
| Assembly.producer_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:351` | `Assembly` | S |
| Assembly.producer_operational_publication | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:353` | `Assembly` | S |
| Assembly.quarantine | `emitted Quarantine` | `crates/vprouter-launch/src/attachment/assembly.rs:346` | `Assembly` | S |
| Assembly.quarantine_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:351` | `Assembly` | S |
| Assembly.repeat_retirement_refused | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:349` | `Assembly` | S |
| Assembly.requirement8_complete | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:354` | `Assembly` | S |
| Assembly.reservation | `emitted AssemblyReservation` | `crates/vprouter-launch/src/attachment/assembly.rs:347` | `Assembly` | S |
| Assembly.resource_cleanup_authorized | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:353` | `Assembly` | S |
| Assembly.resources | `emitted list(Resource)` | `crates/vprouter-launch/src/attachment/assembly.rs:347` | `Assembly` | S |
| Assembly.retired_original_jobs | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/assembly.rs:348` | `Assembly` | S |
| Assembly.schema | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/assembly.rs:346` | `Assembly` | S |
| Assembly.up_authorized | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:353` | `Assembly` | S |
| Assembly.whole_chain_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:350` | `Assembly` | S |
| AssemblyReservation.complete | `bool` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:91` | `AssemblyReservation` | S |
| AssemblyReservation.global_assemblies_reserved | `u64/usize (amd64)` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:92` | `AssemblyReservation` | S |
| AssemblyReservation.global_assembly_limit | `u64/usize (amd64)` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:92` | `AssemblyReservation` | S |
| AssemblyReservation.global_transferred_ticket_limit | `u64/usize (amd64)` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:92` | `AssemblyReservation` | S |
| AssemblyReservation.member | `String` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:91` | `AssemblyReservation` | S |
| AssemblyReservation.member_transfer_pending | `bool` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:93` | `AssemblyReservation` | S |
| AssemblyReservation.original_jobs | `u64/usize (amd64)` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:91` | `AssemblyReservation` | S |
| AssemblyReservation.owner_epoch | `emitted OwnerEpoch` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:91` | `AssemblyReservation` | S |
| Attachment.birth | `Option<ValidationBirth>` | `crates/vprouter-launch/src/owned/preparation/mount.rs:21` | `Attachment` | S, R |
| Attachment.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation/mount.rs:20` | `Attachment` | S, R |
| Attachment.directory | `Identity` | `crates/vprouter-launch/src/owned/preparation/mount.rs:16` | `Attachment` | S, R |
| Attachment.mounted_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/mount.rs:23` | `Attachment` | S, R |
| Attachment.name | `String` | `crates/vprouter-launch/src/owned/preparation/mount.rs:17` | `Attachment` | S, R |
| Attachment.origin | `Origin` | `crates/vprouter-launch/src/owned/preparation/mount.rs:15` | `Attachment` | S, R |
| Attachment.placeholder | `Option<Placeholder>` | `crates/vprouter-launch/src/owned/preparation/mount.rs:22` | `Attachment` | S, R |
| Attachment.published_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/mount.rs:25` | `Attachment` | S, R |
| Attachment.query | `Option<inspection::History>` | `crates/vprouter-launch/src/owned/preparation/mount.rs:24` | `Attachment` | S, R |
| Attachment.request | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/mount.rs:14` | `Attachment` | S, R |
| Attachment.requested_at | `f64` | `crates/vprouter-launch/src/owned/preparation/mount.rs:19` | `Attachment` | S, R |
| Attachment.source | `Identity` | `crates/vprouter-launch/src/owned/preparation/mount.rs:18` | `Attachment` | S, R |
| AttachmentOrigin.container | `String` | `crates/vprouter-launch/src/attachment.rs:282` | `AttachmentOrigin` | S |
| AttachmentOrigin.kind | `emitted origin_kind` | `crates/vprouter-launch/src/attachment.rs:340` | `AttachmentOrigin` | S |
| AttachmentOrigin.launch | `String` | `crates/vprouter-launch/src/attachment.rs:282` | `AttachmentOrigin` | S |
| AttachmentOrigin.network | `emitted Identity` | `crates/vprouter-launch/src/attachment.rs:282` | `AttachmentOrigin` | S |
| AttachmentOrigin.process_start | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment.rs:282` | `AttachmentOrigin` | S |
| AttachmentOrigin.public_result | `[u8;32]` | `crates/vprouter-launch/src/attachment.rs:282` | `AttachmentOrigin` | S |
| AttachmentOrigin.staging | `String` | `crates/vprouter-launch/src/attachment.rs:336` | `AttachmentOrigin` | S |
| AttachmentWitness.base_published | `bool` | `crates/vprouter-launch/src/attachment/mount.rs:958` | `AttachmentWitness` | S |
| AttachmentWitness.fault | `u8` | `crates/vprouter-launch/src/attachment/mount.rs:950` | `AttachmentWitness` | S |
| AttachmentWitness.first_query | `emitted Query` | `crates/vprouter-launch/src/attachment/mount.rs:952` | `AttachmentWitness` | S |
| AttachmentWitness.held_real_writer | `bool` | `crates/vprouter-launch/src/attachment/mount.rs:954` | `AttachmentWitness` | S |
| AttachmentWitness.inspection_deadline | `f64` | `crates/vprouter-launch/src/attachment/mount.rs:951` | `AttachmentWitness` | S |
| AttachmentWitness.inspection_requested_at | `f64` | `crates/vprouter-launch/src/attachment/mount.rs:951` | `AttachmentWitness` | S |
| AttachmentWitness.inspection_verified_at | `f64` | `crates/vprouter-launch/src/attachment/mount.rs:952` | `AttachmentWitness` | S |
| AttachmentWitness.mount | `emitted MountWitness` | `crates/vprouter-launch/src/attachment/mount.rs:953` | `AttachmentWitness` | S |
| AttachmentWitness.namespace_cleanup_or_operational_reuse_authorized | `bool` | `crates/vprouter-launch/src/attachment/mount.rs:959` | `AttachmentWitness` | S |
| AttachmentWitness.normal_ack_ready_preserved | `bool` | `crates/vprouter-launch/src/attachment/mount.rs:955` | `AttachmentWitness` | S |
| AttachmentWitness.normal_ack_writer | `emitted null` | `crates/vprouter-launch/src/attachment/mount.rs:957` | `AttachmentWitness` | S |
| AttachmentWitness.original_mount_retained | `bool` | `crates/vprouter-launch/src/attachment/mount.rs:958` | `AttachmentWitness` | S |
| AttachmentWitness.parent_pristine | `bool` | `crates/vprouter-launch/src/attachment/mount.rs:953` | `AttachmentWitness` | S |
| AttachmentWitness.postmount_query | `emitted Query` | `crates/vprouter-launch/src/attachment/mount.rs:953` | `AttachmentWitness` | S |
| AttachmentWitness.preparation | `emitted Preparation` | `crates/vprouter-launch/src/attachment/mount.rs:950` | `AttachmentWitness` | S |
| AttachmentWitness.requirement8_complete | `bool` | `crates/vprouter-launch/src/attachment/mount.rs:959` | `AttachmentWitness` | S |
| AttachmentWitness.same_service_retained | `bool` | `crates/vprouter-launch/src/attachment/mount.rs:953` | `AttachmentWitness` | S |
| AttachmentWitness.schema | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/mount.rs:950` | `AttachmentWitness` | S |
| AttachmentWitness.second_query | `emitted Query` | `crates/vprouter-launch/src/attachment/mount.rs:952` | `AttachmentWitness` | S |
| AttachmentWitness.tested_non_target_phase | `emitted null` | `crates/vprouter-launch/src/attachment/mount.rs:956` | `AttachmentWitness` | S |
| AttachmentWitness.validator | `emitted ValidatorWitness` | `crates/vprouter-launch/src/attachment/mount.rs:950` | `AttachmentWitness` | S |
| AttachmentWitness.whole_failed_driver_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/mount.rs:954` | `AttachmentWitness` | S |
| Birth.born_at | `f64` | `crates/vprouter-launch/src/owned/preparation.rs:81` | `Birth` | S, R |
| Birth.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation.rs:82` | `Birth` | S, R |
| Birth.pid | `u32` | `crates/vprouter-launch/src/owned/preparation.rs:79` | `Birth` | S, R |
| Birth.start | `u64` | `crates/vprouter-launch/src/owned/preparation.rs:80` | `Birth` | S, R |
| BootstrapHistory.birth | `Option<ValidationBirth>` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:28` | `BootstrapHistory` | S, R |
| BootstrapHistory.creation | `producer_creation::History` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:21` | `BootstrapHistory` | S, R |
| BootstrapHistory.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:25` | `BootstrapHistory` | S, R |
| BootstrapHistory.group | `Identity` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:22` | `BootstrapHistory` | S, R |
| BootstrapHistory.namespace | `Identity` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:20` | `BootstrapHistory` | S, R |
| BootstrapHistory.pins | `[(u64, u64, u32); 8]` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:27` | `BootstrapHistory` | S, R |
| BootstrapHistory.policy | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:26` | `BootstrapHistory` | S, R |
| BootstrapHistory.query | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:23` | `BootstrapHistory` | S, R |
| BootstrapHistory.request | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:18` | `BootstrapHistory` | S, R |
| BootstrapHistory.requested_at | `f64` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:24` | `BootstrapHistory` | S, R |
| BootstrapHistory.result | `Option<PublicResult>` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:29` | `BootstrapHistory` | S, R |
| BootstrapHistory.scope | `Scope` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:19` | `BootstrapHistory` | S, R |
| BootstrapHistory.verified_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:30` | `BootstrapHistory` | S, R |
| BootstrapOperation.accepted_at | `f64` | `crates/vprouter-launch/src/kernel/bootstrap.rs:563` | `BootstrapOperation` | S |
| BootstrapOperation.acknowledged | `bool` | `crates/vprouter-launch/src/kernel/bootstrap.rs:563` | `BootstrapOperation` | S |
| BootstrapOperation.actual_wait_status | `i32` | `crates/vprouter-launch/src/kernel/bootstrap.rs:560` | `BootstrapOperation` | S |
| BootstrapOperation.birth | `emitted Birth` | `crates/vprouter-launch/src/kernel/bootstrap.rs:560` | `BootstrapOperation` | S |
| BootstrapOperation.bootstrap_installation_observed | `bool` | `crates/vprouter-launch/src/kernel/bootstrap.rs:564` | `BootstrapOperation` | S |
| BootstrapOperation.borrowed_registration_count | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/bootstrap.rs:562` | `BootstrapOperation` | S |
| BootstrapOperation.complete_native_registration | `bool` | `crates/vprouter-launch/src/kernel/bootstrap.rs:562` | `BootstrapOperation` | S |
| BootstrapOperation.context_retained | `bool` | `crates/vprouter-launch/src/kernel/bootstrap.rs:564` | `BootstrapOperation` | S |
| BootstrapOperation.deadline | `f64` | `crates/vprouter-launch/src/kernel/bootstrap.rs:558` | `BootstrapOperation` | S |
| BootstrapOperation.durable_birth_released | `bool` | `crates/vprouter-launch/src/kernel/bootstrap.rs:563` | `BootstrapOperation` | S |
| BootstrapOperation.eof | `bool` | `crates/vprouter-launch/src/kernel/bootstrap.rs:564` | `BootstrapOperation` | S |
| BootstrapOperation.group | `emitted Identity` | `crates/vprouter-launch/src/kernel/bootstrap.rs:559` | `BootstrapOperation` | S |
| BootstrapOperation.name | `String` | `crates/vprouter-launch/src/kernel/bootstrap.rs:559` | `BootstrapOperation` | S |
| BootstrapOperation.namespace | `emitted Identity` | `crates/vprouter-launch/src/kernel/bootstrap.rs:559` | `BootstrapOperation` | S |
| BootstrapOperation.native_born | `bool` | `crates/vprouter-launch/src/kernel/bootstrap.rs:560` | `BootstrapOperation` | S |
| BootstrapOperation.native_job_state | `emitted job_state` | `crates/vprouter-launch/src/kernel/bootstrap.rs:561` | `BootstrapOperation` | S |
| BootstrapOperation.original_pid | `u32` | `crates/vprouter-launch/src/kernel/bootstrap.rs:560` | `BootstrapOperation` | S |
| BootstrapOperation.original_registration_slots_verified | `bool` | `crates/vprouter-launch/src/kernel/bootstrap.rs:562` | `BootstrapOperation` | S |
| BootstrapOperation.original_start | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/bootstrap.rs:560` | `BootstrapOperation` | S |
| BootstrapOperation.parent | `emitted Identity` | `crates/vprouter-launch/src/kernel/bootstrap.rs:559` | `BootstrapOperation` | S |
| BootstrapOperation.pins | `[(u64,u64,u32);8]` | `crates/vprouter-launch/src/kernel/bootstrap.rs:559` | `BootstrapOperation` | S |
| BootstrapOperation.placement_authorized | `bool` | `crates/vprouter-launch/src/kernel/bootstrap.rs:564` | `BootstrapOperation` | S |
| BootstrapOperation.policy | `[u8;32]` | `crates/vprouter-launch/src/kernel/bootstrap.rs:559` | `BootstrapOperation` | S |
| BootstrapOperation.query | `[u8;32]` | `crates/vprouter-launch/src/kernel/bootstrap.rs:558` | `BootstrapOperation` | S |
| BootstrapOperation.registered_native_slots | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/bootstrap.rs:562` | `BootstrapOperation` | S |
| BootstrapOperation.request | `[u8;32]` | `crates/vprouter-launch/src/kernel/bootstrap.rs:558` | `BootstrapOperation` | S |
| BootstrapOperation.requested_at | `f64` | `crates/vprouter-launch/src/kernel/bootstrap.rs:558` | `BootstrapOperation` | S |
| BootstrapOperation.result | `emitted BootstrapResult` | `crates/vprouter-launch/src/kernel/bootstrap.rs:563` | `BootstrapOperation` | S |
| BootstrapOperation.scope | `emitted scope` | `crates/vprouter-launch/src/kernel/bootstrap.rs:559` | `BootstrapOperation` | S |
| BootstrapOperation.up_authorized | `bool` | `crates/vprouter-launch/src/kernel/bootstrap.rs:564` | `BootstrapOperation` | S |
| BootstrapResult.group | `Identity` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:10` | `BootstrapResult` | S, R |
| BootstrapResult.namespace | `Identity` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:9` | `BootstrapResult` | S, R |
| BootstrapResult.observed_at | `f64` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:13` | `BootstrapResult` | S, R |
| BootstrapResult.pins | `[(u64, u64, u32); 8]` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:12` | `BootstrapResult` | S, R |
| BootstrapResult.policy | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:11` | `BootstrapResult` | S, R |
| BootstrapWitness.bootstrap_all_scopes_acknowledged | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1253` | `BootstrapWitness` | S |
| BootstrapWitness.bootstrap_context_created | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1253` | `BootstrapWitness` | S |
| BootstrapWitness.bootstrap_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1252` | `BootstrapWitness` | S |
| BootstrapWitness.canonical_negative_checks | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1248` | `BootstrapWitness` | S |
| BootstrapWitness.charges_after_drop | `emitted list(u64)` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1250` | `BootstrapWitness` | S |
| BootstrapWitness.charges_before_drop | `emitted list(u64)` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1250` | `BootstrapWitness` | S |
| BootstrapWitness.failed_constructor | `emitted null` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1249` | `BootstrapWitness` | S |
| BootstrapWitness.failure_retry | `emitted null` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1249` | `BootstrapWitness` | S |
| BootstrapWitness.fault | `u8` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1248` | `BootstrapWitness` | S |
| BootstrapWitness.final_process_verified_at | `f64` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1250` | `BootstrapWitness` | S |
| BootstrapWitness.handoff | `emitted Handoff` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1248` | `BootstrapWitness` | S |
| BootstrapWitness.health_ready_authorized | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1254` | `BootstrapWitness` | S |
| BootstrapWitness.host_addition | `emitted HostAddition` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1248` | `BootstrapWitness` | S |
| BootstrapWitness.multi_exit_runtime_proven | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1255` | `BootstrapWitness` | S |
| BootstrapWitness.operational_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1252` | `BootstrapWitness` | S |
| BootstrapWitness.operations | `emitted list(BootstrapOperation)` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1249` | `BootstrapWitness` | S |
| BootstrapWitness.original_nine_contexts_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1251` | `BootstrapWitness` | S |
| BootstrapWitness.own_intent_polling | `emitted IntentPolling` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1248` | `BootstrapWitness` | S |
| BootstrapWitness.own_query_intent_polling | `emitted IntentPolling` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1248` | `BootstrapWitness` | S |
| BootstrapWitness.parent_pristine | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1254` | `BootstrapWitness` | S |
| BootstrapWitness.placement_authorized | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1254` | `BootstrapWitness` | S |
| BootstrapWitness.preparation | `emitted Preparation` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1248` | `BootstrapWitness` | S |
| BootstrapWitness.queries | `emitted list(Query)` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1249` | `BootstrapWitness` | S |
| BootstrapWitness.requirement8_complete | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1255` | `BootstrapWitness` | S |
| BootstrapWitness.resource_cleanup_authorized | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1255` | `BootstrapWitness` | S |
| BootstrapWitness.result_writer_held | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1251` | `BootstrapWitness` | S |
| BootstrapWitness.retained_result_writer | `emitted null` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1249` | `BootstrapWitness` | S |
| BootstrapWitness.schema | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1248` | `BootstrapWitness` | S |
| BootstrapWitness.scope_process_verified_at | `emitted list(f64)` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1250` | `BootstrapWitness` | S |
| BootstrapWitness.up_authorized | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1254` | `BootstrapWitness` | S |
| BootstrapWitness.whole_chain_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1251` | `BootstrapWitness` | S |
| EntryProducer.binding | `Option<[u8;32]>` | `crates/vprouter-launch/src/owned.rs:619` | `EntryProducer` | S |
| EntryProducer.group | `Identity` | `crates/vprouter-launch/src/owned.rs:621` | `EntryProducer` | S |
| EntryProducer.parent | `Identity` | `crates/vprouter-launch/src/owned.rs:620` | `EntryProducer` | S |
| ForeignEligibility.actual_wait_status | `i32` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:219` | `ForeignEligibility` | S |
| ForeignEligibility.canonical_operation | `bool` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:228` | `ForeignEligibility` | S |
| ForeignEligibility.deadline | `f64` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:219` | `ForeignEligibility` | S |
| ForeignEligibility.eligible_foreign_refused | `bool` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:226` | `ForeignEligibility` | S |
| ForeignEligibility.eligible_original_pid | `u32` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:225` | `ForeignEligibility` | S |
| ForeignEligibility.eligible_original_start | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:225` | `ForeignEligibility` | S |
| ForeignEligibility.eof | `bool` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:219` | `ForeignEligibility` | S |
| ForeignEligibility.failed_actual_wait_status | `emitted null` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:222` | `ForeignEligibility` | S |
| ForeignEligibility.failed_charges_unchanged | `emitted null` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:224` | `ForeignEligibility` | S |
| ForeignEligibility.failed_exit_code | `emitted null` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:223` | `ForeignEligibility` | S |
| ForeignEligibility.failed_original_pid | `emitted null` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:220` | `ForeignEligibility` | S |
| ForeignEligibility.failed_original_start | `emitted null` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:221` | `ForeignEligibility` | S |
| ForeignEligibility.original_pid | `i32` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:219` | `ForeignEligibility` | S |
| ForeignEligibility.original_start | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:219` | `ForeignEligibility` | S |
| ForeignEligibility.parent_counts_after | `emitted list(u64)` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:227` | `ForeignEligibility` | S |
| ForeignEligibility.parent_counts_before | `emitted list(u64)` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:227` | `ForeignEligibility` | S |
| ForeignEligibility.parent_still_eligible | `bool` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:226` | `ForeignEligibility` | S |
| ForeignEligibility.requested_at | `f64` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:219` | `ForeignEligibility` | S |
| ForeignEligibility.schema | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:219` | `ForeignEligibility` | S |
| ForeignEligibility.successful_capacity_transfer_proven | `bool` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:228` | `ForeignEligibility` | S |
| ForeignEligibility.verified_at | `f64` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:219` | `ForeignEligibility` | S |
| FreshTransport.birth | `Option<ValidationBirth>` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:15` | `FreshTransport` | S, R |
| FreshTransport.data | `Identity` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:12` | `FreshTransport` | S, R |
| FreshTransport.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:14` | `FreshTransport` | S, R |
| FreshTransport.directory | `Identity` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:9` | `FreshTransport` | S, R |
| FreshTransport.host | `Identity` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:11` | `FreshTransport` | S, R |
| FreshTransport.mount | `Option<fresh_mount::History>` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:19` | `FreshTransport` | S, R |
| FreshTransport.name | `String` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:10` | `FreshTransport` | S, R |
| FreshTransport.request | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:8` | `FreshTransport` | S, R |
| FreshTransport.requested_at | `f64` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:13` | `FreshTransport` | S, R |
| FreshTransport.source | `Option<Identity>` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:16` | `FreshTransport` | S, R |
| FreshTransport.verified_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:17` | `FreshTransport` | S, R |
| Handoff.charges_after | `emitted list(u64)` | `crates/vprouter-launch/src/attachment/operational.rs:585` | `Handoff` | S |
| Handoff.charges_before | `emitted list(u64)` | `crates/vprouter-launch/src/attachment/operational.rs:585` | `Handoff` | S |
| Handoff.complete | `bool` | `crates/vprouter-launch/src/attachment/operational.rs:587` | `Handoff` | S |
| Handoff.complete_original_job_set | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/operational.rs:587` | `Handoff` | S |
| Handoff.duplicate_reservation | `emitted null` | `crates/vprouter-launch/src/attachment/operational.rs:586` | `Handoff` | S |
| Handoff.fence_counts | `emitted null` | `crates/vprouter-launch/src/attachment/operational.rs:586` | `Handoff` | S |
| Handoff.global_child_capacity_limit | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/operational.rs:588` | `Handoff` | S |
| Handoff.historical_original_jobs | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/operational.rs:587` | `Handoff` | S |
| Handoff.preparation | `emitted Preparation` | `crates/vprouter-launch/src/attachment/operational.rs:586` | `Handoff` | S |
| Handoff.repeat_retirement_refusals | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/operational.rs:585` | `Handoff` | S |
| Handoff.reservation | `emitted OperationalReservation` | `crates/vprouter-launch/src/attachment/operational.rs:584` | `Handoff` | S |
| Handoff.resources | `emitted list(Resource)` | `crates/vprouter-launch/src/attachment/operational.rs:584` | `Handoff` | S |
| Handoff.resources_collected | `bool` | `crates/vprouter-launch/src/attachment/operational.rs:588` | `Handoff` | S |
| Handoff.retired_suffix_jobs | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/operational.rs:585` | `Handoff` | S |
| HostAddition.admission | `emitted HostAdmission` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1136` | `HostAddition` | S |
| HostAddition.baseline_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1143` | `HostAddition` | S |
| HostAddition.canonical_host_addition_acknowledged | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1141` | `HostAddition` | S |
| HostAddition.canonical_negative_checks | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1137` | `HostAddition` | S |
| HostAddition.charges_after_drop | `emitted null` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1148` | `HostAddition` | S |
| HostAddition.charges_before | `emitted list(u64)` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1139` | `HostAddition` | S |
| HostAddition.charges_before_drop | `emitted list(u64)` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1139` | `HostAddition` | S |
| HostAddition.continued_original_context | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1147` | `HostAddition` | S |
| HostAddition.failed_constructor | `emitted null` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1137` | `HostAddition` | S |
| HostAddition.failure_retry | `emitted null` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1139` | `HostAddition` | S |
| HostAddition.fault | `u8` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1136` | `HostAddition` | S |
| HostAddition.generation_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1144` | `HostAddition` | S |
| HostAddition.health_ready_authorized | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1145` | `HostAddition` | S |
| HostAddition.host_addresses_routes_rules_preserved | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1142` | `HostAddition` | S |
| HostAddition.host_link_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1144` | `HostAddition` | S |
| HostAddition.host_neighbor_mutation_authorized | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1142` | `HostAddition` | S |
| HostAddition.isolated_pair_creation_observed | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1140` | `HostAddition` | S |
| HostAddition.multi_exit_runtime_proven | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1146` | `HostAddition` | S |
| HostAddition.operations | `emitted list(HostOperation)` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1137` | `HostAddition` | S |
| HostAddition.original_six_contexts_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1143` | `HostAddition` | S |
| HostAddition.own_intent_polling | `emitted HostIntentPolling` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1138` | `HostAddition` | S |
| HostAddition.parent_pristine | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1145` | `HostAddition` | S |
| HostAddition.placement_authorized | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1145` | `HostAddition` | S |
| HostAddition.planned_host_link_index | `u32` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1137` | `HostAddition` | S |
| HostAddition.preparation | `emitted Preparation` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1136` | `HostAddition` | S |
| HostAddition.producer_binding | `emitted ProducerBinding` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1136` | `HostAddition` | S |
| HostAddition.requirement8_complete | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1146` | `HostAddition` | S |
| HostAddition.resource_cleanup_authorized | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1146` | `HostAddition` | S |
| HostAddition.result_writer_held | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1140` | `HostAddition` | S |
| HostAddition.retained_result_writer | `emitted null` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1139` | `HostAddition` | S |
| HostAddition.schema | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1136` | `HostAddition` | S |
| HostAddition.single_down_host_addition_observed | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1140` | `HostAddition` | S |
| HostAddition.unacknowledged_host_addition_retained | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1141` | `HostAddition` | S |
| HostAddition.up_authorized | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1145` | `HostAddition` | S |
| HostAddition.whole_chain_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1143` | `HostAddition` | S |
| HostAdmission.accepted_at | `f64` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:740` | `HostAdmission` | S |
| HostAdmission.deadline | `f64` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:740` | `HostAdmission` | S |
| HostAdmission.declaration | `[u8;32]` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:739` | `HostAdmission` | S |
| HostAdmission.declared_baseline | `emitted HostBaseline` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:741` | `HostAdmission` | S |
| HostAdmission.namespace | `emitted Identity` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:739` | `HostAdmission` | S |
| HostAdmission.polls | `u32` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:741` | `HostAdmission` | S |
| HostAdmission.requested_at | `f64` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:740` | `HostAdmission` | S |
| HostAdmission.same_generation_owner_retained | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:741` | `HostAdmission` | S |
| HostAdmission.two_original_reads_verified | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:741` | `HostAdmission` | S |
| HostBaseline.addresses | `emitted list(Address)` | `crates/vprouter-network/src/host_observation.rs:16` | `HostBaseline` | S |
| HostBaseline.links | `emitted list(Link)` | `crates/vprouter-network/src/host_observation.rs:14` | `HostBaseline` | S |
| HostBaseline.namespace | `(u64,u64)` | `crates/vprouter-network/src/host_observation.rs:12` | `HostBaseline` | S |
| HostBaseline.routes | `emitted list(Route)` | `crates/vprouter-network/src/host_observation.rs:18` | `HostBaseline` | S |
| HostBaseline.rules | `emitted list(Rule)` | `crates/vprouter-network/src/host_observation.rs:20` | `HostBaseline` | S |
| HostIntentPolling.held_pending_polls | `u32` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1138` | `HostIntentPolling` | S |
| HostIntentPolling.index | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1138` | `HostIntentPolling` | S |
| HostIntentPolling.negative_checks | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1138` | `HostIntentPolling` | S |
| HostIntentPolling.pid | `u32` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1138` | `HostIntentPolling` | S |
| HostIntentPolling.queued_polls | `u32` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1138` | `HostIntentPolling` | S |
| HostIntentPolling.released | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1138` | `HostIntentPolling` | S |
| HostIntentPolling.start | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1138` | `HostIntentPolling` | S |
| HostLinkHistory.addition | `Option<([u8; 32], u32)>` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:17` | `HostLinkHistory` | S, R |
| HostLinkHistory.admission | `[f64; 3]` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:14` | `HostLinkHistory` | S, R |
| HostLinkHistory.birth | `Option<ValidationBirth>` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:18` | `HostLinkHistory` | S, R |
| HostLinkHistory.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:16` | `HostLinkHistory` | S, R |
| HostLinkHistory.declaration | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:13` | `HostLinkHistory` | S, R |
| HostLinkHistory.host | `Identity` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:12` | `HostLinkHistory` | S, R |
| HostLinkHistory.kind | `Kind` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:9` | `HostLinkHistory` | S, R |
| HostLinkHistory.namespace | `Identity` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:11` | `HostLinkHistory` | S, R |
| HostLinkHistory.request | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:10` | `HostLinkHistory` | S, R |
| HostLinkHistory.requested_at | `f64` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:15` | `HostLinkHistory` | S, R |
| HostLinkHistory.result | `Option<PublicResult>` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:19` | `HostLinkHistory` | S, R |
| HostLinkHistory.verified_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:20` | `HostLinkHistory` | S, R |
| HostLinkResult.host | `Option<vprouter_network::Link>` | `crates/vprouter-launch/src/kernel/host_link.rs:24` | `HostLinkResult` | S |
| HostLinkResult.namespace | `Identity` | `crates/vprouter-launch/src/kernel/host_link.rs:23` | `HostLinkResult` | S |
| HostLinkResult.peer | `Option<vprouter_network::Link>` | `crates/vprouter-launch/src/kernel/host_link.rs:25` | `HostLinkResult` | S |
| HostOperation.accepted_at | `f64` | `crates/vprouter-launch/src/kernel/host_link.rs:822` | `HostOperation` | S |
| HostOperation.acknowledged | `bool` | `crates/vprouter-launch/src/kernel/host_link.rs:822` | `HostOperation` | S |
| HostOperation.actual_wait_status | `i32` | `crates/vprouter-launch/src/kernel/host_link.rs:819` | `HostOperation` | S |
| HostOperation.addition | `emitted addition&#124;null` | `crates/vprouter-launch/src/kernel/host_link.rs:817` | `HostOperation` | S |
| HostOperation.admission | `emitted window3` | `crates/vprouter-launch/src/kernel/host_link.rs:817` | `HostOperation` | S |
| HostOperation.birth | `emitted Birth` | `crates/vprouter-launch/src/kernel/host_link.rs:819` | `HostOperation` | S |
| HostOperation.borrowed_registration_count | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/host_link.rs:820` | `HostOperation` | S |
| HostOperation.complete_native_registration | `bool` | `crates/vprouter-launch/src/kernel/host_link.rs:821` | `HostOperation` | S |
| HostOperation.context_retained | `bool` | `crates/vprouter-launch/src/kernel/host_link.rs:822` | `HostOperation` | S |
| HostOperation.deadline | `f64` | `crates/vprouter-launch/src/kernel/host_link.rs:818` | `HostOperation` | S |
| HostOperation.declaration | `[u8;32]` | `crates/vprouter-launch/src/kernel/host_link.rs:817` | `HostOperation` | S |
| HostOperation.durable_birth_released | `bool` | `crates/vprouter-launch/src/kernel/host_link.rs:821` | `HostOperation` | S |
| HostOperation.eof | `bool` | `crates/vprouter-launch/src/kernel/host_link.rs:822` | `HostOperation` | S |
| HostOperation.host | `emitted Identity` | `crates/vprouter-launch/src/kernel/host_link.rs:816` | `HostOperation` | S |
| HostOperation.host_observation | `emitted HostBaseline&#124;null` | `crates/vprouter-launch/src/kernel/host_link.rs:825` | `HostOperation` | S |
| HostOperation.kind | `emitted host_kind` | `crates/vprouter-launch/src/kernel/host_link.rs:816` | `HostOperation` | S |
| HostOperation.namespace | `emitted Identity` | `crates/vprouter-launch/src/kernel/host_link.rs:816` | `HostOperation` | S |
| HostOperation.native_born | `bool` | `crates/vprouter-launch/src/kernel/host_link.rs:819` | `HostOperation` | S |
| HostOperation.native_job_state | `emitted job_state` | `crates/vprouter-launch/src/kernel/host_link.rs:819` | `HostOperation` | S |
| HostOperation.original_pid | `u32` | `crates/vprouter-launch/src/kernel/host_link.rs:818` | `HostOperation` | S |
| HostOperation.original_registration_slots_verified | `bool` | `crates/vprouter-launch/src/kernel/host_link.rs:820` | `HostOperation` | S |
| HostOperation.original_start | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/host_link.rs:818` | `HostOperation` | S |
| HostOperation.placement_authorized | `bool` | `crates/vprouter-launch/src/kernel/host_link.rs:825` | `HostOperation` | S |
| HostOperation.postcompletion_inventory_polls | `u32` | `crates/vprouter-launch/src/kernel/host_link.rs:823` | `HostOperation` | S |
| HostOperation.postcompletion_inventory_preserved | `emitted bool&#124;null` | `crates/vprouter-launch/src/kernel/host_link.rs:824` | `HostOperation` | S |
| HostOperation.registered_native_slots | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/host_link.rs:820` | `HostOperation` | S |
| HostOperation.request | `[u8;32]` | `crates/vprouter-launch/src/kernel/host_link.rs:816` | `HostOperation` | S |
| HostOperation.requested_at | `f64` | `crates/vprouter-launch/src/kernel/host_link.rs:818` | `HostOperation` | S |
| HostOperation.result | `emitted HostLinkResult` | `crates/vprouter-launch/src/kernel/host_link.rs:822` | `HostOperation` | S |
| HostOperation.up_authorized | `bool` | `crates/vprouter-launch/src/kernel/host_link.rs:825` | `HostOperation` | S |
| Identity.dev | `u64` | `crates/vprouter-launch/src/owned.rs:23` | `Identity` | S, R |
| Identity.ino | `u64` | `crates/vprouter-launch/src/owned.rs:24` | `Identity` | S, R |
| InspectionHistory.birth | `Option<ValidationBirth>` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:14` | `InspectionHistory` | S, R |
| InspectionHistory.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:13` | `InspectionHistory` | S, R |
| InspectionHistory.facts | `Option<QueryFacts>` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:15` | `InspectionHistory` | S, R |
| InspectionHistory.initial | `Option<Initial>` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:10` | `InspectionHistory` | S, R |
| InspectionHistory.kind | `QueryKind` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:9` | `InspectionHistory` | S, R |
| InspectionHistory.request | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:11` | `InspectionHistory` | S, R |
| InspectionHistory.requested_at | `f64` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:12` | `InspectionHistory` | S, R |
| InspectionHistory.verified_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:16` | `InspectionHistory` | S, R |
| InspectionInitial.birth | `ValidationBirth` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:22` | `InspectionInitial` | S, R |
| InspectionInitial.facts | `QueryFacts` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:23` | `InspectionInitial` | S, R |
| InspectionInitial.request | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:21` | `InspectionInitial` | S, R |
| InspectionInitial.verified_at | `f64` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:24` | `InspectionInitial` | S, R |
| IntentPolling.held_pending_polls | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:785` | `IntentPolling` | S |
| IntentPolling.index | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:785` | `IntentPolling` | S |
| IntentPolling.negative_checks | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:785` | `IntentPolling` | S |
| IntentPolling.pid | `u32` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:785` | `IntentPolling` | S |
| IntentPolling.queued_polls | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:785` | `IntentPolling` | S |
| IntentPolling.released | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:785` | `IntentPolling` | S |
| IntentPolling.start | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:785` | `IntentPolling` | S |
| Link.alias | `String` | `crates/vprouter-network/src/project.rs:31` | `Link` | S, R |
| Link.all_multicast | `u32` | `crates/vprouter-network/src/project.rs:37` | `Link` | S, R |
| Link.alternate_names | `Vec<String>` | `crates/vprouter-network/src/project.rs:38` | `Link` | S, R |
| Link.controller | `u32` | `crates/vprouter-network/src/project.rs:34` | `Link` | S, R |
| Link.hardware_type | `u16` | `crates/vprouter-network/src/project.rs:33` | `Link` | S, R |
| Link.headroom | `Option<u16>` | `crates/vprouter-network/src/project.rs:43` | `Link` | S, R |
| Link.index | `u32` | `crates/vprouter-network/src/project.rs:27` | `Link` | S, R |
| Link.kind | `String` | `crates/vprouter-network/src/project.rs:28` | `Link` | S, R |
| Link.max_pacing_offload_horizon | `Option<u32>` | `crates/vprouter-network/src/project.rs:42` | `Link` | S, R |
| Link.mtu | `u32` | `crates/vprouter-network/src/project.rs:30` | `Link` | S, R |
| Link.name | `String` | `crates/vprouter-network/src/project.rs:26` | `Link` | S, R |
| Link.peer_index | `Option<u32>` | `crates/vprouter-network/src/project.rs:32` | `Link` | S, R |
| Link.port_kind | `String` | `crates/vprouter-network/src/project.rs:35` | `Link` | S, R |
| Link.promiscuity | `u32` | `crates/vprouter-network/src/project.rs:36` | `Link` | S, R |
| Link.tailroom | `Option<u16>` | `crates/vprouter-network/src/project.rs:44` | `Link` | S, R |
| Link.tun_info | `Vec<(u16, Vec<u8>)>` | `crates/vprouter-network/src/project.rs:40` | `Link` | S, R |
| Link.up | `bool` | `crates/vprouter-network/src/project.rs:29` | `Link` | S, R |
| MountHistory.birth | `Option<ValidationBirth>` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:14` | `MountHistory` | S, R |
| MountHistory.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:13` | `MountHistory` | S, R |
| MountHistory.directory | `Identity` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:10` | `MountHistory` | S, R |
| MountHistory.mounted_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:16` | `MountHistory` | S, R |
| MountHistory.name | `String` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:11` | `MountHistory` | S, R |
| MountHistory.placeholder | `Option<Placeholder>` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:15` | `MountHistory` | S, R |
| MountHistory.published_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:17` | `MountHistory` | S, R |
| MountHistory.request | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:8` | `MountHistory` | S, R |
| MountHistory.requested_at | `f64` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:12` | `MountHistory` | S, R |
| MountHistory.source | `Identity` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:9` | `MountHistory` | S, R |
| MountWitness.actual_wait_status | `i32` | `crates/vprouter-launch/src/kernel/namespace_attachment.rs:884` | `MountWitness` | S |
| MountWitness.birth | `emitted Birth` | `crates/vprouter-launch/src/kernel/namespace_attachment.rs:884` | `MountWitness` | S |
| MountWitness.deadline | `f64` | `crates/vprouter-launch/src/kernel/namespace_attachment.rs:885` | `MountWitness` | S |
| MountWitness.eof | `bool` | `crates/vprouter-launch/src/kernel/namespace_attachment.rs:889` | `MountWitness` | S |
| MountWitness.original_directory | `emitted Identity` | `crates/vprouter-launch/src/kernel/namespace_attachment.rs:886` | `MountWitness` | S |
| MountWitness.original_mounted_namespace_retained | `bool` | `crates/vprouter-launch/src/kernel/namespace_attachment.rs:888` | `MountWitness` | S |
| MountWitness.original_placeholder_retained | `bool` | `crates/vprouter-launch/src/kernel/namespace_attachment.rs:887` | `MountWitness` | S |
| MountWitness.original_source | `emitted Identity` | `crates/vprouter-launch/src/kernel/namespace_attachment.rs:886` | `MountWitness` | S |
| MountWitness.placeholder | `emitted Placeholder` | `crates/vprouter-launch/src/kernel/namespace_attachment.rs:887` | `MountWitness` | S |
| MountWitness.received_packets | `u8` | `crates/vprouter-launch/src/kernel/namespace_attachment.rs:889` | `MountWitness` | S |
| MountWitness.released_gates | `u8` | `crates/vprouter-launch/src/kernel/namespace_attachment.rs:888` | `MountWitness` | S |
| MountWitness.requested_at | `f64` | `crates/vprouter-launch/src/kernel/namespace_attachment.rs:885` | `MountWitness` | S |
| Movement.continued_original_context | `bool` | `crates/vprouter-launch/src/attachment/movement.rs:856` | `Movement` | S |
| Movement.data_move_completed | `bool` | `crates/vprouter-launch/src/attachment/movement.rs:857` | `Movement` | S |
| Movement.failed_constructor | `emitted null` | `crates/vprouter-launch/src/attachment/movement.rs:854` | `Movement` | S |
| Movement.fault | `u8` | `crates/vprouter-launch/src/attachment/movement.rs:851` | `Movement` | S |
| Movement.final_process_verified_at | `f64` | `crates/vprouter-launch/src/attachment/movement.rs:853` | `Movement` | S |
| Movement.held_real_result_writer | `bool` | `crates/vprouter-launch/src/attachment/movement.rs:854` | `Movement` | S |
| Movement.host_resources_created | `bool` | `crates/vprouter-launch/src/attachment/movement.rs:857` | `Movement` | S |
| Movement.move_borrows_both_original_pairs | `bool` | `crates/vprouter-launch/src/attachment/movement.rs:855` | `Movement` | S |
| Movement.movement_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/movement.rs:856` | `Movement` | S |
| Movement.movement_query | `emitted Query` | `crates/vprouter-launch/src/attachment/movement.rs:852` | `Movement` | S |
| Movement.operational_reuse_authorized | `bool` | `crates/vprouter-launch/src/attachment/movement.rs:858` | `Movement` | S |
| Movement.operations | `emitted list(MovementOperation)` | `crates/vprouter-launch/src/attachment/movement.rs:852` | `Movement` | S |
| Movement.original_provision_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/movement.rs:856` | `Movement` | S |
| Movement.original_query_parent_readback_advanced | `bool` | `crates/vprouter-launch/src/attachment/movement.rs:853` | `Movement` | S |
| Movement.parent_pristine | `bool` | `crates/vprouter-launch/src/attachment/movement.rs:856` | `Movement` | S |
| Movement.preparation | `emitted Preparation` | `crates/vprouter-launch/src/attachment/movement.rs:852` | `Movement` | S |
| Movement.provision | `emitted Provision` | `crates/vprouter-launch/src/attachment/movement.rs:851` | `Movement` | S |
| Movement.requirement8_complete | `bool` | `crates/vprouter-launch/src/attachment/movement.rs:858` | `Movement` | S |
| Movement.same_service_retained | `bool` | `crates/vprouter-launch/src/attachment/movement.rs:856` | `Movement` | S |
| Movement.schema | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/movement.rs:851` | `Movement` | S |
| Movement.unacknowledged_native_result_retained | `bool` | `crates/vprouter-launch/src/attachment/movement.rs:855` | `Movement` | S |
| Movement.whole_chain_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/movement.rs:856` | `Movement` | S |
| Movement.wireguard_down_only | `bool` | `crates/vprouter-launch/src/attachment/movement.rs:857` | `Movement` | S |
| MovementHistory.birth | `Option<ValidationBirth>` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:14` | `MovementHistory` | S |
| MovementHistory.configuration | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:11` | `MovementHistory` | S |
| MovementHistory.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:13` | `MovementHistory` | S |
| MovementHistory.destination | `Option<Identity>` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:18` | `MovementHistory` | S |
| MovementHistory.kind | `Kind` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:8` | `MovementHistory` | S |
| MovementHistory.movement_query | `Option<[u8; 32]>` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:20` | `MovementHistory` | S |
| MovementHistory.namespace | `Identity` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:10` | `MovementHistory` | S |
| MovementHistory.request | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:9` | `MovementHistory` | S |
| MovementHistory.requested_at | `f64` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:12` | `MovementHistory` | S |
| MovementHistory.result | `Option<PublicResult>` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:15` | `MovementHistory` | S |
| MovementHistory.verified_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:16` | `MovementHistory` | S |
| MovementOperation.accepted_at | `f64` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1588` | `MovementOperation` | S |
| MovementOperation.acknowledged | `bool` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1588` | `MovementOperation` | S |
| MovementOperation.actual_wait_status | `i32` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1585` | `MovementOperation` | S |
| MovementOperation.birth | `emitted Birth` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1583` | `MovementOperation` | S |
| MovementOperation.borrowed_registration_count | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1587` | `MovementOperation` | S |
| MovementOperation.context_retained | `bool` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1589` | `MovementOperation` | S |
| MovementOperation.deadline | `f64` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1583` | `MovementOperation` | S |
| MovementOperation.full_descriptor_registration | `bool` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1587` | `MovementOperation` | S |
| MovementOperation.kind | `emitted wireguard_kind` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1583` | `MovementOperation` | S |
| MovementOperation.native_born | `bool` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1585` | `MovementOperation` | S |
| MovementOperation.native_job_state | `emitted job_state` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1586` | `MovementOperation` | S |
| MovementOperation.original_pid | `u32` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1584` | `MovementOperation` | S |
| MovementOperation.original_start | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1584` | `MovementOperation` | S |
| MovementOperation.postcompletion_inventory_polls | `u32` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1590` | `MovementOperation` | S |
| MovementOperation.postcompletion_inventory_preserved | `bool` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1591` | `MovementOperation` | S |
| MovementOperation.query_sequences | `Option<[[u32;2];2]>` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1589` | `MovementOperation` | S |
| MovementOperation.registered_native_slots | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1587` | `MovementOperation` | S |
| MovementOperation.request | `[u8;32]` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1655` | `MovementOperation` | S |
| MovementOperation.requested_at | `f64` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1583` | `MovementOperation` | S |
| MovementOperation.result | `emitted WireguardResult` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1588` | `MovementOperation` | S |
| NetfilterHistory.birth | `Option<ValidationBirth>` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:271` | `NetfilterHistory` | S, R |
| NetfilterHistory.configuration | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:265` | `NetfilterHistory` | S, R |
| NetfilterHistory.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:270` | `NetfilterHistory` | S, R |
| NetfilterHistory.host_declaration | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:266` | `NetfilterHistory` | S, R |
| NetfilterHistory.kind | `Kind` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:261` | `NetfilterHistory` | S, R |
| NetfilterHistory.namespace | `Identity` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:264` | `NetfilterHistory` | S, R |
| NetfilterHistory.policy | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:267` | `NetfilterHistory` | S, R |
| NetfilterHistory.query | `Option<[u8; 32]>` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:268` | `NetfilterHistory` | S, R |
| NetfilterHistory.request | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:263` | `NetfilterHistory` | S, R |
| NetfilterHistory.requested_at | `f64` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:269` | `NetfilterHistory` | S, R |
| NetfilterHistory.result | `Option<PublicResult>` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:272` | `NetfilterHistory` | S, R |
| NetfilterHistory.scope | `Scope` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:262` | `NetfilterHistory` | S, R |
| NetfilterHistory.verified_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:273` | `NetfilterHistory` | S, R |
| NetfilterResult.namespace | `Identity` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:278` | `NetfilterResult` | S, R |
| NetfilterResult.observed_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:281` | `NetfilterResult` | S, R |
| NetfilterResult.policy | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:279` | `NetfilterResult` | S, R |
| OperationalReservation.global_transferred_ticket_limit | `u64/usize (amd64)` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:92` | `OperationalReservation` | S |
| OperationalReservation.member | `String` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:20` | `OperationalReservation` | S |
| OperationalReservation.member_transfer_pending | `bool` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:93` | `OperationalReservation` | S |
| OperationalReservation.original_jobs | `u64/usize (amd64)` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:91` | `OperationalReservation` | S |
| OperationalReservation.owner_epoch | `emitted OwnerEpoch` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:91` | `OperationalReservation` | S |
| OperationalReservation.suffix_complete | `bool` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:313` | `OperationalReservation` | S |
| OperationalReservation.suffix_failed | `bool` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:313` | `OperationalReservation` | S |
| OperationalReservation.suffix_jobs | `u64/usize (amd64)` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:313` | `OperationalReservation` | S |
| OriginalWriter.index | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:842` | `OriginalWriter` | S |
| OriginalWriter.pid | `u32` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:842` | `OriginalWriter` | S |
| OriginalWriter.start | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:842` | `OriginalWriter` | S |
| OwnerEpoch.boot | `String` | `crates/vprouter-launch/src/supervision.rs:38` | `OwnerEpoch` | S, R |
| OwnerEpoch.cgroup | `Identity` | `crates/vprouter-launch/src/supervision.rs:43` | `OwnerEpoch` | S, R |
| OwnerEpoch.invocation | `String` | `crates/vprouter-launch/src/supervision.rs:40` | `OwnerEpoch` | S, R |
| OwnerEpoch.pid | `u32` | `crates/vprouter-launch/src/supervision.rs:41` | `OwnerEpoch` | S, R |
| OwnerEpoch.start | `u64` | `crates/vprouter-launch/src/supervision.rs:42` | `OwnerEpoch` | S, R |
| OwnerEpoch.unit | `String` | `crates/vprouter-launch/src/supervision.rs:39` | `OwnerEpoch` | S, R |
| Placeholder.identity | `Identity` | `crates/vprouter-launch/src/owned/preparation/mount.rs:8` | `Placeholder` | S, R |
| Placeholder.mode | `u32` | `crates/vprouter-launch/src/owned/preparation/mount.rs:9` | `Placeholder` | S, R |
| Preparation.attachment | `emitted Attachment` | `crates/vprouter-launch/src/owned/preparation.rs:1619` | `Preparation` | S |
| Preparation.base_network | `emitted Identity` | `crates/vprouter-launch/src/owned/preparation.rs:1615` | `Preparation` | S |
| Preparation.base_network_absent | `bool` | `crates/vprouter-launch/src/owned/preparation.rs:1614` | `Preparation` | S |
| Preparation.birth | `emitted Birth` | `crates/vprouter-launch/src/owned/preparation.rs:1613` | `Preparation` | S |
| Preparation.bootstrap | `emitted list(BootstrapHistory)` | `crates/vprouter-launch/src/owned/preparation.rs:1632` | `Preparation` | S |
| Preparation.bootstrap_queries | `[Option<inspection::History>;3]` | `crates/vprouter-launch/src/owned/preparation.rs:1633` | `Preparation` | S |
| Preparation.canonical_owner_epoch | `emitted OwnerEpoch` | `crates/vprouter-launch/src/owned/preparation.rs:1642` | `Preparation` | S |
| Preparation.canonical_pending | `bool` | `crates/vprouter-launch/src/owned/preparation.rs:1645` | `Preparation` | S |
| Preparation.canonical_result_present | `bool` | `crates/vprouter-launch/src/owned/preparation.rs:1643` | `Preparation` | S |
| Preparation.data_network | `emitted Identity` | `crates/vprouter-launch/src/owned/preparation.rs:1616` | `Preparation` | S |
| Preparation.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation.rs:1613` | `Preparation` | S |
| Preparation.entry_attempt_absent | `bool` | `crates/vprouter-launch/src/owned/preparation.rs:1627` | `Preparation` | S |
| Preparation.entry_links_absent | `bool` | `crates/vprouter-launch/src/owned/preparation.rs:1626` | `Preparation` | S |
| Preparation.entry_phase | `emitted entry_phase` | `crates/vprouter-launch/src/owned/preparation.rs:1625` | `Preparation` | S |
| Preparation.entry_producer | `emitted EntryProducer&#124;null` | `crates/vprouter-launch/src/owned/preparation.rs:1629` | `Preparation` | S |
| Preparation.entry_producer_absent | `bool` | `crates/vprouter-launch/src/owned/preparation.rs:1631` | `Preparation` | S |
| Preparation.entry_terminal_absent | `bool` | `crates/vprouter-launch/src/owned/preparation.rs:1628` | `Preparation` | S |
| Preparation.fresh_transport | `emitted FreshTransport&#124;null` | `crates/vprouter-launch/src/owned/preparation.rs:1620` | `Preparation` | S |
| Preparation.host_link | `emitted list(HostLinkHistory)` | `crates/vprouter-launch/src/owned/preparation.rs:1622` | `Preparation` | S |
| Preparation.inspection | `emitted InspectionHistory` | `crates/vprouter-launch/src/owned/preparation.rs:1618` | `Preparation` | S |
| Preparation.member | `String` | `crates/vprouter-launch/src/owned/preparation.rs:1612` | `Preparation` | S |
| Preparation.member_native_jobs_collected | `bool` | `crates/vprouter-launch/src/owned/preparation.rs:1647` | `Preparation` | S |
| Preparation.movement_query | `emitted InspectionHistory&#124;null` | `crates/vprouter-launch/src/owned/preparation.rs:1639` | `Preparation` | S |
| Preparation.mutation_fenced | `bool` | `crates/vprouter-launch/src/owned/preparation.rs:1645` | `Preparation` | S |
| Preparation.native_children_reaped | `bool` | `crates/vprouter-launch/src/owned/preparation.rs:1646` | `Preparation` | S |
| Preparation.netfilter | `emitted list(NetfilterHistory)` | `crates/vprouter-launch/src/owned/preparation.rs:1637` | `Preparation` | S |
| Preparation.owner_host_anchor_present | `bool` | `crates/vprouter-launch/src/owned/preparation.rs:1641` | `Preparation` | S |
| Preparation.pending_bootstrap | `emitted null` | `crates/vprouter-launch/src/owned/preparation.rs:1649` | `Preparation` | S |
| Preparation.pending_host_link | `emitted null` | `crates/vprouter-launch/src/owned/preparation.rs:1623` | `Preparation` | S |
| Preparation.pending_producer_binding | `emitted null` | `crates/vprouter-launch/src/owned/preparation.rs:1630` | `Preparation` | S |
| Preparation.pending_producer_creation | `emitted null` | `crates/vprouter-launch/src/owned/preparation.rs:1640` | `Preparation` | S |
| Preparation.pending_wireguard | `emitted null` | `crates/vprouter-launch/src/owned/preparation.rs:1640` | `Preparation` | S |
| Preparation.producer_binding | `emitted ProducerBindingHistory&#124;null` | `crates/vprouter-launch/src/owned/preparation.rs:1635` | `Preparation` | S |
| Preparation.producer_binding_query | `emitted InspectionHistory&#124;null` | `crates/vprouter-launch/src/owned/preparation.rs:1634` | `Preparation` | S |
| Preparation.producer_creation | `emitted ProducerCreationHistory&#124;null` | `crates/vprouter-launch/src/owned/preparation.rs:1624` | `Preparation` | S |
| Preparation.producer_query | `emitted InspectionHistory&#124;null` | `crates/vprouter-launch/src/owned/preparation.rs:1636` | `Preparation` | S |
| Preparation.quarantine_query | `emitted InspectionHistory&#124;null` | `crates/vprouter-launch/src/owned/preparation.rs:1638` | `Preparation` | S |
| Preparation.requested_at | `f64` | `crates/vprouter-launch/src/owned/preparation.rs:1612` | `Preparation` | S |
| Preparation.service_reserved | `bool` | `crates/vprouter-launch/src/owned/preparation.rs:1644` | `Preparation` | S |
| Preparation.transport_network | `emitted Identity&#124;null` | `crates/vprouter-launch/src/owned/preparation.rs:1617` | `Preparation` | S |
| Preparation.wireguard | `emitted list(MovementHistory&#124;WireguardHistory)` | `crates/vprouter-launch/src/owned/preparation.rs:1621` | `Preparation` | S |
| Preparation.writers | `emitted list(Writer)` | `crates/vprouter-launch/src/owned/preparation.rs:1648` | `Preparation` | S |
| ProducerBinding.assembly | `emitted Assembly` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1145` | `ProducerBinding` | S |
| ProducerBinding.assembly_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1148` | `ProducerBinding` | S |
| ProducerBinding.canonical_negative_checks | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1146` | `ProducerBinding` | S |
| ProducerBinding.canonical_producer_published | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1147` | `ProducerBinding` | S |
| ProducerBinding.charges_after_drop | `emitted null` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1155` | `ProducerBinding` | S |
| ProducerBinding.charges_before | `emitted list(u64)` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1146` | `ProducerBinding` | S |
| ProducerBinding.charges_before_drop | `emitted list(u64)` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1146` | `ProducerBinding` | S |
| ProducerBinding.continued_original_context | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1154` | `ProducerBinding` | S |
| ProducerBinding.failed_constructor | `emitted null` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1145` | `ProducerBinding` | S |
| ProducerBinding.failure_retry | `emitted null` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1146` | `ProducerBinding` | S |
| ProducerBinding.fault | `u8` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1145` | `ProducerBinding` | S |
| ProducerBinding.final_process_verified_at | `f64` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1146` | `ProducerBinding` | S |
| ProducerBinding.health_ready_authorized | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1149` | `ProducerBinding` | S |
| ProducerBinding.host_network_links_or_routes_created | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1149` | `ProducerBinding` | S |
| ProducerBinding.movement_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1148` | `ProducerBinding` | S |
| ProducerBinding.multi_exit_runtime_proven | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1149` | `ProducerBinding` | S |
| ProducerBinding.observation | `emitted ProducerObservation` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1145` | `ProducerBinding` | S |
| ProducerBinding.original_group | `emitted Identity` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1146` | `ProducerBinding` | S |
| ProducerBinding.original_provision_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1148` | `ProducerBinding` | S |
| ProducerBinding.parent_pristine | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1149` | `ProducerBinding` | S |
| ProducerBinding.placement_authorized | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1149` | `ProducerBinding` | S |
| ProducerBinding.preparation | `emitted Preparation` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1145` | `ProducerBinding` | S |
| ProducerBinding.producer_binding_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1148` | `ProducerBinding` | S |
| ProducerBinding.producer_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1148` | `ProducerBinding` | S |
| ProducerBinding.producer_exception_authorized | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1149` | `ProducerBinding` | S |
| ProducerBinding.quarantine_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1148` | `ProducerBinding` | S |
| ProducerBinding.query | `emitted Query` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1145` | `ProducerBinding` | S |
| ProducerBinding.requirement8_complete | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1149` | `ProducerBinding` | S |
| ProducerBinding.resource_cleanup_authorized | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1149` | `ProducerBinding` | S |
| ProducerBinding.result_writer_held | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1147` | `ProducerBinding` | S |
| ProducerBinding.retained_result_writer | `emitted null` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1146` | `ProducerBinding` | S |
| ProducerBinding.same_original_source | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1149` | `ProducerBinding` | S |
| ProducerBinding.schema | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1145` | `ProducerBinding` | S |
| ProducerBinding.unacknowledged_observation_retained | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1147` | `ProducerBinding` | S |
| ProducerBinding.up_authorized | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1149` | `ProducerBinding` | S |
| ProducerBinding.whole_chain_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1148` | `ProducerBinding` | S |
| ProducerBindingHistory.birth | `Option<ValidationBirth>` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:24` | `ProducerBindingHistory` | S, R |
| ProducerBindingHistory.creation | `producer_creation::History` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:26` | `ProducerBindingHistory` | S, R |
| ProducerBindingHistory.data | `Identity` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:20` | `ProducerBindingHistory` | S, R |
| ProducerBindingHistory.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:23` | `ProducerBindingHistory` | S, R |
| ProducerBindingHistory.group | `Identity` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:25` | `ProducerBindingHistory` | S, R |
| ProducerBindingHistory.name | `String` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:19` | `ProducerBindingHistory` | S, R |
| ProducerBindingHistory.parent | `Identity` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:18` | `ProducerBindingHistory` | S, R |
| ProducerBindingHistory.pins | `[(u64, u64, u32); 6]` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:28` | `ProducerBindingHistory` | S, R |
| ProducerBindingHistory.policy | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:27` | `ProducerBindingHistory` | S, R |
| ProducerBindingHistory.query | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:21` | `ProducerBindingHistory` | S, R |
| ProducerBindingHistory.request | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:17` | `ProducerBindingHistory` | S, R |
| ProducerBindingHistory.requested_at | `f64` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:22` | `ProducerBindingHistory` | S, R |
| ProducerBindingHistory.result | `Option<PublicResult>` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:29` | `ProducerBindingHistory` | S, R |
| ProducerBindingHistory.verified_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:30` | `ProducerBindingHistory` | S, R |
| ProducerBindingResult.group | `Identity` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:9` | `ProducerBindingResult` | S, R |
| ProducerBindingResult.namespace | `Identity` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:8` | `ProducerBindingResult` | S, R |
| ProducerBindingResult.observed_at | `f64` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:12` | `ProducerBindingResult` | S, R |
| ProducerBindingResult.pins | `[(u64, u64, u32); 6]` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:11` | `ProducerBindingResult` | S, R |
| ProducerBindingResult.policy | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:10` | `ProducerBindingResult` | S, R |
| ProducerCreationHistory.birth | `Option<ValidationBirth>` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:15` | `ProducerCreationHistory` | S, R |
| ProducerCreationHistory.data | `Identity` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:11` | `ProducerCreationHistory` | S, R |
| ProducerCreationHistory.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:14` | `ProducerCreationHistory` | S, R |
| ProducerCreationHistory.group | `Option<Identity>` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:16` | `ProducerCreationHistory` | S, R |
| ProducerCreationHistory.name | `String` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:10` | `ProducerCreationHistory` | S, R |
| ProducerCreationHistory.parent | `Identity` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:9` | `ProducerCreationHistory` | S, R |
| ProducerCreationHistory.query | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:12` | `ProducerCreationHistory` | S, R |
| ProducerCreationHistory.request | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:8` | `ProducerCreationHistory` | S, R |
| ProducerCreationHistory.requested_at | `f64` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:13` | `ProducerCreationHistory` | S, R |
| ProducerCreationHistory.verified_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:17` | `ProducerCreationHistory` | S, R |
| ProducerObservation.accepted_at | `f64` | `crates/vprouter-launch/src/kernel/producer_binding.rs:579` | `ProducerObservation` | S |
| ProducerObservation.acknowledged | `bool` | `crates/vprouter-launch/src/kernel/producer_binding.rs:579` | `ProducerObservation` | S |
| ProducerObservation.actual_wait_status | `i32` | `crates/vprouter-launch/src/kernel/producer_binding.rs:576` | `ProducerObservation` | S |
| ProducerObservation.birth | `emitted Birth` | `crates/vprouter-launch/src/kernel/producer_binding.rs:576` | `ProducerObservation` | S |
| ProducerObservation.borrowed_registration_count | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/producer_binding.rs:578` | `ProducerObservation` | S |
| ProducerObservation.complete_native_registration | `bool` | `crates/vprouter-launch/src/kernel/producer_binding.rs:578` | `ProducerObservation` | S |
| ProducerObservation.context_retained | `bool` | `crates/vprouter-launch/src/kernel/producer_binding.rs:580` | `ProducerObservation` | S |
| ProducerObservation.data | `emitted Identity` | `crates/vprouter-launch/src/kernel/producer_binding.rs:575` | `ProducerObservation` | S |
| ProducerObservation.deadline | `f64` | `crates/vprouter-launch/src/kernel/producer_binding.rs:574` | `ProducerObservation` | S |
| ProducerObservation.durable_birth_released | `bool` | `crates/vprouter-launch/src/kernel/producer_binding.rs:579` | `ProducerObservation` | S |
| ProducerObservation.eof | `bool` | `crates/vprouter-launch/src/kernel/producer_binding.rs:580` | `ProducerObservation` | S |
| ProducerObservation.group | `emitted Identity` | `crates/vprouter-launch/src/kernel/producer_binding.rs:575` | `ProducerObservation` | S |
| ProducerObservation.name | `String` | `crates/vprouter-launch/src/kernel/producer_binding.rs:575` | `ProducerObservation` | S |
| ProducerObservation.native_born | `bool` | `crates/vprouter-launch/src/kernel/producer_binding.rs:576` | `ProducerObservation` | S |
| ProducerObservation.native_job_state | `emitted job_state` | `crates/vprouter-launch/src/kernel/producer_binding.rs:577` | `ProducerObservation` | S |
| ProducerObservation.original_pid | `u32` | `crates/vprouter-launch/src/kernel/producer_binding.rs:576` | `ProducerObservation` | S |
| ProducerObservation.original_registration_slots_verified | `bool` | `crates/vprouter-launch/src/kernel/producer_binding.rs:578` | `ProducerObservation` | S |
| ProducerObservation.original_start | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/producer_binding.rs:576` | `ProducerObservation` | S |
| ProducerObservation.parent | `emitted Identity` | `crates/vprouter-launch/src/kernel/producer_binding.rs:575` | `ProducerObservation` | S |
| ProducerObservation.pins | `[(u64,u64,u32);6]` | `crates/vprouter-launch/src/kernel/producer_binding.rs:575` | `ProducerObservation` | S |
| ProducerObservation.placement_authorized | `bool` | `crates/vprouter-launch/src/kernel/producer_binding.rs:580` | `ProducerObservation` | S |
| ProducerObservation.policy | `[u8;32]` | `crates/vprouter-launch/src/kernel/producer_binding.rs:575` | `ProducerObservation` | S |
| ProducerObservation.producer_exception_authorized | `bool` | `crates/vprouter-launch/src/kernel/producer_binding.rs:580` | `ProducerObservation` | S |
| ProducerObservation.query | `[u8;32]` | `crates/vprouter-launch/src/kernel/producer_binding.rs:574` | `ProducerObservation` | S |
| ProducerObservation.registered_native_slots | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/producer_binding.rs:578` | `ProducerObservation` | S |
| ProducerObservation.request | `[u8;32]` | `crates/vprouter-launch/src/kernel/producer_binding.rs:574` | `ProducerObservation` | S |
| ProducerObservation.requested_at | `f64` | `crates/vprouter-launch/src/kernel/producer_binding.rs:574` | `ProducerObservation` | S |
| ProducerObservation.result | `emitted ProducerBindingResult` | `crates/vprouter-launch/src/kernel/producer_binding.rs:579` | `ProducerObservation` | S |
| ProducerObservation.up_authorized | `bool` | `crates/vprouter-launch/src/kernel/producer_binding.rs:580` | `ProducerObservation` | S |
| ProducerWitness.acknowledged | `bool` | `crates/vprouter-launch/src/kernel/producer_creation.rs:710` | `ProducerWitness` | S |
| ProducerWitness.actual_wait_status | `i32` | `crates/vprouter-launch/src/kernel/producer_creation.rs:707` | `ProducerWitness` | S |
| ProducerWitness.birth | `emitted Birth` | `crates/vprouter-launch/src/kernel/producer_creation.rs:39` | `ProducerWitness` | S |
| ProducerWitness.context_retained | `bool` | `crates/vprouter-launch/src/kernel/producer_creation.rs:711` | `ProducerWitness` | S |
| ProducerWitness.data | `emitted Identity` | `crates/vprouter-launch/src/kernel/producer_creation.rs:705` | `ProducerWitness` | S |
| ProducerWitness.deadline | `f64` | `crates/vprouter-launch/src/kernel/producer_creation.rs:704` | `ProducerWitness` | S |
| ProducerWitness.durable_birth_released | `bool` | `crates/vprouter-launch/src/kernel/producer_creation.rs:710` | `ProducerWitness` | S |
| ProducerWitness.eof | `bool` | `crates/vprouter-launch/src/kernel/producer_creation.rs:43` | `ProducerWitness` | S |
| ProducerWitness.full_descriptor_registration | `bool` | `crates/vprouter-launch/src/kernel/producer_creation.rs:709` | `ProducerWitness` | S |
| ProducerWitness.group | `emitted Identity` | `crates/vprouter-launch/src/kernel/producer_creation.rs:705` | `ProducerWitness` | S |
| ProducerWitness.name | `String` | `crates/vprouter-launch/src/kernel/producer_creation.rs:705` | `ProducerWitness` | S |
| ProducerWitness.native_born | `bool` | `crates/vprouter-launch/src/kernel/producer_creation.rs:707` | `ProducerWitness` | S |
| ProducerWitness.native_job_state | `emitted job_state` | `crates/vprouter-launch/src/kernel/producer_creation.rs:708` | `ProducerWitness` | S |
| ProducerWitness.operational_publication | `bool` | `crates/vprouter-launch/src/kernel/producer_creation.rs:711` | `ProducerWitness` | S |
| ProducerWitness.original_pid | `u32` | `crates/vprouter-launch/src/kernel/producer_creation.rs:706` | `ProducerWitness` | S |
| ProducerWitness.original_start | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/producer_creation.rs:706` | `ProducerWitness` | S |
| ProducerWitness.parent | `emitted Identity` | `crates/vprouter-launch/src/kernel/producer_creation.rs:705` | `ProducerWitness` | S |
| ProducerWitness.parent_death_lock_survival_claimed | `bool` | `crates/vprouter-launch/src/kernel/producer_creation.rs:711` | `ProducerWitness` | S |
| ProducerWitness.query | `[u8;32]` | `crates/vprouter-launch/src/kernel/producer_creation.rs:704` | `ProducerWitness` | S |
| ProducerWitness.received_original_group | `bool` | `crates/vprouter-launch/src/kernel/producer_creation.rs:709` | `ProducerWitness` | S |
| ProducerWitness.registered_native_slots | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/producer_creation.rs:709` | `ProducerWitness` | S |
| ProducerWitness.request | `[u8;32]` | `crates/vprouter-launch/src/kernel/producer_creation.rs:28` | `ProducerWitness` | S |
| ProducerWitness.requested_at | `f64` | `crates/vprouter-launch/src/kernel/producer_creation.rs:704` | `ProducerWitness` | S |
| ProducerWitness.verified_at | `f64` | `crates/vprouter-launch/src/kernel/producer_creation.rs:23` | `ProducerWitness` | S |
| Provision.attachment | `emitted AttachmentWitness` | `crates/vprouter-launch/src/attachment/provision.rs:1027` | `Provision` | S |
| Provision.continued_original_context | `bool` | `crates/vprouter-launch/src/attachment/provision.rs:1038` | `Provision` | S |
| Provision.failed_constructor | `emitted null` | `crates/vprouter-launch/src/attachment/provision.rs:1029` | `Provision` | S |
| Provision.fault | `u8` | `crates/vprouter-launch/src/attachment/provision.rs:1027` | `Provision` | S |
| Provision.held_real_result_writer | `bool` | `crates/vprouter-launch/src/attachment/provision.rs:1029` | `Provision` | S |
| Provision.host_resources_created | `bool` | `crates/vprouter-launch/src/attachment/provision.rs:1032` | `Provision` | S |
| Provision.operational_reuse_authorized | `bool` | `crates/vprouter-launch/src/attachment/provision.rs:1032` | `Provision` | S |
| Provision.operations | `emitted list(MovementOperation)` | `crates/vprouter-launch/src/attachment/provision.rs:1028` | `Provision` | S |
| Provision.original_socket_registrations_borrowed | `bool` | `crates/vprouter-launch/src/attachment/provision.rs:1031` | `Provision` | S |
| Provision.parent_pristine | `bool` | `crates/vprouter-launch/src/attachment/provision.rs:1029` | `Provision` | S |
| Provision.preparation | `emitted Preparation` | `crates/vprouter-launch/src/attachment/provision.rs:1027` | `Provision` | S |
| Provision.requirement8_complete | `bool` | `crates/vprouter-launch/src/attachment/provision.rs:1032` | `Provision` | S |
| Provision.same_service_retained | `bool` | `crates/vprouter-launch/src/attachment/provision.rs:1030` | `Provision` | S |
| Provision.schema | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/provision.rs:1027` | `Provision` | S |
| Provision.transport_creation | `emitted TransportWitness` | `crates/vprouter-launch/src/attachment/provision.rs:1028` | `Provision` | S |
| Provision.transport_distinct_from_host_and_data | `bool` | `crates/vprouter-launch/src/attachment/provision.rs:1030` | `Provision` | S |
| Provision.transport_mount | `emitted MountWitness` | `crates/vprouter-launch/src/attachment/provision.rs:1028` | `Provision` | S |
| Provision.unacknowledged_native_result_retained | `bool` | `crates/vprouter-launch/src/attachment/provision.rs:1029` | `Provision` | S |
| Provision.whole_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/provision.rs:1030` | `Provision` | S |
| Provision.wireguard_down_only | `bool` | `crates/vprouter-launch/src/attachment/provision.rs:1031` | `Provision` | S |
| Quarantine.continued_original_context | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1029` | `Quarantine` | S |
| Quarantine.failed_constructor | `emitted null` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1026` | `Quarantine` | S |
| Quarantine.fault | `u8` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1025` | `Quarantine` | S |
| Quarantine.final_process_verified_at | `f64` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1027` | `Quarantine` | S |
| Quarantine.held_real_result_writer | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1027` | `Quarantine` | S |
| Quarantine.host_network_links_or_routes_created | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1031` | `Quarantine` | S |
| Quarantine.initial_quarantine_installation_observed_all_scopes | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1031` | `Quarantine` | S |
| Quarantine.initial_quarantine_only | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1030` | `Quarantine` | S |
| Quarantine.movement | `emitted Movement` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1025` | `Quarantine` | S |
| Quarantine.movement_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1029` | `Quarantine` | S |
| Quarantine.operational_reuse_authorized | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1031` | `Quarantine` | S |
| Quarantine.operations | `emitted list(QuarantineOperation)` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1025` | `Quarantine` | S |
| Quarantine.original_provision_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1029` | `Quarantine` | S |
| Quarantine.own_intent_polling | `emitted QuarantineIntent` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1026` | `Quarantine` | S |
| Quarantine.parent_pristine | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1030` | `Quarantine` | S |
| Quarantine.preparation | `emitted Preparation` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1025` | `Quarantine` | S |
| Quarantine.producer | `emitted ProducerWitness` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1026` | `Quarantine` | S |
| Quarantine.producer_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1028` | `Quarantine` | S |
| Quarantine.producer_exceptions_authorized | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1031` | `Quarantine` | S |
| Quarantine.producer_group_creation_observed | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1031` | `Quarantine` | S |
| Quarantine.producer_operational_publication | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1030` | `Quarantine` | S |
| Quarantine.producer_query | `emitted Query` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1026` | `Quarantine` | S |
| Quarantine.quarantine_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1028` | `Quarantine` | S |
| Quarantine.quarantine_query | `emitted Query` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1026` | `Quarantine` | S |
| Quarantine.requirement8_complete | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1031` | `Quarantine` | S |
| Quarantine.same_service_retained | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1030` | `Quarantine` | S |
| Quarantine.schema | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1025` | `Quarantine` | S |
| Quarantine.unacknowledged_native_result_retained | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1027` | `Quarantine` | S |
| Quarantine.up_authorized | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1031` | `Quarantine` | S |
| Quarantine.wan | `emitted Wan` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1026` | `Quarantine` | S |
| Quarantine.whole_chain_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1028` | `Quarantine` | S |
| QuarantineIntent.actual_wait_status | `i32` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:843` | `QuarantineIntent` | S |
| QuarantineIntent.deadline | `f64` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:843` | `QuarantineIntent` | S |
| QuarantineIntent.held_pending_polls | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:841` | `QuarantineIntent` | S |
| QuarantineIntent.negative_checks | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:842` | `QuarantineIntent` | S |
| QuarantineIntent.original_writer | `emitted OriginalWriter` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:842` | `QuarantineIntent` | S |
| QuarantineIntent.queued_polls | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:841` | `QuarantineIntent` | S |
| QuarantineIntent.requested_at | `f64` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:843` | `QuarantineIntent` | S |
| QuarantineIntent.verified_at | `f64` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:843` | `QuarantineIntent` | S |
| QuarantineOperation.accepted_at | `f64` | `crates/vprouter-launch/src/kernel/netfilter_role.rs:50` | `QuarantineOperation` | S |
| QuarantineOperation.acknowledged | `bool` | `crates/vprouter-launch/src/kernel/netfilter_role.rs:51` | `QuarantineOperation` | S |
| QuarantineOperation.actual_wait_status | `i32` | `crates/vprouter-launch/src/kernel/netfilter_role.rs:71` | `QuarantineOperation` | S |
| QuarantineOperation.birth | `emitted Birth` | `crates/vprouter-launch/src/kernel/netfilter_role.rs:48` | `QuarantineOperation` | S |
| QuarantineOperation.borrowed_registration_count | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/netfilter_role.rs:749` | `QuarantineOperation` | S |
| QuarantineOperation.context_retained | `bool` | `crates/vprouter-launch/src/kernel/netfilter_role.rs:751` | `QuarantineOperation` | S |
| QuarantineOperation.deadline | `f64` | `crates/vprouter-launch/src/kernel/netfilter_role.rs:745` | `QuarantineOperation` | S |
| QuarantineOperation.full_descriptor_registration | `bool` | `crates/vprouter-launch/src/kernel/netfilter_role.rs:749` | `QuarantineOperation` | S |
| QuarantineOperation.kind | `emitted netfilter_kind` | `crates/vprouter-launch/src/kernel/netfilter_role.rs:744` | `QuarantineOperation` | S |
| QuarantineOperation.native_born | `bool` | `crates/vprouter-launch/src/kernel/netfilter_role.rs:747` | `QuarantineOperation` | S |
| QuarantineOperation.native_job_state | `emitted job_state` | `crates/vprouter-launch/src/kernel/netfilter_role.rs:748` | `QuarantineOperation` | S |
| QuarantineOperation.original_pid | `u32` | `crates/vprouter-launch/src/kernel/netfilter_role.rs:746` | `QuarantineOperation` | S |
| QuarantineOperation.original_start | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/netfilter_role.rs:746` | `QuarantineOperation` | S |
| QuarantineOperation.registered_native_slots | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/netfilter_role.rs:749` | `QuarantineOperation` | S |
| QuarantineOperation.request | `[u8;32]` | `crates/vprouter-launch/src/kernel/netfilter_role.rs:34` | `QuarantineOperation` | S |
| QuarantineOperation.requested_at | `f64` | `crates/vprouter-launch/src/kernel/netfilter_role.rs:745` | `QuarantineOperation` | S |
| QuarantineOperation.result | `emitted NetfilterResult` | `crates/vprouter-launch/src/kernel/netfilter_role.rs:49` | `QuarantineOperation` | S |
| QuarantineOperation.scope | `emitted scope` | `crates/vprouter-launch/src/kernel/netfilter_role.rs:744` | `QuarantineOperation` | S |
| Query.actual_wait_status | `i32` | `crates/vprouter-launch/src/kernel/docker_query.rs:1271` | `Query` | S |
| Query.birth | `emitted Birth` | `crates/vprouter-launch/src/kernel/docker_query.rs:1271` | `Query` | S |
| Query.deadline | `f64` | `crates/vprouter-launch/src/kernel/docker_query.rs:1271` | `Query` | S |
| Query.facts | `emitted QueryFacts` | `crates/vprouter-launch/src/kernel/docker_query.rs:1272` | `Query` | S |
| Query.handler_identity_claimed | `bool` | `crates/vprouter-launch/src/kernel/docker_query.rs:1276` | `Query` | S |
| Query.kind | `emitted query_kind` | `crates/vprouter-launch/src/kernel/docker_query.rs:1270` | `Query` | S |
| Query.listener_origin_gid | `u32` | `crates/vprouter-launch/src/kernel/docker_query.rs:1275` | `Query` | S |
| Query.listener_origin_pid | `i32` | `crates/vprouter-launch/src/kernel/docker_query.rs:1273` | `Query` | S |
| Query.listener_origin_uid | `u32` | `crates/vprouter-launch/src/kernel/docker_query.rs:1274` | `Query` | S |
| Query.original_peer_receipt | `bool` | `crates/vprouter-launch/src/kernel/docker_query.rs:1272` | `Query` | S |
| Query.requested_at | `f64` | `crates/vprouter-launch/src/kernel/docker_query.rs:1270` | `Query` | S |
| Query.verified_at | `f64` | `crates/vprouter-launch/src/kernel/docker_query.rs:1271` | `Query` | S |
| QueryFacts.pid | `u32` | `crates/vprouter-launch/src/attachment.rs:793` | `QueryFacts` | S, R |
| QueryFacts.security | `super::evidence::DaemonSecurity` | `crates/vprouter-launch/src/attachment.rs:794` | `QueryFacts` | S, R |
| Resource.actual_wait_status | `i32` | `crates/vprouter-launch/src/kernel.rs:2511` | `Resource` | S |
| Resource.fully_retired | `bool` | `crates/vprouter-launch/src/kernel.rs:2513` | `Resource` | S |
| Resource.kind | `emitted job_kind` | `crates/vprouter-launch/src/kernel.rs:2510` | `Resource` | S |
| Resource.launch_charge_retired | `bool` | `crates/vprouter-launch/src/kernel.rs:2512` | `Resource` | S |
| Resource.lower_charge_required | `bool` | `crates/vprouter-launch/src/kernel.rs:2512` | `Resource` | S |
| Resource.lower_charge_retired | `emitted bool&#124;null` | `crates/vprouter-launch/src/kernel.rs:2513` | `Resource` | S |
| Resource.lower_gated_retirement_refused | `emitted bool&#124;null` | `crates/vprouter-launch/src/kernel.rs:2513` | `Resource` | S |
| Resource.native_job_state | `emitted job_state` | `crates/vprouter-launch/src/kernel.rs:2514` | `Resource` | S |
| Resource.original_pid | `u32` | `crates/vprouter-launch/src/kernel.rs:2510` | `Resource` | S |
| Resource.original_start | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel.rs:2510` | `Resource` | S |
| Resource.transfer_started | `bool` | `crates/vprouter-launch/src/kernel.rs:2511` | `Resource` | S |
| Route.destination | `IpAddr` | `crates/vprouter-network/src/project.rs:62` | `Route` | S, R |
| Route.flags | `u32` | `crates/vprouter-network/src/project.rs:72` | `Route` | S, R |
| Route.gateway | `Option<IpAddr>` | `crates/vprouter-network/src/project.rs:67` | `Route` | S, R |
| Route.kind | `u8` | `crates/vprouter-network/src/project.rs:68` | `Route` | S, R |
| Route.metric | `u32` | `crates/vprouter-network/src/project.rs:71` | `Route` | S, R |
| Route.nexthop_id | `Option<u32>` | `crates/vprouter-network/src/project.rs:60` | `Route` | S, R |
| Route.output | `u32` | `crates/vprouter-network/src/project.rs:65` | `Route` | S, R |
| Route.preference | `u8` | `crates/vprouter-network/src/project.rs:61` | `Route` | S, R |
| Route.prefix | `u8` | `crates/vprouter-network/src/project.rs:63` | `Route` | S, R |
| Route.protocol | `u8` | `crates/vprouter-network/src/project.rs:70` | `Route` | S, R |
| Route.scope | `u8` | `crates/vprouter-network/src/project.rs:69` | `Route` | S, R |
| Route.source | `Option<IpAddr>` | `crates/vprouter-network/src/project.rs:66` | `Route` | S, R |
| Route.table | `u32` | `crates/vprouter-network/src/project.rs:64` | `Route` | S, R |
| Rule.action | `u8` | `crates/vprouter-network/src/project.rs:80` | `Rule` | S, R |
| Rule.flags | `u32` | `crates/vprouter-network/src/project.rs:81` | `Rule` | S, R |
| Rule.fwmark | `Option<u32>` | `crates/vprouter-network/src/project.rs:82` | `Rule` | S, R |
| Rule.fwmask | `Option<u32>` | `crates/vprouter-network/src/project.rs:83` | `Rule` | S, R |
| Rule.goto | `Option<u32>` | `crates/vprouter-network/src/project.rs:86` | `Rule` | S, R |
| Rule.ipv6 | `bool` | `crates/vprouter-network/src/project.rs:77` | `Rule` | S, R |
| Rule.priority | `u32` | `crates/vprouter-network/src/project.rs:78` | `Rule` | S, R |
| Rule.protocol | `Option<u8>` | `crates/vprouter-network/src/project.rs:88` | `Rule` | S, R |
| Rule.realm | `Option<u32>` | `crates/vprouter-network/src/project.rs:87` | `Rule` | S, R |
| Rule.suppress_ifgroup | `Option<u32>` | `crates/vprouter-network/src/project.rs:85` | `Rule` | S, R |
| Rule.suppress_prefixlen | `Option<u32>` | `crates/vprouter-network/src/project.rs:84` | `Rule` | S, R |
| Rule.table | `u32` | `crates/vprouter-network/src/project.rs:79` | `Rule` | S, R |
| TransportWitness.actual_wait_status | `i32` | `crates/vprouter-launch/src/kernel/fresh_transport.rs:502` | `TransportWitness` | S |
| TransportWitness.birth | `emitted Birth` | `crates/vprouter-launch/src/kernel/fresh_transport.rs:36` | `TransportWitness` | S |
| TransportWitness.data | `emitted Identity` | `crates/vprouter-launch/src/kernel/fresh_transport.rs:504` | `TransportWitness` | S |
| TransportWitness.deadline | `f64` | `crates/vprouter-launch/src/kernel/fresh_transport.rs:503` | `TransportWitness` | S |
| TransportWitness.durable_birth_released | `bool` | `crates/vprouter-launch/src/kernel/fresh_transport.rs:505` | `TransportWitness` | S |
| TransportWitness.eof | `bool` | `crates/vprouter-launch/src/kernel/fresh_transport.rs:40` | `TransportWitness` | S |
| TransportWitness.host | `emitted Identity` | `crates/vprouter-launch/src/kernel/fresh_transport.rs:504` | `TransportWitness` | S |
| TransportWitness.original_source_retained | `bool` | `crates/vprouter-launch/src/kernel/fresh_transport.rs:505` | `TransportWitness` | S |
| TransportWitness.request | `[u8;32]` | `crates/vprouter-launch/src/kernel/fresh_transport.rs:27` | `TransportWitness` | S |
| TransportWitness.requested_at | `f64` | `crates/vprouter-launch/src/kernel/fresh_transport.rs:503` | `TransportWitness` | S |
| TransportWitness.source | `emitted Identity` | `crates/vprouter-launch/src/kernel/fresh_transport.rs:504` | `TransportWitness` | S |
| TransportWitness.verified_at | `f64` | `crates/vprouter-launch/src/kernel/fresh_transport.rs:23` | `TransportWitness` | S |
| ValidatorWitness.actual_wait_status | `i32` | `crates/vprouter-launch/src/attachment/mount.rs:845` | `ValidatorWitness` | S |
| ValidatorWitness.birth | `emitted Birth` | `crates/vprouter-launch/src/attachment/mount.rs:867` | `ValidatorWitness` | S |
| Wan.address | `[u8;6]` | `crates/vprouter-launch/src/attachment/host_declaration.rs:19` | `Wan` | S |
| Wan.deadline | `f64` | `crates/vprouter-launch/src/attachment/host_declaration.rs:238` | `Wan` | S |
| Wan.declaration_digest | `[u8;32]` | `crates/vprouter-launch/src/attachment/host_declaration.rs:237` | `Wan` | S |
| Wan.host_namespace | `emitted Identity` | `crates/vprouter-launch/src/attachment/host_declaration.rs:29` | `Wan` | S |
| Wan.index | `u32` | `crates/vprouter-launch/src/attachment/host_declaration.rs:18` | `Wan` | S |
| Wan.name | `String` | `crates/vprouter-launch/src/attachment/host_declaration.rs:17` | `Wan` | S |
| Wan.original_observer_retained | `bool` | `crates/vprouter-launch/src/attachment/host_declaration.rs:238` | `Wan` | S |
| Wan.requested_at | `f64` | `crates/vprouter-launch/src/attachment/host_declaration.rs:238` | `Wan` | S |
| Wan.verified_at | `f64` | `crates/vprouter-launch/src/attachment/host_declaration.rs:169` | `Wan` | S |
| Wireguard.index | `u32` | `crates/vprouter-network/src/project.rs:119` | `Wireguard` | S, R |
| Wireguard.name | `String` | `crates/vprouter-network/src/project.rs:120` | `Wireguard` | S, R |
| Wireguard.peers | `Vec<Peer>` | `crates/vprouter-network/src/project.rs:122` | `Wireguard` | S, R |
| Wireguard.public_key | `[u8; 32]` | `crates/vprouter-network/src/project.rs:121` | `Wireguard` | S, R |
| WireguardHistory.birth | `Option<ValidationBirth>` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:14` | `WireguardHistory` | S |
| WireguardHistory.configuration | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:11` | `WireguardHistory` | S |
| WireguardHistory.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:13` | `WireguardHistory` | S |
| WireguardHistory.kind | `Kind` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:8` | `WireguardHistory` | S |
| WireguardHistory.namespace | `Identity` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:10` | `WireguardHistory` | S |
| WireguardHistory.request | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:9` | `WireguardHistory` | S |
| WireguardHistory.requested_at | `f64` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:12` | `WireguardHistory` | S |
| WireguardHistory.result | `Option<PublicResult>` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:15` | `WireguardHistory` | S |
| WireguardHistory.verified_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:16` | `WireguardHistory` | S |
| WireguardPeer.allowed_ips | `Vec<(IpAddr, u8)>` | `crates/vprouter-network/src/project.rs:113` | `WireguardPeer` | S, R |
| WireguardPeer.endpoint | `SocketAddr` | `crates/vprouter-network/src/project.rs:112` | `WireguardPeer` | S, R |
| WireguardPeer.handshake_unix | `Option<f64>` | `crates/vprouter-network/src/project.rs:114` | `WireguardPeer` | S, R |
| WireguardPeer.public_key | `[u8; 32]` | `crates/vprouter-network/src/project.rs:111` | `WireguardPeer` | S, R |
| WireguardResult.link | `Option<vprouter_network::Link>` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:26` | `WireguardResult` | S |
| WireguardResult.namespace | `Identity` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:25` | `WireguardResult` | S |
| WireguardResult.wireguard | `Option<vprouter_network::Wireguard>` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:27` | `WireguardResult` | S |
| Writer.actual_wait_status | `i32` | `crates/vprouter-launch/src/owned/preparation.rs:1581` | `Writer` | S |
| Writer.io_deadline | `f64` | `crates/vprouter-launch/src/owned/preparation.rs:1580` | `Writer` | S |
| Writer.parent_deadline | `f64` | `crates/vprouter-launch/src/owned/preparation.rs:1581` | `Writer` | S |
| Writer.phase | `String` | `crates/vprouter-launch/src/owned/preparation.rs:1579` | `Writer` | S |
| Writer.pid | `u32` | `crates/vprouter-launch/src/owned/preparation.rs:1579` | `Writer` | S |
| Writer.queued_at | `f64` | `crates/vprouter-launch/src/owned/preparation.rs:1580` | `Writer` | S |
| Writer.start | `u64/usize (amd64)` | `crates/vprouter-launch/src/owned/preparation.rs:1579` | `Writer` | S |
| Writer.verified_at | `f64` | `crates/vprouter-launch/src/owned/preparation.rs:1582` | `Writer` | S |


## Bootstrap success-path guards, function by function

Paths in this ledger are relative to `crates/vprouter-launch/src/`. `E` means
enforced for the serialized successful profile, with the named mutation test;
`N` means a native-only clause in that function, **NOT_RUN**, even where its
recorded projection is checked. No E/N row claims its native clauses are enforced.
Methods that only return a field or translate an error are not validation guards.

Test IDs (all in `test-validate-run410-witness.py`):

| ID | Actual test name |
| --- | --- |
| F | `test_round3_fifteen_reviewer_fixtures_through_validate` |
| W | `test_all_transport_observation_binding_fields_through_validate` |
| INIT | `test_initial_observation_kind_cannot_claim_another_query_stage` |
| R | `test_binding_registry_covers_observations_and_refuses_unregistered_object` |
| RF | `test_registry_coverage_requires_each_identity_field` |
| SW | `test_source_extracted_widths_cover_every_witness_leaf` |
| S | `test_every_real_witness_leaf_through_validate` |
| C | `test_canonical_history_guards_coordinated_copies` |
| P | `test_preparation_success_guards_through_validate` |
| PX | `test_retained_preparation_prefix_through_validate` |
| I | `test_held_intents_bound_to_original_writers_through_validate` |
| Q | `test_boot_deadlines_scope_identity_and_nested_authority` |
| B | `test_binding_result_matches_own_request_through_validate` |
| A | `test_additional_recorded_success_guards` |
| H | `test_retained_success_guards_through_validate` |
| BS | `test_birth_status_pin_and_writer_contract_mutations` |
| SC | `test_success_contract_mutations` |
| ARR | `test_result_and_request_pin_sizes_through_validate` |
| BOOL | `test_all_success_booleans_in_retained_emitters` |

| Rust guard function / source | Recorded enforcement and test IDs | Unserialized clauses |
| --- | --- | --- |
| `owned/preparation/bootstrap.rs:33` History::completed_at | E: populated birth/result/verified, scope ordering; S,Q | none for its serialized fields |
| `:39` History::validate, scope/index/namespace | E: host/transport/DATA order, primary member and allocated namespace; Q,C,S | full Record anchor not embedded |
| `:49` History::validate, query/creation/publication prerequisites | E: completed context-specific query, no Initial, original creation/group/DATA, canonical binding publication; C,B,Q,PX | original shared service capability |
| `:77` History::validate, request/time/policy/pins | E: nonzero digest, two-second query window, prior completion, four host ops/six policies, same-scope completed InitialQuarantine, eight distinct same-device pins with original parent/group; C,Q,ARR,S | regenerate request digest from private constructor inputs |
| `:110` History::validate, birth/result completion | E: u32 PID>1, start>0, finite ordered birth/observation/ack and original deadline, result namespace/group/policy/pins equal request; Q,BS,B,S | actual native birth/custody |
| `:142` Server::bootstrap_policy | E/N: original producer group, four host operations, six policies, canonical publication and scoped policy; C,B,Q | source.bind_service, acknowledged native source, live preparation idle |
| `:189` phase | E: exact18 new writer phases and full105-writer schedule; BS,A,S | none for recorded phase strings |
| `:214` Intent::verify_previous | E/N: original scoped canonical policy/binding and ordered prefix; C,PX | creator PID, Rc shared origin, original native Previous receipt |
| `:252` Intent::transfer_ticket | N | live non-Clone lease/ticket; no JSON capability |
| `:259` Intent::verify_owner_origin | E/N: original member/epoch across snapshots; Q,PX | creator PID/Rc shared pointer |
| `:269` Intent::matches_job | E/N: original job PID/start/status in emitted op/resource; BS,S | matches_reaped native ticket |
| `:280` Intent::same_service | E/N: member/owner epoch consistency; Q,PX | creator/shared Rc and live server |
| `:291` Intent::verify | E/N: index/scope/request/group/pins/policy/query/namespace/request-time canonical equality, original epoch, no fence/pending in successful endpoint; I,Q,C,P,ARR | transient intent requires birth absent, live shared services and Request verification |
| `:328` Intent::prepare | E/N: completed original operation metadata; BOOL,BS | prepares exact FixedNetfilter native lease |
| `:345` Gate::verify | E/N: request/birth/index identity and original frame as completed evidence; I,Q,BS | transient result-absent state, creator/Rc/live admission at release |
| `:381` Native::bootstrap_history | E/N: same indexed completed history across observation/snapshots; PX,Q,R | live creator, journal read and ownership |
| `:395` Native::queue_bootstrap | E/N: serialized phase/window and prefix order, success idle state; P,PX,BS | queue slot availability, one continuation, before-digest/proposed journal, live clock/admission |
| `:458` Server::start_bootstrap | E/N: three ordered histories, six policies and original producer; C,Q,S | transient index equals history length and no Birth/result yet |
| `:500` Server::poll_bootstrap_intent | E/N: held intents bound to writers87/90 and correct query/policy phase; I,BS | live queued progress/lease creation and polling |
| `:525` Server::start_bootstrap_birth | E/N: op/history request and complete Birth equality; BS,Q,S | transient history birth absent, original child bind_service |
| `:539` Server::poll_bootstrap_birth | E/N: recorded durable birth released, original identity; BOOL,BS | native gate construction/receipt and durable writer execution |
| `:558` Server::start_bootstrap_source | E/N: original birth, own result and verified_at equality; Q,B,S | transient result absence and native source verification |
| `:577` Server::poll_bootstrap_source | E/N: birth/result/accepted_at exactly canonical; Q,B,S | live progress receipt/ack polling |
| `:617` Receipt::verify and `:621` verify_history | E/N: original request/birth/result/verified_at, prefix and idle success metadata; P,PX,Q,S | creator/shared origin, acknowledged source, live journal slot |
| `:657` Binding::verify_bootstrap_progress | E/N: original producer/scope/query/window, exact phases/writer receipts, completed history prefix; PX,BS,Q,R | Rc continuation identity, before/proposed full Record, transient per-stage reconstruction and OriginalWrite proof |
| `:761` Server::verify_bootstrap_chain | E/N: exactly3 acknowledged original operations, same queries and histories at each index; Q,BOOL,PX,S | native Rc query-origin identity/service custody |
| `:803` lab_bootstrap_intent_negatives | E/N: emitted query/policy negative counts6/12 and held/released intent metadata; I,SC | actual execution of four negative native progress attempts |
| `:836` lab_bootstrap_schema_checks | E/N: emitted39 count and canonical constraints; SC,C,Q,S | replaying actual Rust 3*(10+3) mutation oracle; no Cargo run |
| `attachment/operational/bootstrap.rs:46` Request::new | E/N: completed predecessor chain, scoped namespace, original source group/policy/pins/query/time; C,Q,B,ARR | exact20 native owner, shared source/query/binding and constructor digest recomputation |
| `:118` Request::require_query_origin | E/N: query/history/birth/facts equality; Q,R | Rc::ptr_eq original Accepted query |
| `:128` Request::check | E/N: query-kind index/scope and original identity; Q,S | creator, current owner admission and live query.require |
| `:143` Request::verify_retained | E/N: original group/producer/pins metadata; B,Q,ARR | Rc source binding, native source/pin custody |
| `:157` Request::verify | E/N: same metadata checks; B,Q,S | current double check before/after native verification |
| `:162` Request::verify_write | E/N: correct recorded writer phase/window and source/group; BS,Q | OriginalWrite capability and source/pin native write proofs |
| `:181` Request::verify_service | E/N: member/epoch/source/query chains; Q,PX,R | source/service/binding/query native custody |
| `:322` Native::advance | E/N: ordered query->intent->birth->result->ack->process projection; BS,Q,BOOL | actual state-machine execution, live process rechecks, current gates |
| `:504` PendingBootstrap::new and `:566` poll | E/N: complete acknowledged3 scopes, context and original-chain retention; SC,BOOL | construction/consumption of native owners and post-poll custody |
| `:636` lab_run success discriminator, `:1028-1069` preparation guards | E: fault0/schema1, writer105/prefix87, reaped/uncollected/reserved, pending/fenced false, creating/absent entry state, producer and retained16 fields unchanged; P,PX,SC | live secret-boundary pristine assertion is recorded only |
| `:1071-1123` lab_run held intents and writer phases | E: query87/policy90 indices/PID/start/status, held2/released/queued1, original18 phases/deadlines; I,BS,Q | actual successful durable writes |
| `:1125-1171` lab_run query/operation history equality | E: three original query and op bindings, zero status, EOF, request/Birth/query/result/ack equality; Q,B,S,R | actual native receipt origin |
| `:1174-1193` lab_run process verification | E: three finite timestamps after matching result-writer verification, before each original deadline; Q,S | observed live process state itself |
| `:1213-1255` lab_run charges/oracle/success witness | E: before charges3/3,39 negatives, intents6/12 held2/released, acknowledged/context/parent and false authority flags; SC,I,BOOL | actual runtime oracle and pristine parent memory |
| `:1257-1287` lab_run drop/retention | E: after charges3/3 and four true final retention assertions; SC,BOOL | Weak upgrades, native resource retention and current custody |
| `kernel/bootstrap.rs:85` Native::inventory and `:132` spawn | E/N: emitted registration counts25, borrowed2, original PID/start/birth and job-state; BS,BOOL,S | actual FD coverage, exact owner/gate/capacity capability and fork |
| `:249` Child::verify_gate and `:255` release | E/N: original birth and durable-release evidence; BS,BOOL | native Gate identity and one release channel |
| `:280` Child::poll | E/N: original job/status0, result namespace/group/policy/eight pins and ordered acceptance; Q,B,BS,ARR | same_constructor native proof, native policy content |
| `:368` Verified::require_acknowledged_history; `:389` verify_retained | E/N: acknowledgment, original completed result/time and retained-context flags; BOOL,Q | current original native owner/source |
| `:397` verify_completion_custody | E/N: zero status, completed result and original deadline/birth ordering; Q,BS,S | actual completion/FD/token custody |
| `:426` write_evidence; `:435` verify_write; `:442` verify; `:446` accept | E/N: observation/history birth/result/accepted_at and acknowledged=true; Q,B,BOOL,R | OriginalWrite/Receipt capability and live acceptance transition |

## Remaining limits and unenforced guards

The registry closes missing observation-to-history accounting for this emitted
successful witness. Its completeness test is finite and schema-scoped; it does
not prove every Rust guard or every coordinated fabrication impossible.
Specifically:

- Creator/current PID checks, Rc/Weak pointer provenance, unique/non-Clone
  capabilities, live service membership, full journal before/proposed records,
  transient intent/Birth/result absence, and actual durable-progress execution
  cannot be replayed from completed JSON. Their metadata projections are checked;
  their native clauses in the ledger above remain **NOT_RUN**.
- FDs, fstatfs, UID/GID, read-only access flags, registration capabilities,
  retained source/namespace custody and actual post-drop survival are absent.
  Serialized pin types/modes/identity and registration/retention assertions do
  not establish current native ownership. `attachment/operational/producer.rs:135-180`
  and `owned/preparation/host_link.rs:435-469` contain these native guards.
- The witness projects preparation instead of serializing its private complete
  History: allocation/configuration/input identities and complete PublicValidation
  report/selected/device_key fields are absent (`owned/preparation.rs:25-74`).
  All digest arrays are typed and their recorded references are bound, but complete
  independent regeneration of constructor/private-input digests is unenforced.
- Foreign-capacity original PID/start and WAN observation timestamps have no
  independent canonical counterpart in the witness. They are explicit canonical
  roots with identity/range/time/status guards, not hidden self-equalities.
  Eligible parent-job identity and WAN declaration/namespace are separately bound.
- Successful fault0 is the validator's profile. Failure/fault1-6 branches,
  alternative optional metadata values and future source/schema changes require
  their own validation/test work. A field/type sweep does not establish their
  operational semantics.
- No current guest/lab liveness, real disposable clients, traffic/leak/direct or
  multi-exit/fault runtime, ARM, performance, migration/reboot/rollback/soak,
  operational UP/placement/health READY/cleanup, requirement8 or release acceptance
  is supplied. Host unchanged=false plus single down veth added=true is expected;
  recorded host inventories preserve original routes/rules/addresses/prior links.

## Verification and revision-4 receipt

Final checks used the final validator/test sources. The earlier long run was
interrupted with SIGINT (exit130) after the last coverage hardening; its log is
retained as `full-suite.log` and is not completion evidence. The37-test run in `final-full-suite.log` passed in255.635s, then the final
registry audit found an additional initial-query discriminator gap. The final
38-test run in `final-full-suite-current.log` passed:38 tests in264.051s, exit0.

| Check | Final result | Evidence |
| --- | --- | --- |
| `python3 -B tools/rust-v2-lab/test-validate-run410-witness.py` | PASS, exit0; **38 tests in264.051s** | `final-full-suite-current.log` |
| All retained reviewer fixtures through actual `validate()` | All44 rejected (18+11+15); real and reserialized real PASS | same full suite |
| Full leaf mutation sweep |28,782 leaves; **102,334 mutations rejected** | same full suite |
| Rust/source width inventory |29 reachable serde structs,218 fields,28,782 leaf entries; no missing/default integer widths | `rust-source-fields.json`; same full suite |
| Registry completeness |67 entries;1,615 observation objects;0 uncovered; root/nested injections and removed individual deadline binding rejected | `binding-registry.json`, `binding-coverage.json`; same full suite |
| `python3 -B tools/rust-v2-lab/test-run410-fixes.py` | PASS, exit0;8 tests; pre-existing generated-template SyntaxWarnings retained | `test-run410-fixes.log` |
| `python3 -B tools/rust-v2-lab/test-run410-isolation.py` | PASS, exit0;21 tests | `test-run410-isolation.log` |
| `python3 -B tools/rust-v2-lab/test-run410-provenance.py` | PASS, exit0;21 tests | `test-run410-provenance.log` |
| `python3 -B tools/rust-v2-lab/test-run410-reservation.py` | PASS, exit0;12 checks; `real_lab_claim_created=false` | `test-run410-reservation.log` |
| `python3 -B -m py_compile` | PASS, exit0; validator, its test and all4 run410 suites; explicit output redirected outside repo | final command output; scratch `pycache/` |
| `git diff --check` | PASS, exit0 | final command output |
| Bounded IO/receipt audit |61 read opens; no validation writes;0600 exclusive scratch receipt; refused overwrite/symlink and -O/-OO | `io-final/io-review.log`, `io-final/io-results.json` |
| Frozen Rust source comparison | All24 files byte-identical, archive read without extraction | `frozen-source-comparison.json` |
| Preservation | All191 pre-existing lab-state/run410-evidence files retain bytes/size/mode; only r4 added in those trees | `preservation-final.json` |
| Cargo/sudo/network/VM, current custody, runtime/release acceptance | **NOT_RUN** | Outside offline scope |

Unless prefixed otherwise, evidence paths above are under
`/dev/shm/vprouter-witness-r4/`. RED evidence remains under
`/tmp/vprouter-witness-r4/` and the two additional RED logs in `/dev/shm`.

Created `target/run410-evidence/witness-validation-r4.json` with
`O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC`, mode0600, file fsync and directory
fsync. Size5903 bytes; SHA256
`a50fdf4f30f58d22ee08aab685791cd74707262a33ceefdb76d5e9cc6e430e8f`.
It reports revision4, PASS in all20 groups, and explicitly supersedes r1-r3.
Its parsed contents equal a fresh `validate()` for the identical relative
raw-record path. The three prior receipts retain their original hashes/mode0600.
The receipt's PASS/full_bootstrap_witness_validation is restricted to the stated
offline successful-record scope; it is not independent review acceptance or proof
of the native-only clauses tabulated above. Runtime/release remain false.

Historical/intermediate attempts are not final verification. Scratch files were first written in
`/tmp/vprouter-witness-r4`; `/tmp` later filled due to unrelated storage use.
No scratch/evidence from other work was deleted. Remaining test temporary files
and logs use `/dev/shm/vprouter-witness-r4` (`TMPDIR`), and explicit py_compile
output uses its own `PYTHONPYCACHEPREFIX` there. All Python executions use `-B`.

## Controller disposition after round 4 (2026-11-06 14:00): still PARTIAL

Round 4 (`task-8c-run410-witness-rereview3.md`): I9/I10/M2 and the initial-query
discriminator are fixed; all 70 retained reviewer mutations from rounds 1-3 fail through
the CLI; the real record passes 20/20 (receipt `witness-validation-r4.json`). The reviewer
reproduced 25 new false-PASS records in four new families — I11 actual network results lack
canonical plan bindings/native success guards, I12 WAN observation window treated as an
independent root, I13 host-addition intent digest may be all zero, I14 DATA and TRANSPORT can
claim different original journal directories — plus M3 (assembly capacity constant). These
stay OPEN. The validator is checkpointed as a strictly stronger PARTIAL validator; it is not
an acceptance. Next round must derive the binding/guard set mechanically from the Rust
sources instead of hand-enumerating observation shapes.
