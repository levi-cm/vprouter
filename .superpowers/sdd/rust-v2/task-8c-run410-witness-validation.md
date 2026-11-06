# Task 8c run-410 offline witness validation, revision 3

2026-11-06. Implementation delegate; `/DATA/AppData/vprouter-rust-v2`, branch
`rust/v2`, HEAD `5e989eeeea3092cc59675bd78ad37e06fce2d7c0`. No subagents.

The r1 and r2 full-validation claims are **SUPERSEDED** by the independent FAIL
reviews. Both receipt files remain byte-for-byte unchanged:

| Historical receipt | SHA256 | Disposition |
| --- | --- | --- |
| `target/run410-evidence/witness-validation.json` | `f75a0edf98406455c6c9dcd8cd59442b233f1125865f07e463595bc08b7ccbc0` | SUPERSEDED; preserve, no writes |
| `target/run410-evidence/witness-validation-r2.json` | `84a38df64f375e2e25043fd3c86b4471a82e44d06080a33e4dc803e915eadeda` | SUPERSEDED; preserve, no writes |

Current candidate receipt: `target/run410-evidence/witness-validation-r3.json`.
Final verification and receipt details appear at the end of this report.

This validates the recorded successful run410 witness and its retained
continuation history, offline. It does not rerun the consumed experiment.
`runtime_acceptance=false`, `release_ready=false`; Task 8c, requirement 8,
runtime and release acceptance remain open. Native objects absent from JSON
are explicitly inventoried below; their live guards cannot be reconstructed.

Raw record: `target/lab-state/actual-program-run-410.json`, SHA256
`bd3d1819f6387491c69388b371f9b05fa28d5e773658223f950ffd743413f0ff`.
Decoded stdout has 14 ordered rows; the witness is line13. Original evidence
is only read, never normalized or rewritten. Candidate source commit is
`da7556282d5fc828a9391a64ab47adab05a55510`.

## Fail-before / pass-after method

All 18 original reviewer fixture files under `/tmp/vprouter-witness-review/`
and all 11 new false-PASS fixtures under `/tmp/vprouter-witness-rereview/` are
loaded as their original bytes and passed directly through `validate()` by
`test_all_independent_reviewer_fixtures_through_validate`. Missing fixtures
fail the test; duplicate-key and NaN fixtures are never reserialized.
The pre-fix test exited1 with exactly 11 false-PASS assertion failures; all18
older mutations already failed and both real-record forms passed.

Additional RED runs exposed: three narrowed emitter types (admission polls,
host inventory polls, mount packets), signed foreign child PID width, Origin
launch digest, four host-inventory/owner-epoch guards, 150 success-boolean/type
failures in the first broad probe, and 35 accepted negative-value mutations
in the first completed leaf sweep. Early exploratory runs during edits are not
final verification. Every final suite below runs the fixed implementation.

The generic sweep visits **all 28,782 leaves**, including repeated retained
copies, never deduplicating by object shape. Every leaf receives a wrong-type
mutation; every integer additionally receives a negative and an overflow
mutation using an independently transcribed Rust-width map. Each object leaf
is tested with its serialized field absent; each populated array leaf is also
tested with null. Existing nulls are not incorrectly classified as invalid
`Option` values. Empty arrays count as leaves. Each mutation is serialized to
an isolated temporary raw record and actually calls `validate()`; there is no
mock schema check or cached verdict. Eight local Python workers run this test;
these are ordinary test processes, not delegated agents. The unchanged real
record and a reserialized copy must independently PASS.

## Review findings fixed

| Finding | Required contract | Enforcement | Regression |
| --- | --- | --- | --- |
| I1-I3 | Distinct six/eight pin results; final preparation/prefix; writer87/90 held intents | typed schemas, preparation_success, bootstrap_success | all18 original fixtures and existing focused tests |
| I4 | Birth PID is u32; no widened native/network fields | primitive ranges, complete core schema source inventory | overflow fixture, narrow-native tests, full leaf sweep |
| I5 | Bootstrap query initial is null | bootstrap_scopes and canonical_histories, all scopes/copies | original fixture and coordinated query-initial test |
| I6 | Canonical completed InitialQuarantine policy in the same scope | canonical_histories plus bootstrap_scopes | wrong-kind and wrong-scope coordinated fixtures |
| I7 | Binding publication, creation/data, query and DATA policy chain | canonical_histories plus own-result equality | four coordinated reviewer fixtures, canonical chain tests |
| I8 | Retained host fault0/oracle20/original intent writer75, operations, charges, continuation | retained_success, recorded_emitters, writer_histories | three reviewer fixtures; success guards, boolean and inventory probes |
| M1 | Valid handoff citation | `attachment/operational.rs:584-588` | source line checked |

`host_links_and_stable_routes_unchanged=false` is expected: the guest preserves
addresses/routes/rules/stable neighbors and prior links while adding exactly
one planned down veth. The controller reports unchanged=false and added=true.
The host operation's complete recorded inventory now also matches its baseline
plus exactly that result link. This remains recorded evidence, not a fresh
network observation.

## Rust domain rules

Ranges: u8=0..255; u16=0..65535; u32=0..4294967295;
u64/amd64 usize=0..18446744073709551615; i32=-2147483648..2147483647.
The primitive checker also implements i64=-9223372036854775808..9223372036854775807;
no reachable witness leaf in this source uses i64 (native wait statuses use i32).
Booleans never count as integers. All operation timestamps are finite f64 and
then checked against their original nonnegative two-second windows.
`[u8;32]` is exactly32 bytes; six/eight pins are distinct arrays of
`(u64,u64,u32)`; host addition is `Option<([u8;32],u32)>`; bootstrap query slots
are exactly `[Option<inspection::History>;3]`; query sequences are
`Option<[[u32;2];2]>`. IP/IPv4/socket-address text and `(IpAddr,u8)` tuples are
parsed, not accepted as arbitrary strings. The WAN address is `[u8;6]` (MAC).

The validator is specialized to this completed successful run. A Rust `Option`
may be narrowed to a populated value or null when this emitted branch requires
it. Historical continuations have false drop flags and null charges_after_drop;
only the final Bootstrap witness has true final drop-retention flags. Tables
below retain the underlying Rust `Option` type rather than silently relabeling
it. Some optional network metadata is fixed null/empty in this run's profile.

Validator references use `validator:<line>` for
`tools/rust-v2-lab/validate-run410-witness.py`. The source-driven inventory test
checks exact core field sets and primitive/array types against current Rust
source; the full leaf sweep tests the emitted copies through `validate()`.

## Serialized field inventory

Every field of every reachable serialized object shape is listed. `S` means
`test_every_real_witness_leaf_through_validate`; `R` additionally means
`test_rust_serialized_field_inventory_and_primitive_ranges`. Aggregates recurse
into the rows for their member shapes. Emitter-projection types use their
explicit JSON-builder origin; they are not fictitious Rust Deserialize structs.

| Field | Rust type / emitted success domain | Rust origin | Validator field line | Mutation test |
| --- | --- | --- | --- | --- |
| Address.address | `IpAddr` | `crates/vprouter-network/src/project.rs:53` | 466 | S, R |
| Address.broadcast | `Option<Ipv4Addr>` | `crates/vprouter-network/src/project.rs:49` | 467 | S, R |
| Address.flags | `u32` | `crates/vprouter-network/src/project.rs:51` | 468 | S, R |
| Address.index | `u32` | `crates/vprouter-network/src/project.rs:52` | 469 | S, R |
| Address.prefix | `u8` | `crates/vprouter-network/src/project.rs:54` | 470 | S, R |
| Address.route_priority | `Option<u32>` | `crates/vprouter-network/src/project.rs:50` | 471 | S, R |
| Address.scope | `u8` | `crates/vprouter-network/src/project.rs:55` | 472 | S, R |
| Assembly.assembly_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:350` | 583 | S |
| Assembly.charges_after | `emitted list(u64)` | `crates/vprouter-launch/src/attachment/assembly.rs:347` | 584 | S |
| Assembly.charges_after_drop | `emitted null` | `crates/vprouter-launch/src/attachment/assembly.rs:347` | 585 | S |
| Assembly.charges_before | `emitted list(u64)` | `crates/vprouter-launch/src/attachment/assembly.rs:347` | 586 | S |
| Assembly.continued_original_context | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:354` | 587 | S |
| Assembly.duplicate_reservation_counts | `emitted null` | `crates/vprouter-launch/src/attachment/assembly.rs:349` | 588 | S |
| Assembly.duplicate_reservation_refused | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:348` | 589 | S |
| Assembly.fault | `u8` | `crates/vprouter-launch/src/attachment/assembly.rs:346` | 590 | S |
| Assembly.fence_blocked_next_transfer | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:349` | 591 | S |
| Assembly.fence_counts | `emitted null` | `crates/vprouter-launch/src/attachment/assembly.rs:350` | 592 | S |
| Assembly.foreign_eligibility | `emitted ForeignEligibility` | `crates/vprouter-launch/src/attachment/assembly.rs:346` | 593 | S |
| Assembly.global_child_capacity_limit | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/assembly.rs:354` | 594 | S |
| Assembly.handoff_complete | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:348` | 595 | S |
| Assembly.lower_repeat_retirement_refused | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:349` | 596 | S |
| Assembly.movement_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:351` | 597 | S |
| Assembly.multi_exit_runtime_proven | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:354` | 598 | S |
| Assembly.operational_reuse_authorized | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:353` | 599 | S |
| Assembly.original_provision_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:352` | 600 | S |
| Assembly.parent_pristine | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:352` | 601 | S |
| Assembly.preparation | `emitted Preparation` | `crates/vprouter-launch/src/attachment/assembly.rs:346` | 602 | S |
| Assembly.producer_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:351` | 603 | S |
| Assembly.producer_operational_publication | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:353` | 604 | S |
| Assembly.quarantine | `emitted Quarantine` | `crates/vprouter-launch/src/attachment/assembly.rs:346` | 605 | S |
| Assembly.quarantine_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:351` | 606 | S |
| Assembly.repeat_retirement_refused | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:349` | 607 | S |
| Assembly.requirement8_complete | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:354` | 608 | S |
| Assembly.reservation | `emitted AssemblyReservation` | `crates/vprouter-launch/src/attachment/assembly.rs:347` | 609 | S |
| Assembly.resource_cleanup_authorized | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:353` | 610 | S |
| Assembly.resources | `emitted list(Resource)` | `crates/vprouter-launch/src/attachment/assembly.rs:347` | 611 | S |
| Assembly.retired_original_jobs | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/assembly.rs:348` | 612 | S |
| Assembly.schema | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/assembly.rs:346` | 613 | S |
| Assembly.up_authorized | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:353` | 614 | S |
| Assembly.whole_chain_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/assembly.rs:350` | 615 | S |
| AssemblyReservation.complete | `bool` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:91` | 885 | S |
| AssemblyReservation.global_assemblies_reserved | `u64/usize (amd64)` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:92` | 886 | S |
| AssemblyReservation.global_assembly_limit | `u64/usize (amd64)` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:92` | 887 | S |
| AssemblyReservation.global_transferred_ticket_limit | `u64/usize (amd64)` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:92` | 888 | S |
| AssemblyReservation.member | `String` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:91` | 889 | S |
| AssemblyReservation.member_transfer_pending | `bool` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:93` | 890 | S |
| AssemblyReservation.original_jobs | `u64/usize (amd64)` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:91` | 891 | S |
| AssemblyReservation.owner_epoch | `emitted OwnerEpoch` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:91` | 892 | S |
| Attachment.birth | `Option<ValidationBirth>` | `crates/vprouter-launch/src/owned/preparation/mount.rs:21` | 142 | S, R |
| Attachment.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation/mount.rs:20` | 143 | S, R |
| Attachment.directory | `Identity` | `crates/vprouter-launch/src/owned/preparation/mount.rs:16` | 144 | S, R |
| Attachment.mounted_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/mount.rs:23` | 145 | S, R |
| Attachment.name | `String` | `crates/vprouter-launch/src/owned/preparation/mount.rs:17` | 146 | S, R |
| Attachment.origin | `Origin` | `crates/vprouter-launch/src/owned/preparation/mount.rs:15` | 147 | S, R |
| Attachment.placeholder | `Option<Placeholder>` | `crates/vprouter-launch/src/owned/preparation/mount.rs:22` | 148 | S, R |
| Attachment.published_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/mount.rs:25` | 149 | S, R |
| Attachment.query | `Option<inspection::History>` | `crates/vprouter-launch/src/owned/preparation/mount.rs:24` | 150 | S, R |
| Attachment.request | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/mount.rs:14` | 151 | S, R |
| Attachment.requested_at | `f64` | `crates/vprouter-launch/src/owned/preparation/mount.rs:19` | 152 | S, R |
| Attachment.source | `Identity` | `crates/vprouter-launch/src/owned/preparation/mount.rs:18` | 153 | S, R |
| AttachmentOrigin.container | `String` | `crates/vprouter-launch/src/attachment.rs:282` | 166 | S |
| AttachmentOrigin.kind | `emitted origin_kind` | `crates/vprouter-launch/src/attachment.rs:340` | 167 | S |
| AttachmentOrigin.launch | `String` | `crates/vprouter-launch/src/attachment.rs:282` | 168 | S |
| AttachmentOrigin.network | `emitted Identity` | `crates/vprouter-launch/src/attachment.rs:282` | 169 | S |
| AttachmentOrigin.process_start | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment.rs:282` | 170 | S |
| AttachmentOrigin.public_result | `[u8;32]` | `crates/vprouter-launch/src/attachment.rs:282` | 171 | S |
| AttachmentOrigin.staging | `String` | `crates/vprouter-launch/src/attachment.rs:336` | 172 | S |
| AttachmentWitness.base_published | `bool` | `crates/vprouter-launch/src/attachment/mount.rs:958` | 757 | S |
| AttachmentWitness.fault | `u8` | `crates/vprouter-launch/src/attachment/mount.rs:950` | 758 | S |
| AttachmentWitness.first_query | `emitted Query` | `crates/vprouter-launch/src/attachment/mount.rs:952` | 759 | S |
| AttachmentWitness.held_real_writer | `bool` | `crates/vprouter-launch/src/attachment/mount.rs:954` | 760 | S |
| AttachmentWitness.inspection_deadline | `f64` | `crates/vprouter-launch/src/attachment/mount.rs:951` | 761 | S |
| AttachmentWitness.inspection_requested_at | `f64` | `crates/vprouter-launch/src/attachment/mount.rs:951` | 762 | S |
| AttachmentWitness.inspection_verified_at | `f64` | `crates/vprouter-launch/src/attachment/mount.rs:952` | 763 | S |
| AttachmentWitness.mount | `emitted MountWitness` | `crates/vprouter-launch/src/attachment/mount.rs:953` | 764 | S |
| AttachmentWitness.namespace_cleanup_or_operational_reuse_authorized | `bool` | `crates/vprouter-launch/src/attachment/mount.rs:959` | 765 | S |
| AttachmentWitness.normal_ack_ready_preserved | `bool` | `crates/vprouter-launch/src/attachment/mount.rs:955` | 766 | S |
| AttachmentWitness.normal_ack_writer | `emitted null` | `crates/vprouter-launch/src/attachment/mount.rs:957` | 767 | S |
| AttachmentWitness.original_mount_retained | `bool` | `crates/vprouter-launch/src/attachment/mount.rs:958` | 768 | S |
| AttachmentWitness.parent_pristine | `bool` | `crates/vprouter-launch/src/attachment/mount.rs:953` | 769 | S |
| AttachmentWitness.postmount_query | `emitted Query` | `crates/vprouter-launch/src/attachment/mount.rs:953` | 770 | S |
| AttachmentWitness.preparation | `emitted Preparation` | `crates/vprouter-launch/src/attachment/mount.rs:950` | 771 | S |
| AttachmentWitness.requirement8_complete | `bool` | `crates/vprouter-launch/src/attachment/mount.rs:959` | 772 | S |
| AttachmentWitness.same_service_retained | `bool` | `crates/vprouter-launch/src/attachment/mount.rs:953` | 773 | S |
| AttachmentWitness.schema | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/mount.rs:950` | 774 | S |
| AttachmentWitness.second_query | `emitted Query` | `crates/vprouter-launch/src/attachment/mount.rs:952` | 775 | S |
| AttachmentWitness.tested_non_target_phase | `emitted null` | `crates/vprouter-launch/src/attachment/mount.rs:956` | 776 | S |
| AttachmentWitness.validator | `emitted ValidatorWitness` | `crates/vprouter-launch/src/attachment/mount.rs:950` | 777 | S |
| AttachmentWitness.whole_failed_driver_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/mount.rs:954` | 778 | S |
| Birth.born_at | `f64` | `crates/vprouter-launch/src/owned/preparation.rs:81` | 156 | S, R |
| Birth.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation.rs:82` | 157 | S, R |
| Birth.pid | `u32` | `crates/vprouter-launch/src/owned/preparation.rs:79` | 158 | S, R |
| Birth.start | `u64` | `crates/vprouter-launch/src/owned/preparation.rs:80` | 159 | S, R |
| BootstrapHistory.birth | `Option<ValidationBirth>` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:28` | 958 | S, R |
| BootstrapHistory.creation | `producer_creation::History` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:21` | 959 | S, R |
| BootstrapHistory.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:25` | 960 | S, R |
| BootstrapHistory.group | `Identity` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:22` | 961 | S, R |
| BootstrapHistory.namespace | `Identity` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:20` | 962 | S, R |
| BootstrapHistory.pins | `[(u64, u64, u32); 8]` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:27` | 963 | S, R |
| BootstrapHistory.policy | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:26` | 964 | S, R |
| BootstrapHistory.query | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:23` | 965 | S, R |
| BootstrapHistory.request | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:18` | 966 | S, R |
| BootstrapHistory.requested_at | `f64` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:24` | 967 | S, R |
| BootstrapHistory.result | `Option<PublicResult>` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:29` | 968 | S, R |
| BootstrapHistory.scope | `Scope` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:19` | 969 | S, R |
| BootstrapHistory.verified_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:30` | 970 | S, R |
| BootstrapOperation.accepted_at | `f64` | `crates/vprouter-launch/src/kernel/bootstrap.rs:563` | 926 | S |
| BootstrapOperation.acknowledged | `bool` | `crates/vprouter-launch/src/kernel/bootstrap.rs:563` | 927 | S |
| BootstrapOperation.actual_wait_status | `i32` | `crates/vprouter-launch/src/kernel/bootstrap.rs:560` | 928 | S |
| BootstrapOperation.birth | `emitted Birth` | `crates/vprouter-launch/src/kernel/bootstrap.rs:560` | 929 | S |
| BootstrapOperation.bootstrap_installation_observed | `bool` | `crates/vprouter-launch/src/kernel/bootstrap.rs:564` | 930 | S |
| BootstrapOperation.borrowed_registration_count | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/bootstrap.rs:562` | 931 | S |
| BootstrapOperation.complete_native_registration | `bool` | `crates/vprouter-launch/src/kernel/bootstrap.rs:562` | 932 | S |
| BootstrapOperation.context_retained | `bool` | `crates/vprouter-launch/src/kernel/bootstrap.rs:564` | 933 | S |
| BootstrapOperation.deadline | `f64` | `crates/vprouter-launch/src/kernel/bootstrap.rs:558` | 934 | S |
| BootstrapOperation.durable_birth_released | `bool` | `crates/vprouter-launch/src/kernel/bootstrap.rs:563` | 935 | S |
| BootstrapOperation.eof | `bool` | `crates/vprouter-launch/src/kernel/bootstrap.rs:564` | 936 | S |
| BootstrapOperation.group | `emitted Identity` | `crates/vprouter-launch/src/kernel/bootstrap.rs:559` | 937 | S |
| BootstrapOperation.name | `String` | `crates/vprouter-launch/src/kernel/bootstrap.rs:559` | 938 | S |
| BootstrapOperation.namespace | `emitted Identity` | `crates/vprouter-launch/src/kernel/bootstrap.rs:559` | 939 | S |
| BootstrapOperation.native_born | `bool` | `crates/vprouter-launch/src/kernel/bootstrap.rs:560` | 940 | S |
| BootstrapOperation.native_job_state | `emitted job_state` | `crates/vprouter-launch/src/kernel/bootstrap.rs:561` | 941 | S |
| BootstrapOperation.original_pid | `u32` | `crates/vprouter-launch/src/kernel/bootstrap.rs:560` | 942 | S |
| BootstrapOperation.original_registration_slots_verified | `bool` | `crates/vprouter-launch/src/kernel/bootstrap.rs:562` | 943 | S |
| BootstrapOperation.original_start | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/bootstrap.rs:560` | 944 | S |
| BootstrapOperation.parent | `emitted Identity` | `crates/vprouter-launch/src/kernel/bootstrap.rs:559` | 945 | S |
| BootstrapOperation.pins | `[(u64,u64,u32);8]` | `crates/vprouter-launch/src/kernel/bootstrap.rs:559` | 946 | S |
| BootstrapOperation.placement_authorized | `bool` | `crates/vprouter-launch/src/kernel/bootstrap.rs:564` | 947 | S |
| BootstrapOperation.policy | `[u8;32]` | `crates/vprouter-launch/src/kernel/bootstrap.rs:559` | 948 | S |
| BootstrapOperation.query | `[u8;32]` | `crates/vprouter-launch/src/kernel/bootstrap.rs:558` | 949 | S |
| BootstrapOperation.registered_native_slots | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/bootstrap.rs:562` | 950 | S |
| BootstrapOperation.request | `[u8;32]` | `crates/vprouter-launch/src/kernel/bootstrap.rs:558` | 951 | S |
| BootstrapOperation.requested_at | `f64` | `crates/vprouter-launch/src/kernel/bootstrap.rs:558` | 952 | S |
| BootstrapOperation.result | `emitted BootstrapResult` | `crates/vprouter-launch/src/kernel/bootstrap.rs:563` | 953 | S |
| BootstrapOperation.scope | `emitted scope` | `crates/vprouter-launch/src/kernel/bootstrap.rs:559` | 954 | S |
| BootstrapOperation.up_authorized | `bool` | `crates/vprouter-launch/src/kernel/bootstrap.rs:564` | 955 | S |
| BootstrapResult.group | `Identity` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:10` | 330 | S, R |
| BootstrapResult.namespace | `Identity` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:9` | 331 | S, R |
| BootstrapResult.observed_at | `f64` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:13` | 332 | S, R |
| BootstrapResult.pins | `[(u64, u64, u32); 8]` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:12` | 333 | S, R |
| BootstrapResult.policy | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:11` | 334 | S, R |
| BootstrapWitness.bootstrap_all_scopes_acknowledged | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1253` | 49 | S |
| BootstrapWitness.bootstrap_context_created | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1253` | 50 | S |
| BootstrapWitness.bootstrap_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1252` | 51 | S |
| BootstrapWitness.canonical_negative_checks | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1248` | 52 | S |
| BootstrapWitness.charges_after_drop | `emitted list(u64)` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1250` | 53 | S |
| BootstrapWitness.charges_before_drop | `emitted list(u64)` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1250` | 54 | S |
| BootstrapWitness.failed_constructor | `emitted null` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1249` | 55 | S |
| BootstrapWitness.failure_retry | `emitted null` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1249` | 56 | S |
| BootstrapWitness.fault | `u8` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1248` | 57 | S |
| BootstrapWitness.final_process_verified_at | `f64` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1250` | 58 | S |
| BootstrapWitness.handoff | `emitted Handoff` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1248` | 59 | S |
| BootstrapWitness.health_ready_authorized | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1254` | 60 | S |
| BootstrapWitness.host_addition | `emitted HostAddition` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1248` | 61 | S |
| BootstrapWitness.multi_exit_runtime_proven | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1255` | 62 | S |
| BootstrapWitness.operational_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1252` | 63 | S |
| BootstrapWitness.operations | `emitted list(BootstrapOperation)` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1249` | 64 | S |
| BootstrapWitness.original_nine_contexts_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1251` | 65 | S |
| BootstrapWitness.own_intent_polling | `emitted IntentPolling` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1248` | 66 | S |
| BootstrapWitness.own_query_intent_polling | `emitted IntentPolling` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1248` | 67 | S |
| BootstrapWitness.parent_pristine | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1254` | 68 | S |
| BootstrapWitness.placement_authorized | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1254` | 69 | S |
| BootstrapWitness.preparation | `emitted Preparation` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1248` | 70 | S |
| BootstrapWitness.queries | `emitted list(Query)` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1249` | 71 | S |
| BootstrapWitness.requirement8_complete | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1255` | 72 | S |
| BootstrapWitness.resource_cleanup_authorized | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1255` | 73 | S |
| BootstrapWitness.result_writer_held | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1251` | 74 | S |
| BootstrapWitness.retained_result_writer | `emitted null` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1249` | 75 | S |
| BootstrapWitness.schema | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1248` | 76 | S |
| BootstrapWitness.scope_process_verified_at | `emitted list(f64)` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1250` | 77 | S |
| BootstrapWitness.up_authorized | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1254` | 78 | S |
| BootstrapWitness.whole_chain_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1251` | 79 | S |
| EntryProducer.binding | `[u8;32]` | `crates/vprouter-launch/src/owned.rs:520` | 201 | S |
| EntryProducer.group | `emitted Identity` | `crates/vprouter-launch/src/owned.rs:467` | 202 | S |
| EntryProducer.parent | `emitted Identity` | `crates/vprouter-launch/src/owned.rs:620` | 203 | S |
| ForeignEligibility.actual_wait_status | `i32` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:219` | 618 | S |
| ForeignEligibility.canonical_operation | `bool` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:228` | 619 | S |
| ForeignEligibility.deadline | `f64` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:219` | 620 | S |
| ForeignEligibility.eligible_foreign_refused | `bool` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:226` | 621 | S |
| ForeignEligibility.eligible_original_pid | `u32` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:225` | 622 | S |
| ForeignEligibility.eligible_original_start | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:225` | 623 | S |
| ForeignEligibility.eof | `bool` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:219` | 624 | S |
| ForeignEligibility.failed_actual_wait_status | `emitted null` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:222` | 625 | S |
| ForeignEligibility.failed_charges_unchanged | `emitted null` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:224` | 626 | S |
| ForeignEligibility.failed_exit_code | `emitted null` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:223` | 627 | S |
| ForeignEligibility.failed_original_pid | `emitted null` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:220` | 628 | S |
| ForeignEligibility.failed_original_start | `emitted null` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:221` | 629 | S |
| ForeignEligibility.original_pid | `i32` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:219` | 630 | S |
| ForeignEligibility.original_start | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:219` | 631 | S |
| ForeignEligibility.parent_counts_after | `emitted list(u64)` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:227` | 632 | S |
| ForeignEligibility.parent_counts_before | `emitted list(u64)` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:227` | 633 | S |
| ForeignEligibility.parent_still_eligible | `bool` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:226` | 634 | S |
| ForeignEligibility.requested_at | `f64` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:219` | 635 | S |
| ForeignEligibility.schema | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:219` | 636 | S |
| ForeignEligibility.successful_capacity_transfer_proven | `bool` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:228` | 637 | S |
| ForeignEligibility.verified_at | `f64` | `crates/vprouter-launch/src/kernel/capacity_lab.rs:219` | 638 | S |
| FreshTransport.birth | `Option<ValidationBirth>` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:15` | 206 | S, R |
| FreshTransport.data | `Identity` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:12` | 207 | S, R |
| FreshTransport.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:14` | 208 | S, R |
| FreshTransport.directory | `Identity` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:9` | 209 | S, R |
| FreshTransport.host | `Identity` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:11` | 210 | S, R |
| FreshTransport.mount | `Option<fresh_mount::History>` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:19` | 211 | S, R |
| FreshTransport.name | `String` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:10` | 212 | S, R |
| FreshTransport.request | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:8` | 213 | S, R |
| FreshTransport.requested_at | `f64` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:13` | 214 | S, R |
| FreshTransport.source | `Option<Identity>` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:16` | 215 | S, R |
| FreshTransport.verified_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:17` | 216 | S, R |
| Handoff.charges_after | `emitted list(u64)` | `crates/vprouter-launch/src/attachment/operational.rs:585` | 82 | S |
| Handoff.charges_before | `emitted list(u64)` | `crates/vprouter-launch/src/attachment/operational.rs:585` | 83 | S |
| Handoff.complete | `bool` | `crates/vprouter-launch/src/attachment/operational.rs:587` | 84 | S |
| Handoff.complete_original_job_set | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/operational.rs:587` | 85 | S |
| Handoff.duplicate_reservation | `emitted null` | `crates/vprouter-launch/src/attachment/operational.rs:586` | 86 | S |
| Handoff.fence_counts | `emitted null` | `crates/vprouter-launch/src/attachment/operational.rs:586` | 87 | S |
| Handoff.global_child_capacity_limit | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/operational.rs:588` | 88 | S |
| Handoff.historical_original_jobs | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/operational.rs:587` | 89 | S |
| Handoff.preparation | `emitted Preparation` | `crates/vprouter-launch/src/attachment/operational.rs:586` | 90 | S |
| Handoff.repeat_retirement_refusals | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/operational.rs:585` | 91 | S |
| Handoff.reservation | `emitted OperationalReservation` | `crates/vprouter-launch/src/attachment/operational.rs:584` | 92 | S |
| Handoff.resources | `emitted list(Resource)` | `crates/vprouter-launch/src/attachment/operational.rs:584` | 93 | S |
| Handoff.resources_collected | `bool` | `crates/vprouter-launch/src/attachment/operational.rs:588` | 94 | S |
| Handoff.retired_suffix_jobs | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/operational.rs:585` | 95 | S |
| HostAddition.admission | `emitted HostAdmission` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1136` | 411 | S |
| HostAddition.baseline_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1143` | 412 | S |
| HostAddition.canonical_host_addition_acknowledged | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1141` | 413 | S |
| HostAddition.canonical_negative_checks | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1137` | 414 | S |
| HostAddition.charges_after_drop | `emitted null` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1148` | 415 | S |
| HostAddition.charges_before | `emitted list(u64)` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1139` | 416 | S |
| HostAddition.charges_before_drop | `emitted list(u64)` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1139` | 417 | S |
| HostAddition.continued_original_context | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1147` | 418 | S |
| HostAddition.failed_constructor | `emitted null` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1137` | 419 | S |
| HostAddition.failure_retry | `emitted null` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1139` | 420 | S |
| HostAddition.fault | `u8` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1136` | 421 | S |
| HostAddition.generation_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1144` | 422 | S |
| HostAddition.health_ready_authorized | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1145` | 423 | S |
| HostAddition.host_addresses_routes_rules_preserved | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1142` | 424 | S |
| HostAddition.host_link_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1144` | 425 | S |
| HostAddition.host_neighbor_mutation_authorized | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1142` | 426 | S |
| HostAddition.isolated_pair_creation_observed | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1140` | 427 | S |
| HostAddition.multi_exit_runtime_proven | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1146` | 428 | S |
| HostAddition.operations | `emitted list(HostOperation)` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1137` | 429 | S |
| HostAddition.original_six_contexts_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1143` | 430 | S |
| HostAddition.own_intent_polling | `emitted HostIntentPolling` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1138` | 431 | S |
| HostAddition.parent_pristine | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1145` | 432 | S |
| HostAddition.placement_authorized | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1145` | 433 | S |
| HostAddition.planned_host_link_index | `u32` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1137` | 434 | S |
| HostAddition.preparation | `emitted Preparation` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1136` | 435 | S |
| HostAddition.producer_binding | `emitted ProducerBinding` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1136` | 436 | S |
| HostAddition.requirement8_complete | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1146` | 437 | S |
| HostAddition.resource_cleanup_authorized | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1146` | 438 | S |
| HostAddition.result_writer_held | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1140` | 439 | S |
| HostAddition.retained_result_writer | `emitted null` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1139` | 440 | S |
| HostAddition.schema | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1136` | 441 | S |
| HostAddition.single_down_host_addition_observed | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1140` | 442 | S |
| HostAddition.unacknowledged_host_addition_retained | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1141` | 443 | S |
| HostAddition.up_authorized | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1145` | 444 | S |
| HostAddition.whole_chain_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1143` | 445 | S |
| HostAdmission.accepted_at | `f64` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:740` | 448 | S |
| HostAdmission.deadline | `f64` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:740` | 449 | S |
| HostAdmission.declaration | `[u8;32]` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:739` | 450 | S |
| HostAdmission.declared_baseline | `emitted HostBaseline` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:741` | 451 | S |
| HostAdmission.namespace | `emitted Identity` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:739` | 452 | S |
| HostAdmission.polls | `u32` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:741` | 453 | S |
| HostAdmission.requested_at | `f64` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:740` | 454 | S |
| HostAdmission.same_generation_owner_retained | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:741` | 455 | S |
| HostAdmission.two_original_reads_verified | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:741` | 456 | S |
| HostBaseline.addresses | `emitted list(Address)` | `crates/vprouter-network/src/host_observation.rs:16` | 459 | S |
| HostBaseline.links | `emitted list(Link)` | `crates/vprouter-network/src/host_observation.rs:14` | 460 | S |
| HostBaseline.namespace | `(u64,u64)` | `crates/vprouter-network/src/host_observation.rs:12` | 461 | S |
| HostBaseline.routes | `emitted list(Route)` | `crates/vprouter-network/src/host_observation.rs:18` | 462 | S |
| HostBaseline.rules | `emitted list(Rule)` | `crates/vprouter-network/src/host_observation.rs:20` | 463 | S |
| HostIntentPolling.held_pending_polls | `u32` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1138` | 1272 | S |
| HostIntentPolling.index | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1138` | 1272 | S |
| HostIntentPolling.negative_checks | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1138` | 1272 | S |
| HostIntentPolling.pid | `u32` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1138` | 1272 | S |
| HostIntentPolling.queued_polls | `u32` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1138` | 1272 | S |
| HostIntentPolling.released | `bool` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1138` | 1272 | S |
| HostIntentPolling.start | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1138` | 1272 | S |
| HostLinkHistory.addition | `Option<([u8; 32], u32)>` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:17` | 231 | S, R |
| HostLinkHistory.admission | `[f64; 3]` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:14` | 232 | S, R |
| HostLinkHistory.birth | `Option<ValidationBirth>` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:18` | 233 | S, R |
| HostLinkHistory.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:16` | 234 | S, R |
| HostLinkHistory.declaration | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:13` | 235 | S, R |
| HostLinkHistory.host | `Identity` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:12` | 236 | S, R |
| HostLinkHistory.kind | `Kind` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:9` | 237 | S, R |
| HostLinkHistory.namespace | `Identity` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:11` | 238 | S, R |
| HostLinkHistory.request | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:10` | 239 | S, R |
| HostLinkHistory.requested_at | `f64` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:15` | 240 | S, R |
| HostLinkHistory.result | `Option<PublicResult>` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:19` | 241 | S, R |
| HostLinkHistory.verified_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:20` | 242 | S, R |
| HostLinkResult.host | `Option<vprouter_network::Link>` | `crates/vprouter-launch/src/kernel/host_link.rs:24` | 245 | S |
| HostLinkResult.namespace | `Identity` | `crates/vprouter-launch/src/kernel/host_link.rs:23` | 246 | S |
| HostLinkResult.peer | `Option<vprouter_network::Link>` | `crates/vprouter-launch/src/kernel/host_link.rs:25` | 247 | S |
| HostOperation.accepted_at | `f64` | `crates/vprouter-launch/src/kernel/host_link.rs:822` | 504 | S |
| HostOperation.acknowledged | `bool` | `crates/vprouter-launch/src/kernel/host_link.rs:822` | 505 | S |
| HostOperation.actual_wait_status | `i32` | `crates/vprouter-launch/src/kernel/host_link.rs:819` | 506 | S |
| HostOperation.addition | `emitted addition&#124;null` | `crates/vprouter-launch/src/kernel/host_link.rs:817` | 507 | S |
| HostOperation.admission | `emitted window3` | `crates/vprouter-launch/src/kernel/host_link.rs:817` | 508 | S |
| HostOperation.birth | `emitted Birth` | `crates/vprouter-launch/src/kernel/host_link.rs:819` | 509 | S |
| HostOperation.borrowed_registration_count | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/host_link.rs:820` | 510 | S |
| HostOperation.complete_native_registration | `bool` | `crates/vprouter-launch/src/kernel/host_link.rs:821` | 511 | S |
| HostOperation.context_retained | `bool` | `crates/vprouter-launch/src/kernel/host_link.rs:822` | 512 | S |
| HostOperation.deadline | `f64` | `crates/vprouter-launch/src/kernel/host_link.rs:818` | 513 | S |
| HostOperation.declaration | `[u8;32]` | `crates/vprouter-launch/src/kernel/host_link.rs:817` | 514 | S |
| HostOperation.durable_birth_released | `bool` | `crates/vprouter-launch/src/kernel/host_link.rs:821` | 515 | S |
| HostOperation.eof | `bool` | `crates/vprouter-launch/src/kernel/host_link.rs:822` | 516 | S |
| HostOperation.host | `emitted Identity` | `crates/vprouter-launch/src/kernel/host_link.rs:816` | 517 | S |
| HostOperation.host_observation | `emitted HostBaseline&#124;null` | `crates/vprouter-launch/src/kernel/host_link.rs:825` | 518 | S |
| HostOperation.kind | `emitted host_kind` | `crates/vprouter-launch/src/kernel/host_link.rs:816` | 519 | S |
| HostOperation.namespace | `emitted Identity` | `crates/vprouter-launch/src/kernel/host_link.rs:816` | 520 | S |
| HostOperation.native_born | `bool` | `crates/vprouter-launch/src/kernel/host_link.rs:819` | 521 | S |
| HostOperation.native_job_state | `emitted job_state` | `crates/vprouter-launch/src/kernel/host_link.rs:819` | 522 | S |
| HostOperation.original_pid | `u32` | `crates/vprouter-launch/src/kernel/host_link.rs:818` | 523 | S |
| HostOperation.original_registration_slots_verified | `bool` | `crates/vprouter-launch/src/kernel/host_link.rs:820` | 524 | S |
| HostOperation.original_start | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/host_link.rs:818` | 525 | S |
| HostOperation.placement_authorized | `bool` | `crates/vprouter-launch/src/kernel/host_link.rs:825` | 526 | S |
| HostOperation.postcompletion_inventory_polls | `u32` | `crates/vprouter-launch/src/kernel/host_link.rs:823` | 527 | S |
| HostOperation.postcompletion_inventory_preserved | `emitted bool&#124;null` | `crates/vprouter-launch/src/kernel/host_link.rs:824` | 528 | S |
| HostOperation.registered_native_slots | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/host_link.rs:820` | 529 | S |
| HostOperation.request | `[u8;32]` | `crates/vprouter-launch/src/kernel/host_link.rs:816` | 530 | S |
| HostOperation.requested_at | `f64` | `crates/vprouter-launch/src/kernel/host_link.rs:818` | 531 | S |
| HostOperation.result | `emitted HostLinkResult` | `crates/vprouter-launch/src/kernel/host_link.rs:822` | 532 | S |
| HostOperation.up_authorized | `bool` | `crates/vprouter-launch/src/kernel/host_link.rs:825` | 533 | S |
| Identity.dev | `u64` | `crates/vprouter-launch/src/owned.rs:23` | 162 | S, R |
| Identity.ino | `u64` | `crates/vprouter-launch/src/owned.rs:24` | 163 | S, R |
| InspectionHistory.birth | `Option<ValidationBirth>` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:14` | 179 | S, R |
| InspectionHistory.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:13` | 180 | S, R |
| InspectionHistory.facts | `Option<QueryFacts>` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:15` | 181 | S, R |
| InspectionHistory.initial | `Option<Initial>` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:10` | 182 | S, R |
| InspectionHistory.kind | `QueryKind` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:9` | 183 | S, R |
| InspectionHistory.request | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:11` | 184 | S, R |
| InspectionHistory.requested_at | `f64` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:12` | 185 | S, R |
| InspectionHistory.verified_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:16` | 186 | S, R |
| InspectionInitial.birth | `ValidationBirth` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:22` | 269 | S, R |
| InspectionInitial.facts | `QueryFacts` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:23` | 270 | S, R |
| InspectionInitial.request | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:21` | 271 | S, R |
| InspectionInitial.verified_at | `f64` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:24` | 272 | S, R |
| IntentPolling.held_pending_polls | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:785` | 536 | S |
| IntentPolling.index | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:785` | 537 | S |
| IntentPolling.negative_checks | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:785` | 538 | S |
| IntentPolling.pid | `u32` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:785` | 539 | S |
| IntentPolling.queued_polls | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:785` | 540 | S |
| IntentPolling.released | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:785` | 541 | S |
| IntentPolling.start | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:785` | 542 | S |
| Link.alias | `String` | `crates/vprouter-network/src/project.rs:31` | 250 | S, R |
| Link.all_multicast | `u32` | `crates/vprouter-network/src/project.rs:37` | 251 | S, R |
| Link.alternate_names | `Vec<String>` | `crates/vprouter-network/src/project.rs:38` | 252 | S, R |
| Link.controller | `u32` | `crates/vprouter-network/src/project.rs:34` | 253 | S, R |
| Link.hardware_type | `u16` | `crates/vprouter-network/src/project.rs:33` | 254 | S, R |
| Link.headroom | `Option<u16>` | `crates/vprouter-network/src/project.rs:43` | 255 | S, R |
| Link.index | `u32` | `crates/vprouter-network/src/project.rs:27` | 256 | S, R |
| Link.kind | `String` | `crates/vprouter-network/src/project.rs:28` | 257 | S, R |
| Link.max_pacing_offload_horizon | `Option<u32>` | `crates/vprouter-network/src/project.rs:42` | 258 | S, R |
| Link.mtu | `u32` | `crates/vprouter-network/src/project.rs:30` | 259 | S, R |
| Link.name | `String` | `crates/vprouter-network/src/project.rs:26` | 260 | S, R |
| Link.peer_index | `Option<u32>` | `crates/vprouter-network/src/project.rs:32` | 261 | S, R |
| Link.port_kind | `String` | `crates/vprouter-network/src/project.rs:35` | 262 | S, R |
| Link.promiscuity | `u32` | `crates/vprouter-network/src/project.rs:36` | 263 | S, R |
| Link.tailroom | `Option<u16>` | `crates/vprouter-network/src/project.rs:44` | 264 | S, R |
| Link.tun_info | `Vec<(u16, Vec<u8>)>` | `crates/vprouter-network/src/project.rs:40` | 265 | S, R |
| Link.up | `bool` | `crates/vprouter-network/src/project.rs:29` | 266 | S, R |
| MountHistory.birth | `Option<ValidationBirth>` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:14` | 219 | S, R |
| MountHistory.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:13` | 220 | S, R |
| MountHistory.directory | `Identity` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:10` | 221 | S, R |
| MountHistory.mounted_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:16` | 222 | S, R |
| MountHistory.name | `String` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:11` | 223 | S, R |
| MountHistory.placeholder | `Option<Placeholder>` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:15` | 224 | S, R |
| MountHistory.published_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:17` | 225 | S, R |
| MountHistory.request | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:8` | 226 | S, R |
| MountHistory.requested_at | `f64` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:12` | 227 | S, R |
| MountHistory.source | `Identity` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:9` | 228 | S, R |
| MountWitness.actual_wait_status | `i32` | `crates/vprouter-launch/src/kernel/namespace_attachment.rs:884` | 781 | S |
| MountWitness.birth | `emitted Birth` | `crates/vprouter-launch/src/kernel/namespace_attachment.rs:884` | 782 | S |
| MountWitness.deadline | `f64` | `crates/vprouter-launch/src/kernel/namespace_attachment.rs:885` | 783 | S |
| MountWitness.eof | `bool` | `crates/vprouter-launch/src/kernel/namespace_attachment.rs:889` | 784 | S |
| MountWitness.original_directory | `emitted Identity` | `crates/vprouter-launch/src/kernel/namespace_attachment.rs:886` | 785 | S |
| MountWitness.original_mounted_namespace_retained | `bool` | `crates/vprouter-launch/src/kernel/namespace_attachment.rs:888` | 786 | S |
| MountWitness.original_placeholder_retained | `bool` | `crates/vprouter-launch/src/kernel/namespace_attachment.rs:887` | 787 | S |
| MountWitness.original_source | `emitted Identity` | `crates/vprouter-launch/src/kernel/namespace_attachment.rs:886` | 788 | S |
| MountWitness.placeholder | `emitted Placeholder` | `crates/vprouter-launch/src/kernel/namespace_attachment.rs:887` | 789 | S |
| MountWitness.received_packets | `u8` | `crates/vprouter-launch/src/kernel/namespace_attachment.rs:889` | 790 | S |
| MountWitness.released_gates | `u8` | `crates/vprouter-launch/src/kernel/namespace_attachment.rs:888` | 791 | S |
| MountWitness.requested_at | `f64` | `crates/vprouter-launch/src/kernel/namespace_attachment.rs:885` | 792 | S |
| Movement.continued_original_context | `bool` | `crates/vprouter-launch/src/attachment/movement.rs:856` | 674 | S |
| Movement.data_move_completed | `bool` | `crates/vprouter-launch/src/attachment/movement.rs:857` | 675 | S |
| Movement.failed_constructor | `emitted null` | `crates/vprouter-launch/src/attachment/movement.rs:854` | 676 | S |
| Movement.fault | `u8` | `crates/vprouter-launch/src/attachment/movement.rs:851` | 677 | S |
| Movement.final_process_verified_at | `f64` | `crates/vprouter-launch/src/attachment/movement.rs:853` | 678 | S |
| Movement.held_real_result_writer | `bool` | `crates/vprouter-launch/src/attachment/movement.rs:854` | 679 | S |
| Movement.host_resources_created | `bool` | `crates/vprouter-launch/src/attachment/movement.rs:857` | 680 | S |
| Movement.move_borrows_both_original_pairs | `bool` | `crates/vprouter-launch/src/attachment/movement.rs:855` | 681 | S |
| Movement.movement_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/movement.rs:856` | 682 | S |
| Movement.movement_query | `emitted Query` | `crates/vprouter-launch/src/attachment/movement.rs:852` | 683 | S |
| Movement.operational_reuse_authorized | `bool` | `crates/vprouter-launch/src/attachment/movement.rs:858` | 684 | S |
| Movement.operations | `emitted list(MovementOperation)` | `crates/vprouter-launch/src/attachment/movement.rs:852` | 685 | S |
| Movement.original_provision_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/movement.rs:856` | 686 | S |
| Movement.original_query_parent_readback_advanced | `bool` | `crates/vprouter-launch/src/attachment/movement.rs:853` | 687 | S |
| Movement.parent_pristine | `bool` | `crates/vprouter-launch/src/attachment/movement.rs:856` | 688 | S |
| Movement.preparation | `emitted Preparation` | `crates/vprouter-launch/src/attachment/movement.rs:852` | 689 | S |
| Movement.provision | `emitted Provision` | `crates/vprouter-launch/src/attachment/movement.rs:851` | 690 | S |
| Movement.requirement8_complete | `bool` | `crates/vprouter-launch/src/attachment/movement.rs:858` | 691 | S |
| Movement.same_service_retained | `bool` | `crates/vprouter-launch/src/attachment/movement.rs:856` | 692 | S |
| Movement.schema | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/movement.rs:851` | 693 | S |
| Movement.unacknowledged_native_result_retained | `bool` | `crates/vprouter-launch/src/attachment/movement.rs:855` | 694 | S |
| Movement.whole_chain_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/movement.rs:856` | 695 | S |
| Movement.wireguard_down_only | `bool` | `crates/vprouter-launch/src/attachment/movement.rs:857` | 696 | S |
| MovementHistory.birth | `Option<ValidationBirth>` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:14` | 365 | S |
| MovementHistory.configuration | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:11` | 366 | S |
| MovementHistory.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:13` | 367 | S |
| MovementHistory.destination | `Option<Identity>` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:18` | 368 | S |
| MovementHistory.kind | `Kind` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:8` | 369 | S |
| MovementHistory.movement_query | `Option<[u8; 32]>` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:20` | 370 | S |
| MovementHistory.namespace | `Identity` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:10` | 371 | S |
| MovementHistory.request | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:9` | 372 | S |
| MovementHistory.requested_at | `f64` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:12` | 373 | S |
| MovementHistory.result | `Option<PublicResult>` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:15` | 374 | S |
| MovementHistory.verified_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:16` | 375 | S |
| MovementOperation.accepted_at | `f64` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1588` | 713 | S |
| MovementOperation.acknowledged | `bool` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1588` | 714 | S |
| MovementOperation.actual_wait_status | `i32` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1585` | 715 | S |
| MovementOperation.birth | `emitted Birth` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1583` | 716 | S |
| MovementOperation.borrowed_registration_count | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1587` | 717 | S |
| MovementOperation.context_retained | `bool` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1589` | 718 | S |
| MovementOperation.deadline | `f64` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1583` | 719 | S |
| MovementOperation.full_descriptor_registration | `bool` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1587` | 720 | S |
| MovementOperation.kind | `emitted wireguard_kind` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1583` | 721 | S |
| MovementOperation.native_born | `bool` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1585` | 722 | S |
| MovementOperation.native_job_state | `emitted job_state` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1586` | 723 | S |
| MovementOperation.original_pid | `u32` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1584` | 724 | S |
| MovementOperation.original_start | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1584` | 725 | S |
| MovementOperation.postcompletion_inventory_polls | `u32` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1590` | 726 | S |
| MovementOperation.postcompletion_inventory_preserved | `bool` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1591` | 727 | S |
| MovementOperation.query_sequences | `Option<[[u32;2];2]>` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1589` | 728 | S |
| MovementOperation.registered_native_slots | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1587` | 729 | S |
| MovementOperation.request | `[u8;32]` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1655` | 730 | S |
| MovementOperation.requested_at | `f64` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1583` | 731 | S |
| MovementOperation.result | `emitted WireguardResult` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:1588` | 732 | S |
| NetfilterHistory.birth | `Option<ValidationBirth>` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:271` | 275 | S, R |
| NetfilterHistory.configuration | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:265` | 276 | S, R |
| NetfilterHistory.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:270` | 277 | S, R |
| NetfilterHistory.host_declaration | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:266` | 278 | S, R |
| NetfilterHistory.kind | `Kind` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:261` | 279 | S, R |
| NetfilterHistory.namespace | `Identity` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:264` | 280 | S, R |
| NetfilterHistory.policy | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:267` | 281 | S, R |
| NetfilterHistory.query | `Option<[u8; 32]>` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:268` | 282 | S, R |
| NetfilterHistory.request | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:263` | 283 | S, R |
| NetfilterHistory.requested_at | `f64` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:269` | 284 | S, R |
| NetfilterHistory.result | `Option<PublicResult>` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:272` | 285 | S, R |
| NetfilterHistory.scope | `Scope` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:262` | 286 | S, R |
| NetfilterHistory.verified_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:273` | 287 | S, R |
| NetfilterResult.namespace | `Identity` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:278` | 290 | S, R |
| NetfilterResult.observed_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:281` | 291 | S, R |
| NetfilterResult.policy | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:279` | 292 | S, R |
| OperationalReservation.global_transferred_ticket_limit | `u64/usize (amd64)` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:92` | 388 | S |
| OperationalReservation.member | `String` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:20` | 389 | S |
| OperationalReservation.member_transfer_pending | `bool` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:93` | 390 | S |
| OperationalReservation.original_jobs | `u64/usize (amd64)` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:91` | 391 | S |
| OperationalReservation.owner_epoch | `emitted OwnerEpoch` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:91` | 392 | S |
| OperationalReservation.suffix_complete | `bool` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:313` | 393 | S |
| OperationalReservation.suffix_failed | `bool` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:313` | 394 | S |
| OperationalReservation.suffix_jobs | `u64/usize (amd64)` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:313` | 395 | S |
| OriginalWriter.index | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:842` | 843 | S |
| OriginalWriter.pid | `u32` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:842` | 844 | S |
| OriginalWriter.start | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:842` | 845 | S |
| OwnerEpoch.boot | `String` | `crates/vprouter-launch/src/supervision.rs:38` | 193 | S, R |
| OwnerEpoch.cgroup | `Identity` | `crates/vprouter-launch/src/supervision.rs:43` | 194 | S, R |
| OwnerEpoch.invocation | `String` | `crates/vprouter-launch/src/supervision.rs:40` | 195 | S, R |
| OwnerEpoch.pid | `u32` | `crates/vprouter-launch/src/supervision.rs:41` | 196 | S, R |
| OwnerEpoch.start | `u64` | `crates/vprouter-launch/src/supervision.rs:42` | 197 | S, R |
| OwnerEpoch.unit | `String` | `crates/vprouter-launch/src/supervision.rs:39` | 198 | S, R |
| Placeholder.identity | `Identity` | `crates/vprouter-launch/src/owned/preparation/mount.rs:8` | 175 | S, R |
| Placeholder.mode | `u32` | `crates/vprouter-launch/src/owned/preparation/mount.rs:9` | 176 | S, R |
| Preparation.attachment | `emitted Attachment` | `crates/vprouter-launch/src/owned/preparation.rs:1619` | 98 | S |
| Preparation.base_network | `emitted Identity` | `crates/vprouter-launch/src/owned/preparation.rs:1615` | 99 | S |
| Preparation.base_network_absent | `bool` | `crates/vprouter-launch/src/owned/preparation.rs:1614` | 100 | S |
| Preparation.birth | `emitted Birth` | `crates/vprouter-launch/src/owned/preparation.rs:1613` | 101 | S |
| Preparation.bootstrap | `emitted list(BootstrapHistory)` | `crates/vprouter-launch/src/owned/preparation.rs:1632` | 102 | S |
| Preparation.bootstrap_queries | `[Option<inspection::History>;3]` | `crates/vprouter-launch/src/owned/preparation.rs:1633` | 103 | S |
| Preparation.canonical_owner_epoch | `emitted OwnerEpoch` | `crates/vprouter-launch/src/owned/preparation.rs:1642` | 104 | S |
| Preparation.canonical_pending | `bool` | `crates/vprouter-launch/src/owned/preparation.rs:1645` | 105 | S |
| Preparation.canonical_result_present | `bool` | `crates/vprouter-launch/src/owned/preparation.rs:1643` | 106 | S |
| Preparation.data_network | `emitted Identity` | `crates/vprouter-launch/src/owned/preparation.rs:1616` | 107 | S |
| Preparation.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation.rs:1613` | 108 | S |
| Preparation.entry_attempt_absent | `bool` | `crates/vprouter-launch/src/owned/preparation.rs:1627` | 109 | S |
| Preparation.entry_links_absent | `bool` | `crates/vprouter-launch/src/owned/preparation.rs:1626` | 110 | S |
| Preparation.entry_phase | `emitted entry_phase` | `crates/vprouter-launch/src/owned/preparation.rs:1625` | 111 | S |
| Preparation.entry_producer | `emitted EntryProducer&#124;null` | `crates/vprouter-launch/src/owned/preparation.rs:1629` | 112 | S |
| Preparation.entry_producer_absent | `bool` | `crates/vprouter-launch/src/owned/preparation.rs:1631` | 113 | S |
| Preparation.entry_terminal_absent | `bool` | `crates/vprouter-launch/src/owned/preparation.rs:1628` | 114 | S |
| Preparation.fresh_transport | `emitted FreshTransport&#124;null` | `crates/vprouter-launch/src/owned/preparation.rs:1620` | 115 | S |
| Preparation.host_link | `emitted list(HostLinkHistory)` | `crates/vprouter-launch/src/owned/preparation.rs:1622` | 116 | S |
| Preparation.inspection | `emitted InspectionHistory` | `crates/vprouter-launch/src/owned/preparation.rs:1618` | 117 | S |
| Preparation.member | `String` | `crates/vprouter-launch/src/owned/preparation.rs:1612` | 118 | S |
| Preparation.member_native_jobs_collected | `bool` | `crates/vprouter-launch/src/owned/preparation.rs:1647` | 119 | S |
| Preparation.movement_query | `emitted InspectionHistory&#124;null` | `crates/vprouter-launch/src/owned/preparation.rs:1639` | 120 | S |
| Preparation.mutation_fenced | `bool` | `crates/vprouter-launch/src/owned/preparation.rs:1645` | 121 | S |
| Preparation.native_children_reaped | `bool` | `crates/vprouter-launch/src/owned/preparation.rs:1646` | 122 | S |
| Preparation.netfilter | `emitted list(NetfilterHistory)` | `crates/vprouter-launch/src/owned/preparation.rs:1637` | 123 | S |
| Preparation.owner_host_anchor_present | `bool` | `crates/vprouter-launch/src/owned/preparation.rs:1641` | 124 | S |
| Preparation.pending_bootstrap | `emitted null` | `crates/vprouter-launch/src/owned/preparation.rs:1649` | 125 | S |
| Preparation.pending_host_link | `emitted null` | `crates/vprouter-launch/src/owned/preparation.rs:1623` | 126 | S |
| Preparation.pending_producer_binding | `emitted null` | `crates/vprouter-launch/src/owned/preparation.rs:1630` | 127 | S |
| Preparation.pending_producer_creation | `emitted null` | `crates/vprouter-launch/src/owned/preparation.rs:1640` | 128 | S |
| Preparation.pending_wireguard | `emitted null` | `crates/vprouter-launch/src/owned/preparation.rs:1640` | 129 | S |
| Preparation.producer_binding | `emitted ProducerBindingHistory&#124;null` | `crates/vprouter-launch/src/owned/preparation.rs:1635` | 130 | S |
| Preparation.producer_binding_query | `emitted InspectionHistory&#124;null` | `crates/vprouter-launch/src/owned/preparation.rs:1634` | 131 | S |
| Preparation.producer_creation | `emitted ProducerCreationHistory&#124;null` | `crates/vprouter-launch/src/owned/preparation.rs:1624` | 132 | S |
| Preparation.producer_query | `emitted InspectionHistory&#124;null` | `crates/vprouter-launch/src/owned/preparation.rs:1636` | 133 | S |
| Preparation.quarantine_query | `emitted InspectionHistory&#124;null` | `crates/vprouter-launch/src/owned/preparation.rs:1638` | 134 | S |
| Preparation.requested_at | `f64` | `crates/vprouter-launch/src/owned/preparation.rs:1612` | 135 | S |
| Preparation.service_reserved | `bool` | `crates/vprouter-launch/src/owned/preparation.rs:1644` | 136 | S |
| Preparation.transport_network | `emitted Identity&#124;null` | `crates/vprouter-launch/src/owned/preparation.rs:1617` | 137 | S |
| Preparation.wireguard | `emitted list(MovementHistory&#124;WireguardHistory)` | `crates/vprouter-launch/src/owned/preparation.rs:1621` | 138 | S |
| Preparation.writers | `emitted list(Writer)` | `crates/vprouter-launch/src/owned/preparation.rs:1648` | 139 | S |
| ProducerBinding.assembly | `emitted Assembly` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1145` | 545 | S |
| ProducerBinding.assembly_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1148` | 546 | S |
| ProducerBinding.canonical_negative_checks | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1146` | 547 | S |
| ProducerBinding.canonical_producer_published | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1147` | 548 | S |
| ProducerBinding.charges_after_drop | `emitted null` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1155` | 549 | S |
| ProducerBinding.charges_before | `emitted list(u64)` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1146` | 550 | S |
| ProducerBinding.charges_before_drop | `emitted list(u64)` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1146` | 551 | S |
| ProducerBinding.continued_original_context | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1154` | 552 | S |
| ProducerBinding.failed_constructor | `emitted null` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1145` | 553 | S |
| ProducerBinding.failure_retry | `emitted null` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1146` | 554 | S |
| ProducerBinding.fault | `u8` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1145` | 555 | S |
| ProducerBinding.final_process_verified_at | `f64` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1146` | 556 | S |
| ProducerBinding.health_ready_authorized | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1149` | 557 | S |
| ProducerBinding.host_network_links_or_routes_created | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1149` | 558 | S |
| ProducerBinding.movement_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1148` | 559 | S |
| ProducerBinding.multi_exit_runtime_proven | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1149` | 560 | S |
| ProducerBinding.observation | `emitted ProducerObservation` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1145` | 561 | S |
| ProducerBinding.original_group | `emitted Identity` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1146` | 562 | S |
| ProducerBinding.original_provision_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1148` | 563 | S |
| ProducerBinding.parent_pristine | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1149` | 564 | S |
| ProducerBinding.placement_authorized | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1149` | 565 | S |
| ProducerBinding.preparation | `emitted Preparation` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1145` | 566 | S |
| ProducerBinding.producer_binding_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1148` | 567 | S |
| ProducerBinding.producer_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1148` | 568 | S |
| ProducerBinding.producer_exception_authorized | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1149` | 569 | S |
| ProducerBinding.quarantine_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1148` | 570 | S |
| ProducerBinding.query | `emitted Query` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1145` | 571 | S |
| ProducerBinding.requirement8_complete | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1149` | 572 | S |
| ProducerBinding.resource_cleanup_authorized | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1149` | 573 | S |
| ProducerBinding.result_writer_held | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1147` | 574 | S |
| ProducerBinding.retained_result_writer | `emitted null` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1146` | 575 | S |
| ProducerBinding.same_original_source | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1149` | 576 | S |
| ProducerBinding.schema | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1145` | 577 | S |
| ProducerBinding.unacknowledged_observation_retained | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1147` | 578 | S |
| ProducerBinding.up_authorized | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1149` | 579 | S |
| ProducerBinding.whole_chain_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/producer_binding.rs:1148` | 580 | S |
| ProducerBindingHistory.birth | `Option<ValidationBirth>` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:24` | 295 | S, R |
| ProducerBindingHistory.creation | `producer_creation::History` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:26` | 296 | S, R |
| ProducerBindingHistory.data | `Identity` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:20` | 297 | S, R |
| ProducerBindingHistory.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:23` | 298 | S, R |
| ProducerBindingHistory.group | `Identity` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:25` | 299 | S, R |
| ProducerBindingHistory.name | `String` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:19` | 300 | S, R |
| ProducerBindingHistory.parent | `Identity` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:18` | 301 | S, R |
| ProducerBindingHistory.pins | `[(u64, u64, u32); 6]` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:28` | 302 | S, R |
| ProducerBindingHistory.policy | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:27` | 303 | S, R |
| ProducerBindingHistory.query | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:21` | 304 | S, R |
| ProducerBindingHistory.request | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:17` | 305 | S, R |
| ProducerBindingHistory.requested_at | `f64` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:22` | 306 | S, R |
| ProducerBindingHistory.result | `Option<PublicResult>` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:29` | 307 | S, R |
| ProducerBindingHistory.verified_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:30` | 308 | S, R |
| ProducerBindingResult.group | `Identity` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:9` | 323 | S, R |
| ProducerBindingResult.namespace | `Identity` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:8` | 324 | S, R |
| ProducerBindingResult.observed_at | `f64` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:12` | 325 | S, R |
| ProducerBindingResult.pins | `[(u64, u64, u32); 6]` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:11` | 326 | S, R |
| ProducerBindingResult.policy | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:10` | 327 | S, R |
| ProducerCreationHistory.birth | `Option<ValidationBirth>` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:15` | 311 | S, R |
| ProducerCreationHistory.data | `Identity` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:11` | 312 | S, R |
| ProducerCreationHistory.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:14` | 313 | S, R |
| ProducerCreationHistory.group | `Option<Identity>` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:16` | 314 | S, R |
| ProducerCreationHistory.name | `String` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:10` | 315 | S, R |
| ProducerCreationHistory.parent | `Identity` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:9` | 316 | S, R |
| ProducerCreationHistory.query | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:12` | 317 | S, R |
| ProducerCreationHistory.request | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:8` | 318 | S, R |
| ProducerCreationHistory.requested_at | `f64` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:13` | 319 | S, R |
| ProducerCreationHistory.verified_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:17` | 320 | S, R |
| ProducerObservation.accepted_at | `f64` | `crates/vprouter-launch/src/kernel/producer_binding.rs:579` | 895 | S |
| ProducerObservation.acknowledged | `bool` | `crates/vprouter-launch/src/kernel/producer_binding.rs:579` | 896 | S |
| ProducerObservation.actual_wait_status | `i32` | `crates/vprouter-launch/src/kernel/producer_binding.rs:576` | 897 | S |
| ProducerObservation.birth | `emitted Birth` | `crates/vprouter-launch/src/kernel/producer_binding.rs:576` | 898 | S |
| ProducerObservation.borrowed_registration_count | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/producer_binding.rs:578` | 899 | S |
| ProducerObservation.complete_native_registration | `bool` | `crates/vprouter-launch/src/kernel/producer_binding.rs:578` | 900 | S |
| ProducerObservation.context_retained | `bool` | `crates/vprouter-launch/src/kernel/producer_binding.rs:580` | 901 | S |
| ProducerObservation.data | `emitted Identity` | `crates/vprouter-launch/src/kernel/producer_binding.rs:575` | 902 | S |
| ProducerObservation.deadline | `f64` | `crates/vprouter-launch/src/kernel/producer_binding.rs:574` | 903 | S |
| ProducerObservation.durable_birth_released | `bool` | `crates/vprouter-launch/src/kernel/producer_binding.rs:579` | 904 | S |
| ProducerObservation.eof | `bool` | `crates/vprouter-launch/src/kernel/producer_binding.rs:580` | 905 | S |
| ProducerObservation.group | `emitted Identity` | `crates/vprouter-launch/src/kernel/producer_binding.rs:575` | 906 | S |
| ProducerObservation.name | `String` | `crates/vprouter-launch/src/kernel/producer_binding.rs:575` | 907 | S |
| ProducerObservation.native_born | `bool` | `crates/vprouter-launch/src/kernel/producer_binding.rs:576` | 908 | S |
| ProducerObservation.native_job_state | `emitted job_state` | `crates/vprouter-launch/src/kernel/producer_binding.rs:577` | 909 | S |
| ProducerObservation.original_pid | `u32` | `crates/vprouter-launch/src/kernel/producer_binding.rs:576` | 910 | S |
| ProducerObservation.original_registration_slots_verified | `bool` | `crates/vprouter-launch/src/kernel/producer_binding.rs:578` | 911 | S |
| ProducerObservation.original_start | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/producer_binding.rs:576` | 912 | S |
| ProducerObservation.parent | `emitted Identity` | `crates/vprouter-launch/src/kernel/producer_binding.rs:575` | 913 | S |
| ProducerObservation.pins | `[(u64,u64,u32);6]` | `crates/vprouter-launch/src/kernel/producer_binding.rs:575` | 914 | S |
| ProducerObservation.placement_authorized | `bool` | `crates/vprouter-launch/src/kernel/producer_binding.rs:580` | 915 | S |
| ProducerObservation.policy | `[u8;32]` | `crates/vprouter-launch/src/kernel/producer_binding.rs:575` | 916 | S |
| ProducerObservation.producer_exception_authorized | `bool` | `crates/vprouter-launch/src/kernel/producer_binding.rs:580` | 917 | S |
| ProducerObservation.query | `[u8;32]` | `crates/vprouter-launch/src/kernel/producer_binding.rs:574` | 918 | S |
| ProducerObservation.registered_native_slots | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/producer_binding.rs:578` | 919 | S |
| ProducerObservation.request | `[u8;32]` | `crates/vprouter-launch/src/kernel/producer_binding.rs:574` | 920 | S |
| ProducerObservation.requested_at | `f64` | `crates/vprouter-launch/src/kernel/producer_binding.rs:574` | 921 | S |
| ProducerObservation.result | `emitted ProducerBindingResult` | `crates/vprouter-launch/src/kernel/producer_binding.rs:579` | 922 | S |
| ProducerObservation.up_authorized | `bool` | `crates/vprouter-launch/src/kernel/producer_binding.rs:580` | 923 | S |
| ProducerWitness.acknowledged | `bool` | `crates/vprouter-launch/src/kernel/producer_creation.rs:710` | 848 | S |
| ProducerWitness.actual_wait_status | `i32` | `crates/vprouter-launch/src/kernel/producer_creation.rs:707` | 849 | S |
| ProducerWitness.birth | `emitted Birth` | `crates/vprouter-launch/src/kernel/producer_creation.rs:39` | 850 | S |
| ProducerWitness.context_retained | `bool` | `crates/vprouter-launch/src/kernel/producer_creation.rs:711` | 851 | S |
| ProducerWitness.data | `emitted Identity` | `crates/vprouter-launch/src/kernel/producer_creation.rs:705` | 852 | S |
| ProducerWitness.deadline | `f64` | `crates/vprouter-launch/src/kernel/producer_creation.rs:704` | 853 | S |
| ProducerWitness.durable_birth_released | `bool` | `crates/vprouter-launch/src/kernel/producer_creation.rs:710` | 854 | S |
| ProducerWitness.eof | `bool` | `crates/vprouter-launch/src/kernel/producer_creation.rs:43` | 855 | S |
| ProducerWitness.full_descriptor_registration | `bool` | `crates/vprouter-launch/src/kernel/producer_creation.rs:709` | 856 | S |
| ProducerWitness.group | `emitted Identity` | `crates/vprouter-launch/src/kernel/producer_creation.rs:705` | 857 | S |
| ProducerWitness.name | `String` | `crates/vprouter-launch/src/kernel/producer_creation.rs:705` | 858 | S |
| ProducerWitness.native_born | `bool` | `crates/vprouter-launch/src/kernel/producer_creation.rs:707` | 859 | S |
| ProducerWitness.native_job_state | `emitted job_state` | `crates/vprouter-launch/src/kernel/producer_creation.rs:708` | 860 | S |
| ProducerWitness.operational_publication | `bool` | `crates/vprouter-launch/src/kernel/producer_creation.rs:711` | 861 | S |
| ProducerWitness.original_pid | `u32` | `crates/vprouter-launch/src/kernel/producer_creation.rs:706` | 862 | S |
| ProducerWitness.original_start | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/producer_creation.rs:706` | 863 | S |
| ProducerWitness.parent | `emitted Identity` | `crates/vprouter-launch/src/kernel/producer_creation.rs:705` | 864 | S |
| ProducerWitness.parent_death_lock_survival_claimed | `bool` | `crates/vprouter-launch/src/kernel/producer_creation.rs:711` | 865 | S |
| ProducerWitness.query | `[u8;32]` | `crates/vprouter-launch/src/kernel/producer_creation.rs:704` | 866 | S |
| ProducerWitness.received_original_group | `bool` | `crates/vprouter-launch/src/kernel/producer_creation.rs:709` | 867 | S |
| ProducerWitness.registered_native_slots | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/producer_creation.rs:709` | 868 | S |
| ProducerWitness.request | `[u8;32]` | `crates/vprouter-launch/src/kernel/producer_creation.rs:28` | 869 | S |
| ProducerWitness.requested_at | `f64` | `crates/vprouter-launch/src/kernel/producer_creation.rs:704` | 870 | S |
| ProducerWitness.verified_at | `f64` | `crates/vprouter-launch/src/kernel/producer_creation.rs:23` | 871 | S |
| Provision.attachment | `emitted AttachmentWitness` | `crates/vprouter-launch/src/attachment/provision.rs:1027` | 735 | S |
| Provision.continued_original_context | `bool` | `crates/vprouter-launch/src/attachment/provision.rs:1038` | 736 | S |
| Provision.failed_constructor | `emitted null` | `crates/vprouter-launch/src/attachment/provision.rs:1029` | 737 | S |
| Provision.fault | `u8` | `crates/vprouter-launch/src/attachment/provision.rs:1027` | 738 | S |
| Provision.held_real_result_writer | `bool` | `crates/vprouter-launch/src/attachment/provision.rs:1029` | 739 | S |
| Provision.host_resources_created | `bool` | `crates/vprouter-launch/src/attachment/provision.rs:1032` | 740 | S |
| Provision.operational_reuse_authorized | `bool` | `crates/vprouter-launch/src/attachment/provision.rs:1032` | 741 | S |
| Provision.operations | `emitted list(MovementOperation)` | `crates/vprouter-launch/src/attachment/provision.rs:1028` | 742 | S |
| Provision.original_socket_registrations_borrowed | `bool` | `crates/vprouter-launch/src/attachment/provision.rs:1031` | 743 | S |
| Provision.parent_pristine | `bool` | `crates/vprouter-launch/src/attachment/provision.rs:1029` | 744 | S |
| Provision.preparation | `emitted Preparation` | `crates/vprouter-launch/src/attachment/provision.rs:1027` | 745 | S |
| Provision.requirement8_complete | `bool` | `crates/vprouter-launch/src/attachment/provision.rs:1032` | 746 | S |
| Provision.same_service_retained | `bool` | `crates/vprouter-launch/src/attachment/provision.rs:1030` | 747 | S |
| Provision.schema | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/provision.rs:1027` | 748 | S |
| Provision.transport_creation | `emitted TransportWitness` | `crates/vprouter-launch/src/attachment/provision.rs:1028` | 749 | S |
| Provision.transport_distinct_from_host_and_data | `bool` | `crates/vprouter-launch/src/attachment/provision.rs:1030` | 750 | S |
| Provision.transport_mount | `emitted MountWitness` | `crates/vprouter-launch/src/attachment/provision.rs:1028` | 751 | S |
| Provision.unacknowledged_native_result_retained | `bool` | `crates/vprouter-launch/src/attachment/provision.rs:1029` | 752 | S |
| Provision.whole_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/provision.rs:1030` | 753 | S |
| Provision.wireguard_down_only | `bool` | `crates/vprouter-launch/src/attachment/provision.rs:1031` | 754 | S |
| Quarantine.continued_original_context | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1029` | 641 | S |
| Quarantine.failed_constructor | `emitted null` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1026` | 642 | S |
| Quarantine.fault | `u8` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1025` | 643 | S |
| Quarantine.final_process_verified_at | `f64` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1027` | 644 | S |
| Quarantine.held_real_result_writer | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1027` | 645 | S |
| Quarantine.host_network_links_or_routes_created | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1031` | 646 | S |
| Quarantine.initial_quarantine_installation_observed_all_scopes | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1031` | 647 | S |
| Quarantine.initial_quarantine_only | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1030` | 648 | S |
| Quarantine.movement | `emitted Movement` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1025` | 649 | S |
| Quarantine.movement_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1029` | 650 | S |
| Quarantine.operational_reuse_authorized | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1031` | 651 | S |
| Quarantine.operations | `emitted list(QuarantineOperation)` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1025` | 652 | S |
| Quarantine.original_provision_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1029` | 653 | S |
| Quarantine.own_intent_polling | `emitted QuarantineIntent` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1026` | 654 | S |
| Quarantine.parent_pristine | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1030` | 655 | S |
| Quarantine.preparation | `emitted Preparation` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1025` | 656 | S |
| Quarantine.producer | `emitted ProducerWitness` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1026` | 657 | S |
| Quarantine.producer_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1028` | 658 | S |
| Quarantine.producer_exceptions_authorized | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1031` | 659 | S |
| Quarantine.producer_group_creation_observed | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1031` | 660 | S |
| Quarantine.producer_operational_publication | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1030` | 661 | S |
| Quarantine.producer_query | `emitted Query` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1026` | 662 | S |
| Quarantine.quarantine_context_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1028` | 663 | S |
| Quarantine.quarantine_query | `emitted Query` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1026` | 664 | S |
| Quarantine.requirement8_complete | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1031` | 665 | S |
| Quarantine.same_service_retained | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1030` | 666 | S |
| Quarantine.schema | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1025` | 667 | S |
| Quarantine.unacknowledged_native_result_retained | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1027` | 668 | S |
| Quarantine.up_authorized | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1031` | 669 | S |
| Quarantine.wan | `emitted Wan` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1026` | 670 | S |
| Quarantine.whole_chain_retained_after_drop | `bool` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:1028` | 671 | S |
| QuarantineIntent.actual_wait_status | `i32` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:843` | 833 | S |
| QuarantineIntent.deadline | `f64` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:843` | 834 | S |
| QuarantineIntent.held_pending_polls | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:841` | 835 | S |
| QuarantineIntent.negative_checks | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:842` | 836 | S |
| QuarantineIntent.original_writer | `emitted OriginalWriter` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:842` | 837 | S |
| QuarantineIntent.queued_polls | `u64/usize (amd64)` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:841` | 838 | S |
| QuarantineIntent.requested_at | `f64` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:843` | 839 | S |
| QuarantineIntent.verified_at | `f64` | `crates/vprouter-launch/src/attachment/quarantine/producer.rs:843` | 840 | S |
| QuarantineOperation.accepted_at | `f64` | `crates/vprouter-launch/src/kernel/netfilter_role.rs:50` | 813 | S |
| QuarantineOperation.acknowledged | `bool` | `crates/vprouter-launch/src/kernel/netfilter_role.rs:51` | 814 | S |
| QuarantineOperation.actual_wait_status | `i32` | `crates/vprouter-launch/src/kernel/netfilter_role.rs:71` | 815 | S |
| QuarantineOperation.birth | `emitted Birth` | `crates/vprouter-launch/src/kernel/netfilter_role.rs:48` | 816 | S |
| QuarantineOperation.borrowed_registration_count | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/netfilter_role.rs:749` | 817 | S |
| QuarantineOperation.context_retained | `bool` | `crates/vprouter-launch/src/kernel/netfilter_role.rs:751` | 818 | S |
| QuarantineOperation.deadline | `f64` | `crates/vprouter-launch/src/kernel/netfilter_role.rs:745` | 819 | S |
| QuarantineOperation.full_descriptor_registration | `bool` | `crates/vprouter-launch/src/kernel/netfilter_role.rs:749` | 820 | S |
| QuarantineOperation.kind | `emitted netfilter_kind` | `crates/vprouter-launch/src/kernel/netfilter_role.rs:744` | 821 | S |
| QuarantineOperation.native_born | `bool` | `crates/vprouter-launch/src/kernel/netfilter_role.rs:747` | 822 | S |
| QuarantineOperation.native_job_state | `emitted job_state` | `crates/vprouter-launch/src/kernel/netfilter_role.rs:748` | 823 | S |
| QuarantineOperation.original_pid | `u32` | `crates/vprouter-launch/src/kernel/netfilter_role.rs:746` | 824 | S |
| QuarantineOperation.original_start | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/netfilter_role.rs:746` | 825 | S |
| QuarantineOperation.registered_native_slots | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel/netfilter_role.rs:749` | 826 | S |
| QuarantineOperation.request | `[u8;32]` | `crates/vprouter-launch/src/kernel/netfilter_role.rs:34` | 827 | S |
| QuarantineOperation.requested_at | `f64` | `crates/vprouter-launch/src/kernel/netfilter_role.rs:745` | 828 | S |
| QuarantineOperation.result | `emitted NetfilterResult` | `crates/vprouter-launch/src/kernel/netfilter_role.rs:49` | 829 | S |
| QuarantineOperation.scope | `emitted scope` | `crates/vprouter-launch/src/kernel/netfilter_role.rs:744` | 830 | S |
| Query.actual_wait_status | `i32` | `crates/vprouter-launch/src/kernel/docker_query.rs:1271` | 699 | S |
| Query.birth | `emitted Birth` | `crates/vprouter-launch/src/kernel/docker_query.rs:1271` | 700 | S |
| Query.deadline | `f64` | `crates/vprouter-launch/src/kernel/docker_query.rs:1271` | 701 | S |
| Query.facts | `emitted QueryFacts` | `crates/vprouter-launch/src/kernel/docker_query.rs:1272` | 702 | S |
| Query.handler_identity_claimed | `bool` | `crates/vprouter-launch/src/kernel/docker_query.rs:1276` | 703 | S |
| Query.kind | `emitted query_kind` | `crates/vprouter-launch/src/kernel/docker_query.rs:1270` | 704 | S |
| Query.listener_origin_gid | `u32` | `crates/vprouter-launch/src/kernel/docker_query.rs:1275` | 705 | S |
| Query.listener_origin_pid | `i32` | `crates/vprouter-launch/src/kernel/docker_query.rs:1273` | 706 | S |
| Query.listener_origin_uid | `u32` | `crates/vprouter-launch/src/kernel/docker_query.rs:1274` | 707 | S |
| Query.original_peer_receipt | `bool` | `crates/vprouter-launch/src/kernel/docker_query.rs:1272` | 708 | S |
| Query.requested_at | `f64` | `crates/vprouter-launch/src/kernel/docker_query.rs:1270` | 709 | S |
| Query.verified_at | `f64` | `crates/vprouter-launch/src/kernel/docker_query.rs:1271` | 710 | S |
| QueryFacts.pid | `u32` | `crates/vprouter-launch/src/attachment.rs:793` | 189 | S, R |
| QueryFacts.security | `super::evidence::DaemonSecurity` | `crates/vprouter-launch/src/attachment.rs:794` | 190 | S, R |
| Resource.actual_wait_status | `i32` | `crates/vprouter-launch/src/kernel.rs:2511` | 398 | S |
| Resource.fully_retired | `bool` | `crates/vprouter-launch/src/kernel.rs:2513` | 399 | S |
| Resource.kind | `emitted job_kind` | `crates/vprouter-launch/src/kernel.rs:2510` | 400 | S |
| Resource.launch_charge_retired | `bool` | `crates/vprouter-launch/src/kernel.rs:2512` | 401 | S |
| Resource.lower_charge_required | `bool` | `crates/vprouter-launch/src/kernel.rs:2512` | 402 | S |
| Resource.lower_charge_retired | `emitted bool&#124;null` | `crates/vprouter-launch/src/kernel.rs:2513` | 403 | S |
| Resource.lower_gated_retirement_refused | `emitted bool&#124;null` | `crates/vprouter-launch/src/kernel.rs:2513` | 404 | S |
| Resource.native_job_state | `emitted job_state` | `crates/vprouter-launch/src/kernel.rs:2514` | 405 | S |
| Resource.original_pid | `u32` | `crates/vprouter-launch/src/kernel.rs:2510` | 406 | S |
| Resource.original_start | `u64/usize (amd64)` | `crates/vprouter-launch/src/kernel.rs:2510` | 407 | S |
| Resource.transfer_started | `bool` | `crates/vprouter-launch/src/kernel.rs:2511` | 408 | S |
| Route.destination | `IpAddr` | `crates/vprouter-network/src/project.rs:62` | 475 | S, R |
| Route.flags | `u32` | `crates/vprouter-network/src/project.rs:72` | 476 | S, R |
| Route.gateway | `Option<IpAddr>` | `crates/vprouter-network/src/project.rs:67` | 477 | S, R |
| Route.kind | `u8` | `crates/vprouter-network/src/project.rs:68` | 478 | S, R |
| Route.metric | `u32` | `crates/vprouter-network/src/project.rs:71` | 479 | S, R |
| Route.nexthop_id | `Option<u32>` | `crates/vprouter-network/src/project.rs:60` | 480 | S, R |
| Route.output | `u32` | `crates/vprouter-network/src/project.rs:65` | 481 | S, R |
| Route.preference | `u8` | `crates/vprouter-network/src/project.rs:61` | 482 | S, R |
| Route.prefix | `u8` | `crates/vprouter-network/src/project.rs:63` | 483 | S, R |
| Route.protocol | `u8` | `crates/vprouter-network/src/project.rs:70` | 484 | S, R |
| Route.scope | `u8` | `crates/vprouter-network/src/project.rs:69` | 485 | S, R |
| Route.source | `Option<IpAddr>` | `crates/vprouter-network/src/project.rs:66` | 486 | S, R |
| Route.table | `u32` | `crates/vprouter-network/src/project.rs:64` | 487 | S, R |
| Rule.action | `u8` | `crates/vprouter-network/src/project.rs:80` | 490 | S, R |
| Rule.flags | `u32` | `crates/vprouter-network/src/project.rs:81` | 491 | S, R |
| Rule.fwmark | `Option<u32>` | `crates/vprouter-network/src/project.rs:82` | 492 | S, R |
| Rule.fwmask | `Option<u32>` | `crates/vprouter-network/src/project.rs:83` | 493 | S, R |
| Rule.goto | `Option<u32>` | `crates/vprouter-network/src/project.rs:86` | 494 | S, R |
| Rule.ipv6 | `bool` | `crates/vprouter-network/src/project.rs:77` | 495 | S, R |
| Rule.priority | `u32` | `crates/vprouter-network/src/project.rs:78` | 496 | S, R |
| Rule.protocol | `Option<u8>` | `crates/vprouter-network/src/project.rs:88` | 497 | S, R |
| Rule.realm | `Option<u32>` | `crates/vprouter-network/src/project.rs:87` | 498 | S, R |
| Rule.suppress_ifgroup | `Option<u32>` | `crates/vprouter-network/src/project.rs:85` | 499 | S, R |
| Rule.suppress_prefixlen | `Option<u32>` | `crates/vprouter-network/src/project.rs:84` | 500 | S, R |
| Rule.table | `u32` | `crates/vprouter-network/src/project.rs:79` | 501 | S, R |
| TransportWitness.actual_wait_status | `i32` | `crates/vprouter-launch/src/kernel/fresh_transport.rs:502` | 799 | S |
| TransportWitness.birth | `emitted Birth` | `crates/vprouter-launch/src/kernel/fresh_transport.rs:36` | 800 | S |
| TransportWitness.data | `emitted Identity` | `crates/vprouter-launch/src/kernel/fresh_transport.rs:504` | 801 | S |
| TransportWitness.deadline | `f64` | `crates/vprouter-launch/src/kernel/fresh_transport.rs:503` | 802 | S |
| TransportWitness.durable_birth_released | `bool` | `crates/vprouter-launch/src/kernel/fresh_transport.rs:505` | 803 | S |
| TransportWitness.eof | `bool` | `crates/vprouter-launch/src/kernel/fresh_transport.rs:40` | 804 | S |
| TransportWitness.host | `emitted Identity` | `crates/vprouter-launch/src/kernel/fresh_transport.rs:504` | 805 | S |
| TransportWitness.original_source_retained | `bool` | `crates/vprouter-launch/src/kernel/fresh_transport.rs:505` | 806 | S |
| TransportWitness.request | `[u8;32]` | `crates/vprouter-launch/src/kernel/fresh_transport.rs:27` | 807 | S |
| TransportWitness.requested_at | `f64` | `crates/vprouter-launch/src/kernel/fresh_transport.rs:503` | 808 | S |
| TransportWitness.source | `emitted Identity` | `crates/vprouter-launch/src/kernel/fresh_transport.rs:504` | 809 | S |
| TransportWitness.verified_at | `f64` | `crates/vprouter-launch/src/kernel/fresh_transport.rs:23` | 810 | S |
| ValidatorWitness.actual_wait_status | `i32` | `crates/vprouter-launch/src/attachment/mount.rs:845` | 795 | S |
| ValidatorWitness.birth | `emitted Birth` | `crates/vprouter-launch/src/attachment/mount.rs:867` | 796 | S |
| Wan.address | `[u8;6]` | `crates/vprouter-launch/src/attachment/host_declaration.rs:19` | 874 | S |
| Wan.deadline | `f64` | `crates/vprouter-launch/src/attachment/host_declaration.rs:238` | 875 | S |
| Wan.declaration_digest | `[u8;32]` | `crates/vprouter-launch/src/attachment/host_declaration.rs:237` | 876 | S |
| Wan.host_namespace | `emitted Identity` | `crates/vprouter-launch/src/attachment/host_declaration.rs:29` | 877 | S |
| Wan.index | `u32` | `crates/vprouter-launch/src/attachment/host_declaration.rs:18` | 878 | S |
| Wan.name | `String` | `crates/vprouter-launch/src/attachment/host_declaration.rs:17` | 879 | S |
| Wan.original_observer_retained | `bool` | `crates/vprouter-launch/src/attachment/host_declaration.rs:238` | 880 | S |
| Wan.requested_at | `f64` | `crates/vprouter-launch/src/attachment/host_declaration.rs:238` | 881 | S |
| Wan.verified_at | `f64` | `crates/vprouter-launch/src/attachment/host_declaration.rs:169` | 882 | S |
| Wireguard.index | `u32` | `crates/vprouter-network/src/project.rs:119` | 353 | S, R |
| Wireguard.name | `String` | `crates/vprouter-network/src/project.rs:120` | 354 | S, R |
| Wireguard.peers | `Vec<Peer>` | `crates/vprouter-network/src/project.rs:122` | 355 | S, R |
| Wireguard.public_key | `[u8; 32]` | `crates/vprouter-network/src/project.rs:121` | 356 | S, R |
| WireguardHistory.birth | `Option<ValidationBirth>` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:14` | 337 | S |
| WireguardHistory.configuration | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:11` | 338 | S |
| WireguardHistory.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:13` | 339 | S |
| WireguardHistory.kind | `Kind` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:8` | 340 | S |
| WireguardHistory.namespace | `Identity` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:10` | 341 | S |
| WireguardHistory.request | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:9` | 342 | S |
| WireguardHistory.requested_at | `f64` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:12` | 343 | S |
| WireguardHistory.result | `Option<PublicResult>` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:15` | 344 | S |
| WireguardHistory.verified_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:16` | 345 | S |
| WireguardPeer.allowed_ips | `Vec<(IpAddr, u8)>` | `crates/vprouter-network/src/project.rs:113` | 359 | S, R |
| WireguardPeer.endpoint | `SocketAddr` | `crates/vprouter-network/src/project.rs:112` | 360 | S, R |
| WireguardPeer.handshake_unix | `Option<f64>` | `crates/vprouter-network/src/project.rs:114` | 361 | S, R |
| WireguardPeer.public_key | `[u8; 32]` | `crates/vprouter-network/src/project.rs:111` | 362 | S, R |
| WireguardResult.link | `Option<vprouter_network::Link>` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:26` | 348 | S |
| WireguardResult.namespace | `Identity` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:25` | 349 | S |
| WireguardResult.wireguard | `Option<vprouter_network::Wireguard>` | `crates/vprouter-launch/src/kernel/wireguard_role.rs:27` | 350 | S |
| Writer.actual_wait_status | `i32` | `crates/vprouter-launch/src/owned/preparation.rs:1581` | 378 | S |
| Writer.io_deadline | `f64` | `crates/vprouter-launch/src/owned/preparation.rs:1580` | 379 | S |
| Writer.parent_deadline | `f64` | `crates/vprouter-launch/src/owned/preparation.rs:1581` | 380 | S |
| Writer.phase | `String` | `crates/vprouter-launch/src/owned/preparation.rs:1579` | 381 | S |
| Writer.pid | `u32` | `crates/vprouter-launch/src/owned/preparation.rs:1579` | 382 | S |
| Writer.queued_at | `f64` | `crates/vprouter-launch/src/owned/preparation.rs:1580` | 383 | S |
| Writer.start | `u64/usize (amd64)` | `crates/vprouter-launch/src/owned/preparation.rs:1579` | 384 | S |
| Writer.verified_at | `f64` | `crates/vprouter-launch/src/owned/preparation.rs:1582` | 385 | S |

## Complete Rust struct/enum inventory, including native-only state

This is a declaration walk of every requested module, including test-only
support. Each listed field/variant preserves its exact Rust type spelling.
Serialized structures cross-reference the table above. All remaining fields
are **NATIVE_ONLY / NOT_RECONSTRUCTIBLE** unless their emitted projection is
listed above. `Rc` pointer identity, creator PID equality to the current
process, FDs, registrations, leases, reaping capabilities, retained Weak
anchors, mutex/registry state, syscall results, and internal Step/Progress
variants are not constructible or verifiable from a JSON witness. No mutation
of that witness can attest them. The validator neither imports nor executes
these Rust modules. `lab_cost` timers/counters and test helper structs do not
emit this witness. They are included to make the walk complete.

| Rust declaration / member or variant | Exact Rust type or variant | Rust file:line | Validator / mutation correspondence |
| --- | --- | --- | --- |
| History (struct) | declaration | `crates/vprouter-launch/src/owned/preparation.rs:25` | Preparation projection; private allocation/configuration/inputs/result omitted |
| History.member | `String` | `crates/vprouter-launch/src/owned/preparation.rs:26` | Preparation projection; private allocation/configuration/inputs/result omitted |
| History.allocation | `String` | `crates/vprouter-launch/src/owned/preparation.rs:27` | Preparation projection; private allocation/configuration/inputs/result omitted |
| History.configuration | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation.rs:28` | Preparation projection; private allocation/configuration/inputs/result omitted |
| History.owner | `OwnerDomainRecord` | `crates/vprouter-launch/src/owned/preparation.rs:29` | Preparation projection; private allocation/configuration/inputs/result omitted |
| History.inputs | `Vec<(String, InputIdentity)>` | `crates/vprouter-launch/src/owned/preparation.rs:30` | Preparation projection; private allocation/configuration/inputs/result omitted |
| History.requested_at | `f64` | `crates/vprouter-launch/src/owned/preparation.rs:31` | Preparation projection; private allocation/configuration/inputs/result omitted |
| History.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation.rs:32` | Preparation projection; private allocation/configuration/inputs/result omitted |
| History.birth | `Option<ValidationBirth>` | `crates/vprouter-launch/src/owned/preparation.rs:33` | Preparation projection; private allocation/configuration/inputs/result omitted |
| History.result | `Option<PublicValidation>` | `crates/vprouter-launch/src/owned/preparation.rs:34` | Preparation projection; private allocation/configuration/inputs/result omitted |
| History.inspection | `Option<inspection::History>` | `crates/vprouter-launch/src/owned/preparation.rs:36` | Preparation projection; private allocation/configuration/inputs/result omitted |
| History.mount | `Option<mount::History>` | `crates/vprouter-launch/src/owned/preparation.rs:38` | Preparation projection; private allocation/configuration/inputs/result omitted |
| History.fresh_transport | `Option<fresh_transport::History>` | `crates/vprouter-launch/src/owned/preparation.rs:40` | Preparation projection; private allocation/configuration/inputs/result omitted |
| History.wireguard | `Vec<wireguard::History>` | `crates/vprouter-launch/src/owned/preparation.rs:42` | Preparation projection; private allocation/configuration/inputs/result omitted |
| History.movement_query | `Option<inspection::History>` | `crates/vprouter-launch/src/owned/preparation.rs:44` | Preparation projection; private allocation/configuration/inputs/result omitted |
| History.quarantine_query | `Option<inspection::History>` | `crates/vprouter-launch/src/owned/preparation.rs:46` | Preparation projection; private allocation/configuration/inputs/result omitted |
| History.producer_query | `Option<inspection::History>` | `crates/vprouter-launch/src/owned/preparation.rs:48` | Preparation projection; private allocation/configuration/inputs/result omitted |
| History.producer_binding_query | `Option<inspection::History>` | `crates/vprouter-launch/src/owned/preparation.rs:50` | Preparation projection; private allocation/configuration/inputs/result omitted |
| History.producer_creation | `Option<producer_creation::History>` | `crates/vprouter-launch/src/owned/preparation.rs:52` | Preparation projection; private allocation/configuration/inputs/result omitted |
| History.producer_binding | `Option<producer_binding::History>` | `crates/vprouter-launch/src/owned/preparation.rs:54` | Preparation projection; private allocation/configuration/inputs/result omitted |
| History.netfilter | `Vec<quarantine::Operation>` | `crates/vprouter-launch/src/owned/preparation.rs:56` | Preparation projection; private allocation/configuration/inputs/result omitted |
| History.host_link | `Vec<host_link::History>` | `crates/vprouter-launch/src/owned/preparation.rs:58` | Preparation projection; private allocation/configuration/inputs/result omitted |
| History.bootstrap_queries | `[Option<inspection::History>; 3]` | `crates/vprouter-launch/src/owned/preparation.rs:60` | Preparation projection; private allocation/configuration/inputs/result omitted |
| History.bootstrap | `Vec<bootstrap::History>` | `crates/vprouter-launch/src/owned/preparation.rs:62` | Preparation projection; private allocation/configuration/inputs/result omitted |
| PublicValidation (struct) | declaration | `crates/vprouter-launch/src/owned/preparation.rs:70` | NATIVE_ONLY; no JSON mutation can exercise this field |
| PublicValidation.report | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation.rs:71` | NATIVE_ONLY; no JSON mutation can exercise this field |
| PublicValidation.selected | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation.rs:72` | NATIVE_ONLY; no JSON mutation can exercise this field |
| PublicValidation.device_key | `Option<[u8; 32]>` | `crates/vprouter-launch/src/owned/preparation.rs:73` | NATIVE_ONLY; no JSON mutation can exercise this field |
| PublicValidation.verified_at | `f64` | `crates/vprouter-launch/src/owned/preparation.rs:74` | NATIVE_ONLY; no JSON mutation can exercise this field |
| ValidationBirth (struct) | declaration | `crates/vprouter-launch/src/owned/preparation.rs:78` | Birth; S/R above |
| ValidationBirth.pid | `u32` | `crates/vprouter-launch/src/owned/preparation.rs:79` | Birth; S/R above |
| ValidationBirth.start | `u64` | `crates/vprouter-launch/src/owned/preparation.rs:80` | Birth; S/R above |
| ValidationBirth.born_at | `f64` | `crates/vprouter-launch/src/owned/preparation.rs:81` | Birth; S/R above |
| ValidationBirth.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation.rs:82` | Birth; S/R above |
| ValidationIntent (struct) | declaration | `crates/vprouter-launch/src/owned/preparation.rs:232` | NATIVE_ONLY; no JSON mutation can exercise this field |
| ValidationIntent.creator | `u32` | `crates/vprouter-launch/src/owned/preparation.rs:233` | NATIVE_ONLY; no JSON mutation can exercise this field |
| ValidationIntent.shared | `Rc<SharedJournal>` | `crates/vprouter-launch/src/owned/preparation.rs:234` | NATIVE_ONLY; no JSON mutation can exercise this field |
| ValidationIntent.member | `String` | `crates/vprouter-launch/src/owned/preparation.rs:235` | NATIVE_ONLY; no JSON mutation can exercise this field |
| ValidationIntent.history | `History` | `crates/vprouter-launch/src/owned/preparation.rs:236` | NATIVE_ONLY; no JSON mutation can exercise this field |
| ValidationIntent.owner | `Rc<OwnerDomain>` | `crates/vprouter-launch/src/owned/preparation.rs:237` | NATIVE_ONLY; no JSON mutation can exercise this field |
| ValidationIntent.domains | `Domains` | `crates/vprouter-launch/src/owned/preparation.rs:238` | NATIVE_ONLY; no JSON mutation can exercise this field |
| ValidationIntent.lease | `MutatorLease` | `crates/vprouter-launch/src/owned/preparation.rs:239` | NATIVE_ONLY; no JSON mutation can exercise this field |
| BirthReceipt (struct) | declaration | `crates/vprouter-launch/src/owned/preparation.rs:295` | NATIVE_ONLY; no JSON mutation can exercise this field |
| BirthReceipt.creator | `u32` | `crates/vprouter-launch/src/owned/preparation.rs:296` | NATIVE_ONLY; no JSON mutation can exercise this field |
| BirthReceipt.shared | `Rc<SharedJournal>` | `crates/vprouter-launch/src/owned/preparation.rs:297` | NATIVE_ONLY; no JSON mutation can exercise this field |
| BirthReceipt.member | `String` | `crates/vprouter-launch/src/owned/preparation.rs:298` | NATIVE_ONLY; no JSON mutation can exercise this field |
| BirthReceipt.birth | `ValidationBirth` | `crates/vprouter-launch/src/owned/preparation.rs:299` | NATIVE_ONLY; no JSON mutation can exercise this field |
| ValidationReceipt (struct) | declaration | `crates/vprouter-launch/src/owned/preparation.rs:301` | NATIVE_ONLY; no JSON mutation can exercise this field |
| ValidationReceipt.creator | `u32` | `crates/vprouter-launch/src/owned/preparation.rs:302` | NATIVE_ONLY; no JSON mutation can exercise this field |
| ValidationReceipt.shared | `Rc<SharedJournal>` | `crates/vprouter-launch/src/owned/preparation.rs:303` | NATIVE_ONLY; no JSON mutation can exercise this field |
| ValidationReceipt.member | `String` | `crates/vprouter-launch/src/owned/preparation.rs:304` | NATIVE_ONLY; no JSON mutation can exercise this field |
| ValidationReceipt.birth | `ValidationBirth` | `crates/vprouter-launch/src/owned/preparation.rs:305` | NATIVE_ONLY; no JSON mutation can exercise this field |
| ValidationReceipt.result | `PublicValidation` | `crates/vprouter-launch/src/owned/preparation.rs:306` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Server (struct) | declaration | `crates/vprouter-launch/src/owned/preparation.rs:374` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Server.native | `Option<Native>` | `crates/vprouter-launch/src/owned/preparation.rs:375` | NATIVE_ONLY; no JSON mutation can exercise this field |
| OriginalWrite (struct) | declaration | `crates/vprouter-launch/src/owned/preparation.rs:380` | NATIVE_ONLY; no JSON mutation can exercise this field |
| OriginalWrite.server | `&'a Server` | `crates/vprouter-launch/src/owned/preparation.rs:381` | NATIVE_ONLY; no JSON mutation can exercise this field |
| OriginalWrite.expected | `Record` | `crates/vprouter-launch/src/owned/preparation.rs:382` | NATIVE_ONLY; no JSON mutation can exercise this field |
| OriginalWrite.phase | `&'static str` | `crates/vprouter-launch/src/owned/preparation.rs:383` | NATIVE_ONLY; no JSON mutation can exercise this field |
| OriginalWrite.started | `f64` | `crates/vprouter-launch/src/owned/preparation.rs:384` | NATIVE_ONLY; no JSON mutation can exercise this field |
| PendingWriter (struct) | declaration | `crates/vprouter-launch/src/owned/preparation.rs:388` | NATIVE_ONLY; no JSON mutation can exercise this field |
| PendingWriter.child | `&'a kernel::JournalChild` | `crates/vprouter-launch/src/owned/preparation.rs:389` | NATIVE_ONLY; no JSON mutation can exercise this field |
| PendingWriter.jobs | `&'a Rc<RefCell<NativeJobs>>` | `crates/vprouter-launch/src/owned/preparation.rs:390` | NATIVE_ONLY; no JSON mutation can exercise this field |
| PendingWriter.member | `&'a str` | `crates/vprouter-launch/src/owned/preparation.rs:391` | NATIVE_ONLY; no JSON mutation can exercise this field |
| PendingWriter.phase | `&'static str` | `crates/vprouter-launch/src/owned/preparation.rs:392` | NATIVE_ONLY; no JSON mutation can exercise this field |
| PendingWriter.started | `f64` | `crates/vprouter-launch/src/owned/preparation.rs:393` | NATIVE_ONLY; no JSON mutation can exercise this field |
| PendingWriter.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation.rs:394` | NATIVE_ONLY; no JSON mutation can exercise this field |
| PendingWriter.mutation | `bool` | `crates/vprouter-launch/src/owned/preparation.rs:395` | NATIVE_ONLY; no JSON mutation can exercise this field |
| PendingWriter.failed | `bool` | `crates/vprouter-launch/src/owned/preparation.rs:396` | NATIVE_ONLY; no JSON mutation can exercise this field |
| PendingWriter.fenced | `bool` | `crates/vprouter-launch/src/owned/preparation.rs:397` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native (struct) | declaration | `crates/vprouter-launch/src/owned/preparation.rs:523` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.creator | `u32` | `crates/vprouter-launch/src/owned/preparation.rs:524` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.transaction | `Transaction` | `crates/vprouter-launch/src/owned/preparation.rs:525` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.owner | `Rc<OwnerDomain>` | `crates/vprouter-launch/src/owned/preparation.rs:526` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.domains | `Domains` | `crates/vprouter-launch/src/owned/preparation.rs:527` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.inputs | `Option<Inputs>` | `crates/vprouter-launch/src/owned/preparation.rs:528` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.history | `History` | `crates/vprouter-launch/src/owned/preparation.rs:529` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.queued_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation.rs:530` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.pending | `Option<JournalJob>` | `crates/vprouter-launch/src/owned/preparation.rs:531` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.failure | `Option<Error>` | `crates/vprouter-launch/src/owned/preparation.rs:532` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.issued | `bool` | `crates/vprouter-launch/src/owned/preparation.rs:533` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.birth | `Option<ValidationBirth>` | `crates/vprouter-launch/src/owned/preparation.rs:534` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.result | `Option<PublicValidation>` | `crates/vprouter-launch/src/owned/preparation.rs:535` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.result_issued | `bool` | `crates/vprouter-launch/src/owned/preparation.rs:536` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.continuation | `Option<Continuation>` | `crates/vprouter-launch/src/owned/preparation.rs:537` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.lab_writers | `Vec<LabWriter>` | `crates/vprouter-launch/src/owned/preparation.rs:539` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.lab_hold | `Option<&'static str>` | `crates/vprouter-launch/src/owned/preparation.rs:541` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Continuation (struct) | declaration | `crates/vprouter-launch/src/owned/preparation.rs:545` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Continuation.quarantine_origin | `Option<quarantine::ProgressOrigin>` | `crates/vprouter-launch/src/owned/preparation.rs:546` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Continuation.before | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation.rs:547` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Continuation.proposed | `Record` | `crates/vprouter-launch/src/owned/preparation.rs:548` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Continuation.started_at | `f64` | `crates/vprouter-launch/src/owned/preparation.rs:549` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Continuation.phase | `&'static str` | `crates/vprouter-launch/src/owned/preparation.rs:550` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Continuation.publication | `Option<Rc<kernel::namespace_attachment::Mounted>>` | `crates/vprouter-launch/src/owned/preparation.rs:551` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Continuation.transport_publication | `Option<Rc<kernel::fresh_transport_mount::Mounted>>` | `crates/vprouter-launch/src/owned/preparation.rs:552` | NATIVE_ONLY; no JSON mutation can exercise this field |
| LabWriter (struct) | declaration | `crates/vprouter-launch/src/owned/preparation.rs:555` | NATIVE_ONLY; no JSON mutation can exercise this field |
| LabWriter.phase | `&'static str` | `crates/vprouter-launch/src/owned/preparation.rs:556` | NATIVE_ONLY; no JSON mutation can exercise this field |
| LabWriter.queued_at | `f64` | `crates/vprouter-launch/src/owned/preparation.rs:557` | NATIVE_ONLY; no JSON mutation can exercise this field |
| LabWriter.io_deadline | `f64` | `crates/vprouter-launch/src/owned/preparation.rs:558` | NATIVE_ONLY; no JSON mutation can exercise this field |
| LabWriter.parent_deadline | `f64` | `crates/vprouter-launch/src/owned/preparation.rs:559` | NATIVE_ONLY; no JSON mutation can exercise this field |
| LabWriter.original | `kernel::Survivor` | `crates/vprouter-launch/src/owned/preparation.rs:560` | NATIVE_ONLY; no JSON mutation can exercise this field |
| LabWriter.verified_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation.rs:561` | NATIVE_ONLY; no JSON mutation can exercise this field |
| PublicBinding (struct) | declaration | `crates/vprouter-launch/src/owned/preparation.rs:1675` | NATIVE_ONLY; no JSON mutation can exercise this field |
| PublicBinding.creator | `u32` | `crates/vprouter-launch/src/owned/preparation.rs:1676` | NATIVE_ONLY; no JSON mutation can exercise this field |
| PublicBinding.shared | `Rc<SharedJournal>` | `crates/vprouter-launch/src/owned/preparation.rs:1677` | NATIVE_ONLY; no JSON mutation can exercise this field |
| PublicBinding.member | `String` | `crates/vprouter-launch/src/owned/preparation.rs:1678` | NATIVE_ONLY; no JSON mutation can exercise this field |
| PublicBinding.result | `PublicValidation` | `crates/vprouter-launch/src/owned/preparation.rs:1679` | NATIVE_ONLY; no JSON mutation can exercise this field |
| PublicBinding.owner | `OwnerDomainRecord` | `crates/vprouter-launch/src/owned/preparation.rs:1680` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Registry (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/assembly.rs:12` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Registry.creator | `u32` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:13` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Registry.owners | `Vec<Rc<ReservationState>>` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:14` | NATIVE_ONLY; no JSON mutation can exercise this field |
| ReservationState (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/assembly.rs:17` | NATIVE_ONLY; no JSON mutation can exercise this field |
| ReservationState.creator | `u32` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:18` | NATIVE_ONLY; no JSON mutation can exercise this field |
| ReservationState.shared | `Rc<SharedJournal>` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:19` | NATIVE_ONLY; no JSON mutation can exercise this field |
| ReservationState.member | `String` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:20` | NATIVE_ONLY; no JSON mutation can exercise this field |
| ReservationState.epoch | `OwnerDomainRecord` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:21` | NATIVE_ONLY; no JSON mutation can exercise this field |
| ReservationState.jobs | `Vec<kernel::NativeJobDrain>` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:22` | NATIVE_ONLY; no JSON mutation can exercise this field |
| ReservationState.complete | `Cell<bool>` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:23` | NATIVE_ONLY; no JSON mutation can exercise this field |
| ReservationState.operational | `RefCell<Option<Rc<OperationalState>>>` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:24` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Reservation (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/assembly.rs:28` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Reservation.state | `Rc<ReservationState>` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:29` | NATIVE_ONLY; no JSON mutation can exercise this field |
| OperationalState (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/assembly.rs:286` | NATIVE_ONLY; no JSON mutation can exercise this field |
| OperationalState.parent | `std::rc::Weak<ReservationState>` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:287` | NATIVE_ONLY; no JSON mutation can exercise this field |
| OperationalState.jobs | `Vec<kernel::NativeJobDrain>` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:288` | NATIVE_ONLY; no JSON mutation can exercise this field |
| OperationalState.complete | `Cell<bool>` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:289` | NATIVE_ONLY; no JSON mutation can exercise this field |
| OperationalState.failed | `Cell<bool>` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:290` | NATIVE_ONLY; no JSON mutation can exercise this field |
| OperationalReservation (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/assembly.rs:292` | NATIVE_ONLY; no JSON mutation can exercise this field |
| OperationalReservation.state | `Rc<OperationalState>` | `crates/vprouter-launch/src/owned/preparation/assembly.rs:293` | NATIVE_ONLY; no JSON mutation can exercise this field |
| PublicResult (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:8` | BootstrapResult; S/R above |
| PublicResult.namespace | `Identity` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:9` | BootstrapResult; S/R above |
| PublicResult.group | `Identity` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:10` | BootstrapResult; S/R above |
| PublicResult.policy | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:11` | BootstrapResult; S/R above |
| PublicResult.pins | `[(u64, u64, u32); 8]` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:12` | BootstrapResult; S/R above |
| PublicResult.observed_at | `f64` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:13` | BootstrapResult; S/R above |
| History (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:17` | BootstrapHistory; S/R above |
| History.request | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:18` | BootstrapHistory; S/R above |
| History.scope | `Scope` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:19` | BootstrapHistory; S/R above |
| History.namespace | `Identity` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:20` | BootstrapHistory; S/R above |
| History.creation | `producer_creation::History` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:21` | BootstrapHistory; S/R above |
| History.group | `Identity` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:22` | BootstrapHistory; S/R above |
| History.query | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:23` | BootstrapHistory; S/R above |
| History.requested_at | `f64` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:24` | BootstrapHistory; S/R above |
| History.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:25` | BootstrapHistory; S/R above |
| History.policy | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:26` | BootstrapHistory; S/R above |
| History.pins | `[(u64, u64, u32); 8]` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:27` | BootstrapHistory; S/R above |
| History.birth | `Option<ValidationBirth>` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:28` | BootstrapHistory; S/R above |
| History.result | `Option<PublicResult>` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:29` | BootstrapHistory; S/R above |
| History.verified_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:30` | BootstrapHistory; S/R above |
| Stage (enum) | declaration | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:184` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Stage::Intent | `Intent` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:185` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Stage::Birth | `Birth` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:186` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Stage::Result | `Result` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:187` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:203` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.creator | `u32` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:204` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.shared | `Rc<SharedJournal>` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:205` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.member | `String` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:206` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.history | `History` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:207` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.index | `usize` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:208` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.owner | `Rc<OwnerDomain>` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:209` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.domains | `Domains` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:210` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.lease | `MutatorLease` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:211` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:337` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.creator | `u32` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:338` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.shared | `Rc<SharedJournal>` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:339` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.member | `String` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:340` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.history | `History` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:341` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.index | `usize` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:342` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Receipt (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:609` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Receipt.creator | `u32` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:610` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Receipt.shared | `Rc<SharedJournal>` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:611` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Receipt.member | `String` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:612` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Receipt.history | `History` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:613` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Receipt.index | `usize` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:614` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Progress (enum) | declaration | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:651` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Progress::Intent | `Intent` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:652` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Progress::Birth | `Birth(&'a kernel::bootstrap::Child)` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:653` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Progress::Result | `Result(&'a kernel::bootstrap::Verified)` | `crates/vprouter-launch/src/owned/preparation/bootstrap.rs:654` | NATIVE_ONLY; no JSON mutation can exercise this field |
| History (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:7` | MountHistory; S/R above |
| History.request | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:8` | MountHistory; S/R above |
| History.source | `Identity` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:9` | MountHistory; S/R above |
| History.directory | `Identity` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:10` | MountHistory; S/R above |
| History.name | `String` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:11` | MountHistory; S/R above |
| History.requested_at | `f64` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:12` | MountHistory; S/R above |
| History.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:13` | MountHistory; S/R above |
| History.birth | `Option<ValidationBirth>` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:14` | MountHistory; S/R above |
| History.placeholder | `Option<Placeholder>` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:15` | MountHistory; S/R above |
| History.mounted_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:16` | MountHistory; S/R above |
| History.published_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:17` | MountHistory; S/R above |
| Intent (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:74` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.creator | `u32` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:75` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.shared | `Rc<SharedJournal>` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:76` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.member | `String` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:77` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.history | `History` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:78` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.owner | `Rc<OwnerDomain>` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:79` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.domains | `Domains` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:80` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.lease | `MutatorLease` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:81` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:156` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.creator | `u32` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:157` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.shared | `Rc<SharedJournal>` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:158` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.member | `String` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:159` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.history | `History` | `crates/vprouter-launch/src/owned/preparation/fresh_mount.rs:160` | NATIVE_ONLY; no JSON mutation can exercise this field |
| History (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:7` | FreshTransport; S/R above |
| History.request | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:8` | FreshTransport; S/R above |
| History.directory | `Identity` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:9` | FreshTransport; S/R above |
| History.name | `String` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:10` | FreshTransport; S/R above |
| History.host | `Identity` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:11` | FreshTransport; S/R above |
| History.data | `Identity` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:12` | FreshTransport; S/R above |
| History.requested_at | `f64` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:13` | FreshTransport; S/R above |
| History.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:14` | FreshTransport; S/R above |
| History.birth | `Option<ValidationBirth>` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:15` | FreshTransport; S/R above |
| History.source | `Option<Identity>` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:16` | FreshTransport; S/R above |
| History.verified_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:17` | FreshTransport; S/R above |
| History.mount | `Option<fresh_mount::History>` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:19` | FreshTransport; S/R above |
| Intent (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:71` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.creator | `u32` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:72` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.shared | `Rc<SharedJournal>` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:73` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.member | `String` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:74` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.history | `History` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:75` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.owner | `Rc<OwnerDomain>` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:76` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.domains | `Domains` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:77` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.lease | `MutatorLease` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:78` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:150` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.creator | `u32` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:151` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.shared | `Rc<SharedJournal>` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:152` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.member | `String` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:153` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.history | `History` | `crates/vprouter-launch/src/owned/preparation/fresh_transport.rs:154` | NATIVE_ONLY; no JSON mutation can exercise this field |
| History (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/host_link.rs:8` | HostLinkHistory; S/R above |
| History.kind | `Kind` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:9` | HostLinkHistory; S/R above |
| History.request | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:10` | HostLinkHistory; S/R above |
| History.namespace | `Identity` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:11` | HostLinkHistory; S/R above |
| History.host | `Identity` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:12` | HostLinkHistory; S/R above |
| History.declaration | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:13` | HostLinkHistory; S/R above |
| History.admission | `[f64; 3]` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:14` | HostLinkHistory; S/R above |
| History.requested_at | `f64` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:15` | HostLinkHistory; S/R above |
| History.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:16` | HostLinkHistory; S/R above |
| History.addition | `Option<([u8; 32], u32)>` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:17` | HostLinkHistory; S/R above |
| History.birth | `Option<ValidationBirth>` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:18` | HostLinkHistory; S/R above |
| History.result | `Option<PublicResult>` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:19` | HostLinkHistory; S/R above |
| History.verified_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:20` | HostLinkHistory; S/R above |
| Intent (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/host_link.rs:200` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.creator | `u32` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:201` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.shared | `Rc<SharedJournal>` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:202` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.member | `String` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:203` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.history | `History` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:204` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.index | `usize` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:205` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.owner | `Rc<OwnerDomain>` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:206` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.domains | `Domains` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:207` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.lease | `MutatorLease` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:208` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/host_link.rs:280` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.creator | `u32` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:281` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.shared | `Rc<SharedJournal>` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:282` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.member | `String` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:283` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.history | `History` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:284` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.index | `usize` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:285` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Receipt (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/host_link.rs:323` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Receipt.gate | `Gate` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:324` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Progress (enum) | declaration | `crates/vprouter-launch/src/owned/preparation/host_link.rs:576` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Progress::Intent | `Intent` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:577` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Progress::Birth | `Birth(&'a Child)` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:578` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Progress::Result | `Result(&'a Verified)` | `crates/vprouter-launch/src/owned/preparation/host_link.rs:579` | NATIVE_ONLY; no JSON mutation can exercise this field |
| History (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/inspection.rs:8` | InspectionHistory; S/R above |
| History.kind | `QueryKind` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:9` | InspectionHistory; S/R above |
| History.initial | `Option<Initial>` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:10` | InspectionHistory; S/R above |
| History.request | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:11` | InspectionHistory; S/R above |
| History.requested_at | `f64` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:12` | InspectionHistory; S/R above |
| History.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:13` | InspectionHistory; S/R above |
| History.birth | `Option<ValidationBirth>` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:14` | InspectionHistory; S/R above |
| History.facts | `Option<QueryFacts>` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:15` | InspectionHistory; S/R above |
| History.verified_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:16` | InspectionHistory; S/R above |
| Initial (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/inspection.rs:20` | InspectionInitial; S/R above |
| Initial.request | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:21` | InspectionInitial; S/R above |
| Initial.birth | `ValidationBirth` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:22` | InspectionInitial; S/R above |
| Initial.facts | `QueryFacts` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:23` | InspectionInitial; S/R above |
| Initial.verified_at | `f64` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:24` | InspectionInitial; S/R above |
| Intent (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/inspection.rs:362` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.creator | `u32` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:363` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.shared | `Rc<SharedJournal>` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:364` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.member | `String` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:365` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.owner | `Rc<OwnerDomain>` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:366` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.domains | `Domains` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:367` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.history | `History` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:368` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.lease | `MutatorLease` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:369` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/inspection.rs:437` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.creator | `u32` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:438` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.shared | `Rc<SharedJournal>` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:439` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.member | `String` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:440` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.birth | `ValidationBirth` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:441` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.request | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:442` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Receipt (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/inspection.rs:475` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Receipt.creator | `u32` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:476` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Receipt.shared | `Rc<SharedJournal>` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:477` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Receipt.member | `String` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:478` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Receipt.history | `History` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:479` | NATIVE_ONLY; no JSON mutation can exercise this field |
| QuarantineProgress (enum) | declaration | `crates/vprouter-launch/src/owned/preparation/inspection.rs:991` | NATIVE_ONLY; no JSON mutation can exercise this field |
| QuarantineProgress::Intent | `Intent` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:992` | NATIVE_ONLY; no JSON mutation can exercise this field |
| QuarantineProgress::Birth | `Birth(&'a kernel::docker_query::Child)` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:993` | NATIVE_ONLY; no JSON mutation can exercise this field |
| QuarantineProgress::Result | `Result(&'a kernel::docker_query::Verified)` | `crates/vprouter-launch/src/owned/preparation/inspection.rs:994` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Family (enum) | declaration | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:5` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Family::Query | `Query` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:6` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Family::Policy | `Policy` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:7` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Family::Other | `Other` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:8` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Key (enum) | declaration | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:22` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Key::AllocationMemory | `AllocationMemory` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:23` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Key::BindingServiceCustody | `BindingServiceCustody` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:24` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Key::BindingRetained | `BindingRetained` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:25` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Key::OwnedProgress | `OwnedProgress` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:26` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Key::TypedBootstrapProgress | `TypedBootstrapProgress` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:27` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Key::OriginalProof | `OriginalProof` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:28` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Key::RecordEncode | `RecordEncode` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:29` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Key::ExpectedRecordEncode | `ExpectedRecordEncode` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:30` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Key::RecordSha256 | `RecordSha256` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:31` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Key::JournalAdvance | `JournalAdvance` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:32` | NATIVE_ONLY; no JSON mutation can exercise this field |
| RetainedKey (enum) | declaration | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:64` | NATIVE_ONLY; no JSON mutation can exercise this field |
| RetainedKey::RetainedTransport | `RetainedTransport` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:65` | NATIVE_ONLY; no JSON mutation can exercise this field |
| RetainedKey::RetainedData | `RetainedData` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:66` | NATIVE_ONLY; no JSON mutation can exercise this field |
| RetainedKey::RetainedOwnerRecord | `RetainedOwnerRecord` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:67` | NATIVE_ONLY; no JSON mutation can exercise this field |
| RetainedKey::RetainedHistory | `RetainedHistory` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:68` | NATIVE_ONLY; no JSON mutation can exercise this field |
| RetainedKey::HistoryAllocationDigest | `HistoryAllocationDigest` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:69` | NATIVE_ONLY; no JSON mutation can exercise this field |
| RetainedKey::CreatedGroupNative | `CreatedGroupNative` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:70` | NATIVE_ONLY; no JSON mutation can exercise this field |
| RetainedKey::SourceIdentityEntries | `SourceIdentityEntries` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:71` | NATIVE_ONLY; no JSON mutation can exercise this field |
| RetainedKey::NativeSourceEntries | `NativeSourceEntries` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:72` | NATIVE_ONLY; no JSON mutation can exercise this field |
| OwnerKey (enum) | declaration | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:106` | NATIVE_ONLY; no JSON mutation can exercise this field |
| OwnerKey::HostPreflight | `HostPreflight` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:107` | NATIVE_ONLY; no JSON mutation can exercise this field |
| OwnerKey::RecordValidate | `RecordValidate` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:108` | NATIVE_ONLY; no JSON mutation can exercise this field |
| OwnerKey::NamespaceIdentities | `NamespaceIdentities` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:109` | NATIVE_ONLY; no JSON mutation can exercise this field |
| OwnerKey::CurrentIdentityChain | `CurrentIdentityChain` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:110` | NATIVE_ONLY; no JSON mutation can exercise this field |
| OwnerKey::RecordClone | `RecordClone` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:111` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Total (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:133` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Total.calls | `u64` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:134` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Total.elapsed_ns | `u128` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:135` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Token (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:146` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Token.creator | `u32` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:147` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Token.epoch | `u64` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:148` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Token.family | `Family` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:149` | NATIVE_ONLY; no JSON mutation can exercise this field |
| State (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:152` | NATIVE_ONLY; no JSON mutation can exercise this field |
| State.creator | `u32` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:153` | NATIVE_ONLY; no JSON mutation can exercise this field |
| State.epoch | `u64` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:154` | NATIVE_ONLY; no JSON mutation can exercise this field |
| State.active | `bool` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:155` | NATIVE_ONLY; no JSON mutation can exercise this field |
| State.family | `Family` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:156` | NATIVE_ONLY; no JSON mutation can exercise this field |
| State.totals | `[Total; ROWS]` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:157` | NATIVE_ONLY; no JSON mutation can exercise this field |
| RetainedTotals (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:210` | NATIVE_ONLY; no JSON mutation can exercise this field |
| RetainedTotals.rows | `[Cell<Total>; RETAINED_ROWS]` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:211` | NATIVE_ONLY; no JSON mutation can exercise this field |
| OwnerTotals (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:242` | NATIVE_ONLY; no JSON mutation can exercise this field |
| OwnerTotals.rows | `[Cell<Total>; OWNER_ROWS]` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:243` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Session (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:277` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Session.token | `Option<Token>` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:278` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Session._thread | `PhantomData<Rc<()>>` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:279` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Timer (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:321` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Timer.entry | `Option<(Token, Key, Instant)>` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:322` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Timer._thread | `PhantomData<Rc<()>>` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:323` | NATIVE_ONLY; no JSON mutation can exercise this field |
| RetainedTimer (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:350` | NATIVE_ONLY; no JSON mutation can exercise this field |
| RetainedTimer.entry | `Option<(Token, RetainedKey, Instant)>` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:351` | NATIVE_ONLY; no JSON mutation can exercise this field |
| RetainedTimer._thread | `PhantomData<Rc<()>>` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:352` | NATIVE_ONLY; no JSON mutation can exercise this field |
| OwnerTimer (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:383` | NATIVE_ONLY; no JSON mutation can exercise this field |
| OwnerTimer.entry | `Option<(Token, OwnerKey, Instant)>` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:384` | NATIVE_ONLY; no JSON mutation can exercise this field |
| OwnerTimer._thread | `PhantomData<Rc<()>>` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:385` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Snapshot (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:425` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Snapshot.totals | `[Total; ROWS]` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:426` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Snapshot.retained_totals | `[Total; RETAINED_ROWS]` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:427` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Snapshot.owner_totals | `[Total; OWNER_ROWS]` | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:428` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Fails (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/lab_cost.rs:750` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Placeholder (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/mount.rs:7` | Placeholder; S/R above |
| Placeholder.identity | `Identity` | `crates/vprouter-launch/src/owned/preparation/mount.rs:8` | Placeholder; S/R above |
| Placeholder.mode | `u32` | `crates/vprouter-launch/src/owned/preparation/mount.rs:9` | Placeholder; S/R above |
| History (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/mount.rs:13` | Attachment; S/R above |
| History.request | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/mount.rs:14` | Attachment; S/R above |
| History.origin | `Origin` | `crates/vprouter-launch/src/owned/preparation/mount.rs:15` | Attachment; S/R above |
| History.directory | `Identity` | `crates/vprouter-launch/src/owned/preparation/mount.rs:16` | Attachment; S/R above |
| History.name | `String` | `crates/vprouter-launch/src/owned/preparation/mount.rs:17` | Attachment; S/R above |
| History.source | `Identity` | `crates/vprouter-launch/src/owned/preparation/mount.rs:18` | Attachment; S/R above |
| History.requested_at | `f64` | `crates/vprouter-launch/src/owned/preparation/mount.rs:19` | Attachment; S/R above |
| History.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation/mount.rs:20` | Attachment; S/R above |
| History.birth | `Option<ValidationBirth>` | `crates/vprouter-launch/src/owned/preparation/mount.rs:21` | Attachment; S/R above |
| History.placeholder | `Option<Placeholder>` | `crates/vprouter-launch/src/owned/preparation/mount.rs:22` | Attachment; S/R above |
| History.mounted_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/mount.rs:23` | Attachment; S/R above |
| History.query | `Option<inspection::History>` | `crates/vprouter-launch/src/owned/preparation/mount.rs:24` | Attachment; S/R above |
| History.published_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/mount.rs:25` | Attachment; S/R above |
| Intent (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/mount.rs:113` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.creator | `u32` | `crates/vprouter-launch/src/owned/preparation/mount.rs:114` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.shared | `Rc<SharedJournal>` | `crates/vprouter-launch/src/owned/preparation/mount.rs:115` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.member | `String` | `crates/vprouter-launch/src/owned/preparation/mount.rs:116` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.history | `History` | `crates/vprouter-launch/src/owned/preparation/mount.rs:117` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.owner | `Rc<OwnerDomain>` | `crates/vprouter-launch/src/owned/preparation/mount.rs:118` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.domains | `Domains` | `crates/vprouter-launch/src/owned/preparation/mount.rs:119` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.lease | `MutatorLease` | `crates/vprouter-launch/src/owned/preparation/mount.rs:120` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/mount.rs:214` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.creator | `u32` | `crates/vprouter-launch/src/owned/preparation/mount.rs:215` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.shared | `Rc<SharedJournal>` | `crates/vprouter-launch/src/owned/preparation/mount.rs:216` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.member | `String` | `crates/vprouter-launch/src/owned/preparation/mount.rs:217` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.history | `History` | `crates/vprouter-launch/src/owned/preparation/mount.rs:218` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Binding (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/movement.rs:6` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Binding.public | `PublicBinding` | `crates/vprouter-launch/src/owned/preparation/movement.rs:7` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Binding.transport | `Rc<kernel::fresh_transport_mount::Mounted>` | `crates/vprouter-launch/src/owned/preparation/movement.rs:8` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Binding.operations | `Vec<wireguard::History>` | `crates/vprouter-launch/src/owned/preparation/movement.rs:9` | NATIVE_ONLY; no JSON mutation can exercise this field |
| PublicResult (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:7` | ProducerBindingResult; S/R above |
| PublicResult.namespace | `Identity` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:8` | ProducerBindingResult; S/R above |
| PublicResult.group | `Identity` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:9` | ProducerBindingResult; S/R above |
| PublicResult.policy | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:10` | ProducerBindingResult; S/R above |
| PublicResult.pins | `[(u64, u64, u32); 6]` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:11` | ProducerBindingResult; S/R above |
| PublicResult.observed_at | `f64` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:12` | ProducerBindingResult; S/R above |
| History (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:16` | ProducerBindingHistory; S/R above |
| History.request | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:17` | ProducerBindingHistory; S/R above |
| History.parent | `Identity` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:18` | ProducerBindingHistory; S/R above |
| History.name | `String` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:19` | ProducerBindingHistory; S/R above |
| History.data | `Identity` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:20` | ProducerBindingHistory; S/R above |
| History.query | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:21` | ProducerBindingHistory; S/R above |
| History.requested_at | `f64` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:22` | ProducerBindingHistory; S/R above |
| History.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:23` | ProducerBindingHistory; S/R above |
| History.birth | `Option<ValidationBirth>` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:24` | ProducerBindingHistory; S/R above |
| History.group | `Identity` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:25` | ProducerBindingHistory; S/R above |
| History.creation | `producer_creation::History` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:26` | ProducerBindingHistory; S/R above |
| History.policy | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:27` | ProducerBindingHistory; S/R above |
| History.pins | `[(u64, u64, u32); 6]` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:28` | ProducerBindingHistory; S/R above |
| History.result | `Option<PublicResult>` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:29` | ProducerBindingHistory; S/R above |
| History.verified_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:30` | ProducerBindingHistory; S/R above |
| Intent (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:200` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.creator | `u32` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:201` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.shared | `Rc<SharedJournal>` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:202` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.member | `String` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:203` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.history | `History` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:204` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.owner | `Rc<OwnerDomain>` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:205` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.domains | `Domains` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:206` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.lease | `MutatorLease` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:207` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:320` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.creator | `u32` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:321` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.shared | `Rc<SharedJournal>` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:322` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.member | `String` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:323` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.history | `History` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:324` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Receipt (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:574` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Receipt.creator | `u32` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:575` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Receipt.shared | `Rc<SharedJournal>` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:576` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Receipt.member | `String` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:577` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Receipt.history | `History` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:578` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Progress (enum) | declaration | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:615` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Progress::Intent | `Intent` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:616` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Progress::Birth | `Birth(&'a kernel::producer_binding::Child)` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:617` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Progress::Result | `Result(&'a kernel::producer_binding::Verified)` | `crates/vprouter-launch/src/owned/preparation/producer_binding.rs:618` | NATIVE_ONLY; no JSON mutation can exercise this field |
| History (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:7` | ProducerCreationHistory; S/R above |
| History.request | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:8` | ProducerCreationHistory; S/R above |
| History.parent | `Identity` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:9` | ProducerCreationHistory; S/R above |
| History.name | `String` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:10` | ProducerCreationHistory; S/R above |
| History.data | `Identity` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:11` | ProducerCreationHistory; S/R above |
| History.query | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:12` | ProducerCreationHistory; S/R above |
| History.requested_at | `f64` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:13` | ProducerCreationHistory; S/R above |
| History.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:14` | ProducerCreationHistory; S/R above |
| History.birth | `Option<ValidationBirth>` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:15` | ProducerCreationHistory; S/R above |
| History.group | `Option<Identity>` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:16` | ProducerCreationHistory; S/R above |
| History.verified_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:17` | ProducerCreationHistory; S/R above |
| Intent (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:96` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.creator | `u32` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:97` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.shared | `Rc<SharedJournal>` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:98` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.member | `String` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:99` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.history | `History` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:100` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.owner | `Rc<OwnerDomain>` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:101` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.domains | `Domains` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:102` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.lease | `MutatorLease` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:103` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:188` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.creator | `u32` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:189` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.shared | `Rc<SharedJournal>` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:190` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.member | `String` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:191` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.history | `History` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:192` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Receipt (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:418` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Receipt.creator | `u32` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:419` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Receipt.shared | `Rc<SharedJournal>` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:420` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Receipt.member | `String` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:421` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Receipt.history | `History` | `crates/vprouter-launch/src/owned/preparation/producer_creation.rs:422` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Binding (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:7` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Binding.public | `PublicBinding` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:8` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Binding.transport | `Rc<kernel::fresh_transport_mount::Mounted>` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:9` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Binding.operations | `Vec<wireguard::History>` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:10` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Binding.movement_query | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:11` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Binding.host | `Identity` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:12` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Binding.host_pin | `OwnedFd` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:13` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Binding.host_registration | `super::super::super::inventory::Registration` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:14` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Binding.configuration | `vprouter_core::config::PublicConfiguration` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:15` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Binding.configuration_digest | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:16` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Binding.owner | `Rc<OwnerDomain>` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:17` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Binding.domains | `Domains` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:18` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Operation (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:260` | NetfilterHistory; S/R above |
| Operation.kind | `Kind` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:261` | NetfilterHistory; S/R above |
| Operation.scope | `Scope` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:262` | NetfilterHistory; S/R above |
| Operation.request | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:263` | NetfilterHistory; S/R above |
| Operation.namespace | `Identity` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:264` | NetfilterHistory; S/R above |
| Operation.configuration | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:265` | NetfilterHistory; S/R above |
| Operation.host_declaration | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:266` | NetfilterHistory; S/R above |
| Operation.policy | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:267` | NetfilterHistory; S/R above |
| Operation.query | `Option<[u8; 32]>` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:268` | NetfilterHistory; S/R above |
| Operation.requested_at | `f64` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:269` | NetfilterHistory; S/R above |
| Operation.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:270` | NetfilterHistory; S/R above |
| Operation.birth | `Option<ValidationBirth>` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:271` | NetfilterHistory; S/R above |
| Operation.result | `Option<PublicResult>` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:272` | NetfilterHistory; S/R above |
| Operation.verified_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:273` | NetfilterHistory; S/R above |
| PublicResult (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:277` | NetfilterResult; S/R above |
| PublicResult.namespace | `Identity` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:278` | NetfilterResult; S/R above |
| PublicResult.policy | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:279` | NetfilterResult; S/R above |
| PublicResult.observed_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:281` | NetfilterResult; S/R above |
| Intent (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:431` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.creator | `u32` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:432` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.shared | `Rc<SharedJournal>` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:433` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.member | `String` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:434` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.history | `Operation` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:435` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.index | `usize` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:436` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.owner | `Rc<OwnerDomain>` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:437` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.domains | `Domains` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:438` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.lease | `MutatorLease` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:439` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:567` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.creator | `u32` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:568` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.shared | `Rc<SharedJournal>` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:569` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.member | `String` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:570` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.history | `Operation` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:571` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.index | `usize` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:572` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Receipt (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:610` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Receipt.creator | `u32` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:611` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Receipt.shared | `Rc<SharedJournal>` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:612` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Receipt.member | `String` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:613` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Receipt.history | `Operation` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:614` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Receipt.index | `usize` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:615` | NATIVE_ONLY; no JSON mutation can exercise this field |
| ProgressOrigin (enum) | declaration | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:967` | NATIVE_ONLY; no JSON mutation can exercise this field |
| ProgressOrigin::Bootstrap | `Bootstrap(Rc<super::super::super::attachment::operational::bootstrap::Request>)` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:968` | NATIVE_ONLY; no JSON mutation can exercise this field |
| ProgressOrigin::HostLink | `HostLink(Rc<super::super::super::attachment::host_addition::Request>)` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:969` | NATIVE_ONLY; no JSON mutation can exercise this field |
| ProgressOrigin::ProducerBinding | `ProducerBinding(Rc<super::super::super::attachment::producer_binding::Request>)` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:970` | NATIVE_ONLY; no JSON mutation can exercise this field |
| ProgressOrigin::Netfilter | `Netfilter(Rc<Request>, usize)` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:971` | NATIVE_ONLY; no JSON mutation can exercise this field |
| ProgressOrigin::Query | `Query(Rc<super::super::super::attachment::InspectionRequest>)` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:972` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Progress (enum) | declaration | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:976` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Progress::Netfilter | `Netfilter(&'a Rc<Request>, usize, NetfilterProgress<'a>)` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:977` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Progress::Query | `Query(` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:978` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Progress.inspection | `:QuarantineProgress<'a>` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:980` | NATIVE_ONLY; no JSON mutation can exercise this field |
| NetfilterProgress (enum) | declaration | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:983` | NATIVE_ONLY; no JSON mutation can exercise this field |
| NetfilterProgress::Intent | `Intent` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:984` | NATIVE_ONLY; no JSON mutation can exercise this field |
| NetfilterProgress::Birth | `Birth(&'a Child)` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:985` | NATIVE_ONLY; no JSON mutation can exercise this field |
| NetfilterProgress::Result | `Result(&'a Verified)` | `crates/vprouter-launch/src/owned/preparation/quarantine.rs:986` | NATIVE_ONLY; no JSON mutation can exercise this field |
| History (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:7` | WireguardHistory, MovementHistory; S/R above |
| History.kind | `Kind` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:8` | WireguardHistory, MovementHistory; S/R above |
| History.request | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:9` | WireguardHistory, MovementHistory; S/R above |
| History.namespace | `Identity` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:10` | WireguardHistory, MovementHistory; S/R above |
| History.configuration | `[u8; 32]` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:11` | WireguardHistory, MovementHistory; S/R above |
| History.requested_at | `f64` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:12` | WireguardHistory, MovementHistory; S/R above |
| History.deadline | `f64` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:13` | WireguardHistory, MovementHistory; S/R above |
| History.birth | `Option<ValidationBirth>` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:14` | WireguardHistory, MovementHistory; S/R above |
| History.result | `Option<PublicResult>` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:15` | WireguardHistory, MovementHistory; S/R above |
| History.verified_at | `Option<f64>` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:16` | WireguardHistory, MovementHistory; S/R above |
| History.destination | `Option<Identity>` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:18` | WireguardHistory, MovementHistory; S/R above |
| History.movement_query | `Option<[u8; 32]>` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:20` | WireguardHistory, MovementHistory; S/R above |
| Intent (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:151` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.creator | `u32` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:152` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.shared | `Rc<SharedJournal>` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:153` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.member | `String` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:154` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.history | `History` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:155` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.index | `usize` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:156` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.owner | `Rc<OwnerDomain>` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:157` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.domains | `Domains` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:158` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Intent.lease | `MutatorLease` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:159` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:275` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.creator | `u32` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:276` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.shared | `Rc<SharedJournal>` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:277` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.member | `String` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:278` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.history | `History` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:279` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Gate.index | `usize` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:280` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Receipt (struct) | declaration | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:318` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Receipt.creator | `u32` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:319` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Receipt.shared | `Rc<SharedJournal>` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:320` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Receipt.member | `String` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:321` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Receipt.history | `History` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:322` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Receipt.index | `usize` | `crates/vprouter-launch/src/owned/preparation/wireguard.rs:323` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Context (struct) | declaration | `crates/vprouter-launch/src/attachment/operational.rs:12` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Context.binding | `std::rc::Rc<super::super::owned::preparation::quarantine::Binding>` | `crates/vprouter-launch/src/attachment/operational.rs:13` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Context.source | `std::rc::Rc<super::super::kernel::producer_creation::Source>` | `crates/vprouter-launch/src/attachment/operational.rs:14` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Context.service | `&'a super::super::owned::preparation::Server` | `crates/vprouter-launch/src/attachment/operational.rs:15` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Custody (struct) | declaration | `crates/vprouter-launch/src/attachment/operational.rs:17` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Custody.binding | `std::rc::Rc<super::super::owned::preparation::quarantine::Binding>` | `crates/vprouter-launch/src/attachment/operational.rs:18` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Custody.service | `&'a super::super::owned::preparation::Server` | `crates/vprouter-launch/src/attachment/operational.rs:19` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native (struct) | declaration | `crates/vprouter-launch/src/attachment/operational.rs:21` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.creator | `u32` | `crates/vprouter-launch/src/attachment/operational.rs:22` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.original | `HostAddedPrimary` | `crates/vprouter-launch/src/attachment/operational.rs:23` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.plan | `Vec<ResourceTransfer>` | `crates/vprouter-launch/src/attachment/operational.rs:24` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.reservation | `Option<OperationalReservation>` | `crates/vprouter-launch/src/attachment/operational.rs:25` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.retired | `usize` | `crates/vprouter-launch/src/attachment/operational.rs:26` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.complete | `bool` | `crates/vprouter-launch/src/attachment/operational.rs:27` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.failure | `Option<Error>` | `crates/vprouter-launch/src/attachment/operational.rs:28` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.anchor | `std::rc::Rc<()>` | `crates/vprouter-launch/src/attachment/operational.rs:30` | NATIVE_ONLY; no JSON mutation can exercise this field |
| OperationalOwner (struct) | declaration | `crates/vprouter-launch/src/attachment/operational.rs:32` | NATIVE_ONLY; no JSON mutation can exercise this field |
| OperationalOwner.native | `Option<Box<Native>>` | `crates/vprouter-launch/src/attachment/operational.rs:33` | NATIVE_ONLY; no JSON mutation can exercise this field |
| LabHandoff (struct) | declaration | `crates/vprouter-launch/src/attachment/operational.rs:464` | NATIVE_ONLY; no JSON mutation can exercise this field |
| LabHandoff.owner | `Option<OperationalOwner>` | `crates/vprouter-launch/src/attachment/operational.rs:465` | NATIVE_ONLY; no JSON mutation can exercise this field |
| LabHandoff.host | `serde_json::Value` | `crates/vprouter-launch/src/attachment/operational.rs:466` | NATIVE_ONLY; no JSON mutation can exercise this field |
| LabHandoff.evidence | `serde_json::Value` | `crates/vprouter-launch/src/attachment/operational.rs:467` | NATIVE_ONLY; no JSON mutation can exercise this field |
| LabHandoff.original_anchors | `super::host_addition::LabAnchors` | `crates/vprouter-launch/src/attachment/operational.rs:468` | NATIVE_ONLY; no JSON mutation can exercise this field |
| LabHandoff.anchor | `std::rc::Weak<()>` | `crates/vprouter-launch/src/attachment/operational.rs:469` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Request (struct) | declaration | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:15` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Request.creator | `u32` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:16` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Request.binding | `Rc<Binding>` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:17` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Request.source | `Rc<kernel::producer_creation::Source>` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:18` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Request.query | `Rc<kernel::docker_query::Accepted>` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:19` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Request.pins | `Pins` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:20` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Request.identities | `[(u64, u64, u32); 8]` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:21` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Request.group | `Identity` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:22` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Request.namespace | `Identity` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:23` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Request.scope | `Scope` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:24` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Request.policy | `[u8; 32]` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:25` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Request.digest | `[u8; 32]` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:26` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Step (enum) | declaration | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:241` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Step::QueryIntent | `QueryIntent` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:242` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Step::QueryBirth | `QueryBirth` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:243` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Step::QueryReading | `QueryReading` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:244` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Step::QueryResult | `QueryResult` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:245` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Step::Intent | `Intent` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:246` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Step::Birth | `Birth` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:247` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Step::Reading | `Reading` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:248` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Step::Result | `Result` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:249` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Step::Next | `Next` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:250` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Step::Complete | `Complete` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:251` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native (struct) | declaration | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:253` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.creator | `u32` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:254` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.input | `OperationalOwner` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:255` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.binding | `Rc<Binding>` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:256` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.query | `Rc<InspectionRequest>` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:257` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.completed | `Vec<(         Rc<kernel::docker_query::Accepted>,         kernel::bootstrap::Verified,     )>` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:258` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.kernel | `:bootstrap::Verified` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:260` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.query_child | `Option<kernel::docker_query::Child>` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:262` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.query_verified | `Option<kernel::docker_query::Verified>` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:263` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.query_accepted | `Option<Rc<kernel::docker_query::Accepted>>` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:264` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.request | `Option<Rc<Request>>` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:265` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.child | `Option<kernel::bootstrap::Child>` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:266` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.verified | `Option<kernel::bootstrap::Verified>` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:267` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.step | `Step` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:268` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.failure | `Option<Error>` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:269` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.anchor | `Rc<()>` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:271` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.final_verified_at | `Option<f64>` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:273` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.process_verified_at | `Vec<f64>` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:275` | NATIVE_ONLY; no JSON mutation can exercise this field |
| PendingBootstrap (struct) | declaration | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:277` | NATIVE_ONLY; no JSON mutation can exercise this field |
| PendingBootstrap.native | `Option<Box<Native>>` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:278` | NATIVE_ONLY; no JSON mutation can exercise this field |
| BootstrappedOwner (struct) | declaration | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:280` | NATIVE_ONLY; no JSON mutation can exercise this field |
| BootstrappedOwner.native | `Option<Box<Native>>` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:281` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Helper (enum) | declaration | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1300` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Cpu (struct) | declaration | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1381` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Cpu.calls | `u64` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1382` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Cpu.samples | `u64` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1383` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Cpu.cpu_ns | `u128` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1384` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Cpu.sample_errors | `u64` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1385` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Driver (struct) | declaration | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1387` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Driver.cpu | `[Cpu; 13]` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1388` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Driver.sleep_calls | `u64` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1389` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Driver.sleep_requested | `u128` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1390` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Driver.sleep_elapsed | `u128` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1391` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Driver.constructor_attempted | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1392` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Driver.constructor_elapsed | `Option<u128>` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1393` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Driver.creator | `u32` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1394` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Driver.stopped | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1395` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Driver.exportable | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1396` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Driver._local | `std::marker::PhantomData<std::rc::Rc<()>>` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1398` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Counters (struct) | declaration | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1483` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Counters.query_queued | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1484` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Counters.query_held | `usize` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1485` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Counters.query_negatives | `usize` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1486` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Counters.query_released | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1487` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Counters.own_queued | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1488` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Counters.own_held | `usize` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1489` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Counters.own_negatives | `usize` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1490` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Counters.own_released | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1491` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Measurements (struct) | declaration | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1493` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Measurements.totals | `[(u64, Duration); HELPERS.len()]` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1494` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Measurements.emitted | `bool` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1495` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Measurements.driver | `Driver` | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1496` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Broken (struct) | declaration | `crates/vprouter-launch/src/attachment/operational/bootstrap.rs:1735` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Pins (struct) | declaration | `crates/vprouter-launch/src/attachment/operational/producer.rs:11` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Pins.creator | `u32` | `crates/vprouter-launch/src/attachment/operational/producer.rs:12` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Pins.source | `Rc<kernel::producer_creation::Source>` | `crates/vprouter-launch/src/attachment/operational/producer.rs:13` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Pins.started | `f64` | `crates/vprouter-launch/src/attachment/operational/producer.rs:14` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Pins.fds | `Vec<OwnedFd>` | `crates/vprouter-launch/src/attachment/operational/producer.rs:15` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Pins.tokens | `Vec<inventory::Registration>` | `crates/vprouter-launch/src/attachment/operational/producer.rs:16` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Pins.identities | `Vec<(u64, u64, u32)>` | `crates/vprouter-launch/src/attachment/operational/producer.rs:17` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Generation (struct) | declaration | `crates/vprouter-launch/src/attachment/host_addition.rs:16` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Generation.creator | `u32` | `crates/vprouter-launch/src/attachment/host_addition.rs:17` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Generation.declaration | `Rc<PinnedBaseline>` | `crates/vprouter-launch/src/attachment/host_addition.rs:18` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Generation.admission | `vprouter_network::PendingHostAdmission` | `crates/vprouter-launch/src/attachment/host_addition.rs:19` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Generation.observer_token | `inventory::Registration` | `crates/vprouter-launch/src/attachment/host_addition.rs:20` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Generation.authority | `vprouter_network::HostAuthority` | `crates/vprouter-launch/src/attachment/host_addition.rs:21` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Generation.allocation | `vprouter_core::allocation::AllocationRecord` | `crates/vprouter-launch/src/attachment/host_addition.rs:22` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Generation.host | `super::Identity` | `crates/vprouter-launch/src/attachment/host_addition.rs:23` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Generation.requested_at | `f64` | `crates/vprouter-launch/src/attachment/host_addition.rs:24` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Generation.accepted_at | `f64` | `crates/vprouter-launch/src/attachment/host_addition.rs:25` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native (struct) | declaration | `crates/vprouter-launch/src/attachment/host_addition.rs:53` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.anchor | `Rc<()>` | `crates/vprouter-launch/src/attachment/host_addition.rs:55` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.creator | `u32` | `crates/vprouter-launch/src/attachment/host_addition.rs:56` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.input | `ProducerBoundAssembly` | `crates/vprouter-launch/src/attachment/host_addition.rs:57` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.binding | `Rc<Binding>` | `crates/vprouter-launch/src/attachment/host_addition.rs:58` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.plan | `vprouter_network::Plan` | `crates/vprouter-launch/src/attachment/host_addition.rs:59` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.generation | `Option<Rc<Generation>>` | `crates/vprouter-launch/src/attachment/host_addition.rs:60` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.declaration | `Option<Rc<PinnedBaseline>>` | `crates/vprouter-launch/src/attachment/host_addition.rs:61` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.observer | `Option<vprouter_network::RouteObserver>` | `crates/vprouter-launch/src/attachment/host_addition.rs:62` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.observer_token | `Option<inventory::Registration>` | `crates/vprouter-launch/src/attachment/host_addition.rs:63` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.admission | `Option<vprouter_network::PendingHostAdmission>` | `crates/vprouter-launch/src/attachment/host_addition.rs:64` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.authority | `Option<vprouter_network::HostAuthority>` | `crates/vprouter-launch/src/attachment/host_addition.rs:65` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.requested_at | `f64` | `crates/vprouter-launch/src/attachment/host_addition.rs:66` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.accepted_at | `Option<f64>` | `crates/vprouter-launch/src/attachment/host_addition.rs:67` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Native.failure | `Option<Error>` | `crates/vprouter-launch/src/attachment/host_addition.rs:68` | NATIVE_ONLY; no JSON mutation can exercise this field |
| PendingHostBaseline (struct) | declaration | `crates/vprouter-launch/src/attachment/host_addition.rs:70` | NATIVE_ONLY; no JSON mutation can exercise this field |
| PendingHostBaseline.native | `Option<Box<Native>>` | `crates/vprouter-launch/src/attachment/host_addition.rs:71` | NATIVE_ONLY; no JSON mutation can exercise this field |
| ObservedHostAssembly (struct) | declaration | `crates/vprouter-launch/src/attachment/host_addition.rs:75` | NATIVE_ONLY; no JSON mutation can exercise this field |
| ObservedHostAssembly.native | `Option<Box<Native>>` | `crates/vprouter-launch/src/attachment/host_addition.rs:76` | NATIVE_ONLY; no JSON mutation can exercise this field |
| PendingHostAddition (struct) | declaration | `crates/vprouter-launch/src/attachment/host_addition.rs:322` | NATIVE_ONLY; no JSON mutation can exercise this field |
| PendingHostAddition.baseline | `Option<PendingHostBaseline>` | `crates/vprouter-launch/src/attachment/host_addition.rs:323` | NATIVE_ONLY; no JSON mutation can exercise this field |
| PendingHostAddition.observed | `Option<ObservedHostAssembly>` | `crates/vprouter-launch/src/attachment/host_addition.rs:324` | NATIVE_ONLY; no JSON mutation can exercise this field |
| PendingHostAddition.links | `Option<operation::PendingHostLinks>` | `crates/vprouter-launch/src/attachment/host_addition.rs:325` | NATIVE_ONLY; no JSON mutation can exercise this field |
| PendingHostAddition.failure | `Option<Error>` | `crates/vprouter-launch/src/attachment/host_addition.rs:326` | NATIVE_ONLY; no JSON mutation can exercise this field |
| PendingHostAddition.complete | `bool` | `crates/vprouter-launch/src/attachment/host_addition.rs:327` | NATIVE_ONLY; no JSON mutation can exercise this field |
| HostAddedPrimary (struct) | declaration | `crates/vprouter-launch/src/attachment/host_addition.rs:329` | NATIVE_ONLY; no JSON mutation can exercise this field |
| HostAddedPrimary.original | `operation::HostLinkedAssembly` | `crates/vprouter-launch/src/attachment/host_addition.rs:330` | NATIVE_ONLY; no JSON mutation can exercise this field |
| LabAnchors (struct) | declaration | `crates/vprouter-launch/src/attachment/host_addition.rs:451` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Kind (enum) | declaration | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:14` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Kind::TransportSockets | `TransportSockets` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:15` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Kind::Pair | `Pair` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:16` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Kind::HostSockets | `HostSockets` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:17` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Kind::Move | `Move` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:18` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Request (struct) | declaration | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:31` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Request.creator | `u32` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:32` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Request.binding | `Rc<Binding>` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:33` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Request.generation | `Rc<Generation>` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:34` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Request.plan | `vprouter_network::Plan` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:35` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Request.kind | `Kind` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:36` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Request.requested_at | `f64` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:37` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Request.digest | `[u8; 32]` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:38` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Request.addition | `Option<([u8; 32], u32)>` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:39` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Step (enum) | declaration | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:182` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Step::Prepare | `Prepare` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:183` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Step::Intent | `Intent` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:184` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Step::Preparing | `Preparing` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:185` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Step::Birth | `Birth` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:186` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Step::Executing | `Executing` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:187` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Step::Result | `Result` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:188` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Step::Complete | `Complete` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:189` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Owner (struct) | declaration | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:191` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Owner.anchor | `Rc<()>` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:193` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Owner.creator | `u32` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:194` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Owner.input | `ObservedHostAssembly` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:195` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Owner.previous | `Vec<kernel::host_link::Verified>` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:196` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Owner.addition | `Option<vprouter_network::HostAdditionPlan>` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:197` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Owner.request | `Option<Rc<Request>>` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:198` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Owner.child | `Option<kernel::host_link::Child>` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:199` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Owner.verified | `Option<kernel::host_link::Verified>` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:200` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Owner.index | `usize` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:201` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Owner.step | `Step` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:202` | NATIVE_ONLY; no JSON mutation can exercise this field |
| Owner.failure | `Option<Error>` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:203` | NATIVE_ONLY; no JSON mutation can exercise this field |
| PendingHostLinks (struct) | declaration | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:205` | NATIVE_ONLY; no JSON mutation can exercise this field |
| PendingHostLinks.native | `Option<Box<Owner>>` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:206` | NATIVE_ONLY; no JSON mutation can exercise this field |
| HostLinkedAssembly (struct) | declaration | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:208` | NATIVE_ONLY; no JSON mutation can exercise this field |
| HostLinkedAssembly.native | `Option<Box<Owner>>` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:209` | NATIVE_ONLY; no JSON mutation can exercise this field |
| LabAnchors (struct) | declaration | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1194` | NATIVE_ONLY; no JSON mutation can exercise this field |
| LabAnchors.original | `Vec<std::rc::Weak<()>>` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1195` | NATIVE_ONLY; no JSON mutation can exercise this field |
| LabAnchors.baseline | `std::rc::Weak<()>` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1196` | NATIVE_ONLY; no JSON mutation can exercise this field |
| LabAnchors.link | `std::rc::Weak<()>` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1197` | NATIVE_ONLY; no JSON mutation can exercise this field |
| LabAnchors.generation | `std::rc::Weak<Generation>` | `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1198` | NATIVE_ONLY; no JSON mutation can exercise this field |

Declaration walk totals: 19 Rust modules, 116 structs/enums, 636 listed fields/variants (including enum payload fields).


## Recorded success guard ledger

All paths below are relative to `crates/vprouter-launch/src/`, except explicitly
prefixed tools paths. Every row identifies the original guard or emitter, its
validator implementation, and end-to-end mutation coverage. Type/range/null
coverage is supplied for every field by S above; semantic probes additionally
cover coordinated copies so retained-prefix equality is not the only oracle.

| Field or success guard | Rust file:line | Validator line | Mutation test |
| --- | --- | --- | --- |
| Preparation member / creating phase / links, attempt, terminal absent | `owned/preparation.rs:89` | validator:1760 | `test_canonical_history_guards_coordinated_copies` |
| Preparation pending/fenced false, service reserved, children reaped, jobs uncollected | `attachment/operational/bootstrap.rs:1032` | validator:1555 | `test_preparation_success_guards_through_validate` |
| Final unchanged entry producer, 87 writer prefix and 16 retained histories/identities | `attachment/operational/bootstrap.rs:1046` | validator:1555 | `test_retained_preparation_prefix_through_validate` |
| All earlier retained preparation writer prefixes stay original | `attachment/host_addition/operation.rs:948` | validator:1965 | `test_retained_preparation_prefix_through_validate; test_additional_recorded_success_guards` |
| Preparation bootstrap queries fixed three Option slots | `owned/preparation.rs:59` | validator:1336 | `test_audit_origin_fixed_query_array_and_canonical_names; test_every_real_witness_leaf_through_validate` |
| Birth PID u32 >1, start u64 >0, born finite and within original window | `owned/preparation.rs:78` | validator:1648 | `test_all_independent_reviewer_fixtures_through_validate; test_boot_deadlines_scope_identity_and_nested_authority` |
| Request/birth/result time ordering and deadline=requested+2 | `owned/preparation/bootstrap.rs:77` | validator:1648 | `test_boot_deadlines_scope_identity_and_nested_authority` |
| Every recorded owner epoch matches original boot, unit, PID/start and cgroup | `supervision.rs:46` | validator:1629 | `test_boot_deadlines_scope_identity_and_nested_authority; test_retained_preparation_prefix_through_validate` |
| Owner invocation nonzero32 lowercase hex; cgroup inode >0 | `supervision.rs:50` | validator:1629 | `test_additional_recorded_success_guards` |
| All digest arrays typed, 32 bytes and nonzero when required | `owned/preparation/bootstrap.rs:77` | validator:1685 | `test_fixed_arrays_and_byte_ranges_are_typed; test_every_real_witness_leaf_through_validate` |
| Inspection Recheck has Initial; initial request nonzero and distinct | `owned/preparation/inspection.rs:143` | validator:1760 | `test_canonical_history_guards_coordinated_copies; test_every_real_witness_leaf_through_validate` |
| Initial birth window/verification precedes current birth; same facts | `owned/preparation/inspection.rs:151` | validator:1760 | `test_all_success_booleans_in_retained_emitters; test_boot_deadlines_scope_identity_and_nested_authority` |
| All query facts PID >1 and <=i32::MAX, consistent with original gateway | `owned/preparation/inspection.rs:318` | validator:1760 | `test_boot_deadlines_scope_identity_and_nested_authority; test_every_real_witness_leaf_through_validate` |
| Attachment/Movement/Quarantine/Producer/Binding/Bootstrap rechecks forbid Initial | `owned/preparation/inspection.rs:27` | validator:1760 | `test_all_independent_reviewer_fixtures_through_validate; test_canonical_history_guards_coordinated_copies` |
| Query kind matches scope/index and contextual prerequisite completion | `owned/preparation/inspection.rs:203` | validator:1760 | `test_all_independent_reviewer_fixtures_through_validate; test_canonical_history_guards_coordinated_copies` |
| Query facts match original inspection; completed query has birth/facts/verified | `owned/preparation/inspection.rs:228` | validator:1760 | `test_every_real_witness_leaf_through_validate` |
| Original query native status0, original peer receipt, no handler claim, listener1 root/root | `kernel/docker_query.rs:1269` | validator:2090 | `test_all_success_booleans_in_retained_emitters; test_every_real_witness_leaf_through_validate` |
| Origin enum existing_admitted, launch/staging/container digest formats, positive start/network, nonzero public result | `attachment.rs:294` | validator:1760 | `test_audit_origin_fixed_query_array_and_canonical_names; test_every_real_witness_leaf_through_validate` |
| DATA mount directory/source nonzero, canonical data name, source/origin identity | `owned/preparation/mount.rs:41` | validator:1760 | `test_retained_preparation_prefix_through_validate; test_every_real_witness_leaf_through_validate` |
| Mount requested after inspection; query window same as mount and birth after mounted_at | `owned/preparation/inspection.rs:273` | validator:1760 | `test_boot_deadlines_scope_identity_and_nested_authority; test_every_real_witness_leaf_through_validate` |
| Placeholder has same device, positive inode, exact mode0100600 | `owned/preparation/mount.rs:69` | validator:1760 | `test_remaining_narrow_native_emitter_types; test_every_real_witness_leaf_through_validate` |
| Mount verified/published after birth/query and before deadline; published DATA/base/source equal | `owned/preparation/mount.rs:96` | validator:1760 | `test_boot_deadlines_scope_identity_and_nested_authority; test_retained_preparation_prefix_through_validate` |
| Fresh transport directory/host/data nonzero; source positive, distinct host and DATA | `owned/preparation/fresh_transport.rs:31` | validator:1760 | `test_all_success_booleans_in_retained_emitters; test_every_real_witness_leaf_through_validate` |
| Fresh creation after DATA publication, fresh mount same source/directory/name after creation | `owned/preparation/fresh_mount.rs:29` | validator:1760 | `test_retained_preparation_prefix_through_validate; test_every_real_witness_leaf_through_validate` |
| Fresh mount placeholder, mounted/published order and transport namespace equality | `owned/preparation/fresh_mount.rs:52` | validator:1760 | `test_all_success_booleans_in_retained_emitters; test_every_real_witness_leaf_through_validate` |
| Wireguard ordered kinds sockets/provision/query/data_sockets/move; original namespaces | `owned/preparation/wireguard.rs:74` | validator:1760 | `test_canonical_history_guards_coordinated_copies; test_every_real_witness_leaf_through_validate` |
| Wireguard shared configuration; completion after prior op/mount | `owned/preparation/wireguard.rs:93` | validator:1760 | `test_retained_preparation_prefix_through_validate; test_every_real_witness_leaf_through_validate` |
| Move destination DATA distinct from transport, original movement digest/request/window/birth after query | `owned/preparation/wireguard.rs:106` | validator:1760 | `test_retained_preparation_prefix_through_validate; test_every_real_witness_leaf_through_validate` |
| Socket results have null link/WG; other results populated in correct namespace | `owned/preparation/wireguard.rs:141` | validator:1760 | `test_every_real_witness_leaf_through_validate` |
| Six policy operations in exact host/transport/data sockets/initial order | `owned/preparation/quarantine.rs:331` | validator:1760 | `test_all_independent_reviewer_fixtures_through_validate; test_canonical_history_guards_coordinated_copies` |
| Policy namespace/configuration/declaration, prior completion and pair policy agreement | `owned/preparation/quarantine.rs:346` | validator:1760 | `test_canonical_history_guards_coordinated_copies; test_quarantine_host_declaration_matches_all_recorded_copies` |
| Only DATA initial policy has the quarantine query; start and birth after that query | `owned/preparation/quarantine.rs:365` | validator:1760 | `test_canonical_history_guards_coordinated_copies; test_every_real_witness_leaf_through_validate` |
| Policy result namespace/policy equality, sockets observed=null, initial finite observed in window | `owned/preparation/quarantine.rs:406` | validator:1760 | `test_canonical_history_guards_coordinated_copies; test_boot_deadlines_scope_identity_and_nested_authority` |
| Canonical policy source completed InitialQuarantine in same scope; binding policy DATA | `owned/preparation/quarantine.rs:296` | validator:1685 | `test_all_independent_reviewer_fixtures_through_validate` |
| Producer creation original query/start/deadline, data namespace, canonical group name | `owned/preparation/producer_creation.rs:50` | validator:1760 | `test_canonical_history_guards_coordinated_copies; test_audit_origin_fixed_query_array_and_canonical_names` |
| Producer group same parent device, positive/different inode; completion after birth/query | `owned/preparation/producer_creation.rs:77` | validator:1760 | `test_canonical_history_guards_coordinated_copies; test_every_real_witness_leaf_through_validate` |
| Binding creation equals original, source parent/group/name/data equal and DATA equals entry | `owned/preparation/producer_binding.rs:79` | validator:1760 | `test_all_independent_reviewer_fixtures_through_validate; test_canonical_history_guards_coordinated_copies` |
| Binding query digest/request/window/order and canonical DATA policy | `owned/preparation/producer_binding.rs:89` | validator:1760 | `test_all_independent_reviewer_fixtures_through_validate` |
| Binding six pins: parent/group first identities, all same device and positive inode | `owned/preparation/producer_binding.rs:98` | validator:1760 | `test_result_and_request_pin_sizes_through_validate; test_every_real_witness_leaf_through_validate` |
| Binding result six pins / namespace / group / policy matches request | `owned/preparation/producer_binding.rs:114` | validator:1685 | `test_binding_result_matches_own_request_through_validate; test_all_independent_reviewer_fixtures_through_validate` |
| Publication binding digest, parent/group, creating/absent links/attempt/terminal | `owned/preparation/producer_binding.rs:53` | validator:1760 | `test_all_independent_reviewer_fixtures_through_validate; test_canonical_history_guards_coordinated_copies` |
| Host kinds exact transport_sockets/pair/host_sockets/move; host vs transport namespace | `owned/preparation/host_link.rs:52` | validator:1760 | `test_canonical_history_guards_coordinated_copies; test_every_real_witness_leaf_through_validate` |
| Host admission triple finite/positive, +2 deadline, accepted within window and <=request | `owned/preparation/host_link.rs:77` | validator:1648 | `test_host_admission_window_and_environment_order` |
| Host admission after canonical binding; same declaration/window/host for all four ops | `owned/preparation/host_link.rs:83` | validator:1760 | `test_host_admission_window_and_environment_order; test_quarantine_host_declaration_matches_all_recorded_copies` |
| Host addition present iff Move, nonzero digest and canonical planned u32 index | `owned/preparation/host_link.rs:87` | validator:1760 | `test_original_down_host_endpoint_cannot_be_replaced; test_every_real_witness_leaf_through_validate` |
| Host operation request after previous completion, correct result namespace/status/window | `owned/preparation/host_link.rs:100` | validator:1760 | `test_canonical_history_guards_coordinated_copies; test_host_admission_window_and_environment_order` |
| Host sockets result null pair; pair names/aliases/down/veth/positive distinct reciprocal indices | `owned/preparation/host_link.rs:143` | validator:1760 | `test_canonical_history_guards_coordinated_copies; test_all_success_booleans_in_retained_emitters` |
| Host Move result exactly original pair with only host index and peer_index changed | `owned/preparation/host_link.rs:168` | validator:1760 | `test_original_down_host_endpoint_cannot_be_replaced; test_every_real_witness_leaf_through_validate` |
| Bootstrap completed scopes host/transport/data in order and exact namespaces | `owned/preparation/bootstrap.rs:44` | validator:1685 | `test_boot_deadlines_scope_identity_and_nested_authority` |
| Bootstrap original producer creation/group/data and prior host/scope completion | `owned/preparation/bootstrap.rs:77` | validator:1685 | `test_all_independent_reviewer_fixtures_through_validate; test_retained_preparation_prefix_through_validate` |
| Bootstrap query digest/start/+2 window and initial=null | `owned/preparation/bootstrap.rs:84` | validator:1685 | `test_all_independent_reviewer_fixtures_through_validate` |
| Bootstrap eight pins parent/group identities, positive same-device and unique dev/inode | `owned/preparation/bootstrap.rs:93` | validator:1685 | `test_fixed_arrays_and_byte_ranges_are_typed; test_result_and_request_pin_sizes_through_validate` |
| Bootstrap pin recorded file type and nonwritable group/other modes | `attachment/operational/producer.rs:151` | validator:2090 | `test_every_real_witness_leaf_through_validate; test_fixed_arrays_and_byte_ranges_are_typed` |
| Bootstrap result namespace/group/policy/eight pins equals request, observed born<=observed<=verified<deadline | `owned/preparation/bootstrap.rs:121` | validator:1685 | `test_birth_status_pin_and_writer_contract_mutations; test_boot_deadlines_scope_identity_and_nested_authority` |
| Top Bootstrap schema1/fault0/null failure fields/ack/context/parent flags, writer not held | `attachment/operational/bootstrap.rs:1248` | validator:1533 | `test_success_contract_mutations; test_all_success_booleans_in_retained_emitters` |
| Bootstrap oracle39 =3*(10 field+3 null mutations) | `owned/preparation/bootstrap.rs:857` | validator:1533 | `test_success_contract_mutations` |
| Held Bootstrap query/policy intents queued1/held2/negative6,12/released; writer87,90 PID/start/status | `attachment/operational/bootstrap.rs:1071` | validator:1533 | `test_held_intents_bound_to_original_writers_through_validate; test_emitted_intent_queued_poll_count_through_validate` |
| All105 writers exact phase schedule/status0/PID/start/window, each retained prefix equal | `attachment/operational/bootstrap.rs:1090` | validator:2196 | `test_birth_status_pin_and_writer_contract_mutations; test_additional_recorded_success_guards` |
| Bootstrap query/operation/history fields equal, acknowledgments and original native receipt | `attachment/operational/bootstrap.rs:1140` | validator:1685 | `test_birth_status_pin_and_writer_contract_mutations; test_all_independent_reviewer_fixtures_through_validate` |
| Scope verification count3, ordered, >=ack and <query deadline, final equals last | `attachment/operational/bootstrap.rs:1182` | validator:1648 | `test_boot_deadlines_scope_identity_and_nested_authority; test_every_real_witness_leaf_through_validate` |
| Bootstrap charges[3,3] retained after drop; all final retention flags true | `attachment/operational/bootstrap.rs:1213` | validator:1576 | `test_success_contract_mutations; test_all_success_booleans_in_retained_emitters` |
| Handoff exact20=15+5, suffix5, repeated refusals5, child limit64, no failure reservations | `attachment/operational.rs:554` | validator:1583 | `test_success_contract_mutations` |
| Handoff reservation original15/suffix5/complete true/pending false/ticket limit2560/member/epoch | `owned/preparation/assembly.rs:303` | validator:1583 | `test_success_contract_mutations; test_all_success_booleans_in_retained_emitters` |
| Handoff five native original resources retired, original binding+host PID/start/status/charges | `attachment/operational.rs:566` | validator:1583 | `test_birth_status_pin_and_writer_contract_mutations; test_success_contract_mutations` |
| Handoff charges[5,5]->[0,0], preparation unchanged from host, no resources collected | `attachment/operational.rs:584` | validator:1576 | `test_success_contract_mutations; test_all_success_booleans_in_retained_emitters` |
| Retained host fault0, continuation true and null charges_after_drop | `attachment/operational.rs:485` | validator:1965 | `test_all_independent_reviewer_fixtures_through_validate; test_retained_success_guards_through_validate` |
| Retained host 87writers/75prefix/idle prep and prefix histories unchanged | `attachment/host_addition/operation.rs:948` | validator:1965 | `test_retained_success_guards_through_validate; test_all_success_booleans_in_retained_emitters` |
| Host intent queued1/held2/net negatives12/released and original writer75 PID/start/status | `attachment/host_addition/operation.rs:988` | validator:1965 | `test_all_independent_reviewer_fixtures_through_validate; test_retained_success_guards_through_validate` |
| Host four operation/history receipts, borrowed0/2/0/4, native slots, original status/birth/EOF/release | `attachment/host_addition/operation.rs:1005` | validator:1965 | `test_retained_success_guards_through_validate; test_all_success_booleans_in_retained_emitters` |
| Host pair/move inventory polls>=2 and preservation; current result inventory baseline+one down endpoint | `attachment/host_addition/operation.rs:1101` | validator:1965 | `test_additional_recorded_success_guards; test_all_success_booleans_in_retained_emitters` |
| Host canonical negatives20=16 field+4 replacements, charges[1,1]->[5,5], retained false drop flags | `attachment/host_addition/operation.rs:1119` | validator:1965 | `test_all_independent_reviewer_fixtures_through_validate; test_retained_success_guards_through_validate` |
| Host original two-read baseline admission, polls u32 >0, same generation/declaration | `attachment/host_addition/operation.rs:719` | validator:1965 | `test_remaining_narrow_native_emitter_types; test_all_success_booleans_in_retained_emitters` |
| Binding retained fault0, original source/publication and null/false failure/drop branch | `attachment/producer_binding.rs:1145` | validator:1965 | `test_retained_success_guards_through_validate; test_all_success_booleans_in_retained_emitters` |
| Binding retained 75writers/69prefix, own original query and observation/history, final process within deadline | `attachment/producer_binding.rs:957` | validator:1965 | `test_retained_preparation_prefix_through_validate; test_canonical_history_guards_coordinated_copies` |
| Binding canonical negatives25, before[0,0], after[1,1] | `owned/preparation/producer_binding.rs:711` | validator:1965 | `test_additional_recorded_success_guards` |
| Assembly retained fault0, retired15 complete, charges[15,11]->[0,0], repeat/lower-repeat refusal, duplicate false | `attachment/assembly.rs:299` | validator:1965 | `test_retained_success_guards_through_validate; test_all_success_booleans_in_retained_emitters` |
| Assembly15 exact original resource kinds/identities, retired flags and conditional lower Option flags | `kernel.rs:2490` | validator:2090 | `test_all_success_booleans_in_retained_emitters; test_every_real_witness_leaf_through_validate` |
| Assembly unchanged preparation and complete registry reservation, limit128 and tickets2560 | `attachment/assembly.rs:329` | validator:1965 | `test_retained_success_guards_through_validate; test_all_success_booleans_in_retained_emitters` |
| Foreign eligibility refusal schema1/status0/EOF/eligible original plan[3] PID/start/no canonical transfer/unchanged charges | `kernel/capacity_lab.rs:219` | validator:2090 | `test_all_success_booleans_in_retained_emitters; test_foreign_capacity_pid_keeps_native_i32_width` |
| Quarantine retained 69writers/42prefix, six original receipts and original producer query/group | `attachment/quarantine/producer.rs:845` | validator:1965 | `test_retained_success_guards_through_validate; test_all_success_booleans_in_retained_emitters` |
| Quarantine original intent42, queued1/held>=2/negative12 and receipt window/status | `attachment/quarantine/producer.rs:824` | validator:1965 | `test_all_success_booleans_in_retained_emitters; test_every_real_witness_leaf_through_validate` |
| Quarantine completed producer creation receipt native flags/identity/status, no operational publication or parent-death claim | `kernel/producer_creation.rs:672` | validator:2090 | `test_all_success_booleans_in_retained_emitters; test_canonical_history_guards_coordinated_copies` |
| Movement retained42writers/33prefix, original first3 operations retained,5 operations, query parent sequence advances | `attachment/movement.rs:677` | validator:1965 | `test_retained_success_guards_through_validate; test_all_success_booleans_in_retained_emitters` |
| Movement final process >=writer41 acknowledgment and <query deadline, down-only/data move and dual original pairs | `attachment/movement.rs:840` | validator:1965 | `test_all_success_booleans_in_retained_emitters; test_every_real_witness_leaf_through_validate` |
| Provision retained33writers/17prefix,3 operations, original fresh source and mount, down-only and borrowed registrations | `attachment/provision.rs:852` | validator:1965 | `test_retained_success_guards_through_validate; test_all_success_booleans_in_retained_emitters` |
| Attachment retained17writers, base published, mount intact, original query births/facts/times and no held/failure writer | `attachment/mount.rs:844` | validator:2090 | `test_all_success_booleans_in_retained_emitters; test_every_real_witness_leaf_through_validate` |
| Mount packet/gate counters u8 exactly2 and retained original source/placeholder/EOF/status | `kernel/namespace_attachment.rs:884` | validator:2090 | `test_remaining_narrow_native_emitter_types; test_all_success_booleans_in_retained_emitters` |
| All retained continuations return before drop, false drop flags/null charge fields, schemas/faults/parents true as emitted | `attachment/host_addition/operation.rs:1147` | validator:1965 | `test_retained_success_guards_through_validate` |
| All nested authority/READY/UP/placement/cleanup/runtime/requirement8 flags false | `attachment/operational/bootstrap.rs:1255` | validator:1614 | `test_success_contract_mutations; test_all_success_booleans_in_retained_emitters` |
| Raw/source/controller/reservation/claim frozen bindings and consumed budget0; exact ordered rows | `tools/rust-v2-lab/target/platform-lab/run-frozen-secret-bootstrap410.py:1` | validator:1477 | `test_record_binding_mutations; test_missing_duplicate_and_inconsistent_rows` |
| Controller build/harness/launcher/case PASS, original gateway, owner absent, single down link allowed name/index, observations ordered | `attachment/operational/bootstrap.rs:1288` | validator:2235 | `test_missing_duplicate_and_inconsistent_rows; test_host_admission_window_and_environment_order` |
| Declared host baseline exact frozen template/digests/namespace and baseline admission | `attachment/host_addition/operation.rs:739` | validator:2295 | `test_host_admission_window_and_environment_order; test_additional_recorded_success_guards` |
| Quarantine host allocation fields/WAN identity/digest match every retained policy declaration | `owned/preparation/quarantine.rs:347` | validator:2295 | `test_quarantine_host_declaration_matches_all_recorded_copies` |

## Guards not reconstructible from emitted metadata

| Original Rust guard | Source | Offline treatment / remaining limit |
| --- | --- | --- |
| Preparation allocation/configuration/private input identities and PublicValidation report/selected/device_key validation | `owned/preparation.rs:89-150,211-229` | Original History is not embedded wholesale. Projection checks member, identities, public_result, completion, and frozen source/artifact/reservation bindings. Omitted inputs/result fields cannot be validated as if they were present. No claim to deserialize the complete private journal. |
| Creator equals current PID, Rc::ptr_eq source/service/query/owner origin, live owner process/cgroup and pristine secret boundary | `owned/preparation.rs:1699-1779`; `attachment/operational/bootstrap.rs:46-185`; `attachment/host_addition.rs:27-49` | Recorded identity/status/parent_pristine fields and source chains checked. Live process/namespace/registration identity and pointer provenance NOT_RUN. |
| FDs still match fstat/fstatfs/read-only registration, UID/GID0, ancestry pins and exact native resource custody | `attachment/operational/producer.rs:135-180`; `owned/preparation/host_link.rs:435-469` | Serialized pin identities/modes and native-registration assertions checked. Actual FDs, access flags, UID/GID and ancestry registrations are not serialized and cannot be re-observed offline. |
| Unique non-Clone reservation, leases, child capacity retirement capabilities, Weak upgrade/drop survival and retained process custody | `owned/preparation/assembly.rs:31-108`; `attachment/operational.rs:73-83`; `attachment/operational/bootstrap.rs:1257-1287` | Counts/statuses/identities/retention assertions validated as recorded. No current custody, drop replay or actual capacity experiment claimed. |
| Recompute native request/policy digests from private constructor inputs / verify live policy content | `attachment/operational/bootstrap.rs:78-107`; `owned/preparation/quarantine.rs:296-311` | Digest array type/nonzero, kind/scope, result/request and canonical producer/query/policy/declaration equality enforced. Missing constructor-only inputs prevent complete independent regeneration of all digests. |
| Live host neighbor preservation, original Docker listener handler identity, real-client/leak/direct/multi-exit/fault/ARM/performance/migration/reboot/rollback/soak/release acceptance | Guest/controller and LIMITS in validator | Explicitly NOT_RUN. Original Docker peer receipt does not claim handler identity. Runtime/release false; consumed run410 unchanged. |

This is a stronger offline consistency validator, not a mathematical proof that
all future source changes or all possible coordinated fabrications are rejected.
Source-driven schema and full-leaf tests prevent silent additions/type widening
in the covered emitted profile; further independent review remains appropriate.

## Verification and receipt

Final checks on the unchanged validator/test sources:

| Check | Result |
| --- | --- |
| `python3 -B tools/rust-v2-lab/test-validate-run410-witness.py` | PASS; 30 tests, 278.524s |
| Original independent reviewer fixtures through `validate()` | All29 rejected: 18 earlier fixtures and 11 rereview fixtures; the pre-fix regression had exactly11 false-PASS assertions |
| Full-leaf end-to-end mutation sweep | PASS; 28,782 leaves, 102,334 serialized mutations, all rejected |
| Real raw record and reserialized copy | Both PASS |
| `python3 -B tools/rust-v2-lab/test-run410-fixes.py` | PASS; 8 tests; pre-existing generated-template SyntaxWarnings remain |
| `python3 -B tools/rust-v2-lab/test-run410-isolation.py` | PASS; 21 tests |
| `python3 -B tools/rust-v2-lab/test-run410-provenance.py` | PASS; 21 tests |
| `python3 -B tools/rust-v2-lab/test-run410-reservation.py` | PASS; 12 tests; `real_lab_claim_created=false` |
| Explicit `py_compile` under `python3 -B` | PASS; validator, its tests and four run410 suites; bytecode written only to an automatically removed temporary directory |
| `git diff --check` | PASS |
| Frozen Rust source and enum audit | All19 requested modules byte-identical to candidate `source.tar`; all10 enum domains exactly match source |

Created `target/run410-evidence/witness-validation-r3.json` using the exclusive
`O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC` writer, mode0600, file fsync and parent
directory fsync. It is 5,569 bytes, SHA256
`f004b626169bb8481c5d61780c10cbcad382f328a38982bb183e4c2a572b37f6`.
The receipt reports revision3, PASS in all19 check groups, and the two previous
receipt paths as superseded. Its parsed contents equal a fresh `validate()`
result for the identical relative raw-record path. Both earlier receipts retain
their original hashes and mode0600. `runtime_acceptance=false` and
`release_ready=false` remain explicit.

Preservation comparison covered783 baseline files beneath `target/lab-state`,
`target/run410-evidence`, `target/candidates/run410-da75562-20261104`,
`tools/rust-v2-lab` and `.superpowers/sdd/rust-v2`. SHA256, byte count and mode
match for every file outside the three authorized existing-file changes;
the only authorized addition is the r3 receipt. The unrelated dirty
`progress.md` is unchanged. HEAD remains
`5e989eeeea3092cc59675bd78ad37e06fce2d7c0`; no staging or commit occurred.

An inline Python audit observed61 read opens and zero validation writes. Its
temporary receipt exercise observed the expected create and refused-overwrite
attempts, confirmed mode0600 and preserved bytes, and denied subprocess,
network, preserved-path access and unexpected mutations. This is a bounded
Python audit, not a whole-machine syscall trace. No Cargo, sudo, network or VM
operation was performed. No preserved-tree access, run409/410 record, claim or
reservation write occurred. The new receipt is offline consistency evidence;
the nonserialized/live guards and runtime/release limits tabulated above remain
NOT_RUN.

## Controller disposition (2026-11-06): NOT ACCEPTED as exhaustive validation

Three independent review rounds each returned FAIL for completeness: round 1
(`task-8c-run410-witness-review.md`, I1-I3/M1), round 2 (`-rereview.md`, I4-I8),
round 3 (`-rereview2.md`, I9 transport creation/mount not bound to canonical
history; I10 WireGuard down-only/original-move guards; M2 Route.kind width in the
leaf sweep). Every earlier finding was closed each round and the real record
passes all 19 groups of r3 (`target/run410-evidence/witness-validation-r3.json`),
but each round found new unreproduced-by-tests false PASS fixtures in areas the
previous rounds had not covered. The 3-attempt limit for this step was reached, so
no fourth round was run. Consequences: the validator is committed as a strict
**partial** validator (far stronger than the collector's NOT_RUN); I9, I10 and M2
stay OPEN; `full_bootstrap_witness_validation` is recorded as
`PASS_PARTIAL_UNREVIEWED_GAPS`, not an acceptance. runtime_acceptance=false,
release_ready=false. The run-410 execution itself is not shown to have failed.
