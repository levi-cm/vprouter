#!/usr/bin/env python3
"""Extract the bounded run410 Rust witness contract, without Rust execution.

stdout is canonical JSON; --output writes only the explicitly selected path.
The parser balances Rust delimiters, masks comments/strings, and rejects unknown
serde type syntax. Source hashes bind even syntax outside the supported subset.
Success-profile adapters describe JSON-builder/envelope projections, which are
not Rust Deserialize structs. Actual serde declarations always override their
field types, field sets, options and enums; no observed record is consulted.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import tomllib

ROOT = Path(__file__).resolve().parents[2]
LAUNCH = 'crates/vprouter-launch/src/'
NETWORK = 'crates/vprouter-network/src/'
# Explicit entry points select type identities, never integer widths.
TYPE_ROOTS = [('crates/vprouter-launch/src/owned/preparation.rs', 'ValidationBirth', 'Birth'),
 ('crates/vprouter-launch/src/owned.rs', 'Identity', 'Identity'),
 ('crates/vprouter-launch/src/supervision.rs', 'OwnerDomainRecord', 'OwnerEpoch'),
 ('crates/vprouter-launch/src/attachment.rs', 'QueryFacts', 'QueryFacts'),
 ('crates/vprouter-launch/src/owned/preparation/inspection.rs', 'History', 'InspectionHistory'),
 ('crates/vprouter-launch/src/owned/preparation/inspection.rs', 'Initial', 'InspectionInitial'),
 ('crates/vprouter-launch/src/owned/preparation/mount.rs', 'History', 'Attachment'),
 ('crates/vprouter-launch/src/owned/preparation/mount.rs', 'Placeholder', 'Placeholder'),
 ('crates/vprouter-launch/src/owned/preparation/fresh_transport.rs', 'History', 'FreshTransport'),
 ('crates/vprouter-launch/src/owned/preparation/fresh_mount.rs', 'History', 'MountHistory'),
 ('crates/vprouter-launch/src/owned/preparation/host_link.rs', 'History', 'HostLinkHistory'),
 ('crates/vprouter-launch/src/owned/preparation/quarantine.rs', 'Operation', 'NetfilterHistory'),
 ('crates/vprouter-launch/src/owned/preparation/quarantine.rs', 'PublicResult', 'NetfilterResult'),
 ('crates/vprouter-launch/src/owned/preparation/producer_creation.rs', 'History', 'ProducerCreationHistory'),
 ('crates/vprouter-launch/src/owned/preparation/producer_binding.rs', 'History', 'ProducerBindingHistory'),
 ('crates/vprouter-launch/src/owned/preparation/producer_binding.rs',
  'PublicResult',
  'ProducerBindingResult'),
 ('crates/vprouter-launch/src/owned/preparation/bootstrap.rs', 'History', 'BootstrapHistory'),
 ('crates/vprouter-launch/src/owned/preparation/bootstrap.rs', 'PublicResult', 'BootstrapResult'),
 ('crates/vprouter-network/src/project.rs', 'Link', 'Link'),
 ('crates/vprouter-network/src/project.rs', 'Address', 'Address'),
 ('crates/vprouter-network/src/project.rs', 'Route', 'Route'),
 ('crates/vprouter-network/src/project.rs', 'Rule', 'Rule'),
 ('crates/vprouter-network/src/project.rs', 'Wireguard', 'Wireguard'),
 ('crates/vprouter-network/src/project.rs', 'Peer', 'WireguardPeer'),
 ('crates/vprouter-launch/src/owned/preparation/wireguard.rs', 'History', 'WireguardHistory'),
 ('crates/vprouter-launch/src/kernel/wireguard_role.rs', 'PublicResult', 'WireguardResult'),
 ('crates/vprouter-launch/src/kernel/host_link.rs', 'PublicResult', 'HostLinkResult'),
 ('crates/vprouter-launch/src/owned.rs', 'ProducerOwnership', 'EntryProducer'),
 ('crates/vprouter-network/src/host_observation.rs', 'HostObservation', 'HostBaseline')]

TYPE_ROOTS += [
    (LAUNCH+'attachment/host_declaration.rs','Wan','WanDeclaration'),
    (LAUNCH+'attachment/host_declaration.rs','Declaration','QuarantineHostDeclaration'),
    (LAUNCH+'attachment/host_baseline.rs','Declaration','BaselineDeclaration'),
    ('crates/vprouter-core/src/allocation.rs','AllocationRecord','Allocation'),
    ('crates/vprouter-core/src/allocation.rs','ExitAllocation','AllocationExit'),
]

# Reviewed successful JSON-builder and Python envelope adapters. These preserve
# contextual non-null completion requirements; they cannot override Rust types.
# Their emitter expressions/locations and complete source hashes are extracted
# below. Changes to any emitter require regeneration and review.
SUCCESS_ADAPTERS = {'AdmissionMetadata': {'content': 'ImageAdmission|HostAcceptance',
                       'device': 'u64',
                       'inode': 'u64',
                       'path': 'str'},
 'AdmissionRow': {'secret_attachment_admission': 'AdmissionMetadata'},
 'Allocation': {'deployment_id': 'str',
                'exits': 'list(AllocationExit)',
                'generation': 'u64',
                'schema_version': 'u64'},
 'AllocationExit': {'data_interface': 'str',
                    'data_namespace': 'str',
                    'exit_id': 'str',
                    'host_interface': 'str',
                    'mode': 'str',
                    'nft_table': 'str',
                    'state_dir': 'str',
                    'transport_namespace': 'str',
                    'transport_subnet': 'str',
                    'wireguard_interface': 'str'},
 'Assembly': {'assembly_context_retained_after_drop': 'bool',
              'charges_after': 'list(u64)',
              'charges_after_drop': 'null',
              'charges_before': 'list(u64)',
              'continued_original_context': 'bool',
              'duplicate_reservation_counts': 'null',
              'duplicate_reservation_refused': 'bool',
              'fault': 'u8',
              'fence_blocked_next_transfer': 'bool',
              'fence_counts': 'null',
              'foreign_eligibility': 'ForeignEligibility',
              'global_child_capacity_limit': 'u64',
              'handoff_complete': 'bool',
              'lower_repeat_retirement_refused': 'bool',
              'movement_context_retained_after_drop': 'bool',
              'multi_exit_runtime_proven': 'bool',
              'operational_reuse_authorized': 'bool',
              'original_provision_context_retained_after_drop': 'bool',
              'parent_pristine': 'bool',
              'preparation': 'Preparation',
              'producer_context_retained_after_drop': 'bool',
              'producer_operational_publication': 'bool',
              'quarantine': 'Quarantine',
              'quarantine_context_retained_after_drop': 'bool',
              'repeat_retirement_refused': 'bool',
              'requirement8_complete': 'bool',
              'reservation': 'AssemblyReservation',
              'resource_cleanup_authorized': 'bool',
              'resources': 'list(Resource)',
              'retired_original_jobs': 'u64',
              'schema': 'u64',
              'up_authorized': 'bool',
              'whole_chain_retained_after_drop': 'bool'},
 'AssemblyReservation': {'complete': 'bool',
                         'global_assemblies_reserved': 'u64',
                         'global_assembly_limit': 'u64',
                         'global_transferred_ticket_limit': 'u64',
                         'member': 'str',
                         'member_transfer_pending': 'bool',
                         'original_jobs': 'u64',
                         'owner_epoch': 'OwnerEpoch'},
 'AttachmentOrigin': {'container': 'str',
                      'kind': 'origin_kind',
                      'launch': 'str',
                      'network': 'Identity',
                      'process_start': 'u64',
                      'public_result': 'bytes32',
                      'staging': 'str'},
 'AttachmentWitness': {'base_published': 'bool',
                       'fault': 'u8',
                       'first_query': 'Query',
                       'held_real_writer': 'bool',
                       'inspection_deadline': 'f64',
                       'inspection_requested_at': 'f64',
                       'inspection_verified_at': 'f64',
                       'mount': 'MountWitness',
                       'namespace_cleanup_or_operational_reuse_authorized': 'bool',
                       'normal_ack_ready_preserved': 'bool',
                       'normal_ack_writer': 'null',
                       'original_mount_retained': 'bool',
                       'parent_pristine': 'bool',
                       'postmount_query': 'Query',
                       'preparation': 'Preparation',
                       'requirement8_complete': 'bool',
                       'same_service_retained': 'bool',
                       'schema': 'u64',
                       'second_query': 'Query',
                       'tested_non_target_phase': 'null',
                       'validator': 'ValidatorWitness',
                       'whole_failed_driver_retained_after_drop': 'bool'},
 'BaselineDeclaration': {'allocation_digest': 'str',
                         'baseline': 'HostBaseline',
                         'deployment_id': 'str',
                         'generation': 'u64',
                         'host_namespace': 'Identity',
                         'schema_version': 'u64'},
 'BaselineMetadata': {'authored_public_input_only': 'bool',
                      'builder_sha256': 'str',
                      'bytes': 'u64',
                      'declaration': 'BaselineDeclaration',
                      'host_authority_granted': 'bool',
                      'projection_matched_authored_shape': 'bool',
                      'review_sha256': 'str',
                      'sha256': 'str',
                      'template_baseline_sha256': 'str',
                      'template_sha256': 'str'},
 'BaselineRow': {'secret_host_baseline': 'BaselineMetadata'},
 'BootstrapOperation': {'accepted_at': 'f64',
                        'acknowledged': 'bool',
                        'actual_wait_status': 'i32',
                        'birth': 'Birth',
                        'bootstrap_installation_observed': 'bool',
                        'borrowed_registration_count': 'u64',
                        'complete_native_registration': 'bool',
                        'context_retained': 'bool',
                        'deadline': 'f64',
                        'durable_birth_released': 'bool',
                        'eof': 'bool',
                        'group': 'Identity',
                        'name': 'str',
                        'namespace': 'Identity',
                        'native_born': 'bool',
                        'native_job_state': 'job_state',
                        'original_pid': 'u32',
                        'original_registration_slots_verified': 'bool',
                        'original_start': 'u64',
                        'parent': 'Identity',
                        'pins': 'pins8',
                        'placement_authorized': 'bool',
                        'policy': 'bytes32',
                        'query': 'bytes32',
                        'registered_native_slots': 'u64',
                        'request': 'bytes32',
                        'requested_at': 'f64',
                        'result': 'BootstrapResult',
                        'scope': 'scope',
                        'up_authorized': 'bool'},
 'BootstrapWitness': {'bootstrap_all_scopes_acknowledged': 'bool',
                      'bootstrap_context_created': 'bool',
                      'bootstrap_context_retained_after_drop': 'bool',
                      'canonical_negative_checks': 'u64',
                      'charges_after_drop': 'list(u64)',
                      'charges_before_drop': 'list(u64)',
                      'failed_constructor': 'null',
                      'failure_retry': 'null',
                      'fault': 'u8',
                      'final_process_verified_at': 'f64',
                      'handoff': 'Handoff',
                      'health_ready_authorized': 'bool',
                      'host_addition': 'HostAddition',
                      'multi_exit_runtime_proven': 'bool',
                      'operational_context_retained_after_drop': 'bool',
                      'operations': 'list(BootstrapOperation)',
                      'original_nine_contexts_retained_after_drop': 'bool',
                      'own_intent_polling': 'IntentPolling',
                      'own_query_intent_polling': 'IntentPolling',
                      'parent_pristine': 'bool',
                      'placement_authorized': 'bool',
                      'preparation': 'Preparation',
                      'queries': 'list(Query)',
                      'requirement8_complete': 'bool',
                      'resource_cleanup_authorized': 'bool',
                      'result_writer_held': 'bool',
                      'retained_result_writer': 'null',
                      'schema': 'u64',
                      'scope_process_verified_at': 'list(f64)',
                      'up_authorized': 'bool',
                      'whole_chain_retained_after_drop': 'bool'},
 'BoundedObservation': {'status': 'str', 'text': 'str'},
 'BuildExitRow': {'secret_attachment_build_exit': 'u64'},
 'CaseResult': {'case': 'str', 'result': 'str'},
 'Controller': {'canonical_and_mount_resources_retained': 'bool',
                'harness_exit_code': 'u64',
                'host_addresses_routes_rules_preserved': 'bool',
                'host_allowed_index': 'u64',
                'host_allowed_name': 'str',
                'host_links_and_stable_routes_unchanged': 'bool',
                'host_single_down_link_added': 'bool',
                'host_stable_neighbors_preserved': 'bool',
                'inert_gateway_retained': 'bool',
                'native_transport_operations_requested': 'bool',
                'original_gateway_native_identity_unchanged': 'bool',
                'owner_unit_absent': 'bool',
                'synthetic_only': 'bool'},
 'ControllerRow': {'secret_attachment_controller': 'Controller'},
 'Descriptor': {'allocation': 'Allocation',
                'allocation_digest': 'str',
                'artifact_kind': 'str',
                'artifact_path': 'str',
                'artifact_sha256': 'str',
                'artifact_size': 'u64',
                'configuration': 'str',
                'container_mounts_allowed': 'bool',
                'container_required': 'bool',
                'deployment_id': 'str',
                'docker_queried': 'bool',
                'execution_policy_sha256': 'null',
                'image_ref': 'str',
                'nonce': 'str',
                'owner_unit': 'str',
                'planned_host_link_index': 'u32',
                'primary': 'str',
                'production_startup_authorized': 'bool',
                'profile_contents_read': 'bool',
                'program_manifest_sha256': 'str',
                'schema_version': 'u64',
                'spec': 'str',
                'staging': 'Staging',
                'staging_path': 'str',
                'worker_path': 'str'},
 'DescriptorRow': {'secret_attachment_descriptor': 'Descriptor'},
 'Environment': {'after': 'EnvironmentSnapshot',
                 'before': 'EnvironmentSnapshot',
                 'sampled_during_native_operation': 'bool',
                 'schema': 'u64',
                 'whole_vm_only': 'bool'},
 'EnvironmentFiles': {'boot': 'BoundedObservation',
                      'cpu': 'BoundedObservation',
                      'cpu_pressure': 'BoundedObservation',
                      'io_pressure': 'BoundedObservation',
                      'memory_pressure': 'BoundedObservation',
                      'root_cpu_max': 'UnavailableObservation',
                      'root_cpu_stat': 'BoundedObservation'},
 'EnvironmentRow': {'secret_attachment_environment': 'Environment'},
 'EnvironmentSnapshot': {'affinity': 'list(u64)',
                         'files': 'EnvironmentFiles',
                         'finished_at': 'f64',
                         'logical_cpus': 'u64',
                         'machine': 'str',
                         'operation_cost_attribution': 'bool',
                         'scope': 'str',
                         'started_at': 'f64'},
 'ForeignEligibility': {'actual_wait_status': 'i32',
                        'canonical_operation': 'bool',
                        'deadline': 'f64',
                        'eligible_foreign_refused': 'bool',
                        'eligible_original_pid': 'u32',
                        'eligible_original_start': 'u64',
                        'eof': 'bool',
                        'failed_actual_wait_status': 'null',
                        'failed_charges_unchanged': 'null',
                        'failed_exit_code': 'null',
                        'failed_original_pid': 'null',
                        'failed_original_start': 'null',
                        'original_pid': 'i32',
                        'original_start': 'u64',
                        'parent_counts_after': 'list(u64)',
                        'parent_counts_before': 'list(u64)',
                        'parent_still_eligible': 'bool',
                        'requested_at': 'f64',
                        'schema': 'u64',
                        'successful_capacity_transfer_proven': 'bool',
                        'verified_at': 'f64'},
 'Gateway': {'container_id': 'str',
             'host_network_namespace': 'list(u64)',
             'image_id': 'str',
             'inert': 'bool',
             'init_sha256': 'str',
             'mounts': 'empty',
             'name': 'str',
             'pid': 'u32',
             'program_manifest_sha256': 'str',
             'provider_state_mounted': 'bool',
             'source_namespace': 'list(u64)',
             'spec_sha256': 'str',
             'staging_sha256': 'str',
             'start': 'u64',
             'started_at': 'str'},
 'GatewayRow': {'secret_attachment_gateway': 'Gateway'},
 'Handoff': {'charges_after': 'list(u64)',
             'charges_before': 'list(u64)',
             'complete': 'bool',
             'complete_original_job_set': 'u64',
             'duplicate_reservation': 'null',
             'fence_counts': 'null',
             'global_child_capacity_limit': 'u64',
             'historical_original_jobs': 'u64',
             'preparation': 'Preparation',
             'repeat_retirement_refusals': 'u64',
             'reservation': 'OperationalReservation',
             'resources': 'list(Resource)',
             'resources_collected': 'bool',
             'retired_suffix_jobs': 'u64'},
 'HostAcceptance': {'artifact_sha256': 'str', 'network_dev': 'u64', 'network_ino': 'u64'},
 'HostAddition': {'admission': 'HostAdmission',
                  'baseline_context_retained_after_drop': 'bool',
                  'canonical_host_addition_acknowledged': 'bool',
                  'canonical_negative_checks': 'u64',
                  'charges_after_drop': 'null',
                  'charges_before': 'list(u64)',
                  'charges_before_drop': 'list(u64)',
                  'continued_original_context': 'bool',
                  'failed_constructor': 'null',
                  'failure_retry': 'null',
                  'fault': 'u8',
                  'generation_context_retained_after_drop': 'bool',
                  'health_ready_authorized': 'bool',
                  'host_addresses_routes_rules_preserved': 'bool',
                  'host_link_context_retained_after_drop': 'bool',
                  'host_neighbor_mutation_authorized': 'bool',
                  'isolated_pair_creation_observed': 'bool',
                  'multi_exit_runtime_proven': 'bool',
                  'operations': 'list(HostOperation)',
                  'original_six_contexts_retained_after_drop': 'bool',
                  'own_intent_polling': 'IntentPolling',
                  'parent_pristine': 'bool',
                  'placement_authorized': 'bool',
                  'planned_host_link_index': 'u32',
                  'preparation': 'Preparation',
                  'producer_binding': 'ProducerBinding',
                  'requirement8_complete': 'bool',
                  'resource_cleanup_authorized': 'bool',
                  'result_writer_held': 'bool',
                  'retained_result_writer': 'null',
                  'schema': 'u64',
                  'single_down_host_addition_observed': 'bool',
                  'unacknowledged_host_addition_retained': 'bool',
                  'up_authorized': 'bool',
                  'whole_chain_retained_after_drop': 'bool'},
 'HostAdmission': {'accepted_at': 'f64',
                   'deadline': 'f64',
                   'declaration': 'bytes32',
                   'declared_baseline': 'HostBaseline',
                   'namespace': 'Identity',
                   'polls': 'u32',
                   'requested_at': 'f64',
                   'same_generation_owner_retained': 'bool',
                   'two_original_reads_verified': 'bool'},
 'HostOperation': {'accepted_at': 'f64',
                   'acknowledged': 'bool',
                   'actual_wait_status': 'i32',
                   'addition': 'addition|null',
                   'admission': 'window3',
                   'birth': 'Birth',
                   'borrowed_registration_count': 'u64',
                   'complete_native_registration': 'bool',
                   'context_retained': 'bool',
                   'deadline': 'f64',
                   'declaration': 'bytes32',
                   'durable_birth_released': 'bool',
                   'eof': 'bool',
                   'host': 'Identity',
                   'host_observation': 'HostBaseline|null',
                   'kind': 'host_kind',
                   'namespace': 'Identity',
                   'native_born': 'bool',
                   'native_job_state': 'job_state',
                   'original_pid': 'u32',
                   'original_registration_slots_verified': 'bool',
                   'original_start': 'u64',
                   'placement_authorized': 'bool',
                   'postcompletion_inventory_polls': 'u32',
                   'postcompletion_inventory_preserved': 'bool|null',
                   'registered_native_slots': 'u64',
                   'request': 'bytes32',
                   'requested_at': 'f64',
                   'result': 'HostLinkResult',
                   'up_authorized': 'bool'},
 'ImageAdmission': {'image_id': 'str', 'program_manifest_sha256': 'str', 'schema': 'u64'},
 'InputManifest': {'canonical_root_precreated': 'bool',
                   'configuration_sha256': 'str',
                   'duplicate_private_input': 'bool',
                   'keys_created_outside_rust_parent': 'bool',
                   'mode': 'str',
                   'nonce': 'str',
                   'private_bytes_in_argv_environment_or_configuration': 'bool',
                   'profiles': 'list(ProfileMetadata)',
                   'schema': 'u64',
                   'state_root': 'str',
                   'synthetic_only': 'bool'},
 'InputRow': {'secret_attachment_input': 'InputManifest'},
 'IntentPolling': {'held_pending_polls': 'u64',
                   'index': 'u64',
                   'negative_checks': 'u64',
                   'pid': 'u32',
                   'queued_polls': 'u64',
                   'released': 'bool',
                   'start': 'u64'},
 'Launcher': {'exit_code': 'u64', 'native_wait_status_proven': 'bool', 'stderr': 'str', 'stdout': 'str'},
 'LauncherRow': {'secret_attachment_owner_launcher': 'Launcher'},
 'MountWitness': {'actual_wait_status': 'i32',
                  'birth': 'Birth',
                  'deadline': 'f64',
                  'eof': 'bool',
                  'original_directory': 'Identity',
                  'original_mounted_namespace_retained': 'bool',
                  'original_placeholder_retained': 'bool',
                  'original_source': 'Identity',
                  'placeholder': 'Placeholder',
                  'received_packets': 'u8',
                  'released_gates': 'u8',
                  'requested_at': 'f64'},
 'Movement': {'continued_original_context': 'bool',
              'data_move_completed': 'bool',
              'failed_constructor': 'null',
              'fault': 'u8',
              'final_process_verified_at': 'f64',
              'held_real_result_writer': 'bool',
              'host_resources_created': 'bool',
              'move_borrows_both_original_pairs': 'bool',
              'movement_context_retained_after_drop': 'bool',
              'movement_query': 'Query',
              'operational_reuse_authorized': 'bool',
              'operations': 'list(MovementOperation)',
              'original_provision_context_retained_after_drop': 'bool',
              'original_query_parent_readback_advanced': 'bool',
              'parent_pristine': 'bool',
              'preparation': 'Preparation',
              'provision': 'Provision',
              'requirement8_complete': 'bool',
              'same_service_retained': 'bool',
              'schema': 'u64',
              'unacknowledged_native_result_retained': 'bool',
              'whole_chain_retained_after_drop': 'bool',
              'wireguard_down_only': 'bool'},
 'MovementOperation': {'accepted_at': 'f64',
                       'acknowledged': 'bool',
                       'actual_wait_status': 'i32',
                       'birth': 'Birth',
                       'borrowed_registration_count': 'u64',
                       'context_retained': 'bool',
                       'deadline': 'f64',
                       'full_descriptor_registration': 'bool',
                       'kind': 'wireguard_kind',
                       'native_born': 'bool',
                       'native_job_state': 'job_state',
                       'original_pid': 'u32',
                       'original_start': 'u64',
                       'postcompletion_inventory_polls': 'u32',
                       'postcompletion_inventory_preserved': 'bool',
                       'query_sequences': 'sequences2|null',
                       'registered_native_slots': 'u64',
                       'request': 'bytes32',
                       'requested_at': 'f64',
                       'result': 'WireguardResult'},
 'OperationalReservation': {'global_transferred_ticket_limit': 'u64',
                            'member': 'str',
                            'member_transfer_pending': 'bool',
                            'original_jobs': 'u64',
                            'owner_epoch': 'OwnerEpoch',
                            'suffix_complete': 'bool',
                            'suffix_failed': 'bool',
                            'suffix_jobs': 'u64'},
 'OriginalWriter': {'index': 'u64', 'pid': 'u32', 'start': 'u64'},
 'OwnerProbe': {'component_only': 'bool', 'mode': 'str', 'nonce': 'str', 'unit': 'str'},
 'OwnerProbeRow': {'owner_probe': 'OwnerProbe'},
 'Preparation': {'attachment': 'Attachment',
                 'base_network': 'Identity',
                 'base_network_absent': 'bool',
                 'birth': 'Birth',
                 'bootstrap': 'list(BootstrapHistory)',
                 'bootstrap_queries': 'queries3',
                 'canonical_owner_epoch': 'OwnerEpoch',
                 'canonical_pending': 'bool',
                 'canonical_result_present': 'bool',
                 'data_network': 'Identity',
                 'deadline': 'f64',
                 'entry_attempt_absent': 'bool',
                 'entry_links_absent': 'bool',
                 'entry_phase': 'entry_phase',
                 'entry_producer': 'EntryProducer|null',
                 'entry_producer_absent': 'bool',
                 'entry_terminal_absent': 'bool',
                 'fresh_transport': 'FreshTransport|null',
                 'host_link': 'list(HostLinkHistory)',
                 'inspection': 'InspectionHistory',
                 'member': 'str',
                 'member_native_jobs_collected': 'bool',
                 'movement_query': 'InspectionHistory|null',
                 'mutation_fenced': 'bool',
                 'native_children_reaped': 'bool',
                 'netfilter': 'list(NetfilterHistory)',
                 'owner_host_anchor_present': 'bool',
                 'pending_bootstrap': 'null',
                 'pending_host_link': 'null',
                 'pending_producer_binding': 'null',
                 'pending_producer_creation': 'null',
                 'pending_wireguard': 'null',
                 'producer_binding': 'ProducerBindingHistory|null',
                 'producer_binding_query': 'InspectionHistory|null',
                 'producer_creation': 'ProducerCreationHistory|null',
                 'producer_query': 'InspectionHistory|null',
                 'quarantine_query': 'InspectionHistory|null',
                 'requested_at': 'f64',
                 'service_reserved': 'bool',
                 'transport_network': 'Identity|null',
                 'wireguard': 'list(MovementHistory|WireguardHistory)',
                 'writers': 'list(Writer)'},
 'ProducerBinding': {'assembly': 'Assembly',
                     'assembly_context_retained_after_drop': 'bool',
                     'canonical_negative_checks': 'u64',
                     'canonical_producer_published': 'bool',
                     'charges_after_drop': 'null',
                     'charges_before': 'list(u64)',
                     'charges_before_drop': 'list(u64)',
                     'continued_original_context': 'bool',
                     'failed_constructor': 'null',
                     'failure_retry': 'null',
                     'fault': 'u8',
                     'final_process_verified_at': 'f64',
                     'health_ready_authorized': 'bool',
                     'host_network_links_or_routes_created': 'bool',
                     'movement_context_retained_after_drop': 'bool',
                     'multi_exit_runtime_proven': 'bool',
                     'observation': 'ProducerObservation',
                     'original_group': 'Identity',
                     'original_provision_context_retained_after_drop': 'bool',
                     'parent_pristine': 'bool',
                     'placement_authorized': 'bool',
                     'preparation': 'Preparation',
                     'producer_binding_context_retained_after_drop': 'bool',
                     'producer_context_retained_after_drop': 'bool',
                     'producer_exception_authorized': 'bool',
                     'quarantine_context_retained_after_drop': 'bool',
                     'query': 'Query',
                     'requirement8_complete': 'bool',
                     'resource_cleanup_authorized': 'bool',
                     'result_writer_held': 'bool',
                     'retained_result_writer': 'null',
                     'same_original_source': 'bool',
                     'schema': 'u64',
                     'unacknowledged_observation_retained': 'bool',
                     'up_authorized': 'bool',
                     'whole_chain_retained_after_drop': 'bool'},
 'ProducerObservation': {'accepted_at': 'f64',
                         'acknowledged': 'bool',
                         'actual_wait_status': 'i32',
                         'birth': 'Birth',
                         'borrowed_registration_count': 'u64',
                         'complete_native_registration': 'bool',
                         'context_retained': 'bool',
                         'data': 'Identity',
                         'deadline': 'f64',
                         'durable_birth_released': 'bool',
                         'eof': 'bool',
                         'group': 'Identity',
                         'name': 'str',
                         'native_born': 'bool',
                         'native_job_state': 'job_state',
                         'original_pid': 'u32',
                         'original_registration_slots_verified': 'bool',
                         'original_start': 'u64',
                         'parent': 'Identity',
                         'pins': 'pins6',
                         'placement_authorized': 'bool',
                         'policy': 'bytes32',
                         'producer_exception_authorized': 'bool',
                         'query': 'bytes32',
                         'registered_native_slots': 'u64',
                         'request': 'bytes32',
                         'requested_at': 'f64',
                         'result': 'ProducerBindingResult',
                         'up_authorized': 'bool'},
 'ProducerWitness': {'acknowledged': 'bool',
                     'actual_wait_status': 'i32',
                     'birth': 'Birth',
                     'context_retained': 'bool',
                     'data': 'Identity',
                     'deadline': 'f64',
                     'durable_birth_released': 'bool',
                     'eof': 'bool',
                     'full_descriptor_registration': 'bool',
                     'group': 'Identity',
                     'name': 'str',
                     'native_born': 'bool',
                     'native_job_state': 'job_state',
                     'operational_publication': 'bool',
                     'original_pid': 'u32',
                     'original_start': 'u64',
                     'parent': 'Identity',
                     'parent_death_lock_survival_claimed': 'bool',
                     'query': 'bytes32',
                     'received_original_group': 'bool',
                     'registered_native_slots': 'u64',
                     'request': 'bytes32',
                     'requested_at': 'f64',
                     'verified_at': 'f64'},
 'ProfileMetadata': {'device': 'u64',
                     'device_public_key': 'bytes32',
                     'gid': 'u64',
                     'inode': 'u64',
                     'member': 'str',
                     'mode': 'u32',
                     'path': 'str',
                     'size': 'u64',
                     'uid': 'u64'},
 'Provision': {'attachment': 'AttachmentWitness',
               'continued_original_context': 'bool',
               'failed_constructor': 'null',
               'fault': 'u8',
               'held_real_result_writer': 'bool',
               'host_resources_created': 'bool',
               'operational_reuse_authorized': 'bool',
               'operations': 'list(MovementOperation)',
               'original_socket_registrations_borrowed': 'bool',
               'parent_pristine': 'bool',
               'preparation': 'Preparation',
               'requirement8_complete': 'bool',
               'same_service_retained': 'bool',
               'schema': 'u64',
               'transport_creation': 'TransportWitness',
               'transport_distinct_from_host_and_data': 'bool',
               'transport_mount': 'MountWitness',
               'unacknowledged_native_result_retained': 'bool',
               'whole_context_retained_after_drop': 'bool',
               'wireguard_down_only': 'bool'},
 'Quarantine': {'continued_original_context': 'bool',
                'failed_constructor': 'null',
                'fault': 'u8',
                'final_process_verified_at': 'f64',
                'held_real_result_writer': 'bool',
                'host_network_links_or_routes_created': 'bool',
                'initial_quarantine_installation_observed_all_scopes': 'bool',
                'initial_quarantine_only': 'bool',
                'movement': 'Movement',
                'movement_context_retained_after_drop': 'bool',
                'operational_reuse_authorized': 'bool',
                'operations': 'list(QuarantineOperation)',
                'original_provision_context_retained_after_drop': 'bool',
                'own_intent_polling': 'QuarantineIntent',
                'parent_pristine': 'bool',
                'preparation': 'Preparation',
                'producer': 'ProducerWitness',
                'producer_context_retained_after_drop': 'bool',
                'producer_exceptions_authorized': 'bool',
                'producer_group_creation_observed': 'bool',
                'producer_operational_publication': 'bool',
                'producer_query': 'Query',
                'quarantine_context_retained_after_drop': 'bool',
                'quarantine_query': 'Query',
                'requirement8_complete': 'bool',
                'same_service_retained': 'bool',
                'schema': 'u64',
                'unacknowledged_native_result_retained': 'bool',
                'up_authorized': 'bool',
                'wan': 'Wan',
                'whole_chain_retained_after_drop': 'bool'},
 'QuarantineHostDeclaration': {'allocation_digest': 'str',
                               'deployment_id': 'str',
                               'generation': 'u64',
                               'host_namespace': 'Identity',
                               'member': 'str',
                               'schema_version': 'u64',
                               'wan': 'WanDeclaration'},
 'QuarantineHostMetadata': {'authored_public_input_only': 'bool',
                            'builder_sha256': 'str',
                            'bytes': 'u64',
                            'declaration': 'QuarantineHostDeclaration',
                            'host_authority_granted': 'bool',
                            'native_validation_performed_by_controller': 'bool',
                            'sha256': 'str'},
 'QuarantineHostRow': {'secret_quarantine_host': 'QuarantineHostMetadata'},
 'QuarantineIntent': {'actual_wait_status': 'i32',
                      'deadline': 'f64',
                      'held_pending_polls': 'u64',
                      'negative_checks': 'u64',
                      'original_writer': 'OriginalWriter',
                      'queued_polls': 'u64',
                      'requested_at': 'f64',
                      'verified_at': 'f64'},
 'QuarantineOperation': {'accepted_at': 'f64',
                         'acknowledged': 'bool',
                         'actual_wait_status': 'i32',
                         'birth': 'Birth',
                         'borrowed_registration_count': 'u64',
                         'context_retained': 'bool',
                         'deadline': 'f64',
                         'full_descriptor_registration': 'bool',
                         'kind': 'netfilter_kind',
                         'native_born': 'bool',
                         'native_job_state': 'job_state',
                         'original_pid': 'u32',
                         'original_start': 'u64',
                         'registered_native_slots': 'u64',
                         'request': 'bytes32',
                         'requested_at': 'f64',
                         'result': 'NetfilterResult',
                         'scope': 'scope'},
 'Query': {'actual_wait_status': 'i32',
           'birth': 'Birth',
           'deadline': 'f64',
           'facts': 'QueryFacts',
           'handler_identity_claimed': 'bool',
           'kind': 'query_kind',
           'listener_origin_gid': 'u32',
           'listener_origin_pid': 'i32',
           'listener_origin_uid': 'u32',
           'original_peer_receipt': 'bool',
           'requested_at': 'f64',
           'verified_at': 'f64'},
 'Resource': {'actual_wait_status': 'i32',
              'fully_retired': 'bool',
              'kind': 'job_kind',
              'launch_charge_retired': 'bool',
              'lower_charge_required': 'bool',
              'lower_charge_retired': 'bool|null',
              'lower_gated_retirement_refused': 'bool|null',
              'native_job_state': 'job_state',
              'original_pid': 'u32',
              'original_start': 'u64',
              'transfer_started': 'bool'},
 'RunRecord': {'actual_gateway_is_inert': 'bool',
               'artifact_sha256': 'str',
               'baseline_declaration_builder_sha256': 'str',
               'baseline_reconciliation_sha256': 'str',
               'component_test_mode': 'str',
               'context_checker_sha256': 'str',
               'context_sha256': 'str',
               'exit_code': 'u64',
               'guest_boot_id': 'str',
               'guest_sha256': 'str',
               'host_baseline_template_sha256': 'str',
               'host_declaration_builder_sha256': 'str',
               'namespace_or_container_fixture': 'bool',
               'observed_at_utc': 'str',
               'platform': 'str',
               'production_changes': 'bool',
               'provider_profiles_used': 'bool',
               'real_client_acceptance': 'str',
               'result': 'str',
               'run_reservation': 'RunReservationReference',
               'runner_sha256': 'str',
               'source_archive_sha256': 'str',
               'source_binding': 'SourceBinding',
               'stderr': 'str',
               'stdout': 'str',
               'wall_seconds': 'f64'},
 'RunReservationReference': {'claim': 'str',
                             'continuity': 'str',
                             'historical_raw_records_recovered': 'bool',
                             'path': 'str',
                             'sha256': 'str'},
 'SourceBinding': {'source_aggregate_sha256': 'str',
                   'source_archive_sha256': 'str',
                   'source_commit': 'str',
                   'tracked_build_inputs_verified': 'u64'},
 'Staging': {'architecture': 'str',
             'artifact_kind': 'str',
             'artifact_path': 'str',
             'artifact_sha256': 'str',
             'artifact_size': 'u64',
             'content_id': 'str',
             'image_ref': 'str',
             'os': 'str',
             'schema_version': 'u64',
             'worker_path': 'str'},
 'TransportWitness': {'actual_wait_status': 'i32',
                      'birth': 'Birth',
                      'data': 'Identity',
                      'deadline': 'f64',
                      'durable_birth_released': 'bool',
                      'eof': 'bool',
                      'host': 'Identity',
                      'original_source_retained': 'bool',
                      'request': 'bytes32',
                      'requested_at': 'f64',
                      'source': 'Identity',
                      'verified_at': 'f64'},
 'UnavailableObservation': {'errno': 'u64', 'status': 'str'},
 'ValidatorWitness': {'actual_wait_status': 'i32', 'birth': 'Birth'},
 'Wan': {'address': 'mac6',
         'deadline': 'f64',
         'declaration_digest': 'bytes32',
         'host_namespace': 'Identity',
         'index': 'u32',
         'name': 'str',
         'original_observer_retained': 'bool',
         'requested_at': 'f64',
         'verified_at': 'f64'},
 'WanDeclaration': {'address': 'list(u64)', 'index': 'u64', 'name': 'str'},
 'Writer': {'actual_wait_status': 'i32',
            'io_deadline': 'f64',
            'parent_deadline': 'f64',
            'phase': 'str',
            'pid': 'u32',
            'queued_at': 'f64',
            'start': 'u64',
            'verified_at': 'f64'}}

COMPLETED_FIELDS = {'Address': ['address', 'flags', 'index', 'prefix', 'scope'],
 'Attachment': ['birth',
                'deadline',
                'directory',
                'mounted_at',
                'name',
                'origin',
                'placeholder',
                'published_at',
                'query',
                'request',
                'requested_at',
                'source'],
 'Birth': ['born_at', 'deadline', 'pid', 'start'],
 'BootstrapHistory': ['birth',
                      'creation',
                      'deadline',
                      'group',
                      'namespace',
                      'pins',
                      'policy',
                      'query',
                      'request',
                      'requested_at',
                      'result',
                      'scope',
                      'verified_at'],
 'BootstrapResult': ['group', 'namespace', 'observed_at', 'pins', 'policy'],
 'EntryProducer': ['binding', 'group', 'parent'],
 'FreshTransport': ['birth',
                    'data',
                    'deadline',
                    'directory',
                    'host',
                    'mount',
                    'name',
                    'request',
                    'requested_at',
                    'source',
                    'verified_at'],
 'HostBaseline': ['addresses', 'links', 'namespace', 'routes', 'rules'],
 'HostLinkHistory': ['admission',
                     'birth',
                     'deadline',
                     'declaration',
                     'host',
                     'kind',
                     'namespace',
                     'request',
                     'requested_at',
                     'result',
                     'verified_at'],
 'HostLinkResult': ['namespace'],
 'Identity': ['dev', 'ino'],
 'InspectionHistory': ['birth', 'deadline', 'facts', 'kind', 'request', 'requested_at', 'verified_at'],
 'InspectionInitial': ['birth', 'facts', 'request', 'verified_at'],
 'Link': ['alias',
          'all_multicast',
          'alternate_names',
          'controller',
          'hardware_type',
          'index',
          'kind',
          'mtu',
          'name',
          'port_kind',
          'promiscuity',
          'tun_info',
          'up'],
 'MountHistory': ['birth',
                  'deadline',
                  'directory',
                  'mounted_at',
                  'name',
                  'placeholder',
                  'published_at',
                  'request',
                  'requested_at',
                  'source'],
 'NetfilterHistory': ['birth',
                      'configuration',
                      'deadline',
                      'host_declaration',
                      'kind',
                      'namespace',
                      'policy',
                      'request',
                      'requested_at',
                      'result',
                      'scope',
                      'verified_at'],
 'NetfilterResult': ['namespace', 'policy'],
 'OwnerEpoch': ['boot', 'cgroup', 'invocation', 'pid', 'start', 'unit'],
 'Placeholder': ['identity', 'mode'],
 'ProducerBindingHistory': ['birth',
                            'creation',
                            'data',
                            'deadline',
                            'group',
                            'name',
                            'parent',
                            'pins',
                            'policy',
                            'query',
                            'request',
                            'requested_at',
                            'result',
                            'verified_at'],
 'ProducerBindingResult': ['group', 'namespace', 'observed_at', 'pins', 'policy'],
 'ProducerCreationHistory': ['birth',
                             'data',
                             'deadline',
                             'group',
                             'name',
                             'parent',
                             'query',
                             'request',
                             'requested_at',
                             'verified_at'],
 'QueryFacts': ['pid', 'security'],
 'Route': ['destination',
           'flags',
           'kind',
           'metric',
           'output',
           'preference',
           'prefix',
           'protocol',
           'scope',
           'table'],
 'Rule': ['action', 'flags', 'ipv6', 'priority', 'protocol', 'suppress_prefixlen', 'table'],
 'Wireguard': ['index', 'name', 'peers', 'public_key'],
 'WireguardHistory': ['birth',
                      'configuration',
                      'deadline',
                      'kind',
                      'namespace',
                      'request',
                      'requested_at',
                      'result',
                      'verified_at'],
 'WireguardPeer': ['allowed_ips', 'endpoint', 'handshake_unix', 'public_key'],
 'WireguardResult': ['namespace']}

PROJECTION_ENUMS = {'daemon_security': ('AppArmorBuiltinSeccomp', 'BuiltinSeccomp'),
 'entry_phase': ('creating', 'offline', 'activating', 'bootstrap'),
 'host_kind': ('transport_sockets', 'pair', 'host_sockets', 'move'),
 'job_kind': ('Journal',
              'HostAudit',
              'RetirementStop',
              'RetirementCleanup',
              'SecretValidation',
              'DockerInspection',
              'NamespaceAttachment',
              'FreshTransport',
              'FreshTransportMount',
              'WireguardSecret',
              'FixedNetfilter',
              'FixedVeth',
              'ProducerCreation'),
 'job_state': ('prepared', 'born', 'no_birth', 'collected', 'transferred_resources'),
 'netfilter_kind': ('sockets', 'initial_quarantine'),
 'origin_kind': ('existing_admitted',),
 'query_kind': ('Initial',
                'Recheck',
                'AttachmentRecheck',
                'MovementRecheck',
                'QuarantineRecheck',
                'ProducerRecheck',
                'ProducerBindingRecheck',
                'BootstrapHostRecheck',
                'BootstrapTransportRecheck',
                'BootstrapDataRecheck'),
 'scope': ('host', 'transport', 'data'),
 'wireguard_kind': ('sockets', 'provision', 'query', 'data_sockets', 'move')}


def masked(text):
    """Preserve offsets/newlines while hiding comments and string contents."""
    pattern = r'''//[^\n]*|/\*[\s\S]*?\*/|r(#+)?"[\s\S]*?"\1|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])' '''.strip()
    return re.sub(pattern, lambda m: ''.join('\n' if c == '\n' else ' ' for c in m[0]), text)


def close_at(text, start):
    opening = text[start]
    closing = {'(':')','[':']','{':'}'}[opening]
    depth = 1
    for i in range(start+1,len(text)):
        if text[i] == opening:
            depth += 1
        elif text[i] == closing:
            depth -= 1
            if depth == 0:
                return i
    raise ValueError('unbalanced Rust delimiter at '+str(start))


def split_top(text, separator=',', angles=True):
    depth, start, result = 0, 0, []
    for i,c in enumerate(text):
        if c in ('(<[{' if angles else '([{'):
            depth += 1
        elif c in (')>]}' if angles else ')]}'):
            depth -= 1
        elif c == separator and depth == 0:
            if text[start:i].strip():
                result.append(text[start:i].strip())
            start = i+1
    if text[start:].strip():
        result.append(text[start:].strip())
    return result


def normalized(text):
    return re.sub(r'\s+',' ',text).strip()


def attrs_before(text, start):
    before = text[:start]
    m = re.search(r'((?:\s*#\[[^\]]*\])+)\s*(?:pub(?:\([^)]*\))?\s+)?$',before)
    return re.findall(r'#\[([^\]]*)\]',m[1]) if m else []


def rust_type_tree(ty):
    ty = normalized(ty)
    if ty.startswith('Option<'):
        return dict(kind='option',inner=rust_type_tree(ty[7:-1]),nullable=True)
    if ty.startswith('Vec<'):
        return dict(kind='vector',inner=rust_type_tree(ty[4:-1]))
    if ty.startswith('['):
        item,length = split_top(ty[1:-1],';')
        return dict(kind='array',length=int(length),inner=rust_type_tree(item))
    if ty.startswith('('):
        return dict(kind='tuple',elements=[rust_type_tree(t) for t in split_top(ty[1:-1])])
    if re.fullmatch(r'[ui](8|16|32|64)|usize|isize',ty):
        return dict(kind='integer',width=64 if ty.endswith('size') else int(ty[1:]),signed=ty[0]=='i')
    return dict(kind='primitive' if ty in ('bool','f32','f64','String') else 'named',name=ty)


def source_files():
    # Broad conservative closure: preparation, all sub-emitters, native result
    # validators and their declaration/identity/plan modules. Include all .rs in
    # those trees so new modules cannot silently evade the drift test.
    result = set()
    for base in (LAUNCH+'owned/preparation', LAUNCH+'attachment', NETWORK):
        result.update(p for p in (ROOT/base).rglob('*.rs') if p.is_file())
    for name in ('owned/preparation.rs','attachment.rs','owned.rs','supervision.rs','kernel.rs','evidence.rs'):
        result.add(ROOT/(LAUNCH+name))
    for name in ('bootstrap','docker_query','fresh_transport','fresh_transport_mount',
                 'namespace_attachment','wireguard_role','netfilter_role','producer_creation',
                 'producer_binding','host_link'):
        result.add(ROOT/(LAUNCH+'kernel/'+name+'.rs'))
    result.update(ROOT/p for p in ('crates/vprouter-core/src/allocation.rs','crates/vprouter-core/src/config.rs'))
    return sorted(result)


# This is a conservative lexical may-call graph, not a Rust type checker. All
# same-named workspace implementations are followed (including trait impls),
# and local function items are followed even when passed rather than invoked.
# Unsupported calls fail generation. This cannot certify dynamic dispatch,
# proc-macro expansions, cfg selection or compiler-resolved import identities.
EXTERNAL_CALLS = {
    'std': set('as_ref as_mut as_deref as_deref_mut clone cloned copied copy_from_slice len is_empty iter iter_mut into_iter enumerate zip chain collect map map_err and_then or_else ok_or ok_or_else unwrap unwrap_or unwrap_or_else unwrap_or_default expect is_ok is_err is_some is_none take replace insert remove push pop clear retain contains contains_key get get_mut entry or_insert or_default extend extend_from_slice sort sort_by sort_by_key dedup binary_search filter filter_map find any all count sum fold next last first flatten flat_map for_each repeat to_vec to_string to_owned as_str as_bytes bytes chars lines split split_once split_whitespace trim strip_prefix strip_suffix starts_with ends_with eq ne cmp min max checked_add checked_sub checked_mul saturating_add saturating_sub wrapping_add wrapping_mul checked_duration_since duration_since elapsed checked_add as_secs_f64 as_secs as_millis as_nanos from_secs from_millis from_secs_f64 now is_finite is_ascii is_ascii_alphanumeric is_ascii_lowercase is_ascii_digit is_absolute components display parent file_name join starts_with into_owned into_inner into_raw as_raw_fd as_fd from_raw_fd as_ptr as_mut_ptr addr port ip octets is_ipv4 is_ipv6 is_unspecified is_loopback is_multicast parse from_str from_le_bytes to_le_bytes from_ne_bytes to_ne_bytes from_be_bytes to_be_bytes to_bits from_bits try_from try_into into from default new with_capacity with_hasher resize resize_with truncate reserve swap swap_remove reverse write write_all write_fmt flush read read_to_end read_to_string read_exact seek metadata canonicalize open create create_new set_len sync_all sync_data set_permissions set_read_timeout set_write_timeout try_clone connect bind send send_to recv recv_from local_addr peer_addr shutdown spawn wait wait_with_output kill status output args arg env envs env_clear current_dir stdin stdout stderr id exit abort drop size_of align_of forget transmute replace zeroed ptr_eq downgrade upgrade strong_count weak_count borrow borrow_mut try_borrow try_borrow_mut set get_or_insert get_or_insert_with get_or_default close fcntl getpid getuid geteuid pipe fork socketpair panic unreachable todo unimplemented assert assert_eq assert_ne debug_assert debug_assert_eq debug_assert_ne format format_args vec matches eprintln println print write writeln include_str include_bytes concat stringify cfg option_env env file line column Some None Ok Err Self'.split()),
    'rustix': set('fstat fstatfs stat statfs pread pwrite read write fcntl_getfl fcntl_getfd fcntl_setfd fcntl_setfl dup dup3 open openat openat2 mkdir mkdirat unlinkat renameat fsync flock fchmod fchown statx ioctl_fionread getsockopt socket socketpair recv recvmsg send sendmsg bind connect listen accept acceptfrom getsockname getpeername setns unshare mount umount2 pivot_root chroot setrlimit getrlimit setresuid setresgid setgroups getuid geteuid getgid getegid getpid getppid gettid kill waitpid waitid pipe_with fork execve exit_group prctl sigaction sigprocmask timerfd_create timerfd_settime poll epoll_create epoll_add epoll_del epoll_mod epoll_wait clock_gettime clock_getres'.split()),
    'serde': set('serialize deserialize serialize_seq serialize_element serialize_field serialize_struct end deserialize_seq deserialize_any deserialize_map deserialize_struct next_element next_key next_value custom to_vec to_writer to_string from_slice from_str json'.split()),
    'sha2': set('digest update finalize'.split()),
}

EXTERNAL_CALLS['std'].update('with is_some_and is_none_or as_slice ok borrow_raw from_utf8 ino raw_os_error dev is_ok_and transpose last_os_error not to_str revents null from_mut values position find_map skip map_or try_clone_to_owned write_str mode as_raw from_str_radix clearenv cast last_mut saturating_duration_since retain_mut from_raw uninit or null_mut args_os then_some sort_unstable fetch_add as_os_str push_str to_bytes remove_dir_all read_dir nth groups then temp_dir from_mode set_nonblocking try_from_secs_f64 windows is_private symlink_metadata read_link is_err_and remove_dir discriminant pointer_mut eq_ignore_ascii_case and is_zero inspect_err rsplit_once try_wait segments as_mut_slice keys rdev fchdir from_nanos to_string_lossy pop_front is_dir into_bytes chunks gid as_micros as_raw_nonzero split_at_mut from_ref cast_mut as_raw_pid is_ascii_hexdigit push_back headers fill with_extension front to_ascii_lowercase is_broadcast is_file try_fold map_or_else current_exe vars_os as_encoded_bytes once yield_now parse_chunk_size is_ascii_uppercase as_u16 sort_unstable_by_key from_iter fetch_update compare_exchange try_send try_lock create_dir_all is_ascii_graphic extension dedup_by sync_channel is_subset difference nlink is downcast_ref get_ref powi trim_end_matches subsec_nanos div_ceil from_fn is_multiple_of floor debug_struct finish_non_exhaustive from_utf8_lossy from_borrowed_fd from_ascii size_of_val take_error pointer try_exists values_mut cycle new_abstract_name chunks_exact_mut chunks_exact is_char_device file_type split_last len_utf8 encode_utf8 from_u32'.split())
EXTERNAL_CALLS['rustix'].update('fcntl_dupfd_cloexec from_raw_mode statat intersects repr socket_with bits cmsg_space major minor eventfd socket_domain socket_type socket_protocol socket_peercred sendto recvfrom pidfd_open socket_error open_tree ioctl memfd_create renameat_with fstatvfs pause clock_gettime_dynamic makedev readlink getgroups pipe2 move_mount accept4 accept_with'.split())
EXTERNAL_CALLS['serde'].update('duplicate_field missing_field as_array as_f64 as_u64 from_value as_bool to_value as_f64 is_f64 from_f64 to_vec_pretty as_i64 deserialize_string visit_borrowed_str is_boolean sort_all_objects serialize_u64 as_array_mut'.split())
EXTERNAL_CALLS.update({
 'libc': set('syscall WIFEXITED WEXITSTATUS WIFSIGNALED WTERMSIG sigemptyset sigtimedwait sigaddset _exit chdir kill_process'.split()),
 'tokio': set('timeout new_current_thread block_on enable_io enable_time changed from_std interval_at set_missed_tick_behavior timeout_at peer_cred unix_stream into_std call process_id unix_user_id enable_all set_nodelay'.split()),
 'crypto': set('x25519 default_provider builder_with_provider with_safe_default_protocol_versions with_no_client_auth with_root_certificates generate der builder with_single_cert self_signed signed_by serialize_der'.split()),
 'netlink-packet': set('ScmRights V4 V6 NewLink InnerMessage SetLink GetLink IfName LinkInfo GetAddress GetRoute Inet NewAddress NewRoute PrivateKey NetNsFd Mtu Flags from_payload IfAlias emit_value GetRule PublicKey IfIndex read_from Ipv4 DelLink Broadcast CacheInfo FamilyName AfSpecUnspec Destination Oif PrefSource Gateway Priority Inet6 IpAddr Cidr PresharedKey PersistentKeepalive Fwmark set_resolved_family_id Domain NewRule SuppressPrefixLen move_into_link_name_space sender RoutePriority Label FamilyId PortKind PortData BridgePort Tun Bridge Controller Promiscuity AllMulticast PropList AltIfName ProtoDown Xdp Attached DevlinkPort DpllPin PermAddress ParentDevName ParentDevBusName Qdisc TxQueueLen OperState Group NumTxQueues NumRxQueues Carrier CarrierChanges CarrierUpCount CarrierDownCount GsoMaxSegs GsoMaxSize MinMtu MaxMtu GroMaxSize TsoMaxSize TsoMaxSegs GsoIpv4MaxSize GroIpv4MaxSize Stats Stats64 Map LinkNetNsId NetnsImmutable Preference NhId LastHandshake RxBytes TxBytes ProtocolVersion ListenPort read_u32 try_parse FwMark FwMask SuppressIfGroup Goto Realm add_query query Known AddrGenMode WireguardPeer WireguardAllowedIp NewIfIndex'.split()),
 'http-dns': set('A CNAME method uri send_request get_all body_mut is_trailers into_data max_headers max_buf_size handshake is_parse is_user is_incomplete_message is_canceled'.split()),
 'Rust attribute/pattern syntax': set('derive allow cfg_attr serde Normal Ca break'.split()),
})

EXTERNAL_CALLS['std'].update('trim_matches rename symlink hard_link'.split())
EXTERNAL_CALLS['libc'].add('dup2')
EXTERNAL_CALLS['serde'].add('next_entry')
EXTERNAL_CALLS['netlink-packet'].add('value_len')
EXTERNAL_CALLS['http-dns'].add('header')
EXTERNAL_CALLS['memchr']={'memmem'}


def validation_call_graph(texts, root_files, require_complete=True):
    nodes, by_name = {}, {}
    for file,text in sorted(texts.items()):
        code=masked(text)
        candidates=functions(text)
        for m in re.finditer(r'\bmacro_rules!\s*(\w+)\s*\{',code):
            candidates.append(dict(name=m[1],start=m.start(),body=m.end()-1,end=close_at(code,m.end()-1),signature='macro_rules! '+m[1]))
        for f in candidates:
            f['is_test']=any(a.strip()=='test' for a in attrs_before(text,f['start']))
            identity=f'{file}:{text.count(chr(10),0,f["start"])+1}:{f["name"]}'
            f=dict(f,id=identity,file=file)
            nodes[identity]=f;by_name.setdefault(f['name'],[]).append(identity)
    for text in texts.values():
        for original,alias in re.findall(r'\b(\w+)\s+as\s+(\w+)',masked(text)):
            if original in by_name:
                by_name.setdefault(alias,[]).extend(by_name[original])
    known_roots=set(by_name)
    for manifest in (ROOT/'crates').glob('*/Cargo.toml'):
        package=tomllib.loads(manifest.read_text())
        for section in ('dependencies','dev-dependencies','build-dependencies'):
            known_roots.update(name.replace('-','_') for name in package.get(section,{}))
    known_roots.update(('Vec','String','Box','Option','Result','Default','char',
                        'std','core','alloc','rustix','libc','serde','serde_json','sha2','tokio','Self',
                        'u8','u16','u32','u64','usize','i8','i16','i32','i64','isize','f32','f64'))
    for file,text in texts.items():
        known_roots.update(re.findall(r'\b(?:struct|enum|type|mod|trait)\s+(\w+)',masked(text)))
        known_roots.update(re.findall(r'\b([A-Z]\w*)\s*:(?!:)',masked(text)))
        # Import aliases and grouped imports supply qualified roots. This is
        # still lexical; receiver/type identity remains explicitly unproved.
        for use in re.finditer(r'\buse\s+([^;]+);',masked(text)):
            known_roots.update(re.findall(r'\b[A-Za-z_]\w*\b',use[1]))
        for part in Path(file).parts:
            if part.startswith('vprouter-'):known_roots.add(part.replace('-','_'))
    roots=sorted(k for k,f in nodes.items() if f['file'] in root_files and not f.get('is_test'))
    visited=set();todo=list(roots);edges=[];unresolved=[]
    # All source constructors are resolved as syntax, never mistaken for helpers.
    constructors=set()
    for text in texts.values():
        code=masked(text)
        constructors.update(re.findall(r'\b(?:struct|enum|type)\s+(\w+)',code))
        for enum in re.finditer(r'\benum\s+\w+\s*\{',code):
            for item in split_top(code[enum.end():close_at(code,enum.end()-1)]):
                variant=re.match(r'(?:#\[[^]]*\]\s*)*(\w+)',item)
                if variant:constructors.add(variant[1])
    while todo:
        identity=todo.pop()
        if identity in visited:continue
        visited.add(identity);f=nodes[identity];text=texts[f['file']]
        body=masked(text[f['body']+1:f['end']])
        closures=set(re.findall(r'\blet\s+(?:mut\s+)?(\w+)\s*=\s*(?:move\s+)?\|',body))
        closures.update(re.findall(r'\blet\s+Some\((\w+)\)\s*=',body))
        parameters=set(re.findall(r'\b(\w+)\s*:\s*(?:impl\s+)?(?:Fn|F\b)',f['signature']))
        local_calls=[]
        for m in re.finditer(r'\b([A-Za-z_]\w*)\s*(?:(?:!\s*)|(?:::\s*<[^;{}]*?>\s*))?\(',body):
            name=m[1]
            if name in ('if','while','for','match','return','fn','let','loop','unsafe','extern'):continue
            if re.search(r'\bfn\s*$',body[max(0,m.start()-5):m.start()]):continue
            prefix=re.search(r'([A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)::$',body[:m.start()])
            qualified=prefix[1]+'::'+name if prefix else name
            if prefix and prefix[1].split('::')[0] not in known_roots and not re.search(r'\b'+re.escape(prefix[1].split('::')[0])+r'\b',f['signature']):
                local_calls.append((qualified,m.start()))
            else:
                local_calls.append((name,m.start()))
        # Resolve higher-order function items and macro bodies as a conservative
        # superset: lexical references to local functions become edges as well.
        called={n for n,_ in local_calls}
        for m in re.finditer(r'\b[A-Za-z_]\w*\b',body):
            if m[0] in by_name and m[0] not in called:
                local_calls.append((m[0],m.start()));called.add(m[0])
        for name,offset in local_calls:
            edge=dict(caller=identity,callee=name,line=text.count('\n',0,f['body']+1+offset)+1)
            if name in closures or name in parameters:
                edge.update(external='lexical closure/parameter',reason='Closure body is scanned in the containing function; generic Fn targets require compiler review.')
            elif name in by_name:
                edge['targets']=name;todo.extend(by_name[name])
            elif name in constructors:
                edge.update(external='Rust constructor syntax',reason='Value construction; not a function body. Enum/type identities are not compiler-resolved.')
            else:
                provider=next((p for p,names in EXTERNAL_CALLS.items() if name in names),None)
                if provider:
                    edge.update(external=provider,reason='Explicit external symbol inventory; body unavailable in workspace. Name-based resolution requires compiler review.')
                else:
                    unresolved.append(dict(edge));edge['unresolved']=True
            edges.append(edge)
    unique={}
    for edge in edges:
        key=(edge['caller'],edge['callee'])
        if key not in unique:unique[key]=edge
    edges=list(unique.values())
    graph=dict(dependency_manifests={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((ROOT/'crates').glob('*/Cargo.toml'))},target_sets={name:sorted(ids) for name,ids in sorted(by_name.items()) if any(i in visited for i in ids)},kind='conservative lexical may-call graph; NOT compiler closure proof',roots=roots,
               nodes=[{k:f[k] for k in ('id','name','file','signature')} for k,f in sorted(nodes.items()) if k in visited],
               edges=sorted(edges,key=lambda e:(e['caller'],e['line'],e['callee'])),unresolved=unresolved,
               limitations=['overloaded method and trait targets conservatively include all same-name implementations',
                            'external calls resolved by explicit symbol name, not receiver type',
                            'closures scanned lexically; generic Fn and dynamic dispatch not compiler-proven',
                            'proc macros, cfg, include expansions and import alias identity require compiler review'])
    if unresolved and require_complete:
        raise ValueError('unresolved validation callees: '+repr(unresolved[:30]))
    return graph


def atomic_predicates(expression):
    """Split boolean structure, retaining enclosing quantifier/polarity context.

    A match, call or unsupported Rust expression remains a pending atom. This
    is an inventory, not an evaluator or proof of semantic normal form.
    """
    result=[]
    def walk(value,context):
        value=value.strip();code=masked(value)
        while code and code[0] in '({' and close_at(code,0)==len(code)-1:
            value=value[1:-1].strip();code=masked(value)
        depth=0;start=0;pieces=[];i=0
        while i<len(code):
            if code[i] in '([{':i=close_at(code,i)+1;continue
            if code[i:i+2] in ('||','&&'):
                pieces.append(value[start:i]);start=i+2;i+=2;continue
            i+=1
        if pieces:
            pieces.append(value[start:])
            for piece in pieces:walk(piece,context+[normalized(value)])
            return
        # Closures inside iter().any/all are predicates with a quantifier.
        closure=re.search(r'\|(?:[^|]|\|\|)*?\|',code)
        if closure:
            # Find the first opening argument group containing the closure.
            begins=[i for i,c in enumerate(code[:closure.start()]) if c=='(' and close_at(code,i)>=closure.end()]
            if begins and re.search(r'\b(?:any|all|filter|find|position)\s*$',code[:begins[-1]]):
                end=close_at(code,begins[-1]);inner=value[closure.end():end].strip()
                if inner:
                    walk(inner,context+[normalized(value)]);return
        result.append(dict(expression=normalized(value),context=context))
    try:
        walk(expression,[])
    except ValueError as error:
        return [dict(expression=normalized(expression),context=[],syntax_unresolved=str(error))]
    return result


def serialization_index(contract):
    """Public field paths and emitter expressions; no observed record consulted."""
    result={}
    for key in contract['field_sources']:
        result.setdefault(key.rsplit('.',1)[-1],[]).append('field_sources:'+key)
    for builder in contract['json_builders']:
        for key,expression in builder['fields'].items():
            result.setdefault(key,[]).append(f'json_builders:{builder["file"]}:{builder["line"]}:{key}')
            for field in re.findall(r'\.\s*([A-Za-z_]\w*)\b(?!\s*\()',masked(expression)):
                result.setdefault(field,[]).append(f'json_builders:{builder["file"]}:{builder["line"]}:{key}={expression}')
    return {k:sorted(set(v)) for k,v in sorted(result.items())}


# Reviewed necessary public projections only. These annotations are deliberately
# not extrapolated to every field with the same spelling. Generic source-to-JSON
# def-use analysis is still missing and therefore withholds the complete claim.
SERIALIZED_PROJECTIONS = {'0df26af51ab07703279b': ['HostBaseline', 'Link'],
 '174fc9cdeafd09c23620': ['WanDeclaration',
                          'QuarantineHostDeclaration',
                          'Allocation',
                          'AllocationExit',
                          'Identity'],
 '189fb825268a7848d90c': ['WanDeclaration',
                          'QuarantineHostDeclaration',
                          'Allocation',
                          'AllocationExit',
                          'Identity'],
 '18a6bd9f2eb7ac520c83': ['HostBaseline', 'Link'],
 '1c84c14a78aaaf24a19b': ['Link'],
 '1d7723d139a47fbc0689': ['WanDeclaration',
                          'QuarantineHostDeclaration',
                          'Allocation',
                          'AllocationExit',
                          'Identity'],
 '27dffc5cc205d5a9a2e3': ['ProducerBindingHistory', 'ProducerBindingResult'],
 '281eb7f32266024621f1': ['HostBaseline', 'Link'],
 '2b5996af901fc1d48d99': ['WanDeclaration',
                          'QuarantineHostDeclaration',
                          'Allocation',
                          'AllocationExit',
                          'Identity'],
 '49189111d51923f14cb3': ['HostBaseline'],
 '4b967c4a190e596069f1': ['WanDeclaration',
                          'QuarantineHostDeclaration',
                          'Allocation',
                          'AllocationExit',
                          'Identity'],
 '4bb4e02af9996f098b46': ['Link'],
 '5409a4644ddeeaa8d0e4': ['WanDeclaration',
                          'QuarantineHostDeclaration',
                          'Allocation',
                          'AllocationExit',
                          'Identity'],
 '58a37ac8bd9cba1d4b5e': ['HostBaseline', 'Link'],
 '595abe5f1b2aceb3a46b': ['WanDeclaration',
                          'QuarantineHostDeclaration',
                          'Allocation',
                          'AllocationExit',
                          'Identity'],
 '5d782b5ab3f56cea23b6': ['HostBaseline', 'Link'],
 '6203fb73943d6ed610b0': ['WanDeclaration',
                          'QuarantineHostDeclaration',
                          'Allocation',
                          'AllocationExit',
                          'Identity'],
 '6605a6920812640e8be8': ['HostBaseline', 'Link'],
 '69f97ad4042afc0bfc8a': ['Link'],
 '6aa0fdff0aac04f01d01': ['Link'],
 '705b76140fbce87e8113': ['HostBaseline'],
 '7181849b73f3ba2ab893': ['Link'],
 '742acfbb590976810451': ['WanDeclaration',
                          'QuarantineHostDeclaration',
                          'Allocation',
                          'AllocationExit',
                          'Identity'],
 '80917945bf0b541fef17': ['WanDeclaration',
                          'QuarantineHostDeclaration',
                          'Allocation',
                          'AllocationExit',
                          'Identity'],
 '877c79dae70246045f06': ['HostBaseline', 'Link'],
 '88f0d880b81419ef46e3': ['HostBaseline', 'Link'],
 '8de1b1217bfc9647313b': ['Link'],
 '8e86d38dcde823037621': ['WanDeclaration',
                          'QuarantineHostDeclaration',
                          'Allocation',
                          'AllocationExit',
                          'Identity'],
 '8eb5f21fcb51977b6207': ['Link'],
 '9255b33211650f65d358': ['Link'],
 '9a9b7fdc4f89724ef5b8': ['WanDeclaration',
                          'QuarantineHostDeclaration',
                          'Allocation',
                          'AllocationExit',
                          'Identity'],
 'a33695bdf5772e1c6ea4': ['WanDeclaration',
                          'QuarantineHostDeclaration',
                          'Allocation',
                          'AllocationExit',
                          'Identity'],
 'a715e3b6511ddca36e94': ['WanDeclaration',
                          'QuarantineHostDeclaration',
                          'Allocation',
                          'AllocationExit',
                          'Identity'],
 'af93a4df5a610d2e4583': ['WanDeclaration',
                          'QuarantineHostDeclaration',
                          'Allocation',
                          'AllocationExit',
                          'Identity'],
 'b68c92ed64dd276d2f9a': ['WanDeclaration',
                          'QuarantineHostDeclaration',
                          'Allocation',
                          'AllocationExit',
                          'Identity'],
 'bc38d4da0d591e6ef705': ['WanDeclaration',
                          'QuarantineHostDeclaration',
                          'Allocation',
                          'AllocationExit',
                          'Identity'],
 'bc6d5d798292ec5b6c99': ['ProducerBindingHistory', 'ProducerBindingResult'],
 'be7a10b85d65230129c7': ['Link'],
 'ca3f7cd71b82cc76e868': ['Link'],
 'cf14d0e17c320e6b0f3f': ['HostBaseline', 'Link'],
 'd1d06eaace8c847f7276': ['HostBaseline', 'Link'],
 'd29468d858334bbe5d28': ['WanDeclaration',
                          'QuarantineHostDeclaration',
                          'Allocation',
                          'AllocationExit',
                          'Identity'],
 'e05cb7ecffd20753a083': ['HostBaseline', 'Link'],
 'fac2e6ecbb9e75ba9efb': ['Link'],
 'fc6fafb473083b5c9ca3': ['WanDeclaration',
                          'QuarantineHostDeclaration',
                          'Allocation',
                          'AllocationExit',
                          'Identity']}

def predicate_decidability(predicate,contract):
    """Fail closed: missing mapping is UNKNOWN, never evidence of absence.

    Live intrinsic searches produce candidates, never absence certificates. A field-name match
    supplies candidate serialized paths, not a def-use/type equivalence proof.
    All other expressions need manual/compiler lineage proof before disposition.
    """
    expression=predicate['expression'];code=masked(expression)
    lineage=contract.get('predicate_lineage',{}).get(predicate.get('id'))
    if lineage:
        if not lineage['field_sources'] or any(key not in contract['field_sources'] for key in lineage['field_sources']):
            raise ValueError('stale serialized predicate lineage: '+str(predicate.get('id')))
        return dict(status='serialized_projection',absence_proofs=[],lineage=lineage)
    index=contract.get('serialization_index') or serialization_index(contract)
    fields=sorted(set(re.findall(r'\.\s*([A-Za-z_]\w*|\d+)\b(?!\s*\()',code)))
    paths={f:index.get(f,[]) for f in fields}
    proofs=[]
    for pattern,value in ((r'\bstd::process::id\s*\(', 'std::process::id()'),
                          (r'\b(?:Rc|Weak)::ptr_eq\s*\(', 'Rc/Weak pointer identity'),
                          (r'\bInstant::now\s*\(', 'Instant::now()')):
        if re.search(pattern,code):
            # An emitter of the same intrinsic is insufficient to serialize the
            # fresh operand at validation time. Keep that case unresolved.
            emitters=[f'json_builders:{b["file"]}:{b["line"]}:{key}'
                      for b in contract['json_builders'] for key,expr in b['fields'].items() if re.search(pattern,masked(expr))]
            if not emitters:
                proofs.append(dict(value=value,serialization_paths=[],
                    search_domains=['field_sources','json_builders'],
                    reason='Fresh live intrinsic result/pointer identity has no serialized operand; historical PID/time fields cannot supply it.'))
    if proofs:
        return dict(status='requires_lineage_proof',absence_proofs=[],absence_candidates=proofs,field_paths=paths,
                    reason='Direct emitter search cannot exclude serialization through helper/alias paths.')
    # These names are only candidates. E.g. self.index in an unrelated native
    # struct is not automatically Link.index. Never equate them by spelling.
    return dict(status='requires_lineage_proof',absence_proofs=[],field_paths=paths)


def declarations(file, text):
    code = masked(text)
    result = []
    for m in re.finditer(r'\b(struct|enum)\s+(\w+)\s*\{',code):
        start,end = m.end()-1,close_at(code,m.end()-1)
        attrs = attrs_before(text,m.start())
        if not any('Serialize' in a for a in attrs) and (file,m[2]) not in ((LAUNCH+'kernel.rs','NativeJobKind'),(LAUNCH+'kernel.rs','NativeJobState')):
            continue
        body = text[start+1:end]
        fields,variants = {},[]
        cursor = 0
        for piece in split_top(re.sub(r'//[^\n]*|/\*[\s\S]*?\*/','',body)):
            field_attrs = re.findall(r'#\[([^\]]*)\]',piece)
            clean = re.sub(r'#\[[^\]]*\]','',piece).strip()
            line = text.count('\n',0,start+1+body.find(piece))+1
            if m[1] == 'struct':
                field = re.fullmatch(r'(?:pub(?:\([^)]*\))?\s+)?(\w+)\s*:\s*([\s\S]+)',clean)
                if not field:
                    raise ValueError(f'unsupported serde field {file}:{line}: {clean}')
                field_offset = re.search(r'\b'+re.escape(field[1])+r'\s*:',body[cursor:])
                if field_offset is None:
                    raise ValueError('cannot locate source field '+field[1])
                offset = cursor+field_offset.start()
                line = text.count('\n',0,start+1+offset)+1
                cursor = cursor+field_offset.end()
                ty = normalized(field[2])
                fields[field[1]] = dict(rust_type=ty,type_tree=rust_type_tree(ty),option=ty.startswith('Option<'),
                                       serde_attributes=field_attrs,line=line)
            else:
                variant = re.fullmatch(r'(\w+)(?:\s*=\s*\d+|\s*(\{[\s\S]*\}|\([\s\S]*\)))?',clean)
                if not variant:
                    raise ValueError(f'unsupported serde enum {file}:{line}: {clean}')
                rename = next((re.search(r'rename\s*=\s*"([^"]+)"',a)[1]
                               for a in field_attrs if re.search(r'rename\s*=\s*"([^"]+)"',a)),None)
                payload = variant[2] if variant.lastindex and variant.lastindex >= 2 else None
                payload_fields = {}
                if payload and payload.startswith('{'):
                    for item in split_top(payload[1:-1]):
                        key,ty = item.split(':',1)
                        ty = normalized(ty)
                        payload_fields[key.strip()] = dict(rust_type=ty,type_tree=rust_type_tree(ty),option=ty.startswith('Option<'))
                variants.append(dict(fields=payload_fields,payload=normalized(payload) if payload else None,name=variant[1],serialized=rename or variant[1],
                                     serde_attributes=field_attrs,line=line))
        result.append(dict(id=file+'::'+m[2],name=m[2],kind=m[1],file=file,
                           line=text.count('\n',0,m.start())+1,
                           serde_attributes=attrs,fields=dict(sorted(fields.items())),variants=variants))
    return result


def functions(text):
    code = masked(text)
    result = []
    # Function braces in arguments/generics are absent in this bounded source
    # grammar; bodies may contain arbitrarily nested blocks/closures/macros.
    for m in re.finditer(r'\bfn\s+(\w+)\s*(?:<[^;{]*?>)?\s*\(',code):
        args_start = code.index('(',m.start())
        args_end = close_at(code,args_start)
        cursor=args_end+1
        while cursor < len(code) and code[cursor] not in '{;':
            if code[cursor] in '([':
                cursor=close_at(code,cursor)+1
            else:
                cursor+=1
        if cursor == len(code) or code[cursor] == ';':
            continue
        body_start=cursor
        result.append(dict(name=m[1],start=m.start(),body=body_start,end=close_at(code,body_start),
                           signature=normalized(text[m.start():body_start])))
    return result


def guards_in(file,text):
    code = masked(text)
    funcs = functions(text)
    guards = []
    def emit(start,end,kind):
        owners = [f for f in funcs if f['body'] < start < f['end']]
        if not owners:
            return
        owner = min(owners,key=lambda f:f['end']-f['start'])
        # Exclude actual #[test] functions, not cfg(test) lab emitters/oracles.
        if any(a.strip() == 'test' for a in attrs_before(text,owner['start'])):
            return
        expression = normalized(text[start:end])
        # Retain full expression and all field selectors, including tuple fields
        # and quoted JSON keys; receiver method names are not called fields.
        fields = sorted(set(re.findall(r'\.\s*([A-Za-z_]\w*|\d+)\b(?!\s*\()',masked(expression))) |
                        set(re.findall(r'\[\s*"([^"]+)"\s*\]',expression)))
        identity = f'{file}:{text.count(chr(10),0,start)+1}:{kind}:{expression}'
        guards.append(dict(id=hashlib.sha256(identity.encode()).hexdigest()[:20],kind=kind,
                           file=file,line=text.count('\n',0,start)+1,function=owner['name'],
                           expression=expression,fields=fields))
    # Parse conditional bodies independently of nested if/match expressions.
    # This avoids swallowing a later sibling guard or losing a guard nested in
    # an if-let body. Strings/comments retain byte offsets through masking.
    def if_body(begin):
        pos = begin
        while pos < len(code):
            if code[pos] in '([':
                pos = close_at(code,pos)+1
            elif re.match(r'if\b',code[pos:]):
                nested = if_body(pos+2)
                if nested is None:
                    return None
                pos = close_at(code,nested)+1
                tail = re.match(r'\s*else\s*',code[pos:])
                if tail:
                    pos += tail.end()
                    if code[pos] == '{':
                        pos = close_at(code,pos)+1
                    elif code[pos:pos+2] == 'if':
                        # The scanner handles the next nested if expression.
                        continue
            elif re.match(r'match\b',code[pos:]):
                block = code.find('{',pos)
                if block < 0:
                    return None
                pos = close_at(code,block)+1
            elif code[pos] == '{':
                end = close_at(code,pos)
                # An explicit block expression is legal in comparisons. A
                # statement body is followed by else/sibling/closing scope.
                if re.match(r'\s*(?:[!=<>]=?|\|\||&&|[.?])',code[end+1:]):
                    pos = end+1
                else:
                    return pos
            elif code[pos] in ';})]':
                return None
            else:
                pos += 1
        return None
    condition_spans = []
    for m in re.finditer(r'\bif\s+',code):
        # A nested if used as a value is not a second conditional early return.
        if any(a <= m.start() < b for a,b in condition_spans):
            continue
        pos = m.end()
        while pos < len(code):
            if code[pos] in '([':
                pos = close_at(code,pos)+1
            elif code[pos:pos+2] == '=>':
                emit(m.end(),pos,'match_guard')
                break
            elif code[pos] in ';{})]':
                break
            else:
                pos += 1
        body = if_body(m.end())
        if body is not None:
            end = close_at(code,body)
            if re.match(r'\s*return\s+Err\b',code[body+1:end]):
                emit(m.end(),body,'if_return_err')
                condition_spans.append((m.end(),body))
    # Macro/function assertions and require/ensure calls. Include method guards
    # and Result-returning validation calls (native capability calls are explicit
    # offline limits). An unsupported/new expression gets a new unmapped ID.
    for m in re.finditer(r'\b(?:assert(?:_eq|_ne)?|debug_assert(?:_eq|_ne)?|require\w*|ensure\w*|verify\w*|validate\w*)\s*!?\s*\(',code):
        pos = code.index('(',m.start())
        end = close_at(code,pos)
        if re.search(r'\bfn\s*$',code[max(0,m.start()-4):m.start()]):
            continue
        begin = m.start()
        cursor = begin-1
        if cursor >= 0 and code[cursor] == '.':
            # Recover the complete receiver, balancing chained call/index
            # groups backwards. It is part of the original guard expression.
            while cursor >= 0:
                char = code[cursor]
                if char in ')]':
                    opening = '(' if char == ')' else '['
                    depth = 1; cursor -= 1
                    while cursor >= 0 and depth:
                        depth += (code[cursor] == char) - (code[cursor] == opening)
                        cursor -= 1
                elif char.isalnum() or char in '_ .\n\t?&':
                    cursor -= 1
                else:
                    break
            begin = cursor+1
            while begin < m.start() and code[begin].isspace():
                begin += 1
        emit(begin,end+1,'call')
    return sorted({g['id']:g for g in guards}.values(),key=lambda g:(g['file'],g['line'],g['id']))


def json_builders(file,text):
    code = masked(text)
    result = []
    for m in re.finditer(r'\bjson!\s*\(',code):
        start = code.index('(',m.start())
        end = close_at(code,start)
        content = text[start+1:end].strip()
        if not content.startswith('{'):
            continue
        entries = {}
        for entry in split_top(content[1:-1],angles=False):
            field = re.match(r'"([^"]+)"\s*:\s*([\s\S]+)$',entry)
            if not field:
                raise ValueError(f'unsupported JSON builder {file}: {entry}')
            entries[field[1]] = normalized(field[2])
        result.append(dict(file=file,line=text.count('\n',0,m.start())+1,
                           fields=dict(sorted(entries.items()))))
    return result


def plain_type(file,name,field):
    text = (ROOT/file).read_text()
    code = masked(text)
    m = re.search(r'\bstruct\s+'+re.escape(name)+r'\s*\{',code)
    if m is None:
        raise ValueError('missing source struct '+file+'::'+name)
    start = m.end()-1
    body = text[start+1:close_at(code,start)]
    field_match = re.search(r'\b'+re.escape(field)+r'\s*:\s*([^;\n]+)',body)
    if field_match is None:
        raise ValueError('missing source field '+name+'.'+field)
    # A nested array type may contain semicolons, so take the full source line.
    line = body[field_match.start():].splitlines()[0]
    return normalized(line.split(':',1)[1].rstrip().removesuffix(','))


ENUM_ROOTS = {
    'scope': (LAUNCH+'attachment/quarantine.rs','Scope'),
    'netfilter_kind': (LAUNCH+'attachment/quarantine.rs','Kind'),
    'wireguard_kind': (LAUNCH+'attachment/provision.rs','Kind'),
    'host_kind': (LAUNCH+'attachment/host_addition/operation.rs','Kind'),
    'query_kind': (LAUNCH+'attachment.rs','QueryKind'),
    'entry_phase': (LAUNCH+'owned.rs','Phase'),
    'daemon_security': (LAUNCH+'evidence.rs','DaemonSecurity'),
    'origin_kind': (LAUNCH+'attachment.rs','Origin'),
    'exit_mode': ('crates/vprouter-core/src/config.rs','ExitMode'),
    'job_kind': (LAUNCH+'kernel.rs','NativeJobKind'),
    'job_state': (LAUNCH+'kernel.rs','NativeJobState'),
}


def extract():
    root_files={str(p.relative_to(ROOT)) for p in source_files()}
    workspace_texts={str(p.relative_to(ROOT)):p.read_text() for p in (ROOT/'crates').rglob('*.rs')}
    graph=validation_call_graph(workspace_texts,root_files)
    reached_files=root_files | {node['file'] for node in graph['nodes']}
    texts={file:workspace_texts[file] for file in sorted(reached_files)}
    decls = [d for file,text in texts.items() for d in declarations(file,text)]
    by_id = {d['id']:d for d in decls}
    schemas = json.loads(json.dumps(SUCCESS_ADAPTERS))
    schemas['HostIntentPolling'] = dict(schemas['IntentPolling'],queued_polls='u32',held_pending_polls='u32')
    schemas['HostAddition']['own_intent_polling'] = 'HostIntentPolling'
    enums = dict(PROJECTION_ENUMS)
    aliases = {(file,name):schema for file,name,schema in TYPE_ROOTS}
    aliases[(LAUNCH+'owned/preparation/wireguard.rs','History')] = 'MovementHistory'
    replacements = {'String':'str','bool':'bool','f64':'f64','usize':'usize',
                    'IpAddr':'ip','Ipv4Addr':'ipv4_text','SocketAddr':'socket_address',
                    'Identity':'Identity','ValidationBirth':'Birth','QueryFacts':'QueryFacts',
                    'OwnerDomainRecord':'OwnerEpoch','ProducerOwnership':'EntryProducer',
                    'vprouter_network::Link':'Link','vprouter_network::Wireguard':'Wireguard',
                    'ExitAllocation':'AllocationExit','ExitMode':'exit_mode','PathBuf':'str','Wan':'WanDeclaration','Shape':'HostBaseline',
                    'Link':'Link','Address':'Address','Route':'Route','Rule':'Rule','Peer':'WireguardPeer'}
    def type_spec(ty,file,schema,field):
        ty = normalized(ty)
        if ty.startswith('Option<'):
            return type_spec(ty[7:-1],file,schema,field)+'|null'
        if ty.startswith('Vec<'):
            return 'list('+type_spec(ty[4:-1],file,schema,field)+')'
        if ty.startswith('['):
            inner,size = split_top(ty[1:-1],';')
            return 'array('+size+','+type_spec(inner,file,schema,field)+')'
        if ty.startswith('('):
            return 'tuple('+','.join(type_spec(t,file,schema,field) for t in split_top(ty[1:-1]))+')'
        if re.fullmatch(r'[ui](?:8|16|32|64)|usize|isize',ty):
            return ty
        if ty in replacements:
            return replacements[ty]
        if ty.startswith(('crate::','vprouter_network::')) and ty.split('::')[-1] in replacements:
            return replacements[ty.split('::')[-1]]
        if ty == 'Kind':
            return {'InspectionHistory':'query_kind','HostLinkHistory':'host_kind','WireguardHistory':'wireguard_kind',
                    'MovementHistory':'wireguard_kind','NetfilterHistory':'netfilter_kind'}[schema]
        if ty == 'Scope':
            return 'scope'
        if ty == 'QueryKind':
            return 'query_kind'
        if ty.split('::')[-1] == 'DaemonSecurity':
            return 'daemon_security'
        if ty == 'PublicResult':
            return {'BootstrapHistory':'BootstrapResult','ProducerBindingHistory':'ProducerBindingResult',
                    'WireguardHistory':'WireguardResult','MovementHistory':'WireguardResult',
                    'HostLinkHistory':'HostLinkResult','NetfilterHistory':'NetfilterResult'}[schema]
        if ty == 'Origin':
            return 'AttachmentOrigin'
        if ty == 'Placeholder':
            return 'Placeholder'
        if ty == 'Initial':
            return 'InspectionInitial'
        # Explicit module selectors mirror Rust imports, not field/width maps.
        parts = ty.split('::')
        if len(parts) == 2:
            target = LAUNCH+'owned/preparation/'+parts[0]+'.rs'
            if (target,parts[1]) in aliases:
                return aliases[target,parts[1]]
        raise ValueError(f'unresolved serialized type {file} {schema}.{field}: {ty}')
    field_sources = {}
    for file,name,schema in TYPE_ROOTS:
        decl = by_id[file+'::'+name]
        fields = {}
        for key,field in decl['fields'].items():
            spec = type_spec(field['rust_type'],file,schema,key)
            # The emitted successful profile narrows Option fields to completed
            # values. Exact Option/skip/default attributes remain in declarations.
            old = key in COMPLETED_FIELDS.get(schema,[])
            if old and field['option']:
                spec = spec.removesuffix('|null')
            fields[key] = spec
            field_sources[schema+'.'+key] = dict(declaration=decl['id'],**field)
        if schema == 'WireguardHistory':
            # Serde skip_serializing_if omits these fields in the first 4 stages.
            fields.pop('destination')
            fields.pop('movement_query')
        schemas[schema] = fields
    # Same Rust History; the move stage requires both optional extension fields.
    wg = by_id[LAUNCH+'owned/preparation/wireguard.rs::History']
    schemas['MovementHistory'] = {k:type_spec(f['rust_type'],wg['file'],'MovementHistory',k).removesuffix('|null')
                                 if k in ('birth','verified_at','destination','movement_query')
                                 else type_spec(f['rust_type'],wg['file'],'MovementHistory',k)
                                 for k,f in wg['fields'].items()}
    for alias,(file,name) in ENUM_ROOTS.items():
        d = by_id[file+'::'+name]
        rename_all = next((re.search(r'rename_all\s*=\s*"([^"]+)"',a)[1]
                           for a in d['serde_attributes'] if 'rename_all' in a),None)
        variants = []
        for v in d['variants']:
            word = v['serialized']
            if word == v['name'] and (rename_all == 'snake_case' or alias == 'job_state'):
                word = re.sub(r'(?<!^)(?=[A-Z])','_',word).lower()
            variants.append(word)
        enums[alias] = sorted(variants)
    origin = by_id[LAUNCH+'attachment.rs::Origin']
    variant = origin['variants'][0]
    origin_fields = {'kind':'origin_kind'}
    for piece in split_top(variant['payload'][1:-1]):
        key,ty = piece.split(':',1)
        origin_fields[key.strip()] = type_spec(ty.strip(),origin['file'],'AttachmentOrigin',key.strip())
    schemas['AttachmentOrigin'] = origin_fields
    builders = [b for file,text in texts.items() for b in json_builders(file,text)]
    guards = [g for file,text in texts.items() for g in guards_in(file,text)]
    projection_sources = {}
    native_schema_names = {s for _,_,s in TYPE_ROOTS} | {'MovementHistory','AttachmentOrigin'}
    for name,fields in schemas.items():
        if name in native_schema_names:
            continue
        candidates = []
        for builder in builders:
            keys = set(builder['fields'])
            overlap = len(keys & fields.keys())
            score = overlap/max(len(keys),len(fields))
            if score >= 0.70:
                candidates.append((score,builder))
        if candidates:
            best = max(score for score,_ in candidates)
            projection_sources[name] = [b for score,b in candidates if score == best]
    # Derive fixed native Link guards and emitter literals from source text.
    readback = texts[NETWORK+'native/readback.rs']
    token_guard = re.search(r'if &l.kind != kind([\s\S]*?)return Err\(Error::Drifted\)',readback)[1]
    link_fixed = {key:int(value) for key,value in re.findall(r'l\.(\w+) != (\d+)',token_guard)}
    link_fixed.update({key:[] if key == 'alternate_names' else ''
                       for key in re.findall(r'!l\.(\w+)\.is_empty\(\)',token_guard)})
    if re.search(r'\|\| l\.up\b',token_guard):
        link_fixed['up'] = False
    capacity = next(b for b in builders if b['file'] == LAUNCH+'attachment/assembly.rs'
                    and 'global_child_capacity_limit' in b['fields'])
    # Only the already retained, public guest program is inspected. This reads
    # literal public peer/endpoint/default-route inputs, never private key data.
    guest_path = ROOT/'target/candidates/run410-da75562-20261104/bootstrap410-driver-cost/controller-guest.py'
    guest = guest_path.read_text()
    import ast
    literals = [n.value for n in ast.walk(ast.parse(guest)) if isinstance(n,ast.Constant) and isinstance(n.value,str)]
    profile = next(v for v in literals if '[Peer]' in v and 'Endpoint=' in v)
    public_profile = {k:v for k,v in re.findall(r'(PublicKey|Endpoint|AllowedIPs)=([^\n]+)',profile)}
    import base64
    public_profile['PublicKey'] = list(base64.b64decode(public_profile['PublicKey'],validate=True))
    contract = dict(schema=2,call_graph=graph,coverage_complete=False,profile='run410 Bootstrap fault0 completed retained continuation',
                target_pointer_width=64,
                success_rules={'allocation_hash_seed':int(re.search(r'\.fold\((0x[0-9a-f]+)',texts['crates/vprouter-core/src/allocation.rs'])[1],16),
                               'allocation_hash_prime':int(re.search(r'wrapping_mul\((0x[0-9a-f]+)',texts['crates/vprouter-core/src/allocation.rs'])[1],16),
                               'max_exits':int(re.search(r'const MAX_EXITS: usize = (\d+)',texts['crates/vprouter-core/src/config.rs'])[1]),
                               'network_link_fixed':link_fixed,
                               'network_link_guard_source':NETWORK+'native/readback.rs:149',
                               'assembly_capacity':int(capacity['fields']['global_child_capacity_limit']),
                               'assembly_capacity_source':capacity['file']+':'+str(capacity['line']),
                               'public_profile':public_profile,
                               'public_profile_source':str(guest_path.relative_to(ROOT)),
                               'public_profile_source_sha256':hashlib.sha256(guest.encode()).hexdigest()},
                source_files={file:hashlib.sha256(text.encode()).hexdigest() for file,text in texts.items()},
                declarations=sorted(decls,key=lambda d:d['id']),
                json_builders=sorted(builders,key=lambda b:(b['file'],b['line'])),
                schemas=schemas,enums=enums,field_sources=field_sources,projection_sources=projection_sources,
                aliases={'bytes32':schemas['BootstrapHistory']['request'],
                         'pins6':schemas['ProducerBindingHistory']['pins'],
                         'pins8':schemas['BootstrapHistory']['pins'],
                         'namespace2':'array(2,'+schemas['Identity']['dev']+')',
                         'window3':schemas['HostLinkHistory']['admission'],
                         'addition':schemas['HostLinkHistory']['addition'].removesuffix('|null'),
                         'queries3':type_spec(by_id[LAUNCH+'owned/preparation.rs::History']['fields']['bootstrap_queries']['rust_type'],LAUNCH+'owned/preparation.rs','Preparation','bootstrap_queries'),
                         'sequences2':type_spec(plain_type(LAUNCH+'kernel/wireguard_role.rs','Native','lab_query_sequences'),LAUNCH+'kernel/wireguard_role.rs','MovementOperation','query_sequences').removesuffix('|null'),
                         'mac6':schemas['WanDeclaration']['address'],
                         'ip_prefix':schemas['WireguardPeer']['allowed_ips'][5:-1]},
                guards=sorted(guards,key=lambda g:(g['file'],g['line'],g['id'])))
    contract['predicate_lineage']={identity:dict(schemas=schemas,
        field_sources=sorted(key for key in field_sources if key.split('.')[0] in schemas),
        proof_scope='Reviewed necessary public projection under enclosing guard/quantifier context; not a general def-use proof.')
        for identity,schemas in SERIALIZED_PROJECTIONS.items()}
    contract['serialization_index']=serialization_index(contract)
    for guard in contract['guards']:
        guard['predicates']=[]
        for i,atom in enumerate(atomic_predicates(guard['expression'])):
            atom['id']=hashlib.sha256((guard['id']+':'+str(i)+':'+atom['expression']).encode()).hexdigest()[:20]
            guard['predicates'].append(atom)
    contract['inventory_limits'] = [
        'Lexical may-call closure is not compiler-resolved closure; external receiver types and dispatch are unproved.',
        'Guard inventory supports selected early-error/assert/match syntaxes; arbitrary Rust control/data flow is not normalized.',
        'Generic/tuple structs, inline-module identities, serde rename/flatten/discriminants, const-symbol arrays and proc macros require compiler review.',
        'Serialization field spelling and builder expressions are candidate lineage, not an equivalence proof.',
        'No pending predicate is claimed enforced or unenforceable_offline; full validation cannot PASS while pending exists.']
    return contract


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path)
    args = parser.parse_args()
    data = (json.dumps(extract(),indent=2,sort_keys=True,allow_nan=False)+'\n').encode()
    if args.output:
        args.output.write_bytes(data)
    else:
        import sys
        sys.stdout.buffer.write(data)


if __name__ == '__main__':
    main()
