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
    pattern = r'//[^\n]*|/\*[\s\S]*?\*/|r(#+)?"[\s\S]*?"\1|"(?:\\.|[^"\\])*"'
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
        body_start = code.find('{',args_end)
        semi = code.find(';',args_end)
        if body_start < 0 or (semi >= 0 and semi < body_start):
            continue
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
    texts = {str(p.relative_to(ROOT)):p.read_text() for p in source_files()}
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
    return dict(schema=1,profile='run410 Bootstrap fault0 completed retained continuation',
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
