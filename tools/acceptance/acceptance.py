#!/usr/bin/env python3
"""Credential-free Task 15 preparation. No network/capture/host-execution API.

Pure validators accept bounded JSON values. The CLI only reads local JSON and
optionally publishes a redacted hash-named report into an existing private dir.
Synthetic oracle PASS is NEVER real acceptance PASS or release authorization.
"""
import argparse
import ctypes
from collections import namedtuple
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys

MAX_BYTES = 1_048_576
MAX_INT = 2**63 - 1
MAX_DEPTH = 32
STATES = ('NOT_RUN', 'PASS', 'FAIL', 'UNVERIFIED')
PROTOCOLS = ('ipv4', 'dns', 'ipv6', 'tcp', 'udp')
POINTS = ('client_wan', 'host_wan', 'transport', 'data')
CONFIGS = {'one_mullvad': (1, 0), 'five_mullvad': (5, 0),
           'one_direct': (0, 1), 'five_mullvad_one_direct': (5, 1)}
FAULTS = {
    'tunnel_provider': 'wireguard_deleted wireguard_down handshake_stale endpoint_wrong peer_key_wrong transport_loss http_transient http_permanent provider_malformed provider_negative server_wrong',
    'routing': 'ordinary_default_restored endpoint_route docker_subnet_route docker_gateway_route unexpected_interface spoofed_source ipv6_route',
    'firewall': 'data_policy_drift data_policy_removed host_guard_drift host_guard_removed atomic_update_failed bridge_identity_changed foreign_conflict',
    'process': 'worker_crash worker_freeze host_guard_crash host_guard_freeze tailscale_crash container_kill oom service_restart docker_restart',
    'resources': 'disk_full tmpfs_full runtime_operation_failure docker_api_unavailable api_delayed health_malformed host_reboot',
    'identity': 'approval_revoked credential_expired credential_revoked control_plane_loss duplicate_identity name_server_mismatch',
    'isolation': 'exit_failure_others_active exit_restart_others_active shared_endpoint overlapping_vpn_addresses direct_active_during_mullvad_faults',
    'clients': 'exit_disappears selected_node_changes tailscale_restarts routes_reset dns_cache_empty proxy_upstream_failed proxy_settings_absent proxy_settings_bypassed',
    'migration': 'inspect stage plan protect drain_stop backup activate restore_identity verify commit recover',
}
GATES = ('single_exit_native_guard_parity namespace_firewall_unsafe_independent_review '
         'helper_cgroup_capability_fd_isolation existing_identity_canary_debdev '
         'second_existing_installation_migration mixed_mode_24_hour_soak '
         'repeated_ten_minute_one_five_six_exit_benchmarks throughput_latency_load '
         'x86_64_arm64_artifacts_provenance systemd_reboot_update_rollback_uninstall '
         'runit_reboot_update_rollback_uninstall').split()
EXTRA = tuple('traffic.'+p for p in PROTOCOLS) + tuple('coverage.'+p for p in POINTS) + (
    'capture.positive_controls', 'boot.capture_before_traffic')
SOURCE_SCENARIOS = tuple(group+'.'+fault for group, faults in FAULTS.items()
                         for fault in faults.split())
# Expanded from the package-owned spec requirement table after reader definitions.
SCENARIOS = SOURCE_SCENARIOS + EXTRA
SCOPE = {
    'instruction': 'all testing locally',
    'environments': ['local_host', 'isolated_local_vms', 'local_disposable_tailscale_clients'],
    'remote_installation_access': 'OUT_OF_SCOPE_PER_USER',
    'second_existing_installation_migration': 'separate local legacy deployment with independent established test identity and declared adapters',
    'remote_installation_validation': 'NOT_PERFORMED',
    'external_protocol_services': ['Tailscale', 'Mullvad'],
    'unavailable_platform_checks': 'remain explicitly unverified',
}
PREREQUISITES = (
    'task8c_runtime_client_acceptance', 'reviewed_complete_implementation',
    'immutable_candidate_and_artifacts', 'whole_branch_independent_review',
    'namespace_firewall_unsafe_review', 'client_enforcement_review',
    'local_guest_and_disposable_clients', 'tailscale_credentials_available',
    'mullvad_profiles_available', 'capture_privileges_and_boot_order',
    'capture_positive_controls_all_points', 'all_fault_matrix_pass',
    'compatibility_security_artifact_gates', 'debdev_preserved_primary',
    'second_local_independent_legacy_identity', 'declared_adapters_and_dependencies',
    'stopped_state_backup_compatible_rollback', 'no_concurrent_identity_copies',
    'explicit_direct_authorization', 'performance_gates', 'soak_24h_window',
)


class Invalid(ValueError):
    """Errors contain controlled codes only, never offending data or paths."""


class Violation(Invalid):
    pass


def require(condition, code='invalid_shape'):
    if not condition:
        raise Invalid(code)


def shape(value, keys):
    require(type(value) is dict and set(value) == set(keys))


def integer(value):
    require(type(value) is int and 0 <= value <= MAX_INT, 'invalid_integer')
    return value


def sha(value, size=64):
    require(type(value) is str and re.fullmatch('[0-9a-f]{'+str(size)+'}', value)
            is not None, 'invalid_digest')


def token(value):
    require(type(value) is str and re.fullmatch(r'syn-[a-z0-9-]{1,28}', value)
            is not None, 'redaction_refused')


def bounded(value, depth=0, budget=None):
    """Exact builtins only, including in direct Python APIs; no float coercion."""
    if budget is None:
        budget = [100_000]
    budget[0] -= 1
    require(budget[0] >= 0 and depth <= MAX_DEPTH, 'input_limit')
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        integer(value)
    elif type(value) is str:
        require(len(value) <= 1024 and all(32 <= ord(c) <= 126 for c in value),
                'invalid_encoding')
    elif type(value) is dict:
        require(len(value) <= 128, 'input_limit')
        for key, child in value.items():
            require(type(key) is str, 'invalid_key')
            bounded(key, depth+1, budget)
            bounded(child, depth+1, budget)
    elif type(value) is list:
        require(len(value) <= 4096, 'input_limit')
        for child in value:
            bounded(child, depth+1, budget)
    else:
        raise Invalid('invalid_type')


def strict_load(raw):
    require(type(raw) is bytes and len(raw) <= MAX_BYTES, 'input_limit')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate_key')
            result[key] = value
        return result
    def number(text):
        require(len(text) <= 19 and text.isascii() and text.isdigit(), 'invalid_integer')
        return integer(int(text))
    def reject(_):
        raise Invalid('invalid_number')
    try:
        # UTF-8 only; explicitly no BOM, UTF-16/32, surrogate or normalization.
        require(not raw.startswith(b'\xef\xbb\xbf'), 'invalid_encoding')
        value = json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=pairs,
                           parse_int=number, parse_float=reject, parse_constant=reject)
        bounded(value)
        return value
    except (UnicodeError, json.JSONDecodeError, RecursionError, OverflowError):
        raise Invalid('invalid_json') from None


def canonical(value):
    bounded(value)
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def load_ledger(raw):
    value = strict_load(raw)
    shape(value, ('schema_version candidate_base release_ready traffic_protocols '
                  'observation_points positive_controls boot_capture_operational_before_traffic '
                  'configurations other_gates test_execution_scope').split())
    require(type(value['schema_version']) is int and value['schema_version'] == 1)
    sha(value['candidate_base'], 40)
    require(value['release_ready'] is False, 'release_claim_refused')
    require(value['traffic_protocols'] == list(PROTOCOLS) and
            value['observation_points'] == list(POINTS), 'coverage_mismatch')
    require(canonical(value['test_execution_scope']) == canonical(SCOPE), 'scope_refused')
    for key in ('positive_controls', 'boot_capture_operational_before_traffic'):
        require(type(value[key]) is str and value[key] in STATES, 'invalid_status')
    configs = value['configurations']
    require(type(configs) is list and len(configs) == 4)
    seen = set()
    for config in configs:
        shape(config, ('name mullvad_exits direct_exits scenarios forbidden_markers evidence').split())
        name = config['name']
        require(type(name) is str and name in CONFIGS and name not in seen)
        seen.add(name)
        require((integer(config['mullvad_exits']), integer(config['direct_exits'])) == CONFIGS[name])
        shape(config['scenarios'], FAULTS)
        for group, faults in FAULTS.items():
            shape(config['scenarios'][group], faults.split())
            for status in config['scenarios'][group].values():
                require(type(status) is str and status in STATES, 'invalid_status')
        if config['forbidden_markers'] is not None:
            integer(config['forbidden_markers'])
        require(type(config['evidence']) is list and len(config['evidence']) <= 128)
        for reference in config['evidence']:
            sha(reference)
    shape(value['other_gates'], GATES)
    require(all(type(s) is str and s in STATES for s in value['other_gates'].values()),
            'invalid_status')
    return value


def exit_modes(configuration):
    require(type(configuration) is str and configuration in CONFIGS)
    mullvad, direct = CONFIGS[configuration]
    return {'syn-m'+str(i+1): 'mullvad' for i in range(mullvad)} | (
        {'syn-direct': 'direct'} if direct else {})


def scan_violations(bundle):
    """A reported leak is FAIL even if the rest of the bundle is incomplete."""
    if type(bundle) is not dict or type(bundle.get('captures')) is not list:
        return
    budget = 100_000
    for capture in bundle['captures'][:4096]:
        budget -= 1
        if budget <= 0:
            return
        if type(capture) is not dict:
            continue
        for key in ('forbidden_plaintext_markers', 'cross_exit_markers',
                    'host_ip_as_mullvad_app_egress'):
            count = capture.get(key)
            if type(count) is int and count > 0:
                raise Violation('forbidden_egress')
        records = capture.get('records')
        if type(records) is list:
            for record in records[:4096]:
                budget -= 1
                if budget <= 0:
                    return
                if type(record) is dict and type(record.get('marker')) is str and record['marker'] in (
                        'forbidden_plaintext', 'cross_exit', 'host_as_mullvad'):
                    raise Violation('forbidden_egress')


def validate_context(context, expected):
    shape(expected, ('configuration scenario candidate_sha256 ledger_sha256 bundle_sha256 expected_run').split())
    shape(context, ('configuration scenario candidate_sha256 ledger_sha256 run_id').split())
    require(type(context['configuration']) is str and context['configuration'] in CONFIGS)
    require(type(context['scenario']) is str and context['scenario'] in SCENARIOS)
    for field in ('candidate_sha256', 'ledger_sha256'):
        sha(context[field])
    sha(expected['bundle_sha256'])
    for key in ('configuration', 'scenario', 'candidate_sha256', 'ledger_sha256'):
        require(type(expected[key]) is str and context[key] == expected[key], 'binding_mismatch')
    token(context['run_id'])


def validate_run(bundle, expected_run):
    """External admission, never inferred from producer labels or wall time."""
    shape(expected_run, ('run_id epoch not_before_ns not_after_ns').split())
    token(expected_run['run_id'])
    token(expected_run['epoch'])
    first = integer(expected_run['not_before_ns'])
    last = integer(expected_run['not_after_ns'])
    require(first < last, 'run_admission')
    require(bundle['context']['run_id'] == expected_run['run_id'] and
            bundle['execution']['epoch'] == expected_run['epoch'], 'run_admission')
    require(first <= bundle['execution']['traffic_start_ns'] <
            bundle['execution']['traffic_end_ns'] <= last, 'run_admission')
    for capture in bundle['captures']:
        require(first <= capture['start_ns'] <= capture['stop_ns'] <= last, 'run_admission')


def validate_execution(execution, scenario):
    shape(execution, ('injection boundary expected actual cleanup ownership epoch '
                      'traffic_start_ns traffic_end_ns').split())
    require(execution['injection'] == 'synthetic_fault' and
            execution['boundary'] == scenario and execution['expected'] == 'contained' and
            execution['actual'] == 'contained' and execution['cleanup'] == 'owned_retained' and
            execution['ownership'] == 'verified', 'execution_unverified')
    token(execution['epoch'])
    start = integer(execution['traffic_start_ns'])
    end = integer(execution['traffic_end_ns'])
    require(start < end, 'clock_order')


def validate_captures(captures, context, execution):
    require(type(captures) is list and len(captures) <= 24, 'coverage_mismatch')
    modes = exit_modes(context['configuration'])
    required = {(point, exit_id) for point in POINTS for exit_id in modes}
    seen = set()
    traffic_start = execution['traffic_start_ns']
    traffic_end = execution['traffic_end_ns']
    fields = ('point exit mode epoch start_ns ready_ns stop_ns records source_sha256 packets '
              'positive_control_packets forbidden_plaintext_markers cross_exit_markers '
              'host_ip_as_mullvad_app_egress kernel_drops').split()
    for capture in captures:
        shape(capture, fields)
        require(type(capture['point']) is str and type(capture['exit']) is str)
        key = (capture['point'], capture['exit'])
        require(key in required and key not in seen, 'coverage_mismatch')
        seen.add(key)
        require(capture['mode'] == modes[capture['exit']], 'mode_mismatch')
        require(capture['epoch'] == execution['epoch'], 'clock_epoch')
        start, ready, stop = (integer(capture[k]) for k in ('start_ns', 'ready_ns', 'stop_ns'))
        require(start <= ready < traffic_start < traffic_end < stop, 'capture_order')
        for field in ('packets', 'positive_control_packets', 'forbidden_plaintext_markers',
                      'cross_exit_markers', 'host_ip_as_mullvad_app_egress', 'kernel_drops'):
            integer(capture[field])
        require(capture['kernel_drops'] == 0, 'capture_loss')
        require(all(capture[k] == 0 for k in ('forbidden_plaintext_markers',
                'cross_exit_markers', 'host_ip_as_mullvad_app_egress')), 'forbidden_egress')
        records = capture['records']
        require(type(records) is list and 15 <= len(records) <= 128, 'capture_controls')
        sha(capture['source_sha256'])
        require(capture['source_sha256'] == digest(records), 'source_binding')
        require(capture['packets'] == len(records), 'counter_mismatch')
        before, after, allowed = set(), set(), set()
        controls = 0
        last = start
        for record in records:
            shape(record, ('protocol', 'marker', 'time_ns'))
            protocol, marker = record['protocol'], record['marker']
            require(type(protocol) is str and protocol in PROTOCOLS and type(marker) is str and
                    marker in ('control', 'allowed'), 'record_unverified')
            time = integer(record['time_ns'])
            require(last <= time <= stop, 'clock_order')
            last = time
            if marker == 'control':
                controls += 1
                require(ready <= time < traffic_start or traffic_end < time <= stop,
                        'control_order')
                (before if time < traffic_start else after).add(protocol)
            else:
                require(traffic_start <= time <= traffic_end, 'traffic_order')
                allowed.add(protocol)
        require(controls == capture['positive_control_packets'], 'counter_mismatch')
        require(before == after == allowed == set(PROTOCOLS), 'capture_controls')
    require(seen == required, 'coverage_mismatch')


def validate_manifest(bundle, expected):
    manifest = bundle['manifest']
    shape(manifest, ('algorithm context_sha256 execution_sha256 captures_sha256 payload_sha256').split())
    require(manifest['algorithm'] == 'sha256', 'manifest_algorithm')
    for key in ('context', 'execution', 'captures'):
        sha(manifest[key+'_sha256'])
        require(manifest[key+'_sha256'] == digest(bundle[key]), 'manifest_binding')
    body = {k: v for k, v in bundle.items() if k != 'manifest'}
    sha(manifest['payload_sha256'])
    require(manifest['payload_sha256'] == digest(body), 'manifest_binding')
    require(expected['bundle_sha256'] == digest(bundle), 'external_binding')


def assess_bundle(bundle, expected):
    try:
        scan_violations(bundle)
        bounded(bundle)
        bounded(expected)
        shape(bundle, ('schema_version kind context execution captures manifest').split())
        require(type(bundle['schema_version']) is int and bundle['schema_version'] == 1)
        require(bundle['kind'] == 'synthetic', 'real_evidence_unsupported')
        validate_context(bundle['context'], expected)
        validate_execution(bundle['execution'], bundle['context']['scenario'])
        validate_captures(bundle['captures'], bundle['context'], bundle['execution'])
        validate_run(bundle, expected['expected_run'])
        validate_manifest(bundle, expected)
        return {'oracle_status': 'PASS', 'acceptance_status': 'UNVERIFIED',
                'reason': 'synthetic_only', 'scope': 'synthetic', 'release_ready': False}
    except Violation:
        return {'oracle_status': 'FAIL', 'acceptance_status': 'FAIL',
                'reason': 'forbidden_egress', 'scope': 'synthetic', 'release_ready': False}
    except (Invalid, RecursionError):
        return {'oracle_status': 'UNVERIFIED', 'acceptance_status': 'UNVERIFIED',
                'reason': 'evidence_invalid', 'scope': 'synthetic', 'release_ready': False}


def resolve_status(requested, bundle, expected):
    if requested == 'FAIL' and type(requested) is str:
        return {'status': 'FAIL', 'oracle_status': 'UNVERIFIED', 'reason': 'recorded_failure'}
    if bundle is not None:
        verdict = assess_bundle(bundle, expected)
        if verdict['oracle_status'] == 'FAIL':
            return {'status': 'FAIL', 'oracle_status': 'FAIL', 'reason': 'forbidden_egress'}
        return {'status': 'UNVERIFIED', 'oracle_status': verdict['oracle_status'],
                'reason': verdict['reason']}
    if type(requested) is str and requested == 'NOT_RUN':
        return {'status': 'NOT_RUN', 'oracle_status': 'UNVERIFIED', 'reason': 'not_run'}
    return {'status': 'UNVERIFIED', 'oracle_status': 'UNVERIFIED', 'reason': 'missing_evidence'}


def build_ledger(raw, observations=None):
    source = load_ledger(raw)
    bound_digest = hashlib.sha256(raw).hexdigest()
    sha(bound_digest)
    rows = []
    for config in sorted(source['configurations'], key=lambda c: c['name']):
        for scenario in sorted(SCENARIOS):
            if scenario.startswith('capture.'):
                recorded = source['positive_controls']
            elif scenario.startswith('boot.'):
                recorded = source['boot_capture_operational_before_traffic']
            elif scenario in EXTRA:
                recorded = 'NOT_RUN'
            elif scenario in SOURCE_SCENARIOS:
                group, fault = scenario.split('.')
                recorded = config['scenarios'][group][fault]
            else:
                recorded = 'NOT_RUN'  # Supplemental spec-derived rows have no source verdict.
            verdict = resolve_status(recorded, None, {})
            if config['forbidden_markers'] is not None and config['forbidden_markers'] > 0:
                verdict = resolve_status('FAIL', None, {})
            rows.append({'configuration': config['name'], 'scenario': scenario,
                         'evidence_sha256': None, **verdict})
    for gate in sorted(GATES):
        rows.append({'configuration': 'global', 'scenario': 'gate.'+gate,
                     'evidence_sha256': None, **resolve_status(source['other_gates'][gate], None, {})})
    if observations is not None:
        bounded(observations)
        shape(observations, ('schema_version candidate_sha256 observations').split())
        require(type(observations['schema_version']) is int and observations['schema_version'] == 1)
        sha(observations['candidate_sha256'])
        entries = observations['observations']
        require(type(entries) is list and len(entries) <= len(rows))
        by_key = {(row['configuration'], row['scenario']): row for row in rows}
        used = set()
        for observation in entries:
            shape(observation, ('configuration scenario requested_status bundle bundle_sha256 expected_run').split())
            require(type(observation['configuration']) is str and type(observation['scenario']) is str)
            key = (observation['configuration'], observation['scenario'])
            require(key in by_key and key not in used, 'observation_binding')
            used.add(key)
            sha(observation['bundle_sha256'])
            expected = {'configuration': key[0], 'scenario': key[1],
                        'candidate_sha256': observations['candidate_sha256'],
                        'ledger_sha256': bound_digest, 'bundle_sha256': observation['bundle_sha256'],
                        'expected_run': observation['expected_run']}
            row = by_key[key]
            status = 'FAIL' if row['status'] == 'FAIL' else observation['requested_status']
            row.update(resolve_status(status, observation['bundle'], expected))
            row['evidence_sha256'] = observation['bundle_sha256']
    counts = {status: sum(row['status'] == status for row in rows) for status in STATES}
    return {'schema_version': 1, 'scope': 'preparation_only', 'release_ready': False,
            'ledger_sha256': bound_digest, 'rows': rows, 'counts': counts,
            'mandatory_acceptance': 'UNVERIFIED'}


def plan_spec():
    """Fixed local-only plan; proposed argv are DATA and are never dispatched."""
    return {
        'schema_version': 1, 'scope': 'preparation_only', 'status': 'NOT_RUN',
        'execution_scope': 'local_only', 'execution_supported': False,
        'remote_validation': 'NOT_PERFORMED', 'minimum_soak_seconds': 86400,
        'prerequisites': list(PREREQUISITES),
        'cases': [
            {'id': 'debdev_primary', 'target': 'local_debdev',
             'identity_policy': 'preserve_primary_no_reenrollment_no_concurrent_copy',
             'status': 'NOT_RUN'},
            {'id': 'second_local_legacy', 'target': 'separate_local_legacy_deployment',
             'identity_policy': 'preserve_independently_established_test_identity',
             'status': 'NOT_RUN'},
            {'id': 'mixed_soak', 'target': 'local_mixed_six_exit',
             'identity_policy': 'preserve_all_approved_identities', 'status': 'NOT_RUN'},
        ],
        'steps': [
            {'id': 'inspect', 'availability': 'observational_cli_only',
             'argv_template': ['target/release/vprouter', 'migrate', 'inspect',
                               '--legacy-config', 'LOCAL_LEGACY_CONFIG'], 'status': 'NOT_RUN'},
            {'id': 'plan', 'availability': 'observational_cli_only',
             'argv_template': ['target/release/vprouter', 'migrate', 'plan',
                               '--legacy-config', 'LOCAL_LEGACY_CONFIG', '--site', 'LOCAL_SITE',
                               '--expected-server', 'EXPECTED_SERVER', '--deployment-id', 'LOCAL_DEPLOYMENT'],
             'status': 'NOT_RUN'},
            {'id': 'apply', 'availability': 'future_cli_not_implemented',
             'argv_template': ['target/release/vprouter', 'migrate', 'apply',
                               '--plan', 'REVIEWED_LOCAL_PLAN'], 'status': 'NOT_RUN'},
            {'id': 'rollback', 'availability': 'future_cli_not_implemented',
             'argv_template': ['target/release/vprouter', 'migrate', 'rollback',
                               '--plan', 'REVIEWED_LOCAL_PLAN'], 'status': 'NOT_RUN'},
            {'id': 'capture_fault_and_soak', 'availability': 'future_controller_not_implemented',
             'argv_template': ['ACCEPTANCE_CONTROLLER_NOT_IMPLEMENTED', '--local-only',
                               '--boot-capture-before-traffic', '--all-configurations',
                               '--all-faults', '--soak-seconds', '86400'], 'status': 'NOT_RUN'},
        ],
        'required_records': [
            'same_identity_addresses_credentials_approval_before_after',
            'rename_verified_by_actual_protected_client', 'declared_hostname_dependencies',
            'declared_idempotent_drain_stop_rebind_start_health_adapters',
            'stopped_state_private_backup', 'compatible_release_and_state_rollback',
            'quarantine_before_cutover_and_uncertain_recovery',
            'kill_resume_reverse_at_every_migration_boundary',
            'distinct_additional_imported_device_profiles', 'explicit_direct_never_fallback',
            'continuous_mixed_24h_faults_positive_capture_controls',
            'all_failed_attempts_retained_and_hash_bound',
        ],
    }


def empty_declarations():
    return {'schema_version': 1, 'prerequisites': {
        name: {'status': 'NOT_RUN', 'evidence_sha256': None} for name in PREREQUISITES}}


def preflight(plan, declarations):
    bounded(plan)
    bounded(declarations)
    require(canonical(plan) == canonical(plan_spec()), 'plan_refused')
    shape(declarations, ('schema_version', 'prerequisites'))
    require(type(declarations['schema_version']) is int and declarations['schema_version'] == 1)
    shape(declarations['prerequisites'], PREREQUISITES)
    missing = []
    for name in PREREQUISITES:
        declaration = declarations['prerequisites'][name]
        shape(declaration, ('status', 'evidence_sha256'))
        reference = declaration['evidence_sha256']
        if reference is not None:
            sha(reference)
        # Unknown/skip/false/absent evidence cannot satisfy a prerequisite.
        if declaration['status'] != 'PASS' or type(declaration['status']) is not str or reference is None:
            missing.append(name)
    return {'schema_version': 1, 'scope': 'preparation_only', 'release_ready': False,
            'status': 'NOT_RUN', 'preflight': 'BLOCKED' if missing else 'DECLARED_ONLY',
            'execution_supported': False, 'missing': sorted(missing)}


def synthetic_fixture(ledger_raw, configuration='one_mullvad', scenario='routing.endpoint_route'):
    load_ledger(ledger_raw)
    require(scenario in SCENARIOS, 'scenario_mismatch')
    context = {'configuration': configuration, 'scenario': scenario,
               'candidate_sha256': 'a'*64, 'ledger_sha256': hashlib.sha256(ledger_raw).hexdigest(),
               'run_id': 'syn-run-001'}
    execution = {'injection': 'synthetic_fault', 'boundary': scenario, 'expected': 'contained',
                 'actual': 'contained', 'cleanup': 'owned_retained', 'ownership': 'verified',
                 'epoch': 'syn-epoch-001', 'traffic_start_ns': 30, 'traffic_end_ns': 70}
    captures = []
    for point in POINTS:
        for exit_id, mode in exit_modes(configuration).items():
            records = [{'protocol': protocol, 'marker': marker, 'time_ns': time}
                       for marker, time in (('control', 20), ('allowed', 50), ('control', 80))
                       for protocol in PROTOCOLS]
            captures.append({'point': point, 'exit': exit_id, 'mode': mode,
                             'epoch': 'syn-epoch-001', 'start_ns': 0, 'ready_ns': 10, 'stop_ns': 100,
                             'records': records, 'source_sha256': digest(records), 'packets': 15,
                             'positive_control_packets': 10, 'forbidden_plaintext_markers': 0,
                             'cross_exit_markers': 0, 'host_ip_as_mullvad_app_egress': 0, 'kernel_drops': 0})
    body = {'schema_version': 1, 'kind': 'synthetic', 'context': context,
            'execution': execution, 'captures': captures}
    manifest = {'algorithm': 'sha256', 'context_sha256': digest(context),
                'execution_sha256': digest(execution), 'captures_sha256': digest(captures),
                'payload_sha256': digest(body)}
    bundle = dict(body, manifest=manifest)
    expected = {key: context[key] for key in ('configuration', 'scenario', 'candidate_sha256', 'ledger_sha256')}
    expected['bundle_sha256'] = digest(bundle)
    expected['expected_run'] = {'run_id': 'syn-run-001', 'epoch': 'syn-epoch-001',
                                'not_before_ns': 0, 'not_after_ns': 100}
    return {'expected': expected, 'bundle': bundle}


REASONS = ('recorded_failure', 'not_run', 'missing_evidence', 'forbidden_egress',
           'synthetic_only', 'evidence_invalid')


def report_bytes(document):
    """Report allowlist, not blacklist redaction. Arbitrary text is never copied."""
    bounded(document)
    require(type(document) is dict and document.get('release_ready') is False, 'redaction_refused')
    if 'rows' in document:
        shape(document, ('schema_version scope release_ready ledger_sha256 rows counts mandatory_acceptance').split())
        require(type(document['schema_version']) is int and document['schema_version'] == 1)
        require(document['scope'] == 'preparation_only' and document['mandatory_acceptance'] == 'UNVERIFIED')
        sha(document['ledger_sha256'])
        require(type(document['rows']) is list and
                len(document['rows']) == len(CONFIGS)*len(SCENARIOS)+len(GATES))
        seen = set()
        for row in document['rows']:
            shape(row, ('configuration scenario evidence_sha256 status oracle_status reason').split())
            config, scenario = row['configuration'], row['scenario']
            require(type(config) is str and type(scenario) is str)
            require((config in CONFIGS and scenario in SCENARIOS) or
                    (config == 'global' and scenario in ['gate.'+g for g in GATES]))
            require((config, scenario) not in seen)
            seen.add((config, scenario))
            require(row['status'] in ('NOT_RUN', 'FAIL', 'UNVERIFIED') and
                    row['oracle_status'] in STATES and row['reason'] in REASONS)
            if row['evidence_sha256'] is not None:
                sha(row['evidence_sha256'])
        shape(document['counts'], STATES)
        for status in STATES:
            integer(document['counts'][status])
            require(document['counts'][status] == sum(r['status'] == status for r in document['rows']))
    elif 'oracle_status' in document:
        keys = ('oracle_status acceptance_status reason scope release_ready').split()
        if 'input_sha256' in document or 'expected_sha256' in document:
            keys += ['input_sha256', 'expected_sha256']
            sha(document.get('input_sha256'))
            sha(document.get('expected_sha256'))
        shape(document, keys)
        require(document['oracle_status'] in STATES and document['acceptance_status'] in ('FAIL', 'UNVERIFIED')
                and document['reason'] in REASONS and document['scope'] == 'synthetic')
    elif 'preflight' in document:
        shape(document, ('schema_version scope release_ready status preflight execution_supported missing').split())
        require(type(document['schema_version']) is int and document['schema_version'] == 1 and
                document['scope'] == 'preparation_only' and document['status'] == 'NOT_RUN' and
                document['preflight'] in ('BLOCKED', 'DECLARED_ONLY') and
                document['execution_supported'] is False)
        require(type(document['missing']) is list and
                all(type(x) is str and x in PREREQUISITES for x in document['missing']))
    else:
        raise Invalid('redaction_refused')
    result = canonical(document)+b'\n'
    require(len(result) <= MAX_BYTES, 'output_limit')
    return result


def open_directory(path, private=False):
    """Pin every path component with directory FDs; never follow symlinks."""
    parts = Path(os.path.abspath(os.fspath(path))).parts
    require('..' not in Path(path).parts, 'path_refused')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=fd)
            os.close(fd)
            fd = next_fd
        info = os.fstat(fd)
        if private:
            require(info.st_uid == os.geteuid() and info.st_mode & 0o777 == 0o700,
                    'private_directory_required')
        return fd
    except BaseException:
        os.close(fd)
        raise


InputSnapshot = namedtuple('InputSnapshot', 'raw sha256')


def read_snapshot(path):
    """Single bounded read under cooperative producer handoff; no path rereads.

    Producers hold LOCK_EX while mutating a handed-off inode. Prefer atomic
    publication of a complete file, then leave that inode unchanged. Metadata
    checks are rejection signals, not an arbitrary-writer immutability proof.
    A short read is refused, never stitched to a second version.
    """
    parent = None
    fd = None
    try:
        require('..' not in Path(path).parts, 'path_refused')
        parent = open_directory(Path(path).parent)
        fd = os.open(Path(path).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=parent)
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= MAX_BYTES,
                'input_refused')
        raw = os.read(fd, MAX_BYTES+1)
        require(len(raw) <= MAX_BYTES, 'input_limit')
        after = os.fstat(fd)
        def identity(info):
            return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
                    info.st_mode, info.st_uid, info.st_gid, info.st_nlink)
        require(identity(before) == identity(after) and len(raw) == before.st_size, 'input_changed')
        return InputSnapshot(raw, hashlib.sha256(raw).hexdigest())
    except OSError:
        raise Invalid('input_refused') from None
    finally:
        if fd is not None:
            os.close(fd)
        if parent is not None:
            os.close(parent)


def read_input(path):
    return read_snapshot(path).raw


def requirement_scenarios(raw):
    """Package-owned spec expansion supplements, never modifies, source ledger."""
    table = strict_load(raw)
    require(table['schema_version'] == 1)
    scenarios = set(SOURCE_SCENARIOS + EXTRA)
    for group in table['failure_phrases'] + table['other_phrases'] + table['migration_phrases']:
        for requirement in group['requirements']:
            require(requirement['scenario_ids'] and requirement['configurations'])
            require(all(c in CONFIGS for c in requirement['configurations']))
            for scenario in requirement['scenario_ids']:
                require(type(scenario) is str and re.fullmatch(r'[a-z_]+(?:\.[a-z0-9_]+){1,4}', scenario))
                scenarios.add(scenario)
    return tuple(sorted(scenarios))


def rename_exclusive(directory_fd, source, destination):
    # Linux/glibc renameat2 gives atomic RENAME_NOREPLACE: there is NO
    # check-then-rename and NO overwrite-capable fallback.
    libc = ctypes.CDLL(None, use_errno=True)
    function = getattr(libc, 'renameat2', None)
    require(function is not None, 'exclusive_rename_unavailable')
    function.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    function.restype = ctypes.c_int
    require(function(directory_fd, source.encode('ascii'), directory_fd,
                     destination.encode('ascii'), 1) == 0, 'exclusive_publication_refused')


def publish(directory, document):
    content = report_bytes(document)
    name = hashlib.sha256(content).hexdigest()+'.json'
    directory_fd = None
    fd = None
    temporary = None
    renamed = False
    created = False
    try:
        directory_fd = open_directory(directory, private=True)
        temporary = '.tmp-'+secrets.token_hex(16)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=directory_fd)
        created = True
        view = memoryview(content)
        while view:
            written = os.write(fd, view)
            require(written > 0, 'publication_write_failed')
            view = view[written:]
        os.fchmod(fd, 0o400)
        os.fsync(fd)
        os.close(fd)
        fd = None
        rename_exclusive(directory_fd, temporary, name)
        renamed = True
        os.fsync(directory_fd)
        return name
    except (OSError, Invalid):
        raise Invalid('publication_durability_unknown' if renamed else 'publication_refused') from None
    finally:
        if fd is not None:
            os.close(fd)
        if directory_fd is not None:
            if created and temporary is not None and not renamed:
                try:
                    os.unlink(temporary, dir_fd=directory_fd)
                except FileNotFoundError:
                    pass
            os.close(directory_fd)


# INVARIANT/RULE REGISTRY. Tests verify every entry resolves to an enforcement
# function and a behavioral negative/mutation test. New rules must extend both.
RULES = tuple({'id': rule_id, 'invariant': invariant, 'enforcement': enforcement,
               'mutation_test': mutation} for rule_id, invariant, enforcement, mutation in (
    ('R01', 'Duplicate keys never overwrite a prior verdict', 'strict_load', 'BehavioralRed.test_duplicate_keys_cannot_be_silently_overwritten'),
    ('R02', 'Exact bounded integers and strict encoding only', 'strict_load', 'Contracts.test_strict_json_rejects_ambiguous_and_unbounded_numbers'),
    ('R03', 'Spec phrases and every migration boundary have independent matrix bindings', 'build_ledger', 'ReviewRoundOne.test_spec_requirement_table_covers_every_phrase_and_expanded_item'),
    ('R04', 'Closed evidence fields and no bool integer aliases', 'assess_bundle', 'Contracts.test_closed_evidence_schema_rejects_unknown_fields_and_type_aliases'),
    ('R05', 'Missing or unknown evidence blocks claims', 'resolve_status', 'BehavioralRed.test_unbound_pass_is_unverified'),
    ('R06', 'Skipped or unknown status never passes', 'resolve_status', 'BehavioralRed.test_unknown_or_skip_is_unverified'),
    ('R07', 'Synthetic evidence cannot satisfy acceptance', 'resolve_status', 'Contracts.test_complete_fixture_passes_only_synthetic_oracle'),
    ('R08', 'Positive controls and point exit protocol coverage required', 'validate_captures', 'Contracts.test_positive_controls_and_every_point_exit_protocol_are_required'),
    ('R09', 'Any forbidden plaintext cross exit or host Mullvad egress fails', 'scan_violations', 'Contracts.test_forbidden_marker_or_host_egress_is_fail_even_with_broken_bundle'),
    ('R10', 'One monotonic epoch and capture ready before traffic', 'validate_captures', 'Contracts.test_capture_windows_require_one_monotonic_epoch_and_strict_start_order'),
    ('R11', 'External candidate ledger scenario and bundle hash binding', 'validate_context', 'Contracts.test_context_and_manifest_cannot_be_rebound_or_reused_for_another_scenario'),
    ('R12', 'Every leaf perturbation and cross scenario substitution is fail closed', 'validate_manifest', 'ReviewRoundOne.test_all_leaf_perturbations_and_cross_scenario_swaps_cannot_forge_pass'),
    ('R13', 'Reports never copy arbitrary secret identity or address data', 'report_bytes', 'Contracts.test_redaction_fuzz_never_echoes_secrets_identity_addresses_or_paths'),
    ('R14', 'Failures are retained and observations cannot overwrite rows', 'build_ledger', 'Contracts.test_fail_is_preserved_and_bad_observations_cannot_upgrade_the_ledger'),
    ('R15', 'Plan never executes and every prerequisite is required', 'preflight', 'Contracts.test_plan_never_runs_and_all_prerequisites_are_required'),
    ('R16', 'Output deterministic without host metadata', 'build_ledger', 'Contracts.test_reports_are_deterministic_and_have_no_host_metadata'),
    ('R17', 'Atomic exclusive read only hash named output', 'publish', 'Publication.test_publication_is_exclusive_readonly_and_hash_named'),
    ('R18', 'No symlink traversal or unsafe publication directory', 'open_directory', 'Publication.test_symlink_and_unsafe_directory_refusal'),
    ('R19', 'Competing publishers never overwrite', 'rename_exclusive', 'Publication.test_parallel_publishers_cannot_overwrite_each_other'),
    ('R20', 'File and directory fsync failures cannot claim durability', 'publish', 'Publication.test_fsync_failure_cleans_temps_and_preserves_visible_publication'),
    ('R21', 'Single bounded snapshot read never assembles multiple file versions', 'read_snapshot', 'ReviewRoundOne.test_multichunk_mixed_invalid_versions_never_yield_cli_oracle_pass'),
    ('R22', 'A colliding temp belongs to another invocation', 'publish', 'PublicationRaces.test_colliding_temporary_symlink_is_never_deleted'),
    ('R23', 'Late destination creation preserves existing bytes', 'rename_exclusive', 'PublicationRaces.test_late_destination_race_preserves_existing_bytes'),
    ('R24', 'Parent pathname replacement cannot redirect pinned output', 'publish', 'PublicationRaces.test_parent_replacement_cannot_redirect_pinned_publication'),
    ('R25', 'Known leak evidence takes priority over malformed unrelated metadata', 'scan_violations', 'AdditionalRefusals.test_reported_host_egress_is_not_hidden_by_invalid_other_metadata'),
    ('R26', 'Execution boundary result ownership and selected mode must match', 'validate_execution', 'AdditionalRefusals.test_execution_result_and_capture_mode_cannot_be_forged'),
    ('R27', 'Freshness is bound to independent external run admission', 'validate_run', 'ReviewRoundOne.test_run_admission_rejects_relabelled_or_out_of_window_replay'),
    ('R28', 'Published check hashes identify only acquired input buffers', 'read_snapshot', 'ReviewRoundOne.test_snapshot_hash_and_published_verdict_use_only_acquired_bytes'),
    ('R29', 'Short reads and cooperative writer contention refuse admission', 'read_snapshot', 'ReviewRoundOne.test_partial_reads_or_cooperative_writer_cannot_be_admitted'),
))


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Invalid('invalid_arguments')


def main(argv=None):
    try:
        require(sys.flags.isolated and sys.dont_write_bytecode and not sys.flags.optimize,
                'python_flags_required')
        parser = Parser(description=__doc__)
        parser.add_argument('command', choices=('ledger', 'check', 'fixture', 'plan', 'declarations', 'preflight', 'rules'))
        parser.add_argument('--ledger', default='docs/rust-v2/acceptance.json')
        parser.add_argument('--observations')
        parser.add_argument('--input')
        parser.add_argument('--expected')
        parser.add_argument('--plan')
        parser.add_argument('--declarations')
        parser.add_argument('--configuration', default='one_mullvad', choices=tuple(CONFIGS))
        parser.add_argument('--scenario', default='routing.endpoint_route')
        parser.add_argument('--publish-dir')
        args = parser.parse_args(argv)
        is_report = True
        if args.command == 'ledger':
            document = build_ledger(read_input(args.ledger),
                                   strict_load(read_input(args.observations)) if args.observations else None)
        elif args.command == 'check':
            require(args.input is not None and args.expected is not None, 'missing_arguments')
            snapshot = read_snapshot(args.input)
            expected_snapshot = read_snapshot(args.expected)
            document = assess_bundle(strict_load(snapshot.raw), strict_load(expected_snapshot.raw))
            document.update(input_sha256=snapshot.sha256, expected_sha256=expected_snapshot.sha256)
        elif args.command == 'fixture':
            document = synthetic_fixture(read_input(args.ledger), args.configuration, args.scenario)
            is_report = False
        elif args.command == 'plan':
            document = plan_spec()
            is_report = False
        elif args.command == 'declarations':
            document = empty_declarations()
            is_report = False
        elif args.command == 'preflight':
            require(args.plan is not None and args.declarations is not None, 'missing_arguments')
            document = preflight(strict_load(read_input(args.plan)), strict_load(read_input(args.declarations)))
        else:
            document = list(RULES)
            is_report = False
        if args.publish_dir:
            require(is_report, 'report_required')
            publish(args.publish_dir, document)
        sys.stdout.buffer.write(report_bytes(document) if is_report else canonical(document)+b'\n')
        if args.command == 'check':
            return 0 if document['oracle_status'] == 'PASS' else (1 if document['oracle_status'] == 'FAIL' else 2)
        if args.command == 'preflight':
            return 2  # No execution support even if every declaration asserts PASS.
        return 0
    except (Invalid, OSError, RecursionError):
        sys.stdout.buffer.write(b'{"release_ready":false,"status":"UNVERIFIED","reason":"input_or_operation_refused"}\n')
        return 2


SCENARIOS = requirement_scenarios(read_input(Path(__file__).parent/'mandatory-requirements.json'))


if __name__ == '__main__':
    raise SystemExit(main())
