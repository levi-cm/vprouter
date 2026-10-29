"""Strict, offline evidence contracts; no workload execution or authority grant."""
import argparse
import hashlib
import json
import math
import pathlib
import statistics

MAX_JSON = 16 * 1024 * 1024
MONITORING = dict(provider_seconds=5, retry_seconds=1, handshake_seconds=180,
                  health_seconds=45, watchdog_seconds=90)
COMPONENTS = {'host_guard_publisher', 'worker_control', 'init_shim', 'docker_runtime', 'tailscale'}
LABELS = COMPONENTS | {'rust_control', 'python_control', 'container_runtime', 'workload', 'observer'}
CONTROL = {'host_guard_publisher', 'worker_control', 'init_shim', 'rust_control', 'python_control'}
SCENARIOS = [(count, mode) for count in (1, 5, 6) for mode in ('steady', 'load')]


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def number(value, minimum=0):
    require(type(value) in (int, float) and minimum <= value <= 2**64-1 and math.isfinite(value), 'invalid_number')
    return value


def integer(value, minimum=0):
    require(type(value) is int and minimum <= value <= 2**64-1, 'invalid_integer')
    return value


def digest(value):
    require(type(value) is str and len(value) == 64 and set(value) <= set('0123456789abcdef'), 'invalid_sha256')
    return value


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate_json_key')
        result[key] = value
    return result


def decode_json(raw):
    require(len(raw) <= MAX_JSON, 'json_bound_exceeded')
    return json.loads(raw, object_pairs_hook=unique_pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite_json')),
                      parse_int=bounded_json_int)


def bounded_json_int(raw):
    value = int(raw)
    require(abs(value) <= 2**64-1, 'json_integer_out_of_range')
    return value


def load_json(path):
    with pathlib.Path(path).open('rb') as stream:
        return decode_json(stream.read(MAX_JSON + 1))


def load_bound_json(path, expected):
    with pathlib.Path(path).open('rb') as stream:
        raw = stream.read(MAX_JSON + 1)
    require(hashlib.sha256(raw).hexdigest() == digest(expected), 'json_changed_after_descriptor_check')
    return decode_json(raw)


def parse_process_stat(raw):
    require(')' in raw and '(' in raw, 'invalid_process_stat')
    values = raw[raw.rfind(')') + 2:].split()
    require(len(values) >= 20 and values[0] in 'RSDZTWtXxKPI', 'invalid_process_stat')
    return integer(int(values[19]), 1), integer(int(values[11])) + integer(int(values[12])), values[0]


def validate_binding(value):
    required = {'implementation', 'source_sha256', 'artifact_sha256', 'config_sha256', 'workload_sha256',
                'identity_set_sha256', 'peers_sha256', 'network_conditions_sha256', 'tailscale_version',
                'tailscale_artifact_sha256', 'host_id_sha256', 'run_id', 'repetition', 'exits', 'exit_ids', 'exit_modes', 'scenario', 'monitoring'}
    require(type(value) is dict and set(value) == required, 'binding_fields')
    for key in required:
        if key.endswith('_sha256'):
            digest(value[key])
    require(value['implementation'] in ('python', 'rust'), 'implementation')
    require(type(value['exits']) is int and value['exits'] in (1, 5, 6), 'exit_count')
    require(type(value['exit_ids']) is list and len(value['exit_ids']) == value['exits'] and len(set(value['exit_ids'])) == value['exits'], 'exit_inventory')
    require(all(type(item) is str and 1 <= len(item) <= 64 and item != 'host' for item in value['exit_ids']), 'exit_id')
    require(value['exit_modes'] == ['mullvad'] * min(5,value['exits']) + (['direct'] if value['exits'] == 6 else []), 'exit_modes')
    require(value['scenario'] in ('steady', 'load'), 'scenario')
    integer(value['repetition'], 1)
    require(type(value['run_id']) is str and 1 <= len(value['run_id']) <= 96, 'run_id')
    require(type(value['tailscale_version']) is str and 1 <= len(value['tailscale_version']) <= 96, 'tailscale_version')
    require(value['monitoring'] == MONITORING and all(type(v) is int for v in value['monitoring'].values()), 'monitoring_contract_changed')


def validate_manifest(value):
    require(type(value) is dict and set(value) == {'schema', 'boot_id', 'groups', 'executable_labels', 'binding',
            'evidence_origin', 'accounting', 'stable_processes'}, 'manifest_fields')
    require(value['schema'] == 2 and type(value['schema']) is int, 'manifest_schema')
    validate_binding(value['binding'])
    require(value['evidence_origin'] in ('actual_runtime', 'synthetic'), 'evidence_origin')
    require(type(value['boot_id']) is str and 1 <= len(value['boot_id']) <= 64, 'boot_id')
    groups = value['groups']
    require(type(groups) is list and 1 <= len(groups) <= 32, 'group_count')
    roles, paths, native = {}, [], set()
    for group in groups:
        require(set(group) == {'role', 'relative', 'native_identity', 'accounting_class'}, 'group_fields')
        role, path = group['role'], group['relative']
        require(type(role) is str and 1 <= len(role) <= 64 and role not in roles, 'duplicate_or_invalid_role')
        require(type(path) is str and not path.startswith('/') and all(p not in ('', '.', '..') and len(p) <= 255 for p in path.split('/')), 'invalid_cgroup_path')
        require(all(path != old and not path.startswith(old + '/') and not old.startswith(path + '/') for old in paths), 'overlapping_cgroups')
        identity = group['native_identity']
        require(type(identity) is list and len(identity) == 2, 'cgroup_identity')
        for item in identity:
            integer(item, 1)
        require(tuple(identity) not in native, 'duplicate_cgroup_identity')
        native.add(tuple(identity)); paths.append(path); roles[role] = group
        require(group['accounting_class'] in ('control', 'runtime', 'tailscale', 'workload', 'mixed'), 'accounting_class')
    labels = value['executable_labels']
    require(type(labels) is dict and 1 <= len(labels) <= 128, 'executable_labels')
    for key, label in labels.items():
        digest(key); require(label in LABELS, 'executable_label')
    accounting = value['accounting']
    require(type(accounting) is dict and set(accounting) == {'method', 'scope_sha256', 'review_sha256', 'complete',
            'outside_domain_overhead', 'required_components', 'kernel_buffers', 'isolated_host'}, 'accounting_fields')
    require(accounting['method'] == 'disjoint_cgroup_v2_memory_current', 'unsupported_accounting_method')
    digest(accounting['scope_sha256']); digest(accounting['review_sha256'])
    require(accounting['complete'] is True and accounting['isolated_host'] is True, 'incomplete_accounting')
    require(accounting['outside_domain_overhead'] == 'none_on_isolated_host', 'outside_domain_overhead_unavailable')
    require(accounting['kernel_buffers'] == 'included_in_memory_current_and_memory_stat', 'kernel_buffers_unavailable')
    coverage = accounting['required_components']
    require(type(coverage) is dict and set(coverage) == COMPONENTS, 'component_coverage')
    for component, names in coverage.items():
        require(type(names) is list and names and len(names) == len(set(names)) and set(names) <= set(roles), 'component_group_coverage')
        expected = 'tailscale' if component == 'tailscale' else 'runtime' if component == 'docker_runtime' else 'control'
        require(all(roles[name]['accounting_class'] in (expected, 'mixed') for name in names), 'component_accounting_class')
    require(set(roles) <= {name for names in coverage.values() for name in names} |
            {name for name, group in roles.items() if group['accounting_class'] == 'workload'}, 'uncovered_group')
    stable = value['stable_processes']
    require(type(stable) is list and 1 <= len(stable) <= 32768, 'stable_process_inventory')
    identities = set()
    for process in stable:
        require(set(process) == {'pid', 'start', 'executable_sha256', 'group'}, 'stable_process_fields')
        key = integer(process['pid'], 1), integer(process['start'], 1)
        require(key not in identities and process['group'] in roles, 'stable_process_identity')
        identities.add(key); digest(process['executable_sha256'])
        require(process['executable_sha256'] in labels, 'stable_executable_unclassified')
    return value


def canonical_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def file_digest(path):
    result = hashlib.sha256()
    with pathlib.Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def enrich_summary(path, summary):
    """Derive lifecycle/coverage independently from retained complete JSONL."""
    begin = None
    previous = {}
    lifecycle, problems = [], []
    observed_mixed_control_roles = set()
    footprint_peak = control_peak = tailscale_peak = 0
    memory_stat_peak = {}
    byte_gauges = {'anon','file','kernel','kernel_stack','pagetables','sec_pagetables','percpu','sock','vmalloc',
                   'shmem','zswap','zswapped','file_mapped','file_dirty','file_writeback','swapcached',
                   'anon_thp','file_thp','shmem_thp','inactive_anon','active_anon','inactive_file','active_file',
                   'unevictable','slab_reclaimable','slab_unreclaimable','slab'}
    second_digest = hashlib.sha256()
    with pathlib.Path(path).open('rb') as stream:
        for line in stream:
            second_digest.update(line)
            row = decode_json(line)
            if row['kind'] == 'begin':
                begin = row
                require(row.get('schema') == 2, 'record_schema')
                manifest = validate_manifest(row['manifest'])
                require(row['manifest_canonical_sha256'] == canonical_digest(manifest), 'manifest_digest_mismatch')
                require(row.get('evidence_origin') == manifest['evidence_origin'], 'origin_mismatch')
                digest(row['collector_sha256']); digest(row['collector_helper_sha256'])
                require(summary['boot_id'] == manifest['boot_id'], 'boot_binding_mismatch')
                require(summary['workload_binding_sha256'] == manifest['binding']['workload_sha256'], 'workload_binding_mismatch')
                inventory = {group['role']: group for group in manifest['groups']}
            if row['kind'] != 'sample':
                continue
            require(begin is not None, 'missing_begin')
            require(set(group['role'] for group in row['groups']) == set(inventory), 'inventory_group_mismatch')
            require({'MemTotal_bytes','MemFree_bytes','MemAvailable_bytes','Buffers_bytes','Cached_bytes','Slab_bytes',
                     'SReclaimable_bytes','SUnreclaim_bytes','KernelStack_bytes','PageTables_bytes','Percpu_bytes'} <= set(row['whole_host']['memory']), 'host_kernel_buffer_context_unavailable')
            current, control_pss, tailscale_pss, memory = {}, 0, 0, 0
            sample_memory_stat = {}
            for group in row['groups']:
                expected = inventory[group['role']]
                require(group['native_identity'] == expected['native_identity'] and group['accounting_class'] == expected['accounting_class'], 'inventory_identity_mismatch')
                require(type(group.get('memory_stat')) is dict, 'missing_kernel_accounting')
                require({'oom', 'oom_kill'} <= set(group['memory_events']), 'oom_accounting_unavailable')
                require({'anon', 'file', 'kernel', 'sock'} <= set(group['memory_stat']), 'kernel_accounting_unavailable')
                for key, value in group['memory_stat'].items():
                    integer(value)
                    if key in byte_gauges and expected['accounting_class'] != 'workload':
                        sample_memory_stat[key] = sample_memory_stat.get(key, 0) + value
                if expected['accounting_class'] != 'workload':
                    memory += integer(group['memory_current_bytes'])
                for process in group['processes']:
                    key = integer(process['pid'], 1), integer(process['start'], 1)
                    require(key not in current, 'duplicate_pid_accounting')
                    require(process['executable_sha256'] in manifest['executable_labels'], 'unclassified_executable')
                    require(process['label'] == manifest['executable_labels'][process['executable_sha256']], 'executable_label_mismatch')
                    require(process['state'] in 'RSDZTWtXxKPI', 'invalid_process_state')
                    if process['state'] in 'ZXTtx':
                        problems.append('terminal_or_stopped_process:' + str(key))
                    relative = process['cgroup']
                    require(relative == expected['relative'] or relative.startswith(expected['relative'] + '/'), 'process_outside_group')
                    current[key] = (group['role'], process['executable_sha256'], relative, process['state'])
                    label = process['label']
                    category = expected['accounting_class']
                    if label in CONTROL:
                        require(category in ('control','mixed'), 'control_pss_outside_control_group')
                        control_pss += integer(process['pss_bytes'])
                        if category == 'mixed': observed_mixed_control_roles.add(group['role'])
                    elif label == 'tailscale':
                        require(category in ('tailscale','mixed'), 'tailscale_pss_in_wrong_group')
                        tailscale_pss += integer(process['pss_bytes'])
                    else:
                        require(category != 'control', 'noncontrol_process_in_supervision_cpu_group')
            for stable in manifest['stable_processes']:
                key = stable['pid'], stable['start']
                if key not in current or current[key][:2] != (stable['group'], stable['executable_sha256']):
                    problems.append('stable_process_missing_or_changed:' + str(key))
            if previous:
                for key in sorted(set(previous) | set(current)):
                    if previous.get(key) != current.get(key):
                        lifecycle.append(dict(sequence=row['sequence'], pid=key[0], start=key[1],
                                              before=previous.get(key), after=current.get(key)))
            previous = current
            for key, value in sample_memory_stat.items():
                memory_stat_peak[key] = max(memory_stat_peak.get(key, 0), value)
            footprint_peak = max(footprint_peak, memory)
            control_peak = max(control_peak, control_pss)
            tailscale_peak = max(tailscale_peak, tailscale_pss)
    require(second_digest.hexdigest() == summary['input_sha256'], 'raw_record_changed_between_passes')
    control_cpu_low, control_cpu_high = 0, 0
    service_cpu_low, service_cpu_high, service_cpu_seconds = 0, 0, 0
    for name, cohort in summary['cohorts'].items():
        expected = inventory[name]
        low_ns, high_ns = cohort['cpu_duration_bounds_ns']
        seconds = cohort['cpu_delta_usec']['usage_usec'] / 1000000
        if expected['accounting_class'] != 'workload':
            service_cpu_low += seconds / (high_ns / 1e9)
            service_cpu_high += seconds / (low_ns / 1e9)
            service_cpu_seconds += seconds
        if expected['accounting_class'] == 'control':
            control_cpu_low += seconds / (high_ns / 1e9)
            control_cpu_high += seconds / (low_ns / 1e9)
    if summary['max_gap_ns'] > begin['interval'] * 1.25 * 1e9:
        problems.append('collection_deadline_missed')
    if not summary['pss_valid_for_entire_run']:
        problems.append('incomplete_pss_coverage')
    for name, cohort in summary['cohorts'].items():
        if any(cohort['memory_event_deltas'].get(key, 0) for key in ('oom', 'oom_kill', 'oom_group_kill')):
            problems.append('oom:' + name)
    control_roles = {name for component in ('host_guard_publisher','worker_control','init_shim')
                     for name in manifest['accounting']['required_components'][component]}
    mixed_cpu = bool(observed_mixed_control_roles) or any(inventory[name]['accounting_class'] == 'mixed' for name in control_roles)
    summary.update(origin=manifest['evidence_origin'], binding=manifest['binding'], accounting=manifest['accounting'],
                   collector_sha256=begin['collector_sha256'], collector_helper_sha256=begin['collector_helper_sha256'],
                   analysis_helper_sha256=file_digest(__file__), lifecycle_events=lifecycle, problems=sorted(set(problems)),
                   control_cpu_core_seconds_per_second_bounds=None if mixed_cpu else [control_cpu_low, control_cpu_high],
                   control_cpu_percent_one_core_bounds=None if mixed_cpu else [control_cpu_low * 100, control_cpu_high * 100],
                   router_service_cpu_core_seconds=service_cpu_seconds,
                   router_service_cpu_core_seconds_per_second_bounds=[service_cpu_low, service_cpu_high],
                   router_service_cpu_percent_one_core_bounds=[service_cpu_low*100, service_cpu_high*100],
                   observed_control_bearing_mixed_groups=sorted(observed_mixed_control_roles),
                   control_cpu_coverage='INSUFFICIENT:mixed_cgroup_transient_cpu_unattributable' if mixed_cpu else 'complete_dedicated_cgroup_counters',
                   unavailable_metrics={'supervision_cpu':'mixed cgroup CPU includes Tailscale/runtime; per-PID snapshots cannot account for unsampled short-lived control work'} if mixed_cpu else {},
                   router_service_footprint_peak_bytes=footprint_peak,
                   control_pss_peak_bytes=control_peak if summary['pss_valid_for_entire_run'] else None,
                   tailscale_pss_peak_bytes=tailscale_peak if summary['pss_valid_for_entire_run'] else None,
                   cgroup_memory_stat_peak_totals_bytes=memory_stat_peak,
                   original_window_boottime_ns=[summary.pop('_first_sample_ns'), summary.pop('_last_sample_ns')],
                   observer_included_in_whole_host_context=True,
                   accounting_limitation='Completeness is a Root-reviewed declaration, not discoverable from cgroup samples. Outside-domain relevant overhead makes this method insufficient.')
    return summary


def run_problems(run):
    problems = list(run.get('problems', []))
    if run.get('origin') != 'actual_runtime': problems.append('synthetic_or_unproven_origin')
    if run.get('sample_start_span_ns', 0) < 600 * 10**9: problems.append('short_or_absent_600_second_window')
    if not run.get('pss_valid_for_entire_run', False): problems.append('incomplete_pss_coverage')
    if not run.get('traffic'): problems.append('missing_actual_traffic_and_monitor_evidence')
    if not run.get('accounting', {}).get('complete'): problems.append('incomplete_accounting')
    return sorted(set(problems))


PYTHON_LEGACY_SOURCES = {
    'router_runtime.py':'36a087a833d260fc6c951ed407c22db2448a1a6dea55fdbf5aa8928bb3e11901',
    'host/orchestrate.py':'fe62364ae1c88c409f9e830f448a5a04f00e31927e5d02f24ea5a6b51f1296c9',
}


def validate_protection(value):
    require(type(value) is dict and set(value) == {'kind','evidence_sha256'} and value['kind'] in
            ('tailscale_down','host_quarantine','terminal_quarantine','withdrawal'), 'blocked_protection_evidence')
    digest(value['evidence_sha256'])


def validate_legacy_monitoring(monitor, run, window):
    fields = {'variant','source_bindings','contract','window_boottime_ns','complete','deadline_misses',
              'monotonic_boottime_brackets','router_cycles','health','host_cycles','retry_coverage'}
    require(set(monitor) == fields and run['binding']['implementation'] == 'python', 'legacy_monitor_fields')
    require(monitor['source_bindings'] == PYTHON_LEGACY_SOURCES, 'legacy_source_binding')
    require(monitor['contract'] == MONITORING and monitor['window_boottime_ns'] == window and monitor['complete'] is True, 'legacy_monitor_coverage')
    ids, modes = run['binding']['exit_ids'], dict(zip(run['binding']['exit_ids'],run['binding']['exit_modes']))
    require(all(mode == 'mullvad' for mode in modes.values()), 'legacy_source_mullvad_only_direct_unrepresented')
    # No exact conversion of MONOTONIC to BOOTTIME: retain an intersection of
    # measured offset brackets. Suspend/clock-domain discontinuity is insufficient.
    sync = monitor['monotonic_boottime_brackets']
    require(type(sync) is list and len(sync) >= 2, 'legacy_clock_brackets')
    offsets=[]; previous=None
    for sample in sync:
        require(type(sample) is dict and set(sample) == {'monotonic_before_ns','boottime_ns','monotonic_after_ns'}, 'legacy_clock_fields')
        before,boot,after=(integer(sample[key]) for key in ('monotonic_before_ns','boottime_ns','monotonic_after_ns'))
        require(before <= after and (previous is None or boot > previous), 'legacy_clock_order')
        offsets.append((boot-after,boot-before));previous=boot
    low_offset=max(item[0] for item in offsets);high_offset=min(item[1] for item in offsets)
    require(low_offset <= high_offset and sync[0]['boottime_ns'] <= window[0] and sync[-1]['boottime_ns'] >= window[1], 'legacy_clock_uncertainty_or_suspend')
    require(type(monitor['retry_coverage']) is list and monitor['retry_coverage'], 'missing_retry_coverage')
    operations={}
    for operation in monitor['retry_coverage']:
        require(operation.get('scope') in modes, 'legacy_retry_scope')
        validate_retry(operation,modes[operation['scope']],legacy=True)
        key=operation['scope'],operation['sample_id']
        require(key not in operations, 'duplicate_retry_operation');operations[key]=operation
        handshake=operation['handshake']
        if operation['retry'].get('coverage') == 'aborted':
            require(handshake is None, 'legacy_abort_invented_handshake')
        else:
            require(type(handshake) is dict and set(handshake) == {'wall_before_ns','wall_after_ns','latest_handshake_seconds','event_sha256'}, 'legacy_handshake_evidence')
            before,after=integer(handshake['wall_before_ns']),integer(handshake['wall_after_ns'])
            stamp=integer(handshake['latest_handshake_seconds'])*10**9;digest(handshake['event_sha256'])
            require(before <= after and before >= stamp and after-stamp < 180*10**9, 'legacy_handshake_age_uncertain_or_expired')
    routers=monitor['router_cycles'];referenced=set()
    require(type(routers) is list and {item.get('scope') for item in routers} == set(ids) and len(routers)==len(ids), 'legacy_router_coverage')
    for router in routers:
        require(set(router)=={'scope','clock','cycles'} and router['clock']=='CLOCK_MONOTONIC', 'legacy_router_clock')
        cycles=router['cycles'];require(type(cycles) is list and len(cycles)>=2,'legacy_router_cycles')
        previous=None
        for cycle in cycles:
            require(set(cycle)=={'sample_id','started_ns','work_finished_ns','sleep_started_ns','original_wake_ns','woke_ns','event_sha256'},'legacy_router_cycle_fields')
            started,finished,sleep,wake,woke=(integer(cycle[key]) for key in ('started_ns','work_finished_ns','sleep_started_ns','original_wake_ns','woke_ns'))
            digest(cycle['event_sha256'])
            require(started <= finished <= sleep and wake == sleep+5*10**9 and woke >= wake, 'legacy_original_sleep5')
            require(previous is None or started >= previous, 'legacy_router_cycle_overlap')
            key=router['scope'],cycle['sample_id'];require(key in operations and key not in referenced,'legacy_retry_cycle_coverage')
            operation=operations[key]
            require(started <= operation['started_ns'] <= operation['completed_ns'] <= finished,'legacy_provider_work_window')
            referenced.add(key);previous=woke
        require(cycles[0]['started_ns']+high_offset <= window[0] and cycles[-1]['woke_ns']+low_offset >= window[1], 'legacy_router_window_uncertain')
    require(referenced == set(operations),'legacy_retry_cycle_coverage')
    health=monitor['health']
    require(type(health) is list and {item.get('scope') for item in health}==set(ids) and len(health)==len(ids),'legacy_health_coverage')
    wall_offsets=[]
    for stream in health:
        require(set(stream)=={'scope','observations'},'legacy_health_stream_fields')
        observations=stream['observations'];require(type(observations) is list and len(observations)>=2,'legacy_health_observations')
        previous=None
        for observation in observations:
            require(set(observation)=={'read_begin_ns','read_end_ns','wall_before_ns','wall_after_ns','state','time','heartbeat','status_result','protection','event_sha256'},'legacy_health_fields')
            begin,end,before,after=(integer(observation[key]) for key in ('read_begin_ns','read_end_ns','wall_before_ns','wall_after_ns'))
            digest(observation['event_sha256'])
            require(begin <= end and before <= after and (previous is None or begin > previous),'legacy_health_clock_order')
            wall_offsets.append((before-end,after-begin));previous=end
            if observation['state']=='BLOCKED':
                require(observation['status_result']=='blocked','legacy_blocked_status')
                validate_protection(observation['protection'])
                # None means unavailable; do not replace it with zero/fresh time.
                for key in ('time','heartbeat'):
                    if observation[key] is not None:integer(observation[key])
            else:
                require(observation['state']=='READY' and observation['status_result']=='ready' and observation['protection'] is None,'legacy_health_state')
                heartbeat=integer(observation['heartbeat'])*10**9;integer(observation['time'])
                require(before >= heartbeat and after-heartbeat < 45*10**9,'legacy_health_age_uncertain_or_expired')
        require(observations[0]['read_end_ns'] <= window[0] and observations[-1]['read_begin_ns'] >= window[1],'legacy_health_window_uncertain')
    require(max(value[0] for value in wall_offsets) <= min(value[1] for value in wall_offsets),'legacy_wall_clock_discontinuity')
    host=monitor['host_cycles'];require(type(host) is list and len(host)>=2,'legacy_host_cycles')
    previous={};last_reported={};services={};bounds={};misses=0
    for cycle in host:
        if type(cycle) is dict and cycle.get('outcome') == 'BLOCKED':
            require(set(cycle)=={'scope','service_id_sha256','started_ns','work_finished_ns','event_sha256','outcome','protection'}
                    and cycle['scope'] in ids, 'legacy_blocked_host_fields')
            scope=cycle['scope'];service=digest(cycle['service_id_sha256']);digest(cycle['event_sha256'])
            require(scope not in services or services[scope]==service,'legacy_host_service_changed');services[scope]=service
            started,finished=integer(cycle['started_ns']),integer(cycle['work_finished_ns'])
            require(started <= finished and (scope not in previous or started >= previous[scope]),'legacy_blocked_host_order')
            validate_protection(cycle['protection'])
            matching=next(item['observations'] for item in health if item['scope']==scope)
            require(any(item['state']=='BLOCKED' and started <= item['read_begin_ns']-high_offset
                        and item['read_end_ns']-low_offset <= finished for item in matching),'legacy_blocked_host_health_coverage')
            previous[scope]=finished
            if scope not in bounds:bounds[scope]=[started,finished]
            else:bounds[scope][1]=finished
            continue
        fields={'scope','service_id_sha256','started_ns','work_finished_ns','notify_started_ns','notify_finished_ns','manager_read_started_ns',
                'manager_read_finished_ns','reported_clock','reported_property','reported_timestamp_us','watchdog_usec',
                'sleep_started_ns','original_wake_ns','woke_ns','event_sha256'}
        require(set(cycle)==fields and cycle['scope'] in ids,'legacy_host_cycle_fields');digest(cycle['event_sha256'])
        scope=cycle['scope'];service=digest(cycle['service_id_sha256'])
        require(scope not in services or services[scope]==service,'legacy_host_service_changed');services[scope]=service
        started,finished,sent,sent_end,read,read_end,sleep,wake,woke=(integer(cycle[key]) for key in
            ('started_ns','work_finished_ns','notify_started_ns','notify_finished_ns','manager_read_started_ns','manager_read_finished_ns','sleep_started_ns','original_wake_ns','woke_ns'))
        require(started <= finished <= sent <= sent_end <= read <= read_end <= sleep and wake==sleep+2*10**9 and woke>=wake,'legacy_original_sleep2')
        require(scope not in previous or started >= previous[scope],'legacy_host_cycle_overlap')
        require(cycle['reported_clock']=='CLOCK_MONOTONIC' and cycle['reported_property']=='WatchdogTimestampMonotonic'
                and type(cycle['watchdog_usec']) is int and cycle['watchdog_usec']==90*10**6,'legacy_systemd_clock_or_lease')
        reported=integer(cycle['reported_timestamp_us'])*1000
        # systemd exposes microseconds: preserve the [stamp,stamp+1us) bracket.
        require(reported+1000 > sent and reported <= read_end and (scope not in last_reported or reported>last_reported[scope]),'legacy_systemd_receipt_unavailable')
        if scope in last_reported:misses+=int(read_end >= last_reported[scope]+90*10**9)
        misses+=int(read_end >= reported+90*10**9)
        matching=next(item['observations'] for item in health if item['scope']==scope)
        selected=[item for item in matching if started <= item['read_begin_ns']-high_offset and item['read_end_ns']-low_offset <= finished]
        require(selected,'legacy_host_health_coverage')
        require(all(item['heartbeat'] is not None and item['wall_before_ns'] >= item['heartbeat']*10**9
                    and item['wall_after_ns']-item['heartbeat']*10**9 < 45*10**9 for item in selected),
                'legacy_no_fresh_health_requires_host_abort')
        last_reported[scope]=reported;previous[scope]=woke
        if scope not in bounds:bounds[scope]=[started,woke]
        else:bounds[scope][1]=woke
    require(set(bounds)==set(ids) and len(set(services.values()))==len(services),'legacy_host_service_coverage')
    require(all(start+high_offset <= window[0] and finish+low_offset >= window[1] for start,finish in bounds.values()),'legacy_host_window_uncertain')
    require(integer(monitor['deadline_misses'])==misses,'monitor_miss_projection')
    return misses


def validate_retry(operation, mode, legacy=False):
    """Replay the conditional once-only retry; a 1s timer is a not-before bound."""
    fields = {'scope','sample_id','started_ns','completed_ns','original_deadline_ns',
              'first_result','first_finished_ns','retry'}
    if legacy: fields |= {'attempt_timeout_ns','handshake'}
    require(type(operation) is dict and set(operation) == fields, 'retry_operation_fields')
    started, finished, first_end = (integer(operation[key]) for key in ('started_ns','completed_ns','first_finished_ns'))
    if legacy:
        require(operation['original_deadline_ns'] is None and operation['attempt_timeout_ns'] == 12*10**9, 'legacy_per_attempt_timeout')
        deadline = None
    else:
        deadline = integer(operation['original_deadline_ns'])
        require(deadline == started + 34*10**9, 'rust_original_outer34_window')
    require(started <= first_end <= finished and (deadline is None or started < deadline), 'retry_operation_order')
    require(type(operation['sample_id']) is str and 1 <= len(operation['sample_id']) <= 96, 'retry_operation_id')
    outcomes = {'success','http_408','http_429','http_5xx','transport_eligible','attempt_timeout',
                'http_permanent','tls_permanent','malformed','negative','wrong_server'}
    eligible = {'http_408','http_429','http_5xx','transport_eligible','attempt_timeout'}
    result, retry = operation['first_result'], operation['retry']
    require(result in outcomes and type(retry) is dict, 'retry_first_result')
    if result not in eligible:
        require(set(retry) == {'coverage','reason'} and retry['coverage'] == 'not_triggered'
                and retry['reason'] == result, 'retry_no_trigger_coverage')
    elif retry.get('coverage') == 'aborted':
        stage = retry.get('stage')
        fields = {'coverage','reason','stage','failed_check','protection'}
        if stage == 'after_delay': fields |= {'pre_delay_check','delay_started_ns','original_not_before_ns'}
        require(stage in ('before_delay','after_delay') and set(retry) == fields and retry['reason'] == result, 'retry_abort_fields')
        failed = retry['failed_check']
        require(type(failed) is dict and set(failed) == {'checked_ns','failed_component','event_sha256'}
                and failed['failed_component'] in ('interfaces','default_route','handshake'), 'retry_abort_failed_check')
        checked = integer(failed['checked_ns']);digest(failed['event_sha256'])
        require(first_end <= checked <= finished, 'retry_abort_order')
        validate_protection(retry['protection'])
        if stage == 'after_delay':
            before = retry['pre_delay_check']
            require(type(before) is dict and set(before) == {'checked_ns','interfaces_sha256','routes_sha256','handshake_age_ns'}, 'retry_abort_pre_check')
            digest(before['interfaces_sha256']);digest(before['routes_sha256'])
            if mode == 'mullvad': require(integer(before['handshake_age_ns']) < 180*10**9, 'retry_stale_handshake')
            else: require(before['handshake_age_ns'] is None, 'direct_retry_handshake')
            delay,not_before=integer(retry['delay_started_ns']),integer(retry['original_not_before_ns'])
            require(first_end <= integer(before['checked_ns']) <= delay and not_before == delay+10**9
                    and not_before <= checked, 'retry_abort_original_timer')
    else:
        require(set(retry) == {'coverage','reason','pre_delay_check','delay_started_ns',
                'original_not_before_ns','post_delay_check','retry_started_ns','retry_completed_ns','retry_result'}
                and retry['coverage'] == 'triggered' and retry['reason'] == result, 'retry_trigger_coverage')
        delay, not_before, retry_start, retry_end = (integer(retry[key]) for key in
            ('delay_started_ns','original_not_before_ns','retry_started_ns','retry_completed_ns'))
        require(not_before == delay + 10**9, 'retry_original_one_second_timer')
        checks = []
        for name in ('pre_delay_check','post_delay_check'):
            check = retry[name]
            require(type(check) is dict and set(check) == {'checked_ns','interfaces_sha256','routes_sha256','handshake_age_ns'}, 'retry_fresh_check_fields')
            checked = integer(check['checked_ns']); digest(check['interfaces_sha256']); digest(check['routes_sha256'])
            if mode == 'mullvad': require(integer(check['handshake_age_ns']) < 180*10**9, 'retry_stale_handshake')
            else: require(check['handshake_age_ns'] is None, 'direct_retry_handshake')
            checks.append(checked)
        require(first_end <= checks[0] <= delay < not_before <= checks[1] <= retry_start <= retry_end <= finished,
                'retry_missing_fresh_pre_post_delay_checks')
        require(retry['retry_result'] in outcomes, 'retry_second_result')
    # The original outer operation deadline is exclusive. HTTP attempt timeout
    # is an eligible first_result, not an invented successful monitor deadline.
    return int(finished >= deadline) if deadline is not None else 0


def validate_monitoring(monitor, run, window):
    require(type(monitor) is dict and 'retry_coverage' in monitor, 'missing_retry_coverage')
    if monitor.get('variant') == 'python_legacy_v1': return validate_legacy_monitoring(monitor, run, window)
    require(monitor.get('variant') == 'rust_native_v1' and monitor.get('source_bindings') ==
            {'source_sha256':run['binding']['source_sha256']}, 'rust_monitor_source_binding')
    require(run['binding']['implementation'] == 'rust', 'rust_monitor_implementation')
    require(set(monitor) == {'variant','source_bindings','contract','window_boottime_ns','complete','deadline_misses','streams','retry_coverage'}, 'monitor_fields')
    require(monitor['contract'] == MONITORING and monitor['window_boottime_ns'] == window
            and monitor['complete'] is True, 'monitor_coverage')
    ids, modes = run['binding']['exit_ids'], dict(zip(run['binding']['exit_ids'],run['binding']['exit_modes']))
    expected = {(component, scope, None) for scope in ids for component in ('cadence','health')}
    expected.update({('watchdog',scope,writer) for scope in ids for writer in ('transport','data','host')})
    streams = monitor['streams']
    require(type(streams) is list, 'monitor_stream_fields')
    observed = set()
    by_scope = {}
    for stream in streams:
        require(type(stream) is dict and set(stream) == ({'component','scope','writer','observations'}
                if stream.get('component') == 'watchdog' else {'component','scope','observations'}), 'monitor_stream_fields')
        key = stream['component'], stream['scope'], stream.get('writer')
        require(key not in observed, 'duplicate_monitor_stream')
        observed.add(key); by_scope[key] = stream['observations']
    require(observed == expected, 'monitor_stream_coverage')
    operations = monitor['retry_coverage']
    require(type(operations) is list and operations, 'missing_retry_coverage')
    operation_by_id, misses = {}, 0
    for operation in operations:
        require(type(operation) is dict and operation.get('scope') in modes, 'retry_operation_scope')
        misses += validate_retry(operation, modes[operation['scope']])
        key = operation['scope'], operation['sample_id']
        require(key not in operation_by_id, 'duplicate_retry_operation')
        operation_by_id[key] = operation
    referenced, started_operations = set(), set()
    health_by_scope = {}
    for scope in ids:
        ticks = by_scope['cadence',scope,None]
        require(type(ticks) is list and len(ticks) >= 2, 'missing_cadence_ticks')
        previous = None
        for tick in ticks:
            require(type(tick) is dict and set(tick) == {'scheduled_ns','completed_ns','deadline_ns','action','sample_id'}, 'cadence_fields')
            scheduled, completed, deadline = (integer(tick[key]) for key in ('scheduled_ns','completed_ns','deadline_ns'))
            require(scheduled <= completed and scheduled < deadline <= scheduled + 5*10**9, 'cadence_original_deadline')
            require(previous is None or scheduled - previous == 5*10**9, 'monitor_schedule_gap_or_reset')
            misses += int(completed >= deadline)
            key = scope,tick['sample_id']
            require(key in operation_by_id, 'missing_retry_coverage_for_cadence')
            operation = operation_by_id[key]
            require(tick['action'] in ('sample','heartbeat'), 'cadence_action')
            if tick['action'] == 'sample':
                require(key not in started_operations and scheduled <= operation['started_ns'] < deadline, 'provider_operation_original_start')
                started_operations.add(key)
            else:
                require(operation['started_ns'] <= scheduled < operation['completed_ns'], 'heartbeat_without_pending_operation')
            referenced.add(key); previous = scheduled
        require(ticks[0]['scheduled_ns'] <= window[0] and ticks[-1]['scheduled_ns'] >= window[1], 'monitor_window_not_covered')
        observations = by_scope['health',scope,None]
        require(type(observations) is list and len(observations) >= 2, 'missing_health_observations')
        previous_at, previous_expiry = None, None
        for observation in observations:
            if type(observation) is dict and observation.get('state') == 'BLOCKED':
                require(set(observation) == {'observed_ns','state','protection'}, 'blocked_health_fields')
                now=integer(observation['observed_ns']);validate_protection(observation['protection'])
                require(previous_at is None or now > previous_at, 'health_time_reset')
                previous_at,previous_expiry=now,None
                continue
            require(type(observation) is dict and set(observation) == {'observed_ns','provider_at_ns','structural_at_ns',
                    'heartbeat_at_ns','verified_at_ns','message_sent_ns','handshake_age_at_structural_ns','session_deadline_ns'}, 'health_observation_fields')
            now = integer(observation['observed_ns'])
            anchors = [integer(observation[key]) for key in ('provider_at_ns','structural_at_ns','heartbeat_at_ns','verified_at_ns')]
            sent = integer(observation['message_sent_ns'])
            require(all(anchor <= sent <= now and now - anchor < 45*10**9 for anchor in anchors), 'health_original_age_expired')
            require(now - sent < 2*10**9, 'health_message_age_expired')
            # Session expires strictly before the shared45s boundary (44s margin).
            expiry = min(sent,min(anchors)) + 44*10**9
            age = observation['handshake_age_at_structural_ns']
            if modes[scope] == 'mullvad':
                integer(age)
                handshake_expiry = observation['structural_at_ns'] + 180*10**9 - age
                require(age < 180*10**9 and now < handshake_expiry, 'handshake_original_age_expired')
                expiry = min(expiry,handshake_expiry)
            else: require(age is None, 'direct_health_handshake')
            require(integer(observation['session_deadline_ns']) == expiry, 'health_original_expiry_changed')
            misses += int(now >= expiry)
            require(previous_at is None or now > previous_at, 'health_time_reset')
            require(previous_expiry is None or now < previous_expiry, 'health_expiry_gap')
            previous_at, previous_expiry = now, expiry
        require(observations[0]['observed_ns'] <= window[0] and observations[-1]['observed_ns'] >= window[1], 'health_window_not_covered')
        health_by_scope[scope] = observations
    require(referenced == set(operation_by_id) and started_operations == set(operation_by_id), 'retry_cadence_coverage_mismatch')
    for scope in ids:
        for writer in ('transport','data','host'):
            observations = by_scope['watchdog',scope,writer]
            require(type(observations) is list and len(observations) >= 2, 'missing_watchdog_observations')
            previous, previous_at, health_index = None, None, 0
            health = health_by_scope[scope]
            for observation in observations:
                if type(observation) is dict and observation.get('state') == 'BLOCKED':
                    require(set(observation) == {'observed_ns','state','protection'}, 'blocked_watchdog_fields')
                    now=integer(observation['observed_ns']);validate_protection(observation['protection'])
                    require(previous_at is None or now > previous_at, 'watchdog_observation_clock_order')
                    previous_at=now
                    if previous is not None:require(now > previous['observed_ns'], 'watchdog_observation_gap_or_reset')
                    previous=None
                    continue
                require(type(observation) is dict and set(observation) == {'observed_ns','liveness_sent_ns','accepted_ns',
                        'lease_deadline_ns','session_deadline_ns','trigger_ns','sequence'}, 'watchdog_observation_fields')
                now,sent,accepted,lease,session,trigger,sequence = (integer(observation[key]) for key in
                    ('observed_ns','liveness_sent_ns','accepted_ns','lease_deadline_ns','session_deadline_ns','trigger_ns','sequence'))
                require(previous_at is None or now > previous_at, 'watchdog_observation_clock_order')
                previous_at=now
                require(sequence > 0 and sent <= accepted <= now and accepted - sent < 2*10**9, 'watchdog_original_liveness_age')
                require(lease == sent + 90*10**9 and trigger == min(lease,session) - 5*10**9, 'watchdog_original_lease_changed')
                while health_index + 1 < len(health) and health[health_index+1]['observed_ns'] <= now: health_index += 1
                require(health[health_index]['observed_ns'] <= now and health[health_index].get('state') != 'BLOCKED' and session == health[health_index].get('session_deadline_ns'), 'watchdog_health_binding')
                misses += int(now >= trigger)
                if previous is not None:
                    require(now > previous['observed_ns'] and now < previous['trigger_ns'], 'watchdog_observation_gap_or_reset')
                    require(sequence in (previous['sequence'], previous['sequence']+1), 'watchdog_liveness_sequence_gap')
                    if sequence == previous['sequence']:
                        require(sent == previous['liveness_sent_ns'] and accepted == previous['accepted_ns'], 'watchdog_liveness_rejuvenated')
                    else: require(sent >= previous['liveness_sent_ns'], 'watchdog_liveness_clock_reset')
                previous = observation
            require(observations[0]['observed_ns'] <= window[0] and observations[-1]['observed_ns'] >= window[1], 'watchdog_window_not_covered')
    require(integer(monitor['deadline_misses']) == misses, 'monitor_miss_projection')
    return misses


def validate_traffic(value, run):
    require(type(value) is dict and set(value) == {'schema', 'evidence_origin', 'binding', 'record_sha256', 'provenance',
            'window_boottime_ns', 'throughput_bytes_per_second', 'throughput_intervals', 'latency_ns', 'monitoring', 'unexpected_restarts', 'oom_events', 'traffic_protocols'}, 'traffic_fields')
    require(value['schema'] == 2 and value['evidence_origin'] == 'actual_runtime', 'traffic_not_actual')
    require(value['binding'] == run['binding'], 'traffic_binding_mismatch')
    require(value['record_sha256'] == run['input_sha256'], 'traffic_record_mismatch')
    require(value['window_boottime_ns'] == run['original_window_boottime_ns'], 'traffic_original_window_mismatch')
    proof = value['provenance']
    require(set(proof) == {'producer_sha256', 'raw_evidence_sha256', 'review_sha256', 'kind'}, 'traffic_provenance')
    for key in ('producer_sha256', 'raw_evidence_sha256', 'review_sha256'): digest(proof[key])
    require(proof['kind'] == 'real_disposable_tailscale_clients', 'traffic_source_not_real_clients')
    require(set(value['traffic_protocols']) == {'ipv4', 'dns', 'ipv6', 'tcp', 'udp'}, 'incomplete_protocol_coverage')
    number(value['throughput_bytes_per_second'], 0.000001)
    cursor = value['window_boottime_ns'][0]
    total_bytes = 0
    require(type(value['throughput_intervals']) is list and value['throughput_intervals'], 'missing_traffic_intervals')
    for interval in value['throughput_intervals']:
        require(set(interval) == {'start_ns', 'end_ns', 'bytes'}, 'traffic_interval_fields')
        low, high = integer(interval['start_ns']), integer(interval['end_ns'])
        require(low == cursor and high > low, 'traffic_gap_overlap_or_reset')
        cursor = high; total_bytes += integer(interval['bytes'])
    require(cursor == value['window_boottime_ns'][1], 'traffic_gap_at_end')
    duration = (cursor - value['window_boottime_ns'][0]) / 1e9
    require(duration > 0 and math.isclose(total_bytes / duration, value['throughput_bytes_per_second'], rel_tol=1e-12), 'throughput_projection')
    latency = value['latency_ns']
    require(set(latency) == {'p95', 'samples', 'complete', 'values_ns'}, 'latency_fields')
    number(latency['p95'], 0.000001); integer(latency['samples'], 1)
    require(latency['complete'] is True and type(latency['values_ns']) is list and len(latency['values_ns']) == latency['samples'], 'incomplete_latency')
    for item in latency['values_ns']: integer(item, 1)
    require(sorted(latency['values_ns'])[math.ceil(.95 * latency['samples']) - 1] == latency['p95'], 'p95_projection')
    validate_monitoring(value['monitoring'], run, value['window_boottime_ns'])
    for key in ('unexpected_restarts', 'oom_events'): integer(value[key])
    return value


def compare_runs(python, rust):
    """Require repetitions for each steady/load 1/5/6 case; never average away failure."""
    scenarios = []
    global_issues = []
    all_submitted = python + rust
    for implementation, runs in (('python', python), ('rust', rust)):
        for key in ('source_sha256', 'artifact_sha256'):
            if len({run['binding'][key] for run in runs}) > 1:
                global_issues.append('suite_' + implementation + '_' + key + '_mismatch')
    for key in ('collector_sha256', 'collector_helper_sha256', 'summarizer_sha256', 'analysis_helper_sha256'):
        if len({run[key] for run in all_submitted}) > 1:
            global_issues.append('suite_instrumentation_version_mismatch:' + key)
    for key in ('host_id_sha256','tailscale_version','tailscale_artifact_sha256'):
        if len({run['binding'][key] for run in all_submitted}) > 1:
            global_issues.append('suite_host_or_tailscale_mismatch:' + key)
    fingerprints = [run['input_sha256'] for run in all_submitted]
    if len(set(fingerprints)) != len(fingerprints): global_issues.append('duplicate_record')
    run_ids = [run['binding']['run_id'] for run in all_submitted]
    if len(set(run_ids)) != len(run_ids): global_issues.append('duplicate_global_run_id')
    ordered = sorted(all_submitted, key=lambda r: (r['binding']['host_id_sha256'], r['boot_id'], r['original_window_boottime_ns'][0]))
    for old, new in zip(ordered, ordered[1:]):
        if (old['binding']['host_id_sha256'], old['boot_id']) == (new['binding']['host_id_sha256'], new['boot_id']) and new['original_window_boottime_ns'][0] <= old['original_window_boottime_ns'][1]:
            global_issues.append('concurrent_same_host_benchmarks')
    for count, mode in SCENARIOS:
        baseline = [r for r in python if r.get('binding', {}).get('exits') == count and r['binding'].get('scenario') == mode]
        candidate = [r for r in rust if r.get('binding', {}).get('exits') == count and r['binding'].get('scenario') == mode]
        issues = list(global_issues)
        if len(baseline) < 2 or len(candidate) < 2: issues.append('need_two_complete_python_and_rust_repetitions')
        baseline_by_rep = {r['binding']['repetition']: r for r in baseline}
        candidate_by_rep = {r['binding']['repetition']: r for r in candidate}
        if len(baseline_by_rep) != len(baseline) or len(candidate_by_rep) != len(candidate): issues.append('duplicate_repetition')
        if set(baseline_by_rep) != set(candidate_by_rep): issues.append('unmatched_repetitions')
        all_runs = baseline + candidate
        for run in all_runs: issues.extend(run_problems(run))
        matching = ('host_id_sha256', 'tailscale_version', 'tailscale_artifact_sha256', 'config_sha256',
                    'workload_sha256', 'identity_set_sha256', 'peers_sha256', 'network_conditions_sha256', 'monitoring', 'exit_ids', 'exit_modes')
        for index, runs in enumerate((baseline, candidate)):
            expected = 'python' if index == 0 else 'rust'
            if any(r['binding']['implementation'] != expected for r in runs): issues.append('wrong_implementation')
            if len({r['binding']['run_id'] for r in runs}) != len(runs): issues.append('duplicate_run_id')
            for key in ('source_sha256', 'artifact_sha256'):
                if len({r['binding'][key] for r in runs}) > 1: issues.append('source_or_artifact_changed_between_repetitions')
        if len({r['input_sha256'] for r in all_runs}) != len(all_runs): issues.append('duplicate_record')
        for run in all_runs[1:]:
            if any(run[key] != all_runs[0][key] for key in ('collector_sha256','collector_helper_sha256','summarizer_sha256','analysis_helper_sha256')): issues.append('instrumentation_version_mismatch')
            if any(run['binding'].get(k) != all_runs[0]['binding'].get(k) for k in matching): issues.append('host_version_or_workload_mismatch')
            if run.get('accounting') != all_runs[0].get('accounting'): issues.append('accounting_method_or_coverage_mismatch')
        # Same boot supports detecting concurrent identity copies; same host may be rebooted.
        ordered = sorted(all_runs, key=lambda r: (r.get('boot_id',''), r.get('original_window_boottime_ns',[0])[0]))
        for old, new in zip(ordered, ordered[1:]):
            if old.get('boot_id') == new.get('boot_id') and new['original_window_boottime_ns'][0] <= old['original_window_boottime_ns'][1]:
                issues.append('overlapping_same_identity_windows')
        row = dict(exits=count, scenario=mode, python_repetitions=len(baseline), rust_repetitions=len(candidate),
                   accounting=all_runs[0]['accounting'] if all_runs else None)
        if issues:
            row.update(status='NOT_RUN' if not all_runs else 'INSUFFICIENT', reasons=sorted(set(issues)), gates={})
        else:
            # Worst Rust vs best Python: repetitions cannot hide a regression.
            cpu_complete = all(r['control_cpu_core_seconds_per_second_bounds'] is not None for r in all_runs)
            python_cpu = min(r['control_cpu_core_seconds_per_second_bounds'][0] for r in baseline) if cpu_complete else None
            rust_cpu = max(r['control_cpu_core_seconds_per_second_bounds'][1] for r in candidate) if cpu_complete else None
            python_memory = min(r['router_service_footprint_peak_bytes'] for r in baseline)
            rust_memory = max(r['router_service_footprint_peak_bytes'] for r in candidate)
            python_throughput = max(r['traffic']['throughput_bytes_per_second'] for r in baseline)
            rust_throughput = min(r['traffic']['throughput_bytes_per_second'] for r in candidate)
            python_latency = min(r['traffic']['latency_ns']['p95'] for r in baseline)
            rust_latency = max(r['traffic']['latency_ns']['p95'] for r in candidate)
            gates = dict(total_memory=rust_memory <= python_memory,
                         throughput=rust_throughput >= .95 * python_throughput,
                         p95_latency=rust_latency <= 1.05 * python_latency,
                         no_monitor_miss_restart_oom=all(not (r['traffic']['monitoring']['deadline_misses'] or
                          r['traffic']['unexpected_restarts'] or r['traffic']['oom_events']) for r in all_runs))
            if count == 1: gates['supervision_cpu_reduction_at_least_50_percent'] = (python_cpu > 0 and rust_cpu <= .5 * python_cpu) if cpu_complete else 'INSUFFICIENT'
            if count in (1,5): gates['control_pss'] = max(r['control_pss_peak_bytes'] for r in candidate) <= (16 if count == 1 else 48) * 1024**2
            pairs = []
            for repetition in sorted(baseline_by_rep):
                py, rs = baseline_by_rep[repetition], candidate_by_rep[repetition]
                cpu = py['control_cpu_core_seconds_per_second_bounds'][0] if cpu_complete else None
                memory = py['router_service_footprint_peak_bytes']
                pairs.append(dict(repetition=repetition,
                    python_record_sha256=py['input_sha256'], rust_record_sha256=rs['input_sha256'],
                    python_binding=py['binding'], rust_binding=rs['binding'],
                    python_window_boottime_ns=py['original_window_boottime_ns'], rust_window_boottime_ns=rs['original_window_boottime_ns'],
                    ratios=dict(cpu=rs['control_cpu_core_seconds_per_second_bounds'][1]/cpu if cpu_complete and cpu else None,
                        memory=rs['router_service_footprint_peak_bytes']/memory if memory else None,
                        throughput=rs['traffic']['throughput_bytes_per_second']/py['traffic']['throughput_bytes_per_second'],
                        p95_latency=rs['traffic']['latency_ns']['p95']/py['traffic']['latency_ns']['p95'])))
            row.update(status='FAIL' if any(value is False for value in gates.values()) else 'INSUFFICIENT' if 'INSUFFICIENT' in gates.values() else 'PASS',
                       gates=gates, pairs=pairs, unavailable_metrics={} if cpu_complete else {'supervision_cpu':'mixed cgroup or otherwise incomplete control CPU coverage'},
                       control_pss_target_bytes=(16 if count == 1 else 48) * 1024**2 if count in (1,5) else None,
                       ranges={name: {'python': spread_values([extract(r) for r in baseline]),
                                      'rust': spread_values([extract(r) for r in candidate])} for name, extract in
                               [('control_pss_bytes', lambda r: r['control_pss_peak_bytes']),
                                ('service_footprint_bytes', lambda r: r['router_service_footprint_peak_bytes']),
                                ('supervision_cpu_core_seconds_per_second', lambda r: r['control_cpu_core_seconds_per_second_bounds'][1] if r['control_cpu_core_seconds_per_second_bounds'] is not None else None),
                                ('throughput_bytes_per_second', lambda r: r['traffic']['throughput_bytes_per_second']),
                                ('p95_latency_ns', lambda r: r['traffic']['latency_ns']['p95'])]},
                       worst_case_ratios=dict(cpu=rust_cpu / python_cpu if python_cpu else None,
                           memory=rust_memory / python_memory if python_memory else None,
                           throughput=rust_throughput / python_throughput, p95_latency=rust_latency / python_latency))
        scenarios.append(row)
    statuses = {row['status'] for row in scenarios}
    status = 'FAIL' if 'FAIL' in statuses else 'PASS' if statuses == {'PASS'} else 'NOT_RUN' if statuses == {'NOT_RUN'} else 'INSUFFICIENT'
    return dict(schema=1, status=status, scope='Performance evidence only; independent security/client/release acceptance still required.',
                scenarios=scenarios, uncertainty='Counter brackets and repetition ranges retained; conservative worst-case comparison, no inferred statistical significance.')


def spread_values(values):
    if any(value is None for value in values): return dict(status='INSUFFICIENT', reason='unavailable_measurements', values=values)
    return dict(min=min(values), max=max(values), median=statistics.median(values), samples=len(values))


def validate_soak(value):
    """Validate a complete actual 24h timeline of already validated real run segments."""
    issues, events = [], []
    try:
        require(type(value) is dict and set(value) == {'schema', 'evidence_origin', 'binding', 'window_boottime_ns', 'segments', 'provenance'}, 'soak_fields')
        require(value['schema'] == 1 and value['evidence_origin'] == 'actual_runtime', 'soak_not_actual')
        validate_binding(value['binding'])
        require(value['binding']['exits'] == 6, 'soak_not_mixed_five_plus_direct')
        require(set(value['provenance']) == {'review_sha256', 'raw_timeline_sha256', 'producer_sha256'}, 'soak_provenance')
        for item in value['provenance'].values(): digest(item)
        start, finish = value['window_boottime_ns']
        integer(start); integer(finish)
        require(finish - start >= 86400 * 10**9, 'shorter_than_actual_24_hours')
        segments = value['segments']
        require(type(segments) is list and 1 <= len(segments) <= 10000, 'missing_soak_segments')
        cursor, boot, accounting = start, None, None
        for run in segments:
            require(not run_problems(run), 'incomplete_or_synthetic_soak_segment')
            require(run['binding'] == value['binding'], 'soak_binding_mismatch')
            low, high = run['original_window_boottime_ns']
            require(low == cursor and high > low, 'soak_gap_overlap_or_reset')
            require(boot is None or run['boot_id'] == boot, 'soak_boot_changed')
            require(accounting is None or run['accounting'] == accounting, 'soak_accounting_changed')
            boot, cursor, accounting = run['boot_id'], high, run['accounting']
            require(not run['traffic']['monitoring']['deadline_misses'] and not run['traffic']['unexpected_restarts'] and not run['traffic']['oom_events'], 'soak_monitor_restart_oom_failure')
            events.extend(run['lifecycle_events'])
        require(cursor == finish, 'soak_window_not_covered')
    except (ValueError, KeyError, TypeError) as error:
        issues.append(str(error))
    return dict(schema=1, status='INSUFFICIENT' if issues else 'PASS', reasons=issues,
                lifecycle_events=events, scope='Actual-duration evidence timeline only; mandatory mixed fault/capture acceptance remains separate.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    compare = sub.add_parser('compare')
    compare.add_argument('--python', nargs='+', default=[])
    compare.add_argument('--rust', nargs='+', default=[])
    soak = sub.add_parser('soak')
    soak.add_argument('timeline')
    args = parser.parse_args()
    if args.command == 'compare':
        # Inputs are descriptors pointing to raw JSONL and matching public traffic evidence,
        # never caller-edited summaries that can bypass raw lifecycle validation.
        import analyze
        def read_run(descriptor):
            value = load_json(descriptor)
            require(set(value) == {'record', 'traffic', 'record_sha256', 'traffic_sha256'}, 'run_descriptor_fields')
            base = pathlib.Path(descriptor).resolve().parent
            record, traffic = base / value['record'], base / value['traffic']
            require(file_digest(record) == digest(value['record_sha256']) and file_digest(traffic) == digest(value['traffic_sha256']), 'descriptor_digest_mismatch')
            run = analyze.summarize(record)
            require(run['input_sha256'] == value['record_sha256'], 'record_changed_after_descriptor_check')
            run['traffic'] = validate_traffic(load_bound_json(traffic, value['traffic_sha256']), run)
            return run
        result = compare_runs([read_run(p) for p in args.python], [read_run(p) for p in args.rust])
    else:
        # Segment descriptors are revalidated exactly as compare inputs; no trusted summaries.
        value = load_json(args.timeline)
        import analyze
        segments = []
        base = pathlib.Path(args.timeline).resolve().parent
        for descriptor in value.get('segments', []):
            require(set(descriptor) == {'record', 'traffic', 'record_sha256', 'traffic_sha256'}, 'soak_descriptor_fields')
            record, traffic = base / descriptor['record'], base / descriptor['traffic']
            require(file_digest(record) == digest(descriptor['record_sha256']) and file_digest(traffic) == digest(descriptor['traffic_sha256']), 'soak_descriptor_digest')
            run = analyze.summarize(record)
            require(run['input_sha256'] == descriptor['record_sha256'], 'soak_record_changed_after_descriptor_check')
            run['traffic'] = validate_traffic(load_bound_json(traffic, descriptor['traffic_sha256']), run)
            segments.append(run)
        value['segments'] = segments
        result = validate_soak(value)
    print(json.dumps(result, indent=2, allow_nan=False))
    return 0 if result['status'] == 'PASS' else 2


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError) as error:
        print(json.dumps(dict(schema=1, status='INSUFFICIENT', reason=type(error).__name__ + ':' + str(error))))
        raise SystemExit(2)
