"""Summarize bound read-only accounting output, without performance acceptance.

CPU includes short-lived cohort processes through cumulative cgroup counters.
PSS estimates are suppressed for the complete run if any sample is invalid.
Raw JSONL and its digest remain necessary evidence. No workload is launched.
"""
import hashlib
import json
import math
import pathlib
import sys

if not __debug__:
    raise RuntimeError('optimized_python_refused')


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def integer(value, minimum=0):
    require(type(value) is int and value >= minimum, 'invalid_integer')
    return value


def finite(value, minimum=0):
    require(type(value) in (int, float) and math.isfinite(value) and value >= minimum, 'invalid_number')
    return value


def summarize(path):
    digest = hashlib.sha256()
    begin = end = previous = None
    sequence = 0
    pending = None
    base = None
    cohorts = {}
    first_host = last_host = None
    first_host_bounds = last_host_bounds = None
    host_memory_max = {}
    host_memory_min = {}
    invalid_samples = []
    max_gap = 0
    last_observer = 0
    last_flush = None
    samples = 0
    first_elapsed = None
    total_pss_weighted = 0
    total_pss_max = 0
    with path.open('rb') as stream:
        for line_number, raw in enumerate(stream, 1):
            require(line_number <= 700010 and len(raw) <= 64 * 1024 * 1024, 'input_bound_exceeded')
            digest.update(raw)
            row = json.loads(raw)
            require(type(row) is dict and end is None, 'trailing_or_invalid_record')
            kind = row.get('kind')
            if begin is None:
                require(kind == 'begin' and row['clock'] == 'CLOCK_BOOTTIME', 'missing_begin')
                require(all(type(row[key]) is str and len(row[key]) == 64 and set(row[key]) <= set('0123456789abcdef') for key in ('manifest_sha256', 'workload_binding_sha256')), 'missing_binding')
                require(1 <= integer(row['requested_seconds']) <= 86400 and 0.25 <= finite(row['interval']) <= 10, 'invalid_interval')
                begin = row
                continue
            if kind == 'sample':
                require(pending is None and row['sequence'] == sequence, 'sample_pair_or_sequence')
                elapsed = integer(row['elapsed_ns'])
                if first_elapsed is None: first_elapsed = elapsed
                gap = integer(row['gap_ns'])
                require(gap == elapsed - (previous['elapsed_ns'] if previous else 0), 'gap_mismatch')
                require(previous is None or elapsed > previous['elapsed_ns'], 'nonmonotonic_time')
                max_gap = max(max_gap, gap)
                groups = row['groups']
                require(1 <= len(groups) <= 32, 'invalid_cohort_count')
                require(all(type(g['role']) is str and 1 <= len(g['role']) <= 64 for g in groups), 'invalid_role')
                require(len({tuple(g['native_identity']) for g in groups}) == len(groups), 'duplicate_cohort_native_identity')
                roles = [g['role'] for g in groups]
                require(len(set(roles)) == len(roles), 'duplicate_role')
                if cohorts:
                    require(set(roles) == set(cohorts), 'cohort_set_changed')
                seen = set()
                duplicates = []
                valid = True
                pss_total = 0
                for group in groups:
                    role = group['role']
                    identity = group['native_identity']
                    require(type(identity) is list and len(identity) == 2, 'invalid_native_identity')
                    for value in identity: integer(value, 1)
                    start = integer(group['counters_read_started_boottime_ns'])
                    finish = integer(group['counters_read_finished_boottime_ns'])
                    require(start <= finish, 'counter_read_interval')
                    cpu = group['cpu']
                    for key in ('usage_usec', 'user_usec', 'system_usec'): integer(cpu[key])
                    for value in group['memory_events'].values(): integer(value)
                    pss = integer(group['pss_kib'])
                    integer(group['memory_current_bytes'])
                    labels = {}
                    process_pss = 0
                    for process in group['processes']:
                        native = (integer(process['pid'], 1), integer(process['start'], 1))
                        if native in seen: duplicates.append(dict(pid=native[0], start=native[1]))
                        seen.add(native)
                        value = integer(process['pss_kib'])
                        process_pss += value
                        label = process['label']
                        labels[label] = labels.get(label, 0) + value
                    require(process_pss == pss and labels == group['pss_by_label_kib'], 'pss_projection_mismatch')
                    vanished_processes = integer(group['vanished_processes'])
                    vanished_groups = integer(group['vanished_groups'])
                    valid = valid and not group['invalid_processes'] and not vanished_processes and not vanished_groups
                    pss_total += pss
                    if role not in cohorts:
                        cohorts[role] = dict(identity=identity, first=group, last=group, pss_max=pss, memory_max=group['memory_current_bytes'], pss_weighted=0, labels_weighted={}, labels_max={})
                    entry = cohorts[role]
                    require(entry['identity'] == identity, 'cohort_identity_changed')
                    old = entry['last']
                    if previous is not None:
                        require(old['counters_read_finished_boottime_ns'] < start, 'counter_reads_overlap_or_reverse')
                        for key in ('usage_usec', 'user_usec', 'system_usec'):
                            require(cpu[key] >= old['cpu'][key], 'cpu_counter_reset')
                        require(set(old['memory_events']) == set(group['memory_events']), 'memory_event_set_changed')
                        for key, value in group['memory_events'].items():
                            require(value >= old['memory_events'][key], 'memory_event_counter_reset')
                        weight = elapsed - previous['elapsed_ns']
                        entry['pss_weighted'] += old['pss_kib'] * weight
                        for label, value in old['pss_by_label_kib'].items():
                            entry['labels_weighted'][label] = entry['labels_weighted'].get(label, 0) + value * weight
                    entry['last'] = group
                    entry['pss_max'] = max(entry['pss_max'], pss)
                    entry['memory_max'] = max(entry['memory_max'], group['memory_current_bytes'])
                    for label, value in labels.items(): entry['labels_max'][label] = max(entry['labels_max'].get(label, 0), value)
                require(duplicates == row['duplicate_process_identities'], 'duplicate_witness_mismatch')
                valid = bool(valid and not duplicates)
                require(row['pss_sum_valid'] is valid and row['total_cohort_pss_kib'] == (pss_total if valid else None), 'pss_validity_mismatch')
                if not valid: invalid_samples.append(sequence)
                if previous is not None and previous['pss_sum_valid']:
                    total_pss_weighted += previous['total_cohort_pss_kib'] * (elapsed - previous['elapsed_ns'])
                total_pss_max = max(total_pss_max, pss_total)
                host = row['whole_host']
                require(set(host) == {'cpu_ticks', 'memory'}, 'invalid_host_counters')
                required_cpu = {'user', 'nice', 'system', 'idle', 'iowait', 'irq', 'softirq', 'steal'}
                require(required_cpu <= set(host['cpu_ticks']) <= required_cpu | {'guest', 'guest_nice'}, 'invalid_host_cpu_set')
                for value in host['cpu_ticks'].values(): integer(value)
                require(host['memory'], 'missing_host_memory')
                for name, value in host['memory'].items():
                    integer(value)
                    host_memory_max[name] = max(host_memory_max.get(name, 0), value)
                    host_memory_min[name] = min(host_memory_min.get(name, value), value)
                if last_host is not None:
                    require(set(last_host['cpu_ticks']) == set(host['cpu_ticks']) and set(last_host['memory']) == set(host['memory']), 'host_counter_set_changed')
                    for name, value in host['cpu_ticks'].items():
                        require(value >= last_host['cpu_ticks'][name], 'host_cpu_counter_reset')
                bounds = [integer(row['whole_host_read_started_boottime_ns']), integer(row['whole_host_read_finished_boottime_ns'])]
                if first_host is None: first_host, first_host_bounds = host, bounds
                last_host, last_host_bounds = host, bounds
                pending = row
                samples += 1
            elif kind == 'sample_complete':
                require(pending is not None and row['sequence'] == sequence, 'missing_original_sample')
                started = integer(row['read_started_boottime_ns'])
                finished = integer(row['read_finished_boottime_ns'])
                flushed = integer(row['sample_flush_finished_boottime_ns'])
                require(started <= finished <= flushed and finished - started == pending['read_collection_ns'], 'sample_read_bounds')
                require(last_flush is None or started >= last_flush, 'sample_flush_overlap')
                last_flush = flushed
                derived_base = started - pending['elapsed_ns']
                require(base is None or base == derived_base, 'clock_origin_changed')
                base = derived_base
                require(all(started <= g['counters_read_started_boottime_ns'] <= g['counters_read_finished_boottime_ns'] <= finished for g in pending['groups']), 'group_outside_sample')
                require(started <= pending['whole_host_read_started_boottime_ns'] <= pending['whole_host_read_finished_boottime_ns'] <= finished, 'whole_host_outside_sample')
                observer = finite(row['observer_cpu_seconds_through_sample_flush'])
                require(observer >= finite(pending['observer_cpu_seconds']) >= last_observer, 'observer_cpu_reset')
                last_observer = observer
                previous, pending = pending, None
                sequence += 1
            elif kind == 'end':
                require(pending is None and previous is not None and samples >= 2, 'incomplete_or_short_record')
                require(row['samples'] == samples and row['elapsed_ns'] == previous['elapsed_ns'] and row['max_gap_ns'] == max_gap, 'end_mismatch')
                require(row['elapsed_ns'] >= begin['requested_seconds'] * 1000000000, 'requested_duration_incomplete')
                require(row['ten_minute_duration_met'] is (row['elapsed_ns'] >= 600000000000) and row['full_day_duration_met'] is (row['elapsed_ns'] >= 86400000000000), 'duration_claim_mismatch')
                require(finite(row['observer_cpu_seconds_through_prior_output']) >= last_observer, 'end_observer_cpu_reset')
                end = row
            else:
                raise ValueError('incomplete_or_unknown_record')
    require(end is not None, 'missing_complete_end')
    duration = previous['elapsed_ns'] - first_elapsed
    require(duration > 0, 'no_measurement_duration')
    pss_valid = not invalid_samples
    summaries = {}
    for role, entry in cohorts.items():
        first, last = entry['first'], entry['last']
        low = last['counters_read_started_boottime_ns'] - first['counters_read_finished_boottime_ns']
        high = last['counters_read_finished_boottime_ns'] - first['counters_read_started_boottime_ns']
        require(low > 0 and high >= low, 'invalid_cpu_duration')
        cpu_delta = {k: last['cpu'][k] - first['cpu'][k] for k in ('usage_usec', 'user_usec', 'system_usec')}
        summaries[role] = dict(native_identity=entry['identity'], cpu_delta_usec=cpu_delta,
            cpu_duration_bounds_ns=[low, high], cpu_percent_one_core_bounds=[100000 * cpu_delta['usage_usec'] / high, 100000 * cpu_delta['usage_usec'] / low],
            mean_pss_kib=entry['pss_weighted']/duration if pss_valid else None, max_pss_kib=entry['pss_max'] if pss_valid else None,
            mean_pss_by_label_kib={k:entry['labels_weighted'].get(k, 0)/duration for k in entry['labels_max']} if pss_valid else None,
            max_pss_by_label_kib=entry['labels_max'] if pss_valid else None, max_memory_current_bytes=entry['memory_max'],
            memory_event_deltas={k:last['memory_events'][k]-first['memory_events'][k] for k in first['memory_events']})
    host_low = last_host_bounds[0] - first_host_bounds[1]
    host_high = last_host_bounds[1] - first_host_bounds[0]
    require(host_low > 0 and host_high >= host_low, 'invalid_host_cpu_duration')
    host_cpu_delta = {name:value-first_host['cpu_ticks'][name] for name,value in last_host['cpu_ticks'].items()}
    busy_ticks = sum(host_cpu_delta[name] for name in ('user', 'nice', 'system', 'irq', 'softirq'))
    ticks = integer(begin['clock_ticks'], 1)
    host_summary = dict(cpu_delta_ticks=host_cpu_delta, clock_ticks_per_second=ticks, cpu_duration_bounds_ns=[host_low, host_high],
        busy_cpu_percent_one_core_bounds=[busy_ticks*100000000000/ticks/host_high, busy_ticks*100000000000/ticks/host_low],
        busy_definition='user+nice+system+irq+softirq; guest already included in user/nice; idle/iowait/steal reported separately',
        memory_min_kib=host_memory_min, memory_max_kib=host_memory_max,
        scope='Entire VM including observer and unrelated activity; not attributed router overhead')
    return dict(schema=1, summarizer_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(), input=str(path), input_sha256=digest.hexdigest(), manifest_sha256=begin['manifest_sha256'], workload_binding_sha256=begin['workload_binding_sha256'], boot_id=begin['boot_id'], samples=samples,
        elapsed_ns=end['elapsed_ns'], sample_start_span_ns=duration, max_gap_ns=max_gap, requested_seconds=begin['requested_seconds'],
        pss_valid_for_entire_run=pss_valid, invalid_pss_sample_sequences=invalid_samples,
        total_cohort_mean_pss_kib=total_pss_weighted/duration if pss_valid else None, total_cohort_max_pss_kib=total_pss_max if pss_valid else None,
        cohorts=summaries, whole_host=host_summary, observer_cpu_seconds_through_prior_output=end['observer_cpu_seconds_through_prior_output'],
        collector_duration_only_ten_minutes=end['ten_minute_duration_met'], collector_duration_only_full_day=end['full_day_duration_met'],
        measured_sample_start_span_ten_minutes=duration >= 600000000000, measured_sample_start_span_full_day=duration >= 86400000000000,
        performance_acceptance='NOT_EVALUATED', router_traffic_acceptance='NOT_RUN', throughput_and_p95='NOT_MEASURED',
        limitations=begin['limitations']+['Time weighted PSS uses the preceding snapshot between sample starts; the final read tail is excluded.', 'CPU duration bounds reflect counter-read brackets, not a workload-only attribution.', 'Complete paired source/artifact/workload/fault evidence is still required.'])


if __name__ == '__main__':
    print(json.dumps(summarize(pathlib.Path(sys.argv[1])), indent=2))
