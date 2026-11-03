"""Read closed failed-Bootstrap diagnostics; no runtime or state authority."""
import hashlib
import json
import math
import pathlib
import re
import sys


HELPERS = (
    'query_source', 'query_hold', 'query_checkpoint', 'query_identity',
    'query_held_negatives', 'query_release', 'policy_hold',
    'policy_queued_negatives', 'policy_checkpoint', 'policy_held_negatives',
    'policy_identity', 'policy_release', 'native_poll',
)
CATEGORIES = (
    'allocation_anchor_memory', 'binding_service_custody', 'binding_retained',
    'owned_progress', 'typed_bootstrap_progress', 'original_proof',
    'record_json_encode', 'expected_record_json_encode', 'record_sha256',
    'journal_advance',
)
RETAINED_CATEGORIES = (
    'retained_transport', 'retained_data', 'retained_owner_record',
    'retained_history', 'history_allocation_digest', 'created_group_native',
    'source_identity_entries', 'native_source_entries',
)
OWNER_CATEGORIES = (
    'owner_host_preflight', 'owner_record_validate',
    'owner_namespace_identities', 'owner_current_identity_chain',
    'owner_record_clone',
)
STEPS = (
    'absent', 'query_intent', 'query_birth', 'query_reading', 'query_result',
    'intent', 'birth', 'reading', 'result', 'next', 'complete',
)
BOOLS = (
    'query_present', 'query_child_present', 'query_accepted_present',
    'policy_present', 'query_queued', 'query_released', 'own_queued',
    'own_released',
)
COUNTS = ('query_held', 'query_negatives', 'own_held', 'own_negatives')


def require(value):
    if not value:
        raise ValueError('invalid_closed_bootstrap_diagnostic')


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def invalid_constant(_):
    raise ValueError('nonfinite_json_refused')


def fields(line, marker):
    require(line.startswith(marker))
    parts = line[len(marker):].split(' ')
    require(all(part.count('=') == 1 for part in parts))
    return unique(part.split('=', 1) for part in parts)


def integer(value, bits):
    require(re.fullmatch(r'0|[1-9][0-9]{0,38}', value) is not None)
    number = int(value)
    require(number < 2 ** bits)
    return number


def clock(value, optional=False):
    if optional:
        if value == 'None':
            return None
        require(value.startswith('Some(') and value.endswith(')'))
        value = value[5:-1]
    require(re.fullmatch(r'[0-9]{1,12}(?:[.][0-9]{1,18})?', value) is not None)
    number = float(value)
    require(math.isfinite(number) and 0 <= number <= 1e12)
    return number


def main():
    require(len(sys.argv) == 3)
    source, destination = map(pathlib.Path, sys.argv[1:])
    require(0 < source.stat().st_size <= 16 * 1024 * 1024)
    raw = source.read_bytes()
    record = json.loads(raw, object_pairs_hook=unique,
                        parse_constant=invalid_constant)
    require(record['exit_code'] == 1 and record['result'] == 'FAIL'
            and record['component_test_mode'] == 'secret_bootstrap_success'
            and record['production_changes'] is False)
    binding = record['source_binding']
    require(set(binding) == {'source_commit', 'source_archive_sha256',
                             'tracked_build_inputs_verified', 'source_aggregate_sha256'})
    for key, length in (('source_commit', 40), ('source_archive_sha256', 64),
                        ('source_aggregate_sha256', 64)):
        require(type(binding[key]) is str
                and re.fullmatch('[a-f0-9]{' + str(length) + '}', binding[key]) is not None)
    require(type(binding['tracked_build_inputs_verified']) is int
            and 0 < binding['tracked_build_inputs_verified'] <= 10000)
    lines = record['stderr'].splitlines()
    selected = lambda prefix: [line for line in lines if line.startswith(prefix)]
    boundaries = selected('LAB_SECRET_BOOTSTRAP_BOUNDARY_FAILURE ')
    require(len(boundaries) == 1)
    boundary = fields(boundaries[0], 'LAB_SECRET_BOOTSTRAP_BOUNDARY_FAILURE ')
    require(set(boundary) == set(BOOLS + COUNTS + (
        'helper', 'step', 'reason', 'original_requested_at',
        'original_deadline', 'observed_boot_now')))
    require(boundary['helper'] in HELPERS and boundary['step'] in STEPS
            and boundary['reason'] == 'Deadline')
    for key in BOOLS:
        require(boundary[key] in ('true', 'false'))
        boundary[key] = boundary[key] == 'true'
    for key in COUNTS:
        boundary[key] = integer(boundary[key], 64)
    for key in ('original_requested_at', 'original_deadline'):
        boundary[key] = clock(boundary[key], optional=True)
    boundary['observed_boot_now'] = clock(boundary['observed_boot_now'])
    start, end = boundary['original_requested_at'], boundary['original_deadline']
    require((start is None and end is None)
            or (start is not None and end == start + 2.))

    wrappers = []
    for line in selected('LAB_SECRET_BOOTSTRAP_WRAPPER_TOTAL '):
        row = fields(line, 'LAB_SECRET_BOOTSTRAP_WRAPPER_TOTAL ')
        require(set(row) == {'helper', 'calls', 'elapsed_ns', 'measurement'}
                and row.pop('measurement') == 'wrapper_elapsed_including_nested_validation')
        row['calls'] = integer(row['calls'], 64)
        row['elapsed_ns'] = integer(row['elapsed_ns'], 128)
        require(row['calls'] > 0 or row['elapsed_ns'] == 0)
        wrappers.append(row)
    require(tuple(row['helper'] for row in wrappers) == HELPERS)

    nested = []
    for line in selected('LAB_SECRET_BOOTSTRAP_NESTED_TOTAL '):
        row = fields(line, 'LAB_SECRET_BOOTSTRAP_NESTED_TOTAL ')
        require(set(row) == {'family', 'category', 'calls', 'elapsed_ns',
                             'measurement', 'grouping'}
                and row.pop('measurement') == 'inclusive_nested_elapsed'
                and row.pop('grouping') == 'lab_loop_entry_step_family')
        row['calls'] = integer(row['calls'], 64)
        row['elapsed_ns'] = integer(row['elapsed_ns'], 128)
        require(row['calls'] > 0 or row['elapsed_ns'] == 0)
        nested.append(row)
    require(tuple((row['family'], row['category']) for row in nested)
            == tuple((family, key) for family in ('query', 'policy', 'other')
                     for key in CATEGORIES))

    retained = []
    retained_marker = 'LAB_SECRET_BOOTSTRAP_RETAINED_TOTAL'
    for line in lines:
        # A malformed occurrence must not silently look like an absent extension.
        if retained_marker not in line:
            continue
        row = fields(line, retained_marker + ' ')
        require(set(row) == {'family', 'category', 'calls', 'elapsed_ns',
                             'measurement', 'grouping'}
                and row.pop('measurement') == 'inclusive_retained_elapsed'
                and row.pop('grouping') == 'lab_loop_entry_step_family')
        row['calls'] = integer(row['calls'], 64)
        row['elapsed_ns'] = integer(row['elapsed_ns'], 128)
        require(row['calls'] > 0 or row['elapsed_ns'] == 0)
        require(row['category'] not in RETAINED_CATEGORIES[-2:]
                or row['elapsed_ns'] == 0)
        retained.append(row)
    if retained:
        require(tuple((row['family'], row['category']) for row in retained)
                == tuple((family, key) for family in ('query', 'policy', 'other')
                         for key in RETAINED_CATEGORIES))

    owner = []
    owner_marker = 'LAB_SECRET_BOOTSTRAP_OWNER_TOTAL'
    for line in lines:
        # A malformed occurrence must not silently look like an absent extension.
        if owner_marker not in line:
            continue
        row = fields(line, owner_marker + ' ')
        require(set(row) == {'family', 'category', 'calls', 'elapsed_ns',
                             'measurement', 'grouping'}
                and row.pop('measurement') == 'inclusive_owner_elapsed'
                and row.pop('grouping') == 'lab_loop_entry_step_family')
        row['calls'] = integer(row['calls'], 64)
        row['elapsed_ns'] = integer(row['elapsed_ns'], 128)
        require(row['calls'] > 0 or row['elapsed_ns'] == 0)
        owner.append(row)
    if owner:
        require(tuple((row['family'], row['category']) for row in owner)
                == tuple((family, key) for family in ('query', 'policy', 'other')
                         for key in OWNER_CATEGORIES))

    # Every driver marker occurrence belongs to one complete, ordered extension.
    driver_lines = [line for line in record['stderr'].splitlines(keepends=True)
                    if 'LAB_SECRET_BOOTSTRAP_DRIVER' in line]
    driver_cpu = []
    if driver_lines:
        require(len(driver_lines) == 15
                and all(line.endswith('\n') and '\r' not in line
                        for line in driver_lines))
        for line, wrapper in zip(driver_lines[:13], wrappers):
            row = fields(line[:-1], 'LAB_SECRET_BOOTSTRAP_DRIVER_CPU ')
            require(tuple(row) == ('helper', 'calls', 'samples', 'cpu_ns',
                                   'sample_errors', 'measurement', 'grouping')
                    and row.pop('measurement') == 'bracketing_parent_thread_cpu'
                    and row.pop('grouping') == 'wrapper_helper'
                    and row['helper'] == wrapper['helper'])
            for key in ('calls', 'samples', 'sample_errors'):
                row[key] = integer(row[key], 64)
            row['cpu_ns'] = integer(row['cpu_ns'], 128)
            require(row['calls'] == wrapper['calls']
                    and min(row['samples'] + row['sample_errors'], 2 ** 64 - 1)
                    == row['calls']
                    and (row['samples'] > 0 or row['cpu_ns'] == 0))
            driver_cpu.append(row)

        driver_sleep = fields(driver_lines[13][:-1],
                              'LAB_SECRET_BOOTSTRAP_DRIVER_SLEEP ')
        require(tuple(driver_sleep) == ('calls', 'requested_ns', 'elapsed_ns',
                                       'measurement', 'grouping')
                and driver_sleep.pop('measurement') == 'existing_sleep_elapsed'
                and driver_sleep.pop('grouping') == 'driver_loop')
        driver_sleep['calls'] = integer(driver_sleep['calls'], 64)
        for key in ('requested_ns', 'elapsed_ns'):
            driver_sleep[key] = integer(driver_sleep[key], 128)
        requested = driver_sleep['calls'] * 1000000
        require((driver_sleep['requested_ns'] == requested
                 if driver_sleep['calls'] < 2 ** 64 - 1
                 else driver_sleep['requested_ns'] >= requested)
                and (driver_sleep['calls'] > 0 or driver_sleep['elapsed_ns'] == 0))

        driver_constructor = fields(driver_lines[14][:-1],
                                    'LAB_SECRET_BOOTSTRAP_DRIVER_CONSTRUCTOR ')
        require(tuple(driver_constructor) == ('samples', 'elapsed_ns',
                                             'sample_errors', 'measurement',
                                             'grouping')
                and driver_constructor.pop('measurement')
                == 'original_request_to_first_wrapper'
                and driver_constructor.pop('grouping') == 'driver_once')
        for key in ('samples', 'sample_errors'):
            driver_constructor[key] = integer(driver_constructor[key], 64)
        driver_constructor['elapsed_ns'] = integer(driver_constructor['elapsed_ns'], 128)
        require(driver_constructor['samples'] + driver_constructor['sample_errors'] <= 1
                and (driver_constructor['samples'] > 0
                     or driver_constructor['elapsed_ns'] == 0))

    output = dict(
        record_sha256=hashlib.sha256(raw).hexdigest(),
        source_binding=binding, boundary=boundary,
        wrappers=wrappers, nested=nested,
        total_wrapper_elapsed_ns=sum(row['elapsed_ns'] for row in wrappers),
        scope='Closed fixed labels and bounded values only; inclusive nested rows overlap and are not summed. No CPU, inner-predicate or performance-fix attribution.',
    )
    if retained:
        output['retained'] = retained
    if owner:
        output['owner'] = owner
    if driver_lines:
        output['driver_cpu'] = driver_cpu
        output['driver_sleep'] = driver_sleep
        output['driver_constructor'] = driver_constructor
        output['driver_scope'] = 'CPU is parent-thread bracketing CPU, includes observer work and excludes child execution; it does not identify scheduling. CPU and wall spans differ. CPU/wall attribution requires complete unsaturated helper rows: samples=calls, sample_errors=0, all counts below u64 maximum and CPU/wall totals below u128 maximum. Incomplete or saturated rows are unattributable. Clock differences, observer effects, sampling failures and constructor scalar precision limit inference. No off-CPU subtraction, exclusive sum or fit claim.'
    with destination.open('x') as stream:
        json.dump(output, stream, indent=2, allow_nan=False)
        stream.write('\n')
    destination.chmod(0o600)
    print(json.dumps(dict(output=str(destination), wrappers=len(wrappers),
                          nested=len(nested), reason=boundary['reason'],
                          step=boundary['step'])))


if __name__ == '__main__':
    main()
