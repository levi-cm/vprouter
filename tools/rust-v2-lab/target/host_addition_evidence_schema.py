"""Closed, type-sensitive HOST addition evidence. Parsed receipts grant no custody.

The frozen exporter exposes registration counts and original Reap/ACK receipts,
not socket identities, sequence numbers, role reports, or neighbor inventories.
Those remain source/internal or external checks, never inferred by this schema.
"""
import copy
import importlib.util
import math
import pathlib
import re

if not __debug__:
    raise RuntimeError('optimized_python_refused')

shape_path = pathlib.Path(__file__).parent / 'platform-lab/host_baseline_declaration.py'
shape_bytes = shape_path.read_bytes()
shape_spec = importlib.util.spec_from_loader('host_addition_shape', loader=None)
shape_module = importlib.util.module_from_spec(shape_spec)
exec(compile(shape_bytes, str(shape_path), 'exec'), shape_module.__dict__)

KINDS = ('transport_sockets', 'pair', 'host_sockets', 'move')
HISTORY = set('kind request namespace host declaration admission requested_at deadline addition birth result verified_at'.split())
NATIVE = (HISTORY - {'verified_at'}) | set('original_pid original_start actual_wait_status native_born native_job_state registered_native_slots original_registration_slots_verified borrowed_registration_count complete_native_registration durable_birth_released accepted_at acknowledged eof context_retained postcompletion_inventory_polls postcompletion_inventory_preserved host_observation up_authorized placement_authorized'.split())
WRITER = set('phase pid start queued_at io_deadline parent_deadline actual_wait_status verified_at'.split())
RETAINED = set('index pid start actual_wait_status io_deadline parent_deadline launch_charge original_reap_bound charge_retained_before_cancel charge_retained_after_collection charge_retained_after_retries charge_retained_after_drop failed mutation acknowledged canonical_pending mutation_fenced'.split())
OUTER = set('schema fault producer_binding preparation admission operations failed_constructor planned_host_link_index canonical_negative_checks own_intent_polling charges_before charges_before_drop charges_after_drop failure_retry retained_result_writer result_writer_held isolated_pair_creation_observed single_down_host_addition_observed canonical_host_addition_acknowledged unacknowledged_host_addition_retained host_addresses_routes_rules_preserved host_neighbor_mutation_authorized whole_chain_retained_after_drop original_six_contexts_retained_after_drop baseline_context_retained_after_drop generation_context_retained_after_drop host_link_context_retained_after_drop parent_pristine placement_authorized up_authorized health_ready_authorized resource_cleanup_authorized multi_exit_runtime_proven requirement8_complete'.split())

def same(a, b):
    return shape_module.canonical(a) == shape_module.canonical(b)

def keys(value, expected):
    assert type(value) is dict and set(value) == set(expected)

def integer(value, low=0, high=18446744073709551615):
    assert type(value) is int and low <= value <= high
    return value

def finite(value):
    assert type(value) in (int, float) and math.isfinite(value) and 0 < value <= 1.7976931348623157e308
    return value

def identity(value):
    keys(value, ('dev', 'ino'))
    return [integer(value['dev'], 1), integer(value['ino'], 1)]

def digest(value):
    assert type(value) is list and len(value) == 32 and any(value)
    for byte in value:
        integer(byte, 0, 255)

def validate_host_addition(c):
    w = c['host_addition_top']
    fault = c['host_addition_fault']
    keys(w, OUTER)
    integer(fault, 0, 3)
    assert integer(w['schema'], 1, 1) == 1 and integer(w['fault'], 0, 3) == fault
    assert c['producer_binding_fault'] == 0 and type(c['producer_binding_fault']) is int
    assert same(w['producer_binding'], c['producer_binding_top'])
    old = c['producer_binding_top']['preparation']
    p = w['preparation']
    keys(p, old)
    changed = {'writers', 'host_link', 'pending_host_link', 'mutation_fenced', 'canonical_pending', 'pending_wireguard', 'pending_producer_creation', 'pending_producer_binding'}
    assert all(same(p[k], old[k]) for k in old if k not in changed)
    assert old['host_link'] == [] and old['pending_host_link'] is None
    assert p['mutation_fenced'] is p['canonical_pending'] is (fault == 2)
    assert same(p['pending_wireguard'], p['wireguard'] if fault == 2 else None)
    assert same(p['pending_producer_creation'], p['producer_creation'] if fault == 2 else None)
    # A failed HOST Result retains the entire proposed record. Its already
    # acknowledged producer fields stay identical to the canonical prefix;
    # this exported pending view does not imply a new producer publication.
    pending_binding = p['pending_producer_binding']
    if fault == 2:
        keys(pending_binding, ('history', 'producer'))
        assert same(pending_binding['history'], p['producer_binding'])
        assert same(pending_binding['producer'], p['entry_producer'])
    else:
        assert pending_binding is None
    for key in ('service_reserved', 'native_children_reaped', 'entry_links_absent', 'entry_attempt_absent', 'entry_terminal_absent'):
        assert p[key] is True
    assert p['entry_phase'] == 'creating' and p['entry_producer_absent'] is p['member_native_jobs_collected'] is False
    descriptor = c['descriptor']
    allocation = descriptor['allocation']
    member = descriptor['primary']
    selected = [e for e in allocation['exits'] if e['exit_id'] == member]
    assert len(selected) == 1
    index = integer(descriptor['planned_host_link_index'], 1000000, 2147483647)
    assert integer(w['planned_host_link_index'], 1000000, 2147483647) == index
    admission = w['admission']
    keys(admission, 'declaration namespace requested_at deadline accepted_at polls two_original_reads_verified same_generation_owner_retained declared_baseline'.split())
    host = admission['namespace']
    identity(host)
    assert identity(host) == c['gateway']['host_network_namespace']
    baseline = admission['declared_baseline']
    shape_module.validate_shape(baseline)
    assert same(baseline['namespace'], identity(host))
    assert all(v['index'] != index and v['name'] != selected[0]['host_interface'] and not v['alias'].startswith('vprouter-v2:' + allocation['deployment_id'] + ':') for v in baseline['links'])
    declaration = c['host_baseline_declaration']
    metadata = c['host_baseline']
    keys(metadata, 'declaration sha256 bytes builder_sha256 template_sha256 template_baseline_sha256 review_sha256 authored_public_input_only projection_matched_authored_shape host_authority_granted'.split())
    assert same(metadata['declaration'], declaration)
    assert metadata['authored_public_input_only'] is metadata['projection_matched_authored_shape'] is True and metadata['host_authority_granted'] is False
    integer(metadata['bytes'], 1, 262144)
    for key in ('sha256', 'builder_sha256', 'template_sha256', 'template_baseline_sha256', 'review_sha256'):
        assert type(metadata[key]) is str and re.fullmatch('[a-f0-9]{64}', metadata[key])
    keys(declaration, 'schema_version deployment_id generation allocation_digest host_namespace baseline'.split())
    assert integer(declaration['schema_version'], 1, 1) == 1
    assert declaration['deployment_id'] == descriptor['deployment_id'] == allocation['deployment_id']
    assert integer(declaration['generation'], 1) == allocation['generation']
    assert declaration['allocation_digest'] == descriptor['allocation_digest'] and re.fullmatch('[a-f0-9]{64}', declaration['allocation_digest'])
    assert same(declaration['host_namespace'], host) and same(declaration['baseline'], baseline)
    declaration_hash = metadata['sha256']
    digest(admission['declaration'])
    assert admission['declaration'] == list(bytes.fromhex(declaration_hash))
    start, deadline, accepted = (finite(admission[k]) for k in ('requested_at', 'deadline', 'accepted_at'))
    assert deadline == start + 2 and start <= accepted < deadline
    assert old['writers'][74]['verified_at'] <= start
    assert integer(admission['polls'], 1, 4294967295) >= 1
    assert admission['two_original_reads_verified'] is admission['same_generation_owner_retained'] is True
    windows = [start, deadline, accepted]
    histories = p['host_link']
    operations = w['operations']
    assert type(histories) is list and len(histories) == 4
    assert type(operations) is list and len(operations) == (3 if fault in (1, 3) else 4)
    writers = p['writers']
    assert type(writers) is list and len(writers) == (85 if fault in (1, 3) else 87)
    assert same(writers[:75], old['writers']) and len(old['writers']) == 75
    ids = c['ids']
    requests = []
    after = finite(c['environment']['after']['started_at'])
    prior_ack = accepted
    for i, h in enumerate(histories):
        keys(h, HISTORY)
        assert h['kind'] == KINDS[i]
        digest(h['request'])
        assert h['request'] not in requests
        requests.append(h['request'])
        identity(h['namespace']); identity(h['host'])
        expected_ns = host if i == 2 else p['transport_network']
        assert same(h['namespace'], expected_ns) and same(h['host'], host)
        assert same(h['declaration'], admission['declaration']) and same(h['admission'], windows)
        requested = finite(h['requested_at']); end = finite(h['deadline'])
        assert prior_ack <= requested and end == requested + 2
        if i == 3:
            assert type(h['addition']) is list and len(h['addition']) == 2
            digest(h['addition'][0]); assert integer(h['addition'][1], 1000000, 2147483647) == index
        else:
            assert h['addition'] is None
        chunk = writers[75 + 3*i:78 + 3*i]
        assert len(chunk) == (1 if i == 3 and fault in (1, 3) else 3)
        for j, writer in enumerate(chunk):
            keys(writer, WRITER)
            assert writer['phase'] == ('host_link_intent', 'host_link_birth', 'host_link_result')[j]
            pair = (integer(writer['pid'], 2, 4294967295), integer(writer['start'], 1))
            assert pair not in ids; ids.append(pair)
            queued = finite(writer['queued_at'])
            assert requested <= queued < end and queued <= after
            assert finite(writer['io_deadline']) == finite(writer['parent_deadline']) == end
            failed = fault == 2 and i == 3 and j == 2
            assert integer(writer['actual_wait_status'], 0, 2147483647) == (9 if failed else 0)
            if failed:
                assert writer['verified_at'] is None
            else:
                assert queued <= finite(writer['verified_at']) < end and writer['verified_at'] <= after
            if j:
                assert chunk[j-1]['verified_at'] <= queued
        constructor = i == 3 and fault in (1, 3)
        native = w['failed_constructor'] if constructor else operations[i]
        keys(native, NATIVE)
        for key in HISTORY - {'birth', 'result', 'verified_at'}:
            assert same(native[key], h[key])
        assert integer(native['registered_native_slots'], 3, 4294967295) >= 3
        assert native['original_registration_slots_verified'] is native['context_retained'] is True
        assert integer(native['borrowed_registration_count'], 0, 4294967295) == (0, 2, 0, 4)[i]
        assert native['up_authorized'] is native['placement_authorized'] is False
        polls = integer(native['postcompletion_inventory_polls'], 0, 4294967295)
        if constructor:
            assert h['birth'] is h['result'] is h['verified_at'] is native['birth'] is native['result'] is native['accepted_at'] is None
            for key in ('complete_native_registration', 'durable_birth_released', 'acknowledged', 'eof'):
                assert native[key] is False
            assert native['postcompletion_inventory_preserved'] is False and polls == 0
            assert native['host_observation'] is None and native['original_start'] is None
            assert native['native_born'] is (fault == 1) and native['native_job_state'] == ('born' if fault == 1 else 'prepared')
            if fault == 1:
                integer(native['original_pid'], 2, 4294967295)
                assert native['original_pid'] not in [pair[0] for pair in ids]
                assert integer(native['actual_wait_status'], 0, 2147483647) == 9
            else:
                assert native['original_pid'] is native['actual_wait_status'] is None
            continue
        b = h['birth']
        keys(b, ('pid', 'start', 'born_at', 'deadline'))
        integer(b['pid'], 2, 4294967295); integer(b['start'], 1)
        c['birth'](b, requested, end)
        assert finite(b['deadline']) == end and chunk[0]['verified_at'] <= b['born_at'] <= chunk[1]['queued_at']
        assert same(native['birth'], b)
        assert integer(native['original_pid'], 2, 4294967295) == b['pid'] and integer(native['original_start'], 1) == b['start']
        assert integer(native['actual_wait_status'], 0, 2147483647) == 0
        for key in ('native_born', 'complete_native_registration', 'durable_birth_released', 'eof'):
            assert native[key] is True
        assert native['native_job_state'] == 'born' and native['acknowledged'] is not (fault == 2 and i == 3)
        if i in (1, 3):
            assert polls >= 2 and native['postcompletion_inventory_preserved'] is True
        else:
            assert polls == 0 and native['postcompletion_inventory_preserved'] is None
        result = native['result']
        keys(result, ('namespace', 'host', 'peer'))
        identity(result['namespace'])
        assert same(result['namespace'], host if i == 3 else h['namespace'])
        at = finite(native['accepted_at'])
        assert chunk[1]['verified_at'] <= at < end and at <= chunk[2]['queued_at']
        if i in (0, 2):
            assert result['host'] is result['peer'] is native['host_observation'] is None
        else:
            pair_shape = dict(namespace=identity(result['namespace']), links=[result['host'], result['peer']], addresses=[], routes=[], rules=[])
            shape_module.validate_shape(pair_shape)
            a, peer = result['host'], result['peer']
            alias = 'vprouter-v2:{}:{}:{}'.format(allocation['deployment_id'], allocation['generation'], member)
            assert a['name'] == selected[0]['host_interface'] and peer['name'] == selected[0]['data_interface']
            assert a['kind'] == peer['kind'] == 'veth' and a['alias'] == peer['alias'] == alias
            assert a['up'] is peer['up'] is False and a['index'] != peer['index']
            assert integer(a['peer_index'], 1, 4294967295) == peer['index'] and integer(peer['peer_index'], 1, 4294967295) == a['index']
            if i == 1:
                assert native['host_observation'] is None
            else:
                expected_host = copy.deepcopy(histories[1]['result']['host']); expected_host['index'] = index
                expected_peer = copy.deepcopy(histories[1]['result']['peer']); expected_peer['peer_index'] = index
                assert same(a, expected_host) and same(peer, expected_peer)
                observed = native['host_observation']
                shape_module.validate_shape(observed)
                for key in ('namespace', 'addresses', 'routes', 'rules'):
                    assert same(observed[key], baseline[key])
                assert len(observed['links']) == len(baseline['links']) + 1
                assert sorted(shape_module.canonical(v) for v in observed['links']) == sorted(shape_module.canonical(v) for v in baseline['links'] + [a])
        if fault == 2 and i == 3:
            assert h['result'] is h['verified_at'] is None
        else:
            assert same(h['result'], result) and same(h['verified_at'], at)
            prior_ack = chunk[2]['verified_at']
    if fault in (0, 2):
        assert w['failed_constructor'] is None
    pending = p['pending_host_link']
    if fault == 2:
        proposed = copy.deepcopy(histories)
        proposed[3]['result'] = operations[3]['result']
        proposed[3]['verified_at'] = operations[3]['accepted_at']
        assert same(pending, proposed)
    else:
        assert pending is None
    own = w['own_intent_polling']
    keys(own, 'index pid start queued_polls held_pending_polls negative_checks released'.split())
    assert integer(own['index']) == 75 and integer(own['pid'], 2, 4294967295) == writers[75]['pid'] and integer(own['start'], 1) == writers[75]['start']
    assert integer(own['queued_polls']) == 1 and integer(own['held_pending_polls']) == 2 and integer(own['negative_checks']) == 12 and own['released'] is True
    charges = [6, 5] if fault == 2 else [4, 4] if fault == 3 else [5, 5]
    for key, expected in (('charges_before', [1, 1]), ('charges_before_drop', charges), ('charges_after_drop', charges)):
        assert type(w[key]) is list and len(w[key]) == 2
        for value in w[key]: integer(value, 0, 64)
        assert w[key] == expected
    retained = w['retained_result_writer']
    if fault == 2:
        keys(retained, RETAINED)
        assert integer(retained['index']) == 86 and integer(retained['launch_charge'], 1, 1) == 1
        for key in ('pid', 'start', 'actual_wait_status', 'io_deadline', 'parent_deadline'):
            assert same(retained[key], writers[86][key])
        assert retained['acknowledged'] is False
        for key in RETAINED - {'index', 'pid', 'start', 'actual_wait_status', 'io_deadline', 'parent_deadline', 'launch_charge', 'acknowledged'}:
            assert retained[key] is True
    else:
        assert retained is None
    retry = w['failure_retry']
    if fault:
        keys(retry, 'polls native_births_before native_births_after charges_before charges_after same_original_request same_step original_error_retained generation_reuse_refused'.split())
        assert integer(retry['polls']) == 2 and integer(retry['native_births_before']) == integer(retry['native_births_after'])
        assert same(retry['charges_before'], charges) and same(retry['charges_after'], charges)
        for key in ('same_original_request', 'same_step', 'original_error_retained', 'generation_reuse_refused'):
            assert retry[key] is True
    else:
        assert retry is None
    for key in ('whole_chain_retained_after_drop', 'original_six_contexts_retained_after_drop', 'baseline_context_retained_after_drop', 'generation_context_retained_after_drop', 'host_link_context_retained_after_drop', 'parent_pristine', 'isolated_pair_creation_observed'):
        assert w[key] is True
    for key in ('single_down_host_addition_observed', 'host_addresses_routes_rules_preserved'):
        assert w[key] is (fault in (0, 2))
    for key in ('result_writer_held', 'unacknowledged_host_addition_retained'):
        assert w[key] is (fault == 2)
    assert w['canonical_host_addition_acknowledged'] is (fault == 0)
    for key in ('host_neighbor_mutation_authorized', 'placement_authorized', 'up_authorized', 'health_ready_authorized', 'resource_cleanup_authorized', 'multi_exit_runtime_proven', 'requirement8_complete'):
        assert w[key] is False
    assert integer(w['canonical_negative_checks']) == (20 if fault == 0 else 0)
    return dict(ordered_writers_verified=len(writers), original_operation_clocks_verified=23,
        canonical_host_addition_acknowledged=fault == 0, unacknowledged_host_addition_retained=fault == 2,
        declared_generation_and_planned_index_bound=True, final_nine_context_anchors_reported=True,
        native_socket_identity_sequence_or_role_receipts_exported=False, neighbor_inventory_exported=False,
        socket_role_origin_checks='SOURCE_REVIEWED', immutable_index_derivation_and_collision_refusal='SOURCE_REVIEWED',
        opaque_addition_plan_digest_bound=True,
        native_acceptance=False, placement_authorized=False, health_ready_authorized=False, up_authorized=False)
