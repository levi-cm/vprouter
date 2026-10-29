"""LOCAL SYNTHETIC SCHEMA ONLY. No new source/native execution or raw rewriting.

A cached 4bdd original prefix is independently validated, then copied in memory.
Only invented HOST receipts and explicit continuation metadata are added. Every
report prominently states native_acceptance:false.
"""
import copy
import datetime
import hashlib
import importlib.util
import json
import pathlib
import subprocess
import sys

if not __debug__:
    raise RuntimeError('optimized_python_refused')
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
collector_path = pathlib.Path(__file__).with_name('collect-secret-host-addition.py')
spec = importlib.util.spec_from_file_location('host_addition_collector_smoke', collector_path)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
schema = sys.modules['host_addition_evidence_schema']
CANDIDATE = 'target/continuation-20261028T044917Z/candidate.json'
LABEL = 'amd64-clean-secret-producer-binding-4bdd241-success'
base = m.validate_prefix(CANDIDATE, LABEL, producer_binding=True)
m.binding.validate_complete(base)
projection_path = pathlib.Path('target/continuation-20261028T063217Z/host-projection-debian-clean-x86_64/record.json')
projection = json.loads(projection_path.read_text())['report']['projection']

def fixture(fault=0):
    c = m.validate_prefix(CANDIDATE, LABEL, producer_binding=True)
    prefix = c['producer_binding_top']
    prefix['continued_original_context'] = True
    prefix['charges_after_drop'] = None
    for key in ('whole_chain_retained_after_drop', 'producer_binding_context_retained_after_drop',
        'assembly_context_retained_after_drop', 'producer_context_retained_after_drop',
        'quarantine_context_retained_after_drop', 'movement_context_retained_after_drop',
        'original_provision_context_retained_after_drop'):
        prefix[key] = False
    def add_new_fields(value):
        if type(value) is dict:
            if 'writers' in value and 'canonical_owner_epoch' in value:
                value.update(host_link=[], pending_host_link=None)
            for nested in value.values(): add_new_fields(nested)
        elif type(value) is list:
            for nested in value: add_new_fields(nested)
    add_new_fields(prefix)
    p = copy.deepcopy(prefix['preparation'])
    index = 1900011  # Explicit synthetic Rust-descriptor stand-in; no observed lookup.
    c['descriptor']['planned_host_link_index'] = index
    host = dict(zip(('dev', 'ino'), c['gateway']['host_network_namespace']))
    baseline = copy.deepcopy(projection)
    baseline['namespace'] = schema.identity(host)
    declaration = dict(schema_version=1, deployment_id=c['descriptor']['deployment_id'],
        generation=c['descriptor']['allocation']['generation'], allocation_digest=c['descriptor']['allocation_digest'],
        host_namespace=host, baseline=baseline)
    declaration_bytes = schema.shape_module.canonical(declaration)
    stamp = hashlib.sha256(declaration_bytes).hexdigest()
    c['host_baseline_declaration'] = declaration
    c['host_baseline'] = dict(declaration=copy.deepcopy(declaration), sha256=stamp, bytes=len(declaration_bytes),
        builder_sha256=hashlib.sha256(schema.shape_bytes).hexdigest(), template_sha256='1'*64,
        template_baseline_sha256=hashlib.sha256(schema.shape_module.canonical(baseline)).hexdigest(),
        review_sha256='2'*64, authored_public_input_only=True, projection_matched_authored_shape=True, host_authority_granted=False)
    start = prefix['preparation']['writers'][74]['verified_at'] + .10
    admission = dict(declaration=list(bytes.fromhex(stamp)), namespace=host, requested_at=start,
        deadline=start+2., accepted_at=start+.10, polls=3, two_original_reads_verified=True,
        same_generation_owner_retained=True, declared_baseline=copy.deepcopy(baseline))
    max_pid = max([v['pid'] for v in p['writers']] + [v['original_pid'] for v in c['assembly_top']['resources']] + [c['assembly_top']['foreign_eligibility']['original_pid']])
    next_pid = max_pid + 1000
    allocation = c['descriptor']['allocation']
    member = c['descriptor']['primary']
    selected = next(e for e in allocation['exits'] if e['exit_id'] == member)
    alias = 'vprouter-v2:{}:{}:{}'.format(allocation['deployment_id'], allocation['generation'], member)
    pair_host = dict(name=selected['host_interface'], index=3001, kind='veth', up=False, mtu=1500,
        alias=alias, peer_index=3002, hardware_type=1, controller=0, port_kind='', promiscuity=0,
        all_multicast=0, alternate_names=[], tun_info=[], max_pacing_offload_horizon=None, headroom=None, tailroom=None)
    pair_peer = copy.deepcopy(pair_host)
    pair_peer.update(name=selected['data_interface'], index=3002, peer_index=3001)
    histories, operations, failed_constructor = [], [], None
    for i, kind in enumerate(schema.KINDS):
        t = start + .20 + i*.20
        end = t+2.
        native_birth = dict(pid=next_pid+i, start=900001+i, born_at=t+.03, deadline=end)
        result = dict(namespace=copy.deepcopy(host if i in (2, 3) else p['transport_network']), host=None, peer=None)
        if i in (1, 3):
            result.update(host=copy.deepcopy(pair_host), peer=copy.deepcopy(pair_peer))
            if i == 3:
                result['host']['index'] = index
                result['peer']['peer_index'] = index
        ctor = i == 3 and fault in (1, 3)
        pending = i == 3 and fault == 2
        h = dict(kind=kind, request=[20+i]*32, namespace=copy.deepcopy(host if i == 2 else p['transport_network']),
            host=copy.deepcopy(host), declaration=admission['declaration'].copy(),
            admission=[start, start+2., start+.10], requested_at=t, deadline=end,
            addition=[[30]*32, index] if i == 3 else None, birth=None if ctor else native_birth,
            result=None if ctor or pending else copy.deepcopy(result), verified_at=None if ctor or pending else t+.07)
        native = {key:copy.deepcopy(h[key]) for key in schema.HISTORY - {'verified_at'}}
        observed = None
        if i == 3 and not ctor:
            observed = copy.deepcopy(baseline)
            observed['links'].append(copy.deepcopy(result['host']))
        native.update(original_pid=None if ctor and fault == 3 else next_pid+i,
            original_start=None if ctor else 900001+i, actual_wait_status=(9 if fault == 1 else None) if ctor else 0,
            native_born=not(ctor and fault == 3), native_job_state='prepared' if ctor and fault == 3 else 'born',
            registered_native_slots=9, original_registration_slots_verified=True,
            borrowed_registration_count=(0, 2, 0, 4)[i], complete_native_registration=not ctor,
            durable_birth_released=not ctor, result=None if ctor else copy.deepcopy(result),
            accepted_at=None if ctor else t+.07, acknowledged=not ctor and not pending, eof=not ctor,
            context_retained=True, postcompletion_inventory_polls=2 if i in (1, 3) and not ctor else 0,
            postcompletion_inventory_preserved=(not ctor) if i in (1, 3) else None,
            host_observation=observed, up_authorized=False, placement_authorized=False)
        histories.append(h)
        if ctor: failed_constructor = native
        else: operations.append(native)
        for j in range(1 if ctor else 3):
            wi = len(p['writers'])
            is_failed = pending and j == 2
            queued = t + (.001, .04, .08)[j]
            verified = t + (.02, .05, .09)[j]
            p['writers'].append(dict(phase=('host_link_intent', 'host_link_birth', 'host_link_result')[j],
                pid=next_pid+100+wi, start=910000+wi, queued_at=queued, io_deadline=end,
                parent_deadline=end, actual_wait_status=9 if is_failed else 0, verified_at=None if is_failed else verified))
    proposed = None
    if fault == 2:
        proposed = copy.deepcopy(histories)
        proposed[3].update(result=copy.deepcopy(operations[3]['result']), verified_at=operations[3]['accepted_at'])
    p.update(host_link=histories, pending_host_link=proposed, mutation_fenced=fault == 2,
        canonical_pending=fault == 2, pending_wireguard=copy.deepcopy(p['wireguard']) if fault == 2 else None,
        pending_producer_creation=copy.deepcopy(p['producer_creation']) if fault == 2 else None,
        pending_producer_binding=dict(history=copy.deepcopy(p['producer_binding']),
            producer=copy.deepcopy(p['entry_producer'])) if fault == 2 else None)
    charges = [6, 5] if fault == 2 else [4, 4] if fault == 3 else [5, 5]
    retained = None
    if fault == 2:
        retained = {key:copy.deepcopy(p['writers'][86][key]) for key in ('pid', 'start', 'actual_wait_status', 'io_deadline', 'parent_deadline')}
        retained.update(index=86, launch_charge=1, original_reap_bound=True, charge_retained_before_cancel=True,
            charge_retained_after_collection=True, charge_retained_after_retries=True, charge_retained_after_drop=True,
            failed=True, mutation=True, acknowledged=False, canonical_pending=True, mutation_fenced=True)
    retry = None if not fault else dict(polls=2, native_births_before=52, native_births_after=52,
        charges_before=charges.copy(), charges_after=charges.copy(), same_original_request=True,
        same_step=True, original_error_retained=True, generation_reuse_refused=True)
    w = dict(schema=1, fault=fault, producer_binding=prefix, preparation=p, admission=admission,
        operations=operations, failed_constructor=failed_constructor, planned_host_link_index=index,
        canonical_negative_checks=20 if fault == 0 else 0,
        own_intent_polling=dict(index=75, pid=p['writers'][75]['pid'], start=p['writers'][75]['start'],
            queued_polls=1, held_pending_polls=2, negative_checks=12, released=True),
        charges_before=[1, 1], charges_before_drop=charges.copy(), charges_after_drop=charges.copy(),
        failure_retry=retry, retained_result_writer=retained, result_writer_held=fault == 2,
        isolated_pair_creation_observed=True, single_down_host_addition_observed=fault in (0, 2),
        canonical_host_addition_acknowledged=fault == 0, unacknowledged_host_addition_retained=fault == 2,
        host_addresses_routes_rules_preserved=fault in (0, 2), host_neighbor_mutation_authorized=False,
        whole_chain_retained_after_drop=True, original_six_contexts_retained_after_drop=True,
        baseline_context_retained_after_drop=True, generation_context_retained_after_drop=True,
        host_link_context_retained_after_drop=True, parent_pristine=True, placement_authorized=False,
        up_authorized=False, health_ready_authorized=False, resource_cleanup_authorized=False,
        multi_exit_runtime_proven=False, requirement8_complete=False)
    c.update(host_addition_top=w, host_addition_fault=fault)
    c['environment']['after'].update(started_at=start+20., finished_at=start+20.01)
    return c

rows = [dict(case='historical_4bdd_prefix_without_synthetic_HOST', result='PASS', native_acceptance=False)]
for fault in range(4):
    m.validate_complete(fixture(fault))
    rows.append(dict(case='synthetic_HOST_mode_'+str(fault), result='PASS', native_acceptance=False))

mutations = []
def mutation(name, function, fault=0): mutations.append((name, function, fault))
def top(c): return c['host_addition_top']
def hist(c, i=3): return top(c)['preparation']['host_link'][i]
def op(c, i=3): return top(c)['operations'][i]

mutation('outer_unknown', lambda c: top(c).update(extra=1))
mutation('schema_bool', lambda c: top(c).update(schema=True))
mutation('fault_bool', lambda c: c.update(host_addition_fault=False))
mutation('missing_operation', lambda c: top(c)['operations'].pop())
mutation('duplicate_operation', lambda c: top(c)['operations'].__setitem__(2, copy.deepcopy(op(c, 0))))
mutation('foreign_kind', lambda c: hist(c).update(kind='pair'))
mutation('extra_native_field', lambda c: op(c).update(socket_identity={'ino':1}))
mutation('old_writer_mutation', lambda c: top(c)['preparation']['writers'][74].update(actual_wait_status=9))
mutation('old_history_mutation', lambda c: top(c)['preparation']['producer_binding'].update(policy=[99]*32))
mutation('old_prefix_drop_claim', lambda c: c['producer_binding_top'].update(whole_chain_retained_after_drop=True))
mutation('missing_history', lambda c: top(c)['preparation']['host_link'].pop())
mutation('partial_birth', lambda c: hist(c).update(birth=None))
mutation('partial_result', lambda c: hist(c).update(result=None))
mutation('missing_pending', lambda c: top(c)['preparation'].update(pending_host_link=None), 2)
mutation('pending_result_committed', lambda c: hist(c).update(result=copy.deepcopy(op(c)['result'])), 2)
mutation('pending_time_committed', lambda c: hist(c).update(verified_at=op(c)['accepted_at']), 2)
mutation('pending_foreign_digest', lambda c: top(c)['preparation']['pending_host_link'][3].update(request=[77]*32), 2)
mutation('pending_missing_prior_history', lambda c: top(c)['preparation']['pending_host_link'].pop(0), 2)
mutation('pending_global_fence_cleared', lambda c: top(c)['preparation'].update(mutation_fenced=False), 2)
mutation('success_invented_pending', lambda c: top(c)['preparation'].update(pending_host_link=[]))
mutation('late_native_result', lambda c: op(c).update(accepted_at=hist(c)['deadline']))
mutation('nan_native_result', lambda c: op(c).update(accepted_at=float('nan')))
mutation('infinite_deadline', lambda c: hist(c).update(deadline=float('inf')))
mutation('renewed_window', lambda c: hist(c).update(deadline=hist(c)['deadline']+2))
mutation('admission_late', lambda c: top(c)['admission'].update(accepted_at=top(c)['admission']['deadline']))
mutation('admission_prior_to_original_binding', lambda c: top(c)['admission'].update(requested_at=1., deadline=3., accepted_at=2.))
mutation('single_read', lambda c: top(c)['admission'].update(two_original_reads_verified=False))
mutation('generation_rc_lost', lambda c: top(c)['admission'].update(same_generation_owner_retained=False))
mutation('declaration_digest_wrong', lambda c: top(c)['admission'].update(declaration=[44]*32))
mutation('baseline_generation_wrong', lambda c: c['host_baseline_declaration'].update(generation=2))
mutation('baseline_namespace_wrong', lambda c: c['host_baseline_declaration']['host_namespace'].update(ino=3))
mutation('baseline_not_authored', lambda c: c['host_baseline'].update(authored_public_input_only=False))
mutation('baseline_grants_authority', lambda c: c['host_baseline'].update(host_authority_granted=True))
mutation('baseline_metadata_unknown', lambda c: c['host_baseline'].update(extra=1))
mutation('baseline_sha_wrong', lambda c: c['host_baseline'].update(sha256='f'*64))
mutation('descriptor_index_bool', lambda c: c['descriptor'].update(planned_host_link_index=True))
mutation('index_not_planned', lambda c: top(c).update(planned_host_link_index=top(c)['planned_host_link_index']+1))
mutation('index_low', lambda c: c['descriptor'].update(planned_host_link_index=999999))
mutation('index_overflow', lambda c: c['descriptor'].update(planned_host_link_index=2**31))
mutation('addition_index_wrong', lambda c: hist(c)['addition'].__setitem__(1, 1900012))
mutation('addition_zero_digest', lambda c: hist(c)['addition'].__setitem__(0, [0]*32))
mutation('addition_digest_native_mismatch', lambda c: op(c)['addition'][0].__setitem__(0, 31))
mutation('addition_missing', lambda c: hist(c).update(addition=None))
mutation('namespace_role_swapped', lambda c: hist(c, 2).update(namespace=copy.deepcopy(hist(c, 0)['namespace'])))
mutation('namespace_foreign', lambda c: op(c)['namespace'].update(ino=3))
mutation('namespace_float', lambda c: op(c)['namespace'].update(dev=4.0))
mutation('native_role_swapped', lambda c: op(c, 1).update(kind='host_sockets'))
mutation('request_duplicate', lambda c: hist(c).update(request=hist(c, 2)['request'].copy()))
mutation('request_zero', lambda c: hist(c).update(request=[0]*32))
mutation('native_pid_foreign', lambda c: op(c).update(original_pid=op(c)['original_pid']+1))
mutation('native_start_float', lambda c: op(c).update(original_start=float(op(c)['original_start'])))
mutation('native_status_bool', lambda c: op(c).update(actual_wait_status=False))
mutation('native_not_eof', lambda c: op(c).update(eof=False))
mutation('native_not_released', lambda c: op(c).update(durable_birth_released=False))
mutation('native_unregistered', lambda c: op(c).update(complete_native_registration=False))
mutation('slots_partial', lambda c: op(c).update(registered_native_slots=2))
mutation('slots_bool', lambda c: op(c).update(registered_native_slots=True))
mutation('foreign_borrowed_lineage', lambda c: op(c).update(borrowed_registration_count=2))
mutation('postcompleted_inventory_poll_missing', lambda c: op(c).update(postcompletion_inventory_polls=1))
mutation('postcompleted_inventory_changed', lambda c: op(c).update(postcompletion_inventory_preserved=False))
mutation('socket_invented_inventory_claim', lambda c: op(c, 0).update(postcompletion_inventory_preserved=True))
mutation('constructor_born_release', lambda c: top(c)['failed_constructor'].update(durable_birth_released=True), 1)
mutation('constructor_invented_start', lambda c: top(c)['failed_constructor'].update(original_start=1), 1)
mutation('constructor_false_zero_status', lambda c: top(c)['failed_constructor'].update(actual_wait_status=0), 1)
mutation('registration_invented_pid', lambda c: top(c)['failed_constructor'].update(original_pid=2), 3)
mutation('registration_invented_birth', lambda c: hist(c).update(birth={}), 3)
mutation('constructor_invented_complete', lambda c: top(c)['failed_constructor'].update(complete_native_registration=True), 3)
mutation('result_namespace_foreign', lambda c: op(c)['result']['namespace'].update(ino=4))
mutation('result_peer_foreign', lambda c: op(c)['result']['peer'].update(index=999))
mutation('result_link_up', lambda c: op(c)['result']['host'].update(up=True))
mutation('result_link_index_float', lambda c: op(c)['result']['host'].update(index=1900011.0))
mutation('result_alias_generation_foreign', lambda c: op(c)['result']['host'].update(alias='vprouter-v2:foreign:2:a'))
mutation('pair_peer_not_reciprocal', lambda c: op(c, 1)['result']['peer'].update(peer_index=1))
mutation('stale_snapshot', lambda c: op(c).update(host_observation=copy.deepcopy(top(c)['admission']['declared_baseline'])))
mutation('snapshot_added_extra_link', lambda c: op(c)['host_observation']['links'].append(copy.deepcopy(op(c)['result']['host'])))
mutation('snapshot_missing_prior_link', lambda c: op(c)['host_observation']['links'].pop(0))
mutation('snapshot_changed_routes', lambda c: op(c)['host_observation']['routes'].pop())
mutation('snapshot_unknown_neighbors', lambda c: op(c)['host_observation'].update(neighbors=[]))
mutation('snapshot_changed_existing_link', lambda c: op(c)['host_observation']['links'][0].update(mtu=999))
mutation('snapshot_status_bool', lambda c: op(c)['host_observation']['links'][0].update(index=True))
mutation('writer_missing', lambda c: top(c)['preparation']['writers'].pop())
mutation('writer_identity_duplicate', lambda c: top(c)['preparation']['writers'][86].update(pid=top(c)['preparation']['writers'][85]['pid'], start=top(c)['preparation']['writers'][85]['start']))
mutation('writer_phase', lambda c: top(c)['preparation']['writers'][86].update(phase='host_link_birth'))
mutation('writer_late', lambda c: top(c)['preparation']['writers'][86].update(verified_at=hist(c)['deadline']))
mutation('writer_status_bool', lambda c: top(c)['preparation']['writers'][86].update(actual_wait_status=False))
mutation('writer_no_ack', lambda c: top(c)['preparation']['writers'][86].update(verified_at=None))
mutation('writer_before_birth_ack', lambda c: op(c).update(accepted_at=hist(c)['requested_at']+.045))
mutation('writer_false_original_window', lambda c: top(c)['preparation']['writers'][86].update(parent_deadline=hist(c)['deadline']+2))
mutation('writer_wrong_global_deadline', lambda c: top(c)['preparation']['writers'][75].update(parent_deadline=hist(c)['deadline']))
mutation('own_intent_wrong_writer', lambda c: top(c)['own_intent_polling'].update(index=74))
mutation('own_intent_not_held', lambda c: top(c)['own_intent_polling'].update(held_pending_polls=1))
mutation('own_intent_not_released', lambda c: top(c)['own_intent_polling'].update(released=False))
mutation('own_intent_missing_negatives', lambda c: top(c)['own_intent_polling'].update(negative_checks=6))
mutation('charges_before_wrong', lambda c: top(c).update(charges_before=[0, 0]))
mutation('charges_bool', lambda c: top(c).update(charges_before_drop=[True, 5]))
mutation('charges_retired_after_drop', lambda c: top(c).update(charges_after_drop=[0, 0]))
mutation('result_failed_writer_not_held', lambda c: top(c).update(result_writer_held=False), 2)
mutation('result_failed_writer_released_charge', lambda c: top(c).update(charges_after_drop=[5, 5]), 2)
mutation('retained_missing', lambda c: top(c).update(retained_result_writer=None), 2)
mutation('retained_wrong_index', lambda c: top(c)['retained_result_writer'].update(index=85), 2)
mutation('retained_weak_charge_missing', lambda c: top(c)['retained_result_writer'].update(charge_retained_after_collection=False), 2)
mutation('retained_acknowledged', lambda c: top(c)['retained_result_writer'].update(acknowledged=True), 2)
mutation('retained_wrong_reap', lambda c: top(c)['retained_result_writer'].update(pid=2), 2)
mutation('retained_charge_replaced', lambda c: top(c)['retained_result_writer'].update(launch_charge=2), 2)
mutation('retained_extra', lambda c: top(c)['retained_result_writer'].update(extra=True), 2)
mutation('retry_missing', lambda c: top(c).update(failure_retry=None), 1)
mutation('retry_births_changed', lambda c: top(c)['failure_retry'].update(native_births_after=53), 1)
mutation('retry_charges_changed', lambda c: top(c)['failure_retry'].update(charges_after=[0, 0]), 1)
mutation('retry_request_changed', lambda c: top(c)['failure_retry'].update(same_original_request=False), 1)
mutation('retry_step_changed', lambda c: top(c)['failure_retry'].update(same_step=False), 1)
mutation('retry_generation_reused', lambda c: top(c)['failure_retry'].update(generation_reuse_refused=False), 1)
mutation('success_invented_retry', lambda c: top(c).update(failure_retry={}))
for key in ('whole_chain_retained_after_drop', 'original_six_contexts_retained_after_drop',
    'baseline_context_retained_after_drop', 'generation_context_retained_after_drop', 'host_link_context_retained_after_drop'):
    mutation('drop_anchor_'+key, lambda c, key=key: top(c).__setitem__(key, False))
for key in ('placement_authorized', 'up_authorized', 'health_ready_authorized', 'host_neighbor_mutation_authorized',
    'resource_cleanup_authorized', 'multi_exit_runtime_proven', 'requirement8_complete'):
    mutation('forbidden_'+key, lambda c, key=key: top(c).__setitem__(key, True))
for key in ('original_reap_bound', 'charge_retained_before_cancel', 'charge_retained_after_retries', 'charge_retained_after_drop', 'failed', 'mutation', 'canonical_pending', 'mutation_fenced'):
    mutation('retained_'+key, lambda c, key=key: top(c)['retained_result_writer'].__setitem__(key, False), 2)
# Coherent multi-surface mutations defeat equality-only implementations. These
# keep exported native/canonical/snapshot copies aligned but violate causality,
# declared generation, original pair lineage, or the exact pending proposal.
def sync_result(c, i):
    hist(c, i)['result'] = copy.deepcopy(op(c, i)['result'])
    hist(c, i)['verified_at'] = op(c, i)['accepted_at']

def coherent_pair_generation(c):
    for i in (1, 3):
        for endpoint in ('host', 'peer'):
            op(c, i)['result'][endpoint]['alias'] = 'vprouter-v2:foreign:2:foreign'
        sync_result(c, i)
    op(c)['host_observation']['links'][-1] = copy.deepcopy(op(c)['result']['host'])
mutation('coherent_foreign_pair_generation', coherent_pair_generation)

def coherent_move_lineage(c):
    op(c)['result']['host']['mtu'] += 1
    sync_result(c, 3)
    op(c)['host_observation']['links'][-1] = copy.deepcopy(op(c)['result']['host'])
mutation('coherent_wrong_moved_original_link', coherent_move_lineage)

def coherent_accept_before_birth_ack(c):
    op(c)['accepted_at'] = hist(c)['requested_at'] + .045
    sync_result(c, 3)
mutation('coherent_native_acceptance_before_birth_ack', coherent_accept_before_birth_ack)

def coherent_next_request_before_result_ack(c):
    h = hist(c, 1)
    at = op(c, 0)['accepted_at'] + .001
    h.update(requested_at=at, deadline=at+2.)
    h['birth']['deadline'] = at+2.
    op(c, 1).update(requested_at=at, deadline=at+2.)
    op(c, 1)['birth']['deadline'] = at+2.
    for writer in top(c)['preparation']['writers'][78:81]:
        writer.update(io_deadline=at+2., parent_deadline=at+2.)
mutation('coherent_next_operation_before_original_result_ack', coherent_next_request_before_result_ack)

def coherent_wrong_socket_namespace(c):
    ns = copy.deepcopy(hist(c, 0)['namespace'])
    hist(c, 2)['namespace'] = ns
    hist(c, 2)['result']['namespace'] = copy.deepcopy(ns)
    op(c, 2)['namespace'] = copy.deepcopy(ns)
    op(c, 2)['result']['namespace'] = copy.deepcopy(ns)
mutation('coherent_socket_namespace_role_lineage', coherent_wrong_socket_namespace)

def coherent_duplicate_original_birth(c):
    prior = hist(c, 1)['birth']
    h = hist(c)
    h['birth'].update(pid=prior['pid'], start=prior['start'])
    op(c)['birth'] = copy.deepcopy(h['birth'])
    op(c).update(original_pid=prior['pid'], original_start=prior['start'])
mutation('coherent_duplicate_original_birth', coherent_duplicate_original_birth)

def coherent_pending_wrong_move(c):
    op(c)['result']['host']['mtu'] += 1
    top(c)['preparation']['pending_host_link'][3]['result'] = copy.deepcopy(op(c)['result'])
    op(c)['host_observation']['links'][-1] = copy.deepcopy(op(c)['result']['host'])
mutation('coherent_pending_foreign_original_link', coherent_pending_wrong_move, 2)

def coherent_pending_prior_result_changed(c):
    proposed = top(c)['preparation']['pending_host_link']
    proposed[1]['result']['host']['mtu'] += 1
mutation('pending_retains_entire_exact_prior_history', coherent_pending_prior_result_changed, 2)

def coherent_retained_wrong_original_writer(c):
    writer = top(c)['preparation']['writers'][86]
    writer.update(actual_wait_status=0, verified_at=hist(c)['requested_at']+.09)
    retained = top(c)['retained_result_writer']
    retained['actual_wait_status'] = 0
mutation('coherent_failed_result_writer_claims_zero_exit', coherent_retained_wrong_original_writer, 2)

def pending_binding(c): return top(c)['preparation']['pending_producer_binding']
mutation('HOST_pending_binding_missing', lambda c: top(c)['preparation'].update(pending_producer_binding=None), 2)
mutation('HOST_pending_binding_no_history', lambda c: pending_binding(c).pop('history'), 2)
mutation('HOST_pending_binding_no_producer', lambda c: pending_binding(c).pop('producer'), 2)
mutation('HOST_pending_binding_extra', lambda c: pending_binding(c).update(extra=True), 2)
mutation('HOST_pending_binding_not_wrapper', lambda c: top(c)['preparation'].update(pending_producer_binding=[]), 2)
mutation('HOST_pending_binding_history_null', lambda c: pending_binding(c).update(history=None), 2)
mutation('HOST_pending_binding_producer_null', lambda c: pending_binding(c).update(producer=None), 2)
mutation('HOST_pending_binding_request_foreign', lambda c: pending_binding(c)['history'].update(request=[99]*32), 2)
mutation('HOST_pending_binding_policy_foreign', lambda c: pending_binding(c)['history'].update(policy=[99]*32), 2)
mutation('HOST_pending_binding_result_absent', lambda c: pending_binding(c)['history'].update(result=None), 2)
mutation('HOST_pending_binding_time_changed', lambda c: pending_binding(c)['history'].update(verified_at=pending_binding(c)['history']['verified_at']+.001), 2)
mutation('HOST_pending_binding_publication_foreign', lambda c: pending_binding(c)['producer'].update(binding=[99]*32), 2)
mutation('HOST_pending_binding_publication_parent_float', lambda c: pending_binding(c)['producer']['parent'].update(dev=float(pending_binding(c)['producer']['parent']['dev'])), 2)
mutation('HOST_pending_binding_publication_group_bool', lambda c: pending_binding(c)['producer']['group'].update(ino=True), 2)
for fault in (0, 1, 3):
    mutation('HOST_nonpending_binding_wrapper_'+str(fault), lambda c: top(c)['preparation'].update(
        pending_producer_binding=dict(history=copy.deepcopy(top(c)['preparation']['producer_binding']),
            producer=copy.deepcopy(top(c)['preparation']['entry_producer']))), fault)

for name, change, fault in mutations:
    c = fixture(fault)
    change(c)
    try:
        m.validate_complete(c)
    except (AssertionError, KeyError, TypeError, ValueError, OverflowError):
        rows.append(dict(case=name, result='PASS_REFUSED', native_acceptance=False))
    else:
        raise AssertionError('invalid_HOST_evidence_accepted:'+name)
# Cached actual394 is immutable native evidence, reanalysed locally only. This
# calls validate_complete(), never collect(), so no accepted sidecar is written.
HOST394_CANDIDATE = 'target/continuation-20261028T080736Z/candidate.json'
HOST394_LABEL = 'amd64-clean-90a7dcc-host-result-failure'
def cached394():
    return m.validate_prefix(HOST394_CANDIDATE, HOST394_LABEL, host_addition=True)
actual394 = cached394()
actual394_path = actual394['path']
actual394_raw = actual394['raw']
assert actual394_path.name == 'actual-program-run-394.json'
assert actual394['host_addition_fault'] == 2
assert set(k for k in top(actual394)['preparation'] if not schema.same(
    top(actual394)['preparation'][k], actual394['producer_binding_top']['preparation'][k])) == {
    'writers', 'host_link', 'pending_host_link', 'mutation_fenced', 'canonical_pending',
    'pending_wireguard', 'pending_producer_creation', 'pending_producer_binding'}
actual394_proof = m.validate_complete(actual394)
assert actual394_proof['host_addition']['ordered_writers_verified'] == 87
assert actual394_proof['host_addition']['unacknowledged_host_addition_retained'] is True
rows.append(dict(case='cached_actual394_strict_schema_reanalysis', result='PASS', native_acceptance=False,
    raw_sha256=hashlib.sha256(actual394_raw).hexdigest()))
cached_mutations = [(name, change) for name, change, fault in mutations if fault == 2]
def coherent_canonical_pending_history_changed(c):
    p = top(c)['preparation']
    p['producer_binding']['policy'] = [99]*32
    p['pending_producer_binding']['history'] = copy.deepcopy(p['producer_binding'])
def coherent_canonical_pending_publication_changed(c):
    p = top(c)['preparation']
    p['entry_producer']['binding'] = [99]*32
    p['pending_producer_binding']['producer'] = copy.deepcopy(p['entry_producer'])
cached_mutations.extend([
    ('unchanged_old_history_stays_strict', coherent_canonical_pending_history_changed),
    ('unchanged_old_publication_stays_strict', coherent_canonical_pending_publication_changed),
    ('unchanged_original_writer_stays_strict', lambda c: top(c)['preparation']['writers'][74].update(actual_wait_status=9)),
    ('unchanged_original_clock_stays_strict', lambda c: top(c)['preparation']['producer_binding'].update(deadline=top(c)['preparation']['producer_binding']['deadline']+2)),
    ('exact_retained_charges_stay_strict', lambda c: top(c).update(charges_after_drop=[5, 5])),
    ('exact_generation_anchor_stays_strict', lambda c: top(c).update(generation_context_retained_after_drop=False))])
for name, change in cached_mutations:
    c = cached394()
    change(c)
    try:
        m.validate_complete(c)
    except (AssertionError, KeyError, TypeError, ValueError, OverflowError):
        rows.append(dict(case='cached394_'+name, result='PASS_REFUSED', native_acceptance=False))
    else:
        raise AssertionError('invalid_cached_HOST394_evidence_accepted:'+name)
assert actual394_path.read_bytes() == actual394_raw

assert m.loads_unique('{"schema":1,"nested":{"value":2}}') == {'schema':1, 'nested':{'value':2}}
rows.append(dict(case='strict_JSON_unique_keys', result='PASS', native_acceptance=False))
for case, raw in (('duplicate_top_JSON_key', '{"fault":1,"fault":0}'),
    ('duplicate_nested_JSON_key', '{"w":{"pid":1,"pid":2}}'),
    ('nonfinite_JSON_nan', '{"accepted_at":NaN}'), ('nonfinite_JSON_inf', '{"deadline":Infinity}')):
    try:
        m.loads_unique(raw)
    except (AssertionError, ValueError):
        rows.append(dict(case=case, result='PASS_REFUSED', native_acceptance=False))
    else:
        raise AssertionError(case)
for file in (collector_path, pathlib.Path(__file__).with_name('host_addition_evidence_schema.py')):
    result = subprocess.run([sys.executable, '-O', str(file)], capture_output=True, text=True)
    assert result.returncode != 0 and 'optimized_python_refused' in result.stderr
    rows.append(dict(case='optimized_python_refused_'+file.name, result='PASS_REFUSED', native_acceptance=False))
stamp = datetime.datetime.now(datetime.timezone.utc)
output = pathlib.Path('target/lab-state') / ('host-addition-evidence-smokes-' + stamp.strftime('%Y%m%dT%H%M%S%fZ') + '.json')
with output.open('x') as stream:
    json.dump(dict(observed_at_utc=stamp.isoformat(), checks=rows,
        files=[dict(path=path, sha256=hashlib.sha256(raw).hexdigest()) for path, raw in m.DEPENDENCY_BYTES.items()] +
            [dict(path=str(pathlib.Path(__file__)), sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()),
             dict(path=str(base['path']), sha256=hashlib.sha256(base['raw']).hexdigest()),
             dict(path=str(projection_path), sha256=hashlib.sha256(projection_path.read_bytes()).hexdigest()),
             dict(path=str(actual394_path), sha256=hashlib.sha256(actual394_raw).hexdigest())],
        native_acceptance=False, raw_records_rewritten=False, source_executed=False,
        scope='LOCAL_HOST_SCHEMA_ONLY; SYNTHETIC_HOST_PLUS_CACHED394_REANALYSIS_ONLY (no collect or sidecar394). Historical 4bdd original prefix plus explicitly invented HOST receipts, continuation flags, clocks, descriptor index and authored baseline. No new native case, no protected input staging, no native HOST mutation, placement, UP, health READY, provider/client, runtime or release acceptance.'), stream, indent=2, allow_nan=False)
print(json.dumps(dict(record=str(output), checks=len(rows), native_acceptance=False, source_executed=False)))
