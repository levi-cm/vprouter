"""Local synthetic scoped diagnostic validation; no native evidence."""
import copy,datetime,hashlib,importlib.util,json,pathlib
if not __debug__:raise RuntimeError('optimized_python_refused')
p=pathlib.Path(__file__).with_name('movement_failure_schema.py');spec=importlib.util.spec_from_file_location('schema',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
span=dict(scope='outer',phase='inner_poll',calls=2,failed_calls=1,first_at=10.1,last_at=12.001,total_seconds=.15,max_seconds=.1)
lower=dict(read_phase=2,readback_present=True,completed_present=True,report_present=True,validated=True,preparation_bound=True,accepted_at=11.8)
native=dict(request=[2]*32,requested_at=10.,deadline=12.,original_pid=1234,original_start=300,actual_wait_status=0,native_born=True,complete_present=True,result_present=True,accepted_at=11.8,acknowledged=False,postcompletion_inventory_polls=15,movement=lower)
inner=dict(step='result',request=[2]*32,requested_at=10.,deadline=12.,child=None,verified=native,last_history=None,preparation=None)
base=dict(schema=1,scope='outer',reason='Deadline',request=[1]*32,requested_at=10.,deadline=12.,observed_at=12.01,cached=dict(outer_step='moving',inner=inner,completed_owner=None,final_process_verified_at=None),spans=[span],omitted=0,inclusive_spans_not_additive=True,native_reads=False)
def validate(rows):return m.validate(rows,{('outer','inner_poll')},{'Deadline'},13.,lambda _:None)
rows=[]
validate([copy.deepcopy(base)]);rows.append(dict(case='valid_cached_result_unacknowledged',result='PASS'))
v=copy.deepcopy(base);v['cached']['inner']=None;validate([v]);rows.append(dict(case='unobserved_inner',result='PASS'))
v=copy.deepcopy(base);v.update(scope='native',cached=copy.deepcopy(native));validate([v]);rows.append(dict(case='native_scope',result='PASS'))
v=copy.deepcopy(base);v.update(scope='inner',cached=copy.deepcopy(inner));validate([v]);rows.append(dict(case='inner_scope',result='PASS'))
a=copy.deepcopy(base);a.update(scope='native',cached=copy.deepcopy(native));b=copy.deepcopy(base);b.update(scope='inner',cached=copy.deepcopy(inner));validate([a,b,copy.deepcopy(base)]);rows.append(dict(case='ordered_unwind',result='PASS'))
mutations=[('schema_bool',lambda x:x.update(schema=True)),('scope',lambda x:x.update(scope='adopt')),('reason',lambda x:x.update(reason='unknown')),('extra',lambda x:x.update(extra=1)),('digest_bool',lambda x:x['request'].__setitem__(0,True)),('digest_length',lambda x:x.update(request=[1]*31)),('digest_overflow',lambda x:x['request'].__setitem__(0,256)),('clock_bool',lambda x:x.update(requested_at=True,deadline=3.)),('changed_end',lambda x:x.update(deadline=14.)),('late_observer',lambda x:x.update(observed_at=14.)),('nan',lambda x:x.update(observed_at=float('nan'))),('spans_too_many',lambda x:x.update(spans=x['spans']*33)),('unknown_pair',lambda x:x['spans'][0].update(phase='adopt')),('duplicate_span',lambda x:x['spans'].append(copy.deepcopy(x['spans'][0]))),('calls_bool',lambda x:x['spans'][0].update(calls=True)),('fails_exceed',lambda x:x['spans'][0].update(failed_calls=3)),('span_before',lambda x:x['spans'][0].update(first_at=9.)),('span_after',lambda x:x['spans'][0].update(last_at=12.02)),('negative_total',lambda x:x['spans'][0].update(total_seconds=-1.)),('max_above_total',lambda x:x['spans'][0].update(max_seconds=.2)),('total_above_duration',lambda x:x['spans'][0].update(total_seconds=2.)),('total_above_callmax',lambda x:x['spans'][0].update(total_seconds=.25)),('omitted_bool',lambda x:x.update(omitted=False)),('not_inclusive',lambda x:x.update(inclusive_spans_not_additive=False)),('native_reads',lambda x:x.update(native_reads=True)),('outer_step',lambda x:x['cached'].update(outer_step='adopt')),('inner_step',lambda x:x['cached']['inner'].update(step='adopt')),('inner_clock',lambda x:x['cached']['inner'].update(requested_at=9.,deadline=11.)),('native_clock',lambda x:x['cached']['inner']['verified'].update(requested_at=9.,deadline=11.)),('native_digest',lambda x:x['cached']['inner']['verified'].update(request=[3]*32)),('pid_bool',lambda x:x['cached']['inner']['verified'].update(original_pid=True)),('orphan_start',lambda x:x['cached']['inner']['verified'].update(original_pid=None)),('status_bool',lambda x:x['cached']['inner']['verified'].update(actual_wait_status=False)),('accepted_late',lambda x:x['cached']['inner']['verified'].update(accepted_at=12.)),('inventory_bool',lambda x:x['cached']['inner']['verified'].update(postcompletion_inventory_polls=True)),('lower_phase',lambda x:x['cached']['inner']['verified']['movement'].update(read_phase=3)),('lower_bool',lambda x:x['cached']['inner']['verified']['movement'].update(validated=1)),('final_time_late',lambda x:x['cached'].update(final_process_verified_at=12.))]
for name,change in mutations:
 v=copy.deepcopy(base);change(v)
 try:validate([v])
 except(AssertionError,TypeError,ValueError,KeyError):rows.append(dict(case=name,result='PASS_REFUSED'))
 else:raise AssertionError('invalid_movement_accepted:'+name)
for name,items in [('duplicate_scope',[copy.deepcopy(base),copy.deepcopy(base)]),('wrong_unwind',[copy.deepcopy(base),copy.deepcopy(a)]),('changed_outer_request',[copy.deepcopy(a),copy.deepcopy(base)]),('backwards_observation',[copy.deepcopy(a),copy.deepcopy(base)])]:
 if name=='changed_outer_request':items[1]['request']=[5]*32
 if name=='backwards_observation':items[1]['observed_at']=12.005
 try:validate(items)
 except(AssertionError,TypeError,ValueError,KeyError):rows.append(dict(case=name,result='PASS_REFUSED'))
 else:raise AssertionError('invalid_order_accepted:'+name)
source_paths=[pathlib.Path(name)for name in m.SOURCE_PATHS]
source_pairs=m.extract_pairs([path.read_bytes()for path in source_paths])
for phase in ('binding_verify','poll_ack_reap','receipt_verify'):
 v=copy.deepcopy(base);v['spans'][0].update(scope='result_writer',phase=phase)
 m.validate([v],source_pairs,{'Deadline'},13.,lambda _:None);rows.append(dict(case='source_derived_result_writer_'+phase,result='PASS'))
lower_path=pathlib.Path('crates/vprouter-network/src/secret_role/movement.rs');lower_source=lower_path.read_text()
assert 'n.accepted_at = Some(vprouter_core::health::boot_seconds());\n            end_instant(n.end)?;'in lower_source
v=copy.deepcopy(base);n=v['cached']['inner']['verified'];n.update(accepted_at=None,result_present=False,complete_present=False,actual_wait_status=None);n['movement']['accepted_at']=12.001
proof=validate([v]);assert proof['lower_attempted_timestamps'][0]['status']=='late'and proof['lower_attempted_timestamps'][0]['acceptance_authority']is False;rows.append(dict(case='source_correlated_late_lower_attempt',result='PASS'))
v['cached']['inner']['verified']['movement']['accepted_at']=12.
proof=validate([v]);assert proof['lower_attempted_timestamps'][0]['status']=='late';rows.append(dict(case='lower_exact_end_attempt_late',result='PASS'))
v['cached']['inner']['verified']['movement']['accepted_at']=14.
try:validate([v])
except(AssertionError,TypeError,ValueError,KeyError):rows.append(dict(case='lower_attempt_after_observer',result='PASS_REFUSED'))
else:raise AssertionError('attempt_after_observer_accepted')
files=[pathlib.Path(__file__),p,pathlib.Path(__file__).with_name('collect-movement-failure.py')];files.extend(source_paths);files.append(lower_path)
record=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),checks=rows,files=[dict(path=str(f),sha256=hashlib.sha256(f.read_bytes()).hexdigest())for f in files],native_acceptance=False,scope='LOCAL_SYNTHETIC_DIAGNOSTIC_SCHEMA_ONLY; no native action, cause, ACK/reap, cleanup, retry, CPU attribution or release acceptance')
out=pathlib.Path('target/lab-state')/('movement-failure-diagnostic-smokes-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.json')
with out.open('x')as stream:json.dump(record,stream,indent=2);stream.write('\n')
print(json.dumps(dict(record=str(out),checks=len(rows),native_acceptance=False)))
