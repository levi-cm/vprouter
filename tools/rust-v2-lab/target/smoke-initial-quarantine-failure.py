"""Cached-only diagnostic schema mutations; no native action or authority."""
import copy,datetime,hashlib,importlib.util,json,pathlib
if not __debug__:raise RuntimeError('optimized_python_refused')
p=pathlib.Path(__file__).with_name('initial_quarantine_failure_schema.py');spec=importlib.util.spec_from_file_location('initial_failure_schema',p);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
phases={'advance_binding','queue_idle'}
failure=dict(schema=1,phase='advance_binding',reason='OwnershipMismatch',operation_index=0,step='intent',requested_at=10.,deadline=12.,queue_state=dict(failed=False,pending=False,queued=False,continuation=False,result_issued=True),job_counts=dict(total=8,matched=8),observed_at=10.01,child=None)
progress=dict(schema=1,member='a',owner_epoch={'unit':'unit'},writers=[dict(phase='intent',pid=42,start=100,queued_at=9.,io_deadline=11.,parent_deadline=11.,actual_wait_status=0,verified_at=9.1)],netfilter=[],pending_netfilter=None,canonical_pending=False,mutation_fenced=False)
rows=[]
module.validate_failure(copy.deepcopy(failure),phases,13.);rows.append(dict(case='valid_cached_failure',result='PASS'))
v=copy.deepcopy(failure);v.update(requested_at=None,deadline=None,queue_state=None,job_counts=None);proof=module.validate_failure(v,phases,13.);assert proof['active_clock_observed']is False;rows.append(dict(case='unknown_stays_unknown',result='PASS'))
module.validate_progress(copy.deepcopy(progress),'a',{'unit':'unit'},13.);rows.append(dict(case='valid_cached_progress',result='PASS'))
v=copy.deepcopy(progress);v['writers'][0].update(pid=None,start=None,actual_wait_status=None,verified_at=None);module.validate_progress(v,'a',{'unit':'unit'},13.);rows.append(dict(case='unobserved_writer_stays_unknown',result='PASS'))
mutations=[('schema_bool',lambda v:v.update(schema=True)),('unknown_phase',lambda v:v.update(phase='adopted')),('index_bool',lambda v:v.update(operation_index=True)),('index_large',lambda v:v.update(operation_index=7)),('step',lambda v:v.update(step='adopt')),('one_clock_null',lambda v:v.update(deadline=None)),('new_end',lambda v:v.update(deadline=14.)),('nan_clock',lambda v:v.update(observed_at=float('nan'))),('after_observer',lambda v:v.update(observed_at=14.)),('queue_bool',lambda v:v['queue_state'].update(result_issued=1)),('job_mismatch',lambda v:v['job_counts'].update(matched=9)),('job_bool',lambda v:v['job_counts'].update(total=True)),('extra',lambda v:v.update(extra=1))]
for name,mutate in mutations:
 v=copy.deepcopy(failure);mutate(v)
 try:module.validate_failure(v,phases,13.)
 except(AssertionError,TypeError,ValueError,KeyError):rows.append(dict(case=name,result='PASS_REFUSED'))
 else:raise AssertionError('invalid_failure_accepted:'+name)
mutations=[('wrong_member',lambda v:v.update(member='b')),('wrong_epoch',lambda v:v.update(owner_epoch={'unit':'other'})),('pending_bool',lambda v:v.update(canonical_pending=1)),('too_many_writers',lambda v:v.update(writers=v['writers']*81)),('status_bool',lambda v:v['writers'][0].update(actual_wait_status=False)),('verified_without_reap',lambda v:v['writers'][0].update(actual_wait_status=None)),('late_queue',lambda v:v['writers'][0].update(queued_at=14.)),('late_ack',lambda v:v['writers'][0].update(verified_at=11.)),('missing_pid_start',lambda v:v['writers'][0].update(pid=None)),('too_many_histories',lambda v:v.update(netfilter=[{}]*7))]
for name,mutate in mutations:
 v=copy.deepcopy(progress);mutate(v)
 try:module.validate_progress(v,'a',{'unit':'unit'},13.)
 except(AssertionError,TypeError,ValueError,KeyError):rows.append(dict(case=name,result='PASS_REFUSED'))
 else:raise AssertionError('invalid_progress_accepted:'+name)
def identified_child():
 v=copy.deepcopy(failure);v['child']=dict(pid=1234,start=300,actual_wait_status=0,born=True,birth=dict(pid=1234,start=300,born_at=10.002,deadline=12.),accepted_at=10.004);return v
module.validate_failure(identified_child(),phases,13.);rows.append(dict(case='identified_cached_child',result='PASS'))
v=identified_child();v['child'].update(actual_wait_status=None,accepted_at=None);module.validate_failure(v,phases,13.);rows.append(dict(case='born_unreaped_child',result='PASS'))
for name,change in [('orphan_start',lambda c:c.update(pid=None)),('orphan_status',lambda c:c.update(pid=None,start=None,birth=None,accepted_at=None)),('birth_pid_overflow',lambda c:c['birth'].update(pid=2**32)),('birth_clock',lambda c:c['birth'].update(deadline=14.)),('birth_before_window',lambda c:c['birth'].update(born_at=9.)),('birth_after_observed',lambda c:c['birth'].update(born_at=10.02)),('accepted_before_birth',lambda c:c.update(accepted_at=10.001)),('accepted_without_birth',lambda c:c.update(birth=None)),('accepted_nonzero',lambda c:c.update(actual_wait_status=9)),('accepted_unreaped',lambda c:c.update(actual_wait_status=None))]:
 v=identified_child();change(v['child'])
 try:module.validate_failure(v,phases,13.)
 except(AssertionError,TypeError,ValueError,KeyError):rows.append(dict(case=name,result='PASS_REFUSED'))
 else:raise AssertionError('invalid_cached_child_accepted:'+name)
v=copy.deepcopy(progress);v['writers'][0].update(pid=2**32)
try:module.validate_progress(v,'a',{'unit':'unit'},13.)
except(AssertionError,TypeError,ValueError,KeyError):rows.append(dict(case='writer_pid_overflow',result='PASS_REFUSED'))
else:raise AssertionError('overwidth_writer_accepted')
v=copy.deepcopy(progress);v['writers'][0].update(queued_at=.5,io_deadline=1.,parent_deadline=True,actual_wait_status=None,verified_at=None)
try:module.validate_progress(v,'a',{'unit':'unit'},13.)
except(AssertionError,TypeError,ValueError,KeyError):rows.append(dict(case='parent_deadline_bool_targeted',result='PASS_REFUSED'))
else:raise AssertionError('boolean_parent_deadline_accepted')
files=[pathlib.Path(__file__),p,pathlib.Path(__file__).with_name('collect-initial-quarantine-failure.py')]
record=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),checks=rows,files=[dict(path=str(f),sha256=hashlib.sha256(f.read_bytes()).hexdigest())for f in files],scope='LOCAL_SYNTHETIC_CACHED_DIAGNOSTIC_SCHEMA_ONLY; no native, kernel, current state, ACK, cleanup or release acceptance')
destination=pathlib.Path('target/lab-state')/('initial-quarantine-diagnostic-smokes-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.json')
with destination.open('x')as stream:json.dump(record,stream,indent=2);stream.write('\n')
print(json.dumps(dict(record=str(destination),checks=len(rows),native_acceptance=False)))
