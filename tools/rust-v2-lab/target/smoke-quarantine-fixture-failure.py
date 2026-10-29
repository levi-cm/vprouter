"""Cached fixture diagnostics only; synthetic cases do not execute a child."""
import copy,datetime,hashlib,importlib.util,json,pathlib
if not __debug__:raise RuntimeError('optimized_python_refused')
p=pathlib.Path(__file__).with_name('initial_quarantine_failure_schema.py');spec=importlib.util.spec_from_file_location('schema',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
base=dict(schema=1,phase='advance_binding',reason='Deadline',operation_index=0,step='intent',requested_at=10.,deadline=12.,queue_state=None,job_counts=None,observed_at=12.01,child=None,own_intent_fixture=dict(queued_polls=1,held_pending_polls=2,intent_released=True,original_writer=dict(index=42,pid=1234,start=300)))
w=dict(phase='netfilter_intent',pid=1234,start=300,queued_at=10.1,io_deadline=12.,parent_deadline=12.,actual_wait_status=None,verified_at=None)
progress=dict(schema=1,member='a',owner_epoch={'unit':'unit'},writers=[copy.deepcopy(w)for _ in range(43)],netfilter=[],pending_netfilter=[],canonical_pending=True,mutation_fenced=False,checkpoint_waiting=False)
def validate(f,g):
 m.validate_failure(f,{'advance_binding'},13.,fixture=True)
 if g is not None:m.validate_progress(g,'a',{'unit':'unit'},13.,fixture=True)
 m.bind_fixture(f,g)
rows=[]
for name,change in [('released',lambda f,g:None),('held',lambda f,g:(f['own_intent_fixture'].update(held_pending_polls=1,intent_released=False),g.update(checkpoint_waiting=True))),('before_checkpoint',lambda f,g:f['own_intent_fixture'].update(held_pending_polls=0,intent_released=False,original_writer=None)),('unobserved_fixture',lambda f,g:f.update(own_intent_fixture=None)),('unobserved_checkpoint',lambda f,g:g.update(checkpoint_waiting=None))]:
 f,g=copy.deepcopy(base),copy.deepcopy(progress);change(f,g);validate(f,g);rows.append(dict(case=name,result='PASS'))
mutations=[('missing_fixture',lambda f,g:f.pop('own_intent_fixture')),('extra_fixture',lambda f,g:f['own_intent_fixture'].update(extra=1)),('queue_bool',lambda f,g:f['own_intent_fixture'].update(queued_polls=True)),('queue_large',lambda f,g:f['own_intent_fixture'].update(queued_polls=2)),('held_bool',lambda f,g:f['own_intent_fixture'].update(held_pending_polls=True)),('held_large',lambda f,g:f['own_intent_fixture'].update(held_pending_polls=3)),('release_integer',lambda f,g:f['own_intent_fixture'].update(intent_released=1)),('released_before_two',lambda f,g:f['own_intent_fixture'].update(held_pending_polls=1)),('held_without_writer',lambda f,g:f['own_intent_fixture'].update(original_writer=None)),('held_without_queue',lambda f,g:f['own_intent_fixture'].update(queued_polls=0)),('writer_index_bool',lambda f,g:f['own_intent_fixture']['original_writer'].update(index=True)),('writer_index_wrong',lambda f,g:f['own_intent_fixture']['original_writer'].update(index=41)),('writer_pid_bool',lambda f,g:f['own_intent_fixture']['original_writer'].update(pid=True)),('writer_pid_overflow',lambda f,g:f['own_intent_fixture']['original_writer'].update(pid=2**32)),('writer_start_bool',lambda f,g:f['own_intent_fixture']['original_writer'].update(start=True)),('writer_start_zero',lambda f,g:f['own_intent_fixture']['original_writer'].update(start=0)),('writer_phase_mismatch',lambda f,g:g['writers'][42].update(phase='netfilter_result')),('writer_pid_mismatch',lambda f,g:g['writers'][42].update(pid=1235)),('writer_start_mismatch',lambda f,g:g['writers'][42].update(start=301)),('writer_end_mismatch',lambda f,g:g['writers'][42].update(io_deadline=12.1,parent_deadline=12.1)),('writer_missing',lambda f,g:g.update(writers=g['writers'][:42])),('checkpoint_missing',lambda f,g:g.pop('checkpoint_waiting')),('checkpoint_integer',lambda f,g:g.update(checkpoint_waiting=1))]
for name,change in mutations:
 f,g=copy.deepcopy(base),copy.deepcopy(progress);change(f,g)
 try:validate(f,g)
 except(AssertionError,TypeError,ValueError,KeyError):rows.append(dict(case=name,result='PASS_REFUSED'))
 else:raise AssertionError('invalid_fixture_accepted:'+name)
files=[pathlib.Path(__file__),p,pathlib.Path(__file__).with_name('collect-initial-quarantine-failure.py')]
record=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),checks=rows,files=[dict(path=str(f),sha256=hashlib.sha256(f.read_bytes()).hexdigest())for f in files],native_acceptance=False,scope='LOCAL synthetic cached fixture/checkpoint schema only; no ACK/reap, operation cause, retry, timer extension or resource authority')
out=pathlib.Path('target/lab-state')/('quarantine-fixture-diagnostic-smokes-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.json')
with out.open('x')as stream:json.dump(record,stream,indent=2);stream.write('\n')
print(json.dumps(dict(record=str(out),checks=len(rows),native_acceptance=False)))
