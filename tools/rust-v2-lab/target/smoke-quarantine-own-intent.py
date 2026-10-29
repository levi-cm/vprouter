"""Synthetic exact-own-queue polling evidence; no writer is held or released."""
import datetime,hashlib,json,pathlib
if not __debug__:raise RuntimeError('optimized_python_refused')
p=pathlib.Path(__file__).with_name('smoke-wireguard-postcompletion.py');setup={'__file__':str(p)}
exec(compile(p.read_text().split('\nrows=[]',1)[0],str(p),'exec'),setup)
def sample(fault=0,expected=True):
 c=setup['sample'](fault);c['own_intent_polling_expected']=expected
 if expected:
  p=c['quarantine_top']['preparation'];w=p['writers'][42];h=p['netfilter'][0]
  c['quarantine_top']['own_intent_polling']=dict(queued_polls=1,held_pending_polls=2,negative_checks=12,original_writer=dict(index=42,pid=w['pid'],start=w['start']),requested_at=h['requested_at'],deadline=h['deadline'],verified_at=w['verified_at'],actual_wait_status=0)
 return c
collector=setup['producer']['collector'];rows=[]
for fault in range(4):
 for expected in[False,True]:
  c=sample(fault,expected);proof=collector.validate_quarantine(c);assert proof['own_intent_polling']['required']is expected
  rows.append(dict(case='mode_'+str(fault)+'_feature_'+str(expected),result='PASS'))
mutations=[('queued_bool',lambda p:p.update(queued_polls=True)),('missing_queued_poll',lambda p:p.update(queued_polls=0)),('one_pending_poll',lambda p:p.update(held_pending_polls=1)),('pending_bool',lambda p:p.update(held_pending_polls=True)),('pending_overflow',lambda p:p.update(held_pending_polls=2**64)),('missing_negative',lambda p:p.update(negative_checks=11)),('wrong_index',lambda p:p['original_writer'].update(index=43)),('wrong_pid',lambda p:p['original_writer'].update(pid=p['original_writer']['pid']+1)),('wrong_start',lambda p:p['original_writer'].update(start=p['original_writer']['start']+1)),('new_end',lambda p:p.update(deadline=p['deadline']+2)),('not_original_ack',lambda p:p.update(verified_at=p['verified_at']+.001)),('status_bool',lambda p:p.update(actual_wait_status=False)),('status_failure',lambda p:p.update(actual_wait_status=9)),('extra_field',lambda p:p.update(extra=True))]
for name,mutate in mutations:
 c=sample();mutate(c['quarantine_top']['own_intent_polling'])
 try:collector.validate_quarantine(c)
 except(AssertionError,TypeError,KeyError,ValueError):rows.append(dict(case=name,result='PASS_REFUSED'))
 else:raise AssertionError('invalid_own_intent_evidence_accepted:'+name)
c=sample();c['quarantine_top'].pop('own_intent_polling')
try:collector.validate_quarantine(c)
except(AssertionError,TypeError,KeyError,ValueError):rows.append(dict(case='required_evidence_missing',result='PASS_REFUSED'))
else:raise AssertionError('missing_own_intent_evidence_accepted')
c=sample();prep=c['quarantine_top']['preparation'];h=prep['netfilter'][0];w=prep['writers'][42];proof=c['quarantine_top']['own_intent_polling']
h.update(requested_at=1.,deadline=3.);h['birth'].update(born_at=1.03);w.update(queued_at=1.01,verified_at=1.02,io_deadline=3.,parent_deadline=3.);proof.update(requested_at=1.,deadline=3.,verified_at=1.02);c['environment']['after']['started_at']=4.
collector.validate_own_intent_polling(c,prep);rows.append(dict(case='small_positive_clock_direct_helper',result='PASS'))
proof['requested_at']=True
try:collector.validate_own_intent_polling(c,prep)
except(AssertionError,TypeError,KeyError,ValueError):rows.append(dict(case='copied_request_clock_bool_targeted',result='PASS_REFUSED'))
else:raise AssertionError('boolean_copied_clock_accepted')
paths=[pathlib.Path(__file__),p]+[pathlib.Path(__file__).with_name(name)for name in['collect-secret-quarantine.py','quarantine_evidence_base.py','quarantine_history_schema.py','wireguard_inventory_schema.py']]
record=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),checks=rows,files=[dict(path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest())for p in paths],scope='LOCAL_SYNTHETIC_OWN_INTENT_SCHEMA_ONLY; no native writer, queued/pending transition, ACK, held child, permission or release acceptance')
destination=pathlib.Path('target/lab-state')/('quarantine-own-intent-smokes-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.json')
with destination.open('x')as f:json.dump(record,f,indent=2);f.write('\n')
print(json.dumps(dict(record=str(destination),checks=len(rows),native_acceptance=False)))
