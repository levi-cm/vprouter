"""Feature-gated post-completion inventory schema; no native completion minted."""
import datetime,hashlib,importlib.util,json,pathlib
if not __debug__:raise RuntimeError('optimized_python_refused')
def load(name):
 p=pathlib.Path(__file__).with_name(name);n={'__file__':str(p)};exec(compile(p.read_text().split('\nrows=[]',1)[0],str(p),'exec'),n);return n
producer=load('smoke-quarantine-producer.py');provision=load('smoke-provision-evidence.py');movement=load('smoke-movement-evidence.py')
def set_fields(c,expected=True):
 c['postcompletion_inventory_expected']=expected
 if not expected:return c
 values=list(c['top']['operations'])
 if 'movement_top'in c:values+=c['movement_top']['operations']
 for holder in[c['top'],c.get('movement_top',{})]:
  if holder.get('failed_constructor'):values.append(holder['failed_constructor'])
 for op in values:
  required=op.get('accepted_at')is not None and op['kind']in('provision','query','move')
  op.update(postcompletion_inventory_polls=2 if required else 0,postcompletion_inventory_preserved=required)
 return c
def sample(fault=0,expected=True):return set_fields(producer['sample'](fault,whole=True),expected)
rows=[]
for fault in range(4):
 for expected in[False,True]:
  c=sample(fault,expected);proof=producer['collector'].validate_quarantine(c);assert proof['movement']['postcompletion_inventory_required']is expected
  rows.append(dict(case='whole_mode_'+str(fault)+'_feature_'+str(expected),result='PASS'))
 c=set_fields(provision['sample'](fault));provision['collector'].validate_pipeline(c);rows.append(dict(case='provision_mode_'+str(fault),result='PASS'))
 c=set_fields(movement['sample'](fault));movement['movement'].validate_movement(c);rows.append(dict(case='movement_mode_'+str(fault),result='PASS'))
def modify(c,kind,change):
 for op in c['top']['operations']+c['movement_top']['operations']:
  if op['kind']==kind:change(op)
mutations=[
 ('missing_provision','provision',lambda op:op.pop('postcompletion_inventory_polls',None)),
 ('one_provision_pass','provision',lambda op:op.update(postcompletion_inventory_polls=1)),
 ('query_not_preserved','query',lambda op:op.update(postcompletion_inventory_preserved=False)),
 ('move_not_preserved','move',lambda op:op.update(postcompletion_inventory_preserved=False)),
 ('move_count_bool','move',lambda op:op.update(postcompletion_inventory_polls=True)),
 ('query_count_overflow','query',lambda op:op.update(postcompletion_inventory_polls=2**32)),
 ('accepted_status_bool','provision',lambda op:op.update(actual_wait_status=False)),
 ('socket_false_claim','sockets',lambda op:op.update(postcompletion_inventory_polls=2,postcompletion_inventory_preserved=True)),
 ('data_socket_false_claim','data_sockets',lambda op:op.update(postcompletion_inventory_polls=2,postcompletion_inventory_preserved=True)),
]
for name,kind,change in mutations:
 c=sample();modify(c,kind,change)
 try:producer['collector'].validate_quarantine(c)
 except(AssertionError,ValueError,TypeError,KeyError):rows.append(dict(case=name,result='PASS_REFUSED'))
 else:raise AssertionError('bad_postcompletion_inventory_accepted:'+name)
paths=[pathlib.Path(__file__),pathlib.Path(__file__).with_name('wireguard_inventory_schema.py')]
paths += [pathlib.Path(__file__).with_name(name)for name in['collect-secret-provision.py','collect-secret-movement.py','collect-secret-quarantine.py','provision_evidence_base.py','movement_evidence_base.py','quarantine_evidence_base.py','smoke-quarantine-producer.py']]
record=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),checks=rows,files=[dict(path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest())for p in paths],scope='LOCAL_SYNTHETIC_POSTCOMPLETION_SCHEMA_ONLY; no actual child, Completed, FD, token, native or release acceptance')
destination=pathlib.Path('target/lab-state')/('wireguard-postcompletion-smokes-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.json')
with destination.open('x')as f:json.dump(record,f,indent=2);f.write('\n')
print(json.dumps(dict(record=str(destination),checks=len(rows),native_acceptance=False)))
