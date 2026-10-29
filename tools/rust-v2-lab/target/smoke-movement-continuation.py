"""Synthetic live42 continuation truth; never a native movement proof."""
import copy,datetime,hashlib,json,pathlib
if not __debug__:raise RuntimeError('optimized_python_refused')
source=pathlib.Path(__file__).with_name('smoke-movement-evidence.py')
namespace={'__file__':str(source)}
exec(compile(source.read_text().split('\nrows=[]',1)[0],str(source),'exec'),namespace)
movement=namespace['movement'];sample=namespace['sample']
fields=['whole_chain_retained_after_drop','movement_context_retained_after_drop','original_provision_context_retained_after_drop']
def live():
 c=sample(0);c['movement_top'].update(continued_original_context=True,**{k:False for k in fields});return c
rows=[]
c=live();proof=movement.validate_movement(c,continuation=True)
assert proof['movement_original_context_continued']is True and proof['final_whole_chain_drop_verified']is False
rows.append(dict(case='continued_live42',result='PASS'))
for name,make,kwargs in [
 ('standalone_rejects_live',live,{}),
 ('continuation_rejects_standalone',lambda:sample(0),dict(continuation=True)),
 ('continuation_rejects_fault',lambda:sample(1),dict(continuation=True)),
 ('boolean_mode_only',live,dict(continuation=1)),
 *[(f'continuation_rejects_prior_drop_{k}',lambda k=k:(lambda c:(c['movement_top'].update(**{k:True}),c)[1])(live()),dict(continuation=True))for k in fields],
 ('continuation_rejects_missing_claim',lambda:(lambda c:(c['movement_top'].pop('continued_original_context'),c)[1])(live()),dict(continuation=True)),
]:
 try:movement.validate_movement(make(),**kwargs)
 except (AssertionError,TypeError,KeyError,ValueError):rows.append(dict(case=name,result='PASS_REFUSED'))
 else:raise AssertionError('invalid_continuation_accepted:'+name)
dependencies=[pathlib.Path(__file__),source,pathlib.Path(__file__).with_name('collect-secret-movement.py'),pathlib.Path(__file__).with_name('collect-secret-provision.py')]
record=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),checks=rows,files=[dict(path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest())for p in dependencies],scope='LOCAL_SYNTHETIC_SCHEMA_ONLY; no native, frozen-prefix, actual Drop, quarantine, producer, cleanup, reuse or release acceptance')
destination=pathlib.Path('target/lab-state')/('movement-continuation-smokes-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.json')
with destination.open('x')as stream:json.dump(record,stream,indent=2);stream.write('\n')
print(json.dumps(dict(record=str(destination),checks=len(rows),native_acceptance=False)))
