"""Local observer/schema checks; no VM, workload or native acceptance."""
import ast,copy,hashlib,json,os,pathlib,tempfile,time
if not __debug__:raise RuntimeError('optimized_python_refused')
path=pathlib.Path('target/platform-lab/secret-attachment.guest.py');source=path.read_text();tree=ast.parse(source)
fn=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='observation_context'];assert len(fn)==1
namespace=dict(os=os,time=time);exec(compile(ast.Module(body=fn,type_ignores=[]),str(path),'exec'),namespace)
observe=namespace['observation_context'];before,after=observe(),observe()
e=dict(schema=1,before=before,after=after,sampled_during_native_operation=False,whole_vm_only=True)
collector=pathlib.Path('target/collect-secret-attachment.py');s=collector.read_text();block=s[s.index('environment=None'):s.index('ids=[]')];compiled=compile(block,'exact-environment-schema','exec')
def integer(v,minimum=0):assert type(v)is int and v>=minimum;return v
def finite(v):
 import math
 assert type(v)in(int,float)and math.isfinite(v)and v>0
 return v
results=[]
with tempfile.TemporaryDirectory(prefix='attachment-environment-smoke-',dir='target')as d:
 directory=pathlib.Path(d);(directory/'controller-guest.py').write_text(source)
 def check(name,value,valid):
  import re
  ns=dict(directory=directory,environments=[value],arch='amd64',integer=integer,finite=finite,re=re)
  try:exec(compiled,ns);actual=True
  except(AssertionError,KeyError,TypeError):actual=False
  assert actual==valid,(name,actual,valid)
  results.append(dict(name=name,expected_accept=valid,result='PASS'))
 check('bounded_local_observation',copy.deepcopy(e),True)
 n=copy.deepcopy(e);n['before']['files']['io_pressure']={'status':'unavailable','errno':2};check('explicit_metric_unavailable',n,True)
 n=copy.deepcopy(e);n['before']['files']['memory_pressure']={'status':'too_large','text':None};check('explicit_metric_too_large',n,True)
 n=copy.deepcopy(e);n['before']['finished_at']=n['after']['started_at']+1;check('overlapping_or_reversed_samples',n,False)
 n=copy.deepcopy(e);n['after']['files']['boot']['text']='00000000-0000-0000-0000-000000000000\n';check('boot_changed',n,False)
 n=copy.deepcopy(e);n['sampled_during_native_operation']=True;check('sampled_during_operation',n,False)
 n=copy.deepcopy(e);n['before']['operation_cost_attribution']=True;check('cost_attribution_claim',n,False)
 n=copy.deepcopy(e);n['before']['affinity']=[True];check('bool_cpu_number',n,False)
 n=copy.deepcopy(e);n['before']['files']['boot']['text']='-'*36;check('non_uuid_boot',n,False)
 n=copy.deepcopy(e);n['before']['files']['extra']={'status':'bounded','text':''};check('unknown_file',n,False)
 n=copy.deepcopy(e);n['before']['files']['cpu']['text']='x'*4097;check('unbounded_text',n,False)
# Exercise the exact cross-binding block independently of native acceptance.
binding_block=s[s.index('if environment is not None:'):s.index('# New frozen fixtures')]
binding_compiled=compile(binding_block,'exact-environment-owner-binding','exec')
def binding_check(name,owner_boot,requested,verified,valid):
 ns=dict(environment=e,p=dict(canonical_owner_epoch=dict(boot=owner_boot),requested_at=requested),writers=[dict(verified_at=verified)])
 try:exec(binding_compiled,ns);actual=True
 except AssertionError:actual=False
 assert actual==valid,(name,actual,valid)
 results.append(dict(name=name,expected_accept=valid,result='PASS'))
boot=e['before']['files']['boot']['text'].strip()
binding_check('owner_boot_and_clock_bound',boot,before['finished_at'],after['started_at'],True)
binding_check('reject_unrelated_owner_boot','00000000-0000-0000-0000-000000000000',before['finished_at'],after['started_at'],False)
binding_check('reject_operation_before_context',boot,before['finished_at']-1,after['started_at'],False)
binding_check('reject_receipt_after_context',boot,before['finished_at'],after['started_at']+1,False)
x=dict(scope='LOCAL_OBSERVER_AND_SCHEMA_ONLY; no VM, native operation, traffic, cost attribution or acceptance.',guest_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),collector_sha256=hashlib.sha256(collector.read_bytes()).hexdigest(),smoke_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),cases=results)
p=pathlib.Path('target/lab-state/attachment-environment-smokes-20261027-v2.json')
with p.open('x')as f:json.dump(x,f,indent=2);f.write('\n')
print(json.dumps(dict(record=str(p),local_smokes=len(results),native_acceptance=False)))
