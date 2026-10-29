"""Local live69 continuation checks against cached evidence; no native action."""
import copy,datetime,hashlib,importlib.util,json,pathlib,sys
if not __debug__:raise RuntimeError('optimized_python_refused')
sys.path.insert(0,str(pathlib.Path(__file__).parent));p=pathlib.Path(__file__).with_name('collect-secret-quarantine.py');spec=importlib.util.spec_from_file_location('quarantine',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
candidate='target/continuation-20261028T014707Z/candidate.json';root=pathlib.Path(candidate).parent
bindings=[]
for bp in root.rglob('directory-binding.json'):
 d=json.loads(bp.read_text());n=int(pathlib.Path(d['record']).stem.rsplit('-',1)[1])
 if 328<=n<=343:bindings.append((n,bp.parent.name))
assert len(bindings)==16
rows=[]
for n,label in sorted(bindings):
 c=m.validate_prefix(candidate,label);m.validate_quarantine(c);rows.append(dict(case='cached_standalone_'+str(n),result='PASS_CACHED_VALIDATION'))
success=next(label for n,label in bindings if n==328)
def fixture(fault=False):
 label=next(label for n,label in bindings if n==341)if fault else success
 c=m.validate_prefix(candidate,label);w=c['quarantine_top'];w['continued_original_context']=True
 for key in['whole_chain_retained_after_drop','quarantine_context_retained_after_drop','producer_context_retained_after_drop','movement_context_retained_after_drop','original_provision_context_retained_after_drop']:w[key]=False
 return c
c=fixture();proof=m.validate_quarantine(c,continuation=True);assert proof['producer']['quarantine_original_context_continued']is True and proof['producer']['final_whole_chain_drop_verified']is False;rows.append(dict(case='live69_continuation',result='PASS_SYNTHETIC_MUTANT'))
mutations=[('default_refuses_continuation',lambda c:None,False),('missing_continuation',lambda c:c['quarantine_top'].pop('continued_original_context'),True),('false_continuation',lambda c:c['quarantine_top'].update(continued_original_context=False),True),('bool_continuation',lambda c:c['quarantine_top'].update(continued_original_context=1),True)]
for key in['whole_chain_retained_after_drop','quarantine_context_retained_after_drop','producer_context_retained_after_drop','movement_context_retained_after_drop','original_provision_context_retained_after_drop']:mutations.append((key,lambda c,key=key:c['quarantine_top'].__setitem__(key,True),True))
for name,change,continuation in mutations:
 c=fixture();change(c)
 try:m.validate_quarantine(c,continuation=continuation)
 except(AssertionError,KeyError,ValueError,TypeError):rows.append(dict(case=name,result='PASS_REFUSED'))
 else:raise AssertionError('invalid_continuation_accepted:'+name)
try:m.validate_quarantine(fixture(True),continuation=True)
except(AssertionError,KeyError,ValueError,TypeError):rows.append(dict(case='failed69_cannot_continue',result='PASS_REFUSED'))
else:raise AssertionError('failed69_continued')
from quarantine_evidence_base import validate_assembly_prefix
for fault in range(4):
 value={'schema':1,'fault':fault,'quarantine':{'schema':1,'fault':0}}
 assert validate_assembly_prefix(value,fault)==value['quarantine'];rows.append(dict(case='assembly_prefix_fault_'+str(fault),result='PASS_SYNTHETIC_PREFIX'))
for name,change in [('outer_schema_bool',lambda v:v.update(schema=True)),('outer_fault_bool',lambda v:v.update(fault=False)),('nested_schema_bool',lambda v:v['quarantine'].update(schema=True)),('nested_fault_bool',lambda v:v['quarantine'].update(fault=False)),('nested_fault_nonzero',lambda v:v['quarantine'].update(fault=1)),('nested_schema_wrong',lambda v:v['quarantine'].update(schema=2))]:
 value={'schema':1,'fault':0,'quarantine':{'schema':1,'fault':0}};change(value)
 try:validate_assembly_prefix(value,0)
 except(AssertionError,KeyError,ValueError,TypeError):rows.append(dict(case=name,result='PASS_REFUSED'))
 else:raise AssertionError('invalid_assembly_prefix_accepted:'+name)
try:validate_assembly_prefix({'schema':1,'fault':0,'quarantine':{'schema':1,'fault':0}},False)
except(AssertionError,KeyError,ValueError,TypeError):rows.append(dict(case='expected_fault_bool',result='PASS_REFUSED'))
else:raise AssertionError('boolean_expected_fault_accepted')
files=[pathlib.Path(__file__),p,pathlib.Path(__file__).with_name('quarantine_evidence_base.py'),pathlib.Path(__file__).with_name('quarantine_producer_schema.py')]
out=pathlib.Path('target/lab-state')/('quarantine-continuation-smokes-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.json')
with out.open('x')as f:json.dump(dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),checks=rows,files=[dict(path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest())for p in files],native_acceptance=False,scope='16 cached standalone revalidations and synthetic live69 continuation mutations only; no raw record rewriting, new native case, ACK/reap or custody transfer proof'),f,indent=2)
print(json.dumps(dict(record=str(out),checks=len(rows),native_acceptance=False)))
