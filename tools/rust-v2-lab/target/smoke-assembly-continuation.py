"""Cached standalone checks and synthetic live-assembly prefix; no native action."""
import datetime,hashlib,importlib.util,json,pathlib,sys
if not __debug__:raise RuntimeError('optimized_python_refused')
sys.path.insert(0,str(pathlib.Path(__file__).parent));p=pathlib.Path(__file__).with_name('collect-secret-assembly.py');spec=importlib.util.spec_from_file_location('assembly',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
candidate='target/continuation-20261028T024239Z/candidate.json';root=pathlib.Path(candidate).parent;bindings={}
for path in root.rglob('directory-binding.json'):
 b=json.loads(path.read_text());n=int(pathlib.Path(b['record']).stem.rsplit('-',1)[1])
 if 346<=n<=361:bindings[n]=path.parent.name
assert len(bindings)==16;rows=[]
for n,label in sorted(bindings.items()):m.validate_complete(m.validate_prefix(candidate,label,assembly=True));rows.append(dict(case='cached_standalone_'+str(n),result='PASS_CACHED_VALIDATION'))
drops=['whole_chain_retained_after_drop','assembly_context_retained_after_drop','producer_context_retained_after_drop','quarantine_context_retained_after_drop','movement_context_retained_after_drop','original_provision_context_retained_after_drop']
def fixture(n=346):
 c=m.validate_prefix(candidate,bindings[n],assembly=True);w=c['assembly_top'];w['continued_original_context']=True;w['charges_after_drop']=None
 for key in drops:w[key]=False
 return c
proof=m.validate_complete(fixture(),continuation=True);assert proof['assembly']['assembly_original_context_continued']is True and proof['assembly']['final_whole_chain_drop_verified']is False;rows.append(dict(case='live_assembly_continuation',result='PASS_SYNTHETIC_MUTANT'))
mutations=[('standalone_refuses_live',lambda w:None,False),('missing_continued',lambda w:w.pop('continued_original_context'),True),('false_continued',lambda w:w.update(continued_original_context=False),True),('integer_continued',lambda w:w.update(continued_original_context=1),True),('unperformed_after_drop_sample',lambda w:w.update(charges_after_drop=[0,0]),True),('changed_after_charge',lambda w:w.update(charges_after=[1,0]),True)]
for key in drops:mutations.append((key,lambda w,key=key:w.__setitem__(key,True),True))
for name,change,continuation in mutations:
 c=fixture();change(c['assembly_top'])
 try:m.validate_complete(c,continuation=continuation)
 except(AssertionError,KeyError,TypeError,ValueError):rows.append(dict(case=name,result='PASS_REFUSED'))
 else:raise AssertionError('invalid_live_assembly_accepted:'+name)
for n in(347,348,349):
 try:m.validate_complete(fixture(n),continuation=True)
 except(AssertionError,KeyError,TypeError,ValueError):rows.append(dict(case='fault_cannot_continue_'+str(n),result='PASS_REFUSED'))
 else:raise AssertionError('fault_assembly_continued')
c=m.validate_prefix(candidate,bindings[346],assembly=True);c['assembly_top']['continued_original_context']=False;m.validate_complete(c);rows.append(dict(case='explicit_standalone_false',result='PASS_CACHED_VALIDATION'))
files=[pathlib.Path(__file__),p,pathlib.Path(__file__).with_name('assembly_evidence_schema.py'),m.mechanics_path]
out=pathlib.Path('target/lab-state')/('assembly-continuation-smokes-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.json')
with out.open('x')as f:json.dump(dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),checks=rows,files=[dict(path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest())for p in files],native_acceptance=False,scope='16 cached standalone revalidations plus synthetic live assembly continuation; null post-Drop sample when no Drop occurred; no raw rewriting, new native case, canonical group binding, current policy or resource authority'),f,indent=2)
print(json.dumps(dict(record=str(out),checks=len(rows),native_acceptance=False)))
