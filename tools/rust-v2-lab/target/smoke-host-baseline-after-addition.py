"""Pure known-mutation reconciliation checks; no authority or native work."""
import ast,copy,datetime,hashlib,json,pathlib
if not __debug__:raise RuntimeError('optimized_python_refused')
p=pathlib.Path('target/author-host-baseline-after-addition.py');raw=p.read_bytes();ns={'json':json,'copy':copy};tree=ast.parse(raw);names={'canonical','stable','append_original'};exec(compile(ast.Module(body=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in names],type_ignores=[]),str(p),'exec'),ns);apply=ns['append_original']
prior=dict(namespace=[4,77],links=[dict(index=1,name='lo',kind='loopback',up=True)],addresses=[dict(index=1,address='127.0.0.1')],routes=[dict(output=1)],rules=[dict(priority=0)])
added=dict(index=1000001,name='vhlab',kind='veth',up=False,alias='prior-original')
observed=copy.deepcopy(prior);observed['links'].append(copy.deepcopy(added));rows=[]
assert apply(prior,added,observed)==observed;rows.append('exact_original_addition')
reverse=copy.deepcopy(observed);reverse['links'].reverse();assert apply(prior,added,reverse)==reverse;rows.append('equal_values_order_only')
assert len(prior['links'])==1 and added['index']==1000001;rows.append('inputs_not_modified')
mutants=[]
for category in ('links','addresses','routes','rules'):
 value=copy.deepcopy(observed);value[category].append(dict(unknown=True));mutants.append((category+'_unknown',prior,added,value))
 value=copy.deepcopy(observed);value[category][0]['unexpected']=True;mutants.append((category+'_field_changed',prior,added,value))
value=copy.deepcopy(observed);value['namespace']=[4,78];mutants.append(('namespace_changed',prior,added,value))
value=copy.deepcopy(observed);value['links']=value['links'][:1];mutants.append(('original_addition_missing',prior,added,value))
for key,value in [('index',1),('name','lo'),('up',True),('up',0),('kind','bridge')]:
 a=copy.deepcopy(added);a[key]=value;v=copy.deepcopy(prior);v['links'].append(a);mutants.append(('bad_original_'+key+'_'+str(value),prior,a,v))
for name,b,a,v in mutants:
 try:apply(b,a,v)
 except(AssertionError,KeyError,ValueError,TypeError):rows.append(name)
 else:raise AssertionError(name)
assert p.read_bytes()==raw
out=pathlib.Path('target/lab-state')/('host-baseline-after-addition-smokes-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')+'.json')
with out.open('x')as f:json.dump(dict(result='PASS',checks=rows,helper_sha256=hashlib.sha256(raw).hexdigest(),native_actions=False,host_authority_granted=False),f,indent=2);f.write('\n')
print(json.dumps(dict(record=str(out),checks=len(rows),result='PASS',native_actions=False)))
