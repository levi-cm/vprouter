"""Fixed failed-read protocol mutants; no native/VM actions or authority."""
import ast,copy,datetime,hashlib,json,pathlib,re
if not __debug__:raise RuntimeError('optimized_python_refused')
p=pathlib.Path('target/platform-lab/run-frozen-host-projection.py');raw=p.read_bytes();ns={'json':json,'re':re};tree=ast.parse(raw);exec(compile(ast.Module(body=[n for n in tree.body if isinstance(n,ast.FunctionDef)],type_ignores=[]),str(p),'exec'),ns)
validate=ns['validate_projection_failure'];success=ns['validate_projection_envelope']
def witness():return dict(schema=1,creator_pid=123,creator_start=345,requested_at=100.0,deadline=102.0,stage='poll_read',polls=14,reason='UnsupportedLinkAttribute(99)')
def envelope(w=None):return dict(uid=1000,machine='x86_64',root_pid=123,root_start=345,root_reaped=True,exit_code=1,timed_out=False,before=99.9,after=100.2,retained_executable='/tmp/synthetic/payload',stdout='',stderr='LAB_HOST_ROUTE_PROJECTION_FAILURE '+json.dumps(w or witness())+'\nhost_route_projection: network_operation\n')
rows=[]
for stage in ('open','start_read','poll_read'):
 w=witness();w.update(stage=stage,polls=1 if stage=='poll_read'else 0);validate(envelope(w),'x86_64');rows.append(stage+'_fixed_failure')
for reason in ('Oversized','Malformed','UnsupportedRouteAttribute(65535)','KernelErrno(-2147483648)','KernelErrno(2147483647)'):
 w=witness();w['reason']=reason;validate(envelope(w),'x86_64');rows.append(reason+'_fixed_reason')
w=witness();w['reason']='Deadline';v=envelope(w);v['after']=102.1;validate(v,'x86_64');rows.append('deadline_refusal_after_original_end')
mutants=[]
for key,value in [('uid',False),('uid',0),('root_pid',True),('root_pid',2**32),('root_start',False),('root_start',2**64),('machine','aarch64'),('root_reaped',False),('exit_code',True),('exit_code',0),('exit_code',-11),('timed_out',True),('stdout','{}'),('before',True),('before',101),('after',99),('after',float('inf')),('retained_executable',None),('stderr','host_route_projection: network_operation\n')]:mutants.append((False,key,value))
for key,value in [('schema',True),('schema',2),('creator_pid',True),('creator_pid',124),('creator_start',345.0),('creator_start',346),('requested_at',True),('requested_at',99),('deadline',103),('deadline',float('nan')),('stage','observe'),('stage','open'),('polls',False),('polls',0),('polls',2**32),('reason','arbitrary external body'),('reason','UnsupportedLinkAttribute(-1)'),('reason','UnsupportedLinkAttribute(65536)'),('reason','KernelErrno(2147483648)'),('reason','KernelErrno(-2147483649)'),('reason','Deadline'),('unknown',False)]:mutants.append((True,key,value))
for i,(inside,key,value)in enumerate(mutants):
 if inside:w=witness();w[key]=value;v=envelope(w)
 else:v=envelope();v[key]=value
 try:validate(v,'x86_64')
 except(AssertionError,ValueError,KeyError,TypeError):rows.append('mutant_'+str(i)+'_'+key)
 else:raise AssertionError(('accepted_failure_mutant',i,key))
for name,stderr in [('duplicate_key',envelope()['stderr'].replace('"schema": 1','"schema": 1, "schema": 1')),('extra_line',envelope()['stderr']+'extra\n'),('duplicate_marker',envelope()['stderr']+envelope()['stderr'])]:
 v=envelope();v['stderr']=stderr
 try:validate(v,'x86_64')
 except(AssertionError,ValueError):rows.append(name)
 else:raise AssertionError(name)
try:success(envelope(),'x86_64')
except AssertionError:rows.append('failure_never_accepted_as_projection')
else:raise AssertionError('failure_was_projection')
assert p.read_bytes()==raw
out=pathlib.Path('target/lab-state')/('host-projection-failure-smokes-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')+'.json')
with out.open('x')as f:json.dump(dict(result='PASS',checks=rows,controller_sha256=hashlib.sha256(raw).hexdigest(),self_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),native_actions=False,host_authority_granted=False),f,indent=2);f.write('\n')
print(json.dumps(dict(record=str(out),checks=len(rows),result='PASS',native_actions=False)))
