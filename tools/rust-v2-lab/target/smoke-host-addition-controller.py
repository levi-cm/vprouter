"""Pure controller regressions; no native fixture or VM mutation."""
import ast,datetime,hashlib,json,pathlib,runpy,subprocess,sys
if not __debug__:raise RuntimeError('optimized_python_refused')
root=pathlib.Path('target/platform-lab')
paths=[root/name for name in ('run-frozen-secret-host-addition.py','secret-host-addition.guest.py','attachment_context_check.py','quarantine_host_declaration.py','host_baseline_declaration.py')]
raw={str(p):p.read_bytes()for p in paths}
guest=ast.parse(raw[str(paths[1])]);function=next(n for n in guest.body if isinstance(n,ast.FunctionDef)and n.name=='stable_neighbors')
ns={'json':json};exec(compile(ast.Module(body=[function],type_ignores=[]),'captured-neighbor-projection','exec'),ns);project=ns['stable_neighbors']
checks=[]
base={'dst':'192.0.2.1','dev':'eth0','lladdr':'02:00:00:00:00:01','router':None,'proxy':True}
def row(state,**extra):return dict(base,state=state,**extra)
def check(name,condition):assert condition,name;checks.append(name)
check('dynamic_nud_aging_equal',project([row(['REACHABLE'],used=1)])==project([row(['STALE'],used=9,probes=2)]))
for state in ('PERMANENT','NOARP'):
 check(state+'_to_dynamic_detected',project([row([state])])!=project([row(['REACHABLE'])]))
 check(state+'_to_absent_detected',project([row([state])])!=project([base]))
 check(state+'_list_string_normalized',project([row([state])])==project([row(state)]))
check('permanent_to_noarp_detected',project([row(['PERMANENT'])])!=project([row(['NOARP'])]))
check('static_state_set_normalized',project([row(['NOARP','PERMANENT','NOARP'])])==project([row('PERMANENT,NOARP')]))
for field,value in (('dst','192.0.2.2'),('dev','eth1'),('lladdr','02:00:00:00:00:02'),('router',False),('proxy',False)):
 altered=dict(base);altered[field]=value;check('preserves_'+field,project([base])!=project([altered]))
check('entry_removal_detected',project([base])!=project([]))
try:project([row(123)])
except AssertionError:checks.append('invalid_state_refused')
else:raise AssertionError('invalid_state_accepted')
# Closed source guards plus pre-interface refusal: intercept before any process.
runner=paths[0];saved_argv=sys.argv;saved_run,saved_check=subprocess.run,subprocess.check_output
calls=[]
def refuse(*a,**k):calls.append(a);raise AssertionError('unexpected_subprocess')
label='must-not-create-host-controller-smoke'
old=pathlib.Path('target/continuation-20261028T044917Z/candidate.json')
assert not(old.parent/label).exists()
try:
 subprocess.run=subprocess.check_output=refuse;sys.argv=[str(runner),str(old),'debian-clean-x86_64',label,'success']
 try:runpy.run_path(str(runner),run_name='__main__')
 except AssertionError as error:assert str(error)=='frozen_source_missing_secret_host_addition_interface'
 else:raise AssertionError('old_interface_accepted')
finally:sys.argv=saved_argv;subprocess.run,subprocess.check_output=saved_run,saved_check
check('old_source_refused_before_subprocess',not calls and not(old.parent/label).exists())
for path in paths[:2]:
 result=subprocess.run([sys.executable,'-O',str(path)],capture_output=True,text=True)
 check(path.name+'_optimized_refused',result.returncode!=0 and 'optimized_python_refused'in result.stderr)
# Ensure snapshots describe this exact tested byte set.
assert all(pathlib.Path(p).read_bytes()==data for p,data in raw.items())
out=pathlib.Path('target/lab-state')/('host-addition-controller-smokes-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')+'.json')
with out.open('x')as stream:json.dump(dict(result='PASS',checks=checks,files={p:hashlib.sha256(data).hexdigest()for p,data in raw.items()},native_acceptance=False,vm_mutation=False),stream,indent=2);stream.write('\n')
print(json.dumps(dict(record=str(out),checks=len(checks),result='PASS',native_acceptance=False)))
