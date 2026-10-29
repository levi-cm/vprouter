"""Only local schema validation; no native ACK interleaving is executed."""
import copy,hashlib,json,pathlib
if not __debug__:raise RuntimeError('optimized_python_refused')
p=pathlib.Path('target/collect-secret-attachment.py');s=p.read_text();block=s[s.index('# New frozen fixtures'):s.index("assert writers[0]")]
compiled=compile(block,'exact-collector-new-ack-schema','exec')
def integer(v,minimum=0):assert type(v)is int and v>=minimum;return v
cases=[]
def check(name,w,fault,valid):
 ns=dict(code=b'normal_ack_writer',fault=fault,w=w,writers=w['preparation']['writers'],mount=w['mount'],integer=integer)
 try:exec(compiled,ns);passed=True
 except(AssertionError,KeyError,IndexError):passed=False
 assert passed==valid,(name,passed,valid)
 cases.append(dict(name=name,expected_accept=valid,result='PASS'))
for fault,run in[(0,256),(1,257),(2,258)]:
 w=copy.deepcopy(json.loads(pathlib.Path(f'target/lab-state/secret-attachment-run-{run}.json').read_text())['witness'])
 w.update(normal_ack_ready_preserved=fault!=0,tested_non_target_phase=None if not fault else'attachment_birth'if fault==1 else'attachment_placeholder',normal_ack_writer=None)
 if fault:
  index=10 if fault==1 else 11;old=w['preparation']['writers'][index];w['normal_ack_writer']=dict(index=index,pid=old['pid'],start=old['start'])
 check('matching_'+str(fault),w,fault,True)
 if fault:
  for field,value in[('pid',999999999),('start',999999999),('index',len(w['preparation']['writers'])-1),('index',True)]:
   n=copy.deepcopy(w);n['normal_ack_writer'][field]=value;check('reject_'+str(fault)+'_'+field+'_'+str(value),n,fault,False)
  n=copy.deepcopy(w);n['tested_non_target_phase']='attachment_primary';check('reject_target_phase_'+str(fault),n,fault,False)
  n=copy.deepcopy(w);n['normal_ack_ready_preserved']=False;check('reject_no_ready_'+str(fault),n,fault,False)
 else:
  n=copy.deepcopy(w);n['normal_ack_ready_preserved']=True;check('reject_success_claim',n,fault,False)
x=dict(scope='LOCAL_SCHEMA_SMOKES_ONLY; old native witnesses supplemented with synthetic new fields. No new native interleaving or acceptance.',collector_sha256=hashlib.sha256(p.read_bytes()).hexdigest(),smoke_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),cases=cases)
out=pathlib.Path('target/lab-state/attachment-ack-schema-smokes-20261027-v2.json')
with out.open('x')as f:json.dump(x,f,indent=2);f.write('\n')
print(json.dumps(dict(record=str(out),local_schema_smokes=len(cases),native_acceptance=False)))
