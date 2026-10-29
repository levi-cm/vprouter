"""Exact failed standalone fixture inspection; public metadata only, no signals."""
import hashlib,json,pathlib,re,subprocess,sys
if not __debug__: raise RuntimeError('optimized_python_refused')
run=int(sys.argv[1]);binding=json.loads(pathlib.Path(sys.argv[2]).read_text());p=pathlib.Path(f'target/lab-state/actual-program-run-{run}.json');raw=p.read_bytes();record=json.loads(raw)
assert record['exit_code']!=0 and record['component_test_mode'].startswith('secret_preparation_') and binding['record']==str(p) and binding['source_commit']==record['source_binding']['source_commit']
inputs=[];probes=[]
for line in record['stdout'].splitlines():
 try:v=json.loads(line)
 except ValueError:continue
 if 'secret_preparation_input'in v:inputs.append(v['secret_preparation_input'])
 if 'owner_probe'in v:probes.append(v['owner_probe'])
assert len(inputs)==1 and len(probes)<=1;manifest=inputs[0];nonce=manifest['nonce'];assert re.fullmatch('[a-f0-9]{64}',nonce)
unit=probes[0]['unit'] if probes else None
if unit:assert re.fullmatch('vprouter-v2-owner@[a-f0-9]{64}[.]service',unit)
port,known={'debian-clean-x86_64':(22036,'target/platform-lab/debian-clean-x86_64/known_hosts'),'debian-x86_64':(22032,'target/lab-state/known_hosts'),'debian-arm64':(22034,'target/platform-lab/debian-arm64/known_hosts'),'arch-x86_64':(22033,'target/platform-lab/arch-x86_64/known_hosts')}[binding['platform']]
s=r'''import os,pathlib,stat,json,hashlib,subprocess,time
assert os.geteuid()==0
root=pathlib.Path('/var/lib/vprouter-v2-lab')
def read(path):
 st=path.lstat();assert stat.S_ISREG(st.st_mode) and st.st_uid==st.st_gid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and st.st_size<=1024*1024;return path.read_bytes()
assert read(root/'owner-domain-nonce').decode()==NONCE
public=read(root/'secret-preparation.json');assert hashlib.sha256(public).hexdigest()==MANIFEST['configuration_sha256']
out={'observed_boottime':time.clock_gettime(7),'nonce':NONCE,'configuration':json.loads(public),'configuration_sha256':hashlib.sha256(public).hexdigest(),'profiles':[]}
for expected in MANIFEST['profiles']:
 p=pathlib.Path(expected['path']);st=p.lstat();out['profiles'].append({'path':str(p),'device':st.st_dev,'inode':st.st_ino,'size':st.st_size,'uid':st.st_uid,'gid':st.st_gid,'mode':stat.S_IMODE(st.st_mode),'links':st.st_nlink})
base=root/('owner-secret-'+NONCE);out['owner_directory_exists']=base.exists()
if base.exists():
 out['journal_files']={}
 for name in ('allocations.json','namespaces.json'):
  path=base/name
  if path.exists():out['journal_files'][name]=json.loads(read(path))
if UNIT is not None:
 r=subprocess.run(['systemctl','show',UNIT,'--property=LoadState,ActiveState,SubState,MainPID,ControlGroup,InvocationID','--no-pager'],capture_output=True,text=True,check=True,timeout=5)
 out['owner_unit']=dict(line.split('=',1) for line in r.stdout.splitlines())
 group=pathlib.Path('/sys/fs/cgroup/system.slice')/UNIT;out['owner_cgroup_exists']=group.exists()
 if group.exists():out['owner_cgroup_inode']=group.stat().st_ino;out['owner_cgroup_procs']=(group/'cgroup.procs').read_text()
print(json.dumps(out))
'''.replace('NONCE',repr(nonce)).replace('MANIFEST',repr(manifest)).replace('UNIT',repr(unit))
r=subprocess.run(['ssh','-i','target/lab-state/id_ed25519','-p'+str(port),'-o','UserKnownHostsFile='+known,'-o','StrictHostKeyChecking=yes','vprouterlab@127.0.0.1','sudo -n python3 -I -'],input=s,capture_output=True,text=True,timeout=30);assert r.returncode==0,r.stderr
x=json.loads(r.stdout);x.update(record=str(p),record_sha256=hashlib.sha256(raw).hexdigest(),source_binding=record['source_binding'],artifact_sha256=record['artifact_sha256'],platform=binding['platform'],read_only=True,private_profile_contents_read=False)
out=pathlib.Path(f'target/lab-state/secret-preparation-failure-run-{run}.json')
with out.open('x') as f:json.dump(x,f,indent=2);f.write('\n')
print(json.dumps(dict(record=str(out),owner_unit=x.get('owner_unit'),owner_cgroup_exists=x.get('owner_cgroup_exists'),journal_files=list(x.get('journal_files',{})),private_profile_contents_read=False)))
