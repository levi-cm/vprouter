"""Exact failed attachment fixture inspection; public metadata, no signals/unmount."""
import hashlib,json,pathlib,re,subprocess,sys
if not __debug__:raise RuntimeError('optimized_python_refused')
run=int(sys.argv[1]);binding=json.loads(pathlib.Path(sys.argv[2]).read_text());path=pathlib.Path(f'target/lab-state/actual-program-run-{run}.json');raw=path.read_bytes();record=json.loads(raw)
assert record['exit_code']!=0 and record['component_test_mode'] in ('secret_producer_binding_success','secret_producer_binding_postbirth_failure','secret_producer_binding_result_failure','secret_producer_binding_registration_failure')and binding['record']==str(path)and binding['source_commit']==record['source_binding']['source_commit']and binding['platform']==record['platform']
assert binding['source_archive_sha256']==record['source_archive_sha256']and binding['artifact_sha256']==record['artifact_sha256']
directory=pathlib.Path(sys.argv[2]).parent
for key,name in [('runner_sha256','controller-runner.py'),('guest_sha256','controller-guest.py'),('context_checker_sha256','controller-context.py'),('host_declaration_builder_sha256','controller-host-declaration.py')]:assert hashlib.sha256((directory/name).read_bytes()).hexdigest()==record[key]
rows=[]
for line in record['stdout'].splitlines():
 try:rows.append(json.loads(line))
 except ValueError:pass
inputs=[r['secret_attachment_input']for r in rows if'secret_attachment_input'in r];assert len(inputs)==1;manifest=inputs[0];nonce=manifest['nonce'];assert re.fullmatch('[a-f0-9]{64}',nonce)
owners=[r['owner_probe']for r in rows if'owner_probe'in r];descriptors=[r['secret_attachment_descriptor']for r in rows if'secret_attachment_descriptor'in r];gateways=[r['secret_attachment_gateway']for r in rows if'secret_attachment_gateway'in r]
assert len(owners)<=1 and len(descriptors)<=1 and len(gateways)<=1
hosts=[r['secret_quarantine_host']for r in rows if'secret_quarantine_host'in r];assert len(hosts)==1
unit=owners[0]['unit']if owners else descriptors[0]['owner_unit']if descriptors else None
if unit:assert re.fullmatch('vprouter-v2-owner@[a-f0-9]{64}[.]service',unit)
port,known={'debian-clean-x86_64':(22036,'target/platform-lab/debian-clean-x86_64/known_hosts'),'debian-x86_64':(22032,'target/lab-state/known_hosts'),'debian-arm64':(22034,'target/platform-lab/debian-arm64/known_hosts'),'arch-x86_64':(22033,'target/platform-lab/arch-x86_64/known_hosts')}[record['platform']]
script=r'''import os,pathlib,stat,json,hashlib,subprocess,time
if not __debug__:raise RuntimeError('optimized_python_refused')
assert os.geteuid()==0
root=pathlib.Path('/var/lib/vprouter-v2-lab');inputs=root/('secret-inputs-'+NONCE)
def read(path):
 s=path.lstat();assert stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and s.st_size<=1024*1024;return path.read_bytes()
out={'observed_boottime':time.clock_gettime(7),'nonce':NONCE,'fixed_selectors':{},'profiles':[],'canonical':{}}
for name in ['owner-domain-nonce','secret-attachment.json','secret-attachment-spec.json','secret-attachment-staging.json','secret-quarantine-host.json','task8b2-image','task8b2-host-acceptance']:
 p=root/name
 if p.exists():
  data=read(p);s=p.stat();out['fixed_selectors'][name]={'device':s.st_dev,'inode':s.st_ino,'sha256':hashlib.sha256(data).hexdigest(),'size':s.st_size,'public_content':data.decode()if name=='owner-domain-nonce'else json.loads(data)}
assert out['fixed_selectors']['owner-domain-nonce']['public_content']==NONCE
assert out['fixed_selectors']['secret-attachment.json']['sha256']==MANIFEST['configuration_sha256']
assert out['fixed_selectors']['secret-quarantine-host.json']['sha256']==HOST['sha256']and out['fixed_selectors']['secret-quarantine-host.json']['public_content']==HOST['declaration']
for expected in MANIFEST['profiles']:
 p=pathlib.Path(expected['path']);s=p.lstat();out['profiles'].append(dict(path=str(p),device=s.st_dev,inode=s.st_ino,size=s.st_size,mode=stat.S_IMODE(s.st_mode),uid=s.st_uid,gid=s.st_gid,links=s.st_nlink))
base=root/('owner-secret-'+NONCE);out['canonical_root_exists']=base.exists()
for name in ['allocations.json','namespaces.json']:
 p=base/name
 if p.exists():out['canonical'][name]=json.loads(read(p))
if UNIT is not None:
 r=subprocess.run(['systemctl','show',UNIT,'--property=LoadState,ActiveState,SubState,MainPID,ControlGroup,InvocationID','--no-pager'],capture_output=True,text=True,check=True,timeout=5);out['owner_unit']=dict(line.split('=',1)for line in r.stdout.splitlines())
 group=pathlib.Path('/sys/fs/cgroup/system.slice')/UNIT;out['owner_cgroup_exists']=group.exists()
 if group.exists():out['owner_cgroup_identity']=[group.stat().st_dev,group.stat().st_ino];out['owner_cgroup_procs']=(group/'cgroup.procs').read_text()
if GATEWAY:
 r=subprocess.run(['docker','inspect','--format','{{json .State}}',GATEWAY['container_id']],capture_output=True,text=True,timeout=8);out['gateway_inspect_exit']=r.returncode
 if r.returncode==0:out['gateway_state']=json.loads(r.stdout)
print(json.dumps(out))
'''.replace('NONCE',repr(nonce)).replace('MANIFEST',repr(manifest)).replace('HOST',repr(hosts[0])).replace('UNIT',repr(unit)).replace('GATEWAY',repr(gateways[0]if gateways else None))
r=subprocess.run(['ssh','-i','target/lab-state/id_ed25519','-p'+str(port),'-o','UserKnownHostsFile='+known,'-o','StrictHostKeyChecking=yes','vprouterlab@127.0.0.1','sudo -n python3 -I -'],input=script,capture_output=True,text=True,timeout=30);assert r.returncode==0,r.stderr
out=json.loads(r.stdout);out.update(record=str(path),record_sha256=hashlib.sha256(raw).hexdigest(),source_binding=record['source_binding'],artifact_sha256=record['artifact_sha256'],platform=record['platform'],expected_owner_unit=unit,read_only=True,private_profile_contents_read=False,signals_unmount_or_cleanup=False)
destination=pathlib.Path(f'target/lab-state/secret-producer-binding-failure-run-{run}.json')
with destination.open('x')as stream:json.dump(out,stream,indent=2);stream.write('\n')
print(json.dumps(dict(record=str(destination),owner_unit=out.get('owner_unit'),owner_cgroup_exists=out.get('owner_cgroup_exists'),canonical_files=list(out['canonical']),private_profile_contents_read=False)))
