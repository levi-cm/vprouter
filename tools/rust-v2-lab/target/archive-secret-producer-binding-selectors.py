"""Archive only exact fixed public selectors after original fixture unit absence."""
import hashlib,json,pathlib,re,subprocess,sys
if not __debug__:raise RuntimeError('optimized_python_refused')
run=int(sys.argv[1]);binding=json.loads(pathlib.Path(sys.argv[2]).read_text());path=pathlib.Path(f'target/lab-state/actual-program-run-{run}.json');raw=path.read_bytes();record=json.loads(raw);reference=json.loads(pathlib.Path(f'target/lab-state/secret-producer-binding-failure-run-{run}.json').read_text())
assert record['exit_code']!=0 and record['component_test_mode'] in ('secret_producer_binding_success','secret_producer_binding_postbirth_failure','secret_producer_binding_result_failure','secret_producer_binding_registration_failure')and reference['record_sha256']==hashlib.sha256(raw).hexdigest()and reference['source_binding']==record['source_binding']and reference['platform']==binding['platform']==record['platform']
assert binding['record']==str(path)and binding['source_commit']==record['source_binding']['source_commit']and binding['source_archive_sha256']==record['source_archive_sha256']and binding['artifact_sha256']==record['artifact_sha256']
assert reference['owner_unit']['LoadState']=='not-found'and reference['owner_cgroup_exists']is False
rows=[]
for line in record['stdout'].splitlines():
 try:rows.append(json.loads(line))
 except ValueError:pass
gateways=[v['secret_attachment_gateway']for v in rows if'secret_attachment_gateway'in v];assert len(gateways)==1
gateway=gateways[0]
nonce=reference['nonce'];unit=reference['expected_owner_unit'];assert re.fullmatch('[a-f0-9]{64}',nonce)and re.fullmatch('vprouter-v2-owner@[a-f0-9]{64}[.]service',unit)
port,known={'debian-clean-x86_64':(22036,'target/platform-lab/debian-clean-x86_64/known_hosts'),'debian-x86_64':(22032,'target/lab-state/known_hosts'),'debian-arm64':(22034,'target/platform-lab/debian-arm64/known_hosts'),'arch-x86_64':(22033,'target/platform-lab/arch-x86_64/known_hosts')}[record['platform']]
script=r'''import os,pathlib,stat,json,hashlib,subprocess
if not __debug__:raise RuntimeError('optimized_python_refused')
assert os.geteuid()==0
root=pathlib.Path('/var/lib/vprouter-v2-lab');inputs=root/('secret-inputs-'+NONCE);s=inputs.lstat();assert stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700
r=subprocess.run(['systemctl','show',UNIT,'--property=LoadState','--value'],capture_output=True,text=True,check=True,timeout=5);assert r.stdout.strip()=='not-found'and not(pathlib.Path('/sys/fs/cgroup/system.slice')/UNIT).exists()
import select
expected=GATEWAY
r=subprocess.run(['docker','inspect','--format','{{json .State}}',expected['container_id']],capture_output=True,text=True,check=True,timeout=8);state=json.loads(r.stdout)
assert state['Running']is True and state['Pid']==expected['pid']and state['StartedAt']==expected['started_at']
pin=os.pidfd_open(expected['pid'],0);assert not select.select([pin],[],[],0)[0]
raw=pathlib.Path('/proc',str(expected['pid']),'stat').read_text();assert int(raw[raw.rfind(')')+2:].split()[19])==expected['start']
ns=pathlib.Path('/proc',str(expected['pid']),'ns/net').stat();assert[ns.st_dev,ns.st_ino]==expected['source_namespace']and not select.select([pin],[],[],0)[0]
os.close(pin)

outputs=[]
for name,expected in SELECTORS.items():
 assert name in ['owner-domain-nonce','secret-attachment.json','secret-attachment-spec.json','secret-attachment-staging.json','secret-quarantine-host.json','task8b2-image','task8b2-host-acceptance']
 source=root/name;s=source.lstat();assert stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and(s.st_dev,s.st_ino)==(expected['device'],expected['inode'])and s.st_size==expected['size']and hashlib.sha256(source.read_bytes()).hexdigest()==expected['sha256']
 destination=inputs/(str(RUN)+'-failed-'+name);assert not destination.exists();os.link(source,destination,follow_symlinks=False);source.unlink();outputs.append(str(destination))
for directory in(root,inputs):
 fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
print(json.dumps(dict(failed_run=RUN,exact_owner_unit_verified_absent=UNIT,selectors_archived=outputs,container_state_profiles_canonical_and_mounts_retained=True,private_profile_contents_read=False,signals_or_unmounts=False)))
'''.replace('NONCE',repr(nonce)).replace('UNIT',repr(unit)).replace('SELECTORS',repr(reference['fixed_selectors'])).replace('RUN',str(run)).replace('GATEWAY',repr(gateway))
r=subprocess.run(['ssh','-i','target/lab-state/id_ed25519','-p'+str(port),'-o','UserKnownHostsFile='+known,'-o','StrictHostKeyChecking=yes','vprouterlab@127.0.0.1','sudo -n python3 -I -'],input=script,capture_output=True,text=True,timeout=30);assert r.returncode==0,r.stderr
out=json.loads(r.stdout);out.update(record=str(path),record_sha256=hashlib.sha256(raw).hexdigest(),source_binding=record['source_binding'],platform=record['platform']);destination=pathlib.Path(f'target/lab-state/secret-producer-binding-selector-archive-run-{run}.json')
with destination.open('x')as stream:json.dump(out,stream,indent=2);stream.write('\n')
print(json.dumps(out))
