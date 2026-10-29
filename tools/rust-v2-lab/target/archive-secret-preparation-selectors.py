"""Archive only exact fixed selectors after failed fixture owner/native exit."""
import hashlib,json,pathlib,re,subprocess,sys
if not __debug__: raise RuntimeError('optimized_python_refused')
run=int(sys.argv[1]);b=json.loads(pathlib.Path(sys.argv[2]).read_text());p=pathlib.Path(f'target/lab-state/actual-program-run-{run}.json');raw=p.read_bytes();record=json.loads(raw);assert record['exit_code']!=0 and record['component_test_mode'].startswith('secret_preparation_')
reference=json.loads(pathlib.Path(f'target/lab-state/secret-preparation-failure-run-{run}.json').read_text());assert reference['record_sha256']==hashlib.sha256(raw).hexdigest() and reference['source_binding']==record['source_binding'] and reference['platform']==b['platform']
assert reference['owner_unit']['LoadState']=='not-found' and reference['owner_cgroup_exists'] is False
nonce=reference['nonce'];assert re.fullmatch('[a-f0-9]{64}',nonce)
probes=[]
for line in record['stdout'].splitlines():
 try:v=json.loads(line)
 except ValueError:continue
 if 'owner_probe'in v:probes.append(v['owner_probe'])
assert len(probes)==1 and probes[0]['nonce']==nonce;unit=probes[0]['unit'];assert re.fullmatch('vprouter-v2-owner@[a-f0-9]{64}[.]service',unit)
port,known={'debian-clean-x86_64':(22036,'target/platform-lab/debian-clean-x86_64/known_hosts'),'debian-x86_64':(22032,'target/lab-state/known_hosts'),'debian-arm64':(22034,'target/platform-lab/debian-arm64/known_hosts'),'arch-x86_64':(22033,'target/platform-lab/arch-x86_64/known_hosts')}[b['platform']]
s=r'''import pathlib,os,stat,json,hashlib,subprocess
assert os.geteuid()==0
root=pathlib.Path('/var/lib/vprouter-v2-lab');destination=root/('secret-inputs-'+NONCE)
s=destination.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700
r=subprocess.run(['systemctl','show',UNIT,'--property=LoadState','--value'],capture_output=True,text=True,check=True,timeout=5);assert r.stdout.strip()=='not-found'
assert not (pathlib.Path('/sys/fs/cgroup/system.slice')/UNIT).exists()
def check(path):
 s=path.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and s.st_size<=1024*1024
nonce=root/'owner-domain-nonce';configuration=root/'secret-preparation.json';check(nonce);check(configuration)
assert nonce.read_text()==NONCE and hashlib.sha256(configuration.read_bytes()).hexdigest()==CONFIG_SHA
outputs=[]
for source,label in ((nonce,'failed-nonce'),(configuration,'failed-configuration.json')):
 target=destination/(str(RUN)+'-'+label);assert not target.exists();os.link(source,target,follow_symlinks=False);source.unlink();check(target);outputs.append(str(target))
for directory in (root,destination):
 fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
print(json.dumps(dict(failed_run=RUN,exact_owner_unit_verified_absent=UNIT,selectors_archived=outputs,profile_journal_and_other_resources_retained=True,private_profile_contents_read=False)))
'''.replace('NONCE',repr(nonce)).replace('UNIT',repr(unit)).replace('CONFIG_SHA',repr(reference['configuration_sha256'])).replace('RUN',str(run))
r=subprocess.run(['ssh','-i','target/lab-state/id_ed25519','-p'+str(port),'-o','UserKnownHostsFile='+known,'-o','StrictHostKeyChecking=yes','vprouterlab@127.0.0.1','sudo -n python3 -I -'],input=s,capture_output=True,text=True,timeout=25);assert r.returncode==0,r.stderr
out=json.loads(r.stdout);out.update(source_binding=record['source_binding'],record=str(p),record_sha256=hashlib.sha256(raw).hexdigest(),platform=b['platform'])
destination=pathlib.Path(f'target/lab-state/secret-preparation-selector-archive-run-{run}.json')
with destination.open('x') as f:json.dump(out,f,indent=2);f.write('\n')
print(json.dumps(out))
