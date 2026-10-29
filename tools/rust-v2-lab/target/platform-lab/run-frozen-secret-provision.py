"""Root-only fixed local VM DOWN WireGuard provision fixture with external inert gateway."""
import datetime,hashlib,json,pathlib,re,shutil,struct,subprocess,sys,tarfile,time
if not __debug__: raise RuntimeError('optimized_python_refused')
candidate_path=pathlib.Path(sys.argv[1]);candidate=json.loads(candidate_path.read_text());platform=sys.argv[2];label=sys.argv[3];mode=sys.argv[4]
assert re.fullmatch('[a-z0-9_-]+',label)
flags={'success':'--ignored-secret-provision','postbirth-failure':'--ignored-secret-provision-postbirth-failure','result-failure':'--ignored-secret-provision-result-failure','registration-failure':'--ignored-secret-provision-registration-failure'}
flag=flags[mode]
arch,port,known={'debian-clean-x86_64':('amd64',22036,'target/platform-lab/debian-clean-x86_64/known_hosts'),'debian-x86_64':('amd64',22032,'target/lab-state/known_hosts'),'arch-x86_64':('amd64',22033,'target/platform-lab/arch-x86_64/known_hosts'),'debian-arm64':('arm64',22034,'target/platform-lab/debian-arm64/known_hosts')}[platform]
artifact=pathlib.Path(candidate['platforms'][arch]['artifact']);source=pathlib.Path(candidate['source']);assert hashlib.sha256(artifact.read_bytes()).hexdigest()==candidate['platforms'][arch]['artifact_sha256'];assert hashlib.sha256(source.read_bytes()).hexdigest()==candidate['source_sha256']
with tarfile.open(source) as archive:
 main=archive.extractfile('crates/vprouter-launch/src/actual_lab_main.rs').read();assert ('"'+flag+'"').encode() in main and b'"--secret-attachment-descriptor"' in main,'frozen_source_missing_secret_provision_interface'
 assert b'LAB_SECRET_PROVISION' in archive.extractfile('crates/vprouter-launch/src/attachment/provision.rs').read(),'frozen_source_missing_secret_provision_witness'
binding=json.loads(subprocess.check_output([sys.executable,'tools/verify-frozen-build-inputs.py',str(source),candidate['source_commit']]))
assert binding==candidate['binding']
elffile=artifact.read_bytes();machine={'amd64':62,'arm64':183}[arch];assert elffile[:7]==b'\x7fELF\x02\x01\x01' and struct.unpack_from('<H',elffile,18)[0]==machine
phoff=struct.unpack_from('<Q',elffile,32)[0];size,count=struct.unpack_from('<HH',elffile,54);assert size==56 and 1<=count<=256;assert not {2,3}&{struct.unpack_from('<I',elffile,phoff+i*size)[0] for i in range(count)}
from attachment_context_check import context_check
context= candidate_path.parent/(arch+'.context.tar');assert hashlib.sha256(context.read_bytes()).hexdigest()==candidate['platforms'][arch]['context_sha256']
manifest,inventory,init=context_check(context,source,arch)
guest_path=pathlib.Path('target/platform-lab/secret-provision.guest.py');guest_bytes=guest_path.read_bytes();guest=guest_bytes.decode().replace('CONFIGURATION',repr(dict(artifact_sha256=candidate['platforms'][arch]['artifact_sha256'],context_sha256=candidate['platforms'][arch]['context_sha256'],manifest_sha256=manifest,init_sha256=init['sha256'],init_bytes=init['bytes'],architecture=arch,mode=mode,flag=flag)));compile(guest,'fixed-secret-provision-guest','exec')
out=candidate_path.parent/label;out.mkdir(mode=0o700);shutil.copyfile(guest_path,out/'controller-guest.py');shutil.copyfile(__file__,out/'controller-runner.py');shutil.copyfile('target/platform-lab/attachment_context_check.py',out/'controller-context.py')
ssh=['ssh','-i','target/lab-state/id_ed25519','-p'+str(port),'-o','UserKnownHostsFile='+known,'-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=5','vprouterlab@127.0.0.1']
listing="""import pathlib,re,stat,json
root=pathlib.Path('/var/lib/vprouter-v2-lab');st=root.lstat();assert st.st_uid==st.st_gid==0 and stat.S_IMODE(st.st_mode)==0o700
print(json.dumps(sorted(str(p) for p in root.iterdir() if re.fullmatch('task8b2-[1-9][0-9]*',p.name))))
"""
def directories():
 r=subprocess.run([*ssh,'sudo -n python3 -I -'],input=listing,capture_output=True,text=True,check=True,timeout=15);return json.loads(r.stdout)
before=directories();(out/'directories-before.json').write_text(json.dumps(before,indent=2)+'\n')
opts=['-i','target/lab-state/id_ed25519','-P'+str(port),'-o','UserKnownHostsFile='+known,'-o','StrictHostKeyChecking=yes']
subprocess.run(['scp','-q',*opts,str(artifact),'vprouterlab@127.0.0.1:/home/vprouterlab/secret-attachment-'+candidate['platforms'][arch]['artifact_sha256']],capture_output=True,check=True,timeout=30)
subprocess.run(['scp','-q',*opts,str(context),'vprouterlab@127.0.0.1:/home/vprouterlab/secret-attachment-context-'+candidate['platforms'][arch]['context_sha256']],capture_output=True,check=True,timeout=45)
start=time.monotonic()
try:
 result=subprocess.run([*ssh,'sudo -n python3 -I -'],input=guest,capture_output=True,text=True,timeout=250);code,stdout,stderr=result.returncode,result.stdout,result.stderr
except subprocess.TimeoutExpired as e:
 code=124;stdout=e.stdout.decode(errors='replace') if isinstance(e.stdout,bytes) else e.stdout or '';stderr=e.stderr.decode(errors='replace') if isinstance(e.stderr,bytes) else e.stderr or ''
record=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),artifact_sha256=candidate['platforms'][arch]['artifact_sha256'],source_archive_sha256=candidate['source_sha256'],source_binding=binding,platform=platform,runner_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),guest_sha256=hashlib.sha256(guest_bytes).hexdigest(),exit_code=code,wall_seconds=round(time.monotonic()-start,3),stdout=stdout,stderr=stderr,result='PASS_PARTIAL_SECRET_PROVISION' if code==0 else 'FAIL',component_test_mode='secret_provision_'+mode.replace('-','_'),real_client_acceptance='NOT_RUN',production_changes=False,provider_profiles_used=False,namespace_or_container_fixture=True,actual_gateway_is_inert=True,context_sha256=candidate['platforms'][arch]['context_sha256'],context_checker_sha256=hashlib.sha256(pathlib.Path('target/platform-lab/attachment_context_check.py').read_bytes()).hexdigest())
base=pathlib.Path('target/lab-state');run=1
while (base/f'actual-program-run-{run}.json').exists():run+=1
path=base/f'actual-program-run-{run}.json'
with path.open('x') as stream:json.dump(record,stream,indent=2);stream.write('\n')
path.chmod(0o600)
events=[]
for line in stdout.splitlines():
 if line.startswith('LAB_SECRET_PROVISION '):events.append(dict(event='secret_provision',value=json.loads(line.split(' ',1)[1])))
 else:
  try:value=json.loads(line)
  except ValueError:continue
  if 'case'in value:events.append(value)
summary=dict(record=str(path),exit_code=code,runtime_events=events,stderr=stderr,component_test_mode=record['component_test_mode'])
(out/'controller.json').write_text(json.dumps(summary,indent=2)+'\n');(out/'controller.stderr').write_text(stderr)
after=directories();assert set(after)==set(before)
(out/'directory-binding.json').write_text(json.dumps(dict(record=str(path),platform=platform,source_commit=candidate['source_commit'],source_archive_sha256=candidate['source_sha256'],artifact_sha256=record['artifact_sha256'],new_directories=[]),indent=2)+'\n')
print(json.dumps(dict(record=str(path),exit_code=code,case_count=len(events),new_directories=[],stderr_tail='\n'.join(stderr.splitlines()[-10:]) if code else '')))
raise SystemExit(code)
