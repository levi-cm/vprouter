"""Root-only fixed local VM HOST-addition fixture with external inert gateway."""
import datetime,hashlib,json,os,pathlib,re,stat,struct,subprocess,sys,tarfile,time
if not __debug__: raise RuntimeError('optimized_python_refused')
controller_bytes=pathlib.Path(__file__).read_bytes()
candidate_path=pathlib.Path(sys.argv[1]);candidate=json.loads(candidate_path.read_text());platform=sys.argv[2];label=sys.argv[3];mode=sys.argv[4]
assert re.fullmatch('[a-z0-9_-]+',label)
flags={'success':'--ignored-secret-host-addition','postbirth-failure':'--ignored-secret-host-addition-postbirth-failure','result-failure':'--ignored-secret-host-addition-result-failure','registration-failure':'--ignored-secret-host-addition-registration-failure'}
flag=flags[mode]
arch,port,known={'debian-clean-x86_64':('amd64',22036,'target/platform-lab/debian-clean-x86_64/known_hosts'),'debian-x86_64':('amd64',22032,'target/lab-state/known_hosts'),'arch-x86_64':('amd64',22033,'target/platform-lab/arch-x86_64/known_hosts'),'debian-arm64':('arm64',22034,'target/platform-lab/debian-arm64/known_hosts')}[platform]
artifact=pathlib.Path(candidate['platforms'][arch]['artifact']);source=pathlib.Path(candidate['source']);assert hashlib.sha256(artifact.read_bytes()).hexdigest()==candidate['platforms'][arch]['artifact_sha256'];assert hashlib.sha256(source.read_bytes()).hexdigest()==candidate['source_sha256']
with tarfile.open(source) as archive:
 main=archive.extractfile('crates/vprouter-launch/src/actual_lab_main.rs').read();assert ('"'+flag+'"').encode() in main and b'"--secret-attachment-descriptor"' in main,'frozen_source_missing_secret_host_addition_interface'
 assert b'LAB_SECRET_HOST_ADDITION' in archive.extractfile('crates/vprouter-launch/src/attachment/host_addition.rs').read(),'frozen_source_missing_secret_host_addition_witness'
baseline_builder_path=pathlib.Path('target/platform-lab/host_baseline_declaration.py');baseline_builder_bytes=baseline_builder_path.read_bytes();baseline_builder=baseline_builder_bytes.decode();baseline_builder_sha256=hashlib.sha256(baseline_builder_bytes).hexdigest()
template_path=candidate_path.parent/('authored-host-baseline-'+platform+'.json');review_path=candidate_path.parent/('host-baseline-reconciliation-'+platform+'.json')
fd=os.open(template_path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
with os.fdopen(fd,'rb')as stream:
 info=os.fstat(stream.fileno());assert stat.S_ISREG(info.st_mode)and info.st_uid==os.geteuid()and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600 and 0<info.st_size<=256*1024;template_bytes=stream.read(256*1024+1);assert len(template_bytes)==info.st_size
review_bytes=review_path.read_bytes();template=json.loads(template_bytes);baseline_namespace={};exec(compile(baseline_builder,str(baseline_builder_path),'exec'),baseline_namespace);baseline_namespace['validate_template'](template,candidate['binding'],platform)
assert hashlib.sha256(review_bytes).hexdigest()==template['review_sha256']
for ref in template['prior_evidence']:
 rp=pathlib.Path(ref['path']);assert not rp.is_absolute()and rp.parts[0]=='target'and '..'not in rp.parts and rp.suffix=='.json';assert hashlib.sha256(rp.read_bytes()).hexdigest()==ref['sha256']
template_sha256=hashlib.sha256(template_bytes).hexdigest();review_sha256=hashlib.sha256(review_bytes).hexdigest()
binding=json.loads(subprocess.check_output([sys.executable,'tools/verify-frozen-build-inputs.py',str(source),candidate['source_commit']]))
assert binding==candidate['binding']
elffile=artifact.read_bytes();machine={'amd64':62,'arm64':183}[arch];assert elffile[:7]==b'\x7fELF\x02\x01\x01' and struct.unpack_from('<H',elffile,18)[0]==machine
phoff=struct.unpack_from('<Q',elffile,32)[0];size,count=struct.unpack_from('<HH',elffile,54);assert size==56 and 1<=count<=256;assert not {2,3}&{struct.unpack_from('<I',elffile,phoff+i*size)[0] for i in range(count)}
context_checker_path=pathlib.Path('target/platform-lab/attachment_context_check.py');context_checker_bytes=context_checker_path.read_bytes();context_namespace={'__name__':'captured_host_context_checker','__file__':str(context_checker_path)};exec(compile(context_checker_bytes,str(context_checker_path),'exec'),context_namespace);context_check=context_namespace['context_check']
context= candidate_path.parent/(arch+'.context.tar');assert hashlib.sha256(context.read_bytes()).hexdigest()==candidate['platforms'][arch]['context_sha256']
manifest,inventory,init=context_check(context,source,arch)
host_builder_path=pathlib.Path('target/platform-lab/quarantine_host_declaration.py');host_builder_bytes=host_builder_path.read_bytes();host_builder=host_builder_bytes.decode();host_builder_sha256=hashlib.sha256(host_builder_bytes).hexdigest()
guest_path=pathlib.Path('target/platform-lab/secret-host-addition.guest.py');guest_bytes=guest_path.read_bytes();guest=guest_bytes.decode().replace('CONFIGURATION',repr(dict(artifact_sha256=candidate['platforms'][arch]['artifact_sha256'],context_sha256=candidate['platforms'][arch]['context_sha256'],manifest_sha256=manifest,init_sha256=init['sha256'],init_bytes=init['bytes'],architecture=arch,mode=mode,flag=flag,platform=platform,host_declaration_builder=host_builder,host_declaration_builder_sha256=host_builder_sha256,host_baseline_builder=baseline_builder,host_baseline_builder_sha256=baseline_builder_sha256,host_baseline_template=template,host_baseline_template_sha256=template_sha256,baseline_reconciliation_sha256=review_sha256,source_binding=binding)));compile(guest,'fixed-secret-host-addition-guest','exec')
out=candidate_path.parent/label;out.mkdir(mode=0o700)
for name,raw in {'controller-guest.py':guest_bytes,'controller-runner.py':controller_bytes,'controller-context.py':context_checker_bytes,'controller-host-declaration.py':host_builder_bytes,'controller-baseline-declaration.py':baseline_builder_bytes,'controller-authored-baseline.json':template_bytes,'controller-baseline-reconciliation.json':review_bytes}.items():
 with(out/name).open('xb')as stream:stream.write(raw)
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
record=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),artifact_sha256=candidate['platforms'][arch]['artifact_sha256'],source_archive_sha256=candidate['source_sha256'],source_binding=binding,platform=platform,runner_sha256=hashlib.sha256(controller_bytes).hexdigest(),host_declaration_builder_sha256=host_builder_sha256,baseline_declaration_builder_sha256=baseline_builder_sha256,host_baseline_template_sha256=template_sha256,baseline_reconciliation_sha256=review_sha256,guest_sha256=hashlib.sha256(guest_bytes).hexdigest(),exit_code=code,wall_seconds=round(time.monotonic()-start,3),stdout=stdout,stderr=stderr,result='PASS_PARTIAL_SECRET_HOST_ADDITION' if code==0 else 'FAIL',component_test_mode='secret_host_addition_'+mode.replace('-','_'),real_client_acceptance='NOT_RUN',production_changes=False,provider_profiles_used=False,namespace_or_container_fixture=True,actual_gateway_is_inert=True,context_sha256=candidate['platforms'][arch]['context_sha256'],context_checker_sha256=hashlib.sha256(context_checker_bytes).hexdigest())
base=pathlib.Path('target/lab-state');run=1
while (base/f'actual-program-run-{run}.json').exists():run+=1
path=base/f'actual-program-run-{run}.json'
with path.open('x') as stream:json.dump(record,stream,indent=2);stream.write('\n')
path.chmod(0o600)
events=[]
for line in stdout.splitlines():
 if line.startswith('LAB_SECRET_HOST_ADDITION '):events.append(dict(event='secret_host_addition',value=json.loads(line.split(' ',1)[1])))
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
