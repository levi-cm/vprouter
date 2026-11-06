"""Root-only fixed local VM Bootstrap fixture with external inert gateway."""
import contextlib,datetime,hashlib,json,os,pathlib,re,stat,struct,subprocess,sys,tarfile,time
if not __debug__: raise RuntimeError('optimized_python_refused')
import importlib.util
spec=importlib.util.spec_from_file_location('run411_path_guard','tools/rust-v2-lab/run411-reservation.py');path_guard=importlib.util.module_from_spec(spec);spec.loader.exec_module(path_guard)

def compile_remote_programs(guest,host_builder,baseline_builder,boot=None):
 """Compile the exact stdin programs and both embedded builders before claim.

 SCP transfers only the static ELF and context tar; neither is Python source.
 Keep the unreserved listing byte-for-byte identical to the historical program.
 """
 listing="""import pathlib,re,stat,json
root=pathlib.Path('/var/lib/vprouter-v2-lab');st=root.lstat();assert st.st_uid==st.st_gid==0 and stat.S_IMODE(st.st_mode)==0o700
print(json.dumps(sorted(str(p) for p in root.iterdir() if re.fullmatch('task8b2-[1-9][0-9]*',p.name))))
"""
 if boot is not None:
  prefix="import pathlib;assert pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()=="+repr(boot)+'\n'
  listing=prefix+listing;guest=prefix+guest
 programs={'listing':listing,'guest':guest,'host-declaration':host_builder,'baseline-declaration':baseline_builder}
 for name,program in programs.items():compile(program,'bootstrap-remote-'+name,'exec')
 return programs

path_guard.freeze_inputs()
controller_bytes=path_guard.read_bytes(pathlib.Path(__file__))
assert sys.argv[2]=='debian-arm64' and sys.argv[3]=='bootstrap411-arm64' and sys.argv[4]=='success','explicit_run411_parameters_required'
candidate_path=pathlib.Path(sys.argv[1]);candidate=json.loads(path_guard.read_text(candidate_path));path_guard.check_references(candidate);platform=sys.argv[2];label=sys.argv[3];mode=sys.argv[4]
assert re.fullmatch('[a-z0-9_-]+',label)
flags={name:'--ignored-secret-bootstrap'+suffix for name,suffix in [('success',''),('postbirth-failure','-postbirth-failure'),('result-failure','-result-failure'),('registration-failure','-registration-failure'),('handoff-fence','-handoff-fence'),('handoff-partial','-handoff-partial'),('handoff-duplicate','-handoff-duplicate')]}
flag=flags[mode]
arch,port,known={'debian-clean-x86_64':('amd64',22036,'target/platform-lab/debian-clean-x86_64/known_hosts'),'debian-x86_64':('amd64',22032,'target/lab-state/known_hosts'),'arch-x86_64':('amd64',22033,'target/platform-lab/arch-x86_64/known_hosts'),'debian-arm64':('arm64',22034,'target/platform-lab/debian-arm64/known_hosts')}[platform]
artifact=pathlib.Path(candidate['platforms'][arch]['artifact']);source=pathlib.Path(candidate['source'])
artifact_input=path_guard.acquire(artifact);source_input=path_guard.acquire(source)
assert artifact_input.sha256==candidate['platforms'][arch]['artifact_sha256'];assert source_input.sha256==candidate['source_sha256']
with path_guard.ByteTarfiles.open(source_input.data) as archive:
 main=archive.extractfile('crates/vprouter-launch/src/actual_lab_main.rs').read();assert ('"'+flag+'"').encode() in main and b'"--secret-attachment-descriptor"' in main,'frozen_source_missing_secret_host_addition_interface'
 assert b'LAB_SECRET_BOOTSTRAP' in archive.extractfile('crates/vprouter-launch/src/attachment/operational/bootstrap.rs').read(),'frozen_source_missing_secret_bootstrap_witness'
baseline_builder_path=pathlib.Path('target/platform-lab/host_baseline_declaration.py');baseline_builder_bytes=path_guard.read_bytes(baseline_builder_path);baseline_builder=baseline_builder_bytes.decode();baseline_builder_sha256=hashlib.sha256(baseline_builder_bytes).hexdigest()
template_path=candidate_path.parent/('authored-host-baseline-'+platform+'.json');review_path=candidate_path.parent/('host-baseline-reconciliation-'+platform+'.json')
template_input=path_guard.acquire(template_path);info=template_input.info;template_bytes=template_input.data
assert stat.S_ISREG(info.st_mode)and info.st_uid==os.geteuid()and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600 and 0<len(template_bytes)==info.st_size<=256*1024
review_bytes=path_guard.read_bytes(review_path);template=json.loads(template_bytes);path_guard.check_references(template);path_guard.check_references(json.loads(review_bytes));baseline_namespace={};exec(compile(baseline_builder,str(baseline_builder_path),'exec'),baseline_namespace);baseline_namespace['validate_template'](template,candidate['binding'],platform)
assert hashlib.sha256(review_bytes).hexdigest()==template['review_sha256']
for ref in template['prior_evidence']:
 rp=pathlib.Path(ref['path']);assert not rp.is_absolute()and rp.parts[0]=='target'and '..'not in rp.parts and rp.suffix=='.json';assert hashlib.sha256(path_guard.read_bytes(rp)).hexdigest()==ref['sha256']
template_sha256=hashlib.sha256(template_bytes).hexdigest();review_sha256=hashlib.sha256(review_bytes).hexdigest()
binding=path_guard.verify_source(source_input.data,candidate['source_commit'])
assert binding==candidate['binding']
elffile=artifact_input.data;machine={'amd64':62,'arm64':183}[arch];assert elffile[:7]==b'\x7fELF\x02\x01\x01' and struct.unpack_from('<H',elffile,18)[0]==machine
phoff=struct.unpack_from('<Q',elffile,32)[0];size,count=struct.unpack_from('<HH',elffile,54);assert size==56 and 1<=count<=256;assert not {2,3}&{struct.unpack_from('<I',elffile,phoff+i*size)[0] for i in range(count)}
context_checker_path=pathlib.Path('target/platform-lab/attachment_context_check.py');context_checker_bytes=path_guard.read_bytes(context_checker_path);context_namespace={'__name__':'captured_host_context_checker','__file__':str(context_checker_path)};exec(compile(context_checker_bytes,str(context_checker_path),'exec'),context_namespace);context_check=context_namespace['context_check']
context=candidate_path.parent/(arch+'.context.tar');context_input=path_guard.acquire(context);assert context_input.sha256==candidate['platforms'][arch]['context_sha256']
context_namespace['tarfile']=path_guard.ByteTarfiles
manifest,inventory,init=context_check(context_input.data,source_input.data,arch)
host_builder_path=pathlib.Path('target/platform-lab/quarantine_host_declaration.py');host_builder_bytes=path_guard.read_bytes(host_builder_path);host_builder=host_builder_bytes.decode();host_builder_sha256=hashlib.sha256(host_builder_bytes).hexdigest()
guest_path=pathlib.Path('target/platform-lab/secret-bootstrap.guest.py');guest_bytes=path_guard.read_bytes(guest_path);guest=guest_bytes.decode().replace('CONFIGURATION',repr(dict(artifact_sha256=candidate['platforms'][arch]['artifact_sha256'],context_sha256=candidate['platforms'][arch]['context_sha256'],manifest_sha256=manifest,init_sha256=init['sha256'],init_bytes=init['bytes'],architecture=arch,mode=mode,flag=flag,platform=platform,host_declaration_builder=host_builder,host_declaration_builder_sha256=host_builder_sha256,host_baseline_builder=baseline_builder,host_baseline_builder_sha256=baseline_builder_sha256,host_baseline_template=template,host_baseline_template_sha256=template_sha256,baseline_reconciliation_sha256=review_sha256,source_binding=binding)))
# Explicit reservation is required on the fresh clean-Debian continuation.
reservation_data=None;reservation_lock=None
if len(sys.argv)>5:
 assert len(sys.argv) in (7,8) and sys.argv[5]=='--reservation'
 preflight=len(sys.argv)==8
 if preflight:assert sys.argv[7]=='--preflight-only'
 import importlib.util
 reservation_helper=pathlib.Path('tools/rust-v2-lab/run411-reservation.py')
 reservation_module=path_guard
 fresh=path_guard.load_module('fresh_provenance','tools/rust-v2-lab/run411-provenance.py')
 programs={}
 def preclaim_check():
  admitted=fresh.validate_fresh_provenance(template,json.loads(review_bytes),candidate)
  programs.update(compile_remote_programs(guest,host_builder,baseline_builder,admitted['guest_boot_id']))
 reservation_lock,reservation_data=reservation_module.admit(sys.argv[6],candidate_path,platform,label,mode,preflight,provenance_check=preclaim_check)
 guest=programs['guest'];listing=programs['listing']
 if preflight:
  print(json.dumps(dict(reservation_preflight='PASS',remote_program_compile='PASS',compiled_remote_programs=sorted(programs),run=411,budget_remaining=1,guest_actions_executed=False)));raise SystemExit(0)
else:
 raise AssertionError('explicit_run411_reservation_required')

try:
 out=candidate_path.parent/label;path_guard.allowed_path(out);out.mkdir(mode=0o700)
 for name,raw in {'controller-guest.py':guest_bytes,'controller-runner.py':controller_bytes,'controller-context.py':context_checker_bytes,'controller-host-declaration.py':host_builder_bytes,'controller-baseline-declaration.py':baseline_builder_bytes,'controller-authored-baseline.json':template_bytes,'controller-baseline-reconciliation.json':review_bytes}.items():
  with os.fdopen(path_guard.open_exclusive(out/name),'wb')as stream:stream.write(raw)
 ssh_scope=contextlib.ExitStack()
 identity,known_hosts=ssh_scope.enter_context(path_guard.ssh_material('target/lab-state/id_ed25519',known))
 ssh=['ssh','-F', '/dev/null', '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none', '-i',identity,'-p'+str(port),'-o','UserKnownHostsFile='+known_hosts,'-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=5','vprouterlab@127.0.0.1']
 def directories():
  r=subprocess.run([*ssh,'sudo -n python3 -I -'],input=listing,capture_output=True,text=True,check=True,timeout=15);return json.loads(r.stdout)
 before=directories();path_guard.write_new(out/'directories-before.json',(json.dumps(before,indent=2)+'\n').encode())
 opts=['-F', '/dev/null', '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none', '-i',identity,'-P'+str(port),'-o','UserKnownHostsFile='+known_hosts,'-o','StrictHostKeyChecking=yes']
 with path_guard.transfer_fd(artifact_input.data) as artifact_fd:
  subprocess.run(['scp','-q',*opts,'/proc/self/fd/'+str(artifact_fd),'vprouterlab@127.0.0.1:/home/vprouterlab/secret-attachment-'+candidate['platforms'][arch]['artifact_sha256']],pass_fds=(artifact_fd,),capture_output=True,check=True,timeout=30)
 with path_guard.transfer_fd(context_input.data) as context_fd:
  subprocess.run(['scp','-q',*opts,'/proc/self/fd/'+str(context_fd),'vprouterlab@127.0.0.1:/home/vprouterlab/secret-attachment-context-'+candidate['platforms'][arch]['context_sha256']],pass_fds=(context_fd,),capture_output=True,check=True,timeout=45)
 start=time.monotonic()
 try:
  result=subprocess.run([*ssh,'sudo -n python3 -I -'],input=guest,capture_output=True,text=True,timeout=250);code,stdout,stderr=result.returncode,result.stdout,result.stderr
 except subprocess.TimeoutExpired as e:
  code=124;stdout=e.stdout.decode(errors='replace') if isinstance(e.stdout,bytes) else e.stdout or '';stderr=e.stderr.decode(errors='replace') if isinstance(e.stderr,bytes) else e.stderr or ''
 record=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),artifact_sha256=candidate['platforms'][arch]['artifact_sha256'],source_archive_sha256=candidate['source_sha256'],source_binding=binding,platform=platform,runner_sha256=hashlib.sha256(controller_bytes).hexdigest(),host_declaration_builder_sha256=host_builder_sha256,baseline_declaration_builder_sha256=baseline_builder_sha256,host_baseline_template_sha256=template_sha256,baseline_reconciliation_sha256=review_sha256,guest_sha256=hashlib.sha256(guest_bytes).hexdigest(),exit_code=code,wall_seconds=round(time.monotonic()-start,3),stdout=stdout,stderr=stderr,result='PASS_PARTIAL_SECRET_BOOTSTRAP' if code==0 else 'FAIL',component_test_mode='secret_bootstrap_'+mode.replace('-','_'),real_client_acceptance='NOT_RUN',production_changes=False,provider_profiles_used=False,namespace_or_container_fixture=True,actual_gateway_is_inert=True,context_sha256=candidate['platforms'][arch]['context_sha256'],context_checker_sha256=hashlib.sha256(context_checker_bytes).hexdigest())
 base=pathlib.Path('target/lab-state');run=411 if reservation_data is not None else 1
 if reservation_data is None:
  while (base/f'actual-program-run-{run}.json').exists():run+=1
 else:
  record['guest_boot_id']=reservation_data['guest_boot_id']
  record['run_reservation']=dict(path=sys.argv[6],sha256=reservation_module.sha(sys.argv[6]),claim=str(reservation_module.CLAIM),continuity='fresh-lab',historical_raw_records_recovered=False)
 path=base/f'actual-program-run-{run}.json'
 if reservation_data is not None:reservation_module.save(path,record)
 else:raise AssertionError('explicit_run411_reservation_required')
 events=[]
 for line in stdout.splitlines():
  if line.startswith('LAB_SECRET_BOOTSTRAP '):events.append(dict(event='secret_bootstrap',value=json.loads(line.split(' ',1)[1])))
  else:
   try:value=json.loads(line)
   except ValueError:continue
   if 'case'in value:events.append(value)
 summary=dict(record=str(path),exit_code=code,runtime_events=events,stderr=stderr,component_test_mode=record['component_test_mode'])
 path_guard.write_new(out/'controller.json',(json.dumps(summary,indent=2)+'\n').encode());path_guard.write_new(out/'controller.stderr',stderr.encode())
 after=directories();assert set(after)==set(before)
 path_guard.write_new(out/'directory-binding.json',(json.dumps(dict(record=str(path),platform=platform,source_commit=candidate['source_commit'],source_archive_sha256=candidate['source_sha256'],artifact_sha256=record['artifact_sha256'],new_directories=[]),indent=2)+'\n').encode())
 print(json.dumps(dict(record=str(path),exit_code=code,case_count=len(events),new_directories=[],stderr_tail='\n'.join(stderr.splitlines()[-10:]) if code else '')))
 raise SystemExit(code)
except Exception as error:
 if reservation_data is not None:
  def diagnostic(value):return value.decode(errors='replace')if isinstance(value,bytes)else value
  reservation_module.save(pathlib.Path('target/lab-state/run-411-controller-error.json'),dict(run=411,reservation_sha256=reservation_module.sha(sys.argv[6]),error_type=type(error).__name__,error=str(error),stdout=diagnostic(getattr(error,'stdout',None)),stderr=diagnostic(getattr(error,'stderr',None)),raw_record_present=reservation_module.RUN.exists(),budget_remaining=0))
 raise

finally:
 if 'ssh_scope' in globals():ssh_scope.close()
