"""Bind cached parent diagnostics to exact failed artifact and public inspection."""
import datetime,hashlib,json,pathlib,re,subprocess,sys,tarfile
if not __debug__:raise RuntimeError('optimized_python_refused')
helper=pathlib.Path(__file__).with_name('initial_quarantine_failure_schema.py');helper_bytes=helper.read_bytes();namespace={'__name__':'initial_quarantine_failure_schema','__file__':str(helper)};exec(compile(helper_bytes,str(helper),'exec'),namespace)
cp=pathlib.Path(sys.argv[1]);candidate=json.loads(cp.read_text());run=int(sys.argv[2]);path=pathlib.Path(f'target/lab-state/actual-program-run-{run}.json');raw=path.read_bytes();record=json.loads(raw)
assert record['exit_code']!=0 and record['component_test_mode']in('secret_quarantine_success','secret_quarantine_postbirth_failure','secret_quarantine_result_failure','secret_quarantine_registration_failure')
assert record['source_binding']==candidate['binding']and record['source_archive_sha256']==candidate['source_sha256']and record['production_changes']is record['provider_profiles_used']is False and record['real_client_acceptance']=='NOT_RUN'
source=pathlib.Path(candidate['source']);assert hashlib.sha256(source.read_bytes()).hexdigest()==candidate['source_sha256']
assert json.loads(subprocess.check_output([sys.executable,'tools/verify-frozen-build-inputs.py',str(source),candidate['source_commit']]))==candidate['binding']
with tarfile.open(source)as archive:
 code=archive.extractfile('crates/vprouter-launch/src/attachment/quarantine.rs').read();other=archive.extractfile('crates/vprouter-launch/src/owned/preparation/quarantine.rs').read()
 fixture=b'"own_intent_fixture"'in code
 assert b'LAB_INITIAL_QUARANTINE_FAILURE'in code and b'LAB_INITIAL_QUARANTINE_PROGRESS'in code
 phases={v.decode()for v in re.findall(rb'lab_stage\("([a-z_]+)"\)',code+other)}|{'construction','unarmed'}
bindings=[(p.parent,json.loads(p.read_text()))for p in cp.parent.rglob('directory-binding.json')if json.loads(p.read_text())['record']==str(path)];assert len(bindings)==1;directory,binding=bindings[0]
assert binding['source_commit']==candidate['source_commit']and binding['source_archive_sha256']==candidate['source_sha256']and binding['platform']==record['platform']
arch={'debian-clean-x86_64':'amd64','debian-x86_64':'amd64','arch-x86_64':'amd64','debian-arm64':'arm64'}[record['platform']]
assert binding['artifact_sha256']==record['artifact_sha256']==candidate['platforms'][arch]['artifact_sha256']and record['context_sha256']==candidate['platforms'][arch]['context_sha256']
for key,name in[('runner_sha256','controller-runner.py'),('guest_sha256','controller-guest.py'),('context_checker_sha256','controller-context.py'),('host_declaration_builder_sha256','controller-host-declaration.py')]:assert hashlib.sha256((directory/name).read_bytes()).hexdigest()==record[key]
reference_path=pathlib.Path(f'target/lab-state/secret-quarantine-failure-run-{run}.json');reference_bytes=reference_path.read_bytes();reference=json.loads(reference_bytes)
assert reference['record_sha256']==hashlib.sha256(raw).hexdigest()and reference['source_binding']==record['source_binding']and reference['platform']==record['platform']and reference['read_only']is True and reference['private_profile_contents_read']is reference['signals_unmount_or_cleanup']is False
failures=[json.loads(line.split(' ',1)[1])for line in record['stderr'].splitlines()if line.startswith('LAB_INITIAL_QUARANTINE_FAILURE ')]
progress=[json.loads(line.split(' ',1)[1])for line in record['stderr'].splitlines()if line.startswith('LAB_INITIAL_QUARANTINE_PROGRESS ')]
assert len(failures)==1 and len(progress)<=1
rows=[]
for line in record['stdout'].splitlines():
 try:rows.append(json.loads(line))
 except ValueError:pass
environments=[v['secret_attachment_environment']for v in rows if'secret_attachment_environment'in v];descriptors=[v['secret_attachment_descriptor']for v in rows if'secret_attachment_descriptor'in v];assert len(environments)==len(descriptors)==1
after=environments[0]['after']['started_at'];proof=namespace['validate_failure'](failures[0],phases,after,fixture=fixture)
progress_proof=None
if progress:progress_proof=namespace['validate_progress'](progress[0],descriptors[0]['primary'],reference['canonical']['namespaces.json']['owner_epoch'],after,fixture=fixture)
if fixture:namespace['bind_fixture'](failures[0],progress[0]if progress else None)
out=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),record=str(path),record_sha256=hashlib.sha256(raw).hexdigest(),inspection=str(reference_path),inspection_sha256=hashlib.sha256(reference_bytes).hexdigest(),source_binding=record['source_binding'],artifact_sha256=record['artifact_sha256'],context_sha256=record['context_sha256'],platform=record['platform'],collector_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),schema_validator_sha256=hashlib.sha256(helper_bytes).hexdigest(),failure=failures[0],cached_progress=progress[0]if progress else None,proof=proof,progress_proof=progress_proof,original_failure_preserved=True,fresh_reap_or_resource_authority=False,requirement8_complete=False,allnine_complete=False,limit='Last entered parent boundary and cached queue/job/child/writer state only; queue/job fields may precede the failing boundary. Null is unobserved. Disk canonical presence is not ACK/reap authority. No unique native syscall/filter cause, current-idle, deadline extension, cleanup/reuse, native success or release acceptance.')
destination=pathlib.Path(f'target/lab-state/initial-quarantine-failure-run-{run}.json')
with destination.open('x')as stream:json.dump(out,stream,indent=2);stream.write('\n')
print(json.dumps(dict(record=str(destination),failure=failures[0],progress_proof=progress_proof,original_failure_preserved=True)))
