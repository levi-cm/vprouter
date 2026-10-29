"""Frozen cached movement failure diagnostics, without fresh native inspection."""
import datetime,hashlib,json,pathlib,re,subprocess,sys,tarfile
if not __debug__:raise RuntimeError('optimized_python_refused')
def load_helper(name):
 p=pathlib.Path(__file__).with_name(name);data=p.read_bytes();ns={'__name__':name,'__file__':str(p)};exec(compile(data,str(p),'exec'),ns);return ns,hashlib.sha256(data).hexdigest()
validator,validator_sha=load_helper('movement_failure_schema.py');initial,initial_sha=load_helper('initial_quarantine_failure_schema.py')
cp=pathlib.Path(sys.argv[1]);c=json.loads(cp.read_text());run=int(sys.argv[2]);rp=pathlib.Path(f'target/lab-state/actual-program-run-{run}.json');raw=rp.read_bytes();r=json.loads(raw)
assert r['exit_code']!=0 and r['component_test_mode']in('secret_quarantine_success','secret_quarantine_postbirth_failure','secret_quarantine_result_failure','secret_quarantine_registration_failure')
assert r['source_binding']==c['binding']and r['source_archive_sha256']==c['source_sha256']and r['production_changes']is r['provider_profiles_used']is False and r['real_client_acceptance']=='NOT_RUN'
source=pathlib.Path(c['source']);assert hashlib.sha256(source.read_bytes()).hexdigest()==c['source_sha256']
assert json.loads(subprocess.check_output([sys.executable,'tools/verify-frozen-build-inputs.py',str(source),c['source_commit']]))==c['binding']
with tarfile.open(source)as archive:
 paths=['crates/vprouter-launch/src/attachment/movement/trace.rs',*validator['SOURCE_PATHS']];codes=[archive.extractfile(p).read()for p in paths]
 assert b'LAB_MOVEMENT_PROGRESS'in codes[0]and b'inclusive_spans_not_additive'in codes[0]
 pairs=validator['extract_pairs'](codes[1:])
 errorcode=archive.extractfile('crates/vprouter-launch/src/error.rs').read();enum=errorcode.split(b'pub enum Error {',1)[1].split(b'}',1)[0];errors={v.decode()for v in re.findall(rb'^\s*([A-Z][A-Za-z]+),',enum,re.M)};assert 'Deadline'in errors
bindings=[(p.parent,json.loads(p.read_text()))for p in cp.parent.rglob('directory-binding.json')if json.loads(p.read_text())['record']==str(rp)];assert len(bindings)==1;directory,binding=bindings[0]
assert binding['source_commit']==c['source_commit']and binding['source_archive_sha256']==c['source_sha256']and binding['platform']==r['platform']
arch={'debian-clean-x86_64':'amd64','debian-x86_64':'amd64','arch-x86_64':'amd64','debian-arm64':'arm64'}[r['platform']]
assert binding['artifact_sha256']==r['artifact_sha256']==c['platforms'][arch]['artifact_sha256']and r['context_sha256']==c['platforms'][arch]['context_sha256']
for key,name in[('runner_sha256','controller-runner.py'),('guest_sha256','controller-guest.py'),('context_checker_sha256','controller-context.py'),('host_declaration_builder_sha256','controller-host-declaration.py')]:assert hashlib.sha256((directory/name).read_bytes()).hexdigest()==r[key]
ip=pathlib.Path(f'target/lab-state/secret-quarantine-failure-run-{run}.json');ibytes=ip.read_bytes();inspection=json.loads(ibytes)
assert inspection['record_sha256']==hashlib.sha256(raw).hexdigest()and inspection['source_binding']==r['source_binding']and inspection['platform']==r['platform']and inspection['read_only']is True and inspection['private_profile_contents_read']is inspection['signals_unmount_or_cleanup']is False
parsed=[]
for line in r['stdout'].splitlines():
 try:parsed.append(json.loads(line))
 except ValueError:pass
env=[x['secret_attachment_environment']for x in parsed if 'secret_attachment_environment'in x];desc=[x['secret_attachment_descriptor']for x in parsed if 'secret_attachment_descriptor'in x];assert len(env)==len(desc)==1
after=env[0]['after']['started_at'];owner=inspection['canonical']['namespaces.json']['owner_epoch'];member=desc[0]['primary']
markers=[];progress=[]
for line in r['stderr'].splitlines():
 if line.startswith('LAB_MOVEMENT_PRIMARY_FAILURE '):
  found=re.fullmatch(r'LAB_MOVEMENT_PRIMARY_FAILURE scope=(native|inner|outer) reason=([A-Za-z]+)',line);assert found and found[2]in errors;markers.append((found[1],found[2]))
 elif line.startswith('LAB_MOVEMENT_PROGRESS '):progress.append(json.loads(line.split(' ',1)[1]))
assert markers==[(x['scope'],x['reason'])for x in progress]
def prep(row):return initial['validate_progress'](row,member,owner,after,fixture=True)
proof=validator['validate'](progress,pairs,errors,after,prep)
out=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),record=str(rp),record_sha256=hashlib.sha256(raw).hexdigest(),inspection=str(ip),inspection_sha256=hashlib.sha256(ibytes).hexdigest(),source_binding=r['source_binding'],artifact_sha256=r['artifact_sha256'],context_sha256=r['context_sha256'],platform=r['platform'],collector_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),schema_validator_sha256=validator_sha,preparation_validator_sha256=initial_sha,progress=progress,proof=proof,original_failure_preserved=True,fresh_reap_or_resource_authority=False,requirement8_complete=False,allnine_complete=False,limit='Ordered cached scopes only; each row precedes its own cancellation, while higher rows may follow lower cancellation/collection. Earliest deepest row is not proof of a unique root cause. Inclusive spans overlap and cannot be added or treated as CPU cost. Disk canonical presence is not writer ACK/reap authority. No deadline extension, unchanged retry, cleanup/reuse or success acceptance.')
dest=pathlib.Path(f'target/lab-state/movement-failure-run-{run}.json')
with dest.open('x')as stream:json.dump(out,stream,indent=2);stream.write('\n')
print(json.dumps(dict(record=str(dest),proof=proof,original_failure_preserved=True)))
