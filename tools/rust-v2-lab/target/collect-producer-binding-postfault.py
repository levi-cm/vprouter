"""Bind cached postfault row to exact failed artifact and public RO inspection."""
import datetime,hashlib,json,pathlib,subprocess,sys,tarfile
if not __debug__:raise RuntimeError('optimized_python_refused')
hp=pathlib.Path(__file__).with_name('producer_binding_postfault_schema.py');hb=hp.read_bytes();schema={'__name__':'binding_postfault','__file__':str(hp)};exec(compile(hb,str(hp),'exec'),schema)
cp=pathlib.Path(sys.argv[1]);c=json.loads(cp.read_text());run=int(sys.argv[2]);path=pathlib.Path(f'target/lab-state/actual-program-run-{run}.json');raw=path.read_bytes();r=json.loads(raw)
modes={'secret_producer_binding_postbirth_failure':1,'secret_producer_binding_result_failure':2,'secret_producer_binding_registration_failure':3};fault=modes[r['component_test_mode']]
assert r['exit_code']!=0 and r['source_binding']==c['binding']and r['source_archive_sha256']==c['source_sha256']and r['production_changes']is r['provider_profiles_used']is False and r['real_client_acceptance']=='NOT_RUN'
source=pathlib.Path(c['source']);assert hashlib.sha256(source.read_bytes()).hexdigest()==c['source_sha256']
assert json.loads(subprocess.check_output([sys.executable,'tools/verify-frozen-build-inputs.py',str(source),c['source_commit']]))==c['binding']
with tarfile.open(source)as tar:
 code=tar.extractfile('crates/vprouter-launch/src/attachment/producer_binding.rs').read();assert b'LAB_PRODUCER_BINDING_POSTFAULT'in code;phases=schema['phases_from_source'](code)
bindings=[(p.parent,json.loads(p.read_text()))for p in cp.parent.rglob('directory-binding.json')if json.loads(p.read_text())['record']==str(path)];assert len(bindings)==1;directory,binding=bindings[0]
assert binding['source_commit']==c['source_commit']and binding['source_archive_sha256']==c['source_sha256']and binding['platform']==r['platform']and binding['artifact_sha256']==r['artifact_sha256']
arch={'debian-clean-x86_64':'amd64','debian-x86_64':'amd64','arch-x86_64':'amd64','debian-arm64':'arm64'}[r['platform']]
assert r['artifact_sha256']==c['platforms'][arch]['artifact_sha256']and r['context_sha256']==c['platforms'][arch]['context_sha256']
for key,name in[('runner_sha256','controller-runner.py'),('guest_sha256','controller-guest.py'),('context_checker_sha256','controller-context.py'),('host_declaration_builder_sha256','controller-host-declaration.py')]:assert hashlib.sha256((directory/name).read_bytes()).hexdigest()==r[key]
ip=pathlib.Path(f'target/lab-state/secret-producer-binding-failure-run-{run}.json');ib=ip.read_bytes();inspection=json.loads(ib)
assert inspection['record_sha256']==hashlib.sha256(raw).hexdigest()and inspection['source_binding']==r['source_binding']and inspection['platform']==r['platform']and inspection['read_only']is True and inspection['private_profile_contents_read']is inspection['signals_unmount_or_cleanup']is False
rows=[schema['loads_unique'](line.split(' ',1)[1])for line in r['stderr'].splitlines()if line.startswith('LAB_PRODUCER_BINDING_POSTFAULT ')];assert len(rows)==1
parsed=[]
for line in r['stdout'].splitlines():
 try:parsed.append(json.loads(line))
 except ValueError:pass
envs=[v['secret_attachment_environment']for v in parsed if'secret_attachment_environment'in v];assert len(envs)==1
document=inspection['canonical']['namespaces.json'];entries=[e for e in document['entries']if e.get('preparation')and e['preparation'].get('producer_binding_query')];assert len(entries)==1;p=entries[0]['preparation']
assert p['producer_binding']['query']==p['producer_binding_query']['request']
proof=schema['validate'](rows[0],phases,fault,document['owner_epoch']['pid'],p['producer_binding_query'],envs[0]['after']['started_at'])
if rows[0]['constructor']is not None:assert rows[0]['constructor']['request']==p['producer_binding']['request']
out=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),record=str(path),record_sha256=hashlib.sha256(raw).hexdigest(),inspection=str(ip),inspection_sha256=hashlib.sha256(ib).hexdigest(),source_binding=r['source_binding'],artifact_sha256=r['artifact_sha256'],context_sha256=r['context_sha256'],platform=r['platform'],collector_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),schema_validator_sha256=hashlib.sha256(hb).hexdigest(),diagnostic=rows[0],proof=proof,original_failure_preserved=True,fresh_reap_or_resource_authority=False,allnine_complete=False,requirement8_complete=False,limit='Last-entered check and cached values only; driver_poll cancellation ordering is unobserved, later postfault phases follow existing failure handling. A phase does not prove the check passed; null is unobserved. Cached status is not fresh reap authority and disk result is not ACK authority. No original clock renewal, mutation/reuse, unique syscall cause or native success claim.')
dest=pathlib.Path(f'target/lab-state/producer-binding-postfault-run-{run}.json')
with dest.open('x')as f:json.dump(out,f,indent=2);f.write('\n')
print(json.dumps(dict(record=str(dest),proof=proof,original_failure_preserved=True)))
