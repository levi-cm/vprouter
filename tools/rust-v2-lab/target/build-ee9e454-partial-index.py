"""Index reviewed component evidence; preserve earlier failed checkpoints."""
import datetime,hashlib,json,pathlib,subprocess
if not __debug__:raise RuntimeError('optimized_python_refused')
cp=pathlib.Path('target/continuation-20261027T213436Z/candidate.json');c=json.loads(cp.read_text());d=cp.parent
assert json.loads(subprocess.check_output(['python3','tools/verify-frozen-build-inputs.py',c['source'],c['source_commit']]))==c['binding']
assert hashlib.sha256(pathlib.Path(c['source']).read_bytes()).hexdigest()==c['source_sha256']
for arch,v in c['platforms'].items():
 assert hashlib.sha256(pathlib.Path(v['artifact']).read_bytes()).hexdigest()==v['artifact_sha256']
 assert hashlib.sha256((d/(arch+'.context.tar')).read_bytes()).hexdigest()==v['context_sha256']
by_record={}
for p in d.rglob('directory-binding.json'):
 b=json.loads(p.read_text());assert b['source_commit']==c['source_commit']and b['record']not in by_record;by_record[b['record']]=b
rows=[];paths=set()
for run in range(279,297):
 p=pathlib.Path(f'target/lab-state/actual-program-run-{run}.json');r=json.loads(p.read_text());assert r['source_binding']==c['binding']and r['exit_code']==0;b=by_record[str(p)]
 assert b['platform']==r.get('platform',r.get('platform_lab',b['platform']))
 rows.append(dict(run=run,mode=r.get('component_test_mode','actual'),result='PASS',platform=b['platform']))
 paths.update(pathlib.Path('target/lab-state').glob('*run-'+str(run)+'.json'))
for run in range(279,295):
 p=pathlib.Path(f'target/lab-state/secret-provision-run-{run}.json');x=json.loads(p.read_text());assert x['source_binding']==c['binding']and x['allnine_complete']is x['requirement8_complete']is False
 assert x['proof']['ordered_writers_verified']=={0:33,1:25,2:30,3:25}[x['witness']['fault']]
names=['target/collect-secret-provision.py','target/provision_evidence_base.py','target/smoke-provision-evidence.py','target/run-frozen-provision-modes.py','target/inspect-secret-provision-failure.py','target/archive-secret-provision-selectors.py','target/collect-wireguard-failure.py','target/platform-lab/run-frozen-secret-provision.py','target/platform-lab/secret-provision.guest.py','target/platform-lab/attachment_context_check.py','target/platform-lab/collect-component-evidence.py','target/collect-secret-attachment.py','target/collect-retirement-cleanup-failure.py','target/cleanup_failure_diagnostic.py',__file__]
keepers=d/'root-collectors';keepers.mkdir(mode=0o700)
for name in names:
 p=pathlib.Path(name)
 with(keepers/p.name).open('xb')as stream:stream.write(p.read_bytes())
paths.update(p for p in d.rglob('*')if p.is_file()and p.suffix in('.json','.py','.stderr','.log'))
paths.update(pathlib.Path('target/process-inspection-root-verification-20261027').glob('*ee9e454*'))
paths.update(pathlib.Path('target').glob('ee9e454*.log'))
paths.update(pathlib.Path('target').glob('provision-profile-hint*.log'))
paths.update(pathlib.Path('target').glob('provision-hint*.log'))
paths.update(pathlib.Path('target/lab-state/provision-controller-preparation-20261027T205741Z').glob('*'))
paths.update(pathlib.Path('target/lab-state').glob('provision-schema-smokes-20261027T2056*.json'))
aggregates=[json.loads(p.read_text())for p in d.rglob('capture-aggregate.json')];assert len(aggregates)==2
for a in aggregates:assert a['capture_files']==6 and a['packet_records']==112 and a['forbidden_markers']==a['kernel_drops']==0
entries=[]
for p in sorted(paths):
 assert p.is_file();raw=p.read_bytes();entries.append(dict(path=str(p),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()))
workspace=json.loads(pathlib.Path('target/process-inspection-root-verification-20261027/workspace-ee9e454.json').read_text());assert workspace['passed']==354 and workspace['failed']==workspace['exit_code']==0
x=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_binding=c['binding'],workspace=workspace,native_results=rows,program_passes=18,program_failures=0,reviewed_provision_cases=16,provision_case_modes=4,provision_platform_routes=4,normal_regression_cases_per_platform=17,normal_packet_records_per_platform=112,normal_forbidden_markers_per_platform=0,normal_kernel_drops_per_platform=0,entries=entries,previous_failures_preserved=[273,277,278],allnine_complete=False,requirement8_complete=False,real_client_acceptance='NOT_RUN',scope='Partial DOWN-only connected provision/query component checkpoint. Full-report filename-hint parity repaired without reducing validation. Sixteen original-clock success/fault cases and two Starting/observer/daemon packet suites; no original clock renewal, namespace cleanup, operational reuse, DATA move/UP, real provider/client, complete fork/erasure, migration/service lifecycle, router workload or24h acceptance. Current source continues separately.')
destination=d/'partial-checkpoint-index.json'
with destination.open('x')as stream:json.dump(x,stream,indent=2);stream.write('\n')
print(json.dumps(dict(record=str(destination),sha_bound_entries=len(entries),program_passes=18,reviewed_provision_cases=16,allnine_complete=False)))
