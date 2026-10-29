"""Index the completed component checkpoint; current source may have continued."""
import datetime,hashlib,json,pathlib,shutil,subprocess
if not __debug__:raise RuntimeError('optimized_python_refused')
cp=pathlib.Path('target/continuation-20261027T185926Z/candidate.json');c=json.loads(cp.read_text());d=cp.parent
assert json.loads(subprocess.check_output(['python3','tools/verify-frozen-build-inputs.py',c['source'],c['source_commit']]))==c['binding']
assert hashlib.sha256(pathlib.Path(c['source']).read_bytes()).hexdigest()==c['source_sha256']
for arch,v in c['platforms'].items():
 assert hashlib.sha256(pathlib.Path(v['artifact']).read_bytes()).hexdigest()==v['artifact_sha256']
 assert hashlib.sha256((d/(arch+'.context.tar')).read_bytes()).hexdigest()==v['context_sha256']
platforms={}
for p in d.rglob('directory-binding.json'):
 b=json.loads(p.read_text());assert b['source_commit']==c['source_commit']and b['record']not in platforms;platforms[b['record']]=b['platform']
rows=[];paths=set()
for run in range(256,273):
 p=pathlib.Path(f'target/lab-state/actual-program-run-{run}.json');r=json.loads(p.read_text());assert r['source_binding']==c['binding']
 platform=platforms[str(p)];assert r.get('platform',r.get('platform_lab',platform))==platform
 rows.append(dict(run=run,mode=r.get('component_test_mode','actual'),result='PASS'if r['exit_code']==0 else'FAIL',platform=platform))
 paths.update(pathlib.Path('target/lab-state').glob('*run-'+str(run)+'.json'))
 if r.get('component_test_mode','').startswith('secret_attachment_')and r['exit_code']==0:assert pathlib.Path(f'target/lab-state/secret-attachment-run-{run}.json').is_file()
assert {r['run']for r in rows if r['result']=='FAIL'}=={260,264,267}
assert len(rows)==17
collector_names=['target/collect-secret-attachment.py','target/collect-attachment-phase-profile.py','target/inspect-secret-attachment-failure.py','target/archive-secret-attachment-selectors.py','target/collect-owner-retirement-stop.py','target/collect-retirement-input-selection.py','target/collect-handoff-profile.py','target/collect-terminal-witness.py','target/collect-retirement-cleanup-failure.py','target/platform-lab/collect-component-evidence.py','target/run-a8a267-attachment-three.py','target/run-a8a267-owner-regressions.py',__file__]
keepers=d/'root-collectors';keepers.mkdir(mode=0o700)
for name in collector_names:
 source=pathlib.Path(name);target=keepers/source.name
 with target.open('xb')as f:f.write(source.read_bytes())
paths.update(p for p in d.rglob('*')if p.is_file()and p.suffix in('.json','.py','.stderr','.log'))
paths.update(pathlib.Path('target/process-inspection-root-verification-20261027').glob('*a8a267*'))
paths.update(pathlib.Path(p)for p in ['target/signal-poll-frozen-preflight.log','target/signal-poll-arm-preflight.log','target/lab-state/preservation-readonly-20261027T190934Z.json'])
aggregates=[json.loads(p.read_text())for p in d.rglob('capture-aggregate.json')];assert len(aggregates)==3
for a in aggregates:assert a['capture_files']==6 and a['packet_records']==112 and a['forbidden_markers']==a['kernel_drops']==0
entries=[]
for p in sorted(paths):
 assert p.is_file();data=p.read_bytes();entries.append(dict(path=str(p),bytes=len(data),sha256=hashlib.sha256(data).hexdigest()))
x=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_binding=c['binding'],workspace=dict(passed=342,failed=0,ignored=2),native_results=rows,program_passes=14,program_failures=3,reviewed_attachment_cases=7,normal_regression_cases_per_platform=17,normal_packet_records_per_platform=112,normal_forbidden_markers_per_platform=0,normal_kernel_drops_per_platform=0,entries=entries,known_failures={'260':'ARM original inspection deadline before intended placeholder fault; exact cost cause unsampled','264':'ARM cleanup NetworkOperation before second native fence and WG deletion; exact check unproven','267':'Arch publication-fault attempt generic child_failed; source-confirmed checkpoint ACK race, exact failure branch inferred'},allnine_complete=False,requirement8_complete=False,real_client_acceptance='NOT_RUN',scope='Completed partial component checkpoint. All failures and original resource-retention evidence preserved. Signal poll correction and bounded component gates only; current source continues separately. No provider/client/operational launch, cleanup/reuse, full secret-lifetime closure, router benchmark or 24h acceptance.')
p=d/'partial-checkpoint-index.json'
with p.open('x')as f:json.dump(x,f,indent=2);f.write('\n')
print(json.dumps(dict(path=str(p),sha_bound_entries=len(entries),program_passes=14,program_failures=3,attachment_cases=7,allnine_complete=False)))
