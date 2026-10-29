import pathlib,json,hashlib,datetime,subprocess
if not __debug__:raise RuntimeError('optimized_python_refused')
candidate_path=pathlib.Path('target/continuation-20261027T164048Z/candidate.json');candidate=json.loads(candidate_path.read_text());directory=candidate_path.parent
binding=json.loads(subprocess.check_output(['python3','tools/verify-frozen-build-inputs.py',candidate['source'],candidate['source_commit']]));assert binding==candidate['binding']
platforms={}
for p in directory.rglob('directory-binding.json'):
 b=json.loads(p.read_text());assert b['source_commit']==candidate['source_commit'];assert b['record']not in platforms;platforms[b['record']]=b['platform']
paths=set(directory.rglob('*.json'))|set(directory.rglob('*.py'))|set(directory.rglob('*.stderr'));rows=[]
for run in range(225,253):
 p=pathlib.Path(f'target/lab-state/actual-program-run-{run}.json');r=json.loads(p.read_text());assert r['source_binding']==binding;paths.add(p)
 platform=platforms[str(p)];assert r.get('platform',r.get('platform_lab',platform))==platform
 rows.append(dict(run=run,mode=r.get('component_test_mode','actual'),result='PASS'if r['exit_code']==0 else'FAIL',platform=platform))
 if r.get('component_test_mode','').startswith('secret_preparation_')and r['exit_code']==0:paths.add(pathlib.Path(f'target/lab-state/secret-preparation-run-{run}.json'))
paths|=set(pathlib.Path('target/lab-state').glob('secret-preparation-*225.json'))
paths|={pathlib.Path('target/lab-state/secret-preparation-controller-correction-20261027.json'),pathlib.Path('target/lab-state/secret-preparation-controller-preparation-20261027.json'),pathlib.Path('target/lab-state/preservation-readonly-20261027T165314Z.json')}
paths|=set(pathlib.Path('target/process-inspection-root-verification-20261027').glob('*62dae90*'))
for name in ['target/collect-secret-preparation.py','target/platform-lab/run-frozen-secret-preparation.py','target/platform-lab/secret-preparation.guest.py','target/inspect-secret-preparation-failure.py','target/archive-secret-preparation-selectors.py','target/secret-preparation-frozen-preflight.log',__file__]:paths.add(pathlib.Path(name))
assert sum(row['result']=='FAIL'for row in rows)==1
aggregates=[json.loads(p.read_text())for p in directory.rglob('capture-aggregate.json')];assert len(aggregates)==3
for a in aggregates:assert a['capture_files']==6 and a['packet_records']==112 and a['forbidden_markers']==a['kernel_drops']==0
entries=[]
for p in sorted(paths):
 assert p.is_file(),p;data=p.read_bytes();entries.append(dict(path=str(p),bytes=len(data),sha256=hashlib.sha256(data).hexdigest()))
summary=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_commit=candidate['source_commit'],source_archive_sha256=candidate['source_sha256'],binding=binding,workspace=dict(passed=333,failed=0,ignored=2),native_results=rows,independently_reviewed_validation_cases=24,emitted_validation_case_plus_witness_events=48,separate_failed_admission_setup_run=225,normal_regression_cases_per_platform=17,normal_capture_records_per_platform=112,normal_forbidden_markers_per_platform=0,normal_kernel_drops_per_platform=0,entries=entries,allnine_complete=False,requirement8_complete=False,real_client_acceptance='NOT_RUN',scope='Completed partial validation component checkpoint. Failed225 preserved. Does not assert current source remains frozen after ordinary continuation GO or public runtime/provider/client/whole-no-fork/performance acceptance.')
p=directory/'partial-checkpoint-index.json'
with p.open('x')as f:json.dump(summary,f,indent=2);f.write('\n')
print(json.dumps(dict(path=str(p),sha_bound_entries=len(entries),passes=27,failures=1,validation_cases=24,scope=summary['scope'])))
