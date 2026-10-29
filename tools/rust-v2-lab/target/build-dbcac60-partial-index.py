"""Retain failed whole-workspace gate; no native program was run for dbc."""
import datetime,hashlib,json,pathlib,subprocess
if not __debug__:raise RuntimeError('optimized_python_refused')
cp=pathlib.Path('target/continuation-20261028T001847Z/candidate.json');c=json.loads(cp.read_text());d=cp.parent
assert json.loads(subprocess.check_output(['python3','tools/verify-frozen-build-inputs.py',c['source'],c['source_commit']]))==c['binding']
assert hashlib.sha256(pathlib.Path(c['source']).read_bytes()).hexdigest()==c['source_sha256']
for arch,v in c['platforms'].items():assert hashlib.sha256(pathlib.Path(v['artifact']).read_bytes()).hexdigest()==v['artifact_sha256']and hashlib.sha256((d/(arch+'.context.tar')).read_bytes()).hexdigest()==v['context_sha256']
workspace_path=pathlib.Path('target/process-inspection-root-verification-20261027/workspace-dbcac60.json');workspace=json.loads(workspace_path.read_text());assert workspace['exit_code']==101 and workspace['passed']==20 and workspace['failed']==1
names=['target/verify-frozen-inspection-preflight.py','target/platform-lab/run-native-inspection-preflight.py','target/platform-lab/selftest_mechanics.py',__file__]
keepers=d/'root-collectors';keepers.mkdir(mode=0o700)
for name in names:
 p=pathlib.Path(name)
 with(keepers/p.name).open('xb')as stream:stream.write(p.read_bytes())
paths={p for p in d.rglob('*')if p.is_file()and p.suffix in('.json','.py','.stderr','.log')};paths.update(pathlib.Path('target/process-inspection-root-verification-20261027').glob('*dbcac60*'));paths.update(pathlib.Path('target').glob('dbcac60*.log'))
diagnostic=pathlib.Path('target/core-lock-race-diagnostic/reproduced-ofd-inheritance.json');paths.add(diagnostic);paths.add(pathlib.Path('target/core-lock-race-diagnostic/core-trace-2.log'))
entries=[]
for p in sorted(paths):data=p.read_bytes();entries.append(dict(path=str(p),bytes=len(data),sha256=hashlib.sha256(data).hexdigest()))
record=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_binding=c['binding'],workspace=workspace,workspace_result='FAIL',native_results=[],program_passes=0,program_failures=0,mechanical_reports_each=5,entries=entries,known_failure='Default-parallel core two_writers final read allocation.rs666 sees LockBusy after joins. Production core unchanged. Separate unchanged-source traced reproduction fails analogous owned_transaction assertion: selfexec inherits CLOEXEC flock OFD during pre-exec window. Original Root failure lacks exact holder trace; preserve both observations. Subsequent fixture-only integration-process isolation belongs to later6c source.',allnine_complete=False,requirement8_complete=False,real_client_acceptance='NOT_RUN',scope='Initial exact artifact/mechanical preflight checkpoint; whole workspace FAILED, no privileged pipeline program run. No native inventory GREEN, nft/cgroup, UP/provider/client, migration/services, full secret lifetime, performance or24h acceptance.')
destination=d/'partial-checkpoint-index.json'
with destination.open('x')as stream:json.dump(record,stream,indent=2);stream.write('\n')
print(json.dumps(dict(record=str(destination),sha_bound_entries=len(entries),workspace_result='FAIL',native_programs=0,allnine_complete=False)))
