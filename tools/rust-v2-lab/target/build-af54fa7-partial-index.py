"""Immutable partial checkpoint; failed315 never becomes native acceptance."""
import datetime,hashlib,json,pathlib,subprocess
if not __debug__:raise RuntimeError('optimized_python_refused')
cp=pathlib.Path('target/continuation-20261027T235636Z/candidate.json');c=json.loads(cp.read_text());d=cp.parent
assert json.loads(subprocess.check_output(['python3','tools/verify-frozen-build-inputs.py',c['source'],c['source_commit']]))==c['binding']
assert hashlib.sha256(pathlib.Path(c['source']).read_bytes()).hexdigest()==c['source_sha256']
for arch,v in c['platforms'].items():
 assert hashlib.sha256(pathlib.Path(v['artifact']).read_bytes()).hexdigest()==v['artifact_sha256']and hashlib.sha256((d/(arch+'.context.tar')).read_bytes()).hexdigest()==v['context_sha256']
raw=pathlib.Path('target/lab-state/actual-program-run-315.json');r=json.loads(raw.read_text());assert r['exit_code']!=0 and r['source_binding']==c['binding']and r['component_test_mode']=='secret_quarantine_success'
inspection=json.loads(pathlib.Path('target/lab-state/secret-quarantine-failure-run-315.json').read_text());diagnostic=json.loads(pathlib.Path('target/lab-state/quarantine-wireguard-failure-run-315.json').read_text());archive=json.loads(pathlib.Path('target/lab-state/secret-quarantine-selector-archive-run-315.json').read_text())
assert all(v['record_sha256']==hashlib.sha256(raw.read_bytes()).hexdigest()and v['source_binding']==c['binding']for v in[inspection,diagnostic,archive])
assert inspection['owner_unit']['LoadState']=='not-found'and inspection['owner_cgroup_exists']is False and len(archive['selectors_archived'])==5
row=diagnostic['diagnostics'][0];assert row['actual_wait_status']==0 and row['durable_birth_bound']is True and row['parent_stage']==6 and row['diagnostic_bound']is False
workspace_path=pathlib.Path('target/process-inspection-root-verification-20261027/workspace-af54fa7.json');workspace=json.loads(workspace_path.read_text());assert workspace['passed']==363 and workspace['failed']==workspace['exit_code']==0
names=['target/collect-secret-quarantine.py','target/quarantine_evidence_base.py','target/quarantine_history_schema.py','target/quarantine_native_schema.py','target/quarantine_producer_schema.py','target/collect-secret-movement.py','target/movement_evidence_base.py','target/collect-secret-provision.py','target/provision_evidence_base.py','target/platform-lab/run-frozen-secret-quarantine.py','target/platform-lab/secret-quarantine.guest.py','target/platform-lab/quarantine_host_declaration.py','target/platform-lab/attachment_context_check.py','target/platform-lab/selftest_mechanics.py','target/verify-frozen-inspection-preflight.py','target/platform-lab/run-native-inspection-preflight.py','target/run-frozen-quarantine-modes.py','target/inspect-secret-quarantine-failure.py','target/archive-secret-quarantine-selectors.py','target/collect-quarantine-wireguard-failure.py',__file__]
keepers=d/'root-collectors';keepers.mkdir(mode=0o700)
for name in names:
 p=pathlib.Path(name)
 with(keepers/p.name).open('xb')as stream:stream.write(p.read_bytes())
paths={p for p in d.rglob('*')if p.is_file()and p.suffix in('.json','.py','.stderr','.log')}
paths.update(pathlib.Path('target/lab-state').glob('*run-315.json'));paths.update(pathlib.Path('target/process-inspection-root-verification-20261027').glob('*af54fa7*'));paths.update(pathlib.Path('target').glob('af54fa7*.log'))
for folder in ['quarantine-full-controller-preparation-20261028T000307Z','quarantine-producer-observer-red-20261028T000420Z']:
 paths.update(pathlib.Path('target/lab-state',folder).glob('*'))
for name in ['quarantine-producer-smokes-20261028T000427Z.json','selftest-mechanics-smokes-20261027T235907Z.json','preservation-readonly-20261027T231237Z.json']:paths.add(pathlib.Path('target/lab-state',name))
entries=[]
for p in sorted(paths):data=p.read_bytes();entries.append(dict(path=str(p),bytes=len(data),sha256=hashlib.sha256(data).hexdigest()))
record=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_binding=c['binding'],workspace=workspace,native_results=[dict(run=315,platform=r['platform'],mode=r['component_test_mode'],result='FAIL')],program_passes=0,program_failures=1,mechanical_preflight_platforms=['root-amd64','debian-arm64'],mechanical_reports_each=5,entries=entries,known_failure='315 actual original Provision child20871/start5478281 exits0; durable Birth present but canonical result/time absent. Parent rejects~47ms into unchanged2s, last recorded stage6. Frozen-source review identifies empty consumed Child inventory access after Completed transfer and async yield; narrow repair/native GREEN pending. No unique inner native syscall failure inferred.',allnine_complete=False,requirement8_complete=False,real_client_acceptance='NOT_RUN',scope='Frozen-source workspace/mechanical component checkpoint with one FAILED connected native pipeline. Exact five public selectors archived only after fresh owner absence/original gateway identity. All namespaces, mounts, gateway, synthetic profiles and canonical resources retained. No quarantine/producer runtime success, UP/provider/client, cleanup/reuse, full secret lifetime, migration, service, benchmark or24h acceptance. Later source repairs are separate.')
destination=d/'partial-checkpoint-index.json'
with destination.open('x')as stream:json.dump(record,stream,indent=2);stream.write('\n')
print(json.dumps(dict(record=str(destination),sha_bound_entries=len(entries),program_passes=0,program_failures=1,allnine_complete=False)))
