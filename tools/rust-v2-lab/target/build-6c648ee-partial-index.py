"""Corrected inventory/core gates pass; first quarantine attempt remains failed."""
import datetime,hashlib,json,pathlib,subprocess
if not __debug__:raise RuntimeError('optimized_python_refused')
cp=pathlib.Path('target/continuation-20261028T003306Z/candidate.json');c=json.loads(cp.read_text());d=cp.parent
assert json.loads(subprocess.check_output(['python3','tools/verify-frozen-build-inputs.py',c['source'],c['source_commit']]))==c['binding']
assert hashlib.sha256(pathlib.Path(c['source']).read_bytes()).hexdigest()==c['source_sha256']
for arch,v in c['platforms'].items():assert hashlib.sha256(pathlib.Path(v['artifact']).read_bytes()).hexdigest()==v['artifact_sha256']and hashlib.sha256((d/(arch+'.context.tar')).read_bytes()).hexdigest()==v['context_sha256']
workspace_path=pathlib.Path('target/process-inspection-root-verification-20261027/workspace-6c648ee.json');workspace=json.loads(workspace_path.read_text());assert workspace['passed']==363 and workspace['failed']==workspace['exit_code']==0
raw=pathlib.Path('target/lab-state/actual-program-run-316.json');r=json.loads(raw.read_text());assert r['exit_code']!=0 and r['source_binding']==c['binding']
inspection=json.loads(pathlib.Path('target/lab-state/secret-quarantine-failure-run-316.json').read_text());archive=json.loads(pathlib.Path('target/lab-state/secret-quarantine-selector-archive-run-316.json').read_text())
assert all(v['record_sha256']==hashlib.sha256(raw.read_bytes()).hexdigest()and v['source_binding']==c['binding']for v in[inspection,archive])
assert inspection['owner_unit']['LoadState']=='not-found'and inspection['owner_cgroup_exists']is False and len(archive['selectors_archived'])==5
preparations=[e['preparation']for e in inspection['canonical']['namespaces.json']['entries']if e.get('preparation')];assert len(preparations)==1
p=preparations[0];assert len(p['wireguard'])==5 and all(h['result']is not None and h['verified_at']is not None for h in p['wireguard'])and not p.get('netfilter')
names=['target/collect-secret-quarantine.py','target/quarantine_evidence_base.py','target/quarantine_history_schema.py','target/quarantine_native_schema.py','target/quarantine_producer_schema.py','target/wireguard_inventory_schema.py','target/collect-secret-movement.py','target/movement_evidence_base.py','target/collect-secret-provision.py','target/provision_evidence_base.py','target/platform-lab/run-frozen-secret-quarantine.py','target/platform-lab/secret-quarantine.guest.py','target/platform-lab/quarantine_host_declaration.py','target/platform-lab/attachment_context_check.py','target/platform-lab/selftest_mechanics.py','target/verify-frozen-inspection-preflight.py','target/platform-lab/run-native-inspection-preflight.py','target/inspect-secret-quarantine-failure.py','target/archive-secret-quarantine-selectors.py','target/run-frozen-quarantine-modes.py',__file__]
keepers=d/'root-collectors';keepers.mkdir(mode=0o700)
for name in names:
 path=pathlib.Path(name)
 with(keepers/path.name).open('xb')as stream:stream.write(path.read_bytes())
paths={p for p in d.rglob('*')if p.is_file()and p.suffix in('.json','.py','.stderr','.log')};paths.update(pathlib.Path('target/lab-state').glob('*run-316.json'));paths.update(pathlib.Path('target/process-inspection-root-verification-20261027').glob('*6c648ee*'));paths.update(pathlib.Path('target').glob('6c648ee*.log'))
paths.add(pathlib.Path('target/lab-state/wireguard-postcompletion-smokes-20261028T002310Z.json'));paths.add(pathlib.Path('target/core-lock-race-diagnostic/isolation-green.json'))
entries=[]
for path in sorted(paths):data=path.read_bytes();entries.append(dict(path=str(path),bytes=len(data),sha256=hashlib.sha256(data).hexdigest()))
record=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_binding=c['binding'],workspace=workspace,native_results=[dict(run=316,platform=r['platform'],mode=r['component_test_mode'],result='FAIL')],program_passes=0,program_failures=1,entries=entries,known_failure='316 OwnershipMismatch inside initial-quarantine polling after constructor succeeded. Five WG histories committed including move; no netfilter history or post42 journal-start observed. First request/prefix/proposal/queue boundary remains unlocalized; do not call this a native nft/kernel failure. Scalar diagnostic continuation is separate.',allnine_complete=False,requirement8_complete=False,real_client_acceptance='NOT_RUN',scope='167-source and363workspace/exact mechanical checkpoint with FAILED connected pipeline. Original315 and dbc workspace failures retained separately. Exact five public selectors archived after fresh owner absence/original gateway pin checks; all resources retained/no signals or unmount. No native quarantine/cgroup/UP/provider/client, assembly/reuse, full secret lifetime, migration/services, performance or24h acceptance.')
destination=d/'partial-checkpoint-index.json'
with destination.open('x')as stream:json.dump(record,stream,indent=2);stream.write('\n')
print(json.dumps(dict(record=str(destination),sha_bound_entries=len(entries),program_passes=0,program_failures=1,allnine_complete=False)))
