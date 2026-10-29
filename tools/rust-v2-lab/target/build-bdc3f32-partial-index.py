"""Frozen component checkpoint for all four modes on four local platforms."""
import datetime,hashlib,json,pathlib,subprocess
if not __debug__: raise RuntimeError('optimized_python_refused')
cp=pathlib.Path('target/continuation-20261028T024239Z/candidate.json');c=json.loads(cp.read_text());d=cp.parent
assert json.loads(subprocess.check_output(['python3','tools/verify-frozen-build-inputs.py',c['source'],c['source_commit']]))==c['binding']
assert hashlib.sha256(pathlib.Path(c['source']).read_bytes()).hexdigest()==c['source_sha256']
for arch,v in c['platforms'].items():
 assert hashlib.sha256(pathlib.Path(v['artifact']).read_bytes()).hexdigest()==v['artifact_sha256']
 assert hashlib.sha256((d/(arch+'.context.tar')).read_bytes()).hexdigest()==v['context_sha256']
wpath=pathlib.Path('target/process-inspection-root-verification-20261027/workspace-bdc3f32.json');w=json.loads(wpath.read_text());assert w['passed']==367 and w['failed']==w['exit_code']==0
native=[]
for n in range(346,362):
 raw=pathlib.Path(f'target/lab-state/actual-program-run-{n}.json');r=json.loads(raw.read_text());assert r['source_binding']==c['binding']
 passed=True
 assert (r['exit_code']==0)==passed
 sidepaths=[pathlib.Path(f'target/lab-state/secret-assembly-run-{n}.json')] if passed else [pathlib.Path(f'target/lab-state/{kind}-run-{n}.json') for kind in ('secret-quarantine-failure','secret-quarantine-selector-archive')]
 for p in sidepaths:
  side=json.loads(p.read_text());assert side['record_sha256']==hashlib.sha256(raw.read_bytes()).hexdigest() and side['source_binding']==c['binding']
 if not passed:
  inspection=json.loads(sidepaths[0].read_text());archive=json.loads(sidepaths[1].read_text())
  assert inspection['owner_unit']['LoadState']=='not-found' and inspection['owner_cgroup_exists']is False and len(archive['selectors_archived'])==5
 side=json.loads(sidepaths[0].read_text());assert side['proof']['assembly']['ordered_writers_verified']==69 and side['proof']['assembly']['original_resource_jobs_verified']==15 and side['proof']['assembly']['resources_collected']is False
 native.append(dict(run=n,platform=r['platform'],mode=r['component_test_mode'],result=r['result']))
assert len({(r['platform'],r['mode'])for r in native})==16
names=['target/collect-secret-quarantine.py','target/quarantine_evidence_base.py','target/quarantine_history_schema.py','target/quarantine_native_schema.py','target/quarantine_producer_schema.py','target/wireguard_inventory_schema.py','target/collect-secret-movement.py','target/movement_evidence_base.py','target/collect-secret-provision.py','target/provision_evidence_base.py','target/platform-lab/run-frozen-secret-quarantine.py','target/platform-lab/secret-quarantine.guest.py','target/platform-lab/quarantine_host_declaration.py','target/platform-lab/attachment_context_check.py','target/platform-lab/selftest_mechanics.py','target/verify-frozen-inspection-preflight.py','target/platform-lab/run-native-inspection-preflight.py','target/inspect-secret-quarantine-failure.py','target/archive-secret-quarantine-selectors.py','target/run-frozen-quarantine-modes.py','target/collect-initial-quarantine-failure.py','target/initial_quarantine_failure_schema.py','target/smoke-initial-quarantine-failure.py','target/smoke-wireguard-postcompletion.py','target/smoke-quarantine-own-intent.py','target/smoke-quarantine-fixture-failure.py','target/collect-movement-failure.py','target/movement_failure_schema.py','target/smoke-movement-failure.py','target/collect-secret-assembly.py','target/assembly_evidence_schema.py','target/platform-lab/run-frozen-secret-assembly.py','target/platform-lab/secret-assembly.guest.py','target/run-frozen-assembly-modes.py','target/inspect-secret-assembly-failure.py','target/archive-secret-assembly-selectors.py','target/smoke-assembly-evidence.py','target/smoke-capacity-mechanics.py',__file__]
keepers=d/'root-collectors';keepers.mkdir(mode=0o700)
for name in names:
 path=pathlib.Path(name)
 with(keepers/path.name).open('xb')as stream:stream.write(path.read_bytes())
paths={p for p in d.rglob('*')if p.is_file()and p.suffix in('.json','.py','.stderr','.log')}
for n in range(346,362): paths.update(pathlib.Path('target/lab-state').glob(f'*run-{n}.json'))
paths.update(pathlib.Path('target/process-inspection-root-verification-20261027').glob('*bdc3f32*'));paths.update(pathlib.Path('target').glob('bdc3f32*.log'))
paths.add(pathlib.Path('target/lab-state/assembly-final-controller-preparation-20261028T024257Z/record.json'))
entries=[]
for p in sorted(paths):
 data=p.read_bytes();entries.append(dict(path=str(p),bytes=len(data),sha256=hashlib.sha256(data).hexdigest()))
record=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_binding=c['binding'],workspace=w,native_results=native,program_partial_passes=16,program_failures=0,entries=entries,historical_failures_preserved={'322':'Prior55cf movement Deadline; new diagnostics did not reproduce failure or establish cause/fix.','323':'Prior55cf first NFIntent Deadline; new diagnostics did not reproduce failure or establish cause/fix.'},allnine_complete=False,requirement8_complete=False,real_client_acceptance='NOT_RUN',scope='Exact component checkpoint only. Fresh Debian AMD64, retained Debian AMD64, Arch AMD64 and emulated Debian ARM64 each pass four modes. Historical322/323 failures remain unchanged in55cf checkpoint. All fixture resources remain retained; no cleanup/reuse claim. Exact single-exit15-resource custody handoff with original69 writers/17 windows, separate eligible-foreign checker and failed/gated refusal proofs. Fifteen launch and eleven lower charges retire only when complete; partial/pretransfer fences and duplicate reservation refusal preserve resources. No resource collection, operational publication/UP/provider/client/parentdeathsurvival/actual1-5-6runtime/fullsecret/migration/services/performance/24h acceptance.')
out=d/'partial-checkpoint-index.json'
with out.open('x')as stream:json.dump(record,stream,indent=2);stream.write('\n')
print(json.dumps(dict(record=str(out),sha_bound_entries=len(entries),program_partial_passes=16,program_failures=0,allnine_complete=False)))
