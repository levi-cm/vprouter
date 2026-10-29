"""Frozen component checkpoint; preserve eight partial passes and two failures."""
import datetime,hashlib,json,pathlib,subprocess
if not __debug__: raise RuntimeError('optimized_python_refused')
cp=pathlib.Path('target/continuation-20261028T012007Z/candidate.json');c=json.loads(cp.read_text());d=cp.parent
assert json.loads(subprocess.check_output(['python3','tools/verify-frozen-build-inputs.py',c['source'],c['source_commit']]))==c['binding']
assert hashlib.sha256(pathlib.Path(c['source']).read_bytes()).hexdigest()==c['source_sha256']
for arch,v in c['platforms'].items():
 assert hashlib.sha256(pathlib.Path(v['artifact']).read_bytes()).hexdigest()==v['artifact_sha256']
 assert hashlib.sha256((d/(arch+'.context.tar')).read_bytes()).hexdigest()==v['context_sha256']
wpath=pathlib.Path('target/process-inspection-root-verification-20261027/workspace-55cf31c.json');w=json.loads(wpath.read_text());assert w['passed']==363 and w['failed']==w['exit_code']==0
native=[]
for n in range(318,328):
 raw=pathlib.Path(f'target/lab-state/actual-program-run-{n}.json');r=json.loads(raw.read_text());assert r['source_binding']==c['binding']
 passed=n not in (322,323)
 assert (r['exit_code']==0)==passed
 sidepaths=[pathlib.Path(f'target/lab-state/secret-quarantine-run-{n}.json')] if passed else [pathlib.Path(f'target/lab-state/{kind}-run-{n}.json') for kind in ('secret-quarantine-failure','secret-quarantine-selector-archive')]
 for p in sidepaths:
  side=json.loads(p.read_text());assert side['record_sha256']==hashlib.sha256(raw.read_bytes()).hexdigest() and side['source_binding']==c['binding']
 if not passed:
  inspection=json.loads(sidepaths[0].read_text());archive=json.loads(sidepaths[1].read_text())
  assert inspection['owner_unit']['LoadState']=='not-found' and inspection['owner_cgroup_exists']is False and len(archive['selectors_archived'])==5
 native.append(dict(run=n,platform=r['platform'],mode=r['component_test_mode'],result=r['result']))
names=['target/collect-secret-quarantine.py','target/quarantine_evidence_base.py','target/quarantine_history_schema.py','target/quarantine_native_schema.py','target/quarantine_producer_schema.py','target/wireguard_inventory_schema.py','target/collect-secret-movement.py','target/movement_evidence_base.py','target/collect-secret-provision.py','target/provision_evidence_base.py','target/platform-lab/run-frozen-secret-quarantine.py','target/platform-lab/secret-quarantine.guest.py','target/platform-lab/quarantine_host_declaration.py','target/platform-lab/attachment_context_check.py','target/platform-lab/selftest_mechanics.py','target/verify-frozen-inspection-preflight.py','target/platform-lab/run-native-inspection-preflight.py','target/inspect-secret-quarantine-failure.py','target/archive-secret-quarantine-selectors.py','target/run-frozen-quarantine-modes.py','target/collect-initial-quarantine-failure.py','target/initial_quarantine_failure_schema.py','target/smoke-initial-quarantine-failure.py','target/smoke-wireguard-postcompletion.py','target/smoke-quarantine-own-intent.py',__file__]
keepers=d/'root-collectors';keepers.mkdir(mode=0o700)
for name in names:
 path=pathlib.Path(name)
 with(keepers/path.name).open('xb')as stream:stream.write(path.read_bytes())
paths={p for p in d.rglob('*')if p.is_file()and p.suffix in('.json','.py','.stderr','.log')}
for n in range(318,328): paths.update(pathlib.Path('target/lab-state').glob(f'*run-{n}.json'))
paths.update(pathlib.Path('target/process-inspection-root-verification-20261027').glob('*55cf31c*'));paths.update(pathlib.Path('target').glob('55cf31c*.log'))
paths.add(pathlib.Path('target/lab-state/quarantine-own-progress-controller-preparation-20261028T012050Z/record.json'))
entries=[]
for p in sorted(paths):
 data=p.read_bytes();entries.append(dict(path=str(p),bytes=len(data),sha256=hashlib.sha256(data).hexdigest()))
record=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_binding=c['binding'],workspace=w,native_results=native,program_partial_passes=8,program_failures=2,entries=entries,known_failures={'322':'Movement Deadline +10.209ms; canonical result before original end does not prove writer ACK/reap/finalprocess. Unique inner subphase/cause unestablished.','323':'Initial quarantine first NFIntent writer42 pending, Deadline +1.084ms; cached result_issued is prior preparation flag. Fixture checkpoint/release state absent, cause unestablished.'},allnine_complete=False,requirement8_complete=False,real_client_acceptance='NOT_RUN',scope='Exact component checkpoint only. Fresh and retained Debian each pass four modes. ARM/Arch stop at first failed case, remaining modes NOT_RUN. All failed resources retained; only exact public selectors archived after fresh owner absence/original gateway checks. No operational publication/UP/provider/client/parentdeathsurvival/fullsecret/migration/services/performance/24h acceptance.')
out=d/'partial-checkpoint-index.json'
with out.open('x')as stream:json.dump(record,stream,indent=2);stream.write('\n')
print(json.dumps(dict(record=str(out),sha_bound_entries=len(entries),program_partial_passes=8,program_failures=2,allnine_complete=False)))
