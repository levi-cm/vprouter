"""Preserve original binding success and failed injected-fault checkpoint."""
import datetime,hashlib,json,pathlib,subprocess
if not __debug__:raise RuntimeError('optimized_python_refused')
cp=pathlib.Path('target/continuation-20261028T043804Z/candidate.json');c=json.loads(cp.read_text());d=cp.parent
assert json.loads(subprocess.check_output(['python3','tools/verify-frozen-build-inputs.py',c['source'],c['source_commit']]))==c['binding']
assert hashlib.sha256(pathlib.Path(c['source']).read_bytes()).hexdigest()==c['source_sha256']
for arch,v in c['platforms'].items():assert hashlib.sha256(pathlib.Path(v['artifact']).read_bytes()).hexdigest()==v['artifact_sha256']and hashlib.sha256((d/(arch+'.context.tar')).read_bytes()).hexdigest()==v['context_sha256']
workspace=json.loads(pathlib.Path('target/process-inspection-root-verification-20261027/workspace-a95ac92.json').read_text());assert workspace['passed']==369 and workspace['failed']==workspace['exit_code']==0
rows=[]
for n in(367,368):
 p=pathlib.Path(f'target/lab-state/actual-program-run-{n}.json');raw=p.read_bytes();r=json.loads(raw);assert r['source_binding']==c['binding'] and (r['exit_code']==0)==(n==367)
 names=[f'secret-producer-binding-run-{n}.json']if n==367 else[f'secret-producer-binding-failure-run-{n}.json',f'secret-producer-binding-selector-archive-run-{n}.json',f'producer-binding-postfault-run-{n}.json']
 for name in names:
  x=json.loads((pathlib.Path('target/lab-state')/name).read_text());assert x['record_sha256']==hashlib.sha256(raw).hexdigest()and x['source_binding']==c['binding']
 if n==368:
  archive=json.loads((pathlib.Path('target/lab-state')/f'secret-producer-binding-selector-archive-run-{n}.json').read_text());assert archive['signals_or_unmounts']is False and len(archive['selectors_archived'])==5
  assert x['diagnostic']['phase']=='charge_and_creating_boundary' and x['diagnostic']['charges']==[2,1] and x['diagnostic']['preparation']['mutation_fenced']is True and x['diagnostic']['preparation']['canonical_pending']is True
 rows.append(dict(run=n,platform=r['platform'],mode=r['component_test_mode'],result=r['result']))
source_names=['platform-lab/run-frozen-secret-producer-binding.py','platform-lab/secret-producer-binding.guest.py','run-frozen-producer-binding-modes.py','inspect-secret-producer-binding-failure.py','archive-secret-producer-binding-selectors.py','collect-secret-producer-binding.py','producer_binding_evidence_schema.py','collect-secret-assembly.py','assembly_evidence_schema.py','collect-secret-quarantine.py','quarantine_evidence_base.py','quarantine_history_schema.py','quarantine_native_schema.py','quarantine_producer_schema.py','collect-secret-movement.py','movement_evidence_base.py','collect-secret-provision.py','provision_evidence_base.py','wireguard_inventory_schema.py','platform-lab/selftest_mechanics.py','platform-lab/attachment_context_check.py','platform-lab/quarantine_host_declaration.py','smoke-producer-binding-evidence.py','smoke-producer-netfilter-mechanics.py','smoke-assembly-continuation.py','collect-producer-binding-postfault.py','producer_binding_postfault_schema.py','smoke-producer-binding-postfault.py']
keepers=d/'root-collectors';keepers.mkdir(mode=0o700)
for name in source_names:
 p=pathlib.Path('target')/name
 with(keepers/p.name).open('xb')as f:f.write(p.read_bytes())
with(keepers/pathlib.Path(__file__).name).open('xb')as f:f.write(pathlib.Path(__file__).read_bytes())
paths={p for p in d.rglob('*')if p.is_file()and p.suffix in('.json','.py','.stderr','.log')}
for n in(367,368):paths.update(pathlib.Path('target/lab-state').glob(f'*run-{n}.json'))
paths.update(pathlib.Path('target/process-inspection-root-verification-20261027').glob('*a95ac92*'));paths.update(pathlib.Path('target').glob('a95ac92*.log'));paths.add(pathlib.Path('target/lab-state/producer-binding-controller-preparation-20261028T040452Z/record.json'))
entries=[]
for p in sorted(paths):
 raw=p.read_bytes();entries.append(dict(path=str(p),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()))
x=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_binding=c['binding'],workspace=workspace,native_results=rows,program_partial_passes=1,program_failures=1,entries=entries,known_failure='368 result-failure stopped at charge_and_creating_boundary, cached retained charges[2,1] vs frozen fixture expected[1,1].75 writers, global fence and canonical pending true; actual final Journal writer status9. No canonical producer. Retained failed-writer charge semantics under independent investigation; no correction or source defect claimed yet. Historical365/366 preserved separately.',allnine_complete=False,requirement8_complete=False,real_client_acceptance='NOT_RUN',scope='177-source/369-workspace/exact seven-report AMD+ARM initial proof plus reviewed corrected postbirth367 PASS73writers18windows/original failed owner two-poll stability and seven final anchors. Failed Result writer368 preserved, registration and success modes NOT_RUN on a95. Exact five public selectors archived after fresh owner absence/original gateway pin checks; all resources retained, no signals/unmount/private profile reads. No placement/healthREADY/UP/reuse/multi-exit/fullsecret/runtime/client/migration/lifecycle/performance/24h acceptance.')
out=d/'partial-checkpoint-index.json'
with out.open('x')as f:json.dump(x,f,indent=2);f.write('\n')
print(json.dumps(dict(record=str(out),sha_bound_entries=len(entries),program_partial_passes=1,program_failures=1,allnine_complete=False)))
