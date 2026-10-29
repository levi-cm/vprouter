"""Hash-bound partial checkpoint, preserving every failure and its limits."""
import datetime,hashlib,json,pathlib,subprocess
if not __debug__:raise RuntimeError('optimized_python_refused')
cp=pathlib.Path('target/continuation-20261027T210921Z/candidate.json');c=json.loads(cp.read_text());d=cp.parent
assert json.loads(subprocess.check_output(['python3','tools/verify-frozen-build-inputs.py',c['source'],c['source_commit']]))==c['binding']
assert hashlib.sha256(pathlib.Path(c['source']).read_bytes()).hexdigest()==c['source_sha256']
for arch,v in c['platforms'].items():
 assert hashlib.sha256(pathlib.Path(v['artifact']).read_bytes()).hexdigest()==v['artifact_sha256']
 assert hashlib.sha256((d/(arch+'.context.tar')).read_bytes()).hexdigest()==v['context_sha256']
by_record={}
for p in d.rglob('directory-binding.json'):
 b=json.loads(p.read_text());assert b['source_commit']==c['source_commit']and b['record']not in by_record;by_record[b['record']]=b
rows=[];paths=set()
for run in range(273,278):
 p=pathlib.Path(f'target/lab-state/actual-program-run-{run}.json');r=json.loads(p.read_text());assert r['source_binding']==c['binding'];b=by_record[str(p)];assert b['platform']==r.get('platform',r.get('platform_lab',b['platform']))
 rows.append(dict(run=run,mode=r.get('component_test_mode','actual'),result='PASS'if r['exit_code']==0 else'FAIL',platform=b['platform']))
 paths.update(pathlib.Path('target/lab-state').glob('*run-'+str(run)+'.json'))
assert {r['run']for r in rows if r['result']=='FAIL'}=={273,277}
for run in (274,275,276):
 p=pathlib.Path(f'target/lab-state/secret-attachment-run-{run}.json');w=json.loads(p.read_text())['witness'];assert w['normal_ack_ready_preserved']is True
names=['target/collect-secret-provision.py','target/provision_evidence_base.py','target/smoke-provision-evidence.py','target/inspect-secret-provision-failure.py','target/archive-secret-provision-selectors.py','target/platform-lab/run-frozen-secret-provision.py','target/platform-lab/secret-provision.guest.py','target/platform-lab/attachment_context_check.py','target/collect-secret-attachment.py','target/platform-lab/run-frozen-secret-attachment.py','target/platform-lab/secret-attachment.guest.py','target/collect-retirement-cleanup-failure.py','target/cleanup_failure_diagnostic.py','target/collect-retirement-input-selection.py','target/inspect-expiry-drop-failure.py','target/inspect-expiry-drop-deny.py','target/drain-retirement-failure-guard.py','target/archive-failed-owner-nonce.py',__file__]
keepers=d/'root-collectors';keepers.mkdir(mode=0o700)
for name in names:
 p=pathlib.Path(name);snapshot=keepers/p.name
 with snapshot.open('xb')as stream:stream.write(p.read_bytes())
paths.update(p for p in d.rglob('*')if p.is_file()and p.suffix in('.json','.py','.stderr','.log'))
paths.update(pathlib.Path('target/process-inspection-root-verification-20261027').glob('*efd8bf6*'))
paths.update(pathlib.Path('target').glob('efd8bf6*.log'))
paths.update(pathlib.Path('target/lab-state/provision-controller-preparation-20261027T205741Z').glob('*'))
paths.update(pathlib.Path('target/lab-state').glob('provision-schema-smokes-20261027T2056*.json'))
paths.update(pathlib.Path('target/lab-state').glob('cleanup-subphase-parser-smokes-20261027T210602Z.json'))
paths.add(pathlib.Path('target/lab-state/preservation-readonly-20261027T204611Z.json'))
paths.add(pathlib.Path('target/connected-provision-static-build.log'));paths.add(pathlib.Path('target/connected-provision-static-build-v2.log'))
entries=[]
for p in sorted(paths):
 assert p.is_file();raw=p.read_bytes();entries.append(dict(path=str(p),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()))
workspace=json.loads(pathlib.Path('target/process-inspection-root-verification-20261027/workspace-efd8bf6.json').read_text());assert workspace['exit_code']==workspace['failed']==0
record=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_binding=c['binding'],workspace=workspace,native_results=rows,program_passes=3,program_failures=2,reviewed_attachment_ack_cases=3,entries=entries,known_failures={'273':'Provision executing NetworkOperation about31ms into original2s; actual child status/subcause unobserved; canonical transport/socket records are not a substitute for missing native success receipts','277':'Original cleanup parent deadline after checkpoint/release with353.698ms remaining; no child diagnostic/reap status; not the earlier264 predelete NetworkOperation'},allnine_complete=False,requirement8_complete=False,real_client_acceptance='NOT_RUN',scope='Partial connected-source checkpoint and three reviewed actual attachment ACK regressions. Provision/query acceptance failed. Original failed resources retained; precise actor containment grants no original parent reap, cleanup or reuse. Local schema smokes are not native acceptance. No provider/client/operational runtime, migration/lifecycle, full secret erasure, router benchmark or24h acceptance. Live source continues separately.')
destination=d/'partial-checkpoint-index.json'
with destination.open('x')as stream:json.dump(record,stream,indent=2);stream.write('\n')
print(json.dumps(dict(record=str(destination),sha_bound_entries=len(entries),program_passes=3,program_failures=2,allnine_complete=False)))
