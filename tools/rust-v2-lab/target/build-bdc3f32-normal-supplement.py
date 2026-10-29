"""Supplement closed component checkpoint with two normal packet regressions."""
import datetime,hashlib,json,pathlib
if not __debug__:raise RuntimeError('optimized_python_refused')
root=pathlib.Path('target/continuation-20261028T024239Z');candidate=json.loads((root/'candidate.json').read_text());parent=root/'partial-checkpoint-index.json';parent_bytes=parent.read_bytes();index=json.loads(parent_bytes)
assert index['program_partial_passes']==16 and index['program_failures']==0 and index['allnine_complete']is False
for item in index['entries']:
 data=pathlib.Path(item['path']).read_bytes();assert len(data)==item['bytes']and hashlib.sha256(data).hexdigest()==item['sha256']
paths={pathlib.Path(__file__)};runs=[]
for n,platform,label in[(362,'debian-clean-x86_64','amd64-clean-bdc3f32-regression'),(363,'arch-x86_64','arch-bdc3f32-regression')]:
 p=pathlib.Path(f'target/lab-state/actual-program-run-{n}.json');r=json.loads(p.read_text());assert r['source_binding']==candidate['binding']and r['exit_code']==0 and r['real_client_acceptance']=='NOT_RUN'and r['production_changes']is False
 rows=[]
 for line in r['stdout'].splitlines():
  try:e=json.loads(line)
  except ValueError:continue
  if 'case'in e:rows.append(e)
 assert len(rows)==17 and len({x['case']for x in rows})==17 and all(x['result']=='pass'for x in rows)
 d=root/label;b=json.loads((d/'directory-binding.json').read_text());a=json.loads((d/'capture-aggregate.json').read_text());captures=json.loads((d/'captures.json').read_text())
 assert b['source_commit']==candidate['source_commit']and b['record']==str(p)and b['platform']==platform and len(b['new_directories'])==1
 assert a['capture_files']==6 and a['packet_records']==112 and a['forbidden_markers']==a['kernel_drops']==0 and a['real_client_acceptance']=='NOT_RUN'
 assert captures['read_only']is True and captures['production_changes']is False
 for cap in captures['captures']:assert cap['status']=='FRAMING_VERIFIED'and cap['records']==cap['capture_counters']['captured']and cap['capture_counters']['dropped_by_kernel']==cap['marker_occurrences']['forbidden_prefix']==0
 runs.append(dict(run=n,platform=platform,cases=rows,capture_summary=a))
 paths.add(p);paths.add(pathlib.Path(f'target/bdc3f32-native{n}.root.log'));paths.update(q for q in d.rglob('*')if q.is_file())
entries=[]
for p in sorted(paths):
 data=p.read_bytes();entries.append(dict(path=str(p),bytes=len(data),sha256=hashlib.sha256(data).hexdigest()))
out=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_binding=candidate['binding'],parent_index=str(parent),parent_index_sha256=hashlib.sha256(parent_bytes).hexdigest(),parent_index_entries=len(index['entries']),normal_regressions=runs,entries=entries,allnine_complete=False,requirement8_complete=False,real_client_acceptance='NOT_RUN',scope='Two isolated Starting/observer/daemon packet suites only. 17 cases each, six captures/112 records each with positive controls and zero forbidden markers/kernel drops. Parent16-case checkpoint preserved unchanged. No operational producer publication, full secret-lifetime closure, provider/client, migration, lifecycle, performance or24h acceptance. Historical322/323 failures remain unresolved.')
p=root/'normal-regression-supplement.json'
with p.open('x')as f:json.dump(out,f,indent=2);f.write('\n')
print(json.dumps(dict(record=str(p),parent_entries=len(index['entries']),supplement_entries=len(entries),normal_cases=34,allnine_complete=False)))
