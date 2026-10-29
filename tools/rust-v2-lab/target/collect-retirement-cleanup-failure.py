"""Retain original-constructor cleanup timing from a failed frozen lab case.

Cached native fields are not fresh reap observations or cleanup authority.
"""
import datetime,hashlib,json,math,pathlib,subprocess,sys,tarfile
if not __debug__:raise RuntimeError('optimized_python_refused')
from cleanup_failure_diagnostic import parse as parse_diagnostic
candidate=json.loads(pathlib.Path(sys.argv[1]).read_text());run=int(sys.argv[2]);assert run>0
path=pathlib.Path(f'target/lab-state/actual-program-run-{run}.json');raw=path.read_bytes();record=json.loads(raw)
assert record['exit_code']!=0 and record['component_test_mode'] in ('owner_retirement','owner_retirement_host_span')
assert record['real_client_acceptance']=='NOT_RUN' and record['production_changes'] is False
assert record['source_binding']==candidate['binding'] and record['source_archive_sha256']==candidate['source_sha256']
assert record['artifact_sha256'] in {v['artifact_sha256'] for v in candidate['platforms'].values()}
source=pathlib.Path(candidate['source']);assert hashlib.sha256(source.read_bytes()).hexdigest()==candidate['source_sha256']
assert json.loads(subprocess.check_output([sys.executable,'tools/verify-frozen-build-inputs.py',str(source),candidate['source_commit']]))==candidate['binding']
with tarfile.open(source) as archive:
 assert b'LAB_RETIREMENT_CLEANUP_TIMING' in archive.extractfile('crates/vprouter-launch/src/owned.rs').read()
 cleanup_code=archive.extractfile('crates/vprouter-launch/src/kernel/cleanup.rs').read()
 subphase_enabled=b'pid={} start={:?}'in cleanup_code and b'subphase={}'in cleanup_code
rows=[json.loads(line.split(' ',1)[1]) for line in record['stderr'].splitlines() if line.startswith('LAB_RETIREMENT_CLEANUP_TIMING ')]
assert 1<=len(rows)<=3 and rows[-1]['event']=='failure' and sum(v['event']=='failure' for v in rows)==1
for row in rows:
 assert row['event'] in ('launched','checkpoint','failure')
 assert type(row['observed_at']) in (float,int) and math.isfinite(row['observed_at']) and row['observed_at']>0
 native=row['native']
 if native is not None:
  assert set(native)=={'pid','start','original_started_at','original_deadline','actual_wait_status','native_reaped','failed'}
  assert type(native['pid']) is int and native['pid']>1
  assert native['start'] is None or type(native['start']) is int and native['start']>0
  began,end=native['original_started_at'],native['original_deadline']
  assert all(type(v) in (float,int) and math.isfinite(v) and v>0 for v in (began,end)) and abs(end-began-2)<0.00001
  assert native['actual_wait_status'] is None or type(native['actual_wait_status']) is int
  assert type(native['native_reaped']) is type(native['failed']) is bool
failure=rows[-1]
for key in ('checkpoint_at','checkpoint_released_at'):
 value=failure[key];assert value is None or type(value) in (float,int) and math.isfinite(value) and value>0
for key in ('a_at_checkpoint','a_at_release','a_last_completed'):
 value=failure[key];assert value is None or type(value) is int and value>=0
diagnostic=parse_diagnostic(record['stderr'],failure['native'],subphase_enabled)
out=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),record=str(path),record_sha256=hashlib.sha256(raw).hexdigest(),source_binding=record['source_binding'],artifact_sha256=record['artifact_sha256'],context_sha256=record['context_sha256'],collector_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),diagnostic_parser_sha256=hashlib.sha256(pathlib.Path(__file__).with_name('cleanup_failure_diagnostic.py').read_bytes()).hexdigest(),native_run_exit_code=record['exit_code'],timings=rows,diagnostic=diagnostic,real_client_acceptance='NOT_RUN',limit='Failed native retirement component. Original constructor and parent checkpoint/release observations only. Native reap fields are cached, no extra poll is performed to obtain fresh death evidence. Bound subphase names identify the operation entered, not its inner syscall cause. No cleanup/reuse/provider/client/ARM-performance acceptance or unlogged causal attribution.')
dest=pathlib.Path(f'target/lab-state/retirement-cleanup-failure-run-{run}.json')
with dest.open('x') as stream:json.dump(out,stream,indent=2);stream.write('\n')
print(json.dumps(dict(sidecar=str(dest),failure=failure,cached_native_fields_only=True)))
