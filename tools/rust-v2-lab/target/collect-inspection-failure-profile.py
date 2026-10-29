"""Collect bounded, incomplete handoff and original-job failure diagnostics.

A failed run never becomes successful verification or a router benchmark.
"""
import datetime,hashlib,json,math,pathlib,re,subprocess,sys,tarfile
candidate=json.loads(pathlib.Path(sys.argv[1]).read_text());run=int(sys.argv[2]);assert run>0
path=pathlib.Path(f'target/lab-state/actual-program-run-{run}.json');raw=path.read_bytes();record=json.loads(raw)
assert record['exit_code']!=0 and record['component_test_mode']=='owner_process_inspection'
assert record['real_client_acceptance']=='NOT_RUN' and record['production_changes'] is False
assert record['source_binding']==candidate['binding'] and record['source_archive_sha256']==candidate['source_sha256']
assert record['artifact_sha256'] in {v['artifact_sha256'] for v in candidate['platforms'].values()}
source=pathlib.Path(candidate['source']);assert hashlib.sha256(source.read_bytes()).hexdigest()==candidate['source_sha256']
binding=json.loads(subprocess.check_output([sys.executable,'tools/verify-frozen-build-inputs.py',str(source),candidate['source_commit']]))
assert binding==candidate['binding']
with tarfile.open(source) as archive:
 inspection=archive.extractfile('crates/vprouter-launch/src/inspection.rs').read()
 assert b'LAB_INSPECTION_FAILURE_JOB bound=true' in inspection
 assert b'failure.job.as_ref() != Some(job)' in inspection
rows=[];jobs=[];diagnostics=[];summary=[]
row=re.compile(r'LAB_HANDOFF_PROFILE phase=(\w+) sequence=(\d+) elapsed_us=(\d+) ok=(true|false) original_remaining_us=(\d+)')
job=re.compile(r'LAB_INSPECTION_FAILURE_JOB bound=true stage=(\d+) substage=(\d+) sequence=(\d+) sent_at=([0-9.]+) finished_at=([0-9.]+) elapsed_us=(\d+) original_rpc_remaining_us=(\d+)')
for line in record['stderr'].splitlines():
 m=row.fullmatch(line)
 if m:rows.append(dict(phase=m[1],sequence=int(m[2]),elapsed_us=int(m[3]),ok=m[4]=='true',enclosing_original_remaining_us=int(m[5])))
 m=job.fullmatch(line)
 if m:
  stage,substage,sequence=map(int,m.group(1,2,3));sent,finished=map(float,m.group(4,5));elapsed,remaining=map(int,m.group(6,7))
  assert 0<=stage<=255 and 0<=substage<=255 and sequence>0 and all(math.isfinite(v) for v in (sent,finished)) and 0<sent<=finished
  assert abs(elapsed-(finished-sent)*1000000)<2 and abs(remaining-max(0,sent+2-finished)*1000000)<2
  requests=[z for z in record['stderr'].splitlines() if re.fullmatch(r'LAB_OWNER_REQUEST sequence='+str(sequence)+r' kind=inspect_[a-z_]+',z)]
  assert len(requests)==1
  jobs.append(dict(stage=stage,substage=substage,sequence=sequence,sent_at=sent,finished_at=finished,elapsed_us=elapsed,original_rpc_remaining_us=remaining,request=requests[0]))
 if line.startswith(('LAB_INSPECTION_FAILURE ','LAB_INSPECTION_FAILURE_JOB bound=false','LAB_HANDOFF_PHASE ','LAB_OWNED_GUARD_FAILURE ','LAB_OWNER_TERMINAL ')):diagnostics.append(line)
 if line.startswith('LAB_HANDOFF_PROFILE phase=summary '):summary.append(line)
assert len(rows)<=63 and len(jobs)<=8
phases=('handoff_base','daemon_before_audit','host_and_native_shape','daemon_after_audit','sender_verify');top={}
for phase in phases:
 found=[v for v in rows if v['phase']==phase];assert len(found)<=1
 if found and found[0]['ok']:top[phase]=found[0]['elapsed_us']
out=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),record=str(path),record_sha256=hashlib.sha256(raw).hexdigest(),source_binding=binding,artifact_sha256=record['artifact_sha256'],context_sha256=record['context_sha256'],native_run_exit_code=record['exit_code'],profile_complete=False,profile_rows=rows,completed_disjoint_phases_us=top,completed_disjoint_sum_us=sum(top.values()),original_job_failures=jobs,original_job_diagnostic_status='BOUND' if jobs else 'NOT_LOGGED',summary=summary,diagnostics=diagnostics,real_client_acceptance='NOT_RUN',limit='Failed native component. Partial inclusive RPC spans and exact private original-job failure timing only. Missing rows are not assumed, no full-permission success, cause of target exit, overall router performance or release acceptance is inferred.')
dest=pathlib.Path(f'target/lab-state/inspection-failure-profile-run-{run}.json')
with dest.open('x') as stream:json.dump(out,stream,indent=2);stream.write('\n')
print(json.dumps(dict(sidecar=str(dest),rows=len(rows),completed_disjoint_sum_us=sum(top.values()),original_job_failures=jobs)))
