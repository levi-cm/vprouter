"""Preserve bounded original-clock phase traces, including failed candidates.

Spans can nest; their durations MUST NOT be summed as disjoint work. The OK bit
is local function progress, not acceptance within the tagged original deadline.
"""
import datetime,hashlib,json,math,pathlib,re,sys,tarfile
if not __debug__:raise RuntimeError('optimized_python_refused')
candidate_path=pathlib.Path(sys.argv[1]);candidate=json.loads(candidate_path.read_text());run=int(sys.argv[2]);path=pathlib.Path(f'target/lab-state/actual-program-run-{run}.json');raw=path.read_bytes();record=json.loads(raw)
assert record['source_binding']==candidate['binding']and record['component_test_mode'].startswith('secret_attachment_')
assert record['source_archive_sha256']==candidate['source_sha256']
arch={'debian-clean-x86_64':'amd64','debian-x86_64':'amd64','arch-x86_64':'amd64','debian-arm64':'arm64'}[record['platform']]
assert record['artifact_sha256']==candidate['platforms'][arch]['artifact_sha256']and record['context_sha256']==candidate['platforms'][arch]['context_sha256']
source=pathlib.Path(candidate['source']);assert hashlib.sha256(source.read_bytes()).hexdigest()==candidate['source_sha256']
with tarfile.open(source)as archive:
 a=archive.extractfile('crates/vprouter-launch/src/attachment.rs').read();m=archive.extractfile('crates/vprouter-launch/src/attachment/mount.rs').read();assert b'Cell::new(48)'in a and b'LAB_ATTACHMENT_PHASE'in a and b'LAB_ATTACHMENT_ORIGINAL_QUERIES'in m
scopes={'initial_result','recheck_result','initial_inspection','recheck_inspection','attachment_constructor','fixture_handoff'}
phases={'accept_original_query','open_native_process','native_process_revalidate','recheck_request_binding','recheck_intent_queue','old_queries_require_and_equality','request_binding_verify','network_identity_and_origin_hash','staging_copy_and_public_binding','final_original_deadline','creator_preflight','old_queries_entry','initial_binding','new_attachment_anchor','public_binding','original_directory_and_namespace_pins','original_origin_binding_and_hash','native_pin_verification','final_old_queries_require','mount_intent_queue','query_receipt_evidence','pending_attachment_new','entry_global_stop','entry_deadline','intent_poll','birth_poll','reading_poll','result_poll'}
rows=[];failure_markers=[];preparations=[];query_receipts=[]
for line in record['stderr'].splitlines():
 if line.startswith('LAB_ATTACHMENT_PHASE '):rows.append(json.loads(line.split(' ',1)[1]))
 if line.startswith('LAB_ATTACHMENT_FAILURE '):failure_markers.append(line)
 if line.startswith('LAB_ATTACHMENT_PREPARATION '):preparations.append(json.loads(line.split(' ',1)[1]))
 if line.startswith('LAB_ATTACHMENT_ORIGINAL_QUERIES '):query_receipts.append(json.loads(line.split(' ',1)[1]))
assert 0<len(rows)<=48 and len(preparations)<=1 and len(query_receipts)<=1
if record['exit_code']!=0:assert failure_markers
output_rows=[];clocks={}
def finite(v):assert type(v)in(int,float)and math.isfinite(v)and v>0;return v
for i,row in enumerate(rows):
 assert row['scope']in scopes and row['phase']in phases and type(row['ok'])is bool
 requested,deadline,finished=map(finite,(row['original_requested_at'],row['original_deadline'],row['finished_at']));assert abs(deadline-requested-2)<0.00001
 key=(row['scope'],requested,deadline);clocks[key]=True
 result=dict(sequence=i,**row,remaining_at_finish_ms=(deadline-finished)*1000,finished_after_original_deadline=finished>=deadline)
 if 'started_at'in row:
  started=finite(row['started_at']);assert requested<=started<=finished;result['elapsed_ms']=(finished-started)*1000
 else:assert row['ok']is False and type(row['reason'])is str and len(row['reason'])<=128
 output_rows.append(result)
if preparations:
 p=preparations[0];assert type(p['writers'])is list
 for writer in p['writers']:
  assert writer['phase']in('intent','birth','result','inspection_intent','inspection_birth','inspection_result','attachment_intent','attachment_birth','attachment_placeholder','attachment_mounted','attachment_query_intent','attachment_query_birth','attachment_query_result','attachment_primary')
  assert type(writer['pid'])is int and writer['pid']>1 and type(writer['start'])is int and writer['start']>0
  assert finite(writer['io_deadline'])==finite(writer['parent_deadline'])
  if writer['verified_at']is not None:assert writer['queued_at']<=finite(writer['verified_at'])<writer['parent_deadline']and writer['actual_wait_status']==0
if query_receipts:
 q=query_receipts[0];assert q['first']['facts']==q['second']['facts']and q['first']['deadline']==q['second']['deadline']==q['inspection_requested_at']+2
 assert q['inspection_requested_at']<=q['inspection_verified_at']<q['second']['deadline']
summary=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),record=str(path),record_sha256=hashlib.sha256(raw).hexdigest(),source_binding=record['source_binding'],artifact_sha256=record['artifact_sha256'],platform=record['platform'],exit_code=record['exit_code'],collector_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),rows=output_rows,phase_count=len(rows),potential_48_record_cap_reached=len(rows)==48,first_local_failure=next((v for v in output_rows if not v['ok']),None),failure_markers=failure_markers,preparation_evidence=preparations[0]if preparations else None,original_query_receipts=query_receipts[0]if query_receipts else None,scope='Bounded parent-side diagnostic spans. Some scopes wrap others; no summed/exclusive CPU attribution. Local OK does not prove original deadline acceptance. No retry, clock reset, native reread/reap or optimization result from this collector.',real_client_acceptance='NOT_RUN',requirement8_complete=False,allnine_complete=False)
destination=pathlib.Path(f'target/lab-state/attachment-phase-profile-run-{run}.json')
with destination.open('x')as f:json.dump(summary,f,indent=2);f.write('\n')
print(json.dumps(dict(record=str(destination),phase_count=len(rows),first_local_failure=summary['first_local_failure'],actual_program_exit_code=record['exit_code'],span_totals_summed=False)))
