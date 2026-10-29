"""Strict frozen synthetic DOWN-WireGuard pipeline evidence; no release claim."""
import datetime,hashlib,json,pathlib,re,sys
if not __debug__:raise RuntimeError('optimized_python_refused')
from provision_evidence_base import validate_prefix
from wireguard_inventory_schema import validate_postcompletion_inventory

def validate_pipeline(c,continuation=False):
 w=c['top'];fault=c['provision_fault'];old=c['p'];p=w['preparation'];integer=c['integer'];finite=c['finite'];identity=c['identity'];clock=c['original_clock'];birth=c['birth'];ids=c['ids'];gateway=c['gateway'];descriptor=c['descriptor']
 assert fault in (0,1,2,3)
 assert all(w[k]is True for k in ['parent_pristine','same_service_retained','transport_distinct_from_host_and_data','original_socket_registrations_borrowed'])
 if continuation:
  assert fault==0 and w['whole_context_retained_after_drop']is False and w['continued_original_context']is True
 else:
  assert w['whole_context_retained_after_drop']is True and w.get('continued_original_context',False)is False
 assert all(w[k]is False for k in ['host_resources_created','operational_reuse_authorized','requirement8_complete'])
 assert w['unacknowledged_native_result_retained']is(fault==2)and w['held_real_result_writer']is(fault==2)and w['wireguard_down_only']is(fault in (0,2))
 for k in ['member','requested_at','deadline','birth','canonical_owner_epoch','base_network','data_network','inspection','attachment','owner_host_anchor_present','canonical_result_present','service_reserved']:
  assert p[k]==old[k],k
 assert p['writers'][:17]==old['writers']and len(old['writers'])==17
 assert p['base_network_absent']is False and p['native_children_reaped']is True and p['member_native_jobs_collected']is False
 assert p['canonical_pending']is p['mutation_fenced']is(fault==2)
 creation=w['transport_creation'];mount=w['transport_mount'];history=p['fresh_transport'];mounted=history['mount'];operations=w['operations'];histories=p['wireguard'];writers=p['writers']
 def digest(v):assert isinstance(v,list)and len(v)==32 and any(v)and all(type(x)is int and 0<=x<=255 for x in v);return v
 def original(o):clock(o['requested_at'],o['deadline']);birth(o['birth'],o['requested_at'],o['deadline']);assert o['actual_wait_status']==0
 original(creation);original(mount)
 assert creation['eof']is creation['original_source_retained']is creation['durable_birth_released']is True
 assert identity(creation['host'])==gateway['host_network_namespace']and identity(creation['data'])==gateway['source_namespace']
 assert creation['source']!=creation['host']and creation['source']!=creation['data'];identity(creation['source'])
 assert creation['birth']['born_at']<=finite(creation['verified_at'])<creation['deadline']
 assert c['w']['preparation']['attachment']['published_at']<=creation['requested_at']
 for k in ['request','host','data','source','requested_at','deadline','birth','verified_at']:assert history[k]==creation[k],k
 digest(history['request']);identity(history['directory']);assert isinstance(history['name'],str)and history['name']
 allocation=descriptor['allocation'];selected=[e for e in allocation['exits']if e['exit_id']==descriptor['primary']];assert len(selected)==1;allocated=selected[0]
 assert history['name']==allocated['transport_namespace']
 assert creation['verified_at']<=mount['requested_at']and mount['original_source']==creation['source']==p['transport_network']
 assert all(mount[k]is True for k in ['eof','original_placeholder_retained','original_mounted_namespace_retained'])
 assert mount['released_gates']==mount['received_packets']==2
 assert mount['original_directory']==history['directory'];placeholder=mount['placeholder'];identity(placeholder['identity']);assert placeholder['mode']==0o100600 and placeholder['identity']['dev']==history['directory']['dev']
 for k,new in [('source','original_source'),('directory','original_directory'),('birth','birth'),('placeholder','placeholder'),('requested_at','requested_at'),('deadline','deadline')]:assert mounted[k]==mount[new],k
 digest(mounted['request']);assert mounted['name']==history['name']
 assert mount['birth']['born_at']<=finite(mounted['mounted_at'])<=finite(mounted['published_at'])<mount['deadline']
 phases=['transport_intent','transport_birth','transport_source','transport_mount_intent','transport_mount_birth','transport_mount_placeholder','transport_mount_publication']+['wireguard_intent','wireguard_birth','wireguard_result']*3
 count={0:33,1:25,2:30,3:25}[fault];assert len(writers)==count and [v['phase']for v in writers[17:]]==phases[:count-17]
 assert len(histories)=={0:3,1:1,2:2,3:1}[fault]and len(operations)=={0:3,1:0,2:2,3:0}[fault]
 windows=[(creation['requested_at'],creation['deadline'])]*3+[(mount['requested_at'],mount['deadline'])]*4
 for i,h in enumerate(histories):
  assert h['kind']==['sockets','provision','query'][i]and h['namespace']==creation['source'];digest(h['request']);digest(h['configuration']);clock(h['requested_at'],h['deadline'])
  assert h['requested_at']>=(mounted['published_at']if i==0 else histories[i-1]['verified_at'])
  if i:assert h['configuration']==histories[0]['configuration']and h['request']!=histories[i-1]['request']
  windows.extend([(h['requested_at'],h['deadline'])]*3)
 for index,writer in enumerate(writers[17:],17):
  requested,deadline=windows[index-17];pair=(integer(writer['pid'],2),integer(writer['start'],1));assert pair not in ids;ids.append(pair)
  assert requested<=finite(writer['queued_at'])<deadline and writer['io_deadline']==writer['parent_deadline']==deadline
  failed=fault==2 and index==count-1;assert writer['actual_wait_status']==(9 if failed else 0)
  if failed:assert writer['verified_at']is None
  else:assert writer['queued_at']<=finite(writer['verified_at'])<deadline
 assert writers[16]['verified_at']<=creation['requested_at']and writers[17]['verified_at']<=creation['birth']['born_at']
 assert writers[18]['verified_at']<=creation['verified_at']<=writers[19]['queued_at']and writers[19]['verified_at']<=mount['requested_at']
 assert writers[20]['verified_at']<=mount['birth']['born_at']and writers[21]['verified_at']<=writers[22]['queued_at']
 assert writers[22]['verified_at']<=mounted['mounted_at']<=writers[23]['queued_at']and mounted['published_at']<=writers[23]['verified_at']<=histories[0]['requested_at']
 for i,op in enumerate(operations):
  validate_postcompletion_inventory(op,c.get('postcompletion_inventory_expected',False))
  h=histories[i];offset=24+3*i;original(op)
  assert op['kind']==h['kind']and all(op[k]==h[k]for k in ['request','requested_at','deadline','birth'])
  unacknowledged=fault==2 and i==1
  if unacknowledged:
   assert h['result']is h['verified_at']is None
   proposal=p['pending_wireguard'];assert isinstance(proposal,list)and len(proposal)==2 and proposal[0]==histories[0]
   proposed=proposal[i];assert all(proposed[k]==h[k]for k in ['kind','request','namespace','configuration','requested_at','deadline','birth'])and proposed['result']==op['result']and proposed['verified_at']==op['accepted_at']
  else:assert op['result']==h['result']and op['accepted_at']==h['verified_at']
  integer(op['registered_native_slots'],3)
  assert op['native_born']is op['full_descriptor_registration']is op['context_retained']is True and op['native_job_state']=='born'
  assert op['borrowed_registration_count']==(0 if i==0 else 2)
  assert op['original_pid']==op['birth']['pid']and op['original_start']==op['birth']['start']
  assert op['birth']['born_at']<=finite(op['accepted_at'])<op['deadline']and op['result']['namespace']==creation['source']
  assert op['acknowledged']is not(fault==2 and i==1)
  assert writers[offset]['verified_at']<=op['birth']['born_at']and writers[offset+1]['verified_at']<=op['accepted_at']<=writers[offset+2]['queued_at']
  if op['acknowledged']and i+1<len(histories):assert writers[offset+2]['verified_at']<=histories[i+1]['requested_at']
  result=op['result']
  if i==0:assert result['link']is result['wireguard']is None
  else:
   link=result['link'];wg=result['wireguard'];assert link['up']is False and link['kind']=='wireguard'and link['name']==wg['name']==allocated['wireguard_interface']and integer(link['index'],1)==wg['index'];digest(wg['public_key']);expected_public=[entry['device_public_key']for entry in c['profiles']if entry['member']==descriptor['primary']];assert len(expected_public)==1 and wg['public_key']==expected_public[0]
   assert len(wg['peers'])==1;peer=wg['peers'][0];assert peer['endpoint']=='185.66.0.1:51820'and peer['allowed_ips']==[['0.0.0.0',0]]and (peer['handshake_unix']is None or type(peer['handshake_unix'])in(int,float)and peer['handshake_unix']==0)
   import base64
   assert peer['public_key']==list(base64.b64decode('zo060cy2M+x7cMF4FKXHbs0CloUFDTRHRboFhw5YfVk='))
 if fault==0:assert operations[1]['result']==operations[2]['result']
 if fault!=2:assert p['pending_wireguard']is None
 failed=w['failed_constructor']
 if fault in (1,3):
  validate_postcompletion_inventory(failed,c.get('postcompletion_inventory_expected',False))
  assert isinstance(failed,dict);h=histories[0];assert failed['kind']=='sockets'and all(failed[k]==h[k]for k in ['request','requested_at','deadline'])
  integer(failed['registered_native_slots'],3)
  assert failed['full_descriptor_registration']is failed['context_retained']is True and failed['borrowed_registration_count']==0 and failed['acknowledged']is False
  assert failed['birth']is failed['accepted_at']is failed['original_start']is failed['result']is h['birth']is h['result']is h['verified_at']is None
  assert failed['native_born']is(fault==1)and failed['native_job_state']==('born'if fault==1 else'prepared')
  if fault==1:integer(failed['original_pid'],2);assert failed['actual_wait_status']==9
  else:assert failed['original_pid']is failed['actual_wait_status']is None
 else:assert failed is None
 environment=c['environment'];assert environment is not None
 assert all(v['verified_at']is None or v['verified_at']<=environment['after']['started_at']for v in writers)
 return dict(postcompletion_inventory_required=c.get('postcompletion_inventory_expected',False),original_context_continued=continuation,whole_context_drop_verified=not continuation,original_operation_clocks_verified=5+len(histories),ordered_writers_verified=count,constructor_birth_failure_proven=fault==1,partial_registration_failure_proven=fault==3,down_wireguard_provision_query_proven=fault==0)

if __name__=='__main__':
 c=validate_prefix(sys.argv[1],sys.argv[2]);proof=validate_pipeline(c);path=c['path'];record=c['record'];run=re.fullmatch('actual-program-run-([0-9]+).json',path.name)[1]
 output=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),record=str(path),record_sha256=hashlib.sha256(c['raw']).hexdigest(),source_binding=record['source_binding'],artifact_sha256=record['artifact_sha256'],context_sha256=record['context_sha256'],platform=record['platform'],component_test_mode=record['component_test_mode'],collector_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),prefix_validator_sha256=hashlib.sha256(pathlib.Path(__file__).with_name('provision_evidence_base.py').read_bytes()).hexdigest(),inventory_validator_sha256=hashlib.sha256(pathlib.Path(__file__).with_name('wireguard_inventory_schema.py').read_bytes()).hexdigest(),input_manifest=c['manifest'],gateway=c['gateway'],witness=c['top'],environment=c['environment'],proof=proof,real_client_acceptance='NOT_RUN',requirement8_complete=False,allnine_complete=False,limit='Synthetic external profiles/inert gateway; original fresh transport namespace, DOWN-only WireGuard and raw query. No DATA move, host veth/routes, UP, provider/client, operational reuse, cleanup or full secret-lifetime acceptance.')
 destination=pathlib.Path('target/lab-state')/('secret-provision-run-'+run+'.json')
 with destination.open('x')as stream:json.dump(output,stream,indent=2);stream.write('\n')
 print(json.dumps(dict(record=str(destination),platform=record['platform'],fault=c['provision_fault'],**proof,requirement8_complete=False)))
