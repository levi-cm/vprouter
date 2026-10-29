"""Frozen original-context DOWN movement; no operational/reuse acceptance."""
import datetime,hashlib,importlib.util,json,pathlib,re,sys
if not __debug__:raise RuntimeError('optimized_python_refused')
from movement_evidence_base import validate_prefix
from wireguard_inventory_schema import validate_postcompletion_inventory
provision_path=pathlib.Path(__file__).with_name('collect-secret-provision.py')
spec=importlib.util.spec_from_file_location('movement_provision_validation',provision_path);pv=importlib.util.module_from_spec(spec);spec.loader.exec_module(pv)

def validate_movement(c,continuation=False):
 prefix=pv.validate_pipeline(c,continuation=True)
 assert prefix['original_context_continued']is True and prefix['whole_context_drop_verified']is False
 w=c['movement_top'];fault=c['movement_fault'];original=c['top'];old=original['preparation'];p=w['preparation'];histories=p['wireguard'];ops=w['operations'];writers=p['writers'];q=w['movement_query'];canonical=p['movement_query'];integer=c['integer'];finite=c['finite'];clock=c['original_clock'];birth=c['birth'];ids=c['ids']
 assert fault in(0,1,2,3)and w['schema']==1 and w['fault']==fault
 assert w['original_query_parent_readback_advanced']is True
 sequences=original['operations'][2]['query_sequences'];assert isinstance(sequences,list)and len(sequences)==2
 for pair in sequences:assert isinstance(pair,list)and len(pair)==2 and all(type(v)is int and 0<=v<=4294967295 for v in pair)
 assert sequences[1][0]>sequences[0][0]and sequences[1][1]==sequences[0][1]
 assert type(continuation)is bool
 assert all(w[k]is True for k in['parent_pristine','same_service_retained','wireguard_down_only'])
 drop_fields=['whole_chain_retained_after_drop','movement_context_retained_after_drop','original_provision_context_retained_after_drop']
 if continuation:
  assert fault==0 and w['continued_original_context']is True and all(w[k]is False for k in drop_fields)
 else:
  assert w.get('continued_original_context',False)is False and all(w[k]is True for k in drop_fields)
 assert all(w[k]is False for k in['host_resources_created','operational_reuse_authorized','requirement8_complete'])
 assert w['held_real_result_writer']is w['unacknowledged_native_result_retained']is(fault==2)and w['data_move_completed']is(fault in(0,2))
 for k in['member','requested_at','deadline','birth','canonical_owner_epoch','inspection','attachment','fresh_transport','base_network','data_network','transport_network','owner_host_anchor_present','canonical_result_present','service_reserved']:
  assert p[k]==old[k],k
 assert p['base_network_absent']is False and p['native_children_reaped']is True and p['member_native_jobs_collected']is False
 assert p['canonical_pending']is p['mutation_fenced']is(fault==2)
 count=40 if fault in(1,3)else 42;assert len(writers)==count and writers[:33]==old['writers']and len(old['writers'])==33
 assert len(histories)==5 and histories[:3]==old['wireguard']and len(ops)==(4 if fault in(1,3)else 5)and ops[:3]==original['operations']
 data,move=histories[3:];assert data['kind']=='data_sockets'and move['kind']=='move'
 assert data['namespace']==p['data_network']and move['namespace']==p['transport_network']and move['destination']==p['data_network']
 for h in(data,move):
  clock(h['requested_at'],h['deadline']);digest=h['request'];assert isinstance(digest,list)and len(digest)==32 and any(digest)and all(type(x)is int and 0<=x<=255 for x in digest)
  assert h['configuration']==histories[0]['configuration']and all(h['request']!=oldh['request']for oldh in histories[:3])
 assert writers[32]['verified_at']<=data['requested_at']and data['verified_at']<=q['requested_at']
 assert q['kind']==canonical['kind']=='MovementRecheck'and canonical['initial']is None and q['actual_wait_status']==0 and q['original_peer_receipt']is True and q['handler_identity_claimed']is False
 integer(q['listener_origin_pid'],1);assert q['listener_origin_uid']==q['listener_origin_gid']==0 and q['facts']==original['attachment']['postmount_query']['facts']and q['facts']['pid']==c['gateway']['pid']
 clock(q['requested_at'],q['deadline']);assert q['requested_at']==move['requested_at']and q['deadline']==move['deadline']
 assert all(q[k]==canonical[k]for k in['requested_at','deadline','birth','facts','verified_at'])and canonical['request']==move['movement_query']
 digest=canonical['request'];assert isinstance(digest,list)and len(digest)==32 and any(digest)and all(type(x)is int and 0<=x<=255 for x in digest)
 birth(q['birth'],q['requested_at'],q['deadline']);assert q['birth']['born_at']<=finite(q['verified_at'])<q['deadline']
 phases=['wireguard_intent','wireguard_birth','wireguard_result','movement_query_intent','movement_query_birth','movement_query_result','wireguard_intent','wireguard_birth','wireguard_result']
 assert[v['phase']for v in writers[33:]]==phases[:count-33]
 for i,writer in enumerate(writers[33:],33):
  requested,end=(data['requested_at'],data['deadline'])if i<36 else(q['requested_at'],q['deadline'])
  pair=(integer(writer['pid'],2),integer(writer['start'],1));assert pair not in ids;ids.append(pair)
  assert requested<=finite(writer['queued_at'])<end and writer['io_deadline']==writer['parent_deadline']==end
  failed=fault==2 and i==41;assert writer['actual_wait_status']==(9 if failed else 0)
  if failed:assert writer['verified_at']is None
  else:assert writer['queued_at']<=finite(writer['verified_at'])<end
 assert writers[36]['verified_at']<=q['birth']['born_at']and writers[37]['verified_at']<=q['verified_at']<=writers[38]['queued_at']and writers[38]['verified_at']<=writers[39]['queued_at']
 for i,op in enumerate(ops[3:],3):
  validate_postcompletion_inventory(op,c.get('postcompletion_inventory_expected',False))
  h=histories[i];unack=fault==2 and i==4;offset=33 if i==3 else 39
  assert op['kind']==h['kind']and all(op[k]==h[k]for k in['request','requested_at','deadline','birth'])
  assert op['actual_wait_status']==0 and op['native_born']is op['full_descriptor_registration']is op['context_retained']is True and op['native_job_state']=='born'
  integer(op['registered_native_slots'],3);assert op['borrowed_registration_count']==(0 if i==3 else 4)
  birth(op['birth'],h['requested_at'],h['deadline']);assert op['original_pid']==op['birth']['pid']and op['original_start']==op['birth']['start']
  assert op['birth']['born_at']<=finite(op['accepted_at'])<h['deadline']and op['acknowledged']is not unack
  if unack:
   assert h['result']is h['verified_at']is None;proposal=p['pending_wireguard'];assert len(proposal)==5 and proposal[:4]==histories[:4];proposed=proposal[i]
   assert all(proposed[k]==h[k]for k in h if k not in('result','verified_at'))and proposed['result']==op['result']and proposed['verified_at']==op['accepted_at']
  else:assert op['result']==h['result']and op['accepted_at']==h['verified_at']
  assert writers[offset]['verified_at']<=op['birth']['born_at']and writers[offset+1]['verified_at']<=op['accepted_at']<=writers[offset+2]['queued_at']
  if i==3:assert op['result']==dict(namespace=p['data_network'],link=None,wireguard=None)and writers[35]['verified_at']<=q['requested_at']
  else:
   assert q['verified_at']<=op['birth']['born_at']and w['move_borrows_both_original_pairs']is True
   result=op['result'];prior=original['operations'][2]['result'];assert result['namespace']==p['data_network']
   link,wg=result['link'],result['wireguard'];before=prior['link'];assert link['up']is False and link['kind']=='wireguard'and link['name']==before['name']and link['alias']==before['alias']and link['mtu']==before['mtu']
   assert integer(link['index'],1)==wg['index']and wg['name']==link['name']and wg['public_key']==prior['wireguard']['public_key']and wg['peers']==prior['wireguard']['peers']
 # Kernel renumbering is allowed. Index authority comes from the original move
 # and exact destination readback, with no pre-reservation claim.
 if fault!=2:assert p['pending_wireguard']is None
 failed=w['failed_constructor']
 if fault in(1,3):
  validate_postcompletion_inventory(failed,c.get('postcompletion_inventory_expected',False))
  assert isinstance(failed,dict)and failed['kind']=='move'and all(failed[k]==move[k]for k in['request','requested_at','deadline'])
  assert failed['full_descriptor_registration']is failed['context_retained']is True and failed['borrowed_registration_count']==4;integer(failed['registered_native_slots'],3)
  assert failed['birth']is failed['accepted_at']is failed['original_start']is failed['result']is move['birth']is move['result']is move['verified_at']is None and failed['acknowledged']is False
  assert failed['native_born']is(fault==1)and failed['native_job_state']==('born'if fault==1 else'prepared')
  if fault==1:integer(failed['original_pid'],2);assert failed['actual_wait_status']==9
  else:assert failed['original_pid']is failed['actual_wait_status']is None
 else:assert failed is None
 checked=w['final_process_verified_at']
 if fault==0:assert writers[41]['verified_at']<=finite(checked)<q['deadline']and checked<=c['environment']['after']['started_at']
 else:assert checked is None
 assert c['environment']is not None and all(v['verified_at']is None or v['verified_at']<=c['environment']['after']['started_at']for v in writers)
 return dict(postcompletion_inventory_required=c.get('postcompletion_inventory_expected',False),original_operation_clocks_verified=10,ordered_writers_verified=count,original_context_continued=True,final_whole_chain_drop_verified=not continuation,movement_original_context_continued=continuation,down_move_completed=fault in(0,2),move_result_acknowledged=fault==0)

if __name__=='__main__':
 c=validate_prefix(sys.argv[1],sys.argv[2]);proof=validate_movement(c);r=c['record'];path=c['path'];run=re.fullmatch('actual-program-run-([0-9]+).json',path.name)[1]
 dependencies=[pathlib.Path(__file__),pathlib.Path(__file__).with_name('movement_evidence_base.py'),provision_path,pathlib.Path(__file__).with_name('provision_evidence_base.py'),pathlib.Path(__file__).with_name('wireguard_inventory_schema.py')]
 out=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),record=str(path),record_sha256=hashlib.sha256(c['raw']).hexdigest(),source_binding=r['source_binding'],artifact_sha256=r['artifact_sha256'],context_sha256=r['context_sha256'],platform=r['platform'],component_test_mode=r['component_test_mode'],collectors=[dict(path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest())for p in dependencies],input_manifest=c['manifest'],gateway=c['gateway'],witness=c['movement_top'],environment=c['environment'],proof=proof,real_client_acceptance='NOT_RUN',requirement8_complete=False,allnine_complete=False,limit='Original synthetic DOWN WireGuard movement into original DATA with a fresh fixed policy/native-process recheck; no interface-UP, host veth/routes, provider/client, cleanup/reuse, complete secret-lifetime or operational acceptance.')
 destination=pathlib.Path(f'target/lab-state/secret-movement-run-{run}.json')
 with destination.open('x')as stream:json.dump(out,stream,indent=2);stream.write('\n')
 print(json.dumps(dict(record=str(destination),platform=r['platform'],fault=c['movement_fault'],**proof,requirement8_complete=False)))
