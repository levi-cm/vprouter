"""Synthetic movement-schema mutations; no native/frozen-prefix acceptance."""
import copy,datetime,hashlib,importlib.util,json,pathlib
if not __debug__:raise RuntimeError('optimized_python_refused')
provision_smoke=pathlib.Path(__file__).with_name('smoke-provision-evidence.py');setup={'__file__':str(provision_smoke)}
exec(compile(provision_smoke.read_text().split('rows=[]',1)[0],str(provision_smoke),'exec'),setup)
movement_path=pathlib.Path(__file__).with_name('collect-secret-movement.py');spec=importlib.util.spec_from_file_location('movement_schema',movement_path);movement=importlib.util.module_from_spec(spec);spec.loader.exec_module(movement)

def sample(fault):
 c=setup['sample'](0);original=c['top'];original.update(whole_context_retained_after_drop=False,continued_original_context=True);original['operations'][2]['query_sequences']=[[10,11],[13,11]]
 for value in original['operations'][1:]+original['preparation']['wireguard'][1:]:value['result']['link'].update(alias='synthetic-owned-alias',mtu=1420)
 old=original['preparation'];p=copy.deepcopy(old);ops=copy.deepcopy(original['operations']);writers=p['writers'];histories=p['wireguard'];serial=[950000]
 def ident():serial[0]+=1;return serial[0],serial[0]+1000000
 def child(at,end):pid,start=ident();return dict(pid=pid,start=start,born_at=at,deadline=end)
 def writer(phase,at,end,failed=False):
  pid,start=ident();return dict(phase=phase,pid=pid,start=start,queued_at=at,io_deadline=end,parent_deadline=end,actual_wait_status=9 if failed else 0,verified_at=None if failed else at+.005)
 def operation(h,slots,borrowed,ack=True):
  return dict(kind=h['kind'],request=h['request'],requested_at=h['requested_at'],deadline=h['deadline'],birth=h['birth'],original_pid=h['birth']['pid'],original_start=h['birth']['start'],actual_wait_status=0,native_born=True,native_job_state='born',full_descriptor_registration=True,registered_native_slots=slots,borrowed_registration_count=borrowed,accepted_at=h['verified_at'],acknowledged=ack,result=copy.deepcopy(h['result']),context_retained=True)
 at=writers[-1]['verified_at']+.1;end=at+2;data=dict(kind='data_sockets',request=[31]*32,configuration=histories[0]['configuration'],namespace=p['data_network'],requested_at=at,deadline=end,birth=child(at+.02,end),result=dict(namespace=p['data_network'],link=None,wireguard=None),verified_at=at+.04)
 histories.append(data);ops.append(operation(data,7,0));writers.extend(writer(phase,at+offset,end)for phase,offset in[('wireguard_intent',.01),('wireguard_birth',.03),('wireguard_result',.05)])
 began=at+.2;end=began+2;q=dict(kind='MovementRecheck',requested_at=began,deadline=end,birth=child(began+.02,end),facts=original['attachment']['postmount_query']['facts'],verified_at=began+.04,actual_wait_status=0,original_peer_receipt=True,listener_origin_pid=1,listener_origin_uid=0,listener_origin_gid=0,handler_identity_claimed=False)
 canonical={k:copy.deepcopy(q[k])for k in['kind','requested_at','deadline','birth','facts','verified_at']};canonical.update(initial=None,request=[32]*32);p['movement_query']=canonical
 writers.extend(writer(phase,began+offset,end)for phase,offset in[('movement_query_intent',.01),('movement_query_birth',.03),('movement_query_result',.05)])
 result=copy.deepcopy(original['operations'][2]['result']);result['namespace']=p['data_network'];result['link']['index']=31;result['wireguard']['index']=31
 h=dict(kind='move',request=[33]*32,configuration=histories[0]['configuration'],namespace=p['transport_network'],destination=p['data_network'],movement_query=canonical['request'],requested_at=began,deadline=end,birth=child(began+.07,end),result=result,verified_at=began+.1)
 histories.append(h);writers.append(writer('wireguard_intent',began+.06,end));failed=None
 if fault in(1,3):
  h.update(birth=None,result=None,verified_at=None);failed=dict(kind='move',request=h['request'],requested_at=began,deadline=end,birth=None,original_pid=990001 if fault==1 else None,original_start=None,actual_wait_status=9 if fault==1 else None,native_born=fault==1,native_job_state='born'if fault==1 else'prepared',full_descriptor_registration=True,registered_native_slots=12,borrowed_registration_count=4,accepted_at=None,acknowledged=False,result=None,context_retained=True)
 else:
  ops.append(operation(h,15,4,ack=fault==0));writers.append(writer('wireguard_birth',began+.08,end));writers.append(writer('wireguard_result',began+.11,end,failed=fault==2))
 p.update(canonical_pending=fault==2,mutation_fenced=fault==2,pending_wireguard=copy.deepcopy(histories)if fault==2 else None)
 if fault==2:h.update(result=None,verified_at=None)
 c['movement_fault']=fault;c['movement_top']=dict(original_query_parent_readback_advanced=True,schema=1,fault=fault,provision=original,preparation=p,operations=ops,movement_query=q,failed_constructor=failed,held_real_result_writer=fault==2,unacknowledged_native_result_retained=fault==2,move_borrows_both_original_pairs=True,parent_pristine=True,same_service_retained=True,whole_chain_retained_after_drop=True,movement_context_retained_after_drop=True,original_provision_context_retained_after_drop=True,data_move_completed=fault in(0,2),wireguard_down_only=True,host_resources_created=False,operational_reuse_authorized=False,requirement8_complete=False,final_process_verified_at=began+.12 if fault==0 else None)
 c['environment']['after']['started_at']=began+5
 return c

rows=[]
for fault in range(4):movement.validate_movement(sample(fault));rows.append(dict(case='synthetic_valid_fault_'+str(fault),result='PASS'))
def change_query_state(c,sequences):
 c['top']['operations'][2]['query_sequences']=copy.deepcopy(sequences);c['movement_top']['operations'][2]['query_sequences']=copy.deepcopy(sequences)
mutations=[
 ('missing_readback_advancement',0,lambda c:change_query_state(c,[[10,11],[10,11]])),
 ('changed_unadvanced_generic',0,lambda c:change_query_state(c,[[10,11],[13,12]])),
 ('wrong_movement_purpose',0,lambda c:c['movement_top']['preparation']['movement_query'].update(kind='Initial')),
 ('changed_original_writer',0,lambda c:c['movement_top']['preparation']['writers'][0].update(pid=999999)),
 ('changed_old_history',0,lambda c:c['movement_top']['preparation']['wireguard'][0].update(deadline=1.)),
 ('wrong_destination_namespace',0,lambda c:c['movement_top']['preparation']['wireguard'][4].update(destination=dict(dev=4,ino=22))),
 ('rearmed_move_window',0,lambda c:c['movement_top']['preparation']['wireguard'][4].update(deadline=c['movement_top']['movement_query']['deadline']+2)),
 ('wrong_policy_digest',0,lambda c:c['movement_top']['preparation']['wireguard'][4].update(movement_query=[99]*32)),
 ('missing_borrowed_pair',0,lambda c:c['movement_top']['operations'][4].update(borrowed_registration_count=2)),
 ('empty_native_slots',0,lambda c:c['movement_top']['operations'][4].update(registered_native_slots=0)),
 ('unexpected_up',0,lambda c:c['movement_top']['operations'][4]['result']['link'].update(up=True)),
 ('changed_key',0,lambda c:c['movement_top']['operations'][4]['result']['wireguard'].update(public_key=[88]*32)),
 ('published_unacknowledged_result',2,lambda c:c['movement_top']['preparation']['wireguard'][4].update(result=copy.deepcopy(c['movement_top']['operations'][4]['result']))),
 ('wrong_pending_request',2,lambda c:c['movement_top']['preparation']['pending_wireguard'][4].update(request=[66]*32)),
 ('postbirth_missing_actual_reap',1,lambda c:c['movement_top']['failed_constructor'].update(actual_wait_status=None)),
 ('prebirth_claimed_child',3,lambda c:c['movement_top']['failed_constructor'].update(original_pid=12345)),
 ('missing_new_context_drop_proof',0,lambda c:c['movement_top'].update(movement_context_retained_after_drop=False)),
 ('missing_old_context_drop_proof',0,lambda c:c['movement_top'].update(original_provision_context_retained_after_drop=False)),
 ('fictitious_prior_drop',0,lambda c:c['top'].update(whole_context_retained_after_drop=True)),
 ('final_process_after_deadline',0,lambda c:c['movement_top'].update(final_process_verified_at=c['movement_top']['movement_query']['deadline'])),
 ('final_process_after_environment',0,lambda c:c['environment']['after'].update(started_at=c['movement_top']['final_process_verified_at']-.0001)),
 ('fault_claimed_final_process',2,lambda c:c['movement_top'].update(final_process_verified_at=c['movement_top']['movement_query']['requested_at']+.2)),
]
for name,fault,mutate in mutations:
 c=sample(fault);mutate(c)
 try:movement.validate_movement(c)
 except (AssertionError,TypeError,KeyError,ValueError):rows.append(dict(case=name,result='PASS_REFUSED'))
 else:raise AssertionError('bad_movement_schema_accepted:'+name)
dependencies=[movement_path,pathlib.Path(__file__),provision_smoke,pathlib.Path(__file__).with_name('collect-secret-provision.py')]
out=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),checks=rows,files=[dict(path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest())for p in dependencies],scope='LOCAL_SYNTHETIC_SCHEMA_ONLY; no native movement, frozen-prefix, current process, fork-secret, cleanup/reuse or release acceptance')
destination=pathlib.Path('target/lab-state')/('movement-schema-smokes-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.json')
with destination.open('x')as stream:json.dump(out,stream,indent=2);stream.write('\n')
print(json.dumps(dict(record=str(destination),checks=len(rows),native_acceptance=False)))
