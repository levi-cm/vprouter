"""Synthetic four-mode whole schema and exclusive group evidence; no native."""
import copy,datetime,hashlib,importlib.util,json,pathlib
if not __debug__:raise RuntimeError('optimized_python_refused')
prefix=pathlib.Path(__file__).with_name('smoke-quarantine-native-evidence.py');setup={'__file__':str(prefix)}
exec(compile(prefix.read_text().split('\nrows=[]',1)[0],str(prefix),'exec'),setup)
collector_path=pathlib.Path(__file__).with_name('collect-secret-quarantine.py');spec=importlib.util.spec_from_file_location('quarantine_collector',collector_path);collector=importlib.util.module_from_spec(spec);spec.loader.exec_module(collector)
def sample(fault,whole=False):
 c,p,operations,query,wan=setup['sample']();at=p['writers'][62]['verified_at']+.1;end=at+2;counter=[3000000]
 def pair():counter[0]+=1;return counter[0],counter[0]+1000000
 def born(at):pid,start=pair();return dict(pid=pid,start=start,born_at=at,deadline=end)
 def writer(phase,offset):pid,start=pair();return dict(phase=phase,pid=pid,start=start,queued_at=at+offset,io_deadline=end,parent_deadline=end,actual_wait_status=0,verified_at=at+offset+.005)
 pq=dict(kind='ProducerRecheck',initial=None,request=[190]*32,requested_at=at,deadline=end,birth=born(at+.02),facts=copy.deepcopy(p['quarantine_query']['facts']),verified_at=at+.04)
 p['producer_query']=pq;pq_native=copy.deepcopy(pq);pq_native.update(actual_wait_status=0,original_peer_receipt=True,handler_identity_claimed=False,listener_origin_pid=1,listener_origin_uid=0,listener_origin_gid=0)
 allocation=c['descriptor']['allocation'];member=next(e for e in allocation['exits']if e['exit_id']==c['descriptor']['primary'])
 h=dict(request=[191]*32,parent=dict(dev=29,ino=8001),name=member['nft_table']+'-g'+str(allocation['generation'])+'-health',data=copy.deepcopy(p['data_network']),query=pq['request'],requested_at=at,deadline=end,birth=None,group=None,verified_at=None)
 p['producer_creation']=h;p['pending_producer_creation']=None;p['entry_producer_absent']=True;p.update(canonical_pending=fault==2,mutation_fenced=fault==2,pending_wireguard=copy.deepcopy(p['wireguard'])if fault==2 else None)
 p['writers'].extend(writer(phase,offset)for phase,offset in[('producer_query_intent',.01),('producer_query_birth',.025),('producer_query_result',.045),('producer_intent',.06)])
 native=None;failed=None
 if fault in(1,3):
  failed=copy.deepcopy(h);failed.update(original_pid=pair()[0]if fault==1 else None,original_start=None,actual_wait_status=9 if fault==1 else None,native_born=fault==1,native_job_state='born'if fault==1 else'prepared',registered_native_slots=8,full_descriptor_registration=True,received_original_group=False,eof=False,durable_birth_released=False,acknowledged=False,context_retained=True,operational_publication=False,parent_death_lock_survival_claimed=False)
 else:
  h.update(birth=born(at+.08),group=dict(dev=29,ino=8002),verified_at=at+.11)
  native=copy.deepcopy(h);native.update(original_pid=h['birth']['pid'],original_start=h['birth']['start'],actual_wait_status=0,native_born=True,native_job_state='born',registered_native_slots=12,full_descriptor_registration=True,received_original_group=True,eof=True,durable_birth_released=True,acknowledged=fault==0,context_retained=True,operational_publication=False,parent_death_lock_survival_claimed=False)
  p['writers'].extend(writer(phase,offset)for phase,offset in[('producer_birth',.09),('producer_result',.12)])
  if fault==2:p['pending_producer_creation']=copy.deepcopy(h);h.update(group=None,verified_at=None);p['writers'][68].update(actual_wait_status=9,verified_at=None)
 w=dict(schema=1,fault=fault,movement=c['movement_top'],preparation=p,operations=operations,quarantine_query=query,wan=wan,producer_query=pq_native,producer=native,failed_constructor=failed,final_process_verified_at=at+.13 if fault==0 else None,held_real_result_writer=fault==2,unacknowledged_native_result_retained=fault==2,whole_chain_retained_after_drop=True,quarantine_context_retained_after_drop=True,producer_context_retained_after_drop=True,movement_context_retained_after_drop=True,original_provision_context_retained_after_drop=True,parent_pristine=True,same_service_retained=True,initial_quarantine_only=True,producer_operational_publication=False,producer_exceptions_authorized=False,host_network_links_or_routes_created=False,initial_quarantine_installation_observed_all_scopes=True,producer_group_creation_observed=fault in(0,2),up_authorized=False,operational_reuse_authorized=False,requirement8_complete=False)
 c.update(quarantine_top=w,quarantine_fault=fault);c['environment']['after']['started_at']=at+3
 if whole:
  old=c['w'];c['ids'][:]=[(v['pid'],v['start'])for v in c['p']['writers']]+[(v['birth']['pid'],v['birth']['start'])for v in[old['validator'],old['mount'],old['first_query'],old['second_query'],old['postmount_query']]]
 return c
rows=[]
for fault in range(4):
 c=sample(fault);proof=collector.validate_producer(c);assert proof['ordered_writers_verified']==(67 if fault in(1,3)else 69)
 rows.append(dict(case='producer_valid_'+str(fault),result='PASS'))
 c=sample(fault,whole=True);proof=collector.validate_quarantine(c);assert proof['producer']['original_operation_clocks_verified']==17
 rows.append(dict(case='whole_schema_valid_'+str(fault),result='PASS'))
mutations=[
 ('query_purpose',0,lambda w:w['producer_query'].update(kind='QuarantineRecheck')),
 ('name',0,lambda w:w['preparation']['producer_creation'].update(name='other')),
 ('data',0,lambda w:w['preparation']['producer_creation'].update(data=dict(dev=4,ino=12))),
 ('parent',0,lambda w:w['producer'].update(parent=dict(dev=29,ino=999))),
 ('native_status',0,lambda w:w['producer'].update(actual_wait_status=9)),
 ('status_bool',0,lambda w:w['producer'].update(actual_wait_status=False)),
 ('no_original_group',0,lambda w:w['producer'].update(received_original_group=False)),
 ('no_eof',0,lambda w:w['producer'].update(eof=False)),
 ('gate_not_released',0,lambda w:w['producer'].update(durable_birth_released=False)),
 ('placement_grant',0,lambda w:w.update(up_authorized=True)),
 ('publication',0,lambda w:w['producer'].update(operational_publication=True)),
 ('parent_death_claim',0,lambda w:w['producer'].update(parent_death_lock_survival_claimed=True)),
 ('entry_published',0,lambda w:w['preparation'].update(entry_producer_absent=False)),
 ('final_after_end',0,lambda w:w.update(final_process_verified_at=w['producer']['deadline'])),
 ('missing_producer_anchor',0,lambda w:w.update(producer_context_retained_after_drop=False)),
 ('missing_quarantine_anchor',0,lambda w:w.update(quarantine_context_retained_after_drop=False)),
 ('ambiguous_host_claim',0,lambda w:w.update(host_resources_created=False)),
 ('false_creation_claim',0,lambda w:w.update(producer_group_creation_observed=False)),
 ('prebirth_birth_writer',0,lambda w:w['preparation']['writers'][67].update(queued_at=w['producer']['birth']['born_at']-.001)),
 ('query_prebirth_writer',0,lambda w:w['preparation']['writers'][64].update(queued_at=w['producer_query']['birth']['born_at']-.001)),
 ('writer_status_bool',0,lambda w:w['preparation']['writers'][63].update(actual_wait_status=False)),
 ('committed_unacked_group',2,lambda w:w['preparation']['producer_creation'].update(group=w['producer']['group'])),
 ('pending_mismatch',2,lambda w:w['preparation']['pending_producer_creation'].update(request=[1]*32)),
 ('unacked_claimed_ack',2,lambda w:w['producer'].update(acknowledged=True)),
 ('failed_writer_has_ack',2,lambda w:w['preparation']['writers'][68].update(verified_at=w['producer']['verified_at'])),
 ('fault_final_process',2,lambda w:w.update(final_process_verified_at=w['producer']['verified_at'])),
 ('postbirth_missing_reap',1,lambda w:w['failed_constructor'].update(actual_wait_status=None)),
 ('postbirth_claimed_start',1,lambda w:w['failed_constructor'].update(original_start=123)),
 ('registration_claimed_pid',3,lambda w:w['failed_constructor'].update(original_pid=123)),
 ('registration_claimed_group',3,lambda w:w['failed_constructor'].update(received_original_group=True)),
]
for name,fault,mutate in mutations:
 c=sample(fault);mutate(c['quarantine_top'])
 try:collector.validate_producer(c)
 except(AssertionError,ValueError,KeyError,TypeError):rows.append(dict(case=name,result='PASS_REFUSED'))
 else:raise AssertionError('invalid_producer_evidence_accepted:'+name)
c=sample(2);w=c['quarantine_top'];c['environment']['after']['started_at']=(w['preparation']['writers'][67]['verified_at']+w['producer']['verified_at'])/2
try:collector.validate_producer(c)
except(AssertionError,ValueError,KeyError,TypeError):rows.append(dict(case='unacknowledged_source_and_queue_after_observer',result='PASS_REFUSED'))
else:raise AssertionError('after_observer_source_accepted')
dependencies=[pathlib.Path(__file__),collector_path,pathlib.Path(__file__).with_name('quarantine_producer_schema.py'),prefix,pathlib.Path(__file__).with_name('quarantine_history_schema.py'),pathlib.Path(__file__).with_name('quarantine_native_schema.py')]
record=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),checks=rows,files=[dict(path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest())for p in dependencies],scope='LOCAL_SYNTHETIC_PRODUCER_AND_WHOLE_SCHEMA_ONLY; no frozen input/actual child/VM/WAN/nft/cgroup creation/Drop or release acceptance')
destination=pathlib.Path('target/lab-state')/('quarantine-producer-smokes-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.json')
with destination.open('x')as f:json.dump(record,f,indent=2);f.write('\n')
print(json.dumps(dict(record=str(destination),checks=len(rows),native_acceptance=False)))
