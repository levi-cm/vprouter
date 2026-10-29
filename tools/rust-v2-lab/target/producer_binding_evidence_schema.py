"""One-way canonical group binding; metadata never grants operational authority."""
import json
if not __debug__:raise RuntimeError('optimized_python_refused')
def same(a,b):return json.dumps(a,sort_keys=True,separators=(',',':'),allow_nan=False)==json.dumps(b,sort_keys=True,separators=(',',':'),allow_nan=False)
def validate_binding(c,continuation=False):
 assert type(continuation)is bool
 w=c['producer_binding_top'];fault=c['producer_binding_fault'];old=c['assembly_top']['preparation'];p=w['preparation']
 integer,finite,clock,birth,identity,ids=(c[k]for k in('integer','finite','original_clock','birth','identity','ids'))
 def digest(v):assert isinstance(v,list)and len(v)==32 and any(v)and all(type(n)is int and 0<=n<=255 for n in v)
 assert type(fault)is int and fault in(0,1,2,3)
 fields={'schema','fault','assembly','preparation','query','observation','failed_constructor','original_group','final_process_verified_at','charges_before','charges_before_drop','charges_after_drop','canonical_producer_published','unacknowledged_observation_retained','result_writer_held','whole_chain_retained_after_drop','producer_binding_context_retained_after_drop','assembly_context_retained_after_drop','producer_context_retained_after_drop','quarantine_context_retained_after_drop','movement_context_retained_after_drop','original_provision_context_retained_after_drop','same_original_source','parent_pristine','producer_exception_authorized','placement_authorized','health_ready_authorized','up_authorized','host_network_links_or_routes_created','resource_cleanup_authorized','multi_exit_runtime_proven','requirement8_complete','canonical_negative_checks','failure_retry','retained_result_writer'}
 assert set(w)in(fields,fields|{'continued_original_context'})and type(w['schema'])is int and w['schema']==1 and type(w['fault'])is int and w['fault']==fault
 assert type(w.get('continued_original_context',False))is bool and w.get('continued_original_context',False)is continuation
 if continuation:assert fault==0 and w['continued_original_context']is True
 assert w['assembly']==c['assembly_top']and c['assembly_fault']==0
 changed={'writers','entry_producer','entry_producer_absent','producer_binding_query','producer_binding','pending_producer_binding','mutation_fenced','canonical_pending','pending_wireguard','pending_producer_creation'}
 assert set(p)==set(old)and all(same(p[k],old[k])for k in old if k not in changed)
 assert p['member']==c['descriptor']['primary']and p['canonical_owner_epoch']==old['canonical_owner_epoch']and p['service_reserved']is p['native_children_reaped']is True and p['member_native_jobs_collected']is False
 assert p['entry_phase']=='creating'and all(p[k]is True for k in('entry_links_absent','entry_attempt_absent','entry_terminal_absent'))
 assert p['mutation_fenced']is(fault==2)and p['canonical_pending']is(fault==2)
 assert p['pending_wireguard']==(p['wireguard']if fault==2 else None)and p['pending_producer_creation']==(p['producer_creation']if fault==2 else None)
 count=73 if fault in(1,3)else 75;writers=p['writers'];assert len(writers)==count and same(writers[:69],old['writers'])
 foreign=c['assembly_top']['foreign_eligibility'];pair=(foreign['original_pid'],foreign['original_start']);assert pair not in ids;ids.append(pair)
 h=p['producer_binding'];q=w['query'];canonical=p['producer_binding_query'];original=p['producer_creation']
 assert set(h)=={'request','parent','name','data','query','requested_at','deadline','birth','group','creation','policy','pins','result','verified_at'}
 for k in('request','query','policy'):digest(h[k])
 assert same(h['creation'],original)and h['parent']==original['parent']and h['group']==original['group']==w['original_group']and h['name']==original['name']and h['data']==original['data']==p['data_network']
 identity(h['parent']);identity(h['group']);identity(h['data']);digest(canonical['request']);assert h['parent']['dev']==h['group']['dev']and h['parent']!=h['group']
 assert h['policy']==p['netfilter'][5]['policy']and h['query']==canonical['request']and h['requested_at']==canonical['requested_at']and h['deadline']==canonical['deadline']
 clock(h['requested_at'],h['deadline']);assert foreign['verified_at']<=h['requested_at']and old['writers'][68]['verified_at']<=h['requested_at']
 pins=h['pins'];assert isinstance(pins,list)and len(pins)==6 and len({tuple(v[:2])for v in pins})==6
 for i,pin in enumerate(pins):
  assert isinstance(pin,list)and len(pin)==3 and integer(pin[0],1)==h['parent']['dev'];integer(pin[1],1);assert integer(pin[2])<=4294967295 and pin[2]&0o170000==(0o040000 if i<2 else 0o100000)
 assert pins[0][:2]==[h['parent']['dev'],h['parent']['ino']]and pins[1][:2]==[h['group']['dev'],h['group']['ino']]
 assert q['kind']==canonical['kind']=='ProducerBindingRecheck'and canonical['initial']is None
 assert all(same(q[k],canonical[k])for k in('requested_at','deadline','birth','facts','verified_at'))and same(q['facts'],p['quarantine_query']['facts'])
 assert integer(q['actual_wait_status'])==0 and q['original_peer_receipt']is True and q['handler_identity_claimed']is False
 integer(q['listener_origin_pid'],1);assert type(q['listener_origin_uid'])is type(q['listener_origin_gid'])is int and q['listener_origin_uid']==q['listener_origin_gid']==0
 birth(q['birth'],q['requested_at'],q['deadline']);assert q['birth']['pid']<=4294967295;assert q['birth']['born_at']<=finite(q['verified_at'])<q['deadline']
 phases=['producer_binding_query_intent','producer_binding_query_birth','producer_binding_query_result','producer_binding_intent','producer_binding_birth','producer_binding_result']
 assert [r['phase']for r in writers[69:]]==phases[:count-69]
 for i,writer in enumerate(writers[69:],69):
  pair=(integer(writer['pid'],2),integer(writer['start'],1));assert pair not in ids and writer['pid']<=4294967295;ids.append(pair)
  assert h['requested_at']<=finite(writer['queued_at'])<h['deadline']and writer['parent_deadline']==writer['io_deadline']==h['deadline']
  failed=fault==2 and i==74;assert integer(writer['actual_wait_status'])==(9 if failed else 0)
  if failed:assert writer['verified_at']is None
  else:assert writer['queued_at']<=finite(writer['verified_at'])<h['deadline']
 assert writers[69]['verified_at']<=q['birth']['born_at']<=writers[70]['queued_at']and writers[70]['verified_at']<=q['verified_at']<=writers[71]['queued_at']and writers[71]['verified_at']<=writers[72]['queued_at']
 assert all(r['queued_at']<=c['environment']['after']['started_at']and(r['verified_at']is None or r['verified_at']<=c['environment']['after']['started_at'])for r in writers)
 source=w['observation'];failed=w['failed_constructor'];pending=p['pending_producer_binding'];published=p['entry_producer']
 assert p['entry_producer_absent']is(fault!=0)and w['canonical_producer_published']is(fault==0)and w['unacknowledged_observation_retained']is w['result_writer_held']is(fault==2)
 if fault in(1,3):
  assert source is None and isinstance(failed,dict)and h['birth']is h['result']is h['verified_at']is published is pending is None
  native=failed
 else:
  assert failed is None and isinstance(source,dict);native=source;birth(h['birth'],h['requested_at'],h['deadline'])
  assert writers[72]['verified_at']<=h['birth']['born_at']<=writers[73]['queued_at']and q['verified_at']<=h['birth']['born_at']
  assert same(h['birth'],source['birth'])and integer(source['original_pid'],2)<=4294967295 and integer(source['original_start'],1)==h['birth']['start']and source['original_pid']==h['birth']['pid']and integer(source['actual_wait_status'])==0
  assert source['native_born']is source['complete_native_registration']is source['durable_birth_released']is source['eof']is True and source['native_job_state']=='born'and source['acknowledged']is(fault==0)
  result=source['result'];assert set(result)=={'namespace','group','policy','pins','observed_at'}and same(result['namespace'],h['data'])and same(result['group'],h['group'])and same(result['policy'],h['policy'])and same(result['pins'],h['pins'])
  assert h['birth']['born_at']<=writers[73]['verified_at']<=finite(result['observed_at'])<=finite(source['accepted_at'])<h['deadline']and writers[73]['verified_at']<=source['accepted_at']<=writers[74]['queued_at']
  if fault==0:
   assert pending is None and same(h['result'],result)and h['verified_at']==source['accepted_at']and set(published)=={'parent','group','binding'}and same(published,dict(parent=h['parent'],group=h['group'],binding=h['request']))
  else:
   assert published is h['result']is h['verified_at']is None and set(pending)=={'producer','history'}
   assert set(pending['history'])==set(h)and all(same(pending['history'][k],h[k])for k in h if k not in('result','verified_at'))
   assert same(pending['history']['result'],result)and pending['history']['verified_at']==source['accepted_at']and same(pending['producer'],dict(parent=h['parent'],group=h['group'],binding=h['request']))
 native_fields={'request','query','requested_at','deadline','parent','group','name','data','policy','pins','original_pid','original_start','actual_wait_status','birth','native_born','native_job_state','registered_native_slots','original_registration_slots_verified','borrowed_registration_count','complete_native_registration','durable_birth_released','result','accepted_at','acknowledged','eof','context_retained','producer_exception_authorized','placement_authorized','up_authorized'}
 assert set(native)==native_fields and all(same(native[k],h[k])for k in('request','query','requested_at','deadline','parent','group','name','data','policy','pins'))
 assert integer(native['registered_native_slots'],9)>=9 and native['original_registration_slots_verified']is native['context_retained']is True and integer(native['borrowed_registration_count'])==2
 assert all(native[k]is False for k in('producer_exception_authorized','placement_authorized','up_authorized'))
 if fault in(1,3):
  assert native['birth']is native['result']is native['accepted_at']is None and native['durable_birth_released']is native['complete_native_registration']is native['acknowledged']is native['eof']is False and native['native_born']is(fault==1)
  assert native['native_job_state']==('born'if fault==1 else'prepared')and native['original_start']is None
  if fault==1:assert integer(native['original_pid'],2)<=4294967295;assert integer(native['actual_wait_status'])==9
  else:assert native['original_pid']is native['actual_wait_status']is None
 final=w['final_process_verified_at']
 if fault==0:assert writers[74]['verified_at']<=finite(final)<h['deadline']and final<=c['environment']['after']['started_at']
 else:assert final is None
 for key,expected in [('charges_before',[0,0]),('charges_before_drop',[0,0]if fault==3 else[2,1]if fault==2 else[1,1]),('charges_after_drop',[0,0]if fault==3 else[2,1]if fault==2 else[1,1])]:
  value=w[key]
  if continuation and key=='charges_after_drop':assert value is None
  else:assert isinstance(value,list)and len(value)==2 and all(type(n)is int for n in value)and value==expected
 retained=w['retained_result_writer']
 if fault!=2:assert retained is None
 else:
  assert set(retained)=={'index','pid','start','actual_wait_status','io_deadline','parent_deadline','launch_charge','original_reap_bound','charge_retained_before_cancel','charge_retained_after_collection','charge_retained_after_retries','charge_retained_after_drop','failed','mutation','acknowledged','canonical_pending','mutation_fenced'}
  assert integer(retained['index'])==74 and integer(retained['launch_charge'])==1
  for key in('pid','start','actual_wait_status','io_deadline','parent_deadline'):assert same(retained[key],writers[74][key])
  assert retained['io_deadline']==retained['parent_deadline']==h['deadline']
  assert all(retained[key]is True for key in('original_reap_bound','charge_retained_before_cancel','charge_retained_after_collection','charge_retained_after_retries','charge_retained_after_drop','failed','mutation','canonical_pending','mutation_fenced'))and retained['acknowledged']is False
 retry=w['failure_retry']
 if fault==0:assert retry is None
 else:
  assert set(retry)=={'polls','native_births_before','native_births_after','charges_before','charges_after','same_original_request','same_step','original_error_retained','assembly_reuse_refused'}
  assert integer(retry['polls'])==2 and integer(retry['native_births_before'])==integer(retry['native_births_after'])
  for key in('charges_before','charges_after'):
   value=retry[key];assert isinstance(value,list)and len(value)==2 and all(type(n)is int for n in value)and value==w['charges_before_drop']
  assert all(retry[key]is True for key in('same_original_request','same_step','original_error_retained','assembly_reuse_refused'))
 for key in('whole_chain_retained_after_drop','producer_binding_context_retained_after_drop','assembly_context_retained_after_drop','producer_context_retained_after_drop','quarantine_context_retained_after_drop','movement_context_retained_after_drop','original_provision_context_retained_after_drop'):assert w[key]is(not continuation)
 for key in('same_original_source','parent_pristine'):assert w[key]is True
 for key in('producer_exception_authorized','placement_authorized','health_ready_authorized','up_authorized','host_network_links_or_routes_created','resource_cleanup_authorized','multi_exit_runtime_proven','requirement8_complete'):assert w[key]is False
 assert integer(w['canonical_negative_checks'])==(25 if fault==0 else 0)
 return dict(ordered_writers_verified=count,original_operation_clocks_verified=18,canonical_producer_published=fault==0,unacknowledged_observation_retained=fault==2,original_group_preserved=True,producer_binding_original_context_continued=continuation,final_whole_chain_drop_verified=not continuation,placement_authorized=False,health_ready_authorized=False,up_authorized=False)
