"""Exclusive original group creation; never publication or placement authority."""
if not __debug__:raise RuntimeError('optimized_python_refused')
def validate_producer(c,continuation=False):
 assert type(continuation)is bool
 w=c['quarantine_top'];fault=c['quarantine_fault'];p=w['preparation'];h=p['producer_creation'];q=w['producer_query'];canonical=p['producer_query']
 integer,finite,clock,birth,identity,ids=(c[k]for k in['integer','finite','original_clock','birth','identity','ids'])
 def digest(value):assert isinstance(value,list)and len(value)==32 and any(value)and all(type(v)is int and 0<=v<=255 for v in value)
 assert type(fault)is int and fault in(0,1,2,3)and type(w['schema'])is int and w['schema']==1 and type(w['fault'])is int and w['fault']==fault
 assert set(h)=={'request','parent','name','data','query','requested_at','deadline','birth','group','verified_at'}
 digest(h['request']);digest(h['query']);identity(h['parent']);assert h['data']==p['data_network']
 allocation=c['descriptor']['allocation'];members=[e for e in allocation['exits']if e['exit_id']==c['descriptor']['primary']];assert len(members)==1
 assert h['name']==members[0]['nft_table']+'-g'+str(allocation['generation'])+'-health'
 assert h['requested_at']==canonical['requested_at']and h['deadline']==canonical['deadline']and h['query']==canonical['request']
 clock(h['requested_at'],h['deadline']);assert p['writers'][62]['verified_at']<=h['requested_at']
 assert q['kind']==canonical['kind']=='ProducerRecheck'and canonical['initial']is None
 assert all(q[k]==canonical[k]for k in['requested_at','deadline','birth','facts','verified_at'])and q['facts']==p['quarantine_query']['facts']
 assert integer(q['actual_wait_status'])==0 and q['original_peer_receipt']is True and q['handler_identity_claimed']is False
 integer(q['listener_origin_pid'],1);assert type(q['listener_origin_uid'])is type(q['listener_origin_gid'])is int and q['listener_origin_uid']==q['listener_origin_gid']==0
 birth(q['birth'],q['requested_at'],q['deadline']);assert q['birth']['born_at']<=finite(q['verified_at'])<q['deadline']
 count=67 if fault in(1,3)else 69;writers=p['writers'];assert len(writers)==count
 phases=['producer_query_intent','producer_query_birth','producer_query_result','producer_intent','producer_birth','producer_result']
 assert [v['phase']for v in writers[63:]]==phases[:count-63]
 for index,writer in enumerate(writers[63:],63):
  pair=(integer(writer['pid'],2),integer(writer['start'],1));assert pair not in ids;ids.append(pair)
  assert h['requested_at']<=finite(writer['queued_at'])<h['deadline']and writer['io_deadline']==writer['parent_deadline']==h['deadline']
  failed=fault==2 and index==68;assert integer(writer['actual_wait_status'])==(9 if failed else 0)
  if failed:assert writer['verified_at']is None
  else:assert writer['queued_at']<=finite(writer['verified_at'])<h['deadline']
 assert writers[63]['verified_at']<=q['birth']['born_at']<=writers[64]['queued_at']and writers[64]['verified_at']<=q['verified_at']<=writers[65]['queued_at']and writers[65]['verified_at']<=writers[66]['queued_at']
 assert p['canonical_pending']is p['mutation_fenced']is(fault==2)and p['entry_producer_absent']is True
 assert p['pending_wireguard']==(p['wireguard']if fault==2 else None)
 assert p['native_children_reaped']is True and p['member_native_jobs_collected']is False
 assert w['held_real_result_writer']is w['unacknowledged_native_result_retained']is(fault==2)
 pending=p['pending_producer_creation'];failed=w['failed_constructor'];source=w['producer']
 if fault in(1,3):
  assert source is None and pending is None and isinstance(failed,dict)
  assert all(failed[k]==h[k]for k in['request','query','parent','name','data','requested_at','deadline'])
  assert h['birth']is h['group']is h['verified_at']is failed['birth']is failed['group']is failed['verified_at']is failed['original_start']is None
  assert failed['full_descriptor_registration']is failed['context_retained']is True and integer(failed['registered_native_slots'],3)>=3
  assert failed['native_born']is(fault==1)and failed['native_job_state']==('born'if fault==1 else'prepared')
  assert failed['received_original_group']is failed['durable_birth_released']is failed['acknowledged']is failed['operational_publication']is failed['parent_death_lock_survival_claimed']is False
  if fault==1:integer(failed['original_pid'],2);assert integer(failed['actual_wait_status'])==9
  else:assert failed['original_pid']is failed['actual_wait_status']is None
 else:
  assert failed is None and isinstance(source,dict)
  assert all(source[k]==h[k]for k in['request','query','parent','name','data','requested_at','deadline','birth'])
  birth(h['birth'],h['requested_at'],h['deadline']);assert writers[66]['verified_at']<=h['birth']['born_at']<=writers[67]['queued_at']and q['verified_at']<=h['birth']['born_at']
  assert integer(source['original_pid'],2)==h['birth']['pid']and integer(source['original_start'],1)==h['birth']['start']and integer(source['actual_wait_status'])==0
  assert source['native_born']is source['full_descriptor_registration']is source['received_original_group']is source['eof']is source['durable_birth_released']is source['context_retained']is True and source['native_job_state']=='born'
  integer(source['registered_native_slots'],3);assert source['operational_publication']is source['parent_death_lock_survival_claimed']is False and source['acknowledged']is(fault==0)
  if fault==2:
   assert h['group']is h['verified_at']is None and isinstance(pending,dict)and set(pending)==set(h)
   assert all(pending[k]==h[k]for k in h if k not in('group','verified_at'));bound=pending
  else:assert pending is None;bound=h
  assert source['group']==bound['group']and source['verified_at']==bound['verified_at']
  identity(bound['group']);assert bound['group']['dev']==h['parent']['dev']and bound['group']!=h['parent']
  assert writers[67]['verified_at']<=finite(source['verified_at'])<h['deadline']and source['verified_at']<=writers[68]['queued_at']
  assert source['verified_at']<=c['environment']['after']['started_at']
 final=w['final_process_verified_at']
 if fault==0:assert writers[68]['verified_at']<=finite(final)<h['deadline']and final<=c['environment']['after']['started_at']
 else:assert final is None
 assert all(v['verified_at']is None or v['verified_at']<=c['environment']['after']['started_at']for v in writers)
 assert all(v['queued_at']<=c['environment']['after']['started_at']for v in writers)
 drop_fields=['whole_chain_retained_after_drop','quarantine_context_retained_after_drop','producer_context_retained_after_drop','movement_context_retained_after_drop','original_provision_context_retained_after_drop']
 if continuation:assert fault==0 and w['continued_original_context']is True and all(w[k]is False for k in drop_fields)
 else:assert w.get('continued_original_context',False)is False and all(w[k]is True for k in drop_fields)
 assert all(w[k]is True for k in['parent_pristine','same_service_retained','initial_quarantine_only','initial_quarantine_installation_observed_all_scopes'])
 assert all(w[k]is False for k in['producer_operational_publication','producer_exceptions_authorized','host_network_links_or_routes_created','up_authorized','operational_reuse_authorized','requirement8_complete'])and 'host_resources_created'not in w
 assert w['producer_group_creation_observed']is(fault in(0,2))
 return dict(original_operation_clocks_verified=17,ordered_writers_verified=count,original_group_creation_observed=fault in(0,2),producer_result_acknowledged=fault==0,final_whole_chain_drop_verified=not continuation,quarantine_original_context_continued=continuation,operational_publication=False,parent_death_lock_survival_claimed=False)
