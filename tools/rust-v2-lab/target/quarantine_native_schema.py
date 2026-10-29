"""Bind cached original NF and WAN receipts; no post-reap table grant."""
if not __debug__:raise RuntimeError('optimized_python_refused')
def validate_initial_receipts(c,p,operations,query,wan):
 histories=p['netfilter'];canonical=p['quarantine_query'];integer=c['integer'];finite=c['finite']
 assert isinstance(operations,list)and len(operations)==len(histories)==6
 for op,h in zip(operations,histories):
  assert all(op[key]==h[key]for key in['kind','scope','request','requested_at','deadline','birth','result'])
  assert integer(op['actual_wait_status'])==0 and op['native_born']is op['full_descriptor_registration']is op['context_retained']is True and op['native_job_state']=='born'
  assert integer(op['original_pid'],2)==h['birth']['pid']and integer(op['original_start'],1)==h['birth']['start']
  assert integer(op['registered_native_slots'],3)>=3
  assert type(op['borrowed_registration_count'])is int and op['borrowed_registration_count']==(0 if h['kind']=='sockets'else 2)
  assert op['acknowledged']is True and op['accepted_at']==h['verified_at']and h['birth']['born_at']<=finite(op['accepted_at'])<h['deadline']
 assert all(query[key]==canonical[key]for key in['kind','requested_at','deadline','birth','facts','verified_at'])
 assert query['kind']=='QuarantineRecheck'and integer(query['actual_wait_status'])==0 and query['original_peer_receipt']is True and query['handler_identity_claimed']is False
 integer(query['listener_origin_pid'],1);assert type(query['listener_origin_uid'])is type(query['listener_origin_gid'])is int and query['listener_origin_uid']==query['listener_origin_gid']==0
 expected_digest=list(bytes.fromhex(c['host']['sha256']));declaration=c['host']['declaration'];host_initial=histories[1]
 assert wan['declaration_digest']==expected_digest and wan['host_namespace']==declaration['host_namespace']
 assert wan['name']==declaration['wan']['name']and type(wan['index'])is int and wan['index']==declaration['wan']['index']
 assert isinstance(wan['address'],list)and all(type(x)is int for x in wan['address'])and wan['address']==declaration['wan']['address']
 assert wan['original_observer_retained']is True
 assert wan['requested_at']==host_initial['requested_at']and wan['deadline']==host_initial['deadline']
 assert wan['requested_at']<=finite(wan['verified_at'])<=host_initial['birth']['born_at']and wan['verified_at']<wan['deadline']
 assert wan['verified_at']<=c['environment']['after']['started_at']
 return dict(original_netfilter_receipts=6,fresh_data_policy_receipt=True,wan_bound_to_host_initial_window=True,scope='ORIGINAL_INSTALLATION_RECEIPTS_ONLY; no post-reap current table, producer publication, placement, UP or final Drop grant')
