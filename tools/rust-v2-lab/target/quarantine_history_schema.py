"""Canonical initial-quarantine prefix only; original native proof is required."""
if not __debug__:raise RuntimeError('optimized_python_refused')

def validate_own_intent_polling(c,p):
 expected=c.get('own_intent_polling_expected',False);assert type(expected)is bool
 if not expected:return dict(required=False)
 proof=c['quarantine_top']['own_intent_polling'];integer=c['integer'];finite=c['finite'];h=p['netfilter'][0];writer=p['writers'][42]
 assert set(proof)=={'queued_polls','held_pending_polls','negative_checks','original_writer','requested_at','deadline','verified_at','actual_wait_status'}
 assert integer(proof['queued_polls'])==1 and integer(proof['held_pending_polls'],2)<=18446744073709551615 and integer(proof['negative_checks'])==12
 identity=proof['original_writer'];assert set(identity)=={'index','pid','start'}and integer(identity['index'])==42
 assert integer(identity['pid'],2)==writer['pid']and identity['pid']<=4294967295 and integer(identity['start'],1)==writer['start']and identity['start']<=18446744073709551615 and writer['phase']=='netfilter_intent'
 assert integer(proof['actual_wait_status'])==integer(writer['actual_wait_status'])==0
 assert finite(proof['requested_at'])==h['requested_at']and finite(proof['deadline'])==h['deadline']==writer['io_deadline']==writer['parent_deadline']
 assert proof['verified_at']==writer['verified_at']and writer['queued_at']<=finite(proof['verified_at'])<proof['deadline']and proof['verified_at']<=h['birth']['born_at']
 assert proof['verified_at']<=c['environment']['after']['started_at']
 return dict(required=True,queued_polls=1,held_pending_polls=proof['held_pending_polls'],negative_checks=12,original_writer_index=42,same_original_end=True)

def validate_initial_history(c,p):
 old=c['movement_top']['preparation'];histories=p['netfilter'];q=p['quarantine_query']
 clock,finite,birth,integer,ids=(c[k]for k in['original_clock','finite','birth','integer','ids'])
 def digest(value):
  assert isinstance(value,list)and len(value)==32 and any(value)and all(type(x)is int and 0<=x<=255 for x in value)
  return value
 assert len(old['writers'])==42 and p['writers'][:42]==old['writers']and len(p['writers'])>=63
 for key in['member','requested_at','deadline','birth','base_network','data_network','transport_network','inspection','attachment','fresh_transport','wireguard','movement_query','canonical_owner_epoch','owner_host_anchor_present','canonical_result_present','service_reserved']:
  assert p[key]==old[key],key
 assert isinstance(histories,list)and len(histories)==6
 assert q['kind']=='QuarantineRecheck'and q['initial']is None and q['facts']==old['movement_query']['facts']
 digest(q['request']);clock(q['requested_at'],q['deadline']);birth(q['birth'],q['requested_at'],q['deadline'])
 assert q['birth']['born_at']<=finite(q['verified_at'])<q['deadline']
 expected=[('host','sockets',42),('host','initial_quarantine',45),('transport','sockets',48),('transport','initial_quarantine',51),('data','sockets',54),('data','initial_quarantine',60)]
 host=c['host'];declaration=list(bytes.fromhex(host['sha256']))
 namespaces={'host':host['declaration']['host_namespace'],'transport':old['transport_network'],'data':old['data_network']}
 configuration=old['wireguard'][0]['configuration'];requests=[]
 assert c['movement_top']['final_process_verified_at']<=histories[0]['requested_at']
 for index,(h,(scope,kind,offset))in enumerate(zip(histories,expected)):
  assert set(h)=={'kind','scope','request','namespace','configuration','host_declaration','policy','query','requested_at','deadline','birth','result','verified_at'}
  assert h['scope']==scope and h['kind']==kind and h['namespace']==namespaces[scope]
  request=digest(h['request']);assert request not in requests;requests.append(request)
  digest(h['policy']);assert h['configuration']==configuration and h['host_declaration']==declaration
  clock(h['requested_at'],h['deadline']);birth(h['birth'],h['requested_at'],h['deadline'])
  assert h['birth']['born_at']<=finite(h['verified_at'])<h['deadline']
  if index:
   previous_writer=56 if index==5 else offset-1
   assert histories[index-1]['verified_at']<=h['requested_at']and p['writers'][previous_writer]['verified_at']<=h['requested_at']
  else:assert old['writers'][41]['verified_at']<=h['requested_at']
  if kind=='initial_quarantine':assert h['policy']==histories[index-1]['policy']
  result=h['result'];assert set(result)=={'namespace','policy','observed_at'}and result['namespace']==h['namespace']and result['policy']==h['policy']
  if kind=='sockets':assert result['observed_at']is None
  else:assert h['birth']['born_at']<=finite(result['observed_at'])<=h['verified_at']
  if index==5:
   assert h['query']==q['request']and h['requested_at']==q['requested_at']and h['deadline']==q['deadline']and q['verified_at']<=h['birth']['born_at']
  else:assert h['query']is None
  writers=p['writers'][offset:offset+3];assert [w['phase']for w in writers]==['netfilter_intent','netfilter_birth','netfilter_result']
  assert writers[0]['verified_at']<=h['birth']['born_at']<=writers[1]['queued_at']and writers[1]['verified_at']<=h['verified_at']<=writers[2]['queued_at']
  for writer in writers:
   pair=(integer(writer['pid'],2),integer(writer['start'],1));assert pair not in ids;ids.append(pair)
   assert h['requested_at']<=finite(writer['queued_at'])<h['deadline']and writer['io_deadline']==writer['parent_deadline']==h['deadline']and integer(writer['actual_wait_status'])==0
   assert writer['queued_at']<=finite(writer['verified_at'])<h['deadline']
 writers=p['writers'][57:60];assert [w['phase']for w in writers]==['quarantine_query_intent','quarantine_query_birth','quarantine_query_result']
 assert writers[0]['verified_at']<=q['birth']['born_at']<=writers[1]['queued_at']and writers[1]['verified_at']<=q['verified_at']<=writers[2]['queued_at']and writers[2]['verified_at']<=p['writers'][60]['queued_at']
 assert p['writers'][56]['verified_at']<=q['requested_at']
 for writer in writers:
  pair=(integer(writer['pid'],2),integer(writer['start'],1));assert pair not in ids;ids.append(pair)
  assert q['requested_at']<=finite(writer['queued_at'])<q['deadline']and writer['io_deadline']==writer['parent_deadline']==q['deadline']and integer(writer['actual_wait_status'])==0
  assert writer['queued_at']<=finite(writer['verified_at'])<q['deadline']
 assert all(w['verified_at']<=c['environment']['after']['started_at']for w in p['writers'][42:63])
 return dict(canonical_initial_operations=6,ordered_writer_prefix=63,original_operation_clock_prefix=16,scope='CANONICAL_PREFIX_ONLY; no native constructor, WAN, actual table, producer or final Drop acceptance')
