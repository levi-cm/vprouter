"""Original completed-resource capacity handoff, without reuse/publication authority."""
import json
if not __debug__:raise RuntimeError('optimized_python_refused')
def same_json(left,right):return json.dumps(left,sort_keys=True,separators=(',',':'),allow_nan=False)==json.dumps(right,sort_keys=True,separators=(',',':'),allow_nan=False)
def validate_assembly(c):
 w=c['assembly_top'];fault=c['assembly_fault'];old=c['quarantine_top']['preparation'];integer=c['integer']
 assert type(fault)is int and fault in(0,1,2,3)
 expected={0:15,1:0,2:1,3:15}[fault];complete=fault in(0,3)
 fields={'schema','fault','quarantine','preparation','resources','reservation','charges_before','charges_after','charges_after_drop','retired_original_jobs','handoff_complete','duplicate_reservation_refused','duplicate_reservation_counts','repeat_retirement_refused','lower_repeat_retirement_refused','fence_blocked_next_transfer','fence_counts','whole_chain_retained_after_drop','assembly_context_retained_after_drop','producer_context_retained_after_drop','quarantine_context_retained_after_drop','movement_context_retained_after_drop','original_provision_context_retained_after_drop','parent_pristine','resource_cleanup_authorized','producer_operational_publication','up_authorized','operational_reuse_authorized','global_child_capacity_limit','multi_exit_runtime_proven','requirement8_complete'}
 assert set(w)==fields and type(w['schema'])is int and w['schema']==1 and type(w['fault'])is int and w['fault']==fault
 assert w['quarantine']==c['quarantine_top']and c['quarantine_fault']==0
 p=w['preparation'];assert set(p)==set(old)
 assert all(same_json(p[k],old[k])for k in old if k!='mutation_fenced')and p['mutation_fenced']is(fault in(1,2))
 assert len(p['writers'])==69 and p['native_children_reaped']is p['service_reserved']is True and p['member_native_jobs_collected']is p['canonical_pending']is False
 def charges(value):
  assert isinstance(value,list)and len(value)==2
  for n in value:integer(n)
  return value
 after=[15-expected,0 if complete else 11]
 assert charges(w['charges_before'])==[15,11]and charges(w['charges_after'])==after and charges(w['charges_after_drop'])==after
 assert integer(w['retired_original_jobs'])==expected and w['handoff_complete']is complete
 assert w['duplicate_reservation_refused']is(fault==3)and w['repeat_retirement_refused']is(fault!=1)and w['lower_repeat_retirement_refused']is complete and w['fence_blocked_next_transfer']is(fault in(1,2))
 for key,present,target in[('duplicate_reservation_counts',fault==3,[15,11]),('fence_counts',fault in(1,2),after)]:
  value=w[key]
  if not present:assert value is None
  else:assert isinstance(value,list)and len(value)==2 and all(charges(v)==target for v in value)
 reservation=w['reservation']
 assert set(reservation)=={'member','owner_epoch','original_jobs','complete','global_assemblies_reserved','global_assembly_limit','global_transferred_ticket_limit','member_transfer_pending'}
 assert reservation['member']==p['member']==c['descriptor']['primary']and reservation['owner_epoch']==p['canonical_owner_epoch']
 assert integer(reservation['original_jobs'])==15 and reservation['complete']is complete and reservation['member_transfer_pending']is(not complete)
 assert integer(reservation['global_assemblies_reserved'])==1 and integer(reservation['global_assembly_limit'])==128 and integer(reservation['global_transferred_ticket_limit'])==1920
 births=[p['attachment']['birth'],p['fresh_transport']['birth'],p['fresh_transport']['mount']['birth']]+[h['birth']for h in p['wireguard']]+[h['birth']for h in p['netfilter']]+[p['producer_creation']['birth']]
 assert len(births)==15 and len({(b['pid'],b['start'])for b in births})==15
 kinds=['NamespaceAttachment','FreshTransport','FreshTransportMount']+['WireguardSecret']*5+['FixedNetfilter']*6+['ProducerCreation']
 resources=w['resources'];assert isinstance(resources,list)and len(resources)==15
 for index,(resource,birth,kind)in enumerate(zip(resources,births,kinds)):
  assert set(resource)=={'kind','original_pid','original_start','actual_wait_status','transfer_started','launch_charge_retired','lower_charge_required','lower_charge_retired','fully_retired','native_job_state'}
  assert resource['kind']==kind and integer(resource['original_pid'],2)<=4294967295 and integer(resource['original_start'],1)>0
  assert resource['original_pid']==birth['pid']and resource['original_start']==birth['start']and integer(resource['actual_wait_status'])==0
  retired=index<expected;lower=3<=index<14
  assert resource['transfer_started']is resource['launch_charge_retired']is resource['fully_retired']is retired
  assert resource['lower_charge_required']is lower
  if lower:assert resource['lower_charge_retired']is retired
  else:assert resource['lower_charge_retired']is None
  assert resource['native_job_state']==('transferred_resources'if retired else'born')
 for key in('whole_chain_retained_after_drop','assembly_context_retained_after_drop','producer_context_retained_after_drop','quarantine_context_retained_after_drop','movement_context_retained_after_drop','original_provision_context_retained_after_drop','parent_pristine'):assert w[key]is True
 for key in('resource_cleanup_authorized','producer_operational_publication','up_authorized','operational_reuse_authorized','multi_exit_runtime_proven','requirement8_complete'):assert w[key]is False
 assert integer(w['global_child_capacity_limit'])==64
 return dict(original_operation_clocks_verified=17,ordered_writers_verified=69,original_resource_jobs_verified=15,launch_charges_retired=expected,lower_charges_retired=11 if complete else 0,handoff_complete=complete,final_whole_chain_drop_verified=True,resources_collected=False,operational_publication=False,multi_exit_runtime_proven=False)
