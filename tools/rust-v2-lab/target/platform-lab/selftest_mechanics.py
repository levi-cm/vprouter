"""Closed frozen-source mechanical selftest records; no network acceptance."""
import json,math,tarfile
if not __debug__:raise RuntimeError('optimized_python_refused')
EXPECTED={
 'LAB_FIXED_NETWORK_FILTER':dict(distinct_gate_result=True,two_actual_wait_zero=True,eof_verified=True,directional_denials=True,actual_route_generic_sockets=True,no_netlink_transactions=True,entered_transport_namespace=False,provisioning_proven=False),
 'LAB_FIXED_MOVEMENT_FILTER':dict(four_original_sockets=True,two_namespace_pins=True,actual_wait_zero=True,selected_io_reached_kernel=True,high_word_and_direction_denied=True,scm_rights_denied=True,no_netlink_transactions=True,actual_namespace_movement=False),
 'LAB_FIXED_NETFILTER_FILTER':dict(two_actual_wait_zero=True,eof_verified=True,two_original_netfilter_sockets=True,route_generic_creator_denied=True,direction_and_high_word_denied=True,no_netlink_transactions=True,actual_quarantine_installation=False),
 'LAB_FIXED_PRODUCER_FILTER':dict(actual_wait_zero=True,eof_verified=True,original_scm_descriptor_retained=True,exclusive_mkdir_collision_refused=True,foreign_pointer_mode_high_word_denied=True,fork_exec_namespace_unlink_denied=True,actual_cgroup_creation=False),
}
PROGRESS='LAB_PENDING_ROUTE_PROGRESS'
CAPACITY='LAB_ASSEMBLY_CAPACITY_REFUSALS'
PRODUCER_NETFILTER='LAB_FIXED_PRODUCER_NETFILTER_FILTER'
VETH='LAB_FIXED_VETH_FILTER'
VETH_MOVE='LAB_FIXED_VETH_MOVE_FILTER'
def validate_progress(value):
 assert isinstance(value,dict)and set(value)=={'requested_at','deadline','sequence','pending_parent_polls','independent_pid','independent_start','actual_wait_status','independent_completed_at','route_completed_at','reply_messages','original_kernel_dump_completed','unrelated_owner_rpc_claimed'}
 for key in['requested_at','deadline','independent_completed_at','route_completed_at']:assert type(value[key])in(int,float)and math.isfinite(value[key])and value[key]>0
 assert abs(value['deadline']-value['requested_at']-2)<.00001 and value['requested_at']<=value['independent_completed_at']<=value['route_completed_at']<value['deadline']
 for key,minimum in[('sequence',1),('pending_parent_polls',2),('independent_pid',2),('independent_start',1),('reply_messages',1)]:assert type(value[key])is int and minimum<=value[key]<=18446744073709551615
 assert all(value[key]<=4294967295 for key in['sequence','pending_parent_polls','independent_pid'])and type(value['actual_wait_status'])is int and value['actual_wait_status']==0
 assert value['original_kernel_dump_completed']is True and value['unrelated_owner_rpc_claimed']is False
 return value
def validate_capacity_refusals(value,eligible=None,counts=None,after=None,earliest=None):
 assert set(value)=={'schema','requested_at','deadline','verified_at','original_pid','original_start','actual_wait_status','eof','failed_original_pid','failed_original_start','failed_actual_wait_status','failed_exit_code','failed_charges_unchanged','eligible_original_pid','eligible_original_start','eligible_foreign_refused','parent_still_eligible','parent_counts_before','parent_counts_after','canonical_operation','successful_capacity_transfer_proven'}
 def integer(v,low=0,high=18446744073709551615):assert type(v)is int and low<=v<=high;return v
 def finite(v):assert type(v)in(int,float)and math.isfinite(v)and v>0;return v
 assert type(value['schema'])is int and value['schema']==1
 at,end,verified=(finite(value[k])for k in('requested_at','deadline','verified_at'));assert abs(end-at-2)<.00001 and at<=verified<end
 if after is not None:assert verified<=finite(after)
 if earliest is not None:assert finite(earliest)<=at
 pid=integer(value['original_pid'],2,4294967295);integer(value['original_start'],1)
 assert type(value['actual_wait_status'])is int and value['actual_wait_status']==0 and value['eof']is True
 assert value['canonical_operation']is value['successful_capacity_transfer_proven']is False
 for k in('parent_counts_before','parent_counts_after'):
  assert isinstance(value[k],list)and len(value[k])==2
  for n in value[k]:integer(n,0,64)
 assert value['parent_counts_before']==value['parent_counts_after']
 if counts is not None:assert value['parent_counts_before']==counts
 if eligible is None:
  assert integer(value['failed_original_pid'],2,4294967295)!=pid
  if value['failed_original_start']is not None:integer(value['failed_original_start'],1)
  assert type(value['failed_actual_wait_status'])is int and value['failed_actual_wait_status']==31232 and type(value['failed_exit_code'])is int and value['failed_exit_code']==122
  assert isinstance(value['failed_charges_unchanged'],list)and len(value['failed_charges_unchanged'])==2 and all(type(n)is int and n==1 for n in value['failed_charges_unchanged'])
  assert value['eligible_original_pid']is value['eligible_original_start']is None and value['eligible_foreign_refused']is value['parent_still_eligible']is False
 else:
  assert len(eligible)==2;integer(eligible[0],2,4294967295);integer(eligible[1],1)
  assert type(value['eligible_original_pid'])is int and type(value['eligible_original_start'])is int and[value['eligible_original_pid'],value['eligible_original_start']]==list(eligible)and pid!=eligible[0]
  assert value['eligible_foreign_refused']is value['parent_still_eligible']is True
  assert all(value[k]is None for k in('failed_original_pid','failed_original_start','failed_actual_wait_status','failed_exit_code','failed_charges_unchanged'))
 return dict(original_checker_actual_wait_zero=True,failed_original_refusal_verified=eligible is None,eligible_foreign_refusal_verified=eligible is not None,successful_capacity_transfer_proven=False,canonical_operation=False)

def validate_producer_netfilter_filter(value):
 assert isinstance(value,dict)
 yes={'eof_verified','six_selected_descriptors','four_read_only_inputs','parent_group_pread_denied','all_group_writes_denied','foreign_and_high_word_denied','role_direction_denied','no_netlink_transactions'}
 no={'actual_group_observation','actual_table_observation'}
 assert set(value)=={'schema','original_pid','original_start','actual_wait_status','requested_at','deadline','verified_at'}|yes|no
 assert type(value['schema'])is int and value['schema']==1
 assert type(value['original_pid'])is int and 2<=value['original_pid']<=4294967295 and type(value['original_start'])is int and 1<=value['original_start']<=18446744073709551615
 assert type(value['actual_wait_status'])is int and value['actual_wait_status']==0
 for key in('requested_at','deadline','verified_at'):assert type(value[key])in(int,float)and 0<value[key]<=1.7976931348623157e308 and math.isfinite(value[key])
 assert abs(value['deadline']-value['requested_at']-2)<.00001 and value['requested_at']<=value['verified_at']<value['deadline']
 assert all(value[k]is True for k in yes)and all(value[k]is False for k in no)
 return value

def validate_veth_filter(value):
 assert isinstance(value,dict)
 yes={'eof_verified','route_io_reached_kernel','generic_transactions_denied','generic_custody_verified','high_word_and_direction_denied','scm_rights_denied','no_netlink_transactions'}
 no={'actual_pair_creation','actual_host_mutation'}
 assert set(value)=={'schema','original_pid','original_start','actual_wait_status','requested_at','deadline','verified_at'}|yes|no
 assert type(value['schema'])is int and value['schema']==1
 assert type(value['original_pid'])is int and 2<=value['original_pid']<=4294967295
 assert type(value['original_start'])is int and 1<=value['original_start']<=18446744073709551615
 assert type(value['actual_wait_status'])is int and value['actual_wait_status']==0
 for key in('requested_at','deadline','verified_at'):assert type(value[key])in(int,float)and 0<value[key]<=1.7976931348623157e308 and math.isfinite(value[key])
 assert abs(value['deadline']-value['requested_at']-2)<.00001 and value['requested_at']<=value['verified_at']<value['deadline']
 assert all(value[k]is True for k in yes)and all(value[k]is False for k in no)
 return value

def validate_mechanics(source_archive,stdout):
 assert isinstance(stdout,str)
 with tarfile.open(source_archive)as archive:
  code=archive.extractfile('crates/vprouter-launch/src/kernel/wireguard_role.rs').read()
  try:producer_code=archive.extractfile('crates/vprouter-launch/src/kernel/producer_creation.rs').read()
  except KeyError:producer_code=b''
  try:capacity_code=archive.extractfile('crates/vprouter-launch/src/kernel/capacity_lab.rs').read()
  except KeyError:capacity_code=b''
 expected=[key for key in EXPECTED if key.encode()in(code+producer_code)]
 if PROGRESS.encode()in producer_code:expected.append(PROGRESS)
 if CAPACITY.encode()in capacity_code:expected.append(CAPACITY)
 if PRODUCER_NETFILTER.encode()in code:expected.append(PRODUCER_NETFILTER)
 if VETH.encode()in code:expected.append(VETH)
 if VETH_MOVE.encode()in code:expected.append(VETH_MOVE)
 rows={key:[]for key in[*EXPECTED,PROGRESS,CAPACITY,PRODUCER_NETFILTER,VETH,VETH_MOVE]}
 def unique_object(pairs):
  result={}
  for key,value in pairs:
   assert key not in result
   result[key]=value
  return result
 for line in stdout.splitlines():
  key,separator,value=line.partition(' ')
  if key in rows:
   assert separator
   rows[key].append(json.loads(value,object_pairs_hook=unique_object))
 for key,values in rows.items():
  assert len(values)==(1 if key in expected else 0),key
  if values:
   value=values[0]
   if key==PROGRESS:validate_progress(value)
   elif key==CAPACITY:validate_capacity_refusals(value)
   elif key==PRODUCER_NETFILTER:validate_producer_netfilter_filter(value)
   elif key in(VETH,VETH_MOVE):validate_veth_filter(value)
   else:assert isinstance(value,dict)and set(value)==set(EXPECTED[key])and all(type(v)is bool for v in value.values())and value==EXPECTED[key],key
 if rows[VETH]and rows[VETH_MOVE]:assert tuple(rows[VETH][0][k]for k in('original_pid','original_start'))!=tuple(rows[VETH_MOVE][0][k]for k in('original_pid','original_start'))
 return dict(frozen_source_records=expected,verified_records=len(expected),pending_route_progress=rows[PROGRESS][0]if rows[PROGRESS]else None,capacity_refusals=rows[CAPACITY][0]if rows[CAPACITY]else None,producer_netfilter_filter=rows[PRODUCER_NETFILTER][0]if rows[PRODUCER_NETFILTER]else None,veth_filter=rows[VETH][0]if rows[VETH]else None,veth_move_filter=rows[VETH_MOVE][0]if rows[VETH_MOVE]else None,scope='ROOTLESS_SOCKET_FILTER_RETAINED_ROUTE_READ_AND_FAILED_CAPACITY_REFUSAL_MECHANICS_ONLY; no pair creation, host mutation, namespace movement, provisioning, actual cgroup creation, quarantine, unrelated owner RPC or release acceptance')
