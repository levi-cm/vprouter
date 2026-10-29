"""Cached boundary only; cancellation ordering is source-bounded, never authority."""
import json,math,re
if not __debug__:raise RuntimeError('optimized_python_refused')
def phases_from_source(code):
 phases={x.decode()for x in re.findall(rb'trace[.]phase\s*=\s*"([a-z_]+)"',code)}
 for block in re.findall(rb'for\s+key\s+in\s*\[([^]]*)\]\s*\{\s*trace[.]phase\s*=\s*key',code,re.S):phases.update(x.decode()for x in re.findall(rb'"([a-z_]+)"',block))
 for block in re.findall(rb'let phases\s*=\s*\[([^]]*)\]',code,re.S):phases.update(x.decode()for x in re.findall(rb'"([a-z_]+)"',block))
 match=re.search(rb'let mut trace\s*=\s*LabPostfault\s*\{(.*?)\};',code,re.S);assert match
 phases.update(x.decode()for x in re.findall(rb'phase:\s*"([a-z_]+)"',match[1]));assert phases;return phases
def loads_unique(text):
 def unique(pairs):
  out={}
  for key,value in pairs:
   assert key not in out
   out[key]=value
  return out
 return json.loads(text,object_pairs_hook=unique)
def integer(v,low=0,high=18446744073709551615):assert type(v)is int and low<=v<=high;return v
def finite(v):assert type(v)in(int,float)and 0<v<=1.7976931348623157e308 and math.isfinite(v);return v
def digest(v):assert isinstance(v,list)and len(v)==32 and any(v)and all(type(n)is int and 0<=n<=255 for n in v)
def validate(row,phases,fault,owner_pid,query,after):
 assert set(row)=={'schema','creator','fault','query','requested_at','deadline','phase','constructor','preparation','charges'}
 assert type(row['schema'])is int and row['schema']==1 and type(row['fault'])is int and row['fault']==fault and fault in(1,2,3)
 assert integer(row['creator'],2,4294967295)==owner_pid and row['phase']in phases;digest(row['query'])
 assert row['query']==query['request']and finite(row['requested_at'])==query['requested_at']<=finite(after)and finite(row['deadline'])==query['deadline']and abs(row['deadline']-row['requested_at']-2)<.00001
 constructor=row['constructor']
 if constructor is not None:
  assert set(constructor)=={'request','original_pid','original_start','actual_wait_status','native_born','native_job_state','registered_native_slots','original_registration_slots_verified','borrowed_registration_count','complete_native_registration','durable_birth_released'};digest(constructor['request'])
  if constructor['original_pid']is None:assert constructor['original_start']is constructor['actual_wait_status']is None
  else:integer(constructor['original_pid'],2,4294967295)
  if constructor['original_start']is not None:integer(constructor['original_start'],1)
  if constructor['actual_wait_status']is not None:integer(constructor['actual_wait_status'],0,2147483647)
  for k in('native_born','original_registration_slots_verified','complete_native_registration','durable_birth_released'):assert type(constructor[k])is bool
  assert constructor['native_born']is(constructor['original_pid']is not None)and constructor['native_job_state']in{'prepared','born','no_birth','collected','transferred_resources'}
  integer(constructor['registered_native_slots']);integer(constructor['borrowed_registration_count'])
  assert constructor['original_registration_slots_verified']is(constructor['registered_native_slots']>=9)
 preparation=row['preparation']
 if preparation is not None:
  assert set(preparation)=={'writer_count','member_native_jobs_collected','native_children_reaped','service_reserved','mutation_fenced','canonical_pending','entry_phase','entry_producer_absent','binding_birth_present','binding_result_present'}
  if preparation['writer_count']is not None:integer(preparation['writer_count'])
  for k in('member_native_jobs_collected','native_children_reaped','service_reserved','mutation_fenced','canonical_pending','entry_producer_absent','binding_birth_present','binding_result_present'):assert type(preparation[k])is bool
  assert preparation['entry_phase']is None or preparation['entry_phase']in{'creating','offline','activating','bootstrap'}
 if row['charges']is not None:
  assert isinstance(row['charges'],list)and len(row['charges'])==2
  for n in row['charges']:integer(n,0,64)
 return dict(last_entered_boundary=row['phase'],cached_constructor_observed=constructor is not None,cached_preparation_observed=preparation is not None,cached_charges_observed=row['charges']is not None,post_cancellation_snapshot=None if row['phase']=='driver_poll'else True,cancellation_order='unobserved'if row['phase']=='driver_poll'else'after_existing_failure_path',fresh_reap_or_resource_authority=False)
