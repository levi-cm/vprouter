"""Validate bounded cached timing; never turn a diagnostic into native authority."""
import math,re
if not __debug__:raise RuntimeError('optimized_python_refused')
SOURCE_PATHS=('crates/vprouter-launch/src/attachment/movement.rs','crates/vprouter-launch/src/attachment/provision.rs','crates/vprouter-launch/src/kernel/wireguard_role.rs','crates/vprouter-launch/src/owned/preparation/wireguard.rs')
def extract_pairs(codes):
 assert len(codes)==len(SOURCE_PATHS)
 pairs={(a.decode(),b.decode())for a,b in re.findall(rb'Span::new\(\s*"([a-z_]+)",\s*"([a-z_]+)"',b'\n'.join(codes))};assert pairs;return pairs

def integer(v,low=0,high=2**64-1):assert type(v)is int and low<=v<=high;return v
def number(v,positive=True):assert type(v)in(int,float)and math.isfinite(v)and(v>0 if positive else v>=0);return v
def boolean(v):assert type(v)is bool;return v
def digest(v):assert isinstance(v,list)and len(v)==32;[integer(x,0,255)for x in v];return v
def clock(row,observed):
 digest(row['request']);at=number(row['requested_at']);end=number(row['deadline']);assert at<=observed and abs(end-at-2)<.00001;return at,end
def optional_time(t,at,end,observed):
 if t is not None:assert at<=number(t)<end and t<=observed

def lower(row,at,end,observed):
 if row is None:return
 assert set(row)=={'read_phase','readback_present','completed_present','report_present','validated','preparation_bound','accepted_at'}
 integer(row['read_phase'],0,2)
 for k in('readback_present','completed_present','report_present','validated','preparation_bound'):boolean(row[k])
 if row['accepted_at']is not None:assert at<=number(row['accepted_at'])<=observed

def native(row,observed):
 if row is None:return
 assert set(row)=={'request','requested_at','deadline','original_pid','original_start','actual_wait_status','native_born','complete_present','result_present','accepted_at','acknowledged','postcompletion_inventory_polls','movement'}
 at,end=clock(row,observed)
 if row['original_pid']is None:assert row['original_start']is row['actual_wait_status']is None
 else:integer(row['original_pid'],2,2**32-1)
 if row['original_start']is not None:integer(row['original_start'],1)
 if row['actual_wait_status']is not None:integer(row['actual_wait_status'],0,2**31-1)
 for k in('native_born','complete_present','result_present','acknowledged'):boolean(row[k])
 integer(row['postcompletion_inventory_polls'],0,2**32-1);optional_time(row['accepted_at'],at,end,observed)
 if row['accepted_at']is not None:assert type(row['actual_wait_status'])is int and row['actual_wait_status']==0 and row['result_present']is True
 lower(row['movement'],at,end,observed)

def inner(row,observed,validate_preparation):
 if row is None:return
 assert set(row)=={'step','request','requested_at','deadline','child','verified','last_history','preparation'}
 assert row['step']in{'intent','preparing','birth','executing','result','complete'};clock(row,observed)
 for key in('child','verified','last_history'):
  native(row[key],observed)
  if key!='last_history'and row[key]is not None:assert all(row[key][k]==row[k]for k in('request','requested_at','deadline'))
 if row['preparation']is not None:validate_preparation(row['preparation'])

def validate(rows,pairs,errors,after,validate_preparation):
 assert isinstance(rows,list)and 1<=len(rows)<=3
 scopes=[];request=None;previous_at=None;attempted=[]
 for row in rows:
  assert set(row)=={'schema','scope','reason','request','requested_at','deadline','observed_at','cached','spans','omitted','inclusive_spans_not_additive','native_reads'}
  assert type(row['schema'])is int and row['schema']==1 and row['scope']in{'native','inner','outer'}and row['reason']in errors
  assert row['scope']not in scopes;scopes.append(row['scope'])
  observed=number(row['observed_at']);assert observed<=number(after)
  if previous_at is not None:assert previous_at<=observed
  previous_at=observed;at,end=clock(row,observed)
  identity=(row['request'],at,end)
  if request is None:request=identity
  else:assert request==identity
  assert row['inclusive_spans_not_additive']is True and row['native_reads']is False
  integer(row['omitted'],0,2**32-1)
  spans=row['spans'];assert isinstance(spans,list)and len(spans)<=32;seen=set()
  for span in spans:
   assert set(span)=={'scope','phase','calls','failed_calls','first_at','last_at','total_seconds','max_seconds'}
   pair=(span['scope'],span['phase']);assert pair in pairs and pair not in seen;seen.add(pair)
   calls=integer(span['calls'],1,2**32-1);assert integer(span['failed_calls'],0,2**32-1)<=calls
   first,last=number(span['first_at']),number(span['last_at']);assert at<=first<=last<=observed
   total,maximum=number(span['total_seconds'],False),number(span['max_seconds'],False)
   assert maximum<=total+1e-7 and maximum<=last-first+1e-7 and total<=last-first+1e-7
   assert total<=calls*maximum+1e-7
  cached=row['cached']
  attempted.extend(attempted_timestamps(cached,row['scope']))
  if row['scope']=='native':
   native(cached,observed)
   if cached is not None:assert cached['requested_at']==at and cached['deadline']==end
  elif row['scope']=='inner':
   inner(cached,observed,validate_preparation)
   if cached is not None:assert cached['requested_at']==at and cached['deadline']==end
  else:
   assert set(cached)=={'outer_step','inner','completed_owner','final_process_verified_at'}
   assert cached['outer_step']in{'query_intent','query_birth','query_reading','query_result','move_prepare','moving','complete'}
   inner(cached['inner'],observed,validate_preparation);inner(cached['completed_owner'],observed,validate_preparation)
   for key in('inner','completed_owner'):
    if cached[key]is not None:assert cached[key]['requested_at']==at and cached[key]['deadline']==end
   optional_time(cached['final_process_verified_at'],at,end,observed)
 assert scopes==sorted(scopes,key=['native','inner','outer'].index)
 return dict(scopes=scopes,earliest_scope=scopes[0],cached_only=True,inclusive_spans_not_additive=True,fresh_reap_or_resource_authority=False,lower_attempted_timestamps=attempted)

def attempted_timestamps(value,scope,path='cached'):
 out=[]
 if not isinstance(value,dict):return out
 if 'movement'in value and isinstance(value['movement'],dict)and value['movement']['accepted_at']is not None:
  at=value['movement']['accepted_at'];end=value['deadline']
  out.append(dict(scope=scope,path=path+'.movement.accepted_at',timestamp=at,original_deadline=end,status='timely'if at<end else 'late',acceptance_authority=False))
 for key,child in value.items():
  if isinstance(child,dict):out.extend(attempted_timestamps(child,scope,path+'.'+key))
 return out
