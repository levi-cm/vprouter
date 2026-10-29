"""Cached failure diagnostics only; null never implies collected or authorized."""
import math
if not __debug__:raise RuntimeError('optimized_python_refused')
def integer(v,minimum=0):assert type(v)is int and minimum<=v<=18446744073709551615;return v
def finite(v):assert type(v)in(int,float)and math.isfinite(v)and v>0;return v
def validate_failure(row,phases,after,fixture=False):
 assert type(fixture)is bool
 assert set(row)==({'schema','phase','reason','operation_index','step','requested_at','deadline','queue_state','job_counts','observed_at','child'}|({'own_intent_fixture'}if fixture else set()))
 if fixture:validate_fixture(row['own_intent_fixture'])
 assert type(row['schema'])is int and row['schema']==1 and row['phase']in phases
 assert isinstance(row['reason'],str)and 0<len(row['reason'])<=256 and row['reason'].isascii()
 assert integer(row['operation_index'])<=6 and row['step']in{'prepare','wan','query_intent','query_birth','query_reading','query_result','intent','birth','executing','result','complete'}
 observed=finite(row['observed_at']);assert observed<=finite(after)
 at,end=row['requested_at'],row['deadline']
 if at is None:assert end is None
 else:assert finite(at)<=observed and abs(finite(end)-at-2)<.00001
 queue=row['queue_state']
 if queue is not None:assert set(queue)=={'failed','pending','queued','continuation','result_issued'}and all(type(v)is bool for v in queue.values())
 jobs=row['job_counts']
 if jobs is not None:assert set(jobs)=={'total','matched'}and integer(jobs['matched'])<=integer(jobs['total'])
 child=row['child']
 if child is not None:
  assert set(child)=={'pid','start','actual_wait_status','born','birth','accepted_at'}and type(child['born'])is bool
  if child['pid']is None:assert all(child[k]is None for k in['start','actual_wait_status','birth','accepted_at'])
  else:assert integer(child['pid'],2)<=4294967295
  if child['start']is not None:integer(child['start'],1)
  if child['actual_wait_status']is not None:assert integer(child['actual_wait_status'])<=2147483647
  if child['birth']is not None:
   b=child['birth'];assert set(b)=={'pid','start','born_at','deadline'};assert integer(b['pid'],2)<=4294967295;integer(b['start'],1)
   assert b['pid']==child['pid']and b['start']==child['start']and child['born']is True
   assert at is not None and b['deadline']==end and at<=finite(b['born_at'])<finite(b['deadline'])and b['born_at']<=observed
  if child['accepted_at']is not None:
   assert child['birth']is not None and type(child['actual_wait_status'])is int and child['actual_wait_status']==0
   assert child['birth']['born_at']<=finite(child['accepted_at'])<end and child['accepted_at']<=observed
 return dict(active_clock_observed=at is not None,cached_child_observed=child is not None,fresh_reap_or_resource_authority=False)
def validate_progress(progress,member,owner,after,fixture=False):
 assert type(fixture)is bool
 assert set(progress)==({'schema','member','owner_epoch','writers','netfilter','pending_netfilter','canonical_pending','mutation_fenced'}|({'checkpoint_waiting'}if fixture else set()))
 if fixture:assert progress['checkpoint_waiting']is None or type(progress['checkpoint_waiting'])is bool
 assert type(progress['schema'])is int and progress['schema']==1 and progress['member']==member and progress['owner_epoch']==owner
 assert type(progress['canonical_pending'])is type(progress['mutation_fenced'])is bool
 assert isinstance(progress['netfilter'],list)and len(progress['netfilter'])<=6
 assert progress['pending_netfilter']is None or isinstance(progress['pending_netfilter'],list)and len(progress['pending_netfilter'])<=6
 writers=progress['writers'];assert isinstance(writers,list)and len(writers)<=80
 for w in writers:
  assert set(w)=={'phase','pid','start','queued_at','io_deadline','parent_deadline','actual_wait_status','verified_at'}
  assert isinstance(w['phase'],str)and 0<len(w['phase'])<=64 and w['phase'].isascii()
  if w['pid']is None:assert w['start']is None
  else:assert integer(w['pid'],2)<=4294967295;integer(w['start'],1)
  assert finite(w['queued_at'])<=after and w['queued_at']<finite(w['io_deadline'])==finite(w['parent_deadline'])
  if w['actual_wait_status']is not None:assert integer(w['actual_wait_status'])<=2147483647
  if w['verified_at']is not None:assert type(w['actual_wait_status'])is int and w['actual_wait_status']==0 and w['queued_at']<=finite(w['verified_at'])<w['parent_deadline']and w['verified_at']<=after
 return dict(cached_writers=len(writers),cached_netfilter_history=len(progress['netfilter']),fresh_collection_or_ack_claim=False)

def validate_fixture(row):
 if row is None:return
 assert set(row)=={'queued_polls','held_pending_polls','intent_released','original_writer'}
 assert integer(row['queued_polls'])<=1 and integer(row['held_pending_polls'])<=2 and type(row['intent_released'])is bool
 writer=row['original_writer']
 if writer is not None:
  assert set(writer)=={'index','pid','start'}and type(writer['index'])is int and writer['index']==42
  assert integer(writer['pid'],2)<=4294967295;integer(writer['start'],1)
 if row['held_pending_polls']>0:assert writer is not None and row['queued_polls']==1
 if row['intent_released']:assert row['held_pending_polls']==2 and writer is not None

def bind_fixture(failure,progress):
 row=failure['own_intent_fixture']
 if row is None or progress is None:return
 writer=row['original_writer']
 if writer is None:return
 assert len(progress['writers'])>writer['index']
 original=progress['writers'][writer['index']]
 assert original['phase']=='netfilter_intent'and original['pid']==writer['pid']and original['start']==writer['start']
 if failure['operation_index']==0 and failure['step']=='intent':
  assert original['parent_deadline']==failure['deadline']
