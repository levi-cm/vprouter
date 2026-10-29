"""Parse source-bound cached child diagnostics; never poll or grant authority."""
import re
if not __debug__:raise RuntimeError('optimized_python_refused')
LABELS=['not_entered','bind_original_networks','check_removal_binding','first_producer_fence','offline','verify_cooperation','host_observe_before','host_exact_before','namespace_audit','verify_offline','second_producer_fence','delete_wireguard','third_producer_fence','delete_host_link','verify_host_absent','verify_transport_absent','host_observe_after','host_exact_after','cleanup_permits','final_producer_fence']
PATTERN=re.compile(r'LAB_CLEANUP_CHILD_FAILURE producer=(true|false) pid=([1-9][0-9]*) start=(None|Some\(([1-9][0-9]*)\)) wait_status=(-?[0-9]+) diagnostic_bound=(true|false) phase=([0-9]+) reason_code=([0-9]+) subphase=([0-9]+)')
def parse(stderr,native,enabled):
 lines=[line for line in stderr.splitlines()if line.startswith('LAB_CLEANUP_CHILD_FAILURE ')]
 if not enabled:return dict(source_has_subphase=False,original_child_diagnostics=[])
 assert len(lines)<=1
 out=[]
 for line in lines:
  m=PATTERN.fullmatch(line);assert m is not None
  producer,pid,_,start,status,bound,phase,reason,subphase=m.groups();pid=int(pid);start=int(start)if start else None;status=int(status);phase=int(phase);reason=int(reason);subphase=int(subphase);bound=bound=='true'
  assert pid>1 and native is not None and pid==native['pid']and start==native['start']and status==native['actual_wait_status']and native['native_reaped']is True and status!=0
  assert 0<=phase<=255 and 0<=subphase<=19
  if bound:assert 1<=reason<=5
  else:assert phase==reason==subphase==0
  out.append(dict(pid=pid,start=start,actual_wait_status=status,producer_operation=producer=='true',diagnostic_bound=bound,phase=phase,reason_code=reason,subphase=subphase,subphase_operation=LABELS[subphase]if bound else None,original_cached_receipt_bound=True,fresh_reap_observed=False))
 return dict(source_has_subphase=True,original_child_diagnostics=out)
