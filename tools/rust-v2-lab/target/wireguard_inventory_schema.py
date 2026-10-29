"""Frozen-feature-gated original post-completion inventory evidence."""
if not __debug__:raise RuntimeError('optimized_python_refused')
def validate_postcompletion_inventory(op,expected):
 assert type(expected)is bool
 if not expected:return
 polls=op['postcompletion_inventory_polls'];preserved=op['postcompletion_inventory_preserved']
 assert type(polls)is int and 0<=polls<=4294967295 and type(preserved)is bool
 accepted=op.get('accepted_at')is not None
 if accepted:assert type(op['actual_wait_status'])is int and op['actual_wait_status']==0
 if accepted and op['kind']in('provision','query','move'):assert polls>=2 and preserved is True
 else:assert polls==0 and preserved is False
