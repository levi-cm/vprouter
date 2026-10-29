"""Synthetic receipt binding checks; never runs native children or a VM."""
import copy,datetime,hashlib,importlib.util,json,pathlib
if not __debug__:raise RuntimeError('optimized_python_refused')
history_smoke=pathlib.Path(__file__).with_name('smoke-quarantine-history.py');setup={'__file__':str(history_smoke)}
exec(compile(history_smoke.read_text().split('\nrows=[]',1)[0],str(history_smoke),'exec'),setup)
schema_path=pathlib.Path(__file__).with_name('quarantine_native_schema.py');spec=importlib.util.spec_from_file_location('quarantine_native',schema_path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
def sample():
 c,p=setup['sample']();setup['module'].validate_initial_history(c,p)
 operations=[]
 for h in p['netfilter']:
  op={k:copy.deepcopy(h[k])for k in['kind','scope','request','requested_at','deadline','birth','result']}
  op.update(original_pid=h['birth']['pid'],original_start=h['birth']['start'],actual_wait_status=0,native_born=True,native_job_state='born',registered_native_slots=12,full_descriptor_registration=True,borrowed_registration_count=0 if h['kind']=='sockets'else 2,accepted_at=h['verified_at'],acknowledged=True,context_retained=True);operations.append(op)
 query=copy.deepcopy(p['quarantine_query']);query.update(actual_wait_status=0,original_peer_receipt=True,handler_identity_claimed=False,listener_origin_pid=1,listener_origin_uid=0,listener_origin_gid=0)
 c['host']['declaration']['wan']=dict(name='ens2',index=2,address=[82,84,0,18,52,86])
 h=p['netfilter'][1];wan=dict(declaration_digest=list(bytes.fromhex(c['host']['sha256'])),host_namespace=copy.deepcopy(c['host']['declaration']['host_namespace']),name='ens2',index=2,address=[82,84,0,18,52,86],requested_at=h['requested_at'],deadline=h['deadline'],verified_at=h['requested_at']+.02,original_observer_retained=True)
 return c,p,operations,query,wan
rows=[];proof=module.validate_initial_receipts(*sample());assert proof['original_netfilter_receipts']==6
rows.append(dict(case='six_original_receipts',result='PASS'))
mutations=[
 ('missing_operation',lambda c,p,o,q,w:o.pop()),
 ('request',lambda c,p,o,q,w:o[0].update(request=[1]*32)),
 ('scope',lambda c,p,o,q,w:o[0].update(scope='data')),
 ('status',lambda c,p,o,q,w:o[0].update(actual_wait_status=9)),
 ('status_bool',lambda c,p,o,q,w:o[0].update(actual_wait_status=False)),
 ('original_pid',lambda c,p,o,q,w:o[0].update(original_pid=o[0]['original_pid']+1)),
 ('original_start',lambda c,p,o,q,w:o[0].update(original_start=o[0]['original_start']+1)),
 ('registration',lambda c,p,o,q,w:o[0].update(full_descriptor_registration=False)),
 ('slots',lambda c,p,o,q,w:o[0].update(registered_native_slots=0)),
 ('borrowed_sockets',lambda c,p,o,q,w:o[1].update(borrowed_registration_count=0)),
 ('unexpected_borrow',lambda c,p,o,q,w:o[0].update(borrowed_registration_count=2)),
 ('result',lambda c,p,o,q,w:o[1]['result'].update(observed_at=None)),
 ('accepted_at',lambda c,p,o,q,w:o[0].update(accepted_at=o[0]['accepted_at']+.01)),
 ('unacknowledged',lambda c,p,o,q,w:o[0].update(acknowledged=False)),
 ('unretained',lambda c,p,o,q,w:o[0].update(context_retained=False)),
 ('query_status',lambda c,p,o,q,w:q.update(actual_wait_status=9)),
 ('query_purpose',lambda c,p,o,q,w:q.update(kind='MovementRecheck')),
 ('query_handler_claim',lambda c,p,o,q,w:q.update(handler_identity_claimed=True)),
 ('query_origin',lambda c,p,o,q,w:q.update(listener_origin_uid=1)),
 ('wan_digest',lambda c,p,o,q,w:w.update(declaration_digest=[7]*32)),
 ('wan_namespace',lambda c,p,o,q,w:w.update(host_namespace=dict(dev=4,ino=44))),
 ('wan_name',lambda c,p,o,q,w:w.update(name='other')),
 ('wan_index_bool',lambda c,p,o,q,w:w.update(index=True)),
 ('wan_address',lambda c,p,o,q,w:w.update(address=[1,2,3,4,5,6])),
 ('wan_clock',lambda c,p,o,q,w:w.update(deadline=w['deadline']+2)),
 ('wan_after_birth',lambda c,p,o,q,w:w.update(verified_at=p['netfilter'][1]['birth']['born_at']+.001)),
 ('wan_observer_missing',lambda c,p,o,q,w:w.update(original_observer_retained=False)),
]
for name,mutate in mutations:
 values=sample();mutate(*values)
 try:module.validate_initial_receipts(*values)
 except(AssertionError,ValueError,KeyError,TypeError):rows.append(dict(case=name,result='PASS_REFUSED'))
 else:raise AssertionError('invalid_initial_receipt_accepted:'+name)
dependencies=[pathlib.Path(__file__),schema_path,history_smoke,pathlib.Path(__file__).with_name('quarantine_history_schema.py')]
record=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),checks=rows,files=[dict(path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest())for p in dependencies],scope='LOCAL_SYNTHETIC_RECEIPT_SCHEMA_ONLY; no child, VM, frozen prefix, native WAN, actual nft table, producer, final Drop or release acceptance')
destination=pathlib.Path('target/lab-state')/('quarantine-native-schema-smokes-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.json')
with destination.open('x')as f:json.dump(record,f,indent=2);f.write('\n')
print(json.dumps(dict(record=str(destination),checks=len(rows),native_acceptance=False)))
