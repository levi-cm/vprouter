"""Synthetic six-operation canonical history; no native receipts or WAN proof."""
import copy,datetime,hashlib,importlib.util,json,pathlib
if not __debug__:raise RuntimeError('optimized_python_refused')
old_smoke=pathlib.Path(__file__).with_name('smoke-movement-evidence.py');setup={'__file__':str(old_smoke)}
exec(compile(old_smoke.read_text().split('\nrows=[]',1)[0],str(old_smoke),'exec'),setup)
schema_path=pathlib.Path(__file__).with_name('quarantine_history_schema.py');spec=importlib.util.spec_from_file_location('quarantine_history',schema_path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
def sample():
 c=setup['sample'](0);w=c['movement_top'];w.update(whole_chain_retained_after_drop=False,movement_context_retained_after_drop=False,original_provision_context_retained_after_drop=False,continued_original_context=True)
 setup['movement'].validate_movement(c,continuation=True)
 p=copy.deepcopy(w['preparation']);p['netfilter']=[];p['quarantine_query']=None
 c['host']=dict(sha256='ab'*32,declaration=dict(host_namespace=dict(dev=4,ino=333333)))
 counter=[2000000]
 def pair():counter[0]+=1;return counter[0],counter[0]+1000000
 def birth(at,end):pid,start=pair();return dict(pid=pid,start=start,born_at=at,deadline=end)
 def writer(phase,at,end):pid,start=pair();return dict(phase=phase,pid=pid,start=start,queued_at=at,io_deadline=end,parent_deadline=end,actual_wait_status=0,verified_at=at+.005)
 at=w['final_process_verified_at']+.1
 for i,(scope,kind)in enumerate([('host','sockets'),('host','initial_quarantine'),('transport','sockets'),('transport','initial_quarantine'),('data','sockets'),('data','initial_quarantine')]):
  end=at+2;ns=c['host']['declaration']['host_namespace']if scope=='host'else p[scope+'_network'];policy=[90+i//2]*32
  h=dict(kind=kind,scope=scope,request=[150+i]*32,namespace=copy.deepcopy(ns),configuration=p['wireguard'][0]['configuration'],host_declaration=list(bytes.fromhex(c['host']['sha256'])),policy=policy,query=None,requested_at=at,deadline=end)
  if i==5:
   q=dict(kind='QuarantineRecheck',request=[170]*32,initial=None,requested_at=at,deadline=end,birth=birth(at+.02,end),facts=copy.deepcopy(p['movement_query']['facts']),verified_at=at+.04)
   p['quarantine_query']=q;h['query']=q['request']
   p['writers'].extend(writer(phase,at+offset,end)for phase,offset in[('quarantine_query_intent',.01),('quarantine_query_birth',.025),('quarantine_query_result',.045)])
   h.update(birth=birth(at+.07,end),verified_at=at+.1)
   offsets=[.06,.08,.11];observed=at+.09
  else:
   h.update(birth=birth(at+.03,end),verified_at=at+.05)
   offsets=[.01,.035,.06];observed=at+.045
  h['result']=dict(namespace=copy.deepcopy(ns),policy=copy.deepcopy(policy),observed_at=None if kind=='sockets'else observed)
  p['netfilter'].append(h);p['writers'].extend(writer(phase,at+offset,end)for phase,offset in zip(['netfilter_intent','netfilter_birth','netfilter_result'],offsets));at=p['writers'][-1]['verified_at']+.1
 c['environment']['after']['started_at']=at+1
 return c,p
rows=[];c,p=sample();proof=module.validate_initial_history(c,p)
assert proof['ordered_writer_prefix']==63 and proof['original_operation_clock_prefix']==16
rows.append(dict(case='six_operation_prefix',result='PASS'))
mutations=[
 ('changed_old_writer',lambda c,p:p['writers'][0].update(pid=77)),
 ('changed_old_history',lambda c,p:p['wireguard'][0].update(request=[77]*32)),
 ('scope',lambda c,p:p['netfilter'][0].update(scope='data')),
 ('kind',lambda c,p:p['netfilter'][0].update(kind='initial_quarantine')),
 ('host_namespace',lambda c,p:p['netfilter'][0].update(namespace=dict(dev=4,ino=44))),
 ('declaration_digest',lambda c,p:p['netfilter'][0].update(host_declaration=[11]*32)),
 ('configuration',lambda c,p:p['netfilter'][0].update(configuration=[11]*32)),
 ('duplicate_request',lambda c,p:p['netfilter'][1].update(request=p['netfilter'][0]['request'])),
 ('empty_policy',lambda c,p:p['netfilter'][0].update(policy=[0]*32)),
 ('policy_pair',lambda c,p:p['netfilter'][1].update(policy=[11]*32)),
 ('socket_observation',lambda c,p:p['netfilter'][0]['result'].update(observed_at=p['netfilter'][0]['verified_at'])),
 ('missing_observation',lambda c,p:p['netfilter'][1]['result'].update(observed_at=None)),
 ('observation_after_acceptance',lambda c,p:p['netfilter'][1]['result'].update(observed_at=p['netfilter'][1]['verified_at']+.001)),
 ('deadline',lambda c,p:p['netfilter'][1].update(deadline=p['netfilter'][1]['deadline']+2)),
 ('missing_query',lambda c,p:p['netfilter'][5].update(query=None)),
 ('query_purpose',lambda c,p:p['quarantine_query'].update(kind='MovementRecheck')),
 ('query_facts',lambda c,p:p['quarantine_query']['facts'].update(pid=99)),
 ('writer_phase',lambda c,p:p['writers'][42].update(phase='wireguard_intent')),
 ('writer_failure',lambda c,p:p['writers'][42].update(actual_wait_status=9)),
 ('nft_status_bool',lambda c,p:p['writers'][42].update(actual_wait_status=False)),
 ('query_status_bool',lambda c,p:p['writers'][57].update(actual_wait_status=False)),
 ('nft_prebirth_writer',lambda c,p:p['writers'][43].update(queued_at=p['netfilter'][0]['birth']['born_at']-.001)),
 ('query_prebirth_writer',lambda c,p:p['writers'][58].update(queued_at=p['quarantine_query']['birth']['born_at']-.001)),
 ('late_writer',lambda c,p:p['writers'][42].update(verified_at=p['writers'][42]['io_deadline'])),
 ('duplicate_writer',lambda c,p:p['writers'][43].update(pid=p['writers'][42]['pid'],start=p['writers'][42]['start'])),
 ('after_environment',lambda c,p:c['environment']['after'].update(started_at=p['writers'][62]['verified_at']-.001)),
]
for name,mutate in mutations:
 c,p=sample();mutate(c,p)
 try:module.validate_initial_history(c,p)
 except(AssertionError,ValueError,KeyError,TypeError):rows.append(dict(case=name,result='PASS_REFUSED'))
 else:raise AssertionError('invalid_initial_history_accepted:'+name)
dependencies=[pathlib.Path(__file__),schema_path,old_smoke,pathlib.Path(__file__).with_name('collect-secret-movement.py'),pathlib.Path(__file__).with_name('collect-secret-provision.py')]
record=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),checks=rows,files=[dict(path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest())for p in dependencies],scope='LOCAL_SYNTHETIC_CANONICAL_PREFIX_ONLY; no native, full frozen prefix, WAN, actual nft table, producer or Drop acceptance')
destination=pathlib.Path('target/lab-state')/('quarantine-history-smokes-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.json')
with destination.open('x')as f:json.dump(record,f,indent=2);f.write('\n')
print(json.dumps(dict(record=str(destination),checks=len(rows),native_acceptance=False)))
