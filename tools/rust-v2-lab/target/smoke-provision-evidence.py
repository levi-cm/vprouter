"""Synthetic schema mutation checks; neither native nor frozen-prefix acceptance."""
import base64,copy,datetime,hashlib,importlib.util,json,math,pathlib
if not __debug__:raise RuntimeError('optimized_python_refused')
module_path=pathlib.Path(__file__).with_name('collect-secret-provision.py')
spec=importlib.util.spec_from_file_location('provision_collector',module_path);collector=importlib.util.module_from_spec(spec);spec.loader.exec_module(collector)
retained=pathlib.Path('target/lab-state/secret-attachment-run-256.json');old=json.loads(retained.read_text())
raw=json.loads(pathlib.Path(old['record']).read_text());descriptor=[json.loads(line)['secret_attachment_descriptor']for line in raw['stdout'].splitlines()if line.startswith('{')and 'secret_attachment_descriptor'in json.loads(line)][0]

def sample(fault):
 attachment=copy.deepcopy(old['witness']);prior=attachment['preparation'];p=copy.deepcopy(prior);q=p['writers'][-1]['verified_at']+.1
 source={'dev':4,'ino':900000001};directory={'dev':34,'ino':900000002};name=[e for e in descriptor['allocation']['exits']if e['exit_id']==descriptor['primary']][0]['transport_namespace'];wgname=[e for e in descriptor['allocation']['exits']if e['exit_id']==descriptor['primary']][0]['wireguard_interface']
 serial=[900000]
 def child(at):serial[0]+=1;return dict(pid=serial[0],start=serial[0]+1000000,born_at=at+.02,deadline=at+2)
 def writes(phases,at):
  out=[]
  for i,phase in enumerate(phases):
   serial[0]+=1;queued=at+.01+.02*i;out.append(dict(phase=phase,pid=serial[0],start=serial[0]+1000000,queued_at=queued,io_deadline=at+2,parent_deadline=at+2,actual_wait_status=0,verified_at=queued+.005))
  return out
 creation=dict(birth=child(q),actual_wait_status=0,requested_at=q,deadline=q+2,verified_at=q+.04,request=[1]*32,source=source,host=old['gateway']['host_network_namespace'],data=old['gateway']['source_namespace'],eof=True,original_source_retained=True,durable_birth_released=True)
 # Native identities serialize as dev/ino maps, unlike external gateway pairs.
 for k in ('host','data'):creation[k]=dict(zip(('dev','ino'),creation[k]))
 at=q+.2;placeholder=dict(identity=dict(dev=directory['dev'],ino=900000003),mode=0o100600)
 mount=dict(birth=child(at),actual_wait_status=0,requested_at=at,deadline=at+2,original_source=source,original_directory=directory,placeholder=placeholder,original_placeholder_retained=True,original_mounted_namespace_retained=True,released_gates=2,received_packets=2,eof=True)
 mounted=dict(request=[2]*32,source=source,directory=directory,name=name,requested_at=at,deadline=at+2,birth=mount['birth'],placeholder=placeholder,mounted_at=at+.06,published_at=at+.065)
 history={k:copy.deepcopy(creation[k])for k in ('request','host','data','source','requested_at','deadline','birth','verified_at')};history.update(directory=directory,name=name,mount=mounted)
 p.update(transport_network=source,fresh_transport=history,wireguard=[],canonical_pending=fault==2,mutation_fenced=fault==2,native_children_reaped=True,member_native_jobs_collected=False)
 p['writers']+=writes(['transport_intent','transport_birth','transport_source'],q)+writes(['transport_mount_intent','transport_mount_birth','transport_mount_placeholder','transport_mount_publication'],at)
 operations=[];public=[7]*32;wg=dict(index=25,name=wgname,public_key=public,peers=[dict(public_key=list(base64.b64decode('zo060cy2M+x7cMF4FKXHbs0CloUFDTRHRboFhw5YfVk=')),endpoint='185.66.0.1:51820',allowed_ips=[['0.0.0.0',0]],handshake_unix=0.)]);result=dict(namespace=source,link=dict(name=wgname,index=25,kind='wireguard',up=False),wireguard=wg)
 for i in range({0:3,1:1,2:2,3:1}[fault]):
  at=q+.4+.2*i;b=child(at);h=dict(kind=['sockets','provision','query'][i],request=[10+i]*32,configuration=[9]*32,namespace=source,requested_at=at,deadline=at+2,birth=b,result=copy.deepcopy(dict(namespace=source,link=None,wireguard=None)if i==0 else result),verified_at=at+.04)
  if fault in (1,3):h.update(birth=None,result=None,verified_at=None)
  else:
   op=dict(kind=h['kind'],request=h['request'],requested_at=at,deadline=at+2,birth=b,original_pid=b['pid'],original_start=b['start'],actual_wait_status=0,native_born=True,native_job_state='born',full_descriptor_registration=True,registered_native_slots=3,borrowed_registration_count=0 if i==0 else 2,accepted_at=h['verified_at'],acknowledged=not(fault==2 and i==1),result=copy.deepcopy(h['result']),context_retained=True);operations.append(op)
  if fault==2 and i==1:h.update(result=None,verified_at=None)
  p['wireguard'].append(h);p['writers']+=writes(['wireguard_intent']if fault in (1,3)else['wireguard_intent','wireguard_birth','wireguard_result'],at)
 if fault==2:p['writers'][-1].update(actual_wait_status=9,verified_at=None)
 failed=None
 if fault in (1,3):
  h=p['wireguard'][0];failed=dict(kind='sockets',request=h['request'],requested_at=h['requested_at'],deadline=h['deadline'],birth=None,original_pid=990000 if fault==1 else None,original_start=None,actual_wait_status=9 if fault==1 else None,native_born=fault==1,native_job_state='born'if fault==1 else'prepared',full_descriptor_registration=True,registered_native_slots=3,borrowed_registration_count=0,accepted_at=None,acknowledged=False,result=None,context_retained=True)
 p['pending_wireguard']=copy.deepcopy(p['wireguard'])if fault==2 else None
 if fault==2:p['pending_wireguard'][1].update(result=copy.deepcopy(operations[1]['result']),verified_at=operations[1]['accepted_at'])
 top=dict(unacknowledged_native_result_retained=fault==2,schema=1,fault=fault,attachment=attachment,preparation=p,transport_creation=creation,transport_mount=mount,operations=operations,failed_constructor=failed,held_real_result_writer=fault==2,parent_pristine=True,same_service_retained=True,whole_context_retained_after_drop=True,transport_distinct_from_host_and_data=True,original_socket_registrations_borrowed=True,wireguard_down_only=fault in (0,2),host_resources_created=False,operational_reuse_authorized=False,requirement8_complete=False)
 ids=[(v['pid'],v['start'])for v in prior['writers']]+[(v['birth']['pid'],v['birth']['start'])for v in [attachment['validator'],attachment['mount'],attachment['first_query'],attachment['second_query'],attachment['postmount_query']]]
 def integer(v,minimum=0):assert type(v)is int and v>=minimum;return v
 def finite(v):assert type(v)in(int,float)and math.isfinite(v)and v>0;return v
 def identity(v):assert set(v)=={'dev','ino'};integer(v['dev'],1);integer(v['ino'],1);return[v['dev'],v['ino']]
 def clock(at,end):finite(at);finite(end);assert abs(end-at-2)<.00001
 def birth(v,at,end):
  pair=(integer(v['pid'],2),integer(v['start'],1));assert pair not in ids;ids.append(pair);assert at<=finite(v['born_at'])<end and v['deadline']==end
 return dict(top=top,provision_fault=fault,p=prior,w=attachment,integer=integer,finite=finite,identity=identity,original_clock=clock,birth=birth,ids=ids,gateway=old['gateway'],descriptor=descriptor,profiles=[dict(member=descriptor['primary'],device_public_key=public)],environment=dict(after=dict(started_at=q+5)))

rows=[]
for fault in range(4):collector.validate_pipeline(sample(fault));rows.append(dict(case='synthetic_valid_fault_'+str(fault),result='PASS'))
mutations=[
 ('empty_registered_slots',0,lambda c:c['top']['operations'][0].update(registered_native_slots=0)),
 ('wrong_pending_proposal',2,lambda c:c['top']['preparation']['pending_wireguard'][1].update(request=[99]*32)),
 ('wrong_pending_accepted_time',2,lambda c:c['top']['preparation']['pending_wireguard'][1].update(verified_at=1.)),
 ('original_writer_changed',0,lambda c:c['top']['preparation']['writers'][0].update(pid=999999)),
 ('owner_epoch_changed',0,lambda c:c['top']['preparation']['canonical_owner_epoch'].update(pid=999999)),
 ('wrong_transport_namespace',0,lambda c:c['top']['preparation'].update(transport_network=dict(dev=4,ino=19))),
 ('rearmed_operation_clock',0,lambda c:c['top']['operations'][1].update(deadline=c['top']['operations'][1]['deadline']+2)),
 ('borrowed_registration_lost',0,lambda c:c['top']['operations'][1].update(borrowed_registration_count=0)),
 ('wrong_device_key',0,lambda c:c['top']['operations'][1]['result']['wireguard'].update(public_key=[8]*32)),
 ('unexpected_up',0,lambda c:c['top']['operations'][1]['result']['link'].update(up=True)),
 ('unexpected_handshake',0,lambda c:c['top']['operations'][1]['result']['wireguard']['peers'][0].update(handshake_unix=1.)),
 ('unacknowledged_committed_result',2,lambda c:c['top']['preparation']['wireguard'][1].update(result=copy.deepcopy(c['top']['operations'][1]['result']))),
 ('unacknowledged_claimed_ack',2,lambda c:c['top']['operations'][1].update(acknowledged=True)),
 ('postbirth_without_actual_reap',1,lambda c:c['top']['failed_constructor'].update(actual_wait_status=None)),
 ('prebirth_claimed_native_child',3,lambda c:c['top']['failed_constructor'].update(native_born=True)),
 ('prebirth_missing_registration',3,lambda c:c['top']['failed_constructor'].update(full_descriptor_registration=False)),
 ('duplicate_writer_identity',0,lambda c:c['top']['preparation']['writers'][18].update(pid=c['top']['preparation']['writers'][17]['pid'],start=c['top']['preparation']['writers'][17]['start'])),
 ('late_ack',0,lambda c:c['top']['preparation']['writers'][19].update(verified_at=c['top']['transport_creation']['deadline'])),
]
for name,fault,mutate in mutations:
 c=sample(fault);mutate(c)
 try:collector.validate_pipeline(c)
 except (AssertionError,ValueError,KeyError,TypeError):rows.append(dict(case=name,result='PASS_REFUSED'))
 else:raise AssertionError('corruption_accepted:'+name)
# Explicit continuation preserves live custody without claiming a prior Drop.
continued=sample(0);continued['top'].update(whole_context_retained_after_drop=False,continued_original_context=True)
proof=collector.validate_pipeline(continued,continuation=True);assert proof['original_context_continued']is True and proof['whole_context_drop_verified']is False
rows.append(dict(case='explicit_live_continuation',result='PASS'))
for name,fault,optin,drop,live in [('continuation_without_optin',0,False,False,True),('standalone_mislabeled_continuation',0,True,True,False),('failed_operation_cannot_continue',2,True,False,True),('continued_context_cannot_claim_drop',0,False,True,True)]:
 c=sample(fault);c['top'].update(whole_context_retained_after_drop=drop,continued_original_context=live)
 try:collector.validate_pipeline(c,continuation=optin)
 except AssertionError:rows.append(dict(case=name,result='PASS_REFUSED'))
 else:raise AssertionError('bad_continuation_accepted:'+name)
out=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_public_fixture=str(retained),source_public_fixture_sha256=hashlib.sha256(retained.read_bytes()).hexdigest(),collector_sha256=hashlib.sha256(module_path.read_bytes()).hexdigest(),smoke_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),checks=rows,scope='LOCAL_SYNTHETIC_SCHEMA_ONLY; no frozen prefix, new native operation, VM or acceptance proof')
destination=pathlib.Path('target/lab-state')/('provision-schema-smokes-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.json')
with destination.open('x')as stream:json.dump(out,stream,indent=2);stream.write('\n')
print(json.dumps(dict(record=str(destination),checks=len(rows),native_acceptance=False)))
