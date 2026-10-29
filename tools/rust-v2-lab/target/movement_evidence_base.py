"""Strict movement provenance and preserved attachment-prefix validation.
No writes, VM access, or standalone acceptance. Full provision validation is required.
"""
import hashlib,json,math,pathlib,re,tarfile
if not __debug__:raise RuntimeError('optimized_python_refused')
def validate_prefix(candidate_path,directory_label):
 candidate_path=pathlib.Path(candidate_path);candidate=json.loads(candidate_path.read_text());directory=candidate_path.parent/directory_label
 binding=json.loads((directory/'directory-binding.json').read_text());controller=json.loads((directory/'controller.json').read_text());path=pathlib.Path(controller['record']);raw=path.read_bytes();record=json.loads(raw)
 assert record['exit_code']==controller['exit_code']==0 and record['source_binding']==candidate['binding'] and record['platform']==binding['platform']and binding['record']==str(path)
 assert binding['source_commit']==candidate['source_commit']and binding['source_archive_sha256']==candidate['source_sha256']==record['source_archive_sha256']and binding['new_directories']==[]
 for key,name in [('runner_sha256','controller-runner.py'),('guest_sha256','controller-guest.py'),('context_checker_sha256','controller-context.py')]:assert hashlib.sha256((directory/name).read_bytes()).hexdigest()==record[key]
 arch={'debian-clean-x86_64':'amd64','debian-x86_64':'amd64','arch-x86_64':'amd64','debian-arm64':'arm64'}[record['platform']];assert record['artifact_sha256']==binding['artifact_sha256']==candidate['platforms'][arch]['artifact_sha256']and record['context_sha256']==candidate['platforms'][arch]['context_sha256']
 assert record['real_client_acceptance']=='NOT_RUN'and record['production_changes'] is record['provider_profiles_used'] is False and record['namespace_or_container_fixture']is record['actual_gateway_is_inert']is True
 modes={'secret_movement_success':(0,'actual_secret_free_parent_original_down_wireguard_move_to_data'),'secret_movement_postbirth_failure':(1,'actual_wireguard_move_postbirth_failure_retains_both_namespaces'),'secret_movement_result_failure':(2,'actual_wireguard_move_result_writer_failure_retains_original_networks'),'secret_movement_registration_failure':(3,'actual_wireguard_move_registration_failure_retains_prepared_context')}
 fault,label=modes[record['component_test_mode']];source=pathlib.Path(candidate['source']);assert hashlib.sha256(source.read_bytes()).hexdigest()==candidate['source_sha256']
 with tarfile.open(source)as archive:
  postcompletion_inventory_expected=b'postcompletion_inventory_polls'in archive.extractfile('crates/vprouter-launch/src/kernel/wireguard_role.rs').read()
  code=archive.extractfile('crates/vprouter-launch/src/attachment/mount.rs').read();provision_code=archive.extractfile('crates/vprouter-launch/src/attachment/movement.rs').read();assert provision_code.count(label.encode())==1
  flag='--ignored-secret-movement'+(''if fault==0 else '-'+record['component_test_mode'].removeprefix('secret_movement_').replace('_','-'));assert ('"'+flag+'"').encode()in archive.extractfile('crates/vprouter-launch/src/actual_lab_main.rs').read()
  program_bytes=archive.extractfile('docs/rust-v2/programs-'+arch+'.json').read();program=json.loads(program_bytes);init=[p for p in program['programs']if p['role']=='gateway_init'];assert len(init)==1
 values={k:[]for k in ['input','gateway','descriptor','controller','admission','owner']};events=[];environments=[]
 for line in record['stdout'].splitlines():
  if line.startswith('LAB_SECRET_MOVEMENT '):events.append(dict(event='secret_movement',value=json.loads(line.split(' ',1)[1])));continue
  try:value=json.loads(line)
  except ValueError:continue
  if 'case'in value:events.append(value)
  if 'secret_attachment_environment'in value:environments.append(value['secret_attachment_environment'])
  for key in values:
   field='owner_probe'if key=='owner'else'secret_attachment_'+key
   if field in value:values[key].append(value[field])
 assert events==controller['runtime_events']and len(events)==2 and events[0]==dict(case=label,result='PASS')and events[1]['event']=='secret_movement'
 assert all(len(values[k])==1 for k in values if k!='admission')and len(values['admission'])==2
 manifest,gateway,descriptor,end,owner=(values[k][0]for k in ['input','gateway','descriptor','controller','owner'])
 nonce=manifest['nonce'];assert re.fullmatch('[a-f0-9]{64}',nonce)and nonce==descriptor['nonce']==owner['nonce']
 assert manifest['schema']==1 and manifest['synthetic_only']is manifest['keys_created_outside_rust_parent']is True
 assert manifest['private_bytes_in_argv_environment_or_configuration']is manifest['duplicate_private_input']is manifest['canonical_root_precreated']is False
 assert manifest['state_root']=='/var/lib/vprouter-v2-lab/secret-gateway-state-'+nonce
 profiles=manifest['profiles'];assert len(profiles)==2 and {p['member']for p in profiles}=={'a'+nonce[:12],'b'+nonce[:12]}
 for p in profiles:
  assert p['member']in['a'+nonce[:12],'b'+nonce[:12]]and p['path']=='/var/lib/vprouter-v2-lab/secret-inputs-'+nonce+'/'+p['member']+'/de-fra-wg-404.conf'
  assert p['uid']==p['gid']==0 and p['mode']==0o600 and p['inode']>0 and 0<p['size']<=65536
 assert descriptor['schema_version']==1 and descriptor['owner_unit']==owner['unit']and descriptor['primary']=='a'+nonce[:12]and descriptor['deployment_id']=='secretlab-'+nonce[:12]
 assert descriptor['profile_contents_read']is descriptor['docker_queried']is descriptor['container_mounts_allowed']is descriptor['production_startup_authorized']is False
 assert gateway['inert']is True and gateway['mounts']==[]and gateway['provider_state_mounted']is False
 assert gateway['program_manifest_sha256']==descriptor['program_manifest_sha256']==hashlib.sha256(program_bytes).hexdigest()
 assert gateway['init_sha256']==descriptor['artifact_sha256']==init[0]['sha256']and descriptor['artifact_size']==init[0]['bytes']
 assert descriptor['image_ref']=='vprouter-v2-lab@'+gateway['image_id']and re.fullmatch('sha256:[a-f0-9]{64}',gateway['image_id'])and re.fullmatch('[a-f0-9]{64}',gateway['container_id'])
 assert gateway['source_namespace']!=gateway['host_network_namespace']
 assert end['harness_exit_code']==0 and all(end[k]is True for k in ['owner_unit_absent','host_links_and_stable_routes_unchanged','inert_gateway_retained','original_gateway_native_identity_unchanged','synthetic_only','canonical_and_mount_resources_retained'])and end['native_transport_operations_requested']is True and 'transport_or_route_creation'not in end
 for a in values['admission']:
  assert a['device']>0 and a['inode']>0
  if a['path'].endswith('/task8b2-image'):assert a['content']==dict(schema=1,image_id=gateway['image_id'],program_manifest_sha256=gateway['program_manifest_sha256'])
  else:assert a['path']=='/var/lib/vprouter-v2-lab/task8b2-host-acceptance'and a['content']['artifact_sha256']==record['artifact_sha256']and[a['content']['network_dev'],a['content']['network_ino']]==gateway['host_network_namespace']
 
 def integer(v,minimum=0):assert type(v)is int and v>=minimum;return v
 def finite(v):assert type(v)in(int,float)and math.isfinite(v)and v>0;return v
 def identity(v):assert set(v)=={'dev','ino'};integer(v['dev'],1);integer(v['ino'],1);return[v['dev'],v['ino']]
 def original_clock(requested,deadline):finite(requested);finite(deadline);assert abs(deadline-requested-2)<0.00001
 environment=None
 if b'def observation_context()'in(directory/'controller-guest.py').read_bytes():
  assert len(environments)==1
  environment=environments[0];assert environment['schema']==1 and environment['sampled_during_native_operation']is False and environment['whole_vm_only']is True
  for sample in[environment['before'],environment['after']]:
   assert finite(sample['started_at'])<=finite(sample['finished_at'])and sample['scope']=='whole_vm_context_only'and sample['operation_cost_attribution']is False
   assert sample['machine']==('aarch64'if arch=='arm64'else'x86_64')
   integer(sample['logical_cpus'],1);assert isinstance(sample['affinity'],list)and sample['affinity']==sorted(set(sample['affinity']))and 0<len(sample['affinity'])<=sample['logical_cpus']
   for cpu in sample['affinity']:integer(cpu)
   assert set(sample['files'])=={'boot','cpu','cpu_pressure','io_pressure','memory_pressure','root_cpu_max','root_cpu_stat'}
   for value in sample['files'].values():
    if value['status']=='bounded':assert set(value)=={'status','text'}and isinstance(value['text'],str)and len(value['text'])<=4096
    elif value['status']=='too_large':assert set(value)=={'status','text'}and value['text']is None
    else:assert value['status']=='unavailable'and set(value)=={'status','errno'}and integer(value['errno'],1)
  before,after=environment['before'],environment['after'];assert before['finished_at']<=after['started_at']
  assert before['files']['boot']==after['files']['boot']and before['files']['boot']['status']=='bounded'and re.fullmatch('[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\n?',before['files']['boot']['text'])
 else:assert environments==[]
 ids=[]
 def birth(v,requested,deadline):
  pair=(integer(v['pid'],2),integer(v['start'],1));assert pair not in ids;ids.append(pair);assert requested<=finite(v['born_at'])<deadline and v['deadline']==deadline
 movement_top=events[1]['value'];movement_fault=fault;assert movement_top['schema']==1 and movement_top['fault']==movement_fault
 top=movement_top['provision'];provision_fault=0;assert top['schema']==1 and top['fault']==0
 w=top['attachment'];fault=0;assert w['schema']==1 and w['fault']==fault and w['parent_pristine']is w['same_service_retained']is True
 assert w['held_real_writer']is w['whole_failed_driver_retained_after_drop']is(fault!=0)and w['original_mount_retained']is(fault!=1)and w['base_published']is(fault==0)
 assert w['namespace_cleanup_or_operational_reuse_authorized']is w['requirement8_complete']is False
 p=w['preparation'];assert p['member']==descriptor['primary']and p['owner_host_anchor_present']is p['canonical_result_present']is p['service_reserved']is p['native_children_reaped']is True
 assert p['base_network_absent']is p['canonical_pending']is p['mutation_fenced']is(fault!=0)and p['transport_network']is None
 owner_epoch=p['canonical_owner_epoch'];assert owner_epoch['unit']==owner['unit']and re.fullmatch('vprouter-v2-owner@[a-f0-9]{64}[.]service',owner['unit']);integer(owner_epoch['pid'],2);integer(owner_epoch['start'],1);identity(owner_epoch['cgroup']);assert re.fullmatch('[a-f0-9-]{36}',owner_epoch['boot'])and re.fullmatch('[a-f0-9]{32}',owner_epoch['invocation'])
 original_clock(p['requested_at'],p['deadline']);birth(w['validator']['birth'],p['requested_at'],p['deadline']);assert w['validator']['birth']==p['birth']and w['validator']['actual_wait_status']==0
 original_clock(w['inspection_requested_at'],w['inspection_deadline']);assert p['requested_at']<w['inspection_requested_at']<=finite(w['inspection_verified_at'])<w['inspection_deadline']
 mount=w['mount'];original_clock(mount['requested_at'],mount['deadline']);assert w['inspection_verified_at']<=mount['requested_at']<w['inspection_deadline'];birth(mount['birth'],mount['requested_at'],mount['deadline'])
 assert mount['actual_wait_status']==(9 if fault==1 else 0)and mount['original_placeholder_retained']is True and mount['original_mounted_namespace_retained']is(fault!=1)
 assert mount['released_gates']==(1 if fault==1 else 2)and mount['received_packets']==(1 if fault==1 else 2)
 assert identity(mount['original_source'])==gateway['source_namespace'];identity(mount['original_directory']);placeholder=mount['placeholder'];identity(placeholder['identity']);assert placeholder['identity']['dev']==mount['original_directory']['dev']and placeholder['mode']==0o100600
 attachment=p['attachment'];assert attachment['birth']==mount['birth']and attachment['source']==mount['original_source']and attachment['directory']==mount['original_directory']and attachment['requested_at']==mount['requested_at']and attachment['deadline']==mount['deadline']
 origin=attachment['origin'];assert origin['kind']=='existing_admitted'and origin['container']==gateway['container_id']and origin['process_start']==gateway['start']and origin['network']==mount['original_source']
 for q,kind,requested,deadline in[(w['first_query'],'Initial',w['inspection_requested_at'],w['inspection_deadline']),(w['second_query'],'Recheck',w['inspection_requested_at'],w['inspection_deadline'])]+([]if fault==1 else[(w['postmount_query'],'AttachmentRecheck',mount['requested_at'],mount['deadline'])]):
  assert q['kind']==kind and q['requested_at']==requested and q['deadline']==deadline and q['actual_wait_status']==0 and q['original_peer_receipt']is True
  integer(q['listener_origin_pid'],1);assert q['listener_origin_uid']==q['listener_origin_gid']==0 and q['handler_identity_claimed']is False
  birth(q['birth'],requested,deadline);assert q['birth']['born_at']<=finite(q['verified_at'])<deadline and q['facts']['pid']==gateway['pid']and q['facts']['security']in('BuiltinSeccomp','AppArmorBuiltinSeccomp')
 canonical=p['inspection'];assert canonical['kind']=='Recheck'and canonical['requested_at']==w['inspection_requested_at']and canonical['deadline']==w['inspection_deadline']
 assert canonical['initial']['birth']==w['first_query']['birth']and canonical['initial']['facts']==w['first_query']['facts']and canonical['initial']['verified_at']==w['first_query']['verified_at']
 assert canonical['birth']==w['second_query']['birth']and canonical['facts']==w['second_query']['facts']and canonical['verified_at']==w['second_query']['verified_at']
 for digest in(canonical['request'],canonical['initial']['request']):assert len(digest)==32 and any(digest)and all(type(v)is int and 0<=v<=255 for v in digest)
 assert canonical['request']!=canonical['initial']['request']
 if fault==1:assert attachment['query']is None
 else:
  canonical_query=attachment['query'];q=w['postmount_query'];digest=canonical_query['request'];assert len(digest)==32 and any(digest)and all(type(v)is int and 0<=v<=255 for v in digest)
  assert canonical_query['kind']=='AttachmentRecheck'and canonical_query['initial']is None and all(canonical_query[k]==q[k]for k in ['requested_at','deadline','birth','facts','verified_at'])
 assert w['first_query']['facts']==w['second_query']['facts']and w['first_query']['verified_at']<=w['second_query']['birth']['born_at']and w['second_query']['verified_at']<=w['inspection_verified_at']
 if fault==1:
  assert w['postmount_query']is None and attachment['placeholder']is attachment['mounted_at']is attachment['published_at']is None
 else:
  assert mount['eof']is True and attachment['placeholder']==placeholder and mount['birth']['born_at']<=finite(attachment['mounted_at'])<mount['deadline']
  assert w['postmount_query']['facts']==w['second_query']['facts']and attachment['mounted_at']<=w['postmount_query']['birth']['born_at']
 if fault==0:
  assert p['base_network']==p['data_network']==mount['original_source']and w['postmount_query']['verified_at']<=finite(attachment['published_at'])<mount['deadline']
 else:assert p['base_network']is p['data_network']is attachment['published_at']is None
 phases=['intent','birth','result']+['inspection_intent','inspection_birth','inspection_result']*2+['attachment_intent','attachment_birth','attachment_placeholder']+([]if fault==1 else['attachment_mounted','attachment_query_intent','attachment_query_birth','attachment_query_result','attachment_primary'])
 assert[writer['phase']for writer in p['writers']]==phases
 for index,writer in enumerate(p['writers']):
  requested,deadline=(p['requested_at'],p['deadline'])if index<3 else(w['inspection_requested_at'],w['inspection_deadline'])if index<9 else(mount['requested_at'],mount['deadline'])
  pair=(integer(writer['pid'],2),integer(writer['start'],1));assert pair not in ids;ids.append(pair)
  assert requested<=finite(writer['queued_at'])<deadline and writer['io_deadline']==writer['parent_deadline']==deadline
  failed=fault!=0 and index==len(phases)-1;assert writer['actual_wait_status']==(9 if failed else 0)
  if failed:assert writer['verified_at']is None
  else:assert writer['queued_at']<=finite(writer['verified_at'])<deadline
 writers=p['writers']
 if environment is not None:
  assert environment['before']['files']['boot']['text'].strip()==p['canonical_owner_epoch']['boot']
  assert environment['before']['finished_at']<=p['requested_at']
  assert all(writer['verified_at']is None or writer['verified_at']<=environment['after']['started_at']for writer in writers)
 # New frozen fixtures force a ready ordinary ACK at a non-target phase.
 # Older retained checkpoints retain their original witness schema.
 if b'normal_ack_writer' in code:
  if fault==0:
   assert w['normal_ack_ready_preserved']is False and w['tested_non_target_phase']is w['normal_ack_writer']is None
  else:
   assert w['normal_ack_ready_preserved']is True
   expected='attachment_birth'if fault==1 else'attachment_placeholder'
   assert w['tested_non_target_phase']==expected
   original=w['normal_ack_writer'];assert set(original)=={'index','pid','start'}
   index=integer(original['index']);assert index<len(writers)-1
   writer=writers[index];assert writer['phase']==expected and writer['pid']==original['pid']and writer['start']==original['start']
   assert writer['actual_wait_status']==0 and writer['verified_at']is not None and writer['verified_at']<mount['deadline']
 assert writers[0]['verified_at']<=w['validator']['birth']['born_at']and writers[1]['verified_at']<=writers[2]['queued_at']and writers[2]['verified_at']<=w['inspection_requested_at']
 assert writers[8]['verified_at']<=w['inspection_verified_at']
 for q,offset in[(w['first_query'],3),(w['second_query'],6)]+([]if fault==1 else[(w['postmount_query'],13)]):
  assert writers[offset]['verified_at']<=q['birth']['born_at']and writers[offset+1]['verified_at']<=q['verified_at']<=writers[offset+2]['queued_at']
 assert writers[5]['verified_at']<=w['second_query']['birth']['born_at']and writers[9]['verified_at']<=mount['birth']['born_at']
 if fault!=1:assert attachment['mounted_at']<=writers[12]['queued_at']and writers[12]['verified_at']<=w['postmount_query']['birth']['born_at']
 assert owner['mode']=='secret-movement-'+record['component_test_mode'].removeprefix('secret_movement_').replace('_','-')
 return locals()
