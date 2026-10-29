"""Strict quarantine provenance and preserved attachment-prefix validation.
No writes, VM access, or standalone acceptance. Full live42 movement validation and new quarantine validation are required.
"""
import hashlib,json,math,pathlib,re,tarfile
if not __debug__:raise RuntimeError('optimized_python_refused')

def validate_public_host(host,descriptor,gateway,platform,builder_sha256):
 """Public binding only. This never performs native WAN validation."""
 assert set(host)=={'declaration','sha256','bytes','builder_sha256','authored_public_input_only','native_validation_performed_by_controller','host_authority_granted'}
 assert host['authored_public_input_only']is True and host['native_validation_performed_by_controller']is host['host_authority_granted']is False
 assert isinstance(builder_sha256,str)and re.fullmatch('[a-f0-9]{64}',builder_sha256)and host['builder_sha256']==builder_sha256
 descriptor_digest=descriptor['allocation_digest'];assert isinstance(descriptor_digest,str)and re.fullmatch('[a-f0-9]{64}',descriptor_digest)
 v=host['declaration'];assert set(v)=={'schema_version','deployment_id','generation','member','allocation_digest','host_namespace','wan'}
 assert type(v['schema_version'])is int and v['schema_version']==1
 assert type(v['generation'])is int and 0<v['generation']<=18446744073709551615 and v['generation']==descriptor['allocation']['generation']
 assert isinstance(v['deployment_id'],str)and v['deployment_id']==descriptor['deployment_id']==descriptor['allocation']['deployment_id']
 assert isinstance(v['member'],str)and v['member']==descriptor['primary']and len([e for e in descriptor['allocation']['exits']if e['exit_id']==v['member']])==1
 assert v['allocation_digest']==descriptor_digest
 ns=v['host_namespace'];assert set(ns)=={'dev','ino'}and all(type(x)is int and 0<x<=18446744073709551615 for x in ns.values())and[ns['dev'],ns['ino']]==gateway['host_network_namespace']
 wan=v['wan'];assert set(wan)=={'name','index','address'}
 assert wan['name']=={'debian-clean-x86_64':'ens2','debian-x86_64':'ens2','debian-arm64':'enp0s1','arch-x86_64':'eth0'}[platform]
 assert type(wan['index'])is int and wan['index']==2 and isinstance(wan['address'],list)and len(wan['address'])==6 and all(type(x)is int and 0<=x<=255 for x in wan['address'])and wan['address']==[82,84,0,18,52,86]
 data=json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
 assert 0<len(data)<=4096 and type(host['bytes'])is int and host['bytes']==len(data)and host['sha256']==hashlib.sha256(data).hexdigest()
 return dict(public_declaration_bound=True,native_wan_validation_by_controller=False,host_authority_granted=False)

def validate_assembly_prefix(top,expected_fault):
 assert type(expected_fault)is int and expected_fault in(0,1,2,3)
 assert type(top['schema'])is int and top['schema']==1 and type(top['fault'])is int and top['fault']==expected_fault
 nested=top['quarantine'];assert type(nested['schema'])is int and nested['schema']==1 and type(nested['fault'])is int and nested['fault']==0
 return nested

def validate_baseline_host(meta,descriptor,gateway,candidate,record,directory):
 """Bind authored input provenance only; native admission remains outer proof."""
 def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
 def digest(value):assert type(value)is str and re.fullmatch('[a-f0-9]{64}',value)
 assert type(meta)is dict and set(meta)=={'declaration','sha256','bytes','builder_sha256','template_sha256','template_baseline_sha256','review_sha256','authored_public_input_only','projection_matched_authored_shape','host_authority_granted'}
 assert meta['authored_public_input_only']is meta['projection_matched_authored_shape']is True and meta['host_authority_granted']is False
 builder=(directory/'controller-baseline-declaration.py').read_bytes();template_raw=(directory/'controller-authored-baseline.json').read_bytes();review_raw=(directory/'controller-baseline-reconciliation.json').read_bytes()
 assert hashlib.sha256(builder).hexdigest()==record['baseline_declaration_builder_sha256']==meta['builder_sha256']
 assert 0<len(template_raw)<=256*1024 and hashlib.sha256(template_raw).hexdigest()==record['host_baseline_template_sha256']==meta['template_sha256']
 assert hashlib.sha256(review_raw).hexdigest()==record['baseline_reconciliation_sha256']==meta['review_sha256']
 template=json.loads(template_raw);review=json.loads(review_raw)
 assert set(template)=={'schema','platform','source_binding','baseline','baseline_sha256','prior_evidence','review_sha256'}and type(template['schema'])is int and template['schema']==1
 assert template['platform']==record['platform']and canonical(template['source_binding'])==canonical(candidate['binding'])
 assert template['review_sha256']==meta['review_sha256']and review['platform']==record['platform']and canonical(review['source_binding'])==canonical(candidate['binding'])
 assert type(template['prior_evidence'])is list and 1<=len(template['prior_evidence'])<=64
 for reference in template['prior_evidence']:
  assert set(reference)=={'path','sha256'};digest(reference['sha256']);path=pathlib.Path(reference['path'])
  assert not path.is_absolute()and path.parts[0]=='target'and '..'not in path.parts and path.suffix=='.json'
  assert hashlib.sha256(path.read_bytes()).hexdigest()==reference['sha256']
 baseline=template['baseline'];assert set(baseline)=={'namespace','links','addresses','routes','rules'}and baseline['namespace']==gateway['host_network_namespace']
 assert hashlib.sha256(canonical(baseline)).hexdigest()==template['baseline_sha256']==meta['template_baseline_sha256']==review['baseline_sha256']
 assert review['namespace']==gateway['host_network_namespace']and review['prior_structure_reconstructed']is review['ordering_only_aligned_after_exact_multiset_comparison']is True
 ns=gateway['host_network_namespace'];assert type(ns)is list and len(ns)==2 and all(type(n)is int and 0<n<=18446744073709551615 for n in ns)
 expected=dict(schema_version=1,deployment_id=descriptor['deployment_id'],generation=descriptor['allocation']['generation'],allocation_digest=descriptor['allocation_digest'],host_namespace=dict(dev=ns[0],ino=ns[1]),baseline=baseline)
 assert canonical(meta['declaration'])==canonical(expected)
 raw=canonical(expected);assert 0<len(raw)<=256*1024 and type(meta['bytes'])is int and meta['bytes']==len(raw)and meta['sha256']==hashlib.sha256(raw).hexdigest()
 return expected

def validate_prefix(candidate_path,directory_label,assembly=False,producer_binding=False,host_addition=False):
 assert type(assembly)is type(producer_binding)is type(host_addition)is bool and sum((assembly,producer_binding,host_addition))<=1
 candidate_path=pathlib.Path(candidate_path);candidate=json.loads(candidate_path.read_text());directory=candidate_path.parent/directory_label
 binding=json.loads((directory/'directory-binding.json').read_text());controller=json.loads((directory/'controller.json').read_text());path=pathlib.Path(controller['record']);raw=path.read_bytes();record=json.loads(raw)
 assert record['exit_code']==controller['exit_code']==0 and record['source_binding']==candidate['binding'] and record['platform']==binding['platform']and binding['record']==str(path)
 assert binding['source_commit']==candidate['source_commit']and binding['source_archive_sha256']==candidate['source_sha256']==record['source_archive_sha256']and binding['new_directories']==[]
 for key,name in [('runner_sha256','controller-runner.py'),('guest_sha256','controller-guest.py'),('context_checker_sha256','controller-context.py'),('host_declaration_builder_sha256','controller-host-declaration.py')]:assert hashlib.sha256((directory/name).read_bytes()).hexdigest()==record[key]
 arch={'debian-clean-x86_64':'amd64','debian-x86_64':'amd64','arch-x86_64':'amd64','debian-arm64':'arm64'}[record['platform']];assert record['artifact_sha256']==binding['artifact_sha256']==candidate['platforms'][arch]['artifact_sha256']and record['context_sha256']==candidate['platforms'][arch]['context_sha256']
 assert record['real_client_acceptance']=='NOT_RUN'and record['production_changes'] is record['provider_profiles_used'] is False and record['namespace_or_container_fixture']is record['actual_gateway_is_inert']is True
 modes={'secret_quarantine_success':(0,'actual_secret_free_parent_original_quarantine_and_producer'),'secret_quarantine_postbirth_failure':(1,'actual_producer_postbirth_failure_retains_quarantine_context'),'secret_quarantine_result_failure':(2,'actual_producer_result_writer_failure_retains_original_group'),'secret_quarantine_registration_failure':(3,'actual_producer_registration_failure_retains_prepared_context')}
 if assembly:modes={'secret_assembly_success':(0,'actual_secret_free_parent_original_resource_assembly'),'secret_assembly_pretransfer_failure':(1,'actual_assembly_pretransfer_failure_retains_all_resources'),'secret_assembly_partial_transfer_failure':(2,'actual_assembly_partial_transfer_failure_retains_all_resources'),'secret_assembly_duplicate_transfer':(3,'actual_assembly_duplicate_reservation_refused')}
 if producer_binding:modes={'secret_producer_binding_success':(0,'actual_original_producer_binding_published_under_quarantine'),'secret_producer_binding_postbirth_failure':(1,'actual_producer_binding_postbirth_failure_retains_unpublished_group'),'secret_producer_binding_result_failure':(2,'actual_producer_binding_result_failure_retains_unacknowledged_publication'),'secret_producer_binding_registration_failure':(3,'actual_producer_binding_registration_failure_retains_original_assembly')}
 if host_addition:modes={'secret_host_addition_success':(0,'actual_original_down_pair_added_to_declared_host'),'secret_host_addition_postbirth_failure':(1,'actual_host_addition_postbirth_failure_retains_isolated_pair'),'secret_host_addition_result_failure':(2,'actual_host_addition_result_failure_retains_unacknowledged_host_endpoint'),'secret_host_addition_registration_failure':(3,'actual_host_addition_registration_failure_retains_original_generation')}
 fault,label=modes[record['component_test_mode']];source=pathlib.Path(candidate['source']);assert hashlib.sha256(source.read_bytes()).hexdigest()==candidate['source_sha256']
 with tarfile.open(source)as archive:
  postcompletion_inventory_expected=b'postcompletion_inventory_polls'in archive.extractfile('crates/vprouter-launch/src/kernel/wireguard_role.rs').read()
  own_intent_polling_expected=b'own_intent_polling'in archive.extractfile('crates/vprouter-launch/src/attachment/quarantine/producer.rs').read()
  code=archive.extractfile('crates/vprouter-launch/src/attachment/mount.rs').read();provision_code=archive.extractfile('crates/vprouter-launch/src/attachment/'+('host_addition.rs'if host_addition else'producer_binding.rs'if producer_binding else'assembly.rs'if assembly else'quarantine.rs')).read();assert provision_code.count(label.encode())==1
  family='host-addition'if host_addition else'producer-binding'if producer_binding else'assembly'if assembly else'quarantine';json_family=family.replace('-','_');flag='--ignored-secret-'+family+(''if fault==0 else '-'+record['component_test_mode'].removeprefix('secret_'+family.replace('-','_')+'_').replace('_','-'));assert ('"'+flag+'"').encode()in archive.extractfile('crates/vprouter-launch/src/actual_lab_main.rs').read()
  program_bytes=archive.extractfile('docs/rust-v2/programs-'+arch+'.json').read();program=json.loads(program_bytes);init=[p for p in program['programs']if p['role']=='gateway_init'];assert len(init)==1
 values={k:[]for k in ['input','gateway','descriptor','controller','admission','owner','host']};events=[];environments=[]
 if host_addition:values['baseline']=[]
 for line in record['stdout'].splitlines():
  if line.startswith('LAB_SECRET_HOST_ADDITION 'if host_addition else'LAB_SECRET_PRODUCER_BINDING 'if producer_binding else'LAB_SECRET_ASSEMBLY 'if assembly else'LAB_SECRET_QUARANTINE '):events.append(dict(event='secret_host_addition'if host_addition else'secret_producer_binding'if producer_binding else'secret_assembly'if assembly else'secret_quarantine',value=json.loads(line.split(' ',1)[1])));continue
  try:value=json.loads(line)
  except ValueError:continue
  if 'case'in value:events.append(value)
  if 'secret_attachment_environment'in value:environments.append(value['secret_attachment_environment'])
  for key in values:
   field='owner_probe'if key=='owner'else'secret_quarantine_host'if key=='host'else'secret_host_baseline'if key=='baseline'else'secret_attachment_'+key
   if field in value:values[key].append(value[field])
 assert events==controller['runtime_events']and len(events)==2 and events[0]==dict(case=label,result='PASS')and events[1]['event']==('secret_host_addition'if host_addition else'secret_producer_binding'if producer_binding else'secret_assembly'if assembly else'secret_quarantine')
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
 host=values['host'][0];validate_public_host(host,descriptor,gateway,record['platform'],record['host_declaration_builder_sha256'])
 assert end['harness_exit_code']==0 and all(end[k]is True for k in ['owner_unit_absent','inert_gateway_retained','original_gateway_native_identity_unchanged','synthetic_only','canonical_and_mount_resources_retained'])and end['native_transport_operations_requested']is True and 'transport_or_route_creation'not in end
 if host_addition:
  assert type(descriptor['planned_host_link_index'])is int and 1000000<=descriptor['planned_host_link_index']<=2147483647
  assert end['host_links_and_stable_routes_unchanged']is(fault in(1,3))and end['host_single_down_link_added']is(fault in(0,2))
  assert end['host_addresses_routes_rules_preserved']is end['host_stable_neighbors_preserved']is True
  assert type(end['host_allowed_index'])is int and end['host_allowed_index']==descriptor['planned_host_link_index']
  assert end['host_allowed_name']==next(e for e in descriptor['allocation']['exits']if e['exit_id']==descriptor['primary'])['host_interface']
 else:assert end['host_links_and_stable_routes_unchanged']is True
 host_baseline=values['baseline'][0]if host_addition else None
 host_baseline_declaration=validate_baseline_host(host_baseline,descriptor,gateway,candidate,record,directory)if host_addition else None
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
 host_addition_top=events[1]['value']if host_addition else None;host_addition_fault=fault if host_addition else None
 if host_addition:assert type(host_addition_top['schema'])is int and host_addition_top['schema']==1 and type(host_addition_top['fault'])is int and host_addition_top['fault']==fault
 producer_binding_top=host_addition_top['producer_binding']if host_addition else events[1]['value']if producer_binding else None;producer_binding_fault=0 if host_addition else fault if producer_binding else None
 if producer_binding or host_addition:assert type(producer_binding_top['schema'])is int and producer_binding_top['schema']==1 and type(producer_binding_top['fault'])is int and producer_binding_top['fault']==producer_binding_fault
 assembly_top=producer_binding_top['assembly']if producer_binding or host_addition else events[1]['value']if assembly else None;assembly_fault=0 if producer_binding or host_addition else fault if assembly else None
 if assembly or producer_binding or host_addition:
  validate_assembly_prefix(assembly_top,assembly_fault)
  assert manifest['mode']==record['component_test_mode'].removeprefix('secret_'+('host_addition'if host_addition else'producer_binding'if producer_binding else'assembly')+'_').replace('_','-')
 quarantine_top=assembly_top['quarantine']if assembly or producer_binding or host_addition else events[1]['value'];quarantine_fault=0 if assembly or producer_binding or host_addition else fault;assert quarantine_top['schema']==1 and quarantine_top['fault']==quarantine_fault
 movement_top=quarantine_top['movement'];movement_fault=0;assert movement_top['schema']==1 and movement_top['fault']==0
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
 family='host-addition'if host_addition else'producer-binding'if producer_binding else'assembly'if assembly else'quarantine';assert owner['mode']=='secret-'+family+'-'+record['component_test_mode'].removeprefix('secret_'+family.replace('-','_')+'_').replace('_','-')
 return locals()
