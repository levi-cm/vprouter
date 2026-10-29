"""Synthetic public declaration evidence binding; no native acceptance."""
import copy,datetime,hashlib,importlib.util,json,pathlib
if not __debug__:raise RuntimeError('optimized_python_refused')
base_path=pathlib.Path(__file__).with_name('quarantine_evidence_base.py')
spec=importlib.util.spec_from_file_location('quarantine_evidence',base_path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
helper=pathlib.Path(__file__).with_name('platform-lab')/'quarantine_host_declaration.py'
spec=importlib.util.spec_from_file_location('host_declaration',helper);builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
descriptor=dict(schema_version=1,profile_contents_read=False,docker_queried=False,production_startup_authorized=False,deployment_id='evidence-test',primary='member-a',allocation_digest='a'*64,allocation=dict(deployment_id='evidence-test',generation=1,exits=[dict(exit_id='member-a')]))
gateway=dict(host_network_namespace=[4,4026531840]);builder_sha=hashlib.sha256(helper.read_bytes()).hexdigest()
def sample(platform='debian-clean-x86_64'):
 d=copy.deepcopy(descriptor);g=copy.deepcopy(gateway)
 v,data=builder.host_declaration(d,dict(dev=4,ino=4026531840),dict(ifname=builder.AUTHORED_WAN[platform],ifindex=2,address='52:54:00:12:34:56',link_type='ether'),platform)
 h=dict(declaration=v,sha256=hashlib.sha256(data).hexdigest(),bytes=len(data),builder_sha256=builder_sha,authored_public_input_only=True,native_validation_performed_by_controller=False,host_authority_granted=False)
 return h,d,g
rows=[]
for platform in builder.AUTHORED_WAN:
 proof=module.validate_public_host(*sample(platform),platform,builder_sha)
 assert proof==dict(public_declaration_bound=True,native_wan_validation_by_controller=False,host_authority_granted=False)
 rows.append(dict(case=platform,result='PASS'))
mutations=[
 ('allocation_digest',lambda h,d,g:h['declaration'].update(allocation_digest='b'*64)),
 ('descriptor_digest',lambda h,d,g:d.update(allocation_digest='wrong')),
 ('builder',lambda h,d,g:h.update(builder_sha256='b'*64)),
 ('checksum',lambda h,d,g:h.update(sha256='b'*64)),
 ('byte_count',lambda h,d,g:h.update(bytes=1)),
 ('byte_count_bool',lambda h,d,g:h.update(bytes=True)),
 ('host_authority',lambda h,d,g:h.update(host_authority_granted=True)),
 ('native_claim',lambda h,d,g:h.update(native_validation_performed_by_controller=True)),
 ('namespace',lambda h,d,g:g.update(host_network_namespace=[4,4026531841])),
 ('namespace_bool',lambda h,d,g:h['declaration']['host_namespace'].update(dev=True)),
 ('namespace_overflow',lambda h,d,g:h['declaration']['host_namespace'].update(ino=2**64)),
 ('generation',lambda h,d,g:h['declaration'].update(generation=2)),
 ('generation_bool',lambda h,d,g:h['declaration'].update(generation=True)),
 ('schema_bool',lambda h,d,g:h['declaration'].update(schema_version=True)),
 ('member',lambda h,d,g:h['declaration'].update(member='member-b')),
 ('duplicate_member',lambda h,d,g:d['allocation']['exits'].append(dict(exit_id='member-a'))),
 ('deployment',lambda h,d,g:h['declaration'].update(deployment_id='other')),
 ('wan_name',lambda h,d,g:h['declaration']['wan'].update(name='eth0')),
 ('wan_index_bool',lambda h,d,g:h['declaration']['wan'].update(index=True)),
 ('wan_address_bool',lambda h,d,g:h['declaration']['wan']['address'].__setitem__(0,True)),
 ('extra_wan',lambda h,d,g:h['declaration']['wan'].update(extra=1)),
 ('extra_metadata',lambda h,d,g:h.update(extra=1)),
]
for name,mutate in mutations:
 h,d,g=sample();mutate(h,d,g)
 # Keep semantic mutations internally byte-consistent so the intended
 # predicate must reject them before the final integrity check.
 if name not in ('checksum','byte_count','byte_count_bool'):
  data=json.dumps(h['declaration'],sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
  h.update(sha256=hashlib.sha256(data).hexdigest(),bytes=len(data))
 try:module.validate_public_host(h,d,g,'debian-clean-x86_64',builder_sha)
 except(AssertionError,TypeError,ValueError,KeyError):rows.append(dict(case=name,result='PASS_REFUSED'))
 else:raise AssertionError('invalid_public_evidence_accepted:'+name)
dependencies=[pathlib.Path(__file__),base_path,helper]
record=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),checks=rows,files=[dict(path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest())for p in dependencies],scope='LOCAL_SYNTHETIC_PUBLIC_BINDING_ONLY; no native, full frozen prefix, protected selector, current WAN, table, producer, cleanup, reuse or release acceptance')
destination=pathlib.Path('target/lab-state')/('quarantine-public-evidence-smokes-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.json')
with destination.open('x')as f:json.dump(record,f,indent=2);f.write('\n')
print(json.dumps(dict(record=str(destination),checks=len(rows),native_acceptance=False)))
