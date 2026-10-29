"""Strict frozen-source validation/preparation fixture witness collector.

Public facts and original reap receipts only; no real-profile/requirement8 claim.
"""
import datetime,hashlib,json,math,pathlib,re,sys,tarfile
if not __debug__: raise RuntimeError('optimized_python_refused')
candidate_path=pathlib.Path(sys.argv[1]);candidate=json.loads(candidate_path.read_text());directory=candidate_path.parent/sys.argv[2]
binding=json.loads((directory/'directory-binding.json').read_text());controller=json.loads((directory/'controller.json').read_text());path=pathlib.Path(controller['record']);raw=path.read_bytes();record=json.loads(raw)
assert record['exit_code']==controller['exit_code']==0 and record['source_binding']==candidate['binding'] and binding['record']==str(path)
assert record['platform']==binding['platform']
for key,name in [('runner_sha256','controller-runner.py'),('guest_sha256','controller-guest.py')]:
 assert hashlib.sha256((directory/name).read_bytes()).hexdigest()==record[key]
assert binding['new_directories']==[] and binding['source_commit']==candidate['source_commit'] and binding['artifact_sha256']==record['artifact_sha256']
assert record['real_client_acceptance']=='NOT_RUN' and record['production_changes'] is record['provider_profiles_used'] is record['namespace_or_container_fixture'] is False
arch={'debian-clean-x86_64':'amd64','debian-x86_64':'amd64','arch-x86_64':'amd64','debian-arm64':'arm64'}[binding['platform']];assert record['artifact_sha256']==candidate['platforms'][arch]['artifact_sha256']
cases={
 'secret_preparation_success':(0,'actual_secret_free_parent_durable_validation_result_and_original_reaps'),
 'secret_preparation_reject':(1,'actual_secret_validation_rejection_retains_context'),
 'secret_preparation_intent_deadline':(2,'actual_secret_validation_intent_writer_original_deadline_retained'),
 'secret_preparation_birth_deadline':(3,'actual_secret_validation_birth_writer_original_deadline_retained'),
 'secret_preparation_result_failure':(4,'actual_secret_validation_result_writer_failure_retains_context'),
 'secret_preparation_result_receipt_mismatch':(5,'actual_secret_validation_mismatched_result_receipt_retains_original_report')}
fault,label=cases[record['component_test_mode']]
source=pathlib.Path(candidate['source']);assert hashlib.sha256(source.read_bytes()).hexdigest()==candidate['source_sha256']
with tarfile.open(source) as archive:
 code=archive.extractfile('crates/vprouter-launch/src/secret.rs').read();assert code.count(label.encode())==1
 flag='--ignored-secret-preparation'+('' if fault==0 else '-'+record['component_test_mode'].removeprefix('secret_preparation_').replace('_','-'))
 assert ('"'+flag+'"').encode() in archive.extractfile('crates/vprouter-launch/src/actual_lab_main.rs').read()
events=[];inputs=[];probes=[];ends=[]
for line in record['stdout'].splitlines():
 if line.startswith('LAB_SECRET_PREPARATION '):events.append(dict(event='secret_preparation',value=json.loads(line.split(' ',1)[1])));continue
 try:value=json.loads(line)
 except ValueError:continue
 if 'case'in value:events.append(value)
 if 'secret_preparation_input'in value:inputs.append(value['secret_preparation_input'])
 if 'owner_probe'in value:probes.append(value['owner_probe'])
 if 'secret_preparation_controller'in value:ends.append(value['secret_preparation_controller'])
assert events==controller['runtime_events'] and len(events)==2 and events[0]==dict(case=label,result='PASS') and events[1]['event']=='secret_preparation'
assert len(inputs)==len(probes)==len(ends)==1
manifest,probe,end=inputs[0],probes[0],ends[0]
assert manifest['schema']==1 and manifest['synthetic_only'] is manifest['keys_created_outside_rust_parent'] is True
assert manifest['private_bytes_in_argv_environment_or_configuration'] is False and manifest['duplicate_private_input'] is (fault==1)
nonce=manifest['nonce'];assert re.fullmatch('[a-f0-9]{64}',nonce) and nonce==probe['nonce']
assert end['harness_exit_code']==0 and end['owner_unit_absent'] is end['host_links_and_stable_routes_unchanged'] is end['synthetic_only'] is True and end['namespace_or_container_creation'] is False
profiles=manifest['profiles'];assert len(profiles)==2
for profile in profiles:
 assert profile['uid']==profile['gid']==0 and profile['mode']==0o600 and type(profile['inode'])is int and profile['inode']>0 and 0<profile['size']<=65536
 assert profile['path']=='/var/lib/vprouter-v2-lab/secret-inputs-'+nonce+'/'+profile['member']+'/de-fra-wg-404.conf'

def integer(value,minimum=0):assert type(value)is int and value>=minimum;return value
def finite(value):assert type(value)in(int,float) and math.isfinite(value) and value>0;return value
w=events[1]['value'];assert w['schema']==1 and w['fault']==fault
assert w['parent_pristine'] is w['same_service_retained'] is True
assert w['namespace_or_link_authority'] is w['requirement8_complete'] is False
p=w['preparation'];requested,deadline=map(finite,(p['requested_at'],p['deadline']));assert abs(deadline-requested-2)<0.00001
assert p['member']=='a'+nonce[:12] and p['base_network_absent'] is p['owner_host_anchor_present'] is p['service_reserved'] is p['native_children_reaped'] is True
owner=p['canonical_owner_epoch'];assert owner['unit']==probe['unit'] and re.fullmatch('vprouter-v2-owner@[a-f0-9]{64}[.]service',owner['unit'])
assert re.fullmatch('[a-f0-9-]{36}',owner['boot']) and re.fullmatch('[a-f0-9]{32}',owner['invocation'])
integer(owner['pid'],2);integer(owner['start'],1);integer(owner['cgroup']['dev'],1);integer(owner['cgroup']['ino'],1)
assert p['canonical_result_present'] is (fault in(0,5))
assert p['canonical_pending'] is p['mutation_fenced'] is (fault in(2,3,4))
expected_phases={0:['intent','birth','result'],1:['intent','birth'],2:['intent'],3:['intent','birth'],4:['intent','birth','result'],5:['intent','birth','result']}[fault]
writers=p['writers'];assert [v['phase'] for v in writers]==expected_phases
writer_ids=[]
for i,writer in enumerate(writers):
 pid,start=integer(writer['pid'],2),integer(writer['start'],1);writer_ids.append((pid,start))
 assert requested<=finite(writer['queued_at'])<deadline and writer['io_deadline']==writer['parent_deadline']==deadline
 failed=(fault in(2,3,4) and i==len(writers)-1)
 assert writer['actual_wait_status']==((9 if fault==4 else 122<<8) if failed else 0)
 if failed:assert writer['verified_at'] is None
 else:assert writer['queued_at']<=finite(writer['verified_at'])<deadline
assert len(set(writer_ids))==len(writer_ids)
validator=w['validator']
if fault==2:assert validator is None
else:
 assert validator is not None
 birth=validator['birth'];assert birth==p['birth']
 vid=(integer(birth['pid'],2),integer(birth['start'],1));assert vid not in writer_ids
 assert requested<=finite(birth['born_at'])<deadline and birth['deadline']==deadline
 status=validator['actual_wait_status']
 assert status==0 if fault in(0,4,5) else status==122<<8 if fault==1 else status in(9,122<<8)
if fault==0:
 assert p['member_native_jobs_collected'] is w['profile_pins_retained'] is True
 assert w['profile_pin_count']==w['whole_configuration_members']==2
else:
 assert w['whole_failed_driver_retained_after_drop'] is True
 assert w['held_real_writer'] is w['unreaped_writer_reported_not_drained'] is (fault in(2,3,4))
 assert w['expired_native_writer_status']==(122<<8 if fault in(2,3) else None)
 assert w['mismatched_receipt_retained_original_report'] is (fault==5)
output=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),record=str(path),record_sha256=hashlib.sha256(raw).hexdigest(),source_binding=record['source_binding'],artifact_sha256=record['artifact_sha256'],platform=binding['platform'],component_test_mode=record['component_test_mode'],collector_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),input_manifest=manifest,witness=w,real_client_acceptance='NOT_RUN',requirement8_complete=False,limit='Original native validation and pre-resource journal component with external synthetic profiles only. Parent pristine is supplemental; no provisioning/raw-WG/legacy-fork/namespace/client/provider/public-runtime/whole requirement8 or all-nine acceptance.')
run=re.fullmatch('actual-program-run-([0-9]+).json',path.name)[1];destination=pathlib.Path('target/lab-state')/('secret-preparation-run-'+run+'.json')
with destination.open('x') as stream:json.dump(output,stream,indent=2);stream.write('\n')
print(json.dumps(dict(record=str(destination),platform=binding['platform'],fault=fault,original_deadline_verified=True,original_native_reaps_verified=True,requirement8_complete=False)))
