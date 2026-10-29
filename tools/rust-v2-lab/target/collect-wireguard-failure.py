"""Bind fixed scalar failure evidence to frozen source and original public history."""
import datetime,hashlib,json,math,pathlib,subprocess,sys,tarfile
if not __debug__:raise RuntimeError('optimized_python_refused')
PARENT={1:'child_poll',2:'receipt_current',3:'profile_pins',4:'public_decode',5:'sequences',6:'new_down_token',7:'down_readback',8:'link_equality',9:'public_wireguard_check',10:'final_accepted'}
CHILD={1:'profile_load',2:'member_selection',3:'confined_network',10:'plan',11:'absence',12:'new_link',13:'created_shape',14:'mtu',15:'down_token',16:'family',17:'set_device',18:'configuration',19:'down',20:'creation_complete',21:'fresh_wireguard',22:'fresh_down',23:'role_check',24:'public_encode'}

def validate_rows(rows,canonical):
 assert 1<=len(rows)<=8
 histories=[h for entry in canonical['entries']for h in(entry.get('preparation')or{}).get('wireguard',[])]
 for row in rows:
  assert set(row)=={'kind','request','original_pid','original_start','actual_wait_status','requested_at','deadline','parent_stage','parent_reason','diagnostic_bound','child_stage','child_code','child_errno','child_at'}
  digest=row['request'];assert isinstance(digest,list)and len(digest)==32 and any(digest)and all(type(v)is int and 0<=v<=255 for v in digest)
  matches=[h for h in histories if h['request']==digest and h['kind']==row['kind']];assert len(matches)==1;h=matches[0]
  assert row['kind']in('sockets','provision','query')and row['requested_at']==h['requested_at']and row['deadline']==h['deadline']and h['result']is h['verified_at']is None
  began,end=row['requested_at'],row['deadline'];assert all(type(v)in(int,float)and math.isfinite(v)and v>0 for v in(began,end))and abs(end-began-2)<.00001
  pid,start=row['original_pid'],row['original_start'];assert pid is None or type(pid)is int and pid>1;assert start is None or type(start)is int and start>0
  assert start is None or pid is not None
  assert row['actual_wait_status']is None or pid is not None
  b=h['birth']
  if b is not None:
   assert type(b['pid'])is int and b['pid']>1 and type(b['start'])is int and b['start']>0
   assert type(b['born_at'])in(int,float)and math.isfinite(b['born_at'])and began<=b['born_at']<end and b['deadline']==end
   assert(pid,start)==(b['pid'],b['start'])
  status=row['actual_wait_status'];assert status is None or type(status)is int and 0<=status<=2147483647
  stage=row['parent_stage'];assert stage is None or type(stage)is int and 0<=stage<=31
  reason=row['parent_reason'];assert reason is None or isinstance(reason,str)and 0<len(reason)<=256 and reason.isascii()
  assert type(row['diagnostic_bound'])is bool
  if row['diagnostic_bound']:
   assert b is not None and status is not None and status!=0
   assert type(row['child_stage'])is int and 1<=row['child_stage']<=31 and type(row['child_code'])is int and 1<=row['child_code']<=31
   assert type(row['child_errno'])is int and -4095<=row['child_errno']<=4095
   at=row['child_at'];assert type(at)in(int,float)and math.isfinite(at)and b['born_at']<=at<end
  else:assert all(row[k]is None for k in['child_stage','child_code','child_errno','child_at'])
 return [dict(**row,durable_birth_bound=any(h['request']==row['request']and h['kind']==row['kind']and h['birth']is not None for h in histories),parent_operation=PARENT.get(row['parent_stage']),child_operation=CHILD.get(row['child_stage'])if row['diagnostic_bound']else None)for row in rows]

if __name__=='__main__':
 cp=pathlib.Path(sys.argv[1]);candidate=json.loads(cp.read_text());run=int(sys.argv[2]);path=pathlib.Path(f'target/lab-state/actual-program-run-{run}.json');raw=path.read_bytes();r=json.loads(raw)
 assert r['exit_code']!=0 and r['component_test_mode']in('secret_provision_success','secret_provision_postbirth_failure','secret_provision_result_failure','secret_provision_registration_failure')and r['source_binding']==candidate['binding']and r['source_archive_sha256']==candidate['source_sha256']
 assert r['real_client_acceptance']=='NOT_RUN'and r['production_changes']is r['provider_profiles_used']is False
 source=pathlib.Path(candidate['source']);assert hashlib.sha256(source.read_bytes()).hexdigest()==candidate['source_sha256']
 assert json.loads(subprocess.check_output([sys.executable,'tools/verify-frozen-build-inputs.py',str(source),candidate['source_commit']]))==candidate['binding']
 with tarfile.open(source)as archive:assert b'LAB_WIREGUARD_FAILURE'in archive.extractfile('crates/vprouter-launch/src/kernel/wireguard_role.rs').read(),'frozen_source_has_no_wireguard_diagnostic'
 bindings=[(p.parent,json.loads(p.read_text()))for p in cp.parent.rglob('directory-binding.json')if json.loads(p.read_text())['record']==str(path)];assert len(bindings)==1;directory,b=bindings[0]
 assert b['source_archive_sha256']==candidate['source_sha256']
 for key,name in [('runner_sha256','controller-runner.py'),('guest_sha256','controller-guest.py'),('context_checker_sha256','controller-context.py')]:assert hashlib.sha256((directory/name).read_bytes()).hexdigest()==r[key]
 arch={'debian-clean-x86_64':'amd64','debian-x86_64':'amd64','arch-x86_64':'amd64','debian-arm64':'arm64'}[b['platform']];assert b['platform']==r['platform']and b['source_commit']==candidate['source_commit']and b['artifact_sha256']==r['artifact_sha256']==candidate['platforms'][arch]['artifact_sha256']and r['context_sha256']==candidate['platforms'][arch]['context_sha256']
 reference_path=pathlib.Path(f'target/lab-state/secret-provision-failure-run-{run}.json');reference_raw=reference_path.read_bytes();reference=json.loads(reference_raw)
 assert reference['record_sha256']==hashlib.sha256(raw).hexdigest()and reference['source_binding']==r['source_binding']and reference['platform']==r['platform']and reference['read_only']is True and reference['private_profile_contents_read']is reference['signals_unmount_or_cleanup']is False
 rows=[json.loads(line.split(' ',1)[1])for line in r['stderr'].splitlines()if line.startswith('LAB_WIREGUARD_FAILURE ')]
 diagnostics=validate_rows(rows,reference['canonical']['namespaces.json'])
 output=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),record=str(path),record_sha256=hashlib.sha256(raw).hexdigest(),inspection=str(reference_path),inspection_sha256=hashlib.sha256(reference_raw).hexdigest(),source_binding=r['source_binding'],artifact_sha256=r['artifact_sha256'],context_sha256=r['context_sha256'],platform=r['platform'],collector_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),diagnostics=diagnostics,original_failure_preserved=True,fresh_reap_or_resource_authority=False,requirement8_complete=False,allnine_complete=False,limit='Original constructor/channel-bound scalar diagnostics only. Missing diagnostics stay unobserved. Operation labels identify the entered source operation; errno/code do not identify a denied filter or inner syscall without further evidence. No native success, deadline extension, cleanup, reuse or provider/client acceptance.')
 destination=pathlib.Path(f'target/lab-state/wireguard-failure-run-{run}.json')
 with destination.open('x')as stream:json.dump(output,stream,indent=2);stream.write('\n')
 print(json.dumps(dict(record=str(destination),diagnostics=diagnostics,original_failure_preserved=True)))
