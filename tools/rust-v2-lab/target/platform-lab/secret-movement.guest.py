"""Root-owned inert gateway fixture; all profiles are external synthetic input."""
import base64,hashlib,json,os,pathlib,re,secrets,stat,subprocess,tarfile,time
if not __debug__:raise RuntimeError('optimized_python_refused')
CONFIG=CONFIGURATION
root=pathlib.Path('/var/lib/vprouter-v2-lab');assert os.geteuid()==0
for path in (pathlib.Path('/'),pathlib.Path('/var'),pathlib.Path('/var/lib'),root):
 s=path.lstat();assert stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and not s.st_mode&0o022
assert stat.S_IMODE(root.stat().st_mode)==0o700

def regular(path,mode):
 s=path.lstat();assert stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==mode and s.st_nlink==1;return s

def create(path,data,mode=0o600):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
 with os.fdopen(fd,'wb')as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
 regular(path,mode)

def command(argv,timeout=8):
 r=subprocess.run(argv,capture_output=True,text=True,timeout=timeout);assert r.returncode==0,(argv[0],r.returncode,r.stderr[:4096]);assert len(r.stdout)<4*1024*1024;return r.stdout

def observation_context():
 # Outside the native owner invocation. These are whole-VM context samples,
 # never per-operation CPU attribution or an admission/deadline exception.
 started=time.clock_gettime(time.CLOCK_BOOTTIME)
 paths={'boot':'/proc/sys/kernel/random/boot_id','cpu':'/proc/stat','cpu_pressure':'/proc/pressure/cpu','io_pressure':'/proc/pressure/io','memory_pressure':'/proc/pressure/memory','root_cpu_max':'/sys/fs/cgroup/cpu.max','root_cpu_stat':'/sys/fs/cgroup/cpu.stat'}
 values={}
 for name,path in paths.items():
  try:
   with open(path,'r',encoding='ascii')as stream:data=stream.readline(4097)if name=='cpu'else stream.read(4097)
   values[name]={'status':'bounded'if len(data)<=4096 else'too_large','text':data if len(data)<=4096 else None}
  except OSError as error:values[name]={'status':'unavailable','errno':error.errno}
 sample=dict(started_at=started,machine=os.uname().machine,logical_cpus=os.cpu_count(),affinity=sorted(os.sched_getaffinity(0)),files=values,scope='whole_vm_context_only',operation_cost_attribution=False)
 sample['finished_at']=time.clock_gettime(time.CLOCK_BOOTTIME)
 return sample

def stable_host():
 links=json.loads(command(['ip','-j','-d','link','show']));keys=('ifindex','ifname','ifalias','mtu','flags','address','link_index')
 routes={}
 for family in ('-4','-6'):
  values=json.loads(command(['ip','-j',family,'route','show','table','all']));routes[family]=sorted([{k:v for k,v in row.items()if k!='expires'}for row in values],key=lambda row:json.dumps(row,sort_keys=True))
 return dict(links=sorted([{k:row[k]for k in keys if k in row}for row in links],key=lambda row:row['ifindex']),routes=routes)

regular(root/'isolated-acceptance',0o600)
selectors=[root/name for name in ('owner-domain-nonce','secret-attachment.json','secret-attachment-spec.json','secret-attachment-staging.json','task8b2-image','task8b2-host-acceptance')]
assert not any(path.exists()or path.is_symlink()for path in selectors),'existing_fixed_selector_requires_review'
before=stable_host()
for label,digest,mode,uploaded in (
 ('payload',CONFIG['artifact_sha256'],0o555,'secret-attachment-'+CONFIG['artifact_sha256']),
 ('context.tar',CONFIG['context_sha256'],0o600,'secret-attachment-context-'+CONFIG['context_sha256'])):
 target=root/('secret-attachment-'+digest+'.'+label)
 if target.exists():regular(target,mode);assert hashlib.sha256(target.read_bytes()).hexdigest()==digest
 else:
  data=(pathlib.Path('/home/vprouterlab')/uploaded).read_bytes();assert hashlib.sha256(data).hexdigest()==digest;create(target,data,mode)
payload=root/('secret-attachment-'+CONFIG['artifact_sha256']+'.payload');context=root/('secret-attachment-'+CONFIG['context_sha256']+'.context.tar')
with tarfile.open(context)as archive:
 member=archive.getmember('rootfs/usr/local/bin/vprouter-worker');assert member.isfile()and member.size==CONFIG['init_bytes'];init=archive.extractfile(member).read();assert hashlib.sha256(init).hexdigest()==CONFIG['init_sha256']
artifact=root/('task8b2-'+CONFIG['init_sha256']+'.gateway-init')
if artifact.exists():regular(artifact,0o555);assert artifact.read_bytes()==init
else:create(artifact,init,0o555)
del init
build=root/('secret-attachment-build-'+CONFIG['context_sha256'])
if not build.exists():build.mkdir(mode=0o700)
s=build.lstat();assert stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700
iid=build/'image-id'
if not iid.exists():
 with context.open('rb')as stream:r=subprocess.run(['docker','build','--network=none','--pull=false','--iidfile',str(iid),'-'],stdin=stream,capture_output=True,text=True,timeout=75)
 print(json.dumps(dict(secret_attachment_build_exit=r.returncode)),flush=True);assert r.returncode==0,r.stderr[-4096:];os.chmod(iid,0o600)
regular(iid,0o600);image_id=iid.read_text().strip();assert re.fullmatch('sha256:[a-f0-9]{64}',image_id)
assert command(['docker','image','inspect','--format','{{.Id}}',image_id]).strip()==image_id
assert json.loads(command(['docker','image','inspect','--format','{{json .Config.Entrypoint}}',image_id]))==['/usr/local/bin/vprouter-worker']
assert command(['docker','image','inspect','--format','{{index .Config.Labels "io.vprouter.programs"}}',image_id]).strip()==CONFIG['manifest_sha256']
nonce=secrets.token_hex(32);inputs=root/('secret-inputs-'+nonce);inputs.mkdir(mode=0o700);state_root=root/('secret-gateway-state-'+nonce);state_root.mkdir(mode=0o700)
ids=['a'+nonce[:12],'b'+nonce[:12]];keys=[bytearray(secrets.token_bytes(32)),bytearray(secrets.token_bytes(32))]
def clamp(value):
 out=bytearray(value);out[0]&=248;out[31]&=127;out[31]|=64;return out
while clamp(keys[0])==clamp(keys[1]):keys[1][:]=secrets.token_bytes(32)
exits=[];metadata=[]
for index,member in enumerate(ids):
 directory=inputs/member;directory.mkdir(mode=0o700);state=state_root/member;state.mkdir(mode=0o700);profile=directory/'de-fra-wg-404.conf'
 private=base64.b64encode(keys[index]).decode()
 public_result=subprocess.run(['wg','pubkey'],input=private+'\n',capture_output=True,text=True,timeout=5)
 assert public_result.returncode==0,'synthetic_public_derivation_failed'
 device_public=base64.b64decode(public_result.stdout.strip(),validate=True);assert len(device_public)==32 and any(device_public)
 text='[Interface]\nPrivateKey='+private+'\nAddress=10.64.0.2/32\nDNS=10.64.0.1\n[Peer]\nPublicKey=zo060cy2M+x7cMF4FKXHbs0CloUFDTRHRboFhw5YfVk=\nAllowedIPs=0.0.0.0/0\nEndpoint=185.66.0.1:51820\n';create(profile,text.encode());s=regular(profile,0o600)
 metadata.append(dict(member=member,device_public_key=list(device_public),path=str(profile),device=s.st_dev,inode=s.st_ino,size=s.st_size,mode=stat.S_IMODE(s.st_mode),uid=s.st_uid,gid=s.st_gid))
 exits.append(dict(id=member,enabled=index==0,state_dir=str(state),mode=dict(kind='mullvad',profile=str(profile),expected_server='de-fra-wg-404')))
for key in keys:key[:]=bytes(len(key))
del keys,private,text,device_public,public_result
configuration=dict(schema_version=2,deployment_id='secretlab-'+nonce[:12],site='debdev',gateway_image='vprouter-v2-lab@'+image_id,exits=exits,dependency_adapters=[],client_policies=[])
public=json.dumps(configuration,sort_keys=True,separators=(',',':')).encode();create(inputs/'configuration.json',public);create(root/'secret-attachment.json',public);create(root/'owner-domain-nonce',nonce.encode())
manifest=dict(schema=1,nonce=nonce,mode=CONFIG['mode'],configuration_sha256=hashlib.sha256(public).hexdigest(),profiles=metadata,synthetic_only=True,keys_created_outside_rust_parent=True,private_bytes_in_argv_environment_or_configuration=False,duplicate_private_input=False,state_root=str(state_root),canonical_root_precreated=False)
create(inputs/'input-manifest.json',json.dumps(manifest,sort_keys=True).encode());print(json.dumps(dict(secret_attachment_input=manifest)),flush=True)
net=pathlib.Path('/proc/self/ns/net').stat();init_net=pathlib.Path('/proc/1/ns/net').stat();assert(net.st_dev,net.st_ino)==(init_net.st_dev,init_net.st_ino)
markers=[root/'task8b2-image',root/'task8b2-host-acceptance'];contents=[dict(schema=1,image_id=image_id,program_manifest_sha256=CONFIG['manifest_sha256']),dict(artifact_sha256=CONFIG['artifact_sha256'],network_dev=net.st_dev,network_ino=net.st_ino)]
marker_ids=[]
for path,content in zip(markers,contents):create(path,json.dumps(content,sort_keys=True).encode());s=path.stat();marker_ids.append((s.st_dev,s.st_ino));print(json.dumps(dict(secret_attachment_admission=dict(path=str(path),device=s.st_dev,inode=s.st_ino,content=content))),flush=True)
descriptor=json.loads(command([str(payload),'--secret-attachment-descriptor']))
assert descriptor['schema_version']==1 and descriptor['nonce']==nonce and descriptor['deployment_id']==configuration['deployment_id']and descriptor['primary']==ids[0]
assert descriptor['profile_contents_read'] is descriptor['docker_queried'] is descriptor['container_mounts_allowed'] is descriptor['production_startup_authorized'] is False
assert descriptor['container_required'] is True and descriptor['program_manifest_sha256']==CONFIG['manifest_sha256']
assert descriptor['configuration']==str(root/'secret-attachment.json')and descriptor['spec']==str(root/'secret-attachment-spec.json')and descriptor['staging_path']==str(root/'secret-attachment-staging.json')
create(inputs/'descriptor.json',json.dumps(descriptor,sort_keys=True).encode());print(json.dumps(dict(secret_attachment_descriptor=descriptor)),flush=True)
staging=descriptor['staging'];assert staging['image_ref']==configuration['gateway_image']and staging['content_id']==image_id and staging['artifact_path']==str(artifact)and staging['artifact_sha256']==CONFIG['init_sha256']and staging['artifact_size']==CONFIG['init_bytes']and staging['architecture']==CONFIG['architecture']and staging['artifact_kind']=='actual_gateway_lab_v1'and staging.get('execution_policy_sha256')is None
allocation=descriptor['allocation'];assert allocation['deployment_id']==configuration['deployment_id']and allocation['generation']==1
primary=[entry for entry in allocation['exits']if entry['exit_id']==ids[0]];assert len(primary)==1
name='vprouter-v2-lab-secret-attachment-'+nonce[:16]
assert command(['docker','container','ls','--all','--filter','name=^/'+name+'$','--format','{{.ID}}']).strip()==''
create(inputs/'gateway-create-intent.json',json.dumps(dict(name=name,image_id=image_id,deployment_id=configuration['deployment_id'],only_inert_gateway=True),sort_keys=True).encode())
container=command(['docker','run','--detach','--name',name,'--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--label','io.vprouter.deployment='+configuration['deployment_id'],'--label','io.vprouter.role=gateway','--entrypoint','/usr/local/bin/vprouter-worker',image_id],timeout=15).strip();assert re.fullmatch('[a-f0-9]{64}',container)
state=json.loads(command(['docker','inspect','--format','{{json .State}}',container]));assert state['Running']and not state['Paused']and state['Pid']>1 and state['StartedAt']
pid=state['Pid'];pin=os.pidfd_open(pid,0)
import select
assert not select.select([pin],[],[],0)[0];raw=pathlib.Path('/proc',str(pid),'stat').read_text();start=int(raw[raw.rfind(')')+2:].split()[19]);assert not select.select([pin],[],[],0)[0]
network=pathlib.Path('/proc',str(pid),'ns/net').stat();source_namespace=[network.st_dev,network.st_ino]
assert source_namespace!=[net.st_dev,net.st_ino]
spec=dict(schema_version=1,allocation=allocation,generation=1,exit=primary[0],container_id=container,started_at=state['StartedAt'],process_start_time=start,image_ref=staging['image_ref'],worker_sha256=staging['artifact_sha256'])
for fixed,archived,value in((root/'secret-attachment-spec.json',inputs/'spec.json',spec),(root/'secret-attachment-staging.json',inputs/'staging.json',staging)):
 data=json.dumps(value,sort_keys=True,separators=(',',':')).encode();create(fixed,data);create(archived,data)
gateway=dict(container_id=container,name=name,image_id=image_id,pid=pid,start=start,started_at=state['StartedAt'],source_namespace=source_namespace,host_network_namespace=[net.st_dev,net.st_ino],spec_sha256=hashlib.sha256((inputs/'spec.json').read_bytes()).hexdigest(),staging_sha256=hashlib.sha256((inputs/'staging.json').read_bytes()).hexdigest(),program_manifest_sha256=CONFIG['manifest_sha256'],init_sha256=CONFIG['init_sha256'],inert=True,mounts=[],provider_state_mounted=False)
create(inputs/'gateway-manifest.json',json.dumps(gateway,sort_keys=True).encode());print(json.dumps(dict(secret_attachment_gateway=gateway)),flush=True)
unit=descriptor['owner_unit'];assert re.fullmatch('vprouter-v2-owner@[a-f0-9]{64}[.]service',unit)
assert command(['systemctl','show',unit,'--property=LoadState','--value']).strip()=='not-found'
output=root/('secret-attachment-'+nonce+'.stdout');diagnostic=root/('secret-attachment-'+nonce+'.stderr');create(output,b'');create(diagnostic,b'')
print(json.dumps(dict(owner_probe=dict(unit=unit,nonce=nonce,mode='secret-movement-'+CONFIG['mode'],component_only=True))),flush=True)
environment_before=observation_context()
r=subprocess.run(['systemd-run','--quiet','--wait','--collect','--service-type=exec','--property=StandardInput=null','--property=StandardOutput=file:'+str(output),'--property=StandardError=file:'+str(diagnostic),'--unit='+unit,'--property=Slice=system.slice','--property=KillMode=control-group','--property=KillSignal=SIGKILL','--property=TimeoutStopSec=3s','--property=RuntimeMaxSec=110s','--',str(payload),CONFIG['flag']],capture_output=True,text=True,timeout=120)
environment_after=observation_context()
print(json.dumps(dict(secret_attachment_environment=dict(schema=1,before=environment_before,after=environment_after,sampled_during_native_operation=False,whole_vm_only=True))),flush=True)
regular(output,0o600);regular(diagnostic,0o600);stdout=output.read_bytes();stderr=diagnostic.read_bytes();assert len(stdout)<4*1024*1024 and len(stderr)<65536;print(stdout.decode(),end='',flush=True)
if stderr:os.write(2,stderr)
assert before==stable_host(),'unexpected_host_link_or_stable_route_change'
assert command(['systemctl','show',unit,'--property=LoadState','--value']).strip()=='not-found'and not(pathlib.Path('/sys/fs/cgroup/system.slice')/unit).exists()
assert not select.select([pin],[],[],0)[0];again=json.loads(command(['docker','inspect','--format','{{json .State}}',container]));assert again['Running']and again['Pid']==pid and again['StartedAt']==state['StartedAt'];current=pathlib.Path('/proc',str(pid),'ns/net').stat();assert[current.st_dev,current.st_ino]==source_namespace;os.close(pin)
for path,content,identity in zip(markers,contents,marker_ids):
 s=regular(path,0o600);assert(s.st_dev,s.st_ino)==identity and json.loads(path.read_bytes())==content;os.link(path,inputs/path.name,follow_symlinks=False);path.unlink()
print(json.dumps(dict(secret_attachment_controller=dict(harness_exit_code=r.returncode,owner_unit_absent=True,host_links_and_stable_routes_unchanged=True,inert_gateway_retained=True,original_gateway_native_identity_unchanged=True,synthetic_only=True,native_transport_operations_requested=True,canonical_and_mount_resources_retained=True))),flush=True)
if r.returncode==0:
 for path in selectors[:4]:
  regular(path,0o600);expected={'owner-domain-nonce':nonce.encode(),'secret-attachment.json':public,'secret-attachment-spec.json':(inputs/'spec.json').read_bytes(),'secret-attachment-staging.json':(inputs/'staging.json').read_bytes()}[path.name];assert path.read_bytes()==expected;os.link(path,inputs/('selected-'+path.name),follow_symlinks=False);path.unlink()
else:print(json.dumps(dict(secret_attachment_selectors_retained=True,nonce=nonce,reason='failed_case_requires_exact_owner_child_mount_and_selector_review')),flush=True)
for directory in(root,inputs):
 fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
raise SystemExit(r.returncode)
