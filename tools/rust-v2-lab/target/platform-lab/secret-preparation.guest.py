"""Fixed Root-owned external synthetic-input preparation fixture controller."""
import base64,hashlib,json,os,pathlib,re,secrets,stat,subprocess,time
if not __debug__: raise RuntimeError('optimized_python_refused')
CONFIG=CONFIGURATION
root=pathlib.Path('/var/lib/vprouter-v2-lab')
assert os.geteuid()==0
for path in (pathlib.Path('/'),pathlib.Path('/var'),pathlib.Path('/var/lib'),root):
 st=path.lstat();assert stat.S_ISDIR(st.st_mode) and st.st_uid==st.st_gid==0 and st.st_mode&0o022==0
assert stat.S_IMODE(root.stat().st_mode)==0o700

def regular(path,mode):
 st=path.lstat();assert stat.S_ISREG(st.st_mode) and st.st_uid==st.st_gid==0 and stat.S_IMODE(st.st_mode)==mode and st.st_nlink==1;return st

def create(path,data,mode=0o600):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
 with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
 regular(path,mode)

def run(argv):
 r=subprocess.run(argv,capture_output=True,text=True,check=True,timeout=8);assert len(r.stdout)<4*1024*1024;return r.stdout

def stable_host():
 links=json.loads(run(['ip','-j','-d','link','show']));keys=('ifindex','ifname','ifalias','mtu','flags','address','link_index')
 routes={}
 for family in ('-4','-6'):
  rows=json.loads(run(['ip','-j',family,'route','show','table','all']));routes[family]=sorted([{k:v for k,v in row.items() if k!='expires'} for row in rows],key=lambda row:json.dumps(row,sort_keys=True))
 return dict(links=sorted([{k:row[k] for k in keys if k in row} for row in links],key=lambda row:row['ifindex']),routes=routes)

regular(root/'isolated-acceptance',0o600)
admission_path=root/'task8b2-host-acceptance'
assert not admission_path.exists() and not admission_path.is_symlink(),'existing_admission_requires_review'
net=pathlib.Path('/proc/self/ns/net').stat();init=pathlib.Path('/proc/1/ns/net').stat()
assert (net.st_dev,net.st_ino)==(init.st_dev,init.st_ino)
admission=dict(artifact_sha256=CONFIG['artifact_sha256'],network_dev=net.st_dev,network_ino=net.st_ino)
before=stable_host()
payload=root/('secret-preparation-'+CONFIG['artifact_sha256']+'.payload')
if payload.exists():regular(payload,0o555);assert hashlib.sha256(payload.read_bytes()).hexdigest()==CONFIG['artifact_sha256']
else:
 uploaded=pathlib.Path('/home/vprouterlab')/('secret-preparation-'+CONFIG['artifact_sha256']);data=uploaded.read_bytes();assert hashlib.sha256(data).hexdigest()==CONFIG['artifact_sha256'];create(payload,data,0o555)
nonce_path=root/'owner-domain-nonce';configuration_path=root/'secret-preparation.json'
assert not nonce_path.exists() and not nonce_path.is_symlink() and not configuration_path.exists() and not configuration_path.is_symlink(),'existing_fixed_selector_requires_review'
nonce=secrets.token_hex(32);inputs=root/('secret-inputs-'+nonce);inputs.mkdir(mode=0o700)
ids=['a'+nonce[:12],'b'+nonce[:12]]
keys=[bytearray(secrets.token_bytes(32)),bytearray(secrets.token_bytes(32))]
def clamped(value):
 out=bytearray(value);out[0]&=248;out[31]&=127;out[31]|=64;return out
while clamped(keys[0])==clamped(keys[1]):keys[1][:]=secrets.token_bytes(32)
if CONFIG['mode']=='reject':keys[1][:]=keys[0]
exits=[];metadata=[]
for index,member in enumerate(ids):
 directory=inputs/member;directory.mkdir(mode=0o700);profile=directory/'de-fra-wg-404.conf'
 private=base64.b64encode(keys[index]).decode()
 text='[Interface]\nPrivateKey='+private+'\nAddress=10.64.0.2/32\nDNS=10.64.0.1\n[Peer]\nPublicKey=zo060cy2M+x7cMF4FKXHbs0CloUFDTRHRboFhw5YfVk=\nAllowedIPs=0.0.0.0/0\nEndpoint=185.66.0.1:51820\n'
 create(profile,text.encode());st=regular(profile,0o600)
 metadata.append(dict(member=member,path=str(profile),device=st.st_dev,inode=st.st_ino,size=st.st_size,mode=stat.S_IMODE(st.st_mode),uid=st.st_uid,gid=st.st_gid))
 exits.append(dict(id=member,enabled=index==0,state_dir=str(root/('owner-secret-'+nonce)/'state'/member),mode=dict(kind='mullvad',profile=str(profile),expected_server='de-fra-wg-404')))
for key in keys:key[:]=bytes(len(key))
del keys,private,text
configuration=dict(schema_version=2,deployment_id='secretlab-'+nonce[:12],site='debdev',gateway_image='sha256:'+'a'*64,exits=exits,dependency_adapters=[],client_policies=[])
public=json.dumps(configuration,sort_keys=True,separators=(',',':')).encode();create(inputs/'configuration.json',public);create(configuration_path,public);create(nonce_path,nonce.encode())
manifest=dict(schema=1,nonce=nonce,mode=CONFIG['mode'],configuration_sha256=hashlib.sha256(public).hexdigest(),profiles=metadata,synthetic_only=True,keys_created_outside_rust_parent=True,private_bytes_in_argv_environment_or_configuration=False,duplicate_private_input=CONFIG['mode']=='reject')
create(inputs/'input-manifest.json',json.dumps(manifest,sort_keys=True).encode());print(json.dumps({'secret_preparation_input':manifest}),flush=True)
descriptor=json.loads(run([str(payload),'--secret-preparation-descriptor']))
assert descriptor['schema_version']==1 and descriptor['nonce']==nonce and descriptor['deployment_id']==configuration['deployment_id'] and descriptor['primary']==ids[0]
assert descriptor['configuration']==str(configuration_path) and descriptor['profile_contents_read'] is descriptor['container_required'] is descriptor['network_mutations'] is False
unit=descriptor['owner_unit'];assert re.fullmatch('vprouter-v2-owner@[a-f0-9]{64}[.]service',unit)
assert run(['systemctl','show',unit,'--property=LoadState','--value']).strip()=='not-found'
output=root/('secret-preparation-'+nonce+'.stdout');diagnostic=root/('secret-preparation-'+nonce+'.stderr');create(output,b'');create(diagnostic,b'')
create(admission_path,json.dumps(admission,sort_keys=True).encode())
admission_identity=admission_path.stat()
print(json.dumps({'owner_probe':dict(unit=unit,nonce=nonce,mode='secret-preparation-'+CONFIG['mode'],component_only=True)}),flush=True)
argv=['systemd-run','--quiet','--wait','--collect','--service-type=exec','--property=StandardInput=null','--property=StandardOutput=file:'+str(output),'--property=StandardError=file:'+str(diagnostic),'--unit='+unit,'--property=Slice=system.slice','--property=KillMode=control-group','--property=KillSignal=SIGKILL','--property=TimeoutStopSec=3s','--property=RuntimeMaxSec=110s','--',str(payload),CONFIG['flag']]
result=subprocess.run(argv,capture_output=True,text=True,timeout=120)
regular(output,0o600);regular(diagnostic,0o600);stdout=output.read_bytes();stderr=diagnostic.read_bytes();assert len(stdout)<4*1024*1024 and len(stderr)<65536
print(stdout.decode(),end='',flush=True)
if stderr:os.write(2,stderr)
assert before==stable_host(),'unexpected_host_link_or_stable_route_change'
assert run(['systemctl','show',unit,'--property=LoadState','--value']).strip()=='not-found'
assert not (pathlib.Path('/sys/fs/cgroup/system.slice')/unit).exists()
current=regular(admission_path,0o600)
assert (current.st_dev,current.st_ino)==(admission_identity.st_dev,admission_identity.st_ino)
assert json.loads(admission_path.read_bytes())==admission
os.link(admission_path,inputs/'host-admission.json',follow_symlinks=False);admission_path.unlink()
fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
print(json.dumps({'secret_preparation_controller':dict(harness_exit_code=result.returncode,owner_unit_absent=True,host_links_and_stable_routes_unchanged=True,inputs_retained=str(inputs),synthetic_only=True,namespace_or_container_creation=False)}),flush=True)
if result.returncode==0:
 regular(nonce_path,0o600);assert nonce_path.read_text()==nonce;regular(configuration_path,0o600);assert configuration_path.read_bytes()==public
 os.link(nonce_path,inputs/'selected-nonce',follow_symlinks=False);nonce_path.unlink()
 os.link(configuration_path,inputs/'selected-configuration.json',follow_symlinks=False);configuration_path.unlink()
 fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
else:print(json.dumps({'secret_preparation_selectors_retained':True,'nonce':nonce,'reason':'failed_case_requires_exact_owner_child_and_selector_review'}),flush=True)
raise SystemExit(result.returncode)
