import pathlib,subprocess,json
repo=pathlib.Path.cwd();base=repo/'target/lab-state'
argv=['ssh','-i',str(base/'id_ed25519'),'-o','IdentitiesOnly=yes','-o','UserKnownHostsFile='+str(base/'known_hosts'),'-o','StrictHostKeyChecking=yes','-p22032','vprouterlab@127.0.0.1','sudo python3 -']
guest=r'''
import pathlib,subprocess,json,os,stat,tarfile,datetime,time
root=pathlib.Path('/var/lib/vprouter-v2-lab');name='vprouter-v2-lab-primary-enrollment'
expected_id='b6ef3d7e8b772fce99595e35a35be0194ec12c18920183efeb3c9a0112934f0d'
expected_node='n8P8U86ryZ11CNTRL';expected_ips={'100.101.230.31','fd7a:115c:a1e0::9438:e621'}
state=root/'gateway-primary'
def call(args,timeout=15):
 r=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
 assert r.returncode==0,('fixed_lab_command_failed',args[:2],r.returncode)
 return r.stdout
def metadata(container):return json.loads(call(['docker','inspect',container]))[0]
def status(container):
 j=json.loads(call(['docker','exec',container,'/usr/local/bin/tailscale','status','--json']))
 n=j['Self'];assert n['ID']==expected_node and set(n['TailscaleIPs'])==expected_ips
 assert not n['ExitNodeOption']
 return {'backend':j['BackendState'],'node_id':n['ID'],'ips':n['TailscaleIPs'],'online':n['Online'],'exit_node_option':n['ExitNodeOption']}
assert os.geteuid()==0 and stat.S_IMODE(root.stat().st_mode)==0o700
old=metadata(name)
assert old['Id']==expected_id and old['Config']['Labels'].get('io.vprouter.lab')=='enrollment-only'
assert old['Config']['Image']=='tailscale/tailscale@sha256:c507f3a2a6ab1cabd8d809b98edeb41edbd5c3fb6ad9632ffd098b4c7d0b4065'
assert old['State']['Running'] and old['Path']=='/usr/local/bin/tailscaled' and '--tun=userspace-networking' in old['Args']
assert [{'source':m['Source'],'destination':m['Destination']} for m in old['Mounts']]==[{'source':str(state),'destination':'/var/lib/tailscale'}]
before=status(name);assert before['backend']=='Running'
output=root/'approved-kernel-metadata-20261026';output.mkdir(mode=0o700)
call(['docker','stop','--time','10',expected_id],20)
assert not metadata(expected_id)['State']['Running'] and metadata(expected_id)['State']['Pid']==0
group=pathlib.Path('/sys/fs/cgroup/system.slice/docker-'+expected_id+'.scope/cgroup.procs')
assert not group.exists() or not group.read_text().strip()
for container in call(['docker','ps','-q']).splitlines():
 mounts=json.loads(call(['docker','inspect','--format','{{json .Mounts}}',container]))
 assert all(m['Source']!=str(state) for m in mounts),'another_running_identity_mount'
backup=output/'stopped-state-backup.tar'
with backup.open('xb') as stream:
 os.fchmod(stream.fileno(),0o600)
 with tarfile.open(fileobj=stream,mode='w') as tar:tar.add(state,arcname='gateway-primary',recursive=True)
config={'version':'alpha0','locked':True,'enabled':True,'acceptDNS':False,'acceptRoutes':False,'advertiseRoutes':[],'advertiseExitNode':False,'disableSNAT':True,'netfilterMode':'off','noStatefulFiltering':True,'runSSHServer':False,'runWebClient':False,'remoteConfig':False,'autoUpdate':{'Check':False,'Apply':False}}
config_path=output/'metadata-config.json';config_path.write_text(json.dumps(config));config_path.chmod(0o600)
saved_name='vprouter-v2-lab-primary-userspace-before-kernel-20261026'
call(['docker','rename',expected_id,saved_name])
new=call(['docker','run','--detach','--name',name,'--read-only','--cap-drop','ALL','--cap-add','NET_ADMIN','--security-opt','no-new-privileges','--device','/dev/net/tun:/dev/net/tun:rwm','--log-driver','none','--label','io.vprouter.lab=approved-kernel-metadata','--label','io.vprouter.previous-container='+expected_id,'--volume',str(state)+':/var/lib/tailscale','--volume',str(config_path)+':/etc/tailscale-metadata.json:ro','--tmpfs','/run:rw,nosuid,nodev,noexec,size=16m','--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=16m','--entrypoint','/usr/local/bin/tailscaled',old['Config']['Image'],'--tun=tailscale0','--statedir=/var/lib/tailscale','--socket=/run/tailscale/tailscaled.sock','--config=/etc/tailscale-metadata.json']).strip()
end=time.monotonic()+20
while True:
 try:
  after=status(new)
  if after['backend']=='Running' and after['online']:break
 except (AssertionError,KeyError):pass
 assert time.monotonic()<end,'kernel_gateway_did_not_recover_same_identity'
 time.sleep(.2)
j=metadata(new);pid=j['State']['Pid'];assert pid>0
fd=os.open(f'/proc/{pid}/ns/net',os.O_RDONLY|os.O_CLOEXEC)
prefix=['nsenter',f'--net=/proc/self/fd/{fd}']
observations={}
for key,args in [('links',['-d','-j','link']),('addresses',['-j','address']),('routes4',['-j','-4','route','show','table','all']),('routes6',['-j','-6','route','show','table','all']),('rules4',['-j','-4','rule']),('rules6',['-j','-6','rule']),('nft',['nft','-j','list','ruleset'])]:
 command=[*prefix,'ip',*args] if key!='nft' else [*prefix,*args]
 r=subprocess.run(command,pass_fds=[fd],capture_output=True,text=True,timeout=8);assert r.returncode==0,key
 observations[key]=json.loads(r.stdout)
prefs=json.loads(call(['docker','exec',new,'/usr/local/bin/tailscale','debug','prefs']))
public_prefs={key:prefs.get(key) for key in ['WantRunning','RouteAll','CorpDNS','AdvertiseRoutes','NetfilterMode','NoSNAT','NoStatefulFiltering','RunSSH','ExitNodeID','ExitNodeIP']}
assert not public_prefs['AdvertiseRoutes'] and public_prefs['NetfilterMode']==0 and not public_prefs['RunSSH']
result={'scope':'approved_local_gateway_kernel_metadata_only','observed_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'old_container':expected_id,'stopped_old_retained_as':saved_name,'new_container':new,'identity_before':before,'identity_after':after,'same_identity':True,'old_identity_users_stopped_before_new_start':True,'stopped_state_backup_private':True,'state_path_preserved':True,'no_enrollment_or_reset':True,'no_exit_advertisement':True,'protected_workloads':False,'production_changes':False,'kernel_metadata':observations,'prefs':public_prefs,'namespace':{'dev':os.fstat(fd).st_dev,'ino':os.fstat(fd).st_ino},'client_destinations':['100.120.226.13'],'runtime_acceptance':'NOT_RUN'}
(output/'metadata.json').write_text(json.dumps(result,indent=2)+chr(10));(output/'metadata.json').chmod(0o600)
print(json.dumps(result))
'''
result=subprocess.run(argv,input=guest,text=True,capture_output=True,timeout=80)
output=repo/'.superpowers/sdd/implementation-2026-10-26/approved-kernel-shape.json'
if result.returncode:
 print(result.stderr[-2500:]);raise SystemExit(result.returncode)
output.write_text(json.dumps(json.loads(result.stdout),indent=2)+chr(10))
print(str(output))
