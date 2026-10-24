# Test-only pinned Tailscale kernel metadata oracle. Run ONLY in the owned lab.
# Creates one network-none memory-state daemon; never reads an enrolled identity.
import subprocess,json,time,os,pathlib,stat
assert os.geteuid()==0, 'root_required'
for part in ['/', '/var', '/var/lib', '/var/lib/vprouter-v2-lab']:
 st=pathlib.Path(part).lstat()
 assert stat.S_ISDIR(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022, 'untrusted_lab_parent'
st=pathlib.Path('/var/lib/vprouter-v2-lab/isolated-acceptance').lstat()
assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_gid==0 and stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1, 'lab_marker_required'
image='tailscale/tailscale@sha256:c507f3a2a6ab1cabd8d809b98edeb41edbd5c3fb6ad9632ffd098b4c7d0b4065'
name='vprouter-v2-kernel-rule-oracle-1'
label='io.vprouter.oracle=kernel-rule-1'
def call(args,**kw):return subprocess.run(args,capture_output=True,text=True,timeout=8,check=True,**kw).stdout
assert not call(['docker','ps','-a','--filter','name=^/'+name+'$','--format','{{.ID}}']).strip()
cid=call(['docker','run','-d','--name',name,'--label',label,'--network','none','--read-only','--cap-drop','ALL','--cap-add','NET_ADMIN','--security-opt','no-new-privileges','--device','/dev/net/tun:/dev/net/tun','--tmpfs','/tmp:rw,nosuid,nodev,noexec,mode=0700,size=16m','--log-driver','none','--entrypoint','/usr/local/bin/tailscaled',image,'--state=mem:','--statedir=/tmp/state','--socket=/tmp/tailscaled.sock','--tun=tailscale0']).strip()
assert len(cid)==64 and all(c in '0123456789abcdef' for c in cid)
out={'image':image,'container':cid,'state':'mem:','network':'none','credential_or_identity_state_used':False,'advertised_exit':False,'production_changes':False}
raw_code='''import socket,struct,json
s=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,socket.NETLINK_ROUTE);s.settimeout(2);s.bind((0,0));s.send(struct.pack("IHHII",28,34,0x301,1,0)+bytes(12));rows=[];done=False;total=0
while not done:
 b=s.recv(65536);total+=len(b);assert total<262144
 while b:
  n,t,f,q,p=struct.unpack_from("IHHII",b);assert 16<=n<=len(b) and q==1
  if t==3:done=True
  elif t==2:raise RuntimeError("netlink_error")
  else:assert t==32;rows.append({"type":t,"flags":f,"payload_hex":b[16:n].hex()})
  b=b[(n+3)&~3:]
print(json.dumps(rows))'''
try:
 for _ in range(30):
  meta=json.loads(call(['docker','inspect',cid]))[0]
  assert meta['State']['Running']
  probe=subprocess.run(['docker','exec',cid,'/usr/local/bin/tailscale','--socket=/tmp/tailscaled.sock','debug','prefs'],capture_output=True,text=True,timeout=3)
  if probe.returncode==0:break
  time.sleep(.1)
 assert probe.returncode==0,'socket_not_ready'
 pid=meta['State']['Pid'];assert pid>1
 def projection():
  result={}
  for kind in ['link','address']:
   result[kind]=json.loads(call(['nsenter','--target',str(pid),'--net','ip','-details','-json',kind,'show']))
  for family in ['-4','-6']:
   result[family]={}
   for kind in ['rule','route']:
    args=['nsenter','--target',str(pid),'--net','ip',family,'-details','-json',kind,'show']
    if kind=='route':args+=['table','all']
    result[family][kind]=json.loads(call(args))
  result['raw_rules']=json.loads(call(['nsenter','--target',str(pid),'--net','python3','-c',raw_code]))
  return result
 prefs=json.loads(probe.stdout)
 out['before']={'prefs':{k:prefs.get(k) for k in ['WantRunning','AdvertiseRoutes','NetfilterMode','RouteAll','ExitNodeID','ExitNodeIP']},'kernel':projection()}
 # Explicit mode setup only: no up, no authentication, no advertised routes.
 call(['docker','exec',cid,'/usr/local/bin/tailscale','--socket=/tmp/tailscaled.sock','set','--netfilter-mode=off','--accept-dns=false','--accept-routes=false'])
 prefs=json.loads(call(['docker','exec',cid,'/usr/local/bin/tailscale','--socket=/tmp/tailscaled.sock','debug','prefs']))
 out['after_mode_off']={'prefs':{k:prefs.get(k) for k in ['WantRunning','AdvertiseRoutes','NetfilterMode','RouteAll','ExitNodeID','ExitNodeIP']},'kernel':projection()}
 for phase in ['before','after_mode_off']:
  k=out[phase]['kernel'];assert {l['ifname'] for l in k['link']}<= {'lo','tailscale0'}
  assert all(r.get('dst')!='default' for fam in ['-4','-6'] for r in k[fam]['route'])
  assert not out[phase]['prefs']['AdvertiseRoutes']
 out['result']='PASS_SHAPE_ORACLE_ONLY'
finally:
 meta=json.loads(call(['docker','inspect',cid]))[0]
 assert meta['Name']=='/'+name and meta['Config']['Labels'].get('io.vprouter.oracle')=='kernel-rule-1' and meta['Config']['Image']==image
 call(['docker','rm','-f',cid]);assert not call(['docker','ps','-a','--filter','label='+label,'--format','{{.ID}}']).strip()
 out['cleanup_exact_container_absent']=True
print(json.dumps(out,indent=2))
