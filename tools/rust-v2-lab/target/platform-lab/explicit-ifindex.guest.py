"""Root-only disposable SRC/DST network namespace kernel contract probe."""
import array,ctypes,fcntl,hashlib,json,os,pathlib,socket,stat,struct,subprocess,sys
assert os.geteuid()==0
libc=ctypes.CDLL(None,use_errno=True)
CLONE_NEWNET=0x40000000
host_fd=os.open('/proc/self/ns/net',os.O_RDONLY|os.O_CLOEXEC)
host_identity=os.fstat(host_fd).st_ino

def run(argv):
 r=subprocess.run(argv,capture_output=True,text=True,timeout=8,check=True);assert len(r.stdout)<4*1024*1024;return json.loads(r.stdout)
def host_shape():
 links=run(['ip','-j','-d','link','show'])
 keys=('ifindex','ifname','ifalias','mtu','flags','address','link_index')
 return dict(links=sorted([{k:v[k] for k in keys if k in v} for v in links],key=lambda v:v['ifindex']),routes4=run(['ip','-j','-4','route','show','table','all']),routes6=run(['ip','-j','-6','route','show','table','all']))
before_host=host_shape()
def make_namespace():
 parent,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET|socket.SOCK_CLOEXEC)
 creator=os.getpid();pid=os.fork()
 if pid==0:
  parent.close()
  if libc.prctl(1,9,0,0,0)!=0 or os.getppid()!=creator or libc.unshare(CLONE_NEWNET)!=0:os._exit(81)
  fd=os.open('/proc/self/ns/net',os.O_RDONLY|os.O_CLOEXEC)
  start=int(pathlib.Path('/proc/self/stat').read_text().rsplit(') ',1)[1].split()[19])
  child.sendmsg([json.dumps({'pid':os.getpid(),'start':start}).encode()],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]))]);os.close(fd);child.close();os._exit(0)
 child.close();parent.settimeout(5);data,anc,flags,_=parent.recvmsg(1024,socket.CMSG_SPACE(4),socket.MSG_CMSG_CLOEXEC)
 assert flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC)==0 and len(anc)==1 and anc[0][:2]==(socket.SOL_SOCKET,socket.SCM_RIGHTS)
 fds=array.array('i');fds.frombytes(anc[0][2]);assert len(fds)==1
 fd=fds[0];identity=os.fstat(fd).st_ino;birth=json.loads(data);assert birth['pid']==pid
 assert os.waitpid(pid,0)==(pid,0) and fcntl.ioctl(fd,0xb703)==CLONE_NEWNET
 parent.close();return fd,dict(identity=identity,creator_pid=pid,creator_start=birth['start'],actual_parent_wait_status=0)
src,src_record=make_namespace();dst,dst_record=make_namespace();assert len({host_identity,src_record['identity'],dst_record['identity']})==3
INNER=r'''
import json,os,pathlib,socket,struct,subprocess
assert pathlib.Path('/proc/self/ns/net').stat().st_ino==EXPECTED_NAMESPACE
COMMAND=COMMAND_VALUE
DESTINATION_FD=DESTINATION_VALUE

def ip(*args):
 r=subprocess.run(['ip',*args],capture_output=True,text=True,timeout=5,check=True);return r.stdout

def attrs(data):
 out=[];offset=0
 while offset<len(data):
  assert len(data)-offset>=4
  size,kind=struct.unpack_from('=HH',data,offset);assert size>=4 and offset+size<=len(data)
  out.append((kind,data[offset+4:offset+size]));offset+=(size+3)&~3
 assert offset==len(data) and len(out)<=256
 return out

def scalar(values,kind,fmt,default=None):
 found=[v for k,v in values if k==kind]
 if not found:return default
 assert len(found)==1 and len(found[0])==struct.calcsize(fmt)
 return struct.unpack(fmt,found[0])[0]
def string(values,kind,default=''):
 found=[v for k,v in values if k==kind]
 if not found:return default
 assert len(found)==1 and 0<len(found[0])<=256 and found[0][-1]==0
 return found[0][:-1].decode()
def links():
 s=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW|socket.SOCK_CLOEXEC,socket.NETLINK_ROUTE);s.settimeout(3);s.bind((0,0));sequence=37
 payload=struct.pack('=BBHiII',0,0,0,0,0,0);s.sendto(struct.pack('=IHHII',16+len(payload),18,0x301,sequence,0)+payload,(0,0));out=[];done=False
 while not done:
  data,peer=s.recvfrom(1024*1024);assert peer[0]==0;offset=0
  while offset<len(data):
   length,kind,flags,seq,pid=struct.unpack_from('=IHHII',data,offset);assert 16<=length<=len(data)-offset and seq==sequence and not flags&0x10
   body=data[offset+16:offset+length];offset+=(length+3)&~3
   if kind==3:done=True;continue
   if kind==2:assert struct.unpack_from('=i',body)[0]==0;continue
   assert kind==16 and len(body)>=16
   family,pad,hardware,index,linkflags,change=struct.unpack_from('=BBHiII',body);values=attrs(body[16:]);info=next((attrs(v) for k,v in values if k&0x3fff==18),[])
   out.append(dict(name=string(values,3),index=index,kind=string(info,1),up=bool(linkflags&1),raw_flags=linkflags,mtu=scalar(values,4,'=I',0),alias=string(values,20),peer_index=scalar(values,5,'=I'),hardware_type=hardware,controller=scalar(values,10,'=I',0),port_kind=string(info,4),promiscuity=scalar(values,30,'=I',0),all_multicast=scalar(values,61,'=I',0),alternate_names=[v[:-1].decode() for k,v in next((attrs(v) for k,v in values if k&0x3fff==52),[]) if k&0x3fff==53],tun_info=[],max_pacing_offload_horizon=scalar(values,66,'=I'),headroom=scalar(values,68,'=H'),tailroom=scalar(values,69,'=H'),mac=next((v.hex(':') for k,v in values if k==1),''),link_netnsid=scalar(values,37,'=i'),attribute_inventory=[(k,len(v)) for k,v in values]))
 s.close();return sorted(out,key=lambda v:v['index'])
def snapshot():
 return dict(namespace=EXPECTED_NAMESPACE,links=links(),addresses=json.loads(ip('-j','address','show')),routes4=json.loads(ip('-j','-4','route','show','table','all')),routes6=json.loads(ip('-j','-6','route','show','table','all')))
if COMMAND['operation']=='pair':
 number=COMMAND['number'];host='vph'+str(number);peer='vpp'+str(number)
 ip('link','add',host,'mtu','1420','address','02:00:00:00:0'+str(number)+':10','type','veth','peer','name',peer,'mtu','1420','address','02:00:00:00:0'+str(number)+':11')
 ip('link','set','dev',host,'alias','vprouter-probe-pair'+str(number)+'-host');ip('link','set','dev',peer,'alias','vprouter-probe-pair'+str(number)+'-peer')
 print(json.dumps(snapshot()))
elif COMMAND['operation']=='dummy':
 name=COMMAND.get('name','occupied');ip('link','add',name,'index',str(COMMAND['index']),'type','dummy');ip('link','set','dev',name,'alias','vprouter-probe-'+name)
 print(json.dumps(snapshot()))
elif COMMAND['operation']=='move':
 index=COMMAND['source_index'];wanted=COMMAND['wanted_index'];s=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW|socket.SOCK_CLOEXEC,socket.NETLINK_ROUTE);s.bind((0,0));s.settimeout(3)
 def nla(kind,value):
  size=4+len(value);return struct.pack('=HH',size,kind)+value+b'\0'*((-size)%4)
 payload=struct.pack('=BBHiII',0,0,0,index,0,0)+nla(28,struct.pack('=i',DESTINATION_FD))+nla(49,struct.pack('=I',wanted));s.sendto(struct.pack('=IHHII',16+len(payload),16,5,41,0)+payload,(0,0))
 data,peer=s.recvfrom(65536);length,kind,flags,seq,pid=struct.unpack_from('=IHHII',data);assert peer[0]==0 and kind==2 and seq==41 and length<=len(data)
 error=struct.unpack_from('=i',data,16)[0];s.close();print(json.dumps(dict(native_ack_errno=-error,request_type=16,request_flags=5,source_index=index,wanted_index=wanted,source_snapshot=snapshot())))
else:assert COMMAND['operation']=='snapshot';print(json.dumps(snapshot()))
'''
def invoke(fd,identity,command):
 source=INNER.replace('EXPECTED_NAMESPACE',str(identity)).replace('COMMAND_VALUE',repr(command)).replace('DESTINATION_VALUE',str(dst))
 r=subprocess.run(['nsenter','--net=/proc/self/fd/'+str(fd),'--','python3','-I','-'],input=source,capture_output=True,text=True,pass_fds=(src,dst),timeout=15)
 assert r.returncode==0,r.stderr;assert len(r.stdout)<1024*1024;return json.loads(r.stdout)
def phase(name,value):print(json.dumps({'probe_phase':name,'value':value}),flush=True)
def named(snapshot,name):return next(v for v in snapshot['links'] if v['name']==name)
def check_down(snapshot):
 for v in snapshot['links']:
  if v['name']!='lo':assert not v['up']
 for v in snapshot['addresses']:
  if v['ifname']!='lo':assert v.get('addr_info',[])==[]
first=invoke(src,src_record['identity'],dict(operation='pair',number=0));check_down(first);host=named(first,'vph0');peer=named(first,'vpp0');assert host['peer_index']==peer['index'] and peer['peer_index']==host['index'];phase('first_pair_before',first)
move=invoke(src,src_record['identity'],dict(operation='move',source_index=host['index'],wanted_index=100001));phase('successful_move_ack',move);assert move['native_ack_errno']==0
src_after=invoke(src,src_record['identity'],dict(operation='snapshot'));dst_after=invoke(dst,dst_record['identity'],dict(operation='snapshot'));check_down(src_after);check_down(dst_after);phase('successful_move_src',src_after);phase('successful_move_dst',dst_after)
moved=named(dst_after,'vph0');assert moved['index']==100001 and moved['name']==host['name'] and moved['alias']==host['alias'] and moved['mtu']==host['mtu']==1420 and moved['mac']==host['mac'] and moved['peer_index']==peer['index'] and not moved['up'];assert named(src_after,'vpp0')['peer_index']==100001
second=invoke(src,src_record['identity'],dict(operation='pair',number=1));occupied=invoke(dst,dst_record['identity'],dict(operation='dummy',index=100003));check_down(second);check_down(occupied);phase('collision_src_before',second);phase('collision_dst_before',occupied)
collision=invoke(src,src_record['identity'],dict(operation='move',source_index=named(second,'vph1')['index'],wanted_index=100003));phase('collision_move_ack',collision)
collision_src=invoke(src,src_record['identity'],dict(operation='snapshot'));collision_dst=invoke(dst,dst_record['identity'],dict(operation='snapshot'));phase('collision_src_after',collision_src);phase('collision_dst_after',collision_dst)
assert collision['native_ack_errno'] in (16,17) and collision_src==second and collision_dst==occupied
third=invoke(src,src_record['identity'],dict(operation='pair',number=2));name_occupied=invoke(dst,dst_record['identity'],dict(operation='dummy',index=100005,name='vph2'));phase('name_collision_src_before',third);phase('name_collision_dst_before',name_occupied)
name_collision=invoke(src,src_record['identity'],dict(operation='move',source_index=named(third,'vph2')['index'],wanted_index=100007));phase('name_collision_ack',name_collision)
name_src_after=invoke(src,src_record['identity'],dict(operation='snapshot'));name_dst_after=invoke(dst,dst_record['identity'],dict(operation='snapshot'));phase('name_collision_src_after',name_src_after);phase('name_collision_dst_after',name_dst_after)
assert name_collision['native_ack_errno'] in (16,17) and name_src_after==third and name_dst_after==name_occupied
after_host=host_shape();phase('host_before',before_host);phase('host_after',after_host);phase('host_namespace_after',pathlib.Path('/proc/self/ns/net').stat().st_ino)
def stable_host(value):
 return dict(links=value['links'],routes4=sorted([{k:v for k,v in r.items() if k!='expires'} for r in value['routes4']],key=lambda r:json.dumps(r,sort_keys=True)),routes6=sorted([{k:v for k,v in r.items() if k!='expires'} for r in value['routes6']],key=lambda r:json.dumps(r,sort_keys=True)))
assert stable_host(before_host)==stable_host(after_host) and pathlib.Path('/proc/self/ns/net').stat().st_ino==host_identity
result=dict(kernel=os.uname().release,machine=os.uname().machine,host_namespace=host_identity,src=src_record,dst=dst_record,requested_index_preserved=True,occupied_index_refused_errno=collision['native_ack_errno'],occupied_name_refused_errno=name_collision['native_ack_errno'],requested_eexist_observed=collision['native_ack_errno']==17,failed_move_left_source_and_destination_unchanged=True,down_unaddressed=True,host_link_and_stable_route_facts_unchanged=True,route_expiry_countdown_only_excluded_from_comparison=True,netlink_request_flags='REQUEST|ACK (no CREATE/REPLACE)',runtime_authority=False,reservation=False,provider_profiles_used=False,limit='Disposable detached namespace kernel contract only. Index is not a reservation. No runtime ownership, role-filter, mutation policy, provider/client or release acceptance.')
phase('PASS',result)
os.close(src);os.close(dst);os.close(host_fd)
