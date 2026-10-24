# Controller-only read-only Docker forwarding chain shape oracle in owned guest.
import os,pathlib,stat,subprocess,socket,struct,json,hashlib,datetime
base=pathlib.Path('/var/lib/vprouter-v2-lab')
for p in [pathlib.Path('/'),pathlib.Path('/var'),pathlib.Path('/var/lib'),base]:
 s=p.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022
s=(base/'isolated-acceptance').lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_gid==0 and s.st_nlink==1 and s.st_mode&0o7777==0o600
assert os.geteuid()==0
r=subprocess.run(['nft','-j','list','chain','ip','filter','FORWARD'],check=True,capture_output=True,text=True,timeout=3)
assert len(r.stdout.encode())<=65536
cli=json.loads(r.stdout)
def attr(t,b):
 v=struct.pack('HH',len(b)+4,t)+b
 return v+b'\0'*((-len(v))%4)
sock=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,12);sock.settimeout(2);sock.bind((0,0));port=sock.getsockname()[0];seq=17
payload=bytes([socket.AF_INET,0,0,0])+attr(1,b'filter\0')+attr(3,b'FORWARD\0')
sock.sendto(struct.pack('IHHII',16+len(payload),2564,5,seq,port)+payload,(0,0))
messages=[];ack=False
for _ in range(8):
 data,peer=sock.recvfrom(65536);assert peer[0]==0
 offset=0
 while offset<len(data):
  assert len(data)-offset>=16
  length,kind,flags,reply_seq,reply_port=struct.unpack_from('IHHII',data,offset)
  assert length>=16 and offset+length<=len(data) and reply_seq==seq and reply_port in (0,port)
  value=data[offset+16:offset+length]
  if kind==2:
   assert len(value)>=4 and struct.unpack_from('i',value)[0]==0;ack=True
  else:
   assert kind==2563;messages.append({'type':kind,'flags':flags,'payload_hex':value.hex()})
  offset+=(length+3)&~3
 if ack and messages:break
assert ack and len(messages)==1
print(json.dumps({'observed_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'authority':'read_only_owned_guest_chain_shape_only','nft_chain':cli,'raw_chain_messages':messages,'raw_request_type':2564,'nft_stderr':r.stderr,'runtime_changes':False,'packet_acceptance':'NOT_RUN','source_sha256':hashlib.sha256(pathlib.Path('/dev/stdin').read_bytes()).hexdigest() if False else None},indent=2))
