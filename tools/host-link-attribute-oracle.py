import socket,struct,json,datetime,os
assert os.geteuid()==0
s=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,0);s.settimeout(2);s.bind((0,0));port=s.getsockname()[0]
payload=bytes(16);s.sendto(struct.pack('IHHII',32,18,0x301,71,port)+payload,(0,0))
def attrs(b):
 a=[]
 while b:
  assert len(b)>=4;n,t=struct.unpack_from('HH',b);assert 4<=n<=len(b)
  v=b[4:n];entry={'kind':t,'kind_masked':t&0x3fff,'value_len':len(v)}
  if (t&0x3fff)in[3,6,20,38,53,55,56]:entry['text']=v.rstrip(b'\0').decode(errors='replace')
  if (t&0x3fff)in[10,16,30,61]and len(v)==4:entry['number']=struct.unpack('I',v)[0]
  if t&0x8000:entry['nested']=attrs(v)
  if (t&0x3fff)==18:entry['linkinfo']=attrs(v)
  a.append(entry);b=b[(n+3)&~3:]
 return a
out=[];done=False;total=0
while not done:
 data,peer=s.recvfrom(65536);assert peer[0]==0;total+=len(data);assert total<1048576
 while data:
  n,t,flags,q,p=struct.unpack_from('IHHII',data);assert 16<=n<=len(data) and q==71
  value=data[16:n]
  if t==3:done=True
  elif t==2:assert struct.unpack_from('i',value)[0]==0
  else:
   assert t==16 and len(value)>=16
   fam,_,typ,index,iflags,change=struct.unpack_from('BBHiII',value)
   out.append({'index':index,'type':typ,'flags':iflags,'attributes':attrs(value[16:])})
  data=data[(n+3)&~3:]
print(json.dumps({'observed_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'read_only':True,'links':out},indent=2))
