"""Root-only kernel characterization using PID1's native PIDFDs scope path.

Retain all results. No product execution, providers, identity or cleanup grants.
Scope-name absence is never the predicate. The independent known grandchild is
an observed native pidfd, not a new parent/reaping capability.
"""
import datetime
import hashlib
import json
import pathlib
import subprocess
import sys
import uuid


platform = sys.argv[1] if len(sys.argv) > 1 else "debian-x86_64"
port, known = {
    "debian-clean-x86_64": (22036, "target/platform-lab/debian-clean-x86_64/known_hosts"),
    "debian-x86_64": (22032, "target/lab-state/known_hosts"),
    "debian-arm64": (22034, "target/platform-lab/debian-arm64/known_hosts"),
    "arch-x86_64": (22033, "target/platform-lab/arch-x86_64/known_hosts"),
}[platform]
nonce = uuid.uuid4().hex
output = pathlib.Path("target/lab-state") / ("original-scope-pin-order-" + platform + "-" + nonce)
output.mkdir(mode=0o700)
guest = r'''
import array,ctypes,datetime,dbus,errno,json,os,pathlib,platform,select,socket,stat,subprocess,sys,time
assert os.geteuid()==0
root=pathlib.Path('/var/lib/vprouter-v2-lab')
assert stat.S_IMODE(root.stat().st_mode)==0o700
marker=(root/'isolated-acceptance').stat();assert marker.st_uid==marker.st_gid==0 and stat.S_IMODE(marker.st_mode)==0o600 and marker.st_nlink==1
directory=root/('original-scope-pin-'+nonce);directory.mkdir(mode=0o700)
events=(directory/'events.jsonl').open('x')
def event(value):
 events.write(json.dumps(value)+'\n');events.flush();os.fsync(events.fileno())
boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
ns={name:[os.stat('/proc/self/ns/'+name).st_dev,os.stat('/proc/self/ns/'+name).st_ino] for name in ['pid','mnt','net','user']}
assert ns=={name:[os.stat('/proc/1/ns/'+name).st_dev,os.stat('/proc/1/ns/'+name).st_ino] for name in ns}
bus=dbus.SystemBus();daemon=dbus.Interface(bus.get_object('org.freedesktop.DBus','/org/freedesktop/DBus',introspect=False),'org.freedesktop.DBus')
owner=str(daemon.GetNameOwner('org.freedesktop.systemd1'))
assert int(daemon.GetConnectionUnixProcessID(owner))==1 and int(daemon.GetConnectionUnixUser(owner))==0
manager=dbus.Interface(bus.get_object(owner,'/org/freedesktop/systemd1',introspect=False),'org.freedesktop.systemd1.Manager')
class Statfs(ctypes.Structure):
 _fields_=[('f_type',ctypes.c_long),('f_bsize',ctypes.c_long),('f_blocks',ctypes.c_ulong),('f_bfree',ctypes.c_ulong),('f_bavail',ctypes.c_ulong),('f_files',ctypes.c_ulong),('f_ffree',ctypes.c_ulong),('f_fsid',ctypes.c_int*2),('f_namelen',ctypes.c_long),('f_frsize',ctypes.c_long),('f_flags',ctypes.c_long),('f_spare',ctypes.c_long*4)]
assert ctypes.sizeof(Statfs)==120
libc=ctypes.CDLL(None,use_errno=True);libc.fstatfs.argtypes=[ctypes.c_int,ctypes.POINTER(Statfs)];libc.fstatfs.restype=ctypes.c_int
def fstatfs(fd):
 value=Statfs();result=libc.fstatfs(fd,ctypes.byref(value))
 if result:return dict(errno=ctypes.get_errno())
 return dict(type=value.f_type,type_hex=hex(value.f_type),fsid=list(value.f_fsid),flags=value.f_flags,block_size=value.f_bsize)
def fstat(fd):
 s=os.fstat(fd);return dict(dev=s.st_dev,ino=s.st_ino,mode=s.st_mode,nlink=s.st_nlink,uid=s.st_uid,gid=s.st_gid)
def identity(pid):
 raw=pathlib.Path('/proc',str(pid),'stat').read_text();fields=raw[raw.rfind(')')+2:].split();return dict(pid=pid,start=int(fields[19]),state=fields[0])
def readfd(fd):
 try:
  os.lseek(fd,0,os.SEEK_SET);value=os.read(fd,8193);assert len(value)<=8192
  return dict(value=value.decode())
 except OSError as e:return dict(errno=e.errno,error=errno.errorcode.get(e.errno,'UNKNOWN'))
def preadfd(fd):
 try:
  value=os.pread(fd,8193,0);assert len(value)<=8192
  return dict(value=value.decode())
 except OSError as e:return dict(errno=e.errno,error=errno.errorcode.get(e.errno,'UNKNOWN'))
def open_read(group,name):
 try:
  fd=os.open(name,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=group)
  try:return readfd(fd)
  finally:os.close(fd)
 except OSError as e:return dict(errno=e.errno,error=errno.errorcode.get(e.errno,'UNKNOWN'))
def sample(stage,group,pins,original):
 value=dict(stage=stage,boottime_ns=time.clock_gettime_ns(time.CLOCK_BOOTTIME),directory=fstat(group),fstatfs=fstatfs(group),kernel_fd_link=os.readlink('/proc/self/fd/'+str(group)),openat_same_directory={name:open_read(group,name) for name in ['cgroup.events','cgroup.procs']},retained_file_reads={name:readfd(fd) for name,fd in pins.items()},retained_file_pread_zero={name:preadfd(fd) for name,fd in pins.items()},retained_file_native={name:dict(fstat=fstat(fd),fstatfs=fstatfs(fd),kernel_fd_link=os.readlink('/proc/self/fd/'+str(fd))) for name,fd in pins.items()})
 assert (value['directory']['dev'],value['directory']['ino'])==original
 if 'type' in value['fstatfs']:assert value['fstatfs']['type']==0x63677270
 event(value);return value
def owner_unchanged():
 assert str(daemon.GetNameOwner('org.freedesktop.systemd1'))==owner and int(daemon.GetConnectionUnixProcessID(owner))==1
child_source=r"""
import array,json,os,pathlib,socket,subprocess,sys
control=socket.socket(fileno=int(sys.argv[1]));grand_gate=int(sys.argv[2])
def ident(pid):
 raw=pathlib.Path('/proc',str(pid),'stat').read_text();v=raw[raw.rfind(')')+2:].split();return {'pid':pid,'start':int(v[19])}
control.send(json.dumps(dict(kind='ready',**ident(os.getpid()))).encode())
command=control.recv(1)
if command==b'B':
 code='import os; os.read('+str(grand_gate)+',1)'
 grand=subprocess.Popen([sys.executable,'-I','-c',code],pass_fds=(grand_gate,),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 pin=os.pidfd_open(grand.pid,0)
 control.sendmsg([json.dumps(dict(kind='grandchild',**ident(grand.pid))).encode()],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[pin]))])
 os.close(pin);command=control.recv(1)
assert command==b'X'
os._exit(0)
"""
results=[]
for descendants in [False,True]:
 label='descendant' if descendants else 'solo';unit='vprouter-v2-'+__import__('hashlib').sha256(nonce.encode()).hexdigest()+'-'+__import__('hashlib').sha256((nonce+label).encode()).hexdigest()+'-expiry-host.scope'
 parent,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET|socket.SOCK_CLOEXEC);parent.settimeout(5)
 gate_read,gate_write=os.pipe2(os.O_CLOEXEC)
 diagnostic=(directory/(label+'.child.stderr')).open('xb')
 process=subprocess.Popen([sys.executable,'-I','-c',child_source,str(child.fileno()),str(gate_read)],pass_fds=(child.fileno(),gate_read),stdout=subprocess.DEVNULL,stderr=diagnostic)
 child.close();os.close(gate_read);pidfd=os.pidfd_open(process.pid,0)
 first=identity(process.pid);ready=json.loads(parent.recv(8192));assert ready==dict(kind='ready',pid=process.pid,start=first['start'])
 event(dict(stage='native_child_birth_before_placement',unit=unit,identity=first,native_pidfd_retained=True))
 properties=dbus.Array([
 ('Description',dbus.String('vprouter-v2 isolated lifecycle',variant_level=1)),
 ('PIDFDs',dbus.Array([dbus.types.UnixFd(pidfd)],signature='h',variant_level=1)),
 ('Slice',dbus.String('system.slice',variant_level=1)),('Delegate',dbus.Boolean(False,variant_level=1)),
 ('KillMode',dbus.String('control-group',variant_level=1)),('KillSignal',dbus.Int32(9,variant_level=1)),
 ('TimeoutStopUSec',dbus.UInt64(2000000,variant_level=1)),('SendSIGHUP',dbus.Boolean(False,variant_level=1)),('SendSIGKILL',dbus.Boolean(True,variant_level=1))],signature='(sv)')
 job=manager.StartTransientUnit(dbus.String(unit),dbus.String('fail'),properties,dbus.Array([],signature='(sa(sv))'),timeout=2)
 path=manager.GetUnit(unit,timeout=2);props=dbus.Interface(bus.get_object(owner,path,introspect=False),'org.freedesktop.DBus.Properties')
 end=time.monotonic()+2
 while True:
  u=props.GetAll('org.freedesktop.systemd1.Unit',timeout=2)
  if str(u['ActiveState'])=='active':break
  assert str(u['ActiveState'])!='failed' and time.monotonic()<end;time.sleep(0.005)
 scope=props.GetAll('org.freedesktop.systemd1.Scope',timeout=2)
 assert bool(u['Transient']) and str(u['Id'])==unit and not u['BindsTo'] and not u['PartOf'] and str(scope['Slice'])=='system.slice' and str(scope['ControlGroup'])=='/system.slice/'+unit
 assert not bool(scope['Delegate']) and str(scope['KillMode'])=='control-group' and int(scope['KillSignal'])==9 and int(scope['TimeoutStopUSec'])==2000000 and not bool(scope['SendSIGHUP']) and bool(scope['SendSIGKILL'])
 invocation=bytes(u['InvocationID']).hex();assert len(invocation)==32 and set(invocation)!={'0'}
 assert identity(process.pid)['start']==first['start'] and pathlib.Path('/proc',str(process.pid),'cgroup').read_text()=='0::/system.slice/'+unit+'\n'
 owner_unchanged()
 group=os.open('/sys/fs/cgroup/system.slice/'+unit,os.O_PATH|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW)
 initial=fstat(group);original=(initial['dev'],initial['ino']);assert initial['nlink']>0
 pins={name:os.open(name,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=group) for name in ['cgroup.events','cgroup.procs']}
 live=sample(label+'_live_before_release',group,pins,original);assert live['openat_same_directory']['cgroup.procs']['value'].split()==[str(process.pid)] and 'populated 1\n' in live['openat_same_directory']['cgroup.events']['value']
 grand=None;grand_pin=None
 if descendants:
  parent.send(b'B');data,ancillary,flags,_=parent.recvmsg(8192,socket.CMSG_SPACE(4),socket.MSG_CMSG_CLOEXEC)
  event(dict(stage='private_factory_grandchild_packet_received',data=json.loads(data),received_flags=flags,ancillary_count=len(ancillary)))
  assert flags&~socket.MSG_CMSG_CLOEXEC==0 and len(ancillary)==1
  level,kind,received=ancillary[0];assert level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS
  received_fds=array.array('i');received_fds.frombytes(received);assert len(received_fds)==1;grand_pin=received_fds[0]
  assert not os.get_inheritable(grand_pin)
  grand=json.loads(data);assert set(grand)=={'kind','pid','start'} and grand['kind']=='grandchild'
  assert identity(grand['pid'])['start']==grand['start'] and pathlib.Path('/proc',str(grand['pid']),'cgroup').read_text()=='0::/system.slice/'+unit+'\n'
  fdinfo=pathlib.Path('/proc/self/fdinfo',str(grand_pin)).read_text();assert ('Pid:\t'+str(grand['pid'])+'\n') in fdinfo
  event(dict(stage='known_factory_grandchild_pidfd_received_no_reap_authority',identity=grand))
 parent.send(b'X');status=process.wait(timeout=5);assert status==0
 event(dict(stage='native_direct_child_actual_waitpid',unit=unit,identity=first,return_code=status))
 os.close(pidfd);parent.close();diagnostic.close()
 held=[]
 if descendants:
  for index in range(3):
   current=identity(grand['pid']);assert current['start']==grand['start'] and current['state'] not in ('Z','X') and not select.select([grand_pin],[],[],0)[0]
   value=sample('grandchild_live_after_parent_actual_waitpid_'+str(index),group,pins,original)
   assert value['directory']['nlink']>0 and value['openat_same_directory']['cgroup.procs']['value'].split()==[str(grand['pid'])] and 'populated 1\n' in value['openat_same_directory']['cgroup.events']['value'];held.append(value['boottime_ns']);time.sleep(0.1)
  os.write(gate_write,b'X');assert select.select([grand_pin],[],[],5)[0]
  event(dict(stage='grandchild_pidfd_exit_observed',identity=grand,actual_waitpid='NOT_OBSERVED: constructor parent exited; no new Root reap authority'))
 os.close(gate_write)
 end=time.monotonic()+5;checks=0
 while time.monotonic()<end:
  paired={name:preadfd(fd) for name,fd in pins.items()}
  if all(v.get('errno')==errno.ENODEV for v in paired.values()):break
  time.sleep(0.0001);checks+=1
 assert all(v.get('errno')==errno.ENODEV for v in paired.values())
 before_lookup=dict(stage='original_file_targets_AFTER_paired_ENODEV_BEFORE_ANY_fresh_child_lookup',boottime_ns=time.clock_gettime_ns(time.CLOCK_BOOTTIME),paired_pread_zero=paired,retained_file_native={name:dict(fstat=fstat(fd),fstatfs=fstatfs(fd),kernel_fd_link=os.readlink('/proc/self/fd/'+str(fd))) for name,fd in pins.items()},group_target=os.readlink('/proc/self/fd/'+str(group)))
 event(before_lookup)
 fresh_lookup={name:open_read(group,name) for name in ['cgroup.events','cgroup.procs']}
 after_lookup=dict(stage='same_original_file_targets_AFTER_exact_original_directory_fresh_child_lookup',boottime_ns=time.clock_gettime_ns(time.CLOCK_BOOTTIME),fresh_lookup=fresh_lookup,retained_file_native={name:dict(fstat=fstat(fd),fstatfs=fstatfs(fd),kernel_fd_link=os.readlink('/proc/self/fd/'+str(fd))) for name,fd in pins.items()},group_target=os.readlink('/proc/self/fd/'+str(group)))
 event(after_lookup)
 unlinked=sample(label+'_original_pin_after_actual_parent_reap',group,pins,original)
 owner_unchanged();assert pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()==boot
 results.append(dict(unit=unit,job=str(job),invocation_id=invocation,original_directory_identity=list(original),initial_nlink=initial['nlink'],final_nlink=unlinked['directory']['nlink'],child_identity=first,child_actual_waitpid_return_code=status,grandchild=grand,grandchild_actual_waitpid='NOT_OBSERVED' if descendants else 'NOT_APPLICABLE',original_live_pin=live,before_exact_original_child_lookup=before_lookup,after_exact_original_child_lookup=after_lookup,held_live_grandchild_observations_ns=held,native_events_openat_failed='errno' in unlinked['openat_same_directory']['cgroup.events'],original_pin_poll_count=checks,final_pin=unlinked))
 if grand_pin is not None:os.close(grand_pin)
 for fd in pins.values():os.close(fd)
 os.close(group)
result=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),boot_id=boot,kernel=platform.release(),machine=platform.machine(),namespaces=ns,manager_unique_name=owner,manager_pid=1,request_method='StartTransientUnit',pid_property='PIDFDs:ah',numeric_pid_property_fallback=False,results=results,resource_cleanup='none; only native systemd auto-removal observed',scope='original cgroup-pin deletion characterization only; no member/kernel-work quiescence or cleanup/reuse authority')
(directory/'result.json').write_text(json.dumps(result,indent=2)+'\n');events.close();print(json.dumps(result))
'''
payload = "nonce=" + repr(nonce) + "\n" + guest
(output / "guest.py").write_text(payload)
command = ["ssh", "-i", "target/lab-state/id_ed25519", "-p" + str(port), "-o", "IdentitiesOnly=yes", "-o", "UserKnownHostsFile=" + known, "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=5", "vprouterlab@127.0.0.1", "sudo -n python3 -I -"]
result = subprocess.run(command, input=payload, capture_output=True, text=True, timeout=40)
(output / "ssh.stdout").write_text(result.stdout)
(output / "ssh.stderr").write_text(result.stderr)
record = dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(), platform=platform,
              guest_script_sha256=hashlib.sha256(payload.encode()).hexdigest(), nonce=nonce,
              ssh_exit_code=result.returncode, scope="kernel-only original scope-pin characterization; no product acceptance")
if result.returncode == 0:
    record["result"] = json.loads(result.stdout)
with (output / "record.json").open("x") as stream:
    json.dump(record, stream, indent=2)
    stream.write("\n")
print(json.dumps(dict(output=str(output), exit_code=result.returncode, result=record.get("result"))))
raise SystemExit(result.returncode)
