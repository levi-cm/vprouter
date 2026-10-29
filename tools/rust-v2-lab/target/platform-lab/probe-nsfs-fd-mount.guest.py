"""Root-only fresh nsfs bind contract; no Docker, profiles, existing resources."""
import ctypes,fcntl,json,os,pathlib,select,socket,stat,subprocess,sys,time,uuid
if not __debug__:raise RuntimeError('optimized_python_refused')
assert os.geteuid()==0 and os.uname().machine in ('x86_64','aarch64')
libc=ctypes.CDLL(None,use_errno=True)
libc.mount.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_char_p,ctypes.c_ulong,ctypes.c_void_p]
libc.umount2.argtypes=[ctypes.c_char_p,ctypes.c_int]
def call(value):
 if value<0:raise OSError(ctypes.get_errno(),os.strerror(ctypes.get_errno()))
 return value
def ident(fd):
 s=os.fstat(fd);return [s.st_dev,s.st_ino]
def nsident(path):
 s=pathlib.Path(path).stat();return[s.st_dev,s.st_ino]
def fs_type(fd):
 buffer=ctypes.create_string_buffer(512);call(libc.fstatfs(fd,ctypes.byref(buffer)));return ctypes.c_long.from_buffer(buffer).value
def fdinfo(fd):return dict(line.split(':',1)for line in pathlib.Path('/proc/self/fdinfo',str(fd)).read_text().splitlines()if':'in line)
def mountid(fd):return int(fdinfo(fd)['mnt_id'])
def event(phase,**fields):print(json.dumps(dict(phase=phase,**fields)),flush=True)
class How(ctypes.Structure):_fields_=[('flags',ctypes.c_uint64),('mode',ctypes.c_uint64),('resolve',ctypes.c_uint64)]
def reopen(directory):
 how=How(os.O_RDONLY|os.O_CLOEXEC,0,0x08|0x04)
 return call(libc.syscall(437,directory,ctypes.c_char_p(b'data_namespace'),ctypes.byref(how),ctypes.sizeof(how)))
root=pathlib.Path('/var/lib/vprouter-v2-lab');s=root.lstat();assert stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700
parent_net=nsident('/proc/self/ns/net');parent_mount=nsident('/proc/self/ns/mnt')
assert parent_net==nsident('/proc/1/ns/net')and parent_mount==nsident('/proc/1/ns/mnt')
directory=root/('nsfs-fd-mount-probe-'+uuid.uuid4().hex);directory.mkdir(mode=0o700)
anchor=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW)
source='''import ctypes,os,select,sys
libc=ctypes.CDLL(None,use_errno=True)
if libc.unshare(0x40000000)!=0:raise OSError(ctypes.get_errno(),'unshare_new_private_net')
print('READY',flush=True)
assert select.select([sys.stdin.buffer],[],[],15)[0] and sys.stdin.buffer.read(1)==b'q'
'''
child=subprocess.Popen([sys.executable,'-I','-c',source],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
pidfd=os.pidfd_open(child.pid,0);assert select.select([child.stdout],[],[],5)[0]and child.stdout.readline()==b'READY\n'
raw=pathlib.Path('/proc',str(child.pid),'stat').read_text();start=int(raw[raw.rfind(')')+2:].split()[19])
assert not select.select([pidfd],[],[],0)[0]
namespace=os.open('/proc/'+str(child.pid)+'/ns/net',os.O_RDONLY|os.O_CLOEXEC);assert not select.select([pidfd],[],[],0)[0]
source_identity=ident(namespace);assert source_identity!=parent_net and fs_type(namespace)==0x6e736673
placeholder=os.open('data_namespace',os.O_RDONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=anchor);original=ident(placeholder);s=os.fstat(placeholder);assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_uid==s.st_gid==0;os.fsync(anchor)
event('original_pins_and_exclusive_placeholder',directory=str(directory),directory_identity=ident(anchor),creator=dict(pid=child.pid,start=start),source_namespace=source_identity,source_mount_id=mountid(namespace),original_placeholder=original)
call(libc.mount(('/proc/self/fd/'+str(namespace)).encode(),('/proc/self/fd/'+str(placeholder)).encode(),None,4096,None))
event('bind_syscall_completed',source_namespace=source_identity,placeholder_underlying_still_original=ident(placeholder)==original)
assert ident(placeholder)==original and stat.S_ISREG(os.fstat(placeholder).st_mode)
opened=reopen(anchor);assert ident(opened)==source_identity and fs_type(opened)==0x6e736673;bound_mount=mountid(opened);assert bound_mount!=mountid(namespace)
assert nsident('/proc/self/ns/net')==parent_net and nsident('/proc/self/ns/mnt')==parent_mount
child.stdin.write(b'q');child.stdin.flush();child.stdin.close();waited,status=os.waitpid(child.pid,0);assert waited==child.pid and status==0;child.returncode=0
assert child.stdout.read()==b''and child.stderr.read()==b'';child.stdout.close();child.stderr.close()
fresh=reopen(anchor);assert ident(fresh)==source_identity and mountid(fresh)==bound_mount and ident(placeholder)==original
proof=dict(schema=1,kernel=os.uname().release,machine=os.uname().machine,uid=os.geteuid(),source_creator=dict(pid=child.pid,start=start,actual_waitpid=True,raw_wait_status=status),directory_identity=ident(anchor),source_namespace=source_identity,source_mount_id=mountid(namespace),bound_mount_id=bound_mount,original_placeholder=original,underlying_original_fd_still_regular_and_same_inode=True,openat2_beneath_no_symlinks_returns_original_namespace=True,namespace_retained_after_creator_actual_reap=True,parent_network_namespace_unchanged=True,parent_mount_namespace_unchanged=True,helper_setns_or_unshare=False,creator_used_fresh_private_netns=True,docker_profiles_or_existing_resources_accessed=False)
event('contract_proved_before_disposal',**proof)
# Disposal is probe-only, after success. Close only new bind-mount descriptors;
# retain original source/placeholder/directory pins and recheck the exact name.
os.close(fresh);os.close(opened)
call(libc.umount2(('/proc/self/fd/'+str(anchor)+'/data_namespace').encode(),8))
after=reopen(anchor);assert ident(after)==original and stat.S_ISREG(os.fstat(after).st_mode);os.close(after)
assert ident(placeholder)==original;os.close(placeholder);os.unlink('data_namespace',dir_fd=anchor);os.fsync(anchor);os.close(namespace);os.close(pidfd);os.close(anchor);directory.rmdir()
assert nsident('/proc/self/ns/net')==parent_net and nsident('/proc/self/ns/mnt')==parent_mount
proof.update(temporary_resources_removed_after_actual_reap=True,scope='Fresh kernel contract only; no Docker admission, product attachment receipt, provider or runtime acceptance.')
event('result',value=proof)
