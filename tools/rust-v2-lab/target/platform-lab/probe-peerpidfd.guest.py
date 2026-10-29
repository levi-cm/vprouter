"""Unprivileged original-peer pidfd kernel contract; no Docker/admin/credentials."""
import fcntl,hashlib,json,os,pathlib,select,socket,stat,struct,subprocess,sys,tempfile,time
if not __debug__:raise RuntimeError('optimized_python_refused')
assert os.geteuid()!=0
root=pathlib.Path(tempfile.mkdtemp(prefix='vpr-peerpidfd-',dir='/home/vprouterlab'));os.chmod(root,0o700);path=root/'peer.sock'
source='''import os,pathlib,select,socket,sys
p=sys.argv[1];server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);server.bind(p);server.listen(1);print('READY',flush=True)
server.settimeout(10);connection,_=server.accept();connection.settimeout(10)
assert connection.recv(1)==b'x';connection.sendall(b'y')
assert select.select([sys.stdin.buffer],[],[],10)[0] and sys.stdin.buffer.read(1)==b'q'
connection.close();server.close()
'''
child=subprocess.Popen([sys.executable,'-I','-c',source,str(path)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
original=os.pidfd_open(child.pid,0)
assert select.select([child.stdout],[],[],5)[0] and child.stdout.readline()==b'READY\n'
raw=pathlib.Path('/proc',str(child.pid),'stat').read_text();start=int(raw[raw.rfind(')')+2:].split()[19]);socket_identity=path.stat()
client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);client.settimeout(5);client.connect(str(path));client.sendall(b'x');assert client.recv(1)==b'y'
credentials=struct.unpack('3i',client.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12));assert credentials==(child.pid,os.geteuid(),os.getegid())
pins=[];rows=[]
for _ in range(2):
 raw=client.getsockopt(socket.SOL_SOCKET,77,struct.calcsize('i'));assert len(raw)==struct.calcsize('i');fd=struct.unpack('i',raw)[0];assert fd>=0;pins.append(fd)
 flags=fcntl.fcntl(fd,fcntl.F_GETFD);assert flags&fcntl.FD_CLOEXEC
 fields=dict(line.split(':',1)for line in pathlib.Path('/proc/self/fdinfo',str(fd)).read_text().splitlines()if':'in line)
 assert int(fields['Pid'])==child.pid
 rows.append(dict(close_on_exec=True,original_peer_pid=int(fields['Pid'])))
def ready(fd):
 poll=select.poll();poll.register(fd,select.POLLIN|select.POLLHUP|select.POLLERR);return bool(poll.poll(0))
assert not any(ready(fd)for fd in [original,*pins])
child.stdin.write(b'q');child.stdin.flush();child.stdin.close()
waited,status=os.waitpid(child.pid,0);assert waited==child.pid and status==0;child.returncode=os.waitstatus_to_exitcode(status)
assert all(ready(fd)for fd in [original,*pins])
after=struct.unpack('3i',client.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12));assert after==credentials
post=[]
for fd in pins:
 fields=dict(line.split(':',1)for line in pathlib.Path('/proc/self/fdinfo',str(fd)).read_text().splitlines()if':'in line);assert int(fields['Pid'])==-1;post.append(int(fields['Pid']))
assert child.stdout.read()==b'' and child.stderr.read()==b''
child.stdout.close();child.stderr.close();client.close()
for fd in [original,*pins]:os.close(fd)
current=path.lstat();assert stat.S_ISSOCK(current.st_mode)and(current.st_dev,current.st_ino)==(socket_identity.st_dev,socket_identity.st_ino);path.unlink();root.rmdir()
print(json.dumps(dict(schema=1,kernel=os.uname().release,machine=os.uname().machine,uid=os.geteuid(),original_child=dict(pid=child.pid,start=start,actual_waitpid=True,raw_wait_status=status),atomic_peer_pidfd_option=77,atomic_peer_pin_results=rows,all_pins_not_ready_while_original_peer_live=True,all_pins_ready_after_actual_peer_reap=True,post_reap_peer_pidfd_info=post,cached_numeric_credentials_unchanged_after_reap=True,temporary_resources_removed_after_actual_reap=True,docker_or_production_access=False,scope='Unprivileged kernel contract only; not Docker query/native authority or PID-reuse exploit proof.')))
