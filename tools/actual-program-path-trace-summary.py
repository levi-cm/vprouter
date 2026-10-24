"""Collect fixed file-metadata traces from one identity-free local fixture.

Never trace or emit decoded I/O, random bytes, argv or environments. Refuse
syscalls outside the runner's explicit file-metadata whitelist.
"""
import pathlib
import re
import subprocess
import sys

assert len(sys.argv) == 2 and re.fullmatch(
    r'/var/lib/vprouter-v2-lab/task8b2-path-trace-[a-f0-9]{64}-[1-9][0-9]*', sys.argv[1]
), 'usage: exact_owned_path_trace_directory'
guest = r'''
import hashlib,json,os,pathlib,re,stat
root=pathlib.Path('/var/lib/vprouter-v2-lab')
assert os.geteuid()==0
for p in [pathlib.Path('/'),pathlib.Path('/var'),pathlib.Path('/var/lib'),root]:
 s=p.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==0 and not s.st_mode&0o022
assert stat.S_IMODE(root.lstat().st_mode)==0o700
s=(root/'isolated-acceptance').lstat()
assert stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600
directory=pathlib.Path(DIRECTORY);s=directory.lstat()
assert directory.parent==root and stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700
allowed={'openat','openat2','newfstatat','getcwd','mkdirat','statx','access','faccessat'}
rows=[]
for p in sorted(directory.glob('syscall.*')):
 assert re.fullmatch(r'syscall\.[1-9][0-9]*',p.name)
 s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and s.st_nlink==1 and s.st_size<=16*1024*1024
 fd=os.open(p,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as inp:
  current=os.fstat(inp.fileno());assert (current.st_dev,current.st_ino,current.st_size)==(s.st_dev,s.st_ino,s.st_size)
  raw=inp.read(16*1024*1024+1);assert len(raw)==s.st_size
 lines=raw.decode().splitlines();diagnostics=[]
 for line in lines:
  if line.startswith(('--- ','+++ ')):continue
  match=re.match(r'([a-z0-9_]+)\(',line)
  assert match and match[1] in allowed,'unexpected_syscall_or_format'
  if '= -1' in line or match[1] in {'getcwd','mkdirat'}:diagnostics.append(line)
 rows.append({'file':p.name,'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'lines':len(lines),'diagnostic_file_metadata':diagnostics[-40:]})
assert rows
print(json.dumps({'directory':str(directory),'fixed_metadata_syscall_whitelist_verified':True,'decoded_io_random_exec_environment':False,'read_only':True,'files':rows},indent=2))
'''.replace('DIRECTORY', repr(sys.argv[1]))
base = pathlib.Path('target/lab-state')
result = subprocess.run([
    'ssh', '-i', str(base/'id_ed25519'), '-o', 'IdentitiesOnly=yes', '-o',
    'UserKnownHostsFile='+str(base/'known_hosts'), '-o', 'StrictHostKeyChecking=yes',
    '-o', 'ConnectTimeout=5', '-p22032', 'vprouterlab@127.0.0.1', 'sudo python3 -'
], input=guest, capture_output=True, text=True, timeout=25)
print(result.stdout, end='')
print(result.stderr, end='', file=sys.stderr)
sys.exit(result.returncode)
