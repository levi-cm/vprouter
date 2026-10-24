"""Classify a bounded FD2-only trace from an identity-free local fixture.

Raw logs remain in the protected guest. Output contains hashes and predefined
public error tokens and closed diagnostic type/predicate vectors only; it never
emits log messages, IDs or credentials.
"""
import pathlib
import re
import subprocess
import sys

assert len(sys.argv) == 2 and re.fullmatch(
    r'/var/lib/vprouter-v2-lab/task8b2-stderr-trace-[a-f0-9]{64}-[1-9][0-9]*', sys.argv[1]
), 'usage: exact_owned_stderr_trace_directory'
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
tokens=['fatal','error','failed','engine','tun','tuntap','iptables','nftables','route','bind','socket','permission denied','operation not permitted','read-only file system','no such file or directory','invalid argument','not supported','logpolicy','config','state','syspolicy','user','network','listen','wgengine','tpm','mkdir','ioctl','pipe','inotify','offload']
def public_observations(text):
 shapes={'status_types':(4,int),'status_node_types':(4,int),'prefs_types':(11,int),'status_predicates':(4,bool),'prefs_predicates':(10,bool)}
 rows=[]
 for line in text.splitlines():
  match=re.fullmatch(r'observation_(status_types|status_node_types|prefs_types|status_predicates|prefs_predicates)=(\[[0-6truefals, ]+\])',line)
  if match:
   key,encoded=match.groups()
   try:values=json.loads(encoded)
   except ValueError:continue
   count,kind=shapes[key]
   if len(values)==count and all(type(v)==kind and (kind==bool or 0<=v<=6) for v in values):
    rows.append({'code':key,'values':values})
  elif re.fullmatch(r'observation_(status|prefs)_(json|parse)_refused',line):
   rows.append({'code':line})
 return rows
rows=[]
for p in sorted(directory.glob('syscall.*')):
 assert re.fullmatch(r'syscall\.[1-9][0-9]*',p.name)
 s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and s.st_nlink==1 and s.st_size<=1024*1024
 fd=os.open(p,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as inp:
  current=os.fstat(inp.fileno());assert (s.st_dev,s.st_ino,s.st_size)==(current.st_dev,current.st_ino,current.st_size)
  raw=inp.read(1024*1024+1);assert len(raw)==s.st_size
 lines=raw.decode().splitlines();classified=[];fragments=[]
 for n,line in enumerate(lines):
  if line.startswith(('--- ','+++ ')):continue
  assert re.match(r'(write|writev)\(2,',line),'unexpected_syscall_or_descriptor'
  hits=[token for token in tokens if token in line.lower()]
  if hits:classified.append({'line':n,'public_tokens':hits})
  for literal in re.findall(r'"(?:[^"\\]|\\.)*"',line):
   try:fragments.append(json.loads(literal))
   except ValueError:fragments.append('\n')
 rows.append({'file':p.name,'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'lines':len(lines),'classifications':classified,'public_observations':public_observations(''.join(fragments))})
assert rows
print(json.dumps({'directory':str(directory),'trace_kind':'bounded_fd2_writes_only','decoded_logs_emitted':False,'predefined_tokens_only':True,'closed_observation_codebook_only':True,'read_only':True,'files':rows},indent=2))
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
