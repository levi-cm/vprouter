"""Read only fixed synthetic PCAPs from one exact owned local-guest test run.

Reports packet framing, capture counters and fixed marker counts, never payloads.
This evidence does not establish real-client or complete fault-matrix acceptance.
"""
import json
import pathlib
import re
import subprocess
import sys

assert len(sys.argv) == 2 and re.fullmatch(
    r"/var/lib/vprouter-v2-lab/(?:task8a|task8b2)-[1-9][0-9]*", sys.argv[1]
), "usage: exact_owned_test_directory"
script = r'''
import datetime, hashlib, json, os, pathlib, pwd, re, stat, struct
root = pathlib.Path('/var/lib/vprouter-v2-lab')
for p in [pathlib.Path('/'), pathlib.Path('/var'), pathlib.Path('/var/lib'), root]:
 s = p.lstat()
 assert stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and s.st_gid == 0 and not s.st_mode & 0o022
assert os.geteuid() == 0
s = (root/'isolated-acceptance').lstat()
assert stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_gid == 0 and s.st_nlink == 1 and stat.S_IMODE(s.st_mode) == 0o600
directory = pathlib.Path(DIRECTORY)
s = directory.lstat()
assert directory.parent == root and stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and s.st_gid == 0 and not s.st_mode & 0o077

def read(p, maximum, capture=False):
 s = p.lstat()
 owners = {(0,0)}
 if capture:
  account = pwd.getpwnam("tcpdump")
  owners.add((account.pw_uid,account.pw_gid))
 assert stat.S_ISREG(s.st_mode) and (s.st_uid,s.st_gid) in owners and s.st_nlink == 1 and not s.st_mode & 0o022 and s.st_size <= maximum
 fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
 with os.fdopen(fd, 'rb') as f:
  current = os.fstat(f.fileno())
  assert (s.st_dev,s.st_ino,s.st_size) == (current.st_dev,current.st_ino,current.st_size)
  b = f.read(maximum+1)
  assert len(b) == s.st_size
  return b

record = json.loads(read(directory/'resources.json', 65536))
assert record['records'] == str(directory/'records') and record['deployment'] == 'transportlab'+directory.name.rsplit('-',1)[1]
rows = []
phases = ['actual-positive', 'actual-negative'] if directory.name.startswith('task8b2-') else ['positive', 'negative']
for phase in phases:
 for scope in (['data'] if directory.name.startswith('task8b2-') else ['data', 'transport', 'host']):
  p = directory/(phase+'-'+scope+'.pcap')
  if not p.exists():
   rows.append({'file':p.name, 'status':'NOT_PRESENT'})
   continue
  b = read(p, 16*1024*1024, capture=True)
  endian = {b'\xd4\xc3\xb2\xa1':'<',b'\xa1\xb2\xc3\xd4':'>',b'\x4d\x3c\xb2\xa1':'<',b'\xa1\xb2\x3c\x4d':'>'}.get(b[:4])
  assert endian and len(b) >= 24
  major,minor,_,_,snaplen,linktype = struct.unpack_from(endian+'HHIIII',b,4)
  assert (major,minor) == (2,4) and 0 < snaplen <= 1048576
  packets = []; offset = 24
  while offset < len(b):
   assert len(b)-offset >= 16
   _,_,included,original = struct.unpack_from(endian+'IIII',b,offset)
   offset += 16
   assert included <= original and included <= snaplen and offset+included <= len(b)
   packets.append(b[offset:offset+included]); offset += included
  stderr = read(p.with_suffix('.stderr'),65536).decode('utf-8')
  counters = {label:int(m.group(1)) for label,pattern in [('captured',r'(\d+) packets? captured'),('received_by_filter',r'(\d+) packets? received by filter'),('dropped_by_kernel',r'(\d+) packets? dropped by kernel')] if (m:=re.search(pattern,stderr))}
  needles = [('positive_producer',b'VR8B2_POSITIVE_PRODUCER'),('forbidden_prefix',b'VR8B2_FORBIDDEN_')] if directory.name.startswith('task8b2-') else [('positive_data_health',b'VR8A_POSITIVE_DATA_HEALTH'),('positive_plaintext_control',b'VR8A_POSITIVE_PLAINTEXT_CAPTURE'),('forbidden_prefix',b'VR8A_FORBIDDEN_')]
  markers = {label:sum(packet.count(marker) for packet in packets) for label,marker in needles}
  rows.append({'file':p.name,'status':'FRAMING_VERIFIED','bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'linktype':linktype,'records':len(packets),'capture_counters':counters,'marker_occurrences':markers})
continuous = {'status':'NOT_PRESENT'}
if (directory/'continuous-sender.json').exists():
 c = json.loads(read(directory/'continuous-sender.json',65536))
 assert c['bounded_nonblocking_sender'] is True and c['joined'] is True and isinstance(c['attempts'],int) and c['attempts'] >= 3
 checkpoints = []
 for point in c['checkpoints']:
  assert isinstance(point['phase'],str) and re.fullmatch(r'[A-Za-z0-9_]{1,160}',point['phase'])
  delta = point['attempts_after']-point['attempts_before']
  assert delta >= 3 and c['attempts'] >= point['attempts_after']
  checkpoints.append({'phase':point['phase'],'send_attempt_delta':delta})
 assert checkpoints
 continuous = {'status':'COUNTS_VERIFIED','send_attempts':c['attempts'],'joined':True,'checkpoints':checkpoints}
print(json.dumps({'observed_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'directory':str(directory),'read_only':True,'synthetic_capture_metadata_only':True,'complete_fault_verdict':'NOT_ESTABLISHED_BY_THIS_TOOL','real_client_acceptance':'NOT_RUN','production_changes':False,'captures':rows,'continuous_sender':continuous},indent=2))
'''.replace("DIRECTORY", repr(sys.argv[1]))
base = pathlib.Path("target/lab-state")
result = subprocess.run(
    ["ssh", "-i", str(base/"id_ed25519"), "-o", "IdentitiesOnly=yes", "-o",
     "UserKnownHostsFile="+str(base/"known_hosts"), "-o", "StrictHostKeyChecking=yes",
     "-o", "ConnectTimeout=5", "-p22032", "vprouterlab@127.0.0.1", "sudo python3 -"],
    input=script, capture_output=True, text=True, timeout=20)
print(result.stdout, end="")
print(result.stderr, end="", file=sys.stderr)
sys.exit(result.returncode)
