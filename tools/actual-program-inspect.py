"""Read-only metadata inventory of one exact identity-free actual-program run.

Never reads daemon state, configuration, argv, environment or packet contents.
Missing namespace pins are reported; their persistence is not inferred.
"""
import json
import pathlib
import re
import subprocess
import sys

assert len(sys.argv) == 2 and re.fullmatch(
    r'/var/lib/vprouter-v2-lab/task8b2-[1-9][0-9]*', sys.argv[1]
), 'usage: exact_owned_actual_program_directory'
guest = r'''
import datetime,hashlib,json,os,pathlib,stat,subprocess
root=pathlib.Path('/var/lib/vprouter-v2-lab')
assert os.geteuid()==0
for path in [pathlib.Path('/'),pathlib.Path('/var'),pathlib.Path('/var/lib'),root]:
 s=path.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==0 and not s.st_mode&0o022
assert stat.S_IMODE(root.lstat().st_mode)==0o700
s=(root/'isolated-acceptance').lstat()
assert stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600
directory=pathlib.Path(DIRECTORY)
s=directory.lstat();assert directory.parent==root and stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700
def read(path,maximum=65536):
 s=path.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and s.st_nlink==1 and not s.st_mode&0o022 and s.st_size<=maximum
 fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as inp:
  current=os.fstat(inp.fileno());assert (s.st_dev,s.st_ino,s.st_size)==(current.st_dev,current.st_ino,current.st_size)
  data=inp.read(maximum+1);assert len(data)==s.st_size
  return data
def call(argv):
 try:r=subprocess.run(argv,capture_output=True,text=True,timeout=5)
 except subprocess.TimeoutExpired:return {'code':124,'data':None,'stderr':'metadata_command_timeout'}
 assert len(r.stdout)<4*1024*1024 and len(r.stderr)<65536
 try:out=json.loads(r.stdout)
 except ValueError:out=r.stdout
 return {'code':r.returncode,'data':out,'stderr':r.stderr}
resources=json.loads(read(directory/'resources.json'))
assert resources['records']==str(directory/'records') and resources['deployment']=='transportlab'+directory.name.rsplit('-',1)[1]
allocation=resources['allocation']['exits'][0]
metadata=call(['docker','inspect',resources['container']])
container=None
if metadata['code']==0:
 value=metadata['data'][0]
 assert value['Id']==resources['container'] and value['Config']['Labels']['io.vprouter.deployment']==resources['deployment'] and value['Config']['Labels']['io.vprouter.role']=='gateway'
 container={'id':value['Id'],'image_id':value['Image'],'state':value['State'],'network_mode':value['HostConfig']['NetworkMode'],'privileged':value['HostConfig']['Privileged'],'cap_drop':value['HostConfig']['CapDrop'],'devices':value['HostConfig']['Devices'],'readonly_root':value['HostConfig']['ReadonlyRootfs']}
observations=[]
for scope,name in [('host',None),('transport',allocation['transport_namespace']),('data',allocation['data_namespace'])]:
 pin=pathlib.Path(resources['records'])/name if name else None
 prefix=['nsenter','--net='+str(pin)] if pin else []
 observations.append({'scope':scope,'pin':str(pin) if pin else None,'links':call([*prefix,'ip','-details','-j','link','show']),'addresses':call([*prefix,'ip','-j','address','show']),'routes4':call([*prefix,'ip','-j','-4','route','show','table','all']),'routes6':call([*prefix,'ip','-j','-6','route','show','table','all']),'rules4':call([*prefix,'ip','-j','-4','rule','show']),'rules6':call([*prefix,'ip','-j','-6','rule','show']),'nft':call([*prefix,'nft','-j','list','ruleset'])})
files={}
for name in ['daemon-process.json','observer-process.json','actual-daemon-kernel.json','result.json']:
 path=directory/name
 if path.exists():
  raw=read(path,4*1024*1024)
  files[name]={'sha256':hashlib.sha256(raw).hexdigest(),'data':json.loads(raw)}
records=pathlib.Path(resources['records'])
ownership=json.loads(read(records/'namespaces.json')) if (records/'namespaces.json').exists() else None
print(json.dumps({'observed_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'read_only':True,'deployments':[{'directory':str(directory),'resources':resources,'container':container,'container_inspection_code':metadata['code'],'ownership_record':ownership,'scopes':observations,'fixture_files':files}],'admission_markers_present':{name:(root/name).exists() for name in ['task8b2-image','task8b2-host-acceptance']},'real_client_acceptance':'NOT_RUN','production_changes':False},indent=2))
'''.replace('DIRECTORY', repr(sys.argv[1]))
base = pathlib.Path('target/lab-state')
result = subprocess.run([
    'ssh', '-i', str(base/'id_ed25519'), '-o', 'IdentitiesOnly=yes', '-o',
    'UserKnownHostsFile='+str(base/'known_hosts'), '-o', 'StrictHostKeyChecking=yes',
    '-o', 'ConnectTimeout=5', '-p22032', 'vprouterlab@127.0.0.1', 'sudo python3 -'
], input=guest, capture_output=True, text=True, timeout=55)
print(result.stdout, end='')
print(result.stderr, end='', file=sys.stderr)
sys.exit(result.returncode)
