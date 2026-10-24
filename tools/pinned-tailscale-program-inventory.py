"""Root-controller public program inventory from pinned images in the LOCAL VM.

Creates only a fresh stopped, network-none, state-free container, copies a fixed
public-file allowlist as tar streams, and removes that exact owned container.
Never starts a process or accesses any enrolled identity/profile/state directory.
"""
import hashlib
import io
import json
import pathlib
import re
import struct
import subprocess
import sys
import tarfile

assert len(sys.argv) == 2 and sys.argv[1] in ('amd64', 'arm64')
arch = sys.argv[1]
index_digest = 'sha256:c507f3a2a6ab1cabd8d809b98edeb41edbd5c3fb6ad9632ffd098b4c7d0b4065'
base = pathlib.Path('target/lab-state')
index = json.loads((base/'tailscale-1.102.5-manifest-index.json').read_text())
entries = [e for e in index['manifests'] if e['platform'] == {'architecture':arch,'os':'linux'}]
assert len(entries) == 1 and re.fullmatch(r'sha256:[a-f0-9]{64}', entries[0]['digest'])
digest = entries[0]['digest']
image = 'tailscale/tailscale@'+digest
ssh = ['ssh','-i',str(base/'id_ed25519'),'-o','IdentitiesOnly=yes','-o',
       'UserKnownHostsFile='+str(base/'known_hosts'),'-o','StrictHostKeyChecking=yes',
       '-o','ConnectTimeout=5','-p22032','vprouterlab@127.0.0.1']
script = r'''
import json,os,pathlib,stat,subprocess
root=pathlib.Path('/var/lib/vprouter-v2-lab')
assert os.geteuid()==0
for p in [pathlib.Path('/'),pathlib.Path('/var'),pathlib.Path('/var/lib'),root]:
 s=p.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and s.st_gid==0 and not s.st_mode&0o022
s=(root/'isolated-acceptance').lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600
image=IMAGE
arch=ARCH
subprocess.run(['docker','pull','--platform','linux/'+arch,image],check=True,stdout=subprocess.DEVNULL,timeout=90)
meta=json.loads(subprocess.check_output(['docker','image','inspect',image],timeout=8))[0]
assert meta['Architecture']==arch and meta['Os']=='linux' and image in meta['RepoDigests']
args=['docker','create','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--label','io.vprouter.lab=public-program-inventory','--entrypoint','/usr/local/bin/tailscaled',image,'--version']
cid=subprocess.check_output(args,text=True,timeout=8).strip()
container=json.loads(subprocess.check_output(['docker','inspect',cid],timeout=8))[0]
assert container['Id']==cid and container['Image']==meta['Id'] and container['Config']['Image']==image and not container['State']['Running'] and container['State']['Status']=='created' and container['HostConfig']['NetworkMode']=='none' and not container['Mounts'] and container['Config']['Labels']['io.vprouter.lab']=='public-program-inventory'
print(json.dumps({'container_id':cid,'image_id':meta['Id'],'platform_manifest':image,'architecture':arch,'os':meta['Os'],'container_stopped':True,'identity_state_mounted':False}))
'''.replace('IMAGE',repr(image)).replace('ARCH',repr(arch))
result=subprocess.run([*ssh,'sudo python3 -'],input=script,text=True,capture_output=True,check=True,timeout=110)
meta=json.loads(result.stdout);cid=meta['container_id'];assert re.fullmatch(r'[a-f0-9]{64}',cid)
destination=pathlib.Path('target/program-inventory')/('tailscale-1.102.5-'+arch)
destination.mkdir(mode=0o700,parents=True,exist_ok=True)
rows=[]
for source,name,elf in [('/usr/local/bin/tailscaled','tailscaled',True),('/usr/local/bin/tailscale','tailscale',True),('/etc/ssl/certs/ca-certificates.crt','ca-certificates.crt',False)]:
 response=subprocess.run([*ssh,'sudo docker cp '+cid+':'+source+' -'],capture_output=True,check=True,timeout=25)
 assert len(response.stdout)<=128*1024*1024
 with tarfile.open(fileobj=io.BytesIO(response.stdout)) as archive:
  members=archive.getmembers();assert len(members)==1 and members[0].isfile() and members[0].name==name and members[0].size<=120*1024*1024
  data=archive.extractfile(members[0]).read()
 assert data
 machine=None
 if elf:
  assert data[:6]==b'\x7fELF\x02\x01' and struct.unpack_from('<H',data,16)[0] in (2,3)
  machine=struct.unpack_from('<H',data,18)[0];assert machine=={'amd64':62,'arm64':183}[arch]
 else:
  assert b'-----BEGIN CERTIFICATE-----' in data and b'PRIVATE KEY' not in data
 target=destination/name
 if target.exists():assert target.read_bytes()==data
 else:
  with target.open('xb') as output:output.write(data)
 target.chmod(0o555 if elf else 0o444)
 rows.append({'source_path':source,'local_path':str(target),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'elf_machine':machine})
cleanup=r'''
import json,subprocess
cid=CID
v=json.loads(subprocess.check_output(['docker','inspect',cid],timeout=8))[0]
assert v['Id']==cid and v['Image']==IMAGE_ID and v['Config']['Image']==IMAGE and v['Config']['Labels']['io.vprouter.lab']=='public-program-inventory' and v['State']['Status']=='created' and not v['State']['Running'] and not v['Mounts']
subprocess.run(['docker','rm',cid],check=True,stdout=subprocess.DEVNULL,timeout=8)
print(json.dumps({'exact_owned_stopped_container_removed':True}))
'''.replace('CID',repr(cid)).replace('IMAGE_ID',repr(meta['image_id'])).replace('IMAGE',repr(image))
removed=subprocess.run([*ssh,'sudo python3 -'],input=cleanup,text=True,capture_output=True,check=True,timeout=12)
report={'schema_version':1,'tailscale_version':'1.102.5','source_index':'tailscale/tailscale@'+index_digest,'inventory_tool_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'platform':meta,'public_files':rows,'cleanup':json.loads(removed.stdout),'runtime_execution':'NOT_RUN','production_changes':False}
(base/('tailscale-program-inventory-'+arch+'.json')).write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
