"""Read-only exact-identity inspection of a failed local Debian terminal fixture."""
import json,pathlib,re,subprocess,sys
run=int(sys.argv[1]);assert run>0
record=json.loads(pathlib.Path(f'target/lab-state/actual-program-run-{run}.json').read_text());assert record['exit_code']!=0
intents=[json.loads(line.split(' ',1)[1]) for line in record['stderr'].splitlines() if line.startswith('LAB_GUARD_SCOPE_INTENT ')]
assert len(intents)==4 and {e['role'] for e in intents}=={'guard','expiry-host','expiry-transport','expiry-data'}
probes=[json.loads(line)['owner_probe'] for line in record['stdout'].splitlines() if line.startswith('{"owner_probe":')];assert len(probes)==1
probe=probes[0];nonce=probe['nonce'];assert re.fullmatch('[a-f0-9]{64}',nonce)
assert all(e['lifecycle']==nonce and re.fullmatch('vprouter-v2-[a-f0-9]{64}-[a-f0-9]{64}-(guard|expiry-host|expiry-transport|expiry-data)[.]scope',e['unit']) for e in intents)
binding=json.loads(pathlib.Path(sys.argv[2]).read_text())
assert binding['record']==f'target/lab-state/actual-program-run-{run}.json' and len(binding['new_directories'])==1
port,known={'debian-clean-x86_64':(22036,'target/platform-lab/debian-clean-x86_64/known_hosts'),'debian-x86_64':(22032,'target/lab-state/known_hosts'),'debian-arm64':(22034,'target/platform-lab/debian-arm64/known_hosts')}[binding['platform']]
task=binding['new_directories'][0];assert re.fullmatch('/var/lib/vprouter-v2-lab/task8b2-[1-9][0-9]*',task)
script=r'''
import os,pathlib,json,hashlib,stat,subprocess,time
root=pathlib.Path('/var/lib/vprouter-v2-lab');assert os.geteuid()==0
s=root.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700
noncepath=root/'owner-domain-nonce';s=noncepath.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and noncepath.read_text()==NONCE
out={'observed_boottime':time.clock_gettime(7),'source_commit':SOURCE,'artifact_sha256':ARTIFACT,'actors':[]}
for e in EXPECTED:
 p=pathlib.Path('/proc')/str(e['pid']);g=pathlib.Path('/sys/fs/cgroup/system.slice')/e['unit'];a={'expected':e,'proc_exists':p.exists(),'cgroup_exists':g.exists()}
 if p.exists():
  fields=(p/'stat').read_text().rsplit(') ',1)[1].split();a.update(state=fields[0],start=int(fields[19]),cgroup=(p/'cgroup').read_text().strip(),exe_sha256=hashlib.sha256((p/'exe').read_bytes()).hexdigest())
 if g.exists():a.update(members=(g/'cgroup.procs').read_text().split(),inode=g.stat().st_ino)
 r=subprocess.run(['systemctl','show',e['unit'],'--property=LoadState','--value'],capture_output=True,text=True,timeout=4);assert r.returncode==0;a['load_state']=r.stdout.strip();out['actors'].append(a)
path=pathlib.Path(TASK)/'records/namespaces.json';s=path.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<=1024*1024
doc=json.loads(path.read_text());out['entries']=doc['entries']
print(json.dumps(out))
'''
for key,value in [('NONCE',nonce),('SOURCE',binding['source_commit']),('ARTIFACT',record['artifact_sha256']),('EXPECTED',intents),('TASK',task)]:script=script.replace(key,repr(value))
r=subprocess.run(['ssh','-i','target/lab-state/id_ed25519','-p'+str(port),'-o','UserKnownHostsFile='+known,'-o','StrictHostKeyChecking=yes','vprouterlab@127.0.0.1','sudo python3 -'],input=script,capture_output=True,text=True,timeout=25)
assert r.returncode==0,r.stderr
result=json.loads(r.stdout);path=pathlib.Path(f'target/lab-state/terminal{run}-actor-journal-reference.json')
with path.open('x') as stream:json.dump(result,stream,indent=2);stream.write('\n')
print(json.dumps(result,indent=2))
