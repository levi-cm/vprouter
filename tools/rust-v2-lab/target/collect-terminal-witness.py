"""Read-only source-bound public terminal witness collection from an owned VM."""
import json,pathlib,re,subprocess,sys
candidate=pathlib.Path(sys.argv[1]);platform=sys.argv[2];label=sys.argv[3];run=int(sys.argv[4]);assert run>0
cfg=json.loads(candidate.read_text());binding=json.loads((candidate.parent/label/'directory-binding.json').read_text());assert binding['record']==f'target/lab-state/actual-program-run-{run}.json' and len(binding['new_directories'])==1
arch,port,known={'debian-clean-x86_64':('amd64',22036,'target/platform-lab/debian-clean-x86_64/known_hosts'),'debian-x86_64':('amd64',22032,'target/lab-state/known_hosts'),'debian-arm64':('arm64',22034,'target/platform-lab/debian-arm64/known_hosts')}[platform]
record=json.loads(pathlib.Path(binding['record']).read_text());assert record['exit_code']==0 and record['artifact_sha256']==cfg['platforms'][arch]['artifact_sha256'] and record['source_archive_sha256']==cfg['source_sha256']
task=binding['new_directories'][0];assert re.fullmatch('/var/lib/vprouter-v2-lab/task8b2-[1-9][0-9]*',task)
probes=[json.loads(line)['owner_probe'] for line in record['stdout'].splitlines() if line.startswith('{"owner_probe":')];assert len(probes)==1
script=r'''
import os,pathlib,stat,json
assert os.geteuid()==0
p=pathlib.Path(TASK)
for directory in [pathlib.Path('/var/lib/vprouter-v2-lab'),p]:
 s=directory.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700
p=p/'terminal-executor-witness.json';s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<=128*1024
print(json.dumps(json.loads(p.read_text())))
'''.replace('TASK',repr(task))
r=subprocess.run(['ssh','-i','target/lab-state/id_ed25519','-p'+str(port),'-o','UserKnownHostsFile='+known,'-o','StrictHostKeyChecking=yes','vprouterlab@127.0.0.1','sudo python3 -'],input=script,capture_output=True,text=True,timeout=15);assert r.returncode==0,r.stderr
w=json.loads(r.stdout);assert w['lifecycle']==probes[0]['nonce'] and w['expired_actor_resumed'] is False and len(w['completions'])==3
assert all(e['result']=='verified_before_deadline' and e['finished_at']<=e['deadline'] for e in w['completions'])
x={'source_commit':cfg['source_commit'],'source_archive_sha256':cfg['source_sha256'],'artifact_sha256':record['artifact_sha256'],'platform':platform,'record':binding['record'],'witness':w}
p=pathlib.Path(f'target/lab-state/terminal-witness-run-{run}.json')
with p.open('x') as f:json.dump(x,f,indent=2);f.write('\n')
p.chmod(0o600)
print(json.dumps({'record':binding['record'],'source_commit':cfg['source_commit'],'protected_public_witness_copied':True,'verified_before_deadline_completions':len(w['completions']),'expired_actor_resumed':w['expired_actor_resumed']}))
