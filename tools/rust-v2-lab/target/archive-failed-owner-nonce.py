import json,pathlib,re,subprocess,sys
run=int(sys.argv[1]);assert run>0
platform=sys.argv[2] if len(sys.argv)>2 else 'debian-x86_64'
choices={'debian-clean-x86_64':(22036,'target/platform-lab/debian-clean-x86_64/known_hosts'),'debian-x86_64':(22032,'target/lab-state/known_hosts'),'arch-x86_64':(22033,'target/platform-lab/arch-x86_64/known_hosts'),'debian-arm64':(22034,'target/platform-lab/debian-arm64/known_hosts')}
port,known=choices[platform]
x=json.loads(pathlib.Path(f'target/lab-state/actual-program-run-{run}.json').read_text());assert x['exit_code']!=0
items=[]
for line in x['stdout'].splitlines():
 try:v=json.loads(line)
 except ValueError:continue
 if 'owner_probe' in v:items.append(v['owner_probe'])
assert len(items)==1
e=items[0];owner=e['unit'];nonce=e['nonce'];assert re.fullmatch('vprouter-v2-owner@[a-f0-9]{64}[.]service',owner) and re.fullmatch('[a-f0-9]{64}',nonce)
units={owner};intents=[]
pattern='vprouter-v2-[a-f0-9]{64}-[a-f0-9]{64}-(guard|expiry-host|expiry-transport|expiry-data)[.]scope'
for line in x['stderr'].splitlines():
 if line.startswith('LAB_GUARD_SCOPE_INTENT '):
  v=json.loads(line.split(' ',1)[1]);assert re.fullmatch(pattern,v['unit'])
  assert v['unit']==f"vprouter-v2-{v['allocation_digest']}-{v['lifecycle']}-{v['role']}.scope"
  assert type(v['pid']) is int and v['pid']>1 and type(v['start_time']) is int and v['start_time']>0
  units.add(v['unit']);intents.append(v)
 elif line.startswith('LAB_SCOPE_POLICY_READBACK '):
  v=json.loads(line.split(' ',1)[1]);assert re.fullmatch(pattern,v['Id']);units.add(v['Id'])
# Stable owner service keys do NOT identify any child allocation/lifecycle.
# Exact source-bound intents/readback enumerate children; never infer their names.
script="""import pathlib,os,stat,subprocess,json
root=pathlib.Path('/var/lib/vprouter-v2-lab');group_root=pathlib.Path('/sys/fs/cgroup/system.slice')
for unit in UNITS:
 r=subprocess.run(['systemctl','show','--property=LoadState','--value',unit],capture_output=True,text=True,timeout=5,check=True);assert r.stdout.strip()=='not-found',(unit,r.stdout)
 assert not (group_root/unit).exists(),unit
r=subprocess.run(['systemctl','list-units','--all','--type=service,scope','--plain','--no-legend','--no-pager','vprouter-v2-*'+NONCE+'*'],capture_output=True,text=True,timeout=5,check=True);assert not r.stdout.strip()
p=root/'owner-domain-nonce';s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1;assert p.read_text()==NONCE
q=root/('owner-domain-nonce-run'+str(RUN)+'-'+NONCE);assert not q.exists()
os.link(p,q,follow_symlinks=False);p.unlink();fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
print(json.dumps({'failed_run':RUN,'exact_actor_units_verified_absent':UNITS,'retained_nonce':str(q),'deleted_resources':False}))
""".replace('UNITS',repr(sorted(units))).replace('NONCE',repr(nonce)).replace('RUN',str(run))
r=subprocess.run(['ssh','-i','target/lab-state/id_ed25519','-p'+str(port),'-o','UserKnownHostsFile='+known,'-o','StrictHostKeyChecking=yes','vprouterlab@127.0.0.1','sudo python3 -'],input=script,capture_output=True,text=True,timeout=25)
assert r.returncode==0,r.stderr
result=json.loads(r.stdout);result['source_commit']=x['source_binding']['source_commit'];result['platform']=platform;result['scope_intents']=intents
p=pathlib.Path('target/lab-state')/f'owner-nonce-archive-run-{run}.json';assert not p.exists();p.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
