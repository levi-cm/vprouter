import json,pathlib,subprocess,sys
run=int(sys.argv[1]);assert run>0
platform=sys.argv[2] if len(sys.argv)>2 else 'debian-x86_64'
choices={'debian-clean-x86_64':(22036,'target/platform-lab/debian-clean-x86_64/known_hosts'),'debian-x86_64':(22032,'target/lab-state/known_hosts'),'arch-x86_64':(22033,'target/platform-lab/arch-x86_64/known_hosts'),'debian-arm64':(22034,'target/platform-lab/debian-arm64/known_hosts')}
port,known=choices[platform]
x=json.loads(pathlib.Path(f'target/lab-state/actual-program-run-{run}.json').read_text());assert x['exit_code']!=0
intents=[json.loads(z.split(' ',1)[1]) for z in x['stderr'].splitlines() if z.startswith('LAB_GUARD_SCOPE_INTENT ')]
assert intents and all(e['role']=='guard' for e in intents)
script="""import os,pathlib,json,hashlib,stat
out=[]
for e in EXPECTED:
 p=pathlib.Path('/proc')/str(e['pid']);f=(p/'stat').read_text().split(') ',1)[1].split();group=pathlib.Path('/sys/fs/cgroup/system.slice')/e['unit'];members=[int(v) for v in (group/'cgroup.procs').read_text().split()]
 exe=os.readlink(p/'exe');digest=hashlib.sha256((p/'exe').read_bytes()).hexdigest()
 out.append({'expected':e,'actual_state':f[0],'actual_start':int(f[19]),'exe':exe,'exe_sha256':digest,'cgroup':(p/'cgroup').read_text().strip(),'scope_members':members,'scope_cgroup_inode':group.stat().st_ino})
print(json.dumps(out))
""".replace('EXPECTED',repr(intents))
r=subprocess.run(['ssh','-i','target/lab-state/id_ed25519','-p'+str(port),'-o','UserKnownHostsFile='+known,'-o','StrictHostKeyChecking=yes','vprouterlab@127.0.0.1','sudo python3 -'],input=script,capture_output=True,text=True,timeout=20);assert r.returncode==0,r.stderr
a=json.loads(r.stdout);p=pathlib.Path(f'target/lab-state/owner-actor-inspect-run-{run}.json');assert not p.exists();p.write_text(json.dumps(a,indent=2)+'\n');print(json.dumps(a))
