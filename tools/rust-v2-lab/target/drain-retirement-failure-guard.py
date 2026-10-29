import hashlib,json,pathlib,subprocess,sys
run=int(sys.argv[1]);assert run>0
platform=sys.argv[2] if len(sys.argv)>2 else 'debian-x86_64'
choices={'debian-clean-x86_64':(22036,'target/platform-lab/debian-clean-x86_64/known_hosts'),'debian-x86_64':(22032,'target/lab-state/known_hosts'),'arch-x86_64':(22033,'target/platform-lab/arch-x86_64/known_hosts'),'debian-arm64':(22034,'target/platform-lab/debian-arm64/known_hosts')}
port,known=choices[platform]
x=json.loads(pathlib.Path(f'target/lab-state/actual-program-run-{run}.json').read_text());assert x['exit_code']!=0 and x['component_test_mode'] in {'owner_retirement','owner_retirement_host_span'}
reference=json.loads(pathlib.Path(f'target/lab-state/expiry-drop-failed-actors-run-{run}.json').read_text());assert reference['platform']==platform and reference['artifact_sha256']==x['artifact_sha256']
assert reference['record_sha256']==hashlib.sha256(pathlib.Path(f'target/lab-state/actual-program-run-{run}.json').read_bytes()).hexdigest()
allactors=reference['actors'];guards=[v for v in allactors if v['expected']['role']=='guard'];assert len(guards)==2
assert sum(v['proc_exists'] for v in guards)==1
assert all(v['state']=='T' and v['start_matches'] for v in guards if v['proc_exists'])
e=[{'expected':v['expected'],'scope_cgroup_inode':v['inode'],'exe':v['exe']} for v in allactors if v['expected']['role']=='guard' and v['proc_exists']];assert len(e)==1
expired=[v['expected'] for v in allactors if not v['proc_exists']];assert len(expired)==4
assert all(not v['proc_exists'] and not v['cgroup_exists'] and v['load_state']=='not-found' for v in allactors if not v['proc_exists'])
deny=json.loads(pathlib.Path(f'target/lab-state/expiry-drop-deny-run-{run}.json').read_text());assert deny['source_commit']==reference['source_commit'] and len(deny['tables'])==3 and all(t['exit_code']==0 for t in deny['tables'])
assert [sum('rule'in v and any('drop'in z for z in v['rule'].get('expr',[])) for v in t['observed'].get('nftables',[])) for t in deny['tables']]==[12,3,3]

intents=[json.loads(z.split(' ',1)[1]) for z in x['stderr'].splitlines() if z.startswith('LAB_GUARD_SCOPE_INTENT ') and json.loads(z.split(' ',1)[1])['role']=='guard']
assert [v['expected'] for v in guards]==intents
probes=[json.loads(z)['owner_probe'] for z in x['stdout'].splitlines() if z.startswith('{') and 'owner_probe' in json.loads(z)];assert len(probes)==1
nonce=probes[0]['nonce']
s="""import os,pathlib,json,hashlib,stat,signal,select
assert os.geteuid()==0
nonce_path=pathlib.Path('/var/lib/vprouter-v2-lab/owner-domain-nonce');st=nonce_path.lstat();assert stat.S_ISREG(st.st_mode) and st.st_uid==st.st_gid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and nonce_path.read_text()==NONCE
import subprocess
for e in EXPIRY_EXPECTED:
 assert e['role'] in ('guard','expiry-host','expiry-transport','expiry-data')
 assert not pathlib.Path('/proc',str(e['pid'])).exists()
 assert not pathlib.Path('/sys/fs/cgroup/system.slice',e['unit']).exists()
 r=subprocess.run(['systemctl','show','--property=LoadState','--value',e['unit']],capture_output=True,text=True,timeout=4,check=True);assert r.stdout.strip()=='not-found'
handles=[]
for v in EXPECTED:
 e=v['expected'];assert e['role']=='guard' and e['unit']=='vprouter-v2-'+e['allocation_digest']+'-'+e['lifecycle']+'-guard.scope';p=pathlib.Path('/proc')/str(e['pid']);fd=os.pidfd_open(e['pid'],0);f=(p/'stat').read_text().split(') ',1)[1].split();g=pathlib.Path('/sys/fs/cgroup/system.slice')/e['unit']
 assert f[0]=='T' and int(f[19])==e['start_time']
 assert g.stat().st_ino==v['scope_cgroup_inode'] and [int(a) for a in (g/'cgroup.procs').read_text().split()]==[e['pid']]
 assert (p/'cgroup').read_text().strip()=='0::/system.slice/'+e['unit']
 assert v['exe']=='/var/lib/vprouter-v2-lab/task8b2-'+DIGEST+'.payload' and os.readlink(p/'exe')==v['exe'] and hashlib.sha256((p/'exe').read_bytes()).hexdigest()==DIGEST
 st=pathlib.Path(v['exe']).stat();assert st.st_uid==st.st_gid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o555
 handles.append((e,fd))
for e,fd in handles:signal.pidfd_send_signal(fd,signal.SIGKILL,None,0)
out=[]
for e,fd in handles:
 poll=select.poll();poll.register(fd,select.POLLIN);assert poll.poll(5000),e
 out.append({'pid':e['pid'],'start_time':e['start_time'],'unit':e['unit'],'signal':'SIGKILL','retained_pidfd_exit_readable':True,'resumed':False});os.close(fd)
print(json.dumps({'failed_run':RUN,'exact_owned_actors_drained':out,'namespace_policy_journal_container_resources_retained':True}))
""".replace('EXPIRY_EXPECTED',repr(expired)).replace('EXPECTED',repr(e)).replace('DIGEST',repr(x['artifact_sha256'])).replace('RUN',str(run)).replace('NONCE',repr(nonce))
r=subprocess.run(['ssh','-i','target/lab-state/id_ed25519','-p'+str(port),'-o','UserKnownHostsFile='+known,'-o','StrictHostKeyChecking=yes','vprouterlab@127.0.0.1','sudo -n python3 -I -'],input=s,capture_output=True,text=True,timeout=20);assert r.returncode==0,r.stderr
p=pathlib.Path(f'target/lab-state/retirement-guard-drain-run-{run}.json');assert not p.exists();p.write_text(r.stdout);print(r.stdout)
