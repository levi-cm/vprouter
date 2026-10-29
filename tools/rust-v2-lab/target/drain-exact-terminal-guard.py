"""Kill/reap only the exact stopped guard after other expiry actors are absent."""
import pathlib,json,subprocess,sys
run=int(sys.argv[1]);binding=json.loads(pathlib.Path(sys.argv[2]).read_text());assert binding['record']==f'target/lab-state/actual-program-run-{run}.json'
reference=json.loads(pathlib.Path(f'target/lab-state/terminal{run}-actor-journal-reference.json').read_text());deny=json.loads(pathlib.Path(f'target/lab-state/terminal{run}-deny-reference.json').read_text());record=json.loads(pathlib.Path(binding['record']).read_text());assert record['exit_code']!=0 and reference['source_commit']==binding['source_commit'] and all(t['exit_code']==0 for t in deny['tables'])
guard=next(v for v in reference['actors'] if v['expected']['role']=='guard');others=[v['expected'] for v in reference['actors'] if v['expected']['role']!='guard'];assert len(others)==3 and len(reference['entries'])==1 and guard['state']=='T' and guard['start']==guard['expected']['start_time']
nonce=reference['entries'][0]['terminal']['lifecycle'];probes=[json.loads(line)['owner_probe'] for line in record['stdout'].splitlines() if line.startswith('{"owner_probe":')];assert len(probes)==1 and probes[0]['nonce']==nonce
port,known={'debian-clean-x86_64':(22036,'target/platform-lab/debian-clean-x86_64/known_hosts'),'debian-x86_64':(22032,'target/lab-state/known_hosts'),'debian-arm64':(22034,'target/platform-lab/debian-arm64/known_hosts')}[binding['platform']]
script=r'''
import pathlib,os,stat,json,signal,select,hashlib
assert os.geteuid()==0;v=GUARD;e=v['expected'];digest=DIGEST
p=pathlib.Path('/var/lib/vprouter-v2-lab/owner-domain-nonce');s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and p.read_text()==NONCE
for other in OTHERS:
 assert not pathlib.Path('/proc',str(other['pid'])).exists()
 assert not pathlib.Path('/sys/fs/cgroup/system.slice',other['unit']).exists()
fd=os.pidfd_open(e['pid'],0);p=pathlib.Path('/proc',str(e['pid']));fields=(p/'stat').read_text().rsplit(') ',1)[1].split();assert fields[0]=='T' and int(fields[19])==e['start_time']
g=pathlib.Path('/sys/fs/cgroup/system.slice',e['unit']);assert g.stat().st_ino==v['inode'] and (g/'cgroup.procs').read_text().split()==[str(e['pid'])] and (p/'cgroup').read_text().strip()=='0::/system.slice/'+e['unit']
exe=pathlib.Path('/var/lib/vprouter-v2-lab/task8b2-'+digest+'.payload');assert os.readlink(p/'exe')==str(exe)
s=exe.stat();assert stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o555 and hashlib.sha256((p/'exe').read_bytes()).hexdigest()==digest
signal.pidfd_send_signal(fd,signal.SIGKILL,None,0);poll=select.poll();poll.register(fd,select.POLLIN);assert poll.poll(5000)
print(json.dumps({'failed_run':RUN,'exact_guard':e,'signal':'SIGKILL','retained_pidfd_exit_readable':True,'resumed':False,'other_three_expiry_identities_and_cgroups_already_absent':True,'three_exact_terminal_tables_observed_before_kill':True,'namespace_policy_journal_container_resources_retained':True}))
'''
for key,value in [('GUARD',guard),('DIGEST',record['artifact_sha256']),('NONCE',nonce),('OTHERS',others),('RUN',run)]:script=script.replace(key,repr(value))
r=subprocess.run(['ssh','-i','target/lab-state/id_ed25519','-p'+str(port),'-o','UserKnownHostsFile='+known,'-o','StrictHostKeyChecking=yes','vprouterlab@127.0.0.1','sudo python3 -'],input=script,capture_output=True,text=True,timeout=20);assert r.returncode==0,r.stderr
with pathlib.Path(f'target/lab-state/owner-actor-drain-run-{run}.json').open('x') as stream:stream.write(r.stdout)
print(r.stdout)
