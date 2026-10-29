"""Read-only inspection of three exact retained terminal tables."""
import json,pathlib,subprocess,sys
run=int(sys.argv[1]);binding=json.loads(pathlib.Path(sys.argv[2]).read_text());assert binding['record']==f'target/lab-state/actual-program-run-{run}.json' and binding['new_directories']==[]
reference=json.loads(pathlib.Path(f'target/lab-state/expiry-drop-failed-actors-run-{run}.json').read_text());assert reference['source_commit']==binding['source_commit'];entries=[e for e in reference['journal_entries'] if 'terminal' in e];assert len(entries)==1;entry=entries[0];task='/var/lib/vprouter-v2-lab/owner-bootstrap-'+reference['nonce']
port,known={'debian-clean-x86_64':(22036,'target/platform-lab/debian-clean-x86_64/known_hosts'),'debian-x86_64':(22032,'target/lab-state/known_hosts'),'debian-arm64':(22034,'target/platform-lab/debian-arm64/known_hosts')}[binding['platform']]
script=r'''
import pathlib,os,json,subprocess
entry=ENTRY;nonce=entry['terminal']['lifecycle'];records=pathlib.Path(TASK)/'records';prefix=entry['data_name'].removeprefix('vr-data-');out=[]
for scope,kind,key in [('host','h',None),('transport','t','transport'),('data','d','data')]:
 table='vr_'+prefix+'_'+kind+'q_terminal_'+nonce;fds=[]
 if key:
  fd=os.open(records/entry[key+'_name'],os.O_RDONLY|os.O_CLOEXEC);s=os.fstat(fd);assert (s.st_dev,s.st_ino)==(entry[key]['dev'],entry[key]['ino']);fds=[fd];args=['nsenter','--net=/proc/self/fd/'+str(fd)]
 else:
  s=pathlib.Path('/proc/self/ns/net').stat();assert (s.st_dev,s.st_ino)==(entry['links']['host_namespace']['dev'],entry['links']['host_namespace']['ino']);args=[]
 result=subprocess.run(args+['nft','-j','list','table','inet',table],capture_output=True,text=True,timeout=5,pass_fds=fds)
 out.append({'scope':scope,'table':table,'exit_code':result.returncode,'observed':json.loads(result.stdout) if result.returncode==0 else None,'stderr':result.stderr})
 for fd in fds:os.close(fd)
print(json.dumps(out))
'''.replace('ENTRY',repr(entry)).replace('TASK',repr(task))
r=subprocess.run(['ssh','-i','target/lab-state/id_ed25519','-p'+str(port),'-o','UserKnownHostsFile='+known,'-o','StrictHostKeyChecking=yes','vprouterlab@127.0.0.1','sudo python3 -'],input=script,capture_output=True,text=True,timeout=25);assert r.returncode==0,r.stderr
tables=json.loads(r.stdout);record={'failed_run':run,'operation':'readonly_exact_retained_terminal_tables','source_commit':reference['source_commit'],'tables':tables}
with pathlib.Path(f'target/lab-state/expiry-drop-deny-run-{run}.json').open('x') as stream:json.dump(record,stream,indent=2);stream.write('\n')
print(json.dumps([{'scope':t['scope'],'table_exists':t['exit_code']==0,'drop_rules':sum('rule'in v and any('drop'in z for z in v['rule'].get('expr',[])) for v in (t['observed']or{}).get('nftables',[])),'stderr':t['stderr']} for t in tables],indent=2))
