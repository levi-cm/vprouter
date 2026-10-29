import hashlib,json,pathlib,re,subprocess,sys
run=int(sys.argv[1]);assert run>0
p=pathlib.Path(f'target/lab-state/actual-program-run-{run}.json');raw=p.read_bytes();x=json.loads(raw);assert x['exit_code']!=0
assert not any(z.startswith('LAB_GUARD_SCOPE_INTENT ') for z in x['stderr'].splitlines())
probes=[]
for line in x['stdout'].splitlines():
 try:v=json.loads(line)
 except ValueError:continue
 if 'owner_probe' in v:probes.append(v['owner_probe'])
assert len(probes)==1;nonce=probes[0]['nonce'];assert re.fullmatch('[a-f0-9]{64}',nonce)
b=json.loads(pathlib.Path(sys.argv[2]).read_text());assert b['source_commit']==x['source_binding']['source_commit'] and b['new_directories']==[] and b['record']==str(p)
port,known={'debian-arm64':(22034,'target/platform-lab/debian-arm64/known_hosts'),'debian-clean-x86_64':(22036,'target/platform-lab/debian-clean-x86_64/known_hosts')}[b['platform']]
s=r'''import pathlib,os,stat,json,hashlib,subprocess,time
assert os.geteuid()==0
root=pathlib.Path('/var/lib/vprouter-v2-lab')
def read(path):
 st=path.lstat();assert stat.S_ISREG(st.st_mode) and st.st_uid==st.st_gid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and st.st_size<=1024*1024
 return path.read_bytes()
assert read(root/'owner-domain-nonce').decode()==NONCE
base=root/('owner-bootstrap-'+NONCE)
def query(argv):
 r=subprocess.run(argv,capture_output=True,text=True,check=True,timeout=8);assert len(r.stdout)<4*1024*1024;return json.loads(r.stdout)
resources=read(base/'resources.json');journal=read(base/'records/namespaces.json')
print(json.dumps(dict(observed_boottime=time.clock_gettime(7),resources=json.loads(resources),resources_sha256=hashlib.sha256(resources).hexdigest(),journal=json.loads(journal),journal_sha256=hashlib.sha256(journal).hexdigest(),routes=query(['ip','-j','-4','route','show','table','all']),links=query(['ip','-j','-d','link','show']))))
'''.replace('NONCE',repr(nonce))
r=subprocess.run(['ssh','-i','target/lab-state/id_ed25519','-p'+str(port),'-o','UserKnownHostsFile='+known,'-o','StrictHostKeyChecking=yes','vprouterlab@127.0.0.1','sudo -n python3 -I -'],input=s,capture_output=True,text=True,timeout=35);assert r.returncode==0,r.stderr
d=json.loads(r.stdout);d.update(record=str(p),record_sha256=hashlib.sha256(raw).hexdigest(),source_binding=x['source_binding'],artifact_sha256=x['artifact_sha256'],platform=b['platform'],nonce=nonce,read_only=True)
out=pathlib.Path(f'target/lab-state/bootstrap-route-failure-run-{run}.json')
with out.open('x') as f:json.dump(d,f,indent=2);f.write('\n')
print(json.dumps(dict(record=str(out),resources=d['resources'],journal=d['journal'],route_count=len(d['routes']),link_count=len(d['links']))))
