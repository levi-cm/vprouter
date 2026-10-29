import pathlib,subprocess,hashlib,json,shlex
r=pathlib.Path.cwd();s=r/'target/platform-lab/void-x86_64';a=r/'target/continuation-20261026T130553Z/shared-leases/execution_probe';digest=hashlib.sha256(a.read_bytes()).hexdigest();assert digest=='b8d45ec031ab22989e2b4d42ae36ff167e5a6e3dfefade634ada3bd67f01f982'
opts=['-i',str(r/'target/lab-state/id_ed25519'),'-o','UserKnownHostsFile='+str(s/'known_hosts'),'-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=5'];ssh=['ssh',*opts,'-p22035','vprouterlab@127.0.0.1'];tmp='/home/vprouterlab/cgroup-shape-probe-'+digest
subprocess.run(['scp','-q',*opts,'-P22035',str(a),'vprouterlab@127.0.0.1:'+tmp],check=True)
code=r'''
import pathlib,hashlib,subprocess,json,io,tarfile,os,stat
root=pathlib.Path('/var/lib/vprouter-v2-lab');assert os.geteuid()==0 and stat.S_IMODE(root.stat().st_mode)==0o700
p=pathlib.Path(TEMP); data=p.read_bytes();assert hashlib.sha256(data).hexdigest()==DIGEST
out=root/'void-cgroup-shape-20261026';out.mkdir(mode=0o700)
probe=out/'probe';probe.write_bytes(data);probe.chmod(0o555);p.unlink()
b=io.BytesIO()
with tarfile.open(fileobj=b,mode='w') as t:
 for name,mode,value in [('Dockerfile',0o644,b'FROM scratch\nCOPY probe /probe\nENTRYPOINT ["/probe","--test-probe-container"]\n'),('probe',0o555,data)]:
  i=tarfile.TarInfo(name);i.size=len(value);i.mode=mode;t.addfile(i,io.BytesIO(value))
run=lambda a:subprocess.run(a,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,check=True).stdout.strip()
image='vprouter-lab-void-cgroup:20261026'
# Fixed public scratch build: no state, credentials, network, or host directories.
p=subprocess.run(['docker','build','--network=none','-q','-t',image,'-'],input=b.getvalue(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True);imageid=p.stdout.decode().strip()
id=run(['docker','run','-d','--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--label','io.vprouter.lab=void-cgroup-20261026',image])
try:
 c=json.loads(run(['docker','inspect',id]))[0];assert c['Id']==id and c['Config']['Labels']['io.vprouter.lab']=='void-cgroup-20261026' and c['State']['Running'];pid=c['State']['Pid']
 path=pathlib.Path(f'/proc/{pid}/cgroup');cg=path.read_text();assert cg.startswith('0::/') and len(cg.splitlines())==1
 relative=cg.strip()[3:];d=pathlib.Path('/sys/fs/cgroup')/relative.lstrip('/');st=d.stat();procs=(d/'cgroup.procs').read_text().splitlines();assert str(pid) in procs
 v={'platform':'void-runit-cgroupfs-v2','container':id,'image':imageid,'probe_sha256':DIGEST,'pid':pid,'proc_cgroup':cg,'cgroup_directory':str(d),'directory_uid':st.st_uid,'directory_gid':st.st_gid,'directory_mode':oct(stat.S_IMODE(st.st_mode)),'cgroup_procs':procs,'cgroup_events':(d/'cgroup.events').read_text(),'mountinfo':[l for l in pathlib.Path('/proc/self/mountinfo').read_text().splitlines() if ' /sys/fs/cgroup ' in l],'pid1':pathlib.Path('/proc/1/comm').read_text().strip(),'production_changes':False}
 (out/'metadata.json').write_text(json.dumps(v,indent=2)+'\n');(out/'metadata.json').chmod(0o600);print(json.dumps(v,indent=2))
finally:
 assert json.loads(run(['docker','inspect',id]))[0]['Config']['Labels']['io.vprouter.lab']=='void-cgroup-20261026';run(['docker','rm','-f',id])
'''.replace('TEMP',repr(tmp)).replace('DIGEST',repr(digest))
p=subprocess.run(ssh+['sudo python3 -'],input=code,capture_output=True,text=True);(s/'cgroup-shape.stderr').write_text(p.stderr);assert p.returncode==0,p.stderr
v=json.loads(p.stdout);(s/'cgroup-shape.json').write_text(json.dumps(v,indent=2)+'\n');print(p.stdout)
