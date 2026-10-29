import pathlib,subprocess,json,os
root=pathlib.Path(__file__).resolve().parent;repo=root.parent.parent
script="""import os,pathlib,json,subprocess,stat
p=pathlib.Path('/var/lib/vprouter-v2-lab')
s=p.stat() if p.exists() else None
try:
 result=subprocess.run(['cloud-init','status','--format=json'],capture_output=True,text=True,timeout=8)
 status=json.loads(result.stdout).get('status','unknown')
except Exception:status='unavailable'
print(json.dumps({'kernel':os.uname().release,'architecture':os.uname().machine,'pid1':pathlib.Path('/proc/1/comm').read_text().strip(),'os_release':pathlib.Path('/etc/os-release').read_text(),'cgroup_v2':pathlib.Path('/sys/fs/cgroup/cgroup.controllers').is_file(),'docker_socket':pathlib.Path('/run/docker.sock').is_socket(),'cloud_init_status':status,'bootstrap_complete':(p/'bootstrap-complete').exists(),'lab_root_owner':s.st_uid if s else None,'lab_root_mode':oct(stat.S_IMODE(s.st_mode)) if s else None}))
"""
for platform in ['arch-x86_64','debian-arm64']:
 state=root/platform
 row=json.loads((state/'process.json').read_text())
 proc=pathlib.Path('/proc')/str(row['pid'])
 if not proc.exists() or proc.joinpath('stat').read_text().rsplit(')',1)[1].split()[0] in ['Z','X']:
  print(platform,'VM_EXITED',flush=True);continue
 cmd=proc.joinpath('cmdline').read_bytes()
 assert str(state/'guest.qcow2').encode() in cmd and ('127.0.0.1:'+str(row['ssh_port'])).encode() in cmd
 known=state/'known_hosts'
 if not known.exists():
  scan=subprocess.run(['ssh-keyscan','-T','3','-t','ed25519','-p',str(row['ssh_port']),'127.0.0.1'],capture_output=True,text=True,timeout=8)
  if not scan.stdout:
   print(platform,'SSH_NOT_READY',flush=True);continue
  known.write_text(scan.stdout);known.chmod(0o600)
 argv=['ssh','-i',str(repo/'target/lab-state/id_ed25519'),'-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(known),'-o','ConnectTimeout=4','-p',str(row['ssh_port']),'vprouterlab@127.0.0.1','sudo python3 -']
 result=subprocess.run(argv,input=script,capture_output=True,text=True,timeout=20)
 if result.returncode:
  print(platform,'PROBE_FAILED',result.stderr[:500],flush=True);continue
 value=json.loads(result.stdout)
 (state/'preflight.json').write_text(json.dumps(value,indent=2)+'\n')
 print(platform,json.dumps(value),flush=True)
