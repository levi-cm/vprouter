import pathlib,json,subprocess,sys,re
p=pathlib.Path(sys.argv[1]);c=json.loads(p.read_text());platform=sys.argv[2]
choices={'debian-clean-x86_64':('amd64','target/platform-lab/run-actual-monitor-debian-clean-x86_64.py',22036,'target/platform-lab/debian-clean-x86_64/known_hosts'),'debian-x86_64':('amd64','tools/actual-program-oracle.py',22032,'target/lab-state/known_hosts'),'debian-arm64':('arm64','target/platform-lab/run-actual-monitor-debian-arm64-tcg120.py',22034,'target/platform-lab/debian-arm64/known_hosts'),'arch-x86_64':('amd64','target/platform-lab/run-actual-monitor-arch-x86_64.py',22033,'target/platform-lab/arch-x86_64/known_hosts'),'void-x86_64':('amd64','target/platform-lab/run-actual-monitor-void-x86_64.py',22035,'target/platform-lab/void-x86_64/known_hosts')}
arch,runner,port,known=choices[platform];v=c['platforms'][arch]
mode=sys.argv[4] if len(sys.argv)>4 else 'actual';assert mode in {'owner-retirement-queued-failure','owner-retirement-writer-failure','owner-retirement-global-stop','owner-retirement-host-span','owner-retirement','owner-retained-drop','owner-admission-birth-failure','owner-expiry-drop','owner-expiry-partial-drop','actual','terminal','terminal-death','operational-profile','owner-domains','owner-watchdog','owner-journal','owner-deployment','owner-bootstrap','owner-host-audit','owner-terminal','owner-terminal-death','owner-expiry-placement','owner-process-inspection','owner-inspection-held','owner-inspection-setup','owner-admission-stop'}
if mode=='terminal':
 assert platform=='debian-x86_64';runner='target/platform-lab/run-terminal-executor-debian.py'
elif mode=='terminal-death':
 assert platform=='debian-x86_64';runner='target/platform-lab/run-terminal-death-debian.py'
if mode=='operational-profile':
 assert platform in {'debian-x86_64','debian-arm64'};runner='target/platform-lab/run-operational-profile-debian-arm64.py' if platform=='debian-arm64' else 'target/platform-lab/run-operational-profile-debian.py'
if mode in {'owner-domains','owner-watchdog','owner-journal','owner-deployment','owner-bootstrap','owner-host-audit','owner-terminal','owner-terminal-death','owner-expiry-placement','owner-process-inspection','owner-inspection-held','owner-inspection-setup','owner-admission-stop'} and platform!='debian-clean-x86_64':
 assert platform=='debian-x86_64' or (platform=='arch-x86_64' and mode in {'owner-domains','owner-admission-stop','owner-inspection-held'}) or (platform=='debian-arm64' and mode in {'owner-domains','owner-journal','owner-deployment','owner-bootstrap','owner-host-audit','owner-expiry-placement','owner-inspection-held','owner-process-inspection','owner-inspection-setup','owner-admission-stop'});runner=('target/platform-lab/run-owner-domains-arch.py' if mode=='owner-domains' else 'target/platform-lab/run-'+mode+'-arch.py') if platform=='arch-x86_64' else ('target/platform-lab/run-'+mode+'-debian-arm64.py' if platform=='debian-arm64' else 'target/platform-lab/run-'+mode+'-debian.py')
if mode in {'owner-retirement-queued-failure','owner-retirement-writer-failure','owner-retirement-global-stop','owner-retirement-host-span','owner-retirement','owner-retained-drop','owner-admission-birth-failure','owner-expiry-drop','owner-expiry-partial-drop'} and platform!='debian-clean-x86_64':
 assert platform in ({'debian-x86_64','debian-arm64','arch-x86_64'} if mode in {'owner-retirement-queued-failure','owner-retirement-writer-failure','owner-retirement-global-stop','owner-retirement-host-span','owner-retirement','owner-expiry-drop','owner-expiry-partial-drop'} else {'debian-x86_64','debian-arm64'});runner='target/platform-lab/run-'+mode+('-debian-arm64.py' if platform=='debian-arm64' else ('-arch.py' if platform=='arch-x86_64' else '-debian.py'))
if platform=='debian-clean-x86_64':
 assert mode=='actual' or mode.startswith('owner-');runner=('target/platform-lab/run-'+mode+'-debian-clean.py') if mode.startswith('owner-') else runner
label=sys.argv[3] if len(sys.argv)>3 else platform+'-actual';assert re.fullmatch('[a-z0-9_-]+',label)
out=p.parent/label;out.mkdir(mode=0o700)
ssh=['ssh','-i','target/lab-state/id_ed25519','-p'+str(port),'-o','UserKnownHostsFile='+known,'-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=5','vprouterlab@127.0.0.1','sudo python3 -']
script="""import pathlib,stat,json,os,re
root=pathlib.Path('/var/lib/vprouter-v2-lab');s=root.lstat();assert os.geteuid()==0 and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700
out=[]
for p in root.iterdir():
 if re.fullmatch('task8b2-[1-9][0-9]*',p.name):
  s=p.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700;out.append(str(p))
print(json.dumps(out))
"""
def directories():
 r=subprocess.run(ssh,input=script,capture_output=True,text=True,check=True,timeout=15);return set(json.loads(r.stdout))
before=directories();(out/'directories-before.json').write_text(json.dumps(sorted(before),indent=2)+'\n')
r=subprocess.run(['python3',runner,v['artifact'],v['artifact_sha256'],c['source'],c['source_sha256'],str(p.parent/(arch+'.context.tar')),v['context_sha256'],c['source_commit']],capture_output=True,text=True,timeout=250 if platform=='debian-arm64' or mode.startswith('owner-') else 110)
(out/'controller.json').write_text(r.stdout);(out/'controller.stderr').write_text(r.stderr)
x=json.loads(r.stdout);new=directories()-before
(out/'directory-binding.json').write_text(json.dumps({'source_commit':c['source_commit'],'source_archive_sha256':c['source_sha256'],'artifact_sha256':v['artifact_sha256'],'platform':platform,'record':x['record'],'new_directories':sorted(new)},indent=2)+'\n')
assert len(new)<=1,new
if x['exit_code']==0:assert len(new)==(0 if mode=='operational-profile' or (mode.startswith('owner-') and mode not in {'owner-terminal','owner-terminal-death','owner-process-inspection'}) else 1),new
summary={'record':x['record'],'exit_code':x['exit_code'],'case_count':len(x['runtime_events']),'new_directories':sorted(new)}
if x['exit_code']!=0:
 summary.update(stderr_tail='\n'.join(x['stderr'].splitlines()[-32:]),runtime_events=x['runtime_events'])
 summary['diagnostic_events']=[line for line in x['stderr'].splitlines() if any(marker in line for marker in ('LAB_NATIVE_FAILURE','LAB_CONFINEMENT_FAILURE','LAB_INSPECTION_FAILURE','LAB_OWNER_TERMINAL','LAB_INSPECTION_DRAIN','actual_lab:'))]
 summary['full_stderr_retained_in_record']=x['record']
elif mode.startswith('owner-'):summary['runtime_events']=x['runtime_events']
print(json.dumps(summary,indent=2));raise SystemExit(r.returncode)
