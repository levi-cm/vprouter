import pathlib,subprocess,os,json,tarfile,hashlib,sys,datetime
root=pathlib.Path.cwd();cp=pathlib.Path(sys.argv[1]);c=json.loads(cp.read_text());out=cp.parent/'netfilter-native';out.mkdir(mode=0o700);source=out/'source';source.mkdir(mode=0o700)
subprocess.run(['python3','tools/verify-frozen-build-inputs.py',c['source'],c['source_commit']],check=True)
with tarfile.open(c['source'])as archive:archive.extractall(source,filter='data')
env=dict(os.environ,RUSTFLAGS='-C relocation-model=static',CC_x86_64_unknown_linux_musl=str(root/'target/toolchains/x86_64-linux-musl-cc'),CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER='rust-lld',CARGO_TARGET_DIR=str((out/'build').resolve()),CARGO_BUILD_JOBS='2')
r=subprocess.run(['cargo','test','--locked','--release','--target','x86_64-unknown-linux-musl','-p','vprouter-netfilter','--lib','--no-run','--message-format=json'],cwd=source,env=env,capture_output=True,text=True);(out/'build.stderr').write_text(r.stderr);assert r.returncode==0,r.stderr
es=[json.loads(l)for l in r.stdout.splitlines()if l.startswith('{')];payload=pathlib.Path(next(e['executable']for e in es if e.get('reason')=='compiler-artifact'and e.get('executable')and e['target']['name']=='vprouter_netfilter'));artifact=out/'payload';artifact.write_bytes(payload.read_bytes());artifact.chmod(0o600);digest=hashlib.sha256(artifact.read_bytes()).hexdigest()
base=root/'target/lab-state';opts=['-i',str(base/'id_ed25519'),'-o','UserKnownHostsFile='+str(base/'known_hosts'),'-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=5'];ssh=['ssh',*opts,'-p22032','vprouterlab@127.0.0.1'];temporary='/home/vprouterlab/terminal-native-'+digest;destination='/var/lib/vprouter-v2-lab/terminal-native-'+digest
subprocess.run(['scp','-q',*opts,'-P22032',str(artifact),'vprouterlab@127.0.0.1:'+temporary],check=True,timeout=20)
subprocess.run(ssh+['sudo install -o root -g root -m 0555 '+temporary+' '+destination],check=True,timeout=15);subprocess.run(ssh+['rm -- '+temporary],check=True,timeout=10)
guest=r'''
import pathlib,stat,hashlib,subprocess,json,os
root=pathlib.Path('/var/lib/vprouter-v2-lab');assert os.geteuid()==0
for p in [pathlib.Path('/'),pathlib.Path('/var'),pathlib.Path('/var/lib'),root]:
 s=p.lstat();assert stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and not s.st_mode&0o022
assert stat.S_IMODE(root.stat().st_mode)==0o700
for p,mode in [(root/'isolated-acceptance',0o600),(pathlib.Path(PAYLOAD),0o555)]:
 s=p.lstat();assert stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==mode
assert hashlib.sha256(pathlib.Path(PAYLOAD).read_bytes()).hexdigest()==DIGEST
p=subprocess.run(['timeout','--kill-after=3s','60s','unshare','--net',PAYLOAD,'--ignored','--exact','isolated_kernel_integration::native_acceptance','--nocapture'],timeout=66)
raise SystemExit(p.returncode)
'''.replace('PAYLOAD',repr(destination)).replace('DIGEST',repr(digest))
r=subprocess.run(ssh+['sudo python3 -'],input=guest,text=True,capture_output=True,timeout=85)
v={'observed_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source_commit':c['source_commit'],'source_archive_sha256':c['source_sha256'],'artifact_sha256':digest,'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr,'guard_runtime':False,'real_client_acceptance':'NOT_RUN','production_changes':False};(out/'native-run.json').write_text(json.dumps(v,indent=2)+'\n');print(json.dumps(v,indent=2))
if r.returncode:raise SystemExit(r.returncode)
rows=[json.loads(l)for l in r.stdout.splitlines()if l.startswith('{')];terminal=[r for r in rows if r.get('case')=='terminal_commit_fences_stale_release_and_survives_fresh_release'];assert len(terminal)==3 and {r['scope']for r in terminal}=={'Data','Transport','Host'};assert any(r.get('case')=='native_netfilter_isolated_acceptance'and r.get('result')=='pass'for r in rows)
