import datetime,hashlib,json,os,pathlib,subprocess,sys,tarfile
root=pathlib.Path.cwd();base=root/'target/lab-state';cp=pathlib.Path(sys.argv[1]);c=json.loads(cp.read_text());out=cp.parent/'shared-leases';out.mkdir(mode=0o700);frozen=out/'source';frozen.mkdir(mode=0o700)
assert hashlib.sha256(pathlib.Path(c['source']).read_bytes()).hexdigest()==c['source_sha256']
subprocess.run(['python3','tools/verify-frozen-build-inputs.py',c['source'],c['source_commit']],check=True)
with tarfile.open(c['source']) as archive:archive.extractall(frozen,filter='data')
env=dict(os.environ,RUSTFLAGS='-C relocation-model=static',CC_x86_64_unknown_linux_musl=str(root/'target/toolchains/x86_64-linux-musl-cc'),CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER='rust-lld',CARGO_TARGET_DIR=str((out/'build').resolve()),CARGO_BUILD_JOBS='2')
a=['cargo','test','--locked','--release','--target','x86_64-unknown-linux-musl','-p','vprouter-launch','--test','execution_probe','--test','execution_lab','--test','producer_lab','--no-run','--message-format=json']
r=subprocess.run(a,cwd=frozen,env=env,capture_output=True,text=True);(out/'build.stderr').write_text(r.stderr);assert r.returncode==0,r.stderr
artifacts={}
for line in r.stdout.splitlines():
 if not line.startswith('{'):continue
 e=json.loads(line)
 if e.get('reason')=='compiler-artifact' and e.get('executable') and e['target']['name'] in ['execution_probe','execution_lab','producer_lab']:
  name=e['target']['name'];p=out/name;p.write_bytes(pathlib.Path(e['executable']).read_bytes());p.chmod(0o600);artifacts[name]={'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
assert set(artifacts)=={'execution_probe','execution_lab','producer_lab'}
opts=['-i',str(base/'id_ed25519'),'-o','IdentitiesOnly=yes','-o','UserKnownHostsFile='+str(base/'known_hosts'),'-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=5'];ssh=['ssh',*opts,'-p22032','vprouterlab@127.0.0.1']
probe=artifacts['execution_probe'];temporary='/home/vprouterlab/shared-lease-probe-'+probe['sha256'];destination='/var/lib/vprouter-v2-lab/launch-execution-probe'
subprocess.run(['scp','-q',*opts,'-P22032',probe['path'],'vprouterlab@127.0.0.1:'+temporary],check=True)
subprocess.run(ssh+['sudo install -o root -g root -m 0555 '+temporary+' '+destination],check=True)
subprocess.run(ssh+['rm -- '+temporary],check=True)
check=subprocess.run(ssh+['sudo sha256sum '+destination],check=True,capture_output=True,text=True);assert check.stdout.split()[0]==probe['sha256']
records=[]
# Both harnesses are admitted by exact-payload producer runner; it creates an
# isolated network+mount namespace and artifact-bound marker before execution.
runner=(root/'tools/producer-placement-oracle.py').read_text();assert runner.count('808789d0d5d59b673c7f6fd55b306c3ecfc05ef0bbdd65731cff2ae7695bd828')==2
runner=runner.replace('808789d0d5d59b673c7f6fd55b306c3ecfc05ef0bbdd65731cff2ae7695bd828',probe['sha256'])
for name in ['execution_lab','producer_lab']:
 rp=out/(name+'.runner.py');rp.write_text(runner);p=artifacts[name]
 result=subprocess.run(['python3',str(rp),p['path'],p['sha256'],c['source'],c['source_sha256']],capture_output=True,text=True,timeout=100)
 (out/(name+'.json')).write_text(result.stdout);(out/(name+'.stderr')).write_text(result.stderr)
 records.append({'harness':name,'exit_code':result.returncode,'artifact':p,'source_commit':c['source_commit']});(out/'summary.json').write_text(json.dumps({'artifacts':artifacts,'records':records},indent=2)+'\n');print(name,result.returncode,flush=True)
 if result.returncode:raise SystemExit(result.returncode)
