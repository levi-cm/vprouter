import hashlib,json,os,pathlib,subprocess,sys,tarfile
root=pathlib.Path.cwd();base=root/'target/lab-state'
candidate_path=pathlib.Path(sys.argv[1])
candidate=json.loads(candidate_path.read_text())
out=candidate_path.parent/'transport';out.mkdir(mode=0o700)
frozen=out/'source';frozen.mkdir(mode=0o700)
with tarfile.open(candidate['source']) as archive:archive.extractall(frozen,filter='data')
env=dict(os.environ,RUSTFLAGS='-C relocation-model=static',
         CC_x86_64_unknown_linux_musl=str(root/'target/toolchains/x86_64-linux-musl-cc'),
         CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER='rust-lld',CARGO_TARGET_DIR=str((out/'build').resolve()),CARGO_BUILD_JOBS='2')
r=subprocess.run(['cargo','test','--locked','--release','--target','x86_64-unknown-linux-musl',
 '-p','vprouter-launch','--test','transport_lab','--no-run','--message-format=json'],
 env=env,cwd=frozen,capture_output=True,text=True,check=True)
events=[json.loads(line) for line in r.stdout.splitlines() if line.startswith('{')]
payload=pathlib.Path(next(e['executable'] for e in events if e.get('reason')=='compiler-artifact'
 and e['target']['name']=='transport_lab' and e.get('executable')))
artifact=out/'payload';artifact.write_bytes(payload.read_bytes());artifact.chmod(0o600)
digest=hashlib.sha256(artifact.read_bytes()).hexdigest()
ssh=['ssh','-i',str(base/'id_ed25519'),'-o','IdentitiesOnly=yes','-o',
 'UserKnownHostsFile='+str(base/'known_hosts'),'-o','StrictHostKeyChecking=yes',
 '-o','ConnectTimeout=5','-p22032','vprouterlab@127.0.0.1','sudo python3 -']
def guest(script):
 return subprocess.run(ssh,input=script,capture_output=True,text=True,check=True,timeout=25).stdout
def directories():
 return set(json.loads(guest("import json,pathlib;print(json.dumps([str(p) for p in pathlib.Path('/var/lib/vprouter-v2-lab').glob('task8a-[0-9]*') if p.is_dir()]))")))
rows=[]
for scenario in ['reversible','deleted-wg','deleted-transport','cooperation-drift',
                 'foreign-collision','interrupted-activation','interrupted-cleanup']:
 before=directories()
 result=subprocess.run(['python3','tools/guarded-transport-oracle.py',str(artifact),digest,
  candidate['source'],candidate['source_sha256'],scenario],capture_output=True,text=True,timeout=95)
 (out/(scenario+'.controller.json')).write_text(result.stdout)
 (out/(scenario+'.controller.stderr')).write_text(result.stderr)
 record=json.loads(result.stdout)
 new=directories()-before;assert len(new)==1,new
 directory=new.pop()
 script=(root/'tools/guarded-transport-inspect-guest.py').read_text().replace(
  "for d in root.glob('task8a-*'):","for d in [pathlib.Path("+repr(directory)+")]:")
 inventory=out/(scenario+'.inventory.json');inventory.write_text(guest(script))
 captures=out/(scenario+'.captures.json')
 with captures.open('w') as stream:
  subprocess.run(['python3','tools/guarded-transport-capture-oracle.py',directory],stdout=stream,check=True)
 cleanup=out/(scenario+'.cleanup.json')
 with cleanup.open('w') as stream:
  subprocess.run(['python3','tools/guarded-transport-cleanup-wan.py',str(inventory),directory],stdout=stream,check=True)
 rows.append({'scenario':scenario,'exit_code':record['exit_code'],'directory':directory,
              'artifact_sha256':digest,'source_commit':candidate['source_commit'],
              'controller_record':str(out/(scenario+'.controller.json')),
              'inventory':str(inventory),'captures':str(captures),'cleanup':str(cleanup)})
 (out/'summary.json').write_text(json.dumps(rows,indent=2)+'\n')
 print(scenario,record['result'],flush=True)
 if result.returncode:sys.exit(result.returncode)
