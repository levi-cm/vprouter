import subprocess,pathlib,json,hashlib,sys,re,time
from datetime import datetime,timezone
assert len(sys.argv)==4,'usage: artifact sha256 source_commit'
artifact=pathlib.Path(sys.argv[1]);digest=sys.argv[2];source=sys.argv[3]
assert re.fullmatch('[a-f0-9]{64}',digest) and re.fullmatch('[a-f0-9]{40}',source)
assert hashlib.sha256(artifact.read_bytes()).hexdigest()==digest
subprocess.run(['git','diff','--exit-code',source,'--','crates/vprouter-worker','crates/vprouter-network','Cargo.toml','Cargo.lock'],check=True,stdout=subprocess.DEVNULL)
b=pathlib.Path('target/lab-state');opts=['-i',str(b/'id_ed25519'),'-o','IdentitiesOnly=yes','-o','UserKnownHostsFile='+str(b/'known_hosts'),'-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=5'];ssh=['ssh',*opts,'-p22032','vprouterlab@127.0.0.1']
temp='/home/vprouterlab/worker-localapi-lab-'+digest;dest='/var/lib/vprouter-v2-lab/worker-localapi-lab'
subprocess.run(['scp','-q',*opts,'-P22032',str(artifact),'vprouterlab@127.0.0.1:'+temp],check=True,timeout=15)
subprocess.run([*ssh,'sudo install -o root -g root -m 0555 '+temp+' '+dest],check=True,timeout=5)
r=subprocess.run([*ssh,'sudo sha256sum '+dest],check=True,capture_output=True,text=True,timeout=5);assert r.stdout.split()[0]==digest
subprocess.run([*ssh,'rm -- '+temp],check=True,timeout=5)
setup=pathlib.Path(__file__).with_name('worker-localapi-parser-guest.py');start=time.monotonic()
r=subprocess.run([*ssh,'sudo timeout --kill-after=3s 14s unshare --net --mount --propagation private python3 -'],input=setup.read_text(),capture_output=True,text=True,timeout=20)
e={'observed_at_utc':datetime.now(timezone.utc).isoformat(),'source_commit':source,'artifact_sha256':digest,'setup_sha256':hashlib.sha256(setup.read_bytes()).hexdigest(),'exit_code':r.returncode,'wall_seconds':round(time.monotonic()-start,3),'stdout':r.stdout,'stderr':r.stderr,'result':'PASS_NATIVE_LOCALAPI_PARSER_ONLY' if r.returncode==0 else 'FAIL','native_worker_placement':'NOT_RUN','native_tls_provider':'NOT_RUN','real_client_traffic':'NOT_RUN','production_changes':False}
attempt=1
while (b/f'worker-localapi-run-{attempt}.json').exists():attempt+=1
path=b/f'worker-localapi-run-{attempt}.json';assert not path.exists();path.write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(e,indent=2))
sys.exit(0 if r.returncode == 0 else 1)
