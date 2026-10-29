import datetime,hashlib,json,pathlib,subprocess,sys,uuid
platform=sys.argv[1]
port,known={'debian-clean-x86_64':(22036,'target/platform-lab/debian-clean-x86_64/known_hosts'),'arch-x86_64':(22033,'target/platform-lab/arch-x86_64/known_hosts'),'debian-arm64':(22034,'target/platform-lab/debian-arm64/known_hosts')}[platform]
source=pathlib.Path('target/platform-lab/explicit-ifindex.guest.py').read_bytes();compile(source,'explicit-ifindex.guest.py','exec')
out=pathlib.Path('target/lab-state')/('explicit-ifindex-'+platform+'-'+uuid.uuid4().hex);out.mkdir(mode=0o700)
start=datetime.datetime.now(datetime.timezone.utc)
r=subprocess.run(['ssh','-i','target/lab-state/id_ed25519','-p'+str(port),'-o','UserKnownHostsFile='+known,'-o','StrictHostKeyChecking=yes','vprouterlab@127.0.0.1','sudo -n python3 -I -'],input=source,capture_output=True,timeout=75)
(out/'guest.py').write_bytes(source);(out/'stdout').write_bytes(r.stdout);(out/'stderr').write_bytes(r.stderr)
phases=[]
for line in r.stdout.splitlines():
 try:phases.append(json.loads(line))
 except ValueError:pass
record=dict(observed_at_utc=start.isoformat(),platform=platform,guest_sha256=hashlib.sha256(source).hexdigest(),exit_code=r.returncode,phases=phases,stderr=r.stderr.decode(errors='replace'),functional_oracle_counter_unchanged=True,provider_profiles_used=False,runtime_authority=False,disposable_detached_namespaces_only=True)
with (out/'record.json').open('x') as f:json.dump(record,f,indent=2);f.write('\n')
print(json.dumps(dict(record=str(out/'record.json'),exit_code=r.returncode,final=phases[-1] if phases and phases[-1].get('probe_phase')=='PASS' else ({'probe_phase':phases[-1].get('probe_phase'),'native_ack_errno':(phases[-1].get('value') or {}).get('native_ack_errno') if isinstance(phases[-1].get('value'),dict) else None} if phases else None),stderr=r.stderr.decode(errors='replace')[-1500:])))
raise SystemExit(r.returncode)
