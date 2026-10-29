"""Root-only sequential fixed cases; stop on any oracle or collector failure."""
import json,pathlib,re,subprocess,sys
if not __debug__:raise RuntimeError('optimized_python_refused')
candidate=pathlib.Path(sys.argv[1]);platform,prefix=sys.argv[2:4];modes=sys.argv[4:]
assert platform in('debian-clean-x86_64','debian-x86_64','debian-arm64','arch-x86_64')and re.fullmatch('[a-z0-9_-]+',prefix)
assert modes and len(set(modes))==len(modes)and set(modes)<=set(['success','postbirth-failure','result-failure','registration-failure'])
for mode in modes:
 label=prefix+'-'+mode;log=candidate.parent/(label+'.root.log');assert not(candidate.parent/label).exists()
 with log.open('x')as stream:
  result=subprocess.run([sys.executable,'target/platform-lab/run-frozen-secret-movement.py',str(candidate),platform,label,mode],stdout=stream,stderr=subprocess.STDOUT)
 print(json.dumps(dict(mode=mode,exit_code=result.returncode,log=str(log))),flush=True)
 if result.returncode:raise SystemExit(result.returncode)
 subprocess.run([sys.executable,'target/collect-secret-movement.py',str(candidate),label],check=True)
