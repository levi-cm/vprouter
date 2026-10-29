"""Root controller: sequential existing native regressions, stop on first failure."""
import json,pathlib,subprocess,sys
candidate='target/continuation-20261027T185926Z/candidate.json'
platform=sys.argv[1]
assert platform in ('debian-arm64','debian-clean-x86_64','arch-x86_64')
prefix={'debian-arm64':'arm64','debian-clean-x86_64':'amd64-clean','arch-x86_64':'arch'}[platform]
modes=sys.argv[2:]
assert modes and len(set(modes))==len(modes)and set(modes)<=set(['owner-retirement-global-stop','actual','owner-process-inspection','owner-retirement'])
for mode in modes:
 label=prefix+'-pollfix-'+mode
 log=pathlib.Path(candidate).parent/(label+'.root.log')
 with log.open('x')as f:
  result=subprocess.run([sys.executable,'target/platform-lab/run-frozen-platform-actual.py',candidate,platform,label,mode],stdout=f,stderr=subprocess.STDOUT)
 binding=json.loads((pathlib.Path(candidate).parent/label/'directory-binding.json').read_text())
 run=int(pathlib.Path(binding['record']).stem.rsplit('-',1)[1])
 print(json.dumps(dict(mode=mode,run=run,exit_code=result.returncode,log=str(log))),flush=True)
 if result.returncode:sys.exit(result.returncode)
 commands=[]
 if mode=='actual':commands.append(['target/platform-lab/collect-component-evidence.py',candidate,platform,label])
 if mode=='owner-retirement-global-stop':commands.extend([['target/collect-retirement-input-selection.py',candidate,label],['target/collect-owner-retirement-stop.py',candidate,label]])
 if mode=='owner-process-inspection':commands.extend([['target/collect-terminal-witness.py',candidate,platform,label,str(run)],['target/collect-handoff-profile.py',candidate,str(run)]])
 if mode=='owner-retirement':commands.extend([['target/collect-retirement-input-selection.py',candidate,label],['target/collect-owner-retirement.py',candidate,label]])
 for command in commands:subprocess.run([sys.executable,*command],check=True)
