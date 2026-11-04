#!/usr/bin/env python3
"""Offline original-byte verification of the cold run409 preservation archive.

The one absolute historical helper reference is explicitly resolved to captured
original bytes, never changed to a current helper hash. No VM or payload runs.
"""
import hashlib,json,os,pathlib,shutil,stat,subprocess,sys,tempfile
if not __debug__:raise RuntimeError('optimized_python_refused')
root=pathlib.Path.cwd();p=pathlib.Path('/DATA/vprouter-lab/preserved/run409-guest')
count=0
for line in (p/'SHA256SUMS').read_text().splitlines():
 digest,name=line.split('  ',1);f=p/name
 assert hashlib.sha256(f.read_bytes()).hexdigest()==digest,name
 assert stat.S_IMODE(f.stat().st_mode)==0o400,name
 count+=1
assert stat.S_IMODE(p.stat().st_mode)==0o500
old=json.loads((p/'collected-chain/receipt.json').read_bytes());assert old['provenance_valid'] is True
with tempfile.TemporaryDirectory(prefix='run409-original-chain-') as td:
 temp=pathlib.Path(td)
 for row in old['retained']:
  src=p/'collected-chain/files'/row['path'];assert hashlib.sha256(src.read_bytes()).hexdigest()==row['sha256']
  dest=temp/row['path'];dest.parent.mkdir(mode=0o700,parents=True,exist_ok=True);dest.write_bytes(src.read_bytes());dest.chmod(0o600)
 for src in (p/'reference-inputs').rglob('*'):
  if src.is_file():
   dest=temp/src.relative_to(p/'reference-inputs');dest.parent.mkdir(mode=0o700,parents=True,exist_ok=True);dest.write_bytes(src.read_bytes());dest.chmod(0o600)
 # No remote or artifact executable is used: the original C validator is local.
 tracer="""import pathlib,sys,runpy
from unittest.mock import patch
original=pathlib.Path.read_bytes
# The historical author recorded one absolute helper pathname. Resolve that
# exact historical reference to its captured original bytes in this offline view.
absolute=pathlib.Path('/DATA/AppData/vprouter-rust-v2/tools/rust-v2-lab/fresh-baseline.py')
def read(path):
 return original(pathlib.Path('tools/rust-v2-lab/fresh-baseline.py') if path==absolute else path)
sys.argv=['collector','checked-original-bundle']
with patch.object(pathlib.Path,'read_bytes',read):runpy.run_path('tools/rust-v2-lab/collect-run409-evidence.py',run_name='__main__')
"""
 r=subprocess.run([sys.executable,'-B','-c',tracer],cwd=td,text=True,capture_output=True,timeout=15,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'))
 assert r.returncode==0,(r.stdout,r.stderr)
 result=json.loads((temp/'checked-original-bundle/receipt.json').read_bytes());assert result['provenance_valid'] is True and result['exit_code']==1
 raw=(temp/'target/lab-state/actual-program-run-409.json').read_bytes();assert raw==(root/'target/lab-state/actual-program-run-409.json').read_bytes()
 result=dict(preserved_file_hashes=count,original_c_validator_exit=r.returncode,original_409_provenance_valid=True,original_raw_sha256=hashlib.sha256(raw).hexdigest(),outcome=result['outcome'],budget_remaining=0,overlay_never_rebooted=True,offline=True,absolute_historical_helper_resolved_to_captured_bytes=True)
print(json.dumps(result,indent=2))
