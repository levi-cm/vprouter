"""Run the actual workspace suite while the sole writer holds a coherent freeze."""
import datetime,hashlib,json,pathlib,re,subprocess,sys,tarfile,time
candidate=json.loads(pathlib.Path(sys.argv[1]).read_text())
commit=candidate['source_commit'];assert re.fullmatch('[a-f0-9]{40}',commit)
def check_inputs():
 source=pathlib.Path(candidate['source']);assert hashlib.sha256(source.read_bytes()).hexdigest()==candidate['source_sha256']
 binding=json.loads(subprocess.check_output([sys.executable,'tools/verify-frozen-build-inputs.py',str(source),commit]));assert binding==candidate['binding']
 with tarfile.open(source) as archive:
  for member in archive:
   if member.isfile():assert pathlib.Path(member.name).read_bytes()==archive.extractfile(member).read(),member.name
check_inputs()
root=pathlib.Path('target/process-inspection-root-verification-20261027');log=root/('workspace-'+commit[:7]+'.log');record=root/('workspace-'+commit[:7]+'.json');assert not record.exists()
start=time.monotonic()
with log.open('x') as stream:
 result=subprocess.run(['cargo','test','--workspace','--locked'],stdout=stream,stderr=subprocess.STDOUT,timeout=300)
elapsed=time.monotonic()-start
check_inputs()
rows=re.findall(r'test result: \w+[.] (\d+) passed; (\d+) failed; (\d+) ignored;',log.read_text())
assert rows,'missing suite result rows'
passed,failed,ignored=(sum(int(row[i]) for row in rows) for i in range(3))
out=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_commit=commit,exit_code=result.returncode,passed=passed,failed=failed,ignored=ignored,elapsed_seconds=elapsed,log=str(log))
with record.open('x') as stream:json.dump(out,stream,indent=2);stream.write('\n')
print(json.dumps(out));sys.exit(result.returncode or bool(failed))
