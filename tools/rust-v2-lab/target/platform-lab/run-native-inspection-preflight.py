"""Execute only the exact frozen rootless selftest in a pinned local lab VM.

This is ABI/syscall preflight, not a functional network oracle or release gate.
It does not consume actual-program run numbers, use sudo, or load credentials.
Retain both executable and result; never remove a failed attempt.
"""
import datetime
import hashlib
import json
import pathlib
import re
import shlex
import subprocess
import sys


if not __debug__:raise RuntimeError('optimized_python_refused')
mechanics_path=pathlib.Path(__file__).with_name('selftest_mechanics.py')
mechanics_bytes=mechanics_path.read_bytes()
mechanics_namespace={'__name__':'frozen_selftest_mechanics','__file__':str(mechanics_path)}
exec(compile(mechanics_bytes,str(mechanics_path),'exec'),mechanics_namespace)
validate_mechanics=mechanics_namespace['validate_mechanics']

candidate_path = pathlib.Path(sys.argv[1])
platform = sys.argv[2]
choices = {
    "debian-x86_64": ("amd64", "x86_64", 22032, "target/lab-state/known_hosts"),
    "debian-arm64": ("arm64", "aarch64", 22034, "target/platform-lab/debian-arm64/known_hosts"),
    "arch-x86_64": ("amd64", "x86_64", 22033, "target/platform-lab/arch-x86_64/known_hosts"),
    "void-x86_64": ("amd64", "x86_64", 22035, "target/platform-lab/void-x86_64/known_hosts"),
}
arch, machine, port, known = choices[platform]
candidate = json.loads(candidate_path.read_text())
commit = candidate["source_commit"]
assert re.fullmatch(r"[a-f0-9]{40}", commit)
source = pathlib.Path(candidate["source"])
assert hashlib.sha256(source.read_bytes()).hexdigest() == candidate["source_sha256"]
binding = json.loads(subprocess.check_output([
    sys.executable, "tools/verify-frozen-build-inputs.py", str(source), commit,
]))
assert binding == candidate["binding"]
artifact = candidate["platforms"][arch]
payload = pathlib.Path(artifact["artifact"]).read_bytes()
digest = artifact["artifact_sha256"]
assert re.fullmatch(r"[a-f0-9]{64}", digest)
assert hashlib.sha256(payload).hexdigest() == digest
output = candidate_path.parent / ("native-preflight-" + platform)
output.mkdir(mode=0o700)
remote = r'''
import hashlib,json,os,pathlib,platform,subprocess,sys,tempfile
if not __debug__:raise RuntimeError('optimized_python_refused')
commit,digest,machine=sys.argv[1:]
assert platform.machine()==machine
assert os.getuid()!=0 and os.geteuid()!=0
payload=sys.stdin.buffer.read(67108865)
assert len(payload)<=67108864 and hashlib.sha256(payload).hexdigest()==digest
directory=pathlib.Path(tempfile.mkdtemp(prefix='vprouter-frozen-preflight-'+commit[:12]+'-',dir=pathlib.Path.home()))
path=directory/'payload'
fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o500)
with os.fdopen(fd,'wb') as stream:stream.write(payload)
assert hashlib.sha256(path.read_bytes()).hexdigest()==digest
command=[str(path),'--inspection-filter-selftest']
process=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
root_pid=process.pid
try:
 raw=pathlib.Path('/proc',str(root_pid),'stat').read_text()
 root_start=int(raw[raw.rfind(')')+2:].split()[19])
except FileNotFoundError:root_start=None
(directory/'birth.json').write_text(json.dumps({'source_commit':commit,'artifact_sha256':digest,'root_pid':root_pid,'root_start':root_start}))
try:
 stdout,stderr=process.communicate(timeout=60)
 data={'exit_code':process.returncode,'stdout':stdout,'stderr':stderr,'timed_out':False}
except subprocess.TimeoutExpired as error:
 # Popen has not reaped this child, so its numeric identity is not reusable.
 # Kill/reap this exact root only; no descendant or resource cleanup inferred.
 process.kill()
 process.wait(timeout=5)
 def decoded(value):return value.decode(errors='replace') if isinstance(value,bytes) else value
 stdout,stderr=decoded(error.output),decoded(error.stderr)
 process.stdout.close()
 process.stderr.close()
 data={'exit_code':process.returncode,'stdout':stdout,'stderr':stderr,'timed_out':True,'descendant_drain':'NOT_PROVEN'}
data.update(machine=platform.machine(),kernel=platform.release(),uid=os.geteuid(),artifact_sha256=digest,source_commit=commit,retained_executable=str(path),arguments=command[1:],root_pid=root_pid,root_start=root_start,root_reaped=True)
assert hashlib.sha256(path.read_bytes()).hexdigest()==digest
print(json.dumps(data))
'''
command = [
    "ssh", "-i", "target/lab-state/id_ed25519", "-p" + str(port),
    "-o", "UserKnownHostsFile=" + known, "-o", "StrictHostKeyChecking=yes",
    "-o", "ConnectTimeout=5", "vprouterlab@127.0.0.1",
    "python3 -I -c " + shlex.quote(remote) + " " + shlex.quote(commit)
    + " " + shlex.quote(digest) + " " + shlex.quote(machine),
]
result = subprocess.run(command, input=payload, capture_output=True, timeout=80)
(output / "ssh.stdout").write_bytes(result.stdout)
(output / "ssh.stderr").write_bytes(result.stderr)
record = {
    "observed_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "source_commit": commit, "source_archive_sha256": candidate["source_sha256"],
    "source_binding": binding, "artifact_sha256": digest, "platform": platform,
    "ssh_exit_code": result.returncode,
    "scope": "unprivileged exact frozen native VM selftest only; no enrolled/network/release acceptance",
}
if result.returncode == 0:
    record["result"] = json.loads(result.stdout)
mechanics_ok=True
if result.returncode==0 and record['result']['exit_code']==0 and not record['result']['timed_out']:
    try:record['mechanical_protocol']=validate_mechanics(source,record['result']['stdout'])
    except (AssertionError,ValueError,KeyError,TypeError)as error:
        mechanics_ok=False;record['mechanical_protocol']={'validation_failed':True,'error_type':type(error).__name__}
record['mechanics_validator_sha256']=hashlib.sha256(mechanics_bytes).hexdigest()
with(output/'mechanics-validator.py').open('xb')as stream:stream.write(mechanics_bytes)
(output/'mechanics-validator.py').chmod(0o600)

with (output / "record.json").open("x") as stream:
    json.dump(record, stream, indent=2)
    stream.write("\n")
print(json.dumps(record, indent=2))
if result.returncode:
    raise SystemExit(result.returncode)
data = record["result"]
assert data["source_commit"] == commit and data["artifact_sha256"] == digest
assert data["machine"] == machine and data["uid"] != 0
assert not data["timed_out"] and data["exit_code"] == 0, data

assert mechanics_ok, 'mechanical_protocol_validation_failed'
