"""Controller-only fixed producer-gate payload runner in the owned local VM.

No actual observer/Go execution, identity state, usable transport or traffic
acceptance is authorized by this runner. Retain every failed attempt.
"""
import datetime
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import sys
import time


def main():
    assert len(sys.argv) == 5, 'usage: artifact sha256 source_archive source_sha256'
    artifact, digest, source, source_digest = sys.argv[1:]
    base = pathlib.Path('target/lab-state')
    for value in (digest, source_digest):
        assert re.fullmatch(r'[a-f0-9]{64}', value)
    for path, expected, suffix in ((artifact, digest, 'payload'),
                                   (source, source_digest, 'source.tar')):
        assert hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest() == expected
        retained = base / ('task8b1-' + expected + '.' + suffix)
        if retained.exists():
            assert hashlib.sha256(retained.read_bytes()).hexdigest() == expected
        else:
            with retained.open('xb') as output, pathlib.Path(path).open('rb') as input_file:
                shutil.copyfileobj(input_file, output)
            retained.chmod(0o600)
    opts = ['-i', str(base / 'id_ed25519'), '-o', 'IdentitiesOnly=yes', '-o',
            'UserKnownHostsFile=' + str(base / 'known_hosts'), '-o',
            'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=5']
    ssh = ['ssh', *opts, '-p22032', 'vprouterlab@127.0.0.1']
    temporary = '/home/vprouterlab/task8b1-' + digest
    destination = '/var/lib/vprouter-v2-lab/task8b1-payload-' + digest
    guest = r'''
import hashlib,json,os,pathlib,stat,subprocess
root=pathlib.Path('/var/lib/vprouter-v2-lab')
assert os.geteuid()==0
for p in [pathlib.Path('/'),pathlib.Path('/var'),pathlib.Path('/var/lib'),root]:
 s=p.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and s.st_gid==0 and not s.st_mode&0o022
assert stat.S_IMODE(root.lstat().st_mode)==0o700
def regular(p,mode):
 s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==mode
regular(root/'isolated-acceptance',0o600)
digest=DIGEST
payload=root/('task8b1-payload-'+digest)
regular(payload,0o555)
assert hashlib.sha256(payload.read_bytes()).hexdigest()==digest
probe=root/'launch-execution-probe'
regular(probe,0o555)
assert hashlib.sha256(probe.read_bytes()).hexdigest()=='808789d0d5d59b673c7f6fd55b306c3ecfc05ef0bbdd65731cff2ae7695bd828'
net=pathlib.Path('/proc/self/ns/net').stat();init=pathlib.Path('/proc/1/ns/net').stat()
assert (net.st_dev,net.st_ino)!=(init.st_dev,init.st_ino)
marker=root/'task8b1-producer-acceptance'
content={'artifact_sha256':digest,'network_dev':net.st_dev,'network_ino':net.st_ino}
fd=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'w') as f:
 json.dump(content,f);f.flush();os.fsync(f.fileno())
print(json.dumps({'preflight':'PASS','network_namespace':{'dev':net.st_dev,'ino':net.st_ino},'probe_sha256':'808789d0d5d59b673c7f6fd55b306c3ecfc05ef0bbdd65731cff2ae7695bd828'}),flush=True)
try:
 result=subprocess.run(['timeout','--kill-after=3s','60s',str(payload),'--ignored'],timeout=66)
 print(json.dumps({'harness_exit_code':result.returncode}),flush=True)
finally:
 regular(marker,0o600);assert json.loads(marker.read_text())==content;marker.unlink()
raise SystemExit(result.returncode)
'''.replace('DIGEST', repr(digest))
    started = time.monotonic()
    code, stdout, stderr = 1, '', ''
    try:
        subprocess.run(['scp', '-q', *opts, '-P22032', artifact,
                        'vprouterlab@127.0.0.1:' + temporary], check=True, timeout=20,
                       capture_output=True, text=True)
        subprocess.run([*ssh, 'sudo install -o root -g root -m 0555 ' + temporary + ' ' + destination],
                       check=True, timeout=8, capture_output=True, text=True)
        subprocess.run([*ssh, 'rm -- ' + temporary], check=True, timeout=8,
                       capture_output=True, text=True)
        result = subprocess.run([*ssh, 'sudo unshare --net --mount --propagation private python3 -'],
                                input=guest, capture_output=True, text=True, timeout=78)
        code, stdout, stderr = result.returncode, result.stdout, result.stderr
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        code = error.returncode if isinstance(error, subprocess.CalledProcessError) else 124
        def decoded(value):
            return value.decode(errors='replace') if isinstance(value, bytes) else (value or '')
        stdout, stderr = decoded(error.stdout), decoded(error.stderr)
    evidence = {'observed_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'artifact_sha256': digest, 'source_archive_sha256': source_digest,
                'runner_sha256': hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
                'exit_code': code, 'wall_seconds': round(time.monotonic() - started, 3),
                'stdout': stdout, 'stderr': stderr,
                'result': 'PASS_PARTIAL_PRODUCER_GATE' if code == 0 else 'FAIL',
                'actual_observer_execution': 'NOT_RUN', 'go_execution': 'NOT_RUN',
                'real_client_acceptance': 'NOT_RUN', 'production_changes': False}
    attempt = 1
    while (base / f'producer-placement-run-{attempt}.json').exists():
        attempt += 1
    path = base / f'producer-placement-run-{attempt}.json'
    with path.open('x') as output:
        json.dump(evidence, output, indent=2)
        output.write('\n')
    path.chmod(0o600)
    print(json.dumps(evidence, indent=2))
    return 0 if code == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
