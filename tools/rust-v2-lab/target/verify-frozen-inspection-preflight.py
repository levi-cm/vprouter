"""Root-only, unprivileged preflight of the exact frozen x86 payload."""
import datetime
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tarfile

if not __debug__:raise RuntimeError('optimized_python_refused')
mechanics_path=pathlib.Path('target/platform-lab/selftest_mechanics.py')
mechanics_bytes=mechanics_path.read_bytes()
mechanics_namespace={'__name__':'frozen_selftest_mechanics','__file__':str(mechanics_path)}
exec(compile(mechanics_bytes,str(mechanics_path),'exec'),mechanics_namespace)
validate_mechanics=mechanics_namespace['validate_mechanics']
candidate_path = pathlib.Path(sys.argv[1])
candidate = json.loads(candidate_path.read_text())
commit = candidate['source_commit']
assert re.fullmatch('[a-f0-9]{40}', commit)
root = pathlib.Path.cwd()
output = root / 'target/process-inspection-root-verification-20261027'
output.mkdir(mode=0o700, exist_ok=True)
source = pathlib.Path(candidate['source'])
assert hashlib.sha256(source.read_bytes()).hexdigest() == candidate['source_sha256']
binding = json.loads(subprocess.check_output([
    sys.executable, 'tools/verify-frozen-build-inputs.py', str(source), commit,
]))
assert binding == candidate['binding']
with tarfile.open(source) as archive:
    descriptor_expected = b'"--normal-fixture-descriptor"' in archive.extractfile(
        'crates/vprouter-launch/src/actual_lab_main.rs'
    ).read()
mismatches = []
count = 0
with tarfile.open(source) as archive:
    for member in archive:
        if not member.isfile():
            continue
        path = pathlib.PurePosixPath(member.name)
        assert not path.is_absolute() and '..' not in path.parts
        count += 1
        current = root / member.name
        if not current.is_file() or current.read_bytes() != archive.extractfile(member).read():
            mismatches.append(member.name)
assert not mismatches, mismatches
assert count == binding['tracked_build_inputs_verified']
platform = candidate['platforms']['amd64']
artifact = pathlib.Path(platform['artifact']).read_bytes()
digest = platform['artifact_sha256']
assert hashlib.sha256(artifact).hexdigest() == digest
executable = output / ('musl-preflight-' + digest)
if not executable.exists():
    fd = os.open(executable, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o500)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(artifact)
assert not executable.is_symlink() and hashlib.sha256(executable.read_bytes()).hexdigest() == digest
result = subprocess.run([str(executable), '--inspection-filter-selftest'], capture_output=True, text=True, timeout=15)
descriptor = None
descriptor_ok = True
if result.returncode == 0 and descriptor_expected:
    described = subprocess.run([str(executable), '--normal-fixture-descriptor'], capture_output=True, text=True, timeout=5)
    expected = {'schema': 1, 'endpoint_policy': 'bounded-nonce-18566-v1', 'candidate_limit': 16, 'exclusive_add_only': True}
    try:
        value = json.loads(described.stdout)
    except ValueError:
        value = None
    descriptor_ok = described.returncode == 0 and not described.stderr and value == expected
    descriptor = {'exit_code': described.returncode, 'matches_closed_policy': descriptor_ok, 'value': value, 'stderr': described.stderr}
mechanics_ok=True;mechanics=None
if result.returncode==0:
    try:mechanics=validate_mechanics(source,result.stdout)
    except (AssertionError,ValueError,KeyError,TypeError)as error:
        mechanics_ok=False;mechanics={'validation_failed':True,'error_type':type(error).__name__}
mechanics_sha=hashlib.sha256(mechanics_bytes).hexdigest()
mechanics_saved=output/('mechanics-'+mechanics_sha+'.py')
if not mechanics_saved.exists():
    with mechanics_saved.open('xb')as stream:stream.write(mechanics_bytes)
    mechanics_saved.chmod(0o600)
assert not mechanics_saved.is_symlink()and mechanics_saved.read_bytes()==mechanics_bytes
record = {
    'observed_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'source_commit': commit, 'source_sha256': candidate['source_sha256'],
    'source_files': count, 'source_mismatches': mismatches,
    'independent_source_binding': binding,
    'artifact_sha256': digest, 'arguments': ['--inspection-filter-selftest'],
    'exit_code': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr,
    'normal_fixture_descriptor': descriptor,
    'mechanical_protocol':mechanics,'mechanics_validator_sha256':mechanics_sha,'saved_mechanics_validator':str(mechanics_saved),
    'scope': 'unprivileged exact frozen x86 musl payload preflight; no VM acceptance',
}
record_path = output / ('frozen-preflight-' + commit + '.json')
with record_path.open('x') as stream:
    json.dump(record, stream, indent=2)
    stream.write('\n')
print(json.dumps(record, indent=2))
raise SystemExit(result.returncode if result.returncode else (0 if descriptor_ok and mechanics_ok else 1))
