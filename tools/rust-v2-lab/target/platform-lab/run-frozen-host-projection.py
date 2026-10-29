"""Root's read-only lab projection collector; never authors or stages authority."""
import datetime
import hashlib
import json
import pathlib
import re
import shlex
import subprocess
import sys
import tarfile

if not __debug__:
    raise RuntimeError('optimized_python_refused')

controller_bytes = pathlib.Path(__file__).read_bytes()

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate_json_key')
        result[key] = value
    return result

def invalid_constant(value):
    raise ValueError('nonfinite_json_constant')

def loads(raw):
    return json.loads(raw, object_pairs_hook=unique_object, parse_constant=invalid_constant)

def identity_pair(value):
    assert isinstance(value, list) and len(value) == 2
    assert all(type(n) is int and 0 < n <= 18446744073709551615 for n in value)

def validate_projection_envelope(data, machine):
    assert set(data) == {'uid', 'machine', 'root_pid', 'root_start', 'root_reaped',
        'exit_code', 'timed_out', 'before', 'after', 'retained_executable', 'stdout', 'stderr'}
    assert type(data['uid']) is int and 0 < data['uid'] <= 4294967295
    assert type(data['root_pid']) is int and 1 < data['root_pid'] <= 4294967295
    assert type(data['root_start']) is int and 0 < data['root_start'] <= 18446744073709551615
    assert data['machine'] == machine and data['root_reaped'] is True and data['timed_out'] is False
    assert type(data['exit_code']) is int and data['exit_code'] == 0
    assert type(data['stdout']) is str and type(data['stderr']) is str and not data['stderr']
    assert type(data['retained_executable']) is str
    assert all(type(data[k]) in (float, int) and 0 <= data[k] <= 1e12 for k in ('before', 'after'))
    assert data['before'] <= data['after']
    report = loads(data['stdout'])
    assert set(report) == {'schema', 'creator_pid', 'creator_start', 'namespace', 'route_socket',
        'requested_at', 'deadline', 'verified_at', 'polls', 'projection', 'read_only',
        'declaration_authority', 'host_change_authority'}
    assert type(report['schema']) is int and report['schema'] == 1
    assert type(report['creator_pid']) is int and 1 < report['creator_pid'] <= 4294967295
    assert report['creator_pid'] == data['root_pid']
    assert type(report['creator_start']) is int and 0 < report['creator_start'] <= 18446744073709551615
    assert report['creator_start'] == data['root_start']
    assert type(report['polls']) is int and 1 <= report['polls'] <= 4294967295
    assert all(type(report[k]) in (float, int) and 0 <= report[k] <= 1e12
        for k in ('requested_at', 'deadline', 'verified_at'))
    assert data['before'] <= report['requested_at'] <= report['verified_at'] < report['deadline']
    assert report['deadline'] == report['requested_at'] + 2 and report['verified_at'] <= data['after']
    assert report['read_only'] is True
    assert report['declaration_authority'] is report['host_change_authority'] is False
    identity_pair(report['namespace'])
    assert set(report['route_socket']) == {'dev', 'ino'}
    identity_pair([report['route_socket']['dev'], report['route_socket']['ino']])
    assert report['namespace'] == report['projection']['namespace']
    assert set(report['projection']) == {'namespace', 'links', 'addresses', 'routes', 'rules'}
    assert all(type(report['projection'][k]) is list for k in ('links', 'addresses', 'routes', 'rules'))
    assert len(json.dumps(report['projection'], separators=(',', ':')).encode()) <= 128 * 1024
    assert sum(len(report['projection'][k]) for k in ('links', 'addresses', 'routes', 'rules')) <= 4096
    return report

def validate_projection_failure(data, machine):
    assert set(data) == {'uid', 'machine', 'root_pid', 'root_start', 'root_reaped',
        'exit_code', 'timed_out', 'before', 'after', 'retained_executable', 'stdout', 'stderr'}
    assert type(data['uid']) is int and 0 < data['uid'] <= 4294967295
    assert type(data['root_pid']) is int and 1 < data['root_pid'] <= 4294967295
    assert type(data['root_start']) is int and 0 < data['root_start'] <= 18446744073709551615
    assert data['machine'] == machine and data['root_reaped'] is True and data['timed_out'] is False
    assert type(data['exit_code']) is int and data['exit_code'] == 1
    assert type(data['stdout']) is str and data['stdout'] == ''
    assert type(data['stderr']) is str and len(data['stderr']) <= 4096
    assert type(data['retained_executable']) is str
    assert all(type(data[k]) in (float, int) and 0 <= data[k] <= 1e12 for k in ('before', 'after'))
    assert data['before'] <= data['after']
    lines = data['stderr'].splitlines()
    marker = 'LAB_HOST_ROUTE_PROJECTION_FAILURE '
    assert len(lines) == 2 and lines[0].startswith(marker)
    assert lines[1] == 'host_route_projection: network_operation'
    report = loads(lines[0][len(marker):])
    assert set(report) == {'schema', 'creator_pid', 'creator_start', 'requested_at',
        'deadline', 'stage', 'polls', 'reason'}
    assert type(report['schema']) is int and report['schema'] == 1
    assert type(report['creator_pid']) is int and report['creator_pid'] == data['root_pid']
    assert type(report['creator_start']) is int and report['creator_start'] == data['root_start']
    assert all(type(report[k]) in (float, int) and 0 <= report[k] <= 1e12
        for k in ('requested_at', 'deadline'))
    assert data['before'] <= report['requested_at'] <= data['after']
    assert report['deadline'] == report['requested_at'] + 2
    assert report['stage'] in ('open', 'start_read', 'poll_read')
    assert type(report['polls']) is int and 0 <= report['polls'] <= 4294967295
    assert (report['polls'] > 0) == (report['stage'] == 'poll_read')
    reason = report['reason']
    fixed = {'InvalidInput', 'DirectUnsupported', 'Foreign', 'Drifted', 'HostDrift',
        'TransportDrift', 'DataDrift', 'Absent', 'Unsupported', 'Malformed', 'Oversized',
        'Deadline', 'SocketUnavailable', 'Io', 'KernelRejected', 'SequenceMismatch',
        'SenderMismatch', 'Interrupted', 'NamespaceUnverified', 'LabRequired'}
    assert type(reason) is str
    if reason not in fixed:
        match = re.fullmatch(r'(UnsupportedLinkAttribute|UnsupportedLinkInfo|UnsupportedAddressAttribute|UnsupportedRouteAttribute|KernelErrno)\((-?[0-9]+)\)', reason)
        assert match is not None
        code = int(match[2])
        assert (-2147483648 <= code <= 2147483647) if match[1] == 'KernelErrno' else (0 <= code <= 65535)
    if reason == 'Deadline':
        assert data['after'] >= report['deadline']
    return report

candidate_path = pathlib.Path(sys.argv[1])
platform = sys.argv[2]
choices = {
    'debian-clean-x86_64': ('amd64', 22036, 'target/platform-lab/debian-clean-x86_64/known_hosts'),
    'debian-x86_64': ('amd64', 22032, 'target/lab-state/known_hosts'),
    'arch-x86_64': ('amd64', 22033, 'target/platform-lab/arch-x86_64/known_hosts'),
    'debian-arm64': ('arm64', 22034, 'target/platform-lab/debian-arm64/known_hosts'),
}
arch, port, known = choices[platform]
c = loads(candidate_path.read_text())
assert re.fullmatch('[a-f0-9]{40}', c['source_commit'])
source = pathlib.Path(c['source'])
assert hashlib.sha256(source.read_bytes()).hexdigest() == c['source_sha256']
with tarfile.open(source) as archive:
    main = archive.extractfile('crates/vprouter-launch/src/actual_lab_main.rs').read()
    failure_diagnostic = b'LAB_HOST_ROUTE_PROJECTION_FAILURE' in archive.extractfile(
        'crates/vprouter-launch/src/actual_lab.rs').read()
    if b'"--host-route-projection"' not in main:
        raise RuntimeError('frozen_source_missing_metadata_only_host_projection')
v = c['platforms'][arch]
payload = pathlib.Path(v['artifact']).read_bytes()
assert hashlib.sha256(payload).hexdigest() == v['artifact_sha256']
binding = json.loads(subprocess.check_output([
    sys.executable, 'tools/verify-frozen-build-inputs.py', str(source), c['source_commit']]))
assert binding == c['binding']

remote = r'''
import hashlib,json,os,pathlib,platform,subprocess,sys,tempfile,time
if not __debug__:raise RuntimeError('optimized_python_refused')
digest,commit,machine=sys.argv[1:]
assert platform.machine()==machine and os.getuid()==os.geteuid()!=0
payload=sys.stdin.buffer.read(67108865)
assert len(payload)<=67108864 and hashlib.sha256(payload).hexdigest()==digest
directory=pathlib.Path(tempfile.mkdtemp(prefix='vprouter-host-projection-'+commit[:12]+'-',dir=pathlib.Path.home()))
executable=directory/'payload'
fd=os.open(executable,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o500)
with os.fdopen(fd,'wb')as stream:stream.write(payload)
before=time.clock_gettime(time.CLOCK_BOOTTIME)
process=subprocess.Popen([str(executable),'--host-route-projection'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
root_pid=process.pid
try:
 raw=pathlib.Path('/proc',str(root_pid),'stat').read_text()
 root_start=int(raw[raw.rfind(')')+2:].split()[19])
except FileNotFoundError:root_start=None
timed_out=False
try:stdout,stderr=process.communicate(timeout=15)
except subprocess.TimeoutExpired:
 timed_out=True
 process.kill()
 stdout,stderr=process.communicate(timeout=5)
after=time.clock_gettime(time.CLOCK_BOOTTIME)
assert len(stdout)<=262144 and len(stderr)<=65536
assert hashlib.sha256(executable.read_bytes()).hexdigest()==digest
print(json.dumps(dict(uid=os.geteuid(),machine=platform.machine(),root_pid=root_pid,
 root_start=root_start,root_reaped=True,exit_code=process.returncode,timed_out=timed_out,
 before=before,after=after,retained_executable=str(executable),stdout=stdout.decode(),stderr=stderr.decode())))
'''
out = candidate_path.parent / ('host-projection-' + platform)
out.mkdir(mode=0o700)
with (out / 'controller.py').open('xb') as stream:
    stream.write(controller_bytes)
machine = {'amd64': 'x86_64', 'arm64': 'aarch64'}[arch]
command = ['ssh', '-i', 'target/lab-state/id_ed25519', '-p' + str(port),
    '-o', 'IdentitiesOnly=yes', '-o', 'UserKnownHostsFile=' + known,
    '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=5',
    'vprouterlab@127.0.0.1', 'python3 -I -c ' + shlex.quote(remote) + ' '
    + ' '.join(map(shlex.quote, [v['artifact_sha256'], c['source_commit'], machine]))]
result = subprocess.run(command, input=payload, capture_output=True, timeout=45)
(out / 'ssh.stdout').write_bytes(result.stdout)
(out / 'ssh.stderr').write_bytes(result.stderr)
assert result.returncode == 0
data = loads(result.stdout)
if data['exit_code'] != 0:
    assert failure_diagnostic, 'frozen_source_missing_fixed_projection_failure_diagnostic'
    failure = validate_projection_failure(data, machine)
    refusal = dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        result='REFUSED', source_binding=binding, artifact_sha256=v['artifact_sha256'],
        platform=platform, controller_sha256=hashlib.sha256(controller_bytes).hexdigest(),
        remote=data, failure=failure, declaration_staged=False, host_authority_granted=False,
        production_changes=False, private_profile_contents_read=False,
        scope='Failed GET-only read. No accepted projection or declaration authority; fixed diagnostic only.')
    with (out / 'refusal.json').open('x') as stream:
        json.dump(refusal, stream, indent=2)
        stream.write('\n')
    print(json.dumps(dict(record=str(out / 'refusal.json'), result='REFUSED',
        stage=failure['stage'], reason=failure['reason'], host_authority_granted=False)))
    raise SystemExit(1)
report = validate_projection_envelope(data, machine)
record = dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    source_binding=binding, artifact_sha256=v['artifact_sha256'], platform=platform,
    controller_sha256=hashlib.sha256(controller_bytes).hexdigest(),
    remote=data, report=report, declaration_staged=False, host_authority_granted=False,
    production_changes=False, private_profile_contents_read=False,
    scope='Public metadata and original read provenance only; independent reconciliation and an authored protected declaration are still required.')
with (out / 'record.json').open('x') as stream:
    json.dump(record, stream, indent=2)
    stream.write('\n')
print(json.dumps(dict(record=str(out / 'record.json'), platform=platform,
    declaration_staged=False, host_authority_granted=False)))
