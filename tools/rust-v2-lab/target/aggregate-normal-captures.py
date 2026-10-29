"""Check fixed synthetic packet controls; never infer real-client protection."""
import json
import hashlib
import pathlib
import sys

if not __debug__:
    raise RuntimeError('optimized_python_refused')

p = pathlib.Path(sys.argv[1])
def read(path):
    return json.loads(pathlib.Path(path).read_text())

b = read(p / 'directory-binding.json')
c = read(p / 'captures.json')
m = read(p / 'metadata.json')
r = read(b['record'])
candidate = read(p.parent / 'candidate.json')
assert r['exit_code'] == 0 and r['source_binding'] == candidate['binding']
assert len(b['new_directories']) == 1 and c['directory'] == b['new_directories'][0]
assert b['source_commit'] == candidate['source_commit']
runner = {
    'debian-clean-x86_64': 'target/platform-lab/run-actual-monitor-debian-clean-x86_64.py',
    'arch-x86_64': 'target/platform-lab/run-actual-monitor-arch-x86_64.py',
}[b['platform']]
assert r['runner_sha256'] == hashlib.sha256(pathlib.Path(runner).read_bytes()).hexdigest()
if 'platform_lab' in r:
    assert b['platform'] == r['platform_lab']
else:
    assert b['platform'] == 'debian-clean-x86_64'
assert c['read_only'] is m['read_only'] is True
assert c['production_changes'] is m['production_changes'] is False
rows = c['captures']
assert len(rows) == 6
for x in rows:
    assert x['status'] == 'FRAMING_VERIFIED'
    assert x['records'] == x['capture_counters']['captured']
    assert x['capture_counters']['dropped_by_kernel'] == 0
    assert x['marker_occurrences']['forbidden_prefix'] == 0
by = {x['file']: x for x in rows}
assert by['actual-positive-data.pcap']['marker_occurrences']['positive_producer'] == 2
for f in ['actual-positive-transport.pcap', 'actual-positive-host.pcap']:
    assert by[f]['marker_occurrences']['positive_plaintext_control'] == 1
assert by['actual-negative-data.pcap']['marker_occurrences']['authorized_during_denial'] == 32
for f in ['actual-negative-transport.pcap', 'actual-negative-host.pcap']:
    assert by[f]['marker_occurrences']['authorized_during_denial'] == 0
account = m['deployments'][0]['fixture_files']['actual-packet-accounting.json']['data']
expected = dict(authorized_roundtrips_during_denial=16, capture_kernel_drops=0,
    capture_planes=['data', 'transport', 'host'], kernel_permission_denials=16,
    locally_queued_sends=0, positive_controls=True, readiness=False,
    unauthorized_peer_receives=0, unauthorized_send_attempts=16)
assert json.dumps(account, sort_keys=True) == json.dumps(expected, sort_keys=True)
out = dict(platform=b['platform'], source_commit=b['source_commit'],
    record=b['record'], directory=c['directory'], capture_files=len(rows),
    packet_records=sum(x['records'] for x in rows), forbidden_markers=0,
    kernel_drops=0, real_client_acceptance='NOT_RUN',
    evidence_scope='isolated Starting/observer/daemon component only')
assert out['packet_records'] == 112
with (p / 'capture-aggregate.json').open('x') as stream:
    json.dump(out, stream, indent=2)
    stream.write('\n')
print(json.dumps(out))
