"""Replayable public declaration schema checks; no native or file authority."""
import copy, datetime, hashlib, importlib.util, json, pathlib, subprocess, sys
if not __debug__: raise RuntimeError('optimized_python_refused')
helper = pathlib.Path(__file__).with_name('platform-lab') / 'quarantine_host_declaration.py'
spec = importlib.util.spec_from_file_location('quarantine_host_input', helper)
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
descriptor = dict(schema_version=1, profile_contents_read=False, docker_queried=False,
    production_startup_authorized=False, deployment_id='public-schema-test', primary='member-a',
    allocation_digest='a'*64, allocation=dict(deployment_id='public-schema-test', generation=1,
    exits=[dict(exit_id='member-a')]))
namespace = dict(dev=4, ino=4026531840)
rows = []
for platform, name in module.AUTHORED_WAN.items():
    link = dict(ifname=name, ifindex=2, address='52:54:00:12:34:56', link_type='ether')
    value, data = module.host_declaration(descriptor, namespace, link, platform)
    assert json.loads(data) == value and value['allocation_digest'] == descriptor['allocation_digest']
    assert value['host_namespace'] == namespace and value['wan']['address'] == [82,84,0,18,52,86]
    assert 0 < len(data) <= 4096
    rows.append(dict(case=platform, result='PASS'))
platform = 'debian-clean-x86_64'
link = dict(ifname='ens2', ifindex=2, address='52:54:00:12:34:56', link_type='ether')
cases = [
    ('digest', lambda d,n,l: d.update(allocation_digest='not-digest')),
    ('readflag', lambda d,n,l: d.update(profile_contents_read=True)),
    ('namespace_bool', lambda d,n,l: n.update(dev=True)),
    ('name', lambda d,n,l: l.update(ifname='other')),
    ('index', lambda d,n,l: l.update(ifindex=3)),
    ('mac', lambda d,n,l: l.update(address='52:54:00:12:34:57')),
    ('type', lambda d,n,l: l.update(link_type='loopback')),
    ('schema_bool', lambda d,n,l: d.update(schema_version=True)),
    ('generation_overflow', lambda d,n,l: d['allocation'].update(generation=2**64)),
    ('namespace_overflow', lambda d,n,l: n.update(ino=2**64)),
    ('deployment_type', lambda d,n,l: d.update(deployment_id=9)),
    ('primary_type', lambda d,n,l: d.update(primary=9)),
    ('generation_bool', lambda d,n,l: d['allocation'].update(generation=True)),
    ('index_bool', lambda d,n,l: l.update(ifindex=True)),
    ('namespace_extra', lambda d,n,l: n.update(extra=1)),
    ('missing_member', lambda d,n,l: d['allocation'].update(exits=[])),
    ('duplicate_member', lambda d,n,l: d['allocation']['exits'].append(dict(exit_id='member-a'))),
    ('oversize', lambda d,n,l: d.update(primary='x'*5000, allocation=dict(deployment_id=d['deployment_id'], generation=1, exits=[dict(exit_id='x'*5000)]))),
]
for name, mutate in cases:
    d,n,l = copy.deepcopy(descriptor), copy.deepcopy(namespace), copy.deepcopy(link)
    mutate(d,n,l)
    try: module.host_declaration(d,n,l,platform)
    except (AssertionError, KeyError, TypeError, ValueError): rows.append(dict(case=name,result='PASS_REFUSED'))
    else: raise AssertionError('invalid_input_accepted:'+name)
optimized = subprocess.run([sys.executable,'-O',str(helper)],capture_output=True,text=True)
assert optimized.returncode != 0 and 'optimized_python_refused' in optimized.stderr
record = dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),checks=rows,
    optimized_guard=True,files=[dict(path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in (helper,pathlib.Path(__file__))],
    scope='LOCAL_PUBLIC_SCHEMA_ONLY; no protected file, native WAN verification, HostAuthority, route, reservation or permit acceptance')
destination = pathlib.Path('target/lab-state')/('quarantine-host-input-replay-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.json')
with destination.open('x') as stream: json.dump(record,stream,indent=2); stream.write('\n')
print(json.dumps(dict(record=str(destination),checks=len(rows),native_acceptance=False)))
