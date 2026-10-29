"""Pure schema/refusal checks; observed metadata is not staged as authority."""
import copy
import datetime
import hashlib
import importlib.util
import json
import pathlib
import subprocess
import sys

if not __debug__:
    raise RuntimeError('optimized_python_refused')
p = pathlib.Path('target/platform-lab/host_baseline_declaration.py')
spec = importlib.util.spec_from_file_location('host_declaration', p)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
cached = pathlib.Path('target/continuation-20261028T063217Z/host-projection-debian-clean-x86_64/record.json')
record = json.loads(cached.read_text())
shape = record['report']['projection']
m.validate_shape(shape)
binding = record['source_binding']
template = dict(schema=1, platform='debian-clean-x86_64', source_binding=binding,
    baseline=copy.deepcopy(shape), baseline_sha256=hashlib.sha256(m.canonical(shape)).hexdigest(),
    prior_evidence=[dict(path='synthetic-schema-only', sha256='1' * 64)], review_sha256='2' * 64)
descriptor = dict(schema_version=1, deployment_id='synthetic-schema-only',
    allocation=dict(deployment_id='synthetic-schema-only', generation=1),
    allocation_digest='3' * 64, planned_host_link_index=1000011)
host = dict(zip(('dev', 'ino'), shape['namespace']))
value, raw = m.host_baseline_declaration(descriptor, host, template, binding, template['platform'])
assert m.canonical(value) == raw and value['baseline'] == shape
rows = ['cached_projection_shape_schema', 'synthetic_declaration_serialization_only']

def refuse(name, function):
    try:
        function()
    except (AssertionError, KeyError, TypeError, ValueError):
        rows.append(name + '_refused')
    else:
        raise AssertionError(name)

mutations = [('namespace_bool', lambda s: s['namespace'].__setitem__(0, True)),
    ('extra_wireguard', lambda s: s.update(wireguard={})),
    ('links_mapping', lambda s: s.update(links={})),
    ('link_index_bool', lambda s: s['links'][0].update(index=True)),
    ('link_mtu_float', lambda s: s['links'][0].update(mtu=65536.0)),
    ('link_up_integer', lambda s: s['links'][0].update(up=1)),
    ('link_alias_oversize', lambda s: s['links'][0].update(alias='x' * 256)),
    ('link_unknown', lambda s: s['links'][0].update(secret='forbidden')),
    ('link_peer_negative', lambda s: s['links'][0].update(peer_index=-1)),
    ('address_scope_bool', lambda s: s['addresses'][0].update(scope=True)),
    ('address_prefix', lambda s: s['addresses'][0].update(prefix=129)),
    ('address_zone', lambda s: s['addresses'][0].update(address='fe80::1%lo')),
    ('route_table_float', lambda s: s['routes'][0].update(table=254.0)),
    ('route_prefix', lambda s: s['routes'][0].update(prefix=129)),
    ('rule_ipv6_integer', lambda s: s['rules'][0].update(ipv6=0)),
    ('rule_protocol_overflow', lambda s: s['rules'][0].update(protocol=256)),
    ('record_count', lambda s: s.update(rules=s['rules'] * 820))]
for name, change in mutations:
    candidate = copy.deepcopy(shape)
    change(candidate)
    refuse(name, lambda candidate=candidate: m.validate_shape(candidate))

for key, value in [('schema', True), ('platform', 'other'), ('baseline_sha256', '4' * 64),
    ('review_sha256', 'invalid'), ('prior_evidence', [])]:
    changed = copy.deepcopy(template)
    changed[key] = value
    refuse('template_' + key, lambda changed=changed: m.validate_template(changed, binding, template['platform']))
refuse('raw_projection_is_not_template', lambda: m.validate_template(shape, binding, template['platform']))
for key, value in [('schema_version', True), ('planned_host_link_index', True),
    ('planned_host_link_index', 999999), ('planned_host_link_index', 2**31),
    ('allocation_digest', 'invalid'), ('deployment_id', 'other')]:
    changed = copy.deepcopy(descriptor)
    changed[key] = value
    refuse('descriptor_' + key + '_' + str(value), lambda changed=changed:
        m.host_baseline_declaration(changed, host, template, binding, template['platform']))
changed = copy.deepcopy(template)
changed['baseline']['links'][0]['alias'] = 'vprouter-v2:synthetic-schema-only:1:a'
changed['baseline_sha256'] = hashlib.sha256(m.canonical(changed['baseline'])).hexdigest()
refuse('same_deployment_existing_alias', lambda: m.host_baseline_declaration(descriptor,
    host, changed, binding, template['platform']))
bad_host = dict(host)
bad_host['ino'] += 1
refuse('host_namespace_mismatch', lambda: m.host_baseline_declaration(descriptor,
    bad_host, template, binding, template['platform']))
result = subprocess.run([sys.executable, '-O', str(p)], capture_output=True, text=True)
assert result.returncode != 0 and 'optimized_python_refused' in result.stderr
rows.append('optimized_python_refused')
stamp = datetime.datetime.now(datetime.timezone.utc)
out = pathlib.Path('target/lab-state') / ('host-baseline-schema-smokes-' + stamp.strftime('%Y%m%dT%H%M%S%fZ') + '.json')
with out.open('x') as stream:
    json.dump(dict(observed_at_utc=stamp.isoformat(), checks=rows,
        files=[dict(path=str(f), sha256=hashlib.sha256(f.read_bytes()).hexdigest())
            for f in (pathlib.Path(__file__), p, cached)],
        native_acceptance=False, declaration_staged=False, host_authority_granted=False,
        scope='Schema-only use of cached public projection and synthetic authored metadata. No reference reconciliation, baseline staging, HOST mutation or runtime acceptance.'), stream, indent=2)
print(json.dumps(dict(record=str(out), checks=len(rows), declaration_staged=False, host_authority_granted=False)))
