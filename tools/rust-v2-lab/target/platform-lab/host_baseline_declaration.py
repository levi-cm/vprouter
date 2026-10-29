"""Validate an independently authored foreign shape, never learn one from HOST."""
import hashlib
import ipaddress
import json
import re

if not __debug__:
    raise RuntimeError('optimized_python_refused')

PLATFORMS = {'debian-clean-x86_64', 'debian-x86_64', 'arch-x86_64', 'debian-arm64'}
def integer(value, maximum=4294967295, minimum=0):
    assert type(value) is int and minimum <= value <= maximum
    return value

def text(value, maximum, empty=True):
    assert type(value) is str and len(value.encode()) <= maximum and '\0' not in value
    assert empty or value

def digest(value):
    assert type(value) is str and re.fullmatch('[a-f0-9]{64}', value)

def pair(value):
    assert type(value) is list and len(value) == 2
    for item in value:
        integer(item, 18446744073709551615, 1)

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()

def ip(value, version=None):
    assert type(value) is str and '%' not in value
    result = ipaddress.ip_address(value)
    assert str(result) == value and (version is None or result.version == version)
    return result

def optional(value, maximum=4294967295):
    if value is not None:
        integer(value, maximum)

def validate_shape(shape):
    assert type(shape) is dict and set(shape) == {'namespace', 'links', 'addresses', 'routes', 'rules'}
    pair(shape['namespace'])
    assert all(type(shape[k]) is list for k in ('links', 'addresses', 'routes', 'rules'))
    assert sum(len(shape[k]) for k in ('links', 'addresses', 'routes', 'rules')) <= 4096
    assert len(canonical(shape)) <= 128 * 1024
    for link in shape['links']:
        assert type(link) is dict and set(link) == {'name', 'index', 'kind', 'up', 'mtu', 'alias',
            'peer_index', 'hardware_type', 'controller', 'port_kind', 'promiscuity', 'all_multicast',
            'alternate_names', 'tun_info', 'max_pacing_offload_horizon', 'headroom', 'tailroom'}
        text(link['name'], 15, False)
        text(link['kind'], 64)
        text(link['alias'], 255)
        text(link['port_kind'], 64)
        assert type(link['up']) is bool
        integer(link['index'], minimum=1)
        integer(link['mtu'], minimum=1)
        integer(link['hardware_type'], 65535)
        for key in ('controller', 'promiscuity', 'all_multicast'):
            integer(link[key])
        optional(link['peer_index'])
        optional(link['max_pacing_offload_horizon'])
        optional(link['headroom'], 65535)
        optional(link['tailroom'], 65535)
        alternatives = link['alternate_names']
        assert type(alternatives) is list and len(alternatives) <= 64
        for name in alternatives:
            text(name, 127, False)
        assert type(link['tun_info']) is list and len(link['tun_info']) <= 64
        for attribute in link['tun_info']:
            assert type(attribute) is list and len(attribute) == 2
            integer(attribute[0], 65535)
            assert type(attribute[1]) is list and len(attribute[1]) <= 256
            for byte in attribute[1]:
                integer(byte, 255)
    for address in shape['addresses']:
        assert type(address) is dict and set(address) == {'broadcast', 'route_priority', 'flags', 'index', 'address', 'prefix', 'scope'}
        version = ip(address['address']).version
        if address['broadcast'] is not None:
            ip(address['broadcast'], 4)
            assert version == 4
        optional(address['route_priority'])
        integer(address['flags'])
        integer(address['index'], minimum=1)
        integer(address['prefix'], 32 if version == 4 else 128)
        integer(address['scope'], 255)
    for route in shape['routes']:
        assert type(route) is dict and set(route) == {'nexthop_id', 'preference', 'destination', 'prefix',
            'table', 'output', 'source', 'gateway', 'kind', 'scope', 'protocol', 'metric', 'flags'}
        version = ip(route['destination']).version
        integer(route['prefix'], 32 if version == 4 else 128)
        optional(route['nexthop_id'])
        for key in ('preference', 'kind', 'scope', 'protocol'):
            integer(route[key], 255)
        for key in ('table', 'output', 'metric', 'flags'):
            integer(route[key])
        for key in ('source', 'gateway'):
            if route[key] is not None:
                ip(route[key], version)
    for rule in shape['rules']:
        assert type(rule) is dict and set(rule) == {'ipv6', 'priority', 'table', 'action', 'flags',
            'fwmark', 'fwmask', 'suppress_prefixlen', 'suppress_ifgroup', 'goto', 'realm', 'protocol'}
        assert type(rule['ipv6']) is bool
        integer(rule['action'], 255)
        for key in ('priority', 'table', 'flags'):
            integer(rule[key])
        for key in ('fwmark', 'fwmask', 'suppress_prefixlen', 'suppress_ifgroup', 'goto', 'realm'):
            optional(rule[key])
        optional(rule['protocol'], 255)
    return shape

def validate_template(template, source_binding, platform):
    assert type(template) is dict and set(template) == {'schema', 'platform', 'source_binding',
        'baseline', 'baseline_sha256', 'prior_evidence', 'review_sha256'}
    assert type(template['schema']) is int and template['schema'] == 1
    assert platform in PLATFORMS and template['platform'] == platform
    assert canonical(template['source_binding']) == canonical(source_binding)
    validate_shape(template['baseline'])
    digest(template['baseline_sha256'])
    assert template['baseline_sha256'] == hashlib.sha256(canonical(template['baseline'])).hexdigest()
    digest(template['review_sha256'])
    assert type(template['prior_evidence']) is list and 1 <= len(template['prior_evidence']) <= 64
    for reference in template['prior_evidence']:
        assert type(reference) is dict and set(reference) == {'path', 'sha256'}
        text(reference['path'], 4096, False)
        digest(reference['sha256'])
    return template['baseline']

def host_baseline_declaration(descriptor, host, template, source_binding, platform):
    baseline = validate_template(template, source_binding, platform)
    assert type(host) is dict and set(host) == {'dev', 'ino'}
    pair([host['dev'], host['ino']])
    assert baseline['namespace'] == [host['dev'], host['ino']]
    assert type(descriptor['schema_version']) is int and descriptor['schema_version'] == 1
    allocation = descriptor['allocation']
    assert descriptor['deployment_id'] == allocation['deployment_id']
    text(descriptor['deployment_id'], 255, False)
    integer(allocation['generation'], 18446744073709551615, 1)
    digest(descriptor['allocation_digest'])
    integer(descriptor['planned_host_link_index'], 2147483647, 1000000)
    assert not any(link['alias'].startswith('vprouter-v2:' + descriptor['deployment_id'] + ':') for link in baseline['links'])
    result = dict(schema_version=1, deployment_id=descriptor['deployment_id'],
        generation=allocation['generation'], allocation_digest=descriptor['allocation_digest'],
        host_namespace=host, baseline=baseline)
    raw = canonical(result)
    assert 0 < len(raw) <= 256 * 1024
    return result, raw
