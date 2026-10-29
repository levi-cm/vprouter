"""Pure, closed ARM preservation expectations from bound historical evidence.

No current projection value enters reconstruction. WAN index 158 is an explicit
sequence expectation, not an exported original receipt. No custody is created.
"""
import ast
import copy
import hashlib
import io
import json
import re
import tarfile

if not __debug__:
    raise RuntimeError('optimized_python_refused')

NAMESPACE = [4, 4026531840]
NONCE = '43c06cb584edab54d8f9328faaf68ed2fb6e9c3306b2137c5e2eaf1d13990d59'
CURRENT_BINDING = dict(
    source_commit='90a7dcc756f073cccd3a1c34959676f001eb7601',
    source_archive_sha256='efbf8fd12c7a521cd7ba83544ceb99185dca5e0a7d9c737b702647cc1756e373',
    tracked_build_inputs_verified=195,
    source_aggregate_sha256='9cf69c8c83e44134bcdb513d7ba2781015ecbe3c9190954c428e601f516ff4a2')
CURRENT_CANDIDATE_SHA = 'a64ac9deb9df4a409fc1a8ae78230d40c0302ba6ff2911dc84dcaa24847d5c03'
CURRENT_ARTIFACT_SHA = '817c5a92e39676864ea6bcb0fd7b716bb72aaacd7b99f48692e5e7392c97779f'
DEPENDENCY_SHAS = {
    'prior': '0ea98ae8b1855f545a5bed1655f9107d189b431f948aa4fd37ba2e0bf1da4289',
    'schema': '367d2322ea841a81d9ec00006f7c38cf694300cffb77783e4f72903317d1a212',
    'projection_controller': '687ed1627b0a5f1efac5d1a90be283ac185d8e5710b46646c57e2e7b6a9e08af',
}
# Paths are closed, public historical artifacts; never profiles or credentials.
HISTORY = {
    'prior_index': ('target/continuation-20261027T164048Z/partial-checkpoint-index.json', '1a08baa4bd8af45556ab52299676e12618e6fefdd9363a86b09021ead848e914'),
    'prior_metadata': ('target/continuation-20261027T164048Z/arm64-secret-preparation-normal-regression/metadata.json', '9cdaefa80879c2237fdd5aa7eacf6919971666fc7b927d813b04f7dc4d7e0f71'),
    'early_index': ('target/continuation-20261027T185926Z/partial-checkpoint-index.json', '04749350ebc35335234078935fa9103e23e0f660cc8703add504c4b589ccc231'),
    'late_index': ('target/continuation-20261027T210921Z/partial-checkpoint-index.json', '9a2a26c353d7a92e067fb31b03c6e54c70ad6d8c0ba28d72722e0e975c47dca2'),
    'run261': ('target/lab-state/actual-program-run-261.json', 'c260e5829e77659b35e6fb03177f99fceb33543df7a95c46ecad35ce07d352e0'),
    'run263': ('target/lab-state/actual-program-run-263.json', '46d079c500ec88905a1db9ed96c142e42b337c1d6a6166922173aeed897a2896'),
    'run264': ('target/lab-state/actual-program-run-264.json', '92951d2bf0a7fd407a2656020b84a62b387a36cb7e5ddae5d1522252ca221a79'),
    'run277': ('target/lab-state/actual-program-run-277.json', '66a80d0451d8e7e50be39f72998715f25a38f2f117067d940ed32dd4ab823147'),
    'actors277': ('target/lab-state/expiry-drop-failed-actors-run-277.json', 'bf2fd070636df135a1da166f6922cc830b7f09d852e9e89e04be0da3c71dec4e'),
    'early_candidate': ('target/continuation-20261027T185926Z/candidate.json', '038ad6ddf3e5373b38a8f895183b650f1e045471cc00ff2b91792877b8638568'),
    'late_candidate': ('target/continuation-20261027T210921Z/candidate.json', '33b90f0ce526d219e4d9db564dc48771f4bf3c74f2eb5c23eea95f046e6d16c8'),
    'early_source': ('target/continuation-20261027T185926Z/source.tar', 'b4da986fd7a286356df792a2ba9e2061b40a7895e2e3a4aff71f7b8fb28508ad'),
    'late_source': ('target/continuation-20261027T210921Z/source.tar', '1a37c2933da20bbe2c9717d70f1938bafc61bbc1bebff702d1474b5054302019'),
    'early_artifact': ('target/continuation-20261027T185926Z/arm64.payload', 'f82d233c5524f0caacb132c135ef9a50e839978100cf7f24699102ac535854b7'),
    'late_artifact': ('target/continuation-20261027T210921Z/arm64.payload', '1fd21f5ade881669dff8cf2162a105399fc896d5db12eff269bbfc6e9870273e'),
    'runner261': ('target/platform-lab/run-owner-retirement-global-stop-debian-arm64.py', 'bff64736f0a272c5f4937569cc2a5d16743ec8c740ef4ca9323d7215fb0c1e70'),
    'runner263': ('target/platform-lab/run-owner-process-inspection-debian-arm64.py', '32fe268b3de9a1e94c8fba53f839cb4a8e968a639670b6fc289a35b5a34d5dad'),
    'runner264_277': ('target/platform-lab/run-owner-retirement-debian-arm64.py', '2edc71165a50d6998425d39e1fcc3d068a90893d27d29b7c1afc365b50383224'),
}
POLICIES = (
    dict(id='wan_index_sequence', classification='AUTHORED_EXPECTATION_NOT_ORIGINAL_RECEIPT',
         expectation='Historical maximum157, then fixed WAN creation, then original journal-bound A159: expect WAN158. No directly exported original WAN-index receipt.'),
    dict(id='last_two_fixed_fields', classification='SOURCE_DERIVED_EXPECTATION',
         expectation='Copy historical same-operation WAN155/A156 fixed Link fields; change only name/alias/index. Expect peer2, UP, veth, MTU1500/1420, controller/promiscuity/all_multicast0, empty alternate/tun/port fields and absent Debian pacing/headroom/tailroom.'),
    dict(id='last_two_addresses_routes', classification='SOURCE_DERIVED_EXPECTATION',
         expectation='Nonce43/c0 yields endpoint185.66.67.192 and WAN HOST185.66.67.193/32. Selected10.203.1.204/30 yields AHOST10.203.1.205/32 and peer10.203.1.206. Copy historical same-operation local/boot-WAN/static-member route forms with only original/predicted index and those IPs changed.'),
    dict(id='ipv6_multicast_routes', classification='AUTHORED_KERNEL_POLICY_EXPECTATION',
         expectation='Ten added UP veths each have one ff00::/8 route. Copy the full historical index143 ff00 route, changing output index only. addrgenmode none expects no new IPv6 link-local address.'),
    dict(id='old_ipv6_rules_preserved', classification='PRESERVATION_EXPECTATION',
         expectation='Old IPv6 routes and both rule families stay unchanged except the ten explicit ff00 multicast routes. Whole-structure comparison refuses any deviation.'),
    dict(id='historical_converter_defaults', classification='EXPLICIT_PRIOR_CONVERTER_EXPECTATIONS',
         expectation='Captured converter defaults below are authored expectations where old ip JSON omits fields; flags/enums otherwise follow that exact reviewed helper. No observed-value filling.',
         defaults={
             'links': dict(kind='', alias='', peer_index=None, controller=0, port_kind='',
                 promiscuity=0, all_multicast=0, alternate_names=[], tun_info=[],
                 max_pacing_offload_horizon=None, headroom=None, tailroom=None),
             'addresses': dict(broadcast=None, route_priority=None,
                 static_flags_before_explicit_bits=128, dynamic_flags_before_explicit_bits=0),
             'routes': dict(nexthop_id=None, preference=0, default_prefix=0,
                 table=254, missing_device_output=0, source=None, gateway=None,
                 kind=1, scope=0, protocol=3, metric=0, flags=0),
             'rules': dict(source='all', action=1, flags=0, fwmark=None, fwmask=None,
                 suppress_prefixlen=4294967295, suppress_ifgroup=None, goto=None,
                 realm=None, protocol=2)}),
    dict(id='failed_run_history', classification='EVIDENCE_LIMIT',
         expectation='Runs264/277 remain FAIL. No whole-retirement, cleanup completion, ownership, membership, removal, UP or readiness acceptance follows. Former fixture test-learned HostAuthority admission is not independent production declaration admission.'),
)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def same(left, right):
    return canonical(left) == canonical(right)


def digest(raw):
    assert type(raw) is bytes
    return hashlib.sha256(raw).hexdigest()


def loads(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            assert key not in result, 'duplicate_json_key'
            result[key] = value
        return result
    def invalid(value):
        raise ValueError('nonfinite_json_constant')
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def events(record, key):
    assert type(record['stdout']) is str
    values = []
    for line in record['stdout'].splitlines():
        try:
            value = loads(line)
        except (ValueError, AssertionError):
            continue
        if type(value) is dict and key in value:
            values.append(value[key])
    assert len(values) == 1, 'missing_or_duplicate_historical_event'
    return values[0]


def load_dependencies(captured):
    assert set(captured) == set(DEPENDENCY_SHAS)
    for key, expected in DEPENDENCY_SHAS.items():
        assert digest(captured[key]) == expected, 'dependency_bytes_mismatch:' + key
    modules = {}
    for key in ('prior', 'schema'):
        namespace = {'__name__': 'arm_history_' + key}
        exec(compile(captured[key], '<captured-arm-history-' + key + '>', 'exec'), namespace)
        modules[key] = namespace
    tree = ast.parse(captured['projection_controller'])
    functions = ast.Module(body=[n for n in tree.body if isinstance(n, ast.FunctionDef)], type_ignores=[])
    namespace = {'json': json, 're': re}
    exec(compile(functions, '<captured-projection-validator-functions>', 'exec'), namespace)
    modules['projection_validator'] = namespace['validate_projection_envelope']
    return modules


def _bound(index, key, blobs):
    path, expected = HISTORY[key]
    found = [e for e in index['entries'] if e['path'] == path]
    assert len(found) == 1
    entry = found[0]
    assert type(entry['bytes']) is int and entry['bytes'] == len(blobs[key])
    assert entry['sha256'] == expected == digest(blobs[key])


def verify_history(blobs):
    assert set(blobs) == set(HISTORY)
    for key, (_, expected) in HISTORY.items():
        assert digest(blobs[key]) == expected, 'historical_bytes_mismatch:' + key
    parsed = {key: loads(raw) for key, raw in blobs.items() if HISTORY[key][0].endswith('.json')}
    _bound(parsed['prior_index'], 'prior_metadata', blobs)
    for key in ('run261', 'run263', 'run264'):
        _bound(parsed['early_index'], key, blobs)
    for key in ('run277', 'actors277'):
        _bound(parsed['late_index'], key, blobs)
    for phase in ('early', 'late'):
        candidate = parsed[phase + '_candidate']
        assert candidate['source_sha256'] == digest(blobs[phase + '_source'])
        assert candidate['platforms']['arm64']['artifact_sha256'] == digest(blobs[phase + '_artifact'])
        assert candidate['binding']['source_archive_sha256'] == candidate['source_sha256']
        for number in ((261, 263, 264) if phase == 'early' else (277,)):
            record = parsed['run' + str(number)]
            assert same(record['source_binding'], candidate['binding'])
            assert record['artifact_sha256'] == candidate['platforms']['arm64']['artifact_sha256']
            runner = 'runner264_277' if number in (264, 277) else 'runner' + str(number)
            assert record['runner_sha256'] == digest(blobs[runner])
    with tarfile.open(fileobj=io.BytesIO(blobs['late_source'])) as archive:
        source = archive.extractfile('crates/vprouter-launch/src/transport_lab.rs').read()
    assert digest(source) == '621806e9b3e35ace80dcf03ea7384c280906c574cb328058b71baa6024a83138'
    assert b'Test-learned baseline in this controlled owned guest' in source
    return parsed


def validate_history_semantics(history):
    """Also check parsed facts; tests can challenge them independently of hashes."""
    metadata = history['prior_metadata']
    assert metadata['read_only'] is True
    host_scopes = [s for s in metadata['deployments'][0]['scopes'] if s['scope'] == 'host']
    assert len(host_scopes) == 1
    old = host_scopes[0]
    assert old['links']['code'] == 0 and len(old['links']['data']) == 96
    record = history['run277']
    assert type(record['exit_code']) is int and record['exit_code'] == 1 and record['result'] == 'FAIL'
    selection = events(record, 'synthetic_nonce_selection')
    assert type(selection['schema']) is int and selection['schema'] == 2
    assert selection['nonce'] == NONCE
    assert selection['allocation_algorithm_sha256'] == '1dfcaa8f69b6efe40941768104a48051ba6bba8f150213e19e3d2fc7ccab69e2'
    assert selection['before_native_network_mutation'] is selection['exclusive_kernel_race_checks_unchanged'] is True
    baseline = selection['baseline']
    assert type(baseline) is dict and set(baseline) == {'links', 'addresses', 'routes'}
    assert selection['baseline_sha256'] == digest(canonical(baseline)) == 'ebf9db109b4048023bee54185a8dd5739f7fec93c3bf7613b85bbe94c178a4d9'
    assert all(type(baseline[k]) is list for k in baseline)
    assert (len(baseline['links']), len(baseline['addresses']), len(baseline['routes'])) == (104, 104, 213)
    link_map = {row['ifindex']: row for row in baseline['links']}
    assert len(link_map) == 104 and max(link_map) == 157
    expected_names = {148: 'vjh6ceb3b4f95', 149: 'vh242fbc951063', 150: 'vhcb9bd569df26',
        153: 'vr8w31433', 154: 'vhda679612241c', 155: 'vjh586b9e6b6b',
        156: 'vhed5530e2a9cb', 157: 'vh41cba425d55a'}
    assert all(link_map[index]['ifname'] == name for index, name in expected_names.items())
    intended = [entry for entry in selection['intended'] if entry['exit_id'] == 'a' + NONCE[:12]]
    assert len(intended) == 1
    assert same(intended[0], dict(exit_id='a43c06cb584ed', host_interface='vh8dcda176c073',
        data_interface='vd8dcda176c073', wireguard_interface='wg8dcda176c073', transport_subnet='10.203.1.204/30'))
    actors = history['actors277']
    assert actors['record'] == HISTORY['run277'][0]
    assert actors['record_sha256'] == HISTORY['run277'][1]
    assert same(actors['source_commit'], record['source_binding']['source_commit'])
    assert actors['artifact_sha256'] == record['artifact_sha256'] and actors['platform'] == 'debian-arm64'
    assert actors['nonce'] == NONCE
    rows = [entry for entry in actors['journal_entries'] if entry['exit_id'] == 'a' + NONCE[:12]]
    assert len(rows) == 1
    links = rows[0]['links']
    assert set(links) == {'host_namespace', 'host_index', 'transport_index', 'wireguard_index'}
    assert same(links, dict(host_namespace=dict(dev=4, ino=4026531840), host_index=159,
        transport_index=2, wireguard_index=3))
    preflight = events(record, 'preflight')
    # events returns only the key's string for this historical event; inspect the
    # unique containing row to bind its exact namespace independently.
    assert preflight == 'PASS'
    lines = [loads(line) for line in record['stdout'].splitlines() if line.startswith('{')]
    preflights = [row for row in lines if 'preflight' in row]
    assert len(preflights) == 1 and same(preflights[0]['host_namespace'], dict(dev=4, ino=4026531840))
    return old, baseline


def reconstruct_expected(history, modules):
    old, baseline = validate_history_semantics(history)
    prior = modules['prior']
    schema = modules['schema']
    initial = prior['expected_from_prior'](old, copy.deepcopy(NAMESPACE), 'debian-arm64')
    schema['validate_shape'](initial)
    scope = copy.deepcopy(old)
    for key, rows in (('links', baseline['links']), ('addresses', baseline['addresses']), ('routes4', baseline['routes'])):
        scope[key] = dict(code=0, data=copy.deepcopy(rows))
    expected = prior['expected_from_prior'](scope, copy.deepcopy(NAMESPACE), 'debian-arm64')
    # Historical replacement must not silently replace any original foreign row.
    for key in ('links', 'addresses', 'routes', 'rules'):
        assert all(any(same(row, candidate) for candidate in expected[key]) for row in initial[key])
    by_index = {row['index']: row for row in expected['links']}
    for index, mtu in ((155, 1500), (156, 1420)):
        row = by_index[index]
        assert same({k: row[k] for k in ('kind', 'up', 'mtu', 'peer_index', 'hardware_type', 'controller',
            'port_kind', 'promiscuity', 'all_multicast', 'alternate_names', 'tun_info',
            'max_pacing_offload_horizon', 'headroom', 'tailroom')},
            dict(kind='veth', up=True, mtu=mtu, peer_index=2, hardware_type=1, controller=0,
                port_kind='', promiscuity=0, all_multicast=0, alternate_names=[], tun_info=[],
                max_pacing_offload_horizon=None, headroom=None, tailroom=None))
    wan = copy.deepcopy(by_index[155])
    wan.update(index=158, name='vjh43c06cb584', alias='owner-bootstrap-' + NONCE)
    member = copy.deepcopy(by_index[156])
    member.update(index=159, name='vh8dcda176c073', alias='vprouter-v2:launchlab-43c06cb584ed:1:a43c06cb584ed')
    expected['links'].extend([wan, member])
    for old_index, new_index, address, peer in ((155, 158, '185.66.67.193', '185.66.67.192'),
            (156, 159, '10.203.1.205', '10.203.1.206')):
        address_rows = [r for r in expected['addresses'] if r['index'] == old_index and ':' not in r['address']]
        assert len(address_rows) == 1
        row = copy.deepcopy(address_rows[0])
        assert same({k: row[k] for k in ('broadcast', 'route_priority', 'flags', 'prefix', 'scope')},
            dict(broadcast=None, route_priority=None, flags=128, prefix=32, scope=0))
        row.update(index=new_index, address=address)
        expected['addresses'].append(row)
        route_rows = [r for r in expected['routes'] if r['output'] == old_index]
        assert len(route_rows) == 2 and {r['table'] for r in route_rows} == {254, 255}
        for old_route in route_rows:
            row = copy.deepcopy(old_route)
            assert ':' not in row['destination'] and row['source'] is not None
            row.update(output=new_index, source=address,
                destination=address if row['table'] == 255 else peer)
            expected['routes'].append(row)
    multicast = [r for r in expected['routes'] if r['output'] == 143 and r['destination'] == 'ff00::']
    assert len(multicast) == 1
    for index in (148, 149, 150, 153, 154, 155, 156, 157, 158, 159):
        row = copy.deepcopy(multicast[0])
        row['output'] = index
        expected['routes'].append(row)
    schema['validate_shape'](expected)
    assert [len(expected[k]) for k in ('links', 'addresses', 'routes', 'rules')] == [106, 109, 327, 5]
    assert len({row['index'] for row in expected['links']}) == 106
    assert len({row['name'] for row in expected['links']}) == 106
    return expected


def validate_current(candidate_bytes, source_bytes, artifact_bytes, projection_bytes, ssh_bytes, modules):
    assert digest(candidate_bytes) == CURRENT_CANDIDATE_SHA, 'unreviewed_current_candidate'
    candidate = loads(candidate_bytes)
    assert set(candidate) == {'source_commit', 'source', 'source_sha256', 'binding', 'platforms'}
    assert same(candidate['binding'], CURRENT_BINDING)
    assert candidate['source_commit'] == CURRENT_BINDING['source_commit']
    assert digest(source_bytes) == candidate['source_sha256'] == CURRENT_BINDING['source_archive_sha256']
    assert digest(artifact_bytes) == candidate['platforms']['arm64']['artifact_sha256'] == CURRENT_ARTIFACT_SHA
    record = loads(projection_bytes)
    assert set(record) == {'observed_at_utc', 'source_binding', 'artifact_sha256', 'platform',
        'controller_sha256', 'remote', 'report', 'declaration_staged', 'host_authority_granted',
        'production_changes', 'private_profile_contents_read', 'scope'}
    assert same(record['source_binding'], CURRENT_BINDING)
    assert record['artifact_sha256'] == CURRENT_ARTIFACT_SHA and record['platform'] == 'debian-arm64'
    assert record['controller_sha256'] == DEPENDENCY_SHAS['projection_controller']
    assert all(record[k] is False for k in ('declaration_staged', 'host_authority_granted',
        'production_changes', 'private_profile_contents_read'))
    remote = loads(ssh_bytes)
    assert same(remote, record['remote'])
    report = modules['projection_validator'](remote, 'aarch64')
    assert same(report, record['report']) and same(report['namespace'], NAMESPACE)
    modules['schema']['validate_shape'](report['projection'])
    return candidate, record


def reconcile(expected, observed, schema):
    """Only compare current values; select output rows exclusively from expected."""
    schema['validate_shape'](expected)
    schema['validate_shape'](observed)
    assert same(expected['namespace'], NAMESPACE) and same(observed['namespace'], NAMESPACE)
    assert set(expected) == set(observed)
    ordered = dict(namespace=copy.deepcopy(expected['namespace']))
    for key in ('links', 'addresses', 'routes', 'rules'):
        assert sorted(map(canonical, expected[key])) == sorted(map(canonical, observed[key])), 'unexplained_foreign_drift:' + key
        remaining = copy.deepcopy(expected[key])
        ordered[key] = []
        for current_row in observed[key]:
            position = next(i for i, row in enumerate(remaining) if same(row, current_row))
            ordered[key].append(remaining.pop(position))
        assert not remaining
    return ordered
