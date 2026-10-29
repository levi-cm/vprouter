"""Author expected public fields from prior bound ip metadata, not a live dump."""
import ipaddress
import json

if not __debug__:
    raise RuntimeError('optimized_python_refused')

TABLE = {'local': 255, 'main': 254, 'default': 253}
PROTOCOL = {'unspec': 0, 'redirect': 1, 'kernel': 2, 'boot': 3, 'static': 4, 'ra': 9, 'dhcp': 16}
SCOPE = {'global': 0, 'site': 200, 'link': 253, 'host': 254, 'nowhere': 255}
KIND = {'unicast': 1, 'local': 2, 'broadcast': 3, 'anycast': 4, 'multicast': 5,
    'blackhole': 6, 'unreachable': 7, 'prohibit': 8, 'throw': 9, 'nat': 10, 'xresolve': 11}
PREFERENCE = {'medium': 0, 'high': 1, 'low': 3}
ADDRESS_FLAGS = {'secondary': 1, 'temporary': 1, 'nodad': 2, 'optimistic': 4, 'dadfailed': 8,
    'home': 16, 'deprecated': 32, 'tentative': 64, 'mngtmpaddr': 256,
    'noprefixroute': 512, 'mcautojoin': 1024, 'stable-privacy': 2048}
ROUTE_FLAGS = {'dead': 1, 'onlink': 4, 'linkdown': 16, 'notify': 256,
    'cloned': 512, 'offload': 16384, 'trap': 32768}

def enum(value, names):
    if type(value) is int:
        return value
    assert type(value) is str and value in names
    return names[value]

def rows(scope, key):
    value = scope[key]
    assert value['code'] == 0 and type(value['data']) is list
    return value['data']

def expected_from_prior(scope, namespace, platform):
    """Unreported scalar/link fields are explicitly authored absent/default.

    Every such choice is later compared to the complete frozen projection. A
    different value refuses reconciliation; it is never learned or substituted.
    """
    links = rows(scope, 'links')
    assert platform in ('debian-clean-x86_64', 'debian-x86_64', 'arch-x86_64', 'debian-arm64')
    names = {link['ifname']: link['ifindex'] for link in links}
    assert len(names) == len(links)
    shape = dict(namespace=namespace, links=[], addresses=[], routes=[], rules=[])
    for link in links:
        info = link.get('linkinfo', {})
        assert info.get('info_kind', '') != 'tun'
        assert not info.get('info_slave_kind') and not info.get('info_port_kind')
        shape['links'].append(dict(name=link['ifname'], index=link['ifindex'], kind=info.get('info_kind', ''),
            up='UP' in link['flags'], mtu=link['mtu'], alias=link.get('ifalias', ''),
            peer_index=link.get('link_index'), hardware_type={'loopback':772,'ether':1,'none':65534}[link['link_type']],
            controller=names[link['master']] if 'master' in link else 0, port_kind='',
            promiscuity=link.get('promiscuity', 0), all_multicast=link.get('allmulti', 0),
            alternate_names=link.get('altnames', []), tun_info=[],
            max_pacing_offload_horizon=None, headroom=None, tailroom=None))
        if platform == 'arch-x86_64':
            # Explicit reviewed values omitted by this fixture's ip JSON.
            # They are expectations, never filled from a new observation.
            shape['links'][-1].update(max_pacing_offload_horizon=0,
                headroom=12 if link['ifname'] == 'eth0' and link['ifindex'] == 2 else 0,
                tailroom=0)
    for link in rows(scope, 'addresses'):
        for address in link['addr_info']:
            flags = 0 if address.get('dynamic', False) else 128
            for flag, bit in ADDRESS_FLAGS.items():
                if address.get(flag, False):
                    flags |= bit
            shape['addresses'].append(dict(broadcast=address.get('broadcast'), route_priority=address.get('metric'),
                flags=flags, index=link['ifindex'], address=str(ipaddress.ip_address(address['local'])),
                prefix=address['prefixlen'], scope=enum(address['scope'], SCOPE)))
    for family, key in [(4, 'routes4'), (6, 'routes6')]:
        for route in rows(scope, key):
            destination = route.get('dst', 'default')
            network = ipaddress.ip_network(('0.0.0.0/0' if family == 4 else '::/0') if destination == 'default' else destination, strict=False)
            assert network.version == family and not route.get('tos')
            flags = 0
            for flag in route.get('flags', []):
                flags |= ROUTE_FLAGS[flag]
            shape['routes'].append(dict(nexthop_id=route.get('nhid'), preference=enum(route.get('pref', 'medium'), PREFERENCE),
                destination=str(network.network_address), prefix=network.prefixlen,
                table=enum(route.get('table', 'main'), TABLE), output=names[route['dev']] if 'dev' in route else 0,
                source=route.get('prefsrc'), gateway=route.get('gateway'), kind=enum(route.get('type', 'unicast'), KIND),
                scope=enum(route.get('scope', 'global'), SCOPE), protocol=enum(route.get('protocol', 'boot'), PROTOCOL),
                metric=route.get('metric', 0), flags=flags))
    for ipv6, key in [(False, 'rules4'), (True, 'rules6')]:
        for rule in rows(scope, key):
            assert set(rule) <= {'priority', 'src', 'table', 'protocol'} and rule.get('src', 'all') == 'all'
            shape['rules'].append(dict(ipv6=ipv6, priority=rule['priority'], table=enum(rule['table'], TABLE),
                action=1, flags=0, fwmark=None, fwmask=None, suppress_prefixlen=4294967295,
                suppress_ifgroup=None, goto=None, realm=None, protocol=enum(rule.get('protocol', 'kernel'), PROTOCOL)))
    return shape

def stable(shape):
    """Only collection ordering is normalized; no structural fields disappear."""
    result = dict(shape)
    for key in ('links', 'addresses', 'routes', 'rules'):
        result[key] = sorted(shape[key], key=lambda row: json.dumps(row, sort_keys=True, separators=(',', ':')))
    return result
