import fcntl
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess as sp
import time


def run(*args, check=True, data=None):
    return sp.run(args, input=data, text=True, capture_output=True, check=check).stdout


if os.environ.get('VPROUTER_AUDIT_ISOLATED') != '1':
    raise SystemExit('Run only in the isolated disposable container described in README.md')
if any(link['ifname'] != 'lo' for link in json.loads(run('ip', '-j', 'link', 'show'))):
    raise SystemExit('Refusing to alter a namespace with existing non-loopback interfaces')


def tun(name):
    fd = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK)
    fcntl.ioctl(fd, 0x400454ca, struct.pack('16sH', name.encode(), 0x1001))
    run('ip', 'link', 'set', name, 'up')
    return fd


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    n = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while n >> 16:
        n = (n & 65535) + (n >> 16)
    return (~n) & 65535


def packet(dst, port, marker, ipv6=False):
    payload = marker.encode()
    udp = struct.pack('!HHHH', 42000 + len(results), port, 8 + len(payload), 0) + payload
    if ipv6:
        src = socket.inet_pton(socket.AF_INET6, 'fd7a:115c:a1e0::50')
        dest = socket.inet_pton(socket.AF_INET6, dst)
        pseudo = src + dest + struct.pack('!I3xB', len(udp), 17)
        udp = udp[:6] + struct.pack('!H', checksum(pseudo + udp) or 65535) + udp[8:]
        return struct.pack('!IHBB', 6 << 28, len(udp), 17, 64) + src + dest + udp
    src, dest = socket.inet_aton('100.64.0.50'), socket.inet_aton(dst)
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), len(results) + 1, 0, 64, 17, 0, src, dest)
    return hdr[:10] + struct.pack('!H', checksum(hdr)) + hdr[12:] + udp


def drain(fd):
    while select.select([fd], [], [], 0)[0]:
        os.read(fd, 65535)


results = []


def probe(name, dst='1.1.1.1', port=443, ipv6=False, local=False, expected=None):
    drain(wan)
    marker = 'VPROUTER_AUDIT_' + str(len(results)) + '_' + name
    if local:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(marker.encode(), (dst, port))
        except PermissionError:
            pass
        sock.close()
    else:
        os.write(ts, packet(dst, port, marker, ipv6))
    end = time.monotonic() + .35
    packets = []
    while time.monotonic() < end:
        if select.select([wan], [], [], max(0, end-time.monotonic()))[0]:
            packets.append(os.read(wan, 65535))
    leaked = any(marker.encode() in p for p in packets)
    row = dict(test=name, plaintext_on_wan=leaked, wan_packets=len(packets), expected_plaintext=expected)
    results.append(row)
    Path('/audit/packet-results.json').write_text(json.dumps(results, indent=2) + '\n')
    print(json.dumps(row), flush=True)
    if expected is not None:
        assert leaked == expected, row


for binary in ['iptables', 'ip6tables']:
    for table in ['filter', 'nat', 'mangle']:
        run(binary, '-t', table, '-F')
        run(binary, '-t', table, '-X')
run('ip', 'link', 'delete', 'wg0', check=False)
wan = tun('eth0')
ts = tun('tailscale0')
run('ip', 'addr', 'add', '172.19.0.2/16', 'dev', 'eth0')
run('ip', 'addr', 'add', '100.109.179.104/32', 'dev', 'tailscale0')
run('ip', 'route', 'add', '100.64.0.0/10', 'dev', 'tailscale0')
run('ip', 'route', 'add', 'default', 'via', '172.19.0.1', 'dev', 'eth0')

# No actual Tailscale identity, provider key, external network, or real user traffic.
# The startup probe measures the permissive kernel state before firewall installation.
probe('startup_before_firewall', expected=True)

run('ip', 'link', 'add', 'wg0', 'type', 'wireguard')
private = run('wg', 'genkey').strip()
peer = run('wg', 'pubkey', data=run('wg', 'genkey')).strip()
keypath = Path('/tmp/audit-private-key')
keypath.write_text(private)
keypath.chmod(0o600)
run('wg', 'set', 'wg0', 'private-key', str(keypath), 'peer', peer, 'allowed-ips', '0.0.0.0/0,::/0', 'endpoint', '169.150.201.2:51820')
keypath.unlink()
run('ip', 'addr', 'add', '10.66.243.214/32', 'dev', 'wg0')
run('ip', 'link', 'set', 'wg0', 'up')
run('ip', 'route', 'add', '169.150.201.2', 'via', '172.19.0.1', 'dev', 'eth0')
run('ip', 'route', 'add', '9.9.9.9/32', 'dev', 'wg0')
run('ip', 'route', 'replace', 'default', 'dev', 'wg0')
run('iptables-restore', data=Path('/audit/iptables.v4').read_text())
run('ip6tables-restore', data=Path('/audit/iptables.v6').read_text())

probe('dead_or_invalid_wireguard_peer_default_route_intact', expected=False)
probe('healthy_rules_endpoint_host_route_bypass', dst='169.150.201.2', expected=True)
probe('healthy_rules_endpoint_dns_bypass', dst='169.150.201.2', port=53, expected=True)
probe('healthy_rules_docker_lan_bypass', dst='172.19.0.1', expected=True)
probe('local_endpoint_udp_443_bypass', dst='169.150.201.2', local=True, expected=True)

run('ip', 'link', 'set', 'wg0', 'down')
probe('wg_link_down_without_fallback', expected=False)
run('ip', 'link', 'delete', 'wg0')
probe('wg_deleted_without_fallback', expected=False)
probe('wg_deleted_endpoint_route_remains', dst='169.150.201.2', expected=True)
run('ip', 'route', 'add', 'default', 'via', '172.19.0.1', 'dev', 'eth0')
probe('wg_deleted_ethernet_default_restored', expected=True)
probe('forwarded_dns_default_restored', port=53, expected=True)
probe('forwarded_udp_853_default_restored', port=853, expected=True)
probe('local_dns_53_default_restored', port=53, local=True, expected=False)
probe('local_udp_443_default_restored', local=True, expected=True)
probe('local_doq_853_default_restored', port=853, local=True, expected=True)

run('ip', '-6', 'addr', 'add', '2001:db8:1::2/64', 'dev', 'eth0', 'nodad')
run('ip', '-6', 'addr', 'add', 'fd7a:115c:a1e0::2a38:b369/128', 'dev', 'tailscale0', 'nodad')
run('ip', '-6', 'route', 'add', 'fd7a:115c:a1e0::/48', 'dev', 'tailscale0')
run('ip', '-6', 'route', 'add', 'default', 'dev', 'eth0')
probe('ipv6_uplink_enabled_no_killswitch', dst='2001:db8:2::1', ipv6=True, expected=True)

Path('/audit/packet-results.json').write_text(json.dumps(results, indent=2) + '\n')
