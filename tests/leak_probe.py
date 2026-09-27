"""Kernel packet regression test. Run only in a disposable, disconnected container."""

import fcntl
import json
import os
import select
import socket
import struct
import subprocess
import time


def run(*args, input_text=None):
    return subprocess.run(args, input=input_text, text=True, capture_output=True, check=True).stdout


def tun(name):
    fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
    fcntl.ioctl(fd, 0x400454CA, struct.pack("16sH", name.encode(), 0x1001))
    run("ip", "link", "set", name, "up")
    return fd


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    n = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while n >> 16:
        n = (n & 65535) + (n >> 16)
    return (~n) & 65535


def packet(destination, marker, ipv6=False):
    payload = marker.encode()
    udp = struct.pack("!HHHH", 41000, 443, 8 + len(payload), 0) + payload
    if ipv6:
        src = socket.inet_pton(socket.AF_INET6, "fd7a:115c:a1e0::50")
        dst = socket.inet_pton(socket.AF_INET6, destination)
        pseudo = src + dst + struct.pack("!I3xB", len(udp), 17)
        udp = udp[:6] + struct.pack("!H", checksum(pseudo + udp) or 65535) + udp[8:]
        return struct.pack("!IHBB", 6 << 28, len(udp), 17, 64) + src + dst + udp
    src, dst = socket.inet_aton("100.64.0.50"), socket.inet_aton(destination)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, src, dst)
    return hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:] + udp


def flush(fd):
    while select.select([fd], [], [], 0)[0]:
        os.read(fd, 65535)


def inject(test, destination, ipv6=False, expect_plaintext=False):
    flush(wan)
    marker = "LEAK_PROBE_" + test
    os.write(ts, packet(destination, marker, ipv6))
    deadline = time.monotonic() + .35
    emitted = []
    while time.monotonic() < deadline:
        if select.select([wan], [], [], max(0, deadline - time.monotonic()))[0]:
            emitted.append(os.read(wan, 65535))
    leaked = any(marker.encode() in item for item in emitted)
    result = {"scenario": test, "plaintext_on_wan": leaked, "wan_packets": len(emitted)}
    print(json.dumps(result), flush=True)
    assert leaked == expect_plaintext, result


if os.environ.get("VPROUTER_LAB_ISOLATED") != "1":
    raise SystemExit("This probe requires an explicit disposable-lab opt-in")
if os.getpid() == 1:
    raise SystemExit("Do not replace the router supervisor with this probe")
if {item["ifname"] for item in json.loads(run("ip", "-j", "link", "show"))} != {"lo"}:
    raise SystemExit("Refusing a namespace that already has non-loopback interfaces")
run("nft", "list", "table", "inet", "vprouter")

wan = tun("eth0")
ts = tun("tailscale0")
run("ip", "addr", "add", "172.19.0.2/16", "dev", "eth0")
run("ip", "addr", "add", "100.64.0.60/32", "dev", "tailscale0")
run("ip", "route", "add", "100.64.0.0/10", "dev", "tailscale0")
run("ip", "route", "add", "default", "via", "172.19.0.1", "dev", "eth0")
run("nft", "delete", "table", "inet", "vprouter")
inject("unguarded_positive_control", "1.1.1.1", expect_plaintext=True)
run("nft", "-f", "/usr/local/share/vprouter/router.nft")
inject("boot_ordinary_default", "1.1.1.1")

run("ip", "link", "add", "wg0", "type", "wireguard")
first = run("wg", "genkey").strip()
second = run("wg", "pubkey", input_text=run("wg", "genkey")).strip()
# A temporary mode-600 key is removed before returning to the host.
keypath = "/tmp/leak-probe-private"
with open(keypath, "w", encoding="ascii") as stream:
    stream.write(first)
os.chmod(keypath, 0o600)
run("wg", "set", "wg0", "private-key", keypath, "peer", second, "allowed-ips", "0.0.0.0/0", "endpoint", "192.0.2.77:51820")
os.unlink(keypath)
run("ip", "addr", "add", "10.222.0.2/32", "dev", "wg0")
run("ip", "link", "set", "wg0", "up")
run("ip", "route", "add", "192.0.2.77", "via", "172.19.0.1", "dev", "eth0")
run("ip", "route", "replace", "default", "dev", "wg0")
inject("wireguard_born_without_transport_namespace", "1.1.1.1")
inject("endpoint_host_route", "192.0.2.77")
inject("docker_bridge_gateway", "172.19.0.1")
run("ip", "link", "delete", "wg0")
fake_wg = tun("wg0")
run("ip", "addr", "add", "10.222.0.2/32", "dev", "wg0")
run("ip", "route", "replace", "default", "dev", "wg0")
real_wan = wan
wan = fake_wg
run("nft", "delete", "table", "inet", "vprouter")
inject("unguarded_fake_wg_positive_control", "1.1.1.1", expect_plaintext=True)
run("nft", "-f", "/usr/local/share/vprouter/router.nft")
inject("non_wireguard_interface_named_wg0", "1.1.1.1")
wan = real_wan
os.close(fake_wg)
run("ip", "route", "add", "default", "via", "172.19.0.1", "dev", "eth0")
inject("vpn_deleted_default_restored", "1.1.1.1")
inject("vpn_deleted_endpoint_exception", "192.0.2.77")
run("ip", "-6", "addr", "add", "2001:db8:1::2/64", "dev", "eth0", "nodad")
run("ip", "-6", "addr", "add", "fd7a:115c:a1e0::2a38:b369/128", "dev", "tailscale0", "nodad")
run("ip", "-6", "route", "add", "default", "dev", "eth0")
inject("introduced_ipv6_uplink", "2001:db8:2::1", ipv6=True)
