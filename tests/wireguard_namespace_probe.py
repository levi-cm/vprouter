"""Real WireGuard namespace/forwarding test in a disposable isolated network.

Run as root with VPROUTER_LAB_ISOLATED=1 under unshare --net.
"""

import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from host.orchestrate import Provider, Site, install_guard


def call(*args, input_text=None):
    return subprocess.run(args, input=input_text, check=True, text=True, capture_output=True).stdout.strip()


def enter(pid, *args):
    return call("nsenter", "-t", str(pid), "-n", *args)


def new_namespace():
    return subprocess.Popen(["unshare", "--net", "sleep", "60"])


def veth(name, other, pid):
    call("ip", "link", "add", name, "type", "veth", "peer", "name", other)
    call("ip", "link", "set", other, "netns", str(pid))
    call("ip", "link", "set", name, "up")
    enter(pid, "ip", "link", "set", other, "up")
    enter(pid, "ip", "link", "set", "lo", "up")


def set_wg(pid, interface, private, peer, allowed, endpoint=None, port=None):
    with tempfile.NamedTemporaryFile(mode="w", prefix="wg-probe-", delete=False) as stream:
        stream.write(private + "\n")
        name = stream.name
    os.chmod(name, 0o600)
    try:
        args = ["wg", "set", interface, "private-key", name]
        if port:
            args += ["listen-port", str(port)]
        args += ["peer", peer, "allowed-ips", allowed]
        if endpoint:
            args += ["endpoint", endpoint]
        enter(pid, *args)
    finally:
        os.unlink(name)


if os.geteuid() != 0 or os.environ.get("VPROUTER_LAB_ISOLATED") != "1":
    raise SystemExit("Requires root and explicit isolated-network opt-in")
if {row["ifname"] for row in json.loads(call("ip", "-j", "link", "show"))} != {"lo"}:
    raise SystemExit("Refusing a network namespace with existing non-loopback links")

transport, provider, router, tailnet_client = (new_namespace() for _ in range(4))
server = None
try:
    call("ip", "link", "add", "br-vpr-uplink", "type", "bridge")
    call("ip", "addr", "add", "10.255.240.1/29", "dev", "br-vpr-uplink")
    call("ip", "link", "set", "br-vpr-uplink", "up")
    veth("host-t", "guest-t", transport.pid)
    call("ip", "link", "set", "host-t", "master", "br-vpr-uplink")
    enter(transport.pid, "ip", "addr", "add", "10.255.240.2/29", "dev", "guest-t")
    enter(transport.pid, "ip", "route", "add", "default", "via", "10.255.240.1")
    veth("host-e", "guest-e", provider.pid)
    call("ip", "addr", "add", "192.0.2.1/24", "dev", "host-e")
    enter(provider.pid, "ip", "addr", "add", "192.0.2.77/24", "dev", "guest-e")
    enter(provider.pid, "ip", "route", "add", "default", "via", "192.0.2.1")
    enter(router.pid, "ip", "link", "set", "lo", "up")
    enter(router.pid, "nft", "-f", str(Path(__file__).resolve().parents[1] / "router.nft"))
    Path("/proc/sys/net/ipv4/ip_forward").write_text("1")
    site = Site("probe", Path("/dev/null"), Path("/tmp"), "sha256:" + "a"*64,
                Path("/tmp"), Provider("10.1.1.1/32", "192.0.2.77", 51820, "", ""))
    install_guard(site)

    client_private = call("wg", "genkey")
    server_private = call("wg", "genkey")
    client_public = call("wg", "pubkey", input_text=client_private + "\n")
    server_public = call("wg", "pubkey", input_text=server_private + "\n")
    enter(provider.pid, "ip", "link", "add", "wg-peer", "type", "wireguard")
    set_wg(provider.pid, "wg-peer", server_private, client_public, "10.1.1.1/32", port=51820)
    enter(provider.pid, "ip", "addr", "add", "10.1.1.2/32", "dev", "wg-peer")
    enter(provider.pid, "ip", "link", "set", "wg-peer", "up")
    enter(provider.pid, "ip", "route", "add", "10.1.1.1/32", "dev", "wg-peer")
    enter(transport.pid, "ip", "link", "add", "wg0", "type", "wireguard")
    set_wg(transport.pid, "wg0", client_private, server_public, "0.0.0.0/0",
           endpoint="192.0.2.77:51820")
    enter(transport.pid, "ip", "link", "set", "wg0", "netns", str(router.pid))
    enter(router.pid, "ip", "addr", "add", "10.1.1.1/32", "dev", "wg0")
    enter(router.pid, "ip", "link", "set", "wg0", "up")
    enter(router.pid, "ip", "route", "add", "default", "dev", "wg0")

    sniff = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    sniff.bind(("host-t", 0))
    sniff.setblocking(False)
    server_code = """import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('10.1.1.2',7777));s.settimeout(4)
try:
 p,a=s.recvfrom(2048);print(p.decode(),flush=True);s.sendto(b'protected-reply',a)
except socket.timeout: print('TIMEOUT',flush=True)
"""
    server = subprocess.Popen(["nsenter", "-t", str(provider.pid), "-n", sys.executable, "-c", server_code],
                              stdout=subprocess.PIPE, text=True)
    time.sleep(.1)
    marker = "VPROUTER_CLEAR_PACKET_PROBE"
    client_code = """import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(3)
s.sendto(b'VPROUTER_CLEAR_PACKET_PROBE',('10.1.1.2',7777))
try: print(s.recvfrom(2048)[0].decode())
except socket.timeout: print('TIMEOUT')
"""
    reply = enter(router.pid, sys.executable, "-c", client_code)
    received, _ = server.communicate(timeout=5)
    packets = []
    while select.select([sniff], [], [], 0)[0]:
        packets.append(sniff.recv(65535))
    result = {"server_received": received.strip() == marker,
              "router_received_reply": reply.strip() == "protected-reply",
              "wireguard_handshake": bool(enter(router.pid, "wg", "show", "wg0", "latest-handshakes").split()[-1] != "0"),
              "plaintext_on_transport": any(marker.encode() in packet for packet in packets),
              "transport_packets": len(packets)}
    print(json.dumps(result))
    assert result["server_received"] and result["router_received_reply"] and result["wireguard_handshake"]
    assert not result["plaintext_on_transport"] and result["transport_packets"] > 0

    call("ip", "link", "add", "ts-router", "type", "veth", "peer", "name", "ts-client")
    call("ip", "link", "set", "ts-router", "netns", str(router.pid))
    call("ip", "link", "set", "ts-client", "netns", str(tailnet_client.pid))
    enter(router.pid, "ip", "link", "set", "ts-router", "name", "tailscale0")
    enter(router.pid, "ip", "addr", "add", "100.64.0.1/10", "dev", "tailscale0")
    enter(router.pid, "ip", "link", "set", "tailscale0", "up")
    enter(router.pid, "sysctl", "-w", "net.ipv4.ip_forward=1")
    enter(tailnet_client.pid, "ip", "link", "set", "lo", "up")
    enter(tailnet_client.pid, "ip", "addr", "add", "100.64.0.50/10", "dev", "ts-client")
    enter(tailnet_client.pid, "ip", "link", "set", "ts-client", "up")
    enter(tailnet_client.pid, "ip", "route", "add", "default", "via", "100.64.0.1")
    forward_server = subprocess.Popen(["nsenter", "-t", str(provider.pid), "-n", sys.executable, "-c", server_code],
                                      stdout=subprocess.PIPE, text=True)
    time.sleep(.1)
    forward_reply = enter(tailnet_client.pid, sys.executable, "-c", client_code)
    forwarded, _ = forward_server.communicate(timeout=5)
    forward_packets = []
    while select.select([sniff], [], [], 0)[0]:
        forward_packets.append(sniff.recv(65535))
    sniff.close()
    forward_result = {"tailnet_payload_reached_provider": forwarded.strip() == marker,
                      "tailnet_client_received_reply": forward_reply.strip() == "protected-reply",
                      "plaintext_on_transport": any(marker.encode() in packet for packet in forward_packets),
                      "transport_packets": len(forward_packets)}
    print(json.dumps(forward_result))
    assert forward_result["tailnet_payload_reached_provider"] and forward_result["tailnet_client_received_reply"]
    assert not forward_result["plaintext_on_transport"] and forward_result["transport_packets"] > 0
finally:
    if server and server.poll() is None:
        server.terminate()
    for process in (transport, provider, router, tailnet_client):
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
