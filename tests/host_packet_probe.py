"""Exercise the real host nft guard in an unshared, internet-disconnected network.

Run as: sudo unshare --net python3 tests/host_packet_probe.py
"""

import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from host.orchestrate import Provider, Site, guard_snapshot, install_guard, verify_bridge


def call(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def link_to_namespace(host_end, guest_end, pid, host_address, guest_address):
    call("ip", "link", "add", host_end, "type", "veth", "peer", "name", guest_end)
    call("ip", "link", "set", guest_end, "netns", str(pid))
    call("ip", "addr", "add", host_address, "dev", host_end)
    call("ip", "link", "set", host_end, "up")
    call("nsenter", "-t", str(pid), "-n", "ip", "addr", "add", guest_address, "dev", guest_end)
    call("nsenter", "-t", str(pid), "-n", "ip", "link", "set", guest_end, "up")
    call("nsenter", "-t", str(pid), "-n", "ip", "link", "set", "lo", "up")


if os.geteuid() != 0 or os.environ.get("VPROUTER_LAB_ISOLATED") != "1":
    raise SystemExit("Requires root and explicit isolated-network opt-in")
if {row["ifname"] for row in json.loads(call("ip", "-j", "link", "show"))} != {"lo"}:
    raise SystemExit("Refusing a network namespace with existing non-loopback links")

transport = subprocess.Popen(["unshare", "--net", "sleep", "60"])
endpoint = subprocess.Popen(["unshare", "--net", "sleep", "60"])
server = None
try:
    call("ip", "link", "add", "br-vpr-uplink", "type", "bridge")
    call("ip", "addr", "add", "10.255.240.1/29", "dev", "br-vpr-uplink")
    call("ip", "link", "set", "br-vpr-uplink", "up")
    link_to_namespace("host-t", "guest-t", transport.pid, "10.255.240.3/29", "10.255.240.2/29")
    call("ip", "link", "set", "host-t", "master", "br-vpr-uplink")
    link_to_namespace("host-e", "guest-e", endpoint.pid, "192.0.2.1/24", "192.0.2.77/24")
    call("nsenter", "-t", str(transport.pid), "-n", "ip", "route", "add", "default", "via", "10.255.240.1")
    call("nsenter", "-t", str(endpoint.pid), "-n", "ip", "route", "add", "default", "via", "192.0.2.1")
    Path("/proc/sys/net/ipv4/ip_forward").write_text("1")
    site = Site("probe", Path("/dev/null"), Path("/tmp"), "sha256:" + "a"*64,
                Path("/tmp"), Provider("10.1.1.1/32", "192.0.2.77", 51820, "", ""))
    install_guard(site)
    install_guard(site)  # Replacing an existing guard must work without a gap.
    before_counter = guard_snapshot()
    ping = subprocess.run(["ping", "-c", "1", "-W", "1", "192.0.2.77"],
                          capture_output=True, text=True)
    assert ping.returncode != 0, "host ICMP to the provider was not blocked"
    output_rules = json.loads(call("nft", "-j", "list", "chain", "inet", "vprouter_guard", "output"))["nftables"]
    drops = [expr["counter"]["packets"] for entry in output_rules
             for expr in entry.get("rule", {}).get("expr", []) if "counter" in expr]
    assert drops and drops[0] >= 1, "host output drop counter did not advance"
    assert guard_snapshot() == before_counter, "counter activity changed the policy snapshot"
    print(json.dumps({"host_provider_icmp_blocked": True,
                      "host_output_drop_count": drops[0]}))

    host_listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    host_listener.bind(("10.255.240.1", 51820))
    server_code = """import select,socket,time
good=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);good.bind(('192.0.2.77',51820))
bad=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);bad.bind(('192.0.2.77',51821))
seen=[]; deadline=time.monotonic()+2
while time.monotonic()<deadline:
 ready,_,_=select.select([good,bad],[],[],max(0,deadline-time.monotonic()))
 for s in ready:
  p,a=s.recvfrom(2048);seen.append(p.decode())
  if s is good: s.sendto(b'reply',a)
print(','.join(seen),flush=True)
"""
    server = subprocess.Popen(["nsenter", "-t", str(endpoint.pid), "-n", sys.executable, "-c", server_code],
                              stdout=subprocess.PIPE, text=True)
    time.sleep(.1)
    client_code = """import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(1)
s.sendto(b'allowed',('192.0.2.77',51820))
try: print(s.recvfrom(1024)[0].decode())
except socket.timeout: print('TIMEOUT')
s.sendto(b'wrong-port',('192.0.2.77',51821))
s.sendto(b'host-input',('10.255.240.1',51820))
"""
    response = call("nsenter", "-t", str(transport.pid), "-n", sys.executable, "-c", client_code)
    received, _ = server.communicate(timeout=5)
    host_input_received = bool(select.select([host_listener], [], [], 0)[0])
    host_listener.close()
    result = {"allowed_endpoint_received": received.strip() == "allowed",
              "return_packet_received": "reply" in response,
              "other_payload_received": "wrong-port" in received or host_input_received}
    print(json.dumps(result))
    assert result == {"allowed_endpoint_received": True, "return_packet_received": True,
                      "other_payload_received": False}, result

    expected = guard_snapshot()
    call("nft", "flush", "table", "inet", "vprouter_guard")
    assert guard_snapshot() != expected, "a removed guard must be detected"
    install_guard(site)
    assert guard_snapshot() == expected, "a reinstalled guard must match its original snapshot"
    call("ip", "link", "set", "br-vpr-uplink", "name", "br-vpr-renamed")
    try:
        verify_bridge()
        raise AssertionError("a renamed bridge was not detected")
    except subprocess.CalledProcessError:
        pass
    blocked_code = """import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('192.0.2.77',51820));s.settimeout(.5)
try: print(s.recvfrom(2048)[0].decode())
except socket.timeout: print('BLOCKED')
"""
    blocked_server = subprocess.Popen(["nsenter", "-t", str(endpoint.pid), "-n", sys.executable, "-c", blocked_code],
                                      stdout=subprocess.PIPE, text=True)
    time.sleep(.1)
    call("nsenter", "-t", str(transport.pid), "-n", sys.executable, "-c",
         "import socket;socket.socket(socket.AF_INET,socket.SOCK_DGRAM).sendto(b'renamed-bridge',('192.0.2.77',51820))")
    blocked_result, _ = blocked_server.communicate(timeout=2)
    assert blocked_result.strip() == "BLOCKED", blocked_result
    print(json.dumps({"renamed_bridge_outbound_blocked": True, "flushed_guard_detected": True}))
finally:
    if server and server.poll() is None:
        server.terminate()
    for process in (transport, endpoint):
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
