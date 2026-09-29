"""Disposable Compose/provisioning integration test; no real VPN credentials.

Requires VPROUTER_LAB_ISOLATED=1 and root. Refuses an existing hardened guard,
bridge, test container, or test network; only removes resources it creates.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from host.orchestrate import Provider, Site, SiteError, compose, guard_snapshot, install_guard, provision_wireguard, router_health, wait_for_firewall


def command(*args):
    return subprocess.run(args, capture_output=True, text=True, check=True).stdout.strip()


def exists(*args):
    return subprocess.run(args, capture_output=True).returncode == 0


if os.geteuid() != 0 or os.environ.get("VPROUTER_LAB_ISOLATED") != "1":
    raise SystemExit("Requires root and explicit disposable-lab opt-in")
if exists("nft", "list", "table", "inet", "vprouter_guard"):
    raise SystemExit("Refusing to replace an existing host guard")
if exists("ip", "link", "show", "br-vpr-uplink"):
    raise SystemExit("Refusing to use an existing dedicated bridge")
for resource in ("vprouter-stage", "vprouter-stage-uplink"):
    if exists("docker", "container", "inspect", resource) or exists("docker", "network", "inspect", resource):
        raise SystemExit("Refusing an existing test resource")

root = Path(__file__).resolve().parents[1]
client_key = command("wg", "genkey")
peer_private = command("wg", "genkey")
peer_key = subprocess.run(["wg", "pubkey"], input=peer_private + "\n", text=True,
                          check=True, capture_output=True).stdout.strip()
with tempfile.TemporaryDirectory(prefix="vprouter-stage-") as directory:
    site = Site("vprouter-stage", Path("/dev/null"), Path(directory) / "state",
                command("docker", "image", "inspect", "--format", "{{.Id}}",
                        os.environ.get("ROUTER_TEST_IMAGE", "vprouter-hardened:staged")),
                root, Provider("10.1.1.1/32", "192.0.2.77", 51820, client_key, peer_key))
    site.state_dir.mkdir(mode=0o700)
    runtime = Path("/run/vprouter") / site.name
    runtime.mkdir(parents=True, mode=0o700, exist_ok=True)
    started = False
    guarded = False
    try:
        install_guard(site)
        guarded = True
        (runtime / "guard.snapshot.json").write_text(guard_snapshot())
        compose(site, "up", "-d", "transport", "router")
        started = True
        wait_for_firewall(site)
        try:
            provision_wireguard(site)
        except (subprocess.CalledProcessError, SiteError) as exc:
            logs = subprocess.run(["docker", "logs", site.name], capture_output=True, text=True)
            print(json.dumps({"failed_command": getattr(exc, "cmd", None), "stderr": getattr(exc, "stderr", None),
                              "router_state": command("docker", "inspect", "--format", "{{json .State}}", site.name),
                              "router_logs": logs.stdout + logs.stderr}), file=sys.stderr)
            raise
        time.sleep(2)
        router_links = json.loads(command("docker", "exec", site.name, "ip", "-j", "link", "show"))
        transport_links = json.loads(command("docker", "exec", site.name + "-uplink", "ip", "-j", "link", "show"))
        router_names = {item["ifname"] for item in router_links}
        transport_names = {item["ifname"] for item in transport_links}
        health = json.loads(command("docker", "exec", site.name, "cat", "/run/vprouter-health.json"))
        result = {"router_interfaces": sorted(router_names), "transport_interfaces": sorted(transport_names),
                  "router_network_mode": command("docker", "inspect", "--format", "{{.HostConfig.NetworkMode}}", site.name),
                  "unreachable_provider_state": health["state"]}
        print(json.dumps(result))
        assert router_names <= {"lo", "wg0", "tailscale0"} and "wg0" in router_names
        assert transport_names == {"lo", "eth0"}
        assert result["router_network_mode"] == "none"
        assert health["state"] == "BLOCKED"
        try:
            router_health(site.name)
            raise AssertionError("unreachable provider was reported as ready")
        except SiteError:
            pass
    finally:
        if started:
            compose(site, "down", "--remove-orphans")
        if guarded:
            command("nft", "delete", "table", "inet", "vprouter_guard")
        (runtime / "guard.snapshot.json").unlink(missing_ok=True)
        runtime.rmdir()
