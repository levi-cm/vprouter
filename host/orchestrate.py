#!/usr/bin/env python3
"""Provision a WireGuard-only router namespace. Run as a root-owned systemd unit."""

import base64
import argparse
import configparser
from dataclasses import dataclass, field
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time


BRIDGE = "br-vpr-uplink"
TRANSPORT_IP = "10.255.240.2"


class SiteError(ValueError):
    pass


@dataclass(frozen=True)
class Provider:
    address: str
    endpoint_ip: str
    endpoint_port: int
    private_key: str = field(repr=False)
    public_key: str = field(repr=False)


@dataclass(frozen=True)
class Site:
    name: str
    profile: Path
    state_dir: Path
    image_ref: str
    compose_dir: Path
    provider: Provider = field(repr=False)


def _key(value: str) -> str:
    try:
        if len(base64.b64decode(value, validate=True)) != 32:
            raise ValueError("wrong key length")
    except (ValueError, base64.binascii.Error) as exc:
        raise SiteError("WireGuard profile contains an invalid key") from exc
    return value


def _provider(path: Path) -> Provider:
    cfg = configparser.ConfigParser(interpolation=None, strict=True)
    try:
        with path.open(encoding="utf-8") as stream:
            cfg.read_file(stream)
        if set(cfg.sections()) != {"Interface", "Peer"}:
            raise SiteError("profile must contain exactly one Interface and one Peer")
        private = _key(cfg["Interface"]["PrivateKey"].strip())
        public = _key(cfg["Peer"]["PublicKey"].strip())
        address = cfg["Interface"]["Address"].split(",", 1)[0].strip()
        interface = ipaddress.ip_interface(address)
        if interface.version != 4 or interface.network.prefixlen != 32:
            raise SiteError("WireGuard needs an IPv4 /32 address")
        allowed = {part.strip() for part in cfg["Peer"]["AllowedIPs"].split(",")}
        if "0.0.0.0/0" not in allowed:
            raise SiteError("WireGuard must cover the IPv4 default route")
        endpoint = cfg["Peer"]["Endpoint"].strip()
        raw_ip, separator, raw_port = endpoint.rpartition(":")
        if not separator:
            raise SiteError("WireGuard endpoint must be IPv4:port")
        endpoint_ip = str(ipaddress.IPv4Address(raw_ip))
        port = int(raw_port)
        if not 1 <= port <= 65535:
            raise SiteError("invalid WireGuard endpoint port")
        return Provider(address, endpoint_ip, port, private, public)
    except (OSError, KeyError, configparser.Error, ValueError) as exc:
        if isinstance(exc, SiteError):
            raise
        raise SiteError("invalid or unreadable WireGuard profile") from exc


def load_site(path: Path) -> Site:
    try:
        cfg = json.loads(Path(path).read_text(encoding="utf-8"))
        if set(cfg) != {"name", "profile", "state_dir", "image_ref", "compose_dir"}:
            raise SiteError("unexpected or missing site configuration field")
        name = cfg["name"]
        if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9-]{1,49}", name):
            raise SiteError("invalid router name")
        image = cfg["image_ref"]
        if not isinstance(image, str) or not re.fullmatch(r"(?:sha256:|[a-zA-Z0-9._/-]+@sha256:)[a-f0-9]{64}", image):
            raise SiteError("image must be pinned to a digest or image ID")
        paths = [Path(cfg[key]) for key in ("profile", "state_dir", "compose_dir")]
        if any(not item.is_absolute() for item in paths):
            raise SiteError("all site paths must be absolute")
        return Site(name, paths[0], paths[1], image, paths[2], _provider(paths[0]))
    except (OSError, ValueError, TypeError, KeyError) as exc:
        if isinstance(exc, SiteError):
            raise
        raise SiteError("invalid or unreadable site configuration") from exc


def render_host_guard(site: Site) -> str:
    endpoint = site.provider.endpoint_ip
    port = site.provider.endpoint_port
    return f"""add table inet vprouter_guard
add chain inet vprouter_guard forward {{ type filter hook forward priority -150; policy accept; }}
add chain inet vprouter_guard input {{ type filter hook input priority -150; policy accept; }}
add chain inet vprouter_guard output {{ type filter hook output priority -150; policy accept; }}
add rule inet vprouter_guard forward iifname "{BRIDGE}" ip saddr {TRANSPORT_IP} ip daddr {endpoint} udp dport {port} accept
add rule inet vprouter_guard forward ip saddr 10.255.240.0/29 drop
add rule inet vprouter_guard forward iifname "{BRIDGE}" drop
add rule inet vprouter_guard forward oifname "{BRIDGE}" ct state established,related ip saddr {endpoint} udp sport {port} ip daddr {TRANSPORT_IP} accept
add rule inet vprouter_guard forward ip daddr 10.255.240.0/29 drop
add rule inet vprouter_guard forward oifname "{BRIDGE}" drop
add rule inet vprouter_guard input ip saddr 10.255.240.0/29 drop
add rule inet vprouter_guard input iifname "{BRIDGE}" drop
add rule inet vprouter_guard output ip daddr {endpoint} ip protocol icmp counter drop
"""


def render_wg_config(site: Site) -> str:
    p = site.provider
    return f"""[Interface]
PrivateKey = {p.private_key}

[Peer]
PublicKey = {p.public_key}
AllowedIPs = 0.0.0.0/0
Endpoint = {p.endpoint_ip}:{p.endpoint_port}
PersistentKeepalive = 25
"""


def command(*args, timeout=30, env=None, input_text=None):
    return subprocess.run(
        args, input=input_text, capture_output=True, text=True, check=True,
        timeout=timeout, env=env,
    ).stdout.strip()


def compose_env(site: Site):
    return {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/root",
        "ROUTER_NAME": site.name,
        "ROUTER_IMAGE": site.image_ref,
        "TS_STATE_PATH": str(site.state_dir),
        "VPN_DNS": "9.9.9.9",
        "UPLINK_NETWORK": site.name + "-uplink",
    }


def compose(site: Site, *args, timeout=90):
    return command(
        "docker", "compose", "-f", str(site.compose_dir / "docker-compose.yaml"),
        "--project-name", site.name, *args, timeout=timeout, env=compose_env(site),
    )


def assert_host_ownership(site: Site, config_path: Path):
    private = (config_path, site.profile, site.state_dir)
    release = (site.compose_dir, site.compose_dir / "docker-compose.yaml",
               site.compose_dir / "Dockerfile", site.compose_dir / "router.nft",
               site.compose_dir / "router_runtime.py", site.compose_dir / "host" / "orchestrate.py")
    for path in private + release:
        if path.is_symlink():
            raise SiteError("managed paths may not be symbolic links")
        info = path.stat()
        if info.st_uid != 0 or info.st_mode & (0o077 if path in private else 0o022):
            raise SiteError("managed paths must be root-owned with restricted permissions")
        for parent in path.parents:
            if parent == Path("/"):
                break
            parent_info = parent.stat()
            if parent.is_symlink() or parent_info.st_uid != 0 or parent_info.st_mode & 0o022:
                raise SiteError("parent directories must be root-owned and not writable by others")


def runtime_path(site: Site):
    return Path("/run/vprouter") / site.name


def install_guard(site: Site):
    policy = render_host_guard(site)
    already_installed = subprocess.run(
        ["/usr/sbin/nft", "list", "table", "inet", "vprouter_guard"],
        capture_output=True, check=False,
    ).returncode == 0
    if already_installed:
        # nft -f commits this replacement as one transaction, so a restart
        # neither trusts stale rules nor creates a permissive gap.
        policy = "delete table inet vprouter_guard\n" + policy
    command("/usr/sbin/nft", "-c", "-f", "-", input_text=policy)
    command("/usr/sbin/nft", "-f", "-", input_text=policy)


def guard_snapshot():
    document = json.loads(command("/usr/sbin/nft", "-j", "list", "table", "inet", "vprouter_guard"))
    for entry in document["nftables"]:
        for value in entry.values():
            if isinstance(value, dict):
                value.pop("handle", None)
                for expression in value.get("expr", []):
                    if "counter" in expression:
                        expression["counter"] = {"packets": 0, "bytes": 0}
    return json.dumps(document, sort_keys=True, separators=(",", ":"))


def verify_bridge():
    rows = json.loads(command("/usr/bin/ip", "-d", "-j", "link", "show", BRIDGE))
    if len(rows) != 1 or rows[0].get("linkinfo", {}).get("info_kind") != "bridge":
        raise SiteError("dedicated transport bridge changed")


def inspect_pid(container_name: str) -> int:
    pid = int(command("docker", "inspect", "--format", "{{.State.Pid}}", container_name))
    if pid < 2:
        raise SiteError("container has no running network namespace")
    return pid


def in_netns(pid: int, *args):
    return command("/usr/bin/nsenter", "-t", str(pid), "-n", *args)


def provision_wireguard(site: Site):
    router_pid = inspect_pid(site.name)
    transport_pid = inspect_pid(site.name + "-uplink")
    router_links = json.loads(in_netns(router_pid, "ip", "-j", "link", "show"))
    if {link["ifname"] for link in router_links} != {"lo"}:
        raise SiteError("router namespace must have only loopback before provisioning")
    transport_links = json.loads(in_netns(transport_pid, "ip", "-j", "link", "show"))
    if {link["ifname"] for link in transport_links} != {"lo", "eth0"}:
        raise SiteError("transport namespace has unexpected interfaces")
    in_netns(transport_pid, "ip", "link", "add", "wg0", "type", "wireguard")
    private_file = None
    try:
        fd, name = tempfile.mkstemp(prefix="wg-", dir=runtime_path(site))
        private_file = Path(name)
        with os.fdopen(fd, "w") as stream:
            stream.write(render_wg_config(site))
        private_file.chmod(0o600)
        in_netns(transport_pid, "/usr/bin/wg", "setconf", "wg0", str(private_file))
    finally:
        if private_file is not None:
            private_file.unlink(missing_ok=True)
    in_netns(transport_pid, "ip", "link", "set", "wg0", "netns", str(router_pid))
    in_netns(router_pid, "ip", "addr", "add", site.provider.address, "dev", "wg0")
    in_netns(router_pid, "ip", "link", "set", "wg0", "up")
    in_netns(router_pid, "ip", "route", "replace", "default", "dev", "wg0")
    # The router runtime has already installed its restrictive nftables policy.
    for attempt in range(5):
        try:
            command("docker", "exec", site.name, "/bin/touch", "/run/vprouter-provisioned")
            break
        except subprocess.CalledProcessError:
            if attempt == 4:
                raise
            if command("docker", "inspect", "--format", "{{.State.Running}}", site.name) != "true":
                raise SiteError("router exited before provisioning completed")
            time.sleep(1)


def wait_for_firewall(site: Site, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if command("docker", "inspect", "--format", "{{.State.Running}}", site.name) != "true":
            raise SiteError("router exited before installing its firewall")
        ready = subprocess.run(
            ["docker", "exec", site.name, "/bin/sh", "-c", "test -f /run/vprouter-firewall-ready"],
            capture_output=True, timeout=5,
        ).returncode == 0
        if ready:
            return
        time.sleep(.5)
    raise SiteError("router firewall was not ready before provisioning")


def startup(site: Site, config_path: Path):
    if os.geteuid() != 0:
        raise SiteError("host provisioning requires root")
    if config_path.stem != site.name:
        raise SiteError("service instance and container name must match")
    site.state_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    assert_host_ownership(site, config_path)
    own_runtime = runtime_path(site)
    own_runtime.mkdir(parents=True, mode=0o700, exist_ok=True)
    runtime_info = own_runtime.stat()
    if runtime_info.st_uid != 0 or runtime_info.st_mode & 0o077:
        raise SiteError("runtime directory must be root-owned and private")
    with (own_runtime / "lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        signal.signal(signal.SIGTERM, request_stop)
        signal.signal(signal.SIGINT, request_stop)
        command("docker", "image", "inspect", site.image_ref)
        install_guard(site)
        guard = guard_snapshot()
        snapshot_file = own_runtime / "guard.snapshot.json"
        snapshot_file.write_text(guard)
        snapshot_file.chmod(0o600)
        # A prior failed attempt is stopped before its namespace is recreated.
        compose(site, "down", "--remove-orphans")
        try:
            compose(site, "up", "-d", "--no-recreate", "transport", "router")
            verify_bridge()
            wait_for_firewall(site)
            provision_wireguard(site)
            monitor(site, guard)
        finally:
            stop_containers(site)


def stop_containers(site: Site):
    for name in (site.name, site.name + "-uplink"):
        stop_owned_container(name, site.name)


def stop_owned_container(container_name: str, project_name: str):
    inspect = subprocess.run(
        ["docker", "inspect", "--format", "{{index .Config.Labels \"com.docker.compose.project\"}}", container_name],
        capture_output=True, text=True, timeout=10,
    )
    if inspect.returncode != 0 or inspect.stdout.strip() != project_name:
        return
    if command("docker", "inspect", "--format", "{{.State.Running}}", container_name) != "true":
        return
    try:
        command("docker", "stop", "-t", "2", container_name, timeout=15)
    except subprocess.SubprocessError:
        if command("docker", "inspect", "--format", "{{.State.Running}}", container_name) == "true":
            command("docker", "kill", container_name, timeout=15)


def cleanup_owned(project_name: str):
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,49}", project_name):
        raise SiteError("invalid cleanup project name")
    for name in (project_name, project_name + "-uplink"):
        stop_owned_container(name, project_name)


def owned_running(container_name: str, project_name: str) -> bool:
    label = command("docker", "inspect", "--format", "{{index .Config.Labels \"com.docker.compose.project\"}}", container_name)
    running = command("docker", "inspect", "--format", "{{.State.Running}}", container_name)
    return label == project_name and running == "true"


def router_health(project_name: str) -> dict:
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,49}", project_name):
        raise SiteError("invalid project name")
    if not all(owned_running(name, project_name) for name in (project_name, project_name + "-uplink")):
        raise SiteError("a managed container is not running")
    verify_bridge()
    expected_guard = (Path("/run/vprouter") / project_name / "guard.snapshot.json").read_text()
    if guard_snapshot() != expected_guard:
        raise SiteError("host firewall guard changed")
    verify_router_tunnel(project_name)
    data = json.loads(command("docker", "exec", project_name, "cat", "/run/vprouter-health.json", timeout=5))
    observed_time = data.get("time")
    if not isinstance(observed_time, int) or data.get("state") != "READY" or not 0 <= time.time() - observed_time < 45:
        raise SiteError("router health is not READY and fresh")
    return {"name": project_name, "state": "READY", "time": data["time"]}


def verify_router_tunnel(project_name: str):
    """Restart provisioning if the kernel tunnel structure has been lost."""
    router_pid = inspect_pid(project_name)
    links = json.loads(in_netns(router_pid, "ip", "-j", "-d", "link", "show", "dev", "wg0"))
    if (len(links) != 1 or links[0].get("ifname") != "wg0"
            or links[0].get("linkinfo", {}).get("info_kind") != "wireguard"
            or "UP" not in links[0].get("flags", [])):
        raise SiteError("router WireGuard interface is missing or down")
    routes = json.loads(in_netns(router_pid, "ip", "-j", "-4", "route", "show", "default"))
    if len(routes) != 1 or routes[0].get("dev") != "wg0":
        raise SiteError("router WireGuard default route is missing")


def notify_status(message: str):
    target = os.environ.get("NOTIFY_SOCKET")
    if not target:
        return
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as connection:
            connection.sendto(("STATUS=" + message).encode(), ("\0" + target[1:]) if target.startswith("@") else target)
    except OSError:
        pass


def monitor(site: Site, expected_guard: str):
    last_health = None
    while not STOP:
        if guard_snapshot() != expected_guard:
            raise SiteError("host firewall guard changed")
        verify_bridge()
        for name in (site.name, site.name + "-uplink"):
            if command("docker", "inspect", "--format", "{{.State.Running}}", name) != "true":
                raise SiteError("essential container exited")
        verify_router_tunnel(site.name)
        try:
            health = json.loads(command("docker", "exec", site.name, "cat", "/run/vprouter-health.json", timeout=5))
            state = health.get("state", "UNKNOWN")
        except (OSError, ValueError, subprocess.SubprocessError):
            state = "UNKNOWN"
        if state != last_health:
            print(f"vprouter {site.name}: {state}", flush=True)
            notify_status(site.name + ": " + state)
            last_health = state
        time.sleep(2)


STOP = False


def request_stop(_signum, _frame):
    global STOP
    STOP = True


def main():
    parser = argparse.ArgumentParser(description="Manage a WireGuard-only Tailscale exit node")
    parser.add_argument("action", choices=["validate", "serve", "cleanup", "status"])
    parser.add_argument("--config", type=Path)
    parser.add_argument("--name")
    args = parser.parse_args()
    if args.action in ("cleanup", "status"):
        if not args.name or args.config:
            parser.error("cleanup/status require --name and no --config")
        if args.action == "cleanup":
            cleanup_owned(args.name)
        else:
            print(json.dumps(router_health(args.name)))
        return 0
    if not args.config or args.name:
        parser.error("validate/serve require --config and no --name")
    site = load_site(args.config)
    if args.action == "validate":
        print(json.dumps({
            "name": site.name, "endpoint": f"{site.provider.endpoint_ip}:{site.provider.endpoint_port}",
            "image_ref": site.image_ref, "state_dir": str(site.state_dir),
        }))
        return 0
    startup(site, args.config)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.SubprocessError, SiteError) as exc:
        print(f"vprouter host guard stopped: {type(exc).__name__}", file=sys.stderr)
        sys.exit(1)
