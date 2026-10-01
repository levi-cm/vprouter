#!/usr/bin/env python3
"""Supervise the exit node only inside its WireGuard-only network namespace."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import urllib.request


POLICY = "/usr/local/share/vprouter/router.nft"
HEALTH = Path("/run/vprouter-health.json")
PROVIDER_CHECK = "https://am.i.mullvad.net/json"
# WireGuard starts rekeying at 120s but accepts the session until 180s.
# Rejecting at the rekey boundary disconnects a healthy, renewing tunnel.
HANDSHAKE_MAX_AGE = 180
RUNNING = True


class RuntimeErrorClosed(RuntimeError):
    pass


def run(*args, timeout=10):
    return subprocess.run(args, capture_output=True, text=True, check=True, timeout=timeout).stdout


def verify_interfaces(names):
    if "lo" not in names or "wg0" not in names or names - {"lo", "wg0", "tailscale0"}:
        raise RuntimeErrorClosed("unexpected or missing router interface")


def verify_boot_interfaces(names):
    if names != {"lo"}:
        raise RuntimeErrorClosed("router must boot with loopback only")


def verify_egress_response(data):
    if data.get("mullvad_exit_ip") is not True:
        raise RuntimeErrorClosed("VPN provider did not confirm protected egress")


def interface_names():
    return {link["ifname"] for link in json.loads(run("ip", "-j", "link", "show"))}


def verify_default_route():
    routes = json.loads(run("ip", "-j", "-4", "route", "show", "default"))
    if len(routes) != 1 or routes[0].get("dev") != "wg0":
        raise RuntimeErrorClosed("default route is not exclusively WireGuard")
    if json.loads(run("ip", "-j", "-6", "route", "show", "default")):
        raise RuntimeErrorClosed("public IPv6 default route is prohibited")


def wait_for_tailscaled(daemon, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if daemon.poll() is not None:
            raise RuntimeErrorClosed("tailscaled exited during startup")
        try:
            run("tailscale", "status", "--json", timeout=3)
            return
        except (OSError, subprocess.SubprocessError):
            time.sleep(1)
    raise RuntimeErrorClosed("tailscaled control socket did not become ready")


def provider_probe():
    verify_interfaces(interface_names())
    verify_default_route()
    with urllib.request.urlopen(PROVIDER_CHECK, timeout=12) as response:
        data = json.load(response)
        verify_egress_response(data)
    rows = run("wg", "show", "wg0", "latest-handshakes").splitlines()
    now = time.time()
    if len(rows) != 1 or not 0 <= now - int(rows[0].split()[-1]) < HANDSHAKE_MAX_AGE:
        raise RuntimeErrorClosed("WireGuard handshake is stale")
    return data


def collector_probe():
    data = provider_probe()
    if not tailscale_ready():
        raise RuntimeErrorClosed("Tailscale exit is not approved and online")
    return {"public_exit": data["ip"], "relay": data["mullvad_exit_ip_hostname"],
            "tunnel_healthy": True, "dns_guard": True, "ipv6_guard": True}


def tailscale_ready():
    status = json.loads(run("tailscale", "status", "--json"))
    node = status.get("Self")
    if (status.get("BackendState") != "Running" or not isinstance(node, dict)
            or node.get("Online") is not True or node.get("ExitNodeOption") is not True):
        return False
    prefs = json.loads(run("tailscale", "debug", "prefs"))
    return set(prefs.get("AdvertiseRoutes", [])) == {"0.0.0.0/0", "::/0"} and prefs.get("NetfilterMode") == 0


def set_health(state, reason):
    HEALTH.parent.mkdir(parents=True, exist_ok=True)
    temp = HEALTH.with_suffix(".tmp")
    now = int(time.time())
    temp.write_text(json.dumps({"state": state, "reason": reason, "time": now, "heartbeat": now}) + "\n")
    temp.replace(HEALTH)


def beat():
    data = json.loads(HEALTH.read_text())
    data["heartbeat"] = int(time.time())
    temp = HEALTH.with_suffix(".tmp")
    temp.write_text(json.dumps(data) + "\n")
    temp.replace(HEALTH)


def withdraw_exit_node(reason):
    set_health("BLOCKED", reason)
    # If LocalAPI is unavailable, let the failure escape. The outer finally
    # stops tailscaled and the host service reprovisions the namespace.
    run("tailscale", "down", timeout=5)


def block_failed_provider(up, reason):
    stop_process(up)
    withdraw_exit_node(reason)


def failure_reason(exc):
    # Internal check messages are safe; external errors can contain URLs.
    return str(exc) if isinstance(exc, RuntimeErrorClosed) else type(exc).__name__


def on_signal(_signum, _frame):
    global RUNNING
    RUNNING = False


def tailscale_up_command():
    return [
        "tailscale", "up", "--reset", "--advertise-exit-node",
        "--hostname=" + os.environ.get("TS_HOSTNAME", "max-vprouter"),
        "--accept-dns=false", "--accept-routes=false", "--netfilter-mode=off",
        "--ssh=false", "--snat-subnet-routes=false", "--timeout=30s",
    ]


def stop_process(proc):
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--status":
        try:
            data = json.loads(HEALTH.read_text())
            heartbeat = data["heartbeat"]
            return 0 if (data["state"] == "READY" and type(heartbeat) is int
                         and 0 <= time.time() - heartbeat < 45) else 1
        except (OSError, ValueError, KeyError):
            return 1

    if len(sys.argv) > 1 and sys.argv[1] == "--probe":
        print(json.dumps(collector_probe(), sort_keys=True))
        return 0

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    set_health("STARTING", "firewall")
    verify_boot_interfaces(interface_names())
    run("nft", "-f", POLICY)
    Path("/run/vprouter-firewall-ready").touch()
    set_health("BLOCKED", "waiting for WireGuard")
    while RUNNING and not Path("/run/vprouter-provisioned").is_file():
        beat()
        time.sleep(1)
    if not RUNNING:
        return 0
    verify_interfaces(interface_names())
    verify_default_route()
    daemon = subprocess.Popen(["tailscaled", "--statedir=/var/lib/tailscale"], close_fds=True)
    up = None
    serving = False
    successes = 0
    previous_check = 0.0
    next_up_at = 0.0
    up_backoff = 30.0
    try:
        # A persisted node may resume automatically. Clear its advertised exit
        # state before considering this run healthy.
        wait_for_tailscaled(daemon)
        run("tailscale", "down", timeout=20)
        while RUNNING:
            beat()
            if daemon.poll() is not None:
                raise RuntimeErrorClosed("tailscaled exited")
            now = time.monotonic()
            if now - previous_check >= 5:
                previous_check = now
                try:
                    provider_probe()
                    successes += 1
                except (OSError, ValueError, subprocess.SubprocessError, RuntimeErrorClosed) as exc:
                    successes = 0
                    block_failed_provider(up, failure_reason(exc))
                    up = None
                    serving = False
            if successes >= 3 and up is None and not serving and now >= next_up_at:
                up = subprocess.Popen(tailscale_up_command(), close_fds=True)
                set_health("RECOVERING", "starting Tailscale")
            if up and up.poll() is not None:
                if up.returncode != 0:
                    set_health("BLOCKED", "Tailscale authentication or control is unavailable")
                    run("tailscale", "down")
                    next_up_at = time.monotonic() + up_backoff
                    up_backoff = min(up_backoff * 2, 300.0)
                else:
                    next_up_at = time.monotonic() + up_backoff
                up = None
            if successes >= 3:
                try:
                    if tailscale_ready():
                        serving = True
                        up_backoff = 30.0
                        set_health("READY", "protected egress verified")
                    elif serving:
                        run("tailscale", "down")
                        serving = False
                        set_health("BLOCKED", "Tailscale is not ready")
                except (OSError, ValueError, subprocess.SubprocessError):
                    if serving:
                        serving = False
                        withdraw_exit_node("Tailscale health check failed")
            time.sleep(5)
    finally:
        set_health("BLOCKED", "stopping")
        stop_process(up)
        try:
            run("tailscale", "down", timeout=5)
        except (OSError, subprocess.SubprocessError):
            pass
        stop_process(daemon)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.SubprocessError, RuntimeErrorClosed) as exc:
        set_health("BLOCKED", type(exc).__name__)
        print(f"router stopped safely: {type(exc).__name__}", file=sys.stderr)
        sys.exit(1)
