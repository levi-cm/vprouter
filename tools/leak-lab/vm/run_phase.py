#!/usr/bin/env python3
"""Run one external leak-lab phase against the provisioned vprlab VM.

Execute as root on debdev:

    python3 -B tools/leak-lab/vm/run_phase.py \
        --phase start-router --duration 120 \
        --profile-file /root/vprouter-lab.conf \
        --used-nonces /root/leaklab-used-nonces.txt --index 1

The runner refuses to start unless exactly one guest can run (it holds the
global ``/run/vprlab/run.lock``), the host lab network exists with the M1
ownership token, gateway MAC and static neighbour, the state overlay is backed
by the pinned base image, and the profile's declared Mullvad endpoint is a
public IPv4 endpoint.  The policy is built here from that endpoint and the
fixed lab values; there is no operator-supplied policy or extra endpoint.

Capture order: tcpdump first, then QEMU (tap only), QGA, silence check, secrets,
BEFORE control, phase action, duration, AFTER control, stop/disable router
units, guest poweroff, wait for QEMU to exit, verify AFTER reached the pcap,
2 s quiet, SIGINT tcpdump, scan.

Exit code is the final phase result: 0 PASS, 1 LEAK, 2 INVALID.  A clean
capture never certifies a phase whose setup, action, postcondition, cleanup or
QEMU exit failed.  LEAK keeps precedence over every phase error.

The WireGuard profile is read once and only passed to QGA guest-file-write.
It is never logged, printed, hashed into the record, or copied to the state
directory.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import secrets
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import time

_VM_DIR = pathlib.Path(__file__).resolve().parent
_LEAK_LAB_DIR = _VM_DIR.parent
if str(_LEAK_LAB_DIR) not in sys.path:
    sys.path.insert(0, str(_LEAK_LAB_DIR))

import control as control_mod  # noqa: E402  (read-only import of reviewed module)
import policy as policy_mod  # noqa: E402
import tsnames  # noqa: E402

import guest  # noqa: E402
import hostcheck  # noqa: E402
import login_url as login_url_mod  # noqa: E402
import runlock  # noqa: E402
from qga import ExecResult, QGAClient, QGAError, wait_for_qga  # noqa: E402

PHASES = (
    "start-router",
    "idle",
    "login",
    "reboot-with-router-enabled",
    "stop-router",
    "kill-wireguard",
    "kill-container",
    "restart-docker",
)
#: Phases that start the router as a setup step, wait for a live WireGuard
#: handshake, and only then apply their action.  ``idle`` and ``login`` have no
#: destructive action; the other four inject a fault.
SETUP_PHASES = frozenset(
    {"idle", "login", "stop-router", "kill-wireguard", "kill-container", "restart-docker"}
)
FAULT_PHASES = frozenset(
    {"stop-router", "kill-wireguard", "kill-container", "restart-docker"}
)

#: Fixed phase -> tunnel expectation table.  Every phase that measures a
#: router must show a pre-fault WireGuard handshake; the fault is proven by an
#: in-guest postcondition, never by a whole-window "down".
PHASE_EXPECTATIONS = {
    "start-router": "up",
    "idle": "up",
    "login": "up",
    "reboot-with-router-enabled": "up",
    "stop-router": "up",
    "kill-wireguard": "up",
    "kill-container": "up",
    "restart-docker": "up",
}

MAX_PROFILE_BYTES = 65536
SILENCE_TIMEOUT = 180.0
QGA_BOOT_TIMEOUT = 180.0
ACTION_TIMEOUT = 360.0
ROUTER_ACTIVE_TIMEOUT = 180.0
ROUTER_HANDSHAKE_TIMEOUT = 120.0
DOCKER_RESTART_TIMEOUT = 120.0
POWEROFF_TIMEOUT = 180.0
AFTER_CAPTURE_TIMEOUT = 30.0
QUIET_SECONDS = 2.0
USED_NONCES_MODE = 0o600
SINK_UDP_PORT = 39001
EVIDENCE_ROOT = pathlib.Path("/DATA/vprouter-lab/leaklab/evidence")


def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with pathlib.Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_root() -> None:
    """Separate function so offline tests can exercise the rest as non-root."""
    if os.geteuid() != 0:
        raise hostcheck.Refusal("phase execution requires root")


# ---------------------------------------------------------------------------
# Secrets


@dataclasses.dataclass(frozen=True)
class SecretMaterial:
    """Bytes that must never be rendered by repr or the phase record."""

    data: bytes = dataclasses.field(repr=False)

    def __repr__(self) -> str:
        return "SecretMaterial(<redacted>)"


def read_profile_fd(fd: int) -> SecretMaterial:
    """Read a profile from an inherited file descriptor without logging it."""
    try:
        duplicate = os.dup(fd)
    except OSError as exc:
        raise hostcheck.Refusal("profile file descriptor is not usable") from exc
    chunks: list[bytes] = []
    total = 0
    try:
        while True:
            chunk = os.read(duplicate, 4096)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_PROFILE_BYTES:
                raise hostcheck.Refusal("profile is unreasonably large")
            chunks.append(chunk)
    finally:
        os.close(duplicate)
    if total == 0:
        raise hostcheck.Refusal("profile is empty")
    return SecretMaterial(b"".join(chunks))


def read_profile_path(path: pathlib.Path, *, owner_uid: int | None = 0) -> SecretMaterial:
    """Read a root-only regular file; refuse symlinks and open modes."""
    path = pathlib.Path(path)
    try:
        info = path.lstat()
    except OSError as exc:
        raise hostcheck.Refusal(f"profile file is unreadable: {exc.__class__.__name__}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise hostcheck.Refusal("profile must be a regular file, not a symlink")
    if owner_uid is not None and info.st_uid != owner_uid:
        raise hostcheck.Refusal("profile must be owned by root")
    if info.st_mode & 0o077:
        raise hostcheck.Refusal("profile must be mode 0600 (no group/other access)")
    if info.st_size <= 0 or info.st_size > MAX_PROFILE_BYTES:
        raise hostcheck.Refusal("profile size is invalid")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise hostcheck.Refusal(f"profile file is unreadable: {exc.__class__.__name__}") from exc
    return SecretMaterial(data)


def profile_endpoint(material: SecretMaterial) -> tuple[str, int]:
    """Extract only ``[Peer] Endpoint``; never return or log key material.

    Only the Endpoint line is decoded; a ``PrivateKey`` line is never converted
    to text in this function.
    """
    section = b""
    endpoint: str | None = None
    for raw in material.data.splitlines():
        stripped = raw.strip()
        if not stripped or stripped[:1] in (b"#", b";"):
            continue
        if stripped.startswith(b"[") and stripped.endswith(b"]"):
            section = stripped[1:-1].strip().lower()
            continue
        if section != b"peer" or b"=" not in stripped:
            continue
        key, _, value = stripped.partition(b"=")
        if key.strip().lower() == b"endpoint":
            try:
                endpoint = value.strip().decode("ascii")
            except UnicodeDecodeError as exc:
                raise hostcheck.Refusal("profile endpoint is not ASCII") from exc
    if endpoint is None:
        raise hostcheck.Refusal("profile has no [Peer] Endpoint")
    raw_ip, separator, raw_port = endpoint.rpartition(":")
    if not separator:
        raise hostcheck.Refusal("profile endpoint must be IPv4:port")
    try:
        address = str(ipaddress.IPv4Address(raw_ip))
        port = int(raw_port)
    except ValueError as exc:
        raise hostcheck.Refusal("profile endpoint is not a valid IPv4:port") from exc
    if not 1 <= port <= 65535:
        raise hostcheck.Refusal("profile endpoint port is invalid")
    return address, port


def build_lab_policy(endpoint: tuple[str, int]) -> policy_mod.Policy:
    """Build the single-flow policy from the profile endpoint and lab facts."""
    address, port = endpoint
    document = {
        "schema_version": 1,
        "vm_wan_mac": guest.VM_MAC,
        "vm_wan_ipv4": guest.VM_IPV4,
        "gateway_ipv4": guest.GATEWAY_IPV4,
        "gateway_mac": guest.GATEWAY_MAC,
        "allowed": [
            {
                "proto": "udp",
                "dst_ipv4": address,
                "dst_port": port,
                "label": "profile-endpoint",
            }
        ],
        "allow_arp": False,
        "positive_control": {
            "sink_ipv4": guest.GATEWAY_IPV4,
            "sink_udp_port": SINK_UDP_PORT,
        },
        "ipv6_allowed": False,
    }
    try:
        policy = policy_mod.parse_policy(document)
    except policy_mod.PolicyError as exc:
        raise hostcheck.Refusal(f"profile endpoint is not usable: {exc}") from exc
    verify_policy(policy, endpoint=endpoint)
    return policy


def verify_policy(
    policy: policy_mod.Policy,
    *,
    endpoint: tuple[str, int] | None = None,
    vm_mac: str = guest.VM_MAC,
    vm_ipv4: str = guest.VM_IPV4,
    gateway_ipv4: str = guest.GATEWAY_IPV4,
    gateway_mac: str = guest.GATEWAY_MAC,
) -> None:
    """Refuse a policy that does not describe this fixed lab topology."""
    if policy.vm_wan_mac != vm_mac:
        raise hostcheck.Refusal("policy vm_wan_mac does not match the fixed lab MAC")
    if policy.vm_wan_ipv4 != vm_ipv4:
        raise hostcheck.Refusal("policy vm_wan_ipv4 does not match the lab VM address")
    if policy.gateway_ipv4 != gateway_ipv4:
        raise hostcheck.Refusal("policy gateway_ipv4 does not match the lab gateway")
    if policy.gateway_mac is None or policy.gateway_mac != gateway_mac:
        raise hostcheck.Refusal(
            "policy gateway_mac must equal the fixed host bridge MAC "
            f"{gateway_mac}"
        )
    if policy.allow_arp is not False:
        raise hostcheck.Refusal(
            "policy allow_arp must be false: both neighbours are static"
        )
    if len(policy.allowed) != 1:
        raise hostcheck.Refusal(
            "the single-peer lab policy must allow exactly one destination flow"
        )
    flow = policy.allowed[0]
    if flow.proto != "udp":
        raise hostcheck.Refusal("the only allowed flow must be UDP/WireGuard")
    if endpoint is not None and (flow.dst_ipv4, flow.dst_port) != endpoint:
        raise hostcheck.Refusal(
            "the allowed flow is not exactly the profile's declared endpoint"
        )
    if policy.positive_control.sink_udp_port != SINK_UDP_PORT:
        raise hostcheck.Refusal("positive-control sink port is not the fixed lab port")


def config_document(name: str, image_id: str) -> dict:
    return {
        "name": name,
        "profile": f"/etc/vprouter/{name}.conf",
        "state_dir": f"/var/lib/vprouter/{name}",
        "image_ref": image_id,
        "compose_dir": "/opt/vprouter/current",
        "tailscale_hostname": name,
    }


# ---------------------------------------------------------------------------
# Guest file installation


def install_guest_file(
    client: QGAClient,
    path: str,
    data: bytes,
    *,
    mode: int,
    timeout: float = 60.0,
) -> None:
    """Install a root-owned file through a 0700 root-only staging dir."""
    stage = "/run/vprlab-stage"
    prepared = client.execute(
        "/bin/sh",
        ["-c", f"install -d -m 0700 -o root -g root {shlex.quote(stage)}"],
        timeout=15.0,
    )
    if prepared.exitcode != 0:
        raise hostcheck.Refusal("cannot create the guest staging directory")
    staged = f"{stage}/{os.path.basename(path)}"
    client.write_file(staged, data, timeout=timeout)
    command = (
        f"chmod {mode:04o} {shlex.quote(staged)} && "
        f"chown root:root {shlex.quote(staged)} && "
        f"mv -f {shlex.quote(staged)} {shlex.quote(path)}"
    )
    installed = client.execute("/bin/sh", ["-c", command], timeout=15.0)
    if installed.exitcode != 0:
        raise hostcheck.Refusal(f"cannot install guest file {path}")


def verify_guest_secret(client: QGAClient, path: str) -> None:
    result = client.execute(
        "/bin/sh", ["-c", f"stat -c '%a %U %G' {shlex.quote(path)}"], timeout=15.0
    )
    if result.exitcode != 0 or result.stdout.strip() != b"600 root root":
        raise hostcheck.Refusal(f"guest secret {path} is not mode 0600 root:root")


def prepare_vm_secrets(
    client: QGAClient,
    name: str,
    profile: SecretMaterial,
    image_id: str,
) -> dict[str, str]:
    """Write the profile and site config into the guest at test time only."""
    profile_path = f"/etc/vprouter/{name}.conf"
    config_path = f"/etc/vprouter/{name}.json"
    state_dir = f"/var/lib/vprouter/{name}"
    setup = client.execute(
        "/bin/sh",
        [
            "-c",
            "install -d -m 0755 -o root -g root /etc/vprouter && "
            "install -d -m 0755 -o root -g root /var/lib/vprouter && "
            "chown root:root /etc/vprouter /var/lib/vprouter && "
            "chmod 0755 /etc/vprouter /var/lib/vprouter && "
            f"install -d -m 0700 -o root -g root {shlex.quote(state_dir)} && "
            f"chmod 0700 {shlex.quote(state_dir)}",
        ],
        timeout=30.0,
    )
    if setup.exitcode != 0:
        raise hostcheck.Refusal("cannot create guest config/state directories")
    install_guest_file(client, profile_path, profile.data, mode=0o600)
    verify_guest_secret(client, profile_path)
    config = (
        json.dumps(config_document(name, image_id), sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    install_guest_file(client, config_path, config, mode=0o600)
    verify_guest_secret(client, config_path)
    return {
        "profile_path": profile_path,
        "config_path": config_path,
        "state_dir": state_dir,
    }


# ---------------------------------------------------------------------------
# Nonces


def load_used_nonces(path: pathlib.Path) -> set[str]:
    path = pathlib.Path(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return set()
    except OSError as exc:
        raise hostcheck.Refusal(f"used-nonces file is unreadable: {exc.__class__.__name__}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise hostcheck.Refusal("used-nonces file must be a regular file")
    if info.st_mode & 0o077:
        raise hostcheck.Refusal("used-nonces file must be mode 0600")
    try:
        return control_mod.load_used_nonces(path)
    except policy_mod.PolicyError as exc:
        raise hostcheck.Refusal(f"used-nonces file is invalid: {exc}") from exc


def fresh_pair(
    used: set[str], *, generator=None
) -> dict[str, str]:
    """Generate a distinct before/after pair and refuse any reuse."""
    if generator is None:
        generator = control_mod.generate_pair
    try:
        pair = generator(set(used))
    except policy_mod.PolicyError as exc:
        raise hostcheck.Refusal(f"nonce generation failed: {exc}") from exc
    if not isinstance(pair, dict):
        raise hostcheck.Refusal("nonce generator returned a non-object")
    before = pair.get("before")
    after = pair.get("after")
    for label, nonce in (("before", before), ("after", after)):
        if not policy_mod.is_control_nonce(nonce):
            raise hostcheck.Refusal(f"{label} nonce is not 32 lowercase hex characters")
    if before == after:
        raise hostcheck.Refusal("before and after nonces must differ")
    if before in used or after in used:
        raise hostcheck.Refusal("nonce generator reused a recorded nonce")
    return {"before": before, "after": after}


def append_used_nonces(path: pathlib.Path, nonces: dict[str, str]) -> None:
    path = pathlib.Path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, USED_NONCES_MODE)
    except OSError as exc:
        raise hostcheck.Refusal(f"used-nonces file is not writable: {exc.__class__.__name__}") from exc
    try:
        os.fchmod(descriptor, USED_NONCES_MODE)
        payload = "".join(f"{nonces[role]}\n" for role in ("before", "after"))
        os.write(descriptor, payload.encode("ascii"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


# ---------------------------------------------------------------------------
# Capture


@dataclasses.dataclass
class Capture:
    process: subprocess.Popen
    argv: list[str]
    pcap: pathlib.Path
    stats: pathlib.Path


def start_capture(
    interface: str,
    pcap: pathlib.Path,
    stats: pathlib.Path,
    *,
    tcpdump: str,
    popen=subprocess.Popen,
    timeout: float = 15.0,
) -> Capture:
    argv = guest.tcpdump_argv(interface, pcap)
    with stats.open("xb") as error_log:
        process = popen(
            argv,
            executable=tcpdump,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=error_log,
            start_new_session=True,
        )
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = process.poll()
        if status is not None:
            raise hostcheck.Refusal(f"tcpdump exited before listening (status {status})")
        if pcap.is_file() and pcap.stat().st_size >= 24:
            os.chmod(stats, 0o600)
            os.chmod(pcap, 0o600)
            return Capture(process=process, argv=argv, pcap=pcap, stats=stats)
        time.sleep(0.05)
    stop_capture(Capture(process=process, argv=argv, pcap=pcap, stats=stats), timeout=5)
    raise hostcheck.Refusal("tcpdump did not start listening in time")


def stop_capture(capture: Capture | None, *, timeout: float = 20.0) -> int | None:
    if capture is None:
        return None
    process = capture.process
    if process.poll() is None:
        try:
            process.send_signal(signal.SIGINT)
        except OSError:
            pass
    try:
        status = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except OSError:
            process.kill()
        status = process.wait(timeout=10)
    for path in (capture.pcap, capture.stats):
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    return status


def file_contains_payload(path: pathlib.Path, needle: bytes) -> bool:
    """Return True when ``needle`` is present in the growing capture file."""
    carry = b""
    try:
        with pathlib.Path(path).open("rb") as stream:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    return False
                window = carry + chunk
                if needle in window:
                    return True
                carry = window[-max(0, len(needle) - 1) :]
    except OSError:
        return False


def wait_for_control_in_pcap(
    path: pathlib.Path,
    nonce: str,
    *,
    timeout: float | None = None,
) -> bool:
    """Wait until tcpdump's ``-U --immediate-mode`` file contains the AFTER."""
    if timeout is None:
        timeout = AFTER_CAPTURE_TIMEOUT
    needle = policy_mod.CONTROL_PREFIX + nonce.encode("ascii")
    deadline = time.monotonic() + timeout
    while True:
        if file_contains_payload(path, needle):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.1)


# ---------------------------------------------------------------------------
# Phase record


def base_phase_record(
    *,
    phase: str,
    name: str,
    state: pathlib.Path,
    evidence_dir: pathlib.Path,
    image_id: str,
) -> dict:
    return {
        "schema": "vprlab-vm-phase-v1",
        "phase": phase,
        "name": name,
        "mode": "test",
        "state": str(state),
        "evidence_dir": str(evidence_dir),
        "image_ref": image_id,
        "expect_tunnel": PHASE_EXPECTATIONS[phase],
        "qemu_argv": [],
        "launch_argv": [],
        "tcpdump_argv": [],
        "pcapscan_argv": [],
        "nonces": {
            "before": None,
            "after": None,
            "used_nonces_file": None,
            "reserved": False,
        },
        "boot": {
            "qga_socket": str(pathlib.Path(state) / guest.QGA_SOCKET),
            "rebooted": False,
            "boot_control": None,
        },
        "guest": {
            "profile_path": f"/etc/vprouter/{name}.conf",
            "config_path": f"/etc/vprouter/{name}.json",
            "state_dir": f"/var/lib/vprouter/{name}",
        },
        "silence": [],
        "setup": {"command": None, "exitcode": None, "active": None},
        "action": {"command": None, "exitcode": None},
        "postcondition": {"command": None, "exitcode": None},
        "tailscale": {"backend_state": None},
        "controls": {
            "before_exitcode": None,
            "after_exitcode": None,
            "before_transport": None,
            "after_transport": None,
        },
        "cleanup": {"services": None},
        "timestamps": {},
        "durations": {},
        "hashes": {},
        "scan": {
            "exitcode": None,
            "verdict": None,
            "path": str(pathlib.Path(evidence_dir) / guest.SCAN_REPORT_FILE),
        },
        "errors": [],
        "result": "ERROR",
        "result_reason": None,
        "error_class": None,
    }


def write_private_json(path: pathlib.Path, document: dict) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(document, stream, indent=2, sort_keys=True)
        stream.write("\n")


def write_private_text(path: pathlib.Path, text: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(text)


def ensure_root_directory(path: pathlib.Path) -> None:
    """Create/validate a root-only 0700 directory without following links."""
    path = pathlib.Path(path)
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as exc:
        raise hostcheck.Refusal(
            f"cannot create evidence directory: {exc.__class__.__name__}"
        ) from exc
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise hostcheck.Refusal("evidence path must be a real directory") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode):
            raise hostcheck.Refusal("evidence path must be a real directory")
        if os.geteuid() == 0 and info.st_uid != 0:
            raise hostcheck.Refusal("evidence directory must be owned by root")
        os.fchmod(descriptor, 0o700)
    finally:
        os.close(descriptor)


# ---------------------------------------------------------------------------
# Guest actions


def action_command(phase: str, name: str) -> str:
    guest.validate_name(name)
    if phase == "start-router":
        return f"systemctl start vprouter@{name}.service"
    if phase in {"idle", "login"}:
        return "true"
    if phase == "stop-router":
        return f"systemctl stop vprouter@{name}.service"
    if phase == "kill-wireguard":
        return (
            f"pid=$(docker inspect --format '{{{{.State.Pid}}}}' {name}) || exit 1; "
            '[ "$pid" -gt 1 ] || exit 1; '
            'exec nsenter -t "$pid" -n ip link del wg0'
        )
    if phase == "kill-container":
        return f"docker kill {name}"
    if phase == "restart-docker":
        return "systemctl restart docker.service"
    raise hostcheck.Refusal(f"unsupported phase action {phase}")


def postcondition_command(phase: str, name: str) -> str | None:
    """Return the in-guest proof that a fault phase actually took effect."""
    guest.validate_name(name)
    if phase == "stop-router":
        return (
            f"systemctl is-active --quiet vprouter@{name}.service "
            "&& exit 1; exit 0"
        )
    if phase == "kill-wireguard":
        return (
            f"pid=$(docker inspect --format '{{{{.State.Pid}}}}' {name}) || exit 1; "
            '[ "$pid" -gt 1 ] || exit 1; '
            'nsenter -t "$pid" -n sh -c \'! ip link show wg0 >/dev/null 2>&1\''
        )
    if phase == "kill-container":
        return (
            f"if docker inspect --format '{{{{.State.Running}}}}' {name} "
            "2>/dev/null | grep -qx true; then exit 1; fi; exit 0"
        )
    return None


def run_silence_check(
    client: QGAClient,
    *,
    name: str,
    image_id: str,
    expect_router_disabled: bool,
) -> ExecResult:
    script = guest.silence_check_script(
        name=name,
        image_id=image_id,
        expect_router_disabled=expect_router_disabled,
    )
    result = client.execute("/bin/sh", ["-c", script], timeout=SILENCE_TIMEOUT)
    if result.exitcode != 0 or b"SILENCE-OK" not in result.stdout:
        raise hostcheck.Refusal("guest silence check failed")
    return result


def verify_guest_image(
    client: QGAClient, image_id: str, *, timeout: float = 180.0
) -> None:
    """Require the guest's Docker store to contain the exact pinned image ID."""
    guest.validate_image_id(image_id)
    deadline = time.monotonic() + timeout
    command = f"docker image inspect --format '{{{{.Id}}}}' {image_id}"
    while time.monotonic() < deadline:
        result = client.execute("/bin/sh", ["-c", command], timeout=30.0)
        if result.exitcode == 0 and result.stdout.decode(
            "ascii", "replace"
        ).strip() == image_id:
            return
        time.sleep(1.0)
    raise hostcheck.Refusal("the guest does not hold the expected Docker image ID")


def emit_control(
    client: QGAClient,
    nonce: str,
    policy: policy_mod.Policy,
    device: str,
) -> int | None:
    command = control_mod.build_command(
        nonce,
        device,
        policy.vm_wan_ipv4,
        policy.positive_control.sink_ipv4,
        policy.positive_control.sink_udp_port,
    )
    result = client.execute("/bin/sh", ["-c", command], timeout=30.0)
    if result.exitcode != 0:
        raise hostcheck.Refusal("positive control did not exit zero")
    return result.exitcode


def resolve_wan_device(client: QGAClient, mac: str = guest.VM_MAC) -> str:
    """Find the test NIC by MAC; the control must bind to the real name."""
    script = (
        "for directory in /sys/class/net/*; do "
        '[ -e "$directory/address" ] || continue; '
        f'if [ "$(cat "$directory/address")" = "{guest.validate_mac(mac)}" ]; then '
        'printf "%s\\n" "${directory##*/}"; fi; done'
    )
    result = client.execute("/bin/sh", ["-c", script], timeout=15.0)
    device = result.stdout.decode("ascii", "replace").strip()
    if result.exitcode != 0 or not re.fullmatch(r"[A-Za-z0-9_.:@-]{1,15}", device):
        raise hostcheck.Refusal("cannot resolve the WAN interface by MAC")
    return device


def stage_boot_control(
    client: QGAClient,
    nonce: str,
    policy: policy_mod.Policy,
    *,
    boot_token: str,
) -> dict[str, str]:
    prepared = client.execute(
        "/bin/sh",
        [
            "-c",
            "install -d -m 0700 -o root -g root "
            + shlex.quote(guest.BOOT_CONTROL_DIR),
        ],
        timeout=30.0,
    )
    if prepared.exitcode != 0:
        raise hostcheck.Refusal("cannot create the persistent boot-control directory")
    spec = guest.boot_control_spec(
        nonce,
        policy.positive_control.sink_ipv4,
        policy.positive_control.sink_udp_port,
        boot_token=boot_token,
    ).encode("ascii")
    install_guest_file(client, guest.BOOT_CONTROL_SPEC, spec, mode=0o600)
    install_guest_file(
        client,
        guest.BOOT_CONTROL_SCRIPT,
        guest.boot_control_script_text().encode("ascii"),
        mode=0o755,
    )
    install_guest_file(
        client,
        guest.BOOT_CONTROL_UNIT_PATH,
        guest.boot_control_unit_text().encode("ascii"),
        mode=0o644,
    )
    enabled = client.execute(
        "/bin/sh",
        [
            "-c",
            f"systemctl daemon-reload && systemctl enable {guest.BOOT_CONTROL_UNIT}",
        ],
        timeout=60.0,
    )
    if enabled.exitcode != 0:
        raise hostcheck.Refusal("cannot enable the boot-control unit")
    return {
        "unit": guest.BOOT_CONTROL_UNIT,
        "unit_path": guest.BOOT_CONTROL_UNIT_PATH,
        "spec_path": guest.BOOT_CONTROL_SPEC,
        "sent_path": guest.BOOT_CONTROL_SENT,
        "boot_token": boot_token,
    }


def wait_boot_control_sent(
    client: QGAClient, boot_token: str, *, timeout: float | None = None
) -> None:
    if timeout is None:
        timeout = 120.0
    deadline = time.monotonic() + timeout
    command = (
        f"test -f {guest.BOOT_CONTROL_SENT} && "
        f"test ! -e {guest.BOOT_CONTROL_SPEC} && "
        f"grep -qx {shlex.quote(boot_token)} {guest.BOOT_CONTROL_SENT}"
    )
    while time.monotonic() < deadline:
        result = client.execute("/bin/sh", ["-c", command], timeout=10.0)
        if result.exitcode == 0:
            return
        time.sleep(0.5)
    raise hostcheck.Refusal("the boot-control unit did not send its nonce")


def wait_router_active(
    client: QGAClient, name: str, *, timeout: float | None = None
) -> None:
    if timeout is None:
        timeout = ROUTER_ACTIVE_TIMEOUT
    deadline = time.monotonic() + timeout
    command = f"systemctl is-active --quiet vprouter@{name}.service"
    while time.monotonic() < deadline:
        result = client.execute("/bin/sh", ["-c", command], timeout=10.0)
        if result.exitcode == 0:
            return
        time.sleep(1.0)
    raise hostcheck.Refusal("the router unit did not become active")


def router_handshake_command(name: str) -> str:
    return (
        f"pid=$(docker inspect --format '{{{{.State.Pid}}}}' {name}) || exit 1; "
        '[ "$pid" -gt 1 ] || exit 1; '
        'exec nsenter -t "$pid" -n wg show wg0 latest-handshakes'
    )


def wait_router_handshake(
    client: QGAClient, name: str, *, timeout: float | None = None
) -> None:
    """Require a real WireGuard handshake inside the router netns."""
    if timeout is None:
        timeout = ROUTER_HANDSHAKE_TIMEOUT
    deadline = time.monotonic() + timeout
    command = router_handshake_command(name)
    while time.monotonic() < deadline:
        result = client.execute("/bin/sh", ["-c", command], timeout=15.0)
        if result.exitcode == 0:
            for line in result.stdout.decode("utf-8", "replace").splitlines():
                fields = line.split()
                if len(fields) >= 2 and fields[1].isdigit() and int(fields[1]) > 0:
                    return
        time.sleep(1.0)
    raise hostcheck.Refusal("no WireGuard handshake was observed in the router netns")


def wait_router_ready(client: QGAClient, name: str) -> None:
    wait_router_active(client, name)
    wait_router_handshake(client, name)


def read_boot_id(client: QGAClient) -> str:
    result = client.execute(
        "/bin/sh",
        ["-c", "cat /proc/sys/kernel/random/boot_id"],
        timeout=15.0,
    )
    if result.exitcode != 0:
        raise hostcheck.Refusal("cannot read the guest boot ID")
    value = result.stdout.decode("ascii", "replace").strip()
    if not re.fullmatch(r"[0-9a-f-]{36}", value):
        raise hostcheck.Refusal("guest boot ID has an unexpected shape")
    return value


def read_docker_pid(client: QGAClient) -> str:
    result = client.execute(
        "/bin/sh", ["-c", "cat /var/run/docker.pid"], timeout=15.0
    )
    value = result.stdout.decode("ascii", "replace").strip()
    if result.exitcode != 0 or not value.isdigit():
        raise hostcheck.Refusal("cannot read the Docker daemon PID")
    return value


def wait_docker_restarted(
    client: QGAClient, previous_pid: str, *, timeout: float | None = None
) -> str:
    if timeout is None:
        timeout = DOCKER_RESTART_TIMEOUT
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            current = read_docker_pid(client)
        except hostcheck.Refusal:
            current = None
        if current is not None and current != previous_pid:
            probe = client.execute("/bin/sh", ["-c", "docker info"], timeout=15.0)
            if probe.exitcode == 0:
                return current
        time.sleep(1.0)
    raise hostcheck.Refusal("the Docker daemon did not restart with a new PID")


def read_tailscale_backend_state(client: QGAClient, name: str) -> str | None:
    result = client.execute(
        "/bin/sh",
        ["-c", f"docker exec {name} tailscale status --json 2>/dev/null || true"],
        timeout=20.0,
    )
    try:
        document = json.loads(result.stdout.decode("utf-8", "replace"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(document, dict):
        return None
    state = document.get("BackendState")
    if not isinstance(state, str):
        return None
    return "".join(ch for ch in state if ch.isprintable())[:64]


def record_tailscale_state(record: dict, client: QGAClient, name: str) -> None:
    try:
        record["tailscale"]["backend_state"] = read_tailscale_backend_state(client, name)
    except (QGAError, OSError):
        record["tailscale"]["backend_state"] = None


def find_login_url(client: QGAClient, name: str) -> str | None:
    return login_url_mod.find_login_url(client, name)


def login_phase_wait(
    client: QGAClient,
    *,
    name: str,
    duration: float,
    evidence_dir: pathlib.Path,
    record: dict,
) -> None:
    """Poll the login URL through the runner's own QGA connection."""
    url_path = evidence_dir / "login-url.txt"
    deadline = time.monotonic() + duration
    found: str | None = None
    while True:
        try:
            url = find_login_url(client, name)
        except (QGAError, OSError):
            url = None
        if url is not None and found is None:
            found = url
            write_private_text(url_path, url + "\n")
            record["login_url"] = str(url_path)
            print(f"run_phase: login URL {url}", file=sys.stderr)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(2.0, remaining))


def wait_for_reboot(
    socket_path: pathlib.Path,
    previous_boot_id: str,
    *,
    timeout: float | None = None,
) -> QGAClient:
    """Reconnect QGA only after the guest reports a different boot ID.

    A guest agent accepts connections again while the old boot is still
    shutting down, so a successful socket connect alone does not prove the
    reboot happened.
    """
    if timeout is None:
        timeout = QGA_BOOT_TIMEOUT
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            client = wait_for_qga(
                socket_path,
                timeout=min(15.0, max(1.0, deadline - time.monotonic())),
            )
        except QGAError:
            if time.monotonic() >= deadline:
                break
            time.sleep(0.5)
            continue
        try:
            if read_boot_id(client) != previous_boot_id:
                return client
        except (QGAError, hostcheck.Refusal):
            pass
        client.close()
        time.sleep(0.5)
    raise hostcheck.Refusal("guest did not reboot within the timeout")


def cleanup_guest_units(client: QGAClient, name: str) -> None:
    """Stop/disable the router and reboot units; report a real failure."""
    command = (
        "rc=0; "
        f"systemctl stop 'vprouter@{name}.service' >/dev/null 2>&1 || rc=1; "
        f"systemctl disable 'vprouter@{name}.service' >/dev/null 2>&1 || true; "
        f"if [ -f {guest.BOOT_CONTROL_UNIT_PATH} ]; then "
        f"systemctl disable --now {guest.BOOT_CONTROL_UNIT} >/dev/null 2>&1 || rc=1; "
        "fi; "
        f"rm -f {guest.BOOT_CONTROL_UNIT_PATH} {guest.BOOT_CONTROL_SPEC} "
        f"{guest.BOOT_CONTROL_SENT}; "
        "systemctl daemon-reload >/dev/null 2>&1 || rc=1; exit $rc"
    )
    result = client.execute("/bin/sh", ["-c", command], timeout=180.0)
    if result.exitcode != 0:
        raise hostcheck.Refusal("cannot stop/disable the guest router units")


# ---------------------------------------------------------------------------
# Host / state preflight


def _run_json(argv: list[str], *, what: str) -> object:
    try:
        completed = subprocess.run(
            argv, check=False, capture_output=True, text=True, timeout=20
        )
    except OSError as exc:
        raise hostcheck.Refusal(f"cannot run {what}: {exc.__class__.__name__}") from exc
    except subprocess.SubprocessError as exc:
        raise hostcheck.Refusal(f"{what} failed: {exc.__class__.__name__}") from exc
    if completed.returncode != 0:
        raise hostcheck.Refusal(f"{what} failed with status {completed.returncode}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise hostcheck.Refusal(f"{what} did not return JSON") from exc


def verify_host_lab(
    *, tap: str, bridge: str, owner_file: str | pathlib.Path = hostcheck.OWNER_FILE
) -> None:
    token = hostcheck.load_owner_token(owner_file)
    try:
        forwarding = pathlib.Path("/proc/sys/net/ipv4/ip_forward").read_text(
            encoding="ascii"
        ).strip()
    except OSError as exc:
        raise hostcheck.Refusal("cannot read net.ipv4.ip_forward") from exc
    if forwarding != "1":
        raise hostcheck.Refusal(
            "net.ipv4.ip_forward is not 1; the host plan requires it for the phase"
        )
    links = _run_json(["ip", "-d", "-j", "link", "show"], what="ip -d -j link show")
    addresses = _run_json(["ip", "-j", "addr", "show"], what="ip -j addr show")
    # ``nft -j list table`` exits non-zero when the table is absent; that is a
    # refusal, not a crash.
    try:
        table = subprocess.run(
            ["nft", "-j", "list", "table", "inet", "vprlab"],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
    except OSError as exc:
        raise hostcheck.Refusal(f"cannot run nft: {exc.__class__.__name__}") from exc
    if table.returncode != 0:
        raise hostcheck.Refusal("nft table inet vprlab is missing")
    try:
        table_document = json.loads(table.stdout)
    except json.JSONDecodeError as exc:
        raise hostcheck.Refusal("nft -j list table did not return JSON") from exc
    neighbors = _run_json(["ip", "-j", "neigh", "show"], what="ip -j neigh show")
    problems = hostcheck.verify_host_network(
        links,
        table_document,
        neighbors,
        addresses_document=addresses,
        bridge=bridge,
        tap=tap,
        owner_token=token,
    )
    if problems:
        raise hostcheck.Refusal("; ".join(problems))


def verify_state(
    state: pathlib.Path, *, qemu_uid: int, base: pathlib.Path, qemu_gid: int | None = None
) -> None:
    try:
        info = state.lstat()
    except OSError as exc:
        raise hostcheck.Refusal("state directory is missing") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise hostcheck.Refusal("state path must be a real directory")
    if stat.S_IMODE(info.st_mode) != 0o700:
        raise hostcheck.Refusal("state directory must be mode 0700")
    if info.st_uid != qemu_uid:
        raise hostcheck.Refusal("state directory must be owned by the QEMU user")
    overlay = state / guest.OVERLAY_FILE
    try:
        overlay_info = overlay.lstat()
    except OSError as exc:
        raise hostcheck.Refusal("state overlay is missing") from exc
    if not stat.S_ISREG(overlay_info.st_mode):
        raise hostcheck.Refusal("state overlay must be a regular file")
    if overlay_info.st_uid != qemu_uid:
        raise hostcheck.Refusal("state overlay must be owned by the QEMU user")
    if overlay_info.st_mode & 0o077:
        raise hostcheck.Refusal("state overlay must be mode 0600")

    # The overlay is written by QEMU running as the unprivileged user, so its
    # parser must run as that same user (never as root).
    if qemu_gid is None:
        qemu_gid = qemu_gid_for(qemu_uid)
    argv = guest.build_setpriv_argv(
        guest.build_qemu_img_info_argv(overlay), qemu_uid, qemu_gid
    )
    try:
        completed = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
            env=guest.qemu_env({}),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise hostcheck.Refusal("qemu-img could not inspect the overlay") from exc
    if completed.returncode != 0:
        raise hostcheck.Refusal("qemu-img could not inspect the overlay")
    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise hostcheck.Refusal("qemu-img returned non-JSON output") from exc
    guest.verify_overlay_chain(document, overlay, base)


def qemu_gid_for(uid: int) -> int:
    try:
        import pwd

        return pwd.getpwuid(uid).pw_gid
    except KeyError as exc:
        raise hostcheck.Refusal("QEMU user has no passwd entry") from exc


# ---------------------------------------------------------------------------
# VM lifecycle


def start_vm(
    state: pathlib.Path,
    *,
    name: str,
    tap: str,
    qemu_user: str,
    uid: int,
    gid: int,
    log_path: pathlib.Path,
) -> tuple[subprocess.Popen, list[str], list[str]]:
    for stale in (guest.PID_FILE, guest.QGA_SOCKET):
        try:
            (state / stale).unlink()
        except OSError:
            pass
    qemu_argv = guest.build_qemu_argv("test", state, name=name, tap=tap)
    launch_argv = guest.build_launch_argv(qemu_argv, qemu_user, uid=uid, gid=gid)
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(log_path, flags, 0o600)
    with os.fdopen(descriptor, "ab") as log:
        process = subprocess.Popen(
            launch_argv,
            env=guest.qemu_env({}),
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    return process, qemu_argv, launch_argv


def wait_for_qga_or_exit(
    socket_path: pathlib.Path,
    process: subprocess.Popen,
    *,
    timeout: float = QGA_BOOT_TIMEOUT,
) -> QGAClient:
    deadline = time.monotonic() + timeout
    while True:
        if process.poll() is not None:
            raise hostcheck.Refusal(
                f"QEMU exited before the guest agent (status {process.returncode})"
            )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise hostcheck.Refusal("guest agent did not become ready")
        try:
            return wait_for_qga(socket_path, timeout=min(5.0, remaining))
        except QGAError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.25)


def poweroff_vm(
    client: QGAClient | None, process: subprocess.Popen | None
) -> tuple[int | None, bool]:
    """Power the guest off and wait for QEMU; return ``(status, forced)``."""
    if client is not None:
        try:
            client.shutdown("powerdown", timeout=5.0)
        except (QGAError, OSError):
            pass
        finally:
            try:
                client.close()
            except OSError:
                pass
    if process is None:
        return None, False
    try:
        return process.wait(timeout=POWEROFF_TIMEOUT), False
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except OSError:
            process.kill()
        return process.wait(timeout=10), True


# ---------------------------------------------------------------------------
# Signal handling


class PhaseInterrupted(RuntimeError):
    """A termination signal arrived; unwind through the ordered cleanup."""


_signal_seen = False


def _handle_signal(signum: int, _frame) -> None:
    global _signal_seen
    if _signal_seen:
        return
    _signal_seen = True
    raise PhaseInterrupted(f"received signal {signum}")


def install_signal_handlers() -> None:
    global _signal_seen
    _signal_seen = False
    for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(signum, _handle_signal)


# ---------------------------------------------------------------------------
# Main phase


def _evidence_run_dir(root: pathlib.Path, phase: str, name: str) -> pathlib.Path:
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    ensure_root_directory(root)
    run_dir = pathlib.Path(root) / f"{phase}-{stamp}-{name}"
    ensure_root_directory(run_dir)
    return run_dir


def run_phase(arguments: argparse.Namespace) -> int:
    require_root()
    if arguments.phase not in PHASES:
        raise hostcheck.Refusal(f"unknown phase {arguments.phase}")
    name = guest.validate_name(arguments.name)
    if not tsnames.is_test_node(name):
        raise hostcheck.Refusal(
            "name must be a throw-away zz-vprtest-NN-do-not-use label"
        )
    image_id = guest.validate_image_id(arguments.image_id)
    if arguments.duration < 0 or arguments.duration > 86400:
        raise hostcheck.Refusal("duration must be in 0..86400 seconds")
    if arguments.profile_fd is not None and arguments.profile_file is not None:
        raise hostcheck.Refusal("use exactly one of --profile-fd and --profile-file")
    if arguments.profile_fd is None and arguments.profile_file is None:
        raise hostcheck.Refusal("a WireGuard profile is required")
    if arguments.tap != guest.TAP or arguments.bridge != guest.BRIDGE:
        # pcapscan's argv and stats banner are bound to the fixed lab tap.
        raise hostcheck.Refusal(
            f"the leak lab uses the fixed tap {guest.TAP} and bridge {guest.BRIDGE}"
        )

    state = (
        pathlib.Path(arguments.state)
        if arguments.state is not None
        else guest.state_path(arguments.index, pathlib.Path(arguments.state_root))
    )
    base = pathlib.Path(arguments.base_image)
    used_path = pathlib.Path(arguments.used_nonces)

    lock_fd = runlock.acquire(arguments.run_lock)
    try:
        return _run_phase_locked(
            arguments,
            name=name,
            image_id=image_id,
            state=state,
            base=base,
            used_path=used_path,
        )
    finally:
        runlock.release(lock_fd)


def _run_phase_locked(
    arguments: argparse.Namespace,
    *,
    name: str,
    image_id: str,
    state: pathlib.Path,
    base: pathlib.Path,
    used_path: pathlib.Path,
) -> int:
    # The single-guest check happens while the global lock is held.
    hostcheck.refuse_if_qemu_running(self_pid=os.getpid())
    try:
        uid, gid = guest.resolve_unprivileged_user(arguments.qemu_user)
    except guest.GeneratorError as exc:
        raise hostcheck.Refusal(str(exc)) from exc
    base_digest = guest.verify_base_image(base, pathlib.Path(arguments.checksum_manifest))

    if arguments.profile_fd is not None:
        profile = read_profile_fd(arguments.profile_fd)
    else:
        profile = read_profile_path(
            pathlib.Path(arguments.profile_file),
            owner_uid=0 if os.geteuid() == 0 else os.geteuid(),
        )
    endpoint = profile_endpoint(profile)
    lab_policy = build_lab_policy(endpoint)

    verify_state(state, qemu_uid=uid, qemu_gid=gid, base=base)
    verify_host_lab(
        tap=arguments.tap, bridge=arguments.bridge, owner_file=arguments.owner_file
    )

    used = load_used_nonces(used_path)
    pair = fresh_pair(used)
    append_used_nonces(used_path, pair)

    tcpdump = shutil.which(arguments.tcpdump)
    if tcpdump is None:
        raise hostcheck.Refusal("tcpdump is not installed")

    evidence_root = pathlib.Path(arguments.evidence_root)
    try:
        state_real = state.resolve()
        evidence_real = evidence_root.resolve()
    except OSError as exc:
        raise hostcheck.Refusal("cannot resolve the evidence path") from exc
    if evidence_real == state_real or state_real in evidence_real.parents:
        raise hostcheck.Refusal(
            "evidence must live outside the opsec-owned VM state directory"
        )
    evidence_dir = _evidence_run_dir(evidence_root, arguments.phase, name)
    pcap = evidence_dir / guest.CAPTURE_FILE
    stats = evidence_dir / guest.CAPTURE_STATS_FILE
    scan_path = evidence_dir / guest.SCAN_REPORT_FILE
    qemu_log = evidence_dir / guest.QEMU_LOG_FILE
    policy_path = evidence_dir / "policy.json"
    write_private_json(policy_path, lab_policy.to_dict())

    record = base_phase_record(
        phase=arguments.phase,
        name=name,
        state=state,
        evidence_dir=evidence_dir,
        image_id=image_id,
    )
    record["nonces"]["before"] = pair["before"]
    record["nonces"]["after"] = pair["after"]
    record["nonces"]["used_nonces_file"] = str(used_path)
    record["nonces"]["reserved"] = True
    record["policy"] = {
        "path": str(policy_path),
        "sha256": sha256_file(policy_path),
        "allowed": [flow.to_dict() for flow in lab_policy.allowed],
        "positive_control": lab_policy.positive_control.to_dict(),
        "allow_arp": lab_policy.allow_arp,
        "gateway_mac": lab_policy.gateway_mac,
    }
    record["base_image"] = str(base)
    record["base_image_sha512"] = base_digest
    record["qemu_log"] = str(qemu_log)
    boot_control_phase = arguments.phase == "reboot-with-router-enabled"

    capture: Capture | None = None
    qemu_process: subprocess.Popen | None = None
    client: QGAClient | None = None
    errors: list[str] = []
    after_control_sent = False
    started = time.monotonic()
    record["timestamps"]["started_at"] = utc_now()

    def note(reason: str) -> None:
        if reason not in errors:
            errors.append(reason)

    try:
        capture = start_capture(arguments.tap, pcap, stats, tcpdump=tcpdump)
        record["tcpdump_argv"] = capture.argv
        record["timestamps"]["capture_started"] = utc_now()
        write_private_json(evidence_dir / guest.CAPTURE_ARGV_FILE, capture.argv)

        qemu_process, qemu_argv, launch_argv = start_vm(
            state,
            name=name,
            tap=arguments.tap,
            qemu_user=arguments.qemu_user,
            uid=uid,
            gid=gid,
            log_path=qemu_log,
        )
        record["qemu_argv"] = qemu_argv
        record["launch_argv"] = launch_argv
        record["timestamps"]["qemu_started"] = utc_now()
        time.sleep(0.5)
        if qemu_process.poll() is not None:
            raise hostcheck.Refusal(
                f"QEMU exited immediately with status {qemu_process.returncode}"
            )

        client = wait_for_qga_or_exit(state / guest.QGA_SOCKET, qemu_process)
        record["timestamps"]["qga_ready"] = utc_now()
        # A crashed earlier phase may have left a staged boot-control unit or
        # an enabled router.  Clear both before the silence check can see them.
        try:
            cleanup_guest_units(client, name)
        except hostcheck.Refusal:
            note("cleanup_failed")
            raise
        initial_silence = run_silence_check(
            client, name=name, image_id=image_id, expect_router_disabled=True
        )
        record["silence"].append(
            {"when": "initial", "exitcode": initial_silence.exitcode, "ok": True}
        )
        record["timestamps"]["silence_checked"] = utc_now()
        verify_guest_image(client, image_id)
        record["guest"]["image_verified"] = True

        wan_device = resolve_wan_device(client)
        record["guest"]["wan_device"] = wan_device
        secrets_paths = prepare_vm_secrets(client, name, profile, image_id)
        record["guest"].update(secrets_paths)

        if boot_control_phase:
            enabled = client.execute(
                "/bin/sh",
                ["-c", f"systemctl enable vprouter@{name}.service"],
                timeout=30.0,
            )
            if enabled.exitcode != 0:
                raise hostcheck.Refusal("cannot enable the router for the reboot phase")
            boot_token = secrets.token_hex(16)
            record["boot"]["boot_control"] = stage_boot_control(
                client, pair["before"], lab_policy, boot_token=boot_token
            )
            record["controls"]["before_transport"] = "boot-control-unit"
            record["timestamps"]["boot_control_staged"] = utc_now()
            record["boot"]["rebooted"] = True
            previous_boot_id = read_boot_id(client)
            record["boot"]["previous_boot_id"] = previous_boot_id
            client.shutdown("reboot", timeout=5.0)
            client.close()
            client = wait_for_reboot(
                state / guest.QGA_SOCKET, previous_boot_id
            )
            record["boot"]["new_boot_id"] = read_boot_id(client)
            record["boot"]["boot_id_changed"] = (
                record["boot"]["new_boot_id"] != previous_boot_id
            )
            record["postcondition"] = {
                "command": "boot_id changed",
                "exitcode": 0 if record["boot"]["boot_id_changed"] else 1,
                "previous_boot_id": previous_boot_id,
                "new_boot_id": record["boot"]["new_boot_id"],
            }
            record["timestamps"]["reboot_qga_ready"] = utc_now()
            wait_boot_control_sent(client, boot_token)
            record["timestamps"]["before_control"] = utc_now()
            second_silence = run_silence_check(
                client,
                name=name,
                image_id=image_id,
                expect_router_disabled=False,
            )
            record["silence"].append(
                {"when": "after-reboot", "exitcode": second_silence.exitcode, "ok": True}
            )
            boot_setup_ok = True
            try:
                wait_router_ready(client, name)
                record["setup"]["active"] = True
            except hostcheck.Refusal:
                record["setup"]["active"] = False
                note("router_not_ready")
                boot_setup_ok = False
            record["timestamps"]["router_active"] = utc_now()
            record_tailscale_state(record, client, name)
            record["controls"]["before_exitcode"] = 0
        else:
            record["controls"]["before_exitcode"] = emit_control(
                client, pair["before"], lab_policy, wan_device
            )
            record["controls"]["before_transport"] = "qga"
            record["timestamps"]["before_control"] = utc_now()

        setup_ok = boot_setup_ok if boot_control_phase else True
        if not boot_control_phase and arguments.phase in SETUP_PHASES:
            setup_command = f"systemctl start vprouter@{name}.service"
            record["setup"]["command"] = setup_command
            record["timestamps"]["setup_started"] = utc_now()
            setup = client.execute(
                "/bin/sh", ["-c", setup_command], timeout=ACTION_TIMEOUT
            )
            record["setup"]["exitcode"] = setup.exitcode
            record["timestamps"]["setup_finished"] = utc_now()
            if setup.exitcode != 0:
                record["setup"]["active"] = False
                note("setup_failed")
                setup_ok = False
            else:
                try:
                    wait_router_ready(client, name)
                    record["setup"]["active"] = True
                except hostcheck.Refusal:
                    record["setup"]["active"] = False
                    note("router_not_ready")
                    setup_ok = False
                else:
                    record_tailscale_state(record, client, name)

        action_ok = setup_ok
        if setup_ok:
            if boot_control_phase:
                # The action of this phase *was* the reboot; its BEFORE
                # control came from the one-shot boot unit.
                pass
            elif arguments.phase in {"idle", "login"}:
                record["action"]["command"] = "true"
                record["action"]["exitcode"] = 0
            else:
                command = action_command(arguments.phase, name)
                record["action"]["command"] = command
                docker_pid_before = None
                if arguments.phase == "restart-docker":
                    try:
                        docker_pid_before = read_docker_pid(client)
                    except hostcheck.Refusal:
                        note("postcondition_failed")
                        action_ok = False
                if action_ok:
                    record["timestamps"]["action_started"] = utc_now()
                    action = client.execute(
                        "/bin/sh", ["-c", command], timeout=ACTION_TIMEOUT
                    )
                    record["action"]["exitcode"] = action.exitcode
                    record["timestamps"]["action_finished"] = utc_now()
                    if action.exitcode != 0:
                        note("action_failed")
                        action_ok = False
                if action_ok:
                    if arguments.phase == "start-router":
                        try:
                            wait_router_ready(client, name)
                        except hostcheck.Refusal:
                            note("router_not_ready")
                            action_ok = False
                        else:
                            record_tailscale_state(record, client, name)
                    elif arguments.phase == "restart-docker":
                        try:
                            new_pid = wait_docker_restarted(
                                client, docker_pid_before
                            )
                            record["postcondition"] = {
                                "command": "docker daemon restart",
                                "exitcode": 0,
                                "docker_pid_before": docker_pid_before,
                                "docker_pid_after": new_pid,
                            }
                        except hostcheck.Refusal:
                            note("postcondition_failed")
                            action_ok = False
                    elif arguments.phase in FAULT_PHASES:
                        command = postcondition_command(arguments.phase, name)
                        record["postcondition"]["command"] = command
                        check = client.execute(
                            "/bin/sh", ["-c", command], timeout=ACTION_TIMEOUT
                        )
                        record["postcondition"]["exitcode"] = check.exitcode
                        if check.exitcode != 0:
                            note("postcondition_failed")
                            action_ok = False

        if action_ok:
            if arguments.phase == "login":
                login_phase_wait(
                    client,
                    name=name,
                    duration=arguments.duration,
                    evidence_dir=evidence_dir,
                    record=record,
                )
                record_tailscale_state(record, client, name)
            else:
                time.sleep(arguments.duration)

        record["controls"]["after_exitcode"] = emit_control(
            client, pair["after"], lab_policy, wan_device
        )
        record["controls"]["after_transport"] = "qga"
        record["timestamps"]["after_control"] = utc_now()
        after_control_sent = True
    except BaseException as exc:  # noqa: BLE001 - recorded and re-raised below
        record["error_class"] = exc.__class__.__name__
        note(f"phase_exception:{exc.__class__.__name__}")
    finally:
        record["timestamps"]["finally_entered"] = utc_now()
        # 1. AFTER control was sent above.  Stop/disable the router and the
        #    reboot units while the capture is still alive.
        if client is not None:
            try:
                cleanup_guest_units(client, name)
                record["cleanup"]["services"] = "ok"
            except BaseException as exc:  # noqa: BLE001 - one step must not skip the rest
                record["cleanup"]["services"] = exc.__class__.__name__
                note("cleanup_failed")
        # 2. Guest poweroff.
        record["timestamps"]["vm_poweroff_started"] = utc_now()
        try:
            status, forced = poweroff_vm(client, qemu_process)
        except BaseException as exc:  # noqa: BLE001
            status, forced = None, True
            record["poweroff_error"] = exc.__class__.__name__
        client = None
        record["qemu_exit_status"] = status
        record["timestamps"]["vm_finished_at"] = utc_now()
        if forced:
            note("forced_poweroff")
        elif status not in (0, None):
            note("qemu_exit_status")
        # 3. Verify the AFTER marker reached the pcap before stopping tcpdump.
        if after_control_sent and capture is not None:
            try:
                arrived = wait_for_control_in_pcap(capture.pcap, pair["after"])
            except BaseException:  # noqa: BLE001
                arrived = False
            record["controls"]["after_in_pcap"] = arrived
            record["timestamps"]["after_in_pcap"] = utc_now()
            if not arrived:
                note("after_control_not_captured")
        # 4. Drain/quiet interval, then stop capture.
        try:
            time.sleep(QUIET_SECONDS)
        except BaseException:  # noqa: BLE001
            pass
        if capture is not None:
            try:
                record["tcpdump_exit_status"] = stop_capture(capture)
                record["timestamps"]["capture_stopped"] = utc_now()
            except BaseException as exc:  # noqa: BLE001
                record["tcpdump_exit_status"] = None
                record["capture_stop_error"] = exc.__class__.__name__
                note("capture_stop_failed")
            capture = None
        record["errors"] = list(errors)

    # Scan even after a failed phase: missing controls and truncated windows
    # are pcapscan's INVALID, not a reason to suppress the capture.
    scan_exit = 2
    scan_verdict: str | None = None
    if pcap.is_file():
        scan_argv = [
            sys.executable,
            "-B",
            str(_LEAK_LAB_DIR / "pcapscan.py"),
            "--policy",
            str(policy_path),
            "--pcap",
            str(pcap),
            "--tcpdump-stats",
            str(stats),
            "--capture-argv-file",
            str(evidence_dir / guest.CAPTURE_ARGV_FILE),
            "--expect-tunnel",
            PHASE_EXPECTATIONS[arguments.phase],
            "--control-before",
            pair["before"],
            "--control-after",
            pair["after"],
        ]
        try:
            completed = subprocess.run(
                scan_argv, check=False, capture_output=True, timeout=300
            )
            scan_exit = completed.returncode
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(scan_path, flags, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(completed.stdout)
            scan_stderr = completed.stderr[:4096]
        except (OSError, subprocess.SubprocessError) as exc:
            scan_exit = 2
            scan_stderr = f"pcapscan failed: {exc.__class__.__name__}".encode("ascii")
        record["pcapscan_argv"] = scan_argv
        record["scan"]["exitcode"] = scan_exit
        record["scan"]["stderr"] = scan_stderr.decode("utf-8", "replace")
        if scan_path.is_file():
            try:
                report = json.loads(scan_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                report = None
            if isinstance(report, dict):
                raw = report.get("verdict")
                scan_verdict = raw if isinstance(raw, str) else None
                expected_exit = {"PASS": 0, "LEAK": 1, "INVALID": 2}.get(
                    scan_verdict or ""
                )
                if expected_exit is None or expected_exit != scan_exit:
                    note("scan_report_mismatch")
                if report.get("control_before") not in (None, pair["before"]):
                    note("scan_report_mismatch")
                if report.get("control_after") not in (None, pair["after"]):
                    note("scan_report_mismatch")
            record["scan"]["verdict"] = scan_verdict
            record["hashes"]["scan_sha256"] = sha256_file(scan_path)
        else:
            note("scan_report_missing")
    else:
        note("capture_missing")

    record["hashes"]["policy_sha256"] = record["policy"]["sha256"]
    record["hashes"]["stats_sha256"] = (
        sha256_file(stats) if stats.is_file() else None
    )
    record["hashes"]["pcap_sha256"] = sha256_file(pcap) if pcap.is_file() else None
    record["hashes"]["capture_argv_sha256"] = (
        sha256_file(evidence_dir / guest.CAPTURE_ARGV_FILE)
        if (evidence_dir / guest.CAPTURE_ARGV_FILE).is_file()
        else None
    )
    record["durations"]["phase_seconds"] = round(time.monotonic() - started, 3)
    record["timestamps"]["scan_finished"] = utc_now()

    # The effective phase result is unambiguous.  LEAK keeps precedence; any
    # other phase error turns the run INVALID even when the scanner said PASS.
    if scan_exit == 1:
        final_result = "LEAK"
        final_exit = 1
    elif errors:
        final_result = "INVALID"
        final_exit = 2
    else:
        final_result = "PASS" if scan_exit == 0 else "INVALID"
        final_exit = 0 if scan_exit == 0 else 2
    record["result"] = final_result
    record["result_reason"] = "; ".join(errors) if errors else None
    record["errors"] = list(errors)
    write_private_json(evidence_dir / guest.PHASE_RECORD_FILE, record)

    if record["error_class"] is not None:
        print(
            f"run_phase: phase error {record['error_class']}",
            file=sys.stderr,
        )
    print(
        json.dumps(
            {
                "phase": arguments.phase,
                "result": final_result,
                "verdict": final_result,
                "scan_verdict": scan_verdict,
                "exit": final_exit,
                "expect_tunnel": PHASE_EXPECTATIONS[arguments.phase],
                "evidence": str(evidence_dir),
            },
            sort_keys=True,
        )
    )
    return final_exit


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="run one vprlab leak-lab phase")
    parser.add_argument("--phase", required=True, choices=PHASES)
    parser.add_argument("--duration", type=float, required=True)
    parser.add_argument("--profile-fd", type=int)
    parser.add_argument("--profile-file")
    parser.add_argument("--used-nonces", required=True)
    parser.add_argument("--name", default=guest.DEFAULT_NAME)
    parser.add_argument("--index", type=int, default=guest.DEFAULT_INDEX)
    parser.add_argument("--state")
    parser.add_argument("--state-root", default=str(guest.STATE_ROOT))
    parser.add_argument("--image-id", default=guest.DEPLOYED_IMAGE_ID)
    parser.add_argument("--base-image", default=str(guest.BASE_IMAGE))
    parser.add_argument("--checksum-manifest", default=str(guest.CHECKSUM_MANIFEST))
    parser.add_argument("--qemu-user", default=guest.QEMU_USER)
    parser.add_argument("--tap", default=guest.TAP)
    parser.add_argument("--bridge", default=guest.BRIDGE)
    parser.add_argument("--tcpdump", default="tcpdump")
    parser.add_argument("--evidence-root", default=str(EVIDENCE_ROOT))
    parser.add_argument("--run-lock", default=str(runlock.RUN_LOCK))
    parser.add_argument("--owner-file", default=str(hostcheck.OWNER_FILE))
    arguments = parser.parse_args(argv)
    install_signal_handlers()
    try:
        return run_phase(arguments)
    except (
        hostcheck.Refusal,
        guest.GeneratorError,
        guest.IntegrityError,
        policy_mod.PolicyError,
        runlock.LockError,
    ) as exc:
        print(f"run_phase: {exc}", file=sys.stderr)
        return 2
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001 - never report 1 for a crash
        print(f"run_phase: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
