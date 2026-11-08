#!/usr/bin/env python3
"""Run one external leak-lab phase against the provisioned vprlab VM.

Execute as root on debdev:

    python3 -B tools/leak-lab/vm/run_phase.py \
        --phase start-router --duration 120 \
        --policy policy.json --profile-file /root/vprouter-lab.conf \
        --used-nonces /root/leaklab-used-nonces.txt --index 1

The runner refuses to start unless exactly one guest can run, the host lab
network exists with the fixed gateway MAC and the static neighbour, the state
overlay is backed by the pinned base image, and the supplied policy names this
VM and the profile's declared Mullvad endpoint.

Capture order: tcpdump first, then QEMU (tap only), QGA, silence check, secrets,
BEFORE control, phase action, duration, AFTER control, SIGINT tcpdump, scan.
The exit code is pcapscan's (0 PASS, 1 LEAK, 2 INVALID); any pre-scan failure
also returns 2.

The WireGuard profile is read once and only passed to QGA guest-file-write.
It is never logged, printed, hashed into the record, or copied to the state
directory.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import hashlib
import json
import os
import pathlib
import pwd
import re
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
from qga import ExecResult, QGAClient, QGAError, wait_for_qga  # noqa: E402

PHASES = (
    "start-router",
    "idle",
    "reboot-with-router-enabled",
    "stop-router",
    "kill-wireguard",
    "kill-container",
    "restart-docker",
)

#: Failure phases need a running router before their action.  The runner emits
#: the BEFORE control first, then starts the router inside the measured window,
#: then applies the failure.  All router start-up traffic is therefore inside
#: the control window and must still match the allowed Mullvad endpoint.
SETUP_PHASES = frozenset(
    {"stop-router", "kill-wireguard", "kill-container", "restart-docker"}
)

MAX_PROFILE_BYTES = 65536
SILENCE_TIMEOUT = 180.0
QGA_BOOT_TIMEOUT = 180.0
ACTION_TIMEOUT = 360.0
USED_NONCES_MODE = 0o600


def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with pathlib.Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
    """Extract only ``[Peer] Endpoint``; never return or log key material."""
    try:
        text = material.data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise hostcheck.Refusal("profile is not UTF-8 text") from exc
    section = None
    endpoint = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped[0] in "#;":
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip()
            continue
        if section == "Peer" and "=" in stripped:
            key, value = stripped.split("=", 1)
            if key.strip() == "Endpoint":
                endpoint = value.strip()
    if endpoint is None:
        raise hostcheck.Refusal("profile has no [Peer] Endpoint")
    import ipaddress

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
    """Install a root-owned file atomically through a 0700 root-only staging dir."""
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
        "controls": {
            "before_exitcode": None,
            "after_exitcode": None,
            "before_transport": None,
            "after_transport": None,
        },
        "timestamps": {},
        "durations": {},
        "hashes": {},
        "scan": {
            "exitcode": None,
            "verdict": None,
            "path": str(pathlib.Path(evidence_dir) / guest.SCAN_REPORT_FILE),
        },
        "result": "ERROR",
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


# ---------------------------------------------------------------------------
# Guest actions


def action_command(phase: str, name: str) -> str:
    guest.validate_name(name)
    if phase == "start-router":
        return f"systemctl start vprouter@{name}.service"
    if phase == "idle":
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
    client: QGAClient, nonce: str, policy: policy_mod.Policy
) -> dict[str, str]:
    spec = guest.boot_control_spec(
        nonce,
        policy.positive_control.sink_ipv4,
        policy.positive_control.sink_udp_port,
    ).encode("ascii")
    install_guest_file(client, guest.BOOT_CONTROL_SPEC, spec, mode=0o600)
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
    }


def wait_boot_control_sent(client: QGAClient, *, timeout: float = 120.0) -> None:
    deadline = time.monotonic() + timeout
    command = (
        f"test -f {guest.BOOT_CONTROL_SENT} && "
        f"test ! -e {guest.BOOT_CONTROL_SPEC}"
    )
    while time.monotonic() < deadline:
        result = client.execute("/bin/sh", ["-c", command], timeout=10.0)
        if result.exitcode == 0:
            return
        time.sleep(0.5)
    raise hostcheck.Refusal("the boot-control unit did not send its nonce")


def wait_router_active(client: QGAClient, name: str, *, timeout: float = 300.0) -> None:
    deadline = time.monotonic() + timeout
    command = f"systemctl is-active --quiet vprouter@{name}.service"
    while time.monotonic() < deadline:
        result = client.execute("/bin/sh", ["-c", command], timeout=10.0)
        if result.exitcode == 0:
            return
        time.sleep(1.0)
    raise hostcheck.Refusal("the router unit did not become active after reboot")


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


def wait_for_reboot(
    socket_path: pathlib.Path,
    previous_boot_id: str,
    *,
    timeout: float = QGA_BOOT_TIMEOUT,
) -> QGAClient:
    """Reconnect QGA only after the guest reports a different boot ID.

    A guest agent accepts connections again while the old boot is still
    shutting down, so a successful socket connect alone does not prove the
    reboot happened.
    """
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


def cleanup_reboot_units(client: QGAClient, name: str) -> None:
    command = (
        f"systemctl disable --now {guest.BOOT_CONTROL_UNIT} "
        f"'vprouter@{name}.service' >/dev/null 2>&1 || true; "
        f"rm -f {guest.BOOT_CONTROL_UNIT_PATH} {guest.BOOT_CONTROL_SPEC} "
        f"{guest.BOOT_CONTROL_SENT}; systemctl daemon-reload"
    )
    client.execute("/bin/sh", ["-c", command], timeout=180.0)


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


def verify_host_lab(*, tap: str, bridge: str) -> None:
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
    )
    if problems:
        raise hostcheck.Refusal("; ".join(problems))


def verify_state(state: pathlib.Path, *, qemu_uid: int, base: pathlib.Path) -> None:
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

    environment = guest.qemu_env(dict(os.environ))
    try:
        completed = subprocess.run(
            guest.build_qemu_img_info_argv(overlay),
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise hostcheck.Refusal("qemu-img could not inspect the overlay") from exc
    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise hostcheck.Refusal("qemu-img returned non-JSON output") from exc
    guest.verify_overlay_chain(document, overlay, base)


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
) -> tuple[subprocess.Popen, list[str], list[str]]:
    for stale in (guest.PID_FILE, guest.QMP_SOCKET, guest.QGA_SOCKET):
        try:
            (state / stale).unlink()
        except FileNotFoundError:
            pass
    qemu_argv = guest.build_qemu_argv("test", state, name=name, tap=tap)
    launch_argv = guest.build_launch_argv(qemu_argv, qemu_user, uid=uid, gid=gid)
    with (state / guest.QEMU_LOG_FILE).open("ab") as log:
        process = subprocess.Popen(
            launch_argv,
            env=guest.qemu_env(dict(os.environ)),
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


def poweroff_vm(client: QGAClient | None, process: subprocess.Popen | None) -> int | None:
    if client is not None:
        try:
            client.shutdown("powerdown", timeout=5.0)
        finally:
            client.close()
    if process is None:
        return None
    try:
        return process.wait(timeout=60.0)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except OSError:
            process.kill()
        return process.wait(timeout=10)


# ---------------------------------------------------------------------------
# Main phase


def verify_policy(
    policy: policy_mod.Policy,
    *,
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


def run_phase(arguments: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        raise hostcheck.Refusal("phase execution requires root")
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

    state = (
        pathlib.Path(arguments.state)
        if arguments.state is not None
        else guest.state_path(arguments.index, pathlib.Path(arguments.state_root))
    )
    base = pathlib.Path(arguments.base_image)
    policy_path = pathlib.Path(arguments.policy)
    used_path = pathlib.Path(arguments.used_nonces)

    hostcheck.refuse_if_qemu_running(self_pid=os.getpid())
    base_digest = guest.verify_base_image(base, pathlib.Path(arguments.checksum_manifest))
    try:
        record_policy = policy_mod.load_policy(policy_path)
    except (OSError, policy_mod.PolicyError) as exc:
        raise hostcheck.Refusal(f"policy is invalid: {exc}") from exc
    verify_policy(record_policy)

    if arguments.profile_fd is not None:
        profile = read_profile_fd(arguments.profile_fd)
    else:
        profile = read_profile_path(
            pathlib.Path(arguments.profile_file),
            owner_uid=0 if os.geteuid() == 0 else os.geteuid(),
        )
    endpoint = profile_endpoint(profile)
    if endpoint not in record_policy.outbound_allowed():
        raise hostcheck.Refusal(
            "profile Endpoint is not the declared allowed WireGuard flow"
        )

    try:
        qemu_record = pwd.getpwnam(arguments.qemu_user)
    except KeyError as exc:
        raise hostcheck.Refusal(
            f"unknown unprivileged QEMU user {arguments.qemu_user!r}"
        ) from exc
    uid, gid = qemu_record.pw_uid, qemu_record.pw_gid
    verify_state(state, qemu_uid=uid, base=base)
    verify_host_lab(tap=arguments.tap, bridge=arguments.bridge)

    used = load_used_nonces(used_path)
    pair = fresh_pair(used)
    append_used_nonces(used_path, pair)

    tcpdump = shutil.which(arguments.tcpdump)
    if tcpdump is None:
        raise hostcheck.Refusal("tcpdump is not installed")

    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    evidence_root = state / "evidence"
    if evidence_root.is_symlink():
        raise hostcheck.Refusal("evidence path must not be a symbolic link")
    evidence_root.mkdir(mode=0o700, exist_ok=True)
    os.chmod(evidence_root, 0o700)
    evidence_dir = evidence_root / f"{arguments.phase}-{stamp}"
    evidence_dir.mkdir(mode=0o700)
    os.chmod(evidence_dir, 0o700)
    pcap = evidence_dir / guest.CAPTURE_FILE
    stats = evidence_dir / guest.CAPTURE_STATS_FILE
    scan_path = evidence_dir / guest.SCAN_REPORT_FILE

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
    record["expect_tunnel"] = arguments.expect_tunnel
    record["policy"] = {
        "path": str(policy_path),
        "sha256": sha256_file(policy_path),
        "allowed": [flow.to_dict() for flow in record_policy.allowed],
        "positive_control": record_policy.positive_control.to_dict(),
        "allow_arp": record_policy.allow_arp,
        "gateway_mac": record_policy.gateway_mac,
    }
    record["base_image"] = str(base)
    record["base_image_sha512"] = base_digest
    boot_control_phase = arguments.phase == "reboot-with-router-enabled"

    capture: Capture | None = None
    qemu_process: subprocess.Popen | None = None
    client: QGAClient | None = None
    error: BaseException | None = None
    started = time.monotonic()
    record["timestamps"]["started_at"] = utc_now()

    try:
        capture = start_capture(
            arguments.tap, pcap, stats, tcpdump=tcpdump
        )
        record["tcpdump_argv"] = capture.argv
        record["timestamps"]["capture_started"] = utc_now()
        capture_argv_path = evidence_dir / guest.CAPTURE_ARGV_FILE
        write_private_json(capture_argv_path, capture.argv)

        qemu_process, qemu_argv, launch_argv = start_vm(
            state,
            name=name,
            tap=arguments.tap,
            qemu_user=arguments.qemu_user,
            uid=uid,
            gid=gid,
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
        cleanup_reboot_units(client, name)
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
            record["boot"]["boot_control"] = stage_boot_control(
                client, pair["before"], record_policy
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
            record["timestamps"]["reboot_qga_ready"] = utc_now()
            wait_boot_control_sent(client)
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
            wait_router_active(client, name)
            record["timestamps"]["router_active"] = utc_now()
            record["controls"]["before_exitcode"] = 0
        else:
            record["controls"]["before_exitcode"] = emit_control(
                client, pair["before"], record_policy, wan_device
            )
            record["controls"]["before_transport"] = "qga"
            record["timestamps"]["before_control"] = utc_now()

        if not boot_control_phase:
            if arguments.phase in SETUP_PHASES:
                setup_command = f"systemctl start vprouter@{name}.service"
                record["setup"]["command"] = setup_command
                record["timestamps"]["setup_started"] = utc_now()
                setup = client.execute(
                    "/bin/sh", ["-c", setup_command], timeout=ACTION_TIMEOUT
                )
                record["setup"]["exitcode"] = setup.exitcode
                record["timestamps"]["setup_finished"] = utc_now()
                if setup.exitcode == 0:
                    try:
                        wait_router_active(client, name, timeout=120.0)
                        record["setup"]["active"] = True
                    except hostcheck.Refusal:
                        record["setup"]["active"] = False
                else:
                    record["setup"]["active"] = False
            if arguments.phase == "idle":
                record["action"]["command"] = "true"
                record["action"]["exitcode"] = 0
            else:
                command = action_command(arguments.phase, name)
                record["action"]["command"] = command
                record["timestamps"]["action_started"] = utc_now()
                action = client.execute("/bin/sh", ["-c", command], timeout=ACTION_TIMEOUT)
                record["action"]["exitcode"] = action.exitcode
                record["timestamps"]["action_finished"] = utc_now()
            time.sleep(arguments.duration)
        else:
            time.sleep(arguments.duration)

        record["controls"]["after_exitcode"] = emit_control(
            client, pair["after"], record_policy, wan_device
        )
        record["controls"]["after_transport"] = "qga"
        record["timestamps"]["after_control"] = utc_now()
    except Exception as exc:  # noqa: BLE001 - recorded and re-raised below
        error = exc
        record["error_class"] = exc.__class__.__name__
    finally:
        record["timestamps"]["finally_entered"] = utc_now()
        try:
            if capture is not None:
                record["tcpdump_exit_status"] = stop_capture(capture)
                capture = None
                record["timestamps"]["capture_stopped"] = utc_now()
        finally:
            if boot_control_phase and client is not None:
                try:
                    cleanup_reboot_units(client, name)
                except (QGAError, hostcheck.Refusal):
                    pass
            record["timestamps"]["vm_poweroff_started"] = utc_now()
            record["qemu_exit_status"] = poweroff_vm(client, qemu_process)
            client = None
            record["timestamps"]["vm_finished_at"] = utc_now()

    # Scan even after a failed phase: missing controls and truncated windows
    # are pcapscan's INVALID, not a reason to suppress the capture.
    scan_exit = 2
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
            arguments.expect_tunnel,
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
            scan_flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            if hasattr(os, "O_NOFOLLOW"):
                scan_flags |= os.O_NOFOLLOW
            descriptor = os.open(scan_path, scan_flags, 0o600)
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
                record["scan"]["verdict"] = report.get("verdict")
            except (OSError, json.JSONDecodeError):
                record["scan"]["verdict"] = None
            record["hashes"]["scan_sha256"] = sha256_file(scan_path)
        record["result"] = {
            0: "PASS",
            1: "LEAK",
            2: "INVALID",
        }.get(scan_exit, "ERROR")
    else:
        record["result"] = "ERROR"
    # A clean capture never certifies a phase whose setup or action failed:
    # the tested behaviour did not happen. LEAK stays LEAK.
    if error is not None and scan_exit == 0:
        scan_exit = 2
        record["result"] = "INVALID"
        record["result_reason"] = "phase_action_failed"

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
    write_private_json(evidence_dir / guest.PHASE_RECORD_FILE, record)
    os.chmod(evidence_dir / guest.PHASE_RECORD_FILE, 0o600)

    if error is not None:
        print(f"run_phase: {error.__class__.__name__}: {error}", file=sys.stderr)
    print(
        json.dumps(
            {
                "phase": arguments.phase,
                "verdict": record["scan"]["verdict"],
                "exit": scan_exit,
                "evidence": str(evidence_dir),
            },
            sort_keys=True,
        )
    )
    return scan_exit


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="run one vprlab leak-lab phase")
    parser.add_argument("--phase", required=True, choices=PHASES)
    parser.add_argument("--duration", type=float, required=True)
    parser.add_argument("--policy", required=True)
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
    parser.add_argument(
        "--expect-tunnel",
        required=True,
        choices=("up", "down", "any"),
        help="pcapscan tunnel expectation; required so a phase never "
        "silently passes without bidirectional tunnel evidence",
    )
    arguments = parser.parse_args(argv)
    try:
        return run_phase(arguments)
    except (
        hostcheck.Refusal,
        guest.GeneratorError,
        guest.IntegrityError,
        policy_mod.PolicyError,
    ) as exc:
        print(f"run_phase: {exc}", file=sys.stderr)
        return 2
    except (OSError, subprocess.SubprocessError, QGAError) as exc:
        print(f"run_phase: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
