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
import resource
import secrets
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time

_REAL_POPEN = subprocess.Popen

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
import rootfs  # noqa: E402
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
EVIDENCE_ROOT = guest.EVIDENCE_ROOT
MAX_PHASE_DURATION = 3600.0
HANDSHAKE_MAX_AGE_SECONDS = 180.0
MIN_MEMORY_AVAILABLE = 1536 * 1024 * 1024
DISK_HEADROOM = 1024 * 1024 * 1024
DEFAULT_CAPTURE_SIZE_CAP = 2 * 1024 * 1024 * 1024
CAPTURE_WATCH_INTERVAL = 0.1
SCAN_MEMORY_LIMIT = 1024 * 1024 * 1024
#: The root runner deliberately runs under a hard address-space bound.  It
#: never needs anything close to this; the scanner child gets its own 1 GiB
#: and QEMU/tcpdump explicitly have the inherited limit reset.
RUNNER_MEMORY_LIMIT = 2 * 1024 * 1024 * 1024
#: QEMU's qcow2 overlay is created with a 4 GiB virtual size.  The guest may
#: fill it, so admission reserves that much plus the shared headroom on the
#: state filesystem.
OVERLAY_VIRTUAL_SIZE = 4 * 1024 * 1024 * 1024
#: A test boot writes no serial file (``-serial none``), but QEMU still gets
#: RLIMIT_FSIZE as a seat-belt for the overlay and qemu.log.
TEST_QEMU_FSIZE_LIMIT = 6 * 1024 * 1024 * 1024
SCAN_TIMEOUT = 300.0
#: tcpdump's own RLIMIT_FSIZE is the capture cap plus this margin, so the
#: guard (not the rlimit) normally decides; the rlimit only matters if the
#: runner itself dies.  A truncated capture is then structurally INVALID.
CAPTURE_FSIZE_MARGIN = 256 * 1024 * 1024
INSTALLED_LEAKLAB = pathlib.Path("/opt/vprlab-tools/leaklab")
TAILSCALE_BACKEND_STATES = frozenset(
    {"NoState", "NeedsLogin", "NeedsMachineAuth", "Stopped", "Starting", "Running"}
)
UNRECOGNIZED_GUEST_STATE = "unrecognized"
CERTIFICATION = "server_side_no_client_traffic"
#: Absolute tools for the root runner; never resolve these through root's PATH.
IP = "/usr/sbin/ip"
NFT = "/usr/sbin/nft"


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


def set_runner_limits() -> None:
    """Bound the root runner's address space at 2 GiB (documented in the VM doc)."""
    import resource

    limit = RUNNER_MEMORY_LIMIT
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    target = limit
    if hard != resource.RLIM_INFINITY:
        target = min(target, hard)
    if soft != resource.RLIM_INFINITY:
        target = min(target, soft)
    if target > 0:
        resource.setrlimit(resource.RLIMIT_AS, (target, hard))


def apply_child_limits(
    pid: int,
    *,
    address_space: int | None = None,
    file_size: int | None = None,
) -> None:
    """Apply ``prlimit`` limits to our own already-spawned child.

    The root runner lives under ``RLIMIT_AS`` 2 GiB.  That limit is inherited
    by every child, including QEMU and tcpdump, so each spawn resets it to
    infinity here; the scanner wrapper instead tightens it to 1 GiB.  QEMU
    also gets an ``RLIMIT_FSIZE`` bound.
    """
    import resource

    for name, value in (
        (resource.RLIMIT_AS, address_space),
        (resource.RLIMIT_FSIZE, file_size),
    ):
        if value is None:
            continue
        try:
            resource.prlimit(pid, name, (value, value))
        except ProcessLookupError:
            # It exited immediately; the caller's next poll records that.
            return
        except (OSError, ValueError):
            # An externally imposed hard limit cannot be raised; the child
            # then keeps it.  Never turn that into a spawn failure.
            continue


def _safe_manifest_path(relative: object) -> str:
    if not isinstance(relative, str) or not relative or "\x00" in relative:
        raise hostcheck.Refusal("installed tool manifest has an invalid path")
    if relative.startswith("/") or "\\" in relative:
        raise hostcheck.Refusal("installed tool manifest has an absolute path")
    parts = relative.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise hostcheck.Refusal("installed tool manifest path escapes its root")
    return relative


def _installed_file(root: pathlib.Path, relative: str) -> pathlib.Path:
    """Return a manifest path after refusing symlinked components."""
    current = root
    parts = relative.split("/")
    for part in parts[:-1]:
        current = current / part
        try:
            info = current.lstat()
        except OSError as exc:
            raise hostcheck.Refusal(
                f"installed tool directory is missing: {current}"
            ) from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise hostcheck.Refusal(
                f"installed tool directory is not a real directory: {current}"
            )
    target = current / parts[-1]
    try:
        info = target.lstat()
    except OSError as exc:
        raise hostcheck.Refusal(f"installed tool file is missing: {target}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise hostcheck.Refusal(f"installed tool file is not a regular file: {target}")
    return target


def verify_leaklab_manifest(root: pathlib.Path) -> dict[str, str]:
    """Verify the root-owned scanner copy and return ``{relative: sha256}``."""
    root = pathlib.Path(root)
    if os.geteuid() == 0:
        try:
            rootfs.validate_ancestry(root, expected_uid=0)
        except rootfs.PathError as exc:
            raise hostcheck.Refusal(
                f"installed leak-lab ancestry is not root-trusted: {exc}"
            ) from exc
    manifest = _installed_file(root, "SHA256SUMS")
    try:
        text = manifest.read_text(encoding="utf-8")
    except OSError as exc:
        raise hostcheck.Refusal(
            f"installed leak-lab manifest is unreadable: {exc.__class__.__name__}"
        ) from exc
    digests: dict[str, str] = {}
    for line in text.splitlines():
        if not line:
            continue
        digest, separator, relative = line.partition("  ")
        if not separator or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise hostcheck.Refusal("installed leak-lab manifest is malformed")
        name = _safe_manifest_path(relative)
        if name in digests:
            raise hostcheck.Refusal("installed leak-lab manifest has duplicates")
        target = _installed_file(root, name)
        try:
            actual = sha256_file(target)
        except OSError as exc:
            raise hostcheck.Refusal(
                f"installed tool is unreadable: {name}"
            ) from exc
        if actual != digest:
            raise hostcheck.Refusal(
                f"installed tool hash mismatch: {name} (re-run hostsetup)"
            )
        digests[name] = digest
    if "pcapscan.py" not in digests:
        raise hostcheck.Refusal("installed leak-lab manifest does not list pcapscan.py")
    # Python would prefer a matching cached .pyc over the verified source
    # (r5 review M4): the scanner tree must not contain any bytecode.
    for current, directories, files in os.walk(root, followlinks=False):
        for name in directories + files:
            if name == "__pycache__" or name.endswith((".pyc", ".pyo")):
                raise hostcheck.Refusal(
                    "installed leak-lab tree contains cached bytecode (re-run hostsetup)"
                )
    return digests


def resolve_pcapscan(
    repo_path: pathlib.Path,
    *,
    installed_root: pathlib.Path = INSTALLED_LEAKLAB,
    allow_repo: bool = False,
) -> pathlib.Path:
    """Return the root-owned scanner, or the repo copy with an explicit override.

    Every file listed in the installed manifest must verify against its own
    digest *and* be byte-for-byte identical to the repository copy.  That
    includes the scanner's imports (``policy.py``, ``netplan.py``, ...), so a
    stale module cannot silently change the verdict.  ``--allow-repo-scanner``
    is the documented developer override for running a working-tree scanner
    before re-running hostsetup.
    """
    repo_path = pathlib.Path(repo_path)
    repo_root = repo_path.parent
    installed_root = pathlib.Path(installed_root)
    try:
        digests = verify_leaklab_manifest(installed_root)
    except (hostcheck.Refusal, OSError):
        if allow_repo:
            return repo_path
        raise
    for relative, installed_digest in sorted(digests.items()):
        repo_file = repo_path if relative == "pcapscan.py" else repo_root / relative
        try:
            repo_digest = sha256_file(repo_file)
        except OSError as exc:
            raise hostcheck.Refusal(
                f"repository leak-lab file {relative} is unreadable: "
                f"{exc.__class__.__name__}; re-run hostsetup.py or pass "
                "--allow-repo-scanner"
            ) from exc
        if installed_digest != repo_digest:
            if allow_repo:
                return repo_path
            raise hostcheck.Refusal(
                f"installed {relative} differs from the repository copy; "
                "re-run hostsetup.py or pass --allow-repo-scanner"
            )
    return installed_root / "pcapscan.py"


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
        if section != b"peer" or (b"=" not in stripped and b":" not in stripped):
            continue
        separator = b"=" if b"=" in stripped else b":"
        key, _, value = stripped.partition(separator)
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
    forced_stop: bool = False


def reap_after_setup_failure(process: subprocess.Popen | None) -> None:
    """Kill and reap a child whose log-stream close failed after Popen.

    Otherwise the exception from leaving the ``with`` block would orphan a
    tcpdump/QEMU process with no handle for the caller's finally.
    """
    if process is None:
        return
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    except OSError:
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=5)
    except (subprocess.TimeoutExpired, OSError):
        pass


def start_capture(
    interface: str,
    pcap: pathlib.Path,
    stats: pathlib.Path,
    *,
    tcpdump: str,
    evidence_fd: int | None = None,
    popen=subprocess.Popen,
    timeout: float = 15.0,
    file_size_limit: int | None = None,
) -> Capture:
    if evidence_fd is None:
        argv = guest.tcpdump_argv(interface, pcap)
        error_log = stats.open("xb")
        popen_kwargs: dict = {}
    else:
        # tcpdump must open the pcap through the retained directory fd, so a
        # rename of the evidence path cannot redirect its output.
        rootfs.write_bytes_at(evidence_fd, pcap.name, b"", mode=0o600)
        argv = guest.tcpdump_argv(
            interface, pathlib.Path(rootfs.proc_path(evidence_fd, pcap.name))
        )
        error_descriptor = rootfs.open_file_at(
            evidence_fd, stats.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        error_log = os.fdopen(error_descriptor, "wb")
        popen_kwargs = {"pass_fds": (evidence_fd,)}
    process = None
    try:
        with error_log as error_stream:
            process = popen(
                argv,
                executable=tcpdump,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=error_stream,
                start_new_session=True,
                restore_signals=True,
                **popen_kwargs,
            )
            # The Popen handle exists before any deferred signal is examined.
            if isinstance(process, _REAL_POPEN):
                # RLIMIT_FSIZE bounds the capture file even if this runner is
                # SIGKILLed and the CaptureGuard thread dies with it.
                apply_child_limits(
                    process.pid,
                    address_space=resource.RLIM_INFINITY,
                    file_size=file_size_limit,
                )
    except BaseException:
        reap_after_setup_failure(process)
        raise
    try:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            check_interrupt()
            status = process.poll()
            if status is not None:
                raise hostcheck.Refusal(f"tcpdump exited before listening (status {status})")
            if pcap.is_file() and pcap.stat().st_size >= 24:
                if evidence_fd is not None:
                    for name in (pcap.name, stats.name):
                        descriptor = rootfs.open_file_at(evidence_fd, name, os.O_RDONLY)
                        try:
                            os.fchmod(descriptor, 0o600)
                        finally:
                            os.close(descriptor)
                else:
                    os.chmod(stats, 0o600)
                    os.chmod(pcap, 0o600)
                return Capture(process=process, argv=argv, pcap=pcap, stats=stats)
            time.sleep(0.05)
    except BaseException:
        # Includes PhaseInterrupted: never leave the child without a handle.
        stop_capture(Capture(process=process, argv=argv, pcap=pcap, stats=stats), timeout=5)
        raise
    stop_capture(Capture(process=process, argv=argv, pcap=pcap, stats=stats), timeout=5)
    raise hostcheck.Refusal("tcpdump did not start listening in time")


def stop_capture(
    capture: Capture | None,
    *,
    timeout: float = 20.0,
    evidence_fd: int | None = None,
) -> int | None:
    if capture is None:
        return None
    process = capture.process
    if process.poll() is None:
        try:
            process.send_signal(signal.SIGINT)
        except OSError:
            pass
    try:
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(process.args if hasattr(process, "args") else "tcpdump", timeout)
            try:
                status = process.wait(timeout=min(0.5, remaining))
            except subprocess.TimeoutExpired:
                continue
            break
    except subprocess.TimeoutExpired:
        capture.forced_stop = True
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except OSError:
            process.kill()
        status = process.wait(timeout=10)
    for path in (capture.pcap, capture.stats):
        try:
            if evidence_fd is not None:
                descriptor = rootfs.open_file_at(evidence_fd, path.name, os.O_RDONLY)
                try:
                    os.fchmod(descriptor, 0o600)
                finally:
                    os.close(descriptor)
            else:
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


def file_contains_payload_at(directory_fd: int, name: str, needle: bytes) -> bool:
    """Descriptor-anchored variant of :func:`file_contains_payload`."""
    carry = b""
    try:
        descriptor = rootfs.open_file_at(directory_fd, name, os.O_RDONLY)
    except OSError:
        return False
    try:
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                return False
            window = carry + chunk
            if needle in window:
                return True
            carry = window[-max(0, len(needle) - 1) :]
    except OSError:
        return False
    finally:
        os.close(descriptor)


def wait_for_control_in_pcap(
    path: pathlib.Path | None,
    nonce: str,
    *,
    timeout: float | None = None,
    evidence_fd: int | None = None,
    name: str | None = None,
) -> bool:
    """Wait until tcpdump's ``-U --immediate-mode`` file contains the AFTER."""
    if timeout is None:
        timeout = AFTER_CAPTURE_TIMEOUT
    needle = policy_mod.CONTROL_PREFIX + nonce.encode("ascii")
    deadline = time.monotonic() + timeout
    while True:
        check_interrupt()
        if evidence_fd is not None and name is not None:
            found = file_contains_payload_at(evidence_fd, name, needle)
        elif path is not None:
            found = file_contains_payload(path, needle)
        else:
            found = False
        if found:
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
        "certifies": CERTIFICATION,
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


@dataclasses.dataclass
class EvidenceDirectory:
    """A retained root directory fd plus a display path for records."""

    fd: int
    path: pathlib.Path

    def close(self) -> None:
        if self.fd >= 0:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = -1

    def open_new(self, name: str, data: bytes, *, mode: int = 0o600) -> None:
        rootfs.write_bytes_at(self.fd, name, data, mode=mode, exclusive=True)

    def open_append(self, name: str, *, mode: int = 0o600) -> int:
        return rootfs.open_file_at(
            self.fd, name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode
        )

    def write_json(self, name: str, document: object, *, mode: int = 0o600) -> None:
        rootfs.write_json_at(self.fd, name, document, mode=mode)

    def write_text(self, name: str, text: str, *, mode: int = 0o600) -> None:
        self.open_new(name, text.encode("utf-8"), mode=mode)

    def read_bytes(self, name: str) -> bytes:
        return rootfs.read_bytes_at(self.fd, name)

    def hash(self, name: str, algorithm: str = "sha256") -> str:
        return rootfs.hash_file_at(self.fd, name, algorithm)

    def size(self, name: str) -> int:
        return rootfs.file_size_at(self.fd, name)

    def proc_path(self, name: str) -> str:
        return rootfs.proc_path(self.fd, name)


def display_argv(argv: list[str], evidence: EvidenceDirectory) -> list[str]:
    """Replace inherited-fd paths with the evidence display path for readers."""
    prefix = f"/proc/self/fd/{evidence.fd}/"
    result: list[str] = []
    for item in argv:
        if item.startswith(prefix):
            result.append(str(evidence.path / item[len(prefix):]))
        else:
            result.append(item)
    return result


def ensure_root_directory(path: pathlib.Path, *, anchor: pathlib.Path | None = None) -> None:
    """Create/validate a root-only 0700 directory without following links."""
    expected_uid = 0 if os.geteuid() == 0 else os.geteuid()
    descriptor = rootfs.open_directory(
        path, create=True, mode=0o700, expected_uid=expected_uid, anchor=anchor
    )
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
        return f"ip -j link show wg0 inside the router netns ({name})"
    if phase == "kill-container":
        return (
            f"if docker inspect --format '{{{{.State.Running}}}}' {name} "
            "2>/dev/null | grep -qx true; then exit 1; fi; exit 0"
        )
    return None


def wg0_state_command(name: str) -> str:
    guest.validate_name(name)
    return (
        f"pid=$(docker inspect --format '{{{{.State.Pid}}}}' {name} 2>/dev/null) "
        "|| { echo stopped; exit 0; }; "
        '[ "$pid" -gt 1 ] || { echo stopped; exit 0; }; '
        'if nsenter -t "$pid" -n ip -j link show wg0 2>/dev/null; then exit 0; '
        'else echo absent; fi'
    )


def read_wg0_state(client: QGAClient, name: str) -> dict:
    """Return container/wg0 state without assuming either still exists."""
    result = client.execute("/bin/sh", ["-c", wg0_state_command(name)], timeout=15.0)
    text = result.stdout.decode("utf-8", "replace").strip()
    if result.exitcode != 0:
        return {"status": "unknown", "container_running": None, "ifindex": None}
    if text == "stopped":
        return {"status": "container_stopped", "container_running": False, "ifindex": None}
    if text == "absent" or not text:
        return {"status": "absent", "container_running": True, "ifindex": None}
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        return {"status": "unknown", "container_running": None, "ifindex": None}
    if isinstance(document, list):
        for entry in document:
            if isinstance(entry, dict) and entry.get("ifname") == "wg0":
                index = entry.get("ifindex")
                if isinstance(index, int) and not isinstance(index, bool):
                    return {
                        "status": "present",
                        "container_running": True,
                        "ifindex": index,
                    }
    return {"status": "absent", "container_running": True, "ifindex": None}


def check_kill_wireguard(
    client: QGAClient,
    name: str,
    *,
    before_ifindex: int,
    window: float = 1.0,
) -> dict:
    """Prove wg0 disappeared or was recreated within one second.

    A stopped router container is also proof: the release's monitor may stop
    it while the fault is being observed (review m-5).  Recovery is recorded
    later, never required, so the check cannot flake.
    """
    deadline = time.monotonic() + window
    state = read_wg0_state(client, name)
    while True:
        check_interrupt()
        if state["status"] == "container_stopped":
            return {"ok": True, "proof": "container_stopped", **state}
        if state["status"] == "absent":
            return {"ok": True, "proof": "wg0_absent", **state}
        if state["status"] == "present" and state["ifindex"] != before_ifindex:
            return {"ok": True, "proof": "ifindex_changed", **state}
        if time.monotonic() >= deadline:
            return {"ok": False, "proof": "wg0_unchanged", **state}
        time.sleep(0.1)
        state = read_wg0_state(client, name)


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
        check_interrupt()
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
        check_interrupt()
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
        check_interrupt()
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
    client: QGAClient,
    name: str,
    *,
    timeout: float | None = None,
    max_age: float = HANDSHAKE_MAX_AGE_SECONDS,
) -> int:
    """Require a real, fresh WireGuard handshake inside the router netns.

    Freshness is measured with the guest's own clock: ``latest-handshakes``
    reports the guest-kernel timestamp, and a static or days-old handshake is
    not proof that the tunnel is currently up.
    """
    if timeout is None:
        timeout = ROUTER_HANDSHAKE_TIMEOUT
    deadline = time.monotonic() + timeout
    command = router_handshake_command(name)
    while time.monotonic() < deadline:
        check_interrupt()
        now = read_guest_clock(client)
        result = client.execute("/bin/sh", ["-c", command], timeout=15.0)
        if result.exitcode == 0:
            for line in result.stdout.decode("utf-8", "replace").splitlines():
                fields = line.split()
                if len(fields) < 2 or not fields[1].isdigit():
                    continue
                timestamp = int(fields[1])
                age = now - timestamp
                if -5 <= age < max_age:
                    return timestamp
        time.sleep(1.0)
    raise hostcheck.Refusal(
        "no fresh WireGuard handshake (age < "
        f"{int(max_age)} s) was observed in the router netns"
    )


def wait_router_ready(
    client: QGAClient,
    name: str,
    *,
    require_tailscale: bool = False,
) -> None:
    """Require the phase's pre-window readiness.

    ``start-router`` (and the login bootstrap) may run before an interactive
    login, so they require only the active unit and a fresh handshake.  Every
    phase that certifies idle/fault behaviour must additionally consume the
    release's own READY status and a running node that advertises an exit
    node.
    """
    wait_router_active(client, name)
    wait_router_handshake(client, name)
    if require_tailscale:
        wait_release_ready(client, name)
        wait_tailscale_ready(client, name)


def read_boot_id(client: QGAClient) -> str:
    result = client.execute(
        "/bin/sh",
        ["-c", "cat /proc/sys/kernel/random/boot_id"],
        timeout=15.0,
    )
    if result.exitcode != 0:
        raise hostcheck.Refusal("cannot read the guest boot ID")
    value = result.stdout.decode("ascii", "replace").strip()
    if not re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value
    ):
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
        check_interrupt()
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


def read_guest_clock(client: QGAClient) -> int:
    """Read the guest wall clock (QGA), used for handshake freshness."""
    result = client.execute("/bin/sh", ["-c", "date +%s"], timeout=15.0)
    value = result.stdout.decode("ascii", "replace").strip()
    if result.exitcode != 0 or not value.isdigit():
        raise hostcheck.Refusal("cannot read the guest clock")
    return int(value)


def read_tailscale_status(client: QGAClient, name: str) -> dict | None:
    result = client.execute(
        "/bin/sh",
        ["-c", f"docker exec {name} tailscale status --json 2>/dev/null || true"],
        timeout=20.0,
    )
    try:
        document = json.loads(result.stdout.decode("utf-8", "replace"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return document if isinstance(document, dict) else None


def tailscale_readiness_problems(document: object) -> list[str]:
    """Require a running Tailscale node that advertises an exit node."""
    if not isinstance(document, dict):
        return ["tailscale status is unavailable"]
    problems: list[str] = []
    if document.get("BackendState") != "Running":
        problems.append("Tailscale BackendState is not Running")
    node = document.get("Self")
    if not isinstance(node, dict):
        problems.append("tailscale status has no Self node")
        return problems
    # The release's own router_runtime.tailscale_ready uses this exact field;
    # Self.AdvertisedRoutes is not emitted by `tailscale status --json`.
    if node.get("ExitNodeOption") is not True:
        problems.append("the node does not advertise an exit node")
    return problems


def normalize_backend_state(value: object) -> str:
    """Map a guest-supplied BackendState to the fixed local vocabulary."""
    if isinstance(value, str) and value in TAILSCALE_BACKEND_STATES:
        return value
    return UNRECOGNIZED_GUEST_STATE


def read_tailscale_backend_state(client: QGAClient, name: str) -> str | None:
    document = read_tailscale_status(client, name)
    if document is None:
        return None
    return normalize_backend_state(document.get("BackendState"))


def record_tailscale_state(record: dict, client: QGAClient, name: str) -> None:
    try:
        record["tailscale"]["backend_state"] = read_tailscale_backend_state(client, name)
    except (QGAError, OSError):
        record["tailscale"]["backend_state"] = None


def release_status_command(name: str) -> str:
    guest.validate_name(name)
    return (
        "exec python3 /opt/vprouter/current/host/orchestrate.py status "
        f"--name {shlex.quote(name)}"
    )


_SAFE_TEXT = re.compile(r"[A-Za-z0-9 .,:;()<>_-]{0,240}")
#: A WireGuard key or any other long token: never recorded.
_LONG_TOKEN = re.compile(r"[A-Za-z0-9]{20,}")
#: Shapes of an address, hostname, auth key or chunked secret (r5 review M1).
_IDENTIFYING = re.compile(
    r"[A-Za-z0-9]\.[A-Za-z0-9]"  # dotted name or IPv4
    r"|[0-9A-Fa-f]:[0-9A-Fa-f:]"  # IPv6
    r"|::"
    r"|tskey"
    r"|(?<![A-Za-z0-9])(?=[A-Za-z0-9]*[0-9])[A-Za-z0-9]{5,}(?![A-Za-z0-9])"  # digit token >= 5
    , re.IGNORECASE,
)


def _safe_text(value: object) -> str | None:
    """Return runner-authored text only if it is plain, short and anonymous."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if (
        not _SAFE_TEXT.fullmatch(value)
        or _LONG_TOKEN.search(value)
        or _IDENTIFYING.search(value)
    ):
        return "unrecognized"
    return value


#: Every health reason the deployed release writes itself
#: (/opt/vprouter/current/router_runtime.py set_health and RuntimeErrorClosed).
RELEASE_HEALTH_REASONS = frozenset({
    "firewall",
    "waiting for WireGuard",
    "starting Tailscale",
    "Tailscale authentication or control is unavailable",
    "protected egress verified",
    "Tailscale is not ready",
    "Tailscale health check failed",
    "stopping",
    "unexpected or missing router interface",
    "router must boot with loopback only",
    "VPN provider did not confirm protected egress",
    "default route is not exclusively WireGuard",
    "public IPv6 default route is prohibited",
    "tailscaled exited during startup",
    "tailscaled control socket did not become ready",
    "WireGuard handshake is stale",
    "Tailscale exit is not approved and online",
    "tailscaled exited",
})
#: ``type(exc).__name__`` and the release's ``HTTPError (HTTP NNN)`` form.
_RELEASE_REASON_SHAPES = re.compile(
    r"[A-Z][A-Za-z]{2,40}|HTTPError \(HTTP [1-5][0-9][0-9]\)"
)


def release_reason(value: object) -> str | dict | None:
    """Map a release health reason to a known string, never free text.

    Anything outside the release's fixed vocabulary is recorded only as its
    length and a short hash, so a later release cannot put an address,
    hostname or token into evidence (r5 review M1).
    """
    if not isinstance(value, str):
        return None
    if value in RELEASE_HEALTH_REASONS or _RELEASE_REASON_SHAPES.fullmatch(value):
        return value
    return {
        "unlisted_sha256_12": hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12],
        "length": len(value),
    }


def record_readiness_refusal(
    record: dict, client: QGAClient, name: str, exc: BaseException
) -> None:
    """Record which readiness gate refused and the release's own health.

    The refusal text is authored by this runner.  The health file is written
    by the deployed release: the state must be one of four enum values and
    the reason one of the release's fixed strings, else only its hash and
    length are kept.
    """
    readiness = record.setdefault("readiness", {})
    readiness["refusal"] = _safe_text(str(exc))
    try:
        result = client.execute(
            "/bin/sh",
            ["-c", f"docker exec {shlex.quote(name)} cat /run/vprouter-health.json"],
            timeout=15.0,
        )
        document = json.loads(result.stdout.decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001 - diagnostics only
        document = None
    if isinstance(document, dict):
        state = document.get("state")
        readiness["release_health_state"] = (
            state if state in {"STARTING", "BLOCKED", "RECOVERING", "READY"} else "unrecognized"
        )
        readiness["release_health_reason"] = release_reason(document.get("reason"))
    try:
        status = read_tailscale_status(client, name)
    except Exception:  # noqa: BLE001 - diagnostics only
        status = None
    # Our own fixed problem strings, plus booleans only (never guest text).
    readiness["tailscale_problems"] = tailscale_readiness_problems(status)
    node = status.get("Self") if isinstance(status, dict) else None
    if isinstance(node, dict):
        readiness["tailscale_self"] = {
            key: node.get(key) if isinstance(node.get(key), bool) else None
            for key in ("Online", "ExitNodeOption", "ExitNode")
        }
    record_tailscale_state(record, client, name)


def wait_release_ready(
    client: QGAClient, name: str, *, timeout: float | None = None
) -> dict:
    """Require the deployed release's own READY health status."""
    if timeout is None:
        timeout = ROUTER_ACTIVE_TIMEOUT
    deadline = time.monotonic() + timeout
    command = release_status_command(name)
    last_problem = "no status"
    while time.monotonic() < deadline:
        check_interrupt()
        result = client.execute("/bin/sh", ["-c", command], timeout=30.0)
        if result.exitcode == 0:
            try:
                document = json.loads(result.stdout.decode("utf-8", "replace"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                document = None
            if (
                isinstance(document, dict)
                and document.get("state") == "READY"
                and document.get("name") == name
            ):
                return document
            last_problem = "status document is not READY"
        else:
            last_problem = f"status exit {result.exitcode}"
        time.sleep(2.0)
    raise hostcheck.Refusal(f"the release did not report READY ({last_problem})")


def wait_tailscale_ready(
    client: QGAClient, name: str, *, timeout: float | None = None
) -> None:
    if timeout is None:
        timeout = ROUTER_HANDSHAKE_TIMEOUT
    deadline = time.monotonic() + timeout
    problems = ["tailscale status is unavailable"]
    while time.monotonic() < deadline:
        check_interrupt()
        problems = tailscale_readiness_problems(read_tailscale_status(client, name))
        if not problems:
            return
        time.sleep(2.0)
    raise hostcheck.Refusal("Tailscale is not a running exit node: " + "; ".join(problems))


def find_login_url(client: QGAClient, name: str) -> str | None:
    return login_url_mod.find_login_url(client, name)


def login_phase_wait(
    client: QGAClient,
    *,
    name: str,
    duration: float,
    evidence: EvidenceDirectory,
    record: dict,
    guard: CaptureGuard | None = None,
    note=None,
) -> None:
    """Poll the login URL through the runner's own QGA connection."""
    url_path = evidence.path / "login-url.txt"
    deadline = time.monotonic() + duration
    found: str | None = None
    while True:
        check_interrupt()
        if guard is not None:
            guard.raise_if_exceeded()
        try:
            url, unrecognized = login_url_mod.find_login_url_result(client, name)
        except (QGAError, OSError):
            url, unrecognized = None, False
        if unrecognized:
            record["login_url_unrecognized"] = True
            problems = record.setdefault("login_url_problems", [])
            if "login_url_unrecognized" not in problems:
                problems.append("login_url_unrecognized")
        if url is not None and found is None:
            found = url
            evidence.write_text("login-url.txt", url + "\n")
            record["login_url"] = str(url_path)
            record["login_url_length"] = len(url)
            print(f"run_phase: login URL {url}", file=sys.stderr)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(2.0, remaining))
    # An unrecognized login.tailscale.com string is never written out.  It is a
    # phase error only when no valid URL was found at all: tailscaled's logs
    # also mention other login.tailscale.com paths (found live 2026-11-09).
    if found is None and record.get("login_url_unrecognized") and note is not None:
        note("login_url_unrecognized")


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
        check_interrupt()
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


def read_mem_available() -> int:
    try:
        text = pathlib.Path("/proc/meminfo").read_text(encoding="ascii")
    except OSError as exc:
        raise hostcheck.Refusal("cannot read /proc/meminfo") from exc
    for line in text.splitlines():
        if line.startswith("MemAvailable:"):
            fields = line.split()
            if len(fields) >= 2 and fields[1].isdigit():
                return int(fields[1]) * 1024
    raise hostcheck.Refusal("/proc/meminfo has no MemAvailable")


def _existing_ancestor(path: pathlib.Path) -> pathlib.Path:
    candidate = pathlib.Path(path)
    while not candidate.exists():
        if candidate.parent == candidate:
            break
        candidate = candidate.parent
    return candidate


def _free_bytes(path: pathlib.Path) -> int:
    try:
        stats = os.statvfs(_existing_ancestor(path))
    except OSError as exc:
        raise hostcheck.Refusal("cannot measure free disk space") from exc
    return stats.f_bavail * stats.f_frsize


def check_admission(
    evidence_root: pathlib.Path,
    capture_size_cap: int,
    *,
    state_root: pathlib.Path | None = None,
    mem_available: int | None = None,
    free_bytes: int | None = None,
    state_free_bytes: int | None = None,
) -> None:
    """Refuse to boot a guest without host memory and disk headroom.

    The evidence filesystem must hold the pcap cap plus 1 GiB.  The state
    filesystem is separate evidence-wise and must hold the guest's 4 GiB
    overlay plus the same 1 GiB headroom; a guest can fill its own disk
    without sending a single packet.
    """
    available = read_mem_available() if mem_available is None else mem_available
    if available < MIN_MEMORY_AVAILABLE:
        raise hostcheck.Refusal(
            "host MemAvailable is below "
            f"{MIN_MEMORY_AVAILABLE // (1024 * 1024)} MiB; refusing to boot"
        )
    if free_bytes is None:
        free_bytes = _free_bytes(evidence_root)
    required = int(capture_size_cap) + DISK_HEADROOM
    if free_bytes < required:
        raise hostcheck.Refusal(
            f"free disk is below the capture cap plus {DISK_HEADROOM // (1024 * 1024)} MiB"
        )
    if state_root is not None or state_free_bytes is not None:
        if state_free_bytes is None:
            state_free_bytes = _free_bytes(state_root)
        state_required = OVERLAY_VIRTUAL_SIZE + DISK_HEADROOM
        if state_free_bytes < state_required:
            raise hostcheck.Refusal(
                "free space on the state filesystem is below the 4 GiB overlay "
                f"plus {DISK_HEADROOM // (1024 * 1024)} MiB headroom"
            )


class CaptureCapExceeded(RuntimeError):
    """The capture outgrew its byte cap or the evidence disk ran low."""


def capture_bounds_problem(
    size: int, capture_size_cap: int, free_bytes: int | None
) -> str | None:
    """Return the fixed INVALID reason for an exceeded capture/disk bound."""
    if size > int(capture_size_cap):
        return "capture_size_cap"
    if free_bytes is not None and free_bytes < DISK_HEADROOM:
        return "capture_disk_low"
    return None


class CaptureGuard:
    """Watch the pcap size and evidence disk for the whole capture lifetime.

    The watcher runs from ``tcpdump`` start until ``tcpdump`` exits, including
    setup, readiness, action, teardown and poweroff waits.  On a breach it
    brings the tap down before the main thread notices and records a fixed
    reason; every later checkpoint re-reads the retained evidence fd.
    """

    def __init__(
        self,
        evidence_fd: int,
        name: str,
        capture_size_cap: int,
        *,
        tap: str = guest.TAP,
        interval: float | None = None,
        capture_process=None,
        qemu_process=None,
    ) -> None:
        self.evidence_fd = evidence_fd
        self.name = name
        self.capture_size_cap = int(capture_size_cap)
        self.tap = tap
        # Read the module constant at call time, so a test (or an operator
        # patch) can shorten the interval without changing the default.
        self.interval = float(CAPTURE_WATCH_INTERVAL if interval is None else interval)
        self.reason: str | None = None
        self.isolation_error: str | None = None
        self.kill_error: str | None = None
        self.capture_process = capture_process
        self.qemu_process = qemu_process
        self.capture_ended_early_at: str | None = None
        self._stopping_capture = False
        self._descriptor: int | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def attach_capture(self, process) -> None:
        self.capture_process = process

    def attach_qemu(self, process) -> None:
        self.qemu_process = process

    def mark_capture_stopping(self) -> None:
        """A normal SIGINT shutdown is about to happen; ignore that exit."""
        self._stopping_capture = True

    def _open(self) -> int | None:
        if self._descriptor is None:
            try:
                self._descriptor = rootfs.open_file_at(
                    self.evidence_fd, self.name, os.O_RDONLY
                )
            except (OSError, rootfs.PathError):
                self._descriptor = None
        return self._descriptor

    def measure(self) -> str | None:
        descriptor = self._open()
        if descriptor is None:
            return None
        size = os.fstat(descriptor).st_size
        free_bytes: int | None = None
        try:
            stats = os.fstatvfs(descriptor)
            free_bytes = stats.f_bavail * stats.f_frsize
        except (OSError, AttributeError):
            free_bytes = None
        return capture_bounds_problem(size, self.capture_size_cap, free_bytes)

    def _breach(self, reason: str) -> None:
        with self._lock:
            if self.reason is None:
                self.reason = reason
            elif self.reason != reason:
                return
        try:
            isolate_tap(self.tap)
        except BaseException as exc:  # noqa: BLE001 - isolation is best effort
            self.isolation_error = exc.__class__.__name__
        # A tap-down does not stop a compromised guest from writing its
        # overlay/serial/qemu.log.  Kill the verified QEMU we own as well; the
        # ordered cleanup still runs and records INVALID.
        if self.qemu_process is not None and reason in (
            "capture_size_cap",
            "capture_disk_low",
        ):
            try:
                kill_qemu(self.qemu_process)
            except BaseException as exc:  # noqa: BLE001
                self.kill_error = exc.__class__.__name__

    def _capture_liveness(self) -> str | None:
        if self.capture_process is None or self._stopping_capture:
            return None
        try:
            status = self.capture_process.poll()
        except BaseException:  # noqa: BLE001 - a broken handle is not liveness
            return None
        if status is None:
            return None
        if self.capture_ended_early_at is None:
            self.capture_ended_early_at = utc_now()
        return "capture_ended_early"

    def check(self) -> str | None:
        if self.reason is None:
            try:
                reason = self.measure()
            except OSError:
                reason = None
            if reason is None:
                reason = self._capture_liveness()
            if reason is not None:
                self._breach(reason)
        return self.reason

    def raise_if_exceeded(self) -> None:
        reason = self.check()
        if reason is not None:
            raise CaptureCapExceeded(reason)

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            self.check()

    def start(self) -> None:
        # Handlers were installed before this thread can receive a signal;
        # handlers only set a flag, so a process-directed signal handled here
        # cannot bypass the main thread's ordered cleanup.
        ensure_signal_handlers()
        self._thread = threading.Thread(
            target=self._run, name="vprlab-capture-guard", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self.check()
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=max(1.0, self.interval * 5))
        if self._descriptor is not None:
            try:
                os.close(self._descriptor)
            except OSError:
                pass
            self._descriptor = None

    def sleep(self, seconds: float, *, chunk: float = 0.25) -> None:
        remaining = max(0.0, float(seconds))
        while True:
            check_interrupt()
            self.raise_if_exceeded()
            if remaining <= 0:
                return
            step = min(chunk, remaining)
            time.sleep(step)
            remaining -= step


def wait_capture_room(
    pcap: pathlib.Path,
    seconds: float,
    capture_size_cap: int,
    *,
    chunk: float = 0.25,
) -> None:
    """Compatibility helper used by callers without an EvidenceDirectory."""
    remaining = max(0.0, float(seconds))
    while True:
        check_interrupt()
        try:
            size = pathlib.Path(pcap).stat().st_size
        except OSError:
            size = 0
        reason = capture_bounds_problem(size, capture_size_cap, None)
        if reason is not None:
            raise CaptureCapExceeded(reason)
        if remaining <= 0:
            return
        step = min(chunk, remaining)
        time.sleep(step)
        remaining -= step


def set_scan_limits() -> None:
    """Set the scanner's address-space limit (kept for direct callers)."""
    limit = SCAN_MEMORY_LIMIT
    resource.setrlimit(resource.RLIMIT_AS, (limit, limit))


#: A tiny, trusted interpreter wrapper.  The root runner may still have the
#: capture-guard thread running while it scans, so it must not use
#: ``preexec_fn``; the wrapper applies the scanner RLIMIT_AS and then
#: ``execve``s the real scanner without changing its argv.
SCAN_LIMIT_WRAPPER = """\
import os, resource, sys
limit = int(sys.argv[1])
resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
os.execv(sys.argv[2], sys.argv[2:])
"""


def scanner_launch_argv(
    scan_argv: list[str], *, limit: int = SCAN_MEMORY_LIMIT
) -> list[str]:
    """Return the wrapper argv that spawns ``scan_argv`` under 1 GiB."""
    return [
        sys.executable,
        "-I",
        "-B",
        "-c",
        SCAN_LIMIT_WRAPPER,
        str(int(limit)),
        *scan_argv,
    ]


def verify_host_lab(
    *,
    tap: str,
    bridge: str,
    owner_file: str | pathlib.Path = hostcheck.OWNER_FILE,
    qemu_user: str | None = None,
) -> None:
    if os.geteuid() == 0:
        try:
            rootfs.validate_ancestry(
                pathlib.Path(owner_file).parent, expected_uid=0
            )
        except rootfs.PathError as exc:
            raise hostcheck.Refusal(
                f"owner-document ancestry is not root-trusted: {exc}"
            ) from exc
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
    links = _run_json([IP, "-d", "-j", "link", "show"], what="ip -d -j link show")
    addresses = _run_json([IP, "-j", "addr", "show"], what="ip -j addr show")
    # ``nft -j list table`` exits non-zero when the table is absent; that is a
    # refusal, not a crash.
    try:
        table = subprocess.run(
            [NFT, "-j", "list", "table", "inet", "vprlab"],
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
    neighbors = _run_json([IP, "-j", "neigh", "show"], what="ip -j neigh show")
    problems = hostcheck.verify_host_network(
        links,
        table_document,
        neighbors,
        addresses_document=addresses,
        bridge=bridge,
        tap=tap,
        owner_token=token,
        tap_user=qemu_user,
    )
    if problems:
        raise hostcheck.Refusal("; ".join(problems))


def verify_state(
    state: pathlib.Path, *, qemu_uid: int, base: pathlib.Path, qemu_gid: int | None = None
) -> None:
    if os.geteuid() == 0:
        try:
            rootfs.validate_ancestry(pathlib.Path(state).parent, expected_uid=0)
        except rootfs.PathError as exc:
            raise hostcheck.Refusal(f"state ancestry is not root-trusted: {exc}") from exc
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
    try:
        guest.verify_tool_ancestry()
    except guest.GeneratorError as exc:
        raise hostcheck.Refusal(str(exc)) from exc
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
            env=guest.clean_environment(),
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
    log_path: pathlib.Path | None = None,
    log_fd: int | None = None,
) -> tuple[subprocess.Popen, list[str], list[str]]:
    if (log_path is None) == (log_fd is None):
        raise hostcheck.Refusal("exactly one of log_path and log_fd is required")
    for stale in (guest.PID_FILE, guest.QGA_SOCKET):
        try:
            (state / stale).unlink()
        except OSError:
            pass
    qemu_argv = guest.build_qemu_argv("test", state, name=name, tap=tap)
    launch_argv = guest.build_launch_argv(qemu_argv, qemu_user, uid=uid, gid=gid)
    if log_fd is None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(log_path, flags, 0o600)
    else:
        descriptor = os.dup(log_fd)
    process = None
    try:
        with os.fdopen(descriptor, "ab") as log:
            process = subprocess.Popen(
                launch_argv,
                env=guest.clean_environment(),
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                restore_signals=True,
            )
            if isinstance(process, _REAL_POPEN):
                apply_child_limits(
                    process.pid,
                    address_space=resource.RLIM_INFINITY,
                    file_size=TEST_QEMU_FSIZE_LIMIT,
                )
    except BaseException:
        reap_after_setup_failure(process)
        raise
    return process, qemu_argv, launch_argv


def wait_for_qga_or_exit(
    socket_path: pathlib.Path,
    process: subprocess.Popen,
    *,
    timeout: float = QGA_BOOT_TIMEOUT,
) -> QGAClient:
    deadline = time.monotonic() + timeout
    while True:
        check_interrupt()
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


def qemu_process_is_ours(process: subprocess.Popen) -> bool:
    """Prove the pid from our own Popen still executes the staged QEMU.

    The QEMU-owned pidfile is not evidence: a compromised guest/QEMU can
    delete or rewrite it.  ``/proc/<pid>/exe`` names the inode the kernel
    actually executes, and the child pid cannot be reused while our un-reaped
    Popen handle exists.
    """
    pid = process.pid
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 1:
        return False
    expected = os.path.realpath(os.fspath(guest.QEMU))
    try:
        executable = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return False
    if os.path.realpath(executable) != expected:
        return False
    try:
        cmdline = pathlib.Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return False
    argv = cmdline.split(b"\x00")
    if not argv or argv[0] != os.fsencode(os.fspath(guest.QEMU)):
        return False
    return True


#: Backwards-compatible name for the old private helper.
def qemu_pid_is_ours(process: subprocess.Popen, state: pathlib.Path | None = None) -> bool:
    del state
    return qemu_process_is_ours(process)


def kill_qemu(process: subprocess.Popen, state: pathlib.Path | None = None) -> bool:
    """SIGKILL our verified QEMU and reap it; return whether it is gone."""
    if process.poll() is not None:
        return True
    if not qemu_process_is_ours(process):
        # Pid reuse, or the staged binary was replaced: never signal it.
        return False
    # A pidfd refers to exactly this process even if the pid is later reused,
    # so a concurrent reap can never redirect the SIGKILL to another process.
    try:
        pidfd = os.pidfd_open(process.pid)
    except OSError:
        return process.poll() is not None
    try:
        if process.poll() is not None:
            return True
        if not qemu_process_is_ours(process):
            return False
        try:
            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
        except ProcessLookupError:
            return True
        except OSError:
            return False
    finally:
        os.close(pidfd)
    try:
        process.wait(timeout=10)
    except (subprocess.TimeoutExpired, OSError):
        return False
    return True


def isolate_tap(tap: str = guest.TAP) -> None:
    """Bring the lab tap down so a surviving guest cannot reach the host."""
    completed = subprocess.run(
        [IP, "link", "set", "dev", tap, "down"],
        check=False,
        capture_output=True,
        timeout=15,
    )
    if completed.returncode != 0:
        raise hostcheck.Refusal("cannot isolate the laboratory tap")


def poweroff_vm(
    client: QGAClient | None,
    process: subprocess.Popen | None,
    *,
    state: pathlib.Path | None = None,
    tap: str = guest.TAP,
) -> tuple[int | None, bool, bool]:
    """Power the guest off; return ``(status, forced, survived)``.

    A timeout, an exception, or a termination signal during the wait falls back
    to a verified SIGKILL of our QEMU.  If the process survives even that, the
    tap is brought down before the caller stops observing it.
    """
    forced = False
    if client is not None:
        try:
            client.shutdown("powerdown", timeout=5.0)
        except BaseException:  # noqa: BLE001 - a failed request still means kill
            forced = True
        finally:
            try:
                client.close()
            except OSError:
                pass
    if process is None:
        return None, forced, False
    try:
        return wait_process(process, POWEROFF_TIMEOUT), forced, False
    except BaseException:  # timeout or a termination signal during the wait
        forced = True
    if kill_qemu(process, state):
        status = process.poll()
        return status, forced, False
    survived = process.poll() is None
    if survived:
        try:
            isolate_tap(tap)
        except (hostcheck.Refusal, OSError, subprocess.SubprocessError):
            pass
    return (process.poll() if not survived else None), forced, survived


# ---------------------------------------------------------------------------
# Signal handling


class PhaseInterrupted(RuntimeError):
    """A termination signal arrived; unwind through the ordered cleanup."""


#: Set by the signal handler and read by every blocking wait/loop.  The
#: handler itself never raises and never blocks anything: a signal delivered
#: while a child is being created therefore cannot orphan it.  The Popen
#: object is assigned as soon as the call returns and the next explicit
#: checkpoint raises into the finally-based cleanup with a live handle.
_signal_seen = False
_signal_number: int | None = None
_signal_raised = False
_handlers_installed = False


def _handle_signal(signum: int, _frame) -> None:
    global _signal_seen, _signal_number
    if _signal_seen:
        return
    _signal_seen = True
    _signal_number = signum


def check_interrupt() -> None:
    """Raise once when a deferred termination signal has been observed.

    Only the first checkpoint raises; later checkpoints (the ordered cleanup)
    must run to completion even if another signal arrived meanwhile.
    """
    global _signal_raised
    if _signal_seen and not _signal_raised:
        _signal_raised = True
        raise PhaseInterrupted(
            f"received signal {_signal_number if _signal_number is not None else 'termination'}"
        )


def install_signal_handlers() -> None:
    global _signal_seen, _signal_number, _signal_raised, _handlers_installed
    _signal_seen = False
    _signal_number = None
    _signal_raised = False
    for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(signum, _handle_signal)
    # Children inherit this mask.  The runner never blocks a termination
    # signal itself, and it clears any mask inherited from its caller so a
    # spawned tcpdump/QEMU starts with SigBlk == 0.
    if hasattr(signal, "pthread_sigmask"):
        signal.pthread_sigmask(signal.SIG_SETMASK, set())
    _handlers_installed = True


def ensure_signal_handlers() -> None:
    expected = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)
    if not _handlers_installed or any(
        signal.getsignal(signum) is not _handle_signal for signum in expected
    ):
        install_signal_handlers()


def wait_process(process: subprocess.Popen, timeout: float, *, chunk: float = 0.5):
    """Wait for a child in short slices so a deferred signal is honoured."""
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return process.wait(timeout=0)
        try:
            return process.wait(timeout=min(chunk, remaining))
        except subprocess.TimeoutExpired:
            check_interrupt()


# ---------------------------------------------------------------------------
# Main phase


def _evidence_run_dir(
    root: pathlib.Path, phase: str, name: str
) -> EvidenceDirectory:
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    expected_uid = 0 if os.geteuid() == 0 else os.geteuid()
    root_fd = rootfs.open_directory(
        root, create=True, mode=0o700, expected_uid=expected_uid
    )
    try:
        run_name = f"{phase}-{stamp}-{name}"
        run_fd = rootfs.make_run_directory(
            root_fd, run_name, expected_uid=expected_uid
        )
    finally:
        os.close(root_fd)
    return EvidenceDirectory(fd=run_fd, path=pathlib.Path(root) / run_name)


@dataclasses.dataclass
class LifecycleState:
    qemu_alive: bool = False


@dataclasses.dataclass
class ScanOutcome:
    present: bool
    exitcode: int
    verdict: str | None
    stderr: str
    argv: list[str]
    hashes: dict[str, str]
    problems: list[str]
    report: dict | None


def scan_evidence(
    evidence: EvidenceDirectory,
    *,
    phase: str,
    before: str,
    after: str,
    scanner_path: pathlib.Path,
) -> ScanOutcome:
    """Scan the retained evidence through the real scanner CLI contract.

    Hashes here and the scanner's ``capture_meta`` hashes both cover the exact
    file bytes; the argv file is written indented with a trailing newline, so
    a canonical re-encoding would never match.
    """
    problems: list[str] = []
    hashes: dict[str, str] = {}
    try:
        capture_present = evidence.size(guest.CAPTURE_FILE) > 0
    except (rootfs.PathError, OSError):
        capture_present = False
    if not capture_present:
        return ScanOutcome(
            present=False,
            exitcode=2,
            verdict=None,
            stderr="",
            argv=[],
            hashes={},
            problems=["capture_missing"],
            report=None,
        )
    try:
        hashes = {
            "pcap_sha256": evidence.hash(guest.CAPTURE_FILE),
            "stats_sha256": evidence.hash(guest.CAPTURE_STATS_FILE),
            "capture_argv_sha256": evidence.hash(guest.CAPTURE_ARGV_FILE),
            "policy_sha256": evidence.hash("policy.json"),
        }
    except (rootfs.PathError, OSError) as exc:
        return ScanOutcome(
            present=True,
            exitcode=2,
            verdict=None,
            stderr="",
            argv=[],
            hashes={},
            problems=["scan_report_invalid"],
            report=None,
        )
    scan_argv = [
        sys.executable,
        "-B",
        str(scanner_path),
        "--policy",
        evidence.proc_path("policy.json"),
        "--pcap",
        evidence.proc_path(guest.CAPTURE_FILE),
        "--tcpdump-stats",
        evidence.proc_path(guest.CAPTURE_STATS_FILE),
        "--capture-argv-file",
        evidence.proc_path(guest.CAPTURE_ARGV_FILE),
        "--expect-tunnel",
        PHASE_EXPECTATIONS[phase],
        "--control-before",
        before,
        "--control-after",
        after,
    ]
    scan_exit = 2
    scan_stderr = ""
    try:
        completed = subprocess.run(
            scanner_launch_argv(scan_argv),
            check=False,
            capture_output=True,
            timeout=SCAN_TIMEOUT,
            pass_fds=(evidence.fd,),
        )
        scan_exit = completed.returncode
        evidence.open_new(guest.SCAN_REPORT_FILE, completed.stdout, mode=0o600)
        scan_stderr = completed.stderr[:4096].decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError) as exc:
        scan_exit = 2
        scan_stderr = f"pcapscan failed: {exc.__class__.__name__}"
    try:
        report = json.loads(evidence.read_bytes(guest.SCAN_REPORT_FILE))
    except (rootfs.PathError, OSError, json.JSONDecodeError):
        report = None
        problems.append("scan_report_invalid")
    scan_verdict: str | None = None
    if isinstance(report, dict):
        raw = report.get("verdict")
        scan_verdict = raw if isinstance(raw, str) else None
        expected_exit = {"PASS": 0, "LEAK": 1, "INVALID": 2}.get(
            scan_verdict or ""
        )
        if expected_exit is None or expected_exit != scan_exit:
            problems.append("scan_report_mismatch")
        if report.get("control_before") not in (None, before):
            problems.append("scan_report_mismatch")
        if report.get("control_after") not in (None, after):
            problems.append("scan_report_mismatch")
        capture_meta = report.get("capture_meta")
        if isinstance(capture_meta, dict):
            for field in (
                "source_sha256",
                "stats_sha256",
                "capture_argv_sha256",
                "policy_sha256",
            ):
                declared = capture_meta.get(field)
                expected = hashes[
                    "pcap_sha256" if field == "source_sha256" else field
                ]
                if declared != expected:
                    problems.append("scan_report_mismatch")
        else:
            problems.append("scan_report_mismatch")
    else:
        problems.append("scan_report_invalid")
    try:
        hashes["scan_sha256"] = evidence.hash(guest.SCAN_REPORT_FILE)
        post_hashes = {
            "pcap_sha256": evidence.hash(guest.CAPTURE_FILE),
            "stats_sha256": evidence.hash(guest.CAPTURE_STATS_FILE),
            "capture_argv_sha256": evidence.hash(guest.CAPTURE_ARGV_FILE),
            "policy_sha256": evidence.hash("policy.json"),
        }
    except (rootfs.PathError, OSError):
        post_hashes = {}
        problems.append("scan_report_invalid")
    if post_hashes and post_hashes != {
        key: hashes[key]
        for key in (
            "pcap_sha256",
            "stats_sha256",
            "capture_argv_sha256",
            "policy_sha256",
        )
    }:
        problems.append("scan_report_mismatch")
    return ScanOutcome(
        present=True,
        exitcode=scan_exit,
        verdict=scan_verdict,
        stderr=scan_stderr,
        argv=scan_argv,
        hashes=hashes,
        problems=list(dict.fromkeys(problems)),
        report=report if isinstance(report, dict) else None,
    )


def run_phase(arguments: argparse.Namespace) -> int:
    require_root()
    install_signal_handlers()
    if arguments.phase not in PHASES:
        raise hostcheck.Refusal(f"unknown phase {arguments.phase}")
    name = guest.validate_name(arguments.name)
    if not tsnames.is_test_node(name):
        raise hostcheck.Refusal(
            "name must be a throw-away zz-vprtest-NN-do-not-use label"
        )
    image_id = guest.validate_image_id(arguments.image_id)
    if arguments.duration < 0 or arguments.duration > MAX_PHASE_DURATION:
        raise hostcheck.Refusal(
            f"duration must be in 0..{int(MAX_PHASE_DURATION)} seconds"
        )
    if arguments.capture_size_cap <= 0:
        raise hostcheck.Refusal("capture size cap must be positive")
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
    lifecycle = LifecycleState()

    lock_fd = runlock.acquire(arguments.run_lock)
    try:
        return _run_phase_locked(
            arguments,
            name=name,
            image_id=image_id,
            state=state,
            base=base,
            used_path=used_path,
            lifecycle=lifecycle,
        )
    finally:
        if lifecycle.qemu_alive:
            # Never release admission while a guest that we could not kill and
            # isolate may still be running.  The descriptor stays open; the
            # kernel releases it only when this process exits.
            print(
                "run_phase: QEMU survived shutdown; keeping the run lock held",
                file=sys.stderr,
            )
        else:
            runlock.release(lock_fd)


def _run_phase_locked(
    arguments: argparse.Namespace,
    *,
    name: str,
    image_id: str,
    state: pathlib.Path,
    base: pathlib.Path,
    used_path: pathlib.Path,
    lifecycle: LifecycleState,
) -> int:
    # The single-guest check happens while the global lock is held.
    hostcheck.refuse_if_qemu_running(self_pid=os.getpid())
    try:
        uid, gid = guest.resolve_unprivileged_user(arguments.qemu_user)
    except guest.GeneratorError as exc:
        raise hostcheck.Refusal(str(exc)) from exc
    if os.geteuid() == 0:
        try:
            rootfs.validate_ancestry(base.parent, expected_uid=0)
        except rootfs.PathError as exc:
            raise hostcheck.Refusal(f"base image ancestry is not root-trusted: {exc}") from exc
    base_digest = guest.verify_base_image(base, pathlib.Path(arguments.checksum_manifest))
    check_admission(
        pathlib.Path(arguments.evidence_root),
        int(arguments.capture_size_cap),
        state_root=state.parent,
    )

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
        tap=arguments.tap,
        bridge=arguments.bridge,
        owner_file=arguments.owner_file,
        qemu_user=arguments.qemu_user,
    )

    if os.geteuid() == 0:
        try:
            rootfs.validate_ancestry(used_path.parent, expected_uid=0)
        except rootfs.PathError as exc:
            raise hostcheck.Refusal(
                f"used-nonces ancestry is not root-trusted: {exc}"
            ) from exc
    used = load_used_nonces(used_path)
    pair = fresh_pair(used)
    append_used_nonces(used_path, pair)

    tcpdump = shutil.which(arguments.tcpdump)
    if tcpdump is None:
        raise hostcheck.Refusal("tcpdump is not installed")
    scanner_path = resolve_pcapscan(
        _LEAK_LAB_DIR / "pcapscan.py",
        installed_root=pathlib.Path(arguments.scanner_root),
        allow_repo=bool(arguments.allow_repo_scanner),
    )

    evidence_root = pathlib.Path(arguments.evidence_root)
    try:
        state_real = state.resolve()
        evidence_real = evidence_root.resolve()
    except OSError as exc:
        raise hostcheck.Refusal("cannot resolve the evidence path") from exc
    if evidence_real == state_real or state_real in evidence_real.parents:
        raise hostcheck.Refusal(
            "evidence must live outside the QEMU-owned VM state directory"
        )
    evidence = _evidence_run_dir(evidence_root, arguments.phase, name)
    evidence_dir = evidence.path
    pcap = evidence_dir / guest.CAPTURE_FILE
    stats = evidence_dir / guest.CAPTURE_STATS_FILE
    scan_path = evidence_dir / guest.SCAN_REPORT_FILE
    qemu_log = evidence_dir / guest.QEMU_LOG_FILE
    evidence.write_json("policy.json", lab_policy.to_dict())
    policy_path = evidence_dir / "policy.json"

    record = base_phase_record(
        phase=arguments.phase,
        name=name,
        state=state,
        evidence_dir=evidence_dir,
        image_id=image_id,
    )
    record["certifies"] = CERTIFICATION
    scanner_root = pathlib.Path(arguments.scanner_root)
    installed = str(scanner_path).startswith(str(scanner_root) + os.sep)
    record["scanner"] = {
        "path": str(scanner_path),
        "source": "installed" if installed else "repo_override",
        "certifiable": bool(installed),
    }
    if installed:
        try:
            record["scanner"]["manifest_sha256"] = sha256_file(
                scanner_root / "SHA256SUMS"
            )
        except OSError:
            record["scanner"]["manifest_sha256"] = None
    record["nonces"]["before"] = pair["before"]
    record["nonces"]["after"] = pair["after"]
    record["nonces"]["used_nonces_file"] = str(used_path)
    record["nonces"]["reserved"] = True
    record["policy"] = {
        "path": str(policy_path),
        "sha256": evidence.hash("policy.json"),
        "allowed": [flow.to_dict() for flow in lab_policy.allowed],
        "positive_control": lab_policy.positive_control.to_dict(),
        "allow_arp": lab_policy.allow_arp,
        "gateway_mac": lab_policy.gateway_mac,
    }
    record["base_image"] = str(base)
    record["base_image_sha512"] = base_digest
    record["qemu_log"] = str(qemu_log)
    record["capture_size_cap"] = int(arguments.capture_size_cap)
    boot_control_phase = arguments.phase == "reboot-with-router-enabled"

    capture: Capture | None = None
    capture_guard: CaptureGuard | None = None
    qemu_process: subprocess.Popen | None = None
    client: QGAClient | None = None
    errors: list[str] = []
    after_control_sent = False
    started = time.monotonic()
    record["timestamps"]["started_at"] = utc_now()

    def note(reason: str) -> None:
        if reason not in errors:
            errors.append(reason)

    def guard_check() -> None:
        if capture_guard is not None:
            capture_guard.raise_if_exceeded()

    try:
        # Start the watcher before tcpdump so the 15 s readiness window is
        # already inside the bound; measure() tolerates the missing file.
        capture_guard = CaptureGuard(
            evidence.fd, pcap.name, int(arguments.capture_size_cap)
        )
        capture_guard.start()
        capture = start_capture(
            arguments.tap, pcap, stats, tcpdump=tcpdump, evidence_fd=evidence.fd,
            file_size_limit=int(arguments.capture_size_cap) + CAPTURE_FSIZE_MARGIN,
        )
        capture_guard.attach_capture(capture.process)
        record["tcpdump_argv"] = capture.argv
        record["tcpdump_argv_display"] = display_argv(capture.argv, evidence)
        record["timestamps"]["capture_started"] = utc_now()
        evidence.write_json(guest.CAPTURE_ARGV_FILE, capture.argv)
        guard_check()

        qemu_log_fd = evidence.open_append(guest.QEMU_LOG_FILE)
        try:
            qemu_process, qemu_argv, launch_argv = start_vm(
                state,
                name=name,
                tap=arguments.tap,
                qemu_user=arguments.qemu_user,
                uid=uid,
                gid=gid,
                log_fd=qemu_log_fd,
            )
        finally:
            os.close(qemu_log_fd)
        capture_guard.attach_qemu(qemu_process)
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
        guard_check()
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
        guard_check()
        verify_guest_image(client, image_id)
        record["guest"]["image_verified"] = True
        guard_check()

        wan_device = resolve_wan_device(client)
        record["guest"]["wan_device"] = wan_device
        secrets_paths = prepare_vm_secrets(client, name, profile, image_id)
        record["guest"].update(secrets_paths)
        guard_check()

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
                wait_router_ready(client, name, require_tailscale=True)
                record["setup"]["active"] = True
            except hostcheck.Refusal as exc:
                record["setup"]["active"] = False
                record_readiness_refusal(record, client, name, exc)
                note("router_not_ready")
                boot_setup_ok = False
            if record["postcondition"]["exitcode"] != 0:
                note("postcondition_failed")
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

        guard_check()
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
                    wait_router_ready(
                        client,
                        name,
                        require_tailscale=arguments.phase != "login",
                    )
                    record["setup"]["active"] = True
                except hostcheck.Refusal as exc:
                    record["setup"]["active"] = False
                    record_readiness_refusal(record, client, name, exc)
                    note("router_not_ready")
                    setup_ok = False
                else:
                    record_tailscale_state(record, client, name)

        guard_check()
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
                wg0_before = None
                if arguments.phase == "restart-docker":
                    try:
                        docker_pid_before = read_docker_pid(client)
                    except hostcheck.Refusal:
                        note("postcondition_failed")
                        action_ok = False
                if arguments.phase == "kill-wireguard" and action_ok:
                    before = read_wg0_state(client, name)
                    if before["status"] == "present" and before["ifindex"] is not None:
                        wg0_before = before["ifindex"]
                        record["preconditions"] = {
                            "wg0_ifindex": wg0_before,
                            "container_running": True,
                        }
                    else:
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
                            wait_router_ready(client, name, require_tailscale=False)
                        except hostcheck.Refusal:
                            note("router_not_ready")
                            action_ok = False
                        else:
                            record["setup"]["active"] = True
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
                            wait_router_ready(client, name, require_tailscale=True)
                        except hostcheck.Refusal:
                            note("postcondition_failed")
                            action_ok = False
                    elif arguments.phase == "kill-wireguard" and wg0_before is not None:
                        proof = check_kill_wireguard(
                            client, name, before_ifindex=wg0_before
                        )
                        record["postcondition"] = {
                            "command": wg0_state_command(name),
                            "exitcode": 0 if proof["ok"] else 1,
                            **proof,
                        }
                        if not proof["ok"]:
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

        guard_check()
        if action_ok:
            if arguments.phase == "login":
                login_phase_wait(
                    client,
                    name=name,
                    duration=arguments.duration,
                    evidence=evidence,
                    record=record,
                    guard=capture_guard,
                    note=note,
                )
                record_tailscale_state(record, client, name)
                if record["tailscale"]["backend_state"] != "Running":
                    note("login_not_running")
            elif capture_guard is not None:
                capture_guard.sleep(arguments.duration)
            else:
                wait_capture_room(
                    pcap, arguments.duration, int(arguments.capture_size_cap)
                )
            if arguments.phase == "kill-wireguard":
                record["recovery"] = read_wg0_state(client, name)

        record["controls"]["after_exitcode"] = emit_control(
            client, pair["after"], lab_policy, wan_device
        )
        record["controls"]["after_transport"] = "qga"
        record["timestamps"]["after_control"] = utc_now()
        after_control_sent = True
    except CaptureCapExceeded as exc:
        note(str(exc) or "capture_size_cap")
    except BaseException as exc:  # noqa: BLE001 - every failure is recorded as INVALID
        record["error_class"] = exc.__class__.__name__
        note(f"phase_exception:{exc.__class__.__name__}")
    finally:
        record["timestamps"]["finally_entered"] = utc_now()

        def note_capture_guard() -> None:
            if capture_guard is None:
                return
            reason = capture_guard.check()
            if reason is not None:
                note(reason)
            if capture_guard.isolation_error is not None:
                record["tap_isolation_error"] = capture_guard.isolation_error
                note("tap_isolation_failed")
            if capture_guard.kill_error is not None:
                record["capture_guard_kill_error"] = capture_guard.kill_error
                note("capture_guard_kill_failed")
            if capture_guard.capture_ended_early_at is not None:
                record["capture_ended_early_at"] = (
                    capture_guard.capture_ended_early_at
                )

        note_capture_guard()
        # 1. AFTER control was sent above.  Stop/disable the router and the
        #    reboot units while the capture is still alive.
        if client is not None:
            try:
                cleanup_guest_units(client, name)
                record["cleanup"]["services"] = "ok"
            except BaseException as exc:  # noqa: BLE001 - one step must not skip the rest
                record["cleanup"]["services"] = exc.__class__.__name__
                note("cleanup_failed")
        # 2. Guest poweroff.  A timeout, an exception or a termination signal
        #    falls back to a verified SIGKILL, then tap isolation; the run lock
        #    is retained if QEMU survives both.
        record["timestamps"]["vm_poweroff_started"] = utc_now()
        try:
            status, forced, survived = poweroff_vm(
                client, qemu_process, state=state, tap=arguments.tap
            )
        except BaseException as exc:  # noqa: BLE001
            record["poweroff_error"] = exc.__class__.__name__
            status, forced = None, True
            survived = qemu_process is not None and qemu_process.poll() is None
            if survived and qemu_process is not None:
                if kill_qemu(qemu_process, state):
                    survived = False
                    status = qemu_process.poll()
                else:
                    try:
                        isolate_tap(arguments.tap)
                    except BaseException:  # noqa: BLE001
                        pass
        client = None
        record["qemu_exit_status"] = status
        record["timestamps"]["vm_finished_at"] = utc_now()
        if forced:
            note("forced_poweroff")
        elif status not in (0, None):
            note("qemu_exit_status")
        if survived:
            note("qemu_still_running")
            record["qemu_survived"] = True
            lifecycle.qemu_alive = True
            try:
                isolate_tap(arguments.tap)
                record["tap_isolated"] = True
            except BaseException as exc:  # noqa: BLE001
                record["tap_isolation_error"] = exc.__class__.__name__
                note("tap_isolation_failed")
        note_capture_guard()
        # 3. Verify the AFTER marker reached the pcap before stopping tcpdump.
        if after_control_sent and capture is not None:
            try:
                arrived = wait_for_control_in_pcap(
                    capture.pcap,
                    pair["after"],
                    evidence_fd=evidence.fd,
                    name=capture.pcap.name,
                )
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
            # tcpdump must still be alive now that QEMU has exited and after
            # the quiet drain.  An early exit means the shutdown tail was not
            # observed, even if the counters and controls otherwise parse.
            try:
                capture_alive = capture.process.poll() is None
            except BaseException:  # noqa: BLE001
                capture_alive = False
            record["capture_alive_before_stop"] = capture_alive
            if not capture_alive:
                record["capture_ended_early"] = True
                if capture_guard is not None and capture_guard.capture_ended_early_at:
                    record["capture_ended_early_at"] = (
                        capture_guard.capture_ended_early_at
                    )
                note("capture_ended_early")
            if capture_guard is not None:
                capture_guard.mark_capture_stopping()
            try:
                record["tcpdump_exit_status"] = stop_capture(
                    capture, evidence_fd=evidence.fd
                )
                record["tcpdump_forced_stop"] = bool(
                    getattr(capture, "forced_stop", False)
                )
                record["timestamps"]["capture_stopped"] = utc_now()
            except BaseException as exc:  # noqa: BLE001
                record["tcpdump_exit_status"] = None
                record["capture_stop_error"] = exc.__class__.__name__
                note("capture_stop_failed")
            capture = None
        if capture_guard is not None:
            try:
                capture_guard.stop()
            except BaseException as exc:  # noqa: BLE001
                record["capture_guard_error"] = exc.__class__.__name__
                note("capture_guard_failed")
            note_capture_guard()
        if record.get("tcpdump_exit_status") not in (0, None):
            note("tcpdump_exit_status")
        record["errors"] = list(errors)

    # Scan even after a failed phase: missing controls and truncated windows
    # are pcapscan's INVALID, not a reason to suppress the capture.
    outcome = scan_evidence(
        evidence,
        phase=arguments.phase,
        before=pair["before"],
        after=pair["after"],
        scanner_path=scanner_path,
    )
    if outcome.present:
        record["pcapscan_argv"] = outcome.argv
        record["pcapscan_argv_display"] = display_argv(outcome.argv, evidence)
        record["scan"]["exitcode"] = outcome.exitcode
        record["scan"]["stderr"] = outcome.stderr
        record["scan"]["verdict"] = outcome.verdict
        record["hashes"].update(outcome.hashes)
    for problem in outcome.problems:
        note(problem)

    scan_exit = outcome.exitcode
    scan_verdict = outcome.verdict
    record["hashes"]["policy_sha256"] = record["policy"]["sha256"]
    record["durations"]["phase_seconds"] = round(time.monotonic() - started, 3)
    record["timestamps"]["scan_finished"] = utc_now()

    # The effective phase result is unambiguous.  Only a parseable report that
    # itself says LEAK may produce LEAK; a scanner crash (missing/invalid
    # report, exit 1) is INVALID even though it fails closed.
    if scan_verdict == "LEAK" and outcome.report is not None:
        final_result = "LEAK"
        final_exit = 1
    elif errors:
        final_result = "INVALID"
        final_exit = 2
    else:
        final_result = (
            "PASS"
            if scan_exit == 0 and scan_verdict == "PASS"
            else "INVALID"
        )
        final_exit = 0 if final_result == "PASS" else 2
    record["result"] = final_result
    record["result_reason"] = "; ".join(errors) if errors else None
    record["errors"] = list(errors)
    try:
        evidence.write_json(guest.PHASE_RECORD_FILE, record)
    finally:
        evidence.close()

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
    parser.add_argument(
        "--capture-size-cap",
        type=int,
        default=DEFAULT_CAPTURE_SIZE_CAP,
        help=(
            "watchdog bound for the whole capture lifetime: above this many "
            "pcap bytes the tap is isolated immediately and the phase is "
            "INVALID (capture_size_cap)"
        ),
    )
    parser.add_argument("--run-lock", default=str(runlock.RUN_LOCK))
    parser.add_argument("--owner-file", default=str(hostcheck.OWNER_FILE))
    parser.add_argument(
        "--scanner-root",
        default=str(INSTALLED_LEAKLAB),
        help=(
            "root-owned leak-lab module copy installed by hostsetup.py; its "
            "SHA256SUMS manifest is verified before the scanner is executed"
        ),
    )
    parser.add_argument(
        "--allow-repo-scanner",
        action="store_true",
        help=(
            "explicit developer override: allow the working-tree pcapscan.py "
            "when the installed copy is missing or differs from the repository"
        ),
    )
    arguments = parser.parse_args(argv)
    install_signal_handlers()
    try:
        set_runner_limits()
    except (OSError, ValueError) as exc:
        print(f"run_phase: cannot set the runner memory limit: {exc}", file=sys.stderr)
        return 2
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
