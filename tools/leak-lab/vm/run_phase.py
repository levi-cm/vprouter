#!/usr/bin/env python3
"""Run one external leak-lab phase against the provisioned vprlab VM.

Execute as root on debdev:

    python3 -B tools/leak-lab/vm/run_phase.py \
        --phase start-router --duration 120 \
        --profile-file /root/vprouter-lab.conf \
        --used-nonces /root/leaklab-used-nonces.txt --index 1

M3 adds ``--client N``: a second, 256 MiB client VM on its own ``vprlab1``
bridge sends traffic through the router's test exit node while the router
phase runs.  ``--phase client-login --client N`` boots only the client for an
interactive login.  The router-only argv, capture, evidence and verdict paths
are unchanged.

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
import math
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
import clientprobe  # noqa: E402
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
    "client-login",
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
    "client-login": "up",
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
#: One client VM adds its 256 MiB to the router + headroom admission floor.
CLIENT_MEMORY_MIB = guest.CLIENT_MEMORY_MIB
MIN_CLIENT_MEMORY_AVAILABLE = MIN_MEMORY_AVAILABLE + CLIENT_MEMORY_MIB * guest.MIB
CLIENT_ROUTED_TIMEOUT = 90.0
CLIENT_READY_TIMEOUT = 180.0
#: A client phase must hold long enough for the probe loop to be observed
#: across more than one host-sampled window.
MIN_CLIENT_HOLD_SECONDS = 30
#: Host-observed coverage (controller decisions 2 and fix-round-4 1/2).  The
#: hold is split into equal windows no longer than this target, so every
#: window stays below clientprobe.MAX_HOLD_SAMPLE_WINDOW (15 s) including the
#: size-read latency ...
CLIENT_HOLD_SAMPLE_TARGET = 14.0
#: ... and no shorter than this, so every window is longer than the traffic
#: loop's worst-case exit spacing (`curl -m 4` marker probe + 3 s sleep +
#: `curl -m 4` exit probe, about 11 s; at most 12 s with the 4.5 s subprocess
#: backstop).  A requested hold for which no equal split fits both bounds is
#: extended (never shortened) to the next whole second that does.
CLIENT_HOLD_SAMPLE_MIN = 12.0
#: The deadline sample (S_end) is started this long before the hold deadline
#: and must finish its size read by the deadline (GPT R4-I1).
CLIENT_HOLD_END_MARGIN = clientprobe.HOLD_END_MARGIN
#: While the fault action and its postcondition run, a helper thread samples
#: the client log this often (start to start), on the host monotonic clock.
#: S_fault is taken at the next point of the same cadence after the action.
CLIENT_ACTION_SAMPLE_INTERVAL = 13.0
#: Bound on joining the action sampler: one sample is at most four QGA execs
#: (15 + 30 + 30 + 20 s).  A sampler that is still alive after this owns the
#: client QGA socket; the runner then never touches that socket again.
CLIENT_SAMPLER_JOIN_TIMEOUT = 180.0
#: The router peer is looked up in the client's netmap until it appears.
CLIENT_PEER_TIMEOUT = 60.0
#: Writer quiescence after a proven stop (controller decision 3, Opus R4
#: M-1): two trusted size reads at least this far apart must agree.  Longer
#: than one worst-case probe loop, so a surviving writer must append.
CLIENT_STOP_QUIESCENCE_SECONDS = 12.0
#: The traffic unit may outlive the hold by this margin; RuntimeMaxSec must
#: cover the pre-fault wait, the fault action, a possible reboot, the hold and
#: this margin.  The runner still stops the unit explicitly.
CLIENT_TRAFFIC_RUNTIME_MARGIN = 600
CLIENT_REBOOT_ALLOWANCE = int(
    QGA_BOOT_TIMEOUT + ROUTER_ACTIVE_TIMEOUT + ROUTER_HANDSHAKE_TIMEOUT
)
CLIENT_PROBE_READ_LIMIT = 1024 * 1024
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


def append_used_nonces(
    path: pathlib.Path,
    nonces: dict[str, str],
    *,
    extra: tuple[str, ...] = (),
) -> None:
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
        values = [nonces[role] for role in ("before", "after")] + list(extra)
        payload = "".join(f"{value}\n" for value in values)
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


def emit_client_control(
    client: QGAClient, nonce: str, client_index: int, device: str
) -> int | None:
    """Send one client positive control to the client bridge gateway sink."""
    command = control_mod.build_command(
        nonce,
        device,
        guest.client_ipv4(client_index),
        guest.CLIENT_GATEWAY_IPV4,
        SINK_UDP_PORT,
    )
    result = client.execute("/bin/sh", ["-c", command], timeout=30.0)
    if result.exitcode != 0:
        raise hostcheck.Refusal("client positive control did not exit zero")
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
            ["-c", f"docker exec {shlex.quote(name)} head -c 4096 /run/vprouter-health.json"],
            timeout=15.0,
        )
        document = json.loads(result.stdout.decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001 - diagnostics only
        document = None
    if isinstance(document, dict):
        state = document.get("state")
        readiness["release_health_state"] = (
            state
            if isinstance(state, str)
            and state in {"STARTING", "BLOCKED", "RECOVERING", "READY"}
            else "unrecognized"
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
    client_login: bool = False,
    stop_when_running: bool = False,
) -> None:
    """Poll the login URL through the runner's own QGA connection.

    ``client_login`` reads the native client tailscaled status/journal instead
    of the router container.  ``stop_when_running`` also polls the client's
    ``BackendState`` and returns as soon as an interactive login completed
    (the transient ``tailscale up`` unit exits on its own).
    """
    url_path = evidence.path / "login-url.txt"
    deadline = time.monotonic() + duration
    found: str | None = None
    while True:
        check_interrupt()
        if guard is not None:
            guard.raise_if_exceeded()
        try:
            if client_login:
                url, unrecognized = login_url_mod.find_client_login_url_result(client)
            else:
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
        if stop_when_running and client_login:
            document = read_client_status(client)
            if isinstance(document, dict) and document.get("BackendState") == "Running":
                break
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
    client_memory_mib: int = 0,
    capture_count: int = 1,
    client_overlay: bool = False,
    router_overlay: bool = True,
) -> None:
    """Refuse to boot a guest without host memory and disk headroom.

    The evidence filesystem must hold every planned capture cap plus 1 GiB.
    The state filesystem must hold the router's 4 GiB overlay (unless the
    caller runs no router VM), the client's 2 GiB overlay when a client VM
    runs, plus the same 1 GiB headroom; a guest can fill its own disk without
    sending a single packet.  ``client_memory_mib`` adds the second (client)
    VM's memory to the admission floor.
    """
    available = read_mem_available() if mem_available is None else mem_available
    required_memory = MIN_MEMORY_AVAILABLE + max(0, int(client_memory_mib)) * guest.MIB
    if available < required_memory:
        raise hostcheck.Refusal(
            "host MemAvailable is below "
            f"{required_memory // (1024 * 1024)} MiB; refusing to boot"
        )
    if free_bytes is None:
        free_bytes = _free_bytes(evidence_root)
    captures = max(0, int(capture_count))
    required = int(capture_size_cap) * captures + DISK_HEADROOM
    if free_bytes < required:
        raise hostcheck.Refusal(
            "free disk is below "
            f"{captures} capture cap(s) plus {DISK_HEADROOM // (1024 * 1024)} MiB"
        )
    if state_root is not None or state_free_bytes is not None:
        if state_free_bytes is None:
            state_free_bytes = _free_bytes(state_root)
        state_required = DISK_HEADROOM
        if router_overlay:
            state_required += OVERLAY_VIRTUAL_SIZE
        if client_overlay:
            state_required += guest.CLIENT_OVERLAY_VIRTUAL_SIZE
        if state_free_bytes < state_required:
            raise hostcheck.Refusal(
                "free space on the state filesystem is below the "
                f"{state_required // (1024 * 1024)} MiB overlay reservation"
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
        self.capture_processes: list = (
            [capture_process] if capture_process is not None else []
        )
        self.qemu_processes: list = (
            [qemu_process] if qemu_process is not None else []
        )
        self.capture_ended_early_at: str | None = None
        self._stopping_capture = False
        self._descriptor: int | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def attach_capture(self, process) -> None:
        self.capture_process = process
        if process is not None and process not in self.capture_processes:
            self.capture_processes.append(process)

    def attach_qemu(self, process) -> None:
        self.qemu_process = process
        if process is not None and process not in self.qemu_processes:
            self.qemu_processes.append(process)

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
        if reason in ("capture_size_cap", "capture_disk_low"):
            for process in self.qemu_processes:
                try:
                    kill_qemu(process)
                except BaseException as exc:  # noqa: BLE001
                    self.kill_error = exc.__class__.__name__

    def _capture_liveness(self) -> str | None:
        if not self.capture_processes or self._stopping_capture:
            return None
        for process in self.capture_processes:
            try:
                status = process.poll()
            except BaseException:  # noqa: BLE001 - a broken handle is not liveness
                continue
            if status is not None:
                if self.capture_ended_early_at is None:
                    self.capture_ended_early_at = utc_now()
                return "capture_ended_early"
        return None

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
    client_index: int | None = None,
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
    if client_index is not None:
        tap_name = guest.client_tap(client_index)
        problems += hostcheck.verify_client_network(
            links,
            neighbors,
            addresses_document=addresses,
            owner_token=token,
            taps={tap_name: (guest.client_ipv4(client_index), guest.client_mac(client_index))},
            tap_user=qemu_user,
        )
    if problems:
        raise hostcheck.Refusal("; ".join(problems))


def verify_state(
    state: pathlib.Path,
    *,
    qemu_uid: int,
    base: pathlib.Path,
    qemu_gid: int | None = None,
    max_virtual_size: int | None = None,
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
    if max_virtual_size is not None:
        top = document[0] if isinstance(document, list) and document else None
        size = top.get("virtual-size") if isinstance(top, dict) else None
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or size <= 0
            or size > max_virtual_size
        ):
            raise hostcheck.Refusal(
                "state overlay virtual size exceeds the client limit"
            )


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
    memory_mib: int = 512,
    mac: str = guest.VM_MAC,
) -> tuple[subprocess.Popen, list[str], list[str]]:
    if (log_path is None) == (log_fd is None):
        raise hostcheck.Refusal("exactly one of log_path and log_fd is required")
    for stale in (guest.PID_FILE, guest.QGA_SOCKET):
        try:
            (state / stale).unlink()
        except OSError:
            pass
    qemu_argv = guest.build_qemu_argv(
        "test", state, name=name, tap=tap, memory_mib=memory_mib, mac=mac
    )
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


# ---------------------------------------------------------------------------
# M3 client helpers


def client_status_command() -> str:
    return f"{guest.CLIENT_TAILSCALE} status --json 2>/dev/null || true"


def read_client_status(client: QGAClient) -> dict | None:
    result = client.execute("/bin/sh", ["-c", client_status_command()], timeout=20.0)
    try:
        document = json.loads(result.stdout.decode("utf-8", "replace"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return document if isinstance(document, dict) else None


def _dns_label(document: dict) -> str | None:
    node = document.get("Self")
    if not isinstance(node, dict):
        return None
    dns_name = node.get("DNSName")
    if isinstance(dns_name, str) and dns_name:
        return dns_name.split(".", 1)[0]
    return None


def client_identity_problems(document: dict, expected_name: str) -> list[str]:
    """Require the client's own identity to be exactly the expected label.

    ``Self.HostName`` is authoritative when present.  A present but different
    value is refused; there is no DNS fallback that could hide a conflicting
    hostname.  A DNSName that disagrees is refused as well.  Only a missing
    HostName falls back to the DNSName label.
    """
    if not isinstance(document, dict):
        return ["the client status is unavailable"]
    node = document.get("Self")
    if not isinstance(node, dict):
        return ["the client status has no Self node"]
    problems: list[str] = []
    hostname = node.get("HostName")
    label = _dns_label(document)
    if isinstance(hostname, str):
        if hostname != expected_name:
            problems.append("the client name is not the expected client label")
        if label is not None and label != expected_name:
            problems.append("the client DNS name disagrees with the expected label")
    elif "HostName" in node:
        # A present but non-string HostName is malformed, never a fallback to
        # a valid DNS label.
        problems.append("the client name is not the expected client label")
    elif label is not None:
        if label != expected_name:
            problems.append("the client name is not the expected client label")
    else:
        problems.append("the client name is unavailable")
    return problems


def _default_route_present(node: dict) -> bool:
    for field in ("PrimaryRoutes", "AllowedIPs"):
        routes = node.get(field)
        if not isinstance(routes, list):
            continue
        for route in routes:
            if isinstance(route, str) and route in ("0.0.0.0/0", "::/0"):
                return True
    return False


def client_readiness_problems(
    document: object, expected_name: str
) -> list[str]:
    """Return fixed-string problems for a client status document."""
    if not isinstance(document, dict):
        return ["client status is unavailable"]
    problems: list[str] = []
    if document.get("BackendState") != "Running":
        problems.append("the client Tailscale backend is not Running")
    problems.extend(client_identity_problems(document, expected_name))
    node = document.get("Self")
    if isinstance(node, dict):
        # ExitNodeOption is the field `tailscale status --json` emits to say
        # this node offers itself as an exit node.  Self.ExitNode is the
        # node's own role flag as well; either set makes it an exit node.
        if node.get("ExitNodeOption") is True or node.get("ExitNode") is True:
            problems.append("the client advertises an exit node")
        if _default_route_present(node):
            problems.append("the client advertises a default route")
    return problems


def read_client_prefs(client: QGAClient) -> dict | None:
    """Read ``tailscale debug prefs``; the result is host-side only."""
    result = client.execute(
        "/bin/sh",
        ["-c", f"{guest.CLIENT_TAILSCALE} debug prefs 2>/dev/null || true"],
        timeout=20.0,
    )
    try:
        document = json.loads(result.stdout.decode("utf-8", "replace"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return document if isinstance(document, dict) else None


def client_route_advertisement_problem(document: object) -> str | None:
    """Return a fixed code unless the client prefs keep the client role.

    ``tailscale debug prefs`` is authoritative for persisted preferences:

    * ``AdvertiseRoutes`` must be present and empty (``[]``, or JSON ``null``,
      which is how Go encodes an empty slice); a missing key is a refusal
      (Pi R3-M5), any route is ``client_advertises_routes``;
    * ``RouteAll`` must be exactly ``false`` (``--accept-routes=false``) and
      ``ShieldsUp`` exactly ``true`` (``--shields-up``; Opus R3-4);
    * ``CorpDNS`` must be exactly ``false`` (``--accept-dns=false``; Opus B
      L-1).  With MagicDNS accepted, tailscaled rewrites ``/etc/resolv.conf``
      and the client silence check refuses every later boot.
    """
    if not isinstance(document, dict):
        return "client_prefs_unreadable"
    if "AdvertiseRoutes" not in document:
        return "client_prefs_incomplete"
    routes = document.get("AdvertiseRoutes")
    if routes is not None and not (isinstance(routes, list) and not routes):
        return "client_advertises_routes"
    if "RouteAll" not in document or "ShieldsUp" not in document:
        return "client_prefs_incomplete"
    if document.get("RouteAll") is not False:
        return "client_accepts_routes"
    if document.get("ShieldsUp") is not True:
        return "client_shields_down"
    if "CorpDNS" not in document:
        return "client_prefs_incomplete"
    if document.get("CorpDNS") is not False:
        return "client_accepts_dns"
    return None


def wait_client_running(
    client: QGAClient,
    expected_name: str,
    *,
    timeout: float | None = None,
) -> dict:
    if timeout is None:
        timeout = CLIENT_READY_TIMEOUT
    deadline = time.monotonic() + timeout
    last = "client status is unavailable"
    while time.monotonic() < deadline:
        check_interrupt()
        document = read_client_status(client)
        problems = client_readiness_problems(document, expected_name)
        if not problems:
            return document
        # Name/exit-node advertising are role violations, not startup delays.
        for problem in problems:
            if problem in (
                "the client name is not the expected client label",
                "the client DNS name disagrees with the expected label",
                "the client name is unavailable",
                "the client advertises an exit node",
                "the client advertises a default route",
            ):
                raise hostcheck.Refusal(problem)
        last = "; ".join(problems)
        time.sleep(1.0)
    raise hostcheck.Refusal(f"the client did not become ready ({last})")


def router_exit_identity(document: object) -> tuple[str, list[str]]:
    """Return the router's own ``Self.ID`` and IPv4 addresses.

    This is read from the router VM's own ``tailscale status --json`` through
    QGA.  The client must then select exactly that peer; a HostName alone is
    never sufficient.
    """
    if not isinstance(document, dict):
        raise hostcheck.Refusal("the router Tailscale status is unavailable")
    node = document.get("Self")
    if not isinstance(node, dict):
        raise hostcheck.Refusal("the router Tailscale status has no Self node")
    node_id = node.get("ID")
    if not isinstance(node_id, str) or not node_id:
        raise hostcheck.Refusal("the router Tailscale status has no Self.ID")
    addresses: list[str] = []
    values = node.get("TailscaleIPs")
    if isinstance(values, list):
        for value in values:
            if not isinstance(value, str):
                continue
            try:
                ipaddress.IPv4Address(value)
            except ValueError:
                continue
            addresses.append(value)
    if not addresses:
        raise hostcheck.Refusal("the router has no Tailscale IPv4 address")
    return node_id, addresses


def client_find_router_peer(
    document: object,
    router_name: str,
    router_id: str,
    router_addresses: list[str],
) -> dict | None:
    """Find exactly the router peer and its first matching IPv4 address.

    The peer must be the single peer carrying the router's own ``Self.ID``,
    with the exact test HostName, ``ExitNodeOption`` true and online.  A
    second peer with the same HostName is an ambiguity and refuses the phase.
    The returned document is host-side only and never recorded: the peer's
    Tailscale address is a non-Mullvad IP.
    """
    if not isinstance(document, dict) or not isinstance(router_id, str):
        return None
    peers = document.get("Peer")
    if not isinstance(peers, dict):
        return None
    by_id = [
        peer
        for peer in peers.values()
        if isinstance(peer, dict) and peer.get("ID") == router_id
    ]
    if len(by_id) != 1:
        return None
    peer = by_id[0]
    if peer.get("HostName") != router_name:
        return None
    hostname_collisions = [
        other
        for key, other in peers.items()
        if isinstance(other, dict)
        and other is not peer
        and other.get("HostName") == router_name
    ]
    if hostname_collisions:
        return None
    if peer.get("ExitNodeOption") is not True or peer.get("Online") is not True:
        return None
    expected = set(router_addresses)
    addresses = peer.get("TailscaleIPs")
    if not isinstance(addresses, list):
        return None
    for address in addresses:
        if not isinstance(address, str):
            continue
        try:
            ipaddress.IPv4Address(address)
        except ValueError:
            continue
        if address in expected:
            return peer
    return None


def client_peer_ipv4(peer: dict, expected: list[str] | None = None) -> str:
    allowed = set(expected or ())
    for address in peer.get("TailscaleIPs") or ():
        if not isinstance(address, str):
            continue
        try:
            ipaddress.IPv4Address(address)
        except ValueError:
            continue
        if not allowed or address in allowed:
            return address
    raise hostcheck.Refusal("the router exit-node peer has no expected IPv4 address")


def client_peer_is_active(
    document: object, router_id: str, address: str, *, require_online: bool = True
) -> bool:
    """Require an explicit ExitNodeStatus for the exact router peer.

    There is deliberately no ``Self.ExitNode``/HostName shortcut: only the
    status naming the router's own node ID and the selected address counts.
    ``require_online`` is True for the pre-fault selection.  Hold samples pass
    False: during stop-router, kill-container or kill-wireguard the router's
    Tailscale is legitimately offline, and what a sample must prove is that
    the client still has exactly this router selected (no switch to another
    exit node), not that the router is healthy.
    """
    if not isinstance(document, dict):
        return False
    status = document.get("ExitNodeStatus")
    if not isinstance(status, dict):
        return False
    if status.get("ID") != router_id:
        return False
    if require_online and status.get("Online") is not True:
        return False
    return _exit_status_has_address(status.get("TailscaleIPs"), address)


def _exit_status_has_address(entries: object, address: str) -> bool:
    """True when ``entries`` holds ``address`` as an IPv4 ``/32``.

    ``ExitNodeStatus.TailscaleIPs`` is ``[]netip.Prefix`` in tailscaled, so the
    JSON carries ``"100.x.y.z/32"`` (and an IPv6 ``/128``), unlike the bare
    addresses of ``PeerStatus.TailscaleIPs`` (Opus B B-1).  A bare address is
    accepted as the same ``/32``.  A wider prefix that merely contains the
    address is not the router's address and is refused.
    """
    try:
        wanted = ipaddress.IPv4Address(address)
    except (ipaddress.AddressValueError, ValueError, TypeError):
        return False
    if not isinstance(entries, list):
        return False
    for entry in entries:
        if not isinstance(entry, str):
            continue
        try:
            interface = ipaddress.ip_interface(entry)
        except ValueError:
            continue
        if (
            interface.version == 4
            and interface.network.prefixlen == 32
            and interface.ip == wanted
        ):
            return True
    return False


def wait_client_router_peer(
    client: QGAClient,
    router_name: str,
    router_id: str,
    router_addresses: list[str],
    *,
    timeout: float | None = None,
) -> dict:
    """Poll the client's netmap until it shows exactly the router peer.

    The router has only just become ready; control pushes its online state to
    the client asynchronously, so a single read can lose that race (Opus B
    P-1).  Every read applies the full :func:`client_find_router_peer` rule.
    """
    if timeout is None:
        timeout = CLIENT_PEER_TIMEOUT
    deadline = time.monotonic() + timeout
    while True:
        check_interrupt()
        peer = client_find_router_peer(
            read_client_status(client), router_name, router_id, router_addresses
        )
        if peer is not None:
            return peer
        if time.monotonic() >= deadline:
            raise hostcheck.Refusal("the client cannot see the test exit node")
        time.sleep(1.0)


def set_client_exit_node(client: QGAClient, address: str) -> None:
    try:
        ipaddress.IPv4Address(address)
    except ValueError as exc:
        raise hostcheck.Refusal("the exit node address is not IPv4") from exc
    command = (
        f"{guest.CLIENT_TAILSCALE} set --exit-node={shlex.quote(address)} "
        "--exit-node-allow-lan-access=false"
    )
    result = client.execute("/bin/sh", ["-c", command], timeout=60.0)
    if result.exitcode != 0:
        raise hostcheck.Refusal("cannot set the client exit node")


def clear_client_exit_node(client: QGAClient) -> None:
    result = client.execute(
        "/bin/sh",
        ["-c", f"{guest.CLIENT_TAILSCALE} set --exit-node="],
        timeout=60.0,
    )
    if result.exitcode != 0:
        raise hostcheck.Refusal("cannot clear the client exit node")


def wait_client_exit_node(
    client: QGAClient,
    router_id: str,
    address: str,
    *,
    timeout: float | None = None,
) -> dict:
    if timeout is None:
        timeout = CLIENT_READY_TIMEOUT
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        check_interrupt()
        document = read_client_status(client)
        if client_peer_is_active(document, router_id, address):
            return document
        time.sleep(1.0)
    raise hostcheck.Refusal("the client did not report the test exit node as active")


def client_exit_node_cleared(document: object) -> bool:
    if not isinstance(document, dict):
        return False
    if isinstance(document.get("ExitNodeStatus"), dict):
        return False
    node = document.get("Self")
    if isinstance(node, dict):
        if node.get("ExitNode") is True:
            return False
        value = node.get("ExitNode")
        if isinstance(value, str) and value:
            return False
    return True


def wait_client_exit_cleared(
    client: QGAClient, *, timeout: float | None = None
) -> None:
    """Wait until no exit node is selected, after tailscaled is running."""
    if timeout is None:
        timeout = CLIENT_READY_TIMEOUT
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        check_interrupt()
        if client_exit_node_cleared(read_client_status(client)):
            return
        time.sleep(1.0)
    raise hostcheck.Refusal("the client did not clear its exit node")


def clear_client_probe_log(client: QGAClient) -> None:
    """Delete the probe log before launch and prove it is absent.

    The log is bound to this run; a stale line from a previous phase must never
    be able to satisfy a positive control.
    """
    result = client.execute(
        "/bin/sh",
        [
            "-c",
            f"rm -f {guest.CLIENT_PROBE_LOG}; "
            f"if [ -e {guest.CLIENT_PROBE_LOG} ]; then exit 1; fi",
        ],
        timeout=15.0,
    )
    if result.exitcode != 0:
        raise hostcheck.Refusal("cannot remove the client probe log")


def start_client_traffic(
    client: QGAClient,
    *,
    marker: str,
    https_ip: str,
    http_ip: str,
    runtime_sec: int,
) -> None:
    if not clientprobe.is_marker(marker):
        raise hostcheck.Refusal("the client marker is not VPRCLIENTMARK1:<32 hex>")
    for address in (https_ip, http_ip):
        if not policy_mod.is_ipv4_literal(address):
            raise hostcheck.Refusal("a client probe address is not IPv4")
    if isinstance(runtime_sec, bool) or not isinstance(runtime_sec, int):
        raise hostcheck.Refusal("the client traffic runtime is invalid")
    if runtime_sec <= 0:
        raise hostcheck.Refusal("the client traffic runtime must be positive")
    clear_client_probe_log(client)
    command = (
        f"systemctl reset-failed {guest.CLIENT_TRAFFIC_UNIT} 2>/dev/null || true; "
        f"systemd-run --unit={guest.CLIENT_TRAFFIC_UNIT} "
        f"-p RuntimeMaxSec={runtime_sec} "
        f"{guest.CLIENT_TRAFFIC_SCRIPT} {shlex.quote(marker)} "
        f"{shlex.quote(https_ip)} {shlex.quote(http_ip)}"
    )
    result = client.execute("/bin/sh", ["-c", command], timeout=60.0)
    if result.exitcode != 0:
        raise hostcheck.Refusal("cannot start the client traffic unit")


def client_traffic_unit_state(client: QGAClient) -> str | None:
    """Return the unit's raw ``systemctl is-active`` word, or None."""
    result = client.execute(
        "/bin/sh",
        ["-c", f"systemctl is-active {guest.CLIENT_TRAFFIC_UNIT}.service"],
        timeout=15.0,
    )
    text = result.stdout.decode("ascii", "replace").strip()
    return text or None


def client_traffic_main_pid(client: QGAClient) -> int | None:
    """Return the unit's ``MainPID`` (0 when no process or no unit), or None."""
    result = client.execute(
        "/bin/sh",
        [
            "-c",
            f"systemctl show -p MainPID --value {guest.CLIENT_TRAFFIC_UNIT}.service",
        ],
        timeout=15.0,
    )
    if result.exitcode != 0:
        return None
    text = result.stdout.decode("ascii", "replace").strip()
    if not text.isdigit():
        return None
    return int(text)


def client_traffic_process_scan_script() -> str:
    """Count live processes whose command line names the traffic script.

    A plain ``/proc`` walk, so it needs no procps in the client.  The pattern
    ends in the bracket expression ``[c]``: the scanning shell's own command
    line contains the text ``...traffi'[c]`` and therefore never matches
    itself, while a running ``python3 /usr/local/sbin/vprlab-client-traffic``
    does.  Unreadable entries (a process that just exited) are skipped.
    """
    path = guest.CLIENT_TRAFFIC_SCRIPT
    head, last = path[:-1], path[-1]
    if not re.fullmatch(r"/[A-Za-z0-9/._-]+", head) or not last.isalnum():
        raise hostcheck.Refusal("the client traffic script path is unexpected")
    return (
        "count=0; "
        "for entry in /proc/[0-9]*; do "
        "[ -r \"$entry/cmdline\" ] || continue; "
        "command=$(tr '\\000' ' ' < \"$entry/cmdline\" 2>/dev/null) || continue; "
        f"case \"$command\" in *'{head}'[{last}]*) count=$((count + 1)) ;; esac; "
        "done; "
        "printf 'TRAFFIC-PROCS:%s\\n' \"$count\""
    )


def client_traffic_process_count(client: QGAClient) -> int | None:
    """Return how many traffic-script processes run in the client, or None."""
    result = client.execute(
        "/bin/sh", ["-c", client_traffic_process_scan_script()], timeout=15.0
    )
    if result.exitcode != 0:
        return None
    text = result.stdout.decode("ascii", "replace").strip()
    match = re.fullmatch(r"TRAFFIC-PROCS:([0-9]{1,6})", text)
    return int(match.group(1)) if match else None


def stop_client_traffic(client: QGAClient) -> bool:
    """Stop the unit and return True only when it is proven not running.

    The stop result is kept, and the postcondition is two separate reads:
    ``systemctl is-active`` must print exactly ``inactive`` or ``failed``
    (``inactive`` is also what it prints for a unit the manager no longer
    knows), and ``systemctl show -p MainPID --value`` must print ``0`` (also
    what it prints for an absent unit).  ``unknown``, ``deactivating``, an
    empty answer or any other word is not proof (Pi R3-M1).  Finally no
    process of the traffic script may remain anywhere in the guest, inside or
    outside the unit's cgroup (Opus R4 M-1).  Writer quiescence is proven
    separately by :func:`client_probe_writer_quiescent` before any snapshot
    is trusted.
    """
    # The stop exit status is deliberately not the proof: `systemctl stop`
    # can return non-zero for an already-gone unit.  The state reads below
    # are authoritative, and they are never skipped.
    client.execute(
        "/bin/sh",
        ["-c", f"systemctl stop {guest.CLIENT_TRAFFIC_UNIT}.service"],
        timeout=60.0,
    )
    # reset-failed only clears the unit's retained failed state; it never
    # changes whether a process runs, and its exit status is not a proof.
    client.execute(
        "/bin/sh",
        ["-c", f"systemctl reset-failed {guest.CLIENT_TRAFFIC_UNIT}.service"],
        timeout=15.0,
    )
    state = client_traffic_unit_state(client)
    if state not in ("inactive", "failed"):
        return False
    if client_traffic_main_pid(client) != 0:
        return False
    return client_traffic_process_count(client) == 0


def stop_client_login_unit(client: QGAClient) -> None:
    """Stop the transient login unit if it is still waiting for a login."""
    client.execute(
        "/bin/sh",
        ["-c", f"systemctl stop {guest.CLIENT_LOGIN_UNIT}.service"],
        timeout=60.0,
    )
    client.execute(
        "/bin/sh",
        ["-c", f"systemctl reset-failed {guest.CLIENT_LOGIN_UNIT}.service"],
        timeout=15.0,
    )


def read_client_probe_size(client: QGAClient) -> int | None:
    """Return the guest-reported log size, or None unless ``stat`` succeeded."""
    result = client.execute(
        "/bin/sh",
        ["-c", f"stat -c %s {guest.CLIENT_PROBE_LOG}"],
        timeout=15.0,
    )
    if result.exitcode != 0:
        return None
    text = result.stdout.decode("ascii", "replace").strip()
    if not text.isdigit():
        return None
    return int(text)


def client_probe_writer_quiescent(client: QGAClient) -> bool:
    """Prove the probe log stopped growing after a proven unit stop.

    Two trusted size reads at least :data:`CLIENT_STOP_QUIESCENCE_SECONDS`
    (12 s, longer than one worst-case probe loop) of host monotonic time apart
    must be equal.  A writer that survived a stop which claimed success makes
    the snapshot untrusted.
    """
    first = read_client_probe_size(client)
    if first is None:
        return False
    due = time.monotonic() + CLIENT_STOP_QUIESCENCE_SECONDS
    while True:
        remaining = due - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(0.25, remaining))
    second = read_client_probe_size(client)
    return second is not None and second == first


_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclasses.dataclass(frozen=True)
class ProbeLogRead:
    """One exact prefix read of the probe log (controller decision 1).

    ``data`` holds whatever bytes arrived, trusted or not, so a well-formed
    LEAK in them is never discarded.  ``problem`` is None exactly when the
    read is trusted: ``stat``, the guest digest and the byte transfer all
    exited 0, ``len(data) == size`` and the host SHA-256 equals the guest's.
    ``stat_start``/``stat_end`` are host monotonic times around the size
    read, which fixes the prefix boundary.
    """

    data: bytes | None
    size: int | None
    sha256: str | None
    problem: str | None
    stat_start: float
    stat_end: float

    @property
    def trusted(self) -> bool:
        return self.problem is None


def read_client_probe_prefix(client: QGAClient) -> ProbeLogRead:
    """Read the first N bytes of the append-only log, N = ``stat -c %s``.

    Three bounded QGA execs: the size, ``head -c N | sha256sum`` and
    ``head -c N``.  The log is append-only after launch, so its first N bytes
    are stable while the unit keeps appending; a short, failed or altered
    transfer cannot match both the length and the guest digest.  This is the
    only read whose bytes the verdict trusts: the pre-fault controls, the
    fault boundary, every hold sample, the deadline sample and the final
    snapshot all use it.
    """
    stat_start = time.monotonic()
    size = read_client_probe_size(client)
    stat_end = time.monotonic()

    def outcome(
        data: bytes | None, digest: str | None, problem: str | None
    ) -> ProbeLogRead:
        return ProbeLogRead(
            data=data,
            size=size,
            sha256=digest,
            problem=problem,
            stat_start=stat_start,
            stat_end=stat_end,
        )

    if size is None:
        return outcome(None, None, "probe_log_missing")
    if size > CLIENT_PROBE_READ_LIMIT:
        return outcome(None, None, "probe_log_oversized")
    if size == 0:
        return outcome(b"", hashlib.sha256(b"").hexdigest(), None)
    digest_result = client.execute(
        "/bin/sh",
        ["-c", f"head -c {size} {guest.CLIENT_PROBE_LOG} | sha256sum"],
        timeout=30.0,
    )
    digest_text = digest_result.stdout.decode("ascii", "replace").strip()
    token = digest_text.split(None, 1)[0] if digest_text else ""
    digest = (
        token
        if digest_result.exitcode == 0 and _SHA256_HEX_RE.fullmatch(token)
        else None
    )
    data_result = client.execute(
        "/bin/sh",
        ["-c", f"head -c {size} {guest.CLIENT_PROBE_LOG}"],
        timeout=30.0,
    )
    data = data_result.stdout
    if len(data) > CLIENT_PROBE_READ_LIMIT:
        return outcome(data[:CLIENT_PROBE_READ_LIMIT], digest, "probe_log_oversized")
    if data_result.exitcode != 0 or digest is None:
        # Bounded bytes are still returned for tolerant LEAK parsing; they
        # are never trusted.
        return outcome(data, digest, "probe_log_unreadable")
    if len(data) != size:
        return outcome(data, digest, "probe_log_truncated")
    if hashlib.sha256(data).hexdigest() != digest:
        return outcome(data, digest, "probe_log_hash_mismatch")
    return outcome(data, digest, None)


def read_client_probe_log(client: QGAClient) -> tuple[bytes | None, str | None]:
    """Prefix read returning ``(bytes, problem)``; problem None iff trusted."""
    read = read_client_probe_prefix(client)
    return read.data, read.problem


def read_client_probe_log_exact(client: QGAClient) -> tuple[bytes | None, str | None]:
    """The final snapshot: a trusted prefix that is non-empty and ends in a newline.

    Only called after the writer was proven stopped and quiescent, so the
    prefix is the whole log.  Received bytes are returned with the problem
    when the read is rejected, so a well-formed leak inside them is never
    masked.
    """
    read = read_client_probe_prefix(client)
    if read.problem is not None:
        return read.data, read.problem
    data = read.data if read.data is not None else b""
    if not data:
        return b"", "probe_log_empty"
    if not data.endswith(b"\n"):
        return data, "probe_log_truncated"
    return data, None


def take_client_probe_sample(
    client: QGAClient, run_id: str, *, base: float | None
) -> tuple[dict[str, Any] | None, ProbeLogRead]:
    """Take one trusted hold sample; an untrusted read yields no sample.

    The sample's sequence numbers come only from complete newline-terminated
    lines of a trusted prefix.  Host times are seconds relative to ``base``
    (the S_fault sample's size read), or to this read when ``base`` is None.
    """
    read = read_client_probe_prefix(client)
    if not read.trusted or read.data is None:
        return None, read
    observation = clientprobe.prefix_observation(read.data, run_id=run_id)
    origin = read.stat_start if base is None else base
    sample = {
        "sequence": observation["sequence"],
        "exit_sequence": observation["exit_sequence"],
        "size": read.size,
        "sha256": read.sha256,
        "stat_start": round(max(0.0, read.stat_start - origin), 3),
        "stat_end": round(max(0.0, read.stat_end - origin), 3),
    }
    return sample, read


@dataclasses.dataclass
class ClientCoverageSample:
    """One coverage sample: the trusted sample (or None) and what it found.

    Built without touching the phase record, so the action sampler thread can
    produce it; the main thread applies it with the same rules in order.
    """

    kind: str
    sample: dict[str, Any] | None
    read: ProbeLogRead
    leak: bool
    problems: list[str]


def take_client_coverage_sample(
    client: QGAClient,
    run_id: str,
    *,
    kind: str,
    base: float | None,
    router_id: str,
    exit_ipv4: str,
) -> ClientCoverageSample:
    """Take one trusted prefix sample and re-check the exit-node selection.

    Controller decisions 1 and 2: only a trusted prefix read can establish a
    sample; an untrusted one is a fixed problem and its bytes are still parsed
    for a LEAK.  The prefix boundary is fixed by the size read, before the
    status call, so nothing written during that call counts for this sample.
    The selection check uses ``require_online=False``: during a fault the
    router may legitimately be offline, but the client must still have
    exactly that router selected.  Only the client's QGA socket is used.
    """
    if kind not in clientprobe.SAMPLE_KINDS:
        raise ValueError("unknown coverage sample kind")
    sample, read = take_client_probe_sample(client, run_id, base=base)
    leak = bool(read.data) and clientprobe.probe_prefix_flags(
        read.data, run_id=run_id
    )["leak"]
    problems: list[str] = []
    if sample is None:
        problems.append(f"probe_{kind}_sample_untrusted")
        if read.problem is not None:
            problems.append(read.problem)
        return ClientCoverageSample(kind, None, read, leak, problems)
    exit_ok = client_peer_is_active(
        read_client_status(client), router_id, exit_ipv4, require_online=False
    )
    sample["kind"] = kind
    sample["exit_node_ok"] = exit_ok
    if not exit_ok:
        problems.append("client_exit_node_lost")
    return ClientCoverageSample(kind, sample, read, leak, problems)


class ClientActionSampler(threading.Thread):
    """Sample the client log while the router fault action runs (Opus R4 I-1).

    The thread only calls ``take`` (which talks to the CLIENT's QGA socket);
    the main thread talks only to the ROUTER's QGA socket until
    :meth:`halt` has joined this thread.  Samples are taken on the host
    monotonic clock, each ``interval`` seconds after the previous sample's
    size read started.  Results are kept here and applied by the main thread
    after the join; the thread never touches the phase record.
    """

    poll_interval = 0.25

    def __init__(self, take, *, first_due: float, interval: float) -> None:
        super().__init__(name="vprlab-client-action-sampler", daemon=True)
        self._take = take
        self._halt = threading.Event()
        self.interval = float(interval)
        self.next_due = float(first_due)
        self.results: list[ClientCoverageSample] = []
        self.failure: str | None = None

    def run(self) -> None:
        try:
            while not self._halt.is_set():
                remaining = self.next_due - time.monotonic()
                if remaining > 0:
                    self._halt.wait(min(self.poll_interval, remaining))
                    continue
                result = self._take()
                self.results.append(result)
                self.next_due = result.read.stat_start + self.interval
        except BaseException as exc:  # noqa: BLE001 - reported by the main thread
            self.failure = exc.__class__.__name__

    def halt(self, timeout: float) -> bool:
        """Stop sampling and join; True only when the thread has ended."""
        self._halt.set()
        if self.ident is not None:
            self.join(timeout)
        return not self.is_alive()


def client_hold_schedule(duration: float) -> tuple[int, int, float]:
    """Return ``(hold_seconds, windows, spacing)`` for a requested hold.

    The deadline sample starts :data:`CLIENT_HOLD_END_MARGIN` before the
    deadline, so ``windows`` equal windows of ``spacing`` seconds cover
    ``hold_seconds - CLIENT_HOLD_END_MARGIN``.  The spacing stays within
    [:data:`CLIENT_HOLD_SAMPLE_MIN`, :data:`CLIENT_HOLD_SAMPLE_TARGET`]; when
    the requested hold has no such split it is extended to the next whole
    second that has one (never shortened).
    """
    requested = int(math.ceil(float(duration)))
    span = requested - CLIENT_HOLD_END_MARGIN
    if span <= 0:
        raise hostcheck.Refusal("the client hold is too short")
    windows = max(1, math.ceil(span / CLIENT_HOLD_SAMPLE_TARGET))
    spacing = span / windows
    hold = requested
    if spacing < CLIENT_HOLD_SAMPLE_MIN:
        hold = int(
            math.ceil(CLIENT_HOLD_END_MARGIN + windows * CLIENT_HOLD_SAMPLE_MIN)
        )
        spacing = (hold - CLIENT_HOLD_END_MARGIN) / windows
    return hold, windows, spacing


def read_guest_mem_available(client: QGAClient) -> int | None:
    """Return the guest's ``MemAvailable`` in bytes, or None (Opus B P-2)."""
    try:
        result = client.execute(
            "/bin/sh",
            ["-c", "grep -m 1 '^MemAvailable:' /proc/meminfo"],
            timeout=15.0,
        )
    except (QGAError, OSError):
        return None
    if result.exitcode != 0:
        return None
    match = re.fullmatch(
        r"MemAvailable:\s+([0-9]{1,12}) kB",
        result.stdout.decode("ascii", "replace").strip(),
    )
    return int(match.group(1)) * 1024 if match else None


def collect_client_probe(
    client: QGAClient,
    evidence: EvidenceDirectory,
    record: dict,
    note,
    *,
    trusted: bool = True,
    run_id: str | None = None,
) -> bytes:
    """Read probe evidence and persist it.

    Called on the success path and again from ``finally`` on every error path
    while the client VM is still up.  A read problem is a fixed reason; the
    evidence file is still created (empty) so the hash field is unambiguous.

    ``trusted=False`` means the writer was not proven stopped at the intended
    snapshot point.  The bytes are still kept for a latched LEAK, but they are
    never labelled exact evidence.  Every persisted read is scanned for a
    current-log non-Mullvad success so the leak flag survives any later
    quality failure.
    """
    if record["client"].get("probe_collected"):
        return evidence.read_bytes(guest.CLIENT_PROBE_FILE)
    if trusted:
        data, problem = read_client_probe_log_exact(client)
    else:
        data, problem = read_client_probe_log(client)
        if problem is None:
            problem = "probe_snapshot_untrusted"
    if problem is not None:
        note(problem)
        if data is None:
            data = b""
    elif trusted:
        record["client"]["probe_log_read"] = "exact"
    if data:
        flags = clientprobe.probe_prefix_flags(data, run_id=run_id)
        if flags["leak"]:
            record["client"]["probe_leak_observed"] = True
    evidence.open_new(guest.CLIENT_PROBE_FILE, data, mode=0o600)
    record["client"]["probe_snapshot_trusted"] = bool(trusted)
    record["client"]["probe_log_sha256"] = evidence.hash(guest.CLIENT_PROBE_FILE)
    record["hashes"]["client_probe_sha256"] = record["client"][
        "probe_log_sha256"
    ]
    record["client"]["probe_collected"] = True
    return data


def resolve_probe_ips(resolver=None) -> dict[str, str]:
    """Resolve the two probe names on the host once per phase.

    Client probes use ``curl --resolve`` with these addresses, so the client
    needs no DNS.  Both must be public IPv4 addresses.
    """
    if resolver is None:
        import socket

        resolver = socket.getaddrinfo
    else:
        import socket
    result: dict[str, str] = {}
    for key, hostname in (("https", "am.i.mullvad.net"), ("http", "example.com")):
        try:
            records = resolver(hostname, 443 if key == "https" else 80, 0, socket.SOCK_STREAM)
        except OSError as exc:
            raise hostcheck.Refusal(f"cannot resolve {hostname}") from exc
        address = None
        for record in records:
            candidate = record[4][0] if len(record) >= 5 else None
            try:
                parsed = ipaddress.IPv4Address(candidate)
            except (ValueError, TypeError):
                continue
            if parsed.is_global:
                address = str(parsed)
                break
        if address is None:
            raise hostcheck.Refusal(f"{hostname} has no public IPv4 address")
        result[key] = address
    return result


def client_runtime_seconds(duration: float) -> int:
    """Cover the whole remaining phase, not just the hold.

    The unit starts before the pre-fault wait and stays up across the fault
    action (including a possible reboot) and the hold.  RuntimeMaxSec is only a
    backstop: the runner stops the unit explicitly.
    """
    value = (
        int(duration)
        + int(CLIENT_ROUTED_TIMEOUT)
        + int(ACTION_TIMEOUT)
        + CLIENT_REBOOT_ALLOWANCE
        + CLIENT_TRAFFIC_RUNTIME_MARGIN
    )
    if value <= 0:
        raise hostcheck.Refusal("client traffic runtime is out of range")
    return value


def client_traffic_unit_active(client: QGAClient) -> bool:
    result = client.execute(
        "/bin/sh",
        ["-c", f"systemctl is-active --quiet {guest.CLIENT_TRAFFIC_UNIT}.service"],
        timeout=15.0,
    )
    return result.exitcode == 0


def wait_client_probe_control(
    client: QGAClient,
    run_id: str,
    *,
    timeout: float | None = None,
) -> dict[str, bool]:
    """Wait for a Mullvad success and a successful marker probe.

    The positive controls come only from trusted prefix reads (complete,
    run-matching lines of a size- and SHA-256-verified prefix; Opus R3-2).
    A non-Mullvad success in any received bytes, trusted or not, is returned
    immediately as a leak; the final collection still runs from ``finally``.
    """
    if timeout is None:
        timeout = CLIENT_ROUTED_TIMEOUT
    deadline = time.monotonic() + timeout
    flags = {"leak": False, "mullvad": False, "marker": False}
    while time.monotonic() < deadline:
        check_interrupt()
        read = read_client_probe_prefix(client)
        if read.data:
            if clientprobe.probe_prefix_flags(read.data, run_id=run_id)["leak"]:
                flags["leak"] = True
                return flags
        if read.trusted and read.data is not None:
            observation = clientprobe.prefix_observation(read.data, run_id=run_id)
            flags["mullvad"] = flags["mullvad"] or observation["mullvad"]
            flags["marker"] = flags["marker"] or observation["marker"]
            if flags["mullvad"] and flags["marker"]:
                return flags
        time.sleep(1.0)
    return flags


def cleanup_client_units(client: QGAClient) -> None:
    """Stop the traffic and login units and clear the exit node."""
    stopped = stop_client_traffic(client)
    stop_client_login_unit(client)
    result = client.execute(
        "/bin/sh",
        ["-c", f"{guest.CLIENT_TAILSCALE} set --exit-node= 2>/dev/null || true"],
        timeout=30.0,
    )
    if not stopped or result.exitcode != 0:
        raise hostcheck.Refusal("cannot stop the client units")


def scan_client_evidence(
    evidence: EvidenceDirectory,
    *,
    before: str,
    after: str,
    marker: str,
    interface: str,
    scanner_path: pathlib.Path,
) -> ScanOutcome:
    """Run clientscan.py over both captures through the retained directory fd."""
    problems: list[str] = []
    hashes: dict[str, str] = {}
    client_scanner = pathlib.Path(scanner_path).with_name("clientscan.py")
    try:
        if evidence.size(guest.CLIENT_CAPTURE_FILE) <= 0:
            return ScanOutcome(
                present=False,
                exitcode=2,
                verdict=None,
                stderr="",
                argv=[],
                hashes={},
                problems=["client_capture_missing"],
                report=None,
            )
        hashes = {
            "client_pcap_sha256": evidence.hash(guest.CLIENT_CAPTURE_FILE),
            "router_pcap_sha256": evidence.hash(guest.CAPTURE_FILE),
            "client_stats_sha256": evidence.hash(
                guest.CLIENT_CAPTURE_STATS_FILE
            ),
            "client_capture_argv_sha256": evidence.hash(
                guest.CLIENT_CAPTURE_ARGV_FILE
            ),
        }
    except (rootfs.PathError, OSError):
        return ScanOutcome(
            present=False,
            exitcode=2,
            verdict=None,
            stderr="",
            argv=[],
            hashes={},
            problems=["client_capture_missing"],
            report=None,
        )
    if not client_scanner.is_file():
        return ScanOutcome(
            present=True,
            exitcode=2,
            verdict=None,
            stderr="",
            argv=[],
            hashes=hashes,
            problems=["client_scanner_missing"],
            report=None,
        )
    scan_argv = [
        sys.executable,
        "-B",
        str(client_scanner),
        "--client-pcap",
        evidence.proc_path(guest.CLIENT_CAPTURE_FILE),
        "--router-pcap",
        evidence.proc_path(guest.CAPTURE_FILE),
        "--client-tcpdump-stats",
        evidence.proc_path(guest.CLIENT_CAPTURE_STATS_FILE),
        "--client-capture-argv-file",
        evidence.proc_path(guest.CLIENT_CAPTURE_ARGV_FILE),
        "--interface",
        interface,
        "--marker",
        marker,
        "--client-control-before",
        before,
        "--client-control-after",
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
        evidence.open_new(guest.CLIENT_SCAN_REPORT_FILE, completed.stdout, mode=0o600)
        scan_stderr = completed.stderr[:4096].decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError) as exc:
        scan_exit = 2
        scan_stderr = f"clientscan failed: {exc.__class__.__name__}"
    try:
        report = json.loads(evidence.read_bytes(guest.CLIENT_SCAN_REPORT_FILE))
    except (rootfs.PathError, OSError, json.JSONDecodeError):
        report = None
        problems.append("client_scan_report_invalid")
    scan_verdict: str | None = None
    if isinstance(report, dict):
        raw = report.get("verdict")
        scan_verdict = raw if isinstance(raw, str) else None
        expected_exit = {"PASS": 0, "LEAK": 1, "INVALID": 2}.get(scan_verdict or "")
        if expected_exit is None or expected_exit != scan_exit:
            problems.append("client_scan_report_mismatch")
        meta = report.get("capture_meta")
        if isinstance(meta, dict):
            for field, key in (
                ("source_sha256", "client_pcap_sha256"),
                ("router_source_sha256", "router_pcap_sha256"),
                ("stats_sha256", "client_stats_sha256"),
                ("capture_argv_sha256", "client_capture_argv_sha256"),
            ):
                if meta.get(field) != hashes[key]:
                    problems.append("client_scan_report_mismatch")
            if meta.get("controls", {}).get("before", {}).get("nonce") != before:
                problems.append("client_scan_report_mismatch")
            if meta.get("controls", {}).get("after", {}).get("nonce") != after:
                problems.append("client_scan_report_mismatch")
        else:
            problems.append("client_scan_report_mismatch")
    else:
        problems.append("client_scan_report_invalid")
    try:
        hashes["client_scan_sha256"] = evidence.hash(
            guest.CLIENT_SCAN_REPORT_FILE
        )
        post = {
            "client_pcap_sha256": evidence.hash(guest.CLIENT_CAPTURE_FILE),
            "router_pcap_sha256": evidence.hash(guest.CAPTURE_FILE),
            "client_stats_sha256": evidence.hash(
                guest.CLIENT_CAPTURE_STATS_FILE
            ),
            "client_capture_argv_sha256": evidence.hash(
                guest.CLIENT_CAPTURE_ARGV_FILE
            ),
        }
        if post != {
            key: hashes[key]
            for key in (
                "client_pcap_sha256",
                "router_pcap_sha256",
                "client_stats_sha256",
                "client_capture_argv_sha256",
            )
        }:
            problems.append("client_scan_report_mismatch")
    except (rootfs.PathError, OSError):
        problems.append("client_scan_report_invalid")
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


def combine_verdicts(
    router_verdict: str | None,
    client_scan_verdict: str | None,
    probe_verdict: str | None,
    *,
    errors: list[str] | tuple[str, ...] = (),
    leak_observed: bool = False,
) -> str:
    """Return the worst of the router, client-scan and probe verdicts.

    A missing or unknown verdict is INVALID, never silently PASS; only a real
    LEAK elsewhere keeps precedence over that defect.  ``leak_observed`` is
    the latched flag: a recognised non-Mullvad success survives every later
    read or quality problem, so the combined result is LEAK.
    """
    raw = (router_verdict, client_scan_verdict, probe_verdict)
    values = [verdict for verdict in raw if isinstance(verdict, str)]
    if leak_observed or "LEAK" in values:
        return "LEAK"
    if (
        errors
        or len(values) != len(raw)
        or any(value not in ("PASS", "INVALID") for value in values)
        or any(value != "PASS" for value in values)
    ):
        return "INVALID"
    return "PASS"


def _run_client_phase_locked(
    arguments: argparse.Namespace, *, lifecycle: LifecycleState
) -> int:
    """Run one M3 phase with a real client VM (router VM also runs)."""
    client_index = guest.validate_client_index(arguments.client)
    client_name = guest.client_name(client_index)
    if not tsnames.is_client_node(client_name):
        raise hostcheck.Refusal("the client name is not a client test label")
    if arguments.phase not in PHASES:
        raise hostcheck.Refusal(f"unknown phase {arguments.phase}")
    if arguments.phase == "login":
        raise hostcheck.Refusal("login does not take --client; use client-login")
    login_only = arguments.phase == "client-login"
    name = guest.validate_name(arguments.name)
    if not login_only and not tsnames.is_test_node(name):
        raise hostcheck.Refusal(
            "name must be a throw-away zz-vprtest-NN-do-not-use label"
        )
    image_id = guest.validate_image_id(arguments.image_id)
    if arguments.duration < 0 or arguments.duration > MAX_PHASE_DURATION:
        raise hostcheck.Refusal(
            f"duration must be in 0..{int(MAX_PHASE_DURATION)} seconds"
        )
    if arguments.duration < MIN_CLIENT_HOLD_SECONDS:
        raise hostcheck.Refusal(
            f"a --client phase needs --duration >= {MIN_CLIENT_HOLD_SECONDS} seconds"
        )
    hold_seconds, hold_windows, hold_spacing = client_hold_schedule(
        arguments.duration
    )
    if arguments.capture_size_cap <= 0:
        raise hostcheck.Refusal("capture size cap must be positive")
    if arguments.tap != guest.TAP or arguments.bridge != guest.BRIDGE:
        raise hostcheck.Refusal(
            f"the leak lab uses the fixed tap {guest.TAP} and bridge {guest.BRIDGE}"
        )
    if arguments.profile_fd is not None and arguments.profile_file is not None:
        raise hostcheck.Refusal("use exactly one of --profile-fd and --profile-file")
    if not login_only and arguments.profile_fd is None and arguments.profile_file is None:
        raise hostcheck.Refusal("a WireGuard profile is required")
    if login_only and (
        arguments.profile_fd is not None or arguments.profile_file is not None
    ):
        arguments.profile_fd = None
        arguments.profile_file = None

    hostcheck.refuse_if_qemu_running(self_pid=os.getpid())
    try:
        uid, gid = guest.resolve_unprivileged_user(arguments.qemu_user)
    except guest.GeneratorError as exc:
        raise hostcheck.Refusal(str(exc)) from exc
    base = pathlib.Path(arguments.base_image)
    if os.geteuid() == 0:
        try:
            rootfs.validate_ancestry(base.parent, expected_uid=0)
        except rootfs.PathError as exc:
            raise hostcheck.Refusal(
                f"base image ancestry is not root-trusted: {exc}"
            ) from exc
    base_digest = guest.verify_base_image(
        base, pathlib.Path(arguments.checksum_manifest)
    )
    router_state = guest.state_path(
        arguments.index, pathlib.Path(arguments.state_root)
    )
    client_state = guest.client_state_path(
        client_index, pathlib.Path(arguments.state_root)
    )
    check_admission(
        pathlib.Path(arguments.evidence_root),
        int(arguments.capture_size_cap),
        state_root=router_state.parent,
        client_memory_mib=CLIENT_MEMORY_MIB,
        capture_count=0 if login_only else 2,
        client_overlay=True,
        router_overlay=not login_only,
    )
    if not login_only:
        verify_state(router_state, qemu_uid=uid, qemu_gid=gid, base=base)
    verify_state(
        client_state,
        qemu_uid=uid,
        qemu_gid=gid,
        base=base,
        max_virtual_size=guest.CLIENT_OVERLAY_VIRTUAL_SIZE,
    )
    verify_host_lab(
        tap=arguments.tap,
        bridge=arguments.bridge,
        owner_file=arguments.owner_file,
        qemu_user=arguments.qemu_user,
        client_index=client_index,
    )

    profile: SecretMaterial | None = None
    lab_policy: policy_mod.Policy | None = None
    endpoint: tuple[str, int] | None = None
    if not login_only:
        if arguments.profile_fd is not None:
            profile = read_profile_fd(arguments.profile_fd)
        else:
            profile = read_profile_path(
                pathlib.Path(arguments.profile_file),
                owner_uid=0 if os.geteuid() == 0 else os.geteuid(),
            )
        endpoint = profile_endpoint(profile)
        lab_policy = build_lab_policy(endpoint)

    used_path = pathlib.Path(arguments.used_nonces)
    if os.geteuid() == 0:
        try:
            rootfs.validate_ancestry(used_path.parent, expected_uid=0)
        except rootfs.PathError as exc:
            raise hostcheck.Refusal(
                f"used-nonces ancestry is not root-trusted: {exc}"
            ) from exc
    used = load_used_nonces(used_path)
    router_pair = fresh_pair(used)
    used.update(router_pair.values())
    client_pair = fresh_pair(used)
    used.update(client_pair.values())
    marker_hex = control_mod.generate_nonce(used)
    used.add(marker_hex)
    marker = clientprobe.MARKER_PREFIX + marker_hex
    append_used_nonces(used_path, router_pair)
    append_used_nonces(used_path, client_pair, extra=(marker_hex,))

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
        evidence_real = evidence_root.resolve()
        state_paths = [client_state.resolve()]
        if not login_only:
            state_paths.append(router_state.resolve())
    except OSError as exc:
        raise hostcheck.Refusal("cannot resolve the evidence path") from exc
    for state_real in state_paths:
        if evidence_real == state_real or state_real in evidence_real.parents:
            raise hostcheck.Refusal(
                "evidence must live outside the QEMU-owned state directories"
            )
    record_name = client_name if login_only else name
    evidence = _evidence_run_dir(evidence_root, arguments.phase, record_name)
    evidence_dir = evidence.path
    pcap = evidence_dir / guest.CAPTURE_FILE
    stats = evidence_dir / guest.CAPTURE_STATS_FILE
    client_pcap = evidence_dir / guest.CLIENT_CAPTURE_FILE
    client_stats = evidence_dir / guest.CLIENT_CAPTURE_STATS_FILE
    qemu_log = evidence_dir / guest.QEMU_LOG_FILE
    client_log = evidence_dir / "client-qemu.log"
    client_tap = guest.client_tap(client_index)
    if lab_policy is not None:
        evidence.write_json("policy.json", lab_policy.to_dict())

    record = base_phase_record(
        phase=arguments.phase,
        name=record_name,
        state=client_state if login_only else router_state,
        evidence_dir=evidence_dir,
        image_id=image_id,
    )
    record["mode"] = "test"
    record["certifies"] = (
        "client_traffic_through_test_exit_node"
        if not login_only
        else "client_login"
    )
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
    record["nonces"] = {
        "before": router_pair["before"],
        "after": router_pair["after"],
        "used_nonces_file": str(used_path),
        "reserved": True,
        "client_before": client_pair["before"],
        "client_after": client_pair["after"],
        "client_marker": marker,
    }
    if lab_policy is not None:
        record["policy"] = {
            "path": str(evidence_dir / "policy.json"),
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
    record["client"] = {
        "index": client_index,
        "name": client_name,
        "memory_mib": CLIENT_MEMORY_MIB,
        "tap": client_tap,
        "bridge": guest.CLIENT_BRIDGE,
        "ipv4": guest.client_ipv4(client_index),
        "mac": guest.client_mac(client_index),
        "nonces": {
            "before": client_pair["before"],
            "after": client_pair["after"],
            "marker": marker,
        },
        "probe_ips": {},
        "exit_node": {
            "router_name": name if not login_only else None,
            "active": False,
        },
        "scan": {
            "verdict": None,
            "path": str(evidence_dir / guest.CLIENT_SCAN_REPORT_FILE),
        },
        "probe": None,
        "probe_leak_observed": False,
        "traffic_stop_proven": None,
        "fault_sequence": None,
        "hold_sequence_end": None,
        "hold_samples": [],
        "hold_seconds": hold_seconds,
        "hold_requested_seconds": int(math.ceil(float(arguments.duration))),
        "guest_mem_available": {"boot": None, "end": None},
        "combined": None,
    }

    router_capture: Capture | None = None
    client_capture: Capture | None = None
    router_guard: CaptureGuard | None = None
    client_guard: CaptureGuard | None = None
    router_process: subprocess.Popen | None = None
    client_process: subprocess.Popen | None = None
    router_client: QGAClient | None = None
    client_client: QGAClient | None = None
    errors: list[str] = []
    after_client_sent = False
    after_router_sent = False
    traffic_started = False
    # The action sampler thread owns the client QGA socket while it runs.  If
    # it cannot be joined, the socket is never used again from this thread.
    action_sampler: ClientActionSampler | None = None
    client_qga_unsafe = False
    started = time.monotonic()
    record["timestamps"]["started_at"] = utc_now()
    record["mem_available"] = read_mem_available()

    def note(reason: str) -> None:
        if reason not in errors:
            errors.append(reason)

    def guard_check() -> None:
        for guard in (router_guard, client_guard):
            if guard is not None:
                guard.raise_if_exceeded()

    try:
        if not login_only:
            router_guard = CaptureGuard(
                evidence.fd, pcap.name, int(arguments.capture_size_cap)
            )
            client_guard = CaptureGuard(
                evidence.fd,
                client_pcap.name,
                int(arguments.capture_size_cap),
                tap=client_tap,
            )
            router_guard.start()
            client_guard.start()
            router_capture = start_capture(
                arguments.tap,
                pcap,
                stats,
                tcpdump=tcpdump,
                evidence_fd=evidence.fd,
                file_size_limit=int(arguments.capture_size_cap)
                + CAPTURE_FSIZE_MARGIN,
            )
            record["tcpdump_argv"] = router_capture.argv
            record["tcpdump_argv_display"] = display_argv(
                router_capture.argv, evidence
            )
            evidence.write_json(guest.CAPTURE_ARGV_FILE, router_capture.argv)
            client_capture = start_capture(
                client_tap,
                client_pcap,
                client_stats,
                tcpdump=tcpdump,
                evidence_fd=evidence.fd,
                file_size_limit=int(arguments.capture_size_cap)
                + CAPTURE_FSIZE_MARGIN,
            )
            record["client"]["tcpdump_argv"] = client_capture.argv
            record["client"]["tcpdump_argv_display"] = display_argv(
                client_capture.argv, evidence
            )
            evidence.write_json(
                guest.CLIENT_CAPTURE_ARGV_FILE, client_capture.argv
            )
            # Both captures are bond to their own guard: a dead tcpdump trips
            # capture_ended_early and isolates the corresponding tap at once.
            router_guard.attach_capture(router_capture.process)
            client_guard.attach_capture(client_capture.process)
            record["timestamps"]["capture_started"] = utc_now()
            guard_check()

        client_log_fd = evidence.open_append("client-qemu.log")
        try:
            client_process, client_qemu_argv, client_launch_argv = start_vm(
                client_state,
                name=client_name,
                tap=client_tap,
                qemu_user=arguments.qemu_user,
                uid=uid,
                gid=gid,
                log_fd=client_log_fd,
                memory_mib=CLIENT_MEMORY_MIB,
                mac=guest.client_mac(client_index),
            )
        finally:
            os.close(client_log_fd)
        for guard in (router_guard, client_guard):
            if guard is not None:
                guard.attach_qemu(client_process)
        record["client"]["qemu_argv"] = client_qemu_argv
        record["client"]["launch_argv"] = client_launch_argv
        record["timestamps"]["client_qemu_started"] = utc_now()
        time.sleep(0.5)
        if client_process.poll() is not None:
            raise hostcheck.Refusal("client QEMU exited immediately")
        client_client = wait_for_qga_or_exit(
            client_state / guest.QGA_SOCKET, client_process
        )
        record["timestamps"]["client_qga_ready"] = utc_now()
        record["client"]["guest_mem_available"]["boot"] = read_guest_mem_available(
            client_client
        )
        guard_check()
        # A crashed earlier phase may have left the transient traffic unit
        # running.  Stop it and prove it is gone before the silence check or
        # the login bootstrap; an unpreventable writer voids every snapshot.
        try:
            stopped = stop_client_traffic(client_client)
        except (QGAError, OSError):
            record["client"]["traffic_stop_proven"] = False
            note("cleanup_failed")
            raise hostcheck.Refusal("cannot stop the stale client traffic unit")
        if not stopped:
            record["client"]["traffic_stop_proven"] = False
            note("cleanup_failed")
            raise hostcheck.Refusal("cannot prove the stale client traffic unit stopped")
        guard_check()
        if not login_only:
            client_silence = client_client.execute(
                "/bin/sh",
                [
                    "-c",
                    guest.client_silence_check_script(client_index),
                ],
                timeout=SILENCE_TIMEOUT,
            )
            if (
                client_silence.exitcode != 0
                or b"SILENCE-OK" not in client_silence.stdout
            ):
                raise hostcheck.Refusal("client silence check failed")
            record["client"]["silence"] = "ok"
            record["client"]["wan_device"] = resolve_wan_device(
                client_client, guest.client_mac(client_index)
            )
        if login_only:
            record["client"]["login_started"] = utc_now()
            # A first interactive `tailscale up` prints the login URL and then
            # blocks until authentication.  Run it as a transient unit so the
            # runner can show the URL and poll BackendState instead of waiting
            # inside a 120 s QGA call that hides the URL.  A stale unit from a
            # crashed run in the same boot is stopped first.
            stop_client_login_unit(client_client)
            login_runtime = int(arguments.duration) + CLIENT_TRAFFIC_RUNTIME_MARGIN
            login_command = (
                f"systemd-run --unit={guest.CLIENT_LOGIN_UNIT} --collect "
                f"--property=RuntimeMaxSec={login_runtime} "
                f"{guest.CLIENT_TAILSCALE} up --reset "
                f"--hostname={shlex.quote(client_name)} --shields-up "
                "--accept-routes=false --accept-dns=false"
            )
            up = client_client.execute(
                "/bin/sh", ["-c", login_command], timeout=60.0
            )
            if up.exitcode != 0:
                note("client_login_failed")
            else:
                record["client"]["login_unit"] = "started"
            login_phase_wait(
                client_client,
                name=client_name,
                duration=arguments.duration,
                evidence=evidence,
                record=record,
                guard=None,
                note=note,
                client_login=True,
                stop_when_running=True,
            )
            document = read_client_status(client_client)
            record["client"]["running"] = (
                isinstance(document, dict)
                and document.get("BackendState") == "Running"
            )
            if not record["client"]["running"]:
                note("login_not_running")
            problem = client_route_advertisement_problem(
                read_client_prefs(client_client)
            )
            if problem is not None:
                note(problem)
            record["client"]["guest_mem_available"]["end"] = (
                read_guest_mem_available(client_client)
            )
            record["client"]["combined"] = (
                "PASS" if not errors else "INVALID"
            )
            record["result"] = record["client"]["combined"]
            record["result_reason"] = "; ".join(errors) if errors else None
            record["errors"] = list(errors)
            record["durations"]["phase_seconds"] = round(
                time.monotonic() - started, 3
            )
            record["timestamps"]["finished_at"] = utc_now()
            try:
                cleanup_client_units(client_client)
                record["client"]["cleanup"] = "ok"
            except BaseException as exc:  # noqa: BLE001
                record["client"]["cleanup"] = exc.__class__.__name__
                note("cleanup_failed")
                record["result"] = "INVALID"
                record["result_reason"] = "; ".join(errors)
            try:
                status, forced, survived = poweroff_vm(
                    client_client, client_process, tap=client_tap
                )
            except BaseException as exc:  # noqa: BLE001
                record["client_poweroff_error"] = exc.__class__.__name__
                status, forced, survived = None, True, False
            client_client = None
            client_process = None
            record["client"]["qemu_exit_status"] = status
            if forced:
                note("forced_poweroff")
            if survived:
                note("qemu_still_running")
                lifecycle.qemu_alive = True
            if errors:
                record["result"] = "INVALID"
                record["result_reason"] = "; ".join(errors)
            record["client"]["combined"] = record["result"]
            try:
                evidence.write_json(guest.PHASE_RECORD_FILE, record)
            finally:
                evidence.close()
            print(
                json.dumps(
                    {
                        "phase": arguments.phase,
                        "result": record["result"],
                        "verdict": record["result"],
                        "exit": 0 if record["result"] == "PASS" else 2,
                        "evidence": str(evidence_dir),
                    },
                    sort_keys=True,
                )
            )
            return 0 if record["result"] == "PASS" else 2

        # Tailscaled must be running before `tailscale set` is usable.  The
        # design's clear-before-wait order races the daemon socket; wait first,
        # then clear any persisted exit node and prove it is gone.
        document = wait_client_running(client_client, client_name)
        record["client"]["running"] = True
        record["client"]["advertises_exit_node"] = False
        route_problem = client_route_advertisement_problem(
            read_client_prefs(client_client)
        )
        if route_problem is not None:
            note(route_problem)
            raise hostcheck.Refusal(route_problem)
        record["client"]["advertises_routes"] = False
        record["timestamps"]["client_ready"] = utc_now()
        guard_check()
        clear_client_exit_node(client_client)
        wait_client_exit_cleared(client_client)
        record["client"]["exit_node"]["cleared"] = True
        record["timestamps"]["client_exit_cleared"] = utc_now()
        guard_check()
        # Client before-control is sent before the router exists.
        client_wan = record["client"]["wan_device"]
        client_control_exitcode = emit_client_control(
            client_client,
            client_pair["before"],
            client_index,
            client_wan,
        )
        record["client"]["nonces"]["before_exitcode"] = client_control_exitcode
        record["timestamps"]["client_before_control"] = utc_now()

        # Router boot and setup.  For client phases the router is always made
        # ready before the fault, so a pre-fault client success is possible for
        # every accepted phase (including start-router, whose action is then
        # idempotent).
        router_log_fd = evidence.open_append(guest.QEMU_LOG_FILE)
        try:
            router_process, router_qemu_argv, router_launch_argv = start_vm(
                router_state,
                name=name,
                tap=arguments.tap,
                qemu_user=arguments.qemu_user,
                uid=uid,
                gid=gid,
                log_fd=router_log_fd,
            )
        finally:
            os.close(router_log_fd)
        for guard in (router_guard, client_guard):
            if guard is not None:
                guard.attach_qemu(router_process)
        record["qemu_argv"] = router_qemu_argv
        record["launch_argv"] = router_launch_argv
        record["timestamps"]["qemu_started"] = utc_now()
        time.sleep(0.5)
        if router_process.poll() is not None:
            raise hostcheck.Refusal(
                f"QEMU exited immediately with status {router_process.returncode}"
            )
        router_client = wait_for_qga_or_exit(
            router_state / guest.QGA_SOCKET, router_process
        )
        record["timestamps"]["qga_ready"] = utc_now()
        guard_check()
        try:
            cleanup_guest_units(router_client, name)
        except hostcheck.Refusal:
            note("cleanup_failed")
            raise
        initial_silence = run_silence_check(
            router_client, name=name, image_id=image_id, expect_router_disabled=True
        )
        record["silence"].append(
            {"when": "initial", "exitcode": initial_silence.exitcode, "ok": True}
        )
        verify_guest_image(router_client, image_id)
        router_wan = resolve_wan_device(router_client)
        secrets_paths = prepare_vm_secrets(
            router_client, name, profile, image_id
        )
        record["guest"].update(secrets_paths)
        guard_check()

        reboot_phase = arguments.phase == "reboot-with-router-enabled"
        if not reboot_phase:
            record["controls"]["before_exitcode"] = emit_control(
                router_client, router_pair["before"], lab_policy, router_wan
            )
            record["controls"]["before_transport"] = "qga"
            record["timestamps"]["before_control"] = utc_now()
        setup_command = f"systemctl start vprouter@{name}.service"
        record["setup"]["command"] = setup_command
        setup = router_client.execute(
            "/bin/sh", ["-c", setup_command], timeout=ACTION_TIMEOUT
        )
        record["setup"]["exitcode"] = setup.exitcode
        if setup.exitcode != 0:
            record["setup"]["active"] = False
            note("setup_failed")
            raise hostcheck.Refusal("router setup failed")
        wait_router_ready(router_client, name, require_tailscale=True)
        record["setup"]["active"] = True
        record_tailscale_state(record, router_client, name)
        record["timestamps"]["router_active"] = utc_now()
        guard_check()

        # Exit node: bind the client's peer to the router's own Self.ID and
        # Tailscale addresses.  HostName alone is not an identity.
        router_id, router_addresses = router_exit_identity(
            read_tailscale_status(router_client, name)
        )
        try:
            peer = wait_client_router_peer(
                client_client, name, router_id, router_addresses
            )
        except hostcheck.Refusal:
            note("client_exit_peer_missing")
            raise
        exit_ipv4 = client_peer_ipv4(peer, router_addresses)
        set_client_exit_node(client_client, exit_ipv4)
        wait_client_exit_node(client_client, router_id, exit_ipv4)
        record["client"]["exit_node"]["active"] = True
        record["client"]["exit_node"]["router_peer_bound"] = True
        record["timestamps"]["exit_node_active"] = utc_now()
        guard_check()

        probe_ips = resolve_probe_ips()
        record["client"]["probe_ips"] = dict(probe_ips)
        record["client"]["probe_clock_start"] = read_guest_clock(client_client)
        # Opus R3-1: the start counts as attempted before the call.  A start
        # that launched the unit and then raised (a lost QGA reply) is still
        # stopped, proven and collected from `finally`, never snapshotted
        # while the writer may run.
        traffic_started = True
        start_client_traffic(
            client_client,
            marker=marker,
            https_ip=probe_ips["https"],
            http_ip=probe_ips["http"],
            runtime_sec=client_runtime_seconds(hold_seconds),
        )
        record["timestamps"]["traffic_started"] = utc_now()
        probe_flags = wait_client_probe_control(
            client_client, clientprobe.marker_run_id(marker)
        )
        if probe_flags["leak"]:
            # Do not wait for the positive controls: the leak is already real
            # evidence and the final probe verdict keeps LEAK precedence.
            record["client"]["probe_leak_observed"] = True
            note("client_real_ip")
            raise hostcheck.Refusal("the client leaked a real IP before the fault")
        if not probe_flags["mullvad"]:
            note("client_not_routed")
            raise hostcheck.Refusal("no pre-fault Mullvad client success")
        if not probe_flags["marker"]:
            note("client_marker_not_sent")
            raise hostcheck.Refusal("no pre-fault successful marker probe")
        record["client"]["pre_fault_mullvad"] = True
        record["client"]["pre_fault_marker"] = True
        record["timestamps"]["pre_fault_control"] = utc_now()

        fault_run_id = clientprobe.marker_run_id(marker)
        hold_samples: list[dict[str, Any]] = record["client"]["hold_samples"]
        coverage_count = {"action": 0}

        def apply_sample(result: ClientCoverageSample) -> None:
            """Apply one coverage sample to the record, in sample order."""
            if result.leak:
                record["client"]["probe_leak_observed"] = True
            for problem in result.problems:
                note(problem)
            if result.sample is not None:
                hold_samples.append(result.sample)

        def coverage_sample(kind: str, base: float | None) -> ClientCoverageSample:
            result = take_client_coverage_sample(
                client_client,
                fault_run_id,
                kind=kind,
                base=base,
                router_id=router_id,
                exit_ipv4=exit_ipv4,
            )
            apply_sample(result)
            return result

        def wait_until(due: float) -> None:
            while True:
                check_interrupt()
                guard_check()
                remaining = due - time.monotonic()
                if remaining <= 0:
                    return
                time.sleep(min(0.25, remaining))

        record["client"]["fault_epoch"] = read_guest_clock(client_client)
        # S_pre (fix round 4, decision 1): a trusted sample immediately before
        # the fault action.  Host-observed coverage runs from here to S_end,
        # through the action and its postcondition, so the fault itself is
        # never covered only by the guest clock (Opus R4 I-1).  All sample
        # offsets are relative to S_pre's size read.
        pre_result = coverage_sample("pre", None)
        sample_base = pre_result.read.stat_start
        record["timestamps"]["pre_fault_sample"] = utc_now()
        if client_client is router_client:
            raise hostcheck.Refusal("the client and router QGA clients are shared")

        def action_take() -> ClientCoverageSample:
            # Runs in the sampler thread: only the client's QGA socket.
            return take_client_coverage_sample(
                client_client,
                fault_run_id,
                kind="action",
                base=sample_base,
                router_id=router_id,
                exit_ipv4=exit_ipv4,
            )

        record["timestamps"]["fault_started"] = utc_now()
        action_ok = True
        sampler_alive = False
        try:
            action_sampler = ClientActionSampler(
                action_take,
                first_due=sample_base + CLIENT_ACTION_SAMPLE_INTERVAL,
                interval=CLIENT_ACTION_SAMPLE_INTERVAL,
            )
            action_sampler.start()
            # From here until the join below only the router QGA is used.
            if reboot_phase:
                enabled = router_client.execute(
                    "/bin/sh",
                    ["-c", f"systemctl enable vprouter@{name}.service"],
                    timeout=30.0,
                )
                if enabled.exitcode != 0:
                    note("setup_failed")
                    action_ok = False
                boot_token = secrets.token_hex(16)
                record["boot"]["boot_control"] = stage_boot_control(
                    router_client, router_pair["before"], lab_policy,
                    boot_token=boot_token,
                )
                record["controls"]["before_transport"] = "boot-control-unit"
                record["boot"]["rebooted"] = True
                previous_boot_id = read_boot_id(router_client)
                record["boot"]["previous_boot_id"] = previous_boot_id
                router_client.shutdown("reboot", timeout=5.0)
                router_client.close()
                router_client = wait_for_reboot(
                    router_state / guest.QGA_SOCKET, previous_boot_id
                )
                record["boot"]["new_boot_id"] = read_boot_id(router_client)
                record["boot"]["boot_id_changed"] = (
                    record["boot"]["new_boot_id"] != previous_boot_id
                )
                wait_boot_control_sent(router_client, boot_token)
                record["timestamps"]["before_control"] = utc_now()
                record["controls"]["before_exitcode"] = 0
                run_silence_check(
                    router_client,
                    name=name,
                    image_id=image_id,
                    expect_router_disabled=False,
                )
                wait_router_ready(router_client, name, require_tailscale=True)
                if not record["boot"]["boot_id_changed"]:
                    note("postcondition_failed")
                    action_ok = False
            else:
                action_ok = run_router_fault(
                    router_client, arguments.phase, name, record, note
                )
        finally:
            # Stopped and joined on every path before the client QGA socket
            # is used again from this thread.
            if action_sampler is not None:
                sampler_alive = not action_sampler.halt(CLIENT_SAMPLER_JOIN_TIMEOUT)
                if sampler_alive:
                    client_qga_unsafe = True
                    note("client_sampler_stuck")
                else:
                    for result in action_sampler.results:
                        coverage_count["action"] += 1
                        apply_sample(result)
                    if action_sampler.failure is not None:
                        note("client_sampler_failed")
            record["timestamps"]["fault_finished"] = utc_now()
        if sampler_alive:
            raise hostcheck.Refusal("the client action sampler did not stop")
        if not action_ok:
            note("action_failed")
        record["client"]["action_samples"] = coverage_count["action"]
        record["client"]["post_fault_epoch"] = read_guest_clock(client_client)
        guard_check()

        # S_fault: the next point of the same <= 13 s cadence after the
        # action and its postcondition finished, so its window still holds a
        # complete probe loop.  Its size read starts the hold.
        last_start = pre_result.read.stat_start
        if action_sampler is not None and action_sampler.results:
            last_start = max(
                last_start,
                max(result.read.stat_start for result in action_sampler.results),
            )
        wait_until(last_start + CLIENT_ACTION_SAMPLE_INTERVAL)
        fault_result = coverage_sample("fault", sample_base)
        hold_base = fault_result.read.stat_start
        fault_sequence = (
            fault_result.sample["sequence"] if fault_result.sample else None
        )
        if fault_sequence is None:
            note("probe_fault_sequence_missing")
        record["client"]["fault_sequence"] = fault_sequence
        record["timestamps"]["fault_sequence_read"] = utc_now()
        guard_check()

        # The hold: equal windows of 12-14 s from S_fault; the deadline
        # sample S_end starts CLIENT_HOLD_END_MARGIN before the deadline and
        # must finish its size read by the deadline (GPT R4-I1).  Lines first
        # written after the deadline never count as coverage.
        hold_deadline = hold_base + float(hold_seconds)
        due_times = [
            hold_base + hold_spacing * index
            for index in range(1, hold_windows + 1)
        ]
        record["client"]["hold_windows"] = hold_windows
        end_result: ClientCoverageSample | None = None
        for index, due in enumerate(due_times):
            wait_until(due)
            last = index == len(due_times) - 1
            result = coverage_sample("end" if last else "hold", sample_base)
            if last:
                end_result = result
        end_sample = end_result.sample if end_result is not None else None
        if end_result is not None and end_result.read.stat_end > hold_deadline:
            note("probe_hold_deadline_late")
        end_sequence = end_sample["sequence"] if end_sample else None
        if end_sequence is None:
            note("probe_end_sequence_missing")
        record["client"]["hold_sequence_end"] = end_sequence
        kinds = [sample.get("kind") for sample in hold_samples]
        record["client"]["exit_node"]["reverified"] = bool(
            kinds
            and kinds[0] == "pre"
            and kinds[-1] == "end"
            and kinds.count("fault") == 1
            and kinds.count("hold") == hold_windows - 1
            and all(sample.get("exit_node_ok") is True for sample in hold_samples)
        )
        record["timestamps"]["exit_node_reverified"] = utc_now()
        if arguments.phase == "kill-wireguard" and router_client is not None:
            record["recovery"] = read_wg0_state(router_client, name)

        if not client_traffic_unit_active(client_client):
            note("client_traffic_unit_inactive")
            if stop_client_traffic(client_client):
                if client_probe_writer_quiescent(client_client):
                    traffic_started = False
                    record["client"]["traffic_stop_proven"] = True
                else:
                    record["client"]["traffic_stop_proven"] = False
                    note("client_writer_not_quiescent")
            raise hostcheck.Refusal(
                "the client traffic unit is not active at the end of the hold"
            )
        if not stop_client_traffic(client_client):
            # The writer may still be running.  Do not trust any snapshot
            # taken after this point, not even one taken after a later cleanup
            # stop proves the unit gone.
            record["client"]["traffic_stop_proven"] = False
            note("client_traffic_stop_failed")
            raise hostcheck.Refusal(
                "the client traffic unit did not stop at the end of the hold"
            )
        # Read the guest clock right after the proven stop: no probe line can
        # follow it, and the quiescence wait does not widen the tail gap.
        record["client"]["probe_clock_stop"] = read_guest_clock(client_client)
        if not client_probe_writer_quiescent(client_client):
            # Decision 3: a log that still grows after a stop that claimed
            # success has a live writer; nothing read now is exact.
            record["client"]["traffic_stop_proven"] = False
            note("client_writer_not_quiescent")
            raise hostcheck.Refusal(
                "the client probe log kept growing after the traffic unit stopped"
            )
        # Opus R4 M-3: a PASS record states the proven stop explicitly.
        record["client"]["traffic_stop_proven"] = True
        traffic_started = False
        collect_client_probe(
            client_client, evidence, record, note, run_id=fault_run_id
        )
        clear_client_exit_node(client_client)
        record["client"]["exit_node"]["active"] = False
        record["client"]["nonces"]["after_exitcode"] = emit_client_control(
            client_client,
            client_pair["after"],
            client_index,
            record["client"]["wan_device"],
        )
        record["timestamps"]["client_after_control"] = utc_now()
        after_client_sent = True
        record["controls"]["after_exitcode"] = emit_control(
            router_client, router_pair["after"], lab_policy, router_wan
        )
        record["controls"]["after_transport"] = "qga"
        record["timestamps"]["after_control"] = utc_now()
        after_router_sent = True
    except CaptureCapExceeded as exc:
        note(str(exc) or "capture_size_cap")
    except BaseException as exc:  # noqa: BLE001
        record["error_class"] = exc.__class__.__name__
        note(f"phase_exception:{exc.__class__.__name__}")
    finally:
        record["timestamps"]["finally_entered"] = utc_now()
        for guard in (router_guard, client_guard):
            if guard is not None:
                reason = guard.check()
                if reason is not None:
                    note(reason)
                if guard.isolation_error is not None:
                    record["tap_isolation_error"] = guard.isolation_error
                    note("tap_isolation_failed")
                if guard.kill_error is not None:
                    record["capture_guard_kill_error"] = guard.kill_error
                    note("capture_guard_kill_failed")
                if guard.capture_ended_early_at is not None:
                    record["capture_ended_early_at"] = (
                        guard.capture_ended_early_at
                    )
        if action_sampler is not None and action_sampler.is_alive():
            # Normally joined right after the action; this is the backstop
            # for any path that skipped it.
            if not action_sampler.halt(CLIENT_SAMPLER_JOIN_TIMEOUT):
                client_qga_unsafe = True
                note("client_sampler_stuck")
        if client_qga_unsafe:
            # A live sampler may still be using the client QGA socket: never
            # share it.  QEMU is killed without a guest powerdown request.
            client_client = None
        if router_client is not None:
            try:
                cleanup_guest_units(router_client, name)
                record["cleanup"]["services"] = "ok"
            except BaseException as exc:  # noqa: BLE001
                record["cleanup"]["services"] = exc.__class__.__name__
                note("cleanup_failed")
        if client_client is not None:
            try:
                if not login_only and not record["client"].get("probe_collected"):
                    if traffic_started:
                        try:
                            stopped = stop_client_traffic(client_client)
                            if (
                                stopped
                                and record["client"].get("traffic_stop_proven")
                                is None
                                and not client_probe_writer_quiescent(
                                    client_client
                                )
                            ):
                                note("client_writer_not_quiescent")
                                stopped = False
                        except BaseException:  # noqa: BLE001
                            stopped = False
                        traffic_started = False
                        if stopped:
                            if (
                                record["client"].get("traffic_stop_proven")
                                is None
                            ):
                                record["client"]["traffic_stop_proven"] = True
                        else:
                            record["client"]["traffic_stop_proven"] = False
                            note("client_traffic_stop_failed")
                    if record["client"].get("probe_clock_stop") is None:
                        record["client"]["probe_clock_stop"] = read_guest_clock(
                            client_client
                        )
                    trusted = (
                        record["client"].get("traffic_stop_proven") is not False
                    )
                    collect_client_probe(
                        client_client,
                        evidence,
                        record,
                        note,
                        trusted=trusted,
                        run_id=clientprobe.marker_run_id(marker),
                    )
            except BaseException:  # noqa: BLE001
                note("probe_collection_failed")
            if not login_only:
                record["client"]["guest_mem_available"]["end"] = (
                    read_guest_mem_available(client_client)
                )
            try:
                cleanup_client_units(client_client)
                record["client"]["cleanup"] = "ok"
            except BaseException as exc:  # noqa: BLE001
                record["client"]["cleanup"] = exc.__class__.__name__
                note("cleanup_failed")
        record["timestamps"]["vm_poweroff_started"] = utc_now()
        statuses: list[int | None] = []
        for process, qga, label, tap in (
            (client_process, client_client, "client", client_tap),
            (router_process, router_client, "router", arguments.tap),
        ):
            if process is None:
                statuses.append(
                    record["client"].get("qemu_exit_status")
                    if label == "client"
                    else record.get("qemu_exit_status")
                )
                continue
            try:
                status, forced, survived = poweroff_vm(
                    qga, process, tap=tap
                )
            except BaseException as exc:  # noqa: BLE001
                record[f"{label}_poweroff_error"] = exc.__class__.__name__
                status, forced, survived = None, True, False
            statuses.append(status)
            if forced:
                note("forced_poweroff")
            elif status not in (0, None):
                note("qemu_exit_status")
            if survived:
                note("qemu_still_running")
                record["qemu_survived"] = True
                lifecycle.qemu_alive = True
        client_client = None
        router_client = None
        record["qemu_exit_status"] = statuses[1] if len(statuses) > 1 else None
        record["client"]["qemu_exit_status"] = statuses[0] if statuses else None
        record["timestamps"]["vm_finished_at"] = utc_now()

        for capture, label, sent, pair in (
            (client_capture, "client", after_client_sent, client_pair),
            (router_capture, "router", after_router_sent, router_pair),
        ):
            if capture is None or not sent:
                continue
            try:
                arrived = wait_for_control_in_pcap(
                    capture.pcap,
                    pair["after"],
                    evidence_fd=evidence.fd,
                    name=capture.pcap.name,
                )
            except BaseException:  # noqa: BLE001
                arrived = False
            record[f"{label}_after_in_pcap"] = arrived
            if label == "router":
                record["controls"]["after_in_pcap"] = arrived
            if not arrived:
                note("after_control_not_captured")
        try:
            time.sleep(QUIET_SECONDS)
        except BaseException:  # noqa: BLE001
            pass
        for capture, guard, label in (
            (client_capture, client_guard, "client"),
            (router_capture, router_guard, "router"),
        ):
            if capture is None:
                continue
            try:
                alive = capture.process.poll() is None
            except BaseException:  # noqa: BLE001
                alive = False
            record[f"{label}_capture_alive_before_stop"] = alive
            if not alive:
                record["capture_ended_early"] = True
                note("capture_ended_early")
            if guard is not None:
                guard.mark_capture_stopping()
            try:
                status = stop_capture(capture, evidence_fd=evidence.fd)
                if label == "router":
                    record["tcpdump_exit_status"] = status
                else:
                    record["client"]["tcpdump_exit_status"] = status
            except BaseException as exc:  # noqa: BLE001
                record[f"{label}_capture_stop_error"] = exc.__class__.__name__
                note("capture_stop_failed")
        for guard in (router_guard, client_guard):
            if guard is not None:
                try:
                    guard.stop()
                except BaseException as exc:  # noqa: BLE001
                    record["capture_guard_error"] = exc.__class__.__name__
                    note("capture_guard_failed")
        record["errors"] = list(errors)

    # Verdicts: router scan unchanged, client scan, then the probe log.
    router_outcome: ScanOutcome | None = None
    if not login_only:
        router_outcome = scan_evidence(
            evidence,
            phase=arguments.phase,
            before=router_pair["before"],
            after=router_pair["after"],
            scanner_path=scanner_path,
        )
        if router_outcome.present:
            record["pcapscan_argv"] = router_outcome.argv
            record["pcapscan_argv_display"] = display_argv(
                router_outcome.argv, evidence
            )
            record["scan"]["exitcode"] = router_outcome.exitcode
            record["scan"]["stderr"] = router_outcome.stderr
            record["scan"]["verdict"] = router_outcome.verdict
            record["hashes"].update(router_outcome.hashes)
        for problem in router_outcome.problems:
            note(problem)
        client_outcome = scan_client_evidence(
            evidence,
            before=client_pair["before"],
            after=client_pair["after"],
            marker=marker,
            interface=client_tap,
            scanner_path=scanner_path,
        )
        if client_outcome.present:
            record["client"]["scan_argv"] = client_outcome.argv
            record["client"]["scan_argv_display"] = display_argv(
                client_outcome.argv, evidence
            )
            record["client"]["scan"]["exitcode"] = client_outcome.exitcode
            record["client"]["scan"]["stderr"] = client_outcome.stderr
            record["client"]["scan"]["verdict"] = client_outcome.verdict
            record["hashes"].update(client_outcome.hashes)
        for problem in client_outcome.problems:
            note(problem)
    else:
        client_outcome = None

    probe_report: dict[str, Any] | None = None
    if not login_only:
        try:
            probe_bytes = evidence.read_bytes(guest.CLIENT_PROBE_FILE)
        except (rootfs.PathError, OSError):
            probe_bytes = b""
        if probe_bytes and clientprobe.probe_prefix_flags(probe_bytes)["leak"]:
            record["client"]["probe_leak_observed"] = True
        probe_report = clientprobe.evaluate_probe_log(
            probe_bytes,
            fault_epoch=record["client"].get("fault_epoch"),
            run_id=clientprobe.marker_run_id(marker),
            clock_start=record["client"].get("probe_clock_start"),
            clock_stop=record["client"].get("probe_clock_stop"),
            post_fault_epoch=record["client"].get("post_fault_epoch"),
            fault_sequence=record["client"].get("fault_sequence"),
            end_sequence=record["client"].get("hold_sequence_end"),
            hold_seconds=record["client"].get("hold_seconds"),
            hold_samples=record["client"].get("hold_samples"),
        )
        if probe_report["leak"]:
            record["client"]["probe_leak_observed"] = True
        if (
            probe_report["verdict"] == "PASS"
            and record["client"].get("probe_log_read") != "exact"
        ):
            # A read-quality defect never leaves a PASS probe object behind;
            # a latched LEAK still wins through combine_verdicts.
            probe_report["verdict"] = "INVALID"
            probe_report["reason"] = "probe_log_read_quality"
        record["client"]["probe"] = probe_report
        if probe_report["verdict"] == "LEAK":
            note("client_real_ip")
        elif probe_report["verdict"] != "PASS":
            note(probe_report.get("reason") or "client_probe_invalid")

    if lab_policy is not None:
        record["hashes"]["policy_sha256"] = record["policy"]["sha256"]
    record["durations"]["phase_seconds"] = round(
        time.monotonic() - started, 3
    )
    record["timestamps"]["scan_finished"] = utc_now()

    if login_only:
        final_result = "PASS" if not errors else "INVALID"
    else:
        final_result = combine_verdicts(
            router_outcome.verdict if router_outcome else None,
            client_outcome.verdict if client_outcome else None,
            probe_report["verdict"] if probe_report else None,
            errors=errors,
            leak_observed=bool(record["client"].get("probe_leak_observed")),
        )
    final_exit = {"PASS": 0, "LEAK": 1, "INVALID": 2}[final_result]
    record["client"]["combined"] = final_result
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
                "scan_verdict": router_outcome.verdict
                if router_outcome is not None
                else None,
                "client_scan_verdict": client_outcome.verdict
                if client_outcome is not None
                else None,
                "client_verdict": probe_report["verdict"]
                if probe_report is not None
                else None,
                "exit": final_exit,
                "expect_tunnel": PHASE_EXPECTATIONS[arguments.phase],
                "evidence": str(evidence_dir),
            },
            sort_keys=True,
        )
    )
    return final_exit



def run_router_fault(
    client: QGAClient,
    phase: str,
    name: str,
    record: dict,
    note,
) -> bool:
    """Apply one client-phase router fault and prove its effect."""
    if phase in {"idle", "login"}:
        record["action"]["command"] = "true"
        record["action"]["exitcode"] = 0
        return True
    command = action_command(phase, name)
    record["action"]["command"] = command
    docker_pid_before = None
    wg0_before = None
    if phase == "restart-docker":
        try:
            docker_pid_before = read_docker_pid(client)
        except hostcheck.Refusal:
            note("postcondition_failed")
            return False
    if phase == "kill-wireguard":
        before = read_wg0_state(client, name)
        if before["status"] == "present" and before["ifindex"] is not None:
            wg0_before = before["ifindex"]
            record["preconditions"] = {
                "wg0_ifindex": wg0_before,
                "container_running": True,
            }
        else:
            note("postcondition_failed")
            return False
    record["timestamps"]["action_started"] = utc_now()
    action = client.execute("/bin/sh", ["-c", command], timeout=ACTION_TIMEOUT)
    record["action"]["exitcode"] = action.exitcode
    record["timestamps"]["action_finished"] = utc_now()
    if action.exitcode != 0:
        return False
    if phase == "start-router":
        try:
            wait_router_ready(client, name, require_tailscale=False)
        except hostcheck.Refusal:
            note("router_not_ready")
            return False
        record["setup"]["active"] = True
        record_tailscale_state(record, client, name)
    elif phase == "restart-docker":
        try:
            new_pid = wait_docker_restarted(client, docker_pid_before)
            record["postcondition"] = {
                "command": "docker daemon restart",
                "exitcode": 0,
                "docker_pid_before": docker_pid_before,
                "docker_pid_after": new_pid,
            }
            wait_router_ready(client, name, require_tailscale=True)
        except hostcheck.Refusal:
            note("postcondition_failed")
            return False
    elif phase == "kill-wireguard" and wg0_before is not None:
        proof = check_kill_wireguard(client, name, before_ifindex=wg0_before)
        record["postcondition"] = {
            "command": wg0_state_command(name),
            "exitcode": 0 if proof["ok"] else 1,
            **proof,
        }
        if not proof["ok"]:
            note("postcondition_failed")
            return False
    elif phase in FAULT_PHASES:
        command = postcondition_command(phase, name)
        record["postcondition"]["command"] = command
        check = client.execute("/bin/sh", ["-c", command], timeout=ACTION_TIMEOUT)
        record["postcondition"]["exitcode"] = check.exitcode
        if check.exitcode != 0:
            note("postcondition_failed")
            return False
    return True


def run_phase(arguments: argparse.Namespace) -> int:
    require_root()
    install_signal_handlers()
    if arguments.phase not in PHASES:
        raise hostcheck.Refusal(f"unknown phase {arguments.phase}")
    name = guest.validate_name(arguments.name)
    client_number = getattr(arguments, "client", None)
    if client_number is not None:
        guest.validate_client_index(client_number)
        if arguments.phase == "login":
            raise hostcheck.Refusal("login does not take --client; use client-login")
    else:
        if arguments.phase == "client-login":
            raise hostcheck.Refusal("client-login requires --client N")
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
    if (
        arguments.phase != "client-login"
        and arguments.profile_fd is None
        and arguments.profile_file is None
    ):
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
        if client_number is not None:
            return _run_client_phase_locked(arguments, lifecycle=lifecycle)
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
    parser.add_argument(
        "--client",
        type=int,
        metavar="N",
        help="run the M3 client VM N (1..9) alongside the router",
    )
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
