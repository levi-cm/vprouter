#!/usr/bin/env python3
"""Pure generators for the vprlab leak-lab VM (QEMU argv, cloud-init, units).

Nothing in this module executes a command.  The runners in this directory call
these functions after their own precondition checks.  Keeping the argv, the
cloud-init user-data and the guest-side scripts here makes them reviewable and
unit-testable without QEMU, root, or a network.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import pathlib
import re
import shlex

# ---------------------------------------------------------------------------
# Fixed lab facts

#: Root-owned layout (controller decision A).  Nothing under
#: ``/DATA/vprouter-lab`` is used at runtime: that tree is owned by the
#: interactive operator and can be renamed at any time.
BASE_IMAGE = pathlib.Path(
    "/var/lib/vprlab/images/debian-13-genericcloud-amd64-20261021-2638.qcow2"
)
BASE_IMAGE_SHA512 = (
    "16e0965312c56feb331049d45d2b1b5778f3f942a33d4300eedbb97527707f2bea"
    "87c0006f3e4cc7a25fadbff739c4e235a51fb9bcd1b66fd554f7f8e80ba45c"
)
CHECKSUM_MANIFEST = pathlib.Path("/var/lib/vprlab/images/SHA512SUMS")
LAB_TOOLS = pathlib.Path("/opt/vprlab-tools")
QEMU = LAB_TOOLS / "usr/bin/qemu-system-x86_64"
QEMU_IMG = LAB_TOOLS / "usr/bin/qemu-img"
GENISOIMAGE = LAB_TOOLS / "usr/bin/genisoimage"
LAB_LIBRARY_DIR = LAB_TOOLS / "usr/lib/x86_64-linux-gnu"
QEMU_MODULE_DIR = LAB_LIBRARY_DIR / "qemu"
QEMU_SHARE_DIR = LAB_TOOLS / "usr/share/qemu"
#: Debian resolves bios-256k.bin through an absolute system symlink into
#: /usr/share/seabios, which the staged tree does not carry; name the staged
#: SeaBIOS image explicitly (found live on 2026-11-09).
QEMU_BIOS = LAB_TOOLS / "usr/share/seabios/bios-256k.bin"

STATE_ROOT = pathlib.Path("/var/lib/vprlab")
EVIDENCE_ROOT = STATE_ROOT / "evidence"
RELEASE_DIR = pathlib.Path("/opt/vprouter/current")
#: Dedicated system account, member of ``kvm`` only.  Created by hostsetup.py.
QEMU_USER = "vprlab-qemu"
#: Groups that must never contain the QEMU account.  Membership in any group
#: other than its own primary group and ``kvm`` is refused.
QEMU_FORBIDDEN_GROUPS = frozenset(
    {"sudo", "wheel", "adm", "docker", "lxd", "libvirt", "disk"}
)
QEMU_ALLOWED_EXTRA_GROUPS = frozenset({"kvm"})

BRIDGE = "vprlab0"
TAP = "vprlab-tap0"
VM_MAC = "52:54:00:76:70:02"
PROVISION_MAC = "52:54:00:76:70:99"
GATEWAY_MAC = "52:54:00:76:70:01"
VM_IPV4 = "10.250.0.2"
GATEWAY_IPV4 = "10.250.0.1"
WAN_DEVICE = "eth0"
VM_SUBNET = ipaddress.IPv4Network("10.250.0.0/24")

#: M3 client lab.  A client never shares the router bridge and never
#: advertises an exit node or routes.  It runs at 256 MiB and one vCPU.
CLIENT_BRIDGE = "vprlab1"
CLIENT_TAP_PREFIX = "vprlab-ctap"
CLIENT_BRIDGE_MAC = "52:54:00:76:71:01"
CLIENT_PROVISION_MAC = "52:54:00:76:71:99"
CLIENT_SUBNET = ipaddress.IPv4Network("10.251.0.0/24")
CLIENT_GATEWAY_IPV4 = "10.251.0.1"
CLIENT_MEMORY_MIB = 256
CLIENT_PROVISION_MEMORY_MIB = 384
CLIENT_OVERLAY_SIZE = "3G"
# The overlay may not be smaller than the 3 GiB base image: a smaller
# virtual disk cuts the root partition off its end (live 2026-11-09: the
# client initramfs dropped to a shell, "PARTUUID ... does not exist").
CLIENT_OVERLAY_VIRTUAL_SIZE = 3 * 1024 * 1024 * 1024
MAX_CLIENT_INDEX = 9
DEFAULT_CLIENT_INDEX = 1
CLIENT_DEFAULT_NAME = "zz-vprclient-01-do-not-use"
CLIENT_PROBE_DIR = "/var/lib/vprlab"
CLIENT_PROBE_LOG = "/var/lib/vprlab/client-probe.jsonl"
CLIENT_TRAFFIC_SCRIPT = "/usr/local/sbin/vprlab-client-traffic"
CLIENT_TRAFFIC_UNIT = "vprlab-client-traffic"
CLIENT_LOGIN_UNIT = "vprlab-client-login"
CLIENT_TAILSCALED = "/usr/local/sbin/tailscaled"
CLIENT_TAILSCALE = "/usr/local/sbin/tailscale"
CLIENT_TAILSCALE_STATE = "/var/lib/tailscale/tailscaled.state"
TAILSCALE_TARBALL_NAME = "tailscale_1.104.5_amd64.tgz"
TAILSCALE_TARBALL_SHA256 = (
    "720cbbccbfc03d8b55df72afc19e5a72e31b0f65934700aa6fa38074d4ad7bf7"
)
MIB = 1024 * 1024

DEFAULT_NAME = "zz-vprtest-01-do-not-use"
DEFAULT_INDEX = 1
#: The deployed host runs Docker 29 with the containerd image store, whose
#: image ID is the OCI *index* digest.  The guest's Docker 26 uses the classic
#: store, whose image ID is the *config* digest of the same image.  Provision
#: hash-verifies the saved tar's index -> manifest -> config chain, so the
#: guest ID below is cryptographically bound to the host index digest
#: (found live on 2026-11-09).
DEPLOYED_IMAGE_INDEX_DIGEST = (
    "sha256:62c283e6a4d350992ed2b9a99a48c7834e60e1c9af92f9e1699a2b2d0c920de3"
)
DEPLOYED_IMAGE_ID = (
    "sha256:9ed5a99d20587da5a0203c90bdc5984bdb78997025e0b8b9c50da4e43f13c61a"
)

TRUSTED_RELEASE_FILES = (
    "Dockerfile",
    "docker-compose.yaml",
    "router.nft",
    "router_runtime.py",
    "host/orchestrate.py",
)
UNIT_SOURCE = "host/vprouter@.service"

SERIAL_FILE = "serial.log"
QEMU_LOG_FILE = "qemu.log"
PID_FILE = "qemu.pid"
QGA_SOCKET = "qga.sock"
OVERLAY_FILE = "guest.qcow2"
SEED_ISO = "seed.iso"
PAYLOAD_ISO = "payload.iso"
PAYLOAD_LABEL = "VPRLABPAYLOAD"
SEED_LABEL = "cidata"

CAPTURE_FILE = "capture.pcap"
CAPTURE_STATS_FILE = "capture.pcap.stderr"
CAPTURE_ARGV_FILE = "capture-argv.json"
SCAN_REPORT_FILE = "scan.json"
PHASE_RECORD_FILE = "phase.json"

#: M3 client evidence.  The client capture is bound exactly like the router
#: capture, and its report is a separate root-only file.
CLIENT_CAPTURE_FILE = "client-capture.pcap"
CLIENT_CAPTURE_STATS_FILE = "client-capture.pcap.stderr"
CLIENT_CAPTURE_ARGV_FILE = "client-capture-argv.json"
CLIENT_PROBE_FILE = "client-probe.jsonl"
CLIENT_SCAN_REPORT_FILE = "client-scan.json"

SANDBOX = "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny"

BOOT_CONTROL_UNIT = "vprlab-boot-control.service"
BOOT_CONTROL_UNIT_PATH = "/etc/systemd/system/" + BOOT_CONTROL_UNIT
BOOT_CONTROL_SCRIPT = "/usr/local/sbin/vprlab-boot-control.py"
#: Persistent, root-only staging area.  ``/run`` is recreated by the reboot
#: that this one-shot unit exists to observe, so the specification must not
#: live there (review I1).
BOOT_CONTROL_DIR = "/var/lib/vprlab"
BOOT_CONTROL_SPEC = BOOT_CONTROL_DIR + "/boot-control.json"
BOOT_CONTROL_SENT = BOOT_CONTROL_DIR + "/boot-control-sent"

ROUTER_UNIT_TEMPLATE = "/etc/systemd/system/vprouter@.service"

#: Units that must never run on the test boot.  "mask" is stronger than
#: "disable": a package or dependency cannot re-enable a masked unit.
#: Debian 13 ships cloud-init 25.x, whose active names are ``cloud-init-main``
#: and ``cloud-init-network``; the old ``cloud-init.service`` name still appears
#: for compatibility and is harmless when absent.
SILENCE_MASK_UNITS = (
    "systemd-timesyncd.service",
    "apt-daily.timer",
    "apt-daily.service",
    "apt-daily-upgrade.timer",
    "apt-daily-upgrade.service",
    "unattended-upgrades.timer",
    "unattended-upgrades.service",
    "man-db.timer",
    "e2scrub_all.timer",
    "e2scrub_reap.service",
    "fstrim.timer",
    "systemd-resolved.service",
    "ssh.service",
    "ssh.socket",
    "sshd.service",
    "dhclient.service",
    "dhcpcd.service",
    "NetworkManager.service",
    "NetworkManager-wait-online.service",
    "networking.service",
    "ifupdown-wait-online.service",
    "ifup@.service",
    "chrony.service",
    "chronyd.service",
    "ntp.service",
    "ntpsec.service",
    "openntpd.service",
    "cloud-init.service",
    "cloud-init-local.service",
    "cloud-init-main.service",
    "cloud-init-network.service",
    "cloud-config.service",
    "cloud-final.service",
    "cloud-init-hotplugd.service",
    "cloud-init-hotplugd.socket",
)

_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{1,49}$")
_MAC_RE = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")
_IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class GeneratorError(ValueError):
    """A supplied value would produce an unsafe or ambiguous artifact."""


class IntegrityError(RuntimeError):
    """The verified base image does not match its published checksum."""


# ---------------------------------------------------------------------------
# Validation and hashing


def validate_name(name: str) -> str:
    if not isinstance(name, str) or _NAME_RE.fullmatch(name) is None:
        raise GeneratorError(
            "router name must match [a-z][a-z0-9-]{1,49} (orchestrate.py rule)"
        )
    return name


def validate_mac(mac: str) -> str:
    if not isinstance(mac, str) or _MAC_RE.fullmatch(mac.lower()) is None:
        raise GeneratorError("MAC address must be six colon-separated hex octets")
    return mac.lower()


def validate_image_id(image_id: str) -> str:
    if not isinstance(image_id, str) or _IMAGE_ID_RE.fullmatch(image_id) is None:
        raise GeneratorError("image ID must be sha256:<64 lowercase hex characters>")
    return image_id


def sha512_file(path: pathlib.Path) -> str:
    digest = hashlib.sha512()
    with pathlib.Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_base_image(
    base: pathlib.Path = BASE_IMAGE,
    manifest: pathlib.Path = CHECKSUM_MANIFEST,
    *,
    expected_digest: str = BASE_IMAGE_SHA512,
) -> str:
    """Hash ``base`` and require it to equal both the manifest and the pin."""
    base = pathlib.Path(base)
    manifest = pathlib.Path(manifest)
    if not base.is_file():
        raise IntegrityError(f"base image missing: {base}")
    if not manifest.is_file():
        raise IntegrityError(f"checksum manifest missing: {manifest}")
    digest = sha512_file(base)
    if digest != expected_digest:
        raise IntegrityError("base image SHA-512 does not match the pinned digest")
    matches: list[str] = []
    for line in manifest.read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if fields and fields[-1].lstrip("*") == base.name:
            matches.append(fields[0].lower())
    if matches != [digest]:
        raise IntegrityError(
            "base image SHA-512 does not match the checksum manifest entry"
        )
    return digest


def state_path(index: int = DEFAULT_INDEX, root: pathlib.Path = STATE_ROOT) -> pathlib.Path:
    if isinstance(index, bool) or not isinstance(index, int) or not 1 <= index <= 99:
        raise GeneratorError("index must be an integer in 1..99")
    return pathlib.Path(root) / f"vm-{index:03d}"


def validate_client_index(index: int) -> int:
    """Validate client N (1..9): tap names, MACs and addresses derive from it."""
    if isinstance(index, bool) or not isinstance(index, int):
        raise GeneratorError("client index must be an integer in 1..9")
    if not 1 <= index <= MAX_CLIENT_INDEX:
        raise GeneratorError(f"client index must be in 1..{MAX_CLIENT_INDEX}")
    return index


def client_state_path(
    index: int = DEFAULT_CLIENT_INDEX, root: pathlib.Path = STATE_ROOT
) -> pathlib.Path:
    validate_client_index(index)
    return pathlib.Path(root) / f"client-{index:03d}"


def client_tap(index: int = DEFAULT_CLIENT_INDEX) -> str:
    return f"{CLIENT_TAP_PREFIX}{validate_client_index(index)}"


def client_mac(index: int = DEFAULT_CLIENT_INDEX) -> str:
    return f"52:54:00:76:71:{validate_client_index(index) + 1:02x}"


def client_ipv4(index: int = DEFAULT_CLIENT_INDEX) -> str:
    return f"10.251.0.{validate_client_index(index) + 1}"


def client_name(index: int = DEFAULT_CLIENT_INDEX) -> str:
    validate_client_index(index)
    return f"zz-vprclient-{index:02d}-do-not-use"


# ---------------------------------------------------------------------------
# QEMU


def clean_environment() -> dict[str, str]:
    """Return a loader-clean environment for the trusted ``setpriv`` binary.

    ``setpriv`` resolves its own shared libraries before it can drop
    privileges, so it must never see ``LD_LIBRARY_PATH`` pointing at an
    operator-owned directory.  The staged QEMU library/module variables are
    applied by ``/usr/bin/env -i`` only after ``setpriv --``.
    """
    return {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
    }


def staged_env_argv() -> list[str]:
    """Return the post-drop ``env -i`` prefix for the staged tool tree."""
    return [
        "/usr/bin/env",
        "-i",
        "LD_LIBRARY_PATH=" + str(LAB_LIBRARY_DIR),
        "QEMU_MODULE_DIR=" + str(QEMU_MODULE_DIR),
    ]


def build_qemu_argv(
    mode: str,
    state: pathlib.Path,
    *,
    name: str = DEFAULT_NAME,
    tap: str = TAP,
    memory_mib: int = 512,
    mac: str = VM_MAC,
    provision_mac: str = PROVISION_MAC,
) -> list[str]:
    """Return the exact QEMU argv for ``provision`` or ``test`` mode.

    Provision mode has only a user-mode netdev and is never attached to the
    lab tap.  Test mode has only the pre-created tap and never a user netdev,
    seed or payload ISO.  Client boots pass their own memory size and MACs;
    the defaults are the unchanged router lab.
    """
    if mode not in {"provision", "test"}:
        raise GeneratorError("mode must be 'provision' or 'test'")
    validate_name(name)
    if isinstance(memory_mib, bool) or not isinstance(memory_mib, int):
        raise GeneratorError("memory_mib must be an integer")
    if not 64 <= memory_mib <= 16384:
        raise GeneratorError("memory_mib must be in 64..16384")
    mac = validate_mac(mac)
    provision_mac = validate_mac(provision_mac)
    state = pathlib.Path(state)
    overlay = state / OVERLAY_FILE

    argv = [
        str(QEMU),
        "-nodefaults",
        "-no-user-config",
        "-accel",
        "kvm",
        "-machine",
        "pc,smm=off",
        "-cpu",
        "host",
        "-smp",
        "1",
        "-m",
        str(memory_mib),
        "-name",
        f"vprlab-{name}",
        "-drive",
        # bootindex=0: in provision mode the payload ISO is a second
        # virtio-blk disk and SeaBIOS would otherwise try to boot it and
        # hang silently (found live on 2026-11-09).
        f"file={overlay},if=none,id=root,format=qcow2",
        "-device",
        "virtio-blk-pci,drive=root,bootindex=0",
        # Explicitly suppress QEMU's implicit default NIC, so the only NIC is
        # the one declared below.
        "-nic",
        "none",
    ]

    if mode == "provision":
        argv += [
            "-netdev",
            "user,id=wan",
            "-device",
            f"virtio-net-pci,netdev=wan,romfile=,mac={provision_mac}",
            "-drive",
            f"file={state / SEED_ISO},media=cdrom,readonly=on",
            # The payload ISO is a plain read-only virtio disk, independent of
            # the cloud-init seed drive.
            "-drive",
            f"file={state / PAYLOAD_ISO},if=none,id=payload,format=raw,readonly=on",
            "-device",
            "virtio-blk-pci,drive=payload,romfile=",
        ]
    else:
        argv += [
            "-netdev",
            f"tap,id=wan,ifname={tap},script=no,downscript=no",
            "-device",
            f"virtio-net-pci,netdev=wan,romfile=,mac={mac}",
        ]

    # Test boots write no serial file at all: the guest is untrusted and a
    # compromised guest could otherwise fill the host filesystem through the
    # emulated UART.  Provisioning needs the console marker and uses a file
    # that is size-capped and RLIMIT_FSIZE-bounded there.
    serial = f"file:{state / SERIAL_FILE}" if mode == "provision" else "none"
    argv += [
        "-display",
        "none",
        "-serial",
        serial,
        "-pidfile",
        str(state / PID_FILE),
        # No QMP socket: it is unused by the lab and would let any local
        # process attach an uncaptured NIC (review M3/pi I12).
        "-chardev",
        f"socket,id=qga0,path={state / QGA_SOCKET},server=on,wait=off",
        "-device",
        "virtio-serial",
        "-device",
        "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0",
        "-sandbox",
        SANDBOX,
        "-L",
        str(QEMU_SHARE_DIR),
        "-bios",
        str(QEMU_BIOS),
    ]
    return argv


def verify_qemu_account(
    user: str = QEMU_USER,
    *,
    pwd_record: object | None = None,
    group_records: list[object] | None = None,
) -> tuple[int, int, str]:
    """Refuse QEMU accounts with root or privileged-group access.

    ``pwd_record`` needs ``pw_uid``/``pw_gid``/``pw_name``; group records need
    ``gr_name``, ``gr_gid`` and ``gr_mem``.  The defaults are read from the
    live host.  Membership is refused for uid 0, any explicitly forbidden
    group, and every supplementary group except ``kvm``.
    """
    import grp
    import pwd

    if pwd_record is None:
        try:
            pwd_record = pwd.getpwnam(user)
        except KeyError as exc:
            raise GeneratorError(f"unknown unprivileged user {user!r}") from exc
    uid = int(getattr(pwd_record, "pw_uid"))
    gid = int(getattr(pwd_record, "pw_gid"))
    if uid == 0:
        raise GeneratorError("QEMU must never run as uid 0")
    records = group_records if group_records is not None else list(grp.getgrall())
    primary = getattr(pwd_record, "pw_name", user)
    for record in records:
        name = str(getattr(record, "gr_name", ""))
        members = getattr(record, "gr_mem", [])
        if not isinstance(members, (list, tuple)):
            continue
        if user not in members and not (name == primary and int(getattr(record, "gr_gid", -1)) == gid):
            continue
        if name in QEMU_FORBIDDEN_GROUPS:
            raise GeneratorError(
                f"QEMU user {user!r} must not be a member of {name!r}"
            )
        if name == primary:
            continue
        if name not in QEMU_ALLOWED_EXTRA_GROUPS:
            raise GeneratorError(
                f"QEMU user {user!r} has an unexpected supplementary group {name!r}"
            )
    return uid, gid, primary


def resolve_unprivileged_user(user: str = QEMU_USER) -> tuple[int, int]:
    """Return ``(uid, gid)`` for a validated non-root, kvm-only account."""
    uid, gid, _primary = verify_qemu_account(user)
    return uid, gid


def verify_tool_ancestry(tools: pathlib.Path = LAB_TOOLS) -> None:
    """Refuse a staged tool tree below an operator-writable directory."""
    import rootfs

    if os.geteuid() != 0:
        # Offline tests run as the operator; the production caller is root and
        # must validate every ancestor.
        return
    try:
        rootfs.validate_ancestry(tools, expected_uid=0)
    except rootfs.PathError as exc:
        raise GeneratorError(f"staged tool tree is not root-trusted: {exc}") from exc


def build_setpriv_argv(
    argv: list[str],
    uid: int,
    gid: int,
    *,
    setpriv: str = "/usr/bin/setpriv",
) -> list[str]:
    """Wrap ``argv`` in setpriv with every extra privilege removed.

    The trusted setpriv itself runs with the caller's clean environment.  The
    staged QEMU library/module variables are only set by ``env -i`` after the
    privilege drop, so the dynamic loader can never resolve setpriv's own
    dependencies from an operator-owned directory.
    """
    if isinstance(uid, bool) or isinstance(gid, bool):
        raise GeneratorError("uid and gid must be integers")
    if not isinstance(uid, int) or not isinstance(gid, int):
        raise GeneratorError("uid and gid must be integers")
    if uid == 0:
        raise GeneratorError("QEMU and its tools must never run as uid 0")
    return [
        setpriv,
        f"--reuid={uid}",
        f"--regid={gid}",
        # Keep exactly the validated account's supplementary groups (``kvm``)
        # so the dedicated QEMU user can open /dev/kvm; never inherit the
        # caller's groups.
        "--init-groups",
        "--no-new-privs",
        "--inh-caps=-all",
        "--bounding-set=-all",
        "--",
    ] + staged_env_argv() + list(argv)


def build_private_tool_argv(
    argv: list[str], uid: int, gid: int, *, umask: int = 0o077
) -> list[str]:
    """Run a generator tool as the QEMU user with a private umask."""
    if not 0 <= umask <= 0o777:
        raise GeneratorError("umask must be an octal mode")
    return build_setpriv_argv(
        ["/bin/sh", "-c", f"umask {umask:03o}; exec \"$@\"", "vprlab-tool", *argv],
        uid,
        gid,
    )


def build_launch_argv(
    qemu_argv: list[str],
    user: str = QEMU_USER,
    *,
    uid: int | None = None,
    gid: int | None = None,
    setpriv: str = "/usr/bin/setpriv",
) -> list[str]:
    """Wrap ``qemu_argv`` so QEMU runs as an unprivileged account."""
    if (uid is None) != (gid is None):
        raise GeneratorError("uid and gid must be supplied together")
    if uid is None:
        uid, gid = resolve_unprivileged_user(user)
    return build_setpriv_argv(list(qemu_argv), int(uid), int(gid), setpriv=setpriv)


def build_qemu_img_create_argv(
    base: pathlib.Path, overlay: pathlib.Path, *, size: str = "4G"
) -> list[str]:
    if not isinstance(size, str) or re.fullmatch(r"[1-9][0-9]{0,3}[GgMm]", size) is None:
        raise GeneratorError("overlay size must be a positive size such as 2G")
    return [
        str(QEMU_IMG),
        "create",
        "-f",
        "qcow2",
        "-F",
        "qcow2",
        "-b",
        str(base),
        str(overlay),
        size,
    ]


def build_qemu_img_info_argv(overlay: pathlib.Path) -> list[str]:
    return [
        str(QEMU_IMG),
        "info",
        "-U",
        "--output=json",
        "--backing-chain",
        str(overlay),
    ]


def verify_overlay_chain(
    document: object, overlay: pathlib.Path, base: pathlib.Path = BASE_IMAGE
) -> None:
    """Refuse a qcow2 that is not a one-level overlay of the verified base."""
    if not isinstance(document, list) or len(document) != 2:
        raise IntegrityError("overlay is not a single-level qcow2 backing chain")
    top, parent = document
    if not isinstance(top, dict) or not isinstance(parent, dict):
        raise IntegrityError("qemu-img returned a malformed backing chain")
    if top.get("format") != "qcow2" or parent.get("format") != "qcow2":
        raise IntegrityError("every backing-chain layer must be qcow2")
    if pathlib.Path(str(top.get("filename", ""))).resolve() != overlay.resolve():
        raise IntegrityError("backing chain does not start at the state overlay")
    parent_name = top.get("full-backing-filename") or top.get("backing-filename")
    if not parent_name or pathlib.Path(str(parent_name)).resolve() != base.resolve():
        raise IntegrityError("overlay is not backed by the verified base image")
    if pathlib.Path(str(parent.get("filename", ""))).resolve() != base.resolve():
        raise IntegrityError("backing chain parent is not the verified base image")
    if parent.get("backing-filename"):
        raise IntegrityError("the verified base image must not have its own backing file")
    top_size, base_size = top.get("virtual-size"), parent.get("virtual-size")
    for size in (top_size, base_size):
        if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
            raise IntegrityError("qemu-img did not report a virtual size")
    if top_size < base_size:
        raise IntegrityError(
            "the overlay is smaller than its base image and would cut off the root partition"
        )


# ---------------------------------------------------------------------------
# ISO generation


def build_seed_iso_argv(output: pathlib.Path, user_data: pathlib.Path, meta_data: pathlib.Path) -> list[str]:
    return [
        str(GENISOIMAGE),
        "-quiet",
        "-output",
        str(output),
        "-volid",
        SEED_LABEL,
        "-joliet",
        "-rock",
        str(user_data),
        str(meta_data),
    ]


def build_payload_iso_argv(output: pathlib.Path, staging: pathlib.Path) -> list[str]:
    return [
        str(GENISOIMAGE),
        "-quiet",
        "-output",
        str(output),
        "-volid",
        PAYLOAD_LABEL,
        "-joliet",
        "-rock",
        str(staging),
    ]


# ---------------------------------------------------------------------------
# Guest-side artifacts

_NETWORK_TEXT = """[Match]
MACAddress=@@VM_MAC@@

[Network]
DHCP=no
LinkLocalAddressing=no
IPv6AcceptRA=no
LLDP=no
EmitLLDP=no
Address=@@VM_IPV4@@/24
Gateway=@@GATEWAY_IPV4@@

[Neighbor]
Address=@@GATEWAY_IPV4@@
LinkLayerAddress=@@GATEWAY_MAC@@
"""

_DOCKER_DAEMON = {
    "ipv6": False,
    "ip6tables": False,
    "dns": [],
    "log-driver": "local",
}


def docker_daemon_text() -> str:
    return json.dumps(_DOCKER_DAEMON, sort_keys=True, separators=(",", ":")) + "\n"


def networkd_text() -> str:
    return (
        _NETWORK_TEXT.replace("@@VM_MAC@@", VM_MAC)
        .replace("@@VM_IPV4@@", VM_IPV4)
        .replace("@@GATEWAY_IPV4@@", GATEWAY_IPV4)
        .replace("@@GATEWAY_MAC@@", GATEWAY_MAC)
    )


def client_networkd_text(index: int = DEFAULT_CLIENT_INDEX) -> str:
    """Return the MAC-matched static network file for one client VM."""
    return (
        _NETWORK_TEXT.replace("@@VM_MAC@@", client_mac(index))
        .replace("@@VM_IPV4@@", client_ipv4(index))
        .replace("@@GATEWAY_IPV4@@", CLIENT_GATEWAY_IPV4)
        .replace("@@GATEWAY_MAC@@", CLIENT_BRIDGE_MAC)
    )


def grub_dropin_text(ipv6_mode: str = "netns-safe") -> str:
    if ipv6_mode not in {"kernel-disable", "netns-safe"}:
        raise GeneratorError("ipv6_mode must be kernel-disable or netns-safe")
    if ipv6_mode == "kernel-disable":
        return (
            "# vprlab leak lab: no IPv6 and a deterministic WAN interface name.\n"
            'GRUB_CMDLINE_LINUX="${GRUB_CMDLINE_LINUX} ipv6.disable=1 net.ifnames=0"\n'
            'GRUB_CMDLINE_LINUX_DEFAULT="${GRUB_CMDLINE_LINUX_DEFAULT} ipv6.disable=1 net.ifnames=0"\n'
        )
    return (
        "# vprlab leak lab: IPv6 is disabled per interface, not kernel-wide.\n"
        "# The deployed compose writes net.ipv6.conf.all.forwarding, which needs\n"
        "# the IPv6 sysctl tree to exist (see docs/rust-v2/leak-lab-vm.md).\n"
        'GRUB_CMDLINE_LINUX="${GRUB_CMDLINE_LINUX} net.ifnames=0"\n'
        'GRUB_CMDLINE_LINUX_DEFAULT="${GRUB_CMDLINE_LINUX_DEFAULT} net.ifnames=0"\n'
    )


def ipv6_sysctl_text() -> str:
    return (
        "# vprlab leak lab: the release's compose needs the IPv6 sysctl tree,\n"
        "# but no guest interface may carry an IPv6 address or accept an RA.\n"
        "net.ipv6.conf.all.disable_ipv6=1\n"
        "net.ipv6.conf.default.disable_ipv6=1\n"
        "net.ipv6.conf.lo.disable_ipv6=1\n"
        "net.ipv6.conf.all.accept_ra=0\n"
        "net.ipv6.conf.default.accept_ra=0\n"
    )


def resolved_dropin_text() -> str:
    return (
        "[Resolve]\n"
        "LLMNR=no\n"
        "MulticastDNS=no\n"
        "DNSStubListener=no\n"
    )


def boot_control_unit_text() -> str:
    """The one-shot unit that must win the race to be the first frame."""
    return f"""[Unit]
Description=vprlab one-shot boot control (nonce)
DefaultDependencies=no
After=systemd-networkd.service
Before=network-online.target docker.service
Wants=systemd-networkd.service

[Service]
Type=oneshot
ExecStart={BOOT_CONTROL_SCRIPT}
RemainAfterExit=no

[Install]
WantedBy=multi-user.target
"""


def boot_control_script_text() -> str:
    """Guest-side sender for the boot-phase BEFORE control.

    The nonce, boot token and sink are read from a mode-0600 persistent file
    (``/var/lib/vprlab``); ``/run`` is recreated by the reboot this unit exists
    to observe.  The datagram is sent once with ``SO_BINDTODEVICE``, the token
    is written to the sent marker, and the specification is unlinked.
    """
    return '''#!/usr/bin/env python3
"""One-shot vprlab boot control: send the staged nonce, then delete it."""
import json
import os
import socket
import subprocess
import time

SPEC = "@@SPEC@@"
SENT = "@@SENT@@"
PREFIX = b"VPRLEAKCTL1:"


def find_interface(mac):
    for name in sorted(os.listdir("/sys/class/net")):
        try:
            with open("/sys/class/net/" + name + "/address", encoding="ascii") as stream:
                if stream.read().strip().lower() == mac.lower():
                    return name
        except OSError:
            continue
    return None


def main():
    with open(SPEC, encoding="ascii") as stream:
        spec = json.load(stream)
    interface = spec.get("device") or find_interface(spec["vm_mac"])
    if not interface:
        raise SystemExit("vprlab boot control: interface not found")
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        result = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "dev", interface],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if spec["vm_ipv4"] + "/" in result.stdout:
            break
        time.sleep(0.1)
    else:
        raise SystemExit("vprlab boot control: static address not ready")
    nonce = spec["nonce"]
    if len(nonce) != 32 or any(ch not in "0123456789abcdef" for ch in nonce):
        raise SystemExit("vprlab boot control: invalid nonce")
    token = spec.get("boot_token", "")
    if len(token) != 32 or any(ch not in "0123456789abcdef" for ch in token):
        raise SystemExit("vprlab boot control: invalid boot token")
    payload = PREFIX + nonce.encode("ascii")
    channel = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    channel.setsockopt(
        socket.SOL_SOCKET,
        getattr(socket, "SO_BINDTODEVICE", 25),
        interface.encode("ascii") + b"\\x00",
    )
    channel.bind((spec["vm_ipv4"], 0))
    channel.sendto(payload, (spec["sink_ipv4"], int(spec["sink_udp_port"])))
    channel.close()
    descriptor = os.open(SENT, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as stream:
        stream.write(token + "\\n")
    os.unlink(SPEC)


if __name__ == "__main__":
    main()
'''.replace("@@SPEC@@", BOOT_CONTROL_SPEC).replace("@@SENT@@", BOOT_CONTROL_SENT)


def boot_control_spec(
    nonce: str,
    sink_ipv4: str,
    sink_udp_port: int,
    *,
    boot_token: str,
    vm_ipv4: str = VM_IPV4,
    vm_mac: str = VM_MAC,
    device: str = "",
) -> str:
    if not re.fullmatch(r"[0-9a-f]{32}", nonce):
        raise GeneratorError("boot control nonce must be 32 lowercase hex characters")
    if not re.fullmatch(r"[0-9a-f]{32}", boot_token):
        raise GeneratorError("boot token must be 32 lowercase hex characters")
    if ipaddress.IPv4Address(sink_ipv4) != ipaddress.IPv4Address(GATEWAY_IPV4):
        raise GeneratorError("boot control sink must be the lab gateway")
    if isinstance(sink_udp_port, bool) or not 1 <= int(sink_udp_port) <= 65535:
        raise GeneratorError("boot control sink port is invalid")
    if device and not re.fullmatch(r"[A-Za-z0-9_.:@-]{1,15}", device):
        raise GeneratorError("boot control device name is invalid")
    return (
        json.dumps(
            {
                "boot_token": boot_token,
                "device": device,
                "nonce": nonce,
                "sink_ipv4": sink_ipv4,
                "sink_udp_port": int(sink_udp_port),
                "vm_ipv4": vm_ipv4,
                "vm_mac": validate_mac(vm_mac),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )


_CLIENT_TRAFFIC_SCRIPT = r'''#!/usr/bin/env python3
"""vprlab M3 client traffic: continuous HTTPS exit and HTTP marker probes.

Every loop appends at most two JSON lines to the probe log.  Every line carries
the phase marker id (``r``) and a gap-free sequence number (``s``).  It never
records the reported IP or location: only the Mullvad boolean is kept.

Cadence: each probe is ``curl -m 4`` (4.5 s subprocess backstop) and the loop
sleeps 2 s, so consecutive exit attempts are at most about 11 s apart even
with the backstop (Opus R5 m-3: at least 1 s of margin under the shortest
12 s coverage window).  The runner's host-sampled coverage windows (12-15 s) are
longer than that, so every window holds a completed exit attempt even while
the exit node is down.
"""
import json
import os
import re
import subprocess
import sys
import time

LOG = "@@PROBE_LOG@@"
MAX_LOG = 1024 * 1024
CURL_MAX_TIME = "4"
PROBE_BACKSTOP = 4.5
LOOP_SLEEP = 2.0
MARKER_RE = re.compile(r"^VPRCLIENTMARK1:([0-9a-f]{32})$")


def write_document(document):
    payload = (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")
    descriptor = os.open(LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        if os.fstat(descriptor).st_size + len(payload) > MAX_LOG:
            return False
        os.write(descriptor, payload)
        return True
    finally:
        os.close(descriptor)


def emit(state, document, stamp):
    sequence = state["s"]
    line = dict(document, r=state["r"], s=sequence, t=stamp)
    if write_document(line):
        state["s"] = sequence + 1
        return True
    overflow = {"k": "overflow", "r": state["r"], "s": sequence, "t": stamp}
    if write_document(overflow):
        state["s"] = sequence + 1
    state["overflow"] = True
    return False


def exit_probe(ip):
    command = [
        "curl", "-sS", "-m", CURL_MAX_TIME, "--resolve",
        "am.i.mullvad.net:443:" + ip, "https://am.i.mullvad.net/json",
    ]
    try:
        result = subprocess.run(
            command, capture_output=True, timeout=PROBE_BACKSTOP, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return {"ok": False, "m": None}
    if result.returncode != 0:
        return {"ok": False, "m": None}
    try:
        document = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"ok": False, "m": None}
    if not isinstance(document, dict):
        return {"ok": False, "m": None}
    flag = document.get("mullvad_exit_ip")
    if not isinstance(flag, bool):
        return {"ok": False, "m": None}
    return {"ok": True, "m": flag}


def marker_probe(marker, ip):
    command = [
        "curl", "-sS", "-m", CURL_MAX_TIME, "--resolve", "example.com:80:" + ip,
        "-H", "X-Vprlab-Marker: " + marker,
        "http://example.com/?vprlab=" + marker,
    ]
    try:
        result = subprocess.run(
            command, capture_output=True, timeout=PROBE_BACKSTOP, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return {"ok": False}
    return {"ok": result.returncode == 0}


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: vprlab-client-traffic MARKER HTTPS-IP HTTP-IP")
    marker, https_ip, http_ip = sys.argv[1:4]
    match = MARKER_RE.fullmatch(marker)
    if match is None:
        raise SystemExit("invalid marker")
    for value in (https_ip, http_ip):
        if re.fullmatch(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", value) is None:
            raise SystemExit("invalid probe address")
    descriptor = os.open(
        LOG, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
    )
    os.close(descriptor)
    state = {"r": match.group(1), "s": 1, "overflow": False}
    while not state["overflow"]:
        stamp = int(time.time())
        emit(state, {"k": "exit", **exit_probe(https_ip)}, stamp)
        emit(state, {"k": "marker", **marker_probe(marker, http_ip)}, stamp)
        time.sleep(LOOP_SLEEP)


if __name__ == "__main__":
    main()
'''


def client_traffic_script_text() -> str:
    """Return the guest traffic script (no argument is baked into it)."""
    return _CLIENT_TRAFFIC_SCRIPT.replace("@@PROBE_LOG@@", CLIENT_PROBE_LOG)


_CLIENT_PROVISION_SCRIPT = r'''#!/bin/sh
# vprlab M3 client provisioning: tailscale, static network, silencing, traffic
# script, then power off.  Runs once, online, from cloud-init.
set -eu

EXPECTED_TAILSCALE_SHA256="$1"
PAYLOAD_LABEL='@@PAYLOAD_LABEL@@'
TAILSCALE_TARBALL='@@TAILSCALE_TARBALL@@'
PINNED_TAILSCALE_SHA256='@@TAILSCALE_SHA256@@'

log() { printf 'vprlab-client-provision: %s\n' "$*" >&2; }
fail() {
    printf 'VPRLAB-CLIENT-PROVISION-FAILED: %s\n' "$*" >/dev/console
    if [ -w /dev/ttyS0 ]; then
        printf 'VPRLAB-CLIENT-PROVISION-FAILED: %s\n' "$*" > /dev/ttyS0
    fi
    log "$*"
    sync || true
    systemctl poweroff >/dev/null 2>&1 || true
    exit 1
}

[ "${#EXPECTED_TAILSCALE_SHA256}" -eq 64 ] || fail "tailscale sha256 has the wrong length"
case "$EXPECTED_TAILSCALE_SHA256" in
    *[!0-9a-f]*) fail "tailscale sha256 is not lowercase hex" ;;
esac
[ "$EXPECTED_TAILSCALE_SHA256" = "$PINNED_TAILSCALE_SHA256" ] \
    || fail "tailscale sha256 does not match the pinned build"

log "installing the small package set (no recommends)"
printf '%s\n' \
    'APT::Install-Recommends "false";' \
    'APT::Install-Suggests "false";' \
    > /etc/apt/apt.conf.d/99-vprlab-norecommends
DEBIAN_FRONTEND=noninteractive apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    qemu-guest-agent ca-certificates curl python3-minimal iproute2 util-linux

log "mounting the read-only payload"
install -d -m 0755 /mnt/vprlab-payload
n=0
while [ ! -e "/dev/disk/by-label/$PAYLOAD_LABEL" ]; do
    n=$((n + 1))
    [ "$n" -lt 120 ] || fail "payload ISO did not appear"
    sleep 1
done
mount -o ro "/dev/disk/by-label/$PAYLOAD_LABEL" /mnt/vprlab-payload
tarball="/mnt/vprlab-payload/$TAILSCALE_TARBALL"
[ -f "$tarball" ] || fail "tailscale tarball missing from the payload"
printf '%s  %s\n' "$EXPECTED_TAILSCALE_SHA256" "$tarball" | sha256sum -c - \
    || fail "tailscale tarball sha256 mismatch"

log "installing the pinned tailscale binaries"
# /var/tmp is on disk; /tmp is a tmpfs in RAM on Debian 13 (Opus B P-4).
rm -rf /var/tmp/vprlab-ts
install -d -m 0700 -o root -g root /var/tmp/vprlab-ts
tar -xzf "$tarball" -C /var/tmp/vprlab-ts
tailscaled=$(find /var/tmp/vprlab-ts -type f -name tailscaled | head -n 1)
tailscale=$(find /var/tmp/vprlab-ts -type f -name tailscale | head -n 1)
[ -n "$tailscaled" ] || fail "tailscaled missing from the tarball"
[ -n "$tailscale" ] || fail "tailscale missing from the tarball"
install -m 0755 "$tailscaled" @@CLIENT_TAILSCALED@@
install -m 0755 "$tailscale" @@CLIENT_TAILSCALE@@
rm -rf /var/tmp/vprlab-ts
install -d -m 0700 -o root -g root /var/lib/tailscale
cat > /etc/systemd/system/tailscaled.service <<'UNIT'
[Unit]
Description=Tailscale node agent (vprlab client)
After=network-pre.target
Wants=network-pre.target

[Service]
Type=simple
ExecStart=@@CLIENT_TAILSCALED@@ --state=@@CLIENT_TAILSCALE_STATE@@ --port=41641
Restart=on-failure
# At 256 MiB an OOM kill of tailscaled would drop tailscale0 and send client
# probes out in clear (Opus B P-2); the traffic script or curl dies first.
OOMScoreAdjust=-900
RuntimeDirectory=tailscale
RuntimeDirectoryMode=0755

[Install]
WantedBy=multi-user.target
UNIT
chmod 0644 /etc/systemd/system/tailscaled.service
systemctl daemon-reload
systemctl enable tailscaled.service
systemctl start tailscaled.service || fail "tailscaled did not start"
tailscale version >/dev/null 2>&1 || fail "tailscale binary is not runnable"

log "installing the static network configuration"
systemctl enable systemd-networkd.service >/dev/null 2>&1 || true
for artifact in \
    /etc/systemd/network/50-cloud-init.network \
    /etc/systemd/network/10-cloud-init.network \
    /etc/network/interfaces.d/50-cloud-init \
    /etc/network/interfaces.d/50-cloud-init.cfg \
    /etc/netplan/50-cloud-init.yaml \
    /etc/netplan/90-cloud-init.yaml; do
    rm -f "$artifact"
done
rm -f /etc/systemd/network/*cloud-init*.network
rm -f /etc/network/interfaces.d/*cloud-init*
rm -f /etc/netplan/*cloud-init*
for config in /etc/systemd/network/*.network; do
    [ -e "$config" ] || continue
    [ "$config" = /etc/systemd/network/10-vprlab-client.network ] && continue
    mv "$config" "$config.vprlab-disabled"
done
install -d -m 0755 /etc/systemd/network
cat > /etc/systemd/network/10-vprlab-client.network <<'EOF'
@@NETWORK@@EOF
chmod 0644 /etc/systemd/network/10-vprlab-client.network

rm -f /etc/resolv.conf
printf '# vprlab leak lab: DNS intentionally disabled\n' > /etc/resolv.conf
chmod 0644 /etc/resolv.conf

log "silencing the OS"
swapoff -a >/dev/null 2>&1 || true
if [ -f /etc/fstab ]; then
    sed -i -E 's/^([^#].*[[:space:]]swap[[:space:]].*)$/#vprlab-disabled \1/' /etc/fstab
fi
for unit in \
    systemd-timesyncd.service \
    apt-daily.timer apt-daily.service \
    apt-daily-upgrade.timer apt-daily-upgrade.service \
    unattended-upgrades.timer unattended-upgrades.service \
    man-db.timer e2scrub_all.timer e2scrub_reap.service fstrim.timer \
    systemd-resolved.service \
    ssh.service ssh.socket sshd.service \
    dhclient.service dhcpcd.service \
    NetworkManager.service NetworkManager-wait-online.service \
    networking.service ifupdown-wait-online.service ifup@.service \
    chrony.service chronyd.service ntp.service ntpsec.service openntpd.service; do
    systemctl disable --now "$unit" >/dev/null 2>&1 || true
    systemctl mask "$unit" >/dev/null 2>&1 || true
done
touch /etc/cloud/cloud-init.disabled
for unit in \
    cloud-init.service cloud-init-local.service cloud-init-main.service \
    cloud-init-network.service cloud-config.service cloud-final.service \
    cloud-init-hotplugd.service cloud-init-hotplugd.socket; do
    systemctl disable --now "$unit" >/dev/null 2>&1 || true
    systemctl mask "$unit" >/dev/null 2>&1 || true
done

install -d -m 0755 /etc/systemd/resolved.conf.d
cat > /etc/systemd/resolved.conf.d/99-vprlab.conf <<'EOF'
@@RESOLVED@@EOF
chmod 0644 /etc/systemd/resolved.conf.d/99-vprlab.conf

install -d -m 0755 /etc/sysctl.d
cat > /etc/sysctl.d/99-vprlab-ipv6.conf <<'EOF'
@@IPV6_SYSCTL@@EOF
chmod 0644 /etc/sysctl.d/99-vprlab-ipv6.conf
sysctl --system >/dev/null 2>&1 || true

install -d -m 0755 /etc/default/grub.d
cat > /etc/default/grub.d/99-vprlab-silence.cfg <<'EOF'
@@GRUB@@EOF
chmod 0644 /etc/default/grub.d/99-vprlab-silence.cfg
update-grub

log "installing the client traffic script"
install -d -m 0700 -o root -g root @@CLIENT_PROBE_DIR@@
cat > @@CLIENT_TRAFFIC_SCRIPT@@ <<'PY'
@@CLIENT_TRAFFIC_PY@@PY
chmod 0755 @@CLIENT_TRAFFIC_SCRIPT@@

log "enabling the guest agent"
systemctl enable qemu-guest-agent.service
systemctl start qemu-guest-agent.service

umount /mnt/vprlab-payload || true
sync
log "client provisioning complete"
if [ -w /dev/ttyS0 ]; then
    printf 'VPRLAB-CLIENT-PROVISION-OK %s\n' "$EXPECTED_TAILSCALE_SHA256" > /dev/ttyS0
fi
printf 'VPRLAB-CLIENT-PROVISION-OK %s\n' "$EXPECTED_TAILSCALE_SHA256" > /dev/console
systemctl poweroff
'''


def client_provision_script(
    index: int = DEFAULT_CLIENT_INDEX,
    *,
    tailscale_sha256: str = TAILSCALE_TARBALL_SHA256,
) -> str:
    """Return the guest-side client provisioning script."""
    validate_client_index(index)
    if (
        not isinstance(tailscale_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", tailscale_sha256) is None
    ):
        raise GeneratorError("tailscale sha256 must be 64 lowercase hex characters")
    script = _CLIENT_PROVISION_SCRIPT
    replacements = {
        "@@PAYLOAD_LABEL@@": PAYLOAD_LABEL,
        "@@TAILSCALE_TARBALL@@": TAILSCALE_TARBALL_NAME,
        "@@TAILSCALE_SHA256@@": tailscale_sha256,
        "@@NETWORK@@": client_networkd_text(index),
        "@@RESOLVED@@": resolved_dropin_text(),
        "@@IPV6_SYSCTL@@": ipv6_sysctl_text(),
        "@@GRUB@@": grub_dropin_text("netns-safe"),
        "@@CLIENT_TRAFFIC_PY@@": client_traffic_script_text(),
        "@@CLIENT_PROBE_DIR@@": CLIENT_PROBE_DIR,
        "@@CLIENT_TRAFFIC_SCRIPT@@": CLIENT_TRAFFIC_SCRIPT,
        "@@CLIENT_TAILSCALED@@": CLIENT_TAILSCALED,
        "@@CLIENT_TAILSCALE@@": CLIENT_TAILSCALE,
        "@@CLIENT_TAILSCALE_STATE@@": CLIENT_TAILSCALE_STATE,
    }
    for token, value in replacements.items():
        script = script.replace(token, value)
    if "@@" in script:
        raise GeneratorError("unexpanded client provisioning template token")
    return script


def build_client_user_data(
    *,
    hostname: str,
    index: int = DEFAULT_CLIENT_INDEX,
    tailscale_sha256: str = TAILSCALE_TARBALL_SHA256,
) -> str:
    """Return a cloud-init NoCloud user-data document for a client VM."""
    if not re.fullmatch(r"[a-z][a-z0-9-]{2,49}", hostname):
        raise GeneratorError("hostname must be a short lowercase DNS label")
    config = {
        "hostname": hostname,
        "preserve_hostname": False,
        "manage_etc_hosts": True,
        "disable_root": True,
        "ssh_pwauth": False,
        "package_update": False,
        "package_upgrade": False,
        "package_reboot_if_required": False,
        "write_files": [
            {
                "path": "/usr/local/sbin/vprlab-client-provision.sh",
                "owner": "root:root",
                "permissions": "0755",
                "content": client_provision_script(
                    index, tailscale_sha256=tailscale_sha256
                ),
            }
        ],
        "runcmd": [
            [
                "/usr/local/sbin/vprlab-client-provision.sh",
                tailscale_sha256,
            ]
        ],
    }
    return "#cloud-config\n" + json.dumps(config, indent=2, sort_keys=True) + "\n"


_PROVISION_SCRIPT = r'''#!/bin/sh
# vprlab Debian 13 provisioning: install the unchanged legacy release, silence
# the OS, then power off.  This script runs once, online, from cloud-init.
set -eu

EXPECTED_IMAGE_ID="$1"
PAYLOAD_LABEL='@@PAYLOAD_LABEL@@'
NAME='@@NAME@@'
VM_MAC='@@VM_MAC@@'
GATEWAY_MAC='@@GATEWAY_MAC@@'
VM_IPV4='@@VM_IPV4@@'
GATEWAY_IPV4='@@GATEWAY_IPV4@@'

log() { printf 'vprlab-provision: %s\n' "$*" >&2; }
fail() {
    printf 'VPRLAB-PROVISION-FAILED: %s\n' "$*" >/dev/console
    if [ -w /dev/ttyS0 ]; then
        printf 'VPRLAB-PROVISION-FAILED: %s\n' "$*" > /dev/ttyS0
    fi
    log "$*"
    sync || true
    systemctl poweroff >/dev/null 2>&1 || true
    exit 1
}

case "$EXPECTED_IMAGE_ID" in
    sha256:*) ;;
    *) fail "expected image ID must be sha256:<64 hex>" ;;
esac
[ "${#EXPECTED_IMAGE_ID}" -eq 71 ] || fail "expected image ID has the wrong length"

log "installing the small package set (no recommends)"
printf '%s\n' \
    'APT::Install-Recommends "false";' \
    'APT::Install-Suggests "false";' \
    > /etc/apt/apt.conf.d/99-vprlab-norecommends
DEBIAN_FRONTEND=noninteractive apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    docker.io docker-cli docker-compose qemu-guest-agent nftables python3 \
    iproute2 wireguard-tools util-linux ca-certificates

log "loading tun and wireguard"
printf '%s\n' tun wireguard br_netfilter > /etc/modules-load.d/vprlab-net.conf
modprobe tun >/dev/null 2>&1 || true
modprobe wireguard >/dev/null 2>&1 || true
install -d -m 0755 /dev/net
[ -e /dev/net/tun ] || mknod /dev/net/tun c 10 200
[ -c /dev/net/tun ] || fail "/dev/net/tun is not a character device"
chmod 0666 /dev/net/tun
printf '%s\n' 'c /dev/net/tun 0666 root root 10 200' \
    > /etc/tmpfiles.d/vprlab-tun.conf
ip link add vprlab-wgtest type wireguard \
    || fail "the wireguard kernel module is unavailable"
ip link del vprlab-wgtest

log "mounting the read-only payload"
install -d -m 0755 /mnt/vprlab-payload
n=0
while [ ! -e "/dev/disk/by-label/$PAYLOAD_LABEL" ]; do
    n=$((n + 1))
    [ "$n" -lt 120 ] || fail "payload ISO did not appear"
    sleep 1
done
mount -o ro "/dev/disk/by-label/$PAYLOAD_LABEL" /mnt/vprlab-payload
[ -d /mnt/vprlab-payload/release ] || fail "payload release directory missing"
[ -f /mnt/vprlab-payload/image/vprouter-image.tar ] || fail "payload image tar missing"

log "installing the release unchanged"
install -d -m 0755 -o root -g root /opt/vprouter
rm -rf /opt/vprouter/current
cp -a /mnt/vprlab-payload/release /opt/vprouter/current
chown -R root:root /opt/vprouter/current
if find /opt/vprouter/current -type l | grep -q .; then
    fail "release contains a symbolic link"
fi
chmod -R u+rwX,go+rX,go-w /opt/vprouter/current
for required in Dockerfile docker-compose.yaml router.nft router_runtime.py host/orchestrate.py; do
    [ -f "/opt/vprouter/current/$required" ] || fail "release file missing: $required"
done
install -m 0644 /mnt/vprlab-payload/unit/vprouter@.service \
    /etc/systemd/system/vprouter@.service
systemctl daemon-reload
# Deliberately NOT enabled: only a phase action starts the router.
if systemctl is-enabled "vprouter@$NAME.service" >/dev/null 2>&1; then
    fail "router unit must not be enabled by provisioning"
fi

log "configuring the Docker daemon"
install -d -m 0755 /etc/docker
cat > /etc/docker/daemon.json <<'JSON'
@@DOCKER_DAEMON@@JSON
chmod 0644 /etc/docker/daemon.json
systemctl enable docker.service
systemctl restart docker.service
n=0
while ! docker info >/dev/null 2>&1; do
    n=$((n + 1))
    if [ "$n" -ge 120 ]; then
        # Diagnostics for the operator (Docker's own logs hold no secrets:
        # the WireGuard profile is only written at test time).
        if [ -w /dev/ttyS0 ]; then
            journalctl -u docker.service -u containerd.service -n 40 --no-pager \
                > /dev/ttyS0 2>&1 || true
        fi
        fail "Docker daemon did not start"
    fi
    sleep 1
done

log "loading and verifying the image tar"
docker load -i /mnt/vprlab-payload/image/vprouter-image.tar
loaded=$(docker image inspect --format '{{.Id}}' "$EXPECTED_IMAGE_ID" 2>/dev/null || true)
[ "$loaded" = "$EXPECTED_IMAGE_ID" ] || fail "loaded image ID does not match the expected digest"
if ! docker compose version >/dev/null 2>&1; then
    if [ -x /usr/bin/docker-compose ]; then
        install -d -m 0755 /usr/local/lib/docker/cli-plugins
        ln -sf /usr/bin/docker-compose \
            /usr/local/lib/docker/cli-plugins/docker-compose
    fi
fi
docker compose version >/dev/null 2>&1 || fail "docker compose plugin is unavailable"

log "enabling the guest agent and the static network manager"
systemctl enable qemu-guest-agent.service
systemctl start qemu-guest-agent.service
systemctl enable systemd-networkd.service >/dev/null 2>&1 || true

log "silencing the OS"
swapoff -a >/dev/null 2>&1 || true
if [ -f /etc/fstab ]; then
    sed -i -E 's/^([^#].*[[:space:]]swap[[:space:]].*)$/#vprlab-disabled \1/' /etc/fstab
fi
for unit in \
    systemd-timesyncd.service \
    apt-daily.timer apt-daily.service \
    apt-daily-upgrade.timer apt-daily-upgrade.service \
    unattended-upgrades.timer unattended-upgrades.service \
    man-db.timer e2scrub_all.timer e2scrub_reap.service fstrim.timer \
    systemd-resolved.service \
    ssh.service ssh.socket sshd.service \
    dhclient.service dhcpcd.service \
    NetworkManager.service NetworkManager-wait-online.service \
    networking.service ifupdown-wait-online.service ifup@.service \
    chrony.service chronyd.service ntp.service ntpsec.service openntpd.service; do
    systemctl disable --now "$unit" >/dev/null 2>&1 || true
    systemctl mask "$unit" >/dev/null 2>&1 || true
done
touch /etc/cloud/cloud-init.disabled
for unit in \
    cloud-init.service cloud-init-local.service cloud-init-main.service \
    cloud-init-network.service cloud-config.service cloud-final.service \
    cloud-init-hotplugd.service cloud-init-hotplugd.socket; do
    systemctl disable --now "$unit" >/dev/null 2>&1 || true
    systemctl mask "$unit" >/dev/null 2>&1 || true
done
install -d -m 0700 -o root -g root @@BOOT_CONTROL_DIR@@

install -d -m 0755 /etc/systemd/resolved.conf.d
cat > /etc/systemd/resolved.conf.d/99-vprlab.conf <<'EOF'
@@RESOLVED@@EOF
chmod 0644 /etc/systemd/resolved.conf.d/99-vprlab.conf

# Remove every cloud-init network configuration: at test time the only network
# configuration is the MAC-matched static file below.
for artifact in \
    /etc/systemd/network/50-cloud-init.network \
    /etc/systemd/network/10-cloud-init.network \
    /etc/network/interfaces.d/50-cloud-init \
    /etc/network/interfaces.d/50-cloud-init.cfg \
    /etc/netplan/50-cloud-init.yaml \
    /etc/netplan/90-cloud-init.yaml; do
    rm -f "$artifact"
done
rm -f /etc/systemd/network/*cloud-init*.network
rm -f /etc/network/interfaces.d/*cloud-init*
rm -f /etc/netplan/*cloud-init*
for config in /etc/systemd/network/*.network; do
    [ -e "$config" ] || continue
    [ "$config" = /etc/systemd/network/10-vprlab-wan.network ] && continue
    mv "$config" "$config.vprlab-disabled"
done
install -d -m 0755 /etc/systemd/network
cat > /etc/systemd/network/10-vprlab-wan.network <<'EOF'
@@NETWORK@@EOF
chmod 0644 /etc/systemd/network/10-vprlab-wan.network

rm -f /etc/resolv.conf
printf '# vprlab leak lab: DNS intentionally disabled\n' > /etc/resolv.conf
chmod 0644 /etc/resolv.conf

install -d -m 0755 /etc/default/grub.d
cat > /etc/default/grub.d/99-vprlab-silence.cfg <<'EOF'
@@GRUB@@EOF
chmod 0644 /etc/default/grub.d/99-vprlab-silence.cfg
update-grub
@@IPV6_SYSCTL@@
cat > @@BOOT_CONTROL_SCRIPT@@ <<'PY'
@@BOOT_CONTROL_PY@@PY
chmod 0755 @@BOOT_CONTROL_SCRIPT@@

umount /mnt/vprlab-payload || true
sync
log "provisioning complete"
if [ -w /dev/ttyS0 ]; then
    printf 'VPRLAB-PROVISION-OK %s\n' "$EXPECTED_IMAGE_ID" > /dev/ttyS0
fi
printf 'VPRLAB-PROVISION-OK %s\n' "$EXPECTED_IMAGE_ID" > /dev/console
systemctl poweroff
'''


def provision_script(
    *,
    name: str = DEFAULT_NAME,
    image_id: str = DEPLOYED_IMAGE_ID,
    ipv6_mode: str = "netns-safe",
    boot_control_script: str | None = None,
) -> str:
    """Return the guest-side provisioning script embedded in cloud-init."""
    validate_name(name)
    validate_image_id(image_id)
    if ipv6_mode not in {"kernel-disable", "netns-safe"}:
        raise GeneratorError("ipv6_mode must be kernel-disable or netns-safe")
    script = _PROVISION_SCRIPT
    ipv6_sysctl = ""
    if ipv6_mode == "netns-safe":
        ipv6_sysctl = (
            "install -d -m 0755 /etc/sysctl.d\n"
            "cat > /etc/sysctl.d/99-vprlab-ipv6.conf <<'EOF'\n"
            + ipv6_sysctl_text()
            + "EOF\n"
            "chmod 0644 /etc/sysctl.d/99-vprlab-ipv6.conf\n"
            "sysctl --system >/dev/null 2>&1 || true\n"
        )
    replacements = {
        "@@PAYLOAD_LABEL@@": PAYLOAD_LABEL,
        "@@NAME@@": name,
        "@@VM_MAC@@": VM_MAC,
        "@@GATEWAY_MAC@@": GATEWAY_MAC,
        "@@VM_IPV4@@": VM_IPV4,
        "@@GATEWAY_IPV4@@": GATEWAY_IPV4,
        "@@DOCKER_DAEMON@@": docker_daemon_text(),
        "@@RESOLVED@@": resolved_dropin_text(),
        "@@NETWORK@@": networkd_text(),
        "@@GRUB@@": grub_dropin_text(ipv6_mode),
        "@@IPV6_SYSCTL@@": ipv6_sysctl,
        "@@BOOT_CONTROL_SCRIPT@@": BOOT_CONTROL_SCRIPT,
        "@@BOOT_CONTROL_DIR@@": BOOT_CONTROL_DIR,
        "@@BOOT_CONTROL_PY@@": boot_control_script
        if boot_control_script is not None
        else boot_control_script_text(),
    }
    for token, value in replacements.items():
        script = script.replace(token, value)
    if "@@" in script:
        raise GeneratorError("unexpanded provisioning template token")
    return script


def build_user_data(
    *,
    hostname: str,
    name: str = DEFAULT_NAME,
    image_id: str = DEPLOYED_IMAGE_ID,
    ipv6_mode: str = "netns-safe",
) -> str:
    """Return a cloud-init NoCloud user-data document (JSON is valid YAML)."""
    if not re.fullmatch(r"[a-z][a-z0-9-]{2,49}", hostname):
        raise GeneratorError("hostname must be a short lowercase DNS label")
    config = {
        "hostname": hostname,
        "preserve_hostname": False,
        "manage_etc_hosts": True,
        "disable_root": True,
        "ssh_pwauth": False,
        "package_update": False,
        "package_upgrade": False,
        "package_reboot_if_required": False,
        "write_files": [
            {
                "path": "/usr/local/sbin/vprlab-provision.sh",
                "owner": "root:root",
                "permissions": "0755",
                "content": provision_script(
                    name=name, image_id=image_id, ipv6_mode=ipv6_mode
                ),
            }
        ],
        "runcmd": [["/usr/local/sbin/vprlab-provision.sh", validate_image_id(image_id)]],
    }
    return "#cloud-config\n" + json.dumps(config, indent=2, sort_keys=True) + "\n"


def build_meta_data(*, hostname: str, instance_id: str) -> str:
    return (
        json.dumps(
            {
                "instance-id": instance_id,
                "local-hostname": hostname,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )


# ---------------------------------------------------------------------------
# Guest silence verification


def silence_check_script(
    *,
    name: str = DEFAULT_NAME,
    image_id: str = DEPLOYED_IMAGE_ID,
    expect_router_disabled: bool = True,
    vm_mac: str = VM_MAC,
) -> str:
    """Return the script the runner executes over QGA before every test boot.

    Debian 13 runs systemd 257.  Its networkd link-state file has no
    ``DHCP4_CLIENT=0``/``DHCP6_CLIENT=0`` keys, so DHCP-off is proven from the
    static ``.network`` file, ``networkctl status`` and the absence of a lease
    file for this interface instead.  ``networkctl`` text output is not a
    stable API; the file and lease checks are authoritative and the text check
    is an additional fail-closed signal.
    """
    validate_name(name)
    validate_image_id(image_id)
    validate_mac(vm_mac)
    masked = " ".join(SILENCE_MASK_UNITS)
    expected_state = "disabled" if expect_router_disabled else "enabled"
    return f'''#!/bin/sh
# vprlab test-boot silence check.  Any deviation fails the phase.
set -u
fail=0
ok() {{ printf 'CHECK-OK %s\\n' "$*"; }}
bad() {{ printf 'CHECK-FAIL %s\\n' "$*"; fail=1; }}

if [ -e /proc/sys/net/ipv6 ]; then
    all_off=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo 0)
    default_off=$(cat /proc/sys/net/ipv6/conf/default/disable_ipv6 2>/dev/null || echo 0)
    if [ "$all_off" = 1 ] && [ "$default_off" = 1 ]; then
        ok ipv6_netns_disabled
    else
        bad ipv6_netns_enabled
    fi
else
    grep -q 'ipv6.disable=1' /proc/cmdline \
        && ok cmdline_ipv6_disable || bad cmdline_ipv6_disable
fi
if [ "$(awk 'NR > 1' /proc/swaps | wc -l)" -eq 0 ]; then
    ok swap_off
else
    bad swap_active
fi

for unit in {masked}; do
    state=$(systemctl is-enabled "$unit" 2>/dev/null || true)
    case "$state" in
        masked) ok "masked:$unit" ;;
        ""|not-found) ok "absent:$unit" ;;
        *) bad "unit_not_masked:$unit=$state" ;;
    esac
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
        bad "unit_active:$unit"
    fi
done
active_cloud_init=$(systemctl list-units 'cloud-init*' --state=active --no-legend --no-pager 2>/dev/null || true)
if [ -n "$active_cloud_init" ]; then
    bad "cloud_init_unit_active"
else
    ok cloud_init_units_inactive
fi

[ -f /etc/cloud/cloud-init.disabled ] && ok cloud_init_disabled || bad cloud_init_enabled

interface=""
for directory in /sys/class/net/*; do
    [ -e "$directory/address" ] || continue
    [ "$(cat "$directory/address")" = "{vm_mac}" ] && interface="${{directory##*/}}"
done
if [ -n "$interface" ]; then
    ok "interface:$interface"
else
    bad "interface_missing:{vm_mac}"
fi

if [ -n "$interface" ]; then
    ip -4 -o addr show dev "$interface" | grep -q "inet {VM_IPV4}/24" \
        && ok static_address || bad static_address
    ip -4 -o route show default | grep -q "default via {GATEWAY_IPV4} dev $interface" \
        && ok static_gateway || bad static_gateway
    ip -4 -o neigh show dev "$interface" | grep -F "{GATEWAY_IPV4}" \
        | grep -Fi "lladdr {GATEWAY_MAC}" | grep -q PERMANENT \
        && ok static_neighbor || bad static_neighbor
    ip -6 -o addr show dev "$interface" 2>/dev/null | grep -q inet6 \
        && bad ipv6_address || ok ipv6_address_absent
    index=$(cat "/sys/class/net/$interface/ifindex")
    network_file=${{VPRLAB_NETWORK_FILE:-/etc/systemd/network/10-vprlab-wan.network}}
    lease_dir=${{VPRLAB_LEASE_DIR:-/run/systemd/netif/leases}}
    if [ -f "$network_file" ] \
        && grep -Eq '^[[:space:]]*DHCP=no[[:space:]]*$' "$network_file"; then
        ok dhcp_off_network_file
    else
        bad dhcp_network_file
    fi
    if [ -e "$lease_dir/$index" ]; then
        bad dhcp_lease_present
    else
        ok dhcp_lease_absent
    fi
    if command -v networkctl >/dev/null 2>&1; then
        status_text=$(networkctl status "$interface" --no-pager 2>/dev/null || true)
        if printf '%s\\n' "$status_text" | grep -Eqi 'DHCP[46]?[[:space:]]+(Client|Lease)'; then
            bad dhcp_client_configured
        else
            ok dhcp_client_absent
        fi
    else
        bad networkctl_missing
    fi
fi

for command_file in /proc/[0-9]*/comm; do
    [ -r "$command_file" ] || continue
    process=$(cat "$command_file")
    case "$process" in
        dhclient|dhcpcd|udhcpc|dhcp6c|NetworkManager) bad "dhcp_client_running:$process" ;;
        chronyd|ntpd|openntpd|systemd-timesyncd) bad "time_sync_running:$process" ;;
    esac
done

if grep -Eq '^[[:space:]]*nameserver' /etc/resolv.conf 2>/dev/null; then
    bad resolv_conf_nameserver
else
    ok resolv_conf_no_nameserver
fi

if python3 - <<'PY'
import json
import sys
expected = {{"ipv6": False, "ip6tables": False, "dns": [], "log-driver": "local"}}
with open("/etc/docker/daemon.json", encoding="utf-8") as stream:
    actual = json.load(stream)
sys.exit(0 if actual == expected else 1)
PY
then
    ok docker_daemon_json
else
    bad docker_daemon_json
fi

[ -f {ROUTER_UNIT_TEMPLATE} ] && ok router_unit_installed || bad router_unit_missing
router_state=$(systemctl is-enabled "vprouter@{name}.service" 2>/dev/null || true)
[ "$router_state" = "{expected_state}" ] \
    && ok "router_unit:$router_state" || bad "router_unit:$router_state"

systemctl is-active --quiet qemu-guest-agent.service \
    && ok guest_agent_active || bad guest_agent_inactive

for required in Dockerfile docker-compose.yaml router.nft router_runtime.py host/orchestrate.py; do
    [ -f "/opt/vprouter/current/$required" ] && ok "release:$required" || bad "release_missing:$required"
done
owner=$(stat -c '%u' /opt/vprouter/current 2>/dev/null || echo missing)
[ "$owner" = 0 ] && ok release_owned_root || bad "release_owner:$owner"
[ "$(stat -c '%a' /opt/vprouter/current 2>/dev/null || echo 0)" = 755 ] \
    && ok release_mode || bad release_mode

if [ "$fail" -eq 0 ]; then
    printf 'SILENCE-OK\\n'
    exit 0
fi
printf 'SILENCE-FAILED\\n'
exit 1
'''


def client_silence_check_script(index: int = DEFAULT_CLIENT_INDEX) -> str:
    """Return the pre-phase silence check for one client VM."""
    validate_client_index(index)
    mac = client_mac(index)
    ipv4 = client_ipv4(index)
    masked = " ".join(SILENCE_MASK_UNITS)
    return f'''#!/bin/sh
# vprlab M3 client silence check.  Any deviation fails the phase.
set -u
fail=0
ok() {{ printf 'CHECK-OK %s\\n' "$*"; }}
bad() {{ printf 'CHECK-FAIL %s\\n' "$*"; fail=1; }}

if [ -e /proc/sys/net/ipv6 ]; then
    all_off=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo 0)
    default_off=$(cat /proc/sys/net/ipv6/conf/default/disable_ipv6 2>/dev/null || echo 0)
    if [ "$all_off" = 1 ] && [ "$default_off" = 1 ]; then
        ok ipv6_netns_disabled
    else
        bad ipv6_netns_enabled
    fi
else
    grep -q 'ipv6.disable=1' /proc/cmdline \\
        && ok cmdline_ipv6_disable || bad cmdline_ipv6_disable
fi
if [ "$(awk 'NR > 1' /proc/swaps | wc -l)" -eq 0 ]; then
    ok swap_off
else
    bad swap_active
fi

for unit in {masked}; do
    state=$(systemctl is-enabled "$unit" 2>/dev/null || true)
    case "$state" in
        masked) ok "masked:$unit" ;;
        ""|not-found) ok "absent:$unit" ;;
        *) bad "unit_not_masked:$unit=$state" ;;
    esac
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
        bad "unit_active:$unit"
    fi
done
[ -f /etc/cloud/cloud-init.disabled ] && ok cloud_init_disabled || bad cloud_init_enabled

interface=""
for directory in /sys/class/net/*; do
    [ -e "$directory/address" ] || continue
    [ "$(cat "$directory/address")" = "{mac}" ] && interface="${{directory##*/}}"
done
if [ -n "$interface" ]; then
    ok "interface:$interface"
    ip -4 -o addr show dev "$interface" | grep -q "inet {ipv4}/24" \\
        && ok static_address || bad static_address
    ip -4 -o route show default | grep -q "default via {CLIENT_GATEWAY_IPV4} dev $interface" \\
        && ok static_gateway || bad static_gateway
    ip -4 -o neigh show dev "$interface" | grep -F "{CLIENT_GATEWAY_IPV4}" \\
        | grep -Fi "lladdr {CLIENT_BRIDGE_MAC}" | grep -q PERMANENT \\
        && ok static_neighbor || bad static_neighbor
    ip -6 -o addr show dev "$interface" 2>/dev/null | grep -q inet6 \\
        && bad ipv6_address || ok ipv6_address_absent
    network_file=/etc/systemd/network/10-vprlab-client.network
    if [ -f "$network_file" ] \\
        && grep -Eq '^[[:space:]]*DHCP=no[[:space:]]*$' "$network_file"; then
        ok dhcp_off_network_file
    else
        bad dhcp_network_file
    fi
else
    bad "interface_missing:{mac}"
fi

systemctl is-active --quiet tailscaled.service \\
    && ok tailscaled_active || bad tailscaled_inactive
systemctl is-active --quiet qemu-guest-agent.service \\
    && ok guest_agent_active || bad guest_agent_inactive
[ -x {CLIENT_TRAFFIC_SCRIPT} ] && ok traffic_script \
    || bad traffic_script_missing
[ -d {CLIENT_PROBE_DIR} ] && ok probe_dir || bad probe_dir_missing
if grep -Eq '^[[:space:]]*nameserver' /etc/resolv.conf 2>/dev/null; then
    bad resolv_conf_nameserver
else
    ok resolv_conf_no_nameserver
fi

for command_file in /proc/[0-9]*/comm; do
    [ -r "$command_file" ] || continue
    process=$(cat "$command_file")
    case "$process" in
        dhclient|dhcpcd|udhcpc|dhcp6c|NetworkManager) bad "dhcp_client_running:$process" ;;
        chronyd|ntpd|openntpd|systemd-timesyncd) bad "time_sync_running:$process" ;;
    esac
done

if [ "$fail" -eq 0 ]; then
    printf 'SILENCE-OK\\n'
    exit 0
fi
printf 'SILENCE-FAILED\\n'
exit 1
'''


# ---------------------------------------------------------------------------
# Host-side capture


def tcpdump_argv(interface: str, pcap: pathlib.Path) -> list[str]:
    return [
        "tcpdump",
        "-i",
        interface,
        "-nn",
        "-U",
        "--immediate-mode",
        "-B",
        "8192",
        "-s",
        "0",
        "-w",
        str(pcap),
    ]


def shell_join(argv: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in argv)
