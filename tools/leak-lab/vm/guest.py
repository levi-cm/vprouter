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
import pathlib
import re
import shlex

# ---------------------------------------------------------------------------
# Fixed lab facts

BASE_IMAGE = pathlib.Path(
    "/DATA/vprouter-lab/lab-images/debian-13-genericcloud-amd64-20261021-2638.qcow2"
)
BASE_IMAGE_SHA512 = (
    "16e0965312c56feb331049d45d2b1b5778f3f942a33d4300eedbb97527707f2bea"
    "87c0006f3e4cc7a25fadbff739c4e235a51fb9bcd1b66fd554f7f8e80ba45c"
)
CHECKSUM_MANIFEST = pathlib.Path(
    "/DATA/vprouter-lab/lab-images/SHA512SUMS-20261021-2638"
)
LAB_TOOLS = pathlib.Path("/DATA/vprouter-lab/lab-tools/root")
QEMU = LAB_TOOLS / "usr/bin/qemu-system-x86_64"
QEMU_IMG = LAB_TOOLS / "usr/bin/qemu-img"
GENISOIMAGE = LAB_TOOLS / "usr/bin/genisoimage"
LAB_LIBRARY_DIR = LAB_TOOLS / "usr/lib/x86_64-linux-gnu"
QEMU_MODULE_DIR = LAB_LIBRARY_DIR / "qemu"
QEMU_SHARE_DIR = LAB_TOOLS / "usr/share/qemu"

STATE_ROOT = pathlib.Path("/DATA/vprouter-lab/leaklab")
RELEASE_DIR = pathlib.Path("/opt/vprouter/current")
QEMU_USER = "opsec"

BRIDGE = "vprlab0"
TAP = "vprlab-tap0"
VM_MAC = "52:54:00:76:70:02"
PROVISION_MAC = "52:54:00:76:70:99"
GATEWAY_MAC = "52:54:00:76:70:01"
VM_IPV4 = "10.250.0.2"
GATEWAY_IPV4 = "10.250.0.1"
WAN_DEVICE = "eth0"
VM_SUBNET = ipaddress.IPv4Network("10.250.0.0/24")

DEFAULT_NAME = "zz-vprtest-01-do-not-use"
DEFAULT_INDEX = 1
DEPLOYED_IMAGE_ID = (
    "sha256:62c283e6a4d350992ed2b9a99a48c7834e60e1c9af92f9e1699a2b2d0c920de3"
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
QMP_SOCKET = "qmp.sock"
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

SANDBOX = "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny"

BOOT_CONTROL_UNIT = "vprlab-boot-control.service"
BOOT_CONTROL_UNIT_PATH = "/etc/systemd/system/" + BOOT_CONTROL_UNIT
BOOT_CONTROL_SCRIPT = "/usr/local/sbin/vprlab-boot-control.py"
BOOT_CONTROL_SPEC = "/run/vprlab-boot-control.json"
BOOT_CONTROL_SENT = "/run/vprlab-boot-control-sent"

ROUTER_UNIT_TEMPLATE = "/etc/systemd/system/vprouter@.service"

#: Units that must never run on the test boot.  "mask" is stronger than
#: "disable": a package or dependency cannot re-enable a masked unit.
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
    "cloud-init.service",
    "cloud-init-local.service",
    "cloud-config.service",
    "cloud-final.service",
    "cloud-init-hotplugd.service",
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


# ---------------------------------------------------------------------------
# QEMU


def qemu_env(base: dict[str, str] | None = None) -> dict[str, str]:
    environment = dict(base if base is not None else {})
    environment["LD_LIBRARY_PATH"] = str(LAB_LIBRARY_DIR)
    environment["QEMU_MODULE_DIR"] = str(QEMU_MODULE_DIR)
    return environment


def build_qemu_argv(
    mode: str,
    state: pathlib.Path,
    *,
    name: str = DEFAULT_NAME,
    tap: str = TAP,
) -> list[str]:
    """Return the exact QEMU argv for ``provision`` or ``test`` mode.

    Provision mode has only a user-mode netdev and is never attached to the
    lab tap.  Test mode has only the pre-created tap and never a user netdev,
    seed or payload ISO.
    """
    if mode not in {"provision", "test"}:
        raise GeneratorError("mode must be 'provision' or 'test'")
    validate_name(name)
    state = pathlib.Path(state)
    overlay = state / OVERLAY_FILE

    argv = [
        str(QEMU),
        "-accel",
        "kvm",
        "-machine",
        "pc,smm=off",
        "-cpu",
        "host",
        "-smp",
        "1",
        "-m",
        "512",
        "-name",
        f"vprlab-{name}",
        "-drive",
        f"file={overlay},if=virtio,format=qcow2",
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
            f"virtio-net-pci,netdev=wan,romfile=,mac={PROVISION_MAC}",
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
            f"virtio-net-pci,netdev=wan,romfile=,mac={VM_MAC}",
        ]

    argv += [
        "-display",
        "none",
        "-serial",
        f"file:{state / SERIAL_FILE}",
        "-pidfile",
        str(state / PID_FILE),
        "-qmp",
        f"unix:{state / QMP_SOCKET},server=on,wait=off",
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
    ]
    return argv


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
        import pwd

        try:
            record = pwd.getpwnam(user)
        except KeyError as exc:
            raise GeneratorError(f"unknown unprivileged user {user!r}") from exc
        uid, gid = record.pw_uid, record.pw_gid
    return [
        setpriv,
        f"--reuid={uid}",
        f"--regid={gid}",
        "--clear-groups",
        "--",
    ] + list(qemu_argv)


def build_qemu_img_create_argv(base: pathlib.Path, overlay: pathlib.Path) -> list[str]:
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
        "4G",
    ]


def build_qemu_img_info_argv(overlay: pathlib.Path) -> list[str]:
    return [
        str(QEMU_IMG),
        "info",
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


def grub_dropin_text(ipv6_mode: str = "kernel-disable") -> str:
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

    The nonce and sink are read from a mode-0600 runtime file, sent once with
    ``SO_BINDTODEVICE``, and the file is deleted afterwards.  The unit itself
    contains no secret.
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
        stream.write("sent\\n")
    os.unlink(SPEC)


if __name__ == "__main__":
    main()
'''.replace("@@SPEC@@", BOOT_CONTROL_SPEC).replace("@@SENT@@", BOOT_CONTROL_SENT)


def boot_control_spec(
    nonce: str,
    sink_ipv4: str,
    sink_udp_port: int,
    *,
    vm_ipv4: str = VM_IPV4,
    vm_mac: str = VM_MAC,
    device: str = "",
) -> str:
    if not re.fullmatch(r"[0-9a-f]{32}", nonce):
        raise GeneratorError("boot control nonce must be 32 lowercase hex characters")
    if ipaddress.IPv4Address(sink_ipv4) != ipaddress.IPv4Address(GATEWAY_IPV4):
        raise GeneratorError("boot control sink must be the lab gateway")
    if isinstance(sink_udp_port, bool) or not 1 <= int(sink_udp_port) <= 65535:
        raise GeneratorError("boot control sink port is invalid")
    if device and not re.fullmatch(r"[A-Za-z0-9_.:@-]{1,15}", device):
        raise GeneratorError("boot control device name is invalid")
    return (
        json.dumps(
            {
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
    docker.io docker-compose qemu-guest-agent nftables python3 \
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
    [ "$n" -lt 120 ] || fail "Docker daemon did not start"
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
    networking.service ifupdown-wait-online.service; do
    systemctl disable --now "$unit" >/dev/null 2>&1 || true
    systemctl mask "$unit" >/dev/null 2>&1 || true
done
touch /etc/cloud/cloud-init.disabled
for unit in \
    cloud-init.service cloud-init-local.service cloud-config.service \
    cloud-final.service cloud-init-hotplugd.service; do
    systemctl disable "$unit" >/dev/null 2>&1 || true
    systemctl mask "$unit" >/dev/null 2>&1 || true
done

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
    ipv6_mode: str = "kernel-disable",
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
    ipv6_mode: str = "kernel-disable",
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
) -> str:
    """Return the script the runner executes over QGA before every test boot."""
    validate_name(name)
    validate_image_id(image_id)
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
done

[ -f /etc/cloud/cloud-init.disabled ] && ok cloud_init_disabled || bad cloud_init_enabled

interface=""
for directory in /sys/class/net/*; do
    [ -e "$directory/address" ] || continue
    [ "$(cat "$directory/address")" = "{VM_MAC}" ] && interface="${{directory##*/}}"
done
if [ -n "$interface" ]; then
    ok "interface:$interface"
else
    bad "interface_missing:{VM_MAC}"
fi

if [ -n "$interface" ]; then
    ip -4 -o addr show dev "$interface" | grep -q "inet {VM_IPV4}/24" \
        && ok static_address || bad static_address
    ip -4 -o route show default | grep -q "default via {GATEWAY_IPV4} dev $interface" \
        && ok static_gateway || bad static_gateway
    ip -4 -o neigh show "$interface" | grep -F "{GATEWAY_IPV4}" \
        | grep -Fi "lladdr {GATEWAY_MAC}" | grep -q PERMANENT \
        && ok static_neighbor || bad static_neighbor
    ip -6 -o addr show dev "$interface" 2>/dev/null | grep -q inet6 \
        && bad ipv6_address || ok ipv6_address_absent
    index=$(cat "/sys/class/net/$interface/ifindex")
    link_state="/run/systemd/netif/links/$index"
    if [ -f "$link_state" ]; then
        grep -qx 'DHCP4_CLIENT=0' "$link_state" && ok dhcp4_off || bad dhcp4_client
        grep -qx 'DHCP6_CLIENT=0' "$link_state" && ok dhcp6_off || bad dhcp6_client
    else
        bad networkd_link_state_missing
    fi
fi

for command_file in /proc/[0-9]*/comm; do
    [ -r "$command_file" ] || continue
    process=$(cat "$command_file")
    case "$process" in
        dhclient|dhcpcd|NetworkManager) bad "dhcp_client_running:$process" ;;
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
        "-s",
        "0",
        "-w",
        str(pcap),
    ]


def shell_join(argv: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in argv)
