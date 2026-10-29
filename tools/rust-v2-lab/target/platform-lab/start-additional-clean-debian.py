"""Create an additional isolated local VM; preserve every existing VM/state.

Use only the immutable cached original Debian base after exact checksum
verification. Never copy a running overlay, enrollment or provider state.
"""
import datetime
import hashlib
import json
import os
import pathlib
import socket
import subprocess


repo = pathlib.Path.cwd()
platform_root = repo / "target/platform-lab"
state = platform_root / "debian-clean-x86_64"
assert not state.exists(), "existing_state_requires_review"
port = 22036
with socket.socket() as probe:
    assert probe.connect_ex(("127.0.0.1", port)) != 0
image = repo / "target/lab-images/debian-13-genericcloud-amd64-20261021-2638.qcow2"
checksum_file = image.parent / "SHA512SUMS-20261021-2638"
matches = [line.split()[0] for line in checksum_file.read_text().splitlines()
           if line.split()[-1].lstrip("*") == image.name]
assert len(matches) == 1
with image.open("rb") as stream:
    digest = hashlib.file_digest(stream, "sha512").hexdigest()
assert digest == matches[0]
state.mkdir(mode=0o700)
tools = repo / "target/lab-tools/root"
env = dict(os.environ, LD_LIBRARY_PATH=str(tools / "usr/lib/x86_64-linux-gnu"),
           QEMU_MODULE_DIR=str(tools / "usr/lib/x86_64-linux-gnu/qemu"))
public_key = (repo / "target/lab-state/id_ed25519.pub").read_text().strip()
assert public_key.startswith("ssh-ed25519 ")
config = {
    "hostname": "vprouter-debian-clean-lab", "ssh_pwauth": False, "disable_root": True,
    "users": [{"name": "vprouterlab", "shell": "/bin/bash", "lock_passwd": True,
               "sudo": ["ALL=(ALL) NOPASSWD:ALL"], "ssh_authorized_keys": [public_key]}],
    "package_update": True, "package_upgrade": False,
    "packages": ["docker.io", "nftables", "iproute2", "wireguard-tools", "tcpdump", "python3", "sudo", "openssh-server"],
    "write_files": [{"path": "/var/lib/vprouter-v2-lab/isolated-acceptance", "owner": "root:root",
                     "permissions": "0600", "content": "additional local isolated lab; no enrolled identities or provider credentials\n"}],
    "runcmd": [["chmod", "0700", "/var/lib/vprouter-v2-lab"],
               ["systemctl", "enable", "--now", "docker"],
               ["sh", "-c", "test -S /run/docker.sock && test -f /sys/fs/cgroup/cgroup.controllers && touch /var/lib/vprouter-v2-lab/bootstrap-complete"]],
}
(state / "user-data").write_text("#cloud-config\n" + json.dumps(config, indent=2) + "\n")
(state / "meta-data").write_text(json.dumps({"instance-id": "vprouter-debian-clean-20261027", "local-hostname": "vprouter-debian-clean-lab"}) + "\n")
subprocess.run([str(tools / "usr/bin/genisoimage"), "-quiet", "-output", str(state / "seed.iso"),
                "-volid", "cidata", "-joliet", "-rock", str(state / "user-data"), str(state / "meta-data")], env=env, check=True)
disk = state / "guest.qcow2"
subprocess.run([str(tools / "usr/bin/qemu-img"), "create", "-f", "qcow2", "-F", "qcow2", "-b", str(image), str(disk), "24G"], env=env, check=True)
argv = [str(tools / "usr/bin/qemu-system-x86_64"), "-accel", "kvm", "-machine", "pc,smm=off",
        "-cpu", "host", "-smp", "2", "-m", "2048", "-bios", str(tools / "usr/share/seabios/bios-256k.bin"),
        "-drive", "file=" + str(disk) + ",if=virtio,format=qcow2",
        "-drive", "file=" + str(state / "seed.iso") + ",media=cdrom,readonly=on",
        "-boot", "c", "-netdev", "user,id=wan,hostfwd=tcp:127.0.0.1:" + str(port) + "-:22",
        "-device", "virtio-net-pci,netdev=wan,romfile=", "-display", "none", "-vga", "none",
        "-serial", "file:" + str(state / "serial.log"), "-pidfile", str(state / "qemu.pid"),
        "-qmp", "unix:" + str(state / "qmp.sock") + ",server=on,wait=off", "-L", str(tools / "usr/share/qemu"),
        "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny"]
with (state / "qemu.log").open("xb") as log:
    process = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=log,
                               stderr=subprocess.STDOUT, start_new_session=True)
raw = pathlib.Path("/proc", str(process.pid), "stat").read_text()
start = int(raw[raw.rfind(")") + 2:].split()[19])
record = dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
              platform="debian-clean-x86_64", pid=process.pid, start_time=start, ssh_port=port, argv=argv,
              base_image=str(image), base_image_sha512=digest, checksum_manifest=str(checksum_file),
              test_status="BOOTING_NOT_VERIFIED", identities_imported=False, provider_credentials_imported=False,
              old_vm_changes=False, production_changes=False)
with (state / "process.json").open("x") as stream:
    json.dump(record, stream, indent=2)
    stream.write("\n")
print(json.dumps(dict(platform=record["platform"], pid=process.pid, start_time=start, ssh_port=port,
                      test_status=record["test_status"], old_vm_changes=False, production_changes=False)))
