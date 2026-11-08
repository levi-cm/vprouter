#!/usr/bin/env python3
"""Offline tests for the vprlab leak-lab VM tooling.

No test starts QEMU, tcpdump, ip, nft, docker or a network connection.  The QGA
client is exercised against a fake unix-socket agent; everything else is pure
argv/user-data/record generation plus refusal paths.
"""

from __future__ import annotations

import base64
import json
import os
import pathlib
import socket
import stat
import tempfile
import threading
import time
import unittest

import guest
import hostcheck
import provision
import run_phase
import tsnames
from qga import ExecResult, QGAClient, QGAError, QGATimeout

VM_MAC = "52:54:00:76:70:02"
GATEWAY_MAC = "52:54:00:76:70:01"
GATEWAY = "10.250.0.1"
VM_IP = "10.250.0.2"
NONCE_A = "a" * 32
NONCE_B = "b" * 32
SECRET_TEXT = b"[Interface]\nPrivateKey = SUPERSECRETKEYMATERIAL\nAddress = 10.99.0.2/32\n\n[Peer]\nPublicKey = PUBLICKEYMATERIAL\nAllowedIPs = 0.0.0.0/0\nEndpoint = 185.65.134.10:51820\n"


class FakeQGAServer(threading.Thread):
    """Synchronous, single-client fake of the QEMU guest-agent wire protocol."""

    def __init__(
        self,
        path: pathlib.Path,
        *,
        exec_stdout: bytes = b"",
        exec_stderr: bytes = b"",
        exec_exit: int = 0,
        hang_status: bool = False,
        error_on: frozenset[str] = frozenset(),
    ):
        super().__init__(daemon=True)
        self.path = path
        self.exec_stdout = exec_stdout
        self.exec_stderr = exec_stderr
        self.exec_exit = exec_exit
        self.hang_status = hang_status
        self.error_on = error_on
        self.commands: list[str] = []
        self.exec_arguments: list[dict] = []
        self.files: dict[str, bytearray] = {}
        self.handles: dict[int, str] = {}
        self.failure: BaseException | None = None
        self._stop_event = threading.Event()
        self._next_pid = 100
        self._next_handle = 1000
        self._connection: socket.socket | None = None
        self._listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._listener.bind(str(path))
        self._listener.listen(1)
        self._listener.settimeout(0.1)

    def run(self) -> None:
        try:
            connection = None
            while not self._stop_event.is_set():
                try:
                    connection, _ = self._listener.accept()
                    break
                except socket.timeout:
                    continue
                except OSError:
                    return
            if connection is None:
                return
            self._connection = connection
            connection.settimeout(0.1)
            connection.sendall(
                b'{"execute":"guest-sync","arguments":{"id":7}}\n'
            )
            buffer = b""
            while not self._stop_event.is_set():
                try:
                    chunk = connection.recv(65536)
                except socket.timeout:
                    continue
                except OSError:
                    return
                if not chunk:
                    return
                buffer += chunk
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    if not line.strip():
                        continue
                    document = json.loads(line)
                    if not self._dispatch(connection, document):
                        return
        except BaseException as exc:  # pragma: no cover - reported by tests
            self.failure = exc

    def _send(self, connection: socket.socket, document: dict, *, delimited: bool = False) -> None:
        wire = json.dumps(document, separators=(",", ":")).encode("ascii") + b"\n"
        connection.sendall((b"\xff" if delimited else b"") + wire)

    def _error(self, connection: socket.socket, name: str) -> None:
        self._send(
            connection,
            {"error": {"class": "GenericError", "desc": f"injected {name} error"}},
        )

    def _dispatch(self, connection: socket.socket, document: dict) -> bool:
        name = document.get("execute")
        self.commands.append(name)
        arguments = document.get("arguments") or {}
        if name in self.error_on:
            self._error(connection, name)
            return True
        if name == "guest-sync-delimited":
            self._send(connection, {"return": arguments.get("id")}, delimited=True)
        elif name == "guest-sync":
            self._send(connection, {"return": arguments.get("id")})
        elif name == "guest-ping":
            self._send(connection, {"return": {}})
        elif name == "guest-exec":
            self.exec_arguments.append(arguments)
            self._next_pid += 1
            self._send(connection, {"return": {"pid": self._next_pid}})
        elif name == "guest-exec-status":
            if self.hang_status:
                self._send(connection, {"return": {"exited": False}})
                time.sleep(0.01)
            else:
                self._send(
                    connection,
                    {
                        "return": {
                            "exited": True,
                            "exitcode": self.exec_exit,
                            "out-data": base64.b64encode(self.exec_stdout).decode("ascii"),
                            "err-data": base64.b64encode(self.exec_stderr).decode("ascii"),
                        }
                    },
                )
        elif name == "guest-file-open":
            path = str(arguments.get("path", ""))
            self._next_handle += 1
            self.handles[self._next_handle] = path
            self.files.setdefault(path, bytearray())
            self._send(connection, {"return": self._next_handle})
        elif name == "guest-file-write":
            handle = arguments.get("handle")
            path = self.handles.get(handle)
            if path is None:
                self._error(connection, name)
                return True
            chunk = base64.b64decode(arguments.get("buf-b64", ""))
            self.files[path].extend(chunk)
            self._send(connection, {"return": {"count": len(chunk)}})
        elif name == "guest-file-close":
            self._send(connection, {"return": {}})
        elif name == "guest-shutdown":
            self._send(connection, {"return": {}})
        else:
            self._error(connection, str(name))
        return True

    def close(self) -> None:
        self._stop_event.set()
        if self._connection is not None:
            try:
                self._connection.close()
            except OSError:
                pass
            self._connection = None
        try:
            self._listener.close()
        except OSError:
            pass
        self.join(timeout=2.0)


class QGATestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.directory = pathlib.Path(self._temporary.name)
        self.socket_path = self.directory / "qga.sock"

    def start_server(self, **kwargs) -> FakeQGAServer:
        server = FakeQGAServer(self.socket_path, **kwargs)
        server.start()
        self.addCleanup(server.close)
        return server

    def client(self) -> QGAClient:
        client = QGAClient(self.socket_path)
        client.connect(timeout=5.0)
        self.addCleanup(client.close)
        return client

    def test_sync_and_ping(self) -> None:
        server = self.start_server()
        client = self.client()
        client.ping(timeout=5.0)
        self.assertIn("guest-sync-delimited", server.commands)
        self.assertIn("guest-ping", server.commands)
        self.assertIsNone(server.failure)

    def test_exec_captures_streams_and_exit_code(self) -> None:
        server = self.start_server(
            exec_stdout=b"hello out\n", exec_stderr=b"hello err\n", exec_exit=7
        )
        client = self.client()
        result = client.execute("/bin/sh", ["-c", "true"], timeout=5.0)
        self.assertIsInstance(result, ExecResult)
        self.assertEqual(result.exitcode, 7)
        self.assertEqual(result.stdout, b"hello out\n")
        self.assertEqual(result.stderr, b"hello err\n")
        self.assertEqual(server.exec_arguments[0]["path"], "/bin/sh")
        self.assertTrue(server.exec_arguments[0]["capture-output"])

    def test_exec_status_timeout(self) -> None:
        self.start_server(hang_status=True)
        client = self.client()
        with self.assertRaises(QGATimeout):
            client.execute("/bin/sh", ["-c", "sleep 100"], timeout=0.3)

    def test_file_write_is_exact_and_closed(self) -> None:
        server = self.start_server()
        client = self.client()
        payload = b"\x00binary secret\xff\n"
        client.write_file("/run/vprlab/secret", payload, timeout=5.0)
        self.assertEqual(bytes(server.files["/run/vprlab/secret"]), payload)
        self.assertIn("guest-file-close", server.commands)

    def test_agent_error_is_raised_without_payload(self) -> None:
        server = self.start_server(error_on=frozenset({"guest-ping"}))
        client = self.client()
        with self.assertRaises(QGAError) as raised:
            client.ping(timeout=5.0)
        self.assertIn("guest-ping", str(raised.exception))
        self.assertIsNone(server.failure)


class QemuArgvTests(unittest.TestCase):
    def test_test_mode_is_tap_only(self) -> None:
        argv = guest.build_qemu_argv("test", pathlib.Path("/state"), name=guest.DEFAULT_NAME)
        self.assertEqual(argv.count("-netdev"), 1)
        self.assertIn(
            "tap,id=wan,ifname=vprlab-tap0,script=no,downscript=no", argv
        )
        self.assertNotIn("user,id=wan", argv)
        joined = " ".join(argv)
        self.assertNotIn("seed.iso", joined)
        self.assertNotIn("payload.iso", joined)
        self.assertIn("mac=" + VM_MAC, joined)
        self.assertEqual(joined.count("virtio-net-pci"), 1)
        self.assertEqual(argv[argv.index("-m") + 1], "512")
        self.assertEqual(argv[argv.index("-smp") + 1], "1")
        self.assertEqual(argv[argv.index("-accel") + 1], "kvm")
        self.assertEqual(argv[argv.index("-cpu") + 1], "host")
        self.assertIn(guest.SANDBOX, argv)
        self.assertIn("-nic", argv)
        self.assertEqual(argv[argv.index("-nic") + 1], "none")
        self.assertIn(
            "socket,id=qga0,path=/state/qga.sock,server=on,wait=off", argv
        )
        self.assertIn("virtserialport,chardev=qga0,name=org.qemu.guest_agent.0", argv)
        self.assertIn("unix:/state/qmp.sock,server=on,wait=off", argv)
        self.assertIn("file:/state/serial.log", argv)
        self.assertIn("/state/qemu.pid", argv)

    def test_provision_mode_is_user_net_only(self) -> None:
        argv = guest.build_qemu_argv(
            "provision", pathlib.Path("/state"), name=guest.DEFAULT_NAME
        )
        joined = " ".join(argv)
        self.assertIn("user,id=wan", argv)
        self.assertNotIn("tap,id=wan", argv)
        self.assertNotIn("vprlab-tap0", joined)
        self.assertNotIn("hostfwd", joined)
        self.assertIn("mac=" + guest.PROVISION_MAC, joined)
        self.assertIn("seed.iso", joined)
        self.assertIn("payload.iso", joined)
        self.assertIn("media=cdrom,readonly=on", joined)

    def test_unprivileged_launch(self) -> None:
        argv = guest.build_qemu_argv("test", pathlib.Path("/state"))
        launched = guest.build_launch_argv(argv, "opsec", uid=1000, gid=1000)
        self.assertEqual(launched[:5], ["/usr/bin/setpriv", "--reuid=1000", "--regid=1000", "--clear-groups", "--"])
        self.assertEqual(launched[5:], argv)

    def test_tcpdump_argv_matches_netplan(self) -> None:
        argv = guest.tcpdump_argv("vprlab-tap0", pathlib.Path("/e/capture.pcap"))
        self.assertEqual(
            argv,
            [
                "tcpdump",
                "-i",
                "vprlab-tap0",
                "-nn",
                "-U",
                "--immediate-mode",
                "-s",
                "0",
                "-w",
                "/e/capture.pcap",
            ],
        )
        import netplan

        self.assertIsNone(netplan.check_capture_argv(argv))


class ActionCommandTests(unittest.TestCase):
    def test_closed_action_set_and_commands(self) -> None:
        name = guest.DEFAULT_NAME
        self.assertEqual(
            run_phase.action_command("start-router", name),
            f"systemctl start vprouter@{name}.service",
        )
        self.assertEqual(run_phase.action_command("idle", name), "true")
        self.assertEqual(
            run_phase.action_command("stop-router", name),
            f"systemctl stop vprouter@{name}.service",
        )
        self.assertIn("nsenter", run_phase.action_command("kill-wireguard", name))
        self.assertIn("ip link del wg0", run_phase.action_command("kill-wireguard", name))
        self.assertEqual(
            run_phase.action_command("kill-container", name), f"docker kill {name}"
        )
        self.assertEqual(
            run_phase.action_command("restart-docker", name),
            "systemctl restart docker.service",
        )
        with self.assertRaises(hostcheck.Refusal):
            run_phase.action_command("not-a-phase", name)

    def test_failure_phases_start_the_router_inside_the_window(self) -> None:
        self.assertEqual(
            run_phase.SETUP_PHASES,
            frozenset(
                {"stop-router", "kill-wireguard", "kill-container", "restart-docker"}
            ),
        )
        self.assertNotIn("start-router", run_phase.SETUP_PHASES)
        self.assertNotIn("idle", run_phase.SETUP_PHASES)


class UserDataTests(unittest.TestCase):
    def setUp(self) -> None:
        text = guest.build_user_data(
            hostname="vprlab-001", name=guest.DEFAULT_NAME, image_id=guest.DEPLOYED_IMAGE_ID
        )
        self.assertTrue(text.startswith("#cloud-config\n"))
        self.config = json.loads(text.split("\n", 1)[1])
        self.script = self.config["write_files"][0]["content"]

    def test_apt_is_minimal_and_no_recommends(self) -> None:
        self.assertIn("--no-install-recommends", self.script)
        for package in (
            "docker.io",
            "docker-compose",
            "qemu-guest-agent",
            "nftables",
            "python3",
            "iproute2",
            "wireguard-tools",
        ):
            self.assertIn(package, self.script)
        self.assertIn("APT::Install-Recommends", self.script)
        self.assertIn("systemctl enable systemd-networkd.service", self.script)
        self.assertIn("/etc/modules-load.d/vprlab-net.conf", self.script)
        self.assertIn("modprobe wireguard", self.script)
        self.assertIn("/dev/net/tun", self.script)
        self.assertIn("swapoff -a", self.script)
        self.assertIn("/usr/local/lib/docker/cli-plugins", self.script)
        self.assertNotIn("openssh-server", self.script)
        self.assertNotIn("sudo", self.script)

    def test_silence_list_is_complete(self) -> None:
        for item in (
            "systemd-timesyncd.service",
            "apt-daily.timer",
            "apt-daily-upgrade.timer",
            "unattended-upgrades",
            "man-db.timer",
            "e2scrub_all.timer",
            "e2scrub_reap.service",
            "fstrim.timer",
            "systemd-resolved.service",
            "ssh.service",
            "ssh.socket",
            "dhclient.service",
            "dhcpcd.service",
            "NetworkManager.service",
            "networking.service",
            "cloud-init.service",
            "cloud-final.service",
        ):
            self.assertIn(item, self.script)
        self.assertIn("systemctl mask", self.script)
        self.assertIn("/etc/cloud/cloud-init.disabled", self.script)
        self.assertIn("LLMNR=no", self.script)
        self.assertIn("MulticastDNS=no", self.script)

    def test_ipv6_disable_via_grub(self) -> None:
        self.assertIn("ipv6.disable=1", self.script)
        self.assertIn("net.ifnames=0", self.script)
        self.assertIn("/etc/default/grub.d/99-vprlab-silence.cfg", self.script)
        self.assertIn("update-grub", self.script)

    def test_static_network_and_neighbor(self) -> None:
        network = guest.networkd_text()
        self.assertIn("MACAddress=" + VM_MAC, network)
        self.assertIn("Address=10.250.0.2/24", network)
        self.assertIn("Gateway=10.250.0.1", network)
        self.assertIn("DHCP=no", network)
        self.assertIn("LinkLocalAddressing=no", network)
        self.assertIn("IPv6AcceptRA=no", network)
        self.assertIn("LLDP=no", network)
        self.assertIn("EmitLLDP=no", network)
        self.assertIn("[Neighbor]", network)
        self.assertIn("Address=10.250.0.1", network)
        self.assertIn("LinkLayerAddress=" + GATEWAY_MAC, network)

    def test_docker_daemon_json(self) -> None:
        expected = {
            "ipv6": False,
            "ip6tables": False,
            "dns": [],
            "log-driver": "local",
        }
        self.assertEqual(json.loads(guest.docker_daemon_text()), expected)
        self.assertIn('"log-driver":"local"', guest.docker_daemon_text())

    def test_image_id_is_verified_and_unit_not_enabled(self) -> None:
        self.assertIn(guest.DEPLOYED_IMAGE_ID, self.config["runcmd"][0])
        self.assertIn('docker image inspect --format', self.script)
        self.assertIn('"$loaded" = "$EXPECTED_IMAGE_ID"', self.script)
        self.assertIn("docker compose version", self.script)
        self.assertIn("systemctl daemon-reload", self.script)
        self.assertIn("ip link add vprlab-wgtest type wireguard", self.script)
        self.assertNotIn("systemctl enable vprouter@", self.script)
        self.assertIn('systemctl is-enabled "vprouter@$NAME.service"', self.script)
        self.assertIn("/etc/systemd/system/vprouter@.service", self.script)
        self.assertIn("VPRLAB-PROVISION-OK", self.script)
        self.assertIn("/dev/ttyS0", self.script)
        self.assertIn("systemctl poweroff", self.script)

    def test_cloud_init_does_not_reboot_or_upgrade(self) -> None:
        self.assertFalse(self.config["package_update"])
        self.assertFalse(self.config["package_upgrade"])
        self.assertFalse(self.config["package_reboot_if_required"])
        self.assertFalse(self.config["ssh_pwauth"])
        self.assertTrue(self.config["disable_root"])

    def test_netns_safe_ipv6_mode_keeps_the_sysctl_tree(self) -> None:
        text = guest.build_user_data(
            hostname="vprlab-001", ipv6_mode="netns-safe"
        )
        config = json.loads(text.split("\n", 1)[1])
        script = config["write_files"][0]["content"]
        self.assertNotIn("ipv6.disable=1", script)
        self.assertIn("net.ipv6.conf.all.disable_ipv6=1", script)
        self.assertIn("net.ipv6.conf.default.disable_ipv6=1", script)
        self.assertIn("net.ifnames=0", script)


class SilenceCheckTests(unittest.TestCase):
    def test_check_script_covers_runtime_state(self) -> None:
        script = guest.silence_check_script(
            name=guest.DEFAULT_NAME, image_id=guest.DEPLOYED_IMAGE_ID
        )
        for text in (
            "SILENCE-OK",
            "ipv6.disable=1",
            "swap_off",
            "DHCP4_CLIENT=0",
            "DHCP6_CLIENT=0",
            "static_neighbor",
            "PERMANENT",
            "docker_daemon_json",
            "qemu-guest-agent",
            "router_unit",
            "systemd-timesyncd.service",
        ):
            self.assertIn(text, script)
        self.assertIn('= "disabled"', script)
        enabled = guest.silence_check_script(
            name=guest.DEFAULT_NAME,
            image_id=guest.DEPLOYED_IMAGE_ID,
            expect_router_disabled=False,
        )
        self.assertIn('= "enabled"', enabled)


class BootControlTests(unittest.TestCase):
    def test_unit_orders_before_docker_and_network_online(self) -> None:
        unit = guest.boot_control_unit_text()
        self.assertIn("Before=network-online.target docker.service", unit)
        self.assertIn("After=systemd-networkd.service", unit)
        self.assertIn("Type=oneshot", unit)
        self.assertIn("ExecStart=/usr/local/sbin/vprlab-boot-control.py", unit)
        self.assertNotIn(NONCE_A, unit)

    def test_script_reads_and_deletes_nonce(self) -> None:
        script = guest.boot_control_script_text()
        self.assertIn("VPRLEAKCTL1:", script)
        self.assertIn("SO_BINDTODEVICE", script)
        self.assertIn("os.unlink(SPEC)", script)
        self.assertIn(guest.BOOT_CONTROL_SPEC, script)
        self.assertNotIn(NONCE_A, script)

    def test_spec_is_mode_ready_and_has_no_key(self) -> None:
        spec = json.loads(
            guest.boot_control_spec(NONCE_A, GATEWAY, 39001, device="eth0")
        )
        self.assertEqual(spec["nonce"], NONCE_A)
        self.assertEqual(spec["sink_ipv4"], GATEWAY)
        self.assertEqual(spec["sink_udp_port"], 39001)
        self.assertEqual(spec["vm_mac"], VM_MAC)
        self.assertEqual(spec["device"], "eth0")
        self.assertNotIn("PrivateKey", json.dumps(spec))


class RefusalTests(unittest.TestCase):
    def test_existing_state_directory_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "vm-001"
            provision.create_state_directory(
                path, uid=os.geteuid(), gid=os.getegid()
            )
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
            with self.assertRaises(FileExistsError):
                provision.create_state_directory(path)

    def test_base_image_hash_mismatch_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary) / "base.qcow2"
            base.write_bytes(b"not the real image")
            digest = guest.sha512_file(base)
            manifest = pathlib.Path(temporary) / "SHA512SUMS"
            manifest.write_text(f"{'0' * 128}  {base.name}\n", encoding="utf-8")
            with self.assertRaises(guest.IntegrityError):
                guest.verify_base_image(base, manifest, expected_digest=digest)

    def test_other_qemu_process_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            proc = pathlib.Path(temporary) / "proc"
            entry = proc / "4242"
            entry.mkdir(parents=True)
            (entry / "cmdline").write_bytes(b"/usr/bin/qemu-system-x86_64\0-m\0512\0")
            with self.assertRaises(hostcheck.Refusal):
                hostcheck.refuse_if_qemu_running(proc_root=proc)
            clean = pathlib.Path(temporary) / "clean-proc" / "4243"
            clean.mkdir(parents=True)
            (clean / "cmdline").write_bytes(b"/usr/bin/python3\0-c\0pass\0")
            hostcheck.refuse_if_qemu_running(proc_root=clean.parent)

    def test_missing_host_network_objects_are_refused(self) -> None:
        links = [
            {
                "ifname": "vprlab0",
                "address": GATEWAY_MAC,
                "flags": ["UP"],
                "linkinfo": {"info_kind": "bridge"},
                "addr_info": [{"family": "inet", "local": GATEWAY, "prefixlen": 24}],
            }
        ]
        table = {"nftables": [{"table": {"family": "inet", "name": "vprlab"}}]}
        neighbor = []
        problems = hostcheck.verify_host_network(links, table, neighbor)
        self.assertTrue(any("tap" in problem for problem in problems))
        self.assertTrue(any("ownership tag" in problem for problem in problems))
        self.assertTrue(any("neighbor" in problem for problem in problems))

    def test_valid_host_network_passes(self) -> None:
        links = [
            {
                "ifname": "vprlab0",
                "address": GATEWAY_MAC,
                "flags": ["UP"],
                "linkinfo": {"info_kind": "bridge"},
                "addr_info": [{"family": "inet", "local": GATEWAY, "prefixlen": 24}],
            },
            {
                "ifname": "vprlab-tap0",
                "flags": ["UP"],
                "linkinfo": {"info_kind": "tap"},
                "master": "vprlab0",
            },
        ]
        table = {
            "nftables": [
                {
                    "table": {
                        "family": "inet",
                        "name": "vprlab",
                        "comment": hostcheck.OWNER_TAG,
                    }
                }
            ]
            + [
                {"chain": {"family": "inet", "name": name, "table": "vprlab"}}
                for name in hostcheck.REQUIRED_CHAINS
            ]
        }
        neighbor = [
            {
                "dst": VM_IP,
                "dev": "vprlab0",
                "lladdr": VM_MAC,
                "state": ["PERMANENT"],
            }
        ]
        addresses = [
            {
                "ifname": "vprlab0",
                "addr_info": [
                    {"family": "inet", "local": GATEWAY, "prefixlen": 24}
                ],
            }
        ]
        self.assertEqual(
            hostcheck.verify_host_network(
                links, table, neighbor, addresses_document=addresses
            ),
            [],
        )

    def test_nonce_reuse_is_refused(self) -> None:
        with self.assertRaises(hostcheck.Refusal):
            run_phase.fresh_pair(
                {NONCE_A}, generator=lambda used: {"before": NONCE_A, "after": NONCE_B}
            )
        with self.assertRaises(hostcheck.Refusal):
            run_phase.fresh_pair(
                set(), generator=lambda used: {"before": NONCE_A, "after": NONCE_A}
            )
        pair = run_phase.fresh_pair(
            set(), generator=lambda used: {"before": NONCE_A, "after": NONCE_B}
        )
        self.assertEqual(pair, {"before": NONCE_A, "after": NONCE_B})

    def test_allow_arp_false_is_loader_compatible(self) -> None:
        policy = run_phase.policy_mod.parse_policy(
            {
                "schema_version": 1,
                "vm_wan_mac": VM_MAC,
                "vm_wan_ipv4": VM_IP,
                "gateway_ipv4": GATEWAY,
                "gateway_mac": GATEWAY_MAC,
                "allowed": [
                    {
                        "proto": "udp",
                        "dst_ipv4": "185.65.134.10",
                        "dst_port": 51820,
                        "label": "mullvad-se-sto",
                    }
                ],
                "allow_arp": False,
                "positive_control": {
                    "sink_ipv4": GATEWAY,
                    "sink_udp_port": 39001,
                },
                "ipv6_allowed": False,
            }
        )
        self.assertFalse(policy.allow_arp)
        run_phase.verify_policy(policy)
        wrong = run_phase.policy_mod.parse_policy(
            {
                "schema_version": 1,
                "vm_wan_mac": VM_MAC,
                "vm_wan_ipv4": VM_IP,
                "gateway_ipv4": GATEWAY,
                "gateway_mac": "52:54:00:76:70:55",
                "allowed": [
                    {
                        "proto": "udp",
                        "dst_ipv4": "185.65.134.10",
                        "dst_port": 51820,
                        "label": "mullvad-se-sto",
                    }
                ],
                "allow_arp": False,
                "positive_control": {
                    "sink_ipv4": GATEWAY,
                    "sink_udp_port": 39001,
                },
                "ipv6_allowed": False,
            }
        )
        with self.assertRaises(hostcheck.Refusal):
            run_phase.verify_policy(wrong)


class SecretTests(unittest.TestCase):
    def test_secret_material_repr_is_redacted(self) -> None:
        material = run_phase.SecretMaterial(SECRET_TEXT)
        self.assertNotIn("SUPERSECRETKEYMATERIAL", repr(material))

    def test_profile_endpoint_never_echoes_keys(self) -> None:
        material = run_phase.SecretMaterial(SECRET_TEXT)
        self.assertEqual(run_phase.profile_endpoint(material), ("185.65.134.10", 51820))
        with self.assertRaises(hostcheck.Refusal) as raised:
            run_phase.profile_endpoint(
                run_phase.SecretMaterial(b"PrivateKey = SUPERSECRETKEYMATERIAL\n")
            )
        self.assertNotIn("SUPERSECRETKEYMATERIAL", str(raised.exception))

    def test_read_profile_path_requires_0600(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "profile.conf"
            path.write_bytes(SECRET_TEXT)
            os.chmod(path, 0o644)
            with self.assertRaises(hostcheck.Refusal):
                run_phase.read_profile_path(path, owner_uid=os.geteuid())
            os.chmod(path, 0o600)
            material = run_phase.read_profile_path(path, owner_uid=os.geteuid())
            self.assertEqual(material.data, SECRET_TEXT)

    def test_profile_fd_read(self) -> None:
        with tempfile.TemporaryFile() as stream:
            stream.write(SECRET_TEXT)
            stream.flush()
            os.lseek(stream.fileno(), 0, os.SEEK_SET)
            material = run_phase.read_profile_fd(stream.fileno())
        self.assertEqual(material.data, SECRET_TEXT)

    def test_secret_never_enters_argv_or_phase_record(self) -> None:
        qemu_argv = guest.build_qemu_argv("test", pathlib.Path("/state"))
        self.assertNotIn(SECRET_TEXT.decode(), " ".join(qemu_argv))
        record = run_phase.base_phase_record(
            phase="start-router",
            name=guest.DEFAULT_NAME,
            state=pathlib.Path("/state"),
            evidence_dir=pathlib.Path("/state/evidence"),
            image_id=guest.DEPLOYED_IMAGE_ID,
        )
        record["qemu_argv"] = qemu_argv
        record["launch_argv"] = ["/usr/bin/setpriv", "--", *qemu_argv]
        record["pcapscan_argv"] = ["pcapscan.py", "--policy", "/policy.json"]
        rendered = json.dumps(record)
        self.assertNotIn(SECRET_TEXT.decode(), rendered)
        self.assertNotIn("PRIVATEKEY", rendered.upper())

    def test_install_guest_file_is_0600_and_secret_is_not_returned(self) -> None:
        client = RecordingClient()
        run_phase.install_guest_file(
            client, "/etc/vprouter/x.conf", SECRET_TEXT, mode=0o600
        )
        self.assertTrue(any("chmod 0600" in command for command in client.commands))
        self.assertEqual(client.writes, [("/run/vprlab-stage/x.conf", SECRET_TEXT)])

    def test_prepare_vm_secrets_returns_paths_only(self) -> None:
        client = RecordingClient()
        paths = run_phase.prepare_vm_secrets(
            client, guest.DEFAULT_NAME, run_phase.SecretMaterial(SECRET_TEXT), guest.DEPLOYED_IMAGE_ID
        )
        self.assertEqual(
            paths,
            {
                "profile_path": "/etc/vprouter/zz-vprtest-01-do-not-use.conf",
                "config_path": "/etc/vprouter/zz-vprtest-01-do-not-use.json",
                "state_dir": "/var/lib/vprouter/zz-vprtest-01-do-not-use",
            },
        )
        self.assertTrue(any(data == SECRET_TEXT for _path, data in client.writes))
        self.assertNotIn("SUPERSECRETKEYMATERIAL", json.dumps(paths))
        self.assertTrue(any("chmod 0600" in command for command in client.commands))


class RecordingClient:
    """Minimal in-memory client for secret installation tests."""

    def __init__(self) -> None:
        self.commands: list[str] = []
        self.writes: list[tuple[str, bytes]] = []

    def execute(self, program: str, args=(), timeout: float = 30.0, **kwargs) -> ExecResult:
        del program, timeout, kwargs
        command = args[-1] if args else ""
        self.commands.append(command)
        if "stat -c" in command:
            return ExecResult(exitcode=0, stdout=b"600 root root\n", stderr=b"")
        return ExecResult(exitcode=0, stdout=b"", stderr=b"")

    def write_file(self, path: str, data: bytes, timeout: float = 60.0) -> None:
        del timeout
        self.writes.append((path, bytes(data)))


class PhaseRecordTests(unittest.TestCase):
    def test_record_shape_and_no_secret(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = pathlib.Path(temporary) / "vm-001"
            evidence = pathlib.Path(temporary) / "evidence"
            record = run_phase.base_phase_record(
                phase="start-router",
                name=guest.DEFAULT_NAME,
                state=state,
                evidence_dir=evidence,
                image_id=guest.DEPLOYED_IMAGE_ID,
            )
            record["nonces"].update(
                {"before": NONCE_A, "after": NONCE_B, "reserved": True}
            )
            record["hashes"] = {
                "pcap_sha256": "1" * 64,
                "stats_sha256": "2" * 64,
                "policy_sha256": "3" * 64,
                "scan_sha256": "4" * 64,
            }
            record["timestamps"] = {"started_at": "2026-11-09T00:00:00+00:00"}
            record["result"] = "PASS"
            self.assertEqual(record["schema"], "vprlab-vm-phase-v1")
            self.assertEqual(record["nonces"]["before"], NONCE_A)
            self.assertEqual(record["guest"]["profile_path"].endswith(".conf"), True)
            rendered = json.dumps(record)
            self.assertNotIn("SUPERSECRETKEYMATERIAL", rendered)
            self.assertNotIn("PrivateKey", rendered)

    def test_private_record_is_mode_0600(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "phase.json"
            run_phase.write_private_json(path, {"a": 1})
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(json.loads(path.read_text()), {"a": 1})


class OverlayTests(unittest.TestCase):
    def test_single_level_overlay_passes_and_deviations_fail(self) -> None:
        overlay = pathlib.Path("/lab/overlay.qcow2")
        base = pathlib.Path("/lab/base.qcow2")
        document = [
            {
                "filename": str(overlay),
                "format": "qcow2",
                "full-backing-filename": str(base),
            },
            {"filename": str(base), "format": "qcow2"},
        ]
        guest.verify_overlay_chain(document, overlay, base)
        bad = [document[0], dict(document[1], **{"backing-filename": "/other"})]
        with self.assertRaises(guest.IntegrityError):
            guest.verify_overlay_chain(bad, overlay, base)
        with self.assertRaises(guest.IntegrityError):
            guest.verify_overlay_chain(document[:1], overlay, base)


class NameTests(unittest.TestCase):
    def test_default_name_is_a_test_node(self) -> None:
        self.assertEqual(guest.validate_name(guest.DEFAULT_NAME), guest.DEFAULT_NAME)
        self.assertTrue(tsnames.is_test_node(guest.DEFAULT_NAME))
        self.assertFalse(tsnames.is_test_node("production-router"))
        with self.assertRaises(guest.GeneratorError):
            guest.validate_name("Production-Router")

    def test_state_path(self) -> None:
        self.assertEqual(guest.state_path(1), pathlib.Path("/DATA/vprouter-lab/leaklab/vm-001"))
        with self.assertRaises(guest.GeneratorError):
            guest.state_path(0)


if __name__ == "__main__":
    unittest.main()


class ControllerDecisionTests(unittest.TestCase):
    def test_expect_tunnel_has_no_default(self) -> None:
        import contextlib
        import io

        import run_phase

        argv = [
            "--phase", "idle", "--duration", "1", "--policy", "p.json",
            "--used-nonces", "u.txt",
        ]
        with contextlib.redirect_stderr(io.StringIO()) as err:
            with self.assertRaises(SystemExit) as raised:
                run_phase.main(argv)
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("--expect-tunnel", err.getvalue())

    def test_failed_action_cannot_certify_a_clean_capture(self) -> None:
        source = (pathlib.Path(__file__).parent / "run_phase.py").read_text()
        self.assertIn('if error is not None and scan_exit == 0:', source)
        self.assertIn('"phase_action_failed"', source)

    def test_provision_defaults_to_netns_safe_ipv6(self) -> None:
        source = (pathlib.Path(__file__).parent / "provision.py").read_text()
        self.assertIn('default="netns-safe"', source)
