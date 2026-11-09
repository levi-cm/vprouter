#!/usr/bin/env python3
"""Offline tests for the vprlab leak-lab VM tooling.

No test starts QEMU, tcpdump, ip, nft, docker, qemu-img, genisoimage or a
network connection.  ``run_phase.run_phase()`` is executed for real with fake
process, QGA and scanner layers; the QGA client is also exercised against a
fake unix-socket agent.  Everything else is pure argv/user-data/record
generation plus refusal paths.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import io
import json
import os
import pathlib
import re
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import guest
import hostcheck
import login_url
import provision
import runlock
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
LOGIN_URL = "https://login.tailscale.com/a/0123456789abcdef"


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
        error_desc: str | None = None,
    ):
        super().__init__(daemon=True)
        self.path = path
        self.exec_stdout = exec_stdout
        self.exec_stderr = exec_stderr
        self.exec_exit = exec_exit
        self.hang_status = hang_status
        self.error_on = error_on
        self.error_desc = error_desc
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
        description = self.error_desc
        if description is None:
            description = f"injected {name} error"
        self._send(
            connection,
            {"error": {"class": "GenericError", "desc": description}},
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

    def test_exec_status_timeout_closes_the_stream(self) -> None:
        self.start_server(hang_status=True)
        client = self.client()
        with self.assertRaises(QGATimeout):
            client.execute("/bin/sh", ["-c", "sleep 100"], timeout=0.3)
        with self.assertRaises(QGAError):
            client.ping(timeout=0.1)

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

    def test_guest_error_text_is_bounded_and_stripped(self) -> None:
        sentinel = "PRIVATE-KEY-SENTINEL" * 40 + "\x00\x07\x1b"
        self.start_server(
            error_on=frozenset({"guest-ping"}), error_desc=sentinel
        )
        client = self.client()
        with self.assertRaises(QGAError) as raised:
            client.ping(timeout=5.0)
        message = str(raised.exception)
        self.assertNotIn("\x00", message)
        self.assertNotIn("\x07", message)
        self.assertNotIn("\x1b", message)
        self.assertLessEqual(len(message), 200 + len("guest agent error GenericError: guest-ping: "))
        self.assertIn("guest-ping", message)


class QemuArgvTests(unittest.TestCase):
    def test_test_mode_is_tap_only_and_has_no_qmp(self) -> None:
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
        self.assertIn("-nodefaults", argv)
        self.assertIn("-no-user-config", argv)
        self.assertIn(
            "socket,id=qga0,path=/state/qga.sock,server=on,wait=off", argv
        )
        self.assertIn("virtserialport,chardev=qga0,name=org.qemu.guest_agent.0", argv)
        self.assertNotIn("-qmp", argv)
        self.assertNotIn("qmp.sock", joined)
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

    def test_unprivileged_launch_drops_every_privilege(self) -> None:
        argv = guest.build_qemu_argv("test", pathlib.Path("/state"))
        launched = guest.build_launch_argv(argv, "opsec", uid=1000, gid=1000)
        self.assertEqual(
            launched[:8],
            [
                "/usr/bin/setpriv",
                "--reuid=1000",
                "--regid=1000",
                "--clear-groups",
                "--no-new-privs",
                "--inh-caps=-all",
                "--bounding-set=-all",
                "--",
            ],
        )
        self.assertIn("--no-new-privs", launched)
        self.assertIn("--inh-caps=-all", launched)
        self.assertIn("--bounding-set=-all", launched)
        self.assertEqual(launched[launched.index("--") + 1 :], argv)

    def test_uid_zero_is_refused(self) -> None:
        with self.assertRaises(guest.GeneratorError):
            guest.build_launch_argv(["qemu"], "root", uid=0, gid=0)
        with self.assertRaises(guest.GeneratorError):
            guest.build_setpriv_argv(["tool"], 0, 0)
        with self.assertRaises(guest.GeneratorError):
            guest.resolve_unprivileged_user("root")

    def test_generator_tools_run_as_qemu_with_private_umask(self) -> None:
        wrapper = guest.build_private_tool_argv(
            ["/lab/qemu-img", "create", "out"], 123, 456
        )
        self.assertEqual(wrapper[0], "/usr/bin/setpriv")
        self.assertIn("--reuid=123", wrapper)
        self.assertIn("--regid=456", wrapper)
        self.assertIn("--no-new-privs", wrapper)
        self.assertIn("/bin/sh", wrapper)
        self.assertIn("umask 077; exec \"$@\"", wrapper)
        self.assertEqual(wrapper[-3:], ["/lab/qemu-img", "create", "out"])
        plain = guest.build_setpriv_argv(["/lab/genisoimage", "-quiet"], 123, 456)
        self.assertNotIn("/bin/sh", plain)

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
        self.assertEqual(run_phase.action_command("login", name), "true")
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

    def test_phase_tables_are_fixed(self) -> None:
        self.assertEqual(
            run_phase.SETUP_PHASES,
            frozenset(
                {
                    "idle",
                    "login",
                    "stop-router",
                    "kill-wireguard",
                    "kill-container",
                    "restart-docker",
                }
            ),
        )
        self.assertNotIn("start-router", run_phase.SETUP_PHASES)
        for phase in run_phase.PHASES:
            self.assertEqual(run_phase.PHASE_EXPECTATIONS[phase], "up")

    def test_fault_postconditions_name_the_real_effect(self) -> None:
        name = guest.DEFAULT_NAME
        stop = run_phase.postcondition_command("stop-router", name)
        self.assertIn("is-active", stop)
        wireguard = run_phase.postcondition_command("kill-wireguard", name)
        self.assertIn("ip link show wg0", wireguard)
        container = run_phase.postcondition_command("kill-container", name)
        self.assertIn("State.Running", container)
        self.assertIsNone(run_phase.postcondition_command("start-router", name))


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

    def test_silence_list_covers_debian_13_units(self) -> None:
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
            "ifup@.service",
            "chrony.service",
            "cloud-init-main.service",
            "cloud-init-network.service",
            "cloud-init-local.service",
            "cloud-config.service",
            "cloud-final.service",
            "cloud-init-hotplugd.socket",
        ):
            self.assertIn(item, self.script)
        self.assertIn("systemctl mask", self.script)
        self.assertIn("/etc/cloud/cloud-init.disabled", self.script)
        self.assertIn("/var/lib/vprlab", self.script)
        self.assertIn("LLMNR=no", self.script)
        self.assertIn("MulticastDNS=no", self.script)

    def test_ipv6_default_is_netns_safe(self) -> None:
        self.assertNotIn("ipv6.disable=1", self.script)
        self.assertIn("net.ipv6.conf.all.disable_ipv6=1", self.script)
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


class SilenceCheckTests(unittest.TestCase):
    def test_script_uses_debian_13_networkd_facts(self) -> None:
        script = guest.silence_check_script(
            name=guest.DEFAULT_NAME, image_id=guest.DEPLOYED_IMAGE_ID
        )
        self.assertIn('ip -4 -o neigh show dev "$interface"', script)
        self.assertNotIn("DHCP4_CLIENT", script)
        self.assertNotIn("DHCP6_CLIENT", script)
        self.assertIn("DHCP=no", script)
        self.assertIn("networkctl status", script)
        self.assertIn("dhcp_lease_absent", script)
        self.assertIn("cloud-init-main.service", script)
        self.assertIn("cloud-init-network.service", script)
        self.assertIn("cloud-init-hotplugd.socket", script)
        self.assertIn("cloud_init_units_inactive", script)
        self.assertIn('= "disabled"', script)
        enabled = guest.silence_check_script(
            name=guest.DEFAULT_NAME,
            image_id=guest.DEPLOYED_IMAGE_ID,
            expect_router_disabled=False,
        )
        self.assertIn('= "enabled"', enabled)

    def test_script_executes_against_debian_13_shims(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            bindir = root / "bin"
            bindir.mkdir()
            mac = pathlib.Path("/sys/class/net/lo/address").read_text().strip()
            network_file = root / "10-vprlab-wan.network"
            network_file.write_text("[Network]\nDHCP=no\n", encoding="utf-8")
            lease_dir = root / "leases"
            lease_dir.mkdir()
            shims = {
                "systemctl": """#!/bin/sh
case "$1" in
  is-enabled)
    case "$2" in
      vprouter@*) echo disabled ;;
      *) echo masked ;;
    esac ;;
  list-units) exit 0 ;;
  is-active)
    case "$*" in
      *qemu-guest-agent*) exit 0 ;;
      *) exit 3 ;;
    esac ;;
  *) exit 0 ;;
esac
""",
                "ip": """#!/bin/sh
case "$*" in
  "-4 -o addr show dev lo") echo "1: lo    inet 10.250.0.2/24 scope global lo" ;;
  "-4 -o route show default") echo "default via 10.250.0.1 dev lo" ;;
  "-4 -o neigh show dev lo") echo "10.250.0.1 dev lo lladdr 52:54:00:76:70:01 PERMANENT" ;;
  "-6 -o addr show dev lo") exit 0 ;;
  *) exit 0 ;;
esac
""",
                "networkctl": """#!/bin/sh
echo "Network File: /etc/systemd/network/10-vprlab-wan.network"
""",
                "stat": """#!/bin/sh
case "$1" in
  -c)
    case "$2" in
      %u) echo 0 ;;
      %a) echo 755 ;;
      *) echo 0 ;;
    esac ;;
  *) echo 0 ;;
esac
""",
            }
            for name, text in shims.items():
                path = bindir / name
                path.write_text(text, encoding="utf-8")
                path.chmod(0o755)
            script = guest.silence_check_script(
                name=guest.DEFAULT_NAME,
                image_id=guest.DEPLOYED_IMAGE_ID,
                vm_mac=mac,
            )
            environment = dict(os.environ)
            environment["PATH"] = f"{bindir}:/usr/bin:/bin"
            environment["VPRLAB_NETWORK_FILE"] = str(network_file)
            environment["VPRLAB_LEASE_DIR"] = str(lease_dir)
            completed = subprocess.run(
                ["/bin/sh", "-c", script],
                capture_output=True,
                text=True,
                env=environment,
                timeout=60,
            )
        output = completed.stdout
        self.assertIn("CHECK-OK static_neighbor", output)
        self.assertIn("CHECK-OK dhcp_off_network_file", output)
        self.assertIn("CHECK-OK dhcp_lease_absent", output)
        self.assertIn("CHECK-OK dhcp_client_absent", output)
        self.assertIn("CHECK-OK masked:cloud-init-main.service", output)
        self.assertIn("CHECK-OK cloud_init_units_inactive", output)
        self.assertNotIn("CHECK-FAIL static_neighbor", output)
        self.assertNotIn("CHECK-FAIL dhcp_off_network_file", output)
        self.assertNotIn("CHECK-FAIL dhcp_lease_present", output)
        self.assertNotIn("CHECK-FAIL dhcp_client_configured", output)


class BootControlTests(unittest.TestCase):
    def test_unit_orders_before_docker_and_network_online(self) -> None:
        unit = guest.boot_control_unit_text()
        self.assertIn("Before=network-online.target docker.service", unit)
        self.assertIn("After=systemd-networkd.service", unit)
        self.assertIn("Type=oneshot", unit)
        self.assertIn("ExecStart=/usr/local/sbin/vprlab-boot-control.py", unit)
        self.assertNotIn(NONCE_A, unit)

    def test_spec_lives_in_persistent_root_only_state(self) -> None:
        self.assertTrue(guest.BOOT_CONTROL_SPEC.startswith("/var/lib/vprlab/"))
        self.assertTrue(guest.BOOT_CONTROL_SENT.startswith("/var/lib/vprlab/"))
        self.assertFalse(guest.BOOT_CONTROL_SPEC.startswith("/run/"))
        script = guest.boot_control_script_text()
        self.assertIn(guest.BOOT_CONTROL_SPEC, script)
        self.assertIn("boot_token", script)
        self.assertNotIn(NONCE_A, script)

    def test_spec_is_bound_to_one_boot_and_has_no_key(self) -> None:
        token = "c" * 32
        spec = json.loads(
            guest.boot_control_spec(
                NONCE_A, GATEWAY, 39001, boot_token=token, device="eth0"
            )
        )
        self.assertEqual(spec["nonce"], NONCE_A)
        self.assertEqual(spec["boot_token"], token)
        self.assertEqual(spec["sink_ipv4"], GATEWAY)
        self.assertEqual(spec["sink_udp_port"], 39001)
        self.assertEqual(spec["vm_mac"], VM_MAC)
        self.assertEqual(spec["device"], "eth0")
        self.assertNotIn("PrivateKey", json.dumps(spec))
        with self.assertRaises(guest.GeneratorError):
            guest.boot_control_spec(NONCE_A, GATEWAY, 39001, boot_token="short")

    def test_script_sends_from_persistent_spec_after_run_is_recreated(self) -> None:
        """The generated script must not need any previous-boot /run state."""
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            spec_path = root / "boot-control.json"
            sent_path = root / "boot-control-sent"
            token = "d" * 32
            spec_path.write_text(
                guest.boot_control_spec(
                    NONCE_A, GATEWAY, 39001, boot_token=token, device="lo"
                ),
                encoding="ascii",
            )
            sent: list[tuple[bytes, tuple[str, int]]] = []

            class FakeChannel:
                def setsockopt(self, *_args) -> None:
                    return None

                def bind(self, _address) -> None:
                    return None

                def sendto(self, payload, address) -> None:
                    sent.append((payload, address))

                def close(self) -> None:
                    return None

            class FakeSocketModule:
                AF_INET = socket.AF_INET
                SOCK_DGRAM = socket.SOCK_DGRAM
                SOL_SOCKET = socket.SOL_SOCKET

                @staticmethod
                def socket(*_args):
                    return FakeChannel()

            class FakeCompleted:
                stdout = "1: lo inet 10.250.0.2/24"

            class FakeSubprocess:
                @staticmethod
                def run(*_args, **_kwargs):
                    return FakeCompleted()

            script = guest.boot_control_script_text()
            script = script.replace(guest.BOOT_CONTROL_SPEC, str(spec_path))
            script = script.replace(guest.BOOT_CONTROL_SENT, str(sent_path))
            namespace: dict = {"__name__": "vprlab_boot_control_test"}
            exec(compile(script, "boot-control.py", "exec"), namespace)
            namespace["socket"] = FakeSocketModule
            namespace["subprocess"] = FakeSubprocess
            namespace["main"]()
            self.assertEqual(sent, [(b"VPRLEAKCTL1:" + NONCE_A.encode(), (GATEWAY, 39001))])
            self.assertEqual(sent_path.read_text(encoding="ascii"), token + "\n")
            self.assertFalse(spec_path.exists())


class HostcheckTests(unittest.TestCase):
    def _valid_documents(self, *, tap_kind="real", master=True, ifalias=True):
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
                "linkinfo": (
                    {"info_kind": "tun", "info_data": {"type": "tap", "persist": True}}
                    if tap_kind == "real"
                    else {"info_kind": "tun", "info_data": {"type": "tun"}}
                ),
            },
        ]
        if master:
            links[1]["master"] = "vprlab0"
        if ifalias:
            links[0]["ifalias"] = "vprlab-owned:" + "e" * 32
            links[1]["ifalias"] = "vprlab-owned:" + "e" * 32
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
        return links, table, neighbor

    def test_real_tap_shape_with_owner_token_passes(self) -> None:
        links, table, neighbor = self._valid_documents()
        self.assertEqual(
            hostcheck.verify_host_network(
                links, table, neighbor, owner_token="e" * 32
            ),
            [],
        )

    def test_plain_tun_is_not_a_tap(self) -> None:
        links, table, neighbor = self._valid_documents(tap_kind="tun")
        problems = hostcheck.verify_host_network(
            links, table, neighbor, owner_token="e" * 32
        )
        self.assertTrue(any("not a tap" in problem for problem in problems))

    def test_tap_must_be_enslaved_to_the_bridge(self) -> None:
        links, table, neighbor = self._valid_documents(master=False)
        problems = hostcheck.verify_host_network(
            links, table, neighbor, owner_token="e" * 32
        )
        self.assertTrue(any("enslaved" in problem for problem in problems))

    def test_missing_owner_ifalias_is_refused(self) -> None:
        links, table, neighbor = self._valid_documents(ifalias=False)
        problems = hostcheck.verify_host_network(
            links, table, neighbor, owner_token="e" * 32
        )
        self.assertTrue(any("ifalias" in problem for problem in problems))

    def test_owner_document_schema_and_modes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "owner.json"
            path.write_text(
                json.dumps({"schema": 1, "token": "f" * 32}), encoding="utf-8"
            )
            os.chmod(path, 0o600)
            self.assertEqual(
                hostcheck.load_owner_token(path, require_root=False), "f" * 32
            )
            path.write_text(
                json.dumps({"schema": 2, "token": "f" * 32}), encoding="utf-8"
            )
            with self.assertRaises(hostcheck.Refusal):
                hostcheck.load_owner_token(path, require_root=False)
            path.write_text(
                json.dumps({"schema": 1, "token": "not-hex"}), encoding="utf-8"
            )
            with self.assertRaises(hostcheck.Refusal):
                hostcheck.load_owner_token(path, require_root=False)
            path.write_text(
                json.dumps({"schema": 1, "token": "f" * 32}), encoding="utf-8"
            )
            os.chmod(path, 0o644)
            with self.assertRaises(hostcheck.Refusal):
                hostcheck.load_owner_token(path, require_root=False)


class RunLockTests(unittest.TestCase):
    def test_second_runner_is_refused_and_release_works(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "run.lock"
            descriptor = runlock.acquire(path)
            try:
                with self.assertRaises(runlock.LockBusy):
                    runlock.acquire(path)
            finally:
                runlock.release(descriptor)
            second = runlock.acquire(path)
            runlock.release(second)

    def test_login_url_refuses_while_a_phase_holds_the_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            lock = root / "run.lock"
            state = root / "vm-001"
            state.mkdir()
            descriptor = runlock.acquire(lock)
            try:
                with contextlib.redirect_stderr(io.StringIO()) as error:
                    code = login_url.main(
                        [
                            "--state",
                            str(state),
                            "--run-lock",
                            str(lock),
                            "--connect-timeout",
                            "0.1",
                        ]
                    )
            finally:
                runlock.release(descriptor)
            self.assertEqual(code, 2)
            self.assertIn("another leak-lab run", error.getvalue())

    def test_login_url_may_probe_when_no_phase_runs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            lock = root / "run.lock"
            state = root / "vm-001"
            state.mkdir()
            with contextlib.redirect_stderr(io.StringIO()) as error:
                code = login_url.main(
                    [
                        "--state",
                        str(state),
                        "--run-lock",
                        str(lock),
                        "--connect-timeout",
                        "0.1",
                    ]
                )
            self.assertEqual(code, 2)
            self.assertNotIn("another leak-lab run", error.getvalue())


class RefusalTests(unittest.TestCase):
    def test_existing_state_directory_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "vm-001"
            provision.create_state_directory(path)
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

    def test_provision_refuses_root_qemu_user_before_launch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            image_tar = root / "image.tar"
            image_tar.write_bytes(b"tar")
            args = argparse.Namespace(
                index=1,
                state_root=str(root / "state-root"),
                name=guest.DEFAULT_NAME,
                image_id=guest.DEPLOYED_IMAGE_ID,
                image_tar=str(image_tar),
                release_dir="/opt/vprouter/current",
                base_image=str(root / "base.qcow2"),
                checksum_manifest=str(root / "manifest"),
                qemu_user="root",
                ipv6_mode="netns-safe",
                run_lock=str(root / "run.lock"),
            )
            with mock.patch.object(provision, "require_root"), mock.patch.object(
                provision.guest, "verify_base_image", return_value="0" * 128
            ), mock.patch.object(
                provision.hostcheck, "refuse_if_qemu_running"
            ), mock.patch.object(provision, "_require_tool"):
                with self.assertRaises(hostcheck.Refusal):
                    provision.provision(args)

    def test_provision_refuses_while_the_global_lock_is_held(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            args = argparse.Namespace(
                index=1,
                state_root=str(root / "state-root"),
                name=guest.DEFAULT_NAME,
                image_id=guest.DEPLOYED_IMAGE_ID,
                image_tar=str(root / "image.tar"),
                release_dir="/opt/vprouter/current",
                base_image=str(root / "base.qcow2"),
                checksum_manifest=str(root / "manifest"),
                qemu_user=guest.QEMU_USER,
                ipv6_mode="netns-safe",
                run_lock=str(root / "run.lock"),
            )
            descriptor = runlock.acquire(root / "run.lock")
            try:
                with mock.patch.object(provision, "require_root"):
                    with self.assertRaises(runlock.LockBusy):
                        provision.provision(args)
            finally:
                runlock.release(descriptor)

    def test_generator_tools_are_wrapped_in_setpriv(self) -> None:
        captured = {}

        class Completed:
            returncode = 0
            stdout = ""
            stderr = ""

        def fake_run(argv, **kwargs):
            captured["argv"] = argv
            captured["env"] = kwargs.get("env")
            return Completed()

        with mock.patch.object(provision.subprocess, "run", side_effect=fake_run):
            provision._run_generator(
                ["/lab/qemu-img", "create", "out"],
                uid=123,
                gid=456,
                what="qemu-img create",
                timeout=10,
                umask=0o077,
            )
        argv = captured["argv"]
        self.assertEqual(argv[0], "/usr/bin/setpriv")
        self.assertIn("--reuid=123", argv)
        self.assertIn("--regid=456", argv)
        self.assertIn("umask 077; exec \"$@\"", argv)
        self.assertEqual(argv[-3:], ["/lab/qemu-img", "create", "out"])
        self.assertEqual(captured["env"]["LD_LIBRARY_PATH"], str(guest.LAB_LIBRARY_DIR))


class ProvisionPipelineTests(unittest.TestCase):
    def test_provision_runs_every_generator_as_the_qemu_user(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            state_root = root / "state-root"
            release = root / "release"
            release.mkdir()
            for relative in guest.TRUSTED_RELEASE_FILES:
                path = release / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("# release\n", encoding="utf-8")
            unit = release / guest.UNIT_SOURCE
            unit.parent.mkdir(parents=True, exist_ok=True)
            unit.write_text("[Unit]\n", encoding="utf-8")
            image_tar = root / "image.tar"
            image_tar.write_bytes(b"image-tar")
            base = root / "base.qcow2"
            base.write_bytes(b"base")
            manifest = root / "manifest"
            manifest.write_text("", encoding="utf-8")
            arguments = argparse.Namespace(
                index=1,
                state_root=str(state_root),
                name=guest.DEFAULT_NAME,
                image_id=guest.DEPLOYED_IMAGE_ID,
                image_tar=str(image_tar),
                release_dir=str(release),
                base_image=str(base),
                checksum_manifest=str(manifest),
                qemu_user=guest.QEMU_USER,
                ipv6_mode="netns-safe",
                run_lock=str(root / "run.lock"),
            )
            generator_calls: list[list[str]] = []

            def fake_run(argv, **kwargs):
                del kwargs
                generator_calls.append(list(argv))
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

            state = state_root / "vm-001"
            serial = state / guest.SERIAL_FILE
            image_id = guest.DEPLOYED_IMAGE_ID

            class FakeQemu:
                returncode = None
                pid = 9001

                def __init__(self, argv, **kwargs):
                    del argv, kwargs
                    serial.write_text(
                        f"VPRLAB-PROVISION-OK {image_id}\n", encoding="utf-8"
                    )

                def poll(self):
                    return self.returncode

                def wait(self, timeout=None):
                    del timeout
                    self.returncode = 0
                    return 0

            uid = os.geteuid()
            gid = os.getegid()
            with mock.patch.object(provision, "require_root"), mock.patch.object(
                provision.guest, "verify_base_image", return_value="0" * 128
            ), mock.patch.object(
                provision.hostcheck, "refuse_if_qemu_running"
            ), mock.patch.object(
                provision, "_require_tool"
            ), mock.patch.object(
                provision, "_qemu_identity", return_value=(uid, gid)
            ), mock.patch.object(
                provision.os, "chown"
            ), mock.patch.object(
                provision.subprocess, "run", side_effect=fake_run
            ), mock.patch.object(
                provision.subprocess, "Popen", FakeQemu
            ), mock.patch.object(
                provision.time, "sleep"
            ), contextlib.redirect_stdout(io.StringIO()):
                code = provision.provision(arguments)
            self.assertEqual(code, 0)
            self.assertEqual(len(generator_calls), 3)
            for argv in generator_calls:
                self.assertEqual(argv[0], "/usr/bin/setpriv")
                self.assertIn(f"--reuid={uid}", argv)
                self.assertIn(f"--regid={gid}", argv)
                self.assertIn("--no-new-privs", argv)
            self.assertIn("create", generator_calls[0])
            self.assertIn("genisoimage", " ".join(generator_calls[1]))
            self.assertIn("genisoimage", " ".join(generator_calls[2]))
            self.assertEqual(
                stat.S_IMODE(state.stat().st_mode), 0o700
            )
            record = json.loads((state / "provision.json").read_text())
            self.assertEqual(record["test_status"], "PROVISIONED_OFFLINE_READY")
            self.assertEqual(record["qemu_exit_status"], 0)
            self.assertEqual(record["qemu_user"], guest.QEMU_USER)


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

    def test_endpoint_parser_matches_configparser_case_rules(self) -> None:
        material = run_phase.SecretMaterial(
            b"[peer]\nendpoint = 185.65.134.10:51820\n"
        )
        self.assertEqual(run_phase.profile_endpoint(material), ("185.65.134.10", 51820))

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
            evidence_dir=pathlib.Path("/evidence"),
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


class PolicyBindingTests(unittest.TestCase):
    def test_built_policy_is_exactly_the_profile_endpoint(self) -> None:
        policy = run_phase.build_lab_policy(("185.65.134.10", 51820))
        self.assertEqual(len(policy.allowed), 1)
        flow = policy.allowed[0]
        self.assertEqual((flow.dst_ipv4, flow.dst_port), ("185.65.134.10", 51820))
        self.assertEqual(policy.positive_control.sink_udp_port, run_phase.SINK_UDP_PORT)
        self.assertFalse(policy.allow_arp)
        self.assertEqual(policy.gateway_mac, GATEWAY_MAC)

    def test_non_public_endpoint_is_refused(self) -> None:
        for endpoint in (("10.0.0.5", 51820), ("192.168.1.5", 51820), ("127.0.0.1", 51820)):
            with self.assertRaises(hostcheck.Refusal):
                run_phase.build_lab_policy(endpoint)

    def test_policy_with_extra_flow_is_refused(self) -> None:
        document = run_phase.build_lab_policy(("185.65.134.10", 51820)).to_dict()
        document["allowed"].append(
            {"proto": "udp", "dst_ipv4": "1.1.1.1", "dst_port": 4444, "label": "extra"}
        )
        policy = run_phase.policy_mod.parse_policy(document)
        with self.assertRaises(hostcheck.Refusal):
            run_phase.verify_policy(policy, endpoint=("185.65.134.10", 51820))


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
            self.assertEqual(record["expect_tunnel"], "up")
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


# ---------------------------------------------------------------------------
# Behavioural runner harness


class FakeProcess:
    def __init__(self, events: list) -> None:
        self.events = events
        self.returncode = None
        self.pid = 4242

    def poll(self):
        return None

    def wait(self, timeout=None):
        self.events.append(("qemu_exit",))
        self.returncode = 0
        return 0


class FakeCaptureProcess:
    def __init__(self, events: list) -> None:
        self.events = events
        self.pid = 5151
        self.returncode = None

    def poll(self):
        return None

    def send_signal(self, _signum):
        self.events.append(("capture_sigint",))

    def wait(self, timeout=None):
        self.returncode = 0
        return 0


class HarnessQGA:
    """Fake QGA client that still drives the real runner decision logic."""

    def __init__(
        self,
        events: list,
        pcap: pathlib.Path,
        *,
        after_nonce: str = NONCE_B,
        image_id: str = guest.DEPLOYED_IMAGE_ID,
        boot_id: str = "11111111-2222-3333-4444-555555555555",
        boot_ids: list[str] | None = None,
        handshake: bytes = b"peerkey\t1700000000\n",
        tailscale_state: str = "NeedsLogin",
        login_url: str | None = LOGIN_URL,
        docker_pids: list[str] | None = None,
        overrides: list | None = None,
        write_after: bool = True,
        raise_after: bool = False,
    ) -> None:
        self.events = events
        self.pcap = pcap
        self.after_nonce = after_nonce
        self.image_id = image_id
        self.boot_ids = list(boot_ids or [boot_id])
        self.handshake = handshake
        self.tailscale_state = tailscale_state
        self.login_url = login_url
        self.docker_pids = list(docker_pids or ["111", "222"])
        self.overrides = list(overrides or [])
        self.write_after = write_after
        self.raise_after = raise_after
        self.files: dict[str, bytes] = {}
        self.shutdown_modes: list[str] = []
        self.commands: list[str] = []

    def _boot_id(self) -> str:
        index = min(len(self.shutdown_modes), len(self.boot_ids) - 1)
        return self.boot_ids[index]

    def execute(self, program, args=(), *, timeout=60.0, capture=True, env=None):
        del program, timeout, capture, env
        command = args[-1] if args else ""
        self.commands.append(command)
        self.events.append(("exec", command))
        if self.raise_after and self.after_nonce in command:
            self.events.append(("after_control_failed",))
            raise QGAError("injected after-control failure")
        if "VPRLEAKCTL1:" in command:
            match = re.search(r"([0-9a-f]{32})", command)
            if match and match.group(1) == self.after_nonce:
                if self.write_after:
                    payload = b"VPRLEAKCTL1:" + match.group(1).encode()
                    target = self.pcap[0] if isinstance(self.pcap, list) else self.pcap
                    target.write_bytes(target.read_bytes() + payload)
                self.events.append(("after_control", match.group(1)))
            return ExecResult(exitcode=0, stdout=b"", stderr=b"")
        for match, result in self.overrides:
            hit = match(command) if callable(match) else match in command
            if hit:
                self.events.append(("override", str(match)))
                if isinstance(result, ExecResult):
                    return result
                return result(command)
        if "SILENCE-OK" in command:
            return ExecResult(exitcode=0, stdout=b"SILENCE-OK\n", stderr=b"")
        if "stat -c '%a %U %G'" in command:
            return ExecResult(exitcode=0, stdout=b"600 root root\n", stderr=b"")
        if "docker image inspect --format '{{.Id}}'" in command:
            return ExecResult(
                exitcode=0, stdout=self.image_id.encode() + b"\n", stderr=b""
            )
        if "/sys/class/net" in command:
            return ExecResult(exitcode=0, stdout=b"eth0\n", stderr=b"")
        if "random/boot_id" in command:
            return ExecResult(
                exitcode=0, stdout=self._boot_id().encode() + b"\n", stderr=b""
            )
        if "latest-handshakes" in command:
            return ExecResult(exitcode=0, stdout=self.handshake, stderr=b"")
        if "tailscale status --json" in command:
            return ExecResult(
                exitcode=0,
                stdout=json.dumps({"BackendState": self.tailscale_state}).encode(),
                stderr=b"",
            )
        if "docker logs" in command:
            return ExecResult(
                exitcode=0,
                stdout=(self.login_url or "").encode(),
                stderr=b"",
            )
        if "cat /var/run/docker.pid" in command:
            value = self.docker_pids.pop(0) if len(self.docker_pids) > 1 else self.docker_pids[0]
            return ExecResult(exitcode=0, stdout=value.encode() + b"\n", stderr=b"")
        if "docker info" in command:
            return ExecResult(exitcode=0, stdout=b"", stderr=b"")
        return ExecResult(exitcode=0, stdout=b"", stderr=b"")

    def write_file(self, path, data, timeout=60.0):
        del timeout
        self.files[path] = bytes(data)

    def shutdown(self, mode="powerdown", *, timeout=5.0):
        del timeout
        self.shutdown_modes.append(mode)
        self.events.append(("guest_shutdown", mode))

    def close(self):
        self.events.append(("client_close",))


class RunPhaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.root = pathlib.Path(self._temporary.name)
        self.state = self.root / "vm-001"
        self.state.mkdir()
        self.used = self.root / "used-nonces.txt"
        self.used.write_text("", encoding="ascii")
        os.chmod(self.used, 0o600)
        self.profile = self.root / "profile.conf"
        self.profile.write_bytes(SECRET_TEXT)
        os.chmod(self.profile, 0o600)
        self.evidence = self.root / "evidence"
        self.lock = self.root / "run.lock"
        self.events: list = []
        self.sleeps: list[float] = []
        self.pcap: pathlib.Path | None = None

    def _arguments(self, phase: str, duration: float, **overrides) -> argparse.Namespace:
        descriptor = os.open(self.profile, os.O_RDONLY)
        self.addCleanup(os.close, descriptor)
        values = dict(
            phase=phase,
            duration=duration,
            profile_fd=descriptor,
            profile_file=None,
            used_nonces=str(self.used),
            name=guest.DEFAULT_NAME,
            index=1,
            state=str(self.state),
            state_root=str(self.root),
            image_id=guest.DEPLOYED_IMAGE_ID,
            base_image=str(self.root / "base.qcow2"),
            checksum_manifest=str(self.root / "manifest"),
            qemu_user="opsec",
            tap=guest.TAP,
            bridge=guest.BRIDGE,
            tcpdump="tcpdump",
            evidence_root=str(self.evidence),
            run_lock=str(self.lock),
            owner_file=str(self.root / "owner.json"),
        )
        values.update(overrides)
        return argparse.Namespace(**values)

    def _run(
        self,
        phase: str = "stop-router",
        *,
        duration: float = 0.0,
        scan_rc: int = 0,
        scan_verdict: str = "PASS",
        capture_stop_error: bool = False,
        poweroff_override=None,
        client_kwargs: dict | None = None,
        **argument_overrides,
    ):
        arguments = self._arguments(phase, duration, **argument_overrides)
        client_kwargs = dict(client_kwargs or {})

        def start_capture(interface, pcap, stats, *, tcpdump, popen=None, timeout=15.0):
            del tcpdump, popen, timeout
            self.events.append(("capture_start",))
            self.pcap = pathlib.Path(pcap)
            pcap_slot[0] = self.pcap
            self.pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
            pathlib.Path(stats).write_text(
                "tcpdump: listening on vprlab-tap0, link-type EN10MB "
                "(Ethernet), snapshot length 262144 bytes\n",
                encoding="utf-8",
            )
            return run_phase.Capture(
                process=FakeCaptureProcess(self.events),
                argv=guest.tcpdump_argv(interface, self.pcap),
                pcap=self.pcap,
                stats=pathlib.Path(stats),
            )

        def stop_capture(capture, timeout=20.0):
            del capture, timeout
            self.events.append(("capture_stop",))
            if capture_stop_error:
                raise OSError("injected capture stop failure")
            return 0

        def start_vm(state, *, name, tap, qemu_user, uid, gid, log_path):
            del state, name, tap, qemu_user, uid, gid
            self.events.append(("vm_start",))
            log_path = pathlib.Path(log_path)
            self.assertTrue(str(log_path).startswith(str(self.evidence)))
            log_path.write_text("qemu log\n", encoding="utf-8")
            return FakeProcess(self.events), ["qemu-system"], ["setpriv", "--", "qemu"]

        def fake_run(argv, **kwargs):
            del kwargs
            text = " ".join(str(part) for part in argv)
            if "pcapscan.py" not in text:
                raise AssertionError(f"unexpected subprocess.run: {text}")
            self.events.append(("scan",))
            return subprocess.CompletedProcess(
                argv,
                scan_rc,
                stdout=json.dumps(
                    {
                        "verdict": scan_verdict,
                        "control_before": NONCE_A,
                        "control_after": NONCE_B,
                    }
                ).encode(),
                stderr=b"",
            )

        pcap_slot: list[pathlib.Path | None] = [None]
        client = HarnessQGA(self.events, pcap_slot, **client_kwargs)

        def fake_poweroff(client_arg, process):
            del client_arg
            self.events.append(("guest_poweroff",))
            if process is not None:
                process.wait()
            return (0, False)

        with contextlib.ExitStack() as stack:
            enter = stack.enter_context
            enter(mock.patch.object(run_phase, "require_root"))
            enter(mock.patch.object(run_phase.hostcheck, "refuse_if_qemu_running"))
            enter(mock.patch.object(run_phase.guest, "verify_base_image", return_value="0" * 128))
            enter(mock.patch.object(run_phase, "verify_state"))
            enter(mock.patch.object(run_phase, "verify_host_lab"))
            enter(mock.patch.object(run_phase, "fresh_pair", return_value={"before": NONCE_A, "after": NONCE_B}))
            enter(mock.patch.object(run_phase.shutil, "which", return_value="/usr/bin/tcpdump"))
            def fake_sleep(seconds):
                self.sleeps.append(seconds)
                if seconds == run_phase.QUIET_SECONDS:
                    self.events.append(("quiet", seconds))

            enter(mock.patch.object(run_phase.time, "sleep", side_effect=fake_sleep))
            enter(mock.patch.object(run_phase, "AFTER_CAPTURE_TIMEOUT", 0.05))
            enter(mock.patch.object(run_phase, "ROUTER_ACTIVE_TIMEOUT", 0.05))
            enter(mock.patch.object(run_phase, "ROUTER_HANDSHAKE_TIMEOUT", 0.05))
            enter(mock.patch.object(run_phase, "DOCKER_RESTART_TIMEOUT", 0.05))
            enter(mock.patch.object(run_phase, "start_capture", side_effect=start_capture))
            enter(mock.patch.object(run_phase, "stop_capture", side_effect=stop_capture))
            enter(mock.patch.object(run_phase, "start_vm", side_effect=start_vm))
            enter(mock.patch.object(run_phase, "wait_for_qga_or_exit", return_value=client))
            if phase == "reboot-with-router-enabled":
                enter(mock.patch.object(run_phase, "wait_for_reboot", return_value=client))
            if poweroff_override is not None:
                enter(mock.patch.object(run_phase, "poweroff_vm", side_effect=poweroff_override))
            enter(mock.patch.object(run_phase.subprocess, "run", side_effect=fake_run))
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = run_phase.run_phase(arguments)
        evidence_dirs = [path for path in self.evidence.iterdir() if path.is_dir()]
        self.assertEqual(len(evidence_dirs), 1)
        record = json.loads((evidence_dirs[0] / guest.PHASE_RECORD_FILE).read_text())
        return code, record, client, self.events, stdout.getvalue(), stderr.getvalue(), evidence_dirs[0]

    # -- C1: failed setup/action must never certify ------------------------

    def test_action_nonzero_is_invalid_even_with_a_clean_scan(self) -> None:
        action = f"docker kill {guest.DEFAULT_NAME}"
        code, record, _client, events, stdout, _stderr, _dir = self._run(
            "kill-container",
            client_kwargs={
                "overrides": [(action, ExecResult(exitcode=7, stdout=b"", stderr=b""))]
            },
        )
        self.assertEqual(code, 2)
        self.assertEqual(record["result"], "INVALID")
        self.assertIn("action_failed", record["result_reason"])
        self.assertEqual(record["scan"]["verdict"], "PASS")
        self.assertEqual(record["action"]["exitcode"], 7)
        self.assertEqual(json.loads(stdout)["result"], "INVALID")
        self.assertEqual(json.loads(stdout)["scan_verdict"], "PASS")

    def test_action_killed_by_signal_is_invalid(self) -> None:
        action = f"docker kill {guest.DEFAULT_NAME}"
        code, record, _client, _events, _stdout, _stderr, _dir = self._run(
            "kill-container",
            client_kwargs={
                "overrides": [(action, ExecResult(exitcode=None, stdout=b"", stderr=b""))]
            },
        )
        self.assertEqual(code, 2)
        self.assertEqual(record["result"], "INVALID")
        self.assertIn("action_failed", record["result_reason"])
        self.assertIsNone(record["action"]["exitcode"])

    def test_failed_setup_aborts_the_injection(self) -> None:
        setup = f"systemctl start vprouter@{guest.DEFAULT_NAME}.service"
        code, record, _client, events, _stdout, _stderr, _dir = self._run(
            "stop-router",
            client_kwargs={
                "overrides": [(setup, ExecResult(exitcode=7, stdout=b"", stderr=b""))]
            },
        )
        self.assertEqual(code, 2)
        self.assertEqual(record["result"], "INVALID")
        self.assertIn("setup_failed", record["result_reason"])
        self.assertFalse(record["setup"]["active"])
        self.assertIsNone(record["action"]["exitcode"])
        action = f"systemctl stop vprouter@{guest.DEFAULT_NAME}.service"
        self.assertFalse(any(entry[0] == "exec" and entry[1] == action for entry in events))

    def test_inactive_setup_is_a_phase_error(self) -> None:
        active = f"systemctl is-active --quiet vprouter@{guest.DEFAULT_NAME}.service"
        code, record, _client, _events, _stdout, _stderr, _dir = self._run(
            "stop-router",
            client_kwargs={
                "overrides": [(active, ExecResult(exitcode=1, stdout=b"", stderr=b""))]
            },
        )
        self.assertEqual(code, 2)
        self.assertEqual(record["result"], "INVALID")
        self.assertIn("router_not_ready", record["result_reason"])
        self.assertFalse(record["setup"]["active"])

    def test_leak_stays_leak_when_the_phase_also_failed(self) -> None:
        action = f"docker kill {guest.DEFAULT_NAME}"
        code, record, _client, _events, stdout, _stderr, _dir = self._run(
            "kill-container",
            scan_rc=1,
            scan_verdict="LEAK",
            client_kwargs={
                "overrides": [(action, ExecResult(exitcode=7, stdout=b"", stderr=b""))]
            },
        )
        self.assertEqual(code, 1)
        self.assertEqual(record["result"], "LEAK")
        self.assertIn("action_failed", record["result_reason"])
        self.assertEqual(json.loads(stdout)["result"], "LEAK")

    def test_after_control_failure_after_send_is_invalid_not_pass(self) -> None:
        code, record, _client, _events, stdout, _stderr, _dir = self._run(
            "kill-container", client_kwargs={"raise_after": True}
        )
        self.assertEqual(code, 2)
        self.assertEqual(record["result"], "INVALID")
        self.assertIn("phase_exception:QGAError", record["result_reason"])
        self.assertEqual(record["scan"]["verdict"], "PASS")
        self.assertEqual(json.loads(stdout)["result"], "INVALID")
        self.assertEqual(json.loads(stdout)["scan_verdict"], "PASS")

    def test_start_router_requires_active_and_a_handshake(self) -> None:
        code, record, _client, _events, _stdout, _stderr, _dir = self._run(
            "start-router",
            client_kwargs={"handshake": b"peerkey\t0\n"},
        )
        self.assertEqual(code, 2)
        self.assertEqual(record["result"], "INVALID")
        self.assertIn("router_not_ready", record["result_reason"])
        self.assertEqual(record["scan"]["verdict"], "PASS")
        self.assertIsNone(record["tailscale"]["backend_state"])

    def test_start_router_pass_requires_handshake_and_records_backend_state(self) -> None:
        code, record, _client, _events, _stdout, _stderr, _dir = self._run("start-router")
        self.assertEqual(code, 0)
        self.assertEqual(record["result"], "PASS")
        self.assertEqual(record["expect_tunnel"], "up")
        self.assertEqual(record["tailscale"]["backend_state"], "NeedsLogin")
        self.assertEqual(record["action"]["exitcode"], 0)
        self.assertEqual(record["errors"], [])

    def test_idle_starts_the_router_and_expects_a_tunnel(self) -> None:
        code, record, _client, _events, _stdout, _stderr, _dir = self._run("idle")
        self.assertEqual(code, 0)
        self.assertEqual(record["result"], "PASS")
        self.assertEqual(record["expect_tunnel"], "up")
        self.assertEqual(record["setup"]["exitcode"], 0)
        self.assertEqual(record["action"]["command"], "true")

    # -- C2: capture lifetime and ordering --------------------------------

    def test_capture_stays_alive_until_qemu_exited_and_after_is_in_the_pcap(self) -> None:
        code, record, _client, events, _stdout, _stderr, _dir = self._run("start-router")
        self.assertEqual(code, 0)
        self.assertTrue(record["controls"]["after_in_pcap"])
        labels = [entry[0] for entry in events]
        after_index = labels.index("after_control")
        cleanup_index = [
            index
            for index, entry in enumerate(events)
            if entry[0] == "exec" and str(entry[1]).startswith("rc=0; systemctl stop")
        ][-1]
        shutdown_index = labels.index("guest_shutdown")
        exit_index = labels.index("qemu_exit")
        stop_index = labels.index("capture_stop")
        self.assertLess(after_index, cleanup_index)
        self.assertLess(cleanup_index, shutdown_index)
        self.assertLess(shutdown_index, exit_index)
        self.assertLess(exit_index, stop_index)

    def test_missing_after_in_pcap_is_invalid_but_capture_is_stopped(self) -> None:
        code, record, _client, events, _stdout, _stderr, _dir = self._run(
            "start-router", client_kwargs={"write_after": False}
        )
        self.assertEqual(code, 2)
        self.assertEqual(record["result"], "INVALID")
        self.assertIn("after_control_not_captured", record["result_reason"])
        self.assertIn("capture_stop", [entry[0] for entry in events])
        self.assertIn("scan", [entry[0] for entry in events])

    def test_forced_poweroff_is_invalid(self) -> None:
        def force_poweroff(client, process):
            del client
            self.events.append(("forced_poweroff",))
            if process is not None:
                process.wait()
            return (-9, True)

        code, record, _client, _events, _stdout, _stderr, _dir = self._run(
            "start-router", poweroff_override=force_poweroff
        )
        self.assertEqual(code, 2)
        self.assertEqual(record["result"], "INVALID")
        self.assertIn("forced_poweroff", record["result_reason"])

    def test_teardown_failure_cannot_certify(self) -> None:
        cleanup_prefix = "rc=0; systemctl stop"

        def second_cleanup_fails(command):
            if command.startswith(cleanup_prefix):
                if not hasattr(second_cleanup_fails, "count"):
                    second_cleanup_fails.count = 0
                second_cleanup_fails.count += 1
                if second_cleanup_fails.count >= 2:
                    return ExecResult(exitcode=7, stdout=b"", stderr=b"")
            return ExecResult(exitcode=0, stdout=b"", stderr=b"")

        code, record, _client, _events, _stdout, _stderr, _dir = self._run(
            "start-router",
            client_kwargs={
                "overrides": [(cleanup_prefix, second_cleanup_fails)]
            },
        )
        self.assertEqual(code, 2)
        self.assertEqual(record["result"], "INVALID")
        self.assertIn("cleanup_failed", record["result_reason"])

    def test_initial_cleanup_failure_is_invalid(self) -> None:
        cleanup_prefix = "rc=0; systemctl stop"

        def first_cleanup_fails(command):
            if command.startswith(cleanup_prefix):
                return ExecResult(exitcode=7, stdout=b"", stderr=b"")
            return ExecResult(exitcode=0, stdout=b"", stderr=b"")

        code, record, _client, _events, _stdout, _stderr, _dir = self._run(
            "start-router",
            client_kwargs={"overrides": [(cleanup_prefix, first_cleanup_fails)]},
        )
        self.assertEqual(code, 2)
        self.assertEqual(record["result"], "INVALID")
        self.assertIn("cleanup_failed", record["result_reason"])

    def test_capture_stop_failure_still_writes_the_phase_record(self) -> None:
        code, record, _client, _events, _stdout, _stderr, _dir = self._run(
            "start-router", capture_stop_error=True
        )
        self.assertEqual(code, 2)
        self.assertEqual(record["result"], "INVALID")
        self.assertIn("capture_stop_failed", record["result_reason"])

    def test_pre_before_failure_still_tears_down_in_order(self) -> None:
        silence = "SILENCE-OK"
        code, record, _client, events, _stdout, _stderr, _dir = self._run(
            "start-router",
            client_kwargs={
                "overrides": [(silence, ExecResult(exitcode=1, stdout=b"SILENCE-FAILED\n", stderr=b""))]
            },
        )
        self.assertEqual(code, 2)
        self.assertEqual(record["result"], "INVALID")
        labels = [entry[0] for entry in events]
        self.assertIn("guest_shutdown", labels)
        self.assertIn("qemu_exit", labels)
        self.assertIn("capture_stop", labels)
        self.assertLess(labels.index("qemu_exit"), labels.index("capture_stop"))
        self.assertIn("phase_exception:Refusal", record["result_reason"])

    # -- fault postconditions --------------------------------------------

    def test_fault_postconditions_are_mandatory(self) -> None:
        cases = {
            "stop-router": lambda name: f"systemctl is-active --quiet vprouter@{name}.service && exit 1; exit 0",
            "kill-wireguard": lambda name: "ip link show wg0",
            "kill-container": lambda name: "State.Running",
        }
        for phase, marker in cases.items():
            with self.subTest(phase=phase):
                # Reset the per-run evidence directory.
                for path in list(self.evidence.glob("*")):
                    if path.is_dir():
                        import shutil

                        shutil.rmtree(path)
                code, record, _client, _events, _stdout, _stderr, _dir = self._run(
                    phase,
                    client_kwargs={
                        "overrides": [
                            (
                                lambda command, marker=marker(guest.DEFAULT_NAME): marker in command,
                                ExecResult(exitcode=1, stdout=b"", stderr=b""),
                            )
                        ]
                    },
                )
                self.assertEqual(code, 2)
                self.assertEqual(record["result"], "INVALID")
                self.assertIn("postcondition_failed", record["result_reason"])

    def test_restart_docker_requires_a_new_daemon_pid(self) -> None:
        # The same PID before and after means Docker did not restart.
        code, record, _client, _events, _stdout, _stderr, _dir = self._run(
            "restart-docker", client_kwargs={"docker_pids": ["111", "111"]}
        )
        self.assertEqual(code, 2)
        self.assertEqual(record["result"], "INVALID")
        self.assertIn("postcondition_failed", record["result_reason"])

    def test_restart_docker_pass_with_new_pid(self) -> None:
        code, record, _client, _events, _stdout, _stderr, _dir = self._run("restart-docker")
        self.assertEqual(code, 0)
        self.assertEqual(record["result"], "PASS")
        self.assertEqual(record["action"]["exitcode"], 0)

    # -- login phase ------------------------------------------------------

    def test_login_phase_writes_only_the_url_to_a_root_only_file(self) -> None:
        code, record, _client, _events, _stdout, stderr, evidence = self._run(
            "login", duration=0.0
        )
        self.assertEqual(code, 0)
        self.assertEqual(record["result"], "PASS")
        url_file = evidence / "login-url.txt"
        self.assertEqual(url_file.read_text(encoding="utf-8"), LOGIN_URL + "\n")
        self.assertEqual(stat.S_IMODE(url_file.stat().st_mode), 0o600)
        self.assertIn(LOGIN_URL, stderr)
        self.assertEqual(record["tailscale"]["backend_state"], "NeedsLogin")

    # -- policy/evidence binding -----------------------------------------

    def test_evidence_lives_outside_the_state_directory_and_policy_is_exact(self) -> None:
        code, record, _client, _events, _stdout, _stderr, evidence = self._run("start-router")
        self.assertEqual(code, 0)
        self.assertTrue(str(evidence).startswith(str(self.evidence)))
        self.assertFalse(str(evidence).startswith(str(self.state)))
        policy = json.loads((evidence / "policy.json").read_text())
        self.assertEqual(len(policy["allowed"]), 1)
        self.assertEqual(
            (policy["allowed"][0]["dst_ipv4"], policy["allowed"][0]["dst_port"]),
            ("185.65.134.10", 51820),
        )
        self.assertEqual(policy["gateway_mac"], GATEWAY_MAC)
        self.assertEqual(record["policy"]["allowed"], policy["allowed"])

    def test_two_second_quiet_interval_precedes_capture_stop(self) -> None:
        code, record, _client, events, _stdout, _stderr, _dir = self._run("start-router")
        self.assertEqual(code, 0)
        self.assertIn(run_phase.QUIET_SECONDS, self.sleeps)
        labels = [entry[0] for entry in events]
        quiet_index = labels.index("quiet")
        self.assertLess(labels.index("qemu_exit"), quiet_index)
        self.assertLess(quiet_index, labels.index("capture_stop"))

    def test_monitor_interface_argv_and_stats_banner_are_bound(self) -> None:
        code, record, _client, _events, _stdout, _stderr, evidence = self._run("start-router")
        self.assertEqual(code, 0)
        capture_argv = json.loads((evidence / guest.CAPTURE_ARGV_FILE).read_text())
        self.assertEqual(capture_argv[capture_argv.index("-w") + 1], str(evidence / guest.CAPTURE_FILE))
        self.assertEqual(capture_argv[capture_argv.index("-i") + 1], guest.TAP)
        self.assertIn("-U", capture_argv)
        self.assertIn("--immediate-mode", capture_argv)
        stats = (evidence / guest.CAPTURE_STATS_FILE).read_text()
        first_line = next(line for line in stats.splitlines() if line.strip())
        self.assertTrue(first_line.startswith("tcpdump: listening on vprlab-tap0, link-type EN10MB"))
        scan_argv = record["pcapscan_argv"]
        self.assertEqual(scan_argv[scan_argv.index("--expect-tunnel") + 1], "up")
        self.assertEqual(
            scan_argv[scan_argv.index("--capture-argv-file") + 1],
            str(evidence / guest.CAPTURE_ARGV_FILE),
        )
        policy = json.loads((evidence / "policy.json").read_text())
        self.assertIn("gateway_mac", policy)

    def test_reboot_phase_requires_a_new_boot_and_a_boot_control_token(self) -> None:
        code, record, client, _events, _stdout, _stderr, _dir = self._run(
            "reboot-with-router-enabled",
            client_kwargs={"boot_ids": ["11111111-2222-3333-4444-555555555555", "66666666-7777-8888-9999-000000000000"]},
        )
        self.assertEqual(code, 0)
        self.assertEqual(record["result"], "PASS")
        self.assertTrue(record["boot"]["rebooted"])
        self.assertIn("reboot", client.shutdown_modes)
        control = record["boot"]["boot_control"]
        self.assertEqual(len(control["boot_token"]), 32)
        self.assertTrue(control["spec_path"].startswith("/var/lib/vprlab/"))
        self.assertEqual(record["controls"]["before_transport"], "boot-control-unit")

    def test_reboot_phase_without_router_readiness_is_invalid(self) -> None:
        active = f"systemctl is-active --quiet vprouter@{guest.DEFAULT_NAME}.service"
        code, record, _client, _events, _stdout, _stderr, _dir = self._run(
            "reboot-with-router-enabled",
            client_kwargs={
                "boot_ids": ["11111111-2222-3333-4444-555555555555", "66666666-7777-8888-9999-000000000000"],
                "overrides": [(active, ExecResult(exitcode=1, stdout=b"", stderr=b""))],
            },
        )
        self.assertEqual(code, 2)
        self.assertEqual(record["result"], "INVALID")
        self.assertIn("router_not_ready", record["result_reason"])

    def test_qemu_log_is_written_outside_the_state_directory(self) -> None:
        code, record, _client, _events, _stdout, _stderr, evidence = self._run("start-router")
        self.assertEqual(code, 0)
        self.assertEqual(record["qemu_log"], str(evidence / guest.QEMU_LOG_FILE))
        self.assertTrue((evidence / guest.QEMU_LOG_FILE).is_file())
        self.assertFalse((self.state / guest.QEMU_LOG_FILE).exists())

    def test_evidence_inside_the_state_directory_is_refused(self) -> None:
        arguments = self._arguments(
            "start-router", 0.0, evidence_root=str(self.state / "evidence")
        )
        with mock.patch.object(run_phase, "require_root"), mock.patch.object(
            run_phase.hostcheck, "refuse_if_qemu_running"
        ), mock.patch.object(
            run_phase.guest, "verify_base_image", return_value="0" * 128
        ), mock.patch.object(run_phase, "verify_state"), mock.patch.object(
            run_phase, "verify_host_lab"
        ), mock.patch.object(
            run_phase, "fresh_pair", return_value={"before": NONCE_A, "after": NONCE_B}
        ), mock.patch.object(run_phase.shutil, "which", return_value="/usr/bin/tcpdump"):
            with self.assertRaises(hostcheck.Refusal):
                run_phase.run_phase(arguments)

    def test_scan_report_mismatch_cannot_certify(self) -> None:
        code, record, _client, _events, _stdout, _stderr, _dir = self._run(
            "start-router", scan_rc=0, scan_verdict="INVALID"
        )
        self.assertEqual(code, 2)
        self.assertEqual(record["result"], "INVALID")
        self.assertIn("scan_report_mismatch", record["result_reason"])


class StateLogSafetyTests(unittest.TestCase):
    def test_state_qemu_log_symlink_is_never_followed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            state = root / "vm-001"
            state.mkdir()
            victim = root / "victim.log"
            victim.write_bytes(b"initial\n")
            (state / guest.QEMU_LOG_FILE).symlink_to(victim)
            log_path = root / "evidence" / guest.QEMU_LOG_FILE
            log_path.parent.mkdir()
            with mock.patch.object(run_phase.subprocess, "Popen") as popen:
                popen.return_value = object()
                run_phase.start_vm(
                    state,
                    name=guest.DEFAULT_NAME,
                    tap=guest.TAP,
                    qemu_user="opsec",
                    uid=os.geteuid(),
                    gid=os.getegid(),
                    log_path=log_path,
                )
            self.assertEqual(victim.read_bytes(), b"initial\n")
            self.assertTrue(log_path.is_file())
            self.assertEqual(log_path.read_bytes(), b"")


class WaitForRebootTests(unittest.TestCase):
    class StubClient:
        def __init__(self, boot_ids):
            self.boot_ids = list(boot_ids)
            self.closed = False

        def execute(self, _program, _args=(), *, timeout=60.0):
            del timeout
            value = self.boot_ids.pop(0) if len(self.boot_ids) > 1 else self.boot_ids[0]
            return ExecResult(exitcode=0, stdout=value.encode() + b"\n", stderr=b"")

        def close(self):
            self.closed = True

    def test_unchanged_boot_id_times_out(self) -> None:
        client = self.StubClient(["11111111-2222-3333-4444-555555555555", "11111111-2222-3333-4444-555555555555"])
        with mock.patch.object(run_phase, "wait_for_qga", return_value=client), mock.patch.object(
            run_phase.time, "sleep"
        ):
            with self.assertRaises(hostcheck.Refusal):
                run_phase.wait_for_reboot(
                    pathlib.Path("/tmp/qga.sock"), "11111111-2222-3333-4444-555555555555", timeout=0.05
                )

    def test_changed_boot_id_is_accepted(self) -> None:
        client = self.StubClient(["66666666-7777-8888-9999-000000000000"])
        with mock.patch.object(run_phase, "wait_for_qga", return_value=client):
            returned = run_phase.wait_for_reboot(
                pathlib.Path("/tmp/qga.sock"), "11111111-2222-3333-4444-555555555555", timeout=1.0
            )
        self.assertIs(returned, client)


class StateVerificationTests(unittest.TestCase):
    def test_qemu_img_info_runs_as_the_qemu_user(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            state = root / "vm-001"
            state.mkdir(mode=0o700)
            os.chmod(state, 0o700)
            overlay = state / guest.OVERLAY_FILE
            overlay.write_bytes(b"qcow2")
            os.chmod(overlay, 0o600)
            base = root / "base.qcow2"
            base.write_bytes(b"base")
            document = [
                {
                    "filename": str(overlay),
                    "format": "qcow2",
                    "full-backing-filename": str(base),
                },
                {"filename": str(base), "format": "qcow2"},
            ]
            captured = {}

            def fake_run(argv, **kwargs):
                captured["argv"] = argv
                captured["env"] = kwargs.get("env")
                return subprocess.CompletedProcess(
                    argv, 0, stdout=json.dumps(document), stderr=""
                )

            uid = os.geteuid()
            with mock.patch.object(run_phase.subprocess, "run", side_effect=fake_run):
                run_phase.verify_state(
                    state, qemu_uid=uid, qemu_gid=os.getegid(), base=base
                )
            argv = captured["argv"]
            self.assertEqual(argv[0], "/usr/bin/setpriv")
            self.assertIn(f"--reuid={uid}", argv)
            self.assertIn(f"--regid={os.getegid()}", argv)
            self.assertIn("--no-new-privs", argv)
            self.assertIn("-U", argv)
            self.assertNotEqual(argv[0], str(guest.QEMU_IMG))


class MainExitTests(unittest.TestCase):
    def test_unexpected_exception_returns_two_never_one(self) -> None:
        argv = [
            "--phase",
            "idle",
            "--duration",
            "0",
            "--profile-fd",
            "0",
            "--used-nonces",
            "/tmp/unused",
        ]

        class Boom(AttributeError):
            pass

        with mock.patch.object(run_phase, "install_signal_handlers"), mock.patch.object(
            run_phase, "run_phase", side_effect=Boom("unexpected")
        ), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(run_phase.main(argv), 2)

    def test_signal_handler_raises_into_the_cleanup_path(self) -> None:
        run_phase.install_signal_handlers()
        try:
            run_phase._signal_seen = False
            with self.assertRaises(run_phase.PhaseInterrupted):
                run_phase._handle_signal(signal.SIGTERM, None)
            # A second signal during cleanup is ignored, not re-raised.
            run_phase._handle_signal(signal.SIGTERM, None)
        finally:
            run_phase._signal_seen = False
            for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
                signal.signal(signum, signal.SIG_DFL)


class CaptureFileTests(unittest.TestCase):
    def test_after_nonce_is_found_in_a_growing_pcap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            pcap = pathlib.Path(temporary) / "capture.pcap"
            pcap.write_bytes(b"header" + b"VPRLEAKCTL1:" + NONCE_B.encode())
            with mock.patch.object(run_phase, "AFTER_CAPTURE_TIMEOUT", 0.05):
                self.assertTrue(run_phase.wait_for_control_in_pcap(pcap, NONCE_B))
                with mock.patch.object(run_phase.time, "sleep"):
                    self.assertFalse(
                        run_phase.wait_for_control_in_pcap(pcap, NONCE_A, timeout=0.01)
                    )


class ProvisionDefaultsTests(unittest.TestCase):
    def test_cli_defaults_are_netns_safe(self) -> None:
        captured: dict = {}

        def fake_provision(arguments):
            captured.update(vars(arguments))
            return 0

        with mock.patch.object(provision, "provision", side_effect=fake_provision):
            code = provision.main(["--image-tar", "/tmp/image.tar"])
        self.assertEqual(code, 0)
        self.assertEqual(captured["ipv6_mode"], "netns-safe")


if __name__ == "__main__":
    unittest.main()
