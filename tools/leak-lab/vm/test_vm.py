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
import struct
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
if str(HERE.parent) not in sys.path:
    sys.path.insert(0, str(HERE.parent))

import guest
import hostcheck
import hostcopy
import hostsetup
import login_url
import policy
import provision
import rootfs
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
        sync_split_at: int | None = None,
    ):
        super().__init__(daemon=True)
        self.path = path
        self.exec_stdout = exec_stdout
        self.exec_stderr = exec_stderr
        self.exec_exit = exec_exit
        self.hang_status = hang_status
        self.error_on = error_on
        self.error_desc = error_desc
        self.sync_split_at = sync_split_at
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
            if self.sync_split_at is None:
                self._send(connection, {"return": arguments.get("id")}, delimited=True)
            else:
                wire = (
                    b"\xff"
                    + json.dumps(
                        {"return": arguments.get("id")}, separators=(",", ":")
                    ).encode("ascii")
                    + b"\n"
                )
                cut = max(0, min(int(self.sync_split_at), len(wire)))
                connection.sendall(wire[:cut])
                time.sleep(0.02)
                connection.sendall(wire[cut:])
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

    def test_sync_delimiter_survives_every_split_position(self) -> None:
        # Build the exact frame the fake agent will send, then split it at
        # every byte boundary.  The marker must be rescanned, not skipped.
        frame = b"\xff" + json.dumps(
            {"return": 2}, separators=(",", ":")
        ).encode("ascii") + b"\n"
        for cut in range(len(frame) + 1):
            with self.subTest(cut=cut):
                if self.socket_path.exists():
                    self.socket_path.unlink()
                server = FakeQGAServer(self.socket_path, sync_split_at=cut)
                server.start()
                client = QGAClient(self.socket_path)
                try:
                    client.connect(timeout=5.0)
                    client.ping(timeout=5.0)
                finally:
                    client.close()
                    server.close()
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

    def test_guest_error_class_and_description_are_never_rendered(self) -> None:
        key = "A" * 43 + "="
        for error_class in ("GenericError", "PRIVATEKEY" + "A" * 32, key):
            with self.subTest(error_class=error_class[:16]):
                client = QGAClient("/not-connected")
                client._buffer = (
                    json.dumps(
                        {
                            "error": {
                                "class": error_class,
                                "desc": "PrivateKey = " + key,
                            }
                        }
                    ).encode("ascii")
                    + b"\n"
                )
                with self.assertRaises(QGAError) as raised:
                    client._read_response(0)
                message = str(raised.exception)
                self.assertNotIn(key, message)
                self.assertNotIn("PrivateKey", message)
                self.assertNotIn("desc", message)
                if error_class == "GenericError":
                    self.assertIn("GenericError", message)
                else:
                    self.assertIn("guest_error", message)

    def test_unbounded_gqa_reply_stream_is_refused_before_memory_grows(self) -> None:
        import qga

        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(self.socket_path))
        listener.listen(1)
        listener.settimeout(5)
        sent = {"bytes": 0}
        failure: list[BaseException] = []

        def serve():
            try:
                connection, _ = listener.accept()
                connection.settimeout(5)
                chunk = b"x" * 65536
                for _ in range(1600):  # 100 MiB with no newline
                    try:
                        connection.sendall(chunk)
                    except OSError:
                        break
                    sent["bytes"] += len(chunk)
                connection.close()
            except BaseException as exc:  # pragma: no cover - reported below
                failure.append(exc)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        client = QGAClient(self.socket_path, timeout=10)
        try:
            with self.assertRaises(qga.QGAProtocolError) as raised:
                client.connect(timeout=10)
        finally:
            client.close()
            listener.close()
            thread.join(timeout=5)
        self.assertIn("reply_too_large", str(raised.exception))
        self.assertFalse(failure)
        self.assertLessEqual(sent["bytes"], qga.MAX_REPLY_BYTES + 2 * 65536)

    def test_guest_exec_output_larger_than_4_mib_is_refused(self) -> None:
        server = self.start_server(
            exec_stdout=b"x" * (4 * 1024 * 1024 + 1)
        )
        client = QGAClient(self.socket_path)
        try:
            client.connect()
            with self.assertRaises(QGAError) as raised:
                client.execute("/bin/true", timeout=5)
            self.assertIsNone(client._socket)
        finally:
            client.close()
            server.close()
        self.assertIn("reply_too_large", str(raised.exception))
        self.assertIn("exec_output_too_large", str(raised.exception))

    def test_guest_error_through_command_is_mapped_only_to_a_class(self) -> None:
        key = "B" * 43 + "="
        client = QGAClient("/not-connected")

        class Socket:
            def sendall(self, _payload):
                return None

        client._socket = Socket()
        client._buffer = (
            json.dumps(
                {
                    "id": None,
                    "error": {"class": key, "desc": "PrivateKey = " + key},
                }
            ).encode("ascii")
            + b"\n"
        )
        with self.assertRaises(QGAError) as raised:
            client.command("guest-ping")
        message = str(raised.exception)
        self.assertIn("guest-ping", message)
        self.assertIn("guest_error", message)
        self.assertNotIn(key, message)
        self.assertNotIn("PrivateKey", message)


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
        self.assertNotIn("file:/state/serial.log", argv)
        self.assertEqual(argv[argv.index("-serial") + 1], "none")
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

    def test_dead_qemu_env_helper_is_gone(self) -> None:
        self.assertFalse(hasattr(guest, "qemu_env"))

    def test_unprivileged_launch_drops_every_privilege(self) -> None:
        argv = guest.build_qemu_argv("test", pathlib.Path("/state"))
        launched = guest.build_launch_argv(argv, "vprlab-qemu", uid=1000, gid=1000)
        self.assertEqual(
            launched[:9],
            [
                "/usr/bin/setpriv",
                "--reuid=1000",
                "--regid=1000",
                "--init-groups",
                "--no-new-privs",
                "--inh-caps=-all",
                "--bounding-set=-all",
                "--",
                "/usr/bin/env",
            ],
        )
        self.assertIn("--no-new-privs", launched)
        self.assertIn("--inh-caps=-all", launched)
        self.assertIn("--bounding-set=-all", launched)
        # The staged-loader variables are applied only after the drop.
        self.assertEqual(launched[9], "-i")
        self.assertEqual(launched[10], "LD_LIBRARY_PATH=" + str(guest.LAB_LIBRARY_DIR))
        self.assertEqual(launched[11], "QEMU_MODULE_DIR=" + str(guest.QEMU_MODULE_DIR))
        self.assertEqual(launched[12:], argv)

    def test_uid_zero_is_refused(self) -> None:
        with self.assertRaises(guest.GeneratorError):
            guest.build_launch_argv(["qemu"], "root", uid=0, gid=0)
        with self.assertRaises(guest.GeneratorError):
            guest.build_setpriv_argv(["tool"], 0, 0)
        with self.assertRaises(guest.GeneratorError):
            guest.resolve_unprivileged_user("root")

    def test_qemu_account_must_be_nonroot_and_kvm_only(self) -> None:
        import types

        def user(uid=123, gid=100):
            return types.SimpleNamespace(
                pw_uid=uid,
                pw_gid=gid,
                pw_name="vprlab-qemu",
                pw_shell="/usr/sbin/nologin",
            )

        def group(name, gid, members):
            return types.SimpleNamespace(gr_name=name, gr_gid=gid, gr_mem=list(members))

        valid_groups = [
            group("vprlab-qemu", 100, []),
            group("kvm", 108, ["vprlab-qemu"]),
        ]
        self.assertEqual(
            guest.verify_qemu_account(
                "vprlab-qemu", pwd_record=user(), group_records=valid_groups
            ),
            (123, 100, "vprlab-qemu"),
        )
        with self.assertRaises(guest.GeneratorError):
            guest.verify_qemu_account(
                "vprlab-qemu", pwd_record=user(uid=0), group_records=valid_groups
            )
        for forbidden in ("sudo", "wheel", "adm", "docker", "lxd", "libvirt", "disk"):
            with self.subTest(group=forbidden):
                groups = valid_groups + [group(forbidden, 50, ["vprlab-qemu"])]
                with self.assertRaises(guest.GeneratorError):
                    guest.verify_qemu_account(
                        "vprlab-qemu", pwd_record=user(), group_records=groups
                    )
        with self.assertRaises(guest.GeneratorError):
            guest.verify_qemu_account(
                "vprlab-qemu",
                pwd_record=user(),
                group_records=valid_groups + [group("backup", 34, ["vprlab-qemu"])],
            )

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
        self.assertIn("ip -j link show wg0", wireguard)
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
                        "comment": "vprlab-owned:" + "e" * 32,
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
        self.assertEqual(captured["env"], guest.clean_environment())
        self.assertNotIn("LD_LIBRARY_PATH", captured["env"])
        self.assertIn(
            "LD_LIBRARY_PATH=" + str(guest.LAB_LIBRARY_DIR),
            argv,
        )


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
                provision, "check_provision_admission"
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

    def _pipeline_arguments(self, root: pathlib.Path):
        state_root = root / "state-root"
        release = root / "release"
        release.mkdir(exist_ok=True)
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
        return argparse.Namespace(
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

    def _pipeline_patches(self, arguments, fake_run, fake_qemu):
        uid = os.geteuid()
        gid = os.getegid()
        return [
            mock.patch.object(provision, "require_root"),
            mock.patch.object(
                provision.guest, "verify_base_image", return_value="0" * 128
            ),
            mock.patch.object(provision.hostcheck, "refuse_if_qemu_running"),
            mock.patch.object(provision, "_require_tool"),
            mock.patch.object(provision, "_qemu_identity", return_value=(uid, gid)),
            mock.patch.object(provision, "check_provision_admission"),
            mock.patch.object(provision.os, "chown"),
            mock.patch.object(provision.subprocess, "run", side_effect=fake_run),
            mock.patch.object(provision.subprocess, "Popen", fake_qemu),
            mock.patch.object(provision.time, "sleep"),
        ]

    def test_stage_payload_copies_the_image_and_never_mutates_the_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            release = root / "release"
            release.mkdir()
            for relative in guest.TRUSTED_RELEASE_FILES:
                path = release / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("# release\n", encoding="utf-8")
            unit = release / guest.UNIT_SOURCE
            unit.parent.mkdir(parents=True, exist_ok=True)
            unit.write_text("[Unit]\n", encoding="utf-8")
            image = root / "operator-image.tar"
            image.write_bytes(b"private-image-bytes")
            os.chmod(image, 0o600)
            state = root / "vm-001"
            state.mkdir(mode=0o700)
            source_inode = image.stat().st_ino
            staging = provision._stage_payload(state, release, image)
            source = image.stat()
            self.assertEqual(stat.S_IMODE(source.st_mode), 0o600)
            self.assertEqual(image.read_bytes(), b"private-image-bytes")
            self.assertEqual(source.st_ino, source_inode)
            staged = staging / "image" / "vprouter-image.tar"
            self.assertNotEqual(staged.stat().st_ino, source_inode)
            self.assertEqual(staged.read_bytes(), b"private-image-bytes")
            self.assertEqual(stat.S_IMODE(staged.stat().st_mode), 0o644)

    def test_self_signal_during_provision_reaps_the_qemu_child(self) -> None:
        for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            with self.subTest(signal=signum.name):
                with tempfile.TemporaryDirectory() as temporary:
                    root = pathlib.Path(temporary)
                    arguments = self._pipeline_arguments(root)
                    state = pathlib.Path(arguments.state_root) / "vm-001"
                    image_id = guest.DEPLOYED_IMAGE_ID

                    class FakeQemu:
                        returncode = None
                        pid = 9001

                        def __init__(self, argv, **kwargs):
                            del argv, kwargs

                        def poll(self):
                            return self.returncode

                        def wait(self, timeout=None):
                            del timeout
                            self.returncode = -15
                            return -15

                    terminated = []

                    def fake_run(argv, **kwargs):
                        del kwargs
                        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

                    def fake_wait(process, serial, timeout):
                        del process, serial, timeout
                        os.kill(os.getpid(), signum)
                        # The real wait loop reaches its checkpoint next.
                        provision.check_interrupt()
                        raise AssertionError("deferred signal was not raised")

                    patches = self._pipeline_patches(
                        arguments, fake_run, FakeQemu
                    ) + [
                        mock.patch.object(
                            provision, "_wait_for_marker", side_effect=fake_wait
                        ),
                        mock.patch.object(
                            provision,
                            "_terminate",
                            side_effect=lambda process: terminated.append(process),
                        ),
                    ]
                    try:
                        with contextlib.ExitStack() as stack:
                            for patch in patches:
                                stack.enter_context(patch)
                            provision.install_signal_handlers()
                            with self.assertRaises(hostcheck.Refusal) as raised:
                                provision.provision(arguments)
                        self.assertIn("ProvisionInterrupted", str(raised.exception))
                        self.assertEqual(len(terminated), 1)
                        record = json.loads((state / "provision.json").read_text())
                        self.assertEqual(record["test_status"], "PROVISION_FAILED")
                    finally:
                        for handled in (
                            signal.SIGTERM,
                            signal.SIGHUP,
                            signal.SIGINT,
                        ):
                            signal.signal(handled, signal.SIG_DFL)


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
        self.assertEqual(guest.state_path(1), pathlib.Path("/var/lib/vprlab/vm-001"))
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
        self.exited = False

    def poll(self):
        return 0 if self.exited else None

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
        handshake: bytes | None = None,
        tailscale_state: str = "Running",
        exit_node: bool = True,
        login_url: str | None = LOGIN_URL,
        docker_pids: list[str] | None = None,
        overrides: list | None = None,
        write_after: bool = True,
        raise_after: bool = False,
        guest_clock: int | None = None,
        container_running: bool = True,
        wg0_ifindex: int = 10,
        wg0_after_action: str = "absent",
    ) -> None:
        self.events = events
        self.pcap = pcap
        self.after_nonce = after_nonce
        self.image_id = image_id
        self.boot_ids = list(boot_ids or [boot_id])
        self.guest_clock = int(time.time()) if guest_clock is None else int(guest_clock)
        self.handshake = (
            f"peerkey\t{self.guest_clock}\n".encode("ascii")
            if handshake is None
            else handshake
        )
        self.tailscale_state = tailscale_state
        self.exit_node = exit_node
        self.container_running = container_running
        self.wg0_ifindex = wg0_ifindex
        self.wg0_after_action = wg0_after_action
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
        if command.strip() == "date +%s":
            return ExecResult(
                exitcode=0, stdout=f"{self.guest_clock}\n".encode("ascii"), stderr=b""
            )
        if "orchestrate.py status" in command:
            return ExecResult(
                exitcode=0,
                stdout=json.dumps(
                    {"name": guest.DEFAULT_NAME, "state": "READY", "heartbeat": 1}
                ).encode(),
                stderr=b"",
            )
        if "latest-handshakes" in command:
            return ExecResult(exitcode=0, stdout=self.handshake, stderr=b"")
        if "ip -j link show wg0" in command and "echo absent" in command:
            action_ran = any(
                entry[0] == "exec" and "ip link del wg0" in str(entry[1])
                for entry in self.events
            )
            if not self.container_running:
                return ExecResult(exitcode=0, stdout=b"stopped\n", stderr=b"")
            if action_ran:
                if self.wg0_after_action == "absent":
                    return ExecResult(exitcode=0, stdout=b"absent\n", stderr=b"")
                if self.wg0_after_action == "unchanged":
                    return ExecResult(
                        exitcode=0,
                        stdout=json.dumps(
                            [{"ifname": "wg0", "ifindex": self.wg0_ifindex}]
                        ).encode(),
                        stderr=b"",
                    )
                return ExecResult(
                    exitcode=0,
                    stdout=json.dumps(
                        [{"ifname": "wg0", "ifindex": self.wg0_ifindex + 1}]
                    ).encode(),
                    stderr=b"",
                )
            return ExecResult(
                exitcode=0,
                stdout=json.dumps(
                    [{"ifname": "wg0", "ifindex": self.wg0_ifindex}]
                ).encode(),
                stderr=b"",
            )
        if "tailscale status --json" in command:
            node = {
                "Online": True,
                "ExitNodeOption": self.exit_node,
                "AdvertisedRoutes": ["0.0.0.0/0"] if self.exit_node else [],
            }
            return ExecResult(
                exitcode=0,
                stdout=json.dumps(
                    {"BackendState": self.tailscale_state, "Self": node}
                ).encode(),
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
        self.scanner_root = self.root / "leaklab"
        self.scanner_root.mkdir()
        import hashlib

        scanner_bytes = (pathlib.Path(__file__).resolve().parent / ".." / "pcapscan.py").read_bytes()
        (self.scanner_root / "pcapscan.py").write_bytes(scanner_bytes)
        (self.scanner_root / "SHA256SUMS").write_text(
            f"{hashlib.sha256(scanner_bytes).hexdigest()}  pcapscan.py\n",
            encoding="utf-8",
        )
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
            capture_size_cap=2 * 1024 * 1024 * 1024,
            run_lock=str(self.lock),
            owner_file=str(self.root / "owner.json"),
            scanner_root=str(self.scanner_root),
            allow_repo_scanner=False,
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
        scan_report_override=None,
        scan_kwargs: dict | None = None,
        admission_raises: bool = False,
        watch_quiet_delay: float = 0.0,
        capture_dies_after_qemu: bool = False,
        **argument_overrides,
    ):
        arguments = self._arguments(phase, duration, **argument_overrides)
        client_kwargs = dict(client_kwargs or {})
        self.events.clear()

        def start_capture(interface, pcap, stats, *, tcpdump, evidence_fd=None, popen=None, timeout=15.0, file_size_limit=None):
            del tcpdump, popen, timeout, evidence_fd
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

        def stop_capture(capture, timeout=20.0, evidence_fd=None):
            del capture, timeout, evidence_fd
            self.events.append(("capture_stop",))
            if capture_stop_error:
                raise OSError("injected capture stop failure")
            return 0

        def start_vm(state, *, name, tap, qemu_user, uid, gid, log_path=None, log_fd=None):
            del state, name, tap, qemu_user, uid, gid
            self.events.append(("vm_start",))
            if log_fd is not None:
                os.write(log_fd, b"qemu log\n")
            else:
                log_path = pathlib.Path(log_path)
                self.assertTrue(str(log_path).startswith(str(self.evidence)))
                log_path.write_text("qemu log\n", encoding="utf-8")
            return FakeProcess(self.events), ["qemu-system"], ["setpriv", "--", "qemu"]

        def fake_run(argv, **kwargs):
            if scan_kwargs is not None:
                scan_kwargs.update(kwargs)
            text = " ".join(str(part) for part in argv)
            if "pcapscan.py" not in text:
                raise AssertionError(f"unexpected subprocess.run: {text}")

            if scan_report_override is not None:
                self.events.append(("scan",))
                return subprocess.CompletedProcess(
                    argv,
                    scan_rc,
                    stdout=json.dumps(scan_report_override).encode()
                    if not isinstance(scan_report_override, bytes)
                    else scan_report_override,
                    stderr=b"",
                )

            def option(name):
                return argv[argv.index(name) + 1]

            def digest(path, algorithm="sha256"):
                hasher = __import__("hashlib").new(algorithm)
                with open(path, "rb") as stream:
                    for chunk in iter(lambda: stream.read(65536), b""):
                        hasher.update(chunk)
                return hasher.hexdigest()

            self.events.append(("scan",))
            report = {
                "verdict": scan_verdict,
                "control_before": option("--control-before"),
                "control_after": option("--control-after"),
                "capture_meta": {
                    "source_sha256": digest(option("--pcap")),
                    "stats_sha256": digest(option("--tcpdump-stats")),
                    "capture_argv_sha256": digest(option("--capture-argv-file")),
                    "policy_sha256": digest(option("--policy")),
                },
            }
            return subprocess.CompletedProcess(
                argv,
                scan_rc,
                stdout=json.dumps(report).encode(),
                stderr=b"",
            )

        pcap_slot: list[pathlib.Path | None] = [None]
        capture_slot: list = [None]
        client = HarnessQGA(self.events, pcap_slot, **client_kwargs)

        original_capture_factory = start_capture

        def capturing(interface, pcap, stats, *, tcpdump, evidence_fd=None, popen=None, timeout=15.0, file_size_limit=None):
            capture = original_capture_factory(
                interface,
                pcap,
                stats,
                tcpdump=tcpdump,
                evidence_fd=evidence_fd,
                popen=popen,
                timeout=timeout,
            )
            capture_slot[0] = capture
            return capture

        def fake_poweroff(client_arg, process, *, state=None, tap=None):
            del client_arg, state, tap
            self.events.append(("guest_poweroff",))
            if process is not None:
                process.wait()
            if capture_dies_after_qemu and capture_slot[0] is not None:
                capture_slot[0].process.exited = True
            return (0, False, False)

        with contextlib.ExitStack() as stack:
            enter = stack.enter_context
            enter(mock.patch.object(run_phase, "require_root"))
            enter(mock.patch.object(run_phase.hostcheck, "refuse_if_qemu_running"))
            enter(
                mock.patch.object(
                    run_phase,
                    "check_admission",
                    side_effect=(
                        hostcheck.Refusal("admission refused")
                        if admission_raises
                        else None
                    ),
                )
            )
            enter(mock.patch.object(
                run_phase.guest,
                "resolve_unprivileged_user",
                return_value=(1000, 1000),
            ))
            enter(mock.patch.object(run_phase.guest, "verify_base_image", return_value="0" * 128))
            enter(mock.patch.object(run_phase, "verify_state"))
            enter(mock.patch.object(run_phase, "verify_host_lab"))
            enter(mock.patch.object(run_phase, "fresh_pair", return_value={"before": NONCE_A, "after": NONCE_B}))
            enter(mock.patch.object(run_phase.shutil, "which", return_value="/usr/bin/tcpdump"))
            def fake_sleep(seconds):
                self.sleeps.append(seconds)
                if seconds == run_phase.QUIET_SECONDS:
                    self.events.append(("quiet", seconds))
                    if watch_quiet_delay:
                        threading.Event().wait(watch_quiet_delay)

            enter(mock.patch.object(run_phase.time, "sleep", side_effect=fake_sleep))
            enter(mock.patch.object(run_phase, "CAPTURE_WATCH_INTERVAL", 0.01))
            enter(mock.patch.object(run_phase, "AFTER_CAPTURE_TIMEOUT", 0.05))
            enter(mock.patch.object(run_phase, "ROUTER_ACTIVE_TIMEOUT", 0.05))
            enter(mock.patch.object(run_phase, "ROUTER_HANDSHAKE_TIMEOUT", 0.05))
            enter(mock.patch.object(run_phase, "DOCKER_RESTART_TIMEOUT", 0.05))
            enter(mock.patch.object(run_phase, "start_capture", side_effect=capturing))
            enter(mock.patch.object(run_phase, "stop_capture", side_effect=stop_capture))
            enter(mock.patch.object(run_phase, "start_vm", side_effect=start_vm))
            enter(mock.patch.object(
                run_phase,
                "isolate_tap",
                side_effect=lambda tap: self.events.append(("isolate_tap", tap)),
            ))
            enter(mock.patch.object(run_phase, "wait_for_qga_or_exit", return_value=client))
            if phase == "reboot-with-router-enabled":
                enter(mock.patch.object(run_phase, "wait_for_reboot", return_value=client))
            if poweroff_override is not None:
                enter(mock.patch.object(run_phase, "poweroff_vm", side_effect=poweroff_override))
            elif capture_dies_after_qemu:
                enter(mock.patch.object(run_phase, "poweroff_vm", side_effect=fake_poweroff))
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

    def test_scanner_crash_is_invalid_never_leak(self) -> None:
        code, record, _client, _events, _stdout, _stderr, _dir = self._run(
            "start-router", scan_rc=1, scan_report_override=b"not a report"
        )
        self.assertEqual(code, 2)
        self.assertEqual(record["result"], "INVALID")
        self.assertIn("scan_report_invalid", record["result_reason"])

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
        self.assertEqual(record["tailscale"]["backend_state"], "Running")
        self.assertEqual(record["action"]["exitcode"], 0)
        self.assertTrue(record["setup"]["active"])
        self.assertEqual(record["errors"], [])

    def test_guest_backend_state_is_allowlisted_and_never_leaks_a_sentinel(self) -> None:
        sentinel = "PrivateKey=" + "A" * 43 + "="
        code, record, _client, _events, stdout, stderr, evidence = self._run(
            "start-router", client_kwargs={"tailscale_state": sentinel}
        )
        self.assertEqual(code, 0)
        self.assertEqual(record["result"], "PASS")
        self.assertEqual(record["tailscale"]["backend_state"], "unrecognized")
        phase_text = (evidence / guest.PHASE_RECORD_FILE).read_text(encoding="utf-8")
        for text in (phase_text, stdout, stderr):
            self.assertNotIn("PrivateKey", text)
            self.assertNotIn("A" * 20, text)

    def test_backend_state_fixed_vocabulary(self) -> None:
        for state in (
            "NoState",
            "NeedsLogin",
            "NeedsMachineAuth",
            "Stopped",
            "Starting",
            "Running",
        ):
            self.assertEqual(run_phase.normalize_backend_state(state), state)
        for value in (
            "Running ",
            "running",
            "PrivateKey=" + "A" * 43,
            None,
            7,
            {"state": "Running"},
        ):
            self.assertEqual(
                run_phase.normalize_backend_state(value), "unrecognized"
            )

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
        def force_poweroff(client, process, *, state=None, tap=None):
            del client, state, tap
            self.events.append(("forced_poweroff",))
            if process is not None:
                process.wait()
            return (-9, True, False)

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
            "kill-wireguard": lambda name: "echo absent",
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
        self.assertEqual(record["tailscale"]["backend_state"], "Running")

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
        self.assertTrue(
            scan_argv[scan_argv.index("--capture-argv-file") + 1].endswith(
                "/" + guest.CAPTURE_ARGV_FILE
            )
        )
        self.assertIn("/proc/self/fd/", scan_argv[scan_argv.index("--pcap") + 1])
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

    def test_reboot_boot_id_postcondition_is_consumed(self) -> None:
        same = "11111111-2222-3333-4444-555555555555"
        code, record, _client, _events, _stdout, _stderr, _dir = self._run(
            "reboot-with-router-enabled",
            client_kwargs={"boot_ids": [same, same]},
        )
        self.assertEqual(code, 2)
        self.assertEqual(record["result"], "INVALID")
        self.assertFalse(record["boot"]["boot_id_changed"])
        self.assertIn("postcondition_failed", record["result_reason"])

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


    def test_phase_record_declares_server_side_certification(self) -> None:
        _code, record, _client, _events, _stdout, _stderr, _dir = self._run(
            "start-router"
        )
        self.assertEqual(
            record["certifies"], run_phase.CERTIFICATION
        )
        self.assertEqual(record["certifies"], "server_side_no_client_traffic")

    def test_stale_handshake_is_not_ready(self) -> None:
        stale = int(time.time()) - 10_000
        code, record, _client, _events, _stdout, _stderr, _dir = self._run(
            "start-router",
            client_kwargs={"handshake": f"peerkey\t{stale}\n".encode()},
        )
        self.assertEqual(code, 2)
        self.assertEqual(record["result"], "INVALID")
        self.assertIn("router_not_ready", record["result_reason"])

    def test_fault_and_idle_phases_require_running_exit_node(self) -> None:
        cases = {
            "idle": {},
            "stop-router": {},
            "kill-wireguard": {},
            "kill-container": {},
            "restart-docker": {},
            "reboot-with-router-enabled": {
                "boot_ids": [
                    "11111111-2222-3333-4444-555555555555",
                    "66666666-7777-8888-9999-000000000000",
                ]
            },
        }
        for phase, kwargs in cases.items():
            with self.subTest(phase=phase):
                for path in list(self.evidence.glob("*")):
                    if path.is_dir():
                        import shutil

                        shutil.rmtree(path)
                code, record, _client, _events, _stdout, _stderr, _dir = self._run(
                    phase,
                    client_kwargs={"tailscale_state": "NeedsLogin", **kwargs},
                )
                self.assertEqual(code, 2)
                self.assertEqual(record["result"], "INVALID")
                self.assertIn("router_not_ready", record["result_reason"])

    def test_missing_exit_node_is_not_ready(self) -> None:
        code, record, _client, _events, _stdout, _stderr, _dir = self._run(
            "stop-router", client_kwargs={"exit_node": False}
        )
        self.assertEqual(code, 2)
        self.assertIn("router_not_ready", record["result_reason"])

    def test_release_status_must_be_ready(self) -> None:
        def not_ready(command):
            return ExecResult(exitcode=1, stdout=b"", stderr=b"BLOCKED")

        code, record, _client, _events, _stdout, _stderr, _dir = self._run(
            "stop-router",
            client_kwargs={"overrides": [("orchestrate.py status", not_ready)]},
        )
        self.assertEqual(code, 2)
        self.assertIn("router_not_ready", record["result_reason"])

    def test_start_router_allows_pre_login(self) -> None:
        code, record, _client, _events, _stdout, _stderr, _dir = self._run(
            "start-router", client_kwargs={"tailscale_state": "NeedsLogin"}
        )
        self.assertEqual(code, 0)
        self.assertEqual(record["result"], "PASS")
        self.assertEqual(record["tailscale"]["backend_state"], "NeedsLogin")

    def test_login_pass_requires_backend_state_running(self) -> None:
        code, record, _client, _events, _stdout, _stderr, _dir = self._run(
            "login", duration=0.0, client_kwargs={"tailscale_state": "NeedsLogin"}
        )
        self.assertEqual(code, 2)
        self.assertEqual(record["result"], "INVALID")
        self.assertIn("login_not_running", record["result_reason"])

    def test_kill_wireguard_proof_within_one_second(self) -> None:
        cases = {
            "absent": ("absent", 0),
            "ifindex changed": ("changed", 0),
            "unchanged": ("unchanged", 2),
        }
        for label, (after_action, expected_code) in cases.items():
            with self.subTest(label=label):
                for path in list(self.evidence.glob("*")):
                    if path.is_dir():
                        import shutil

                        shutil.rmtree(path)
                code, record, _client, _events, _stdout, _stderr, _dir = self._run(
                    "kill-wireguard",
                    client_kwargs={"wg0_after_action": after_action},
                )
                self.assertEqual(code, expected_code)
                self.assertEqual(
                    record["postcondition"]["proof"],
                    "wg0_absent"
                    if after_action == "absent"
                    else "ifindex_changed"
                    if after_action == "changed"
                    else "wg0_unchanged",
                )
                if expected_code:
                    self.assertIn("postcondition_failed", record["result_reason"])

    def test_kill_wireguard_records_later_recovery(self) -> None:
        code, record, _client, _events, _stdout, _stderr, _dir = self._run(
            "kill-wireguard"
        )
        self.assertEqual(code, 0)
        self.assertIn("recovery", record)
        self.assertEqual(record["recovery"]["status"], "absent")

    def test_capture_size_cap_is_invalid_and_still_scans(self) -> None:
        code, record, _client, events, _stdout, _stderr, _dir = self._run(
            "start-router", capture_size_cap=1
        )
        self.assertEqual(code, 2)
        self.assertEqual(record["result"], "INVALID")
        self.assertIn("capture_size_cap", record["result_reason"])
        self.assertIn("scan", [entry[0] for entry in events])
        self.assertEqual(record["scan"]["exitcode"], 0)

    def test_capture_cap_breach_during_teardown_isolates_and_invalidates(self) -> None:
        cleanup_prefix = "rc=0; systemctl stop"
        calls = {"count": 0}

        def grow_during_final_cleanup(command):
            if command.startswith(cleanup_prefix):
                calls["count"] += 1
                if calls["count"] >= 2 and self.pcap is not None:
                    self.pcap.write_bytes(self.pcap.read_bytes() + b"x" * 50_000)
            return ExecResult(exitcode=0, stdout=b"", stderr=b"")

        code, record, _client, events, _stdout, _stderr, _dir = self._run(
            "stop-router",
            capture_size_cap=1000,
            watch_quiet_delay=0.1,
            client_kwargs={
                "overrides": [(cleanup_prefix, grow_during_final_cleanup)]
            },
        )
        self.assertEqual(code, 2)
        self.assertEqual(record["result"], "INVALID")
        self.assertIn("capture_size_cap", record["result_reason"])
        labels = [entry[0] for entry in events]
        self.assertIn("isolate_tap", labels)
        self.assertLess(labels.index("isolate_tap"), labels.index("capture_stop"))
        self.assertIn("scan", labels)
        self.assertGreater(self.pcap.stat().st_size, 1000)

    def test_host_network_tools_never_resolve_through_root_path(self) -> None:
        captured: dict = {}

        def fake_run(argv, **kwargs):
            captured["argv"] = argv
            return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

        with mock.patch.object(run_phase.subprocess, "run", side_effect=fake_run):
            run_phase.isolate_tap()
        self.assertEqual(captured["argv"], ["/usr/sbin/ip", "link", "set", "dev", guest.TAP, "down"])
        self.assertEqual(run_phase.IP, "/usr/sbin/ip")
        self.assertEqual(run_phase.NFT, "/usr/sbin/nft")

    def test_disk_low_guard_isolates_before_any_further_capture(self) -> None:
        import types

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            pcap = root / "capture.pcap"
            pcap.write_bytes(b"x" * 24)
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                guard = run_phase.CaptureGuard(
                    descriptor, pcap.name, 1024 * 1024, interval=0.01
                )
                with mock.patch.object(
                    run_phase.os,
                    "fstatvfs",
                    return_value=types.SimpleNamespace(
                        f_bavail=0, f_frsize=4096
                    ),
                ), mock.patch.object(
                    run_phase,
                    "isolate_tap",
                    side_effect=lambda tap: self.events.append(("isolate_tap", tap)),
                ):
                    guard.start()
                    deadline = time.monotonic() + 2.0
                    while guard.reason is None and time.monotonic() < deadline:
                        time.sleep(0.01)
                    guard.stop()
                self.assertEqual(guard.reason, "capture_disk_low")
                self.assertIn(("isolate_tap", guest.TAP), self.events)
                with self.assertRaises(run_phase.CaptureCapExceeded) as raised:
                    guard.raise_if_exceeded()
                self.assertIn("capture_disk_low", str(raised.exception))
            finally:
                os.close(descriptor)

    def test_capture_filename_matches_the_apparmor_pcap_pattern(self) -> None:
        # Debian's enforcing tcpdump AppArmor profile only permits savefiles
        # matching /**.pcap (and similar); the generated name must end .pcap.
        self.assertTrue(guest.CAPTURE_FILE.endswith(".pcap"))
        self.assertTrue(guest.CAPTURE_STATS_FILE.endswith(".stderr"))
        code, record, _client, _events, _stdout, _stderr, evidence_dir = self._run(
            "start-router"
        )
        self.assertEqual(code, 0)
        self.assertTrue((evidence_dir / guest.CAPTURE_FILE).name.endswith(".pcap"))
        self.assertTrue(str(record["tcpdump_argv"][-1]).endswith(".pcap"))
        self.assertEqual(
            record["tcpdump_argv_display"][-1],
            str(evidence_dir / guest.CAPTURE_FILE),
        )
        self.assertNotIn(
            "/proc/self/fd/", " ".join(record["pcapscan_argv_display"])
        )

    def test_scan_runs_with_address_space_limit_and_timeout(self) -> None:
        scan_kwargs: dict = {}
        code, _record, _client, _events, _stdout, _stderr, _dir = self._run(
            "start-router", scan_kwargs=scan_kwargs
        )
        self.assertEqual(code, 0)
        self.assertNotIn("preexec_fn", scan_kwargs)
        self.assertEqual(scan_kwargs.get("timeout"), run_phase.SCAN_TIMEOUT)
        pass_fds = scan_kwargs.get("pass_fds")
        self.assertIsInstance(pass_fds, tuple)
        self.assertTrue(pass_fds)

    def test_non_object_scan_report_is_invalid(self) -> None:
        code, record, _client, _events, _stdout, _stderr, _dir = self._run(
            "start-router", scan_report_override=[]
        )
        self.assertEqual(code, 2)
        self.assertIn("scan_report_invalid", record["result_reason"])

    def test_scan_report_must_bind_the_hashed_files(self) -> None:
        report = {
            "verdict": "PASS",
            "control_before": NONCE_A,
            "control_after": NONCE_B,
            "capture_meta": {
                "source_sha256": "0" * 64,
                "stats_sha256": "0" * 64,
                "capture_argv_sha256": "0" * 64,
                "policy_sha256": "0" * 64,
            },
        }
        code, record, _client, _events, _stdout, _stderr, _dir = self._run(
            "start-router", scan_report_override=report
        )
        self.assertEqual(code, 2)
        self.assertIn("scan_report_mismatch", record["result_reason"])

    def test_poweroff_failure_kills_isolates_and_retains_the_lock(self) -> None:
        def raising_poweroff(client, process, *, state=None, tap=None):
            del client, process, state, tap
            self.events.append(("poweroff_raised",))
            raise OSError("injected poweroff failure")

        with mock.patch.object(run_phase.runlock, "release") as release:
            code, record, _client, events, _stdout, _stderr, _dir = self._run(
                "start-router", poweroff_override=raising_poweroff
            )
        self.assertEqual(code, 2)
        self.assertTrue(record["qemu_survived"])
        self.assertIn("qemu_still_running", record["result_reason"])
        labels = [entry[0] for entry in events]
        self.assertIn("isolate_tap", labels)
        self.assertLess(labels.index("isolate_tap"), labels.index("capture_stop"))
        self.assertFalse(release.called)

    def test_profile_endpoint_accepts_colon_separator(self) -> None:
        material = run_phase.SecretMaterial(
            b"[Interface]\nPrivateKey = SECRET\n\n[Peer]\nEndpoint: 185.65.134.10:51820\n"
        )
        self.assertEqual(
            run_phase.profile_endpoint(material), ("185.65.134.10", 51820)
        )

    def test_hostcheck_tap_owner_field_is_enforced_when_present(self) -> None:
        link = {
            "ifname": "vprlab-tap0",
            "flags": ["UP"],
            "master": "vprlab0",
            "ifalias": "vprlab-owned:" + "e" * 32,
            "linkinfo": {
                "info_kind": "tun",
                "info_data": {"type": "tap", "user": "opsec"},
            },
        }
        self.assertIsNotNone(hostcheck.validate_tap_owner(link, "vprlab-qemu"))
        link["linkinfo"]["info_data"]["user"] = "vprlab-qemu"
        self.assertIsNone(hostcheck.validate_tap_owner(link, "vprlab-qemu"))


    def test_admission_is_checked_before_any_capture(self) -> None:
        with self.assertRaises(hostcheck.Refusal):
            self._run("start-router", admission_raises=True)
        self.assertNotIn("capture_start", [entry[0] for entry in self.events])

    def test_duration_is_capped_at_one_hour(self) -> None:
        arguments = self._arguments("start-router", run_phase.MAX_PHASE_DURATION + 1)
        with mock.patch.object(run_phase, "require_root"):
            with self.assertRaises(hostcheck.Refusal):
                run_phase.run_phase(arguments)


class AdmissionTests(unittest.TestCase):
    def test_low_memory_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            with self.assertRaises(hostcheck.Refusal):
                run_phase.check_admission(
                    root,
                    2 * 1024 * 1024 * 1024,
                    mem_available=run_phase.MIN_MEMORY_AVAILABLE - 1,
                    free_bytes=10 * 1024 * 1024 * 1024,
                )

    def test_low_disk_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            with self.assertRaises(hostcheck.Refusal):
                run_phase.check_admission(
                    root,
                    2 * 1024 * 1024 * 1024,
                    mem_available=run_phase.MIN_MEMORY_AVAILABLE,
                    free_bytes=2 * 1024 * 1024 * 1024,
                )

    def test_sufficient_memory_and_disk_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            run_phase.check_admission(
                root,
                1024 * 1024 * 1024,
                mem_available=run_phase.MIN_MEMORY_AVAILABLE,
                free_bytes=2 * 1024 * 1024 * 1024 + 1,
            )

    def test_qemu_kill_uses_the_popen_pid_and_proc_exe_not_the_pidfile(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            state = root / "vm-001"
            state.mkdir()
            fake = root / "qemu-system-x86_64"
            fake.write_bytes(pathlib.Path("/bin/sleep").read_bytes())
            fake.chmod(0o755)
            process = subprocess.Popen(
                [str(fake), "30"], start_new_session=True
            )
            try:
                # A foreign, QEMU-controlled pidfile must be irrelevant.
                (state / guest.PID_FILE).write_text(
                    f"{process.pid + 1}\n", encoding="ascii"
                )
                with mock.patch.object(guest, "QEMU", fake):
                    self.assertTrue(run_phase.qemu_process_is_ours(process))
                    self.assertTrue(run_phase.kill_qemu(process, state))
                self.assertIsNotNone(process.poll())
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=10)

    def test_qemu_kill_refuses_a_process_that_is_not_the_staged_binary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            state = root / "vm-001"
            state.mkdir()
            process = subprocess.Popen(["sleep", "30"])
            try:
                (state / guest.PID_FILE).write_text(
                    f"{process.pid}\n", encoding="ascii"
                )
                self.assertFalse(run_phase.qemu_process_is_ours(process))
                self.assertFalse(run_phase.kill_qemu(process, state))
                self.assertIsNone(process.poll())
            finally:
                process.kill()
                process.wait(timeout=10)


class StateLogSafetyTests(unittest.TestCase):
    def test_launch_environment_is_loader_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            state = root / "vm-001"
            state.mkdir()
            log_path = root / guest.QEMU_LOG_FILE
            captured = {}

            def fake_popen(argv, **kwargs):
                captured.update(kwargs)
                return object()

            with mock.patch.object(run_phase.subprocess, "Popen", side_effect=fake_popen):
                run_phase.start_vm(
                    state,
                    name=guest.DEFAULT_NAME,
                    tap=guest.TAP,
                    qemu_user=guest.QEMU_USER,
                    uid=1000,
                    gid=1000,
                    log_path=log_path,
                )
            environment = captured["env"]
            self.assertEqual(environment, guest.clean_environment())
            self.assertNotIn("LD_LIBRARY_PATH", environment)
            self.assertNotIn("QEMU_MODULE_DIR", environment)

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
            run_phase, "set_runner_limits"
        ), mock.patch.object(
            run_phase, "run_phase", side_effect=Boom("unexpected")
        ), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(run_phase.main(argv), 2)

    def test_provision_signal_handler_ignores_a_second_signal(self) -> None:
        provision.install_signal_handlers()
        try:
            handler = signal.getsignal(signal.SIGTERM)
            # Deferred model: the handler never raises (it could otherwise
            # interrupt Popen before the QEMU handle exists).
            handler(signal.SIGTERM, None)
            handler(signal.SIGHUP, None)
            self.assertEqual(provision._signal_number, signal.SIGTERM)
            with self.assertRaises(provision.ProvisionInterrupted):
                provision.check_interrupt()
            # The first checkpoint owns the raise; cleanup checkpoints do not.
            provision.check_interrupt()
        finally:
            provision.install_signal_handlers()
            for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
                signal.signal(signum, signal.SIG_DFL)

    def test_signal_handler_only_sets_a_deferred_flag(self) -> None:
        run_phase.install_signal_handlers()
        try:
            # The handler must never raise or block: a signal during Popen
            # simply sets the flag, and the next checkpoint raises.
            run_phase._handle_signal(signal.SIGTERM, None)
            self.assertTrue(run_phase._signal_seen)
            self.assertEqual(run_phase._signal_number, signal.SIGTERM)
            with self.assertRaises(run_phase.PhaseInterrupted):
                run_phase.check_interrupt()
            # The first checkpoint owns the raise; cleanup checkpoints do not.
            run_phase.check_interrupt()
        finally:
            run_phase._signal_seen = False
            run_phase._signal_number = None
            run_phase._signal_raised = False
            for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
                signal.signal(signum, signal.SIG_DFL)

    def test_signal_during_child_spawn_keeps_a_live_handle_for_cleanup(self) -> None:
        run_phase.install_signal_handlers()
        with tempfile.TemporaryDirectory() as temporary:
            pcap = pathlib.Path(temporary) / "capture.pcap"
            pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
            stats = pathlib.Path(temporary) / "capture.stderr"
            spawled = []
            real_popen = subprocess.Popen

            def popen_then_signal(argv, **kwargs):
                del argv
                child = real_popen(
                    [sys.executable, "-c", "import time; time.sleep(30)"],
                    start_new_session=True,
                    **{k: v for k, v in kwargs.items() if k in ("stdin", "stdout", "stderr")},
                )
                spawled.append(child)
                os.kill(os.getpid(), signal.SIGTERM)
                return child

            try:
                with self.assertRaises(run_phase.PhaseInterrupted):
                    run_phase.start_capture(
                        guest.TAP,
                        pcap,
                        stats,
                        tcpdump="/bin/sleep",
                        popen=popen_then_signal,
                    )
                self.assertEqual(len(spawled), 1)
                self.assertIsNotNone(spawled[0].poll())
            finally:
                for child in spawled:
                    if child.poll() is None:
                        child.kill()
                        child.wait(timeout=10)
                run_phase._signal_seen = False
                run_phase._signal_number = None
                run_phase._signal_raised = False
                for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
                    signal.signal(signum, signal.SIG_DFL)

    def test_spawned_tcpdump_like_child_has_empty_sigmask_and_default_signals(self) -> None:
        run_phase.install_signal_handlers()
        with tempfile.TemporaryDirectory() as temporary:
            pcap = pathlib.Path(temporary) / "capture.pcap"
            pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
            stats = pathlib.Path(temporary) / "capture.stderr"
            spawned = []

            def fake_popen(argv, **kwargs):
                del argv
                child = subprocess.Popen(
                    ["/bin/sleep", "30"], start_new_session=True
                )
                spawned.append(child)
                return child

            try:
                capture = run_phase.start_capture(
                    guest.TAP, pcap, stats, tcpdump="/bin/sleep", popen=fake_popen
                )
                status = pathlib.Path(f"/proc/{capture.process.pid}/status").read_text()
                fields = dict(
                    line.split(":", 1) for line in status.splitlines() if ":" in line
                )
                self.assertEqual(int(fields["SigBlk"].strip(), 16), 0)
                ignored = int(fields["SigIgn"].strip(), 16)
                for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                    self.assertEqual(ignored & (1 << (signum - 1)), 0)
                run_phase.stop_capture(capture, timeout=5)
            finally:
                for child in spawned:
                    if child.poll() is None:
                        child.kill()
                        child.wait(timeout=10)
                run_phase._signal_seen = False
                run_phase._signal_number = None
                run_phase._signal_raised = False
                for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
                    signal.signal(signum, signal.SIG_DFL)

    def test_capture_guard_thread_has_no_blocked_termination_signals(self) -> None:
        run_phase.install_signal_handlers()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "capture.pcap").write_bytes(b"x" * 24)
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                guard = run_phase.CaptureGuard(
                    descriptor, "capture.pcap", 1024 * 1024, interval=0.01
                )
                guard.start()
                ident = guard._thread.native_id
                status = pathlib.Path(f"/proc/self/task/{ident}/status").read_text()
                fields = dict(
                    line.split(":", 1) for line in status.splitlines() if ":" in line
                )
                self.assertEqual(int(fields["SigBlk"].strip(), 16), 0)
                guard.stop()
            finally:
                os.close(descriptor)
                run_phase._signal_seen = False
                run_phase._signal_number = None
                run_phase._signal_raised = False
                for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
                    signal.signal(signum, signal.SIG_DFL)

    def test_process_signal_with_a_running_guard_is_deferred_not_raised_in_thread(self) -> None:
        run_phase.install_signal_handlers()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "capture.pcap").write_bytes(b"x" * 24)
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                guard = run_phase.CaptureGuard(
                    descriptor, "capture.pcap", 1024 * 1024, interval=0.01
                )
                guard.start()
                os.kill(os.getpid(), signal.SIGTERM)
                deadline = time.monotonic() + 2.0
                while not run_phase._signal_seen and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(run_phase._signal_seen)
                self.assertTrue(guard._thread.is_alive())
                with self.assertRaises(run_phase.PhaseInterrupted):
                    run_phase.check_interrupt()
                guard.stop()
            finally:
                os.close(descriptor)
                run_phase._signal_seen = False
                run_phase._signal_number = None
                run_phase._signal_raised = False
                for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
                    signal.signal(signum, signal.SIG_DFL)


class CaptureFileTests(unittest.TestCase):
    def test_setup_failure_reaps_a_child_that_never_reached_the_caller(self) -> None:
        process = subprocess.Popen(
            ["sleep", "30"], start_new_session=True
        )
        run_phase.reap_after_setup_failure(process)
        self.assertIsNotNone(process.poll())

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


class RootPathTests(unittest.TestCase):
    def test_directory_fd_stays_anchored_after_a_rename(self) -> None:
        import rootfs

        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            (base / "lab" / "evidence").mkdir(parents=True)
            descriptor = rootfs.open_directory(
                base / "lab" / "evidence", create=True, anchor=base
            )
            try:
                (base / "lab").rename(base / "old")
                (base / "lab" / "evidence").mkdir(parents=True)
                (base / "lab" / "evidence" / "sentinel").write_text(
                    "forged", encoding="utf-8"
                )
                rootfs.write_bytes_at(descriptor, "capture.pcap", b"real")
                self.assertEqual(
                    (base / "old" / "evidence" / "capture.pcap").read_bytes(),
                    b"real",
                )
                self.assertEqual(
                    (base / "lab" / "evidence" / "sentinel").read_text(),
                    "forged",
                )
                self.assertFalse(
                    (base / "lab" / "evidence" / "capture.pcap").exists()
                )
            finally:
                os.close(descriptor)

    def test_intermediate_symlink_is_refused(self) -> None:
        import rootfs

        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            (base / "real").mkdir()
            (base / "link").symlink_to(base / "real")
            with self.assertRaises(rootfs.PathError):
                rootfs.open_directory(base / "link" / "evidence", create=True, anchor=base)

    def test_ancestry_records_are_produced_for_an_existing_path(self) -> None:
        import rootfs

        records = rootfs.ancestry_records("/var/lib")
        self.assertTrue(records)
        self.assertEqual(records[-1]["path"], "/var/lib")
        self.assertTrue(records[-1]["exists"])
        self.assertIn("/", [record["path"] for record in records])
        problems = rootfs.ancestry_problems(records, expected_uid=0)
        self.assertIsInstance(problems, list)

    def test_ancestry_records_refuse_user_owned_writable_or_symlink(self) -> None:
        import rootfs

        records = [
            {"path": "/", "exists": True, "is_symlink": False, "uid": 0, "mode": 0o755},
            {
                "path": "/var/lib/vprlab",
                "exists": True,
                "is_symlink": False,
                "uid": 1000,
                "mode": 0o755,
            },
        ]
        problems = rootfs.ancestry_problems(records, expected_uid=0)
        self.assertTrue(any("not owned by uid 0" in problem for problem in problems))
        records[1]["uid"] = 0
        records[1]["mode"] = 0o777
        self.assertTrue(
            any("group/other writable" in problem for problem in rootfs.ancestry_problems(records))
        )
        records[1]["mode"] = 0o755
        records[1]["is_symlink"] = True
        self.assertTrue(
            any("symlink" in problem for problem in rootfs.ancestry_problems(records))
        )
        records[1] = {
            "path": "/var/lib/vprlab",
            "exists": False,
            "is_symlink": False,
            "uid": None,
            "mode": None,
        }
        self.assertTrue(
            any("missing" in problem for problem in rootfs.ancestry_problems(records))
        )


class HostsetupTests(unittest.TestCase):
    def _valid_inventory(self):
        stats = {}
        for path, mode in (
            ("/", "0755"),
            ("/opt", "0755"),
            (hostsetup.TOOLS_ROOT, "0755"),
            (hostsetup.LEAKLAB_ROOT, "0755"),
            ("/var", "0755"),
            ("/var/lib", "0755"),
            (hostsetup.STATE_ROOT, "0755"),
            (hostsetup.IMAGES_ROOT, "0755"),
            (hostsetup.EVIDENCE_ROOT, "0700"),
            ("/run", "0755"),
            (hostsetup.RUN_ROOT, "0700"),
        ):
            stats[path] = {"type": "dir", "uid": 0, "gid": 0, "mode": mode}
        stats[hostsetup.STATE_ROOT + "/vm-001"] = {
            "type": "dir",
            "uid": 123,
            "gid": 123,
            "mode": "0700",
        }
        stats[hostsetup.TOOLS_ROOT + "/SHA256SUMS"] = {
            "type": "file",
            "uid": 0,
            "gid": 0,
            "mode": "0644",
        }
        stats[hostsetup.TOOLS_ROOT + "/usr/bin/qemu-system-x86_64"] = {
            "type": "file",
            "uid": 0,
            "gid": 0,
            "mode": "0755",
        }
        stats[hostsetup.LEAKLAB_ROOT + "/pcapscan.py"] = {
            "type": "file",
            "uid": 0,
            "gid": 0,
            "mode": "0644",
        }
        stats[hostsetup.IMAGES_ROOT + "/" + hostsetup.BASE_IMAGE_NAME] = {
            "type": "file",
            "uid": 0,
            "gid": 0,
            "mode": "0644",
        }
        users = {
            "vprlab-qemu": {
                "uid": 123,
                "gid": 123,
                "shell": "/usr/sbin/nologin",
                "home_missing": True,
                "primary_group": "vprlab-qemu",
                "supplementary": ["kvm"],
            }
        }
        return {"stat": stats}, {"users": users}

    def test_check_mode_accepts_the_layout_and_refuses_each_mutation(self) -> None:
        import copy

        stat_inventory, group_inventory = self._valid_inventory()
        self.assertEqual(
            hostsetup.check_layout(stat_inventory, group_inventory), []
        )

        def mutate(change):
            stats = copy.deepcopy(stat_inventory)
            users = copy.deepcopy(group_inventory)
            change(stats["stat"], users["users"]["vprlab-qemu"])
            return hostsetup.check_layout(stats, users)

        mutations = {
            "uid 0": lambda stat, user: user.__setitem__("uid", 0),
            "docker group": lambda stat, user: user.__setitem__(
                "supplementary", ["kvm", "docker"]
            ),
            "missing kvm": lambda stat, user: user.__setitem__("supplementary", []),
            "extra group": lambda stat, user: user.__setitem__(
                "supplementary", ["kvm", "adm2"]
            ),
            "login shell": lambda stat, user: user.__setitem__(
                "shell", "/bin/bash"
            ),
            "home exists": lambda stat, user: user.__setitem__(
                "home_missing", False
            ),
            "tools writable": lambda stat, user: stat[hostsetup.TOOLS_ROOT].__setitem__(
                "mode", "0775"
            ),
            "evidence mode": lambda stat, user: stat[
                hostsetup.EVIDENCE_ROOT
            ].__setitem__("mode", "0755"),
            "run root owner": lambda stat, user: stat[hostsetup.RUN_ROOT].__setitem__(
                "uid", 123
            ),
            "image file mode": lambda stat, user: stat[
                hostsetup.IMAGES_ROOT + "/" + hostsetup.BASE_IMAGE_NAME
            ].__setitem__("mode", "0666"),
            "state owner": lambda stat, user: stat[
                hostsetup.STATE_ROOT + "/vm-001"
            ].__setitem__("uid", 0),
            "state mode": lambda stat, user: stat[
                hostsetup.STATE_ROOT + "/vm-001"
            ].__setitem__("mode", "0755"),
            "missing ancestor": lambda stat, user: stat.pop("/var/lib"),
        }
        for label, change in mutations.items():
            with self.subTest(label=label):
                self.assertTrue(mutate(change))

    def test_check_mode_accepts_installed_executables_and_absent_vm_state(self) -> None:
        import copy

        stat_inventory, group_inventory = self._valid_inventory()
        # A 0755 executable is exactly what the plan installs.
        self.assertEqual(
            hostsetup.check_layout(stat_inventory, group_inventory), []
        )
        # Before provisioning, vm-NNN is absent and that is valid.
        stats = copy.deepcopy(stat_inventory)
        stats["stat"].pop(hostsetup.STATE_ROOT + "/vm-001")
        self.assertEqual(hostsetup.check_layout(stats, group_inventory), [])
        # A hardened root mode is accepted as long as / is trusted.
        stats["stat"]["/"]["mode"] = "0700"
        self.assertEqual(hostsetup.check_layout(stats, group_inventory), [])
        stats["stat"]["/"]["mode"] = "0777"
        self.assertTrue(hostsetup.check_layout(stats, group_inventory))
        # But a present vm-NNN must still be the QEMU user's 0700 directory.
        stats["stat"][hostsetup.STATE_ROOT + "/vm-001"] = {
            "type": "dir",
            "uid": 0,
            "gid": 0,
            "mode": "0755",
        }
        self.assertTrue(hostsetup.check_layout(stats, group_inventory))
        # Group-writable executables remain refused.
        stats = copy.deepcopy(stat_inventory)
        stats["stat"][
            hostsetup.TOOLS_ROOT + "/usr/bin/qemu-system-x86_64"
        ]["mode"] = "0775"
        self.assertTrue(hostsetup.check_layout(stats, group_inventory))

    def test_generated_plan_runs_with_stubbed_privileges_and_keeps_evidence(self):
        import hashlib

        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            tools_source = root / "source-tools"
            image_source = root / "source-images"
            (tools_source / "usr/bin").mkdir(parents=True)
            library = tools_source / "usr/lib/x86_64-linux-gnu"
            library.mkdir(parents=True)
            (library / "libslirp.so.0.4.0").write_bytes(b"slirp")
            (library / "libslirp.so.0").symlink_to("libslirp.so.0.4.0")
            for name, needed in (
                ("qemu-system-x86_64", ["libc.so.6", "libslirp.so.0"]),
                ("qemu-img", ["libc.so.6"]),
                ("genisoimage", ["libc.so.6"]),
            ):
                binary = tools_source / "usr/bin" / name
                binary.write_bytes(_synthetic_elf(needed))
                binary.chmod(0o755)
            (tools_source / "usr/bin/qemu-system-amd64").symlink_to(
                "qemu-system-x86_64"
            )
            image_source.mkdir()
            image_bytes = b"base-image"
            image = image_source / hostsetup.BASE_IMAGE_NAME
            image.write_bytes(image_bytes)
            digest = hashlib.sha512(image_bytes).hexdigest()
            tools_root = root / "dest/opt/vprlab-tools"
            state_root = root / "dest/var/lib/vprlab"
            run_root = root / "dest/run/vprlab"
            for parent in (tools_root.parent, state_root.parent, run_root.parent):
                parent.mkdir(parents=True, exist_ok=True)
            script_text = hostsetup.render_setup_script(
                tools_source=str(tools_source),
                images_source=str(image_source),
                base_image_sha512=digest,
                tools_root=str(tools_root),
                state_root=str(state_root),
                run_root=str(run_root),
            )
            script = root / "hostsetup.sh"
            script.write_text(script_text, encoding="utf-8")
            checked = subprocess.run(
                ["sh", "-n", str(script)], capture_output=True, text=True
            )
            self.assertEqual(checked.returncode, 0, checked.stderr)

            bin_dir = root / "bin"
            bin_dir.mkdir()
            stub = bin_dir / "stub"
            stub.write_text(
                """#!/bin/sh
name=${0##*/}
printf '%s %s\\n' "$name" "$*" >> "$STUB_LOG"
case "$name" in
  id) [ "$1" = "-u" ] && echo 0; exit 0 ;;
  getent)
    case "$1" in
      group) [ -f "$STUB_ROOT/group-created" ] && exit 0 ;;
      passwd) [ -f "$STUB_ROOT/user-created" ] && exit 0 ;;
    esac
    exit 1 ;;
  python3)
    # Embedded check_ancestry/check_account helpers (one argument); the
    # hostcopy helper is invoked with a verb and further arguments.
    if [ "$#" -eq 2 ]; then
      exit 0
    fi
    exec "$STUB_REAL_PYTHON" "$@" ;;
  install)
    mode=0755
    expect_mode=0
    for arg in "$@"; do
      if [ "$expect_mode" = 1 ]; then mode=$arg; expect_mode=0; continue; fi
      case "$arg" in
        -m) expect_mode=1 ;;
        "$STUB_ROOT"/*) mkdir -p "$arg"; chmod "$mode" "$arg" ;;
      esac
    done
    exit 0 ;;
  flock)
    if [ "${STUB_FLOCK:-0}" != "0" ]; then exit "$STUB_FLOCK"; fi
    exec /usr/bin/flock "$@" ;;
  pgrep) exit 1 ;;
  groupadd) touch "$STUB_ROOT/group-created"; exit 0 ;;
  useradd|usermod) touch "$STUB_ROOT/user-created"; exit 0 ;;
  userdel|chown)
    if [ "$name" = "userdel" ] && [ -n "$STUB_LOCK_PROBE" ]; then
      if /usr/bin/flock -n "$STUB_LOCK_PROBE" true 2>/dev/null; then
        printf 'LOCKPROBE free\\n' >> "$STUB_LOG"
      else
        printf 'LOCKPROBE held\\n' >> "$STUB_LOG"
      fi
    fi
    if [ "$name" = "userdel" ] && [ "${STUB_USERDEL_FAIL:-0}" = "1" ]; then
      exit 1
    fi
    exit 0 ;;
  *) exit 0 ;;
esac
""",
                encoding="utf-8",
            )
            stub.chmod(0o755)
            for name in (
                "id",
                "getent",
                "python3",
                "install",
                "flock",
                "pgrep",
                "useradd",
                "groupadd",
                "usermod",
                "userdel",
                "chown",
            ):
                (bin_dir / name).symlink_to("stub")
            log = root / "calls.log"
            environment = dict(os.environ)
            environment["PATH"] = str(bin_dir) + ":" + environment.get("PATH", "")
            environment["STUB_LOG"] = str(log)
            environment["STUB_ROOT"] = str(root / "dest")
            environment["STUB_REAL_PYTHON"] = sys.executable
            environment["STUB_LOCK_PROBE"] = str(run_root / "run.lock")
            busy_setup = dict(environment, STUB_FLOCK="1")
            result = subprocess.run(
                ["sh", str(script)],
                cwd=root,
                env=busy_setup,
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("refusing setup", result.stderr)
            self.assertFalse(tools_root.exists())
            result = subprocess.run(
                ["sh", str(script)],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            calls = log.read_text(encoding="utf-8")
            self.assertIn("useradd --system --no-create-home --shell /usr/sbin/nologin", calls)
            self.assertIn("usermod -aG kvm vprlab-qemu", calls)
            self.assertTrue((tools_root / "SHA256SUMS").is_file())
            self.assertIn(
                "usr/bin/qemu-system-x86_64",
                (tools_root / "SHA256SUMS").read_text(encoding="utf-8"),
            )
            self.assertTrue((tools_root / "usr/bin/qemu-system-x86_64").is_file())
            # The complete tree keeps confined relative links as links.
            self.assertTrue((tools_root / "usr/bin/qemu-system-amd64").is_symlink())
            self.assertEqual(
                os.readlink(tools_root / "usr/bin/qemu-system-amd64"),
                "qemu-system-x86_64",
            )
            self.assertTrue(
                (tools_root / "usr/lib/x86_64-linux-gnu/libslirp.so.0").is_symlink()
            )
            link_manifest = json.loads(
                (tools_root / "SYMLINKS.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                link_manifest["links"]["usr/lib/x86_64-linux-gnu/libslirp.so.0"],
                "libslirp.so.0.4.0",
            )
            # The root-owned scanner copy is installed with its manifest.
            copied_pcapscan = tools_root / "leaklab/pcapscan.py"
            self.assertTrue(copied_pcapscan.is_file())
            self.assertIn(
                "pcapscan.py",
                (tools_root / "leaklab/SHA256SUMS").read_text(encoding="utf-8"),
            )
            self.assertTrue((tools_root / "leaklab/vm/run_phase.py").is_file())
            self.assertFalse((tools_root / "leaklab/test_leak_lab.py").exists())
            self.assertTrue((image_source / hostsetup.BASE_IMAGE_NAME).is_file())
            self.assertTrue((state_root / "images" / hostsetup.BASE_IMAGE_NAME).is_file())
            self.assertIn(
                hostsetup.BASE_IMAGE_NAME,
                (state_root / "images" / "SHA512SUMS").read_text(encoding="utf-8"),
            )
            image_mode = stat.S_IMODE(
                (state_root / "images" / hostsetup.BASE_IMAGE_NAME).stat().st_mode
            )
            self.assertEqual(image_mode, 0o644)
            self.assertTrue((state_root / "evidence").is_dir())
            self.assertEqual(stat.S_IMODE((state_root / "evidence").stat().st_mode), 0o700)
            # provision.py, not hostsetup, owns each state directory.
            self.assertFalse((state_root / "vm-001").exists())
            # The documented setup -> provision sequence reaches provision's
            # exclusive state-directory creation instead of refusing an
            # existing directory.
            image_tar = root / "vprouter-image.tar"
            image_tar.write_bytes(b"image-tar")
            arguments = argparse.Namespace(
                index=1,
                state_root=str(state_root),
                name=guest.DEFAULT_NAME,
                image_id=guest.DEPLOYED_IMAGE_ID,
                image_tar=str(image_tar),
                release_dir=str(root / "release"),
                base_image=str(root / "base.qcow2"),
                checksum_manifest=str(root / "SHA512SUMS"),
                qemu_user="vprlab-qemu",
                run_lock=str(run_root / "run.lock"),
                ipv6_mode="netns-safe",
            )
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(provision, "require_root"))
                stack.enter_context(
                    mock.patch.object(
                        provision,
                        "_qemu_identity",
                        return_value=(os.geteuid(), os.getegid()),
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        provision.guest, "verify_base_image", return_value="0" * 128
                    )
                )
                stack.enter_context(
                    mock.patch.object(provision, "check_provision_admission")
                )
                stack.enter_context(mock.patch.object(provision, "_require_tool"))
                stack.enter_context(
                    mock.patch.object(provision.guest, "verify_tool_ancestry")
                )
                stack.enter_context(
                    mock.patch.object(provision.hostcheck, "refuse_if_qemu_running")
                )
                stack.enter_context(
                    mock.patch.object(
                        provision,
                        "_stage_payload",
                        side_effect=hostcheck.Refusal("stop after state creation"),
                    )
                )
                with self.assertRaises(hostcheck.Refusal) as raised:
                    provision.provision(arguments)
            self.assertIn("stop after state creation", str(raised.exception))
            state = state_root / "vm-001"
            self.assertTrue(state.is_dir())
            self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o700)

            # Missing pgrep must fail closed, not silently skip the QEMU check.
            minimal_bin = root / "bin-minimal"
            minimal_bin.mkdir()
            for name in ("id", "flock"):
                (minimal_bin / name).symlink_to(bin_dir / "stub")
            no_pgrep = dict(environment)
            no_pgrep["PATH"] = str(minimal_bin)
            result = subprocess.run(
                ["/bin/sh", str(script), "teardown"],
                cwd=root,
                env=no_pgrep,
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("without pgrep", result.stderr)
            self.assertTrue(tools_root.exists())
            self.assertTrue((state_root / "evidence").is_dir())

            # A failing userdel must be reported instead of "complete".
            failing = dict(environment, STUB_USERDEL_FAIL="1")
            result = subprocess.run(
                ["sh", str(script), "teardown"],
                cwd=root,
                env=failing,
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("userdel vprlab-qemu failed", result.stderr)

            busy = dict(environment, STUB_FLOCK="1")
            (run_root / "run.lock").write_text("", encoding="utf-8")
            result = subprocess.run(
                ["sh", str(script), "teardown"],
                cwd=root,
                env=busy,
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("refusing teardown", result.stderr)
            self.assertTrue((state_root / "evidence").is_dir())

            result = subprocess.run(
                ["sh", str(script), "teardown"],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(tools_root.exists())
            # Evidence is deliberately retained across teardown.
            self.assertTrue((state_root / "evidence").is_dir())
            self.assertIn("retaining evidence", result.stderr)
            self.assertIn("teardown complete", result.stdout)
            final_log = log.read_text(encoding="utf-8")
            self.assertIn("userdel vprlab-qemu", final_log)
            self.assertIn("LOCKPROBE held", final_log)
            self.assertNotIn("LOCKPROBE free", final_log)

    def test_plan_is_plan_only_and_has_no_relative_destinations(self) -> None:
        text = hostsetup.render_setup_script()
        self.assertTrue(text.startswith("#!/bin/sh\n"))
        self.assertIn("QEMU_USER=vprlab-qemu", text)
        self.assertIn("useradd --system --no-create-home", text)
        self.assertIn("usermod -aG \"$KVM_GROUP\"", text)
        self.assertIn("TOOLS_ROOT=/opt/vprlab-tools", text)
        self.assertIn("STATE_ROOT=/var/lib/vprlab", text)
        self.assertIn("EVIDENCE_ROOT=/var/lib/vprlab/evidence", text)
        self.assertIn("RUN_ROOT=/run/vprlab", text)
        self.assertIn("SHA256SUMS", text)
        self.assertIn("SHA512SUMS", text)
        self.assertIn("teardown", text)


def _synthetic_elf(needed, *, bits=64, endian="<") -> bytes:
    """Build a tiny ET_EXEC with one PT_DYNAMIC and a DT_NEEDED string table."""
    is64 = bits == 64
    ehsize = 64 if is64 else 52
    phentsize = 56 if is64 else 32
    dynent = 16 if is64 else 8
    phoff = ehsize
    dynoff = phoff + phentsize
    strtab = b"\x00"
    offsets = []
    for name in needed:
        offsets.append(len(strtab))
        strtab += name.encode("ascii") + b"\x00"
    stroff = dynoff + dynent * (len(needed) + 3)
    dynamic = bytearray()
    fmt = endian + ("qQ" if is64 else "iI")
    for name_offset in offsets:
        dynamic += struct.pack(fmt, 1, name_offset)
    dynamic += struct.pack(fmt, 5, stroff)
    dynamic += struct.pack(fmt, 10, len(strtab))
    dynamic += struct.pack(fmt, 0, 0)
    assert len(dynamic) == dynent * (len(needed) + 3)
    total = stroff + len(strtab)
    data = bytearray(total)
    ident = bytearray(16)
    ident[:4] = b"\x7fELF"
    ident[4] = 2 if is64 else 1
    ident[5] = 1 if endian == "<" else 2
    ident[6] = 1
    data[:16] = ident
    if is64:
        struct.pack_into(endian + "HHIQQQIHHHHHH", data, 16, 2, 62, 1,
                         dynoff, phoff, 0, 0, ehsize, phentsize, 1, 0, 0, 0)
        struct.pack_into(endian + "IIQQQQQQ", data, phoff,
                         2, 0, dynoff, dynoff, dynoff, len(dynamic), len(dynamic), 8)
    else:
        struct.pack_into(endian + "HHIIIIIHHHHHH", data, 16, 2, 3, 1,
                         dynoff, phoff, 0, 0, ehsize, phentsize, 1, 0, 0, 0)
        struct.pack_into(endian + "IIIIIIII", data, phoff,
                         2, dynoff, dynoff, dynoff, len(dynamic), len(dynamic), 0, 4)
    data[dynoff:dynoff + len(dynamic)] = dynamic
    data[stroff:stroff + len(strtab)] = strtab
    return bytes(data)


def _ipv4_frame(
    payload: bytes,
    *,
    src_ip: str,
    dst_ip: str,
    src_mac: str,
    dst_mac: str,
    protocol: int = 17,
) -> bytes:
    ethernet = (
        bytes.fromhex(dst_mac.replace(":", ""))
        + bytes.fromhex(src_mac.replace(":", ""))
        + struct.pack("!H", 0x0800)
    )
    udp = struct.pack("!HHHH", 40000, 51820, 8 + len(payload), 0) + payload
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp),
        1,
        0,
        64,
        protocol,
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    return ethernet + ipv4 + udp


def _udp_frame(
    payload: bytes,
    *,
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    src_mac: str,
    dst_mac: str,
) -> bytes:
    ethernet = (
        bytes.fromhex(dst_mac.replace(":", ""))
        + bytes.fromhex(src_mac.replace(":", ""))
        + struct.pack("!H", 0x0800)
    )
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp),
        1,
        0,
        64,
        17,
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    return ethernet + ipv4 + udp


def _pcap_bytes(frames: list[bytes]) -> bytes:
    data = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
    for index, frame in enumerate(frames):
        data += struct.pack("<IIII", 1_700_000_000 + index, 0, len(frame), len(frame))
        data += frame
    return bytes(data)


WG_DATA = b"\x04\x00\x00\x00" + b"\x00" * 12 + b"\x00" * 16


class RealScannerIntegrationTests(unittest.TestCase):
    """Run the real pcapscan CLI over evidence written by the real writers."""

    @staticmethod
    def _clean_frames() -> list[bytes]:
        before = policy.control_payload(NONCE_A)
        after = policy.control_payload(NONCE_B)
        return [
            _udp_frame(
                before,
                src_ip=guest.VM_IPV4,
                dst_ip=guest.GATEWAY_IPV4,
                sport=40000,
                dport=39001,
                src_mac=guest.VM_MAC,
                dst_mac=guest.GATEWAY_MAC,
            ),
            _ipv4_frame(
                WG_DATA,
                src_ip=guest.VM_IPV4,
                dst_ip="185.65.134.10",
                src_mac=guest.VM_MAC,
                dst_mac=guest.GATEWAY_MAC,
            ),
            _udp_frame(
                WG_DATA,
                src_ip="185.65.134.10",
                dst_ip=guest.VM_IPV4,
                sport=51820,
                dport=40000,
                src_mac=guest.GATEWAY_MAC,
                dst_mac=guest.VM_MAC,
            ),
            _udp_frame(
                after,
                src_ip=guest.VM_IPV4,
                dst_ip=guest.GATEWAY_IPV4,
                sport=40000,
                dport=39001,
                src_mac=guest.VM_MAC,
                dst_mac=guest.GATEWAY_MAC,
            ),
        ]

    def _scan(self, frames: list[bytes]) -> run_phase.ScanOutcome:
        evidence_root = self.root / "evidence"
        evidence_root.mkdir()
        root_fd = rootfs.open_directory(
            evidence_root, create=True, expected_uid=os.geteuid()
        )
        try:
            run_fd = rootfs.make_run_directory(
                root_fd, "phase-run", expected_uid=os.geteuid()
            )
        finally:
            os.close(root_fd)
        evidence = run_phase.EvidenceDirectory(fd=run_fd, path=evidence_root / "phase-run")
        self.addCleanup(evidence.close)
        lab_policy = run_phase.build_lab_policy(("185.65.134.10", 51820))
        rootfs.write_json_at(run_fd, "policy.json", lab_policy.to_dict())
        rootfs.write_bytes_at(run_fd, guest.CAPTURE_FILE, _pcap_bytes(frames))
        stats = (
            "tcpdump: listening on vprlab-tap0, link-type EN10MB (Ethernet), "
            "snapshot length 262144 bytes\n"
            f"{len(frames)} packets captured\n"
            f"{len(frames)} packets received by filter\n"
            "0 packets dropped by kernel\n"
        )
        rootfs.write_bytes_at(
            run_fd, guest.CAPTURE_STATS_FILE, stats.encode("ascii")
        )
        rootfs.write_json_at(
            run_fd,
            guest.CAPTURE_ARGV_FILE,
            guest.tcpdump_argv(
                guest.TAP, pathlib.Path(rootfs.proc_path(run_fd, guest.CAPTURE_FILE))
            ),
        )
        self.scanner = pathlib.Path(__file__).resolve().parent.parent / "pcapscan.py"
        return run_phase.scan_evidence(
            evidence,
            phase="idle",
            before=NONCE_A,
            after=NONCE_B,
            scanner_path=self.scanner,
        )

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.root = pathlib.Path(self._temporary.name)

    def test_clean_four_record_capture_passes_end_to_end(self) -> None:
        outcome = self._scan(self._clean_frames())
        self.assertTrue(outcome.present)
        self.assertEqual(outcome.exitcode, 0, outcome.stderr)
        self.assertEqual(outcome.verdict, "PASS")
        self.assertEqual(outcome.problems, [])
        meta = outcome.report["capture_meta"]
        self.assertEqual(meta["capture_argv_sha256"], outcome.hashes["capture_argv_sha256"])
        self.assertEqual(meta["source_sha256"], outcome.hashes["pcap_sha256"])
        self.assertEqual(meta["stats_sha256"], outcome.hashes["stats_sha256"])
        self.assertEqual(meta["policy_sha256"], outcome.hashes["policy_sha256"])
        self.assertNotIn("scan_report_mismatch", outcome.problems)

    def test_one_dns_record_is_a_leak_end_to_end(self) -> None:
        frames = self._clean_frames()
        frames.insert(
            -1,
            _udp_frame(
                b"\x00" * 12,
                src_ip=guest.VM_IPV4,
                dst_ip="1.1.1.1",
                sport=40000,
                dport=53,
                src_mac=guest.VM_MAC,
                dst_mac=guest.GATEWAY_MAC,
            ),
        )
        outcome = self._scan(frames)
        self.assertTrue(outcome.present)
        self.assertEqual(outcome.exitcode, 1, outcome.stderr)
        self.assertEqual(outcome.verdict, "LEAK")
        self.assertEqual(outcome.problems, [])


class HostcopyTests(unittest.TestCase):
    def test_minimal_elf_reader_parses_64_and_32_bit_dynamic_needed(self) -> None:
        for bits, endian in ((64, "<"), (64, ">"), (32, "<"), (32, ">")):
            with self.subTest(bits=bits, endian=endian):
                blob = _synthetic_elf(
                    ["libc.so.6", "libslirp.so.0"], bits=bits, endian=endian
                )
                self.assertEqual(
                    hostcopy.elf_needed_sonames(blob),
                    ["libc.so.6", "libslirp.so.0"],
                )
        with self.assertRaises(hostcopy.ElfError):
            hostcopy.elf_needed_sonames(b"not an elf")

    def test_staged_tool_dependencies_accept_real_library_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "usr/bin").mkdir(parents=True)
            library = root / "usr/lib/x86_64-linux-gnu"
            library.mkdir(parents=True)
            # Real Debian shape: the SONAME is a relative link to the full file.
            (library / "libslirp.so.0.4.0").write_bytes(b"library")
            (library / "libslirp.so.0").symlink_to("libslirp.so.0.4.0")
            for name in ("qemu-system-x86_64", "qemu-img", "genisoimage"):
                needed = ["libc.so.6", "libm.so.6"]
                if name == "qemu-system-x86_64":
                    needed.append("libslirp.so.0")
                (root / f"usr/bin/{name}").write_bytes(
                    _synthetic_elf(needed)
                )
            self.assertEqual(hostcopy.check_staged_tools(root), [])
            (library / "libslirp.so.0.4.0").unlink()
            problems = hostcopy.check_staged_tools(root)
            self.assertTrue(any("libslirp.so.0" in item for item in problems))
            # A host-provided base library is explicitly allowed.
            (root / "usr/bin/qemu-img").write_bytes(
                _synthetic_elf(["libc.so.6", "ld-linux-x86-64.so.2"])
            )
            self.assertFalse(
                any("ld-linux" in item for item in hostcopy.check_staged_tools(root))
            )

    def test_copy_preserves_links_and_verifies_both_manifests(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            source = base / "source"
            (source / "usr/bin").mkdir(parents=True)
            library = source / "usr/lib/x86_64-linux-gnu"
            library.mkdir(parents=True)
            (source / "usr/bin/qemu-system-x86_64").write_bytes(b"qemu")
            (source / "usr/bin/qemu-system-amd64").symlink_to("qemu-system-x86_64")
            (library / "libslirp.so.0.4.0").write_bytes(b"slirp")
            (library / "libslirp.so.0").symlink_to("libslirp.so.0.4.0")
            destination = base / "dest"
            manifest = destination / "SHA256SUMS"
            links = destination / "SYMLINKS.json"
            hostcopy.copy_tree(source, destination, manifest, links)
            self.assertTrue((destination / "usr/bin/qemu-system-amd64").is_symlink())
            self.assertEqual(
                os.readlink(destination / "usr/bin/qemu-system-amd64"),
                "qemu-system-x86_64",
            )
            self.assertTrue((destination / "usr/lib/x86_64-linux-gnu/libslirp.so.0").is_symlink())
            recorded = json.loads(links.read_text(encoding="utf-8"))
            self.assertEqual(
                recorded["links"]["usr/lib/x86_64-linux-gnu/libslirp.so.0"],
                "libslirp.so.0.4.0",
            )
            self.assertIn(
                "usr/lib/x86_64-linux-gnu/libslirp.so.0",
                links.read_text(encoding="utf-8"),
            )
            self.assertIn(
                "usr/lib/x86_64-linux-gnu/libslirp.so.0.4.0",
                manifest.read_text(encoding="utf-8"),
            )
            self.assertEqual(
                hostcopy.verify_tree(destination, manifest, links), []
            )
            # A manifest link target mismatch is detected.
            recorded["links"]["usr/lib/x86_64-linux-gnu/libslirp.so.0"] = (
                "libslirp.so.0.4.1"
            )
            links.write_text(json.dumps(recorded), encoding="utf-8")
            problems = hostcopy.verify_tree(destination, manifest, links)
            self.assertTrue(any("libslirp.so.0" in item for item in problems))

    def test_copy_refuses_absolute_and_escaping_links(self) -> None:
        for target in ("/etc/passwd", "../../outside"):
            with self.subTest(target=target):
                with tempfile.TemporaryDirectory() as temporary:
                    base = pathlib.Path(temporary)
                    source = base / "source"
                    source.mkdir()
                    (source / "link").symlink_to(target)
                    with self.assertRaises(hostcopy.HostcopyError):
                        hostcopy.copy_tree(
                            source,
                            base / "dest",
                            base / "dest/SHA256SUMS",
                            base / "dest/SYMLINKS.json",
                        )

    def test_copy_refuses_a_regular_file_swapped_for_a_symlink_after_listing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            source = base / "source"
            (source / "usr/bin").mkdir(parents=True)
            binary = source / "usr/bin/qemu-system-x86_64"
            binary.write_bytes(b"qemu")
            secret = base / "secret"
            secret.write_bytes(b"PRIVATE-KEY-SENTINEL")
            original_collect = hostcopy._collect

            def collecting(*args, **kwargs):
                plan = original_collect(*args, **kwargs)
                binary.unlink()
                binary.symlink_to(secret)
                return plan

            with mock.patch.object(hostcopy, "_collect", side_effect=collecting):
                with self.assertRaises(hostcopy.HostcopyError):
                    hostcopy.copy_tree(
                        source,
                        base / "dest",
                        base / "dest/SHA256SUMS",
                        base / "dest/SYMLINKS.json",
                    )


class ScannerResolutionTests(unittest.TestCase):
    def setUp(self) -> None:
        import hashlib

        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.root = pathlib.Path(self._temporary.name)
        self.repo = self.root / "repo-pcapscan.py"
        self.repo.write_bytes(b"# repository scanner\n")
        self.installed_root = self.root / "installed"
        self.installed_root.mkdir()
        self.installed = self.installed_root / "pcapscan.py"
        self.installed.write_bytes(self.repo.read_bytes())
        digest = hashlib.sha256(self.installed.read_bytes()).hexdigest()
        (self.installed_root / "SHA256SUMS").write_text(
            f"{digest}  pcapscan.py\n", encoding="utf-8"
        )

    def resolve(self, *, allow_repo=False):
        return run_phase.resolve_pcapscan(
            self.repo,
            installed_root=self.installed_root,
            allow_repo=allow_repo,
        )

    def test_verified_root_copy_is_preferred(self) -> None:
        self.assertEqual(self.resolve(), self.installed)

    def test_tampered_installed_copy_is_refused_or_overridden(self) -> None:
        self.installed.write_bytes(b"# tampered\n")
        with self.assertRaises(hostcheck.Refusal):
            self.resolve()
        self.assertEqual(self.resolve(allow_repo=True), self.repo)

    def test_missing_installed_copy_is_refused_or_overridden(self) -> None:
        (self.installed_root / "SHA256SUMS").unlink()
        with self.assertRaises(hostcheck.Refusal):
            self.resolve()
        self.assertEqual(self.resolve(allow_repo=True), self.repo)

    def test_repo_drift_needs_the_explicit_flag(self) -> None:
        self.repo.write_bytes(b"# developer working copy\n")
        with self.assertRaises(hostcheck.Refusal) as raised:
            self.resolve()
        self.assertIn("--allow-repo-scanner", str(raised.exception))
        self.assertEqual(self.resolve(allow_repo=True), self.repo)

    def test_run_phase_uses_the_installed_scanner_path(self) -> None:
        # The behavioural harness already resolves its own installed copy;
        # assert the recorded argv names it rather than the repository file.
        case = RunPhaseTests("test_idle_starts_the_router_and_expects_a_tunnel")
        case.setUp()
        try:
            code, record, _client, _events, _stdout, _stderr, _dir = case._run(
                "idle"
            )
            self.assertEqual(code, 0)
            self.assertEqual(record["pcapscan_argv"][2], str(case.scanner_root / "pcapscan.py"))
        finally:
            case.doCleanups()


class MainLimitTests(unittest.TestCase):
    def test_runner_sets_a_two_gib_address_space_limit(self) -> None:
        script = (
            "import resource, run_phase; run_phase.set_runner_limits(); "
            "print(resource.getrlimit(resource.RLIMIT_AS)[0])"
        )
        completed = subprocess.run(
            [sys.executable, "-B", "-c", script],
            cwd=pathlib.Path(__file__).resolve().parent,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(int(completed.stdout.strip()), run_phase.RUNNER_MEMORY_LIMIT)

    def test_main_applies_the_runner_limit(self) -> None:
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
        with mock.patch.object(run_phase, "install_signal_handlers"), mock.patch.object(
            run_phase, "set_runner_limits"
        ) as limits, mock.patch.object(run_phase, "run_phase", return_value=0):
            self.assertEqual(run_phase.main(argv), 0)
        limits.assert_called_once_with()


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



class ResourceLimitContractTests(unittest.TestCase):
    """QEMU/tcpdump must not inherit the runner's 2 GiB RLIMIT_AS."""

    def _set_runner_as(self, value: int):
        import resource

        previous = resource.getrlimit(resource.RLIMIT_AS)
        soft, hard = previous
        target = value if hard == resource.RLIM_INFINITY else min(value, hard)
        resource.setrlimit(resource.RLIMIT_AS, (target, hard))
        self.addCleanup(resource.setrlimit, resource.RLIMIT_AS, previous)

    @staticmethod
    def _limit(pid: int, name: str) -> str:
        text = pathlib.Path(f"/proc/{pid}/limits").read_text(encoding="utf-8")
        for line in text.splitlines():
            if line.startswith(name):
                return line
        raise AssertionError(f"{name} not found")

    def test_tcpdump_like_child_starts_with_unlimited_address_space(self) -> None:
        self._set_runner_as(2 * 1024 * 1024 * 1024)
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            pcap = root / "capture.pcap"
            pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
            stats = root / "capture.stderr"
            spawned = []

            def fake_popen(argv, **kwargs):
                del argv
                child = subprocess.Popen(
                    ["/bin/sleep", "30"], start_new_session=True
                )
                spawned.append(child)
                return child

            capture = run_phase.start_capture(
                guest.TAP, pcap, stats, tcpdump="/bin/sleep", popen=fake_popen
            )
            try:
                line = self._limit(capture.process.pid, "Max address space")
                self.assertIn("unlimited", line)
                self.assertNotIn(str(2 * 1024 * 1024 * 1024), line)
            finally:
                run_phase.stop_capture(capture, timeout=5)
                for child in spawned:
                    if child.poll() is None:
                        child.kill()
                        child.wait(timeout=10)

    def test_qemu_like_child_gets_fsize_and_unlimited_address_space(self) -> None:
        self._set_runner_as(2 * 1024 * 1024 * 1024)
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            state = root / "vm-001"
            state.mkdir()
            log = root / "qemu.log"
            real_popen = subprocess.Popen
            spawned = []

            def fake_popen(argv, **kwargs):
                del argv, kwargs
                child = real_popen(["/bin/sleep", "30"], start_new_session=True)
                spawned.append(child)
                return child

            with mock.patch.object(run_phase.subprocess, "Popen", side_effect=fake_popen):
                process, _argv, _launch = run_phase.start_vm(
                    state,
                    name=guest.DEFAULT_NAME,
                    tap=guest.TAP,
                    qemu_user=guest.QEMU_USER,
                    uid=1000,
                    gid=1000,
                    log_path=log,
                )
            try:
                self.assertIn(
                    "unlimited", self._limit(process.pid, "Max address space")
                )
                fsize = self._limit(process.pid, "Max file size")
                self.assertIn(
                    str(run_phase.TEST_QEMU_FSIZE_LIMIT), fsize
                )
                status = pathlib.Path(
                    f"/proc/{process.pid}/status"
                ).read_text(encoding="utf-8")
                fields = dict(
                    line.split(":", 1)
                    for line in status.splitlines()
                    if ":" in line
                )
                self.assertEqual(int(fields["SigBlk"].strip(), 16), 0)
                ignored = int(fields["SigIgn"].strip(), 16)
                for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                    self.assertEqual(ignored & (1 << (signum - 1)), 0)
            finally:
                for child in spawned:
                    if child.poll() is None:
                        child.kill()
                        child.wait(timeout=10)


class CaptureLivenessTests(unittest.TestCase):
    def test_run_phase_marks_a_capture_that_exited_before_stop_invalid(self) -> None:
        case = RunPhaseTests("test_idle_starts_the_router_and_expects_a_tunnel")
        case.setUp()
        try:
            code, record, _client, _events, _stdout, _stderr, _dir = case._run(
                "start-router", capture_dies_after_qemu=True
            )
            self.assertEqual(code, 2)
            self.assertEqual(record["result"], "INVALID")
            self.assertIn("capture_ended_early", record["result_reason"])
            self.assertFalse(record["capture_alive_before_stop"])
        finally:
            case.doCleanups()

    def test_guard_records_the_time_of_an_early_capture_exit(self) -> None:
        class Exited:
            def poll(self):
                return 0

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "capture.pcap").write_bytes(b"x" * 24)
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            events = []
            try:
                guard = run_phase.CaptureGuard(
                    descriptor,
                    "capture.pcap",
                    1024 * 1024,
                    interval=0.01,
                    capture_process=Exited(),
                )
                with mock.patch.object(
                    run_phase,
                    "isolate_tap",
                    side_effect=lambda tap: events.append(("isolate_tap", tap)),
                ):
                    guard.start()
                    deadline = time.monotonic() + 2.0
                    while guard.reason is None and time.monotonic() < deadline:
                        time.sleep(0.01)
                    guard.stop()
                self.assertEqual(guard.reason, "capture_ended_early")
                self.assertIsNotNone(guard.capture_ended_early_at)
                self.assertIn(("isolate_tap", guest.TAP), events)
            finally:
                os.close(descriptor)

    def test_guard_kills_the_verified_qemu_on_a_capture_size_breach(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            fake_qemu = root / "qemu-system-x86_64"
            fake_qemu.write_bytes(pathlib.Path("/bin/sleep").read_bytes())
            fake_qemu.chmod(0o755)
            (root / "capture.pcap").write_bytes(b"x" * 64)
            process = subprocess.Popen(
                [str(fake_qemu), "30"], start_new_session=True
            )
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                guard = run_phase.CaptureGuard(
                    descriptor,
                    "capture.pcap",
                    32,
                    interval=0.01,
                    qemu_process=process,
                )
                with mock.patch.object(guest, "QEMU", fake_qemu), mock.patch.object(
                    run_phase,
                    "isolate_tap",
                    side_effect=lambda tap: None,
                ):
                    guard.start()
                    deadline = time.monotonic() + 3.0
                    while guard.reason is None and time.monotonic() < deadline:
                        time.sleep(0.01)
                    guard.stop()
                self.assertEqual(guard.reason, "capture_size_cap")
                process.wait(timeout=10)
                self.assertIsNotNone(process.poll())
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=10)
                os.close(descriptor)


class LoginUrlShapeTests(unittest.TestCase):
    class Client:
        def __init__(self, auth_url=None, logs=b""):
            self.auth_url = auth_url
            self.logs = logs

        def execute(self, program, args=(), **_kwargs):
            del program
            command = args[-1] if args else ""
            if "tailscale status --json" in command:
                return ExecResult(
                    0,
                    json.dumps({"AuthURL": self.auth_url or ""}).encode(),
                    b"",
                )
            if "docker logs" in command:
                return ExecResult(0, self.logs, b"")
            return ExecResult(0, b"", b"")

    def test_empty_auth_url_is_not_unrecognized(self) -> None:
        found, unrecognized = login_url.find_login_url_result(
            self.Client(auth_url=""), guest.DEFAULT_NAME
        )
        self.assertIsNone(found)
        self.assertFalse(unrecognized)

    def test_only_the_fixed_login_path_shape_is_accepted(self) -> None:
        for length in range(8, 17):
            with self.subTest(length=length):
                url = "https://login.tailscale.com/a/" + "a" * length
                found, unrecognized = login_url.find_login_url_result(
                    self.Client(auth_url=url), guest.DEFAULT_NAME
                )
                self.assertEqual(found, url)
                self.assertFalse(unrecognized)
        for bad in (
            "https://login.tailscale.com/a/" + "a" * 7,
            "https://login.tailscale.com/a/" + "a" * 17,
            "https://login.tailscale.com/a/" + "A" * 16,
            "https://login.tailscale.com/a/" + "a" * 8 + "/extra",
            "https://login.tailscale.com/a/" + "a" * 8 + "%00",
            "https://login.tailscale.com/other/" + "a" * 16,
        ):
            with self.subTest(bad=bad):
                found, unrecognized = login_url.find_login_url_result(
                    self.Client(auth_url=bad), guest.DEFAULT_NAME
                )
                self.assertIsNone(found)
                self.assertTrue(unrecognized)

    def test_invalid_login_url_is_not_written_and_is_an_error(self) -> None:
        invalid = "https://login.tailscale.com/a/" + "a" * 24
        case = RunPhaseTests("test_login_phase_writes_only_the_url_to_a_root_only_file")
        case.setUp()
        try:
            code, record, _client, _events, _stdout, stderr, evidence = case._run(
                "login", duration=0.0, client_kwargs={"login_url": invalid}
            )
            self.assertEqual(code, 2)
            self.assertIn("login_url_unrecognized", record["result_reason"])
            self.assertTrue(record["login_url_unrecognized"])
            self.assertFalse((evidence / "login-url.txt").exists())
            self.assertNotIn(invalid, stderr)
        finally:
            case.doCleanups()

    def test_valid_login_url_records_its_length(self) -> None:
        case = RunPhaseTests("test_login_phase_writes_only_the_url_to_a_root_only_file")
        case.setUp()
        try:
            code, record, _client, _events, _stdout, _stderr, evidence = case._run(
                "login", duration=0.0
            )
            self.assertEqual(code, 0)
            self.assertEqual(record["login_url_length"], len(LOGIN_URL))
            self.assertEqual(
                (evidence / "login-url.txt").read_text(encoding="utf-8"),
                LOGIN_URL + "\n",
            )
        finally:
            case.doCleanups()


class HostsetupInjectionTests(unittest.TestCase):
    def test_gpt_shell_payloads_are_refused(self) -> None:
        injections = (
            {"base_image_name": "x'; printf SAFETY_INJECTED; : '"},
            {"tools_source": "/tmp/$(printf SAFETY_INJECTED)"},
            {"images_source": "/tmp/a'b"},
            {"leak_lab_source": "/tmp/a\nb"},
            {"tools_root": "/opt/../etc"},
            {"state_root": "/var/lib/vprlab;id"},
            {"run_root": "/run/$(id)"},
            {"qemu_user": "user;id"},
        )
        for kwargs in injections:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(hostsetup.LayoutError):
                    hostsetup.render_setup_script(**kwargs)

    def test_default_script_has_no_unquoted_metacharacters(self) -> None:
        text = hostsetup.render_setup_script()
        self.assertNotIn("SAFETY_INJECTED", text)
        self.assertNotIn("printf SAFETY", text)


class ProvisionBoundTests(unittest.TestCase):
    def test_provision_process_sets_the_eight_gib_file_size_limit(self) -> None:
        script = (
            "import resource, provision; provision.set_provision_limits(); "
            "print(resource.getrlimit(resource.RLIMIT_FSIZE)[0])"
        )
        completed = subprocess.run(
            [sys.executable, "-B", "-c", script],
            cwd=pathlib.Path(__file__).resolve().parent,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            int(completed.stdout.strip()), provision.PROVISION_QEMU_FSIZE_LIMIT
        )

    def test_provision_admission_requires_eight_gib(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            with self.assertRaises(hostcheck.Refusal):
                provision.check_provision_admission(
                    root, free_bytes=provision.PROVISION_DISK_REQUIRED - 1
                )
            provision.check_provision_admission(
                root, free_bytes=provision.PROVISION_DISK_REQUIRED
            )

    def test_provision_serial_cap_kills_qemu_and_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            serial = root / guest.SERIAL_FILE
            serial.write_bytes(b"x" * (provision.SERIAL_SIZE_CAP + 1))
            events = []

            class FakeProcess:
                returncode = None

                def poll(self):
                    return None

                def wait(self, timeout=None):
                    del timeout
                    return 0

            def terminate(process):
                events.append(("terminate", process))

            with mock.patch.object(provision, "_terminate", side_effect=terminate):
                with self.assertRaises(hostcheck.Refusal) as raised:
                    provision._wait_for_marker(FakeProcess(), serial, 1.0)
            self.assertIn("64 MiB", str(raised.exception))
            self.assertEqual(len(events), 1)

    def test_provision_qemu_gets_eight_gib_fsize_and_no_as_limit(self) -> None:
        import resource

        previous = resource.getrlimit(resource.RLIMIT_AS)
        soft, hard = previous
        target = 2 * 1024 * 1024 * 1024 if hard == resource.RLIM_INFINITY else min(
            2 * 1024 * 1024 * 1024, hard
        )
        resource.setrlimit(resource.RLIMIT_AS, (target, hard))
        child = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True)
        try:
            provision._apply_qemu_limits(child)
            text = pathlib.Path(f"/proc/{child.pid}/limits").read_text()
            address = next(
                line for line in text.splitlines() if line.startswith("Max address space")
            )
            fsize = next(
                line for line in text.splitlines() if line.startswith("Max file size")
            )
            self.assertIn("unlimited", address)
            self.assertIn(str(provision.PROVISION_QEMU_FSIZE_LIMIT), fsize)
        finally:
            resource.setrlimit(resource.RLIMIT_AS, previous)
            if child.poll() is None:
                child.kill()
                child.wait(timeout=10)


class HostcopyConfinementTests(unittest.TestCase):
    def test_chained_symlinks_that_escape_the_source_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            source = base / "source"
            (source / "a/b").mkdir(parents=True)
            (source / "top").mkdir()
            (source / "a/b/s").symlink_to("../../top")
            (source / "a/b/k").symlink_to("s/../..")
            with self.assertRaises(hostcopy.HostcopyError):
                hostcopy.copy_tree(
                    source,
                    base / "dest",
                    base / "dest/SHA256SUMS",
                    base / "dest/SYMLINKS.json",
                )

    def test_verify_tree_reports_a_chained_link_escape_and_extra_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            source = base / "source"
            source.mkdir()
            (source / "file").write_bytes(b"data")
            destination = base / "dest"
            manifest = destination / "SHA256SUMS"
            links = destination / "SYMLINKS.json"
            hostcopy.copy_tree(source, destination, manifest, links)
            self.assertEqual(hostcopy.verify_tree(destination, manifest, links), [])
            # Plant an extra file and a chained link after the copy; the
            # verifier must report both even if the link manifest matches.
            (destination / "extra").write_bytes(b"planted")
            (destination / "a/b").mkdir(parents=True)
            (destination / "top").mkdir()
            (destination / "a/b/s").symlink_to("../../top")
            (destination / "a/b/k").symlink_to("s/../..")
            document = json.loads(links.read_text(encoding="utf-8"))
            document["links"]["a/b/s"] = "../../top"
            document["links"]["a/b/k"] = "s/../.."
            links.write_text(json.dumps(document), encoding="utf-8")
            problems = hostcopy.verify_tree(destination, manifest, links)
            self.assertTrue(any("extra" in problem for problem in problems))
            self.assertTrue(any("k" in problem and "outside" in problem for problem in problems))

    def test_hardlinked_sources_are_copied_as_independent_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            source = base / "source"
            source.mkdir()
            first = source / "first"
            first.write_bytes(b"same-bytes")
            os.link(first, source / "second")
            destination = base / "dest"
            hostcopy.copy_tree(
                source,
                destination,
                destination / "SHA256SUMS",
                destination / "SYMLINKS.json",
            )
            one = (destination / "first").stat()
            two = (destination / "second").stat()
            self.assertNotEqual((one.st_dev, one.st_ino), (two.st_dev, two.st_ino))
            self.assertEqual((destination / "first").read_bytes(), b"same-bytes")
            self.assertEqual((destination / "second").read_bytes(), b"same-bytes")


class ScannerClosureTests(unittest.TestCase):
    def _tree(self, base: pathlib.Path):
        import hashlib

        repo = base / "repo"
        installed = base / "installed"
        repo.mkdir()
        installed.mkdir()
        for name in ("pcapscan.py", "policy.py", "netplan.py"):
            text = f"# {name} original\n".encode()
            (repo / name).write_bytes(text)
            (installed / name).write_bytes(text)
        manifest = "".join(
            f"{hashlib.sha256((installed / name).read_bytes()).hexdigest()}  {name}\n"
            for name in ("pcapscan.py", "policy.py", "netplan.py")
        )
        (installed / "SHA256SUMS").write_text(manifest, encoding="utf-8")
        return repo, installed

    def test_stale_installed_import_module_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            repo, installed = self._tree(base)
            (installed / "netplan.py").write_bytes(b"# stale module\n")
            import hashlib

            lines = []
            for name in ("pcapscan.py", "policy.py", "netplan.py"):
                lines.append(
                    f"{hashlib.sha256((installed / name).read_bytes()).hexdigest()}  {name}"
                )
            (installed / "SHA256SUMS").write_text(
                "\n".join(lines) + "\n", encoding="utf-8"
            )
            with self.assertRaises(hostcheck.Refusal) as raised:
                run_phase.resolve_pcapscan(
                    repo / "pcapscan.py", installed_root=installed
                )
            self.assertIn("netplan.py", str(raised.exception))
            self.assertEqual(
                run_phase.resolve_pcapscan(
                    repo / "pcapscan.py", installed_root=installed, allow_repo=True
                ),
                repo / "pcapscan.py",
            )

    def test_every_manifest_file_matches_the_repository(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = pathlib.Path(temporary)
            repo, installed = self._tree(base)
            self.assertEqual(
                run_phase.resolve_pcapscan(
                    repo / "pcapscan.py", installed_root=installed
                ),
                installed / "pcapscan.py",
            )
            (repo / "policy.py").write_bytes(b"# developer change\n")
            with self.assertRaises(hostcheck.Refusal):
                run_phase.resolve_pcapscan(
                    repo / "pcapscan.py", installed_root=installed
                )


class AdmissionStateTests(unittest.TestCase):
    def test_state_filesystem_needs_overlay_plus_headroom(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            required = run_phase.OVERLAY_VIRTUAL_SIZE + run_phase.DISK_HEADROOM
            with self.assertRaises(hostcheck.Refusal):
                run_phase.check_admission(
                    root,
                    1024 * 1024 * 1024,
                    state_root=root,
                    mem_available=run_phase.MIN_MEMORY_AVAILABLE,
                    free_bytes=2 * 1024 * 1024 * 1024,
                    state_free_bytes=required - 1,
                )
            run_phase.check_admission(
                root,
                1024 * 1024 * 1024,
                state_root=root,
                mem_available=run_phase.MIN_MEMORY_AVAILABLE,
                free_bytes=2 * 1024 * 1024 * 1024,
                state_free_bytes=required,
            )

    def test_scanner_wrapper_applies_one_gib_without_preexec(self) -> None:
        argv = run_phase.scanner_launch_argv(
            [
                sys.executable,
                "-c",
                "import resource; print(resource.getrlimit(resource.RLIMIT_AS)[0])",
            ]
        )
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            int(completed.stdout.strip()), run_phase.SCAN_MEMORY_LIMIT
        )


class CaptureWatchIntervalTests(unittest.TestCase):
    def test_interval_is_read_when_the_guard_is_constructed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "capture.pcap").write_bytes(b"x" * 24)
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with mock.patch.object(run_phase, "CAPTURE_WATCH_INTERVAL", 0.0123):
                    guard = run_phase.CaptureGuard(
                        descriptor, "capture.pcap", 1024 * 1024
                    )
                self.assertEqual(guard.interval, 0.0123)
            finally:
                os.close(descriptor)


if __name__ == "__main__":
    unittest.main()


class ControllerR4Tests(unittest.TestCase):
    """Controller fixes after the round-4 SAFETY gate."""

    def test_kill_qemu_signals_through_a_pidfd(self) -> None:
        child = subprocess.Popen(["sleep", "30"], start_new_session=True)
        try:
            sent = []
            real = signal.pidfd_send_signal

            def spy(fd, sig, *rest):
                sent.append(sig)
                return real(fd, sig, *rest)

            with mock.patch.object(run_phase, "qemu_process_is_ours", return_value=True), \
                    mock.patch.object(run_phase.signal, "pidfd_send_signal", side_effect=spy):
                self.assertTrue(run_phase.kill_qemu(child))
            self.assertEqual(sent, [signal.SIGKILL])
            self.assertEqual(child.returncode, -signal.SIGKILL)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()

    def test_kill_qemu_never_signals_an_unverified_process(self) -> None:
        child = subprocess.Popen(["sleep", "30"], start_new_session=True)
        try:
            with mock.patch.object(run_phase, "qemu_process_is_ours", return_value=False):
                self.assertFalse(run_phase.kill_qemu(child))
            self.assertIsNone(child.poll())
        finally:
            child.kill()
            child.wait()

    def test_stop_capture_waits_the_full_timeout_before_sigkill(self) -> None:
        # A child that needs ~0.8 s to exit on SIGINT must not be SIGKILLed.
        script = (
            "import signal,time,sys\n"
            "signal.signal(signal.SIGINT, lambda *a: (time.sleep(0.8), sys.exit(0)))\n"
            "time.sleep(30)\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            process = subprocess.Popen(
                [sys.executable, "-I", "-c", script], start_new_session=True
            )
            time.sleep(0.3)
            capture = types.SimpleNamespace(
                process=process,
                pcap=root / "c.pcap",
                stats=root / "c.pcap.stderr",
                forced_stop=False,
            )
            status = run_phase.stop_capture(capture, timeout=5.0)
            self.assertEqual(status, 0)
            self.assertFalse(capture.forced_stop)

    def test_verify_tree_excludes_nested_leaklab_and_pycache(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source = root / "src"
            (source / "bin").mkdir(parents=True)
            (source / "bin" / "tool").write_bytes(b"x")
            destination = root / "dst"
            manifest = root / "SHA256SUMS"
            links = root / "SYMLINKS.json"
            hostcopy.copy_tree(source, destination, manifest, links)
            (destination / "leaklab").mkdir()
            (destination / "leaklab" / "pcapscan.py").write_bytes(b"y")
            (destination / "bin" / "__pycache__").mkdir()
            (destination / "bin" / "__pycache__" / "t.pyc").write_bytes(b"z")
            self.assertEqual(
                hostcopy.verify_tree(destination, manifest, links, exclude=("leaklab",)),
                [],
            )
            problems = hostcopy.verify_tree(destination, manifest, links)
            self.assertTrue(any("leaklab" in p for p in problems), problems)

    def test_capture_rlimit_fsize_is_cap_plus_margin(self) -> None:
        self.assertEqual(run_phase.CAPTURE_FSIZE_MARGIN, 256 * 1024 * 1024)
        child = subprocess.Popen(["sleep", "30"])
        try:
            run_phase.apply_child_limits(
                child.pid, file_size=run_phase.DEFAULT_CAPTURE_SIZE_CAP + run_phase.CAPTURE_FSIZE_MARGIN
            )
            limits = pathlib.Path(f"/proc/{child.pid}/limits").read_text()
            line = next(l for l in limits.splitlines() if l.startswith("Max file size"))
            self.assertIn(str(run_phase.DEFAULT_CAPTURE_SIZE_CAP + run_phase.CAPTURE_FSIZE_MARGIN), line)
        finally:
            child.kill()
            child.wait()
