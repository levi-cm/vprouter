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
import hashlib
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
import netplan
import clientscan
import clientprobe
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


def _harness_control_frame(payload, *, src_mac=VM_MAC, src_ip=VM_IP,
                           dst_mac=GATEWAY_MAC, dst_ip=GATEWAY):
    udp = struct.pack("!HHHH", 40000, 39001, 8 + len(payload), 0) + payload
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
    return (
        bytes.fromhex(dst_mac.replace(":", ""))
        + bytes.fromhex(src_mac.replace(":", ""))
        + struct.pack("!H", 0x0800)
        + ipv4
        + udp
    )


def _harness_pcap_record(frame, timestamp):
    ts_sec = int(timestamp)
    return (
        struct.pack("<IIII", ts_sec, 0, len(frame), len(frame)) + frame
    )


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
                "-B",
                "8192",
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
            ), mock.patch.object(provision, "verify_image_tar_chain"), mock.patch.object(
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
            ), mock.patch.object(provision, "verify_image_tar_chain"), mock.patch.object(
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
            mock.patch.object(provision, "verify_image_tar_chain"),
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
                "virtual-size": 4 * 1024**3,
            },
            {"filename": str(base), "format": "qcow2", "virtual-size": 3 * 1024**3},
        ]
        guest.verify_overlay_chain(document, overlay, base)
        # live 2026-11-09: a 2 GiB overlay of the 3 GiB base cut off the root
        # partition; equal size is the smallest that boots.
        equal = [dict(document[0], **{"virtual-size": 3 * 1024**3}), document[1]]
        guest.verify_overlay_chain(equal, overlay, base)
        for top_size in (2 * 1024**3, None, True, 0):
            with self.subTest(top_size=top_size):
                small = [dict(document[0], **{"virtual-size": top_size}), document[1]]
                with self.assertRaises(guest.IntegrityError):
                    guest.verify_overlay_chain(small, overlay, base)
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
        self.harness_ts = 1_700_000_000

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
                    self.harness_ts += 1
                    target.write_bytes(
                        target.read_bytes()
                        + _harness_pcap_record(
                            _harness_control_frame(payload), self.harness_ts
                        )
                    )
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
                "ID": "peer-router",
                "Online": True,
                "ExitNodeOption": self.exit_node,
                "PrimaryRoutes": ["0.0.0.0/0"] if self.exit_node else [],
                "TailscaleIPs": ["100.64.0.9"],
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
                    "virtual-size": 4 * 1024**3,
                },
                {"filename": str(base), "format": "qcow2", "virtual-size": 3 * 1024**3},
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
                    mock.patch.object(provision, "verify_image_tar_chain")
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

    def test_unrecognized_candidate_after_a_valid_url_is_not_an_error(self) -> None:
        # Live 2026-11-09: a valid URL was printed, yet the phase reported
        # login_url_unrecognized because later polls saw other tailscale URLs.
        calls = {"n": 0}
        valid = "https://login.tailscale.com/a/1873cd0401b6f7"

        def fake(client, name):
            calls["n"] += 1
            return (valid, False) if calls["n"] == 1 else (None, True)

        case = RunPhaseTests("test_login_phase_writes_only_the_url_to_a_root_only_file")
        case.setUp()
        try:
            with mock.patch.object(run_phase.login_url_mod, "find_login_url_result", side_effect=fake), \
                    mock.patch.object(run_phase.time, "sleep"):
                code, record, *_ = case._run("login", duration=0.05)
            self.assertNotIn("login_url_unrecognized", record.get("result_reason") or "")
            self.assertTrue(record["login_url_unrecognized"])
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

    def test_cached_bytecode_in_the_installed_tree_is_refused(self) -> None:
        # r5 review (Opus M4): a matching .pyc would shadow the verified source.
        for relative in ("__pycache__/policy.cpython-313.pyc", "vm/__pycache__",
                         "stale.pyc", "vm/old.pyo"):
            with self.subTest(path=relative), tempfile.TemporaryDirectory() as temporary:
                repo, installed = self._tree(pathlib.Path(temporary))
                target = installed / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                if relative.endswith("__pycache__"):
                    target.mkdir()
                else:
                    target.write_bytes(b"bytecode")
                with self.assertRaises(hostcheck.Refusal) as raised:
                    run_phase.resolve_pcapscan(repo / "pcapscan.py", installed_root=installed)
                self.assertIn("bytecode", str(raised.exception))

    def test_scanner_wrapper_writes_no_bytecode(self) -> None:
        argv = run_phase.scanner_launch_argv(["/usr/bin/python3", "-B", "x.py"])
        self.assertEqual(argv[1:3], ["-I", "-B"])


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


class LiveBringUpTests(unittest.TestCase):
    """Regressions for issues found during the live debdev bring-up."""

    def test_both_boot_modes_name_the_staged_seabios_image(self) -> None:
        # Live 2026-11-09: "could not load PC BIOS 'bios-256k.bin'".
        for mode in ("provision", "test"):
            with self.subTest(mode=mode):
                argv = guest.build_qemu_argv(mode, pathlib.Path("/var/lib/vprlab/vm-001"))
                self.assertIn("-bios", argv)
                self.assertEqual(
                    argv[argv.index("-bios") + 1],
                    str(guest.LAB_TOOLS / "usr/share/seabios/bios-256k.bin"),
                )


class LiveBootOrderTests(unittest.TestCase):
    def test_root_disk_has_bootindex_zero_in_both_modes(self) -> None:
        # Live 2026-11-09: with the payload ISO as a second virtio-blk disk,
        # SeaBIOS booted the payload and the guest hung with no console output.
        for mode in ("provision", "test"):
            with self.subTest(mode=mode):
                argv = guest.build_qemu_argv(mode, pathlib.Path("/var/lib/vprlab/vm-001"))
                self.assertIn("virtio-blk-pci,drive=root,bootindex=0", argv)
                self.assertNotIn(
                    "file=/var/lib/vprlab/vm-001/guest.qcow2,if=virtio,format=qcow2", argv
                )


class LivePackageTests(unittest.TestCase):
    def test_docker_cli_is_installed_explicitly(self) -> None:
        # Live 2026-11-09: on Debian 13 the docker CLI is a separate package
        # that --no-install-recommends skips; `docker info` then never works.
        script = guest.provision_script(
            name=guest.DEFAULT_NAME, image_id=guest.DEPLOYED_IMAGE_ID
        )
        install = next(
            line for line in script.splitlines() if "docker.io" in line and "docker-compose" in line
        )
        self.assertIn("docker-cli", install.split())


class ImageTarChainTests(unittest.TestCase):
    """Live 2026-11-09: host containerd-store ID (index) != guest classic ID (config)."""

    def _tar(self, root: pathlib.Path, *, tamper: bool = False, top_extra=(), inner_extra=(),
             variant: str = ""):
        import hashlib, io, tarfile

        blobs = {}

        def add(document: dict) -> str:
            data = json.dumps(document).encode()
            digest = "sha256:" + hashlib.sha256(data).hexdigest()
            blobs[digest] = data
            return digest

        config = add({"architecture": "amd64", "os": "linux"})
        attest_config = add({"attestation": True})
        layer = add({"layer": "synthetic tar bytes"})
        manifest = add({"mediaType": "application/vnd.oci.image.manifest.v1+json", "config": {"digest": config},
                        "layers": [{"digest": layer}]})
        attest = add({"mediaType": "application/vnd.oci.image.manifest.v1+json", "config": {"digest": attest_config}})
        oci = "application/vnd.oci.image.manifest.v1+json"
        if variant == "fake attestation":
            other = add({"architecture": "amd64", "os": "linux", "different": True})
            second = add({"mediaType": oci, "config": {"digest": other}, "layers": [{"digest": layer}]})
            inner_extra = [{"mediaType": oci, "digest": second,
                            "platform": {"os": "linux", "architecture": "amd64"},
                            "annotations": {"vnd.docker.reference.type": "attestation-manifest"}}]
        if variant == "second same config":
            second = add({"mediaType": oci, "config": {"digest": config}, "layers": [{"digest": layer}],
                          "annotations": {"probe": "second"}})
            inner_extra = [{"mediaType": oci, "digest": second,
                            "platform": {"os": "linux", "architecture": "amd64"}}]
        index = add({"manifests": [
            {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": manifest,
             "platform": {"os": "linux", "architecture": "amd64"}},
            {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": attest,
             "platform": {"os": "unknown", "architecture": "unknown"},
             "annotations": {"vnd.docker.reference.type": "attestation-manifest"}},
            *inner_extra,
        ]})
        path = root / "image.tar"
        with tarfile.open(path, "w") as archive:
            def put(name, data):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            top = json.dumps({"manifests": [*top_extra, {"digest": index}]}).encode()
            if variant == "symlink index":
                put("real-index.json", top)
                link = tarfile.TarInfo("index.json")
                link.type = tarfile.SYMTYPE
                link.linkname = "real-index.json"
                archive.addfile(link)
            else:
                put("index.json", top)
            member = "blobs/sha256/" + manifest.split(":")[1]
            if variant == "duplicate bad first":
                put(member, b'{"different": "manifest"}')
            for digest, data in blobs.items():
                if tamper and digest == manifest:
                    data = data + b" "
                if variant == "tampered layer" and digest == layer:
                    data = data + b" "
                if variant == "missing layer" and digest == layer:
                    continue
                put("blobs/sha256/" + digest.split(":")[1], data)
        return path, index, config

    def test_valid_chain_binds_index_to_config_ignoring_attestations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path, index, config = self._tar(pathlib.Path(temporary))
            provision.verify_image_tar_chain(path, index, config)

    def test_wrong_config_or_index_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path, index, config = self._tar(pathlib.Path(temporary))
            with self.assertRaises(hostcheck.Refusal):
                provision.verify_image_tar_chain(path, index, "sha256:" + "0" * 64)
            with self.assertRaises(hostcheck.Refusal):
                provision.verify_image_tar_chain(path, "sha256:" + "1" * 64, config)

    def test_malformed_manifest_entries_are_a_refusal_not_a_crash(self) -> None:
        # r5 review (Opus M2): a non-dict entry raised AttributeError.
        for name, kwargs in {"top": {"top_extra": ["x"]},
                             "inner": {"inner_extra": [7]}}.items():
            with self.subTest(where=name), tempfile.TemporaryDirectory() as temporary:
                path, index, config = self._tar(pathlib.Path(temporary), **kwargs)
                with self.assertRaises(hostcheck.Refusal):
                    provision.verify_image_tar_chain(path, index, config)

    def test_ambiguous_or_incomplete_archives_are_refused(self) -> None:
        # r5b review (GPT M1): each of these used to be accepted.
        for variant in ("duplicate bad first", "symlink index", "fake attestation",
                        "second same config", "tampered layer", "missing layer"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                path, index, config = self._tar(pathlib.Path(temporary), variant=variant)
                with self.assertRaises(hostcheck.Refusal):
                    provision.verify_image_tar_chain(path, index, config)

    def test_tampered_blob_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path, index, config = self._tar(pathlib.Path(temporary), tamper=True)
            with self.assertRaises(hostcheck.Refusal):
                provision.verify_image_tar_chain(path, index, config)


class ReadinessDiagnosticsTests(unittest.TestCase):
    def test_safe_text_keeps_release_reasons_and_drops_key_shapes(self) -> None:
        self.assertEqual(run_phase._safe_text("Tailscale is not ready"), "Tailscale is not ready")
        self.assertEqual(run_phase._safe_text("waiting for WireGuard"), "waiting for WireGuard")
        key = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
        for leaky in (key, "reason " + key.rstrip("="), "x" * 25, "a/b", "a\nb"):
            with self.subTest(value=leaky[:12]):
                self.assertEqual(run_phase._safe_text(leaky), "unrecognized")
        self.assertIsNone(run_phase._safe_text(None))

    def test_safe_text_drops_addresses_hostnames_and_chunked_secrets(self) -> None:
        # r5 review (Opus M1): each of these used to be recorded verbatim.
        chunk = "0123456789abcdef012"
        for leaky in (
            "public exit 203.0.113.77 via ch-zrh-wg-001.relays.mullvad.net",
            "2a03:1b20:3:f011::a01f",
            "fe80::1",
            "max-vprouter.tail1234.ts.net",
            "tskey-auth-kAbCdEf123CNTRL-x",
            "k " + " ".join([chunk] * 4),
            "node ab12c",
            # r5b review (GPT I1) samples
            "peer 198.51.100.77:51820 host router-private.example",
            "peer 2001:db8::1234",
            "tskey-auth-abcdefghijklmno-pqrstuvwxyz012345",
            "token 12345678-1234-1234-1234-123456789abc",
        ):
            with self.subTest(value=leaky[:16]):
                self.assertEqual(run_phase._safe_text(leaky), "unrecognized")

    def test_every_readiness_refusal_survives_the_filter(self) -> None:
        # Only refusals raised under wait_router_ready reach this diagnostic.
        problems = run_phase.tailscale_readiness_problems({"BackendState": "Stopped"})
        problems += run_phase.tailscale_readiness_problems({"BackendState": "Running"})
        problems += run_phase.tailscale_readiness_problems(None)
        problems += run_phase.tailscale_readiness_problems(
            {"BackendState": "Running", "Self": {"Online": False, "ExitNodeOption": False}})
        self.assertGreaterEqual(len(set(problems)), 4)
        texts = [
            "cannot read the guest clock",
            "the release did not report READY (no status)",
            "the release did not report READY (status document is not READY)",
            "the release did not report READY (status exit 1)",
            "the router unit did not become active",
            "no fresh WireGuard handshake (age < 180 s) was observed in the router netns",
            "Tailscale is not a running exit node: " + "; ".join(sorted(set(problems))),
        ]
        for text in texts:
            with self.subTest(text=text[:40]):
                self.assertEqual(run_phase._safe_text(text), text)

    def test_release_reason_is_a_fixed_vocabulary(self) -> None:
        for known in ("starting Tailscale", "protected egress verified",
                      "WireGuard handshake is stale", "TimeoutExpired",
                      "CalledProcessError", "HTTPError (HTTP 503)"):
            with self.subTest(value=known):
                self.assertEqual(run_phase.release_reason(known), known)
        for unknown in ("public exit 203.0.113.77", "Tailscale is not ready on node ab",
                        "HTTPError (HTTP 503) at https://x", "httperror", ""):
            with self.subTest(value=unknown[:16]):
                recorded = run_phase.release_reason(unknown)
                self.assertIsInstance(recorded, dict)
                self.assertEqual(set(recorded), {"unlisted_sha256_12", "length"})
                self.assertNotIn(unknown or "\0", json.dumps(recorded))
        self.assertIsNone(run_phase.release_reason(None))

    def test_unhashable_or_odd_health_documents_do_not_crash(self) -> None:
        # r5b review (GPT M2): {"state": []} raised TypeError in the diagnostic.
        for body in ('{"state": [], "reason": "READY"}', '{"state": {}, "reason": []}',
                     '[]', '"READY"', 'not json'):
            class Client:
                def execute(self, program, args=(), **kwargs):
                    if "vprouter-health.json" in args[-1]:
                        return run_phase.ExecResult(exitcode=0, stdout=body.encode(), stderr=b"")
                    return run_phase.ExecResult(exitcode=1, stdout=b"", stderr=b"")
            with self.subTest(body=body):
                record = {"tailscale": {}}
                run_phase.record_readiness_refusal(
                    record, Client(), guest.DEFAULT_NAME, hostcheck.Refusal("readiness failed"))
                if body.startswith("{"):
                    self.assertEqual(record["readiness"]["release_health_state"], "unrecognized")

    def test_guest_reason_with_an_address_never_reaches_the_record(self) -> None:
        reason = "peer 198.51.100.77:51820 host router-private.example tskey-auth-abc-def"
        class Client:
            def execute(self, program, args=(), **kwargs):
                if "vprouter-health.json" in args[-1]:
                    body = json.dumps({"state": "BLOCKED", "reason": reason})
                    return run_phase.ExecResult(exitcode=0, stdout=body.encode(), stderr=b"")
                return run_phase.ExecResult(exitcode=1, stdout=b"", stderr=b"")
        record = {"tailscale": {}}
        run_phase.record_readiness_refusal(
            record, Client(), guest.DEFAULT_NAME, hostcheck.Refusal("readiness failed"))
        text = json.dumps(record)
        for fragment in ("198.51.100.77", "router-private", "tskey"):
            self.assertNotIn(fragment, text)
        self.assertEqual(record["readiness"]["release_health_reason"]["length"], len(reason))

    def test_refusal_records_gate_and_release_health(self) -> None:
        class Client:
            def execute(self, program, args=(), **kwargs):
                command = args[-1]
                if "vprouter-health.json" in command:
                    body = json.dumps({"state": "BLOCKED", "reason": "Tailscale is not ready"})
                    return run_phase.ExecResult(exitcode=0, stdout=body.encode(), stderr=b"")
                return run_phase.ExecResult(exitcode=1, stdout=b"", stderr=b"")

        record = {"tailscale": {}}
        run_phase.record_readiness_refusal(
            record, Client(), guest.DEFAULT_NAME,
            hostcheck.Refusal("the release did not report READY (status exit 1)"),
        )
        self.assertEqual(record["readiness"]["release_health_state"], "BLOCKED")
        self.assertEqual(record["readiness"]["release_health_reason"], "Tailscale is not ready")
        self.assertIn("did not report READY", record["readiness"]["refusal"])


class ClientGuestTests(unittest.TestCase):
    def test_client_fixed_facts_and_validation(self) -> None:
        self.assertEqual(guest.client_tap(1), "vprlab-ctap1")
        self.assertEqual(guest.client_mac(1), "52:54:00:76:71:02")
        self.assertEqual(guest.client_mac(9), "52:54:00:76:71:0a")
        self.assertEqual(guest.client_ipv4(1), "10.251.0.2")
        self.assertEqual(guest.client_ipv4(9), "10.251.0.10")
        self.assertEqual(guest.client_name(1), "zz-vprclient-01-do-not-use")
        self.assertEqual(
            guest.client_state_path(1), pathlib.Path("/var/lib/vprlab/client-001")
        )
        self.assertEqual(guest.CLIENT_MEMORY_MIB, 256)
        self.assertEqual(guest.CLIENT_PROVISION_MEMORY_MIB, 384)
        for index in (0, 10, True, "1"):
            with self.subTest(index=index), self.assertRaises(guest.GeneratorError):
                guest.validate_client_index(index)
        self.assertEqual(guest.CLIENT_OVERLAY_SIZE, "3G")
        self.assertEqual(guest.TAILSCALE_TARBALL_SHA256[:8], "720cbbcc")

    def test_client_qemu_boot_is_256_mib_with_its_own_mac(self) -> None:
        argv = guest.build_qemu_argv(
            "test",
            pathlib.Path("/state"),
            name=guest.client_name(1),
            tap=guest.client_tap(1),
            memory_mib=guest.CLIENT_MEMORY_MIB,
            mac=guest.client_mac(1),
        )
        self.assertEqual(argv[argv.index("-m") + 1], "256")
        joined = " ".join(argv)
        self.assertIn("ifname=vprlab-ctap1", joined)
        self.assertIn("mac=52:54:00:76:71:02", joined)
        self.assertIn(guest.SANDBOX, argv)
        self.assertNotIn("-qmp", argv)
        provision = guest.build_qemu_argv(
            "provision",
            pathlib.Path("/state"),
            name=guest.client_name(1),
            memory_mib=guest.CLIENT_PROVISION_MEMORY_MIB,
            mac=guest.client_mac(1),
            provision_mac=guest.CLIENT_PROVISION_MAC,
        )
        self.assertEqual(provision[provision.index("-m") + 1], "384")
        self.assertIn("mac=" + guest.CLIENT_PROVISION_MAC, " ".join(provision))
        self.assertIn("user,id=wan", provision)

    def test_client_networkd_matches_the_client_bridge(self) -> None:
        text = guest.client_networkd_text(1)
        self.assertIn("MACAddress=52:54:00:76:71:02", text)
        self.assertIn("Address=10.251.0.2/24", text)
        self.assertIn("Gateway=10.251.0.1", text)
        self.assertIn("LinkLayerAddress=52:54:00:76:71:01", text)
        self.assertIn("DHCP=no", text)
        self.assertIn("IPv6AcceptRA=no", text)

    def test_client_traffic_script_uses_curl_resolve_and_never_records_the_ip(self) -> None:
        script = guest.client_traffic_script_text()
        self.assertIn("am.i.mullvad.net:443:", script)
        self.assertIn("https://am.i.mullvad.net/json", script)
        self.assertIn("example.com:80:", script)
        self.assertIn("X-Vprlab-Marker:", script)
        # Controller decision 1: every line is bound to the phase run id and a
        # gap-free sequence; the reversible IP hash is gone.
        self.assertIn('"r": match.group(1)', script)
        self.assertIn("s=sequence", script)
        self.assertIn('"k": "overflow"', script)
        self.assertNotIn('"h"', script)
        self.assertNotIn("hashlib", script)
        self.assertIn('"k": "exit"', script)
        self.assertIn('"k": "marker"', script)
        # Fix round 4 (P-3): curl -m 4 per probe, 4.5 s backstop, 3 s sleep;
        # worst-case loop about 11 s, below every 12-15 s coverage window.
        self.assertIn('"-m", CURL_MAX_TIME', script)
        self.assertIn('CURL_MAX_TIME = "4"', script)
        self.assertIn("timeout=PROBE_BACKSTOP", script)
        self.assertIn("PROBE_BACKSTOP = 4.5", script)
        self.assertIn("LOOP_SLEEP = 2.0", script)
        self.assertIn("time.sleep(LOOP_SLEEP)", script)
        self.assertNotIn("time.sleep(1.0)", script)
        worst_loop = 4.5 + 3.0 + 4.5
        self.assertLess(worst_loop, run_phase.CLIENT_HOLD_SAMPLE_MIN + 0.5)
        self.assertLessEqual(
            run_phase.CLIENT_HOLD_SAMPLE_TARGET + 1.0,
            clientprobe.MAX_HOLD_SAMPLE_WINDOW,
        )
        self.assertNotIn("@ip", script)  # parses only the boolean/json, not a raw IP field

    def test_client_traffic_script_compiles(self) -> None:
        import py_compile

        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "vprlab-client-traffic"
            path.write_text(guest.client_traffic_script_text(), encoding="utf-8")
            py_compile.compile(str(path), doraise=True)

    def test_client_provision_script_installs_pinned_tailscale_and_silences(self) -> None:
        text = guest.client_provision_script(1)
        # Opus B P-2 / P-4: tailscaled is protected from the OOM killer and
        # the tarball is extracted on disk, not in the /tmp tmpfs.
        self.assertIn("OOMScoreAdjust=-900", text)
        self.assertIn("/var/tmp/vprlab-ts", text)
        self.assertNotIn("/tmp/vprlab-ts", text.replace("/var/tmp/vprlab-ts", ""))
        self.assertIn(guest.TAILSCALE_TARBALL_NAME, text)
        self.assertIn(guest.TAILSCALE_TARBALL_SHA256, text)
        self.assertIn("sha256sum -c -", text)
        self.assertIn("--port=41641", text)
        self.assertIn(guest.CLIENT_TAILSCALE_STATE, text)
        for package in (
            "qemu-guest-agent",
            "ca-certificates",
            "curl",
            "python3-minimal",
        ):
            self.assertIn(package, text)
        self.assertIn("--no-install-recommends", text)
        self.assertIn("VPRLAB-CLIENT-PROVISION-OK", text)
        self.assertIn(guest.CLIENT_TRAFFIC_SCRIPT, text)
        self.assertNotIn("docker.io", text)
        self.assertNotIn("@@", text)
        user_data = guest.build_client_user_data(
            hostname="vprlab-client-001", index=1
        )
        self.assertTrue(user_data.startswith("#cloud-config\n"))
        self.assertIn("vprlab-client-provision.sh", user_data)

    def test_client_silence_check_names_the_client_network(self) -> None:
        script = guest.client_silence_check_script(1)
        self.assertIn("SILENCE-OK", script)
        self.assertIn("tailscaled.service", script)
        self.assertIn(guest.CLIENT_TRAFFIC_SCRIPT, script)
        self.assertIn("10.251.0.2/24", script)
        self.assertIn("10.251.0.1", script)
        self.assertIn("52:54:00:76:71:01", script)
        self.assertIn("52:54:00:76:71:02", script)
        self.assertNotIn("vprouter@", script)

    def test_client_overlay_is_three_gibibytes(self) -> None:
        argv = guest.build_qemu_img_create_argv(
            pathlib.Path("/base.qcow2"),
            pathlib.Path("/client.qcow2"),
            size=guest.CLIENT_OVERLAY_SIZE,
        )
        self.assertEqual(argv[-1], "3G")
        self.assertEqual(guest.CLIENT_OVERLAY_VIRTUAL_SIZE, 3 * 1024 ** 3)


class ProvisionClientTests(unittest.TestCase):
    def test_tailscale_tarball_hash_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            good = root / guest.TAILSCALE_TARBALL_NAME
            good.write_bytes(b"tailscale")
            import hashlib

            with mock.patch.object(
                guest,
                "TAILSCALE_TARBALL_SHA256",
                hashlib.sha256(b"tailscale").hexdigest(),
            ):
                self.assertEqual(
                    provision.verify_tailscale_tarball(good),
                    hashlib.sha256(b"tailscale").hexdigest(),
                )
            with self.assertRaises(hostcheck.Refusal):
                provision.verify_tailscale_tarball(good)
            link = root / "link.tgz"
            link.symlink_to(good)
            with self.assertRaises(hostcheck.Refusal):
                provision.verify_tailscale_tarball(link)
            with self.assertRaises(hostcheck.Refusal):
                provision.verify_tailscale_tarball(root / "missing.tgz")

    def test_client_name_and_address_are_validated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            arguments = argparse.Namespace(
                client=True,
                index=11,
                name="zz-vprclient-11-do-not-use",
                state_root=str(root),
                run_lock=str(root / "run.lock"),
            )
            with mock.patch.object(provision, "require_root"), self.assertRaises(
                hostcheck.Refusal
            ):
                provision.provision(arguments)
            arguments.index = 1
            arguments.name = "zz-vprclient-02-do-not-use"
            with mock.patch.object(provision, "require_root"), self.assertRaises(
                hostcheck.Refusal
            ):
                provision.provision(arguments)

    def test_client_provision_uses_a_three_gibibyte_overlay(self) -> None:
        calls = []
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            base = root / "base.qcow2"
            base.write_bytes(b"base")
            overlay = root / "client-001" / guest.OVERLAY_FILE
            with mock.patch.object(provision, "_run_generator") as generator:
                generator.side_effect = lambda argv, **kwargs: calls.append(argv)
                provision._run_generator(
                    guest.build_qemu_img_create_argv(
                        base, overlay, size=guest.CLIENT_OVERLAY_SIZE
                    ),
                    uid=1,
                    gid=1,
                    what="qemu-img create",
                    timeout=1,
                )
        self.assertEqual(calls[0][-1], "3G")

    def test_staged_tailscale_copy_is_rehashed_after_copy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            state = root / "client-001"
            state.mkdir()
            tarball = root / guest.TAILSCALE_TARBALL_NAME
            tarball.write_bytes(b"tailscale")
            digest = hashlib.sha256(b"tailscale").hexdigest()
            staging = provision._stage_client_payload(state, tarball, digest)
            self.assertEqual(
                (staging / guest.TAILSCALE_TARBALL_NAME).read_bytes(),
                b"tailscale",
            )
            other = root / "client-002"
            other.mkdir()
            with self.assertRaises(hostcheck.Refusal):
                provision._stage_client_payload(other, tarball, "0" * 64)

    def test_client_provision_pipeline_is_384_mib_and_three_gibibytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            state_root = root / "state-root"
            base = root / "base.qcow2"
            base.write_bytes(b"base")
            manifest = root / "manifest"
            manifest.write_text("", encoding="utf-8")
            tarball = root / guest.TAILSCALE_TARBALL_NAME
            tarball.write_bytes(b"tailscale")
            arguments = argparse.Namespace(
                client=True,
                index=1,
                name=guest.client_name(1),
                state_root=str(state_root),
                image_id=guest.DEPLOYED_IMAGE_ID,
                image_tar=None,
                release_dir=str(root),
                base_image=str(base),
                checksum_manifest=str(manifest),
                qemu_user=guest.QEMU_USER,
                ipv6_mode="netns-safe",
                run_lock=str(root / "run.lock"),
                tailscale_tar=str(tarball),
            )
            calls: list[list[str]] = []
            marker = hashlib.sha256(b"tailscale").hexdigest()

            def fake_run(argv, **kwargs):
                del kwargs
                calls.append(list(argv))
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

            class FakeQemu:
                returncode = None
                pid = 9100

                def __init__(self, argv, **kwargs):
                    del argv, kwargs
                    state = state_root / "client-001"
                    (state / guest.SERIAL_FILE).write_text(
                        f"VPRLAB-CLIENT-PROVISION-OK {marker}\n",
                        encoding="utf-8",
                    )

                def poll(self):
                    return self.returncode

                def wait(self, timeout=None):
                    del timeout
                    self.returncode = 0
                    return 0

            with contextlib.ExitStack() as stack:
                enter = stack.enter_context
                enter(mock.patch.object(provision, "require_root"))
                enter(mock.patch.object(provision.guest, "verify_base_image", return_value="0" * 128))
                enter(mock.patch.object(provision, "verify_tailscale_tarball", return_value=marker))
                enter(mock.patch.object(provision.hostcheck, "refuse_if_qemu_running"))
                enter(mock.patch.object(provision, "_require_tool"))
                enter(mock.patch.object(provision, "_qemu_identity", return_value=(os.geteuid(), os.getegid())))
                enter(mock.patch.object(provision, "check_provision_admission"))
                enter(mock.patch.object(provision.os, "chown"))
                enter(mock.patch.object(provision.subprocess, "run", side_effect=fake_run))
                enter(mock.patch.object(provision.subprocess, "Popen", FakeQemu))
                enter(mock.patch.object(provision.time, "sleep"))
                enter(contextlib.redirect_stdout(io.StringIO()))
                code = provision.provision(arguments)
            self.assertEqual(code, 0)
            self.assertEqual(len(calls), 3)
            self.assertEqual(calls[0][-1], guest.CLIENT_OVERLAY_SIZE)
            self.assertTrue(any(part.startswith("--reuid=") for part in calls[0]))
            state = state_root / "client-001"
            record = json.loads((state / "provision.json").read_text())
            self.assertEqual(record["role"], "client")
            self.assertEqual(record["memory_mib"], 384)
            self.assertEqual(record["test_memory_mib"], 256)
            self.assertEqual(record["overlay_size"], "3G")
            self.assertEqual(record["test_status"], "PROVISIONED_OFFLINE_READY")
            qemu_argv = record["qemu_argv"]
            self.assertEqual(qemu_argv[qemu_argv.index("-m") + 1], "384")
            self.assertIn(f"mac={guest.CLIENT_PROVISION_MAC}", " ".join(qemu_argv))


class CombinedVerdictTests(unittest.TestCase):
    def test_worst_verdict_wins(self) -> None:
        self.assertEqual(run_phase.combine_verdicts("PASS", "PASS", "PASS"), "PASS")
        self.assertEqual(run_phase.combine_verdicts("PASS", "INVALID", "PASS"), "INVALID")
        self.assertEqual(run_phase.combine_verdicts("LEAK", "INVALID", "PASS"), "LEAK")
        self.assertEqual(run_phase.combine_verdicts("PASS", "PASS", "LEAK"), "LEAK")
        self.assertEqual(
            run_phase.combine_verdicts("PASS", "PASS", "PASS", errors=["x"]), "INVALID"
        )

    def test_missing_or_unknown_verdict_is_invalid_unless_a_leak_exists(self) -> None:
        self.assertEqual(run_phase.combine_verdicts(None, None, None), "INVALID")
        self.assertEqual(run_phase.combine_verdicts("PASS", None, "PASS"), "INVALID")
        self.assertEqual(run_phase.combine_verdicts("PASS", "BOGUS", "PASS"), "INVALID")
        self.assertEqual(run_phase.combine_verdicts("LEAK", None, "PASS"), "LEAK")
        self.assertEqual(
            run_phase.combine_verdicts("LEAK", None, "PASS", errors=["scanner"]),
            "LEAK",
        )


class ClientExitBindingTests(unittest.TestCase):
    def status(self, **overrides):
        document = {
            "BackendState": "Running",
            "Self": {
                "ID": "router-node",
                "HostName": guest.DEFAULT_NAME,
                "DNSName": guest.DEFAULT_NAME + ".tailnet.ts.net.",
                "ExitNode": False,
                "ExitNodeOption": False,
                "PrimaryRoutes": [],
                "AllowedIPs": [],
            },
        }
        document.update(overrides)
        return document

    def peer(self, **overrides):
        document = {
            "ID": "router-node",
            "HostName": guest.DEFAULT_NAME,
            "ExitNodeOption": True,
            "Online": True,
            "TailscaleIPs": ["100.64.0.9", "fd7a::9"],
        }
        document.update(overrides)
        return document

    def test_router_identity_comes_from_self_id_and_addresses(self) -> None:
        node_id, addresses = run_phase.router_exit_identity(
            self.status(
                Self={
                    "ID": "router-node",
                    "TailscaleIPs": ["100.64.0.9", "fd7a::9"],
                }
            )
        )
        self.assertEqual(node_id, "router-node")
        self.assertEqual(addresses, ["100.64.0.9"])
        with self.assertRaises(hostcheck.Refusal):
            run_phase.router_exit_identity({"Self": {"TailscaleIPs": ["100.64.0.9"]}})

    def test_peer_is_bound_by_id_and_refuses_hostname_collisions(self) -> None:
        document = self.status(Peer={"a": self.peer()})
        peer = run_phase.client_find_router_peer(
            document, guest.DEFAULT_NAME, "router-node", ["100.64.0.9"]
        )
        self.assertIsNotNone(peer)
        collision = dict(document)
        collision["Peer"] = {
            "a": self.peer(),
            "b": self.peer(ID="impostor"),
        }
        self.assertIsNone(
            run_phase.client_find_router_peer(
                collision, guest.DEFAULT_NAME, "router-node", ["100.64.0.9"]
            )
        )
        duplicate_id = dict(document)
        duplicate_id["Peer"] = {"a": self.peer(), "b": self.peer()}
        self.assertIsNone(
            run_phase.client_find_router_peer(
                duplicate_id, guest.DEFAULT_NAME, "router-node", ["100.64.0.9"]
            )
        )
        wrong_id = dict(document)
        wrong_id["Peer"] = {"a": self.peer(ID="impostor")}
        self.assertIsNone(
            run_phase.client_find_router_peer(
                wrong_id, guest.DEFAULT_NAME, "router-node", ["100.64.0.9"]
            )
        )

    # Real `tailscale status --json` shape (Opus B B-1): PeerStatus
    # TailscaleIPs are bare netip.Addr values, ExitNodeStatus.TailscaleIPs
    # are netip.Prefix values.
    REAL_STATUS_JSON = """{
      "Version": "1.104.5-t0123456789-g0123456789",
      "BackendState": "Running",
      "TailscaleIPs": ["100.64.0.20", "fd7a:115c:a1e0::14"],
      "Self": {"ID": "nClient", "HostName": "zz-vprclient-01-do-not-use",
               "DNSName": "zz-vprclient-01-do-not-use.tail0000.ts.net.",
               "TailscaleIPs": ["100.64.0.20", "fd7a:115c:a1e0::14"],
               "Online": true, "ExitNode": false, "ExitNodeOption": false},
      "Peer": {"nodekey:00": {"ID": "router-node",
               "HostName": "zz-vprtest-01-do-not-use",
               "TailscaleIPs": ["100.64.0.9", "fd7a:115c:a1e0::9"],
               "Online": true, "ExitNode": true, "ExitNodeOption": true}},
      "ExitNodeStatus": {"ID": "router-node", "Online": true,
                         "TailscaleIPs": ["100.64.0.9/32", "fd7a:115c:a1e0::9/128"]}
    }"""

    def test_opus_b_b1_real_shaped_exit_node_status_is_accepted(self) -> None:
        document = json.loads(self.REAL_STATUS_JSON)
        peer = run_phase.client_find_router_peer(
            document, guest.DEFAULT_NAME, "router-node", ["100.64.0.9"]
        )
        self.assertIsNotNone(peer)
        self.assertEqual(run_phase.client_peer_ipv4(peer, ["100.64.0.9"]), "100.64.0.9")
        self.assertTrue(
            run_phase.client_peer_is_active(document, "router-node", "100.64.0.9")
        )
        self.assertTrue(
            run_phase.client_peer_is_active(
                document, "router-node", "100.64.0.9", require_online=False
            )
        )
        offline = json.loads(self.REAL_STATUS_JSON)
        offline["ExitNodeStatus"]["Online"] = False
        self.assertFalse(
            run_phase.client_peer_is_active(offline, "router-node", "100.64.0.9")
        )
        self.assertTrue(
            run_phase.client_peer_is_active(
                offline, "router-node", "100.64.0.9", require_online=False
            )
        )

    def test_exit_node_status_must_name_the_exact_peer_and_address(self) -> None:
        def status(node_id="router-node", online=True, addresses=("100.64.0.9/32",)):
            return {"ExitNodeStatus": {"ID": node_id, "Online": online,
                                       "TailscaleIPs": list(addresses)}}

        for addresses in (
            ("100.64.0.9/32",),
            ("100.64.0.9/32", "fd7a:115c:a1e0::9/128"),
            ("fd7a:115c:a1e0::9/128", "100.64.0.9/32"),
            # A bare address is accepted as the same /32.
            ("100.64.0.9",),
        ):
            with self.subTest(addresses=addresses):
                self.assertTrue(
                    run_phase.client_peer_is_active(
                        status(addresses=addresses), "router-node", "100.64.0.9"
                    )
                )
        for document in (
            status(node_id="wrong"),
            status(online=False),
            status(addresses=("100.64.0.10/32",)),
            # A wider prefix that contains the address is not the address.
            status(addresses=("100.64.0.0/10",)),
            status(addresses=("100.64.0.9/31",)),
            status(addresses=("fd7a:115c:a1e0::9/128",)),
            status(addresses=("::ffff:100.64.0.9/128",)),
            status(addresses=("100.64.0.9/32x", "garbage", 7, None)),
            status(addresses=()),
            {"ExitNodeStatus": {"ID": "router-node", "Online": True,
                                "TailscaleIPs": "100.64.0.9/32"}},
            {"ExitNodeStatus": {"ID": "router-node", "Online": True}},
            {"ExitNodeStatus": None},
            {"Self": {"ExitNode": True}},
        ):
            with self.subTest(document=document):
                self.assertFalse(
                    run_phase.client_peer_is_active(document, "router-node", "100.64.0.9")
                )
        self.assertFalse(
            run_phase.client_peer_is_active(status(), "router-node", "not-an-ip")
        )

    def test_hold_samples_accept_an_offline_router_but_never_another_peer(self) -> None:
        # During stop-router/kill-container/kill-wireguard the router's
        # Tailscale is legitimately offline; the sample proves the selection.
        offline = {"ExitNodeStatus": {"ID": "router-node", "Online": False,
                                      "TailscaleIPs": ["100.64.0.9/32"]}}
        self.assertTrue(run_phase.client_peer_is_active(
            offline, "router-node", "100.64.0.9", require_online=False))
        self.assertFalse(run_phase.client_peer_is_active(
            offline, "router-node", "100.64.0.9"))
        for status in (
            {"ExitNodeStatus": {"ID": "wrong", "Online": False, "TailscaleIPs": ["100.64.0.9/32"]}},
            {"ExitNodeStatus": {"ID": "router-node", "Online": False, "TailscaleIPs": ["100.64.0.10/32"]}},
            {"ExitNodeStatus": None},
            {"Self": {"ExitNode": True}},
        ):
            with self.subTest(status=status):
                self.assertFalse(run_phase.client_peer_is_active(
                    status, "router-node", "100.64.0.9", require_online=False))

    def test_client_identity_rejects_a_conflicting_hostname_and_dns(self) -> None:
        self.assertEqual(
            run_phase.client_identity_problems(
                self.status(
                    Self={
                        "HostName": guest.client_name(1),
                        "DNSName": guest.client_name(1) + ".tailnet.ts.net.",
                    }
                ),
                guest.client_name(1),
            ),
            [],
        )
        self.assertTrue(
            run_phase.client_identity_problems(
                self.status(
                    Self={
                        "HostName": "production-client",
                        "DNSName": guest.client_name(1) + ".tailnet.ts.net.",
                    }
                ),
                guest.client_name(1),
            )
        )
        self.assertTrue(
            run_phase.client_identity_problems(
                self.status(
                    Self={
                        "HostName": guest.client_name(1),
                        "DNSName": "production-client.tailnet.ts.net.",
                    }
                ),
                guest.client_name(1),
            )
        )
        # A missing HostName may fall back to the DNS label.
        self.assertEqual(
            run_phase.client_identity_problems(
                self.status(
                    Self={
                        "DNSName": guest.client_name(1) + ".tailnet.ts.net.",
                    }
                ),
                guest.client_name(1),
            ),
            [],
        )
        # A present but non-string HostName never falls back to the DNS label.
        self.assertTrue(
            run_phase.client_identity_problems(
                self.status(
                    Self={
                        "HostName": 123,
                        "DNSName": guest.client_name(1) + ".tailnet.ts.net.",
                    }
                ),
                guest.client_name(1),
            )
        )

    def test_truncated_exact_read_keeps_readable_leak_evidence(self) -> None:
        leak = (
            b'{"k":"exit","m":false,"ok":true,"r":"'
            + b"a" * 32
            + b'","s":1,"t":100}\n'
        )

        class FakeClient:
            def execute(self, program, args=(), timeout=60.0):
                del program, timeout
                command = args[-1] if args else ""
                # The guest file holds one more byte than the transfer
                # delivers: the guest digest covers all N bytes.
                if command.startswith("stat -c %s"):
                    return ExecResult(0, str(len(leak) + 1).encode(), b"")
                if command.endswith("| sha256sum"):
                    return ExecResult(
                        0,
                        (hashlib.sha256(leak + b"{").hexdigest() + "  -\n").encode(),
                        b"",
                    )
                if command.startswith("head -c "):
                    return ExecResult(0, leak, b"")
                return ExecResult(0, b"", b"")

        data, problem = run_phase.read_client_probe_log_exact(FakeClient())
        self.assertEqual(problem, "probe_log_truncated")
        self.assertEqual(data, leak)
        report = clientprobe.evaluate_probe_log(
            data,
            fault_epoch=105,
            post_fault_epoch=105,
            clock_start=90,
            clock_stop=110,
            run_id="a" * 32,
            fault_sequence=0,
            end_sequence=1,
            hold_seconds=30,
        )
        self.assertEqual(report["verdict"], "LEAK")

    def test_client_role_checks_use_real_route_and_exit_fields(self) -> None:
        self.assertIn(
            "the client advertises a default route",
            run_phase.client_readiness_problems(
                self.status(Self={"HostName": guest.client_name(1),
                                  "DNSName": guest.client_name(1) + ".",
                                  "PrimaryRoutes": ["0.0.0.0/0"]}),
                guest.client_name(1),
            ),
        )
        self.assertIn(
            "the client advertises a default route",
            run_phase.client_readiness_problems(
                self.status(Self={"HostName": guest.client_name(1),
                                  "DNSName": guest.client_name(1) + ".",
                                  "AllowedIPs": ["::/0"]}),
                guest.client_name(1),
            ),
        )
        self.assertIn(
            "the client advertises an exit node",
            run_phase.client_readiness_problems(
                self.status(Self={"HostName": guest.client_name(1),
                                  "DNSName": guest.client_name(1) + ".",
                                  "ExitNodeOption": True}),
                guest.client_name(1),
            ),
        )


class ClientAdmissionTests(unittest.TestCase):
    def test_two_captures_and_two_overlays_are_reserved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            cap = 1024 * 1024 * 1024
            state_required = (
                run_phase.OVERLAY_VIRTUAL_SIZE
                + guest.CLIENT_OVERLAY_VIRTUAL_SIZE
                + run_phase.DISK_HEADROOM
            )
            with self.assertRaises(hostcheck.Refusal):
                run_phase.check_admission(
                    root,
                    cap,
                    state_root=root,
                    mem_available=8 * 1024 ** 3,
                    free_bytes=2 * cap + run_phase.DISK_HEADROOM,
                    state_free_bytes=state_required - 1,
                    client_memory_mib=guest.CLIENT_MEMORY_MIB,
                    capture_count=2,
                    client_overlay=True,
                )
            with self.assertRaises(hostcheck.Refusal):
                run_phase.check_admission(
                    root,
                    cap,
                    mem_available=8 * 1024 ** 3,
                    free_bytes=2 * cap + run_phase.DISK_HEADROOM - 1,
                    capture_count=2,
                )
            run_phase.check_admission(
                root,
                cap,
                state_root=root,
                mem_available=8 * 1024 ** 3,
                free_bytes=2 * cap + run_phase.DISK_HEADROOM,
                state_free_bytes=state_required,
                client_memory_mib=guest.CLIENT_MEMORY_MIB,
                capture_count=2,
                client_overlay=True,
            )

    def test_login_only_reserves_only_its_own_resources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            cap = 1024 * 1024 * 1024
            state_required = (
                guest.CLIENT_OVERLAY_VIRTUAL_SIZE + run_phase.DISK_HEADROOM
            )
            # No capture and no router overlay: only headroom and the client
            # overlay are reserved.
            run_phase.check_admission(
                root,
                cap,
                state_root=root,
                mem_available=8 * 1024 ** 3,
                free_bytes=run_phase.DISK_HEADROOM,
                state_free_bytes=state_required,
                client_memory_mib=guest.CLIENT_MEMORY_MIB,
                capture_count=0,
                client_overlay=True,
                router_overlay=False,
            )
            with self.assertRaises(hostcheck.Refusal):
                run_phase.check_admission(
                    root,
                    cap,
                    mem_available=8 * 1024 ** 3,
                    free_bytes=run_phase.DISK_HEADROOM - 1,
                    capture_count=0,
                )
            with self.assertRaises(hostcheck.Refusal):
                run_phase.check_admission(
                    root,
                    cap,
                    state_root=root,
                    mem_available=8 * 1024 ** 3,
                    free_bytes=run_phase.DISK_HEADROOM,
                    state_free_bytes=state_required - 1,
                    client_memory_mib=guest.CLIENT_MEMORY_MIB,
                    capture_count=0,
                    client_overlay=True,
                    router_overlay=False,
                )


def client_leak_suffix(client) -> bytes:
    """Append one well-formed current-run non-Mullvad success to a fake log."""
    import json as _json

    client.sequence += 1
    document = {
        "k": "exit",
        "m": False,
        "ok": True,
        "r": client.run_id,
        "s": client.sequence,
        "t": client.clock,
    }
    return (
        _json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()


class ClientRunPhaseTests(unittest.TestCase):
    """M3 orchestration with fake router and client VMs."""

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.root = pathlib.Path(self._temporary.name)
        self.router_state = self.root / "vm-001"
        self.router_state.mkdir()
        self.client_state = self.root / "client-001"
        self.client_state.mkdir()
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

        for name in ("pcapscan.py", "clientscan.py"):
            source = (
                pathlib.Path(__file__).resolve().parent.parent / name
            ).read_bytes()
            (self.scanner_root / name).write_bytes(source)
        lines = []
        for name in ("pcapscan.py", "clientscan.py"):
            digest = hashlib.sha256((self.scanner_root / name).read_bytes()).hexdigest()
            lines.append(f"{digest}  {name}\n")
        (self.scanner_root / "SHA256SUMS").write_text("".join(lines), encoding="utf-8")
        self.events: list = []
        self.router_pcap: pathlib.Path | None = None
        self.client_pcap: pathlib.Path | None = None
        self.probe_log = b""

    def _arguments(self, phase="idle", duration=30.0, **overrides):
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
            client=1,
            state=str(self.router_state),
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

    def _run(self, phase="idle", duration=30.0, *, client_kwargs=None,
             client_capture_dead=False, **overrides):
        arguments = self._arguments(phase, duration, **overrides)
        self.events.clear()
        events = self.events
        client_name = guest.client_name(1)
        client_tap = guest.client_tap(1)
        client_kwargs = dict(client_kwargs or {})

        class FakeProcess:
            def __init__(self, label):
                self.label = label
                self.returncode = None
                self.pid = 7000 if label == "router" else 7001

            def poll(self):
                return None

            def wait(self, timeout=None):
                self.returncode = 0
                events.append(("qemu_exit", self.label))
                return 0

        class FakeCaptureProcess:
            def __init__(self, label):
                self.label = label
                self.pid = 5100 if label == "router" else 5101
                self.returncode = None

            def poll(self):
                if self.label == "client" and client_capture_dead:
                    return 1
                return None

            def send_signal(self, _signum):
                events.append(("capture_sigint", self.label))

            def wait(self, timeout=None):
                return 0

        def pcap_header():
            return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)

        def pcap_record(frame, timestamp):
            ts_sec = int(timestamp)
            ts_usec = int(round((timestamp - ts_sec) * 1_000_000))
            return (
                struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame))
                + frame
            )

        self.client_record_count = 0

        def start_capture(interface, pcap, stats, *, tcpdump, evidence_fd=None,
                          popen=None, timeout=15.0, file_size_limit=None):
            del tcpdump, evidence_fd, popen, timeout, file_size_limit
            label = "router" if interface == guest.TAP else "client"
            self.events.append(("capture_start", label, interface))
            path = pathlib.Path(pcap)
            data = pcap_header()
            if label == "router":
                data += pcap_record(b"\x00" * 60, 1_700_000_000)
            path.write_bytes(data)
            pathlib.Path(stats).write_text(
                f"tcpdump: listening on {interface}, link-type EN10MB "
                "(Ethernet), snapshot length 262144 bytes\n",
                encoding="utf-8",
            )
            if label == "router":
                self.router_pcap = path
                self._router_slot = [path]
            else:
                self.client_pcap = path
                self._client_slot = [path]
            return run_phase.Capture(
                process=FakeCaptureProcess(label),
                argv=guest.tcpdump_argv(interface, path),
                pcap=path,
                stats=pathlib.Path(stats),
            )

        def stop_capture(capture, timeout=20.0, evidence_fd=None):
            del timeout, evidence_fd
            label = "router" if capture.pcap == self.router_pcap else "client"
            self.events.append(("capture_stop", label))
            if label == "router":
                count = 1
            else:
                count = self.client_record_count
            interface = guest.TAP if label == "router" else client_tap
            pathlib.Path(capture.stats).write_text(
                f"tcpdump: listening on {interface}, link-type EN10MB "
                "(Ethernet), snapshot length 262144 bytes\n"
                f"{count} packets captured\n"
                f"{count} packets received by filter\n"
                "0 packets dropped by kernel\n",
                encoding="utf-8",
            )
            return 0

        def start_vm(state, *, name, tap, qemu_user, uid, gid, log_path=None,
                     log_fd=None, memory_mib=512, mac=guest.VM_MAC):
            del state, tap, qemu_user, uid, gid
            label = "client" if name == client_name else "router"
            self.events.append(("vm_start", label, memory_mib, mac))
            if log_fd is not None:
                os.write(log_fd, label.encode() + b"\n")
            else:
                pathlib.Path(log_path).write_text(label, encoding="utf-8")
            return (
                FakeProcess(label),
                [f"qemu-{label}", "-m", str(memory_mib)],
                ["setpriv", "--", f"qemu-{label}"],
            )

        fake_clock = [1_000_000.0]

        def fake_sleep(seconds):
            if seconds == run_phase.QUIET_SECONDS:
                self.events.append(("quiet",))
            remaining = max(0.0, float(seconds))
            while remaining > 0:
                step = min(1.0, remaining)
                fake_clock[0] += step
                remaining -= step
                if client.traffic_active and not client.silent_hold:
                    client.maybe_probe(fake_clock[0])
                if client.ghost_writing:
                    client.ghost_tick(fake_clock[0])

        def fake_monotonic():
            return fake_clock[0]

        class ClientQGA:
            def __init__(self, *, marker_fail=False, leak_only=False,
                         truncate_cat=False, truncate_final_cat=False,
                         stop_suffix=b"", stop_fail_at=None, stop_lies_at=None,
                         silent_hold=False, cat_exit=0,
                         advertise_routes=None,
                         login_blocks_until_authenticated=False,
                         frozen_clock=False, digest_fail=False,
                         prefs=None, is_active_after_stop=None,
                         ghost_writer_after_stop=None, ghost_period=1.0,
                         ghost_first=0.0, ghost_hidden=False):
                self.exit_node_active = False
                self.log = b""
                self.commands = []
                self.clock = 1_700_000_000
                self.run_id = None
                self.sequence = 0
                self.traffic_active = False
                self.capture_ts = 1_700_000_000
                self.marker_fail = marker_fail
                self.leak_only = leak_only
                self.truncate_cat = truncate_cat
                self.truncate_final_cat = truncate_final_cat
                self.stop_suffix = stop_suffix
                self.stop_fail_at = stop_fail_at
                self.stop_lies_at = stop_lies_at
                self.stop_count = 0
                self.silent_hold = silent_hold
                self.cat_exit = cat_exit
                self.advertise_routes = list(advertise_routes or ())
                self.login_blocks_until_authenticated = (
                    login_blocks_until_authenticated
                )
                self.authenticated = not login_blocks_until_authenticated
                self.login_url_reads = 0
                self.next_probe_at = None
                self.frozen_clock = frozen_clock
                self.digest_fail = digest_fail
                self.prefs = prefs
                # Round 3 knobs.  is_active_after_stop=(n, word): from stop n
                # on, `systemctl is-active` prints `word` for a stopped unit.
                self.is_active_after_stop = is_active_after_stop
                # ghost_writer_after_stop=n: stop n claims success, but a
                # writer keeps appending one current-run leak line per second.
                self.ghost_writer_after_stop = ghost_writer_after_stop
                self.ghost_writing = False
                # Round 4 knobs (Opus R4 M-1): the surviving writer appends
                # every `ghost_period` fake seconds, first `ghost_first`
                # seconds after the stop; `ghost_hidden` hides it from the
                # /proc scan (an escaped process with another command line).
                self.ghost_period = float(ghost_period)
                self.ghost_first = float(ghost_first)
                self.ghost_hidden = ghost_hidden
                self.ghost_next = None
                # truncate_next_read=(lines, exitcode): the next content read
                # (`cat` or `head -c N`) returns only the first `lines` lines.
                self.truncate_next_read = None
                # hold_plan(offset) -> bool decides whether the 1 Hz loop
                # writes at hold offset `offset` (set with hold_started_at).
                self.hold_plan = None
                self.hold_started_at = None

            def maybe_probe(self, now):
                """Model the 1 Hz traffic loop while the fake hold runs."""
                if self.next_probe_at is None:
                    self.next_probe_at = now
                while now >= self.next_probe_at:
                    due = self.next_probe_at
                    self.next_probe_at += 1.0
                    if (
                        self.hold_plan is not None
                        and self.hold_started_at is not None
                        and due > self.hold_started_at
                        and not self.hold_plan(due - self.hold_started_at)
                    ):
                        continue
                    self.clock += 1
                    self.probe_pair()

            def ghost_probe(self):
                """A writer that outlived a stop which claimed success."""
                self.append_probe("exit", ok=True, m=False)

            def ghost_tick(self, now):
                if self.ghost_next is None:
                    self.ghost_next = now + self.ghost_first
                while now >= self.ghost_next:
                    self.ghost_next += self.ghost_period
                    self.ghost_probe()

            def append_probe(self, kind, **fields):
                self.sequence += 1
                document = {
                    "k": kind,
                    "r": self.run_id,
                    "s": self.sequence,
                    "t": self.clock,
                }
                document.update(fields)
                self.log += (
                    json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
                    + b"\n"
                )

            def probe_pair(self):
                if self.leak_only:
                    self.append_probe("exit", ok=True, m=False)
                    self.append_probe("marker", ok=not self.marker_fail)
                    return
                self.append_probe("exit", ok=True, m=True)
                self.append_probe("marker", ok=not self.marker_fail)

            def status(self):
                # Real shapes (Opus B B-1): PeerStatus.TailscaleIPs are bare
                # netip.Addr values, ExitNodeStatus.TailscaleIPs are
                # netip.Prefix values.
                peer = {
                    "ID": "peer-router",
                    "HostName": guest.DEFAULT_NAME,
                    "ExitNodeOption": True,
                    "Online": True,
                    "TailscaleIPs": ["100.64.0.9", "fd7a:115c:a1e0::9"],
                }
                document = {
                    "BackendState": (
                        "Running" if self.authenticated else "NeedsLogin"
                    ),
                    "Self": {
                        "ID": "peer-client",
                        "HostName": client_name,
                        "DNSName": client_name + ".tailnet.ts.net.",
                        "ExitNode": False,
                        "ExitNodeOption": False,
                        "PrimaryRoutes": [],
                        "AllowedIPs": [],
                    },
                    "Peer": {guest.DEFAULT_NAME: peer},
                }
                if self.exit_node_active:
                    document["ExitNodeStatus"] = {
                        "ID": "peer-router",
                        "Online": True,
                        "TailscaleIPs": [
                            "100.64.0.9/32",
                            "fd7a:115c:a1e0::9/128",
                        ],
                    }
                return document

            def execute(self, program, args=(), timeout=60.0, **kwargs):
                del program, timeout, kwargs
                command = args[-1] if args else ""
                self.commands.append(command)
                events.append(("client_exec", command))
                if "SILENCE-OK" in command:
                    return ExecResult(0, b"SILENCE-OK\n", b"")
                if "tailscale status --json" in command:
                    return ExecResult(0, json.dumps(self.status()).encode(), b"")
                if "tailscale set --exit-node=" in command:
                    if "--exit-node= " not in command and command.rstrip().endswith("--exit-node="):
                        self.exit_node_active = False
                        events.append(("client_exit_cleared",))
                        return ExecResult(0, b"", b"")
                    self.exit_node_active = True
                    events.append(("client_exit_set",))
                    return ExecResult(0, b"", b"")
                if command.startswith("rm -f " + guest.CLIENT_PROBE_LOG):
                    self.log = b""
                    self.sequence = 0
                    return ExecResult(0, b"", b"")
                if "systemd-run" in command and guest.CLIENT_LOGIN_UNIT in command:
                    events.append(("client_up",))
                    self.login_unit_active = True
                    return ExecResult(0, b"", b"")
                if "systemd-run" in command:
                    events.append(("traffic_start",))
                    match = re.search(r"VPRCLIENTMARK1:([0-9a-f]{32})", command)
                    if match:
                        self.run_id = match.group(1)
                    self.sequence = 0
                    self.traffic_active = True
                    self.next_probe_at = None
                    self.probe_pair()
                    return ExecResult(0, b"", b"")
                if "systemctl is-active --quiet" in command:
                    return (
                        ExecResult(0, b"", b"")
                        if self.traffic_active
                        else ExecResult(3, b"", b"")
                    )
                if "systemctl show -p MainPID --value" in command:
                    pid = b"4242\n" if self.traffic_active else b"0\n"
                    return ExecResult(0, pid, b"")
                if "TRAFFIC-PROCS" in command:
                    live = self.traffic_active or (
                        self.ghost_writing and not self.ghost_hidden
                    )
                    return ExecResult(
                        0, b"TRAFFIC-PROCS:%d\n" % (1 if live else 0), b""
                    )
                if "/proc/meminfo" in command:
                    return ExecResult(0, b"MemAvailable:     123456 kB\n", b"")
                if "systemctl is-active" in command:
                    state = "active" if self.traffic_active else "inactive"
                    if (
                        not self.traffic_active
                        and self.is_active_after_stop is not None
                        and self.stop_count >= self.is_active_after_stop[0]
                    ):
                        state = self.is_active_after_stop[1]
                    return ExecResult(
                        0 if self.traffic_active else 3,
                        state.encode() + b"\n",
                        b"",
                    )
                if "systemctl stop vprlab-client-traffic" in command:
                    self.stop_count += 1
                    events.append(("traffic_stop", self.stop_count))
                    if self.stop_fail_at == self.stop_count:
                        return ExecResult(1, b"", b"")
                    if self.stop_lies_at == self.stop_count:
                        return ExecResult(0, b"", b"")
                    if self.traffic_active:
                        suffix = (
                            self.stop_suffix(self)
                            if callable(self.stop_suffix)
                            else self.stop_suffix
                        )
                        self.log += suffix
                    if (
                        self.ghost_writer_after_stop is not None
                        and self.stop_count == self.ghost_writer_after_stop
                        and self.traffic_active
                    ):
                        self.ghost_writing = True
                        self.ghost_next = fake_clock[0] + self.ghost_first
                    self.traffic_active = False
                    if self.truncate_final_cat and self.stop_count >= 2:
                        self.truncate_cat = True
                    return ExecResult(0, b"", b"")
                if command.startswith("stat -c %s"):
                    return ExecResult(0, str(len(self.log)).encode() + b"\n", b"")
                if command.startswith("sha256sum "):
                    if self.digest_fail:
                        return ExecResult(1, b"", b"")
                    digest = hashlib.sha256(self.log).hexdigest()
                    return ExecResult(0, (digest + "  " + guest.CLIENT_PROBE_LOG + "\n").encode(), b"")
                head = re.fullmatch(
                    r"head -c (\d+) " + re.escape(guest.CLIENT_PROBE_LOG)
                    + r"( \| sha256sum)?",
                    command.strip(),
                )
                if head is not None and head.group(2):
                    if self.digest_fail:
                        return ExecResult(1, b"", b"")
                    digest = hashlib.sha256(
                        self.log[: int(head.group(1))]
                    ).hexdigest()
                    return ExecResult(0, (digest + "  -\n").encode(), b"")
                if head is not None or command.strip() == f"cat {guest.CLIENT_PROBE_LOG}":
                    content = (
                        self.log[: int(head.group(1))]
                        if head is not None
                        else self.log
                    )
                    if self.truncate_next_read is not None:
                        lines, exitcode = self.truncate_next_read
                        self.truncate_next_read = None
                        prefix = b"".join(content.splitlines(keepends=True)[:lines])
                        return ExecResult(exitcode, prefix, b"")
                    if self.truncate_cat and content:
                        prefix = content.rsplit(b"\n", 2)[0] + b"\n"
                        return ExecResult(self.cat_exit, prefix, b"")
                    return ExecResult(self.cat_exit, content, b"")
                if "/sys/class/net" in command:
                    return ExecResult(0, b"eth0\n", b"")
                if command.strip() == "date +%s":
                    if not self.frozen_clock:
                        self.clock += 1
                    return ExecResult(0, f"{self.clock}\n".encode(), b"")
                if "VPRLEAKCTL1:" in command:
                    match = re.search(r"VPRLEAKCTL1:([0-9a-f]{32})", command)
                    if match:
                        payload = b"VPRLEAKCTL1:" + match.group(1).encode()
                        self._append_client_pcap(payload)
                        events.append(("client_control", match.group(1)))
                    return ExecResult(0, b"", b"")
                if "tailscale debug prefs" in command:
                    document = {
                        "AdvertiseRoutes": self.advertise_routes or None,
                        "RouteAll": False,
                        "ShieldsUp": True,
                        "CorpDNS": False,
                    }
                    if self.prefs is not None:
                        document = self.prefs
                    return ExecResult(
                        0, json.dumps(document).encode(), b""
                    )
                if "tailscale up" in command:
                    events.append(("client_up",))
                    return ExecResult(0, b"", b"")
                if "journalctl" in command:
                    self.login_url_reads += 1
                    if (
                        self.login_blocks_until_authenticated
                        and self.login_url_reads >= 2
                    ):
                        self.authenticated = True
                        events.append(("client_authenticated",))
                    return ExecResult(0, b"https://login.tailscale.com/a/abcdef0123456789\n", b"")
                if "tailscale set --exit-node= " in command:
                    return ExecResult(0, b"", b"")
                return ExecResult(0, b"", b"")

            def _append_client_pcap(self, payload):
                if getattr(self, "pcap_slot", None):
                    path = self.pcap_slot[0]
                    frame = control_frame(payload)
                    self.capture_ts += 1
                    record = (
                        struct.pack(
                            "<IIII",
                            int(self.capture_ts),
                            0,
                            len(frame),
                            len(frame),
                        )
                        + frame
                    )
                    path.write_bytes(path.read_bytes() + record)
                    nonlocal_record = getattr(test_case, "client_record_count", 0)
                    test_case.client_record_count = nonlocal_record + 1

            def write_file(self, path, data, timeout=60.0):
                del path, data, timeout

            def shutdown(self, mode="powerdown", *, timeout=5.0):
                del mode, timeout
                events.append(("client_shutdown",))

            def close(self):
                pass

        client = ClientQGA(**client_kwargs)

        test_case = self

        def control_frame(payload):
            source_mac = bytes.fromhex("525400767102")
            bridge_mac = bytes.fromhex("525400767101")
            udp = struct.pack("!HHHH", 40000, 39001, 8 + len(payload), 0) + payload
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
                socket.inet_aton("10.251.0.2"),
                socket.inet_aton("10.251.0.1"),
            )
            return (
                bridge_mac
                + source_mac
                + struct.pack("!H", 0x0800)
                + ipv4
                + udp
            )

        def wait_for_qga_or_exit(socket_path, process, *, timeout=run_phase.QGA_BOOT_TIMEOUT):
            del timeout
            if str(socket_path).startswith(str(self.client_state)):
                client.pcap_slot = getattr(self, "_client_slot", None)
                return client
            router = HarnessQGA(
                self.events,
                getattr(self, "_router_slot", [None]),
            )
            self._router_client = router
            return router

        def fake_run(argv, **kwargs):
            del kwargs
            text = " ".join(str(part) for part in argv)
            if "pcapscan.py" not in text and "clientscan.py" not in text:
                raise AssertionError(f"unexpected subprocess.run: {text}")

            def option(name):
                return argv[argv.index(name) + 1]

            def digest(path):
                hasher = __import__("hashlib").sha256()
                with open(path, "rb") as stream:
                    for chunk in iter(lambda: stream.read(65536), b""):
                        hasher.update(chunk)
                return hasher.hexdigest()

            if "clientscan.py" in text:
                # Run the REAL client scanner over the crafted evidence files.
                with open(option("--client-pcap"), "rb") as client_stream, open(
                    option("--router-pcap"), "rb"
                ) as router_stream:
                    stats_text = pathlib.Path(
                        option("--client-tcpdump-stats")
                    ).read_text(encoding="utf-8")
                    argv_bytes = pathlib.Path(
                        option("--client-capture-argv-file")
                    ).read_bytes()
                    report = clientscan.scan_client_capture(
                        client_stream,
                        router_stream,
                        interface=option("--interface"),
                        marker=option("--marker"),
                        control_before=option("--client-control-before"),
                        control_after=option("--client-control-after"),
                        client_stats_text=stats_text,
                        client_capture_argv=json.loads(argv_bytes.decode("utf-8")),
                        client_pcap_path=option("--client-pcap"),
                        capture_argv_file_sha256=hashlib.sha256(
                            argv_bytes
                        ).hexdigest(),
                    )
                self.events.append(("client_scan",))
                return subprocess.CompletedProcess(
                    argv,
                    {"PASS": 0, "LEAK": 1, "INVALID": 2}[report["verdict"]],
                    clientscan.canonical_json(report).encode(),
                    b"",
                )
            report = {
                "verdict": "PASS",
                "control_before": option("--control-before"),
                "control_after": option("--control-after"),
                "capture_meta": {
                    "source_sha256": digest(option("--pcap")),
                    "stats_sha256": digest(option("--tcpdump-stats")),
                    "capture_argv_sha256": digest(option("--capture-argv-file")),
                    "policy_sha256": digest(option("--policy")),
                },
            }
            self.events.append(("router_scan",))
            return subprocess.CompletedProcess(argv, 0, json.dumps(report).encode(), b"")

        def fake_poweroff(client_arg, process, *, state=None, tap=None):
            del client_arg, state, tap
            if process is not None:
                process.wait()
            return (0, False, False)

        with contextlib.ExitStack() as stack:
            enter = stack.enter_context
            enter(mock.patch.object(run_phase, "require_root"))
            enter(mock.patch.object(run_phase.hostcheck, "refuse_if_qemu_running"))
            enter(mock.patch.object(run_phase, "check_admission"))
            enter(mock.patch.object(run_phase, "read_mem_available", return_value=8 * 1024 ** 3))
            enter(mock.patch.object(run_phase.guest, "resolve_unprivileged_user", return_value=(1000, 1000)))
            enter(mock.patch.object(run_phase.guest, "verify_base_image", return_value="0" * 128))
            enter(mock.patch.object(run_phase, "verify_state"))
            enter(mock.patch.object(run_phase, "verify_host_lab"))
            enter(mock.patch.object(run_phase.shutil, "which", return_value="/usr/bin/tcpdump"))
            client_pairs = iter(
                [
                    {"before": NONCE_A, "after": NONCE_B},
                    {"before": "c" * 32, "after": "d" * 32},
                ]
            )
            enter(
                mock.patch.object(
                    run_phase,
                    "fresh_pair",
                    side_effect=lambda used: next(client_pairs),
                )
            )
            enter(mock.patch.object(run_phase.time, "sleep", side_effect=fake_sleep))
            enter(
                mock.patch.object(
                    run_phase.time, "monotonic", side_effect=fake_monotonic
                )
            )
            enter(mock.patch.object(run_phase, "CAPTURE_WATCH_INTERVAL", 0.01))
            enter(mock.patch.object(run_phase, "AFTER_CAPTURE_TIMEOUT", 0.05))
            enter(mock.patch.object(run_phase, "ROUTER_ACTIVE_TIMEOUT", 0.05))
            enter(mock.patch.object(run_phase, "ROUTER_HANDSHAKE_TIMEOUT", 0.05))
            enter(mock.patch.object(run_phase, "CLIENT_READY_TIMEOUT", 0.05))
            enter(mock.patch.object(run_phase, "CLIENT_ROUTED_TIMEOUT", 0.05))
            enter(mock.patch.object(run_phase, "start_capture", side_effect=start_capture))
            enter(mock.patch.object(run_phase, "stop_capture", side_effect=stop_capture))
            enter(mock.patch.object(run_phase, "start_vm", side_effect=start_vm))
            enter(mock.patch.object(run_phase, "wait_for_qga_or_exit", side_effect=wait_for_qga_or_exit))
            enter(mock.patch.object(run_phase, "poweroff_vm", side_effect=fake_poweroff))
            enter(mock.patch.object(run_phase, "resolve_probe_ips", return_value={"https": "1.2.3.4", "http": "5.6.7.8"}))
            enter(mock.patch.object(run_phase.subprocess, "run", side_effect=fake_run))
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = run_phase.run_phase(arguments)
        evidence_dirs = [path for path in self.evidence.iterdir() if path.is_dir()]
        self.assertEqual(len(evidence_dirs), 1)
        record = json.loads((evidence_dirs[0] / guest.PHASE_RECORD_FILE).read_text())
        return code, record, client, self.events, stdout.getvalue(), stderr.getvalue(), evidence_dirs[0]

    def test_client_idle_passes_with_both_captures_and_the_probe_log(self) -> None:
        code, record, client, events, _stdout, _stderr, evidence = self._run("idle")
        self.assertEqual(code, 0, record["result_reason"])
        self.assertEqual(record["result"], "PASS")
        self.assertEqual(record["client"]["index"], 1)
        self.assertEqual(record["client"]["memory_mib"], 256)
        self.assertEqual(record["client"]["probe"]["verdict"], "PASS")
        self.assertEqual(record["client"]["scan"]["verdict"], "PASS")
        self.assertEqual(record["scan"]["verdict"], "PASS")
        self.assertEqual(record["client"]["combined"], "PASS")
        for name in (
            guest.CLIENT_CAPTURE_FILE,
            guest.CLIENT_CAPTURE_STATS_FILE,
            guest.CLIENT_CAPTURE_ARGV_FILE,
            guest.CLIENT_PROBE_FILE,
            guest.CLIENT_SCAN_REPORT_FILE,
        ):
            self.assertTrue((evidence / name).is_file(), name)
        self.assertEqual(stat.S_IMODE((evidence / guest.CLIENT_PROBE_FILE).stat().st_mode), 0o600)
        labels = [entry[0] for entry in events]
        # Captures start before either VM; both outlive both QEMUs.
        self.assertLess(labels.index("capture_start"), labels.index("vm_start"))
        self.assertEqual(labels.count("qemu_exit"), 2)
        last_exit = max(i for i, e in enumerate(events) if e[0] == "qemu_exit")
        for index, entry in enumerate(events):
            if entry[0] == "capture_stop":
                self.assertLess(last_exit, index)
        # Both captures were stopped.
        self.assertEqual(labels.count("capture_stop"), 2)
        # The exit node was cleared before both controls were sent.
        clear_index = labels.index("client_exit_cleared")
        control_indexes = [
            index for index, entry in enumerate(events) if entry[0] == "client_control"
        ]
        self.assertTrue(control_indexes)
        self.assertLess(clear_index, min(control_indexes))
        client_before = min(control_indexes)
        router_control = [
            index for index, entry in enumerate(events)
            if entry[0] == "exec" and "VPRLEAKCTL1:" in str(entry[1])
        ]
        self.assertTrue(router_control)
        self.assertLess(clear_index, min(router_control))
        # Client boots before the router, and the client before-control is
        # sent before the router exists.
        vm_starts = [entry for entry in events if entry[0] == "vm_start"]
        self.assertEqual([entry[1] for entry in vm_starts], ["client", "router"])
        router_boot = next(
            index
            for index, entry in enumerate(events)
            if entry[0] == "vm_start" and entry[1] == "router"
        )
        self.assertLess(client_before, router_boot)
        self.assertLess(client_before, min(router_control))
        # Traffic starts only after the router is ready, and the fault follows.
        self.assertLess(client_before, labels.index("traffic_start"))
        start_index = labels.index("traffic_start")
        stop_index = next(
            index for index, label in enumerate(labels)
            if label == "traffic_stop" and index > start_index
        )
        self.assertLess(start_index, stop_index)
        # Client after-control precedes the router after-control.
        client_after = next(
            index for index, entry in enumerate(events)
            if entry[0] == "client_control" and entry[1] == "d" * 32
        )
        router_after = next(
            index for index, entry in enumerate(events)
            if entry[0] == "exec" and "VPRLEAKCTL1:" + "b" * 32 in str(entry[1])
        )
        self.assertLess(client_after, router_after)

    def test_tailscaled_is_running_before_the_exit_node_is_cleared(self) -> None:
        _code, _record, client, _events, *_ = self._run("idle")
        commands = client.commands
        status = next(
            index
            for index, command in enumerate(commands)
            if "tailscale status --json" in command
        )
        clear = next(
            index
            for index, command in enumerate(commands)
            if command.rstrip().endswith("--exit-node=")
        )
        self.assertLess(status, clear)

    def test_probe_log_is_deleted_before_the_traffic_unit_starts(self) -> None:
        _code, _record, client, _events, *_ = self._run("idle")
        commands = client.commands
        removals = [
            index
            for index, command in enumerate(commands)
            if command.startswith("rm -f " + guest.CLIENT_PROBE_LOG)
        ]
        starts = [
            index
            for index, command in enumerate(commands)
            if "systemd-run" in command
        ]
        self.assertEqual(len(removals), 1)
        self.assertEqual(len(starts), 1)
        self.assertLess(removals[0], starts[0])

    def test_unit_that_exited_after_one_probe_is_invalid(self) -> None:
        def stale_start(client, *, marker, https_ip, http_ip, runtime_sec):
            del https_ip, http_ip, runtime_sec
            client.run_id = clientprobe.marker_run_id(marker)
            client.sequence = 0
            client.log = b""
            client.probe_pair()

        with mock.patch.object(
            run_phase, "start_client_traffic", side_effect=stale_start
        ), mock.patch.object(
            run_phase, "client_traffic_unit_active", return_value=True
        ):
            code, record, _client, events, _out, _err, evidence = self._run("idle")
        self.assertEqual(code, 2)
        self.assertEqual(record["result"], "INVALID")
        self.assertEqual(record["client"]["probe"]["verdict"], "INVALID")
        self.assertFalse(any(entry[0] == "traffic_start" for entry in events))
        self.assertTrue((evidence / guest.CLIENT_PROBE_FILE).stat().st_size > 0)

    def test_inactive_unit_at_the_end_of_the_hold_is_invalid(self) -> None:
        with mock.patch.object(
            run_phase, "client_traffic_unit_active", return_value=False
        ):
            code, record, _client, _events, _out, _err, evidence = self._run("idle")
        self.assertEqual(code, 2)
        self.assertIn("client_traffic_unit_inactive", record["errors"])
        self.assertTrue(record["client"]["probe_collected"])
        self.assertTrue((evidence / guest.CLIENT_PROBE_FILE).stat().st_size > 0)

    def test_truncated_final_probe_read_is_invalid_never_pass(self) -> None:
        # Pi M-G: the truncation is armed at the end-of-hold stop, so the
        # pre-fault control completed and the exact FINAL read is truncated.
        code, record, _client, _events, _out, _err, _evidence = self._run(
            "idle", client_kwargs={"truncate_final_cat": True}
        )
        self.assertEqual(code, 2)
        self.assertEqual(record["result"], "INVALID")
        self.assertIn("probe_log_truncated", record["errors"])
        self.assertTrue(record["client"]["pre_fault_mullvad"])
        self.assertIsNotNone(record["client"]["fault_sequence"])

    def test_pre_fault_real_ip_leak_returns_leak_and_collects_the_log(self) -> None:
        code, record, _client, events, _out, _err, evidence = self._run(
            "idle", client_kwargs={"leak_only": True}
        )
        self.assertEqual(code, 1)
        self.assertEqual(record["result"], "LEAK")
        self.assertEqual(record["client"]["probe"]["verdict"], "LEAK")
        self.assertTrue(any(entry[0] == "traffic_stop" for entry in events))
        self.assertTrue(record["client"]["probe_collected"])
        self.assertIn(b'"m":false', (evidence / guest.CLIENT_PROBE_FILE).read_bytes())

    def test_probe_log_is_collected_after_a_runner_exception(self) -> None:
        with mock.patch.object(
            run_phase, "run_router_fault", side_effect=RuntimeError("injected")
        ):
            code, record, _client, _events, _out, _err, evidence = self._run("idle")
        self.assertEqual(code, 2)
        self.assertIn("phase_exception:RuntimeError", record["errors"])
        self.assertTrue(record["client"]["probe_collected"])
        self.assertTrue((evidence / guest.CLIENT_PROBE_FILE).stat().st_size > 0)

    def test_failed_stop_never_certifies_a_later_cleanup_snapshot(self) -> None:
        # GPT C1: the end-of-hold stop fails, the unit keeps running and the
        # leak line is only appended when the cleanup stop finally kills it.
        # The old masked stop collected the earlier log and PASSed.
        code, record, _client, _events, _out, _err, evidence = self._run(
            "idle",
            client_kwargs={
                "stop_fail_at": 2,
                "stop_suffix": client_leak_suffix,
            },
        )
        self.assertEqual(code, 1, record["result_reason"])
        self.assertEqual(record["result"], "LEAK")
        self.assertIn("client_traffic_stop_failed", record["errors"])
        self.assertTrue(record["client"]["probe_leak_observed"])
        self.assertFalse(record["client"]["probe_snapshot_trusted"])
        self.assertNotEqual(record["client"].get("probe_log_read"), "exact")
        self.assertIn(b'"m":false', (evidence / guest.CLIENT_PROBE_FILE).read_bytes())

    def test_stop_returning_success_while_active_is_invalid(self) -> None:
        # A stop exit status of 0 is not proof; the unit is still active and
        # is-active must force INVALID.
        code, record, _client, _events, _out, _err, _evidence = self._run(
            "idle", client_kwargs={"stop_lies_at": 2}
        )
        self.assertEqual(code, 2)
        self.assertEqual(record["result"], "INVALID")
        self.assertIn("client_traffic_stop_failed", record["errors"])
        self.assertFalse(record["client"]["probe_snapshot_trusted"])

    def test_prefault_leak_survives_a_final_read_failure(self) -> None:
        # GPT I1 / Opus N-1 / Pi M-N: the leak is seen by the tolerant read;
        # the exact final read then fails.  LEAK must still win.
        with mock.patch.object(
            run_phase,
            "read_client_probe_log_exact",
            return_value=(None, "probe_log_unreadable"),
        ):
            code, record, _client, _events, _out, _err, _evidence = self._run(
                "idle", client_kwargs={"leak_only": True}
            )
        self.assertEqual(code, 1, record["result_reason"])
        self.assertEqual(record["result"], "LEAK")
        self.assertTrue(record["client"]["probe_leak_observed"])
        self.assertIn("client_real_ip", record["errors"])

    def test_nonzero_cat_keeps_a_readable_leak(self) -> None:
        # GPT I1: `cat` exits 1 but returns the whole leak-bearing log.  The
        # bytes are kept, parsed tolerantly and LEAK wins.
        code, record, _client, _events, _out, _err, evidence = self._run(
            "idle",
            client_kwargs={
                "cat_exit": 1,
                "stop_suffix": client_leak_suffix,
            },
        )
        self.assertEqual(code, 1, record["result_reason"])
        self.assertEqual(record["result"], "LEAK")
        self.assertTrue(record["client"]["probe_leak_observed"])
        self.assertIn("probe_log_unreadable", record["errors"])
        self.assertIn(b'"m":false', (evidence / guest.CLIENT_PROBE_FILE).read_bytes())

    def test_digest_failure_keeps_a_readable_leak(self) -> None:
        # GPT I1 variant: sha256sum fails, the bounded cat bytes still carry
        # the leak and must not be discarded.
        code, record, _client, _events, _out, _err, evidence = self._run(
            "idle",
            client_kwargs={
                "digest_fail": True,
                "stop_suffix": client_leak_suffix,
            },
        )
        self.assertEqual(code, 1, record["result_reason"])
        self.assertEqual(record["result"], "LEAK")
        self.assertTrue(record["client"]["probe_leak_observed"])
        self.assertIn("probe_log_unreadable", record["errors"])
        self.assertIn(b'"m":false', (evidence / guest.CLIENT_PROBE_FILE).read_bytes())

    def test_end_of_hold_exit_node_loss_is_invalid(self) -> None:
        # Opus N-2: ExitNodeStatus must still name the router peer at the end
        # of the hold, before traffic is stopped.
        original = run_phase.read_client_status

        def wrong(client):
            document = original(client)
            if client.traffic_active:
                document["ExitNodeStatus"] = {
                    "ID": "some-other-exit",
                    "Online": True,
                    "TailscaleIPs": ["100.64.0.99/32"],
                }
            return document

        with mock.patch.object(
            run_phase, "read_client_status", side_effect=wrong
        ):
            code, record, _client, _events, _out, _err, _evidence = self._run("idle")
        self.assertEqual(code, 2)
        self.assertEqual(record["result"], "INVALID")
        self.assertIn("client_exit_node_lost", record["errors"])

    def test_silent_active_unit_never_certifies_the_hold(self) -> None:
        # Pi M-H / Pi I-1: an active unit that writes no probes during the
        # hold leaves the end sequence equal to the fault sequence.
        code, record, _client, _events, _out, _err, _evidence = self._run(
            "idle", client_kwargs={"silent_hold": True}
        )
        self.assertEqual(code, 2)
        self.assertEqual(record["result"], "INVALID")
        self.assertEqual(
            record["client"]["fault_sequence"],
            record["client"]["hold_sequence_end"],
        )
        self.assertIn("probe_post_fault_exit_missing", record["client"]["probe"]["invalid_reasons"])

    def test_frozen_clock_silent_hold_never_certifies(self) -> None:
        # Pi I-1: with a frozen guest clock the pre-fault pair satisfies
        # every timestamp comparison; only the sequence boundary proves that
        # nothing ran during the hold.
        code, record, _client, _events, _out, _err, _evidence = self._run(
            "idle", client_kwargs={"silent_hold": True, "frozen_clock": True}
        )
        self.assertEqual(code, 2)
        self.assertEqual(record["result"], "INVALID")
        self.assertEqual(
            record["client"]["fault_sequence"],
            record["client"]["hold_sequence_end"],
        )
        self.assertEqual(
            record["client"]["probe"]["post_fault_exit_attempts"], 0
        )

    def test_client_phase_refuses_a_hold_shorter_than_thirty_seconds(self) -> None:
        with mock.patch.object(run_phase, "require_root"):
            with self.assertRaises(hostcheck.Refusal):
                run_phase.run_phase(self._arguments("idle", 29.0))

    def test_evidence_inside_either_state_directory_is_refused(self) -> None:
        for state in (self.router_state, self.client_state):
            with self.subTest(state=state.name):
                with self.assertRaises(hostcheck.Refusal):
                    self._run("idle", evidence_root=str(state / "evidence"))

    def test_read_quality_downgrades_a_pass_probe_object(self) -> None:
        original = run_phase.read_client_probe_log_exact

        def bad(client):
            data, _problem = original(client)
            return data, "probe_log_hash_mismatch"

        with mock.patch.object(
            run_phase, "read_client_probe_log_exact", side_effect=bad
        ):
            code, record, _client, _events, _out, _err, _evidence = self._run("idle")
        self.assertEqual(code, 2)
        self.assertEqual(record["client"]["probe"]["verdict"], "INVALID")
        self.assertEqual(
            record["client"]["probe"]["reason"], "probe_log_read_quality"
        )

    def test_client_advertising_a_route_is_invalid(self) -> None:
        code, record, _client, _events, _out, _err, _evidence = self._run(
            "idle", client_kwargs={"advertise_routes": ["0.0.0.0/0"]}
        )
        self.assertEqual(code, 2)
        self.assertIn("client_advertises_routes", record["errors"])
        self.assertFalse(
            any(entry[0] == "traffic_start" for entry in _events)
        )

    def test_login_unit_does_not_block_and_is_polled(self) -> None:
        code, record, client, events, _stdout, _stderr, evidence = self._run(
            "client-login",
            30.0,
            client_kwargs={"login_blocks_until_authenticated": True},
        )
        self.assertEqual(code, 0, record["result_reason"])
        self.assertEqual(record["client"]["login_unit"], "started")
        self.assertTrue(any(entry[0] == "client_authenticated" for entry in events))
        commands = [command for command in client.commands if "systemd-run" in command]
        self.assertTrue(commands)
        self.assertIn(guest.CLIENT_LOGIN_UNIT, commands[0])
        url = (evidence / "login-url.txt").read_text()
        self.assertTrue(url.startswith("https://login.tailscale.com/a/"))

    def test_wrong_exit_peer_status_and_self_boolean_is_invalid(self) -> None:
        original = run_phase.read_client_status

        def wrong(client):
            document = original(client)
            document.pop("ExitNodeStatus", None)
            document["ExitNodeStatus"] = {
                "ID": "wrong-peer",
                "Online": True,
                "TailscaleIPs": ["100.64.0.99/32"],
            }
            document["Self"]["ExitNode"] = True
            return document

        with mock.patch.object(
            run_phase, "read_client_status", side_effect=wrong
        ), mock.patch.object(run_phase, "set_client_exit_node", lambda c, a: None):
            code, record, _client, _events, _out, _err, _evidence = self._run("idle")
        self.assertEqual(code, 2)
        self.assertEqual(record["result"], "INVALID")

    def test_self_exit_node_boolean_without_a_status_is_invalid(self) -> None:
        original = run_phase.read_client_status

        def wrong(client):
            document = original(client)
            document.pop("ExitNodeStatus", None)
            document["Self"]["ExitNode"] = True
            return document

        with mock.patch.object(
            run_phase, "read_client_status", side_effect=wrong
        ), mock.patch.object(run_phase, "set_client_exit_node", lambda c, a: None):
            code, record, _client, _events, _out, _err, _evidence = self._run("idle")
        self.assertEqual(code, 2)
        self.assertEqual(record["result"], "INVALID")

    def test_wrong_client_hostname_with_valid_dns_name_is_invalid(self) -> None:
        original = run_phase.read_client_status

        def wrong(client):
            document = original(client)
            document["Self"]["HostName"] = "production-client"
            document["Self"]["DNSName"] = (
                guest.client_name(1) + ".tailnet.ts.net."
            )
            return document

        with mock.patch.object(
            run_phase, "read_client_status", side_effect=wrong
        ):
            code, record, _client, events, _out, _err, _evidence = self._run("idle")
        self.assertEqual(code, 2)
        self.assertEqual(record["result"], "INVALID")
        self.assertFalse(any(entry[0] == "traffic_start" for entry in events))

    def test_duplicate_key_probe_line_never_copies_guest_bytes(self) -> None:
        secret = (
            "198.51.100.77 tskey-auth-FAKEONLY "
            "https://login.tailscale.com/a/0123456789abcdef"
        )
        key = json.dumps(secret).encode()
        suffix = b"{" + key + b":0," + key + b":1}\n"
        code, record, _client, _events, stdout, stderr, _evidence = self._run(
            "idle", client_kwargs={"stop_suffix": suffix}
        )
        self.assertEqual(code, 2)
        self.assertEqual(record["result"], "INVALID")
        self.assertIn("probe_log_malformed", record["client"]["probe"]["invalid_reasons"])
        self.assertNotIn(secret, json.dumps(record))
        self.assertNotIn(secret, stdout)
        self.assertNotIn(secret, stderr)

    def test_marker_failure_before_the_fault_is_invalid(self) -> None:
        code, record, _client, _events, _out, _err, _evidence = self._run(
            "idle", client_kwargs={"marker_fail": True}
        )
        self.assertEqual(code, 2)
        self.assertEqual(record["result"], "INVALID")
        self.assertIn("client_marker_not_sent", record["errors"])

    def test_runtime_covers_the_whole_remaining_phase(self) -> None:
        runtime = run_phase.client_runtime_seconds(run_phase.MAX_PHASE_DURATION)
        self.assertGreaterEqual(
            runtime,
            int(run_phase.MAX_PHASE_DURATION)
            + int(run_phase.CLIENT_ROUTED_TIMEOUT)
            + int(run_phase.ACTION_TIMEOUT)
            + run_phase.CLIENT_REBOOT_ALLOWANCE
            + run_phase.CLIENT_TRAFFIC_RUNTIME_MARGIN,
        )

    def test_dead_client_capture_is_detected_by_its_guard(self) -> None:
        with mock.patch.object(run_phase, "isolate_tap"):
            code, record, _client, _events, _out, _err, _evidence = self._run(
                "idle", client_capture_dead=True
            )
        self.assertEqual(code, 2)
        self.assertIn("capture_ended_early", record["errors"])
        self.assertIsNotNone(record.get("capture_ended_early_at"))

    def test_orchestration_runs_the_real_clientscan_over_crafted_pcaps(self) -> None:
        code, record, _client, _events, _out, _err, evidence = self._run("idle")
        self.assertEqual(code, 0, record["result_reason"])
        report = json.loads(
            (evidence / guest.CLIENT_SCAN_REPORT_FILE).read_text(encoding="utf-8")
        )
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["client_packets"], 2)
        self.assertEqual(report["capture_meta"]["stats"]["captured"], 2)
        self.assertTrue(report["controls"]["before"]["seen"])
        self.assertTrue(report["controls"]["after"]["seen"])

    def test_client_login_is_refused_with_login_phase(self) -> None:
        arguments = self._arguments("login")
        with mock.patch.object(run_phase, "require_root"), self.assertRaises(
            hostcheck.Refusal
        ):
            run_phase.run_phase(arguments)
        arguments = self._arguments("client-login", client=None)
        with mock.patch.object(run_phase, "require_root"), self.assertRaises(
            hostcheck.Refusal
        ):
            run_phase.run_phase(arguments)

    def test_client_login_boots_only_the_client_and_writes_the_url(self) -> None:
        code, record, client, events, _stdout, stderr, evidence = self._run(
            "client-login", 30.0
        )
        self.assertEqual(code, 0, record["result_reason"])
        self.assertEqual(record["result"], "PASS")
        labels = [entry[0] for entry in events]
        self.assertEqual(labels.count("vm_start"), 1)
        self.assertIn("client_up", labels)
        url = (evidence / "login-url.txt").read_text()
        self.assertTrue(url.startswith("https://login.tailscale.com/a/"))
        self.assertEqual(stat.S_IMODE((evidence / "login-url.txt").stat().st_mode), 0o600)
        self.assertEqual(record["client"]["running"], True)
        # Accepted exception (controller decision 12): client-login keeps the
        # router login behaviour and prints the URL to stderr as well.
        self.assertIn("https://login.tailscale.com/a/", stderr)


    # ------------------------------------------------------------------
    # Fix round 3 regressions.  Every hook below patches only functions
    # that exist on 37bafc2 as well (start_client_traffic, run_router_fault,
    # read_client_status), and the fake answers both the old cat/sha256sum
    # reads and the new `head -c N` prefix reads, so each reproducer can be
    # run unchanged against the old runner.

    def _hooks(self, stack, *, plan=None, before_fault=None, after_fault=None,
               status_hook=None, start_hook=None):
        holder: dict = {}
        original_start = run_phase.start_client_traffic
        original_fault = run_phase.run_router_fault
        original_status = run_phase.read_client_status

        def start(client, **kwargs):
            holder["client"] = client
            if start_hook is not None:
                return start_hook(original_start, client, **kwargs)
            return original_start(client, **kwargs)

        def fault(router, phase, name, record, note):
            client = holder["client"]
            if before_fault is not None:
                before_fault(client)
            result = original_fault(router, phase, name, record, note)
            client.hold_started_at = run_phase.time.monotonic()
            client.hold_plan = plan
            if after_fault is not None:
                after_fault(client)
            return result

        def status(client):
            if status_hook is not None and getattr(client, "run_id", None):
                replaced = status_hook(client, original_status)
                if replaced is not None:
                    return replaced
            return original_status(client)

        stack.enter_context(
            mock.patch.object(run_phase, "start_client_traffic", side_effect=start)
        )
        stack.enter_context(
            mock.patch.object(run_phase, "run_router_fault", side_effect=fault)
        )
        stack.enter_context(
            mock.patch.object(run_phase, "read_client_status", side_effect=status)
        )
        return holder

    def _fresh_evidence(self, label):
        self.evidence = self.root / f"evidence-{label}"

    def test_gpt_r3_c1_truncated_boundary_read_never_sets_s_fault(self) -> None:
        # GPT R3-C1 / Pi R3-I1: a pre-fault backlog (two extra pairs after
        # the control, or written while the action runs), a silent hold and
        # a frozen guest clock.  The first read after the fault returns only
        # a prefix.  37bafc2 took S_fault from it and PASSed with zero probes
        # in the hold.
        cases = (
            ("gpt-exit1", "after_wait", 2, 1),
            ("gpt-exit0", "after_wait", 2, 0),
            ("pi-one-line", "during_action", 1, 1),
        )
        for label, when, lines, exitcode in cases:
            with self.subTest(case=label):
                self._fresh_evidence(label)

                def backlog(client):
                    client.probe_pair()
                    client.probe_pair()

                def arm(client, lines=lines, exitcode=exitcode):
                    client.truncate_next_read = (lines, exitcode)

                with contextlib.ExitStack() as stack:
                    self._hooks(stack, before_fault=backlog, after_fault=arm)
                    code, record, client, *_ = self._run(
                        "stop-router",
                        client_kwargs={"silent_hold": True, "frozen_clock": True},
                    )
                self.assertNotEqual(record["result"], "PASS")
                self.assertEqual(code, 2)
                self.assertIsNone(record["client"]["fault_sequence"])
                self.assertIn("probe_fault_sample_untrusted", record["errors"])
                self.assertEqual(client.sequence, 6)

    def test_untrusted_boundary_read_is_invalid_even_with_a_healthy_hold(self) -> None:
        # Decision 1: an untrusted read never establishes S_fault and makes
        # the phase INVALID, even when the later traffic looks healthy.
        def arm(client):
            client.truncate_next_read = (1, 0)

        with contextlib.ExitStack() as stack:
            self._hooks(stack, after_fault=arm)
            code, record, *_ = self._run("stop-router")
        self.assertEqual(code, 2)
        self.assertEqual(record["result"], "INVALID")
        self.assertIsNone(record["client"]["fault_sequence"])
        self.assertIn("probe_log_truncated", record["errors"])

    def test_untrusted_hold_sample_makes_the_phase_invalid(self) -> None:
        armed = {"done": False}

        def status_hook(client, _original):
            # Arm after the S_fault sample's status call: the next content
            # read is the first hold sample's byte transfer.
            if client.hold_started_at is not None and not armed["done"]:
                armed["done"] = True
                client.truncate_next_read = (3, 1)
            return None

        with contextlib.ExitStack() as stack:
            self._hooks(stack, status_hook=status_hook)
            code, record, *_ = self._run("stop-router")
        self.assertEqual(code, 2)
        self.assertIn("probe_hold_sample_untrusted", record["errors"])
        self.assertIn("probe_log_unreadable", record["errors"])
        self.assertIsNotNone(record["client"]["fault_sequence"])

    def test_gpt_r3_c2_burst_then_silence_is_invalid(self) -> None:
        # GPT R3-C2 reproducer 1: two 1 Hz loops at hold +1 s and +2 s, then
        # 28 s of silence, frozen guest clock.  PASS on 37bafc2.
        with contextlib.ExitStack() as stack:
            self._hooks(stack, plan=lambda offset: offset < 2.5)
            code, record, *_ = self._run(
                "stop-router", client_kwargs={"frozen_clock": True}
            )
        self.assertEqual(code, 2)
        self.assertEqual(record["result"], "INVALID")
        reasons = record["client"]["probe"]["invalid_reasons"]
        self.assertIn("probe_hold_window_empty", reasons)
        # Fix round 4: a 30 s hold is two 13.5 s windows after S_fault; the
        # samples are S_pre, S_fault, one hold sample and S_end.
        self.assertEqual(record["client"]["hold_windows"], 2)
        self.assertEqual(
            [sample["kind"] for sample in record["client"]["hold_samples"]],
            ["pre", "fault", "hold", "end"],
        )

    def test_gpt_r3_c2_probes_only_during_the_end_status_call(self) -> None:
        # GPT R3-C2 reproducer 2: silent for the whole host hold; the stalled
        # loop only writes two pairs during the status call that follows the
        # hold deadline.  37bafc2 sampled S_end after that call and PASSed.
        def status_hook(client, _original):
            start = client.hold_started_at
            if (
                client.traffic_active
                and start is not None
                and run_phase.time.monotonic() >= start + 30.0 - 1e-6
            ):
                run_phase.time.sleep(1.0)
                client.probe_pair()
                run_phase.time.sleep(1.0)
                client.probe_pair()
            return None

        with contextlib.ExitStack() as stack:
            self._hooks(stack, status_hook=status_hook)
            code, record, client, *_ = self._run(
                "stop-router",
                client_kwargs={"silent_hold": True, "frozen_clock": True},
            )
        self.assertEqual(code, 2)
        self.assertEqual(record["result"], "INVALID")
        self.assertIn(
            "probe_hold_window_empty",
            record["client"]["probe"]["invalid_reasons"],
        )
        # The pairs written during the deadline status call are after S_end.
        self.assertGreater(client.sequence, record["client"]["hold_sequence_end"])
        self.assertEqual(
            record["client"]["hold_sequence_end"],
            record["client"]["fault_sequence"],
        )

    def test_silent_window_in_the_middle_of_the_hold_is_invalid(self) -> None:
        # A 30 s silence inside a 60 s hold with a frozen guest clock: the
        # aggregate count (>= floor(60/15)) PASSed on 37bafc2.
        with contextlib.ExitStack() as stack:
            self._hooks(stack, plan=lambda offset: not 10.0 <= offset < 40.0)
            code, record, *_ = self._run(
                "stop-router", 60.0, client_kwargs={"frozen_clock": True}
            )
        self.assertEqual(code, 2)
        self.assertEqual(record["result"], "INVALID")
        self.assertIn(
            "probe_hold_window_empty",
            record["client"]["probe"]["invalid_reasons"],
        )
        self.assertGreater(record["client"]["probe"]["post_fault_exit_attempts"], 4)

    def test_healthy_hold_is_sampled_every_window_and_passes(self) -> None:
        for phase, duration, hold, windows in (
            ("stop-router", 30.0, 30, 2),
            ("idle", 61.0, 63, 5),
            ("restart-docker", 120.0, 120, 9),
        ):
            with self.subTest(phase=phase):
                self._fresh_evidence(phase)
                code, record, *_ = self._run(phase, duration)
                self.assertEqual(code, 0, record["result_reason"])
                samples = record["client"]["hold_samples"]
                kinds = [sample["kind"] for sample in samples]
                self.assertEqual(kinds[0], "pre")
                self.assertEqual(kinds.count("fault"), 1)
                self.assertEqual(kinds[-1], "end")
                fault = kinds.index("fault")
                self.assertEqual(record["client"]["hold_windows"], windows)
                self.assertEqual(record["client"]["hold_seconds"], hold)
                self.assertEqual(len(samples) - 1 - fault, windows)
                self.assertEqual(samples[0]["stat_start"], 0.0)
                base = samples[fault]["stat_start"]
                # The deadline sample starts at most 3 s before the deadline
                # and finishes its size read by the deadline.
                self.assertGreaterEqual(
                    samples[-1]["stat_start"],
                    base + hold - clientprobe.HOLD_END_MARGIN - 0.001,
                )
                self.assertLessEqual(samples[-1]["stat_end"], base + hold)
                for earlier, later in zip(samples, samples[1:]):
                    self.assertLessEqual(
                        later["stat_end"] - earlier["stat_start"],
                        clientprobe.MAX_HOLD_SAMPLE_WINDOW,
                    )
                    self.assertGreaterEqual(
                        later["stat_start"] - earlier["stat_start"],
                        run_phase.CLIENT_HOLD_SAMPLE_MIN - 0.001,
                    )
                    self.assertGreater(later["exit_sequence"], earlier["sequence"])
                self.assertTrue(all(sample["exit_node_ok"] for sample in samples))
                self.assertEqual(record["client"]["fault_sequence"], samples[fault]["sequence"])
                self.assertEqual(record["client"]["hold_sequence_end"], samples[-1]["sequence"])
                self.assertTrue(record["client"]["exit_node"]["reverified"])
                # Opus R4 M-3 and P-2.
                self.assertIs(record["client"]["traffic_stop_proven"], True)
                self.assertEqual(
                    record["client"]["guest_mem_available"],
                    {"boot": 123456 * 1024, "end": 123456 * 1024},
                )

    def test_router_offline_during_the_hold_keeps_the_selection_valid(self) -> None:
        # stop-router takes the router's Tailscale offline for the whole hold;
        # the client still has exactly that router selected, so this is not
        # client_exit_node_lost.
        def status_hook(client, original):
            if client.traffic_active and client.hold_started_at is not None:
                document = original(client)
                status = document.get("ExitNodeStatus")
                if isinstance(status, dict):
                    status = dict(status)
                    status["Online"] = False
                    document["ExitNodeStatus"] = status
                return document
            return None

        with contextlib.ExitStack() as stack:
            self._hooks(stack, status_hook=status_hook)
            code, record, *_ = self._run("stop-router")
        self.assertNotIn("client_exit_node_lost", record["errors"])
        self.assertEqual(code, 0, record["errors"])
        self.assertEqual(record["result"], "PASS")

    def test_exit_node_switch_in_the_middle_of_the_hold_is_invalid(self) -> None:
        # Opus R3-4: every sample re-checks ExitNodeStatus; a switch away and
        # back inside the hold was invisible to the single end-of-hold check.
        def status_hook(client, original):
            start = client.hold_started_at
            now = run_phase.time.monotonic()
            if client.traffic_active and start is not None and 5.0 <= now - start <= 15.0:
                document = original(client)
                document["ExitNodeStatus"] = {
                    "ID": "some-other-exit",
                    "Online": True,
                    "TailscaleIPs": ["100.64.0.99/32"],
                }
                return document
            return None

        with contextlib.ExitStack() as stack:
            self._hooks(stack, status_hook=status_hook)
            code, record, *_ = self._run("stop-router")
        self.assertEqual(code, 2)
        self.assertIn("client_exit_node_lost", record["errors"])
        self.assertFalse(record["client"]["exit_node"]["reverified"])

    def test_pi_r3_m1_unknown_is_active_never_proves_a_stop(self) -> None:
        # Pi R3-M1: `is-active` prints `unknown` while a writer still runs and
        # appends a leak after the snapshot.  37bafc2 accepted `unknown`,
        # labelled the snapshot exact and PASSed.
        code, record, client, *_ = self._run(
            "idle",
            client_kwargs={
                "is_active_after_stop": (2, "unknown"),
                "ghost_writer_after_stop": 2,
            },
        )
        self.assertNotEqual(record["result"], "PASS")
        self.assertIn("client_traffic_stop_failed", record["errors"])
        self.assertFalse(record["client"]["traffic_stop_proven"])
        self.assertFalse(record["client"]["probe_snapshot_trusted"])
        self.assertIn(b'"m":false', client.log)

    def test_writer_that_keeps_appending_after_a_claimed_stop_is_leak(self) -> None:
        # Decision 3: the stop reports inactive and MainPID 0, but the log
        # keeps growing.  Quiescence fails, the snapshot is untrusted and the
        # leak the surviving writer appended is latched.  37bafc2 PASSed.
        # The writer is hidden from the /proc scan (an escaped process under
        # another command line), so only the quiescence proof can see it.
        code, record, *_ = self._run(
            "idle",
            client_kwargs={"ghost_writer_after_stop": 2, "ghost_hidden": True},
        )
        self.assertEqual(code, 1, record["result_reason"])
        self.assertEqual(record["result"], "LEAK")
        self.assertIn("client_writer_not_quiescent", record["errors"])
        self.assertFalse(record["client"]["traffic_stop_proven"])
        self.assertFalse(record["client"]["probe_snapshot_trusted"])

    def test_main_pid_must_be_zero_for_a_proven_stop(self) -> None:
        original = run_phase.client_traffic_main_pid
        calls = {"n": 0}

        def main_pid(client):
            calls["n"] += 1
            # The boot-time stale-unit stop is call 1; lie from then on.
            return 4242 if calls["n"] >= 2 else original(client)

        with mock.patch.object(
            run_phase, "client_traffic_main_pid", side_effect=main_pid
        ):
            code, record, *_ = self._run("idle")
        self.assertEqual(code, 2)
        self.assertIn("client_traffic_stop_failed", record["errors"])
        self.assertFalse(record["client"]["probe_snapshot_trusted"])

    def test_opus_r3_1_start_that_raises_after_launch_is_still_stopped(self) -> None:
        # Opus R3-1: the unit started, then the QGA reply was lost.  The
        # writer appends a leak before it is finally stopped.  37bafc2 took a
        # trusted snapshot of the live writer first and reported INVALID.
        def start_hook(original, client, **kwargs):
            original(client, **kwargs)
            raise QGAError("reply lost after systemd-run")

        with contextlib.ExitStack() as stack:
            self._hooks(stack, start_hook=start_hook)
            code, record, *_ = self._run(
                "idle", client_kwargs={"stop_suffix": client_leak_suffix}
            )
        self.assertEqual(code, 1, record["result_reason"])
        self.assertEqual(record["result"], "LEAK")
        self.assertTrue(record["client"]["probe_leak_observed"])
        self.assertTrue(record["client"]["traffic_stop_proven"])

    def test_opus_r3_2_untrusted_reads_never_pass_the_pre_fault_gate(self) -> None:
        # Opus R3-2: every log transfer exits 1 but carries good lines.  The
        # destructive fault must not run without a trusted pre-fault proof.
        code, record, _client, events, *_ = self._run(
            "stop-router", client_kwargs={"cat_exit": 1}
        )
        self.assertEqual(code, 2)
        self.assertIn("client_not_routed", record["errors"])
        router_commands = [str(entry[1]) for entry in events if entry[0] == "exec"]
        self.assertFalse(
            any("systemctl stop vprouter@" in command for command in router_commands)
        )
        self.assertNotIn("pre_fault_mullvad", record["client"])

    def test_client_prefs_must_keep_the_client_role(self) -> None:
        good = {"AdvertiseRoutes": None, "RouteAll": False, "ShieldsUp": True,
                "CorpDNS": False}
        for label, prefs, reason in (
            ("missing-routes", {"RouteAll": False, "ShieldsUp": True}, "client_prefs_incomplete"),
            ("accept-routes", dict(good, RouteAll=True), "client_accepts_routes"),
            ("shields-down", dict(good, ShieldsUp=False), "client_shields_down"),
            ("missing-shields", {"AdvertiseRoutes": [], "RouteAll": False}, "client_prefs_incomplete"),
        ):
            with self.subTest(case=label):
                self._fresh_evidence(label)
                code, record, _client, events, *_ = self._run(
                    "idle", client_kwargs={"prefs": prefs}
                )
                self.assertEqual(code, 2)
                self.assertIn(reason, record["errors"])
                self.assertFalse(any(entry[0] == "traffic_start" for entry in events))
        for label, prefs in (("null", good), ("empty", dict(good, AdvertiseRoutes=[]))):
            with self.subTest(case=label):
                self._fresh_evidence(label)
                code, record, *_ = self._run("idle", client_kwargs={"prefs": prefs})
                self.assertEqual(code, 0, record["result_reason"])

    # ------------------------------------------------------------------
    # Fix round 4 regressions.  Like round 3, the hooks patch only functions
    # that exist on 06baf40 as well (start_client_traffic, run_router_fault,
    # read_client_status, read_client_prefs) or wrap the fake QGA itself, so
    # each reproducer runs unchanged against the old runner.

    def _deadline_hooks(self, stack, *, delay_until, late_pair, silence_after=20.0):
        """GPT R4-I1: a stalled tail and a slow deadline size read.

        The guest clock follows the fake host clock (no frozen clock).  The
        hold base h0 is the first size read after the fault action returned.
        The loop writes only for hold offsets <= ``silence_after``.  The first
        size read at hold offset >= 26.9 s (06baf40: the deadline read at
        30 s; now: S_end at deadline - 3 s) is held until hold offset
        ``delay_until``; with ``late_pair`` one probe pair is written just
        before that read executes, i.e. after the 30 s hold deadline.
        """
        holder = {"fault_done": False, "h0": None, "delayed": False}
        original_start = run_phase.start_client_traffic
        original_fault = run_phase.run_router_fault

        def start(client, **kwargs):
            result = original_start(client, **kwargs)
            holder["client"] = client
            holder["t0"] = run_phase.time.monotonic()
            holder["g0"] = client.clock
            execute = client.execute
            pair = client.probe_pair

            def guest_now():
                return holder["g0"] + int(run_phase.time.monotonic() - holder["t0"])

            def probe_pair():
                client.clock = guest_now()
                pair()

            def wrapped(program, args=(), timeout=60.0, **extra):
                command = args[-1] if args else ""
                if command.startswith("stat -c %s") and holder["fault_done"]:
                    now = run_phase.time.monotonic()
                    if holder["h0"] is None:
                        holder["h0"] = now
                        client.hold_started_at = now
                        client.hold_plan = lambda offset: offset <= silence_after
                    offset = now - holder["h0"]
                    if (
                        offset >= 26.9
                        and client.traffic_active
                        and not holder["delayed"]
                    ):
                        holder["delayed"] = True
                        wait = holder["h0"] + delay_until - now
                        if wait > 0:
                            run_phase.time.sleep(wait)
                        if late_pair:
                            probe_pair()
                if command.strip() == "date +%s":
                    client.clock = guest_now()
                    return ExecResult(0, f"{client.clock}\n".encode(), b"")
                return execute(program, args, timeout=timeout, **extra)

            client.probe_pair = probe_pair
            client.execute = wrapped
            return result

        def fault(*args, **kwargs):
            result = original_fault(*args, **kwargs)
            holder["fault_done"] = True
            return result

        stack.enter_context(
            mock.patch.object(run_phase, "start_client_traffic", side_effect=start)
        )
        stack.enter_context(
            mock.patch.object(run_phase, "run_router_fault", side_effect=fault)
        )
        return holder

    def test_gpt_r4_i1_late_deadline_read_never_credits_post_hold_lines(self) -> None:
        # GPT R4-I1: the deadline size read finishes 1 s / 2 s after the
        # 30 s hold, and the only exit attempt after hold offset 20 is a pair
        # first written after the deadline.  06baf40 credited it (2 s grace)
        # and PASSed.
        for label, until in (("1s", 31.0), ("2s", 32.0)):
            with self.subTest(delay=label):
                self._fresh_evidence("r4i1-" + label)
                with contextlib.ExitStack() as stack:
                    holder = self._deadline_hooks(
                        stack, delay_until=until, late_pair=True
                    )
                    code, record, client, *_ = self._run("stop-router")
                self.assertTrue(holder["delayed"])
                self.assertNotEqual(record["result"], "PASS")
                self.assertEqual(code, 2)
                self.assertIn("probe_hold_deadline_late", record["errors"])
                end = record["client"]["hold_samples"][-1]
                fault = next(
                    sample for sample in record["client"]["hold_samples"]
                    if sample.get("kind") == "fault"
                )
                self.assertGreater(end["stat_end"] - fault["stat_start"], 30.0)

    def test_gpt_r4_i1_controls(self) -> None:
        # Same slow deadline read without the late pair: INVALID as well.
        self._fresh_evidence("r4i1-nolate")
        with contextlib.ExitStack() as stack:
            self._deadline_hooks(stack, delay_until=31.0, late_pair=False)
            code, record, *_ = self._run("stop-router")
        self.assertEqual(code, 2)
        self.assertIn("probe_hold_deadline_late", record["errors"])
        # A 1 s slow read that still ends before the deadline is fine: the
        # end sample starts 3 s early, and the pair it sees was written
        # inside the hold.  (Its window, 13.5 s + 1 s, stays <= 15 s; a
        # longer read is INVALID by the window rule, never a PASS.)
        self._fresh_evidence("r4i1-margin")
        with contextlib.ExitStack() as stack:
            self._deadline_hooks(stack, delay_until=28.0, late_pair=True)
            code, record, *_ = self._run("stop-router")
        self.assertEqual(code, 0, record["errors"])
        end = record["client"]["hold_samples"][-1]
        self.assertEqual(end["kind"], "end")
        self._fresh_evidence("r4i1-slow")
        with contextlib.ExitStack() as stack:
            self._deadline_hooks(stack, delay_until=29.5, late_pair=True)
            code, record, *_ = self._run("stop-router")
        self.assertEqual(code, 2)
        self.assertIn("probe_hold_window_late", record["client"]["probe"]["invalid_reasons"])
        # Healthy, no delay, silence only after hold offset 20: every window
        # of the 13.5 s split still has an exit attempt.
        self._fresh_evidence("r4i1-healthy")
        with contextlib.ExitStack() as stack:
            self._deadline_hooks(stack, delay_until=0.0, late_pair=False)
            code, record, *_ = self._run("stop-router")
        self.assertEqual(code, 0, record["errors"])

    def _silent_action(self, stack, seconds=60.0):
        """Opus R4 I-1: the fault action takes ``seconds`` of host time while
        the client loop writes nothing and its clock does not advance (a
        paused client VM); the 1 Hz loop resumes for the whole hold."""
        original_start = run_phase.start_client_traffic
        original_fault = run_phase.run_router_fault
        holder = {}

        def start(client, **kwargs):
            holder["client"] = client
            return original_start(client, **kwargs)

        def fault(*args, **kwargs):
            client = holder["client"]
            client.silent_hold = True
            client.frozen_clock = True
            run_phase.time.sleep(seconds)
            client.silent_hold = False
            client.frozen_clock = False
            client.next_probe_at = None
            return original_fault(*args, **kwargs)

        stack.enter_context(
            mock.patch.object(run_phase, "start_client_traffic", side_effect=start)
        )
        stack.enter_context(
            mock.patch.object(run_phase, "run_router_fault", side_effect=fault)
        )

    def test_opus_r4_i1_silent_fault_action_is_never_covered(self) -> None:
        # 06baf40 started host coverage only after the action, so a 60 s
        # action with zero client probes PASSed on the guest clock's word.
        for phase in ("restart-docker", "kill-wireguard", "kill-container"):
            with self.subTest(phase=phase):
                self._fresh_evidence("r4i1a-" + phase)
                with contextlib.ExitStack() as stack:
                    self._silent_action(stack)
                    code, record, *_ = self._run(phase)
                self.assertNotEqual(record["result"], "PASS")
                self.assertEqual(code, 2)
                reasons = set(record["client"]["probe"]["invalid_reasons"])
                self.assertTrue(
                    {"probe_hold_window_empty", "probe_hold_window_late"} & reasons,
                    reasons,
                )
                self.assertEqual(record["client"]["hold_samples"][0]["kind"], "pre")

    def test_long_healthy_fault_action_is_sampled_by_the_helper_thread(self) -> None:
        # Positive control for decision 1: a 60 s action with live client
        # traffic is sampled from the helper thread (client QGA only) every
        # 13 s and PASSes; the action windows are part of the evidence.
        instances = []

        class Recording(run_phase.ClientActionSampler):
            poll_interval = 0.001

            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                instances.append(self)

        original_fault = run_phase.run_router_fault
        router_threads = set()

        def fault(router, *args, **kwargs):
            router_threads.add(threading.get_ident())
            sampler = instances[-1]
            for _ in range(60):
                run_phase.time.sleep(1.0)
                give_up = time.perf_counter() + 5.0
                while (
                    sampler.is_alive()
                    and sampler.next_due <= run_phase.time.monotonic()
                    and time.perf_counter() < give_up
                ):
                    threading.Event().wait(0.0005)
            return original_fault(router, *args, **kwargs)

        with mock.patch.object(run_phase, "ClientActionSampler", Recording), \
                mock.patch.object(run_phase, "run_router_fault", side_effect=fault):
            code, record, *_ = self._run("restart-docker")
        self.assertEqual(code, 0, record["errors"])
        kinds = [sample["kind"] for sample in record["client"]["hold_samples"]]
        self.assertEqual(kinds[:6], ["pre", "action", "action", "action", "action", "fault"])
        self.assertEqual(record["client"]["action_samples"], 4)
        self.assertEqual(router_threads, {threading.get_ident()})
        self.assertFalse(instances[-1].is_alive())
        samples = record["client"]["hold_samples"]
        for earlier, later in zip(samples, samples[1:]):
            self.assertLessEqual(
                later["stat_end"] - earlier["stat_start"],
                clientprobe.MAX_HOLD_SAMPLE_WINDOW,
            )

    def test_action_sampler_is_joined_when_the_action_raises(self) -> None:
        instances = []

        class Recording(run_phase.ClientActionSampler):
            poll_interval = 0.001

            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                instances.append(self)

        with mock.patch.object(run_phase, "ClientActionSampler", Recording), \
                mock.patch.object(
                    run_phase, "run_router_fault", side_effect=RuntimeError("boom")
                ):
            code, record, *_ = self._run("kill-container")
        self.assertEqual(code, 2)
        self.assertTrue(instances)
        self.assertFalse(instances[-1].is_alive())
        self.assertTrue(record["client"]["probe_collected"])

    def test_stuck_action_sampler_never_shares_the_client_socket(self) -> None:
        # A sampler that cannot be joined still owns the client QGA socket:
        # the runner refuses and never uses that socket again (no probe
        # collection, no client cleanup; QEMU is killed instead).
        entered = threading.Event()
        release = threading.Event()
        original_take = run_phase.take_client_coverage_sample
        original_fault = run_phase.run_router_fault

        seen = {}

        def take(client, run_id, *, kind, **kwargs):
            if kind == "action":
                seen["client"] = client
                entered.set()
                release.wait(10.0)
                raise QGAError("released")
            return original_take(client, run_id, kind=kind, **kwargs)

        def fault(*args, **kwargs):
            entered.wait(5.0)
            result = original_fault(*args, **kwargs)
            # The sampler is blocked inside its sample; from here on every
            # client command would come from the main thread.
            seen["commands"] = len(seen["client"].commands)
            return result

        class Fast(run_phase.ClientActionSampler):
            poll_interval = 0.001

        try:
            with mock.patch.object(run_phase, "take_client_coverage_sample", side_effect=take), \
                    mock.patch.object(run_phase, "run_router_fault", side_effect=fault), \
                    mock.patch.object(run_phase, "ClientActionSampler", Fast), \
                    mock.patch.object(run_phase, "CLIENT_ACTION_SAMPLE_INTERVAL", 0.0), \
                    mock.patch.object(run_phase, "CLIENT_SAMPLER_JOIN_TIMEOUT", 0.05):
                code, record, client, *_ = self._run("kill-container")
                commands_after = list(client.commands[seen["commands"]:])
        finally:
            release.set()
        self.assertTrue(entered.is_set())
        self.assertEqual(code, 2)
        self.assertIn("client_sampler_stuck", record["errors"])
        self.assertNotIn("cleanup", record["client"])
        self.assertIsNot(record["client"].get("probe_collected"), True)
        self.assertEqual(commands_after, [])

    def test_opus_r5_m1_stuck_sampler_keeps_a_leak_it_already_saw(self) -> None:
        # Opus R5 m-1: the first action sample saw a non-Mullvad success, then
        # the sampler hung.  Nothing else from the stuck thread is trusted,
        # but the observed leak must stay latched (LEAK, not INVALID).
        entered = threading.Event()
        release = threading.Event()
        original_take = run_phase.take_client_coverage_sample
        calls = {"action": 0}

        def take(client, run_id, *, kind, **kwargs):
            if kind == "action":
                calls["action"] += 1
                if calls["action"] == 1:
                    read = run_phase.ProbeLogRead(
                        data=None, size=None, sha256=None,
                        problem="probe_log_unreadable",
                        stat_start=run_phase.time.monotonic(),
                        stat_end=run_phase.time.monotonic(),
                    )
                    return run_phase.ClientCoverageSample(kind, None, read, True, [])
                entered.set()
                release.wait(10.0)
                raise QGAError("released")
            return original_take(client, run_id, kind=kind, **kwargs)

        original_fault = run_phase.run_router_fault

        def fault(*args, **kwargs):
            entered.wait(5.0)
            return original_fault(*args, **kwargs)

        class Fast(run_phase.ClientActionSampler):
            poll_interval = 0.001

        try:
            with mock.patch.object(run_phase, "take_client_coverage_sample", side_effect=take), \
                    mock.patch.object(run_phase, "run_router_fault", side_effect=fault), \
                    mock.patch.object(run_phase, "ClientActionSampler", Fast), \
                    mock.patch.object(run_phase, "CLIENT_ACTION_SAMPLE_INTERVAL", 0.0), \
                    mock.patch.object(run_phase, "CLIENT_SAMPLER_JOIN_TIMEOUT", 0.05):
                code, record, *_ = self._run("kill-container")
        finally:
            release.set()
        self.assertTrue(entered.is_set())
        self.assertIn("client_sampler_stuck", record["errors"])
        self.assertTrue(record["client"].get("probe_leak_observed"))
        self.assertEqual(record["result"], "LEAK")
        self.assertEqual(code, 1)

    def test_gpt_r5_m1_sample_offsets_never_shrink_a_window(self) -> None:
        # GPT R5-M1: nearest-millisecond rounding turned a 15.0004 s window
        # into 15.000 s.  The start rounds down and the end rounds up.
        read = run_phase.ProbeLogRead(
            data=b"", size=0, sha256=hashlib.sha256(b"").hexdigest(), problem=None,
            stat_start=100.0004, stat_end=115.0008,
        )
        with mock.patch.object(run_phase, "read_client_probe_prefix", return_value=read):
            sample, _ = run_phase.take_client_probe_sample(object(), "a" * 32, base=100.0)
        self.assertEqual(sample["stat_start"], 0.0)
        self.assertEqual(sample["stat_end"], 15.001)
        self.assertGreaterEqual(sample["stat_end"] - sample["stat_start"], 115.0008 - 100.0004)

    def test_opus_r5_m2_process_scan_error_is_never_a_stop(self) -> None:
        class Client:
            def __init__(self, stdout, code):
                self.result = run_phase.ExecResult(exitcode=code, stdout=stdout, stderr=b"")

            def execute(self, *args, **kwargs):
                return self.result

        for stdout, code in ((b"TRAFFIC-PROCS:ERROR\n", 1), (b"TRAFFIC-PROCS:ERROR\n", 0),
                             (b"", 0), (b"TRAFFIC-PROCS:0\n", 0)):
            with self.subTest(stdout=stdout, code=code):
                count = run_phase.client_traffic_process_count(Client(stdout, code))
                self.assertEqual(count, 0 if (stdout == b"TRAFFIC-PROCS:0\n" and code == 0) else None)

    def test_opus_r4_m1_slow_writer_after_a_clean_looking_stop(self) -> None:
        # Opus R4 M-1: `is-active` says inactive and MainPID is 0, but a
        # writer appends a current-run leak every 5 s, first 3 s after the
        # stop.  06baf40's 2 s quiescence missed it and PASSed.  Now the
        # /proc scan sees it, and a writer hidden from the scan is caught by
        # the 12 s quiescence (its leak is latched).
        for label, hidden in (("visible", False), ("hidden", True)):
            with self.subTest(writer=label):
                self._fresh_evidence("m1-" + label)
                code, record, client, *_ = self._run(
                    "idle",
                    client_kwargs={
                        "ghost_writer_after_stop": 2,
                        "ghost_period": 5.0,
                        "ghost_first": 3.0,
                        "ghost_hidden": hidden,
                    },
                )
                self.assertNotEqual(record["result"], "PASS")
                self.assertFalse(record["client"]["traffic_stop_proven"])
                self.assertFalse(record["client"]["probe_snapshot_trusted"])
                if hidden:
                    self.assertEqual(code, 1, record["errors"])
                    self.assertIn("client_writer_not_quiescent", record["errors"])
                else:
                    self.assertEqual(code, 2, record["errors"])
                    self.assertIn("client_traffic_stop_failed", record["errors"])

    def test_opus_b_b1_real_prefix_shaped_exit_node_status_is_selected(self) -> None:
        # Opus B B-1: ExitNodeStatus.TailscaleIPs are netip.Prefix values
        # ("100.64.0.9/32"); 06baf40 compared bare addresses and could never
        # select the exit node with real tailscaled output.
        code, record, *_ = self._run("idle")
        self.assertEqual(code, 0, record["errors"])
        self.assertTrue(record["client"]["exit_node"]["router_peer_bound"])
        self.assertTrue(record["client"]["exit_node"]["reverified"])

    def test_opus_b_l1_client_must_not_accept_tailnet_dns(self) -> None:
        # Opus B L-1: client-login runs `tailscale up --accept-dns=false`,
        # and a phase refuses a client whose prefs accept DNS.
        code, record, client, events, *_ = self._run(
            "idle",
            client_kwargs={"prefs": {"AdvertiseRoutes": None, "RouteAll": False,
                                     "ShieldsUp": True, "CorpDNS": True}},
        )
        self.assertEqual(code, 2)
        self.assertIn("client_accepts_dns", record["errors"])
        self.assertFalse(any(entry[0] == "traffic_start" for entry in events))
        self._fresh_evidence("l1-login")
        code, record, client, *_ = self._run("client-login", 30.0)
        login = [command for command in client.commands
                 if "systemd-run" in command and "tailscale up" in command]
        self.assertEqual(len(login), 1)
        self.assertIn("--accept-dns=false", login[0])
        self.assertEqual(code, 0, record["errors"])
        self._fresh_evidence("l1-login-dns")
        code, record, *_ = self._run(
            "client-login", 30.0,
            client_kwargs={"prefs": {"AdvertiseRoutes": None, "RouteAll": False,
                                     "ShieldsUp": True, "CorpDNS": True}},
        )
        self.assertEqual(code, 2)
        self.assertIn("client_accepts_dns", record["errors"])

    def test_opus_b_p1_router_peer_lookup_is_retried(self) -> None:
        # The client's netmap shows the freshly started router online only
        # on the third read after the router became ready; 06baf40 refused
        # after a single read.
        state = {"router_ready": False, "offline_reads": 0}
        original_status = run_phase.read_client_status
        original_ready = run_phase.wait_router_ready

        def ready(*args, **kwargs):
            result = original_ready(*args, **kwargs)
            state["router_ready"] = True
            return result

        def status(client):
            document = original_status(client)
            if (
                state["router_ready"]
                and not client.exit_node_active
                and state["offline_reads"] < 2
                and isinstance(document, dict)
            ):
                state["offline_reads"] += 1
                for peer in document.get("Peer", {}).values():
                    peer["Online"] = False
            return document

        with mock.patch.object(run_phase, "wait_router_ready", side_effect=ready), \
                mock.patch.object(run_phase, "read_client_status", side_effect=status):
            code, record, *_ = self._run("idle")
        self.assertEqual(state["offline_reads"], 2)
        self.assertEqual(code, 0, record["errors"])

class ClientProbeReadTests(unittest.TestCase):
    """Fix round 3: the exact prefix-read primitive and the stop proof."""

    LOG = guest.CLIENT_PROBE_LOG

    class Guest:
        def __init__(self, log=b"", *, stat_exit=0, digest_exit=0, data_exit=0,
                     deliver=None, digest_of=None, states=("inactive",), main_pid="0",
                     procs="TRAFFIC-PROCS:0"):
            self.log = log
            self.stat_exit = stat_exit
            self.digest_exit = digest_exit
            self.data_exit = data_exit
            self.deliver = deliver
            self.digest_of = digest_of
            self.states = list(states)
            self.main_pid = main_pid
            self.procs = procs
            self.commands = []

        def execute(self, program, args=(), timeout=60.0):
            del program, timeout
            command = args[-1] if args else ""
            self.commands.append(command)
            if command.startswith("stat -c %s"):
                return ExecResult(self.stat_exit, f"{len(self.log)}\n".encode(), b"")
            match = re.fullmatch(r"head -c (\d+) \S+( \| sha256sum)?", command)
            if match and match.group(2):
                source = self.digest_of if self.digest_of is not None else self.log
                digest = hashlib.sha256(source[: int(match.group(1))]).hexdigest()
                return ExecResult(self.digest_exit, (digest + "  -\n").encode(), b"")
            if match:
                data = self.deliver if self.deliver is not None else self.log
                return ExecResult(self.data_exit, data[: int(match.group(1))], b"")
            if command.startswith("cat "):
                data = self.deliver if self.deliver is not None else self.log
                return ExecResult(self.data_exit, data, b"")
            if command.startswith("sha256sum "):
                source = self.digest_of if self.digest_of is not None else self.log
                digest = hashlib.sha256(source).hexdigest()
                return ExecResult(self.digest_exit, (digest + "  x\n").encode(), b"")
            if "systemctl is-active" in command:
                state = self.states.pop(0) if len(self.states) > 1 else self.states[0]
                return ExecResult(0 if state == "active" else 3, state.encode() + b"\n", b"")
            if "systemctl show -p MainPID --value" in command:
                return ExecResult(0, self.main_pid.encode() + b"\n", b"")
            if "TRAFFIC-PROCS" in command:
                return ExecResult(0, self.procs.encode() + b"\n", b"")
            return ExecResult(0, b"", b"")

    RUN_ID = "a" * 32

    def line(self, sequence, *, kind="exit", ok=True, m=True):
        document = {"k": kind, "ok": ok, "r": self.RUN_ID, "s": sequence, "t": 100}
        if kind == "exit":
            document["m"] = m
        return json.dumps(document, sort_keys=True, separators=(",", ":")).encode() + b"\n"

    def test_complete_prefix_is_trusted(self) -> None:
        log = self.line(1) + self.line(2, kind="marker")
        read = run_phase.read_client_probe_prefix(self.Guest(log))
        self.assertTrue(read.trusted)
        self.assertEqual(read.data, log)
        self.assertEqual(read.size, len(log))
        self.assertEqual(read.sha256, hashlib.sha256(log).hexdigest())
        self.assertLessEqual(read.stat_start, read.stat_end)

    def test_every_failed_step_makes_the_read_untrusted(self) -> None:
        log = self.line(1) + self.line(2, kind="marker")
        cases = (
            ("stat", dict(stat_exit=1), "probe_log_missing"),
            ("digest", dict(digest_exit=1), "probe_log_unreadable"),
            ("bytes-exit", dict(data_exit=1), "probe_log_unreadable"),
            ("short", dict(deliver=self.line(1)), "probe_log_truncated"),
            ("altered", dict(deliver=log.replace(b'"m":true', b'"m":fals')), "probe_log_hash_mismatch"),
            ("guest-hash", dict(digest_of=log[::-1]), "probe_log_hash_mismatch"),
        )
        for label, knobs, problem in cases:
            with self.subTest(case=label):
                read = run_phase.read_client_probe_prefix(self.Guest(log, **knobs))
                self.assertFalse(read.trusted)
                self.assertEqual(read.problem, problem)
                sample, _read = run_phase.take_client_probe_sample(
                    self.Guest(log, **knobs), self.RUN_ID, base=None
                )
                self.assertIsNone(sample)

    def test_untrusted_bytes_are_still_returned_for_leak_parsing(self) -> None:
        log = self.line(1, m=False) + self.line(2, kind="marker")
        read = run_phase.read_client_probe_prefix(self.Guest(log, data_exit=1))
        self.assertFalse(read.trusted)
        self.assertTrue(clientprobe.probe_prefix_flags(read.data)["leak"])

    def test_sample_sequence_comes_from_complete_lines_only(self) -> None:
        log = self.line(1) + self.line(2, kind="marker") + self.line(3)[:-5]
        sample, read = run_phase.take_client_probe_sample(
            self.Guest(log), self.RUN_ID, base=None
        )
        self.assertTrue(read.trusted)
        self.assertEqual(sample["sequence"], 2)
        self.assertEqual(sample["exit_sequence"], 1)
        self.assertEqual(sample["size"], len(log))
        self.assertEqual(sample["stat_start"], 0.0)

    def test_final_snapshot_needs_a_non_empty_newline_terminated_log(self) -> None:
        self.assertEqual(
            run_phase.read_client_probe_log_exact(self.Guest(b""))[1], "probe_log_empty"
        )
        partial = self.line(1)[:-1]
        self.assertEqual(
            run_phase.read_client_probe_log_exact(self.Guest(partial)),
            (partial, "probe_log_truncated"),
        )
        log = self.line(1)
        self.assertEqual(run_phase.read_client_probe_log_exact(self.Guest(log)), (log, None))

    def test_stop_proof_accepts_only_inactive_or_failed_with_main_pid_zero(self) -> None:
        for states, main_pid, expected in (
            (("inactive",), "0", True),
            (("failed",), "0", True),
            (("unknown",), "0", False),
            (("deactivating",), "0", False),
            (("",), "0", False),
            (("active",), "0", False),
            (("inactive",), "812", False),
            (("inactive",), "", False),
        ):
            with self.subTest(states=states, main_pid=main_pid):
                self.assertIs(
                    run_phase.stop_client_traffic(
                        self.Guest(states=states, main_pid=main_pid)
                    ),
                    expected,
                )
        # Opus R4 M-1: no traffic-script process may remain anywhere.
        for procs, expected in (
            ("TRAFFIC-PROCS:0", True),
            ("TRAFFIC-PROCS:1", False),
            ("TRAFFIC-PROCS:", False),
            ("", False),
            ("TRAFFIC-PROCS:0 extra", False),
        ):
            with self.subTest(procs=procs):
                self.assertIs(
                    run_phase.stop_client_traffic(self.Guest(procs=procs)), expected
                )

    def test_quiescence_needs_two_equal_size_reads_twelve_seconds_apart(self) -> None:
        clock = [100.0]
        guest_vm = self.Guest(self.line(1))

        def sleep(seconds):
            clock[0] += seconds
            guest_vm.log += self.line(2)

        with mock.patch.object(run_phase.time, "monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(run_phase.time, "sleep", side_effect=sleep):
            self.assertFalse(run_phase.client_probe_writer_quiescent(guest_vm))
        quiet = self.Guest(self.line(1))
        start = [0.0]

        def quiet_sleep(seconds):
            clock[0] += seconds

        with mock.patch.object(run_phase.time, "monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(run_phase.time, "sleep", side_effect=quiet_sleep):
            start[0] = clock[0]
            self.assertTrue(run_phase.client_probe_writer_quiescent(quiet))
            self.assertGreaterEqual(
                clock[0] - start[0], run_phase.CLIENT_STOP_QUIESCENCE_SECONDS
            )
        # Longer than one worst-case probe loop (Opus R4 M-1).
        self.assertGreaterEqual(run_phase.CLIENT_STOP_QUIESCENCE_SECONDS, 12.0)
        self.assertFalse(
            run_phase.client_probe_writer_quiescent(self.Guest(self.line(1), stat_exit=1))
        )

    def test_opus_r3_2_untrusted_reads_never_set_the_positive_controls(self) -> None:
        # Opus R3-2 at the function: every transfer exits 1 but contains a
        # Mullvad success and a successful marker.  37bafc2 returned both
        # controls after the timeout.
        log = self.line(1) + self.line(2, kind="marker")
        clock = [0.0]
        with mock.patch.object(run_phase.time, "monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(
                    run_phase.time, "sleep",
                    side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
                ):
            flags = run_phase.wait_client_probe_control(
                self.Guest(log, data_exit=1), self.RUN_ID, timeout=3.0
            )
            self.assertFalse(flags["mullvad"])
            self.assertFalse(flags["marker"])
            self.assertFalse(flags["leak"])
            leak = self.line(1, m=False)
            flags = run_phase.wait_client_probe_control(
                self.Guest(leak, data_exit=1), self.RUN_ID, timeout=3.0
            )
            self.assertTrue(flags["leak"])
            flags = run_phase.wait_client_probe_control(
                self.Guest(log), self.RUN_ID, timeout=3.0
            )
            self.assertTrue(flags["mullvad"] and flags["marker"])

    def test_prefs_require_present_empty_routes_and_the_client_flags(self) -> None:
        good = {"AdvertiseRoutes": None, "RouteAll": False, "ShieldsUp": True,
                "CorpDNS": False}
        check = run_phase.client_route_advertisement_problem
        self.assertIsNone(check(good))
        self.assertIsNone(check(dict(good, AdvertiseRoutes=[])))
        self.assertEqual(check({"RouteAll": False, "ShieldsUp": True}), "client_prefs_incomplete")
        self.assertEqual(check(dict(good, AdvertiseRoutes=["10.0.0.0/8"])), "client_advertises_routes")
        self.assertEqual(check(dict(good, AdvertiseRoutes="0.0.0.0/0")), "client_advertises_routes")
        self.assertEqual(check(dict(good, RouteAll=True)), "client_accepts_routes")
        self.assertEqual(check(dict(good, RouteAll=None)), "client_accepts_routes")
        self.assertEqual(check(dict(good, ShieldsUp=False)), "client_shields_down")
        self.assertEqual(check({"AdvertiseRoutes": []}), "client_prefs_incomplete")
        self.assertEqual(check(None), "client_prefs_unreadable")
        # Opus B L-1: MagicDNS must be off (`--accept-dns=false`).
        self.assertEqual(check(dict(good, CorpDNS=True)), "client_accepts_dns")
        self.assertEqual(check(dict(good, CorpDNS=None)), "client_accepts_dns")
        missing = dict(good)
        del missing["CorpDNS"]
        self.assertEqual(check(missing), "client_prefs_incomplete")


class TestFileLayoutTests(unittest.TestCase):
    """r5 review M3: a class after the __main__ guard is skipped by `python3 FILE`."""

    def test_main_guard_is_the_last_statement(self):
        import ast
        tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
        last = tree.body[-1]
        self.assertIsInstance(last, ast.If)
        self.assertIn("__main__", ast.unparse(last.test))
        guards = [node for node in tree.body
                  if isinstance(node, ast.If) and "__main__" in ast.unparse(node.test)]
        self.assertEqual(len(guards), 1)


if __name__ == "__main__":
    unittest.main()
