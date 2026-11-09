#!/usr/bin/env python3
"""Minimal QEMU guest-agent client for the vprlab leak VM.

Only the subset the leak lab needs is implemented: the delimited sync
handshake, ``guest-ping``, ``guest-exec`` with captured output and bounded
polling, ``guest-file-open``/``guest-file-write``/``guest-file-close`` for
root-only files, and ``guest-shutdown``.

This module never logs, prints or returns the bytes it writes to the guest.
Errors carry the method name and, at most, a locally allowlisted guest error
class; guest-provided descriptions are discarded unread.

The wire protocol is the public QEMU guest-agent JSON protocol:

* a fresh connection may first receive the agent's ``guest-sync`` greeting;
* the client sends ``guest-sync-delimited`` and discards every byte up to the
  ``0xFF`` delimiter that precedes the reply;
* afterwards every command is one JSON line and every reply is one JSON line.
"""

from __future__ import annotations

import base64
import json
import pathlib
import socket
import time
from dataclasses import dataclass

DEFAULT_TIMEOUT = 30.0
DEFAULT_CONNECT_TIMEOUT = 120.0
MAX_FILE_CHUNK = 65536
#: A single reply frame may never exceed this many bytes.  The root runner is
#: an untrusted-guest boundary; a guest that stops qemu-ga and streams to the
#: virtio port must not be able to grow our buffer without bound.
MAX_REPLY_BYTES = 16 * 1024 * 1024
#: Captured stdout/stderr of one command.  Huge guest-exec output is not
#: evidence and is refused before decoding into a second allocation.
MAX_EXEC_OUTPUT_BYTES = 4 * 1024 * 1024
#: Guest-provided error text is never rendered.  Only a known QGA error class
#: may be named; everything else becomes a local ``guest_error``.  A 44-byte
#: WireGuard key fits comfortably inside any truncation limit, so length
#: bounding is not secrecy.
QGA_ERROR_CLASSES = frozenset(
    {
        "GenericError",
        "CommandNotFound",
        "CommandDisabled",
        "InvalidParameter",
        "DeviceNotActive",
        "DeviceNotFound",
        "FileNotFound",
        "FileExists",
        "IoError",
        "PermissionDenied",
        "Unsupported",
    }
)
UNKNOWN_GUEST_ERROR = "guest_error"


def _error_class_name(value: object) -> str:
    """Map an untrusted guest error class to a local allowlisted name."""
    if isinstance(value, str) and value in QGA_ERROR_CLASSES:
        return value
    return UNKNOWN_GUEST_ERROR


class QGAError(RuntimeError):
    """The guest agent rejected a command or the channel failed."""


class QGATimeout(QGAError):
    """The guest agent did not answer within the requested deadline."""


class QGAProtocolError(QGAError):
    """The guest agent sent a frame this client cannot understand."""


@dataclass(frozen=True, slots=True)
class ExecResult:
    """The captured result of one ``guest-exec`` command."""

    exitcode: int | None
    stdout: bytes
    stderr: bytes


def _decode_field(value: object) -> bytes:
    if value is None:
        return b""
    if not isinstance(value, str):
        raise QGAProtocolError("guest-exec-status returned a non-string output field")
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise QGAProtocolError(
            "guest-exec-status returned malformed base64 output"
        ) from exc
    if len(decoded) > MAX_EXEC_OUTPUT_BYTES:
        raise QGAProtocolError(
            "reply_too_large: exec_output_too_large"
        )
    return decoded


class QGAClient:
    """A single synchronous connection to ``org.qemu.guest_agent.0``."""

    def __init__(self, socket_path: str | pathlib.Path, *, timeout: float = DEFAULT_TIMEOUT):
        self.path = pathlib.Path(socket_path)
        self.timeout = float(timeout)
        self._socket: socket.socket | None = None
        self._buffer = b""
        self._scan_from = 0
        self._next_id = 1

    # -- connection -----------------------------------------------------
    def connect(self, *, timeout: float | None = None) -> None:
        if self._socket is not None:
            raise QGAError("already connected")
        deadline = time.monotonic() + (self.timeout if timeout is None else timeout)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            remaining = max(0.0, deadline - time.monotonic())
            sock.settimeout(max(0.001, remaining))
            sock.connect(str(self.path))
            self._socket = sock
            self._buffer = b""
            self._scan_from = 0
            self._handshake(deadline)
        except BaseException:
            sock.close()
            self._socket = None
            raise

    def close(self) -> None:
        if self._socket is not None:
            try:
                self._socket.close()
            finally:
                self._socket = None
                self._buffer = b""
                self._scan_from = 0

    def __enter__(self) -> "QGAClient":
        self.connect()
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        self.close()

    # -- framing --------------------------------------------------------
    def _send_json(self, document: dict) -> None:
        if self._socket is None:
            raise QGAError("not connected")
        wire = json.dumps(document, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        self._socket.sendall(wire + b"\n")

    def _fill(self, deadline: float) -> None:
        if self._socket is None:
            raise QGAError("not connected")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise QGATimeout("timed out waiting for the guest agent")
        self._socket.settimeout(max(0.001, remaining))
        try:
            chunk = self._socket.recv(65536)
        except socket.timeout as exc:
            raise QGATimeout("timed out waiting for the guest agent") from exc
        except OSError as exc:
            raise QGAError(f"guest agent channel failed: {exc.__class__.__name__}") from exc
        if not chunk:
            raise QGAError("guest agent closed the connection")
        self._buffer += chunk
        if len(self._buffer) > MAX_REPLY_BYTES:
            # Close immediately: the peer is not speaking the framed protocol
            # and delaying only grows the buffer and the O(n) rescan cost.
            self.close()
            raise QGAProtocolError("reply_too_large")

    @staticmethod
    def _parse(payload: bytes) -> dict:
        try:
            document = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise QGAProtocolError("guest agent sent invalid JSON") from exc
        if not isinstance(document, dict):
            raise QGAProtocolError("guest agent sent a non-object frame")
        return document

    def _handshake(self, deadline: float) -> None:
        sync_id = self._next_id
        self._next_id += 1
        self._send_json(
            {"execute": "guest-sync-delimited", "arguments": {"id": sync_id}}
        )
        while True:
            marker = self._buffer.find(b"\xff", self._scan_from)
            if marker >= 0:
                end = self._buffer.find(b"\n", marker)
                if end >= 0:
                    frame = self._buffer[marker + 1 : end]
                    self._buffer = self._buffer[end + 1 :]
                    self._scan_from = 0
                    document = self._parse(frame)
                    if document.get("return") == sync_id:
                        return
                    # Not our sync reply: keep scanning.  A greeting is safe
                    # to ignore; anything else is still bounded by the deadline.
                    continue
            self._scan_from = max(0, len(self._buffer) - 1)
            self._fill(deadline)

    def _read_response(self, deadline: float, expected_id: int | None = None) -> object:
        while True:
            end = self._buffer.find(b"\n", self._scan_from)
            if end >= 0:
                line = self._buffer[:end]
                self._buffer = self._buffer[end + 1 :]
                self._scan_from = 0
                if not line.strip():
                    continue
                document = self._parse(line)
                if "execute" in document and "return" not in document:
                    # The unsolicited greeting or a stray notification.
                    continue
                reply_id = document.get("id")
                if (
                    expected_id is not None
                    and reply_id is not None
                    and reply_id != expected_id
                ):
                    # A late reply to an earlier timed-out request.  Never
                    # attribute it to the current command.
                    continue
                error = document.get("error")
                if error is not None:
                    if not isinstance(error, dict):
                        raise QGAError("guest agent returned a malformed error")
                    klass = _error_class_name(error.get("class"))
                    # The guest-controlled ``desc`` is deliberately discarded:
                    # it is untrusted and may contain profile or Tailscale
                    # state bytes.
                    message = f"guest agent error {klass}"
                    raise QGAError(message)
                if "return" not in document:
                    raise QGAProtocolError("guest agent frame has no return value")
                return document["return"]
            self._scan_from = max(0, len(self._buffer) - 1)
            self._fill(deadline)

    # -- commands -------------------------------------------------------
    def command(
        self, name: str, arguments: dict | None = None, *, timeout: float | None = None
    ) -> object:
        deadline = time.monotonic() + (self.timeout if timeout is None else float(timeout))
        self._next_id += 1
        request_id = self._next_id
        document = {"execute": name, "id": request_id}
        if arguments is not None:
            document["arguments"] = arguments
        self._send_json(document)
        try:
            return self._read_response(deadline, request_id)
        except QGATimeout:
            # The stream is desynchronised after a timeout.  Closing it makes
            # every later call fail visibly instead of reading a stale reply.
            self.close()
            raise
        except QGAError as exc:
            if isinstance(exc, QGAProtocolError):
                # A malformed/oversized frame desynchronises the stream; never
                # keep reading stale bytes from it.
                self.close()
            raise QGAError(f"{name}: {exc}") from exc

    def ping(self, *, timeout: float | None = None) -> None:
        self.command("guest-ping", {}, timeout=timeout)

    def execute(
        self,
        program: str,
        args: list[str] | tuple[str, ...] = (),
        *,
        timeout: float = 60.0,
        capture: bool = True,
        env: dict[str, str] | None = None,
    ) -> ExecResult:
        """Run ``program`` in the guest and poll until it exits or times out."""
        deadline = time.monotonic() + float(timeout)
        launch: dict[str, object] = {
            "path": program,
            "arg": list(args),
            "capture-output": bool(capture),
        }
        if env is not None:
            launch["env"] = list(f"{key}={value}" for key, value in env.items())
        reply = self.command("guest-exec", launch, timeout=min(10.0, timeout))
        if not isinstance(reply, dict) or not isinstance(reply.get("pid"), int):
            raise QGAProtocolError("guest-exec did not return a pid")
        pid = reply["pid"]
        delay = 0.05
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.close()
                raise QGATimeout(f"guest-exec {program} timed out")
            status = self.command(
                "guest-exec-status", {"pid": pid}, timeout=min(5.0, remaining)
            )
            if not isinstance(status, dict):
                raise QGAProtocolError("guest-exec-status returned a non-object")
            if status.get("exited") is True:
                exitcode = status.get("exitcode")
                if exitcode is not None and not isinstance(exitcode, int):
                    self.close()
                    raise QGAProtocolError("guest-exec-status returned a bad exit code")
                try:
                    stdout = _decode_field(status.get("out-data"))
                    stderr = _decode_field(status.get("err-data"))
                except QGAProtocolError:
                    self.close()
                    raise
                return ExecResult(
                    exitcode=exitcode,
                    stdout=stdout,
                    stderr=stderr,
                )
            time.sleep(min(delay, max(0.0, deadline - time.monotonic())))
            delay = min(delay * 1.5, 0.5)

    def open_file(self, path: str, mode: str = "wb", *, timeout: float | None = None) -> int:
        reply = self.command(
            "guest-file-open", {"path": path, "mode": mode}, timeout=timeout
        )
        if not isinstance(reply, int) or isinstance(reply, bool):
            raise QGAProtocolError("guest-file-open did not return a handle")
        return reply

    def write_handle(self, handle: int, data: bytes, *, timeout: float | None = None) -> int:
        written = 0
        for offset in range(0, len(data), MAX_FILE_CHUNK):
            chunk = data[offset : offset + MAX_FILE_CHUNK]
            reply = self.command(
                "guest-file-write",
                {"handle": handle, "buf-b64": base64.b64encode(chunk).decode("ascii")},
                timeout=timeout,
            )
            if not isinstance(reply, dict) or not isinstance(reply.get("count"), int):
                raise QGAProtocolError("guest-file-write did not return a count")
            if reply["count"] != len(chunk):
                raise QGAError("guest-file-write wrote a short chunk")
            written += reply["count"]
        return written

    def close_file(self, handle: int, *, timeout: float | None = None) -> None:
        self.command("guest-file-close", {"handle": handle}, timeout=timeout)

    def write_file(self, path: str, data: bytes, *, timeout: float = 60.0) -> None:
        """Write ``data`` to ``path``; the caller is responsible for its mode.

        Nothing is logged.  The handle is always closed, even after a failure.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("write_file data must be bytes")
        handle = self.open_file(path, "wb", timeout=timeout)
        try:
            self.write_handle(handle, bytes(data), timeout=timeout)
        finally:
            try:
                self.close_file(handle, timeout=timeout)
            except QGAError:
                pass

    def shutdown(self, mode: str = "powerdown", *, timeout: float = 5.0) -> None:
        """Ask the guest to power down, reboot or halt.

        ``guest-shutdown`` normally does not answer because the guest is going
        away, so a timeout or a closed channel is treated as success.
        """
        if mode not in {"powerdown", "reboot", "halt"}:
            raise ValueError("unsupported guest-shutdown mode")
        try:
            self.command("guest-shutdown", {"mode": mode}, timeout=timeout)
        except (QGATimeout, QGAError):
            return


def wait_for_qga(
    socket_path: str | pathlib.Path,
    *,
    timeout: float = DEFAULT_CONNECT_TIMEOUT,
    interval: float = 0.25,
) -> QGAClient:
    """Return a connected, pinged client, retrying until ``timeout`` expires."""
    deadline = time.monotonic() + float(timeout)
    last_error = "no attempt"
    while True:
        client = QGAClient(socket_path)
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise QGATimeout(
                    f"guest agent {socket_path} unavailable: {last_error}"
                )
            client.connect(timeout=min(5.0, remaining))
            client.ping(timeout=min(5.0, max(0.1, deadline - time.monotonic())))
            return client
        except (OSError, QGAError) as exc:
            last_error = f"{exc.__class__.__name__}: {exc}"
            client.close()
            if time.monotonic() >= deadline:
                raise QGATimeout(
                    f"guest agent {socket_path} unavailable: {last_error}"
                ) from exc
            time.sleep(max(0.0, min(interval, deadline - time.monotonic())))


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="send one command to a QEMU guest agent")
    parser.add_argument("socket", help="guest-agent unix socket path")
    parser.add_argument("--ping", action="store_true")
    parser.add_argument("--exec", dest="command", metavar="SHELL")
    parser.add_argument("--timeout", type=float, default=30.0)
    arguments = parser.parse_args()
    client = wait_for_qga(arguments.socket, timeout=arguments.timeout)
    try:
        if arguments.ping or arguments.command is None:
            client.ping(timeout=arguments.timeout)
            print("pong")
        else:
            result = client.execute(
                "/bin/sh", ["-c", arguments.command], timeout=arguments.timeout
            )
            print(f"exit={result.exitcode}")
    finally:
        client.close()
