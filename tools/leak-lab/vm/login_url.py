#!/usr/bin/env python3
"""Print only the interactive Tailscale login URL from the running router.

Run this command as root on debdev only when **no** leak-lab phase is running.
A QEMU socket chardev serves exactly one QGA client, so the helper refuses
(exit 2) while the runner holds ``/run/vprlab/run.lock``.  During a phase use
the ``login`` phase instead: it polls the URL through the runner's own QGA
connection and writes it to ``<evidence>/login-url.txt``.

    python3 -B tools/leak-lab/vm/login_url.py --index 1 --wait 120

It reads ``tailscale status --json`` and the container log through QGA and
prints exactly one URL.  Everything else, including the WireGuard profile and
Tailscale state, stays in the VM.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import time

import guest
import runlock
from qga import QGAError, wait_for_qga

#: The only login URL shape the runner records.  The Tailscale auth path is
#: 8..16 lowercase hex characters; anything longer or with other characters
#: could carry a guest-selected encoding of profile/state bytes into the host
#: evidence file and stderr.
LOGIN_URL_RE = re.compile(r"https://login\.tailscale\.com/a/[0-9a-f]{8,16}")
#: A candidate prefix used only to notice (and refuse) an unrecognized value.
LOGIN_CANDIDATE_RE = re.compile(r"https://login\.tailscale\.com/[^\s\"']+")

TAILSCALE_LOGIN_URL_LENGTHS = range(8, 17)


def _extract(text: str) -> str | None:
    match = LOGIN_URL_RE.search(text)
    return match.group(0) if match else None


def _valid(url: object) -> bool:
    return isinstance(url, str) and LOGIN_URL_RE.fullmatch(url) is not None


def find_login_url_result(client, name: str) -> tuple[str | None, bool]:
    """Return ``(url, unrecognized)`` from guest status/log text.

    ``url`` is only ever the fixed-shape URL.  ``unrecognized`` is True when
    the guest did advertise a login-tailscale URL of another shape; the
    caller records ``login_url_unrecognized`` and writes nothing.
    """
    candidates: list[str] = []
    status = client.execute(
        "/bin/sh",
        ["-c", f"docker exec {name} tailscale status --json 2>/dev/null || true"],
        timeout=20.0,
    )
    if status.stdout:
        try:
            document = json.loads(status.stdout.decode("utf-8", "replace"))
        except json.JSONDecodeError:
            document = None
        if isinstance(document, dict):
            auth_url = document.get("AuthURL")
            if isinstance(auth_url, str) and auth_url.strip():
                candidates.append(auth_url.strip())

    logs = client.execute(
        "/bin/sh",
        ["-c", f"docker logs --tail 400 {name} 2>&1 || true"],
        timeout=30.0,
    )
    text = logs.stdout.decode("utf-8", "replace")
    candidates.extend(match.group(0) for match in LOGIN_CANDIDATE_RE.finditer(text))
    unrecognized = False
    for candidate in candidates:
        if _valid(candidate):
            return candidate, unrecognized
        unrecognized = True
    return None, unrecognized


def find_login_url(client, name: str) -> str | None:
    url, _unrecognized = find_login_url_result(client, name)
    return url


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="print the Tailscale login URL only")
    parser.add_argument("--index", type=int, default=guest.DEFAULT_INDEX)
    parser.add_argument("--state")
    parser.add_argument("--state-root", default=str(guest.STATE_ROOT))
    parser.add_argument("--name", default=guest.DEFAULT_NAME)
    parser.add_argument(
        "--wait",
        type=float,
        default=0.0,
        help="poll for this many seconds before giving up",
    )
    parser.add_argument("--connect-timeout", type=float, default=10.0)
    parser.add_argument("--run-lock", default=str(runlock.RUN_LOCK))
    arguments = parser.parse_args(argv)
    # A runner holds one QGA connection for the whole phase; a second client
    # cannot complete the handshake.  Hold the same global lock across the
    # connection (not just a check-then-release probe) so a phase cannot take
    # it between the check and the connect.
    try:
        lock_fd = runlock.acquire(arguments.run_lock)
    except runlock.LockError as exc:
        print(f"login_url: {exc}", file=sys.stderr)
        return 2
    try:
        try:
            guest.validate_name(arguments.name)
        except guest.GeneratorError as exc:
            print(f"login_url: {exc}", file=sys.stderr)
            return 2
        state = (
            pathlib.Path(arguments.state)
            if arguments.state is not None
            else guest.state_path(arguments.index, pathlib.Path(arguments.state_root))
        )
        deadline = time.monotonic() + max(0.0, arguments.wait)
        try:
            client = wait_for_qga(
                state / guest.QGA_SOCKET, timeout=arguments.connect_timeout
            )
        except QGAError as exc:
            print(f"login_url: {exc}", file=sys.stderr)
            return 2
        try:
            while True:
                try:
                    url = find_login_url(client, arguments.name)
                except QGAError as exc:
                    print(f"login_url: {exc}", file=sys.stderr)
                    return 2
                if url is not None:
                    print(url)
                    return 0
                if time.monotonic() >= deadline:
                    print(
                        "login_url: no login URL yet; the router may be starting or "
                        "already authenticated",
                        file=sys.stderr,
                    )
                    return 1
                time.sleep(2.0)
        finally:
            client.close()
    finally:
        runlock.release(lock_fd)


if __name__ == "__main__":
    raise SystemExit(main())
