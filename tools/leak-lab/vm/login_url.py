#!/usr/bin/env python3
"""Print only the interactive Tailscale login URL from the running router.

The router unit is started by a phase (for example ``start-router`` with a long
duration).  Run this command on debdev while that phase is live:

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
from qga import QGAError, wait_for_qga

LOGIN_URL_RE = re.compile(r"https://login\.tailscale\.com/[A-Za-z0-9/_-]+")


def _extract(text: str) -> str | None:
    match = LOGIN_URL_RE.search(text)
    return match.group(0) if match else None


def find_login_url(client, name: str) -> str | None:
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
            if isinstance(auth_url, str):
                match = LOGIN_URL_RE.match(auth_url)
                if match:
                    return match.group(0)

    logs = client.execute(
        "/bin/sh",
        ["-c", f"docker logs --tail 400 {name} 2>&1 || true"],
        timeout=30.0,
    )
    return _extract(logs.stdout.decode("utf-8", "replace"))


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
    arguments = parser.parse_args(argv)
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


if __name__ == "__main__":
    raise SystemExit(main())
