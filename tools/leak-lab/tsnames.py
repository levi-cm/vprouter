#!/usr/bin/env python3
"""Generate and recognize safe names for throw-away test Tailscale nodes.

Production names must never look like these; every generated name carries the
``zz-vprtest-NN-do-not-use`` (router/exit node) or ``zz-vprclient-NN-do-not-use``
(client) prefix.  Generation refuses an over-long result instead of truncating
it, because truncation could silently turn a test name into a different valid
(or colliding) DNS label.
"""

from __future__ import annotations

import argparse
import re
import sys

PREFIX = "zz-vprtest-"
CLIENT_PREFIX = "zz-vprclient-"
MARKER = "-do-not-use"
MAX_DNS_LABEL = 63

_SUFFIX_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_TEST_NODE_RE = re.compile(
    r"^zz-vprtest-(?:0[1-9]|[1-9][0-9])-do-not-use"
    r"(?:-[a-z0-9]+(?:-[a-z0-9]+)*)?$"
)
_CLIENT_NODE_RE = re.compile(
    r"^zz-vprclient-(?:0[1-9]|[1-9][0-9])-do-not-use$"
)


def generate(index: int, suffix: str | None = None) -> str:
    """Return ``zz-vprtest-NN-do-not-use[-suffix]`` or raise ValueError.

    ``index`` is 1..99.  A suffix is a lowercase DNS-label fragment such as
    ``mullvad-hot-dingo``.  The complete label must be <= 63 characters; this
    function refuses rather than truncating.
    """
    if isinstance(index, bool) or not isinstance(index, int):
        raise ValueError("index must be an integer in 1..99")
    if not 1 <= index <= 99:
        raise ValueError("index must be in 1..99")
    name = f"{PREFIX}{index:02d}{MARKER}"
    if suffix is not None:
        if not isinstance(suffix, str) or _SUFFIX_RE.fullmatch(suffix) is None:
            raise ValueError(
                "suffix must be lowercase [a-z0-9] with single hyphens and no "
                "leading/trailing hyphen"
            )
        name = f"{name}-{suffix}"
    if len(name) > MAX_DNS_LABEL:
        raise ValueError(
            f"refusing to generate {len(name)}-character DNS label "
            f"(maximum {MAX_DNS_LABEL}): {name!r}"
        )
    if _TEST_NODE_RE.fullmatch(name) is None:
        raise ValueError(f"internal error: generated name is not a test-node label: {name!r}")
    return name


def is_test_node(name: str) -> bool:
    """Return True only for the exact ``zz-vprtest-NN-do-not-use[-suffix]`` form.

    The match is on the bare DNS label: a MagicDNS FQDN such as
    ``zz-vprtest-01-do-not-use.tailnet.ts.net`` is rejected, and callers must
    strip the domain before checking.  Any accepted suffix is opaque data, not a
    safety claim; only the ``zz-vprtest-NN-do-not-use`` prefix is meaningful.
    """
    return (
        isinstance(name, str)
        and 0 < len(name) <= MAX_DNS_LABEL
        and _TEST_NODE_RE.fullmatch(name) is not None
    )


def generate_client(index: int) -> str:
    """Return ``zz-vprclient-NN-do-not-use`` or raise ValueError.

    Client nodes never advertise an exit node or routes, so unlike the router
    name there is deliberately no opaque suffix: the whole label is fixed.
    """
    if isinstance(index, bool) or not isinstance(index, int):
        raise ValueError("client index must be an integer in 1..99")
    if not 1 <= index <= 99:
        raise ValueError("client index must be in 1..99")
    name = f"{CLIENT_PREFIX}{index:02d}{MARKER}"
    if len(name) > MAX_DNS_LABEL:
        raise ValueError(
            f"refusing to generate {len(name)}-character DNS label "
            f"(maximum {MAX_DNS_LABEL}): {name!r}"
        )
    if _CLIENT_NODE_RE.fullmatch(name) is None:
        raise ValueError(
            f"internal error: generated name is not a client-node label: {name!r}"
        )
    return name


def is_client_node(name: str) -> bool:
    """Return True only for the exact ``zz-vprclient-NN-do-not-use`` form.

    The bare DNS label is required; callers must strip a MagicDNS domain.  No
    suffix is accepted because a client node's whole safety claim is its fixed
    name and role.
    """
    return (
        isinstance(name, str)
        and 0 < len(name) <= MAX_DNS_LABEL
        and _CLIENT_NODE_RE.fullmatch(name) is not None
    )


def client_index(name: str) -> int | None:
    """Return the NN of a valid client label, or None."""
    if not is_client_node(name):
        return None
    return int(name[len(CLIENT_PREFIX):][:2])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="generate or check a vprlab test Tailscale node hostname"
    )
    parser.add_argument("--index", type=int, help="test node number 1..99")
    parser.add_argument("--suffix", help="optional stable suffix, e.g. mullvad-hot-dingo")
    parser.add_argument(
        "--client-index",
        type=int,
        help="generate zz-vprclient-NN-do-not-use for client NN",
    )
    parser.add_argument(
        "--check",
        metavar="NAME",
        help="check a name; exit 0 when it is a test node, 1 otherwise",
    )
    parser.add_argument(
        "--check-client",
        metavar="NAME",
        help="check a name; exit 0 when it is a client node, 1 otherwise",
    )
    args = parser.parse_args(argv)

    if args.check is not None and args.check_client is not None:
        parser.error("--check and --check-client are mutually exclusive")
    if args.check is not None:
        result = is_test_node(args.check)
        print("true" if result else "false")
        return 0 if result else 1
    if args.check_client is not None:
        result = is_client_node(args.check_client)
        print("true" if result else "false")
        return 0 if result else 1
    if args.client_index is not None:
        if args.index is not None or args.suffix is not None:
            parser.error("--client-index cannot be combined with --index/--suffix")
        try:
            print(generate_client(args.client_index))
        except ValueError as exc:
            print(f"tsnames: {exc}", file=sys.stderr)
            return 2
        return 0
    if args.index is None:
        parser.error(
            "--index or --client-index is required unless --check/--check-client is used"
        )
    try:
        print(generate(args.index, args.suffix))
    except ValueError as exc:
        print(f"tsnames: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
