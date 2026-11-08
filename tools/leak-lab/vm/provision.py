#!/usr/bin/env python3
"""Provision the silent Debian 13 vprlab leak VM (online, never on the tap).

Run as root on debdev:

    python3 -B tools/leak-lab/vm/provision.py \
        --index 1 --image-tar /path/to/vprouter-image.tar

The VM boots once with QEMU user-mode networking and a read-only payload ISO,
installs the unchanged deployed release plus a pinned Docker image, silences
the OS, writes ``VPRLAB-PROVISION-OK`` to the serial console and powers off.
The same qcow2 is then used offline (tap only) by ``run_phase.py``.

Nothing here contacts the network itself; only the provision guest does, and
only through QEMU's user-mode netdev.  The runner never reads or prints secrets.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import pathlib
import pwd
import shutil
import signal
import stat
import subprocess
import sys
import time

import guest
import hostcheck

PROVISION_TIMEOUT = 1800.0
POWEROFF_TIMEOUT = 120.0


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _atomic_json(path: pathlib.Path, document: dict) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(document, stream, indent=2, sort_keys=True)
        stream.write("\n")


def _qemu_identity(user: str) -> tuple[int, int]:
    try:
        record = pwd.getpwnam(user)
    except KeyError as exc:
        raise hostcheck.Refusal(f"unknown unprivileged user {user!r}") from exc
    return record.pw_uid, record.pw_gid


def _require_tool(path: pathlib.Path) -> None:
    if not path.is_file() or not os.access(path, os.X_OK):
        raise hostcheck.Refusal(f"staged tool is missing or not executable: {path}")


def _copy_release(source: pathlib.Path, destination: pathlib.Path) -> None:
    if not source.is_dir():
        raise hostcheck.Refusal(f"release directory is missing: {source}")
    for required in guest.TRUSTED_RELEASE_FILES:
        if not (source / required).is_file():
            raise hostcheck.Refusal(f"release file is missing: {source / required}")
    for root, directories, files in os.walk(source):
        for name in list(directories) + list(files):
            candidate = pathlib.Path(root) / name
            if candidate.is_symlink():
                raise hostcheck.Refusal(f"release contains a symbolic link: {candidate}")
    shutil.copytree(
        source,
        destination,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
        symlinks=True,
    )


def create_state_directory(path: pathlib.Path, *, uid: int | None = None, gid: int | None = None) -> pathlib.Path:
    """Create a brand-new 0700 state directory; refuse an existing path."""
    path = pathlib.Path(path)
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)
    if uid is not None or gid is not None:
        if uid is None or gid is None:
            raise hostcheck.Refusal("uid and gid must be supplied together")
        os.chown(path, uid, gid)
    return path


def _stage_payload(
    state: pathlib.Path, release: pathlib.Path, image_tar: pathlib.Path
) -> pathlib.Path:
    """Stage release + image tar for the read-only payload ISO."""
    staging = state / "payload"
    staging.mkdir(mode=0o700)
    os.chmod(staging, 0o700)
    _copy_release(release, staging / "release")
    (staging / "unit").mkdir(mode=0o755)
    unit = release / guest.UNIT_SOURCE
    if not unit.is_file():
        raise hostcheck.Refusal(f"release unit file is missing: {unit}")
    shutil.copyfile(unit, staging / "unit" / "vprouter@.service")
    os.chmod(staging / "unit" / "vprouter@.service", 0o644)

    (staging / "image").mkdir(mode=0o755)
    destination = staging / "image" / "vprouter-image.tar"
    hardlinked = False
    try:
        os.link(image_tar, destination)
        hardlinked = True
    except OSError:
        shutil.copyfile(image_tar, destination)
    if not hardlinked:
        os.chmod(destination, 0o644)
    return staging


def _wait_for_marker(process: subprocess.Popen, serial: pathlib.Path, timeout: float) -> str:
    deadline = time.monotonic() + timeout
    marker = b"VPRLAB-PROVISION-OK "
    collected = b""
    while time.monotonic() < deadline:
        if serial.is_file():
            try:
                with serial.open("rb") as stream:
                    stream.seek(0, os.SEEK_END)
                    size = stream.tell()
                    stream.seek(max(0, size - 262144))
                    collected = stream.read()
            except OSError:
                pass
            index = collected.find(marker)
            if index >= 0:
                end = collected.find(b"\n", index)
                line = collected[index : end if end >= 0 else len(collected)]
                return line.decode("utf-8", "replace").strip()
            failure = collected.find(b"VPRLAB-PROVISION-FAILED:")
            if failure >= 0:
                end = collected.find(b"\n", failure)
                line = collected[failure : end if end >= 0 else len(collected)]
                raise hostcheck.Refusal(
                    "guest reported: " + line.decode("utf-8", "replace").strip()
                )
        status = process.poll()
        if status is not None:
            raise hostcheck.Refusal(
                f"QEMU exited with status {status} before the provisioning marker"
            )
        time.sleep(0.5)
    raise hostcheck.Refusal("provisioning timed out without a completion marker")


def _terminate(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    except OSError:
        process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except OSError:
            process.kill()
        process.wait(timeout=10)


def provision(arguments: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        raise hostcheck.Refusal("provisioning requires root")
    state = guest.state_path(arguments.index, pathlib.Path(arguments.state_root))
    if state.exists():
        raise hostcheck.Refusal(f"state directory already exists: {state}")

    base = pathlib.Path(arguments.base_image)
    digest = guest.verify_base_image(base, pathlib.Path(arguments.checksum_manifest))

    image_tar = pathlib.Path(arguments.image_tar)
    if image_tar.is_symlink() or not image_tar.is_file():
        raise hostcheck.Refusal("image tar must be a regular file, not a symlink")
    if image_tar.stat().st_size <= 0:
        raise hostcheck.Refusal("image tar is empty")
    image_id = guest.validate_image_id(arguments.image_id)

    for tool in (guest.QEMU, guest.QEMU_IMG, guest.GENISOIMAGE):
        _require_tool(tool)
    hostcheck.refuse_if_qemu_running(self_pid=os.getpid())

    uid, gid = _qemu_identity(arguments.qemu_user)
    root = pathlib.Path(arguments.state_root)
    if not root.exists():
        root.mkdir(mode=0o711, parents=True)
        os.chmod(root, 0o711)
    root_info = root.stat()
    if not root_info.st_mode & stat.S_IXOTH:
        raise hostcheck.Refusal(
            f"{root} must be traversable by the unprivileged QEMU user (mode 0711)"
        )

    release = pathlib.Path(arguments.release_dir)
    try:
        create_state_directory(state, uid=uid, gid=gid)
    except FileExistsError as exc:
        raise hostcheck.Refusal(f"state directory already exists: {state}") from exc

    record: dict = {
        "schema": "vprlab-vm-provision-v1",
        "state": str(state),
        "base_image": str(base),
        "base_image_sha512": digest,
        "image_ref": image_id,
        "image_tar": str(image_tar),
        "release_dir": str(release),
        "ipv6_mode": arguments.ipv6_mode,
        "qemu_user": arguments.qemu_user,
        "qemu_uid": uid,
        "qemu_gid": gid,
        "started_at": _utc_now(),
        "test_status": "PROVISIONING",
    }

    process: subprocess.Popen | None = None
    try:
        overlay = state / guest.OVERLAY_FILE
        environment = guest.qemu_env(dict(os.environ))
        subprocess.run(
            guest.build_qemu_img_create_argv(base, overlay),
            env=environment,
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
        os.chmod(overlay, 0o600)
        os.chown(overlay, uid, gid)

        staging = _stage_payload(state, release, image_tar)
        user_data = state / "user-data"
        meta_data = state / "meta-data"
        hostname = f"vprlab-{arguments.index:03d}"
        user_data.write_text(
            guest.build_user_data(
                hostname=hostname,
                name=arguments.name,
                image_id=image_id,
                ipv6_mode=arguments.ipv6_mode,
            ),
            encoding="utf-8",
        )
        meta_data.write_text(
            guest.build_meta_data(
                hostname=hostname, instance_id=f"vprlab-vm-{arguments.index:03d}"
            ),
            encoding="utf-8",
        )
        os.chmod(user_data, 0o644)
        os.chmod(meta_data, 0o644)

        seed = state / guest.SEED_ISO
        subprocess.run(
            guest.build_seed_iso_argv(seed, user_data, meta_data),
            env=environment,
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
        payload_iso = state / guest.PAYLOAD_ISO
        subprocess.run(
            guest.build_payload_iso_argv(payload_iso, staging),
            env=environment,
            check=True,
            capture_output=True,
            text=True,
            timeout=600,
        )
        os.chmod(seed, 0o644)
        os.chmod(payload_iso, 0o644)

        qemu_argv = guest.build_qemu_argv("provision", state, name=arguments.name)
        launch_argv = guest.build_launch_argv(
            qemu_argv, arguments.qemu_user, uid=uid, gid=gid
        )
        record["qemu_argv"] = qemu_argv
        record["launch_argv"] = launch_argv
        record["payload_iso"] = str(payload_iso)
        record["seed_iso"] = str(seed)

        with (state / guest.QEMU_LOG_FILE).open("xb") as log:
            process = subprocess.Popen(
                launch_argv,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        record["qemu_pid"] = process.pid
        record["qemu_started_at"] = _utc_now()
        _atomic_json(state / "provision.json", record)

        marker = _wait_for_marker(
            process, state / guest.SERIAL_FILE, PROVISION_TIMEOUT
        )
        try:
            status = process.wait(timeout=POWEROFF_TIMEOUT)
        except subprocess.TimeoutExpired as exc:
            raise hostcheck.Refusal(
                "guest printed the completion marker but did not power off"
            ) from exc
        if status != 0:
            raise hostcheck.Refusal(f"QEMU exited with status {status} after provisioning")
        if image_id not in marker:
            raise hostcheck.Refusal("completion marker does not name the expected image")
        record["serial_marker"] = marker
        record["finished_at"] = _utc_now()
        record["qemu_exit_status"] = status
        record["test_status"] = "PROVISIONED_OFFLINE_READY"
        _atomic_json(state / "provision.json", record)
        print(json.dumps({"state": str(state), "status": record["test_status"]}, sort_keys=True))
        return 0
    except (
        OSError,
        subprocess.SubprocessError,
        guest.GeneratorError,
        hostcheck.Refusal,
    ) as exc:
        record["finished_at"] = _utc_now()
        record["test_status"] = "PROVISION_FAILED"
        record["failure"] = exc.__class__.__name__
        try:
            _atomic_json(state / "provision.json", record)
        except OSError:
            pass
        detail = str(exc) if isinstance(exc, hostcheck.Refusal) else exc.__class__.__name__
        raise hostcheck.Refusal(f"provisioning failed: {detail}") from exc
    finally:
        if process is not None:
            _terminate(process)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="provision the vprlab leak VM once")
    parser.add_argument("--index", type=int, default=guest.DEFAULT_INDEX)
    parser.add_argument("--state-root", default=str(guest.STATE_ROOT))
    parser.add_argument("--name", default=guest.DEFAULT_NAME)
    parser.add_argument("--image-id", default=guest.DEPLOYED_IMAGE_ID)
    parser.add_argument("--image-tar", required=True)
    parser.add_argument("--release-dir", default=str(guest.RELEASE_DIR))
    parser.add_argument("--base-image", default=str(guest.BASE_IMAGE))
    parser.add_argument("--checksum-manifest", default=str(guest.CHECKSUM_MANIFEST))
    parser.add_argument("--qemu-user", default=guest.QEMU_USER)
    parser.add_argument(
        "--ipv6-mode",
        default="netns-safe",
        choices=("kernel-disable", "netns-safe"),
        help=(
            "netns-safe (default, controller decision) disables IPv6 on every "
            "interface but keeps the sysctl tree, because the deployed compose "
            "writes net.ipv6.conf.all.forwarding and would fail under "
            "ipv6.disable=1; any IPv6 frame on the tap is still a finding"
        ),
    )
    arguments = parser.parse_args(argv)
    try:
        guest.validate_name(arguments.name)
        guest.validate_image_id(arguments.image_id)
        return provision(arguments)
    except (hostcheck.Refusal, guest.GeneratorError, guest.IntegrityError) as exc:
        print(f"provision: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"provision: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
