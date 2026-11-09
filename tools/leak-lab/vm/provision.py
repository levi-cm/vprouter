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
import shutil
import signal
import stat
import subprocess
import sys
import time

_REAL_POPEN = subprocess.Popen

import guest
import hostcheck
import rootfs
import runlock

PROVISION_TIMEOUT = 1800.0
POWEROFF_TIMEOUT = 180.0
#: Provision writes a diagnostic serial file.  The guest is untrusted, so the
#: file is capped (and QEMU has RLIMIT_FSIZE below as a second bound).
SERIAL_SIZE_CAP = 64 * 1024 * 1024
PROVISION_QEMU_FSIZE_LIMIT = 8 * 1024 * 1024 * 1024
PROVISION_DISK_REQUIRED = 8 * 1024 * 1024 * 1024


class ProvisionInterrupted(RuntimeError):
    """A termination signal arrived; unwind through the child reaper."""


_signal_seen = False
_signal_number: int | None = None
_signal_raised = False


def check_interrupt() -> None:
    """Raise ProvisionInterrupted once if a termination signal arrived."""
    global _signal_raised
    if _signal_seen and not _signal_raised:
        _signal_raised = True
        raise ProvisionInterrupted(f"received signal {_signal_number}")


def install_signal_handlers() -> None:
    global _signal_seen, _signal_number, _signal_raised
    _signal_seen = False
    _signal_number = None
    _signal_raised = False

    def handle(signum, _frame):
        # Deferred: only record the signal.  Raising from the handler could
        # interrupt subprocess.Popen() before the child handle exists and
        # orphan QEMU; every wait loop calls check_interrupt() instead.
        global _signal_seen, _signal_number
        if not _signal_seen:
            _signal_seen = True
            _signal_number = signum

    for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(signum, handle)


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def require_root() -> None:
    """Separate function so offline tests can exercise the rest as non-root."""
    if os.geteuid() != 0:
        raise hostcheck.Refusal("provisioning requires root")


def _atomic_json(path: pathlib.Path, document: dict) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(document, stream, indent=2, sort_keys=True)
        stream.write("\n")


def _write_json_fd(descriptor: int, document: dict) -> None:
    payload = (
        json.dumps(document, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    os.lseek(descriptor, 0, os.SEEK_SET)
    os.ftruncate(descriptor, 0)
    os.write(descriptor, payload)
    os.fsync(descriptor)


def _open_private(path: pathlib.Path, flags: int, mode: int = 0o600) -> int:
    """Open a leaf without following a symlink planted by the state owner."""
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return os.open(path, flags, mode)


def _qemu_identity(user: str) -> tuple[int, int]:
    try:
        return guest.resolve_unprivileged_user(user)
    except guest.GeneratorError as exc:
        raise hostcheck.Refusal(str(exc)) from exc


def set_provision_limits() -> None:
    """Bound the provisioning process's own file writes at 8 GiB.

    QEMU gets the same limit explicitly after spawn.  The staging copies this
    process writes (image tar/release payload) are therefore capped too.
    """
    import resource

    soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    target = PROVISION_QEMU_FSIZE_LIMIT
    if hard != resource.RLIM_INFINITY:
        target = min(target, hard)
    if soft != resource.RLIM_INFINITY:
        target = min(target, soft)
    if target > 0:
        resource.setrlimit(resource.RLIMIT_FSIZE, (target, hard))


def _free_bytes(path: pathlib.Path) -> int:
    candidate = pathlib.Path(path)
    while not candidate.exists():
        if candidate.parent == candidate:
            break
        candidate = candidate.parent
    try:
        stats = os.statvfs(candidate)
    except OSError as exc:
        raise hostcheck.Refusal("cannot measure free disk space") from exc
    return stats.f_bavail * stats.f_frsize


def check_provision_admission(
    state_root: pathlib.Path, *, free_bytes: int | None = None
) -> None:
    """Refuse provisioning without room for the overlay, serial and staging."""
    if free_bytes is None:
        free_bytes = _free_bytes(state_root)
    if free_bytes < PROVISION_DISK_REQUIRED:
        raise hostcheck.Refusal(
            "free space on the state filesystem is below "
            f"{PROVISION_DISK_REQUIRED // (1024 * 1024 * 1024)} GiB; "
            "refusing to provision"
        )


def _apply_qemu_limits(process: subprocess.Popen) -> None:
    """Reset inherited RLIMIT_AS and bound the guest-writable host files."""
    import resource

    if not isinstance(process, _REAL_POPEN):
        return
    for name, value in (
        (resource.RLIMIT_AS, resource.RLIM_INFINITY),
        (resource.RLIMIT_FSIZE, PROVISION_QEMU_FSIZE_LIMIT),
    ):
        try:
            resource.prlimit(process.pid, name, (value, value))
        except (ProcessLookupError, PermissionError):
            return
        except (OSError, ValueError):
            continue


def _require_tool(path: pathlib.Path) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise hostcheck.Refusal(f"staged tool is missing: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise hostcheck.Refusal(f"staged tool is not a regular file: {path}")
    if not os.access(path, os.X_OK):
        raise hostcheck.Refusal(f"staged tool is not executable: {path}")
    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise hostcheck.Refusal(
            f"staged tool is writable by a non-root account: {path}"
        )
    if os.geteuid() == 0 and info.st_uid != 0:
        raise hostcheck.Refusal(f"staged tool is not owned by root: {path}")


def _run_generator(
    argv: list[str],
    *,
    uid: int,
    gid: int,
    what: str,
    timeout: float,
    umask: int | None = None,
) -> None:
    """Run qemu-img/genisoimage as the QEMU user, never as root."""
    if umask is None:
        wrapper = guest.build_setpriv_argv(argv, uid, gid)
    else:
        wrapper = guest.build_private_tool_argv(argv, uid, gid, umask=umask)
    try:
        completed = subprocess.run(
            wrapper,
            env=guest.clean_environment(),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise hostcheck.Refusal(
            f"{what} could not run as the QEMU user: {exc.__class__.__name__}"
        ) from exc
    if completed.returncode != 0:
        raise hostcheck.Refusal(f"{what} failed with status {completed.returncode}")


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
    """Stage release + image tar for the read-only payload ISO.

    Staging is created while the state directory is still root-owned; every
    entry is made world-readable so ``genisoimage`` (running as the QEMU user)
    can read it after the directory is handed over.
    """
    staging = state / "payload"
    staging.mkdir(mode=0o755)
    os.chmod(staging, 0o755)
    _copy_release(release, staging / "release")
    (staging / "unit").mkdir(mode=0o755)
    unit = release / guest.UNIT_SOURCE
    if not unit.is_file():
        raise hostcheck.Refusal(f"release unit file is missing: {unit}")
    shutil.copyfile(unit, staging / "unit" / "vprouter@.service")
    os.chmod(staging / "unit" / "vprouter@.service", 0o644)

    (staging / "image").mkdir(mode=0o755)
    destination = staging / "image" / "vprouter-image.tar"
    # Never hard-link an operator input: the recursive mode normalisation
    # below would also chmod the source inode outside the lab.
    shutil.copyfile(image_tar, destination)
    os.chmod(destination, 0o644)
    for root, directories, files in os.walk(staging):
        os.chmod(root, stat.S_IMODE(os.stat(root).st_mode) | 0o555)
        for name in directories:
            path = pathlib.Path(root) / name
            os.chmod(path, stat.S_IMODE(path.stat().st_mode) | 0o555)
        for name in files:
            path = pathlib.Path(root) / name
            os.chmod(path, stat.S_IMODE(path.stat().st_mode) | 0o444)
    return staging


def _wait_for_marker(process: subprocess.Popen, serial: pathlib.Path, timeout: float) -> str:
    deadline = time.monotonic() + timeout
    marker = b"VPRLAB-PROVISION-OK "
    collected = b""
    while time.monotonic() < deadline:
        check_interrupt()
        if serial.is_file():
            try:
                flags = os.O_RDONLY
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                descriptor = os.open(serial, flags)
                with os.fdopen(descriptor, "rb") as stream:
                    stream.seek(0, os.SEEK_END)
                    size = stream.tell()
                    if size > SERIAL_SIZE_CAP:
                        # The guest filled the diagnostic console file.  Stop
                        # QEMU now; the caller's failure path also reaps it.
                        _terminate(process)
                        raise hostcheck.Refusal(
                            "guest serial output exceeded the 64 MiB cap"
                        )
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
    require_root()
    state = guest.state_path(arguments.index, pathlib.Path(arguments.state_root))
    if state.exists():
        raise hostcheck.Refusal(f"state directory already exists: {state}")

    lock_fd = runlock.acquire(arguments.run_lock)
    try:
        return _provision_locked(arguments, state)
    finally:
        runlock.release(lock_fd)


def _provision_locked(arguments: argparse.Namespace, state: pathlib.Path) -> int:
    uid, gid = _qemu_identity(arguments.qemu_user)
    check_provision_admission(pathlib.Path(arguments.state_root))
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
    try:
        guest.verify_tool_ancestry()
    except guest.GeneratorError as exc:
        raise hostcheck.Refusal(str(exc)) from exc
    # The global lock is held, so this check and the later QEMU launch are
    # one admission decision.
    hostcheck.refuse_if_qemu_running(self_pid=os.getpid())

    root = pathlib.Path(arguments.state_root)
    expected_uid = 0 if os.geteuid() == 0 else os.geteuid()
    try:
        descriptor = rootfs.open_directory(
            root, create=True, mode=0o755, expected_uid=expected_uid
        )
    except rootfs.PathError as exc:
        raise hostcheck.Refusal(f"state root is not trustworthy: {exc}") from exc
    os.close(descriptor)

    release = pathlib.Path(arguments.release_dir)
    try:
        create_state_directory(state)
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
    record_fd: int | None = None
    log_fd: int | None = None
    try:
        overlay = state / guest.OVERLAY_FILE
        staging = _stage_payload(state, release, image_tar)
        user_data = state / "user-data"
        meta_data = state / "meta-data"
        hostname = f"vprlab-{arguments.index:03d}"
        for path, text in (
            (
                user_data,
                guest.build_user_data(
                    hostname=hostname,
                    name=arguments.name,
                    image_id=image_id,
                    ipv6_mode=arguments.ipv6_mode,
                ),
            ),
            (
                meta_data,
                guest.build_meta_data(
                    hostname=hostname,
                    instance_id=f"vprlab-vm-{arguments.index:03d}",
                ),
            ),
        ):
            descriptor = _open_private(
                path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644
            )
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(text)
        record_fd = _open_private(
            state / "provision.json", os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600
        )
        log_fd = _open_private(
            state / guest.QEMU_LOG_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        _write_json_fd(record_fd, record)

        # From here on every write inside the state directory is done by the
        # QEMU user; root only keeps the already-open descriptors above.
        os.chmod(state, 0o700)
        os.chown(state, uid, gid)

        _run_generator(
            guest.build_qemu_img_create_argv(base, overlay),
            uid=uid,
            gid=gid,
            what="qemu-img create",
            timeout=120,
            umask=0o077,
        )

        seed = state / guest.SEED_ISO
        payload_iso = state / guest.PAYLOAD_ISO
        _run_generator(
            guest.build_seed_iso_argv(seed, user_data, meta_data),
            uid=uid,
            gid=gid,
            what="genisoimage seed",
            timeout=120,
        )
        _run_generator(
            guest.build_payload_iso_argv(payload_iso, staging),
            uid=uid,
            gid=gid,
            what="genisoimage payload",
            timeout=600,
        )

        qemu_argv = guest.build_qemu_argv("provision", state, name=arguments.name)
        launch_argv = guest.build_launch_argv(
            qemu_argv, arguments.qemu_user, uid=uid, gid=gid
        )
        record["qemu_argv"] = qemu_argv
        record["launch_argv"] = launch_argv
        record["payload_iso"] = str(payload_iso)
        record["seed_iso"] = str(seed)

        with os.fdopen(log_fd, "wb") as log:
            log_fd = None
            process = subprocess.Popen(
                launch_argv,
                env=guest.clean_environment(),
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                restore_signals=True,
            )
            _apply_qemu_limits(process)
        check_interrupt()
        record["qemu_pid"] = process.pid
        record["qemu_started_at"] = _utc_now()
        _write_json_fd(record_fd, record)

        marker = _wait_for_marker(
            process, state / guest.SERIAL_FILE, PROVISION_TIMEOUT
        )
        poweroff_deadline = time.monotonic() + POWEROFF_TIMEOUT
        while True:
            check_interrupt()
            try:
                status = process.wait(timeout=0.5)
                break
            except subprocess.TimeoutExpired:
                if time.monotonic() >= poweroff_deadline:
                    raise hostcheck.Refusal(
                        "guest printed the completion marker but did not power off"
                    ) from None
        if status != 0:
            raise hostcheck.Refusal(f"QEMU exited with status {status} after provisioning")
        if image_id not in marker:
            raise hostcheck.Refusal("completion marker does not name the expected image")
        record["serial_marker"] = marker
        record["finished_at"] = _utc_now()
        record["qemu_exit_status"] = status
        record["test_status"] = "PROVISIONED_OFFLINE_READY"
        if record_fd is not None:
            _write_json_fd(record_fd, record)
        print(json.dumps({"state": str(state), "status": record["test_status"]}, sort_keys=True))
        return 0
    except (
        OSError,
        subprocess.SubprocessError,
        guest.GeneratorError,
        hostcheck.Refusal,
        ProvisionInterrupted,
    ) as exc:
        record["finished_at"] = _utc_now()
        record["test_status"] = "PROVISION_FAILED"
        record["failure"] = exc.__class__.__name__
        if record_fd is not None:
            try:
                _write_json_fd(record_fd, record)
            except OSError:
                pass
        detail = str(exc) if isinstance(exc, hostcheck.Refusal) else exc.__class__.__name__
        raise hostcheck.Refusal(f"provisioning failed: {detail}") from exc
    finally:
        if process is not None:
            _terminate(process)
        for descriptor in (log_fd, record_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


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
    parser.add_argument("--run-lock", default=str(runlock.RUN_LOCK))
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
    install_signal_handlers()
    try:
        set_provision_limits()
    except (OSError, ValueError) as exc:
        print(f"provision: cannot set the file-size limit: {exc}", file=sys.stderr)
        return 2
    try:
        guest.validate_name(arguments.name)
        guest.validate_image_id(arguments.image_id)
        return provision(arguments)
    except (hostcheck.Refusal, guest.GeneratorError, guest.IntegrityError) as exc:
        print(f"provision: {exc}", file=sys.stderr)
        return 2
    except ProvisionInterrupted as exc:
        print(f"provision: interrupted ({exc})", file=sys.stderr)
        return 2
    except (OSError, runlock.LockError) as exc:
        print(f"provision: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
