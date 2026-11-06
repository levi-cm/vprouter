#!/usr/bin/env python3
"""Exclusive fresh-lab run411 reservation and fail-closed generation replacement.

One global claim spans every generation. Supersession never resets that claim.
The durable tombstone is written before the old reservation is moved. Interrupted
supersession fails closed; there is deliberately no automatic repair/reset API.
"""
import argparse
import contextlib
import functools
import datetime
import fcntl
import hashlib
import io
import importlib.util
import types
import tempfile
import tarfile
import subprocess
import json
import os
import pathlib
import re
import stat

if not __debug__:
    raise RuntimeError('optimized_python_refused')

RESERVATION = pathlib.Path('target/lab-state/run-411-reservation.json')
SUPERSESSION = pathlib.Path('target/lab-state/run-411-supersession.json')
CLAIM = pathlib.Path('target/lab-state/run-411-consumed.json')
LOCK = pathlib.Path('target/lab-state/run-411.lock')
RUN = pathlib.Path('target/lab-state/actual-program-run-411.json')
CANDIDATE = pathlib.Path('target/candidates/run410-da75562-20261104/candidate.json')
PLATFORM = 'debian-arm64'
LABEL = 'bootstrap411-arm64'
# Existing lab storage indirections: translate explicitly, never follow them.
TRUSTED_STORAGE_BRIDGES = {
    pathlib.Path('/DATA/AppData/vprouter-rust-v2/target')/name: pathlib.Path('/DATA/vprouter-lab')/name
    for name in ('lab-state', 'candidates', 'run411-prep', 'platform-lab')
}


def allowed_path(path, _observed=None):
    """Refuse old chains and aliases without opening their content.

    The frozen run410 candidate directory is an input, not the old execution
    chain. Its bootstrap409/410 evidence subdirectories remain forbidden.
    Reject every symlink component and every multiply linked regular inode;
    detecting hardlink aliases this way needs no traversal of preserved data.
    """
    path = pathlib.Path(path)
    assert '..' not in path.parts, 'parent_traversal_forbidden'
    # Linux treats // as /, while PurePath preserves that spelling.
    absolute = pathlib.Path('/'+str(path.absolute()).lstrip('/'))
    preserved = pathlib.Path('/DATA/vprouter-lab/preserved')
    assert absolute != preserved and preserved not in absolute.parents, 'preserved_access_forbidden'
    for index, part in enumerate(absolute.parts):
        # Also permit a collector's files/target/candidates snapshot of it.
        if part == 'run410-da75562-20261104' and (
            absolute.parts[index-2:index] == ('target', 'candidates') or
            pathlib.Path(*absolute.parts[:index]) == pathlib.Path('/DATA/vprouter-lab/candidates')
        ):
            tail = absolute.parts[index+1:]
            assert not tail or tail[0] in {
                'candidate.json', 'root-verification.json', 'source.tar',
                'arm64.payload', 'arm64.context.tar',
                'authored-host-baseline-debian-arm64.json',
                'host-baseline-reconciliation-debian-arm64.json',
                'host-projection-debian-arm64', 'bootstrap411-arm64',
            }, 'run410_candidate_evidence_forbidden'
            continue
        match = re.search(r'(?:run-?|bootstrap)(409|410)(?![0-9])', part)
        assert match is None, 'run'+match[1]+'_access_forbidden' if match else ''
    current = pathlib.Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try: info = current.lstat()
        except FileNotFoundError: break
        if stat.S_ISLNK(info.st_mode) and current in TRUSTED_STORAGE_BRIDGES:
            backing = TRUSTED_STORAGE_BRIDGES[current]
            assert os.readlink(current) == str(backing), 'storage_bridge_changed'
            translated = allowed_path(backing/absolute.relative_to(current), _observed)
            after = current.lstat()
            assert (info.st_dev, info.st_ino) == (after.st_dev, after.st_ino), 'storage_bridge_inode_changed'
            return translated
        if _observed is not None: _observed[str(current)] = info
        assert not stat.S_ISLNK(info.st_mode), 'symlink_access_forbidden'
        if stat.S_ISREG(info.st_mode):
            assert info.st_nlink == 1, 'hardlink_access_forbidden'
    return path


def parent_fd(path):
    """Walk from / with O_NOFOLLOW at every directory component."""
    path = allowed_path(path).absolute()
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd); fd = child
        return fd, path.name
    except BaseException:
        os.close(fd); raise


class Acquired:
    """Bytes, digest and descriptor metadata from one guarded acquisition."""
    def __init__(self, data, info):
        self.data, self.info = data, info
        self.sha256 = hashlib.sha256(data).hexdigest()


_captures = None


def freeze_inputs(reset=False):
    global _captures
    if reset or _captures is None: _captures = {}


@contextlib.contextmanager
def input_scope():
    global _captures
    owner = _captures is None
    if owner: _captures = {}
    try: yield
    finally:
        if owner: _captures = None


def captured_call(function):
    @functools.wraps(function)
    def call(*args, **kwargs):
        with input_scope(): return function(*args, **kwargs)
    return call


def acquire(path):
    observed = {}
    admitted = allowed_path(path, observed)
    key = str(admitted.absolute())
    if _captures is not None and key in _captures: return _captures[key]
    before = observed.get(key)
    if before is None: raise FileNotFoundError(str(path))
    parent, name = parent_fd(admitted)
    try:
        assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'unsafe_input_inode'
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
        try:
            after = os.fstat(fd)
            assert (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino), 'input_inode_changed'
            assert stat.S_ISREG(after.st_mode) and after.st_nlink == 1, 'unsafe_input_inode'
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                data = stream.read()
            final = os.fstat(fd)
            assert (after.st_dev, after.st_ino, after.st_nlink, after.st_size, after.st_mtime_ns, after.st_ctime_ns) == (final.st_dev, final.st_ino, final.st_nlink, final.st_size, final.st_mtime_ns, final.st_ctime_ns), 'input_changed_during_read'
            captured = Acquired(data, final)
            if _captures is not None: _captures[key] = captured
            return captured
        finally: os.close(fd)
    finally: os.close(parent)


def open_read(path):
    """Compatibility stream over captured bytes, never a pathname reopen."""
    return io.BytesIO(acquire(path).data)


def read_bytes(path):
    return acquire(path).data


def read_text(path):
    return read_bytes(path).decode()


def open_exclusive(path):
    parent, name = parent_fd(path)
    try: return os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
    finally: os.close(parent)


def check_references(value):
    """Check recursive JSON reference paths before any consumer follows them."""
    if isinstance(value, dict):
        for key, child in value.items():
            if key in ('path', 'retained_path', 'candidate', 'record', 'claim') and isinstance(child, str): allowed_path(child)
            else: check_references(child)
    elif isinstance(value, list):
        for child in value: check_references(child)


def sha(path):
    return acquire(path).sha256


def encoded(data):
    return (json.dumps(data, indent=2, allow_nan=False)+'\n').encode()


def sync_directory(path):
    parent, name = parent_fd(path)
    try: fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    finally: os.close(parent)
    try: os.fsync(fd)
    finally: os.close(fd)


def write_new(path, data):
    fd = open_exclusive(path)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    sync_directory(pathlib.Path(path).parent)


def save(path, data):
    write_new(path, encoded(data))


def protected(path):
    captured = acquire(path); info = captured.info
    assert stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
    assert stat.S_IMODE(info.st_mode) == 0o600 and 0 < len(captured.data) == info.st_size <= 1024*1024
    return json.loads(captured.data)


def lock():
    parent, name = parent_fd(LOCK)
    try: fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
    finally: os.close(parent)
    try:
        info = os.fstat(fd)
        assert stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except BaseException:
        os.close(fd); raise


def binding_paths():
    """Mandatory execution AND post-run chain, rather than optional user bindings."""
    return [CANDIDATE,
            CANDIDATE.parent/('authored-host-baseline-'+PLATFORM+'.json'),
            CANDIDATE.parent/('host-baseline-reconciliation-'+PLATFORM+'.json'),
            CANDIDATE.parent/('host-projection-'+PLATFORM)/'record.json',
            *map(pathlib.Path, ['target/run411-prep/baseline-comparison.json',
                 'target/run411-prep/admission.json', 'target/run411-prep/guest-gates.json']),
            CANDIDATE.parent/'root-verification.json',
            *map(pathlib.Path, ['target/platform-lab/run-frozen-secret-bootstrap411.py',
                 'target/platform-lab/secret-bootstrap.guest.py',
                 'target/platform-lab/attachment_context_check.py',
                 'target/platform-lab/quarantine_host_declaration.py',
                 'target/platform-lab/host_baseline_declaration.py',
                 'target/platform-lab/run-frozen-host-projection.py',
                 'tools/rust-v2-lab/run411-provenance.py',
                 'target/inspect-secret-bootstrap411-failure.py',
                 'target/archive-secret-bootstrap411-selectors.py',
                 'tools/rust-v2-lab/fresh-baseline.py',
                 'tools/rust-v2-lab/phase3-readonly-preflight.py',
                 'tools/rust-v2-lab/run411-reservation.py',
                 'tools/rust-v2-lab/collect-run411-evidence.py',
                 'tools/rust-v2-lab/inspect-run411-state.py',
                 'tools/rust-v2-lab/parse-bootstrap-cost-diagnostics.py',
                 'tools/rust-v2-lab/source-manifest411.json',
                 'target/run411-prep/guest-identity.json',
                 'tools/rust-v2-lab/rebuild-20261103-build.py',
                 'tools/verify-frozen-build-inputs.py',
                 'target/quarantine_evidence_base.py',
                 'target/run411-prep/inventory-arm64.json',
                 'target/run411-prep/tcg-budgets.json',
                 CANDIDATE.parent/'arm64.payload', CANDIDATE.parent/'arm64.context.tar',
                 'target/platform-lab/start-clean-debian-arm64.py',
                 'target/platform-lab/debian-arm64/known_hosts',
                 'target/platform-lab/debian-arm64/process.json'])]


def next_supersession(digest):
    assert isinstance(digest, str) and len(digest) == 64 and all(c in '0123456789abcdef' for c in digest)
    return SUPERSESSION.with_name(SUPERSESSION.stem+'-'+digest+'.json')


@captured_call
def supersession_chain():
    """Verify every immutable tombstone and retained generation, in order.

    The first receipt keeps its original pathname/bytes. Later receipts are
    append-only and keyed by the generation they retire. A pending receipt also
    advances the expected active digest, so interrupted replacement fails closed.
    """
    chain = []; path = SUPERSESSION; previous = None; seen = set()
    while os.path.lexists(path):
        receipt = protected(path)
        assert receipt['schema'] == 1 and receipt['run'] == 411
        assert receipt['old_budget_unconsumed'] is True and receipt['total_one_shot_budget'] == 1
        assert receipt['claim'] == str(CLAIM)
        old, new = receipt['superseded_sha256'], receipt['replacement_sha256']
        next_path = next_supersession(new)
        assert old != new and old not in seen and new not in seen
        retained = RESERVATION.with_name('run-411-reservation.superseded-'+old+'.json')
        assert receipt['retained_path'] == str(retained)
        data = protected(retained)
        assert sha(retained) == old and data['run'] == 411 and data['one_shot_budget'] == 1
        if previous is not None:
            assert old == previous['replacement_sha256']
            assert data['schema'] == 2 and data['supersedes_sha256'] == previous['superseded_sha256']
        seen.add(old); chain.append((path, receipt)); previous = receipt; path = next_path
    return chain


@captured_call
def active():
    """Read active generation, even after consumption; never claims or writes."""
    data = protected(RESERVATION)
    assert type(data['schema']) is int and data['schema'] == 2
    chain = supersession_chain()
    if chain:
        receipt = chain[-1][1]
        assert data['supersedes_sha256'] == receipt['superseded_sha256'] != sha(RESERVATION)
        assert sha(RESERVATION) == receipt['replacement_sha256']
    else:
        assert data['supersedes_sha256'] is None
    return data


@captured_call
def validate_bindings(data):
    check_references(data)
    assert type(data['run']) is int and data['run'] == 411
    assert type(data['one_shot_budget']) is int and data['one_shot_budget'] == 1
    assert data['historical_high_water_mark'] == 410 and data['historical_raw_records_recovered'] is False
    assert data['continuity'] == 'fresh-lab'
    assert (data['candidate'], data['platform'], data['label'], data['mode']) == (str(CANDIDATE), PLATFORM, LABEL, 'success')
    refs = {ref['path']: ref['sha256'] for ref in data['bindings']}
    assert len(refs) == len(data['bindings']) and set(refs) == {str(p) for p in binding_paths()}
    for path, digest in refs.items():
        assert sha(path) == digest, ('reservation_binding_drift', path)
    return data


def unspent():
    assert not any(os.path.lexists(p) for p in (CLAIM, RUN, CANDIDATE.parent/LABEL))


@captured_call
def validate(path, candidate, platform, label, mode):
    assert pathlib.Path(path) == RESERVATION and pathlib.Path(candidate) == CANDIDATE
    assert (platform, label, mode) == (PLATFORM, LABEL, 'success')
    unspent()
    return validate_bindings(active())


@captured_call
def admit(path, candidate, platform, label, mode, preflight=False, provenance_check=None):
    fd = lock()
    try:
        data = validate(path, candidate, platform, label, mode)
        if provenance_check is not None: provenance_check()
        if not preflight:
            assert data['controller_boot_id'] == read_text('/proc/sys/kernel/random/boot_id').strip()
            save(CLAIM, dict(reservation=str(path), reservation_sha256=sha(path), run=411,
                            pid=os.getpid(), controller_boot_id=data['controller_boot_id'],
                            started_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                            budget_remaining=0, policy='No retry, including failure before raw-record creation.'))
        return fd, data
    except BaseException:
        os.close(fd); raise


@captured_call
def replacement(supersedes=None):
    admission = json.loads(read_bytes('target/run411-prep/admission.json'))
    identity = json.loads(read_bytes('target/run411-prep/guest-identity.json'))
    assert identity['boot_id'] == admission['boot_id']
    process=json.loads(read_bytes('target/platform-lab/debian-arm64/process.json'))
    assert process['instance_id'].startswith('vprouter-run411-') and process['platform']==PLATFORM
    assert identity['process_pid']==process['pid'] and identity['process_start_time']==process['start_time']
    assert identity['known_hosts_sha256'] == sha('target/platform-lab/debian-arm64/known_hosts')
    return dict(schema=2, run=411, candidate=str(CANDIDATE), platform=PLATFORM, label=LABEL,
                mode='success', one_shot_budget=1, continuity='fresh-lab', historical_high_water_mark=410,
                historical_raw_records_recovered=False, unavailable_historical_runs=list(range(398,409)), preserved_prior_run=409,
                guest_boot_id=admission['boot_id'],
                controller_boot_id=read_text('/proc/sys/kernel/random/boot_id').strip(),
                supersedes_sha256=supersedes,
                bindings=[dict(path=str(p), sha256=sha(p)) for p in binding_paths()],
                created_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(), execution_authorized_by_this_phase=False)


@captured_call
def supersede(expected_sha256, reason, new):
    """Caller holds LOCK. Tombstone and old bytes survive any later failure."""
    unspent()
    old = protected(RESERVATION)
    assert old['run'] == 411 and old['one_shot_budget'] == 1
    assert sha(RESERVATION) == expected_sha256
    if os.path.lexists(SUPERSESSION): active()
    receipt_path = next_supersession(expected_sha256) if os.path.lexists(SUPERSESSION) else SUPERSESSION
    assert not os.path.lexists(receipt_path) and reason.strip()
    assert new['schema'] == 2 and new['run'] == 411 and new['one_shot_budget'] == 1
    assert new['supersedes_sha256'] == expected_sha256
    retained = RESERVATION.with_name('run-411-reservation.superseded-'+expected_sha256+'.json')
    assert not os.path.lexists(retained)
    receipt = dict(schema=1, run=411, superseded_sha256=expected_sha256, retained_path=str(retained),
                   replacement_sha256=hashlib.sha256(encoded(new)).hexdigest(), reason=reason,
                   old_budget_unconsumed=True, total_one_shot_budget=1, claim=str(CLAIM),
                   observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
    save(receipt_path, receipt)
    parent, name = parent_fd(RESERVATION)
    try:
        # Both names are in this pinned directory, including through storage bridges.
        allowed_path(retained)
        os.link(name, retained.name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
        os.unlink(name, dir_fd=parent)
    finally: os.close(parent)
    sync_directory(RESERVATION.parent)
    save(RESERVATION, new)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['reserve', 'supersede'])
    parser.add_argument('--expected-sha256'); parser.add_argument('--reason')
    args = parser.parse_args()
    fd = lock()
    try:
        unspent()
        if args.action == 'reserve':
            assert not os.path.lexists(RESERVATION) and not os.path.lexists(SUPERSESSION)
            save(RESERVATION, replacement())
        else:
            supersede(args.expected_sha256, args.reason, replacement(args.expected_sha256))
        validate_bindings(active())
        print(json.dumps(dict(reservation=str(RESERVATION), sha256=sha(RESERVATION), run411_executed=False, budget_remaining=1)))
    finally: os.close(fd)





class ByteTarfiles:
    """Adapt the frozen checker to bytes; a pathname is a type error."""
    @staticmethod
    def open(data):
        assert type(data) is bytes, 'tar_requires_acquired_bytes'
        return tarfile.open(fileobj=io.BytesIO(data), mode='r:')


class GuardAPI:
    def __getattr__(self, name): return globals()[name]


def load_module(name, path):
    """Compile the bytes we acquired, never ask an import loader to reopen."""
    captured = acquire(path)
    module = types.ModuleType(name); module.__file__ = str(path); module.__captured_source__ = captured.data
    module.__dict__['_run411_guard'] = GuardAPI()
    exec(compile(captured.data, str(path), 'exec'), module.__dict__)
    return module


def verify_source(data, commit):
    """Frozen build-input verifier, with bytes replacing its pathname API."""
    assert type(data) is bytes and re.fullmatch(r'[a-f0-9]{40}', commit)
    names = subprocess.check_output(['git', 'ls-tree', '-rz', '--name-only', commit]).decode().split('\0')
    required = {n for n in names if n in ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml',
        'docs/rust-v2/programs-amd64.json', 'docs/rust-v2/programs-arm64.json')
        or n.startswith(('crates/', 'examples/v2/'))}
    assert {'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml'} <= required
    seen = {}
    with ByteTarfiles.open(data) as archive:
        for item in archive:
            if item.isdir(): continue
            assert item.isfile() and item.name in required and item.name not in seen, item.name
            assert item.size < 16 * 1024 * 1024, item.name
            raw = archive.extractfile(item).read()
            assert raw == subprocess.check_output(['git', 'show', commit + ':' + item.name]), item.name
            seen[item.name] = hashlib.sha256(raw).hexdigest()
    assert set(seen) == required, sorted(required - set(seen))
    aggregate = hashlib.sha256()
    for name, digest in sorted(seen.items()): aggregate.update((name + '\0' + digest + '\n').encode())
    return dict(source_commit=commit, source_archive_sha256=hashlib.sha256(data).hexdigest(),
        tracked_build_inputs_verified=len(seen), source_aggregate_sha256=aggregate.hexdigest())

@contextlib.contextmanager
def transfer_fd(data):
    """Anonymous, sealed SCP source built exclusively from acquired bytes."""
    assert type(data) is bytes
    fd = os.memfd_create('run411-verified-transfer', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(data); stream.flush()
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        os.lseek(fd, 0, os.SEEK_SET)
        yield fd
    finally: os.close(fd)


@contextlib.contextmanager
def ssh_material(identity, known_hosts):
    """OpenSSH children see only private, exclusively staged acquired bytes.

    SCP may close inherited descriptors before launching its SSH child, so
    credentials/pins use fresh private names rather than /proc fd references.
    """
    key = acquire(identity).data; pins = acquire(known_hosts).data
    with tempfile.TemporaryDirectory(prefix='run411-ssh-') as directory:
        private = pathlib.Path(directory)
        assert stat.S_IMODE(private.stat().st_mode) == 0o700
        key_path, pin_path = private/'identity', private/'known_hosts'
        write_new(key_path, key); write_new(pin_path, pins)
        yield str(key_path), str(pin_path)


if __name__ == '__main__': main()
