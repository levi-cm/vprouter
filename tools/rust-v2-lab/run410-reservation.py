#!/usr/bin/env python3
"""Exclusive fresh-lab run410 reservation and fail-closed generation replacement.

One global claim spans every generation. Supersession never resets that claim.
The durable tombstone is written before the old reservation is moved. Interrupted
supersession fails closed; there is deliberately no automatic repair/reset API.
"""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
import pathlib
import stat

if not __debug__:
    raise RuntimeError('optimized_python_refused')

RESERVATION = pathlib.Path('target/lab-state/run-410-reservation.json')
SUPERSESSION = pathlib.Path('target/lab-state/run-410-supersession.json')
CLAIM = pathlib.Path('target/lab-state/run-410-consumed.json')
LOCK = pathlib.Path('target/lab-state/run-410.lock')
RUN = pathlib.Path('target/lab-state/actual-program-run-410.json')
CANDIDATE = pathlib.Path('target/candidates/run410-da75562-20261104/candidate.json')
PLATFORM = 'debian-clean-x86_64'
LABEL = 'bootstrap410-driver-cost'


def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def encoded(data):
    return (json.dumps(data, indent=2, allow_nan=False)+'\n').encode()


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def save(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(encoded(data)); stream.flush(); os.fsync(stream.fileno())
    sync_directory(pathlib.Path(path).parent)


def protected(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        assert stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
        assert stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= 1024*1024
        return json.load(stream)


def lock():
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
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
            *map(pathlib.Path, ['target/run410-prep/baseline-comparison.json',
                 'target/run410-prep/admission.json', 'target/run410-prep/guest-gates.json']),
            CANDIDATE.parent/'root-verification.json',
            *map(pathlib.Path, ['target/platform-lab/run-frozen-secret-bootstrap410.py',
                 'target/platform-lab/secret-bootstrap.guest.py',
                 'target/platform-lab/attachment_context_check.py',
                 'target/platform-lab/quarantine_host_declaration.py',
                 'target/platform-lab/host_baseline_declaration.py',
                 'target/platform-lab/run-frozen-host-projection.py',
                 'tools/rust-v2-lab/run410-provenance.py',
                 'target/inspect-secret-bootstrap410-failure.py',
                 'target/archive-secret-bootstrap410-selectors.py',
                 'tools/rust-v2-lab/fresh-baseline.py',
                 'tools/rust-v2-lab/phase3-readonly-preflight.py',
                 'tools/rust-v2-lab/run410-reservation.py',
                 'tools/rust-v2-lab/collect-run410-evidence.py',
                 'tools/rust-v2-lab/inspect-run410-state.py',
                 'tools/rust-v2-lab/parse-bootstrap-cost-diagnostics.py',
                 'tools/rust-v2-lab/source-manifest.json',
                 'target/run410-prep/guest-identity.json',
                 'tools/rust-v2-lab/rebuild-20261103-build.py',
                 'tools/verify-frozen-build-inputs.py',
                 'target/quarantine_evidence_base.py',
                 'target/run410-prep/inventory-amd64.json',
                 'target/run410-prep/inventory-arm64.json',
                 'target/lab-state/run-409-consumed.json',
                 'target/lab-state/actual-program-run-409.json',
                 'target/platform-lab/debian-clean-x86_64/known_hosts',
                 'target/platform-lab/debian-clean-x86_64/process.json'])]


def next_supersession(digest):
    assert isinstance(digest, str) and len(digest) == 64 and all(c in '0123456789abcdef' for c in digest)
    return SUPERSESSION.with_name(SUPERSESSION.stem+'-'+digest+'.json')


def supersession_chain():
    """Verify every immutable tombstone and retained generation, in order.

    The first receipt keeps its original pathname/bytes. Later receipts are
    append-only and keyed by the generation they retire. A pending receipt also
    advances the expected active digest, so interrupted replacement fails closed.
    """
    chain = []; path = SUPERSESSION; previous = None; seen = set()
    while os.path.lexists(path):
        receipt = protected(path)
        assert receipt['schema'] == 1 and receipt['run'] == 410
        assert receipt['old_budget_unconsumed'] is True and receipt['total_one_shot_budget'] == 1
        assert receipt['claim'] == str(CLAIM)
        old, new = receipt['superseded_sha256'], receipt['replacement_sha256']
        next_path = next_supersession(new)
        assert old != new and old not in seen and new not in seen
        retained = RESERVATION.with_name('run-410-reservation.superseded-'+old+'.json')
        assert receipt['retained_path'] == str(retained)
        data = protected(retained)
        assert sha(retained) == old and data['run'] == 410 and data['one_shot_budget'] == 1
        if previous is not None:
            assert old == previous['replacement_sha256']
            assert data['schema'] == 2 and data['supersedes_sha256'] == previous['superseded_sha256']
        seen.add(old); chain.append((path, receipt)); previous = receipt; path = next_path
    return chain


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


def validate_bindings(data):
    assert type(data['run']) is int and data['run'] == 410
    assert type(data['one_shot_budget']) is int and data['one_shot_budget'] == 1
    assert data['historical_high_water_mark'] == 409 and data['historical_raw_records_recovered'] is False
    assert data['continuity'] == 'fresh-lab'
    assert (data['candidate'], data['platform'], data['label'], data['mode']) == (str(CANDIDATE), PLATFORM, LABEL, 'success')
    refs = {ref['path']: ref['sha256'] for ref in data['bindings']}
    assert len(refs) == len(data['bindings']) and set(refs) == {str(p) for p in binding_paths()}
    for path, digest in refs.items():
        assert sha(path) == digest, ('reservation_binding_drift', path)
    return data


def unspent():
    assert not any(os.path.lexists(p) for p in (CLAIM, RUN, CANDIDATE.parent/LABEL))


def validate(path, candidate, platform, label, mode):
    assert pathlib.Path(path) == RESERVATION and pathlib.Path(candidate) == CANDIDATE
    assert (platform, label, mode) == (PLATFORM, LABEL, 'success')
    unspent()
    return validate_bindings(active())


def admit(path, candidate, platform, label, mode, preflight=False, provenance_check=None):
    fd = lock()
    try:
        data = validate(path, candidate, platform, label, mode)
        if provenance_check is not None: provenance_check()
        if not preflight:
            assert data['controller_boot_id'] == pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            save(CLAIM, dict(reservation=str(path), reservation_sha256=sha(path), run=410,
                            pid=os.getpid(), controller_boot_id=data['controller_boot_id'],
                            started_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                            budget_remaining=0, policy='No retry, including failure before raw-record creation.'))
        return fd, data
    except BaseException:
        os.close(fd); raise


def replacement(supersedes=None):
    admission = json.loads(pathlib.Path('target/run410-prep/admission.json').read_bytes())
    prior_claim = protected(pathlib.Path('target/lab-state/run-409-consumed.json'))
    prior_run = json.loads(pathlib.Path('target/lab-state/actual-program-run-409.json').read_bytes())
    assert prior_claim['run'] == 409 and prior_claim['budget_remaining'] == 0
    assert admission['boot_id'] != prior_run['guest_boot_id'], 'fresh_guest_required'
    identity = json.loads(pathlib.Path('target/run410-prep/guest-identity.json').read_bytes())
    assert identity['boot_id'] == admission['boot_id']
    assert identity['known_hosts_sha256'] == sha('target/platform-lab/debian-clean-x86_64/known_hosts')
    return dict(schema=2, run=410, candidate=str(CANDIDATE), platform=PLATFORM, label=LABEL,
                mode='success', one_shot_budget=1, continuity='fresh-lab', historical_high_water_mark=409,
                historical_raw_records_recovered=False, unavailable_historical_runs=list(range(398,409)), preserved_prior_run=409,
                guest_boot_id=admission['boot_id'],
                controller_boot_id=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                supersedes_sha256=supersedes,
                bindings=[dict(path=str(p), sha256=sha(p)) for p in binding_paths()],
                created_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(), execution_authorized_by_this_phase=False)


def supersede(expected_sha256, reason, new):
    """Caller holds LOCK. Tombstone and old bytes survive any later failure."""
    unspent()
    old = protected(RESERVATION)
    assert old['run'] == 410 and old['one_shot_budget'] == 1
    assert sha(RESERVATION) == expected_sha256
    if os.path.lexists(SUPERSESSION): active()
    receipt_path = next_supersession(expected_sha256) if os.path.lexists(SUPERSESSION) else SUPERSESSION
    assert not os.path.lexists(receipt_path) and reason.strip()
    assert new['schema'] == 2 and new['run'] == 410 and new['one_shot_budget'] == 1
    assert new['supersedes_sha256'] == expected_sha256
    retained = RESERVATION.with_name('run-410-reservation.superseded-'+expected_sha256+'.json')
    assert not os.path.lexists(retained)
    receipt = dict(schema=1, run=410, superseded_sha256=expected_sha256, retained_path=str(retained),
                   replacement_sha256=hashlib.sha256(encoded(new)).hexdigest(), reason=reason,
                   old_budget_unconsumed=True, total_one_shot_budget=1, claim=str(CLAIM),
                   observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
    save(receipt_path, receipt)
    os.link(RESERVATION, retained, follow_symlinks=False)
    RESERVATION.unlink(); sync_directory(RESERVATION.parent)
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
        print(json.dumps(dict(reservation=str(RESERVATION), sha256=sha(RESERVATION), run410_executed=False, budget_remaining=1)))
    finally: os.close(fd)


if __name__ == '__main__': main()
