#!/usr/bin/env python3
"""Preserve every fresh run411 outcome, including interruption before raw output.

Exclusive local bundle first, validation second. Never converts a Bootstrap
witness into a HOST record, accepts historical flags, or grants runtime acceptance.
A failed validation exits nonzero but leaves all captured bytes and its receipt.
"""
import hashlib
import importlib.util
import json
import os
import pathlib
import stat
import sys

if not __debug__:
    raise RuntimeError('optimized_python_refused')


spec = importlib.util.spec_from_file_location('collector_path_guard', pathlib.Path(__file__).with_name('run411-reservation.py'))
guard = importlib.util.module_from_spec(spec); spec.loader.exec_module(guard)


def load(name, path):
    return guard.load_module(name, path)


def save(path, data):
    guard.allowed_path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = guard.open_exclusive(path)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())




def collect(destination):
    guard.freeze_inputs(reset=True)
    destination = pathlib.Path(destination)
    guard.allowed_path(destination)
    destination.mkdir(mode=0o700)
    retained = []
    def normalized(path):
        path = pathlib.Path(path)
        return path.relative_to(pathlib.Path.cwd()) if path.is_absolute() else path
    def capture(path):
        guard.allowed_path(path)
        path = normalized(path)
        assert not path.is_absolute() and '..' not in path.parts
        acquired = guard.acquire(path); info = acquired.info
        assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
        data = acquired.data; save(destination/'files'/path, data)
        retained.append(dict(path=str(path), sha256=hashlib.sha256(data).hexdigest(), bytes=len(data)))
        return data
    receipt = dict(run=411, retained=retained, provenance_valid=False,
                   runtime_acceptance=False, release_ready=False,
                   full_bootstrap_witness_validation='NOT_RUN')
    try:
        reservation_path = pathlib.Path('target/lab-state/run-411-reservation.json')
        r = json.loads(capture(reservation_path))
        guard.check_references(r)
        for path in ('target/lab-state/run-411-consumed.json', 'target/lab-state/run-411-supersession.json', 'target/lab-state/run-411-controller-error.json'):
            if os.path.lexists(path): capture(path)
        # Retain every generation before validation, including partial chains.
        for tombstone in sorted(pathlib.Path('target/lab-state').glob('run-411-supersession*.json')):
            if str(tombstone) not in {row['path'] for row in retained}: capture(tombstone)
            retired = json.loads(guard.read_bytes(tombstone))['retained_path']
            guard.allowed_path(retired)
            if retired not in {row['path'] for row in retained}: capture(retired)
        # Preserve the raw record before touching any validator or output parser.
        source = pathlib.Path('target/lab-state/actual-program-run-411.json')
        raw = capture(source) if os.path.lexists(source) else None
        cp = pathlib.Path(r['candidate']); directory = cp.parent/r['label']
        assert cp == pathlib.Path('target/candidates/run410-da75562-20261104/candidate.json') and r['label'] == 'bootstrap411-arm64'
        guard.allowed_path(directory)
        if directory.exists():
            for path in sorted(directory.iterdir()): capture(path)
        seen = {row['path'] for row in retained}
        for ref in r['bindings']:
            if ref['path'] not in seen: capture(ref['path']); seen.add(ref['path'])
        # Preserve recursive baseline references too, so cold validation remains possible.
        for name in ('authored-host-baseline-', 'host-baseline-reconciliation-'):
            value = json.loads(guard.read_bytes(cp.parent/(name+r['platform']+'.json')))
            guard.check_references(value)
            for key in ('prior_evidence', 'references', 'helpers'):
                for ref in value.get(key, []):
                    path = normalized(ref['path'])
                    if str(path) not in seen:
                        capture(path); seen.add(str(path))
        validator = load('outcome_provenance', 'tools/rust-v2-lab/run411-provenance.py')
        reservation = guard
        c = json.loads(guard.read_bytes(cp))
        template = json.loads(guard.read_bytes(cp.parent/('authored-host-baseline-'+r['platform']+'.json')))
        review = json.loads(guard.read_bytes(cp.parent/('host-baseline-reconciliation-'+r['platform']+'.json')))
        validator.validate_fresh_provenance(template, review, c)
        claim = reservation.protected(reservation.CLAIM)
        assert claim['reservation'] == str(reservation.RESERVATION) and claim['reservation_sha256'] == reservation.sha(reservation.RESERVATION)
        assert claim['run'] == 411 and claim['budget_remaining'] == 0 and claim['controller_boot_id'] == r['controller_boot_id']
        receipt.update(provenance_valid=True, raw_record_present=raw is not None)
        if raw is None:
            receipt.update(outcome='controller_interrupted_before_raw_record', baseline_declaration_checked=False)
        else:
            record = json.loads(raw)
            validator.validate_fresh_provenance(template, review, c, record)
            for key, name in [('runner_sha256','controller-runner.py'), ('guest_sha256','controller-guest.py'),
                              ('context_checker_sha256','controller-context.py'), ('host_declaration_builder_sha256','controller-host-declaration.py'),
                              ('baseline_declaration_builder_sha256','controller-baseline-declaration.py')]:
                assert reservation.sha(directory/name) == record[key]
            assert guard.read_bytes(directory/'controller-authored-baseline.json') == guard.read_bytes(cp.parent/('authored-host-baseline-'+r['platform']+'.json'))
            assert guard.read_bytes(directory/'controller-baseline-reconciliation.json') == guard.read_bytes(cp.parent/('host-baseline-reconciliation-'+r['platform']+'.json'))
            rows = []; witnesses = []
            for line in record['stdout'].splitlines():
                if line.startswith('LAB_SECRET_BOOTSTRAP '): witnesses.append(json.loads(line.split(' ',1)[1])); continue
                try: rows.append(json.loads(line))
                except ValueError: pass
            values = lambda key: [v[key] for v in rows if isinstance(v,dict) and key in v]
            baselines, descriptors, gateways = (values(key) for key in ('secret_host_baseline','secret_attachment_descriptor','secret_attachment_gateway'))
            assert len(baselines) <= 1 and len(descriptors) <= 1 and len(gateways) <= 1
            checked = bool(baselines and descriptors and gateways)
            if checked: validator.validate_baseline_host(baselines[0],descriptors[0],gateways[0],c,record,directory)
            assert type(record['exit_code']) is int
            if record['exit_code'] == 0:
                assert record['result'] == 'PASS_PARTIAL_SECRET_BOOTSTRAP' and len(witnesses) == 1 and checked
                ends = values('secret_attachment_controller'); assert len(ends) == 1 and ends[0]['harness_exit_code'] == 0
                assert all(ends[0][key] is True for key in ('owner_unit_absent','host_single_down_link_added',
                           'host_addresses_routes_rules_preserved','host_stable_neighbors_preserved','inert_gateway_retained',
                           'original_gateway_native_identity_unchanged','canonical_and_mount_resources_retained'))
                outcome = 'bootstrap_exit_zero_preserved'
            else:
                assert record['result'] == 'FAIL'; outcome = 'failed_bootstrap_preserved'
            receipt.update(outcome=outcome, exit_code=record['exit_code'], baseline_declaration_checked=checked,
                           bootstrap_witness_count=len(witnesses), controller_postprocessing_complete=(directory/'directory-binding.json').exists())
        for row in retained:
            assert hashlib.sha256(guard.read_bytes(pathlib.Path(row['path']))).hexdigest() == row['sha256'], ('changed_during_collection',row['path'])
    except Exception as error:
        receipt['provenance_valid'] = False
        receipt['validation_error'] = type(error).__name__+': '+str(error)
    save(destination/'receipt.json', (json.dumps(receipt,indent=2,allow_nan=False)+'\n').encode())
    for directory in sorted([p for p in destination.rglob('*') if p.is_dir()],key=lambda p:len(p.parts),reverse=True)+[destination]:
        guard.sync_directory(directory)
    print(json.dumps(receipt))
    return 1 if 'validation_error' in receipt else 0


if __name__ == '__main__':
    assert len(sys.argv) == 2
    sys.exit(collect(sys.argv[1]))
