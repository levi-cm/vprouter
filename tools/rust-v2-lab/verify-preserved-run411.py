#!/usr/bin/env python3
"""Offline, read-only verification of run411 cold evidence; no VM/payload runs."""
import hashlib
import json
import os
import pathlib
import re
import stat
from datetime import datetime

if not __debug__: raise RuntimeError('optimized_python_refused')

A_SHA = 'd0d13f68c9a6fc39cbba1f7d2a68ab10baeb7d9d9c93072c77a28064cd1fb657'
SOURCE_STATE = pathlib.Path('/DATA/AppData/vprouter-rust-v2/target/platform-lab/debian-arm64')
RAW_SHA = 'a69050610bde2a1d78b23aabf30335afb4576919bc897c9cb872435a3cea9f61'
PRESERVE_ERR_SHA = '1f9e8114512bc939675b20ac4d54af4d9e6c3793ade5efd8c9f5d580b0e1c7e8'
ROOT = pathlib.Path('/DATA/vprouter-lab/preserved/run411-guest')

def require(condition, message):
    if not condition: raise RuntimeError(message)

def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(4*1024*1024), b''): h.update(block)
    return h.hexdigest()

def timestamp_ns(value):
    stamp = datetime.fromisoformat(value)
    require(stamp.tzinfo is not None and stamp.utcoffset().total_seconds() == 0, 'non_UTC_exit_receipt_time')
    return int(stamp.timestamp())*1_000_000_000+stamp.microsecond*1000

def walk(root):
    for path in sorted(root.iterdir()):
        yield path
        if stat.S_ISDIR(path.lstat().st_mode): yield from walk(path)

def verify_manifest(root):
    require(stat.S_IMODE(root.lstat().st_mode) == 0o500, 'root_mode')
    listed = {}
    for line in (root/'SHA256SUMS').read_text().splitlines():
        digest, name = line.split('  ', 1); rel = pathlib.Path(name)
        require(re.fullmatch('[a-f0-9]{64}', digest) and not rel.is_absolute() and '..' not in rel.parts and name not in listed and name != 'SHA256SUMS', 'unsafe_manifest_row')
        listed[name] = digest
    require('README.md' in listed, 'README_not_covered')
    found = set()
    for path in walk(root):
        s = path.lstat(); name = str(path.relative_to(root))
        if stat.S_ISDIR(s.st_mode): require(stat.S_IMODE(s.st_mode) == 0o500, 'directory_mode:'+name)
        elif stat.S_ISREG(s.st_mode):
            require(stat.S_IMODE(s.st_mode) == 0o400 and s.st_nlink == 1, 'file_mode_or_hardlink:'+name)
            if name == 'SHA256SUMS': continue
            require(name in listed and sha(path) == listed[name], 'file_hash_or_membership:'+name); found.add(name)
        elif stat.S_ISLNK(s.st_mode): require(name == 'state/known_hosts', 'unexpected_symlink:'+name)
        elif stat.S_ISSOCK(s.st_mode): require(name == 'state/qmp.sock' and stat.S_IMODE(s.st_mode) == 0o400, 'unexpected_socket:'+name)
        else: raise RuntimeError('unexpected_file_type:'+name)
    require(found == set(listed), 'manifest_missing_files')
    return len(found)

def verify(root=ROOT):
    count = verify_manifest(root)
    c = json.loads((root/'collected-chain/receipt.json').read_bytes())
    require(c['run'] == 411 and c['provenance_valid'] is True and c['exit_code'] == 1 and c['outcome'] == 'failed_bootstrap_preserved', 'original_C_outcome')
    for row in c['retained']:
        rel = pathlib.Path(row['path']); require(not rel.is_absolute() and '..' not in rel.parts, 'unsafe_C_path')
        path = root/'collected-chain/files'/rel
        require(sha(path) == row['sha256'] and path.stat().st_size == row['bytes'], 'original_C_hash:'+str(rel))
    raw = root/'collected-chain/files/target/lab-state/actual-program-run-411.json'
    require(sha(raw) == RAW_SHA, 'original_raw_hash')
    claim = json.loads((root/'collected-chain/files/target/lab-state/run-411-consumed.json').read_bytes())
    require(claim['run'] == 411 and claim['budget_remaining'] == 0, 'consumed_claim')
    reservation = root/'collected-chain/files/target/lab-state/run-411-reservation.json'
    require(sha(reservation) == claim['reservation_sha256'], 'consumed_reservation_hash')
    p = json.loads((root/'preservation.json').read_bytes())
    require(p['qemu_pid'] == 493434 and p['qemu_start_tick'] == 5902200 and p['guest_boot_id'] == '525e9103-b2f9-4611-a663-ced9d001245a', 'preserved_identity')
    require(p['qemu_exit_confirmed'] and p['serial_shutdown_verified'] and p['platform'] == 'debian-arm64' and p['serial_shutdown_rule'] == 'systemd-PSCI-power-down' and not p['serial_acpi_power_down'] and not p['force_stop'] and not p['overlay_rebooted'] and not p['guest_cleanup'], 'shutdown_disposition')
    serial = re.sub(r'\x1b\[[0-9;]*m', '', (root/'state/serial.log').read_text(errors='replace')).strip()
    require(re.search(r'(?:^|\n)(?:\[\s*[0-9.]+\] )?reboot: Power down[.\s]*$', serial), 'serial_ending')
    start = serial.find('shutdown.target'); require(start >= 0, 'serial_shutdown_sequence')
    shutdown_serial = serial[start:]; offset = 0
    require(not re.search(r'Linux version|Booting Linux|UEFI firmware|U-Boot|new boot', shutdown_serial, re.I), 'serial_later_boot')
    for marker in ('shutdown.target', 'poweroff.target', 'systemd-shutdown[1]: Syncing filesystems and block devices.',
                   'systemd-shutdown[1]: All filesystems unmounted.', 'systemd-shutdown[1]: Powering off.', 'reboot: Power down'):
        pos = shutdown_serial.find(marker, offset); require(pos >= 0, 'serial_shutdown_sequence:'+marker); offset = pos+len(marker)
    shutdown = json.loads((root/'shutdown-request.json').read_bytes())
    require(shutdown == json.loads((root/'poweroff.command.json').read_bytes()) and shutdown['exit_code'] == p['shutdown_exit_code'] == 0
            and shutdown['started_utc'] == p['shutdown_requested_utc'] and shutdown['completed_utc'] == p['shutdown_command_completed_utc'],
            'shutdown_receipt_binding')
    exit_record = json.loads((root/'qemu-exit.json').read_bytes())
    require(exit_record == p['qemu_exit_receipt'] and exit_record['qemu_pid'] == p['qemu_pid']
            and exit_record['qemu_start_tick'] == p['qemu_start_tick']
            and exit_record['poweroff_command_sha256'] == sha(root/'poweroff.command.json')
            and timestamp_ns(exit_record['exit_instant_utc']) == exit_record['exit_instant_ns']
            and timestamp_ns(shutdown['completed_utc']) <= exit_record['exit_instant_ns']
            and p['qemu_exit_observed_utc'] == exit_record['exit_instant_utc'], 'exit_receipt_binding')
    require(exit_record['method'] in ('pidfd-wait-completion','retained-post-wait-error-upper-bound'), 'exit_receipt_method')
    if exit_record['method'] == 'retained-post-wait-error-upper-bound':
        evidence = exit_record['evidence']
        require(evidence['retained_path'] == 'qemu-exit-evidence/preserve.err'
                and sha(root/evidence['retained_path']) == evidence['sha256'] == PRESERVE_ERR_SHA
                and (root/evidence['retained_path']).stat().st_size == evidence['bytes']
                and evidence['mtime_ns'] == exit_record['exit_instant_ns']
                and evidence['poweroff_completed_utc'] == shutdown['completed_utc']
                and 'wait_exit' in exit_record['derivation'], 'exit_receipt_derivation')
    snap_command = json.loads((root/'final-snapshot.command.json').read_bytes())
    require(snap_command['exit_code'] == 0 and datetime.fromisoformat(snap_command['completed_utc']) <= datetime.fromisoformat(shutdown['started_utc'])
            and snap_command['argv'][:-1] == shutdown['argv'][:-1], 'snapshot_receipt_binding')
    if 'resume' in p:
        r = json.loads((root/'resume-validation.json').read_bytes())
        require(r == p['resume'] and r['mode'] == 'resume-after-shutdown' and r['guest_contact'] is False and r['qemu_actions'] is False,
                'resume_disposition')
        require(r['qemu_exit_instant_utc'] == exit_record['exit_instant_utc'] and r['state_time_tolerance_ns'] == 2_000_000_000
                and r['state_cutoff_ns'] == exit_record['exit_instant_ns']+2_000_000_000
                and timestamp_ns(r['state_cutoff_utc']) == r['state_cutoff_ns'], 'resume_state_time_cutoff')
        require(set(r['state_times_before_move']) == {'.',*r['state_identity_before_move']}
                and all(max(row['mtime_ns'],row['ctime_ns']) <= r['state_cutoff_ns']
                        for row in r['state_times_before_move'].values()), 'resume_state_time_after_cutoff')
        require(set(r['receipt_hashes']) == {'preflight.json','final-snapshot.command.json','final-snapshot.stdout',
                'poweroff.command.json','shutdown-request.json','qemu-exit.json'}, 'resume_exit_receipt_membership')
        for name,digest in r['receipt_hashes'].items():
            require(name in ('preflight.json','final-snapshot.command.json','final-snapshot.stdout','poweroff.command.json','shutdown-request.json','qemu-exit.json')
                    and sha(root/name) == digest, 'resume_receipt_hash')
        found = {}
        for path in walk(root/'state'):
            mode = path.lstat().st_mode; name = str(path.relative_to(root/'state'))
            if stat.S_ISREG(mode): found[name] = ['file',path.stat().st_size,sha(path)]
            elif stat.S_ISDIR(mode): found[name] = ['directory']
            elif stat.S_ISLNK(mode): found[name] = ['symlink',os.readlink(path)]
            elif stat.S_ISSOCK(mode): found[name] = ['socket']
        require(found == r['state_identity_before_move'], 'resume_state_move_identity')
    snap = json.loads((root/'final-snapshot.stdout').read_bytes())
    require(snap['guest_boot_id'] == p['guest_boot_id'] and snap['owner_absent'] and snap['gateway']['original_identity_matches'] and len(snap['archived_selectors']) == 6, 'final_snapshot')
    require(all(row['exit_code'] == 0 for row in snap['inventories']) and not snap['private_profile_contents_read'] and snap['read_only'] is True, 'snapshot_inventory')
    pin = json.loads((root/'symlink-record.json').read_bytes())
    require(sha(root/'console-known_hosts') == pin['sha256'], 'console_pin_hash')
    require((root/'state/known_hosts').is_symlink() == pin['was_symlink'], 'pin_type')
    if pin['was_symlink']: require(os.readlink(root/'state/known_hosts') == pin['link_text'], 'pin_link_text')
    else: require(sha(root/'state/known_hosts') == pin['sha256'], 'state_pin_hash')
    require(not os.path.lexists(SOURCE_STATE), 'original_state_path_reappeared')
    # Verify every prep/reference/source file against the captured preflight,
    # without importing or running any historical program.
    pre = json.loads((root/'preflight.json').read_bytes())
    for name, digest in pre['refs'].items():
        path = root/'reference-inputs'/name
        if not path.exists(): path = root/'collected-chain/files'/name
        require(sha(path) == digest, 'reference_hash:'+name)
    require(sha(root/'state/process.json') == pre['refs']['target/platform-lab/debian-arm64/process.json'], 'moved_process_record_hash')
    a_path = root/'reference-inputs/target/lab-state/secret-bootstrap-selector-archive-run-411.json'
    require(sha(a_path) == A_SHA, 'original_A_receipt_hash')
    a = json.loads(a_path.read_bytes())
    f = json.loads((root/'reference-inputs/target/lab-state/secret-bootstrap-failure-run-411.json').read_bytes())
    require(a['record_sha256'] == f['record_sha256'] == RAW_SHA and set(a['selectors_archived']) == set(snap['archived_selectors']), 'FA_snapshot_paths')
    for path, row in snap['archived_selectors'].items():
        name = pathlib.PurePosixPath(path).name.removeprefix('411-failed-')
        old = f['fixed_selectors'][name]
        require(row['sha256'] == old['sha256'] and row['dev'] == old['device'] and row['ino'] == old['inode'], 'archived_selector_identity')
    return dict(verifier='PASS', offline=True, preserved_file_hashes=count, original_C_retained_files=len(c['retained']),
                original_raw_sha256=sha(raw), original_A_receipt_sha256=sha(a_path), budget_remaining=0, shutdown_exit_code=p['shutdown_exit_code'],
                qemu_exit_instant_utc=exit_record['exit_instant_utc'], qemu_exit_reference_method=exit_record['method'],
                state_transfer=p['state_transfer'], SHA256SUMS_sha256=sha(root/'SHA256SUMS'))

if __name__ == '__main__': print(json.dumps(verify(), indent=2))
