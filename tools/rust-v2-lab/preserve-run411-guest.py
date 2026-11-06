#!/usr/bin/env python3
"""One-way, fail-closed cold preservation of the consumed run411 ARM64 guest.

Default is an offline dry-run (no SSH). --execute never retries shutdown and
never sends a signal to QEMU. A failed operation leaves its exclusive archive
and all diagnostics in place. --resume-after-shutdown explicitly finishes an\noffline partial archive only after receipts, cold identity and state-time checks.
"""
import argparse
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import select
import shutil
import socket
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone

if not __debug__: raise RuntimeError('optimized_python_refused')

ROOT = pathlib.Path('/DATA/AppData/vprouter-rust-v2')
STATE = ROOT/'target/platform-lab/debian-arm64'
DEST = pathlib.Path('/DATA/vprouter-lab/preserved/run411-guest')
PRESERVE_ERR = pathlib.Path('/DATA/vprouter-lab/run411-exec/preserve.err')
PRESERVE_ERR_SHA = '1f9e8114512bc939675b20ac4d54af4d9e6c3793ade5efd8c9f5d580b0e1c7e8'
STATE_TIME_TOLERANCE_NS = 2_000_000_000
RAW = 'target/lab-state/actual-program-run-411.json'
A_SHA = 'd0d13f68c9a6fc39cbba1f7d2a68ab10baeb7d9d9c93072c77a28064cd1fb657'
RAW_SHA = 'a69050610bde2a1d78b23aabf30335afb4576919bc897c9cb872435a3cea9f61'
BOOT = '525e9103-b2f9-4611-a663-ced9d001245a'
SELECTORS = ('owner-domain-nonce', 'secret-attachment.json', 'secret-attachment-spec.json',
             'secret-attachment-staging.json', 'secret-quarantine-host.json', 'secret-host-baseline.json')

def require(condition, message):
    if not condition: raise RuntimeError(message)

def utc(): return datetime.now(timezone.utc).isoformat()

def sha(path):
    h = hashlib.sha256()
    with pathlib.Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(4*1024*1024), b''): h.update(block)
    return h.hexdigest()

def save(path, data):
    path = pathlib.Path(path); path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open('xb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())

def save_json(path, value): save(path, (json.dumps(value, indent=2)+'\n').encode())
def read_json(path): return json.loads(pathlib.Path(path).read_bytes())

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module

def proc_identity(pid):
    proc = pathlib.Path('/proc')/str(pid)
    raw = (proc/'stat').read_text(); fields = raw[raw.rfind(')')+2:].split()
    return dict(pid=pid, start_time=int(fields[19]), state=fields[0],
                argv=(proc/'cmdline').read_bytes().rstrip(b'\0').decode().split('\0'))

def match_process(expected, actual):
    require(actual['state'] not in ('Z', 'X') and all(actual[k] == expected[k] for k in ('pid', 'start_time', 'argv')),
            'qemu_identity_mismatch')

def ssh_argv(identity, pin):
    return ['ssh', '-F', '/dev/null', '-o', 'GlobalKnownHostsFile=/dev/null',
            '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none', '-o', 'BatchMode=yes',
            '-o', 'UpdateHostKeys=no', '-i', str(identity), '-p22034',
            '-o', 'UserKnownHostsFile='+str(pin), '-o', 'StrictHostKeyChecking=yes',
            '-o', 'ConnectTimeout=5', 'vprouterlab@127.0.0.1']

def wait_exit(pidfd, timeout):
    end = time.monotonic()+timeout
    while True:
        remaining = end-time.monotonic()
        require(remaining > 0, 'qemu_exit_timeout_STOP_never_force_stop')
        if select.select([pidfd], [], [], min(remaining, 1))[0]: return

def check_serial(data, platform='debian-arm64'):
    # Strip terminal colour only; never discard later output or boot banners.
    text = re.sub(r'\x1b\[[0-9;]*m', '', data.decode(errors='replace')).strip()
    require(re.search(r'(?:^|\n)(?:\[\s*[0-9.]+\] )?reboot: Power down[.\s]*$', text),
            'serial_missing_final_power_down_STOP')
    if platform == 'debian-arm64':
        markers = ('shutdown.target', 'poweroff.target',
                   'systemd-shutdown[1]: Syncing filesystems and block devices.',
                   'systemd-shutdown[1]: All filesystems unmounted.',
                   'systemd-shutdown[1]: Powering off.', 'reboot: Power down')
        pos = text.find('shutdown.target')
        require(pos >= 0, 'serial_missing_systemd_shutdown_STOP')
        shutdown = text[pos:]
        require(not re.search(r'Linux version|Booting Linux|UEFI firmware|U-Boot|new boot', shutdown, re.I),
                'serial_later_boot_STOP')
        offset = 0
        for marker in markers:
            found = shutdown.find(marker, offset)
            require(found >= 0, 'serial_missing_ordered_shutdown:'+marker)
            offset = found+len(marker)
        return 'systemd-PSCI-power-down'
    require(platform in ('debian-x86_64', 'debian-amd64', 'debian-x86', 'alpine-x86_64'), 'unknown_serial_platform')
    tail = text[-8192:]
    pos = tail.find('ACPI: PM: Preparing to enter system sleep state S5')
    require(pos >= 0 and not re.search(r'Linux version|Booting Linux|new boot', tail[pos:], re.I),
            'serial_missing_final_ACPI_power_down_STOP')
    return 'ACPI-S5-power-down'

def entries(root):
    """lstat-only walk; never follows a directory symlink."""
    for path in sorted(root.iterdir()):
        yield path
        if stat.S_ISDIR(path.lstat().st_mode): yield from entries(path)

def tree_identity(root):
    result = {}
    for path in entries(root):
        mode = path.lstat().st_mode; name = str(path.relative_to(root))
        if stat.S_ISREG(mode): result[name] = ['file', path.stat().st_size, sha(path)]
        elif stat.S_ISDIR(mode): result[name] = ['directory']
        elif stat.S_ISLNK(mode): result[name] = ['symlink', os.readlink(path)]
        elif stat.S_ISSOCK(mode): result[name] = ['socket']
        else: raise RuntimeError('unexpected_special_file:'+str(path))
    return result

def copy_tree(source, destination, sockets=False):
    destination.mkdir(mode=0o700)
    for path in sorted(source.iterdir()):
        target = destination/path.name; mode = path.lstat().st_mode
        if stat.S_ISDIR(mode): copy_tree(path, target, sockets)
        elif stat.S_ISREG(mode):
            require(path.stat().st_nlink == 1, 'hardlink_refused:'+str(path))
            shutil.copyfile(path, target)
            with target.open('rb') as stream: os.fsync(stream.fileno())
            require(sha(path) == sha(target), 'copy_hash_mismatch:'+str(path))
        elif stat.S_ISLNK(mode): target.symlink_to(os.readlink(path))
        elif stat.S_ISSOCK(mode) and sockets:
            # A closed pathname socket has no stream bytes. Cross-device moves
            # preserve its type/name as an explicitly recorded inert placeholder.
            sock = socket.socket(socket.AF_UNIX)
            try: sock.bind(str(target))
            finally: sock.close()
        else: raise RuntimeError('unexpected_special_file:'+str(path))

def move_state(source, destination):
    require(not os.path.lexists(destination), 'state_destination_exists')
    try:
        os.rename(source, destination)
        return 'rename'
    except OSError as error:
        if error.errno != errno.EXDEV: raise
    before = tree_identity(source)
    copy_tree(source, destination, sockets=True)
    require(before == tree_identity(destination) == tree_identity(source), 'cross_device_copy_verification_failed_source_retained')
    shutil.rmtree(source)
    return 'copy_verify_remove'

def seal(root):
    lines = []
    for path in entries(root):
        mode = path.lstat().st_mode
        if stat.S_ISREG(mode):
            require(path.name != 'SHA256SUMS' or path.parent != root, 'manifest_already_exists')
            lines.append(sha(path)+'  '+str(path.relative_to(root))+'\n')
            path.chmod(0o400)
        elif stat.S_ISSOCK(mode): path.chmod(0o400)
    save(root/'SHA256SUMS', ''.join(lines).encode()); (root/'SHA256SUMS').chmod(0o400)
    for path in reversed(list(entries(root))):
        if stat.S_ISDIR(path.lstat().st_mode): path.chmod(0o500)
    root.chmod(0o500)

def remote_program(unit, gateway, failure, archive):
    nonce = failure['nonce']; require(re.fullmatch('[a-f0-9]{64}', nonce), 'invalid_nonce')
    paths = ['/var/lib/vprouter-v2-lab/secret-inputs-'+nonce+'/411-failed-'+name for name in SELECTORS]
    require(archive['selectors_archived'] == paths, 'unexpected_archived_selector_paths')
    inspector = load('snapshot411_template', ROOT/'tools/rust-v2-lab/inspect-run411-state.py')
    script = 'EXPECTED_BOOT='+repr(BOOT)+'\nUNIT='+repr(unit)+'\nGATEWAY='+repr(gateway)+'\n'+inspector.REMOTE
    # Reuse the reviewed run411 variant of the run409 snapshot, adding only
    # explicit public archived selector files and inventories before its print.
    extra = r'''
expected_archives=ARCHIVED_ROWS
out['archived_selectors']={}
for name,path,expected in expected_archives:
 p=pathlib.Path(path);s=p.lstat()
 assert stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<=1024*1024
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  opened=os.fstat(fd);assert (opened.st_dev,opened.st_ino)==(s.st_dev,s.st_ino)
  with os.fdopen(fd,'rb',closefd=False)as stream:data=stream.read(1024*1024+1)
 finally:os.close(fd)
 assert len(data)==s.st_size
 digest=hashlib.sha256(data).hexdigest()
 assert digest==expected['sha256']and s.st_dev==expected['device']and s.st_ino==expected['inode']and s.st_size==expected['size']
 out['archived_selectors'][path]=dict(dev=s.st_dev,ino=s.st_ino,mode=stat.S_IMODE(s.st_mode),uid=s.st_uid,gid=s.st_gid,nlink=s.st_nlink,size=s.st_size,sha256=digest,public_content=data.decode()if name=='owner-domain-nonce'else json.loads(data))
assert all(not row['present']for row in out['selectors'].values())
assert out['gateway']['original_identity_matches']is True
assert out['owner']['cgroup_exists']is False
owner_fields=dict(line.split('=',1)for line in out['owner']['stdout'].splitlines()if'='in line)
assert owner_fields['LoadState']=='not-found'and owner_fields['MainPID']=='0'and owner_fields['ActiveState']=='inactive'
out['owner_absent']=True
out['inventories']=[]
for argv in [['ip','-j','-d','link','show'],['ip','-j','-d','address','show'],['ip','-j','-4','route','show','table','all'],['ip','-j','-6','route','show','table','all'],['ip','-j','-4','rule','show'],['ip','-j','-6','rule','show'],['nft','-j','list','ruleset'],['docker','ps','-a','--no-trunc','--format','{{json .}}'],['findmnt','-J'],['ip','netns','list']]:
 r=subprocess.run(argv,capture_output=True,text=True,timeout=20)
 out['inventories'].append(dict(argv=argv,exit_code=r.returncode,stdout=r.stdout,stderr=r.stderr))
 assert r.returncode==0
assert pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()==boot
'''.replace('ARCHIVED_ROWS', repr([(name, path, failure['fixed_selectors'][name]) for name, path in zip(SELECTORS, paths)]))
    require(script.count('print(json.dumps(out))') == 1, 'snapshot_template_changed')
    script = script.replace('print(json.dumps(out))', extra+'\nprint(json.dumps(out))')
    compile(script, 'run411-final-snapshot-remote', 'exec')
    return script

def preflight():
    require(pathlib.Path.cwd() == ROOT, 'wrong_working_directory')
    require(not os.path.lexists(DEST), 'archive_exists_STOP_no_rerun')
    process = read_json(STATE/'process.json')
    require(process['pid'] == 493434 and process['start_time'] == 5902200 and process['ssh_port'] == 22034, 'unexpected_QEMU_record')
    require(process['controller_boot_id'] == pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'controller_boot_changed')
    match_process(process, proc_identity(process['pid']))
    require(sha(ROOT/RAW) == RAW_SHA, 'original_raw_hash_mismatch')
    raw = read_json(ROOT/RAW); receipt = read_json(ROOT/'target/run411-evidence/receipt.json')
    require(receipt['provenance_valid'] is True and receipt['exit_code'] == 1 and receipt['outcome'] == 'failed_bootstrap_preserved', 'original_collector_not_failed_valid')
    refs = {}
    for row in receipt['retained']:
        name = row['path']; rel = pathlib.Path(name)
        require(not rel.is_absolute() and '..' not in rel.parts, 'unsafe_retained_path')
        require(sha(ROOT/'target/run411-evidence/files'/name) == row['sha256'] == sha(ROOT/name), 'original_collected_bytes_mismatch:'+name)
        refs[name] = row['sha256']
    reservation = read_json(ROOT/'target/lab-state/run-411-reservation.json')
    claim = read_json(ROOT/'target/lab-state/run-411-consumed.json')
    require(claim['run'] == 411 and claim['budget_remaining'] == 0 and claim['reservation_sha256'] == sha(ROOT/'target/lab-state/run-411-reservation.json'), 'claim_mismatch')
    require(reservation['guest_boot_id'] == BOOT, 'reservation_boot_mismatch')
    for row in reservation['bindings']:
        require(refs[row['path']] == row['sha256'], 'reservation_binding_mismatch')
    cp = ROOT/reservation['candidate']; candidate = read_json(cp)
    require(sha(pathlib.Path(candidate['source'])) == candidate['source_sha256'], 'source_archive_hash_mismatch')
    refs[str(pathlib.Path(candidate['source']).relative_to(ROOT))] = candidate['source_sha256']
    failure = read_json(ROOT/'target/lab-state/secret-bootstrap-failure-run-411.json')
    archive = read_json(ROOT/'target/lab-state/secret-bootstrap-selector-archive-run-411.json')
    require(failure['record_sha256'] == archive['record_sha256'] == RAW_SHA and archive['failed_run'] == 411, 'FA_raw_mismatch')
    gateway = unit = None
    for line in raw['stdout'].splitlines():
        try: value = json.loads(line)
        except ValueError: continue
        if isinstance(value, dict):
            if 'secret_attachment_gateway' in value: gateway = value['secret_attachment_gateway']
            if 'owner_probe' in value: unit = value['owner_probe']['unit']
    require(unit == archive['exact_owner_unit_verified_absent'] == failure['expected_owner_unit'] and gateway is not None, 'missing_native_identity')
    require(re.fullmatch(r'vprouter-v2-owner@[a-f0-9]{64}[.]service', unit), 'unsafe_owner_unit')
    # Capture each original recursively validated reference, with historical
    # absolute paths normalized only as archive names, never changing its bytes.
    for name in ('authored-host-baseline-', 'host-baseline-reconciliation-'):
        data = read_json(cp.parent/(name+'debian-arm64.json'))
        for key in ('prior_evidence', 'references', 'helpers'):
            for row in data.get(key, []):
                path = pathlib.Path(row['path']); path = path if path.is_absolute() else ROOT/path
                rel = str(path.relative_to(ROOT))
                require('..' not in pathlib.Path(rel).parts and sha(path) == row['sha256'], 'baseline_reference_hash_mismatch')
                refs[rel] = row['sha256']
    special = []
    for path in entries(STATE):
        mode = path.lstat().st_mode
        require(stat.S_ISREG(mode) or stat.S_ISDIR(mode) or stat.S_ISLNK(mode) or (stat.S_ISSOCK(mode) and path.name == 'qmp.sock'), 'unexpected_state_type')
        if stat.S_ISSOCK(mode): special.append(dict(path='state/'+str(path.relative_to(STATE)), type='socket', original_stat=list(path.lstat())))
    pin = STATE/'known_hosts'; pin_bytes = pin.read_bytes()
    pin_record = dict(original_path=str(pin), was_symlink=pin.is_symlink(), link_text=os.readlink(pin) if pin.is_symlink() else None,
                      resolved_original_path=str(pin.resolve(strict=True)), sha256=hashlib.sha256(pin_bytes).hexdigest(),
                      preserved_path='state/known_hosts', exact_pin_copy='console-known_hosts')
    return dict(process=process, receipt=receipt, refs=refs, pin_record=pin_record, pin_bytes=pin_bytes,
                special=special, script=remote_program(unit, gateway, failure, archive))

def record_command(archive, name, argv, body=None, timeout=90):
    started = utc(); then = time.monotonic()
    try:
        result = subprocess.run(argv, input=body, text=True, capture_output=True, timeout=timeout)
        stdout, stderr, code = result.stdout, result.stderr, result.returncode
    except (subprocess.TimeoutExpired, OSError) as error:
        code = 124 if isinstance(error, subprocess.TimeoutExpired) else 125
        def decoded(value): return value.decode(errors='replace') if isinstance(value, bytes) else value or ''
        stdout = decoded(getattr(error, 'stdout', None)); stderr = decoded(getattr(error, 'stderr', None))+'\n'+str(error)
    save(archive/(name+'.stdout'), stdout.encode()); save(archive/(name+'.stderr'), stderr.encode())
    record = dict(argv=argv, started_utc=started, completed_utc=utc(), elapsed_seconds=time.monotonic()-then, exit_code=code)
    save_json(archive/(name+'.command.json'), record)
    return code, stdout, record

def execute(data, sudo_snapshot, timeout):
    process = data['process']; pidfd = os.pidfd_open(process['pid'], 0)
    try:
        match_process(process, proc_identity(process['pid']))
        require(not select.select([pidfd], [], [], 0)[0], 'QEMU_exited_before_snapshot')
        DEST.mkdir(mode=0o700)
        save_json(DEST/'preflight.json', {k: v for k, v in data.items() if k not in ('pin_bytes', 'script')})
        save(DEST/'final-snapshot-remote.py', data['script'].encode())
        save(DEST/'console-known_hosts', data['pin_bytes']); save_json(DEST/'symlink-record.json', data['pin_record'])
        save_json(DEST/'special-record.json', data['special'])
        # Stage evidence BEFORE shutdown. Copying records never edits originals.
        copy_tree(ROOT/'target/run411-evidence', DEST/'collected-chain')
        copy_tree(ROOT/'target/candidates/run410-da75562-20261104/bootstrap411-arm64', DEST/'runner-output')
        copy_tree(pathlib.Path('/DATA/vprouter-lab/run411-exec'), DEST/'execution-evidence')
        for name in ['target/lab-state/secret-bootstrap-failure-run-411.json',
                     'target/lab-state/secret-bootstrap-selector-archive-run-411.json', 'target/run411-evidence-post-state.json']:
            save(DEST/'reference-inputs'/name, (ROOT/name).read_bytes())
        for name, digest in data['refs'].items():
            target = DEST/'reference-inputs'/name
            # C already captured most references. Keep the reference-inputs
            # directory focused on prep/reference inputs and the source archive.
            if name.startswith('target/run411-prep/') or name.endswith('/source.tar') or name not in {r['path'] for r in data['receipt']['retained']}:
                save(target, (ROOT/name).read_bytes()); require(sha(target) == digest, 'reference_copy_mismatch')
        for name in ('preserve-run411-guest.py', 'verify-preserved-run411.py', 'test-preserve-run411-guest.py'):
            save(DEST/'preservation-tools'/name, (ROOT/'tools/rust-v2-lab'/name).read_bytes())
        guard = load('run411_ssh_material', ROOT/'tools/rust-v2-lab/run411-reservation.py')
        with guard.ssh_material('target/lab-state/id_ed25519', 'target/platform-lab/debian-arm64/known_hosts') as (identity, pin):
            ssh = ssh_argv(identity, pin)
            snapshot_command = 'sudo -n python3 -I -B -' if sudo_snapshot else 'python3 -I -B -'
            code, stdout, _ = record_command(DEST, 'final-snapshot', ssh+[snapshot_command], data['script'], timeout=240)
            require(code == 0, 'snapshot_failed_STOP_guest_not_powered_off')
            snapshot = json.loads(stdout)
            require(snapshot['guest_boot_id'] == BOOT and snapshot['owner_absent'] is True and snapshot['gateway']['original_identity_matches'] is True
                    and len(snapshot['archived_selectors']) == 6 and all(row['exit_code'] == 0 for row in snapshot['inventories']), 'snapshot_incomplete_STOP')
            match_process(process, proc_identity(process['pid']))
            require(sha(STATE/'process.json') == data['refs']['target/platform-lab/debian-arm64/process.json'] and sha(STATE/'known_hosts') == data['pin_record']['sha256'], 'process_or_pin_changed_STOP')
            # The second handshake rechecks the boot immediately before the
            # single authorized lifecycle action, using exactly the same SSH.
            command = "test \"$(cat /proc/sys/kernel/random/boot_id)\" = "+BOOT+' && sudo -n systemctl poweroff'
            code, _, shutdown = record_command(DEST, 'poweroff', ssh+[command], timeout=30)
            save_json(DEST/'shutdown-request.json', shutdown)
            # A transport close can accompany poweroff; retain it and still wait
            # for the pinned QEMU. No second poweroff or signal is ever sent.
            wait_exit(pidfd, timeout)
            # Capture wall time immediately on pidfd completion, before context
            # cleanup, serial validation, hashing or moving the cold state.
            exit_utc = utc()
            save_json(DEST/'qemu-exit.json', dict(method='pidfd-wait-completion', exit_instant_utc=exit_utc,
                      exit_instant_ns=timestamp_ns(exit_utc), qemu_pid=process['pid'], qemu_start_tick=process['start_time'],
                      poweroff_command_sha256=sha(DEST/'poweroff.command.json')))
        serial = (STATE/'serial.log').read_bytes(); check_serial(serial)
        with socket.socket() as port:
            port.bind(('127.0.0.1', 22034))
        for row in data['receipt']['retained']:
            require(sha(DEST/'collected-chain/files'/row['path']) == row['sha256'], 'copied_collected_chain_changed')
        finish_preservation(data, serial, shutdown, sudo_snapshot)
    finally: os.close(pidfd)

def finish_preservation(data, serial, shutdown, sudo_snapshot, resume_record=None):
    rule = check_serial(serial, data['process'].get('platform', 'debian-arm64'))
    process = data['process']; code = shutdown['exit_code']
    move = move_state(STATE, DEST/'state')
    result = dict(run=411, budget_remaining=0, guest_boot_id=BOOT, qemu_pid=process['pid'], qemu_start_tick=process['start_time'],
                  shutdown_requested_utc=shutdown['started_utc'], shutdown_command_completed_utc=shutdown['completed_utc'], shutdown_exit_code=code,
                  qemu_exit_observed_utc=read_json(DEST/'qemu-exit.json')['exit_instant_utc'],
                  qemu_exit_receipt=read_json(DEST/'qemu-exit.json'), qemu_exit_confirmed=True, serial_ending=serial.decode(errors='replace').splitlines()[-15:],
                  platform=process.get('platform', 'debian-arm64'), serial_shutdown_verified=True, serial_shutdown_rule=rule,
                  serial_acpi_power_down=rule == 'ACPI-S5-power-down', port_22034_bindable=True, state_transfer=move,
                  special_socket_handling='original pathname socket moved by rename' if move == 'rename' else 'inert closed socket placeholder reconstructed after verified cross-device copy',
                  original_raw_sha256=RAW_SHA, private_profile_contents_read=False, guest_cleanup=False,
                  readonly_snapshot_sudo_explicitly_authorized=sudo_snapshot, force_stop=False, overlay_rebooted=False)
    if resume_record is not None: result['resume'] = resume_record
    save_json(DEST/'preservation.json', result)
    save(DEST/'README.md', ('''# Run 411 guest preservation

Run 411 is consumed; budget 0. NEVER BOOT THIS OVERLAY. A final strict read-only
SSH snapshot preceded one guest systemctl poweroff. The original QEMU exited;
the ARM64 serial log ends in systemd shutdown / PSCI reboot: Power down. No selectors, containers,
profiles, canonical files, mounts, links or namespaces were cleaned up. Selector
archival A had already moved the six public selectors to their 411-failed-* names.
Cold disk and the snapshot preserve evidence, not continuing live kernel identities.

state/ is the original moved overlay, seed, cloud-init sources, AAVMF vars, logs,
process record, pin and QMP pathname. Recorded argv are HISTORICAL: never execute
them. The read-only backing image remains at
/DATA/vprouter-lab/lab-images/debian-13-genericcloud-arm64-20261021-2638.qcow2;
no base was modified and no private SSH key is included here.

collected-chain/ contains the unchanged original C bundle. runner-output/ and
execution-evidence/ copy run411's runner and C/I/F/A/P evidence. reference-inputs/
contains F/A receipts, I state, validated prep references and frozen source archive.
preservation-tools/ retains the original attempt sources; resume-tools/, when present,\ncontains the sources used to finish preservation offline.
final-snapshot.* records all commands, exit codes and public inventories.
qemu-exit.json records the pidfd completion instant, or an explicitly derived
upper bound from the retained post-wait failure. It binds poweroff.command.json.
qemu-exit-evidence/, when present, retains that original failure verbatim.
Offline resume accepts state mtime and ctime only through exit instant + 2 s;
resume-validation.json records this cutoff and the state timestamps before move.

symlink-record.json records the original known_hosts type/link/resolution and its
exact pin hash. For this ARM64 guest it was a regular file, so it stays regular;
console-known_hosts retains an additional exact pin copy. Symlinks, if present,
are retained as symlinks and are never followed by manifest traversal.
special-record.json records qmp.sock's original metadata; preservation.json records
its move/placeholder disposition. The cold socket has no live QMP listener.

SHA256SUMS covers every regular evidence file INCLUDING this README, except the
manifest itself. Files and socket are 0400, directories 0500. This is owner-mode
protection, not WORM storage. The verifier never boots a VM or executes payloads.
''').encode())
    seal(DEST)
    result['artifact_hashes'] = {name: sha(DEST/name) for name in ('state/guest.qcow2', 'state/seed.iso', 'state/serial.log', 'state/process.json', 'state/vars.fd', 'console-known_hosts', 'final-snapshot.stdout', 'README.md', 'SHA256SUMS')}
    print(json.dumps(result, indent=2))
    require(code == 0, 'preserved_cleanly_but_poweroff_SSH_exit_nonzero_see_receipt')

def timestamp_ns(value):
    stamp = datetime.fromisoformat(value)
    require(stamp.tzinfo is not None and stamp.utcoffset().total_seconds() == 0, 'non_UTC_receipt_time')
    return int(stamp.timestamp())*1_000_000_000+stamp.microsecond*1000

def ns_utc(value):
    seconds, nanos = divmod(value, 1_000_000_000)
    require(nanos % 1000 == 0, 'exit_time_not_microsecond_representable')
    return datetime.fromtimestamp(seconds, timezone.utc).replace(microsecond=nanos//1000).isoformat()

def exit_reference(process, shutdown):
    """Read-only until all resume gates pass; never substitute the current time."""
    evidence = None
    if (DEST/'qemu-exit.json').exists():
        record = read_json(DEST/'qemu-exit.json')
        require(record['method'] == 'pidfd-wait-completion', 'unexpected_partial_exit_method')
    else:
        before = PRESERVE_ERR.lstat()
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'unsafe_exit_upper_bound_evidence')
        evidence = PRESERVE_ERR.read_bytes()
        after = PRESERVE_ERR.lstat()
        require((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns) ==
                (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
                and hashlib.sha256(evidence).hexdigest() == PRESERVE_ERR_SHA, 'exit_upper_bound_evidence_changed')
        # The pinned original traceback is from execute's serial validation,
        # reached only after its pidfd wait_exit returned. Its mtime is therefore
        # an upper bound on that completion, not an exact exit measurement.
        instant = before.st_mtime_ns
        record = dict(method='retained-post-wait-error-upper-bound', exit_instant_utc=ns_utc(instant),
                      exit_instant_ns=instant, qemu_pid=process['pid'], qemu_start_tick=process['start_time'],
                      poweroff_command_sha256=sha(DEST/'poweroff.command.json'),
                      derivation='Original execute reached serial validation only after wait_exit(pidfd) completed. '
                                 'The pinned preserve.err traceback mtime bounds that completion from above; '
                                 'poweroff.command.json completed_utc is the earlier request completion. '
                                 'No exact historical pidfd completion timestamp was recorded.',
                      evidence=dict(original_path=str(PRESERVE_ERR), retained_path='qemu-exit-evidence/preserve.err',
                                    sha256=PRESERVE_ERR_SHA, bytes=len(evidence), mtime_ns=instant,
                                    ctime_ns=before.st_ctime_ns, poweroff_completed_utc=shutdown['completed_utc']))
    require(record['qemu_pid'] == process['pid'] and record['qemu_start_tick'] == process['start_time']
            and record['poweroff_command_sha256'] == sha(DEST/'poweroff.command.json'), 'exit_receipt_identity_binding')
    require(timestamp_ns(record['exit_instant_utc']) == record['exit_instant_ns']
            and timestamp_ns(shutdown['completed_utc']) <= record['exit_instant_ns'] <= time.time_ns(), 'invalid_exit_reference_time')
    return record, evidence

def require_cold(process):
    require(process['controller_boot_id'] == pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'controller_boot_changed')
    try: actual = proc_identity(process['pid'])
    except FileNotFoundError: actual = None
    require(actual is None or actual['start_time'] != process['start_time'], 'qemu_identity_still_present')
    # Check kernel listener tables without making any connection or QMP request.
    for name in ('tcp', 'tcp6'):
        for line in pathlib.Path('/proc/net', name).read_text().splitlines()[1:]:
            fields = line.split()
            require(not (fields[3] == '0A' and int(fields[1].split(':')[1], 16) == 22034), 'port_22034_listening')
    with socket.socket() as port: port.bind(('127.0.0.1', 22034))

def state_before_cutoff(cutoff):
    timestamps = {}
    for path in [STATE, *entries(STATE)]:
        st = path.lstat(); name = str(path.relative_to(STATE))
        require(max(st.st_mtime_ns, st.st_ctime_ns) <= cutoff, 'state_modified_after_shutdown:'+name)
        require(stat.S_ISDIR(st.st_mode) or (stat.S_ISREG(st.st_mode) and st.st_nlink == 1)
                or (stat.S_ISLNK(st.st_mode) and name == 'known_hosts')
                or (stat.S_ISSOCK(st.st_mode) and name == 'qmp.sock'), 'unexpected_state_type:'+name)
        timestamps[name] = dict(mtime_ns=st.st_mtime_ns, ctime_ns=st.st_ctime_ns)
    return timestamps

def validate_partial():
    require(pathlib.Path.cwd() == ROOT, 'wrong_working_directory')
    require(DEST.is_dir() and not DEST.is_symlink(), 'partial_archive_missing_or_symlink')
    require(STATE.is_dir() and not STATE.is_symlink(), 'unmoved_state_missing_or_symlink')
    expected = {'preflight.json', 'collected-chain', 'reference-inputs', 'runner-output', 'execution-evidence',
                'preservation-tools', 'console-known_hosts', 'symlink-record.json', 'special-record.json',
                'final-snapshot-remote.py', 'final-snapshot.command.json', 'final-snapshot.stdout', 'final-snapshot.stderr',
                'poweroff.command.json', 'poweroff.stdout', 'poweroff.stderr', 'shutdown-request.json'}
    actual = {p.name for p in DEST.iterdir()}
    require(actual == expected or actual == expected | {'qemu-exit.json'}, 'inconsistent_partial_archive_or_already_finished')
    for path in entries(DEST):
        st = path.lstat()
        require(stat.S_ISDIR(st.st_mode) or (stat.S_ISREG(st.st_mode) and st.st_nlink == 1), 'unsafe_partial_archive_type')
    data = read_json(DEST/'preflight.json'); process = data['process']
    require((process['pid'], process['start_time'], process['ssh_port'], process['platform']) ==
            (493434, 5902200, 22034, 'debian-arm64'), 'unexpected_QEMU_record')
    require_cold(process)
    require(read_json(STATE/'process.json') == process, 'state_process_record_changed')
    snapshot_command = read_json(DEST/'final-snapshot.command.json')
    shutdown = read_json(DEST/'shutdown-request.json')
    require(shutdown == read_json(DEST/'poweroff.command.json'), 'shutdown_receipts_disagree')
    for receipt in (snapshot_command, shutdown):
        require(receipt['exit_code'] == 0 and timestamp_ns(receipt['started_utc']) <= timestamp_ns(receipt['completed_utc']),
                'unsuccessful_or_invalid_command_receipt')
        argv = receipt['argv']; key = argv[argv.index('-i')+1]
        pin_options = [part for part in argv if part.startswith('UserKnownHostsFile=')]
        require(len(pin_options) == 1 and argv[:-1] == ssh_argv(key, pin_options[0].split('=', 1)[1]), 'recorded_SSH_not_confined')
    require(snapshot_command['argv'][:-1] == shutdown['argv'][:-1] and
            snapshot_command['argv'][-1] in ('python3 -I -B -', 'sudo -n python3 -I -B -') and
            shutdown['argv'][-1] == 'test "$(cat /proc/sys/kernel/random/boot_id)" = '+BOOT+' && sudo -n systemctl poweroff' and
            timestamp_ns(snapshot_command['completed_utc']) <= timestamp_ns(shutdown['started_utc']), 'unexpected_snapshot_or_shutdown_receipt')
    require(all(not (DEST/name).read_bytes() for name in ('final-snapshot.stderr', 'poweroff.stdout', 'poweroff.stderr')),
            'unexpected_snapshot_or_shutdown_diagnostics')
    snapshot = read_json(DEST/'final-snapshot.stdout')
    require(snapshot['guest_boot_id'] == BOOT and snapshot['owner_absent'] is True and snapshot['gateway']['original_identity_matches'] is True
            and snapshot['read_only'] is True and snapshot['private_profile_contents_read'] is False
            and len(snapshot['archived_selectors']) == 6 and snapshot['inventories']
            and all(row['exit_code'] == 0 for row in snapshot['inventories']), 'snapshot_incomplete_STOP')
    c = read_json(DEST/'collected-chain/receipt.json')
    require(c == data['receipt'] and c['run'] == 411 and c['provenance_valid'] is True and c['exit_code'] == 1
            and c['outcome'] == 'failed_bootstrap_preserved', 'partial_C_receipt_mismatch')
    for row in c['retained']:
        rel = pathlib.Path(row['path'])
        require(not rel.is_absolute() and '..' not in rel.parts, 'unsafe_C_path')
        path = DEST/'collected-chain/files'/rel
        require(sha(path) == row['sha256'] and path.stat().st_size == row['bytes'], 'partial_C_hash:'+str(rel))
    require(sha(DEST/'collected-chain/files'/RAW) == RAW_SHA, 'original_raw_hash_mismatch')
    for name, digest in data['refs'].items():
        rel = pathlib.Path(name)
        require(not rel.is_absolute() and '..' not in rel.parts, 'unsafe_reference_path')
        path = DEST/'reference-inputs'/rel
        if not path.exists(): path = DEST/'collected-chain/files'/rel
        require(sha(path) == digest, 'partial_reference_hash:'+name)
    require(sha(STATE/'process.json') == data['refs']['target/platform-lab/debian-arm64/process.json'], 'process_record_hash')
    a_path = DEST/'reference-inputs/target/lab-state/secret-bootstrap-selector-archive-run-411.json'
    require(sha(a_path) == A_SHA, 'original_A_receipt_hash')
    a = read_json(a_path); f = read_json(a_path.with_name('secret-bootstrap-failure-run-411.json'))
    require(a['record_sha256'] == f['record_sha256'] == RAW_SHA and a['failed_run'] == 411 and
            set(a['selectors_archived']) == set(snapshot['archived_selectors']), 'partial_FA_snapshot_mismatch')
    for path, row in snapshot['archived_selectors'].items():
        name = pathlib.PurePosixPath(path).name.removeprefix('411-failed-')
        old = f['fixed_selectors'][name]
        require(row['sha256'] == old['sha256'] and row['dev'] == old['device'] and row['ino'] == old['inode'],
                'archived_selector_identity')
    claim = read_json(DEST/'collected-chain/files/target/lab-state/run-411-consumed.json')
    reservation = DEST/'collected-chain/files/target/lab-state/run-411-reservation.json'
    require(claim['run'] == 411 and claim['budget_remaining'] == 0 and claim['reservation_sha256'] == sha(reservation)
            and read_json(reservation)['guest_boot_id'] == BOOT, 'partial_consumed_claim_mismatch')
    pin = read_json(DEST/'symlink-record.json')
    require(pin == data['pin_record'] and sha(DEST/'console-known_hosts') == pin['sha256'] == sha(STATE/'known_hosts')
            and (STATE/'known_hosts').is_symlink() == pin['was_symlink'], 'partial_console_pin_mismatch')
    if pin['was_symlink']: require(os.readlink(STATE/'known_hosts') == pin['link_text'], 'partial_pin_link_mismatch')
    require(read_json(DEST/'special-record.json') == data['special'], 'partial_special_record_mismatch')
    exit_record, exit_evidence = exit_reference(process, shutdown)
    cutoff = exit_record['exit_instant_ns']+STATE_TIME_TOLERANCE_NS
    state_before_cutoff(cutoff)
    serial = (STATE/'serial.log').read_bytes(); check_serial(serial, process['platform'])
    return data, shutdown, snapshot_command, serial, cutoff, exit_record, exit_evidence

def resume_after_shutdown():
    # Lock the existing archive directory itself: no lockfile, process signal,
    # SSH setup, subprocess, socket connection or QEMU/QMP operation is needed.
    require(not os.path.lexists(DEST/'state') and not os.path.lexists(DEST/'SHA256SUMS'), 'already_moved_or_sealed_no_rerun')
    fd = os.open(DEST, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        data, shutdown, snapshot_command, serial, cutoff, exit_record, exit_evidence = validate_partial()
        before = tree_identity(STATE)
        state_before_cutoff(cutoff); require_cold(data['process'])
        require(before == tree_identity(STATE), 'state_changed_during_resume_validation')
        if exit_evidence is not None:
            save(DEST/'qemu-exit-evidence/preserve.err', exit_evidence)
            save_json(DEST/'qemu-exit.json', exit_record)
        # Preserve original attempt tools byte-for-byte, adding current sources.
        for name in ('preserve-run411-guest.py', 'verify-preserved-run411.py', 'test-preserve-run411-guest.py'):
            save(DEST/'resume-tools'/name, (ROOT/'tools/rust-v2-lab'/name).read_bytes())
        record = dict(mode='resume-after-shutdown', guest_contact=False, qemu_actions=False, validated_utc=utc(),
                      qemu_exit_instant_utc=exit_record['exit_instant_utc'], state_cutoff_ns=cutoff,
                      state_cutoff_utc=ns_utc(cutoff), state_time_tolerance_ns=STATE_TIME_TOLERANCE_NS,
                      state_times_before_move=state_before_cutoff(cutoff), state_identity_before_move=before,
                      receipt_hashes={name:sha(DEST/name) for name in ('preflight.json','final-snapshot.command.json',
                                    'final-snapshot.stdout','poweroff.command.json','shutdown-request.json','qemu-exit.json')})
        save_json(DEST/'resume-validation.json', record)
        state_before_cutoff(cutoff); require_cold(data['process'])
        finish_preservation(data, serial, shutdown, snapshot_command['argv'][-1].startswith('sudo '), record)
    finally: os.close(fd)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--execute', action='store_true')
    mode.add_argument('--resume-after-shutdown', action='store_true', help='Offline only: validate the partial archive and finish its cold state move; never SSH/QEMU')
    parser.add_argument('--sudo-read-only-snapshot', action='store_true', help='Only with explicit authorization extending the poweroff-only sudo constraint')
    parser.add_argument('--shutdown-timeout', type=int, default=180)
    args = parser.parse_args()
    require(1 <= args.shutdown_timeout <= 300, 'unbounded_shutdown_timeout_refused')
    if args.resume_after_shutdown:
        require(not args.sudo_read_only_snapshot, 'resume_never_sudo')
        resume_after_shutdown()
        return
    data = preflight()
    if not args.execute:
        print(json.dumps(dict(dry_run=True, ssh_executed=False, guest_changes=False, destination=str(DEST),
                              qemu=data['process'], collected_files_validated=len(data['receipt']['retained']),
                              references_validated=len(data['refs']), pin=data['pin_record'], snapshot_compiles=True,
                              sudo_readonly_snapshot_requested=args.sudo_read_only_snapshot), indent=2))
        return
    execute(data, args.sudo_read_only_snapshot, args.shutdown_timeout)

if __name__ == '__main__': main()
