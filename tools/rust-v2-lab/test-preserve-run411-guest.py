#!/usr/bin/env python3
"""Synthetic fixtures only: never connects to or changes a lab guest."""
import errno
import importlib.util
import json
import os
import pathlib
import socket
import stat
import tempfile
import time
import unittest
from datetime import datetime, timezone, timedelta
from contextlib import contextmanager, ExitStack, chdir, redirect_stdout
import io
from types import SimpleNamespace
from unittest.mock import patch

def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, pathlib.Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

p = load('preserve411', 'preserve-run411-guest.py')
v = load('verify411', 'verify-preserved-run411.py')

class PreservationTests(unittest.TestCase):
    def test_process_start_and_complete_argv_fence(self):
        expected = dict(pid=42, start_time=123, argv=['qemu', '-accel', 'tcg'])
        p.match_process(expected, dict(pid=42, start_time=123, argv=expected['argv'], state='S'))
        for change in [dict(start_time=124), dict(argv=['qemu']), dict(state='Z'), dict(pid=43)]:
            with self.assertRaises(RuntimeError):
                p.match_process(expected, dict(pid=42, start_time=123, argv=expected['argv'], state='S', **{}) | change)

    def test_wait_timeout_never_signals(self):
        with patch.object(p.select, 'select', return_value=([], [], [])), patch.object(p.time, 'monotonic', side_effect=[0, 2]), patch.object(os, 'kill', side_effect=AssertionError('must not kill')):
            with self.assertRaisesRegex(RuntimeError, 'never_force_stop'):
                p.wait_exit(123, 1)

    ARM_SERIAL = (b'Reached target shutdown.target - System Shutdown.\n'
                  b'Reached target poweroff.target - System Power Off.\n'
                  b'systemd-shutdown[1]: Syncing filesystems and block devices.\n'
                  b'systemd-shutdown[1]: All filesystems unmounted.\n'
                  b'systemd-shutdown[1]: Powering off.\nreboot: Power down\n')

    def test_arm64_psci_shutdown_is_accepted_without_acpi(self):
        p.check_serial(self.ARM_SERIAL, 'debian-arm64')

    def test_x86_requires_acpi_s5(self):
        x86 = b'ACPI: PM: Preparing to enter system sleep state S5\nreboot: Power down\n'
        p.check_serial(x86, 'debian-x86_64')
        with self.assertRaises(RuntimeError): p.check_serial(self.ARM_SERIAL, 'debian-x86_64')

    def test_incomplete_halted_and_rebooted_serial_are_refused(self):
        for text in [b'reboot: Power down\n', self.ARM_SERIAL[:-20],
                     self.ARM_SERIAL.replace(b'reboot: Power down', b'reboot: System halted'),
                     self.ARM_SERIAL+b'Linux version new boot\n',
                     self.ARM_SERIAL+b'Linux version new boot\n'+self.ARM_SERIAL,
                     self.ARM_SERIAL.replace(b'systemd-shutdown[1]: Powering off.', b'Linux version new boot')]:
            with self.subTest(text=text), self.assertRaises(RuntimeError):
                p.check_serial(text, 'debian-arm64')

    def test_strict_ssh_and_only_explicit_snapshot_sudo(self):
        argv = p.ssh_argv('/key', '/pin')
        for item in ['GlobalKnownHostsFile=/dev/null', 'IdentityAgent=none', 'IdentitiesOnly=yes', 'StrictHostKeyChecking=yes', 'BatchMode=yes', 'UpdateHostKeys=no', 'UserKnownHostsFile=/pin']:
            self.assertIn(item, argv)
        self.assertEqual(argv[1:3], ['-F', '/dev/null'])
        self.assertEqual(argv[-1], 'vprouterlab@127.0.0.1')

    def fixture(self, root):
        source = root/'source'; source.mkdir()
        (source/'guest.qcow2').write_bytes(b'synthetic overlay')
        (source/'known_hosts').symlink_to('../pin')
        (root/'pin').write_bytes(b'public pin')
        s = socket.socket(socket.AF_UNIX); s.bind(str(source/'qmp.sock')); s.close()
        (source/'nested').mkdir(); (source/'nested/data').write_bytes(b'data')
        return source

    def test_same_filesystem_move_keeps_inode_symlink_and_socket(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td); source = self.fixture(root); dest = root/'state'
            inode = (source/'guest.qcow2').stat().st_ino
            self.assertEqual(p.move_state(source, dest), 'rename')
            self.assertFalse(source.exists()); self.assertEqual((dest/'guest.qcow2').stat().st_ino, inode)
            self.assertEqual(os.readlink(dest/'known_hosts'), '../pin')
            self.assertTrue(stat.S_ISSOCK((dest/'qmp.sock').lstat().st_mode))

    def test_cross_device_copy_is_verified_before_source_removal(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td); source = self.fixture(root); dest = root/'state'
            with patch.object(p.os, 'rename', side_effect=OSError(errno.EXDEV, 'synthetic cross device')):
                self.assertEqual(p.move_state(source, dest), 'copy_verify_remove')
            self.assertFalse(source.exists()); self.assertEqual((dest/'guest.qcow2').read_bytes(), b'synthetic overlay')
            self.assertEqual(os.readlink(dest/'known_hosts'), '../pin')
            self.assertTrue(stat.S_ISSOCK((dest/'qmp.sock').lstat().st_mode))

    def test_cross_device_corruption_retains_source(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td); source = self.fixture(root); dest = root/'state'
            with patch.object(p.os, 'rename', side_effect=OSError(errno.EXDEV, 'synthetic')), patch.object(p, 'tree_identity', side_effect=[{'original': 1}, {'corrupt': 1}]):
                with self.assertRaisesRegex(RuntimeError, 'copy_verification'): p.move_state(source, dest)
            self.assertTrue((source/'guest.qcow2').exists())

    def test_manifest_and_modes_detect_tampering_and_unlisted_files(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)/'archive'; root.mkdir()
            (root/'README.md').write_text('synthetic')
            p.seal(root)
            self.assertEqual(v.verify_manifest(root), 1)
            root.chmod(0o700); (root/'extra').write_text('unlisted')
            with self.assertRaises(RuntimeError): v.verify_manifest(root)
            (root/'extra').unlink(); root.chmod(0o500)
            (root/'README.md').chmod(0o600)
            with self.assertRaises(RuntimeError): v.verify_manifest(root)
            (root/'README.md').write_text('tampered'); (root/'README.md').chmod(0o400)
            with self.assertRaises(RuntimeError): v.verify_manifest(root)
            root.chmod(0o700)

    def test_remote_compiles_and_reads_only_explicit_public_archive_names(self):
        f = dict(nonce='a'*64, fixed_selectors={name: {} for name in p.SELECTORS})
        archive = dict(selectors_archived=[str(pathlib.PurePosixPath('/var/lib/vprouter-v2-lab')/('secret-inputs-'+f['nonce'])/('411-failed-'+name)) for name in p.SELECTORS])
        script = p.remote_program('unit', {}, f, archive)
        compile(script, '<synthetic snapshot>', 'exec')
        self.assertNotIn('sudo', script)
        self.assertNotIn('rglob', script)
        self.assertIn('411-failed-', script)
        archive['selectors_archived'][0] += '/../profile.conf'
        with self.assertRaises(RuntimeError): p.remote_program('unit', {}, f, archive)

    @contextmanager
    def execution_fixture(self):
        with tempfile.TemporaryDirectory() as td, ExitStack() as stack:
            root = pathlib.Path(td); state = root/'target/platform-lab/debian-arm64'; state.mkdir(parents=True)
            dest = root/'archive'
            (state/'process.json').write_text('{}'); (state/'known_hosts').write_bytes(b'pin')
            (state/'serial.log').write_bytes(self.ARM_SERIAL)
            (state/'guest.qcow2').write_bytes(b'synthetic overlay'); (state/'seed.iso').write_bytes(b'seed'); (state/'vars.fd').write_bytes(b'vars')
            for name in ['target/run411-evidence', 'target/candidates/run410-da75562-20261104/bootstrap411-arm64', 'exec']:
                (root/name).mkdir(parents=True)
            for name in ['target/lab-state/secret-bootstrap-failure-run-411.json', 'target/lab-state/secret-bootstrap-selector-archive-run-411.json', 'target/run411-evidence-post-state.json']:
                path = root/name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text('{}')
            for name in ['preserve-run411-guest.py', 'verify-preserved-run411.py', 'test-preserve-run411-guest.py']:
                path = root/'tools/rust-v2-lab'/name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text('# synthetic')
            process = dict(pid=493434, start_time=5902200, argv=['qemu'])
            data = dict(process=process, receipt=dict(retained=[]), refs={'target/platform-lab/debian-arm64/process.json': p.sha(state/'process.json')},
                        pin_record=dict(sha256=p.sha(state/'known_hosts')), pin_bytes=b'pin', special=[], script='# synthetic')
            calls = []
            snapshot = dict(guest_boot_id=p.BOOT, owner_absent=True, gateway=dict(original_identity_matches=True),
                            archived_selectors={str(i):{} for i in range(6)}, inventories=[])
            def command(archive, name, argv, body=None, timeout=90):
                calls.append((name, argv))
                record=dict(started_utc=p.utc(),completed_utc=p.utc(),exit_code=0,argv=argv)
                p.save_json(archive/(name+'.command.json'),record)
                return (0,json.dumps(snapshot),record)
            @contextmanager
            def material(*args): yield '/dedicated-key', '/dedicated-pin'
            for obj, name, value in [(p,'ROOT',root),(p,'STATE',state),(p,'DEST',dest),(p,'proc_identity',lambda pid:dict(process,state='S')),
                                     (p,'record_command',command),(p,'load',lambda *args:SimpleNamespace(ssh_material=material)),
                                     (p,'wait_exit',lambda *args:None),(p.os,'pidfd_open',lambda *args:123),(p.os,'close',lambda *args:None),
                                     (p.select,'select',lambda *args:([],[],[]))]:
                stack.enter_context(patch.object(obj,name,value,create=True))
            original_copy = p.copy_tree
            def copy(source, target, sockets=False):
                return original_copy(root/'exec' if source == pathlib.Path('/DATA/vprouter-lab/run411-exec') else source, target, sockets)
            stack.enter_context(patch.object(p,'copy_tree',copy))
            yield data, calls, snapshot, state, dest
            # Sealed fixture directories must be made writable for cleanup.
            if dest.exists():
                dest.chmod(0o700)
                for path in p.entries(dest):
                    if path.is_dir():path.chmod(0o700)

    def test_bad_snapshot_never_requests_poweroff_or_moves_state(self):
        for change in [dict(guest_boot_id='different'), dict(owner_absent=False), dict(gateway=dict(original_identity_matches=False))]:
            with self.subTest(change=change), self.execution_fixture() as (data,calls,snapshot,state,dest):
                snapshot.update(change)
                with self.assertRaisesRegex(RuntimeError, 'snapshot_incomplete'):p.execute(data,False,1)
                self.assertEqual([name for name,argv in calls],['final-snapshot'])
                self.assertTrue((state/'guest.qcow2').exists())
                self.assertEqual(calls[0][1][-1], 'python3 -I -B -')

    def test_shutdown_timeout_retains_state_and_never_moves_it(self):
        with self.execution_fixture() as (data,calls,snapshot,state,dest), patch.object(p,'wait_exit',side_effect=RuntimeError('timeout_STOP')):
            with self.assertRaisesRegex(RuntimeError,'timeout_STOP'):p.execute(data,True,1)
            self.assertEqual([name for name,argv in calls],['final-snapshot','poweroff'])
            self.assertEqual(calls[0][1][-1], 'sudo -n python3 -I -B -')
            self.assertTrue(calls[1][1][-1].endswith('sudo -n systemctl poweroff'))
            self.assertTrue((state/'guest.qcow2').exists());self.assertFalse((dest/'state').exists())

    def test_execute_records_exit_before_serial_validation_failure(self):
        with self.execution_fixture() as (data,calls,snapshot,state,dest):
            (state/'serial.log').write_bytes(b'incomplete')
            with self.assertRaisesRegex(RuntimeError,'serial_missing'):
                p.execute(data,True,1)
            receipt=json.loads((dest/'qemu-exit.json').read_bytes())
            self.assertEqual(receipt['method'],'pidfd-wait-completion')
            self.assertEqual(receipt['qemu_pid'],493434)
            self.assertLessEqual(p.timestamp_ns(receipt['exit_instant_utc']),time.time_ns())
            self.assertFalse((dest/'state').exists())

class ResumeTests(unittest.TestCase):
    @contextmanager
    def partial(self):
        with tempfile.TemporaryDirectory() as td, ExitStack() as stack:
            root = pathlib.Path(td); state = root/'state-source'; state.mkdir()
            stack.enter_context(chdir(root))
            dest = root/'archive'; dest.mkdir()
            for name, body in {'guest.qcow2':b'overlay', 'seed.iso':b'seed', 'vars.fd':b'vars',
                               'known_hosts':b'pin', 'serial.log':PreservationTests.ARM_SERIAL}.items():
                (state/name).write_bytes(body)
            process = dict(pid=493434, start_time=5902200, platform='debian-arm64', ssh_port=22034,
                           controller_boot_id=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(), argv=['qemu'])
            p.save_json(state/'process.json', process)
            for name in ['collected-chain/files/target/lab-state', 'reference-inputs/target/lab-state',
                         'preservation-tools', 'execution-evidence', 'runner-output']:
                (dest/name).mkdir(parents=True)
            raw = dest/'collected-chain/files'/p.RAW; raw.write_text('{}')
            a = dest/'reference-inputs/target/lab-state/secret-bootstrap-selector-archive-run-411.json'
            p.save_json(a, dict(record_sha256=p.sha(raw), failed_run=411, selectors_archived=[str(i) for i in range(6)]))
            f = a.with_name('secret-bootstrap-failure-run-411.json')
            p.save_json(f, dict(record_sha256=p.sha(raw), fixed_selectors={str(i):dict(sha256='a'*64,device=1,inode=i) for i in range(6)}))
            reservation = raw.with_name('run-411-reservation.json')
            p.save_json(reservation, dict(guest_boot_id=p.BOOT))
            claim = raw.with_name('run-411-consumed.json')
            p.save_json(claim, dict(run=411, budget_remaining=0, reservation_sha256=p.sha(reservation)))
            retained = [dict(path='target/lab-state/'+path.name, sha256=p.sha(path), bytes=path.stat().st_size)
                        for path in (raw,reservation,claim)]
            receipt = dict(run=411, provenance_valid=True, exit_code=1, outcome='failed_bootstrap_preserved', retained=retained)
            p.save_json(dest/'collected-chain/receipt.json', receipt)
            refs = {row['path']:row['sha256'] for row in retained}
            refs['target/platform-lab/debian-arm64/process.json']=p.sha(state/'process.json')
            # Reference process.json is already present in the real partial archive.
            p.save(dest/'reference-inputs/target/platform-lab/debian-arm64/process.json', (state/'process.json').read_bytes())
            pin_record = dict(original_path=str(state/'known_hosts'), was_symlink=False, link_text=None,
                              resolved_original_path=str(state/'known_hosts'), sha256=p.sha(state/'known_hosts'))
            p.save_json(dest/'preflight.json', dict(process=process, refs=refs, receipt=receipt, pin_record=pin_record, special=[]))
            p.save_json(dest/'symlink-record.json', pin_record); p.save(dest/'console-known_hosts', b'pin')
            p.save_json(dest/'special-record.json', [])
            p.save(dest/'final-snapshot-remote.py', b'# snapshot')
            snap = dict(guest_boot_id=p.BOOT, owner_absent=True, gateway=dict(original_identity_matches=True),
                        archived_selectors={str(i):dict(sha256='a'*64,dev=1,ino=i) for i in range(6)}, inventories=[dict(exit_code=0)],
                        private_profile_contents_read=False, read_only=True)
            p.save_json(dest/'final-snapshot.stdout', snap)
            now = (datetime.now(timezone.utc)-timedelta(seconds=10)).isoformat()
            snapshot = dict(argv=p.ssh_argv('/key','/pin')+['sudo -n python3 -I -B -'], started_utc=now, completed_utc=now, exit_code=0)
            shutdown = dict(argv=p.ssh_argv('/key','/pin')+['test "$(cat /proc/sys/kernel/random/boot_id)" = '+p.BOOT+' && sudo -n systemctl poweroff'],
                            started_utc=now, completed_utc=now, exit_code=0)
            p.save_json(dest/'final-snapshot.command.json', snapshot)
            p.save_json(dest/'poweroff.command.json', shutdown); p.save_json(dest/'shutdown-request.json', shutdown)
            exit_utc=p.utc()
            p.save_json(dest/'qemu-exit.json',dict(method='pidfd-wait-completion',exit_instant_utc=exit_utc,
                        exit_instant_ns=p.timestamp_ns(exit_utc),qemu_pid=493434,qemu_start_tick=5902200,
                        poweroff_command_sha256=p.sha(dest/'poweroff.command.json')))
            error=root/'exec/preserve.err'
            p.save(error,b'Traceback (most recent call last):\nserial = (STATE/\'serial.log\').read_bytes(); check_serial(serial)\nRuntimeError: serial_missing_final_ACPI_power_down_STOP\n')
            for name in ['final-snapshot.stderr','poweroff.stdout','poweroff.stderr']: p.save(dest/name,b'')
            for obj, name, value in [(p,'ROOT',root),(p,'STATE',state),(p,'DEST',dest),(p,'RAW_SHA',p.sha(raw)),(p,'A_SHA',p.sha(a)),
                                     (p,'proc_identity',lambda pid: (_ for _ in ()).throw(FileNotFoundError())),
                                     (p,'PRESERVE_ERR',error),(p,'PRESERVE_ERR_SHA',p.sha(error)),
                                     (p.subprocess,'run',lambda *a,**kw: (_ for _ in ()).throw(AssertionError('no subprocess'))),
                                     (p.socket.socket,'connect',lambda *a: (_ for _ in ()).throw(AssertionError('no connection')))]:
                stack.enter_context(patch.object(obj,name,value,create=True))
            for name,value in [('RAW_SHA',p.sha(raw)),('A_SHA',p.sha(a)),('SOURCE_STATE',state)]:
                stack.enter_context(patch.object(v,name,value,create=True))
            stack.enter_context(patch.object(v,'PRESERVE_ERR_SHA',p.sha(error),create=True))
            for name in ('preserve-run411-guest.py','verify-preserved-run411.py','test-preserve-run411-guest.py'):
                p.save(root/'tools/rust-v2-lab'/name, pathlib.Path(__file__).with_name(name).read_bytes())
            stack.enter_context(redirect_stdout(io.StringIO()))
            try: yield root,state,dest
            finally:
                if dest.exists():
                    dest.chmod(0o700)
                    for path in p.entries(dest):
                        if stat.S_ISDIR(path.lstat().st_mode): path.chmod(0o700)

    def test_resume_completes_cold_archive_without_guest_contact_and_never_removes_twice(self):
        with self.partial() as (root,state,dest):
            inode=(state/'guest.qcow2').stat().st_ino
            p.resume_after_shutdown()
            self.assertFalse(state.exists())
            self.assertEqual((dest/'state/guest.qcow2').stat().st_ino,inode)
            self.assertEqual((dest/'state/guest.qcow2').read_bytes(),b'overlay')
            self.assertGreater(v.verify_manifest(dest),10)
            self.assertEqual(v.verify(dest)['verifier'],'PASS')
            with self.assertRaises(RuntimeError): p.resume_after_shutdown()
            self.assertEqual((dest/'state/guest.qcow2').stat().st_ino,inode)

    def test_resume_refuses_modified_state_including_backdated_content(self):
        with self.partial() as (root,state,dest):
            time.sleep(2.05)  # A backdated mtime must still fail the exit+2s ctime fence.
            old=(state/'guest.qcow2').stat().st_mtime_ns
            (state/'guest.qcow2').write_bytes(b'tampered')
            os.utime(state/'guest.qcow2',ns=(old,old))
            with self.assertRaisesRegex(RuntimeError,'modified_after_shutdown'):p.resume_after_shutdown()
            self.assertTrue(state.exists());self.assertFalse((dest/'state').exists())

    def test_resume_accepts_writes_at_and_just_before_exit_and_at_tolerance(self):
        for offset in (-1_000_000,0,2_000_000_000):
            with self.subTest(offset=offset),self.partial() as (root,state,dest):
                exit_record=json.loads((dest/'qemu-exit.json').read_bytes())
                ns=exit_record['exit_instant_ns']+offset
                os.utime(state/'guest.qcow2',ns=(ns,ns))
                p.resume_after_shutdown()
                self.assertEqual(v.verify(dest)['verifier'],'PASS')
                receipt=json.loads((dest/'resume-validation.json').read_bytes())
                self.assertEqual(receipt['state_cutoff_ns'],exit_record['exit_instant_ns']+2_000_000_000)

    def test_resume_refuses_write_one_ns_after_exit_tolerance(self):
        with self.partial() as (root,state,dest):
            exit_record=json.loads((dest/'qemu-exit.json').read_bytes())
            ns=exit_record['exit_instant_ns']+2_000_000_001
            os.utime(state/'guest.qcow2',ns=(ns,ns))
            before=p.tree_identity(dest)
            with self.assertRaisesRegex(RuntimeError,'state_modified_after_shutdown:guest.qcow2'):
                p.resume_after_shutdown()
            self.assertEqual(p.tree_identity(dest),before)
            self.assertTrue(state.exists())

    def test_request_only_archive_derives_documented_exit_upper_bound(self):
        with self.partial() as (root,state,dest):
            (dest/'qemu-exit.json').unlink()
            error=root/'exec/preserve.err'; upper=error.stat().st_mtime_ns
            p.resume_after_shutdown()
            receipt=json.loads((dest/'qemu-exit.json').read_bytes())
            self.assertEqual(receipt['method'],'retained-post-wait-error-upper-bound')
            self.assertEqual(receipt['exit_instant_ns'],upper)
            self.assertIn('wait_exit',receipt['derivation'])
            self.assertEqual((dest/'qemu-exit-evidence/preserve.err').read_bytes(),error.read_bytes())
            self.assertEqual(receipt['evidence']['sha256'],p.sha(error))
            self.assertEqual(v.verify(dest)['verifier'],'PASS')

    def test_request_only_archive_refuses_missing_or_changed_exit_evidence(self):
        for missing in (True,False):
            with self.subTest(missing=missing),self.partial() as (root,state,dest):
                (dest/'qemu-exit.json').unlink()
                error=root/'exec/preserve.err'
                if missing:error.unlink()
                else:error.write_bytes(b'unrelated later failure')
                before=p.tree_identity(dest)
                with self.assertRaises((RuntimeError,FileNotFoundError)):p.resume_after_shutdown()
                self.assertEqual(p.tree_identity(dest),before)
                self.assertTrue(state.exists())

    def test_verifier_refuses_exit_receipt_identity_and_late_state_time(self):
        for late_time in (False,True):
            with self.subTest(late_time=late_time),self.partial() as (root,state,dest):
                p.resume_after_shutdown()
                dest.chmod(0o700)
                for path in p.entries(dest):
                    if stat.S_ISDIR(path.lstat().st_mode):path.chmod(0o700)
                if late_time:
                    path=dest/'resume-validation.json'
                    record=json.loads(path.read_bytes())
                    record['state_times_before_move']['guest.qcow2']['mtime_ns']=record['state_cutoff_ns']+1
                    path.chmod(0o600);path.write_text(json.dumps(record))
                    path=dest/'preservation.json';preserved=json.loads(path.read_bytes());preserved['resume']=record
                    path.chmod(0o600);path.write_text(json.dumps(preserved))
                else:
                    path=dest/'qemu-exit.json';record=json.loads(path.read_bytes());record['qemu_pid']=1
                    path.chmod(0o600);path.write_text(json.dumps(record))
                (dest/'SHA256SUMS').unlink();p.seal(dest)
                with self.assertRaisesRegex(RuntimeError,'exit_receipt|state_time'):
                    v.verify(dest)

    def test_resume_refuses_missing_or_inconsistent_receipts(self):
        for name in ['shutdown-request.json','poweroff.command.json','final-snapshot.stdout','preflight.json']:
            with self.subTest(name=name), self.partial() as (root,state,dest):
                (dest/name).unlink()
                with self.assertRaises((RuntimeError,FileNotFoundError)):p.resume_after_shutdown()
                self.assertTrue(state.exists())
        with self.partial() as (root,state,dest):
            (dest/'poweroff.command.json').write_text('{}')
            with self.assertRaises(RuntimeError):p.resume_after_shutdown()
            self.assertTrue(state.exists())

    def test_resume_refuses_live_pid_even_without_guest_contact(self):
        with self.partial() as (root,state,dest), patch.object(p,'proc_identity',return_value=dict(pid=493434,start_time=5902200,state='S',argv=['qemu'])):
            with self.assertRaisesRegex(RuntimeError,'qemu_identity_still_present'):p.resume_after_shutdown()
            self.assertTrue(state.exists())

    def test_resume_refuses_listener_and_tampered_collected_raw(self):
        with self.partial() as (root,state,dest), socket.socket() as listener:
            listener.bind(('127.0.0.1',22034));listener.listen()
            with self.assertRaises((RuntimeError,OSError)):p.resume_after_shutdown()
            self.assertTrue(state.exists())
        with self.partial() as (root,state,dest):
            (dest/'collected-chain/files'/p.RAW).write_bytes(b'tamper')
            with self.assertRaises(RuntimeError):p.resume_after_shutdown()
            self.assertTrue(state.exists())

    def test_resume_refuses_snapshot_selector_identity_changed(self):
        with self.partial() as (root,state,dest):
            snap=json.loads((dest/'final-snapshot.stdout').read_bytes())
            snap['archived_selectors']['0']['ino']=999
            (dest/'final-snapshot.stdout').write_text(json.dumps(snap))
            with self.assertRaisesRegex(RuntimeError,'archived_selector_identity'):p.resume_after_shutdown()
            self.assertTrue(state.exists())

    def test_verifier_refuses_fixed_A_hash_tamper_even_after_new_manifest(self):
        with self.partial() as (root,state,dest):
            p.resume_after_shutdown()
            dest.chmod(0o700)
            for path in p.entries(dest):
                if stat.S_ISDIR(path.lstat().st_mode):path.chmod(0o700)
            a=dest/'reference-inputs/target/lab-state/secret-bootstrap-selector-archive-run-411.json'
            a.chmod(0o600);a.write_bytes(a.read_bytes()+b'\n')
            (dest/'SHA256SUMS').unlink();p.seal(dest)
            with self.assertRaisesRegex(RuntimeError,'original_A_receipt_hash'):v.verify(dest)

if __name__ == '__main__': unittest.main(verbosity=2)
