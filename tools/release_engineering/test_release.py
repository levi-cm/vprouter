"""Offline behaviour tests; all filesystem mutations stay in TemporaryDirectory."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('release', Path(__file__).with_name('release.py'))
r = importlib.util.module_from_spec(SPEC)
if SPEC.loader:
    try:
        SPEC.loader.exec_module(r)
    except FileNotFoundError:
        pass


class Services(unittest.TestCase):
    def test_no_generated_service_can_activate_and_order_is_explicit(self):
        self.assertTrue(hasattr(r, 'services'), 'missing service generator')
        for manager in ('systemd', 'runit'):
            files = r.services(manager, 'max-vprouter', 'candidate-1')
            self.assertEqual(files, r.services(manager, 'max-vprouter', 'candidate-1'))
            self.assertTrue(all(f['uid'] == 0 and f['gid'] == 0 for f in files))
            self.assertTrue(all('state' not in f['path'] for f in files))
            text = '\n'.join(f.get('content', '') for f in files)
            self.assertNotIn('ExecStop=', text)
            if manager == 'systemd':
                self.assertIn('NoNewPrivileges=yes', text)
                self.assertIn('CapabilityBoundingSet=\n', text)
                self.assertIn('ProtectSystem=strict', text)
                self.assertIn('PrivateTmp=yes', text)
                self.assertIn('ExecStart=/usr/bin/false', text)
                self.assertIn('After=network-online.target', text)
            else:
                self.assertTrue(any(f['path'].endswith('/down') for f in files))
                self.assertIn('exec /usr/bin/false', text)



# Removing path validation, owner/content comparison, or readiness refusal must fail these.
class Plans(unittest.TestCase):
    def manifest(self, version='candidate-1'):
        self.assertTrue(hasattr(r, 'ownership_manifest'), 'missing ownership manifest')
        return r.ownership_manifest('systemd', 'max-vprouter', version, 'state-v1')

    def test_uninstall_exact_owned_only_and_idempotent_empty_install(self):
        m = self.manifest()
        observed = {f['path']: f for f in m['files']}
        observed['/var/lib/vprouter/identity'] = {'foreign': True}
        plan = r.plan('uninstall', m, None, observed)
        self.assertEqual(set(plan['remove']), {f['path'] for f in m['files']})
        self.assertFalse(plan['release_ready'])
        self.assertEqual(plan, r.plan('uninstall', m, None, observed))
        install = r.plan('install', None, m, {})
        self.assertEqual(install['write'], m['files'])
        self.assertEqual(r.plan('install', None, m, {f['path']: f for f in m['files']})['write'], [])

    def test_foreign_mutated_and_injected_inputs_refuse(self):
        import copy
        m = self.manifest()
        for field, bad in [('uid', 10), ('mode', 0o777), ('sha256', '0' * 64), ('owner', 'foreign')]:
            with self.subTest(field=field):
                observed = {f['path']: copy.deepcopy(f) for f in m['files']}
                observed[m['files'][0]['path']][field] = bad
                with self.assertRaises(ValueError):
                    r.plan('uninstall', m, None, observed)
        for bad in ('x\nExecStart=evil', 'x%u', 'x$HOME', '../x', 'x/y', 'x"', 'é', 'x\x00', '', 'x'*49):
            for manager in ('systemd', 'runit'):
                with self.subTest(bad=bad, manager=manager), self.assertRaises(ValueError):
                    r.services(manager, bad, 'candidate-1')
        mutated = copy.deepcopy(m)
        mutated['files'][0]['path'] = '/var/lib/vprouter/identity'
        with self.assertRaises(ValueError):
            r.plan('uninstall', mutated, None, {})

    def test_update_and_rollback_exchange_real_directory_preserving_state(self):
        old, new = self.manifest(), self.manifest('candidate-2')
        observed = {f['path']: f for f in old['files']}
        for operation, source, dest in [('update', old, new), ('rollback', old, new)]:
            p = r.plan(operation, source, dest, observed)
            self.assertEqual(p['exchange']['kind'], 'renameat2_RENAME_EXCHANGE_real_directories')
            self.assertEqual(p['steps'][0], 'independent_quarantine_and_client_guards')
            self.assertLess(p['steps'].index('capture_ready_this_boot'), p['steps'].index('protected_workloads'))
            self.assertTrue(p['exchange']['retain_previous'])
        new['state_format'] = 'incompatible'
        with self.assertRaises(ValueError):
            r.plan('rollback', old, new, observed)
        with self.assertRaises(ValueError):
            r.plan('activate', old, new, observed)


class Artifacts(unittest.TestCase):
    def bundle(self):
        self.assertTrue(hasattr(r, 'build_bundle'), 'missing artifact builder')
        import struct
        binaries = {}
        for target, machine in zip(r.TARGETS, (62, 183)):
            # Minimal static ELF64 with one LOAD header, never executed.
            data = bytearray(120)
            data[:7] = b'\x7fELF\x02\x01\x01'
            struct.pack_into('<HHIQQQIHHHHHH', data, 16, 2, machine, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0)
            struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, 0, 0, 0, 120, 120, 4096)
            for name in r.BINARIES:
                binaries[target + '--' + name] = bytes(data)
        repo = Path(__file__).resolve().parents[2]
        lock = (repo / 'Cargo.lock').read_bytes()
        inventories = {arch: (repo / ('docs/rust-v2/programs-' + arch + '.json')).read_bytes()
                       for arch in ('amd64', 'arm64')}
        return r.build_bundle(binaries, lock, inventories, 'c0c730d2a216d68ac493a785de732a055f660d3e',
                              '1.97.0', 'offline-fixture-builder-v1')

    def test_deterministic_inventory_sbom_provenance_and_no_unsigned_release(self):
        files = self.bundle()
        self.assertEqual(files, self.bundle())
        anchor = r.digest(files['SHA256SUMS'])
        report = r.verify_bundle(files, anchor)
        self.assertFalse(report['release_ready'])
        self.assertEqual(report['signature'], 'UNSIGNED')
        sbom = r.parse_json(files['sbom.cdx.json'])
        self.assertEqual(sbom['bomFormat'], 'CycloneDX')
        self.assertTrue(any(c['name'] == 'tailscaled' for c in sbom['components']))
        self.assertTrue(any(c['name'] == 'serde' for c in sbom['components']))
        prov = r.parse_json(files['provenance.json'])
        self.assertEqual(len(prov['subject']), len(r.TARGETS) * len(r.BINARIES))
        with self.assertRaises(ValueError):
            r.verify_bundle(files, anchor, require_release=True)

    def test_every_bundle_byte_and_membership_mutation_refuses(self):
        files = self.bundle()
        anchor = r.digest(files['SHA256SUMS'])
        for name in files:
            with self.subTest(name=name):
                mutated = dict(files)
                mutated[name] += b' '
                with self.assertRaises(ValueError):
                    r.verify_bundle(mutated, anchor)
                del mutated[name]
                with self.assertRaises(ValueError):
                    r.verify_bundle(mutated, anchor)
        for bad in ('../evil', '/evil', 'a//b', 'a/./b', 'a\\b', 'é', 'x\x00', 'x\n', 'extra'):
            with self.subTest(name=bad), self.assertRaises(ValueError):
                r.verify_bundle(dict(files, **{bad: b'x'}), anchor)
        with self.assertRaises(ValueError):
            r.parse_json(b'{"x":1,"x":2}')
        with self.assertRaises(ValueError):
            r.parse_json(b'{"x":NaN}')

    def test_static_elf_and_exact_target_set_required(self):
        files = self.bundle()
        # Rebuild from verified materials with forged headers / absent target.
        args = r.bundle_inputs(files)
        name = next(iter(args['binaries']))
        for offset, replacement in ((18, b'\x03\x00'), (64, b'\x03\x00\x00\x00'), (54, b'\x00\x00')):
            mutated = dict(args)
            mutated['binaries'] = dict(args['binaries'])
            data = bytearray(mutated['binaries'][name])
            data[offset:offset+len(replacement)] = replacement
            mutated['binaries'][name] = bytes(data)
            with self.assertRaises(ValueError):
                r.build_bundle(**mutated)
        del args['binaries'][name]
        with self.assertRaises(ValueError):
            r.build_bundle(**args)


class FixturePublication(unittest.TestCase):
    bundle = Artifacts.bundle
    def fixture(self, root):
        import os
        os.chmod(root, 0o700)
        (root / 'offline-release.fixture').write_bytes(b'offline-release-fixture-v1\n')
        (root / '.release.lock').write_bytes(b'offline-release-lock-v1\n')
        for name in ('offline-release.fixture', '.release.lock'):
            os.chmod(root / name, 0o600)

    def test_publish_reopen_identical_and_refuse_all_metadata_attacks(self):
        import os
        import tempfile
        files = self.bundle()
        anchor = r.digest(files['SHA256SUMS'])
        self.assertTrue(hasattr(r, 'FixtureStore'), 'missing fixture publication')
        for attack in ('symlink', 'hardlink', 'mode', 'timestamp', 'extra', 'missing', 'rename-over'):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                self.fixture(root)
                with r.FixtureStore(root) as store:
                    store.publish(files, anchor)
                    self.assertEqual(store.read(anchor)['release_ready'], False)
                    store.publish(files, anchor)
                    leaf = root / 'bundle' / 'manifest.json'
                    if attack == 'symlink':
                        leaf.unlink()
                        leaf.symlink_to(root / 'offline-release.fixture')
                    elif attack == 'hardlink':
                        leaf.unlink()
                        os.link(root / 'offline-release.fixture', leaf)
                    elif attack == 'mode':
                        os.chmod(leaf, 0o666)
                    elif attack == 'timestamp':
                        os.utime(leaf, ns=(0, 1))
                    elif attack == 'extra':
                        (root / 'bundle' / 'extra').write_bytes(b'foreign')
                    elif attack == 'missing':
                        leaf.unlink()
                    else:
                        leaf.rename(root / 'retained')
                        leaf.write_bytes(b'foreign')
                        os.chmod(leaf, 0o444)
                        os.utime(leaf, ns=(0, 0))
                    with self.assertRaises((ValueError, OSError)):
                        store.read(anchor)

    def test_fault_at_every_publish_boundary_retains_evidence_and_recovers(self):
        import tempfile
        self.assertTrue(hasattr(r, 'FixtureStore'), 'missing fixture publication')
        files = self.bundle()
        anchor = r.digest(files['SHA256SUMS'])
        checkpoints = []
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root)
            with r.FixtureStore(root) as store:
                store.publish(files, anchor, checkpoint=checkpoints.append)
        self.assertIn('before_rename', checkpoints)
        self.assertIn('after_directory_fsync', checkpoints)
        for boundary in range(len(checkpoints)):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                self.fixture(root)
                cursor = [0]
                def fault(_):
                    i = cursor[0]
                    cursor[0] += 1
                    if i == boundary:
                        raise OSError('injected interruption')
                with r.FixtureStore(root) as store:
                    with self.assertRaises(OSError):
                        store.publish(files, anchor, checkpoint=fault)
                    store.recover(files, anchor)
                    store.publish(files, anchor)
                    before = {p.name: p.read_bytes() for p in (root / 'bundle').iterdir()}
                    store.publish(files, anchor)
                    self.assertEqual(before, {p.name: p.read_bytes() for p in (root / 'bundle').iterdir()})
                    self.assertEqual(store.read(anchor)['status'], 'OFFLINE_INTEGRITY_ONLY')

    def test_root_lock_pending_symlink_and_rename_attacks_never_adopt_or_delete(self):
        import os
        import tempfile
        self.assertTrue(hasattr(r, 'FixtureStore'), 'missing fixture publication')
        files = self.bundle()
        anchor = r.digest(files['SHA256SUMS'])
        for attack in ('no-marker', 'symlink-root', 'lock-replace', 'root-replace',
                       'pending-foreign', 'pending-symlink', 'pending-hardlink', 'destination-race'):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as tmp:
                parent = Path(tmp)
                root = parent / 'root'
                root.mkdir(mode=0o700)
                self.fixture(root)
                if attack == 'no-marker':
                    (root / 'offline-release.fixture').unlink()
                    with self.assertRaises((ValueError, OSError)):
                        r.FixtureStore(root)
                    continue
                if attack == 'symlink-root':
                    alias = parent / 'alias'
                    alias.symlink_to(root)
                    with self.assertRaises((ValueError, OSError)):
                        r.FixtureStore(alias)
                    continue
                with r.FixtureStore(root) as store:
                    if attack == 'lock-replace':
                        lock = root / '.release.lock'
                        lock.rename(root / 'old-lock')
                        lock.write_bytes(b'offline-release-lock-v1\n')
                        os.chmod(lock, 0o600)
                    elif attack == 'root-replace':
                        root.rename(parent / 'retained')
                        root.mkdir(mode=0o700)
                        self.fixture(root)
                    elif attack.startswith('pending-'):
                        pending = root / '.pending'
                        pending.mkdir(mode=0o700)
                        leaf = pending / 'manifest.json'
                        if attack == 'pending-foreign':
                            leaf.write_bytes(b'foreign-not-an-owned-prefix')
                            os.chmod(leaf, 0o600)
                        elif attack == 'pending-symlink':
                            leaf.symlink_to(root / 'offline-release.fixture')
                        else:
                            os.link(root / 'offline-release.fixture', leaf)
                        with self.assertRaises((ValueError, OSError)):
                            store.recover(files, anchor)
                        self.assertTrue(leaf.exists())
                    else:
                        def race(label):
                            if label == 'before_rename':
                                (root / 'bundle').mkdir(mode=0o700)
                        with self.assertRaises((ValueError, OSError)):
                            store.publish(files, anchor, checkpoint=race)
                        self.assertTrue((root / '.pending').exists())
                        continue
                    with self.assertRaises((ValueError, OSError)):
                        store.publish(files, anchor)


class ClassClosure(unittest.TestCase):
    def test_ownership_must_cover_real_release_directory_and_binary_bindings(self):
        m = r.ownership_manifest('systemd', 'max-vprouter', 'candidate-1', 'state-v1')
        # Dropping the real release directory inventory must be detected.
        self.assertTrue(any(f['path'].startswith('/opt/vprouter/releases/candidate-1/')
                            for f in m['files']), 'release ownership inventory missing')

    def test_inventory_role_path_swap_is_not_a_valid_pinned_program_input(self):
        import json
        files = Artifacts.bundle(self)
        args = r.bundle_inputs(files)
        inv = json.loads(args['inventories']['amd64'])
        inv['programs'][0]['path'] = '/usr/local/bin/tailscaled'
        args['inventories']['amd64'] = json.dumps(inv).encode()
        with self.assertRaises(ValueError):
            r.build_bundle(**args)

    def test_source_materials_cannot_smuggle_undeclared_host_path_or_timestamp(self):
        args = r.bundle_inputs(Artifacts.bundle(self))
        # Cargo source inventory has no authority to add build-host fields.
        args['lock'] += b'\n[metadata]\nhost_path = "/home/sensitive"\n'
        with self.assertRaises(ValueError):
            r.build_bundle(**args)


class StrictBoundaries(unittest.TestCase):
    def test_unknown_host_preflight_and_unproved_runit_contract_remain_blocked(self):
        self.assertTrue(hasattr(r, 'preflight'), 'missing pure host preflight')
        host = {'os': 'linux', 'distro': 'debian13', 'libc': 'glibc', 'manager': 'systemd',
                'arch': 'x86_64', 'kernel': [6, 1], 'cgroup': 2, 'nft': True, 'wireguard': True, 'tun': True}
        self.assertEqual(r.preflight(host)['status'], 'UNVERIFIED_NATIVE_GATES')
        for field, bad in [('os', 'darwin'), ('distro', 'voidmusl'), ('libc', 'musl'),
                           ('manager', 'openrc'), ('arch', 'riscv64'), ('kernel', [6, 0]),
                           ('cgroup', 1), ('nft', False), ('wireguard', False), ('tun', False)]:
            changed = dict(host, **{field: bad})
            with self.subTest(field=field), self.assertRaises(ValueError):
                r.preflight(changed)
        host.update(distro='void', manager='runit')
        p = r.preflight(host)
        self.assertIn('runit_native_cgroup_watchdog_readiness', p['blocked_on'])
        self.assertFalse(p['release_ready'])

    def test_pure_build_recipe_pins_offline_cross_toolchain_and_four_jobs(self):
        self.assertTrue(hasattr(r, 'build_recipe'), 'missing build recipe')
        recipe = r.build_recipe()
        self.assertEqual(len(recipe), 2)
        for invocation in recipe:
            argv = invocation['argv']
            self.assertIn('--offline', argv)
            self.assertIn('--locked', argv)
            self.assertIn('--release', argv)
            self.assertEqual(argv[argv.index('-j') + 1], '4')
            self.assertEqual(invocation['env']['SOURCE_DATE_EPOCH'], '0')
            self.assertEqual(invocation['env']['CARGO_BUILD_JOBS'], '4')
            self.assertEqual(invocation['execute'], False)

    def test_binary_install_inventory_requires_complete_fixed_name_set(self):
        hashes = {name: 'a' * 64 for name in r.BINARIES}
        m = r.ownership_manifest('runit', 'max-vprouter', 'candidate-1', 'state-v1', hashes)
        binary_paths = {f['path'] for f in m['files'] if f.get('content') is None}
        self.assertEqual(binary_paths, {'/opt/vprouter/releases/candidate-1/' + n for n in r.BINARIES})
        observed = {f['path']: f for f in m['files']}
        self.assertFalse(r.plan('uninstall', m, None, observed)['release_ready'])
        for bad in ('../state', '/identity', 'x%u', 'x$HOME'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                r.ownership_manifest('runit', 'max-vprouter', 'candidate-1', 'state-v1', {bad:'a'*64})
        for path in ('/x/../identity', '//identity', '/a/./b', '/é', '/x\n'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                r.plan('uninstall', m, None, dict(observed, **{path: {}}))

    def test_store_rejects_ancestor_permissions_drift_and_closed_store_is_terminal(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root = parent / 'fixture'
            root.mkdir(mode=0o700)
            FixturePublication.fixture(self, root)
            files = Artifacts.bundle(self)
            anchor = r.digest(files['SHA256SUMS'])
            with r.FixtureStore(root) as store:
                os.chmod(parent, 0o777)
                try:
                    with self.assertRaises(ValueError):
                        store.publish(files, anchor)
                finally:
                    os.chmod(parent, 0o700)
            with self.assertRaises(ValueError):
                store.publish(files, anchor)


class PreservationAndBounds(unittest.TestCase):
    def test_update_never_schedules_deletion_of_retained_rollback_release(self):
        old = r.ownership_manifest('systemd', 'max-vprouter', 'candidate-1', 'state-v1')
        new = r.ownership_manifest('systemd', 'max-vprouter', 'candidate-2', 'state-v1')
        p = r.plan('update', old, new, {f['path']:f for f in old['files']})
        self.assertFalse(any(path.startswith('/opt/vprouter/releases/candidate-1') for path in p['remove']),
                         'update deletes the retained rollback release')

    def test_modified_directory_time_fifo_sparse_size_and_lock_content_refuse(self):
        import os
        import tempfile
        files = Artifacts.bundle(self)
        anchor = r.digest(files['SHA256SUMS'])
        for attack in ('directory-time', 'fifo', 'sparse', 'lock-bytes'):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                FixturePublication.fixture(self, root)
                with r.FixtureStore(root) as store:
                    store.publish(files, anchor)
                    leaf = root / 'bundle' / 'manifest.json'
                    if attack == 'directory-time':
                        os.utime(root / 'bundle', ns=(0, 1))
                    elif attack == 'lock-bytes':
                        (root / '.release.lock').write_bytes(b'foreign')
                    else:
                        leaf.unlink()
                        if attack == 'fifo':
                            os.mkfifo(leaf, 0o444)
                        else:
                            with leaf.open('wb') as f:
                                f.truncate(r.MAX_FILE + 1)
                            os.chmod(leaf, 0o444)
                            os.utime(leaf, ns=(0, 0))
                        os.utime(root / 'bundle', ns=(0, 0))
                    with self.assertRaises((ValueError, OSError)):
                        store.read(anchor)

    def test_partial_and_zero_write_and_recovery_interruption_are_bounded(self):
        import os
        import tempfile
        from unittest.mock import patch
        files = Artifacts.bundle(self)
        anchor = r.digest(files['SHA256SUMS'])
        original = os.write
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            FixturePublication.fixture(self, root)
            with r.FixtureStore(root) as store:
                # Real filesystem short writes; not a success-returning fake.
                with patch.object(r.os, 'write', side_effect=lambda fd, data: original(fd, data[:31])):
                    store.publish(files, anchor)
                self.assertEqual(store.read(anchor)['status'], 'OFFLINE_INTEGRITY_ONLY')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            FixturePublication.fixture(self, root)
            with r.FixtureStore(root) as store:
                with patch.object(r.os, 'write', return_value=0):
                    with self.assertRaises(ValueError):
                        store.publish(files, anchor)
                self.assertTrue((root / '.pending').exists())
                store.recover(files, anchor)
                store.publish(files, anchor)


class RecoveryAndCustody(unittest.TestCase):
    def test_recovery_before_and_after_each_unlink_replays_safely(self):
        import os
        import tempfile
        from unittest.mock import patch
        files = Artifacts.bundle(self)
        anchor = r.digest(files['SHA256SUMS'])
        unlink = os.unlink
        for after in (False, True):
            for boundary in range(len(files)):
                with self.subTest(after=after, boundary=boundary), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    FixturePublication.fixture(self, root)
                    with r.FixtureStore(root) as store:
                        def stop(label):
                            if label == 'before_rename':
                                raise OSError('stop with complete pending')
                        with self.assertRaises(OSError):
                            store.publish(files, anchor, checkpoint=stop)
                        cursor = [0]
                        def fail_unlink(*args, **kwargs):
                            i = cursor[0]
                            cursor[0] += 1
                            if i == boundary and not after:
                                raise OSError('before unlink')
                            value = unlink(*args, **kwargs)
                            if i == boundary and after:
                                raise OSError('after unlink')
                            return value
                        with patch.object(r.os, 'unlink', side_effect=fail_unlink):
                            with self.assertRaises(OSError):
                                store.recover(files, anchor)
                        store.recover(files, anchor)
                        store.recover(files, anchor)
                        store.publish(files, anchor)
                        self.assertFalse(store.read(anchor)['release_ready'])

    def test_lock_contention_and_missing_lock_never_reset_existing_inode(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            FixturePublication.fixture(self, root)
            inode = (root / '.release.lock').stat().st_ino
            with r.FixtureStore(root):
                with self.assertRaises(BlockingIOError):
                    r.FixtureStore(root)
            with r.FixtureStore(root):
                self.assertEqual(inode, (root / '.release.lock').stat().st_ino)
            (root / '.release.lock').unlink()
            with self.assertRaises(FileNotFoundError):
                r.FixtureStore(root)
            self.assertFalse((root / '.release.lock').exists())

    def test_bad_types_are_refused_before_any_payload_data_open(self):
        import os
        import tempfile
        from unittest.mock import patch
        files = Artifacts.bundle(self)
        anchor = r.digest(files['SHA256SUMS'])
        original = os.open
        for attack in ('symlink', 'hardlink', 'fifo', 'mode'):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                FixturePublication.fixture(self, root)
                with r.FixtureStore(root) as store:
                    store.publish(files, anchor)
                    leaf = root / 'bundle' / 'manifest.json'
                    leaf.unlink()
                    if attack == 'symlink':
                        leaf.symlink_to(root / 'offline-release.fixture')
                    elif attack == 'hardlink':
                        os.link(root / 'offline-release.fixture', leaf)
                    elif attack == 'fifo':
                        os.mkfifo(leaf, 0o444)
                    else:
                        leaf.write_bytes(b'foreign')
                        os.chmod(leaf, 0o666)
                    os.utime(root / 'bundle', ns=(0, 0))
                    opened = []
                    def tracking(path, *args, **kwargs):
                        opened.append(path)
                        return original(path, *args, **kwargs)
                    with patch.object(r.os, 'open', side_effect=tracking):
                        with self.assertRaises((ValueError, OSError)):
                            store.read(anchor)
                    self.assertNotIn('manifest.json', opened)


class BundleScope(unittest.TestCase):
    def test_sbom_binds_supplied_binaries_separately_from_pinned_inputs(self):
        files = Artifacts.bundle(self)
        bom = r.parse_json(files['sbom.cdx.json'])
        actual = {c['name']:c for c in bom['components'] if c['bom-ref'].startswith('artifact:')}
        expected = {name for name in files if '--' in name}
        self.assertEqual(set(actual), expected)
        for name in expected:
            self.assertEqual(actual[name]['hashes'][0]['content'], r.digest(files[name]))

    def test_extra_unknown_member_is_refused_before_its_data_is_opened(self):
        import os
        import tempfile
        from unittest.mock import patch
        files = Artifacts.bundle(self)
        anchor = r.digest(files['SHA256SUMS'])
        original = os.open
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            FixturePublication.fixture(self, root)
            with r.FixtureStore(root) as store:
                store.publish(files, anchor)
                extra = root / 'bundle' / 'unexpected'
                extra.write_bytes(b'foreign')
                os.chmod(extra, 0o444)
                os.utime(extra, ns=(0, 0))
                os.utime(root / 'bundle', ns=(0, 0))
                opened = []
                def tracking(path, *args, **kwargs):
                    opened.append(path)
                    return original(path, *args, **kwargs)
                with patch.object(r.os, 'open', side_effect=tracking):
                    with self.assertRaises(ValueError):
                        store.read(anchor)
                self.assertNotIn('unexpected', opened)


class ExactTypes(unittest.TestCase):
    def test_numeric_aliases_cannot_forge_owned_manifest_or_observations(self):
        import copy
        manifest = r.ownership_manifest('systemd', 'max-vprouter', 'candidate-1', 'state-v1')
        for field, value in (('schema', True), ('release_ready', 0)):
            mutated = copy.deepcopy(manifest)
            mutated[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                r.plan('uninstall', mutated, None, {f['path']:f for f in manifest['files']})
        for field, value in (('uid', False), ('gid', 0.0), ('mode', 420.0)):
            observed = {f['path']:copy.deepcopy(f) for f in manifest['files']}
            observed[manifest['files'][0]['path']][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                r.plan('uninstall', manifest, None, observed)

    def test_boolean_inventory_version_is_not_version_one(self):
        import json
        args = r.bundle_inputs(Artifacts.bundle(self))
        inv = json.loads(args['inventories']['amd64'])
        inv['schema'] = True
        args['inventories']['amd64'] = json.dumps(inv).encode()
        with self.assertRaises(ValueError):
            r.build_bundle(**args)

class ReviewLifecycle(unittest.TestCase):
    # Missing restoration, stale-boot reuse, restart-before-verify and foreign
    # removal must fail. Expectations below come from IMPLEMENTATION.md:49-54.
    def test_all_lifecycle_plans_keep_required_order_and_offline_failure_policy(self):
        import copy
        import contextlib
        from unittest.mock import patch
        prefix = ['independent_quarantine_and_client_guards',
                  'verify_native_authenticated_ownership', 'capture_ready_this_boot',
                  'drain_adapters', 'stop_all_identity_users',
                  'verify_all_identity_users_stopped', 'stopped_state_compatible_backup']
        restart = ['verify_same_identity_then_name', 'controlled_restart',
                   'verify_guard_and_client_coverage', 'protected_workloads', 'commit']
        transitions = {
            'install': ['stage_complete_release'] + restart,
            'update': ['stage_complete_release', 'atomic_exchange'] + restart,
            'rollback': ['select_retained_compatible_stopped_state_backup',
                         'verify_backup_release_state_identity_binding',
                         'stage_complete_release', 'atomic_exchange',
                         'restore_compatible_stopped_state', 'verify_restored_stopped_state'] + restart,
            'uninstall': ['remove_exact_owned_leaves_and_empty_dirs', 'retain_all_guards', 'offline'],
            'reboot-recovery': ['reconcile_persistent_ownership_this_boot',
                                'verify_current_release_and_state_pair'] + restart}
        for manager in ('systemd', 'runit'):
            old = r.ownership_manifest(manager, 'max-vprouter', 'candidate-1', 'state-v1')
            new = r.ownership_manifest(manager, 'max-vprouter', 'candidate-2', 'state-v1')
            for operation, tail in transitions.items():
                current = None if operation == 'install' else (new if operation == 'rollback' else old)
                desired = None if operation == 'uninstall' else (new if operation == 'update' else old)
                observed = {f['path']: copy.deepcopy(f) for f in current['files']} if current else {}
                observed['/var/lib/vprouter/foreign-state'] = {'foreign': True}
                before = copy.deepcopy(observed)
                with self.subTest(manager=manager, operation=operation):
                    # There is no lifecycle executor: planning must stay pure.
                    with contextlib.ExitStack() as no_io:
                        for syscall in ('open', 'stat', 'fstat', 'read', 'scandir', 'mkdir',
                                        'write', 'fsync', 'fchmod', 'utime', 'rename', 'unlink',
                                        'rmdir', 'close'):
                            no_io.enter_context(patch.object(r.os, syscall,
                                side_effect=AssertionError('plan performed IO: ' + syscall)))
                        no_io.enter_context(patch.object(r.fcntl, 'flock',
                            side_effect=AssertionError('plan acquired a native lock')))
                        try:
                            p = r.plan(operation, current, desired, observed)
                        except ValueError as exc:
                            self.fail('valid lifecycle transition refused: ' + str(exc))
                        self.assertEqual(p, r.plan(operation, current, desired, observed))
                    self.assertEqual(p['steps'], prefix + tail)
                    self.assertEqual(p['on_failure'], ['independent_quarantine_and_client_guards',
                        'restore_compatible_release_and_stopped_state_or_leave_offline'])
                    self.assertEqual(p['status'], 'DRAFT_BLOCKED')
                    self.assertIs(p['release_ready'], False)
                    self.assertIs(p['native_authority'], False)
                    self.assertEqual(before, observed)
                    self.assertNotIn('/var/lib/vprouter/foreign-state', p['remove'])
                    self.assertTrue(set(p['remove']) <= ({f['path'] for f in current['files']} if current else set()))
                    if operation == 'rollback':
                        self.assertIn('retained_compatible_stopped_state_backup', p['required'])
                        self.assertIn('verified_stopped_state_restoration', p['required'])
                        self.assertEqual(p['exchange']['from_release'], 'candidate-2')
                        self.assertEqual(p['exchange']['to_release'], 'candidate-1')
                        self.assertFalse(any('/releases/candidate-2' in x for x in p['remove']))
                    if operation == 'reboot-recovery':
                        self.assertEqual(p['write'], [])
                        self.assertEqual(p['remove'], [])
                        self.assertIsNone(p['exchange'])


class ReviewDurability(unittest.TestCase):
    # A successful replay must repair namespace durability even when the last
    # failure removed .pending or installed bundle. Real fsync is kept below.
    def test_recover_retries_final_parent_sync_after_rmdir_or_fsync_failure(self):
        import errno
        import os
        import tempfile
        from unittest.mock import patch
        files = Artifacts.bundle(self)
        anchor = r.digest(files['SHA256SUMS'])
        for boundary in ('after_rmdir', 'final_fsync'):
            for reopen in (False, True):
                with self.subTest(boundary=boundary, reopen=reopen), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    FixturePublication.fixture(self, root)
                    store = r.FixtureStore(root)
                    try:
                        def stop(label):
                            if label == 'before_rename':
                                raise OSError(errno.EIO, 'pending')
                        with self.assertRaises(OSError):
                            store.publish(files, anchor, checkpoint=stop)
                        real_sync, real_rmdir = os.fsync, os.rmdir
                        def fail_sync(fd):
                            if fd == store.root:
                                raise OSError(errno.EIO, 'final parent fsync')
                            return real_sync(fd)
                        def fail_rmdir(*a, **kw):
                            real_rmdir(*a, **kw)
                            raise OSError(errno.EIO, 'interrupted after rmdir')
                        with patch.object(r.os, 'fsync', side_effect=fail_sync if boundary == 'final_fsync' else real_sync), \
                             patch.object(r.os, 'rmdir', side_effect=fail_rmdir if boundary == 'after_rmdir' else real_rmdir):
                            with self.assertRaises(OSError):
                                store.recover(files, anchor)
                        self.assertFalse((root / '.pending').exists())
                        if reopen:
                            store.close()
                            store = r.FixtureStore(root)
                        synced = []
                        def track(fd):
                            synced.append(os.fstat(fd).st_ino)
                            return real_sync(fd)
                        with patch.object(r.os, 'fsync', side_effect=track):
                            store.recover(files, anchor)
                        self.assertIn(root.stat().st_ino, synced, 'empty recovery skipped parent fsync')
                    finally:
                        store.close()

    def test_publish_replay_syncs_parent_after_failed_post_rename_fsync(self):
        import errno
        import os
        import tempfile
        from unittest.mock import patch
        files = Artifacts.bundle(self)
        anchor = r.digest(files['SHA256SUMS'])
        real_sync = os.fsync
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            FixturePublication.fixture(self, root)
            with r.FixtureStore(root) as store:
                def fail(fd):
                    if fd == store.root:
                        raise OSError(errno.EIO, 'parent fsync')
                    return real_sync(fd)
                with patch.object(r.os, 'fsync', side_effect=fail):
                    with self.assertRaises(OSError):
                        store.publish(files, anchor)
                synced = []
                def track(fd):
                    synced.append(os.fstat(fd).st_ino)
                    real_sync(fd)
                with patch.object(r.os, 'fsync', side_effect=track):
                    store.publish(files, anchor)
                self.assertIn(root.stat().st_ino, synced, 'existing publication skipped parent fsync')


class DurableSyscalls:
    """Test-only interposer: real calls, one injected error, real fsync receipts.

    Parent obligations survive the failing call and recovery. A receipt is an
    actual successful fsync of that directory inode after its last mutation.
    No production test hook is used to select syscall boundaries.
    """
    def __init__(self, boundary=None, failure=None):
        self.boundary, self.failure = boundary, failure
        self.calls, self.dirty, self.hit = [], set(), False
        self.opened = set()

    def __enter__(self):
        import contextlib
        from unittest.mock import patch
        self.stack = contextlib.ExitStack()
        for name in ('open', 'mkdir', 'write', 'fsync', 'fchmod', 'utime',
                     'rename', 'unlink', 'rmdir', 'close'):
            original = getattr(r.os, name)
            self.stack.enter_context(patch.object(r.os, name, self.wrap(name, original)))
        self.stack.enter_context(patch.object(r.fcntl, 'flock', self.wrap('flock', r.fcntl.flock)))
        return self

    def __exit__(self, *_):
        self.stack.close()

    def wrap(self, name, original):
        def call(*args, **kw):
            import errno
            import os
            # Read-only descriptor opens aren't namespace publications. Keep
            # every close to exercise cleanup after files and directory opens.
            relevant = name != 'open' or bool(args[1] & os.O_CREAT) or args[0] == '.release.lock'
            selected = False
            if relevant:
                index = len(self.calls)
                self.calls.append(name)
                selected = index == self.boundary and not self.hit
                if selected:
                    self.hit = True
                    if self.failure in (errno.EIO, errno.ENOSPC, errno.EINTR):
                        raise OSError(self.failure, 'injected before ' + name)
                    if self.failure == 'zero' and name == 'write':
                        return 0
                    if self.failure == 'short' and name == 'write':
                        args = (args[0], args[1][:max(1, len(args[1]) // 2)])
            result = original(*args, **kw)
            if name == 'open':
                self.opened.add(result)
            elif name == 'close':
                self.opened.discard(args[0])
            if name in ('mkdir', 'unlink', 'rmdir') or (name == 'open' and args[1] & os.O_CREAT):
                self.dirty.add(os.fstat(kw['dir_fd']).st_ino)
            elif name == 'rename':
                self.dirty.update(os.fstat(kw[k]).st_ino for k in ('src_dir_fd', 'dst_dir_fd'))
            elif name == 'fsync':
                self.dirty.discard(os.fstat(args[0]).st_ino)
            if selected and self.failure == 'after':
                raise OSError(errno.EIO, 'interrupted after ' + name)
            return result
        return call

    def process_exit(self):
        # Test-only process teardown model for interrupted constructor/close:
        # close leaked FDs just as kernel exit would; preserve every file byte.
        import os
        for fd in list(self.opened):
            try:
                os.close(fd)
            except OSError:
                pass
        self.opened.clear()


class ReviewSyscallSweep(unittest.TestCase):
    def test_every_durable_syscall_boundary_recovers_syncs_parents_and_replays(self):
        import errno
        import tempfile
        args = r.bundle_inputs(Artifacts.bundle(self))
        # Tiny public dependency inventory makes exhaustive fault replay cheap;
        # the real-size inventory is independently covered by Artifacts tests.
        args['lock'] = b'version = 4\n[[package]]\nname = "fixture"\nversion = "1"\n'
        files = r.build_bundle(**args)
        anchor = r.digest(files['SHA256SUMS'])
        coverage, cases = {}, 0

        def pending(store):
            def stop(label):
                if label == 'before_rename':
                    raise OSError('retain complete pending')
            with self.assertRaises(OSError):
                store.publish(files, anchor, checkpoint=stop)

        def snapshot(root):
            return {p.name: (p.read_bytes(), p.stat().st_mode, p.stat().st_mtime_ns)
                    for p in (root / 'bundle').iterdir()}

        for operation in ('publish', 'recover', 'publish-replay', 'recover-empty', 'recover-bundle'):
            def prepare(root):
                FixturePublication.fixture(self, root)
                if operation != 'publish':
                    with r.FixtureStore(root) as store:
                        if operation == 'recover':
                            pending(store)
                        elif operation != 'recover-empty':
                            store.publish(files, anchor)

            def perform(root, holder):
                store = r.FixtureStore(root)
                holder.append(store)
                if operation.startswith('publish'):
                    store.publish(files, anchor)
                else:
                    store.recover(files, anchor)
                store.close()

            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                prepare(root)
                with DurableSyscalls() as trace:
                    perform(root, [])
                boundaries = trace.calls
            coverage[operation] = len(boundaries)
            for index, syscall in enumerate(boundaries):
                failures = [errno.EIO, errno.ENOSPC, errno.EINTR, 'after']
                if syscall == 'write':
                    failures += ['zero', 'short']
                for failure in failures:
                    for reopen in (False, True):
                        cases += 1
                        with self.subTest(operation=operation, index=index, syscall=syscall,
                                          failure=failure, reopen=reopen), tempfile.TemporaryDirectory() as tmp:
                            root = Path(tmp)
                            prepare(root)
                            holders = []
                            with DurableSyscalls(index, failure) as trace:
                                try:
                                    perform(root, holders)
                                except (OSError, ValueError):
                                    self.assertNotEqual(failure, 'short')
                                else:
                                    self.assertEqual(failure, 'short', 'injected fault was swallowed')
                                self.assertTrue(trace.hit)
                                # Visible target is wholly absent/old or new,
                                # never a partial bundle, under every error.
                                if (root / 'bundle').exists():
                                    self.assertEqual({p.name: p.read_bytes() for p in (root / 'bundle').iterdir()}, files)
                                store = holders[0] if holders else None
                                if (reopen or store is None or store.lock is None or
                                        store.lock not in trace.opened or store.root not in trace.opened):
                                    if store is not None:
                                        try:
                                            store.close()
                                        except OSError:
                                            pass
                                    trace.process_exit()
                                    store = r.FixtureStore(root)
                                try:
                                    store.recover(files, anchor)
                                    self.assertFalse(trace.dirty, 'recovery left an unsynced mutated parent')
                                    store.publish(files, anchor)
                                    self.assertFalse(trace.dirty, 'publication left an unsynced mutated parent')
                                    first = snapshot(root)
                                    store.recover(files, anchor)
                                    store.publish(files, anchor)
                                    self.assertEqual(first, snapshot(root))
                                finally:
                                    store.close()
                                    trace.process_exit()
        print('Durable syscall boundaries:', coverage, 'fault/replay cases:', cases)


class ReviewELF(unittest.TestCase):
    @staticmethod
    def fixture(machine, sections=False):
        import struct
        data = bytearray(120 if not sections else 256)
        data[:7] = b'\x7fELF\x02\x01\x01'
        struct.pack_into('<HHIQQQIHHHHHH', data, 16, 2, machine, 1, 0, 64,
                         128 if sections else 0, 0, 64, 56, 1, 64 if sections else 0,
                         2 if sections else 0, 1 if sections else 0)
        struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, 0, 0, 0, 120, 120, 4096)
        if sections:
            # NULL section then a one-byte string table; tables never overlap.
            struct.pack_into('<IIQQQQIIQQ', data, 192, 0, 3, 0, 0, 120, 1, 0, 0, 1, 0)
        return bytes(data)

    @staticmethod
    def three_sections(machine, kind, size, entsize):
        # NULL, section-name STRTAB, one test section whose type/size/entsize vary.
        import struct
        data = bytearray(384)
        data[:7] = b'\x7fELF\x02\x01\x01'
        struct.pack_into('<HHIQQQIHHHHHH', data, 16, 2, machine, 1, 0, 64, 192, 0, 64, 56, 1, 64, 3, 1)
        struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, 0, 0, 0, 120, 120, 4096)
        data[128:135] = b'\0.note\0'
        struct.pack_into('<IIQQQQIIQQ', data, 256, 0, 3, 0, 0, 128, 7, 0, 0, 1, 0)
        struct.pack_into('<IIQQQQIIQQ', data, 320, 1, kind, 0, 0, 144, size, 0, 0, 1, entsize)
        return bytes(data)

    def test_relocation_section_headers_require_the_fixed_entry_size(self):
        # Review round 2 (M2): zero / wrong entsize on SHT_REL(A) was admitted.
        for machine in (62, 183):
            r.static_elf(self.three_sections(machine, 1, 16, 0), machine)  # control: PROGBITS
            r.static_elf(self.three_sections(machine, 4, 24, 24), machine)  # valid RELA
            r.static_elf(self.three_sections(machine, 9, 16, 16), machine)  # valid REL
            for kind, good in ((4, 24), (9, 16)):
                for entsize in (0, 1, 8, good - 1, good + 1, 2 * good):
                    with self.subTest(machine=machine, kind=kind, entsize=entsize), \
                            self.assertRaises(ValueError):
                        r.static_elf(self.three_sections(machine, kind, 2 * good, entsize), machine)
                with self.subTest(machine=machine, kind=kind, size='not-a-multiple'), \
                        self.assertRaises(ValueError):
                    r.static_elf(self.three_sections(machine, kind, good + 1, good), machine)

    def test_relocation_section_link_and_info_are_bounded(self):
        # Controller-fix review M1/M2: sh_link must be 0 or a symbol table, sh_info
        # must index a section even when SHF_INFO_LINK is clear (0 stays valid).
        import struct
        for machine in (62, 183):
            for kind, good in ((4, 24), (9, 16)):
                base = bytearray(self.three_sections(machine, kind, good, good))
                r.static_elf(bytes(base), machine)  # control: link 0, info 0
                for link in (1, 2, 3, 0xffffffff):  # NULL-adjacent STRTAB, itself, out of range
                    data = bytearray(base)
                    struct.pack_into('<I', data, 320 + 40, link)
                    with self.subTest(machine=machine, kind=kind, link=link), \
                            self.assertRaises(ValueError):
                        r.static_elf(bytes(data), machine)
                for info in (3, 4, 0xffffffff):
                    for flags in (0, 0x40):
                        data = bytearray(base)
                        struct.pack_into('<I', data, 320 + 44, info)
                        struct.pack_into('<Q', data, 320 + 8, flags)
                        with self.subTest(machine=machine, kind=kind, info=info, flags=flags), \
                                self.assertRaises(ValueError):
                            r.static_elf(bytes(data), machine)
                data = bytearray(base)
                struct.pack_into('<I', data, 320 + 44, 1)  # info -> existing section
                r.static_elf(bytes(data), machine)

    def test_generated_header_mutations_and_truncations_for_both_targets(self):
        import struct
        fields = [
            ('type', 16, 'H', [0, 1, 3, 0xffff]),
            ('machine', 18, 'H', [0, 3, 0xffff]),
            ('version', 20, 'I', [0, 2, 0xffffffff]),
            ('entry', 24, 'Q', [120, 0xffffffffffffffff]),
            ('phoff', 32, 'Q', [0, 1, 63, 65, 120, 0xffffffffffffffff]),
            ('shoff', 40, 'Q', [1, 64, 120, 0xffffffffffffffff]),
            ('flags', 48, 'I', [1, 0xffffffff]),
            ('ehsize', 52, 'H', [0, 1, 63, 65, 0xffff]),
            ('phentsize', 54, 'H', [0, 1, 55, 57, 0xffff]),
            ('phnum', 56, 'H', [0, 2, 257, 0xffff]),
            ('shentsize', 58, 'H', [1, 63, 65, 0xffff]),
            ('shnum', 60, 'H', [1, 2, 0xffff]),
            ('shstrndx', 62, 'H', [1, 2, 0xffff]),
            ('p_type', 64, 'I', [0, 2, 3]),
            ('p_flags', 68, 'I', [0, 8, 0xffffffff]),
            ('p_offset', 72, 'Q', [1, 120, 0xffffffffffffffff]),
            ('p_vaddr', 80, 'Q', [1, 0xffffffffffffffff]),
            ('p_paddr', 88, 'Q', [0xffffffffffffffff]),
            ('p_filesz', 96, 'Q', [121, 0xffffffffffffffff]),
            ('p_memsz', 104, 'Q', [0, 119]),
            ('p_align', 112, 'Q', [3, 0xffffffffffffffff])]
        for machine in (62, 183):
            valid = self.fixture(machine)
            r.static_elf(valid, machine)
            r.static_elf(self.fixture(machine, sections=True), machine)
            for byte in range(16):
                allowed = {valid[byte]} if byte != 7 else {0, 3}
                for value in range(256):
                    data = bytearray(valid)
                    data[byte] = value
                    with self.subTest(machine=machine, ident=byte, value=value):
                        if value in allowed:
                            r.static_elf(bytes(data), machine)
                        else:
                            with self.assertRaises(ValueError):
                                r.static_elf(bytes(data), machine)
            for name, offset, fmt, values in fields:
                for value in values:
                    data = bytearray(valid)
                    struct.pack_into('<' + fmt, data, offset, value)
                    with self.subTest(machine=machine, field=name, value=value), self.assertRaises(ValueError):
                        r.static_elf(bytes(data), machine)
            sectioned = self.fixture(machine, sections=True)
            for length in range(len(sectioned)):
                with self.subTest(machine=machine, length=length), self.assertRaises(ValueError):
                    r.static_elf(sectioned[:length], machine)
            for length in range(len(valid)):
                with self.subTest(machine=machine, minimal_length=length), self.assertRaises(ValueError):
                    r.static_elf(valid[:length], machine)
            # Permitted declarations are not rejected simply for being different.
            for offset, fmt, value in [(7, 'B', 3), (24, 'Q', 1), (88, 'Q', 123),
                                       (68, 'I', 1), (68, 'I', 7),
                                       (104, 'Q', 121), (104, 'Q', 0xffffffffffffffff),
                                       (112, 'Q', 0), (112, 'Q', 1)]:
                data = bytearray(valid)
                struct.pack_into('<' + fmt, data, offset, value)
                r.static_elf(bytes(data), machine)

    def test_section_headers_and_program_overlap_ranges(self):
        import struct
        for machine in (62, 183):
            valid = self.fixture(machine, sections=True)
            for offset, fmt, values in [
                (40, 'Q', [64, 119, 129, 0xffffffffffffffff]),
                (58, 'H', [0, 63, 65]), (60, 'H', [1, 3, 0xffff]),
                (62, 'H', [2, 0xffff]), (128, 'I', [1]),
                (192, 'I', [1, 0xffffffff]), (196, 'I', [0, 0xffffffff]),
                (200, 'Q', [0xffffffffffffffff]),
                (208, 'Q', [0xffffffffffffffff]),
                (216, 'Q', [256, 0xffffffffffffffff]),
                (224, 'Q', [257, 0xffffffffffffffff]),
                (232, 'I', [2, 0xffffffff]), (236, 'I', [0xffffffff]),
                (240, 'Q', [3, 0xffffffffffffffff]), (248, 'Q', [2, 0xffffffffffffffff])]:
                for value in values:
                    data = bytearray(valid)
                    struct.pack_into('<' + fmt, data, offset, value)
                    with self.subTest(machine=machine, offset=offset, value=value), self.assertRaises(ValueError):
                        r.static_elf(bytes(data), machine)
            # Two disjoint valid LOADs; a table covered by a LOAD is legal ELF.
            data = bytearray(240)
            data[:120] = self.fixture(machine)
            struct.pack_into('<H', data, 56, 2)
            struct.pack_into('<IIQQQQQQ', data, 120, 1, 4, 200, 200, 0, 40, 40, 1)
            r.static_elf(bytes(data), machine)
            for offset, value in ((128, 119), (136, 119), (152, 41), (136, 0xffffffffffffffff)):
                bad = bytearray(data)
                struct.pack_into('<Q', bad, offset, value)
                with self.subTest(machine=machine, overlap=offset), self.assertRaises(ValueError):
                    r.static_elf(bytes(bad), machine)
            for kind in (2, 3):
                bad = bytearray(data)
                struct.pack_into('<I', bad, 120, kind)
                with self.assertRaises(ValueError):
                    r.static_elf(bytes(bad), machine)

    def test_tls_sizes_phdr_binding_and_section_fixed_entry_sizes(self):
        import struct
        for machine in (62, 183):
            # TLS can overlap its containing LOAD; it must fit total TLS memory.
            tls = bytearray(240)
            tls[:120] = self.fixture(machine)
            struct.pack_into('<H', tls, 56, 2)
            struct.pack_into('<IIQQQQQQ', tls, 120, 7, 4, 200, 200, 0, 40, 40, 1)
            r.static_elf(bytes(tls), machine)
            bad = bytearray(tls)
            struct.pack_into('<Q', bad, 160, 39)
            with self.subTest(machine=machine, field='tls_size'), self.assertRaises(ValueError):
                r.static_elf(bytes(bad), machine)
            # PHDR itself describes the complete program table and precedes LOAD.
            phdr = bytearray(176)
            phdr[:64] = self.fixture(machine)[:64]
            struct.pack_into('<H', phdr, 56, 2)
            struct.pack_into('<IIQQQQQQ', phdr, 64, 6, 4, 64, 64, 0, 112, 112, 8)
            struct.pack_into('<IIQQQQQQ', phdr, 120, 1, 5, 0, 0, 0, 176, 176, 4096)
            r.static_elf(bytes(phdr), machine)
            for offset, value in ((72, 65), (80, 65), (96, 111), (104, 111)):
                bad = bytearray(phdr)
                struct.pack_into('<Q', bad, offset, value)
                with self.subTest(machine=machine, phdr=offset), self.assertRaises(ValueError):
                    r.static_elf(bytes(bad), machine)
            # An allocated, fixed-width init array is valid only with 8-byte entries.
            section = bytearray(self.fixture(machine, sections=True))
            struct.pack_into('<H', section, 62, 0)  # no section-name string table
            struct.pack_into('<IIQQQQIIQQ', section, 192, 0, 14, 0, 0, 120, 8, 0, 0, 8, 8)
            r.static_elf(bytes(section), machine)
            for entsize in (0, 1, 4, 16):
                bad = bytearray(section)
                struct.pack_into('<Q', bad, 248, entsize)
                with self.subTest(machine=machine, array_entsize=entsize), self.assertRaises(ValueError):
                    r.static_elf(bytes(bad), machine)

    def test_malformed_size_fields_refuse_newly_anchored_packaging(self):
        import struct
        args = r.bundle_inputs(Artifacts.bundle(self))
        for target in r.TARGETS:
            name = target + '--vprouter'
            for offset, fmt, value in ((52, 'H', 0), (104, 'Q', 0)):
                bad = dict(args, binaries=dict(args['binaries']))
                data = bytearray(bad['binaries'][name])
                struct.pack_into('<' + fmt, data, offset, value)
                bad['binaries'][name] = bytes(data)
                with self.subTest(target=target, offset=offset), self.assertRaises(ValueError):
                    r.build_bundle(**bad)

    def test_generated_reserved_flag_bits_and_valid_os_processor_bits(self):
        import struct
        # ELF64 gABI SHF_MASKOS=0x0ff00000, SHF_MASKPROC=0xf0000000;
        # standard flags occupy bits0..11 except reserved bit3.
        for machine in (62, 183):
            valid = self.fixture(machine, sections=True)
            for bit in range(64):
                data = bytearray(valid)
                struct.pack_into('<Q', data, 200, 1 << bit)
                with self.subTest(machine=machine, section_flag_bit=bit):
                    if bit in (3, *range(12, 20), *range(32, 64)):
                        with self.assertRaises(ValueError):
                            r.static_elf(bytes(data), machine)
                    else:
                        try:
                            r.static_elf(bytes(data), machine)
                        except ValueError as exc:
                            self.fail('permitted section flag refused: ' + str(exc))
            for offset, fmt in ((48, 'I'), (68, 'I')):
                for bit in range(32):
                    if offset == 68 and bit < 3:
                        continue
                    data = bytearray(self.fixture(machine))
                    struct.pack_into('<' + fmt, data, offset, (5 if offset == 68 else 0) | (1 << bit))
                    with self.subTest(machine=machine, offset=offset, flag_bit=bit), self.assertRaises(ValueError):
                        r.static_elf(bytes(data), machine)


if __name__ == '__main__':
    unittest.main()
