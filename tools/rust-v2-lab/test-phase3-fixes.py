#!/usr/bin/env python3
"""Offline review regressions. Every possible guest subprocess is intercepted."""
import ast
import contextlib
import copy
import importlib.util
import io
import json
import os
import pathlib
import runpy
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

if not __debug__:
    raise RuntimeError('optimized_python_refused')

ROOT = pathlib.Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


fixtures = module('phase3_fixtures', 'tools/rust-v2-lab/test-phase3b-provenance.py')


class BlockedSSH(Exception):
    pass


class FreshRoutes(unittest.TestCase):
    def test_routes(self):
        variants = ('valid', 'tampered', 'deleted', 'mixed', 'historical',
                    'fresh_route', 'false_history', 'false_reconstruction', 'fresh_record', 'historical_no_review')
        for tool in ('inspect-secret-bootstrap-failure.py', 'archive-secret-bootstrap-selectors.py'):
            for variant in variants:
                with self.subTest(tool=tool, variant=variant):
                    case = fixtures.Declarations('test_fresh'); case.setUp()
                    try:
                        nonce = 'a'*64; unit = 'vprouter-v2-owner@'+nonce+'.service'
                        stdout = '\n'.join(json.dumps({key: value}) for key, value in (
                            ('secret_attachment_input', dict(nonce=nonce, configuration_sha256='c'*64, profiles=[])),
                            ('secret_quarantine_host', dict(sha256='d'*64, declaration={})),
                            ('owner_probe', dict(unit=unit)),
                            ('secret_attachment_gateway', dict(container_id='b'*64, pid=42, start=10,
                                started_at='synthetic', source_namespace=[4,56], host_network_namespace=[4,55]))))
                        directory = case.prepare_record(1, stdout)
                        run = 409
                        if variant == 'tampered': case.record['run_reservation']['sha256'] = '0'*64
                        if variant == 'deleted': case.record.pop('run_reservation')
                        if variant == 'mixed':
                            review = copy.deepcopy(case.review); review['route'] = 'historical'
                            case.write(directory/'controller-baseline-reconciliation.json', review)
                        if variant in ('historical', 'fresh_route', 'false_history', 'false_reconstruction', 'fresh_record', 'historical_no_review'):
                            run = 408; case.record.pop('run_reservation')
                            review = copy.deepcopy(case.review)
                            review.pop('route'); review.pop('historical_continuity')
                            review['prior_structure_reconstructed'] = True
                            review['ordering_only_aligned_after_exact_multiset_comparison'] = True
                            if variant == 'fresh_route': review['route'] = 'fresh-lab'
                            if variant == 'false_history': review['historical_continuity'] = False
                            if variant == 'false_reconstruction': review['prior_structure_reconstructed'] = False
                            if variant == 'fresh_record': case.record['continuity'] = 'fresh-lab'
                            case.write(directory/'controller-baseline-reconciliation.json', review)
                            if variant == 'historical_no_review': (directory/'controller-baseline-reconciliation.json').unlink()
                        raw_path = pathlib.Path(f'target/lab-state/actual-program-run-{run}.json')
                        case.write(raw_path, case.record)
                        binding = directory/'directory-binding.json'
                        case.write(binding, dict(record=str(raw_path), source_commit=case.c['binding']['source_commit'],
                            platform=case.m.PLATFORM, source_archive_sha256=case.record['source_archive_sha256'],
                            artifact_sha256=case.record['artifact_sha256']))
                        reference = dict(record_sha256=case.m.sha(raw_path), source_binding=case.record['source_binding'],
                            platform=case.m.PLATFORM, owner_unit=dict(LoadState='not-found'), owner_cgroup_exists=False,
                            nonce=nonce, expected_owner_unit=unit, fixed_selectors={})
                        case.write(f'target/lab-state/secret-bootstrap-failure-run-{run}.json', reference)
                        def intercept(argv, **kwargs):
                            self.assertEqual(argv[0], 'ssh')
                            compile(kwargs['input'], tool+'-actual-remote', 'exec')
                            self.assertEqual("/proc/sys/kernel/random/boot_id" in kwargs['input'], variant == 'valid')
                            raise BlockedSSH()
                        with patch.object(sys, 'argv', [tool, str(run), str(binding)]), \
                             patch.object(subprocess, 'run', side_effect=intercept) as remote:
                            if variant in ('valid', 'historical', 'historical_no_review'):
                                with self.assertRaises(BlockedSSH): runpy.run_path(str(ROOT/'target'/tool), run_name='__main__')
                                self.assertEqual(remote.call_count, 1)
                            else:
                                with self.assertRaises((AssertionError, KeyError)):
                                    runpy.run_path(str(ROOT/'target'/tool), run_name='__main__')
                                self.assertEqual(remote.call_count, 0)
                    finally: case.doCleanups()


class InspectorErrors(unittest.TestCase):
    def test_transport_receipts(self):
        for error in (subprocess.TimeoutExpired(['synthetic-ssh'], 30, output=b'partial snapshot\xff', stderr=b'partial error'),
                      OSError('synthetic spawn error')):
            with self.subTest(error=type(error).__name__):
                case = fixtures.Declarations('test_fresh'); case.setUp()
                try:
                    inspector = module('timeout_inspector', 'tools/rust-v2-lab/inspect-run409-state.py')
                    destination = pathlib.Path('inspection.json')
                    with patch.object(sys, 'argv', ['inspector', str(destination)]), \
                         patch.object(subprocess, 'run', side_effect=error) as remote, \
                         contextlib.redirect_stdout(io.StringIO()):
                        self.assertNotEqual(inspector.main(), 0)
                        self.assertEqual(remote.call_count, 1)
                        compile(remote.call_args.kwargs['input'], 'inspector-actual-remote', 'exec')
                    receipt = json.loads(destination.read_bytes())
                    self.assertEqual(receipt['error_type'], type(error).__name__)
                    self.assertEqual(receipt['error_classification'], 'transport_timeout' if isinstance(error, subprocess.TimeoutExpired) else 'transport_start_error')
                    self.assertFalse(receipt['archival_authorized'])
                    self.assertFalse(receipt['runtime_acceptance'])
                    self.assertEqual(receipt['stdout'], 'partial snapshot\ufffd' if isinstance(error, subprocess.TimeoutExpired) else '')
                    self.assertEqual(receipt['stderr'], 'partial error' if isinstance(error, subprocess.TimeoutExpired) else '')
                    self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
                    with self.assertRaises(FileExistsError): case.m.save(destination, {})
                finally: case.doCleanups()


class ReservationChain(unittest.TestCase):
    def setup_chain(self, directory):
        m = module('chain_reservation', 'tools/rust-v2-lab/run409-reservation.py')
        for key, name in (('RESERVATION','reservation.json'), ('SUPERSESSION','supersession.json'),
                          ('CLAIM','claim.json'), ('RUN','run.json'), ('CANDIDATE','candidate.json')):
            setattr(m, key, pathlib.Path(directory)/name)
        m.save(m.RESERVATION, dict(schema=1, run=409, one_shot_budget=1))
        original = m.sha(m.RESERVATION)
        m.supersede(original, 'first offline generation', dict(schema=2, run=409, one_shot_budget=1, supersedes_sha256=original))
        return m

    def test_append_preserves_all_generations_and_single_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            m = self.setup_chain(tmp)
            prior = {p: p.read_bytes() for p in pathlib.Path(tmp).glob('*')}
            old = m.sha(m.RESERVATION)
            m.supersede(old, 'second offline generation', dict(schema=2, run=409, one_shot_budget=1, supersedes_sha256=old))
            latest = m.RESERVATION.read_bytes()
            chain = m.supersession_chain()
            self.assertEqual(len(chain), 2)
            self.assertEqual(m.active()['supersedes_sha256'], old)
            self.assertFalse(m.CLAIM.exists())
            for path, raw in prior.items():
                self.assertEqual((path if path != m.RESERVATION else pathlib.Path(chain[-1][1]['retained_path'])).read_bytes(), raw)
            for _, receipt in chain:
                m.RESERVATION.unlink(); m.save(m.RESERVATION, json.loads(pathlib.Path(receipt['retained_path']).read_bytes()))
                with self.assertRaises(AssertionError): m.active()
            m.RESERVATION.unlink(); m.save(m.RESERVATION, json.loads(latest))
            m.save(m.CLAIM, dict(budget_remaining=0))
            with self.assertRaises(AssertionError):
                m.supersede(m.sha(m.RESERVATION), 'spent refuses', dict(schema=2, run=409, one_shot_budget=1, supersedes_sha256=m.sha(m.RESERVATION)))
            self.assertEqual(len(m.supersession_chain()), 2)

    def test_append_interruptions_fail_closed(self):
        for boundary in ('tombstone', 'link', 'unlink', 'replacement'):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as tmp:
                m = self.setup_chain(tmp); old = m.sha(m.RESERVATION)
                anchor = m.SUPERSESSION.read_bytes()
                original_save, original_link, original_sync = m.save, os.link, m.sync_directory
                def save(path, data):
                    if boundary == 'replacement' and path == m.RESERVATION: raise OSError('synthetic interrupted replacement')
                    original_save(path, data)
                    if boundary == 'tombstone' and path != m.RESERVATION: raise OSError('synthetic interrupted tombstone')
                def link(*args, **kwargs):
                    original_link(*args, **kwargs)
                    if boundary == 'link': raise OSError('synthetic interrupted link')
                def sync(path):
                    original_sync(path)
                    if boundary == 'unlink' and not m.RESERVATION.exists(): raise OSError('synthetic interrupted unlink')
                with patch.object(m, 'save', side_effect=save), patch.object(os, 'link', side_effect=link), patch.object(m, 'sync_directory', side_effect=sync):
                    with self.assertRaises(OSError):
                        m.supersede(old, 'offline interruption', dict(schema=2, run=409, one_shot_budget=1, supersedes_sha256=old))
                self.assertEqual(m.SUPERSESSION.read_bytes(), anchor)
                self.assertTrue(m.next_supersession(old).exists())
                self.assertFalse(m.CLAIM.exists())
                with self.assertRaises((AssertionError, FileNotFoundError)): m.active()

    def test_collector_preserves_complete_chain(self):
        case = fixtures.Declarations('test_fresh'); case.setUp()
        try:
            case.m.CLAIM.unlink()
            for number in range(2):
                old = case.m.sha(case.m.RESERVATION)
                new = copy.deepcopy(case.r); new['supersedes_sha256'] = old
                case.m.supersede(old, 'offline chain '+str(number), new)
                case.r = new
            case.claim()
            collector = module('chain_collector', 'tools/rust-v2-lab/collect-run409-evidence.py')
            with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(collector.collect('chain-bundle'), 0)
            receipt = json.loads(pathlib.Path('chain-bundle/receipt.json').read_bytes())
            retained = {row['path'] for row in receipt['retained']}
            for path, tombstone in case.m.supersession_chain():
                for name in (str(path), tombstone['retained_path']):
                    self.assertIn(name, retained)
                    self.assertEqual(pathlib.Path('chain-bundle/files', name).read_bytes(), pathlib.Path(name).read_bytes())
        finally: case.doCleanups()


class RemotePrograms(unittest.TestCase):
    def controller(self):
        path = ROOT/'target/platform-lab/run-frozen-secret-bootstrap.py'
        tree = ast.parse(path.read_bytes())
        definitions = [n for n in tree.body if isinstance(n, ast.FunctionDef)]
        names = {}
        exec(compile(ast.Module(body=definitions, type_ignores=[]), str(path), 'exec'), names)
        return tree, names

    def programs(self, names, boot):
        guest = (ROOT/'target/platform-lab/secret-bootstrap.guest.py').read_text().replace('CONFIGURATION', repr(dict(
            host_declaration_builder=(ROOT/'target/platform-lab/quarantine_host_declaration.py').read_text(),
            host_baseline_builder=(ROOT/'target/platform-lab/host_baseline_declaration.py').read_text())))
        return names['compile_remote_programs'](guest,
            (ROOT/'target/platform-lab/quarantine_host_declaration.py').read_text(),
            (ROOT/'target/platform-lab/host_baseline_declaration.py').read_text(), boot)

    def test_actual_generated_programs_and_head_listing(self):
        _, names = self.controller()
        head = ast.parse(subprocess.check_output(['git', 'show', 'HEAD:tools/rust-v2-lab/target/platform-lab/run-frozen-secret-bootstrap.py'], cwd=ROOT))
        original = next(n.value.value for n in ast.walk(head) if isinstance(n, ast.Assign)
                        and any(isinstance(t, ast.Name) and t.id == 'listing' for t in n.targets))
        historical = self.programs(names, None)
        fresh = self.programs(names, 'synthetic-boot')
        self.assertEqual(historical['listing'], original)
        prefix = "import pathlib;assert pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()=='synthetic-boot'\n"
        self.assertEqual(fresh['listing'], prefix+original)
        self.assertEqual(fresh['guest'], prefix+historical['guest'])
        for route, programs in (('historical', historical), ('fresh', fresh)):
            for name, program in programs.items(): compile(program, route+'-'+name, 'exec')

    def test_compile_failure_precedes_claim_including_preflight(self):
        import builtins
        for preflight in (False, True):
            for payload in ('listing', 'guest', 'host-declaration', 'baseline-declaration'):
                with self.subTest(preflight=preflight, payload=payload):
                    tree, names = self.controller()
                    block = next(n for n in tree.body if isinstance(n, ast.If) and ast.unparse(n.test) == 'len(sys.argv) > 5')
                    case = fixtures.Declarations('test_fresh'); case.setUp()
                    try:
                        case.m.CLAIM.unlink()
                        reservation = case.m
                        fresh = types.SimpleNamespace(validate_fresh_provenance=lambda *a: case.r)
                        real_spec = importlib.util.spec_from_file_location
                        real_module = importlib.util.module_from_spec
                        stubs = {'run409_reservation': reservation, 'fresh_provenance': fresh}
                        def spec(name, path):
                            if name in stubs: return types.SimpleNamespace(name=name, loader=types.SimpleNamespace(exec_module=lambda m: None))
                            return real_spec(name, path)
                        def load(spec): return stubs[spec.name] if spec.name in stubs else real_module(spec)
                        names.update(sys=sys, pathlib=pathlib, json=json, candidate_path=case.cp, platform=case.m.PLATFORM,
                            label=case.m.LABEL, mode='success', template=case.template, review_bytes=case.rp.read_bytes(),
                            candidate=case.c, guest='print("synthetic")\n', host_builder='pass\n', baseline_builder='pass\n')
                        code = compile(ast.Module(body=[block], type_ignores=[]), 'admission-block', 'exec')
                        real_compile = builtins.compile
                        def reject(source, filename, *args, **kwargs):
                            if filename == 'bootstrap-remote-'+payload: raise SyntaxError('synthetic payload error')
                            return real_compile(source, filename, *args, **kwargs)
                        argv = ['controller', str(case.cp), case.m.PLATFORM, case.m.LABEL, 'success', '--reservation', str(case.m.RESERVATION)]
                        if preflight: argv.append('--preflight-only')
                        with patch.object(sys, 'argv', argv), patch.object(importlib.util, 'spec_from_file_location', side_effect=spec), \
                             patch.object(importlib.util, 'module_from_spec', side_effect=load), \
                             patch.object(builtins, 'compile', side_effect=reject), \
                             patch.object(subprocess, 'run', side_effect=AssertionError('no subprocess permitted')):
                            with self.assertRaises(SyntaxError): exec(code, names)
                        self.assertFalse(case.m.CLAIM.exists())
                    finally: case.doCleanups()

    def test_other_remote_templates(self):
        for tool in ('fresh-baseline.py', 'phase3-readonly-preflight.py', 'inspect-run409-state.py'):
            helper = module('compile_'+tool, 'tools/rust-v2-lab/'+tool)
            script = helper.REMOTE.replace('EXPECTED_BOOT', repr('synthetic')).replace('UNIT', 'None').replace('GATEWAY', 'None')
            compile(script, tool+'-actual-remote', 'exec')
        for tool in ('run-native-inspection-preflight.py', 'run-frozen-host-projection.py'):
            tree = ast.parse((ROOT/'target/platform-lab'/tool).read_bytes())
            script = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
                          and any(isinstance(t, ast.Name) and t.id == 'remote' for t in n.targets))
            compile(script, tool+'-actual-remote', 'exec')
        collector = ast.parse((ROOT/'tools/rust-v2-lab/collect-run409-evidence.py').read_bytes())
        self.assertFalse(any(isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == 'subprocess' for n in ast.walk(collector)))


if __name__ == '__main__': unittest.main(verbosity=2)
