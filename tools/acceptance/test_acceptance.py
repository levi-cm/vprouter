"""Offline contract tests; no network, subprocess, capture or host execution."""
import unittest
import acceptance as a


class BehavioralRed(unittest.TestCase):
    def test_duplicate_keys_cannot_be_silently_overwritten(self):
        with self.assertRaises(ValueError):
            a.strict_load(b'{"status":"FAIL","status":"PASS"}')

    def test_missing_bundle_cannot_pass_oracle(self):
        self.assertNotEqual(a.assess_bundle({}, {})['oracle_status'], 'PASS')

    def test_unbound_pass_is_unverified(self):
        self.assertEqual(a.resolve_status('PASS', None, {})['status'], 'UNVERIFIED')

    def test_unknown_or_skip_is_unverified(self):
        for value in ('SKIP', 'UNKNOWN', None, True):
            self.assertEqual(a.resolve_status(value, None, {})['status'], 'UNVERIFIED')

    def test_host_as_mullvad_egress_immediately_fails(self):
        hostile = {'captures': [{'host_ip_as_mullvad_app_egress': 1}]}
        self.assertEqual(a.assess_bundle(hostile, {})['oracle_status'], 'FAIL')



# Each group names a wrong verdict or unsafe side effect that mutations must catch.
import copy
import hashlib
import json
import os
from pathlib import Path
import random
import tempfile
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
LEDGER = ROOT / 'docs/rust-v2/acceptance.json'


def fixture(configuration='one_mullvad', scenario='routing.endpoint_route'):
    return a.synthetic_fixture(LEDGER.read_bytes(), configuration, scenario)


def leaves(value, path=()):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from leaves(child, path + (key,))
    elif isinstance(value, list):
        for key, child in enumerate(value):
            yield from leaves(child, path + (key,))
    else:
        yield path, value


def mutate(value, path, replacement, remove=False):
    result = copy.deepcopy(value)
    parent = result
    for key in path[:-1]:
        parent = parent[key]
    if remove:
        del parent[path[-1]]
    else:
        parent[path[-1]] = replacement
    return result


def reseal(bundle):
    """Producer-side rehash to test semantic oracles, not merely hash mismatches."""
    body = {key: value for key, value in bundle.items() if key != 'manifest'}
    bundle['manifest'] = {
        'algorithm': 'sha256',
        'context_sha256': a.digest(bundle['context']),
        'execution_sha256': a.digest(bundle['execution']),
        'captures_sha256': a.digest(bundle['captures']),
        'payload_sha256': a.digest(body),
    }
    return bundle


def assess_changed(bundle, expected):
    reseal(bundle)
    expected = dict(expected, bundle_sha256=a.digest(bundle))
    return a.assess_bundle(bundle, expected)


class Contracts(unittest.TestCase):
    def test_strict_json_rejects_ambiguous_and_unbounded_numbers(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":{"a":1,"a":2}}', b'NaN',
                    b'Infinity', b'-Infinity', b'1.0', b'1e0', b'1e999999',
                    b'1e-999999', b'9223372036854775808', b'-1', b'1'*20000,
                    b'\xef\xbb\xbf{}', '{}'.encode('utf-16'), b'"\xff"',
                    b'"\\ud800"', b'"\\u00e9"', b'"\\u0000"', b'{} {}',
                    b'['*34+b'0'+b']'*34, b' '*1048577):
            with self.subTest(raw=raw[:24]):
                with self.assertRaises(ValueError):
                    a.strict_load(raw)
        self.assertEqual(a.strict_load(b'{"a":9223372036854775807}'),
                         {'a': 9223372036854775807})

    def test_ledger_is_exact_and_never_trusts_recorded_pass(self):
        source = LEDGER.read_bytes()
        ledger = a.load_ledger(source)
        result = a.build_ledger(source)
        self.assertFalse(result['release_ready'])
        self.assertEqual(len(result['rows']), 1535)
        self.assertEqual(result['counts'], {'NOT_RUN': 1535, 'PASS': 0,
                                           'FAIL': 0, 'UNVERIFIED': 0})
        self.assertEqual(len({(r['configuration'], r['scenario'])
                              for r in result['rows']}), 1535)
        for operation in ('unknown', 'missing', 'alias', 'duplicate', 'scope', 'ready'):
            bad = copy.deepcopy(ledger)
            if operation == 'unknown':
                bad['configurations'][0]['scenarios']['routing']['extra'] = 'NOT_RUN'
            elif operation == 'missing':
                del bad['configurations'][1]['scenarios']['migration']['backup']
            elif operation == 'alias':
                bad['configurations'][0]['mullvad_exits'] = True
            elif operation == 'duplicate':
                bad['configurations'][1] = copy.deepcopy(bad['configurations'][0])
            elif operation == 'scope':
                bad['test_execution_scope']['remote_installation_validation'] = 'PASS'
            else:
                bad['release_ready'] = True
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                a.load_ledger(a.canonical(bad))
        ledger['configurations'][0]['scenarios']['routing']['endpoint_route'] = 'PASS'
        changed = a.build_ledger(a.canonical(ledger))
        row = next(r for r in changed['rows'] if r['configuration'] == 'one_mullvad'
                   and r['scenario'] == 'routing.endpoint_route')
        self.assertEqual(row['status'], 'UNVERIFIED')

    def test_complete_fixture_passes_only_synthetic_oracle(self):
        for configuration in ('one_mullvad', 'five_mullvad', 'one_direct',
                              'five_mullvad_one_direct'):
            f = fixture(configuration)
            verdict = a.assess_bundle(f['bundle'], f['expected'])
            self.assertEqual(verdict['oracle_status'], 'PASS')
            self.assertEqual(verdict['acceptance_status'], 'UNVERIFIED')
            row = a.resolve_status('PASS', f['bundle'], f['expected'])
            self.assertEqual(row['status'], 'UNVERIFIED')
            self.assertEqual(row['oracle_status'], 'PASS')

    def test_closed_evidence_schema_rejects_unknown_fields_and_type_aliases(self):
        f = fixture()
        for path in ((), ('context',), ('execution',), ('captures', 0),
                     ('captures', 0, 'records', 0), ('manifest',)):
            bad = copy.deepcopy(f['bundle'])
            target = bad
            for key in path:
                target = target[key]
            target['unknown'] = 'syn-test'
            if path == ('manifest',):
                expected = dict(f['expected'], bundle_sha256=a.digest(bad))
                verdict = a.assess_bundle(bad, expected)
            else:
                verdict = assess_changed(bad, f['expected'])
            self.assertNotEqual(verdict['oracle_status'], 'PASS')
        for replacement in (True, False, 0.0, '1', None, 2**63):
            bad = mutate(f['bundle'], ('schema_version',), replacement)
            self.assertNotEqual(a.assess_bundle(bad, f['expected'])['oracle_status'], 'PASS')

    def test_positive_controls_and_every_point_exit_protocol_are_required(self):
        f = fixture('five_mullvad_one_direct')
        bad = copy.deepcopy(f['bundle'])
        del bad['captures'][-1]
        self.assertNotEqual(assess_changed(bad, f['expected'])['oracle_status'], 'PASS')
        bad = copy.deepcopy(f['bundle'])
        bad['captures'][-1] = copy.deepcopy(bad['captures'][0])
        self.assertNotEqual(assess_changed(bad, f['expected'])['oracle_status'], 'PASS')
        for field, value in (('positive_control_packets', 0), ('kernel_drops', 1),
                             ('packets', 0), ('source_sha256', '0'*64)):
            bad = copy.deepcopy(f['bundle'])
            bad['captures'][0][field] = value
            self.assertNotEqual(assess_changed(bad, f['expected'])['oracle_status'], 'PASS')
        for i in range(15):
            bad = copy.deepcopy(f['bundle'])
            del bad['captures'][0]['records'][i]
            # Even a dishonest producer's internally consistent counts cannot
            # turn absent pre/post controls or traffic into a complete capture.
            c = bad['captures'][0]
            c['source_sha256'] = a.digest(c['records'])
            c['packets'] = len(c['records'])
            c['positive_control_packets'] = sum(r['marker'] == 'control' for r in c['records'])
            self.assertNotEqual(assess_changed(bad, f['expected'])['oracle_status'], 'PASS')

    def test_forbidden_marker_or_host_egress_is_fail_even_with_broken_bundle(self):
        for field in ('forbidden_plaintext_markers', 'cross_exit_markers',
                      'host_ip_as_mullvad_app_egress'):
            self.assertEqual(a.assess_bundle({'captures': [{field: 1}]}, {})['oracle_status'], 'FAIL')
        f = fixture()
        for marker in ('forbidden_plaintext', 'cross_exit', 'host_as_mullvad'):
            bad = copy.deepcopy(f['bundle'])
            bad['captures'][0]['records'][0]['marker'] = marker
            self.assertEqual(assess_changed(bad, f['expected'])['oracle_status'], 'FAIL')

    def test_capture_windows_require_one_monotonic_epoch_and_strict_start_order(self):
        f = fixture()
        for path, value in ((('captures', 0, 'ready_ns'), 30),
                            (('captures', 0, 'start_ns'), 31),
                            (('captures', 0, 'stop_ns'), 69),
                            (('captures', 0, 'epoch'), 'syn-other'),
                            (('execution', 'traffic_end_ns'), 29),
                            (('execution', 'traffic_start_ns'), True),
                            (('captures', 0, 'records', 0, 'time_ns'), 99)):
            bad = mutate(f['bundle'], path, value)
            self.assertNotEqual(assess_changed(bad, f['expected'])['oracle_status'], 'PASS')
        # Large integer clocks with a one-nanosecond boundary remain exact.
        bad = copy.deepcopy(f['bundle'])
        shift = 2**62
        for key in ('traffic_start_ns', 'traffic_end_ns'):
            bad['execution'][key] += shift
        for c in bad['captures']:
            for key in ('start_ns', 'ready_ns', 'stop_ns'):
                c[key] += shift
            for r in c['records']:
                r['time_ns'] += shift
            c['source_sha256'] = a.digest(c['records'])
        # Explicit external admission for the shifted synthetic clock epoch.
        admitted = copy.deepcopy(f['expected'])
        admitted['expected_run']['not_before_ns'] += shift
        admitted['expected_run']['not_after_ns'] += shift
        self.assertEqual(assess_changed(bad, admitted)['oracle_status'], 'PASS')
        bad['captures'][0]['ready_ns'] = bad['execution']['traffic_start_ns']
        self.assertNotEqual(assess_changed(bad, f['expected'])['oracle_status'], 'PASS')

    def test_context_and_manifest_cannot_be_rebound_or_reused_for_another_scenario(self):
        f = fixture()
        for key in f['expected']:
            wrong = dict(f['expected'])
            wrong[key] = '0'*64 if key.endswith('sha256') else 'clients.exit_disappears'
            self.assertNotEqual(a.assess_bundle(f['bundle'], wrong)['oracle_status'], 'PASS')
        for field in f['bundle']['manifest']:
            bad = copy.deepcopy(f['bundle'])
            bad['manifest'][field] = '0'*64
            expected = dict(f['expected'], bundle_sha256=a.digest(bad))
            self.assertNotEqual(a.assess_bundle(bad, expected)['oracle_status'], 'PASS')

    def test_each_leaf_missing_unknown_or_mutated_cannot_pass(self):
        f = fixture()
        count = 0
        for path, value in leaves(f['bundle']):
            replacement = value + 1 if type(value) is int else 'unknown'
            for bad in (mutate(f['bundle'], path, replacement),
                        mutate(f['bundle'], path, None),
                        mutate(f['bundle'], path, None, remove=True)):
                self.assertNotEqual(a.assess_bundle(bad, f['expected'])['oracle_status'], 'PASS', path)
                count += 1
        self.assertGreater(count, 700)

    def test_redaction_fuzz_never_echoes_secrets_identity_addresses_or_paths(self):
        f = fixture()
        corpus = ['tskey-auth-SECRET', '-----BEGIN PRIVATE KEY-----',
                  '192.0.2.4', '8.8.8.8', '2001:db8::1', '::1',
                  '/home/somebody/private', 'user@example.test', 'node-secret-id',
                  'A'*44, '\x00', '\ud800', 'token=secret', '100.64.0.1']
        rng = random.Random(15)
        corpus += ['tskey-'+''.join(rng.choices('abcdef0123456789', k=40)) for _ in range(80)]
        for secret in corpus:
            bad = copy.deepcopy(f['bundle'])
            bad['context']['run_id'] = secret
            verdict = a.assess_bundle(bad, f['expected'])
            self.assertNotEqual(verdict['oracle_status'], 'PASS')
            out = a.canonical(verdict)
            self.assertNotIn(secret.encode('ascii', 'backslashreplace'), out)
        with self.assertRaises(ValueError):
            a.report_bytes({'message': 'tskey-auth-SECRET'})

    def test_fail_is_preserved_and_bad_observations_cannot_upgrade_the_ledger(self):
        f = fixture()
        self.assertEqual(a.resolve_status('FAIL', f['bundle'], f['expected'])['status'], 'FAIL')
        source = LEDGER.read_bytes()
        observations = {'schema_version': 1, 'candidate_sha256': 'a'*64,
                        'observations': [{'configuration': 'one_mullvad',
                            'scenario': 'routing.endpoint_route', 'requested_status': 'PASS',
                            'bundle': f['bundle'], 'bundle_sha256': a.digest(f['bundle']),
                            'expected_run': f['expected']['expected_run']}]}
        result = a.build_ledger(source, observations)
        self.assertEqual(result['counts']['PASS'], 0)
        self.assertEqual(result['counts']['UNVERIFIED'], 1)
        observations['observations'].append(copy.deepcopy(observations['observations'][0]))
        with self.assertRaises(ValueError):
            a.build_ledger(source, observations)

    def test_plan_never_runs_and_all_prerequisites_are_required(self):
        plan = a.plan_spec()
        declarations = a.empty_declarations()
        result = a.preflight(plan, declarations)
        self.assertEqual(result['status'], 'NOT_RUN')
        self.assertEqual(result['preflight'], 'BLOCKED')
        self.assertGreaterEqual(len(result['missing']), 12)
        for entry in declarations['prerequisites'].values():
            entry['status'] = 'PASS'
            entry['evidence_sha256'] = 'a'*64
        complete = a.preflight(plan, declarations)
        self.assertEqual(complete['preflight'], 'DECLARED_ONLY')
        self.assertEqual(complete['status'], 'NOT_RUN')
        self.assertFalse(complete['execution_supported'])
        for key in declarations['prerequisites']:
            bad = copy.deepcopy(declarations)
            bad['prerequisites'][key]['status'] = 'SKIP'
            self.assertIn(key, a.preflight(plan, bad)['missing'])
        badplan = copy.deepcopy(plan)
        badplan['execution_scope'] = 'remote'
        with self.assertRaises(ValueError):
            a.preflight(badplan, declarations)

    def test_reports_are_deterministic_and_have_no_host_metadata(self):
        raw = LEDGER.read_bytes()
        first = a.report_bytes(a.build_ledger(raw))
        self.assertEqual(first, a.report_bytes(a.build_ledger(raw)))
        reversed_input = dict(reversed(list(a.load_ledger(raw).items())))
        reordered = a.build_ledger(a.canonical(reversed_input))
        self.assertEqual(a.build_ledger(raw)['rows'], reordered['rows'])
        self.assertEqual(a.build_ledger(raw)['counts'], reordered['counts'])
        self.assertNotEqual(a.build_ledger(raw)['ledger_sha256'], reordered['ledger_sha256'])
        self.assertNotIn(str(ROOT).encode(), first)
        self.assertNotIn(b'created_at', first)


class Publication(unittest.TestCase):
    def test_publication_is_exclusive_readonly_and_hash_named(self):
        with tempfile.TemporaryDirectory() as directory:
            document = a.build_ledger(LEDGER.read_bytes())
            name = a.publish(directory, document)
            path = Path(directory) / name
            content = path.read_bytes()
            self.assertEqual(name, hashlib.sha256(content).hexdigest()+'.json')
            self.assertEqual(path.stat().st_mode & 0o777, 0o400)
            with self.assertRaises(ValueError):
                a.publish(directory, document)
            self.assertEqual(path.read_bytes(), content)
            self.assertEqual(len(list(Path(directory).iterdir())), 1)

    def test_symlink_and_unsafe_directory_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            doc = a.build_ledger(LEDGER.read_bytes())
            name = hashlib.sha256(a.report_bytes(doc)).hexdigest()+'.json'
            target = Path(directory) / 'retained'
            target.write_text('retained')
            (Path(directory) / name).symlink_to(target)
            with self.assertRaises(ValueError):
                a.publish(directory, doc)
            self.assertEqual(target.read_text(), 'retained')
            (Path(directory) / 'link').symlink_to(directory, target_is_directory=True)
            with self.assertRaises(ValueError):
                a.publish(str(Path(directory)/'link'), doc)
            os.chmod(directory, 0o777)
            with self.assertRaises(ValueError):
                a.publish(directory, doc)

    def test_parallel_publishers_cannot_overwrite_each_other(self):
        with tempfile.TemporaryDirectory() as directory:
            def attempt(_):
                try:
                    return a.publish(directory, a.build_ledger(LEDGER.read_bytes()))
                except ValueError:
                    return None
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(attempt, range(2)))
            self.assertEqual(sum(r is not None for r in results), 1)
            self.assertEqual(len(list(Path(directory).iterdir())), 1)

    def test_fsync_failure_cleans_temps_and_preserves_visible_publication(self):
        for fail_at in (1, 2):
            with tempfile.TemporaryDirectory() as directory:
                real = os.fsync
                count = 0
                def fail(fd):
                    nonlocal count
                    count += 1
                    if count == fail_at:
                        raise OSError('sensitive host metadata')
                    return real(fd)
                with mock.patch.object(a.os, 'fsync', side_effect=fail):
                    with self.assertRaises(ValueError) as raised:
                        a.publish(directory, a.build_ledger(LEDGER.read_bytes()))
                self.assertNotIn('sensitive', str(raised.exception))
                files = list(Path(directory).iterdir())
                self.assertEqual(len(files), 0 if fail_at == 1 else 1)
                self.assertFalse(any(p.name.startswith('.tmp-') for p in files))

    def test_read_input_refuses_symlinks_special_and_oversized_files(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory)/'input'
            p.write_bytes(b'{}')
            self.assertEqual(a.read_input(p), b'{}')
            link = Path(directory)/'link'
            link.symlink_to(p)
            with self.assertRaises(ValueError):
                a.read_input(link)
            with p.open('wb') as stream:
                stream.truncate(1048577)
            with self.assertRaises(ValueError):
                a.read_input(p)
            p.unlink()
            os.mkfifo(p)
            with self.assertRaises(ValueError):
                a.read_input(p)


class Registry(unittest.TestCase):
    def test_every_rule_has_enforcement_and_behavioral_mutation_test(self):
        self.assertGreaterEqual(len(a.RULES), 15)
        names = set()
        for rule in a.RULES:
            self.assertEqual(set(rule), {'id', 'invariant', 'enforcement', 'mutation_test'})
            self.assertNotIn(rule['id'], names)
            names.add(rule['id'])
            self.assertTrue(callable(getattr(a, rule['enforcement'], None)))
            group, method = rule['mutation_test'].split('.')
            self.assertTrue(callable(getattr(globals()[group], method, None)))


class PublicationRaces(unittest.TestCase):
    def test_colliding_temporary_symlink_is_never_deleted(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)/'retained'
            target.write_bytes(b'preserved')
            temporary = Path(directory)/('.tmp-'+'0'*32)
            temporary.symlink_to(target)
            with mock.patch.object(a.secrets, 'token_hex', return_value='0'*32):
                with self.assertRaises(ValueError):
                    a.publish(directory, a.build_ledger(LEDGER.read_bytes()))
            self.assertTrue(temporary.is_symlink())
            self.assertEqual(target.read_bytes(), b'preserved')

    def test_late_destination_race_preserves_existing_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            actual = a.rename_exclusive
            def race(fd, source, destination):
                target = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=fd)
                os.write(target, b'existing')
                os.close(target)
                actual(fd, source, destination)
            with mock.patch.object(a, 'rename_exclusive', side_effect=race):
                with self.assertRaises(ValueError):
                    a.publish(directory, a.build_ledger(LEDGER.read_bytes()))
            files = list(Path(directory).iterdir())
            self.assertEqual(len(files), 1)
            self.assertEqual(files[0].read_bytes(), b'existing')

    def test_parent_replacement_cannot_redirect_pinned_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory)/'original'
            original.mkdir(mode=0o700)
            other = Path(directory)/'other'
            other.mkdir(mode=0o700)
            retained = Path(directory)/'retained'
            actual = a.rename_exclusive
            def race(fd, source, destination):
                original.rename(retained)
                original.symlink_to(other, target_is_directory=True)
                actual(fd, source, destination)
            with mock.patch.object(a, 'rename_exclusive', side_effect=race):
                name = a.publish(original, a.build_ledger(LEDGER.read_bytes()))
            self.assertTrue((retained/name).is_file())
            self.assertEqual(list(other.iterdir()), [])


class AdditionalRefusals(unittest.TestCase):
    def test_reported_host_egress_is_not_hidden_by_invalid_other_metadata(self):
        bad = {'captures': [{'host_ip_as_mullvad_app_egress': 1}], 'unknown': 0.5}
        self.assertEqual(a.assess_bundle(bad, {})['oracle_status'], 'FAIL')

    def test_execution_result_and_capture_mode_cannot_be_forged(self):
        f = fixture()
        for path, replacement in ((('execution', 'actual'), 'unknown'),
                                  (('execution', 'ownership'), 'foreign'),
                                  (('execution', 'cleanup'), 'skipped'),
                                  (('execution', 'injection'), 'none'),
                                  (('execution', 'boundary'), 'migration.commit'),
                                  (('captures', 0, 'mode'), 'direct'),
                                  (('kind',), 'real')):
            bad = mutate(f['bundle'], path, replacement)
            self.assertNotEqual(assess_changed(bad, f['expected'])['oracle_status'], 'PASS')

    def test_every_expected_binding_leaf_is_required_and_closed(self):
        f = fixture()
        for key in f['expected']:
            for remove in (True, False):
                bad = mutate(f['expected'], (key,), None, remove=remove)
                self.assertNotEqual(a.assess_bundle(f['bundle'], bad)['oracle_status'], 'PASS')
        unknown = dict(f['expected'], unknown='syn-data')
        self.assertNotEqual(a.assess_bundle(f['bundle'], unknown)['oracle_status'], 'PASS')

    def test_checked_in_fixtures_and_plan_are_reproducible(self):
        for config in ('one_mullvad', 'five_mullvad', 'one_direct', 'five_mullvad_one_direct'):
            f = fixture(config)
            for key in ('bundle', 'expected'):
                raw = (ROOT/'tools/acceptance/fixtures'/(config+'.'+key+'.json')).read_bytes()
                self.assertEqual(a.strict_load(raw), f[key])
        self.assertEqual(a.strict_load((ROOT/'tools/acceptance/canary-plan.json').read_bytes()), a.plan_spec())
        self.assertEqual(a.strict_load((ROOT/'tools/acceptance/prerequisites-not-run.json').read_bytes()), a.empty_declarations())

    def test_machine_security_map_covers_every_original_invariant_group_and_gate(self):
        mapping = a.strict_load((ROOT/'tools/acceptance/security-test-map.json').read_bytes())
        self.assertEqual(len(mapping['rows']), 12)
        groups = set()
        gates = set()
        for row in mapping['rows']:
            groups.update(row['scenario_groups'])
            gates.update(row['other_gates'])
            self.assertEqual(row['runtime_status'], 'NOT_RUN')
        self.assertEqual(groups, {'tunnel_provider', 'routing', 'firewall', 'process', 'resources',
                                  'identity', 'isolation', 'clients', 'migration'})
        self.assertEqual(len(gates), 11)
        self.assertEqual(mapping['source_sha256'], hashlib.sha256(
            (ROOT/'docs/rust-v2/security-evidence-map.md').read_bytes()).hexdigest())


class CLI(unittest.TestCase):
    def invoke(self, arguments):
        import io
        from types import SimpleNamespace
        stream = io.BytesIO()
        with mock.patch.object(a.sys, 'stdout', SimpleNamespace(buffer=stream)):
            code = a.main(arguments)
        return code, a.strict_load(stream.getvalue())

    def test_cli_oracle_pass_does_not_change_acceptance_status(self):
        for config in ('one_mullvad', 'five_mullvad', 'one_direct', 'five_mullvad_one_direct'):
            base = ROOT/'tools/acceptance/fixtures'
            code, document = self.invoke(['check', '--input', str(base/(config+'.bundle.json')),
                                         '--expected', str(base/(config+'.expected.json'))])
            self.assertEqual(code, 0)
            self.assertEqual(document['oracle_status'], 'PASS')
            self.assertEqual(document['acceptance_status'], 'UNVERIFIED')
            self.assertFalse(document['release_ready'])

    def test_cli_invalid_arguments_files_and_duplicate_keys_are_redacted(self):
        for args in (['unknown-command-with-secret'], ['check'],
                     ['ledger', '--unknown-secret-flag'],
                     ['ledger', '--ledger', 'private-secret-path-that-does-not-exist']):
            code, document = self.invoke(args)
            self.assertEqual(code, 2)
            self.assertEqual(document, {'release_ready': False, 'status': 'UNVERIFIED',
                                        'reason': 'input_or_operation_refused'})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'input.json'
            path.write_bytes(b'{"x":1,"x":2}')
            code, document = self.invoke(['check', '--input', str(path), '--expected', str(path)])
            self.assertEqual(code, 2)
            self.assertEqual(document['status'], 'UNVERIFIED')

    def test_cli_reports_forbidden_egress_fail_and_preflight_not_run(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'input.json'
            path.write_bytes(b'{"captures":[{"host_ip_as_mullvad_app_egress":1}]}')
            code, document = self.invoke(['check', '--input', str(path), '--expected', str(path)])
            self.assertEqual(code, 1)
            self.assertEqual(document['oracle_status'], 'FAIL')
        code, document = self.invoke(['preflight', '--plan', str(ROOT/'tools/acceptance/canary-plan.json'),
                                     '--declarations', str(ROOT/'tools/acceptance/prerequisites-not-run.json')])
        self.assertEqual(code, 2)
        self.assertEqual(document['status'], 'NOT_RUN')
        self.assertEqual(document['preflight'], 'BLOCKED')

    def test_checked_in_registry_export_cannot_drift_from_enforcement(self):
        self.assertEqual(a.strict_load((ROOT/'tools/acceptance/invariant-registry.json').read_bytes()),
                         list(a.RULES))

    def test_schema_refs_and_closed_objects_cover_the_entire_fixture(self):
        schema = a.strict_load((ROOT/'tools/acceptance/evidence-schema.json').read_bytes())
        # Local independent structural evaluator for the declared schema subset;
        # production semantic validation is a separate implementation.
        def structural(value, node):
            if '$ref' in node:
                return structural(value, schema['$defs'][node['$ref'].split('/')[-1]])
            if 'const' in node:
                self.assertEqual(value, node['const'])
            if 'enum' in node:
                self.assertIn(value, node['enum'])
            kind = node.get('type')
            if kind == 'object':
                self.assertIs(type(value), dict)
                self.assertFalse(node['additionalProperties'])
                self.assertEqual(set(value), set(node['required']))
                self.assertEqual(set(value), set(node['properties']))
                for key in value:
                    structural(value[key], node['properties'][key])
            elif kind == 'array':
                self.assertIs(type(value), list)
                self.assertGreaterEqual(len(value), node['minItems'])
                self.assertLessEqual(len(value), node['maxItems'])
                for entry in value:
                    structural(entry, node['items'])
            elif kind == 'integer':
                self.assertIs(type(value), int)
                if 'minimum' in node:
                    self.assertGreaterEqual(value, node['minimum'])
                if 'maximum' in node:
                    self.assertLessEqual(value, node['maximum'])
            elif kind == 'string':
                self.assertIs(type(value), str)
                if 'pattern' in node:
                    self.assertRegex(value, node['pattern'])
                if 'maxLength' in node:
                    self.assertLessEqual(len(value), node['maxLength'])
        for config in ('one_mullvad', 'five_mullvad', 'one_direct', 'five_mullvad_one_direct'):
            f = fixture(config)
            structural(f['bundle'], schema)
            structural(f['expected'], schema['$defs']['expected'])
        # Removing a required schema field must not silently broaden the contract.
        bad = fixture()['bundle']
        bad['extra'] = 'syn-test'
        with self.assertRaises(AssertionError):
            structural(bad, schema)


class ReviewRoundOne(unittest.TestCase):
    # Expectations below come from the spec, not FAULTS/SCENARIOS.
    def test_required_failure_subitems_have_independent_rows(self):
        inventory = {
            'tunnel_provider': 'wireguard_deleted wireguard_down handshake_stale peer_wrong peer_key_wrong endpoint_wrong transport_loss http_transient http_permanent provider_malformed provider_negative server_wrong',
            'routing': 'route_drift ordinary_default_restored endpoint_route docker_subnet_route docker_gateway_route ipv6_route unexpected_interface spoofed_source',
            'firewall': 'data_policy_removed data_policy_drift host_guard_removed host_guard_drift atomic_update_failed foreign_conflict bridge_identity_changed',
            'process': 'worker_crash worker_freeze host_guard_crash host_guard_freeze tailscale_crash tailscale_freeze container_kill container_restart docker_restart service_restart oom',
            'resources': 'disk_full tmpfs_full runtime_operation_failure docker_api_unavailable api_delayed health_malformed host_reboot',
            'identity': 'identity_revoked control_revoked approval_revoked name_revoked credential_revoked credential_expired control_plane_loss duplicate_identity name_server_mismatch',
            'isolation': 'exit_failure_others_active exit_restart_others_active direct_active_during_mullvad_faults shared_endpoint overlapping_vpn_addresses',
            'clients': 'exit_disappears selected_node_changes tailscale_restarts routes_reset dns_cache_empty proxy_upstream_failed proxy_settings_absent proxy_settings_bypassed',
            'migration': 'inspect stage plan protect drain stop backup activate restore_identity rename verify commit recover',
        }
        required = {group+'.'+name for group, names in inventory.items() for name in names.split()}
        rows = {(r['configuration'], r['scenario']) for r in a.build_ledger(LEDGER.read_bytes())['rows']}
        missing = {(c, s) for c in ('one_mullvad', 'five_mullvad', 'one_direct',
                                    'five_mullvad_one_direct') for s in required} - rows
        self.assertEqual(missing, set())

    def test_spec_requirement_table_covers_every_phrase_and_expanded_item(self):
        path = ROOT/'tools/acceptance/mandatory-requirements.json'
        self.assertTrue(path.is_file(), 'missing spec-derived machine-readable requirement table')
        table = a.strict_load(path.read_bytes())
        spec = (ROOT/'docs/rust-v2/IMPLEMENTATION.md').read_text()
        mandatory = ' '.join(spec.split('## Mandatory acceptance\n', 1)[1].split('\n## ', 1)[0].split())
        self.assertEqual(' '.join(' '.join(table['mandatory_text']).split()), mandatory)
        failure_text = mandatory.split('Failures cover ', 1)[1].split('. Boot capture', 1)[0]
        phrases = failure_text.split('; ')
        mapped = {row['phrase']: row for row in table['failure_phrases']}
        self.assertEqual(set(mapped), set(phrases))
        # Slash-separated prose items cannot disappear behind a broad group label.
        for phrase in phrases:
            expanded = [p.strip() for p in phrase.split('/')]
            self.assertEqual([r['phrase'] for r in mapped[phrase]['requirements']], expanded)
        rows = {(r['configuration'], r['scenario']) for r in a.build_ledger(LEDGER.read_bytes())['rows']}
        seen_ids = set()
        for group in table['failure_phrases'] + table['other_phrases'] + table['migration_phrases']:
            for requirement in group['requirements']:
                self.assertNotIn(requirement['id'], seen_ids)
                seen_ids.add(requirement['id'])
                self.assertTrue(requirement['scenario_ids'])
                for config in requirement['configurations']:
                    for scenario in requirement['scenario_ids']:
                        self.assertTrue((config, scenario) in rows, (requirement['id'], config, scenario))
        # Every non-failure sentence and artifact item must also be mapped.
        other_phrases = {g['phrase'] for g in table['other_phrases']}
        for phrase in (
                'Real disposable Tailscale clients generating IPv4, DNS, IPv6, TCP, UDP',
                'capture at client WAN, host WAN, transports and data.',
                'One Mullvad, five Mullvad, direct, and five+direct configurations.',
                'Positive capture controls',
                'zero forbidden plaintext/cross-exit markers; host IP as Mullvad app egress immediately fails.',
                'Boot capture must be operational BEFORE protected traffic.',
                'Skips/unknowns are unverified and block claims.',
                'No unmanaged/non-Linux client guarantee.', 'Do not publish until all gates pass.'):
            self.assertIn(phrase, other_phrases)
        artifacts = mandatory.split('Artifacts: ', 1)[1].split('. Do not publish', 1)[0]
        self.assertTrue(set(artifacts.split(', ')) <= other_phrases)
        # Independent I/O inventory, derived from migration-preparation's journal contract.
        migration_text = ' '.join((ROOT/'docs/rust-v2/migration-preparation.md').read_text().split())
        for group in table['migration_phrases']:
            self.assertIn(group['phrase'], migration_text)
        for direction in ('apply', 'resume', 'rollback'):
            operations = ('quarantine stage_create stage_write stage_verify stage_file_fsync '
                          'stage_directory_fsync stage_checksums adapter_drain adapter_pre_start_stop '
                          'service_stop adapter_post_stop_stop all_users_stopped stopped_state_retention '
                          'old_release_checksum state_format identity_verify release_exchange '
                          'release_parent_fsync restore_identity node_rename client_verify service_start '
                          'adapter_rebind adapter_post_start adapter_health journal_pending_create '
                          'journal_write journal_verify journal_file_fsync journal_rename '
                          'journal_parent_fsync journal_cas pending_validate pending_unlink '
                          'stage_cleanup_validate stage_cleanup_unlink cleanup_intent cleanup_quarantine '
                          'cleanup_adapter_stop cleanup_service_stop cleanup_all_users_stopped '
                          'terminal_publish reversal_intent terminal_replay').split()
            for operation in operations:
                for edge in ('before', 'after'):
                    for config in ('one_mullvad', 'five_mullvad', 'one_direct', 'five_mullvad_one_direct'):
                        self.assertIn((config, f'migration.{direction}.{operation}.{edge}'), rows)

    def test_schema_enumerates_and_accepts_each_independent_fault_binding(self):
        schema = a.strict_load((ROOT/'tools/acceptance/evidence-schema.json').read_bytes())
        scenarios = {r['scenario'] for r in a.build_ledger(LEDGER.read_bytes())['rows']
                     if r['configuration'] == 'one_mullvad'}
        for obj, field in (('context', 'scenario'), ('expected', 'scenario'), ('execution', 'boundary')):
            declared = schema['$defs'][obj]['properties'][field]['enum']
            self.assertEqual(set(declared), scenarios)
            self.assertEqual(len(declared), len(scenarios))
        for config in ('one_mullvad', 'five_mullvad', 'one_direct', 'five_mullvad_one_direct'):
            for scenario in ('process.container_restart', 'migration.drain', 'migration.stop',
                             'migration.rename', 'identity.identity_revoked', 'identity.control_revoked',
                             'identity.name_revoked', 'migration.rollback.journal_write.after'):
                f = fixture(config, scenario)
                verdict = a.assess_bundle(f['bundle'], f['expected'])
                self.assertEqual(verdict['oracle_status'], 'PASS', (config, scenario))
                self.assertEqual(verdict['acceptance_status'], 'UNVERIFIED')

    def test_run_admission_rejects_relabelled_or_out_of_window_replay(self):
        f = fixture()
        bad = copy.deepcopy(f['bundle'])
        bad['context']['run_id'] = 'syn-run-002'
        self.assertNotEqual(assess_changed(bad, f['expected'])['oracle_status'], 'PASS')
        self.assertIn('expected_run', f['expected'])
        for key, value in (('run_id', 'syn-other'), ('epoch', 'syn-other'),
                           ('not_before_ns', 1), ('not_after_ns', 99)):
            expected = copy.deepcopy(f['expected'])
            expected['expected_run'][key] = value
            self.assertNotEqual(a.assess_bundle(f['bundle'], expected)['oracle_status'], 'PASS')

    def test_partial_reads_or_cooperative_writer_cannot_be_admitted(self):
        import fcntl
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'input.json'
            path.write_bytes(b' '*100 + b'{}')
            real_read = os.read
            with mock.patch.object(a.os, 'read', side_effect=lambda fd, size: real_read(fd, min(size, 16))):
                with self.assertRaises(a.Invalid):
                    a.read_input(path)
            with path.open('r+b') as writer:
                fcntl.flock(writer, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaises(a.Invalid):
                    a.read_input(path)

    def test_fstat_change_during_acquisition_refuses_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'input.json'
            path.write_bytes(b'{}')
            real_read = os.read
            def race(fd, size):
                result = real_read(fd, size)
                path.write_bytes(b'{"changed":true}')
                return result
            with mock.patch.object(a.os, 'read', side_effect=race):
                with self.assertRaises(a.Invalid):
                    a.read_input(path)

    def test_multichunk_mixed_invalid_versions_never_yield_cli_oracle_pass(self):
        f = fixture()
        # The first context is before the old 64KiB boundary; captures are after it.
        def padded(bundle):
            prefix = b'{"schema_version":1,"kind":"synthetic","context":' + a.canonical(bundle['context'])
            tail = b',"execution":' + a.canonical(bundle['execution'])
            tail += b',"captures":' + a.canonical(bundle['captures'])
            tail += b',"manifest":' + a.canonical(bundle['manifest']) + b'}'
            return prefix + b' '*(65536-len(prefix)+16) + tail
        version_a = copy.deepcopy(f['bundle'])
        version_a['captures'][0]['positive_control_packets'] = 11
        version_b = copy.deepcopy(f['bundle'])
        version_b['context']['run_id'] = 'syn-run-002'
        raw_a, raw_b = padded(version_a), padded(version_b)
        self.assertEqual(len(raw_a), len(raw_b))
        for raw in (raw_a, raw_b):
            self.assertNotEqual(a.assess_bundle(a.strict_load(raw), f['expected'])['oracle_status'], 'PASS')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'input.json'
            expected_path = Path(directory)/'expected.json'
            path.write_bytes(raw_a)
            expected_path.write_bytes(a.canonical(f['expected']))
            real_read = os.read
            calls = 0
            def race(fd, size):
                nonlocal calls
                result = real_read(fd, size)
                if os.fstat(fd).st_ino == path.stat().st_ino:
                    calls += 1
                    if calls == 1:
                        path.write_bytes(raw_b)  # real same-size concurrent content swap
                return result
            with mock.patch.object(a.os, 'read', side_effect=race):
                code, document = CLI.invoke(self, ['check', '--input', str(path), '--expected', str(expected_path)])
            self.assertNotEqual(document.get('oracle_status'), 'PASS')
            self.assertNotEqual(code, 0)
            self.assertEqual(calls, 1, 'one bounded acquisition; never assemble multiple read versions')

    def test_snapshot_hash_and_published_verdict_use_only_acquired_bytes(self):
        f = fixture()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'input.json'
            expected = Path(directory)/'expected.json'
            raw = a.canonical(f['bundle']) + b'\n'
            path.write_bytes(raw)
            expected.write_bytes(a.canonical(f['expected']))
            real_assess = a.assess_bundle
            def replace_after_snapshot(bundle, external):
                path.write_bytes(b'{"invalid":true}')
                return real_assess(bundle, external)
            with mock.patch.object(a, 'assess_bundle', side_effect=replace_after_snapshot):
                code, doc = CLI.invoke(self, ['check', '--input', str(path), '--expected', str(expected),
                                               '--publish-dir', directory])
            self.assertEqual(code, 0)
            self.assertEqual(doc.get('input_sha256'), hashlib.sha256(raw).hexdigest())
            self.assertEqual(doc.get('expected_sha256'), hashlib.sha256(expected.read_bytes()).hexdigest())
            report = Path(directory)/(hashlib.sha256(a.report_bytes(doc)).hexdigest()+'.json')
            self.assertEqual(a.strict_load(report.read_bytes()), doc)

    def test_all_leaf_perturbations_and_cross_scenario_swaps_cannot_forge_pass(self):
        f = fixture()
        other = fixture(scenario='clients.exit_disappears')['bundle']
        other_leaves = dict(leaves(other))
        for path, value in leaves(f['bundle']):
            for label, replacement, remove in (
                    ('missing', None, True), ('null', None, False),
                    ('wrong_type', {} if type(value) is not dict else [], False),
                    ('nan', float('nan'), False), ('huge', 2**80, False),
                    ('scenario_swap', other_leaves[path], False)):
                bad = mutate(f['bundle'], path, replacement, remove)
                verdict = a.assess_bundle(bad, f['expected'])
                self.assertNotEqual(verdict['acceptance_status'], 'PASS', (path, label))
                if label != 'scenario_swap' or replacement != value:
                    self.assertNotEqual(verdict['oracle_status'], 'PASS', (path, label))
            # Duplicate the nearest containing object member, including array leaves.
            owner_path = path
            while type(owner_path[-1]) is int:
                owner_path = owner_path[:-1]
            parent = f['bundle']
            for key in owner_path[:-1]:
                parent = parent[key]
            key = owner_path[-1]
            class DuplicatePairs(dict):
                def items(self):
                    return list(super().items()) + [(key, parent[key])]
            target = DuplicatePairs(parent)
            bad = mutate(f['bundle'], owner_path[:-1], target) if len(owner_path) > 1 else target
            raw = json.dumps(bad, separators=(',', ':')).encode()
            with self.assertRaises(a.Invalid, msg=str(path)):
                a.strict_load(raw)


if __name__ == '__main__':
    unittest.main()
