#!/usr/bin/env python3
"""Offline acceptance and adversarial tests; all fixture writes are temporary."""
import copy
import importlib.util
import json
import multiprocessing
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

if not __debug__:
    raise RuntimeError('optimized_python_refused')

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / 'tools/rust-v2-lab/validate-run410-witness.py'
RAW = ROOT / 'target/lab-state/actual-program-run-410.json'


def split(record):
    lines = record['stdout'].splitlines()
    index = next(i for i, line in enumerate(lines) if line.startswith('LAB_SECRET_BOOTSTRAP '))
    return lines, index, json.loads(lines[index].split(' ', 1)[1])


# Independently transcribed from ValidationBirth, OwnerDomainRecord, QueryFacts,
# project.rs and native result emitters. This map is NOT read from SCHEMAS.
U32_FIELDS = set(('pid original_pid eligible_original_pid listener_origin_uid '
                  'listener_origin_gid planned_host_link_index mode mtu controller '
                  'promiscuity all_multicast route_priority nexthop_id output metric '
                  'flags priority table suppress_prefixlen postcompletion_inventory_polls').split())
U8_FIELDS = set('prefix scope preference protocol action fault received_packets released_gates'.split())
DIGEST_FIELDS = set(('request query policy configuration declaration host_declaration '
                     'binding public_result public_key device_public_key declaration_digest '
                     'movement_query').split())


# Field-level source inventory used by the mechanical Rust/schema check and
# the report. Option fields may be narrowed for this completed success profile.
RUST_SHAPES = [
    ('crates/vprouter-launch/src/owned/preparation.rs','ValidationBirth','Birth'),
    ('crates/vprouter-launch/src/owned.rs','Identity','Identity'),
    ('crates/vprouter-launch/src/supervision.rs','OwnerDomainRecord','OwnerEpoch'),
    ('crates/vprouter-launch/src/attachment.rs','QueryFacts','QueryFacts'),
    ('crates/vprouter-launch/src/owned/preparation/inspection.rs','History','InspectionHistory'),
    ('crates/vprouter-launch/src/owned/preparation/inspection.rs','Initial','InspectionInitial'),
    ('crates/vprouter-launch/src/owned/preparation/mount.rs','History','Attachment'),
    ('crates/vprouter-launch/src/owned/preparation/mount.rs','Placeholder','Placeholder'),
    ('crates/vprouter-launch/src/owned/preparation/fresh_transport.rs','History','FreshTransport'),
    ('crates/vprouter-launch/src/owned/preparation/fresh_mount.rs','History','MountHistory'),
    ('crates/vprouter-launch/src/owned/preparation/host_link.rs','History','HostLinkHistory'),
    ('crates/vprouter-launch/src/owned/preparation/quarantine.rs','Operation','NetfilterHistory'),
    ('crates/vprouter-launch/src/owned/preparation/quarantine.rs','PublicResult','NetfilterResult'),
    ('crates/vprouter-launch/src/owned/preparation/producer_creation.rs','History','ProducerCreationHistory'),
    ('crates/vprouter-launch/src/owned/preparation/producer_binding.rs','History','ProducerBindingHistory'),
    ('crates/vprouter-launch/src/owned/preparation/producer_binding.rs','PublicResult','ProducerBindingResult'),
    ('crates/vprouter-launch/src/owned/preparation/bootstrap.rs','History','BootstrapHistory'),
    ('crates/vprouter-launch/src/owned/preparation/bootstrap.rs','PublicResult','BootstrapResult'),
    ('crates/vprouter-network/src/project.rs','Link','Link'),
    ('crates/vprouter-network/src/project.rs','Address','Address'),
    ('crates/vprouter-network/src/project.rs','Route','Route'),
    ('crates/vprouter-network/src/project.rs','Rule','Rule'),
    ('crates/vprouter-network/src/project.rs','Wireguard','Wireguard'),
    ('crates/vprouter-network/src/project.rs','Peer','WireguardPeer'),
]


def rust_fields(relative, name):
    text = (ROOT / relative).read_text()
    match = re.search(r'\bstruct ' + name + r'\s*\{(.*?)^}', text, re.S | re.M)
    assert match, (relative, name)
    return [(m.group(1),m.group(2).strip()) for m in re.finditer(
        r'^    (?:pub(?:\([^)]*\))? )?(\w+): (.*),$', match.group(1), re.M)]


def leaf_cases(value, path=()):
    if type(value) is dict:
        for key, item in value.items():
            yield from leaf_cases(item, path + (key,))
    elif type(value) is list and value:
        for index, item in enumerate(value):
            yield from leaf_cases(item, path + (index,))
    else:
        yield path, value


def integer_bits(path):
    key = path[-1]
    if type(key) is int:
        field = next(p for p in reversed(path) if type(p) is str)
        if field in DIGEST_FIELDS or field == 'address':
            return 8
        if field == 'pins':
            return 32 if key == 2 else 64
        if field == 'addition':
            return 32 if len(path) >= 2 and path[-2] == 'addition' else 8
        if field == 'query_sequences':
            return 32
        if field == 'allowed_ips':
            return 8
        return 64
    if key == 'polls' and path[-2] == 'admission':
        return 32
    if key == 'hardware_type':
        return 16
    if key == 'index':
        # Writer indices are usize; link and WAN indices are u32.
        return 64 if path[-2] in ('own_intent_polling', 'own_query_intent_polling', 'original_writer') else 32
    if key == 'original_pid' and path[-2] == 'foreign_eligibility':
        return 31
    if key in ('held_pending_polls','queued_polls') and path[-3:-1] == ('host_addition','own_intent_polling'):
        return 32
    if key in U32_FIELDS or key == 'peer_index':
        return 32
    if key in U8_FIELDS:
        return 8
    if key in ('actual_wait_status', 'listener_origin_pid'):
        return 31  # i32::MAX+1; negative tested separately by success status guards.
    return 64


def sweep_chunk(paths):
    spec = importlib.util.spec_from_file_location('sweep_validator', TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    record = json.loads(RAW.read_bytes())
    lines, index, witness = split(record)
    failures, total = [], 0
    with tempfile.TemporaryDirectory(prefix='run410-leaf-') as tmp:
        raw = Path(tmp) / 'record.json'
        for path, original in paths:
            parent = witness
            for key in path[:-1]:
                parent = parent[key]
            key = path[-1]
            mutations = [('wrong_type', {'invalid_leaf_type': True})]
            if type(original) is int:
                mutations += [('negative', -1), ('overflow', 2 ** integer_bits(path))]
            # All non-null scalars have a required serialized key or fixed-array
            # slot. Absence tests object keys; null tests populated array slots.
            if type(key) is str:
                mutations.append(('absent', None))
            elif original is not None:
                mutations.append(('null', None))
            for kind, replacement in mutations:
                if kind == 'absent':
                    del parent[key]
                else:
                    parent[key] = replacement
                lines[index] = 'LAB_SECRET_BOOTSTRAP ' + json.dumps(witness, separators=(',', ':'))
                record['stdout'] = '\n'.join(lines) + '\n'
                raw.write_text(json.dumps(record, separators=(',', ':')))
                receipt = module.validate(raw)
                total += 1
                if receipt['verdict'] != 'FAIL':
                    failures.append((path, kind))
                parent[key] = original
    return total, failures


class WitnessValidation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Missing production validation is an assertion failure in the RED run.
        assert TOOL.is_file(), 'typed run410 validator is not implemented'
        spec = importlib.util.spec_from_file_location('run410_witness', TOOL)
        cls.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.m)
        cls.record = json.loads(RAW.read_bytes())
        cls.lines, cls.index, cls.witness = split(cls.record)

    def receipt(self, record):
        with tempfile.TemporaryDirectory(prefix='run410-witness-') as tmp:
            path = Path(tmp) / 'record.json'
            path.write_text(json.dumps(record, allow_nan=False))
            return self.m.validate(path)

    def rejected(self, record, check):
        receipt = self.receipt(record)
        self.assertEqual(receipt['verdict'], 'FAIL')
        self.assertTrue(any(c['status'] == 'FAIL' and c['name'] == check
                            for c in receipt['checks']), receipt)

    def mutated(self, change):
        record = copy.deepcopy(self.record)
        lines, index, witness = split(record)
        change(witness)
        lines[index] = 'LAB_SECRET_BOOTSTRAP ' + json.dumps(witness)
        record['stdout'] = '\n'.join(lines) + '\n'
        return record

    def test_all_independent_reviewer_fixtures_through_validate(self):
        # Keep these exact reviewer bytes, including duplicate-key/NaN probes.
        prior = Path('/tmp/vprouter-witness-review')
        current = Path('/tmp/vprouter-witness-rereview')
        original = (
            'authorization boot_id charge deadline drop_row duplicate_key fault nan '
            'unknown_field binding_result_8pins bootstrap_result_6pins own_intent_identity '
            'query_intent_index preparation_fenced preparation_pending preparation_phase '
            'preparation_unreaped retained_prefix_birth').split()
        fresh = (
            'bootstrap_query_u32_pid_overflow bootstrap_query_has_initial '
            'host_bootstrap_policy_wrong_kind host_bootstrap_policy_wrong_scope '
            'entry_producer_binding_mismatch_all_prefixes '
            'binding_policy_mismatch_canonical_all_prefixes '
            'binding_query_mismatch_all_prefixes binding_data_mismatch_all_prefixes '
            'host_fault_nonzero host_negative_count_zero host_own_intent_identity').split()
        self.assertEqual((len(original), len(fresh)), (18, 11))
        for directory, names in ((prior, original), (current, fresh)):
            for name in names:
                path = directory / (name + '.json')
                with self.subTest(fixture=str(path)):
                    self.assertTrue(path.is_file(), 'required reviewer fixture missing')
                    self.assertEqual(self.m.validate(path)['verdict'], 'FAIL', name)
        self.assertEqual(self.m.validate(prior / 'real.json')['verdict'], 'PASS')

    def test_every_real_witness_leaf_through_validate(self):
        leaves = list(leaf_cases(self.witness))
        self.assertEqual(len(leaves), 28782, 'review leaf inventory changed; audit it')
        chunks = [leaves[i:i+128] for i in range(0, len(leaves), 128)]
        # Local Python test workers only, no model delegation or guest execution.
        workers = min(8, len(os.sched_getaffinity(0)))
        total, failures = 0, []
        with multiprocessing.get_context('fork').Pool(workers) as pool:
            for count, errors in pool.imap_unordered(sweep_chunk, chunks):
                total += count
                failures.extend(errors)
        print('leaf sweep:', len(leaves), 'leaves,', total, 'end-to-end mutations', flush=True)
        self.assertEqual(failures, [], 'false PASS leaf mutations: ' + repr(failures))

    def test_retained_success_guards_through_validate(self):
        # Each is a retained successful continuation, prior to its own drop.
        host = ('host_addition',)
        binding = host + ('producer_binding',)
        assembly = binding + ('assembly',)
        quarantine = assembly + ('quarantine',)
        movement = quarantine + ('movement',)
        provision = movement + ('provision',)
        stages = [host, binding, assembly, quarantine, movement, provision]
        for path in stages:
            original = self.witness
            for key in path:
                original = original[key]
            values = {'fault': 1, 'schema': 2, 'parent_pristine': False,
                      'continued_original_context': False}
            values.update({k: True for k in original if k.endswith('_retained_after_drop')})
            for field, value in values.items():
                def change(w):
                    obj = w
                    for key in path:
                        obj = obj[key]
                    obj[field] = value
                with self.subTest(stage=path, field=field):
                    self.rejected(self.mutated(change), 'retained_success')
        for field, value in [('canonical_negative_checks', 0), ('charges_before', [0, 0]),
                             ('charges_before_drop', [0, 0]), ('result_writer_held', True),
                             ('unacknowledged_host_addition_retained', True)]:
            self.rejected(self.mutated(lambda w: w['host_addition'].__setitem__(field, value)),
                          'retained_success')
        for key in ('index', 'pid', 'start', 'queued_polls', 'held_pending_polls', 'negative_checks', 'released'):
            self.rejected(self.mutated(lambda w: w['host_addition']['own_intent_polling'].__setitem__(key, 0 if key != 'released' else False)),
                          'retained_success')

    def test_canonical_history_guards_coordinated_copies(self):
        # Mutate every retained Preparation together to avoid prefix-equality
        # checks accidentally serving as the only canonical oracle.
        cases = [
            ('binding_parent', lambda p: p['producer_binding']['parent'].__setitem__('ino', 2)),
            ('binding_name', lambda p: p['producer_binding'].__setitem__('name', 'wrong')),
            ('binding_creation', lambda p: p['producer_binding']['creation']['group'].__setitem__('ino', 2)),
            ('entry_binding', lambda p: p['entry_producer']['binding'].__setitem__(0, p['entry_producer']['binding'][0] ^ 1)),
            ('policy_kind', lambda p: p['netfilter'][1].__setitem__('kind', 'sockets')),
            ('policy_scope', lambda p: p['netfilter'][1].__setitem__('scope', 'data')),
            ('query_initial', lambda p: p['producer_binding_query'].__setitem__('initial', p['inspection']['initial'])),
            ('creation_data', lambda p: p['producer_creation']['data'].__setitem__('ino', 2)),
            ('quarantine_result', lambda p: p['netfilter'][1]['result']['policy'].__setitem__(0, 0)),
            ('host_order', lambda p: p['host_link'][0].__setitem__('kind', 'host_sockets') if p['host_link'] else None),
        ]
        for name, mutate in cases:
            def change(w):
                def visit(obj):
                    if type(obj) is dict:
                        if 'canonical_owner_epoch' in obj and obj.get('producer_binding') is not None:
                            mutate(obj)
                        for item in obj.values():
                            visit(item)
                    elif type(obj) is list:
                        for item in obj:
                            visit(item)
                visit(w)
            with self.subTest(guard=name):
                receipt = self.receipt(self.mutated(change))
                self.assertEqual(receipt['verdict'], 'FAIL', name)

    def test_remaining_narrow_native_emitter_types(self):
        cases = [
            ('admission_polls', lambda w: w['host_addition']['admission'], 'polls', 2**32),
            ('host_inventory', lambda w: w['host_addition']['operations'][0], 'postcompletion_inventory_polls', 2**32),
            ('mount_packets', lambda w: w['host_addition']['producer_binding']['assembly']['quarantine']['movement']['provision']['attachment']['mount'], 'received_packets', 256),
        ]
        for name, select, key, value in cases:
            with self.subTest(type=name):
                self.rejected(self.mutated(lambda w: select(w).__setitem__(key,value)), 'typed_witness')

    def test_all_success_booleans_in_retained_emitters(self):
        # Metadata booleans in typed emitter evidence, excluding network-model
        # fields whose validity follows the declared baseline/link contracts.
        cases = [(path,value) for path,value in leaf_cases(self.witness)
                 if type(value) is bool and path[-1] not in ('up','ipv6')]
        for path,value in cases:
            def change(w):
                obj = w
                for key in path[:-1]:
                    obj = obj[key]
                obj[path[-1]] = not value
            with self.subTest(path=path):
                self.assertEqual(self.receipt(self.mutated(change))['verdict'], 'FAIL')

    def test_rust_serialized_field_inventory_and_primitive_ranges(self):
        for file,name,schema in RUST_SHAPES:
            fields = rust_fields(file,name)
            self.assertEqual(set(k for k,_ in fields), set(self.m.SCHEMAS[schema]), (file,name,schema))
            for key,rust_type in fields:
                base = rust_type.removeprefix('Option<').removesuffix('>')
                if base not in ('u8','u16','u32','u64','i32','i64','[u8; 32]','[(u64, u64, u32); 6]','[(u64, u64, u32); 8]'):
                    continue
                spec = self.m.SCHEMAS[schema][key]
                expected = {'[u8; 32]':'bytes32','[(u64, u64, u32); 6]':'pins6',
                            '[(u64, u64, u32); 8]':'pins8'}.get(base,base)
                # Some Option values are fixed null in this success profile.
                if spec != 'null':
                    self.assertIn(expected, list(self.m.alternatives(spec)), (file,key,rust_type,spec))
        for bits in (8,16,32,64):
            for value in (-1,2**bits,True,1.0,None):
                with self.assertRaises(ValueError):
                    self.m.typed(value,'u'+str(bits),'Rust range')
        for spec,bits in (('i32',32),('i64',64)):
            for value in (-2**(bits-1)-1,2**(bits-1),True,1.0,None):
                with self.assertRaises(ValueError):
                    self.m.typed(value,spec,'Rust signed range')

    def test_additional_recorded_success_guards(self):
        cases = [
            ('host_inventory', lambda w: w['host_addition']['operations'][3]['host_observation']['addresses'].clear()),
            ('host_inventory_extra', lambda w: w['host_addition']['operations'][3]['host_observation']['links'].pop()),
            ('owner_invocation', lambda w: [obj.__setitem__('invocation','0'*32) for _,obj in self.m.objects(w) if 'invocation' in obj]),
            ('owner_cgroup', lambda w: [obj['cgroup'].__setitem__('ino',0) for _,obj in self.m.objects(w) if 'invocation' in obj]),
            ('writer_phase', lambda w: [obj['writers'][0].__setitem__('phase','wrong') for _,obj in self.m.objects(w) if 'canonical_owner_epoch' in obj]),
            ('binding_oracle', lambda w: w['host_addition']['producer_binding'].__setitem__('canonical_negative_checks',0)),
        ]
        for name,change in cases:
            with self.subTest(guard=name):
                self.assertEqual(self.receipt(self.mutated(change))['verdict'], 'FAIL')

    def test_audit_origin_fixed_query_array_and_canonical_names(self):
        cases = [
            ('query_array_size', lambda w: w['host_addition']['preparation']['bootstrap_queries'].append(None)),
            ('origin_launch', lambda w: [obj['attachment']['origin'].__setitem__('launch','invalid') for _,obj in self.m.objects(w) if 'canonical_owner_epoch' in obj]),
            ('producer_name', lambda w: [obj['producer_creation'].__setitem__('name','invalid') for _,obj in self.m.objects(w) if 'canonical_owner_epoch' in obj and obj['producer_creation'] is not None]),
        ]
        for name,change in cases:
            with self.subTest(guard=name):
                self.assertEqual(self.receipt(self.mutated(change))['verdict'], 'FAIL')

    def test_foreign_capacity_pid_keeps_native_i32_width(self):
        self.rejected(self.mutated(lambda w: w['host_addition']['producer_binding']['assembly']['foreign_eligibility'].__setitem__('original_pid',2**31)), 'typed_witness')

    def test_quarantine_host_declaration_matches_all_recorded_copies(self):
        def change(w):
            for _,obj in self.m.objects(w):
                if 'host_declaration' in obj:
                    obj['host_declaration'][0] ^= 1
        self.assertEqual(self.receipt(self.mutated(change))['verdict'], 'FAIL')

    def test_real_and_reserialized_fixture_pass_without_byte_oracle(self):
        for receipt in (self.m.validate(RAW), self.receipt(self.record)):
            self.assertEqual(receipt['verdict'], 'PASS', receipt)
            self.assertFalse(receipt['runtime_acceptance'])
            self.assertFalse(receipt['release_ready'])
            self.assertTrue(receipt['does_not_prove'])
            self.assertTrue(all(c['status'] == 'PASS' for c in receipt['checks']))

    def test_every_required_top_level_field_removed_or_wrong_type(self):
        for key, value in self.witness.items():
            with self.subTest(field=key, mutation='missing'):
                self.rejected(self.mutated(lambda w: w.pop(key)), 'typed_witness')
            with self.subTest(field=key, mutation='type'):
                wrong = False if type(value) is int else 0 if type(value) is bool else 'wrong-type'
                self.rejected(self.mutated(lambda w: w.__setitem__(key, wrong)), 'typed_witness')

    def test_nested_required_fields_are_closed_and_typed(self):
        # Exercise every field of every distinct nested object shape, including
        # historical records. Schema omissions must not hide behind semantics.
        seen = set()
        def visit(value, path):
            if type(value) is dict:
                shape = tuple(sorted(value))
                if shape not in seen:
                    seen.add(shape)
                    for key in value:
                        altered = copy.deepcopy(value)
                        del altered[key]
                        with self.subTest(path=path, field=key, mutation='missing'):
                            with self.assertRaises(ValueError):
                                self.m.typed_object(altered, shape, path)
                        altered = copy.deepcopy(value)
                        altered[key] = {'unknown_type_sentinel': True}
                        with self.subTest(path=path, field=key, mutation='type'):
                            with self.assertRaises(ValueError):
                                self.m.typed_object(altered, shape, path)
                    altered = dict(value, unexpected=True)
                    with self.assertRaises(ValueError):
                        self.m.typed_object(altered, shape, path)
                for key, item in value.items():
                    visit(item, path + '.' + key)
            elif type(value) is list:
                for item in value:
                    visit(item, path + '[]')
        visit(self.witness, 'witness')
        self.assertGreaterEqual(len(seen), 60)

    def test_success_contract_mutations(self):
        cases = [
            ('fault', 1, 'bootstrap_success'), ('schema', 2, 'bootstrap_success'),
            ('canonical_negative_checks', 38, 'bootstrap_success'),
            ('charges_before_drop', [2, 3], 'charge_conservation'),
            ('charges_after_drop', [3, 2], 'charge_conservation'),
            ('parent_pristine', False, 'bootstrap_success'),
        ]
        cases += [(k, False, 'bootstrap_success') for k in self.witness
                  if k.endswith('_retained_after_drop') or k in
                  ('bootstrap_all_scopes_acknowledged', 'bootstrap_context_created')]
        cases += [(k, True, 'no_authority') for k in (
            'up_authorized', 'placement_authorized', 'health_ready_authorized',
            'resource_cleanup_authorized', 'multi_exit_runtime_proven', 'requirement8_complete')]
        for key, value, check in cases:
            with self.subTest(field=key):
                self.rejected(self.mutated(lambda w: w.__setitem__(key, value)), check)
        for field, value in [('charges_before', [4, 5]), ('charges_after', [1, 0]),
                             ('complete_original_job_set', 19), ('historical_original_jobs', 14),
                             ('retired_suffix_jobs', 4), ('complete', False)]:
            check = 'charge_conservation' if field.startswith('charges') else 'handoff'
            self.rejected(self.mutated(lambda w: w['handoff'].__setitem__(field, value)), check)

    def test_boot_deadlines_scope_identity_and_nested_authority(self):
        mutations = [
            (lambda w: w['preparation']['canonical_owner_epoch'].__setitem__('boot', '0'*36), 'owner_identity'),
            (lambda w: w['preparation']['canonical_owner_epoch'].__setitem__('unit', 'other.service'), 'owner_identity'),
            (lambda w: w['queries'][0]['birth'].__setitem__('born_at', w['queries'][0]['deadline']), 'monotonic_deadlines'),
            (lambda w: w['queries'][0].__setitem__('verified_at', w['queries'][0]['deadline']), 'monotonic_deadlines'),
            (lambda w: w['operations'][1].__setitem__('namespace', w['operations'][0]['namespace']), 'bootstrap_scopes'),
            (lambda w: w['operations'][0].__setitem__('up_authorized', True), 'no_authority'),
            (lambda w: w['preparation']['bootstrap'][0]['result']['policy'].__setitem__(0, 0), 'bootstrap_scopes'),
        ]
        for change, check in mutations:
            self.rejected(self.mutated(change), check)
        record = copy.deepcopy(self.record)
        record['guest_boot_id'] = '0'*36
        self.rejected(record, 'owner_identity')

    def test_missing_duplicate_and_inconsistent_rows(self):
        required = ['secret_attachment_input', 'secret_attachment_descriptor',
                    'secret_attachment_gateway', 'secret_attachment_environment',
                    'secret_attachment_owner_launcher', 'secret_attachment_controller',
                    'secret_attachment_admission', 'secret_host_baseline',
                    'secret_quarantine_host', 'owner_probe']
        for key in required:
            lines = [l for l in self.lines if not l.startswith('{"' + key + '"')]
            record = dict(self.record, stdout='\n'.join(lines)+'\n')
            self.rejected(record, 'stdout_rows')
        for key, value in [('inert_gateway_retained', False),
                           ('original_gateway_native_identity_unchanged', False),
                           ('host_links_and_stable_routes_unchanged', True),
                           ('host_single_down_link_added', False), ('owner_unit_absent', False),
                           ('host_allowed_index', 123), ('host_allowed_name', 'other')]:
            lines = list(self.lines)
            row = json.loads(lines[-1])
            row['secret_attachment_controller'][key] = value
            lines[-1] = json.dumps(row)
            self.rejected(dict(self.record, stdout='\n'.join(lines)+'\n'), 'controller_consistency')
        self.rejected(dict(self.record, stdout=self.record['stdout']+self.lines[-1]+'\n'), 'stdout_rows')

    def test_record_binding_mutations(self):
        for field in ('artifact_sha256', 'context_sha256', 'runner_sha256', 'guest_sha256',
                      'source_archive_sha256', 'context_checker_sha256'):
            self.rejected(dict(self.record, **{field: '0'*64}), 'frozen_bindings')
        record = copy.deepcopy(self.record)
        record['source_binding']['source_commit'] = '0'*40
        self.rejected(record, 'frozen_bindings')

    def test_host_admission_window_and_environment_order(self):
        self.rejected(self.mutated(lambda w: w['preparation']['host_link'][0]['admission'].__setitem__(2, 0)),
                      'monotonic_deadlines')
        record = copy.deepcopy(self.record)
        lines = list(self.lines)
        row = json.loads(lines[10])
        row['secret_attachment_environment']['after']['started_at'] = 0
        lines[10] = json.dumps(row)
        record['stdout'] = '\n'.join(lines)+'\n'
        self.rejected(record, 'controller_consistency')

    def test_birth_status_pin_and_writer_contract_mutations(self):
        mutations = [
            (lambda w: w['operations'][0].__setitem__('original_pid', 2), 'bootstrap_scopes'),
            (lambda w: w['operations'][0].__setitem__('actual_wait_status', 9), 'bootstrap_scopes'),
            (lambda w: w['preparation']['writers'][-1].__setitem__('phase', 'wrong'), 'bootstrap_scopes'),
            (lambda w: w['handoff']['resources'][0].__setitem__('fully_retired', False), 'handoff'),
            (lambda w: w['handoff']['resources'][0].__setitem__('original_pid', 2), 'handoff'),
            (lambda w: w['preparation']['bootstrap'][0]['policy'].__setitem__(0, 256), 'typed_witness'),
        ]
        for change, check in mutations:
            self.rejected(self.mutated(change), check)

    def test_fixed_arrays_and_byte_ranges_are_typed(self):
        source = self.witness['preparation']['bootstrap'][0]
        for key, value in [('request', [1]*31), ('request', [1]*31+[256]),
                           ('pins', [[1, 2, 3]]), ('pins', [[1, 2, 2**32]]*8),
                           ('scope', 'other')]:
            changed = copy.deepcopy(source)
            changed[key] = value
            with self.subTest(field=key, value=value):
                with self.assertRaises(ValueError):
                    self.m.typed(changed, 'BootstrapHistory', 'history')

    def test_result_and_request_pin_sizes_through_validate(self):
        # Same field names do not make these Rust fixed-array types identical.
        cases = [
            ('binding_result_8pins', lambda w: w['preparation']['producer_binding']['result'], 8),
            ('binding_observation_result_8pins', lambda w: w['host_addition']['producer_binding']['observation']['result'], 8),
            ('binding_request_8pins', lambda w: w['preparation']['producer_binding'], 8),
            ('binding_observation_request_8pins', lambda w: w['host_addition']['producer_binding']['observation'], 8),
            ('bootstrap_history_result_6pins', lambda w: w['preparation']['bootstrap'][0]['result'], 6),
            ('bootstrap_operation_result_6pins', lambda w: w['operations'][0]['result'], 6),
            ('bootstrap_history_request_6pins', lambda w: w['preparation']['bootstrap'][0], 6),
            ('bootstrap_operation_request_6pins', lambda w: w['operations'][0], 6),
        ]
        for name, select, size in cases:
            def change(w):
                obj = select(w)
                obj['pins'] = (obj['pins'] + [[1, 2, 3], [4, 5, 6]])[:size]
            with self.subTest(fixture=name):
                self.rejected(self.mutated(change), 'typed_witness')

    def test_preparation_success_guards_through_validate(self):
        cases = [
            ('preparation_unreaped', 'native_children_reaped', False),
            ('preparation_collected', 'member_native_jobs_collected', True),
            ('preparation_unreserved', 'service_reserved', False),
            ('preparation_fenced', 'mutation_fenced', True),
            ('preparation_pending', 'canonical_pending', True),
            ('preparation_phase', 'entry_phase', 'offline'),
            ('preparation_links', 'entry_links_absent', False),
            ('preparation_attempt', 'entry_attempt_absent', False),
            ('preparation_terminal', 'entry_terminal_absent', False),
        ]
        for name, field, value in cases:
            with self.subTest(fixture=name):
                self.rejected(self.mutated(lambda w: w['preparation'].__setitem__(field, value)),
                              'preparation_success')

    def test_retained_preparation_prefix_through_validate(self):
        # Each retained field must equal the host/handoff snapshot; no blanket
        # assertion about historical continuation or drop flags is appropriate.
        cases = [
            ('retained_prefix_birth', lambda w: w['preparation']['writers'][0], 'pid'),
            ('entry_producer', lambda w: w['preparation']['entry_producer']['parent'], 'ino'),
        ]
        for field in ('wireguard', 'netfilter', 'producer_creation', 'producer_binding',
                      'producer_binding_query', 'producer_query', 'quarantine_query',
                      'movement_query', 'inspection', 'attachment', 'fresh_transport', 'host_link'):
            def select(w, field=field):
                obj = w['preparation'][field]
                return (obj[0] if isinstance(obj, list) else obj)['birth']
            cases.append((field, select, 'pid'))
        for field in ('base_network', 'data_network', 'transport_network'):
            cases.append((field, lambda w, field=field: w['preparation'][field], 'ino'))
        cases.append(('canonical_owner_epoch', lambda w: w['preparation']['canonical_owner_epoch'], 'pid'))
        for name, select, field in cases:
            def change(w):
                obj = select(w)
                obj[field] += 1
            with self.subTest(field=name):
                self.rejected(self.mutated(change), 'preparation_success')

    def test_held_intents_bound_to_original_writers_through_validate(self):
        # Reproduce own_intent_identity/query_intent_index, plus the other
        # intent's index and both PID/start components independently.
        for intent in ('own_intent_polling', 'own_query_intent_polling'):
            for field in ('index', 'pid', 'start'):
                def change(w):
                    w[intent][field] = 0 if field == 'index' else w[intent][field] + 1
                with self.subTest(intent=intent, field=field):
                    self.rejected(self.mutated(change), 'bootstrap_success')

    def test_emitted_intent_queued_poll_count_through_validate(self):
        # bootstrap.rs:786,833 emit exactly one queued poll for each intent.
        for intent in ('own_intent_polling', 'own_query_intent_polling'):
            with self.subTest(intent=intent):
                self.rejected(self.mutated(lambda w: w[intent].__setitem__('queued_polls', 2)),
                              'bootstrap_success')

    def test_binding_result_matches_own_request_through_validate(self):
        # Keep all retained copies equal so the prefix check cannot mask a
        # same-sized result that disagrees with its own six-pin request.
        for field in ('namespace', 'group', 'policy', 'pins'):
            def change(w):
                def visit(obj):
                    if isinstance(obj, dict):
                        if all(key in obj for key in ('data', 'pins', 'result')):
                            result = obj['result']
                            if field in ('namespace', 'group'):
                                result[field]['ino'] += 1
                            elif field == 'policy':
                                result[field][0] ^= 1
                            else:
                                result[field][0][2] ^= 1
                        for item in obj.values():
                            visit(item)
                    elif isinstance(obj, list):
                        for item in obj:
                            visit(item)
                visit(w)
            with self.subTest(field=field):
                self.rejected(self.mutated(change), 'bootstrap_scopes')

    def test_original_down_host_endpoint_cannot_be_replaced(self):
        for field, value in [('addition', None), ('verified_at', None)]:
            self.rejected(self.mutated(lambda w: w['preparation']['host_link'][3].__setitem__(field, value)),
                          'typed_witness' if field == 'verified_at' else 'controller_consistency')

    def test_duplicate_unknown_nonfinite_and_malformed_json(self):
        texts = [RAW.read_text().replace('"exit_code": 0', '"exit_code": 0, "exit_code": 0', 1)]
        for bad in ('NaN', 'Infinity', '-Infinity', '1e999', 'true, "schema": 1'):
            lines = list(self.lines)
            lines[self.index] = lines[self.index].replace('"schema":1', '"schema":'+bad, 1)
            self.assertNotEqual(lines[self.index], self.lines[self.index])
            texts.append(json.dumps(dict(self.record, stdout='\n'.join(lines))))
        texts += [json.dumps(self.mutated(lambda w: w.__setitem__('unexpected', True)))]
        texts += [json.dumps(dict(self.record, stdout=self.record['stdout']+'{bad}\n'))]
        with tempfile.TemporaryDirectory(prefix='run410-json-') as tmp:
            path = Path(tmp) / 'record.json'
            for text in texts:
                path.write_text(text)
                self.assertEqual(self.m.validate(path)['verdict'], 'FAIL')

    def test_cli_exclusive_mode0600_and_optimized_refusal(self):
        with tempfile.TemporaryDirectory(prefix='run410-cli-') as tmp:
            receipt = Path(tmp) / 'receipt.json'
            command = [sys.executable, '-B', str(TOOL), str(RAW), str(receipt)]
            result = subprocess.run(command, capture_output=True, text=True, cwd=ROOT)
            self.assertEqual(result.returncode, 0, result.stderr)
            before = receipt.read_bytes()
            self.assertEqual(receipt.stat().st_mode & 0o777, 0o600)
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 1)
            self.assertEqual(receipt.read_bytes(), before)
            receipt.unlink()
            receipt.symlink_to(Path(tmp)/'absent')
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 1)
            self.assertFalse((Path(tmp)/'absent').exists())
            optimized = subprocess.run([sys.executable, '-B', '-O', str(TOOL), str(RAW)],
                                       capture_output=True, text=True)
            self.assertNotEqual(optimized.returncode, 0)
            self.assertIn('optimized_python_refused', optimized.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
