#!/usr/bin/env python3
"""Offline typed validation of the frozen run-410 successful Bootstrap witness.

No guest actions, locks, claims or imported controller code. Only an explicitly
requested receipt is written, with O_EXCL/O_NOFOLLOW and mode 0600. This validates
recorded assertions and their consistency, never current native custody.
"""
import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import sys

if not __debug__:
    raise RuntimeError('optimized_python_refused')

ROOT = Path(__file__).resolve().parents[2]
CANDIDATE = Path('target/candidates/run410-da75562-20261104/candidate.json')
RESERVATION = Path('target/lab-state/run-410-reservation.json')
CLAIM = Path('target/lab-state/run-410-consumed.json')
SOURCE_COMMIT = 'da7556282d5fc828a9391a64ab47adab05a55510'
UNIT = r'vprouter-v2-owner@[a-f0-9]{64}[.]service'
# Three scopes x (ten field mutations + three missing-value mutations):
# crates/vprouter-launch/src/owned/preparation/bootstrap.rs:855-889.
CANONICAL_NEGATIVE_CHECKS = 3 * (10 + 3)
LIMITS = [
    'No real disposable Tailscale client, traffic capture or leak acceptance.',
    'No multi-exit runtime, isolation/fault matrix or direct-mode acceptance.',
    'No ARM runtime execution or platform qualification.',
    'No performance, CPU attribution, sleep/constructor samples or speedup proof.',
    'No migration, reboot/rollback, compatibility-deployment or soak acceptance.',
    'No current guest liveness, retained native custody or post-run live identity proof.',
    'No operational UP, placement, health READY, resource cleanup or requirement 8 completion.',
]

# The generated source contract is the sole type/enum/array authority.
CONTRACT_PATH = Path(__file__).with_name('witness-contract.json')
CONTRACT_BYTES = CONTRACT_PATH.read_bytes()
CONTRACT = json.loads(CONTRACT_BYTES)
CONTRACT_SHA256 = hashlib.sha256(CONTRACT_BYTES).hexdigest()
VALIDATOR_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
EXTRACTOR_SHA256 = hashlib.sha256(CONTRACT_PATH.with_name('witness-contract-extract.py').read_bytes()).hexdigest()
_EXTRACTOR_SPEC=importlib.util.spec_from_file_location('run410_contract_extractor',CONTRACT_PATH.with_name('witness-contract-extract.py'))
EXTRACTOR=importlib.util.module_from_spec(_EXTRACTOR_SPEC)
_EXTRACTOR_SPEC.loader.exec_module(EXTRACTOR)

SCHEMAS = CONTRACT['schemas']
ENUMS = CONTRACT['enums']
INTEGER_RANGES = {**{f'u{bits}': (0, 2**bits-1) for bits in (8,16,32,64)},
                  **{f'i{bits}': (-2**(bits-1),2**(bits-1)-1) for bits in (8,16,32,64)},
                  'usize': (0,2**CONTRACT['target_pointer_width']-1),
                  'isize': (-2**(CONTRACT['target_pointer_width']-1),2**(CONTRACT['target_pointer_width']-1)-1)}


# Predicate IDs are exact; no function/file-wide inheritance of coverage.
# Prior r5's 178 "enforced" IDs and 3,200 blanket offline IDs are retired.
# Unreviewed lineage/semantics stays pending and withholds the full claim.
PREDICATE_CHECKS = {'0df26af51ab07703279b': {'check_ids': ['host_observation_bounds'],
                          'projection_proof': 'HostBaseline/HostObservation complete namespace and public '
                                              'vector/string/TUN bounds, preserving quantifier context.'},
 '174fc9cdeafd09c23620': {'check_ids': ['baseline_consistency', 'allocation_contract', 'contract_success'],
                          'projection_proof': 'Serialized public declaration and allocation; canonical '
                                              'digest recomputed; full WAN predicate applied.'},
 '189fb825268a7848d90c': {'check_ids': ['baseline_consistency', 'allocation_contract', 'contract_success'],
                          'projection_proof': 'Serialized public declaration and allocation; canonical '
                                              'digest recomputed; full WAN predicate applied.'},
 '18a6bd9f2eb7ac520c83': {'check_ids': ['host_observation_bounds'],
                          'projection_proof': 'HostBaseline/HostObservation complete namespace and public '
                                              'vector/string/TUN bounds, preserving quantifier context.'},
 '1c84c14a78aaaf24a19b': {'check_ids': ['contract_success'],
                          'projection_proof': 'Link.index is copied from m.header.index; WG peer_index is '
                                              'retained unchanged by ownership-alias marking.'},
 '1d7723d139a47fbc0689': {'check_ids': ['baseline_consistency', 'allocation_contract', 'contract_success'],
                          'projection_proof': 'Serialized public declaration and allocation; canonical '
                                              'digest recomputed; full WAN predicate applied.'},
 '27dffc5cc205d5a9a2e3': {'check_ids': ['recorded_emitters'],
                          'projection_proof': 'Necessary six-pin expected-group mode projection under the '
                                              'preceding native fstat triple equality; no fstat replay '
                                              'claimed.'},
 '281eb7f32266024621f1': {'check_ids': ['host_observation_bounds'],
                          'projection_proof': 'HostBaseline/HostObservation complete namespace and public '
                                              'vector/string/TUN bounds, preserving quantifier context.'},
 '2b5996af901fc1d48d99': {'check_ids': ['baseline_consistency', 'allocation_contract', 'contract_success'],
                          'projection_proof': 'Serialized public declaration and allocation; canonical '
                                              'digest recomputed; full WAN predicate applied.'},
 '49189111d51923f14cb3': {'check_ids': ['host_observation_bounds'],
                          'projection_proof': 'HostBaseline/HostObservation complete namespace and public '
                                              'vector/string/TUN bounds, preserving quantifier context.'},
 '4b967c4a190e596069f1': {'check_ids': ['baseline_consistency', 'allocation_contract', 'contract_success'],
                          'projection_proof': 'Serialized public declaration and allocation; canonical '
                                              'digest recomputed; full WAN predicate applied.'},
 '4bb4e02af9996f098b46': {'check_ids': ['contract_success'],
                          'projection_proof': 'Serialized original WG/veth Link; these fields are unchanged '
                                              'by native ownership-alias marking.'},
 '5409a4644ddeeaa8d0e4': {'check_ids': ['baseline_consistency', 'allocation_contract', 'contract_success'],
                          'projection_proof': 'Serialized public declaration and allocation; canonical '
                                              'digest recomputed; full WAN predicate applied.'},
 '58a37ac8bd9cba1d4b5e': {'check_ids': ['host_observation_bounds'],
                          'projection_proof': 'HostBaseline/HostObservation complete namespace and public '
                                              'vector/string/TUN bounds, preserving quantifier context.'},
 '595abe5f1b2aceb3a46b': {'check_ids': ['baseline_consistency', 'allocation_contract', 'contract_success'],
                          'projection_proof': 'Serialized public declaration and allocation; canonical '
                                              'digest recomputed; full WAN predicate applied.'},
 '5d782b5ab3f56cea23b6': {'check_ids': ['host_observation_bounds'],
                          'projection_proof': 'HostBaseline/HostObservation complete namespace and public '
                                              'vector/string/TUN bounds, preserving quantifier context.'},
 '6203fb73943d6ed610b0': {'check_ids': ['baseline_consistency', 'allocation_contract', 'contract_success'],
                          'projection_proof': 'Serialized public declaration and allocation; canonical '
                                              'digest recomputed; full WAN predicate applied.'},
 '6605a6920812640e8be8': {'check_ids': ['host_observation_bounds'],
                          'projection_proof': 'HostBaseline/HostObservation complete namespace and public '
                                              'vector/string/TUN bounds, preserving quantifier context.'},
 '69f97ad4042afc0bfc8a': {'check_ids': ['contract_success'],
                          'projection_proof': 'Serialized original WG/veth Link; these fields are unchanged '
                                              'by native ownership-alias marking.'},
 '6aa0fdff0aac04f01d01': {'check_ids': ['contract_success'],
                          'projection_proof': 'Serialized original WG/veth Link; these fields are unchanged '
                                              'by native ownership-alias marking.'},
 '705b76140fbce87e8113': {'check_ids': ['host_observation_bounds'],
                          'projection_proof': 'HostBaseline/HostObservation complete namespace and public '
                                              'vector/string/TUN bounds, preserving quantifier context.'},
 '7181849b73f3ba2ab893': {'check_ids': ['contract_success'],
                          'projection_proof': 'Serialized original WG/veth Link; these fields are unchanged '
                                              'by native ownership-alias marking.'},
 '742acfbb590976810451': {'check_ids': ['baseline_consistency', 'allocation_contract', 'contract_success'],
                          'projection_proof': 'Serialized public declaration and allocation; canonical '
                                              'digest recomputed; full WAN predicate applied.'},
 '80917945bf0b541fef17': {'check_ids': ['baseline_consistency', 'allocation_contract', 'contract_success'],
                          'projection_proof': 'Serialized public declaration and allocation; canonical '
                                              'digest recomputed; full WAN predicate applied.'},
 '877c79dae70246045f06': {'check_ids': ['host_observation_bounds'],
                          'projection_proof': 'HostBaseline/HostObservation complete namespace and public '
                                              'vector/string/TUN bounds, preserving quantifier context.'},
 '88f0d880b81419ef46e3': {'check_ids': ['host_observation_bounds'],
                          'projection_proof': 'HostBaseline/HostObservation complete namespace and public '
                                              'vector/string/TUN bounds, preserving quantifier context.'},
 '8de1b1217bfc9647313b': {'check_ids': ['contract_success'],
                          'projection_proof': 'Serialized original WG/veth Link; these fields are unchanged '
                                              'by native ownership-alias marking.'},
 '8e86d38dcde823037621': {'check_ids': ['baseline_consistency', 'allocation_contract', 'contract_success'],
                          'projection_proof': 'Serialized public declaration and allocation; canonical '
                                              'digest recomputed; full WAN predicate applied.'},
 '8eb5f21fcb51977b6207': {'check_ids': ['contract_success'],
                          'projection_proof': 'Serialized original WG/veth Link; these fields are unchanged '
                                              'by native ownership-alias marking.'},
 '9255b33211650f65d358': {'check_ids': ['contract_success'],
                          'projection_proof': 'Serialized original WG/veth Link; these fields are unchanged '
                                              'by native ownership-alias marking.'},
 '9a9b7fdc4f89724ef5b8': {'check_ids': ['baseline_consistency', 'allocation_contract', 'contract_success'],
                          'projection_proof': 'Serialized public declaration and allocation; canonical '
                                              'digest recomputed; full WAN predicate applied.'},
 'a33695bdf5772e1c6ea4': {'check_ids': ['baseline_consistency', 'allocation_contract', 'contract_success'],
                          'projection_proof': 'Serialized public declaration and allocation; canonical '
                                              'digest recomputed; full WAN predicate applied.'},
 'a715e3b6511ddca36e94': {'check_ids': ['baseline_consistency', 'allocation_contract', 'contract_success'],
                          'projection_proof': 'Serialized public declaration and allocation; canonical '
                                              'digest recomputed; full WAN predicate applied.'},
 'af93a4df5a610d2e4583': {'check_ids': ['baseline_consistency', 'allocation_contract', 'contract_success'],
                          'projection_proof': 'Serialized public declaration and allocation; canonical '
                                              'digest recomputed; full WAN predicate applied.'},
 'b68c92ed64dd276d2f9a': {'check_ids': ['baseline_consistency', 'allocation_contract', 'contract_success'],
                          'projection_proof': 'Serialized public declaration and allocation; canonical '
                                              'digest recomputed; full WAN predicate applied.'},
 'bc38d4da0d591e6ef705': {'check_ids': ['baseline_consistency', 'allocation_contract', 'contract_success'],
                          'projection_proof': 'Serialized public declaration and allocation; canonical '
                                              'digest recomputed; full WAN predicate applied.'},
 'bc6d5d798292ec5b6c99': {'check_ids': ['recorded_emitters'],
                          'projection_proof': 'Necessary six-pin expected-group mode projection under the '
                                              'preceding native fstat triple equality; no fstat replay '
                                              'claimed.'},
 'be7a10b85d65230129c7': {'check_ids': ['contract_success'],
                          'projection_proof': 'Serialized original WG/veth Link; these fields are unchanged '
                                              'by native ownership-alias marking.'},
 'ca3f7cd71b82cc76e868': {'check_ids': ['contract_success'],
                          'projection_proof': 'Link.index is copied from m.header.index; WG peer_index is '
                                              'retained unchanged by ownership-alias marking.'},
 'cf14d0e17c320e6b0f3f': {'check_ids': ['host_observation_bounds'],
                          'projection_proof': 'HostBaseline/HostObservation complete namespace and public '
                                              'vector/string/TUN bounds, preserving quantifier context.'},
 'd1d06eaace8c847f7276': {'check_ids': ['host_observation_bounds'],
                          'projection_proof': 'HostBaseline/HostObservation complete namespace and public '
                                              'vector/string/TUN bounds, preserving quantifier context.'},
 'd29468d858334bbe5d28': {'check_ids': ['baseline_consistency', 'allocation_contract', 'contract_success'],
                          'projection_proof': 'Serialized public declaration and allocation; canonical '
                                              'digest recomputed; full WAN predicate applied.'},
 'e05cb7ecffd20753a083': {'check_ids': ['host_observation_bounds'],
                          'projection_proof': 'HostBaseline/HostObservation complete namespace and public '
                                              'vector/string/TUN bounds, preserving quantifier context.'},
 'fac2e6ecbb9e75ba9efb': {'check_ids': ['contract_success'],
                          'projection_proof': 'Serialized original WG/veth Link; these fields are unchanged '
                                              'by native ownership-alias marking.'},
 'fc6fafb473083b5c9ca3': {'check_ids': ['baseline_consistency', 'allocation_contract', 'contract_success'],
                          'projection_proof': 'Serialized public declaration and allocation; canonical '
                                              'digest recomputed; full WAN predicate applied.'}}

def require(condition, reference):
    if not condition:
        raise ValueError(reference)


def guard_dispositions(guards=None):
    guards = CONTRACT['guards'] if guards is None else guards
    require({g['id'] for g in guards} == {g['id'] for g in CONTRACT['guards']},
            'unmapped/stale guard inventory')
    require(len(guards) == len({g['id'] for g in guards}), 'duplicate extracted guard')
    result = {}; seen = set()
    for guard in guards:
        predicates={}
        for predicate in guard['predicates']:
            identity=predicate['id']
            require(identity not in seen, 'duplicate predicate disposition: '+identity)
            seen.add(identity)
            decision=EXTRACTOR.predicate_decidability(predicate,CONTRACT)
            if identity in PREDICATE_CHECKS:
                mapping=PREDICATE_CHECKS[identity]
                require(decision['status']=='serialized_projection', 'enforced predicate without serialized projection lineage')
                require(not predicate.get('syntax_unresolved'), 'cannot enforce opaque Rust syntax')
                require(all(callable(globals().get(k)) for k in mapping['check_ids']), 'predicate check missing')
                row=dict(status='enforced',**mapping)
            elif decision['status']=='absent_value':
                require(decision['absence_proofs'], 'offline predicate without absence proof')
                row=dict(status='unenforceable_offline',reason='Explicit live operand absent; see absence certificate.')
            else:
                row=dict(status='pending',reason='Serialized lineage or predicate implementation not proved; never treated as offline.')
            row['decidability']=decision
            predicates[identity]=row
        skipped=[key for key,p in predicates.items() if p['status']!='enforced']
        result[guard['id']]=dict(status='partial' if skipped else 'enforced',
                                predicates=predicates,skipped_predicates=skipped)
    require(set(PREDICATE_CHECKS) <= seen, 'stale predicate enforcement mapping')
    require(set(CONTRACT.get('predicate_lineage', {})) <= seen, 'stale predicate lineage mapping')
    return result


def contract_guards():
    # Inventory integrity is distinct from complete semantic validation.
    require(not CONTRACT['call_graph']['unresolved'], 'unresolved lexical validation callee')
    require(GUARD_COUNTS['extracted'] == len(CONTRACT['guards']), 'contract guard count drift')
    require(PREDICATE_COUNTS['extracted'] == sum(PREDICATE_COUNTS[k]
            for k in ('enforced','unenforceable_offline','pending')), 'predicate accounting incomplete')



def strict_json(data):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, 'duplicate JSON key: ' + key)
            value[key] = item
        return value

    def nonfinite(token):
        raise ValueError('nonfinite JSON number: ' + token)

    def finite_float(token):
        value = float(token)
        require(math.isfinite(value), 'nonfinite JSON number: ' + token)
        return value

    return json.loads(data, object_pairs_hook=pairs, parse_constant=nonfinite,
                      parse_float=finite_float)


def alternatives(spec):
    depth = start = 0
    for index, char in enumerate(spec):
        if char == '(':
            depth += 1
        elif char == ')':
            depth -= 1
        elif char == '|' and depth == 0:
            yield spec[start:index]
            start = index + 1
    yield spec[start:]


SHAPES = {tuple(sorted(fields)): name for name, fields in SCHEMAS.items()}


def split_contract_types(spec):
    result,depth,start = [],0,0
    for i,c in enumerate(spec):
        if c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
        elif c == ',' and depth == 0:
            result.append(spec[start:i])
            start = i+1
    result.append(spec[start:])
    return result


def contract_leaves(value, spec='BootstrapWitness', path=()):
    """Type every leaf by traversing declared contract edges, never key names."""
    if '|' in spec:
        choices = list(alternatives(spec))
        if value is None:
            # Retain optional scalar width even for absent values.
            spec = next((s for s in choices if s != 'null'),'null')
        else:
            candidates = [s for s in choices if s in SCHEMAS and type(value) is dict]
            spec = min(candidates,key=lambda s:len(set(value).symmetric_difference(SCHEMAS[s]))) if candidates else next(s for s in choices if s != 'null')
    if spec in SCHEMAS and type(value) is dict:
        for key,child in SCHEMAS[spec].items():
            if key in value:
                yield from contract_leaves(value[key],child,path+(key,))
    elif (spec.startswith(('array(','list(','tuple(')) or spec in CONTRACT['aliases']) and type(value) is list:
        if spec in CONTRACT['aliases']:
            yield from contract_leaves(value,CONTRACT['aliases'][spec],path)
            return
        if not value:
            yield path,spec
            return
        if spec.startswith('array('):
            _,child = split_contract_types(spec[6:-1]); children = [child]*len(value)
        elif spec.startswith('tuple('):
            children = split_contract_types(spec[6:-1])
        else:
            children = [spec[5:-1]]*len(value)
        for i,(item,child) in enumerate(zip(value,children)):
            yield from contract_leaves(item,child,path+(i,))
    else:
        yield path,spec


def typed(value, spec, path):
    choices = list(alternatives(spec)) if '|' in spec else [spec]
    if len(choices) > 1:
        for choice in choices:
            try:
                typed(value, choice, path)
                return
            except ValueError:
                pass
        raise ValueError(path + ': expected ' + spec)
    if spec in SCHEMAS:
        fields = SCHEMAS[spec]
        require(type(value) is dict, path + ': expected object ' + spec)
        if value.keys() != fields.keys():
            raise ValueError(path + ': missing=' + ','.join(sorted(set(fields)-set(value))) +
                             '; unknown=' + ','.join(sorted(set(value)-set(fields))))
        for key, item in value.items():
            typed(item, fields[key], path + '.' + key)
    elif spec.startswith('array(') or spec.startswith('tuple('):
        parts = split_contract_types(spec[spec.index('(')+1:-1])
        if spec.startswith('array('):
            size,child = parts
            children = [child]*int(size)
        else:
            children = parts
        require(type(value) is list and len(value) == len(children),path+': expected '+spec)
        for i,(item,child) in enumerate(zip(value,children)):
            typed(item,child,path+'['+str(i)+']')
    elif spec.startswith('list('):
        require(type(value) is list, path + ': expected array')
        for index, item in enumerate(value):
            typed(item, spec[5:-1], path + '[' + str(index) + ']')
    elif spec in CONTRACT['aliases']:
        typed(value,CONTRACT['aliases'][spec],path)
    elif spec in ('ip', 'ipv4_text', 'socket_address'):
        import ipaddress
        require(type(value) is str, path + ': IpAddr')
        if spec == 'socket_address':
            address, port = value.rsplit(':', 1)
            require(port.isascii() and port.isdecimal() and 0 <= int(port) <= 65535, path + ': port u16')
            if address.startswith('[') and address.endswith(']'):
                ipaddress.IPv6Address(address[1:-1])
            else:
                ipaddress.IPv4Address(address)
        else:
            parsed = ipaddress.ip_address(value)
            require(spec != 'ipv4_text' or parsed.version == 4, path + ': IPv4 address')
    elif spec in ENUMS:
        require(type(value) is str and value in ENUMS[spec], path + ': ' + spec + ' enum')
    elif spec in INTEGER_RANGES:
        lo, hi = INTEGER_RANGES[spec]
        require(type(value) is int and lo <= value <= hi, path + ': expected ' + spec)
    elif spec == 'f64':
        require(type(value) in (int, float) and math.isfinite(value) and value >= 0,
                path + ': expected finite nonnegative f64')
    else:
        valid = ((spec == 'null' and value is None) or
                 (spec == 'bool' and type(value) is bool) or
                 (spec == 'str' and type(value) is str) or
                 (spec == 'empty' and type(value) is list and not value))
        require(valid, path + ': expected ' + spec)



def typed_object(value, shape, path):
    require(shape in SHAPES, path + ': unknown object schema')
    typed(value, SHAPES[shape], path)


def objects(value, path='witness'):
    if type(value) is dict:
        yield path, value
        for key, item in value.items():
            yield from objects(item, path + '.' + key)
    elif type(value) is list:
        for index, item in enumerate(value):
            yield from objects(item, path + '[' + str(index) + ']')


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode()


def stdout_rows(record):
    rows = {}
    witness = None
    expected = ['secret_attachment_build_exit', 'secret_attachment_input',
                'secret_attachment_admission', 'secret_attachment_admission',
                'secret_attachment_descriptor', 'secret_quarantine_host',
                'secret_host_baseline', 'secret_attachment_gateway', 'owner_probe',
                'secret_attachment_owner_launcher', 'secret_attachment_environment',
                'case', 'LAB_SECRET_BOOTSTRAP', 'secret_attachment_controller']
    lines = record['stdout'].splitlines()
    require(len(lines) == len(expected), 'stdout: expected exactly 14 ordered lines')
    references = {}
    for number, (line, key) in enumerate(zip(lines, expected), 1):
        if key == 'LAB_SECRET_BOOTSTRAP':
            require(line.startswith(key + ' '), 'stdout line ' + str(number) + ': witness prefix')
            witness = strict_json(line.split(' ', 1)[1])
        else:
            row = strict_json(line)
            require(type(row) is dict and key in row, 'stdout line ' + str(number) + ': ' + key)
            shape = tuple(sorted(row))
            typed_object(row, shape, 'stdout[' + str(number) + ']')
            require(set(row) == ({'case', 'result'} if key == 'case' else {key}),
                    'stdout line ' + str(number) + ': extra row keys')
            rows.setdefault(key, []).append(row if key == 'case' else row[key])
        references.setdefault(key, []).append(number)
    return witness, rows, references


def frozen_bindings(record):
    # The original reservation binds all 34 inputs, including the archive
    # manifest and both controller programs. Do not import or execute them.
    reservation_bytes = (ROOT / RESERVATION).read_bytes()
    require(hashlib.sha256(reservation_bytes).hexdigest() ==
            'b080960ec82c23bfe9f802e033886bb75b5fc288b4e56df336b400c57a369140',
            'reservation frozen SHA256')
    reservation = strict_json(reservation_bytes)
    require(reservation['run'] == 410 and reservation['candidate'] == str(CANDIDATE)
            and reservation['mode'] == 'success' and reservation['one_shot_budget'] == 1,
            'reservation run/candidate/mode/budget')
    seen = set()
    for binding in reservation['bindings']:
        relative = Path(binding['path'])
        require(not relative.is_absolute() and '..' not in relative.parts,
                'reservation binding outside repository')
        require(str(relative) not in seen, 'duplicate reservation binding')
        seen.add(str(relative))
        retained = ROOT/'target/run410-evidence/files'/relative
        historical = retained if str(relative) in (
            'tools/rust-v2-lab/fresh-baseline.py',
            'tools/rust-v2-lab/phase3-readonly-preflight.py') else ROOT/relative
        require(sha(historical) == binding['sha256'], 'reservation historical binding: '+str(historical))
    require(len(seen) == 34, 'reservation: 34 mandatory bindings')
    candidate = strict_json((ROOT / CANDIDATE).read_bytes())
    require(candidate['source_commit'] == SOURCE_COMMIT, 'candidate.source_commit')
    require(record['source_binding'] == candidate['binding'], 'record.source_binding')
    require(record['source_binding']['source_commit'] == SOURCE_COMMIT, 'record source commit')
    require(record['source_archive_sha256'] == candidate['source_sha256'] ==
            sha(ROOT / CANDIDATE.parent / 'source.tar'),
            'record.source_archive_sha256')
    for key, name in [('artifact_sha256', 'amd64.payload'), ('context_sha256', 'amd64.context.tar')]:
        require(record[key] == candidate['platforms']['amd64'][key] == sha(ROOT / CANDIDATE.parent / name),
                'record.' + key)
    directory = ROOT / CANDIDATE.parent / reservation['label']
    for key, original, retained in [
        ('runner_sha256', 'run-frozen-secret-bootstrap410.py', 'controller-runner.py'),
        ('guest_sha256', 'secret-bootstrap.guest.py', 'controller-guest.py'),
        ('context_checker_sha256', 'attachment_context_check.py', 'controller-context.py'),
        ('host_declaration_builder_sha256', 'quarantine_host_declaration.py', 'controller-host-declaration.py'),
        ('baseline_declaration_builder_sha256', 'host_baseline_declaration.py', 'controller-baseline-declaration.py'),
    ]:
        require(record[key] == sha(ROOT / 'target/platform-lab' / original) == sha(directory / retained),
                'record.' + key + ': original/retained bytes')
    for key, original, retained in [
        ('host_baseline_template_sha256', 'authored-host-baseline-debian-clean-x86_64.json', 'controller-authored-baseline.json'),
        ('baseline_reconciliation_sha256', 'host-baseline-reconciliation-debian-clean-x86_64.json', 'controller-baseline-reconciliation.json'),
    ]:
        require(record[key] == sha(ROOT / CANDIDATE.parent / original) == sha(directory / retained), 'record.' + key)
    require(record['platform'] == reservation['platform'] == 'debian-clean-x86_64', 'record.platform')
    require(record['run_reservation'] == dict(path=str(RESERVATION), sha256=hashlib.sha256(reservation_bytes).hexdigest(),
            claim=str(CLAIM), continuity='fresh-lab', historical_raw_records_recovered=False), 'record.run_reservation')
    claim = strict_json((ROOT / CLAIM).read_bytes())
    require(claim['reservation'] == str(RESERVATION) and claim['reservation_sha256'] == sha(ROOT / RESERVATION)
            and type(claim['run']) is int and claim['run'] == 410
            and type(claim['budget_remaining']) is int and claim['budget_remaining'] == 0
            and claim['controller_boot_id'] == reservation['controller_boot_id'], 'consumed claim binding/budget')
    require(record['guest_boot_id'] == reservation['guest_boot_id'], 'record.guest_boot_id / reservation')


def bootstrap_success(w, record):
    require(w['schema'] == 1 and w['fault'] == 0, 'witness.schema/fault')
    for key in ('failed_constructor', 'failure_retry', 'retained_result_writer'):
        require(w[key] is None, 'witness.' + key + ' must be null on success')
    for key in ('bootstrap_all_scopes_acknowledged', 'bootstrap_context_created', 'parent_pristine',
                'whole_chain_retained_after_drop', 'original_nine_contexts_retained_after_drop',
                'operational_context_retained_after_drop', 'bootstrap_context_retained_after_drop'):
        require(w[key] is True, 'witness.' + key)
    require(w['canonical_negative_checks'] == CANONICAL_NEGATIVE_CHECKS, 'witness.canonical_negative_checks: expected 39')
    require(w['result_writer_held'] is False, 'witness.result_writer_held')
    require(record['exit_code'] == 0 and record['result'] == 'PASS_PARTIAL_SECRET_BOOTSTRAP'
            and record['component_test_mode'] == 'secret_bootstrap_success', 'record success classification')
    for key, negatives, index in [('own_intent_polling', 12, 90), ('own_query_intent_polling', 6, 87)]:
        intent = w[key]
        require(intent['held_pending_polls'] == 2 and intent['negative_checks'] == negatives
                and intent['released'] is True and intent['queued_polls'] == 1, 'witness.' + key)
        writer = w['preparation']['writers'][index]
        require(intent['index'] == index and intent['pid'] == writer['pid']
                and intent['start'] == writer['start'] and writer['actual_wait_status'] == 0
                and writer['verified_at'] is not None, 'witness.' + key + ': original intent writer')


def preparation_success(w):
    # attachment/operational/bootstrap.rs:1028-1069, specialized to fault=0.
    # These checks concern the final preparation. Earlier snapshots keep their
    # original continuation/drop flags; only the listed fields are retained.
    p, host = w['preparation'], w['host_addition']['preparation']
    for key in ('native_children_reaped', 'service_reserved', 'entry_links_absent',
                'entry_attempt_absent', 'entry_terminal_absent'):
        require(p[key] is True, 'preparation.' + key)
    for key in ('member_native_jobs_collected', 'canonical_pending', 'mutation_fenced'):
        require(p[key] is False, 'preparation.' + key)
    require(p['entry_phase'] == 'creating', 'preparation.entry_phase')
    require(p['entry_producer'] == host['entry_producer'], 'preparation.entry_producer: unchanged host prefix')
    require(len(p['writers']) == 105 and len(host['writers']) == 87
            and p['writers'][:87] == host['writers'], 'preparation.writers: unchanged 87-writer host prefix')
    for key in ('wireguard', 'netfilter', 'producer_creation', 'producer_binding',
                'producer_binding_query', 'producer_query', 'quarantine_query',
                'movement_query', 'inspection', 'attachment', 'fresh_transport', 'host_link',
                'base_network', 'data_network', 'transport_network', 'canonical_owner_epoch'):
        require(p[key] == host[key], 'preparation.' + key + ': unchanged host prefix')


def charge_conservation(w):
    for key in ('charges_before_drop', 'charges_after_drop'):
        require(w[key] == [3, 3], 'witness.' + key + ': expected [3,3]')
    require(w['handoff']['charges_before'] == [5, 5] and w['handoff']['charges_after'] == [0, 0],
            'witness.handoff charges: expected [5,5] -> [0,0]')


def handoff(w):
    h = w['handoff']
    require(h['complete'] is True and h['complete_original_job_set'] == 20
            and h['historical_original_jobs'] == 15 and h['retired_suffix_jobs'] == 5
            and h['repeat_retirement_refusals'] == 5 and h['global_child_capacity_limit'] == 64,
            'witness.handoff: complete 20 = 15 historical + 5 suffix')
    require(h['duplicate_reservation'] is None and h['fence_counts'] is None
            and h['resources_collected'] is False, 'handoff: no failure reservation/cleanup')
    r = h['reservation']
    require(r['original_jobs'] == 15 and r['suffix_jobs'] == 5 and r['suffix_complete'] is True
            and r['suffix_failed'] is False and r['member_transfer_pending'] is False
            and r['global_transferred_ticket_limit'] == 2560 and r['member'] == w['preparation']['member'],
            'handoff.reservation: completed original job set')
    resources = h['resources']
    require(len(resources) == 5 and [a['kind'] for a in resources] == ['FixedNetfilter'] + ['FixedVeth']*4,
            'handoff.resources: five original suffix jobs')
    expected = [w['host_addition']['producer_binding']['observation']] + w['host_addition']['operations']
    identities = set()
    for resource, original in zip(resources, expected):
        identity = (resource['original_pid'], resource['original_start'])
        require(identity == (original['original_pid'], original['original_start']) and identity not in identities,
                'handoff.resources: original job identities')
        identities.add(identity)
        require(resource['actual_wait_status'] == 0 and resource['native_job_state'] == 'transferred_resources',
                'handoff.resources: actual status/state')
        for key in ('fully_retired', 'launch_charge_retired', 'lower_charge_required', 'lower_charge_retired',
                    'lower_gated_retirement_refused', 'transfer_started'):
            require(resource[key] is True, 'handoff.resources.' + key)
    require(h['preparation'] == w['host_addition']['preparation'], 'handoff.preparation: unchanged host prefix')


def no_authority(w, record, rows):
    for path, obj in objects(w):
        for key, value in obj.items():
            if key.endswith('_authorized') or key in ('multi_exit_runtime_proven', 'requirement8_complete'):
                require(value is False, path + '.' + key + ': authority must remain false')
    require(record['real_client_acceptance'] == 'NOT_RUN' and record['production_changes'] is False
            and record['provider_profiles_used'] is False and record['namespace_or_container_fixture'] is True
            and record['actual_gateway_is_inert'] is True, 'record component-only scope')
    descriptor = rows['secret_attachment_descriptor'][0]
    for key in ('profile_contents_read', 'docker_queried', 'container_mounts_allowed', 'production_startup_authorized'):
        require(descriptor[key] is False, 'descriptor.' + key)
    for key in ('secret_host_baseline', 'secret_quarantine_host'):
        require(rows[key][0]['host_authority_granted'] is False, key + '.host_authority_granted')


def owner_identity(w, record, rows):
    epoch = w['preparation']['canonical_owner_epoch']
    require(re.fullmatch(UNIT, epoch['unit']) is not None, 'witness canonical owner unit pattern')
    require(epoch['boot'] == record['guest_boot_id'], 'witness canonical owner boot / record.guest_boot_id')
    require(re.fullmatch(r'[a-f0-9-]{36}', epoch['boot']) is not None and epoch['pid'] > 1 and epoch['start'] > 0,
            'owner boot/pid/start')
    require(epoch['cgroup']['ino'] > 0 and re.fullmatch(r'[a-f0-9]{32}', epoch['invocation']) is not None
            and epoch['invocation'] != '0'*32, 'owner cgroup/invocation')
    require(rows['owner_probe'][0]['unit'] == rows['secret_attachment_descriptor'][0]['owner_unit'] == epoch['unit'],
            'owner_probe/descriptor/canonical owner unit')
    for path, obj in objects(w):
        if set(obj) == set(SCHEMAS['OwnerEpoch']):
            require(obj == epoch, path + ': original canonical owner epoch')
    env = rows['secret_attachment_environment'][0]
    for key in ('before', 'after'):
        require(env[key]['files']['boot']['status'] == 'bounded'
                and env[key]['files']['boot']['text'].strip() == epoch['boot'], 'environment.' + key + ': boot')


def monotonic_deadlines(w):
    for path, obj in objects(w):
        if type(obj.get('admission')) is list:
            admission = obj['admission']
            require(len(admission) == 3 and 0 < admission[0] <= admission[2] < admission[1]
                    and admission[1] == admission[0] + 2.
                    and admission[2] <= obj['requested_at'], path + ': original host admission window')
        if 'born_at' in obj:
            require(0 <= obj['born_at'] < obj['deadline'], path + ': born_at < deadline')
            require(obj['pid'] > 1 and obj['start'] > 0, path + ': native birth identity')
        if 'requested_at' in obj and 'deadline' in obj:
            start, end = obj['requested_at'], obj['deadline']
            require(0 <= start < end and end == start + 2., path + ': original two-second request window')
            birth = obj.get('birth')
            if birth is not None:
                require(start <= birth['born_at'] < end and birth['deadline'] == end, path + '.birth: original window')
            previous = birth['born_at'] if birth is not None else start
            for key in ('mounted_at', 'published_at', 'verified_at', 'accepted_at'):
                if obj.get(key) is not None:
                    require(previous <= obj[key] < end, path + '.' + key + ': within original window')
                    previous = obj[key]
            result = obj.get('result')
            if type(result) is dict and result.get('observed_at') is not None:
                require((birth['born_at'] if birth is not None else start) <= result['observed_at'] <= previous < end,
                        path + '.result.observed_at: born <= observed <= verified < deadline')
        if 'io_deadline' in obj:
            require(0 <= obj['queued_at'] <= obj['verified_at'] < obj['io_deadline'] <= obj['parent_deadline'],
                    path + ': queued <= verified < io_deadline <= parent_deadline')
    times = w['scope_process_verified_at']
    require(len(times) == 3 and times == sorted(times) and w['final_process_verified_at'] == times[-1],
            'witness.scope_process_verified_at/final_process_verified_at')
    for index, at in enumerate(times):
        query = w['queries'][index]
        writer = w['preparation']['writers'][87 + index * 6 + 5]
        require(writer['verified_at'] <= at < query['deadline'], 'scope process verification before original deadline')


def bootstrap_scopes(w, rows):
    p = w['preparation']
    # Canonical producer-binding validation (producer_binding.rs:114-130)
    # applies to its retained histories and original operation evidence too.
    binding_shapes = [set(SCHEMAS[name]) for name in ('ProducerBindingHistory', 'ProducerObservation')]
    for path, obj in objects(w):
        if set(obj) in binding_shapes:
            result = obj['result']
            require(result['namespace'] == obj['data'] and result['group'] == obj['group']
                    and result['policy'] == obj['policy'] and result['pins'] == obj['pins'],
                    path + ': producer-binding result identity/policy/six pins')
    require(len(w['operations']) == len(w['queries']) == len(p['bootstrap']) == len(p['bootstrap_queries']) == 3,
            'three Bootstrap scopes/queries/histories')
    require(len(p['writers']) == 105 and len(p['netfilter']) == 6 and len(p['host_link']) == 4,
            'canonical preparation: 105 writers / six policies / four host operations')
    previous = p['host_link'][3]['verified_at']
    scopes = [('host', rows['secret_attachment_gateway'][0]['host_network_namespace']),
              ('transport', [p['transport_network']['dev'], p['transport_network']['ino']]),
              ('data', [p['data_network']['dev'], p['data_network']['ino']])]
    for index, (scope, ns) in enumerate(scopes):
        op, q, h, qh = w['operations'][index], w['queries'][index], p['bootstrap'][index], p['bootstrap_queries'][index]
        identity = dict(dev=ns[0], ino=ns[1])
        require(op['scope'] == h['scope'] == scope and op['namespace'] == h['namespace'] == identity,
                'Bootstrap scope/namespace: ' + scope)
        require(qh['initial'] is None, 'Bootstrap query forbids initial evidence')
        require(q['kind'] == qh['kind'] == 'Bootstrap' + scope.title() + 'Recheck', 'query kind: ' + scope)
        for key in ('birth', 'requested_at', 'deadline', 'facts', 'verified_at'):
            require(q[key] == qh[key], 'query canonical history.' + key)
        require(q['facts']['pid'] == rows['secret_attachment_gateway'][0]['pid']
                and q['facts']['security'] == 'AppArmorBuiltinSeccomp', 'query original gateway PID/security')
        require(q['actual_wait_status'] == 0 and q['original_peer_receipt'] is True
                and q['handler_identity_claimed'] is False and q['listener_origin_pid'] == 1
                and q['listener_origin_uid'] == q['listener_origin_gid'] == 0, 'original Docker query receipt')
        for key in ('birth', 'requested_at', 'deadline', 'namespace', 'scope', 'request', 'query', 'policy', 'pins', 'group', 'result'):
            require(op[key] == h[key], 'Bootstrap operation/canonical history.' + key)
        require(op['accepted_at'] == h['verified_at'] and op['query'] == qh['request']
                and op['requested_at'] == q['requested_at'] and op['deadline'] == q['deadline'], 'Bootstrap query/ack/request binding')
        require(previous <= op['requested_at'] <= q['birth']['born_at'] <= q['verified_at'] <= op['birth']['born_at']
                <= op['result']['observed_at'] <= op['accepted_at'] <= w['scope_process_verified_at'][index]
                < op['deadline'], 'Bootstrap ordered query/birth/observation/ack/process')
        previous = op['accepted_at']
        require(op['result']['namespace'] == op['namespace'] and op['result']['group'] == op['group']
                and op['result']['policy'] == op['policy'] and op['result']['pins'] == op['pins'], 'Bootstrap result identity/policy/pins')
        policy = p['netfilter'][index*2+1]
        require(policy['kind'] == 'initial_quarantine' and policy['scope'] == scope
                and all(policy[k] is not None for k in ('birth', 'result', 'verified_at')),
                'Bootstrap completed initial quarantine policy in original scope')
        require(op['policy'] == policy['policy'] and h['creation'] == p['producer_creation']
                and op['group'] == p['producer_creation']['group'] and op['parent'] == p['producer_creation']['parent']
                and op['name'] == p['producer_creation']['name'], 'Bootstrap original producer and policy')
        pins = op['pins']
        require(len(pins) == 8 and all(len(pin) == 3 for pin in pins)
                and len({tuple(pin[:2]) for pin in pins}) == 8
                and pins[0][:2] == [op['parent']['dev'], op['parent']['ino']]
                and pins[1][:2] == [op['group']['dev'], op['group']['ino']]
                and all(pin[0] == op['parent']['dev'] and pin[1] > 0 for pin in pins), 'Bootstrap eight original pins')
        require(op['original_pid'] == op['birth']['pid'] and op['original_start'] == op['birth']['start']
                and op['actual_wait_status'] == 0 and op['native_job_state'] == 'born'
                and op['borrowed_registration_count'] == 2 and op['registered_native_slots'] == 25,
                'Bootstrap native identity/registration/status')
        for key in ('acknowledged', 'native_born', 'complete_native_registration', 'context_retained',
                    'durable_birth_released', 'eof', 'bootstrap_installation_observed', 'original_registration_slots_verified'):
            require(op[key] is True, 'Bootstrap operation.' + key)
        for stage, writer in enumerate(p['writers'][87 + index*6:93 + index*6]):
            phase = 'bootstrap_' + scope + '_' + ('query_' if stage < 3 else '') + ('intent', 'birth', 'result')[stage % 3]
            require(writer['phase'] == phase and writer['actual_wait_status'] == 0
                    and writer['io_deadline'] == writer['parent_deadline'] == op['deadline']
                    and op['requested_at'] <= writer['queued_at'] < op['deadline'], 'Bootstrap original writer phase/status/window')
    for path, obj in objects(w):
        for key in ('request', 'policy', 'query', 'configuration', 'declaration', 'host_declaration'):
            if type(obj.get(key)) is list and obj[key]:
                require(len(obj[key]) == 32 and all(type(n) is int and 0 <= n <= 255 for n in obj[key])
                        and any(obj[key]), path + '.' + key + ': nonzero 32-byte digest')


def canonical_histories(w, rows):
    host = dict(zip(('dev','ino'), rows['secret_attachment_gateway'][0]['host_network_namespace']))
    member = w['preparation']['member']
    descriptor = rows['secret_attachment_descriptor'][0]
    allocation = descriptor['allocation']
    exit_record = next(e for e in allocation['exits'] if e['exit_id'] == member)
    for path, p in objects(w):
        if 'canonical_owner_epoch' not in p:
            continue
        preparation_idle(p)
        require(p['member'] == member, path + ': original member')
        # Every retained snapshot is already past successful DATA publication.
        require(p['base_network'] == p['data_network'] == p['attachment']['source'], 'published DATA namespace')
        mount = p['attachment']
        require(all(re.fullmatch(r'[a-f0-9]{64}',mount['origin'][key]) is not None
                    for key in ('launch','staging','container')) and mount['origin']['process_start'] > 0
                and any(mount['origin']['public_result']), 'original admitted Origin digest/identity')
        require(mount['name'] == exit_record['data_namespace'], 'canonical DATA namespace name')
        require(mount['origin']['network'] == mount['source'] and mount['directory']['ino'] > 0
                and mount['source']['ino'] > 0 and mount['placeholder']['identity']['ino'] > 0
                and mount['placeholder']['identity']['dev'] == mount['directory']['dev']
                and mount['placeholder']['mode'] == 0o100600
                and p['inspection']['verified_at'] <= mount['requested_at']
                and mount['query']['requested_at'] == mount['requested_at']
                and mount['query']['deadline'] == mount['deadline']
                and mount['mounted_at'] <= mount['query']['birth']['born_at']
                and mount['query']['verified_at'] <= mount['published_at'], 'DATA mount completion chain')
        original_facts = p['inspection']['facts']
        require(p['inspection']['kind'] == 'Recheck' and p['inspection']['initial'] is not None
                and p['inspection']['initial']['facts'] == original_facts
                and p['inspection']['initial']['request'] != p['inspection']['request']
                and p['inspection']['initial']['birth']['deadline'] == p['inspection']['deadline']
                and p['inspection']['requested_at'] <= p['inspection']['initial']['birth']['born_at']
                <= p['inspection']['initial']['verified_at'] <= p['inspection']['birth']['born_at'],
                'original initial/recheck inspection')
        queries = [('inspection',p['inspection'],'Recheck'), ('mount query',mount['query'],'AttachmentRecheck')]
        for key, kind in [('movement_query','MovementRecheck'), ('quarantine_query','QuarantineRecheck'),
                           ('producer_query','ProducerRecheck'), ('producer_binding_query','ProducerBindingRecheck')]:
            if p[key] is not None:
                queries.append((key,p[key],kind))
        for i,q in enumerate(p['bootstrap_queries']):
            if q is not None:
                queries.append(('bootstrap query',q,('BootstrapHostRecheck','BootstrapTransportRecheck','BootstrapDataRecheck')[i]))
        for key,q,kind in queries:
            require(q['kind'] == kind and q['facts'] == original_facts and 1 < q['facts']['pid'] <= 2**31-1
                    and (q['initial'] is None) == (kind != 'Recheck'), 'canonical query kind/initial/facts: ' + key)
        fresh = p['fresh_transport']
        if fresh is not None:
            fm = fresh['mount']
            require(fresh['host'] == host and fresh['data'] == p['data_network']
                    and fresh['source']['ino'] > 0 and fresh['source'] not in (host, fresh['data'])
                    and fresh['directory']['ino'] > 0 and fresh['name'] == exit_record['transport_namespace'] and fresh['requested_at'] >= mount['published_at']
                    and fm['source'] == fresh['source'] == p['transport_network']
                    and fm['directory'] == fresh['directory'] and fm['name'] == fresh['name']
                    and fresh['verified_at'] <= fm['requested_at']
                    and fm['placeholder']['identity']['dev'] == fm['directory']['dev']
                    and fm['placeholder']['identity']['ino'] > 0 and fm['placeholder']['mode'] == 0o100600,
                    'fresh transport creation/mount chain')
        wireguard = p['wireguard']
        require(len(wireguard) in (0,3,5), 'retained completed wireguard prefix')
        for i,h in enumerate(wireguard):
            kind = ('sockets','provision','query','data_sockets','move')[i]
            require(h['kind'] == kind and h['namespace'] == (p['data_network'] if i == 3 else p['transport_network'])
                    and h['namespace']['ino'] > 0, 'wireguard original kind/namespace')
            require(h['requested_at'] >= (wireguard[i-1]['verified_at'] if i else fresh['mount']['published_at']),
                    'wireguard ordered completion')
            require(h['configuration'] == wireguard[0]['configuration'], 'wireguard immutable configuration')
            r = h['result']
            require(r['namespace'] == (p['data_network'] if i == 4 else h['namespace'])
                    and ((r['link'] is None and r['wireguard'] is None) if i in (0,3)
                         else (r['link'] is not None and r['wireguard'] is not None)), 'wireguard result contract')
            # attachment/provision.rs:1002-1005 and movement.rs:824-835.
            # The booleans on the enclosing witness cannot establish link state.
            if i not in (0,3):
                require(r['link']['up'] is False and r['link']['kind'] == 'wireguard',
                        'WireGuard result must remain down and kind wireguard')
            if i == 4:
                q = p['movement_query']
                require(h['destination'] == p['data_network'] != h['namespace'] and h['movement_query'] == q['request']
                        and h['requested_at'] == q['requested_at'] and h['deadline'] == q['deadline']
                        and h['birth']['born_at'] >= q['verified_at'], 'movement canonical query binding')
        policies = p['netfilter']
        require(len(policies) in (0,6), 'retained six policy history')
        for i,h in enumerate(policies):
            scope = ('host','transport','data')[i//2]
            ns = host if i//2 == 0 else p['transport_network'] if i//2 == 1 else p['data_network']
            require(h['kind'] == ('sockets' if i%2 == 0 else 'initial_quarantine') and h['scope'] == scope
                    and h['namespace'] == ns and h['result']['namespace'] == ns and h['result']['policy'] == h['policy']
                    and (h['result']['observed_at'] is None) == (i%2 == 0), 'canonical completed policy kind/scope/result')
            require(h['requested_at'] > 0 and h['requested_at'] >= wireguard[4]['verified_at']
                    and h['configuration'] == wireguard[4]['configuration'], 'canonical policy configuration/order')
            if i:
                require(h['requested_at'] >= policies[i-1]['verified_at']
                        and h['host_declaration'] == policies[i-1]['host_declaration']
                        and (i%2 == 0 or h['policy'] == policies[i-1]['policy']), 'canonical policy predecessor')
            if i == 5:
                q = p['quarantine_query']
                require(h['query'] == q['request'] and h['requested_at'] == q['requested_at']
                        and h['birth']['born_at'] >= q['verified_at'], 'DATA policy canonical query')
            else:
                require(h['query'] is None, 'policy without DATA query')
        creation, binding = p['producer_creation'], p['producer_binding']
        if creation is not None:
            q = p['producer_query']
            require(creation['query'] == q['request'] and creation['requested_at'] == q['requested_at']
                    and creation['deadline'] == q['deadline'] and creation['birth']['born_at'] >= q['verified_at']
                    and creation['data'] == p['data_network'] and creation['parent']['ino'] > 0
                    and creation['group']['ino'] > 0 and creation['group']['dev'] == creation['parent']['dev']
                    and creation['group'] != creation['parent']
                    and creation['name'] == exit_record['nft_table']+'-g'+str(allocation['generation'])+'-health'
                    and q['requested_at'] >= policies[5]['verified_at'], 'canonical producer creation')
        if binding is not None:
            q = p['producer_binding_query']
            require(binding['creation'] == creation, 'producer binding original creation')
            same_fields(binding,creation,('parent','group','name','data'),'producer binding original source')
            require(binding['data'] == p['data_network'] and binding['query'] == q['request']
                    and binding['requested_at'] == q['requested_at'] and binding['deadline'] == q['deadline']
                    and creation['verified_at'] <= q['requested_at'] <= q['verified_at'] <= binding['birth']['born_at']
                    and binding['policy'] == policies[5]['policy'], 'producer binding canonical DATA/query/policy')
            pub = p['entry_producer']
            require(pub is not None and pub['binding'] == binding['request']
                    and pub['parent'] == binding['parent'] and pub['group'] == binding['group'],
                    'producer binding original publication')
            pins = binding['pins']
            require(pins[0][:2] == [binding['parent']['dev'],binding['parent']['ino']]
                    and pins[1][:2] == [binding['group']['dev'],binding['group']['ino']]
                    and all(pin[0] == binding['parent']['dev'] and pin[1] > 0 for pin in pins),
                    'producer binding six original pins')
        for i,h in enumerate(p['host_link']):
            require(h['kind'] == ('transport_sockets','pair','host_sockets','move')[i]
                    and h['host'] == host and h['namespace'] == (host if i == 2 else p['transport_network'])
                    and h['admission'][0] >= binding['verified_at']
                    and (h['addition'] is not None) == (i == 3), 'host canonical kind/namespace/admission/addition')
            if i:
                previous = p['host_link'][i-1]
                same_fields(h,previous,('declaration','admission','host'),'host canonical original admission')
                require(h['requested_at'] >= previous['verified_at'], 'host ordered original completion')
            r = h['result']
            require(r['namespace'] == (host if i == 3 else h['namespace']), 'host result namespace')
            if i in (0,2):
                require(r['host'] is None and r['peer'] is None, 'host sockets result')
            elif i == 1:
                a,b = r['host'],r['peer']
                require(a['kind'] == b['kind'] == 'veth' and a['up'] is b['up'] is False
                        and 0 < a['index'] != b['index'] > 0 and a['peer_index'] == b['index']
                        and b['peer_index'] == a['index'] and a['name'] == exit_record['host_interface']
                        and b['name'] == exit_record['data_interface']
                        and a['alias'] == b['alias'] == 'vprouter-v2:'+allocation['deployment_id']+':'+str(allocation['generation'])+':'+member,
                        'host original down pair')
            else:
                old = p['host_link'][1]['result']
                a,b = dict(old['host']),dict(old['peer'])
                a['index'] = b['peer_index'] = h['addition'][1]
                require(r['host'] == a and r['peer'] == b
                        and h['addition'][1] == w['host_addition']['planned_host_link_index'], 'host move original pair result')


def same_fields(left, right, keys, reference):
    for key in keys:
        require(left[key] == right[key], reference + '.' + key)


# A registry entry names the observation, its canonical source, and every
# compared field (including aliases). No observed value chooses its own source.
# Paths are absolute in {witness, rows}; '*' captures an array index only.
P = ('witness', 'preparation')
HOST = ('witness', 'host_addition')
BINDING = HOST + ('producer_binding',)
ASSEMBLY = BINDING + ('assembly',)
QUARANTINE = ASSEMBLY + ('quarantine',)
MOVEMENT = QUARANTINE + ('movement',)
PROVISION = MOVEMENT + ('provision',)
ATTACHMENT = PROVISION + ('attachment',)


def binding_entry(name, observation, canonical, fields, mode='equal', guards=()):
    pairs = tuple((tuple(a.split('.')), tuple(b.split('.'))) if isinstance(a, str)
                  else (a,b) for a,b in
                  ((f,f) if isinstance(f,str) else f for f in fields))
    return dict(name=name, observation=observation, canonical=canonical,
                fields=pairs, mode=mode, guards=guards)


def make_binding_registry():
    registry = []
    def add(name, observation, canonical, fields, mode='equal', guards=()):
        registry.append(binding_entry(name,observation,canonical,fields,mode,guards))

    # These are the canonical recorded roots, not observations of another
    # serialized object. Domain/order/publication guards still run separately.
    # Native custody and the independent regeneration of digests are not implied.
    roots = ('attachment base_network birth bootstrap bootstrap_queries canonical_owner_epoch '
             'data_network deadline entry_producer fresh_transport host_link inspection '
             'member movement_query netfilter producer_binding producer_binding_query '
             'producer_creation producer_query quarantine_query requested_at transport_network wireguard writers').split()
    add('canonical_preparation',P,None,roots,'root',
        ('canonical_histories','bootstrap_scopes','owner_identity','writer_histories','monotonic_deadlines'))
    # Each retained preparation is a historical projection, with populated
    # histories/prefixes bound to the final history. Null/empty earlier stages
    # remain checked by retained_success and their exact stage cardinalities.
    for stage in (('witness','handoff'),HOST,BINDING,ASSEMBLY,QUARANTINE,MOVEMENT,PROVISION,ATTACHMENT):
        add('retained_preparation:'+'.'.join(stage),stage+('preparation',),P,roots,
            'projection',('preparation_success','retained_success'))

    # I9: provision.rs:878-885; kernel/fresh_transport.rs:498-505;
    # kernel/fresh_transport_mount.rs:852-861; owned/preparation/
    # fresh_transport.rs:112-120, fresh_mount.rs:115-120,452-453.
    add('transport_creation',PROVISION+('transport_creation',),P+('fresh_transport',),
        tuple(sorted(set(SCHEMAS['TransportWitness']) & set(SCHEMAS['FreshTransport']))))
    mount_fields = tuple(k for k in ('birth','requested_at','deadline','placeholder')
                         if k in SCHEMAS['MountHistory']) + (
                    ('original_source','source'),('original_directory','directory'))
    add('transport_mount',PROVISION+('transport_mount',),P+('fresh_transport','mount'),mount_fields)
    add('data_mount',ATTACHMENT+('mount',),P+('attachment',),mount_fields)
    add('validator_birth',ATTACHMENT+('validator',),P,('birth',))

    query_fields = tuple(sorted(set(SCHEMAS['Query']) & set(SCHEMAS['InspectionHistory'])))
    for name,observation,history in (
        ('attachment_recheck',ATTACHMENT+('second_query',),P+('inspection',)),
        ('postmount_query',ATTACHMENT+('postmount_query',),P+('attachment','query')),
        ('movement_query',MOVEMENT+('movement_query',),P+('movement_query',)),
        ('quarantine_query',QUARANTINE+('quarantine_query',),P+('quarantine_query',)),
        ('producer_query',QUARANTINE+('producer_query',),P+('producer_query',)),
        ('binding_query',BINDING+('query',),P+('producer_binding_query',)),
        ('bootstrap_queries',('witness','queries','*'),P+('bootstrap_queries','*'))):
        add(name,observation,history,query_fields)
    add('initial_query',ATTACHMENT+('first_query',),P+('inspection','initial'),('birth','facts','verified_at'))
    # Initial History intentionally omits its kind; the source discriminator is
    # fixed by owned/preparation/inspection.rs:142,864-875, not freely substitutable.
    add('initial_query_kind',ATTACHMENT+('first_query',),('expected','initial_query'),('kind',))
    add('initial_query_window',ATTACHMENT+('first_query',),P+('inspection',),('requested_at','deadline'))

    operation_fields = tuple(sorted(set(SCHEMAS['MovementOperation']) & set(SCHEMAS['WireguardHistory']))) + (('accepted_at','verified_at'),
                        ('original_pid','birth.pid'),('original_start','birth.start'))
    for name,observation,history,extra in (
        ('provision_operations',PROVISION+('operations','*'),P+('wireguard','*'),()),
        ('movement_operations',MOVEMENT+('operations','*'),P+('wireguard','*'),()),
        ('quarantine_operations',QUARANTINE+('operations','*'),P+('netfilter','*'),('scope',)),
        ('host_operations',HOST+('operations','*'),P+('host_link','*'),('namespace','host','declaration','admission','addition')),
        ('bootstrap_operations',('witness','operations','*'),P+('bootstrap','*'),('namespace','scope','query','policy','pins','group'))):
        fields = tuple(f for f in operation_fields if f != 'kind') if name == 'bootstrap_operations' else operation_fields
        add(name,observation,history,fields+extra)
    add('bootstrap_producer_source',('witness','operations','*'),P+('producer_creation',),('parent','name'))
    add('binding_operation',BINDING+('observation',),P+('producer_binding',),
        tuple(f for f in operation_fields if f != 'kind')+('parent','group','name','data','query','policy','pins'))
    add('producer_operation',QUARANTINE+('producer',),P+('producer_creation',),
        ('request','parent','group','name','data','query','birth','requested_at','deadline','verified_at',
         ('original_pid','birth.pid'),('original_start','birth.start')))
    add('binding_original_group',BINDING,P+('producer_creation',),(('original_group','group'),))

    for name,observation,index in (
        ('host_intent',HOST+('own_intent_polling',),75),
        ('bootstrap_query_intent',('witness','own_query_intent_polling'),87),
        ('bootstrap_intent',('witness','own_intent_polling'),90)):
        add(name,observation,P+('writers',index),('pid','start'))
    add('quarantine_intent',QUARANTINE+('own_intent_polling',),P+('writers',42),
        (('original_writer.pid','pid'),('original_writer.start','start'),
         ('deadline','io_deadline'),'verified_at','actual_wait_status'))

    original_jobs = [P+('attachment','birth'),P+('fresh_transport','birth'),P+('fresh_transport','mount','birth')]
    original_jobs += [P+('wireguard',i,'birth') for i in range(5)]
    original_jobs += [P+('netfilter',i,'birth') for i in range(6)]
    original_jobs += [P+('producer_creation','birth')]
    suffix_jobs = [P+('producer_binding','birth')]+[P+('host_link',i,'birth') for i in range(4)]
    for prefix,jobs in ((ASSEMBLY,original_jobs),(('witness','handoff'),suffix_jobs)):
        for i,source in enumerate(jobs):
            add('retired_job:'+'.'.join(prefix)+':'+str(i),prefix+('resources',i),source,
                (('original_pid','pid'),('original_start','start')))
        add('reservation_owner:'+'.'.join(prefix),prefix+('reservation',),P,
            (('owner_epoch','canonical_owner_epoch'),'member'))

    # I10: attachment/movement.rs:824-835. Use the original query result,
    # not another retained copy of the moved result.
    add('original_wireguard_move',P+('wireguard',4,'result'),P+('wireguard',2,'result'),
        ('link.name','link.alias','wireguard.public_key','wireguard.peers'))

    add('host_admission_history',HOST+('admission',),P+('host_link',0),
        ('declaration',('namespace','host'),(('requested_at',),('admission',0)),
         (('deadline',),('admission',1)),(('accepted_at',),('admission',2))))
    add('host_baseline',HOST+('admission',),('rows','secret_host_baseline',0,'declaration'),
        (('declared_baseline','baseline'),('namespace','host_namespace')))
    add('host_inventory',HOST+('operations',3,'host_observation'),HOST+('admission','declared_baseline'),
        ('namespace','addresses','routes','rules'))
    # The added link is separately checked against the original host result.
    add('host_inventory_links',HOST+('operations',3,'host_observation'),None,('links',),'root',('retained_success',))
    add('wan_declaration',QUARANTINE+('wan',),('rows','secret_quarantine_host',0,'declaration'),
        (('host_namespace','host_namespace'),('name','wan.name'),('index','wan.index'),('address','wan.address')))
    add('wan_observation_window',QUARANTINE+('wan',),P+('netfilter',1),('requested_at','deadline'))
    add('foreign_capacity_parent',ASSEMBLY+('foreign_eligibility',),P+('wireguard',0,'birth'),
        (('eligible_original_pid','pid'),('eligible_original_start','start')))
    add('foreign_capacity_observation',ASSEMBLY+('foreign_eligibility',),None,
        ('original_pid','original_start','requested_at','deadline','verified_at'),
        'root',('recorded_emitters','monotonic_deadlines'))
    return tuple(registry)


BINDING_REGISTRY = make_binding_registry()


def schema_nodes(value, spec='BootstrapWitness', path=('witness',)):
    """Walk declared schema edges only; unknown observation children stay uncovered."""
    if value is None:
        return
    if '|' in spec:
        choices = [s for s in alternatives(spec) if s in SCHEMAS and type(value) is dict]
        if choices:
            spec = min(choices,key=lambda s: len(set(value).symmetric_difference(SCHEMAS[s])))
    if spec in SCHEMAS and type(value) is dict:
        yield path, value
        for key,child_spec in SCHEMAS[spec].items():
            if key in value:
                yield from schema_nodes(value[key],child_spec,path+(key,))
    elif spec.startswith('list(') or spec == 'queries3':
        child_spec = 'InspectionHistory|null' if spec == 'queries3' else spec[5:-1]
        if type(value) is list:
            for i,child in enumerate(value):
                yield from schema_nodes(child,child_spec,path+(i,))


def at_path(root, path):
    for key in path:
        root = root[key]
    return root


def binding_instances(root, pattern, path=(), captures=()):
    if not pattern:
        yield path,captures,root
    elif pattern[0] == '*':
        require(type(root) is list, 'binding wildcard requires array')
        for i,item in enumerate(root):
            yield from binding_instances(item,pattern[1:],path+(i,),captures+(i,))
    else:
        key = pattern[0]
        yield from binding_instances(root[key],pattern[1:],path+(key,),captures)


def bind_observations(w, rows):
    """The single comparison engine for the complete declarative registry."""
    root = dict(witness=w,rows=rows,expected={'initial_query': {'kind': 'Initial'}})
    for entry in BINDING_REGISTRY:
        for path,captures,observation in binding_instances(root,entry['observation']):
            if entry['mode'] == 'root':
                continue  # explicitly named canonical evidence; guards run in validate
            indices = iter(captures)
            source_path = tuple(next(indices) if key == '*' else key for key in entry['canonical'])
            source = at_path(root,source_path)
            for left,right in entry['fields']:
                actual,expected = at_path(observation,left),at_path(source,right)
                if entry['mode'] == 'projection':
                    if actual is None:
                        continue
                    if left == ('bootstrap_queries',):
                        require(all(q is None or q == expected[i] for i,q in enumerate(actual)),entry['name']+': queries')
                        continue
                    if type(actual) is list:
                        expected = expected[:len(actual)]
                require(actual == expected, entry['name']+': '+repr(path+left)+' binds '+repr(source_path+right))
    coverage = binding_coverage(w)
    require(not coverage['uncovered'], 'unregistered observation objects: '+repr(coverage['uncovered']))


OBSERVATION_KEYS = frozenset(('pid','start','dev','ino','deadline','birth','original_pid',
                              'original_start','process_start','io_deadline','parent_deadline'))


def binding_coverage(w):
    # Coverage is established by explicit compared fields, not a blanket parent
    # exemption or object-shape whitelist. schema_nodes refuses unknown edges.
    nodes = dict(schema_nodes(w))
    prefixes = set()
    for entry in BINDING_REGISTRY:
        for path,_,_ in binding_instances(dict(witness=w),entry['observation']):
            for left,_ in entry['fields']:
                prefixes.add(path+left)
    observations = []
    uncovered = []
    def walk(value,path):
        if type(value) is dict:
            keys = OBSERVATION_KEYS.intersection(value)
            if keys:
                observations.append(path)
                fields = [path+(key,) for key in keys]
                if path not in nodes or any(not any(field[:i] in prefixes for i in range(1,len(field)+1))
                                            for field in fields):
                    uncovered.append(path)
            for key,child in value.items():
                walk(child,path+(key,))
        elif type(value) is list:
            for i,child in enumerate(value):
                walk(child,path+(i,))
    walk(w,('witness',))
    return dict(observations=len(observations),uncovered=uncovered)


def intent_success(intent, p, index, negatives, held=2):
    writer = p['writers'][index]
    identity = intent.get('original_writer', intent)
    require(identity['index'] == index and identity['pid'] == writer['pid']
            and identity['start'] == writer['start'] and writer['actual_wait_status'] == 0,
            'original held intent writer identity/status')
    require(intent['queued_polls'] == 1 and intent['held_pending_polls'] >= held
            and intent['negative_checks'] == negatives, 'original intent poll/negative counts')
    if 'released' in intent:
        require(intent['released'] is True and intent['held_pending_polls'] == held,
                'original intent release/held count')
    else:
        require(intent['actual_wait_status'] == 0 and intent['verified_at'] == writer['verified_at']
                and intent['deadline'] == writer['io_deadline'] == writer['parent_deadline'],
                'original quarantine intent receipt')


def preparation_idle(p):
    for key in ('native_children_reaped', 'service_reserved', 'entry_links_absent',
                'entry_attempt_absent', 'entry_terminal_absent', 'owner_host_anchor_present',
                'canonical_result_present'):
        require(p[key] is True, 'successful preparation.' + key)
    for key in ('member_native_jobs_collected', 'canonical_pending', 'mutation_fenced', 'base_network_absent'):
        require(p[key] is False, 'successful preparation.' + key)
    require(p['entry_phase'] == 'creating' and p['entry_producer_absent'] is (p['entry_producer'] is None),
            'successful creating entry/publication discriminator')
    for key in ('pending_bootstrap', 'pending_host_link', 'pending_producer_binding',
                'pending_producer_creation', 'pending_wireguard'):
        require(p[key] is None, 'successful preparation.' + key)


def original_operation(op, history, borrowed=None):
    same_fields(op, history, [key for key in ('kind', 'scope', 'namespace', 'host', 'data', 'parent',
                'name', 'group', 'request', 'query', 'policy', 'pins', 'declaration', 'admission',
                'addition', 'birth', 'requested_at', 'deadline', 'result') if key in op and key in history],
                'original operation/history')
    require(op['accepted_at'] == history['verified_at'] and op['actual_wait_status'] == 0
            and op['original_pid'] == history['birth']['pid']
            and op['original_start'] == history['birth']['start']
            and op['native_job_state'] == 'born', 'original operation identity/status/ack')
    for key in ('acknowledged', 'native_born', 'context_retained', 'eof', 'durable_birth_released',
                'complete_native_registration', 'full_descriptor_registration', 'original_registration_slots_verified'):
        if key in op:
            require(op[key] is True, 'original completed operation.' + key)
    if borrowed is not None:
        require(op['borrowed_registration_count'] == borrowed, 'original borrowed registrations')


def retained_success(w):
    host = w['host_addition']
    binding = host['producer_binding']
    assembly = binding['assembly']
    quarantine = assembly['quarantine']
    movement = quarantine['movement']
    provision = movement['provision']
    attachment = provision['attachment']
    stages = [host, binding, assembly, quarantine, movement, provision]
    counts = [87, 75, 69, 69, 42, 33]
    for stage, count in zip(stages, counts):
        require(stage['schema'] == 1 and stage['fault'] == 0 and stage['parent_pristine'] is True
                and stage['continued_original_context'] is True, 'retained successful continuation schema/fault/parent')
        # These emitters return their continuing owner before their drop branch.
        for key in stage:
            if key.endswith('_retained_after_drop'):
                require(stage[key] is False, 'retained continuation precedes drop: ' + key)
        for key in ('failed_constructor', 'failure_retry', 'retained_result_writer', 'charges_after_drop'):
            if key in stage:
                require(stage[key] is None, 'retained continuation.' + key)
        for key in ('result_writer_held', 'held_real_result_writer', 'unacknowledged_native_result_retained',
                    'unacknowledged_host_addition_retained', 'unacknowledged_observation_retained'):
            if key in stage:
                require(stage[key] is False, 'retained success.' + key)
        preparation_idle(stage['preparation'])
        require(stage['preparation']['bootstrap'] == [] and stage['preparation']['bootstrap_queries'] == [None]*3,
                'retained stage precedes Bootstrap')
        require(len(stage['preparation']['writers']) == count, 'retained writer count')
    for later, earlier, count, fields in [
        (host, binding, 75, ('wireguard','netfilter','producer_creation','producer_binding',
          'producer_binding_query','producer_query','quarantine_query','movement_query','inspection','attachment','fresh_transport')),
        (binding, assembly, 69, ('member','requested_at','deadline','birth','base_network_absent','base_network',
          'data_network','transport_network','inspection','attachment','fresh_transport','wireguard',
          'movement_query','netfilter','quarantine_query','producer_query','producer_creation')),
        (quarantine, movement, 42, ('member','canonical_owner_epoch','inspection','attachment','fresh_transport',
          'wireguard','movement_query','base_network','data_network','transport_network')),
        (movement, provision, 33, ('canonical_owner_epoch','inspection','attachment','fresh_transport',
          'base_network','data_network','transport_network')),
        (provision, attachment, 17, ('canonical_owner_epoch','member','base_network','data_network','inspection','attachment'))]:
        lp, ep = later['preparation'], earlier['preparation']
        require(lp['writers'][:count] == ep['writers'], 'retained original writer prefix')
        same_fields(lp, ep, fields, 'retained preparation prefix')
    require(assembly['preparation'] == quarantine['preparation'], 'assembly unchanged preparation')
    require(movement['preparation']['wireguard'][:3] == provision['preparation']['wireguard']
            and movement['operations'][:3] == provision['operations'], 'movement original provision operations')
    require(host['canonical_negative_checks'] == 20 and host['charges_before'] == [1,1]
            and host['charges_before_drop'] == [5,5], 'host schema oracle and charges')
    intent_success(host['own_intent_polling'], host['preparation'], 75, 12)
    require(binding['charges_before'] == [0,0] and binding['charges_before_drop'] == [1,1]
            and binding['canonical_negative_checks'] == 25 and binding['canonical_producer_published'] is True and binding['same_original_source'] is True,
            'producer binding success publication/charges')
    require(binding['original_group'] == binding['preparation']['producer_creation']['group'], 'original producer group')
    require(assembly['charges_before'] == [15,11] and assembly['charges_after'] == [0,0]
            and assembly['retired_original_jobs'] == 15 and assembly['handoff_complete'] is True
            and assembly['duplicate_reservation_refused'] is False and assembly['repeat_retirement_refused'] is True
            and assembly['lower_repeat_retirement_refused'] is True and assembly['fence_blocked_next_transfer'] is False
            and assembly['duplicate_reservation_counts'] is None and assembly['fence_counts'] is None,
            'original assembly retirement success')
    r = assembly['reservation']
    require(r['complete'] is True and r['original_jobs'] == 15 and r['member_transfer_pending'] is False
            and r['global_assemblies_reserved'] == 1 and r['global_assembly_limit'] == 128
            and r['global_transferred_ticket_limit'] == 2560 and r['member'] == w['preparation']['member'],
            'original assembly reservation')
    intent_success(quarantine['own_intent_polling'], quarantine['preparation'], 42, 12)
    for stage, flags in [(host, ('isolated_pair_creation_observed','single_down_host_addition_observed',
                                  'canonical_host_addition_acknowledged','host_addresses_routes_rules_preserved')),
                         (quarantine, ('same_service_retained','initial_quarantine_only',
                           'initial_quarantine_installation_observed_all_scopes','producer_group_creation_observed')),
                         (movement, ('same_service_retained','data_move_completed','move_borrows_both_original_pairs',
                           'original_query_parent_readback_advanced','wireguard_down_only')),
                         (provision, ('same_service_retained','transport_distinct_from_host_and_data',
                           'original_socket_registrations_borrowed','wireguard_down_only'))]:
        for flag in flags:
            require(stage[flag] is True, 'retained success.' + flag)
    for stage, key in [(binding,'host_network_links_or_routes_created'), (quarantine,'host_network_links_or_routes_created'),
                       (movement,'host_resources_created'), (provision,'host_resources_created'),
                       (assembly,'producer_operational_publication'), (quarantine,'producer_operational_publication')]:
        require(stage[key] is False, 'retained boundary.' + key)
    for stage, writer_index, query in [(binding,74,binding['query']), (quarantine,68,quarantine['producer_query']),
                                     (movement,41,movement['movement_query'])]:
        require(stage['preparation']['writers'][writer_index]['verified_at'] <= stage['final_process_verified_at']
                < query['deadline'], 'retained final process verification window')
    require(host['admission']['two_original_reads_verified'] is True
            and host['admission']['same_generation_owner_retained'] is True
            and host['admission']['polls'] > 0, 'host original baseline admission')
    admission = host['admission']
    baseline = admission['declared_baseline']
    final = host['operations'][3]['host_observation']
    require(final is not None and final['namespace'] == baseline['namespace'], 'host inventory namespace')
    same_fields(final, baseline, ('addresses','routes','rules'), 'host preserved inventory')
    added = host['operations'][3]['result']['host']
    require(len(final['links']) == len(baseline['links'])+1
            and final['links'].count(added) == 1 and all(final['links'].count(link) == 1 for link in baseline['links']),
            'host exactly one original down addition')
    for i,op in enumerate(host['operations']):
        require(op['admission'] == [admission['requested_at'],admission['deadline'],admission['accepted_at']]
                and op['declaration'] == admission['declaration']
                and (op['host_observation'] is not None) == (i == 3), 'host original admission/observation chain')
    hp = host['preparation']
    require(len(host['operations']) == len(hp['host_link']) == 4, 'four host operations')
    for index, (op, h) in enumerate(zip(host['operations'], hp['host_link'])):
        original_operation(op, h, [0,2,0,4][index])
        if index in (1,3):
            require(op['postcompletion_inventory_preserved'] is True and op['postcompletion_inventory_polls'] >= 2,
                    'host postcompletion inventories')
        for writer in hp['writers'][75+index*3:78+index*3]:
            require(writer['io_deadline'] == writer['parent_deadline'] == h['deadline'], 'host writer window')
    require([x['phase'] for x in hp['writers'][75:]] == ['host_link_'+s for _ in range(4) for s in ('intent','birth','result')],
            'host writer phases')
    require(len(quarantine['operations']) == 6, 'six quarantine operations')
    for i, (op,h) in enumerate(zip(quarantine['operations'], quarantine['preparation']['netfilter'])):
        original_operation(op,h,0 if i % 2 == 0 else 2)
    original_operation(binding['observation'], binding['preparation']['producer_binding'], 2)
    for stage in (movement,provision):
        require(len(stage['operations']) == (5 if stage is movement else 3), 'wireguard operation count')
        for op,h in zip(stage['operations'],stage['preparation']['wireguard']):
            original_operation(op,h)
    for stage,query,key in [(binding,binding['query'],'producer_binding_query'),
                            (quarantine,quarantine['producer_query'],'producer_query'),
                            (quarantine,quarantine['quarantine_query'],'quarantine_query'),
                            (movement,movement['movement_query'],'movement_query')]:
        same_fields(query, stage['preparation'][key], ('kind','birth','facts','requested_at','deadline','verified_at'),
                    'retained original query/history')


def recorded_emitters(w, rows):
    # Additional success evidence from the retained constructor/result builders.
    shapes = {name:set(SCHEMAS[name]) for name in ('Query','Resource','MountWitness',
              'TransportWitness','AttachmentWitness','ProducerWitness','Wan','MovementOperation')}
    gateway = rows['secret_attachment_gateway'][0]
    for path,obj in objects(w):
        shape = set(obj)
        if shape == shapes['Query']:
            require(obj['actual_wait_status'] == 0 and obj['original_peer_receipt'] is True
                    and obj['handler_identity_claimed'] is False and obj['listener_origin_pid'] == 1
                    and obj['listener_origin_uid'] == obj['listener_origin_gid'] == 0
                    and obj['facts']['pid'] == gateway['pid']
                    and obj['facts']['security'] == 'AppArmorBuiltinSeccomp', path + ': original Docker query receipt')
        elif shape == shapes['Resource']:
            lower = obj['kind'] in ('WireguardSecret','FixedNetfilter','FixedVeth')
            require(obj['actual_wait_status'] == 0 and obj['native_job_state'] == 'transferred_resources'
                    and obj['fully_retired'] is True and obj['launch_charge_retired'] is True
                    and obj['transfer_started'] is True and obj['lower_charge_required'] is lower
                    and obj['lower_charge_retired'] is (True if lower else None)
                    and obj['lower_gated_retirement_refused'] is (True if lower else None), path + ': original retired resource')
        elif shape == shapes['MountWitness']:
            require(obj['actual_wait_status'] == 0 and obj['eof'] is True
                    and obj['original_mounted_namespace_retained'] is True
                    and obj['original_placeholder_retained'] is True and obj['received_packets'] == 2
                    and obj['released_gates'] == 2, path + ': original completed mount')
        elif shape == shapes['TransportWitness']:
            require(obj['actual_wait_status'] == 0 and obj['durable_birth_released'] is True
                    and obj['eof'] is True and obj['original_source_retained'] is True,
                    path + ': original fresh transport')
        elif shape == shapes['AttachmentWitness']:
            require(obj['schema'] == 1 and obj['fault'] == 0 and obj['base_published'] is True
                    and obj['original_mount_retained'] is True and obj['parent_pristine'] is True
                    and obj['same_service_retained'] is True and obj['held_real_writer'] is False
                    and obj['whole_failed_driver_retained_after_drop'] is False
                    and obj['normal_ack_ready_preserved'] is False, path + ': successful attachment')
            p = obj['preparation']
            require(len(p['writers']) == 17 and p['transport_network'] is None, 'attachment preparation')
            require(obj['validator']['birth'] == p['birth'] and obj['validator']['actual_wait_status'] == 0,
                    'original validator birth/status')
            same_fields(obj['mount'],p['attachment'],('birth','requested_at','deadline','placeholder'),'original DATA mount')
            require(obj['mount']['original_source'] == p['attachment']['source']
                    and obj['mount']['original_directory'] == p['attachment']['directory'], 'original DATA mount identities')
            for query,key in [(obj['first_query'],'initial'),(obj['second_query'],None)]:
                history = p['inspection'][key] if key else p['inspection']
                same_fields(query,history,('birth','facts','verified_at'),'original first/second inspection')
            same_fields(obj['postmount_query'],p['attachment']['query'],('birth','facts','verified_at'), 'original postmount query')
            require(obj['inspection_requested_at'] == p['inspection']['requested_at']
                    and obj['inspection_deadline'] == p['inspection']['deadline']
                    and p['inspection']['verified_at'] <= obj['inspection_verified_at'] < obj['inspection_deadline']
                    and obj['inspection_verified_at'] <= p['attachment']['requested_at'], 'original inspection window')
        elif shape == shapes['ProducerWitness']:
            for key in ('acknowledged','context_retained','durable_birth_released','eof','full_descriptor_registration',
                        'native_born','received_original_group'):
                require(obj[key] is True, path + '.' + key)
            require(obj['operational_publication'] is False and obj['parent_death_lock_survival_claimed'] is False
                    and obj['actual_wait_status'] == 0 and obj['native_job_state'] == 'born'
                    and obj['registered_native_slots'] >= 3, 'original producer evidence')
            creation = w['preparation']['producer_creation']
            same_fields(obj,creation,('request','parent','group','name','data','query','birth','requested_at','deadline','verified_at'),
                        'original producer creation operation')
            require(obj['original_pid'] == obj['birth']['pid'] and obj['original_start'] == obj['birth']['start'],
                    'original producer native identity')
        elif shape == shapes['Wan']:
            require(obj['original_observer_retained'] is True, 'original WAN observer')
        elif shape == shapes['MovementOperation']:
            inventory = obj['kind'] not in ('sockets','data_sockets')
            require(obj['postcompletion_inventory_preserved'] is inventory
                    and (obj['postcompletion_inventory_polls'] >= 2 if inventory else obj['postcompletion_inventory_polls'] == 0),
                    'original transport postcompletion inventory')
            require(obj['borrowed_registration_count'] == (4 if obj['kind'] == 'move' else 0 if not inventory else 2)
                    and obj['registered_native_slots'] >= 3, 'original transport native registrations')
    host = w['host_addition']
    binding = host['producer_binding']
    assembly = binding['assembly']
    quarantine = assembly['quarantine']
    movement = quarantine['movement']
    provision = movement['provision']
    expected = [provision['attachment']['mount'], provision['transport_creation'], provision['transport_mount']] + movement['operations'] + quarantine['operations'] + [quarantine['producer']]
    resources = assembly['resources']
    require(len(resources) == 15 and [r['kind'] for r in resources] ==
            ['NamespaceAttachment','FreshTransport','FreshTransportMount']+['WireguardSecret']*5+['FixedNetfilter']*6+['ProducerCreation'],
            'assembly fifteen original resource kinds')
    for resource,op in zip(resources,expected):
        birth = op['birth']
        require(resource['original_pid'] == birth['pid'] and resource['original_start'] == birth['start'],
                'assembly original retired resource identity')
    f = assembly['foreign_eligibility']
    require(f['schema'] == 1 and 1 < f['original_pid'] <= 2**31-1 and f['original_start'] > 0 and f['actual_wait_status'] == 0 and f['eof'] is True
            and f['eligible_foreign_refused'] is True and f['parent_still_eligible'] is True
            and f['canonical_operation'] is False and f['successful_capacity_transfer_proven'] is False
            and f['parent_counts_before'] == f['parent_counts_after'] == [15,11]
            and f['eligible_original_pid'] == resources[3]['original_pid']
            and f['eligible_original_start'] == resources[3]['original_start'], 'foreign capacity refusal metadata')
    # The original query's accepted readback advances only the route sequence.
    sequences = movement['operations'][2]['query_sequences']
    require(sequences[1][0] > sequences[0][0] and sequences[0][1] == sequences[1][1], 'original query parent readback')
    for op in host['operations']:
        require(op['registered_native_slots'] >= 3, 'host native registration minimum')
    require(binding['observation']['registered_native_slots'] >= 9, 'binding native registration minimum')
    # These are immutable recorded fstat modes. UID/GID, FD access modes and
    # fstatfs custody are not present in the witness and cannot be reconstructed.
    for _, obj in objects(w):
        if 'pins' in obj and len(obj['pins']) == 6:
            require((obj['pins'][1][2] & 0o7777) == 0o700,
                    'original six-pin producer observation group permission bits')
    for op in w['operations']:
        require(all((mode & 0o022) == 0 and (mode & 0o170000) == (0o100000 if 2 <= i < 6 else 0o040000)
                    for i,(_,_,mode) in enumerate(op['pins'])), 'Bootstrap pin file types and modes')


def allocation_contract(w,rows):
    """Public AllocationRecord::validate, including every nonprimary exit."""
    descriptor = rows['secret_attachment_descriptor'][0]
    allocation = descriptor['allocation']
    deployment = descriptor['deployment_id']
    def label(value):
        require(bool(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?',value)) and len(value) <= 32,
                'native allocation bounded ASCII label')
    label(deployment)
    require(allocation['deployment_id'] == deployment and allocation['schema_version'] == 2
            and allocation['generation'] > 0 and 0 < len(allocation['exits']) <= CONTRACT['success_rules']['max_exits'],
            'native public allocation deployment/schema/generation/exits')
    resources = {k:set() for k in ('ids','namespaces','interfaces','tables','subnets')}
    states = []
    def unique(category,value):
        require(value not in resources[category],'native allocation duplicate '+category)
        resources[category].add(value)
    for exit in allocation['exits']:
        identity = exit['exit_id'];label(identity);unique('ids',identity)
        state = exit['state_dir']
        parts = state.split('/')[1:]
        require(state.startswith('/') and state != '/' and '\0' not in state
                and all(part not in ('','.','..') for part in parts),'native allocation absolute nonroot state path')
        require(not any(parts[:len(old)] == old or old[:len(parts)] == parts for old in states),
                'native allocation overlapping state paths')
        states.append(parts)
        h = CONTRACT['success_rules']['allocation_hash_seed']
        for byte in deployment.encode()+b'\0'+identity.encode():
            h = ((h ^ byte)*CONTRACT['success_rules']['allocation_hash_prime']) & (2**64-1)
        short,full,slot = f'{h & 0xffffffffffff:012x}',f'{h:016x}',h & 0xffff
        expected = dict(exit_id=identity,mode=exit['mode'],state_dir=state,
                        data_namespace='vr-data-'+full,transport_namespace='vr-trans-'+full,
                        nft_table='vr_'+full,host_interface='vh'+short,data_interface='vd'+short,
                        wireguard_interface='wg'+short if exit['mode']=='mullvad' else None,
                        transport_subnet=f'10.{200+(slot >> 14)}.{(slot >> 6)&255}.{(slot & 63)*4}/30')
        require(exit == expected,'native allocation deterministic original resource names/subnet')
        for key in ('data_namespace','transport_namespace'):
            unique('namespaces',exit[key])
        for key in ('host_interface','data_interface','wireguard_interface'):
            if exit[key] is not None:
                require(len(exit[key]) <= 15,'native allocation interface name length')
                unique('interfaces',exit[key])
        unique('tables',exit['nft_table'])
        # Every generated subnet is a /30 in the fixed pool. Distinct slots
        # cannot overlap, so exact /30 equality is the overlap test here.
        unique('subnets',exit['transport_subnet'])
    def ordered(value,schema):
        names = sorted(SCHEMAS[schema],key=lambda key:CONTRACT['field_sources'][schema+'.'+key]['line'])
        return {key:([ordered(e,'AllocationExit') for e in value[key]] if key=='exits' else value[key]) for key in names}
    digest = hashlib.sha256(json.dumps(ordered(allocation,'Allocation'),ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
    require(digest == descriptor['allocation_digest'],'native canonical serde allocation digest')


def host_observation_bounds(w, rows):
    """HostObservation::validate public bounds; raw wire bytes remain distinct."""
    for root in (w, rows):
        for path, obj in objects(root):
            if set(obj) != set(SCHEMAS['HostBaseline']):
                continue
            require(all(v > 0 for v in obj['namespace']), path+': observation namespace')
            require(sum(len(obj[k]) for k in ('links','addresses','routes','rules')) <= 4096,
                    path+': observation record count')
            for link in obj['links']:
                require(0 < len(link['name'].encode()) <= 15
                        and len(link['alias'].encode()) <= 255
                        and len(link['kind'].encode()) <= 64
                        and len(link['port_kind'].encode()) <= 64
                        and len(link['alternate_names']) <= 64
                        and all(0 < len(name.encode()) <= 127 for name in link['alternate_names'])
                        and len(link['tun_info']) <= 64
                        and all(len(value) <= 256 for _, value in link['tun_info']),
                        path+': observation Link string/alternate-name/TUN bounds')


def contract_success(w,rows):
    """Serialized native-success guards plus original plan/journal prerequisites."""
    p = w['preparation']
    descriptor = rows['secret_attachment_descriptor'][0]
    allocation = descriptor['allocation']
    primary = next(e for e in allocation['exits'] if e['exit_id'] == p['member'])
    inputs = rows['secret_attachment_input'][0]
    profile = next(e for e in inputs['profiles'] if e['member'] == p['member'])
    rules = CONTRACT['success_rules']
    alias = f"vprouter-v2:{descriptor['deployment_id']}:{allocation['generation']}:{primary['exit_id']}"
    public = rules['public_profile']
    # The profile constants are extracted from the retained guest whose bytes
    # are bound by record.guest_sha256 in frozen_bindings.
    def link_guards(link,name,kind):
        require(link['name'] == name and link['kind'] == kind and link['alias'] == alias,
                'native result original allocated name/kind/ownership alias')
        require(link['index'] > 0, 'native decoded Link positive index')
        require(link['hardware_type'] == (65534 if kind == 'wireguard' else 1),
                'native created Link hardware type')
        if kind == 'wireguard':
            require(link['peer_index'] is None, 'original created WG has no peer index')
        for key,expected in rules['network_link_fixed'].items():
            require(link[key] == expected,'native Link success guard: '+key)
    for history in p['wireguard']:
        result = history['result']
        if result['link'] is None:
            continue
        link,device = result['link'],result['wireguard']
        link_guards(link,primary['wireguard_interface'],'wireguard')
        require(device is not None and device['index'] == link['index']
                and device['name'] == link['name']
                and device['public_key'] == profile['device_public_key'],
                'native WG original Link index/name and recorded public input key')
        require(len(device['peers']) == 1,'native WG exactly one planned peer')
        peer = device['peers'][0]
        require(peer['public_key'] == public['PublicKey'] and peer['endpoint'] == public['Endpoint']
                and peer['allowed_ips'] == [['0.0.0.0',0]],'native WG planned peer/endpoint/default route')
    # Query must retain the complete original provision Link, as well as its
    # original public plan. Moving can change Link index but not its plan.
    require(p['wireguard'][1]['result']['link'] == p['wireguard'][2]['result']['link'],
            'WG query original provision Link continuity')
    for history in p['host_link']:
        result = history['result']
        if result['host'] is not None:
            link_guards(result['host'],primary['host_interface'],'veth')
            link_guards(result['peer'],primary['data_interface'],'veth')
        if history['addition'] is not None:
            require(any(history['addition'][0]),'nonzero original HostAdditionPlan digest')
    wan = w['host_addition']['producer_binding']['assembly']['quarantine']['wan']
    host_policy = p['netfilter'][1]
    require(wan['requested_at'] == host_policy['requested_at'] and wan['deadline'] == host_policy['deadline']
            and wan['verified_at'] <= host_policy['birth']['born_at'],
            'WAN original HOST InitialQuarantine request window and prerequisite completion')
    require(p['attachment']['directory'] == p['fresh_transport']['directory'] == p['fresh_transport']['mount']['directory'],
            'DATA and TRANSPORT original journal directory')
    require(w['host_addition']['producer_binding']['assembly']['global_child_capacity_limit'] == rules['assembly_capacity'],
            'assembly emitter fixed global child capacity')


def writer_histories(w):
    p = w['preparation']
    expected = []
    def append(phases, end):
        expected.extend((phase,end) for phase in phases)
    append(('intent','birth','result'),p['deadline'])
    append(('inspection_intent','inspection_birth','inspection_result')*2,p['inspection']['deadline'])
    append(('attachment_intent','attachment_birth','attachment_placeholder','attachment_mounted',
            'attachment_query_intent','attachment_query_birth','attachment_query_result','attachment_primary'),p['attachment']['deadline'])
    append(('transport_intent','transport_birth','transport_source'),p['fresh_transport']['deadline'])
    append(('transport_mount_intent','transport_mount_birth','transport_mount_placeholder','transport_mount_publication'),p['fresh_transport']['mount']['deadline'])
    for h in p['wireguard'][:3]:
        append(('wireguard_intent','wireguard_birth','wireguard_result'),h['deadline'])
    append(('wireguard_intent','wireguard_birth','wireguard_result'),p['wireguard'][3]['deadline'])
    append(('movement_query_intent','movement_query_birth','movement_query_result'),p['movement_query']['deadline'])
    append(('wireguard_intent','wireguard_birth','wireguard_result'),p['wireguard'][4]['deadline'])
    for h in p['netfilter'][:5]:
        append(('netfilter_intent','netfilter_birth','netfilter_result'),h['deadline'])
    append(('quarantine_query_intent','quarantine_query_birth','quarantine_query_result'),p['quarantine_query']['deadline'])
    append(('netfilter_intent','netfilter_birth','netfilter_result'),p['netfilter'][5]['deadline'])
    append(('producer_query_intent','producer_query_birth','producer_query_result'),p['producer_query']['deadline'])
    append(('producer_intent','producer_birth','producer_result'),p['producer_creation']['deadline'])
    append(('producer_binding_query_intent','producer_binding_query_birth','producer_binding_query_result'),p['producer_binding_query']['deadline'])
    append(('producer_binding_intent','producer_binding_birth','producer_binding_result'),p['producer_binding']['deadline'])
    for h in p['host_link']:
        append(('host_link_intent','host_link_birth','host_link_result'),h['deadline'])
    for h in p['bootstrap']:
        append(tuple('bootstrap_'+h['scope']+'_'+s for s in ('query_intent','query_birth','query_result','intent','birth','result')),h['deadline'])
    require(len(expected) == len(p['writers']) == 105, 'complete writer schedule')
    for writer,(phase,end) in zip(p['writers'],expected):
        require(writer['phase'] == phase and writer['actual_wait_status'] == 0
                and writer['io_deadline'] == writer['parent_deadline'] == end
                and end-2 <= writer['queued_at'] <= writer['verified_at'] < end
                and writer['pid'] > 1 and writer['start'] > 0, 'original writer phase/window/status/identity')
    for path,obj in objects(w):
        if 'canonical_owner_epoch' in obj:
            require(obj['writers'] == p['writers'][:len(obj['writers'])], path + ': original writer prefix')


def controller_consistency(w, record, rows):
    c = rows['secret_attachment_controller'][0]
    descriptor, gateway, inputs = (rows[key][0] for key in (
        'secret_attachment_descriptor', 'secret_attachment_gateway', 'secret_attachment_input'))
    primary = next(e for e in descriptor['allocation']['exits'] if e['exit_id'] == descriptor['primary'])
    require(c['harness_exit_code'] == record['exit_code'] == rows['secret_attachment_owner_launcher'][0]['exit_code'] == 0
            and rows['secret_attachment_build_exit'] == [0]
            and rows['case'] == [dict(case='actual_original_three_scope_bootstrap_after_exact_twenty_handoff', result='PASS')], 'build/harness/launcher/case status')
    for key in ('owner_unit_absent', 'host_single_down_link_added', 'host_addresses_routes_rules_preserved',
                'host_stable_neighbors_preserved', 'inert_gateway_retained', 'original_gateway_native_identity_unchanged',
                'synthetic_only', 'native_transport_operations_requested', 'canonical_and_mount_resources_retained'):
        require(c[key] is True, 'controller.' + key)
    require(c['host_links_and_stable_routes_unchanged'] is False
            and c['host_links_and_stable_routes_unchanged'] is (not c['host_single_down_link_added']),
            'controller: unchanged=false is required by single down link addition')
    require(c['host_allowed_index'] == descriptor['planned_host_link_index'] == w['host_addition']['planned_host_link_index']
            and c['host_allowed_name'] == primary['host_interface'], 'controller original allowed link index/name')
    require(gateway['inert'] is True and gateway['provider_state_mounted'] is False and gateway['mounts'] == [],
            'gateway inert / no mounts / no provider state')
    origin = w['preparation']['attachment']['origin']
    require(origin['container'] == gateway['container_id'] and origin['process_start'] == gateway['start']
            and origin['network'] == dict(zip(('dev', 'ino'), gateway['source_namespace']))
            and w['preparation']['attachment']['source'] == origin['network'], 'gateway original native identity')
    require(w['preparation']['data_network'] == origin['network']
            and gateway['source_namespace'] != gateway['host_network_namespace'], 'gateway data namespace distinct from host')
    require(inputs['nonce'] == descriptor['nonce'] == rows['owner_probe'][0]['nonce']
            and descriptor['primary'] == w['preparation']['member'] == inputs['profiles'][0]['member'], 'input nonce/member')
    require(inputs['synthetic_only'] is True and inputs['private_bytes_in_argv_environment_or_configuration'] is False
            and inputs['keys_created_outside_rust_parent'] is True, 'synthetic input boundary')
    env = rows['secret_attachment_environment'][0]
    require(env['schema'] == 1 and env['sampled_during_native_operation'] is False and env['whole_vm_only'] is True
            and 0 <= env['before']['started_at'] <= env['before']['finished_at'] <= w['preparation']['requested_at']
            <= w['final_process_verified_at'] <= env['after']['started_at'] <= env['after']['finished_at'],
            'environment: before/Bootstrap/after monotonic order and observational scope')
    host = w['host_addition']
    require(host['single_down_host_addition_observed'] is True and host['isolated_pair_creation_observed'] is True
            and host['canonical_host_addition_acknowledged'] is True
            and host['host_addresses_routes_rules_preserved'] is True, 'host addition success observations')
    final_link = w['preparation']['host_link'][3]
    require(final_link['kind'] == 'move' and final_link['birth'] is not None
            and final_link['verified_at'] is not None and final_link['result'] is not None
            and final_link['addition'] is not None and final_link['addition'][1] == c['host_allowed_index'],
            'canonical completed original host move/addition')
    require(final_link['result'] == host['operations'][3]['result']
            and final_link['result']['host']['index'] == c['host_allowed_index'],
            'canonical host move / recorded native operation result')
    for path, obj in objects(w):
        if 'host' in obj and type(obj['host']) is dict and 'index' in obj['host']:
            link = obj['host']
            if link['index'] == c['host_allowed_index']:
                require(link['name'] == c['host_allowed_name'] and link['up'] is False and link['kind'] == 'veth',
                        path + ': original down host veth')
    admissions = rows['secret_attachment_admission']
    require(admissions[0]['content']['image_id'] == gateway['image_id']
            and admissions[0]['content']['program_manifest_sha256'] == gateway['program_manifest_sha256'] == descriptor['program_manifest_sha256']
            and admissions[1]['content']['artifact_sha256'] == record['artifact_sha256']
            and [admissions[1]['content']['network_dev'], admissions[1]['content']['network_ino']] == gateway['host_network_namespace'],
            'admission image/artifact/host namespace')


def baseline_consistency(w, record, rows):
    meta = rows['secret_host_baseline'][0]
    template = strict_json((ROOT / CANDIDATE.parent / 'authored-host-baseline-debian-clean-x86_64.json').read_bytes())
    descriptor = rows['secret_attachment_descriptor'][0]
    namespace = dict(zip(('dev', 'ino'), rows['secret_attachment_gateway'][0]['host_network_namespace']))
    expected = dict(schema_version=1, deployment_id=descriptor['deployment_id'], generation=descriptor['allocation']['generation'],
                    allocation_digest=descriptor['allocation_digest'], host_namespace=namespace, baseline=template['baseline'])
    require(meta['declaration'] == expected and meta['sha256'] == hashlib.sha256(canonical(expected)).hexdigest()
            and meta['bytes'] == len(canonical(expected)), 'baseline declaration/digest/size')
    for key, record_key in [('builder_sha256', 'baseline_declaration_builder_sha256'),
                            ('template_sha256', 'host_baseline_template_sha256'), ('review_sha256', 'baseline_reconciliation_sha256')]:
        require(meta[key] == record[record_key], 'baseline.' + key)
    require(meta['template_baseline_sha256'] == template['baseline_sha256'] == hashlib.sha256(canonical(template['baseline'])).hexdigest()
            and w['host_addition']['admission']['declared_baseline'] == template['baseline']
            and w['host_addition']['admission']['namespace'] == namespace
            and w['host_addition']['admission']['declaration'] == list(bytes.fromhex(meta['sha256']))
            and meta['authored_public_input_only'] is meta['projection_matched_authored_shape'] is True,
            'host admission matches frozen authored baseline')
    host = rows['secret_quarantine_host'][0]
    require(host['bytes'] == len(canonical(host['declaration']))
            and host['sha256'] == hashlib.sha256(canonical(host['declaration'])).hexdigest()
            and host['builder_sha256'] == record['host_declaration_builder_sha256']
            and host['declaration']['host_namespace'] == namespace, 'quarantine host declaration binding')
    declaration = host['declaration']
    require(namespace['dev'] > 0 and namespace['ino'] > 0, 'original host namespace positive identity')
    require(declaration['schema_version'] == 1 and declaration['deployment_id'] == descriptor['deployment_id']
            and declaration['generation'] == descriptor['allocation']['generation']
            and declaration['member'] == descriptor['primary']
            and declaration['allocation_digest'] == descriptor['allocation_digest'], 'original quarantine host allocation')
    digest = list(bytes.fromhex(host['sha256']))
    for path,obj in objects(w):
        if 'host_declaration' in obj:
            require(obj['host_declaration'] == digest, path + ': original quarantine host declaration')
    wan = w['host_addition']['producer_binding']['assembly']['quarantine']['wan']
    uplink = declaration['wan']
    name = uplink['name']
    allocated_names = {exit[key] for exit in descriptor['allocation']['exits']
                       for key in ('host_interface','data_interface','wireguard_interface')}
    require(uplink['index'] > 0 and 0 < len(name.encode()) <= 15
            and re.fullmatch(r'[A-Za-z0-9_.-]+', name) is not None
            and name not in ('lo','tailscale0') and name not in allocated_names
            and any(uplink['address']) and uplink['address'][0] & 1 == 0,
            'original declared WAN index/name/unicast nonzero MAC/allocation disjointness')
    same_fields(wan,declaration['wan'],('name','index','address'),'original declared WAN')
    require(wan['host_namespace'] == namespace and wan['declaration_digest'] == digest, 'original WAN declaration/namespace')


def validate(raw_path):
    receipt = dict(schema=1, validator_revision=6, run=410, raw_record=str(raw_path), verdict='FAIL', checks=[],
                   full_bootstrap_witness_validation='FAIL', runtime_acceptance=False,
                   validator_sha256=VALIDATOR_SHA256,
                   extractor_sha256=EXTRACTOR_SHA256,
                   contract_sha256=CONTRACT_SHA256,guard_counts=GUARD_COUNTS,predicate_counts=PREDICATE_COUNTS,
                   verdict_scope='implemented recorded-consistency checks only; complete contract validation INCOMPLETE',
                   complete_predicate_validation=False,source_closure='conservative lexical; compiler closure NOT_PROVEN',
                   frozen_helper_scope='historical retained run410 copies for fresh-baseline.py and phase3-readonly-preflight.py; no current helper/lab readiness',
                   release_ready=False, does_not_prove=LIMITS,
                   validation_scope='offline recorded run410 successful witness consistency; no live custody',
                   supersedes=['target/run410-evidence/witness-validation.json',
                               'target/run410-evidence/witness-validation-r2.json',
                               'target/run410-evidence/witness-validation-r3.json',
                               'target/run410-evidence/witness-validation-r4.json',
                               'target/run410-evidence/witness-validation-r5.json'])

    def check(name, references, function):
        row = dict(name=name, status='PASS', references=references)
        try:
            result = function()
        except (ValueError, KeyError, TypeError, IndexError, OSError, StopIteration, OverflowError, RecursionError) as error:
            row.update(status='FAIL', error=type(error).__name__ + ': ' + str(error))
            result = None
        receipt['checks'].append(row)
        return result

    def read_record():
        raw = Path(raw_path).read_bytes()
        require(0 < len(raw) < 8*1024*1024, 'raw record size bound')
        receipt['raw_record_sha256'] = hashlib.sha256(raw).hexdigest()
        return strict_json(raw)

    record = check('strict_record_json', ['raw JSON: no duplicate keys or nonfinite numbers'], read_record)
    if record is None:
        return receipt
    check('typed_record', ['raw record: closed run410 envelope'], lambda: typed(record, 'RunRecord', 'record'))
    parsed = check('stdout_rows', ['record.stdout lines 1-14: closed ordered rows, one witness'], lambda: stdout_rows(record))
    if parsed is not None:
        w, rows, references = parsed
        receipt['stdout_line_references'] = references
        check('typed_witness', ['record.stdout line 13 LAB_SECRET_BOOTSTRAP: closed recursive types'], lambda: typed(w, 'BootstrapWitness', 'witness'))
        if receipt['checks'][-1]['status'] == 'FAIL':
            return receipt
        check('frozen_bindings', ['record.source_binding, *_sha256, run_reservation', str(RESERVATION), str(CANDIDATE)], lambda: frozen_bindings(record))
        for name, refs, fn in [
            ('bootstrap_success', ['stdout:13 schema/fault/nulls/acknowledgments/retention/parent_pristine/39 negatives; intent index/PID/start at writers 87/90'], lambda: bootstrap_success(w, record)),
            ('preparation_success', ['stdout:13 preparation success guards/entry_producer/87-writer prefix/16 retained fields', 'attachment/operational/bootstrap.rs:1028-1069'], lambda: preparation_success(w)),
            ('retained_success', ['stdout:13 retained successful emitter continuations; host intent writer75/oracle20/operations'], lambda: retained_success(w)),
            ('contract_guards', ['per-predicate enforced/absence-proved/pending accounting; full semantic coverage is separate'], contract_guards),
            ('allocation_contract', ['AllocationRecord::validate; complete public allocated resource plan'], lambda: allocation_contract(w, rows)),
            ('host_observation_bounds', ['HostObservation::validate: serialized namespace/count/string/TUN bounds'], lambda: host_observation_bounds(w, rows)),
            ('contract_success', ['source contract success_rules; native Link/WG plan/WAN/nonzero addition/journal/capacity'], lambda: contract_success(w, rows)),
            ('canonical_histories', ['stdout:13 all retained preparation histories and canonical publication chains'], lambda: canonical_histories(w, rows)),
            ('observation_bindings', ['BINDING_REGISTRY: every observation to its canonical history; explicit canonical roots',
                                      'attachment/provision.rs:878-885; attachment/movement.rs:824-835'], lambda: bind_observations(w, rows)),
            ('recorded_emitters', ['stdout:13 retained constructor/result receipts and resource identities'], lambda: recorded_emitters(w, rows)),
            ('writer_histories', ['stdout:13 every retained original writer, exact phase/window/status schedule'], lambda: writer_histories(w)),
            ('charge_conservation', ['stdout:13 charges_before_drop/charges_after_drop/handoff.charges_*'], lambda: charge_conservation(w)),
            ('handoff', ['stdout:13 handoff.complete/job counts/reservation/resources/preparation'], lambda: handoff(w)),
            ('no_authority', ['stdout:13 recursive *_authorized/multi_exit_runtime_proven/requirement8_complete', 'raw component scope; stdout:5-7'], lambda: no_authority(w, record, rows)),
            ('owner_identity', ['record.guest_boot_id; stdout:5,9,11,13 canonical owner epochs'], lambda: owner_identity(w, record, rows)),
            ('monotonic_deadlines', ['stdout:13 recursive births/requests/results/writers/scope_process_verified_at'], lambda: monotonic_deadlines(w)),
            ('bootstrap_scopes', ['stdout:13 operations/queries/preparation.bootstrap/bootstrap_queries/netfilter/writers'], lambda: bootstrap_scopes(w, rows)),
            ('controller_consistency', ['stdout:1-5,8-10,12-14 controller/gateway/original native identity/down host link'], lambda: controller_consistency(w, record, rows)),
            ('baseline_consistency', ['stdout:6-8,13 host_addition.admission; frozen authored baseline'], lambda: baseline_consistency(w, record, rows)),
        ]:
            check(name, refs, fn)
    if all(row['status'] == 'PASS' for row in receipt['checks']):
        receipt['verdict'] = 'PASS'
        receipt['full_bootstrap_witness_validation'] = ('PASS' if receipt['complete_predicate_validation'] else 'INCOMPLETE')
    return receipt


def save_receipt(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('receipt', type=Path, nargs='?')
    args = parser.parse_args()
    receipt = validate(args.record)
    data = (json.dumps(receipt, indent=2, allow_nan=False) + '\n').encode()
    if args.receipt is not None:
        try:
            save_receipt(args.receipt, data)
        except OSError as error:
            print('receipt_create_failed: ' + str(error), file=sys.stderr)
            return 1
    print(data.decode(), end='')
    return 0 if receipt['verdict'] == 'PASS' else 1


# Build after every referenced check function exists; reject unmapped guards
# before either CLI validation or receipt creation. No subprocess is executed.
GUARD_DISPOSITIONS = guard_dispositions()
GUARD_COUNTS = dict(extracted=len(GUARD_DISPOSITIONS),
                    enforced=sum(d['status']=='enforced' for d in GUARD_DISPOSITIONS.values()),
                    partial=sum(d['status']=='partial' for d in GUARD_DISPOSITIONS.values()))
PREDICATE_COUNTS = dict(extracted=sum(len(d['predicates']) for d in GUARD_DISPOSITIONS.values()),
                       **{status:sum(p['status']==status for d in GUARD_DISPOSITIONS.values() for p in d['predicates'].values())
                          for status in ('enforced','unenforceable_offline','pending')})

if __name__ == '__main__':
    sys.exit(main())
