"""Compile source-bound identities; schema availability never invents an identity.

The catalog is author-maintained source data. The schema selects applicable
identities and must not silently make an unimplemented identity available.
"""
import copy
import itertools
import json
from pathlib import Path

ROOT = Path(__file__).parent
CATALOG = json.loads((ROOT/'kernel-identities.json').read_text())


def numeric_paths(schema):
    def walk(node, path=''):
        if '$ref' in node:
            yield from walk(schema['$defs'][node['$ref'].split('/')[-1]], path)
            return
        types = node.get('type', [])
        if type(types) is str:
            types = [types]
        if ('integer' in types or type(node.get('const')) is int or
                any(type(v) is int for v in node.get('enum', []))):
            yield path
        for key, value in node.get('properties', {}).items():
            yield from walk(value, path+'/'+key)
        for value in node.get('patternProperties', {}).values():
            yield from walk(value, path+'/*')
        if type(node.get('additionalProperties')) is dict:
            yield from walk(node['additionalProperties'], path+'/*')
        if 'items' in node:
            yield from walk(node['items'], path+'/*')
        for branch in ('anyOf', 'oneOf', 'allOf'):
            for value in node.get(branch, []):
                yield from walk(value, path)
    return set(walk(schema))


def derive_relations(schema, catalog=CATALOG):
    paths = numeric_paths(schema)
    result = []
    for identity in catalog['identities']:
        if not set(identity['quantities']) <= paths:
            continue
        if not identity['checks']:
            raise ValueError('recorded_identity_without_check:'+identity['id'])
        for template in identity['checks']:
            rule = copy.deepcopy(template)
            rule['catalog_identity'] = identity['id']
            result.append(rule)
    return result


def operand_names(node):
    """Final field names of DSL references in a relation operand tree."""
    if type(node) is str:
        return {node.split('.')[-1]} if '.' in node else set()
    if type(node) is list:
        return set().union(*(operand_names(value) for value in node)) if node else set()
    return set()


def relation_side_names(rule, side):
    if side == 'parent':
        keys = ('parent', 'antecedent')
    else:
        keys = ('consequent', 'children')
    result = set()
    for key in keys:
        result |= operand_names(rule.get(key))
    return result


def relation_child_groups(rule):
    """Operand names of each distinct child expression of a check.

    A pair is covered as siblings only when its two counters occur in two
    distinct children. Two operands summed inside one child expression (for
    example process utime and stime added into one usage child) are not
    siblings of a partition and do not make their pair related.
    """
    return [operand_names(child) for child in rule.get('children', [])]


def counter_pair_problems(catalog, schema, model):
    """Audit the explicit within-source counter-pair decision table.

    The table covers every pair of recorded monotonic counters co-located in
    one native source object. Each pair must name the catalog identity that
    relates its operands, or an explicit no-native-relation reason. A pair that
    appears in an identity's quantity list but not in its check operands is not
    silently counted as related.
    """
    if 'quantities' not in model:
        return []
    problems = []
    paths = numeric_paths(schema)
    monotonic = {entry['path'] for entry in model['quantities'] if entry.get('monotonic')}
    identities = catalog['identities']
    by_id = {identity['id']:identity for identity in identities}
    sources = catalog.get('counter_sources', [])
    if not sources:
        problems.append('missing_counter_sources')
    expected = {}
    assigned = set()
    source_ids = set()
    for source in sources:
        source_id = source.get('id')
        if not source_id or source_id in source_ids:
            problems.append('invalid_or_duplicate_counter_source:'+str(source_id))
        source_ids.add(source_id)
        quantities = source.get('quantities', [])
        if not quantities:
            problems.append('empty_counter_source:'+str(source_id))
        for path in quantities:
            if path in assigned:
                problems.append('duplicate_counter_source_quantity:'+path)
            assigned.add(path)
            if path not in paths:
                problems.append('counter_source_unavailable:'+path)
            if path not in monotonic:
                problems.append('counter_source_not_monotonic:'+path)
        for left, right in itertools.combinations(quantities, 2):
            expected[frozenset((left, right))] = source_id
    for path in sorted(monotonic-assigned):
        problems.append('unassigned_monotonic_counter:'+path)
    actual = {}
    for entry in catalog.get('counter_pairs', []):
        quantities = entry.get('quantities')
        if type(quantities) is not list or len(quantities) != 2 or quantities[0] == quantities[1]:
            problems.append('invalid_counter_pair:'+str(entry.get('source')))
            continue
        pair = frozenset(quantities)
        if pair in actual:
            problems.append('duplicate_counter_pair:'+'|'.join(sorted(pair)))
            continue
        actual[pair] = entry
        if entry.get('source') != expected.get(pair):
            problems.append('counter_pair_source_mismatch:'+'|'.join(sorted(pair)))
        decision = entry.get('decision')
        if decision == 'identity':
            identity = by_id.get(entry.get('identity'))
            if identity is None:
                problems.append('counter_pair_unknown_identity:'+'|'.join(sorted(pair)))
            else:
                if not pair <= set(identity['quantities']):
                    problems.append('counter_pair_identity_unbound:'+'|'.join(sorted(pair)))
                names = {item.split('/')[-1] for item in pair}
                if not any(names <= (relation_side_names(rule, 'parent') | relation_side_names(rule, 'child'))
                           for rule in identity['checks']):
                    problems.append('counter_pair_identity_not_relating:'+'|'.join(sorted(pair)))
        elif decision == 'no_native_relation':
            if not entry.get('reason'):
                problems.append('counter_pair_without_reason:'+'|'.join(sorted(pair)))
            names = {item.split('/')[-1] for item in pair}
            # A pair may share a check expression (e.g. RX and TX both add
            # into traffic), but a no-native decision is contradicted by a
            # direct parent/child or antecedent/consequent relation, or by the
            # two counters being siblings under one partition/containment.
            direct = False
            for identity in identities:
                for rule in identity['checks']:
                    parent = relation_side_names(rule, 'parent')
                    child = relation_side_names(rule, 'child')
                    if (names <= (parent | child) and len(names & parent) == 1
                            and len(names & child) == 1):
                        direct = True
                    groups = relation_child_groups(rule)
                    for index, left_group in enumerate(groups):
                        for right_group in groups[index+1:]:
                            if (len(names & left_group) == 1
                                    and len(names & right_group) == 1
                                    and (names & left_group) != (names & right_group)):
                                direct = True
            if direct:
                problems.append('counter_pair_unrelated_but_identity:'+'|'.join(sorted(pair)))
        else:
            problems.append('counter_pair_decision:'+'|'.join(sorted(pair)))
    for pair in expected.keys()-actual.keys():
        problems.append('missing_counter_pair:'+'|'.join(sorted(pair)))
    return problems


def coverage(model, schema, catalog=CATALOG):
    """Bidirectional, exact template audit, including available-but-unbound IDs."""
    problems = []
    identities = catalog['identities']
    by_id = {i['id']:i for i in identities}
    if len(by_id) != len(identities):
        problems.append('duplicate_identity')
    paths = numeric_paths(schema)
    expected = {}
    for identity in identities:
        if not identity['citations'] or not identity['quantities']:
            problems.append('uncited_or_unbound_identity:'+identity['id'])
        if set(identity['quantities']) <= paths:
            if not identity['checks']:
                problems.append('recorded_identity_without_check:'+identity['id'])
            for rule in identity['checks']:
                if rule['id'] in expected:
                    problems.append('duplicate_catalog_check:'+rule['id'])
                expected[rule['id']] = rule | {'catalog_identity':identity['id']}
    actual = {}
    for rule in model['relations']:
        if rule['id'] in actual:
            problems.append('duplicate_generated_check:'+rule['id'])
        actual[rule['id']] = rule
        if rule.get('catalog_identity') not in by_id:
            problems.append('uncited_generated_check:'+rule['id'])
        if rule != expected.get(rule['id']):
            problems.append('unjustified_generated_check:'+rule['id'])
    for check in expected.keys()-actual.keys():
        problems.append('missing_generated_check:'+check)
    problems.extend(counter_pair_problems(catalog, schema, model))
    return sorted(problems)
