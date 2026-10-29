"""Cached standalone receipts and synthetic live-prefix refusal checks only."""
import copy
import datetime
import hashlib
import importlib.util
import json
import pathlib

if not __debug__:
    raise RuntimeError('optimized_python_refused')

p = pathlib.Path('target/collect-secret-producer-binding.py')
spec = importlib.util.spec_from_file_location('binding_continuation', p)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
candidate = 'target/continuation-20261028T044917Z/candidate.json'
drops = ('whole_chain_retained_after_drop', 'producer_binding_context_retained_after_drop',
    'assembly_context_retained_after_drop', 'producer_context_retained_after_drop',
    'quarantine_context_retained_after_drop', 'movement_context_retained_after_drop',
    'original_provision_context_retained_after_drop')
def fresh(mode='success', live=True):
    c = m.validate_prefix(candidate, 'amd64-clean-secret-producer-binding-4bdd241-' + mode,
        producer_binding=True)
    if live:
        w = c['producer_binding_top']
        w['continued_original_context'] = True
        w['charges_after_drop'] = None
        for key in drops:
            w[key] = False
    return c

rows = []
for prefix in ('amd64-clean', 'arch', 'debian', 'arm64'):
    for mode in ('success', 'postbirth-failure', 'result-failure', 'registration-failure'):
        c = m.validate_prefix(candidate, prefix + '-secret-producer-binding-4bdd241-' + mode,
            producer_binding=True)
        proof = m.validate_complete(c)
        assert proof['producer_binding']['final_whole_chain_drop_verified'] is True
        assert proof['producer_binding']['producer_binding_original_context_continued'] is False
        rows.append('cached_standalone_' + prefix + '_' + mode)

proof = m.validate_complete(fresh(), continuation=True)
assert proof['producer_binding']['producer_binding_original_context_continued'] is True
assert proof['producer_binding']['final_whole_chain_drop_verified'] is False
rows.append('synthetic_live_success_prefix')
mutations = [('missing_live', lambda w: w.pop('continued_original_context')),
    ('false_live', lambda w: w.update(continued_original_context=False)),
    ('integer_live', lambda w: w.update(continued_original_context=1)),
    ('invented_after_drop', lambda w: w.update(charges_after_drop=[1, 1]))]
mutations.extend((key, lambda w, key=key: w.__setitem__(key, True)) for key in drops)
for name, change in mutations:
    c = fresh()
    change(c['producer_binding_top'])
    try:
        m.validate_complete(c, continuation=True)
    except (AssertionError, KeyError, TypeError, ValueError):
        rows.append(name + '_refused')
    else:
        raise AssertionError(name)
for mode in ('postbirth-failure', 'result-failure', 'registration-failure'):
    try:
        m.validate_complete(fresh(mode), continuation=True)
    except (AssertionError, KeyError, TypeError, ValueError):
        rows.append('failed_prefix_' + mode + '_refused')
    else:
        raise AssertionError(mode)
for name, c, flag in [('standalone_cannot_claim_live', fresh(), False),
    ('live_requires_live_snapshot', fresh(live=False), True),
    ('typed_continuation', fresh(), 1)]:
    try:
        m.validate_complete(c, continuation=flag)
    except (AssertionError, KeyError, TypeError, ValueError):
        rows.append(name + '_refused')
    else:
        raise AssertionError(name)

files = [pathlib.Path(__file__), p, pathlib.Path('target/producer_binding_evidence_schema.py'),
    m.assembly.mechanics_path]
stamp = datetime.datetime.now(datetime.timezone.utc)
out = pathlib.Path('target/lab-state') / ('binding-continuation-smokes-' + stamp.strftime('%Y%m%dT%H%M%SZ') + '.json')
with out.open('x') as stream:
    json.dump(dict(observed_at_utc=stamp.isoformat(), checks=rows,
        files=[dict(path=str(f), sha256=hashlib.sha256(f.read_bytes()).hexdigest()) for f in files],
        native_acceptance=False, scope='Cached standalone validation plus invented live metadata only; no raw rewrite, new native execution, host admission or host mutation.'), stream, indent=2)
print(json.dumps(dict(record=str(out), checks=len(rows), native_acceptance=False)))
