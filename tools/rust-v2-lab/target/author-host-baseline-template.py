"""Reconcile bound prior evidence; author local input only, never mutate HOST."""
import datetime
import hashlib
import json
import pathlib
import sys

if not __debug__:
    raise RuntimeError('optimized_python_refused')

def read(path):
    return json.loads(pathlib.Path(path).read_text())

def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

candidate_path = pathlib.Path(sys.argv[1])
platform = sys.argv[2]
label, old_run = {'debian-clean-x86_64': ('amd64-clean', 372), 'arch-x86_64': ('arch', 376)}[platform]
candidate = read(candidate_path)
root = candidate_path.parent
prior_root = pathlib.Path('target/continuation-20261028T044917Z')
parent = prior_root / 'partial-checkpoint-index.json'
supplement = prior_root / 'normal-regression-supplement.json'
assert sha(parent) == '88b95547f95174529a9cab3a2f725568f0392bcc8c1164911e9293e792720aff'
assert sha(supplement) == '2eb1b015a48901142b0ff179553a51ed3af87c10798d9f4fccf37a64e1aab8e9'
def bound(index, path):
    entry = next(e for e in read(index)['entries'] if e['path'] == str(path))
    assert pathlib.Path(path).stat().st_size == entry['bytes'] and sha(path) == entry['sha256']

metadata_path = prior_root / (label + '-4bdd241-regression') / 'metadata.json'
namespace_path = pathlib.Path(f'target/lab-state/secret-producer-binding-run-{old_run}.json')
bound(supplement, metadata_path)
bound(parent, namespace_path)
metadata = read(metadata_path)
host_scopes = [s for s in metadata['deployments'][0]['scopes'] if s['scope'] == 'host']
assert len(host_scopes) == 1 and metadata['read_only'] is True
namespace = read(namespace_path)['gateway']['host_network_namespace']
projection_path = root / ('host-projection-' + platform) / 'record.json'
projection = read(projection_path)
assert projection['source_binding'] == candidate['binding'] and projection['platform'] == platform
assert projection['declaration_staged'] is projection['host_authority_granted'] is False
assert sha(projection_path.parent / 'controller.py') == projection['controller_sha256']
modules = {}
captured = {}
for name in ('host_baseline_prior.py', 'host_baseline_declaration.py'):
    path = pathlib.Path('target/platform-lab') / name
    content = path.read_bytes()
    module = {'__name__': 'root_' + path.stem, '__file__': str(path)}
    exec(compile(content, str(path), 'exec'), module)
    modules[name] = module
    captured[name] = content
prior, declaration = modules['host_baseline_prior.py'], modules['host_baseline_declaration.py']
expected = prior['expected_from_prior'](host_scopes[0], namespace, platform)
observed = projection['report']['projection']
declaration['validate_shape'](expected)
assert prior['stable'](expected) == prior['stable'](observed), 'prior_shape_or_authored_uapi_expectation_mismatch'
# Retain only independently expected field values. Ordering is not structural;
# align equal rows to the frozen projection so the fixture's direct Vec equality
# cannot confuse kernel enumeration order with a change of foreign state.
baseline = dict(namespace=expected['namespace'])
for key in ('links', 'addresses', 'routes', 'rules'):
    remaining = list(expected[key])
    baseline[key] = []
    for row in observed[key]:
        index = next(i for i, value in enumerate(remaining) if value == row)
        baseline[key].append(remaining.pop(index))
    assert not remaining
baseline_sha = hashlib.sha256(declaration['canonical'](baseline)).hexdigest()
references = [parent, supplement, metadata_path, namespace_path, projection_path]
reconciliation = dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    source_binding=candidate['binding'], platform=platform, namespace=namespace,
    counts={k: len(baseline[k]) for k in ('links', 'addresses', 'routes', 'rules')},
    baseline_sha256=baseline_sha, references=[dict(path=str(p), sha256=sha(p)) for p in references],
    helpers=[dict(path='target/platform-lab/' + name, sha256=hashlib.sha256(content).hexdigest()) for name, content in captured.items()],
    prior_index_entries_verified=2, prior_structure_reconstructed=True,
    omitted_link_uapi_policy='Explicit absent Debian fields; Arch pacing/tailroom0 and headroom12 only eth0/index2,0 others. No observed value substitution.',
    ordering_only_aligned_after_exact_multiset_comparison=True,
    declaration_staged=False, host_authority_granted=False,
    review_scope='Root-authored preservation-only foreign baseline; independent review pending before native controller use.')
review_path = root / ('host-baseline-reconciliation-' + platform + '.json')
with review_path.open('x') as stream:
    json.dump(reconciliation, stream, indent=2)
    stream.write('\n')
template = dict(schema=1, platform=platform, source_binding=candidate['binding'],
    baseline=baseline, baseline_sha256=baseline_sha,
    prior_evidence=[dict(path=str(p), sha256=sha(p)) for p in references], review_sha256=sha(review_path))
declaration['validate_template'](template, candidate['binding'], platform)
out = root / ('authored-host-baseline-' + platform + '.json')
with out.open('xb') as stream:
    stream.write(declaration['canonical'](template))
out.chmod(0o600)
for name, content in captured.items():
    snapshot = root / ('baseline-authoring-' + platform + '-' + name)
    with snapshot.open('xb') as stream:
        stream.write(content)
print(json.dumps(dict(template=str(out), sha256=sha(out), reconciliation=str(review_path),
    baseline_sha256=baseline_sha, counts=reconciliation['counts'], declaration_staged=False,
    host_authority_granted=False)))
