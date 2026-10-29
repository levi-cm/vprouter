"""Preserve exact four-mode component proof on four isolated platforms."""
import datetime
import hashlib
import json
import pathlib
import subprocess

if not __debug__:
    raise RuntimeError('optimized_python_refused')

def read(path):
    return json.loads(pathlib.Path(path).read_text())

def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

candidate_path = pathlib.Path('target/continuation-20261028T044917Z/candidate.json')
c = read(candidate_path)
d = candidate_path.parent
binding = json.loads(subprocess.check_output([
    'python3', 'tools/verify-frozen-build-inputs.py', c['source'], c['source_commit']]))
assert binding == c['binding'] and sha(c['source']) == c['source_sha256']
for arch, v in c['platforms'].items():
    assert sha(v['artifact']) == v['artifact_sha256']
    assert sha(d / (arch + '.context.tar')) == v['context_sha256']
workspace = read('target/process-inspection-root-verification-20261027/workspace-4bdd241.json')
assert workspace['passed'] == 369 and workspace['failed'] == workspace['exit_code'] == 0

native = []
paths = set()
for n in [*range(369, 381), *range(382, 386)]:
    raw = pathlib.Path(f'target/lab-state/actual-program-run-{n}.json')
    side = pathlib.Path(f'target/lab-state/secret-producer-binding-run-{n}.json')
    r, s = read(raw), read(side)
    assert r['source_binding'] == s['source_binding'] == binding
    assert r['exit_code'] == 0 and s['record_sha256'] == sha(raw)
    proof = s['proof']['producer_binding']
    fault = s['witness']['fault']
    assert proof['ordered_writers_verified'] == (73 if fault in (1, 3) else 75)
    assert proof['original_operation_clocks_verified'] == 18
    assert proof['canonical_producer_published'] is (fault == 0)
    assert proof['final_whole_chain_drop_verified'] is True
    assert s['allnine_complete'] is s['requirement8_complete'] is False
    native.append(dict(run=n, platform=r['platform'], mode=r['component_test_mode'], result=r['result']))
    paths.update((raw, side))
assert len({(r['platform'], r['mode']) for r in native}) == 16

history = []
for directory, runs in [
    ('20261028T012007Z', (322, 323)), ('20261028T040347Z', (365,)),
    ('20261028T042100Z', (366,)), ('20261028T043804Z', (368,)),
]:
    index_path = pathlib.Path('target/continuation-' + directory + '/partial-checkpoint-index.json')
    index = read(index_path)
    for n in runs:
        raw = pathlib.Path(f'target/lab-state/actual-program-run-{n}.json')
        entry = next(e for e in index['entries'] if e['path'] == str(raw))
        assert raw.stat().st_size == entry['bytes'] and sha(raw) == entry['sha256']
        assert read(raw)['exit_code'] != 0
        paths.add(raw)
    history.append(dict(index=str(index_path), sha256=sha(index_path), failed_runs=list(runs)))
    paths.add(index_path)

names = read('target/continuation-20261028T043804Z/partial-checkpoint-index.json')['entries']
collector_names = {pathlib.Path(e['path']).name for e in names if '/root-collectors/' in e['path']}
collector_names.discard('build-a95ac92-partial-index.py')
collector_names.add(pathlib.Path(__file__).name)
keepers = d / 'root-collectors'
keepers.mkdir(mode=0o700)
for name in sorted(collector_names):
    candidates = [pathlib.Path('target') / name, pathlib.Path('target/platform-lab') / name]
    selected = next(p for p in candidates if p.is_file())
    with (keepers / name).open('xb') as stream:
        stream.write(selected.read_bytes())
paths.update(p for p in d.rglob('*') if p.is_file() and p.suffix in ('.json', '.py', '.stderr', '.log') and not any(part.endswith('-regression') for part in p.parts))
paths.update(pathlib.Path('target/process-inspection-root-verification-20261027').glob('*4bdd241*'))
paths.update(p for p in pathlib.Path('target').glob('4bdd241*.log') if 'normal' not in p.name)
paths.add(pathlib.Path('target/lab-state/producer-binding-evidence-smokes-20261028T044532Z.json'))
entries = [dict(path=str(p), bytes=p.stat().st_size, sha256=sha(p)) for p in sorted(paths)]
out = dict(
    observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    source_binding=binding, workspace=workspace, native_results=native,
    program_partial_passes=16, program_failures=0, entries=entries,
    historical_failures_preserved=history, allnine_complete=False,
    requirement8_complete=False, real_client_acceptance='NOT_RUN',
    scope='Component custody and Creating-only canonical group binding. Four modes on fresh Debian AMD64, retained Debian AMD64, Arch AMD64 and emulated Debian ARM64. Original 69-writer/17-window assembly remains intact; full cases use75/73/75/73 writers and18 original windows. Failed Result writer retains its exact original charge through cancellation, collection, retries and outer Drop; no capacity release. No placement, permit, health READY, UP, cleanup/reuse, parent-death reconciliation, operational1/5/6 runtime, real provider/client, full secret boundary, migration, lifecycle, controlled performance or24h acceptance.')
destination = d / 'partial-checkpoint-index.json'
with destination.open('x') as stream:
    json.dump(out, stream, indent=2)
    stream.write('\n')
print(json.dumps(dict(record=str(destination), sha_bound_entries=len(entries), program_partial_passes=16, program_failures=0, allnine_complete=False)))
