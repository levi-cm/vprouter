"""Strict frozen HOST evidence collection; no mutation or native invocation."""
import datetime
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import sys

if not __debug__:
    raise RuntimeError('optimized_python_refused')

# Snapshot all local executable dependency bytes before executing any helper.
# The sidecar hashes exactly these compiled bytes, never a later filesystem read.
ROOT = pathlib.Path(__file__).resolve().parent
DEPENDENCY_NAMES = (
    'collect-secret-host-addition.py', 'host_addition_evidence_schema.py',
    'collect-secret-producer-binding.py', 'producer_binding_evidence_schema.py',
    'collect-secret-assembly.py', 'assembly_evidence_schema.py',
    'collect-secret-quarantine.py', 'quarantine_evidence_base.py',
    'quarantine_history_schema.py', 'quarantine_native_schema.py', 'quarantine_producer_schema.py',
    'collect-secret-movement.py', 'movement_evidence_base.py',
    'collect-secret-provision.py', 'provision_evidence_base.py', 'wireguard_inventory_schema.py',
    'platform-lab/selftest_mechanics.py', 'platform-lab/host_baseline_declaration.py')
DEPENDENCY_BYTES = {str(ROOT / name): (ROOT / name).read_bytes() for name in DEPENDENCY_NAMES}
EXECUTED_DEPENDENCY_BYTES = {}

class FrozenLoader:
    """Compile captured bytes while preserving imports of existing helper names."""
    def __init__(self, path): self.path = path
    def create_module(self, spec): return None
    def exec_module(self, module):
        module.__file__ = self.path
        raw = DEPENDENCY_BYTES[self.path]
        exec(compile(raw, self.path, 'exec'), module.__dict__)
        EXECUTED_DEPENDENCY_BYTES[self.path] = raw

class FrozenFinder:
    def find_spec(self, fullname, path=None, target=None):
        candidate = str(ROOT / (fullname.rsplit('.', 1)[-1] + '.py'))
        if candidate in DEPENDENCY_BYTES:
            return importlib.util.spec_from_loader(fullname, FrozenLoader(candidate), origin=candidate)
        return None

# Existing collectors load named paths through spec_from_file_location and two
# helpers compile direct read_bytes themselves. Verify that every byte they
# actually read is the snapshot; reject changes before or during validation.
def verify_dependency_snapshot():
    assert all(pathlib.Path(path).read_bytes() == raw for path, raw in DEPENDENCY_BYTES.items())

frozen_finder = FrozenFinder()
sys.meta_path.insert(0, frozen_finder)
from quarantine_evidence_base import validate_prefix
from host_addition_evidence_schema import validate_host_addition, shape_bytes, shape_path
# Freeze legacy path-based dynamic loads too. Their nested imports use this
# exact importlib module object; restore it once loading finishes.
original_file_spec = importlib.util.spec_from_file_location
def frozen_file_spec(name, location, *args, **kwargs):
    path = str(pathlib.Path(location).resolve())
    if path in DEPENDENCY_BYTES:
        return importlib.util.spec_from_loader(name, FrozenLoader(path), origin=path)
    return original_file_spec(name, location, *args, **kwargs)
importlib.util.spec_from_file_location = frozen_file_spec
binding_path = ROOT / 'collect-secret-producer-binding.py'
spec = importlib.util.spec_from_loader('host_addition_producer_binding', FrozenLoader(str(binding_path)))
binding = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(binding)
finally:
    importlib.util.spec_from_file_location = original_file_spec
    sys.meta_path.remove(frozen_finder)
assert binding.assembly.mechanics_bytes == DEPENDENCY_BYTES[str(ROOT / 'platform-lab/selftest_mechanics.py')]
assert shape_bytes == DEPENDENCY_BYTES[str(shape_path.resolve())]
EXECUTED_DEPENDENCY_BYTES[str(ROOT / 'platform-lab/selftest_mechanics.py')] = binding.assembly.mechanics_bytes
EXECUTED_DEPENDENCY_BYTES[str(shape_path.resolve())] = shape_bytes
# The entry script is interpreted by Python; all helper modules must have gone
# through the snapshot loader or the two checked explicit compile calls.
EXECUTED_DEPENDENCY_BYTES[str(pathlib.Path(__file__).resolve())] = DEPENDENCY_BYTES[str(pathlib.Path(__file__).resolve())]
assert EXECUTED_DEPENDENCY_BYTES == DEPENDENCY_BYTES, 'preimported_or_unexecuted_dependency_refused'
verify_dependency_snapshot()

def validate_complete(c):
    verify_dependency_snapshot()
    old = binding.validate_complete(c, continuation=True)
    assert old['producer_binding']['producer_binding_original_context_continued'] is True
    assert old['producer_binding']['final_whole_chain_drop_verified'] is False
    proof = dict(producer_binding=old, host_addition=validate_host_addition(c))
    verify_dependency_snapshot()
    return proof

def loads_unique(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            assert key not in value, 'duplicate_json_key_refused'
            value[key] = item
        return value
    def reject_constant(value):
        raise ValueError('nonfinite_json_constant_refused:' + value)
    return json.loads(raw, object_pairs_hook=unique, parse_constant=reject_constant)

def collect(candidate, label):
    candidate_path = pathlib.Path(candidate)
    candidate_bytes = candidate_path.read_bytes()
    loads_unique(candidate_bytes)
    c = validate_prefix(candidate, label, host_addition=True)
    r, path = c['record'], c['path']
    loads_unique(c['raw'])
    for line in r['stdout'].splitlines():
        payload = line.removeprefix('LAB_SECRET_HOST_ADDITION ')
        try:
            json.loads(payload)
        except ValueError:
            continue
        loads_unique(payload)
    proof = validate_complete(c)
    assert candidate_path.read_bytes() == candidate_bytes, 'candidate_changed_during_validation'
    run = re.fullmatch(r'actual-program-run-([0-9]+)\.json', path.name)[1]
    out = dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        record=str(path), record_sha256=hashlib.sha256(c['raw']).hexdigest(),
        candidate=str(candidate_path), candidate_sha256=hashlib.sha256(candidate_bytes).hexdigest(),
        directory_label=label, source_archive_sha256=r['source_archive_sha256'],
        source_binding=r['source_binding'], artifact_sha256=r['artifact_sha256'], context_sha256=r['context_sha256'],
        platform=r['platform'], component_test_mode=r['component_test_mode'],
        collectors=[dict(path=path, sha256=hashlib.sha256(raw).hexdigest()) for path, raw in EXECUTED_DEPENDENCY_BYTES.items()],
        input_manifest=c['manifest'], gateway=c['gateway'], host_declaration=c['host'],
        host_baseline=c['host_baseline'], host_baseline_declaration=c['host_baseline_declaration'],
        witness=c['host_addition_top'], environment=c['environment'], proof=proof,
        native_acceptance=False, real_client_acceptance='NOT_RUN', requirement8_complete=False, allnine_complete=False,
        limit='Component evidence only. Four original socket/pair/socket/move operations retain one declared generation and bind the exact Rust-computed planned index; 75 original writers/18 windows remain unchanged. Actual parent HOST projection preserves declared links, addresses, routes and rules plus one original DOWN endpoint. Faults retain original owners, proposals and charges. Parsed metadata grants no custody. Socket identity/sequence and role origins, immutable index derivation and collision refusal are SOURCE_REVIEWED internal checks, not separately exported native receipts. HostObservation has no neighbors; external structural neighbor preservation is separate. No placement, UP, health READY, neighbor mutation, cleanup, real client/provider, full secret lifetime, runtime or release acceptance.')
    destination = ROOT / 'lab-state' / ('secret-host-addition-run-' + run + '.json')
    verify_dependency_snapshot()
    with destination.open('x') as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(out, stream, indent=2, allow_nan=False)
        stream.write('\n')
    return dict(record=str(destination), platform=r['platform'], fault=c['host_addition_fault'],
        **proof['host_addition'], requirement8_complete=False)

if __name__ == '__main__':
    assert len(sys.argv) == 3
    print(json.dumps(collect(sys.argv[1], sys.argv[2]), allow_nan=False))
