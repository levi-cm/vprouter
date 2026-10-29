"""Synthetic provenance mutants and no-work guards; never invoke a lab VM."""
import ast
import copy
import datetime
import hashlib
import json
import pathlib
import runpy
import subprocess
import sys

if not __debug__:
    raise RuntimeError('optimized_python_refused')

controller = pathlib.Path('target/platform-lab/run-frozen-host-projection.py')
controller_bytes = controller.read_bytes()
self_bytes = pathlib.Path(__file__).read_bytes()
tree = ast.parse(controller_bytes)
namespace = {'json': json}
functions = ast.Module(body=[n for n in tree.body if isinstance(n, ast.FunctionDef)], type_ignores=[])
exec(compile(functions, str(controller), 'exec'), namespace)
validate = namespace['validate_projection_envelope']

def report():
    return dict(schema=1, creator_pid=123, creator_start=345,
        namespace=[4, 777], route_socket=dict(dev=9, ino=778),
        requested_at=100.0, deadline=102.0, verified_at=100.1, polls=14,
        projection=dict(namespace=[4, 777], links=[], addresses=[], routes=[], rules=[]),
        read_only=True, declaration_authority=False, host_change_authority=False)

def envelope():
    return dict(uid=1000, machine='x86_64', root_pid=123, root_start=345,
        root_reaped=True, exit_code=0, timed_out=False, before=99.9, after=100.2,
        retained_executable='/tmp/synthetic-metadata-only/payload',
        stdout=json.dumps(report()), stderr='')

rows = []
validate(envelope(), 'x86_64')
rows.append('synthetic_typed_positive')
mutants = []
for key, value in [('uid', True), ('uid', 0), ('root_pid', True),
    ('root_pid', 2**32), ('root_start', 345.0), ('root_start', 2**64),
    ('exit_code', False), ('exit_code', 1), ('before', True), ('after', float('inf')),
    ('root_reaped', False), ('timed_out', True), ('machine', 'aarch64'),
    ('stderr', 'unexpected'), ('stdout', '{}{}')]:
    mutants.append(('remote_' + key + '_' + repr(value), False, key, value))
for key, value in [('creator_pid', True), ('creator_pid', 124),
    ('creator_start', 345.0), ('creator_start', 2**64), ('polls', True),
    ('polls', 2**32), ('requested_at', True), ('verified_at', 102.0),
    ('deadline', 104.0), ('schema', True), ('read_only', False),
    ('declaration_authority', True), ('host_change_authority', True),
    ('namespace', [True, 777]), ('route_socket', {'dev': 9, 'ino': 778.0})]:
    mutants.append(('report_' + key + '_' + repr(value), True, key, value))
for name, is_report, key, value in mutants:
    value = copy.deepcopy(value)
    data = envelope()
    if is_report:
        witness = report()
        witness[key] = value
        data['stdout'] = json.dumps(witness)
    else:
        data[key] = value
    try:
        validate(data, 'x86_64')
    except (AssertionError, KeyError, TypeError, ValueError):
        rows.append(name + '_refused')
    else:
        raise AssertionError(name)

for key in ('links', 'addresses', 'routes', 'rules'):
    for value in ('', {}):
        data, witness = envelope(), report()
        witness['projection'][key] = value
        data['stdout'] = json.dumps(witness)
        try:
            validate(data, 'x86_64')
        except (AssertionError, KeyError, TypeError, ValueError):
            rows.append('projection_' + key + '_' + type(value).__name__ + '_refused')
        else:
            raise AssertionError(key)

for raw in ('{"a":1,"a":2}', '{"a":{"b":1,"b":2}}', '{"a":NaN}', '{"a":Infinity}'):
    try:
        namespace['loads'](raw)
    except ValueError:
        rows.append('ambiguous_json_refused_' + str(len(rows)))
    else:
        raise AssertionError('ambiguous_json')

candidate = 'target/continuation-20261028T044917Z/candidate.json'
output = pathlib.Path(candidate).parent / 'host-projection-debian-clean-x86_64'
assert not output.exists()
original_argv = sys.argv[:]
original_run, original_check = subprocess.run, subprocess.check_output
calls = []
def refuse(*args, **kwargs):
    calls.append(True)
    raise AssertionError('unexpected_subprocess')
try:
    subprocess.run = subprocess.check_output = refuse
    sys.argv = [str(controller), candidate, 'debian-clean-x86_64']
    try:
        runpy.run_path(str(controller), run_name='__main__')
    except RuntimeError as error:
        assert str(error) == 'frozen_source_missing_metadata_only_host_projection'
    else:
        raise AssertionError('old_candidate_accepted')
finally:
    subprocess.run, subprocess.check_output = original_run, original_check
    sys.argv = original_argv
assert not calls and not output.exists()
rows.append('old_candidate_refused_before_subprocess')
result = subprocess.run([sys.executable, '-O', str(controller), candidate,
    'debian-clean-x86_64'], capture_output=True, text=True)
assert result.returncode != 0 and 'optimized_python_refused' in result.stderr
assert not output.exists()
rows.append('optimized_python_refused_before_work')
assert controller.read_bytes() == controller_bytes
stamp = datetime.datetime.now(datetime.timezone.utc)
directory = pathlib.Path('target/lab-state') / ('host-projection-preparation-' + stamp.strftime('%Y%m%dT%H%M%SZ'))
directory.mkdir(mode=0o700)
for name, content in [('controller.py', controller_bytes), ('smokes.py', self_bytes)]:
    with (directory / name).open('xb') as stream:
        stream.write(content)
record = dict(observed_at_utc=stamp.isoformat(), checks=rows,
    files=[dict(name=name, sha256=hashlib.sha256(content).hexdigest())
        for name, content in [('controller.py', controller_bytes), ('smokes.py', self_bytes)]],
    vm_actions=False, native_projection_acceptance=False,
    declaration_staged=False, host_authority_granted=False,
    scope='Local synthetic provenance validation and preflight refusal only.')
with (directory / 'record.json').open('x') as stream:
    json.dump(record, stream, indent=2)
    stream.write('\n')
print(json.dumps(dict(record=str(directory / 'record.json'), checks=len(rows), native_projection_acceptance=False)))
