"""Pure ARM history/source/receipt and comparison mutants. No VM or staging."""
import contextlib
import copy
import datetime
import hashlib
import io
import json
import pathlib
import runpy
import subprocess
import sys

if not __debug__:
    raise RuntimeError('optimized_python_refused')

MODULE_PATH = pathlib.Path('target/platform-lab/host_baseline_arm_history.py')
MODULE_BYTES = MODULE_PATH.read_bytes()
module = {'__name__': 'arm_history_smoke', '__file__': str(MODULE_PATH)}
exec(compile(MODULE_BYTES, str(MODULE_PATH), 'exec'), module)
AUTHOR_PATH = pathlib.Path('target/author-arm-host-baseline-template.py')
AUTHOR_BYTES = AUTHOR_PATH.read_bytes()
SELF_BYTES = pathlib.Path(__file__).read_bytes()
canonical = module['canonical']
digest = module['digest']
rows = []


def passed(name, condition=True):
    assert condition, name
    rows.append(name)


def refuse(name, action):
    try:
        action()
    except (AssertionError, KeyError, ValueError, TypeError, StopIteration):
        rows.append(name + '_refused')
    else:
        raise AssertionError(name + '_accepted')


captured = {key: pathlib.Path(path).read_bytes() for key, (path, _) in module['HISTORY'].items()}
root = pathlib.Path('target/continuation-20261028T080736Z')
projection_dir = root / 'host-projection-debian-arm64'
dependencies = dict(
    prior=pathlib.Path('target/platform-lab/host_baseline_prior.py').read_bytes(),
    schema=pathlib.Path('target/platform-lab/host_baseline_declaration.py').read_bytes(),
    projection_controller=(projection_dir / 'controller.py').read_bytes())
modules = module['load_dependencies'](dependencies)
history = module['verify_history'](captured)
expected = module['reconstruct_expected'](history, modules)
passed('bound_historical_reconstruction', [len(expected[k]) for k in ('links', 'addresses', 'routes', 'rules')] == [106, 109, 327, 5])
current = [(root / name).read_bytes() for name in ('candidate.json', 'source.tar', 'arm64.payload')]
projection_raw = (projection_dir / 'record.json').read_bytes()
ssh_raw = (projection_dir / 'ssh.stdout').read_bytes()
candidate, record = module['validate_current'](*current, projection_raw, ssh_raw, modules)
observed = record['report']['projection']
baseline = module['reconcile'](expected, observed, modules['schema'])
passed('exact_frozen_projection_comparison', module['same'](baseline, observed))
passed('seven_explicit_policies', len(module['POLICIES']) == 7)
passed('wan_index_labeled_expectation', module['POLICIES'][0]['classification'] == 'AUTHORED_EXPECTATION_NOT_ORIGINAL_RECEIPT')
passed('no_current_object_reuse', all(a is not b for key in ('links', 'addresses', 'routes', 'rules') for a, b in zip(baseline[key], observed[key])))

for key in ('prior_metadata', 'prior_index', 'run261', 'run263', 'run264', 'run277', 'actors277',
        'early_candidate', 'late_candidate', 'early_source', 'late_source', 'early_artifact',
        'late_artifact', 'runner261', 'runner263', 'runner264_277'):
    changed = dict(captured)
    changed[key] += b' '
    refuse('pinned_' + key, lambda changed=changed: module['verify_history'](changed))
for key in dependencies:
    changed = dict(dependencies)
    changed[key] += b'\n'
    refuse('captured_dependency_' + key, lambda changed=changed: module['load_dependencies'](changed))
changed = dict(captured)
changed['unexpected_history'] = b'{}'
refuse('unknown_history_input', lambda: module['verify_history'](changed))

# Receipt facts are tested independently of the outer byte pins too.
for name, mutate in (
    ('original_host_index', lambda h: h['actors277']['journal_entries'][0]['links'].update(host_index=160)),
    ('original_host_index_float', lambda h: h['actors277']['journal_entries'][0]['links'].update(host_index=159.0)),
    ('original_transport_index', lambda h: h['actors277']['journal_entries'][0]['links'].update(transport_index=3)),
    ('original_host_namespace', lambda h: h['actors277']['journal_entries'][0]['links']['host_namespace'].update(ino=4026531841)),
    ('unknown_receipt_field', lambda h: h['actors277']['journal_entries'][0]['links'].update(authority=True)),
    ('original_record_sha', lambda h: h['actors277'].update(record_sha256='1' * 64)),
    ('original_source_commit', lambda h: h['actors277'].update(source_commit='1' * 40)),
    ('historical_failure_reclassified', lambda h: h['run277'].update(exit_code=0, result='PASS')),
    ('historical_not_read_only', lambda h: h['prior_metadata'].update(read_only=False)),
):
    changed = copy.deepcopy(history)
    mutate(changed)
    refuse(name, lambda changed=changed: module['reconstruct_expected'](changed, modules))

# Current identity/binding mutants cannot alter the reviewed source contract.
for name, position in (('candidate', 0), ('source_archive', 1), ('artifact', 2)):
    changed = list(current)
    changed[position] += b' '
    refuse('current_' + name, lambda changed=changed: module['validate_current'](*changed, projection_raw, ssh_raw, modules))
for name, mutate in (
    ('source_binding', lambda r: r['source_binding'].update(source_commit='1' * 40)),
    ('artifact_binding', lambda r: r.update(artifact_sha256='1' * 64)),
    ('controller_binding', lambda r: r.update(controller_sha256='1' * 64)),
    ('authority', lambda r: r.update(host_authority_granted=True)),
    ('staged', lambda r: r.update(declaration_staged=True)),
    ('private_profiles', lambda r: r.update(private_profile_contents_read=True)),
    ('unknown_record', lambda r: r.update(extra={})),
    ('report_namespace', lambda r: r['report'].update(namespace=[4, 4026531841])),
    ('report_creator', lambda r: r['report'].update(creator_pid=r['report']['creator_pid'] + 1)),
    ('remote_creator', lambda r: r['remote'].update(root_start=r['remote']['root_start'] + 1)),
    ('native_exit', lambda r: r['remote'].update(exit_code=1)),
    ('native_timeout', lambda r: r['remote'].update(timed_out=True)),
):
    changed = copy.deepcopy(record)
    mutate(changed)
    refuse('projection_' + name, lambda changed=changed: module['validate_current'](*current, canonical(changed), ssh_raw, modules))

# Coherent observed changes preserve envelope provenance, so only independent
# expected-value comparison can reject them. Never fill absent/default fields.
for name, mutate in (
    ('learn_wan_index', lambda s: s['links'][-2].update(index=1580)),
    ('learn_default_headroom', lambda s: s['links'][0].update(headroom=8)),
    ('learn_original_mtu', lambda s: s['links'][0].update(mtu=s['links'][0]['mtu'] - 1)),
    ('learn_address', lambda s: s['addresses'][0].update(address='127.0.0.2')),
    ('learn_route_metric', lambda s: s['routes'][0].update(metric=s['routes'][0]['metric'] + 1)),
    ('learn_rule', lambda s: s['rules'][0].update(priority=s['rules'][0]['priority'] + 1)),
    ('unknown_link_field', lambda s: s['links'][0].update(new_field=0)),
    ('namespace_boolean', lambda s: s.update(namespace=[True, 4026531840])),
    ('unknown_shape', lambda s: s.update(wireguard={})),
    ('missing_link', lambda s: s['links'].pop()),
    ('duplicate_link', lambda s: s['links'].append(copy.deepcopy(s['links'][0]))),
):
    changed = copy.deepcopy(record)
    mutate(changed['report']['projection'])
    # Keep the original request/process identity and all authority flags.
    changed['remote']['stdout'] = canonical(changed['report']).decode() + '\n'
    coherent_ssh = canonical(changed['remote'])
    def action(changed=changed, coherent_ssh=coherent_ssh):
        _, validated = module['validate_current'](*current, canonical(changed), coherent_ssh, modules)
        module['reconcile'](expected, validated['report']['projection'], modules['schema'])
    refuse(name, action)
extra = copy.deepcopy(observed)
foreign = copy.deepcopy(extra['links'][0])
foreign.update(index=1000001, name='foreign0', alias='unexplained-foreign')
extra['links'].append(foreign)
refuse('extra_current_foreign_object', lambda: module['reconcile'](expected, extra, modules['schema']))
reordered = copy.deepcopy(observed)
for key in ('links', 'addresses', 'routes', 'rules'):
    reordered[key].reverse()
ordered = module['reconcile'](expected, reordered, modules['schema'])
passed('ordering_only_after_full_equality', module['same'](ordered, reordered))
passed('ordering_selects_expected_objects', all(a is not b for key in ('links', 'addresses', 'routes', 'rules') for a, b in zip(ordered[key], reordered[key])))

# Exercise the complete authoring assembly with output intercepted in memory.
# No local input/template/snapshot is created by this check.
wrapper = runpy.run_path(str(AUTHOR_PATH), run_name='arm_author_smoke_not_main')
created = {}
def memory_create(path, raw):
    key = str(path)
    assert key not in created
    created[key] = raw
wrapper['main'].__globals__['create'] = memory_create
old_argv, old_fsync = sys.argv, wrapper['os'].fsync
try:
    sys.argv = [str(AUTHOR_PATH), str(root / 'candidate.json')]
    wrapper['os'].fsync = lambda fd: None
    with contextlib.redirect_stdout(io.StringIO()):
        wrapper['main']()
finally:
    sys.argv = old_argv
    wrapper['os'].fsync = old_fsync
review_path = str(root / 'host-baseline-reconciliation-debian-arm64.json')
template_path = str(root / 'authored-host-baseline-debian-arm64.json')
review = json.loads(created[review_path])
template = json.loads(created[template_path])
passed('author_memory_only_output_count', len(created) == 7)
passed('author_original_wan_receipt_not_claimed', review['original_wan_index_directly_exported'] is False)
passed('author_original_a_receipt_recorded', review['original_a_index_from_historical_journal'] == 159)
passed('author_sequence_expectation_explicit', review['wan_index_sequence_expectation'] == 158)
passed('author_all_policies_retained', len(review['authored_expectations']) == 7)
passed('author_explicit_new_fields', [len(review['explicit_new_object_expectations'][key])
    for key in ('last_two_links','last_two_addresses','last_two_ipv4_routes','ten_new_multicast_routes')] == [2,2,4,10])
passed('author_converter_absent_defaults', review['authored_expectations'][5]['defaults']['links']['headroom'] is None
    and review['authored_expectations'][5]['defaults']['rules']['suppress_prefixlen'] == 4294967295)
passed('author_failed_runs_not_promoted', review['historical_runs264_and277_remain'] == 'FAIL')
passed('author_review_pending', review['independent_review'] == 'PENDING')
passed('author_no_authority', review['declaration_staged'] is review['host_authority_granted'] is False)
passed('author_no_membership_removal', review['foreign_resource_membership_granted'] is review['foreign_resource_removal_granted'] is False)
passed('author_review_bytes_hash', template['review_sha256'] == digest(created[review_path]))
for helper in review['helpers']:
    passed('snapshot_' + pathlib.Path(helper['snapshot']).name,
        helper['sha256'] == digest(created[helper['snapshot']]) and helper['bytes'] == len(created[helper['snapshot']]))
modules['schema']['validate_template'](template, candidate['binding'], 'debian-arm64')
passed('author_template_schema')
for path in (MODULE_PATH, AUTHOR_PATH, pathlib.Path(__file__)):
    result = subprocess.run([sys.executable, '-O', str(path)], capture_output=True, text=True)
    passed('optimized_guard_' + path.name, result.returncode != 0 and 'optimized_python_refused' in result.stderr)
assert MODULE_PATH.read_bytes() == MODULE_BYTES and AUTHOR_PATH.read_bytes() == AUTHOR_BYTES
assert pathlib.Path(__file__).read_bytes() == SELF_BYTES
stamp = datetime.datetime.now(datetime.timezone.utc)
out = pathlib.Path('target') / ('arm-host-baseline-history-tests-' + stamp.strftime('%Y%m%dT%H%M%S%fZ') + '.json')
with out.open('x') as stream:
    json.dump(dict(observed_at_utc=stamp.isoformat(), result='PASS', checks=rows,
        files=[dict(path=str(p), sha256=digest(raw)) for p, raw in ((MODULE_PATH, MODULE_BYTES),
            (AUTHOR_PATH, AUTHOR_BYTES), (pathlib.Path(__file__), SELF_BYTES))],
        native_actions=False, actual_templates_created=False, declaration_staged=False,
        host_authority_granted=False, scope='Pure bound-history, receipt, typed projection, no-value-learning and intercepted local-authoring checks only.'), stream, indent=2)
    stream.write('\n')
print(json.dumps(dict(record=str(out), checks=len(rows), result='PASS', native_actions=False,
    actual_templates_created=False)))
