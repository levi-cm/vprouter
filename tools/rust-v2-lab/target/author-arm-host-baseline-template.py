"""Author local preservation input from reviewed ARM history; never stage it."""
import datetime
import hashlib
import os
import pathlib
import stat
import sys

if not __debug__:
    raise RuntimeError('optimized_python_refused')

ROOT = pathlib.Path('/DATA/AppData/vprouter-rust-v2')
assert pathlib.Path.cwd() == ROOT
AUTHOR_BYTES = pathlib.Path(__file__).read_bytes()
MODULE_PATH = pathlib.Path('target/platform-lab/host_baseline_arm_history.py')
MODULE_BYTES = MODULE_PATH.read_bytes()
module = {'__name__': 'captured_arm_history', '__file__': str(MODULE_PATH)}
exec(compile(MODULE_BYTES, str(MODULE_PATH), 'exec'), module)


def capture(path, maximum=64 * 1024 * 1024):
    """One original nofollow regular file, no later file read for hash/execution."""
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        assert stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
        assert before.st_nlink == 1 and 0 < before.st_size <= maximum
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        stamp = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mode, s.st_nlink, s.st_ctime_ns, s.st_mtime_ns)
        assert stamp(before) == stamp(after) and len(raw) == before.st_size
    return raw


def create(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
        s = os.fstat(stream.fileno())
        assert stat.S_ISREG(s.st_mode) and s.st_uid == os.geteuid() and s.st_nlink == 1
        assert stat.S_IMODE(s.st_mode) == 0o600 and s.st_size == len(raw)


def main():
    assert len(sys.argv) == 2
    candidate_path = pathlib.Path(sys.argv[1])
    expected_root = ROOT / 'target/continuation-20261028T080736Z'
    assert candidate_path.resolve() == expected_root / 'candidate.json'
    candidate_raw = capture(candidate_path, 65536)
    assert module['digest'](candidate_raw) == module['CURRENT_CANDIDATE_SHA']
    candidate = module['loads'](candidate_raw)
    root = candidate_path.parent
    assert pathlib.Path(candidate['source']) == expected_root / 'source.tar'
    assert pathlib.Path(candidate['platforms']['arm64']['artifact']) == expected_root / 'arm64.payload'
    projection_path = root / 'host-projection-debian-arm64/record.json'
    projection_directory = projection_path.parent
    captured = {key: capture(path) for key, (path, _) in module['HISTORY'].items()}
    dependencies = {
        'prior': capture('target/platform-lab/host_baseline_prior.py'),
        'schema': capture('target/platform-lab/host_baseline_declaration.py'),
        'projection_controller': capture(projection_directory / 'controller.py'),
    }
    dependency_paths = {
        'prior': 'target/platform-lab/host_baseline_prior.py',
        'schema': 'target/platform-lab/host_baseline_declaration.py',
        'projection_controller': str(projection_directory / 'controller.py'),
    }
    modules = module['load_dependencies'](dependencies)
    history = module['verify_history'](captured)
    expected = module['reconstruct_expected'](history, modules)
    source_raw = capture(candidate['source'])
    artifact_raw = capture(candidate['platforms']['arm64']['artifact'])
    projection_raw = capture(projection_path, 8 * 1024 * 1024)
    ssh_raw = capture(projection_directory / 'ssh.stdout', 8 * 1024 * 1024)
    candidate, projection = module['validate_current'](candidate_raw, source_raw, artifact_raw,
        projection_raw, ssh_raw, modules)
    baseline = module['reconcile'](expected, projection['report']['projection'], modules['schema'])
    canonical = module['canonical']
    digest = module['digest']
    baseline_sha = digest(canonical(baseline))
    # The detailed policy/rationale exists before any template output. The
    # reconciliation repeats every assumption and remains review-pending.
    policy_report = pathlib.Path('target/arm-host-baseline-history-audit.md')
    policy_report_raw = capture(policy_report, 1024 * 1024)
    assert b'allocation-sequence expectation' in policy_report_raw
    references = [dict(path=path, sha256=digest(captured[key]))
        for key, (path, _) in module['HISTORY'].items() if path.endswith('.json')]
    references.extend([dict(path=str(candidate_path), sha256=digest(candidate_raw)),
        dict(path=str(projection_path), sha256=digest(projection_raw))])
    artifacts = [dict(path=path, bytes=len(captured[key]), sha256=digest(captured[key]))
        for key, (path, _) in module['HISTORY'].items() if not path.endswith('.json')]
    artifacts.extend([
        dict(path=candidate['source'], bytes=len(source_raw), sha256=digest(source_raw)),
        dict(path=candidate['platforms']['arm64']['artifact'], bytes=len(artifact_raw), sha256=digest(artifact_raw)),
        dict(path=str(projection_directory / 'ssh.stdout'), bytes=len(ssh_raw), sha256=digest(ssh_raw)),
    ])
    snapshots = {
        'arm-history-author.py': (str(pathlib.Path(__file__)), AUTHOR_BYTES),
        'host_baseline_arm_history.py': (str(MODULE_PATH), MODULE_BYTES),
        'host_baseline_prior.py': (dependency_paths['prior'], dependencies['prior']),
        'host_baseline_declaration.py': (dependency_paths['schema'], dependencies['schema']),
        'projection-controller.py': (dependency_paths['projection_controller'], dependencies['projection_controller']),
    }
    helpers = []
    for name, (original, raw) in snapshots.items():
        helpers.append(dict(path=original,
            snapshot=str(root / ('baseline-authoring-debian-arm64-' + name)),
            bytes=len(raw), sha256=digest(raw),
            execution='captured function definitions only' if name == 'projection-controller.py' else 'captured bytes'))
    reconciliation = dict(
        observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        source_binding=candidate['binding'], platform='debian-arm64', namespace=baseline['namespace'],
        counts={key: len(baseline[key]) for key in ('links', 'addresses', 'routes', 'rules')},
        baseline_sha256=baseline_sha, references=references, source_artifacts=artifacts, helpers=helpers,
        policy_report=dict(path=str(policy_report), sha256=digest(policy_report_raw)),
        authored_expectations=module['POLICIES'],
        explicit_new_object_expectations=dict(
            last_two_links=[row for row in expected['links'] if row['index'] in (158, 159)],
            last_two_addresses=[row for row in expected['addresses'] if row['index'] in (158, 159)],
            last_two_ipv4_routes=[row for row in expected['routes']
                if row['output'] in (158, 159) and ':' not in row['destination']],
            ten_new_multicast_routes=[row for row in expected['routes']
                if row['output'] in (148,149,150,153,154,155,156,157,158,159)
                and row['destination'] == 'ff00::'],
            field_origin='Complete values exclusively from the reconstructed expected model. WAN158 sequence expectation; A159 original journal index; other fields same-operation historical rows/source and declared converter/kernel policies.'),
        original_wan_index_directly_exported=False, original_a_index_from_historical_journal=159,
        wan_index_sequence_expectation=158, historical_runs264_and277_remain='FAIL',
        prior_structure_reconstructed=True, ordering_only_aligned_after_exact_multiset_comparison=True,
        current_observed_value_substitution=False, foreign_resource_membership_granted=False,
        foreign_resource_removal_granted=False, independent_review='PENDING',
        declaration_staged=False, host_authority_granted=False,
        review_scope='Local preservation-only foreign expectation from bound history and explicitly labeled source/kernel policies. Exact full-shape comparison is required. No custody, installation, ownership, UP, health, runtime or release proof.')
    review_path = root / 'host-baseline-reconciliation-debian-arm64.json'
    review_raw = canonical(reconciliation) + b'\n'
    template = dict(schema=1, platform='debian-arm64', source_binding=candidate['binding'],
        baseline=baseline, baseline_sha256=baseline_sha, prior_evidence=references,
        review_sha256=digest(review_raw))
    modules['schema']['validate_template'](template, candidate['binding'], 'debian-arm64')
    out = root / 'authored-host-baseline-debian-arm64.json'
    destinations = [review_path, out] + [pathlib.Path(h['snapshot']) for h in helpers]
    assert len(set(destinations)) == len(destinations)
    assert not any(p.exists() or p.is_symlink() for p in destinations), 'existing_local_outputs_preserved'
    for helper, (_, raw) in zip(helpers, snapshots.values()):
        create(helper['snapshot'], raw)
    create(review_path, review_raw)
    create(out, canonical(template))
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    os.fsync(fd)
    os.close(fd)
    print(canonical(dict(template=str(out), template_sha256=digest(canonical(template)),
        reconciliation=str(review_path), reconciliation_sha256=digest(review_raw),
        baseline_sha256=baseline_sha, counts=reconciliation['counts'],
        independent_review='PENDING', original_wan_index_directly_exported=False,
        declaration_staged=False, host_authority_granted=False)).decode())


if __name__ == '__main__':
    main()
