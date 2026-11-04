#!/usr/bin/env python3
"""Fresh lab rebuild; ARM64 is compile-only. No VM, SSH or enrollment actions."""
import datetime
import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile

if not __debug__:
    raise RuntimeError('optimized_python_refused')

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--name')
args = parser.parse_args()
root = pathlib.Path.cwd()
stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
out = root / 'target/candidates' / (args.name or ('rebuild-' + stamp))
out.mkdir(mode=0o700)
print(json.dumps({'build_directory': str(out)}), flush=True)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def run(args, env=None, capture=False):
    print(json.dumps({'command': args}), flush=True)
    return subprocess.run(args, env=env, check=True, text=True,
                          stdout=subprocess.PIPE if capture else None).stdout

platforms = {}
for arch, triple in [('amd64', 'x86_64'), ('arm64', 'aarch64')]:
    target = triple + '-unknown-linux-musl'
    env = dict(os.environ)
    env['RUSTFLAGS'] = '-C relocation-model=static'
    cross = pathlib.Path.home() / '.local/share/zig-cross/bin'
    env['CC_' + target.replace('-', '_')] = str(cross / (triple + '-linux-musl-gcc'))
    env['AR_' + target.replace('-', '_')] = str(cross / (triple + '-linux-musl-ar'))
    env['CARGO_TARGET_' + target.replace('-', '_').upper() + '_RUSTFLAGS'] = '-C relocation-model=static'
    env['CARGO_TARGET_' + target.replace('-', '_').upper() + '_LINKER'] = 'rust-lld'
    common = ['cargo', 'build', '--locked', '--release', '-j', '4', '--target', target]
    init_args = common + ['-p', 'vprouter-launch', '--bin', 'vprouter-gateway-init']
    run(common + ['-p', 'vprouter-worker', '--bin', 'vprouter-worker-observe', '--bin', 'vprouter-worker-monitor'], env)
    run(init_args, env)
    manifest_path = root / f'docs/rust-v2/programs-{arch}.json'
    manifest = json.loads(manifest_path.read_bytes())
    if not any(e['role'] == 'worker_monitor' for e in manifest['programs']):
        manifest['programs'].append({'role': 'worker_monitor', 'path': '/usr/local/bin/vprouter-worker-monitor', 'sha256': '', 'bytes': 0, 'policy': 'guard-bound-monitor-zero-caps-private-root-v1'})
    for entry in manifest['programs']:
        name = {'gateway_init': 'vprouter-gateway-init', 'worker_observer': 'vprouter-worker-observe', 'worker_monitor': 'vprouter-worker-monitor'}.get(entry['role'])
        if name:
            binary = root / 'target' / target / 'release' / name
            entry.update(sha256=sha(binary), bytes=binary.stat().st_size)
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
    run(init_args, env)
    init = next(x for x in manifest['programs'] if x['role'] == 'gateway_init')
    assert sha(root / 'target' / target / 'release/vprouter-gateway-init') == init['sha256']
    build = run(['cargo', 'test', '--locked', '--release', '-j', '4', '--target', target,
                 '-p', 'vprouter-launch', '--test', 'actual_lab', '--no-run',
                 '--message-format=json'], env, True)
    events = [json.loads(line) for line in build.splitlines() if line.startswith('{')]
    payload = pathlib.Path(next(e['executable'] for e in events
                               if e.get('reason') == 'compiler-artifact'
                               and e['target']['name'] == 'actual_lab' and e.get('executable')))
    retained_payload = out / (arch + '.payload')
    retained_payload.write_bytes(payload.read_bytes())
    retained_payload.chmod(0o600)
    if arch == 'amd64':
        # Glibc/debug is insufficient: execute an exact retained musl byte copy
        # under the installed role profile before publishing this candidate.
        preflight = out / 'amd64.filter-preflight'
        preflight.write_bytes(retained_payload.read_bytes())
        preflight.chmod(0o700)
        assert sha(preflight) == sha(retained_payload)
        checked = subprocess.run([str(preflight), '--inspection-filter-selftest'],
                                 check=False, text=True, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, timeout=30)
        (out / 'amd64.filter-preflight.log').write_text(checked.stdout)
        checked.check_returncode()
    run(init_args, env)
    assert sha(root / 'target' / target / 'release/vprouter-gateway-init') == init['sha256']
    platforms[arch] = {'artifact': str(retained_payload), 'artifact_sha256': sha(retained_payload)}

# Retain both compile-only artifact sets before the public-cache boundary.
# This is explicitly incomplete evidence, never a continuation candidate.
partial = {'status': 'CONTEXTS_NOT_BUILT', 'parent_head': run(['git', 'rev-parse', 'HEAD'], capture=True).strip(),
           'driver_sha256': sha(pathlib.Path(__file__)), 'platforms': platforms,
           'baseline_discontinuity': 'Old target deleted 2026-11-03 without backup; original guest continuity permanently broken.',
           'native_bootstrap': 'NOT_RUN', 'arm64_runtime': 'NOT_RUN', 'release_ready': False}
(out / 'partial-build.json').write_text(json.dumps(partial, indent=2) + '\n')
for arch in ('amd64', 'arm64'):
    context_dir = root / 'target/gateway-context' / arch
    if context_dir.exists():
        context_dir.rename(context_dir.with_name(stamp + '-previous-' + arch))
    run(['python3', 'tools/build-gateway-context.py', '--architecture', arch])
    context = context_dir / 'context.tar'
    platforms[arch].update(context=str(context), context_sha256=sha(context))

# Freeze directly from existing HEAD; no index, commit, object or ref writes.
# Fail if generated manifests or any other build input differ from that commit.
source_commit = run(['git', 'rev-parse', 'HEAD'], capture=True).strip()
assert source_commit == 'da7556282d5fc828a9391a64ab47adab05a55510'
source = out / 'source.tar'
with source.open('xb') as stream:
    subprocess.run(['git', 'archive', '--format=tar', source_commit,
                    'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'crates',
                    'examples/v2', 'docs/rust-v2/programs-amd64.json',
                    'docs/rust-v2/programs-arm64.json'], check=True, stdout=stream)
binding = json.loads(run(['python3', 'tools/verify-frozen-build-inputs.py', str(source), source_commit], capture=True))
record = {'source_commit': source_commit, 'source': str(source),
          'source_sha256': sha(source), 'binding': binding, 'platforms': platforms}
(out / 'candidate.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps({'candidate': str(out / 'candidate.json'), 'source_commit': source_commit}), flush=True)
