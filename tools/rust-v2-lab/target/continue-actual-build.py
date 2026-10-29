import datetime
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile

root = pathlib.Path.cwd()
stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
out = root / 'target' / ('continuation-' + stamp)
out.mkdir(mode=0o700)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def run(args, env=None, capture=False):
    return subprocess.run(args, env=env, check=True, text=True,
                          stdout=subprocess.PIPE if capture else None).stdout

platforms = {}
for arch, triple in [('amd64', 'x86_64'), ('arm64', 'aarch64')]:
    target = triple + '-unknown-linux-musl'
    env = dict(os.environ)
    env['RUSTFLAGS'] = '-C relocation-model=static'
    env['CC_' + target.replace('-', '_')] = str(root / 'target/toolchains' / (triple + '-linux-musl-cc'))
    env['CARGO_TARGET_' + target.replace('-', '_').upper() + '_LINKER'] = 'rust-lld'
    common = ['cargo', 'build', '--locked', '--release', '--target', target]
    init_args = common + ['-p', 'vprouter-launch', '--bin', 'vprouter-gateway-init']
    run(common + ['-p', 'vprouter-worker', '--bin', 'vprouter-worker-observe'], env)
    run(init_args, env)
    manifest_path = root / f'docs/rust-v2/programs-{arch}.json'
    manifest = json.loads(manifest_path.read_bytes())
    for entry in manifest['programs']:
        name = {'gateway_init': 'vprouter-gateway-init', 'worker_observer': 'vprouter-worker-observe'}.get(entry['role'])
        if name:
            binary = root / 'target' / target / 'release' / name
            entry.update(sha256=sha(binary), bytes=binary.stat().st_size)
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
    run(init_args, env)
    init = next(x for x in manifest['programs'] if x['role'] == 'gateway_init')
    assert sha(root / 'target' / target / 'release/vprouter-gateway-init') == init['sha256']
    build = run(['cargo', 'test', '--locked', '--release', '--target', target,
                 '-p', 'vprouter-launch', '--test', 'actual_lab', '--no-run',
                 '--message-format=json'], env, True)
    events = [json.loads(line) for line in build.splitlines() if line.startswith('{')]
    payload = pathlib.Path(next(e['executable'] for e in events
                               if e.get('reason') == 'compiler-artifact'
                               and e['target']['name'] == 'actual_lab' and e.get('executable')))
    retained_payload = out / (arch + '.payload')
    retained_payload.write_bytes(payload.read_bytes())
    retained_payload.chmod(0o600)
    run(init_args, env)
    assert sha(root / 'target' / target / 'release/vprouter-gateway-init') == init['sha256']
    context_dir = root / 'target/gateway-context' / arch
    if context_dir.exists():
        context_dir.rename(context_dir.with_name(stamp + '-previous-' + arch))
    run(['python3', 'tools/build-gateway-context.py', '--architecture', arch])
    context = context_dir / 'context.tar'
    platforms[arch] = {'artifact': str(retained_payload), 'artifact_sha256': sha(retained_payload),
                       'context': str(context), 'context_sha256': sha(context)}

# Preserve the branch, index and existing unfinished work. The candidate is an
# immutable local Git object/ref used solely to bind exact source to test bytes.
with tempfile.TemporaryDirectory(dir=out) as temporary:
    env = dict(os.environ, GIT_INDEX_FILE=str(pathlib.Path(temporary) / 'index'))
    parent = run(['git', 'rev-parse', 'HEAD'], capture=True).strip()
    run(['git', 'read-tree', parent], env)
    run(['git', 'add', '-u'], env)
    tree = run(['git', 'write-tree'], env, True).strip()
    identity = dict(os.environ, GIT_AUTHOR_NAME='Codex', GIT_AUTHOR_EMAIL='codex@localhost',
                    GIT_COMMITTER_NAME='Codex', GIT_COMMITTER_EMAIL='codex@localhost')
    source_commit = subprocess.check_output(['git', 'commit-tree', tree, '-p', parent], env=identity,
                       input=('Local Rust v2 test candidate ' + stamp + '\n').encode()).decode().strip()
    run(['git', 'update-ref', 'refs/vprouter-test-candidates/' + stamp, source_commit])
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
