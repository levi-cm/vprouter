"""Compare a frozen Rust build-input tar to an exact commit, without extraction."""
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tarfile

assert len(sys.argv) == 3, 'usage: source_archive full_commit'
archive, commit = pathlib.Path(sys.argv[1]), sys.argv[2]
assert re.fullmatch(r'[a-f0-9]{40}', commit)
names = subprocess.check_output(['git', 'ls-tree', '-rz', '--name-only', commit]).decode().split('\0')
required = {name for name in names if name in (
    'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml',
    'docs/rust-v2/programs-amd64.json', 'docs/rust-v2/programs-arm64.json')
    or name.startswith(('crates/', 'examples/v2/'))}
assert {'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml'} <= required
seen = {}
with tarfile.open(archive) as source:
    for item in source:
        if item.isdir():
            continue
        assert item.isfile() and item.name in required and item.name not in seen, item.name
        assert item.size < 16 * 1024 * 1024, item.name
        data = source.extractfile(item).read()
        assert data == subprocess.check_output(['git', 'show', commit + ':' + item.name]), item.name
        seen[item.name] = hashlib.sha256(data).hexdigest()
assert set(seen) == required, sorted(required - set(seen))
aggregate = hashlib.sha256()
for name, digest in sorted(seen.items()):
    aggregate.update((name + '\0' + digest + '\n').encode())
print(json.dumps({'source_commit': commit,
                  'source_archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
                  'tracked_build_inputs_verified': len(seen),
                  'source_aggregate_sha256': aggregate.hexdigest()}, indent=2))
