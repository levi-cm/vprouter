import hashlib,json,pathlib,struct,tarfile
if not __debug__: raise RuntimeError("optimized_python_refused")

def sha(data):
    return hashlib.sha256(data).hexdigest()


def context_check(context, source, architecture='amd64'):
    assert architecture in {'amd64', 'arm64'}
    with tarfile.open(source) as archive:
        main = archive.extractfile('crates/vprouter-launch/src/actual_lab_main.rs').read()
        assert b'"--secret-attachment-descriptor"' in main, 'frozen_source_missing_secret_attachment_interface'
        manifests = {
            arch: archive.extractfile(f'docs/rust-v2/programs-{arch}.json').read()
            for arch in ('amd64', 'arm64')
        }
    manifest_bytes = manifests[architecture]
    manifest = json.loads(manifest_bytes)
    assert manifest['architecture'] == architecture
    assert manifest['base_index'] == 'tailscale/tailscale@sha256:c507f3a2a6ab1cabd8d809b98edeb41edbd5c3fb6ad9632ffd098b4c7d0b4065'
    platform, daemon_digest, daemon_bytes, machine = {
        'amd64': ('sha256:08a1bc6c82fee62d1a135788fb67fefa9d22deea3830e8a45ebe1a3cb116e325',
                  'b2ec98126c6ee19d7b3603b0cfee97c5dd646874065aed7016653d30ff92a9cd', 42902060, 62),
        'arm64': ('sha256:472c549d2ef8cebc000de2c8a94061bbdc864d2454177b2ada713262475449ef',
                  '3cf2640069ded59322dc2113be5fa90540937410be22bb40873a614773ab27cc', 40133663, 183),
    }[architecture]
    assert manifest['base_platform'] == platform
    entries = {entry['role']: entry for entry in manifest['programs']}
    assert len(entries) == len(manifest['programs']) == 4
    paths = {
        'gateway_init': 'rootfs/usr/local/bin/vprouter-worker',
        'worker_observer': 'rootfs/usr/local/bin/vprouter-worker-observe',
        'worker_monitor': 'rootfs/usr/local/bin/vprouter-worker-monitor',
        'tailscaled': 'rootfs/usr/local/bin/tailscaled',
    }
    assert set(entries) == set(paths)
    assert entries['worker_monitor']['policy'] == 'guard-bound-monitor-zero-caps-private-root-v1'
    assert entries['tailscaled']['sha256'] == daemon_digest
    assert entries['tailscaled']['bytes'] == daemon_bytes
    manifest_digest = sha(manifest_bytes)
    dockerfile = (
        'FROM scratch\nCOPY rootfs /\nENV LANG=C PATH=/bin\n'
        'LABEL io.vprouter.source="' + manifest['base_index']
        + '" io.vprouter.platform="' + manifest['base_platform']
        + '" io.vprouter.programs="' + manifest_digest
        + '"\nENTRYPOINT ["/usr/local/bin/vprouter-worker"]\n'
    ).encode()
    expected = set(paths.values()) | {
        'Dockerfile', 'rootfs/etc/ssl/certs/ca-certificates.crt',
        'rootfs/usr/share/vprouter/programs.json',
    }
    directories = {'rootfs/tmp', 'rootfs/state', 'rootfs/run', 'rootfs/proc', 'rootfs/dev/net'}
    for path in expected:
        directories.update(str(p) for p in pathlib.PurePosixPath(path).parents if str(p) != '.')
    seen = set()
    inventory = []
    with tarfile.open(context) as archive:
        for item in archive:
            assert item.name not in seen and item.name in expected | directories, item.name
            seen.add(item.name)
            assert item.uid == item.gid == item.mtime == 0
            assert not item.pax_headers and not item.linkname
            if item.name in directories:
                assert item.isdir() and item.mode == 0o755 and item.size == 0
                continue
            assert item.isfile() and item.size < 64 * 1024 * 1024
            data = archive.extractfile(item).read()
            if item.name == 'Dockerfile':
                assert item.mode == 0o444 and data == dockerfile
            elif item.name.endswith('/programs.json'):
                assert item.mode == 0o444 and data == manifest_bytes
            elif item.name.endswith('/ca-certificates.crt'):
                assert item.mode == 0o444 and len(data) == 181724
                assert sha(data) == '028fca5150ee1915c4474489985d55c54fceaa680c754cc8d1301734f01b2232'
            else:
                role = next(role for role, path in paths.items() if path == item.name)
                entry = entries[role]
                assert item.name == 'rootfs' + entry['path'] and item.mode == 0o555
                assert len(data) == entry['bytes'] and sha(data) == entry['sha256']
                assert data[:7] == b'\x7fELF\x02\x01\x01' and struct.unpack_from('<H', data, 18)[0] == machine
                offset = struct.unpack_from('<Q', data, 32)[0]
                size, count = struct.unpack_from('<HH', data, 54)
                assert size == 56 and 1 <= count <= 256 and offset + size * count <= len(data)
                kinds = [struct.unpack_from('<I', data, offset + size * i)[0] for i in range(count)]
                assert 1 in kinds and not {2, 3}.intersection(kinds)
            inventory.append({'path': item.name, 'sha256': sha(data), 'bytes': len(data)})
    assert seen == expected | directories
    return manifest_digest, inventory, entries['gateway_init']


