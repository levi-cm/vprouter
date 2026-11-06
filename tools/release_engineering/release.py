#!/usr/bin/env python3
"""PREPARATION ONLY. Offline release data; no installation or activation executor."""
import fcntl
import hashlib
import json
import os
import re
import stat

TARGETS = ('x86_64-unknown-linux-musl', 'aarch64-unknown-linux-musl')
BINARIES = ('vprouter', 'vprouter-gateway-init', 'vprouter-worker-observe',
            'vprouter-worker-monitor', 'vprouter-launch-admit')
MAX_JSON = 4 * 1024 * 1024
MAX_FILE = 64 * 1024 * 1024
BUNDLE_NAMES = {t + '--' + b for t in TARGETS for b in BINARIES} | {
    'Cargo.lock', 'programs-amd64.json', 'programs-arm64.json', 'sbom.cdx.json',
    'provenance.json', 'manifest.json', 'SHA256SUMS'}


def require(condition, message='invalid offline input'):
    if not condition:
        raise ValueError(message)


def identifier(value):
    require(isinstance(value, str) and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,47}', value))
    return value


def canonical(value):
    result = (json.dumps(value, sort_keys=True, separators=(',', ':'),
                         ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')
    require(len(result) <= MAX_JSON, 'metadata size limit')
    return result


def digest(data):
    return hashlib.sha256(data).hexdigest()


def services(manager, instance, release):
    """Generate inert drafts only. No caller-supplied command, environment or path."""
    identifier(instance)
    identifier(release)
    require(manager in ('systemd', 'runit'))
    files = []

    def add(path, content='', mode=0o644, kind='file'):
        files.append({'path': path, 'content': content, 'mode': mode, 'kind': kind,
                      'uid': 0, 'gid': 0, 'owner': 'vprouter:' + instance,
                      'sha256': digest(content.encode()) if kind == 'file' else None})

    roles = ('quarantine', 'capture', 'router')
    if manager == 'systemd':
        for role in roles:
            name = instance if role == 'router' else instance + '-' + role
            previous = ('network-online.target' if role == 'quarantine' else
                        instance + ('-quarantine.service' if role == 'capture' else '-capture.service'))
            unit = ('# UNRELEASED inert draft; native readiness/watchdog acceptance OPEN\n'
                    '[Unit]\nDescription=vprouter offline preparation\n'
                    'Wants=network-online.target\nAfter=' + previous + '\n'
                    'Before=' + instance + '-clients.target\n'
                    'StartLimitIntervalSec=60\nStartLimitBurst=3\n')
            if role != 'quarantine':
                unit += 'Requires=' + instance + '-quarantine.service\n'
            if role == 'router':
                unit += 'Requires=' + instance + '-capture.service\n'
            unit += ('[Service]\nType=notify\nNotifyAccess=main\n'
                     'ExecStart=/usr/bin/false\nUser=root\nGroup=root\n'
                     'NoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\n'
                     'ProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\n'
                     'RestrictSUIDSGID=yes\nLockPersonality=yes\nUMask=0077\n'
                     'Restart=on-failure\nRestartSec=5\nTimeoutStartSec=30\n'
                     'TimeoutStopSec=15\nKillMode=control-group\n'
                     'CPUAccounting=yes\nMemoryAccounting=yes\nTasksAccounting=yes\n')
            if role == 'quarantine':
                unit += 'WatchdogSec=90\n'
            add('/etc/systemd/system/' + name + '.service', unit)
    else:
        add('/etc/sv/' + instance, mode=0o755, kind='directory')
        for role in roles:
            base = '/etc/sv/' + instance + '/' + role
            add(base, mode=0o755, kind='directory')
            add(base + '/down')
            add(base + '/run', '#!/bin/sh\n# UNRELEASED: no native readiness/cgroup/watchdog driver\nexec /usr/bin/false\n', 0o755)
            add(base + '/finish', '#!/bin/sh\n# Retain quarantine; never remove policy on stop.\nexit 0\n', 0o755)
    return sorted(files, key=lambda f: f['path'])


def ownership_manifest(manager, instance, release, state_format, artifact_hashes=None):
    """Every draft-installed leaf/owned dir; shared ancestors are preconditions."""
    identifier(state_format)
    artifact_hashes = {} if artifact_hashes is None else artifact_hashes
    require(isinstance(artifact_hashes, dict) and
            (not artifact_hashes or set(artifact_hashes) == set(BINARIES)), 'incomplete binary ownership')
    for value in artifact_hashes.values():
        sha(value)
    files = services(manager, instance, release)
    base = '/opt/vprouter/releases/' + release
    common = {'uid': 0, 'gid': 0, 'owner': 'vprouter:' + instance}
    files.append(dict(common, path=base, kind='directory', mode=0o700, sha256=None, content=''))
    descriptor = canonical({'release': release, 'state_format': state_format,
                            'artifact_hashes': artifact_hashes, 'release_ready': False}).decode()
    files.append(dict(common, path=base + '/release.json', kind='file', mode=0o444,
                      sha256=digest(descriptor.encode()), content=descriptor))
    for name, value in sorted(artifact_hashes.items()):
        files.append(dict(common, path=base + '/' + name, kind='file', mode=0o555,
                          sha256=value, content=None))
    return {'schema': 1, 'manager': manager, 'instance': instance, 'release': release,
            'state_format': state_format, 'artifact_hashes': artifact_hashes,
            'files': sorted(files, key=lambda f: f['path']),
            'release_ready': False, 'status': 'OFFLINE_PREPARATION_ONLY'}


def validate_ownership(manifest):
    require(isinstance(manifest, dict))
    expected = ownership_manifest(manifest.get('manager'), manifest.get('instance'),
                                  manifest.get('release'), manifest.get('state_format'),
                                  manifest.get('artifact_hashes'))
    require(canonical(manifest) == canonical(expected), 'foreign or modified ownership manifest')
    return manifest


def plan(operation, current, desired, observed):
    """Pure hypothetical transaction, NEVER a native ownership receipt/executor.

    Observed maps contain public expected records only. All old paths must be
    present and byte/owner/mode/type matched; unknown observed paths are retained.
    """
    require(operation in ('install', 'update', 'rollback', 'uninstall', 'reboot-recovery'))
    require(isinstance(observed, dict) and len(observed) <= 1024)
    for path in observed:
        require(isinstance(path, str) and len(path) <= 512 and
                re.fullmatch(r'/[A-Za-z0-9_./-]+', path) and
                all(c not in ('', '.', '..') for c in path.split('/')[1:]), 'unsafe observed path')
    require((current is None) == (operation == 'install'))
    require((desired is None) == (operation == 'uninstall'))
    for manifest in (current, desired):
        if manifest is not None:
            validate_ownership(manifest)
    if current:
        for f in current['files']:
            require(canonical(observed.get(f['path'])) == canonical(f), 'missing/drifted/foreign owned path')
    if current and desired:
        require(all(current[k] == desired[k] for k in ('instance', 'manager', 'state_format')),
                'incompatible identity/service/state rollback')
        if operation == 'reboot-recovery':
            require(canonical(current) == canonical(desired), 'reboot recovery must verify the current pair')
        else:
            require(current['release'] != desired['release'], 'same release update')
    old_paths = {f['path'] for f in current['files']} if current else set()
    new_files = desired['files'] if desired else []
    for f in new_files:
        if f['path'] in observed and f['path'] not in old_paths:
            require(canonical(observed[f['path']]) == canonical(f), 'foreign destination')
    steps = ['independent_quarantine_and_client_guards',
             'verify_native_authenticated_ownership', 'capture_ready_this_boot',
             'drain_adapters', 'stop_all_identity_users',
             'verify_all_identity_users_stopped', 'stopped_state_compatible_backup']
    result = {'schema': 1, 'operation': operation, 'status': 'DRAFT_BLOCKED',
              'release_ready': False, 'native_authority': False,
              'write': [f for f in new_files if canonical(observed.get(f['path'])) != canonical(f)],
              'remove': sorted(old_paths - {f['path'] for f in new_files},
                               key=lambda p: (-p.count('/'), p)),
              'remove_directories': 'empty_only_never_recursive',
              'preserve': ['identity', 'credentials', 'profiles', 'state', 'backups',
                           'client_policy', 'host_quarantine', 'foreign_paths'],
              'steps': steps, 'exchange': None,
              'on_failure': ['independent_quarantine_and_client_guards',
                             'restore_compatible_release_and_stopped_state_or_leave_offline'],
              'required': ['native_authenticated_ownership', 'Task8c_acceptance',
                           'same_node_IP_approval_server', 'fsync_staging_and_parent',
                           'root_private_real_directories_same_device',
                           'locked_journal_generation_CAS', 'no_concurrent_identity_users',
                           'complete_verified_binary_artifact_hashes']}
    restart = ['verify_same_identity_then_name', 'controlled_restart',
               'verify_guard_and_client_coverage', 'protected_workloads', 'commit']
    if operation == 'reboot-recovery':
        steps += ['reconcile_persistent_ownership_this_boot',
                  'verify_current_release_and_state_pair'] + restart
    elif current and desired:
        result['exchange'] = {'kind': 'renameat2_RENAME_EXCHANGE_real_directories',
                              'current': '/opt/vprouter/current',
                              'staged': '/opt/vprouter/staged', 'retain_previous': True,
                              'from_release': current['release'], 'to_release': desired['release'],
                              'state_format': current['state_format']}
        if operation == 'rollback':
            result['required'] += ['retained_compatible_stopped_state_backup',
                                   'verified_stopped_state_restoration']
            steps += ['select_retained_compatible_stopped_state_backup',
                      'verify_backup_release_state_identity_binding']
        steps += ['stage_complete_release', 'atomic_exchange']
        if operation == 'rollback':
            steps += ['restore_compatible_stopped_state', 'verify_restored_stopped_state']
        steps += restart
    elif operation == 'install':
        steps += ['stage_complete_release'] + restart
    else:
        steps += ['remove_exact_owned_leaves_and_empty_dirs', 'retain_all_guards', 'offline']
    if current and desired:
        retained = '/opt/vprouter/releases/' + current['release']
        result['remove'] = [p for p in result['remove']
                            if p != retained and not p.startswith(retained + '/')]
        result['retained_release_paths'] = sorted(f['path'] for f in current['files']
                                                 if f['path'] == retained or f['path'].startswith(retained + '/'))
    # No timestamp, clock callback, executable command or transition API exists.
    canonical(result)  # Reserve the complete encoded capacity at admission.
    return result


def parse_json(data):
    require(isinstance(data, bytes) and len(data) <= MAX_JSON)

    def pairs(items):
        require(len(items) <= 2048)
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON field')
            result[key] = value
        return result

    def constant(_):
        raise ValueError('nonfinite JSON number')

    try:
        return json.loads(data.decode('ascii'), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, RecursionError, json.JSONDecodeError) as exc:
        raise ValueError('invalid bounded ASCII JSON') from exc


def sha(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value))
    return value


def member_name(name):
    require(isinstance(name, str) and len(name) <= 128 and
            re.fullmatch('[A-Za-z0-9.][A-Za-z0-9._-]*', name) and name != '.' and '..' not in name,
            'invalid flat bundle member name')
    return name


def static_elf(data, machine):
    """Bounded static ELF64 shape admission, never an executable qualification.

    Extended section numbering and overlapping LOAD mappings are deliberately
    outside this preparation profile. LOADs may cover the ELF/program headers.
    """
    import struct
    limit = (1 << 64) - 1
    require(type(machine) is int and machine in (62, 183))
    require(isinstance(data, bytes) and 120 <= len(data) <= MAX_FILE)
    require(data[:7] == b'\x7fELF\x02\x01\x01', 'not ELF64 little endian')
    require(data[7] in (0, 3) and data[8:16] == bytes(8), 'unsupported ELF ABI/reserved bytes')
    (kind, actual, version, entry, offset, shoff, flags, ehsize,
     size, count, shsize, shcount, shstr) = struct.unpack_from('<HHIQQQIHHHHHH', data, 16)
    require(kind == 2 and actual == machine and version == 1, 'wrong ELF target/type')
    require(flags == 0 and ehsize == 64, 'unsupported flags or invalid ELF header size')
    require(size == 56 and 1 <= count <= 256 and offset >= 64 and
            offset + count * size <= len(data), 'invalid ELF program table')
    phend = offset + count * size
    if shoff == 0:
        require((shsize, shcount, shstr) == (0, 0, 0), 'inconsistent absent section table')
    else:
        require(shsize == 64 and 1 <= shcount <= 4096 and shstr < shcount and
                shoff >= 64 and shoff + shsize * shcount <= len(data) and
                (shoff >= phend or shoff + shsize * shcount <= offset), 'invalid ELF section table')

    def aligned(value):
        return value in (0, 1) or value & (value - 1) == 0

    loads, types, phdrs = [], [], []
    for i in range(count):
        kind, permissions, start, address, physical, length, memory, alignment = struct.unpack_from(
            '<IIQQQQQQ', data, offset + i * size)
        types.append(kind)
        require(kind in (0, 1, 4, 6, 7, 0x6474e550, 0x6474e551, 0x6474e552, 0x6474e553),
                'unsupported or dynamic ELF segment')
        require(permissions & ~7 == 0 and start <= len(data) and length <= len(data) - start,
                'ELF segment flags/range')
        require(memory <= limit - address and memory <= limit - physical and aligned(alignment),
                'ELF segment address overflow/alignment')
        if kind in (1, 7):
            require(length <= memory, 'invalid ELF LOAD/TLS sizes')
        if kind == 6:
            require(not phdrs and not loads and start == offset and length == count * size and
                    memory == length, 'invalid ELF PHDR table binding/order')
            phdrs.append((start, address, length))
        if kind == 1:
            require(alignment <= 1 or start % alignment == address % alignment,
                    'invalid ELF LOAD sizes/alignment')
            for old_start, old_address, old_length, old_memory, _ in loads:
                require(not (length and old_length and start < old_start + old_length and old_start < start + length),
                        'overlapping ELF LOAD file ranges')
                require(not (memory and old_memory and address < old_address + old_memory and old_address < address + memory),
                        'overlapping ELF LOAD virtual ranges')
            loads.append((start, address, length, memory, permissions))
    require(1 in types and not {2, 3}.intersection(types), 'dynamic ELF refused')
    require(any(address <= entry < address + memory and permissions & 1
                for _, address, _, memory, permissions in loads), 'ELF entry outside executable LOAD')
    for start, address, length in phdrs:
        require(any(base <= start and start + length <= base + size and
                    address == virtual + start - base for base, virtual, size, _, _ in loads),
                'ELF PHDR outside containing LOAD')
    if shoff:
        sections = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shsize) for i in range(shcount)]
        require(sections[0] == (0,) * 10, 'invalid NULL section / extended numbering refused')
        strings = sections[shstr] if shstr else None
        require(strings is None or strings[1] == 3, 'section names require STRTAB')
        for name, kind, sflags, address, start, length, link, info, alignment, entsize in sections[1:]:
            require(kind in (1, 2, 3, 4, 5, 7, 8, 9, 11, 14, 15, 16, 17, 18,
                             0x6ffffff5, 0x6ffffff6, 0x6ffffffd, 0x6ffffffe, 0x6fffffff),
                    'unsupported ELF section type')
            # Standard SHF bits (bit3 reserved), plus the gABI OS/processor masks.
            require(sflags & ~0xfff00ff7 == 0 and length <= limit - address and
                    aligned(alignment) and (alignment <= 1 or address % alignment == 0),
                    'ELF section flags/address/alignment')
            require(start <= len(data) and (kind == 8 or length <= len(data) - start),
                    'ELF section outside file')
            require(link < shcount and (not sflags & 0x40 or info < shcount) and
                    (not entsize or length % entsize == 0), 'ELF section links/entry size')
            if kind in (2, 11):
                require(entsize == 24 and sections[link][1] == 3 and info <= length // entsize,
                        'invalid symbol table')
            if kind in (4, 9):
                # ELF64 SHT_RELA / SHT_REL fixed entry sizes; header shape only.
                # sh_link is 0 (symbol-free static relocations) or a symbol table;
                # sh_info (target section, 0 valid) is bounded regardless of SHF_INFO_LINK.
                require(entsize == (24 if kind == 4 else 16) and length % entsize == 0 and
                        (link == 0 or sections[link][1] in (2, 11)) and info < shcount,
                        'invalid ELF relocation section header')
            if kind in (14, 15, 16):
                require(entsize == 8 and info == 0 and link == 0, 'invalid ELF address array')
            if kind == 3:
                require(length > 0 and data[start] == 0 and data[start + length - 1] == 0 and
                        info == 0 and link == 0 and entsize == 0, 'invalid string table')
            if strings is None:
                require(name == 0, 'names without string table')
            else:
                require(name < strings[5] and
                        data.find(b'\0', strings[4] + name, strings[4] + strings[5]) != -1,
                        'invalid section name')


def sbom(lock, inventories):
    import tomllib
    require(isinstance(lock, bytes) and len(lock) <= MAX_JSON)
    try:
        parsed = tomllib.loads(lock.decode('ascii'))
        require(set(parsed) == {'version', 'package'} and parsed['version'] == 4)
        packages = parsed['package']
    except (ValueError, UnicodeError, KeyError) as exc:
        raise ValueError('invalid Cargo.lock') from exc
    require(isinstance(packages, list) and 1 <= len(packages) <= 1024)
    components = []
    refs = set()
    for p in packages:
        require(set(p) <= {'name', 'version', 'source', 'checksum', 'dependencies'})
        require({'name', 'version'} <= set(p))
        dependencies = p.get('dependencies', [])
        require(isinstance(dependencies, list) and len(dependencies) <= 1024 and
                all(isinstance(d, str) and re.fullmatch('[a-zA-Z0-9_.+ -]{1,170}', d) for d in dependencies))
        name, version = p['name'], p['version']
        require(re.fullmatch('[a-zA-Z0-9_-]{1,80}', name) and
                re.fullmatch('[0-9A-Za-z.+-]{1,80}', version))
        ref = 'cargo:' + name + '@' + version
        require(ref not in refs, 'duplicate Cargo package')
        refs.add(ref)
        c = {'type': 'library', 'bom-ref': ref, 'name': name, 'version': version}
        if 'source' in p:
            require(p['source'] == 'registry+https://github.com/rust-lang/crates.io-index',
                    'unreviewed dependency source')
            c['hashes'] = [{'alg': 'SHA-256', 'content': sha(p.get('checksum'))}]
        components.append(c)
    require(set(inventories) == {'amd64', 'arm64'})
    for arch in sorted(inventories):
        inv = parse_json(inventories[arch])
        require(set(inv) == {'schema', 'architecture', 'base_index', 'base_platform', 'programs'})
        require(type(inv['schema']) is int and inv['schema'] == 1 and inv['architecture'] == arch)
        require(inv['base_index'] == 'tailscale/tailscale@sha256:c507f3a2a6ab1cabd8d809b98edeb41edbd5c3fb6ad9632ffd098b4c7d0b4065')
        expected = {'amd64': '08a1bc6c82fee62d1a135788fb67fefa9d22deea3830e8a45ebe1a3cb116e325',
                    'arm64': '472c549d2ef8cebc000de2c8a94061bbdc864d2454177b2ada713262475449ef'}
        require(inv['base_platform'] == 'sha256:' + expected[arch])
        programs = inv['programs']
        require(len(programs) == 4 and {p['role'] for p in programs} ==
                {'gateway_init', 'worker_observer', 'worker_monitor', 'tailscaled'})
        for p in programs:
            require(set(p) == {'role', 'path', 'sha256', 'bytes', 'policy'})
            require(type(p['bytes']) is int and 1 <= p['bytes'] <= MAX_FILE)
            role_paths = {'tailscaled': '/usr/local/bin/tailscaled',
                          'gateway_init': '/usr/local/bin/vprouter-worker',
                          'worker_observer': '/usr/local/bin/vprouter-worker-observe',
                          'worker_monitor': '/usr/local/bin/vprouter-worker-monitor'}
            require(p['path'] == role_paths[p['role']], 'role/path swap')
            require(isinstance(p['policy'], str) and re.fullmatch('[a-z0-9.;-]{1,128}', p['policy']))
            if p['role'] == 'tailscaled':
                require(p['path'] == '/usr/local/bin/tailscaled' and p['policy'].startswith('tailscale-1.102.5;'))
            components.append({'type': 'application', 'bom-ref': arch + ':' + p['role'],
                               'name': p['path'].rsplit('/', 1)[-1],
                               'version': '1.102.5' if p['role'] == 'tailscaled' else 'pinned-inventory',
                               'hashes': [{'alg': 'SHA-256', 'content': sha(p['sha256'])}],
                               'properties': [{'name': 'inventory-origin', 'value': arch},
                                              {'name': 'scope', 'value': 'pinned-program-input-not-built-artifact'}]})
        components.append({'type': 'container', 'bom-ref': arch + ':base',
                           'name': 'tailscale/tailscale', 'version': inv['base_platform'],
                           'hashes': [{'alg': 'SHA-256', 'content': expected[arch]}]})
    return canonical({'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
                      'components': sorted(components, key=lambda c: c['bom-ref']),
                      'metadata': {'properties': [{'name': 'scope', 'value':
                          'offline-lock-and-pinned-program-inventory; licenses/transitives-of-prebuilt-programs-unverified'}]}})


def build_bundle(binaries, lock, inventories, commit, toolchain, builder):
    require(isinstance(commit, str) and re.fullmatch('[0-9a-f]{40}', commit))
    require(toolchain == '1.97.0', 'unpinned Rust toolchain')
    identifier(builder)
    names = {t + '--' + b for t in TARGETS for b in BINARIES}
    require(set(binaries) == names, 'missing/extra release binaries')
    files = dict(binaries)
    for target, machine in zip(TARGETS, (62, 183)):
        for name in BINARIES:
            static_elf(files[target + '--' + name], machine)
    files.update({'Cargo.lock': lock, 'programs-amd64.json': inventories['amd64'],
                  'programs-arm64.json': inventories['arm64']})
    bom = parse_json(sbom(lock, inventories))
    for name in sorted(names):
        bom['components'].append({'type': 'application', 'bom-ref': 'artifact:' + name,
                                  'name': name, 'version': commit,
                                  'hashes': [{'alg': 'SHA-256', 'content': digest(files[name])}],
                                  'properties': [{'name': 'scope', 'value': 'supplied-artifact-not-build-attestation'}]})
    bom['components'].sort(key=lambda c: c['bom-ref'])
    files['sbom.cdx.json'] = canonical(bom)
    subjects = [{'name': n, 'digest': {'sha256': digest(files[n])}} for n in sorted(names)]
    materials = {n: digest(files[n]) for n in ('Cargo.lock', 'programs-amd64.json',
                                               'programs-arm64.json', 'sbom.cdx.json')}
    files['provenance.json'] = canonical({
        '_type': 'https://in-toto.io/Statement/v1', 'subject': subjects,
        'predicateType': 'https://vprouter.invalid/offline-preparation/v1',
        'predicate': {'source_commit': commit, 'materials': materials, 'toolchain': toolchain,
                      'builder': builder, 'signature': 'UNSIGNED', 'release_ready': False,
                      'build_command': ['cargo', 'build', '--locked', '--offline', '-j', '4', '--release'],
                      'claim': 'packaged-inputs-only-not-proof-of-executed-build', 'epoch': 0}})
    files['manifest.json'] = canonical({
        'schema': 1, 'status': 'OFFLINE_PREPARATION_ONLY', 'release_ready': False,
        'source_commit': commit, 'toolchain': toolchain, 'builder': builder, 'epoch': 0,
        'targets': sorted(TARGETS), 'artifacts': subjects,
        'files': [{'name': n, 'bytes': len(v), 'sha256': digest(v), 'mode': 0o444}
                  for n, v in sorted(files.items())]})
    files['SHA256SUMS'] = ''.join(digest(v) + '  ' + n + '\n' for n, v in sorted(files.items())).encode('ascii')
    require(sum(map(len, files.values())) <= 512 * 1024 * 1024, 'bundle size limit')
    return dict(sorted(files.items()))


def bundle_inputs(files):
    require(isinstance(files, dict) and set(files) == BUNDLE_NAMES)
    for name, data in files.items():
        member_name(name)
        require(isinstance(data, bytes) and len(data) <= MAX_FILE)
    manifest = parse_json(files.get('manifest.json', b''))
    try:
        return {'binaries': {n: files[n] for n in files if '--' in n},
                'lock': files['Cargo.lock'],
                'inventories': {a: files['programs-' + a + '.json'] for a in ('amd64', 'arm64')},
                'commit': manifest['source_commit'], 'toolchain': manifest['toolchain'],
                'builder': manifest['builder']}
    except (KeyError, TypeError) as exc:
        raise ValueError('incomplete bundle') from exc


def verify_bundle(files, expected_digest, require_release=False):
    sha(expected_digest)
    try:
        require(digest(files['SHA256SUMS']) == expected_digest, 'external digest mismatch')
        rebuilt = build_bundle(**bundle_inputs(files))
        require(rebuilt == files, 'noncanonical or mutated artifact bundle')
        require(not require_release, 'UNSIGNED: release approval refused')
    except (KeyError, TypeError, RecursionError) as exc:
        raise ValueError('invalid bundle') from exc
    return {'status': 'OFFLINE_INTEGRITY_ONLY', 'signature': 'UNSIGNED',
            'release_ready': False, 'bundle_digest': expected_digest}


# Filesystem support is exclusively for pre-created private, marked fixtures.
# Plans have no executor. No directory is discovered/created outside this root.
READ = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOATIME
DIRECTORY = READ | os.O_DIRECTORY


def pin(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_nlink,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def entries(fd):
    result = []
    with os.scandir(fd) as iterator:
        for item in iterator:
            require(len(result) < 64, 'directory member limit')
            member_name(item.name)
            result.append(item.name)
    return sorted(result)


def private(st, directory=False, mode=None):
    require((stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode)) and
            st.st_uid == os.geteuid() and st.st_gid == os.getegid(), 'unowned/special fixture inode')
    require(stat.S_IMODE(st.st_mode) == (mode if mode is not None else (0o700 if directory else 0o600)),
            'fixture permissions')
    if not directory:
        require(st.st_nlink == 1 and st.st_size <= MAX_FILE, 'hardlink/oversized input')


def read_leaf(directory, name, mode=0o444, fixed_time=True):
    """Check metadata BEFORE data open; special/link aliases never get data FDs."""
    member_name(name)
    before = os.stat(name, dir_fd=directory, follow_symlinks=False)
    private(before, mode=mode)
    if fixed_time:
        require(before.st_mtime_ns == 0, 'nonreproducible file time')
    fd = os.open(name, READ, dir_fd=directory)
    try:
        require(pin(before) == pin(os.fstat(fd)), 'file replaced before read')
        chunks, count = [], 0
        while True:
            chunk = os.read(fd, min(65536, MAX_FILE + 1 - count))
            if not chunk:
                break
            chunks.append(chunk)
            count += len(chunk)
            require(count <= MAX_FILE, 'file read limit')
        require(count == before.st_size and pin(before) == pin(os.fstat(fd)) ==
                pin(os.stat(name, dir_fd=directory, follow_symlinks=False)), 'file changed during read')
        return b''.join(chunks), before
    finally:
        os.close(fd)


class FixtureStore:
    """Private cooperative-lock boundary, not protection against malicious root.

    Constructor writes nothing; the test/operator supplies marker and existing
    lock. Pending evidence refuses ordinary publication; explicit recovery only
    removes validated expected prefixes. No age-based cleanup or recursive delete.
    """
    def __init__(self, root):
        text = os.fspath(root)
        require(isinstance(text, str) and len(text) <= 1024 and text.startswith('/') and
                re.fullmatch(r'/[A-Za-z0-9_./-]+', text) and
                all(c not in ('', '.', '..') for c in text.split('/')[1:]), 'unsafe fixture root path')
        self.fds = []
        self.chain = []
        self.lock = None
        try:
            parent = os.open('/', DIRECTORY & ~os.O_NOATIME)
            self.fds.append(parent)
            parts = text.split('/')[1:]
            for i, part in enumerate(parts):
                fd = os.open(part, DIRECTORY & ~os.O_NOATIME, dir_fd=parent)
                self.fds.append(fd)
                st = os.fstat(fd)
                require(st.st_uid in (0, os.geteuid()) and not stat.S_IMODE(st.st_mode) & 0o022 or
                        (i == 0 and part == 'tmp' and st.st_uid == 0 and st.st_mode & stat.S_ISVTX),
                        'untrusted fixture ancestor')
                require((st.st_dev, st.st_ino) ==
                        (os.stat(part, dir_fd=parent, follow_symlinks=False).st_dev,
                         os.stat(part, dir_fd=parent, follow_symlinks=False).st_ino))
                self.chain.append((parent, part, fd, st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid))
                parent = fd
            self.root = parent
            private(os.fstat(self.root), directory=True)
            marker, self.marker = read_leaf(self.root, 'offline-release.fixture', 0o600, False)
            require(marker == b'offline-release-fixture-v1\n')
            lock_bytes, st = read_leaf(self.root, '.release.lock', 0o600, False)
            require(lock_bytes == b'offline-release-lock-v1\n')
            self.lock = os.open('.release.lock', READ, dir_fd=self.root)
            require(pin(os.fstat(self.lock)) == pin(st))
            self.lock_pin = pin(st)
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._check()
        except BaseException:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        if self.lock is not None:
            os.close(self.lock)
            self.lock = None
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds = []

    def _check(self):
        require(self.lock is not None, 'closed fixture store is terminal')
        for parent, name, fd, device, inode, mode, uid, gid in self.chain:
            st = os.stat(name, dir_fd=parent, follow_symlinks=False)
            require((st.st_mode, st.st_uid, st.st_gid) == (mode, uid, gid) and
                    stat.S_ISDIR(st.st_mode) and (st.st_dev, st.st_ino) == (device, inode) ==
                    (os.fstat(fd).st_dev, os.fstat(fd).st_ino), 'fixture ancestor renamed/replaced')
        private(os.fstat(self.root), directory=True)
        require(pin(os.fstat(self.lock)) == self.lock_pin ==
                pin(os.stat('.release.lock', dir_fd=self.root, follow_symlinks=False)), 'lock replaced')
        data, st = read_leaf(self.root, 'offline-release.fixture', 0o600, False)
        require(data == b'offline-release-fixture-v1\n' and pin(st) == pin(self.marker), 'marker replaced')
        require(set(entries(self.root)) <= {'offline-release.fixture', '.release.lock', '.pending', 'bundle'},
                'foreign root evidence retained')

    def _directory(self, name):
        st = os.stat(name, dir_fd=self.root, follow_symlinks=False)
        private(st, directory=True)
        require(st.st_dev == os.fstat(self.root).st_dev, 'foreign device')
        fd = os.open(name, DIRECTORY, dir_fd=self.root)
        try:
            require((st.st_dev, st.st_ino) == (os.fstat(fd).st_dev, os.fstat(fd).st_ino))
        except BaseException:
            os.close(fd)
            raise
        return fd

    def _named_directory(self, name, fd):
        st = os.stat(name, dir_fd=self.root, follow_symlinks=False)
        require((st.st_dev, st.st_ino) == (os.fstat(fd).st_dev, os.fstat(fd).st_ino), 'directory replaced')
        private(st, directory=True)
        self._check()

    def _read(self, name):
        self._check()
        fd = self._directory(name)
        try:
            st = os.fstat(fd)
            require(st.st_mtime_ns == 0, 'nonreproducible directory time')
            names = entries(fd)
            require(set(names) == BUNDLE_NAMES, 'missing/extra bundle member before data access')
            files, pins = {}, {}
            for leaf in names:
                data, info = read_leaf(fd, leaf)
                require(info.st_dev == st.st_dev)
                files[leaf], pins[leaf] = data, pin(info)
                require(sum(map(len, files.values())) <= 512 * 1024 * 1024)
            require(entries(fd) == names and pin(os.fstat(fd)) == pin(st), 'directory changed')
            for leaf in names:
                require(pin(os.stat(leaf, dir_fd=fd, follow_symlinks=False)) == pins[leaf], 'late file replacement')
            self._named_directory(name, fd)
            return files
        finally:
            os.close(fd)

    def read(self, expected_digest):
        return verify_bundle(self._read('bundle'), expected_digest)

    def publish(self, files, expected_digest, checkpoint=lambda _: None):
        verify_bundle(files, expected_digest)
        self._check()
        names = entries(self.root)
        require('.pending' not in names, 'pending evidence: explicit recover required')
        if 'bundle' in names:
            require(self._read('bundle') == files, 'immutable output differs')
            # A previous call may have renamed successfully then failed fsync.
            # Presence alone never proves the namespace mutation is durable.
            os.fsync(self.root)
            return self.read(expected_digest)
        checkpoint('before_mkdir')
        self._check()
        os.mkdir('.pending', 0o700, dir_fd=self.root)
        checkpoint('after_mkdir')
        fd = self._directory('.pending')
        try:
            for name, data in sorted(files.items()):
                checkpoint('before_create:' + name)
                self._named_directory('.pending', fd)
                out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                              0o600, dir_fd=fd)
                try:
                    checkpoint('after_create:' + name)
                    cursor = 0
                    while cursor < len(data):
                        checkpoint('before_write:' + name)
                        self._named_directory('.pending', fd)
                        st = os.fstat(out)
                        private(st)
                        require(pin(st) == pin(os.stat(name, dir_fd=fd, follow_symlinks=False)))
                        written = os.write(out, data[cursor:cursor + 4096])
                        require(written > 0, 'zero write')
                        cursor += written
                        checkpoint('after_write:' + name)
                    checkpoint('before_file_fsync:' + name)
                    private(os.fstat(out))
                    require(pin(os.fstat(out)) == pin(os.stat(name, dir_fd=fd, follow_symlinks=False)))
                    os.fsync(out)
                    os.fchmod(out, 0o444)
                    os.utime(out, ns=(0, 0))
                    os.fsync(out)
                    checkpoint('after_file_fsync:' + name)
                finally:
                    os.close(out)
            os.utime(fd, ns=(0, 0))
            checkpoint('before_staging_fsync')
            os.fsync(fd)
            checkpoint('after_staging_fsync')
            require(self._read('.pending') == files)
            checkpoint('before_rename')
            self._named_directory('.pending', fd)
            require('bundle' not in entries(self.root), 'destination appeared')
            os.rename('.pending', 'bundle', src_dir_fd=self.root, dst_dir_fd=self.root)
            checkpoint('after_rename')
            checkpoint('before_directory_fsync')
            self._named_directory('bundle', fd)
            os.fsync(self.root)
            checkpoint('after_directory_fsync')
        finally:
            os.close(fd)
        return self.read(expected_digest)

    def recover(self, files, expected_digest):
        """Discard only matching partial public prefixes, never unknown evidence."""
        verify_bundle(files, expected_digest)
        self._check()
        names = entries(self.root)
        if 'bundle' in names:
            require(self._read('bundle') == files)
            require('.pending' not in names, 'ambiguous double publication')
            os.fsync(self.root)
            return
        if '.pending' not in names:
            # rmdir may have succeeded in an earlier call whose final fsync
            # failed or was interrupted. Replay must finish that obligation.
            os.fsync(self.root)
            return
        fd = self._directory('.pending')
        try:
            leaves = entries(fd)
            pins = {}
            for name in leaves:
                require(name in files, 'foreign pending leaf')
                st = os.stat(name, dir_fd=fd, follow_symlinks=False)
                require(stat.S_IMODE(st.st_mode) in (0o444, 0o600))
                data, info = read_leaf(fd, name, stat.S_IMODE(st.st_mode), False)
                require(files[name].startswith(data), 'unowned pending bytes')
                pins[name] = pin(info)
            # Validate the entire partial set BEFORE the first deletion.
            require(entries(fd) == leaves)
            for name in leaves:
                self._named_directory('.pending', fd)
                require(pin(os.stat(name, dir_fd=fd, follow_symlinks=False)) == pins[name])
                os.unlink(name, dir_fd=fd)
            os.fsync(fd)
            self._named_directory('.pending', fd)
            os.rmdir('.pending', dir_fd=self.root)
            os.fsync(self.root)
        finally:
            os.close(fd)


def preflight(host):
    """Validate a DECLARATION offline; never observes or certifies a live host."""
    require(isinstance(host, dict) and set(host) ==
            {'os', 'distro', 'libc', 'manager', 'arch', 'kernel', 'cgroup', 'nft', 'wireguard', 'tun'})
    require(host['os'] == 'linux' and host['libc'] == 'glibc')
    require((host['distro'], host['manager']) in
            {('debian13', 'systemd'), ('arch', 'systemd'), ('cachyos', 'systemd'), ('void', 'runit')})
    require(host['arch'] in ('x86_64', 'aarch64'))
    kernel = host['kernel']
    require(isinstance(kernel, list) and len(kernel) == 2 and
            all(type(n) is int and 0 <= n <= 999 for n in kernel) and kernel >= [6, 1])
    require(type(host['cgroup']) is int and host['cgroup'] == 2 and
            all(host[k] is True for k in ('nft', 'wireguard', 'tun')))
    blocked = ['Task8c_runtime_ARM_client_acceptance', 'actual_platform_preflight',
               'independent_quarantine', 'capture_ready_before_traffic',
               'authenticated_ownership_and_same_identity', 'service_runtime_acceptance']
    if host['manager'] == 'runit':
        blocked.append('runit_native_cgroup_watchdog_readiness')
    return {'status': 'UNVERIFIED_NATIVE_GATES', 'release_ready': False,
            'declaration_eligible': True, 'install_allowed': False, 'blocked_on': blocked}


def build_recipe():
    """An inert recipe; caller MUST NOT execute missing/unverified toolchains.

    Build paths/debug paths must be remapped in a separately admitted reproducible
    environment before claiming reproducible BINARY builds. This recipe and the
    bundle builder alone make no claim that compilation happened or is reproducible.
    """
    result = []
    for target in TARGETS:
        arch = target.split('-')[0]
        env = {'CARGO_BUILD_JOBS': '4', 'SOURCE_DATE_EPOCH': '0', 'CARGO_NET_OFFLINE': 'true',
               'RUSTUP_TOOLCHAIN': '1.97.0', 'RUSTFLAGS': '-C relocation-model=static',
               'CARGO_TARGET_' + target.upper().replace('-', '_') + '_LINKER': 'rust-lld',
               'CC_' + target.replace('-', '_'): 'target/toolchains/' + arch + '-linux-musl-cc'}
        argv = ['cargo', 'build', '--locked', '--offline', '-j', '4', '--release', '--target', target]
        for name in BINARIES:
            argv += ['--bin', name]
        result.append({'argv': argv, 'env': env, 'execute': False, 'sequential_only': True,
                       'required': ['pinned_Zig_CC_wrapper_bytes', 'cached_target_and_dependencies',
                                    'memory_admission', 'source_and_cache_path_remapping',
                                    'clean_source_binding', 'repeat_binary_build_comparison']})
    return result
