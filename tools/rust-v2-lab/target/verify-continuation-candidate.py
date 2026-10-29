"""Root's offline source/static artifact proof; no runtime or acceptance authority."""
import hashlib
import importlib.util
import json
import pathlib
import struct
import subprocess
import sys
import tarfile

if not __debug__:
    raise RuntimeError('optimized_python_refused')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    candidate_path = pathlib.Path(sys.argv[1])
    candidate = json.loads(candidate_path.read_bytes())
    source = pathlib.Path(candidate['source'])
    assert sha(source) == candidate['source_sha256']
    binding = json.loads(subprocess.check_output([
        sys.executable, 'tools/verify-frozen-build-inputs.py',
        str(source), candidate['source_commit'],
    ]))
    assert binding == candidate['binding']
    current = {}
    with tarfile.open(source) as archive:
        for member in archive:
            if member.isfile():
                raw = archive.extractfile(member).read()
                assert pathlib.Path(member.name).read_bytes() == raw, member.name
                current[member.name] = hashlib.sha256(raw).hexdigest()
    checker = pathlib.Path('target/platform-lab/attachment_context_check.py')
    spec = importlib.util.spec_from_file_location('exact_context_checker', checker)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    platforms = {}
    for arch, machine in [('amd64', 62), ('arm64', 183)]:
        fields = candidate['platforms'][arch]
        artifact = pathlib.Path(fields['artifact'])
        assert sha(artifact) == fields['artifact_sha256']
        raw = artifact.read_bytes()
        assert raw[:7] == b'\x7fELF\x02\x01\x01'
        assert struct.unpack_from('<H', raw, 18)[0] == machine
        offset = struct.unpack_from('<Q', raw, 32)[0]
        size, count = struct.unpack_from('<HH', raw, 54)
        assert size == 56 and 1 <= count <= 256
        assert offset + size * count <= len(raw)
        kinds = {struct.unpack_from('<I', raw, offset + i * size)[0] for i in range(count)}
        assert 1 in kinds and not {2, 3}.intersection(kinds)
        retained = candidate_path.parent / (arch + '.context.tar')
        context = retained if retained.exists() else pathlib.Path(fields['context'])
        assert sha(context) == fields['context_sha256']
        manifest, inventory, _ = module.context_check(context, source, arch)
        if context != retained:
            with retained.open('xb') as stream:
                stream.write(context.read_bytes())
            retained.chmod(0o600)
            assert sha(retained) == fields['context_sha256']
        platforms[arch] = dict(
            manifest_sha256=manifest, context_sha256=sha(retained),
            payload_sha256=sha(artifact), verified_context_files=len(inventory),
            static_elf=True,
        )
    preflight = candidate_path.parent / 'amd64.filter-preflight'
    assert sha(preflight) == candidate['platforms']['amd64']['artifact_sha256']
    log = candidate_path.parent / 'amd64.filter-preflight.log'
    assert log.is_file()
    result = dict(
        binding=binding, current_source_matches=True,
        current_input_hashes=current, platforms=platforms,
        amd64_filter_preflight_log_sha256=sha(log),
        root_verifier_sha256=sha(pathlib.Path(__file__)),
        context_checker_sha256=sha(checker),
        native_bootstrap='NOT_RUN', arm64_runtime='NOT_RUN', release_ready=False,
    )
    output = candidate_path.parent / 'root-verification.json'
    with output.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    output.chmod(0o600)
    print(json.dumps(dict(output=str(output), binding=binding, platforms=platforms)))


if __name__ == '__main__':
    main()
