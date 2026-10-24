#!/usr/bin/env python3
"""Stage only fixed verified public inputs. Never invokes Docker or reads lab-state."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import struct
import tarfile

ROOT = Path(__file__).resolve().parent.parent


def checked(path, expected, executable=False, machine=None):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size != expected['bytes']:
            raise ValueError('fixed input type or size mismatch')
        data = b''
        while len(data) < before.st_size:
            piece = os.read(descriptor, min(65536, before.st_size-len(data)))
            if not piece:
                raise ValueError('truncated fixed input')
            data += piece
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
            before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size,
                                   after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('fixed input changed while hashing')
        if hashlib.sha256(data).hexdigest() != expected['sha256']:
            raise ValueError('fixed input digest mismatch')
        if executable:
            if data[:7] != b'\x7fELF\x02\x01\x01' or struct.unpack_from('<H',data,18)[0] != machine:
                raise ValueError('fixed input ELF architecture mismatch')
            offset = struct.unpack_from('<Q',data,32)[0]
            size, count = struct.unpack_from('<HH',data,54)
            if size != 56 or not 1 <= count <= 256 or offset+size*count>len(data):
                raise ValueError('invalid fixed ELF program headers')
            kinds = [struct.unpack_from('<I',data,offset+i*size)[0] for i in range(count)]
            if 1 not in kinds or any(k in (2,3) for k in kinds):
                raise ValueError('fixed ELF is not static without PT_DYNAMIC/PT_INTERP')
        return data
    finally:
        os.close(descriptor)


def build(architecture):
    target, machine = {'amd64':('x86_64',62),'arm64':('aarch64',183)}[architecture]
    manifest_path = ROOT / f'docs/rust-v2/programs-{architecture}.json'
    manifest = json.loads(manifest_path.read_bytes())
    source = json.loads((ROOT/'docs/rust-v2/pinned-program-inventory.json').read_bytes())
    public = next(p for p in source['platforms'] if p['platform']['architecture']==architecture)
    entries = {p['role']:p for p in manifest['programs']}
    if set(entries) != {'gateway_init','worker_observer','tailscaled'} or manifest['architecture'] != architecture or manifest['base_index'] != source['source_index'] or public['platform']['platform_manifest'] != 'tailscale/tailscale@'+manifest['base_platform']:
        raise ValueError('fixed source/manifest/platform mismatch')
    files = {}
    inputs = []
    for role, name in [('gateway_init','vprouter-gateway-init'),('worker_observer','vprouter-worker-observe'),('tailscaled','tailscaled')]:
        entry = entries[role]
        path = ROOT / (f'target/program-inventory/tailscale-1.102.5-{architecture}/tailscaled' if role=='tailscaled' else f'target/{target}-unknown-linux-musl/release/{name}')
        data = checked(path,entry,True,machine)
        if role=='tailscaled':
            upstream = next(p for p in public['public_files'] if p['source_path']=='/usr/local/bin/tailscaled')
            if (entry['sha256'],entry['bytes']) != (upstream['sha256'],upstream['bytes']):
                raise ValueError('fixed daemon differs from pinned OCI inventory')
        files['rootfs'+entry['path']] = (data,0o555)
        inputs.append({'path':str(path.relative_to(ROOT)),'sha256':entry['sha256'],'bytes':len(data)})
    ca = next(p for p in public['public_files'] if p['source_path']=='/etc/ssl/certs/ca-certificates.crt')
    files['rootfs/etc/ssl/certs/ca-certificates.crt'] = (checked(ROOT/ca['local_path'],ca),0o444)
    inputs.append({'path':ca['local_path'],'sha256':ca['sha256'],'bytes':ca['bytes']})
    manifest_bytes = manifest_path.read_bytes()
    manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
    files['rootfs/usr/share/vprouter/programs.json'] = (manifest_bytes,0o444)
    files['Dockerfile'] = (('FROM scratch\nCOPY rootfs /\nENV LANG=C PATH=/bin\nLABEL io.vprouter.source="'+manifest['base_index']+'" io.vprouter.platform="'+manifest['base_platform']+'" io.vprouter.programs="'+manifest_hash+'"\nENTRYPOINT ["/usr/local/bin/vprouter-worker"]\n').encode(),0o444)
    directories = {'rootfs/tmp','rootfs/state','rootfs/run','rootfs/proc','rootfs/dev/net'}
    for name in files:
        directories.update(str(p) for p in Path(name).parents if str(p)!='.')
    out = ROOT / 'target/gateway-context' / architecture
    out.mkdir(parents=True,exist_ok=False)
    archive = out/'context.tar'
    with tarfile.open(archive,'w',format=tarfile.USTAR_FORMAT) as tar:
        for name in sorted(directories):
            item=tarfile.TarInfo(name);item.type=tarfile.DIRTYPE;item.mode=0o755
            tar.addfile(item)
        for name,(data,mode) in sorted(files.items()):
            item=tarfile.TarInfo(name);item.mode=mode;item.size=len(data)
            tar.addfile(item,io.BytesIO(data))
    inventory={'schema':1,'architecture':architecture,'source_index':manifest['base_index'],'source_platform':manifest['base_platform'],'program_manifest_sha256':manifest_hash,'inputs':inputs,'context_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'context_bytes':archive.stat().st_size,'context_paths':sorted(directories|files.keys()),'identity_state_included':False,'production_ready':False}
    (out/'inventory.json').write_text(json.dumps(inventory,indent=2)+'\n')
    print(json.dumps({'context':str(archive),'sha256':inventory['context_sha256'],'bytes':inventory['context_bytes']}))


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--architecture',required=True,choices=('amd64','arm64'))
    build(parser.parse_args().architecture)
