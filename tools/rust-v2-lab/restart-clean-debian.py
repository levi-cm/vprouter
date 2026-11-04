#!/usr/bin/env python3
"""Explicit restart of the preserved phase 2 guest, from the repository root.

Never creates a disk, seed or key. Retains process.json and archives runtime
files that QEMU reuses. A restart is a new boot, not historical live continuity.
"""
import datetime
import fcntl
import hashlib
import json
import os
import pathlib
import shutil
import socket
import subprocess
import time

if not __debug__:
    raise RuntimeError('optimized_python_refused')

repo = pathlib.Path.cwd()
state = repo / 'target/platform-lab/debian-clean-x86_64'
assert state.is_dir(), 'existing_state_required'
lock = (state / 'restart.lock').open('a')
fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
original = (state / 'process.json').read_bytes()
record = json.loads(original)
argv = record['argv']
assert record['platform'] == 'debian-clean-x86_64' and record['ssh_port'] == 22036
tools = repo / 'target/lab-tools/root'
assert argv[0] == str(tools / 'usr/bin/qemu-system-x86_64')
assert argv[argv.index('-drive') + 1] == f'file={state}/guest.qcow2,if=virtio,format=qcow2'
assert f'file={state}/seed.iso,media=cdrom,readonly=on' in argv
assert argv[argv.index('-netdev') + 1] == 'user,id=wan,hostfwd=tcp:127.0.0.1:22036-:22'
assert argv[argv.index('-serial') + 1] == f'file:{state}/serial.log'
assert argv[argv.index('-pidfile') + 1] == str(state / 'qemu.pid')
assert argv[argv.index('-qmp') + 1] == f'unix:{state}/qmp.sock,server=on,wait=off'
for name in ('guest.qcow2', 'seed.iso', 'user-data', 'meta-data'):
    assert (state / name).is_file(), name

def refuse_live():
    for proc in pathlib.Path('/proc').glob('[0-9]*'):
        try:
            raw = (proc / 'cmdline').read_bytes()
        except FileNotFoundError:
            continue
        except PermissionError:
            # A hidden process could own this disk: fail closed.
            raise RuntimeError(f'cannot_inspect_process:{proc.name}')
        if b'qemu' in raw and any(p.encode() in raw for p in
                                  (str(state), str(state.resolve()), '22036')):
            raise RuntimeError(f'live_qemu_for_state_or_port:{proc.name}')
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 22036))

refuse_live()
image = pathlib.Path(record['base_image'])
assert image == repo / 'target/lab-images/debian-13-genericcloud-amd64-20261021-2638.qcow2'
expected = '16e0965312c56feb331049d45d2b1b5778f3f942a33d4300eedbb97527707f2bea87c0006f3e4cc7a25fadbff739c4e235a51fb9bcd1b66fd554f7f8e80ba45c'
with image.open('rb') as stream:
    digest = hashlib.file_digest(stream, 'sha512').hexdigest()
assert digest == record['base_image_sha512'] == expected, 'base_sha512_mismatch'
manifest = pathlib.Path(record['checksum_manifest'])
matches = [line.split()[0] for line in manifest.read_text().splitlines()
           if line.split() and line.split()[-1].lstrip('*') == image.name]
assert matches == [digest], 'checksum_manifest_mismatch'
env = dict(os.environ, LD_LIBRARY_PATH=str(tools / 'usr/lib/x86_64-linux-gnu'),
           QEMU_MODULE_DIR=str(tools / 'usr/lib/x86_64-linux-gnu/qemu'))
chain = json.loads(subprocess.check_output(
    [str(tools / 'usr/bin/qemu-img'), 'info', '--output=json', '--backing-chain',
     str(state / 'guest.qcow2')], env=env))
assert len(chain) == 2 and all(x['format'] == 'qcow2' for x in chain), 'unexpected_chain'
assert pathlib.Path(chain[0]['filename']).resolve() == (state / 'guest.qcow2').resolve()
assert pathlib.Path(chain[0]['full-backing-filename']).resolve() == image.resolve()
assert pathlib.Path(chain[1]['filename']).resolve() == image.resolve()
assert not chain[1].get('backing-filename'), 'base_has_backing_file'
refuse_live()
stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
archive = state / ('restart-' + stamp)
archive.mkdir(mode=0o700)
(archive / 'backing-chain.json').write_text(json.dumps(chain, indent=2) + '\n')
for name in ('process.json', 'serial.log', 'qemu.log'):
    if (state / name).exists():
        shutil.copy2(state / name, archive / name)
for name in ('qemu.pid', 'qmp.sock'):
    if (state / name).exists():
        (state / name).rename(archive / name)
with (archive / 'qemu-new.log').open('xb') as log:
    process = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL,
                               stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
raw = pathlib.Path('/proc', str(process.pid), 'stat').read_text()
start = int(raw[raw.rfind(')') + 2:].split()[19])
new = dict(record, pid=process.pid, start_time=start,
           observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
           controller_boot_id=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
           original_process_sha256=hashlib.sha256(original).hexdigest(),
           previous_process_record=str(state / 'process.json'), restart_archive=str(archive),
           base_image_sha512=digest, backing_chain=chain, test_status='RESTART_BOOTING_NOT_VERIFIED')
destination = state / ('process-restart-' + stamp + '.json')
with destination.open('x') as stream:
    json.dump(new, stream, indent=2)
    stream.write('\n')
print(json.dumps(dict(process_record=str(destination), pid=process.pid, start_time=start)), flush=True)
time.sleep(1)
assert process.poll() is None, f'qemu_start_failed:{process.returncode}:see:{archive}/qemu-new.log'
assert pathlib.Path('/proc', str(process.pid), 'cmdline').read_bytes().split(b'\0')[:-1] == [s.encode() for s in argv]
assert (state / 'process.json').read_bytes() == original, 'original_record_changed'
