"""Controller-only fixed actual-program runner in the owned local Debian VM.

Builds only an independently checked public whitelist context. Never imports
profiles, identity state or lab SSH files. Every failed runtime attempt is kept.
This is observation-only component evidence, never real-client acceptance.
"""
import datetime
import hashlib
import json
import pathlib
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import time


def sha(data):
    return hashlib.sha256(data).hexdigest()


def context_check(context, source, architecture='amd64'):
    assert architecture in {'amd64', 'arm64'}
    with tarfile.open(source) as archive:
        assert b'"--ignored-owner-expiry-partial-drop"' in archive.extractfile("crates/vprouter-launch/src/actual_lab_main.rs").read(), "frozen_source_missing_exact_lifecycle_flag"
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


GUEST = r'''
import hashlib,json,os,pathlib,stat,subprocess
root=pathlib.Path('/var/lib/vprouter-v2-lab')
assert os.geteuid()==0
for p in [pathlib.Path('/'),pathlib.Path('/var'),pathlib.Path('/var/lib'),root]:
 s=p.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==0 and not s.st_mode&0o022
assert stat.S_IMODE(root.lstat().st_mode)==0o700
def regular(path,mode):
 s=path.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==mode
regular(root/'isolated-acceptance',0o600)
config=CONFIGURATION
for kind,mode in [('payload',0o555),('context.tar',0o600)]:
 digest=config[kind]
 source=pathlib.Path('/home/vprouterlab/task8b2-'+digest)
 target=root/('task8b2-'+digest+'.'+kind)
 if target.exists():
  regular(target,mode);assert hashlib.sha256(target.read_bytes()).hexdigest()==digest
 else:
  s=source.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size<64*1024*1024
  data=source.read_bytes();assert hashlib.sha256(data).hexdigest()==digest
  fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
  with os.fdopen(fd,'wb') as out:out.write(data);out.flush();os.fsync(out.fileno())
  regular(target,mode)
 if source.exists():source.unlink()
net=pathlib.Path('/proc/self/ns/net').stat();init=pathlib.Path('/proc/1/ns/net').stat()
assert (net.st_dev,net.st_ino)==(init.st_dev,init.st_ino)
# Admission compares a separate protected host artifact with the container's
# exact PID1 bytes. Preserve each content-addressed artifact; the first frozen
# candidate alone also uses an exclusive legacy fixed path. Never replace it.
with __import__('tarfile').open(root/('task8b2-'+config['context.tar']+'.context.tar')) as archive:
 member=archive.getmember('rootfs/usr/local/bin/vprouter-worker')
 assert member.isfile() and member.size==config['init_bytes']
 data=archive.extractfile(member).read()
 assert hashlib.sha256(data).hexdigest()==config['init_sha256']
init_paths=[root/('task8b2-'+config['init_sha256']+'.gateway-init')]
if config['legacy_fixed_init']:init_paths.append(root/'task8b2-gateway-init')
for path in init_paths:
 if path.exists():
  regular(path,0o555);assert hashlib.sha256(path.read_bytes()).hexdigest()==config['init_sha256']
 else:
  fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o555)
  with os.fdopen(fd,'wb') as out:out.write(data);out.flush();os.fsync(out.fileno())
  regular(path,0o555)
def run(args):
 r=subprocess.run(args,capture_output=True,text=True,timeout=8)
 assert r.returncode==0,(args,r.returncode,r.stderr[:4096])
 assert len(r.stdout)<4*1024*1024
 return r.stdout
routes=json.loads(run(['ip','-j','-4','route','show','table','all']))
addresses=json.loads(run(['ip','-j','address','show']))
chain=json.loads(run(['nft','-j','list','chain','ip','filter','FORWARD']))
assert any(v.get('chain',{}).get('policy')=='drop' for v in chain['nftables'])
markers=[root/'task8b2-image',root/'task8b2-host-acceptance']
assert not any(p.exists() or p.is_symlink() for p in markers),'stale_marker_requires_review'
build=root/('task8b2-build-'+config['context.tar'])
if not build.exists():build.mkdir(mode=0o700)
s=build.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700
iid=build/'image-id'
if not iid.exists():
 result=subprocess.run(['docker','build','--network=none','--pull=false','--iidfile',str(iid),'-'],stdin=(root/('task8b2-'+config['context.tar']+'.context.tar')).open('rb'),capture_output=True,text=True,timeout=75)
 print(json.dumps({'build_exit':result.returncode,'build_stdout':result.stdout[:32768],'build_stderr':result.stderr[:32768]}),flush=True)
 assert result.returncode==0
 os.chmod(iid,0o600)
regular(iid,0o600)
image_id=iid.read_text().strip()
assert __import__('re').fullmatch('sha256:[a-f0-9]{64}',image_id)
image=json.loads(run(['docker','image','inspect',image_id]))[0]
assert image['Id']==image_id and image['Config']['Entrypoint']==['/usr/local/bin/vprouter-worker']
assert image['Config']['Labels']['io.vprouter.programs']==config['manifest']
contents=[{'schema':1,'image_id':image_id,'program_manifest_sha256':config['manifest']},{'artifact_sha256':config['payload'],'network_dev':net.st_dev,'network_ino':net.st_ino}]
made=[]
try:
 for path,content in zip(markers,contents):
  fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'w') as out:json.dump(content,out);out.flush();os.fsync(out.fileno())
  made.append((path,content))
 print(json.dumps({'preflight':'PASS','host_namespace':{'dev':net.st_dev,'ino':net.st_ino},'image_id':image_id,'image_layers':image['RootFS']['Layers'],'docker_forward_before':chain,'routes_before':routes,'addresses_before':addresses}),flush=True)
 payload=str(root/('task8b2-'+config['payload']+'.payload'))
 nonce_path=root/'owner-domain-nonce'
 assert not nonce_path.exists() and not nonce_path.is_symlink(),'existing_nonce_requires_review'
 # Choose a fresh fixture endpoint without removing retained earlier WANs.
 current_routes=json.loads(run(['ip','-j','-4','route','show','table','all']))
 current_addresses=json.loads(run(['ip','-j','address','show']))
 for attempt in range(16):
  nonce=__import__('secrets').token_hex(32)
  endpoint='185.66.'+str(int(nonce[:2],16))+'.'+str(int(nonce[2:4],16))
  host_endpoint='185.66.'+str(int(nonce[:2],16))+'.'+str(int(nonce[2:4],16)^1)
  selected={endpoint,endpoint+'/32',host_endpoint,host_endpoint+'/32'}
  if not any(r.get('dst') in selected for r in current_routes) and not any(a.get('local') in selected for i in current_addresses for a in i.get('addr_info',[])):break
 else:raise AssertionError('no_free_nonce_synthetic_endpoint')
 fd=os.open(nonce_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as f:f.write(nonce);f.flush();os.fsync(f.fileno())
 regular(nonce_path,0o600)
 descriptor=subprocess.run([payload,'--owner-bootstrap-descriptor'],capture_output=True,text=True,timeout=5,check=True)
 descriptor=json.loads(descriptor.stdout)
 unit=descriptor['owner_unit']
 assert __import__('re').fullmatch('vprouter-v2-owner@[a-f0-9]{64}[.]service',unit)
 prior=subprocess.run(['systemctl','show','--property=LoadState','--value',unit],capture_output=True,text=True,timeout=5)
 assert prior.stdout.strip()=='not-found',('preexisting_owner_unit',prior.stdout)
 assert descriptor['deployment_id']=='launchlab-'+nonce[:12] and descriptor['nonce']==nonce
 output_path=root/('owner-probe-'+nonce+'.stdout')
 diagnostic_path=root/('owner-probe-'+nonce+'.stderr')
 for target in (output_path,diagnostic_path):
  fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb') as f:f.flush();os.fsync(f.fileno())
  regular(target,0o600)
 print(json.dumps({'owner_probe':{'unit':unit,'nonce':nonce,'mode':'expiry-partial-drop','component_only':True}}),flush=True)
 argv=['systemd-run','--quiet','--wait','--collect','--service-type=exec','--property=StandardInput=null','--property=StandardOutput=file:'+str(output_path),'--property=StandardError=file:'+str(diagnostic_path),'--unit='+unit,'--property=Slice=system.slice','--property=KillMode=control-group','--property=KillSignal=SIGKILL','--property=TimeoutStopSec=3s','--property=RuntimeMaxSec=110s','--',payload,'--ignored-owner-expiry-partial-drop']
 if config['raw_syscall_metadata']:
  trace=root/('task8b2-trace-'+config['payload']+'-'+str(os.getpid()))
  trace.mkdir(mode=0o700)
  print(json.dumps({'trace_directory':str(trace),'trace_kind':'raw_syscall_arguments_no_decoded_buffers_or_environments'}),flush=True)
  argv=['strace','-ff','-qq','-e','raw=all','-o',str(trace/'syscall'),'--',*argv]
 elif config['file_path_metadata']:
  trace=root/('task8b2-path-trace-'+config['payload']+'-'+str(os.getpid()))
  trace.mkdir(mode=0o700)
  print(json.dumps({'trace_directory':str(trace),'trace_kind':'fixed_file_metadata_syscalls_only_no_io_random_or_exec_environment'}),flush=True)
  calls='openat,openat2,newfstatat,getcwd,mkdirat,statx,access,faccessat'
  argv=['strace','-ff','-qq','-s','256','-e','trace='+calls,'-o',str(trace/'syscall'),'--',*argv]
 elif config['stderr_diagnostic']:
  # Only the fresh identity-free fixture is eligible. Never trace reads,
  # configuration, state, credentials, environments or logged-in daemons.
  trace=root/('task8b2-stderr-trace-'+config['payload']+'-'+str(os.getpid()))
  trace.mkdir(mode=0o700)
  print(json.dumps({'trace_directory':str(trace),'trace_kind':'private_bounded_fd2_writes_only_identity_free_fixture'}),flush=True)
  argv=['strace','-ff','-qq','-s','256','-e','trace=write,writev','-e','trace-fds=2','-o',str(trace/'syscall'),'--',*argv]
 elif config['peer_credential_metadata']:
  trace=root/('task8b2-peer-trace-'+config['payload']+'-'+str(os.getpid()))
  trace.mkdir(mode=0o700)
  print(json.dumps({'trace_directory':str(trace),'trace_kind':'getsockopt_metadata_only_no_io_or_environment'}),flush=True)
  argv=['strace','-ff','-qq','-e','trace=getsockopt','-o',str(trace/'syscall'),'--',*argv]
 result=subprocess.run(argv,timeout=120)
 for target in (output_path,diagnostic_path):regular(target,0o600)
 output=output_path.read_bytes();diagnostic=diagnostic_path.read_bytes()
 assert len(output)<4*1024*1024 and len(diagnostic)<65536
 print(output.decode(),end='',flush=True)
 if diagnostic:os.write(2,diagnostic)
 print(json.dumps({'owner_probe_output':str(output_path),'owner_probe_diagnostic':str(diagnostic_path)}),flush=True)
 if result.returncode==0:
  regular(nonce_path,0o600);assert nonce_path.read_text()==nonce
  nonce_path.unlink()
 else:
  print(json.dumps({'owner_nonce_retained':str(nonce_path),'reason':'failed_native_probe_requires_actor_review'}),flush=True)
 print(json.dumps({'harness_exit_code':result.returncode,'docker_forward_after':json.loads(run(['nft','-j','list','chain','ip','filter','FORWARD']))}),flush=True)
finally:
 for path,content in reversed(made):
  regular(path,0o600);assert json.loads(path.read_text())==content;path.unlink()
raise SystemExit(result.returncode)
'''


def main():
    assert 8 <= len(sys.argv) <= 10, 'usage: artifact sha256 source.tar sha256 context.tar sha256 full_source_commit [--legacy-fixed-init] [--raw-syscall-metadata | --file-path-metadata | --stderr-diagnostic | --peer-credential-metadata]'
    artifact, digest, source, source_digest, context, context_digest, commit = sys.argv[1:8]
    options = set(sys.argv[8:])
    assert len(options) == len(sys.argv[8:]) and options <= {'--legacy-fixed-init', '--raw-syscall-metadata', '--file-path-metadata', '--stderr-diagnostic', '--peer-credential-metadata'}
    legacy_fixed_init = '--legacy-fixed-init' in options
    raw_syscall_metadata = '--raw-syscall-metadata' in options
    file_path_metadata = '--file-path-metadata' in options
    stderr_diagnostic = '--stderr-diagnostic' in options
    peer_credential_metadata = '--peer-credential-metadata' in options
    assert sum([raw_syscall_metadata, file_path_metadata, stderr_diagnostic, peer_credential_metadata]) <= 1
    assert re.fullmatch('[a-f0-9]{40}', commit)
    for path, expected in ((artifact, digest), (source, source_digest), (context, context_digest)):
        assert re.fullmatch('[a-f0-9]{64}', expected)
        assert sha(pathlib.Path(path).read_bytes()) == expected
    binding = json.loads(subprocess.check_output([
        sys.executable, 'tools/verify-frozen-build-inputs.py', source, commit
    ]))
    manifest_digest, inventory, init = context_check(context, source)
    base = pathlib.Path('target/lab-state')
    for path, expected, suffix in ((artifact, digest, 'payload'), (source, source_digest, 'source.tar'),
                                   (context, context_digest, 'context.tar')):
        retained = base / ('task8b2-' + expected + '.' + suffix)
        if retained.exists():
            assert sha(retained.read_bytes()) == expected
        else:
            with retained.open('xb') as out, pathlib.Path(path).open('rb') as input_file:
                shutil.copyfileobj(input_file, out)
            retained.chmod(0o600)
    opts = ['-i', str(base / 'id_ed25519'), '-o', 'IdentitiesOnly=yes', '-o',
            'UserKnownHostsFile=' + str(base / 'known_hosts'), '-o',
            'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=5']
    ssh = ['ssh', *opts, '-p22032', 'vprouterlab@127.0.0.1']
    started = time.monotonic()
    try:
        for path, expected in ((artifact, digest), (context, context_digest)):
            subprocess.run(['scp', '-q', *opts, '-P22032', path,
                            'vprouterlab@127.0.0.1:/home/vprouterlab/task8b2-' + expected],
                           check=True, timeout=30, capture_output=True, text=True)
        guest = GUEST.replace('CONFIGURATION', repr({
            'payload': digest, 'context.tar': context_digest, 'manifest': manifest_digest,
            'init_sha256': init['sha256'], 'init_bytes': init['bytes'],
            'legacy_fixed_init': legacy_fixed_init, 'raw_syscall_metadata': raw_syscall_metadata,
            'file_path_metadata': file_path_metadata,
            'stderr_diagnostic': stderr_diagnostic,
            'peer_credential_metadata': peer_credential_metadata,
        }))
        result = subprocess.run([*ssh, 'sudo unshare --mount --propagation private python3 -'],
                                input=guest, capture_output=True, text=True, timeout=210)
        code, stdout, stderr = result.returncode, result.stdout, result.stderr
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        code = error.returncode if isinstance(error, subprocess.CalledProcessError) else 124
        def decoded(value):
            return value.decode(errors='replace') if isinstance(value, bytes) else (value or '')
        stdout, stderr = decoded(error.stdout), decoded(error.stderr)
    evidence = {
        'observed_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'artifact_sha256': digest, 'source_archive_sha256': source_digest,
        'source_binding': binding, 'context_sha256': context_digest,
        'program_manifest_sha256': manifest_digest, 'context_inventory': inventory,
        'runner_sha256': sha(pathlib.Path(__file__).read_bytes()),
        'exit_code': code, 'wall_seconds': round(time.monotonic() - started, 3),
        'stdout': stdout, 'stderr': stderr,
        'result': 'PASS_PARTIAL_ACTUAL_PROGRAMS' if code == 0 else 'FAIL',
        'component_test_mode':'owner_expiry_partial_drop', 'real_client_acceptance': 'NOT_RUN', 'production_changes': False,
        'raw_syscall_metadata': raw_syscall_metadata,
        'file_path_metadata': file_path_metadata,
        'stderr_diagnostic': stderr_diagnostic,
        'peer_credential_metadata': peer_credential_metadata,
    }
    attempt = 1
    while (base / f'actual-program-run-{attempt}.json').exists():
        attempt += 1
    path = base / f'actual-program-run-{attempt}.json'
    with path.open('x') as out:
        json.dump(evidence, out, indent=2)
        out.write('\n')
    path.chmod(0o600)
    summary = {key: value for key, value in evidence.items() if key != 'stdout'}
    summary['record'] = str(path)
    summary['runtime_events'] = []
    for line in stdout.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if 'case' in event or 'trace_directory' in event:
            summary['runtime_events'].append(event)
    print(json.dumps(summary, indent=2))
    return 0 if code == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
