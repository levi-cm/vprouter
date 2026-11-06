"""Fresh run411 ARM64 TCG guest; never reuse state or boot a consumed guest."""
import argparse,datetime,fcntl,hashlib,json,os,pathlib,re,shutil,socket,subprocess
if not __debug__:raise RuntimeError('optimized_python_refused')
FULL_SANDBOX='on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny'
BISECT=pathlib.Path('/tmp/claude-1000/-DATA-AppData-vprouter-rust-v2/9cc12d03-ae59-4a4d-9623-8b604dae09de/tasks/b3rbbqk4v.output')
BASE_SHA512='e66eea33be9e1345e6c8737e65096e5b31031f4bd4f3f7d59a6f8b53f995a9c41996e97c5b4ab89f1587663efed11dfbd10c4d35b7bcc85b2545e58a12cd0e83'
def bisect_gate(path,live_pids):
 text=pathlib.Path(path).read_text()
 assert 'BISECT_DONE' in text,'bisect_incomplete'
 assert not live_pids,('one_guest_only',live_pids)
 assert re.search(r'^full PASS(?: |$)',text,re.M),'full_sandbox_not_qualified'
 return FULL_SANDBOX

def live_guests():
 found=[]
 for proc in pathlib.Path('/proc').glob('[0-9]*'):
  try:raw=(proc/'cmdline').read_bytes().split(b'\0')[0]
  except (FileNotFoundError,ProcessLookupError):continue
  if pathlib.PurePosixPath(raw.decode()).name.startswith('qemu-system-'):found.append(int(proc.name))
 return found

def qemu_argv(repo,state,sandbox):
 tools=repo/'target/lab-tools/root';arm=repo/'target/platform-lab/tools';firmware=arm/'usr/share/AAVMF'
 argv=[str(arm/'usr/bin/qemu-system-aarch64'),'-accel','tcg,thread=multi','-machine','virt,gic-version=3','-cpu','cortex-a72','-smp','2','-m','1024',
 '-drive','if=pflash,format=raw,readonly=on,file='+str(firmware/'AAVMF_CODE.fd'),'-drive','if=pflash,format=raw,file='+str(state/'vars.fd'),
 '-drive','file='+str(state/'guest.qcow2')+',if=virtio,format=qcow2','-drive','file='+str(state/'seed.iso')+',media=cdrom,readonly=on',
 '-netdev','user,id=wan,hostfwd=tcp:127.0.0.1:22034-:22','-device','virtio-net-pci,netdev=wan,romfile=',
 '-display','none','-serial','file:'+str(state/'serial.log'),'-pidfile',str(state/'qemu.pid'),'-qmp','unix:'+str(state/'qmp.sock')+',server=on,wait=off','-L',str(tools/'usr/share/qemu')]
 if sandbox:argv+=['-sandbox',sandbox]
 return argv

def start(repo,instance_id):
 assert re.fullmatch(r'vprouter-run411-[a-zA-Z0-9_-]{1,80}',instance_id),'invalid_instance_id'
 state=repo/'target/platform-lab/debian-arm64'
 assert not os.path.lexists(state),'existing_state_requires_review'
 lock=(repo/'target/lab-state/guest-lifecycle.lock').open('a')
 fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 sandbox=bisect_gate(BISECT,live_guests())
 port=22034
 with socket.socket()as probe:probe.bind(('127.0.0.1',port))
 image=repo/'target/lab-images/debian-13-genericcloud-arm64-20261021-2638.qcow2'
 checksum_file=image.parent/'SHA512SUMS-20261021-2638'
 matches=[line.split()[0] for line in checksum_file.read_text().splitlines() if line.split()[-1].lstrip('*')==image.name]
 assert len(matches)==1
 with image.open('rb')as stream:digest=hashlib.file_digest(stream,'sha512').hexdigest()
 assert digest==matches[0]==BASE_SHA512,'base_image_checksum'
 state.mkdir(mode=0o700)
 tools=repo/'target/lab-tools/root'
 env=dict(os.environ,LD_LIBRARY_PATH=str(tools/'usr/lib/x86_64-linux-gnu'),QEMU_MODULE_DIR=str(tools/'usr/lib/x86_64-linux-gnu/qemu'))
 args=argparse.Namespace(instance_id=instance_id)
 public_key = (repo / "target/lab-state/id_ed25519.pub").read_text().strip()
 assert public_key.startswith("ssh-ed25519 ")
 config = {
     "hostname": "vprouter-debian-arm64-lab", "ssh_pwauth": False, "disable_root": True,
     "users": [{"name": "vprouterlab", "shell": "/bin/bash", "lock_passwd": True,
                "sudo": ["ALL=(ALL) NOPASSWD:ALL"], "ssh_authorized_keys": [public_key]}],
     "package_update": True, "package_upgrade": False,
     "packages": ["docker.io", "nftables", "iproute2", "wireguard-tools", "tcpdump", "python3", "sudo", "openssh-server"],
     "write_files": [{"path": "/var/lib/vprouter-v2-lab/isolated-acceptance", "owner": "root:root",
                      "permissions": "0600", "content": "additional local isolated lab; no enrolled identities or provider credentials\n"}],
     "runcmd": [["chmod", "0700", "/var/lib/vprouter-v2-lab"],
                ["systemctl", "enable", "--now", "docker"],
                ["sh", "-c", "test -S /run/docker.sock && test -f /sys/fs/cgroup/cgroup.controllers && touch /var/lib/vprouter-v2-lab/bootstrap-complete"]],
 }
 (state / "user-data").write_text("#cloud-config\n" + json.dumps(config, indent=2) + "\n")
 (state / "meta-data").write_text(json.dumps({"instance-id": args.instance_id, "local-hostname": "vprouter-debian-arm64-lab"}) + "\n")
 subprocess.run([str(tools / "usr/bin/genisoimage"), "-quiet", "-output", str(state / "seed.iso"),
                 "-volid", "cidata", "-joliet", "-rock", str(state / "user-data"), str(state / "meta-data")], env=env, check=True)
 disk = state / "guest.qcow2"
 subprocess.run([str(tools / "usr/bin/qemu-img"), "create", "-f", "qcow2", "-F", "qcow2", "-b", str(image), str(disk), "24G"], env=env, check=True)
 shutil.copyfile(repo/'target/platform-lab/tools/usr/share/AAVMF/AAVMF_VARS.fd',state/'vars.fd')
 argv=qemu_argv(repo,state,sandbox)
 with (state / "qemu.log").open("xb") as log:
     process = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=log,
                                stderr=subprocess.STDOUT, start_new_session=True)
 raw = pathlib.Path("/proc", str(process.pid), "stat").read_text()
 start = int(raw[raw.rfind(")") + 2:].split()[19])
 record = dict(instance_id=args.instance_id, controller_boot_id=pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip(), observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
               platform="debian-arm64", pid=process.pid, start_time=start, ssh_port=port, argv=argv,
               base_image=str(image), base_image_sha512=digest, checksum_manifest=str(checksum_file),
               test_status="BOOTING_NOT_VERIFIED", identities_imported=False, provider_credentials_imported=False,
               old_vm_changes=False, production_changes=False, sandbox=sandbox, bisect_evidence=BISECT.read_text(), memory_mib=1024)
 with (state / "process.json").open("x") as stream:
     json.dump(record, stream, indent=2)
     stream.write("\n")
 print(json.dumps(dict(platform=record["platform"], pid=process.pid, start_time=start, ssh_port=port,
                       test_status=record["test_status"], old_vm_changes=False, production_changes=False, sandbox=sandbox, bisect_evidence=BISECT.read_text(), memory_mib=1024)))

if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--instance-id',required=True);args=parser.parse_args();start(pathlib.Path.cwd(),args.instance_id)
