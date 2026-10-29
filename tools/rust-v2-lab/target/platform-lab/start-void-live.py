import pathlib,subprocess,json,os,socket,time
root=pathlib.Path(__file__).resolve().parent;repo=root.parent.parent
tools=repo/'target/lab-tools/root'
env=dict(os.environ,LD_LIBRARY_PATH=str(tools/'usr/lib/x86_64-linux-gnu'),QEMU_MODULE_DIR=str(tools/'usr/lib/x86_64-linux-gnu/qemu'))
state=root/'void-x86_64';state.mkdir(mode=0o700,exist_ok=True)
assert not (state/'process.json').exists(),'inspect existing process before relaunch'
with socket.socket() as sock:assert sock.connect_ex(('127.0.0.1',22035))!=0
subprocess.run([str(root/'tools/usr/bin/minisign'),'-V','-p',str(root/'downloads/void-release-20250202.pub'),'-x',str(root/'downloads/void.sha256sum.sig'),'-m',str(root/'downloads/void.sha256sum.txt')],check=True)
iso=root/'downloads/void-live-x86_64-20250202-base.iso'
for name in ['vmlinuz','initrd']:
 path=state/name
 if not path.exists():
  with path.open('wb') as output:subprocess.run([str(tools/'usr/bin/isoinfo'),'-R','-x','/boot/'+name,'-i',str(iso)],env=env,stdout=output,check=True)
 assert path.stat().st_size>1024*1024
(state/'vprouter.pub').write_bytes((repo/'target/lab-state/id_ed25519.pub').read_bytes())
bootstrap='''#!/bin/sh
set -eu
test "$(id -u)" = 0
if ! id vprouterlab >/dev/null 2>&1; then useradd -m -s /bin/bash vprouterlab; fi
install -d -m 0700 -o vprouterlab -g vprouterlab /home/vprouterlab/.ssh
install -m 0600 -o vprouterlab -g vprouterlab /mnt/vprouter.pub /home/vprouterlab/.ssh/authorized_keys
mkdir -p /etc/sudoers.d
printf '%s\n' 'vprouterlab ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/90-vprouter-lab
chmod 0440 /etc/sudoers.d/90-vprouter-lab
passwd -l root
if [ ! -e /etc/runit/runsvdir/default/sshd ]; then ln -s /etc/sv/sshd /etc/runit/runsvdir/default/sshd; fi
install -d -m 0700 /var/lib/vprouter-v2-lab
umask 077
printf '%s\n' 'local disposable Void live staging only' > /var/lib/vprouter-v2-lab/isolated-acceptance
printf '%s\n' 'VPROUTER_VOID_BOOTSTRAP_COMPLETE'
'''
(state/'bootstrap.sh').write_text(bootstrap)
subprocess.run([str(tools/'usr/bin/genisoimage'),'-quiet','-output',str(state/'seed.iso'),'-volid','VPR_VOID_SEED','-joliet','-rock',str(state/'vprouter.pub'),str(state/'bootstrap.sh')],env=env,check=True)
disk=state/'guest.qcow2'
if not disk.exists():subprocess.run([str(tools/'usr/bin/qemu-img'),'create','-f','qcow2',str(disk),'24G'],env=env,check=True)
argv=[str(tools/'usr/bin/qemu-system-x86_64'),'-accel','kvm','-machine','pc,smm=off','-cpu','host','-smp','2','-m','1536',
 '-bios',str(tools/'usr/share/seabios/bios-256k.bin'),'-vga','none',
 '-kernel',str(state/'vmlinuz'),'-initrd',str(state/'initrd'),
 '-append','root=live:CDLABEL=VOID_LIVE ro rd.luks=0 rd.md=0 rd.dm=0 rd.live.overlay.overlayfs=1 console=ttyS0,115200 cgroup_no_v1=all loglevel=4 init=/bin/sh',
 '-drive','file='+str(disk)+',if=none,id=voiddisk,format=qcow2',
 '-device','virtio-blk-pci,drive=voiddisk,serial=VPROUTER_VOID_LAB_20261026',
 '-drive','file='+str(iso)+',media=cdrom,readonly=on',
 '-drive','file='+str(state/'seed.iso')+',media=cdrom,readonly=on',
 '-netdev','user,id=wan,hostfwd=tcp:127.0.0.1:22035-:22','-device','virtio-net-pci,netdev=wan,romfile=',
 '-display','none','-chardev','socket,id=serial0,path='+str(state/'serial.sock')+',server=on,wait=on,logfile='+str(state/'serial.log'),
 '-serial','chardev:serial0','-pidfile',str(state/'qemu.pid'),'-qmp','unix:'+str(state/'qmp.sock')+',server=on,wait=off',
 '-L',str(tools/'usr/share/qemu'),'-sandbox','on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny']
with (state/'qemu.log').open('ab') as output:
 process=subprocess.Popen(argv,env=env,stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
(state/'process.json').write_text(json.dumps({'platform':'void-x86_64','pid':process.pid,'ssh_port':22035,'argv':argv,'test_status':'LIVE_STAGING_NOT_INSTALLED_NOT_VERIFIED','production_changes':False},indent=2)+'\n')
print('Void live staging PID',process.pid)
end=time.monotonic()+8
connection=socket.socket(socket.AF_UNIX);connection.settimeout(1)
while True:
 try:connection.connect(str(state/'serial.sock'));break
 except (FileNotFoundError,ConnectionRefusedError):
  if time.monotonic()>end:raise
  time.sleep(.1)
data=b'';end=time.monotonic()+45
while b'# ' not in data:
 try:data+=connection.recv(65536)
 except socket.timeout:pass
 assert time.monotonic()<end,'initial root shell not reached'
 assert len(data)<2*1024*1024
connection.sendall(b'mount -o remount,rw /; mkdir -p /mnt; mount /dev/sr1 /mnt; sh /mnt/bootstrap.sh && exec /sbin/init\n')
end=time.monotonic()+30
while b'VPROUTER_VOID_BOOTSTRAP_COMPLETE' not in data:
 try:data+=connection.recv(65536)
 except socket.timeout:pass
 assert time.monotonic()<end,'bootstrap did not finish'
print('Void live key/bootstrap staging finished; installed runtime remains unverified',flush=True)
connection.close()
