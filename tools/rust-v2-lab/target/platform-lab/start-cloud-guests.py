import pathlib,os,json,subprocess,shutil,socket
root=pathlib.Path(__file__).resolve().parent
repo=root.parent.parent
tools=repo/'target/lab-tools/root'
env=dict(os.environ,LD_LIBRARY_PATH=str(tools/'usr/lib/x86_64-linux-gnu'),
         QEMU_MODULE_DIR=str(tools/'usr/lib/x86_64-linux-gnu/qemu'))
public_key=(repo/'target/lab-state/id_ed25519.pub').read_text().strip()
inventory=json.loads((root/'input-inventory.json').read_text())
assert json.loads((root/'arch-signature-verification.json').read_text())['signature_verified']
rows=[]
for platform,port,image in [
 ('arch-x86_64',22033,'Arch-Linux-x86_64-cloudimg-20261015.611680.qcow2'),
 ('debian-arm64',22034,'debian-13-genericcloud-arm64-20261021-2638.qcow2')]:
    assert any(pathlib.Path(i['path']).name==image and i['checksum_verified'] for i in inventory['images'])
    state=root/platform
    state.mkdir(mode=0o700,exist_ok=True)
    if (state/'process.json').exists():
        print(platform,'already has process record; inspect before relaunch',flush=True)
        continue
    with socket.socket() as sock:assert sock.connect_ex(('127.0.0.1',port))!=0
    packages=['docker','nftables','iproute2','wireguard-tools','tcpdump','python','sudo','openssh'] if platform.startswith('arch') else ['docker.io','nftables','iproute2','wireguard-tools','tcpdump','python3','sudo','openssh-server']
    config={
      'hostname':'vprouter-'+platform+'-lab','ssh_pwauth':False,'disable_root':True,
      'users':[{'name':'vprouterlab','shell':'/bin/bash','lock_passwd':True,
                'sudo':['ALL=(ALL) NOPASSWD:ALL'],'ssh_authorized_keys':[public_key]}],
      'package_update':True,'package_upgrade':False,'packages':packages,
      'write_files':[{'path':'/var/lib/vprouter-v2-lab/isolated-acceptance','owner':'root:root','permissions':'0600','content':'local disposable platform acceptance only\n'}],
      'runcmd':[['chmod','0700','/var/lib/vprouter-v2-lab'],
                 ['systemctl','enable','--now','docker'],
                 ['sh','-c','test -S /run/docker.sock && test -f /sys/fs/cgroup/cgroup.controllers && touch /var/lib/vprouter-v2-lab/bootstrap-complete']],
    }
    (state/'user-data').write_text('#cloud-config\n'+json.dumps(config,indent=2)+'\n')
    (state/'meta-data').write_text(json.dumps({'instance-id':'vprouter-'+platform+'-20261026','local-hostname':'vprouter-'+platform+'-lab'})+'\n')
    subprocess.run([str(tools/'usr/bin/genisoimage'),'-quiet','-output',str(state/'seed.iso'),'-volid','cidata','-joliet','-rock',str(state/'user-data'),str(state/'meta-data')],env=env,check=True)
    disk=state/'guest.qcow2'
    if not disk.exists():subprocess.run([str(tools/'usr/bin/qemu-img'),'create','-f','qcow2','-F','qcow2','-b',str(root/'downloads'/image),str(disk),'24G'],env=env,check=True)
    if platform.startswith('arch'):
        argv=[str(tools/'usr/bin/qemu-system-x86_64'),'-accel','kvm','-machine','pc,smm=off','-cpu','host',
              '-bios',str(tools/'usr/share/seabios/bios-256k.bin'),'-vga','none']
    else:
        firmware=root/'tools/usr/share/AAVMF'
        variables=state/'AAVMF_VARS.fd'
        if not variables.exists():shutil.copyfile(firmware/'AAVMF_VARS.fd',variables)
        argv=[str(root/'tools/usr/bin/qemu-system-aarch64'),'-accel','tcg,thread=multi','-machine','virt,gic-version=3','-cpu','cortex-a72',
              '-drive','if=pflash,format=raw,readonly=on,file='+str(firmware/'AAVMF_CODE.fd'),
              '-drive','if=pflash,format=raw,file='+str(variables)]
    argv+=['-smp','2','-m','1536','-drive','file='+str(disk)+',if=virtio,format=qcow2',
           '-drive','file='+str(state/'seed.iso')+',media=cdrom,readonly=on',
           '-netdev',f'user,id=wan,hostfwd=tcp:127.0.0.1:{port}-:22',
           '-device','virtio-net-pci,netdev=wan,romfile=','-display','none',
           '-serial','file:'+str(state/'serial.log'),'-pidfile',str(state/'qemu.pid'),
           '-qmp','unix:'+str(state/'qmp.sock')+',server=on,wait=off',
           '-L',str(tools/'usr/share/qemu'),'-sandbox','on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny']
    with (state/'qemu.log').open('ab') as output:
        process=subprocess.Popen(argv,env=env,stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
    row={'platform':platform,'pid':process.pid,'ssh_port':port,'argv':argv,'test_status':'BOOTING_NOT_VERIFIED','production_changes':False}
    (state/'process.json').write_text(json.dumps(row,indent=2)+'\n')
    print(json.dumps(row),flush=True)
