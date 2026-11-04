#!/usr/bin/env python3
"""Strict SSH read-only admission/clock syscall gates for the fresh lab.

Does not execute Bootstrap, create containers, enter namespaces or change nft.
Clock evidence is direct x86 syscall availability in the guest root process,
not execution of the frozen Rust driver or ARM runtime evidence.
"""
import hashlib
import json
import pathlib
import subprocess
import sys

if not __debug__:
    raise RuntimeError('optimized_python_refused')

REMOTE=r'''
import ctypes,json,os,pathlib,platform,stat,subprocess
assert os.geteuid()==0 and platform.machine()=='x86_64'
root=pathlib.Path('/var/lib/vprouter-v2-lab');metadata={}
for path in [pathlib.Path('/'),pathlib.Path('/var'),pathlib.Path('/var/lib'),root]:
 s=path.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==0 and not s.st_mode&0o022
 metadata[str(path)]={'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid,'dev':s.st_dev,'ino':s.st_ino}
assert stat.S_IMODE(root.stat().st_mode)==0o700
p=root/'isolated-acceptance';s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1
metadata[str(p)]={'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid,'nlink':s.st_nlink,'dev':s.st_dev,'ino':s.st_ino}
selectors=['owner-domain-nonce','secret-attachment.json','secret-attachment-spec.json','secret-attachment-staging.json','secret-quarantine-host.json','secret-host-baseline.json','task8b2-image','task8b2-host-acceptance']
assert all(not os.path.lexists(root/name) for name in selectors)
ns=pathlib.Path('/proc/self/ns/net').stat();init=pathlib.Path('/proc/1/ns/net').stat();assert (ns.st_dev,ns.st_ino)==(init.st_dev,init.st_ino)
def command(argv):
 r=subprocess.run(argv,capture_output=True,text=True,timeout=10);assert r.returncode==0,r.stderr;return r.stdout
links=json.loads(command(['ip','-j','link','show','dev','ens2']));assert len(links)==1 and links[0]['ifindex']==2 and links[0]['address']=='52:54:00:12:34:56' and links[0]['link_type']=='ether'
assert command(['systemctl','show','docker','--property=ActiveState','--value']).strip()=='active'
for digest in ['sha256:472c549d2ef8cebc000de2c8a94061bbdc864d2454177b2ada713262475449ef','sha256:08a1bc6c82fee62d1a135788fb67fefa9d22deea3830e8a45ebe1a3cb116e325']:
 command(['docker','image','inspect','--format','{{.Id}}','tailscale/tailscale@'+digest])
assert command(['docker','ps','-aq']).strip()==''
assert command(['stat','-fc','%T','/sys/fs/cgroup']).strip()=='cgroup2fs'
status=pathlib.Path('/proc/self/status').read_text();seccomp={line.split(':')[0]:line.split(':')[1].strip() for line in status.splitlines() if line.startswith(('Seccomp:','Seccomp_filters:','NoNewPrivs:'))}
class Timespec(ctypes.Structure):_fields_=[('tv_sec',ctypes.c_long),('tv_nsec',ctypes.c_long)]
libc=ctypes.CDLL(None,use_errno=True);libc.syscall.restype=ctypes.c_long
clocks=[]
for clock_id in [3,7]:
 t=Timespec();result=libc.syscall(ctypes.c_long(228),ctypes.c_long(clock_id),ctypes.byref(t));error=ctypes.get_errno() if result else 0
 assert result==0 and t.tv_sec>=0 and 0<=t.tv_nsec<1000000000
 clocks.append(dict(syscall=228,clock_id=clock_id,exit_code=result,errno=error,seconds=t.tv_sec,nanoseconds=t.tv_nsec))
assert seccomp['Seccomp']=='0'
print(json.dumps(dict(boot_id=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),namespace=[ns.st_dev,ns.st_ino],parents_marker=metadata,selectors_absent=selectors,wan=links[0],docker_active=True,pinned_images_inspected=True,no_containers=True,cgroup2=True,seccomp=seccomp,clock_syscalls=clocks,clock_scope='Direct x86_64 root guest syscall availability only; frozen driver execution and ARM64 runtime NOT_RUN',network_namespace_nft_container_mutations=False),indent=2))
'''


def main():
    output=pathlib.Path(sys.argv[1])
    ssh=['ssh','-F','/dev/null','-o','GlobalKnownHostsFile=/dev/null','-o','IdentitiesOnly=yes','-o','IdentityAgent=none','-o','BatchMode=yes','-o','UpdateHostKeys=no','-i','target/lab-state/id_ed25519','-p22036','-o','UserKnownHostsFile=target/platform-lab/debian-clean-x86_64/known_hosts','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=5','vprouterlab@127.0.0.1','sudo -n python3 -I -']
    r=subprocess.run(ssh,input=REMOTE,capture_output=True,text=True,timeout=30)
    with output.open('x') as f:json.dump(dict(argv=ssh,exit_code=r.returncode,stdout=r.stdout,stderr=r.stderr,helper_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()),f,indent=2)
    assert r.returncode==0 and not r.stderr,r.stderr
    data=json.loads(r.stdout);assert data['boot_id']=='e14efc10-050b-41b0-89d8-1e946725098c'
    print(json.dumps(data,indent=2))


if __name__=='__main__':main()
