# Controller-only setup for a read-only client-parser smoke; NOT worker placement.
import pathlib,subprocess,json,os,stat,sys
base=pathlib.Path('/var/lib/vprouter-v2-lab')
for p in [pathlib.Path('/'),pathlib.Path('/var'),pathlib.Path('/var/lib'),base]:
 st=p.lstat();assert stat.S_ISDIR(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022
st=(base/'isolated-acceptance').lstat();assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_gid==0 and st.st_mode&0o7777==0o600 and st.st_nlink==1
assert os.stat('/proc/self/ns/net').st_ino!=os.stat('/proc/1/ns/net').st_ino
assert os.stat('/proc/self/ns/mnt').st_ino!=os.stat('/proc/1/ns/mnt').st_ino
image='tailscale/tailscale@sha256:c507f3a2a6ab1cabd8d809b98edeb41edbd5c3fb6ad9632ffd098b4c7d0b4065'
r=subprocess.run(['docker','inspect','vprouter-v2-lab-primary-enrollment'],capture_output=True,text=True,check=True,timeout=3)
m=json.loads(r.stdout)[0];assert m['Config']['Image']==image and m['Config']['Labels']=={'io.vprouter.lab':'enrollment-only'} and m['State']['Running']
pid=m['State']['Pid'];assert pid>1
source=pathlib.Path(f'/proc/{pid}/root/run/tailscale')
st=(source/'tailscaled.sock').stat();assert stat.S_ISSOCK(st.st_mode) and st.st_uid==0
for args in [['mount','-t','tmpfs','-o','mode=0755,size=1m,nosuid,nodev,noexec','worker-lab-private-run','/run']]:subprocess.run(args,check=True,timeout=3)
pathlib.Path('/run/tailscale').mkdir(mode=0o755)
# Controller-only symlink in private read-only tmpfs, preserving the actual
# proc-root socket path; never canonicalize it into the host /run path.
pathlib.Path('/run/tailscale/tailscaled.sock').symlink_to(source/'tailscaled.sock')
subprocess.run(['mount','-o','remount,ro,nosuid,nodev,noexec','/run'],check=True,timeout=3)
assert ((source/'tailscaled.sock').stat().st_dev,(source/'tailscaled.sock').stat().st_ino)==(pathlib.Path('/run/tailscale/tailscaled.sock').stat().st_dev,pathlib.Path('/run/tailscale/tailscaled.sock').stat().st_ino)
r=subprocess.run([str(base/'worker-localapi-lab'),'--ignored'],capture_output=True,text=True,timeout=9)
print(json.dumps({'container_id':m['Id'],'source_pid':pid,'private_mount_and_no_wan_namespace':True,'same_actual_socket_inode':True,'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr,'production_changes':False,'native_worker_placement':'NOT_RUN','native_tls_provider':'NOT_RUN','real_client_traffic':'NOT_RUN'}))
sys.exit(r.returncode)
