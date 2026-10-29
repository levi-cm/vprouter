import pathlib,subprocess,json,hashlib
r=pathlib.Path.cwd();s=r/'target/platform-lab/void-x86_64';opts=['-i',str(r/'target/lab-state/id_ed25519'),'-p22035','-o','UserKnownHostsFile='+str(s/'known_hosts'),'-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=5'];ssh=['ssh',*opts,'vprouterlab@127.0.0.1']
script=r'''
import pathlib,subprocess,os,json,hashlib,stat
root=pathlib.Path('/var/lib/vprouter-v2-lab');assert os.geteuid()==0 and stat.S_IMODE(root.stat().st_mode)==0o700
p=subprocess.run(['docker','ps','-aq'],capture_output=True,text=True,check=True);assert not p.stdout.strip(),'owned identity-free guest must have no containers before backend reboot'
assert not pathlib.Path('/var/service/iptables').exists() and not pathlib.Path('/var/service/ip6tables').exists()
out=root/'nft-backend-switch-20261026';out.mkdir(mode=0o700)
def keep(name,args):
 p=subprocess.run(args,capture_output=True,check=True);f=out/name;f.write_bytes(p.stdout);f.chmod(0o600);return hashlib.sha256(p.stdout).hexdigest()
old={name:keep(name,args) for name,args in [('iptables-before.save',['iptables-save']),('ip6tables-before.save',['ip6tables-save']),('alternatives-before.txt',['xbps-alternatives','-l'])]}
p=subprocess.run(['xbps-install','-Sy','iptables-nft'],capture_output=True);(out/'install.stdout').write_bytes(p.stdout);(out/'install.stderr').write_bytes(p.stderr);assert p.returncode==0,p.returncode
p=subprocess.run(['xbps-alternatives','-s','iptables-nft'],capture_output=True);(out/'select.stdout').write_bytes(p.stdout);(out/'select.stderr').write_bytes(p.stderr);assert p.returncode==0,p.returncode
new={}
for cmd in ['iptables','ip6tables']:
 v=subprocess.run([cmd,'--version'],capture_output=True,text=True,check=True).stdout.strip();assert '(nf_tables)'in v;new[cmd]=v
v={'owned_guest_no_containers':True,'old_snapshot_sha256':old,'selected_frontends':new,'cold_reboot_required_before_router_tests':True,'production_changes':False};p=out/'transition.json';p.write_text(json.dumps(v,indent=2)+'\n')
for p in out.iterdir():p.chmod(0o600)
subprocess.run(['sync'],check=True);print(json.dumps(v,indent=2))
'''
p=subprocess.run(ssh+['sudo python3 -'],input=script,capture_output=True,text=True,timeout=60);(s/'nft-backend-switch.stderr').write_text(p.stderr);assert p.returncode==0,p.stderr
(s/'nft-backend-switch.json').write_text(p.stdout);print(p.stdout)
