import pathlib,subprocess,json,os,time
r=pathlib.Path.cwd();s=r/'target/platform-lab/void-x86_64';p=json.loads((s/'process.json').read_text());pid=p['pid'];assert os.fsencode(str(s/'guest.qcow2'))in pathlib.Path(f'/proc/{pid}/cmdline').read_bytes();assert pathlib.Path(f'/proc/{pid}/stat').read_text().split(') ',1)[1][0]not in 'ZX'
ssh=['ssh','-i',str(r/'target/lab-state/id_ed25519'),'-p22035','-o','UserKnownHostsFile='+str(s/'known_hosts'),'-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=2','vprouterlab@127.0.0.1']
before=subprocess.run(ssh+['cat /proc/sys/kernel/random/boot_id'],capture_output=True,text=True,check=True,timeout=5).stdout.strip();q=subprocess.run(ssh+['sudo reboot'],capture_output=True,text=True,timeout=8)
(s/'nft-backend-reboot-request.json').write_text(json.dumps({'qemu_pid':pid,'boot_id_before':before,'ssh_reboot_returncode':q.returncode,'owned_identity_free_guest':True,'production_changes':False},indent=2)+'\n');assert q.returncode in [0,255]
code=r'''import pathlib,subprocess,json
run=lambda a:subprocess.run(a,capture_output=True,text=True,check=True).stdout
info=json.loads(run(['docker','info','--format','{{json .}}']))
print(json.dumps({'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'pid1':pathlib.Path('/proc/1/comm').read_text().strip(),'iptables':run(['iptables','--version']).strip(),'ip6tables':run(['ip6tables','--version']).strip(),'cgroup_driver':info['CgroupDriver'],'cgroup_version':info['CgroupVersion'],'nft_forward':json.loads(run(['nft','-j','list','chain','ip','filter','FORWARD'])),'legacy_table_names':pathlib.Path('/proc/net/ip_tables_names').read_text()if pathlib.Path('/proc/net/ip_tables_names').exists()else None},indent=2))
'''
end=time.monotonic()+50
while time.monotonic()<end:
 try:q=subprocess.run(ssh+['sudo python3 -'],input=code,capture_output=True,text=True,timeout=6)
 except subprocess.TimeoutExpired:time.sleep(1);continue
 if q.returncode==0:
  v=json.loads(q.stdout)
  if v['boot_id']!=before:break
 time.sleep(1)
else:raise RuntimeError('reboot/native Docker preflight not ready')
assert v['pid1']=='runit'and '(nf_tables)'in v['iptables']and v['cgroup_driver']=='cgroupfs'and v['cgroup_version']=='2'
assert any(x.get('chain',{}).get('policy')=='drop'for x in v['nft_forward']['nftables']);assert not(v['legacy_table_names']or'').strip()
(s/'nft-backend-after-reboot.json').write_text(json.dumps(v,indent=2)+'\n');print(json.dumps(v,indent=2))
