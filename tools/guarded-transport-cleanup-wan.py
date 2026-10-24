"""Remove only the failed test WAN veth matched to a retained read-only inventory.

Leaves the test container, namespace pins, cgroup and quarantines for inspection.
"""
import json
import pathlib
import subprocess
import sys

assert len(sys.argv) == 3, "usage: inventory_json exact_test_directory"
inventory = json.loads(pathlib.Path(sys.argv[1]).read_text())
matches = [d for d in inventory["deployments"] if d["directory"] == sys.argv[2]]
assert len(matches) == 1 and inventory["read_only"] is True
expected = matches[0]
host = next(s for s in expected["scopes"] if s["scope"] == "host")
resource = expected["resources"]
links = [l for l in host["links"]["data"] if l["ifname"] == resource["wan_host"]]
assert len(links) == 1
expected = {"directory": expected["directory"], "resources": resource, "link": links[0]}
script = r'''
import json,pathlib,subprocess,stat,os,datetime
expected=EXPECTED
root=pathlib.Path('/var/lib/vprouter-v2-lab');m=(root/'isolated-acceptance').lstat()
assert os.geteuid()==0 and stat.S_ISREG(m.st_mode) and m.st_uid==0 and m.st_gid==0 and m.st_nlink==1 and stat.S_IMODE(m.st_mode)==0o600
directory=pathlib.Path(expected['directory'])
assert directory.parent==root and __import__('re').fullmatch(r'(?:task8a|task8b2)-[1-9][0-9]*',directory.name)
record=directory/'resources.json';s=record.lstat()
assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_gid==0 and s.st_nlink==1 and not s.st_mode&0o077
r=json.loads(record.read_text());assert r==expected['resources']
def call(argv):return subprocess.run(argv,check=True,capture_output=True,text=True,timeout=4).stdout
meta=json.loads(call(['docker','inspect',r['container']]))[0]
assert meta['Id']==r['container'] and meta['Config']['Labels']['io.vprouter.deployment']==r['deployment'] and meta['Config']['Labels']['io.vprouter.role']=='gateway' and meta['HostConfig']['NetworkMode']=='none'
wan=json.loads(call(['ip','-j','-d','link','show','dev',r['wan_host']]))[0]
for k in ['ifindex','link_index','ifname','address','link_netnsid','ifalias','linkinfo']:
 assert wan[k]==expected['link'][k],('identity_drift',k)
assert wan['ifalias']=='task8a-owned-synthetic-wan' and wan['linkinfo']['info_kind']=='veth'
addresses=json.loads(call(['ip','-j','address','show','dev',r['wan_host']]))[0]['addr_info']
assert [(a['local'],a['prefixlen']) for a in addresses if a['family']=='inet']==[('185.65.134.89',32)]
peers=json.loads(call(['ip','-n',r['wan_namespace'],'-j','-d','link','show']))
peers=[p for p in peers if p['ifindex']==wan['link_index']]
assert len(peers)==1 and peers[0]['link_index']==wan['ifindex'] and peers[0]['linkinfo']['info_kind']=='veth'
assert json.loads(call(['ip','-j','-4','route','show','185.65.134.88/32']))==[{'dst':'185.65.134.88','dev':r['wan_host'],'scope':'link','prefsrc':'185.65.134.89','flags':[]}]
call(['ip','link','delete','dev',r['wan_host']])
assert not json.loads(call(['ip','-j','-4','route','show','185.65.134.88/32']))
print(json.dumps({'observed_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'operation':'delete_exact_failed_attempt_synthetic_wan_veth_only','directory':str(directory),'verified_link_before':wan,'synthetic_endpoint_route_removed_with_link':True,'container_namespace_pins_cgroup_quarantines_retained':True,'production_changes':False}))
'''.replace("EXPECTED", repr(expected))
base = pathlib.Path("target/lab-state")
ssh = ["ssh", "-i", str(base / "id_ed25519"), "-o", "IdentitiesOnly=yes",
       "-o", "UserKnownHostsFile=" + str(base / "known_hosts"), "-o",
       "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=5", "-p22032",
       "vprouterlab@127.0.0.1", "sudo python3 -"]
result = subprocess.run(ssh, input=script, capture_output=True, text=True, timeout=25)
print(result.stdout, end="")
print(result.stderr, file=sys.stderr, end="")
sys.exit(result.returncode)
