import datetime,hashlib,json,pathlib,re,runpy,tarfile
candidate=json.loads(pathlib.Path('target/continuation-20261027T144457Z/candidate.json').read_text())
with tarfile.open(candidate['source']) as archive:core=archive.extractfile('crates/vprouter-core/src/allocation.rs').read()
parts=[re.search(rb'fn allocation\(.*?\n}\n',core,re.S).group(),re.search(rb'pub\(crate\) fn stable_hash\(.*?\n}\n',core,re.S).group()]
algorithm=hashlib.sha256(b'\0'.join(parts)).hexdigest()
now=datetime.datetime.now(datetime.timezone.utc);backup=pathlib.Path('target')/('retirement-nonce-controller-backup-'+now.strftime('%Y%m%dT%H%M%SZ'));backup.mkdir()
old=''' # Choose a fresh fixture endpoint without removing retained earlier WANs.
 current_routes=json.loads(run(['ip','-j','-4','route','show','table','all']))
 current_addresses=json.loads(run(['ip','-j','address','show']))
 for attempt in range(16):
  nonce=__import__('secrets').token_hex(32)
  endpoint='185.66.'+str(int(nonce[:2],16))+'.'+str(int(nonce[2:4],16))
  host_endpoint='185.66.'+str(int(nonce[:2],16))+'.'+str(int(nonce[2:4],16)^1)
  selected={endpoint,endpoint+'/32',host_endpoint,host_endpoint+'/32'}
  if not any(r.get('dst') in selected for r in current_routes) and not any(a.get('local') in selected for i in current_addresses for a in i.get('addr_info',[])):break
 else:raise AssertionError('no_free_nonce_synthetic_endpoint')
'''
new=''' # Root lab input selection only; no runtime allocation authority is granted.
 import ipaddress
 current_routes=json.loads(run(['ip','-j','-4','route','show','table','all']))
 current_addresses=json.loads(run(['ip','-j','address','show']))
 current_links=json.loads(run(['ip','-j','-d','link','show']))
 baseline={'routes':current_routes,'addresses':current_addresses,'links':current_links}
 networks=[]
 for route in current_routes:
  destination=route.get('dst','default')
  if destination!='default':networks.append(ipaddress.IPv4Network(destination,strict=False))
 for interface in current_addresses:
  for address in interface.get('addr_info',[]):
   if address.get('family')=='inet':networks.append(ipaddress.IPv4Network(str(address['local'])+'/'+str(address['prefixlen']),strict=False))
 names={link['ifname'] for link in current_links}
 rejected=[]
 for attempt in range(16):
  nonce=__import__('secrets').token_hex(32)
  deployment='launchlab-'+nonce[:12]
  intended=[]
  for prefix in ('a','b'):
   exit_id=prefix+nonce[:12];value=0xcbf29ce484222325
   for byte in deployment.encode()+b'\\0'+exit_id.encode():value=((value^byte)*0x100000001b3)&0xffffffffffffffff
   short=format(value&0xffffffffffff,'012x');slot=value&65535
   intended.append({'exit_id':exit_id,'host_interface':'vh'+short,'data_interface':'vd'+short,'wireguard_interface':'wg'+short,'transport_subnet':'10.'+str(200+(slot>>14))+'.'+str((slot>>6)&255)+'.'+str((slot&63)*4)+'/30'})
  endpoint='185.66.'+str(int(nonce[:2],16))+'.'+str(int(nonce[2:4],16))
  host_endpoint='185.66.'+str(int(nonce[:2],16))+'.'+str(int(nonce[2:4],16)^1)
  planned=[ipaddress.IPv4Network(e['transport_subnet']) for e in intended]+[ipaddress.IPv4Network(endpoint+'/31',strict=False)]
  conflicts=[]
  for network in planned:
   conflicts.extend({'planned':str(network),'existing':str(other)} for other in networks if network.overlaps(other))
  if planned[0].overlaps(planned[1]):conflicts.append({'cohort_subnet_collision':True})
  planned_names={value for e in intended for key,value in e.items() if key.endswith('_interface')}|{'vjh'+nonce[:10],'vjp'+nonce[:10]}
  conflicts.extend({'interface_name_collision':name} for name in sorted(planned_names&names))
  if not conflicts:break
  rejected.append({'nonce':nonce,'intended':intended,'conflicts':conflicts})
 else:raise AssertionError('no_free_nonce_synthetic_allocations')
 print(json.dumps({'synthetic_nonce_selection':{'schema':2,'allocation_algorithm_sha256':'ALGORITHM_HASH','baseline_sha256':hashlib.sha256(json.dumps(baseline,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'baseline':baseline,'attempts':attempt+1,'rejected':rejected,'nonce':nonce,'intended':intended,'before_native_network_mutation':True,'exclusive_kernel_race_checks_unchanged':True}}),flush=True)
'''.replace('ALGORITHM_HASH',algorithm)
rows=[]
for path in sorted(pathlib.Path('target/platform-lab').glob('run-owner-retirement*.py')):
 s=path.read_text();assert s.count(old)==1,path
 saved=backup/path.name;saved.write_text(s)
 # Verify the exact public allocation functions from this frozen source before SSH.
 marker="        manifests = {"
 addition="""        allocation_source = archive.extractfile('crates/vprouter-core/src/allocation.rs').read()
        allocation_parts = [re.search(rb'fn allocation\\(.*?\\n}\\n', allocation_source, re.S).group(), re.search(rb'pub\\(crate\\) fn stable_hash\\(.*?\\n}\\n', allocation_source, re.S).group()]
        assert sha(b'\\0'.join(allocation_parts)) == 'ALGORITHM_HASH', 'frozen_allocation_algorithm_changed'
""".replace('ALGORITHM_HASH',algorithm)
 assert s.count(marker)==1;s=s.replace(marker,addition+marker).replace(old,new);compile(s,str(path),'exec');path.write_text(s)
 module=runpy.run_path(str(path),run_name='fixed_preparation');compile(module['GUEST'],str(path)+':GUEST','exec')
 rows.append(dict(path=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),prior_path=str(saved),prior_sha256=hashlib.sha256(saved.read_bytes()).hexdigest()))
assert len(rows)==20
out=dict(observed_at_utc=now.isoformat(),source_commit=candidate['source_commit'],allocation_algorithm_sha256=algorithm,controllers=rows,derivation_checked_against_failed_219_both_exits=True,selection_bound=16,syntax='PASS',native_case_status='NOT_RUN',scope='Root synthetic two-exit retirement input chooser only; full fresh public route/address/link conflict checks before fixture networking; no runtime authority, reservation, EXCL relaxation, old resource cleanup or failed-run relabel.')
p=pathlib.Path('target/lab-state/retirement-bounded-nonce-selection-preparation-20261027.json')
with p.open('x') as f:json.dump(out,f,indent=2);f.write('\n')
print(json.dumps(dict(record=str(p),controllers=len(rows),backup=str(backup),algorithm_sha256=algorithm)))
