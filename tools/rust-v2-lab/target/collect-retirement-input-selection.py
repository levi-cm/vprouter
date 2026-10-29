"""Verify synthetic fixture input selection. This grants no runtime authority."""
import datetime,hashlib,ipaddress,json,pathlib,re,sys,tarfile
p=pathlib.Path(sys.argv[1]);candidate=json.loads(p.read_text());directory=p.parent/sys.argv[2]
binding=json.loads((directory/'directory-binding.json').read_text());controller=json.loads((directory/'controller.json').read_text());path=pathlib.Path(controller['record']);raw=path.read_bytes();record=json.loads(raw)
assert binding['record']==str(path) and record['source_binding']==candidate['binding'] and binding['source_commit']==candidate['source_commit'] and binding['artifact_sha256']==record['artifact_sha256']
assert record['component_test_mode'].startswith('owner_retirement') and record['real_client_acceptance']=='NOT_RUN' and record['production_changes'] is False
source=pathlib.Path(candidate['source']);assert hashlib.sha256(source.read_bytes()).hexdigest()==candidate['source_sha256']
with tarfile.open(source) as archive:core=archive.extractfile('crates/vprouter-core/src/allocation.rs').read()
parts=[re.search(rb'fn allocation\(.*?\n}\n',core,re.S).group(),re.search(rb'pub\(crate\) fn stable_hash\(.*?\n}\n',core,re.S).group()];algorithm=hashlib.sha256(b'\0'.join(parts)).hexdigest()
selections=[];probes=[]
for index,line in enumerate(record['stdout'].splitlines()):
 try:value=json.loads(line)
 except ValueError:continue
 if 'synthetic_nonce_selection'in value:selections.append((index,value['synthetic_nonce_selection']))
 if 'owner_probe'in value:probes.append((index,value['owner_probe']))
assert len(selections)==len(probes)==1 and selections[0][0]<probes[0][0]
x=selections[0][1];assert x['schema']==2 and x['allocation_algorithm_sha256']==algorithm
assert x['before_native_network_mutation'] is x['exclusive_kernel_race_checks_unchanged'] is True
assert type(x['attempts'])is int and 1<=x['attempts']<=16 and len(x['rejected'])==x['attempts']-1
nonce=x['nonce'];assert re.fullmatch('[a-f0-9]{64}',nonce) and nonce==probes[0][1]['nonce']
assert len({item['nonce'] for item in x['rejected']}|{nonce})==x['attempts']
assert all(item['conflicts'] for item in x['rejected'])
expected=[]
for prefix in ('a','b'):
 exit_id=prefix+nonce[:12];h=0xcbf29ce484222325
 for byte in ('launchlab-'+nonce[:12]).encode()+b'\0'+exit_id.encode():h=((h^byte)*0x100000001b3)&0xffffffffffffffff
 short=format(h&0xffffffffffff,'012x');slot=h&65535
 expected.append(dict(exit_id=exit_id,host_interface='vh'+short,data_interface='vd'+short,wireguard_interface='wg'+short,transport_subnet=f'10.{200+(slot>>14)}.{(slot>>6)&255}.{(slot&63)*4}/30'))
assert expected==x['intended']
baseline=x['baseline'];assert set(baseline)=={'routes','addresses','links'}
assert hashlib.sha256(json.dumps(baseline,sort_keys=True,separators=(',',':')).encode()).hexdigest()==x['baseline_sha256']
networks=[]
for r in baseline['routes']:
 if r.get('dst','default')!='default':
  n=ipaddress.IPv4Network(r['dst'],strict=False)
  if n.prefixlen:networks.append(n)
for interface in baseline['addresses']:
 for address in interface.get('addr_info',[]):
  if address.get('family')=='inet':
   n=ipaddress.IPv4Network(str(address['local'])+'/'+str(address['prefixlen']),strict=False)
   if n.prefixlen:networks.append(n)
endpoint='185.66.'+str(int(nonce[:2],16))+'.'+str(int(nonce[2:4],16))
planned=[ipaddress.IPv4Network(e['transport_subnet']) for e in expected]+[ipaddress.IPv4Network(endpoint+'/31',strict=False)]
assert not planned[0].overlaps(planned[1]) and not any(n.overlaps(other) for n in planned for other in networks)
names={v for e in expected for key,v in e.items() if key.endswith('_interface')}|{'vjh'+nonce[:10],'vjp'+nonce[:10]}
assert not names&{link['ifname'] for link in baseline['links']}
run=re.fullmatch('actual-program-run-([0-9]+).json',path.name)[1]
out=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),record=str(path),record_sha256=hashlib.sha256(raw).hexdigest(),source_binding=record['source_binding'],artifact_sha256=record['artifact_sha256'],platform=binding['platform'],selection=x,collector_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),native_run_exit_code=record['exit_code'],preflight_only=True,resource_reservation=False,runtime_authority=False,real_client_acceptance='NOT_RUN',limit='Bounded synthetic lab input choice against an observed baseline only. Baseline can become stale; actual exclusive kernel race checks remain mandatory. No cleanup, reuse, runtime allocation or acceptance authority is created.')
dest=pathlib.Path('target/lab-state')/f'retirement-input-selection-run-{run}.json'
with dest.open('x') as stream:json.dump(out,stream,indent=2);stream.write('\n')
print(json.dumps(dict(record=str(dest),attempts=x['attempts'],both_allocations_conflict_free_at_preflight=True,runtime_authority=False)))
