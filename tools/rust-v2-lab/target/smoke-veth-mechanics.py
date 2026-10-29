"""Closed new-role filter report; local schemas/cached output, no native calls."""
import copy,datetime,hashlib,importlib.util,io,json,pathlib,tarfile,tempfile
if not __debug__:raise RuntimeError('optimized_python_refused')
p=pathlib.Path(__file__).with_name('platform-lab')/'selftest_mechanics.py';spec=importlib.util.spec_from_file_location('mechanics',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
base=dict(schema=1,original_pid=1234,original_start=300,actual_wait_status=0,requested_at=10.,deadline=12.,verified_at=10.2,eof_verified=True,route_io_reached_kernel=True,generic_transactions_denied=True,generic_custody_verified=True,high_word_and_direction_denied=True,scm_rights_denied=True,no_netlink_transactions=True,actual_pair_creation=False,actual_host_mutation=False)
rows=[];m.validate_veth_filter(base);rows.append(dict(case='valid_filter_only_report',result='PASS'))
mutations=[('schema_bool',lambda v:v.update(schema=True)),('extra',lambda v:v.update(extra=1)),('pid_bool',lambda v:v.update(original_pid=True)),('pid_overflow',lambda v:v.update(original_pid=2**32)),('start_bool',lambda v:v.update(original_start=True)),('status_bool',lambda v:v.update(actual_wait_status=False)),('status_nonzero',lambda v:v.update(actual_wait_status=9)),('clock_bool',lambda v:v.update(requested_at=True,deadline=3.)),('nan',lambda v:v.update(verified_at=float('nan'))),('huge_integer_time',lambda v:v.update(verified_at=10**10000)),('renewed_end',lambda v:v.update(deadline=14.)),('late',lambda v:v.update(verified_at=12.))]
for key in('eof_verified','route_io_reached_kernel','generic_transactions_denied','generic_custody_verified','high_word_and_direction_denied','scm_rights_denied','no_netlink_transactions'):
 mutations.append((key+'_false',lambda v,key=key:v.__setitem__(key,False)));mutations.append((key+'_integer',lambda v,key=key:v.__setitem__(key,1)))
for key in('actual_pair_creation','actual_host_mutation'):mutations.append((key,lambda v,key=key:v.__setitem__(key,True)))
for name,change in mutations:
 v=copy.deepcopy(base);change(v)
 try:m.validate_veth_filter(v)
 except(AssertionError,TypeError,KeyError,ValueError):rows.append(dict(case=name,result='PASS_REFUSED'))
 else:raise AssertionError('invalid_filter_report_accepted:'+name)
for name,value in [('list',[]),('scalar',1),('null',None),('string','bad')]:
 try:m.validate_veth_filter(value)
 except AssertionError:rows.append(dict(case='non_object_'+name,result='PASS_REFUSED'))
 else:raise AssertionError('non_object_filter_accepted:'+name)
with tempfile.TemporaryDirectory(prefix='veth-schema-')as temp:
 def archive(name,present):
  path=pathlib.Path(temp)/name
  with tarfile.open(path,'x')as tar:
   data=m.VETH.encode()if present else b'';info=tarfile.TarInfo('crates/vprouter-launch/src/kernel/wireguard_role.rs');info.size=len(data);tar.addfile(info,io.BytesIO(data))
  return path
 new=archive('new.tar',True);old=archive('old.tar',False);line=m.VETH+' '+json.dumps(base)
 proof=m.validate_mechanics(new,line);assert proof['verified_records']==1 and proof['veth_filter']==base;rows.append(dict(case='frozen_source_marker_gate',result='PASS'))
 for name,source,output in[('missing',new,''),('duplicate',new,line+'\n'+line),('unexpected_old',old,line),('duplicate_json_key',new,m.VETH+' '+json.dumps(base).replace('"schema": 1','"schema": 1,"schema": 1'))]:
  try:m.validate_mechanics(source,output)
  except(AssertionError,TypeError,KeyError,ValueError):rows.append(dict(case=name,result='PASS_REFUSED'))
  else:raise AssertionError('invalid_marker_accepted:'+name)
log=pathlib.Path('target/veth-role-native.log');cached=[json.loads(x.split(' ',1)[1])for x in log.read_text().splitlines()if x.startswith(m.VETH+' ')];assert len(cached)==1;m.validate_veth_filter(cached[0]);rows.append(dict(case='cached_unfrozen_source_debug_report_schema',result='PASS_CACHED_SCHEMA_ONLY'))
files=[pathlib.Path(__file__),p,log]
out=pathlib.Path('target/lab-state')/('veth-mechanics-smokes-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.json')
with out.open('x')as f:json.dump(dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),checks=rows,files=[dict(path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest())for p in files],native_acceptance=False,scope='LOCAL synthetic filter-schema/source-marker mutations plus cached UNFROZEN debug report validation; no new native execution, pair creation/HOST mutation, canonical publication, permit or release acceptance'),f,indent=2)
print(json.dumps(dict(record=str(out),checks=len(rows),native_acceptance=False)))
