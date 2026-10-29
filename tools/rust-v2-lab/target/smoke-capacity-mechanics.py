"""Local capacity-report mutations and frozen-marker gating; no native calls."""
import copy,datetime,hashlib,importlib.util,io,json,pathlib,tarfile,tempfile
if not __debug__:raise RuntimeError('optimized_python_refused')
p=pathlib.Path(__file__).with_name('platform-lab')/'selftest_mechanics.py';spec=importlib.util.spec_from_file_location('mechanics',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
base=dict(schema=1,requested_at=10.,deadline=12.,verified_at=10.5,original_pid=200,original_start=300,actual_wait_status=0,eof=True,failed_original_pid=201,failed_original_start=None,failed_actual_wait_status=31232,failed_exit_code=122,failed_charges_unchanged=[1,1],eligible_original_pid=None,eligible_original_start=None,eligible_foreign_refused=False,parent_still_eligible=False,parent_counts_before=[2,0],parent_counts_after=[2,0],canonical_operation=False,successful_capacity_transfer_proven=False)
rows=[];m.validate_capacity_refusals(base);rows.append(dict(case='valid_failed_native_report',result='PASS'))
v=copy.deepcopy(base);v['failed_original_start']=301;m.validate_capacity_refusals(v);rows.append(dict(case='failed_start_known',result='PASS'))
mutations=[('schema_bool',lambda v:v.update(schema=True)),('extra',lambda v:v.update(extra=1)),('clock_bool',lambda v:v.update(requested_at=True,deadline=3.)),('new_deadline',lambda v:v.update(deadline=14.)),('nan',lambda v:v.update(verified_at=float('nan'))),('late',lambda v:v.update(verified_at=12.)),('pid_bool',lambda v:v.update(original_pid=True)),('pid_overflow',lambda v:v.update(original_pid=2**32)),('start_bool',lambda v:v.update(original_start=True)),('status_bool',lambda v:v.update(actual_wait_status=False)),('status_nonzero',lambda v:v.update(actual_wait_status=9)),('eof_integer',lambda v:v.update(eof=1)),('failed_pid_alias',lambda v:v.update(failed_original_pid=200)),('failed_start_bool',lambda v:v.update(failed_original_start=True)),('raw_status_is_exit_code',lambda v:v.update(failed_actual_wait_status=122)),('exit_code_is_raw_status',lambda v:v.update(failed_exit_code=31232)),('failed_count_bool',lambda v:v.update(failed_charges_unchanged=[True,True])),('failed_count_changed',lambda v:v.update(failed_charges_unchanged=[1,0])),('parent_count_float',lambda v:v.update(parent_counts_before=[2.,0],parent_counts_after=[2.,0])),('parent_count_changed',lambda v:v.update(parent_counts_after=[1,0])),('count_above_limit',lambda v:v.update(parent_counts_before=[65,0],parent_counts_after=[65,0])),('false_foreign_claim',lambda v:v.update(eligible_foreign_refused=True)),('false_parent_claim',lambda v:v.update(parent_still_eligible=True)),('canonical_claim',lambda v:v.update(canonical_operation=True)),('transfer_claim',lambda v:v.update(successful_capacity_transfer_proven=True))]
for name,change in mutations:
 v=copy.deepcopy(base);change(v)
 try:m.validate_capacity_refusals(v)
 except(AssertionError,TypeError,KeyError,ValueError):rows.append(dict(case=name,result='PASS_REFUSED'))
 else:raise AssertionError('invalid_capacity_accepted:'+name)
v=copy.deepcopy(base)
for key in('failed_original_pid','failed_original_start','failed_actual_wait_status','failed_exit_code','failed_charges_unchanged'):v[key]=None
v.update(eligible_original_pid=400,eligible_original_start=500,eligible_foreign_refused=True,parent_still_eligible=True,parent_counts_before=[15,11],parent_counts_after=[15,11]);m.validate_capacity_refusals(v,eligible=(400,500),counts=[15,11],earliest=10.,after=11.);rows.append(dict(case='eligible_foreign_scoped',result='PASS'))
for name,kwargs in [('wrong_eligible',dict(eligible=(401,500))),('wrong_counts',dict(eligible=(400,500),counts=[14,11])),('earlier_than_prefix',dict(eligible=(400,500),earliest=10.1)),('after_observer',dict(eligible=(400,500),after=10.4))]:
 try:m.validate_capacity_refusals(v,**kwargs)
 except(AssertionError,TypeError,KeyError,ValueError):rows.append(dict(case=name,result='PASS_REFUSED'))
 else:raise AssertionError('invalid_foreign_bound_accepted:'+name)
with tempfile.TemporaryDirectory(prefix='capacity-marker-schema-')as temp:
 def archive(name,present):
  path=pathlib.Path(temp)/name
  with tarfile.open(path,'x')as tar:
   for source,data in [('crates/vprouter-launch/src/kernel/wireguard_role.rs',b''),('crates/vprouter-launch/src/kernel/capacity_lab.rs',m.CAPACITY.encode()if present else b'')]:
    info=tarfile.TarInfo(source);info.size=len(data);tar.addfile(info,io.BytesIO(data))
  return path
 new=archive('new.tar',True);old=archive('old.tar',False);line=m.CAPACITY+' '+json.dumps(base)
 proof=m.validate_mechanics(new,line);assert proof['verified_records']==1 and proof['capacity_refusals']==base;rows.append(dict(case='source_gated_capacity_marker',result='PASS'))
 for name,source,stdout in [('missing_marker',new,''),('duplicate_marker',new,line+'\n'+line),('unexpected_old_marker',old,line),('duplicate_json_key',new,m.CAPACITY+' '+json.dumps(base).replace('"schema": 1','"schema": 1,"schema": 1')),('malformed_json',new,m.CAPACITY+' {bad}')]:
  try:m.validate_mechanics(source,stdout)
  except(AssertionError,TypeError,KeyError,ValueError):rows.append(dict(case=name,result='PASS_REFUSED'))
  else:raise AssertionError('invalid_marker_accepted:'+name)
files=[pathlib.Path(__file__),p]
out=pathlib.Path('target/lab-state')/('capacity-mechanics-smokes-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.json')
with out.open('x')as f:json.dump(dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),checks=rows,files=[dict(path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest())for p in files],native_acceptance=False,scope='LOCAL_SYNTHETIC_CLOSED_MARKER_SCHEMA_ONLY; raw failed wait31232 is exit122; actual foreign/helper/native/transfer proof remains separate'),f,indent=2)
print(json.dumps(dict(record=str(out),checks=len(rows),native_acceptance=False)))
