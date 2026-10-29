"""Parser and cached-output checks only; never launches a payload or VM."""
import copy,datetime,hashlib,importlib.util,io,json,pathlib,tarfile,tempfile
if not __debug__:raise RuntimeError('optimized_python_refused')
helper=pathlib.Path(__file__).with_name('platform-lab')/'selftest_mechanics.py'
spec=importlib.util.spec_from_file_location('selftest_mechanics',helper);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
keys=list(module.EXPECTED)
temporary=tempfile.TemporaryDirectory(prefix='vprouter-mechanics-schema-');serial=0
def source(selected):
 global serial
 serial+=1;path=pathlib.Path(temporary.name)/(str(serial)+'.tar')
 with tarfile.open(path,mode='x')as archive:
  for filename,values in [('wireguard_role.rs',[k for k in selected if k not in('LAB_FIXED_PRODUCER_FILTER',module.PROGRESS)]),('producer_creation.rs',[k for k in selected if k in('LAB_FIXED_PRODUCER_FILTER',module.PROGRESS)])]:
   if filename=='producer_creation.rs'and not values:continue
   data='\n'.join(values).encode();info=tarfile.TarInfo('crates/vprouter-launch/src/kernel/'+filename);info.size=len(data);archive.addfile(info,io.BytesIO(data))
 return path
def stdout(values):return '\n'.join(key+' '+json.dumps(value)for key,value in values)
def validate(selected,lines):return module.validate_mechanics(source(selected),stdout(lines))
rows=[]
for count in range(len(keys)+1):
 proof=validate(keys[:count],[(key,module.EXPECTED[key])for key in keys[:count]])
 assert proof['verified_records']==count and proof['frozen_source_records']==keys[:count]
 rows.append(dict(case='synthetic_selected_'+str(count),result='PASS'))
for key in keys:
 others=[(k,copy.deepcopy(v))for k,v in module.EXPECTED.items()if k!=key]
 fields=list(module.EXPECTED[key]);first=fields[0];false_field=next(k for k,v in module.EXPECTED[key].items()if v is False)
 cases=[('missing',others),('duplicate',others+[(key,module.EXPECTED[key])]*2)]
 for name,change in [
  ('changed_true',lambda v:v.update(**{first:False})),
  ('changed_false',lambda v:v.update(**{false_field:True})),
  ('numeric_bool',lambda v:v.update(**{first:1})),
  ('extra_field',lambda v:v.update(extra=False)),
  ('missing_field',lambda v:v.pop(first)),
 ]:
  value=copy.deepcopy(module.EXPECTED[key]);change(value);cases.append((name,others+[(key,value)]))
 for name,lines in cases:
  try:validate(keys,lines)
  except(AssertionError,ValueError,TypeError,KeyError):rows.append(dict(case=key+'_'+name,result='PASS_REFUSED'))
  else:raise AssertionError('invalid_mechanical_record_accepted:'+key+'_'+name)
for name,text in [('malformed',keys[0]+' not-json'),('duplicate_json_key',keys[0]+' {"distinct_gate_result":true,"distinct_gate_result":false}'),('json_list',keys[0]+' '+json.dumps(list(module.EXPECTED[keys[0]]))),('json_scalar',keys[0]+' true'),('json_string',keys[0]+' "wrong"')]:
 try:module.validate_mechanics(source([keys[0]]),text)
 except(AssertionError,ValueError,TypeError,KeyError):rows.append(dict(case=name,result='PASS_REFUSED'))
 else:raise AssertionError('invalid_mechanical_json_accepted:'+name)
try:validate([],[(keys[0],module.EXPECTED[keys[0]])])
except AssertionError:rows.append(dict(case='unexpected_record_without_source_feature',result='PASS_REFUSED'))
else:raise AssertionError('unexpected_source_feature_accepted')
progress=dict(requested_at=20.,deadline=22.,sequence=7,pending_parent_polls=2,independent_pid=1234,independent_start=500,actual_wait_status=0,independent_completed_at=20.5,route_completed_at=20.6,reply_messages=1,original_kernel_dump_completed=True,unrelated_owner_rpc_claimed=False)
proof=validate([module.PROGRESS],[(module.PROGRESS,progress)]);assert proof['pending_route_progress']==progress
rows.append(dict(case='pending_route_valid',result='PASS'))
for name,change in [('new_end',lambda v:v.update(deadline=24.)),('late_route',lambda v:v.update(route_completed_at=22.)),('out_of_order',lambda v:v.update(independent_completed_at=20.7)),('missing_poll',lambda v:v.update(pending_parent_polls=1)),('poll_bool',lambda v:v.update(pending_parent_polls=True)),('poll_overflow',lambda v:v.update(pending_parent_polls=2**32)),('pid_overflow',lambda v:v.update(independent_pid=2**32)),('status',lambda v:v.update(actual_wait_status=9)),('status_bool',lambda v:v.update(actual_wait_status=False)),('wrong_sequence',lambda v:v.update(sequence=2**32)),('no_messages',lambda v:v.update(reply_messages=0)),('fake_rpc',lambda v:v.update(unrelated_owner_rpc_claimed=True)),('incomplete_dump',lambda v:v.update(original_kernel_dump_completed=False)),('nan_time',lambda v:v.update(route_completed_at=float('nan'))),('extra',lambda v:v.update(extra=1))]:
 value=copy.deepcopy(progress);change(value)
 try:validate([module.PROGRESS],[(module.PROGRESS,value)])
 except(AssertionError,ValueError,TypeError,KeyError):rows.append(dict(case='pending_route_'+name,result='PASS_REFUSED'))
 else:raise AssertionError('invalid_pending_route_accepted:'+name)
candidate=pathlib.Path('target/continuation-20261027T222552Z/candidate.json');c=json.loads(candidate.read_text());cached=[]
paths=[pathlib.Path('target/process-inspection-root-verification-20261027')/('frozen-preflight-'+c['source_commit']+'.json'),candidate.parent/'native-preflight-debian-arm64/record.json',candidate.parent/'native-preflight-void-x86_64/record.json']
assert hashlib.sha256(pathlib.Path(c['source']).read_bytes()).hexdigest()==c['source_sha256']
for p in paths:
 data=json.loads(p.read_text());result=data.get('result',data)
 assert result['exit_code']==0
 proof=module.validate_mechanics(c['source'],result['stdout']);assert proof['verified_records']==2
 cached.append(dict(path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest(),verified_records=2))
dependencies=[pathlib.Path(__file__),helper,pathlib.Path('target/verify-frozen-inspection-preflight.py'),pathlib.Path('target/platform-lab/run-native-inspection-preflight.py')]
record=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),synthetic_checks=rows,cached_previous_outputs=cached,files=[dict(path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest())for p in dependencies],scope='LOCAL_PARSER_AND_CACHED_OUTPUT_ONLY; no executable, fresh native syscall, namespace, transaction, quarantine or release acceptance')
destination=pathlib.Path('target/lab-state')/('selftest-mechanics-smokes-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.json')
with destination.open('x')as f:json.dump(record,f,indent=2);f.write('\n')
print(json.dumps(dict(record=str(destination),synthetic_checks=len(rows),cached_outputs=len(cached),native_execution=False)))
temporary.cleanup()
