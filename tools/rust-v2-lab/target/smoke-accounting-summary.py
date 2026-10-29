import copy,hashlib,importlib.util,json,pathlib,subprocess,tempfile,datetime
if not __debug__:raise RuntimeError('optimized_python_refused')
script=pathlib.Path('target/summarize-readonly-accounting.py');spec=importlib.util.spec_from_file_location('accounting_summary',script);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
root=pathlib.Path('target/lab-state/accounting-analysis-preparation-20261027')
p=module.summarize(root/'positive.stdout');assert not p['measured_sample_start_span_ten_minutes'] and p['pss_valid_for_entire_run'] and p['total_cohort_mean_pss_kib']>0 and p['throughput_and_p95']=='NOT_MEASURED'
d=module.summarize(root/'duplicate-native.stdout');assert not d['pss_valid_for_entire_run'] and d['total_cohort_mean_pss_kib'] is d['total_cohort_max_pss_kib'] is None
assert all(v['mean_pss_kib'] is None and v['max_pss_kib'] is None and v['cpu_delta_usec']['usage_usec']>=0 for v in d['cohorts'].values())
rows=[json.loads(line)for line in (root/'positive.stdout').read_text().splitlines()]
def duplicate_empty_cohorts(r):
 for v in r:
  if v['kind']=='sample':
   original=v['groups'][0];original.update(processes=[],pss_kib=0,pss_by_label_kib={})
   v.update(total_cohort_pss_kib=0,duplicate_process_identities=[],pss_sum_valid=True)
   v['groups'].append(dict(original,role='duplicate'))
cases=['native-short-positive','native-cross-cohort-duplicate-suppresses-whole-pss']
mutations={
 'missing-end':lambda r:r.pop(),
 'missing-final-completion':lambda r:r.pop(-2),
 'false-duration':lambda r:r[-1].update(ten_minute_duration_met=True),
 'negative-cpu-counter':lambda r:next(v for v in reversed(r)if v['kind']=='sample')['groups'][0]['cpu'].update(usage_usec=-1),
 'nonnegative-cpu-decrease':lambda r:(next(v for v in r if v['kind']=='sample')['groups'][0]['cpu'].update(usage_usec=2),next(v for v in reversed(r)if v['kind']=='sample')['groups'][0]['cpu'].update(usage_usec=1)),
 'flush-overlap':lambda r:next(v for v in r if v['kind']=='sample_complete').update(sample_flush_finished_boottime_ns=10**30),
 'duplicate-empty-cohort-native-identity':duplicate_empty_cohorts,
 'host-counter-reset':lambda r:(next(v for v in r if v['kind']=='sample')['whole_host']['cpu_ticks'].update(user=2),next(v for v in reversed(r)if v['kind']=='sample')['whole_host']['cpu_ticks'].update(user=1)),
 'changed-native-identity':lambda r:next(v for v in reversed(r)if v['kind']=='sample')['groups'][0]['native_identity'].__setitem__(1,999999),
 'false-pss-total':lambda r:next(v for v in r if v['kind']=='sample').update(total_cohort_pss_kib=0),
 'changed-clock-origin':lambda r:next(v for v in r if v['kind']=='sample_complete').update(read_started_boottime_ns=1),
 'trailing-record':lambda r:r.append({'kind':'sample'}),
 'native-incomplete':None,
}
with tempfile.TemporaryDirectory(prefix='accounting-summary-local-')as temporary:
 path=pathlib.Path(temporary)/'input.jsonl'
 for name,change in mutations.items():
  if change:
   changed=copy.deepcopy(rows);change(changed);path.write_text(''.join(json.dumps(v)+'\n'for v in changed))
  else:path.write_bytes((root/'replacement.stdout').read_bytes())
  try:module.summarize(path)
  except(ValueError,KeyError,TypeError):cases.append(name)
  else:raise AssertionError('mutation accepted '+name)
 changed=copy.deepcopy(rows);last=next(v for v in reversed(changed)if v['kind']=='sample')['groups'][0]
 assert len(last['processes'])==1
 last['processes'][0]['label']='rust_control';last['pss_by_label_kib']={'rust_control':last['pss_kib']}
 path.write_text(''.join(json.dumps(v)+'\n'for v in changed));final=module.summarize(path)['cohorts'][last['role']]
 assert final['mean_pss_by_label_kib']['rust_control']==0 and final['max_pss_by_label_kib']['rust_control']>0
 cases.append('final-only-label-included-with-zero-covered-time')
 r=subprocess.run(['python3','-O',str(script)],capture_output=True,text=True);assert r.returncode!=0 and 'optimized_python_refused'in r.stderr;cases.append('optimized-python-refused')
output=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),summarizer_sha256=hashlib.sha256(script.read_bytes()).hexdigest(),cases=cases,case_count=len(cases),native_inputs='Read-only copies of existing one-second instrumentation smoke; no new workload run.',benchmark_acceptance='NOT_RUN',performance_acceptance='NOT_EVALUATED')
with (root/'summary-smoke-v4.json').open('x')as f:json.dump(output,f,indent=2);f.write('\n')
snapshot=root/('summarizer-'+output['summarizer_sha256'][:12]+'.py')
if snapshot.exists():assert snapshot.read_bytes()==script.read_bytes()
else:
 with snapshot.open('xb')as f:f.write(script.read_bytes())
print(json.dumps(output))
