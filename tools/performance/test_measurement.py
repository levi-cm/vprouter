"""Offline regression checks. All fixtures are synthetic and never acceptance."""
import copy
import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).parent
spec = importlib.util.spec_from_file_location('measurement', ROOT / 'measurement.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
H = 'a' * 64


def binding(implementation='rust'):
    return dict(implementation=implementation, source_sha256=H, artifact_sha256=H,
                config_sha256=H, workload_sha256=H, identity_set_sha256=H,
                peers_sha256=H, network_conditions_sha256=H, tailscale_version='1.90.1',
                tailscale_artifact_sha256=H, host_id_sha256=H, run_id='run-1', repetition=1,
                exits=1, exit_ids=['exit1'], exit_modes=['mullvad'], scenario='steady', monitoring=dict(provider_seconds=5,
                retry_seconds=1, handshake_seconds=180, health_seconds=45, watchdog_seconds=90))


def manifest():
    groups = [dict(role=role, relative='lab/' + role, native_identity=[1, i+2], accounting_class=category)
              for i, (role, category) in enumerate([('control','control'),('runtime','runtime'),('tailscale','tailscale')])]
    return dict(schema=2, boot_id='boot', groups=groups,
                executable_labels={H:'worker_control'}, binding=binding(),
                evidence_origin='synthetic', accounting=dict(method='disjoint_cgroup_v2_memory_current',
                scope_sha256=H, review_sha256=H, complete=True, outside_domain_overhead='none_on_isolated_host',
                required_components={'host_guard_publisher':['control'],'worker_control':['control'],
                'init_shim':['control'],'docker_runtime':['runtime'],'tailscale':['tailscale']},
                kernel_buffers='included_in_memory_current_and_memory_stat', isolated_host=True),
                stable_processes=[dict(pid=123,start=100,executable_sha256=H,group='control')])


class Contract(unittest.TestCase):
    def test_nested_cgroups_cannot_double_count(self):
        value=manifest(); value['groups'][1]['relative']='lab/control/child'
        with self.assertRaisesRegex(ValueError, 'overlap'):
            m.validate_manifest(value)

    def test_missing_kernel_coverage_is_insufficient(self):
        value=manifest(); del value['accounting']['kernel_buffers']
        with self.assertRaises(ValueError): m.validate_manifest(value)

    def test_monitoring_contract_cannot_be_weakened(self):
        value=manifest(); value['binding']['monitoring']['provider_seconds']=10
        with self.assertRaises(ValueError): m.validate_manifest(value)

    def test_synthetic_record_cannot_satisfy_acceptance(self):
        value=dict(origin='synthetic', problems=[], binding=binding(), elapsed_ns=600000000000)
        self.assertIn('synthetic', ' '.join(m.run_problems(value)))

    def test_absent_runs_stay_not_run(self):
        report=m.compare_runs([], [])
        self.assertEqual(report['status'],'NOT_RUN')
        self.assertEqual(len(report['scenarios']),6)

    def test_real_process_stat_handles_parentheses_and_zombie(self):
        line='123 (odd ) process) Z ' + ' '.join(str(i) for i in range(1,50))
        self.assertEqual(m.parse_process_stat(line),(19,23,'Z'))

    def test_short_soak_is_insufficient(self):
        value=dict(schema=1, evidence_origin='actual_runtime', segments=[])
        self.assertEqual(m.validate_soak(value)['status'],'INSUFFICIENT')

    def test_nonfinite_or_boolean_metrics_are_rejected(self):
        for value in (float('nan'),float('inf'),True,-1):
            with self.assertRaises(ValueError): m.number(value)

    def test_duplicate_json_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path=pathlib.Path(directory)/'input.json';path.write_text('{"schema":1,"schema":2}')
            with self.assertRaises(ValueError):m.load_json(path)

    def test_accounting_incompleteness_is_not_zero(self):
        value=manifest(); value['accounting']['outside_domain_overhead']='unavailable'
        with self.assertRaises(ValueError):m.validate_manifest(value)




def raw_fixture(origin='synthetic'):
    """Hand-specified procfs-shaped counters, never a measured benchmark."""
    value=manifest(); value['evidence_origin']=origin
    value['executable_labels']={H:'worker_control','b'*64:'docker_runtime','c'*64:'tailscale'}
    begin=dict(kind='begin',schema=2,manifest=value,manifest_canonical_sha256=m.canonical_digest(value),
               evidence_origin=origin,collector_sha256=H,collector_helper_sha256=H,manifest_sha256=H,
               workload_binding_sha256=H,boot_id='boot',requested_seconds=600,interval=5,
               clock='CLOCK_BOOTTIME',clock_ticks=100,limitations=[])
    records=[begin]
    base=10**12
    for index in range(121):
        start=base+index*5*10**9
        groups=[]
        for position,(role,category,label,exe) in enumerate([('control','control','worker_control',H),
            ('runtime','runtime','docker_runtime','b'*64),('tailscale','tailscale','tailscale','c'*64)]):
            pss=(position+1)*1024**2
            process=dict(pid=123+position,start=100+position,cpu_ticks=100+index,
                         state='S',cgroup='lab/'+role,pss_bytes=pss,rss_bytes=pss,
                         executable_sha256=exe,label=label)
            groups.append(dict(role=role,accounting_class=category,native_identity=[1,position+2],
                cpu=dict(usage_usec=1000+index*10000,user_usec=500+index*5000,system_usec=500+index*5000),
                counters_read_started_boottime_ns=start+10+position*10,
                counters_read_finished_boottime_ns=start+20+position*10,
                memory_current_bytes=(8-position*2)*1024**2,
                memory_events=dict(low=0,high=0,max=0,oom=0,oom_kill=0,oom_group_kill=0),
                memory_stat=dict(anon=1024**2,file=1024**2,kernel=1024,sock=0),
                pss_bytes=pss,pss_by_label_bytes={label:pss},processes=[process],
                descendant_groups=1,vanished_groups=0,vanished_processes=0,invalid_processes=[]))
        records.append(dict(kind='sample',sequence=index,elapsed_ns=index*5*10**9,
            read_collection_ns=100,gap_ns=5*10**9 if index else 0,groups=groups,
            duplicate_process_identities=[],pss_sum_valid=True,total_cohort_pss_bytes=6*1024**2,
            whole_host=dict(cpu_ticks={key:index*500+1 for key in ('user','nice','system','idle','iowait','irq','softirq','steal')},
                            memory=dict(MemTotal_bytes=1024**3,MemFree_bytes=512*1024**2,MemAvailable_bytes=768*1024**2,Slab_bytes=1024**2,
                            Buffers_bytes=1024,Cached_bytes=1024,SReclaimable_bytes=1024,SUnreclaim_bytes=1024,KernelStack_bytes=1024,PageTables_bytes=1024,Percpu_bytes=1024)),
            whole_host_read_started_boottime_ns=start+60,whole_host_read_finished_boottime_ns=start+70,
            observer_cpu_seconds=index*.01,observer_maxrss_bytes=1024**2))
        records.append(dict(kind='sample_complete',sequence=index,read_started_boottime_ns=start,
            read_finished_boottime_ns=start+100,sample_flush_finished_boottime_ns=start+120,
            observer_cpu_seconds_through_sample_flush=index*.01,observer_maxrss_bytes=1024**2))
    records.append(dict(kind='end',samples=121,elapsed_ns=600*10**9,max_gap_ns=5*10**9,
        observer_cpu_seconds_through_prior_output=2,ten_minute_duration_met=True,full_day_duration_met=False))
    return records


class RawEvidence(unittest.TestCase):
    def summarize(self, records):
        import sys
        sys.path.insert(0,str(ROOT))
        import analyze
        with tempfile.TemporaryDirectory() as directory:
            path=pathlib.Path(directory)/'raw.jsonl'
            path.write_text(''.join(json.dumps(row)+'\n' for row in records))
            return analyze.summarize(path)

    def test_complete_counter_accounting_has_hand_derived_bytes_and_cpu(self):
        result=self.summarize(raw_fixture())
        self.assertEqual(result['router_service_footprint_peak_bytes'],18*1024**2)
        self.assertEqual(result['control_pss_peak_bytes'],1024**2)
        self.assertEqual(result['tailscale_pss_peak_bytes'],3*1024**2)
        low,high=result['control_cpu_core_seconds_per_second_bounds']
        self.assertLess(low,.002000001);self.assertGreater(high,.001999999)
        self.assertEqual(result['original_window_boottime_ns'],[10**12,10**12+600*10**9])
        self.assertFalse(result['problems'])
        self.assertIn('synthetic', ' '.join(m.run_problems(result)))

    def test_counter_reset_refused(self):
        rows=raw_fixture();rows[3]['groups'][0]['cpu']['usage_usec']=0
        with self.assertRaisesRegex(ValueError,'cpu_counter_reset'):self.summarize(rows)

    def test_pid_reuse_is_retained_and_stable_identity_is_invalidated(self):
        rows=raw_fixture();rows[3]['groups'][0]['processes'][0]['start']=999
        result=self.summarize(rows)
        self.assertTrue(result['lifecycle_events'])
        self.assertIn('stable_process_missing_or_changed', ' '.join(result['problems']))

    def test_terminal_state_is_never_accepted_as_running(self):
        rows=raw_fixture();rows[3]['groups'][0]['processes'][0]['state']='Z'
        result=self.summarize(rows)
        self.assertIn('terminal_or_stopped_process',' '.join(result['problems']))

    def test_duplicate_pid_invalidates_record(self):
        rows=raw_fixture();rows[3]['groups'][1]['processes'][0].update(pid=123,start=100)
        with self.assertRaises(ValueError):self.summarize(rows)

    def test_missing_pss_suppresses_whole_run_control_pss(self):
        rows=raw_fixture();rows[3]['groups'][0]['vanished_processes']=1
        rows[3]['pss_sum_valid']=False;rows[3]['total_cohort_pss_bytes']=None
        result=self.summarize(rows)
        self.assertIsNone(result['control_pss_peak_bytes'])
        self.assertIn('incomplete_pss_coverage',result['problems'])

    def test_cgroup_replacement_is_never_reset_to_new_baseline(self):
        rows=raw_fixture();rows[3]['groups'][0]['native_identity']=[1,999]
        with self.assertRaisesRegex(ValueError,'identity_changed'):self.summarize(rows)

    def test_truncated_jsonl_cannot_be_analyzed_as_complete(self):
        with self.assertRaisesRegex(ValueError,'missing_complete_end'):self.summarize(raw_fixture()[:-1])

    def test_oom_is_recorded(self):
        rows=raw_fixture();rows[-3]['groups'][0]['memory_events']['oom_kill']=1
        self.assertIn('oom:control',self.summarize(rows)['problems'])


def traffic_fixture(run):
    """Synthetic telemetry shaped like original ticks, evidence and leases."""
    low,high=run['original_window_boottime_ns']
    points=list(range(low-5*10**9,high+5*10**9+1,5*10**9))
    ticks=[];health=[];watchdog=[];retry=[]
    for index,point in enumerate(points):
        sample_id='sample-'+str(index)
        ticks.append(dict(scheduled_ns=point,completed_ns=point+1,deadline_ns=point+5*10**9,
                          action='sample',sample_id=sample_id))
        health.append(dict(observed_ns=point+3,provider_at_ns=point+1,structural_at_ns=point+2,
            heartbeat_at_ns=point+2,verified_at_ns=point+1,message_sent_ns=point+2,
            handshake_age_at_structural_ns=10*10**9,session_deadline_ns=point+1+44*10**9))
        watchdog.append(dict(observed_ns=point+4,liveness_sent_ns=point,accepted_ns=point+1,
            lease_deadline_ns=point+90*10**9,session_deadline_ns=point+1+44*10**9,
            trigger_ns=point+1+39*10**9,sequence=index+1))
        retry.append(dict(scope='exit1',sample_id=sample_id,started_ns=point,completed_ns=point+2,
            original_deadline_ns=point+34*10**9,first_result='success',first_finished_ns=point+1,
            retry=dict(coverage='not_triggered',reason='success')))
    streams=[dict(component='cadence',scope='exit1',observations=ticks),
             dict(component='health',scope='exit1',observations=health)]
    streams.extend(dict(component='watchdog',scope='exit1',writer=writer,observations=copy.deepcopy(watchdog))
                   for writer in ('transport','data','host'))
    return dict(schema=2,evidence_origin='actual_runtime',binding=run['binding'],record_sha256=run['input_sha256'],
        provenance=dict(producer_sha256=H,raw_evidence_sha256=H,review_sha256=H,kind='real_disposable_tailscale_clients'),
        window_boottime_ns=[low,high],throughput_bytes_per_second=100,
        throughput_intervals=[dict(start_ns=low,end_ns=high,bytes=60000)],
        latency_ns=dict(p95=20,samples=20,complete=True,values_ns=list(range(2,22))),
        monitoring=dict(variant='rust_native_v1',source_bindings={'source_sha256':run['binding']['source_sha256']},contract=m.MONITORING,window_boottime_ns=[low,high],complete=True,
                        deadline_misses=0,streams=streams,retry_coverage=retry),
        unexpected_restarts=0,oom_events=0,traffic_protocols=['ipv4','dns','ipv6','tcp','udp'])


class TrafficEvidence(unittest.TestCase):
    summarize = RawEvidence.summarize
    def run_record(self):
        run=self.summarize(raw_fixture('actual_runtime'))
        return run

    def test_actual_sidecar_aggregates_full_samples_and_intervals(self):
        run=self.run_record()
        result=m.validate_traffic(traffic_fixture(run),run)
        self.assertEqual(result['throughput_bytes_per_second'],100)

    def test_forged_p95_rejected(self):
        run=self.run_record();sidecar=traffic_fixture(run);sidecar['latency_ns']['p95']=1
        with self.assertRaisesRegex(ValueError,'p95_projection'):m.validate_traffic(sidecar,run)

    def test_missing_per_exit_monitor_stream_rejected(self):
        run=self.run_record();sidecar=traffic_fixture(run);sidecar['monitoring']['streams'].pop()
        with self.assertRaisesRegex(ValueError,'monitor_stream_coverage'):m.validate_traffic(sidecar,run)

    def test_monitor_miss_is_computed_from_original_deadline(self):
        run=self.run_record();sidecar=traffic_fixture(run)
        observation=sidecar['monitoring']['streams'][0]['observations'][0]
        observation['completed_ns']=observation['deadline_ns']+1
        with self.assertRaisesRegex(ValueError,'monitor_miss_projection'):m.validate_traffic(sidecar,run)

    def test_missing_traffic_interval_rejected(self):
        run=self.run_record();sidecar=traffic_fixture(run)
        sidecar['throughput_intervals'][0]['start_ns']+=1
        with self.assertRaisesRegex(ValueError,'traffic_gap'):m.validate_traffic(sidecar,run)


class MatchedComparisons(unittest.TestCase):
    summarize = RawEvidence.summarize

    def runs(self):
        baseline=[];candidate=[]
        seed=self.summarize(raw_fixture('actual_runtime'))
        # These are explicitly synthetic in-memory gate fixtures, not exported evidence.
        for count,mode in m.SCENARIOS:
            for implementation,target in [('python',baseline),('rust',candidate)]:
                for repetition in range(2):
                    run=copy.deepcopy(seed)
                    run['binding'].update(implementation=implementation,exits=count,scenario=mode,
                        exit_ids=['exit'+str(i+1) for i in range(count)],
                        exit_modes=['mullvad']*min(5,count)+(['direct'] if count==6 else []),
                        run_id=f'{implementation}-{count}-{mode}-{repetition}',repetition=repetition+1)
                    unique=len(baseline)+len(candidate)+1
                    run['input_sha256']=hashlib.sha256(str(unique).encode()).hexdigest()
                    run['original_window_boottime_ns']=[unique*1000*10**9,(unique*1000+600)*10**9]
                    run['traffic']=dict(throughput_bytes_per_second=100,latency_ns=dict(p95=100),
                        monitoring=dict(deadline_misses=0),unexpected_restarts=0,oom_events=0)
                    run['control_cpu_core_seconds_per_second_bounds']=[1,1] if implementation=='python' else [.4,.4]
                    target.append(run)
        return baseline,candidate

    def test_all_gates_require_all_shapes_and_repetitions(self):
        baseline,candidate=self.runs()
        report=m.compare_runs(baseline,candidate)
        self.assertEqual(report['status'],'PASS')
        self.assertIsNone(report['scenarios'][-1]['control_pss_target_bytes'])
        self.assertNotIn('control_pss',report['scenarios'][-1]['gates'])

    def test_bad_repetition_is_not_averaged_away(self):
        baseline,candidate=self.runs();candidate[0]['control_cpu_core_seconds_per_second_bounds']=[.7,.7]
        self.assertEqual(m.compare_runs(baseline,candidate)['scenarios'][0]['status'],'FAIL')

    def test_host_mismatch_is_insufficient(self):
        baseline,candidate=self.runs();candidate[0]['binding']['host_id_sha256']='b'*64
        self.assertEqual(m.compare_runs(baseline,candidate)['scenarios'][0]['status'],'INSUFFICIENT')

    def test_one_missing_repetition_is_insufficient(self):
        baseline,candidate=self.runs();candidate.pop(0)
        self.assertEqual(m.compare_runs(baseline,candidate)['scenarios'][0]['status'],'INSUFFICIENT')

    def test_cross_shape_concurrent_benchmarks_are_refused(self):
        baseline,candidate=self.runs()
        candidate[-1]['original_window_boottime_ns']=candidate[0]['original_window_boottime_ns']
        self.assertEqual(m.compare_runs(baseline,candidate)['status'],'INSUFFICIENT')

    def test_repetition_spread_contains_cpu_throughput_and_latency(self):
        baseline,candidate=self.runs()
        ranges=m.compare_runs(baseline,candidate)['scenarios'][0]['ranges']
        self.assertIn('supervision_cpu_core_seconds_per_second',ranges)
        self.assertIn('throughput_bytes_per_second',ranges)
        self.assertIn('p95_latency_ns',ranges)


class CompletenessRegressions(unittest.TestCase):
    summarize = RawEvidence.summarize
    runs = MatchedComparisons.runs
    def test_missing_oom_counter_is_unavailable(self):
        rows=raw_fixture()
        for row in rows:
            if row['kind']=='sample':del row['groups'][0]['memory_events']['oom_kill']
        with self.assertRaisesRegex(ValueError,'oom_accounting_unavailable'):self.summarize(rows)

    def test_missing_kernel_host_context_is_unavailable(self):
        rows=raw_fixture()
        for row in rows:
            if row['kind']=='sample':del row['whole_host']['memory']['Slab_bytes']
        with self.assertRaisesRegex(ValueError,'host_kernel_buffer_context_unavailable'):self.summarize(rows)

    def test_reports_individual_matched_pairs_and_accounting(self):
        baseline,candidate=self.runs()
        row=m.compare_runs(baseline,candidate)['scenarios'][0]
        self.assertEqual(len(row['pairs']),2)
        self.assertEqual(row['pairs'][0]['ratios']['cpu'],.4)
        self.assertEqual(row['accounting']['method'],'disjoint_cgroup_v2_memory_current')


class MixedAccounting(unittest.TestCase):
    summarize = RawEvidence.summarize
    runs = MatchedComparisons.runs

    def test_huge_json_integer_refused_without_overflow(self):
        with self.assertRaises(ValueError):m.number(10**1000)

    def test_mixed_container_cgroup_retains_total_pss_and_marks_control_cpu_unavailable(self):
        rows=raw_fixture()
        manifest=rows[0]['manifest']
        for group in manifest['groups']:group['accounting_class']='mixed'
        rows[0]['manifest_canonical_sha256']=m.canonical_digest(manifest)
        for row in rows:
            if row['kind']=='sample':
                for group in row['groups']:group['accounting_class']='mixed'
        result=self.summarize(rows)
        self.assertEqual(result['router_service_footprint_peak_bytes'],18*1024**2)
        self.assertEqual(result['control_pss_peak_bytes'],1024**2)
        self.assertIsNone(result['control_cpu_core_seconds_per_second_bounds'])
        self.assertEqual(result['control_cpu_coverage'],'INSUFFICIENT:mixed_cgroup_transient_cpu_unattributable')

    def test_mixed_control_cpu_does_not_hide_other_gates(self):
        baseline,candidate=self.runs()
        baseline[0]['control_cpu_core_seconds_per_second_bounds']=None
        row=m.compare_runs(baseline,candidate)['scenarios'][0]
        self.assertEqual(row['status'],'INSUFFICIENT')
        self.assertEqual(row['gates']['supervision_cpu_reduction_at_least_50_percent'],'INSUFFICIENT')
        self.assertIs(row['gates']['total_memory'],True)


class SoakAndMixedLayout(unittest.TestCase):
    summarize = RawEvidence.summarize

    def test_one_mixed_group_includes_all_roles_without_double_counting(self):
        rows=raw_fixture();manifest=rows[0]['manifest']
        manifest['groups']=manifest['groups'][:1];manifest['groups'][0]['accounting_class']='mixed'
        manifest['accounting']['required_components']={name:['control'] for name in m.COMPONENTS}
        rows[0]['manifest_canonical_sha256']=m.canonical_digest(manifest)
        for row in rows:
            if row['kind']!='sample':continue
            groups=row['groups'];group=groups[0]
            group['accounting_class']='mixed'
            group['processes']=[process for item in groups for process in item['processes']]
            for process in group['processes']:process['cgroup']='lab/control'
            group['memory_current_bytes']=18*1024**2
            group['pss_bytes']=6*1024**2
            group['pss_by_label_bytes']={process['label']:process['pss_bytes'] for process in group['processes']}
            row['groups']=[group]
        result=self.summarize(rows)
        self.assertEqual(result['router_service_footprint_peak_bytes'],18*1024**2)
        self.assertEqual(result['total_cohort_max_pss_bytes'],6*1024**2)
        self.assertIsNone(result['control_cpu_core_seconds_per_second_bounds'])

    def timeline(self):
        run=self.summarize(raw_fixture('actual_runtime'))
        run['binding'].update(exits=6,exit_ids=['exit'+str(i) for i in range(6)],exit_modes=['mullvad']*5+['direct'])
        run['original_window_boottime_ns']=[10**12,10**12+86400*10**9]
        run['sample_start_span_ns']=86400*10**9
        run['traffic']=dict(monitoring=dict(deadline_misses=0),unexpected_restarts=0,oom_events=0)
        return dict(schema=1,evidence_origin='actual_runtime',binding=run['binding'],window_boottime_ns=run['original_window_boottime_ns'],
            segments=[run],provenance=dict(review_sha256=H,raw_timeline_sha256=H,producer_sha256=H))

    def test_offline_soak_validator_requires_full_original_day(self):
        value=self.timeline();value['window_boottime_ns'][1]-=1
        self.assertEqual(m.validate_soak(value)['status'],'INSUFFICIENT')

    def test_offline_soak_validator_accepts_only_complete_timeline_shape(self):
        # Simulation only: no elapsed time or actual soak is claimed by this test.
        self.assertEqual(m.validate_soak(self.timeline())['status'],'PASS')

    def test_soak_oom_cannot_be_dismissed_by_complete_timeline(self):
        value=self.timeline();value['segments'][0]['traffic']['oom_events']=1
        self.assertEqual(m.validate_soak(value)['status'],'INSUFFICIENT')




class IndependentReviewRegressions(unittest.TestCase):
    summarize = RawEvidence.summarize
    runs = MatchedComparisons.runs

    def test_observed_control_in_unmapped_mixed_runtime_group_is_insufficient(self):
        rows=raw_fixture();manifest=rows[0]['manifest']
        manifest['groups'][1]['accounting_class']='mixed'
        rows[0]['manifest_canonical_sha256']=m.canonical_digest(manifest)
        for row in rows:
            if row['kind']!='sample':continue
            group=row['groups'][1];group['accounting_class']='mixed'
            group['processes'][0].update(label='worker_control',executable_sha256=H)
            group['pss_by_label_bytes']={'worker_control':2*1024**2}
        self.assertIsNone(self.summarize(rows)['control_cpu_core_seconds_per_second_bounds'])

    def test_suite_cannot_combine_different_rust_artifacts_across_shapes(self):
        baseline,candidate=self.runs()
        for run in candidate:
            if run['binding']['exits']==6:run['binding']['artifact_sha256']='b'*64
        self.assertEqual(m.compare_runs(baseline,candidate)['status'],'INSUFFICIENT')

    def test_suite_cannot_combine_different_rust_sources_across_shapes(self):
        baseline,candidate=self.runs()
        for run in candidate:
            if run['binding']['scenario']=='load':run['binding']['source_sha256']='b'*64
        self.assertEqual(m.compare_runs(baseline,candidate)['status'],'INSUFFICIENT')

    def test_suite_cannot_mix_collectors_across_shapes(self):
        baseline,candidate=self.runs()
        for run in baseline+candidate:
            if run['binding']['exits']==6:run['collector_sha256']='b'*64
        self.assertEqual(m.compare_runs(baseline,candidate)['status'],'INSUFFICIENT')

    def test_missing_retry_coverage_is_not_no_monitor_miss(self):
        run=self.summarize(raw_fixture('actual_runtime'));value=traffic_fixture(run)
        value['monitoring'].pop('retry_coverage',None)
        with self.assertRaises(ValueError):m.validate_traffic(value,run)

    def test_completion_at_original_deadline_is_a_miss(self):
        run=self.summarize(raw_fixture('actual_runtime'));value=traffic_fixture(run)
        monitor=value['monitoring']
        observation=monitor['streams'][0]['observations'][0]
        observation['completed_ns']=observation['deadline_ns']
        with self.assertRaisesRegex(ValueError,'monitor_miss_projection'):m.validate_traffic(value,run)


def add_triggered_retry(sidecar):
    operation=sidecar['monitoring']['retry_coverage'][0]
    point=operation['started_ns']
    operation['first_result']='http_429';operation['completed_ns']=point+2*10**9
    check=lambda at:dict(checked_ns=at,interfaces_sha256=H,routes_sha256=H,handshake_age_ns=10*10**9)
    operation['retry']=dict(coverage='triggered',reason='http_429',pre_delay_check=check(point+2),
        delay_started_ns=point+3,original_not_before_ns=point+3+10**9,
        post_delay_check=check(point+4+10**9),retry_started_ns=point+5+10**9,
        retry_completed_ns=point+6+10**9,retry_result='success')
    return operation


class OriginalClockSemantics(unittest.TestCase):
    summarize = RawEvidence.summarize

    def setUp(self):
        self.run=self.summarize(raw_fixture('actual_runtime'))
        self.value=traffic_fixture(self.run)

    def test_real_triggered_retry_has_one_original_second_and_both_fresh_checks(self):
        add_triggered_retry(self.value)
        self.assertEqual(m.validate_traffic(self.value,self.run)['monitoring']['deadline_misses'],0)

    def test_triggered_retry_missing_after_delay_check_refused(self):
        operation=add_triggered_retry(self.value)
        del operation['retry']['post_delay_check']
        with self.assertRaisesRegex(ValueError,'retry_trigger_coverage'):m.validate_traffic(self.value,self.run)

    def test_retry_timer_cannot_be_shortened(self):
        operation=add_triggered_retry(self.value)
        operation['retry']['original_not_before_ns']-=1
        with self.assertRaisesRegex(ValueError,'retry_original_one_second_timer'):m.validate_traffic(self.value,self.run)

    def test_retry_cannot_reuse_the_before_delay_structural_check(self):
        operation=add_triggered_retry(self.value)
        operation['retry']['post_delay_check']=copy.deepcopy(operation['retry']['pre_delay_check'])
        with self.assertRaisesRegex(ValueError,'retry_missing_fresh'):m.validate_traffic(self.value,self.run)

    def test_permanent_error_cannot_trigger_retry(self):
        operation=add_triggered_retry(self.value);operation['first_result']='http_permanent'
        with self.assertRaisesRegex(ValueError,'retry_no_trigger_coverage'):m.validate_traffic(self.value,self.run)

    def test_eligible_error_cannot_claim_not_triggered(self):
        operation=self.value['monitoring']['retry_coverage'][0];operation['first_result']='http_429'
        operation['retry']=dict(coverage='not_triggered',reason='http_429')
        with self.assertRaisesRegex(ValueError,'retry_trigger_coverage'):m.validate_traffic(self.value,self.run)

    def test_one_missing_retry_operation_is_incomplete_even_when_no_failure_is_claimed(self):
        self.value['monitoring']['retry_coverage'].pop()
        with self.assertRaisesRegex(ValueError,'missing_retry_coverage_for_cadence'):m.validate_traffic(self.value,self.run)

    def test_health_45_is_an_exclusive_age_not_an_observation_period(self):
        observation=self.value['monitoring']['streams'][1]['observations'][0]
        observation['provider_at_ns']=observation['observed_ns']-45*10**9
        with self.assertRaisesRegex(ValueError,'health_original_age_expired'):m.validate_traffic(self.value,self.run)

    def test_handshake_expires_at_180_including_age_since_structural_sample(self):
        observation=self.value['monitoring']['streams'][1]['observations'][0]
        observation['handshake_age_at_structural_ns']=180*10**9-1
        with self.assertRaisesRegex(ValueError,'handshake_original_age_expired'):m.validate_traffic(self.value,self.run)

    def test_health_observation_cannot_extend_original_session_margin(self):
        observation=self.value['monitoring']['streams'][1]['observations'][0]
        observation['session_deadline_ns']+=10**9
        with self.assertRaisesRegex(ValueError,'health_original_expiry_changed'):m.validate_traffic(self.value,self.run)

    def test_watchdog_90_is_an_original_sent_at_lease_not_a_poll_interval(self):
        observation=self.value['monitoring']['streams'][2]['observations'][0]
        observation['lease_deadline_ns']+=1
        with self.assertRaisesRegex(ValueError,'watchdog_original_lease_changed'):m.validate_traffic(self.value,self.run)

    def test_liveness_message_at_two_seconds_is_expired(self):
        observation=self.value['monitoring']['streams'][2]['observations'][0]
        observation['liveness_sent_ns']=observation['accepted_ns']-2*10**9
        with self.assertRaisesRegex(ValueError,'watchdog_original_liveness_age'):m.validate_traffic(self.value,self.run)

    def test_outer_provider_completion_equal_deadline_is_a_monitor_miss(self):
        operation=self.value['monitoring']['retry_coverage'][0]
        operation['completed_ns']=operation['original_deadline_ns']
        with self.assertRaisesRegex(ValueError,'monitor_miss_projection'):m.validate_traffic(self.value,self.run)

    def test_old_fictitious_poll_streams_refused(self):
        self.value['schema']=1
        with self.assertRaisesRegex(ValueError,'traffic_not_actual'):m.validate_traffic(self.value,self.run)




PYTHON_SOURCES={'router_runtime.py':'36a087a833d260fc6c951ed407c22db2448a1a6dea55fdbf5aa8928bb3e11901',
    'host/orchestrate.py':'fe62364ae1c88c409f9e830f448a5a04f00e31927e5d02f24ea5a6b51f1296c9'}


def legacy_fixture(run):
    value=traffic_fixture(run);value['binding']['implementation']='python'
    low,high=run['original_window_boottime_ns'];offset=100*10**9
    wall_offset=1700000000*10**9
    cycles=[];health=[];host=[];operations=[];sync=[]
    for index,point in enumerate(range(low-10*10**9,high+10*10**9+1,6*10**9)):
        mono=point-offset;sample_id='legacy-'+str(index)
        cycles.append(dict(sample_id=sample_id,started_ns=mono,work_finished_ns=mono+10**9,
            sleep_started_ns=mono+10**9,original_wake_ns=mono+6*10**9,woke_ns=mono+6*10**9,event_sha256=H))
        heartbeat=(point+wall_offset)//10**9
        health.append(dict(read_begin_ns=point,read_end_ns=point+1000,wall_before_ns=point+wall_offset,
            wall_after_ns=point+wall_offset+1000,state='READY',time=heartbeat,heartbeat=heartbeat,
            status_result='ready',protection=None,event_sha256=H))
        operations.append(dict(scope='exit1',sample_id=sample_id,started_ns=mono,completed_ns=mono+10**9,
            first_finished_ns=mono+10**9-1,original_deadline_ns=None,attempt_timeout_ns=12*10**9,
            first_result='success',retry=dict(coverage='not_triggered',reason='success'),
            handshake=dict(wall_before_ns=point+wall_offset,wall_after_ns=point+wall_offset+1000,
                latest_handshake_seconds=heartbeat-10,event_sha256=H)))
    for point in range(low-4*10**9,high+4*10**9+1,2*10**9+4000):
        mono=point-offset
        host.append(dict(scope='exit1',service_id_sha256=H,started_ns=mono,work_finished_ns=mono+1000,notify_started_ns=mono+1000,
            notify_finished_ns=mono+2000,manager_read_started_ns=mono+2000,manager_read_finished_ns=mono+3000,
            reported_clock='CLOCK_MONOTONIC',reported_property='WatchdogTimestampMonotonic',
            reported_timestamp_us=(mono+1000)//1000,watchdog_usec=90*10**6,
            sleep_started_ns=mono+4000,original_wake_ns=mono+2*10**9+4000,woke_ns=mono+2*10**9+4000,event_sha256=H))
    health=[]
    for cycle in host:
        point=cycle['started_ns']+offset
        heartbeat=(point+wall_offset)//10**9
        health.append(dict(read_begin_ns=point+100,read_end_ns=point+900,
            wall_before_ns=point+wall_offset+100,wall_after_ns=point+wall_offset+900,
            state='READY',time=heartbeat,heartbeat=heartbeat,status_result='ready',protection=None,event_sha256=H))
    for point in (low-20*10**9,high+20*10**9):
        sync.append(dict(monotonic_before_ns=point-offset-10,boottime_ns=point,monotonic_after_ns=point-offset+10))
    value['monitoring']=dict(variant='python_legacy_v1',source_bindings=PYTHON_SOURCES,
        contract=m.MONITORING,window_boottime_ns=[low,high],complete=True,deadline_misses=0,
        monotonic_boottime_brackets=sync,router_cycles=[dict(scope='exit1',clock='CLOCK_MONOTONIC',cycles=cycles)],
        health=[dict(scope='exit1',observations=health)],host_cycles=host,retry_coverage=operations)
    return value


class LegacyAdapter(unittest.TestCase):
    summarize=RawEvidence.summarize
    def setUp(self):
        self.run=self.summarize(raw_fixture('actual_runtime'));self.run['binding']['implementation']='python'
        self.value=legacy_fixture(self.run)

    def test_real_legacy_work_then_sleep_and_wall_health_supported(self):
        self.assertIs(m.validate_traffic(self.value,self.run),self.value)

    def test_legacy_never_requires_rust_private_receipts(self):
        self.assertNotIn('streams',self.value['monitoring'])
        self.assertEqual(m.validate_traffic(self.value,self.run)['monitoring']['variant'],'python_legacy_v1')

    def test_legacy_source_hash_must_match_reviewed_source(self):
        self.value['monitoring']['source_bindings']=dict(PYTHON_SOURCES,**{'router_runtime.py':'f'*64})
        with self.assertRaisesRegex(ValueError,'legacy_source_binding'):m.validate_traffic(self.value,self.run)

    def test_legacy_must_not_invent_a_whole_operation_12_second_deadline(self):
        operation=self.value['monitoring']['retry_coverage'][0]
        operation['original_deadline_ns']=operation['started_ns']+12*10**9
        with self.assertRaisesRegex(ValueError,'legacy_per_attempt_timeout'):m.validate_traffic(self.value,self.run)

    def test_legacy_sleep5_is_after_work_and_can_exceed_fixed_tick5(self):
        self.assertEqual(self.value['monitoring']['router_cycles'][0]['cycles'][1]['started_ns']-
                         self.value['monitoring']['router_cycles'][0]['cycles'][0]['started_ns'],6*10**9)
        m.validate_traffic(self.value,self.run)

    def test_legacy_wall_uncertainty_at_45_is_insufficient(self):
        observation=self.value['monitoring']['health'][0]['observations'][0]
        observation['wall_before_ns']=observation['heartbeat']*10**9+45*10**9-1
        observation['wall_after_ns']=observation['heartbeat']*10**9+45*10**9+1
        with self.assertRaisesRegex(ValueError,'legacy_health_age'):m.validate_traffic(self.value,self.run)

    def test_legacy_blocked_without_health_has_actual_protection_proof(self):
        observation=self.value['monitoring']['health'][0]['observations'][0]
        observation.update(state='BLOCKED',time=None,heartbeat=None,status_result='blocked',
                           protection=dict(kind='tailscale_down',evidence_sha256=H))
        host=self.value['monitoring']['host_cycles'][0]
        blocked={key:host[key] for key in ('scope','service_id_sha256','started_ns','work_finished_ns','event_sha256')}
        blocked.update(outcome='BLOCKED',protection=dict(kind='host_quarantine',evidence_sha256=H))
        self.value['monitoring']['host_cycles'][0]=blocked
        m.validate_traffic(self.value,self.run)

    def test_legacy_blocked_without_actual_protection_is_insufficient(self):
        observation=self.value['monitoring']['health'][0]['observations'][0]
        observation.update(state='BLOCKED',time=None,heartbeat=None,status_result='blocked')
        with self.assertRaisesRegex(ValueError,'blocked_protection_evidence'):m.validate_traffic(self.value,self.run)


class SafeFaultBranches(unittest.TestCase):
    summarize=RawEvidence.summarize
    def test_eligible_retry_aborted_before_timer_has_no_timer_or_attempt2(self):
        run=self.summarize(raw_fixture('actual_runtime'));value=traffic_fixture(run)
        operation=value['monitoring']['retry_coverage'][0];point=operation['started_ns']
        operation['first_result']='http_429'
        operation['retry']=dict(coverage='aborted',reason='http_429',stage='before_delay',
            failed_check=dict(checked_ns=point+1,failed_component='default_route',event_sha256=H),
            protection=dict(kind='terminal_quarantine',evidence_sha256=H))
        m.validate_traffic(value,run)

    def test_retry_abort_cannot_smuggle_a_second_attempt(self):
        run=self.summarize(raw_fixture('actual_runtime'));value=traffic_fixture(run)
        operation=value['monitoring']['retry_coverage'][0];point=operation['started_ns']
        operation['first_result']='http_429'
        operation['retry']=dict(coverage='aborted',reason='http_429',stage='before_delay',
            failed_check=dict(checked_ns=point+1,failed_component='default_route',event_sha256=H),
            protection=dict(kind='terminal_quarantine',evidence_sha256=H),retry_started_ns=point+1)
        with self.assertRaisesRegex(ValueError,'retry_abort_fields'):m.validate_traffic(value,run)

    def test_rust_blocked_health_and_writers_need_no_fabricated_session(self):
        run=self.summarize(raw_fixture('actual_runtime'));value=traffic_fixture(run)
        health=value['monitoring']['streams'][1]['observations'][0]
        health.clear();health.update(observed_ns=run['original_window_boottime_ns'][0]-5*10**9,
            state='BLOCKED',protection=dict(kind='terminal_quarantine',evidence_sha256=H))
        for stream in value['monitoring']['streams'][2:]:
            observation=stream['observations'][0];point=observation['observed_ns']
            observation.clear();observation.update(observed_ns=point,state='BLOCKED',
                protection=dict(kind='terminal_quarantine',evidence_sha256=H))
        m.validate_traffic(value,run)

    def test_legacy_sparse_health_cannot_claim_complete_host_monitoring(self):
        run=self.summarize(raw_fixture('actual_runtime'));run['binding']['implementation']='python'
        value=legacy_fixture(run);observations=value['monitoring']['health'][0]['observations']
        value['monitoring']['health'][0]['observations']=[observations[0],observations[-1]]
        with self.assertRaisesRegex(ValueError,'legacy_host_health_coverage'):m.validate_traffic(value,run)

    def test_legacy_suspend_cannot_turn_clock_brackets_into_an_exact_lease(self):
        run=self.summarize(raw_fixture('actual_runtime'));run['binding']['implementation']='python';value=legacy_fixture(run)
        value['monitoring']['monotonic_boottime_brackets'][-1]['boottime_ns']+=10**9
        with self.assertRaisesRegex(ValueError,'legacy_clock_uncertainty'):m.validate_traffic(value,run)


class LegacyFaultAndClockEdges(unittest.TestCase):
    summarize=RawEvidence.summarize
    def setUp(self):
        self.run=self.summarize(raw_fixture('actual_runtime'));self.run['binding']['implementation']='python'
        self.value=legacy_fixture(self.run)

    def test_legacy_structural_abort_before_sleep_has_no_delay_or_second_attempt(self):
        operation=self.value['monitoring']['retry_coverage'][0];point=operation['started_ns']
        operation['first_result']='http_429';operation['handshake']=None
        operation['retry']=dict(coverage='aborted',reason='http_429',stage='before_delay',
            failed_check=dict(checked_ns=point+10**9,failed_component='handshake',event_sha256=H),
            protection=dict(kind='tailscale_down',evidence_sha256=H))
        m.validate_traffic(self.value,self.run)

    def test_missing_manager_receipt_cannot_be_inferred_from_notify_call(self):
        cycle=self.value['monitoring']['host_cycles'][0];cycle['reported_timestamp_us']=0
        with self.assertRaisesRegex(ValueError,'legacy_systemd_receipt_unavailable'):m.validate_traffic(self.value,self.run)

    def test_systemd_reported_clock_must_remain_explicit(self):
        self.value['monitoring']['host_cycles'][0]['reported_clock']='CLOCK_BOOTTIME'
        with self.assertRaisesRegex(ValueError,'legacy_systemd_clock_or_lease'):m.validate_traffic(self.value,self.run)

    def test_legacy_handshake_wall_upper_bound_at180_is_expired(self):
        handshake=self.value['monitoring']['retry_coverage'][0]['handshake']
        handshake['wall_after_ns']=handshake['latest_handshake_seconds']*10**9+180*10**9
        with self.assertRaisesRegex(ValueError,'legacy_handshake_age'):m.validate_traffic(self.value,self.run)

    def test_blocked_does_not_accept_fabricated_fresh_wall_time(self):
        observation=self.value['monitoring']['health'][0]['observations'][0]
        observation.update(state='BLOCKED',time=None,heartbeat=None,status_result='ready',
            protection=dict(kind='host_quarantine',evidence_sha256=H))
        with self.assertRaisesRegex(ValueError,'legacy_blocked_status'):m.validate_traffic(self.value,self.run)




class LegacyBlockedHost(unittest.TestCase):
    summarize=RawEvidence.summarize
    def test_blocked_host_failure_has_no_fabricated_notify_receipt_or_sleep(self):
        run=self.summarize(raw_fixture('actual_runtime'));run['binding']['implementation']='python'
        value=legacy_fixture(run);cycle=value['monitoring']['host_cycles'][0]
        cycle={key:cycle[key] for key in ('scope','service_id_sha256','started_ns','work_finished_ns','event_sha256')}
        cycle.update(outcome='BLOCKED',protection=dict(kind='host_quarantine',evidence_sha256=H))
        value['monitoring']['host_cycles'][0]=cycle
        observation=value['monitoring']['health'][0]['observations'][0]
        observation.update(state='BLOCKED',time=None,heartbeat=None,status_result='blocked',
            protection=dict(kind='host_quarantine',evidence_sha256=H))
        m.validate_traffic(value,run)




class OriginalOuterWindowAndBlockedOrdering(unittest.TestCase):
    summarize=RawEvidence.summarize
    def setUp(self):
        self.run=self.summarize(raw_fixture('actual_runtime'));self.value=traffic_fixture(self.run)

    def test_rust_outer_deadline_cannot_be_extended_past_original34s(self):
        operation=self.value['monitoring']['retry_coverage'][0]
        operation['completed_ns']=operation['started_ns']+35*10**9
        operation['original_deadline_ns']=operation['started_ns']+40*10**9
        with self.assertRaisesRegex(ValueError,'rust_original_outer34_window'):m.validate_traffic(self.value,self.run)

    def test_rust_outer34_boundary_remains_exclusive(self):
        operation=self.value['monitoring']['retry_coverage'][0]
        operation['completed_ns']=operation['original_deadline_ns']
        self.assertEqual(m.validate_retry(operation,'mullvad'),1)

    def test_legacy_per_attempt12_does_not_imply_rust_outer34(self):
        run=self.run;run['binding']['implementation']='python';value=legacy_fixture(run)
        operation=value['monitoring']['retry_coverage'][0]
        operation['completed_ns']=operation['started_ns']+40*10**9
        operation['first_finished_ns']=operation['completed_ns']
        self.assertEqual(m.validate_retry(operation,'mullvad',legacy=True),0)

    def test_consecutive_blocked_watchdog_observations_cannot_regress_or_repeat(self):
        for delta in (-1,0):
            with self.subTest(delta=delta):
                value=traffic_fixture(self.run);stream=value['monitoring']['streams'][2]['observations']
                at=stream[-2]['observed_ns']+10
                blocked=lambda point:dict(observed_ns=point,state='BLOCKED',
                    protection=dict(kind='terminal_quarantine',evidence_sha256=H))
                stream[-1:-1]=[blocked(at),blocked(at+delta)]
                with self.assertRaisesRegex(ValueError,'watchdog_observation_clock_order'):m.validate_traffic(value,self.run)

    def test_healthy_watchdog_after_blocked_cannot_regress(self):
        stream=self.value['monitoring']['streams'][2]['observations']
        previous=copy.deepcopy(stream[-2]);at=previous['observed_ns']
        stream[-1]=copy.deepcopy(previous);stream[-1]['observed_ns']=at+5
        stream[-1:-1]=[dict(observed_ns=at+10,state='BLOCKED',
            protection=dict(kind='terminal_quarantine',evidence_sha256=H))]
        with self.assertRaisesRegex(ValueError,'watchdog_observation_clock_order'):m.validate_traffic(self.value,self.run)


if __name__ == '__main__':
    unittest.main()
