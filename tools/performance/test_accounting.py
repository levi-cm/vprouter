"""Synthetic behavioral fixtures only; no product measurements or credentials."""
import copy
from fractions import Fraction
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).parent
SPEC = importlib.util.spec_from_file_location('accounting', ROOT / 'accounting.py')
a = importlib.util.module_from_spec(SPEC)
try:
    SPEC.loader.exec_module(a)
except FileNotFoundError:
    pass

H = 'a' * 64
MIB = 1048576


def fixture(implementation='rust', repetition=1, exits=1, scenario='steady'):
    """Hand-built 601-point fake recording; never emitted as actual evidence."""
    components = [('control', ['supervision', 'workers', 'guard', 'init_shim']),
                  ('runtime', ['container']), ('tailscale', ['tailscaled']),
                  ('observer', ['observer']), ('workload', ['workload'])]
    binding = dict(implementation=implementation, source_sha256=H, artifact_sha256=H,
                   config_sha256=H, workload_sha256=H, identity_set_sha256=H,
                   peers_sha256=H, network_conditions_sha256=H, tailscale_version='1.102.5',
                   tailscale_artifact_sha256=H, host_id_sha256=H,
                   run_id=f'{implementation}-{exits}-{scenario}-{repetition}', repetition=repetition,
                   exits=exits, exit_ids=['exit'+str(i+1) for i in range(exits)],
                   exit_modes=['mullvad']*min(5, exits)+(['direct'] if exits == 6 else []),
                   scenario=scenario, monitoring=dict(provider_seconds=5, retry_seconds=1,
                       handshake_seconds=180, health_seconds=45, watchdog_seconds=90))
    domains = [dict(id=name, scope=['suite', name], native_identity=[1, n+1], components=parts)
               for n, (name, parts) in enumerate(components)]
    offset = (exits*100 + (10 if scenario == 'load' else 0) + repetition*2 +
              (1 if implementation == 'rust' else 0))*1000*10**9
    samples = []
    for second in range(601):
        groups, processes = {}, []
        for n, (name, parts) in enumerate(components):
            cpu = second*(400000 if implementation == 'rust' else 1000000) if name == 'control' else second*10000
            groups[name] = dict(cpu=dict(usage_usec=cpu, user_usec=cpu, system_usec=0),
                                memory_current_bytes=20*MIB, memory_stat=dict(anon=10*MIB,file=2*MIB,kernel=2*MIB,sock=0),
                                memory_events=dict(oom=0,oom_kill=0), io={},member_pids=[n+1])
            processes.append(dict(pid=n+1,start_ticks=1,executable_sha256=H,domain=name,component=parts[0],
                                  utime_ticks=second,stime_ticks=0,pss_bytes=8*MIB,rss_bytes=10*MIB,
                                  uss_bytes=4*MIB,threads=1,fds=3,wakeups=second))
        mono = offset+second*10**9
        samples.append(dict(mono_ns=mono, read_end_ns=mono+1000, wall_before_ns=mono+10**15,
                            wall_after_ns=mono+10**15+1000, domains=groups,processes=processes,
                            host=dict(irq_ticks=second,softirq_ticks=second,swap_in_pages=0,
                                      swap_out_pages=0,swap_used_bytes=0,thermal_throttle_count=0,
                                      temperature_millic=40000)))
    run=dict(schema=1,evidence_origin='synthetic',purpose='harness_self_test',binding=binding,
                host=dict(kernel='6.12.0',cpu_model='fixture-cpu',architecture='x86_64',logical_cpus=4,
                          governor='performance',memory_total_bytes=1024*MIB,swap_total_bytes=0,
                          tick_hz=100,tick_bits=64,thermal_limit_millic=90000),
                boot_id=H,clock='CLOCK_BOOTTIME',interval_ns=10**9,warmup_discard_ns=0,
                duration_ns=600*10**9,instrumentation_sha256=H,domains=domains,accounting=dict(complete=True,isolated_host=True,
                kernel_networking='included_in_domains',outside_overhead='none',review_sha256=H),
                samples=samples,traffic=dict(bytes=600000,latencies_ns=[100]*100,
                monitor_misses=0,unexpected_restarts=0,oom_events=0),runtime_evidence=None)
    enrich_review(run)
    return run


class NativeParsing(unittest.TestCase):
    # Dropping any unit/duplicate/range check must break these fixtures.
    def need(self, name):
        self.assertTrue(hasattr(a, name), 'missing strict parser: '+name)
        return getattr(a, name)

    def test_smaps_units_duplicates_uss_and_bounds(self):
        parse = self.need('parse_smaps_rollup')
        raw = '00400000-00401000 ---p 00000000 00:00 0 [rollup]\nRss: 12 kB\nPss: 10 kB\nPrivate_Clean: 2 kB\nPrivate_Dirty: 3 kB\n'
        self.assertEqual(parse(raw), dict(rss_bytes=12288,pss_bytes=10240,uss_bytes=5120))
        for bad in (raw+'Pss: 1 kB\n',raw.replace('10 kB','10 MB'),raw.replace('10 kB','-1 kB'),
                    raw.replace('10 kB',str(2**64)+' kB'),raw.replace('10 kB','nan kB'),
                    raw.replace('Pss: 10 kB\n',''),raw+'Odd: 1 kB\n',raw.replace('10 kB','13 kB')):
            with self.subTest(bad=bad), self.assertRaises(ValueError): parse(bad)

    def test_stat_statusthreads_fds_wakeups_and_wrap(self):
        parse = self.need('parse_proc_stat')
        fields = ['S']+['0']*49
        fields[11:13] = ['10','20']; fields[17]='2'; fields[19]='123'
        raw = '42 (a name ) with parens) '+' '.join(fields)
        self.assertEqual(parse(raw), dict(pid=42,start_ticks=123,utime_ticks=10,stime_ticks=20,threads=2))
        for bad in (raw.replace('10 20','-1 20'),raw.replace('10 20',str(2**64)+' 20'),
                    raw.replace('10 20','nan 20'),raw.replace('42 (','0 ('),raw[:40]):
            with self.subTest(bad=bad), self.assertRaises(ValueError): parse(bad)
        with self.assertRaises(ValueError): parse(raw.replace('10 20',str(2**32)+' 20'),tick_bits=32)
        sched = self.need('parse_wakeups')
        self.assertEqual(sched('se.statistics.nr_wakeups : 17\n'),17)
        self.assertIsNone(sched('nr_switches : 99\n'))
        for raw in ('se.statistics.nr_wakeups : 1\nse.statistics.nr_wakeups : 2\n', 'se.statistics.nr_wakeups : -1\n'):
            with self.assertRaises(ValueError): sched(raw)
        self.assertEqual(self.need('parse_fd_entries')(['0','1','2']),3)
        for names in (['0','0'], ['-1'], ['01'], ['1']*65537):
            with self.assertRaises(ValueError): a.parse_fd_entries(names)

    def test_cgroup_duplicate_units_overflow_and_io(self):
        parse = self.need('parse_cgroup')
        good = dict(cpu_stat='usage_usec 10\nuser_usec 6\nsystem_usec 4\n',memory_current='4096\n',
                    memory_stat='anon 1024\nfile 1024\nkernel 1024\nsock 0\n',
                    memory_events='oom 0\noom_kill 0\n',cgroup_procs='1\n2\n',io_stat='8:0 rbytes=1 wbytes=2 rios=3 wios=4 dbytes=0 dios=0\n')
        got = parse(**good)
        self.assertEqual(got['io']['8:0']['wbytes'],2)
        self.assertEqual(got['memory_current_bytes'],4096)
        for key,bad in [('cpu_stat',good['cpu_stat']+'usage_usec 1\n'),('memory_current','1 kB'),
                        ('memory_stat','anon 1\n'),('memory_events','oom 0\noom_kill -1'),
                        ('memory_current',str(2**64)),('io_stat',good['io_stat']*2),
                        ('io_stat','8:0 rbytes=1 rbytes=2'),('cpu_stat','usage_usec 1\n'),('cgroup_procs','1\n1\n'),('cgroup_procs','0\n')]:
            with self.subTest(key=key,bad=bad), self.assertRaises(ValueError): parse(**(good|{key:bad}))


class Statistics(unittest.TestCase):
    # Changing nearest-rank to interpolation or hiding outliers must fail.
    def test_exact_small_n_and_distribution_free_ci(self):
        self.assertTrue(hasattr(a,'describe'),'missing statistics engine')
        one=a.describe([4]); self.assertEqual((one['median'],one['p95'],one['p99'],one['mad']),(4,4,4,0))
        self.assertIsNone(one['median_ci95'])
        d=a.describe(list(range(1,21)))
        self.assertEqual((d['median'],d['p95'],d['p99'],d['mad']),(10.5,19,20,5))
        self.assertEqual(d['median_ci95'],[6,15])
        self.assertEqual(a.describe([1]*5+[100])['outliers'],[100])
        self.assertEqual(a.describe([1,2,3,4,5])['median_ci95'],None)
        self.assertEqual(a.describe([1,2,3,4,5,6])['median_ci95'],[1,6])
        for bad in ([],[float('nan')],[float('inf')],[-1],[True],[1]*100001):
            with self.subTest(bad=str(bad)[:30]), self.assertRaises(ValueError): a.describe(bad)


class Accounting(unittest.TestCase):
    def summarize(self, run=None):
        self.assertTrue(hasattr(a,'summarize'),'missing accounting engine')
        return a.summarize(fixture() if run is None else run)

    def test_disjoint_totals_observer_and_kernel_not_double_counted(self):
        run=fixture(); before=copy.deepcopy(run); s=self.summarize(run)
        self.assertEqual(run,before)
        self.assertEqual(s['metrics']['total_memory_bytes'],60*MIB)
        self.assertEqual(s['metrics']['control_pss_bytes'],8*MIB)
        self.assertEqual(s['metrics']['supervision_cpu'],Fraction(2,5))
        self.assertEqual(s['metrics']['service_cpu'],Fraction(21,50))
        self.assertEqual(s['observer']['peak_memory_bytes'],20*MIB)
        self.assertEqual(s['host_context']['softirq_ticks'],0)
        self.assertIn('synthetic_evidence',s['reasons'])
        self.assertNotIn('incomplete_accounting',s['reasons'])

    def test_unknown_missing_overlap_mixed_and_identity_change_cannot_pass(self):
        mutations=[('governor_unavailable',lambda r:r['host'].update(governor='unknown')),
                   ('missing_environment_metric',lambda r:r['samples'][1]['host'].update(temperature_millic=None)),
                   ('mixed_service_observer_or_workload',lambda r:r['domains'][1]['components'].append('workload')),
                   ('incomplete_component_coverage',lambda r:r['domains'][0]['components'].remove('workers')),
                   ('missing_metric',lambda r:r['samples'][0]['processes'][0].update(wakeups=None)),
                   ('overlapping_domains',lambda r:r['domains'][1].update(scope=['suite','control','child'])),
                   ('incomplete_accounting',lambda r:r['accounting'].update(complete=False)),
                   ('kernel_networking_unavailable',lambda r:r['accounting'].update(kernel_networking='unavailable')),
                   ('outside_overhead_unavailable',lambda r:r['accounting'].update(outside_overhead='unavailable')),
                   ('mixed_control_cpu',lambda r:r['domains'][0]['components'].append('tailscaled')),
                   ('process_inventory_changed',lambda r:r['samples'][-1]['processes'][0].update(start_ticks=2))]
        for reason, mutate in mutations:
            with self.subTest(reason=reason):
                run=fixture();mutate(run);s=self.summarize(run)
                self.assertIn(reason,s['reasons'])
                self.assertEqual(s['status'],'INSUFFICIENT_DATA')

    def test_clocks_gaps_resets_thermal_and_swap_never_interpolated(self):
        cases=[('sampling_gap',lambda r:r['samples'].pop(300)),
               ('nonmonotonic_time',lambda r:r['samples'][1].update(mono_ns=r['samples'][0]['mono_ns'],read_end_ns=r['samples'][0]['read_end_ns'])),
               ('clock_discontinuity',lambda r:r['samples'][300].update(wall_before_ns=1,wall_after_ns=2)),
               ('counter_regression',lambda r:r['samples'][300]['domains']['control']['cpu'].update(usage_usec=0,user_usec=0)),
               ('counter_regression',lambda r:r['samples'][300]['processes'][0].update(utime_ticks=0)),
               ('counter_regression',lambda r:r['samples'][300]['host'].update(softirq_ticks=1)),
               ('thermal_contamination',lambda r:r['samples'][10]['host'].update(temperature_millic=90000)),
               ('thermal_contamination',lambda r:r['samples'][10]['host'].update(thermal_throttle_count=1)),
               ('swap_contamination',lambda r:r['samples'][10]['host'].update(swap_used_bytes=1)),
               ('short_run',lambda r:(r['samples'].pop(),r.update(duration_ns=599*10**9))),
               ('warmup_boundary_missing',lambda r:r.update(warmup_discard_ns=1)),
               ('unsupported_tick_width',lambda r:r['host'].update(tick_bits=32))]
        for reason,mutate in cases:
            with self.subTest(reason=reason):
                run=fixture(); mutate(run);self.assertIn(reason,self.summarize(run)['reasons'])
        for bad in (float('nan'),float('inf'),-1,True):
            run=fixture();run['samples'][1]['mono_ns']=bad
            with self.subTest(bad=bad): self.assertEqual(self.summarize(run)['status'],'INSUFFICIENT_DATA')

    def test_warmup_discard_is_explicit_and_not_counted_in_600_seconds(self):
        run=fixture();run['warmup_discard_ns']=30*10**9
        s=self.summarize(run);self.assertIn('short_run',s['reasons']);self.assertEqual(s['measured_duration_ns'],570*10**9)


class Completeness(unittest.TestCase):
    def summarize(self,run):
        self.assertTrue(hasattr(a,'summarize'),'missing accounting engine')
        return a.summarize(run)

    def test_omitted_cgroup_member_cannot_reduce_pss(self):
        run=fixture();run['samples'][10]['domains']['control']['member_pids'].append(12345)
        result=self.summarize(run)
        self.assertIn('incomplete_process_coverage',result['reasons'])
        self.assertIsNone(result['metrics']['control_pss_bytes'])
        run=fixture();run['samples'][10]['processes'].pop()
        self.assertIn('incomplete_process_coverage',self.summarize(run)['reasons'])

    def test_process_tick_wakeup_memory_and_fd_overhead_is_reported(self):
        result=self.summarize(fixture())
        self.assertIn('processes',result,'missing per-process overhead diagnostics')
        p=result['processes'][0]
        self.assertEqual(p['cpu_delta_ticks'],24000)
        self.assertEqual(p['wakeups_delta'],600)
        self.assertEqual((p['peak_pss_bytes'],p['peak_rss_bytes'],p['peak_uss_bytes']),(8*MIB,10*MIB,4*MIB))
        self.assertEqual((p['peak_threads'],p['peak_fds']),(1,3))

    def test_oom_during_discarded_warmup_is_not_discarded(self):
        run=fixture();run['warmup_discard_ns']=30*10**9
        for sample in run['samples'][10:]:sample['domains']['control']['memory_events']['oom_kill']=1
        result=self.summarize(run)
        self.assertEqual(result['metrics']['oom_events'],1)

    def test_recursive_missing_extra_wrong_types_nonfinite_are_never_accepted(self):
        good=fixture()
        locations=[(),('binding',),('host',),('accounting',),('domains',0),('samples',0),
                   ('samples',0,'domains','control'),('samples',0,'processes',0),('samples',0,'host'),('traffic',)]
        for location in locations:
            obj=good
            for key in location:obj=obj[key]
            for key in obj:
                run=copy.deepcopy(good);target=run
                for segment in location:target=target[segment]
                del target[key]
                with self.subTest(location=location,key=key):self.assertEqual(self.summarize(run)['status'],'INSUFFICIENT_DATA')
            run=copy.deepcopy(good);target=run
            for segment in location:target=target[segment]
            target['unknown']=None
            with self.subTest(location=location):self.assertEqual(self.summarize(run)['status'],'INSUFFICIENT_DATA')
        for key in ('pss_bytes','rss_bytes','uss_bytes','utime_ticks','stime_ticks','wakeups','threads','fds'):
            for bad in (-1,2**64,float('nan'),float('inf'),True):
                run=fixture();run['samples'][10]['processes'][0][key]=bad
                with self.subTest(key=key,bad=bad):self.assertEqual(self.summarize(run)['status'],'INSUFFICIENT_DATA')

    def test_unknown_or_mutated_runtime_proof_is_not_a_monitor_pass(self):
        run=fixture();run.update(evidence_origin='actual_runtime',purpose='runtime_measurement')
        for proof in (None,{}, {'schema':2,'monitoring':{'deadline_misses':0}}):
            run['runtime_evidence']=proof
            result=self.summarize(run)
            self.assertEqual(result['status'],'INSUFFICIENT_DATA')
            self.assertIn('missing_runtime_evidence' if proof is None else 'invalid_runtime_evidence',result['reasons'])


class FinalStrictness(unittest.TestCase):
    def test_unknown_host_metadata_is_not_complete_evidence(self):
        for key in ('kernel','cpu_model','architecture'):
            for bad in ('unknown','unavailable','not_measured'):
                run=fixture();run['host'][key]=bad
                self.assertIn('host_metadata_unavailable',a.summarize(run)['reasons'])

    def test_aggregate_overflow_and_terminal_processes_are_refused(self):
        run=fixture()
        for sample in run['samples']:
            for domain in sample['domains'].values():domain['memory_current_bytes']=2**64-1
        self.assertEqual(a.summarize(run)['reasons'],['invalid_run'])
        run=fixture()
        for sample in run['samples']:
            for process in sample['processes']:process.update(pss_bytes=2**64-1,rss_bytes=2**64-1,uss_bytes=0)
        self.assertEqual(a.summarize(run)['reasons'],['invalid_run'])
        fields=['S']+['0']*49;fields[11:13]=['10','20'];fields[17]='2';fields[19]='123'
        for state in ('Z','X','x','T','t'):
            fields[0]=state
            with self.subTest(state=state),self.assertRaises(ValueError):a.parse_proc_stat('42 (fixture) '+' '.join(fields))
        raw='00401000-00400000 ---p 00000000 00:00 0 [rollup]\nRss: 12 kB\nPss: 10 kB\nPrivate_Clean: 2 kB\nPrivate_Dirty: 3 kB\n'
        with self.assertRaises(ValueError):a.parse_smaps_rollup(raw)


class RuntimeIntegration(unittest.TestCase):
    @staticmethod
    def bound_fixture(implementation='rust',rep=1):
        # Reuse established source-specific fake clocks/receipts, never export.
        spec=importlib.util.spec_from_file_location('_old_fixtures',ROOT/'test_measurement.py')
        old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
        run=fixture(implementation,rep)
        run.update(evidence_origin='actual_runtime',purpose='runtime_measurement')
        run['traffic'].update(bytes=60000,latencies_ns=list(range(2,22)))
        view=dict(binding=run['binding'],input_sha256=a.record_digest(run),
                  original_window_boottime_ns=[run['samples'][0]['mono_ns'],run['samples'][-1]['mono_ns']])
        run['runtime_evidence']=(old.traffic_fixture if implementation=='rust' else old.legacy_fixture)(view)
        run['runtime_evidence']['throughput_bytes_per_second']=100
        return run

    def test_both_original_monitor_contracts_integrate_and_mutation_is_insufficient(self):
        for implementation in ('rust','python'):
            run=self.bound_fixture(implementation)
            self.assertEqual(a.summarize(run)['status'],'PASS')
            for key in ('binding','record_sha256','window_boottime_ns','provenance','monitoring','latency_ns','throughput_intervals'):
                changed=copy.deepcopy(run);del changed['runtime_evidence'][key]
                with self.subTest(implementation=implementation,key=key):
                    self.assertIn('invalid_runtime_evidence',a.summarize(changed)['reasons'])
        run=self.bound_fixture();run['traffic']['monitor_misses']=1
        run['runtime_evidence']['record_sha256']=a.record_digest(run)
        self.assertIn('invalid_runtime_evidence',a.summarize(run)['reasons'])

    def test_complete_shape_can_pass_but_incomplete_suite_cannot(self):
        b=[self.bound_fixture('python',rep) for rep in range(1,7)]
        c=[self.bound_fixture('rust',rep) for rep in range(1,7)]
        result=a.compare(b,c)
        self.assertEqual(result['scenarios'][0]['status'],'PASS')
        self.assertEqual(result['status'],'INSUFFICIENT_DATA')
        # A genuine, complete observed failure is FAIL, not discarded as noise.
        c[0]['traffic']['latencies_ns']=[22]*20
        proof=c[0]['runtime_evidence'];proof['record_sha256']=a.record_digest(c[0])
        proof['latency_ns'].update(values_ns=[22]*20,p95=22)
        result=a.compare(b,c)
        self.assertEqual(result['scenarios'][0]['status'],'FAIL')
        self.assertEqual(result['status'],'INSUFFICIENT_DATA')


class Thresholds(unittest.TestCase):
    # Exact rational comparisons must catch rounding and each weakened inequality.
    def test_every_gate_at_inside_outside_and_unknown(self):
        self.assertTrue(hasattr(a,'evaluate_metrics'),'missing comparator gates')
        base=dict(supervision_cpu=100,total_memory_bytes=1000,control_pss_bytes=1,
                  throughput=1000,p95_latency_ns=1000,monitor_misses=0,unexpected_restarts=0,oom_events=0)
        candidate=base|dict(supervision_cpu=50,throughput=950,p95_latency_ns=1050,control_pss_bytes=16*MIB)
        cases=[('supervision_cpu',50,49,51,'supervision_cpu'),('total_memory_bytes',1000,999,1001,'total_memory'),
               ('control_pss_bytes',16*MIB,16*MIB-1,16*MIB+1,'control_pss'),
               ('throughput',950,951,949,'throughput'),('p95_latency_ns',1050,1049,1051,'p95_latency')]
        for field,at,inside,outside,gate in cases:
            for value,want in [(at,'PASS'),(inside,'PASS'),(outside,'FAIL'),(None,'INSUFFICIENT_DATA')]:
                with self.subTest(field=field,value=value):
                    got=a.evaluate_metrics(base,candidate|{field:value},1)
                    self.assertEqual(got['gates'][gate],want)
        for count,target in [(1,16*MIB),(5,48*MIB)]:
            for delta,want in [(-1,'PASS'),(0,'PASS'),(1,'FAIL')]:
                self.assertEqual(a.evaluate_metrics(base,candidate|dict(control_pss_bytes=target+delta),count)['gates']['control_pss'],want)
        self.assertNotIn('control_pss',a.evaluate_metrics(base,candidate,6)['gates'])
        for field in ('monitor_misses','unexpected_restarts','oom_events'):
            for side in ('baseline','candidate'):
                b,c=base.copy(),candidate.copy();(b if side=='baseline' else c)[field]=1
                self.assertEqual(a.evaluate_metrics(b,c,1)['status'],'FAIL')
        for field in ('supervision_cpu','total_memory_bytes','throughput','p95_latency_ns'):
            for bad in (0,1e-100,float('nan'),float('inf'),-1,True):
                self.assertEqual(a.evaluate_metrics(base|{field:bad},candidate,1)['status'],'INSUFFICIENT_DATA')
        self.assertEqual(a.evaluate_metrics(base,candidate,1)['status'],'PASS')


class AdditionalGates(unittest.TestCase):
    def test_every_missing_gate_and_tiny_denom_reason(self):
        b=dict(supervision_cpu=100,total_memory_bytes=1000,control_pss_bytes=1,throughput=1000,
               p95_latency_ns=1000,monitor_misses=0,unexpected_restarts=0,oom_events=0)
        c=b|dict(supervision_cpu=40,control_pss_bytes=16*MIB)
        for field in b:
            changed=c.copy();changed.pop(field)
            result=a.evaluate_metrics(b,changed,1)
            with self.subTest(field=field):
                self.assertEqual(result['status'],'INSUFFICIENT_DATA')
                self.assertTrue(result['reasons'])
        for bad in (None,-1,True,float('nan'),float('inf')):
            for field in b:
                result=a.evaluate_metrics(b,c|{field:bad},1)
                with self.subTest(field=field,bad=bad):self.assertEqual(result['status'],'INSUFFICIENT_DATA')
        self.assertEqual(a.evaluate_metrics(b|dict(supervision_cpu=Fraction(1,10**6)),c|dict(supervision_cpu=Fraction(1,2*10**6)),1)['gates']['supervision_cpu'],'PASS')
        self.assertEqual(a.evaluate_metrics(b|dict(supervision_cpu=Fraction(999,10**9)),c|dict(supervision_cpu=0),1)['gates']['supervision_cpu'],'INSUFFICIENT_DATA')
        # Decimal inputs on ratio boundaries must not flip through float rounding.
        self.assertEqual(a.evaluate_metrics(b|dict(throughput=1),c|dict(throughput=Fraction(19,20)),1)['gates']['throughput'],'PASS')
        self.assertEqual(a.evaluate_metrics(b|dict(p95_latency_ns=100),c|dict(p95_latency_ns=105),1)['gates']['p95_latency'],'PASS')


class SuiteComparison(unittest.TestCase):
    def compare(self, baseline, candidate):
        self.assertTrue(hasattr(a,'compare'),'missing suite comparator')
        return a.compare(baseline,candidate)

    def test_synthetic_suite_reports_gates_but_never_performance_pass(self):
        baseline=[fixture('python',rep) for rep in range(1,7)]
        candidate=[fixture('rust',rep) for rep in range(1,7)]
        report=self.compare(baseline,candidate)
        self.assertEqual(report['status'],'INSUFFICIENT_DATA')
        row=report['scenarios'][0]
        self.assertEqual(row['gates']['supervision_cpu'],'PASS')
        self.assertEqual(row['statistics']['supervision_cpu']['baseline']['samples'],6)
        self.assertIn('synthetic_evidence',row['reasons'])
        self.assertEqual(report,self.compare(list(reversed(baseline)),list(reversed(candidate))))
        self.assertFalse(report['release_ready'])

    def test_each_suite_insufficiency_is_exposed(self):
        baseline=[fixture('python',rep) for rep in range(1,7)]
        candidate=[fixture('rust',rep) for rep in range(1,7)]
        cases=[('too_few_repetitions',lambda b,c:c.pop()),
               ('unmatched_repetitions',lambda b,c:c[0]['binding'].update(repetition=7)),
               ('duplicate_repetition',lambda b,c:c[0]['binding'].update(repetition=2)),
               ('instrumentation_mismatch',lambda b,c:c[0].update(instrumentation_sha256='b'*64)),
               ('mixed_host',lambda b,c:c[0]['binding'].update(host_id_sha256='b'*64)),
               ('host_contract_mismatch',lambda b,c:c[0]['host'].update(governor='powersave')),
               ('tailscale_mismatch',lambda b,c:c[0]['binding'].update(tailscale_version='1.2.3')),
               ('wrong_implementation',lambda b,c:c[0]['binding'].update(implementation='python')),
               ('duplicate_run_id',lambda b,c:c[0]['binding'].update(run_id=b[0]['binding']['run_id'])),
               ('accounting_mismatch',lambda b,c:c[0]['accounting'].update(review_sha256='b'*64)),
               ('domain_coverage_mismatch',lambda b,c:c[0]['domains'][0]['components'].append('tailscaled')),
               ('workload_mismatch',lambda b,c:c[0]['binding'].update(workload_sha256='b'*64)),
               ('source_or_artifact_mismatch',lambda b,c:c[0]['binding'].update(artifact_sha256='b'*64)),
               ('overlapping_runs',lambda b,c:c.__setitem__(0,copy.deepcopy(b[0]))),
               ('duplicate_record',lambda b,c:c.append(copy.deepcopy(c[0]))),
               ('sampling_contract_mismatch',lambda b,c:c[0].update(warmup_discard_ns=10**9)),
               ('invalid_run',lambda b,c:c[0].update(unknown=1))]
        for reason,mutate in cases:
            with self.subTest(reason=reason):
                b,c=copy.deepcopy(baseline),copy.deepcopy(candidate);mutate(b,c)
                result=self.compare(b,c)
                self.assertEqual(result['status'],'INSUFFICIENT_DATA')
                self.assertIn(reason,result['reasons']+result['scenarios'][0]['reasons'])
        for b,c in [([],[]),(None,[]),([{}],[]),([fixture()]*129,[])]:
            self.assertEqual(self.compare(b,c)['status'],'INSUFFICIENT_DATA')

    def test_failed_repetition_and_missing_data_are_both_visible(self):
        b=[fixture('python',rep) for rep in range(1,7)]
        c=[fixture('rust',rep) for rep in range(1,7)]
        c[0]['traffic']['latencies_ns']=[106]*100
        row=self.compare(b,c)['scenarios'][0]
        self.assertEqual(row['gates']['p95_latency'],'FAIL')
        self.assertEqual(row['status'],'INSUFFICIENT_DATA')
        self.assertIn('missing_runtime_evidence',row['reasons'])



# Review-round regressions use raw records and the original monitoring adapters.
# All receipts are constructed in memory; this is never runtime evidence.
def review_record(kind='rust', rep=1):
    run=RuntimeIntegration.bound_fixture(kind,rep)
    run['samples']=run['samples'][::10]
    run['interval_ns']=10**10
    for sample in run['samples']:
        sample['read_end_ns']=sample['mono_ns']
        sample['wall_after_ns']=sample['wall_before_ns']
    rebind_review(run)
    return run


def rebind_review(run):
    proof=run['runtime_evidence']
    proof['record_sha256']=a.record_digest(run)
    proof['throughput_intervals'][0]['bytes']=run['traffic']['bytes']
    value=Fraction(run['traffic']['bytes'],600)
    proof['throughput_bytes_per_second']=dict(numerator=value.numerator,denominator=value.denominator)
    proof['latency_ns'].update(values_ns=run['traffic']['latencies_ns'],p95=a.percentile(run['traffic']['latencies_ns'],95))


class ReviewRoundTwo(unittest.TestCase):
    def test_boot_clock_bounds_stable_start_and_cumulative_cpu(self):
        for kind in ('future_start','process_cpu','host_cpu','domain_cpu'):
            run=reconciled_record();self.assertEqual(a.summarize(run)['status'],'PASS')
            for s in run['samples']:
                if kind=='future_start':s['processes'][0]['start_ticks']=2**60
                elif kind=='process_cpu':s['processes'][0]['utime_ticks']+=2**60
                elif kind=='host_cpu':
                    s['host']['busy_ticks']+=2**60;s['host']['user_ticks']+=2**60
                else:
                    s['domains']['control']['cpu']['usage_usec']+=2**60
                    s['domains']['control']['cpu']['user_usec']+=2**60
            rebind_review(run)
            with self.subTest(kind=kind):self.assertEqual(a.summarize(run)['status'],'INSUFFICIENT_DATA')

    def test_RI1_endpoint_allowance_cannot_accumulate(self):
        run=RuntimeIntegration.bound_fixture()
        for i,s in enumerate(run['samples']):
            s['read_end_ns']=s['mono_ns']
            s['wall_after_ns']=s['wall_before_ns']
            d=s['domains']['control'];d['cpu'].update(usage_usec=0,user_usec=0)
            s['processes'][0]['utime_ticks']=i
            # Remove only control CPU from host; other domains remain valid.
            s['host']['busy_ticks']=i*4
        rebind_review(run)
        got=a.summarize(run)
        self.assertEqual(got['status'],'INSUFFICIENT_DATA')
        self.assertIn('cpu_accounting_contradiction',got['reasons'])

    def test_RI2_irq_and_softirq_are_busy_subsets(self):
        for field in ('irq_ticks','softirq_ticks'):
            run=reconciled_record()
            self.assertEqual(a.summarize(run)['status'],'PASS')
            for i,s in enumerate(run['samples']):s['host'][field]=i*1000
            rebind_review(run)
            got=a.summarize(run)
            with self.subTest(field=field):
                self.assertEqual(got['status'],'INSUFFICIENT_DATA')
                self.assertIn('cpu_subset_contradiction',got['reasons'])

    def test_RI3_pss_subset_cannot_exceed_physical_RAM(self):
        run=reconciled_record()
        self.assertEqual(a.summarize(run)['status'],'PASS')
        for s in run['samples']:
            for p in s['processes']:
                if p['component'] in ('container','tailscaled'):
                    p.update(pss_bytes=600*MIB,rss_bytes=600*MIB)
        rebind_review(run)
        got=a.summarize(run)
        self.assertEqual(got['status'],'INSUFFICIENT_DATA')
        self.assertIn('system_memory_contradiction',got['reasons'])


class ReviewRoundOne(unittest.TestCase):
    def test_I1_raw_rate_boundaries_and_large_one_byte_shortfall(self):
        for byte_b,byte_c,want in [(60080,57076,'PASS'),
                (18000000000000000000,17099999999999999999,'FAIL')]:
            b=[review_record('python',i) for i in range(1,7)]
            c=[review_record('rust',i) for i in range(1,7)]
            for group,count in [(b,byte_b),(c,byte_c)]:
                for run in group:run['traffic']['bytes']=count;rebind_review(run)
            with self.subTest(bytes=(byte_b,byte_c)):
                self.assertEqual(a.compare(b,c)['scenarios'][0]['gates']['throughput'],want)
        b=[review_record('python',i) for i in range(1,7)]
        c=[review_record('rust',i) for i in range(1,7)]
        for group,total in [(b,200000000),(c,100000000)]:
            for run in group:
                for i,s in enumerate(run['samples']):
                    s['domains']['control']['cpu'].update(usage_usec=i*total//60,user_usec=i*total//60)
                enrich_review(run)
                rebind_review(run)
        self.assertEqual(a.compare(b,c)['scenarios'][0]['gates']['supervision_cpu'],'PASS')

    def test_I2_observer_and_workload_oom_retained_over_whole_run(self):
        for domain in ('observer','workload'):
            for event in ('oom','oom_kill'):
                run=review_record()
                run['warmup_discard_ns']=10**10
                for s in run['samples'][1:]:s['domains'][domain]['memory_events'][event]=1
                rebind_review(run)
                with self.subTest(domain=domain,event=event):
                    self.assertEqual(a.summarize(run)['metrics']['oom_events'],1)

    def test_I3_stable_member_ticks_cannot_contradict_zero_cgroup_cpu(self):
        run=review_record()
        for i,s in enumerate(run['samples']):
            s['processes'][0]['utime_ticks']=i*400
            s['domains']['control']['cpu'].update(usage_usec=0,user_usec=0)
        rebind_review(run)
        self.assertEqual(a.summarize(run)['status'],'INSUFFICIENT_DATA')

    def test_M1_malformed_legacy_nested_item_is_redacted(self):
        run=review_record('python')
        run['runtime_evidence']['monitoring']['router_cycles']=[None]
        self.assertEqual(a.summarize(run)['status'],'INSUFFICIENT_DATA')

    def test_M2_exact_large_integer_median_MAD_and_outliers(self):
        from fractions import Fraction
        for n in (1,6):
            for big in (2**53+1,2**63,2**64-1):
                with self.subTest(n=n,big=big):
                    stats=a.describe([big]*n)
                    self.assertEqual(stats['median'],big)
                    self.assertEqual(stats['mad'],0)
                    self.assertEqual(stats['outliers'],[])
        for big in (2**53+1,2**63):
            stats=a.describe([big,big+1])
            self.assertEqual(stats['median'],Fraction(2*big+1,2))
            self.assertEqual(stats['mad'],Fraction(1,2))
            self.assertEqual(stats['outliers'],[])
            self.assertEqual(a.describe([big]*5+[big+1])['outliers'],[big+1])


def reconciled_record(kind='rust',rep=1):
    """Future producer contract: aligned residuals, explicit all-domain failures."""
    run=review_record(kind,rep)
    enrich_review(run)
    rebind_review(run)
    return run


def enrich_review(run):
    run['host']['cpu_clock_contract']='constant_online_no_suspend'
    for key,value in dict(link_capacity_bps=10**9,max_fd_entries=1048576,pid_max=4194304).items():
        run['host'].setdefault(key,value)
    run['failure_domains']={name:dict(memory_oom_kills=0,kernel_oom_kills=0,
        unexpected_restarts=0,monitor_misses=0,missing_samples=0)
        for name in sorted(a.COMPONENTS|{'kernel'})}
    for s in run['samples']:
        busy=0
        for name,d in s['domains'].items():
            members=[p for p in s['processes'] if p['domain']==name]
            for p in members:
                p['utime_ticks']=0;p['stime_ticks']=0;p['io']={}
                p.update(swap_bytes=0,swap_pss_bytes=0)
            members[0]['utime_ticks']=d['cpu']['usage_usec']*run['host']['tick_hz']//10**6
            d.update(pids_current=sum(p['threads'] for p in members),cpu_exited_usec=0,
                     cpu_exited_user_usec=0,cpu_exited_system_usec=0,swap_current_bytes=0,
                     memory_other_bytes=d['memory_current_bytes']-sum(p['uss_bytes'] for p in members),
                     memory_stat_other_bytes=d['memory_current_bytes']-sum(d['memory_stat'][k] for k in ('anon','file','kernel')),io_other={})
            busy+=d['cpu']['usage_usec']
        ticks=busy*run['host']['tick_hz']//10**6
        elapsed=s['mono_ns']-run['samples'][0]['mono_ns']
        s['host'].update(busy_ticks=ticks,user_ticks=ticks,system_ticks=0,irq_ticks=0,softirq_ticks=0,
            steal_ticks=0,idle_ticks=elapsed*run['host']['logical_cpus']*run['host']['tick_hz']//10**9-ticks,
            network_rx_bytes=elapsed//10**6,network_tx_bytes=elapsed//10**6,other_cpu_usec=0)


class ReviewClassClosure(unittest.TestCase):
    def test_exact_units_and_all_WP11_threshold_boundary_sweep(self):
        from fractions import Fraction as F
        # Unit conversions are rate = counter * exact unit / duration_ns.
        self.assertTrue(hasattr(a,'rate'),'missing exact unit conversion')
        for n in (1,2**53+1,2**63,2**64-1):
            self.assertEqual(a.rate(n,600*10**9,'cpu_usec'),F(n,600*10**6))
            self.assertEqual(a.rate(n,600*10**9,'bytes'),F(n,600))
            self.assertEqual(a.rate(n,600*10**9,'ticks',100),F(n,60000))
        for n in (-1,2**64,True):
            with self.assertRaises(ValueError):a.rate(n,10**9,'bytes')
        base=dict(supervision_cpu=100,total_memory_bytes=1000,control_pss_bytes=1,
            throughput=1000,p95_latency_ns=1000,monitor_misses=0,unexpected_restarts=0,oom_events=0)
        good=base|dict(supervision_cpu=50,throughput=950,p95_latency_ns=1050)
        cases=0
        for magnitude in (1000,2**53+1,2**63,2**64):
            # Scale to represent each ratio exactly even when baseline is odd.
            for field,gate,ratio,direction in [('supervision_cpu','supervision_cpu',F(1,2),'le'),
                    ('total_memory_bytes','total_memory',F(1),'le'),
                    ('throughput','throughput',F(19,20),'ge'),
                    ('p95_latency_ns','p95_latency',F(21,20),'le')]:
                for delta in (-1,0,1):
                    b=base|{field:magnitude}
                    c=good|{field:F(magnitude)*ratio+delta}
                    want=('INSUFFICIENT_DATA' if magnitude>=2**64 or c[field]>2**64-1 else
                        'PASS' if (delta<=0 if direction=='le' else delta>=0) else 'FAIL')
                    with self.subTest(field=field,magnitude=magnitude,delta=delta):
                        self.assertEqual(a.evaluate_metrics(b,c,1)['gates'][gate],want)
                    cases+=1
            for count,target in [(1,16*MIB),(5,48*MIB)]:
                for value in (target-1,target,target+1,magnitude):
                    want='INSUFFICIENT_DATA' if value>=2**64 else 'PASS' if value<=target else 'FAIL'
                    self.assertEqual(a.evaluate_metrics(base,good|dict(control_pss_bytes=value),count)['gates']['control_pss'],want)
                    cases+=1
            for field in ('monitor_misses','unexpected_restarts','oom_events'):
                for value in (-1,0,1,magnitude):
                    for side in ('b','c'):
                        b,c=base.copy(),good.copy();(b if side=='b' else c)[field]=value
                        want='INSUFFICIENT_DATA' if value<0 or value>=2**64 else 'PASS' if value==0 else 'FAIL'
                        self.assertEqual(a.evaluate_metrics(b,c,1)['gates'][field],want);cases+=1
        self.assertEqual(cases,176)

    def test_every_failure_domain_cross_every_signal_and_missing_evidence(self):
        seed=reconciled_record()
        self.assertEqual(a.summarize(seed)['status'],'PASS','positive control must qualify')
        for name in sorted(seed['failure_domains']):
            for signal in seed['failure_domains'][name]:
                for value in (1,None):
                    run=copy.deepcopy(seed);run['failure_domains'][name][signal]=value;rebind_review(run)
                    with self.subTest(domain=name,signal=signal,value=value):
                        self.assertEqual(a.summarize(run)['status'],'INSUFFICIENT_DATA')
                run=copy.deepcopy(seed);del run['failure_domains'][name][signal];rebind_review(run)
                self.assertEqual(a.summarize(run)['status'],'INSUFFICIENT_DATA')
            run=copy.deepcopy(seed);del run['failure_domains'][name];rebind_review(run)
            self.assertEqual(a.summarize(run)['status'],'INSUFFICIENT_DATA')
        for domain in seed['samples'][0]['domains']:
            for signal in ('oom','oom_kill','oom_group_kill'):
                for warmup in (0,10**10):
                    run=copy.deepcopy(seed);run['warmup_discard_ns']=warmup
                    for i,s in enumerate(run['samples']):s['domains'][domain]['memory_events'][signal]=int(i>0)
                    rebind_review(run)
                    result=a.summarize(run)
                    with self.subTest(domain=domain,signal=signal,warmup=warmup):
                        self.assertEqual(result['metrics']['oom_events'],1)
                        self.assertNotEqual(result['status'],'PASS')
            run=copy.deepcopy(seed);del run['samples'][1]['domains'][domain];rebind_review(run)
            self.assertEqual(a.summarize(run)['status'],'INSUFFICIENT_DATA')

    def test_redundant_accounting_pairs_reject_both_directions(self):
        seed=reconciled_record()
        self.assertEqual(a.summarize(seed)['status'],'PASS','positive control must qualify')
        changes=[('cpu_ticks_low',lambda r:r['samples'][-1]['processes'][0].update(utime_ticks=1)),
            ('cpu_ticks_high',lambda r:r['samples'][-1]['processes'][0].update(utime_ticks=60000)),
            ('cgroup_cpu_low',lambda r:r['samples'][-1]['domains']['control']['cpu'].update(usage_usec=0,user_usec=0)),
            ('cgroup_cpu_high',lambda r:r['samples'][-1]['domains']['control']['cpu'].update(usage_usec=10**12,user_usec=10**12)),
            ('memory_low',lambda r:r['samples'][-1]['domains']['control'].update(memory_current_bytes=1)),
            ('memory_high',lambda r:r['samples'][-1]['domains']['control'].update(memory_current_bytes=100*MIB)),
            ('pids_low',lambda r:r['samples'][-1]['domains']['control'].update(pids_current=0)),
            ('pids_high',lambda r:r['samples'][-1]['domains']['control'].update(pids_current=2)),
            ('system_cpu_low',lambda r:r['samples'][-1]['host'].update(busy_ticks=1)),
            ('system_cpu_high',lambda r:r['samples'][-1]['host'].update(busy_ticks=1000000)),
            ('system_memory_low',lambda r:r['host'].update(memory_total_bytes=MIB)),
            ('process_memory_high',lambda r:r['samples'][-1]['processes'][0].update(rss_bytes=2**63)),
            ('io_member_high',lambda r:r['samples'][-1]['processes'][0]['io'].update({'8:0':dict(rbytes=1,wbytes=0,rios=0,wios=0)})),
            ('io_cgroup_high',lambda r:r['samples'][-1]['domains']['control']['io'].update({'8:0':dict(rbytes=1,wbytes=0,rios=0,wios=0)}))]
        for name,change in changes:
            run=copy.deepcopy(seed);change(run);rebind_review(run)
            with self.subTest(pair=name):self.assertEqual(a.summarize(run)['status'],'INSUFFICIENT_DATA')
        # Quantization allowance: <=2 ticks per stable member at both reads.
        for extra,want in [(2,'PASS'),(3,'INSUFFICIENT_DATA')]:
            run=copy.deepcopy(seed);run['samples'][-1]['processes'][0]['utime_ticks']+=extra;rebind_review(run)
            self.assertEqual(a.summarize(run)['status'],want)


class ReviewAdditionalPairs(unittest.TestCase):
    def test_native_cpu_parts_and_memory_breakdown_both_directions(self):
        seed=reconciled_record()
        for field in ('user_usec','system_usec'):
            for delta in (-3,3):
                run=copy.deepcopy(seed)
                d=run['samples'][-1]['domains']['control']
                d['cpu']['system_usec']=100
                d['cpu']['user_usec']=d['cpu']['usage_usec']-100
                d['cpu'][field]+=delta;rebind_review(run)
                with self.subTest(field=field,delta=delta):
                    self.assertEqual(a.summarize(run)['status'],'INSUFFICIENT_DATA')
        for delta in (-1,1):
            run=copy.deepcopy(seed);run['samples'][-1]['domains']['control']['memory_stat']['anon']+=delta
            rebind_review(run)
            with self.subTest(memory_delta=delta):self.assertEqual(a.summarize(run)['status'],'INSUFFICIENT_DATA')

    def test_aligned_io_residuals_and_cpu_exited_work_are_not_invented(self):
        seed=reconciled_record()
        for i,s in enumerate(seed['samples']):
            p=s['processes'][0];d=s['domains']['control']
            p['io']={'8:0':dict(rbytes=i,wbytes=i*2,rios=i,wios=i)}
            d['io_other']={'8:0':dict(rbytes=i,wbytes=0,rios=i,wios=0)}
            d['io']={'8:0':dict(rbytes=2*i,wbytes=2*i,rios=2*i,wios=i)}
            d['cpu_exited_usec']=i*10000
            d['cpu_exited_user_usec']=i*10000
            d['cpu']['usage_usec']+=i*10000;d['cpu']['user_usec']+=i*10000
        # Reconcile whole-host ticks with the independently added exited work.
        for i,s in enumerate(seed['samples']):
            s['host']['other_cpu_usec']=0;s['host']['busy_ticks']+=i
            s['host']['user_ticks']+=i;s['host']['idle_ticks']-=i
        rebind_review(seed)
        self.assertEqual(a.summarize(seed)['status'],'PASS')
        for side in ('member','cgroup','other'):
            for delta in (-1,1):
                run=copy.deepcopy(seed);s=run['samples'][-1]
                target=(s['processes'][0]['io'] if side=='member' else s['domains']['control']['io' if side=='cgroup' else 'io_other'])
                target['8:0']['rbytes']+=delta;rebind_review(run)
                with self.subTest(side=side,delta=delta):self.assertEqual(a.summarize(run)['status'],'INSUFFICIENT_DATA')

    def test_all_raw_WP11_boundary_sweeps_before_gate_comparison(self):
        from fractions import Fraction as F
        count=0
        for magnitude in (60080,2**53+1,2**63,2**64):
            # Multiples give a reachable exact boundary on integer counter grids.
            bvalue=magnitude if magnitude==2**64 else magnitude//20*20
            for field,gate,ratio,direction in [('cpu','supervision_cpu',F(1,2),'le'),
                    ('memory','total_memory',F(1),'le'),('bytes','throughput',F(19,20),'ge'),
                    ('latency','p95_latency',F(21,20),'le')]:
                for delta in (-1,0,1):
                    b=reconciled_record('python');c=reconciled_record('rust')
                    def assign(run,value):
                        if field=='bytes':
                            run['traffic']['bytes']=value
                            run['host']['link_capacity_bps']=max(10**9,(value*8+599)//600+8)
                            for i,s in enumerate(run['samples']):
                                s['host']['network_rx_bytes']=i*value//60
                                s['host']['network_tx_bytes']=i*value//60
                        if field=='latency':run['traffic']['latencies_ns']=[value]*20
                        if field in ('cpu','memory'):
                            run['host']['logical_cpus']=max(4,(value+600*10**6-1)//(600*10**6)+1)
                            run['host']['memory_total_bytes']=2**64-1
                            for i,s in enumerate(run['samples']):
                                if field=='cpu':s['domains']['control']['cpu'].update(usage_usec=i*value//60,user_usec=i*value//60)
                                else:
                                    for name,d in s['domains'].items():
                                        d['memory_current_bytes']=value if name=='control' else 0
                                        d['memory_stat']=dict(anon=0,file=0,kernel=0,sock=0)
                                        for p in s['processes']:
                                            if p['domain']==name:p.update(uss_bytes=0,pss_bytes=0,rss_bytes=0)
                            # Recompute independent sources in the synthetic producer.
                            enrich_review(run)
                        rebind_review(run)
                    assign(b,bvalue);assign(c,int(F(bvalue)*ratio)+delta)
                    bs,cs=a.summarize(b),a.summarize(c)
                    with self.subTest(magnitude=magnitude,field=field,delta=delta):
                        if magnitude>=2**64:
                            self.assertNotEqual(bs['status'],'PASS')
                        else:
                            self.assertEqual(bs['status'],'PASS',bs['reasons']);self.assertEqual(cs['status'],'PASS',cs['reasons'])
                            want='PASS' if (delta<=0 if direction=='le' else delta>=0) else 'FAIL'
                            self.assertEqual(a.evaluate_metrics(bs['metrics'],cs['metrics'],1)['gates'][gate],want)
                    count+=1
            for exits,target in [(1,16*MIB),(5,48*MIB)]:
                for delta in (-1,0,1):
                    run=reconciled_record();value=target+delta
                    for s in run['samples']:s['processes'][0].update(pss_bytes=value,rss_bytes=value)
                    rebind_review(run);summary=a.summarize(run)
                    self.assertEqual(summary['status'],'PASS')
                    self.assertEqual(a.evaluate_metrics(summary['metrics'],summary['metrics'],exits)['gates']['control_pss'],'PASS' if delta<=0 else 'FAIL')
                    count+=1
            for signal in ('monitor_misses','unexpected_restarts','oom_events'):
                for value in (-1,0,1,magnitude):
                    run=reconciled_record();run['traffic'][signal]=value
                    run['runtime_evidence']['unexpected_restarts']=run['traffic']['unexpected_restarts']
                    run['runtime_evidence']['oom_events']=run['traffic']['oom_events']
                    rebind_review(run);summary=a.summarize(run)
                    self.assertEqual(summary['status'],'PASS' if value==0 else 'INSUFFICIENT_DATA')
                    count+=1
        self.assertEqual(count,120)

    def test_exact_types_and_rational_JSON_roundtrip(self):
        import ast
        tree=ast.parse((ROOT/'accounting.py').read_text())
        self.assertFalse(any(isinstance(n,ast.Constant) and type(n.value) is float for n in ast.walk(tree)))
        self.assertFalse(any(isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='float' for n in ast.walk(tree)))
        run=reconciled_record();run['traffic']['bytes']=57076;rebind_review(run)
        summary=a.summarize(run);value=summary['metrics']['throughput']
        self.assertIsInstance(value,Fraction)
        wire=json.loads(a.canonical(summary));projected=wire['metrics']['throughput']
        self.assertEqual(Fraction(projected['numerator'],projected['denominator']),Fraction(57076,600))
        self.assertEqual(a.describe([2**53+1]*6)['outliers'],[])


class ReviewDurationBounds(unittest.TestCase):
    def test_one_ns_read_uncertainty_is_exact_and_never_relaxes_cpu_gate(self):
        b=reconciled_record('python');c=reconciled_record('rust')
        for run,total in [(b,200000000),(c,100000000)]:
            for i,s in enumerate(run['samples']):
                s['domains']['control']['cpu'].update(usage_usec=i*total//60,user_usec=i*total//60)
                s['read_end_ns']+=1;s['wall_after_ns']+=1
            enrich_review(run);rebind_review(run)
        bs,cs=a.summarize(b),a.summarize(c)
        self.assertEqual(bs['status'],'PASS');self.assertEqual(cs['status'],'PASS')
        self.assertEqual(bs['supervision_cpu_bounds'],[Fraction(200000000000,600000000001),Fraction(200000000000,599999999999)])
        exact=a.evaluate_metrics(bs['metrics'],cs['metrics'],1)
        self.assertEqual(exact['gates']['supervision_cpu'],'PASS')
        bounded=a.evaluate_metrics(bs['metrics']|dict(supervision_cpu=bs['supervision_cpu_bounds'][0]),
            cs['metrics']|dict(supervision_cpu=cs['supervision_cpu_bounds'][1]),1)
        self.assertEqual(bounded['gates']['supervision_cpu'],'FAIL')


class ReviewDerivedNumerators(unittest.TestCase):
    def test_exact_projection_when_derived_numerator_exceeds_raw_u64(self):
        run=reconciled_record()
        run['traffic']['bytes']=2**64-1
        run['host']['link_capacity_bps']=10**18
        for i,s in enumerate(run['samples']):
            s['host']['network_rx_bytes']=i*(2**64-1)//60
            s['host']['network_tx_bytes']=i*(2**64-1)//60
        last=run['samples'][-1]
        for k in ('mono_ns','read_end_ns','wall_before_ns','wall_after_ns'):last[k]+=1
        run['duration_ns']+=1
        spec=importlib.util.spec_from_file_location('_exact_receipts',ROOT/'test_measurement.py')
        old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
        duration=run['duration_ns']
        view=dict(binding=run['binding'],input_sha256=a.record_digest(run),
            original_window_boottime_ns=[run['samples'][0]['mono_ns'],last['mono_ns']])
        proof=old.traffic_fixture(view);run['runtime_evidence']=proof
        proof['throughput_intervals'][0]['bytes']=run['traffic']['bytes']
        proof['throughput_bytes_per_second']=dict(bytes=run['traffic']['bytes'],duration_ns=duration)
        result=a.summarize(run)
        self.assertEqual(result['status'],'PASS',result['reasons'])
        value=result['metrics']['throughput']
        self.assertEqual(value,Fraction((2**64-1)*10**9,duration))
        self.assertGreater(value.numerator,2**64-1)
        proof['throughput_bytes_per_second']['bytes']-=1
        self.assertIn('invalid_runtime_evidence',a.summarize(run)['reasons'])



def round3_record(name):
    bundle=json.loads((ROOT/'fixtures/review-round3.json').read_text())
    run=bundle['base']
    for path,operation,value in bundle['fixtures'][name]['patch']:
        parent=run
        for key in path[:-1]:parent=parent[key]
        if operation=='delete':del parent[path[-1]]
        else:parent[path[-1]]=value
    import hashlib
    assert hashlib.sha256(a.canonical(run)).hexdigest()==bundle['fixtures'][name]['sha256']
    return run


class ReviewRoundThree(unittest.TestCase):
    # Each exact review recording previously qualified. Removing the generated
    # conservation/subset/pair rule must bring back the incorrect PASS.
    def refuse(self,names):
        for name in names:
            with self.subTest(recording=name):
                self.assertEqual(a.summarize(round3_record(name))['status'],'INSUFFICIENT_DATA')

    def test_T3I1_missing_host_clock_both_implementations(self):
        self.refuse(('lost_idle','lost_idle_python'))

    def test_T3I2_cumulative_cpu_offsets(self):
        self.refuse(('snapshot_cpu',))

    def test_T3I3_native_subfields(self):
        self.refuse(('shmem','anon_thp','kernel_stack','slab','cpu_periods'))

    def test_T3I4_completed_io_pairs(self):
        self.refuse(('read_bytes_no_ops','write_bytes_no_ops','discard_bytes_no_ops'))



def receipt_model_seeds():
    """Conditional original receipt shapes for model inventory/mutation tests."""
    spec=importlib.util.spec_from_file_location('_quantity_receipts',ROOT/'test_measurement.py')
    receipts=importlib.util.module_from_spec(spec);spec.loader.exec_module(receipts)
    for kind in ('rust','python'):
        normal=reconciled_record(kind);yield normal
        integer=copy.deepcopy(normal);integer['runtime_evidence']['throughput_bytes_per_second']=normal['traffic']['bytes']//600;yield integer
        raw=copy.deepcopy(normal);raw['runtime_evidence']['throughput_bytes_per_second']={'bytes':normal['traffic']['bytes'],'duration_ns':600*10**9};yield raw
        triggered=copy.deepcopy(normal)
        if kind=='rust':receipts.add_triggered_retry(triggered['runtime_evidence']);yield triggered
        for after in (False,True):
            aborted=copy.deepcopy(normal);op=aborted['runtime_evidence']['monitoring']['retry_coverage'][0]
            point=op['started_ns'];op['first_result']='http_429'
            if kind=='python':op['handshake']=None
            checked=point+(10**9+4 if after else (10**9 if kind=='python' else 1))
            op['completed_ns']=point+2*10**9 if after else op['completed_ns']
            op['retry']=dict(coverage='aborted',reason='http_429',stage='after_delay' if after else 'before_delay',failed_check=dict(checked_ns=checked,failed_component='default_route',event_sha256=H),protection=dict(kind='terminal_quarantine',evidence_sha256=H))
            if after:
                op['first_finished_ns']=point+1
                op['retry'].update(pre_delay_check=dict(checked_ns=point+2,interfaces_sha256=H,routes_sha256=H,handshake_age_ns=10**10),delay_started_ns=point+3,original_not_before_ns=point+3+10**9)
                if kind=='python':
                    router=aborted['runtime_evidence']['monitoring']['router_cycles'][0]['cycles'][0]
                    router['started_ns']-=10**9;op['started_ns']-=10**9;op['completed_ns']=point+10**9
                    op['retry']['delay_started_ns']=point-1;op['retry']['original_not_before_ns']=point-1+10**9
                    op['retry']['pre_delay_check']['checked_ns']=point-2;op['first_finished_ns']=point-3;op['retry']['failed_check']['checked_ns']=point+10**9
            yield aborted


if __name__=='__main__':unittest.main()
