"""Execute deliberate in-memory mutants; never edit product source on disk."""
import ast
import copy
import importlib.util
from pathlib import Path
import types
import unittest

ROOT=Path(__file__).parent
spec=importlib.util.spec_from_file_location('_accounting_fixture_module',ROOT/'test_accounting.py')
t=importlib.util.module_from_spec(spec);spec.loader.exec_module(t)
SOURCE=(ROOT/'accounting.py').read_text()


def mutant(transform):
    tree=transform.visit(ast.parse(SOURCE));ast.fix_missing_locations(tree)
    module=types.ModuleType('_accounting_mutant');module.__file__=str(ROOT/'accounting.py')
    exec(compile(tree,module.__file__,'exec'),module.__dict__)
    return module


class RemoveReason(ast.NodeTransformer):
    def __init__(self,reason):self.reason=reason
    def visit_Call(self,node):
        if (isinstance(node.func,ast.Attribute) and node.func.attr=='add' and len(node.args)==1 and
                isinstance(node.args[0],ast.Constant) and node.args[0].value==self.reason):
            return ast.Constant(None)
        return self.generic_visit(node)


class GateLiteral(ast.NodeTransformer):
    def __init__(self,value,replacement):self.value=value;self.replacement=replacement;self.inside=False
    def visit_FunctionDef(self,node):
        old=self.inside;self.inside=node.name=='evaluate_metrics';self.generic_visit(node);self.inside=old;return node
    def visit_Constant(self,node):
        if self.inside and type(node.value) is int and node.value==self.value:return ast.Constant(self.replacement)
        return node


class ExclusiveGate(ast.NodeTransformer):
    def __init__(self,operator):self.operator=operator;self.inside=False
    def visit_FunctionDef(self,node):
        old=self.inside;self.inside=node.name=='evaluate_metrics';self.generic_visit(node);self.inside=old;return node
    def visit_Compare(self,node):
        if self.inside:
            node.ops=[ast.Lt() if isinstance(op,ast.LtE) and self.operator=='le' else ast.Gt() if isinstance(op,ast.GtE) and self.operator=='ge' else op for op in node.ops]
        return self.generic_visit(node)


class ComparatorMutationTests(unittest.TestCase):
    def test_each_comparator_insufficiency_guard_is_observable(self):
        b=[];c=[]
        for kind,target in [('python',b),('rust',c)]:
            seed=t.fixture(kind);seed['samples']=seed['samples'][:3];seed['duration_ns']=2*10**9;seed['traffic']['bytes']=2000
            for rep in range(1,7):
                run=copy.deepcopy(seed);run['binding'].update(repetition=rep,run_id=f'{kind}-{rep}')
                shift=rep*10000*10**9
                for sample in run['samples']:
                    for field in ('mono_ns','read_end_ns','wall_before_ns','wall_after_ns'):sample[field]+=shift
                target.append(run)
        cases=[('invalid_run',lambda b,c:c[0].update(unknown=1)),
               ('mixed_host',lambda b,c:c[0]['binding'].update(host_id_sha256='b'*64)),
               ('instrumentation_mismatch',lambda b,c:c[0].update(instrumentation_sha256='b'*64)),
               ('host_contract_mismatch',lambda b,c:c[0]['host'].update(governor='powersave')),
               ('sampling_contract_mismatch',lambda b,c:c[0].update(warmup_discard_ns=10**9)),
               ('tailscale_mismatch',lambda b,c:c[0]['binding'].update(tailscale_version='1.2.3')),
               ('duplicate_record',lambda b,c:c.append(copy.deepcopy(c[0]))),
               ('duplicate_run_id',lambda b,c:c[0]['binding'].update(run_id=b[0]['binding']['run_id'])),
               ('wrong_implementation',lambda b,c:c[0]['binding'].update(implementation='python')),
               ('source_or_artifact_mismatch',lambda b,c:c[0]['binding'].update(artifact_sha256='b'*64)),
               ('overlapping_runs',lambda b,c:c.__setitem__(0,copy.deepcopy(b[0]))),
               ('too_few_repetitions',lambda b,c:c.pop()),
               ('duplicate_repetition',lambda b,c:c[0]['binding'].update(repetition=2)),
               ('unmatched_repetitions',lambda b,c:c[0]['binding'].update(repetition=7)),
               ('workload_mismatch',lambda b,c:c[0]['binding'].update(workload_sha256='b'*64)),
               ('accounting_mismatch',lambda b,c:c[0]['accounting'].update(review_sha256='b'*64)),
               ('domain_coverage_mismatch',lambda b,c:c[0]['domains'][0]['components'].append('tailscaled'))]
        for reason,change in cases:
            with self.subTest(reason=reason):
                baseline,candidate=copy.deepcopy(b),copy.deepcopy(c);change(baseline,candidate)
                original=t.a.compare(baseline,candidate)
                self.assertIn(reason,original['reasons']+original['scenarios'][0]['reasons'])
                changed=mutant(RemoveReason(reason)).compare(baseline,candidate)
                self.assertNotIn(reason,changed['reasons']+changed['scenarios'][0]['reasons'])

    def test_all_numeric_gate_mutants_are_killed_by_boundary_cases(self):
        baseline=dict(supervision_cpu=100,total_memory_bytes=1000,control_pss_bytes=1,
                      throughput=1000,p95_latency_ns=1000,monitor_misses=0,unexpected_restarts=0,oom_events=0)
        candidate=baseline|dict(supervision_cpu=50,control_pss_bytes=16*t.MIB,throughput=950,p95_latency_ns=1050)
        cases=[(1,candidate,'supervision_cpu','PASS'),(1,candidate|dict(supervision_cpu=51),'supervision_cpu','FAIL'),
               (1,candidate,'throughput','PASS'),(1,candidate|dict(throughput=949),'throughput','FAIL'),
               (1,candidate,'p95_latency','PASS'),(1,candidate|dict(p95_latency_ns=1051),'p95_latency','FAIL'),
               (1,candidate,'total_memory','PASS'),(1,candidate|dict(total_memory_bytes=1001),'total_memory','FAIL')]
        for count,target in [(1,16*t.MIB),(5,48*t.MIB)]:
            cases.extend([(count,candidate|dict(control_pss_bytes=target),'control_pss','PASS'),
                          (count,candidate|dict(control_pss_bytes=target+1),'control_pss','FAIL')])
        transforms=[GateLiteral(value,value+delta) for value in (50,95,105,16,48) for delta in (-1,1)]
        transforms.extend([ExclusiveGate('le'),ExclusiveGate('ge')])
        for transform in transforms:
            with self.subTest(transform=type(transform).__name__,value=getattr(transform,'value',None),replacement=getattr(transform,'replacement',None)):
                modified=mutant(transform)
                killed=False
                for count,c,gate,want in cases:
                    self.assertEqual(t.a.evaluate_metrics(baseline,c,count)['gates'][gate],want)
                    if modified.evaluate_metrics(baseline,c,count)['gates'][gate]!=want:killed=True
                self.assertTrue(killed,'boundary corpus did not catch comparator mutation')


def physical_seed():
    r=t.reconciled_record()
    h=r['host'];h.update(link_capacity_bps=10**9,max_fd_entries=1048576,pid_max=4194304)
    for s in r['samples']:
        elapsed=s['mono_ns']-r['samples'][0]['mono_ns']
        c=s['host'];c.update(user_ticks=c['busy_ticks'],system_ticks=0,irq_ticks=0,
            softirq_ticks=0,steal_ticks=0,idle_ticks=elapsed*4//10**7-c['busy_ticks'],
            network_rx_bytes=elapsed//10**6,network_tx_bytes=elapsed//10**6)
        for d in s['domains'].values():
            d.update(cpu_exited_user_usec=0,cpu_exited_system_usec=0,swap_current_bytes=0)
        for p in s['processes']:p.update(swap_bytes=0,swap_pss_bytes=0)
    t.rebind_review(r)
    return r


# Each raw mutation names an independent physical equation. A signed delta
# changes either operand: both sides of inequalities, both signs of equalities.
def physical_cases(r, name, sign, amount):
    s=r['samples'][-1];p=s['processes'][0];d=s['domains']['control'];c=s['host'];h=r['host']
    def upper(obj,key,limit):
        if sign>0:obj[key]=limit+amount
        else:obj[key]=0;return -amount
        return limit
    if name=='cpu_members':
        p['utime_ticks']=24000+sign*(2+amount)
    elif name=='cpu_user':
        if sign>0:c['user_ticks']-=16+amount
        else:d['cpu']['user_usec']+=160000+amount
    elif name=='cpu_system':
        if sign>0:d['cpu']['system_usec']=160000+amount
        else:c['system_ticks']=-16-amount
    elif name=='cpu_parts':d['cpu']['user_usec']+=sign*(2+amount)
    elif name=='cpu_exited':d['cpu_exited_usec']=amount if sign>0 else 0;d['cpu_exited_user_usec']=amount if sign<0 else 0
    elif name=='cpu_busy_parts':c['busy_ticks']+=sign*amount
    elif name=='cpu_irq_subset':c['irq_ticks']=c['busy_ticks']+amount if sign>0 else 0;c['softirq_ticks']=c['busy_ticks']+amount if sign<0 else 0
    elif name=='cpu_host_charge':
        if sign>0:c['other_cpu_usec']+=480000+amount
        else:c['busy_ticks']-=48+amount
    elif name=='cpu_capacity':
        if sign>0:c['idle_ticks']=240000-c['busy_ticks']+16*4+amount
        else:h['logical_cpus']=1;c['idle_ticks']=60000-c['busy_ticks']+16+amount
    elif name=='domain_capacity':
        d['cpu']['usage_usec']=2400000000+amount if sign>0 else 600000001;h['logical_cpus']=4 if sign>0 else 1
    elif name=='pss_ram':
        total=sum(q['pss_bytes'] for q in s['processes'])
        if sign>0:p['pss_bytes']+=h['memory_total_bytes']-total+amount
        else:h['memory_total_bytes']=total-amount
    elif name=='uss_ram':
        total=sum(q['uss_bytes'] for q in s['processes'])
        if sign>0:p['uss_bytes']+=h['memory_total_bytes']-total+amount
        else:h['memory_total_bytes']=max(0,total-amount)
    elif name=='rss_ram':
        if sign>0:p['rss_bytes']=h['memory_total_bytes']+amount
        else:h['memory_total_bytes']=max(0,p['rss_bytes']-amount)
    elif name=='uss_pss':
        if sign>0:p['uss_bytes']=p['pss_bytes']+amount
        else:p['pss_bytes']=max(0,p['uss_bytes']-amount)
    elif name=='pss_rss':
        if sign>0:p['pss_bytes']=p['rss_bytes']+amount
        else:p['rss_bytes']=max(0,p['pss_bytes']-amount)
    elif name=='memory_charge':d['memory_current_bytes']+=sign*min(amount,d['memory_current_bytes'])
    elif name=='memory_parts':d['memory_stat']['anon']+=sign*min(amount,d['memory_stat']['anon'])
    elif name=='memory_sock':
        if sign>0:d['memory_stat']['sock']=d['memory_current_bytes']+amount
        else:d['memory_current_bytes']=0;d['memory_stat']['sock']=amount
    elif name=='charges_ram':
        total=sum(g['memory_current_bytes'] for g in s['domains'].values())
        if sign>0:d['memory_current_bytes']+=h['memory_total_bytes']-total+amount
        else:h['memory_total_bytes']=max(0,total-amount)
    elif name=='swap_order':p['swap_pss_bytes']=amount if sign>0 else 0;p['swap_bytes']=0 if sign>0 else -amount
    elif name=='swap_ram':
        if sign>0:c['swap_used_bytes']=h['swap_total_bytes']+amount
        else:h['swap_total_bytes']=-amount
    elif name=='swap_pss':
        if sign>0:p['swap_pss_bytes']=amount
        else:c['swap_used_bytes']=-amount
    elif name=='swap_charge':
        if sign>0:d['swap_current_bytes']=amount
        else:c['swap_used_bytes']=-amount
    elif name=='pids_threads':d['pids_current']+=sign*amount
    elif name=='pid_bound':
        if sign>0:p['pid']=h['pid_max']+amount
        else:h['pid_max']=max(0,p['pid']-amount)
    elif name=='fds_bound':
        if sign>0:p['fds']=h['max_fd_entries']+amount
        else:h['max_fd_entries']=max(0,p['fds']-amount)
    elif name=='threads_bound':p['threads']=h['pid_max']+amount if sign>0 else 1-amount
    elif name=='io_conservation':
        key='io' if sign>0 else 'io_other'
        d[key]={'8:0':dict(rbytes=amount,wbytes=0,rios=0,wios=0)}
    elif name=='counter_monotonic':
        key='utime_ticks' if sign>0 else 'stime_ticks'
        r['samples'][0]['processes'][0][key]=p[key]+amount
    elif name=='wakeups_monotonic':
        if sign>0:r['samples'][0]['processes'][0]['wakeups']=p['wakeups']+amount
        else:p['wakeups']=-amount
    elif name=='network_monotonic':
        key='network_rx_bytes' if sign>0 else 'network_tx_bytes'
        r['samples'][0]['host'][key]=c[key]+amount
    elif name=='network_capacity':
        key='network_rx_bytes' if sign>0 else 'network_tx_bytes'
        c[key]=h['link_capacity_bps']*600//8+amount
    elif name=='network_payload':
        if sign>0:r['traffic']['bytes']=1200000+amount
        else:
            for sample in r['samples']:sample['host']['network_rx_bytes']=0;sample['host']['network_tx_bytes']=0
    elif name=='swap_quiet':
        key='swap_in_pages' if sign>0 else 'swap_out_pages';c[key]=amount
    elif name=='thermal_quiet':
        if sign>0:c['temperature_millic']=h['thermal_limit_millic']-1+amount
        else:h['thermal_limit_millic']=max(0,c['temperature_millic']+1-amount)
    elif name=='numeric_domain':p['fds']=-amount if sign<0 else 2**64-1+amount
    elif name=='sample_clock':s['read_end_ns']=s['mono_ns']-amount if sign<0 else s['mono_ns']+r['interval_ns']//10+amount
    elif name=='coverage':
        if sign<0:d['member_pids']=[]
        else:d['member_pids'].append(h['pid_max']+amount)
    elif name=='metric_availability':
        p['fds' if sign<0 else 'wakeups']=None
        if amount>1:
            for q in s['processes']:q['fds']=None;q['wakeups']=None
    elif name=='failure_quiet':
        target=r['traffic'] if sign>0 else r['failure_domains']['kernel']
        target['oom_events' if sign>0 else 'kernel_oom_kills']=amount
    elif name=='process_start':
        end_ticks=s['read_end_ns']*h['tick_hz']//10**9
        p['start_ticks']=end_ticks+amount if sign>0 else end_ticks
        if sign<0:s['read_end_ns']=max(0,s['read_end_ns']-amount*10**9//h['tick_hz'])
    elif name=='process_lifetime_cpu':
        if sign>0:p['utime_ticks']=(s['read_end_ns']*h['tick_hz']//10**9-p['start_ticks']+2)*h['logical_cpus']+amount
        else:p['start_ticks']=s['read_end_ns']*h['tick_hz']//10**9;p['utime_ticks']=2*h['logical_cpus']+amount
    elif name=='host_boot_cpu':
        total=s['read_end_ns']*h['logical_cpus']*h['tick_hz']//10**9+16*h['logical_cpus']
        if sign>0:c['busy_ticks']=total-c['idle_ticks']+amount
        else:c['idle_ticks']=total-c['busy_ticks']+amount
    elif name=='domain_boot_cpu':
        if sign>0:d['cpu']['usage_usec']=s['read_end_ns']*h['logical_cpus']//1000+amount
        else:s['read_end_ns']=0;d['cpu']['usage_usec']=amount
    else:raise AssertionError('uncovered invariant '+name)


PHYSICAL_IDS={
    'cpu_members','cpu_user','cpu_system','cpu_parts','cpu_exited','cpu_busy_parts',
    'cpu_irq_subset','cpu_host_charge','cpu_capacity','domain_capacity',
    'pss_ram','uss_ram','rss_ram','uss_pss','pss_rss','memory_charge','memory_parts',
    'memory_sock','charges_ram','swap_order','swap_ram','swap_pss','swap_charge',
    'pids_threads','pid_bound','fds_bound','threads_bound','io_conservation',
    'counter_monotonic','wakeups_monotonic','network_monotonic','network_capacity',
    'network_payload','swap_quiet','thermal_quiet','numeric_domain','sample_clock',
    'coverage','metric_availability','failure_quiet','process_start','process_lifetime_cpu',
    'host_boot_cpu','domain_boot_cpu'}


class PhysicalRegistryTests(unittest.TestCase):
    def test_host_task_ceiling_is_also_aggregate(self):
        run=physical_seed();run['host']['pid_max']=5
        for s in run['samples']:
            for p in s['processes']:p['threads']=2
            for d in s['domains'].values():d['pids_current']=2
        t.rebind_review(run)
        self.assertEqual(t.a.summarize(run)['status'],'INSUFFICIENT_DATA')
    def test_registry_has_live_enforcement_and_raw_boundary_tests(self):
        self.assertTrue(hasattr(t.a,'INVARIANT_REGISTRY'),'missing invariant registry')
        self.assertEqual(set(t.a.INVARIANT_REGISTRY),PHYSICAL_IDS)
        seed=physical_seed();self.assertEqual(t.a.summarize(seed)['status'],'PASS')
        observed={row[0] for row in t.a.physical_constraints(seed)}
        self.assertEqual(observed,PHYSICAL_IDS)
        for name,entry in t.a.INVARIANT_REGISTRY.items():
            self.assertTrue(callable(getattr(t.a,entry['enforced_by'])))
            self.assertEqual(entry['test'],'PhysicalRegistryTests.test_raw_signed_boundary_mutations')
            self.assertTrue(callable(getattr(PhysicalRegistryTests,entry['test'].split('.')[-1])))
            self.assertEqual(entry['status'],'INSUFFICIENT_DATA')

    def test_raw_signed_boundary_mutations(self):
        self.assertTrue(hasattr(t.a,'INVARIANT_REGISTRY'),'missing invariant registry')
        seed=physical_seed()
        for name in sorted(PHYSICAL_IDS):
            for sign in (-1,1):
                for amount in (1,2**40):
                    run=copy.deepcopy(seed);physical_cases(run,name,sign,amount);t.rebind_review(run)
                    with self.subTest(invariant=name,sign=sign,amount=amount):
                        self.assertNotEqual(t.a.summarize(run)['status'],'PASS')
                        # Detect omission of this equation even when redundant
                        # equations or structural checks also refuse the input.
                        rows=[row for row in t.a.physical_constraints(run) if row[0]==name]
                        self.assertTrue(any(not ok for _,ok in rows),'mutation did not violate named invariant')

    def test_registry_enforcement_removal_is_killed(self):
        # Bypass only the verdict consumer, leaving all equations executable.
        # Each named raw counterexample must lose its named reason. This catches
        # decorative registry rows and tests masked by other refusal reasons.
        seed=physical_seed()
        for name,entry in t.a.INVARIANT_REGISTRY.items():
            run=copy.deepcopy(seed);physical_cases(run,name,1,1)
            reasons=set();t.a.check_invariants(run,reasons)
            self.assertIn(entry['reason'],reasons)
            saved=t.a.INVARIANT_REGISTRY[name]
            try:
                t.a.INVARIANT_REGISTRY[name]=saved|dict(reason='mutation_removed')
                changed=set();t.a.check_invariants(run,changed)
                self.assertIn('mutation_removed',changed)
            finally:t.a.INVARIANT_REGISTRY[name]=saved

    def test_every_numeric_schema_leaf_signed_boundary_property(self):
        # Cover every numeric schema position, both native/legacy receipt
        # variants, every process component and domain, first/last endpoints.
        # Repeated interior array instances share a schema; they are separately
        # covered by the anchored-prefix accumulation/counter tests.
        def paths(v,path=()):
            if type(v) is int:yield path,v
            elif type(v) is dict:
                for key,value in v.items():yield from paths(value,path+(key,))
            elif type(v) is list:
                seen=set()
                for i,value in enumerate(v):
                    tag=(type(value).__name__,tuple(sorted(value)) if type(value) is dict else '',
                         tuple(value.get(k) for k in ('component','domain','variant','state','coverage','stage')) if type(value) is dict else '',
                         i==len(v)-1)
                    if tag not in seen:seen.add(tag);yield from paths(value,path+(i,))
        count=0;violations=0
        for kind in ('python','rust'):
            seed=physical_seed() if kind=='rust' else t.reconciled_record('python')
            # Include optional IO and memory-event counters in the schema.
            for i,s in enumerate(seed['samples']):
                vals=dict(rbytes=i,wbytes=i,rios=i,wios=i,dbytes=i,dios=i)
                s['processes'][0]['io']={'8:0':dict(vals)}
                s['domains']['control']['io']={'8:0':dict(vals)}
                s['domains']['control']['io_other']={'8:0':{k:0 for k in vals}}
                for d in s['domains'].values():d['memory_events']['oom_group_kill']=0
            seed['runtime_evidence']['record_sha256']=t.a.record_digest(seed)
            self.assertEqual(t.a.summarize(seed)['status'],'PASS')
            for path,value in list(paths(seed)):
                parent=seed
                for key in path[:-1]:parent=parent[key]
                for replacement in sorted({value-1,value+1,value-2**40,value+2**40,-1,2**64}):
                    parent[path[-1]]=replacement
                    seed['runtime_evidence']['record_sha256']=t.a.record_digest(seed)
                    got=t.a.summarize(seed)
                    # The same registry predicates feed production verdicts;
                    # separate raw tests above establish each predicate from
                    # hand-derived equations and kill missing enforcement.
                    try:broken=[name for name,ok in t.a.physical_constraints(seed) if not ok]
                    except (TypeError,ValueError,KeyError,ZeroDivisionError,StopIteration):broken=['invalid_numeric_domain']
                    with self.subTest(kind=kind,path=path,replacement=replacement):
                        if broken or not 0<=replacement<2**64:
                            self.assertNotEqual(got['status'],'PASS');violations+=1
                        # Preserve an independent nonnumeric blocker. Fixing the
                        # sole bad number can legitimately restore PASS; this
                        # property specifically forbids erasing retained faults.
                        origin=seed['evidence_origin'];seed['evidence_origin']='synthetic'
                        seed['runtime_evidence']['record_sha256']=t.a.record_digest(seed)
                        self.assertNotEqual(t.a.summarize(seed)['status'],'PASS')
                        seed['evidence_origin']=origin
                    parent[path[-1]]=value
                    count+=1
                seed['runtime_evidence']['record_sha256']=t.a.record_digest(seed)
        self.assertGreater(count,4000);self.assertGreater(violations,2000)
        # A retained failed gate cannot become PASS through another measurement.
        base=dict(supervision_cpu=100,total_memory_bytes=1000,control_pss_bytes=1,
                  throughput=1000,p95_latency_ns=1000,monitor_misses=0,unexpected_restarts=0,oom_events=1)
        for key in set(base)-{'oom_events'}:
            for delta in (-1,1,-2**40,2**40):
                self.assertNotEqual(t.a.evaluate_metrics(base,base|{key:base[key]+delta},1)['status'],'PASS')
        print('numeric schema boundary probes:',count,'registered/number violations:',violations)


if __name__=='__main__':unittest.main()
