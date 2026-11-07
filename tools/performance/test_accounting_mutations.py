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



class QuantityModelTests(unittest.TestCase):
    def model(self):
        self.assertTrue((ROOT/'quantity-model.json').is_file(),'missing recorded-quantity model')
        self.assertTrue(hasattr(t.a,'_quantities'),'missing model-generated enforcement')
        return t.a._quantities

    def test_schema_inventory_and_model_check_mutation_completeness(self):
        import json
        q=self.model();schema=json.loads((ROOT/'run-schema.json').read_text())
        # This traversal is independent of production's model loader/compiler.
        def leaves(node,path=''):
            if '$ref' in node:
                yield from leaves(schema['$defs'][node['$ref'].split('/')[-1]],path);return
            ty=node.get('type',[]);ty=[ty] if type(ty) is str else ty
            if ('integer' in ty or type(node.get('const')) is int or
                any(type(v) is int for v in node.get('enum',[]))):yield path
            for key,value in node.get('properties',{}).items():yield from leaves(value,path+'/'+key)
            for value in node.get('patternProperties',{}).values():yield from leaves(value,path+'/*')
            if type(node.get('additionalProperties')) is dict:yield from leaves(node['additionalProperties'],path+'/*')
            if 'items' in node:yield from leaves(node['items'],path+'/*')
            for branch in ('anyOf','oneOf','allOf'):
                for value in node.get(branch,[]):yield from leaves(value,path)
        entries=q.MODEL['quantities'];paths={e['path'] for e in entries}
        self.assertEqual(set(leaves(schema)),paths)
        self.assertEqual(len(paths),len(entries),'duplicate modeled schema path')
        # Overflow is an independent witness for EVERY numeric quantity. The
        # same named check must disappear when that entry is removed, proving
        # that it is generated from the entry rather than a decorative table.
        primary=model_seed();receipt_seeds=list(t.receipt_model_seeds())
        for entry in entries:
            seed=next((r for r in [primary]+receipt_seeds if list(q.select(r,entry['path']))),primary)
            with self.subTest(quantity=entry['name']):
                for field in ('name','source','kind','unit','width','monotonic','parent_total','sibling_set','physical_upper_bound','absence_allowed','checks','mutation_test'):
                    self.assertIn(field,entry)
                found=list(q.select(seed,entry['path']))
                self.assertTrue(found,'model quantity has no mutation fixture')
                path,value=found[-1];parent=seed
                for k in path[:-1]:parent=parent[k]
                parent[path[-1]]=2**64
                rows=dict(q.generated_constraints(seed))
                check='quantity:'+entry['name']
                self.assertIn(check,entry['checks']);self.assertFalse(rows[check])
                changed=dict(q.generated_constraints(seed,model=q.MODEL|{'quantities':[e for e in entries if e is not entry]}))
                self.assertNotIn(check,changed)
                model_bind(seed)
                self.assertNotEqual(t.a.summarize(seed)['status'],'PASS')
                parent[path[-1]]=value
        print('model numeric entries and killed entry removals:',len(entries))

    def test_every_leaf_seeded_perturbation_preserves_refusals(self):
        import random
        q=self.model();rng=random.Random(0x14335C3)
        probes=0;broken=0;covered=set()
        seeds=[model_seed('rust'),model_seed('python')]+list(t.receipt_model_seeds())
        for seed in seeds:
            kind=seed['binding']['implementation']
            self.assertEqual(t.a.summarize(seed)['status'],'PASS')
            for entry in q.MODEL['quantities']:
                if (kind,entry['path']) in covered:continue
                matches=[(p,v) for p,v in q.select(seed,entry['path']) if type(v) is int]
                if not matches:continue
                covered.add((kind,entry['path']))
                # Both ends of every schema position, optional native keys too.
                for path,value in (matches[0],matches[-1]) if len(matches)>1 else matches:
                    parent=seed
                    for key in path[:-1]:parent=parent[key]
                    mutations=[value+1,value-1,0,2**64,'ABSENT','DUPLICATE']
                    rng.shuffle(mutations)
                    for replacement in mutations:
                        with self.subTest(kind=kind,path=path,mutation=replacement):
                            if replacement=='DUPLICATE':
                                # JSON duplicate keys have no in-memory dict
                                # representation. Exercise the real decoder.
                                spec=importlib.util.spec_from_file_location('_quantity_offline',ROOT/'offline.py')
                                o=importlib.util.module_from_spec(spec);spec.loader.exec_module(o)
                                raw=duplicate_leaf_json(seed,path)
                                with self.assertRaises(ValueError):o.decode(raw)
                                probes+=1;continue
                            if replacement=='ABSENT':
                                if type(parent) is list:original=parent.pop(path[-1])
                                else:original=parent.pop(path[-1])
                            else:parent[path[-1]]=replacement
                            try:
                                rows=list(q.generated_constraints(seed));bad=any(not ok for _,ok in rows)
                                model_bind(seed);result=t.a.summarize(seed)
                                if bad:self.assertNotEqual(result['status'],'PASS');broken+=1
                                # Keep an independent insufficiency/failure;
                                # repairing the sole cause may validly PASS.
                                origin=seed['evidence_origin'];seed['evidence_origin']='synthetic'
                                model_bind(seed)
                                self.assertNotEqual(t.a.summarize(seed)['status'],'PASS')
                                seed['evidence_origin']=origin
                                failed=dict(supervision_cpu=100,total_memory_bytes=100,control_pss_bytes=1,throughput=1000,p95_latency_ns=100,monitor_misses=0,unexpected_restarts=0,oom_events=1)
                                failed['throughput']=max(0,value if replacement=='ABSENT' else replacement)
                                self.assertNotEqual(t.a.evaluate_metrics(failed,failed,1)['status'],'PASS')
                            finally:
                                if replacement=='ABSENT' and type(parent) is list:parent.insert(path[-1],original)
                                else:parent[path[-1]]=value
                            probes+=1
            model_bind(seed)
        self.assertEqual({p for kind,p in covered},{e['path'] for e in q.MODEL['quantities']})
        self.assertGreater(broken,100)
        print('model fixed-seed +/-1/zero/huge/absent/duplicate probes:',probes,'generated violations:',broken)

    def test_count_bytes_and_optional_presence_boundaries(self):
        q=self.model()
        for scope in ('member','domain','residual'):
            run=model_seed()
            for index,sample in enumerate(run['samples']):
                p=sample['processes'][0];d=sample['domains']['control']
                p['io']['8:0'].update(rbytes=index,rios=index)
                d['io_other']['8:0'].update(rbytes=index,rios=index)
                d['io']['8:0'].update(rbytes=2*index,rios=2*index)
                target=p['io'] if scope=='member' else d['io'] if scope=='domain' else d['io_other']
                target['8:0']['rios']+=index*10
            model_bind(run)
            with self.subTest(scope=scope):
                rows=list(q.generated_constraints(run))
                self.assertTrue(any(name=='relation:io_read' and not ok for name,ok in rows))
        run=model_seed();del run['samples'][1]['domains']['control']['memory_stat']['shmem']
        self.assertFalse(dict(q.generated_constraints(run))['map:memory_stat'])
        run=model_seed();del run['samples'][1]['processes'][0]['io']['8:0']
        self.assertFalse(dict(q.generated_constraints(run))['map:process_io_devices'])

    def test_model_consumer_native_unknowns_and_clock_absence(self):
        from unittest.mock import patch
        q=self.model()
        for name in ('lost_idle','lost_idle_python','snapshot_cpu','shmem','anon_thp','kernel_stack','slab','cpu_periods','read_bytes_no_ops','write_bytes_no_ops','discard_bytes_no_ops'):
            run=t.round3_record(name);run['host']['cpu_clock_contract']='constant_online_no_suspend';model_bind(run)
            with self.subTest(recording=name):
                self.assertEqual(t.a.summarize(run)['status'],'INSUFFICIENT_DATA')
                # The original 44-family checks admit these exact numeric
                # recordings. Removing the model verdict consumer restores the
                # false PASS, so incidental structural rejection cannot mask it.
                with patch.object(q,'check',lambda run,reasons:None):
                    self.assertEqual(t.a.summarize(run)['status'],'PASS')
        seed=model_seed();self.assertEqual(t.a.summarize(seed)['status'],'PASS')
        del seed['host']['cpu_clock_contract'];model_bind(seed)
        self.assertNotEqual(t.a.summarize(seed)['status'],'PASS')
        for section in ('cpu','memory_stat','memory_events'):
            seed=model_seed()
            for sample in seed['samples']:sample['domains']['control'][section]['unmodeled_native_field']=0
            model_bind(seed)
            self.assertIn('quantity_model:map:'+section,t.a.summarize(seed)['reasons'])
        seed=model_seed();seed['runtime_evidence']['monitoring']['unmodeled_numeric']=0;model_bind(seed)
        self.assertIn('quantity_model:inventory:receipt_numeric',t.a.summarize(seed)['reasons'])

    def test_exact_review_fixtures_break_generated_relationships(self):
        q=self.model()
        cases={'lost_idle':'host_clock','lost_idle_python':'host_clock','snapshot_cpu':'snapshot_domain_cpu',
               'shmem':'native_shmem','anon_thp':'native_anon_thp','kernel_stack':'native_kernel_stack',
               'slab':'native_slab','cpu_periods':'native_throttled_periods',
               'read_bytes_no_ops':'io_read','write_bytes_no_ops':'io_write','discard_bytes_no_ops':'io_discard'}
        for name,rule in cases.items():
            run=t.round3_record(name)
            # Add only the newly required reviewed clock contract declaration;
            # preserve every numeric recording in the exact reviewer fixture.
            run['host']['cpu_clock_contract']='constant_online_no_suspend'
            rows=list(q.generated_constraints(run))
            with self.subTest(recording=name):
                self.assertTrue(any(k=='relation:'+rule and not ok for k,ok in rows))
                reduced=q.MODEL|{'relations':[r for r in q.MODEL['relations'] if r['id']!=rule]}
                self.assertFalse(any(k=='relation:'+rule for k,ok in q.generated_constraints(run,model=reduced)))
                t.rebind_review(run)
                self.assertEqual(t.a.summarize(run)['status'],'INSUFFICIENT_DATA')


    def test_relation_boundaries_and_consumer_mutations(self):
        q=self.model();seed=model_seed();witnesses={}
        # Independent raw perturbations, with literal zero/overflow witnesses; no
        # production predicate computes an expected success/failure boundary.
        for entry in q.MODEL['quantities']:
            matches=[(p,v) for p,v in q.select(seed,entry['path']) if type(v) is int]
            for path,value in (matches[0],matches[-1]) if len(matches)>1 else matches:
                parent=seed
                for key in path[:-1]:parent=parent[key]
                for replacement in (-1,0,1,2**64):
                    parent[path[-1]]=replacement
                    for name,ok in q.generated_constraints(seed):
                        if name.startswith('relation:') and not ok and name not in witnesses:
                            witnesses[name]=(path,replacement)
                parent[path[-1]]=value
        expected={'relation:'+r['id'] for r in q.MODEL['relations']}
        self.assertEqual(set(witnesses),expected,'every modeled relation needs a live raw mutation witness')
        for rule in q.MODEL['relations']:
            name='relation:'+rule['id'];path,replacement=witnesses[name]
            parent=seed
            for key in path[:-1]:parent=parent[key]
            value=parent[path[-1]];parent[path[-1]]=replacement
            reasons=set();q.check(seed,reasons)
            with self.subTest(rule=rule['id']):
                self.assertIn('quantity_model:'+name,reasons)
                removed=q.MODEL|{'relations':[r for r in q.MODEL['relations'] if r is not rule]}
                self.assertFalse(any(k==name for k,ok in q.generated_constraints(seed,model=removed)))
                self.assertEqual(rule['mutation_test'],'QuantityModelTests.test_relation_boundaries_and_consumer_mutations')
            parent[path[-1]]=value
        # Hand-derived compiler oracle: exact partition at 10, allowed +/-2,
        # outside at +/-3; strict subset remainders; completed tuples iff zero.
        partition=dict(operator='partition',parent='x',children=['a','b'],upper_tolerance=2,lower_tolerance=2)
        for x,want in [(7,False),(8,True),(10,True),(12,True),(13,False)]:
            self.assertEqual(q.relation_ok(partition,dict(x=x,a=4,b=6)),want)
        subset=partition|dict(upper_tolerance=0,lower_tolerance='x')
        for x,a,want in [(10,11,False),(10,10,True),(10,0,True),(0,1,False)]:
            self.assertEqual(q.relation_ok(subset,dict(x=x,a=a,b=0)),want)
        io=dict(operator='completed_io',parent='bytes',children=['ops'])
        for b,n,want in [(0,0,True),(1,0,False),(0,1,False),(1,1,True),(1,2,False),(2,1,True)]:
            self.assertEqual(q.relation_ok(io,dict(bytes=b,ops=n)),want)
        print('model relation removal mutants killed:',len(expected))

    def test_new_operator_truth_tables(self):
        q=self.model()
        # One-way positive implication: a>0 => b>0; the converse is NOT
        # asserted, because a read may observe a throttled interval before its
        # duration is accumulated.
        implies=dict(operator='implies_positive',antecedent='a',consequent='b')
        for a,b,want in [(0,0,True),(0,1,True),(1,0,False),(1,1,True),(2,0,False),(2,1,True)]:
            self.assertEqual(q.relation_ok(implies,dict(a=a,b=b)),want)
        # One-way presence: a positive antecedent requires a present positive
        # consequent; an absent antecedent is vacuous and never requires the
        # consequent. Every presence combination is covered.
        presence_cases=[({},True),
                        ({'a':0},True),({'a':1},False),({'a':2},False),
                        ({'b':0},True),({'b':1},True),
                        ({'a':0,'b':0},True),({'a':0,'b':1},True),
                        ({'a':1,'b':0},False),({'a':1,'b':1},True),
                        ({'a':2,'b':0},False),({'a':2,'b':1},True)]
        for context,want in presence_cases:
            with self.subTest(context=context):
                self.assertEqual(q.relation_ok(implies,context),want)
        # Count/duration containment: nonnegative contents may not exceed a
        # containing counter; it is not a two-sided partition.
        containment=dict(operator='containment',parent='p',children=['a','b'])
        for p,a,b,want in [(0,0,0,True),(1,0,0,True),(1,0,1,True),(1,1,1,False),
                           (5,2,3,True),(5,2,4,False),(0,1,0,False),(1,1,0,True)]:
            self.assertEqual(q.relation_ok(containment,dict(p=p,a=a,b=b)),want)

def model_bind(run):
    # Preserve the mutated measurement/projection. Rebinding must never repair
    # the very numeric receipt leaf under test.
    run['runtime_evidence']['record_sha256']=t.a.record_digest(run)


def duplicate_leaf_json(run,path):
    # Arrays cannot contain duplicate JSON keys; duplicate the closest named
    # containing field for their leaves. Dict leaves duplicate their exact key.
    target=tuple(path)
    while target and type(target[-1]) is int:target=target[:-1]
    import json
    def encode(value,current=()):
        if type(value) is dict:
            items=[]
            for key,item in value.items():
                field=json.dumps(key).encode()+b':'+encode(item,current+(key,))
                items.append(field)
                if current+(key,)==target:items.append(field)
            return b'{'+b','.join(items)+b'}'
        if type(value) is list:return b'['+b','.join(encode(item,current+(i,)) for i,item in enumerate(value))+b']'
        return t.a.canonical(value)
    return encode(run)


def model_seed(kind='rust'):
    seed=t.reconciled_record(kind)
    # Every supported optional numeric native key is present; no wildcard map
    # can hide an untested extension. All zero IO pairs are intentionally idle.
    q=t.a._quantities
    for entry in q.MODEL['quantities']:
        if not entry['absence_allowed']:continue
        path=entry['path']
        for sample in seed['samples']:
            if '/domains/*/cpu/' in path or '/domains/*/memory_' in path:
                section=path.split('/')[5];key=path.split('/')[-1]
                for domain in sample['domains'].values():domain[section].setdefault(key,0)
        if '/io/' in path or '/io_other/' in path:
            for sample in seed['samples']:
                maps=[p['io'] for p in sample['processes']]+[d[k] for d in sample['domains'].values() for k in ('io','io_other')]
                for io in maps:io.setdefault('8:0',{}).update(rbytes=0,wbytes=0,rios=0,wios=0,dbytes=0,dios=0)
    t.rebind_review(seed)
    return seed



if __name__=='__main__':unittest.main()
