"""Independent Linux-accounting regressions. All recordings are constructed.

Expected invalidity comes from cited source semantics and literal boundary
witnesses, never from asking the generated predicates whether a mutation is bad.
"""
import copy
import importlib.util
import itertools
import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).parent
spec = importlib.util.spec_from_file_location('_identity_fixtures', ROOT/'test_accounting.py')
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)
a = t.a


def round4_record(name, kind='rust', rep=1):
    run = t.reconciled_record(kind, rep)
    for s in run['samples']:
        d = s['domains']['control']
        if name == 'outside_cpu_offset':
            s['host']['other_cpu_usec'] += 10**12
        elif name.startswith('exited_cpu_'):
            d['cpu_exited_usec'] = 10**12
            d['cpu_exited_'+('system' if 'system' in name else 'user')+'_usec'] = 10**12
        elif name.startswith('io_'):
            prefix = {'io_read_offset':'r', 'io_write_offset':'w', 'io_discard_offset':'d'}[name]
            for key in ('io', 'io_other'):
                d[key]['8:0'] = dict(rbytes=0, wbytes=0, rios=0, wios=0, dbytes=0, dios=0)
            d['io_other']['8:0'].update({prefix+'bytes':2**60, prefix+'ios':2**40})
        elif name == 'sock_no_container':
            d['memory_stat'] = dict(anon=20*t.MIB, file=0, kernel=0, sock=10*t.MIB)
            d['memory_stat_other_bytes'] = 0
        elif name == 'fd_int_universe':
            run['host']['max_fd_entries'] = 2**40
            s['processes'][0]['fds'] = 2**32
        elif name == 'smaps_byte_quantum':
            # Reviewer's PSS=2MiB positive control has smaller private USS.
            s['processes'][0]['uss_bytes'] = t.MIB
            d['memory_other_bytes'] = d['memory_current_bytes']-sum(p['uss_bytes'] for p in s['processes'] if p['domain']=='control')
            s['processes'][0]['pss_bytes'] = 2097151
        else:
            raise AssertionError(name)
    t.rebind_review(run)
    return run


ROUND4 = {
    'outside_cpu_offset':'outside_cpu_snapshot',
    'exited_cpu_user_offset':'exited_usage_snapshot',
    'exited_cpu_system_offset':'exited_system_snapshot',
    'io_read_offset':'io_residual_snapshot',
    'io_write_offset':'io_residual_snapshot',
    'io_discard_offset':'io_residual_snapshot',
    'sock_no_container':'socket_container',
    'fd_int_universe':'fd_native_universe',
    'smaps_byte_quantum':'smaps_pss_quantum',
}


class ReviewRoundFour(unittest.TestCase):
    def test_retained_reconstructed_payloads(self):
        import hashlib
        bundle=json.loads((ROOT/'fixtures/review-round4.json').read_text())
        self.assertEqual(set(bundle['fixtures']),set(ROUND4))
        for name,entry in bundle['fixtures'].items():
            run=copy.deepcopy(bundle['base'])
            for path,operation,value in entry['patch']:
                parent=run
                for key in path[:-1]:parent=parent[key]
                if operation=='delete':del parent[path[-1]]
                else:parent[path[-1]]=value
            with self.subTest(recording=name):
                self.assertEqual(hashlib.sha256(a.canonical(run)).hexdigest(),entry['sha256'])
                self.assertEqual(a.summarize(run)['status'],'INSUFFICIENT_DATA')

    def test_native_FD_names_are_signed_int_identifiers(self):
        self.assertEqual(a.parse_fd_entries(['0',str(2**31-1)]),2)
        with self.assertRaises(ValueError):
            a.parse_fd_entries([str(2**31)])

    def test_proportional_smaps_values_need_not_be_page_multiples(self):
        run=t.reconciled_record()
        for s in run['samples']:
            # A PSS kB need not be divisible by a 4KiB page; its native output
            # quantum, unlike its fractional backing pages, is exactly 1KiB.
            s['processes'][0]['pss_bytes']-=1024
        t.rebind_review(run)
        self.assertEqual(a.summarize(run)['status'],'PASS')

    def test_T4_I1_cumulative_CPU_residuals(self):
        self.refuse(list(ROUND4)[:3])

    def test_T4_I2_cumulative_IO_residuals(self):
        self.refuse(list(ROUND4)[3:6])

    def test_T4_I3_socket_charge_container(self):
        self.refuse(['sock_no_container'])

    def test_T4_M1_native_FD_universe(self):
        self.refuse(['fd_int_universe'])

    def test_T4_M2_native_smaps_quantum(self):
        self.refuse(['smaps_byte_quantum'])

    def refuse(self, names):
        self.assertEqual(a.summarize(t.reconciled_record())['status'], 'PASS')
        for name in names:
            run = round4_record(name)
            with self.subTest(recording=name):
                self.assertNotEqual(a.summarize(run)['status'], 'PASS')

    def test_catalog_coverage_in_both_directions(self):
        self.assertTrue((ROOT/'kernel-identities.json').is_file(), 'missing identity catalog')
        self.assertTrue(hasattr(a._quantities, 'catalog_coverage'), 'missing catalog coverage audit')


def put(obj, path, value):
    for key in path[:-1]:
        obj = obj[key]
    obj[path[-1]] = value


def boundary_witnesses():
    """Hand-derived independent source oracle. No catalog/model expressions read.

    For subsets the two directions cross the boundary by raising the child or
    lowering the parent; a perturbation into the valid half-space may PASS.
    """
    cases = {}
    def add(name, mutate):
        if name in cases:
            raise AssertionError(name)
        cases[name] = mutate
    def parts(name, parent, children, allowance=0):
        def mutate(r, sign):
            s=r['samples'][-1]
            total=sum(get(s,p) for p in children)
            put(s,parent,total+sign*(allowance+1))
        add(name,mutate)
    def subset(name,parent,child):
        # Sibling constraints may also refuse; explicitly require THIS predicate
        # to refuse so an unrelated validator cannot mask an omitted identity.
        def mutate(r,sign):
            s=r['samples'][-1]
            put(s,child,4096+(1 if sign>0 else 0))
            put(s,parent,4096-(1 if sign<0 else 0))
        add(name,mutate)
    d=('domains','control');p=('processes',0);c=('host',)
    def hostclock(r,sign):
        r['samples'][-1]['host']['idle_ticks'] += sign*65  # 16*4 endpoint ticks +1
    add('host_clock',hostclock)
    def boot(r,sign):
        s=r['samples'][-1];h=r['host'];s['host']['busy_ticks']=0
        s['host']['idle_ticks']=s['read_end_ns']*h['tick_hz']*h['logical_cpus']//10**9+64
        if sign>0:s['host']['idle_ticks']+=1
        else:s['read_end_ns']-=1
    add('host_boot',boot)
    parts('host_parts',c+('busy_ticks',),[c+(k,) for k in ('user_ticks','system_ticks','irq_ticks','softirq_ticks','steal_ticks')])
    for cls,host,tick,allow in [('usage','busy','utime',48),('user','user','utime',16),('system','system','stime',16)]:
        def snapshot(r,sign,cls=cls,host=host,tick=tick,allow=allow,domain=True):
            s=r['samples'][-1];s['host'][host+'_ticks']=1000
            if domain:
                for g in s['domains'].values():g['cpu'][cls+'_usec']=0
                s['domains']['control']['cpu'][cls+'_usec']=(1000+allow)*10000+(1 if sign>0 else 0)
            else:
                for q in s['processes']:q['utime_ticks']=0;q['stime_ticks']=0
                s['processes'][0][tick+'_ticks']=1000+allow+(1 if sign>0 else 0)
            if sign<0:s['host'][host+'_ticks']-=1
        add('snapshot_domain_cpu' if cls=='usage' else 'snapshot_domain_'+cls,snapshot)
        add('snapshot_process_'+cls,lambda r,sign,fn=snapshot:fn(r,sign,domain=False))
    def aggregate(name,collection,key,parent_path,parent_host=False):
        def mutate(r,sign):
            s=r['samples'][-1];items=s[collection]
            items=list(items.values()) if isinstance(items,dict) else items
            if parent_host:
                r['host'][parent_path]=4096
                limit=4096
            else:
                put(s,parent_path,4096);limit=4096
            for item in items:item[key]=0
            items[0][key]=limit+(1 if sign>0 else 0)
            if sign<0:
                if parent_host:r['host'][parent_path]-=1
                else:put(s,parent_path,limit-1)
        add(name,mutate)
    for field in ('pss_bytes','uss_bytes'):
        aggregate('sum_'+field,'processes',field,'memory_total_bytes',True)
    aggregate('sum_charges','domains','memory_current_bytes','memory_total_bytes',True)
    aggregate('sum_threads','processes','threads','pid_max',True)
    aggregate('swap_pss','processes','swap_pss_bytes',c+('swap_used_bytes',))
    aggregate('swap_charges','domains','swap_current_bytes',c+('swap_used_bytes',))
    def manifest_bound(name,manifest,child):
        def mutate(r,sign):
            r['host'][manifest]=4096
            put(r['samples'][-1],child,4096+(1 if sign>0 else 0))
            if sign<0:r['host'][manifest]-=1
        add(name,mutate)
    manifest_bound('swap_host','swap_total_bytes',c+('swap_used_bytes',))
    for name,parent,child in [('uss_pss','pss_bytes','uss_bytes'),('pss_rss','rss_bytes','pss_bytes'),('swap_order','swap_bytes','swap_pss_bytes')]:
        subset(name,p+(parent,),p+(child,))
    for name,parent,child in [('rss_ram','memory_total_bytes','rss_bytes'),('fd_limit','max_fd_entries','fds'),('pid_limit','pid_max','pid'),('thread_limit','pid_max','threads')]:
        manifest_bound(name,parent,p+(child,))
    def start(r,sign):
        s=r['samples'][-1];s['processes'][0]['start_ticks']=s['read_end_ns']//10**7+(1 if sign>0 else 0)
        if sign<0:s['read_end_ns']-=1
    add('process_start',start)
    def lifetime(r,sign):
        s=r['samples'][-1];q=s['processes'][0]
        q['utime_ticks']=(s['read_end_ns']//10**7-q['start_ticks'])*4+8-q['stime_ticks']+(1 if sign>0 else 0)
        if sign<0:q['start_ticks']+=1
    add('process_lifetime',lifetime)
    parts('domain_parts',d+('cpu','usage_usec'),[d+('cpu','user_usec'),d+('cpu','system_usec')],2)
    parts('exited_parts',d+('cpu_exited_usec',),[d+('cpu_exited_user_usec',),d+('cpu_exited_system_usec',)])
    parts('memory_parts',d+('memory_current_bytes',),[d+('memory_stat',k) for k in ('anon','file','kernel')]+[d+('memory_stat_other_bytes',)])
    def charge(r,sign):
        s=r['samples'][-1];g=s['domains']['control']
        g['memory_current_bytes']=sum(q['uss_bytes'] for q in s['processes'] if q['domain']=='control')+g['memory_other_bytes']+sign
    add('memory_charge',charge)
    def pids(r,sign):
        s=r['samples'][-1];s['domains']['control']['pids_current']=sum(q['threads'] for q in s['processes'] if q['domain']=='control')+sign
    add('pids',pids)
    def domainboot(r,sign):
        s=r['samples'][-1];s['domains']['control']['cpu']['usage_usec']=s['read_end_ns']*4//1000+(1 if sign>0 else 0)
        if sign<0:s['read_end_ns']-=1
    add('domain_boot',domainboot)
    subset('native_sock',d+('memory_current_bytes',),d+('memory_stat','sock'))
    for key,parent in {'shmem':'file','anon_thp':'anon','file_thp':'file','shmem_thp':'shmem','kernel_stack':'kernel','pagetables':'kernel','sec_pagetables':'kernel','percpu':'kernel','vmalloc':'kernel','slab':'kernel','slab_reclaimable':'slab','slab_unreclaimable':'slab','file_mapped':'file','file_dirty':'file','file_writeback':'file'}.items():
        subset('native_'+key,d+('memory_stat',parent),d+('memory_stat',key))
    def slabs(r,sign,partition=False):
        m=r['samples'][-1]['domains']['control']['memory_stat']
        m.update(slab=4096,slab_reclaimable=2048,slab_unreclaimable=2048)
        if partition:m['slab']+=sign
        elif sign>0:m['slab_reclaimable']+=1
        else:m['slab']-=1
    add('native_slab_parts',lambda r,s:slabs(r,s,True))
    add('native_slab_subset',slabs)
    def kernelpieces(r,sign):
        m=r['samples'][-1]['domains']['control']['memory_stat']
        for k in ('kernel_stack','pagetables','sec_pagetables','percpu','vmalloc','slab'):m[k]=0
        m['kernel']=4096;m['slab']=4096+(1 if sign>0 else 0)
        if sign<0:m['kernel']-=1
    add('native_kernel_components',kernelpieces)
    for name in ('native_throttled_periods','native_throttled_period_deltas'):
        subset(name,d+('cpu','nr_periods'),d+('cpu','nr_throttled'))
    def throttle_time(r,sign):
        cpu=r['samples'][-1]['domains']['control']['cpu']
        cpu['nr_periods']=0;cpu['nr_throttled']=0
        cpu['throttled_usec']=1 if sign>0 else 2
    add('native_throttle_time_count',throttle_time)
    def group_kill(r,sign):
        events=r['samples'][-1]['domains']['control']['memory_events']
        events.update(oom=0,oom_kill=0,oom_group_kill=1 if sign>0 else 2)
    add('native_group_kill_oom_kill',group_kill)
    for label,prefix in [('read','r'),('write','w'),('discard','d')]:
        def completed(r,sign,prefix=prefix):
            m=r['samples'][-1]['domains']['control']['io']['8:0']
            m[prefix+'bytes']=1 if sign>0 else 0
            m[prefix+'ios']=0 if sign>0 else 1
        add('io_'+label,completed);add('io_'+label+'_delta',completed)
    for cls in ('usage','user','system'):
        def member(r,sign,cls=cls):
            # four control members, two ticks/member, 100Hz => 80,000us
            r['samples'][-1]['domains']['control']['cpu'][cls+'_usec']+=sign*80001
        add('member_cpu_'+cls,member)
    add('host_charge',lambda r,s:r['samples'][-1]['host'].__setitem__('busy_ticks',r['samples'][-1]['host']['busy_ticks']+s*49))
    for cls in ('user','system'):
        def classdelta(r,sign,cls=cls):
            s=r['samples'][-1];s['host'][cls+'_ticks']=1000
            for g in s['domains'].values():g['cpu'][cls+'_usec']=0
            s['domains']['control']['cpu'][cls+'_usec']=10160000+(1 if sign>0 else 0)
            if sign<0:s['host'][cls+'_ticks']-=1
        add('domain_'+cls+'_delta',classdelta)
    def capacity(r,sign):
        s=r['samples'][-1];first=r['samples'][0]
        s['domains']['control']['cpu']['usage_usec']=(s['read_end_ns']-first['mono_ns'])*4//1000+(1 if sign>0 else 0)
        if sign<0:s['read_end_ns']-=1
    add('domain_capacity',capacity)
    for direction in ('rx','tx'):
        def network(r,sign,direction=direction):
            s=r['samples'][-1];first=r['samples'][0]
            s['host']['network_'+direction+'_bytes']=first['host']['network_'+direction+'_bytes']+r['host']['link_capacity_bps']*(s['read_end_ns']-first['mono_ns'])//(8*10**9)+(1 if sign>0 else 0)
            if sign<0:r['host']['link_capacity_bps']-=1
        add('network_'+direction,network)
    def payload(r,sign):
        last=r['samples'][-1]['host']
        if sign>0:r['traffic']['bytes']=1200001
        else:last['network_rx_bytes']=0;last['network_tx_bytes']=r['traffic']['bytes']-1
    add('network_payload',payload)
    def io_conserve(r,sign):
        g=r['samples'][-1]['domains']['control']
        g['io' if sign>0 else 'io_other']['8:0']['rbytes']=1
    add('io_conservation',io_conserve)
    def outside(r,sign):
        s=r['samples'][-1];s['host']['other_cpu_usec']=s['host']['busy_ticks']*10000+480000+(1 if sign>0 else 0)
        if sign<0:s['host']['busy_ticks']-=1
    add('outside_cpu_snapshot',outside)
    add('snapshot_host_accounted',lambda r,s:r['samples'][-1]['host'].__setitem__('busy_ticks',r['samples'][-1]['host']['busy_ticks']+s*49))
    for cls in ('usage','user','system'):
        def exited(r,sign,cls=cls):
            g=r['samples'][-1]['domains']['control']
            g['cpu_exited_'+('' if cls=='usage' else cls+'_')+'usec']=g['cpu'][cls+'_usec']+2+(1 if sign>0 else 0)
            if sign<0:g['cpu'][cls+'_usec']-=1
        add('exited_'+cls+'_snapshot',exited)
    subset('io_residual_snapshot',d+('io','8:0','rbytes'),d+('io_other','8:0','rbytes'))
    def socket(r,sign):
        g=r['samples'][-1]['domains']['control']
        g['memory_stat']['sock']=g['memory_stat']['kernel']+g['memory_stat_other_bytes']+(1 if sign>0 else 0)
        if sign<0:g['memory_stat_other_bytes']-=1
    add('socket_container',socket)
    add('fd_native_universe',lambda r,s:r['samples'][-1]['processes'][0].__setitem__('fds',2**31+1 if s>0 else -1))
    for key in ('pss','rss','uss','swap','swap_pss'):
        add('smaps_'+key+'_quantum',lambda r,s,key=key:r['samples'][-1]['processes'][0].__setitem__(key+'_bytes',4096+s))
    # Explicit native counter inventory from the source documentation, not from
    # the model's monotonic flag. Domain/member/residual populations are distinct.
    D='/samples/*/domains/*/';P='/samples/*/processes/*/';C='/samples/*/host/'
    for prefix,keys in [(D+'memory_events/',('low','high','max','oom','oom_kill','oom_group_kill')),
                       (D+'cpu/',('usage_usec','user_usec','system_usec','nr_periods','nr_throttled','throttled_usec')),
                       (D,('cpu_exited_usec','cpu_exited_user_usec','cpu_exited_system_usec')),
                       (C,('other_cpu_usec',)),(P,('utime_ticks','stime_ticks','wakeups')),
                       (D+'io/*/',('rbytes','wbytes','rios','wios','dbytes','dios')),
                       (D+'io_other/*/',('rbytes','wbytes','rios','wios','dbytes','dios')),
                       (P+'io/*/',('rbytes','wbytes','rios','wios','dbytes','dios')),
                       (C,('network_rx_bytes','network_tx_bytes','busy_ticks','user_ticks','system_ticks','irq_ticks','softirq_ticks','steal_ticks','swap_in_pages','swap_out_pages'))]:
        for key in keys:
            path=(prefix+key).strip('/').split('/')[2:]
            path=tuple('control' if k=='*' and j and path[j-1]=='domains' else '8:0' if k=='*' and j and path[j-1] in ('io','io_other') else 0 if k=='*' else k for j,k in enumerate(path))
            def regress(r,sign,path=path):
                first=r['samples'][0];last=r['samples'][-1]
                if sign>0:put(first,path,get(last,path)+1)
                else:put(last,path,get(first,path)-1)
            add('counter_'+(prefix+key).strip('/').replace('/*','').replace('/','_'),regress)
    return cases


def get(obj,path):
    for key in path:obj=obj[key]
    return obj


def full_seed():
    r=t.reconciled_record()
    for s in r['samples']:
        for g in s['domains'].values():
            for k in ('nr_periods','nr_throttled','throttled_usec'):g['cpu'][k]=0
            for k in ('shmem','anon_thp','file_thp','shmem_thp','kernel_stack','pagetables','sec_pagetables','percpu','vmalloc','slab','slab_reclaimable','slab_unreclaimable','file_mapped','file_dirty','file_writeback'):g['memory_stat'][k]=0
            for k in ('low','high','max','oom_group_kill'):g['memory_events'][k]=0
            for key in ('io','io_other'):g[key]['8:0']=dict(rbytes=0,wbytes=0,rios=0,wios=0,dbytes=0,dios=0)
        for p in s['processes']:p['io']['8:0']=dict(rbytes=0,wbytes=0,rios=0,wios=0,dbytes=0,dios=0)
    t.rebind_review(r)
    return r


class IdentityCatalogTests(unittest.TestCase):
    def test_measured_network_identity_refuses_unavailable_warmup_anchor(self):
        run=full_seed()
        run['warmup_discard_ns']=run['duration_ns']+1
        rows=list(a._quantities.generated_constraints(run))
        self.assertIn(('relation:network_payload',False),rows)

    def test_bidirectional_coverage_removal_and_unsupported_source_gates(self):
        q=a._quantities
        self.assertEqual(q.catalog_coverage(),[])
        catalog=json.loads((ROOT/'kernel-identities.json').read_text())
        # Schema traversal is independent from the catalog compiler's traversal.
        schema=json.loads((ROOT/'run-schema.json').read_text())
        def leaves(node,path=''):
            if '$ref' in node:
                yield from leaves(schema['$defs'][node['$ref'].split('/')[-1]],path);return
            ty=node.get('type',[])
            if ty=='integer' or isinstance(ty,list) and 'integer' in ty or type(node.get('const')) is int or any(type(v) is int for v in node.get('enum',[])):yield path
            for k,v in node.get('properties',{}).items():yield from leaves(v,path+'/'+k)
            for v in node.get('patternProperties',{}).values():yield from leaves(v,path+'/*')
            if isinstance(node.get('additionalProperties'),dict):yield from leaves(node['additionalProperties'],path+'/*')
            if 'items' in node:yield from leaves(node['items'],path+'/*')
            for key in ('anyOf','oneOf','allOf'):
                for v in node.get(key,[]):yield from leaves(v,path)
        paths=set(leaves(schema));rules=q.MODEL['relations']
        ids={r['id'] for r in rules}
        applicable={i['id'] for i in catalog['identities'] if set(i['quantities'])<=paths}
        # Literal witnesses establish an independent expected identity set.
        self.assertEqual(applicable,set(boundary_witnesses()))
        for i in catalog['identities']:
            self.assertTrue(i['statement']);self.assertTrue(i['citations'])
            for c in i['citations']:self.assertTrue(c['document']);self.assertTrue(c['section']);self.assertTrue(c['text'])
            if i['id'] in applicable:
                self.assertTrue(i['checks'])
                self.assertTrue({r['id'] for r in i['checks']}<=ids)
            else:
                self.assertIn('unavailable_reason',i)
                # Synthesise schema availability without inventing enforcement.
                dummy={'type':'object','properties':{}}
                for path in i['quantities']:
                    node=dummy
                    for key in path.strip('/').split('/'):
                        node=node.setdefault('properties',{}).setdefault(key,{'type':'object'})
                    node.update(type='integer')
                errors=q.catalog_coverage(model={'relations':[]},schema=dummy)
                self.assertIn('recorded_identity_without_check:'+i['id'],errors)
        for rule in rules:
            removed=q.MODEL|{'relations':[r for r in rules if r['id']!=rule['id']]}
            self.assertIn('missing_generated_check:'+rule['id'],q.catalog_coverage(removed))
            uncited=copy.deepcopy(rule);uncited['catalog_identity']='nonexistent'
            self.assertIn('uncited_generated_check:'+rule['id'],q.catalog_coverage(q.MODEL|{'relations':[uncited]}))
        print('catalog coverage:',len(applicable),'applicable identities;',len(catalog['identities'])-len(applicable),'unavailable source identities;',len(rules),'checked removal/reverse-citation mutants')

    def test_fixed_seed_minimal_signed_identity_violations_never_PASS(self):
        cases=boundary_witnesses();order=[(name,sign) for name in cases for sign in (-1,1)]
        random.Random(0x144EB2F50E).shuffle(order)
        seed=full_seed();self.assertEqual(a.summarize(seed)['status'],'PASS')
        for name,sign in order:
            run=copy.deepcopy(seed);cases[name](run,sign)
            t.rebind_review(run)
            with self.subTest(identity=name,direction=sign):
                # Oracle invalidity is unconditional: no production predicate
                # decides whether to assert refusal. Assert named enforcement too.
                rows=list(a._quantities.generated_constraints(run))
                self.assertTrue(any(k=='relation:'+name and not ok for k,ok in rows))
                self.assertNotEqual(a.summarize(run)['status'],'PASS')
        print('independent identity boundary probes:',len(order),'seed 0x144EB2F50E')

    def test_raw_round4_scenarios_and_CLI_refuse_publication(self):
        from unittest.mock import patch
        base=[t.reconciled_record('python',rep) for rep in range(1,7)]
        positive=[t.reconciled_record('rust',rep) for rep in range(1,7)]
        self.assertEqual(a.compare(base,positive)['scenarios'][0]['status'],'PASS')
        with tempfile.TemporaryDirectory() as td:
            td=Path(td)
            for name,relation in ROUND4.items():
                baseline=copy.deepcopy(base)
                if name=='fd_int_universe':
                    # Review uses the same loose manifest limit on both sides;
                    # host-contract mismatch must not mask native-count refusal.
                    for run in baseline:
                        run['host']['max_fd_entries']=2**40
                        t.rebind_review(run)
                records=[round4_record(name,'rust',rep) for rep in range(1,7)]
                for run in records:
                    self.assertNotEqual(a.summarize(run)['status'],'PASS')
                scenario=a.compare(baseline,records)['scenarios'][0]
                self.assertNotEqual(scenario['status'],'PASS')
                self.assertNotIn('host_contract_mismatch',scenario['reasons'])
                rows=list(a._quantities.generated_constraints(records[0]))
                self.assertTrue(any(k=='relation:'+relation and not ok for k,ok in rows))
                # Establish that legacy/structural gates alone still admit the
                # reconstructed numeric counterexample, not a schema rejection.
                with patch.object(a._quantities,'check',lambda r,reasons:None):
                    self.assertEqual(a.summarize(records[0])['status'],'PASS')
                source=td/'input.json';destination=td/'result.json'
                source.write_bytes(a.canonical(records[0]))
                result=subprocess.run([sys.executable,'-B','-I',str(ROOT/'offline.py'),'summarize',str(source),'--output',str(destination)],capture_output=True,check=False)
                self.assertEqual(result.returncode,2)
                self.assertEqual(result.stderr,b'')
                self.assertFalse(destination.exists())
                self.assertNotIn(str(source).encode(),result.stdout)
                self.assertEqual(json.loads(result.stdout),dict(schema=1,status='INSUFFICIENT_DATA',release_ready=False,reasons=['invalid_input_or_publication']))
                self.assertEqual({p.name for p in td.iterdir()},{'input.json'})
        print('round4: 54 candidate summaries, 9 six-repetition scenarios and 9 actual CLI refusal/no-publication cases')


def optional_counters(run):
    """Present every supported optional native counter at its zero baseline."""
    for sample in run['samples']:
        for domain in sample['domains'].values():
            domain['cpu'].update(nr_periods=0, nr_throttled=0, throttled_usec=0)
            domain['memory_events'].update(oom_group_kill=0)
    t.rebind_review(run)
    return run


def throttle_record(variant, kind='rust', rep=1):
    run = optional_counters(t.reconciled_record(kind, rep))
    for index, sample in enumerate(run['samples']):
        cpu = sample['domains']['control']['cpu']
        cpu['nr_periods'] = 0
        cpu['nr_throttled'] = 0
        cpu['throttled_usec'] = 1000000 if variant == 'constant' else index*10000
    t.rebind_review(run)
    return run


def memory_event_record(variant, kind='rust', rep=1):
    values = {'group_only':(0,0,1), 'group_over_oom':(1,1,2),
              'oom_baseline':(1,1,0), 'oom_kill_baseline':(0,1,0),
              'group_baseline':(1,1,1), 'global_group_kill':(0,1,1),
              'global_group_kill_two':(0,2,1)}[variant]
    run = optional_counters(t.reconciled_record(kind, rep))
    for sample in run['samples']:
        events = sample['domains']['control']['memory_events']
        events.update(oom=values[0], oom_kill=values[1], oom_group_kill=values[2])
    t.rebind_review(run)
    return run


class ReviewRoundFive(unittest.TestCase):
    """Round-5 one-way throttle and OOM containment/constant-baseline findings."""

    def cli_refuses(self, run):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp); source = tmp/'input.json'; destination = tmp/'result.json'
            source.write_bytes(a.canonical(run))
            result = subprocess.run([sys.executable, '-B', '-I', str(ROOT/'offline.py'),
                                     'summarize', str(source), '--output', str(destination)],
                                    capture_output=True, check=False)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stderr, b'')
            self.assertFalse(destination.exists())
            self.assertEqual(json.loads(result.stdout)['status'], 'INSUFFICIENT_DATA')
            self.assertEqual({p.name for p in tmp.iterdir()}, {'input.json'})

    def test_R5_I1_throttle_time_requires_a_throttled_period(self):
        self.assertEqual(a.summarize(optional_counters(t.reconciled_record()))['status'], 'PASS')
        for variant in ('constant', 'increasing'):
            run = throttle_record(variant)
            with self.subTest(variant=variant):
                summary = a.summarize(run)
                self.assertEqual(summary['status'], 'INSUFFICIENT_DATA')
                self.assertIn('quantity_model:relation:native_throttle_time_count', summary['reasons'])
                rows = list(a._quantities.generated_constraints(run))
                self.assertTrue(any(name == 'relation:native_throttle_time_count' and not ok
                                    for name, ok in rows))
                # The generated relation, not a legacy/structural gate, is the
                # enforcement; bypassing the model restores the false PASS.
                with patch.object(a._quantities, 'check', lambda r, reasons: None):
                    self.assertEqual(a.summarize(run)['status'], 'PASS')
                self.cli_refuses(run)
                baseline = [optional_counters(t.reconciled_record('python', rep)) for rep in range(1, 7)]
                records = [throttle_record(variant, 'rust', rep) for rep in range(1, 7)]
                scenario = a.compare(baseline, records)['scenarios'][0]
                self.assertNotEqual(scenario['status'], 'PASS')
                self.assertIn('quantity_model:relation:native_throttle_time_count', scenario['reasons'])

    def test_R5_I1_first_sample_tearing_and_no_converse_are_tolerated(self):
        # A single torn first cpu.stat sample is exempt by the documented rule.
        run = optional_counters(t.reconciled_record())
        for index, sample in enumerate(run['samples']):
            cpu = sample['domains']['control']['cpu']
            cpu.update(nr_periods=index, nr_throttled=1 if index else 0,
                       throttled_usec=1000)
        t.rebind_review(run)
        self.assertEqual(a.summarize(run)['status'], 'PASS', a.summarize(run)['reasons'])
        # A throttled interval may be observed before its duration is added: the
        # converse is not asserted and a zero duration with a positive period
        # count is a valid half-space, not a violation.
        run = optional_counters(t.reconciled_record())
        for index, sample in enumerate(run['samples']):
            cpu = sample['domains']['control']['cpu']
            cpu.update(nr_periods=index, nr_throttled=1 if index else 0,
                       throttled_usec=0 if index < 2 else 1000)
        t.rebind_review(run)
        self.assertEqual(a.summarize(run)['status'], 'PASS', a.summarize(run)['reasons'])

    def test_R5_I2_group_kill_is_contained_by_killed_tasks(self):
        self.assertEqual(a.summarize(optional_counters(t.reconciled_record()))['status'], 'PASS')
        for variant in ('group_only', 'group_over_oom'):
            run = memory_event_record(variant)
            with self.subTest(variant=variant):
                summary = a.summarize(run)
                self.assertEqual(summary['status'], 'INSUFFICIENT_DATA')
                # oom_group_kill <= oom is not a kernel identity: a system-wide
                # OOM group kill may leave this cgroup's own oom counter zero.
                self.assertNotIn('quantity_model:relation:native_group_kill_oom',
                                 summary['reasons'])
                self.assertIn('quantity_model:relation:native_group_kill_oom_kill', summary['reasons'])
                rows = list(a._quantities.generated_constraints(run))
                self.assertFalse(any(name == 'relation:native_group_kill_oom'
                                     for name, ok in rows))
                self.assertTrue(any(name == 'relation:native_group_kill_oom_kill' and not ok
                                    for name, ok in rows))
                self.cli_refuses(run)
                baseline = [optional_counters(t.reconciled_record('python', rep)) for rep in range(1, 7)]
                records = [memory_event_record(variant, 'rust', rep) for rep in range(1, 7)]
                scenario = a.compare(baseline, records)['scenarios'][0]
                self.assertNotEqual(scenario['status'], 'PASS')
                self.assertIn('quantity_model:relation:native_group_kill_oom_kill', scenario['reasons'])

    def test_R5_I2_constant_nonzero_oom_baseline_is_contaminated(self):
        # group_baseline satisfies the surviving containment (1 <= 1), so only
        # the absolute first-sample policy can refuse it.
        for variant in ('oom_baseline', 'oom_kill_baseline', 'group_baseline'):
            run = memory_event_record(variant)
            with self.subTest(variant=variant):
                # These baselines satisfy every containment: only the absolute
                # first-sample policy can refuse them.
                rows = list(a._quantities.generated_constraints(run))
                self.assertFalse(any(name == 'relation:native_group_kill_oom'
                                     for name, ok in rows))
                self.assertFalse(any(name == 'relation:native_group_kill_oom_kill' and not ok
                                     for name, ok in rows))
                summary = a.summarize(run)
                self.assertEqual(summary['status'], 'INSUFFICIENT_DATA')
                self.assertIn('oom_baseline_contaminated', summary['reasons'])
                self.assertGreaterEqual(summary['metrics']['oom_events'], 1)
                self.cli_refuses(run)
                baseline = [optional_counters(t.reconciled_record('python', rep)) for rep in range(1, 7)]
                records = [memory_event_record(variant, 'rust', rep) for rep in range(1, 7)]
                scenario = a.compare(baseline, records)['scenarios'][0]
                self.assertNotEqual(scenario['status'], 'PASS')
                self.assertIn('oom_baseline_contaminated', scenario['reasons'])

    def test_counter_pair_audit_covers_every_co_located_counter_pair(self):
        catalog = json.loads((ROOT/'kernel-identities.json').read_text())
        q = a._quantities
        monotonic = {entry['path'] for entry in q.MODEL['quantities'] if entry['monotonic']}
        seen = []
        expected = {}
        for source in catalog['counter_sources']:
            self.assertTrue(source['id']); self.assertTrue(source['quantities'])
            for path in source['quantities']:
                self.assertIn(path, monotonic); seen.append(path)
            for left, right in itertools.combinations(source['quantities'], 2):
                pair = tuple(sorted((left, right)))
                self.assertNotIn(pair, expected)
                expected[pair] = source['id']
        self.assertEqual(sorted(seen), sorted(monotonic), 'every monotonic counter must have one source')
        actual = {}
        identities = {identity['id']:identity for identity in catalog['identities']}
        for entry in catalog['counter_pairs']:
            pair = tuple(sorted(entry['quantities']))
            self.assertNotIn(pair, actual)
            actual[pair] = entry
            self.assertEqual(entry['source'], expected[pair])
            self.assertIn(entry['decision'], ('identity', 'no_native_relation'))
            if entry['decision'] == 'identity':
                identity = identities[entry['identity']]
                self.assertTrue(set(entry['quantities']) <= set(identity['quantities']))
            else:
                self.assertTrue(entry['reason'])
        self.assertEqual(set(actual), set(expected))
        print('counter-pair audit:', len(actual), 'explicit pairs;',
              sum(e['decision'] == 'identity' for e in actual.values()), 'identity pairs')


def throttle_presence_record(variant, kind='rust', rep=1):
    """Optional cpu.stat throttle fields with one side deliberately absent."""
    run = optional_counters(t.reconciled_record(kind, rep))
    for sample in run['samples']:
        cpu = sample['domains']['control']['cpu']
        cpu['nr_periods'] = 0
        if variant == 'missing_consequent':
            # Native schema permits optional fields independently; a producer
            # may capture throttled_usec without either throttle count.
            cpu.pop('nr_periods', None)
            cpu.pop('nr_throttled', None)
            cpu['throttled_usec'] = 1000000
        elif variant == 'missing_antecedent':
            # The converse is not asserted: a throttled period may be observed
            # before its duration is accumulated.
            cpu.pop('throttled_usec', None)
            cpu.update(nr_periods=1, nr_throttled=1)
        elif variant == 'both_absent':
            cpu.pop('nr_periods', None)
            cpu.pop('nr_throttled', None)
            cpu.pop('throttled_usec', None)
        else:
            raise AssertionError(variant)
    t.rebind_review(run)
    return run


class ReviewRoundSix(unittest.TestCase):
    """Round-6 source-semantics and audit-scope regressions."""

    def test_R6_I1_global_oom_group_kill_is_not_a_native_contradiction(self):
        # oom is the cgroup-limit/charge-failure event, not an OOM-kill count.
        # A system-wide OOM with memory.oom.group=1 can kill this group while
        # this cgroup's own oom counter stays zero: oom=0, oom_kill>=1,
        # oom_group_kill=1 is a valid kernel recording.
        self.assertEqual(a.summarize(optional_counters(t.reconciled_record()))['status'], 'PASS')
        for variant in ('global_group_kill', 'global_group_kill_two'):
            run = memory_event_record(variant)
            with self.subTest(variant=variant):
                summary = a.summarize(run)
                # The independent absolute-zero OOM policy still refuses it.
                self.assertEqual(summary['status'], 'INSUFFICIENT_DATA')
                self.assertIn('oom_baseline_contaminated', summary['reasons'])
                self.assertIn('measured_domain_failure', summary['reasons'])
                self.assertGreaterEqual(summary['metrics']['oom_events'], 1)
                rows = list(a._quantities.generated_constraints(run))
                # The false oom_group_kill <= oom identity must not exist at
                # all: this valid shape is not a native contradiction.
                self.assertFalse(any(name == 'relation:native_group_kill_oom'
                                     for name, ok in rows))
                self.assertNotIn('quantity_model:relation:native_group_kill_oom',
                                 summary['reasons'])
                # The surviving nonempty-victim containment is satisfied.
                self.assertTrue(any(name == 'relation:native_group_kill_oom_kill'
                                    for name, ok in rows))
                self.assertTrue(all(ok for name, ok in rows
                                    if name == 'relation:native_group_kill_oom_kill'))
                self.assertNotIn('quantity_model:relation:native_group_kill_oom_kill',
                                 summary['reasons'])
                # The six-repetition comparator must also refuse this entry by
                # the OOM policy, not by a false native group-kill relation.
                baseline = [optional_counters(t.reconciled_record('python', rep))
                            for rep in range(1, 7)]
                records = [memory_event_record(variant, 'rust', rep)
                           for rep in range(1, 7)]
                scenario = a.compare(baseline, records)['scenarios'][0]
                self.assertEqual(scenario['status'], 'INSUFFICIENT_DATA')
                self.assertIn('oom_baseline_contaminated', scenario['reasons'])
                self.assertNotIn('quantity_model:relation:native_group_kill_oom',
                                 scenario['reasons'])
                # The CLI must refuse publication by the same OOM policy, not
                # by a false native contradiction.
                with tempfile.TemporaryDirectory() as tmp:
                    tmp = Path(tmp)
                    source = tmp/'input.json'; destination = tmp/'result.json'
                    source.write_bytes(a.canonical(run))
                    result = subprocess.run(
                        [sys.executable, '-B', '-I', str(ROOT/'offline.py'), 'summarize',
                         str(source), '--output', str(destination)],
                        capture_output=True, check=False)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stderr, b'')
                    self.assertFalse(destination.exists())
                    self.assertEqual(json.loads(result.stdout)['status'], 'INSUFFICIENT_DATA')
                    self.assertEqual({p.name for p in tmp.iterdir()}, {'input.json'})

    def test_R6_M1_positive_antecedent_requires_present_consequent(self):
        # A one-way presence rule, not a symmetric optional pair: the positive
        # antecedent requires the consequent to be present and positive.
        run = throttle_presence_record('missing_consequent')
        summary = a.summarize(run)
        self.assertEqual(summary['status'], 'INSUFFICIENT_DATA')
        self.assertIn('quantity_model:relation:native_throttle_time_count',
                      summary['reasons'])
        rows = list(a._quantities.generated_constraints(run))
        self.assertTrue(any(name == 'relation:native_throttle_time_count' and not ok
                            for name, ok in rows))
        # Absent antecedent (and a nonpositive one) is vacuous, so the valid
        # half-space nr_throttled>0 with throttled_usec absent must PASS.
        run = throttle_presence_record('missing_antecedent')
        self.assertEqual(a.summarize(run)['status'], 'PASS',
                         a.summarize(run)['reasons'])
        run = throttle_presence_record('both_absent')
        self.assertEqual(a.summarize(run)['status'], 'PASS',
                         a.summarize(run)['reasons'])
        run = optional_counters(t.reconciled_record())
        for sample in run['samples']:
            cpu = sample['domains']['control']['cpu']
            cpu.update(nr_periods=0, nr_throttled=0, throttled_usec=0)
        t.rebind_review(run)
        self.assertEqual(a.summarize(run)['status'], 'PASS')

    def test_R6_M2_relation_checks_name_presence_operands(self):
        model = json.loads((ROOT/'quantity-model.json').read_text())
        entries = {entry['name']: entry for entry in model['quantities']}
        for name in ('samples.*.domains.*.cpu.nr_throttled',
                     'samples.*.domains.*.cpu.throttled_usec'):
            with self.subTest(quantity=name):
                self.assertIn('native_throttle_time_count',
                              entries[name]['relation_checks'])

    def test_R6_M3_counter_pair_audit_catches_covered_sibling_pairs(self):
        q = a._quantities
        schema = json.loads((ROOT/'run-schema.json').read_text())
        catalog = json.loads((ROOT/'kernel-identities.json').read_text())
        self.assertEqual(q._catalog.counter_pair_problems(catalog, schema, q.MODEL), [])
        D = '/samples/*/domains/*/'
        C = '/samples/*/host/'
        covered = [
            ('sibling partition', C+'user_ticks', C+'system_ticks'),
            ('parent child', D+'cpu/nr_periods', D+'cpu/nr_throttled'),
            ('antecedent consequent', D+'cpu/nr_throttled', D+'cpu/throttled_usec'),
            ('containment', D+'memory_events/oom_kill', D+'memory_events/oom_group_kill'),
        ]
        for label, left, right in covered:
            mutated = json.loads((ROOT/'kernel-identities.json').read_text())
            pair = {left, right}
            for entry in mutated['counter_pairs']:
                if set(entry['quantities']) == pair:
                    entry.pop('identity', None)
                    entry['decision'] = 'no_native_relation'
                    entry['reason'] = 'mutation witness: covered pair must be caught'
            with self.subTest(pair=label):
                problems = q._catalog.counter_pair_problems(mutated, schema, q.MODEL)
                self.assertIn('counter_pair_unrelated_but_identity:'
                              + '|'.join(sorted(pair)), problems)


    def test_R7_M3_import_time_coverage_runs_the_counter_pair_audit(self):
        # Removing the counter_pair_problems call from coverage() must be caught:
        # the import-time path itself has to report a mutated covered pair.
        q = a._quantities
        schema = json.loads((ROOT/'run-schema.json').read_text())
        mutated = json.loads((ROOT/'kernel-identities.json').read_text())
        pair = {'/samples/*/host/user_ticks', '/samples/*/host/system_ticks'}
        for entry in mutated['counter_pairs']:
            if set(entry['quantities']) == pair:
                entry.pop('identity', None)
                entry['decision'] = 'no_native_relation'
                entry['reason'] = 'mutation witness'
        self.assertEqual(q.CATALOG_PROBLEMS, [])
        problems = q.catalog_coverage(model=q.MODEL, catalog=mutated, schema=schema)
        self.assertIn('counter_pair_unrelated_but_identity:' + '|'.join(sorted(pair)), problems)

    def test_R7_M2_relation_checks_are_exact_operand_matches(self):
        # A quantity lists a relation only if it is an actual operand, never by substring.
        model = json.loads((ROOT/'quantity-model.json').read_text())
        by_path = {e['path']: e['relation_checks'] for e in model['quantities']}
        D = '/samples/*/domains/*/'
        self.assertNotIn('native_group_kill_oom_kill', by_path[D+'memory_events/oom'])
        self.assertIn('native_group_kill_oom_kill', by_path[D+'memory_events/oom_kill'])
        self.assertIn('native_group_kill_oom_kill', by_path[D+'memory_events/oom_group_kill'])
        self.assertIn('native_throttle_time_count', by_path[D+'cpu/nr_throttled'])
        self.assertIn('native_throttle_time_count', by_path[D+'cpu/throttled_usec'])
        for check in ('sum_threads', 'fd_limit', 'pid_limit', 'thread_limit'):
            self.assertNotIn(check, by_path[D+'memory_events/max'])


if __name__ == '__main__':
    unittest.main()

