"""Author the closed schema inventory and declarative quantity model, offline.

Run with python3 -B -I. Changes to semantics require editing this authoring table,
reviewing the generated JSON diff, and updating independent mutation witnesses.
This tool is never invoked by the analyzer or its completeness tests.
"""
import json
import importlib.util
from pathlib import Path

ROOT=Path(__file__).parent
U64=2**64-1
CPU=('usage_usec','user_usec','system_usec','nr_periods','nr_throttled','throttled_usec')
MEMORY=('anon','file','kernel','sock','shmem','anon_thp','file_thp','shmem_thp','kernel_stack','pagetables','sec_pagetables','percpu','vmalloc','slab','slab_reclaimable','slab_unreclaimable','file_mapped','file_dirty','file_writeback')
EVENTS=('low','high','max','oom','oom_kill','oom_group_kill')
IO=('rbytes','wbytes','rios','wios','dbytes','dios')


def author():
    schema=json.loads((ROOT/'run-schema.json').read_text())
    numeric=dict(type='integer',minimum=0,maximum=U64)
    ds=schema['$defs']['domain_sample']['properties']
    maps=[]
    for key,allowed,required in [('cpu',CPU,CPU[:3]),('memory_stat',MEMORY,MEMORY[:4]),('memory_events',EVENTS,('oom','oom_kill'))]:
        ds[key]=dict(type='object',additionalProperties=False,properties={k:dict(numeric) for k in allowed},required=list(required))
        maps.append(dict(id=key,path='/samples/*/domains/*/'+key,required=list(required),allowed=list(allowed)))
    for id,path in [('domain_io','/samples/*/domains/*/io'),('residual_io','/samples/*/domains/*/io_other'),('process_io','/samples/*/processes/*/io')]:
        maps.append(dict(id=id+'_devices',path=path,required=[],key_pattern='^[0-9]+:[0-9]+$',keys_stable=True))
        maps.append(dict(id=id+'_tuple',path=path+'/*',required=list(IO[:4]),allowed=list(IO),keys_stable=True))
    # Every IO tuple has the same closed field semantics, in each location.
    def close_io(node):
        if type(node) is not dict:return
        if node.get('propertyNames',{}).get('enum')==list(IO):
            required=node['required'];node.clear();node.update(type='object',additionalProperties=False,properties={k:dict(numeric) for k in IO},required=required)
        for value in list(node.values()):
            if type(value) is dict:close_io(value)
            elif type(value) is list:
                for item in value:close_io(item)
    close_io(schema)
    schema['$defs']['host']['properties']['cpu_clock_contract']=dict(enum=['constant_online_no_suspend'])
    if 'cpu_clock_contract' not in schema['$defs']['host']['required']:schema['$defs']['host']['required'].append('cpu_clock_contract')
    # Explicitly expose numeric receipt positions formerly hidden behind an
    # opaque schema-2 object. Structural/conditional/order semantics still pass
    # through the original adapter. Unknown numeric receipt paths fail closed.
    spec=importlib.util.spec_from_file_location('_model_author_fixtures',ROOT/'test_accounting.py')
    fixtures=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixtures)
    receipt_paths=set()
    def numbers(value,path=()):
        if type(value) is int:receipt_paths.add(path)
        elif type(value) is dict:
            for key,item in value.items():numbers(item,path+(key,))
        elif type(value) is list:
            for item in value:numbers(item,path+('*',))
    for record in fixtures.receipt_model_seeds():numbers(record['runtime_evidence'])
    def insert(node,path):
        if not path:
            node.setdefault('anyOf',[]).append(dict(type=['integer','null'],minimum=0,maximum=U64));return
        key,*tail=path
        if key=='*':
            node['type']='array';child=node.setdefault('items',{})
        else:
            # Rate projections can be either a number or an object. anyOf
            # carries numeric alternatives without treating objects as numbers.
            child=node.setdefault('properties',{}).setdefault(key,{})
        insert(child,tail)
    receipt_schema=dict(type=['object','null'],description='Numeric inventory; source-specific original adapters remain normative for required conditional shapes, exact projections and ordering.')
    for path in sorted(receipt_paths):insert(receipt_schema,path)
    def normalize(node):
        for key,value in list(node.items()):
            if type(value) is dict:normalize(value)
            elif type(value) is list:
                for item in value:
                    if type(item) is dict:normalize(item)
        if 'properties' in node:
            obj=dict(type='object',properties=node.pop('properties'),additionalProperties=True)
            if 'anyOf' in node:node['anyOf'].append(obj)
            else:node.update(obj)
    normalize(receipt_schema)
    schema['properties']['runtime_evidence']=receipt_schema
    def leaves(node,path='',optional=False):
        if '$ref' in node:
            yield from leaves(schema['$defs'][node['$ref'].split('/')[-1]],path,optional);return
        ty=node.get('type',[]);ty=[ty] if type(ty) is str else ty
        if 'integer' in ty or type(node.get('const')) is int or any(type(v) is int for v in node.get('enum',[])):yield path,node,optional
        for key,value in node.get('properties',{}).items():yield from leaves(value,path+'/'+key,optional or key not in node.get('required',[]))
        for value in node.get('patternProperties',{}).values():yield from leaves(value,path+'/*',optional)
        if type(node.get('additionalProperties')) is dict:yield from leaves(node['additionalProperties'],path+'/*',optional)
        if 'items' in node:yield from leaves(node['items'],path+'/*',optional)
        for branch in ('anyOf','oneOf','allOf'):
            for value in node.get(branch,[]):yield from leaves(value,path,optional)
    entries=[]
    for path,node,optional in leaves(schema):
        key=path.split('/')[-1];name=path.strip('/').replace('/','.')
        kind='gauge';unit='dimensionless';source='run manifest / reviewed producer contract'
        monotonic=False;parent=None;siblings=[];bound='declared integer domain; no universal tighter physical bound'
        if path.startswith('/runtime_evidence/'):
            source='original source-specific schema-2 traffic/monitor receipt; accounting.validate_exact_traffic and measurement.validate_monitoring'
            bound='exact receipt binding/window/cadence/timer/projection equations in original adapter'
        if path.startswith('/samples/'):
            if '/domains/' in path:source='cgroup v2 / '+path.split('/')[5]
            elif '/processes/' in path:source='/proc/PID/stat, smaps_rollup, sched, fd, reviewed completed block IO'
            elif '/host/' in path:source='/proc/stat, meminfo, vmstat, physical serialized link, thermal readings'
            else:source='bracketed CLOCK_BOOTTIME and CLOCK_REALTIME original acquisition'
        if key.endswith('_ns') or key in ('mono_ns','read_end_ns','wall_after_ns','wall_before_ns'):unit='nanosecond'
        elif key.endswith('_seconds'):unit='second'
        elif key.endswith('_ticks') or key=='tick_hz':unit='tick' if key!='tick_hz' else 'tick/second'
        elif key.endswith('_usec'):unit='microsecond'
        elif key.endswith('_bytes') or key in MEMORY or key.endswith('bytes'):unit='byte'
        elif key in IO:unit='operation'
        elif key.endswith('_millic'):unit='millicelsius'
        elif key=='link_capacity_bps':unit='bit/second'
        elif key in ('pid','pid_max','member_pids','threads','pids_current','fds','max_fd_entries','logical_cpus'):unit='count'
        elif '/native_identity/' in path:unit='native_identity_number'
        if key.endswith('_us'):unit='microsecond'
        if key in ('exits','repetition','samples','sequence','nr_periods','nr_throttled'):unit='count'
        if key in ('time','heartbeat'):unit='second since epoch'
        if path.endswith('/window_boottime_ns/*') or path.endswith('/latencies_ns/*') or '/latency_ns/' in path and key in ('p95','*'):unit='nanosecond'
        if path.endswith('/member_pids/*'):unit='PID'
        if key in ('swap_in_pages','swap_out_pages'):unit='page'
        if key in ('wakeups','thermal_throttle_count','deadline_misses','oom_events','unexpected_restarts'):unit='event'
        if path.endswith('/throughput_bytes_per_second'):unit='byte/second'
        if key=='tick_bits':unit='bit'
        if key in ('busy_ticks','user_ticks','system_ticks','irq_ticks','softirq_ticks','steal_ticks','idle_ticks','other_cpu_usec','utime_ticks','stime_ticks','wakeups','swap_in_pages','swap_out_pages','network_rx_bytes','network_tx_bytes','thermal_throttle_count') or '/cpu/' in path or '/io/' in path or '/io_other/' in path or key.startswith('cpu_exited_'):
            kind='cumulative counter';monotonic=True
        if '/memory_events/' in path:kind='cumulative counter';monotonic=True;unit='event'
        if '/failure_domains/' in path or path.startswith('/traffic/') and key in ('monitor_misses','oom_events','unexpected_restarts'):
            kind='event count';unit='event';bound='zero under qualification failure policy'
        if key in ('pss_bytes','rss_bytes','uss_bytes','memory_current_bytes','swap_current_bytes'):
            bound='MemTotal (or SwapTotal for swap), plus declared subset/partition equations'
        if unit in ('microsecond','tick') and kind=='cumulative counter':bound='host boot/lifetime capacity and host cumulative class subsets where attribution exists'
        if key=='user_usec' or key=='system_usec':parent='cpu.usage_usec';siblings=['user_usec','system_usec']
        if key=='nr_throttled':parent='cpu.nr_periods';siblings=['nr_throttled','unrecorded_unthrottled_periods']
        if key in ('user_ticks','system_ticks','irq_ticks','softirq_ticks','steal_ticks'):parent='host.busy_ticks';siblings=['user_ticks','system_ticks','irq_ticks','softirq_ticks','steal_ticks']
        if key in ('anon','file','kernel'):parent='memory_current_bytes';siblings=['anon','file','kernel','memory_stat_other_bytes']
        memory_parent={'shmem':'file','anon_thp':'anon','file_thp':'file','shmem_thp':'shmem','kernel_stack':'kernel','pagetables':'kernel','sec_pagetables':'kernel','percpu':'kernel','vmalloc':'kernel','slab':'kernel','slab_reclaimable':'slab','slab_unreclaimable':'slab','file_mapped':'file','file_dirty':'file','file_writeback':'file'}
        if '/memory_stat/' in path and key in memory_parent:parent='memory_stat.'+memory_parent[key];siblings=[key,'unrecorded_nonnegative_remainder (overlapping subsets are never summed)']
        if '/samples/' in path and '/domains/' in path:
            section=path.split('/')[5]
            source={'cpu':'cgroup v2 cpu.stat','memory_current_bytes':'cgroup v2 memory.current','memory_stat':'cgroup v2 memory.stat','memory_events':'cgroup v2 memory.events','io':'cgroup v2 io.stat','io_other':'original independently acquired completed IO residual evidence','member_pids':'cgroup v2 cgroup.procs','pids_current':'cgroup v2 pids.current','swap_current_bytes':'cgroup v2 memory.swap.current'}.get(section,'original independently acquired '+section+' evidence')
        if '/samples/' in path and '/processes/' in path:
            source={'pid':'/proc/PID/stat field 1','start_ticks':'/proc/PID/stat field 22','utime_ticks':'/proc/PID/stat field 14','stime_ticks':'/proc/PID/stat field 15','threads':'/proc/PID/stat field 20','pss_bytes':'/proc/PID/smaps_rollup Pss','rss_bytes':'/proc/PID/smaps_rollup Rss','uss_bytes':'/proc/PID/smaps_rollup Private_Clean + Private_Dirty','swap_bytes':'/proc/PID/smaps_rollup Swap','swap_pss_bytes':'/proc/PID/smaps_rollup SwapPss','fds':'/proc/PID/fd entry enumeration','wakeups':'/proc/PID/sched se.statistics.nr_wakeups'}.get(key,'original reviewed per-process completed block IO evidence')
        native_width='u64 normalized original producer value; platform semantics require review'
        width=64
        if unit=='tick':native_width='unsigned long, 64-bit host required'
        if key in ('pid','threads','pid_max') or path.endswith('/member_pids/*'):
            native_width='Linux signed 32-bit pid/task integer';width=31
        if unit=='byte' and ('smaps_rollup' in source):native_width='unsigned long 64-bit kB, checked multiply by 1024 into u64'
        entry=dict(name=name,path=path,source={'file':source,'field':path},kind=kind,unit=unit,width=width,rust_width='u64 recorded representation',kernel_width=native_width,
                   monotonic=monotonic,parent_total=parent,sibling_set=siblings,physical_upper_bound=bound,absence_allowed=optional,
                   minimum=node.get('minimum',node.get('const',0)),maximum=node.get('maximum',node.get('const',U64)),
                   checks=['quantity:'+name],mutation_test='QuantityModelTests.test_schema_inventory_and_model_check_mutation_completeness')
        if path.startswith('/runtime_evidence/'):
            entry['absence_allowed']=True
            entry['null_allowed']=True
        if 'enum' in node:entry['enum']=node['enum']
        entries.append(entry)
    entries=list({entry['path']:entry for entry in entries}.values())
    for entry in entries:
        entry['object_alternative']=any(other['path'].startswith(entry['path']+'/') for other in entries)
    rules=[]
    def partition(id,scope,parent,children,tol=0,lower=None,when=(),pairs=()):
        rules.append(dict(id=id,scope=scope,operator='partition',parent=parent,children=children,upper_tolerance=tol,
                          lower_tolerance=tol if lower is None else lower,when_present=list(when),presence_pairs=list(pairs),
                          derivation='endpoint CPU quantization/read skew' if tol!=0 else 'exact aligned partition' if lower is None else 'subset: omitted siblings are nonnegative and at most the whole parent',
                          mutation_test='QuantityModelTests.test_relation_boundaries_and_consumer_mutations'))
    def subset(id,scope,parent,child,tol=0,when=(),pairs=()):partition(id,scope,parent,[child],tol,lower=parent,when=when,pairs=pairs)
    add=lambda *xs:['add',*xs]
    mul=lambda *xs:['mul',*xs]
    sub=lambda x,y:['sub',x,y]
    div=lambda x,y:['div',x,y]
    delta=lambda x:['delta',x]
    sm=lambda collection,field:['sum',collection,field]
    sd=lambda collection,field:['sum_delta',collection,field]
    # w0+w1 = 2*w1 - delta(width).
    widths=sub(mul(2,sub('s.read_end_ns','s.mono_ns')),sub(delta('s.read_end_ns'),delta('s.mono_ns')))
    skew=div(mul(widths,'h.logical_cpus'),1000)
    outer=sub('s.read_end_ns',['sub','s.mono_ns',delta('s.mono_ns')])
    capacity=div(mul(outer,'h.logical_cpus','h.tick_hz'),10**9)
    partition('host_clock','interval',capacity,[delta('c.busy_ticks'),delta('c.idle_ticks')],add(mul(16,'h.logical_cpus'),div(mul(widths,'h.logical_cpus','h.tick_hz'),10**9)))
    # Boot capacity is only an upper bound: no uptime-online history is claimed.
    subset('host_boot','sample',add(div(mul('s.read_end_ns','h.tick_hz','h.logical_cpus'),10**9),mul(16,'h.logical_cpus')),add('c.busy_ticks','c.idle_ticks'))
    partition('host_parts','sample','c.busy_ticks',['c.'+k for k in ('user_ticks','system_ticks','irq_ticks','softirq_ticks','steal_ticks')])
    for cls,hostfield in [('usage','busy'),('user','user'),('system','system')]:
        field={'usage':'usage_usec','user':'user_usec','system':'system_usec'}[cls]
        host=div(mul('c.'+hostfield+'_ticks',10**6),'h.tick_hz')
        tol=add(div(mul(4 if cls!='usage' else 12,'h.logical_cpus',10**6),'h.tick_hz'),div(mul(sub('s.read_end_ns','s.mono_ns'),'h.logical_cpus'),1000))
        subset('snapshot_domain_cpu' if cls=='usage' else 'snapshot_domain_'+cls,'sample',host,sm('groups','item.cpu.'+field),tol)
        ps=sm('processes','item.utime_ticks') if cls=='user' else sm('processes','item.stime_ticks') if cls=='system' else add(sm('processes','item.utime_ticks'),sm('processes','item.stime_ticks'))
        subset('snapshot_process_'+cls,'sample','c.'+hostfield+'_ticks',ps,add(mul(4 if cls!='usage' else 12,'h.logical_cpus'),div(mul(sub('s.read_end_ns','s.mono_ns'),'h.logical_cpus','h.tick_hz'),10**9)))
    for field in ('pss_bytes','uss_bytes'):subset('sum_'+field,'sample','h.memory_total_bytes',sm('processes','item.'+field))
    subset('sum_charges','sample','h.memory_total_bytes',sm('groups','item.memory_current_bytes'))
    subset('sum_threads','sample','h.pid_max',sm('processes','item.threads'))
    subset('swap_host','sample','h.swap_total_bytes','c.swap_used_bytes')
    subset('swap_pss','sample','c.swap_used_bytes',sm('processes','item.swap_pss_bytes'))
    subset('swap_charges','sample','c.swap_used_bytes',sm('groups','item.swap_current_bytes'))
    for id,parent,child in [('uss_pss','p.pss_bytes','p.uss_bytes'),('pss_rss','p.rss_bytes','p.pss_bytes'),('rss_ram','h.memory_total_bytes','p.rss_bytes'),('swap_order','p.swap_bytes','p.swap_pss_bytes'),('fd_limit','h.max_fd_entries','p.fds'),('pid_limit','h.pid_max','p.pid'),('thread_limit','h.pid_max','p.threads'),('process_start',div(mul('s.read_end_ns','h.tick_hz'),10**9),'p.start_ticks')]:subset(id,'process',parent,child)
    lifetime=sub(div(mul('s.read_end_ns','h.tick_hz'),10**9),'p.start_ticks')
    subset('process_lifetime','process',add(mul(lifetime,'h.logical_cpus'),mul(2,'h.logical_cpus')),add('p.utime_ticks','p.stime_ticks'))
    partition('domain_parts','domain','d.cpu.usage_usec',['d.cpu.user_usec','d.cpu.system_usec'],2)
    partition('exited_parts','domain','d.cpu_exited_usec',['d.cpu_exited_user_usec','d.cpu_exited_system_usec'])
    partition('memory_parts','domain','d.memory_current_bytes',['d.memory_stat.'+k for k in ('anon','file','kernel')]+['d.memory_stat_other_bytes'])
    partition('memory_charge','domain','d.memory_current_bytes',[sm('members','item.uss_bytes'),'d.memory_other_bytes'])
    partition('pids','domain','d.pids_current',[sm('members','item.threads')])
    subset('domain_boot','domain',div(mul('s.read_end_ns','h.logical_cpus'),1000),'d.cpu.usage_usec')
    subset('native_sock','domain','d.memory_current_bytes','d.memory_stat.sock')
    for key,parent in memory_parent.items():subset('native_'+key,'domain','d.memory_stat.'+parent,'d.memory_stat.'+key,when=['d.memory_stat.'+key])
    subset('native_slab_subset','domain','d.memory_stat.slab',['present_sum','d.memory_stat',['slab_reclaimable','slab_unreclaimable']],when=['d.memory_stat.slab'])
    # Overlapping byte subsets are not siblings. These disjoint native pieces
    # are partitions only when all members are present.
    partition('native_slab_parts','domain','d.memory_stat.slab',['d.memory_stat.slab_reclaimable','d.memory_stat.slab_unreclaimable'],when=['d.memory_stat.slab','d.memory_stat.slab_reclaimable','d.memory_stat.slab_unreclaimable'])
    subset('native_kernel_components','domain','d.memory_stat.kernel',['present_sum','d.memory_stat',['kernel_stack','pagetables','sec_pagetables','percpu','vmalloc','slab']])
    subset('native_throttled_periods','domain','d.cpu.nr_periods','d.cpu.nr_throttled',when=['d.cpu.nr_periods','d.cpu.nr_throttled'],pairs=[{'object':'d.cpu','keys':['nr_periods','nr_throttled']}])
    subset('native_throttled_period_deltas','domain_interval',delta('d.cpu.nr_periods'),delta('d.cpu.nr_throttled'),when=['d.cpu.nr_periods','d.cpu.nr_throttled'])
    for id,prefix in [('io_read','r'),('io_write','w'),('io_discard','d')]:
        for scope,suffix in [('io',''),('io_interval','_delta')]:
            byte='io.'+prefix+'bytes';ops='io.'+prefix+'ios'
            rules.append(dict(id=id+suffix,scope=scope,operator='completed_io',parent=byte if not suffix else delta(byte),children=[ops if not suffix else delta(ops)],when_present=[byte,ops],presence_pairs=[{'object':'io','keys':[prefix+'bytes',prefix+'ios']}],derivation='each completed data operation transfers at least one byte: 0 <= operations <= bytes, and zero iff zero; no device bandwidth assumption',mutation_test='QuantityModelTests.test_relation_boundaries_and_consumer_mutations'))
    # Original residuals plus stable member CPU at all anchored endpoints.
    member_tol=add(div(mul(2,['len','members'],10**6),'h.tick_hz'),skew)
    for cls in ('usage','user','system'):
        process_ticks=add(sd('members','item.utime_ticks'),sd('members','item.stime_ticks')) if cls=='usage' else sd('members','item.'+('utime_ticks' if cls=='user' else 'stime_ticks'))
        exited='d.cpu_exited_'+('' if cls=='usage' else cls+'_')+'usec'
        partition('member_cpu_'+cls,'domain_interval',delta('d.cpu.'+cls+'_usec'),[div(mul(process_ticks,10**6),'h.tick_hz'),delta(exited)],member_tol)
    # Express aggregate deltas directly with the generic delta expression.
    aggregate=lambda expr:sub(expr,['before',expr])
    partition('host_charge','interval',div(mul(delta('c.busy_ticks'),10**6),'h.tick_hz'),[aggregate(sm('groups','item.cpu.usage_usec')),delta('c.other_cpu_usec')],add(div(mul(12,'h.logical_cpus',10**6),'h.tick_hz'),skew))
    for cls in ('user','system'):
        subset('domain_'+cls+'_delta','interval',div(mul(delta('c.'+cls+'_ticks'),10**6),'h.tick_hz'),aggregate(sm('groups','item.cpu.'+cls+'_usec')),add(div(mul(4,'h.logical_cpus',10**6),'h.tick_hz'),skew))
    subset('domain_capacity','domain_interval',div(mul(outer,'h.logical_cpus'),1000),delta('d.cpu.usage_usec'))
    for direction in ('rx','tx'):subset('network_'+direction,'interval',div(mul('h.link_capacity_bps',outer),8*10**9),delta('c.network_'+direction+'_bytes'))
    partition('io_conservation','device_interval',delta(['device_get','d.io']),[delta(['device_get','d.io_other']),aggregate(sm('members',['device_get','item.io']))])
    for entry in entries:
        # Relation links are actual machine-readable cross references, not an
        # assertion that this finite model proves every possible kernel law.
        entry['relation_checks']=[r['id'] for r in rules if entry['path'].split('/')[-1] in json.dumps([r['parent'],r['children']])]
    model=dict(schema=1,description='Closed recorded-quantity semantics; finite offline consistency model, no authenticity/performance/release proof.',
               clock_contract=dict(field='cpu_clock_contract',value='constant_online_no_suspend',scope='whole recorded window only; no boot-history lower bound'),quantities=entries,native_maps=maps,relations=rules)
    for name,value in [('run-schema.json',schema),('quantity-model.json',model)]:
        (ROOT/name).write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')


if __name__=='__main__':author()
