"""Author the closed schema inventory and declarative quantity model, offline.

Run with python3 -B -I. Relations are derived from kernel-identities.json. Quantity changes require
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


def relation_operands(rule):
    """Exact final field names a relation reads (dotted refs, path rules, present_sum keys)."""
    def names(node):
        if type(node) is str:
            if node.startswith('/'):return {node.split('/')[-1]}
            return {node.split('.')[-1]} if '.' in node else set()
        if type(node) is list and node:
            if node[0]=='present_sum':return names(node[1])|set(node[2])
            return set().union(*(names(value) for value in node))
        return set()
    return set().union(*(names(rule.get(k)) for k in ('parent','children','path','antecedent','consequent')))


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
        if unit=='byte' and ('smaps_rollup' in source):native_width='unsigned long 64-bit integer kB, checked multiply by 1024 into u64; normalized quantum 1024 bytes'
        if key=='fds':
            native_width='count of distinct nonnegative signed-int descriptor numbers, cardinality <= INT_MAX+1'
            bound='native descriptor namespace cardinality <= 2**31, plus reviewed max_fd_entries; shared file descriptions are not distinct entries'
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
    # Identity equations are source data, independent of schema inventory.
    spec=importlib.util.spec_from_file_location('_kernel_catalog_author',ROOT/'kernel_identities.py')
    identities=importlib.util.module_from_spec(spec);spec.loader.exec_module(identities)
    rules=identities.derive_relations(schema)
    for entry in entries:
        # Relation links are actual machine-readable cross references, not an
        # assertion that this finite model proves every possible kernel law.
        name=entry['path'].split('/')[-1]
        entry['relation_checks']=[r['id'] for r in rules if name in relation_operands(r)]
    model=dict(schema=1,description='Closed recorded-quantity semantics; finite offline consistency model, no authenticity/performance/release proof.',
               clock_contract=dict(field='cpu_clock_contract',value='constant_online_no_suspend',scope='whole recorded window only; no boot-history lower bound'),quantities=entries,native_maps=maps,relations=rules)
    for name,value in [('run-schema.json',schema),('quantity-model.json',model)]:
        (ROOT/name).write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')


if __name__=='__main__':author()
