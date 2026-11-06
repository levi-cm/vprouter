"""Pure offline accounting contracts. No host reads, clock reads, traffic or writes.

Schema 1 is specified in docs/rust-v2/performance-harness.md. Native text and
JSON values are caller-supplied. Measurements remain unproven without original
runtime/traffic evidence and independent source/coverage review.
"""
from fractions import Fraction
import hashlib
import importlib.util
import json
from pathlib import Path
import re

# Explicit sibling loading also works with python3 -B -I (no sys.path edits).
_spec = importlib.util.spec_from_file_location('_performance_contract', Path(__file__).with_name('measurement.py'))
_contract = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_contract)

U64 = 2**64-1
MAX_TEXT = 1048576
MAX_SAMPLES = 10001
MAX_VALUES = 10000
MAX_RUNS = 128
MIN_REPETITIONS = 6
NS = 10**9
MIB = 1024**2
CONTROL = {'supervision','workers','guard','init_shim'}
SERVICE = CONTROL | {'container','tailscaled'}
COMPONENTS = SERVICE | {'observer','workload'}
SCENARIOS = [(n, mode) for n in (1,5,6) for mode in ('steady','load')]

# Normative physical/accounting registry. Every row is exercised on raw records
# in both directions at one unit and a large excursion. Missing rows/tests fail
# completeness. All equations also run at anchored prefixes, never a sum of
# adjacent rounding allowances. Provenance/shape/availability checks are separate.
INVARIANT_REGISTRY = {
    name: dict(equation=equation, reason=reason, status='INSUFFICIENT_DATA',
               enforced_by='check_invariants',
               test='PhysicalRegistryTests.test_raw_signed_boundary_mutations')
    for name,equation,reason in (
        ('cpu_members','abs(domain usage - stable ticks - exited CPU) <= endpoint tolerance','cpu_accounting_contradiction'),
        ('cpu_user','member user ticks <= domain user; sum domain user <= host user, endpoint tolerance','cpu_component_contradiction'),
        ('cpu_system','member system ticks <= domain system; sum domain system <= host system, endpoint tolerance','cpu_component_contradiction'),
        ('cpu_parts','abs(user+system-usage) <= 2 us at snapshot, <=4 us across endpoints','cpu_inconsistent'),
        ('cpu_exited','exited user+system = exited usage','cpu_exited_contradiction'),
        ('cpu_busy_parts','host user+system+irq+softirq+steal = busy','cpu_breakdown_contradiction'),
        ('cpu_irq_subset','irq+softirq <= busy (same atomic host read)','cpu_subset_contradiction'),
        ('cpu_host_charge','abs(host busy - disjoint domain CPU - outside CPU) <= endpoint tolerance','system_cpu_contradiction'),
        ('cpu_capacity','busy+idle <= elapsed*ncpu + endpoint tick allowance','cpu_time_contradiction'),
        ('domain_capacity','domain usage <= elapsed*ncpu','cpu_time_contradiction'),
        ('pss_ram','sum process PSS <= MemTotal','system_memory_contradiction'),
        ('uss_ram','sum process USS <= MemTotal','system_memory_contradiction'),
        ('rss_ram','each process RSS <= MemTotal (never sum RSS)','system_memory_contradiction'),
        ('uss_pss','0 <= USS <= PSS','process_memory_inconsistent'),
        ('pss_rss','0 <= PSS <= RSS','process_memory_inconsistent'),
        ('memory_charge','sum member USS + nonnegative charge residual = memory.current','memory_accounting_contradiction'),
        ('memory_parts','anon+file+kernel+other = memory.current','memory_breakdown_contradiction'),
        ('memory_sock','sock <= memory.current','memory_breakdown_contradiction'),
        ('charges_ram','sum disjoint memory.current <= MemTotal','system_memory_contradiction'),
        ('swap_order','0 <= process SwapPss <= Swap','swap_accounting_contradiction'),
        ('swap_ram','0 <= host swap used <= swap total','swap_accounting_contradiction'),
        ('swap_pss','sum process SwapPss <= host swap used','swap_accounting_contradiction'),
        ('swap_charge','sum disjoint cgroup swap.current <= host swap used','swap_accounting_contradiction'),
        ('pids_threads','sum member threads = pids.current','pids_accounting_contradiction'),
        ('pid_bound','1 <= PID <= pid_max','pids_accounting_contradiction'),
        ('fds_bound','0 <= each FD entry count <= max_fd_entries','fd_accounting_contradiction'),
        ('threads_bound','1 <= threads <= pid_max','pids_accounting_contradiction'),
        ('io_conservation','per-device completed IO = member IO + original residual','io_accounting_contradiction'),
        ('counter_monotonic','all CPU, IO, event counters nondecreasing with fixed keys/identities','counter_regression'),
        ('wakeups_monotonic','wakeups nonnegative, nondecreasing for stable identity','counter_regression'),
        ('network_monotonic','physical link RX/TX bytes nondecreasing','counter_regression'),
        ('network_capacity','each direction bytes*8 <= bps*elapsed (full duplex)','network_capacity_contradiction'),
        ('network_payload','delivered payload <= physical link RX+TX bytes','network_payload_contradiction'),
        ('swap_quiet','no swap usage, swap-in or swap-out anywhere in run','swap_contamination'),
        ('thermal_quiet','temperature < limit; no thermal throttle events','thermal_contamination'),
        ('numeric_domain','every numeric leaf is an unsigned u64 integer; semantic minima also validated','invalid_run'),
        ('sample_clock','ordered nonoverlapping brackets, cadence, duration and boottime/wall coherence','clock_accounting_contradiction'),
        ('coverage','stable identities; complete disjoint domains, membership and component coverage','incomplete_process_coverage'),
        ('metric_availability','all mandatory physical measurements available, never zero-filled','missing_metric'),
        ('failure_quiet','no measured failure in any role, domain, traffic or warm-up','measured_domain_failure'),
        ('process_start','process start tick <= current boot-clock tick','process_lifetime_contradiction'),
        ('process_lifetime_cpu','process cumulative CPU <= lifetime*ncpu + 2*ncpu ticks','process_lifetime_contradiction'),
        ('host_boot_cpu','host cumulative busy+idle <= boot elapsed*ncpu + 16*ncpu ticks','cpu_time_contradiction'),
        ('domain_boot_cpu','cgroup cumulative CPU <= boot elapsed*ncpu','cpu_time_contradiction'),
    )
}


def require(ok, code):
    if not ok:
        raise ValueError(code)


def integer(v, minimum=0, maximum=U64):
    require(type(v) is int and minimum <= v <= maximum, 'invalid_integer')
    return v


def scalar(v):
    require(type(v) in (int,Fraction) and 0 <= v <= U64, 'invalid_number')
    return v


def fields(v, names):
    require(type(v) is dict and set(v) == set(names.split()), 'schema_fields')


def identifier(v):
    require(type(v) is str and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,95}',v) is not None, 'invalid_identifier')
    return v


def digest(v):
    require(type(v) is str and re.fullmatch('[0-9a-f]{64}',v) is not None, 'invalid_sha256')
    return v


def canonical(v):
    def exact(value):
        if type(value) is Fraction:
            return value.numerator if value.denominator==1 else dict(numerator=value.numerator,denominator=value.denominator)
        raise TypeError('unsupported_json_value')
    return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False,default=exact).encode('ascii')


def record_digest(run):
    """Bind all original accounting bytes semantically, excluding traffic sidecar."""
    return hashlib.sha256(canonical({k:v for k,v in run.items() if k != 'runtime_evidence'})).hexdigest()


def text_lines(raw):
    require(type(raw) is str and len(raw) <= MAX_TEXT and raw.isascii() and '\x00' not in raw, 'native_text_bound')
    return raw.splitlines()


def unsigned(raw, maximum=U64):
    require(type(raw) is str and re.fullmatch(r'0|[1-9][0-9]{0,19}',raw) is not None, 'unsigned_decimal')
    return integer(int(raw),maximum=maximum)


def parse_smaps_rollup(raw):
    lines=text_lines(raw)
    require(lines and re.fullmatch(r'[0-9a-f]+-[0-9a-f]+ [rwxps-]{4} [0-9a-f]+ [0-9a-f]+:[0-9a-f]+ [0-9]+\s+\[rollup\]',lines[0]) is not None,'smaps_header')
    address=lines[0].split()[0].split('-')
    require(all(len(v)<=16 for v in address) and int(address[0],16)<int(address[1],16),'smaps_address_range')
    known={'Rss','Pss','Pss_Dirty','Pss_Anon','Pss_File','Pss_Shmem','Shared_Clean','Shared_Dirty',
           'Private_Clean','Private_Dirty','Referenced','Anonymous','KSM','LazyFree','AnonHugePages',
           'ShmemPmdMapped','FilePmdMapped','Shared_Hugetlb','Private_Hugetlb','Swap','SwapPss','Locked'}
    values={}
    for line in lines[1:]:
        parts=line.split()
        require(len(parts)==3 and parts[0].endswith(':') and parts[2]=='kB','smaps_units')
        key=parts[0][:-1]
        require(key in known and key not in values,'smaps_unknown_or_duplicate')
        values[key]=integer(unsigned(parts[1])*1024)
    require({'Rss','Pss','Private_Clean','Private_Dirty'} <= set(values),'smaps_missing')
    # Hugetlb pages are excluded by Linux Rss/Pss; cannot silently omit them.
    require(not values.get('Private_Hugetlb',0) and not values.get('Shared_Hugetlb',0),'hugetlb_unrepresented')
    uss=integer(values['Private_Clean']+values['Private_Dirty'])
    require(uss <= values['Pss'] <= values['Rss'],'smaps_inconsistent')
    return dict(rss_bytes=values['Rss'],pss_bytes=values['Pss'],uss_bytes=uss)


def parse_proc_stat(raw, tick_bits=64):
    require(tick_bits in (32,64) and type(tick_bits) is int,'tick_width')
    lines=text_lines(raw)
    require(len(lines)==1,'stat_lines')
    match=re.fullmatch(r'([1-9][0-9]*) \((.*)\) (.*)',raw.rstrip('\n'))
    require(match is not None,'stat_shape')
    values=match[3].split()
    require(20 <= len(values) <= 64 and values[0] in ('R','S','D','Z','T','W','t','X','x','K','P','I'),'stat_fields')
    require(values[0] not in ('Z','X','x','T','t'),'terminal_or_stopped_process')
    result=dict(pid=unsigned(match[1]),start_ticks=unsigned(values[19]),utime_ticks=unsigned(values[11],2**tick_bits-1),
                stime_ticks=unsigned(values[12],2**tick_bits-1),threads=unsigned(values[17]))
    require(result['pid']>0 and result['start_ticks']>0 and result['threads']>0,'stat_identity')
    integer(result['utime_ticks']+result['stime_ticks'])
    # Validate every remaining numeric field too; signed fields exist in proc stat.
    for v in values[1:]:
        require(re.fullmatch(r'-?(0|[1-9][0-9]{0,19})',v) is not None and -2**63 <= int(v) <= U64,'stat_numeric')
    return result


def parse_wakeups(raw):
    seen=set(); result=None
    for line in text_lines(raw):
        if ':' not in line: continue  # sched's title and ruler are not counters.
        key,value=(v.strip() for v in line.split(':',1))
        require(key not in seen,'duplicate_sched_key'); seen.add(key)
        if key=='se.statistics.nr_wakeups': result=unsigned(value)
    return result  # CONFIG_SCHEDSTATS absent is unavailable, never zero.


def parse_fd_entries(names):
    require(type(names) is list and len(names)<=65536,'fd_bound')
    require(all(type(n) is str for n in names) and len(set(names))==len(names),'fd_duplicate')
    for name in names: unsigned(name)
    return len(names)


def pairs(raw, required):
    result={}
    for line in text_lines(raw):
        p=line.split()
        require(len(p)==2 and re.fullmatch('[a-z][a-z0-9_]*',p[0]) is not None and p[0] not in result,'native_key_value')
        require(len(result)<256,'native_key_bound')
        result[p[0]]=unsigned(p[1])
    require(set(required)<=set(result),'native_required_fields')
    return result


def parse_io(raw):
    result={}
    for line in text_lines(raw):
        p=line.split()
        require(len(p)>=5 and re.fullmatch(r'(0|[1-9][0-9]*):(0|[1-9][0-9]*)',p[0]) is not None and p[0] not in result,'io_device')
        for n in p[0].split(':'): unsigned(n,2**32-1)
        entry={}
        for item in p[1:]:
            kv=item.split('=')
            require(len(kv)==2 and kv[0] in {'rbytes','wbytes','rios','wios','dbytes','dios'} and kv[0] not in entry,'io_key')
            entry[kv[0]]=unsigned(kv[1])
        require({'rbytes','wbytes','rios','wios'}<=set(entry),'io_missing')
        require(len(result)<256,'io_device_bound'); result[p[0]]=entry
    return dict(sorted(result.items()))


def parse_cgroup(*, cpu_stat, memory_current, memory_stat, memory_events, io_stat, cgroup_procs):
    members=[unsigned(v) for v in text_lines(cgroup_procs)]
    require(len(members)<=4096 and all(v>0 for v in members) and len(set(members))==len(members),'cgroup_members')
    cpu=pairs(cpu_stat,('usage_usec','user_usec','system_usec'))
    require(abs(cpu['user_usec']+cpu['system_usec']-cpu['usage_usec'])<=2,'cpu_inconsistent')
    require(type(memory_current) is str and len(memory_current)<=32,'memory_current_bound')
    return dict(cpu=cpu,memory_current_bytes=unsigned(memory_current.removesuffix('\n')),
                memory_stat=pairs(memory_stat,('anon','file','kernel','sock')),
                memory_events=pairs(memory_events,('oom','oom_kill')),io=parse_io(io_stat),member_pids=sorted(members))


def percentile(values, percent):
    """Nearest-rank (ceil(p*n)), no interpolation; caller has validated values."""
    ordered=sorted(values)
    return ordered[(percent*len(ordered)+99)//100-1]


def describe(values):
    require(type(values) is list and 1<=len(values)<=MAX_VALUES,'statistics_bound')
    for v in values: scalar(v)
    x=sorted(values); n=len(x)
    median=lambda v: (Fraction(v[(len(v)-1)//2])+Fraction(v[len(v)//2]))/2
    med=median(x); deviations=sorted(abs(v-med) for v in x); mad=median(deviations)
    # Exact distribution-free two-sided median CI, coverage at least 95%.
    # 2*P[Binomial(n,1/2)<k] <= .05, largest k; n<6 has no finite 95% CI.
    tail=0; combination=1; k=0; power=1<<n
    for index in range((n+1)//2):
        tail+=combination
        if 40*tail>power: break
        k=index+1
        combination=combination*(n-index)//(index+1)
    ci=[x[k-1],x[n-k]] if k else None
    outliers=[v for v in x if (abs(v-med)>3*mad if mad else v!=med)]
    return dict(samples=n,min=x[0],max=x[-1],median=med,p95=percentile(x,95),p99=percentile(x,99),
                mad=mad,median_ci95=ci,outliers=outliers,outlier_policy='retain_all_flag_beyond_3_MAD',
                percentile_method='nearest_rank_no_interpolation',ci_method='exact_binomial_order_statistics_95_percent')


def counter_map(v, required=()):
    require(type(v) is dict and len(v)<=256 and set(required)<=set(v),'counter_fields')
    for key,value in v.items(): identifier(key); integer(value)


def validate_domain_sample(v):
    fields(v,'cpu memory_current_bytes memory_stat memory_events io member_pids pids_current cpu_exited_usec cpu_exited_user_usec cpu_exited_system_usec swap_current_bytes memory_other_bytes memory_stat_other_bytes io_other')
    for k in ('pids_current','cpu_exited_usec','cpu_exited_user_usec','cpu_exited_system_usec','swap_current_bytes','memory_other_bytes','memory_stat_other_bytes'): integer(v[k])
    validate_io(v['io_other'])
    members=v['member_pids'];require(type(members) is list and len(members)<=4096,'cgroup_members')
    for pid in members: integer(pid,1)
    require(len(set(members))==len(members),'duplicate_cgroup_member')
    counter_map(v['cpu'],('usage_usec','user_usec','system_usec'))
    require(abs(v['cpu']['user_usec']+v['cpu']['system_usec']-v['cpu']['usage_usec'])<=2,'cpu_inconsistent')
    integer(v['memory_current_bytes'])
    counter_map(v['memory_stat'],('anon','file','kernel','sock'))
    counter_map(v['memory_events'],('oom','oom_kill'))
    validate_io(v['io'])


def regression(old,new):
    return set(old)!=set(new) or any(new[k]<v for k,v in old.items())


def rate(counter, duration_ns, unit, tick_hz=None):
    """Exact cores (CPU us/ticks) or bytes/s. No floating intermediates."""
    integer(counter); integer(duration_ns,1)
    require(unit in ('cpu_usec','bytes','ticks'),'rate_unit')
    scale=1000 if unit=='cpu_usec' else NS
    denominator=duration_ns*(integer(tick_hz,1) if unit=='ticks' else 1)
    return Fraction(counter*scale,denominator)


def validate_io(value):
    require(type(value) is dict and len(value)<=256,'io_bound')
    for key,entry in value.items():
        require(type(key) is str and re.fullmatch(r'[0-9]+:[0-9]+',key) is not None,'io_device')
        for part in key.split(':'): unsigned(part,2**32-1)
        require(type(entry) is dict and {'rbytes','wbytes','rios','wios'} <= set(entry) <= {'rbytes','wbytes','rios','wios','dbytes','dios'},'io_fields')
        counter_map(entry)


def check_reconciliation(sample, previous, current, old_processes, host, reasons):
    """Aligned residuals are producer evidence, never inferred from a mismatch.

    Two ticks/member cover user+system quantization across endpoints. CPU read
    skew is bounded by elapsed read brackets * logical CPUs. Memory and I/O
    have no rate bound: exact reconciled observations are required, not epsilon.
    """
    hz=host['tick_hz']; cpus=host['logical_cpus']; groups=sample['domains']
    for name,d in groups.items():
        members=[p for p in current.values() if p['domain']==name]
        if all(p['threads'] is not None for p in members):
            if sum(p['threads'] for p in members)!=d['pids_current']: reasons.add('pids_accounting_contradiction')
        if all(p['uss_bytes'] is not None for p in members):
            if sum(p['uss_bytes'] for p in members)+d['memory_other_bytes']!=d['memory_current_bytes']: reasons.add('memory_accounting_contradiction')
        # RSS is not summed (shared mappings duplicate it); USS and disjoint
        # cgroup charges may be summed only under the reviewed isolated policy.
        if any(p['rss_bytes'] is not None and p['rss_bytes']>host['memory_total_bytes'] for p in members): reasons.add('system_memory_contradiction')
        stat=d['memory_stat']
        if sum(stat[k] for k in ('anon','file','kernel'))+d['memory_stat_other_bytes']!=d['memory_current_bytes'] or stat['sock']>d['memory_current_bytes']:
            reasons.add('memory_breakdown_contradiction')
        if previous is None: continue
        old=previous['domains'][name]
        if d['cpu_exited_usec']<old['cpu_exited_usec']: reasons.add('counter_regression')
        if set(d['io_other'])!=set(old['io_other']) or any(regression(old['io_other'][dev],d['io_other'][dev]) for dev in set(old['io_other'])&set(d['io_other'])): reasons.add('counter_regression')
        stable=[(p,old_processes[key]) for key,p in current.items() if key in old_processes and p['domain']==name]
        if len(stable)!=len(members) or any(p[k] is None or q[k] is None for p,q in stable for k in ('utime_ticks','stime_ticks')): continue
        ticks=sum(p[k]-q[k] for p,q in stable for k in ('utime_ticks','stime_ticks'))
        expected=Fraction(ticks*10**6,hz)+d['cpu_exited_usec']-old['cpu_exited_usec']
        observed=d['cpu']['usage_usec']-old['cpu']['usage_usec']
        skew=sample['read_end_ns']-sample['mono_ns']+previous['read_end_ns']-previous['mono_ns']
        tolerance=Fraction(2*len(stable)*10**6,hz)+Fraction(skew*cpus,1000)
        if abs(observed-expected)>tolerance: reasons.add('cpu_accounting_contradiction')
        capacity=Fraction((sample['read_end_ns']-previous['mono_ns'])*cpus,1000)
        if observed>capacity: reasons.add('cpu_time_contradiction')
        # Native per-device completed block I/O only. Logical syscall bytes are
        # not comparable to io.stat. Residual captures kernel/exited work.
        devices=set(d['io'])|set(old['io'])|set(d['io_other'])|set(old['io_other'])
        for p,q in stable:
            devices|=set(p['io'])|set(q['io'])
            if set(p['io'])!=set(q['io']) or any(regression(q['io'][dev],p['io'][dev]) for dev in set(p['io'])&set(q['io'])): reasons.add('counter_regression')
        for dev in devices:
            keys=set().union(*(v.get(dev,{}) for v in (d['io'],old['io'],d['io_other'],old['io_other'])),
                             *(v['io'].get(dev,{}) for pair in stable for v in pair))
            for k in keys:
                diff=lambda now,before: now.get(dev,{}).get(k,0)-before.get(dev,{}).get(k,0)
                actual=diff(d['io'],old['io'])
                expected=diff(d['io_other'],old['io_other'])+sum(diff(p['io'],q['io']) for p,q in stable)
                if actual!=expected: reasons.add('io_accounting_contradiction')
    if sum(d['memory_current_bytes'] for d in groups.values())>host['memory_total_bytes']: reasons.add('system_memory_contradiction')
    if previous is not None:
        context=sample['host']; before=previous['host']
        if all(context[k] is not None and before[k] is not None for k in ('busy_ticks','other_cpu_usec')):
            busy=Fraction((context['busy_ticks']-before['busy_ticks'])*10**6,hz)
            charged=sum(d['cpu']['usage_usec']-previous['domains'][name]['cpu']['usage_usec'] for name,d in groups.items())
            residual=context['other_cpu_usec']-before['other_cpu_usec']
            skew=sample['read_end_ns']-sample['mono_ns']+previous['read_end_ns']-previous['mono_ns']
            tolerance=Fraction(12*cpus*10**6,hz)+Fraction(skew*cpus,1000)
            if abs(busy-charged-residual)>tolerance: reasons.add('system_cpu_contradiction')
            if busy>Fraction((sample['read_end_ns']-previous['mono_ns'])*cpus,1000)+tolerance: reasons.add('cpu_time_contradiction')


def physical_constraints(run):
    """Yield named predicates; inputs have passed structural/integer validation.

    Tick endpoint error: each independently rounded counter differs by <1 tick
    at each read, hence a delta by <2 ticks. A process has two tick counters,
    whose combined endpoint allowance is conservatively 2 ticks/member (Linux
    cumulative user+system truncation); host busy has six categories (user
    includes nice), giving 12 ticks/CPU. Capacity adds idle+iowait: 16 ticks/CPU.
    CPU read skew adds (width(first)+width(last))*ncpu ns, converted exactly.
    Each anchored prefix receives this bound ONCE. No sum over sample count.
    Memory/IO/network have no assumed churn/burst rate: require aligned exact
    observations. This can reject skewed acquisitions; it cannot forgive them.
    """
    h=run['host'];hz=h['tick_hz'];ncpu=h['logical_cpus'];samples=run['samples']
    row=lambda name,ok:(name,bool(ok))
    def known(values):return all(v is not None for v in values)
    def proc_key(p):return (p['pid'],p['start_ticks'],p['executable_sha256'],p['domain'],p['component'])
    def numeric(v):
        if type(v) is dict:return all(numeric(x) for x in v.values())
        if type(v) is list:return all(numeric(x) for x in v)
        if type(v) is int:return 0<=v<=U64
        return type(v) in (str,bool) or v is None
    yield row('numeric_domain',numeric(run))
    scopes=[tuple(d['scope']) for d in run['domains']]
    yield row('coverage',len({tuple(d['native_identity']) for d in run['domains']})==len(scopes) and
              not any(p[:len(q)]==q or q[:len(p)]==p for i,p in enumerate(scopes) for q in scopes[i+1:]) and
              set().union(*(set(d['components']) for d in run['domains']))==COMPONENTS)
    yield row('failure_quiet',all(v==0 for signals in run['failure_domains'].values() for v in signals.values()) and
              all(run['traffic'][k]==0 for k in ('monitor_misses','unexpected_restarts','oom_events')) and
              all(d['memory_events'].get(k,0)==samples[0]['domains'][name]['memory_events'].get(k,0)
                  for s in samples for name,d in s['domains'].items() for k in ('oom','oom_kill','oom_group_kill')))
    yield row('sample_clock',samples[-1]['mono_ns']-samples[0]['mono_ns']==run['duration_ns'])
    yield row('sample_clock',max(s['wall_before_ns']-s['read_end_ns'] for s in samples)<=min(s['wall_after_ns']-s['mono_ns'] for s in samples) and
              any(s['mono_ns']-samples[0]['mono_ns']==run['warmup_discard_ns'] for s in samples))
    anchors={0}
    measured=next((i for i,s in enumerate(samples) if s['mono_ns']-samples[0]['mono_ns']>=run['warmup_discard_ns']),0)
    anchors.add(measured)
    for index,s in enumerate(samples):
        c=s['host'];groups=s['domains'];ps=s['processes']
        boot_ticks=Fraction(s['read_end_ns']*hz,NS)
        yield row('host_boot_cpu',known([c['busy_ticks'],c['idle_ticks']]) and c['busy_ticks']+c['idle_ticks']<=boot_ticks*ncpu+16*ncpu)
        yield row('metric_availability',all(v is not None for v in c.values()) and
                  all(p[k] is not None for p in ps for k in ('utime_ticks','stime_ticks','pss_bytes','rss_bytes','uss_bytes','swap_bytes','swap_pss_bytes','threads','fds','wakeups')))
        yield row('sample_clock',s['mono_ns']<=s['read_end_ns']<=s['mono_ns']+run['interval_ns']//10 and
                  s['wall_before_ns']<=s['wall_after_ns']<=s['wall_before_ns']+run['interval_ns']//10)
        yield row('coverage',set(groups)=={d['id'] for d in run['domains']} and
                  {proc_key(p) for p in ps}=={proc_key(p) for p in samples[0]['processes']} and
                  all(set(d['member_pids'])=={p['pid'] for p in ps if p['domain']==name} for name,d in groups.items()))
        threads=[p['threads'] for p in ps]
        yield row('threads_bound',known(threads) and sum(threads)<=h['pid_max'])
        for key,name in [('pss_bytes','pss_ram'),('uss_bytes','uss_ram')]:
            values=[p[key] for p in ps]
            yield row(name,known(values) and sum(values)<=h['memory_total_bytes'])
        yield row('charges_ram',sum(d['memory_current_bytes'] for d in groups.values())<=h['memory_total_bytes'])
        for p in ps:
            yield row('process_start',0<p['start_ticks']<=boot_ticks)
            yield row('process_lifetime_cpu',known([p['utime_ticks'],p['stime_ticks']]) and
                      p['utime_ticks']+p['stime_ticks']<=max(0,boot_ticks-p['start_ticks'])*ncpu+2*ncpu)
            yield row('rss_ram',p['rss_bytes'] is not None and p['rss_bytes']<=h['memory_total_bytes'])
            yield row('uss_pss',known([p['uss_bytes'],p['pss_bytes']]) and 0<=p['uss_bytes']<=p['pss_bytes'])
            yield row('pss_rss',known([p['pss_bytes'],p['rss_bytes']]) and 0<=p['pss_bytes']<=p['rss_bytes'])
            yield row('swap_order',known([p['swap_pss_bytes'],p['swap_bytes']]) and 0<=p['swap_pss_bytes']<=p['swap_bytes'])
            yield row('pid_bound',1<=p['pid']<=h['pid_max'])
            yield row('fds_bound',p['fds'] is not None and 0<=p['fds']<=h['max_fd_entries'])
            yield row('threads_bound',p['threads'] is not None and 1<=p['threads']<=h['pid_max'])
            yield row('wakeups_monotonic',p['wakeups'] is not None and p['wakeups']>=0)
        swap=[p['swap_pss_bytes'] for p in ps]
        yield row('swap_pss',known(swap+[c['swap_used_bytes']]) and sum(swap)<=c['swap_used_bytes'])
        yield row('swap_charge',c['swap_used_bytes'] is not None and sum(d['swap_current_bytes'] for d in groups.values())<=c['swap_used_bytes'])
        yield row('swap_ram',c['swap_used_bytes'] is not None and 0<=c['swap_used_bytes']<=h['swap_total_bytes'])
        yield row('swap_quiet',all(c[k]==0 for k in ('swap_in_pages','swap_out_pages','swap_used_bytes')) and
                  all(d['swap_current_bytes']==0 for d in groups.values()) and all(p['swap_bytes']==0 for p in ps))
        yield row('thermal_quiet',c['temperature_millic'] is not None and 0<=c['temperature_millic']<h['thermal_limit_millic'] and c['thermal_throttle_count']==0)
        parts=('user_ticks','system_ticks','irq_ticks','softirq_ticks','steal_ticks')
        yield row('cpu_busy_parts',known([c[k] for k in parts]+[c['busy_ticks']]) and sum(c[k] for k in parts)==c['busy_ticks'])
        yield row('cpu_irq_subset',known([c[k] for k in ('irq_ticks','softirq_ticks','busy_ticks')]) and c['irq_ticks']+c['softirq_ticks']<=c['busy_ticks'])
        for name,d in groups.items():
            yield row('domain_boot_cpu',d['cpu']['usage_usec']<=Fraction(s['read_end_ns']*ncpu,1000))
            members=[p for p in ps if p['domain']==name]
            threads=[p['threads'] for p in members];uss=[p['uss_bytes'] for p in members]
            yield row('pids_threads',known(threads) and sum(threads)==d['pids_current'])
            yield row('memory_charge',known(uss) and d['memory_other_bytes']>=0 and sum(uss)+d['memory_other_bytes']==d['memory_current_bytes'])
            yield row('memory_parts',sum(d['memory_stat'][k] for k in ('anon','file','kernel'))+d['memory_stat_other_bytes']==d['memory_current_bytes'])
            yield row('memory_sock',d['memory_stat']['sock']<=d['memory_current_bytes'])
            yield row('cpu_parts',abs(d['cpu']['user_usec']+d['cpu']['system_usec']-d['cpu']['usage_usec'])<=2)
            yield row('cpu_exited',d['cpu_exited_user_usec']+d['cpu_exited_system_usec']==d['cpu_exited_usec'])
        # Adjacent checks plus whole-run/measurement anchored prefixes. A bad
        # middle sample cannot be hidden by a final compensating observation.
        for j in sorted(({index-1}|anchors)-{index}):
            if j<0 or j>=index:continue
            before=samples[j];oldc=before['host'];oldps={proc_key(p):p for p in before['processes']}
            elapsed=s['read_end_ns']-before['mono_ns']
            yield row('sample_clock',s['mono_ns']>=before['read_end_ns'] and s['mono_ns']>before['mono_ns'] and
                      (j!=index-1 or abs(s['mono_ns']-before['mono_ns']-run['interval_ns'])<=run['interval_ns']//10))
            skew=s['read_end_ns']-s['mono_ns']+before['read_end_ns']-before['mono_ns']
            skew_us=Fraction(skew*ncpu,1000)
            hd=lambda k:c[k]-oldc[k]
            host_keys=parts+('idle_ticks','busy_ticks','other_cpu_usec','network_rx_bytes','network_tx_bytes',
                             'swap_in_pages','swap_out_pages','thermal_throttle_count')
            yield row('counter_monotonic',all(c[k] is not None and oldc[k] is not None and hd(k)>=0 for k in host_keys))
            yield row('network_monotonic',all(c[k] is not None and oldc[k] is not None and hd(k)>=0 for k in ('network_rx_bytes','network_tx_bytes')))
            for k in ('network_rx_bytes','network_tx_bytes'):
                yield row('network_capacity',known([c[k],oldc[k]]) and hd(k)*8*NS<=h['link_capacity_bps']*elapsed)
            yield row('cpu_capacity',known([c[k] for k in ('busy_ticks','idle_ticks')]+[oldc[k] for k in ('busy_ticks','idle_ticks')]) and
                      (hd('busy_ticks')+hd('idle_ticks'))*NS<=elapsed*ncpu*hz+16*ncpu*NS)
            yield row('cpu_irq_subset',known([c[k] for k in ('busy_ticks','irq_ticks','softirq_ticks')]+[oldc[k] for k in ('busy_ticks','irq_ticks','softirq_ticks')]) and hd('irq_ticks')+hd('softirq_ticks')<=hd('busy_ticks'))
            if known([c['busy_ticks'],oldc['busy_ticks'],c['other_cpu_usec'],oldc['other_cpu_usec']]):
                charged=sum(d['cpu']['usage_usec']-before['domains'][name]['cpu']['usage_usec'] for name,d in groups.items())
                yield row('cpu_host_charge',abs(Fraction(hd('busy_ticks')*10**6,hz)-charged-hd('other_cpu_usec'))<=Fraction(12*ncpu*10**6,hz)+skew_us)
            else:yield row('cpu_host_charge',False)
            for kind in ('user','system'):
                k=kind+'_ticks';dk=kind+'_usec'
                total=sum(d['cpu'][dk]-before['domains'][name]['cpu'][dk] for name,d in groups.items())
                yield row('cpu_'+kind,known([c[k],oldc[k]]) and total<=Fraction(hd(k)*10**6,hz)+Fraction(4*ncpu*10**6,hz)+skew_us)
            for name,d in groups.items():
                old=before['domains'][name];delta=lambda k:d['cpu'][k]-old['cpu'][k]
                yield row('cpu_parts',abs(delta('user_usec')+delta('system_usec')-delta('usage_usec'))<=4)
                yield row('domain_capacity',0<=delta('usage_usec')<=Fraction(elapsed*ncpu,1000))
                monotonic=not regression(old['cpu'],d['cpu']) and not regression(old['memory_events'],d['memory_events'])
                monotonic=monotonic and all(d[k]>=old[k] for k in ('cpu_exited_usec','cpu_exited_user_usec','cpu_exited_system_usec'))
                members=[p for p in ps if p['domain']==name]
                stable=[(p,oldps[proc_key(p)]) for p in members if proc_key(p) in oldps]
                complete=len(stable)==len(members) and all(p[k] is not None and q[k] is not None for p,q in stable for k in ('utime_ticks','stime_ticks'))
                tolerance=Fraction(2*len(stable)*10**6,hz)+skew_us
                if complete:
                    ticks=sum(p[k]-q[k] for p,q in stable for k in ('utime_ticks','stime_ticks'))
                    exited=d['cpu_exited_usec']-old['cpu_exited_usec']
                    yield row('cpu_members',abs(delta('usage_usec')-Fraction(ticks*10**6,hz)-exited)<=tolerance)
                    for kind,pk in [('user','utime_ticks'),('system','stime_ticks')]:
                        ticks=sum(p[pk]-q[pk] for p,q in stable)
                        exited=d['cpu_exited_'+kind+'_usec']-old['cpu_exited_'+kind+'_usec']
                        yield row('cpu_'+kind,abs(delta(kind+'_usec')-Fraction(ticks*10**6,hz)-exited)<=tolerance)
                else:yield row('cpu_members',False)
                for p,q in stable:
                    monotonic=monotonic and all(p[k] is not None and q[k] is not None and p[k]>=q[k] for k in ('utime_ticks','stime_ticks'))
                    yield row('wakeups_monotonic',known([p['wakeups'],q['wakeups']]) and p['wakeups']>=q['wakeups'])
                maps=[(d['io'],old['io']),(d['io_other'],old['io_other'])]+[(p['io'],q['io']) for p,q in stable]
                for now,prev in maps:
                    monotonic=monotonic and set(now)==set(prev) and all(not regression(prev[dev],now[dev]) for dev in set(now)&set(prev))
                yield row('counter_monotonic',monotonic)
                devices=set().union(*(set(now)|set(prev) for now,prev in maps))
                if not devices:yield row('io_conservation',True)
                for dev in devices:
                    keys=set().union(*(set(now.get(dev,{}))|set(prev.get(dev,{})) for now,prev in maps))
                    for k in keys:
                        diffs=[now.get(dev,{}).get(k,0)-prev.get(dev,{}).get(k,0) for now,prev in maps]
                        yield row('io_conservation',diffs[0]==sum(diffs[1:]))
    first=next((s for s in samples if s['mono_ns']-samples[0]['mono_ns']>=run['warmup_discard_ns']),None)
    if first is None:
        yield row('network_payload',False)
        return
    a,b=first['host'],samples[-1]['host']
    yield row('network_payload',known([a[k] for k in ('network_rx_bytes','network_tx_bytes')]+[b[k] for k in ('network_rx_bytes','network_tx_bytes')]) and
              run['traffic']['bytes']<=sum(b[k]-a[k] for k in ('network_rx_bytes','network_tx_bytes')))


def check_invariants(run, reasons):
    for name,ok in physical_constraints(run):
        if not ok:reasons.add(INVARIANT_REGISTRY[name]['reason'])


def exact_projection(v):
    if type(v) is int: return Fraction(integer(v))
    if type(v) is dict and set(v)=={'bytes','duration_ns'}:
        # Raw unit pair avoids requiring a >u64 input numerator after *10**9.
        return rate(v['bytes'],v['duration_ns'],'bytes')
    fields(v,'numerator denominator')
    return Fraction(integer(v['numerator']),integer(v['denominator'],1))


def validate_exact_traffic(value, summary, traffic):
    """Schema-2 receipt semantics with exact projections; reuse monitor replay.

    The older validate_traffic uses float rates and rank arithmetic. It remains
    unchanged for its own CLI; this accounting path accepts exact projections.
    """
    fields(value,'schema evidence_origin binding record_sha256 provenance window_boottime_ns throughput_bytes_per_second throughput_intervals latency_ns monitoring unexpected_restarts oom_events traffic_protocols')
    def tree(v,key='',depth=0):
        require(depth<=32,'evidence_depth')
        if type(v) is dict:
            require(len(v)<=256 and all(type(k) is str for k in v),'evidence_object')
            for k,item in v.items(): tree(item,k,depth+1)
        elif type(v) is list:
            require(len(v)<=100000,'evidence_list')
            for item in v: tree(item,'',depth+1)
        elif type(v) is bool: require(key=='complete','evidence_boolean')
        elif type(v) is int: integer(v)
        elif type(v) is str: require(len(v)<=MAX_TEXT,'evidence_string')
        else: require(v is None,'evidence_scalar')
    # Python equality treats 5.0 == 5 and True == 1. Reject those aliases
    # before inherited equality-only constant/window/binding checks.
    tree(value)
    require(type(value['schema']) is int and value['schema']==2 and value['evidence_origin']=='actual_runtime','traffic_not_actual')
    require(value['binding']==summary['binding'] and value['record_sha256']==summary['input_sha256'],'traffic_binding_mismatch')
    window=summary['original_window_boottime_ns']
    require(value['window_boottime_ns']==window,'traffic_original_window_mismatch')
    proof=value['provenance'];fields(proof,'producer_sha256 raw_evidence_sha256 review_sha256 kind')
    for k in ('producer_sha256','raw_evidence_sha256','review_sha256'): digest(proof[k])
    require(proof['kind']=='real_disposable_tailscale_clients','traffic_source_not_real_clients')
    protocols=value['traffic_protocols']
    require(type(protocols) is list and len(protocols)==5 and set(protocols)=={'ipv4','dns','ipv6','tcp','udp'},'incomplete_protocol_coverage')
    intervals=value['throughput_intervals'];require(type(intervals) is list and 1<=len(intervals)<=100000,'missing_traffic_intervals')
    cursor=window[0];total=0
    for interval in intervals:
        fields(interval,'start_ns end_ns bytes')
        lo=integer(interval['start_ns']);hi=integer(interval['end_ns']);total+=integer(interval['bytes'])
        require(lo==cursor and hi>lo,'traffic_gap_overlap_or_reset');cursor=hi
    require(cursor==window[1] and total==traffic['bytes'],'traffic_counter_mismatch')
    require(exact_projection(value['throughput_bytes_per_second'])==rate(total,window[1]-window[0],'bytes'),'throughput_projection')
    latency=value['latency_ns'];fields(latency,'p95 samples complete values_ns')
    require(latency['complete'] is True and type(latency['values_ns']) is list and integer(latency['samples'],1)==len(latency['values_ns']),'incomplete_latency')
    for v in latency['values_ns']: integer(v,1)
    require(integer(latency['p95'],1)==percentile(latency['values_ns'],95),'p95_projection')
    # Legacy validators dereference mapping items in several nested lists. Check
    # the complete monitor tree before replay, then fail closed at the boundary.
    def shape(v,key='',depth=0):
        require(depth<=32,'monitor_depth')
        if type(v) is dict:
            for k,item in v.items(): shape(item,k,depth+1)
        elif type(v) is list:
            require(len(v)<=100000,'monitor_bound')
            if key!='window_boottime_ns': require(all(type(item) is dict for item in v),'monitor_item_type')
            for item in v: shape(item,'',depth+1)
    shape(value['monitoring'])
    _contract.validate_monitoring(value['monitoring'],summary,window)
    for k in ('unexpected_restarts','oom_events'): integer(value[k])


def _summarize(run):
    fields(run,'schema evidence_origin purpose binding host boot_id clock interval_ns warmup_discard_ns duration_ns instrumentation_sha256 domains accounting samples traffic runtime_evidence failure_domains')
    require(type(run['schema']) is int and run['schema']==1,'schema_version')
    require(run['evidence_origin'] in ('synthetic','actual_runtime') and run['purpose'] in ('harness_self_test','runtime_measurement'),'evidence_origin')
    _contract.validate_binding(run['binding'])
    digest(run['instrumentation_sha256'])
    b=run['binding']
    for name in ('run_id','tailscale_version'): identifier(b[name])
    for name in b['exit_ids']: identifier(name)
    host=run['host']
    fields(host,'kernel cpu_model architecture logical_cpus governor memory_total_bytes swap_total_bytes tick_hz tick_bits thermal_limit_millic link_capacity_bps max_fd_entries pid_max')
    for name in ('kernel','cpu_model','architecture','governor'): identifier(host[name])
    for name in ('logical_cpus','memory_total_bytes','tick_hz','tick_bits','thermal_limit_millic','link_capacity_bps','max_fd_entries','pid_max'): integer(host[name],1)
    integer(host['swap_total_bytes']); digest(run['boot_id'])
    require(run['clock']=='CLOCK_BOOTTIME','unsupported_clock')
    interval=integer(run['interval_ns'],NS//4,10*NS)
    warmup=integer(run['warmup_discard_ns']); duration=integer(run['duration_ns'],1,90000*NS)
    reasons=set()
    failures=run['failure_domains']
    require(type(failures) is dict and set(failures)==COMPONENTS|{'kernel'},'failure_domain_coverage')
    failure_totals=dict(memory_oom_kills=0,kernel_oom_kills=0,unexpected_restarts=0,monitor_misses=0,missing_samples=0)
    for signals in failures.values():
        fields(signals,'memory_oom_kills kernel_oom_kills unexpected_restarts monitor_misses missing_samples')
        for k,v in signals.items():
            integer(v);failure_totals[k]+=v
            if v: reasons.add('measured_domain_failure')

    if run['evidence_origin']!='actual_runtime' or run['purpose']!='runtime_measurement': reasons.add('synthetic_evidence')
    if any(host[k].lower() in ('unknown','unavailable','not_measured','not_run','unset','none') for k in ('kernel','cpu_model','architecture')): reasons.add('host_metadata_unavailable')
    if host['tick_bits']!=64: reasons.add('unsupported_tick_width')
    if host['governor'] not in ('performance','powersave','schedutil','ondemand','conservative','userspace'): reasons.add('governor_unavailable')
    acc=run['accounting'];fields(acc,'complete isolated_host kernel_networking outside_overhead review_sha256')
    for k in ('complete','isolated_host'): require(type(acc[k]) is bool,'accounting_boolean')
    digest(acc['review_sha256'])
    require(acc['kernel_networking'] in ('included_in_domains','unavailable') and acc['outside_overhead'] in ('none','unavailable'),'accounting_method')
    if not acc['complete'] or not acc['isolated_host']: reasons.add('incomplete_accounting')
    if acc['kernel_networking']!='included_in_domains': reasons.add('kernel_networking_unavailable')
    if acc['outside_overhead']!='none': reasons.add('outside_overhead_unavailable')
    domains=run['domains'];require(type(domains) is list and 1<=len(domains)<=32,'domain_bound')
    ids={}; scopes=[]; native=set(); coverage=set(); controls=set(); service=set(); observers=set(); mixed=False
    for domain in domains:
        fields(domain,'id scope native_identity components')
        name=identifier(domain['id']);require(name not in ids,'duplicate_domain')
        scope=domain['scope'];require(type(scope) is list and 1<=len(scope)<=16,'scope_bound')
        for part in scope: identifier(part)
        path=tuple(scope)
        if any(path[:len(old)]==old or old[:len(path)]==path for old in scopes): reasons.add('overlapping_domains')
        scopes.append(path)
        identity=domain['native_identity'];require(type(identity) is list and len(identity)==2,'native_identity')
        for v in identity: integer(v,1)
        require(tuple(identity) not in native,'duplicate_domain_identity');native.add(tuple(identity))
        parts=domain['components'];require(type(parts) is list and parts and all(type(p) is str for p in parts) and len(set(parts))==len(parts) and set(parts)<=COMPONENTS,'component_fields')
        parts=set(parts);coverage|=parts;ids[name]=domain
        if parts & SERVICE:
            service.add(name)
            if parts- SERVICE: reasons.add('mixed_service_observer_or_workload')
        if 'observer' in parts: observers.add(name)
        if parts & CONTROL:
            if parts-CONTROL: mixed=True;reasons.add('mixed_control_cpu')
            else: controls.add(name)
    if coverage!=COMPONENTS: reasons.add('incomplete_component_coverage')
    samples=run['samples'];require(type(samples) is list and 2<=len(samples)<=MAX_SAMPLES,'sample_bound')
    previous=None; previous_processes={}; initial_processes=None; previous_domains={}; offset_low=None;offset_high=None
    selected=[]; first_ns=None; warmup_found=False
    for sample in samples:
        fields(sample,'mono_ns read_end_ns wall_before_ns wall_after_ns domains processes host')
        t=integer(sample['mono_ns']);end=integer(sample['read_end_ns']);wb=integer(sample['wall_before_ns']);wa=integer(sample['wall_after_ns'])
        require(t<=end<=t+interval//10 and wb<=wa and wa-wb<=interval//10,'sample_bracket')
        if first_ns is None: first_ns=t
        if previous is not None:
            if t<=previous['mono_ns'] or t<previous['read_end_ns']: reasons.add('nonmonotonic_time')
            if abs(t-previous['mono_ns']-interval)>interval//10: reasons.add('sampling_gap')
            if wb<previous['wall_before_ns'] or wa<previous['wall_after_ns']: reasons.add('clock_discontinuity')
        low,high=wb-end,wa-t
        offset_low=low if offset_low is None else max(low,offset_low)
        offset_high=high if offset_high is None else min(high,offset_high)
        if offset_low>offset_high: reasons.add('clock_discontinuity')
        elapsed=t-first_ns
        if elapsed==warmup: warmup_found=True
        if elapsed>=warmup: selected.append(sample)
        group=sample['domains'];require(type(group) is dict and set(group)==set(ids),'domain_set_changed')
        for name,value in group.items():
            validate_domain_sample(value)
            if name in previous_domains:
                old=previous_domains[name]
                if regression(old['cpu'],value['cpu']) or regression(old['memory_events'],value['memory_events']): reasons.add('counter_regression')
                if set(old['io'])!=set(value['io']) or any(regression(old['io'][dev],value['io'][dev]) for dev in set(old['io'])&set(value['io'])): reasons.add('counter_regression')
                # memory.stat contains both byte gauges and event counters. Only
                # known byte gauges may decrease; all other fields are counters.
                gauges={'anon','file','kernel','kernel_stack','pagetables','sec_pagetables','percpu','sock','vmalloc','shmem','zswap','zswapped','file_mapped','file_dirty','file_writeback','swapcached','anon_thp','file_thp','shmem_thp','inactive_anon','active_anon','inactive_file','active_file','unevictable','slab_reclaimable','slab_unreclaimable','slab'}
                if regression({k:v for k,v in old['memory_stat'].items() if k not in gauges},
                              {k:v for k,v in value['memory_stat'].items() if k not in gauges}): reasons.add('counter_regression')
        previous_domains=group
        processes=sample['processes'];require(type(processes) is list and 1<=len(processes)<=4096,'process_bound')
        current={};pids=set()
        for p in processes:
            fields(p,'pid start_ticks executable_sha256 domain component utime_ticks stime_ticks pss_bytes rss_bytes uss_bytes swap_bytes swap_pss_bytes threads fds wakeups io')
            validate_io(p['io'])
            pid=integer(p['pid'],1);start=integer(p['start_ticks'],1);digest(p['executable_sha256'])
            require(pid not in pids,'duplicate_pid');pids.add(pid)
            require(p['domain'] in ids and p['component'] in ids[p['domain']]['components'],'process_component')
            for k in ('utime_ticks','stime_ticks','pss_bytes','rss_bytes','uss_bytes','swap_bytes','swap_pss_bytes','threads','fds','wakeups'):
                if p[k] is None: reasons.add('missing_metric')
                else: integer(p[k],1 if k=='threads' else 0,2**host['tick_bits']-1 if k in ('utime_ticks','stime_ticks') and host['tick_bits'] in (32,64) else U64)
            if p['utime_ticks'] is not None and p['stime_ticks'] is not None: integer(p['utime_ticks']+p['stime_ticks'])
            if all(p[k] is not None for k in ('uss_bytes','pss_bytes','rss_bytes')): require(p['uss_bytes']<=p['pss_bytes']<=p['rss_bytes'],'process_memory_inconsistent')
            key=(pid,start,p['executable_sha256'],p['domain'],p['component']);current[key]=p
            if key in previous_processes:
                old=previous_processes[key]
                if any(old[k] is not None and p[k] is not None and p[k]<old[k] for k in ('utime_ticks','stime_ticks','wakeups')): reasons.add('counter_regression')
        for name,value in group.items():
            if set(value['member_pids'])!={p['pid'] for p in processes if p['domain']==name}: reasons.add('incomplete_process_coverage')
        if initial_processes is None: initial_processes=set(current)
        elif initial_processes!=set(current): reasons.add('process_inventory_changed')
        context=sample['host'];fields(context,'irq_ticks softirq_ticks user_ticks system_ticks steal_ticks idle_ticks network_rx_bytes network_tx_bytes swap_in_pages swap_out_pages swap_used_bytes thermal_throttle_count temperature_millic busy_ticks other_cpu_usec')
        for k,v in context.items():
            if v is None: reasons.add('missing_environment_metric')
            else: integer(v)
        check_reconciliation(sample,previous,current,previous_processes,host,reasons)
        previous_processes=current
        if context['temperature_millic'] is not None and context['temperature_millic']>=host['thermal_limit_millic']: reasons.add('thermal_contamination')
        if context['thermal_throttle_count']: reasons.add('thermal_contamination')
        if any(context[k] for k in ('swap_used_bytes','swap_in_pages','swap_out_pages')): reasons.add('swap_contamination')
        if previous is not None:
            for k in ('irq_ticks','softirq_ticks','swap_in_pages','swap_out_pages','thermal_throttle_count','busy_ticks','other_cpu_usec'):
                old=previous['host'][k];new=context[k]
                if old is not None and new is not None and new<old: reasons.add('counter_regression')
        previous=sample
    require(samples[-1]['mono_ns']-samples[0]['mono_ns']==duration,'duration_mismatch')
    if not warmup_found: reasons.add('warmup_boundary_missing')
    measured=selected[-1]['mono_ns']-selected[0]['mono_ns'] if len(selected)>1 else 0
    if measured<600*NS: reasons.add('short_run')
    require(len(selected)>=2,'warmup_exhausts_run')
    first,last=selected[0],selected[-1]
    # Sample spans/read brackets: conservative lower baseline vs upper candidate.
    low=last['mono_ns']-first['read_end_ns'];high=last['read_end_ns']-first['mono_ns']
    require(low>0,'cpu_duration')
    delta=lambda name: last['domains'][name]['cpu']['usage_usec']-first['domains'][name]['cpu']['usage_usec']
    cpu_delta=integer(sum(delta(name) for name in controls))
    service_delta=integer(sum(delta(name) for name in service))
    missing_pss=bool({'missing_metric','process_inventory_changed','incomplete_process_coverage'} & reasons)
    control_peak=max(integer(sum(p['pss_bytes'] or 0 for p in s['processes'] if p['component'] in CONTROL)) for s in selected)
    total_peak=max(integer(sum(s['domains'][n]['memory_current_bytes'] for n in service)) for s in selected)
    traffic=run['traffic'];fields(traffic,'bytes latencies_ns monitor_misses unexpected_restarts oom_events')
    for k in ('bytes','monitor_misses','unexpected_restarts','oom_events'): integer(traffic[k])
    check_invariants(run,reasons)
    latencies=traffic['latencies_ns'];require(type(latencies) is list and 1<=len(latencies)<=100000,'latency_bound')
    for v in latencies: integer(v,1)
    throughput=Fraction(traffic['bytes']*NS,measured) if measured>0 else Fraction(0)
    metrics=dict(supervision_cpu=None if mixed else rate(cpu_delta,measured,'cpu_usec'),
                 service_cpu=rate(service_delta,measured,'cpu_usec'),total_memory_bytes=total_peak,
                 control_pss_bytes=None if missing_pss else control_peak,throughput=throughput,p95_latency_ns=percentile(latencies,95),
                 monitor_misses=traffic['monitor_misses'],unexpected_restarts=traffic['unexpected_restarts'],oom_events=traffic['oom_events'])
    cpu_bounds=None if mixed else [rate(cpu_delta,high,'cpu_usec'),rate(cpu_delta,low,'cpu_usec')]
    # Existing validator enforces original runtime-specific cadence/retry/health/
    # watchdog semantics. No generic zero-count declaration can replace it.
    proof=run['runtime_evidence']
    if proof is None: reasons.add('missing_runtime_evidence')
    else:
        try:
            summary=dict(binding=b,input_sha256=record_digest(run),original_window_boottime_ns=[first['mono_ns'],last['mono_ns']])
            validate_exact_traffic(proof,summary,traffic)
            require(proof['latency_ns']['values_ns']==latencies,'runtime_latency_mismatch')
            for k,p in [('monitor_misses',proof['monitoring']['deadline_misses']),('unexpected_restarts',proof['unexpected_restarts']),('oom_events',proof['oom_events'])]: require(traffic[k]==p,'runtime_event_mismatch')
        except (ValueError,KeyError,TypeError,IndexError,OverflowError,AttributeError,StopIteration): reasons.add('invalid_runtime_evidence')
    domain_oom=sum(samples[-1]['domains'][n]['memory_events'].get(k,0)-samples[0]['domains'][n]['memory_events'].get(k,0)
                   for n in ids for k in ('oom','oom_kill','oom_group_kill'))
    metrics['oom_events']=integer(max(metrics['oom_events'],domain_oom,failure_totals['memory_oom_kills'],failure_totals['kernel_oom_kills']))
    for k in ('monitor_misses','unexpected_restarts'):
        metrics[k]=integer(max(metrics[k],failure_totals[k]))
    if any(metrics[k] for k in ('oom_events','monitor_misses','unexpected_restarts')): reasons.add('measured_domain_failure')
    # I/O, process ticks, thread/fd/wakeup extrema and all PSS families retained.
    diagnostics={}
    for name in sorted(ids):
        diagnostics[name]=dict(cpu_delta_usec=delta(name),memory_peak_bytes=max(s['domains'][name]['memory_current_bytes'] for s in selected),
            io_delta={dev:{k:last['domains'][name]['io'][dev][k]-v for k,v in entry.items()} for dev,entry in first['domains'][name]['io'].items() if dev in last['domains'][name]['io']})
    process_totals={k:(None if any(p[k] is None for s in selected for p in s['processes']) else max(integer(sum(p[k] for p in s['processes'])) for s in selected)) for k in ('pss_bytes','rss_bytes','uss_bytes','threads','fds')}
    process_series={}
    for sample in selected:
        for p in sample['processes']:
            key=(p['pid'],p['start_ticks'],p['executable_sha256'],p['domain'],p['component'])
            process_series.setdefault(key,[]).append(p)
    process_report=[]
    for key,series in sorted(process_series.items()):
        delta_ticks=None
        if len(series)==len(selected) and all(p[k] is not None for p in series for k in ('utime_ticks','stime_ticks')):
            delta_ticks=sum(series[-1][k]-series[0][k] for k in ('utime_ticks','stime_ticks'))
        row=dict(identity_sha256=hashlib.sha256(canonical(key)).hexdigest(),domain=key[3],component=key[4],cpu_delta_ticks=delta_ticks,
                 wakeups_delta=series[-1]['wakeups']-series[0]['wakeups'] if len(series)==len(selected) and all(p['wakeups'] is not None for p in series) else None)
        for source,target in [('pss_bytes','peak_pss_bytes'),('rss_bytes','peak_rss_bytes'),('uss_bytes','peak_uss_bytes'),('threads','peak_threads'),('fds','peak_fds')]:
            row[target]=max(p[source] for p in series) if all(p[source] is not None for p in series) else None
        process_report.append(row)
    host_context={k:(last['host'][k]-first['host'][k] if first['host'][k] is not None and last['host'][k] is not None else None) for k in ('irq_ticks','softirq_ticks','swap_in_pages','swap_out_pages')}
    return dict(status='INSUFFICIENT_DATA' if reasons else 'PASS',reasons=sorted(reasons),binding=b,boot_id=run['boot_id'],
                record_sha256=record_digest(run),instrumentation_sha256=run['instrumentation_sha256'],host_contract_sha256=hashlib.sha256(canonical(host)).hexdigest(),
                accounting=acc,domain_contract=sorted((d for d in domains),key=lambda d:d['id']),
                window_ns=[samples[0]['mono_ns'],samples[-1]['read_end_ns']],measured_duration_ns=measured,
                interval_ns=interval,warmup_discard_ns=warmup,metrics=metrics,supervision_cpu_bounds=cpu_bounds,
                domains=diagnostics,processes=process_report,process_totals=process_totals,host_context=host_context,
                observer=dict(cpu_delta_usec=integer(sum(delta(n) for n in observers)),peak_memory_bytes=max(integer(sum(s['domains'][n]['memory_current_bytes'] for n in observers)) for s in selected)),
                latency=describe(latencies) if len(latencies)<=MAX_VALUES else dict(samples=len(latencies),p95=percentile(latencies,95),p99=percentile(latencies,99)))


def summarize(run):
    try:
        return _summarize(run)
    except (ValueError,KeyError,TypeError,IndexError,OverflowError,RecursionError,AttributeError,StopIteration):
        # Fixed code only: no input path, user, host label or exception text leaks.
        return dict(status='INSUFFICIENT_DATA',reasons=['invalid_run'])


def _valid_metric(v):
    return type(v) in (int,Fraction) and 0<=v<=U64


def evaluate_metrics(baseline,candidate,exits):
    """Arithmetic gates only, not evidence qualification; never authenticates data."""
    require(type(exits) is int and exits in (1,5,6),'exit_count')
    requirements=[('total_memory','total_memory_bytes',100,100,'le',1),
                  ('throughput','throughput',100,95,'ge',1),
                  ('p95_latency','p95_latency_ns',100,105,'le',1)]
    if exits==1: requirements.append(('supervision_cpu','supervision_cpu',100,50,'le',Fraction(1,10**6)))
    gates={}; reasons=[]
    for gate,key,left,right,op,floor in requirements:
        b,c=baseline.get(key),candidate.get(key)
        if not _valid_metric(b) or not _valid_metric(c) or b<floor:
            gates[gate]='INSUFFICIENT_DATA';reasons.append('missing_or_tiny_baseline_or_metric:'+key)
        else:
            l=c*left;r=b*right
            gates[gate]='PASS' if (l<=r if op=='le' else l>=r) else 'FAIL'
    if exits in (1,5):
        value=candidate.get('control_pss_bytes')
        gates['control_pss']='INSUFFICIENT_DATA' if not _valid_metric(value) else 'PASS' if value<=(16 if exits==1 else 48)*MIB else 'FAIL'
        if gates['control_pss']=='INSUFFICIENT_DATA': reasons.append('missing_control_pss')
    for key in ('monitor_misses','unexpected_restarts','oom_events'):
        vals=[baseline.get(key),candidate.get(key)]
        gates[key]='INSUFFICIENT_DATA' if not all(type(v) is int and 0<=v<=U64 for v in vals) else 'PASS' if vals==[0,0] else 'FAIL'
        if gates[key]=='INSUFFICIENT_DATA': reasons.append('missing_event_metric:'+key)
    status='INSUFFICIENT_DATA' if 'INSUFFICIENT_DATA' in gates.values() else 'FAIL' if 'FAIL' in gates.values() else 'PASS'
    return dict(status=status,gates=dict(sorted(gates.items())),reasons=sorted(reasons))


def compare(baseline,candidate):
    """All steady/load 1/5/6 shapes, six matched repetitions; no hidden exclusions."""
    invalid=dict(schema=1,status='INSUFFICIENT_DATA',release_ready=False,reasons=['invalid_suite'],scenarios=[])
    if not (type(baseline) is list and type(candidate) is list and len(baseline)+len(candidate)<=MAX_RUNS): return invalid
    summaries=[(kind,summarize(run)) for kind,runs in [('baseline',baseline),('candidate',candidate)] for run in runs]
    return _compare_summaries(summaries)


def _compare_summaries(summaries):
    # Internal entry for the bounded CLI, which summarizes one raw file at a time.
    global_issues=set()
    if any('binding' not in s for _,s in summaries): global_issues.add('invalid_run')
    good=[(kind,s) for kind,s in summaries if 'binding' in s]
    all_runs=[s for _,s in good]
    if len({s['binding']['host_id_sha256'] for s in all_runs})>1: global_issues.add('mixed_host')
    if len({s['instrumentation_sha256'] for s in all_runs})>1: global_issues.add('instrumentation_mismatch')
    if len({s['host_contract_sha256'] for s in all_runs})>1: global_issues.add('host_contract_mismatch')
    if len({(s['interval_ns'],s['warmup_discard_ns']) for s in all_runs})>1: global_issues.add('sampling_contract_mismatch')
    for key in ('tailscale_version','tailscale_artifact_sha256'):
        if len({s['binding'][key] for s in all_runs})>1: global_issues.add('tailscale_mismatch')
    if len({s['record_sha256'] for s in all_runs})!=len(all_runs): global_issues.add('duplicate_record')
    if len({s['binding']['run_id'] for s in all_runs})!=len(all_runs): global_issues.add('duplicate_run_id')
    for kind in ('baseline','candidate'):
        runs=[s for k,s in good if k==kind]
        if any(s['binding']['implementation']!=('python' if kind=='baseline' else 'rust') for s in runs): global_issues.add('wrong_implementation')
        for key in ('source_sha256','artifact_sha256'):
            if len({s['binding'][key] for s in runs})>1: global_issues.add('source_or_artifact_mismatch')
    ordered=sorted(all_runs,key=lambda s:(s['binding']['host_id_sha256'],s['boot_id'],s['window_ns'][0]))
    for old,new in zip(ordered,ordered[1:]):
        if (old['binding']['host_id_sha256'],old['boot_id'])==(new['binding']['host_id_sha256'],new['boot_id']) and new['window_ns'][0]<=old['window_ns'][1]: global_issues.add('overlapping_runs')
    scenarios=[]
    for count,mode in SCENARIOS:
        groups={kind:sorted([s for k,s in good if k==kind and s['binding']['exits']==count and s['binding']['scenario']==mode],key=lambda s:(s['binding']['repetition'],s['record_sha256'])) for kind in ('baseline','candidate')}
        b,c=groups['baseline'],groups['candidate'];runs=b+c;issues=set(global_issues)
        if len(b)<MIN_REPETITIONS or len(c)<MIN_REPETITIONS: issues.add('too_few_repetitions')
        for group in (b,c):
            if len({s['binding']['repetition'] for s in group})!=len(group): issues.add('duplicate_repetition')
        if {s['binding']['repetition'] for s in b}!={s['binding']['repetition'] for s in c}: issues.add('unmatched_repetitions')
        for s in runs: issues.update(s['reasons'])
        matching=('config_sha256','workload_sha256','identity_set_sha256','peers_sha256','network_conditions_sha256','monitoring','exit_ids','exit_modes')
        if runs:
            if any(any(s['binding'][key]!=runs[0]['binding'][key] for key in matching) for s in runs): issues.add('workload_mismatch')
            if any(s['accounting']!=runs[0]['accounting'] for s in runs): issues.add('accounting_mismatch')
            # Components/coverage must match; native inodes need not survive a
            # stopped-state old/new switch. Topology stays part of workload hash.
            coverage=lambda s: sorted(sorted(d['components']) for d in s['domain_contract'])
            if any(coverage(s)!=coverage(runs[0]) for s in runs): issues.add('domain_coverage_mismatch')
        stats={};worst={};result=dict(status='INSUFFICIENT_DATA',gates={},reasons=[])
        if b and c:
            for key in ('supervision_cpu','total_memory_bytes','control_pss_bytes','throughput','p95_latency_ns','monitor_misses','unexpected_restarts','oom_events'):
                stats[key]={};worst[key]={}
                for kind,group in groups.items():
                    values=[s['metrics'][key] for s in group]
                    stats[key][kind]=describe(values) if all(v is not None and _valid_metric(v) for v in values) else None
                    choose=min if (kind=='baseline' and key in ('supervision_cpu','total_memory_bytes','p95_latency_ns')) or (kind=='candidate' and key=='throughput') else max
                    if key=='supervision_cpu':
                        values=[s['supervision_cpu_bounds'][0 if kind=='baseline' else 1] if s['supervision_cpu_bounds'] is not None else None for s in group]
                    worst[key][kind]=choose(values) if all(v is not None for v in values) else None
            result=evaluate_metrics({k:v['baseline'] for k,v in worst.items()},{k:v['candidate'] for k,v in worst.items()},count)
            issues.update(result['reasons'])
        status='INSUFFICIENT_DATA' if issues or result['status']=='INSUFFICIENT_DATA' else result['status']
        scenarios.append(dict(exits=count,scenario=mode,status=status,reasons=sorted(issues),gates=result['gates'],
                              repetitions={k:len(v) for k,v in groups.items()},statistics=stats,worst=worst,
                              records={k:[s['record_sha256'] for s in v] for k,v in groups.items()},
                              control_pss_target_bytes=(16 if count==1 else 48)*MIB if count in (1,5) else None))
    statuses={s['status'] for s in scenarios}
    status='INSUFFICIENT_DATA' if 'INSUFFICIENT_DATA' in statuses else 'FAIL' if 'FAIL' in statuses else 'PASS'
    return dict(schema=1,status=status,release_ready=False,reasons=sorted(global_issues),scenarios=scenarios,
                scope='Accounting comparison only; independent runtime/client/security/release acceptance required',
                minimum_repetitions=MIN_REPETITIONS,uncertainty='Worst candidate versus best baseline; exact binomial median CIs describe repetitions, not traffic-sample independence; retain all outliers')
