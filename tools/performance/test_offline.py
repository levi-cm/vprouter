"""Offline CLI/publication and short loopback harness tests; all synthetic."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).parent


def module(name):
    spec=importlib.util.spec_from_file_location('task14_'+name,ROOT/(name+'.py'))
    value=importlib.util.module_from_spec(spec)
    try: spec.loader.exec_module(value)
    except FileNotFoundError: pass
    return value


class Boundaries(unittest.TestCase):
    def test_verdict_path_is_exact_including_reused_monitoring(self):
        import ast
        import sys
        from unittest.mock import patch
        o=module('offline');t=module('test_accounting')
        for name in ('offline.py','accounting.py'):
            tree=ast.parse((ROOT/name).read_text())
            self.assertFalse(any(isinstance(n,ast.Constant) and type(n.value) is float for n in ast.walk(tree)))
            self.assertFalse(any(isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='float' for n in ast.walk(tree)))
        def no_float(v):
            if type(v) is float:self.fail('floating value reached verdict path')
            if type(v) is dict:
                for x in v.values():no_float(x)
            elif type(v) in (list,tuple):
                for x in v:no_float(x)
        def trace(frame,event,arg):
            if frame.f_code.co_filename in {str(ROOT/n) for n in ('offline.py','accounting.py','measurement.py')}:
                if event=='return':no_float(arg)
            return trace
        def forbidden(*args,**kwargs):raise AssertionError('legacy floating helper reached')
        for kind in ('python','rust'):
            run=t.reconciled_record(kind);raw=t.a.canonical(run)
            old_trace=sys.gettrace()
            try:
                with patch.object(o.a._contract,'number',forbidden),patch.object(o.a._contract,'validate_traffic',forbidden),patch.object(o.a._contract,'enrich_summary',forbidden):
                    sys.settrace(trace)
                    summary=o.a.summarize(o.decode(raw))
                    self.assertEqual(summary['status'],'PASS')
                    no_float(summary)
                    o.a._compare_summaries([('baseline' if kind=='python' else 'candidate',summary)])
            finally:sys.settrace(old_trace)

    def test_decimal_tokens_are_rejected_without_floating_decode(self):
        o=module('offline')
        for raw in (b'0.0',b'1e0',b'1e-99999',b'{"unused": 0.5}'):
            with self.subTest(raw=raw),self.assertRaises(ValueError):o.decode(raw)

    def test_json_duplicate_nonfinite_overflow_depth_size_and_no_path_leak(self):
        o=module('offline');self.assertTrue(hasattr(o,'decode'),'missing strict JSON adapter')
        self.assertEqual(o.decode(b'{"a":1}'),{'a':1})
        for raw in (b'{"a":1,"a":2}',b'NaN',b'Infinity',b'1e999',b'-1e999',
                    str(2**64).encode(),b'['*33+b'0'+b']'*33,b'"'+b'x'*(16*1024*1024)+b'"',
                    b'{"x": {"a":0,"a":1}}'):
            with self.subTest(raw=raw[:40]), self.assertRaises(ValueError): o.decode(raw)
        with tempfile.TemporaryDirectory() as tmp:
            target=Path(tmp)/'private-user-host.json';target.write_text('{"x":NaN}')
            r=subprocess.run([sys.executable,'-B','-I',str(ROOT/'offline.py'),'summarize',str(target)],capture_output=True,text=True,timeout=5)
            self.assertEqual(r.returncode,2);self.assertNotIn(tmp,r.stdout+r.stderr)
            self.assertEqual(json.loads(r.stdout)['status'],'INSUFFICIENT_DATA')

    def test_atomic_no_overwrite_symlink_and_write_failure(self):
        o=module('offline');self.assertTrue(hasattr(o,'publish'),'missing atomic publication')
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp);dest=directory/'result.json'
            o.publish(dest,b'{"a":1}\n');self.assertEqual(dest.read_bytes(),b'{"a":1}\n')
            with self.assertRaises(OSError): o.publish(dest,b'changed')
            self.assertEqual(dest.read_bytes(),b'{"a":1}\n')
            self.assertEqual(dest.stat().st_mode & 0o777,0o600)
            symlink=directory/'link.json';symlink.symlink_to(dest)
            with self.assertRaises(OSError):o.publish(symlink,b'changed')
            parent=directory/'parent';parent.symlink_to(directory,target_is_directory=True)
            with self.assertRaises(OSError):o.publish(parent/'escape.json',b'x')
            with patch.object(o.os,'fsync',side_effect=OSError('synthetic failure')):
                with self.assertRaises(OSError): o.publish(directory/'incomplete.json',b'x')
            self.assertFalse((directory/'incomplete.json').exists())
            self.assertEqual(sorted(p.name for p in directory.iterdir()),['link.json','parent','result.json'])
            # Real competing exclusive creates: exactly one publisher wins.
            from concurrent.futures import ThreadPoolExecutor
            def attempt(n):
                try:o.publish(directory/'race.json',str(n).encode());return True
                except OSError:return False
            with ThreadPoolExecutor(max_workers=4) as pool:
                self.assertEqual(sum(pool.map(attempt,range(4))),1)
            self.assertIn((directory/'race.json').read_text(),['0','1','2','3'])

    def test_real_atomic_order_has_file_and_directory_fsync(self):
        o=module('offline');self.assertTrue(hasattr(o,'publish'),'missing atomic publication')
        calls=[];original=o.os.fsync
        def fsync(fd):
            import stat
            calls.append('directory' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file')
            original(fd)
        with tempfile.TemporaryDirectory() as tmp,patch.object(o.os,'fsync',side_effect=fsync):
            o.publish(Path(tmp)/'out.json',b'{}')
        self.assertEqual(calls,['file','directory'])

    def test_cli_empty_comparison_and_exclusive_output(self):
        self.assertTrue(hasattr(module('offline'),'main'),'missing comparison CLI')
        with tempfile.TemporaryDirectory() as tmp:
            dest=Path(tmp)/'report.json'
            args=[sys.executable,'-B','-I',str(ROOT/'offline.py'),'compare','--output',str(dest)]
            r=subprocess.run(args,capture_output=True,text=True,timeout=5)
            self.assertEqual(r.returncode,2)
            self.assertEqual(json.loads(dest.read_bytes())['status'],'INSUFFICIENT_DATA')
            before=dest.read_bytes();again=subprocess.run(args,capture_output=True,text=True,timeout=5)
            self.assertEqual(again.returncode,2);self.assertEqual(dest.read_bytes(),before)
            self.assertNotIn(tmp,again.stdout+again.stderr)


class Loopback(unittest.TestCase):
    def test_tcp_udp_dns_like_are_self_test_only_and_bounded(self):
        driver=module('loopback');self.assertTrue(hasattr(driver,'self_test'),'missing loopback driver')
        result=driver.self_test(iterations=2)
        self.assertEqual(result['purpose'],'harness_self_test')
        self.assertFalse(result['performance_evidence']);self.assertFalse(result['release_ready'])
        self.assertEqual(result['status'],'SELF_TEST_PASS')
        self.assertEqual(result['protocols'],{'tcp':2,'udp':2,'dns_like':2})
        self.assertNotIn('host',result);self.assertNotIn('port',result)
        for bad in (0,21,True,-1):
            with self.assertRaises(ValueError):driver.self_test(iterations=bad)
        r=subprocess.run([sys.executable,'-B','-I',str(ROOT/'loopback.py'),'--iterations','2'],capture_output=True,text=True,timeout=4)
        self.assertEqual(r.returncode,0);self.assertEqual(json.loads(r.stdout)['status'],'SELF_TEST_PASS')


if __name__=='__main__':unittest.main()


class ReviewFailureProtocol(unittest.TestCase):
    def test_legacy_null_router_actual_process_redacts_and_leaves_no_file(self):
        t=module('test_accounting');run=t.review_record('python')
        run['runtime_evidence']['monitoring']['router_cycles']=[None]
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'RAW_PRIVATE_MARKER.json';dest=Path(tmp)/'result.json'
            source.write_text(json.dumps(run))
            p=subprocess.run([sys.executable,'-B','-I',str(ROOT/'offline.py'),'summarize',str(source),'--output',str(dest)],capture_output=True,text=True,timeout=5)
            self.assertEqual(p.returncode,2)
            self.assertEqual(p.stderr,'')
            self.assertEqual(json.loads(p.stdout)['status'],'INSUFFICIENT_DATA')
            self.assertNotIn(tmp,p.stdout);self.assertNotIn('RAW_PRIVATE_MARKER',p.stdout)
            self.assertFalse(dest.exists())

    def test_whole_nested_schema_mutations_use_failure_protocol(self):
        import contextlib
        import copy
        import io
        t=module('test_accounting');o=module('offline')
        # Every distinct schema position; equivalent array item shapes sampled
        # once, both monitoring variants traversed. No live collection or traffic.
        def shape(v):
            return (type(v).__name__,tuple(sorted(v)) if type(v) is dict else '',
                    tuple((k,v[k]) for k in ('component','variant','coverage','state','outcome','stage')
                          if type(v) is dict and k in v and type(v[k]) is str))
        def positions(v,path=()):
            yield path,v
            if type(v) is dict:
                for k,x in v.items():yield from positions(x,path+(k,))
            elif type(v) is list:
                seen=set()
                for i,x in enumerate(v):
                    sig=shape(x)
                    if sig not in seen:seen.add(sig);yield from positions(x,path+(i,))
        count=0
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'RAW_PRIVATE_MARKER.json';dest=Path(tmp)/'result.json'
            def invoke(raw):
                nonlocal count
                source.write_bytes(raw)
                try:decoded=o.decode(raw)
                except ValueError:pass
                else:
                    # The short window must not hide a malformed-field accept.
                    reasons=o.a.summarize(decoded).get('reasons',[])
                    self.assertTrue(set(reasons)-{'short_run'},'malformed field accepted by semantic validator')
                out=io.StringIO();err=io.StringIO()
                with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
                    code=o.main(['summarize',str(source),'--output',str(dest)])
                if dest.exists():
                    dest.unlink()
                    self.fail('failed evidence published output')
                self.assertEqual(code,2)
                self.assertEqual(err.getvalue(),'')
                result=json.loads(out.getvalue());self.assertEqual(result['status'],'INSUFFICIENT_DATA')
                for secret in (tmp,'RAW_PRIVATE_MARKER','Traceback',str(ROOT)):
                    self.assertNotIn(secret,out.getvalue())
                self.assertFalse(dest.exists(),'failed evidence must not publish output')
                self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()),['RAW_PRIVATE_MARKER.json'])
                count+=1
            seen_paths=set()
            for kind in ('python','rust'):
                seed=t.reconciled_record(kind)
                self.assertEqual(o.a.summarize(seed)['status'],'PASS')
                # Same schema/validation path in a small constructed window.
                # This bounds the mutation run without replaying 600s receipts
                # thousands of times; short_run is the sole positive reason.
                seed['samples']=seed['samples'][:2];seed['duration_ns']=10**10
                spec=importlib.util.spec_from_file_location('_receipts',ROOT/'test_measurement.py')
                old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
                for i,sample in enumerate(seed['samples']):
                    sample['host']['network_rx_bytes']=i*60000
                    sample['host']['network_tx_bytes']=i*60000
                    io_values=dict(rbytes=i,wbytes=i,rios=i,wios=i,dbytes=0,dios=0)
                    sample['processes'][0]['io']={'8:0':dict(io_values)}
                    sample['domains']['control']['io']={'8:0':dict(io_values)}
                    sample['domains']['control']['io_other']={'8:0':{k:0 for k in io_values}}
                    for d in sample['domains'].values():d['memory_events']['oom_group_kill']=0
                view=dict(binding=seed['binding'],input_sha256=o.a.record_digest(seed),
                    original_window_boottime_ns=[seed['samples'][0]['mono_ns'],seed['samples'][-1]['mono_ns']])
                seed['runtime_evidence']=(old.legacy_fixture if kind=='python' else old.traffic_fixture)(view)
                seed['runtime_evidence']['throughput_bytes_per_second']=6000
                self.assertEqual(o.a.summarize(seed)['reasons'],['short_run'])
                variants=[('normal',seed)]
                for label,projection in [('fraction',dict(numerator=6000,denominator=1)),
                        ('raw_rate',dict(bytes=60000,duration_ns=10**10))]:
                    projected=copy.deepcopy(seed);projected['runtime_evidence']['throughput_bytes_per_second']=projection
                    variants.append((label,projected))
                if kind=='rust':
                    triggered=copy.deepcopy(seed);old.add_triggered_retry(triggered['runtime_evidence'])
                    variants.append(('triggered',triggered))
                for after in (False,True):
                    aborted=copy.deepcopy(seed);op=aborted['runtime_evidence']['monitoring']['retry_coverage'][0]
                    point=op['started_ns'];op['first_result']='http_429'
                    if kind=='python':op['handshake']=None
                    checked=point+(10**9+4 if after else (10**9 if kind=='python' else 1))
                    op['completed_ns']=point+2*10**9 if after else op['completed_ns']
                    op['retry']=dict(coverage='aborted',reason='http_429',stage='after_delay' if after else 'before_delay',
                        failed_check=dict(checked_ns=checked,failed_component='default_route',event_sha256=t.H),
                        protection=dict(kind='terminal_quarantine',evidence_sha256=t.H))
                    if after:
                        op['first_finished_ns']=point+1
                        op['retry'].update(pre_delay_check=dict(checked_ns=point+2,interfaces_sha256=t.H,routes_sha256=t.H,handshake_age_ns=10**10),
                            delay_started_ns=point+3,original_not_before_ns=point+3+10**9)
                        if kind=='python':
                            # Preserve legacy work/sleep/cycle ordering for this
                            # compact first cycle while allowing the 1s retry.
                            router=aborted['runtime_evidence']['monitoring']['router_cycles'][0]['cycles'][0]
                            router['started_ns']-=10**9;op['started_ns']-=10**9
                            op['completed_ns']=point+10**9
                            op['retry']['delay_started_ns']=point-1
                            op['retry']['original_not_before_ns']=point-1+10**9
                            op['retry']['pre_delay_check']['checked_ns']=point-2
                            op['first_finished_ns']=point-3
                            op['retry']['failed_check']['checked_ns']=point+10**9
                    variants.append(('abort_after' if after else 'abort_before',aborted))
                blocked=copy.deepcopy(seed);monitor=blocked['runtime_evidence']['monitoring']
                if kind=='python':
                    monitor['health'][0]['observations'][0].update(state='BLOCKED',time=None,heartbeat=None,status_result='blocked',
                        protection=dict(kind='tailscale_down',evidence_sha256=t.H))
                    cycle=monitor['host_cycles'][0]
                    monitor['host_cycles'][0]={k:cycle[k] for k in ('scope','service_id_sha256','started_ns','work_finished_ns','event_sha256')}
                    monitor['host_cycles'][0].update(outcome='BLOCKED',protection=dict(kind='host_quarantine',evidence_sha256=t.H))
                else:
                    for stream in monitor['streams']:
                        if stream['component'] in ('health','watchdog'):
                            at=stream['observations'][0]['observed_ns']
                            stream['observations'][0]=dict(observed_ns=at,state='BLOCKED',protection=dict(kind='terminal_quarantine',evidence_sha256=t.H))
                variants.append(('blocked',blocked))
                for variant,seed in variants:
                    self.assertEqual(o.a.summarize(seed)['reasons'],['short_run'],variant)
                    for path,value in positions(seed):
                        signature=(kind,path,shape(value))
                        if signature in seen_paths:continue
                        seen_paths.add(signature)
                        bad_type='RAW_PRIVATE_MARKER' if type(value) is not str else []
                        for label,replacement in [('type',bad_type),('null',None),('range',-1),
                                ('NaN',float('nan')),('huge',2**100),('numeric_type',float(value) if type(value) is int else (1 if type(value) is bool else True))]:
                            if replacement is None and value is None: continue  # unchanged nullable value
                            if type(replacement) is type(value) and replacement==value: continue
                            run=copy.deepcopy(seed)
                            if path:
                                target=run
                                for key in path[:-1]:target=target[key]
                                target[path[-1]]=replacement
                            else:run=replacement
                            with self.subTest(kind=kind,path=path,mutation=label):invoke(json.dumps(run).encode())
                        if path:
                            run=copy.deepcopy(seed);target=run
                            for key in path[:-1]:target=target[key]
                            # Field absence is invalid. Removing a surplus
                            # before-window receipt can preserve full coverage;
                            # real sample/coverage gaps have dedicated tests.
                            if type(target) is dict:
                                del target[path[-1]]
                                with self.subTest(kind=kind,path=path,mutation='absence'):invoke(json.dumps(run).encode())
                        if type(value) is dict and value:
                            # Serialize duplicate keys at this precise nested object.
                            key=next(iter(value));duplicate='{' + json.dumps(key)+':null,'+json.dumps(value)[1:]
                            run=copy.deepcopy(seed)
                            if path:
                                target=run
                                for segment in path[:-1]:target=target[segment]
                                target[path[-1]]='__duplicate_object_placeholder__'
                                raw=json.dumps(run).replace(json.dumps('__duplicate_object_placeholder__'),duplicate,1).encode()
                            else:raw=duplicate.encode()
                            with self.subTest(kind=kind,path=path,mutation='duplicate'):invoke(raw)
        self.assertGreater(count,2000)
        print('whole-schema failure protocol cases:',count)
