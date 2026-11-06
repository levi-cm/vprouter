#!/usr/bin/env python3
"""Offline declarations and reservation generations. Never contacts the guest."""
import copy
import contextlib
import io
import importlib.util
import json
import os
import pathlib
import tempfile
import unittest

if not __debug__:
    raise RuntimeError('optimized_python_refused')

ROOT = pathlib.Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class Supersession(unittest.TestCase):
    def test_old_generation_cannot_be_reused(self):
        m = module('reservation_test', 'tools/rust-v2-lab/run411-reservation.py')
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            for name, value in [('RESERVATION', 'reservation.json'), ('CLAIM', 'claim.json'),
                                ('RUN', 'run.json'), ('LOCK', 'lock'),
                                ('SUPERSESSION', 'supersession.json'), ('CANDIDATE', 'candidate.json')]:
                setattr(m, name, root / value)
            m.CANDIDATE.write_text('{}')
            bound = root / 'bound'; bound.write_text('new')
            old = dict(schema=1, run=411, one_shot_budget=1)
            m.save(m.RESERVATION, old)
            old_sha = m.sha(m.RESERVATION)
            new = dict(schema=2, run=411, one_shot_budget=1, supersedes_sha256=old_sha)
            m.supersede(old_sha, 'offline changed bytes', new)
            receipt = m.protected(m.SUPERSESSION)
            self.assertEqual(m.sha(receipt['retained_path']), old_sha)
            self.assertEqual(receipt['replacement_sha256'], m.sha(m.RESERVATION))
            self.assertFalse(m.CLAIM.exists())
            self.assertEqual(m.active()['schema'], 2)
            m.RESERVATION.unlink(); m.save(m.RESERVATION, old)
            with self.assertRaises(AssertionError):
                m.active()


    def test_interrupted_supersession_fails_closed(self):
        from unittest.mock import patch
        m=module('reservation_interrupt_test','tools/rust-v2-lab/run411-reservation.py')
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)
            for name,value in [('RESERVATION','reservation.json'),('SUPERSESSION','supersession.json'),('CLAIM','claim.json'),('RUN','run.json'),('CANDIDATE','candidate.json')]:setattr(m,name,root/value)
            m.save(m.RESERVATION,dict(schema=1,run=411,one_shot_budget=1));old=m.sha(m.RESERVATION)
            new=dict(schema=2,run=411,one_shot_budget=1,supersedes_sha256=old)
            original_save=m.save
            def interrupted(path,data):
                if path==m.RESERVATION:raise OSError('synthetic power loss before replacement')
                original_save(path,data)
            with patch.object(m,'save',interrupted):
                with self.assertRaises(OSError):m.supersede(old,'offline interruption',new)
            self.assertTrue(m.SUPERSESSION.exists());self.assertFalse(m.RESERVATION.exists())
            receipt=m.protected(m.SUPERSESSION);self.assertEqual(m.sha(receipt['retained_path']),old)
            with self.assertRaises(FileNotFoundError):m.active()
            original_save(m.RESERVATION,dict(schema=1,run=411,one_shot_budget=1))
            with self.assertRaises(AssertionError):m.active()

    def test_spent_budget_blocks_supersession(self):
        m=module('reservation_spent_test','tools/rust-v2-lab/run411-reservation.py')
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)
            for name,value in [('RESERVATION','reservation.json'),('SUPERSESSION','supersession.json'),('CLAIM','claim.json'),('RUN','run.json'),('CANDIDATE','candidate.json')]:setattr(m,name,root/value)
            m.save(m.RESERVATION,dict(schema=1,run=411,one_shot_budget=1));old=m.sha(m.RESERVATION)
            m.save(m.CLAIM,dict(budget_remaining=0))
            with self.assertRaises(AssertionError):m.supersede(old,'must refuse',dict(schema=2,run=411,one_shot_budget=1,supersedes_sha256=old))
            self.assertEqual(m.sha(m.RESERVATION),old);self.assertFalse(m.SUPERSESSION.exists())


class Declarations(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.before = pathlib.Path.cwd()
        os.chdir(self.tmp.name)
        self.addCleanup(self.finish)
        self.q = module('quarantine_test', 'tools/rust-v2-lab/run411-provenance.py')
        self.m = module('reservation_test', 'tools/rust-v2-lab/run411-reservation.py')
        # Real pure validators, synthetic declarations/envelope/claim; no VM.
        for path in ['target/quarantine_evidence_base.py', 'tools/rust-v2-lab/run411-provenance.py',
                     'target/platform-lab/run-frozen-host-projection.py',
                     'target/platform-lab/host_baseline_declaration.py',
                     'tools/rust-v2-lab/run411-reservation.py']:
            self.write(path, (ROOT / path).read_bytes())
        self.write('target/lab-state/id_ed25519',b'synthetic-test-identity-not-a-key')
        self.cp = self.m.CANDIDATE
        self.c = dict(binding=dict(source_commit='f'*40,source_archive_sha256='b'*64,tracked_build_inputs_verified=1,source_aggregate_sha256='e'*64), platforms={'arm64': {'artifact_sha256': 'a'*64, 'context_sha256': 'c'*64}}, source_sha256='b'*64)
        self.shape = dict(namespace=[4, 55], links=[], addresses=[], routes=[], rules=[])
        self.review = dict(route='fresh-lab', source_binding=self.c['binding'], platform=self.m.PLATFORM,
                           namespace=[4, 55], baseline_sha256=self.digest(self.shape), guest_boot_id='synthetic-boot',
                           historical_continuity=False, prior_structure_reconstructed=False,
                           ordering_only_aligned_after_exact_multiset_comparison=False,
                           projection_used_to_author=False, host_authority_granted=False)
        self.tp = self.cp.parent / ('authored-host-baseline-'+self.m.PLATFORM+'.json')
        self.rp = self.cp.parent / ('host-baseline-reconciliation-'+self.m.PLATFORM+'.json')
        self.pp = self.cp.parent / ('host-projection-'+self.m.PLATFORM) / 'record.json'
        self.comparison = pathlib.Path('target/run411-prep/baseline-comparison.json')
        self.admission = pathlib.Path('target/run411-prep/admission.json')
        self.write(self.cp, self.c); self.write(self.rp, self.review)
        self.template = dict(schema=1, platform=self.m.PLATFORM, source_binding=self.c['binding'],
                             baseline=self.shape, baseline_sha256=self.digest(self.shape),
                             review_sha256=self.m.sha(self.rp), prior_evidence=[{'path': str(self.admission), 'sha256': '0'*64}])
        self.write(self.admission, dict(boot_id='synthetic-boot', namespace={'/proc/1/ns/net': [4,55], '/proc/self/ns/net': [4,55]}))
        self.template['prior_evidence'][0]['sha256'] = self.m.sha(self.admission)
        self.write(self.tp, self.template)
        report = dict(schema=1, creator_pid=42, creator_start=12, namespace=[4,55], route_socket=dict(dev=9, ino=10),
                      requested_at=10., deadline=12., verified_at=10.1, polls=1, projection=self.shape,
                      read_only=True, declaration_authority=False, host_change_authority=False)
        remote = dict(uid=1000, machine='aarch64', root_pid=42, root_start=12, root_reaped=True,
                      exit_code=0, timed_out=False, before=9., after=11., retained_executable='/synthetic',
                      stdout=json.dumps(report), stderr='')
        self.projection = dict(source_binding=self.c['binding'], platform=self.m.PLATFORM,
                               artifact_sha256='a'*64, controller_sha256=self.m.sha('target/platform-lab/run-frozen-host-projection.py'),
                               remote=remote, report=report)
        self.write(self.pp, self.projection)
        self.check = dict(exact_multisets_equal=True, namespace_preserved=True, no_authority=True,
                          template_sha256=self.m.sha(self.tp), projection_sha256=self.m.sha(self.pp), baseline_sha256=self.digest(self.shape))
        self.write(self.comparison, self.check)
        self.r = dict(schema=2, run=411, one_shot_budget=1, historical_high_water_mark=410,
                      historical_raw_records_recovered=False, continuity='fresh-lab',
                      candidate=str(self.cp), platform=self.m.PLATFORM, label=self.m.LABEL, mode='success',
                      guest_boot_id='synthetic-boot', controller_boot_id='synthetic-controller', supersedes_sha256=None)
        # All mandatory bindings exist, but no code except the pure validators executes.
        for path in self.m.binding_paths():
            if not path.exists(): self.write(path, {})
        self.rebind()
        self.record = dict(platform=self.m.PLATFORM, source_binding=self.c['binding'], component_test_mode='secret_bootstrap_success',
                           source_archive_sha256='b'*64, artifact_sha256='a'*64, context_sha256='c'*64, guest_boot_id='synthetic-boot',
                           host_baseline_template_sha256=self.m.sha(self.tp), baseline_reconciliation_sha256=self.m.sha(self.rp))
        for key,name in [('runner_sha256','run-frozen-secret-bootstrap411.py'),('guest_sha256','secret-bootstrap.guest.py'),('context_checker_sha256','attachment_context_check.py'),('host_declaration_builder_sha256','quarantine_host_declaration.py'),('baseline_declaration_builder_sha256','host_baseline_declaration.py')]:
            self.record[key]=self.m.sha(pathlib.Path('target/platform-lab')/name)
        self.claim()

    def finish(self):
        os.chdir(self.before); self.tmp.cleanup()

    def write(self, path, value):
        path = pathlib.Path(path); path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode()); path.chmod(0o600)

    def digest(self, value):
        import hashlib
        return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()

    def rebind(self):
        self.r['bindings'] = [dict(path=str(p), sha256=self.m.sha(p)) for p in self.m.binding_paths()]
        self.write(self.m.RESERVATION, self.r)

    def claim(self):
        self.record['run_reservation'] = dict(path=str(self.m.RESERVATION), sha256=self.m.sha(self.m.RESERVATION),
                                            claim=str(self.m.CLAIM), continuity='fresh-lab', historical_raw_records_recovered=False)
        self.write(self.m.CLAIM, dict(reservation=str(self.m.RESERVATION), reservation_sha256=self.m.sha(self.m.RESERVATION),
                                    run=411, budget_remaining=0, controller_boot_id='synthetic-controller'))

    def validate(self):
        return self.q.validate_fresh_provenance(self.template, self.review, self.c, self.record)

    def test_fresh(self): self.validate()

    def test_bindings(self):
        for key, value in [('continuity', 'historical'), ('guest_boot_id', 'other'), ('run', 408), ('one_shot_budget', 2)]:
            with self.subTest(key=key):
                original = self.r[key]; self.r[key] = value; self.rebind(); self.claim()
                with self.assertRaises(AssertionError): self.validate()
                self.r[key] = original

    def test_missing_binding(self):
        self.r['bindings'].pop(); self.write(self.m.RESERVATION, self.r); self.claim()
        with self.assertRaises(AssertionError): self.validate()

    def test_claim_binding(self):
        self.record['run_reservation']['sha256'] = '0'*64
        with self.assertRaises(AssertionError): self.validate()

    def test_flags(self):
        for key in ('historical_continuity', 'prior_structure_reconstructed', 'ordering_only_aligned_after_exact_multiset_comparison', 'projection_used_to_author'):
            with self.subTest(key=key):
                self.review[key] = True
                with self.assertRaises(AssertionError): self.validate()
                self.review[key] = False

    def test_exact_multiset_even_with_rebound_hashes(self):
        self.projection['report']['projection'] = copy.deepcopy(self.shape)
        self.projection['report']['projection']['namespace'] = [4, 56]
        self.projection['remote']['stdout'] = json.dumps(self.projection['report'])
        self.write(self.pp, self.projection); self.check['projection_sha256'] = self.m.sha(self.pp)
        self.write(self.comparison, self.check); self.rebind(); self.claim()
        with self.assertRaises(AssertionError): self.validate()

    def test_original_deadline(self):
        self.projection['report']['deadline'] = 13.
        self.projection['remote']['stdout'] = json.dumps(self.projection['report'])
        self.write(self.pp, self.projection); self.check['projection_sha256'] = self.m.sha(self.pp)
        self.write(self.comparison, self.check); self.rebind(); self.claim()
        with self.assertRaises(AssertionError): self.validate()

    def test_bound_bytes_tampered(self):
        self.write(self.admission, {'boot_id':'tampered'})
        with self.assertRaises(AssertionError): self.validate()

    def test_claim_budget(self):
        value=self.m.protected(self.m.CLAIM);value['budget_remaining']=1;self.write(self.m.CLAIM,value)
        with self.assertRaises(AssertionError): self.validate()

    def test_unbound_fresh(self):
        self.m.RESERVATION.unlink()
        with self.assertRaises(FileNotFoundError): self.validate()

    def test_multiset_not_just_namespace(self):
        self.projection['report']['projection']=copy.deepcopy(self.shape)
        self.projection['report']['projection']['rules']=[dict(ipv6=False,priority=0,table=255,action=1,flags=0,fwmark=None,fwmask=None,suppress_prefixlen=None,suppress_ifgroup=None,goto=None,realm=None,protocol=None)]
        self.projection['remote']['stdout']=json.dumps(self.projection['report'])
        self.write(self.pp,self.projection);self.check['projection_sha256']=self.m.sha(self.pp)
        self.write(self.comparison,self.check);self.rebind();self.claim()
        with self.assertRaises(AssertionError):self.validate()

    def prepare_record(self, code, stdout=''):
        directory=self.cp.parent/self.m.LABEL;directory.mkdir()
        names={'controller-runner.py':'run-frozen-secret-bootstrap411.py','controller-guest.py':'secret-bootstrap.guest.py',
               'controller-context.py':'attachment_context_check.py','controller-host-declaration.py':'quarantine_host_declaration.py',
               'controller-baseline-declaration.py':'host_baseline_declaration.py'}
        for dest,source in names.items():self.write(directory/dest,pathlib.Path('target/platform-lab',source).read_bytes())
        self.write(directory/'controller-authored-baseline.json',self.template)
        self.write(directory/'controller-baseline-reconciliation.json',self.review)
        self.record.update(exit_code=code,stdout=stdout,stderr='',result='FAIL'if code else'PASS_PARTIAL_SECRET_BOOTSTRAP')
        self.write(self.m.RUN,self.record)
        return directory

    def test_collect_interrupted_before_raw(self):
        collector=module('collector_test','tools/rust-v2-lab/collect-run411-evidence.py')
        original_collect=collector.collect
        def quiet_collect(destination):
            with contextlib.redirect_stdout(io.StringIO()):return original_collect(destination)
        collector.collect=quiet_collect
        self.assertEqual(collector.collect('bundle'),0)
        receipt=json.loads(pathlib.Path('bundle/receipt.json').read_bytes())
        self.assertEqual(receipt['outcome'],'controller_interrupted_before_raw_record')
        self.assertFalse(receipt['runtime_acceptance'])

    def test_collect_early_failure_and_timeout(self):
        collector=module('collector_test','tools/rust-v2-lab/collect-run411-evidence.py')
        original_collect=collector.collect
        def quiet_collect(destination):
            with contextlib.redirect_stdout(io.StringIO()):return original_collect(destination)
        collector.collect=quiet_collect
        self.prepare_record(1)
        self.assertEqual(collector.collect('early-bundle'),0)
        self.record['exit_code']=124;self.write(self.m.RUN,self.record)
        self.assertEqual(collector.collect('timeout-bundle'),0)
        self.assertEqual(pathlib.Path('timeout-bundle/files',self.m.RUN).read_bytes(),self.m.RUN.read_bytes())

    def test_collect_success(self):
        collector=module('collector_success','tools/rust-v2-lab/collect-run411-evidence.py')
        descriptor=dict(deployment_id='synthetic',allocation={'generation':1},allocation_digest='d'*64)
        gateway=dict(host_network_namespace=[4,55])
        declaration=dict(schema_version=1,deployment_id='synthetic',generation=1,allocation_digest='d'*64,host_namespace=dict(dev=4,ino=55),baseline=self.shape)
        raw=json.dumps(declaration,sort_keys=True,separators=(',',':')).encode()
        import hashlib
        meta=dict(declaration=declaration,sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw),builder_sha256=self.record['baseline_declaration_builder_sha256'],template_sha256=self.m.sha(self.tp),template_baseline_sha256=self.digest(self.shape),review_sha256=self.m.sha(self.rp),authored_public_input_only=True,projection_matched_authored_shape=True,host_authority_granted=False)
        end={key:True for key in ('owner_unit_absent','host_single_down_link_added','host_addresses_routes_rules_preserved','host_stable_neighbors_preserved','inert_gateway_retained','original_gateway_native_identity_unchanged','canonical_and_mount_resources_retained')};end['harness_exit_code']=0
        stdout='\n'.join(json.dumps({key:value})for key,value in [('secret_attachment_descriptor',descriptor),('secret_attachment_gateway',gateway),('secret_host_baseline',meta),('secret_attachment_controller',end)])+'\nLAB_SECRET_BOOTSTRAP '+json.dumps({'synthetic_witness':True})
        self.prepare_record(0,stdout)
        with contextlib.redirect_stdout(io.StringIO()):self.assertEqual(collector.collect('success-bundle'),0)
        receipt=json.loads(pathlib.Path('success-bundle/receipt.json').read_bytes())
        self.assertTrue(receipt['baseline_declaration_checked']);self.assertFalse(receipt['runtime_acceptance'])
        self.assertEqual(receipt['full_bootstrap_witness_validation'],'NOT_RUN')

    def test_collect_invalid_preserves_raw(self):
        collector=module('collector_test','tools/rust-v2-lab/collect-run411-evidence.py')
        original_collect=collector.collect
        def quiet_collect(destination):
            with contextlib.redirect_stdout(io.StringIO()):return original_collect(destination)
        collector.collect=quiet_collect
        self.prepare_record(1);self.record['run_reservation']['sha256']='0'*64;self.write(self.m.RUN,self.record)
        self.assertEqual(collector.collect('invalid-bundle'),1)
        self.assertEqual(pathlib.Path('invalid-bundle/files',self.m.RUN).read_bytes(),self.m.RUN.read_bytes())
        self.assertIn('validation_error',json.loads(pathlib.Path('invalid-bundle/receipt.json').read_bytes()))

    def test_controller_error_before_raw_is_preserved(self):
        import ast,datetime,hashlib,re,subprocess,sys,time
        from unittest.mock import patch
        tree=ast.parse((ROOT/'target/platform-lab/run-frozen-secret-bootstrap411.py').read_bytes())
        block=next(n for n in tree.body if isinstance(n,ast.Try))
        names=dict(candidate_path=self.cp,candidate=self.c,label=self.m.LABEL,reservation_data=self.r,
                   reservation_module=self.m,path_guard=self.m,platform=self.m.PLATFORM,arch='arm64',port=22036,
                   known='target/platform-lab/debian-arm64/known_hosts',guest='',controller_bytes=b'synthetic',guest_bytes=b'synthetic',
                   listing='pass\n',
                   context_checker_bytes=b'synthetic',host_builder_bytes=b'synthetic',baseline_builder_bytes=b'synthetic',
                   template_bytes=self.tp.read_bytes(),review_bytes=self.rp.read_bytes(),
                   pathlib=pathlib,json=json,os=os,datetime=datetime,hashlib=hashlib,re=re,
                   subprocess=subprocess,sys=sys,time=time,contextlib=contextlib)
        argv=['runner',str(self.cp),self.m.PLATFORM,self.m.LABEL,'success','--reservation',str(self.m.RESERVATION)]
        with patch.object(sys,'argv',argv),patch.object(subprocess,'run',side_effect=subprocess.CalledProcessError(255,['synthetic-ssh'],stderr='synthetic disconnected')) as remote:
            with self.assertRaises(subprocess.CalledProcessError):exec(compile(ast.Module(body=[block],type_ignores=[]),'controller-post-admission','exec'),names)
            self.assertEqual(remote.call_count,1)
        error=json.loads(pathlib.Path('target/lab-state/run-411-controller-error.json').read_bytes())
        self.assertFalse(error['raw_record_present']);self.assertEqual(error['stderr'],'synthetic disconnected')
        self.assertEqual(error['budget_remaining'],0);self.assertFalse(self.m.RUN.exists())
        collector=module('error_collector','tools/rust-v2-lab/collect-run411-evidence.py')
        with contextlib.redirect_stdout(io.StringIO()):self.assertEqual(collector.collect('error-bundle'),0)
        self.assertTrue(pathlib.Path('error-bundle/files/target/lab-state/run-411-controller-error.json').exists())

    def test_fresh_deadline_reader(self):
        from unittest.mock import patch
        import sys
        parser=module('cost_reader_test','tools/rust-v2-lab/parse-bootstrap-cost-diagnostics.py')
        boundary=dict(helper='native_poll',step='result',reason='Deadline',original_requested_at='Some(10)',original_deadline='Some(12)',observed_boot_now='12.1')
        boundary.update({k:'false'for k in parser.BOOLS});boundary.update({k:'0'for k in parser.COUNTS})
        lines=['LAB_SECRET_BOOTSTRAP_BOUNDARY_FAILURE '+' '.join(k+'='+v for k,v in boundary.items())]
        lines += ['LAB_SECRET_BOOTSTRAP_WRAPPER_TOTAL helper='+helper+' calls=0 elapsed_ns=0 measurement=wrapper_elapsed_including_nested_validation'for helper in parser.HELPERS]
        lines += ['LAB_SECRET_BOOTSTRAP_NESTED_TOTAL family='+family+' category='+category+' calls=0 elapsed_ns=0 measurement=inclusive_nested_elapsed grouping=lab_loop_entry_step_family'for family in ('query','policy','other')for category in parser.CATEGORIES]
        self.record.update(exit_code=1,result='FAIL',production_changes=False,stderr='\n'.join(lines)+'\n')
        self.write(self.m.RUN,self.record)
        with patch.object(sys,'argv',['parser',str(self.m.RUN),'parsed.json']),contextlib.redirect_stdout(io.StringIO()):parser.main()
        result=json.loads(pathlib.Path('parsed.json').read_bytes())
        self.assertEqual(result['boundary']['helper'],'native_poll');self.assertEqual(result['boundary']['step'],'result')
        self.assertEqual(result['record_sha256'],self.m.sha(self.m.RUN))

    def test_baseline_dispatch_and_historical(self):
        directory = self.cp.parent / self.m.LABEL; directory.mkdir()
        builder = pathlib.Path('target/platform-lab/host_baseline_declaration.py').read_bytes()
        self.write(directory/'controller-baseline-declaration.py', builder)
        import hashlib
        self.record['baseline_declaration_builder_sha256'] = hashlib.sha256(builder).hexdigest()
        descriptor = dict(deployment_id='synthetic', allocation={'generation':1}, allocation_digest='d'*64)
        gateway = dict(host_network_namespace=[4,55])
        declaration = dict(schema_version=1, deployment_id='synthetic', generation=1, allocation_digest='d'*64,
                           host_namespace=dict(dev=4,ino=55),baseline=self.shape)
        raw = json.dumps(declaration,sort_keys=True,separators=(',',':')).encode()
        meta = dict(declaration=declaration,sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw),
                    builder_sha256=self.record['baseline_declaration_builder_sha256'],template_sha256=self.m.sha(self.tp),
                    template_baseline_sha256=self.digest(self.shape),review_sha256=self.m.sha(self.rp),
                    authored_public_input_only=True,projection_matched_authored_shape=True,host_authority_granted=False)
        def publish():
            self.write(directory/'controller-authored-baseline.json',self.template)
            self.write(directory/'controller-baseline-reconciliation.json',self.review)
        publish()
        self.q.validate_baseline_host(meta,descriptor,gateway,self.c,self.record,directory)
        self.review.pop('route'); self.review.pop('historical_continuity')
        self.review['prior_structure_reconstructed'] = self.review['ordering_only_aligned_after_exact_multiset_comparison'] = True
        self.write(self.rp,self.review); self.template['review_sha256']=self.m.sha(self.rp); self.write(self.tp,self.template)
        self.record['host_baseline_template_sha256']=meta['template_sha256']=self.m.sha(self.tp)
        self.record['baseline_reconciliation_sha256']=meta['review_sha256']=self.m.sha(self.rp)
        publish()
        with self.assertRaises(AssertionError):
            self.q.validate_baseline_host(meta,descriptor,gateway,self.c,self.record,directory)
        del self.record['run_reservation']
        self.q.validate_baseline_host(meta,descriptor,gateway,self.c,self.record,directory)
        self.review['prior_structure_reconstructed'] = False; self.write(self.rp,self.review)
        self.template['review_sha256']=self.m.sha(self.rp);self.write(self.tp,self.template)
        self.record['host_baseline_template_sha256']=meta['template_sha256']=self.m.sha(self.tp)
        self.record['baseline_reconciliation_sha256']=meta['review_sha256']=self.m.sha(self.rp);publish()
        with self.assertRaises(AssertionError):
            self.q.validate_baseline_host(meta,descriptor,gateway,self.c,self.record,directory)


if __name__ == '__main__':
    unittest.main(verbosity=2)
