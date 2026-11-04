#!/usr/bin/env python3
"""Cross-run alias, guest binding and one-shot checks without guest actions."""
import copy,importlib.util,os,pathlib,unittest
if not __debug__:raise RuntimeError('optimized_python_refused')
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('fixtures410',ROOT/'tools/rust-v2-lab/test-run410-provenance.py')
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)

class Isolation(f.Declarations):
    def test_409_reservation_and_claim_cannot_alias_410(self):
        for name in ('RESERVATION','CLAIM','RUN','LOCK','SUPERSESSION'):
            self.assertNotIn('409',str(getattr(self.m,name)))
        original=copy.deepcopy(self.r)
        self.r['run']=409;self.rebind();self.claim()
        with self.assertRaises(AssertionError):self.validate()
        self.r=original;self.rebind();self.claim()
        self.record['run_reservation']['path']='target/lab-state/run-409-reservation.json'
        with self.assertRaises(AssertionError):self.validate()
        self.claim()
        claim=self.m.protected(self.m.CLAIM);claim['run']=409;self.write(self.m.CLAIM,claim)
        with self.assertRaises(AssertionError):self.validate()

    def test_410_admission_cannot_use_409_parameters(self):
        self.m.CLAIM.unlink()
        self.r['controller_boot_id']=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        self.rebind()
        args=(self.m.RESERVATION,self.cp,self.m.PLATFORM,self.m.LABEL,'success')
        with self.assertRaises(AssertionError):
            self.m.admit(pathlib.Path('target/lab-state/run-409-reservation.json'),*args[1:],preflight=True)
        with self.assertRaises(AssertionError):
            self.m.admit(*args[:3],'bootstrap409-driver-cost','success',preflight=True)
        self.assertFalse(self.m.CLAIM.exists())
        fd,_=self.m.admit(*args,preflight=True);os.close(fd)
        self.assertFalse(self.m.CLAIM.exists())
        fd,_=self.m.admit(*args);os.close(fd)
        with self.assertRaises(AssertionError):self.m.admit(*args,preflight=True)

    def test_collector_retains_recursive_and_absolute_helper_references(self):
        import contextlib,io,json
        source=pathlib.Path('target/extra-independent-reference.json')
        self.write(source,{'independent':'synthetic-only'})
        helper=pathlib.Path('tools/rust-v2-lab/fresh-baseline.py')
        self.review['references']=[dict(path=str(source),sha256=self.m.sha(source))]
        self.review['helpers']=[dict(path=str(helper.resolve()),sha256=self.m.sha(helper))]
        self.write(self.rp,self.review)
        self.template['review_sha256']=self.m.sha(self.rp);self.write(self.tp,self.template)
        self.record['host_baseline_template_sha256']=self.m.sha(self.tp)
        self.record['baseline_reconciliation_sha256']=self.m.sha(self.rp)
        self.check['template_sha256']=self.m.sha(self.tp);self.write(self.comparison,self.check)
        self.rebind();self.claim();self.prepare_record(1)
        collector=f.module('recursive_collector','tools/rust-v2-lab/collect-run410-evidence.py')
        with contextlib.redirect_stdout(io.StringIO()):self.assertEqual(collector.collect('recursive-bundle'),0)
        self.assertEqual(pathlib.Path('recursive-bundle/files',source).read_bytes(),source.read_bytes())
        self.assertEqual(pathlib.Path('recursive-bundle/files',helper).read_bytes(),helper.read_bytes())
        self.assertTrue(json.loads(pathlib.Path('recursive-bundle/receipt.json').read_bytes())['provenance_valid'])

if __name__=='__main__':unittest.main(verbosity=2)
