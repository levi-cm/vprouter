#!/usr/bin/env python3
"""Cross-run alias, guest binding and one-shot checks without guest actions."""
import copy,importlib.util,os,pathlib,unittest
if not __debug__:raise RuntimeError('optimized_python_refused')
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('fixtures411',ROOT/'tools/rust-v2-lab/test-run411-provenance.py')
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)

class Isolation(f.Declarations):
    def test_409_reservation_and_claim_cannot_alias_411(self):
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

    def test_411_admission_cannot_use_410_parameters(self):
        self.m.CLAIM.unlink()
        self.r['controller_boot_id']=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        self.rebind()
        args=(self.m.RESERVATION,self.cp,self.m.PLATFORM,self.m.LABEL,'success')
        with self.assertRaises(AssertionError):
            self.m.admit(pathlib.Path('target/lab-state/run-410-reservation.json'),*args[1:],preflight=True)
        with self.assertRaises(AssertionError):
            self.m.admit(*args[:3],'bootstrap410-driver-cost','success',preflight=True)
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
        collector=f.module('recursive_collector','tools/rust-v2-lab/collect-run411-evidence.py')
        with contextlib.redirect_stdout(io.StringIO()):self.assertEqual(collector.collect('recursive-bundle'),0)
        self.assertEqual(pathlib.Path('recursive-bundle/files',source).read_bytes(),source.read_bytes())
        self.assertEqual(pathlib.Path('recursive-bundle/files',helper).read_bytes(),helper.read_bytes())
        self.assertTrue(json.loads(pathlib.Path('recursive-bundle/receipt.json').read_bytes())['provenance_valid'])

class No410Access(f.Declarations):
    def test_410_paths_rejected_by_all_reservation_io(self):
        for fn,args in ((self.m.sha,()),(self.m.protected,()),(self.m.save,({},))):
            with self.assertRaisesRegex(AssertionError,'run410_access_forbidden'):
                fn(pathlib.Path('target/lab-state/run-410-consumed.json'),*args)

    def test_no_410_claim_access_and_wrong_run_refused(self):
        from unittest.mock import patch
        import builtins,runpy,sys
        real_open=builtins.open;real_os_open=os.open
        def forbidden(path):
            value=str(path)
            return 'run-410' in value or 'actual-program-run-410' in value
        def safe_open(path,*args,**kwargs):
            assert not forbidden(path),('forbidden_410_access',path)
            return real_open(path,*args,**kwargs)
        def safe_os_open(path,*args,**kwargs):
            assert not forbidden(path),('forbidden_410_access',path)
            return real_os_open(path,*args,**kwargs)
        with patch.object(builtins,'open',safe_open),patch.object(os,'open',safe_os_open):
            self.validate()
            for tool in ('inspect-secret-bootstrap411-failure.py','archive-secret-bootstrap411-selectors.py'):
                with patch.object(sys,'argv',[tool,'410','absent.json']):
                    with self.assertRaisesRegex(AssertionError,'explicit_run411_required'):
                        runpy.run_path(str(f.ROOT/'target'/tool),run_name='__main__')
            self.assertFalse(any(forbidden(p) for p in self.m.binding_paths()))
            self.m.CLAIM.unlink()
            self.r['controller_boot_id']=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip();self.rebind()
            args=(self.m.RESERVATION,self.cp,self.m.PLATFORM,self.m.LABEL,'success')
            fd,_=self.m.admit(*args,preflight=True);os.close(fd)
            with self.assertRaises(AssertionError):
                self.m.admit(pathlib.Path('target/lab-state/run-410-reservation.json'),*args[1:],preflight=True)
            self.assertFalse(self.m.CLAIM.exists())

class PriorEvidenceBoundary(f.Declarations):
    """Catch forbidden content opens, including aliases, before copying bytes."""
    def variants(self, run):
        return [f'target/lab-state/run-{run}-consumed.json',
                f'target/lab-state/run-{run}-reservation.json',
                f'target/lab-state/actual-program-run-{run}.json',
                f'target/lab-state/secret-bootstrap-failure-run-{run}.json',
                f'target/lab-state/secret-bootstrap-selector-archive-run-{run}.json',
                f'target/candidates/run{run}-old/bootstrap{run}-driver-cost/reference.json']

    def test_both_prior_runs_and_preserved_refused_by_all_io(self):
        for path in [p for run in (409,410) for p in self.variants(run)]+['/DATA/vprouter-lab/preserved/reference.json','//DATA/vprouter-lab/preserved/reference.json']:
            for fn,args in ((self.m.sha,()),(self.m.protected,()),(self.m.save,({},))):
                with self.subTest(path=path,fn=fn.__name__):
                    self.assert_forbidden_without_open(lambda:fn(path,*args),path)

    def assert_forbidden_without_open(self, action, path):
        import io
        from unittest.mock import patch
        real_io_open,real_os_open,real_lstat=io.open,os.open,pathlib.Path.lstat
        attempted=[]
        # Even a regression must never reach the real cold-preserved tree.
        class UnsafePreservedProbe(RuntimeError):pass
        def preserved(p):return '/'+str(p).lstrip('/')=='/DATA/vprouter-lab/preserved' or ('/'+str(p).lstrip('/')).startswith('/DATA/vprouter-lab/preserved/')
        def io_open(p,*a,**kw):
            if str(p)==str(path):attempted.append(str(p))
            if preserved(p):raise UnsafePreservedProbe('attempted preserved content I/O')
            return real_io_open(p,*a,**kw)
        def os_open(p,*a,**kw):
            if str(p)==str(path):attempted.append(str(p))
            if preserved(p):raise UnsafePreservedProbe('attempted preserved I/O')
            return real_os_open(p,*a,**kw)
        def lstat(p,*a,**kw):
            if preserved(p):raise UnsafePreservedProbe('attempted preserved traversal')
            return real_lstat(p,*a,**kw)
        with patch.object(io,'open',io_open),patch.object(os,'open',os_open),patch.object(pathlib.Path,'lstat',lstat):
            with self.assertRaises((AssertionError,OSError,KeyError)):action()
        self.assertEqual(attempted,[], 'forbidden content was opened before refusal')

    def test_symlinks_and_hardlinks_refused_before_hash_or_parse(self):
        for run in (409,410):
            source=pathlib.Path(self.variants(run)[0]);self.write(source,{'poison':run})
            for kind in ('symlink','parent-symlink','hardlink'):
                with self.subTest(run=run,kind=kind):
                    alias=pathlib.Path(f'target/alias-{kind}-{run}.json')
                    if kind=='symlink':alias.symlink_to(source.absolute())
                    elif kind=='parent-symlink':
                        parent=pathlib.Path(f'target/alias-parent-{run}');parent.symlink_to(source.parent.absolute(),target_is_directory=True)
                        alias=parent/source.name
                    else:os.link(source,alias)
                    for fn in (self.m.sha,self.m.protected):
                        self.assert_forbidden_without_open(lambda:fn(alias),alias)

    def test_candidate_exception_excludes_old_platform_evidence(self):
        for suffix in ('authored-host-baseline-debian-clean-x86_64.json',
                       'host-baseline-reconciliation-debian-clean-x86_64.json',
                       'host-projection-debian-clean-x86_64/record.json',
                       'native-preflight-debian-clean-x86_64/record.json',
                       'bootstrap410-driver-cost/controller.json'):
            path=self.cp.parent/suffix;self.write(path,{'old_platform_evidence':True})
            with self.subTest(path=str(path)):
                self.assert_forbidden_without_open(lambda:self.m.sha(path),path)
        for suffix in ('source.tar','arm64.payload','arm64.context.tar','root-verification.json'):
            path=self.cp.parent/suffix;self.write(path,{'frozen_input':True})
            self.assertEqual(len(self.m.sha(path)),64)

    def test_explicit_storage_bridge_translates_without_following_symlink(self):
        import hashlib
        from unittest.mock import patch
        logical=pathlib.Path('target/storage-bridge').absolute()
        physical=pathlib.Path('physical-storage').absolute();physical.mkdir()
        logical.symlink_to(physical,target_is_directory=True)
        source=physical/'admitted.json';self.write(source,{'admitted':411})
        alias=logical/source.name
        with patch.object(self.m,'TRUSTED_STORAGE_BRIDGES',{logical:physical},create=True):
            self.assertEqual(self.m.sha(alias),hashlib.sha256(source.read_bytes()).hexdigest())
            self.m.save(logical/'new.json',{'budget_remaining':1})
            self.assertEqual(self.m.protected(logical/'new.json')['budget_remaining'],1)
            logical.unlink();logical.symlink_to(pathlib.Path('other-storage').absolute(),target_is_directory=True)
            with self.assertRaises((AssertionError,OSError)):self.m.sha(alias)
        ordinary=pathlib.Path('target/unlisted-storage');ordinary.symlink_to(physical,target_is_directory=True)
        with self.assertRaises((AssertionError,OSError)):self.m.sha(ordinary/source.name)

    def test_supersession_never_follows_storage_bridge_for_link_or_unlink(self):
        from unittest.mock import patch
        logical=pathlib.Path('target/generation-storage').absolute()
        physical=pathlib.Path('generation-storage').absolute();physical.mkdir()
        logical.symlink_to(physical,target_is_directory=True)
        real_link,real_unlink=os.link,os.unlink
        def link(src,dst,*args,**kwargs):
            self.assertNotIn(str(logical),str(src));self.assertNotIn(str(logical),str(dst))
            return real_link(src,dst,*args,**kwargs)
        def unlink(path,*args,**kwargs):
            self.assertNotIn(str(logical),str(path))
            return real_unlink(path,*args,**kwargs)
        with patch.object(self.m,'TRUSTED_STORAGE_BRIDGES',{logical:physical},create=True), \
             patch.object(self.m,'RESERVATION',logical/'reservation.json'), \
             patch.object(self.m,'SUPERSESSION',logical/'supersession.json'), \
             patch.object(self.m,'CLAIM',logical/'claim.json'),patch.object(self.m,'RUN',logical/'run.json'):
            self.m.save(self.m.RESERVATION,dict(schema=1,run=411,one_shot_budget=1));old=self.m.sha(self.m.RESERVATION)
            with patch.object(os,'link',link),patch.object(os,'unlink',unlink):
                self.m.supersede(old,'synthetic guarded storage',dict(schema=2,run=411,one_shot_budget=1,supersedes_sha256=old))
            self.assertEqual(self.m.active()['supersedes_sha256'],old)

    def test_poisoned_collector_references_never_read_or_copied(self):
        import contextlib,hashlib,io,json
        from unittest.mock import patch
        for run in (409,410):
            source=pathlib.Path(self.variants(run)[0]);self.write(source,{'poison':run})
            for kind in ('direct','symlink','parent-symlink','hardlink'):
                alias=source
                if kind!='direct':
                    alias=pathlib.Path(f'target/poison-{kind}-{run}.json')
                    if kind=='symlink':alias.symlink_to(source.absolute())
                    elif kind=='parent-symlink':
                        parent=pathlib.Path(f'target/poison-parent-{run}');parent.symlink_to(source.parent.absolute(),target_is_directory=True);alias=parent/source.name
                    else:os.link(source,alias)
                for slot in ('binding','tombstone','prior_evidence','references','helpers'):
                    with self.subTest(run=run,kind=kind,slot=slot):
                        self.rebind()
                        ref=dict(path=str(alias),sha256=hashlib.sha256(source.read_bytes()).hexdigest())
                        self.review.pop('references',None);self.review.pop('helpers',None)
                        self.template['prior_evidence']=[dict(path=str(self.admission),sha256=self.m.sha(self.admission))]
                        tombstone=pathlib.Path('target/lab-state/run-411-supersession-poison.json')
                        if slot=='binding':self.r['bindings'].append(ref);self.write(self.m.RESERVATION,self.r)
                        elif slot=='tombstone':self.write(tombstone,dict(retained_path=str(alias)))
                        elif slot=='prior_evidence':self.template['prior_evidence'].append(ref)
                        else:self.review[slot]=[ref]
                        self.write(self.tp,self.template);self.write(self.rp,self.review)
                        collector=f.module('poison_collector','tools/rust-v2-lab/collect-run411-evidence.py')
                        destination=f'bundle-{run}-{kind}-{slot}'
                        attempted=[];real_io_open=io.open;real_os_open=os.open
                        def io_open(path,*args,**kwargs):
                            if str(path) in (str(source),str(alias)):attempted.append(str(path))
                            return real_io_open(path,*args,**kwargs)
                        def os_open(path,*args,**kwargs):
                            if str(path) in (str(source),str(alias),source.name,alias.name):attempted.append(str(path))
                            return real_os_open(path,*args,**kwargs)
                        with contextlib.redirect_stdout(io.StringIO()),patch.object(io,'open',io_open),patch.object(os,'open',os_open):
                            self.assertEqual(collector.collect(destination),1)
                        self.assertEqual(attempted,[],'poisoned reference opened before validation')
                        self.assertFalse(pathlib.Path(destination,'files',alias).exists(),'poisoned reference copied before validation')
                        receipt=json.loads(pathlib.Path(destination,'receipt.json').read_bytes())
                        self.assertFalse(any(row['path']==str(alias) for row in receipt['retained']))
                        if tombstone.exists():tombstone.unlink()

    def test_preserved_prefix_and_alias_refused_without_traversal(self):
        import contextlib,io
        from unittest.mock import patch
        preserved='/DATA/vprouter-lab/preserved/reference.json'
        alias=pathlib.Path('target/preserved-alias');alias.symlink_to('/DATA/vprouter-lab/preserved',target_is_directory=True)
        for index,path in enumerate((preserved,str(alias/'reference.json'))):
            with self.subTest(path=path):
                self.r['bindings'].append(dict(path=path,sha256='0'*64));self.write(self.m.RESERVATION,self.r)
                collector=f.module('preserved_collector','tools/rust-v2-lab/collect-run411-evidence.py')
                real_lstat=pathlib.Path.lstat;traversed=[]
                def lstat(p,*args,**kwargs):
                    if str(p).startswith('/DATA/vprouter-lab/preserved'):traversed.append(str(p))
                    return real_lstat(p,*args,**kwargs)
                with contextlib.redirect_stdout(io.StringIO()),patch.object(pathlib.Path,'lstat',lstat):
                    self.assertEqual(collector.collect('preserved-bundle-'+str(index)),1)
                self.assertEqual(traversed,[])
                self.assertFalse(list(pathlib.Path('preserved-bundle-'+str(index)).rglob('reference.json')))
                self.r['bindings'].pop()

    def test_provenance_rejects_recursive_prior_references(self):
        import hashlib
        for run in (409,410):
            source=pathlib.Path(self.variants(run)[0]);self.write(source,{'poison':run})
            for key in ('prior_evidence','references','helpers'):
                with self.subTest(run=run,key=key):
                    review=copy.deepcopy(self.review)
                    review[key]=[dict(path=str(source),sha256=hashlib.sha256(source.read_bytes()).hexdigest())]
                    self.write(self.rp,review)
                    self.template['review_sha256']=self.m.sha(self.rp);self.write(self.tp,self.template)
                    self.check['template_sha256']=self.m.sha(self.tp);self.write(self.comparison,self.check)
                    self.rebind()
                    self.assert_forbidden_without_open(lambda:self.q.validate_fresh_provenance(self.template,review,self.c),source)

    def test_cli_inputs_refused_before_read_or_guest_call(self):
        import runpy,sys,subprocess
        from unittest.mock import patch
        for run in (409,410):
            source=pathlib.Path(self.variants(run)[0]);self.write(source,{})
            for tool in ('inspect-secret-bootstrap411-failure.py','archive-secret-bootstrap411-selectors.py','platform-lab/run-frozen-secret-bootstrap411.py'):
                with self.subTest(run=run,tool=tool):
                    argv=[tool,'411',str(source)] if not tool.startswith('platform-lab') else [tool,str(source),'debian-arm64','bootstrap411-arm64','success','--reservation',str(self.m.RESERVATION),'--preflight-only']
                    with patch.object(sys,'argv',argv),patch.object(subprocess,'run',side_effect=AssertionError('unexpected guest call')):
                        self.assert_forbidden_without_open(lambda:runpy.run_path(str(f.ROOT/'target'/tool),run_name='__main__'),source)
            inspector=f.module('guard_inspector','tools/rust-v2-lab/inspect-run411-state.py')
            with patch.object(sys,'argv',['inspector',str(source)]),patch.object(subprocess,'run') as remote:
                with self.assertRaises((AssertionError,OSError,TypeError)):inspector.main()
                self.assertEqual(remote.call_count,0)

if __name__=='__main__':unittest.main(verbosity=2)
