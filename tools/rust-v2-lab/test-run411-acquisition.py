#!/usr/bin/env python3
"""End-to-end downstream replacement probes, no real claim or guest calls."""
import ast,builtins,contextlib,hashlib,importlib.util,inspect,io,json,os,pathlib,runpy,shutil,subprocess,sys,tarfile,tempfile,unittest
from unittest.mock import patch
if not __debug__:raise RuntimeError('optimized_python_refused')
ROOT=pathlib.Path(__file__).resolve().parents[2]
TOOLS=['run411-reservation.py','run411-provenance.py','collect-run411-evidence.py','inspect-run411-state.py','target/archive-secret-bootstrap411-selectors.py','target/inspect-secret-bootstrap411-failure.py','target/platform-lab/run-frozen-secret-bootstrap411.py']

# Reviewed complete argv expressions: read-only Git object operations, strict SSH
# with stdin programs, and SCP anonymous sources with explicit descriptor inheritance.
SUBPROCESS_CALLS = {
 "subprocess.check_output(['git', 'ls-tree', '-rz', '--name-only', commit])",
 "subprocess.check_output(['git', 'show', commit + ':' + item.name])",
 "subprocess.run(['scp', '-q', *opts, '/proc/self/fd/' + str(artifact_fd), 'vprouterlab@127.0.0.1:/home/vprouterlab/secret-attachment-' + candidate['platforms'][arch]['artifact_sha256']], pass_fds=(artifact_fd,), capture_output=True, check=True, timeout=30)",
 "subprocess.run(['scp', '-q', *opts, '/proc/self/fd/' + str(context_fd), 'vprouterlab@127.0.0.1:/home/vprouterlab/secret-attachment-context-' + candidate['platforms'][arch]['context_sha256']], pass_fds=(context_fd,), capture_output=True, check=True, timeout=45)",
 "subprocess.run(['ssh', '-F', '/dev/null', '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none', '-i', identity, '-p' + str(port), '-o', 'UserKnownHostsFile=' + known_hosts, '-o', 'StrictHostKeyChecking=yes', 'vprouterlab@127.0.0.1', 'sudo -n python3 -I -'], input=script, capture_output=True, text=True, timeout=30)",
 "subprocess.run([*ssh, 'sudo -n python3 -I -'], input=guest, capture_output=True, text=True, timeout=250)",
 "subprocess.run([*ssh, 'sudo -n python3 -I -'], input=listing, capture_output=True, text=True, check=True, timeout=15)",
 'subprocess.run(ssh, input=script, capture_output=True, text=True, timeout=30)',
}
# Exact remote literals are checked separately from host AST calls.
REMOTE_LITERALS = {
 '0f67c5743857671cf005af48412126a479b2eba56db33550a9008c6ea15b6a72': 'target/inspect-secret-bootstrap411-failure.py: embedded guest program; guest proc/public selectors only',
 '606204a5abe6e14f74b56334bd5897feca98cc5a9edaed88c71ed1661eb4a5b7': 'target/archive-secret-bootstrap411-selectors.py: embedded guest program; guest proc/public selectors only',
 'aa68bc5b44fc76a9fe41c9027bc53116e16d353c68adb136268475323decef98': 'target/platform-lab/run-frozen-secret-bootstrap411.py: embedded guest program; guest proc/public selectors only',
 'f0fe28ebc64fb3cb343c577a0bc9650498e016a1e2ce266fa3e05a56dbb7c3d1': 'inspect-run411-state.py: embedded guest program; guest proc/public selectors only',
}

# Initial fixed-path guard bootstraps are the trust root. All other code is
# compiled by load_module from acquired bytes.
GUARD_BOOTSTRAPS = {
 "importlib.util.spec_from_file_location('collector_path_guard', pathlib.Path(__file__).with_name('run411-reservation.py'))",
 "importlib.util.spec_from_file_location('provenance_guard', pathlib.Path(__file__).resolve().with_name('run411-reservation.py'))",
 "importlib.util.spec_from_file_location('run411_path_guard', 'tools/rust-v2-lab/run411-reservation.py')",
 "importlib.util.spec_from_file_location('state_reservation', 'tools/rust-v2-lab/run411-reservation.py')",
}

CONNECTION_DEFINITIONS = {
 "arch, port, known = {'debian-clean-x86_64': ('amd64', 22036, 'target/platform-lab/debian-clean-x86_64/known_hosts'), 'debian-x86_64': ('amd64', 22032, 'target/lab-state/known_hosts'), 'arch-x86_64': ('amd64', 22033, 'target/platform-lab/arch-x86_64/known_hosts'), 'debian-arm64': ('arm64', 22034, 'target/platform-lab/debian-arm64/known_hosts')}[platform]",
 "identity = json.loads(read_bytes('target/run411-prep/guest-identity.json'))",
 "identity, known_hosts = ssh_scope.enter_context(path_guard.ssh_material('target/lab-state/id_ed25519', known))",
 "opts = ['-F', '/dev/null', '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none', '-i', identity, '-P' + str(port), '-o', 'UserKnownHostsFile=' + known_hosts, '-o', 'StrictHostKeyChecking=yes']",
 "port, known = {'debian-arm64': (22036, 'target/platform-lab/debian-arm64/known_hosts'), 'debian-x86_64': (22032, 'target/lab-state/known_hosts'), 'debian-arm64': (22034, 'target/platform-lab/debian-arm64/known_hosts'), 'arch-x86_64': (22033, 'target/platform-lab/arch-x86_64/known_hosts')}[record['platform']]",
 "ssh = ['ssh', '-F', '/dev/null', '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none', '-i', identity, '-p' + str(port), '-o', 'UserKnownHostsFile=' + known_hosts, '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=5', 'vprouterlab@127.0.0.1']",
 "ssh = ['ssh', '-F', '/dev/null', '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none', '-o', 'BatchMode=yes', '-o', 'UpdateHostKeys=no', '-i', identity, '-p22034', '-o', 'UserKnownHostsFile=' + known_hosts, '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=5', 'vprouterlab@127.0.0.1', 'sudo -n python3 -I -']",
 'ssh_scope = contextlib.ExitStack()',
}

class Custody(unittest.TestCase):
 def test_downstream_replacements(self):
  """18 reviewer cases plus synthetic preserved: source, context, verifier, SCP."""
  original=ROOT/'target/candidates/run410-da75562-20261104'
  actual_tar,actual_open,actual_io_open,actual_os_open,actual_check,actual_run=tarfile.open,builtins.open,io.open,os.open,subprocess.check_output,subprocess.run
  for old in ('409','410','preserved'):
   for slot in ('source','context','verifier-source','scp-artifact','scp-context'):
    for kind in ('symlink','hardlink','regular-inode'):
     with self.subTest(old=old,slot=slot,kind=kind),tempfile.TemporaryDirectory(prefix='run411-custody-') as tmp:
      root=pathlib.Path(tmp);source=root/'source.tar';context=root/'arm64.context.tar';artifact=root/'arm64.payload'
      c=json.loads((original/'candidate.json').read_bytes())
      for name in ('source.tar','arm64.context.tar','arm64.payload','authored-host-baseline-debian-arm64.json','host-baseline-reconciliation-debian-arm64.json'):
       shutil.copyfile(original/name,root/name);(root/name).chmod(0o600)
      c['source']=str(source);c['platforms']['arm64']['artifact']=str(artifact);cp=root/'candidate.json';cp.write_text(json.dumps(c))
      poison=root/('preserved/old.json' if old=='preserved' else f'target/lab-state/actual-program-run-{old}.json');poison.parent.mkdir(parents=True);poison.write_bytes(b'FORBIDDEN-OLD-EVIDENCE-'+old.encode())
      target=artifact if slot=='scp-artifact' else context if slot in ('context','scp-context') else source
      injected=[];reads=[];transferred=[]
      def swap():
       if injected:return
       target.unlink()
       if kind=='symlink':target.symlink_to(poison)
       elif kind=='hardlink':os.link(poison,target)
       else:os.rename(poison,target)
       injected.append(True)
      class Reader:
       def __init__(self,stream):self.stream=stream
       def __getattr__(self,n):return getattr(self.stream,n)
       def read(self,*a):
        data=self.stream.read(*a)
        if b'FORBIDDEN-OLD-EVIDENCE' in data:reads.append(data)
        return data
       def __enter__(self):return self
       def __exit__(self,*a):return self.stream.__exit__(*a)
      def watch(real,p,*a,**kw):
       stream=real(p,*a,**kw)
       return Reader(stream) if injected and isinstance(p,(str,os.PathLike)) and pathlib.Path(p)==target else stream
      def tar_open(name=None,*a,**kw):
       if slot in ('source','context') and any(fr.function=='context_check' for fr in inspect.stack()):swap()
       return actual_tar(name,*a,**kw)
      def check(argv,*a,**kw):
       if slot=='verifier-source' and (argv[:2]==['git','ls-tree'] or len(argv)>2 and argv[2]=='tools/verify-frozen-build-inputs.py'):swap()
       return actual_check(argv,*a,**kw)
      # Execute the complete runner. Admission, publication and remote calls
      # are intercepted: neither a real claim nor a real raw record can exist.
      before=pathlib.Path(os.environ['RUN411_BEFORE_ROOT']) if 'RUN411_BEFORE_ROOT' in os.environ else None
      runner_path=(before/'target/platform-lab/run-frozen-secret-bootstrap411.py') if before else ROOT/'target/platform-lab/run-frozen-secret-bootstrap411.py'
      argv=[str(runner_path),str(cp),'debian-arm64','bootstrap411-arm64','success','--reservation','UNREACHABLE']
      error=None;admissions=[];saves=[]
      real_spec=importlib.util.spec_from_file_location
      def guard_spec(name,path,*a,**kw):
       if before and pathlib.Path(path).name=='run411-reservation.py':path=before/'run411-reservation.py'
       spec=real_spec(name,path,*a,**kw);real_exec=spec.loader.exec_module
       def execute(module):
        if name=='fresh_provenance':
         module.validate_fresh_provenance=lambda *a:dict(guest_boot_id='synthetic-no-guest');return
        real_exec(module)
        if pathlib.Path(path).name=='run411-reservation.py':
         real_save,real_sha=module.save,module.sha
         def save(p,data):
          self.assertIn(pathlib.Path(p).name,('actual-program-run-411.json','run-411-controller-error.json'))
          dest=root/'saved'/pathlib.Path(p).name;dest.parent.mkdir(exist_ok=True)
          saves.append(str(dest));real_save(dest,data)
         module.save=save
         if hasattr(module,'ssh_material'):
          @contextlib.contextmanager
          def material(*a):yield str(root/'synthetic-identity'),str(root/'synthetic-known-hosts')
          module.ssh_material=material
         module.sha=lambda p: 'f'*64 if str(p)=='UNREACHABLE' else real_sha(p)
         def admit(path,*a,provenance_check=None,**kw):
          self.assertEqual(path,'UNREACHABLE');admissions.append('synthetic only')
          if provenance_check:provenance_check()
          return None,dict(guest_boot_id='synthetic-no-guest')
         module.admit=admit
         if hasattr(module,'load_module'):
          real_load=module.load_module
          def load(n,p):
           if n=='fresh_provenance':
            import types
            return types.SimpleNamespace(validate_fresh_provenance=lambda *a:dict(guest_boot_id='synthetic-no-guest'))
           return real_load(n,p)
          module.load_module=load
        if name=='fresh_provenance':module.validate_fresh_provenance=lambda *a:dict(guest_boot_id='synthetic-no-guest')
       spec.loader.exec_module=execute;return spec
      def local_run(argv,*a,**kw):
       if argv[0]=='git' or len(argv)>2 and argv[2]=='tools/verify-frozen-build-inputs.py':return actual_run(argv,*a,**kw)
       import types
       if argv[0]=='scp':
        if slot.startswith('scp-'):swap()
        p=argv[-2];fd=int(p.rsplit('/',1)[1]) if p.startswith('/proc/self/fd/') else None
        if fd is None:raw=pathlib.Path(p).read_bytes()
        else:
         self.assertIn(fd,kw['pass_fds']);raw=os.pread(fd,os.fstat(fd).st_size,0)
         with self.assertRaises(OSError):os.write(fd,b'poison')
        if b'FORBIDDEN-OLD-EVIDENCE' in raw:reads.append(raw)
        transferred.append(hashlib.sha256(raw).hexdigest())
        return types.SimpleNamespace(returncode=0,stdout='',stderr='')
       if argv[0]=='ssh':return types.SimpleNamespace(returncode=0,stdout='[]' if kw.get('timeout')==15 else '',stderr='')
       raise AssertionError(('unexpected subprocess',argv))
      with patch.object(importlib.util,'spec_from_file_location',side_effect=guard_spec),patch.object(sys,'argv',argv),patch.object(tarfile,'open',tar_open),patch.object(subprocess,'check_output',check),patch.object(builtins,'open',lambda p,*a,**k:watch(actual_open,p,*a,**k)),patch.object(io,'open',lambda p,*a,**k:watch(actual_io_open,p,*a,**k)),patch.object(subprocess,'run',side_effect=local_run),contextlib.redirect_stdout(io.StringIO()):
       try:runpy.run_path(str(runner_path),run_name='__main__')
       except SystemExit as e:
        if e.code!=0:error=e
       except Exception as e:error=e
      if error is None:
       self.assertEqual(admissions,['synthetic only'])
       self.assertEqual(transferred,[c['platforms']['arm64']['artifact_sha256'],c['platforms']['arm64']['context_sha256']])
       self.assertEqual(saves,[str(root/'saved/actual-program-run-411.json')])
      self.assertTrue(injected,repr(error))
      self.assertEqual(reads,[],repr(error))
      self.assertIsNone(error)

 def test_acquisition_replacement_after_first_lstat(self):
  spec=importlib.util.spec_from_file_location('race_guard',ROOT/'tools/rust-v2-lab/run411-reservation.py');guard=importlib.util.module_from_spec(spec);spec.loader.exec_module(guard)
  actual=pathlib.Path.lstat
  for old in ('409','410','preserved'):
   for kind in ('symlink','hardlink','regular-inode'):
    with self.subTest(old=old,kind=kind),tempfile.TemporaryDirectory() as tmp:
     root=pathlib.Path(tmp);target=root/'admitted';target.write_bytes(b'valid')
     poison=root/('preserved/old' if old=='preserved' else 'run-'+old+'-consumed.json');poison.parent.mkdir(exist_ok=True);poison.write_bytes(b'forbidden')
     swapped=[]
     def lstat(path,*a,**kw):
      info=actual(path,*a,**kw)
      if path==target and not swapped:
       target.unlink()
       if kind=='symlink':target.symlink_to(poison)
       elif kind=='hardlink':os.link(poison,target)
       else:os.rename(poison,target)
       swapped.append(True)
      return info
     with patch.object(pathlib.Path,'lstat',lstat),patch.object(os,'fdopen',side_effect=AssertionError('forbidden content stream')):
      with self.assertRaises((AssertionError,OSError)):guard.acquire(target)
     self.assertTrue(swapped)

 def test_ssh_material_is_exclusive_private_snapshot(self):
  for old in ('409','410','preserved'):
   for kind in ('symlink','hardlink','regular-inode'):
    for slot in ('identity','known-hosts'):
     with self.subTest(old=old,kind=kind,slot=slot),tempfile.TemporaryDirectory() as tmp:
      spec=importlib.util.spec_from_file_location('ssh_guard',ROOT/'tools/rust-v2-lab/run411-reservation.py');guard=importlib.util.module_from_spec(spec);spec.loader.exec_module(guard)
      root=pathlib.Path(tmp);key=root/'original-key';pins=root/'original-pins'
      key.write_bytes(b'synthetic-identity');pins.write_bytes(b'synthetic-pins')
      poison=root/('preserved/old' if old=='preserved' else 'run-'+old+'-consumed.json');poison.parent.mkdir(exist_ok=True);poison.write_bytes(b'FORBIDDEN')
      guard.freeze_inputs();guard.acquire(key);guard.acquire(pins)
      target=key if slot=='identity' else pins;target.unlink()
      if kind=='symlink':target.symlink_to(poison)
      elif kind=='hardlink':os.link(poison,target)
      else:os.rename(poison,target)
      entered=False
      try:
       with guard.ssh_material(key,pins) as (staged_key,staged_pins):
        entered=True
        self.assertEqual(pathlib.Path(staged_key).read_bytes(),b'synthetic-identity')
        self.assertEqual(pathlib.Path(staged_pins).read_bytes(),b'synthetic-pins')
        self.assertEqual(pathlib.Path(staged_key).stat().st_mode&0o777,0o600)
        self.assertEqual(pathlib.Path(staged_key).parent.stat().st_mode&0o777,0o700)
       self.assertFalse(pathlib.Path(staged_key).exists())
      except (AssertionError,OSError):
       if entered or kind=='regular-inode':raise

 def test_frozen_verifier_equivalence(self):
  spec=importlib.util.spec_from_file_location('verifier_guard',ROOT/'tools/rust-v2-lab/run411-reservation.py');guard=importlib.util.module_from_spec(spec);spec.loader.exec_module(guard)
  cp=ROOT/'target/candidates/run410-da75562-20261104/candidate.json';candidate=json.loads(cp.read_bytes());source=pathlib.Path(candidate['source'])
  expected=json.loads(subprocess.check_output([sys.executable,'-B',str(ROOT/'tools/verify-frozen-build-inputs.py'),str(source),candidate['source_commit']]))
  self.assertEqual(guard.verify_source(guard.acquire(source).data,candidate['source_commit']),expected)

class StaticBoundary(unittest.TestCase):
 def scan(self,source,filename):
  violations=[]
  primitive={'parent_fd','acquire','open_exclusive','sync_directory','lock'}
  guards={'path_guard','guard','module','m','_run411_guard'}
  def visit(node,fn=None):
   if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):fn=node.name
   if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id in ('ssh','opts','known','port','identity','known_hosts','ssh_scope') for target in node.targets for t in ast.walk(target)):
    if ast.unparse(node) not in CONNECTION_DEFINITIONS:violations.append((node.lineno,'unreviewed connection definition'))
   if isinstance(node,ast.Call):
    f=node.func
    if isinstance(f,ast.Name) and f.id=='open':violations.append((node.lineno,'builtin open'))
    if isinstance(f,ast.Attribute):
     receiver=ast.unparse(f.value)
     if f.attr=='spec_from_file_location' and ast.unparse(node) not in GUARD_BOOTSTRAPS:violations.append((node.lineno,'unchecked code loader'))
     if f.attr in ('append','extend','insert') and receiver in ('ssh','opts'):violations.append((node.lineno,'connection mutation'))
     if f.attr in ('read_bytes','read_text','write_bytes','write_text') and receiver not in guards:violations.append((node.lineno,ast.unparse(node)))
     if f.attr=='open' and not (filename=='run411-reservation.py' and receiver=='os' and fn in primitive or receiver in ('path_guard.ByteTarfiles','ByteTarfiles') or receiver=='tarfile' and any(k.arg=='fileobj' for k in node.keywords)):
      violations.append((node.lineno,ast.unparse(node)))
     if f.attr in ('run','check_output','Popen') and receiver=='subprocess':
      text=ast.unparse(node)
      if text not in SUBPROCESS_CALLS:violations.append((node.lineno,'unreviewed subprocess: '+text))
      # No source, context, artifact, or any checked Path may be passed as a
      # pathname. Only stdin bytes/programs, literal commands, Git object names,
      # SSH fixed credentials/options and pinned anonymous fd strings survive.
      for arg in ast.walk(node):
       if isinstance(arg,ast.Call) and isinstance(arg.func,ast.Name) and arg.func.id=='str' and arg.args and isinstance(arg.args[0],ast.Name) and arg.args[0].id not in ('port','artifact_fd','context_fd'):
        violations.append((node.lineno,text))
   if isinstance(node,ast.Constant) and isinstance(node.value,str) and any(x in node.value for x in ('.read_bytes(','.read_text(','open(')):
    if hashlib.sha256(node.value.encode()).hexdigest() not in REMOTE_LITERALS:violations.append((node.lineno,'unreviewed embedded by-path I/O'))
   for child in ast.iter_child_nodes(node):visit(child,fn)
  visit(ast.parse(source));return violations
 def test_no_pathname_consumers(self):
  root=pathlib.Path(os.environ.get('RUN411_STATIC_ROOT',str(ROOT/'tools/rust-v2-lab')))
  for name in TOOLS:
   with self.subTest(tool=name):self.assertEqual(self.scan((root/name).read_text(),pathlib.Path(name).name),[])
 def test_boundary_detects_regressions(self):
  for bad in ('path.open("rb")','path.read_bytes()','path.read_text()','json.load(open(path))','subprocess.run(["scp",str(source),remote])','subprocess.run([python,str(checked)])','subprocess.run(["scp",source,remote])','subprocess.run([checked])','tarfile.open(source)','script="path.read_bytes()"','importlib.util.spec_from_file_location("bad", checked)','opts=[source]','opts.append(source)','identity=source','known_hosts=source','path.write_text("overwrite")'):
   self.assertTrue(self.scan(bad,'runner.py'),bad)

if __name__=='__main__':unittest.main(verbosity=2)
