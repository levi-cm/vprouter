"""Fail-closed ARM substrate tests, no QEMU starts."""
import ast,importlib.util,pathlib,tempfile,unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[2]
class Launcher(unittest.TestCase):
 def test_launcher_present(self):
  self.assertTrue((ROOT/'tools/rust-v2-lab/target/platform-lab/start-clean-debian-arm64.py').exists(),'ARM64 launcher missing')
 def load(self):
  p=ROOT/'tools/rust-v2-lab/target/platform-lab/start-clean-debian-arm64.py'
  if not p.exists():self.skipTest('launcher not implemented')
  s=importlib.util.spec_from_file_location('arm_launcher',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
 def test_bisect_and_live_guest_gate(self):
  m=self.load()
  with tempfile.TemporaryDirectory()as t:
   p=pathlib.Path(t)/'bisect';p.write_text('full PASS exit=0 50s\n')
   with self.assertRaises(AssertionError):m.bisect_gate(p,[])
   p.write_text('full PASS exit=0 50s\nBISECT_DONE\n')
   with self.assertRaises(AssertionError):m.bisect_gate(p,[123])
   self.assertEqual(m.bisect_gate(p,[]),m.FULL_SANDBOX)
   p.write_text('none PASS exit=0 50s\nBISECT_DONE\n')
   with self.assertRaisesRegex(AssertionError,'not_qualified'):m.bisect_gate(p,[])
 def test_argv(self):
  m=self.load();a=m.qemu_argv(ROOT,ROOT/'target/platform-lab/debian-arm64',m.FULL_SANDBOX)
  for k,v in [('-accel','tcg,thread=multi'),('-machine','virt,gic-version=3'),('-cpu','cortex-a72'),('-m','1024'),('-sandbox',m.FULL_SANDBOX)]:self.assertEqual(a[a.index(k)+1],v)
  self.assertIn('AAVMF_CODE.fd',str(a));self.assertIn('readonly=on',str(a));self.assertIn('22034',str(a));self.assertIn('serial.log',str(a))
 def test_existing_state_and_bad_instance_refused_before_commands(self):
  m=self.load()
  with tempfile.TemporaryDirectory()as t:
   root=pathlib.Path(t);(root/'target/platform-lab/debian-arm64').mkdir(parents=True)
   with patch.object(m.subprocess,'run',side_effect=AssertionError('external command')),patch.object(m.subprocess,'Popen',side_effect=AssertionError('QEMU forbidden')):
    with self.assertRaisesRegex(AssertionError,'existing_state'):m.start(root,'vprouter-run411-test')
    with self.assertRaisesRegex(AssertionError,'instance'):m.start(root,'vprouter-run410-test')
if __name__=='__main__':unittest.main(verbosity=2)
