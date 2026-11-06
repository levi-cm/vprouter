"""ARM admission program, syscall ABI and SSH endpoint regression tests."""
import importlib.util,pathlib,unittest
ROOT=pathlib.Path(__file__).resolve().parents[2]
def load(name):
 p=ROOT/'tools/rust-v2-lab'/name;s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
class ArmBaseline(unittest.TestCase):
 def test_arm_clock_and_wan(self):
  m=load('phase3-readonly-preflight.py');self.assertTrue(hasattr(m,'configured_remote'),'ARM admission configurator missing')
  if not hasattr(m,'configured_remote'):return
  remote=m.configured_remote('debian-arm64');compile(remote,'arm-admission','exec')
  self.assertIn("platform.machine()=='aarch64'",remote);self.assertIn("'enp0s1'",remote)
  self.assertIn('ctypes.c_long(113)',remote);self.assertNotIn('ctypes.c_long(228)',remote)
  self.assertNotIn("'docker','image','inspect'",remote)
  self.assertIn('frozen driver execution NOT_RUN',remote)
  self.assertEqual(m.configured_remote('debian-clean-x86_64'),m.REMOTE)
 def test_platform_binding(self):
  m=load('fresh-baseline.py');self.assertTrue(hasattr(m,'PLATFORMS'),'ARM baseline platform mapping missing')
  if not hasattr(m,'PLATFORMS'):return
  self.assertEqual(m.PLATFORMS['debian-arm64'],('arm64',22034,'enp0s1'))
  self.assertEqual(m.PLATFORMS['debian-clean-x86_64'],('amd64',22036,'ens2'))
if __name__=='__main__':unittest.main(verbosity=2)
