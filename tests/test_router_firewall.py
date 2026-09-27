from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]


class RouterFirewallContract(unittest.TestCase):
    def test_policy_is_complete_and_loads_atomically(self):
        policy = ROOT / "router.nft"
        self.assertTrue(policy.is_file())
        result = subprocess.run(
            ["sudo", "-n", "unshare", "--net", "/usr/sbin/nft", "-f", str(policy)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_forwarding_is_limited_to_tailscale_and_wireguard(self):
        policy = (ROOT / "router.nft").read_text()
        self.assertIn("hook forward priority -150; policy drop", policy)
        self.assertIn('iifname "tailscale0" oifname "wg0" meta oifkind "wireguard" ip saddr 100.64.0.0/10 accept', policy)
        self.assertIn('iifname "wg0" meta iifkind "wireguard" oifname "tailscale0" ct state established,related accept', policy)
        self.assertIn('iifname "tailscale0" meta nfproto ipv6 drop', policy)
        self.assertNotIn('oifname "eth0" accept', policy)


if __name__ == "__main__":
    unittest.main()
