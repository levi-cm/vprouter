import base64
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from host.orchestrate import _normalized_nft, load_site, render_host_guard, render_quarantine, SiteError


def fake_key():
    return base64.b64encode(bytes(range(32))).decode()


class HostPolicyContract(unittest.TestCase):
    def test_quarantine_blocks_bridge_and_subnet_before_guard(self):
        policy = render_quarantine()
        self.assertIn("hook forward priority -310", policy)
        self.assertIn('iifname "br-vpr-uplink" drop', policy)
        self.assertIn('oifname "br-vpr-uplink" drop', policy)
        self.assertIn("ip saddr 10.255.240.0/29 drop", policy)
        self.assertIn("ip daddr 10.255.240.0/29 drop", policy)
        with tempfile.NamedTemporaryFile(mode="w") as stream:
            stream.write(policy)
            stream.flush()
            result = subprocess.run(["sudo", "-n", "unshare", "--net", "/usr/sbin/nft", "-f", stream.name],
                                    capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_router_policy_comparison_ignores_only_handles_and_counters(self):
        expected = {"nftables": [{"rule": {"handle": 1, "expr": [
            {"counter": {"packets": 0, "bytes": 0}}, {"drop": None}]}}]}
        changed_counter = {"nftables": [{"rule": {"handle": 9, "expr": [
            {"counter": {"packets": 100, "bytes": 5000}}, {"drop": None}]}}]}
        changed_rule = {"nftables": [{"rule": {"handle": 9, "expr": [
            {"counter": {"packets": 100, "bytes": 5000}}, {"accept": None}]}}]}
        changed_counter_semantics = {"nftables": [{"rule": {"handle": 9, "expr": [
            {"counter": {"packets": 100, "bytes": 5000, "name": "different"}}, {"drop": None}]}}]}
        self.assertEqual(_normalized_nft(expected), _normalized_nft(changed_counter))
        self.assertNotEqual(_normalized_nft(expected), _normalized_nft(changed_rule))
        self.assertNotEqual(_normalized_nft(expected), _normalized_nft(changed_counter_semantics))

    def make_site(self, profile_extra=""):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        profile = root / "provider.conf"
        profile.write_text(
            f"[Interface]\nPrivateKey = {fake_key()}\nAddress = 10.1.2.3/32\n"
            f"[Peer]\nPublicKey = {fake_key()}\nAllowedIPs = 0.0.0.0/0\n"
            f"Endpoint = 192.0.2.77:51820\n{profile_extra}"
        )
        profile.chmod(0o600)
        path = root / "site.json"
        path.write_text(json.dumps({
            "name": "max-vprouter", "profile": str(profile),
            "state_dir": str(root / "state"),
            "image_ref": "sha256:" + "a" * 64,
            "compose_dir": str(root),
        }))
        return path

    def test_guard_allows_only_provider_transport_from_dedicated_bridge(self):
        site = load_site(self.make_site())
        guard = render_host_guard(site)
        self.assertIn('iifname "br-vpr-uplink"', guard)
        self.assertIn("hook forward priority -150; policy accept", guard)
        self.assertIn('ip saddr 10.255.240.2 ip daddr 192.0.2.77 udp dport 51820 accept', guard)
        self.assertIn('iifname "br-vpr-uplink" drop', guard)
        self.assertIn('oifname "br-vpr-uplink" drop', guard)
        self.assertIn('output ip daddr 192.0.2.77 ip protocol icmp counter drop', guard)
        self.assertNotIn("PrivateKey", guard)
        self.assertNotIn(fake_key(), guard)
        policy_path = Path(self.temp.name) / "guard.nft"
        policy_path.write_text(guard)
        loaded = subprocess.run(
            ["sudo", "-n", "unshare", "--net", "/usr/sbin/nft", "-f", str(policy_path)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(loaded.returncode, 0, loaded.stderr)

    def test_endpoint_must_be_numeric_ipv4_and_full_tunnel(self):
        path = self.make_site()
        content = (path.parent / "provider.conf").read_text()
        (path.parent / "provider.conf").write_text(content.replace("192.0.2.77", "vpn.example.com"))
        with self.assertRaises(SiteError):
            load_site(path)
        (path.parent / "provider.conf").write_text(content.replace("0.0.0.0/0", "10.0.0.0/8"))
        with self.assertRaises(SiteError):
            load_site(path)

    def test_unpinned_image_and_name_collision_are_rejected(self):
        path = self.make_site()
        content = json.loads(path.read_text())
        content["image_ref"] = "vprouter:latest"
        path.write_text(json.dumps(content))
        with self.assertRaises(SiteError):
            load_site(path)
        content["image_ref"] = "sha256:" + "a" * 64
        content["name"] = "../../bad"
        path.write_text(json.dumps(content))
        with self.assertRaises(SiteError):
            load_site(path)


if __name__ == "__main__":
    unittest.main()
