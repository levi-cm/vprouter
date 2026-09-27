from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ImageContract(unittest.TestCase):
    def test_image_uses_reviewed_base_digests_and_minimal_tools(self):
        source = (ROOT / "Dockerfile").read_text()
        self.assertIn("tailscale/tailscale@sha256:", source)
        self.assertIn("alpine@sha256:", source)
        self.assertNotIn(":latest", source)
        self.assertIn("nftables", source)
        self.assertNotIn("dnsmasq", source)
        self.assertNotIn("jq", source)
        self.assertNotIn("bash", source)


if __name__ == "__main__":
    unittest.main()
