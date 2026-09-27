import json
import os
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DeploymentContract(unittest.TestCase):
    def compose(self):
        result = subprocess.run(
            ["docker", "compose", "-f", str(ROOT / "docker-compose.yaml"), "config", "--format", "json"],
            cwd=ROOT,
            env={**os.environ, "ROUTER_NAME": "audit-router", "ROUTER_IMAGE": "vprouter-audit:test"},
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_router_cannot_join_an_ordinary_network(self):
        services = self.compose()["services"]
        router = services["router"]
        self.assertEqual(router["network_mode"], "none")
        self.assertNotIn("networks", router)
        self.assertNotIn("ports", router)
        self.assertNotIn("env_file", router)

    def test_transport_is_separate_and_not_privileged(self):
        services = self.compose()["services"]
        transport = services["transport"]
        self.assertNotIn("network_mode", transport)
        self.assertNotIn("ports", transport)
        self.assertFalse(transport.get("privileged", False))
        self.assertEqual(transport["cap_drop"], ["ALL"])
        self.assertEqual(transport["restart"], "no")

    def test_router_has_no_provider_key_mount_or_docker_socket(self):
        router = self.compose()["services"]["router"]
        self.assertEqual(router["restart"], "no")
        self.assertTrue(router["read_only"])
        text = json.dumps(router)
        self.assertNotIn("wireguard.conf", text)
        self.assertNotIn("docker.sock", text)
        self.assertNotIn("TS_AUTHKEY", text)
        self.assertNotIn("WIREGUARD_PRIVATEKEY", text)

    def test_build_context_excludes_credentials_and_state(self):
        self.assertTrue((ROOT / ".dockerignore").is_file())
        patterns = set((ROOT / ".dockerignore").read_text().splitlines())
        for pattern in (".env*", "conf/", "tailscale/", "*.zip", "audit/"):
            self.assertIn(pattern, patterns)


if __name__ == "__main__":
    unittest.main()
