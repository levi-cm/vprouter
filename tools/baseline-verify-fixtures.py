#!/usr/bin/env python3
"""Verify synthetic compatibility fixtures against legacy code, offline."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from host import orchestrate  # noqa: E402
import router_runtime as runtime  # noqa: E402

FIXTURES = ROOT / "tests/fixtures/legacy"


def fixture(name):
    return json.loads((FIXTURES / name).read_text())


class CompatibilityFixtures(unittest.TestCase):
    def test_legacy_configs_and_validate_stdout(self):
        for name in ("site.json", "site-with-hostname.json"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                data = fixture(name)
                data["profile"] = str(FIXTURES / "fixture-router.conf")
                path = Path(tmp) / "site.json"
                path.write_text(json.dumps(data))
                site = orchestrate.load_site(path)
                self.assertEqual(site.tailscale_hostname, data.get("tailscale_hostname", data["name"]))
                self.assertEqual(site.provider.endpoint_ip, "192.0.2.10")
                output = io.StringIO()
                with patch.object(sys, "argv", ["orchestrate.py", "validate", "--config", str(path)]), contextlib.redirect_stdout(output):
                    self.assertEqual(orchestrate.main(), 0)
                self.assertEqual(json.loads(output.getvalue()), fixture("validate.json"))

    def test_health_documents_and_runtime_status(self):
        for name, state in (("health-ready.json", "READY"), ("health-blocked.json", "BLOCKED"), ("health-recovering.json", "RECOVERING")):
            data = fixture(name)
            with self.subTest(name=name), patch.object(orchestrate.time, "time", return_value=1700000003), patch.object(runtime.time, "time", return_value=1700000003):
                self.assertEqual(orchestrate.runtime_health_state(data), state)
                with tempfile.TemporaryDirectory() as tmp:
                    path = Path(tmp) / "health.json"
                    path.write_text(json.dumps(data))
                    with patch.object(runtime, "HEALTH", path), patch.object(sys, "argv", ["router-runtime", "--status"]):
                        self.assertEqual(runtime.main(), 0 if state == "READY" else 1)
                with patch.object(orchestrate.time, "time", return_value=1700000100):
                    with self.assertRaises(orchestrate.SiteError):
                        orchestrate.runtime_health_state(data)

    def test_host_status_stdout_shape(self):
        expected = fixture("host-status-ready.json")
        output = io.StringIO()
        with patch.object(orchestrate, "router_health", return_value=expected), patch.object(sys, "argv", ["orchestrate.py", "status", "--name", expected["name"]]), contextlib.redirect_stdout(output):
            self.assertEqual(orchestrate.main(), 0)
        self.assertEqual(json.loads(output.getvalue()), expected)

    def test_probe_stdout_and_unapproved_failure(self):
        data = fixture("provider-response.json")
        output = io.StringIO()
        with patch.object(runtime, "provider_probe", return_value=data), patch.object(runtime, "tailscale_ready", return_value=True), patch.object(sys, "argv", ["router-runtime", "--probe"]), contextlib.redirect_stdout(output):
            self.assertEqual(runtime.main(), 0)
        self.assertEqual(json.loads(output.getvalue()), fixture("probe.json"))
        with patch.object(runtime, "provider_probe", return_value=data), patch.object(runtime, "tailscale_ready", return_value=False):
            with self.assertRaises(runtime.RuntimeErrorClosed):
                runtime.collector_probe()


if __name__ == "__main__":
    unittest.main()
