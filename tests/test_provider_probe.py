import contextlib
import io
import json
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError

import router_runtime as runtime


class ProviderProbe(unittest.TestCase):
    def setUp(self):
        self.responses = [b'{"mullvad_exit_ip": true}']
        self.requests = 0
        self.interfaces = ["lo", "wg0", "tailscale0"]
        self.route = [{"dev": "wg0"}]
        self.handshake = 1999999990
        self.logs = io.StringIO()
        # Only external commands, HTTPS, and the clock are replaced. The
        # provider, interface, route, and handshake validation remain real.
        for replacement in (
            patch.object(runtime, "run", side_effect=self.run_command),
            patch.object(runtime.urllib.request, "urlopen", side_effect=self.request),
            patch.object(runtime.time, "time", return_value=2000000000),
            patch.object(runtime.time, "sleep"),
            contextlib.redirect_stderr(self.logs),
        ):
            replacement.__enter__()
            self.addCleanup(replacement.__exit__, None, None, None)

    def run_command(self, *args, **kwargs):
        if args == ("ip", "-j", "link", "show"):
            return json.dumps([{"ifname": name} for name in self.interfaces])
        if args == ("ip", "-j", "-4", "route", "show", "default"):
            return json.dumps(self.route)
        if args == ("ip", "-j", "-6", "route", "show", "default"):
            return "[]"
        if args == ("wg", "show", "wg0", "latest-handshakes"):
            return f"public-key\t{self.handshake}\n"
        raise AssertionError(args)

    def request(self, url, timeout):
        self.assertEqual(url, "https://am.i.mullvad.net/json")
        self.assertLessEqual(timeout, 12)
        self.requests += 1
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return io.BytesIO(response)

    def test_transient_http_error_recovers_with_provider_confirmation(self):
        for code in (408, 429, 500, 502, 503, 504):
            with self.subTest(code=code):
                self.responses = [HTTPError("https://secret.invalid/", code, "secret", {}, None),
                                  b'{"mullvad_exit_ip": true}']
                runtime.provider_probe()
                self.assertEqual(self.responses, [])
        self.assertNotIn("secret", self.logs.getvalue())
        self.assertIn("HTTP 429", self.logs.getvalue())

    def test_collector_probe_returns_provider_data_after_transient_failure(self):
        data = {"mullvad_exit_ip": True, "ip": "192.0.2.10",
                "mullvad_exit_ip_hostname": "test-relay"}
        self.responses = [HTTPError("https://secret.invalid/", 503, "secret", {}, None),
                          json.dumps(data).encode()]
        with patch.object(runtime, "tailscale_ready", return_value=True):
            result = runtime.collector_probe()
        self.assertEqual(result["public_exit"], data["ip"])
        self.assertEqual(result["relay"], data["mullvad_exit_ip_hostname"])
        self.assertEqual(self.requests, 2)

    def test_transient_transport_error_recovers_once(self):
        for error in (URLError("secret"), TimeoutError("secret"), ConnectionResetError("secret")):
            with self.subTest(error=type(error).__name__):
                self.responses = [error, b'{"mullvad_exit_ip": true}']
                runtime.provider_probe()
                self.assertEqual(self.responses, [])

    def test_repeated_failure_still_fails_closed_after_two_requests(self):
        self.responses = [HTTPError("https://secret.invalid/", 503, "secret", {}, None),
                          URLError("secret"), b'{"mullvad_exit_ip": true}']
        with self.assertRaises(URLError):
            runtime.provider_probe()
        self.assertEqual(self.requests, 2)
        self.assertEqual(len(self.responses), 1)

    def test_permanent_http_error_is_not_retried(self):
        for code in (400, 401, 403, 404):
            with self.subTest(code=code):
                self.responses = [HTTPError("https://secret.invalid/", code, "secret", {}, None),
                                  b'{"mullvad_exit_ip": true}']
                with self.assertRaises(HTTPError):
                    runtime.provider_probe()
                self.assertEqual(len(self.responses), 1)

    def test_negative_or_malformed_provider_confirmation_is_not_retried(self):
        for body in (b'{"mullvad_exit_ip": false}', b'{}', b'[]', b'invalid json'):
            with self.subTest(body=body):
                self.responses = [body, b'{"mullvad_exit_ip": true}']
                with self.assertRaises((runtime.RuntimeErrorClosed, ValueError)):
                    runtime.provider_probe()
                self.assertEqual(len(self.responses), 1)

    def test_stale_handshake_prevents_retry(self):
        self.handshake = 1999999800
        self.responses = [URLError("temporary"), b'{"mullvad_exit_ip": true}']
        with self.assertRaisesRegex(runtime.RuntimeErrorClosed, "handshake"):
            runtime.provider_probe()
        self.assertEqual(self.requests, 1)

    def test_route_or_interface_drift_during_retry_fails_closed(self):
        for fault in ("route", "interface", "handshake"):
            with self.subTest(fault=fault):
                self.route = [{"dev": "wg0"}]
                self.interfaces = ["lo", "wg0", "tailscale0"]
                self.handshake = 1999999990
                before = self.requests
                def drift(_delay):
                    if fault == "route":
                        self.route = [{"dev": "eth0"}]
                    elif fault == "interface":
                        self.interfaces.append("eth0")
                    else:
                        self.handshake = 1999999800
                self.responses = [URLError("temporary"), b'{"mullvad_exit_ip": true}']
                with patch.object(runtime.time, "sleep", side_effect=drift):
                    with self.assertRaises(runtime.RuntimeErrorClosed):
                        runtime.provider_probe()
                self.assertEqual(self.requests - before, 1)

    def test_retry_cannot_override_negative_provider_confirmation(self):
        self.responses = [URLError("temporary"), b'{"mullvad_exit_ip": false}']
        with self.assertRaises(runtime.RuntimeErrorClosed):
            runtime.provider_probe()
        self.assertEqual(self.requests, 2)

    def test_handshake_accepts_normal_rekey_window_but_rejects_expiry(self):
        for age, accepted in ((0, True), (119, True), (179, True), (180, False), (-1, False)):
            with self.subTest(age=age):
                self.handshake = 2000000000 - age
                self.responses = [b'{"mullvad_exit_ip": true}']
                if accepted:
                    runtime.provider_probe()
                else:
                    with self.assertRaises(runtime.RuntimeErrorClosed):
                        runtime.provider_probe()

    def test_success_response_still_requires_fresh_handshake(self):
        self.handshake = 1999999800
        with self.assertRaisesRegex(runtime.RuntimeErrorClosed, "handshake"):
            runtime.provider_probe()

    def test_http_failure_reason_includes_status_without_url(self):
        error = HTTPError("https://secret.invalid/", 429, "secret", {}, None)
        self.assertEqual(runtime.failure_reason(error), "HTTPError (HTTP 429)")


if __name__ == "__main__":
    unittest.main()
