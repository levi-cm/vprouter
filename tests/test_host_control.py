import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_host_policy import fake_key
from host.orchestrate import SiteError, load_site, render_wg_config, stop_owned_container, verify_router_tunnel


ROOT = Path(__file__).resolve().parents[1]


class HostControlContract(unittest.TestCase):
    def test_monitor_requires_real_up_wireguard_and_its_default_route(self):
        good_link = json.dumps([{"ifname": "wg0", "flags": ["UP"],
                                 "linkinfo": {"info_kind": "wireguard"}}])
        good_route = json.dumps([{"dev": "wg0"}])
        with patch("host.orchestrate.inspect_pid", return_value=123), patch(
            "host.orchestrate.in_netns", side_effect=[good_link, good_route]
        ):
            verify_router_tunnel("max-vprouter")
        for bad_link in ("[]", json.dumps([{"ifname": "wg0", "flags": ["UP"],
                                            "linkinfo": {"info_kind": "dummy"}}]),
                         json.dumps([{"ifname": "wg0", "flags": [],
                                      "linkinfo": {"info_kind": "wireguard"}}])):
            with self.subTest(link=bad_link), patch("host.orchestrate.inspect_pid", return_value=123), patch(
                "host.orchestrate.in_netns", return_value=bad_link
            ), self.assertRaises(SiteError):
                verify_router_tunnel("max-vprouter")
        with patch("host.orchestrate.inspect_pid", return_value=123), patch(
            "host.orchestrate.in_netns", side_effect=[good_link, "[]"]
        ), self.assertRaises(SiteError):
            verify_router_tunnel("max-vprouter")

    def test_cleanup_never_stops_a_container_from_another_project(self):
        seen = []
        def fake_run(args, **_kwargs):
            seen.append(args)
            return subprocess.CompletedProcess(args, 0, "legacy-project\n", "")
        with patch("host.orchestrate.subprocess.run", side_effect=fake_run):
            stop_owned_container("max-vprouter", "hardened-project")
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0][1], "inspect")

    def test_cleanup_is_idempotent_after_container_stops(self):
        seen = []
        def fake_run(args, **_kwargs):
            seen.append(args)
            if len(seen) == 1:
                return subprocess.CompletedProcess(args, 0, "max-vprouter\n", "")
            return subprocess.CompletedProcess(args, 0, "false\n", "")
        with patch("host.orchestrate.subprocess.run", side_effect=fake_run):
            stop_owned_container("max-vprouter", "max-vprouter")
        self.assertEqual(len(seen), 2)

    def test_validate_does_not_print_private_key(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            profile = base / "profile.conf"
            profile.write_text(
                f"[Interface]\nPrivateKey = {fake_key()}\nAddress = 10.1.2.3/32\n"
                f"[Peer]\nPublicKey = {fake_key()}\nAllowedIPs = 0.0.0.0/0\n"
                f"Endpoint = 192.0.2.77:51820\n"
            )
            profile.chmod(0o600)
            site = base / "site.json"
            site.write_text(json.dumps({
                "name": "max-vprouter", "profile": str(profile),
                "state_dir": str(base / "state"),
                "image_ref": "sha256:" + "a" * 64,
                "compose_dir": str(ROOT),
            }))
            result = subprocess.run(
                [sys.executable, str(ROOT / "host" / "orchestrate.py"), "validate", "--config", str(site)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn(fake_key(), result.stdout + result.stderr)

    def test_wireguard_configuration_contains_only_peer_transport(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            profile = base / "profile.conf"
            profile.write_text(
                f"[Interface]\nPrivateKey = {fake_key()}\nAddress = 10.1.2.3/32\nDNS = 9.9.9.9\n"
                f"[Peer]\nPublicKey = {fake_key()}\nAllowedIPs = 0.0.0.0/0\n"
                f"Endpoint = 192.0.2.77:51820\n"
            )
            profile.chmod(0o600)
            site_path = base / "site.json"
            site_path.write_text(json.dumps({
                "name": "max-vprouter", "profile": str(profile),
                "state_dir": str(base / "state"),
                "image_ref": "sha256:" + "a" * 64,
                "compose_dir": str(ROOT),
            }))
            result = render_wg_config(load_site(site_path))
            self.assertIn("Endpoint = 192.0.2.77:51820", result)
            self.assertIn("AllowedIPs = 0.0.0.0/0", result)
            self.assertNotIn("DNS", result)
            self.assertNotIn("Address", result)


if __name__ == "__main__":
    unittest.main()
