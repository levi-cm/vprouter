import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_host_policy import fake_key
from host.orchestrate import (SiteError, cleanup_owned, load_site, monitor, render_wg_config,
                              router_health,
                              runtime_health_state, stop_owned_container,
                              verify_router_policy, verify_router_tunnel)


ROOT = Path(__file__).resolve().parents[1]


class HostControlContract(unittest.TestCase):
    def test_monitor_restarts_after_status_command_quarantines(self):
        with patch("host.orchestrate.STOP", False), patch(
            "host.orchestrate.quarantine_active", return_value=True
        ), self.assertRaisesRegex(SiteError, "quarantine is active"):
            monitor(SimpleNamespace(name="max-vprouter"), "guard", "router")

    def test_status_reports_blocked_while_quarantine_is_active(self):
        with patch("host.orchestrate.quarantine_active", return_value=True), patch(
            "host.orchestrate.owned_running"
        ) as running, self.assertRaisesRegex(SiteError, "quarantine is active"):
            router_health("max-vprouter")
        running.assert_not_called()

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
        info = {"Config": {"Labels": {"com.docker.compose.project": "legacy-project"}},
                "State": {"Running": True}}
        with patch("host.orchestrate.container_info", return_value=info), patch(
            "host.orchestrate.command"
        ) as command, self.assertRaises(SiteError):
            stop_owned_container("max-vprouter", "hardened-project")
        command.assert_not_called()

    def test_cleanup_is_idempotent_after_container_stops(self):
        info = {"Config": {"Labels": {"com.docker.compose.project": "max-vprouter"}},
                "State": {"Running": False}}
        with patch("host.orchestrate.container_info", return_value=info), patch(
            "host.orchestrate.command"
        ) as command:
            stop_owned_container("max-vprouter", "max-vprouter")
        command.assert_not_called()

    def test_cleanup_rejects_container_replacement_during_stop(self):
        owned = {"Config": {"Labels": {"com.docker.compose.project": "max-vprouter"}},
                 "State": {"Running": True}}
        foreign = {"Config": {"Labels": {"com.docker.compose.project": "other"}},
                   "State": {"Running": False}}
        with patch("host.orchestrate.container_info", side_effect=[owned, foreign]), patch(
            "host.orchestrate.command", return_value=""
        ), self.assertRaisesRegex(SiteError, "ownership changed"):
            stop_owned_container("max-vprouter", "max-vprouter")

    def test_docker_api_failure_during_cleanup_keeps_quarantine_and_reports_failure(self):
        with patch("host.orchestrate.install_quarantine") as quarantine, patch(
            "host.orchestrate.container_info", side_effect=OSError("Docker unavailable")
        ), patch("host.orchestrate.release_quarantine") as release, self.assertRaisesRegex(
            SiteError, "cleanup unverified"
        ):
            cleanup_owned("max-vprouter")
        quarantine.assert_called_once()
        release.assert_not_called()

    def test_router_policy_drift_or_unreadable_table_quarantines(self):
        for snapshot in ("changed", OSError("nft unavailable"), KeyError("nftables")):
            with self.subTest(snapshot=snapshot), patch(
                "host.orchestrate.router_snapshot", side_effect=snapshot if isinstance(snapshot, Exception) else None,
                return_value=snapshot if isinstance(snapshot, str) else None
            ), patch("host.orchestrate.install_quarantine") as quarantine, self.assertRaises(
                (SiteError, OSError, KeyError)
            ):
                verify_router_policy(SimpleNamespace(name="max-vprouter"), "expected")
            quarantine.assert_called_once()

    def test_fresh_blocked_and_recovering_are_not_stalls(self):
        with patch("host.orchestrate.time.time", return_value=100):
            self.assertEqual(runtime_health_state({"state": "BLOCKED", "heartbeat": 99}), "BLOCKED")
            self.assertEqual(runtime_health_state({"state": "RECOVERING", "heartbeat": 99}), "RECOVERING")
            for data in ({"state": "READY", "heartbeat": 54},
                         {"state": "BLOCKED", "heartbeat": "99"},
                         {"state": "UNKNOWN", "heartbeat": 99}, []):
                with self.subTest(data=data), self.assertRaises(SiteError):
                    runtime_health_state(data)

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
