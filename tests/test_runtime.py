import unittest
from unittest.mock import patch

from router_runtime import block_failed_provider, verify_boot_interfaces, verify_interfaces, verify_egress_response, withdraw_exit_node, RuntimeErrorClosed


class RuntimePreflight(unittest.TestCase):
    def test_provider_failure_withdraws_even_without_active_up_process(self):
        with patch("router_runtime.stop_process") as stop, patch("router_runtime.withdraw_exit_node") as down:
            block_failed_provider(None, "RuntimeErrorClosed")
        stop.assert_called_once_with(None)
        down.assert_called_once_with("RuntimeErrorClosed")

    def test_control_failure_withdraws_exit_advertisement(self):
        with patch("router_runtime.set_health") as health, patch("router_runtime.run") as run:
            withdraw_exit_node("Tailscale health check failed")
        health.assert_called_once_with("BLOCKED", "Tailscale health check failed")
        run.assert_called_once_with("tailscale", "down", timeout=5)

    def test_boot_waits_with_loopback_only_and_rejects_ordinary_uplink(self):
        verify_boot_interfaces({"lo"})
        with self.assertRaises(RuntimeErrorClosed):
            verify_boot_interfaces({"lo", "eth0"})

    def test_ordinary_interface_causes_closed_failure(self):
        with self.assertRaises(RuntimeErrorClosed):
            verify_interfaces({"lo", "wg0", "eth0"})
        with self.assertRaises(RuntimeErrorClosed):
            verify_interfaces({"lo", "tailscale0", "wg0", "veth2"})

    def test_expected_interfaces_are_accepted(self):
        verify_interfaces({"lo", "wg0"})
        verify_interfaces({"lo", "wg0", "tailscale0"})

    def test_egress_must_be_confirmed_by_provider(self):
        verify_egress_response({"mullvad_exit_ip": True})
        for response in ({"mullvad_exit_ip": False}, {}, {"mullvad_exit_ip": "true"}):
            with self.assertRaises(RuntimeErrorClosed):
                verify_egress_response(response)


if __name__ == "__main__":
    unittest.main()
