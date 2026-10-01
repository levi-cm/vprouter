import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from host.orchestrate import load_site, compose_env
import router_runtime as runtime

class CollectorTests(unittest.TestCase):
    def test_router_name_and_tailscale_identity_are_independent(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'site.json'
            p.write_text(json.dumps(dict(name='immo-mullvad-1', profile='/etc/site.conf', state_dir='/var/lib/site', image_ref='sha256:'+'a'*64, compose_dir='/opt/site', tailscale_hostname='nico-vpn')))
            with patch('host.orchestrate._provider', return_value=None):
                self.assertEqual(compose_env(load_site(p))['TS_HOSTNAME'], 'nico-vpn')
    def test_neutral_probe_returns_verified_provider_evidence(self):
        data={'mullvad_exit_ip':True,'ip':'193.32.248.181','mullvad_exit_ip_hostname':'de-ber-wg-002'}
        with patch.object(runtime,'provider_probe',return_value=data), patch.object(runtime,'tailscale_ready',return_value=True):
            self.assertEqual(runtime.collector_probe()['public_exit'],data['ip'])
    def test_neutral_probe_rejects_unapproved_exit(self):
        with patch.object(runtime,'provider_probe',return_value={'mullvad_exit_ip':True}), patch.object(runtime,'tailscale_ready',return_value=False):
            with self.assertRaises(runtime.RuntimeErrorClosed):runtime.collector_probe()
