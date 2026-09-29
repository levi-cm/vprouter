"""Execute the original bootstrap with controlled command failures; no real credentials."""
import json
import os
from pathlib import Path
import signal
import subprocess as sp
import time

if os.environ.get('VPROUTER_AUDIT_ISOLATED') != '1':
    raise SystemExit('Run only in the isolated disposable container described in README.md')
if any(link['ifname'] != 'lo' for link in json.loads(sp.check_output(['ip', '-j', 'link', 'show']))):
    raise SystemExit('Refusing to run bootstrap tests with non-loopback interfaces present')

root = Path('/audit/stubs')
root.mkdir(exist_ok=True)
stub = '''#!/bin/bash
name=${0##*/}
if [[ "$name" == tailscaled ]]; then exec /bin/sleep 300; fi
if [[ "$name" == tailscale ]]; then
  if [[ "$*" == 'status --json' ]]; then echo '{"MagicDNSSuffix":"audit.invalid"}'; fi
  exit 0
fi
if [[ "$name" == ip && "$*" == route ]]; then echo 'default via 192.0.2.1 dev eth0'; exit 0; fi
case "$FAIL_MODE:$name:$*" in
  invalid_key:wg:*) echo AUDIT_INJECTED_WG_FAILURE >&2; exit 1;;
  route_failure:ip:'route replace default dev wg0') echo AUDIT_INJECTED_ROUTE_FAILURE >&2; exit 2;;
  firewall_failure:iptables:*) echo AUDIT_INJECTED_FIREWALL_FAILURE >&2; exit 4;;
  dns_failure:dnsmasq:*) echo AUDIT_INJECTED_DNS_FAILURE >&2; exit 1;;
esac
exit 0
'''
for cmd in ['tailscaled', 'tailscale', 'ip', 'wg', 'iptables', 'dnsmasq']:
    p = root / cmd
    p.write_text(stub)
    p.chmod(0o755)

results = []
for mode in ['invalid_key', 'route_failure', 'firewall_failure', 'dns_failure']:
    env = os.environ | dict(PATH=str(root) + ':' + os.environ['PATH'], FAIL_MODE=mode,
        WIREGUARD_PRIVATEKEY='AUDIT_FAKE_KEY', WIREGUARD_ADDRESS='10.0.0.2/32',
        WIREGUARD_ENDPOINT='192.0.2.2:51820', WIREGUARD_PEERKEY='AUDIT_FAKE_PEER',
        DNS='9.9.9.9', VPR_DEBUG='true', TS_AUTHKEY='')
    logfile = Path('/audit/' + mode + '.log')
    with logfile.open('w') as stream:
        proc = sp.Popen(['/bin/bash', '/audit/bootstrap.sh'], env=env, stdout=stream,
            stderr=sp.STDOUT, start_new_session=True)
        deadline = time.monotonic() + 9
        while time.monotonic() < deadline:
            if 'Split DNS setup complete' in logfile.read_text():
                break
            time.sleep(.05)
        time.sleep(.1)
        output = logfile.read_text()
        row = dict(test=mode, injected_failure_observed='AUDIT_INJECTED_' in output,
            reported_wireguard_complete='WireGuard setup complete' in output,
            reported_dns_complete='Split DNS setup complete' in output,
            supervisor_still_running=proc.poll() is None)
        results.append(row)
        print(json.dumps(row), flush=True)
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()
        assert row['injected_failure_observed'] and row['reported_dns_complete'] and row['supervisor_still_running'], row
Path('/audit/startup-results.json').write_text(json.dumps(results, indent=2) + '\n')
