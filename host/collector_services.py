#!/usr/bin/env python3
"""Rebind the local collector and suggestions after router namespace recreation."""
import json
from pathlib import Path
import subprocess
import sys
import time

CONFIG = Path('/etc/vprouter/collector-services.json')

def run(*args, **kwargs):
    return subprocess.run(args, check=True, timeout=60, **kwargs)

def main():
    cfg = json.loads(CONFIG.read_text())
    if sys.argv[1] == 'stop':
        run('systemctl', 'stop', 'immo-collector-v4.service')
        found = subprocess.run(['docker', 'inspect', 'pfarr-dietl-app-suggestions-1'], capture_output=True)
        if found.returncode == 0:
            run('docker', 'stop', '--time', '15', 'pfarr-dietl-app-suggestions-1')
        return
    if sys.argv[1] != 'start':
        raise ValueError('expected start or stop')
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        result = subprocess.run(['docker', 'exec', 'immo-mullvad-1', '/usr/local/bin/router-runtime', '--status'], capture_output=True, timeout=10)
        if result.returncode == 0:
            run('docker', 'compose', '-f', cfg['suggestions_compose'], '--project-name', 'pfarr-dietl-app', 'up', '-d', '--no-deps', '--force-recreate', 'suggestions')
            # Start after this service's ExecStartPost has finished to avoid an
            # ordering deadlock with the coordinator's After= router dependency.
            run('systemctl', '--no-block', 'start', 'immo-collector-v4.service')
            return
        time.sleep(2)
    raise RuntimeError('protected router did not become READY; clients stay stopped')

if __name__ == '__main__':
    main()
