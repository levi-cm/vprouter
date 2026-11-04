#!/usr/bin/env python3
"""Read-only liveness check of the existing clean-Debian guest; no lifecycle actions.

Run from any directory. Exit zero only for a live matching QEMU, loopback
listener and successful dedicated-key/single-pin strict SSH with guest boot ID.
"""
import json
import pathlib
import re
import subprocess
import sys


def main():
    repo = pathlib.Path(__file__).resolve().parents[2]
    state = repo / 'target/platform-lab/debian-clean-x86_64'
    result = dict(qemu_alive=False, argv_match=False, port_22036_listener=False,
                  strict_ssh_reachable=False, guest_boot_id=None)
    errors = []
    try:
        expected = json.loads((state / 'process.json').read_text())['argv']
        pid = int((state / 'qemu.pid').read_text())
        raw = pathlib.Path('/proc', str(pid), 'stat').read_text()
        fields = raw[raw.rfind(')') + 2:].split()
        actual = pathlib.Path('/proc', str(pid), 'cmdline').read_bytes().split(b'\0')[:-1]
        result.update(qemu_pid=pid, qemu_start_tick=int(fields[19]),
                      qemu_alive=fields[0] not in ('Z', 'X') and bool(actual)
                      and actual[0] == expected[0].encode(),
                      argv_match=actual == [v.encode() for v in expected])
    except (OSError, ValueError, KeyError, IndexError) as exc:
        errors.append(str(exc))
    try:
        listener = subprocess.run(['ss', '-H', '-ltn', 'sport = :22036'],
                                  capture_output=True, text=True, timeout=5, check=True)
        result['port_22036_listener'] = any(
            line.split()[3] == '127.0.0.1:22036'
            for line in listener.stdout.splitlines() if len(line.split()) >= 4)
    except (OSError, subprocess.SubprocessError) as exc:
        errors.append(str(exc))
    command = ['ssh', '-F', '/dev/null', '-i', str(repo / 'target/lab-state/id_ed25519'),
               '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'IdentitiesOnly=yes',
               '-o', 'IdentityAgent=none', '-o', 'BatchMode=yes',
               '-o', 'UserKnownHostsFile=' + str(state / 'known_hosts'),
               '-o', 'StrictHostKeyChecking=yes', '-o', 'UpdateHostKeys=no',
               '-o', 'ConnectTimeout=5', '-p', '22036', 'vprouterlab@127.0.0.1',
               'cat /proc/sys/kernel/random/boot_id']
    if result['qemu_alive'] and result['argv_match'] and result['port_22036_listener']:
        try:
            ssh = subprocess.run(command, capture_output=True, text=True, timeout=10)
            boot = ssh.stdout.strip()
            result['strict_ssh_reachable'] = ssh.returncode == 0
            if ssh.returncode == 0 and re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', boot):
                result['guest_boot_id'] = boot
            else:
                errors.append(ssh.stderr.strip() or 'invalid_guest_boot_id')
        except (OSError, subprocess.SubprocessError) as exc:
            errors.append(str(exc))
    result['controller_boot_id'] = pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    result['errors'] = errors
    result['ok'] = all(result[k] for k in ('qemu_alive', 'argv_match', 'port_22036_listener',
                                          'strict_ssh_reachable', 'guest_boot_id'))
    print(json.dumps(result, indent=2))
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())
