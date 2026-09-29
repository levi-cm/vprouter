"""One-shot synthetic boot sender for a disposable first-site reboot drill.

The host capture must already be running. This never changes client routing.
"""

import os
import subprocess
import sys
import time


if os.geteuid() != 0 or os.environ.get("VPROUTER_BOOT_PROBE") != "1":
    raise SystemExit("requires root and explicit boot-probe opt-in")

code = """import socket
import time
from pathlib import Path
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
end = time.monotonic() + 150
started = False
while time.monotonic() < end:
    try:
        s.sendto(b"VPR3_REBOOT_PAYLOAD", ("198.51.100.77", 443))
        if not started:
            Path("/run/vprouter-boot-probe-started").write_text("sent\\n")
            started = True
    except OSError:
        pass
    time.sleep(0.1)
"""
deadline = time.monotonic() + 90
while time.monotonic() < deadline:
    result = subprocess.run(
        ["docker", "exec", "-d", "max-vprouter", "python3", "-c", code],
        capture_output=True, text=True, timeout=5,
    )
    if result.returncode == 0:
        for _ in range(40):
            confirmation = subprocess.run(
                ["docker", "exec", "max-vprouter", "test", "-f", "/run/vprouter-boot-probe-started"],
                capture_output=True, timeout=5,
            )
            if confirmation.returncode == 0:
                print("synthetic reboot sender sent a packet", flush=True)
                sys.exit(0)
            time.sleep(.25)
        raise SystemExit("router boot sender could not confirm a packet")
    time.sleep(.25)
raise SystemExit("router container unavailable during boot probe")
