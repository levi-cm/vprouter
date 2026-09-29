# Audit evidence and reproduction

See [the report](../../SECURITY-AUDIT-2026-09-27.md). These are audit artifacts, not deployment changes.

- `live-snapshot.json`: sanitized configuration, original production source hashes, security-database source hashes, and load-test limits.
- The audit-time loader hash in `live-snapshot.json` refers to the original loader. The root-level legacy loader was later linted and no longer has that hash; the archived `bootstrap.sh` still matches its audit-time hash.
- `iptables.v4`, `iptables.v6`: production namespace rules copied for isolated replay. Contain network addresses but no credentials.
- `bootstrap.sh`: original production bootstrap snapshot; compare its SHA-256 with the live snapshot.
- `probe.py`: real Linux forwarding and WireGuard packet test using synthetic TUN endpoints. No real account or keys. A true `plaintext_on_wan` means the application marker escaped WireGuard encryption in that scenario, not that a real Internet destination was contacted.
- `packet-results-baseline.json`, `packet-results-under-load.json`: sixteen completed packet scenarios without extra load and under bounded scheduling pressure, with identical allow/block outcomes. Packet counts include transport/control packets and are not leak counts.
- `startup_probe.py`, `startup-results.json`, and the four named logs: original bootstrap executed with controlled command failures. These mocks prove error-handling behavior, not real service semantics.
- `shutdown-result.json`: original bootstrap as PID 1 with stubbed children; SIGTERM required forced termination.
- `package-review.json`: installed package origins and version matches against Alpine security-fix records. These are not exploit confirmations.

Never run these probes on a production router or in the host network namespace: they deliberately alter routes and firewall rules. The preserved Python probes include opt-in and interface checks added after the initial test runs; the guarded packet probe was subsequently rerun successfully for the saved baseline. Production was never mounted into the test containers. Reproduce with a new disposable container, a copy of this directory, and the already present production image ID:

```bash
audit_copy=$(mktemp -d /tmp/vprouter-replay.XXXXXX)
cp audit/2026-09-27/* "$audit_copy/"
docker run -d --name vprouter-audit-replay \
  --label purpose=vprouter-security-audit \
  --cap-add NET_ADMIN --device /dev/net/tun \
  --sysctl net.ipv4.ip_forward=1 \
  --sysctl net.ipv6.conf.all.forwarding=1 \
  --memory 384m --pids-limit 128 \
  --mount "type=bind,src=$audit_copy,dst=/audit" \
  --entrypoint sleep \
  sha256:cacc8337f3ba82fcb18e9ad7f847f38646ff36b1d3b568988c3caf54a8ea2670 infinity
docker exec vprouter-audit-replay apk add --no-cache python3
docker network disconnect bridge vprouter-audit-replay
docker inspect vprouter-audit-replay --format '{{json .NetworkSettings.Networks}}'
# Expect {} before continuing. No .env, credentials, or live state are mounted.
docker exec -e VPROUTER_AUDIT_ISOLATED=1 vprouter-audit-replay python3 /audit/probe.py
docker exec -e VPROUTER_AUDIT_ISOLATED=1 vprouter-audit-replay python3 /audit/startup_probe.py
docker rm -f vprouter-audit-replay
```

The first probe restores the copied rules and tests deliberately unsafe routes; it does not start Tailscale. Closing the TUN file descriptors removes the synthetic interfaces. The second probe writes only disposable container configuration and its copied evidence directory. Temporary files are retained for review. A fixed container name is intentional: creation fails if it already exists instead of reusing an unknown container.

For the load run, the test container was limited with `docker update --cpus 0.25` and a separate Python process touched a 64 MiB bytearray continuously for 15 seconds while `probe.py` ran. Memory was limited to 384 MiB. No OOM or host-wide overload was induced.

For the shutdown test, a separate container used `/bin/bash /audit/bootstrap.sh` as PID 1, `--network none`, `/audit/stubs` first in PATH, and fake WireGuard values. After setup completed, `docker stop --time 3` took 3.11 seconds and inspection reported exit 137, not OOM. The actual Tailscale and dnsmasq daemons were not involved in that test.
