# Provider-check outage repair, 2026-10-22

The production service recorded six `BLOCKED (HTTPError)` transitions today.
Each withdrew Tailscale and subsequently recovered to READY after 20–31 seconds.
The latest were 17:10:45–17:11:16 and 17:13:13–17:13:40 Europe/Berlin.
The old logs do not contain HTTP status codes, so the upstream HTTP failure
cannot be classified retrospectively as rate limiting or a server error.
These records establish health-check-triggered withdrawals, not VPN failure.

The runtime now retries a transient HTTP 408/429/5xx, URL transport error,
timeout, or connection error once after one second. Each HTTPS attempt keeps
the existing 12-second timeout. Interfaces, routes, and a fresh WireGuard
handshake are required after the failure and again before the second request.
Permanent HTTP errors, malformed or negative provider confirmation, unsafe
network state, and a failed second attempt still fail closed. HTTP failures now
record status codes without URLs or response bodies.

The deployed 180-second handshake window and safe failure reasons were retained
when synchronizing the older source checkout with the deployed runtime. The
deployed host supervisor, service unit, firewall, VPN profile, Tailscale identity,
and state-directory path were preserved. Only the configured immutable image
reference, runtime source, and regression-test file changed in production.

Validation completed:

- Regression tests first reproduced the missing retry on the previous deployed
  runtime; all 42 repository tests then passed, as did `git diff --check`.
- All 11 provider-probe tests passed inside the candidate image.
- An isolated container exercised eight protected packet scenarios with no
  plaintext WAN markers; both deliberately unguarded positive controls emitted
  their markers. Production networking was not used for these fault tests.
- The candidate retains every previous base-image layer and execution setting,
  adding only the runtime replacement layer.
- The service returned to READY at 18:02:13 Europe/Berlin. Both containers became
  healthy. The host status command verified the guard, namespace, firewall,
  tunnel, and fresh READY heartbeat.
- Tailscale retained node `nDCNZroK7r11CNTRL`, IPv4 `100.109.179.104`, online state,
  and exit-node approval.
- A request through the existing Max SOCKS proxy returned `169.150.211.139`,
  `mullvad_exit_ip: true`, and provider hostname `de-fra-wg-404`.
- A separate probe process in the running router recovered from an injected
  HTTP 503 by retrying the real provider request, with real interface, route,
  and handshake validation. It did not alter the supervisor or Tailscale state.

New image: `sha256:2aea51e2f3ee30a7fcc451b71bd1a2055061e3df29c75c59bf5fef6dc73e3931`.
Previous image: `sha256:f04638cb0d22c5c078ea614f9da03fca61c30998926c2740489ca95f3105e3a9`.
The previous image remains available locally. The root-owned source snapshot is
`/opt/vprouter/releases/2026-10-22-pre-provider-retry`. Original configuration,
a stopped-state Tailscale backup, and deployment metadata are retained in the
root-only `/var/lib/vprouter/evidence-2026-10-22-provider-retry` directory.

This repair reduces shutdowns from isolated web-check failures. Repeated failures
still deliberately withdraw the exit node. Short post-deployment checks do not
establish long-term uptime or client behavior during an exit-node failure.
