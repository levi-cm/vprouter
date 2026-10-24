# GitHub integration, 2026-10-24

Production now includes levi-cm/vprouter main through e135adacd33501422fb24ba3ef2bce8693956557 plus the retained local provider-check repair in 528fece. No changes were pushed to GitHub.

The active source checkout is /DATA/AppData/vprouter-first-site; the root-owned deployed release remains /opt/vprouter/current. The older /DATA/AppData/vprouter checkout is not the running service's source.

## Local change assessment

- Retained the one-retry policy for HTTP 408/429/5xx and transient transport errors, with interface/route/handshake rechecks and immediate rejection of unsafe network state, malformed/negative provider confirmation, permanent HTTP errors, and repeated failures. GitHub does not contain this repair.
- Retained dictionary validation for provider JSON and HTTP status logging without URLs or response bodies.
- Integrated the upstream provider-data return contract so the new collector probe works after a transient retry; added a regression test for this combination.
- Upstream already contains the 180-second WireGuard rekey window and safe health-reason logging. No duplicate implementation was added.
- The older checkout's interactive-login bootstrap patch and WireGuard environment loader are unused by the hardened image and are unnecessary for this service. They and the audit files were preserved.
- The pre-integration working tree was preserved in the first-site repository's pre-github-integration-2026-10-24 stash.

## Deployment and validation

- All 50 unit tests passed; git diff --check passed.
- The candidate image replaces only router-runtime on the existing tested image, retaining the installed packages and other execution settings. Image ID: sha256:62c283e6a4d350992ed2b9a99a48c7834e60e1c9af92f9e1699a2b2d0c920de3.
- Isolated packet regression: both unguarded controls emitted their markers; all eight guarded scenarios emitted zero plaintext markers.
- Isolated host endpoint filtering, return traffic, bridge-rename blocking, and firewall-drift detection passed.
- Isolated real WireGuard handshake, forwarding, and return traffic passed without plaintext on transport.
- The first activation was rejected by ownership checks because copied directory modes allowed group writes. The deployment script restored the previous release automatically. Directory permissions were corrected and the exact ownership preflight passed before successful activation.
- New supervisor, runtime, Compose, and firewall bytes match the active source. Image runtime SHA-256 matches source: 36a087a833d260fc6c951ed407c22db2448a1a6dea55fdbf5aa8928bb3e11901.
- The active service returned READY; the router became healthy with zero container restarts and network mode none.
- Node ID, Tailscale addresses, online state, and exit-node approval match the predeployment state. WireGuard profile and Tailscale state-directory configuration were preserved.
- The new --probe succeeds. Traffic through the existing Max SOCKS proxy confirms Mullvad egress at 169.150.211.139, relay de-fra-wg-404.
- A separate process in the live router injected one HTTP 503, then completed the real collector probe with one retry and live interface, route, handshake, provider, and Tailscale validation. It did not change supervisor state.

The optional collector-service systemd hooks target another installation and were not enabled. The host-wide containerd TMPDIR drop-in is available in the merged source but was not installed or activated: /tmp currently has ample capacity and no unrelated container runtime restart was required. The upstream router-side storage error diagnostics are deployed.

Root-only rollback evidence, original configuration, original service unit, and a stopped-state Tailscale backup are retained at /var/lib/vprouter/evidence-2026-10-24-github-merge. The previous live source is /opt/vprouter/releases/2026-10-24-retired-live; an additional predeployment copy is /opt/vprouter/releases/2026-10-24-pre-github-merge. The old image remains locally tagged vprouter-hardened:pre-merge-2026-10-24. Rollback requires stopping the router service, restoring the previous release and original-site.json, and starting the service; the current Tailscale state should be preserved.

These are bounded postdeployment checks. No production tunnel-failure, remote-client fallback, reboot, or extended stability test was performed in this integration.
