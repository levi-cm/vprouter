# Exit-node stability fix — 2026-10-01

The runtime rejected a successful protected-egress probe when the last WireGuard handshake reached 120 seconds. That overlaps the protocol's renewal window: rekeying starts at 120 seconds, while session expiry is 180 seconds. Regression tests reproduce the erroneous rejection at ages 120, 121, 165 and 179 seconds. The corrected check accepts a just-completed handshake and the renewal window, and still rejects age 180 seconds, absent handshakes and future timestamps. Protocol reference: https://www.wireguard.com/papers/wireguard.pdf

All existing provider confirmation, namespace, firewall and Tailscale approval checks remain required. Health state transitions in the host journal now include their specific internal check reason; external exception messages remain redacted to their class. Changes of reason while the state stays BLOCKED remain available in the current health file rather than generating another journal entry.

## Deployment and verification

- Tailscale identity preserved: `nico-vpn`, `100.127.1.84`, ID `nRPMSgTbN121CNTRL`.
- Router and root-owned host supervisor updated; router image: `sha256:0d6de92dfbe1f2ee24070583d8fe6d2e3630ed0fd60b885c45917b51bdeb482e`.
- Web UI rebuilt and deployed; image: `sha256:04b8685fdae7425567747d5979e15bf7f02b8295e43a7b353b91047877529d2b`. Live JavaScript and CSS hashes match the running image, and a fresh browser loaded the search page.
- Full router suite: 37 tests passed. The pre-fix renewal-window regression failed at five tested ages.
- Tailscale client traffic confirmed the same Mullvad exit as the router: `185.209.199.131` / `se-got-wg-008`. Original client exit selection and route guard restored afterward.
- Monitoring: 604 seconds, 59 samples, 6 distinct handshakes, zero unhealthy/offline samples and one unchanged container. The journal contains no later BLOCKED transition after initial READY.
- Router, collector coordinator and suggestions restored and running. Provider holds were not changed.
- Rollback source/config retained under `/var/backups/vprouter/stability-20261001T182953Z`.

This is a bounded live stability check; the old journal did not retain enough failure detail to classify every earlier interruption.
