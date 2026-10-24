# Synthetic legacy compatibility fixtures

Every file here is **synthetic**, derived from source at `84fb353`, and is not
an observation of a real router. Never deploy the configuration or profile.
The public addresses are RFC 5737 documentation addresses. Both WireGuard keys
are deliberately fake base64 encodings of 32 known bytes (zeroes and ones).
The image digest is a placeholder. Paths belong to a nonexistent fixtures tree.
JSON documents keep the exact legacy field shape; this README carries their
provenance rather than adding metadata fields rejected by the legacy parser.

| File | Contract |
| --- | --- |
| `site.json` | Required unversioned site fields; hostname defaults to `name` |
| `site-with-hostname.json` | Optional explicit `tailscale_hostname` |
| `fixture-router.conf` | One Interface/Peer; IPv4 /32; numeric endpoint; fake keys |
| `validate.json` | `orchestrate.py validate --config ...` successful stdout |
| `host-status-ready.json` | `orchestrate.py status --name ...` successful stdout |
| `health-*.json` | `/run/vprouter-health.json`; time is state-write time and heartbeat advances independently |
| `provider-response.json` | Minimal synthetic HTTPS provider response consumed by the probe |
| `probe.json` | `router-runtime --probe` successful stdout |

Timestamps use a fixed synthetic clock: `1700000003` is fresh, `1700000100` is
stale. `router-runtime --status` prints no JSON: it returns 0 only for a fresh
READY document, otherwise 1 (including missing/malformed state). Host `status`
prints JSON only for a fully checked fresh READY state; errors use exit 1 and
safe stderr. It may install quarantine when drift is found, so it is unsuitable
for a strictly read-only live inventory. The fixtures do not establish runtime
readiness or provider protection.

Run `python3 tools/baseline-verify-fixtures.py -q` from the checkout. It parses
the fake profile, runs validate using a temporary local site document, checks
health freshness and status exit codes, and mocks provider/network observations
to verify CLI serialization. The host-status test verifies serialization only;
the existing Python unit suite separately checks its ownership/firewall paths.
No network, Docker, systemd mutation, or real configuration read occurs.

The probe's three guard booleans are unconditional values returned after legacy
checks, not separately measured client DNS/IPv6 results. A future compatibility
wrapper must distinguish these legacy claims from fresh v2 evidence.
