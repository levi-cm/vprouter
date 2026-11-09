# Leak lab M3: real client traffic through the test exit node

Status: design, 2026-11-09. Applies to the legacy deployed release that the
lab already tests (`/opt/vprouter/current`). It is not rust/v2.

## Goal

The server-side phases (idle, stop-router, kill-wireguard, kill-container,
restart-docker, reboot-with-router-enabled) all PASS with no client traffic.
M3 repeats them while a real Tailscale client sends traffic through the test
exit node `zz-vprtest-01-do-not-use`. A phase PASSes only if all of these hold:

1. **Router tap.** Every frame on `vprlab-tap0` is WireGuard to the declared
   Mullvad endpoint. This is the existing scanner, unchanged.
2. **Client exit.** Every successful client HTTPS probe through the exit node
   reports a Mullvad exit (`mullvad_exit_ip: true`). A success that does not is
   a client real-IP leak, so the verdict is LEAK.
3. **Client cleartext.** A per-phase plaintext marker that the client sends
   continuously over HTTP never appears in clear on the client tap or the
   router tap. Through the tunnel it is encrypted, so if it appears in clear,
   client traffic left untunnelled. That is a LEAK.
4. **Positive controls.** Without these the phase is INVALID:
   - Before the fault, at least one client HTTPS probe succeeded with a
     Mullvad exit, which proves client traffic really crossed the router.
   - The client capture saw a before-control and an after-control nonce frame
     from the client in cleartext.
   - Both captures have 0 drops and captured == received.

The verdict precedence is LEAK > INVALID > PASS. The router verdict and the
client verdict combine to the worst of the two. A runner error makes the
phase INVALID.

## User decisions (2026-11-09)

- Two small QEMU guests may run at once: the router VM plus one client VM.
  Never more without asking.
- Keep RAM as low as possible. The router VM stays at 512 MiB. The client VM
  starts at **256 MiB and 1 vCPU**. Record the measured `MemAvailable` in every
  phase record, and go lower later if it is comfortably free.
- Test nodes carry special names so nobody selects them by accident.
  - Client nodes: `zz-vprclient-NN-do-not-use` (NN = 01..99).
  - They never advertise an exit node or routes.
  - They run with `--shields-up` and `--accept-routes=false`.
- Tailscale logins use interactive login URLs, the same way as the router's
  login phase.

## Network

The client VM must not share a bridge with the router VM. Any client frame on
`vprlab0` would be a router-scan finding, and LAN paths would bypass the test.

| Item | Router (existing) | Client N (new, N = 1..9) |
|---|---|---|
| Bridge | `vprlab0`, 10.250.0.1/24 | `vprlab1`, 10.251.0.1/24, MAC 52:54:00:76:71:01 |
| Tap | `vprlab-tap0` | `vprlab-ctapN` |
| VM address | 10.250.0.2, MAC 52:54:00:76:70:02 | 10.251.0.(N+1), MAC 52:54:00:76:71:(N+1, two hex digits) |
| Provision MAC | 52:54:00:76:70:99 | 52:54:00:76:71:99 |

- Host rules for `vprlab1` mirror `vprlab0`:
  - the owner-token `ifalias`;
  - `inet vprlab` masquerade and forward for 10.251.0.0/24 to the WAN only,
    with conntrack for the return path; both forward accepts are source or
    destination scoped to 10.251.0.0/24;
  - the Docker `DOCKER-USER` exceptions;
  - IPv6 disabled on the bridge;
  - static neighbours.
- Add an explicit **drop** between `vprlab0` and `vprlab1` in both directions,
  plus a test that proves the rule exists.
- Setup writes the client indexes it created into `owner.json`. Teardown reads
  that list and removes every recorded client bridge/tap/neighbour/DOCKER-USER
  object even when it was rendered without `--client`, verifying ownership
  first. The collision preflight always inventories every fixed client object
  (`vprlab1`, `vprlab-ctap1..9`), so residue is visible to a no-client plan.
- Setup, teardown, the inventory and the "refuse if not ours" checks cover the
  new objects the same way as the old ones.
- Everything else about the host stays untouched. In particular, do not
  change the production `max-vprouter` objects or the host's own tailscaled.

## Client VM

- Base: the same pinned Debian 13 genericcloud base image as the router, with
  a qcow2 overlay of 2 GiB or less. State lives in `/var/lib/vprlab/client-NNN`,
  owned by the QEMU user as for `vm-NNN`.
- QEMU uses the same hardening as the router: the `vprlab-qemu` user, sandbox,
  `-nic none` plus the explicit tap, `-serial none` in test boots, QGA over
  virtio-serial and the no-kvmapf setting.
- Provisioning reuses the router's online cloud-init path over the QEMU user
  netdev:
  - Packages: `qemu-guest-agent ca-certificates curl python3-minimal`, no
    recommends. Python is allowed only if needed; prefer shell plus curl.
  - **Tailscale:** pinned static tarball `tailscale_1.104.5_amd64.tgz`, sha256
    `720cbbccbfc03d8b55df72afc19e5a72e31b0f65934700aa6fa38074d4ad7bf7`. The
    operator stored it at `/root/vprlab/tailscale_1.104.5_amd64.tgz` (root-only).
    `provision.py` verifies the hash on the host before staging it on the
    payload ISO. The guest installs `tailscaled` and `tailscale` to
    `/usr/local/sbin`, plus a systemd unit with `--state=/var/lib/tailscale/tailscaled.state`
    and `--port=41641`. The unit is enabled.
  - Static networkd config for the client address and gateway 10.251.0.1, with
    IPv6 disabled the same way as the router.
  - No DNS dependency: probes use `curl --resolve` with IPs passed in by the
    runner. The runner resolves them on the host at phase start and records
    them.
  - Install the traffic script below and silence the OS: mask apt timers and
    the like, as the router does. The client tap is not an allowlist scan, but
    a quiet client keeps the evidence small.
- Provisioning runs at 384 MiB if 256 MiB is too small for apt, and every test
  boot runs at 256 MiB. Both values are recorded.

## Client traffic script (in the client)

The script is `/usr/local/sbin/vprlab-client-traffic`. The runner deletes
`/var/lib/vprlab/client-probe.jsonl` before launch and proves it is absent, then
starts the script as a transient unit:

```
systemd-run --unit=vprlab-client-traffic -p RuntimeMaxSec=<remaining phase> \
  /usr/local/sbin/vprlab-client-traffic <marker> <https-ip> <http-ip>
```

`RuntimeMaxSec` covers the pre-fault wait, the fault action (including a
possible reboot), the hold and a 600 s margin; the runner still stops the unit
explicitly after the hold.  The script loops once per second until stopped and
appends one JSON line per probe to `/var/lib/vprlab/client-probe.jsonl`.  It
truncates the file at start and keeps it under 1 MiB; if a line would cross the
cap it writes one final `{"k":"overflow",...}` line, which makes the phase
INVALID.

Every line carries:

- `"r"`: the phase marker id (the 32 lowercase hex characters of the marker);
- `"s"`: a sequence number starting at 1 with no gaps;
- `"t"`: the guest epoch second (non-decreasing; both probes in one loop share
  the loop's second).

- **HTTPS exit probe:**
  ```
  curl -sS -m 3 --resolve am.i.mullvad.net:443:<https-ip> https://am.i.mullvad.net/json
  ```
  The line is `{"t":<epoch>,"k":"exit","ok":true|false,"m":true|false|null,"r":<marker id>,"s":<n>}`,
  where `m` is `mullvad_exit_ip`.
  - Never record the reported IP or location: a non-Mullvad answer is the
    host's real IP. Record only the boolean. The earlier optional `h` hash was
    removed in the fix round: 48 bits over an IPv4 address is reversible.
  - A response that does not parse is `"ok":false`.
- **HTTP marker probe:**
  ```
  curl -sS -m 3 --resolve example.com:80:<http-ip> -H "X-Vprlab-Marker: <marker>" \
    "http://example.com/?vprlab=<marker>"
  ```
  The line is `{"t":...,"k":"marker","ok":true|false,"r":<marker id>,"s":<n>}`.
- The marker is `VPRCLIENTMARK1:` followed by 32 lowercase hex characters. It
  is fresh per phase and comes from the same used-nonce bookkeeping as the
  router controls.

## Phase flow with `--client N`

`run_phase.py --phase <p> --client N` accepts every phase except `login`. A new
phase `client-login` (with `--client N`) boots only the client VM, shows the
login URL the way the router login phase does, and waits for
`BackendState == Running`.

1. **Admission.** Host `MemAvailable` must cover the router plus the client
   plus the existing headroom.
2. **Captures.** Start the router capture on `vprlab-tap0` (unchanged argv
   contract). Start the client capture on `vprlab-ctapN` with the same flags:
   `-nn -U --immediate-mode -B 8192 -s 0 -w`.
3. **Client boot.** Boot the client in a tap-only test boot. Wait for
   `BackendState == Running` (tailscaled must be up before `tailscale set` can
   work), then run `tailscale set --exit-node=` to clear any persisted exit
   node and wait until no exit node is reported. Send the **client
   before-control**: a UDP datagram `VPRLEAKCTL1:<32hex>` from the client to
   10.251.0.1:39001.
4. **Client Tailscale.**
   - Refuse (INVALID) if the client's own `Self.HostName` is not exactly
     `zz-vprclient-NN-do-not-use`; a present but different `DNSName` is also a
     refusal (no DNS fallback may hide a conflicting HostName).
   - Refuse if the client advertises an exit node or a default route.
5. **Router boot.** Boot the router and set it up to READY, unchanged.
6. **Client exit node.**
   - Read the router's own `tailscale status --json` through the router QGA
     and take `Self.ID` and its Tailscale IPv4 addresses.
   - Find exactly that peer in the client's status: exactly one peer with that
     ID, HostName `zz-vprtest-01-do-not-use`, `ExitNodeOption` true, online.
     A duplicate ID or a second peer with the same HostName is a refusal.
   - Run `tailscale set --exit-node=<its Tailscale IPv4> --exit-node-allow-lan-access=false`.
   - Wait until the client reports `ExitNodeStatus` with that exact ID,
     containing that address, `Online` true.
7. **Pre-fault positive control.** The traffic unit is started here so the
   probe stream exists. Within 90 s:
   - at least one HTTPS probe must succeed with `m == true`, and
   - at least one marker probe must succeed (`ok == true`), which proves the
     marker really went out;
   - otherwise the phase is INVALID (`client_not_routed` /
     `client_marker_not_sent`). A successful exit probe with `m` not `true`
     is returned immediately as LEAK; the final collection still runs.
8. **Traffic.** Apply the fault and prove it took effect, exactly as today.
   Hold for `--duration`.
9. **Collect.**
   - Require the traffic unit to be `systemctl is-active` at the end of the
     hold, then stop it explicitly.
   - Read the probe log through QGA in full; require the guest-reported size
     and SHA-256 to match the bytes read and the file to end with a newline.
     Truncation is INVALID; no valid prefix is accepted.
   - Collect the log on every exit path from `finally`, while the client VM is
     still up.
   - Clear the exit node and send the **client after-control**.
   - Then send the router after-control, as today.
10. **Shutdown.** Shut down both VMs and stop both captures in the existing
    order: the capture outlives QEMU.
11. **Verdicts.**
    - Router scan, unchanged.
    - Client scan (new): stats binding, full-frame snaplen, both client
      controls seen exactly once and in record and timestamp order, no
      timestamp regression, and the marker never present in clear in any
      frame. Controls are parsed strictly as Ethernet II / IPv4 (no options or
      fragments) / UDP to 39001 from the client VM MAC and IPv4 to the
      bridge MAC and IPv4 with the exact payload. A duplicated control is
      INVALID unless the marker independently proves a leak.
    - Probe verdict:
      - LEAK on any well-formed `ok && m != true` line, even when other lines
        are malformed or the log is truncated;
      - INVALID if there was no pre-fault Mullvad success, no pre-fault
        successful marker probe, a missing/gapped `s`, a foreign `r`, a
        timestamp regression or out-of-window timestamp, a probe gap above
        10 s, no post-fault exit/marker attempt, an overflow line, or any read
        quality problem;
      - otherwise PASS.
    - Record per-kind counts: total, ok, Mullvad, non-Mullvad and failed,
      before and after the fault. Diagnostics carry fixed error codes and
      line numbers only; guest keys, values and text never reach `phase.json`,
      `client-scan.json`, stdout or stderr.

Failures during a fault are expected, because Tailscale clients drop traffic
when the exit node is gone. They are counted, never a LEAK.

## Evidence

Each phase evidence directory gains:
- `client-capture.pcap`
- `client-capture.pcap.stderr`
- `client-capture-argv.json`
- `client-probe.jsonl`
- `client-scan.json`

`phase.json` gains a `client` object with:
- the name, memory and nonces;
- the resolved probe IPs;
- the counts and the client verdict;
- the combined result.

The rules of the existing evidence directory apply to all of it: root-only,
fd-anchored, hashes in `phase.json`. Never record the client's Tailscale
state, auth keys, login URLs beyond the existing login-URL file, or any
non-Mullvad IP. **Accepted exception (controller decision 12):** `client-login`
prints the login URL to stderr exactly like the router `login` phase; that
pre-existing documented risk is retained rather than changing the shared login
behaviour. The URL remains root-only in `login-url.txt`.

Admission reserves both capture caps on the evidence filesystem and both
overlays (router 4 GiB + client 2 GiB) plus headroom on the state filesystem.

## Tests (offline, required)

- Netplan/hostsetup: the `vprlab1` objects exist; the `vprlab0` and `vprlab1`
  drop rules exist in both directions; teardown and the refusal checks cover
  `vprlab1`; the router plan is unchanged when no client is configured.
- Provision: refuses a tarball with the wrong sha256; the client name and
  address are validated; the overlay is at most 2 GiB.
- Client scan: a pcap with the marker in clear is LEAK (inside the window,
  before the controls, after them, and split across two frames is out of
  scope); missing, duplicated or out-of-order controls are INVALID; forged
  non-Ethernet controls and wrong MAC/IP/UDP tuples are INVALID; drops,
  timestamp regressions and a non-full snaplen are INVALID.
- Probe verdict:
  - `ok` with `m` false is LEAK;
  - `ok` with `m` null is LEAK, because an unparsed success is not trusted;
  - no pre-fault Mullvad success is INVALID;
  - no pre-fault successful marker probe is INVALID;
  - failures only after the fault give PASS when the post-fault attempts are
    present;
  - malformed, oversized or duplicate-key lines are INVALID, but never mask a
    well-formed LEAK line;
  - stale logs, wrong `r`, sequence gaps, timestamp regressions/out-of-window
    values, gaps above 10 s and missing post-fault attempts are INVALID.
- Combined verdict precedence across router and client, including a missing
  verdict as INVALID unless another side is LEAK.
- Run-phase orchestration with fakes for both VMs and the **real** client
  scanner over the crafted pcaps:
  - the order of the steps above;
  - the exit node cleared before both controls;
  - both captures outlive both QEMUs, and a dead client tcpdump trips its
    capture guard;
  - the client never runs without `--client`;
  - `login` with `--client` is refused;
  - an inactive traffic unit, a truncated final read, a stale/foreign probe
    log and a pre-fault leak behave as above.

## Out of scope

- Client DNS-leak tests.
- More than one client at a time.
- IPv6.
- rust/v2.
