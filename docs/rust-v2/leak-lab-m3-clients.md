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
    with conntrack for the return path;
  - the Docker `DOCKER-USER` exceptions;
  - IPv6 disabled on the bridge;
  - static neighbours.
- Add an explicit **drop** between `vprlab0` and `vprlab1` in both directions,
  plus a test that proves the rule exists.
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

The script is `/usr/local/sbin/vprlab-client-traffic`. The runner starts it as
a transient unit:

```
systemd-run --unit=vprlab-client-traffic -p RuntimeMaxSec=<hold+120> \
  /usr/local/sbin/vprlab-client-traffic <marker> <https-ip> <http-ip>
```

It loops once per second until stopped and appends one JSON line per probe to
`/var/lib/vprlab/client-probe.jsonl`. It truncates the file at start and keeps
it under 1 MiB.

- **HTTPS exit probe:**
  ```
  curl -sS -m 5 --resolve am.i.mullvad.net:443:<https-ip> https://am.i.mullvad.net/json
  ```
  The line is `{"t":<epoch>,"k":"exit","ok":true|false,"m":true|false|null}`,
  where `m` is `mullvad_exit_ip`.
  - Never record the reported IP or location: a non-Mullvad answer is the
    host's real IP. Record only the boolean, and at most the first 12 hex
    characters of the IP's sha256, under `"h"`.
  - A response that does not parse is `"ok":false`.
- **HTTP marker probe:**
  ```
  curl -sS -m 5 --resolve example.com:80:<http-ip> -H "X-Vprlab-Marker: <marker>" \
    "http://example.com/?vprlab=<marker>"
  ```
  The line is `{"t":...,"k":"marker","ok":true|false}`.
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
3. **Client boot.** Boot the client in a tap-only test boot. Run
   `tailscale set --exit-node=` to clear any persisted exit node. Send the
   **client before-control**: a UDP datagram
   `VPRLEAKCTL1:<32hex>` from the client to 10.251.0.1:39001.
4. **Client Tailscale.** Wait for `BackendState == Running`.
   - Refuse (INVALID) if the client's own name is not
     `zz-vprclient-NN-do-not-use`.
   - Refuse if the client advertises an exit node.
5. **Router boot.** Boot the router and set it up to READY, unchanged.
6. **Client exit node.**
   - Find the router peer in the client's `tailscale status --json`:
     HostName `zz-vprtest-01-do-not-use`, `ExitNodeOption` true, online.
   - Run `tailscale set --exit-node=<its Tailscale IPv4> --exit-node-allow-lan-access=false`.
   - Wait until the client reports that peer as its active exit node.
7. **Pre-fault positive control.** Within 90 s, at least one HTTPS probe must
   succeed with `m == true`. Otherwise the phase is INVALID with
   `client_not_routed`.
8. **Traffic.** Start the traffic unit. Apply the fault and prove it took
   effect, exactly as today. Hold for `--duration`.
9. **Collect.**
   - Stop the unit and read the probe log through QGA, bounded to 1 MiB and
     parsed strictly.
   - Clear the exit node and send the **client after-control**.
   - Then send the router after-control, as today.
10. **Shutdown.** Shut down both VMs and stop both captures in the existing
    order: the capture outlives QEMU.
11. **Verdicts.**
    - Router scan, unchanged.
    - Client scan (new): stats binding, both client controls seen once and in
      order, and the marker never present in clear in any frame. Search the raw
      bytes of every record in both pcaps.
    - Probe verdict:
      - LEAK on any `ok && m != true`;
      - INVALID if there was no pre-fault Mullvad success;
      - otherwise PASS.
    - Record per-kind counts: total, ok, Mullvad, non-Mullvad and failed,
      before and after the fault.

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
non-Mullvad IP.

## Tests (offline, required)

- Netplan/hostsetup: the `vprlab1` objects exist; the `vprlab0` and `vprlab1`
  drop rules exist in both directions; teardown and the refusal checks cover
  `vprlab1`; the router plan is unchanged when no client is configured.
- Provision: refuses a tarball with the wrong sha256; the client name and
  address are validated; the overlay is at most 2 GiB.
- Client scan: a pcap with the marker in clear is LEAK (inside the window,
  before the controls, after them, and split across two frames is out of
  scope); missing or out-of-order controls are INVALID; drops are INVALID.
- Probe verdict:
  - `ok` with `m` false is LEAK;
  - `ok` with `m` null is LEAK, because an unparsed success is not trusted;
  - no pre-fault Mullvad success is INVALID;
  - failures only after the fault give PASS;
  - malformed, oversized or duplicate-key lines are INVALID.
- Combined verdict precedence across router and client.
- Run-phase orchestration with fakes for both VMs:
  - the order of the steps above;
  - the exit node cleared before both controls;
  - both captures outlive both QEMUs;
  - the client never runs without `--client`;
  - `login` with `--client` is refused.

## Out of scope

- Client DNS-leak tests.
- More than one client at a time.
- IPv6.
- rust/v2.
