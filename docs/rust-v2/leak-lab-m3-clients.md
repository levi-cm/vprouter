# Leak lab M3: real client traffic through the test exit node

Status: design, 2026-11-09 (fix round 3: exact prefix reads, host-observed
hold coverage, proven writer stop; fix round 4: coverage through the fault
action, deadline sample inside the hold, process-scan stop proof, real
`ExitNodeStatus` prefix shape, `--accept-dns=false`). Applies to the legacy deployed release that the
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
   - Client traffic really flowed while the fault and its recovery happened
     and during the whole hold: the runner saw a new exit attempt in every
     host-timed window of at most 15 s from the sample taken immediately
     before the fault action (`S_pre`), through the action and its
     postcondition, to the deadline sample (see step 8 below).
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
  - They run with `--shields-up`, `--accept-routes=false` and
    `--accept-dns=false` (fix round 4, Opus B L-1: with MagicDNS accepted,
    tailscaled rewrites `/etc/resolv.conf` and the client silence check
    refuses the boot).
  - Before `client-login`, the operator deletes any older
    `zz-vprclient-NN-*` node in the Tailscale admin console; otherwise the new
    node gets a `-1` DNS suffix and every client phase refuses its identity.
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
  - after the scoped accepts, explicit drops for every other packet from or
    to the client bridge (decision 6);
  - the Docker `DOCKER-USER` exceptions;
  - IPv6 disabled on the bridge;
  - static neighbours.
- The same scoped-accept-plus-explicit-drop rule applies to `vprlab0`: the
  router VM only needs its own subnet to the WAN and conntrack return traffic.
  Nothing else from either lab bridge may be forwarded.
- Add an explicit **drop** between `vprlab0` and `vprlab1` in both directions,
  plus a test that proves the rule exists.
- Setup writes the client indexes it created into `owner.json`. Teardown reads
  that list and removes every recorded client bridge/tap/neighbour/DOCKER-USER
  object even when it was rendered without `--client`, verifying ownership
  first. The collision preflight always inventories every fixed client object
  (`vprlab1`, `vprlab-ctap1..9`), so residue is visible to a no-client plan.
  If the owner record lists no clients but `vprlab1` or any `vprlab-ctapN`
  exists, teardown refuses before touching anything (fail closed).
- The client neighbour helpers read the complete `ip -j neigh` inventory and
  filter `dst`/`dev` in Python, exactly like the router helper. The filtered
  `ip ... dev` form omits the `dev` key and fails with `Cannot find device`
  when the bridge is gone, so it cannot prove absence. Both helpers
  (`client_neigh_state` and the ownership check `client_neigh_ok`) match
  `dst` **and** `dev`, so the same address on another device can neither
  satisfy nor block the client check (fix round 3, Pi R3-M2).
- **The router-only plan changed too (fix round 2, decision 6).** The
  `vprlab0` forward rules are no longer unscoped accepts: the plan now
  renders `iif vprlab0 oif <wan> ip saddr 10.250.0.0/24 accept`, a
  conntrack-scoped return accept (`ip daddr 10.250.0.0/24 ct state
  established,related`), and then explicit drops for every other packet
  between `vprlab0` and the WAN. Reason: the `inet vprlab` base chains have
  `policy accept`, so an unscoped accept, or no drop after a scoped one,
  forwarded anything that crossed the lab bridge (for example a VM packet with
  a source outside the lab subnet) whenever the host's own FORWARD policy is
  not DROP. The router VM's legitimate traffic (10.250.0.2-sourced egress and
  its conntrack replies) matches the scoped accepts unchanged. The no-client
  plan also carries the client-teardown helpers (used only when `owner.json`
  records clients) and the old-owner residue refusal. Every other router step
  of the plan is unchanged.
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
    `/usr/local/sbin` (extracted under `/var/tmp`, on disk, not the `/tmp`
    tmpfs; Opus B P-4), plus a systemd unit with
    `--state=/var/lib/tailscale/tailscaled.state`, `--port=41641` and
    `OOMScoreAdjust=-900` (Opus B P-2: an OOM kill of tailscaled would remove
    `tailscale0` and send probes out in clear; the traffic script or curl dies
    first, which is a fail-safe INVALID). The unit is enabled.
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
explicitly after the hold.  The script loops until stopped: an exit probe, a
marker probe, then a 2 s sleep.  Each probe is `curl -m 4` with a 4.5 s
subprocess backstop, so consecutive exit attempts are at most about 11 s apart
even with the backstop while the exit node is down, at least 1 s shorter than
every 12-15 s coverage window (fix round 4, Opus B P-3; sleep lowered from 3 s
after Opus R5 m-3; the am.i.mullvad.net rate stays near one request every
2.5-3 s while healthy).  It
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
  curl -sS -m 4 --resolve am.i.mullvad.net:443:<https-ip> https://am.i.mullvad.net/json
  ```
  The line is `{"t":<epoch>,"k":"exit","ok":true|false,"m":true|false|null,"r":<marker id>,"s":<n>}`,
  where `m` is `mullvad_exit_ip`.
  - Never record the reported IP or location: a non-Mullvad answer is the
    host's real IP. Record only the boolean. The earlier optional `h` hash was
    removed in the fix round: 48 bits over an IPv4 address is reversible.
  - A response that does not parse is `"ok":false`.
- **HTTP marker probe:**
  ```
  curl -sS -m 4 --resolve example.com:80:<http-ip> -H "X-Vprlab-Marker: <marker>" \
    "http://example.com/?vprlab=<marker>"
  ```
  The line is `{"t":...,"k":"marker","ok":true|false,"r":<marker id>,"s":<n>}`.
- The marker is `VPRCLIENTMARK1:` followed by 32 lowercase hex characters. It
  is fresh per phase and comes from the same used-nonce bookkeeping as the
  router controls.

## Phase flow with `--client N`

`run_phase.py --phase <p> --client N` accepts every phase except `login`. A new
phase `client-login` (with `--client N`) boots only the client VM, starts
`tailscale up ...` in a transient unit instead of blocking inside QGA, shows the
login URL the way the router login phase does, polls `BackendState`, and waits
for `BackendState == Running`. Its admission reserves no capture and no router
overlay, only the client overlay and headroom.

A `--client` phase requires `--duration >= 30` seconds, including
`client-login`. A shorter timing window cannot be observed by the probe loop
(and a login that short is not useful), so it is refused.

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
     refusal (no DNS fallback may hide a conflicting HostName). A present but
     non-string HostName is refused; DNS is used only when it is missing.
   - Refuse if the client advertises an exit node or a default route.
   - Read `tailscale debug prefs` and refuse unless `AdvertiseRoutes` is
     present and empty (`[]`, or JSON `null`, Go's empty slice; a missing key
     is `client_prefs_incomplete`, any route `client_advertises_routes`),
     `RouteAll` is exactly `false` (`client_accepts_routes`) and `ShieldsUp`
     is exactly `true` (`client_shields_down`) and `CorpDNS` is exactly
     `false` (`client_accepts_dns`; a missing key is
     `client_prefs_incomplete`). The same check runs at the end of
     `client-login`, whose `tailscale up` passes `--accept-dns=false`.
5. **Router boot.** Boot the router and set it up to READY, unchanged.
6. **Client exit node.**
   - Read the router's own `tailscale status --json` through the router QGA
     and take `Self.ID` and its Tailscale IPv4 addresses.
   - Find exactly that peer in the client's status: exactly one peer with that
     ID, HostName `zz-vprtest-01-do-not-use`, `ExitNodeOption` true, online.
     A duplicate ID or a second peer with the same HostName is a refusal.
     The router has only just become ready, and control pushes its online
     state to the client asynchronously, so the client status is re-read
     every second for up to 60 s until the peer appears (Opus B P-1).
   - Run `tailscale set --exit-node=<its Tailscale IPv4> --exit-node-allow-lan-access=false`.
   - Wait until the client reports `ExitNodeStatus` with that exact ID,
     `Online` true, and listing that IPv4 as a `/32` prefix.
     `ExitNodeStatus.TailscaleIPs` is `[]netip.Prefix` in tailscaled
     (`"100.x.y.z/32"`, `"fd7a:.../128"`), unlike the bare addresses of
     `PeerStatus.TailscaleIPs`; each entry is parsed as an interface, a bare
     address counts as its `/32`, and a wider prefix that merely contains the
     address is refused (Opus B B-1).
7. **Pre-fault positive control.** The traffic unit is started here so the
   probe stream exists. The start counts as attempted before the start
   command runs, so a start that launched the unit and then raised is still
   stopped, proven and collected (Opus R3-1). Within 90 s, from **trusted
   prefix reads only** (Opus R3-2):
   - at least one HTTPS probe must succeed with `m == true`, and
   - at least one marker probe must succeed (`ok == true`), which proves the
     marker really went out;
   - otherwise the phase is INVALID (`client_not_routed` /
     `client_marker_not_sent`). A successful exit probe with `m` not `true`
     is latched as a LEAK and returned immediately; the final collection still
     runs.
8. **Traffic and coverage through the fault (fix round 4).**
   - **S_pre.** Immediately before the fault action, take a trusted prefix
     sample (below).  Every sample offset in the record is relative to its
     size read.
   - **Action samples.** While the router action and its postcondition run
     (including a reboot and the router-ready waits), a helper thread takes
     a trusted sample of the client log every 13 s of host monotonic time
     (start to start), with the same window rule and the same exit-node
     re-check.  The thread uses only the client's QGA socket; the main thread
     uses only the router's QGA socket until the thread is stopped and
     joined, on every exit path.  A thread that cannot be joined still owns
     the client socket: the phase is INVALID (`client_sampler_stuck`) and
     the runner never uses that socket again (no collection, QEMU is killed).
     This closes Opus R4 I-1: in restart-docker, kill-wireguard,
     kill-container and reboot the leak-relevant transition happens inside
     the action, and it is now host-observed, not covered only by the guest
     clock.
   - **S_fault.** After the action and its postcondition finished and the
     thread was joined, take a trusted sample at the next point of the same
     13 s cadence (so its window still holds a complete probe loop).  Its
     last complete sequence number is `S_fault`, and the start of its size
     read is the hold base `h0`.  Post-fault exit and marker attempts with
     `s > S_fault` are still required.
   - **Hold samples.** The hold `[h0, h0 + hold]` ends with a 3 s margin:
     the deadline sample `S_end` starts its size read 3 s before the
     deadline and must finish it at or before the deadline, otherwise the
     phase is INVALID (`probe_hold_deadline_late`; GPT R4-I1: a size read
     observes the log anywhere inside `[stat_start, stat_end]`, so one that
     ends after the deadline could credit a line first written after the
     hold).  `[h0, deadline - 3 s]` is split into equal windows of 12-14 s
     (above the probe loop's worst-case exit spacing, below 15 s with the
     read latency).  When the requested duration has no such split (for
     example 33 s or 60 s) the hold is extended, never shortened, to the next
     whole second that has one (39 s, 63 s); `hold_seconds` records the hold
     used and `hold_requested_seconds` the request.  Lines first seen after
     the deadline never count for coverage; they are still parsed for LEAK.
   - **Exit node.** Every sample (S_pre, action samples, S_fault, hold
     samples and S_end) re-reads `ExitNodeStatus` and requires the router's
     own `Self.ID` and the selected `/32`; otherwise INVALID
     (`client_exit_node_lost`).  `Online` is required only for the pre-fault
     selection: during stop-router, kill-container and kill-wireguard the
     router's Tailscale is legitimately offline, and a sample must prove that
     the client still has exactly this router selected, not that the router
     is healthy (controller decision after fix round 3).  The selection is
     sampled, not continuous: a switch away and back between two samples is
     not visible; nothing in the lab triggers one.
   - **Coverage rule.** Every window between consecutive samples, from S_pre
     to S_end, must be at most 15 s long, measured conservatively from the
     start of the earlier sample's size read to the end of the later one's,
     and must contain at least one new exit attempt: an exit line with `s`
     greater than the previous sample's last `s`, seen in the later sample.
     A silent fault action, a burst followed by silence, a silent window in
     the middle, or probes written only during the end status call all leave
     an empty window and are INVALID (`probe_hold_window_empty`).  Windows of
     at most 15 s bound the spacing of individual exit attempts only to
     about two windows in the worst case (an attempt just after one sample
     and the next just before the sample after next, Opus R4 M-4); windows
     are deliberately not shortened, and the guest-clock 15 s row-gap rule
     is the tighter bound.
   - **Trusted prefix read (decision 1).** Every value the verdict trusts
     comes from one primitive: N = `stat -c %s` of the log, then the guest
     SHA-256 of `head -c N` and the bytes of `head -c N` (separate bounded QGA
     execs; the log is append-only after launch, so its first N bytes are
     stable). The read is trusted only if every exec exited 0, exactly N bytes
     arrived and the host SHA-256 equals the guest's. Sequence numbers come
     only from complete newline-terminated lines of a trusted prefix. An
     untrusted read never establishes a sample; it makes the phase INVALID
     (`probe_{pre,action,fault,hold,end}_sample_untrusted` plus the read
     problem) and its bytes are still parsed tolerantly to latch a LEAK.
     There is no retry and no fallback to a partial read.
   - The guest-clock checks remain as extra INVALID conditions only;
     coverage never depends on the guest clock.
9. **Collect.**
   - Require the traffic unit to be `systemctl is-active` at the end of the
     hold. Then `systemctl stop` it *without masking the result* and prove the
     stop (decision 3): `systemctl is-active` must print exactly `inactive` or
     `failed` (`unknown`, `deactivating`, empty or anything else is not
     proof), and `systemctl show -p MainPID --value` must print `0` (which is
     also what an absent unit reports), and a `/proc` scan must find no
     process whose command line names `/usr/local/sbin/vprlab-client-traffic`,
     inside or outside the unit's cgroup (fix round 4, Opus R4 M-1; the scan
     needs no procps and never matches itself). The guest clock
     (`clock_stop`) is read right after the proven stop. Then **writer
     quiescence**: two trusted size reads at least 12 s of host time apart
     (longer than one worst-case probe loop) must be equal. Only then is the
     final snapshot trusted, and the record says `traffic_stop_proven: true`
     (Opus R4 M-3). If any step fails, the phase is
     INVALID (`client_traffic_stop_failed` / `client_writer_not_quiescent`),
     the snapshot is marked untrusted, and a later cleanup stop never
     validates it; the bytes are still kept for LEAK parsing.
   - The final snapshot is a trusted prefix read (above) that must be
     non-empty and end with a newline. Truncation is INVALID; no shorter
     prefix is accepted. The bounded bytes of a failed read are still parsed
     for a LEAK.
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
      - LEAK is latched on any well-formed `ok && m != true` line, seen in the
        pre-fault wait, a mid-phase boundary read, the final read, or the
        bounded bytes of a failed `cat`; it survives every later read or
        quality problem and the combined result is LEAK;
      - INVALID if there was no pre-fault Mullvad success, no pre-fault
        successful marker probe, a missing/gapped `s`, a foreign `r`, a
        timestamp regression or out-of-window timestamp, a guest-clock probe
        gap above 15 s, a guest clock that did not advance across the hold
        (`clock_stop - post_fault_epoch < hold - 2`, `probe_clock_stalled`),
        no post-fault exit/marker attempt with `s > S_fault`, missing or
        inconsistent samples (kinds must run `pre`, `action`*, `fault`,
        `hold`*, `end`), a sample without `exit_node_ok: true`
        (`client_exit_node_lost`; Opus R4 M-2, so the standalone evaluator
        and its CLI carry the binding too), a host window longer than 15 s
        or without a new exit attempt, a deadline sample that starts more
        than 3 s before the deadline or ends after it, an unordered
        clock window (`clock_start <= fault_epoch <= post_fault_epoch <=
        clock_stop`), an overflow line, or any read quality problem;
      - the evaluator re-derives every hold sample from the evidence bytes:
        each sample's `size`/`sha256` must be a prefix of the final log
        (`probe_hold_prefix_mismatch` otherwise), and its recorded `sequence`
        and `exit_sequence` must equal what that prefix contains, so a sample
        can never claim a line the evidence lacks;
      - otherwise PASS. A read-quality problem never leaves a PASS probe
        object behind.
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
- the latched `probe_leak_observed` flag, `fault_sequence`,
  `hold_sequence_end`, `hold_seconds`, `hold_requested_seconds`,
  `hold_windows` (after S_fault), `action_samples`, `hold_samples` (every
  coverage sample from S_pre to S_end; per sample: `kind`, `sequence`,
  `exit_sequence`, `size`, `sha256` of the prefix, host
  `stat_start`/`stat_end` relative to the S_pre sample, `exit_node_ok`),
  `traffic_stop_proven`, `probe_snapshot_trusted` and
  `guest_mem_available` (`boot` and `end`, bytes; Opus B P-2);
- the combined result.

The rules of the existing evidence directory apply to all of it: root-only,
fd-anchored, hashes in `phase.json`. Never record the client's Tailscale
state, auth keys, login URLs beyond the existing login-URL file, or any
non-Mullvad IP. **Accepted exception (controller decision 12):** `client-login`
prints the login URL to stderr exactly like the router `login` phase; that
pre-existing documented risk is retained rather than changing the shared login
behaviour. The URL remains root-only in `login-url.txt`.

Admission reserves both capture caps on the evidence filesystem and both
overlays (router 4 GiB + client 2 GiB) plus headroom on the state filesystem
for a traffic phase. `client-login` reserves no capture and no router overlay:
only the client 2 GiB overlay and the shared headroom.

## Tests (offline, required)

- Netplan/hostsetup: the `vprlab1` objects exist; the `vprlab0` and `vprlab1`
  drop rules exist in both directions; the scoped accepts for both bridges are
  followed by explicit drops; teardown and the refusal checks cover
  `vprlab1`; an owner with no clients plus any client object refuses teardown;
  without `--client` the plan creates no client object, and its router steps
  differ from M2 only by the decision-6 scoped accepts and drops described
  under Network (it is **not** byte-identical to the M2 plan); the client
  neighbour check matches both `dst` and `dev`.
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
  - failures only after the fault give PASS when every host window has a new
    exit attempt;
  - a same-second fault/post-fault pair with no `s > S_fault` is INVALID;
  - an aggregate exit count without host samples, a burst then silence, a
    marker-only window, a window longer than 15 s, a short or late deadline
    sample, a sample that is not a prefix of the evidence or that claims
    lines the evidence lacks, and a stalled guest clock are INVALID;
  - malformed, oversized or duplicate-key lines are INVALID, but never mask a
    well-formed LEAK line; a LEAK seen before a later read failure is latched;
  - stale logs, wrong `r`, sequence gaps, timestamp regressions/out-of-window
    values, gaps above 15 s, missing post-fault attempts, an unordered clock
    window and insufficient hold coverage are INVALID.
- Combined verdict precedence across router and client, including a missing
  verdict as INVALID unless another side is LEAK, and the latched leak flag.
- Run-phase orchestration with fakes for both VMs and the **real** client
  scanner over the crafted pcaps:
  - the order of the steps above;
  - the exit node cleared before both controls and re-verified at the end of
    the hold;
  - both captures outlive both QEMUs, and a dead client tcpdump trips its
    capture guard;
  - the client never runs without `--client`;
  - `login` with `--client` is refused; `client-login` uses a transient unit
    and does not block on an interactive login;
  - an inactive or unkillable traffic unit, a stop that lies, a truncated
    final read after a successful pre-fault control, a stale/foreign probe
    log, a pre-fault leak followed by a failed final read, a client route
    advertisement and a hold shorter than 30 s behave as above;
  - fix round 3 reproducers: a truncated fault-boundary read over a pre-fault
    backlog (exit 0 and exit 1, one or two lines kept), an untrusted
    boundary read with otherwise healthy traffic, an untrusted hold sample, a
    burst then silence, probes only during the end status call, a silent
    window in the middle of the hold, an exit-node switch in the middle of
    the hold, `unknown` from `is-active`, a non-zero `MainPID`, a writer that
    keeps appending after a claimed stop, a start that raises after launching
    the unit, untrusted reads at the pre-fault gate (the fault never runs),
    and client prefs without `AdvertiseRoutes`, with `RouteAll` true or with
    `ShieldsUp` false;
  - fix round 4 reproducers (each fails on 06baf40): a deadline size read
    that ends 1 s or 2 s after the hold while the only late exit attempt is
    a pair first written after the deadline (plus controls: the same slow
    read without the pair, a 1 s slow read that ends inside the hold, a
    2.5 s one that breaks the window rule, and a healthy run); a 60 s fault
    action with zero client probes and a frozen guest clock for
    restart-docker, kill-wireguard and kill-container (plus a healthy 60 s
    action that the helper thread samples, an action that raises, and a
    sampler that cannot be joined); a writer that appends every 5 s, first
    3 s after a clean-looking stop, both visible to and hidden from the
    `/proc` scan; real-shaped `ExitNodeStatus` JSON with `/32` prefixes;
    client prefs with `CorpDNS` true and the `--accept-dns=false` login; a
    router peer that the client sees online only on the third read.

## Accepted residual limits (round 5)

- **Coverage resolution is one window, not one action (GPT R5-I1).** Client
  traffic is proven per host window of at most 15 s, so up to about two
  windows can separate completed exit attempts. A fault action shorter than a
  window (stop-router, kill-wireguard and other actions of about 10-12 s) can
  contain no completed attempt and still PASS when attempts before and after
  it fall inside the window. Demanding a completed attempt inside every short
  action would make healthy runs fail: during a fault each probe can
  legitimately take up to about 11 s to time out. Producing GPT's case needs
  the client to stall exactly during the action and resume right after; the
  client VM is ours, not adversarial. Possible later strengthening: also
  require client-originated frames on the host-side client capture inside
  every action interval longer than a few seconds.
- **Login URL on stderr** (GPT I5, accepted in fix round 1).
- **Guest trust** (Opus round 4): the probe log is the only proof of attempted
  traffic; curl's Mullvad answer is read in the guest; the log is append-only;
  `stat`, `head`, `sha256sum`, systemd and tailscaled answer honestly. A
  stalled or buggy guest cannot produce PASS inside the sampled interval.

## Out of scope

- Client DNS-leak tests.
- More than one client at a time.
- IPv6.
- rust/v2.
