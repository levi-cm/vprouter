# Fail-closed Tailscale exit router

![Conceptual vprouter traffic flow](overview.png)

This Linux-only router advertises a Tailscale exit node after it verifies a
Mullvad WireGuard tunnel. The router container starts with **no ordinary
network interface**. A root-owned host service creates WireGuard in a separate
transport namespace and moves only `wg0` into the router namespace. The
WireGuard UDP socket stays in the transport namespace. The router has an nftables
default-drop policy for input, output, and forwarded traffic; the host guard
allows the transport container to contact only the pinned provider IPv4/UDP
endpoint. IPv6 exit forwarding is blocked. Tailscale state persists separately
at each site. The WireGuard profile file remains on the host; after setup its
private key is also held by the kernel WireGuard interface and is readable by
an actor with network-administration privileges in the router namespace.

This reduces the chance of disclosing the host's public IP if the tunnel,
Tailscale credentials, routing, DNS, the container, or the supervisor fails.
It does **not** provide a mathematical guarantee against Linux kernel defects,
compromised host root/Docker, physical interception, or a client that switches
to direct internet when its exit node disappears. Each client must have its own
fail-closed policy and be tested during exit-node loss. Two locations provide
availability only if clients have a tested failover policy; they do not create
one automatically.

## Site installation

Use one independent site configuration, Tailscale identity/state directory,
WireGuard key/profile, and exit-node name at each location. Do not clone one
site's state or keys to the other. The dedicated bridge name and subnet are
fixed, so this release supports one router per Linux host.

1. Review the release and run the verification commands below. Build the
   container image and record its immutable local image ID with
   `docker image inspect --format '{{.Id}}' vprouter-hardened:staged`.
   A later build may resolve different Alpine packages; retest any new image.
   To use the same tested image at a second site, transfer an OCI image archive
   or publish it under an immutable registry digest rather than rebuilding a
   mutable tag independently.
2. Install the reviewed source under `/opt/vprouter/current`, owned by root and
   not group/user writable. Keep each parent directory root-owned and not
   group/user writable. Install `python3`, Docker with Compose, `nftables`,
   `iproute2`, `util-linux` (`nsenter`), and `wireguard-tools` (`/usr/bin/wg`)
   on the host. The host's Docker bridge must not collide with
   `10.255.240.0/29` or `br-vpr-uplink`.
3. Place a provider profile at `/etc/vprouter/<site>.conf` and a JSON file at
   `/etc/vprouter/<site>.json`. Both must be root-owned and mode `0600`. The
   JSON `name` must match `<site>` so systemd can stop the exact containers.
   Use a numeric IPv4 endpoint, a single WireGuard peer, a `/32` tunnel IPv4
   address, and `AllowedIPs = 0.0.0.0/0`. Example JSON:

   ```json
   {
     "name": "max-vprouter",
     "profile": "/etc/vprouter/max-vprouter.conf",
     "state_dir": "/var/lib/vprouter/max-vprouter",
     "image_ref": "sha256:<64-hex-character-local-image-id>",
     "compose_dir": "/opt/vprouter/current"
   }
   ```

4. Run `python3 /opt/vprouter/current/host/orchestrate.py validate --config
   /etc/vprouter/max-vprouter.json`. Install `host/vprouter@.service` as
   `/etc/systemd/system/vprouter@.service`; run `systemctl daemon-reload`,
   then `systemctl enable --now vprouter@max-vprouter.service`. The host service
   applies the guard before starting either container and stops both containers
   when it exits. Docker restart is deliberately disabled.
5. Enroll the new Tailscale node through the normal protected session if its
   state directory is new. Approve the exit-node advertisement in the Tailscale
   admin console. Verify `docker inspect` reports `network_mode=none` for the
   router and verify its only non-loopback interfaces are `wg0` and
   `tailscale0`. A healthy container status alone is insufficient: send
   traffic from a **test client using this exit node**, confirm the provider
   egress IP, inspect DNS and IPv6 behavior, and test tunnel/credential loss.

For a trusted unattended exit node, decide in the Tailscale admin console
whether to disable node-key expiry. If expiry remains enabled, monitor its
deadline and arrange out-of-band reauthentication before it expires. An
expired or revoked identity must reduce availability, never permit direct
router egress. Keep a separate method to reach the host if Tailscale stops.

Do not switch production clients to a new deployment until the real client
failure tests and independent security review have passed. When replacing the
legacy `max-vprouter` container on a host, stop and disable its Docker restart
policy first; use a distinct new container name during validation to avoid a
name collision. Roll back only to a previously verified hardened release;
otherwise leave the exit node offline. Do not restore the legacy router for
protected client traffic.

## Verification in an isolated lab

```bash
python3 -m unittest discover -s tests -v
sudo env VPROUTER_LAB_ISOLATED=1 unshare --net python3 tests/host_packet_probe.py
sudo env VPROUTER_LAB_ISOLATED=1 unshare --net python3 tests/wireguard_namespace_probe.py
sudo env VPROUTER_LAB_ISOLATED=1 python3 tests/compose_provision_probe.py
# Run tests/leak_probe.py only through stdin in a disposable --network none
# router container. The script refuses any pre-existing non-loopback interface.
```

`tests/host_packet_probe.py` verifies that only the provider tuple crosses the
dedicated bridge and that its reply returns. `tests/leak_probe.py` injects
synthetic traffic into the router namespace and checks that no plaintext
appears on an added ordinary interface under route, endpoint, bridge, and IPv6
faults. These checks are necessary but do not replace live end-to-end tests.

## Operations

`router-runtime --status` reports readiness only after current provider and
Tailscale checks. Monitor the systemd unit, both containers, the WireGuard
handshake, the router's health file, the advertised exit-node state, and a real
test client's provider egress. Alert when any check fails. A blocked router is
safer than silently falling back to direct egress. For planned upgrades,
rotate one site at a time, keep the other site serving, and repeat the client
failure matrix before restoring redundancy.

`python3 /opt/vprouter/current/host/orchestrate.py status --name <site>` exits
nonzero unless both containers, the dedicated bridge, host guard, and the
router's fresh READY record are present. Use it as one monitoring signal; a
real protected-client egress probe is still required.

The older `bootstrap.sh` is retained as historical code but is not used by
the hardened image or Compose deployment.
