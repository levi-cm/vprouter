# Hardened router verification record

This record applies to the hardened source and `vprouter-hardened:staged` image
built on 2026-09-27. The image was installed on the first host as the active
`max-vprouter` service. It is a point-in-time verification record, not a
guarantee against every future failure. The legacy router was stopped, its
restart policy disabled, and its container renamed before cutover.

The tested local image ID is
`sha256:5e005133781efb99ae9c8687b6ad442c76905d3d65b464c08387300f76e0c893`.
The [release inventory](RELEASE-INVENTORY-2026-09-27.txt) records its package
versions. `apk upgrade` resolves packages at build time, so a later rebuild can
produce a different image and must be retested. Copy or publish the exact
tested image by immutable digest for another site.

| Check | Result | What it establishes |
| --- | --- | --- |
| Python unit/contract suite | 21 passed | Configuration rejection, image/Compose isolation, nft syntax, cleanup ownership, tunnel-structure recovery, provider-failure and Tailscale withdrawal, and runtime preflight |
| Disposable router packet injection | Passed | Positive controls emitted cleartext without the guard; guarded startup, default-route restoration, endpoint exceptions, fake `wg0`, bridge and IPv6 cases emitted no cleartext on the fake WAN |
| Isolated host packet test | Passed | Among tested flows, only the pinned UDP endpoint and return packet crossed the dedicated bridge; another port, host input and host ICMP to the provider were blocked; the ICMP drop counter incremented; bridge rename blocked egress; guard flush was detected |
| Isolated WireGuard namespace test | Passed | A real kernel WireGuard interface created in the transport namespace was moved into the router namespace; both router-originated and synthetic tailnet-client forwarded packets and replies traversed the tunnel while the transport observed no plaintext |
| Disposable Docker Compose provisioning | Passed | Router booted with `network_mode=none`, waited for its firewall, received only `wg0` and `tailscale0`, and remained BLOCKED when the fake provider was unreachable |
| systemd unit parse | Passed | The unit is syntactically valid; unrelated host-unit warnings were emitted |
| Live cutover | Passed | Root-owned release and private profile were installed; router and transport containers started under systemd; router remained `network_mode=none` |
| Live protected egress | Passed | The router reported Mullvad exit IP true; host reported false; public addresses differed; Tailscale was online and advertised the exit routes |
| Controlled service stop/start | Passed | Stop made both managed containers inactive and the unit inactive with success; start returned the service to READY |
| `tailscaled` crash | Passed | Killing the daemon triggered a systemd restart and the router returned to READY |
| Live WireGuard deletion and recovery | Passed | Before automatic recovery was added, deleting `wg0` produced an empty default route, BLOCKED health, offline Tailscale, and a failed HTTPS probe. With the monitor fix, deletion triggered automatic restart and reprovisioning, then returned to READY with protected egress. The probe in the later drill was interrupted by container restart. |
| Dedicated bridge fault capture | Passed with observation | Ten ICMP port-unreachable replies addressed to the VPN provider appeared on the bridge during an earlier WireGuard teardown. They quoted the encrypted outer UDP flow, not inner client packets. The capture filter covered IPv4 except pinned provider UDP; no other IPv4 packets matching that filter were observed in that window. |
| Physical-interface fault capture | Passed for provider ICMP | An initial teardown emitted six host-generated ICMP unreachable messages to the VPN provider on the physical interface. On the final image, a simultaneous bridge/WAN capture during deletion found nine IPv4 non-provider-UDP packets on the dedicated bridge before that interface disappeared, the host output drop counter reached five, and zero provider ICMP packets appeared on the physical interface through recovery. The router went BLOCKED, restarted and returned to READY. This capture was scoped to provider ICMP on the WAN, not all WAN traffic. |

The final-image WAN capture started one second before deleting `wg0` and ended
after the service returned to READY. The dedicated-bridge capture ended early
when Docker removed that interface; `tcpdump` returned 1 for that capture and
0 for WAN. The provider address and port came from the
root-owned profile; the physical interface was resolved with `ip -j route get`.
The physical filter was `icmp and host <provider IPv4>`; the dedicated-bridge
filter was `ip and not (udp and host <provider IPv4> and port <provider port>)`.
The capture files and manifest contain real endpoint metadata, so they are
retained locally at `/var/lib/vprouter/evidence/2026-09-27/` with root-only
access and are not published. SHA-256 hashes: `wan-final-image.pcap`
`704e5e5b3234433c01fcfd1b20a306e77e985038120492dc53965c3edd38a4ea`;
`bridge-final-image.pcap`
`abd24154cf2ab85d1ba7ff8a09f40b92e3c554e0fbf2c90ea80ae9da78b6bd1a`;
`final-image-capture-manifest.json`
`bfe939d12df592c6c92640653bc6b7e5837580fa8b812a1ac659059a64c2d60c`.
The manifest records the resolved physical interface, exact filters, UTC
window, capture exit codes, image ID, packet counts and sampled nft counter.

These tests demonstrate containment and recovery properties, but do not prove
universal safety. Real tailnet-client packet verification, forced credential
expiry, sustained overload, and a full host reboot were not run. The direct
HTTPS probe during the live tunnel deletion was interrupted as the container
restarted, so its failed exit alone is not evidence of network blocking; the
isolated packet-injection and host-firewall tests establish the no-fallback
property for that fault. The physical-interface capture checked provider ICMP
only. No finite test set can rule out kernel
defects or host-root compromise. The second location and client behavior are
outside this deployment scope.

The acceptance rule for this router is: when any guard, provider, handshake,
route, interface, or Tailscale health check fails, routed service must be
unavailable. A direct internet fallback from the router namespace is forbidden.
The legacy router is not an acceptable fallback for protected traffic.
