# Tailscale/WireGuard router security audit — 27 September 2026

**Historical scope:** This report captures the legacy router before the hardened
first-site deployment. Statements below about the "current" or "deployed"
router refer to that 27 September snapshot and its image
`sha256:cacc8337f3ba82fcb18e9ad7f847f38646ff36b1d3b568988c3caf54a8ea2670`.
The later hardened release and its remaining verification gaps are documented
in [first-site verification](VERIFICATION-FIRST-SITE-2026-09-27.md).

**Verdict: FAIL for the requirement that protected traffic must never bypass the VPN.**

At audit time, the legacy `max-vprouter` sent ordinary Internet traffic through Mullvad but had no complete, route-independent kill switch. Kernel packet tests reproduced cleartext egress outside WireGuard. Startup errors were ignored, IPv6 was unprotected if an uplink was added, and client-side fallback protection was not established. The legacy deployment was not leak-proof.

This was an audit, not a hardening deployment. Production scripts, routes, firewall rules, credentials, and services were left unchanged. Existing local edits were preserved. Tests ran in disposable containers without production credentials or tailnet membership. The production container remained running with its original start time and zero restarts.

## Scope and evidence

Inspected the actual Compose deployment, startup and credential loader scripts, live IPv4/IPv6 rules and routes, Tailscale preferences, process supervision, container permissions, installed packages, and relevant host Docker forwarding rules. Checked normal router egress against Mullvad's connection endpoint: `mullvad_exit_ip=true`, Frankfurt, `de-fra-wg-401`.

- Production image ID: `sha256:cacc8337f3ba82fcb18e9ad7f847f38646ff36b1d3b568988c3caf54a8ea2670`.
- Tailscale `1.98.5-AlpineLinux`; Alpine `3.24.1`; host kernel `6.12.107+deb13-amd64`.
- Sixteen synthetic packet scenarios exercised the Linux kernel with copied production firewall rules, real WireGuard, disposable generated keys, and TUN interfaces standing in for client and WAN interfaces. All external network attachments were removed before injection. The test reads outgoing packets and searches for its synthetic payload outside WireGuard.
- Repeated the sixteen scenarios with the test container restricted to 0.25 CPU and a concurrent 15-second workload touching 64 MiB. The same allow/block outcomes were observed. This is bounded scheduling pressure, not exhaustive overload or OOM qualification.
- Four command-failure cases executed the original bootstrap with controlled command stubs. A separate container ran that bootstrap as PID 1 to test termination.
- Evidence and reproduction notes: [audit/2026-09-27/README.md](audit/2026-09-27/README.md). File hashes and sanitized runtime details: [live-snapshot.json](audit/2026-09-27/live-snapshot.json).

The packet harness does not authenticate a real Tailscale client or test tailnet ACL admission. It tests what the router's kernel does with a packet already admitted onto `tailscale0`. Mocked command failures establish script behavior, not an actual provider-account expiry event.

## Findings

### F1 — Critical: forwarded traffic can leave outside WireGuard

**Confirmed in the running rules and reproduced in the isolated kernel tests.**

`bootstrap.sh:80-86` only accepts `tailscale0 → wg0` and selected return traffic, and drops unsolicited `wg0 → tailscale0` traffic. There is no terminal deny for `tailscale0 → eth0`. Live `FORWARD` policy is `ACCEPT`. A packet that misses these rules reaches `ts-forward`, which marks traffic arriving on `tailscale0` and accepts it, without restricting the output interface. Tailscale's NAT chain then masquerades marked traffic.

Two bypasses already exist in the healthy routing table:

1. The host route for the WireGuard endpoint sends **every protocol and port addressed to that IP** through `eth0`, not only WireGuard's encrypted transport. Synthetic UDP/443 and DNS/53 packets traversed this path outside the tunnel.
2. The directly connected Docker subnet is reachable through `eth0`. Synthetic client traffic to the bridge gateway escaped the WireGuard path. Whether a particular real client may address a private destination also depends on its routes and tailnet policy; those were not verified.

Deleting `wg0` and restoring an Ethernet default route let general client packets leave directly. Restoring a route was an explicit fault injection, not something observed happening spontaneously in production. The host's `DOCKER-USER` chain was empty, and its NAT table masqueraded the router's Docker subnet. No independent guard was present in that inspected chain.

**Impact:** an external destination reached through this bypass can see the router host's ordinary public egress address. This need not equal the remote PC's public address; PC-side fallback is a separate issue.

**Required correction:** enforce a persistent deny for protected forwarded traffic on every non-VPN egress, independent of routes and Tailscale's permissive chains. Cover both address families, interface changes, existing connections, and Docker/Tailscale rule recreation. Limit the physical-uplink exception to genuine WireGuard transport rather than broadly exempting the endpoint IP. Prefer an independent host or network-namespace boundary as additional protection.

### F2 — Critical: startup is unprotected and setup errors are ignored

**Confirmed by source review, kernel startup-state test, and four injected failures.**

`bootstrap.sh:3-26` starts Tailscale, sleeps five seconds, and enables the exit node before configuring WireGuard or the firewall. Persistent Tailscale state can resume an already authorized exit node during that interval. Compose enables forwarding from container creation. The initial network has ordinary Docker egress and no protective filter; a synthetic forwarded packet escaped in that state. Actual timing of real client reconnection during boot was not measured.

The loader's `set -euo pipefail` does not establish those options in the separately executed bootstrap. The bootstrap has neither fail-fast handling nor explicit checks for `wg setconf`, interface setup, route replacement, or firewall installation. Fault injection proved that WireGuard configuration failure, default-route failure, firewall failure, and DNS startup failure each still reached “WireGuard setup complete” and “Split DNS setup complete”, with the supervisor remaining alive.

**Required correction:** install a closed firewall before starting any forwarding-capable service; validate configuration; require every setup step to succeed; retain the closed policy after any error. Only announce readiness after verifying the complete data path. Avoid incremental exposure during firewall construction and replacement.

### F3 — High: IPv6 safety depends on the absence of an uplink

**Confirmed configuration gap; conditional leak reproduced.**

The node advertises `::/0` and Compose enables IPv6 forwarding. The loader selects only the first WireGuard address, and bootstrap configures only IPv4 routing and `iptables`. Live IPv6 filter policy is permissive and has only Tailscale rules, with no VPN egress guard.

The current Docker network has IPv6 disabled and no external IPv6 default route, so no ordinary IPv6 Internet leak was demonstrated in the present production topology. Adding an IPv6 WAN address and default route to the isolated test immediately allowed synthetic forwarded IPv6 outside the tunnel.

**Required correction:** either implement and test full IPv6 VPN routing and firewall enforcement, or explicitly deny non-required IPv6 Internet egress in both forwarding and local output. An absent route is not a persistent security policy.

### F4 — High: DNS rules do not enforce DNS containment

**Forwarding bypass reproduced; alternate resolver confirmed reachable.**

`bootstrap.sh:123-134` filters only locally generated IPv4 `OUTPUT`. Forwarded DNS follows `FORWARD`, where it can escape through the endpoint route or a restored Ethernet default route. Under the latter condition, a local UDP/53 probe was blocked, but forwarded UDP/53 and local/forwarded UDP/853 probes escaped. The tests used synthetic UDP, not actual HTTPS or DNS-over-QUIC sessions. TCP/853 is covered by a local-output rule; arbitrary encrypted DNS transports cannot be contained by a short port blacklist.

Docker's embedded resolver at `127.0.0.11` also remained usable: an explicit `example.com` query succeeded despite `/etc/resolv.conf` pointing to `127.0.0.1`. Its loopback/NAT path does not match the `eth0` DNS deny. Docker documents forwarding external queries to the host's configured resolvers. The ultimate upstream path was not packet-captured, and this is not evidence that normal client queries are currently using that alternate resolver. [Docker networking documentation](https://docs.docker.com/engine/network/).

**Required correction:** contain all application and forwarded egress, and explicitly account for Docker's DNS proxy and Tailscale's DNS service. Test OS DNS, direct DNS, TCP DNS, DoT, DoH, and IPv6; verify the clients as well as the exit node.

### F5 — Medium: service failure and shutdown are not supervised reliably

**Source and configuration confirmed; signal behavior reproduced with stubs.**

The bootstrap ends in `wait`, lacks signal traps, starts dnsmasq in daemon mode, and has no continuous checks of processes, firewall, or routes. The DNS failure test left the parent alive after failed DNS startup. Docker's `unless-stopped` policy responds to container exit, not every internal service failure. There is no health check, resource limit, PID limit, or explicit log rotation in this Compose service. `VPR_DEBUG` normally suppresses daemon diagnostics.

In the isolated PID-1 test, Docker sent SIGTERM and waited three seconds; the container required forced termination and exited `137`, with `OOMKilled=false`. This proves the shell's termination behavior with the test children; it does not prove a production shutdown leak or reproduce actual Tailscale shutdown cleanup. No host reboot or power cut was performed.

**Required correction:** supervise foreground children, handle signals, and keep the deny policy active throughout termination. Health checks and alerts should report failure; they must not be the mechanism that prevents the first leaked packet. Resource pressure, conntrack exhaustion, and full disks must cause loss of service rather than opening a fallback path.

### F6 — Medium: installed software is behind published security fixes

**Version/advisory match, not a demonstrated remote exploit.**

Tailscale `1.98.5` predates published fixes affecting SSH, Serve/Funnel, Services, and 4via6 routing. SSH and the remote web client are disabled; Serve configuration is empty, no Services are advertised, and only the two exit-node defaults are advertised. These observations limit the applicability of the reviewed feature-specific advisories; they do not justify claiming that those vulnerabilities are actively exploitable here. Use a supported build containing the current fixes. [Tailscale security bulletins](https://tailscale.com/security-bulletins).

Comparing every installed Alpine package origin against the current v3.24 security databases using Alpine's own version comparison identified older versions of `jq` (`1.8.1-r0`, listed fixes at `1.8.2-r0`), OpenSSL libraries (`3.5.7-r0`, listed fixes at `3.5.8-r0`), and Tailscale (Alpine lists relevant fixes at `1.98.10-r0`). Reachability of each advisory was not exploit-tested. [Alpine main security database](https://secdb.alpinelinux.org/v3.24/main.json), [community security database](https://secdb.alpinelinux.org/v3.24/community.json).

The image and Dockerfile use mutable `latest` tags. Live Tailscale preferences show update checking enabled but `Apply=null`; bootstrap's update command is not evidence of an effective patch process.

**Required correction:** rebuild from reviewed patched packages, pin the deployed artifact digest, and establish a repeatable security-update and rollback process with leak regression tests. Full host-kernel, hypervisor, firmware, and supply-chain audits remain outside this assessment.

### F7 — Medium: credential handling needs tighter boundaries

**Confirmed local exposure risks; no evidence of public disclosure.**

The credential-bearing `mullvad_wireguard_linux_all_all.zip` is untracked and not excluded by `.gitignore`; a later broad Git add could publish it. Host `.env`, the profile, and the archive have mode `600`; credential/state directories have mode `700`, which is good.

The generated in-container WireGuard file is mode `644`, but its parent is `700`. A read-permission test as UID 65534 failed, so it is **not** currently world-readable through that directory. Set explicit restrictive permissions nevertheless. The loader exports the private key, and live `tailscaled` was confirmed to inherit it. dnsmasq's environment could not be read in this check; its contents were not established.

The container runs as root with `NET_ADMIN`, a writable filesystem, and no capability drops. A compromise of that privileged network process can undermine an in-container firewall; isolation outside its control is needed for that threat model.

**Required correction:** exclude or securely relocate credential archives, minimize secret copies and environment inheritance, explicitly protect generated files, and reduce privilege where compatible. Do not infer a need to rotate keys from these findings alone; rotate if actual disclosure or unauthorized access is established.

### F8 — Required scope gap: PCs are not protected merely by advertising an exit node

The router cannot enforce packets that a PC sends through another interface or after its VPN software stops. No specified PC/phone was available for an end-to-end client test. The Docker host itself has no selected exit node; that observation is not evidence about other PCs.

For the requested guarantee, identify each protected client and enforce persistent OS-level egress restrictions across boot, login, logout, Tailscale disconnect/crash/update, sleep/resume, interface changes, and exit-node deselection. Test IPv4, IPv6, DNS, and applications that bind a specific interface. Local-network allowances and alternate exit nodes need explicit policy.

The ordinary IP address necessarily remains visible to the access network and the next hop carrying the encrypted VPN transport. Tailscale connectivity infrastructure and peers may learn transport endpoints. The meaningful goal is to prevent protected application traffic from reaching unapproved destinations outside the intended tunnel, rather than claiming anonymity from every party.

## Credential-expiry distinctions

| Event | What is established |
| --- | --- |
| Tailscale enrollment/auth key expires | Does not by itself invalidate an already enrolled node; device/node-key expiry is separate. This deployment normally uses persisted interactive authentication. |
| Exit node's Tailscale device key expires | Tailscale documents retaining the routes so they become unreachable rather than falling back. This was not induced on the live tailnet or tested on the actual PCs. |
| Mullvad account expires, provider rejects the key, or peer is unreachable | A synthetic unresponsive WireGuard peer with the VPN default route intact emitted no application payload onto the test WAN. Actual account expiry/revocation was not performed. |
| WireGuard configuration fails at startup | Bootstrap still reports success in the injected-failure test. Routing outcomes then depend on which later commands succeeded; there is no independent deny guarantee. |
| VPN interface disappears | Ordinary traffic stayed blocked without a replacement default route; the endpoint exception remained open. Restoring the ordinary default route caused general escape. |

Auth-key behavior is documented in [Tailscale auth keys](https://tailscale.com/docs/features/access-control/auth-keys); expired exit-node route handling is documented in [Tailscale exit nodes](https://tailscale.com/docs/features/exit-nodes). Disabling expiry may improve availability, but does not fix this router's leak paths.

## Verification matrix

| Scenario | Audit result |
| --- | --- |
| Normal router Internet egress | Live Mullvad egress verified |
| Initial permissive state before firewall | Synthetic application payload escaped |
| Endpoint host route, normal rules | Forwarded UDP/443 and UDP/53 escaped |
| Connected Docker subnet, normal rules | Forwarded payload escaped |
| Unresponsive WireGuard peer, route intact | No application payload escaped to test WAN |
| WireGuard link down / deleted, no fallback route | Ordinary destination blocked |
| Endpoint route after WireGuard deletion | Payload escaped |
| Ethernet default route restored | Forwarded and local application payloads escaped |
| Local DNS/53 versus forwarded DNS/53 after route restoration | Local blocked; forwarded escaped |
| UDP/853 after route restoration | Local and forwarded payloads escaped |
| IPv6 uplink introduced | IPv6 payload escaped |
| Bounded CPU pressure | Same sixteen packet-test outcomes |
| Invalid WG configuration / route failure / firewall failure / DNS failure | All four falsely reported complete setup |
| PID-1 SIGTERM with three-second grace | Forced termination, exit 137; stubs used |
| Real client key expiry, disconnect, reboot, and interface switching | NOT TESTED |
| Production shutdown, power loss, host/kernel crash, Docker restart | NOT TESTED |
| Actual OOM, disk exhaustion, conntrack exhaustion, full host overload | NOT TESTED |
| Tailnet ACLs, account controls, physical router, other PCs, WebRTC/browser behavior | NOT AUDITED end to end |

No synthetic payloads were sent to an external WAN. These results demonstrate missing controls; they do not establish that previous user traffic actually leaked.

## Required order of remediation

1. Establish permanent IPv4/IPv6 enforcement independent of routing, including all endpoint, Docker, DNS, and local-output exceptions. Install it before any tunnel service can forward traffic.
2. Correct initialization checks, readiness, shutdown, and service supervision without removing that enforcement on error.
3. Patch and pin the container, tighten credential handling, and add independent monitoring and a host/namespace defense where required.
4. Enforce and validate the actual client devices' no-fallback policies.
5. Repeat real-client leak tests with WAN observation across failures, cold boots, shutdown, upgrades, interface changes, and bounded resource exhaustion. Define acceptance as zero protected packets outside the approved encrypted transport; an outage is the safe outcome.

The current system fails before those more demanding qualification tests. Passing a finite set of tests can support specific guarantees under a defined threat model; it cannot honestly establish perfect security under every possible failure or privileged compromise.
