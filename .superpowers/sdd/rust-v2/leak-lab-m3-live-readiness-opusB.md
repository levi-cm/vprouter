# Leak lab M3: live-readiness review (Opus B)

Commit: 06baf40 (branch rust/v2). Reviewer: Claude Opus 5.5, fresh eyes, no subagents.
Scope: host safety of the planned live sequence, whether the client path works
live, and whether the docs match the code. Read-only: the only file written in
the repo is this report. Scratch work was done in /var/tmp/leaklab-m3r4-opusB,
which was deleted at the end. No sudo, QEMU, ip/nft/iptables, docker or network
command was run. The host's `/usr/bin/tailscale` binary was **read** with
`gdb -batch ptype` and a stdlib byte scan to get the real JSON shapes. It was
never executed against the daemon.

## Summary

- **Host safety: no Critical or Important findings.** I replayed the exact live
  sequence through the repo's own stub shell harness (`test_leak_lab._STUB_SOURCE`):
  1. M2-era setup, rendered by the pre-M3 `netplan.py`, with an owner record
     that has no `clients` key.
  2. Teardown with the new plan.
  3. Setup with `--client 1`.
  4. Teardown.

  Every step ended clean. Mid-setup failures and failed teardowns all left a
  state that the next teardown removed. Every nft/iptables call targeted only
  `inet vprlab` or exact `DOCKER-USER` specs. Two Minor notes.
- **Will it work: 1 Blocker, 1 Likely, 4 Possible.**
  - The Blocker (B-1) makes **every** `--client` phase INVALID at exit-node
    selection. `ExitNodeStatus.TailscaleIPs` is `[]netip.Prefix` (`"100.x.y.z/32"`),
    but the code compares a bare address.
  - The Likely (L-1): `tailscale up` without `--accept-dns=false` lets the
    client's tailscaled write `nameserver 100.100.100.100` into
    `/etc/resolv.conf`, and the client silence check refuses any nameserver line.
  - Both are failures to the safe side (INVALID, never a false PASS), and both
    fixes are a few lines.
- **Docs vs code:** every operator command in the docs is accepted by the code
  as written. Three stale statements are listed, and one doc sentence encodes B-1.

## Test suites (run once each, from tools/leak-lab)

- `python3 -B -W error -m unittest test_leak_lab`: **Ran 341 tests, OK** (exit 0)
- `python3 -B -W error -m unittest vm.test_vm`: **Ran 291 tests, OK** (exit 0)

---

## 1. Host safety of the planned sequence

### What was run (stub harness; real tools never invoked)

`/var/tmp/leaklab-m3r4-opusB/sim_host.py` imported `test_leak_lab._prepare_stub_lab`
/ `_stub_env` (PATH points only at the stub `ip`, `nft`, `iptables`, `sysctl`,
`tcpdump`). The old plan was `git show b849e3c^:tools/leak-lab/netplan.py`
(888f0d4, the last pre-M3 netplan) rendered with `render_plan(WAN)`. The new
plans are 06baf40 `render_plan(WAN, clients=(1,))` and `render_plan(WAN)`.
Output, verbatim:

```
=== A: M2-era setup -> new --client 1 teardown -> new --client 1 setup -> teardown
-- old_setup: exit 0; links [vprlab-tap0, vprlab0]; neigh 10.250.0.2@vprlab0; table; rules 2; owner present "<no key>"
-- new_teardown: exit 0; links []; neigh {}; no table; rules 0; owner absent
-- new_setup_c1: exit 0; links [vprlab-ctap1, vprlab-tap0, vprlab0, vprlab1]; neigh 10.250.0.2@vprlab0, 10.251.0.2@vprlab1; table; rules 4; owner [1]
-- new_teardown_c1: exit 0; everything gone; owner absent
=== B: M2-era setup -> new NO-client teardown: exit 0, everything gone (rules 2 -> 0)
=== C: --client 1 setup fails at nft create (vprlab1 + ctap1 exist) -> auto teardown: exit 1, everything gone, owner absent
=== D: --client 1 setup, teardown with NO-client plan (owner lists [1]): exit 0, everything gone
=== E: setup fails at nft create AND auto-teardown cannot delete links:
       exit 1, [vprlab-ctap1, vprlab0, vprlab1] left DOWN, no table, rules 0, owner [1] retained
       -> retry teardown: exit 0, everything gone
=== F: --client 1 setup while the M2-era setup is still present:
       "owner.json already exists; refusing setup", old state untouched (RUN_STARTED stays 0, no auto-teardown)
=== G: teardown where `iptables -C` fails (status 2): exit 1, table + links kept, owner retained
       ("DOCKER-USER rules could not be proved removed") -> retry: exit 0, everything gone
```

No scenario issued an nft or iptables command outside `inet vprlab` or
`DOCKER-USER` (the harness flagged none).

### Findings with evidence

- **Old owner without `clients`:** `_READ_OWNER_CLIENTS_CODE` uses
  `document.get("clients", [])` (`netplan.py:303`), so a schema-1 M2 owner
  record reads as "no clients". With the `--client 1` plan, `CLIENT_INDEXES`
  is still `1`, from `PLANNED_CLIENTS` (`client_indexes()`, `netplan.py:1047-1053`).
  Absent client objects verify as rc 1 ("absent"), and the client teardown
  steps are no-ops (scenario A). With the no-client plan, the fail-closed
  residue check (`netplan.py:1211-1224`) finds nothing (scenario B).
- **Old DOCKER-USER rules are removed by the new plan:** the
  `docker_spec_out`/`docker_spec_in` text is byte-identical in 888f0d4 and
  06baf40 (`netplan.py:1026-1034`), so `iptables -C/-D` with the new spec
  matches the live M2 rules (scenario A: rules 2 → 0).
- **Every command the `--client 1` setup adds** (`netplan.py:1124-1170`):
  - `ip tuntap add dev vprlab-ctap1 mode tap user vprlab-qemu`, then ifalias
    `$OWNER`.
  - `ip link add vprlab1 type bridge`, then `address 52:54:00:76:71:01`, then
    ifalias.
  - Enslave the tap, `sysctl -w net.ipv6.conf.{vprlab1,vprlab-ctap1}.disable_ipv6=1`,
    `ip addr add 10.251.0.1/24 dev vprlab1`.
  - 13 `nft add rule inet vprlab ...` rules. Each one matches only
    `iifname/oifname vprlab1|vprlab0` or the scoped `10.251.0.0/24` masquerade.
  - Two `iptables -I DOCKER-USER -i vprlab1 -o <wan> -s 10.251.0.0/24 ...` /
    `-i <wan> -o vprlab1 -d 10.251.0.0/24 --ctstate ESTABLISHED,RELATED ...`
    accepts with the owner comment.
  - `ip neigh replace 10.251.0.2 lladdr 52:54:00:76:71:02 dev vprlab1 nud permanent`.
  - Links brought up last.

  Nothing names `docker0`, a `br-*` bridge, `tailscale0`, a Docker chain other
  than DOCKER-USER, or another nft table. The `inet vprlab` base chains are
  `policy accept`, so they never decide anything for production traffic. The
  vprlab0↔vprlab1 drops are in place, and the router rules
  (`iifname vprlab0 oifname != WAN drop`, `netplan.py:907-908`) already cover
  both directions before the client block.
- **Production objects and the host's tailscaled:** the runner's only host
  mutation is `ip link set dev <lab tap> down` from the capture guard
  (`run_phase.py:2511`). Every fault (`restart-docker`, `kill-container`, ...)
  runs inside the router VM over QGA, never against the host's Docker. No step
  touches the host tailscaled's `ts-*` chains or its routes.
- **Failure halfway:** an `nft create` failure after vprlab1/ctap1 exist
  triggers the EXIT trap's `do_teardown` (RUN_STARTED=1). That cleans
  everything (scenario C). If the auto-teardown itself fails, the owner record
  is retained and a plain `sh lab.sh teardown` finishes the job (scenario E).

### H-1 (Minor) A failure between `ip link add vprlab1` and its `alias` leaves unowned residue that teardown refuses forever

`netplan.py:1128-1130` runs `ip link add vprlab1 type bridge`, then
`ip link set vprlab1 address ...`, then `alias "$OWNER"`. If the address set
fails, `vprlab1` exists without the owner alias. `verify_ownership` then fails
(`link_owned vprlab1 bridge`), so the auto-teardown and every later teardown
abort "without changes".

This is safe: every link is still DOWN, there is no table and no
DOCKER-USER rule. It does need a manual `ip link del vprlab1` and
`ip link del vprlab0/vprlab-tap0`. vprlab0 has had the same pattern since M1
(`netplan.py:886-888`).

Fix (optional): set the alias immediately after `ip link add`, before the
address change. Or document the manual recovery.

### H-2 (Minor) The client node is a normal tailnet peer behind the same NAT as the host's tailscaled

The client VM's tailscaled (`--port=41641`) is masqueraded to the WAN address,
where the host's own tailscaled also uses 41641. Conntrack masquerade only
remaps on a tuple clash, so neither side breaks.

Since M2, the host tailscaled also advertises 10.250.0.1 (and now 10.251.0.1)
as local endpoint candidates. The client's disco packets to 10.251.0.1 are
dropped by `input iifname "vprlab1" drop`. If the client joins the same tailnet
as the host, it can reach the host's tailnet services over WireGuard, subject
to tailnet ACLs.

No change needed for safety. Consider tagging the client node and denying it
everything except `autogroup:internet` in the ACL.

### Host-side verdict

Safe to run in the planned order:
1. Refresh the tools with `hostsetup.py`.
2. Render the new plan to `/root/vprlab-lab.sh` (with or without `--client 1`;
   both tear down the M2-era setup).
3. `sh /root/vprlab-lab.sh teardown`.
4. Rerun the collision preflight.
5. Render with `--client 1` and run `sh /root/vprlab-lab.sh setup`.
6. Run the router-only idle phase.

Scenario F shows that skipping the teardown is refused without damage.

---

## 2. Will it work live

### B-1 (Blocker) `ExitNodeStatus.TailscaleIPs` holds prefixes, so no client phase can ever select the exit node

`run_phase.py:3097-3122` `client_peer_is_active()` ends with
`return address in addresses`. `address` is a bare IPv4 (`"100.x.y.z"`, from
`client_peer_ipv4`, `run_phase.py:3083-3094`). `addresses` is
`ExitNodeStatus["TailscaleIPs"]`. In real Tailscale that field is
`[]netip.Prefix`. Evidence from the DWARF of the host's
`/usr/bin/tailscale` 1.102.3 (`gdb -batch -ex "ptype 'tailscale.com/ipn/ipnstate.ExitNodeStatus'"`):

```
type = struct tailscale.com/ipn/ipnstate.ExitNodeStatus {
    tailscale.com/tailcfg.StableNodeID ID;
    bool Online;
    []net/netip.Prefix TailscaleIPs;          <-- JSON "100.64.0.9/32", "fd7a:…/128"
}
PeerStatus: []net/netip.Addr TailscaleIPs;    <-- bare (Self, Peer[*]) — correct in the code
```

Reproduced against the real function with a realistic document:

```
prefix form (real tailscale): False
prefix form, require_online=False: False
```

Effects:
- `wait_client_exit_node` (`run_phase.py:3149-3165`, called at `:4447`) times
  out after 180 s with "the client did not report the test exit node as
  active". Every `--client` phase other than `client-login` is INVALID before
  the traffic unit starts.
- If this were patched only at that call site, every hold sample
  (`run_phase.py:4566-4574`, `require_online=False`) would note
  `client_exit_node_lost`.

The fakes in `vm/test_vm.py:5832-5869` and the other `ExitNodeStatus` fakes
(19 occurrences) all use bare addresses, so the suite cannot catch this.

**Fix:**
- Parse each entry with `ipaddress.ip_interface(entry)`. Accept it when it is
  IPv4, the prefix length is 32 and `.ip == IPv4Address(address)`. Ignore IPv6
  entries.
- Switch the fakes to the real `"/32"` form. Add one test that the bare form
  is accepted or refused, as a deliberate choice.
- Update `leak-lab-vm.md:130` and design step 6 ("containing that address")
  to say the IPv4 `/32` prefix.

All other status fields the code reads exist under the names it uses, per the
same DWARF:
- `Status.BackendState`, `Self` (`*PeerStatus`), `Peer` (map of
  `*PeerStatus`), `ExitNodeStatus.ID/Online`.
- `PeerStatus.ID/HostName/DNSName/TailscaleIPs/Online/ExitNode/ExitNodeOption/PrimaryRoutes/AllowedIPs`.
- `ipn.Prefs.RouteAll bool`, `ShieldsUp bool`, `AdvertiseRoutes []netip.Prefix`.

The reflect name table in the binary shows `AdvertiseRoutes` and `RouteAll`
with **no** JSON tag. An empty route list is therefore emitted as `null`,
which the code accepts (`run_phase.py:2951-2955`). `ShieldsUp` also has an
`omitzero` variant somewhere in the binary. If that variant is `ipn.Prefs`,
a false value is omitted and gives `client_prefs_incomplete` instead of
`client_shields_down`. That is still a refusal, so it is harmless.

### L-1 (Likely) `tailscale up` keeps accept-dns on, and the client silence check refuses the nameserver tailscaled writes

- **Login command:** client-login runs
  `tailscale up --reset --hostname=… --shields-up --accept-routes=false`
  (`run_phase.py:4233-4239`). `--reset` returns `CorpDNS` to its default
  `true`. The product itself passes `--accept-dns=false`
  (`/opt/vprouter/current/router_runtime.py:172`).
- **What tailscaled does:** provisioning makes `/etc/resolv.conf` a plain file
  with no owner header and masks systemd-resolved (`guest.py:1123-1125`,
  `:1138`). tailscaled's Linux DNS manager therefore picks *direct* mode. On a
  tailnet with MagicDNS enabled (the default for tailnets created since 2022),
  it rewrites `/etc/resolv.conf` to `nameserver 100.100.100.100` whenever it is
  Running.
- **What the check does:** `client_silence_check_script` fails on any
  nameserver line (`guest.py:1823-1827`: `bad resolv_conf_nameserver`). The
  runner runs that check right after QGA is ready and before
  `wait_client_running` (`run_phase.py:4206-4219`), so the outcome is a boot
  race against tailscaled reaching control.
- **Worse case:** after any forced poweroff (where tailscaled cannot restore
  its backup), the rewritten file persists and every later boot fails
  deterministically with "client silence check failed".

**Fix:**
- Add `--accept-dns=false` to the client-login command.
- Make `client_route_advertisement_problem` also require
  `CorpDNS is False`. The field exists in `ipn.Prefs`.
- Update the command in `leak-lab-vm.md:91-93` and the design's
  "User decisions" section.
- If client-login already ran without the flag, run
  `tailscale set --accept-dns=false` once and confirm the silence check.

### P-1 (Possible) Finding the router peer is a single read and can race the client's netmap

`client_find_router_peer(read_client_status(...))` runs exactly once, right
after the router is READY (`run_phase.py:4433-4444`). It requires the peer to
be `Online: true` with `ExitNodeOption: true` in the **client's** netmap. The
router went from offline to online shortly before, and control pushes peer
online state to the client asynchronously. Usually that takes about a second,
but a single read can lose the race and refuse with
`client_exit_peer_missing`.

Fix: poll for up to about 60 s. Refuse immediately only on an ambiguity
(duplicate ID or hostname collision), not on "not yet online".

### P-2 (Possible) 256 MiB: an OOM kill of tailscaled fails open and would read as a LEAK

Rough budget at test boot:
- MemTotal is about 220 MiB.
- Kernel plus systemd, journald, udevd, networkd and qemu-ga take about
  60–70 MiB.
- tailscaled takes 40–60 MiB RSS.
- The python traffic loop takes about 10 MiB.
- Each curl with OpenSSL takes about 10 MiB.
- Each sample's `tailscale status --json` CLI adds 15–25 MiB transiently.

That leaves tens of MiB with no swap. tailscaled has the largest RSS and is
the default OOM victim. When it dies, `tailscale0` disappears, table 52
empties, and the `lookup 52` rule falls through to `main`. Client probes then
go out in clear through 10.251.0.1, giving `m:false` and marker in clear,
which is LEAK. That is a client-VM artefact, not a router finding.
`Restart=on-failure` narrows the window but does not close it.

Fix:
- Add `OOMScoreAdjust=-900` to the client `tailscaled.service`
  (`guest.py:1077-1092`). An OOM then kills the traffic script or curl, which
  is a fail-safe INVALID (`client_traffic_unit_inactive`).
- Record guest `MemAvailable` (`/proc/meminfo`) in each hold sample. The
  "go lower later" decision currently has only host MemAvailable
  (`run_phase.py:4102`).

### P-3 (Possible) The client's am.i.mullvad.net cadence shares the exit IP with the product's own provider check

- **Client cadence:** the traffic loop hits `https://am.i.mullvad.net/json`
  every loop. That is about every 1.5–2.5 s while healthy (`guest.py:997-1001`).
- **Product check:** the router's `router_runtime.provider_probe()` uses the
  same URL every 5 s from the **same Mullvad exit IP**
  (`router_runtime.py:17, 84-93, 232-240`). It treats a second consecutive
  429 as a failure, which leads to `block_failed_provider` and
  `tailscale down`.
- **Consequence:** if am.i.mullvad.net rate-limits per source IP, the client
  can push the router fail-closed in the middle of a phase. Idle and hold
  verdicts stay fail-safe, but the router-READY waits after restart-docker or
  reboot can time out (INVALID).

Fix: run the exit probe every 5 s; the marker probe to example.com can stay
every loop. Every 10–14 s hold window still gets at least two exit attempts.
This is also kinder to the external service.

### P-4 (Possible) Provisioning extracts the tarball into `/tmp`, which is RAM on Debian 13

`guest.py:1067-1075` extracts the tarball into `/tmp/vprlab-ts`. On Debian 13,
`/tmp` is a tmpfs (50 % of RAM, about 190 MiB at 384 MiB), and cloud-init's
Python is still resident. The roughly 70 MiB of extracted binaries fit, and
the directory is removed before tailscaled starts. Even so, it is the largest
avoidable RAM consumer during the one boot with no swap.

Fix: extract into `/var/tmp/vprlab-ts` (disk).

### P-5 (Minor) Untested pieces of the client tailscaled setup

- **Firewall mode:** the client has no `iptables` or `nft` binary.
  tailscaled's linuxfw auto-detection should then use netlink nftables, which
  needs no binary.
- **IPv6:** IPv6 is disabled by sysctl, which tailscaled detects (`checkIPv6`).
  It then skips `::/0`.
- **Unit:** the unit has no `ExecStopPost=… --cleanup`. That is acceptable
  because nothing persists across a reboot.

Confirm on the first test boot with
`journalctl -u tailscaled | grep -i -E 'firewall|netfilter|nftables|ipv6'`.

### Verified as fine (no change needed)

- **Provisioning (384 MiB, online):**
  - Packages: `qemu-guest-agent ca-certificates curl python3-minimal iproute2
    util-linux`. The genericcloud image already has full python3 for
    cloud-init, so the traffic script's `json`/`subprocess` imports resolve.
  - The tarball hash is checked on the host (`provision.py:179-209`), again
    after staging (`:464-512`), and in the guest (`guest.py:1063`).
  - Binaries go to `/usr/local/sbin`, and the state dir is
    `/var/lib/tailscale` (0700).
  - Unit: `--state=/var/lib/tailscale/tailscaled.state --port=41641`, with
    `RuntimeDirectory=tailscale`, so the default socket
    `/run/tailscale/tailscaled.sock` matches the CLI default.
  - The cloud-init masking sequence (`disable --now cloud-final` from inside
    runcmd) is identical to the router's, which already provisioned live.
  - Admission: 4 GiB on the state filesystem.
- **Static networkd (`guest.py:673-688`, `711-718`):** MAC-matched,
  `10.251.0.(N+1)/24`, gateway 10.251.0.1, permanent `[Neighbor]` for the
  gateway MAC, no DHCP/RA/LL. The silence check verifies each of these. No DNS
  is needed by the probes (`curl --resolve`). tailscaled itself falls back to
  its built-in bootstrap DNS over DERP when resolv.conf has no nameserver.
- **Transient units:**
  - `tailscale up` runs as `systemd-run --unit=vprlab-client-login --collect
    --property=RuntimeMaxSec=<duration+600>` (`run_phase.py:4233-4242`).
  - The URL comes from `Status.AuthURL` or the tailscaled journal, matched by
    the same fixed regex as the router login that already worked live.
  - The login polls BackendState and stops when it is Running.
  - The traffic unit: `systemctl reset-failed …; systemd-run
    --unit=vprlab-client-traffic -p RuntimeMaxSec=<duration+90+360+allowance+600>
    /usr/local/sbin/vprlab-client-traffic '<marker>' '<ip>' '<ip>'`
    (`run_phase.py:3235-3244`). Every argument is `shlex.quote`d and validated
    first. The shebang `/usr/bin/env python3` resolves under systemd's PATH.
- **Exit node commands:** `tailscale set --exit-node=<IPv4>
  --exit-node-allow-lan-access=false` and `tailscale set --exit-node=` are
  correct CLI. The client controls use `SO_BINDTODEVICE` to the client NIC
  (`control.py:125-135`), so they leave in clear on `vprlab-ctapN` even if
  table 52 still has a default route.
- **am.i.mullvad.net JSON:** `mullvad_exit_ip` is a boolean in the real
  response, and the product reads the same document (`router_runtime.py:114`).
  A 429 or HTML body becomes `ok:false` and never `m:false`
  (`guest.py:955-964`).
- **QGA timing against the 15 s windows:**
  - A sample is four guest-exec calls: `stat`, `head -c N | sha256sum`,
    `head -c N`, and `tailscale status --json`. Each exec polls at
    50 ms → 75 ms → … (`qga.py:309-337`), so a healthy sample takes about
    0.3–1 s.
  - Windows are `ceil(D/14)` equal slices (13.3 s for 120 s, 10 s for 30 s).
    The next size read starts at its scheduled time unless the previous
    sample overran the whole slice, which needs more than 12 s of exec
    latency. A slow exec only lengthens a window, which is INVALID (fail-safe).
  - The traffic loop writes an exit line at most every 4 + 4 + 1 s plus fork
    overhead (curl `-m 3`, subprocess timeout 4 s), so with a fault in
    progress every window gets an exit attempt. The 15 s guest-clock gap rule
    holds for the same reason.
  - Exec timeouts are 15/30/30/20 s. A timeout closes the QGA connection,
    which is INVALID, never a false PASS.
- **Admission:** host MemAvailable ≥ 1536 + 256 MiB (`run_phase.py:1924`).
  That is fine on about 4.9 GB, and both QEMUs stay at or below
  512 + 256 MiB plus overhead, which honours the one-router-plus-one-client limit.

---

## 3. Docs vs code

Every operator command in the docs is accepted by the code as written:

| Doc | Command | Code |
|---|---|---|
| `leak-lab-vm.md:87-88`, `:1000-1001` | `provision.py --client --index 1 --tailscale-tar /root/vprlab/tailscale_1.104.5_amd64.tgz` | `provision.py:1060-1117`; name defaults to `zz-vprclient-01-do-not-use` |
| `leak-lab-vm.md:97-99`, `:1014-1016` | `run_phase.py --phase client-login --client 1 --duration 900 --used-nonces …` | `run_phase.py:3860-3889` (no profile needed; ≥30 s; ≤3600 s) |
| `leak-lab-vm.md:112-115`, `:1019-1022` | `run_phase.py --phase idle --client 1 --duration 120 --index 1 --profile-file … --used-nonces …` | accepted |
| `leak-lab-vm.md:91-93` | `tailscale up --reset --hostname=zz-vprclient-01-do-not-use --shields-up --accept-routes=false` | identical to `run_phase.py:4234-4238` (but see L-1) |
| `leak-lab-vm.md:1004`, `leak-lab.md:706-707` | `netplan.py --wan-interface <wan> [--client 1] > /root/vprlab-lab.sh`; `sh … setup` / `teardown` | `netplan.py:1637-1644`, `:875-880`, `:951-955` |
| `leak-lab-vm.md:118` | admission 1536 MiB + 256 MiB | `run_phase.py:1924` |

Stale or wrong statements:

- **D-1 (Minor):** `leak-lab.md:717-720` says that with no `--client` "the
  setup/capture steps are the unchanged M2 router steps". That is false since
  decision 6. The no-client plan now has scoped `ip saddr` / `ip daddr … ct
  state` accepts and explicit drops (`netplan.py:911-917`). The binding design
  (`leak-lab-m3-clients.md:92-105`, `:391-394`) says so explicitly.
- **D-2 (Minor):** `leak-lab.md:701-703` says the vprlab0↔vprlab1 drops come
  "before the bridge-to-WAN accepts". In the generated chain, the vprlab0→WAN
  accepts (`netplan.py:911-912`) come before the whole client block
  (`:924`, `1144-1158`). The rules do not overlap, so behaviour is right, but
  the sentence describes an order that does not exist.
- **D-3 (Minor):** the generated plan header (`netplan.py:549-553`) still says
  "both DOCKER-USER rule comments" and lists only vprlab0/vprlab-tap0 ifaliases.
  The `--check-name-collisions` OK line (`netplan.py:1716`) mentions only
  10.250.0.0/24, although it also checks 10.251.0.0/24.
- **D-4 (Major in effect, small to fix):** design step 6 and
  `leak-lab-vm.md:130` ("wait until `ExitNodeStatus` names that ID, contains
  the address") encode B-1. Fix both together with the code.

---

## Recommended order for the live run

1. Fix B-1 and L-1 (and ideally P-1, P-2 and P-3). Rerun both suites, then
   refresh the root-owned tools with `hostsetup.py`.
2. Run the host steps as planned (section 1). They are safe as committed.
3. Provision the client. P-4 is optional.
4. In the Tailscale admin console, make sure no older `zz-vprclient-01-*`
   node exists before client-login. A `-1` DNS suffix is refused by
   `client_identity_problems` (`run_phase.py:2877-2878`).
5. Run client-login (with `--accept-dns=false`), then idle, then the five
   fault phases with `--client 1`.

**Verdict: READY WITH FIXES.** Host-side steps are safe to run now. As
committed, every `--client` phase is INVALID at exit-node selection (B-1), and
the client silence check is likely to fail at boot (L-1). Fix both before the
first client phase.
