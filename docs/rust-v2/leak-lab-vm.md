# Leak-lab VM (M2: silent Debian guest for the deployed legacy release)

Status: M2 tooling. Everything in `tools/leak-lab/vm/` is offline code plus a
fake-agent unit test suite. Nothing in this directory has been run against
QEMU, the tap, nftables, Docker or a network by this milestone. The controller
runs `provision.py` and `run_phase.py` later, as root on debdev.

M2 does **not** test `rust/v2`. It copies the currently deployed legacy release
from `/opt/vprouter/current` unchanged, runs its host orchestration inside a
minimal Debian 13 VM, and observes the VM's WAN frames from outside.

## Topology

```
 debdev host (trusted capture host)
 ┌────────────────────────────────────────────────────────────────────┐
 │  real WAN interface (NAT/forward from tools/leak-lab/netplan.py)    │
 │       ▲                                                             │
 │  vprlab0 bridge  10.250.0.1/24  MAC 52:54:00:76:70:01 (fixed)       │
 │       │            static neighbour 10.250.0.2 -> 52:..:02          │
 │  vprlab-tap0 (tap owned by opsec)                                   │
 │       │  tcpdump -i vprlab-tap0 ...                                 │
 └───────┼─────────────────────────────────────────────────────────────┘
         │
 ┌───────┴────────────────────────────────┐
 │ Debian 13 VM (untrusted), 1 vCPU, 512M │
 │ eth0 10.250.0.2/24, gw 10.250.0.1      │
 │ permanent neighbour 10.250.0.1 ->      │
 │   52:54:00:76:70:01 (no ARP)           │
 │ Docker: legacy vprouter host service   │
 │ router container: tailscaled + wg0     │
 │ transport container: outer WireGuard   │
 │ only allowed WAN flow: UDP to the      │
 │   profile's Mullvad endpoint           │
 └─────────────────────────────────────────┘
```

The host is the only capture point. The VM never sees `vprlab-tap0`; it sees a
virtio NIC whose MAC is fixed to `52:54:00:76:70:02` in test boots. The host
bridge and the VM use permanent neighbours in both directions, so the monitor
runs `allow_arp: false`: no ARP frame is legitimate.

### Host prerequisites M1's plan does not create

`netplan.py` (M1) creates the bridge, tap and `inet vprlab` table but does not
set a stable bridge MAC or the VM neighbour. Before phases, the controller must
also run (as root, after the M1 setup and before the first capture):

```sh
# netplan.py --tap-user opsec is required: QEMU runs as opsec.
ip link set dev vprlab0 down
ip link set dev vprlab0 address 52:54:00:76:70:01
ip link set dev vprlab0 up
ip neigh replace 10.250.0.2 dev vprlab0 \
    lladdr 52:54:00:76:70:02 nud permanent
```

`run_phase.py` also reads `/run/vprlab/owner.json` (root-owned 0600, schema 1,
token 32 lowercase hex characters) and requires both `vprlab0` and
`vprlab-tap0` to carry `ifalias` exactly `vprlab-owned:<token>` in
`ip -d -j link show`. It refuses unless `vprlab0` carries exactly
`52:54:00:76:70:01`, the tap is a real tun/tap of subtype `tap` and is
enslaved to `vprlab0`, the `inet vprlab` table exists with its ownership
comment and the four chains, and the host neighbour for `10.250.0.2` is
`PERMANENT` with the VM MAC. It also refuses if any other QEMU system process
is visible. Admission is serialised by a non-blocking `flock` on
`/run/vprlab/run.lock` (root 0600), held from before that check until the
guest has exited. Use the current `netplan.py` plan: it also installs the
scoped `DOCKER-USER` accepts that make the host's Docker `FORWARD` policy
allow the lab bridge.

## Sizing, state and base image

- `-m 512 -smp 1`, `-accel kvm -cpu host`, no swap is configured in the guest.
- qcow2 overlay of virtual size 4G on
  `/DATA/vprouter-lab/lab-images/debian-13-genericcloud-amd64-20261021-2638.qcow2`.
- Before use, the base image's SHA-512 is recomputed and must equal both the
  pinned `16e096...ba45c` and the entry in
  `SHA512SUMS-20261021-2638`; any mismatch is a hard refusal. `qemu-img
  --backing-chain` must show exactly one qcow2 layer backed by that file.
- State: `/DATA/vprouter-lab/leaklab/vm-<NNN>/`, mode `0700`, owner the
  unprivileged QEMU user (`opsec`). It is created exclusively; an existing
  state directory is refused. `leaklab/` itself must be traversable by opsec
  (0711 or 0755).
- The directory is opsec-owned because QEMU runs unprivileged and must create
  its overlay, locks, sockets and serial log there. Evidence is **not** kept
  below it: every run writes to
  `/DATA/vprouter-lab/leaklab/evidence/<phase>-<UTC>-<name>/`, created by root
  as mode 0700 and owned by root. The root `tcpdump` writes the pcap there, so
  an opsec process (or an escaped guest) cannot substitute it between capture
  and scan. The qcow2 intentionally becomes secret-bearing after the first
  phase (it contains `/etc/vprouter/<name>.conf` and the Tailscale login
  state); the state directory therefore also contains profile bytes after a
  phase, and the whole directory is destroyed when the lab node is retired.
- Staged tools:
  `/DATA/vprouter-lab/lab-tools/root/usr/bin/{qemu-system-x86_64,qemu-img,genisoimage}`
  with `LD_LIBRARY_PATH=/DATA/vprouter-lab/lab-tools/root/usr/lib/x86_64-linux-gnu`
  and `QEMU_MODULE_DIR=.../qemu`, following
  `tools/rust-v2-lab/restart-clean-debian.py`.
- QEMU argv for both modes is generated by `guest.build_qemu_argv()`. Test
  boots use `-nic none` and exactly one virtio NIC on the tap; they have no
  user netdev, seed or payload ISO.

## Two boot modes

### PROVISION (online, never on the tap)

```sh
python3 -B tools/leak-lab/vm/provision.py \
  --index 1 \
  --image-tar /root/vprouter-image.tar
```

- `-netdev user,id=wan` with no `hostfwd`; the NIC MAC is
  `52:54:00:76:70:99` so the tap-matched static network file cannot apply.
- NoCloud seed ISO (`genisoimage -V cidata`) with `user-data`/`meta-data`, and a
  second read-only payload ISO (`-V VPRLABPAYLOAD`) containing
  `release/`, `unit/vprouter@.service` and `image/vprouter-image.tar`.
- Cloud-init (`package_update/upgrade` disabled, no automatic reboot) runs one
  script that installs only:
  `docker.io docker-compose qemu-guest-agent nftables python3 iproute2
  wireguard-tools util-linux ca-certificates`, with
  `--no-install-recommends` and `APT::Install-Recommends "false"`.
  `docker-compose` is what provides the `docker compose` plugin
  `orchestrate.py` invokes.
- It also loads the `tun` and `wireguard` modules, ensures `/dev/net/tun`
  exists, loads the image tar, and verifies
  `docker image inspect --format '{{.Id}}' sha256:...` equals the expected
  digest (default: the deployed
  `sha256:62c283e6a4d350992ed2b9a99a48c7834e60e1c9af92f9e1699a2b2d0c920de3`).
- The release is copied unchanged to `/opt/vprouter/current`; the unit is
  installed at `/etc/systemd/system/vprouter@.service` and is **not** enabled.
- Debian 13's `docker-compose` package is v2; if `docker compose` is not on the
  CLI plugin path, provisioning links `/usr/bin/docker-compose` into
  `/usr/local/lib/docker/cli-plugins/` and verifies `docker compose version`
  before continuing.
- The script silences the OS, writes `VPRLAB-PROVISION-OK <image-id>` to
  `/dev/ttyS0` and `/dev/console`, and powers off. `provision.py` waits for the
  serial marker and a clean QEMU exit. On failure the state directory is kept
  for inspection and a re-run is refused.

### TEST (offline except the host tap)

- `-netdev tap,id=wan,ifname=vprlab-tap0,script=no,downscript=no`, one
  `virtio-net-pci` with MAC `52:54:00:76:70:02`; no user netdev and no seed.
- QEMU runs as `opsec` via `setpriv --reuid/--regid --clear-groups
  --no-new-privs --inh-caps=-all --bounding-set=-all` (QEMU needs the tap
  created with `netplan.py --tap-user opsec`), with
  `-sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny`,
  `-nodefaults`, `-no-user-config` and a minimal environment. `--qemu-user
  root` (or any uid 0) is refused before any process starts.
- QGA (`org.qemu.guest_agent.0`), `serial.log`, `pidfile` and `-display none`
  live in the state directory. There is deliberately **no QMP socket**: it was
  unused and would let a local opsec process attach an uncaptured NIC.
- The guest boots with `net.ifnames=0` and, by default, the netns-safe IPv6
  mode (no `ipv6.disable=1`; see the caveat below), no DHCP, no cloud-init, no
  SSH, no time sync, no DNS configuration and a static permanent neighbour for
  the gateway. `qemu-img`, `genisoimage` and every qcow2 parse run as the QEMU
  user via `setpriv`, never as root.

### IPv6 mode caveat (release constraint)

The deployed `docker-compose.yaml` sets
`net.ipv6.conf.all.forwarding: "1"` on the router service. A kernel booted with
`ipv6.disable=1` has no `/proc/sys/net/ipv6` tree, so the container runtime
cannot write that sysctl and `docker compose up` may fail; the runtime's own
`ip -6 route show default` probe can also fail closed. `provision.py`
therefore defaults to `--ipv6-mode netns-safe` (controller decision,
2026-11-09). `--ipv6-mode kernel-disable` (`ipv6.disable=1`) stays available for
releases that do not write IPv6 sysctls:

```sh
python3 -B tools/leak-lab/vm/provision.py --index 1 \
  --image-tar /root/vprouter-image.tar --ipv6-mode kernel-disable
```

`netns-safe` keeps the IPv6 sysctl tree (so the release's own compose sysctl is
writable) but writes `/etc/sysctl.d/99-vprlab-ipv6.conf` with
`net.ipv6.conf.all/default/lo.disable_ipv6=1` and `accept_ra=0`, keeps
`IPv6AcceptRA=no`/`LinkLocalAddressing=no` on the tap NIC, and keeps Docker's
`ipv6:false`. The silence check accepts either mode: with the sysctl tree it
requires `all/default.disable_ipv6=1`, without it it requires
`ipv6.disable=1` in `/proc/cmdline`; both require no `inet6` address on the WAN
NIC and any IPv6 frame on the tap is still a pcapscan finding.

## Silence list and verification

Provisioning disables **and masks**:

- `systemd-timesyncd.service`, `chrony.service`, `chronyd.service`,
  `ntp.service`, `ntpsec.service`, `openntpd.service`;
- `apt-daily.timer/service`, `apt-daily-upgrade.timer/service`,
  `unattended-upgrades.timer/service`;
- `man-db.timer`, `e2scrub_all.timer`, `e2scrub_reap.service`,
  `fstrim.timer`;
- `systemd-resolved.service` (plus a `resolved.conf.d` drop-in with
  `LLMNR=no`, `MulticastDNS=no`, `DNSStubListener=no`);
- `ssh.service`, `ssh.socket`, `sshd.service`;
- `dhclient.service`, `dhcpcd.service`, `NetworkManager*`, `networking.service`,
  `ifupdown-wait-online.service`, `ifup@.service`;
- Debian 13 cloud-init 25.x units `cloud-init-local.service`,
  `cloud-init-main.service`, `cloud-init-network.service`,
  `cloud-config.service`, `cloud-final.service`,
  `cloud-init-hotplugd.service`/`.socket` (and the compatibility
  `cloud-init.service`), plus `/etc/cloud/cloud-init.disabled`.

It also runs `swapoff -a` and comments any active swap line in `/etc/fstab`, so
the test boot has no swap. `docker.service` is enabled but restarted after the
daemon JSON is written, so the empty DNS list and IPv6 settings are applied.

It also removes cloud-init's network files (`50-cloud-init.network`,
`/etc/network/interfaces.d/50-cloud-init*`, netplan files), moves any other
`.network` file aside, writes a single MAC-matched static
`/etc/systemd/network/10-vprlab-wan.network` (`DHCP=no`,
`LinkLocalAddressing=no`, `IPv6AcceptRA=no`, `LLDP=no`, `EmitLLDP=no`,
`Address=10.250.0.2/24`, `Gateway=10.250.0.1`, `[Neighbor]
LinkLayerAddress=52:54:00:76:70:01`), replaces `/etc/resolv.conf` with a
comment-only file, and writes the exact Docker daemon JSON:

```json
{"dns":[],"ip6tables":false,"ipv6":false,"log-driver":"local"}
```

`run_phase.py` executes `guest.silence_check_script()` over QGA at the start of
every test boot (and again after a reboot). It requires `SILENCE-OK` only if
all of these hold, and refuses the phase otherwise:

- IPv6 is off: either `/proc/sys/net/ipv6` is absent with `ipv6.disable=1` in
  `/proc/cmdline` (kernel-disable), or the sysctl tree exists with
  `all/default.disable_ipv6=1` (netns-safe);
- `/proc/swaps` has no active swap;
- every unit above is `masked` or not installed and none of them is active,
  and `cloud-init.disabled` exists;
- the NIC is found by MAC, has `10.250.0.2/24`, the default route via
  `10.250.0.1`, a `PERMANENT` neighbour with the gateway MAC (queried as
  `ip -4 -o neigh show dev "$interface"`) and no `inet6` address;
- DHCP is off: the static networkd file contains `DHCP=no`, there is no
  `/run/systemd/netif/leases/<ifindex>` file, `networkctl status` shows no
  DHCP lease line, and no `dhclient`, `dhcpcd`, `udhcpc`, `dhcp6c` or
  `NetworkManager` process exists. Debian 13's systemd 257 link-state file
  does **not** contain `DHCP4_CLIENT=0`/`DHCP6_CLIENT=0`; those checks were
  removed. `networkctl` text output is not a stable API, so it is an extra
  fail-closed signal rather than the sole proof;
- `systemctl list-units 'cloud-init*' --state=active` is empty;
- `/etc/resolv.conf` has no `nameserver` line;
- `/etc/docker/daemon.json` parses exactly to the object above;
- `qemu-guest-agent` is active;
- `/etc/systemd/system/vprouter@.service` is installed, the release is
  root-owned mode 0755 with its five required files, and the router instance
  is `disabled` (or `enabled` after an intentional reboot phase).

## Control protocol

`control.py` remains the nonce generator; the VM layer imports it read-only.
Every phase reserves a fresh before/after pair with
`control.generate_pair()`, appends both nonces to `--used-nonces` (mode 0600,
single-use), and refuses an existing nonce.

Normal phase:

1. root starts `tcpdump -i vprlab-tap0 -nn -U --immediate-mode -s 0 -w ...`
   in the root-only evidence directory, with stderr redirected to the stats
   file, and waits for the pcap header;
2. QEMU test boot, QGA ready, silence check;
3. the profile and site JSON are written through QGA (`0600 root:root`);
4. BEFORE control via `guest-exec` using the exact `control.py` command,
   bound to the actual WAN device found by MAC;
5. phase action, then the requested duration;
6. AFTER control via QGA, followed **in this order** by: stop/disable the
   router and reboot units; `guest-shutdown powerdown`; wait for QEMU to exit
   (a forced SIGKILL makes the phase INVALID `forced_poweroff`); verify the
   AFTER nonce is present in the pcap (tcpdump runs with `-U
   --immediate-mode`); wait 2 s of quiet; SIGINT tcpdump and wait for its
   summary;
7. run `pcapscan.py` with the extracted policy, `--expect-tunnel` from the
   fixed phase table and both nonces; write the evidence directory; exit with
   the **final** result (0 PASS, 1 LEAK, 2 INVALID). The same order is used on
   every error path, so the capture stays alive until QEMU has exited and
   teardown traffic after AFTER is still scanned (a leak there is LEAK).

The expectation is no longer an operator choice. Every phase in this milestone
expects `up`:

| phase | expectation | proof after the action |
|---|---|---|
| `start-router` | up | unit active and a WireGuard handshake in the router netns |
| `idle`, `login` | up | router started in-window, handshake observed |
| `reboot-with-router-enabled` | up | changed boot ID, boot-control token, handshake |
| `stop-router` | up | unit is inactive |
| `kill-wireguard` | up | `wg0` is absent in the router netns |
| `kill-container` | up | the router container is not running |
| `restart-docker` | up | a new Docker daemon PID and working `docker info` |

Setup phases (`idle`, `login`, `stop-router`, `kill-wireguard`,
`kill-container`, `restart-docker`) first start `vprouter@NAME.service`
**inside the measured window** (after BEFORE), require exit 0 and a live
WireGuard handshake before the action; a failed or inactive setup aborts the
injection and makes the phase INVALID. `start-router` starts the unit as its
action. `login` additionally polls the Tailscale login URL through the
runner's own QGA connection and writes only the URL to
`<evidence>/login-url.txt` (0600) and stderr while the duration elapses.
`kill-wireguard` runs:

```sh
pid=$(docker inspect --format '{{.State.Pid}}' NAME)
nsenter -t "$pid" -n ip link del wg0
```

which is the release's own router/transport namespace model: `wg0` lives in
the `network_mode: none` router container, having been created and configured
in the transport container's namespace by `host/orchestrate.py`.

### Boot-phase control (`reboot-with-router-enabled`)

A reboot phase enables `vprouter@NAME.service`, then stages through QGA:

- `/var/lib/vprlab/boot-control.json` (mode 0600) with the nonce, a random
  32-hex boot token, sink port, VM IP and MAC. `/run` is recreated by the
  reboot this unit exists to observe, so the specification lives in persistent
  root-only state and is consumed (unlinked) on the intended boot;
- `/etc/systemd/system/vprlab-boot-control.service`, a `Type=oneshot` unit with
  `DefaultDependencies=no`, `After=systemd-networkd.service` and
  `Before=network-online.target docker.service`;
- `/usr/local/sbin/vprlab-boot-control.py` (installed at provisioning and
  refreshed before use) which finds the NIC by MAC, waits for the static
  address, sends exactly one `VPRLEAKCTL1:<nonce>` datagram with
  `SO_BINDTODEVICE`, writes the boot token to
  `/var/lib/vprlab/boot-control-sent` (0600) and unlinks the specification.

The guest is rebooted with QGA `guest-shutdown reboot`. The runner reconnects
only after `/proc/sys/kernel/random/boot_id` changes, requires the sent file to
contain the same boot token and the specification to be gone, re-runs the
silence check with the router expected `enabled`, waits for the unit to be
active and a WireGuard handshake to appear, records the Tailscale
`BackendState`, waits the duration, emits AFTER via QGA, and disables/removes
the boot-control and router units again before poweroff. The unit carries no
nonce. Because the unit runs before `docker.service` and the static neighbour
removes ARP, its datagram is the first frame of the new boot.

The initial (staging) boot of a reboot phase is also captured. Allowed
WireGuard frames from it are counted as `outside_window_allowed`; any other
frame is a finding (LEAK), and a missing/duplicated control is INVALID. It is
never silently certified.

## Secrets

- The WireGuard profile is supplied only via `--profile-fd FD` or
  `--profile-file PATH`. A file must be a root-owned regular file, mode 0600,
  not a symlink.
- The profile is read once into a `SecretMaterial` object whose `repr` is
  redacted. It is never printed, logged, hashed into a record, copied into the
  state directory or used in any argv. Only `[Peer] Endpoint` is extracted;
  the runner builds the single-flow policy from it and refuses a non-public
  address or any extra allowed flow.
- At test time the profile is written to `/etc/vprouter/<name>.conf` and the
  site JSON to `/etc/vprouter/<name>.json` through QGA. Writes go through a
  root-only 0700 staging directory, are `chmod 0600`, `chown root:root`, moved
  into place, and re-checked with `stat` (`600 root root`).
- Guest-supplied QGA error text is untrusted: it is stripped of control
  characters and truncated to 200 printable characters before it can reach an
  exception or log line. File contents written through QGA never appear in
  errors, and a timeout closes the desynchronised stream instead of reading a
  stale reply.
- The site JSON is exactly what `host/orchestrate.py` accepts:

```json
{
  "name": "zz-vprtest-01-do-not-use",
  "profile": "/etc/vprouter/zz-vprtest-01-do-not-use.conf",
  "state_dir": "/var/lib/vprouter/zz-vprtest-01-do-not-use",
  "image_ref": "sha256:62c283e6a4d350992ed2b9a99a48c7834e60e1c9af92f9e1699a2b2d0c920de3",
  "compose_dir": "/opt/vprouter/current",
  "tailscale_hostname": "zz-vprtest-01-do-not-use"
}
```

### Tailscale hostname mechanism (from the release code)

`orchestrate.py` accepts an optional `tailscale_hostname`; it defaults to
`name`. `compose_env()` exports it as `TS_HOSTNAME`, `docker-compose.yaml`
passes `TS_HOSTNAME` into the router container, and `router_runtime.py` runs:

```text
tailscale up --reset --advertise-exit-node --hostname=$TS_HOSTNAME ...
```

The VM layer therefore sets both `name` and `tailscale_hostname` to the
`tsnames.py` label. `tsnames` allows up to 63 characters, but `orchestrate.py`
only accepts `[a-z][a-z0-9-]{1,49}` (at most 50), so the shorter bound is
enforced.

Tailscale state starts empty: provisioning does not create
`/var/lib/vprouter/<name>`. The phase runner creates it `0700 root:root`; it is
the compose volume `TS_STATE_PATH` → `/var/lib/tailscale`. It persists across
phases so an approved login survives, and it is destroyed with the state
directory.

## Interactive login and exit-node approval

1. Run the `login` phase with a duration long enough for the operator to log
   in, for example:

   ```sh
   python3 -B tools/leak-lab/vm/run_phase.py \
     --phase login --duration 900 --index 1 \
     --profile-file /root/vprouter-lab.conf \
     --used-nonces /root/leaklab-used-nonces.txt
   ```

   The runner starts the router, polls the login URL through its own QGA
   connection, writes only `https://login.tailscale.com/...` to
   `<evidence>/login-url.txt` (0600) and prints it to stderr, then waits the
   duration and records the Tailscale `BackendState`.

2. `login_url.py` remains available only when **no phase is running**. A QEMU
   socket chardev serves one QGA client, so the helper takes the global run
   lock non-blockingly and refuses (exit 2) while a phase holds it:

   ```sh
   python3 -B tools/leak-lab/vm/login_url.py --index 1 --wait 300
   ```

3. In the Tailscale admin console, approve the new machine as an **exit node**
   (Machines → the test node → Edit route settings → Use as exit node). The
   release's readiness check requires `ExitNodeOption`, both advertised default
   routes (`0.0.0.0/0`, `::/0`), `NetfilterMode == 0` and a live Mullvad
   provider check (`https://am.i.mullvad.net/json`). Until then it stays
   `BLOCKED` and retries `tailscale up`, which is expected.

4. End the login phase. The login state stays in the state directory until it
   is destroyed, so later phases reuse it.

## Policy and evidence

The runner **builds** the policy itself. It reads only the `[Peer] Endpoint`
line from the profile (never decoding or logging the key), requires a public
unicast IPv4 address and port, and emits exactly one allowed flow plus the
fixed lab facts:

```json
{
  "schema_version": 1,
  "vm_wan_mac": "52:54:00:76:70:02",
  "vm_wan_ipv4": "10.250.0.2",
  "gateway_ipv4": "10.250.0.1",
  "gateway_mac": "52:54:00:76:70:01",
  "allowed": [
    {"proto": "udp", "dst_ipv4": "<profile endpoint>", "dst_port": 51820,
     "label": "profile-endpoint"}
  ],
  "allow_arp": false,
  "positive_control": {"sink_ipv4": "10.250.0.1", "sink_udp_port": 39001},
  "ipv6_allowed": false
}
```

There is no operator-supplied policy or extra endpoint. The built document is
written to `<evidence>/policy.json` (0600) and that copy - not a path re-read
later - is passed to `pcapscan.py`, which requires `gateway_mac` in all cases.
The parser is case-insensitive for `[Peer]`/`Endpoint` like the release's
`configparser` use.

Evidence per phase is under
`/DATA/vprouter-lab/leaklab/evidence/<phase>-<UTC>-<name>/`, created and
validated as root-owned 0700 (outside the opsec-owned state directory):

- `capture.pcap` (full frames, 0600), `capture.pcap.stderr` (tcpdump summary,
  0600, whose first non-empty line is the
  `tcpdump: listening on vprlab-tap0, link-type EN10MB` banner),
  `capture-argv.json` (the exact tcpdump argv, 0600; its `-w` path is exactly
  the `--pcap` path passed to pcapscan, which rejects any other difference);
- `qemu.log` (0600) - QEMU's output is opened by root here, never through a
  path in the state directory;
- `policy.json` (0600), `scan.json` (pcapscan's canonical report, 0600) and
  `login-url.txt` (0600, `login` phase only);
- `phase.json` (0600) with schema/phase/name, exact QEMU, launch, tcpdump and
  pcapscan argv, both nonces and the used-nonces path, setup/action/
  postcondition commands and exit codes, control transports, silence results,
  Tailscale backend state, timestamps, durations, base SHA-512, policy
  SHA-256, pcap/stats/scan SHA-256, the raw scanner verdict under
  `scan.verdict`, the effective `result`, and `result_reason`/`errors`. It
  never contains profile bytes or key material.

The effective result is final and unambiguous in both `phase.json` and the
single JSON line printed to stdout: `result`/`verdict` are PASS, LEAK or
INVALID; `scan_verdict` keeps pcapscan's raw verdict. Any setup, action,
postcondition, cleanup, control, capture or QEMU-exit error makes the run
INVALID, with a `result_reason` listing the failures, unless the capture
contains a finding (LEAK keeps precedence). Exit code is the effective result:
`0` PASS, `1` LEAK, `2` INVALID (also used for a refusal before a scan and for
any unexpected exception; a crash is never reported as LEAK).

## Naming

`tsnames.py` generates `zz-vprtest-NN-do-not-use[-suffix]` (`NN` 01..99).
`run_phase.py` refuses any name that is not a `tsnames.is_test_node()` label,
and `host/orchestrate.py` independently enforces at most 50 characters. Use a
new number for each throw-away node; never point this at a production tailnet
name.

## Limits and assumptions

- This proves the **deployed legacy release** in a VM, not `rust/v2`. The VM's
  OS is deliberately stricter than production (no DHCP, SSH, DNS, NTP,
  cloud-init, ARP), so a PASS here is not a production claim.
- The deployed compose writes an IPv6 forwarding sysctl, which is incompatible
  with `ipv6.disable=1`; see the IPv6 mode caveat above. This is the one
  release constraint that may require `--ipv6-mode netns-safe`. It should be
  resolved before treating a `start-router` failure as a leak finding.
- The capture sees only frames that reach the host tap inside the window. The
  VM can stay silent, and a silent VM is not distinguished from a clean one.
  The positive controls only prove the monitor was working.
- The monitor sees the outer WireGuard UDP tuple, not the tunnel contents, and
  it does not authenticate WireGuard or prove a working tunnel.
- Container DNS: the guest has no nameserver. The deployed
  `docker-compose.yaml` sets `dns: [9.9.9.9]` on the router, so Docker's
  `8.8.8.8`/`8.8.4.4` fallback is not the expected path. Traffic to the
  compose-supplied resolver must stay inside `wg0`; if it ever appears on the
  tap it is a finding. If the release's Mullvad probe stays `BLOCKED`, there is
  no leak but no login either.
- The image tar is not in the repository; the controller must produce it (for
  example with `docker save`) from the deployed image ID and pass its path.
- `docker compose` must be present as a `docker` CLI plugin; Debian 13's
  `docker-compose` package is expected to provide it. Provisioning fails
  explicitly if not.
- 4G virtual disk must hold Debian + `docker.io` + the image + Docker state.
  Monitor free space and destroy/reprovision the state directory rather than
  growing it silently.
- QEMU cannot attach the tap as `opsec` unless it was created with
  `netplan.py --tap-user opsec`. The preflight cannot see the tun owner through
  `ip -j`; a QEMU permission failure is the backstop.
- The state directory (including the qcow2, which contains the lab profile
  after the first phase and the Tailscale login state) is a secret-bearing
  artifact. It is opsec-owned 0700 so unprivileged QEMU can use it. Evidence
  lives separately under root-owned
  `/DATA/vprouter-lab/leaklab/evidence/`. Delete the whole state directory when
  the lab node is retired. Target-scoped evidence remains until the controller
  removes it.
- Provisioning leaves `payload/`, `payload.iso` and `seed.iso` in the state
  directory after a successful run (roughly the release plus image-tar size).
  This is intentional for inspection; the state directory already holds the
  image and is destroyed/reprovisioned as a unit. `provision.json` and
  `qemu.log` are also there.
- `poweroff_vm` waits 180 s for QEMU, above the release unit's
  `TimeoutStopSec=120s`; a forced SIGKILL still makes the phase INVALID
  (`forced_poweroff`).
- `install_guest_file` stages in a 0700 root-only directory and moves into
  place; the move from tmpfs `/run` to `/etc` may be a copy+unlink, so "atomic"
  is not guaranteed across filesystems.
- The staging boot of a reboot phase is captured. Allowed WireGuard frames
  outside the control window are counted as `outside_window_allowed`; any
  other frame is a finding, so the phase still cannot silently PASS.
- `--tap`/`--bridge` are fixed to `vprlab-tap0`/`vprlab0`; pcapscan's argv and
  stats banner are bound to those names, so an override is refused rather than
  producing a late `capture_argv_mismatch`.
- `ControllerDecisionTests` previously ran after the `__main__` guard; the
  behavioural runner suite now runs under discovery and when the file is run
  directly.
- The guest clock has no NTP. It starts from the host RTC; verify it is sane
  before relying on TLS and WireGuard timestamps.

## Commands

```sh
# once, online (root, debdev); refuses an existing state directory
python3 -B tools/leak-lab/vm/provision.py --index 1 \
  --image-tar /root/vprouter-image.tar

# a phase (root, debdev); the capture stays alive until the guest exits
python3 -B tools/leak-lab/vm/run_phase.py \
  --phase start-router --duration 120 --index 1 \
  --profile-file /root/vprouter-lab.conf \
  --used-nonces /root/leaklab-used-nonces.txt

# offline tests
python3 -B -W error -m unittest discover -s tools/leak-lab/vm -p 'test_*.py' -v
```

The suite has 96 tests. It executes the real phase runner and provision
helpers with fake process/QGA/scanner layers, plus a fake unix-socket guest
agent; it never runs QEMU, tcpdump, ip, nft, docker, qemu-img, genisoimage or a
network command.

## What the release code required (findings)

`/opt/vprouter/current` is a two-container host service, not just an image:

- `host/orchestrate.py` must run as root on the guest and uses
  `docker compose`, `nft`, `ip`, `nsenter`, `unshare`, `wg`, Python 3 stdlib,
  and the pinned image; it requires a root-owned 0600 WireGuard profile, a
  0600 site JSON whose stem equals `name`, a 0700 state dir, and the release
  directory not group/world writable.
- `docker-compose.yaml` runs the router container with `network_mode: none`,
  `read_only`, only `NET_ADMIN/NET_BIND_SERVICE/SETUID/SETGID`, `/dev/net/tun`,
  and a Tailscale state volume; the transport container sleeps on a dedicated
  Docker bridge (`10.255.240.0/29`). Hence `tun`, `wireguard` and
  `/dev/net/tun` must exist in the guest, and the outer UDP leaves through the
  transport container's namespace.
- `router_runtime.py` starts `tailscaled --statedir=/var/lib/tailscale`, uses
  `TS_HOSTNAME` for `tailscale up --advertise-exit-node`, requires a live
  Mullvad provider response before advertising, and requires exit-node
  approval plus `NetfilterMode=0` before reporting `READY`.
- The WireGuard interface is created with `ip link add wg0 type wireguard`,
  configured with `wg setconf`, moved from the transport namespace into the
  router namespace, addressed from the profile, and made the router's default
  route. Killing it from the router namespace is therefore
  `nsenter -t <router-pid> -n ip link del wg0`.
- Provisioning does not enable `vprouter@.service`. The paths that start it
  are `start-router` (action), `idle` and `login` (setup), the four failure
  phases (setup), and the enabled unit at boot for
  `reboot-with-router-enabled`.
