# Leak-lab VM (M2: silent Debian guest for the deployed legacy release)

Status: M2 + M3 tooling. Everything in `tools/leak-lab/vm/` is offline code
plus a fake-agent unit test suite. Nothing in this directory has been run
against QEMU, the tap, nftables, Docker or a network by this milestone. The
controller runs `provision.py` and `run_phase.py` later, as root on debdev.

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
 │  vprlab-tap0 (tap owned by vprlab-qemu)                            │
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

## M3: real client traffic through the test exit node

M3 adds one real Tailscale client VM that sends traffic through the router's
test exit node while the existing router fault phases run.  The client has its
own bridge; it never shares `vprlab0` and never advertises an exit node or
routes.

```
 debdev host
 ┌────────────────────────────────────────────────────────────────────┐
 │ vprlab1  10.251.0.1/24  MAC 52:54:00:76:71:01                     │
 │    │      explicit nft drop to/from vprlab0 in both directions      │
 │ vprlab-ctap1 (tap owned by vprlab-qemu)                            │
 │    │  tcpdump -i vprlab-ctap1 ...                                  │
 └────┼───────────────────────────────────────────────────────────────┘
      │
 ┌────┴───────────────────────────────┐
 │ client VM (untrusted), 256M 1 vCPU │
 │ eth0 10.251.0.2/24, gw 10.251.0.1  │
 │ tailscaled + pinned tailscale      │
 │ /usr/local/sbin/vprlab-client-     │
 │   traffic (HTTPS exit + HTTP       │
 │   marker probes)                   │
 └────────────────────────────────────┘
```

Fixed client facts: tap `vprlab-ctapN`, address `10.251.0.(N+1)`, MAC
`52:54:00:76:71:(N+1, two hex digits)`, provisioning MAC
`52:54:00:76:71:99`, state `/var/lib/vprlab/client-NNN`, qcow2 overlay
`2G`, test boot 256 MiB, provisioning boot 384 MiB.  `N` is 1..9; the client
name is exactly `zz-vprclient-NN-do-not-use` (no suffix).

### Client provisioning and login

Provisioning reuses the router's online cloud-init path but installs no Docker
and no release.  It installs the pinned static tarball (sha256
`720cbbcc...ad7bf7`) to `/usr/local/sbin`, enables a `tailscaled.service` with
`--state=/var/lib/tailscale/tailscaled.state --port=41641`, writes the
MAC-matched static networkd file, masks the router's silence list, and writes
`/usr/local/sbin/vprlab-client-traffic`:

```sh
# once, online (root, debdev).  The tarball hash is verified on the host
# before it is staged on the payload ISO; a wrong hash is a hard refusal.
python3 -B tools/leak-lab/vm/provision.py --client --index 1 \
  --tailscale-tar /root/vprlab/tailscale_1.104.5_amd64.tgz
```

Interactive login boots only the client VM, runs
`tailscale up --reset --hostname=zz-vprclient-01-do-not-use --shields-up
--accept-routes=false`, prints the fixed-shape login URL, and passes only when
`BackendState == Running` at the end:

```sh
python3 -B tools/leak-lab/vm/run_phase.py \
  --phase client-login --client 1 --duration 900 \
  --used-nonces /root/leaklab-used-nonces.txt
```

Approve the client machine in the Tailscale admin console like any other
machine.  The client is **not** an exit node; do not approve it as one.

### Running a phase with a client

`run_phase.py --client N` accepts every phase except `login` (`login` with
`--client` is refused; use `client-login`).  `--client N` boots the client
first and the router second:

```sh
python3 -B tools/leak-lab/vm/run_phase.py \
  --phase idle --client 1 --duration 120 --index 1 \
  --profile-file /root/vprouter-lab.conf \
  --used-nonces /root/leaklab-used-nonces.txt
```

Flow: admission (`MemAvailable` must cover 1536 MiB + the client's 256 MiB;
the measured value is recorded); start both captures (`vprlab-tap0` unchanged
and `vprlab-ctap1` with the same flags); boot the client; run
`tailscale set --exit-node=`; send the client before-control
(`VPRLEAKCTL1:<nonce>`) to `10.251.0.1:39001`; require the client to be
Running with its fixed name and no advertised exit node; boot the router and
make it READY; select the router peer by HostName `zz-vprtest-01-do-not-use`,
`ExitNodeOption: true`, online; `tailscale set --exit-node=<peer IPv4>
--exit-node-allow-lan-access=false`; wait until the client reports it active;
start the transient traffic unit and require a pre-fault Mullvad success
within 90 s (`client_not_routed` otherwise); hold for `--duration`; stop the
unit; clear the exit node; send the client after-control; send the router
after-control; shut both VMs down and stop both captures only after both QEMUs
exited; then scan.

For every accepted phase the router is made READY before the fault, including
`start-router` (whose action is then an idempotent `systemctl start`), because
a pre-fault client success is only possible with a working exit node.
`reboot-with-router-enabled` uses the same boot-control unit and before-nonce
transport as M2.

### Client evidence and verdict

The evidence directory gains `client-capture.pcap`,
`client-capture.pcap.stderr`, `client-capture-argv.json`,
`client-probe.jsonl` and `client-scan.json`; `phase.json` gains a `client`
object with the index/name/memory/tap/nonces, resolved probe IPs, probe
counts, exit-node booleans, the client scan/probe verdicts and the combined
result.  The client's own Tailscale state, auth keys, login URL (beyond
`login-url.txt`) and any non-Mullvad IP are never recorded; the exit probe
keeps only `mullvad_exit_ip` and at most the first 12 hex of the reported IP's
SHA-256.

`clientscan.py` (invoked by the runner through the retained evidence fd) checks
only what is provable on the client path:

- client tcpdump stats: exact banner for `vprlab-ctapN`, zero drops,
  `captured == received`, final count equals the record count, and the exact
  client capture argv;
- exactly one client before-control and one after-control in the client pcap,
  in order (missing/reordered is INVALID, a replay is LEAK);
- the per-phase plaintext marker `VPRCLIENTMARK1:<32 hex>` in no frame of the
  client **or** router capture (raw bytes of every record; a split marker is
  out of scope).  One clear occurrence is LEAK `marker_in_clear`.

`clientprobe.py` parses `client-probe.jsonl` strictly (exact key sets, no
duplicate keys, bounded 1 MiB/4 KiB lines).  Verdict: any successful exit
probe with `m` not `true` (including `null`) is LEAK; no pre-fault Mullvad
success is INVALID `client_not_routed`; failures after the fault are expected
and counted only.  The final phase result is the worst of the router scan, the
client scan, the probe verdict and runner errors: LEAK > INVALID > PASS.

### Host layout: the M1 plan plus hostsetup

The classic layout is root-owned and does not use `/DATA/vprouter-lab` at
runtime.  Run the plan-only generator once as root; it prints a reviewed
`#!/bin/sh` script (it never executes anything itself):

```sh
python3 -B tools/leak-lab/vm/hostsetup.py > /root/vprlab-hostsetup.sh
sh -n /root/vprlab-hostsetup.sh
sh /root/vprlab-hostsetup.sh          # creates the account, tools, images
sh /root/vprlab-hostsetup.sh teardown # exact removal, refuses while a phase runs
```

The script creates:

- `vprlab-qemu`, a system account with no login shell and no home, member of
  `kvm` only (`hostsetup.py --check` refuses uid 0 or any other group);
- `/opt/vprlab-tools` (root:root 0755) with the complete staged QEMU tools,
  library/module trees and confined relative symlinks (for example
  `libslirp.so.0 -> libslirp.so.0.4.0`), copied from
  `/DATA/vprouter-lab/lab-tools/root`.  Every source leaf is opened
  `O_NOFOLLOW`, the exact bytes written are hashed, and both `SHA256SUMS`
  (regular files) and `SYMLINKS.json` (link path and target) are verified
  after the copy.  Every link is additionally resolved with `realpath`
  against the source and destination roots: a chain that resolves outside the
  tree is refused even when its lexical path stays inside.  A hardlinked
  source file is copied as independent content, so the destination has no
  hardlink relationship to the source (or to its other links); `verify_tree`
  also refuses destination entries that neither manifest lists.  The manifest
  is copy-fidelity evidence, not a pinned upstream provenance list; only the
  base image has a pinned digest.  After
  the copy, every direct `DT_NEEDED` of `qemu-system-x86_64`, `qemu-img` and
  `genisoimage` must be present in the copied library directory or be one of
  the fixed host base libraries (`libc.so.6`, `libm.so.6`,
  `ld-linux-x86-64.so.2`, `libpthread.so.0`, `libdl.so.2`, `librt.so.1`,
  `libresolv.so.2`).  The check uses a small in-tree ELF dynamic-section
  reader, not `readelf`;
- `/opt/vprlab-tools/leaklab` (root:root, files 0644) with the runtime copy of
  `clientprobe.py`, `clientscan.py`, `control.py`, `netplan.py`, `pcapscan.py`,
  `policy.py`, `tsnames.py` and the `vm/*.py` modules plus their `SHA256SUMS`
  manifest.  `run_phase.py` executes the scanner from this root-owned copy after
  verifying its manifest, and
  compares **every manifest-listed file** (the scanner and all modules it can
  import) byte-for-byte with the repository copy.  If any file differs it
  refuses unless the explicit `--allow-repo-scanner` developer override is
  given.  `phase.json` records `scanner.path`, `scanner.source`
  (`installed`/`repo_override`), `scanner.certifiable` and, for the installed
  copy, `scanner.manifest_sha256`; the override is explicitly
  `certifiable: false`;
- `/var/lib/vprlab/images` (root 0755, files copied 0600 and made 0644 only
  after the pinned digest and the full `SHA512SUMS`/`SYMLINKS.json` manifest
  verify) with the base image;
- `/var/lib/vprlab` itself (root 0755), `/var/lib/vprlab/evidence` (root 0700)
  and `/run/vprlab` (root 0700).  The plan deliberately **does not** create
  `vm-NNN`: `provision.py` creates each state directory exclusively and then
  chowns it to the QEMU user.  `--check` accepts its absence before
  provisioning and requires QEMU ownership/0700 whenever it is present.

`hostsetup.py --check --stat-json STAT.json --groups-json GROUPS.json`
validates a supplied inventory instead of trusting the live host: every
ancestor must be root-owned and not group/other writable, and the account must
have exactly its own primary group plus `kvm`.

M1's plan now sets the fixed bridge MAC and the static host neighbour itself,
so the operator must not change either by hand.  `netplan.py` defaults to
`--tap-user vprlab-qemu`; keep that default.  Use the setup-only mode so the
plan does not run its own foreground capture:

```sh
python3 -B tools/leak-lab/netplan.py --wan-interface <wan> > /root/vprlab-lab.sh
sh /root/vprlab-lab.sh setup   # leaves the reviewed network running
# ... one or more run_phase.py phases ...
sh /root/vprlab-lab.sh teardown
```

Teardown refuses (nonzero, no changes) while `/run/vprlab/run.lock` is held by
a phase, and it treats a failed link/neighbour inventory as **not proof of
absence**: it keeps the DROP table and Docker accepts installed until a
complete inventory proves the object absent or isolation is read back.  Both
the M1 teardown and `hostsetup.py teardown` acquire the lock and **hold it for
the whole teardown**, and setup takes the same lock/QEMU guard before it
replaces any tool file.  A missing `pgrep` is a refusal, not a skipped check.
`hostsetup.py teardown` deliberately retains
`/var/lib/vprlab/evidence` as the audit record; remove it by hand only after
reviewing it.

Debian's `tcpdump` starts as root, opens the savefile, and then drops to the
`tcpdump` user; the enforced AppArmor profile only permits savefiles matching
`/**.pcap` (and similar patterns).  The generated capture name therefore always
ends in `.pcap`.

`run_phase.py` reads `/run/vprlab/owner.json` (root 0600, schema 1, token 32
lowercase hex characters) and requires both `vprlab0` and `vprlab-tap0` to
carry `ifalias` exactly `vprlab-owned:<token>` in `ip -d -j link show`.  The
`inet vprlab` table comment must be the same per-run tag (the old fixed
`vprlab-leak-lab-m1` string authorizes nothing).  It refuses unless `vprlab0`
carries exactly `52:54:00:76:70:01`, the tap is a real tun/tap of subtype
`tap` (and its reported owner matches the QEMU account when iproute2 exposes
it), is enslaved to `vprlab0`, the four chains exist, and the host neighbour
for `10.250.0.2` is `PERMANENT` with the VM MAC.  Admission is serialised by a
non-blocking `flock` on `/run/vprlab/run.lock` (root 0600), held from before
that check until the guest has exited.  Use the current `netplan.py` plan: it
also installs the scoped `DOCKER-USER` accepts that make the host's Docker
`FORWARD` policy allow the lab bridge.

### Root path and evidence boundary

Evidence is created beneath `/var/lib/vprlab/evidence/<phase>-<UTC>-<name>/`.
Every component from `/` down is validated as root-owned and not group/other
writable, each directory is opened with `O_DIRECTORY|O_NOFOLLOW`, and every
evidence file is created with a `dir_fd`-relative
`O_NOFOLLOW|O_CREAT|O_EXCL` open.  The pcap, stats, policy and capture-argv
files are passed to the scanner as `/proc/self/fd/<run-dir-fd>/<name>` paths,
so renaming the evidence directory after the check cannot redirect a read or
write.  Evidence hashes are always SHA-256 over the exact file bytes the
runner and scanner read: `capture_argv_sha256` covers the byte-for-byte
`capture-argv.json` (indented JSON plus its trailing newline), while the
separate `capture_argv_canonical_sha256` field covers the compact re-encoding
used only for semantic comparison.  `phase.json` also records
`tcpdump_argv_display`/`pcapscan_argv_display` with the fd paths resolved to
the display path, so a reviewer can replay the commands by name; the hashes
still bind the original fd-anchored evidence.

## Sizing, state and base image

- `-m 512 -smp 1`, `-accel kvm -cpu host`, no swap is configured in the guest.
- qcow2 overlay of virtual size 4G on
  `/var/lib/vprlab/images/debian-13-genericcloud-amd64-20261021-2638.qcow2`
  (installed by `hostsetup.py`).  Nothing under `/DATA/vprouter-lab` is used at
  runtime.
- Before use, the base image's SHA-512 is recomputed and must equal both the
  pinned `16e096...ba45c` and the entry in `SHA512SUMS`; any mismatch is a hard
  refusal. `qemu-img --backing-chain` must show exactly one qcow2 layer backed
  by that file.
- State: `/var/lib/vprlab/vm-<NNN>/`, mode `0700`, owner the dedicated
  unprivileged QEMU user (`vprlab-qemu`). `hostsetup.py` creates only the
  trusted parent; `provision.py` creates the state directory exclusively,
  refuses an existing path, and then chowns it to the QEMU user.
  `/var/lib/vprlab` itself is root-owned 0755 and is checked all the way to
  `/` before use.
- The state directory is QEMU-owned because QEMU creates its overlay and
  sockets there (and, during provisioning only, the diagnostic serial log). Evidence is **not** kept below it: every run
  writes to `/var/lib/vprlab/evidence/<phase>-<UTC>-<name>/`, created by root
  as mode 0700 and owned by root through descriptor-anchored opens.  The
  `tcpdump` process starts as root, opens the savefile (name ending `.pcap`),
  then drops to the `tcpdump` user; it writes through the retained directory
  fd, so an escaped guest cannot substitute the pcap between capture and scan
  by renaming an operator-owned ancestor. The qcow2
  intentionally becomes secret-bearing after the first phase (it contains
  `/etc/vprouter/<name>.conf` and the Tailscale login state); the state
  directory therefore also contains profile bytes after a phase, and the whole
  directory is destroyed when the lab node is retired.
- Staged tools live under `/opt/vprlab-tools`: the QEMU/QEMU-img/genisoimage
  binaries in `usr/bin` plus their library and `qemu` module trees in
  `usr/lib/x86_64-linux-gnu`.  The staged loader variables are applied only
  **after** the privilege drop, by
  `/usr/bin/env -i LD_LIBRARY_PATH=... QEMU_MODULE_DIR=... <tool>` after
  `setpriv --`; the trusted `setpriv` itself always runs with a clean
  environment and every ancestor of `/opt/vprlab-tools` is validated as
  root-owned.
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
- QEMU runs as `vprlab-qemu` via `/usr/bin/setpriv --reuid/--regid
  --init-groups --no-new-privs --inh-caps=-all --bounding-set=-all --` (QEMU
  needs the tap created with `netplan.py --tap-user vprlab-qemu`, whose owner
  must be the same account), with
  `-sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny`,
  `-nodefaults`, `-no-user-config` and a loader-clean outer environment.
  `--qemu-user root`, uid 0, or an account in sudo/wheel/adm/docker/lxd/
  libvirt/disk (or any group other than its own primary and `kvm`) is refused
  before any process starts.
- QGA (`org.qemu.guest_agent.0`), `pidfile` and `-display none` live in the
  state directory.  Provisioning also writes `serial.log` there; test boots
  use `-serial none` and write no serial file. There is deliberately **no QMP socket**: it was
  unused and would let a local host process attach an uncaptured NIC.
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

1. root starts `tcpdump -i vprlab-tap0 -nn -U --immediate-mode -B 8192 -s 0 -w ...`
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
expects `up`.  Readiness is now a precondition, not a recorded field:

| phase | expectation | pre-window readiness | proof after the action |
|---|---|---|---|
| `start-router` | up | unit active + fresh handshake (pre-login allowed) | unit active + fresh handshake |
| `idle`, `stop-router`, `kill-wireguard`, `kill-container`, `restart-docker` | up | release `orchestrate.py status` READY, `BackendState=Running`, exit node advertised, fresh handshake | unit/container/wg0/daemon effect below |
| `login` | up | unit active + fresh handshake | `BackendState=Running` at the end |
| `reboot-with-router-enabled` | up | after reboot: READY + Running + exit node + fresh handshake | changed boot ID + boot-control token |

"A fresh handshake" means `wg show wg0 latest-handshakes` inside the router
netns reports an age below 180 s using the guest's own clock.  "Exit node
advertised" means `tailscale status --json` has `Self.ExitNodeOption: true` or
`0.0.0.0/0` in `Self.AdvertisedRoutes`.  `phase.json` records
`certifies: "server_side_no_client_traffic"` for router-only phases: these
phases certify the server-side window and capture, not client traffic through
the exit node.  M3 phases run with `--client N` and record
`certifies: "client_traffic_through_test_exit_node"`; the docs must not read an
M2 PASS as client-path certification.

Setup phases (`idle`, `login`, `stop-router`, `kill-wireguard`,
`kill-container`, `restart-docker`) first start `vprouter@NAME.service`
**inside the measured window** (after BEFORE), require exit 0 and the
readiness above before the action; a failed or inactive setup aborts the
injection and makes the phase INVALID. `start-router` starts the unit as its
action. `login` additionally polls the Tailscale login URL through the
runner's own QGA connection and writes only the URL to
`<evidence>/login-url.txt` (0600) and stderr while the duration elapses; it
PASSes only if `BackendState` is `Running` when the window ends. `kill-wireguard`
runs:

```sh
pid=$(docker inspect --format '{{.State.Pid}}' NAME)
nsenter -t "$pid" -n ip link del wg0
```

and proves the effect within one second: `wg0` is absent, its ifindex changed,
or the router container stopped (the release's monitor may stop it first).  A
later recovery is recorded, never required, so the check cannot flake.  The
namespace model is the release's own: `wg0` lives in the `network_mode: none`
router container, having been created and configured in the transport
container's namespace by `host/orchestrate.py`.

`restart-docker` must also show a new Docker daemon PID, working `docker info`
and the release's READY status with a running exit node again after the
restart.  `kill-wireguard` and `kill-container` record recovery but do not
require it.

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
  redacted. It is never printed, logged, hashed into a record, or used in any
  argv. Only `[Peer] Endpoint` is extracted; the runner builds the single-flow
  policy from it and refuses a non-public address or any extra allowed flow.
  At test time it is written into the guest, so the qcow2 becomes a
  secret-bearing artifact (documented under Limits); it is never staged as a
  separate file in the state directory.
- At test time the profile is written to `/etc/vprouter/<name>.conf` and the
  site JSON to `/etc/vprouter/<name>.json` through QGA. Writes go through a
  root-only 0700 staging directory, are `chmod 0600`, `chown root:root`, moved
  into place, and re-checked with `stat` (`600 root root`).
- Guest-supplied QGA error text is untrusted and is **never rendered**. A
  known QGA class from a local allowlist (`GenericError`, `CommandNotFound`,
  `CommandDisabled`, `InvalidParameter`, `DeviceNotActive`, ...) is named;
  anything else becomes `guest_error`, and the guest's `desc` is discarded
  unread. Chained exceptions keep only the local method name and that class.
  A 44-character WireGuard key fits inside any printable/length bound, so
  truncation is not a secrecy control. File contents written through QGA never
  appear in errors, and a timeout closes the desynchronised stream instead of
  reading a stale reply.
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
   connection, writes the URL to `<evidence>/login-url.txt` (0600) and prints
   it to stderr, then waits the duration and records the Tailscale
   `BackendState`.  Only the fixed shape
   `https://login.tailscale.com/a/[0-9a-f]{8,16}` is accepted (the length is
   recorded); any other `login.tailscale.com` candidate is not written and is
   recorded as `login_url_unrecognized`, making the phase INVALID.  This stops
   a guest from using the URL path as an arbitrary secret-encoding channel.
   `login_url.py` applies the same pattern.

2. `login_url.py` remains available only when **no phase is running**. A QEMU
   socket chardev serves one QGA client, so the helper takes and **holds** the
   global run lock across the connection and poll, refusing (exit 2) while a
   phase holds it.  It therefore cannot race a phase between the check and the
   connect, and a phase cannot start until the helper exits:

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
The parser is case-insensitive for `[Peer]` and accepts an `Endpoint` line with
either `=` or `:` as the key separator, matching the release's common
`configparser` use.  Duplicate/odd forms are not guessed at: only the last
`Endpoint` value is used, and an invalid value refuses the phase.

Evidence per phase is under
`/var/lib/vprlab/evidence/<phase>-<UTC>-<name>/`, created through a
descriptor-anchored root walk (every ancestor root-owned, not group/other
writable, no symlink) and opened `O_DIRECTORY|O_NOFOLLOW`; every file is created
`dir_fd`-relative with `O_NOFOLLOW|O_EXCL`:

- `capture.pcap` (full frames, 0600), `capture.pcap.stderr` (tcpdump summary,
  0600, whose first non-empty line is the
  `tcpdump: listening on vprlab-tap0, link-type EN10MB` banner),
  `capture-argv.json` (the exact tcpdump argv, 0600; its `-w` path traverses
  the retained run-directory fd and is exactly the `--pcap` path passed to
  pcapscan, which rejects any other difference);
- `qemu.log` (0600) - QEMU's output is opened relative to the run-directory fd,
  never through a path in the state directory;
- `policy.json` (0600), `scan.json` (pcapscan's canonical report, 0600) and
  `login-url.txt` (0600, `login` phase only);
- `phase.json` (0600) with schema/phase/name, the `certifies` statement, exact
  QEMU, launch, tcpdump and pcapscan argv, both nonces and the used-nonces
  path, setup/action/postcondition commands and exit codes, control transports,
  silence results, Tailscale backend state, recovery, timestamps, durations,
  base SHA-512, policy SHA-256, pcap/stats/argv/scan SHA-256, the raw scanner
  verdict under `scan.verdict`, the effective `result`, and
  `result_reason`/`errors`. It never contains profile bytes or key material.
  Guest-supplied strings pass through fixed vocabularies before they reach the
  record: `tailscale.backend_state` is one of `NoState`, `NeedsLogin`,
  `NeedsMachineAuth`, `Stopped`, `Starting`, `Running` or `unrecognized`;
  boot IDs are strict UUIDs, the WAN device is an interface-name regex, and
  Docker PIDs are decimal digits.  No raw unit/docker/version string is
  recorded.

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
- QEMU cannot attach the tap unless it was created for `vprlab-qemu` with
  `netplan.py --tap-user vprlab-qemu`.  When iproute2 reports
  `linkinfo.info_data.user`, preflight also requires it to equal the QEMU
  account; absence of the field is not treated as a wrong owner, and QEMU's
  attach failure remains the backstop.
- The state directory (including the qcow2, which contains the lab profile
  after the first phase and the Tailscale login state) is a secret-bearing
  artifact. It is QEMU-owned 0700 so unprivileged QEMU can use it. Evidence
  lives separately under root-owned `/var/lib/vprlab/evidence/`, anchored to a
  retained run-directory fd. Delete the whole state directory when the lab
  node is retired. Target-scoped evidence remains until the controller removes
  it.
- Provisioning leaves `payload/`, `payload.iso` and `seed.iso` in the state
  directory after a successful run (roughly the release plus image-tar size).
  This is intentional for inspection; the state directory already holds the
  image and is destroyed/reprovisioned as a unit. `provision.json` and
  `qemu.log` are also there.
- `poweroff_vm` waits 180 s for QEMU, above the release unit's
  `TimeoutStopSec=120s`.  A timeout, exception or termination signal during
  the wait falls back to SIGKILL of the pid from our own `Popen` handle.  The
  identity check reads `/proc/<pid>/exe` (which must resolve to
  `/opt/vprlab-tools/usr/bin/qemu-system-x86_64`) and matches argv[0] in
  `/proc/<pid>/cmdline`; the QEMU-owned `qemu.pid` is not trusted or needed.
  If the process still survives, `vprlab-tap0` is brought down and the global
  run lock is not released while our QEMU is alive.  A forced SIGKILL still
  makes the phase INVALID (`forced_poweroff`).  `provision.py` installs
  SIGTERM/SIGHUP/SIGINT handlers that route into terminate+reap of its QEMU
  child; a second signal during the reaper is ignored so the cleanup cannot be
  escaped.
- Resource bounds: phase duration is at most 3600 s; admission refuses below
  1536 MiB `MemAvailable`, below the capture cap plus 1 GiB free on the
  evidence filesystem, or below the 4 GiB overlay virtual size plus 1 GiB
  headroom on the **state** filesystem.  The default capture cap is 2 GiB
  (`--capture-size-cap`).  A watcher thread enforces the cap and the 1 GiB
  free-disk floor for the **whole** capture lifetime - from before tcpdump
  starts through setup, readiness, action, duration, teardown and the poweroff
  wait.  It also polls tcpdump itself: if tcpdump exits before the normal
  SIGINT stop, the phase records `capture_ended_early` (with the observed
  time) and is INVALID.  On a `capture_size_cap` or `capture_disk_low` breach
  it brings the tap down **and** SIGKILLs our verified QEMU pid, then the
  ordered cleanup continues; it still scans whatever was written, and any
  finding in that capture is still LEAK.
  - Test boots write **no serial file** (`-serial none`); only provisioning
    writes `serial.log`, which is capped at 64 MiB in provision (`kill QEMU`
    and fail).  The provisioning process and its QEMU child both run under
    `RLIMIT_FSIZE` 8 GiB, so its staging copies are bounded too.  Test QEMU
    runs under `RLIMIT_FSIZE` 6 GiB (4 GiB overlay plus headroom), so the
    guest's own disk writes are bounded even when the tap is already down.
  - The 2 GiB runner `RLIMIT_AS` applies only to the Python runner: each
    spawned tcpdump/QEMU child has `RLIMIT_AS` reset to infinity with
    `prlimit`, and every QEMU child also gets the file-size bound.  The
    scanner runs under its own `RLIMIT_AS` 1 GiB through a trusted
    `python -c` wrapper (`setrlimit` then `execv`), not `preexec_fn`, so it is
    safe while the capture-guard thread exists.
  - `pcapscan` streams records from the file, retains only counters, at most
    1000 outside-window indexes (plus the total) and at most 4096 unfinished
    fragment associations; overflow is `fragment_table_overflow` and INVALID.
    A single QGA reply is capped at 16 MiB and one `guest-exec` output stream
    at 4 MiB (`reply_too_large` / `exec_output_too_large`), closing the
    stream; the buffer search keeps an unterminated `0xFF` sync marker while
    it waits for the rest of the frame.  A scanner crash or a missing/invalid
    report is INVALID, never LEAK; only a parseable report whose verdict is
    LEAK produces LEAK.
- Signal model: SIGTERM/SIGINT/SIGHUP handlers only set a flag and remember
  the signal; they never raise and no signal is blocked in any thread.
  Every blocking wait/loop calls `check_interrupt()`, which raises into the
  single ordered `finally` cleanup on the first observation.  Children
  therefore inherit an empty signal mask and default dispositions (SigBlk is
  0), and the Popen handle is assigned before any checkpoint, so a signal
  during spawn cannot orphan tcpdump or QEMU.  The capture-guard thread is
  started only after the handlers are installed, so a process-directed signal
  cannot be handled by a thread that bypasses the cleanup.  The first
  checkpoint raises only once; subsequent signals during cleanup are ignored
  so the reaper/poweroff/scan path cannot be escaped.  Teardown still stops
  tcpdump with SIGINT after QEMU has exited and the after-control has reached
  the pcap; the liveness check above proves the capture was still alive at
  that point.

  **Skipped Minors (with reasons, this round):**
  - M1's foreground/manual capture still defaults under `/run/vprlab`; the M2
    phases never start it and the lab command is `setup`, so the documented
    path is unaffected.  Revisit before using the M1 capture mode on a host
    where `/run` is small (opus S-4).
  - `qemu_process_is_ours` still reads QEMU-controlled `/proc/<pid>/exe` and
    argv[0].  The `Popen` pid cannot be reused while our un-reaped handle
    exists, and a failed proof keeps the tap down and the run lock held, so
    this only weakens an extra proof, not the fail-safe (opus S-5).
  - `qga.sock` is still connected by path inside the QEMU-owned state
    directory.  The profile is already visible to QEMU and the channel is
    root-to-guest line JSON; a directory-fd/`S_ISSOCK` check is deferred
    (opus S-6 / pi S-4).
  - `hostcopy` still walks the operator-owned source by path and does not
    anchor every directory component with `openat`; the only actor is the
    opsec account, which is already trusted and root-equivalent here.  Leaf
    swaps, link chains, hardlinks and extra destination entries are covered
    (pi S-3).
  - Provision has no host-memory admission (fixed 512 MiB guest); only the
    disk admission and QEMU file-size bound were added.  Live memory is a
    bring-up check (gpt S3 minor remainder).
  - The generated hostsetup teardown still cannot `rmdir /run/vprlab` because
    `run.lock` lives there; `rmdir … || true` leaves the root-owned
    directory/lock, which is harmless (pi A-6).
  - `hostcopy.check_elf_deps`, QEMU/KVM/tap, Docker/Tailscale readiness and
    the Debian tcpdump privilege-drop order remain live gates; only offline
    component evidence is claimed (pi A-3/A-4/A-5, opus D-3).
  - The operator account that runs `run_phase.py`, `hostsetup.py`,
    `provision.py` and the scanner wrapper is explicitly **trusted**: those
    root programs execute from the operator-owned checkout.  Only the
    scanner's installed module tree is compared with the repository (opus
    D-4).
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

### Accepted risks (controller decision, 2026-11-09)

- **Login URL side channel.** The `login` phase accepts only
  `https://login.tailscale.com/a/<8-16 hex>`, so one URL carries at most 64
  bits. A compromised guest could still leak the lab WireGuard key in pieces
  over several `login` phases. The key is one the host itself injected, and the
  URL lands only in root-only evidence and on the operator's terminal, so no
  trust boundary is crossed. This risk is accepted, not fixed (GPT r4 S2).
- **Provisioning disk use.** Provisioning is a one-time, supervised step from
  pinned inputs. It is bounded by a 64 MiB serial cap, RLIMIT_FSIZE 8 GiB and an
  8 GiB free-space admission check. An aggregate quota across the staged
  payload, seed ISOs and overlay is not enforced; the operator watches it
  (GPT r4 S3).
- **Guard SIGKILL.** QEMU is signalled through a pidfd opened from our own
  child handle and re-verified (`/proc/<pid>/exe` is the staged QEMU), so a
  reused pid can never receive the SIGKILL (GPT r4 new finding).
- **tcpdump rlimit.** tcpdump runs with RLIMIT_FSIZE = capture cap + 256 MiB,
  so the capture file stays bounded even if the runner is SIGKILLed and its
  guard thread dies.

## Commands

```sh
# once, root (debdev): account, complete tool/image/module copies, root-owned
# directories; does NOT create vm-NNN (provision does that exclusively)
python3 -B tools/leak-lab/vm/hostsetup.py > /root/vprlab-hostsetup.sh
sh /root/vprlab-hostsetup.sh

# once, online (root, debdev); creates and chowns vm-001, refuses an existing one
python3 -B tools/leak-lab/vm/provision.py --index 1 \
  --image-tar /root/vprouter-image.tar

# once, online (root, debdev): M3 client; verifies the pinned tarball hash
python3 -B tools/leak-lab/vm/provision.py --client --index 1 \
  --tailscale-tar /root/vprlab/tailscale_1.104.5_amd64.tgz

# M1, root: setup-only (no second unbounded capture).  Add --client 1 for M3.
python3 -B tools/leak-lab/netplan.py --wan-interface <wan> > /root/vprlab-lab.sh
sh /root/vprlab-lab.sh setup

# a phase (root, debdev); the capture stays alive until the guest exits
python3 -B tools/leak-lab/vm/run_phase.py \
  --phase start-router --duration 120 --index 1 \
  --profile-file /root/vprouter-lab.conf \
  --used-nonces /root/leaklab-used-nonces.txt

# M3 client login (boots only the client; no profile)
python3 -B tools/leak-lab/vm/run_phase.py \
  --phase client-login --client 1 --duration 900 \
  --used-nonces /root/leaklab-used-nonces.txt

# M3 phase with the client VM and the router VM
python3 -B tools/leak-lab/vm/run_phase.py \
  --phase idle --client 1 --duration 120 --index 1 \
  --profile-file /root/vprouter-lab.conf \
  --used-nonces /root/leaklab-used-nonces.txt

# exact removal last; holds /run/vprlab/run.lock for the whole teardown.
# hostsetup teardown retains /var/lib/vprlab/evidence deliberately.
sh /root/vprlab-lab.sh teardown
sh /root/vprlab-hostsetup.sh teardown

# offline tests
python3 -B -W error -m unittest discover -s tools/leak-lab/vm -p 'test_*.py' -v
python3 -B -W error -m unittest tools/leak-lab/test_leak_lab.py -v
```

`run_phase.py` executes `pcapscan.py` from
`/opt/vprlab-tools/leaklab/` after verifying its `SHA256SUMS`.  If that copy
is missing, or differs from the repository's current `pcapscan.py`, the phase
refuses.  `--allow-repo-scanner` is the explicit developer override for a
working-tree scanner; do not use it for a certification run.

The suite has 227 tests, including an integration test that runs the real
`pcapscan.py` CLI over evidence written by the real `rootfs` writers through an
inherited directory fd.  It executes the real phase runner and provision
helpers with fake process/QGA/scanner layers, the generated hostsetup script
with every privileged command stubbed in a scratch directory, plus a fake
unix-socket guest agent; it never runs QEMU, tcpdump, ip, nft, iptables,
docker, qemu-img, genisoimage or a network command.  The M3 classes add client
provisioning, client guest scripts, the client scan/probe verdicts and a fake
two-VM `run_phase.py --client N` harness.  The separate host-side scanner suite
(`tools/leak-lab/test_leak_lab.py`) has 301 tests.

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
