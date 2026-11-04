# Task 8c rebuild phase 2 fixes report

I1/I2/M2 are resolved for the current handoff; M1 now has a post-hoc reference for future comparisons, not retrospective historical preservation proof. The same phase 2 disk boots with the same pinned host key and machine-id. A new boot/process identity is explicitly recorded. No phase 3 projection, baseline authoring, Bootstrap/run409, enrollment, provider connection or acceptance experiment ran; `release_ready=false` remains.

Workspace `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`, HEAD `d62ab24e172badb9245fa5f20d71f15930731839`. Work date 2026-11-04 CET / 2026-11-03 UTC. Read the complete phase 2 report and review, including I1/I2/M1/M2 and “Phase 3 must provide”, launcher, build-driver optimization guard and relevant controller SSH construction. Used verification-before-completion; lightweight memory lookup supplied preservation/evidence conventions only. Current facts below are freshly observed. No subagents, commit/push/ref writes, outer-host sudo, installs, or changes to debdev network/firewall/Docker/Tailscale settings. The only outer Docker command was read-only `docker ps -a`. No Rust changed, so cargo fmt/clippy/test were NOT_RUN as requested.

Durable evidence: `target/lab-state/phase2-fixes-20261103T232932Z` resolves into `/DATA/vprouter-lab/lab-state/`. `commands.jsonl` contains exact execution argv, timestamps and exits; helper sources retain the exact nested commands and guest read payload. Each ledger command has complete stdout/stderr files, including expected refusals. Entry staged tool and original phase 2 report were preserved (`entry-staged.diff`); original phase 2 report and review are not rewritten as though these fixes happened earlier. Only explicitly named implementation/report paths are added to the index. Keys, VM state, logs and trust files remain ignored/private.

## I1: same guest restart and fresh identity

The orchestrator's verified finding attributes guest disappearance to **debdev's outer-host crash at 2026-11-04 00:21:54 CET**, with new host journal beginning 00:23:07 CET. This supersedes the earlier review's unknown-cause observation; it does not diagnose the underlying host crash mechanism. Earlier debdev crashes predate lab work. The saved disk and `/DATA/vprouter-lab` survived. No evidence supports calling this an autonomous guest failure.

`target/platform-lab/start-additional-clean-debian.py` refuses existing state with `assert not state.exists(), "existing_state_requires_review"`. It was read, not executed. Added the separate maintained `tools/rust-v2-lab/restart-clean-debian.py`; run from the repository root with `python3 tools/rust-v2-lab/restart-clean-debian.py`. It does not recreate an overlay, seed, cloud-init data, or key. The historical archived launcher and all restored controller bytes stay unchanged; the new helper is outside the historical 293-file archive manifest.

The helper refuses optimized Python, serializes its own restart callers with nonblocking flock, refuses a QEMU command line mentioning this state (including its resolved durable path) or port 22036, fails closed on unreadable process command lines, and requires loopback22036 to be bindable. It hashes the full immutable base with SHA512, checks the original process binding and manifest entry, then checks `qemu-img info --output=json --backing-chain` returns exactly the existing qcow2 overlay and that verified qcow2 base, with no further backing file. Those checks completed before launch. It repeats the live-process/port check immediately before archiving reusable runtime files and launching the **exact original `process.json` argv**, using the launcher's tool-library environment. No new network/device/forward arguments were added. This cooperative lock does not serialize arbitrary independent QEMU launchers; future lifecycle owners must honor the lock and the same checks.

Verified base SHA512:

```text
16e0965312c56feb331049d45d2b1b5778f3f942a33d4300eedbb97527707f2bea87c0006f3e4cc7a25fadbff739c4e235a51fb9bcd1b66fd554f7f8e80ba45c
```

The old `process.json` remains byte-identical, SHA256 `2f8c1d8107eea43ea4d36f5bfbb99b12825a5ac807e1438586dc346c72c95200`. Old `serial.log`, `qemu.log` and process record were copied before QEMU could reuse serial output; stale PID/socket were moved to `target/platform-lab/debian-clean-x86_64/restart-20261103T233034.883364Z`. Original seed/user-data/meta-data remain in place. Their current hashes, and original process comparison, are in `final-audit.json`; these current hashes alone are not pre-crash checksum proof. No offline repair or manual fsck was performed. Normal guest boot performed its own recovery.

New process record: `target/platform-lab/debian-clean-x86_64/process-restart-20261103T233034.883364Z.json`. Its full content follows; it deliberately retains `RESTART_BOOTING_NOT_VERIFIED` as a launch-time fact. Fresh SSH, QMP and final-audit results below establish later verification instead of editing that record.

```json
{
  "observed_at_utc": "2026-11-03T23:30:34.886499+00:00",
  "platform": "debian-clean-x86_64",
  "pid": 91972,
  "start_time": 45353,
  "ssh_port": 22036,
  "argv": [
    "/DATA/AppData/vprouter-rust-v2/target/lab-tools/root/usr/bin/qemu-system-x86_64",
    "-accel",
    "kvm",
    "-machine",
    "pc,smm=off",
    "-cpu",
    "host",
    "-smp",
    "2",
    "-m",
    "2048",
    "-bios",
    "/DATA/AppData/vprouter-rust-v2/target/lab-tools/root/usr/share/seabios/bios-256k.bin",
    "-drive",
    "file=/DATA/AppData/vprouter-rust-v2/target/platform-lab/debian-clean-x86_64/guest.qcow2,if=virtio,format=qcow2",
    "-drive",
    "file=/DATA/AppData/vprouter-rust-v2/target/platform-lab/debian-clean-x86_64/seed.iso,media=cdrom,readonly=on",
    "-boot",
    "c",
    "-netdev",
    "user,id=wan,hostfwd=tcp:127.0.0.1:22036-:22",
    "-device",
    "virtio-net-pci,netdev=wan,romfile=",
    "-display",
    "none",
    "-vga",
    "none",
    "-serial",
    "file:/DATA/AppData/vprouter-rust-v2/target/platform-lab/debian-clean-x86_64/serial.log",
    "-pidfile",
    "/DATA/AppData/vprouter-rust-v2/target/platform-lab/debian-clean-x86_64/qemu.pid",
    "-qmp",
    "unix:/DATA/AppData/vprouter-rust-v2/target/platform-lab/debian-clean-x86_64/qmp.sock,server=on,wait=off",
    "-L",
    "/DATA/AppData/vprouter-rust-v2/target/lab-tools/root/usr/share/qemu",
    "-sandbox",
    "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny"
  ],
  "base_image": "/DATA/AppData/vprouter-rust-v2/target/lab-images/debian-13-genericcloud-amd64-20261021-2638.qcow2",
  "base_image_sha512": "16e0965312c56feb331049d45d2b1b5778f3f942a33d4300eedbb97527707f2bea87c0006f3e4cc7a25fadbff739c4e235a51fb9bcd1b66fd554f7f8e80ba45c",
  "checksum_manifest": "/DATA/AppData/vprouter-rust-v2/target/lab-images/SHA512SUMS-20261021-2638",
  "test_status": "RESTART_BOOTING_NOT_VERIFIED",
  "identities_imported": false,
  "provider_credentials_imported": false,
  "old_vm_changes": false,
  "production_changes": false,
  "controller_boot_id": "256891be-cd7c-4f1e-8531-8c1d334d6bf5",
  "original_process_sha256": "2f8c1d8107eea43ea4d36f5bfbb99b12825a5ac807e1438586dc346c72c95200",
  "previous_process_record": "/DATA/AppData/vprouter-rust-v2/target/platform-lab/debian-clean-x86_64/process.json",
  "restart_archive": "/DATA/AppData/vprouter-rust-v2/target/platform-lab/debian-clean-x86_64/restart-20261103T233034.883364Z",
  "backing_chain": [
    {
      "children": [
        {
          "name": "file",
          "info": {
            "children": [],
            "virtual-size": 1236140032,
            "filename": "/DATA/AppData/vprouter-rust-v2/target/platform-lab/debian-clean-x86_64/guest.qcow2",
            "format": "file",
            "actual-size": 1236078592,
            "format-specific": {
              "type": "file",
              "data": {}
            },
            "dirty-flag": false
          }
        }
      ],
      "backing-filename-format": "qcow2",
      "virtual-size": 25769803776,
      "filename": "/DATA/AppData/vprouter-rust-v2/target/platform-lab/debian-clean-x86_64/guest.qcow2",
      "cluster-size": 65536,
      "format": "qcow2",
      "actual-size": 1236078592,
      "format-specific": {
        "type": "qcow2",
        "data": {
          "compat": "1.1",
          "compression-type": "zlib",
          "lazy-refcounts": false,
          "refcount-bits": 16,
          "corrupt": false,
          "extended-l2": false
        }
      },
      "full-backing-filename": "/DATA/AppData/vprouter-rust-v2/target/lab-images/debian-13-genericcloud-amd64-20261021-2638.qcow2",
      "backing-filename": "/DATA/AppData/vprouter-rust-v2/target/lab-images/debian-13-genericcloud-amd64-20261021-2638.qcow2",
      "dirty-flag": false
    },
    {
      "children": [
        {
          "name": "file",
          "info": {
            "children": [],
            "virtual-size": 342294528,
            "filename": "/DATA/AppData/vprouter-rust-v2/target/lab-images/debian-13-genericcloud-amd64-20261021-2638.qcow2",
            "format": "file",
            "actual-size": 342294528,
            "format-specific": {
              "type": "file",
              "data": {}
            },
            "dirty-flag": false
          }
        }
      ],
      "virtual-size": 3221225472,
      "filename": "/DATA/AppData/vprouter-rust-v2/target/lab-images/debian-13-genericcloud-amd64-20261021-2638.qcow2",
      "cluster-size": 65536,
      "format": "qcow2",
      "actual-size": 342294528,
      "format-specific": {
        "type": "qcow2",
        "data": {
          "compat": "1.1",
          "compression-type": "zlib",
          "lazy-refcounts": false,
          "refcount-bits": 16,
          "corrupt": false,
          "extended-l2": false
        }
      },
      "dirty-flag": false
    }
  ]
}
```

Fresh `/proc` start tick **45353**, PID **91972**, exact argv and controller boot ID **256891be-cd7c-4f1e-8531-8c1d334d6bf5** matched at `2026-11-03T23:33:02.143032+00:00`. QMP `query-status` reports running; `query-kvm` reports enabled/present=true (`qmp.json`). Only QMP capability negotiation and those two read queries were issued.

Strict SSH first verified the actual `/etc/ssh/ssh_host_ed25519_key.pub`, before any guest health reads. The retained pin was independently checked for its sole endpoint row and SHA256 `38b48e872f7876cb68b02b9c823107ccc2969c5d63642b9b74561803688e139e`; both key and pin mode0600. Pinned and remotely read host public keys agree byte-for-byte in algorithm/key fields, and both `ssh-keygen -lf` results agree:

```text
SHA256:rk1TQu4ncW/fxBUmvcFu/M3BbOKpqofLaf5glJ86WvA
```

SSH uses `-F /dev/null`, the absolute dedicated lab key, `IdentitiesOnly=yes`, `BatchMode=yes`, the explicit known_hosts file, `GlobalKnownHostsFile=/dev/null`, `StrictHostKeyChecking=yes`, `UpdateHostKeys=no`, `HostKeyAlgorithms=ssh-ed25519`, `ConnectTimeout=5`, port 22036 and `vprouterlab@127.0.0.1`. Exact argv is in `verify-guest.py`. No keyscan, TOFU, accept-new or fallback occurred. The mismatch path stops before health observations. Dedicated access public-key provenance remains the phase 2 generation record; no private-key bytes were printed or staged.

Fresh guest boot ID **ba98deeb-881c-44b4-b6a7-1d0cc8cff4a8**, machine-id **6efc72f8c01340cc91fec545d32e0082**. Kernel `6.12.113+deb13-cloud-amd64`; current and PID1 network namespaces equal. Docker reports systemd/cgroup2/overlay2; cloud-init is done, errors empty. Lab directory root:root0700 and isolated marker root:root0600/single-link passed. Guest `systemctl --failed` lists zero units. Root is mounted ext4 read/write. Both exact phase 2 image IDs remain and `docker image inspect` succeeds:

- amd64 `sha256:94603a5a98fa75ef53c4c5b5401c4025b25cd2e54ad2609720ba8d0e5a3febda`, manifest `sha256:08a1bc6c82fee62d1a135788fb67fefa9d22deea3830e8a45ebe1a3cb116e325`.
- arm64 cache only `sha256:5d3dd33a5cd5ed29514fdada176fa2226d122f19bddd8fe06bc974633083e90e`, manifest `sha256:472c549d2ef8cebc000de2c8a94061bbdc864d2454177b2ada713262475449ef`.

Guest Docker containers are empty. `guest-health.json` retains complete journal, dmesg, journal error priority output, findmnt/df, Docker info/images/inspect/containers, cloud-init, identity, memory and address/route observations. Filesystem evidence includes successful ext4 journal recovery and a clean root fsck, **plus** a FAT dirty bit automatically cleared and unclean journal files replaced. Preserve these caveats; this is boot health evidence, not exhaustive storage-integrity qualification:

```text
2026-11-03T23:30:42+00:00 vprouter-debian-clean-lab kernel: EXT4-fs (vda1): INFO: recovery required on readonly filesystem
2026-11-03T23:30:42+00:00 vprouter-debian-clean-lab kernel: EXT4-fs (vda1): recovery complete
2026-11-03T23:30:42+00:00 vprouter-debian-clean-lab systemd-fsck[286]: /dev/vda1: clean, 32910/1564672 files, 531267/6258683 blocks
2026-11-03T23:30:42+00:00 vprouter-debian-clean-lab systemd-journald[285]: File /var/log/journal/6efc72f8c01340cc91fec545d32e0082/system.journal corrupted or uncleanly shut down, renaming and replacing.
2026-11-03T23:30:43+00:00 vprouter-debian-clean-lab systemd-fsck[393]: Dirty bit is set. Fs was not properly unmounted and some data may be corrupt.
2026-11-03T23:30:43+00:00 vprouter-debian-clean-lab systemd-fsck[393]:  Automatically removing dirty bit.
2026-11-03T23:30:43+00:00 vprouter-debian-clean-lab systemd-fsck[393]: *** Filesystem was changed ***
2026-11-03T23:31:09+00:00 vprouter-debian-clean-lab systemd-journald[285]: File /var/log/journal/6efc72f8c01340cc91fec545d32e0082/user-1000.journal corrupted or uncleanly shut down, renaming and replacing.
```

Verbatim error-priority journal output (not suppressed or called error-free):

```text
Nov 03 23:30:42 vprouter-debian-clean-lab systemd-ssh-generator[253]: Failed to query local AF_VSOCK CID: Cannot assign requested address
Nov 03 23:30:42 vprouter-debian-clean-lab (sd-exec-[243]: /usr/lib/systemd/system-generators/systemd-ssh-generator failed with exit status 1.
```

The full journal also records containerd skipped optional snapshotter/tracing plugins and a missing CNI configuration during CRI initialization; Docker image reads and Docker info succeeded. No remediation or container/network provisioning was attempted.

## I2: controller trust path and dedicated key

Created exactly one relative symlink, after the fresh fingerprint check:

```text
target/platform-lab/debian-clean-x86_64/known_hosts -> ../../lab-state/known_hosts
```

It resolves to `/DATA/vprouter-lab/lab-state/known_hosts`, the single verified source. No pin/key copy can drift independently. Both source and alias bytes hash to `38b48e872f7876cb68b02b9c823107ccc2969c5d63642b9b74561803688e139e`. A separate strict SSH public-key read using **the controller-expected alias** succeeded (`wire-trust.stdout`). No other platform trust files or port mappings were changed. Historical port 22032 references to lab-state do not establish trust for a live original guest; only 22036 is admitted by this pin.

`run-frozen-host-projection.py:121,180-184` and `run-frozen-secret-bootstrap.py:9,36,44` already specify port 22036 for clean Debian, the alias above and `target/lab-state/id_ed25519`. All other restored controllers referencing this alias or shared lab key consume the same filesystem source. Thus no controller edit is required. `controller-input-hashes.json` records all 115 platform files with relevant references before wiring; final audit rehashed them unchanged. Preserved archive sources remain unchanged too.

For projection's exact existing SSH options, `ssh -G` confirmed hostname 127.0.0.1, user vprouterlab, port 22036, exactly the dedicated identityfile, IdentitiesOnly=yes, explicit alias and StrictHostKeyChecking=true; no ProxyCommand, ProxyJump or HostKeyAlias. Full config is retained in `controller-ssh-effective-config.txt`. Controllers retain their existing SSH configuration/default global-known-hosts behavior (`/etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2`); the isolated strict verification session above is a separate read, not execution of those controllers. Future phase 3 review must refresh effective config and decide any additional SSH isolation before execution. No unrelated endpoint was silently retargeted.

Inventory commands (exit0, raw matching lines retained):

```text
rg -n 'known_hosts|id_ed25519|2203[0-9]' target/platform-lab --glob '*.py'
rg -n 'known_hosts|id_ed25519|2203[0-9]' tools/rust-v2-lab/target --glob '*.py'
```

`controller-trust-path-inventory.txt` has runtime platform references; `all-restored-controller-trust-inventory.txt` has all 507 matching lines across 151 restored source files, including helpers outside platform-lab. The latter is listed below using its restored `target/` paths and original line numbers; entries include historical endpoints22032–22035, launch/provisioning tools and validation fixtures, and are **not** permission to execute them. Complete line contents, explicit ports and path expressions are in that raw inventory.

| Restored source path | Matching lines |
| --- | --- |
| `target/actual-program-inspect-monitor.py` | 66, 67, 68 |
| `target/archive-failed-owner-nonce.py` | 4, 37 |
| `target/archive-secret-assembly-selectors.py` | 15, 39 |
| `target/archive-secret-attachment-selectors.py` | 8, 22 |
| `target/archive-secret-bootstrap-selectors.py` | 15, 39 |
| `target/archive-secret-host-addition-selectors.py` | 15, 39 |
| `target/archive-secret-movement-selectors.py` | 8, 22 |
| `target/archive-secret-preparation-selectors.py` | 14, 32 |
| `target/archive-secret-producer-binding-selectors.py` | 15, 39 |
| `target/archive-secret-provision-selectors.py` | 8, 22 |
| `target/archive-secret-quarantine-selectors.py` | 15, 39 |
| `target/collect-terminal-witness.py` | 5, 18 |
| `target/drain-exact-terminal-guard.py` | 7, 23 |
| `target/drain-expiry-drop-failure-guards.py` | 4, 43 |
| `target/drain-retirement-failure-guard.py` | 4, 47 |
| `target/drain-stopped-owner-guards.py` | 4, 31 |
| `target/inspect-bootstrap-route-failure.py` | 12, 26 |
| `target/inspect-expiry-drop-deny.py` | 5, 20 |
| `target/inspect-expiry-drop-failure.py` | 36, 37, 38, 39, 61 |
| `target/inspect-failed-owner-terminal.py` | 12, 31 |
| `target/inspect-secret-assembly-failure.py` | 19, 49 |
| `target/inspect-secret-attachment-failure.py` | 15, 43 |
| `target/inspect-secret-bootstrap-failure.py` | 20, 52 |
| `target/inspect-secret-host-addition-failure.py` | 20, 52 |
| `target/inspect-secret-movement-failure.py` | 15, 43 |
| `target/inspect-secret-preparation-failure.py` | 15, 39 |
| `target/inspect-secret-producer-binding-failure.py` | 19, 49 |
| `target/inspect-secret-provision-failure.py` | 15, 43 |
| `target/inspect-secret-quarantine-failure.py` | 19, 49 |
| `target/inspect-stopped-owner-guards.py` | 4, 17 |
| `target/inspect-terminal-deny.py` | 5, 20 |
| `target/platform-lab/arm-trace-summary.py` | 40, 41, 42 |
| `target/platform-lab/capture-approved-kernel.py` | 3 |
| `target/platform-lab/capture-void-cgroup.py` | 3, 4 |
| `target/platform-lab/collect-component-evidence.py` | 4, 6, 7, 8 |
| `target/platform-lab/probe-cloud-guests.py` | 20, 26 |
| `target/platform-lab/probe-original-scope-pin-order.py` | 18, 19, 20, 21, 173 |
| `target/platform-lab/probe-original-scope-pin.py` | 18, 19, 20, 21, 165 |
| `target/platform-lab/probe-proc-remount.py` | 19 |
| `target/platform-lab/reboot-void-after-backend.py` | 3 |
| `target/platform-lab/run-actual-arch-x86_64.py` | 244, 245, 247, 251 |
| `target/platform-lab/run-actual-debian-arm64.py` | 244, 245, 247, 251 |
| `target/platform-lab/run-actual-monitor-arch-x86_64.py` | 255, 256, 258, 262 |
| `target/platform-lab/run-actual-monitor-debian-arm64-tcg120.py` | 255, 256, 258, 262 |
| `target/platform-lab/run-actual-monitor-debian-arm64.py` | 255, 256, 258, 262 |
| `target/platform-lab/run-actual-monitor-debian-clean-x86_64.py` | 255, 256, 258, 262 |
| `target/platform-lab/run-actual-monitor-debian-x86_64.py` | 255, 256, 258, 262 |
| `target/platform-lab/run-actual-monitor-void-x86_64.py` | 255, 256, 258, 262 |
| `target/platform-lab/run-actual-void-x86_64.py` | 244, 245, 247, 251 |
| `target/platform-lab/run-explicit-ifindex-probe.py` | 3, 7 |
| `target/platform-lab/run-frozen-host-projection.py` | 121, 122, 123, 124, 180 |
| `target/platform-lab/run-frozen-platform-actual.py` | 3, 20 |
| `target/platform-lab/run-frozen-secret-assembly.py` | 8, 23, 31 |
| `target/platform-lab/run-frozen-secret-attachment.py` | 8, 22, 30 |
| `target/platform-lab/run-frozen-secret-bootstrap.py` | 9, 36, 44 |
| `target/platform-lab/run-frozen-secret-host-addition.py` | 9, 36, 44 |
| `target/platform-lab/run-frozen-secret-movement.py` | 8, 22, 30 |
| `target/platform-lab/run-frozen-secret-preparation.py` | 8, 19, 27 |
| `target/platform-lab/run-frozen-secret-producer-binding.py` | 8, 23, 31 |
| `target/platform-lab/run-frozen-secret-provision.py` | 8, 22, 30 |
| `target/platform-lab/run-frozen-secret-quarantine.py` | 8, 23, 31 |
| `target/platform-lab/run-native-inspection-preflight.py` | 27, 28, 29, 30, 88 |
| `target/platform-lab/run-nsfs-fd-mount-probe.py` | 3, 5 |
| `target/platform-lab/run-operational-profile-debian-arm64.py` | 246, 247, 249, 253 |
| `target/platform-lab/run-operational-profile-debian.py` | 246, 247, 249, 253 |
| `target/platform-lab/run-owner-admission-birth-failure-debian-arm64.py` | 286, 287, 289, 293 |
| `target/platform-lab/run-owner-admission-birth-failure-debian-clean.py` | 286, 287, 289, 293 |
| `target/platform-lab/run-owner-admission-birth-failure-debian.py` | 286, 287, 289, 293 |
| `target/platform-lab/run-owner-admission-stop-arch.py` | 285, 286, 288, 292 |
| `target/platform-lab/run-owner-admission-stop-debian-arm64.py` | 285, 286, 288, 292 |
| `target/platform-lab/run-owner-admission-stop-debian-clean.py` | 285, 286, 288, 292 |
| `target/platform-lab/run-owner-admission-stop-debian.py` | 285, 286, 288, 292 |
| `target/platform-lab/run-owner-bootstrap-debian-arm64.py` | 276, 277, 279, 283 |
| `target/platform-lab/run-owner-bootstrap-debian-clean.py` | 276, 277, 279, 283 |
| `target/platform-lab/run-owner-bootstrap-debian.py` | 276, 277, 279, 283 |
| `target/platform-lab/run-owner-deployment-debian-arm64.py` | 275, 276, 278, 282 |
| `target/platform-lab/run-owner-deployment-debian-clean.py` | 275, 276, 278, 282 |
| `target/platform-lab/run-owner-deployment-debian.py` | 275, 276, 278, 282 |
| `target/platform-lab/run-owner-domains-arch.py` | 275, 276, 278, 282 |
| `target/platform-lab/run-owner-domains-debian-arm64.py` | 275, 276, 278, 282 |
| `target/platform-lab/run-owner-domains-debian-clean.py` | 275, 276, 278, 282 |
| `target/platform-lab/run-owner-domains-debian.py` | 275, 276, 278, 282 |
| `target/platform-lab/run-owner-expiry-drop-arch.py` | 286, 287, 289, 293 |
| `target/platform-lab/run-owner-expiry-drop-debian-arm64.py` | 286, 287, 289, 293 |
| `target/platform-lab/run-owner-expiry-drop-debian-clean.py` | 286, 287, 289, 293 |
| `target/platform-lab/run-owner-expiry-drop-debian.py` | 286, 287, 289, 293 |
| `target/platform-lab/run-owner-expiry-partial-drop-arch.py` | 286, 287, 289, 293 |
| `target/platform-lab/run-owner-expiry-partial-drop-debian-arm64.py` | 286, 287, 289, 293 |
| `target/platform-lab/run-owner-expiry-partial-drop-debian-clean.py` | 286, 287, 289, 293 |
| `target/platform-lab/run-owner-expiry-partial-drop-debian.py` | 286, 287, 289, 293 |
| `target/platform-lab/run-owner-expiry-placement-debian-arm64.py` | 285, 286, 288, 292 |
| `target/platform-lab/run-owner-expiry-placement-debian-clean.py` | 285, 286, 288, 292 |
| `target/platform-lab/run-owner-expiry-placement-debian.py` | 285, 286, 288, 292 |
| `target/platform-lab/run-owner-host-audit-debian-arm64.py` | 276, 277, 279, 283 |
| `target/platform-lab/run-owner-host-audit-debian-clean.py` | 276, 277, 279, 283 |
| `target/platform-lab/run-owner-host-audit-debian.py` | 276, 277, 279, 283 |
| `target/platform-lab/run-owner-inspection-held-arch.py` | 285, 286, 288, 292 |
| `target/platform-lab/run-owner-inspection-held-debian-arm64.py` | 285, 286, 288, 292 |
| `target/platform-lab/run-owner-inspection-held-debian-clean.py` | 285, 286, 288, 292 |
| `target/platform-lab/run-owner-inspection-held-debian.py` | 285, 286, 288, 292 |
| `target/platform-lab/run-owner-inspection-setup-debian-arm64.py` | 285, 286, 288, 292 |
| `target/platform-lab/run-owner-inspection-setup-debian-clean.py` | 285, 286, 288, 292 |
| `target/platform-lab/run-owner-inspection-setup-debian.py` | 285, 286, 288, 292 |
| `target/platform-lab/run-owner-journal-debian-arm64.py` | 275, 276, 278, 282 |
| `target/platform-lab/run-owner-journal-debian-clean.py` | 275, 276, 278, 282 |
| `target/platform-lab/run-owner-journal-debian.py` | 275, 276, 278, 282 |
| `target/platform-lab/run-owner-process-inspection-debian-arm64.py` | 285, 286, 288, 292 |
| `target/platform-lab/run-owner-process-inspection-debian-clean.py` | 285, 286, 288, 292 |
| `target/platform-lab/run-owner-process-inspection-debian.py` | 285, 286, 288, 292 |
| `target/platform-lab/run-owner-retained-drop-debian-arm64.py` | 286, 287, 289, 293 |
| `target/platform-lab/run-owner-retained-drop-debian-clean.py` | 286, 287, 289, 293 |
| `target/platform-lab/run-owner-retained-drop-debian.py` | 286, 287, 289, 293 |
| `target/platform-lab/run-owner-retirement-arch.py` | 322, 323, 325, 329 |
| `target/platform-lab/run-owner-retirement-debian-arm64.py` | 322, 323, 325, 329 |
| `target/platform-lab/run-owner-retirement-debian-clean.py` | 322, 323, 325, 329 |
| `target/platform-lab/run-owner-retirement-debian.py` | 322, 323, 325, 329 |
| `target/platform-lab/run-owner-retirement-global-stop-arch.py` | 322, 323, 325, 329 |
| `target/platform-lab/run-owner-retirement-global-stop-debian-arm64.py` | 322, 323, 325, 329 |
| `target/platform-lab/run-owner-retirement-global-stop-debian-clean.py` | 322, 323, 325, 329 |
| `target/platform-lab/run-owner-retirement-global-stop-debian.py` | 322, 323, 325, 329 |
| `target/platform-lab/run-owner-retirement-host-span-arch.py` | 322, 323, 325, 329 |
| `target/platform-lab/run-owner-retirement-host-span-debian-arm64.py` | 322, 323, 325, 329 |
| `target/platform-lab/run-owner-retirement-host-span-debian-clean.py` | 322, 323, 325, 329 |
| `target/platform-lab/run-owner-retirement-host-span-debian.py` | 322, 323, 325, 329 |
| `target/platform-lab/run-owner-retirement-queued-failure-arch.py` | 322, 323, 325, 329 |
| `target/platform-lab/run-owner-retirement-queued-failure-debian-arm64.py` | 322, 323, 325, 329 |
| `target/platform-lab/run-owner-retirement-queued-failure-debian-clean.py` | 322, 323, 325, 329 |
| `target/platform-lab/run-owner-retirement-queued-failure-debian.py` | 322, 323, 325, 329 |
| `target/platform-lab/run-owner-retirement-writer-failure-arch.py` | 322, 323, 325, 329 |
| `target/platform-lab/run-owner-retirement-writer-failure-debian-arm64.py` | 322, 323, 325, 329 |
| `target/platform-lab/run-owner-retirement-writer-failure-debian-clean.py` | 322, 323, 325, 329 |
| `target/platform-lab/run-owner-retirement-writer-failure-debian.py` | 322, 323, 325, 329 |
| `target/platform-lab/run-owner-terminal-death-debian-clean.py` | 285, 286, 288, 292 |
| `target/platform-lab/run-owner-terminal-death-debian.py` | 285, 286, 288, 292 |
| `target/platform-lab/run-owner-terminal-debian-clean.py` | 285, 286, 288, 292 |
| `target/platform-lab/run-owner-terminal-debian.py` | 285, 286, 288, 292 |
| `target/platform-lab/run-owner-watchdog-debian-clean.py` | 275, 276, 278, 282 |
| `target/platform-lab/run-owner-watchdog-debian.py` | 275, 276, 278, 282 |
| `target/platform-lab/run-peerpidfd-probe.py` | 3, 5 |
| `target/platform-lab/run-terminal-death-debian.py` | 246, 247, 249, 253 |
| `target/platform-lab/run-terminal-executor-debian.py` | 246, 247, 249, 253 |
| `target/platform-lab/smoke-readonly-accounting.py` | 211 |
| `target/platform-lab/start-additional-clean-debian.py` | 19, 34 |
| `target/platform-lab/start-cloud-guests.py` | 7, 12, 13 |
| `target/platform-lab/start-void-live.py` | 7, 15, 44, 50 |
| `target/platform-lab/switch-void-nft-backend.py` | 2 |
| `target/run-netfilter-native-frozen.py` | 8, 9 |
| `target/run-shared-lease-regression-frozen.py` | 16, 18 |
| `target/run-transport-regression-frozen-original.py` | 19, 20, 21 |
| `target/run-transport-regression-frozen.py` | 23, 25, 26, 27, 31, 32, 33 |
| `target/run-transport-regression.py` | 17, 18, 19 |

## M2: assertions cannot be stripped

Added the same early optimization refusal used by `tools/rust-v2-lab/rebuild-20261103-build.py`:

```python
if not __debug__:
    raise RuntimeError('optimized_python_refused')
```

It runs before argparse, index reads or guest subprocess work. `python3 -O`, `python3 -OO` and `PYTHONOPTIMIZE=1 python3` each refused with exit1 and `RuntimeError: optimized_python_refused`. Ordinary Python without SSH arguments still exits2 with the required three-option diagnostic. `check-python.py` compiled both changed Python sources without bytecode writes and proved that removal of this exact guard yields the **entry staged tool bytes**. No acquisition was rerun. Historical receipts/candidate retain their old executed inventory-tool hash; the current tool is intentionally newer. No frozen candidate, receipt, program bytes, manifest, source archive or candidate ref was updated.

Current implementation SHA256 values:

```json
{
  "tools/pinned-tailscale-program-inventory.py": "d7c61aa742db1b89606d80e416acdb2f75773a154ef547ec0fd30b986c731000",
  "tools/rust-v2-lab/restart-clean-debian.py": "637f639cf7ec5d1f0f1dd450f630ec1c6ce3f6c884a2746ddd0f0050fecfa953"
}
```

## M1 and host-instability guidance

Current outer-host snapshot: `target/lab-state/host-snapshot-20261103T233034Z.txt`. It contains the exact stdout/stderr and exit status of `ip -br addr`, `ip route`, `docker ps -a --no-trunc --format '{{.Names}}\t{{.Image}}'`, `systemctl --failed`, `last -x -F`, `journalctl --list-boots --no-pager`, `free -h` and `/proc/meminfo`. All commands exited0. It is explicitly **post-hoc**, taken before this restart, suitable as a reference for future before/after comparisons, not historical phase 2 equality proof. No firewall dump or privileged read was attempted.

Current retained journal boot boundaries (CET):

| Host boot | Last visible journal entry | Next boot's first journal entry |
| --- | --- | --- |
| `1665a0797aca4f1c924e3aeebd8587fe` | 2026-11-03 09:36:54 | 2026-11-03 10:20:17 |
| `d6342bddceb24e17816a3435911cabe1` | 2026-11-03 10:55:33 | 2026-11-03 11:30:45 |
| `dca17735bf0841a180aebcb7c02c571f` | 2026-11-03 11:34:40 | 2026-11-03 11:48:09 |
| `d211b1faebf84673b016d2bae5c5fc30` | 2026-11-04 00:21:54 | 2026-11-04 00:23:07 |

`last -x -F` marks the 10:20:13, 11:30:40 and 11:48:04 November 3 boot sessions as `crash`; the prior long-running session's reboot row is also marked crash. Current wtmp boot time is 00:23:01, while the journal starts 00:23:07; do not conflate record sources. These are visible last-entry/boot boundaries, not proof of the exact physical crash instant for the three earlier crashes. `journalctl` prints a visibility warning: this account cannot see all system/other-user messages. The supplied orchestrator investigation independently verified the latest abrupt host crash. The underlying crash cause is not established by these snapshots.

At snapshot time debdev had 19GiB RAM, 9.2GiB available (`MemAvailable: 9634664 kB`), 332MiB free, 47GiB swap with 651MiB used. This is before restarting the 2GiB guest, not an OOM diagnosis or capacity guarantee. Bound concurrent heavy builds while the guest runs, for example use `cargo ... -j 2`, avoid overlapping heavy rebuilds and recheck `free -h`/guest responsiveness before increasing concurrency. No host memory, swap, services, CPU or network settings were changed.

## Commands, expected failures and implementation diff

All ledger commands ran from the repository root via `python3 target/lab-state/phase2-fixes-20261103T232932Z/run.py LABEL COMMAND...`; the table shows exact command argv joined for readability. Output paths are relative to `target/lab-state/phase2-fixes-20261103T232932Z`. Setup/inspection also used read-only `git status`, `rev-parse`, `show-ref`, `git diff`, `cat`/`sed` of the requested reports/controllers/skills and `rg` searches; reversible Python setup wrote only evidence/helpers/report and the implementation delta. No shell command contacted another machine or used outer-host sudo.

| Command | Exit | Full output |
| --- | ---: | --- |
| `python3 /DATA/AppData/vprouter-rust-v2/target/lab-state/phase2-fixes-20261103T232932Z/snapshot.py` | 0 | `host-snapshot.stdout` / `.stderr` |
| `python3 tools/rust-v2-lab/restart-clean-debian.py` | 0 | `restart.stdout` / `.stderr` |
| `python3 /DATA/AppData/vprouter-rust-v2/target/lab-state/phase2-fixes-20261103T232932Z/verify-guest.py` | 0 | `guest-verification.stdout` / `.stderr` |
| `python3 /DATA/AppData/vprouter-rust-v2/target/lab-state/phase2-fixes-20261103T232932Z/wire-trust.py` | 0 | `wire-trust.stdout` / `.stderr` |
| `python3 /DATA/AppData/vprouter-rust-v2/target/lab-state/phase2-fixes-20261103T232932Z/check-python.py` | 0 | `python-checks.stdout` / `.stderr` |
| `python3 tools/rust-v2-lab/restart-clean-debian.py` | 1 | `restart-live-refusal.stdout` / `.stderr` |
| `python3 /DATA/AppData/vprouter-rust-v2/target/lab-state/phase2-fixes-20261103T232932Z/final-audit.py` | 0 | `final-audit.stdout` / `.stderr` |
| `git add -- tools/pinned-tailscale-program-inventory.py tools/rust-v2-lab/restart-clean-debian.py` | 0 | `stage-tools.stdout` / `.stderr` |
| `git add -f -- .superpowers/sdd/rust-v2/task-8c-rebuild-phase2-fixes-report.md` | 0 | `stage-report.stdout` / `.stderr` |
| `git diff --cached --check` | 0 | `staged-whitespace.stdout` / `.stderr` |
| `python3 /DATA/AppData/vprouter-rust-v2/target/lab-state/phase2-fixes-20261103T232932Z/handoff.py` | 1 | `handoff.stdout` / `.stderr` |
| `git add -f -- .superpowers/sdd/rust-v2/task-8c-rebuild-phase2-fixes-report.md` | 0 | `restage-report.stdout` / `.stderr` |
| `python3 /DATA/AppData/vprouter-rust-v2/target/lab-state/phase2-fixes-20261103T232932Z/handoff-v2.py` | 0 | `handoff-v2.stdout` / `.stderr` |

Verbatim expected duplicate-restart refusal (original guest remains running):

```text
Traceback (most recent call last):
  File "/DATA/AppData/vprouter-rust-v2/tools/rust-v2-lab/restart-clean-debian.py", line 56, in <module>
    refuse_live()
    ~~~~~~~~~~~^^
  File "/DATA/AppData/vprouter-rust-v2/tools/rust-v2-lab/restart-clean-debian.py", line 52, in refuse_live
    raise RuntimeError(f'live_qemu_for_state_or_port:{proc.name}')
RuntimeError: live_qemu_for_state_or_port:91972
```

Verbatim optimized-Python failure (the other two modes produce the same traceback; exact individual results are JSON in `python-checks.stdout`):

```text
Traceback (most recent call last):
  File "/DATA/AppData/vprouter-rust-v2/tools/pinned-tailscale-program-inventory.py", line 19, in <module>
    raise RuntimeError('optimized_python_refused')
RuntimeError: optimized_python_refused
```

Verbatim ordinary missing-argument failure:

```text
usage: pinned-tailscale-program-inventory.py [-h] --ssh-port SSH_PORT
                                             --ssh-key SSH_KEY
                                             --ssh-known-hosts SSH_KNOWN_HOSTS
                                             {amd64,arm64}
pinned-tailscale-program-inventory.py: error: the following arguments are required: --ssh-port, --ssh-key, --ssh-known-hosts
```

Port refusal was also checked independently by compiling the actual `refuse_live` function with an empty process enumeration, leaving its real socket bind against the running guest endpoint: `[Errno 98] Address already in use`. This exercised the port gate without restarting/stopping anything. `final-audit.py` also confirmed actual PID/start/argv/controller-boot/QMP, old-record equality, unchanged controller bytes, unchanged HEAD and byte-identical `git show-ref` output. A first handoff-check helper failed on its original-report comparison: its byte split matched a diff header embedded inside the report, rather than the next top-level patch header. This was a verification-helper bug, not a report change. The original helper and failure logs remain intact; `handoff-v2.py` anchors the split to a new line. The corrected check passed before handback at 2026-11-03T23:36:23.568281+00:00. Verbatim first-check failure:

```text
Traceback (most recent call last):
  File "/DATA/AppData/vprouter-rust-v2/target/lab-state/phase2-fixes-20261103T232932Z/handoff.py", line 8, in <module>
    assert subprocess.check_output(['git','diff','--cached','--','.superpowers/sdd/rust-v2/task-8c-rebuild-phase2-report.md'])==original
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
AssertionError
```

Fix-only implementation diff relative to the entry index (new helper included), SHA256 `5493c564c275c58cf8470bd0f23ab03e5d7cd46449d6073f8dca52738754485f`. The prior phase 2 inventory changes remain staged as well; this block does not repeat them. Display trims blank context trailing spaces; exact patch bytes remain in `fixes-implementation.diff`.

```diff
diff --git a/tools/pinned-tailscale-program-inventory.py b/tools/pinned-tailscale-program-inventory.py
index f62053c..7db6062 100644
--- a/tools/pinned-tailscale-program-inventory.py
+++ b/tools/pinned-tailscale-program-inventory.py
@@ -15,6 +15,9 @@ import subprocess
 import sys
 import tarfile

+if not __debug__:
+    raise RuntimeError('optimized_python_refused')
+
 parser = argparse.ArgumentParser(description=__doc__)
 parser.add_argument('architecture', choices=('amd64', 'arm64'))
 parser.add_argument('--ssh-port', type=int, required=True)
diff --git a/tools/rust-v2-lab/restart-clean-debian.py b/tools/rust-v2-lab/restart-clean-debian.py
new file mode 100644
index 0000000..3700a35
--- /dev/null
+++ b/tools/rust-v2-lab/restart-clean-debian.py
@@ -0,0 +1,107 @@
+#!/usr/bin/env python3
+"""Explicit restart of the preserved phase 2 guest, from the repository root.
+
+Never creates a disk, seed or key. Retains process.json and archives runtime
+files that QEMU reuses. A restart is a new boot, not historical live continuity.
+"""
+import datetime
+import fcntl
+import hashlib
+import json
+import os
+import pathlib
+import shutil
+import socket
+import subprocess
+import time
+
+if not __debug__:
+    raise RuntimeError('optimized_python_refused')
+
+repo = pathlib.Path.cwd()
+state = repo / 'target/platform-lab/debian-clean-x86_64'
+assert state.is_dir(), 'existing_state_required'
+lock = (state / 'restart.lock').open('a')
+fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
+original = (state / 'process.json').read_bytes()
+record = json.loads(original)
+argv = record['argv']
+assert record['platform'] == 'debian-clean-x86_64' and record['ssh_port'] == 22036
+tools = repo / 'target/lab-tools/root'
+assert argv[0] == str(tools / 'usr/bin/qemu-system-x86_64')
+assert argv[argv.index('-drive') + 1] == f'file={state}/guest.qcow2,if=virtio,format=qcow2'
+assert f'file={state}/seed.iso,media=cdrom,readonly=on' in argv
+assert argv[argv.index('-netdev') + 1] == 'user,id=wan,hostfwd=tcp:127.0.0.1:22036-:22'
+assert argv[argv.index('-serial') + 1] == f'file:{state}/serial.log'
+assert argv[argv.index('-pidfile') + 1] == str(state / 'qemu.pid')
+assert argv[argv.index('-qmp') + 1] == f'unix:{state}/qmp.sock,server=on,wait=off'
+for name in ('guest.qcow2', 'seed.iso', 'user-data', 'meta-data'):
+    assert (state / name).is_file(), name
+
+def refuse_live():
+    for proc in pathlib.Path('/proc').glob('[0-9]*'):
+        try:
+            raw = (proc / 'cmdline').read_bytes()
+        except FileNotFoundError:
+            continue
+        except PermissionError:
+            # A hidden process could own this disk: fail closed.
+            raise RuntimeError(f'cannot_inspect_process:{proc.name}')
+        if b'qemu' in raw and any(p.encode() in raw for p in
+                                  (str(state), str(state.resolve()), '22036')):
+            raise RuntimeError(f'live_qemu_for_state_or_port:{proc.name}')
+    with socket.socket() as probe:
+        probe.bind(('127.0.0.1', 22036))
+
+refuse_live()
+image = pathlib.Path(record['base_image'])
+assert image == repo / 'target/lab-images/debian-13-genericcloud-amd64-20261021-2638.qcow2'
+expected = '16e0965312c56feb331049d45d2b1b5778f3f942a33d4300eedbb97527707f2bea87c0006f3e4cc7a25fadbff739c4e235a51fb9bcd1b66fd554f7f8e80ba45c'
+with image.open('rb') as stream:
+    digest = hashlib.file_digest(stream, 'sha512').hexdigest()
+assert digest == record['base_image_sha512'] == expected, 'base_sha512_mismatch'
+manifest = pathlib.Path(record['checksum_manifest'])
+matches = [line.split()[0] for line in manifest.read_text().splitlines()
+           if line.split() and line.split()[-1].lstrip('*') == image.name]
+assert matches == [digest], 'checksum_manifest_mismatch'
+env = dict(os.environ, LD_LIBRARY_PATH=str(tools / 'usr/lib/x86_64-linux-gnu'),
+           QEMU_MODULE_DIR=str(tools / 'usr/lib/x86_64-linux-gnu/qemu'))
+chain = json.loads(subprocess.check_output(
+    [str(tools / 'usr/bin/qemu-img'), 'info', '--output=json', '--backing-chain',
+     str(state / 'guest.qcow2')], env=env))
+assert len(chain) == 2 and all(x['format'] == 'qcow2' for x in chain), 'unexpected_chain'
+assert pathlib.Path(chain[0]['filename']).resolve() == (state / 'guest.qcow2').resolve()
+assert pathlib.Path(chain[0]['full-backing-filename']).resolve() == image.resolve()
+assert pathlib.Path(chain[1]['filename']).resolve() == image.resolve()
+assert not chain[1].get('backing-filename'), 'base_has_backing_file'
+refuse_live()
+stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
+archive = state / ('restart-' + stamp)
+archive.mkdir(mode=0o700)
+(archive / 'backing-chain.json').write_text(json.dumps(chain, indent=2) + '\n')
+for name in ('process.json', 'serial.log', 'qemu.log'):
+    if (state / name).exists():
+        shutil.copy2(state / name, archive / name)
+for name in ('qemu.pid', 'qmp.sock'):
+    if (state / name).exists():
+        (state / name).rename(archive / name)
+with (archive / 'qemu-new.log').open('xb') as log:
+    process = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL,
+                               stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
+raw = pathlib.Path('/proc', str(process.pid), 'stat').read_text()
+start = int(raw[raw.rfind(')') + 2:].split()[19])
+new = dict(record, pid=process.pid, start_time=start,
+           observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
+           controller_boot_id=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
+           original_process_sha256=hashlib.sha256(original).hexdigest(),
+           previous_process_record=str(state / 'process.json'), restart_archive=str(archive),
+           base_image_sha512=digest, backing_chain=chain, test_status='RESTART_BOOTING_NOT_VERIFIED')
+destination = state / ('process-restart-' + stamp + '.json')
+with destination.open('x') as stream:
+    json.dump(new, stream, indent=2)
+    stream.write('\n')
+print(json.dumps(dict(process_record=str(destination), pid=process.pid, start_time=start)), flush=True)
+time.sleep(1)
+assert process.poll() is None, f'qemu_start_failed:{process.returncode}:see:{archive}/qemu-new.log'
+assert pathlib.Path('/proc', str(process.pid), 'cmdline').read_bytes().split(b'\0')[:-1] == [s.encode() for s in argv]
+assert (state / 'process.json').read_bytes() == original, 'original_record_changed'
```

## Staging and limits

Stage only `tools/pinned-tailscale-program-inventory.py`, new `tools/rust-v2-lab/restart-clean-debian.py` and this new report, preserving the original staged phase 2 report. Exact staging: `git add -- tools/pinned-tailscale-program-inventory.py tools/rust-v2-lab/restart-clean-debian.py`; `git add -f -- .superpowers/sdd/rust-v2/task-8c-rebuild-phase2-fixes-report.md`. Final `git diff --cached --check`, staged path/content equality, original-report equality, unchanged HEAD/refs and fresh process/strict-SSH liveness checks passed; receipts are retained in the same evidence directory. They are checked again after the final documentation staging. No guest disk/key/trust/log/evidence file is staged.

The old guest identity from the deleted original lab remains lost; this restart preserves the **new phase 2** disk/host key/machine-id, not historical live-process/boot/namespace continuity. New guest and controller boot IDs replace old live claims. Candidate artifacts were neither rebuilt nor requalified by this repair. Phase 3 must still independently review fresh baseline provenance/authoring/reconciliation, disposition of unavailable raw405/407/408 evidence, exclusive pre-execution run409 reservation, exact current admission/clock/filter/capacity prerequisites, durable failure custody and the separately authorized one-shot experiment. No baseline was authored, no run reserved/consumed, and no projection or Bootstrap controller was executed. Outer-host historical non-change remains unproven; crash prevention and storage integrity beyond observed recovery remain unqualified. Guest is deliberately left running.

Final handoff receipts: `handoff-v2.stdout`, `handoff-v2.stderr` and `handoff.json` retain the corrected staged-path/content/original-report checks, unchanged HEAD/refs and live process/strict-SSH boot/key verification. Final staging and `git diff --cached --check` receipts are in `commands.jsonl`.

## Five-line summary

Same phase2 overlay restarted: PID91972/start45353; exact argv, verified base/backing chain and old process record preserved.
Strict SSH confirms host fingerprint SHA256:rk1TQu4ncW/fxBUmvcFu/M3BbOKpqofLaf5glJ86WvA; machine-id and both Docker images survived.
Controller known_hosts aliases the single verified pin; dedicated lab key retained; all restored trust/port references inventoried.
Optimized Python is refused; post-hoc host snapshot and crash/memory guidance retained; tracked fixes staged only.
Guest left running; no Rust checks, commit/push/ref writes, host-setting changes, baseline, projection or Bootstrap/run409.
