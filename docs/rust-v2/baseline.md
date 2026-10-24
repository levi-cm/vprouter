# Rust v2 legacy baseline — 2026-10-24

This package records compatibility and short read-only observations. It does
not activate Rust, change production, establish migration safety, or satisfy
the performance/security/canary acceptance gates in `IMPLEMENTATION.md`.

## Verified source and runtime

| Item | Fresh finding |
| --- | --- |
| Worktree base | `84fb353b128c0b6f7ca222be9cd3934183a4e34a` |
| Retained retry repair | `528feced48f14fd46d48da0abdd64a2587e42b4f` |
| GitHub fork `main` | `e135adacd33501422fb24ba3ef2bce8693956557`; checked with `git ls-remote https://github.com/levi-cm/vprouter.git refs/heads/main` |
| Release | `/opt/vprouter/current`, a real root-owned mode-0755 directory |
| Live unit | `vprouter@max-vprouter.service`, active/running; PID 1300649; zero service restarts |
| Containers | `max-vprouter`, `max-vprouter-uplink`: running, zero restarts, OOM false before/after sample |
| Container image | `sha256:62c283e6a4d350992ed2b9a99a48c7834e60e1c9af92f9e1699a2b2d0c920de3` for both |
| Tailscale | `1.102.5`; commit `5fb2a81b065b0a0bbbfc67ab20a0d9c6a1108115`; long version `1.102.5-1-t5fb2a81b0`; Go `go1.26.6` |
| Host | Kernel `6.12.107+deb13-amd64`, cgroup v2 (`cgroup2fs`) |

`baseline-source-inventory.json` records fresh SHA-256 comparisons for the
runtime, firewall, Dockerfile, Compose file, host supervisor, systemd template,
and collector files. All eight match this baseline checkout byte for byte.
This compares deployed **source** files, not every byte of the OCI image.
The image ID is selected Docker metadata. No entire Docker configuration,
environment, identity, private site configuration or provider profile was dumped.

The merged source records that `/DATA/AppData/vprouter-first-site` supplied
the deployment; `/DATA/AppData/vprouter` is an older checkout. The fresh release
hashes establish the relevant correspondence independently of checkout names.
Upstream `e135ada` lacks the local bounded retry; `528fece` preserves it and
the upstream provider-data return value required by the collector probe.
`84fb353` adds the integration assessment. Nothing was pushed upstream here.

The Dockerfile pins Tailscale source stage
`tailscale/tailscale@sha256:c507f3a2a6ab1cabd8d809b98edeb41edbd5c3fb6ad9632ffd098b4c7d0b4065`
and Alpine base
`alpine@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b`.
These pins and the observed version must be reconciled when producing v2
artifacts; this task does not rebuild or attest the image.

## Legacy contract and fixtures

`tests/fixtures/legacy/README.md` describes every synthetic fixture and its
limitations. Fixture JSON uses the exact legacy field shape, with separate
provenance documentation. Addresses are documentation ranges; keys encode
32 zero bytes and 32 one bytes. No production paths/identity/config values
were copied into these fixtures.

`host/orchestrate.py` requires unversioned `name`, `profile`, `state_dir`,
`image_ref`, `compose_dir`; only `tailscale_hostname` is optional. Extra/missing
fields fail. Image must be a digest/image ID; all three paths are absolute;
name/hostname match `[a-z][a-z0-9-]{1,49}`. Missing hostname defaults to name.
The profile must have exactly one Interface and Peer, valid 32-byte keys,
IPv4 /32 address, IPv4 default AllowedIPs and numeric IPv4 endpoint/valid port.
Legacy parser does not identify an expected provider server from a filename.
The synthetic fixtures must remain readable without assuming live profile
basenames encode a server. There is no schema version, deployment/site ID,
exit list, direct mode, client policy, adapter ownership or allocation record.

Legacy commands and outputs:

| Command | Success contract / limits |
| --- | --- |
| Host `validate --config PATH` | JSON `name`, `endpoint`, `image_ref`, `state_dir`; parses a profile, never emits keys |
| Host `status --name NAME` | JSON `name`, `state: READY`, `heartbeat`, only after checked ownership/firewall/tunnel/fresh runtime health |
| Host `serve --config PATH` | Mutating provisioning/monitor lifecycle; not an observational command |
| Host `cleanup --name NAME` | Quarantine first, stop verified owned containers; not invoked here |
| Runtime `--status` | No JSON; exit 0 only for READY and integer heartbeat age 0–44s, otherwise 1 |
| Runtime `--probe` | JSON `public_exit`, `relay`, `tunnel_healthy`, `dns_guard`, `ipv6_guard` after provider and Tailscale checks |
| Health file | JSON `state`, `reason`, `time`, `heartbeat`; state write time and heartbeat may differ |

Host CLI failures return exit 1 with safe stderr, or argparse exit 2 for CLI
misuse. `STARTING`, `BLOCKED`, `RECOVERING`, `READY` are fresh legacy heartbeat
states; only READY succeeds for status. Legacy probe guard booleans are
unconditional constants after checks, not separately observed client evidence.
The v2 observational CLI must avoid presenting these as fresh client results.

**Do not invoke legacy host status as a read-only inventory:** detected guard
or router-policy drift can install host quarantine. This task read its source
and selected metadata rather than invoking it. No live provider/network probe
or fault test ran; current protected-client egress remains `not_tested` here.

## Retry and monitoring behavior to preserve

Provider HTTPS check has a 12s timeout, validates provider JSON object and
`mullvad_exit_ip is True`, and returns its JSON for the collector probe. A first
HTTP 408/429/5xx, URL transport error, timeout or connection error gets one
retry after 1s. Interfaces, IPv4/IPv6 defaults and handshake are rechecked
after failure and before retry. A second failure, permanent HTTP failure,
malformed/negative response or unsafe structure escapes fail closed. HTTP
status is logged without URL/body. Handshake age must be below 180s.

The provider scheduling interval is 5s, host monitoring sleeps 2s, runtime
main loop sleeps 5s, heartbeat must be younger than 45s, and systemd watchdog
is 90s. These are source constants/behavior; no scheduling latency guarantee
is inferred from the short sample. Existing Python does not bind successful
provider responses to an exact expected server; v2 must add that requirement.

## Hooks, dependencies, ownership and rollback limits

`host/collector-services.conf` adds pre-start stop/post-start start/post-stop stop Python hooks
and 180s startup timeout. `collector_services.py` uses hard-coded
`immo-mullvad-1`, `immo-collector-v4.service`,
`pfarr-dietl-app-suggestions-1`, and Compose project `pfarr-dietl-app` with
`suggestions_compose` read from its private JSON. It stops the collector and
suggestions container, waits up to 120s for router runtime status, recreates
suggestions and asynchronously starts the collector. These are installation
specific dependencies, not generic adapters. No config was read and no hooks
were executed. Fresh `systemctl show ... DropInPaths` is empty for the current
max-vprouter unit, agreeing with the integration note that optional hooks
target another installation and are disabled here. This does not establish
that no external hostname/namespace consumers exist. Their ownership and
drain/rebind/health behavior remain undeclared: unattended cutover is blocked.

Legacy ownership checks require root-owned private config/profile/state paths,
reject direct symlinks and writable/symlink parents, and protect release paths.
The current release is a real directory, which v2 activation must preserve.
Containers are checked by exact name and Compose project label before and
after stop; running state is rechecked. This lacks stable allocation records,
generation checks and full container-ID/PID/root/cgroup/namespace binding.
Bridge `br-vpr-uplink`, subnet `10.255.240.0/29`, transport `.2`, and host
`vprouter_guard`/`vprouter_quarantine` table names are global single-router
resources. They cannot safely implement simultaneous independently owned
v2 exits without an explicit resource/ownership model. Cleanup keeps quarantine
on uncertain container stops, but is not a migration transaction.

`VERIFICATION-GITHUB-MERGE-2026-10-24.md` describes historical/manual rollback:
stop, restore previous source and original site JSON, restart while preserving
the current Tailscale state. Fresh metadata checks confirm the retained
`/opt/vprouter/releases/2026-10-24-retired-live` and
`/opt/vprouter/releases/2026-10-24-pre-github-merge` directories (root, 0755),
and evidence directory `/var/lib/vprouter/evidence-2026-10-24-github-merge`
(root, 0700). The retained image tag resolves to
`sha256:2aea51e2f3ee30a7fcc451b71bd1a2055061e3df29c75c59bf5fef6dc73e3931`.
No backup contents were opened, copied or restored; restore compatibility
is unverified. The earlier repair record names a stopped-state backup and
source snapshot but is historical evidence only. Neither record proves the
new required transactional release+state rollback, interruption recovery,
quarantine/client coverage or same-identity restoration. No rollback was run.

## Fresh short resource sample

`baseline-resource-sample.json` contains 21 snapshots across 20.0001 seconds,
starting `2026-10-24T11:43:44.095960+00:00`. Reproduce the same read-only
measurement using `sudo -n python3 tools/baseline-resource-sample.py`.
It reads selected PID metadata, cgroup CPU/memory/events, process `comm` and
smaps RSS/PSS. It never reads process argv/env or private config. Snapshot
collection traverses each selected cgroup's descendants.

| Scope | CPU % of one core | Mean PSS KiB | Max PSS KiB | Mean cgroup memory bytes |
| --- | ---: | ---: | ---: | ---: |
| Host guard cgroup | 3.8764 | 11,020 | 11,020 | 15,220,541 |
| Router cgroup (Python + tailscaled) | 1.8596 | 92,871.6 | 92,875 | 77,433,320 |
| Uplink cgroup (sleep) | 0 | 430 | 430 | 348,160 |

The first snapshot contains host Python PID 1300649 (11,020 KiB PSS), router
Python PID 1300984 (21,155 KiB), tailscaled PID 1301394 (71,716 KiB), and
uplink sleep PID 1300874 (430 KiB). Cgroup CPU includes exited short-lived
monitor children; one-second PSS snapshots can miss them. Cgroup memory
charges and process PSS account shared pages differently and are not additive
equivalents. No cgroup OOM events changed; final service/container metadata
still showed running with zero restarts and OOM false.

Workload was existing uncontrolled traffic, without a traffic generator.
Docker daemon/containerd/shared shims, kernel/shared system overhead, observer
overhead, external clients, WAN throughput and latency are excluded. Thus this
is a scoped live process baseline, not full system overhead accounting.

**Mandatory repeated 10-minute same-workload performance acceptance: NOT_RUN.**
One/five/six exits, repeated controlled runs, total-memory accounting,
supervision CPU reduction >=50%, control-PSS 16/48 MiB targets, throughput
>=95%, p95 latency <=105%, monitor misses, restart/OOM behavior, and 24h soak
remain unverified. Short observations cannot establish those thresholds.

## Validation and remaining gates

- Existing suite: `python3 -m unittest discover -s tests -q`: **50 passed**.
- Synthetic fixture suite: `python3 tools/baseline-verify-fixtures.py -q`:
  **4 passed**, with temporary files and mocked provider/status observations.
- JSON parsing and `git diff --check`: pass before commit.
- Production faults, migration, namespace/packet tests, performance acceptance,
  multi-exit/direct/client isolation, independent acceptance and canary: NOT_RUN.

The package changes only baseline documentation, synthetic fixtures and
read-only/offline baseline tools. It leaves all runtime and service files alone.
