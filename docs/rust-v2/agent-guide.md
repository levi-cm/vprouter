# Read-only native agent guide

This workspace provides an offline core and native observational preparation.
It does not contain a native guard, worker, activation helper, client guard,
service installer or applicable migration runtime. A schema-2 candidate is a
configuration artifact, not a runtime release. Existing legacy services and
identities are not changed by these commands.

Build from the repository root with the pinned Rust toolchain and Cargo.lock:

```console
cargo build --locked --offline --release -p vprouter
cargo fmt --all -- --check
cargo test --locked --offline --all-targets
cargo test --locked --offline --doc
cargo clippy --locked --offline --all-targets -- -D warnings
target/release/vprouter --help
```

Offline builds require the pinned toolchain and locked crates to have been
downloaded already. The CLI implementation launches no external processes.
The binary uses safe Rust, native files and a Unix-socket HTTP client.

Run the following commands as a user able to read the root-owned protected
configuration and profiles. The paths are operator-provided examples; these
commands do not install or create configuration, keys, directories or services.

```console
target/release/vprouter validate --config /etc/vprouter-v2/debdev.json
target/release/vprouter status --config /etc/vprouter-v2/debdev.json
target/release/vprouter probe --config /etc/vprouter-v2/debdev.json
target/release/vprouter diagnose --config /etc/vprouter-v2/debdev.json
target/release/vprouter migrate inspect --legacy-config /etc/vprouter/max-vprouter.json
target/release/vprouter migrate plan --legacy-config /etc/vprouter/max-vprouter.json --site debdev --expected-server de-fra-wg-404 --deployment-id debdev
target/release/vprouter migrate plan --legacy-config /etc/vprouter/max-vprouter.json --site debdev --expected-server de-fra-wg-404 --deployment-id debdev --output /root/vprouter-migration-plan.json
```

Only the last command can write a file, because `--output` was explicitly
supplied. Its parent must already exist and satisfy the protected-path rules.
The artifact is created exclusively with mode 0600, file fsync and parent fsync.
Existing files, symlinks and symlink parents are refused; no overwrite or
parent-directory creation occurs. A durability failure leaves the artifact for
operator inspection and returns an authored failure code.

Every ordinary success and failure writes JSON to stdout. Parser failures use
`invalid_arguments` without echoing argv. Only explicit help and version requests
write ordinary static text. Schema/profile validation exits 0 when no observed
preflight check fails; unknown checks remain visible and prevent host support
and readiness confirmation. Failed checks and incomplete inspections exit 2.
`status`, `probe`, `diagnose` and all current plans exit 2 because required
verification or runtime implementation remains incomplete. Machine-readable
`capabilities` includes `guard_runtime:false`, the implemented command list and
the exact missing command list.

The unavailable operations are `exit add`, `exit remove`, `exit enable`,
`exit disable`, `migrate apply`, `migrate resume`, `migrate rollback`,
`client install`, `client select` and `client status`. Clap rejects them. There
are no deployment, apply or rollback instructions for this implementation.

## Host checks and ownership

Native preflight checks Linux 6.1 or newer; x86_64 or aarch64; Debian 13 with
systemd, Arch/CachyOS with systemd, or Void glibc with runit; a cgroup-v2 mount;
and a root-owned TUN character device with Linux device number 10:200. PID 1
identifies the manager. The binary's GNU/musl compiler target is never used as host
evidence. This package has no reliable native host-libc probe, so Void adds an
explicit `void_host_glibc:NOT_TESTED` check and remains unverified. No glibc host
is rejected merely because the binary was built for musl. A module directory
or module list is not sufficient to
prove usable nftables or WireGuard. Those active kernel probes are always
`NOT_TESTED` here. Unknown checks prevent `host_supported:true` and activation.
The real `/opt/vprouter/current` release directory is checked for ownership
without treating an existing legacy Python release as native runtime proof.

Protected paths are opened from `/` with descriptor-relative `openat`,
`O_NOFOLLOW` and type checks at every component. Ancestor directories and
release directories must be root-owned and not writable by group or other.
Configuration files must be regular root-owned files without group/other
write access. Profiles, enrollment files and legacy configuration require
permissions no broader than 0600 and one hard link. Private state and per-exit
health directories require permissions no broader than 0700. Special mode bits
are rejected. Key files are parsed using the strict core profile parser, and
no key bytes are serialized. Enrollment files and Tailscale state bytes are
never read by this host layer. Protected readers never create or lock paths.

The root-owned Docker socket uses `/run/docker.sock`, the normal resolved
location of `/var/run/docker.sock` on supported hosts. The `/var/run` symlink is
not traversed. Socket and TUN permission bits have their usual device-access
meaning; their root ownership, exact type, trusted parents and TUN device number
are checked. Normal group-writable Docker socket modes are accepted. No
production option bypasses ownership checks or changes diagnostic paths.

Docker requires Engine 26.0 or newer with API 1.45 inside the daemon's supported
minimum/maximum API range. A GET `/version` negotiates compatibility; inventory
then uses explicit `/v1.45/containers/...` GET endpoints. Hyper parses HTTP,
including chunked responses. Redirects and non-200 responses fail. Each response
has a 1 MiB body cap, a 16 KiB HTTP receive buffer bound, 3-second connect,
header and body deadlines and an outer 9-second request deadline. Full inventory
also has a 9-second total deadline and a 128-container bound. Daemon mutations
and Docker exec are absent.

Inventory projects container ID, validated name, image digest, PID/start time,
state/restarts/OOM, mount references, NetworkMode and scoped vprouter ownership
labels. It drops environment variables, raw Config/State, foreign label values
and external error text. Invalid names are redacted. Observing an existing name
does not prove container or namespace ownership.

## Observational status

`status` and `probe` perform the same observational work. They never quarantine,
stop, rebind, select a node, run an active provider test or write allocation
records. They read only an optional root-owned 0600 health snapshot at
`/run/vprouter-v2/<deployment>/<exit>/health.json`; its per-exit directory must be
0700. Missing, untrusted, stale or mismatched snapshots cannot imply readiness.
Disabled exits report `disabled`. Direct mode always reports `direct-exposed`,
including when disabled or unverified. Mullvad reports `unverified`.

The strict version-1 snapshot envelope binds deployment ID, stable exit ID,
mode, display name, expected server, canonical configuration SHA-256 and current
Linux boot ID. Evidence timestamps use seconds since boot from `/proc/uptime`.
The configured client policies must supply one consistent expected node ID;
the snapshot cannot authorize its own node identity. Core evidence validation
checks freshness, handshake aging, exact server/node, structural/provider
results and negative DNS/IPv6 results. A valid snapshot is identified separately
with `source:"cached"`, `snapshot_valid:true` and an optional cached verification
age. It does not reconstruct a recovery streak or prove current resource
ownership. Status never emits a protected or READY native runtime state, even
from a valid snapshot: native guard liveness and ownership proof do not exist.
DNS and IPv6 verification remain `NOT_TESTED` in command status output. A legacy
Python guard or legacy health snapshot supplies no native readiness evidence.

## Legacy inspection and review plans

Legacy JSON is strict: exactly `name`, `profile`, `state_dir`, `image_ref`,
`compose_dir`, and optional string `tailscale_hostname`. Unknown/duplicate fields,
unsupported versions, invalid names/paths and unpinned images are rejected.
Schema-2 input is reported as `already_v2`. Inspect never reads a WireGuard key
or Tailscale state. Planning reads the operator-selected protected profile using
the explicitly supplied expected server and the core parser. No real credential
files were read during implementation tests.

Inspection inventories protected profile/state metadata, the compose release,
the current real release and bounded release history; hashes an explicit list
of known release code files; inventories known systemd/runit units and bounded
systemd drop-in files; projects the collector's declared `suggestions_compose`
path; and obtains primary/uplink/dependent container metadata from Docker.
Unknown files, unsupported collector fields, missing vendor units, truncated
inventories, undeclared hooks and unknown ownership remain review gaps. No
hook or adapter executes. No broad journal or environment data is collected.

Plans retain the original profile, state directory, pinned image, container and
service names under stable exit ID `primary`. The proposed hostname is validated
using the core formula, such as `mullvad-debdev-exit-de-fra-wg-404`; the old and
new hostnames are separate fields. Paths and identity metadata represent state
without reading or copying identity bytes. Profile binding includes the expected
server, endpoint and a hash of public configuration fields only. A secret file's
opaque hash and private/public key bytes are not serialized. The legacy config
hash is permitted because its strict fields contain configuration references,
not secret contents.

The version-1 plan has strict nested schemas and stable field/vector ordering.
`content_sha256` hashes compact canonical serialization of `content`, excluding
the fingerprint itself. It is an unchanged-content check, not a signature or
proof that a plan is applicable. No current-time field changes repeated plans;
changed observed metadata or container identity correctly changes the plan.
Configuration/profile metadata, public profile binding, release/unit hashes and
container ID/PID/start time are captured as future unchanged preconditions.
The ordered steps describe quarantine, adapter drain/stop, verified identity
shutdown, root-only durable backup, transactional real-directory activation,
same-identity verification before rename, actual-client acceptance, commit and
quarantine-first compatible rollback. These are review requirements, not
implemented commands.

Every plan is `applicable:false` and `verification_complete:false`. Blockers
include the missing apply/guard runtime, kernel feature tests, node identity,
adapters, client coverage, hostname dependency declarations, compatible rollback,
migration interruption tests, immutable native release checksums/provenance and
ownership proof. Missing observations add blockers. No concurrent identity copy,
implicit direct exit or credentials are produced.

`diagnose` emits authored statuses, capabilities, preflight checks and a
`NOT_RUN` acceptance manifest. Single/five/direct/mixed real-client tests,
positive capture controls, fault matrix, boot-capture reboot, 24-hour soak,
performance comparison, second local legacy deployment, independent unsafe-launcher
review and architecture artifacts/SBOM/provenance remain unperformed. Tests of
synthetic profiles and mock APIs provide no runtime or performance claims.
