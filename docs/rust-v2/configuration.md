# Rust v2 offline configuration reference

This is the task-2 library contract. It creates no namespaces, interfaces,
firewall rules, services, containers, clients or identities. Passing validation
is not runtime acceptance. The Python implementation remains unchanged.

## Input and stable identity

Call `Configuration::parse(bytes)` then `validate()` to load profiles without
following symlinks, or `validate_with(reader)` to inject offline profile bytes.
The injected reader returns `Profile`, takes the exact configured server, and
must preserve the same no-symlink and sanitized-error boundary as the built-in
reader. The validated result is immutable through public references.

JSON objects reject unknown and duplicate fields, including fields belonging to
a different tagged mode. Inputs are bounded to 1 MiB. Required arrays must be
present, including empty arrays. Unsupported schema versions, a blank/empty
fleet, more than 128 exits, more than 128 adapters and more than 1024 client
policies are rejected. No automatic fallback field exists.

| Configuration field | Required value |
| --- | --- |
| `schema_version` | Integer `2` |
| `deployment_id` | Stable lowercase DNS label, 1–32 bytes |
| `site` | Explicit lowercase DNS label, 1–63 bytes; generated hostname must also fit |
| `gateway_image` | `sha256:` plus 64 lowercase hex digits, or `repository@sha256:` plus that digest |
| `exits` | Nonempty array of up to 128 exit objects |
| `dependency_adapters` | Array of explicitly declared external consumers |
| `client_policies` | Array of explicit stable-node selections |

Labels start/end with lowercase ASCII letters or digits and may contain `-`.
Repository paths are lowercase OCI-style components; tags, empty components,
malformed separators, empty repositories and invalid registry ports are rejected.
A syntactically valid digest does not authenticate an artifact or approve a
release. Release digest verification belongs to later work packages.

`deployment_id` and each exit `id` are permanent resource identity. Array order,
site, server display name and generated hostname never determine identity or
state paths. Preserve IDs and `state_dir` when renaming a node or changing
presentation. Runtime mode/state changes require an explicit stopped
reconfiguration. Enrollment cloning and replacing an existing node's state are
not supported by this library.

| Exit field | Required value |
| --- | --- |
| `id` | Unique stable lowercase DNS label, 1–32 bytes |
| `enabled` | Explicit boolean |
| `state_dir` | Absolute lexical canonical directory; `/` forbidden |
| `enrollment_key_file` | Optional absolute path, or null; no credential content |
| `mode` | Exactly one tagged object below |

Paths reject relative components, repeated/trailing `/`, `.`/`..`, NUL and
non-UTF-8 representations. All state directories must be distinct and neither
ancestors nor descendants of another exit's state directory. Disabled exits
still reserve IDs, state paths, private keys and hostnames. State paths are
operator inputs, never generated from hostnames.

Mullvad mode:

```json
{"kind":"mullvad","profile":"/private/de-fra-wg-003.conf","expected_server":"de-fra-wg-003"}
```

Direct mode:

```json
{"kind":"direct"}
```

Direct mode rejects `profile`, `expected_server`, and all other extra metadata.
The Mullvad server uses the country-city-`wg`-number syntax, including real
zero-padded numbers such as `003` and `002`. Its exact spelling is preserved.
Syntax validation is not a live catalog lookup. Provider/server/endpoint
attestation is a later runtime gate.

## Display names

The exact unsuffixed names are:

- `mullvad-{site}-exit-{expected_server}`
- `unsafe-direct-host-ip-{site}-exit`

When multiple exits generate the same base name, **every** colliding name gets
`-{id}`. Disabled exits participate. All final names must be unique lowercase
DNS labels of at most 63 bytes. A suffixed name colliding with another final
name is rejected. Names are never truncated.

## Profiles and secret boundaries

Profiles are limited to 64 KiB, UTF-8, exactly one `[Interface]` followed by one
`[Peer]`, with no duplicate fields or repeated sections. Supported fields are:

| Section | Fields |
| --- | --- |
| Interface | Required `PrivateKey`, `Address`; optional `DNS`, `MTU` |
| Peer | Required `PublicKey`, `Endpoint`, `AllowedIPs`; optional `PersistentKeepalive` |

Keys are canonical base64 encoding exactly 32 nonzero bytes. A private key is
never `Debug` or `Serialize`; a parsed `Profile` and validated fleet also have no
such implementations. Duplicate private keys across the entire configured
fleet, including disabled exits, are rejected with a fixed code; no key or
fingerprint is included in errors. Different server files exported from one
Mullvad device often share a key and therefore cannot serve as independent
exit identities.

An IPv4 `/32` address is required. IPv6 `/128` address entries may be present
and are parsed, but are not used for forwarding. The original file is never
rewritten. The peer endpoint is a literal public unicast IPv4 address and
nonzero port. Hostnames, private, loopback, link-local, carrier NAT and reserved
IPv4 destinations are rejected. `AllowedIPs` must contain `0.0.0.0/0`.
`DNS` values, if present, are IP literals; `MTU` is 576–9000; keepalive is an
unsigned 16-bit integer. Commands such as Pre/PostUp/Down, unknown directives,
extra peers, inline shell commands and unrecognized fields are rejected.

`expected_server` is required even with a generic filename. An explicit
`# Server:`, `# Mullvad server:` or `# Server =` comment and a filename stem
matching server-ID syntax must each match it. `# Name =` and `# Device:` are
device labels and do not authenticate a server. `has_matching_server_hint()`
only indicates matching untrusted metadata. Comments, filenames and profile
parsing cannot authenticate the endpoint/server association or private key's
account ownership. Those require runtime provider/catalog evidence. A generic
`max-vprouter.conf` without a server comment is accepted with the explicit pin
and reports no matching hint.

Built-in profile reading walks each directory through file descriptors using
`O_NOFOLLOW`, then opens only a regular file with a bounded read. No symlink
component or final secret symlink is followed. Profile/enrollment ownership and
permission enforcement on the production host remains the Linux crate's gate;
the core does not claim that lexical configuration validation proves protected
file ownership. Enrollment files are not opened in this offline package.

All public errors carry only the authored `Reason` enum. Raw serde input,
external errors, file paths, profile contents and keys never enter error text.
Do not put credentials in adapter argv, user-generated node IDs or other public
configuration fields.

## Adapters and client policies

Every adapter has unique `id`, plus required `drain`, `stop`, `rebind`, `start`
and `health_check` actions. Each action has:

```json
{"executable":"/usr/libexec/consumer-adapter","argv":["drain"],"timeout_seconds":30,"idempotent":true}
```

`executable` is an absolute canonical path. Shell executable names are rejected.
`argv` is an array of at most 64 strings, each at most 4096 bytes without NUL;
it is never interpreted by a shell. Timeouts are 1–300 seconds and the explicit
idempotence declaration must be true. Validation does not execute the adapter
or prove its implementation idempotent; the migration gate must verify that.

Each client policy has unique label `id`, `exit_id` referring to a configured
exit, `selected_node_id` containing the actual stable node identity (1–128
ASCII alphanumeric, `-` or `_`), explicit `mode` (`protected` for Mullvad,
`direct` for direct), and `dependency_adapters` containing unique existing
adapter IDs. Mode mismatches and dangling/duplicate references are rejected.
A display name cannot substitute for a stable node identity.

## Health state and observational status

The state machine begins in `STARTING`. Each successful observation requires
fresh, strictly increasing provider and structural timestamps plus a fresh
heartbeat. Three consecutive distinct successful observations transition to
`RECOVERING`; they cannot transition directly to `READY`. A subsequent valid
observation reaches `READY` only with online status, explicit policy approval,
the exact expected server (none in direct mode), the exact stable node ID,
public IPv4 egress and a fresh verification timestamp.

Failures clear the streak and immediately enter `BLOCKED`; fatal failures enter
`FAILED`. `FAILED` cannot recover through observations. `STOPPING` rejects
observations. Mode changes require `stop()` then explicit `reconfigure()`;
reconfiguration starts again in `STARTING`. A block never changes mode.
The caller must provide a consistent monotonic clock for all evidence.
Handshake age is measured at `structural_at` and continues aging when cached
status is read; a nearly expired handshake cannot borrow the heartbeat window.

Evidence validation rejects negative, nonfinite, backward and future times,
stale observations, a handshake age of 180 seconds or more, wrong server/node,
nonpublic egress, and explicit DNS/IPv6 failures. Heartbeat, provider, structural
and verification age must be strictly less than 45 seconds. Cached readiness is
rechecked when `status(now)` is requested; stale READY evidence returns an
error and must be treated as fail closed by the caller.

DNS and IPv6 verification separately serialize as `verified`, `failed` or
`not_tested`. READY does not imply either check ran. Direct status always uses
exposure `direct-exposed`. Mullvad uses `protected` only with fresh READY
evidence, otherwise `unverified`. Host-egress comparison and actual packet
verification are runtime responsibilities; a public IPv4 literal alone does
not establish protection.

Constants: handshake 180s, staleness 45s, independent host watchdog 90s, provider
cadence 5s, eligible retry delay 1s. Deterministic per-exit offsets stay within
the existing 5-second cadence and return zero for one exit; the library starts
no timers or workers.

## Allocation records and atomic storage

Records contain `schema_version:2`, `deployment_id`, nonzero `generation` and
exit reservations with stable exit ID, mode, state path, data/transport namespace,
nft table, host/data interfaces, optional Mullvad WireGuard interface, and an
IPv4 `/30` transport subnet. Disabled exits retain reservations.

Resource names are deterministic from deployment + exit ID using a fixed stable
hash, with distinct prefixes; Linux interface names are at most 15 bytes.
Transport `/30`s are selected from `10.200.0.0/14`. The hash is an allocation
mechanism, not ownership authentication. Collisions fail closed; there is no
silent probing or reassignment. Before enrollment, select another stable ID or
explicitly plan a pool change if validation reports a collision. Moving to a
new pool later requires a versioned migration.

`validate(deployment, foreign_claims)` rejects wrong deployment/version, tampered
resource names, duplicate IDs/resources, overlapping state/subnets, and overlap
with supplied namespace/interface/table/subnet claims. Callers must supply
fresh host claims before resource activation; offline parsing cannot discover
live foreign resources. `matches_configuration()` accepts order/site/server
presentation changes and rejects mode/state/ID changes requiring explicit
reconfiguration. Record storage validates the internal schema independently.

`AllocationStore::open()` requires an existing root-owned `0700` directory with
root-owned, group/other-nonwritable ancestors. Every path component is opened
without following symlinks. Allocation and permanent lock files must be regular,
root-owned, `0600`, and have one hard link. Directory ownership/mode is rechecked
when locking and before record reads/commits. The current-user temporary-root
constructor exists only in `cfg(test)` unit tests.

A transaction obtains an exclusive **nonblocking** `flock`; contention returns
`lock_busy`. The lock file is never removed. Creation uses expected generation
`None` and generation `1`; updates use `Some(g)` and exactly `g+1`. An incorrect
expected/current generation returns `generation_conflict`. Writes use a unique
`create_new`/`O_EXCL` `0600` temporary file, write-all, file fsync, atomic rename,
then parent-directory fsync. Pre-rename failures preserve the committed record.
A parent-fsync error after rename returns `durability_uncertain`; inspect the
record before retrying. Unknown/incomplete temporary files remain untouched and
are ignored by reads; malformed committed records are rejected, never reset.
This package does not claim power-loss testing on every target filesystem.

## Build and verification

Rust 1.97.0 is pinned with minimal rustfmt/clippy. The core forbids unsafe code,
uses no shell/process execution and locks exact resolved dependencies in
`Cargo.lock`. Run from the workspace root:

```sh
cargo fmt --all -- --check
cargo check --offline --all-targets
cargo test --offline --all-targets
cargo clippy --offline --all-targets -- -D warnings
```

Examples are in [`examples/v2`](../../examples/v2/README.md). They contain
synthetic schema fixtures and a digest placeholder, not usable credentials or
an approved image. All runtime, client, migration, platform and performance
acceptance gates in `IMPLEMENTATION.md` remain unperformed by this package.
