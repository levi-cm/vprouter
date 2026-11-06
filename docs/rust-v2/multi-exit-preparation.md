# Task 9 offline multi-exit preparation

Task8c acceptance remains OPEN, including the run410 witness I9/I10/M2 gaps,
runtime, ARM and client gates. This package supplies library policy and offline
configuration transactions only. Task10 extends the same APIs for explicit
mixed/direct fleets; see [direct-exit-preparation.md](direct-exit-preparation.md). It grants no native activation, launch,
quarantine-release, readiness or cleanup authority. No production CLI command,
service or runtime import path consumes the preparation snapshot.

`vprouter_core::transaction::ExitChange::parse` accepts strict bounded JSON:

```json
{"operation":"add","exit":{"id":"second","enabled":false,"state_dir":"/private/second","mode":{"kind":"mullvad","profile":"/private/second.conf","expected_server":"de-fra-wg-003"}}}
{"operation":"remove","exit_id":"second"}
{"operation":"enable","exit_id":"second"}
{"operation":"disable","exit_id":"second"}
{"operation":"pin_server","exit_id":"second","profile":"/private/second.conf","expected_server":"de-fra-wg-404"}
```

`PreparedFleet::initial` and `FleetRecord::prepare` reuse the schema2 validator,
profile/key parser and deterministic allocation contracts. The reader injection
has the existing `Configuration::validate_with` trust boundary. Actual native
integration must use the reviewed no-fork secret loader and retained authority;
a library profile reader or public binding never substitutes for those receipts.
Every member, including disabled members, is revalidated before a prepared value
exists. Duplicate effective private keys, stable IDs, overlapping state paths,
resource names/subnets, supplied foreign claims and reused client node IDs across
exits refuse. The allocation pool collision policy is unchanged. Inner tunnel
addresses and provider endpoints may overlap; transport /30s must be distinct.
Client-policy references cannot dangle after removal. The binding schema requires
at least one configured exit; disable the last exit instead of removing it.

Hostname calculation remains `mullvad-{site}-exit-{server}` for provider exits;
Task10 uses `unsafe-direct-host-ip-{site}-exit` for explicit direct entries. Every colliding name
gets its own stable exit ID suffix, including disabled entries; no truncation.
`PreparedFleet::renames` reports all resulting hostname changes, including a
previously existing peer gaining or losing a suffix. Resource/state identity
always uses configured stable IDs. Pinning a server is explicit and produces a
hostname reconciliation obligation. Native stop/restart and actual daemon rename
are gated future work; the transaction does neither.

`AllocationStore` provides `commit_preparation`/`read_preparation` on its existing
exclusive allocation flock. An existing live `allocations.json` refuses a
preparation commit. The new `fleet-preparation.json` contains schema1 envelope,
complete schema2 configuration and matching allocation snapshot in ONE atomic
file. A generation increment AND previous canonical-record SHA256 must match.
The existing descriptor-relative root0700/root0600 checks, O_EXCL temporary
creation, file fsync, rename and directory fsync are shared with allocation
storage. An error after rename is `durability_uncertain`: reopen/read before
retry. Orphan temporary files remain untouched; a missing commit stays absent,
and malformed committed files refuse rather than reset. Reads validate public
shape; each subsequent preparation revalidates all profiles. No credential/state
file is removed, renamed or copied when an exit is removed. This is not a
native durable transaction journal or filesystem power-loss acceptance.

`vprouter_core::fleet::FleetPolicy` validates the entire allocation and public
expected bindings before planning actions. Bindings include exact deployment,
generation, ID, display name, mode/server, boot, canonical schema2 configuration
SHA256, node identity and host-assigned lifecycle. Disabled identities/lifecycles
stay reserved. Supplied bindings are data, not authenticated witness authority.
Only explicitly enabled exits have health machines, sessions and deadlines.
At most six are active (at most five Mullvad); up to128 configured reservations use the existing
schema ceiling. Single-exit offset is zero and absent exits have no slots.

Non-clonable correlation tokens bind the exact policy instance, exit and process
epoch. Foreign-instance, wrong-exit wire binding and old-epoch tokens refuse.
Explicit blocked-exit restart requires a fresh lifecycle and invalidates its old
tokens. All retired lifecycles stay reserved up to1024 per policy instance;
exhaustion refuses restart and retains blocked state. Re-admission after that
budget requires future ownership/lifecycle reconciliation, never a silent reset.

Health observations reuse `health::Session`, `Snapshot`, and `HealthMachine`.
The host reconstructs each three-success/RECOVERING/subsequent-READY transition;
a received READY flag cannot skip the streak. Malformed, unknown, replayed,
wrong-binding and expired observations block only that exit. Session expiry
uses its existing44s margin below45s and exact handshake<180s deadline;
heartbeats cannot extend verification. DNS/IPv6 remain independently not_tested
until observed. No server/provider fallback is added. Task10's explicit direct policy is an
offline extension only; native direct paths remain unavailable.

`poll` performs no I/O. It checks all exits and returns quarantine/stop actions
BEFORE sample actions, even with a peer sample in progress. Per-exit offsets are
deterministic within5s, missed ticks are skipped and samples never overlap in a
slot. Completion discards elapsed in-flight ticks and resumes at the next stable
stagger slot (a slot exactly at completion remains eligible); it never replays a
missed tick as catch-up work. In-flight work expires at34s independently of its
completion. The reviewed worker still owns its single eligible retry after1s
with fresh structural checks;
this scheduler never repeats whole failed samples. Guard-loop absence>=90s,
backward/nonfinite host clock or container failure produces terminal emergency
quarantine-and-stop actions for every active exit. All operational callbacks
with `now` (`observe`, `observe_bytes`, `sample_finished`, `restart`, `poll`, `reconcile_direct_host`)
validate it against one host-time high-water mark, including malformed wire
input; worker timestamps remain untrusted per-exit evidence. Only enforcement
polls renew the guard watchdog. Cleanup ambiguity is terminal for its exit.
Late observation, completion, restart, worker-failure, cancel and cleanup
callbacks cannot weaken emergency state or re-arm drained emergency actions.
Status and deadline queries are observational; they perform no enforcement.

Limits bound policy slots and action lists (at most12 actions per poll), retained
lifecycle IDs and wire frames. No new process, timer, pool or thread is started.
These limits are not measured overhead/savings or realtime scheduling evidence.
A future native driver must retain per-exit launch/guard authority, apply each
quarantine before dispatching usable work, use separate namespace-local workers
and clients, and service independent enforcement while operations are blocked.
Returned actions do not prove this driver exists or that quarantine was applied.

`tests/fleet_owned_guest.rs` contains four ignored acceptance specifications.
They deliberately panic if forced because the admitted native harness does not
exist. One/five-exit capture, overlapping-IP/shared-endpoint, adversarial
proc/root/state/socket/FD, crash/freeze/kill/drift, Docker/API failure and exact
cleanup/interruption checks are NOT_RUN. No synthetic/unit success constitutes
runtime, real-client, ARM execution, migration, performance or release acceptance.
