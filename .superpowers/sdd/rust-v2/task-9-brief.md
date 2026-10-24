# Independent multiple-Mullvad-exit lifecycle integration

PREPARATION ONLY. Dispatch after task6b, task7 and actual single-exit task8
independent review. Workdir /DATA/AppData/vprouter-rust-v2, rust/v2, no subagents.
Binding docs/rust-v2/IMPLEMENTATION.md and user implementation handoff. Read
reviewed component reports and task8 actual guard/lifecycle contracts before
choosing a minimal integration change. This brief supplies no activation bypass.
Root controller alone runs credential-bearing/privileged owned-guest tests.

Deliver independent lifecycle for one or five explicitly enabled Mullvad exits
inside ONE gateway container and one independent Rust host guard. Preserve the
primary base NETWORK namespace and compatibility names; additional data networks
are separate, never bridged or routed through primary. Each exit retains its own
worker/tailscaled, private PID/mount/state view, socket, health state, data policy,
WireGuard and independent transport namespace/host connection. Reuse reviewed
launch authority, quarantine, protocol and manifest contracts, not caller proof
booleans or optional verification flags. Single-exit execution must allocate no
placeholder workers/namespaces/timers/state for absent exits.

Create each WireGuard interface in its selected transport namespace then move to
its selected data namespace. Overlapping inner tunnel addresses and shared
provider endpoint must work without assuming fleet-wide inner-IP/endpoint
uniqueness. Duplicate private keys, identities, state directories, owned resource
names/subnets remain refused before runtime mutations. Workers cannot inspect or
open another exit state/proc/root/socket/namespace handles. No cross-exit HTTPS
connection pools or sockets; namespace-local clients only after placement.

Guard keeps durable allocation/generation/ownership locks and reconciles
interrupted scoped transactions. Quarantine before usable transport and policy
before Tailscale. Worker crash/freeze, stale/wrong provider/server/handshake,
namespace/firewall/route drift and restart for one exit quarantine that exit and
leave healthy exits stable. Container-wide failures invoke independent emergency
quarantine. Cleanup failure or ambiguous foreign resources retain quarantine and
stop rather than prefix-delete/adopt. No unrelated Docker/service/firewall changes.

Implement explicit exit add/remove/enable/disable JSON transactions using existing
validated schema. Disabled exits reserve identities/state/resources as documented;
removal must not delete credentials or identity state. Server pin changes require
explicit configuration transaction and matching hostname reconciliation. Naming
mullvad-{site}-exit-{server}, required site debdev here; duplicate generated names
append both stable exit IDs, DNS-label <=63 without truncation. Stable IDs/state
paths never derive from names. No direct mode or automatic provider/server
fallback introduced. Unknown/malformed/unavailable witness remains unready.

Cadence5s, deterministic bounded per-exit staggering, handshake<180s, health<45s,
watchdog90s; one retry after1s for transient failures with fresh structural checks.
One blocked API/provider/exit must not starve another exit enforcement. Keep
explicit memory/timer/process ceilings and measure actual overhead later rather
than equate limits with savings. Status/probe observational, no enforcement side
effects, independent DNS/IPv6 evidence or not_tested.

Normal tests offline/loopback: actual scoped transition/protocol/transaction and
interrupted-write behavior, duplicate keys/state/resources, mode/server/name
reconciliation, isolation token refusal, cancellation and deadline scheduling.
Ignored owned-guest tests: one and five synthetic WG exits with same endpoint,
overlapping tunnel addresses and distinct synthetic keys; continuous distinct
packet markers and independent positive capture controls; destroy/freeze/restart
one exit, mutate route/rule/policy/interface, kill gateway and fail Docker/API,
assert healthy exits remain unchanged and no cross-exit/plaintext path. Adversarial
private proc/state/socket/FD tests for every exit, full exact-owned cleanup and
interrupted transactions. Root may separately import five distinct-device profiles
from protected supplied ZIP for later actual provider/Tailscale-client testing;
never clone approved identities or copy production state. Synthetic tests do not
meet mandatory real-client release gates.

Own minimal guard/CLI/core integration and focused tests/docs. All unsafe Linux
operations stay in the single reviewed module, no steady-state shell/CLI, no
unreviewed privilege/policy expansion. Focused fmt/tests/clippy and static x86_64/
ARM64 checks, explicit owned-file commits and self-review. Report task-9-report.md
with source/artifact hashes, exact commands/results, actual scoped kernel evidence,
remaining unavailable checks and compatibility behavior. Independent review before
direct-mode implementation or production activation.
