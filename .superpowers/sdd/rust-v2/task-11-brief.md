# Persistent Linux client and userspace proxy guards

PREPARATION ONLY. Dispatch after reviewed single-exit, multi-Mullvad and direct
runtime integration (tasks8-10). Workdir /DATA/AppData/vprouter-rust-v2, rust/v2.
No subagents, production changes, real profile/state reads or external operations.
Root controller alone runs privileged tests in owned disposable environments.
Binding docs/rust-v2/IMPLEMENTATION.md and original user handoff; read reviewed
native nft, ownership and runtime contracts before implementation.

Deliver client install/select/status JSON operations for kernel Tailscale Linux
clients and userspace SOCKS/HTTP gateways. Install persistent enforcement BEFORE
protected workloads start. An ordinary service stop, Tailscale stop, lost selected
exit, route reset, restart or upstream failure must retain protection. Removing
the guard is a separate explicit administrative operation with ownership checks.
No transient direct path during install/select/reboot/recovery. Unknown policy,
node authorization, ownership or application scope leaves protected clients offline.

Protected policy selects stable node ID and explicit mullvad mode; reject exposed
direct nodes. Direct selection requires explicit direct mode AND authorized node
ID, with direct-exposed status; name match alone never authorizes exposure. Keep
identity/state distinct from names and preserve existing enrollment and approvals.
Do not clone enrolled state or require credentials in arguments/environment/logs.
Status is observational and reports tested DNS/IPv6 fields or not_tested, never
constant protection booleans or readiness inferred from route advertisements.

Kernel client enforcement must block ordinary WAN internet/DNS/IPv6 fallback for
protected applications. Allow encrypted Tailscale transport only from narrowly
identified daemon traffic using actual verified process/cgroup/socket authority;
never exempt all root, all UDP or all DNS. DNS must use selected authorized exit
path, no generic WAN DNS exception. Reconcile exact owned atomic nft policy and
selected-node/routing evidence continuously; drift quarantines before repair.
No broad foreign-table changes, blanket Docker rules or daemon restarts.

Userspace gateways bind only intended local listeners, preserve HTTP/SOCKS
semantics and always connect applications through the authorized Tailscale path.
On upstream failure drop/reject requests; no ordinary resolver or TCP fallback.
Handle bypassed/absent application proxy settings with a persistent enclosing
application guard, or explicitly refuse protected readiness when its scope cannot
be enforced. An application promise to use the proxy is not a no-leak mechanism.
Namespace-local sockets and DNS only, with bounded responses/deadlines and no
cross-exit socket pools. Keep secrets and auth URLs out of support evidence.

Use native Linux/Tailscale APIs and reviewed ownership/state primitives. No
steady-state subprocesses, unsafe outside the reviewed Linux module, async setns
or caller booleans granting quarantine bypass. Persist generation-bound root-owned
client policy and installation records atomically with locking/fsync; interrupted
installation or selection must remain resumable and fail closed. Provide systemd
and runit startup ordering and precise scope/unsupported-client documentation.

Offline meaningful tests cover selection authorization, exposed-node rejection,
unknown identity, transaction interruption, policy drift, bounded proxy parsing,
upstream loss, no generic DNS/root exception and ordinary-stop persistence.
Ignored owned-guest tests continuously generate IPv4/DNS/IPv6/TCP/UDP markers from
real disposable Tailscale clients while capturing client WAN, host WAN, transport
and data. Test disappearing/changed exit, Tailscale restart, route reset, empty DNS
cache, proxy failure, absent/bypassed settings, install/select boundaries and boot
ordering. Positive capture controls mandatory. Zero forbidden plaintext markers;
unknown/skipped checks remain unverified. Synthetic namespaces do not replace real
Tailscale client acceptance. Keep previous failures and exact source/artifact hashes.

Own minimal client/CLI/service integration, focused tests and documentation. Run
focused fmt/test/clippy and static x86_64/ARM64 checks; explicit owned-file commits,
self-review and task-11-report.md with exact commands/results, capability/syscall
and subprocess inventory, actual scoped evidence and remaining platform gates.
Independent review before migration can rely on client-coverage evidence.
