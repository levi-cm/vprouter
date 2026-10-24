# Explicit direct residential exit integration

PREPARATION ONLY. Dispatch after reviewed actual single-exit guard/worker and
multiple-Mullvad lifecycle tasks. Workdir /DATA/AppData/vprouter-rust-v2, rust/v2;
no subagents. Binding docs/rust-v2/IMPLEMENTATION.md and user handoff. Controller
alone runs privileged/credential-bearing tests in the isolated owned guest.

Deliver direct mode only for explicitly configured+enabled stable exit IDs. Never
create it as a Mullvad failure fallback or select it automatically. Use exact
unsafe-direct-host-ip-{site}-exit naming (site debdev); apply existing duplicate
name suffix/DNS-label63 rules to all conflicting names. Stable node ID/state
remains independent from hostname. Direct mode with Mullvad metadata and Mullvad
mode with direct settings are rejected before mutation. Keep IPv6 forwarding
blocked. Report direct-exposed, never protected, including JSON/probe/diagnose and
selection/migration plans; no constant DNS/IPv6 safety fields.

Use one gateway and reviewed private PID/mount/state/FD/cgroup boundaries. Direct
gets separately owned WAN connection/policy, never a shared permissive path or
routing through primary/base. Its allowed WAN path must be unreachable from every
Mullvad data/transport namespace; no cross-exit bridges. Retain guard-owned
quarantine/activation authority, durable generation/ownership, exact scoped
cleanup and independent emergency quarantine. Ordinary errors keep direct
exposure disabled during incomplete startup. No production bypass of actual
artifact/syscall/LSM admission, no additional SYS_ADMIN in gateway tasks.

Permit public IPv4 application destinations only. Explicitly block host-management
addresses including host public/local addresses, LAN/connected or declared local
prefixes even when globally numbered, private/loopback/shared/link-local/metadata,
unspecified/documentation/benchmark/reserved/multicast/broadcast and other
non-public ranges. Account for known public-address infrastructure/metadata
services; document conservative denied-range policy and its source/version.
Do not assume a public numeric address is public internet traffic simply because
it passes RFC1918 checks. Reconcile host address/prefix changes fail closed.
Return/conntrack/NAT permissions must bind exact exit/interfaces/flow scope so
established traffic cannot cross into another exit. DNS must follow permitted
selected direct path, no host-management resolver exception. No IPv6 bypass.

Direct enrollment is fresh interactive identity with protected state, never cloned.
Direct selection requires explicit mode and stable node ID; hostname alone is
not authorization. Protected client policies must reject exposed nodes. No
Mullvad provider confirmation or protected label inferred for direct mode.
Observed egress/exposure must be verified independently or remain not_tested.
Keep single-exit efficiency and unaffected-exit lifecycle semantics.

Normal tests: actual policy rendering/transaction/scoped transition logic,
range boundaries and special cases, host-public/LAN prefix denial, missing/invalid
metadata/mode/name/direct selection refusal, interrupted initialization and
address-drift failure order. Ignored guest tests: actual public allowed positive
control plus IPv4/DNS/IPv6/TCP/UDP forbidden markers against host/LAN/link-local/
metadata/multicast and cross-exit paths; one direct and five-Mullvad-plus-direct;
keep direct active during every scoped Mullvad fault and show Mullvad never uses
it, healthy exits unchanged. Root runs real Tailscale-client acceptance separately;
synthetic packets never replace mandatory release gates. Preserve failed attempts,
capture sensitivity, exact artifacts/source and exact-owned cleanup evidence.

Own minimal direct guard/worker/CLI/policy integration and focused docs/tests.
No steady-state shell/CLI and no unrelated service/firewall changes. All unsafe
in the reviewed Linux module; no unreviewed daemon capability/policy expansion.
Focused fmt/test/clippy, static x86_64 and ARM64 checks, self-review, explicit
owned-path commits and task-10-report.md with exact commands/results/source and
artifact hashes, actual traffic limits and unperformed release/platform checks.
Independent review mandatory before client integration or production cutover.
