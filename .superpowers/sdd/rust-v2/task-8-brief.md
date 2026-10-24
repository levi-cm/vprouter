# Single-exit guard integration and quarantined native activation

PREPARATION ONLY. Dispatch after task6b execution and task7 worker independent
review gates. Workdir /DATA/AppData/vprouter-rust-v2, rust/v2. No subagents.
Binding docs/rust-v2/IMPLEMENTATION.md. Read reviewed task4/5/6/6b/7 reports and
interfaces. Root controller alone runs ignored tests in the owned disposable
guest; never production fault injection, profile/state reads or cutover here.

Deliver an actual one-Mullvad-exit independent host guard using reviewed native
Docker/netlink/nft/launch/worker pieces, with a minimal pinned gateway/init image.
This is integration, not another observational preparation API. No direct mode,
multiple-exit activation or migration can bypass single-exit parity. Preserve
legacy primary base NETWORK namespace and container name compatibility. Keep
production invocation unavailable until release staging and all required runtime
preconditions are proved; synthetic probe evidence is not production authority.

Guard owns process lifecycle, namespace/allocation locks, durable ownership and
generation, endpoint/server/profile verification, all activation and cleanup.
Install independent host quarantine before creating any usable transport path;
install data+transport policy before starting Tailscale. Namespace managers must
not mint activation authority from caller booleans. Extend DOWN-only native
network interfaces only behind retained guard-owned verified quarantine context.
Create WireGuard in the selected transport namespace and move it into primary
data/base namespace. Data has lo/WireGuard/Tailscale only; no veth, eth0, bridge,
ordinary WAN route or IPv6 forwarding. Transport gets its own scoped host veth,
endpoint-only UDP connection, deterministic reserved addresses and ownership.
Read all route tables/rules and actual link/peer/key/endpoint identities. Duplicate
resource/foreign/uncertain ownership or ambiguous cleanup stays offline.

Concrete integration risk: owned early nft base-chain ACCEPT does not override
later Docker ip filter FORWARD policy DROP. Prove narrowly scoped coexistence by
actual packets in the Docker-enabled guest. Any needed cooperation rule must be
exactly owned, bounded and independently reconciled; no broad exception, foreign
table flush, iptables CLI, Docker/containerd restart or unrelated service mutation.
Host quarantine must remain effective if that cooperation rule drifts or vanishes.
Do not assume current endpoint-only owned tables alone grant WAN forwarding.

Guard and in-namespace worker remain separate failure boundaries. Implement a
bounded protected cross-process health/control protocol, descriptor provenance and
peer identity checks, generation/exit/node binding and monotonic freshness. Worker
health queries are observational. Guard enforces heartbeat <45s and independent
90s watchdog; policy/link/process drift quarantines before stopping children.
Freeze/crash/OOM/container death and delayed/malformed APIs must fail closed.
Timers must not block enforcement on bounded9s Docker or provider12s requests.
Worker initial advertisement is withdrawn before verification and approval.
Native provider exact-server check and three independent healthy samples remain
required; real client egress is separate from READY/advertised status.

Integrate real fixed worker/tailscaled manifests rather than enabling synthetic
staging flags. Pin OCI base digest, Tailscale1.102.5 and exact binary/provenance;
Python absent from runtime image. Review real Rust/Go syscall and LSM policies,
retained NET_ADMIN/NET_RAW and descriptor/config/health allowlists. Probe-only
zero-capability/AppArmor profile cannot silently certify real daemons. Independent
private PID/proc/state views and cgroup/container kill guarantees from6b remain.
All unavoidable unsafe stays in the single reviewed Linux module. No steady-state
shell/CLI commands or async/multithreaded setns. No host sockets or proxy/resolver
environment inherited by placed workers. Approved resolver comes from validated
protected configuration/profile, inside WG-only data policy.

Actual ignored guest tests: native activation over disposable synthetic WG peer,
positive capture sensitivity, actual encrypted socket birth path through native
code; inject deleted/down/stale/wrong peer/endpoint, ordinary/endpoint/Docker/IPv6
route and interface/rule drift, nft removal/drift/failed update, worker/guard/
tailscaled freeze/crash and container kill, malformed/delayed health/Docker APIs,
foreign resources and interrupted startup/cleanup. Exact owned cleanup and
quarantine retained on failure. Root may enroll a fresh test gateway/client and
import supplied profiles only in later explicit credential-bearing tests; do not
clone/use production identities or treat namespace probes as real-client proof.
Record all failures, payload/source hashes and exact observation/capture limits.

Normal tests are offline/loopback only, with meaningful transition/protocol/
failure-ordering assertions. Focused fmt/test/clippy, exact-pinned dependencies,
static x86_64 and ARM64 compilation, self-review and explicit owned-path commits.
Report task-8-report.md with code/artifact hashes, commands/results, actual kernel
evidence, unsafe/capability/subprocess inventory, remaining platform and traffic
acceptance gaps. Independent review is mandatory before multi-exit work.

Bootstrap protection requirement: existing full quarantine drops every non-loopback input/output/forward packet, so provider checks/handshakes cannot progress while it remains fully installed. Add an exact owned, atomic, retained-authority bootstrap stage after full policy installation and stale-advertisement withdrawal: permit only required namespace-local health/control through verified WG and its endpoint-only transport, while protected Tailscale forwarding remains dropped. Only actual provider/structure/online/approval readiness allows full exit forwarding. On any failure restore full quarantine before child stop. Do not relabel full offline quarantine as permitting health or unconditionally release application forwarding to fix initialization. Guard ACKs/health must distinguish bootstrap/offline/ready enforcement states with exit/generation/peer binding rather than a caller proof boolean. Source oracle confirms ExitNodeOption is offered&&approved; withdrawn recovery must not deadlock on it before explicitly advertising under retained bootstrap protection.
