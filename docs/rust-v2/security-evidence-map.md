# Security invariants and evidence scope

The Rust release is incomplete. [acceptance.json](acceptance.json) is the release
gate ledger; its real-client, migration, performance and platform gates remain
`NOT_RUN`. Component evidence below does not satisfy those gates. Tests run only
on the local host and isolated local VMs, as instructed by the user.

| Invariant | Current evidence | Remaining acceptance |
|---|---|---|
| Configuration separates Mullvad and explicit direct modes, rejects duplicate keys/state paths and validates stable naming. | Core contract tests and [configuration reference](configuration.md). | Actual scoped lifecycle, name reconciliation and identity-preserving migration. |
| Worker placement isolates namespaces, private state, process views, descriptors and capabilities. | [Synthetic launch evidence](launch-execution-lab-evidence.json), including repeated-signal shutdown and exact cleanup; [producer gate evidence](producer-placement-lab-evidence.json) verifies fixed-probe subgroup placement and bounded lifecycle. | [Pinned public Go programs](pinned-program-inventory.json) are inventoried; actual Rust/Go execution, immutable final image, producer placement, host accounting and supported-platform runtime tests remain. |
| WG encrypted UDP originates in transport; Mullvad data has no ordinary WAN interface. | [Guarded transport evidence](guarded-transport-lab-evidence.json): exact source/artifact binding, synthetic WG round trips and independent data/transport/WAN captures; scoped transport spec and quality review approved. | Actual Tailscale/provider traffic, autonomous guard and one/five/mixed real-client fault matrix. |
| Bootstrap denies local applications while permitting only the owned health/control producer. | Same-data-namespace ordinary producer and established-input tuple reuse tests; both data filters independently tested through removal/drift. | Real worker/daemon placement before socket creation, real consumer integration and forwarding source-spoof tests. |
| Firewall ownership is scoped; updates are atomic and uncertainty retains quarantine. | [Native actuator evidence](netfilter-lab-evidence.json), guarded transport policy removal/drift tests and preserved foreign Docker rules/handles. | Autonomous drift/deadline enforcement, actual process kills, preexisting startup collision, reboot and multi-exit isolation. The transport failed-batch CLI fixture is separate from native-actuator failure evidence. |
| Interrupted operations never adopt ambiguous existing resources. | Guarded transport test checkpoints retain durable Activating/Bootstrap phases; subsequent acquisition refuses. Deleted/replaced owned interfaces and changed cooperation refuse cleanup. | Real SIGKILL/freeze/power-loss boundaries and complete interrupted migration resume/rollback matrix. Checkpoints are cooperative simulations. |
| Provider checks retain exact-server verification, bounded retry, structural rechecks and evidence expiry. | Worker offline/loopback tests and [actual pinned LocalAPI parser evidence](worker-localapi-lab-evidence.json). | Placed worker, actual imported Mullvad profiles, guarded advertisement/approval and independent host enforcement of verification age. |
| A failed selected exit cannot expose a managed client through ordinary WAN, DNS or IPv6. | No complete Rust client-guard evidence yet. | Persistent kernel-client and userspace-proxy guards plus actual disposable Tailscale-client fault/capture tests. |
| One exit cannot route through another exit or an explicit direct path. | Configuration/policy separation only; no complete multi-exit runtime evidence. | One, five, direct and five-plus-direct deployments under every specified failure group. |
| Migration preserves credentials, node IDs, addresses and compatible stopped-state rollback. | Observational inventory/plan preparation only. | Transactional apply/resume/rollback, adapters, current-main and retry variants, two separately established local legacy deployments. |
| Efficiency improves without reduced monitoring coverage. | [Baseline sample](baseline-resource-sample.json) is uncontrolled orientation only. | Repeated identical ten-minute one/five/six-exit workloads, CPU/PSS/throughput/latency accounting and 24-hour mixed soak. |
| Supported hosts fail preflight before incompatible changes. | Debian local synthetic runtime; x86-64 and ARM64 compilation. | Actual supported-host runtime, systemd/runit lifecycle and release artifacts/provenance. Current producer authority requires the tested systemd Docker cgroup hierarchy; other layouts are unverified. |

Positive controls, capture record counts, kernel drops and forbidden-marker counts
are recorded separately. Zero forbidden markers in a successful synthetic test is
scoped to its observed paths and injected traffic. A skipped, unavailable or failed
check remains unverified; an advertised/READY exit is not proof of client egress.
The approved test identities remain distinct from synthetic test resources and
must never be opened concurrently or reenrolled to make a test pass.
